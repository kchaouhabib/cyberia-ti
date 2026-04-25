"""
AlienVault OTX collector — banking focus.

Hits the public /pulses/search endpoint for banking-relevant queries,
filters for finance-sector tags + known financial APTs, and POSTs
each pulse as a RawThreatRecord to PC1's /raw endpoint.

Run:
    python -m pc1_data.collectors.otx              # fetch + push to localhost:8000
    python -m pc1_data.collectors.otx --cache      # use fixtures/otx_cache.json offline
    python -m pc1_data.collectors.otx --save-cache # fetch and snapshot to cache file
    python -m pc1_data.collectors.otx --help

Why option A (one RawThreatRecord per pulse, not per indicator):
    PC2's regex/LLM IOC extractor needs prose to chew on. We render the
    pulse's structured indicator list back into the raw_text so PC2's
    extraction is honest end-to-end work, not a free pass.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

import httpx
from dotenv import load_dotenv

from shared.schemas import RawThreatRecord

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_PULSES_SEARCH = f"{OTX_BASE_URL}/search/pulses"  # NOT /pulses/search — that's a 404

# Search queries that bias the firehose toward banking-sector intel.
# Mix of generic finance keywords + known financial APT / malware names.
BANKING_QUERIES = [
    "banking",
    "swift",
    "carbanak",
    "fin7",
    "emotet",
    "trickbot",
    "lazarus",
    "dridex",
]

# If a pulse's tags or industries hit any of these, we mark sector="banking".
# Otherwise sector stays None (the pulse is still ingested — PC3 may still
# care about it for cross-sector threat trends).
BANKING_TAG_WHITELIST = frozenset({
    # Sector tags
    "banking", "finance", "financial", "bank", "banks", "fintech",
    "swift", "payment", "payments", "credit-card", "creditcard",
    "card", "pos", "atm",
    # Financial APTs (CLAUDE.md banking defaults)
    "carbanak", "fin7", "lazarus", "silence", "cobalt-group",
    "cobalt-strike", "cobalt",
    # Banking-trojan families
    "emotet", "trickbot", "dridex", "zeus", "qbot", "qakbot", "ramnit",
    "gozi", "tinba", "ursnif",
})

# Pulses with raw text shorter than this are skipped — gives PC2's
# regex/LLM extractor nothing useful to extract from.
MIN_RAW_TEXT_LEN = 100

CACHE_PATH = Path("fixtures/otx_cache.json")


# ──────────────────────────────────────────────────────────────────────────
# Tag normalization & sector inference
# ──────────────────────────────────────────────────────────────────────────


def _normalize_tag(tag: str) -> str:
    """Lowercase + strip + replace spaces/underscores with hyphens for set lookup."""
    return tag.strip().lower().replace(" ", "-").replace("_", "-")


def _is_banking_pulse(pulse: dict) -> bool:
    """Return True if any tag or industry matches our banking whitelist."""
    tags = {_normalize_tag(t) for t in pulse.get("tags", []) if isinstance(t, str)}
    industries = {
        _normalize_tag(i) for i in pulse.get("industries", []) if isinstance(i, str)
    }
    return bool((tags | industries) & BANKING_TAG_WHITELIST)


# ──────────────────────────────────────────────────────────────────────────
# Pulse → RawThreatRecord rendering
# ──────────────────────────────────────────────────────────────────────────


def _render_indicators_block(indicators: list) -> str:
    """Render the structured indicators array as plain text so PC2's regex
    extractor has something to match on."""
    if not indicators:
        return ""
    lines = ["", "Indicators:"]
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        value = ind.get("indicator", "").strip()
        kind = ind.get("type", "?").strip()
        if value:
            lines.append(f"- {value} ({kind})")
    return "\n".join(lines) if len(lines) > 2 else ""


def _build_raw_text(pulse: dict) -> str:
    """Compose a prose+indicators string suitable for PC2's extractor."""
    parts = []
    name = (pulse.get("name") or "").strip()
    if name:
        parts.append(f"Title: {name}")

    created = (pulse.get("created") or "").strip()
    if created:
        parts.append(f"Date: {created}")

    description = (pulse.get("description") or "").strip()
    if description:
        parts.append("")
        parts.append("Description:")
        parts.append(description)

    indicators_block = _render_indicators_block(pulse.get("indicators", []))
    if indicators_block:
        parts.append(indicators_block)

    return "\n".join(parts).strip()


def pulse_to_record(pulse: dict) -> Optional[RawThreatRecord]:
    """Convert one OTX pulse dict to our RawThreatRecord. Returns None if
    the pulse is too sparse (not worth feeding to PC2)."""
    pulse_id = pulse.get("id")
    if not pulse_id:
        return None

    raw_text = _build_raw_text(pulse)
    if len(raw_text) < MIN_RAW_TEXT_LEN:
        return None

    # OTX timestamps are ISO 8601 strings; parse defensively.
    created_str = pulse.get("created") or pulse.get("modified") or ""
    try:
        timestamp = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    # Every query in BANKING_QUERIES is banking-targeted by design, so any
    # pulse this collector returns is banking-relevant by construction.
    # The tag check is kept as a sanity boost (high-confidence banking),
    # but a tag miss is no longer a disqualifier — older pulses often
    # have empty tags arrays even when their content is clearly banking.
    sector = "banking"
    confidence_tag = "banking-strong" if _is_banking_pulse(pulse) else "banking-loose"

    return RawThreatRecord(
        id=f"otx:{pulse_id}",
        source="otx",
        raw_text=raw_text + f"\n\n[sector_confidence={confidence_tag}]",
        timestamp=timestamp,
        sector=sector,
    )


# ──────────────────────────────────────────────────────────────────────────
# OTX API client
# ──────────────────────────────────────────────────────────────────────────


def _otx_headers() -> dict:
    """Build the auth header. Raises loudly if the key is missing — never
    falls back to anonymous (would silently return useless data)."""
    key = os.getenv("OTX_API_KEY")
    if not key:
        raise RuntimeError(
            "OTX_API_KEY not set. Add it to .env on PC1's laptop "
            "(get a free key at https://otx.alienvault.com)."
        )
    return {"X-OTX-API-KEY": key, "User-Agent": "cyberia-ti/0.2 (hackathon)"}


def search_pulses(query: str, limit: int = 20, timeout: float = 15.0) -> List[dict]:
    """Hit /pulses/search for one query. Returns the `results` list (raw
    pulse dicts), or [] on failure (logged but non-fatal)."""
    try:
        resp = httpx.get(
            OTX_PULSES_SEARCH,
            params={"q": query, "limit": limit, "page": 1},
            headers=_otx_headers(),
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])
    except httpx.HTTPError as e:
        print(f"[otx] WARN search '{query}' failed: {e}", file=sys.stderr)
        return []


def fetch_banking_pulses(limit_per_query: int = 20) -> List[RawThreatRecord]:
    """Fetch + filter + dedupe pulses across all banking queries."""
    seen_ids: set[str] = set()
    records: List[RawThreatRecord] = []
    for q in BANKING_QUERIES:
        for pulse in search_pulses(q, limit=limit_per_query):
            pulse_id = pulse.get("id")
            if not pulse_id or pulse_id in seen_ids:
                continue
            seen_ids.add(pulse_id)
            record = pulse_to_record(pulse)
            if record is not None:
                records.append(record)
    return records


# ──────────────────────────────────────────────────────────────────────────
# Cache (offline-demo safety net)
# ──────────────────────────────────────────────────────────────────────────


def save_cache(records: Iterable[RawThreatRecord], path: Path = CACHE_PATH) -> None:
    """Snapshot records to JSON for offline demo. Run once with internet,
    re-run anywhere with --cache."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(
            [json.loads(r.model_dump_json()) for r in records],
            f,
            indent=2,
            ensure_ascii=False,
        )


def load_cache(path: Path = CACHE_PATH) -> List[RawThreatRecord]:
    """Read a previously-saved cache. Used by --cache mode (no internet)."""
    if not path.exists():
        raise FileNotFoundError(
            f"Cache file {path} not found. Run without --cache first to populate it."
        )
    with path.open("r", encoding="utf-8") as f:
        return [RawThreatRecord.model_validate(item) for item in json.load(f)]


# ──────────────────────────────────────────────────────────────────────────
# Push to PC1's API
# ──────────────────────────────────────────────────────────────────────────


def push_to_api(
    records: Iterable[RawThreatRecord],
    api_url: str = "http://localhost:8000",
    timeout: float = 5.0,
) -> tuple[int, int]:
    """POST each record to /raw. Returns (ok_count, fail_count)."""
    ok = 0
    fail = 0
    with httpx.Client(timeout=timeout) as client:
        for record in records:
            try:
                resp = client.post(
                    f"{api_url}/raw",
                    content=record.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                ok += 1
            except httpx.HTTPError as e:
                print(f"[otx] WARN push {record.id} failed: {e}", file=sys.stderr)
                fail += 1
    return ok, fail


# ──────────────────────────────────────────────────────────────────────────
# CLI entry
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="OTX collector — banking focus")
    parser.add_argument(
        "--cache",
        action="store_true",
        help=f"Read from {CACHE_PATH} instead of hitting the OTX API (offline demo).",
    )
    parser.add_argument(
        "--save-cache",
        action="store_true",
        help=f"Fetch from OTX, then save snapshot to {CACHE_PATH}.",
    )
    parser.add_argument(
        "--api",
        default=os.getenv("PC1_API_URL", "http://localhost:8000"),
        help="PC1 API base URL (default: http://localhost:8000).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max pulses to fetch per query (default: 20).",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Fetch + parse but don't POST to the API (dry run).",
    )
    args = parser.parse_args()

    if args.cache:
        print(f"[otx] Loading from cache {CACHE_PATH}...")
        records = load_cache()
    else:
        print(f"[otx] Fetching banking pulses from OTX ({len(BANKING_QUERIES)} queries)...")
        records = fetch_banking_pulses(limit_per_query=args.limit)

    banking_count = sum(1 for r in records if r.sector == "banking")
    print(
        f"[otx] Got {len(records)} unique pulses "
        f"({banking_count} tagged banking, "
        f"{len(records) - banking_count} other)."
    )

    if args.save_cache:
        save_cache(records)
        print(f"[otx] Cached {len(records)} records to {CACHE_PATH}")

    if args.no_push:
        print("[otx] --no-push: skipping API push.")
        return 0

    print(f"[otx] Pushing to {args.api}/raw ...")
    ok, fail = push_to_api(records, api_url=args.api)
    print(f"[otx] Pushed {ok} ok, {fail} failed.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
