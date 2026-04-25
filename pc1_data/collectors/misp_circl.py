"""
CIRCL MISP collector — public OSINT feed (no auth required).

CIRCL (Computer Incident Response Center Luxembourg) publishes a free,
no-auth MISP-formatted feed at https://www.circl.lu/doc/misp/feed-osint/.
Events are published as JSON files referenced by a manifest.

Workflow:
    1. Fetch the manifest.json — a small file mapping event UUID → metadata
    2. For each banking-relevant event in the manifest, fetch its event JSON
    3. Convert the event into a RawThreatRecord (one per event, not per attribute)

Banking filter: an event is banking-relevant if its `Tag` array contains
any of our banking-relevant terms (sector tags, financial APT names,
banking-trojan family names) or if "bank"/"finance"/"swift" appears in
the `info` (event title).

Run:
    python -m pc1_data.collectors.misp_circl              # fetch + push
    python -m pc1_data.collectors.misp_circl --no-push    # dry run
    python -m pc1_data.collectors.misp_circl --limit 30   # cap fetch
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Iterable, List, Optional

import httpx
from dotenv import load_dotenv

from shared.schemas import RawThreatRecord

CIRCL_FEED_BASE = "https://www.circl.lu/doc/misp/feed-osint/"
MANIFEST_URL = f"{CIRCL_FEED_BASE}manifest.json"

# Banking-relevant filter — applied to event tags AND event title (info).
BANKING_KEYWORDS = frozenset({
    # Sector
    "banking", "bank", "finance", "financial", "swift", "fintech",
    "payment", "credit-card", "creditcard", "card", "pos", "atm",
    # Financial APTs
    "carbanak", "fin7", "lazarus", "silence", "cobalt-group", "cobalt",
    # Banking trojans
    "emotet", "trickbot", "dridex", "qakbot", "qbot", "zeus", "icedid",
    "ramnit", "gozi", "ursnif", "tinba",
})

MIN_RAW_TEXT_LEN = 80


# ──────────────────────────────────────────────────────────────────────────
# Manifest fetch + filter
# ──────────────────────────────────────────────────────────────────────────


def fetch_manifest(timeout: float = 30.0) -> dict:
    """Pull the CIRCL manifest. ~1MB, no auth, public."""
    try:
        resp = httpx.get(MANIFEST_URL, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError) as e:
        print(f"[circl] WARN manifest fetch failed: {e}", file=sys.stderr)
        return {}


def _is_banking_event(meta: dict) -> bool:
    """Check the manifest entry — does any tag or the info string mention banking?"""
    tags = meta.get("Tag") or []
    if isinstance(tags, list):
        for tag in tags:
            if not isinstance(tag, dict):
                continue
            name = (tag.get("name") or "").lower()
            for kw in BANKING_KEYWORDS:
                if kw in name:
                    return True

    info = (meta.get("info") or "").lower()
    return any(kw in info for kw in BANKING_KEYWORDS)


def _select_banking_uuids(manifest: dict, limit: int = 30) -> List[str]:
    """From the full manifest, pick UUIDs of banking-relevant events, newest first."""
    items = []
    for uuid, meta in manifest.items():
        if not isinstance(meta, dict):
            continue
        if _is_banking_event(meta):
            items.append((meta.get("date") or "", uuid))
    items.sort(reverse=True)  # newest dates first
    return [uuid for _, uuid in items[:limit]]


# ──────────────────────────────────────────────────────────────────────────
# Event fetch + conversion
# ──────────────────────────────────────────────────────────────────────────


def fetch_event(uuid: str, timeout: float = 30.0) -> Optional[dict]:
    """Fetch one MISP event by UUID."""
    url = f"{CIRCL_FEED_BASE}{uuid}.json"
    try:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError) as e:
        print(f"[circl] WARN event {uuid} fetch failed: {e}", file=sys.stderr)
        return None


def _build_raw_text(event: dict) -> str:
    """Compose prose with the event title, summary, tags, and the IOC attributes
    rendered as a list — gives PC2's regex something to chew on."""
    info = (event.get("info") or "").strip()
    date = (event.get("date") or "").strip()
    threat_level_raw = event.get("threat_level_id")
    threat_level = str(threat_level_raw) if threat_level_raw is not None else "?"

    org = ""
    orgc = event.get("Orgc") or {}
    if isinstance(orgc, dict):
        org = (orgc.get("name") or "").strip()
    tags = event.get("Tag") or []
    tag_names: List[str] = []
    for tag in tags:
        if isinstance(tag, dict):
            name = (tag.get("name") or "").strip()
            if name:
                tag_names.append(name)

    parts = [
        f"Title: {info}",
        f"Date: {date}",
        f"Source: CIRCL MISP feed (Orgc: {org or 'unknown'})",
        f"Threat level: {threat_level}",
    ]
    if tag_names:
        parts.append(f"Tags: {', '.join(tag_names[:25])}")
    parts.append("")
    parts.append("Description:")
    parts.append(
        "Event published by CIRCL via the public OSINT MISP feed. "
        "The event aggregates the following indicators of compromise."
    )

    attributes = event.get("Attribute") or []
    if attributes:
        parts.append("")
        parts.append("Indicators:")
        rendered = 0
        for attr in attributes:
            if not isinstance(attr, dict):
                continue
            value = (attr.get("value") or "").strip()
            kind = (attr.get("type") or "").strip()
            if value and kind:
                parts.append(f"- {value} ({kind})")
                rendered += 1
                if rendered >= 50:  # cap to keep raw_text under control
                    parts.append(f"  ... ({len(attributes) - rendered} more attributes truncated)")
                    break

    return "\n".join(parts).strip()


def event_to_record(event: dict) -> Optional[RawThreatRecord]:
    """Convert one MISP event to a RawThreatRecord. The MISP event format
    nests fields under an "Event" key — handle both shapes."""
    inner = event.get("Event") if isinstance(event.get("Event"), dict) else event
    uuid = (inner.get("uuid") or "").strip()
    if not uuid:
        return None

    raw_text = _build_raw_text(inner)
    if len(raw_text) < MIN_RAW_TEXT_LEN:
        return None

    date_str = (inner.get("date") or "").strip()
    try:
        timestamp = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    return RawThreatRecord(
        id=f"circl-misp:{uuid}",
        source="misp",
        raw_text=raw_text,
        timestamp=timestamp,
        sector="banking",
    )


# ──────────────────────────────────────────────────────────────────────────
# Aggregator
# ──────────────────────────────────────────────────────────────────────────


def fetch_banking_events(limit: int = 30) -> List[RawThreatRecord]:
    """Fetch up to `limit` banking-relevant CIRCL MISP events as RawThreatRecords."""
    manifest = fetch_manifest()
    if not manifest:
        return []
    uuids = _select_banking_uuids(manifest, limit=limit)
    print(f"[circl] {len(uuids)} banking-relevant events selected from manifest.")

    records: List[RawThreatRecord] = []
    for uuid in uuids:
        event = fetch_event(uuid)
        if event is None:
            continue
        record = event_to_record(event)
        if record is not None:
            records.append(record)
    return records


# ──────────────────────────────────────────────────────────────────────────
# Push
# ──────────────────────────────────────────────────────────────────────────


def push_to_api(
    records: Iterable[RawThreatRecord],
    api_url: str = "http://localhost:8000",
    timeout: float = 5.0,
) -> tuple[int, int]:
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
                print(f"[circl] WARN push {record.id} failed: {e}", file=sys.stderr)
                fail += 1
    return ok, fail


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="CIRCL MISP feed collector — banking focus, no auth required."
    )
    parser.add_argument(
        "--api",
        default=os.getenv("PC1_API_URL", "http://localhost:8000"),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Max banking-relevant events to fetch (default: 30).",
    )
    parser.add_argument("--no-push", action="store_true")
    args = parser.parse_args()

    print(f"[circl] Fetching CIRCL manifest...")
    records = fetch_banking_events(limit=args.limit)
    print(f"[circl] {len(records)} events parsed into RawThreatRecord.")

    if args.no_push:
        for r in records[:3]:
            print(f"\n=== {r.id} ===")
            print(r.raw_text[:500])
        return 0

    print(f"[circl] Pushing to {args.api}/raw ...")
    ok, fail = push_to_api(records, api_url=args.api)
    print(f"[circl] {ok} pushed, {fail} failed.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
