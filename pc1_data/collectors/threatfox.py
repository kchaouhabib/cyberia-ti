"""
ThreatFox collector (abuse.ch) — banking-malware family focus.

ThreatFox is abuse.ch's IOC-by-malware-family feed. We query it once per
banking-relevant malware family (Emotet, TrickBot, Carbanak, Cobalt Strike,
Dridex, IcedID, Qakbot, Zeus, Lazarus tooling) and aggregate the IOCs.

Each ThreatFox IOC entry becomes one RawThreatRecord. The raw_text is
prose with the IOC value, type, malware family, and confidence — shaped so
PC2's regex extractor naturally finds the value.

Auth: ThreatFox now requires an abuse.ch Auth-Key (free at
https://auth.abuse.ch). Same key as URLhaus / MalwareBazaar.
Set URLHAUS_AUTH_KEY in .env on PC1.

Run:
    python -m pc1_data.collectors.threatfox              # all families, push
    python -m pc1_data.collectors.threatfox --no-push    # dry run
    python -m pc1_data.collectors.threatfox --family emotet --limit 30
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

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Banking-relevant malware families. ThreatFox accepts the family name in
# the `malware` field of the search-by-malware POST body.
BANKING_FAMILIES = [
    "Emotet",
    "TrickBot",
    "Dridex",
    "Carbanak",
    "Cobalt Strike",
    "IcedID",
    "Qakbot",
    "Zeus",
    "Ursnif",
    "Gozi",
]

MIN_RAW_TEXT_LEN = 80


# ──────────────────────────────────────────────────────────────────────────
# Auth + low-level fetch
# ──────────────────────────────────────────────────────────────────────────


def _auth_headers() -> dict:
    """Build the abuse.ch Auth-Key header. Same key as URLhaus / MalwareBazaar."""
    key = os.getenv("URLHAUS_AUTH_KEY") or os.getenv("ABUSECH_AUTH_KEY")
    if not key:
        return {}
    return {"Auth-Key": key}


def search_by_malware(family: str, limit: int = 30, timeout: float = 15.0) -> List[dict]:
    """Hit ThreatFox /api/v1/ with a 'search_ioc' query for one malware family.

    ThreatFox's POST schema is `{"query": "search_ioc", "malware": "<family>",
    "limit": <int>}`. Returns the `data` list.
    """
    headers = _auth_headers()
    if not headers:
        print(
            "[threatfox] SKIP — no URLHAUS_AUTH_KEY in .env. "
            "Get a free key at https://auth.abuse.ch.",
            file=sys.stderr,
        )
        return []

    # ThreatFox API renamed `malware` → `search_term` (the request body field
    # name is now generic so the same query type can search for any IOC kind).
    payload = {"query": "search_ioc", "search_term": family, "limit": int(limit)}
    try:
        resp = httpx.post(THREATFOX_URL, headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") not in {"ok", "no_result"}:
            print(
                f"[threatfox] WARN family={family} status={data.get('query_status')}",
                file=sys.stderr,
            )
            return []
        # ThreatFox sometimes returns `data` as a STRING explanation on
        # no_result status (e.g. "No matching IOC found"). Guard the type
        # so iteration upstream gets dicts, not characters.
        result = data.get("data", []) or []
        if not isinstance(result, list):
            return []
        return result
    except httpx.HTTPError as e:
        print(f"[threatfox] WARN family={family} fetch failed: {e}", file=sys.stderr)
        return []


# ──────────────────────────────────────────────────────────────────────────
# Pulse → RawThreatRecord
# ──────────────────────────────────────────────────────────────────────────


def _build_raw_text(entry: dict) -> str:
    """Compose a prose record so PC2's regex extractor sees the IOC value."""
    ioc_value = (entry.get("ioc") or "").strip()
    ioc_type = (entry.get("ioc_type") or "?").strip()
    malware = (entry.get("malware_printable") or entry.get("malware") or "?").strip()
    threat_type = (entry.get("threat_type") or "?").strip()
    first_seen = (entry.get("first_seen") or "").strip()
    confidence = entry.get("confidence_level")
    tags = entry.get("tags") or []

    parts = [
        f"Title: ThreatFox IOC — {malware} ({threat_type})",
        f"Date: {first_seen}",
        "Source: ThreatFox (abuse.ch)",
        "",
        "Description:",
        f"abuse.ch ThreatFox reports an IOC associated with the {malware} "
        f"malware family.",
        f"IOC value: {ioc_value}",
        f"IOC type: {ioc_type}",
        f"Threat type: {threat_type}",
    ]
    if confidence is not None:
        parts.append(f"Confidence level: {confidence}/100")
    if tags and isinstance(tags, list):
        parts.append(f"Tags: {', '.join(t for t in tags if isinstance(t, str))}")
    parts.append("")
    parts.append(
        f"{malware} is a known banking-trojan / financial-attack family with "
        "documented use against banks, payment processors, and SWIFT terminals."
    )
    return "\n".join(parts).strip()


def entry_to_record(entry: dict) -> Optional[RawThreatRecord]:
    """Convert one ThreatFox IOC entry to a RawThreatRecord, or None if useless."""
    ioc_id = str(entry.get("id") or "").strip()
    ioc_value = (entry.get("ioc") or "").strip()
    if not ioc_id or not ioc_value:
        return None

    raw_text = _build_raw_text(entry)
    if len(raw_text) < MIN_RAW_TEXT_LEN:
        return None

    date_str = (entry.get("first_seen") or "").strip()
    try:
        timestamp = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    return RawThreatRecord(
        id=f"threatfox:{ioc_id}",
        source="threatfox",
        raw_text=raw_text,
        timestamp=timestamp,
        sector="banking",
    )


# ──────────────────────────────────────────────────────────────────────────
# Aggregator
# ──────────────────────────────────────────────────────────────────────────


def fetch_banking_iocs(
    families: Optional[List[str]] = None, limit_per_family: int = 30
) -> List[RawThreatRecord]:
    """Fetch IOCs across all banking-relevant malware families, dedupe by id."""
    families = families or BANKING_FAMILIES
    seen: set[str] = set()
    records: List[RawThreatRecord] = []
    for family in families:
        for entry in search_by_malware(family, limit=limit_per_family):
            ioc_id = str(entry.get("id") or "").strip()
            if not ioc_id or ioc_id in seen:
                continue
            seen.add(ioc_id)
            record = entry_to_record(entry)
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
                print(f"[threatfox] WARN push {record.id} failed: {e}", file=sys.stderr)
                fail += 1
    return ok, fail


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="ThreatFox collector — banking malware focus")
    parser.add_argument(
        "--api",
        default=os.getenv("PC1_API_URL", "http://localhost:8000"),
    )
    parser.add_argument(
        "--family",
        action="append",
        help=(
            "Restrict to one or more malware families (repeatable). "
            f"Default: {', '.join(BANKING_FAMILIES)}."
        ),
    )
    parser.add_argument("--limit", type=int, default=30, help="Per-family limit (default 30).")
    parser.add_argument("--no-push", action="store_true")
    args = parser.parse_args()

    families = args.family if args.family else BANKING_FAMILIES
    print(f"[threatfox] Querying {len(families)} families...")
    records = fetch_banking_iocs(families=families, limit_per_family=args.limit)
    print(f"[threatfox] {len(records)} unique IOCs after dedupe.")

    if args.no_push:
        for r in records[:5]:
            print(f"\n=== {r.id} ===")
            print(r.raw_text[:400])
        return 0

    print(f"[threatfox] Pushing to {args.api}/raw ...")
    ok, fail = push_to_api(records, api_url=args.api)
    print(f"[threatfox] {ok} pushed, {fail} failed.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
