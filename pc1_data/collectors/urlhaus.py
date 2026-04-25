"""
URLhaus collector (abuse.ch) — banking-phishing focus.

URLhaus is a public, free, no-auth feed of malicious URLs maintained by
abuse.ch. We pull recent URLs and keep the ones whose tags suggest a
banking-sector or financial-malware connection (phishing, banking-trojan
families, etc.).

Each URL becomes one RawThreatRecord. The raw_text is human-readable
prose containing the URL, its tags, the threat label, and the date —
shaped so PC2's regex extractor finds the URL and the surrounding
hostname/domain naturally.

Run:
    python -m pc1_data.collectors.urlhaus              # fetch + push
    python -m pc1_data.collectors.urlhaus --no-push    # dry run
    python -m pc1_data.collectors.urlhaus --limit 50   # cap the fetch
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

URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# Banking-relevant tag whitelist for URLhaus. URLhaus tags are lowercase
# free-form strings — we sample for finance-related ones and known banking-
# trojan family names.
BANKING_URLHAUS_TAGS = frozenset({
    "phishing", "phish", "banking", "bank", "finance",
    "emotet", "trickbot", "dridex", "qakbot", "qbot", "zeus", "icedid",
    "ramnit", "gozi", "ursnif", "tinba", "carbanak", "cobalt-strike",
    "cobaltstrike", "lazarus", "fin7", "silence",
})

# Drop URLs whose raw_text wouldn't give PC2's extractor much to work with.
MIN_RAW_TEXT_LEN = 80


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────


def _is_banking_relevant(entry: dict) -> bool:
    """Return True if the URLhaus entry's tags hit our banking whitelist."""
    tags = entry.get("tags") or []
    if not isinstance(tags, list):
        return False
    norm = {t.strip().lower() for t in tags if isinstance(t, str)}
    return bool(norm & BANKING_URLHAUS_TAGS)


def _build_raw_text(entry: dict) -> str:
    """Compose a prose record so PC2's regex extractor sees the URL and host."""
    url = (entry.get("url") or "").strip()
    host = (entry.get("host") or "").strip()
    threat = (entry.get("threat") or "unknown").strip()
    tags = entry.get("tags") or []
    date_added = (entry.get("date_added") or "").strip()
    reporter = (entry.get("reporter") or "anonymous").strip()
    larted = (entry.get("larted") or "").strip()  # whether the host has been notified

    parts = [
        f"Title: URLhaus malicious URL — {threat}",
        f"Date: {date_added}",
        "Source: URLhaus (abuse.ch public feed)",
        "",
        "Description:",
        f"abuse.ch URLhaus reports a malicious URL with threat-class '{threat}'.",
        f"Reporter: {reporter}.",
        f"Host: {host}",
        f"URL: {url}",
    ]
    if tags:
        parts.append(f"Tags: {', '.join(t for t in tags if isinstance(t, str))}")
    if larted:
        parts.append(f"Hosting provider notified: {larted}")
    parts.append("")
    parts.append(
        "These URLs are commonly used in spearphishing and credential-harvesting "
        "campaigns, especially in financial-sector targeting."
    )
    return "\n".join(parts).strip()


def entry_to_record(entry: dict) -> Optional[RawThreatRecord]:
    """Convert one URLhaus entry to a RawThreatRecord, or None if not useful."""
    url_id = (entry.get("id") or entry.get("url_id") or "").strip()
    url = (entry.get("url") or "").strip()
    if not url_id or not url:
        return None

    raw_text = _build_raw_text(entry)
    if len(raw_text) < MIN_RAW_TEXT_LEN:
        return None

    date_str = (entry.get("date_added") or "").strip()
    try:
        # URLhaus dates look like "2024-01-15 12:34:56"
        timestamp = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    return RawThreatRecord(
        id=f"urlhaus:{url_id}",
        source="urlhaus",
        raw_text=raw_text,
        timestamp=timestamp,
        sector="banking",  # we only kept banking-relevant entries
    )


# ──────────────────────────────────────────────────────────────────────────
# Fetch
# ──────────────────────────────────────────────────────────────────────────


def _auth_headers() -> dict:
    """Build the abuse.ch Auth-Key header. abuse.ch APIs (URLhaus, ThreatFox,
    MalwareBazaar) require a free Auth-Key as of 2025. Get one at
    https://auth.abuse.ch (60-second sign-up, no payment)."""
    key = os.getenv("URLHAUS_AUTH_KEY") or os.getenv("ABUSECH_AUTH_KEY")
    if not key:
        return {}  # caller will get 401 and skip gracefully
    return {"Auth-Key": key}


def fetch_recent(limit: int = 100, timeout: float = 15.0) -> List[dict]:
    """Hit URLhaus /v1/urls/recent/limit/N/. Returns the urls list (each is a dict).

    Requires URLHAUS_AUTH_KEY (or ABUSECH_AUTH_KEY) in env. If missing,
    returns [] with a clear message — the rest of the pipeline skips
    URLhaus rather than crashing.
    """
    headers = _auth_headers()
    if not headers:
        print(
            "[urlhaus] SKIP — no URLHAUS_AUTH_KEY in .env. "
            "Get a free key at https://auth.abuse.ch and add to .env on PC1.",
            file=sys.stderr,
        )
        return []

    url = f"{URLHAUS_RECENT_URL}limit/{int(limit)}/"
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            print(
                f"[urlhaus] WARN query_status={data.get('query_status')}",
                file=sys.stderr,
            )
            return []
        return data.get("urls", []) or []
    except httpx.HTTPError as e:
        print(f"[urlhaus] WARN fetch failed: {e}", file=sys.stderr)
        return []


def fetch_banking_urls(limit: int = 100) -> List[RawThreatRecord]:
    """Fetch + filter + convert URLhaus entries into RawThreatRecord objects."""
    raw_entries = fetch_recent(limit=limit)
    records: List[RawThreatRecord] = []
    for entry in raw_entries:
        if not _is_banking_relevant(entry):
            continue
        record = entry_to_record(entry)
        if record is not None:
            records.append(record)
    return records


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
                print(f"[urlhaus] WARN push {record.id} failed: {e}", file=sys.stderr)
                fail += 1
    return ok, fail


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="URLhaus collector — banking focus")
    parser.add_argument(
        "--api",
        default=os.getenv("PC1_API_URL", "http://localhost:8000"),
        help="PC1 API base URL.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max URLs to fetch from URLhaus (default: 100).",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Fetch + filter but don't POST.",
    )
    args = parser.parse_args()

    print(f"[urlhaus] Fetching up to {args.limit} recent URLs...")
    records = fetch_banking_urls(limit=args.limit)
    print(f"[urlhaus] {len(records)} banking-relevant URLs after filter.")

    if args.no_push:
        for r in records[:5]:
            print(f"\n=== {r.id} ===")
            print(r.raw_text[:400])
        return 0

    print(f"[urlhaus] Pushing to {args.api}/raw ...")
    ok, fail = push_to_api(records, api_url=args.api)
    print(f"[urlhaus] {ok} pushed, {fail} failed.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
