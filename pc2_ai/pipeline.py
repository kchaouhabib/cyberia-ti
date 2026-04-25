"""
PC2 pipeline — Stage 02, Phase 1.

Polls PC1 GET /raw, runs regex IOC extraction, POSTs each IOC to PC1 POST /iocs.
PC1 is at http://10.135.202.212:8000 (ZeroTier). Override with env var PC1_BASE_URL.

Run:
    python -m pc2_ai.pipeline
"""

import logging
import os
import time

import httpx

from pc2_ai.ioc_extractor import extract_iocs
from shared.schemas import IOC, RawThreatRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

PC1_BASE      = os.environ.get("PC1_BASE_URL", "http://10.135.202.212:8000")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))

# Track which record IDs we have already processed so we don't push duplicates
_processed_ids: set[str] = set()


def _fetch_raw() -> list[RawThreatRecord]:
    """GET /raw from PC1 and return parsed records."""
    resp = httpx.get(f"{PC1_BASE}/raw", timeout=10)
    resp.raise_for_status()
    return [RawThreatRecord(**r) for r in resp.json()]


def _push_ioc(ioc: IOC) -> None:
    """POST a single IOC to PC1 /iocs."""
    resp = httpx.post(
        f"{PC1_BASE}/iocs",
        json=ioc.model_dump(mode="json"),
        timeout=10,
    )
    resp.raise_for_status()


def process_record(record: RawThreatRecord) -> int:
    """
    Extract IOCs from one raw record and push each to PC1.
    Returns the number of IOCs pushed.
    """
    iocs = extract_iocs(record.raw_text, source=record.source)
    for ioc in iocs:
        _push_ioc(ioc)
    return len(iocs)


def run_once() -> None:
    """Single pass: fetch new raw records, extract IOCs, push to PC1."""
    records = _fetch_raw()

    new_records = [r for r in records if r.id not in _processed_ids]
    if not new_records:
        log.info("No new records — waiting for PC1 data.")
        return

    total_iocs = 0
    for record in new_records:
        try:
            n = process_record(record)
            log.info(f"[{record.source}] {record.id[:8]}…  →  {n} IOC(s) pushed")
            total_iocs += n
            _processed_ids.add(record.id)
        except Exception as e:
            log.error(f"Failed to process record {record.id}: {e}")

    log.info(f"Pass done — {len(new_records)} record(s) processed, {total_iocs} IOC(s) pushed total")


def run_loop() -> None:
    """Poll PC1 every POLL_INTERVAL seconds indefinitely."""
    log.info(f"PC2 pipeline starting — target: {PC1_BASE}  poll: {POLL_INTERVAL}s")
    while True:
        try:
            run_once()
        except httpx.ConnectError:
            log.warning(f"Cannot reach PC1 at {PC1_BASE} — retrying in {POLL_INTERVAL}s")
        except Exception as e:
            log.error(f"Unexpected error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run_loop()
