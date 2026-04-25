"""
PC2 pipeline — Stage 02, Phase 2.

Full chain:
  PC1 GET /raw  →  regex extract  →  deduplicate  →  classify
  →  confidence score  →  NER apt_attribution  →  PC1 POST /iocs/enriched

PC1 is at http://100.67.61.250:8000 (NetBird). Override with env var PC1_BASE_URL.

Run:
    python -m pc2_ai.pipeline
"""

import logging
import os
import time
from datetime import datetime, timezone

import httpx

from pc2_ai.ioc_extractor import extract_iocs
from pc2_ai.deduplicator import deduplicate
from pc2_ai.classifier import classify
from pc2_ai.confidence_scorer import apply as score_confidence
from pc2_ai.ner import get_apt_attribution
from shared.schemas import EnrichedIOC, RawThreatRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

PC1_BASE      = os.environ.get("PC1_BASE_URL", "http://100.67.61.250:8000")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))

_processed_ids: set[str] = set()


def _fetch_raw() -> list[RawThreatRecord]:
    """GET /raw from PC1 and return parsed records."""
    resp = httpx.get(f"{PC1_BASE}/raw", timeout=10)
    resp.raise_for_status()
    return [RawThreatRecord(**r) for r in resp.json()]


def _push_enriched(ioc: EnrichedIOC) -> None:
    """POST an enriched IOC to PC1 /iocs/enriched."""
    resp = httpx.post(
        f"{PC1_BASE}/iocs/enriched",
        json=ioc.model_dump(mode="json"),
        timeout=10,
    )
    resp.raise_for_status()


def process_record(record: RawThreatRecord) -> int:
    """
    Full AI chain for one raw record.
    Returns number of enriched IOCs pushed.

    Steps:
      1. Regex extraction → raw IOCs
      2. Deduplication (sentence-transformers)
      3. Classify each IOC → threat_type
      4. Confidence score adjustment (per-source)
      5. NER APT attribution from raw text
      6. Build EnrichedIOC and push to PC1
    """
    # Step 1 — extract
    raw_iocs = extract_iocs(record.raw_text, source=record.source)
    if not raw_iocs:
        return 0

    # Step 2 — deduplicate within this record
    deduped, n_removed = deduplicate(raw_iocs)
    if n_removed:
        log.debug(f"  dedup: removed {n_removed} near-duplicate(s)")

    # Step 5 — NER on full text (one call per record, not per IOC)
    apt_attr = get_apt_attribution(record.raw_text)

    pushed = 0
    for ioc in deduped:
        # Step 3 — classify
        threat_type = classify(ioc.value, ioc.type, ioc.source)

        # Step 4 — confidence scoring
        scored_ioc = score_confidence(ioc)

        # Build EnrichedIOC
        enriched = EnrichedIOC(
            value=scored_ioc.value,
            type=scored_ioc.type,
            confidence=scored_ioc.confidence,
            source=scored_ioc.source,
            first_seen=scored_ioc.first_seen,
            threat_type=threat_type,
            related_cves=[],
            geolocation=None,
            reputation=None,
            apt_attribution=apt_attr,
        )

        try:
            _push_enriched(enriched)
            pushed += 1
        except Exception as e:
            log.error(f"  failed to push {ioc.value}: {e}")

    return pushed


def run_once() -> None:
    """Single pass: fetch new raw records, run full AI chain, push enriched IOCs."""
    records = _fetch_raw()
    new_records = [r for r in records if r.id not in _processed_ids]

    if not new_records:
        log.info("No new records — waiting for PC1 data.")
        return

    total_pushed = 0
    total_deduped = 0

    for record in new_records:
        try:
            n = process_record(record)
            sector_tag = f"[{record.sector}]" if record.sector else ""
            log.info(f"[{record.source}]{sector_tag} {record.id[:8]}…  →  {n} enriched IOC(s) pushed")
            total_pushed += n
            _processed_ids.add(record.id)
        except Exception as e:
            log.error(f"Failed to process record {record.id}: {e}")

    log.info(
        f"Pass done — {len(new_records)} record(s), "
        f"{total_pushed} enriched IOC(s) pushed to PC1 /iocs/enriched"
    )


def run_loop() -> None:
    """Poll PC1 every POLL_INTERVAL seconds indefinitely."""
    log.info(f"PC2 pipeline (Phase 2) starting — target: {PC1_BASE}  poll: {POLL_INTERVAL}s")
    log.info("Chain: extract → dedup → classify → score → NER → push /iocs/enriched")
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
