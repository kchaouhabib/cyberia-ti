"""Phase 1 end-to-end demo for PC3.

Builds a small set of fake banking-themed EnrichedIOCs, runs them through the
correlator + risk_scorer, and POSTs the resulting Incident to PC1's
``/incidents`` endpoint.

This satisfies the Phase 1 checkpoint in BATTLE_PLAN.md:
    "Push one fake incident to PC1 /incidents to test the full chain."

Configuration via environment variables:
    PC1_BASE_URL  default: http://10.135.202.212:8000  (PC1's ZeroTier IP)

Usage:
    .venv/Scripts/python.exe pc3_analysis/run_phase1_demo.py

Behavior:
- If PC1 responds 2xx, exit 0 — chain is proven.
- If PC1 is unreachable, write the incident JSON to
  ``data/scenario/phase1_demo_incident.json`` as offline proof and exit 2.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pc3_analysis import correlator, risk_scorer  # noqa: E402
from shared.schemas import EnrichedIOC  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_PC1_URL = "http://192.168.1.5:8000"
PC1_BASE_URL = os.environ.get("PC1_BASE_URL", DEFAULT_PC1_URL).rstrip("/")
HTTP_TIMEOUT_S = 5.0
FALLBACK_PATH = REPO_ROOT / "data" / "scenario" / "phase1_demo_incident.json"


def _build_mock_iocs() -> list[EnrichedIOC]:
    """Synthesize a small phishing burst against Banque Atlas treasury."""
    base = datetime.now(timezone.utc).replace(microsecond=0)
    return [
        EnrichedIOC(
            value="185.220.101.45",
            type="ip",
            confidence=0.92,
            source="scenario",
            first_seen=base,
            threat_type="phishing",
            related_cves=[],
            geolocation="RU",
            reputation=0.05,
        ),
        EnrichedIOC(
            value="bct-securite-update.example",
            type="domain",
            confidence=0.88,
            source="scenario",
            first_seen=base + timedelta(minutes=3),
            threat_type="phishing",
            related_cves=[],
            geolocation="RU",
            reputation=0.07,
        ),
        EnrichedIOC(
            value="d41d8cd98f00b204e9800998ecf8427e" * 2,
            type="hash_sha256",
            confidence=0.96,
            source="scenario",
            first_seen=base + timedelta(minutes=12),
            threat_type="malware",
            related_cves=["CVE-2024-21413"],
            geolocation=None,
            reputation=0.02,
        ),
        EnrichedIOC(
            value="https://bct-securite-update.example/login",
            type="url",
            confidence=0.9,
            source="scenario",
            first_seen=base + timedelta(minutes=18),
            threat_type="phishing",
            related_cves=[],
            geolocation="RU",
            reputation=0.05,
        ),
    ]


def _post_incident(incident_json: str) -> tuple[bool, str]:
    """POST a serialized Incident to PC1. Return (ok, message)."""
    url = f"{PC1_BASE_URL}/incidents"
    try:
        response = httpx.post(
            url,
            content=incident_json,
            headers={"Content-Type": "application/json"},
            timeout=HTTP_TIMEOUT_S,
        )
    except httpx.RequestError as exc:
        return False, f"network error contacting {url}: {exc.__class__.__name__}: {exc}"

    body_preview = response.text[:200]
    if response.is_success:
        return True, f"HTTP {response.status_code}  body={body_preview}"
    return False, f"HTTP {response.status_code}  body={body_preview}"


def _write_offline_fallback(incident_json: str) -> Path:
    """Persist the incident JSON locally so PC1 can pick it up later."""
    FALLBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
    FALLBACK_PATH.write_text(incident_json, encoding="utf-8")
    return FALLBACK_PATH


def main() -> int:
    """CLI entrypoint: build mock incident, score, POST or fall back."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    iocs = _build_mock_iocs()
    logger.info("Built %d mock EnrichedIOC(s) (banking phishing burst)", len(iocs))

    incidents = correlator.correlate(iocs)
    if not incidents:
        logger.error("Correlator returned 0 incidents - pipeline misconfigured")
        return 1

    incident = risk_scorer.apply(incidents[0])
    logger.info(
        "Scored incident: id=%s iocs=%d score=%d severity=%s sectors=%s",
        incident.id,
        len(incident.iocs),
        incident.risk_score,
        incident.severity,
        incident.targeted_sectors,
    )

    incident_json = incident.model_dump_json()

    logger.info("POST %s/incidents (timeout=%.1fs)", PC1_BASE_URL, HTTP_TIMEOUT_S)
    ok, message = _post_incident(incident_json)

    if ok:
        logger.info("PC1 accepted the incident: %s", message)
        return 0

    logger.warning("PC1 unreachable or rejected: %s", message)
    fallback = _write_offline_fallback(incident_json)
    logger.warning(
        "Wrote offline fallback to %s - chain valid on PC3 side; PC1 needs to come up.",
        fallback.relative_to(REPO_ROOT),
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
