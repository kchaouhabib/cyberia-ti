"""PC3 live pipeline - Phase 2.

Polls PC1 ``GET /iocs/enriched`` every ``POLL_INTERVAL_SECONDS``, runs the
full PC3 stack (correlate -> MITRE-tag -> compliance-tag -> risk-score),
and POSTs the resulting Incidents back to PC1 ``POST /incidents``. Also
runs the Isolation Forest anomaly detector each cycle and logs flagged
hourly buckets.

Mirrors PC2's pipeline pattern:

    PC1_BASE_URL              http://100.67.61.250:8000  (NetBird)
    POLL_INTERVAL_SECONDS     10

Run as:
    .venv/Scripts/python.exe -m pc3_analysis.pipeline                # loop
    .venv/Scripts/python.exe -m pc3_analysis.pipeline --once         # one shot
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pc3_analysis import (  # noqa: E402
    anomaly_detector,
    compliance_mapper,
    correlator,
    mitre_mapper,
    risk_scorer,
)
from shared.schemas import EnrichedIOC, Incident  # noqa: E402

logger = logging.getLogger(__name__)

PC1_BASE_URL = os.environ.get("PC1_BASE_URL", "http://100.67.61.250:8000").rstrip("/")
POLL_INTERVAL_S = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))
HTTP_TIMEOUT_S = 10.0


# ──────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────────


def _fetch_enriched_iocs(client: httpx.Client) -> list[EnrichedIOC]:
    """GET /iocs/enriched and parse into EnrichedIOC objects."""
    response = client.get(f"{PC1_BASE_URL}/iocs/enriched", timeout=HTTP_TIMEOUT_S)
    response.raise_for_status()
    return [EnrichedIOC(**row) for row in response.json()]


def _push_incident(client: httpx.Client, incident: Incident) -> None:
    """POST a fully-tagged Incident. PC1 UPSERTs on id, so re-posting is safe."""
    response = client.post(
        f"{PC1_BASE_URL}/incidents",
        content=incident.model_dump_json(),
        headers={"Content-Type": "application/json"},
        timeout=HTTP_TIMEOUT_S,
    )
    response.raise_for_status()


# ──────────────────────────────────────────────────────────────────────────
# Deterministic incident IDs
# ──────────────────────────────────────────────────────────────────────────


def _stable_incident_id(incident: Incident) -> str:
    """Derive a UUID-shaped, deterministic ID from the incident's bucket signature.

    We re-correlate every cycle. Without a stable ID, PC1's UPSERT-on-id behaviour
    would create a new incident row each tick. Hash the (source + earliest_seen
    + sorted IOC fingerprints) so the same bucket always lands on the same row.
    """
    if not incident.iocs:
        seed = f"empty|{incident.detected_at.isoformat()}"
    else:
        ioc_fingerprints = sorted(f"{i.value}::{i.type}" for i in incident.iocs)
        seed = (
            f"{incident.iocs[0].source}"
            f"|{incident.detected_at.isoformat()}"
            f"|{'|'.join(ioc_fingerprints)}"
        )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


# ──────────────────────────────────────────────────────────────────────────
# One pass of the pipeline
# ──────────────────────────────────────────────────────────────────────────


# PC1 explicitly banking-filters every collector (otx, urlhaus, threatfox,
# malwarebazaar, misp) and the scenario injector targets banking by design,
# so any IOC reaching us is in-scope for the banking sector. This is the
# pragmatic fix until PC1 denormalizes ``RawThreatRecord.sector`` onto
# ``EnrichedIOC`` (a one-line schema change).
_BANKING_FILTERED_SOURCES: frozenset[str] = frozenset(
    {"otx", "urlhaus", "threatfox", "malwarebazaar", "misp", "scenario"}
)


def _enrich_incident(incident: Incident) -> Incident:
    """Apply sector heuristic -> MITRE -> compliance -> risk. Returns a new copy."""
    sectors = list(incident.targeted_sectors)
    if not sectors and incident.iocs and incident.iocs[0].source in _BANKING_FILTERED_SOURCES:
        sectors = ["banking"]

    incident = incident.model_copy(
        update={
            "id": _stable_incident_id(incident),
            "targeted_sectors": sectors,
        }
    )
    incident = mitre_mapper.apply(incident)
    incident = compliance_mapper.apply(incident)
    incident = risk_scorer.apply(incident)
    return incident


def run_once() -> int:
    """Run a single end-to-end pass.

    Returns the number of incidents successfully POSTed to PC1.
    """
    with httpx.Client() as client:
        iocs = _fetch_enriched_iocs(client)
        if not iocs:
            logger.info(
                "No enriched IOCs in PC1 yet (PC2 has not shipped any). "
                "Skipping correlation."
            )
            return 0

        logger.info("Fetched %d enriched IOC(s) from PC1", len(iocs))

        incidents = correlator.correlate(iocs)
        if not incidents:
            logger.info("Correlator produced 0 incidents from %d IOCs", len(iocs))
            return 0

        pushed = 0
        for incident in incidents:
            tagged = _enrich_incident(incident)
            try:
                _push_incident(client, tagged)
                pushed += 1
                logger.info(
                    "Pushed incident %s  iocs=%d  score=%d/%s  mitre=%s  compliance=%s  assets=%s",
                    tagged.id[:8] + "...",
                    len(tagged.iocs),
                    tagged.risk_score,
                    tagged.severity,
                    tagged.mitre_techniques,
                    tagged.compliance_breaches,
                    tagged.targeted_assets,
                )
            except httpx.HTTPError as exc:
                logger.error(
                    "Failed to push incident %s: %s",
                    tagged.id[:8] + "...",
                    exc,
                )

        # Anomaly detection runs on the same pulled IOC set, independent of
        # correlation. Logged for now; Phase 3 will surface this on the dashboard.
        anomalies = anomaly_detector.from_iocs(iocs, group_by="source")
        for a in anomalies:
            logger.warning(
                "VOLUME ANOMALY  group=%s  hour=%s  count=%d  score=%.3f",
                a.group_key,
                a.hour.isoformat(),
                a.count,
                a.score,
            )

        return pushed


# ──────────────────────────────────────────────────────────────────────────
# Loop driver
# ──────────────────────────────────────────────────────────────────────────


def run_loop() -> None:
    """Poll forever. Resilient to transient PC1 outages."""
    logger.info(
        "PC3 pipeline starting -> %s  poll=%ds",
        PC1_BASE_URL,
        POLL_INTERVAL_S,
    )
    while True:
        try:
            pushed = run_once()
            logger.info("Cycle done: %d incident(s) pushed", pushed)
        except httpx.ConnectError:
            logger.warning(
                "Cannot reach PC1 at %s - retrying in %ds",
                PC1_BASE_URL,
                POLL_INTERVAL_S,
            )
        except Exception:
            logger.exception("Unexpected error in pipeline cycle")
        time.sleep(POLL_INTERVAL_S)


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="PC3 live correlation + scoring pipeline")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single pass and exit (default: poll forever).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.once:
        pushed = run_once()
        return 0 if pushed >= 0 else 1

    run_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
