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
import re
import sys
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pc3_analysis import (  # noqa: E402
    anomaly_detector,
    behavior_analyzer,
    compliance_mapper,
    correlator,
    cve_prioritizer,
    mitre_mapper,
    predictor,
    risk_scorer,
)
from shared.schemas import EnrichedIOC, Incident, Prediction  # noqa: E402

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


# Matches the generic correlator-built summary ("141 IOC(s) from 'urlhaus'...").
# Same regex PC2's summary_worker uses, so we agree on what "generic" means and
# never accidentally treat a CISO paragraph as generic.
_GENERIC_SUMMARY_RE = re.compile(r"\d+\s+IOC\(s\)\s+from\s+", re.IGNORECASE)


def _preserve_existing_summary(client: httpx.Client, incident: Incident) -> Incident:
    """Return ``incident`` with PC1's existing CISO summary preserved if any.

    Without this, PC3 re-pushes the generic correlator summary every cycle and
    clobbers the CISO paragraph that PC2's summary_worker writes - making PC4's
    AI-summary card flicker between generic and patched text on every poll.

    Behaviour:
      * 404 / new incident: return ``incident`` unchanged (PC2 will patch it
        on its next worker cycle, just like before).
      * Existing summary still generic: return unchanged (nothing to preserve).
      * Existing summary non-generic: copy it onto our locally-built incident.
      * Network error: swallow and return unchanged - graceful degradation.
    """
    try:
        response = client.get(
            f"{PC1_BASE_URL}/incidents/{incident.id}",
            timeout=HTTP_TIMEOUT_S,
        )
        if response.status_code == 200:
            existing = Incident(**response.json())
            if existing.summary and not _GENERIC_SUMMARY_RE.search(existing.summary):
                return incident.model_copy(update={"summary": existing.summary})
    except httpx.HTTPError:
        pass
    return incident


def _push_prediction(client: httpx.Client, prediction: Prediction) -> None:
    """POST a Prediction (volume forecast / cve:* / apt:*).

    PC1 UPSERTs on (sector, threat_type) so re-posting overwrites the previous
    forecast row - exactly the behaviour we want, since each cycle re-derives
    the prediction from the current IOC/incident state.
    """
    response = client.post(
        f"{PC1_BASE_URL}/predictions",
        content=prediction.model_dump_json(),
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
        enriched_incidents: list[Incident] = []
        for incident in incidents:
            tagged = _enrich_incident(incident)
            tagged = _preserve_existing_summary(client, tagged)
            enriched_incidents.append(tagged)
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
        # correlation. Each flagged bucket is logged AND pushed as an
        # ``anomaly:<source>`` Prediction so PC4 can render volume spikes
        # alongside the other prediction kinds.
        anomalies = anomaly_detector.from_iocs(iocs, group_by="source")
        anomaly_predictions: list[Prediction] = []
        for a in anomalies:
            logger.warning(
                "VOLUME ANOMALY  group=%s  hour=%s  count=%d  score=%.3f",
                a.group_key,
                a.hour.isoformat(),
                a.count,
                a.score,
            )
            # IsolationForest decision_function is more negative for stronger
            # anomalies; flip sign and clip to [0, 100] for a forecast_7d
            # value PC4 can render as a 0-100 strength indicator.
            strength = round(min(100.0, max(0.0, -a.score * 100.0)), 2)
            confidence = round(min(1.0, max(0.0, -a.score)), 3)
            anomaly_predictions.append(
                Prediction(
                    sector="banking",
                    threat_type=f"anomaly:{a.group_key}",
                    forecast_7d=strength,
                    trend="rising",
                    confidence=confidence,
                )
            )

        # Phase 3: forecast volume, rank CVEs, match APT signatures. All three
        # producers emit Prediction rows; we POST them via the same UPSERT
        # endpoint. Failures on individual rows are logged but don't abort the
        # cycle - a flaky CVE row should not lose us our Prophet forecast.
        predictions: list[Prediction] = []
        try:
            predictions.extend(predictor.forecast(iocs))
        except Exception:
            logger.exception("Predictor failed; skipping volume forecasts this cycle")
        try:
            predictions.extend(cve_prioritizer.prioritize(iocs))
        except Exception:
            logger.exception("CVE prioritizer failed; skipping CVE rankings this cycle")
        try:
            # behavior_analyzer keys off mitre_techniques and targeted_assets,
            # so we feed it the enriched incidents we already computed above.
            predictions.extend(behavior_analyzer.analyze(enriched_incidents))
        except Exception:
            logger.exception("Behavior analyzer failed; skipping APT matches this cycle")

        predictions.extend(anomaly_predictions)

        for prediction in predictions:
            try:
                _push_prediction(client, prediction)
                logger.info(
                    "Pushed prediction  sector=%s  type=%s  forecast_7d=%.2f  trend=%s  conf=%.2f",
                    prediction.sector,
                    prediction.threat_type,
                    prediction.forecast_7d,
                    prediction.trend,
                    prediction.confidence,
                )
            except httpx.HTTPError as exc:
                logger.error(
                    "Failed to push prediction %s/%s: %s",
                    prediction.sector,
                    prediction.threat_type,
                    exc,
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
