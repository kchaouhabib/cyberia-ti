"""Phase 1 risk scorer — IOC-count skeleton.

Phase 1 goal: produce a 0-100 risk score and severity label from each
correlated incident, using only the IOC count. This proves the shape of
data flowing through to PC4's dashboard before the real banking-weighted
formula lands in Phase 2.

Phase 2 will replace ``score_incident`` with the full formula:

    risk = severity_factor
         * sector_criticality   # banking 1.0, telecom/healthcare 0.5
         * mean_ioc_confidence
         * compliance_weight    # 1.2 if PCI-DSS scope asset, else 1.0
         * 100

Keep the public API stable (``score_incident(Incident) -> tuple[int, str]``)
so the call site in ``run_phase1_demo.py`` does not need to change.
"""

from __future__ import annotations

import logging

from shared.schemas import Incident

logger = logging.getLogger(__name__)

# Each IOC contributes this many points up to the cap. Tuned so that a
# scenario-injector burst of ~7 IOCs already triggers 'critical'.
POINTS_PER_IOC = 12
MAX_SCORE = 100


def score_incident(incident: Incident) -> tuple[int, str]:
    """Return (risk_score, severity) for an Incident based on IOC count alone.

    Args:
        incident: a correlator-produced Incident. Only ``incident.iocs`` is
            consulted in Phase 1.

    Returns:
        Tuple of:
        - risk_score: integer in [0, 100].
        - severity: one of 'critical' | 'high' | 'medium' | 'low'.
    """
    ioc_count = len(incident.iocs)
    score = min(MAX_SCORE, ioc_count * POINTS_PER_IOC)
    severity = _severity_band(score)
    logger.debug(
        "Incident %s: %d IOC(s) -> score=%d severity=%s",
        incident.id,
        ioc_count,
        score,
        severity,
    )
    return score, severity


def apply(incident: Incident) -> Incident:
    """Return a copy of ``incident`` with ``risk_score`` and ``severity`` set.

    Pydantic v2 ``model_copy`` is used to keep Incident immutable from the
    caller's perspective — the correlator's output is never mutated in place.
    """
    score, severity = score_incident(incident)
    return incident.model_copy(update={"risk_score": score, "severity": severity})


def _severity_band(score: int) -> str:
    """Map a 0-100 score to a 4-bucket severity label.

    Bands chosen to align with PC4's dashboard color coding
    (critical=red, high=orange, medium=yellow, low=blue).
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"
