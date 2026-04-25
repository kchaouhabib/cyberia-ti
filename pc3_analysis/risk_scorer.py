"""Phase 2 risk scorer - banking-weighted formula.

Score formula (BATTLE_PLAN.md Phase 2):

    risk = severity_factor
         * sector_criticality      # banking 1.0, telecom/healthcare 0.5
         * mean_ioc_confidence
         * compliance_weight       # 1.2 if PCI-DSS scope asset touched, else 1.0
         * 100                     # scale to 0-100, clamped

Each input is justified:
- severity_factor (0.5-1.0): max over IOC threat_types, encoding "how bad is
  the kind of attack" (phishing 0.5 -> exfiltration 1.0).
- sector_criticality (0.3-1.0): banking primary, telecom/healthcare visible
  in code as scalable architecture, default 0.3 for unknown sectors.
- mean_ioc_confidence (0-1): average IOC.confidence, encoding signal quality.
- compliance_weight: +20% if any targeted asset is in PCI-DSS scope. The
  asset list is whatever ``compliance_mapper.apply`` filled into
  ``incident.targeted_assets``.

Public API stays ``score_incident(Incident) -> tuple[int, str]`` and
``apply(Incident) -> Incident`` so the Phase 1 demo runner does not change.
"""

from __future__ import annotations

import logging

from pc3_analysis import compliance_mapper
from shared.schemas import Incident

logger = logging.getLogger(__name__)

MAX_SCORE = 100

# Threat-type severity weights (max-aggregated across IOCs in an incident).
_THREAT_SEVERITY: dict[str, float] = {
    "phishing": 0.50,
    "malware": 0.70,
    "lateral_movement": 0.80,
    "c2": 0.85,
    "exfiltration": 1.00,
}
_DEFAULT_SEVERITY = 0.40  # unknown / missing threat_type

# Sector criticality - banking is primary; telecom/healthcare are visible in
# code so the jury sees the scalable architecture.
_SECTOR_CRITICALITY: dict[str, float] = {
    "banking": 1.00,
    "telecom": 0.50,
    "healthcare": 0.50,
}
_DEFAULT_SECTOR = 0.30

# Compliance weight applied when any PCI-DSS scope asset is touched.
PCI_DSS_BOOST = 1.20


def _severity_factor(incident: Incident) -> float:
    """Max severity across the incident's IOC threat_types."""
    if not incident.iocs:
        return _DEFAULT_SEVERITY
    return max(
        _THREAT_SEVERITY.get((ioc.threat_type or "").lower(), _DEFAULT_SEVERITY)
        for ioc in incident.iocs
    )


def _sector_factor(incident: Incident) -> float:
    """Max sector_criticality across targeted_sectors. Unknown sector -> default."""
    if not incident.targeted_sectors:
        return _DEFAULT_SECTOR
    return max(
        _SECTOR_CRITICALITY.get(s.lower(), _DEFAULT_SECTOR)
        for s in incident.targeted_sectors
    )


def _mean_confidence(incident: Incident) -> float:
    """Mean IOC.confidence in [0, 1]. Empty incident -> 0."""
    if not incident.iocs:
        return 0.0
    return sum(ioc.confidence for ioc in incident.iocs) / len(incident.iocs)


def _compliance_weight(incident: Incident) -> float:
    """1.2 if any targeted asset is in PCI-DSS scope, else 1.0."""
    if compliance_mapper.is_pci_scope(incident.targeted_assets):
        return PCI_DSS_BOOST
    return 1.0


def score_incident(incident: Incident) -> tuple[int, str]:
    """Return (risk_score, severity) using the full banking-weighted formula.

    Args:
        incident: a correlator-produced Incident. Ideally already MITRE- and
            compliance-tagged so ``targeted_assets`` is populated; if it isn't,
            the compliance_weight degrades gracefully to 1.0.

    Returns:
        Tuple of:
        - risk_score: integer in [0, 100].
        - severity: one of 'critical' | 'high' | 'medium' | 'low'.
    """
    severity = _severity_factor(incident)
    sector = _sector_factor(incident)
    confidence = _mean_confidence(incident)
    compliance = _compliance_weight(incident)

    raw = severity * sector * confidence * compliance * 100
    score = max(0, min(MAX_SCORE, round(raw)))
    severity_label = _severity_band(score)

    logger.debug(
        "Incident %s: sev=%.2f sector=%.2f conf=%.2f comp=%.2f -> score=%d (%s)",
        incident.id,
        severity,
        sector,
        confidence,
        compliance,
        score,
        severity_label,
    )
    return score, severity_label


def apply(incident: Incident) -> Incident:
    """Return a copy of ``incident`` with ``risk_score`` and ``severity`` set.

    Pydantic v2 ``model_copy`` keeps Incident immutable from the caller's
    perspective.
    """
    score, severity = score_incident(incident)
    return incident.model_copy(update={"risk_score": score, "severity": severity})


def _severity_band(score: int) -> str:
    """Map a 0-100 score to a 4-bucket severity label.

    Bands align with PC4's dashboard color coding
    (critical=red, high=orange, medium=yellow, low=blue).
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"
