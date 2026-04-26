"""CSV exporter — flattens incidents and their IOCs into a tabular view.

Used by GET /export/csv. One row per (incident, ioc) pair so analysts can
pivot in Excel. Multi-value fields (mitre_techniques, compliance_breaches,
targeted_assets, related_cves) are joined with ";" inside the cell.

Incidents with zero IOCs still produce a single row with empty IOC columns
so the incident remains visible in the CSV.

The header row is locked — downstream pivot tables in deliverables/
reference these column names verbatim.
"""

from __future__ import annotations

import csv
import io
from typing import List

from shared.schemas import EnrichedIOC, Incident

CSV_HEADERS = [
    "incident_id",
    "severity",
    "risk_score",
    "detected_at",
    "mitre_techniques",
    "compliance_breaches",
    "targeted_assets",
    "targeted_sectors",
    "ioc_value",
    "ioc_type",
    "ioc_threat_type",
    "apt_attribution",
    "confidence",
    "geolocation",
    "reputation",
    "related_cves",
    "first_seen",
    "summary",
]


def _join(values: List[str]) -> str:
    """Join list-of-string fields with ';' for single-cell display."""
    return ";".join(v for v in values if v)


def _ioc_row(incident: Incident, ioc: EnrichedIOC) -> dict:
    return {
        "incident_id": incident.id,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "detected_at": incident.detected_at.isoformat(),
        "mitre_techniques": _join(incident.mitre_techniques),
        "compliance_breaches": _join(incident.compliance_breaches),
        "targeted_assets": _join(incident.targeted_assets),
        "targeted_sectors": _join(incident.targeted_sectors),
        "ioc_value": ioc.value,
        "ioc_type": ioc.type,
        "ioc_threat_type": ioc.threat_type,
        "apt_attribution": ioc.apt_attribution or "",
        "confidence": f"{ioc.confidence:.3f}",
        "geolocation": ioc.geolocation or "",
        "reputation": "" if ioc.reputation is None else f"{ioc.reputation:.3f}",
        "related_cves": _join(ioc.related_cves),
        "first_seen": ioc.first_seen.isoformat(),
        "summary": incident.summary,
    }


def _empty_ioc_row(incident: Incident) -> dict:
    """Row for incidents that carry zero IOCs — preserves the incident in output."""
    return {
        "incident_id": incident.id,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "detected_at": incident.detected_at.isoformat(),
        "mitre_techniques": _join(incident.mitre_techniques),
        "compliance_breaches": _join(incident.compliance_breaches),
        "targeted_assets": _join(incident.targeted_assets),
        "targeted_sectors": _join(incident.targeted_sectors),
        "ioc_value": "",
        "ioc_type": "",
        "ioc_threat_type": "",
        "apt_attribution": "",
        "confidence": "",
        "geolocation": "",
        "reputation": "",
        "related_cves": "",
        "first_seen": "",
        "summary": incident.summary,
    }


def render(incidents: List[Incident]) -> bytes:
    """Serialize incidents to a UTF-8 CSV byte-string ready for download."""
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=CSV_HEADERS, lineterminator="\n")
    writer.writeheader()
    for incident in incidents:
        if not incident.iocs:
            writer.writerow(_empty_ioc_row(incident))
            continue
        for ioc in incident.iocs:
            writer.writerow(_ioc_row(incident, ioc))
    return buf.getvalue().encode("utf-8")
