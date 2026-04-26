"""
Summary worker — PC2, Phase 3.

Polls GET /incidents every cycle, finds any incident whose summary is still
the generic correlator text ("N IOC(s) from ..."), runs the LLM summarizer,
and re-POSTs the incident so PC1 overwrites it in place (UPSERT on id).

PC1's PDF report uses Incident.summary as the executive summary header —
this turns that from "141 IOC(s) from urlhaus..." into a real CISO paragraph.
"""

import logging
import re
from collections import Counter
from typing import Optional

import httpx

from pc2_ai.llm_summarizer import summarize_incident
from shared.schemas import Incident

log = logging.getLogger(__name__)

_GENERIC_SUMMARY_RE = re.compile(r"\d+\s+IOC\(s\)\s+from\s+", re.IGNORECASE)

HTTP_TIMEOUT = 10.0


def _is_generic(summary: str) -> bool:
    return bool(_GENERIC_SUMMARY_RE.search(summary))


def _dominant(values: list[str | None]) -> Optional[str]:
    """Return the most common non-None value, or None if all are None."""
    filtered = [v for v in values if v]
    if not filtered:
        return None
    return Counter(filtered).most_common(1)[0][0]


def _build_summary(incident: Incident) -> str:
    """Derive summarizer inputs from a fully-tagged Incident and call the LLM."""
    threat_type  = _dominant([ioc.threat_type for ioc in incident.iocs]) or "unknown"
    apt_attr     = _dominant([ioc.apt_attribution for ioc in incident.iocs])
    assets       = incident.targeted_assets or ["unspecified assets"]
    severity     = incident.severity or "high"

    return summarize_incident(
        threat_type=threat_type,
        targeted_assets=assets,
        risk_score=incident.risk_score,
        severity=severity,
        mitre_techniques=incident.mitre_techniques,
        compliance_breaches=incident.compliance_breaches,
        ioc_count=len(incident.iocs),
        apt_attribution=apt_attr,
        raw_summary=incident.summary[:500],
    )


def patch_generic_summaries(pc1_base: str) -> int:
    """
    One pass: fetch all incidents, replace generic summaries with LLM paragraphs.
    Returns the number of incidents patched.
    """
    try:
        resp = httpx.get(f"{pc1_base}/incidents", timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        incidents = [Incident(**row) for row in resp.json()]
    except Exception as e:
        log.warning(f"Could not fetch incidents: {e}")
        return 0

    patched = 0
    for incident in incidents:
        if not _is_generic(incident.summary):
            continue

        log.info(f"Generating CISO summary for incident {incident.id[:8]}...")
        new_summary = _build_summary(incident)
        updated = incident.model_copy(update={"summary": new_summary})

        try:
            r = httpx.post(
                f"{pc1_base}/incidents",
                content=updated.model_dump_json(),
                headers={"Content-Type": "application/json"},
                timeout=HTTP_TIMEOUT,
            )
            r.raise_for_status()
            patched += 1
            log.info(
                f"Patched incident {incident.id[:8]}  "
                f"threat={_dominant([i.threat_type for i in incident.iocs])}  "
                f"risk={incident.risk_score}"
            )
        except Exception as e:
            log.error(f"Failed to update incident {incident.id[:8]}: {e}")

    return patched
