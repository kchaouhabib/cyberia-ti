"""Phase 1 correlator: groups EnrichedIOCs into Incidents by (source, 1h window).

Algorithm
---------
1. Sort IOCs by ``first_seen`` ascending.
2. Bucket per source. For each IOC, append it to the most recently opened
   bucket for that source if the IOC arrived within 1 hour of the bucket's
   *earliest* member; otherwise open a new bucket.
3. Each bucket becomes one Incident.

This is intentionally minimal for Phase 1. Phase 2 wires in:
- mitre_mapper (fills mitre_techniques)
- compliance_mapper (fills compliance_breaches)
- risk_scorer with the full banking-weighted formula

The outputs of this module conform to ``shared.schemas.Incident`` *as it exists
today*. When PC1 lands the banking-edition schema fields (targeted_assets,
compliance_breaches), update Incident construction below — the rest of the
algorithm is field-agnostic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable
from uuid import uuid4

from shared.schemas import EnrichedIOC, Incident

logger = logging.getLogger(__name__)

CORRELATION_WINDOW = timedelta(hours=1)


@dataclass
class _Bucket:
    """Internal mutable bucket used during correlation. Not exported."""

    source: str
    earliest: datetime
    iocs: list[EnrichedIOC] = field(default_factory=list)


def correlate(iocs: Iterable[EnrichedIOC]) -> list[Incident]:
    """Group enriched IOCs into Incidents.

    Args:
        iocs: any iterable of EnrichedIOC (order does not matter; we sort).

    Returns:
        List of Incident objects, one per (source, rolling 1-hour) bucket.
        ``mitre_techniques`` is empty (Phase 2 fills it).
        ``risk_score`` is 0 and ``severity`` is ``"low"`` (the risk_scorer
        downstream rewrites both based on IOC count + sector + confidence).
    """
    sorted_iocs = sorted(iocs, key=lambda ioc: ioc.first_seen)
    buckets_by_source: dict[str, list[_Bucket]] = {}

    for ioc in sorted_iocs:
        source_buckets = buckets_by_source.setdefault(ioc.source, [])
        if source_buckets and (ioc.first_seen - source_buckets[-1].earliest) <= CORRELATION_WINDOW:
            source_buckets[-1].iocs.append(ioc)
        else:
            source_buckets.append(
                _Bucket(source=ioc.source, earliest=ioc.first_seen, iocs=[ioc])
            )

    incidents: list[Incident] = []
    for source_buckets in buckets_by_source.values():
        for bucket in source_buckets:
            incidents.append(_bucket_to_incident(bucket))

    total_iocs = sum(len(b.iocs) for bs in buckets_by_source.values() for b in bs)
    logger.info(
        "Correlated %d IOC(s) into %d incident(s) across %d source(s)",
        total_iocs,
        len(incidents),
        len(buckets_by_source),
    )
    return incidents


def _bucket_to_incident(bucket: _Bucket) -> Incident:
    """Build a Phase 1 Incident from a correlation bucket.

    Phase 1 fills only fields the basic correlator can know:
    - id, iocs, detected_at (= bucket.earliest)
    - targeted_sectors: ['banking'] when source == 'scenario' (the bank-attack
      injector targets banking by definition); empty otherwise. PC2's
      classifier provides sector for OSINT records in Phase 2.
    - summary: a placeholder string. PC2's LLM summarizer rewrites this in
      Phase 3.
    - mitre_techniques: empty (mitre_mapper, Phase 2)
    - risk_score / severity: dummies overwritten by risk_scorer in the same
      Phase 1 pipeline.
    """
    targeted_sectors = ["banking"] if bucket.source == "scenario" else []

    return Incident(
        id=str(uuid4()),
        iocs=bucket.iocs,
        mitre_techniques=[],
        targeted_sectors=targeted_sectors,
        risk_score=0,
        severity="low",
        summary=(
            f"{len(bucket.iocs)} IOC(s) from '{bucket.source}' within 1h window "
            f"starting {bucket.earliest.isoformat()}"
        ),
        detected_at=bucket.earliest,
    )
