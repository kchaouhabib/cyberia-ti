"""Phase 3 CVE prioritizer - banking-weighted ranking.

Ranks CVEs surfaced in the live IOC stream by a multiplicative score:

    priority = recency * severity * frequency * banking_stack_boost

Each factor is in [0, 1] except ``banking_stack_boost`` which is in [1.0, 2.0].
The product is scaled to 0-100 so PC4 can render it as a heatmap value.

Why a sibling of ``predictor.py``
----------------------------------
``shared.schemas.Prediction`` only has 5 fields (sector, threat_type,
forecast_7d, trend, confidence). To stay inside the locked contract we encode
each ranked CVE as a ``Prediction`` row with ``threat_type='cve:CVE-YYYY-NNNN'``.
PC4 switches on the ``cve:`` prefix and renders a "patch this first" panel.
``forecast_7d`` is repurposed here as the 0-100 priority score because the
schema has no generic numeric field; the prefix tells PC4 to read it that way.

Banking-tech-stack boost
------------------------
We multiply the score by ``_BANKING_STACK_BOOST`` when the CVE id or any IOC
text mentioning it references stacks our target banks actually run:

    Oracle DB / Oracle WebLogic / Java / OpenJDK
    Temenos T24 / Temenos Transact
    Finastra / Misys / Fusion
    SWIFT Alliance / SWIFT messaging
    Spring Framework, Apache (common in banking middleware)

These keywords are coarse on purpose - the goal is to surface "Temenos
RCE just got reported" before generic CVEs, not to do exhaustive CPE matching.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

from shared.schemas import EnrichedIOC, Prediction

logger = logging.getLogger(__name__)

_CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_BANKING_STACK_KEYWORDS = re.compile(
    r"\b("
    r"oracle|weblogic|java|openjdk|"
    r"temenos|t24|transact|"
    r"finastra|misys|fusion|"
    r"swift|alliance\s?gateway|alliance\s?access|sag|saa|"
    r"spring|springboot|spring[-_]framework|"
    r"apache|tomcat|struts|"
    r"finacle|infosys|"
    r"jboss|wildfly"
    r")\b",
    re.IGNORECASE,
)

_BANKING_STACK_BOOST = 2.0
_MAX_RECENCY_DAYS = 90
_TOP_N_DEFAULT = 10
_MAX_SCORE = 100.0


@dataclass(frozen=True)
class _CveAggregate:
    """Per-CVE rollup of the IOCs that mention it."""

    cve_id: str
    iocs: list[EnrichedIOC]
    earliest_seen: datetime
    latest_seen: datetime
    text_blob: str


def _to_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _extract_cves(ioc: EnrichedIOC) -> set[str]:
    """Pull CVE ids from an IOC: explicit type='cve', related_cves list,
    and any CVE-shaped substring in the value."""
    found: set[str] = set()

    if ioc.type == "cve":
        found.add(ioc.value.upper())

    for cve in ioc.related_cves or []:
        if _CVE_REGEX.fullmatch(cve.strip()):
            found.add(cve.upper())

    for match in _CVE_REGEX.findall(ioc.value or ""):
        found.add(match.upper())

    return found


def _aggregate(iocs: Sequence[EnrichedIOC]) -> list[_CveAggregate]:
    grouped: dict[str, list[EnrichedIOC]] = defaultdict(list)
    for ioc in iocs:
        for cve in _extract_cves(ioc):
            grouped[cve].append(ioc)

    aggregates: list[_CveAggregate] = []
    for cve_id, related in grouped.items():
        seen_dates = [_to_utc(i.first_seen) for i in related]
        text_blob = " ".join(
            [cve_id]
            + [(i.value or "") for i in related]
            + [(i.source or "") for i in related]
        )
        aggregates.append(
            _CveAggregate(
                cve_id=cve_id,
                iocs=related,
                earliest_seen=min(seen_dates),
                latest_seen=max(seen_dates),
                text_blob=text_blob,
            )
        )
    return aggregates


def _recency_factor(latest_seen: datetime, now: datetime) -> float:
    """1.0 for seen-today, decays linearly to 0 at ``_MAX_RECENCY_DAYS``."""
    age_days = max(0.0, (now - latest_seen).total_seconds() / 86400.0)
    if age_days >= _MAX_RECENCY_DAYS:
        return 0.0
    return 1.0 - (age_days / _MAX_RECENCY_DAYS)


def _severity_factor(iocs: Sequence[EnrichedIOC]) -> float:
    """EnrichedIOC has no CVSS field; we use mean ``confidence`` as a severity
    proxy. PC2's classifier is calibrated so high-confidence threats correlate
    with high severity in practice."""
    if not iocs:
        return 0.0
    return sum(i.confidence for i in iocs) / len(iocs)


def _frequency_factor(n_iocs: int, max_observed: int) -> float:
    """Normalised frequency in [0, 1] within the current batch."""
    if max_observed <= 0:
        return 0.0
    return min(1.0, n_iocs / max_observed)


def _banking_stack_boost(text_blob: str) -> float:
    return _BANKING_STACK_BOOST if _BANKING_STACK_KEYWORDS.search(text_blob) else 1.0


def prioritize(
    iocs: Iterable[EnrichedIOC],
    top_n: int = _TOP_N_DEFAULT,
    now: datetime | None = None,
) -> list[Prediction]:
    """Return the top-N CVEs ranked by banking-weighted priority.

    Args:
        iocs: enriched IOCs from the live PC1 stream.
        top_n: how many CVEs to emit (default ``_TOP_N_DEFAULT``).
        now: override "current time" for deterministic tests.

    Returns:
        Sorted list of ``Prediction`` rows (highest priority first), each with
        ``threat_type='cve:CVE-YYYY-NNNN'`` and ``forecast_7d`` carrying the
        0-100 priority score.
    """
    aggregates = _aggregate(list(iocs))
    if not aggregates:
        logger.info("CVE prioritizer: no CVEs found in IOC stream.")
        return []

    now_utc = _to_utc(now) if now else datetime.now(timezone.utc)
    max_freq = max(len(agg.iocs) for agg in aggregates)

    scored: list[tuple[_CveAggregate, float, float]] = []
    for agg in aggregates:
        recency = _recency_factor(agg.latest_seen, now_utc)
        severity = _severity_factor(agg.iocs)
        frequency = _frequency_factor(len(agg.iocs), max_freq)
        boost = _banking_stack_boost(agg.text_blob)

        raw = recency * severity * frequency * boost
        score = round(min(_MAX_SCORE, raw * _MAX_SCORE), 2)
        confidence = round(min(1.0, recency * severity * frequency), 3)
        scored.append((agg, score, confidence))

    scored.sort(key=lambda x: x[1], reverse=True)
    top = scored[:top_n]

    predictions = [
        Prediction(
            sector="banking",
            threat_type=f"cve:{agg.cve_id}",
            forecast_7d=score,
            trend="stable",
            confidence=confidence,
        )
        for agg, score, confidence in top
    ]

    logger.info(
        "CVE prioritizer: %d CVE(s) found -> top %d emitted (highest score=%.1f)",
        len(aggregates),
        len(predictions),
        predictions[0].forecast_7d if predictions else 0.0,
    )
    return predictions
