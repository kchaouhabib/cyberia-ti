"""Phase 2 anomaly detector - Isolation Forest on event volume.

Aggregates events into hourly buckets per group key (source today; will be
asset_type once PC2 lands the field on EnrichedIOC), fits a scikit-learn
IsolationForest, and returns the buckets the model flags as anomalous.

Why per-source today
--------------------
BATTLE_PLAN Phase 2 specifies "per asset type per hour", but ``EnrichedIOC``
doesn't carry ``asset_type`` yet (only ``RawThreatRecord`` does, and PC3
polls the enriched stream). The public functions take a generic
``group_key`` so we can bucket on ``source`` today and swap to asset_type
with a one-line caller change once the schema lands. Algorithm and output
type are unchanged.

Why Isolation Forest
--------------------
Right tool for low-dimensional event-rate anomaly detection: unsupervised,
robust to outliers, fast on small samples, and emits a per-sample anomaly
score we can rank. ``contamination=0.1`` follows the sklearn default.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from shared.schemas import EnrichedIOC

logger = logging.getLogger(__name__)

# Minimum number of hourly buckets needed before we bother fitting IF.
# Below this we return [] - the model has nothing to learn from.
_MIN_BUCKETS_TO_FIT = 3


@dataclass(frozen=True)
class VolumeAnomaly:
    """A flagged hourly bucket. ``score`` is the IsolationForest decision
    function output: more negative = more anomalous."""

    group_key: str
    hour: datetime
    count: int
    score: float


def _floor_to_hour(ts: datetime) -> datetime:
    """Truncate a datetime to the start of its hour, in UTC."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def _aggregate(
    events: Iterable[tuple[datetime, str]],
) -> dict[tuple[str, datetime], int]:
    """Bucket events by (group_key, hour) -> count."""
    buckets: dict[tuple[str, datetime], int] = {}
    for ts, group in events:
        key = (group, _floor_to_hour(ts))
        buckets[key] = buckets.get(key, 0) + 1
    return buckets


def detect_volume_anomalies(
    events: Sequence[tuple[datetime, str]],
    contamination: float = 0.1,
    random_state: int = 42,
) -> list[VolumeAnomaly]:
    """Fit IsolationForest on per-(group, hour) event counts and return anomalies.

    Args:
        events: list of ``(timestamp, group_key)`` tuples. ``group_key`` is
            whatever you want to bucket on - source today, asset_type later.
        contamination: expected fraction of anomalies. Sklearn default 0.1.
        random_state: seed for IsolationForest. Fixed for reproducibility.

    Returns:
        Sorted list of ``VolumeAnomaly`` (most anomalous first). Empty list
        if there are fewer than ``_MIN_BUCKETS_TO_FIT`` distinct buckets -
        IF needs samples to be meaningful, and a hackathon with two events
        does not justify a model.
    """
    buckets = _aggregate(events)
    if len(buckets) < _MIN_BUCKETS_TO_FIT:
        logger.info(
            "Anomaly detector skipped: only %d bucket(s), need >= %d",
            len(buckets),
            _MIN_BUCKETS_TO_FIT,
        )
        return []

    keys = list(buckets.keys())
    counts = np.array([buckets[k] for k in keys], dtype=float).reshape(-1, 1)
    hours_of_day = np.array([k[1].hour for k in keys], dtype=float).reshape(-1, 1)
    weekdays = np.array([k[1].weekday() for k in keys], dtype=float).reshape(-1, 1)

    features = np.hstack([counts, hours_of_day, weekdays])

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(features)
    predictions = model.predict(features)        # 1 = normal, -1 = anomaly
    scores = model.decision_function(features)   # higher = more normal

    anomalies = [
        VolumeAnomaly(
            group_key=keys[i][0],
            hour=keys[i][1],
            count=int(counts[i, 0]),
            score=float(scores[i]),
        )
        for i in range(len(keys))
        if predictions[i] == -1
    ]
    anomalies.sort(key=lambda a: a.score)  # most anomalous first

    logger.info(
        "Anomaly detector: %d bucket(s) examined -> %d anomaly(ies)",
        len(buckets),
        len(anomalies),
    )
    return anomalies


def from_iocs(
    iocs: Iterable[EnrichedIOC],
    group_by: str = "source",
) -> list[VolumeAnomaly]:
    """Convenience wrapper: detect anomalies on a stream of EnrichedIOCs.

    Args:
        iocs: enriched IOCs from PC1 ``GET /iocs/enriched``.
        group_by: 'source' today; once PC2 puts ``asset_type`` on
            EnrichedIOC, switch to 'asset_type' here.

    Returns:
        Same as ``detect_volume_anomalies``.
    """
    if group_by != "source":
        raise NotImplementedError(
            f"group_by={group_by!r} not supported until EnrichedIOC carries that field. "
            "Use 'source' for now."
        )
    events = [(ioc.first_seen, ioc.source) for ioc in iocs]
    return detect_volume_anomalies(events)
