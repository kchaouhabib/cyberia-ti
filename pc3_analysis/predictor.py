"""Phase 3 time-series forecaster - 7-day attack volume per (sector, threat_type).

Fits a Prophet model on daily IOC counts grouped by (sector, threat_type) and
returns a ``Prediction`` for each series with a 7-day forward forecast plus a
qualitative ``trend`` label (rising / stable / falling).

Why this layout
---------------
``shared.schemas.Prediction`` only carries ``sector``, ``threat_type``,
``forecast_7d``, ``trend``, ``confidence``. That maps cleanly onto a volume
forecast - one row per (sector, threat_type). CVE rankings and APT campaign
matches go in sibling modules and are also encoded as ``Prediction`` rows but
with a prefixed ``threat_type`` (e.g. ``cve:CVE-2024-1234`` or ``apt:fin7``)
so PC4 can switch on the prefix to pick the right card.

Why graceful degradation
------------------------
Prophet's documented minimum is ~30 daily points; a hackathon demo with a
few hours of live data will be way under that. Series with fewer than
``_MIN_POINTS_FOR_PROPHET`` points fall back to a flat-rate forecast so we
still emit *something* for PC4 to show. Series with effectively no signal
(< ``_MIN_POINTS_TO_EMIT``) are skipped entirely.

Why scikit-learn fallback
-------------------------
Prophet on Windows depends on cmdstanpy and can fail to install/import. If
the import fails we drop to a sklearn ``LinearRegression`` slope fit - same
output shape, lower fidelity, but the pipeline still produces predictions.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

import numpy as np

from shared.schemas import EnrichedIOC, Prediction

logger = logging.getLogger(__name__)

try:
    from prophet import Prophet  # type: ignore[import-not-found]

    _HAS_PROPHET = True
except Exception as exc:  # pragma: no cover - install-environment dependent
    Prophet = None  # type: ignore[assignment,misc]
    _HAS_PROPHET = False
    logger.warning("Prophet unavailable (%s) - falling back to sklearn linear trend", exc)

from sklearn.linear_model import LinearRegression

# Day-1 emit threshold: even a single day's data produces a flat forecast so
# PC4 never sees an empty predictions panel during the demo. Series with zero
# points are still skipped (no signal).
_MIN_POINTS_TO_EMIT = 1
_MIN_POINTS_FOR_PROPHET = 7
_HORIZON_DAYS = 7
_TREND_BAND = 0.10

_BANKING_FILTERED_SOURCES: frozenset[str] = frozenset(
    {"otx", "urlhaus", "threatfox", "malwarebazaar", "misp", "scenario"}
)


@dataclass(frozen=True)
class _Series:
    sector: str
    threat_type: str
    daily_counts: list[tuple[datetime, int]]


def _infer_sector(ioc: EnrichedIOC) -> str:
    """Until EnrichedIOC carries ``sector``, use the same banking heuristic
    the pipeline uses for incident sector tagging."""
    if ioc.source in _BANKING_FILTERED_SOURCES:
        return "banking"
    return "unknown"


def _floor_to_day(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _build_series(iocs: Sequence[EnrichedIOC]) -> list[_Series]:
    """Aggregate IOCs into per-(sector, threat_type) daily count series."""
    buckets: dict[tuple[str, str], dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
    for ioc in iocs:
        threat = (ioc.threat_type or "unknown").lower()
        if threat == "unknown":
            continue
        sector = _infer_sector(ioc)
        day = _floor_to_day(ioc.first_seen)
        buckets[(sector, threat)][day] += 1

    series: list[_Series] = []
    for (sector, threat), days in buckets.items():
        ordered = sorted(days.items())
        series.append(_Series(sector=sector, threat_type=threat, daily_counts=ordered))
    return series


def _trend_label(history_total: float, forecast_total: float) -> str:
    if history_total <= 0:
        return "stable"
    delta = (forecast_total - history_total) / history_total
    if delta > _TREND_BAND:
        return "rising"
    if delta < -_TREND_BAND:
        return "falling"
    return "stable"


def _forecast_with_prophet(series: _Series) -> tuple[float, float]:
    """Return (forecast_7d_total, confidence_in_[0,1]) using Prophet."""
    import pandas as pd

    df = pd.DataFrame(
        [{"ds": day, "y": count} for day, count in series.daily_counts]
    )
    if df["ds"].dt.tz is not None:
        df["ds"] = df["ds"].dt.tz_convert(None)
    else:
        df["ds"] = df["ds"].dt.tz_localize(None)

    model = Prophet(
        daily_seasonality=False,
        weekly_seasonality=True,
        yearly_seasonality=False,
        interval_width=0.80,
    )
    model.fit(df)

    future = model.make_future_dataframe(periods=_HORIZON_DAYS, freq="D")
    forecast = model.predict(future)
    forward = forecast.tail(_HORIZON_DAYS)
    forecast_total = float(max(0.0, forward["yhat"].sum()))

    spread = (forward["yhat_upper"] - forward["yhat_lower"]).clip(lower=0.0).mean()
    base = max(forward["yhat"].abs().mean(), 1.0)
    rel_spread = float(min(spread / base, 5.0))
    confidence = float(max(0.10, min(0.95, 1.0 - rel_spread / 5.0)))
    return forecast_total, confidence


def _forecast_with_linear(series: _Series) -> tuple[float, float]:
    """Sklearn linear-regression fallback. Returns (forecast_7d_total, confidence)."""
    days = np.array(
        [(d - series.daily_counts[0][0]).days for d, _ in series.daily_counts]
    ).reshape(-1, 1)
    counts = np.array([c for _, c in series.daily_counts], dtype=float)

    model = LinearRegression()
    model.fit(days, counts)
    last_day_idx = int(days[-1][0])
    future_idx = np.array(
        range(last_day_idx + 1, last_day_idx + 1 + _HORIZON_DAYS)
    ).reshape(-1, 1)
    preds = model.predict(future_idx)
    forecast_total = float(max(0.0, preds.sum()))

    r2 = float(model.score(days, counts)) if len(days) >= 2 else 0.0
    confidence = float(max(0.10, min(0.85, (r2 + 1.0) / 2.0)))
    return forecast_total, confidence


def _flat_forecast(series: _Series) -> tuple[float, float]:
    """Last-resort: project the historical mean rate forward for 7 days."""
    if not series.daily_counts:
        return 0.0, 0.10
    mean_per_day = sum(c for _, c in series.daily_counts) / max(len(series.daily_counts), 1)
    return float(mean_per_day * _HORIZON_DAYS), 0.20


def forecast(iocs: Iterable[EnrichedIOC]) -> list[Prediction]:
    """Return a list of 7-day Predictions, one per (sector, threat_type) series.

    Args:
        iocs: enriched IOCs (typically the full live set from PC1).

    Returns:
        Sorted list of Predictions (highest forecast volume first).
    """
    series_list = _build_series(list(iocs))
    if not series_list:
        logger.info("Predictor: no series to forecast (no IOCs with threat_type).")
        return []

    predictions: list[Prediction] = []
    for series in series_list:
        n_points = len(series.daily_counts)
        if n_points < _MIN_POINTS_TO_EMIT:
            logger.debug(
                "Skipping series sector=%s threat=%s: only %d day(s) of history",
                series.sector,
                series.threat_type,
                n_points,
            )
            continue

        if n_points >= _MIN_POINTS_FOR_PROPHET and _HAS_PROPHET:
            try:
                forecast_total, confidence = _forecast_with_prophet(series)
            except Exception as exc:  # pragma: no cover
                logger.warning(
                    "Prophet failed for sector=%s threat=%s (%s); falling back to linear",
                    series.sector,
                    series.threat_type,
                    exc,
                )
                forecast_total, confidence = _forecast_with_linear(series)
        elif n_points >= _MIN_POINTS_FOR_PROPHET:
            forecast_total, confidence = _forecast_with_linear(series)
        else:
            forecast_total, confidence = _flat_forecast(series)

        recent_days = series.daily_counts[-_HORIZON_DAYS:]
        history_total = float(sum(c for _, c in recent_days))
        trend = _trend_label(history_total, forecast_total)

        predictions.append(
            Prediction(
                sector=series.sector,
                threat_type=series.threat_type,
                forecast_7d=round(forecast_total, 2),
                trend=trend,
                confidence=round(confidence, 3),
            )
        )

    predictions.sort(key=lambda p: p.forecast_7d, reverse=True)
    logger.info(
        "Predictor: emitted %d forecast(s) (prophet=%s)",
        len(predictions),
        _HAS_PROPHET,
    )
    return predictions
