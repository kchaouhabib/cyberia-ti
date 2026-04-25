"""Phase 3 behavior analyzer - rule-based APT matching + KMeans clustering.

Two-track output (both encoded as ``Prediction`` rows with
``threat_type='apt:<label>'``):

1. **Rule-based APT matching** (always runs).
   For each financial APT we know, define a TTP signature - a small set of
   MITRE technique IDs that the group is known for. Score each incident's
   technique overlap with each signature. If >=1 incident overlaps strongly,
   emit a Prediction. This is deterministic and works on day-1 with as little
   as one incident; clustering doesn't.

2. **KMeans clustering** (runs when there are enough incidents).
   Build a binary feature vector per incident (technique flags + asset flags
   + sector flag + ioc-volume bucket). Run KMeans with ``k = min(_MAX_K, n)``.
   If a cluster contains >=``_MIN_CLUSTER_SIZE`` incidents, emit a Prediction
   tagged ``apt:cluster-<n>`` with confidence proportional to cluster
   tightness. PC4 can render this as "we found a coordinated campaign".

Why rule-based primary
----------------------
At hackathon scale (handful of incidents) KMeans is statistically meaningless;
financial APT groups have distinctive technique fingerprints that are easy to
encode. We get a defensible "FIN7 match detected" the moment one incident
shows phishing + valid accounts + exfiltration. The clustering layer only
adds value once enough incidents accumulate to find unknown coordinated
patterns.

APT signatures
--------------
Sources: MITRE ATT&CK Group pages plus FS-ISAC reports. Kept conservative -
each signature is the *minimal* technique set strongly associated with the
group. Better to miss a match than to over-attribute.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np
from sklearn.cluster import KMeans

from shared.schemas import Incident, Prediction

logger = logging.getLogger(__name__)

_MIN_OVERLAP = 0.66
_MIN_INCIDENTS_FOR_KMEANS = 4
_MAX_K = 3
_MIN_CLUSTER_SIZE = 2
_MAX_SCORE = 100.0


@dataclass(frozen=True)
class _AptSignature:
    name: str
    techniques: frozenset[str]
    note: str


_APT_SIGNATURES: tuple[_AptSignature, ...] = (
    _AptSignature(
        name="fin7",
        techniques=frozenset({"T1566", "T1078", "T1041"}),
        note="phishing -> valid accounts -> exfiltration (FIN7 textbook)",
    ),
    _AptSignature(
        name="lazarus",
        techniques=frozenset({"T1190", "T1078", "T1041"}),
        note="exploit public-facing app -> valid accounts -> exfil",
    ),
    _AptSignature(
        name="carbanak",
        techniques=frozenset({"T1566", "T1078", "T1486"}),
        note="phishing -> valid accounts -> ransomware",
    ),
    _AptSignature(
        name="silence",
        techniques=frozenset({"T1566", "T1071"}),
        note="phishing into long-haul C2 (Silence-style implant)",
    ),
    _AptSignature(
        name="cobalt-group",
        techniques=frozenset({"T1566", "T1078", "T1041"}),
        note="phishing-led campaigns vs SWIFT / payment switches",
    ),
)


def _match_signature(incident: Incident, sig: _AptSignature) -> float:
    """Return overlap fraction in [0, 1]: matched_techniques / signature_size."""
    if not sig.techniques:
        return 0.0
    techniques = set(incident.mitre_techniques)
    matched = techniques & sig.techniques
    return len(matched) / len(sig.techniques)


def _rule_based_predictions(incidents: Sequence[Incident]) -> list[Prediction]:
    """One Prediction per APT that has at least one strong-overlap incident."""
    if not incidents:
        return []

    predictions: list[Prediction] = []
    for sig in _APT_SIGNATURES:
        scored = [(inc, _match_signature(inc, sig)) for inc in incidents]
        strong = [(inc, score) for inc, score in scored if score >= _MIN_OVERLAP]
        if not strong:
            continue

        avg_overlap = sum(score for _, score in strong) / len(strong)
        match_strength = round(min(_MAX_SCORE, avg_overlap * _MAX_SCORE), 2)
        # Single-incident matches are softer than multi-incident ones.
        confidence = round(min(1.0, avg_overlap * (1.0 if len(strong) > 1 else 0.7)), 3)
        trend = "rising" if len(strong) >= 2 else "stable"

        predictions.append(
            Prediction(
                sector="banking",
                threat_type=f"apt:{sig.name}",
                forecast_7d=match_strength,
                trend=trend,
                confidence=confidence,
            )
        )
        logger.info(
            "APT match: %s (%d incident(s), avg overlap=%.2f) - %s",
            sig.name,
            len(strong),
            avg_overlap,
            sig.note,
        )

    predictions.sort(key=lambda p: p.forecast_7d, reverse=True)
    return predictions


_FEATURE_TECHNIQUES: tuple[str, ...] = (
    "T1566",
    "T1078",
    "T1190",
    "T1539",
    "T1041",
    "T1071",
    "T1486",
)
_FEATURE_ASSETS: tuple[str, ...] = (
    "treasury",
    "payment_gateway",
    "customer_db",
    "swift_terminal",
)


def _featurize(incident: Incident) -> list[float]:
    """Binary + bucketed feature vector for clustering."""
    tech_set = set(incident.mitre_techniques)
    asset_set = set(incident.targeted_assets)
    features: list[float] = []
    features.extend(1.0 if t in tech_set else 0.0 for t in _FEATURE_TECHNIQUES)
    features.extend(1.0 if a in asset_set else 0.0 for a in _FEATURE_ASSETS)
    features.append(1.0 if "banking" in incident.targeted_sectors else 0.0)
    features.append(1.0 if len(incident.iocs) >= 10 else 0.0)
    features.append(1.0 if len(incident.compliance_breaches) >= 1 else 0.0)
    return features


def _cluster_predictions(incidents: Sequence[Incident]) -> list[Prediction]:
    """Emit one Prediction per non-trivial KMeans cluster, if we have data."""
    if len(incidents) < _MIN_INCIDENTS_FOR_KMEANS:
        logger.info(
            "KMeans skipped: %d incident(s), need >= %d",
            len(incidents),
            _MIN_INCIDENTS_FOR_KMEANS,
        )
        return []

    features = np.array([_featurize(inc) for inc in incidents], dtype=float)
    k = min(_MAX_K, len(incidents))
    model = KMeans(n_clusters=k, n_init=10, random_state=42)
    labels = model.fit_predict(features)

    predictions: list[Prediction] = []
    for cluster_id in range(k):
        members = [
            (inc, features[i])
            for i, (inc, lbl) in enumerate(zip(incidents, labels))
            if lbl == cluster_id
        ]
        if len(members) < _MIN_CLUSTER_SIZE:
            continue

        center = model.cluster_centers_[cluster_id]
        distances = [float(np.linalg.norm(vec - center)) for _, vec in members]
        mean_dist = sum(distances) / len(distances)
        # Tighter cluster -> higher confidence. Distances are bounded by sqrt
        # of feature dim; clip at 2.0 so confidence stays meaningful.
        tightness = max(0.0, 1.0 - min(mean_dist / 2.0, 1.0))

        cluster_size_score = min(1.0, len(members) / max(len(incidents), 1))
        match_strength = round(min(_MAX_SCORE, tightness * cluster_size_score * _MAX_SCORE), 2)
        confidence = round(tightness, 3)

        predictions.append(
            Prediction(
                sector="banking",
                threat_type=f"apt:cluster-{cluster_id}",
                forecast_7d=match_strength,
                trend="rising" if len(members) >= 3 else "stable",
                confidence=confidence,
            )
        )
        logger.info(
            "Cluster %d: %d incidents, tightness=%.2f -> apt:cluster-%d score=%.1f",
            cluster_id,
            len(members),
            tightness,
            cluster_id,
            match_strength,
        )

    return predictions


def analyze(incidents: Iterable[Incident]) -> list[Prediction]:
    """Run rule-based APT matching + KMeans clustering and return Predictions.

    Args:
        incidents: list of Incidents already MITRE-tagged by the pipeline.

    Returns:
        Combined sorted list of Predictions (highest match strength first).
    """
    incident_list = list(incidents)
    rule_preds = _rule_based_predictions(incident_list)
    cluster_preds = _cluster_predictions(incident_list)
    combined = rule_preds + cluster_preds
    combined.sort(key=lambda p: p.forecast_7d, reverse=True)
    logger.info(
        "Behavior analyzer: %d APT match(es) + %d cluster(s) from %d incident(s)",
        len(rule_preds),
        len(cluster_preds),
        len(incident_list),
    )
    return combined
