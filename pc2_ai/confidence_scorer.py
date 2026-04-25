"""
Per-source confidence scorer — PC2, Stage 02, Phase 2.

Adjusts an IOC's base confidence score using historical false-positive rates
per source. Higher FP rate → lower multiplier → lower final confidence.

Source weights are based on community reputation of each feed:
  - MalwareBazaar / ThreatFox: very low FP, well-curated
  - AlienVault OTX: moderate FP (community contributions vary)
  - URLhaus: low FP for URLs, slightly higher for domains
  - Scenario injector: synthetic data, treated as high-confidence for demo
  - MISP: trusted community sharing, low FP
"""

from shared.schemas import IOC

# Historical false-positive rate per source (0.0 = perfect, 1.0 = all FP)
# Multiplier = 1.0 - fp_rate
_SOURCE_FP_RATES: dict[str, float] = {
    "malwarebazaar": 0.03,   # very curated hash feed
    "threatfox":     0.05,   # curated IOC feed
    "misp":          0.07,   # trusted community sharing
    "urlhaus":       0.10,   # good URL feed, minor FP on aged entries
    "otx":           0.20,   # community-contributed, variable quality
    "scenario":      0.00,   # synthetic demo data — always trust it
}

_DEFAULT_FP_RATE = 0.15  # unknown sources get moderate trust

# Boost for IOC types that are inherently high-signal in banking context
_TYPE_BOOST: dict[str, float] = {
    "hash_sha256": 0.05,
    "hash_md5":    0.03,
    "cve":         0.04,
    "ip":          0.00,
    "url":         0.00,
    "domain":      0.00,
}

MIN_CONFIDENCE = 0.10
MAX_CONFIDENCE = 0.99


def score(ioc: IOC) -> float:
    """
    Compute adjusted confidence for an IOC.

    Final score = base_confidence × (1 - fp_rate) + type_boost
    Clamped to [MIN_CONFIDENCE, MAX_CONFIDENCE].
    """
    fp_rate   = _SOURCE_FP_RATES.get(ioc.source.lower(), _DEFAULT_FP_RATE)
    multiplier = 1.0 - fp_rate
    boost      = _TYPE_BOOST.get(ioc.type, 0.0)
    adjusted   = ioc.confidence * multiplier + boost
    return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, adjusted)), 4)


def apply(ioc: IOC) -> IOC:
    """
    Return a copy of the IOC with confidence updated by source scoring.
    Does not mutate the original.
    """
    adjusted = score(ioc)
    return ioc.model_copy(update={"confidence": adjusted})
