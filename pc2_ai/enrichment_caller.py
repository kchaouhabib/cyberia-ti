"""
Enrichment caller — PC2, Stage 02, Phase 2.

Calls PC1's POST /enrich endpoint to get VirusTotal + Shodan data for an IOC.
Extracts reputation (VT) and geolocation (Shodan/VT country) from the response.

Only enriches IPs, domains, and hashes — CVEs and URLs are skipped (VT rate limits).
Gracefully degrades if PC1 has no API keys configured (returns None fields).
"""

import logging
from typing import Optional, Tuple

import httpx

log = logging.getLogger(__name__)

# IOC types worth enriching (others skip to save VT rate-limit quota)
_ENRICHABLE_TYPES = {"ip", "domain", "hash_md5", "hash_sha256"}


def enrich(value: str, ioc_type: str, pc1_base: str) -> Tuple[Optional[float], Optional[str]]:
    """
    Call PC1 /enrich and return (reputation, geolocation).

    reputation  : float 0.0–1.0 derived from VT detection ratio, or None
    geolocation : "City, Country" string from Shodan or VT country, or None

    Never raises — returns (None, None) on any failure.
    """
    if ioc_type not in _ENRICHABLE_TYPES:
        return None, None

    try:
        resp = httpx.post(
            f"{pc1_base}/enrich",
            json={"value": value, "type": ioc_type},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.debug(f"Enrichment call failed for {value}: {e}")
        return None, None

    reputation  = _parse_reputation(data.get("vt") or {})
    geolocation = _parse_geolocation(data.get("shodan") or {}, data.get("vt") or {})
    return reputation, geolocation


def _parse_reputation(vt: dict) -> Optional[float]:
    """
    Convert VT response to a 0.0-1.0 reputation score.
    0.0 = fully malicious, 1.0 = clean.
    Returns None if VT data is unavailable.
    """
    if not vt.get("available"):
        return None

    # Use detection_ratio if present ("malicious/total")
    ratio_str = vt.get("detection_ratio", "")
    if ratio_str and "/" in str(ratio_str):
        try:
            malicious, total = ratio_str.split("/")
            malicious, total = int(malicious), int(total)
            if total == 0:
                return None
            # Invert: 0 detections = 1.0 (clean), all detections = 0.0 (malicious)
            return round(1.0 - (malicious / total), 4)
        except (ValueError, ZeroDivisionError):
            pass

    # Fallback: use VT's own reputation field (negative = bad, positive = good)
    vt_rep = vt.get("reputation")
    if vt_rep is not None:
        try:
            # VT reputation ranges roughly -100 to +100, normalize to 0-1
            normalized = (float(vt_rep) + 100) / 200
            return round(max(0.0, min(1.0, normalized)), 4)
        except (ValueError, TypeError):
            pass

    return None


def _parse_geolocation(shodan: dict, vt: dict) -> Optional[str]:
    """
    Build a human-readable geolocation string.
    Prefers Shodan (city + country), falls back to VT country.
    """
    if shodan.get("available"):
        city    = shodan.get("city")
        country = shodan.get("country")
        if city and country:
            return f"{city}, {country}"
        if country:
            return country

    if vt.get("available"):
        country = vt.get("country")
        if country:
            return country

    return None
