"""
Shodan host-info enrichment helper.

Same pattern as virustotal.py — never raises, returns
    {"available": False, "reason": "..."}
when the key is missing or the lookup fails. Free Shodan tier is
limited but enough for the demo.
"""

from __future__ import annotations

import os
from typing import Dict

import httpx

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host"
SHODAN_TIMEOUT = 8.0


def _api_key() -> str:
    return (os.getenv("SHODAN_API_KEY") or "").strip()


def _unavailable(reason: str) -> Dict[str, object]:
    return {"available": False, "reason": reason}


def lookup_ip(ip: str) -> Dict[str, object]:
    """Return a small Shodan summary for an IP. The free tier rate-limits hard."""
    key = _api_key()
    if not key:
        return _unavailable("SHODAN_API_KEY not set in .env on PC1")

    url = f"{SHODAN_HOST_URL}/{ip}"
    try:
        resp = httpx.get(url, params={"key": key}, timeout=SHODAN_TIMEOUT)
        if resp.status_code == 404:
            return _unavailable("Shodan has no record for this IP")
        resp.raise_for_status()
        data = resp.json()
        return {
            "available": True,
            "ports": data.get("ports") or [],
            "hostnames": data.get("hostnames") or [],
            "country": data.get("country_code"),
            "city": data.get("city"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "isp": data.get("isp"),
            "tags": data.get("tags") or [],
            "last_update": data.get("last_update"),
        }
    except httpx.HTTPError as e:
        return _unavailable(f"Shodan request failed: {e.__class__.__name__}")


def lookup(value: str, ioc_type: str) -> Dict[str, object]:
    """Dispatch on IOC type. Shodan only handles IPs natively for our purposes."""
    t = ioc_type.lower()
    if t in {"ip", "ipv4", "ipv6"}:
        return lookup_ip(value)
    return _unavailable(f"Shodan does not enrich ioc_type={ioc_type}")
