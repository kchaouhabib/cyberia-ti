"""
VirusTotal v3 enrichment helper.

Exposes two functions that PC1's API route /enrich calls. Each returns
a typed dict — never raises on missing key, never raises on network
failure. Callers get either real data or
    {"available": False, "reason": "..."}
and can render gracefully in the dashboard.

Free tier: 4 req/min, 500/day. Plenty for a hackathon demo.
"""

from __future__ import annotations

import os
from typing import Dict

import httpx

VT_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 8.0


def _api_key() -> str:
    return (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()


def _unavailable(reason: str) -> Dict[str, object]:
    """Standard 'no enrichment' response shape."""
    return {"available": False, "reason": reason}


def _summarize_vt_attributes(attrs: Dict) -> Dict[str, object]:
    """Pull the small set of fields the dashboard actually wants."""
    last_analysis_stats = attrs.get("last_analysis_stats") or {}
    malicious = last_analysis_stats.get("malicious", 0)
    total = sum(int(v or 0) for v in last_analysis_stats.values())
    return {
        "available": True,
        "detection_ratio": f"{malicious}/{total}" if total else "0/0",
        "country": attrs.get("country") or attrs.get("registrar") or None,
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "categories": list((attrs.get("categories") or {}).values())[:5],
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": last_analysis_stats,
    }


def lookup_ip(ip: str) -> Dict[str, object]:
    """Look up an IPv4/IPv6 address. Returns enrichment dict or unavailable stub."""
    key = _api_key()
    if not key:
        return _unavailable("VIRUSTOTAL_API_KEY not set in .env on PC1")

    url = f"{VT_BASE}/ip_addresses/{ip}"
    try:
        resp = httpx.get(
            url,
            headers={"x-apikey": key},
            timeout=VT_TIMEOUT,
        )
        if resp.status_code == 404:
            return _unavailable("VT has no record for this IP")
        resp.raise_for_status()
        data = resp.json().get("data") or {}
        return _summarize_vt_attributes(data.get("attributes") or {})
    except httpx.HTTPError as e:
        return _unavailable(f"VT request failed: {e.__class__.__name__}")


def lookup_domain(domain: str) -> Dict[str, object]:
    """Look up a domain. Same shape as lookup_ip()."""
    key = _api_key()
    if not key:
        return _unavailable("VIRUSTOTAL_API_KEY not set in .env on PC1")

    url = f"{VT_BASE}/domains/{domain}"
    try:
        resp = httpx.get(
            url,
            headers={"x-apikey": key},
            timeout=VT_TIMEOUT,
        )
        if resp.status_code == 404:
            return _unavailable("VT has no record for this domain")
        resp.raise_for_status()
        data = resp.json().get("data") or {}
        return _summarize_vt_attributes(data.get("attributes") or {})
    except httpx.HTTPError as e:
        return _unavailable(f"VT request failed: {e.__class__.__name__}")


def lookup_hash(file_hash: str) -> Dict[str, object]:
    """Look up a file hash (MD5 / SHA1 / SHA256)."""
    key = _api_key()
    if not key:
        return _unavailable("VIRUSTOTAL_API_KEY not set in .env on PC1")

    url = f"{VT_BASE}/files/{file_hash}"
    try:
        resp = httpx.get(
            url,
            headers={"x-apikey": key},
            timeout=VT_TIMEOUT,
        )
        if resp.status_code == 404:
            return _unavailable("VT has no record for this file hash")
        resp.raise_for_status()
        data = resp.json().get("data") or {}
        return _summarize_vt_attributes(data.get("attributes") or {})
    except httpx.HTTPError as e:
        return _unavailable(f"VT request failed: {e.__class__.__name__}")


def lookup(value: str, ioc_type: str) -> Dict[str, object]:
    """Dispatch on IOC type. Used by the API /enrich route."""
    t = ioc_type.lower()
    if t in {"ip", "ipv4", "ipv6"}:
        return lookup_ip(value)
    if t in {"domain", "hostname"}:
        return lookup_domain(value)
    if t in {"hash_md5", "hash_sha1", "hash_sha256", "md5", "sha1", "sha256"}:
        return lookup_hash(value)
    return _unavailable(f"unsupported ioc_type for VT: {ioc_type}")
