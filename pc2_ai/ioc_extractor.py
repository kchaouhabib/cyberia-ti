"""
Regex-based IOC extractor — PC2, Stage 02, Phase 1.

Extracts IPs, MD5/SHA256 hashes, domains, URLs, and CVEs from raw threat text.
Phase 3 adds LLM-based extraction (llm_extractor.py) for the side-by-side demo comparison.
"""

import re
from datetime import datetime, timezone
from typing import List

from shared.schemas import IOC

# ── Regex patterns ──────────────────────────────────────────────────────────

_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
_MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_IP_RE     = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_URL_RE    = re.compile(r'https?://[^\s<>"\'\]]+')
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
_CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Regex-extracted indicators get these baseline confidence scores
_CONFIDENCE: dict[str, float] = {
    "ip":           0.75,
    "hash_md5":     0.85,
    "hash_sha256":  0.90,
    "url":          0.80,
    "domain":       0.65,
    "cve":          0.95,
}

_PRIVATE_PREFIXES = ("10.", "127.", "0.", "169.254.", "192.168.")


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 / loopback addresses — not valid threat IOCs."""
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return True
    # 172.16.0.0/12
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            pass
    return False


def extract_iocs(text: str, source: str) -> List[IOC]:
    """
    Extract all IOCs from raw threat text using regex patterns.

    Returns a deduplicated list of IOC objects ready to POST to PC1 /iocs.
    Extraction order: SHA256 → MD5 → URLs → IPs → domains → CVEs.
    """
    now = datetime.now(timezone.utc)
    seen: set[tuple[str, str]] = set()
    iocs: List[IOC] = []

    def _add(value: str, ioc_type: str) -> None:
        key = (value.lower(), ioc_type)
        if key in seen:
            return
        seen.add(key)
        iocs.append(IOC(
            value=value,
            type=ioc_type,
            confidence=_CONFIDENCE[ioc_type],
            source=source,
            first_seen=now,
        ))

    # SHA256 first — a 64-char hex string would also match the 32-char MD5 pattern
    sha256_values: set[str] = set()
    for h in _SHA256_RE.findall(text):
        sha256_values.add(h.lower())
        _add(h.lower(), "hash_sha256")

    # MD5 — skip any 32-char substrings that are part of a SHA256 already captured
    for h in _MD5_RE.findall(text):
        if not any(h.lower() in s for s in sha256_values):
            _add(h.lower(), "hash_md5")

    # URLs before domains — record embedded hostnames to avoid double-counting
    url_hosts: set[str] = set()
    for url in _URL_RE.findall(text):
        _add(url, "url")
        m = re.match(r'https?://([^/?\s#]+)', url)
        if m:
            url_hosts.add(m.group(1).lower())

    # IPs — skip private / loopback ranges
    for ip in _IP_RE.findall(text):
        if not _is_private_ip(ip):
            _add(ip, "ip")

    # Domains — skip hosts already captured inside a URL, and skip IP-looking strings
    for domain in _DOMAIN_RE.findall(text):
        if domain.lower() not in url_hosts and not _IP_RE.fullmatch(domain):
            _add(domain.lower(), "domain")

    # CVEs
    for cve in _CVE_RE.findall(text):
        _add(cve.upper(), "cve")

    return iocs
