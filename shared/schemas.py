"""
Pydantic data contracts shared across all 4 PCs.

LOCKED at Phase 0. Do not modify without team consensus —
all PCs code against these models. Changing them mid-build
breaks the cross-PC API contract.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class RawThreatRecord(BaseModel):
    """A raw document from an OSINT source or scenario injector, before any AI processing."""

    id: str
    source: str  # 'otx' | 'urlhaus' | 'threatfox' | 'malwarebazaar' | 'misp' | 'scenario'
    raw_text: str
    timestamp: datetime
    sector: Optional[str] = None  # 'banking' | 'telecom' | 'healthcare' | None


class IOC(BaseModel):
    """A single extracted Indicator of Compromise (pre-enrichment)."""

    value: str
    type: str  # 'ip' | 'hash_md5' | 'hash_sha256' | 'domain' | 'url' | 'cve'
    confidence: float  # 0.0 - 1.0
    source: str
    first_seen: datetime


class EnrichedIOC(IOC):
    """An IOC after enrichment (VT reputation, geo, related CVEs, threat-type classification)."""

    threat_type: str  # 'phishing' | 'malware' | 'lateral_movement' | 'exfiltration' | 'c2'
    related_cves: List[str] = []
    geolocation: Optional[str] = None
    reputation: Optional[float] = None


class Incident(BaseModel):
    """A correlated group of IOCs with MITRE ATT&CK techniques and a risk score."""

    id: str
    iocs: List[EnrichedIOC]
    mitre_techniques: List[str]  # ['T1566', 'T1078', ...]
    targeted_sectors: List[str]
    risk_score: int  # 0-100
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    summary: str  # LLM-generated executive summary
    detected_at: datetime


class Prediction(BaseModel):
    """A forward-looking forecast for a (sector, threat_type) pair."""

    sector: str
    threat_type: str
    forecast_7d: float  # expected attacks in next 7 days
    trend: str  # 'rising' | 'stable' | 'falling'
    confidence: float
