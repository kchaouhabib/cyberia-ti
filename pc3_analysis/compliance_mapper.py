"""Compliance mapper - the killer feature for the bank-CISO pitch.

Tags each Incident with the regulatory frameworks it would breach, and infers
which banking asset class(es) the incident touches (treasury / payment_gateway
/ customer_db / swift_terminal).

Rules implemented (BATTLE_PLAN Appendix F):

    PCI-DSS Req.3        Cardholder data exposure (payment / customer assets +
                         exfiltration or stored-card hash compromise)
    PCI-DSS Req.10       Logging / monitoring gap (any successful lateral
                         movement or C2 implies the SOC didn't catch it)
    PCI-DSS Req.11       Failure to detect intrusion (any successful exfil)
    SWIFT CSP CSCF 2.x   SWIFT message / terminal anomaly
    GDPR Art.33          Personal data breach (72h notification deadline)
    Basel III ORR        Operational risk event (ransomware, major outage)
    BCT Circular         Tunisia-specific cyber-incident on bank ops

Asset-type inference
--------------------
``EnrichedIOC`` does not (yet) carry ``asset_type`` - only ``RawThreatRecord``
does, and PC3 polls the enriched stream. Until PC2 denormalizes the field, we
infer asset class from keywords in IOC values and the incident summary. This
is good enough for a hackathon demo and is easy to upgrade to a direct
``ioc.asset_type`` read once the schema lands.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable

from shared.schemas import Incident

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# Asset-type keyword inference
# ──────────────────────────────────────────────────────────────────────────

# Each asset class -> compiled regex of identifying keywords. Word boundaries
# avoid false positives like "treasury" inside an unrelated URL path.
_ASSET_KEYWORDS: dict[str, re.Pattern[str]] = {
    "treasury": re.compile(r"\b(treasury|treasur|tresorerie)\b", re.IGNORECASE),
    "payment_gateway": re.compile(
        r"\b(payment|paygate|pos[-_]?terminal|pos\b|merchant|cardholder|"
        r"\bcard\b|atm[-_]?network)\b",
        re.IGNORECASE,
    ),
    "customer_db": re.compile(
        r"\b(customer|client[-_]?db|kyc|cif|account[-_]?holder|crm)\b",
        re.IGNORECASE,
    ),
    "swift_terminal": re.compile(
        r"\b(swift|mt103|mt202|mt[-_]?900|iso20022|fin\s?network)\b",
        re.IGNORECASE,
    ),
}

# Fallback asset inference when no keyword fires. EnrichedIOC doesn't carry
# asset_type yet, so we map threat_type and apt_attribution to the asset
# class each is most associated with in banking environments. Coarse on
# purpose - the alternative is rendering "(none)" on every incident.
_THREAT_TO_ASSET: dict[str, str] = {
    "phishing": "customer_db",
    "exfiltration": "customer_db",
    "lateral_movement": "payment_gateway",
    "c2": "payment_gateway",
    "malware": "payment_gateway",
}
_APT_TO_ASSET: dict[str, str] = {
    "fin7": "payment_gateway",
    "carbanak": "payment_gateway",
    "lazarus": "swift_terminal",
    "cobalt-group": "swift_terminal",
    "cobalt_group": "swift_terminal",
    "silence": "swift_terminal",
}

# Assets considered in PCI-DSS scope (cardholder data environment).
_PCI_DSS_SCOPE_ASSETS: frozenset[str] = frozenset(
    {"payment_gateway", "customer_db"}
)

# Threat types that imply a successful intrusion (used for Req.10/11).
_INTRUSION_THREAT_TYPES: frozenset[str] = frozenset(
    {"lateral_movement", "c2", "exfiltration"}
)


def _infer_assets(incident: Incident) -> list[str]:
    """Best-effort asset-type inference.

    All stages ACCUMULATE - they do not short-circuit. A multi-event scenario
    with phishing IOCs (-> customer_db), a Lazarus attribution
    (-> swift_terminal), AND payment-keyword hits (-> payment_gateway)
    should end up with all three assets, not just the first stage that fires.

      0. Authoritative ``EnrichedIOC.asset_type`` from PC2 (highest precedence
         when present - PC2 copies it from the parent RawThreatRecord).
      1. Keyword scan over IOC values + summary text (precise but misses
         when IOC values are bare IPs / hashes).
      2. APT attribution fallback (Lazarus -> swift_terminal, FIN7 -> ...).
      3. threat_type fallback (phishing -> customer_db, c2 -> ...).
    """
    inferred: set[str] = set()

    for ioc in incident.iocs:
        explicit = getattr(ioc, "asset_type", None)
        if explicit:
            inferred.add(explicit)

    blob_parts: list[str] = [ioc.value for ioc in incident.iocs]
    if incident.summary:
        blob_parts.append(incident.summary)
    blob = " ".join(blob_parts)
    for asset, pattern in _ASSET_KEYWORDS.items():
        if pattern.search(blob):
            inferred.add(asset)

    for ioc in incident.iocs:
        apt = (ioc.apt_attribution or "").lower()
        if apt in _APT_TO_ASSET:
            inferred.add(_APT_TO_ASSET[apt])

    for ioc in incident.iocs:
        threat = (ioc.threat_type or "").lower()
        if threat in _THREAT_TO_ASSET:
            inferred.add(_THREAT_TO_ASSET[threat])

    return sorted(inferred)


def _threat_types(incident: Incident) -> set[str]:
    """Set of distinct ``threat_type`` values across the incident's IOCs."""
    return {(ioc.threat_type or "").lower() for ioc in incident.iocs}


# ──────────────────────────────────────────────────────────────────────────
# Compliance rule engine
# ──────────────────────────────────────────────────────────────────────────


def _eval_rules(
    threat_types: set[str],
    techniques: set[str],
    assets: set[str],
    targeted_sectors: Iterable[str],
) -> list[str]:
    """Apply all compliance rules and return the sorted breach list."""
    breaches: set[str] = set()
    sectors = set(targeted_sectors)

    has_intrusion = bool(threat_types & _INTRUSION_THREAT_TYPES)
    has_exfil = "exfiltration" in threat_types or "T1041" in techniques
    has_ransomware = "T1486" in techniques
    pci_assets_touched = bool(assets & _PCI_DSS_SCOPE_ASSETS)

    # PCI-DSS Req.3 - protect stored cardholder data
    if pci_assets_touched and has_exfil:
        breaches.add("PCI-DSS Req.3")

    # PCI-DSS Req.10 - logging / monitoring gap implied by undetected intrusion
    if has_intrusion or techniques & {"T1071", "T1078"}:
        breaches.add("PCI-DSS Req.10")

    # PCI-DSS Req.11 - failure to detect intrusion / vuln management
    if has_exfil or has_ransomware:
        breaches.add("PCI-DSS Req.11")

    # SWIFT CSP CSCF 2.x - anomaly touching SWIFT environment
    if "swift_terminal" in assets:
        breaches.add("SWIFT CSP CSCF 2.x")

    # GDPR Art.33 - personal-data breach, 72h notification
    if "customer_db" in assets and has_exfil:
        breaches.add("GDPR Art.33")
    if has_ransomware:
        # Modern ransomware operators exfiltrate before encrypting (double-extortion).
        breaches.add("GDPR Art.33")

    # Basel III ORR - operational risk event
    if has_ransomware:
        breaches.add("Basel III ORR")

    # BCT Circular - Tunisian central bank cyber-incident reporting
    if has_ransomware or (has_exfil and "banking" in sectors):
        breaches.add("BCT Circular")

    return sorted(breaches)


# ──────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────


def map_incident(
    incident: Incident,
    mitre_techniques: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(compliance_breaches, inferred_assets)`` for an Incident.

    Args:
        incident: Incident already correlated by ``correlator``.
        mitre_techniques: optional override; if None, falls back to
            ``incident.mitre_techniques`` (pass the freshly-tagged list when
            chaining mitre_mapper -> compliance_mapper to avoid two passes).

    Returns:
        (breaches, assets):
        - breaches: sorted list of regulation tags
            (e.g. ['GDPR Art.33', 'PCI-DSS Req.3']).
        - assets: sorted list of inferred asset classes touched
            (e.g. ['customer_db', 'payment_gateway']).
    """
    techniques = set(
        mitre_techniques if mitre_techniques is not None else incident.mitre_techniques
    )
    assets = _infer_assets(incident)
    breaches = _eval_rules(
        threat_types=_threat_types(incident),
        techniques=techniques,
        assets=set(assets),
        targeted_sectors=incident.targeted_sectors,
    )

    logger.debug(
        "Incident %s -> assets=%s breaches=%s",
        incident.id,
        assets,
        breaches,
    )
    return breaches, assets


def is_pci_scope(assets: Iterable[str]) -> bool:
    """True if any asset in ``assets`` is a PCI-DSS scope asset.

    Used by ``risk_scorer`` to decide whether to apply the +20% compliance
    weight to the score.
    """
    return bool(set(assets) & _PCI_DSS_SCOPE_ASSETS)


def apply(incident: Incident) -> Incident:
    """Return a copy of ``incident`` with ``compliance_breaches`` and
    ``targeted_assets`` filled in.

    Reads ``incident.mitre_techniques`` - call ``mitre_mapper.apply`` first
    to ensure that field is populated.
    """
    breaches, assets = map_incident(incident)
    return incident.model_copy(
        update={
            "compliance_breaches": breaches,
            "targeted_assets": assets,
        }
    )
