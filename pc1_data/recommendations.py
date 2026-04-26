"""
Rule-based recommended-actions engine for incidents.

This is the differentiator that turns CYBERIA from a Threat Intelligence
platform into a SOC-Action platform: every team detects; few say what to DO.

The engine is deterministic (no LLM dependency) and runs in microseconds.
For each incident it derives an ordered action list from four signal sources:

  1. MITRE ATT&CK techniques  -> containment / forensics actions
  2. Compliance breaches       -> regulatory notification actions w/ deadlines
  3. Targeted banking assets   -> asset-specific containment
  4. APT attribution           -> threat-actor-specific guidance
  plus
  5. Severity                  -> triage urgency framing

Sorted by `priority` (1 = most urgent, 5 = lowest). The PDF report and
the GET /incidents/{id}/actions API both consume this list.

All thresholds, deadlines, and action text are hand-curated from
BATTLE_PLAN.md Appendix E (MITRE financial techniques) and Appendix F
(compliance frameworks) — public, open-source, original team work.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List

from shared.schemas import Incident


# ──────────────────────────────────────────────────────────────────────────
# Action data model
# ──────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Action:
    """One recommended action. Sorted by priority ascending (1 = most urgent)."""

    priority: int  # 1..5  (1 = page CISO immediately, 5 = log only)
    urgency: str  # 'immediate' | '15m' | '1h' | '24h' | '72h' | 'audit'
    category: str  # 'containment' | 'notification' | 'forensics' | 'recovery'
    text: str
    source: str  # what triggered this action (technique id, framework, asset, ...)

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────
# Static lookup tables
# ──────────────────────────────────────────────────────────────────────────

# MITRE technique -> containment action
# Sources: BATTLE_PLAN.md Appendix E (T1566 / T1078 / T1041 / T1190 / T1539
# / T1071 / T1486 / T1055 / T1098 / T1567 / T1021.002 / T1657 list).
_MITRE_ACTIONS: dict[str, tuple[int, str, str, str]] = {
    # technique_id: (priority, urgency, category, action_text)
    "T1566": (
        2, "1h", "containment",
        "Block sender domain at email gateway. Quarantine all matching emails "
        "received in the last 24 hours. Run user-awareness comms to flagged inboxes.",
    ),
    "T1078": (
        1, "15m", "containment",
        "Force password reset on all compromised accounts. Revoke active sessions "
        "and OAuth tokens. Audit privilege grants for the account in the last 7 days.",
    ),
    "T1190": (
        2, "1h", "recovery",
        "Patch the public-facing application immediately. Audit web logs for "
        "additional exploit attempts against the same CVE.",
    ),
    "T1539": (
        2, "15m", "containment",
        "Invalidate all banking session cookies. Force re-authentication "
        "across the customer portal.",
    ),
    "T1041": (
        1, "15m", "containment",
        "Block destination IP at the perimeter firewall. Audit DLP logs for "
        "additional egress to the same ASN. Snapshot the source host for forensics.",
    ),
    "T1071": (
        2, "1h", "containment",
        "Block the C2 domain at DNS and HTTP proxies. Pivot on related "
        "infrastructure (same registrant, same nameservers).",
    ),
    "T1486": (
        1, "immediate", "recovery",
        "ISOLATE affected endpoints from the network. Restore from clean backup. "
        "DO NOT pay the ransom — engage law enforcement instead.",
    ),
    "T1055": (
        2, "1h", "forensics",
        "Run EDR scan for injected processes. Re-image any workstation flagged "
        "as positive. Capture memory dumps before re-imaging.",
    ),
    "T1098": (
        2, "1h", "containment",
        "Audit privilege changes in the last 24 hours. Revert any unauthorized "
        "account modifications and enforce MFA on the account.",
    ),
    "T1567": (
        2, "1h", "containment",
        "Block egress to non-whitelisted cloud-storage providers. Audit DLP for "
        "exfil volume scope.",
    ),
    "T1021.002": (
        2, "15m", "containment",
        "Disable lateral SMB/IPC$ sessions from the source host. Reset "
        "credentials on every account that authenticated since the alert window.",
    ),
    "T1657": (
        1, "immediate", "containment",
        "Freeze the SWIFT terminal pending forensics. Halt outbound MT messages. "
        "Notify SWIFT CSP and the BCT immediately.",
    ),
}

# Compliance framework -> notification action with regulator-mandated deadline
# Sources: BATTLE_PLAN.md Appendix F.
_COMPLIANCE_ACTIONS: dict[str, tuple[int, str, str]] = {
    # framework: (priority, urgency, action_text)
    "PCI-DSS Req.3": (
        2, "24h",
        "Notify the acquirer per the merchant agreement. Document cardholder-data "
        "exposure scope (rows × PAN/CVV/expiry fields).",
    ),
    "PCI-DSS Req.10": (
        3, "audit",
        "Logging / monitoring gap detected. Provide remediation plan to QSA "
        "before next audit cycle.",
    ),
    "PCI-DSS Req.11": (
        3, "audit",
        "IDS/IPS detection gap detected. Document the failure and schedule a "
        "compensating control re-test.",
    ),
    "SWIFT CSP CSCF 2.x": (
        1, "24h",
        "Notify SWIFT under CSP CSCF Object 2.x within 24 hours. Prepare "
        "incident dossier for SWIFT customer security review.",
    ),
    "GDPR Art.33": (
        1, "72h",
        "Notify the lead data-protection authority within 72 hours of detection. "
        "Begin assembling the GDPR Art.33 dossier (nature, categories, approximate "
        "number of data subjects, contact point, mitigation steps).",
    ),
    "Basel III ORR": (
        3, "audit",
        "Log this as an operational-risk event in the Basel III register per "
        "the local Basel implementation (CBM / BCT / etc.).",
    ),
    "BCT Circular": (
        1, "24h",
        "Notify the Banque Centrale de Tunisie under the relevant cybersecurity "
        "circular within 24 hours. Coordinate with internal compliance officer.",
    ),
}

# Targeted asset -> asset-specific containment action
_ASSET_ACTIONS: dict[str, tuple[int, str, str, str]] = {
    "treasury": (
        2, "15m", "containment",
        "Isolate treasury workstations from the corporate network segment. "
        "Audit recent payment authorizations for the impacted user.",
    ),
    "payment_gateway": (
        1, "immediate", "containment",
        "Suspend non-essential payment processing on the affected gateway. "
        "Audit transaction logs for anomalous merchant flows in the last 24h.",
    ),
    "customer_db": (
        1, "15m", "containment",
        "Audit DB access logs for anomalous queries. Quantify exfiltration scope "
        "(row count × PII fields). Begin breach-notification scope assessment.",
    ),
    "swift_terminal": (
        1, "immediate", "containment",
        "Freeze the SWIFT terminal pending forensics. Halt all outbound MT "
        "messages. Notify SWIFT CSP and BCT.",
    ),
}

# APT attribution -> threat-actor-specific guidance
_APT_ACTIONS: dict[str, tuple[int, str, str]] = {
    # actor (lowercase): (priority, category, action_text)
    "fin7": (
        2, "forensics",
        "FIN7 historically targets POS systems and uses Carbanak-derived backdoors. "
        "Hunt for fileless persistence (WMI, scheduled tasks) and POS-network pivots.",
    ),
    "carbanak": (
        2, "forensics",
        "Carbanak historically lives in the network for months before action. "
        "Run a full-network EDR sweep for known Carbanak C2 patterns and dormant beacons.",
    ),
    "lazarus": (
        1, "forensics",
        "Lazarus group has hit SWIFT terminals at multiple banks (Bangladesh "
        "Bank 2016 — $81M). Audit ALL outbound SWIFT MT messages from the last 30 days.",
    ),
    "cobalt-group": (
        2, "forensics",
        "Cobalt Group typically uses spearphishing -> Cobalt Strike -> ATM-jackpotting "
        "or wire-fraud chains. Audit ATM management network and treasury wires.",
    ),
    "cobalt_group": (
        2, "forensics",
        "Cobalt Group typically uses spearphishing -> Cobalt Strike -> ATM-jackpotting "
        "or wire-fraud chains. Audit ATM management network and treasury wires.",
    ),
    "silence": (
        2, "forensics",
        "Silence group focuses on card-processing systems and ATM card "
        "operations. Audit card-management subnet and HSM traffic.",
    ),
}

# Severity -> triage urgency framing (always emitted, priority 1)
_SEVERITY_TRIAGE: dict[str, str] = {
    "critical": (
        "Convene the emergency response team within 15 minutes. Page the CISO "
        "and the Head of Risk. Activate the incident war room."
    ),
    "high": (
        "Convene the incident response team within 1 hour. Notify CISO."
    ),
    "medium": (
        "Standard incident triage workflow. Respond within 8 hours."
    ),
    "low": (
        "Log and monitor. No immediate action required unless signal escalates."
    ),
}


# ──────────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────────


def recommend_actions(incident: Incident) -> List[Action]:
    """Derive an ordered, deduplicated list of recommended actions for an incident.

    The order is by priority ascending (1 = most urgent). Within the same
    priority, ordering is stable in the order signals were processed:
    severity triage -> assets -> MITRE techniques -> compliance -> APT.
    """
    actions: list[Action] = []
    seen_texts: set[str] = set()

    def add(action: Action) -> None:
        if action.text in seen_texts:
            return
        actions.append(action)
        seen_texts.add(action.text)

    # 1. Severity triage — always emitted as priority 1
    sev = (incident.severity or "low").lower()
    triage_text = _SEVERITY_TRIAGE.get(sev, _SEVERITY_TRIAGE["low"])
    add(
        Action(
            priority=1,
            urgency="immediate" if sev in {"critical", "high"} else "1h",
            category="triage",
            text=triage_text,
            source=f"severity:{sev}",
        )
    )

    # 2. Asset containment
    for asset in (incident.targeted_assets or []):
        spec = _ASSET_ACTIONS.get(asset)
        if spec:
            p, u, c, t = spec
            add(Action(priority=p, urgency=u, category=c, text=t, source=f"asset:{asset}"))

    # 3. MITRE technique containment / forensics
    for tid in (incident.mitre_techniques or []):
        spec = _MITRE_ACTIONS.get(tid)
        if spec:
            p, u, c, t = spec
            add(Action(priority=p, urgency=u, category=c, text=t, source=f"mitre:{tid}"))

    # 4. Compliance notifications (with deadlines)
    for fw in (incident.compliance_breaches or []):
        spec = _COMPLIANCE_ACTIONS.get(fw)
        if spec:
            p, u, t = spec
            add(Action(priority=p, urgency=u, category="notification", text=t, source=f"compliance:{fw}"))

    # 5. APT-specific forensics guidance (any IOC carries an attribution)
    apts: set[str] = set()
    for ioc in (incident.iocs or []):
        a = (getattr(ioc, "apt_attribution", None) or "").lower()
        if a:
            apts.add(a)
    for apt in sorted(apts):
        spec = _APT_ACTIONS.get(apt)
        if spec:
            p, c, t = spec
            add(Action(priority=p, urgency="1h", category=c, text=t, source=f"apt:{apt}"))

    # Sort by priority ascending; preserve insertion order within same priority.
    actions.sort(key=lambda a: a.priority)
    return actions


# ──────────────────────────────────────────────────────────────────────────
# Threat-type -> MITRE technique mapping
# ──────────────────────────────────────────────────────────────────────────

# Used by /incidents/{id}/timeline to tag each event with a MITRE technique
# so PC4 can animate the kill-chain heatmap over time. Coarse but stable.
_THREAT_TYPE_TO_MITRE: dict[str, str] = {
    "phishing": "T1566",
    "lateral_movement": "T1078",
    "exfiltration": "T1041",
    "c2": "T1071",
    "malware": "T1055",
}


def threat_type_to_mitre(threat_type: str | None) -> str | None:
    """Return the canonical MITRE technique id for an EnrichedIOC.threat_type."""
    if not threat_type:
        return None
    return _THREAT_TYPE_TO_MITRE.get(threat_type.lower())
