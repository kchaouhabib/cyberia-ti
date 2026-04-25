"""
LLM CISO summarizer — PC2, Stage 02, Phase 3.

Uses Ollama (Llama 3.2 3B, local) to generate one plain-language paragraph
that a bank CISO can present to the board — including compliance impact.

This is the killer demo feature: every critical alert gets a CISO-ready summary
visible in PC4's dashboard alerts list.
"""

import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

OLLAMA_MODEL   = "llama3.2:3b"
OLLAMA_BASE    = "http://localhost:11434"
OLLAMA_TIMEOUT = 45  # summarization needs slightly more time than extraction

_SYSTEM_PROMPT = (
    "You are a cybersecurity expert writing executive briefings for bank CISOs. "
    "Write in plain language a non-technical decision-maker can understand. "
    "Be concise, direct, and always mention regulatory/compliance implications."
)

_SUMMARY_PROMPT_TEMPLATE = """\
Write ONE paragraph (3-5 sentences) that a bank CISO can present to the board.
The paragraph must cover:
1. What happened (the attack type and targeted bank asset)
2. The immediate business risk (financial, operational, reputational)
3. Which compliance frameworks were breached and the notification deadline
4. One recommended immediate action

Incident details:
- Threat type: {threat_type}
- Targeted assets: {targeted_assets}
- Risk score: {risk_score}/100 (severity: {severity})
- MITRE techniques: {mitre_techniques}
- Compliance breaches: {compliance_breaches}
- IOC count: {ioc_count}
- APT attribution: {apt_attribution}

Raw incident summary:
{raw_summary}

Write only the paragraph. No bullet points. No headers. No preamble.
"""

_FALLBACK_TEMPLATE = (
    "A {severity}-severity {threat_type} incident (risk score {risk_score}/100) has been detected "
    "targeting {targeted_assets}. {ioc_count} indicators of compromise were identified, "
    "linked to {apt_attribution}. "
    "Compliance obligations triggered: {compliance_breaches}. "
    "Immediate investigation and containment recommended."
)


def _call_ollama(prompt: str) -> Optional[str]:
    """Call local Ollama and return the generated text, or None on failure."""
    try:
        import httpx
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.3},  # slight creativity for natural language
        }
        resp = httpx.post(
            f"{OLLAMA_BASE}/api/chat",
            json=payload,
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        text = resp.json()["message"]["content"].strip()
        # Remove any markdown the model might add
        text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
        return text
    except Exception as e:
        log.warning(f"LLM summarization failed: {e}")
        return None


def summarize_incident(
    threat_type: str,
    targeted_assets: list[str],
    risk_score: int,
    severity: str,
    mitre_techniques: list[str],
    compliance_breaches: list[str],
    ioc_count: int,
    apt_attribution: Optional[str] = None,
    raw_summary: str = "",
) -> str:
    """
    Generate a CISO-ready plain-language incident summary.

    Returns the LLM-generated paragraph if Ollama is available,
    otherwise returns a structured fallback string.
    """
    assets_str      = ", ".join(targeted_assets) if targeted_assets else "unspecified assets"
    techniques_str  = ", ".join(mitre_techniques) if mitre_techniques else "unknown techniques"
    compliance_str  = ", ".join(compliance_breaches) if compliance_breaches else "none detected"
    apt_str         = apt_attribution if apt_attribution else "unknown threat actor"

    prompt = _SUMMARY_PROMPT_TEMPLATE.format(
        threat_type=threat_type,
        targeted_assets=assets_str,
        risk_score=risk_score,
        severity=severity,
        mitre_techniques=techniques_str,
        compliance_breaches=compliance_str,
        ioc_count=ioc_count,
        apt_attribution=apt_str,
        raw_summary=raw_summary[:500] if raw_summary else "No additional context.",
    )

    result = _call_ollama(prompt)
    if result:
        return result

    # Fallback: structured template when Ollama is unavailable
    return _FALLBACK_TEMPLATE.format(
        severity=severity,
        threat_type=threat_type,
        risk_score=risk_score,
        targeted_assets=assets_str,
        ioc_count=ioc_count,
        apt_attribution=apt_str,
        compliance_breaches=compliance_str,
    )


if __name__ == "__main__":
    # Demo test — simulates a Banque Atlas incident
    summary = summarize_incident(
        threat_type="lateral_movement",
        targeted_assets=["treasury", "payment_gateway"],
        risk_score=87,
        severity="critical",
        mitre_techniques=["T1566", "T1078", "T1041"],
        compliance_breaches=["PCI-DSS Req.10", "SWIFT CSP CSCF 2.x", "GDPR Art.33"],
        ioc_count=14,
        apt_attribution="lazarus",
        raw_summary=(
            "Lazarus Group spear-phishing campaign compromised treasury workstation. "
            "Lateral movement detected toward SWIFT payment gateway. "
            "Unusual MT103 messages observed."
        ),
    )
    print("=== CISO SUMMARY ===")
    print(summary)
