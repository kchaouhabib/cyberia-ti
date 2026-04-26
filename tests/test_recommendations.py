"""
Tests for the rule-based recommended-actions engine and the timeline
mitre_technique enhancement.

All test data is synthetic — RFC 5737 IPs, RFC 6761 domains, fabricated
CVE ids. No real network calls; FastAPI exercised via TestClient.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from pc1_data import db, recommendations
from pc1_data.api import app
from shared.schemas import EnrichedIOC, Incident


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    yield


def _t(offset_minutes: int = 0) -> datetime:
    return datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc) + timedelta(
        minutes=offset_minutes
    )


def _ioc(value: str, threat_type: str, *, apt: str | None = None) -> EnrichedIOC:
    return EnrichedIOC(
        value=value,
        type="ip",
        confidence=0.9,
        source="scenario",
        first_seen=_t(),
        threat_type=threat_type,
        apt_attribution=apt,
    )


def _incident(
    *,
    severity: str = "critical",
    mitre: list[str] | None = None,
    compl: list[str] | None = None,
    assets: list[str] | None = None,
    iocs: list[EnrichedIOC] | None = None,
) -> Incident:
    return Incident(
        id="rec-test-1",
        iocs=iocs or [_ioc("198.51.100.1", "phishing")],
        mitre_techniques=mitre or [],
        targeted_sectors=["banking"],
        targeted_assets=assets or [],
        risk_score=85,
        severity=severity,
        summary="synthetic test incident",
        compliance_breaches=compl or [],
        detected_at=_t(20),
    )


# ──────────────────────────────────────────────────────────────────────────
# threat_type -> MITRE mapping
# ──────────────────────────────────────────────────────────────────────────


def test_threat_type_to_mitre_known():
    assert recommendations.threat_type_to_mitre("phishing") == "T1566"
    assert recommendations.threat_type_to_mitre("lateral_movement") == "T1078"
    assert recommendations.threat_type_to_mitre("exfiltration") == "T1041"
    assert recommendations.threat_type_to_mitre("c2") == "T1071"
    assert recommendations.threat_type_to_mitre("malware") == "T1055"


def test_threat_type_to_mitre_unknown_or_empty():
    assert recommendations.threat_type_to_mitre(None) is None
    assert recommendations.threat_type_to_mitre("") is None
    assert recommendations.threat_type_to_mitre("unknown_type") is None


def test_threat_type_to_mitre_case_insensitive():
    assert recommendations.threat_type_to_mitre("PHISHING") == "T1566"
    assert recommendations.threat_type_to_mitre("Lateral_Movement") == "T1078"


# ──────────────────────────────────────────────────────────────────────────
# recommend_actions — severity triage always emitted
# ──────────────────────────────────────────────────────────────────────────


def test_severity_triage_always_emitted():
    """Every incident gets a severity-driven triage action regardless of other inputs."""
    actions = recommendations.recommend_actions(_incident(severity="critical"))
    assert any("emergency response team" in a.text.lower() for a in actions)
    assert actions[0].priority == 1
    assert actions[0].source == "severity:critical"


def test_severity_triage_low_does_not_page_ciso():
    actions = recommendations.recommend_actions(_incident(severity="low"))
    triage = next(a for a in actions if a.source.startswith("severity:"))
    assert "log and monitor" in triage.text.lower()


# ──────────────────────────────────────────────────────────────────────────
# recommend_actions — MITRE-driven
# ──────────────────────────────────────────────────────────────────────────


def test_mitre_phishing_yields_email_gateway_block():
    actions = recommendations.recommend_actions(
        _incident(mitre=["T1566"])
    )
    assert any("email gateway" in a.text.lower() and a.source == "mitre:T1566" for a in actions)


def test_mitre_swift_theft_yields_swift_freeze_action():
    """T1657 (Financial Theft) should trigger the SWIFT freeze action."""
    actions = recommendations.recommend_actions(_incident(mitre=["T1657"]))
    swift_action = next(a for a in actions if a.source == "mitre:T1657")
    assert swift_action.priority == 1
    assert swift_action.urgency == "immediate"
    assert "swift" in swift_action.text.lower()


def test_unknown_mitre_technique_skipped():
    actions = recommendations.recommend_actions(_incident(mitre=["T9999"]))
    sources = {a.source for a in actions}
    assert "mitre:T9999" not in sources


# ──────────────────────────────────────────────────────────────────────────
# recommend_actions — compliance-driven
# ──────────────────────────────────────────────────────────────────────────


def test_gdpr_breach_yields_72h_notification():
    actions = recommendations.recommend_actions(
        _incident(compl=["GDPR Art.33"])
    )
    gdpr = next(a for a in actions if a.source == "compliance:GDPR Art.33")
    assert gdpr.urgency == "72h"
    assert gdpr.category == "notification"
    assert "72 hours" in gdpr.text


def test_swift_csp_yields_24h_notification():
    actions = recommendations.recommend_actions(
        _incident(compl=["SWIFT CSP CSCF 2.x"])
    )
    swift = next(a for a in actions if a.source == "compliance:SWIFT CSP CSCF 2.x")
    assert swift.urgency == "24h"
    assert "24 hours" in swift.text


def test_bct_circular_yields_action():
    actions = recommendations.recommend_actions(
        _incident(compl=["BCT Circular"])
    )
    bct = next(a for a in actions if a.source == "compliance:BCT Circular")
    assert "BCT" in bct.text or "Banque Centrale" in bct.text


# ──────────────────────────────────────────────────────────────────────────
# recommend_actions — asset-driven
# ──────────────────────────────────────────────────────────────────────────


def test_swift_terminal_asset_freezes_terminal():
    actions = recommendations.recommend_actions(
        _incident(assets=["swift_terminal"])
    )
    swift = next(a for a in actions if a.source == "asset:swift_terminal")
    assert swift.priority == 1
    assert "freeze" in swift.text.lower()


def test_treasury_asset_yields_isolation():
    actions = recommendations.recommend_actions(
        _incident(assets=["treasury"])
    )
    treasury = next(a for a in actions if a.source == "asset:treasury")
    assert "isolate" in treasury.text.lower()


# ──────────────────────────────────────────────────────────────────────────
# recommend_actions — APT-driven
# ──────────────────────────────────────────────────────────────────────────


def test_lazarus_attribution_mentions_bangladesh_bank():
    """Lazarus action should reference the famous SWIFT breach precedent."""
    actions = recommendations.recommend_actions(
        _incident(iocs=[_ioc("198.51.100.5", "exfiltration", apt="lazarus")])
    )
    lazarus = next(a for a in actions if a.source == "apt:lazarus")
    assert "bangladesh" in lazarus.text.lower()


def test_no_apt_no_apt_action():
    actions = recommendations.recommend_actions(
        _incident(iocs=[_ioc("198.51.100.5", "phishing", apt=None)])
    )
    apt_sources = [a.source for a in actions if a.source.startswith("apt:")]
    assert apt_sources == []


# ──────────────────────────────────────────────────────────────────────────
# recommend_actions — ordering + dedup
# ──────────────────────────────────────────────────────────────────────────


def test_actions_sorted_by_priority_ascending():
    actions = recommendations.recommend_actions(
        _incident(
            severity="critical",
            mitre=["T1566", "T1078", "T1041"],  # mix of priority 1 and 2
            compl=["GDPR Art.33", "PCI-DSS Req.10"],  # priority 1 and 3
            assets=["customer_db", "swift_terminal"],
        )
    )
    priorities = [a.priority for a in actions]
    assert priorities == sorted(priorities), f"actions not sorted: {priorities}"


def test_duplicate_text_deduplicated():
    """Same action text appearing from two signals should appear once."""
    # SWIFT terminal asset and T1657 both produce SWIFT-freeze text.
    actions = recommendations.recommend_actions(
        _incident(assets=["swift_terminal"], mitre=["T1657"])
    )
    swift_texts = [a.text for a in actions if "swift" in a.text.lower() and "freeze" in a.text.lower()]
    # Both signals produce a freeze action; dedup must keep them distinct
    # in source but unique in text.
    assert len(set(swift_texts)) == len(swift_texts)


# ──────────────────────────────────────────────────────────────────────────
# Banque Atlas demo punchline — full kill-chain produces a rich action plan
# ──────────────────────────────────────────────────────────────────────────


def test_full_banque_atlas_scenario_produces_rich_action_plan():
    inc = _incident(
        severity="critical",
        mitre=["T1566", "T1078", "T1041", "T1657"],
        compl=["GDPR Art.33", "SWIFT CSP CSCF 2.x", "PCI-DSS Req.3", "BCT Circular"],
        assets=["treasury", "payment_gateway", "customer_db", "swift_terminal"],
        iocs=[
            _ioc("198.51.100.42", "phishing"),
            _ioc("203.0.113.7", "exfiltration", apt="lazarus"),
        ],
    )
    actions = recommendations.recommend_actions(inc)

    sources = {a.source for a in actions}
    # Must hit every signal axis:
    assert any(s.startswith("severity:") for s in sources)
    assert any(s.startswith("asset:") for s in sources)
    assert any(s.startswith("mitre:") for s in sources)
    assert any(s.startswith("compliance:") for s in sources)
    assert any(s.startswith("apt:") for s in sources)

    # And the top of the list is priority 1
    assert actions[0].priority == 1
    # Should produce at least 8 distinct actions for a full kill chain
    assert len(actions) >= 8


# ──────────────────────────────────────────────────────────────────────────
# HTTP route — GET /incidents/{id}/actions
# ──────────────────────────────────────────────────────────────────────────


def test_actions_route_returns_404_for_unknown_incident():
    client = TestClient(app)
    resp = client.get("/incidents/does-not-exist/actions")
    assert resp.status_code == 404


def test_actions_route_returns_structured_actions():
    inc = _incident(
        severity="critical",
        mitre=["T1566"],
        compl=["GDPR Art.33"],
        assets=["customer_db"],
    )
    db.insert_incident(inc)

    client = TestClient(app)
    resp = client.get(f"/incidents/{inc.id}/actions")
    assert resp.status_code == 200
    body = resp.json()

    assert body["incident_id"] == inc.id
    assert body["severity"] == "critical"
    assert body["risk_score"] == 85
    assert "narrative" in body  # PC2 LLM hook placeholder
    assert isinstance(body["actions"], list)
    assert len(body["actions"]) >= 4

    first = body["actions"][0]
    assert {"priority", "urgency", "category", "text", "source"} <= set(first.keys())


# ──────────────────────────────────────────────────────────────────────────
# Timeline route — mitre_technique on every event
# ──────────────────────────────────────────────────────────────────────────


def test_timeline_carries_mitre_technique_per_event():
    inc = _incident(
        iocs=[
            _ioc("198.51.100.1", "phishing"),
            _ioc("198.51.100.2", "exfiltration"),
            _ioc("198.51.100.3", "c2"),
        ]
    )
    db.insert_incident(inc)

    client = TestClient(app)
    resp = client.get(f"/incidents/{inc.id}/timeline")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) == 3

    for e in events:
        assert "mitre_technique" in e

    technique_set = {e["mitre_technique"] for e in events}
    assert technique_set == {"T1566", "T1041", "T1071"}
