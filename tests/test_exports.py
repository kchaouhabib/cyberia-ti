"""
Smoke tests for the Phase-3 export package and the timeline route.

All test data is synthetic — RFC-reserved IPs and domains, fabricated
SHA256s, fabricated CVE ids. No real network calls; FastAPI is exercised
via TestClient.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from pc1_data import db
from pc1_data.api import app
from pc1_data.exporters import csv_export, json_export, pdf_export
from shared.schemas import EnrichedIOC, Incident


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Fresh SQLite per test — no cross-test contamination."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    yield


def _t(offset_minutes: int = 0) -> datetime:
    """Deterministic timestamp with optional offset."""
    return datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc) + timedelta(
        minutes=offset_minutes
    )


def _make_incident(incident_id: str = "inc-export-1", n_iocs: int = 3) -> Incident:
    iocs = [
        EnrichedIOC(
            value=f"198.51.100.{i + 1}",
            type="ip",
            confidence=0.7 + 0.05 * i,
            source="scenario",
            first_seen=_t(offset_minutes=i * 5),
            threat_type="exfiltration" if i % 2 else "phishing",
            related_cves=["CVE-2024-99999"] if i == 0 else [],
            geolocation="RU" if i == 0 else None,
            reputation=0.05 if i == 0 else None,
            apt_attribution="lazarus" if i == 0 else None,
        )
        for i in range(n_iocs)
    ]
    return Incident(
        id=incident_id,
        iocs=iocs,
        mitre_techniques=["T1566", "T1078", "T1041"],
        targeted_sectors=["banking"],
        targeted_assets=["treasury", "payment_gateway"],
        risk_score=92,
        severity="critical",
        summary="Spearphishing → lateral movement → exfiltration to Lazarus C2.",
        compliance_breaches=["PCI-DSS Req.10", "SWIFT CSP CSCF 2.x", "GDPR Art.33"],
        detected_at=_t(offset_minutes=20),
    )


# ──────────────────────────────────────────────────────────────────────────
# JSON exporter
# ──────────────────────────────────────────────────────────────────────────


def test_json_export_round_trip():
    incident = _make_incident()
    blob = json_export.render([incident])
    assert isinstance(blob, bytes)

    payload = json.loads(blob.decode("utf-8"))
    assert payload["count"] == 1
    assert payload["incidents"][0]["id"] == "inc-export-1"

    rehydrated = Incident.model_validate(payload["incidents"][0])
    assert rehydrated.id == incident.id
    assert rehydrated.severity == "critical"
    assert rehydrated.compliance_breaches == incident.compliance_breaches


def test_json_export_empty_list():
    blob = json_export.render([])
    payload = json.loads(blob.decode("utf-8"))
    assert payload["count"] == 0
    assert payload["incidents"] == []


# ──────────────────────────────────────────────────────────────────────────
# CSV exporter
# ──────────────────────────────────────────────────────────────────────────


def test_csv_export_one_row_per_ioc():
    incident = _make_incident(n_iocs=3)
    blob = csv_export.render([incident])
    assert isinstance(blob, bytes)

    text = blob.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)

    assert len(rows) == 3
    assert reader.fieldnames is not None
    assert "ioc_value" in reader.fieldnames
    assert "compliance_breaches" in reader.fieldnames
    assert rows[0]["incident_id"] == "inc-export-1"
    assert rows[0]["severity"] == "critical"
    assert "PCI-DSS Req.10" in rows[0]["compliance_breaches"]


def test_csv_export_preserves_iocless_incident():
    """An incident with zero IOCs still produces one CSV row."""
    incident = _make_incident(n_iocs=0)
    blob = csv_export.render([incident])
    rows = list(csv.DictReader(io.StringIO(blob.decode("utf-8"))))
    assert len(rows) == 1
    assert rows[0]["incident_id"] == "inc-export-1"
    assert rows[0]["ioc_value"] == ""


# ──────────────────────────────────────────────────────────────────────────
# PDF exporter
# ──────────────────────────────────────────────────────────────────────────


def test_pdf_export_single_incident_starts_with_pdf_magic():
    blob = pdf_export.render([_make_incident()])
    assert isinstance(blob, bytes)
    assert blob.startswith(b"%PDF-")
    assert len(blob) > 1500


def test_pdf_export_portfolio_multiple_incidents():
    incidents = [_make_incident("inc-a", 2), _make_incident("inc-b", 1)]
    blob = pdf_export.render(incidents)
    assert blob.startswith(b"%PDF-")
    single = pdf_export.render([_make_incident("inc-c", 2)])
    assert len(blob) > len(single)


def test_pdf_export_empty_list_does_not_crash():
    blob = pdf_export.render([])
    assert blob.startswith(b"%PDF-")


# ──────────────────────────────────────────────────────────────────────────
# Timeline route + single-incident getter
# ──────────────────────────────────────────────────────────────────────────


def test_timeline_orders_iocs_by_first_seen():
    incident = _make_incident(n_iocs=3)
    db.insert_incident(incident)
    client = TestClient(app)

    resp = client.get(f"/incidents/{incident.id}/timeline")
    assert resp.status_code == 200
    body = resp.json()

    assert body["incident_id"] == incident.id
    assert body["severity"] == "critical"
    assert len(body["events"]) == 3
    seen = [e["first_seen"] for e in body["events"]]
    assert seen == sorted(seen)


def test_get_incident_by_id_404_when_missing():
    client = TestClient(app)
    resp = client.get("/incidents/does-not-exist")
    assert resp.status_code == 404


def test_get_incident_by_id_returns_full_pydantic():
    incident = _make_incident("inc-roundtrip-1")
    db.insert_incident(incident)
    client = TestClient(app)

    resp = client.get(f"/incidents/{incident.id}")
    assert resp.status_code == 200
    rehydrated = Incident.model_validate(resp.json())
    assert rehydrated.id == incident.id
    assert rehydrated.compliance_breaches == incident.compliance_breaches


# ──────────────────────────────────────────────────────────────────────────
# Export routes (full HTTP surface)
# ──────────────────────────────────────────────────────────────────────────


def test_export_json_route_returns_attachment():
    db.insert_incident(_make_incident("inc-route-json"))
    client = TestClient(app)
    resp = client.get("/export/json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "attachment" in resp.headers["content-disposition"]
    assert b'"incidents"' in resp.content


def test_export_csv_route_returns_attachment():
    db.insert_incident(_make_incident("inc-route-csv"))
    client = TestClient(app)
    resp = client.get("/export/csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert b"incident_id," in resp.content


def test_export_pdf_route_returns_pdf_bytes():
    db.insert_incident(_make_incident("inc-route-pdf"))
    client = TestClient(app)
    resp = client.get("/export/pdf?id=inc-route-pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-")


def test_export_pdf_404_for_missing_id():
    client = TestClient(app)
    resp = client.get("/export/pdf?id=does-not-exist")
    assert resp.status_code == 404
