"""
Smoke tests for pc1_data/db.py — Pydantic roundtrip on every table.

Each test gets an isolated DB file under tmp_path so tests don't interfere.
All test data is synthetic — uses RFC-reserved values that are guaranteed
not to be real systems (no real IPs, no real hashes, no real secrets).
"""

from datetime import datetime, timezone

import pytest

from pc1_data import db
from shared.schemas import (
    EnrichedIOC,
    IOC,
    Incident,
    Prediction,
    RawThreatRecord,
)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets a fresh DB file under pytest's tmp_path."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    yield


def _now() -> datetime:
    """Fixed timestamp so test output is deterministic."""
    return datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)


# ──────────────────────────────────────────────────────────────────────────
# raw_records
# ──────────────────────────────────────────────────────────────────────────


def test_raw_roundtrip():
    record = RawThreatRecord(
        id="test-raw-1",
        source="scenario",
        raw_text="phishing email targeting Banque Atlas treasury",
        timestamp=_now(),
        sector="banking",
    )
    db.insert_raw(record)
    out = db.list_raw()
    assert len(out) == 1
    assert out[0].id == "test-raw-1"
    assert out[0].sector == "banking"
    assert out[0].source == "scenario"


def test_raw_idempotent_on_id():
    record = RawThreatRecord(
        id="test-raw-2",
        source="otx",
        raw_text="initial",
        timestamp=_now(),
        sector="banking",
    )
    db.insert_raw(record)
    # Re-fetch the same OTX pulse — should not duplicate
    db.insert_raw(record)
    assert len(db.list_raw()) == 1


# ──────────────────────────────────────────────────────────────────────────
# iocs (insert + enrichment upsert)
# ──────────────────────────────────────────────────────────────────────────


def test_ioc_then_enriched_upsert():
    ioc = IOC(
        value="198.51.100.1",  # TEST-NET-2 reserved range, never routable
        type="ip",
        confidence=0.7,
        source="otx",
        first_seen=_now(),
    )
    db.insert_ioc(ioc)
    assert len(db.list_iocs()) == 1
    assert len(db.list_enriched_iocs()) == 0  # not enriched yet

    enriched = EnrichedIOC(
        value="198.51.100.1",
        type="ip",
        confidence=0.9,
        source="otx",
        first_seen=_now(),
        threat_type="c2",
        related_cves=["CVE-2024-99999"],  # synthetic id, not a real CVE
    )
    db.upsert_enriched_ioc(enriched)
    assert len(db.list_iocs()) == 1  # still one row — UPSERT, not insert
    assert len(db.list_enriched_iocs()) == 1
    assert db.list_enriched_iocs()[0].threat_type == "c2"
    assert db.list_enriched_iocs()[0].related_cves == ["CVE-2024-99999"]


def test_ioc_insert_does_not_overwrite_enriched():
    """Re-extraction of a known IOC must not wipe enrichment."""
    base = IOC(
        value="example.test",  # RFC 6761 reserved domain — guaranteed non-resolving
        type="domain",
        confidence=0.6,
        source="otx",
        first_seen=_now(),
    )
    db.insert_ioc(base)

    enriched = EnrichedIOC(
        value="example.test",
        type="domain",
        confidence=0.8,
        source="otx",
        first_seen=_now(),
        threat_type="phishing",
    )
    db.upsert_enriched_ioc(enriched)

    # PC2 re-extracts the same IOC from a fresh OTX pulse
    db.insert_ioc(base)

    out = db.list_enriched_iocs()
    assert len(out) == 1
    assert out[0].threat_type == "phishing"  # enrichment preserved


# ──────────────────────────────────────────────────────────────────────────
# incidents
# ──────────────────────────────────────────────────────────────────────────


def test_incident_roundtrip():
    enriched = EnrichedIOC(
        value="example.test",
        type="domain",
        confidence=0.95,
        source="otx",
        first_seen=_now(),
        threat_type="phishing",
    )
    incident = Incident(
        id="inc-test-1",
        iocs=[enriched],
        mitre_techniques=["T1566"],
        targeted_sectors=["banking"],
        risk_score=85,
        severity="high",
        summary="Phishing campaign against Banque Atlas treasury",
        detected_at=_now(),
    )
    db.insert_incident(incident)
    out = db.list_incidents()
    assert len(out) == 1
    assert out[0].risk_score == 85
    assert out[0].mitre_techniques == ["T1566"]
    assert out[0].iocs[0].value == "example.test"


# ──────────────────────────────────────────────────────────────────────────
# predictions
# ──────────────────────────────────────────────────────────────────────────


def test_prediction_upsert():
    p = Prediction(
        sector="banking",
        threat_type="phishing",
        forecast_7d=42.0,
        trend="rising",
        confidence=0.8,
    )
    db.upsert_prediction(p)
    assert len(db.list_predictions()) == 1

    # Updated forecast — same key, new value
    p2 = Prediction(
        sector="banking",
        threat_type="phishing",
        forecast_7d=58.0,
        trend="rising",
        confidence=0.85,
    )
    db.upsert_prediction(p2)
    out = db.list_predictions()
    assert len(out) == 1  # still one row
    assert out[0].forecast_7d == 58.0


# ──────────────────────────────────────────────────────────────────────────
# stats
# ──────────────────────────────────────────────────────────────────────────


def test_stats_grouping_by_sector():
    db.insert_raw(RawThreatRecord(
        id="r1", source="otx", raw_text="t", timestamp=_now(), sector="banking",
    ))
    db.insert_raw(RawThreatRecord(
        id="r2", source="otx", raw_text="t", timestamp=_now(), sector="banking",
    ))
    db.insert_raw(RawThreatRecord(
        id="r3", source="otx", raw_text="t", timestamp=_now(), sector="telecom",
    ))
    s = db.get_stats()
    assert s["raw_count"] == 3
    assert s["by_sector"]["banking"] == 2
    assert s["by_sector"]["telecom"] == 1
    assert s["by_sector"]["healthcare"] == 0
