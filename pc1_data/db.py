"""
PC1 SQLite persistence layer.

Maps directly onto shared/schemas.py:
  raw_records  ← RawThreatRecord
  iocs         ← IOC + EnrichedIOC (enrichment fields nullable; one row per IOC)
  incidents    ← Incident
  predictions  ← Prediction

Storage strategy: indexed scalar columns for filters + a `data_json`
column with the full Pydantic-serialized model. Reads are a single
JSON parse; writes are a single string format. No ALTER TABLE needed
when the schema gains optional fields.

Single source of truth for the team. PC2/3/4 never touch this file —
they only see it via PC1's HTTP API.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List

from shared.schemas import (
    EnrichedIOC,
    IOC,
    Incident,
    Prediction,
    RawThreatRecord,
)

DB_PATH = os.getenv("DB_PATH", "./data/cyberia.db")


# ──────────────────────────────────────────────────────────────────────────
# DDL — 4 tables (raw_records, iocs, incidents, predictions)
# ──────────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_records (
    id        TEXT PRIMARY KEY,
    source    TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    sector    TEXT,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raw_source ON raw_records(source);
CREATE INDEX IF NOT EXISTS idx_raw_sector ON raw_records(sector);

CREATE TABLE IF NOT EXISTS iocs (
    value       TEXT NOT NULL,
    type        TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    confidence  REAL,
    threat_type TEXT,                -- NULL until /iocs/enriched UPSERT lands
    data_json   TEXT NOT NULL,        -- IOC or EnrichedIOC, full Pydantic dump
    PRIMARY KEY (value, type, source)
);
CREATE INDEX IF NOT EXISTS idx_iocs_threat_type ON iocs(threat_type);
CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON iocs(first_seen);

CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    detected_at TEXT NOT NULL,
    severity    TEXT,
    risk_score  INTEGER,
    data_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inc_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_detected ON incidents(detected_at);

CREATE TABLE IF NOT EXISTS predictions (
    sector      TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    data_json   TEXT NOT NULL,
    PRIMARY KEY (sector, threat_type)
);
"""


# ──────────────────────────────────────────────────────────────────────────
# Connection management
# ──────────────────────────────────────────────────────────────────────────


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection in WAL mode, with row-factory set to dict-like rows.

    Per-call connection is fine here — SQLite open-in-WAL is sub-millisecond
    and per-call avoids the threading hassle of a shared connection inside
    FastAPI (which dispatches sync routes via a thread pool).
    """
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create tables and indexes if they don't already exist. Idempotent.

    Called once on FastAPI startup (see api.py).
    """
    with get_conn() as conn:
        conn.executescript(_SCHEMA_SQL)


# ──────────────────────────────────────────────────────────────────────────
# Raw records
# ──────────────────────────────────────────────────────────────────────────


def insert_raw(record: RawThreatRecord) -> None:
    """UPSERT a raw record. Idempotent on `id` — re-fetching the same OTX
    pulse does not create duplicates."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO raw_records
                (id, source, timestamp, sector, data_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.source,
                record.timestamp.isoformat(),
                record.sector,
                record.model_dump_json(),
            ),
        )


def list_raw(limit: int = 100) -> List[RawThreatRecord]:
    """List raw records, newest first. PC2 polls this for work."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT data_json FROM raw_records ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [RawThreatRecord.model_validate_json(r["data_json"]) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# IOCs (raw + enriched share the table; enrichment fills `threat_type`)
# ──────────────────────────────────────────────────────────────────────────


def insert_ioc(ioc: IOC) -> None:
    """INSERT a fresh IOC. INSERT-OR-IGNORE on (value, type, source) so a
    re-extraction never wipes enrichment that PC2 has already done. Use
    `upsert_enriched_ioc` for the enrichment phase.
    """
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO iocs
                (value, type, source, first_seen, confidence, threat_type, data_json)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                ioc.value,
                ioc.type,
                ioc.source,
                ioc.first_seen.isoformat(),
                ioc.confidence,
                ioc.model_dump_json(),
            ),
        )


def upsert_enriched_ioc(ioc: EnrichedIOC) -> None:
    """UPSERT an enriched IOC. Fills `threat_type` and replaces the JSON
    blob with the fully-typed EnrichedIOC variant.
    """
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO iocs
                (value, type, source, first_seen, confidence, threat_type, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc.value,
                ioc.type,
                ioc.source,
                ioc.first_seen.isoformat(),
                ioc.confidence,
                ioc.threat_type,
                ioc.model_dump_json(),
            ),
        )


def list_iocs(limit: int = 1000) -> List[IOC]:
    """List ALL IOCs (raw + enriched), parsed as the base IOC type."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT data_json FROM iocs ORDER BY first_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [IOC.model_validate_json(r["data_json"]) for r in rows]


def list_enriched_iocs(limit: int = 1000) -> List[EnrichedIOC]:
    """List IOCs that have been enriched (threat_type IS NOT NULL).
    PC3 polls this for correlation work."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT data_json FROM iocs
            WHERE threat_type IS NOT NULL
            ORDER BY first_seen DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [EnrichedIOC.model_validate_json(r["data_json"]) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Incidents
# ──────────────────────────────────────────────────────────────────────────


def insert_incident(incident: Incident) -> None:
    """UPSERT an incident on `id`. Re-correlation may produce updated
    incident rows; the latest correlation wins."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO incidents
                (id, detected_at, severity, risk_score, data_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident.id,
                incident.detected_at.isoformat(),
                incident.severity,
                incident.risk_score,
                incident.model_dump_json(),
            ),
        )


def list_incidents(limit: int = 200) -> List[Incident]:
    """List incidents, newest first. PC4 dashboard polls this every 5s."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT data_json FROM incidents ORDER BY detected_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [Incident.model_validate_json(r["data_json"]) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Predictions
# ──────────────────────────────────────────────────────────────────────────


def upsert_prediction(p: Prediction) -> None:
    """UPSERT one forecast per (sector, threat_type) pair. PC3 re-runs Prophet
    periodically; the latest forecast wins."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO predictions
                (sector, threat_type, data_json)
            VALUES (?, ?, ?)
            """,
            (p.sector, p.threat_type, p.model_dump_json()),
        )


def list_predictions() -> List[Prediction]:
    """List all current predictions. PC4 dashboard polls this every 5s."""
    with get_conn() as conn:
        rows = conn.execute("SELECT data_json FROM predictions").fetchall()
    return [Prediction.model_validate_json(r["data_json"]) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Stats (dashboard header)
# ──────────────────────────────────────────────────────────────────────────


def get_stats() -> dict:
    """Aggregate counts for the dashboard header. Polled every 5s by PC4 —
    keep it cheap: one round-trip, indexed-column queries only."""
    with get_conn() as conn:
        raw_count = conn.execute("SELECT COUNT(*) FROM raw_records").fetchone()[0]
        ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        enriched_count = conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE threat_type IS NOT NULL"
        ).fetchone()[0]
        incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        prediction_count = conn.execute(
            "SELECT COUNT(*) FROM predictions"
        ).fetchone()[0]

        sector_rows = conn.execute(
            """
            SELECT sector, COUNT(*) AS n
            FROM raw_records
            WHERE sector IS NOT NULL
            GROUP BY sector
            """
        ).fetchall()

    by_sector = {"banking": 0, "telecom": 0, "healthcare": 0}
    for row in sector_rows:
        if row["sector"] in by_sector:
            by_sector[row["sector"]] = row["n"]

    return {
        "raw_count": raw_count,
        "ioc_count": ioc_count,
        "enriched_count": enriched_count,
        "incident_count": incident_count,
        "prediction_count": prediction_count,
        "by_sector": by_sector,
    }
