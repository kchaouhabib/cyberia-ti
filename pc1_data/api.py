"""
PC1 FastAPI service — single source of truth for the team.

Phase 1 stub: every endpoint exists and validates input via Pydantic,
but returns mock empty data. Phase 2 wires real SQLite persistence.
"""

from typing import Dict, List

from fastapi import FastAPI

from shared.schemas import (
    EnrichedIOC,
    IOC,
    Incident,
    Prediction,
    RawThreatRecord,
)

app = FastAPI(
    title="CYBERIA Threat Intelligence API",
    version="0.1.0",
    description="PC1 backbone — single source of truth for raw records, IOCs, incidents, predictions.",
)


# ──────────────────────────────────────────────────────────────────────────
# HEALTH
# ──────────────────────────────────────────────────────────────────────────

@app.get("/")
def root() -> Dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "cyberia-ti", "version": "0.1.0"}


# ──────────────────────────────────────────────────────────────────────────
# RAW RECORDS (collectors → /raw, PC2 reads /raw)
# ──────────────────────────────────────────────────────────────────────────

@app.post("/raw")
def push_raw(record: RawThreatRecord) -> Dict[str, str]:
    """Accept a raw threat record from a collector or the scenario injector."""
    # TODO Phase 1: persist to SQLite raw_records table
    return {"ok": "true", "id": record.id}


@app.get("/raw", response_model=List[RawThreatRecord])
def list_raw() -> List[RawThreatRecord]:
    """List all raw records. PC2 polls this to find work."""
    # TODO Phase 1: SELECT * FROM raw_records
    return []


# ──────────────────────────────────────────────────────────────────────────
# IOCs (PC2 → /iocs and /iocs/enriched, PC3 reads /iocs/enriched)
# ──────────────────────────────────────────────────────────────────────────

@app.post("/iocs")
def push_ioc(ioc: IOC) -> Dict[str, str]:
    """Accept an extracted IOC (pre-enrichment)."""
    return {"ok": "true", "value": ioc.value}


@app.get("/iocs", response_model=List[IOC])
def list_iocs() -> List[IOC]:
    """List all IOCs."""
    return []


@app.post("/iocs/enriched")
def push_enriched_ioc(ioc: EnrichedIOC) -> Dict[str, str]:
    """Accept an enriched IOC (post-VT/Shodan/classifier)."""
    return {"ok": "true", "value": ioc.value}


@app.get("/iocs/enriched", response_model=List[EnrichedIOC])
def list_enriched_iocs() -> List[EnrichedIOC]:
    """List enriched IOCs. PC3 polls this for correlation."""
    return []


# ──────────────────────────────────────────────────────────────────────────
# INCIDENTS (PC3 → /incidents, PC4 reads /incidents)
# ──────────────────────────────────────────────────────────────────────────

@app.post("/incidents")
def push_incident(incident: Incident) -> Dict[str, str]:
    """Accept a correlated incident."""
    return {"ok": "true", "id": incident.id}


@app.get("/incidents", response_model=List[Incident])
def list_incidents() -> List[Incident]:
    """List all incidents. PC4 dashboard polls this."""
    return []


# ──────────────────────────────────────────────────────────────────────────
# PREDICTIONS (PC3 → /predictions, PC4 reads /predictions)
# ──────────────────────────────────────────────────────────────────────────

@app.post("/predictions")
def push_prediction(prediction: Prediction) -> Dict[str, str]:
    """Accept a 7-day forecast for a (sector, threat_type) pair."""
    return {"ok": "true", "sector": prediction.sector}


@app.get("/predictions", response_model=List[Prediction])
def list_predictions() -> List[Prediction]:
    """List predictions. PC4 dashboard polls this."""
    return []


# ──────────────────────────────────────────────────────────────────────────
# DASHBOARD STATS (PC4 reads /stats)
# ──────────────────────────────────────────────────────────────────────────

@app.get("/stats")
def stats() -> Dict[str, object]:
    """Aggregate counts for the dashboard header."""
    return {
        "raw_count": 0,
        "ioc_count": 0,
        "enriched_count": 0,
        "incident_count": 0,
        "prediction_count": 0,
        "by_sector": {"banking": 0, "telecom": 0, "healthcare": 0},
    }
