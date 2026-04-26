"""
PC1 FastAPI service — single source of truth for the team.

All endpoints validate input via Pydantic at the network boundary and
persist to SQLite via pc1_data/db.py. PC2/3/4 only see this surface —
they never touch the DB directly. This keeps the locked schema in
shared/schemas.py as the only contract that matters.
"""

from typing import Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

# Load .env into os.environ at import time so uvicorn-spawned routes (e.g.
# /enrich → VirusTotal/Shodan wrappers) can read the API keys via os.getenv.
# Collectors already do this in their own main(); the FastAPI app needs its
# own call because it has no main().
load_dotenv()

from pc1_data import db
from pc1_data.enrichment import shodan as shodan_enrich
from pc1_data.enrichment import virustotal as vt_enrich
from pc1_data.exporters import csv_export, json_export, pdf_export
from shared.schemas import (
    EnrichedIOC,
    IOC,
    Incident,
    Prediction,
    RawThreatRecord,
)


class EnrichRequest(BaseModel):
    """Body for POST /enrich. type uses the same vocabulary as IOC.type."""

    value: str
    type: str

app = FastAPI(
    title="CYBERIA Threat Intelligence API",
    version="0.2.0",
    description="PC1 backbone — single source of truth for raw records, IOCs, incidents, predictions.",
)


@app.on_event("startup")
def _startup() -> None:
    """Create SQLite tables on first launch. Idempotent."""
    db.init_db()


# ──────────────────────────────────────────────────────────────────────────
# HEALTH
# ──────────────────────────────────────────────────────────────────────────


@app.get("/")
def root() -> Dict[str, str]:
    """Liveness probe — used by teammates to verify ZeroTier reachability."""
    return {"status": "ok", "service": "cyberia-ti", "version": "0.2.0"}


# ──────────────────────────────────────────────────────────────────────────
# RAW RECORDS (collectors → /raw, PC2 reads /raw)
# ──────────────────────────────────────────────────────────────────────────


@app.post("/raw")
def push_raw(record: RawThreatRecord) -> Dict[str, str]:
    """Accept a raw threat record from a collector or the scenario injector."""
    db.insert_raw(record)
    return {"ok": "true", "id": record.id}


@app.get("/raw", response_model=List[RawThreatRecord])
def list_raw(limit: int = 100) -> List[RawThreatRecord]:
    """List raw records, newest first. PC2 polls this for work."""
    return db.list_raw(limit=limit)


# ──────────────────────────────────────────────────────────────────────────
# IOCs (PC2 → /iocs and /iocs/enriched, PC3 reads /iocs/enriched)
# ──────────────────────────────────────────────────────────────────────────


@app.post("/iocs")
def push_ioc(ioc: IOC) -> Dict[str, str]:
    """Accept an extracted IOC (pre-enrichment).

    INSERT-OR-IGNORE on (value, type, source) so a re-extraction never wipes
    enrichment that has already landed.
    """
    db.insert_ioc(ioc)
    return {"ok": "true", "value": ioc.value}


@app.get("/iocs", response_model=List[IOC])
def list_iocs(limit: int = 1000) -> List[IOC]:
    """List all IOCs (raw + enriched), as base IOC."""
    return db.list_iocs(limit=limit)


@app.post("/iocs/enriched")
def push_enriched_ioc(ioc: EnrichedIOC) -> Dict[str, str]:
    """Accept an enriched IOC. UPSERTs over the existing IOC row."""
    db.upsert_enriched_ioc(ioc)
    return {"ok": "true", "value": ioc.value}


@app.get("/iocs/enriched", response_model=List[EnrichedIOC])
def list_enriched_iocs(limit: int = 1000) -> List[EnrichedIOC]:
    """List enriched IOCs only. PC3 polls this for correlation."""
    return db.list_enriched_iocs(limit=limit)


# ──────────────────────────────────────────────────────────────────────────
# ENRICHMENT (PC2 calls /enrich during the enrichment phase)
# ──────────────────────────────────────────────────────────────────────────


@app.post("/enrich")
def enrich_ioc(req: EnrichRequest) -> Dict[str, object]:
    """Look up an IOC against VirusTotal + Shodan and return summarised
    enrichment. Both backends gracefully degrade if their key is missing —
    callers always get a typed dict, never a 500.
    """
    return {
        "value": req.value,
        "type": req.type,
        "vt": vt_enrich.lookup(req.value, req.type),
        "shodan": shodan_enrich.lookup(req.value, req.type),
    }


# ──────────────────────────────────────────────────────────────────────────
# INCIDENTS (PC3 → /incidents, PC4 reads /incidents)
# ──────────────────────────────────────────────────────────────────────────


@app.post("/incidents")
def push_incident(incident: Incident) -> Dict[str, str]:
    """Accept a correlated incident. Latest correlation wins (UPSERT on id)."""
    db.insert_incident(incident)
    return {"ok": "true", "id": incident.id}


@app.get("/incidents", response_model=List[Incident])
def list_incidents(limit: int = 200) -> List[Incident]:
    """List all incidents, newest first. PC4 dashboard polls this every 5s."""
    return db.list_incidents(limit=limit)


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    """Fetch one incident by id. 404 if missing."""
    inc = db.get_incident_by_id(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail=f"incident {incident_id!r} not found")
    return inc


@app.get("/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str) -> Dict[str, object]:
    """Ordered IOC events for one incident — feeds PC4's attack-timeline panel.

    Events are sorted by `first_seen` ascending so the front-end can render a
    top-to-bottom kill-chain (phishing → lateral → exfil → c2 / SWIFT anomaly).
    """
    inc = db.get_incident_by_id(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail=f"incident {incident_id!r} not found")
    events = sorted(inc.iocs, key=lambda i: i.first_seen)
    return {
        "incident_id": inc.id,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "detected_at": inc.detected_at.isoformat(),
        "summary": inc.summary,
        "events": [
            {
                "first_seen": ioc.first_seen.isoformat(),
                "ioc_value": ioc.value,
                "ioc_type": ioc.type,
                "threat_type": ioc.threat_type,
                "apt_attribution": ioc.apt_attribution,
                "confidence": ioc.confidence,
                "geolocation": ioc.geolocation,
                "source": ioc.source,
            }
            for ioc in events
        ],
    }


# ──────────────────────────────────────────────────────────────────────────
# PREDICTIONS (PC3 → /predictions, PC4 reads /predictions)
# ──────────────────────────────────────────────────────────────────────────


@app.post("/predictions")
def push_prediction(prediction: Prediction) -> Dict[str, str]:
    """Accept a 7-day forecast. UPSERT — one row per (sector, threat_type)."""
    db.upsert_prediction(prediction)
    return {"ok": "true", "sector": prediction.sector}


@app.get("/predictions", response_model=List[Prediction])
def list_predictions() -> List[Prediction]:
    """List current predictions. PC4 dashboard polls this every 5s."""
    return db.list_predictions()


# ──────────────────────────────────────────────────────────────────────────
# DASHBOARD STATS (PC4 reads /stats)
# ──────────────────────────────────────────────────────────────────────────


@app.get("/stats")
def stats() -> Dict[str, object]:
    """Aggregate counts for the dashboard header. Polled every 5s by PC4."""
    return db.get_stats()


# ──────────────────────────────────────────────────────────────────────────
# EXPORTS (demo + CISO deliverables) — JSON / CSV / PDF
# ──────────────────────────────────────────────────────────────────────────


def _resolve_export_set(incident_id: Optional[str]) -> List[Incident]:
    """Resolve the incident list for an export. 404 if a specific id is missing."""
    if incident_id:
        inc = db.get_incident_by_id(incident_id)
        if inc is None:
            raise HTTPException(
                status_code=404, detail=f"incident {incident_id!r} not found"
            )
        return [inc]
    return db.list_incidents(limit=1000)


def _attachment_headers(filename: str) -> Dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


@app.get("/export/json")
def export_json(id: Optional[str] = None) -> Response:
    """Download incidents as a JSON document. `?id=` exports one incident."""
    incidents = _resolve_export_set(id)
    payload = json_export.render(incidents)
    fname = f"incident_{id}.json" if id else "incidents.json"
    return Response(
        content=payload,
        media_type="application/json",
        headers=_attachment_headers(fname),
    )


@app.get("/export/csv")
def export_csv(id: Optional[str] = None) -> Response:
    """Download incidents as a flattened CSV. `?id=` exports one incident."""
    incidents = _resolve_export_set(id)
    payload = csv_export.render(incidents)
    fname = f"incident_{id}.csv" if id else "incidents.csv"
    return Response(
        content=payload,
        media_type="text/csv; charset=utf-8",
        headers=_attachment_headers(fname),
    )


@app.get("/export/pdf")
def export_pdf(id: Optional[str] = None) -> Response:
    """Download a SOC-style PDF report. `?id=` exports one incident with appendix."""
    incidents = _resolve_export_set(id)
    payload = pdf_export.render(incidents)
    fname = f"incident_{id}.pdf" if id else "incidents.pdf"
    return Response(
        content=payload,
        media_type="application/pdf",
        headers=_attachment_headers(fname),
    )
