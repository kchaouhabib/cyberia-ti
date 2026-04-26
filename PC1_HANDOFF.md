# PC1 — Status & Asks for the Team

**Author:** PC1 · **Date:** 2026-04-26 · **Phase:** end of Phase 3 → entering Phase 4 (integration & demo run)

> Single source of truth for what PC1 has shipped and what PC1 needs from PC2/PC3/PC4 before the live demo.

---

## 1. What PC1 has shipped (Phases 0 → 3)

### Phase 0 — Setup & contracts (locked)
- Repo skeleton, `requirements.txt`, `.env.example`, `.gitignore` (now includes `.claude/settings.local.json`).
- `shared/schemas.py` — **locked** Pydantic contracts. Banking edition: `RawThreatRecord.asset_type`, `EnrichedIOC.apt_attribution`, `Incident.targeted_assets`, `Incident.compliance_breaches`. Do not modify without team consensus.
- `CLAUDE.md`, `BATTLE_PLAN.md` published.

### Phase 1 — Skeleton (live)
- `pc1_data/api.py` — FastAPI service on `:8000`, all CRUD endpoints, idempotent UPSERTs.
- `pc1_data/db.py` — SQLite at `./data/cyberia.db`, WAL mode, 4 tables (`raw_records`, `iocs`, `incidents`, `predictions`). Hybrid storage: indexed scalar columns + `data_json` blob.
- OTX collector (`pc1_data/collectors/otx.py`).

### Phase 2 — Real data (live)
- 5 OSINT collectors, all banking-tagged by construction:
  - `otx.py`, `urlhaus.py`, `threatfox.py`, `malwarebazaar.py`, `misp_circl.py`
- **Bank scenario injector** `pc1_data/collectors/bank_scenario_injector.py` — 4-event Banque Atlas attack chain (phishing → lateral → exfil → SWIFT MT103). IOCs are internally consistent across events so PC3's correlator should detect ONE incident, not four. All synthetic (RFC 5737 IPs, fabricated SHA256, scenario-tagged domain). `--pace N` for live demo cadence.
- VirusTotal + Shodan enrichment wrappers in `pc1_data/enrichment/`. Graceful fallback when API key is missing — never raises 500.
- `POST /enrich` endpoint, `GET /stats` extended with `compliance_breach_count`.

### Phase 3 — Demo glue (live)
- `pc1_data/exporters/` package — JSON, CSV, PDF.
- **PDF report** (`pdf_export.py`, reportlab Platypus) styled as a SOC report a CISO would file: severity-coloured badge, executive summary paragraph, MITRE techniques table with canonical names (lookup encoded from BATTLE_PLAN Appendix E), IOC table, compliance-breach table with notification deadlines (24h SWIFT, 72h GDPR, etc., from BATTLE_PLAN Appendix F).
- 5 new routes (see §2 below).
- `db.get_incident_by_id()` helper.
- 14 new tests in `tests/test_exports.py`. Full suite: **22/22 green** in 1 s.

---

## 2. Live API surface (every endpoint PC2/PC3/PC4 can hit)

Base URL: `http://100.67.61.250:8000` (NetBird) or `http://localhost:8000` locally.

| Method | Path | Purpose | Producer | Consumer |
|---|---|---|---|---|
| GET | `/` | liveness probe | — | anyone |
| POST | `/raw` | push raw threat record | PC1 collectors | PC1 |
| GET | `/raw?limit=N` | list raw records | PC1 | PC2 |
| POST | `/iocs` | push extracted IOC | PC2 | PC1 |
| GET | `/iocs?limit=N` | list IOCs | PC1 | PC2 |
| POST | `/iocs/enriched` | push enriched IOC | PC2 | PC1 |
| GET | `/iocs/enriched?limit=N` | list enriched IOCs | PC1 | PC3 |
| POST | `/enrich` | VT + Shodan lookup | PC1 | PC2 |
| POST | `/incidents` | push correlated incident | PC3 | PC1 |
| GET | `/incidents?limit=N` | list incidents | PC1 | PC4 |
| **GET** | **`/incidents/{id}`** | **single incident, 404 if missing** | **PC1** | **PC4** |
| **GET** | **`/incidents/{id}/timeline`** | **IOC events sorted by `first_seen`** | **PC1** | **PC4** |
| POST | `/predictions` | push prediction (volume / `cve:*` / `apt:*`) | PC3 | PC1 |
| GET | `/predictions` | list predictions | PC1 | PC4 |
| GET | `/stats` | KPI counters incl. `compliance_breach_count` | PC1 | PC4 |
| **GET** | **`/export/json?id=<opt>`** | **JSON download** | **PC1** | **demo** |
| **GET** | **`/export/csv?id=<opt>`** | **flat CSV download** | **PC1** | **demo** |
| **GET** | **`/export/pdf?id=<opt>`** | **SOC-style PDF report** | **PC1** | **demo** |

Bold rows are new in Phase 3. All datetimes are ISO-8601 with TZ. All IDs are strings.

---

## 3. Asks from PC2

> Status check first — hit `GET /iocs/enriched | jq 'map(select(.threat_type)) | length'` and tell me how many enriched IOCs you've shipped today.

1. **Make sure the LLM CISO summarizer is actually populating `Incident.summary`.** Right now `/incidents/{id}` returns generic correlator text:
   ```
   "summary": "141 IOC(s) from 'urlhaus' within 1h window starting 2026-04-25T22:32:45..."
   ```
   The PDF I just shipped renders `Incident.summary` *as the executive summary at the top of every report*. Generic text there looks unprofessional to the jury. Please either:
   - **(a)** Run `pc2_ai/llm_summarizer.py` as a worker that polls `GET /incidents`, generates a CISO paragraph for each, and re-`POST /incidents` with the LLM `summary` (UPSERT on `id` overwrites cleanly), OR
   - **(b)** Coordinate with PC3 to invoke the summarizer inline before they push incidents.
   Either pattern works for me — just need `summary` to be 3-5 plain-language sentences before the demo.
2. **Set `EnrichedIOC.apt_attribution`** in your enrichment classifier when the IOC text or its source pulse mentions a known financial APT (FIN7, Lazarus, Carbanak, Silence, Cobalt Group). My CSV export has a column for it and PC3's behavior analyzer keys off it.
3. **Confirm `threat_type` is set on every `EnrichedIOC` row** before it lands at `/iocs/enriched`. PC3's correlator already requires it; my CSV/PDF exporters render `(unknown)` if it's missing.
4. **Side-by-side LLM vs regex comparison** — make sure `llm_extractor.side_by_side()` is hooked to the demo so we can actually show the jury "regex got N, LLM got N+M". This is one of the visible AI-grade jury moments.

---

## 4. Asks from PC3

> Status check first — hit `GET /incidents | jq '[.[] | {id, severity, assets: .targeted_assets, compl: .compliance_breaches | length}]'` and confirm what's there.

1. **`Incident.targeted_assets` is currently empty on every existing incident** (I checked the live DB — 6 incidents, all with `targeted_assets: []`). My PDF "Targeted assets" section then renders "(none recorded)" and the CSV column is blank. Please populate it from one of these sources:
   - For `source="scenario"` IOCs: the linked `RawThreatRecord.asset_type` is already set (`treasury` / `payment_gateway` / `customer_db` / `swift_terminal`).
   - For OSINT sources (otx, urlhaus, threatfox, malwarebazaar, misp): infer from the IOC value/text — e.g. SWIFT in raw_text → `swift_terminal`, customer/PII keywords → `customer_db`, SMB/445 → `payment_gateway`. Coarse heuristic is fine.
2. **Verify the bank scenario correlation is the demo punchline.** Run `python -m pc1_data.collectors.bank_scenario_injector --pace 0`, then hit `GET /incidents`. The 4 scenario events share IOCs (`MALICIOUS_SHA256`, `C2_IP`, `EXFIL_IP`, `PHISH_DOMAIN`) — your correlator should produce **exactly one** incident with all 4 `asset_type` values in `targeted_assets`. If you produce 4 separate incidents, the demo punchline ("an isolated SOC sees 4 alerts; we see 1 campaign") doesn't land.
3. **`/predictions` UPSERTs cleanly** — your current pipeline is pushing `cve:*` and `apt:*` prefixed rows. Make sure PC4 knows the prefix scheme (`cve:CVE-YYYY-NNNN`, `apt:fin7`, `apt:cluster-3`).
4. **Anomaly detector currently logs only.** Per BATTLE_PLAN.md:178, the Isolation Forest output should surface on PC4's dashboard. Either push anomalies as low-severity `Incident` rows, or as a new prediction prefix (`anomaly:*`). Coordinate with PC4 on what they want to render.

---

## 5. Asks from PC4 (the dashboard)

> Status check first — confirm the React dashboard is polling `GET /stats` every 5s and `GET /incidents` every 5s.

1. **Add a "Download report" button** on the incident detail view. It calls `GET /export/pdf?id=<incident.id>` and triggers a download. The response is `application/pdf` with `Content-Disposition: attachment; filename="incident_<id>.pdf"`.
2. **Add "Download portfolio" buttons** on the alerts list page — one for `GET /export/json` (full incident dump) and one for `GET /export/csv` (analyst pivot). Same download semantics.
3. **Wire the timeline panel** on the incident detail view. Hit `GET /incidents/{id}/timeline`, render the `events` array as a vertical kill-chain (top to bottom = phishing → lateral → exfil → SWIFT). The endpoint already returns events sorted by `first_seen` ascending, so just iterate.
4. **Compliance panel header** — render `compliance_breach_count` from `GET /stats`. It exists today.
5. **Predictions panel** — handle the three `Prediction.threat_type` prefix shapes coming from PC3:
   - bare (`phishing`, `c2`, etc.) → "7-day volume forecast" card
   - `cve:CVE-YYYY-NNNN` → "Patch this first" card (`forecast_7d` carries a 0–100 priority score, not a count)
   - `apt:fin7` / `apt:cluster-3` → "Coordinated campaign detected" card
6. **MITRE heatmap** is already shipped (good!). For the demo, make sure it visibly updates when the scenario injector fires.

---

## 6. Phase 4 dress-rehearsal sequence (BATTLE_PLAN.md:261-279)

When the team is ready to do the integration run, this is the sequence:

1. PC1 starts uvicorn (`uvicorn pc1_data.api:app --reload --host 0.0.0.0 --port 8000`).
2. PC2 starts its pipeline + LLM workers.
3. PC3 starts its pipeline (`python -m pc3_analysis.pipeline`).
4. PC4 opens the React dashboard pointed at PC1.
5. **Team watches dashboard for 10 min** with no events firing.
6. PC1 fires the scenario:
   ```
   python -m pc1_data.collectors.bank_scenario_injector --pace 60
   ```
   4 events × 60 s = 3 wall-clock minutes. Dashboard should react event-by-event:
   - T+0:00 — phishing alert lands, treasury asset lights up
   - T+1:00 — lateral-movement alert, payment_gateway lights up
   - T+2:00 — exfiltration alert, customer_db lights up, GDPR Art.33 timer starts
   - T+3:00 — SWIFT MT103 anomaly, swift_terminal lights up, SWIFT CSP timer starts
   - PC3 correlator merges all 4 into one incident
   - PC2 LLM generates the CISO summary
   - PC4 renders the unified attack timeline + compliance panel + risk gauge
7. Pre-compute pitch KPIs (BATTLE_PLAN.md:271-279):
   - IOCs extracted per minute
   - False-positive reduction vs raw feeds (%)
   - MTTA reduction estimate (seconds vs hours)
   - # MITRE techniques mapped
   - # incidents auto-correlated from N raw events
   - # compliance breaches auto-flagged
   - Cost per incident detected vs traditional SOC analysis

---

## 7. Things PC1 will NOT change in Phase 4

So nobody waits on me:

- The locked Pydantic schemas in `shared/schemas.py`.
- Every existing endpoint signature (Phase 4 is feature-freeze for PC1).
- The PDF/CSV/JSON export contracts.
- Bank scenario injector output (the 4 raw_records and their IOCs are demo-locked).

If something looks wrong on my surface, ping me in chat and I'll fix it as a bug, not a redesign.
