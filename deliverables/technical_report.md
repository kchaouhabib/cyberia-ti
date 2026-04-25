# Technical Report — CYBERIA TI Platform
**Cyberia 2026 Hackathon · ESPRIT · Banking Edition**

---

## 1. Executive Summary

The CYBERIA TI Platform is an AI-powered Threat Intelligence system built for Tier-2/Tier-3 banks in emerging markets. It ingests scattered OSINT feeds and simulated SOC alerts, processes them through a 5-stage AI pipeline, and delivers prioritized, MITRE ATT&CK-mapped, compliance-tagged intelligence to a real-time dashboard — reducing Mean Time To Action (MTTA) from hours to seconds.

**Target user:** Bank CISO and SOC analysts who need enterprise-grade threat intelligence without a Recorded Future or Mandiant budget.

---

## 2. System Architecture

### 2.1 The 5-Stage Pipeline

```
┌─────────────────┐    ┌──────────────┐    ┌──────────────────┐    ┌────────────┐    ┌───────────────────┐
│  Stage 01       │    │  Stage 02    │    │  Stage 03        │    │  Stage 04  │    │  Stage 05         │
│  Data Sources   │───▶│  AI Engine   │───▶│  Detection &     │───▶│ Prediction │───▶│ Dashboard &       │
│  (PC1)          │    │  (PC2)       │    │  Analysis (PC3)  │    │  (PC3)     │    │ Action (PC4)      │
└─────────────────┘    └──────────────┘    └──────────────────┘    └────────────┘    └───────────────────┘
```

### 2.2 Component Breakdown

| PC | Stage | Technologies | Responsibility |
|---|---|---|---|
| PC1 | Data Sources | FastAPI, SQLite, Python | OSINT collection, scenario injection, enrichment wrappers, REST API |
| PC2 | AI Engine | scikit-learn, spaCy, sentence-transformers, Ollama | IOC extraction, classification, deduplication, LLM summaries |
| PC3 | Detection & Prediction | MITRE ATT&CK STIX, Prophet, scikit-learn | Correlation, MITRE mapping, compliance tagging, risk scoring, forecasting |
| PC4 | Dashboard & Action | Streamlit, Plotly, Folium | Real-time visualization, compliance panel, deliverables |

### 2.3 Network Architecture

All 4 machines communicate over a **NetBird** WireGuard mesh VPN:

```
PC1 (100.67.61.250)  ←──── FastAPI :8000 ─────▶  PC2, PC3, PC4
PC4 (100.67.152.56)  ←──── Streamlit :8501 ──────▶  Jury browser
```

- **Single source of truth:** PC1's SQLite database, exposed via FastAPI
- **No direct DB access:** PC2, PC3, PC4 only read/write through REST endpoints
- **Code sync:** GitHub (branch per PC, merge to `main` every 1–2h)

---

## 3. Stage 01 — Data Sources (PC1)

### 3.1 OSINT Collectors

| Source | Type | Banking Relevance |
|---|---|---|
| AlienVault OTX | Threat pulses | Filtered by `banking`, `finance`, `swift` tags |
| URLhaus (Abuse.ch) | Malicious URLs | Banking phishing infrastructure |
| ThreatFox (Abuse.ch) | IOCs by malware family | Emotet, TrickBot, Carbanak, Dridex, Cobalt Strike |
| MalwareBazaar (Abuse.ch) | Malware samples & hashes | Banking trojans |
| Bank Scenario Injector | Simulated SOC alerts | Staged attack on "Banque Atlas" |

### 3.2 Bank Scenario Injector

A hand-crafted JSON scenario staged as a coordinated 3-wave attack on fictional bank **"Banque Atlas"**:

1. **Wave 1** — Spear-phishing emails impersonating BCT (Banque Centrale de Tunisie) circulars targeting the treasury department
2. **Wave 2** — Lateral movement: compromised treasury workstation → payment gateway server (T1078)
3. **Wave 3** — Data exfiltration to known Lazarus-attributed C2 IP + SWIFT MT103 anomaly (T1041)

This ensures the dashboard visibly reacts during the live demo even without real-time IOC feeds.

### 3.3 Enrichment Pipeline

- **VirusTotal wrapper** — reputation score and malware family tags per IOC
- **Shodan wrapper** — geolocation, open ports, organization for IP IOCs

### 3.4 REST API

FastAPI serving 11 endpoints. Key PC4-facing endpoints:

| Method | Path | Returns |
|---|---|---|
| GET | `/incidents` | List of correlated, scored, MITRE-tagged incidents |
| GET | `/predictions` | 7-day threat forecasts per sector/threat type |
| GET | `/stats` | KPI counts (raw records, IOCs, incidents, compliance hits) |
| GET | `/export/pdf` | Auto-generated CISO incident report (PDF) |

---

## 4. Stage 02 — AI Engine (PC2)

### 4.1 IOC Extraction
- **Regex extractor:** IPs, MD5/SHA256 hashes, domains, URLs, CVEs — fast, deterministic
- **LLM extractor (Phase 3):** Ollama + Llama 3.2 3B — catches IOCs regex misses (obfuscated SWIFT codes, banking-specific terms)
- **Side-by-side demo:** regex extracted N, LLM extracted N+M

### 4.2 Classification
- **Model:** scikit-learn classifier (Logistic Regression / Random Forest)
- **Classes:** `phishing | malware | lateral_movement | exfiltration | c2`
- **Training bias:** financial-sector samples (banking breach datasets)

### 4.3 Deduplication
- `sentence-transformers` embeddings + cosine similarity threshold (0.85)
- Prevents alert fatigue from repeated IOCs across feeds

### 4.4 Named Entity Recognition
- spaCy NER tuned to flag financial APTs: **Carbanak, FIN7, Lazarus, Silence, Cobalt Group**

### 4.5 Confidence Scoring
- Per-source weighted historical false-positive rate
- Higher-confidence IOCs get higher risk weight in PC3

---

## 5. Stage 03 — Detection & Analysis (PC3)

### 5.1 Correlation Engine
- Groups enriched IOCs by source + 1-hour time window → one `Incident`
- Avoids alert flooding from fragmented feeds

### 5.2 MITRE ATT&CK Mapping (Financial Focus)

| Trigger | Technique | Name |
|---|---|---|
| Phishing email IOC | T1566 | Phishing |
| Suspicious admin login | T1078 | Valid Accounts |
| Web session cookie theft | T1539 | Steal Web Session Cookie |
| Public-facing app exploit | T1190 | Exploit Public-Facing App |
| Large outbound transfer | T1041 | Exfiltration over C2 |
| Known C2 domain | T1071 | Application Layer Protocol |
| Ransomware behavior | T1486 | Data Encrypted for Impact |

### 5.3 Risk Scoring Formula

```
risk_score = severity × sector_criticality × IOC_confidence × compliance_weight

Where:
  banking sector_criticality = 1.0   (primary focus)
  telecom / healthcare       = 0.5   (configurable → scalable architecture)
  compliance_weight          = +20%  if PCI-DSS scope asset is involved
```

### 5.4 Compliance Mapper (Killer Feature)

Every incident is automatically tagged with regulatory frameworks it would breach:

| Trigger | Framework | Article | Deadline |
|---|---|---|---|
| Cardholder data exposure | PCI-DSS | Req. 3 | Per acquirer contract |
| Logging/monitoring gap | PCI-DSS | Req. 10 | Audit cycle |
| SWIFT message anomaly | SWIFT CSP | CSCF 2.x | 24h to SWIFT |
| Personal data breach | GDPR | Art. 33 | **72h to regulator** |
| Operational risk event | Basel III | ORR | Per local implementation |
| Bank operations affected | BCT Circular | — | Per local circular |

### 5.5 Anomaly Detection
- **Isolation Forest** on event volume per asset type per hour
- Flags statistically abnormal spikes automatically

---

## 6. Stage 04 — Prediction (PC3)

### 6.1 Time-Series Forecasting
- **Prophet** (Facebook/Meta) for 7-day attack volume forecasts per sector/threat type
- Output: *"Phishing against treasury operations forecast +40% in 7 days"*
- Needs ~30 data points — supplemented with synthetic scenario history

### 6.2 CVE Prioritization
- Rank: `recency × severity × IOC_frequency × banking-stack-relevance`
- Boosted CVEs: Oracle DB, Temenos, Finastra, SWIFT messaging stacks

### 6.3 Behavior Clustering
- **KMeans** on incident feature vectors → clusters → flag coordinated APT campaigns
- Matched against known financial APT TTPs (FIN7, Lazarus, Carbanak)

---

## 7. Stage 05 — Dashboard & Action (PC4)

### 7.1 Technology Stack
- **Streamlit 1.40+** — Python-native web app, no frontend skills required
- **Plotly** — interactive gauge chart, animated bar charts
- **Folium + streamlit-folium** — world map of attack origins
- **Auto-refresh:** `@st.fragment(run_every=5)` — native 5-second refresh, no sleep loops

### 7.2 Dashboard Panels

| Panel | Data Source | Purpose |
|---|---|---|
| KPI Bar | `GET /stats` | Raw records, IOCs, incidents, compliance hits at a glance |
| Risk Gauge | `GET /incidents` | Max risk score (0–100) across active incidents |
| Compliance Panel | `GET /incidents` | Live breach counts per framework + notification deadlines |
| World Map | `GET /incidents` → IOC geolocation | Attack origin visualization |
| APT Panel | `GET /incidents` → IOC attribution | Active threat actor tracking |
| Top Threats Bar | `GET /incidents` → IOC threat_type | Phishing / Malware / Lateral / Exfil / C2 |
| Live Alerts | `GET /incidents` | Color-coded, sorted by severity, expandable |
| Asset View | `GET /incidents` → targeted_assets | Treasury / Payment Gateway / Customer DB |
| Predictions | `GET /predictions` | 7-day forecast table with trend indicators |

### 7.3 Design Decisions
- **Crash-proof:** every API call wrapped in try/except — dashboard shows empty state if PC1 is down
- **Dark theme:** custom CSS injected via `st.markdown` — professional SOC aesthetic
- **Bank-specific:** asset view uses Banque Atlas assets, not generic sector labels
- **SWIFT alert banner:** if SWIFT Terminal is targeted, a red error banner fires at the top of asset view

---

## 8. Sector Scalability

The platform is **sector-agnostic by design.** Banking is the anchor sector, but:

- `sector_criticality` is a config parameter (currently `banking=1.0`, `telecom=0.5`, `healthcare=0.5`)
- Compliance frameworks are a pluggable mapping dict in `pc3_analysis/compliance_mapper.py`
- Adding healthcare support = swap PCI-DSS → HIPAA/GDPR-health in the compliance dict
- Adding telecom support = swap SWIFT CSP → NIS2 in the compliance dict
- Zero code rewrites required in any other module

**Answer to jury question "Can this work for other sectors?":**
*"Yes. Sector criticality and compliance frameworks are configurable parameters. We started with banking because regional banks face regulatory urgency without affordable tools. Healthcare (HIPAA, GDPR-health) and telecom (NIS2) are a config change away."*

---

## 9. Demo Scenario — Live Walkthrough

During the pitch, PC1 triggers the staged Banque Atlas attack in real time:

| Demo Minute | Event | Dashboard Reaction |
|---|---|---|
| 0:30 | Spear-phishing email lands (BCT impersonation) | Phishing alert appears, T1566 mapped |
| 1:00 | Lateral movement: treasury → payment gateway | High alert, T1078, Asset View lights up |
| 1:30 | Exfiltration to Lazarus C2 + SWIFT anomaly | Critical alert, SWIFT CSP breach fires, 24h deadline shown |
| 2:00 | Risk gauge peaks, compliance panel full | Jury sees full platform in action |

---

## 10. Performance KPIs

*(To be measured and locked in Phase 4)*

| KPI | Target |
|---|---|
| IOCs extracted per minute | TBD |
| False-positive reduction vs raw feeds | TBD % |
| MTTA reduction | TBD seconds vs manual hours |
| MITRE techniques mapped | TBD |
| Compliance breaches auto-flagged | TBD |
| Prediction accuracy (backtested) | TBD % |

---

*Phase 2 draft — screenshots and final KPIs added in Phase 4.*
