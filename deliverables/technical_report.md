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

| Layer | Technology | Version |
|---|---|---|
| Framework | React + Vite | React 18, Vite 8 |
| Animations | Framer Motion | AnimatePresence, motion.div, layoutId |
| Charts | Recharts | RadialBarChart, BarChart, AreaChart |
| Styling | Tailwind CSS v4 | @tailwindcss/vite plugin |
| Icons | Lucide React | — |
| Auto-refresh | useEffect + setInterval | 5-second polling loop |

### 7.2 Multi-Page Architecture

The dashboard is a **5-page single-page application** with page-state navigation (no router):

| Page | Key Visuals | Data Source |
|---|---|---|
| Overview | KPI bar, risk gauge, top threats bar, recent alerts, **MITRE heatmap** | `/incidents`, `/stats` |
| Live Alerts | Severity filter bar, expandable alert rows, AI CISO summary, MITRE badges | `/incidents` |
| Compliance | Framework breach counters (5 frameworks), breach table with deadlines, regulation reference | `/incidents` |
| Asset Intelligence | Asset cards (Treasury/Pay GW/Customer DB/SWIFT), attack origins map, APT groups | `/incidents` |
| Threat Predictions | Forecast cards (7d forecast + confidence), sector bar chart, rising threat area charts | `/predictions` |

### 7.3 Signature Components

**MITRE ATT&CK Heatmap** — 7 financial techniques × 4 bank assets matrix, color-coded by incident frequency (orange → red gradient). Biggest visual differentiator in the demo.

**Risk Gauge** — RadialBarChart semicircle (0–100), color-coded green/orange/red. Animates on every data refresh.

**AI CISO Summary** — Each alert row expands to show an AI-generated executive summary from PC2's Ollama LLM, badged as "✦ AI CISO SUMMARY" with a cyan accent.

**Compliance Breach Table** — Each breach row shows: incident ID, regulation + article (e.g., "GDPR Art.33"), notification deadline (e.g., "72 hours → regulator"), urgency color.

**SWIFT Emergency Banner** — Full-width pulsing red banner fires when `swift_terminal` is in targeted_assets. Includes "notify within 24h" instruction.

### 7.4 Design Decisions

- **Crash-proof:** every API call wrapped in try/catch with AbortSignal.timeout(4000) — dashboard shows empty state if PC1 is down, never breaks
- **Dark SOC theme:** `#050d1a` background, `#0a1628` cards, `#1e3a5f` borders, `#00d4ff` accent — professional SOC aesthetic matching real-world platforms
- **Animated page transitions:** `AnimatePresence mode="wait"` with slide-in (x:20→0) / slide-out (x:0→-20) between pages
- **Live tick counter:** footer shows tick #N and total IOC count updating every 5s — visible proof of live data

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

*Phase 3 complete — KPI numbers to be measured and locked in Phase 4. Screenshots to be added post-demo.*
