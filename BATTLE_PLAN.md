# CYBERIA Hackathon — From 0 to Hero
## Complete 15-Hour Battle Plan (Team of 4)

---

## Mission (one phrase)
Build an AI-powered Threat Intelligence platform that turns scattered OSINT and SOC alerts into prioritized, MITRE-mapped, predictive intelligence — so analysts in banking, telecom, and healthcare can see the coordinated national-crisis attack as one story and predict where it strikes next.

## The 5-Stage Pipeline (matches the official architecture slide)
```
Data Sources → AI Engine → Detection & Analysis → Prediction → Dashboard & Action
   (Stage 01)   (Stage 02)      (Stage 03)         (Stage 04)      (Stage 05)
```

---

## The 4-PC Split

| PC | Owns | Stage(s) |
|---|---|---|
| **PC1** | Repo, FastAPI backend, SQLite DB, OSINT collectors, scenario injector, enrichment wrappers | 01 + infra spine |
| **PC2** | NLP/regex/LLM IOC extraction, classifier, dedup, confidence scoring, enrichment caller | 02 (the AI heart) |
| **PC3** | Correlation, MITRE mapping, risk scoring, anomaly detection, predictions, behavior analysis | 03 + 04 |
| **PC4** | Streamlit dashboard, BMC, technical report, pitch deck, demo script, KPIs | 05 + 45% of grade |

---

## How the 4 PCs Are Linked

Three layers stacked together:

1. **Code sync — GitHub.** One repo, branch per person, merge to `main` every 1–2 hours.
2. **Live editing — VS Code Live Share.** For pairing on tricky integrations.
3. **Running services — Tailscale (or local Wi-Fi).** PC1 hosts FastAPI + SQLite. PC2/3/4 call PC1's endpoints over Tailscale IP. Stable across any network.

**The contract:** PC1's API is the single source of truth. None of the 4 PCs block each other — they all read/write through PC1's API and can use mock data while waiting for upstream modules.

---

## Timeline at a Glance

| Phase | Hours | Duration | What Happens |
|---|---|---|---|
| 0. Setup & Sync | 0 – 1 | 1h | Tools installed, repo live, contracts locked |
| 1. Skeleton Running | 1 – 3 | 2h | Empty pipeline runs end-to-end with mock data |
| **Pause 1** | 3 – 3.5 | 30min | Meal |
| 2. Core Build | 3.5 – 7 | 3.5h | Every module does its real job |
| **Pause 2** | 7 – 9 | 2h | Sleep nap (non-negotiable) |
| 3. Advanced AI + Predictive | 9 – 12 | 3h | LLM, predictions, polish, BMC, report |
| **Pause 3** | 12 – 12.5 | 30min | Meal |
| 4. Integration & Demo Run | 12.5 – 14 | 1.5h | Feature freeze, end-to-end live test |
| 5. Rehearsal | 14 – 15 | 1h | 3× pitch rehearsals, final commits |

Total: 15h = 12h actual work + 2h sleep + 1h meals/breaks.

---

## PHASE 0 — Setup & Sync (Hour 0 – 1)

### All 4 PCs install in parallel (20 min)
- Python 3.11
- VS Code + extensions: Python, Pylance, GitLens, **Live Share**
- Git
- **Tailscale** (sign up with the same account, all 4 PCs join the same tailnet)
- Ollama (PC2 only — for the LLM)

### PC1 creates the repo (30 min)

```bash
mkdir cyberia-ti && cd cyberia-ti
git init
# create the folder structure (see Appendix A)
git remote add origin https://github.com/<team>/cyberia-ti.git
git add . && git commit -m "skeleton" && git push -u origin main
```

PC1 immediately writes `shared/schemas.py` with the Pydantic data contracts (Appendix B). **These are locked from this point on.**

### All other PCs clone (10 min)

```bash
git clone https://github.com/<team>/cyberia-ti.git
cd cyberia-ti
python -m venv venv
source venv/bin/activate     # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Team huddle (5 min)
- Confirm Tailscale IPs of each PC. Note them in the README.
- Confirm everyone can push/pull.
- Confirm everyone agrees with `shared/schemas.py`.
- Lock the git rhythm: **pull before any work, push after every working change**.

---

## PHASE 1 — Skeleton Running (Hour 1 – 3)

**Goal:** an empty pipeline that runs end-to-end with mock data. This proves the wiring before anyone builds real features.

### PC1
- Build `pc1_data/api.py` with FastAPI: every endpoint exists but returns mock data.
- Build `pc1_data/db.py` with SQLite: 4 tables (`raw_records`, `iocs`, `incidents`, `predictions`).
- One real collector working: **AlienVault OTX** (free API key, pull recent pulses).
- Run `uvicorn pc1_data.api:app --host 0.0.0.0 --port 8000`.
- Share Tailscale URL with team: `http://pc1-tailscale-ip:8000`.

### PC2
- `pc2_ai/ioc_extractor.py` — regex-only IOC extraction (IPs, MD5/SHA256 hashes, domains, URLs, CVEs).
- A small loop: pull from PC1 `/raw`, run regex, POST to PC1 `/iocs`.
- Validate end-to-end with at least one OTX pulse.

### PC3
- Download the MITRE ATT&CK STIX bundle once into `data/mitre/`.
- `pc3_analysis/correlator.py` — basic grouper: group IOCs by source + 1-hour window into one incident.
- Skeleton risk scorer that just counts IOCs.
- Push one fake incident to PC1 `/incidents` to test the full chain.

### PC4
- Streamlit shell `pc4_dashboard/app.py` with empty placeholders for each panel from the official slide 7.
- Connect to PC1 `/incidents` and `/predictions`, show empty tables.
- Run `streamlit run pc4_dashboard/app.py` and confirm it loads on Tailscale.
- Start `deliverables/BMC.md` outline.

### Phase 1 checkpoint (5 min team review)
Demo together: OTX pulse → regex IOC → fake incident → Streamlit shows it. Ugly is fine. **Wiring proven.**

---

## PAUSE 1 — Meal (30 min)
Eat away from screens. Quick informal chat: "what's the one feature each of us is most excited to add next?"

---

## PHASE 2 — Core Build (Hour 3.5 – 7)

**Goal:** every module does its real job with real data. By end of phase, the PoC is technically complete.

### PC1
- Add 4 more collectors: **URLhaus, ThreatFox, MalwareBazaar, MISP feed** (Appendix C).
- Build the **scenario injector**: hand-crafted JSON of fake phishing emails / lateral-movement logs / exfiltration alerts targeting banking, telecom, healthcare. This is what makes the demo *feel* like the national crisis.
- Wrap VirusTotal + Shodan APIs as helper functions for PC2.
- Add `/stats` endpoint (counts of records, IOCs, incidents per sector) for PC4.

### PC2
- Hand-label ~200 IOCs into 5 classes: `phishing / malware / lateral_movement / exfiltration / c2`. Train a scikit-learn classifier (logistic regression or random forest).
- Add spaCy NER for entity extraction (organizations, malware family names).
- Build deduplicator: `sentence-transformers` embeddings + cosine similarity > 0.85 → duplicate.
- Build per-source confidence scorer (weighted average of historical false-positive rate).
- Build enrichment caller that hits PC1's VT/Shodan wrappers, adds reputation/geo/related CVEs.
- Hook the full chain: raw → extract → dedup → classify → enrich → push.

### PC3
- **MITRE mapper** (rule-based for now):
  - phishing email IOC → T1566
  - suspicious admin login → T1078
  - large outbound transfer → T1041
  - known C2 domain → T1071
- **Risk scorer**: `severity × sector_criticality × IOC_confidence → 0–100`. Banking and healthcare get 1.5× weight.
- **Anomaly detector**: Isolation Forest on event volume per sector per hour.
- Pull enriched IOCs from PC1, group into incidents, score, MITRE-tag, push back.

### PC4
- Wire all dashboard panels with real data, matching the official slide 7 mockup:
  - Risk gauge (overall = max incident risk in last hour)
  - World map of attack origins (from IOC geolocation)
  - Top threats bar chart (Malware / Phishing / Exfiltration / Lateral)
  - Color-coded alerts list (Critical / High / Medium / Low)
  - Sector view: 3 columns for Banking / Telecom / Healthcare
- Auto-refresh every 5s.
- Start `deliverables/technical_report.md` with the architecture diagram screenshot + workflow.

### Phase 2 checkpoint
Real OSINT + scenario data flow end-to-end. Dashboard mirrors the official mockup. **The PoC is technically done.** Everything in Phase 3 is wow-factor.

---

## PAUSE 2 — Sleep Nap (2h, Hour 7 – 9)

**Non-negotiable.** Without 2h of sleep, hours 12–15 produce broken code and a bad pitch. Set alarms. Ideally all four sleep at the same time.

---

## PHASE 3 — Advanced AI + Predictive (Hour 9 – 12)

**Goal:** add the AI features that win the 40% Technical Solution + 20% Performance grade.

### PC1
- Final scenario injection: stage a **coordinated attack sequence** that unfolds during the demo:
  - Hour 9 of demo time → phishing wave hits banking
  - Hour 10 → lateral movement appears in telecom
  - Hour 11 → data exfiltration starts in healthcare
  The dashboard visibly lights up in real time during the pitch.
- Add export endpoints: `/export/json`, `/export/csv`, `/export/pdf` (PDF via `reportlab`).
- Add `/incidents/{id}/timeline` for the attack timeline view.

### PC2
- **LLM-based IOC extraction** using Ollama + Llama 3.2 3B (local, free, fast):
  - Prompt: *"Extract all IOCs from this report as JSON with fields: ips, domains, hashes, cves"*
  - Show jury a side-by-side: regex extracted N IOCs, LLM extracted N+M, with M being the ones regex missed.
- **LLM threat summarization** (slide 5 of your TI deck — "Résumé pour décideur"):
  - Prompt: *"Translate this technical incident into one paragraph that an executive can understand"*
  - Each critical alert in the dashboard gets a plain-language summary.
- Plug deduplication deeper into the pipeline.

### PC3
- **Time-series forecaster with Prophet**: predict attack volume per sector for next 7 days. Output: *"Phishing against banking forecast +40% in 7 days."*
- **CVE prioritization**: simple ranker by recency × severity × IOC frequency. Outputs the top 5 CVEs to patch first.
- **Behavior clustering**: KMeans on incident features → flag "coordinated campaign" patterns. This is your hook for the *"national crisis"* narrative.
- Push everything to PC1 `/predictions`.

### PC4
- Wire the **Predictions panel** in the dashboard.
- Wire **LLM summaries** into the alerts list (each critical alert gets a plain-language paragraph).
- Add a **MITRE ATT&CK heatmap** (techniques × sectors, color-coded by frequency) — biggest visual win for the jury.
- Lock `deliverables/BMC.md`:
  - Value proposition: reduce MTTA from hours to seconds
  - Customer segments: SOC providers, MSSPs, CISOs in banking/telecom/healthcare
  - Revenue: SaaS per analyst seat + per data source
  - Key partners: OSINT feed providers, MISP communities
- Lock `deliverables/technical_report.md` with all module descriptions and screenshots.

### Phase 3 checkpoint
LLM summaries visible. Predictions visible. MITRE heatmap visible. Demo will look impressive.

---

## PAUSE 3 — Meal (30 min, Hour 12 – 12.5)

Eat. Decide who presents which slide. Skim each other's BMC and technical report drafts for typos.

---

## PHASE 4 — Integration & Demo Run (Hour 12.5 – 14)

**Goal: feature freeze.** Only bug fixes from here.

- All 4 PCs sync on `main`. Resolve any merge conflicts now, not in Phase 5.
- PC1 runs the full pipeline live with the staged scenario data.
- PC4 runs the dashboard pointed at PC1.
- Team watches the dashboard for 10 min while PC1 triggers the scenario waves. Note bugs. Fix only.
- Lock the **demo script**: who clicks what, when, while which person speaks.

### Pre-compute the KPIs (these go in the pitch)
- IOCs extracted per minute
- False-positive reduction vs raw feeds (%)
- MTTA reduction estimate (seconds vs hours)
- # of MITRE techniques mapped
- # of incidents auto-correlated from N raw events
- Prediction accuracy on backtested scenario data

---

## PHASE 5 — Rehearsal (Hour 14 – 15)

### 3× full pitch rehearsals, timed at exactly 5 min

Pitch structure (matches official slide 12):

| Slot | Time | Content |
|---|---|---|
| 1. Concept | 1 min | The 3 problems (alert overload + fragmented TI + no prediction). One-line solution. |
| 2. Architecture | 1 min | The 5-stage pipeline diagram. |
| 3. AI | 1.5 min | LLM extraction, classification, MITRE mapping, predictions. |
| 4. Demo | 1.5 min | Live walkthrough of dashboard reacting to staged scenario. |

### Q&A division (10 min Q&A from jury)
- Cybersecurity questions → strongest cyber person
- AI/ML questions → PC2 person
- Architecture / infra questions → PC1 person
- Business / market / BMC questions → PC4 person

### Final actions
- `git tag v1.0` and push
- Backup the full project to a USB stick **and** Google Drive (redundancy)
- Record a 2-min screen capture of the working demo as a fallback if something dies during the live pitch

---

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| OSINT API down | Scenario injector keeps the demo alive |
| LLM slow on PC2 | Fall back to regex+ML, mention LLM as "also implemented" |
| Dashboard breaks during pitch | Pre-recorded demo video as backup |
| Internet dies | Tailscale → local fallback; MITRE data is pre-cached offline |
| One PC crashes | Code is on GitHub; another team member pulls and runs that module |

---

## Appendix A — Repo Structure

```
cyberia-ti/
├── README.md                       # Tailscale IPs, run commands
├── docker-compose.yml              # optional, for consistency
├── requirements.txt
├── .env.example                    # API keys placeholders
├── shared/
│   └── schemas.py                  # Pydantic data contracts (LOCKED phase 0)
├── pc1_data/
│   ├── api.py                      # FastAPI
│   ├── db.py                       # SQLite
│   ├── collectors/
│   │   ├── otx.py
│   │   ├── urlhaus.py
│   │   ├── threatfox.py
│   │   ├── malwarebazaar.py
│   │   └── scenario_injector.py
│   └── enrichment/
│       ├── virustotal.py
│       └── shodan.py
├── pc2_ai/
│   ├── ioc_extractor.py            # regex
│   ├── llm_extractor.py            # Ollama
│   ├── deduplicator.py             # sentence-transformers
│   ├── classifier.py               # scikit-learn
│   └── confidence_scorer.py
├── pc3_analysis/
│   ├── correlator.py
│   ├── mitre_mapper.py
│   ├── risk_scorer.py
│   ├── anomaly_detector.py
│   ├── predictor.py                # Prophet
│   └── behavior_analyzer.py        # KMeans
├── pc4_dashboard/
│   ├── app.py                      # Streamlit
│   └── pages/
├── data/
│   ├── raw/
│   ├── enriched/
│   ├── scenario/                   # the staged crisis data
│   └── mitre/                      # ATT&CK STIX bundle
└── deliverables/
    ├── BMC.md
    ├── technical_report.md
    ├── pitch_deck.pptx
    └── demo_script.md
```

---

## Appendix B — Data Contracts (`shared/schemas.py`)

```python
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class RawThreatRecord(BaseModel):
    id: str
    source: str                  # 'otx' | 'urlhaus' | 'threatfox' | 'malwarebazaar' | 'misp' | 'scenario'
    raw_text: str
    timestamp: datetime
    sector: Optional[str] = None # 'banking' | 'telecom' | 'healthcare' | None

class IOC(BaseModel):
    value: str
    type: str                    # 'ip' | 'hash_md5' | 'hash_sha256' | 'domain' | 'url' | 'cve'
    confidence: float            # 0.0 - 1.0
    source: str
    first_seen: datetime

class EnrichedIOC(IOC):
    threat_type: str             # 'phishing' | 'malware' | 'lateral_movement' | 'exfiltration' | 'c2'
    related_cves: List[str] = []
    geolocation: Optional[str] = None
    reputation: Optional[float] = None

class Incident(BaseModel):
    id: str
    iocs: List[EnrichedIOC]
    mitre_techniques: List[str]  # ['T1566', 'T1078', ...]
    targeted_sectors: List[str]
    risk_score: int              # 0-100
    severity: str                # 'critical' | 'high' | 'medium' | 'low'
    summary: str                 # LLM-generated executive summary
    detected_at: datetime

class Prediction(BaseModel):
    sector: str
    threat_type: str
    forecast_7d: float           # expected attacks in next 7 days
    trend: str                   # 'rising' | 'stable' | 'falling'
    confidence: float
```

---

## Appendix C — FastAPI Endpoints (PC1 owns)

| Method | Path | Purpose | Used by |
|---|---|---|---|
| POST | `/raw` | Push raw threat record | PC1 collectors |
| GET | `/raw` | List raw records | PC2 |
| POST | `/iocs` | Push extracted IOCs | PC2 |
| GET | `/iocs` | List IOCs | PC2 |
| POST | `/iocs/enriched` | Push enriched IOCs | PC2 |
| GET | `/iocs/enriched` | List enriched IOCs | PC3 |
| POST | `/incidents` | Push incidents | PC3 |
| GET | `/incidents` | List incidents | PC4 |
| POST | `/predictions` | Push predictions | PC3 |
| GET | `/predictions` | List predictions | PC4 |
| GET | `/stats` | Dashboard KPIs | PC4 |
| GET | `/export/{format}` | JSON/CSV/PDF export | Demo |

---

## Appendix D — OSINT Sources (free, no auth or easy auth)

| Source | URL | Auth | Best for |
|---|---|---|---|
| AlienVault OTX | `otx.alienvault.com/api/v1/pulses/subscribed` | Free API key | Curated threat reports |
| URLhaus | `urlhaus-api.abuse.ch/v1/urls/recent/` | None | Malicious URLs |
| ThreatFox | `threatfox-api.abuse.ch/api/v1/` | None | IOCs by malware family |
| MalwareBazaar | `mb-api.abuse.ch/api/v1/` | None | Malware samples & hashes |
| MISP CIRCL | `misppriv.circl.lu/feeds/` | None | Community-shared events |
| MITRE ATT&CK | `github.com/mitre/cti` (download once) | None | Technique mapping |

---

## Final Reminders

- **45% of grade is non-code** (Report 15% + BMC 15% + Pitch 15%). Don't underinvest.
- **Demo > complexity.** If a feature is half-broken at hour 12, cut it and polish what works.
- **Push to GitHub constantly.** A laptop crash should never cost more than 30 minutes.
- **Sleep at hour 7.** Anyone who skips this hurts the team.
- **Have a pre-recorded demo video.** Live demos die at the worst moment.
- **Talk in the room, not over messages.** You're physically together — use it.

---

**Let the hacking begin. 🚀**
