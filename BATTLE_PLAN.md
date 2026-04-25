# CYBERIA Hackathon — From 0 to Hero
## Complete 15-Hour Battle Plan (Team of 4) — **Banking Edition**

---

## Mission (one phrase)
Build an AI-powered Threat Intelligence platform for **Tier-2/Tier-3 banks in emerging markets** that turns scattered OSINT and SOC alerts into prioritized, MITRE-mapped, predictive intelligence — so a bank's CISO can see a coordinated attack as one story, predict where it strikes next, and map every incident to PCI-DSS / SWIFT CSP compliance obligations.

## Why Banking?
- **Underserved market**: Tier-1 megabanks have Recorded Future / Mandiant. Regional banks have nothing they can afford.
- **Regulatory urgency**: PCI-DSS, SWIFT CSP, ISO 27001, Basel III, BCT (Banque Centrale de Tunisie) circulars all demand monitoring.
- **High-value target**: average cost of a financial-sector breach = $5.9M (IBM 2024).
- **Demo-friendly**: rich public OSINT on banking APTs (Carbanak, FIN7, Lazarus, Silence).
- **Architecture stays sector-agnostic** — sector criticality is a config parameter, so the platform scales to telecom and healthcare with zero rewrites. **This is the answer to the jury's "can this work for other sectors?" question.**

## The 5-Stage Pipeline (matches the official architecture slide)
```
Data Sources → AI Engine → Detection & Analysis → Prediction → Dashboard & Action
   (Stage 01)   (Stage 02)      (Stage 03)         (Stage 04)      (Stage 05)
```

---

## The 4-PC Split

| PC | Owns | Stage(s) |
|---|---|---|
| **PC1** | Repo, FastAPI backend, SQLite DB, OSINT collectors, **bank-scenario injector**, enrichment wrappers | 01 + infra spine |
| **PC2** | NLP/regex/LLM IOC extraction, classifier, dedup, confidence scoring, enrichment caller | 02 (the AI heart) |
| **PC3** | Correlation, MITRE mapping (financial techniques), **compliance mapper**, risk scoring (banking-weighted), anomaly detection, predictions | 03 + 04 |
| **PC4** | Streamlit dashboard, **compliance panel**, BMC, technical report, pitch deck | 05 + 45% of grade |

---

## How the 4 PCs Are Linked

Three layers stacked together:

1. **Code sync — GitHub.** One repo, branch per person, merge to `main` every 1–2 hours.
2. **Live editing — VS Code Live Share.** For pairing on tricky integrations.
3. **Running services — Tailscale (or local Wi-Fi).** PC1 hosts FastAPI + SQLite. PC2/3/4 call PC1's endpoints over Tailscale IP.

**The contract:** PC1's API is the single source of truth. None of the 4 PCs block each other — they all read/write through PC1's API and can use mock data while waiting for upstream modules.

---

## Timeline at a Glance

| Phase | Hours | Duration | What Happens |
|---|---|---|---|
| 0. Setup & Sync | 0 → 1 | 1h | Tools installed, repo live, contracts locked |
| 1. Skeleton Running | 1 → 3 | 2h | Empty pipeline runs end-to-end with mock data |
| **Pause 1** | 3 → 3.5 | 30min | Meal |
| 2. Core Build | 3.5 → 7 | 3.5h | Every module does its real job |
| **Pause 2** | 7 → 9 | 2h | Sleep nap (non-negotiable) |
| 3. Advanced AI + Predictive | 9 → 12 | 3h | LLM, predictions, polish, BMC, report |
| **Pause 3** | 12 → 12.5 | 30min | Meal |
| 4. Integration & Demo Run | 12.5 → 14 | 1.5h | Feature freeze, end-to-end live test |
| 5. Rehearsal | 14 → 15 | 1h | 3× pitch rehearsals, final commits |

Total: 15h = 12h actual work + 2h sleep + 1h meals/breaks.

---

## PHASE 0 — Setup & Sync (Hour 0 → 1)

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

## PHASE 1 — Skeleton Running (Hour 1 → 3)

**Goal:** an empty pipeline that runs end-to-end with mock data. This proves the wiring before anyone builds real features.

### PC1
- Build `pc1_data/api.py` with FastAPI: every endpoint exists but returns mock data.
- Build `pc1_data/db.py` with SQLite: 4 tables (`raw_records`, `iocs`, `incidents`, `predictions`).
- One real collector working: **AlienVault OTX** (free API key, pull recent pulses, filter for `banking` / `finance` / `swift` tags).
- Run `uvicorn pc1_data.api:app --host 0.0.0.0 --port 8000`.
- Share Tailscale URL with team: `http://pc1-tailscale-ip:8000`.

### PC2
- `pc2_ai/ioc_extractor.py` — regex-only IOC extraction (IPs, MD5/SHA256 hashes, domains, URLs, CVEs).
- A small loop: pull from PC1 `/raw`, run regex, POST to PC1 `/iocs`.
- Validate end-to-end with at least one OTX pulse.

### PC3
- Download the MITRE ATT&CK STIX bundle once into `data/mitre/`.
- Pre-extract the **financial-relevant techniques** into a JSON lookup (T1566, T1078, T1041, T1190, T1539, T1071, T1486 — see Appendix E).
- `pc3_analysis/correlator.py` — basic grouper: group IOCs by source + 1-hour window into one incident.
- Skeleton risk scorer that just counts IOCs.
- Push one fake incident to PC1 `/incidents` to test the full chain.

### PC4
- Streamlit shell `pc4_dashboard/app.py` titled **"Banking Sector Threat Intelligence"** with empty placeholders for each panel from the official slide 7 mockup.
- Connect to PC1 `/incidents` and `/predictions`, show empty tables.
- Run `streamlit run pc4_dashboard/app.py` and confirm it loads on Tailscale.
- Start `deliverables/BMC.md` outline targeting **Tier-2/Tier-3 banks**.

### Phase 1 checkpoint (5 min team review)
Demo together: OTX pulse → regex IOC → fake incident → Streamlit shows it. Ugly is fine. **Wiring proven.**

---

## PAUSE 1 — Meal (30 min)
Eat away from screens. Quick informal chat: "what's the one feature each of us is most excited to add next?"

---

## PHASE 2 — Core Build (Hour 3.5 → 7)

**Goal:** every module does its real job with real data. By end of phase, the PoC is technically complete.

### PC1
- Add 4 more collectors: **URLhaus, ThreatFox, MalwareBazaar, MISP feed** (Appendix D). Filter ThreatFox for banking-relevant malware families: Emotet, TrickBot, Carbanak, Cobalt Strike, Dridex.
- Build the **bank scenario injector**: hand-crafted JSON staging an attack on a fake bank ("Banque Atlas" treasury department):
  - Phishing emails impersonating BCT (Banque Centrale de Tunisie) circulars
  - Lateral-movement logs: compromised treasury workstation → payment gateway server
  - Exfiltration alerts: customer account database leaving the network to known bad IPs
  - SWIFT-related anomalies: unusual MT103 message patterns
- Wrap VirusTotal + Shodan APIs as helper functions for PC2.
- Add `/stats` endpoint (counts of records, IOCs, incidents, **+ compliance breach counts**) for PC4.

### PC2
- Hand-label ~200 IOCs into 5 classes: `phishing / malware / lateral_movement / exfiltration / c2`. Bias the training set toward financial-attack samples.
- Add spaCy NER for entity extraction — flag known financial APTs: Carbanak, FIN7, Lazarus, Cobalt Group, Silence.
- Build deduplicator: `sentence-transformers` embeddings + cosine similarity > 0.85 → duplicate.
- Build per-source confidence scorer (weighted average of historical false-positive rate).
- Build enrichment caller that hits PC1's VT/Shodan wrappers, adds reputation/geo/related CVEs.
- Hook the full chain: raw → extract → dedup → classify → enrich → push.

### PC3
- **MITRE mapper** (rule-based, financial focus):
  - Phishing email IOC → **T1566** (Phishing)
  - Suspicious admin login → **T1078** (Valid Accounts)
  - Web session cookie theft → **T1539**
  - Public-facing app exploit → **T1190**
  - Large outbound transfer → **T1041** (Exfiltration over C2)
  - Known C2 domain → **T1071**
  - Ransomware behavior → **T1486** (Data Encrypted for Impact)
- **Risk scorer**: `severity × sector_criticality × IOC_confidence × compliance_weight → 0–100`.
  - Banking sector_criticality = 1.0 (primary focus)
  - Telecom = 0.5, healthcare = 0.5 (visible in code = scalable architecture)
  - **compliance_weight**: +20% if incident touches a PCI-DSS scope asset (cardholder data, payment systems)
- **Anomaly detector**: Isolation Forest on event volume per asset type per hour.
- **Compliance mapper** (NEW killer feature): tag each incident with the regulatory frameworks it would breach:
  - Cardholder data exposure → PCI-DSS Req. 3
  - Logging gap → PCI-DSS Req. 10
  - SWIFT message anomaly → SWIFT CSP CSCF 2.x
  - Customer data leak → GDPR Art. 33 (72h notification)
- Pull enriched IOCs from PC1, group into incidents, score, MITRE-tag, compliance-tag, push back.

### PC4
- Wire all dashboard panels with real data, matching the official slide 7 mockup but **bank-themed**:
  - Risk gauge labeled "Banking Sector Risk" (overall = max incident risk in last hour)
  - Map of attack origins targeting our fake bank
  - Top threats bar chart (Phishing / Malware / Exfiltration / Lateral / C2)
  - Color-coded alerts list (Critical / High / Medium / Low)
  - **Asset view**: 3 columns for Treasury / Payment Gateway / Customer DB (instead of generic sector view)
  - **Compliance panel** (NEW killer feature): live count of incidents currently breaching PCI-DSS, SWIFT CSP, GDPR
- Auto-refresh every 5s.
- Start `deliverables/technical_report.md` with the architecture diagram screenshot + workflow.

### Phase 2 checkpoint
Real OSINT + bank scenario data flow end-to-end. Dashboard shows the bank under attack. Compliance panel lights up. **The PoC is technically done.** Everything in Phase 3 is wow-factor.

---

## PAUSE 2 — Sleep Nap (2h, Hour 7 → 9)

**Non-negotiable.** Without 2h of sleep, hours 12–15 produce broken code and a bad pitch. Set alarms. Ideally all four sleep at the same time.

---

## PHASE 3 — Advanced AI + Predictive (Hour 9 → 12)

**Goal:** add the AI features that win the 40% Technical Solution + 20% Performance grade.

### PC1
- Final scenario injection: stage a **coordinated attack sequence** that unfolds during the live demo:
  - Demo minute 1 — spear-phishing email lands in Banque Atlas treasury (fake BCT impersonation)
  - Demo minute 2 — compromised account credentials used; lateral movement to payment server
  - Demo minute 3 — exfiltration to known Lazarus-attributed C2 IP; SWIFT MT103 anomaly fires
  The dashboard visibly lights up in real time, alerts cascade, compliance breaches appear live.
- Add export endpoints: `/export/json`, `/export/csv`, `/export/pdf` (PDF via `reportlab`) — **format the PDF as a SOC incident report a CISO would actually file**.
- Add `/incidents/{id}/timeline` for the attack timeline view.

### PC2
- **LLM-based IOC extraction** using Ollama + Llama 3.2 3B (local, free, fast):
  - Prompt: *"Extract all IOCs from this banking-sector threat report as JSON with fields: ips, domains, hashes, cves, financial_keywords"*
  - Show jury a side-by-side: regex extracted N IOCs, LLM extracted N+M, with M being the ones regex missed (e.g., obfuscated SWIFT codes, banking-specific terms).
- **LLM threat summarization** — the killer demo feature (slide 5 of your TI deck — *"Résumé pour décideur"*):
  - Prompt: *"Translate this technical incident into one paragraph that a bank CISO can present to the board. Include compliance impact."*
  - Each critical alert in the dashboard gets a plain-language CISO-ready summary.
- Plug deduplication deeper into the pipeline.

### PC3
- **Time-series forecaster with Prophet**: predict attack volume against banking targets for next 7 days. Output: *"Phishing campaigns against treasury operations forecast +40% in 7 days."*
- **CVE prioritization**: rank CVEs by recency × severity × IOC frequency × **banking-tech-stack relevance** (boost CVEs affecting Oracle DB, Temenos, Finastra, common SWIFT messaging stacks).
- **Behavior clustering**: KMeans on incident features → flag *"this looks like a coordinated APT campaign matching FIN7 patterns"*. Match against known financial APT TTPs.
- Push everything to PC1 `/predictions`.

### PC4
- Wire the **Predictions panel**: "Forecast: +40% phishing on banking sector in 7 days" with trend graph.
- Wire **LLM CISO summaries** into the alerts list.
- Add a **MITRE ATT&CK heatmap** (financial techniques × bank assets, color-coded by frequency) — biggest visual win.
- Polish the **Compliance Panel**: each breach shows the regulation, the article, and the notification deadline (e.g., "GDPR Art. 33 — must notify regulator within 72h").
- Lock `deliverables/BMC.md`:
  - **Customer segments**: CISOs of Tier-2/Tier-3 banks in MENA, Africa, Eastern Europe; MSSPs serving regional banks
  - **Value proposition**: *"Enterprise-grade threat intelligence for banks that can't afford Recorded Future. Reduce MTTA from hours to seconds and automate compliance evidence."*
  - **Revenue model**: SaaS — €X/month per analyst seat + per integrated data source; tier based on bank size (assets under management)
  - **Key partners**: OSINT feed providers (Abuse.ch, AlienVault), MISP communities, regional cybersecurity consultancies, central bank cybersecurity programs
  - **Cost structure**: cloud hosting + LLM inference + dev team + sales
  - **Channels**: direct to bank CISOs via cybersecurity conferences (GITEX, Cyber Africa Forum); via local MSSPs
- Lock `deliverables/technical_report.md` with all module descriptions, screenshots, **and a "Sector Scalability" section explaining how the platform extends to healthcare and telecom by changing config**.

### Phase 3 checkpoint
LLM CISO summaries visible. Predictions visible. MITRE heatmap visible. Compliance breaches with deadlines visible. Demo will look enterprise-grade.

---

## PAUSE 3 — Meal (30 min, Hour 12 → 12.5)

Eat. Decide who presents which slide. Skim each other's BMC and technical report drafts for typos.

---

## PHASE 4 — Integration & Demo Run (Hour 12.5 → 14)

**Goal: feature freeze.** Only bug fixes from here.

- All 4 PCs sync on `main`. Resolve any merge conflicts now, not in Phase 5.
- PC1 runs the full pipeline live with the staged bank-attack scenario.
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
- **# of compliance breaches auto-flagged** (banking-specific KPI)
- **Cost per incident detected** vs traditional SOC manual analysis (BMC ammunition)

---

## PHASE 5 — Rehearsal (Hour 14 → 15)

### 3× full pitch rehearsals, timed at exactly 5 min

Pitch structure (matches official slide 12):

| Slot | Time | Content |
|---|---|---|
| 1. **Concept** | 1 min | Tier-2 banks drown in alerts, can't afford Mandiant, regulators are getting stricter. One-line solution. |
| 2. **Architecture** | 1 min | The 5-stage pipeline diagram. |
| 3. **AI** | 1.5 min | LLM extraction with banking context, classification, MITRE financial techniques, CVE prioritization for banking stack, predictions. |
| 4. **Demo** | 1.5 min | Live walkthrough: attack on Banque Atlas → dashboard reacts → compliance breaches flagged → CISO summary auto-generated. |

### Pitch hook (opening line)
> *"When a regional bank gets hit by the same APT campaign that took down three banks last month, our platform sees the pattern in 30 seconds — not 3 days. And it tells the CISO exactly which PCI-DSS articles were just breached."*

### Q&A division (10 min Q&A from jury)
- Cybersecurity questions → strongest cyber person
- AI/ML questions → PC2 person
- Architecture / infra questions → PC1 person
- Business / market / BMC questions → PC4 person
- **"Can this work for healthcare/telecom?"** → anyone: *"Yes — sector criticality and compliance frameworks are configurable. We started with banking because regional banks face regulatory urgency without affordable tools. The same architecture serves healthcare (HIPAA, GDPR-health) and telecom (NIS2) by swapping the compliance module."*

### Final actions
- `git tag v1.0` and push
- Backup the full project to a USB stick **and** Google Drive
- Record a 2-min screen capture of the working demo as a fallback if something dies during the live pitch

---

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| OSINT API down | Bank scenario injector keeps the demo alive |
| LLM slow on PC2 | Fall back to regex+ML, mention LLM as "also implemented" |
| Dashboard breaks during pitch | Pre-recorded demo video as backup |
| Internet dies | Tailscale → local fallback; MITRE data is pre-cached offline |
| One PC crashes | Code is on GitHub; another team member pulls and runs that module |
| Jury asks about a regulation we don't know | Acknowledge, then redirect: *"compliance frameworks are pluggable — adding one is a config change"* |

---

## Appendix A — Repo Structure

```
cyberia-ti/
├── README.md                       # Tailscale IPs, run commands
├── CLAUDE.md                       # Claude Code shared context
├── BATTLE_PLAN.md                  # this file
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
│   │   └── bank_scenario_injector.py
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
│   ├── mitre_mapper.py             # financial techniques focus
│   ├── compliance_mapper.py        # PCI-DSS / SWIFT CSP / GDPR
│   ├── risk_scorer.py
│   ├── anomaly_detector.py
│   ├── predictor.py                # Prophet
│   └── behavior_analyzer.py        # KMeans, financial APT patterns
├── pc4_dashboard/
│   ├── app.py                      # Streamlit "Banking Sector TI"
│   └── pages/
├── data/
│   ├── raw/
│   ├── enriched/
│   ├── scenario/                   # the staged Banque Atlas attack
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
    sector: Optional[str] = None # 'banking' (primary) | 'telecom' | 'healthcare'
    asset_type: Optional[str] = None  # 'treasury' | 'payment_gateway' | 'customer_db' | 'swift_terminal'

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
    apt_attribution: Optional[str] = None  # 'fin7' | 'lazarus' | 'carbanak' | 'silence' | None

class Incident(BaseModel):
    id: str
    iocs: List[EnrichedIOC]
    mitre_techniques: List[str]            # ['T1566', 'T1078', ...]
    targeted_sectors: List[str]
    targeted_assets: List[str]             # ['treasury', 'payment_gateway']
    risk_score: int                        # 0-100
    severity: str                          # 'critical' | 'high' | 'medium' | 'low'
    summary: str                           # LLM-generated CISO-ready summary
    compliance_breaches: List[str] = []    # ['PCI-DSS Req.10', 'SWIFT CSP 2.1', 'GDPR Art.33']
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
| GET | `/stats` | Dashboard KPIs + compliance counts | PC4 |
| GET | `/export/{format}` | JSON/CSV/PDF incident report export | Demo |

---

## Appendix D — OSINT Sources (free, no auth or easy auth)

| Source | URL | Auth | Best for |
|---|---|---|---|
| AlienVault OTX | `otx.alienvault.com/api/v1/pulses/subscribed` | Free API key | Filter by tags: `banking`, `finance`, `swift`, `apt` |
| URLhaus | `urlhaus-api.abuse.ch/v1/urls/recent/` | None | Malicious URLs (banking phishing) |
| ThreatFox | `threatfox-api.abuse.ch/api/v1/` | None | IOCs by malware family — filter for Emotet, TrickBot, Carbanak, Cobalt Strike, Dridex |
| MalwareBazaar | `mb-api.abuse.ch/api/v1/` | None | Malware samples & hashes — banking trojans |
| MISP CIRCL | `misppriv.circl.lu/feeds/` | None | Community-shared events |
| MITRE ATT&CK | `github.com/mitre/cti` (download once) | None | Technique mapping |

---

## Appendix E — MITRE Techniques Most Relevant to Banking

| Technique | Name | Why it matters for banks |
|---|---|---|
| **T1566** | Phishing | #1 entry vector for bank breaches |
| **T1078** | Valid Accounts | Compromised employee credentials → SWIFT terminals |
| **T1190** | Exploit Public-Facing App | Online banking portals, web app vulnerabilities |
| **T1539** | Steal Web Session Cookie | Banking session hijacking |
| **T1041** | Exfiltration over C2 | Customer data theft |
| **T1071** | Application Layer Protocol | C2 over HTTPS to evade detection |
| **T1486** | Data Encrypted for Impact | Ransomware (Conti, LockBit hit banks regularly) |
| **T1055** | Process Injection | Banking trojans (Emotet, TrickBot) |
| **T1098** | Account Manipulation | Privilege escalation toward payment systems |
| **T1567** | Exfiltration to Cloud Storage | Modern data theft pattern |

---

## Appendix F — Compliance Frameworks for the Compliance Panel

| Framework | Trigger | Notification Deadline |
|---|---|---|
| **PCI-DSS Req. 3** | Cardholder data exposure | Per acquirer contract |
| **PCI-DSS Req. 10** | Logging/monitoring gap | Audit cycle |
| **PCI-DSS Req. 11** | Failure to detect intrusion | Audit cycle |
| **SWIFT CSP CSCF 2.x** | SWIFT message anomaly, unauthorized access | 24h to SWIFT |
| **GDPR Art. 33** | Personal data breach | 72h to regulator |
| **Basel III ORR** | Operational risk event | Per Basel local implementation |
| **BCT Circular** (Tunisia) | Cyber-incident affecting bank operations | Per local circular |

---

## Final Reminders

- **45% of grade is non-code** (Report 15% + BMC 15% + Pitch 15%). Don't underinvest.
- **Banking focus = competitive moat.** Don't dilute the pitch by listing 3 sectors equally.
- **Architecture stays sector-agnostic.** When jury asks about scalability, the answer is ready.
- **Demo > complexity.** If a feature is half-broken at hour 12, cut it and polish what works.
- **Push to GitHub constantly.** A laptop crash should never cost more than 30 minutes.
- **Sleep at hour 7.** Anyone who skips this hurts the team.
- **Have a pre-recorded demo video.** Live demos die at the worst moment.
- **The compliance panel is your secret weapon.** No other team will think of this.

---

**Let the hacking begin. 🚀**
