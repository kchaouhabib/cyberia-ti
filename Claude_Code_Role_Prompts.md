# Claude Code Role Prompts — Banking Edition

Each person opens Claude Code in the repo and pastes their prompt as the **very first message** of the session. Both `CLAUDE.md` and `BATTLE_PLAN.md` must already be in the repo root before doing this — Claude Code reads them automatically.

The pattern `[PASTE CURRENT TASK]` means: at the start of each phase, copy your phase tasks from `BATTLE_PLAN.md` into your Claude Code session.

---

## PC1 — Backend Spine

```
I'm PC1 on the CYBERIA hackathon team. Read CLAUDE.md and BATTLE_PLAN.md first.

My role: I own the backend spine — FastAPI server, SQLite DB, OSINT collectors 
(OTX, URLhaus, ThreatFox, MalwareBazaar, MISP), the bank scenario injector that 
stages the demo's coordinated attack on "Banque Atlas" (treasury → payment gateway 
→ customer DB exfiltration with SWIFT MT103 anomaly), and enrichment wrappers 
(VirusTotal, Shodan).

I work in pc1_data/. I do NOT touch pc2_ai/, pc3_analysis/, or pc4_dashboard/ — 
that's other teammates' territory. If a teammate needs an API change, I expose it; 
they don't reach into my code.

Banking focus reminders:
- OSINT collectors should filter for banking/finance/swift tags where possible
- Scenario injector should impersonate BCT (Banque Centrale de Tunisie) circulars 
  in phishing emails
- Scenario should target realistic bank assets: treasury, payment gateway, customer DB, SWIFT terminal
- PDF export should be formatted as a SOC incident report a CISO would actually file

For this session, I need to: [PASTE CURRENT TASK FROM BATTLE_PLAN.md]

Default behavior:
- Always check shared/schemas.py before suggesting data shapes — those contracts are locked.
- Suggest minimal code that works, not enterprise patterns.
- When you write a collector, also write a 3-line test that proves it returns valid RawThreatRecord objects.
- Remind me to commit and push after every working change.
```

---

## PC2 — AI Engine

```
I'm PC2 on the CYBERIA hackathon team. Read CLAUDE.md and BATTLE_PLAN.md first.

My role: I own the AI Engine (Stage 02) — the heart of the project. Regex IOC 
extraction, spaCy NER, sentence-transformers deduplication, scikit-learn classifier 
(phishing/malware/lateral_movement/exfiltration/c2), per-source confidence scoring, 
and LLM-based extraction + executive summaries via Ollama (Llama 3.2 3B).

I work in pc2_ai/. I read raw records from PC1's GET /raw and POST enriched IOCs 
to PC1's /iocs/enriched. I never write directly to the SQLite DB.

Banking focus reminders:
- Bias the classifier training set toward financial-attack samples
- spaCy NER should flag financial APTs: Carbanak, FIN7, Lazarus, Cobalt Group, Silence
- LLM extraction prompt should mention "banking-sector threat report" and ask for 
  financial_keywords as an extra field
- LLM summarization is the killer demo feature — prompt it to write CISO-ready 
  paragraphs that include compliance impact

For this session, I need to: [PASTE CURRENT TASK FROM BATTLE_PLAN.md]

Default behavior:
- Default to scikit-learn over deep learning unless I say otherwise — we have 12h.
- For the LLM, prompt for strict JSON output and parse defensively.
- When you train a model, save it to data/models/ and load lazily.
- Side-by-side comparison (regex vs LLM extraction) is a demo highlight — keep it visible in code.
- Remind me to commit and push after every working change.
```

---

## PC3 — Detection, Analysis & Prediction

```
I'm PC3 on the CYBERIA hackathon team. Read CLAUDE.md and BATTLE_PLAN.md first.

My role: I own Detection/Analysis (Stage 03) and Prediction (Stage 04). Correlation 
engine that groups IOCs into incidents, MITRE ATT&CK technique mapping (financial 
focus), compliance mapper (PCI-DSS / SWIFT CSP / GDPR / BCT), risk scoring 
(banking-weighted), anomaly detection (Isolation Forest), time-series forecasting 
with Prophet, behavior clustering (KMeans), and CVE prioritization for the banking 
tech stack.

I work in pc3_analysis/. I read enriched IOCs from PC1's GET /iocs/enriched and POST 
incidents and predictions back to PC1.

Banking focus reminders:
- Banking sector_criticality = 1.0 (primary). Telecom = 0.5, Healthcare = 0.5 
  (visible = scalable architecture)
- Compliance_weight: +20% if incident touches PCI-DSS scope assets
- MITRE techniques to prioritize: T1566, T1078, T1190, T1539, T1041, T1071, T1486
- Compliance breaches to detect: PCI-DSS Req. 3/10/11, SWIFT CSP 2.x, GDPR Art. 33, 
  Basel III ORR, BCT circulars
- CVE prioritization should boost CVEs affecting Oracle DB, Temenos, Finastra, 
  SWIFT messaging stacks
- Behavior clustering should match against known financial APT TTPs

For this session, I need to: [PASTE CURRENT TASK FROM BATTLE_PLAN.md]

Default behavior:
- Compliance mapping is the killer feature — every incident should be tagged with 
  every regulation it would breach.
- MITRE technique mapping starts rule-based. ML upgrade only if there's time.
- Prophet needs ~30 data points to forecast — generate synthetic history from the 
  scenario injector if real data is thin.
- Remind me to commit and push after every working change.
```

---

## PC4 — Dashboard & Deliverables

```
I'm PC4 on the CYBERIA hackathon team. Read CLAUDE.md and BATTLE_PLAN.md first.

My role: I own the Streamlit dashboard (Stage 05) AND all non-code deliverables — 
Business Model Canvas, technical report, pitch deck, demo script, KPIs. 
This is 45% of the total grade combined, so non-code work is as important as the dashboard.

I work in pc4_dashboard/ and deliverables/. I read incidents and predictions from 
PC1's GET endpoints. I never modify anyone else's code — if a panel needs different 
data, I ask PC1 to add it to the API.

Banking focus reminders:
- Dashboard title: "Banking Sector Threat Intelligence"
- Asset view (3 columns): Treasury / Payment Gateway / Customer DB (not generic sectors)
- COMPLIANCE PANEL is our killer feature — show live counts of incidents breaching 
  PCI-DSS, SWIFT CSP, GDPR, with notification deadlines visible
- BMC anchored on Tier-2/Tier-3 banks in MENA, Africa, Eastern Europe
- Value prop: "Enterprise-grade TI for banks that can't afford Recorded Future. 
  Reduce MTTA from hours to seconds and automate compliance evidence."
- Technical report needs a "Sector Scalability" section explaining the platform 
  extends to healthcare/telecom by changing config

For this session, I need to: [PASTE CURRENT TASK FROM BATTLE_PLAN.md]

Default behavior:
- Match the visual layout of the official slide 7 mockup (risk gauge, world map, 
  threat trends, top threats bars, color-coded alerts) — but bank-themed.
- Auto-refresh dashboard every 5s.
- Pitch structure: Concept (1m) → Architecture (1m) → AI (1.5m) → Demo (1.5m).
- Pitch hook: "When a regional bank gets hit by the same APT campaign that took 
  down three banks last month, our platform sees the pattern in 30 seconds — not 
  3 days. And it tells the CISO exactly which PCI-DSS articles were just breached."
- Pre-record a backup demo video before final rehearsal.
- Remind me to commit and push after every working change.
```

---

## How to Use During the Hackathon

1. **Hour 0**: PC1 commits `CLAUDE.md` and `BATTLE_PLAN.md` to the repo root and pushes. Everyone pulls.
2. **Hour 0**: Each person opens Claude Code in their cloned repo and pastes their role prompt with the current Phase 1 tasks.
3. **Each phase transition**: Replace `[PASTE CURRENT TASK]` with the new phase's task list from `BATTLE_PLAN.md`.
4. **If scope shifts**: Edit `CLAUDE.md`, commit, push. All 4 Claude Code sessions stay aligned after the next pull.

Keep each Claude Code session running per PC — don't restart between phases. Context compounds.
