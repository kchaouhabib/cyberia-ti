# CLAUDE.md — CYBERIA Hackathon Project Context

You are assisting a 4-person team building an **AI-Powered Threat Intelligence Platform** for the CYBERIA 2026 hackathon at ESPRIT (24h event, our build window is 15h).

## Mission
Turn scattered OSINT and SOC alerts into prioritized, MITRE-mapped, predictive intelligence so a **bank CISO** can see a coordinated attack as one story, predict where it strikes next, and map every incident to compliance obligations (PCI-DSS, SWIFT CSP, GDPR, BCT).

## Sector Focus: Banking (Tier-2 / Tier-3 in Emerging Markets)
We deliberately picked banking as our anchor sector for the following strategic reasons. **Reinforce this focus when suggesting code, examples, or copy:**

- Tier-2/Tier-3 banks are underserved — Recorded Future / Mandiant are too expensive
- Strong regulatory drivers (PCI-DSS, SWIFT CSP, ISO 27001, Basel III, BCT circulars in Tunisia)
- Rich public OSINT on financial APTs (Carbanak, FIN7, Lazarus, Silence, Cobalt Group)
- Easy to argue ROI: $5.9M average breach cost (IBM 2024)

**However: the architecture stays sector-agnostic.** Sector criticality and compliance frameworks are configurable. Healthcare and telecom support is a config change away. This is the answer to the jury's "can this work for other sectors?" question.

## The 5-Stage Pipeline
Data Sources → AI Engine → Detection & Analysis → Prediction → Dashboard & Action

## The 4-PC Split
- **PC1** — FastAPI backend, SQLite DB, OSINT collectors, **bank scenario injector**, enrichment wrappers (Stage 01 + spine)
- **PC2** — Regex/NLP/LLM IOC extraction, classifier, deduplication, confidence scoring (Stage 02)
- **PC3** — Correlation, MITRE mapping (financial techniques), **compliance mapper**, risk scoring (banking-weighted), anomaly detection, predictions (Stages 03 + 04)
- **PC4** — Streamlit dashboard, **compliance panel**, BMC, technical report, pitch deck (Stage 05 + non-code deliverables)

## How the PCs Communicate
- PC1 hosts FastAPI on port 8000 — single source of truth
- PC2/PC3/PC4 call PC1's API over Tailscale: `http://<pc1-tailscale-ip>:8000`
- All data contracts are Pydantic models in `shared/schemas.py` — **never modify these without team approval**
- Code synced via GitHub; pull before work, push after every working change

## Stack (locked, do not propose alternatives)
- Python 3.11
- FastAPI + SQLite (PC1)
- scikit-learn, spaCy, sentence-transformers, Ollama + Llama 3.2 3B (PC2)
- Prophet, MITRE ATT&CK STIX bundle (PC3)
- Streamlit (PC4)

## Banking-Specific Code Defaults
When relevant, default to banking framing in:
- **Scenario data**: fake bank "Banque Atlas", treasury department, payment gateway, customer DB, SWIFT terminal
- **Threat actors to recognize / flag**: Carbanak, FIN7, Lazarus, Silence, Cobalt Group, Emotet, TrickBot, Dridex
- **MITRE techniques to prioritize**: T1566 (Phishing), T1078 (Valid Accounts), T1190 (Exploit Public-Facing App), T1539 (Web Session Cookie), T1041 (Exfil over C2), T1071 (App Layer C2), T1486 (Ransomware)
- **Compliance frameworks to map**: PCI-DSS Req. 3/10/11, SWIFT CSP CSCF 2.x, GDPR Art. 33, Basel III ORR, BCT circulars
- **CVE prioritization**: boost CVEs affecting Oracle DB, Temenos, Finastra, common SWIFT messaging stacks

## Ground Rules
- Working demo > complex features. Always.
- Solutions must be original code. External libraries fine, AI-generated code must be reviewed and adapted.
- No malicious code or harmful payloads.
- Modular, scalable architecture. Every module readable and testable in isolation.
- When in doubt, refer to `BATTLE_PLAN.md` in the repo for the phase timeline.

## Quality Bar
- Every function has a docstring
- Every API endpoint validates input via Pydantic
- No hardcoded paths; use relative paths from repo root
- Commit messages: `[PC<n>] <verb> <what>` — e.g. `[PC2] add LLM IOC extractor`

## Pitch Hook (memorize this opening line)
> *"When a regional bank gets hit by the same APT campaign that took down three banks last month, our platform sees the pattern in 30 seconds — not 3 days. And it tells the CISO exactly which PCI-DSS articles were just breached."*
