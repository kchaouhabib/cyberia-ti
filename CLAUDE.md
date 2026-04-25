# CLAUDE.md — CYBERIA Hackathon Project Context

You are assisting a 4-person team building an **AI-Powered Threat Intelligence Platform** for the CYBERIA 2026 hackathon at ESPRIT (24h event, our build window is 15h).

## Mission
Turn scattered OSINT and SOC alerts into prioritized, MITRE-mapped, predictive intelligence so analysts in banking, telecom, and healthcare can see the coordinated national-crisis attack as one story and predict where it strikes next.

## The 5-Stage Pipeline
Data Sources → AI Engine → Detection & Analysis → Prediction → Dashboard & Action

## The 4-PC Split
- **PC1** — FastAPI backend, SQLite DB, OSINT collectors, scenario injector, enrichment wrappers (Stage 01 + spine)
- **PC2** — Regex/NLP/LLM IOC extraction, classifier, deduplication, confidence scoring (Stage 02)
- **PC3** — Correlation, MITRE mapping, risk scoring, anomaly detection, predictions (Stages 03 + 04)
- **PC4** — Streamlit dashboard, BMC, technical report, pitch deck (Stage 05 + non-code deliverables)

## How the PCs Communicate
- PC1 hosts FastAPI on port 8000 — single source of truth
- PC2/PC3/PC4 call PC1's API over ZeroTier: `http://<pc1-zerotier-ip>:8000`
- All data contracts are Pydantic models in `shared/schemas.py` — **never modify these without team approval**
- Code synced via GitHub; pull before work, push after every working change

## Stack (locked, do not propose alternatives)
- Python 3.11
- FastAPI + SQLite (PC1)
- scikit-learn, spaCy, sentence-transformers, Ollama+Llama 3.2 3B (PC2)
- Prophet, MITRE ATT&CK STIX bundle (PC3)
- Streamlit (PC4)

## Ground Rules
- Working demo > complex features. Always.
- Solutions must be original code. External libraries fine, AI-generated code must be reviewed and adapted.
- No malicious code or harmful payloads.
- Modular, scalable architecture. Every module readable and testable in isolation.
- When in doubt, refer to `BATTLE_PLAN.md` in the repo for the phase timeline.

## Scenario Context
Simulated national crisis: coordinated attacks on banking, telecom, healthcare via phishing, lateral movement, and data exfiltration. Our scenario injector stages waves of fake events during the demo to make the dashboard visibly react.

## Quality Bar
- Every function has a docstring
- Every API endpoint validates input via Pydantic
- No hardcoded paths; use relative paths from repo root
- Commit messages: `[PC<n>] <verb> <what>` — e.g. `[PC2] add LLM IOC extractor`
