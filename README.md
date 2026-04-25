# cyberia-ti

CYBERIA 2026 Hackathon · ESPRIT · 25-26 April 2026
AI-Powered Threat Intelligence Platform.

## ZeroTier IPs

Fill these in once everyone joins the same ZeroTier network:

| PC  | Owner | ZeroTier IP | Role |
|-----|-------|-------------|------|
| PC1 |       | TBD         | Data + API + DB |
| PC2 |       | TBD         | AI engine (IOC extraction, classifier) |
| PC3 |       | TBD         | Correlation + prediction |
| PC4 |       | TBD         | Dashboard + deliverables |

## Quick start

```bash
git clone https://github.com/kchaouhabib/cyberia-ti.git
cd cyberia-ti
python -m venv venv
source venv/Scripts/activate    # on Windows Git Bash
# source venv/bin/activate      # on Linux/macOS
pip install -r requirements.txt
cp .env.example .env             # then fill in keys
```

## Run

**PC1 — API:**
```bash
uvicorn pc1_data.api:app --host 0.0.0.0 --port 8000 --reload
```
Browse `http://localhost:8000/docs` for the OpenAPI UI.

**PC4 — Dashboard:**
```bash
streamlit run pc4_dashboard/app.py
```

## Project context

See [CLAUDE.md](./CLAUDE.md) for the AI-assistant context the team shares.
See `BATTLE_PLAN.md` (in the team Obsidian vault) for the 15-hour phase timeline.

## Layout

```
cyberia-ti/
├── shared/schemas.py            # Pydantic data contracts (LOCKED)
├── pc1_data/                    # PC1 — API, DB, collectors
├── pc2_ai/                      # PC2 — extraction, classification, dedup
├── pc3_analysis/                # PC3 — correlation, MITRE, prediction
├── pc4_dashboard/               # PC4 — Streamlit dashboard
├── data/                        # raw, enriched, scenario, mitre
├── deliverables/                # BMC, technical report, pitch
└── tests/
```

## Commit convention

`[PC<n>] <verb> <what>` — e.g. `[PC2] add LLM IOC extractor`
