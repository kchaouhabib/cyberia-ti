# cyberia-ti

CYBERIA 2026 Hackathon · ESPRIT · 25-26 April 2026
AI-Powered Threat Intelligence Platform.

## NetBird mesh — team IPs

All 4 PCs joined via NetBird (replaces the earlier ZeroTier setup).

| PC  | NetBird IP        | Role |
|-----|-------------------|------|
| PC1 | `100.67.61.250`   | Data + API + DB · **API at `http://100.67.61.250:8000`** |
| PC2 | `100.67.158.179`  | AI engine (IOC extraction, classifier) |
| PC3 | `100.67.161.83`   | Correlation + prediction |
| PC4 | `100.67.152.56`   | Dashboard + deliverables · Streamlit at `http://100.67.152.56:8501` |

**API surface:** `http://100.67.61.250:8000` · Swagger UI: `/docs`

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
