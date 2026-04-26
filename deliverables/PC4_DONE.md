# PC4 — Work Done (All Phases)
**CYBERIA 2026 · Banking Sector Threat Intelligence**

---

## Phase 1 — Skeleton

- Streamlit shell `pc4_dashboard/app.py` with all slide-7 panels as placeholders
- Connected to PC1 `/incidents` and `/predictions`
- `deliverables/BMC.md` outline started (Tier-2/3 banking focus)

---

## Phase 2 — Core Dashboard

- **Switched from Streamlit → React + Vite** for animation and UX quality
- Built 5-page SPA (no router, page-state navigation):

| Page | Content |
|---|---|
| Overview | KPI bar, risk gauge (RadialBarChart), top threats bar, recent alerts |
| Live Alerts | Severity filter, expandable rows with MITRE badges, compliance + APT detail |
| Compliance Monitor | 5 framework cards + breach table with notification deadlines |
| Asset Intelligence | 4 bank asset cards + attack origins + APT groups |
| Threat Predictions | Forecast cards + sector BarChart + AreaChart for rising threats |

- **Tech stack**: React 18, Vite 8, Framer Motion, Tailwind CSS v4, Recharts, Lucide React
- Dark SOC theme: `#050d1a` background, `#0a1628` cards, `#00d4ff` cyan accent
- Auto-refresh every 5 seconds via `useEffect + setInterval`
- Crash-proof API layer: `AbortSignal.timeout(4000)`, fallback to empty state
- `deliverables/technical_report.md` Phase 2 draft — architecture diagram + all pipeline modules

---

## Phase 3 — Advanced Features

### Dashboard additions
- **MITRE ATT&CK Heatmap** (7 financial techniques × 5 IOC threat types, orange→red frequency gradient) — biggest visual differentiator
- **AI CISO Summary badge** (`✦ AI CISO SUMMARY` in cyan) — fires when PC2 LLM summary is present
- **Compliance Panel polished** — each breach row shows regulation + article + notification deadline + urgency color
- **Predictions Panel** — forecast value, trend icon (TrendingUp/Down/Minus), confidence bar, sector stacked BarChart, AreaChart for rising threats

### Data fixes (adapting to real API output)
- Asset inference fallback: when `targeted_assets: []` (PC3 gap), infer from IOC `threat_type` + MITRE techniques
- GEO_MAP extended to handle ISO-2 country codes (`RU`, `CN`, `US`...) — attack origins now populate
- APT prediction labels: `"apt:fin7"` → `"APT: fin7"` display fix
- AI badge guard: only fires on real LLM summaries, not count strings

### Deliverables — locked
- `deliverables/BMC.md` — fully locked:
  - Revenue tiers: €299 / €799 / €1,999 per month by bank AUM
  - Key partners: Abuse.ch, AlienVault OTX, MISP, regional consultancies, BCT/Bank Al-Maghrib
  - KPIs table with addressable market + Y1 revenue target
- `deliverables/technical_report.md` — fully locked:
  - Stage 05 updated to React stack with full component documentation
  - Sector Scalability section (banking → healthcare/telecom via config change)
  - Demo scenario walkthrough table (minute by minute)

---

## Dashboard Access

| URL | Who |
|---|---|
| `http://localhost:5173` | PC4 local |
| `http://100.67.152.56:5173` | Teammates via NetBird |

Auto-refreshes every 5s from `http://100.67.61.250:8000` (PC1 FastAPI).

---

## What the Dashboard Shows RIGHT NOW (live data)

| Panel | Status |
|---|---|
| 6 incidents, severity-sorted | ✅ showing |
| Risk gauge (max risk = 69, HIGH) | ✅ showing |
| MITRE heatmap with real cells (T1566/T1041/T1078 × phishing/exfiltration) | ✅ showing |
| Compliance breaches: BCT Circular + PCI-DSS Req.10/11 | ✅ showing |
| Attack Origins: Russia (from scenario IOCs) | ✅ showing |
| 7 predictions: phishing +826, exfiltration +210, FIN7/Cobalt/Lazarus/Carbanak stable | ✅ showing |
| Stats KPIs: 321 raw / 161 IOCs / 6 incidents / 7 predictions | ✅ showing |
| Asset cards (inferred from IOC threat types) | ✅ showing (fallback) |
| APT Groups panel | ⏳ waiting for PC2 `apt_attribution` |
| AI CISO Summary badge | ⏳ waiting for PC2 LLM summaries |
| Asset cards with real targeted_assets | ⏳ waiting for PC3 pipeline fix |
| Geolocation for URLhaus/ThreatFox IOCs | ⏳ waiting for PC1 enrichment |
