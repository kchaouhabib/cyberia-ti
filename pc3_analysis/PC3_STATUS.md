# PC3 — Status & Cross-PC Asks

This document is the running source of truth for what PC3 has shipped, what
is live on PC1 right now, and what we need from PC1 / PC2 / PC4 to make the
final demo land.

Live target: `http://100.67.61.250:8000` (PC1 over NetBird)

---

## What PC3 ships

PC3 owns **correlation, MITRE/compliance tagging, banking-weighted risk
scoring, anomaly detection, and predictive intelligence**. Everything is
written into PC1 (single source of truth). PC4 reads it from there.

### Module map

```
pc3_analysis/
├── correlator.py            Phase 1  groups EnrichedIOCs into Incidents (1h window per source)
├── mitre_mapper.py          Phase 2  rule-based MITRE tagging (T1566, T1041, …)
├── compliance_mapper.py     Phase 2  PCI-DSS / SWIFT CSP / GDPR / Basel / BCT  ← killer feature
├── risk_scorer.py           Phase 2  severity × sector × confidence × compliance_weight × 100
├── anomaly_detector.py      Phase 2  Isolation Forest on hourly volume per source
├── predictor.py             Phase 3  Prophet 7-day forecast per (sector, threat_type)
├── cve_prioritizer.py       Phase 3  banking-weighted CVE ranking (Oracle / Temenos / Finastra / SWIFT boost)
├── behavior_analyzer.py     Phase 3  rule-based APT signature matching + KMeans clustering
└── pipeline.py              the loop: poll → correlate → tag → score → forecast → POST back
```

### Live data flow

1. `pipeline.run_loop()` polls `GET /iocs/enriched` every 10 s.
2. `correlator.correlate(iocs)` groups them into Incident buckets.
3. For each Incident: `mitre_mapper.apply` → `compliance_mapper.apply` → `risk_scorer.apply`. Sector heuristic falls back to `banking` when the source is one of the banking-filtered feeds.
4. Each enriched Incident is `POST`ed to `/incidents` (UPSERT-on-id).
5. `anomaly_detector.from_iocs(iocs)` logs hourly-volume outliers.
6. **Phase 3 producers** (`predictor`, `cve_prioritizer`, `behavior_analyzer`) emit `Prediction` rows that we `POST` to `/predictions`.

### Prediction encoding (what PC4 needs to know)

The locked `Prediction` schema only has 5 fields (`sector`, `threat_type`,
`forecast_7d`, `trend`, `confidence`). To stay inside the contract while
shipping all three Phase 3 producers, we **overload `threat_type` with a
prefix**:

| `threat_type`         | Producer            | What `forecast_7d` means      | Example                                    |
|-----------------------|---------------------|--------------------------------|--------------------------------------------|
| `phishing`, `c2`, …   | `predictor.py`      | Predicted attack count / 7d    | `banking / phishing / 826 / rising`        |
| `cve:CVE-YYYY-NNNN`   | `cve_prioritizer.py`| 0–100 priority score           | `banking / cve:CVE-2024-99999 / 100 / stable` |
| `apt:<group>`         | `behavior_analyzer` | 0–100 match strength           | `banking / apt:fin7 / 100 / stable`        |
| `apt:cluster-<n>`     | `behavior_analyzer` | 0–100 cluster strength         | `banking / apt:cluster-1 / 73 / rising`    |

PC4 should switch on the prefix to pick the right card and unit label.

### Last live verification

```
GET /incidents     → 2 incidents (top: 141 IOCs, score 69/high,
                                  MITRE [T1041, T1078, T1566],
                                  compliance [BCT Circular,
                                              PCI-DSS Req.10,
                                              PCI-DSS Req.11])
GET /predictions   → 7 rows
                     - 3 volume forecasts (phishing 826/7d, exfil 210/7d, lateral 7/7d)
                     - 4 APT matches (fin7 100, cobalt-group 100, lazarus 67, carbanak 67)
```

---

## What we need from PC1

### 1. Add `sector` + `asset_type` to `EnrichedIOC` (1-line schema change)

```python
class EnrichedIOC(IOC):
    threat_type: str
    related_cves: List[str] = []
    geolocation: Optional[str] = None
    reputation: Optional[float] = None
    apt_attribution: Optional[str] = None
    sector: Optional[str] = None       # ← ADD
    asset_type: Optional[str] = None   # ← ADD
```

Both fields already exist on `RawThreatRecord` but get dropped during
enrichment. Without them PC3 has to:
- guess `sector` via a banking-source allow-list
- guess `asset_type` via keyword regex on IOC values

It works, but it's a workaround. The fix is one line per schema and one line
in PC2's enrichment to copy the parent values through.

### 2. Spread the scenario injector timing during the demo

Currently the bank-attack scenario fires all its events into a single hour /
single day. That:
- starves the **anomaly detector** (needs ≥ 3 distinct hourly buckets to fit
  Isolation Forest)
- starves the **Prophet forecaster** (needs ≥ 7 distinct days for a full fit;
  we fall back to a flat-rate forecast on day-1 data)

For the demo, please drip the scenario events across at least **3 hours and
2 days** so both models leave their fallback paths.

---

## What we need from PC2

### 3. (BLOCKER) Populate `EnrichedIOC.related_cves`

Right now no enriched IOC carries CVE references, so our CVE prioritizer
emits **0 rows** even though the module works. The "patch this Temenos CVE
first" pitch slide has nothing behind it.

Easiest fix in `pc2_ai/llm_extractor.py` (or wherever the enricher
runs):

```python
import re

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(raw_text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_REGEX.findall(raw_text or "")})

# then on enrichment:
enriched_ioc.related_cves = extract_cves(raw.raw_text)
```

If the LLM extractor is already pulling CVE entities, even better — just feed
those into `related_cves` instead.

### 4. Copy `sector` + `asset_type` from `RawThreatRecord` to `EnrichedIOC`

Depends on PC1 ask #1 landing. One-line copy during enrichment.

---

## What we need from PC4

### 5. Strip the `cve:` prefix in the Predictions card title

`pc4_dashboard/react-app/src/pages/Predictions.jsx` line 22 already strips
`apt:`. Add the same for `cve:`:

```jsx
{p.threat_type
  ?.replace("apt:", "APT: ")
  .replace("cve:", "CVE: ")          // ← ADD
  .replace(/_/g, " ")
  .replace(/-/g, " ")}
```

### 6. Switch the unit label based on prefix

Hardcoding `"attacks / 7 days"` on every card (line 36) is wrong for
`cve:` and `apt:` rows. Suggested:

```jsx
const unit =
  p.threat_type?.startsWith("cve:") ? "priority / 100" :
  p.threat_type?.startsWith("apt:") ? "% match"        :
                                      "attacks / 7 days";
```

### 7. Split the predictions panel into 3 sections

Volume forecasts, CVE priority, APT campaigns — each gets its own card grid.
Filter `apt:` and `cve:` rows out of the bar-chart and "rising threats"
area-chart, since those don't have time-series semantics.

### 8. Wire the compliance panel to `Incident.compliance_breaches`

This is our differentiator. Each incident already carries
`compliance_breaches: list[str]`. The dashboard should render those as
coloured badges (PCI-DSS, GDPR Art.33, SWIFT CSP, Basel III ORR, BCT
Circular). Status: unconfirmed — please verify it's wired.

---

## Known limitations (graceful, not blockers)

| Module             | Behaviour when data is thin                                    |
|--------------------|----------------------------------------------------------------|
| `anomaly_detector` | Returns `[]` until ≥ 3 hourly buckets exist                    |
| `predictor`        | Falls back to flat-rate forecast (low confidence) on day-1 data; uses sklearn linear regression if Prophet ever fails to import |
| `cve_prioritizer`  | Returns `[]` if no IOC carries a CVE reference (see PC2 ask #3)|
| `behavior_analyzer`| Rule-based APT match always runs from 1 incident; KMeans waits for ≥ 4 incidents |

---

## Quick reference

- **Run one cycle:** `.venv/Scripts/python.exe -m pc3_analysis.pipeline --once`
- **Run the loop (demo mode):** `.venv/Scripts/python.exe -m pc3_analysis.pipeline`
- **Tail live predictions:** `curl http://100.67.61.250:8000/predictions`
- **Tail live incidents:**   `curl http://100.67.61.250:8000/incidents`
- **Override PC1 IP:**       `set PC1_BASE_URL=http://<ip>:8000` (Windows) or `export PC1_BASE_URL=...`
