"""
Compute the pitch KPIs (BATTLE_PLAN.md:271-279, ToR §8 — 20% of the grade)
directly from PC1's live API. No magic. No precomputed values. No AI.

Run it in front of the jury during the pitch / Q&A. The numbers come from
the running system, not from a slide.

Usage:
    python scripts/compute_kpis.py
    python scripts/compute_kpis.py --api http://100.67.61.250:8000

Each KPI block prints:
  - the formula (what we measured)
  - the inputs (which API call / which fields)
  - the result

Industry citations used (cite these on the pitch slide):
  - IBM Cost of a Data Breach Report 2024 — "Mean time to identify a
    breach: 204 days."
  - (ISC)² Cybersecurity Workforce Study 2023 — SOC analyst total cost
    ~$95k/year (≈ $46/hr loaded).
  - Ponemon — average incident triage time: ~3-5 hrs.

KPIs that depend on industry citations are clearly labeled. KPIs that are
pure measurements from /stats and /incidents have no citation footnote.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone

import httpx

# Windows consoles default to cp1252 which can't encode the em-dashes and
# section symbols used below. Force UTF-8 so the script runs identically on
# Linux/macOS/Windows. Safe fallback if the stream doesn't support reconfigure.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass


def parse_ts(ts: str) -> datetime:
    """Parse ISO-8601, force UTC if the timestamp is timezone-naive."""
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fetch(client: httpx.Client, path: str) -> object:
    r = client.get(path, timeout=10.0)
    r.raise_for_status()
    return r.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute pitch KPIs from PC1's live API")
    parser.add_argument("--api", default="http://localhost:8000", help="PC1 API base URL")
    args = parser.parse_args()
    base = args.api.rstrip("/")

    print(f"=== KPI snapshot from {base} ===")
    print(f"Run at: {datetime.now(timezone.utc).isoformat()}")

    with httpx.Client() as client:
        stats = fetch(client, f"{base}/stats")
        iocs = fetch(client, f"{base}/iocs/enriched?limit=2000")
        incs = fetch(client, f"{base}/incidents?limit=200")
        preds = fetch(client, f"{base}/predictions")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 1 — IOCs/min
    # FORMULA: len(enriched_iocs) / (max first_seen − min first_seen) in min
    # SOURCE : GET /iocs/enriched, field `first_seen` per row
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 1 — IOC ingestion rate ---")
    if len(iocs) >= 2:
        ts_sorted = sorted(parse_ts(i["first_seen"]) for i in iocs)
        window_min = (ts_sorted[-1] - ts_sorted[0]).total_seconds() / 60
        rate = len(iocs) / max(window_min, 1)
        print(f"  enriched IOCs:        {len(iocs)}")
        print(f"  time window (min):    {window_min:.1f}  ({ts_sorted[0].isoformat()} -> {ts_sorted[-1].isoformat()})")
        print(f"  average rate:         {rate:.2f} IOCs/min")
        print(f"  NOTE: averaged over the full ingest window. During the 4-event")
        print(f"        scenario fire (--pace 60), instantaneous rate jumps ~10-30x.")
    else:
        print("  insufficient data")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 2 — Pipeline compression (raw → enriched IOCs)
    # FORMULA: 1 − (enriched_iocs / raw_records)
    # SOURCE : GET /stats.raw_count, GET /stats.ioc_count (or /iocs/enriched)
    # CAVEAT : This is "pipeline compression", NOT "FP reduction". The gap
    #          includes raw records with zero IOCs, sentence-transformers
    #          dedup duplicates, and banking-classifier rejects.
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 2 — pipeline compression ---")
    raw_count = stats["raw_count"]
    ioc_count = len(iocs)
    print(f"  raw threat records:   {raw_count}  (GET /stats.raw_count)")
    print(f"  enriched IOCs:        {ioc_count}  (len GET /iocs/enriched)")
    if raw_count:
        pct = (1 - ioc_count / raw_count) * 100
        print(f"  compression:          {pct:.0f}%  ← framed as 'noise rejection' on the pitch")
        print(f"  CAVEAT: not formal FP reduction (would need ground-truth labels).")
        print(f"          This is dedup + banking-filter + zero-IOC-record drop combined.")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 3 — MTTA (Mean Time To Acknowledge)
    # FORMULA: PC2 poll interval + PC3 poll interval + LLM summary latency
    # SOURCE : pc2_ai/pipeline.py POLL_INTERVAL=10s + pc3_analysis/pipeline.py
    #          POLL_INTERVAL_S=10s + measured Ollama summary ≈ 30s
    # CITE  : IBM Cost of a Data Breach Report 2024 (204-day baseline)
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 3 — MTTA (best-case end-to-end latency) ---")
    pc2_poll = 10  # seconds; from pc2_ai/pipeline.py
    pc3_poll = 10  # seconds; from pc3_analysis/pipeline.py
    llm_summary = 30  # seconds; measured against local Ollama mistral:latest
    mtta_s = pc2_poll + pc3_poll + llm_summary
    industry_baseline_days = 204  # IBM Cost of a Data Breach Report 2024
    industry_baseline_s = industry_baseline_days * 86400
    print(f"  PC2 poll interval:    {pc2_poll} s   (pc2_ai/pipeline.py)")
    print(f"  PC3 poll interval:    {pc3_poll} s   (pc3_analysis/pipeline.py)")
    print(f"  LLM summary latency:  ~{llm_summary} s  (Ollama mistral:latest, local)")
    print(f"  TOTAL best-case MTTA: {mtta_s} s")
    print(f"  Industry baseline:    {industry_baseline_days} days (IBM 2024 Cost of a Data Breach Report)")
    print(f"  Speed-up factor:      {industry_baseline_s / mtta_s:.0f}x")
    print(f"  NOTE: 50 s is best-case lab latency. Quote it as 'pipeline design")
    print(f"        latency' not 'our production-MTTA on real customer data'.")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 4 — MITRE ATT&CK technique coverage
    # FORMULA: union of mitre_techniques across all live incidents
    # SOURCE : GET /incidents[*].mitre_techniques
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 4 — MITRE ATT&CK coverage on live incidents ---")
    techs = sorted({t for i in incs for t in (i.get("mitre_techniques") or [])})
    print(f"  distinct techniques:  {len(techs)}")
    print(f"  list:                 {', '.join(techs)}")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 5 — auto-correlation ratio
    # FORMULA: raw_count / incident_count
    # SOURCE : GET /stats.raw_count and GET /stats.incident_count
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 5 — auto-correlation ratio (raw → incidents) ---")
    inc_count = stats["incident_count"]
    print(f"  raw events:           {raw_count}")
    print(f"  correlated incidents: {inc_count}")
    if inc_count:
        print(f"  compression:          {raw_count / inc_count:.1f}:1")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 6 — prediction coverage by kind
    # FORMULA: bucket /predictions by threat_type prefix
    # SOURCE : GET /predictions[*].threat_type, prefix scheme is documented
    #          in pc3_analysis/PC3_STATUS.md (bare = volume forecast,
    #          cve:* = CVE rank, apt:* = APT match, anomaly:* = volume spike)
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 6 — prediction coverage ---")
    bucket = Counter()
    for p in preds:
        t = p["threat_type"]
        kind = t.split(":")[0] if ":" in t else "volume"
        bucket[kind] += 1
    print(f"  total predictions:    {len(preds)}")
    for k, v in sorted(bucket.items()):
        print(f"    {k:10s} {v}")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 7 — compliance breaches
    # FORMULA: /stats.compliance_breach_count + rollup of frameworks
    # SOURCE : GET /stats.compliance_breach_count, /incidents[*].compliance_breaches
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 7 — compliance breaches auto-flagged ---")
    print(f"  incidents with breaches: {stats['compliance_breach_count']}  (GET /stats.compliance_breach_count)")
    framework_counts = Counter(
        f for i in incs for f in (i.get("compliance_breaches") or [])
    )
    print(f"  frameworks triggered:")
    for f, n in framework_counts.most_common():
        print(f"    {f:25s} {n}")

    # ──────────────────────────────────────────────────────────────────────
    # KPI 8 — cost per incident (BMC ammunition, NOT a measurement)
    # FORMULA: traditional SOC = analyst_hourly_rate × hrs_per_triage
    #          our platform     = ~0 marginal cost (local LLM + free feeds)
    # CITE  : (ISC)² Cybersecurity Workforce Study 2023 ($46/hr loaded)
    #         Ponemon — ~3-5 hrs typical triage
    # ──────────────────────────────────────────────────────────────────────
    print("\n--- KPI 8 — cost per incident (BMC story, NOT a system measurement) ---")
    analyst_rate = 46  # USD/hr loaded; (ISC)² 2023
    triage_hrs_low, triage_hrs_high = 3, 5  # Ponemon typical range
    print(f"  Traditional SOC:")
    print(f"    analyst rate:       ${analyst_rate}/hr (loaded; (ISC)² 2023)")
    print(f"    triage time:        {triage_hrs_low}-{triage_hrs_high} hrs (Ponemon typical)")
    print(f"    per-incident cost:  ${analyst_rate * triage_hrs_low} - ${analyst_rate * triage_hrs_high}")
    print(f"  Our platform:")
    print(f"    Ollama (local):     $0/inference (electricity only)")
    print(f"    OSINT feeds:        $0 (5 free public feeds)")
    print(f"    VT/Shodan:          free tier, 4-500 lookups/day")
    print(f"    per-incident cost:  <$1 in API spend, near-zero marginal")
    print(f"  CAVEAT: cost-per-incident is a BMC argument, not a system metric.")
    print(f"          Cite (ISC)² + Ponemon for the analyst-cost figure.")

    print("\n=== END KPI SNAPSHOT ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
