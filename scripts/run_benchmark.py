"""
Benchmark harness — measures the live system, no AI, no narration.

Every number printed here is a reproducible measurement against PC1's
running API. A juror who clones the repo and runs:

    python scripts/run_benchmark.py

against PC1 will see the same kind of report (with their own numbers).
That is the difference between a benchmark and a marketing claim.

Six benchmarks, each with documented methodology:

  1. Per-route API latency (p50 / p95 / p99) — 50 sequential GETs,
     computed percentiles, no LLM.
  2. Per-source IOC ingestion rate — counts grouped by `source`,
     divided by first_seen time window.
  3. Pipeline compression — raw / incidents ratio from /stats.
  4. MITRE vocabulary precision — every technique value in /incidents
     must be in the 12 financial techniques from BATTLE_PLAN Appendix E.
  5. Compliance vocabulary precision — every framework value must be
     in the 7 from BATTLE_PLAN Appendix F.
  6. End-to-end pipeline latency — POST one synthetic raw record with
     a uniquely-tagged IOC, poll until it surfaces in /iocs/enriched,
     stopwatch the delta.

Outputs:
  data/demo_artifacts/BENCHMARK_RESULTS.md   — human-readable report
  data/demo_artifacts/BENCHMARK_RESULTS.json — same numbers, machine-readable

No external dependencies beyond what's already in requirements.txt
(httpx, stdlib). No LLM calls. No fabricated numbers.
"""

from __future__ import annotations

import json
import random
import statistics
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

BASE = "http://localhost:8000"
OUT = Path("data/demo_artifacts")
OUT.mkdir(parents=True, exist_ok=True)


# Curated vocabulary — the values we expect to see, sourced from
# BATTLE_PLAN.md Appendix E (lines 464-477) + Appendix F (lines 481-491).
EXPECTED_MITRE = {
    "T1566", "T1078", "T1190", "T1539", "T1041", "T1071",
    "T1486", "T1055", "T1098", "T1567", "T1021.002", "T1657",
}
EXPECTED_COMPLIANCE = {
    "PCI-DSS Req.3", "PCI-DSS Req.10", "PCI-DSS Req.11",
    "SWIFT CSP CSCF 2.x", "GDPR Art.33", "Basel III ORR", "BCT Circular",
}


def percentile(values: list[float], p: float) -> float:
    """Compute the p-th percentile (p in [0, 100]) using linear interpolation."""
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


# ──────────────────────────────────────────────────────────────────────────
# Benchmark 1 — Per-route API latency (50 GETs each, p50 / p95 / p99)
# ──────────────────────────────────────────────────────────────────────────
def bench_api_latency(client: httpx.Client, n: int = 50) -> dict:
    routes = ["/stats", "/raw?limit=100", "/iocs/enriched?limit=100",
              "/incidents?limit=50", "/predictions"]
    out: dict[str, dict] = {}
    print(f"  [1/6] API latency benchmark — {n} sequential GETs per route...")
    for route in routes:
        latencies: list[float] = []
        for _ in range(n):
            t0 = time.perf_counter()
            r = client.get(f"{BASE}{route}", timeout=10.0)
            t1 = time.perf_counter()
            r.raise_for_status()
            latencies.append((t1 - t0) * 1000)  # ms
        out[route] = {
            "n": n,
            "min_ms": round(min(latencies), 2),
            "max_ms": round(max(latencies), 2),
            "mean_ms": round(statistics.mean(latencies), 2),
            "p50_ms": round(percentile(latencies, 50), 2),
            "p95_ms": round(percentile(latencies, 95), 2),
            "p99_ms": round(percentile(latencies, 99), 2),
            "stddev_ms": round(statistics.pstdev(latencies), 2),
        }
        print(f"        {route:35s} p50={out[route]['p50_ms']:6.1f}ms"
              f"  p95={out[route]['p95_ms']:6.1f}ms"
              f"  p99={out[route]['p99_ms']:6.1f}ms")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Benchmark 2 — Per-source ingestion rate
# ──────────────────────────────────────────────────────────────────────────
def bench_ingestion_rate(client: httpx.Client) -> dict:
    print("  [2/6] Per-source ingestion rate (count / window minutes)...")
    iocs = client.get(f"{BASE}/iocs/enriched?limit=2000", timeout=30).json()
    by_source: dict[str, list[float]] = {}
    for ioc in iocs:
        ts_str = ioc["first_seen"]
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        by_source.setdefault(ioc["source"], []).append(ts.timestamp())
    out: dict[str, dict] = {}
    for src, times in by_source.items():
        if len(times) < 2:
            continue
        window_min = (max(times) - min(times)) / 60
        rate = len(times) / max(window_min, 1)
        out[src] = {
            "count": len(times),
            "window_minutes": round(window_min, 1),
            "iocs_per_min": round(rate, 3),
        }
        print(f"        {src:20s} n={out[src]['count']:>4d}"
              f"  window={out[src]['window_minutes']:>7.1f} min"
              f"  rate={out[src]['iocs_per_min']:.3f} IOC/min")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Benchmark 3 — Pipeline compression
# ──────────────────────────────────────────────────────────────────────────
def bench_compression(client: httpx.Client) -> dict:
    print("  [3/6] Pipeline compression ratios...")
    stats = client.get(f"{BASE}/stats", timeout=10).json()
    raw = stats["raw_count"]
    ioc = stats["ioc_count"]
    enr = stats["enriched_count"]
    inc = stats["incident_count"]
    out = {
        "raw_count": raw,
        "ioc_count": ioc,
        "enriched_count": enr,
        "incident_count": inc,
        "raw_to_ioc_compression_pct": round((1 - ioc / max(raw, 1)) * 100, 1),
        "ioc_to_incident_ratio": round(ioc / max(inc, 1), 1),
        "raw_to_incident_ratio": round(raw / max(inc, 1), 1),
    }
    print(f"        raw={raw}  ioc={ioc}  enriched={enr}  incidents={inc}")
    print(f"        raw -> ioc compression: {out['raw_to_ioc_compression_pct']}%")
    print(f"        raw -> incident ratio:  {out['raw_to_incident_ratio']}:1")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Benchmark 4 — MITRE vocabulary precision
# ──────────────────────────────────────────────────────────────────────────
def bench_mitre_precision(client: httpx.Client) -> dict:
    print("  [4/6] MITRE vocabulary precision (sanity check vs Appendix E)...")
    incidents = client.get(f"{BASE}/incidents?limit=500", timeout=30).json()
    seen: set[str] = set()
    for i in incidents:
        for t in (i.get("mitre_techniques") or []):
            seen.add(t)
    in_vocab = seen & EXPECTED_MITRE
    out_of_vocab = seen - EXPECTED_MITRE
    precision = len(in_vocab) / max(len(seen), 1)
    out = {
        "distinct_techniques_seen": len(seen),
        "in_vocab": sorted(in_vocab),
        "out_of_vocab": sorted(out_of_vocab),
        "precision_pct": round(precision * 100, 1),
    }
    print(f"        distinct techniques: {len(seen)}  "
          f"in-vocab: {len(in_vocab)}  out-of-vocab: {len(out_of_vocab)}")
    print(f"        precision: {out['precision_pct']}%")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Benchmark 5 — Compliance vocabulary precision
# ──────────────────────────────────────────────────────────────────────────
def bench_compliance_precision(client: httpx.Client) -> dict:
    print("  [5/6] Compliance vocabulary precision (sanity check vs Appendix F)...")
    incidents = client.get(f"{BASE}/incidents?limit=500", timeout=30).json()
    seen: set[str] = set()
    for i in incidents:
        for f in (i.get("compliance_breaches") or []):
            seen.add(f)
    in_vocab = seen & EXPECTED_COMPLIANCE
    out_of_vocab = seen - EXPECTED_COMPLIANCE
    precision = len(in_vocab) / max(len(seen), 1)
    out = {
        "distinct_frameworks_seen": len(seen),
        "in_vocab": sorted(in_vocab),
        "out_of_vocab": sorted(out_of_vocab),
        "precision_pct": round(precision * 100, 1),
    }
    print(f"        distinct frameworks: {len(seen)}  "
          f"in-vocab: {len(in_vocab)}  out-of-vocab: {len(out_of_vocab)}")
    print(f"        precision: {out['precision_pct']}%")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Benchmark 6 — End-to-end pipeline latency (stopwatch)
# ──────────────────────────────────────────────────────────────────────────
def bench_e2e_latency(client: httpx.Client, max_wait_s: int = 120) -> dict:
    print("  [6/6] End-to-end pipeline latency (one synthetic record, stopwatch)...")
    rand = "".join(random.choices(string.hexdigits.lower(), k=12))
    test_ip = f"198.51.100.{random.randint(200, 250)}"  # RFC 5737 reserved
    test_id = f"benchmark:probe-{rand}"
    raw_text = (
        f"Title: BENCHMARK PROBE - synthetic single-event raw record\n"
        f"Source: scripts/run_benchmark.py\n"
        f"Description: a unique destination_ip {test_ip} appears below for "
        f"end-to-end pipeline-latency timing. RFC 5737 reserved range, "
        f"never routable. Benchmark id: {rand}.\n"
    )
    record = {
        "id": test_id,
        "source": "benchmark",
        "raw_text": raw_text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sector": "banking",
        "asset_type": None,
    }

    t0 = time.perf_counter()
    r = client.post(f"{BASE}/raw", json=record, timeout=10)
    r.raise_for_status()
    t_post = time.perf_counter() - t0

    print(f"        POST  raw record   ({t_post*1000:.0f} ms)")
    print(f"        polling /iocs/enriched for value={test_ip} (timeout {max_wait_s}s)...")

    t_extract = None
    poll_start = time.perf_counter()
    while time.perf_counter() - poll_start < max_wait_s:
        time.sleep(2)
        try:
            iocs = client.get(f"{BASE}/iocs/enriched?limit=2000", timeout=10).json()
            if any(i.get("value") == test_ip for i in iocs):
                t_extract = time.perf_counter() - poll_start
                print(f"        FOUND in /iocs/enriched after {t_extract:.1f} s")
                break
        except httpx.HTTPError:
            pass

    out = {
        "test_ioc_value": test_ip,
        "test_record_id": test_id,
        "post_latency_ms": round(t_post * 1000, 2),
        "extract_latency_s": round(t_extract, 1) if t_extract else None,
        "extract_timed_out": t_extract is None,
        "industry_baseline_days_to_identify": 204,
        "industry_baseline_source": "IBM Cost of a Data Breach Report 2024",
        "speedup_factor": round((204 * 86400) / max(t_extract or 1e9, 1), 0)
        if t_extract else None,
    }
    if t_extract is None:
        print(f"        timed out - PC2 pipeline may be idle or backed up")
    return out


# ──────────────────────────────────────────────────────────────────────────
# Report writer
# ──────────────────────────────────────────────────────────────────────────
def write_report(results: dict) -> None:
    md = OUT / "BENCHMARK_RESULTS.md"
    js = OUT / "BENCHMARK_RESULTS.json"

    lines = [
        "# CYBERIA Benchmark Results",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Method:** `python scripts/run_benchmark.py` against PC1's live API",
        "",
        "Every number below is a measurement, not a narration.",
        "Re-run the script and you'll see numbers in the same shape.",
        "",
    ]

    # 1. API latency
    lines.append("## 1. API latency (50 sequential GETs per route)")
    lines.append("")
    lines.append("| Route | n | p50 ms | p95 ms | p99 ms | mean ms | stddev ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for route, m in results["api_latency"].items():
        lines.append(
            f"| `{route}` | {m['n']} | {m['p50_ms']} | {m['p95_ms']} | "
            f"{m['p99_ms']} | {m['mean_ms']} | {m['stddev_ms']} |"
        )
    lines.append("")
    lines.append("*Methodology: `httpx.Client.get` x 50, `time.perf_counter` deltas, "
                 "stdlib `statistics` for percentiles.*")
    lines.append("")

    # 2. Ingestion rate
    lines.append("## 2. Per-source IOC ingestion rate")
    lines.append("")
    lines.append("| Source | IOC count | Window (min) | IOC/min |")
    lines.append("|---|---:|---:|---:|")
    for src, m in sorted(results["ingestion_rate"].items(),
                         key=lambda kv: -kv[1]["count"]):
        lines.append(
            f"| `{src}` | {m['count']} | {m['window_minutes']} | "
            f"{m['iocs_per_min']} |"
        )
    lines.append("")
    lines.append("*Methodology: group `EnrichedIOC.first_seen` by source, "
                 "rate = count / (max - min) in minutes.*")
    lines.append("")

    # 3. Compression
    c = results["compression"]
    lines.extend([
        "## 3. Pipeline compression",
        "",
        f"- Raw threat records: **{c['raw_count']}**",
        f"- IOCs (raw): **{c['ioc_count']}**",
        f"- Enriched IOCs: **{c['enriched_count']}**",
        f"- Correlated incidents: **{c['incident_count']}**",
        f"- **Raw -> IOC compression: {c['raw_to_ioc_compression_pct']}%** "
        "(dedup + banking-classifier + records w/ no IOCs combined)",
        f"- **Raw -> incident ratio: {c['raw_to_incident_ratio']}:1** "
        "(the 'one campaign, many alerts' compression)",
        "",
    ])

    # 4. MITRE precision
    m = results["mitre_precision"]
    lines.extend([
        "## 4. MITRE technique vocabulary precision",
        "",
        f"- Distinct techniques observed: **{m['distinct_techniques_seen']}**",
        f"- In curated vocabulary (BATTLE_PLAN Appendix E, 12 banking-relevant "
        f"techniques): **{len(m['in_vocab'])}** -- "
        f"{', '.join(m['in_vocab']) or '(none)'}",
        f"- Out-of-vocabulary: {len(m['out_of_vocab'])} -- "
        f"{', '.join(m['out_of_vocab']) or '(none)'}",
        f"- **Precision: {m['precision_pct']}%**",
        "",
        "*Methodology: union of `Incident.mitre_techniques` across all "
        "incidents, set-membership check against the 12 techniques in "
        "`BATTLE_PLAN.md` Appendix E. 100% means PC3's mapper never "
        "fabricates technique IDs outside the curated vocabulary.*",
        "",
    ])

    # 5. Compliance precision
    c2 = results["compliance_precision"]
    lines.extend([
        "## 5. Compliance framework vocabulary precision",
        "",
        f"- Distinct frameworks observed: **{c2['distinct_frameworks_seen']}**",
        f"- In curated vocabulary (BATTLE_PLAN Appendix F, 7 frameworks): "
        f"**{len(c2['in_vocab'])}** -- {', '.join(c2['in_vocab']) or '(none)'}",
        f"- Out-of-vocabulary: {len(c2['out_of_vocab'])} -- "
        f"{', '.join(c2['out_of_vocab']) or '(none)'}",
        f"- **Precision: {c2['precision_pct']}%**",
        "",
    ])

    # 6. End-to-end latency
    e = results["e2e_latency"]
    lines.append("## 6. End-to-end pipeline latency (live measurement)")
    lines.append("")
    lines.append(f"- Synthetic test record: `{e['test_record_id']}`")
    lines.append(f"- Test IOC value: `{e['test_ioc_value']}` "
                 "(RFC 5737 TEST-NET-2, never routable)")
    lines.append(f"- POST latency: **{e['post_latency_ms']} ms**")
    if e["extract_timed_out"]:
        lines.append("- IOC extraction: **timed out** "
                     "(PC2 pipeline may be idle or backed up at measurement time)")
    else:
        lines.append(f"- Time from POST `/raw` to value visible in "
                     f"`/iocs/enriched`: **{e['extract_latency_s']} s**")
        lines.append(f"- Industry baseline: **204 days** "
                     f"({e['industry_baseline_source']})")
        lines.append(f"- **Speed-up factor: ~{int(e['speedup_factor']):,}x**")
    lines.append("")
    lines.append("*Methodology: timestamp before POST, timestamp when the IOC "
                 "value first appears in `/iocs/enriched`. Polled every 2 s, "
                 "120 s timeout.*")
    lines.append("")

    md.write_text("\n".join(lines), encoding="utf-8")
    js.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print()
    print(f"  WROTE {md}  ({md.stat().st_size:,} B)")
    print(f"  WROTE {js}  ({js.stat().st_size:,} B)")


# ──────────────────────────────────────────────────────────────────────────
# Driver
# ──────────────────────────────────────────────────────────────────────────
def main() -> int:
    print("=" * 60)
    print("  CYBERIA BENCHMARK HARNESS")
    print(f"  target: {BASE}")
    print(f"  start:  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)
    results: dict = {}
    with httpx.Client() as client:
        results["api_latency"] = bench_api_latency(client)
        results["ingestion_rate"] = bench_ingestion_rate(client)
        results["compression"] = bench_compression(client)
        results["mitre_precision"] = bench_mitre_precision(client)
        results["compliance_precision"] = bench_compliance_precision(client)
        results["e2e_latency"] = bench_e2e_latency(client)
    write_report(results)
    print()
    print("=" * 60)
    print("  BENCHMARK COMPLETE")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
