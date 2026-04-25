"""
Streamlit dashboard — Banking Sector Threat Intelligence
Phase 1: shell with placeholders, reads live from PC1 API.
All panels are wired but show empty state until upstream data arrives.
"""

import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
PC1_BASE_URL = "http://100.67.61.250:8000"

st.set_page_config(
    page_title="Banking Sector Threat Intelligence",
    page_icon="🏦",
    layout="wide",
)

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

COMPLIANCE_DEADLINES = {
    "PCI-DSS Req.3":  "Per acquirer contract",
    "PCI-DSS Req.10": "Audit cycle",
    "PCI-DSS Req.11": "Audit cycle",
    "SWIFT CSP 2.x":  "24h to SWIFT",
    "GDPR Art.33":    "72h to regulator",
    "Basel III ORR":  "Per local implementation",
    "BCT Circular":   "Per local circular",
}


# ── API helpers ───────────────────────────────────────────────────────────────
def fetch(endpoint: str, default=None):
    """Fetch JSON from PC1 API; returns default on any failure."""
    try:
        r = requests.get(f"{PC1_BASE_URL}{endpoint}", timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default if default is not None else []


# ── Dashboard (auto-refreshes every 5s via Streamlit fragment) ────────────────
@st.fragment(run_every=5)
def dashboard():
    incidents   = fetch("/incidents")
    predictions = fetch("/predictions")

    pc1_ok = isinstance(incidents, list)
    status_badge = "🟢 PC1 connected" if pc1_ok else "🔴 PC1 unreachable"
    st.caption(
        f"{status_badge} | Last refresh: {datetime.now().strftime('%H:%M:%S')} "
        f"| API: `{PC1_BASE_URL}`"
    )

    # ── Row 1: Risk Gauge + Compliance Panel ──────────────────────────────────
    # WHY: Risk gauge is the first thing the jury sees — one number tells the story.
    # Compliance panel is PC4's killer feature; placing it top-right gives it equal weight.
    col_gauge, col_compliance = st.columns([1, 2])

    with col_gauge:
        st.subheader("Banking Sector Risk")
        max_risk = max((i.get("risk_score", 0) for i in incidents), default=0)
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=max_risk,
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#e63946"},
                "steps": [
                    {"range": [0,  30], "color": "#2d6a4f"},
                    {"range": [30, 60], "color": "#f4a261"},
                    {"range": [60, 100], "color": "#e63946"},
                ],
            },
        ))
        fig_gauge.update_layout(height=230, margin=dict(t=30, b=0, l=10, r=10))
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col_compliance:
        st.subheader("🔒 Compliance Breaches — Live")
        # Aggregate counts per framework from all incidents
        fw_counts = {"PCI-DSS": 0, "SWIFT CSP": 0, "GDPR": 0, "BCT": 0}
        breach_rows = []
        for inc in incidents:
            for breach in inc.get("compliance_breaches", []):
                for fw in fw_counts:
                    if fw in breach:
                        fw_counts[fw] += 1
                deadline = COMPLIANCE_DEADLINES.get(breach, "—")
                breach_rows.append({
                    "Incident": inc["id"][:8],
                    "Severity": inc.get("severity", "?").upper(),
                    "Breach": breach,
                    "Notification Deadline": deadline,
                })

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("PCI-DSS",    fw_counts["PCI-DSS"])
        c2.metric("SWIFT CSP",  fw_counts["SWIFT CSP"])
        c3.metric("GDPR Art.33", fw_counts["GDPR"])
        c4.metric("BCT",        fw_counts["BCT"])

        if breach_rows:
            st.dataframe(pd.DataFrame(breach_rows), use_container_width=True, height=140)
        else:
            st.info("No compliance breaches detected yet — waiting for incident data from PC1.")

    st.divider()

    # ── Row 2: Top Threats bar chart + Live Alerts list ───────────────────────
    # WHY: Matches slide 7 layout exactly. Threats chart = quick scan;
    # alerts list = the detail analysts drill into.
    col_threats, col_alerts = st.columns([1, 2])

    with col_threats:
        st.subheader("Top Threats")
        tc = {"Phishing": 0, "Malware": 0, "Lateral Mvmt": 0, "Exfiltration": 0, "C2": 0}
        key_map = {
            "phishing": "Phishing", "malware": "Malware",
            "lateral_movement": "Lateral Mvmt", "exfiltration": "Exfiltration", "c2": "C2",
        }
        for inc in incidents:
            for ioc in inc.get("iocs", []):
                label = key_map.get(ioc.get("threat_type", ""))
                if label:
                    tc[label] += 1

        fig_bar = px.bar(
            x=list(tc.values()),
            y=list(tc.keys()),
            orientation="h",
            color=list(tc.values()),
            color_continuous_scale=["#2d6a4f", "#f4a261", "#e63946"],
        )
        fig_bar.update_layout(
            height=230, margin=dict(t=10, b=0),
            showlegend=False, coloraxis_showscale=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_alerts:
        st.subheader("Live Alerts")
        if not incidents:
            st.info("No incidents yet — PC1 skeleton running, waiting for first data.")
        else:
            for inc in reversed(incidents[-10:]):
                sev  = inc.get("severity", "low")
                icon = SEVERITY_ICON.get(sev, "⚪")
                ts   = inc.get("detected_at", "")[:19]
                with st.expander(f"{icon} [{sev.upper()}] {inc['id'][:8]} — {ts}"):
                    st.write(inc.get("summary") or "_CISO summary pending — LLM wires up in Phase 3._")
                    techniques = inc.get("mitre_techniques", [])
                    if techniques:
                        st.caption(f"MITRE: {', '.join(techniques)}")
                    breaches = inc.get("compliance_breaches", [])
                    if breaches:
                        st.caption(f"⚠️ Compliance: {', '.join(breaches)}")

    st.divider()

    # ── Row 3: Asset View ─────────────────────────────────────────────────────
    # WHY: Instead of generic "banking/telecom/healthcare" sectors, we show
    # the three assets of Banque Atlas that the scenario attack targets.
    # This makes the demo narrative concrete and visual.
    st.subheader("Asset View — Banque Atlas")
    col_t, col_pg, col_cdb = st.columns(3)

    asset_buckets: dict[str, list] = {
        "treasury": [], "payment_gateway": [], "customer_db": []
    }
    for inc in incidents:
        for asset in inc.get("targeted_assets", []):
            if asset in asset_buckets:
                asset_buckets[asset].append(inc)

    for col, asset_key, label in zip(
        [col_t, col_pg, col_cdb],
        ["treasury",    "payment_gateway",    "customer_db"],
        ["🏛 Treasury", "💳 Payment Gateway", "🗄 Customer DB"],
    ):
        with col:
            incs = asset_buckets[asset_key]
            st.metric(label, f"{len(incs)} incident{'s' if len(incs) != 1 else ''}")
            for inc in incs[-3:]:
                sev = inc.get("severity", "low")
                st.write(
                    f"{SEVERITY_ICON.get(sev,'⚪')} `{inc['id'][:8]}` "
                    f"— risk **{inc.get('risk_score', 0)}**"
                )
            if not incs:
                st.caption("✅ Clean")

    st.divider()

    # ── Row 4: Predictions ────────────────────────────────────────────────────
    # WHY: Predictions are PC4's panel for PC3's output. Placeholder now;
    # trend graph + forecast numbers wire in Phase 3.
    st.subheader("📈 Threat Predictions — 7-Day Forecast")
    if not predictions:
        st.info("Waiting for predictions from PC3 via PC1 — available from Phase 3 onward.")
    else:
        pred_df = pd.DataFrame(predictions)
        st.dataframe(
            pred_df[["sector", "threat_type", "forecast_7d", "trend", "confidence"]],
            use_container_width=True,
        )


# ── Entry point ───────────────────────────────────────────────────────────────
st.title("🏦 Banking Sector Threat Intelligence")
st.caption("Cyberia 2026 — AI-Powered Threat Intelligence Platform | Banque Atlas Demo")
dashboard()

