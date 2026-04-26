"""
Streamlit dashboard — Banking Sector Threat Intelligence
Phase 2: all panels wired with real data from PC1 API.
"""

import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import folium
from streamlit_folium import st_folium
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
PC1_BASE_URL = "http://100.67.61.250:8000"

st.set_page_config(
    page_title="Banking Sector Threat Intelligence",
    page_icon="🏦",
    layout="wide",
)

# ── Constants ─────────────────────────────────────────────────────────────────
SEVERITY_ICON  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
SEVERITY_COLOR = {"critical": "#e63946", "high": "#f4a261", "medium": "#e9c46a", "low": "#2d6a4f"}
TREND_ICON     = {"rising": "📈", "stable": "➡️", "falling": "📉"}

COMPLIANCE_DEADLINES = {
    "PCI-DSS Req.3":      "Per acquirer contract",
    "PCI-DSS Req.10":     "Audit cycle",
    "PCI-DSS Req.11":     "Audit cycle",
    "SWIFT CSP CSCF 2.x": "24h to SWIFT",
    "GDPR Art.33":         "72h to regulator",
    "Basel III ORR":       "Per local implementation",
    "BCT Circular":        "Per local circular",
}

# Known APT groups targeting banking
APT_LABELS = {
    "fin7":         ("FIN7",        "#e63946"),
    "lazarus":      ("Lazarus",     "#9b2226"),
    "carbanak":     ("Carbanak",    "#ae2012"),
    "silence":      ("Silence",     "#bb3e03"),
    "cobalt-group": ("Cobalt Group","#ca6702"),
}

# Geolocation → (lat, lon) — supports both full names and ISO-2 codes from PC1
GEO_COORDS = {
    "Russia":         (55.75,  37.62),  "RU": (55.75,  37.62),
    "China":          (39.91, 116.39),  "CN": (39.91, 116.39),
    "North Korea":    (39.03, 125.75),  "KP": (39.03, 125.75),
    "Iran":           (35.69,  51.39),  "IR": (35.69,  51.39),
    "Romania":        (44.43,  26.10),  "RO": (44.43,  26.10),
    "Ukraine":        (50.45,  30.52),  "UA": (50.45,  30.52),
    "United States":  (38.89, -77.03),  "US": (38.89, -77.03),
    "Germany":        (52.52,  13.40),  "DE": (52.52,  13.40),
    "Netherlands":    (52.37,   4.90),  "NL": (52.37,   4.90),
    "Brazil":         (-15.78,-47.93),  "BR": (-15.78,-47.93),
    "India":          (28.61,  77.21),  "IN": (28.61,  77.21),
    "Turkey":         (39.93,  32.86),  "TR": (39.93,  32.86),
    "Nigeria":        (9.07,    7.40),  "NG": (9.07,    7.40),
    "Indonesia":      (-6.21, 106.85),  "ID": (-6.21, 106.85),
    "France":         (48.86,   2.35),  "FR": (48.86,   2.35),
    "United Kingdom": (51.51,  -0.13),  "GB": (51.51,  -0.13),
    "Tunisia":        (36.82,  10.18),  "TN": (36.82,  10.18),
    "Morocco":        (33.99,  -6.85),  "MA": (33.99,  -6.85),
}

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background-color: #0d1117; }
[data-testid="stSidebar"]          { background-color: #161b22; }
h1, h2, h3, .stMetric label        { color: #e6edf3 !important; }
.stMetric [data-testid="stMetricValue"] { color: #58a6ff !important; font-size: 2rem !important; }
.alert-card {
    padding: 12px 16px; border-radius: 6px; margin-bottom: 8px;
    border-left: 4px solid; background: #161b22;
}
.kpi-bar { background: #161b22; padding: 10px; border-radius: 8px; text-align:center; }
</style>
""", unsafe_allow_html=True)

# ── API helpers ───────────────────────────────────────────────────────────────
def fetch(endpoint: str, default=None):
    """Fetch JSON from PC1 API; returns default on any failure."""
    try:
        r = requests.get(f"{PC1_BASE_URL}{endpoint}", timeout=4)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default if default is not None else []


# ── Sub-panels ────────────────────────────────────────────────────────────────
def render_risk_gauge(incidents: list):
    """Plotly gauge showing max risk score across active incidents."""
    max_risk = max((i.get("risk_score", 0) for i in incidents), default=0)
    avg_risk = (sum(i.get("risk_score", 0) for i in incidents) // len(incidents)) if incidents else 0
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=max_risk,
        delta={"reference": avg_risk, "valueformat": ".0f"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8b949e"},
            "bar":  {"color": "#e63946"},
            "bgcolor": "#161b22",
            "steps": [
                {"range": [0,  30], "color": "#0d4429"},
                {"range": [30, 60], "color": "#5c3102"},
                {"range": [60, 100], "color": "#4a0010"},
            ],
            "threshold": {
                "line": {"color": "#ff6b6b", "width": 3},
                "thickness": 0.8, "value": max_risk,
            },
        },
        title={"text": "Max Risk Score", "font": {"color": "#8b949e"}},
        number={"font": {"color": "#e6edf3"}},
    ))
    fig.update_layout(
        height=250, margin=dict(t=40, b=0, l=10, r=10),
        paper_bgcolor="#0d1117", font_color="#e6edf3" , font=dict(size=20),
    )
    st.plotly_chart(fig, use_container_width=True)
    c1, c2 = st.columns(2)
    c1.metric("Active Incidents", len(incidents))
    c2.metric("Avg Risk", avg_risk)


def render_compliance_panel(incidents: list):
    """Live compliance breach counts with notification deadlines."""
    fw_counts = {"PCI-DSS": 0, "SWIFT CSP": 0, "GDPR": 0, "BCT": 0}
    breach_rows = []
    for inc in incidents:
        for breach in inc.get("compliance_breaches", []):
            for fw in fw_counts:
                if fw in breach:
                    fw_counts[fw] += 1
            deadline = COMPLIANCE_DEADLINES.get(breach, "—")
            breach_rows.append({
                "Incident":              inc["id"][:8],
                "Severity":              inc.get("severity", "?").upper(),
                "Breach":                breach,
                "Notification Deadline": deadline,
            })

    c1, c2, c3, c4 = st.columns(4)
    for col, (fw, count) in zip([c1, c2, c3, c4], fw_counts.items()):
        label = "GDPR Art.33" if fw == "GDPR" else fw
        col.metric(label, count, delta=("⚠️ ACTIVE" if count > 0 else None))

    if breach_rows:
        df = pd.DataFrame(breach_rows)
        st.dataframe(df, use_container_width=True, height=160,
                     column_config={"Severity": st.column_config.TextColumn(width="small")})
    else:
        st.info("No compliance breaches detected — waiting for incident data.")


def render_world_map(incidents: list):
    """Folium map plotting attack origin geolocations from enriched IOCs."""
    m = folium.Map(
        location=[20, 10], zoom_start=2,
        tiles="CartoDB dark_matter",
    )
    # Collect geolocation hits
    geo_hits: dict[str, int] = {}
    for inc in incidents:
        for ioc in inc.get("iocs", []):
            geo = ioc.get("geolocation")
            if geo:
                geo_hits[geo] = geo_hits.get(geo, 0) + 1

    for country, count in geo_hits.items():
        coords = GEO_COORDS.get(country)
        if coords:
            folium.CircleMarker(
                location=coords,
                radius=min(6 + count * 3, 20),
                color="#e63946", fill=True, fill_color="#e63946", fill_opacity=0.7,
                tooltip=f"{country}: {count} IOC{'s' if count > 1 else ''}",
            ).add_to(m)

    # Always show Banque Atlas (target)
    folium.Marker(
        location=[36.82, 10.18],
        tooltip="🏦 Banque Atlas (Target)",
        icon=folium.Icon(color="blue", icon="bank", prefix="fa"),
    ).add_to(m)

    if not geo_hits:
        st.info("No geolocated IOCs yet — map will populate as enriched data arrives.")

    st_folium(m, width=None, height=320, returned_objects=[])


def render_top_threats(incidents: list):
    """Horizontal bar chart of threat type counts from enriched IOCs."""
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

    colors = ["#e63946" if v == max(tc.values()) else "#58a6ff" for v in tc.values()]
    fig = go.Figure(go.Bar(
        x=list(tc.values()), y=list(tc.keys()),
        orientation="h", marker_color=colors,
        text=list(tc.values()), textposition="outside",
        textfont={"color": "#e6edf3"},
    ))
    fig.update_layout(
        height=250, margin=dict(t=10, b=0, l=10, r=40),
        paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
        xaxis=dict(showgrid=False, color="#8b949e"),
        yaxis=dict(color="#e6edf3"),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_alerts(incidents: list):
    """Color-coded alert cards sorted by severity then time."""
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_incs = sorted(incidents, key=lambda i: SEV_ORDER.get(i.get("severity", "low"), 3))

    if not sorted_incs:
        st.info("No incidents yet — waiting for data from PC1.")
        return

    for inc in sorted_incs[-12:]:
        sev   = inc.get("severity", "low")
        icon  = SEVERITY_ICON.get(sev, "⚪")
        ts    = inc.get("detected_at", "")[:19]
        ioc_count = len(inc.get("iocs", []))
        techniques = ", ".join(inc.get("mitre_techniques", []))
        breaches   = inc.get("compliance_breaches", [])
        apt_tags   = list({
            ioc.get("apt_attribution") for ioc in inc.get("iocs", [])
            if ioc.get("apt_attribution")
        })

        with st.expander(f"{icon} [{sev.upper()}] {inc['id'][:8]}  ·  {ts}  ·  {ioc_count} IOCs"):
            st.markdown(
                inc.get("summary") or "_CISO summary pending — LLM wires in Phase 3._"
            )
            col_a, col_b = st.columns(2)
            if techniques:
                col_a.caption(f"**MITRE:** {techniques}")
            if breaches:
                col_b.caption(f"⚠️ **Compliance:** {', '.join(breaches)}")
            if apt_tags:
                labels = [APT_LABELS.get(a, (a.upper(), "#ff6b6b"))[0] for a in apt_tags]
                st.caption(f"🎯 **APT:** {', '.join(labels)}")


def render_asset_view(incidents: list):
    """3-column asset breakdown: Treasury / Payment Gateway / Customer DB."""
    asset_buckets: dict[str, list] = {
        "treasury": [], "payment_gateway": [], "customer_db": [], "swift_terminal": [],
    }
    for inc in incidents:
        for asset in inc.get("targeted_assets", []):
            if asset in asset_buckets:
                asset_buckets[asset].append(inc)

    col_t, col_pg, col_cdb = st.columns(3)
    for col, asset_key, label in zip(
        [col_t, col_pg, col_cdb],
        ["treasury",    "payment_gateway",    "customer_db"],
        ["🏛 Treasury", "💳 Payment Gateway", "🗄 Customer DB"],
    ):
        with col:
            incs  = asset_buckets[asset_key]
            risks = [i.get("risk_score", 0) for i in incs]
            max_r = max(risks, default=0)
            st.metric(label, f"{len(incs)} incident{'s' if len(incs) != 1 else ''}", delta=f"Max risk {max_r}" if incs else None)
            for inc in sorted(incs, key=lambda i: -i.get("risk_score", 0))[:3]:
                sev = inc.get("severity", "low")
                st.markdown(
                    f"{SEVERITY_ICON.get(sev,'⚪')} `{inc['id'][:8]}` — risk **{inc.get('risk_score',0)}**"
                )
            if not incs:
                st.caption("✅ Clean")

    # Swift terminal as a warning banner if hit
    if asset_buckets["swift_terminal"]:
        st.error(f"🚨 SWIFT Terminal under attack — {len(asset_buckets['swift_terminal'])} incident(s) detected!")


def render_apt_panel(incidents: list):
    """Show which APT groups are active based on IOC attribution."""
    apt_counts: dict[str, int] = {}
    for inc in incidents:
        for ioc in inc.get("iocs", []):
            apt = ioc.get("apt_attribution")
            if apt:
                apt_counts[apt] = apt_counts.get(apt, 0) + 1

    if not apt_counts:
        st.caption("No APT attribution yet.")
        return

    cols = st.columns(len(apt_counts))
    for col, (apt_key, count) in zip(cols, apt_counts.items()):
        label, color = APT_LABELS.get(apt_key, (apt_key.upper(), "#ff6b6b"))
        col.markdown(
            f"<div style='background:{color}22;border:1px solid {color};"
            f"border-radius:6px;padding:8px;text-align:center'>"
            f"<b style='color:{color}'>{label}</b><br>"
            f"<span style='color:#e6edf3;font-size:1.4rem'>{count}</span><br>"
            f"<small style='color:#8b949e'>IOCs</small></div>",
            unsafe_allow_html=True,
        )


# ── Main dashboard (auto-refreshes every 5s) ─────────────────────────────────
@st.fragment(run_every=5)
def dashboard():
    incidents   = fetch("/incidents")
    predictions = fetch("/predictions")
    stats       = fetch("/stats", default={})

    pc1_ok = isinstance(incidents, list)
    badge  = "🟢 PC1 connected" if pc1_ok else "🔴 PC1 unreachable — showing last known state"
    st.caption(f"{badge} | Refresh: {datetime.now().strftime('%H:%M:%S')} | `{PC1_BASE_URL}`")

    # ── KPI bar ──────────────────────────────────────────────────────────────
    if stats:
        k = st.columns(5)
        k[0].metric("Raw Records",    stats.get("raw_count",             len(incidents)))
        k[1].metric("IOCs",           stats.get("ioc_count",             "—"))
        k[2].metric("Incidents",      stats.get("incident_count",        len(incidents)))
        k[3].metric("Predictions",    stats.get("prediction_count",      "—"))
        k[4].metric("Compliance Hits",stats.get("compliance_breach_count","—"))

    st.divider()

    # ── Row 1: Risk Gauge | Compliance Panel ─────────────────────────────────
    col_gauge, col_compliance = st.columns([1, 2])
    with col_gauge:
        st.subheader("🎯 Banking Sector Risk")
        render_risk_gauge(incidents)
    with col_compliance:
        st.subheader("🔒 Compliance Breaches — Live")
        render_compliance_panel(incidents)

    st.divider()

    # ── Row 2: World Map | APT Activity ──────────────────────────────────────
    col_map, col_apt = st.columns([2, 1])
    with col_map:
        st.subheader("🗺 Attack Origins")
        render_world_map(incidents)
    with col_apt:
        st.subheader("🎯 Active APT Groups")
        render_apt_panel(incidents)
        st.divider()
        st.subheader("📊 Top Threats")
        render_top_threats(incidents)

    st.divider()

    # ── Row 3: Live Alerts ───────────────────────────────────────────────────
    st.subheader("⚡ Live Alerts")
    render_alerts(incidents)

    st.divider()

    # ── Row 4: Asset View ────────────────────────────────────────────────────
    st.subheader("🏦 Asset View — Banque Atlas")
    render_asset_view(incidents)

    st.divider()

    # ── Row 5: Predictions ───────────────────────────────────────────────────
    st.subheader("📈 Threat Predictions — 7-Day Forecast")
    if not predictions:
        st.info("Waiting for predictions from PC3 — available from Phase 3.")
    else:
        pred_df = pd.DataFrame(predictions)
        cols_show = [c for c in ["sector","threat_type","forecast_7d","trend","confidence"] if c in pred_df.columns]
        if "trend" in pred_df.columns:
            pred_df["trend"] = pred_df["trend"].apply(lambda t: f"{TREND_ICON.get(t, '')} {t}" if t else "—")
        if "threat_type" in pred_df.columns:
            pred_df["threat_type"] = pred_df["threat_type"].apply(
                lambda t: t.replace("apt:", "APT: ").replace("cve:", "CVE: ").replace("anomaly:", "⚠ ").replace("_", " ") if t else "—"
            )
        if "confidence" in pred_df.columns:
            pred_df["confidence"] = pred_df["confidence"].apply(lambda c: f"{round(c * 100)}%" if c is not None else "—")
        st.dataframe(pred_df[cols_show], use_container_width=True)


# ── Entry point ───────────────────────────────────────────────────────────────
st.title("🏦 Banking Sector Threat Intelligence")
st.caption("Cyberia 2026 · AI-Powered TI Platform · Banque Atlas Demo · Phase 2")
dashboard()
