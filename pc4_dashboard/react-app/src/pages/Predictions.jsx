import { motion } from "framer-motion";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { TrendingUp, TrendingDown, Minus, Shield, AlertTriangle, Activity, Cpu } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const TREND_COLOR = { rising: "#ff2d78", stable: "#00d4ff", falling: "#00ff88" };
const TREND_ICON  = { rising: TrendingUp, stable: Minus, falling: TrendingDown };
const CHART_CLR   = ["#ff2d78", "#ff8c00", "#ffd700", "#00d4ff", "#00ff88", "#8b5cf6"];
const TIPS        = { background: "#08091a", border: "1px solid #1c1e38", borderRadius: 6, fontSize: 11, color: "#e2e8f8" };

function classifyPrediction(p) {
  const t = p.threat_type || "";
  if (t.startsWith("apt:"))     return "apt";
  if (t.startsWith("cve:"))     return "cve";
  if (t.startsWith("anomaly:")) return "anomaly";
  return "volume";
}

/* ── Volume forecast card (bare threat_type) ── */
function VolumeCard({ p, delay }) {
  const c    = TREND_COLOR[p.trend] || "#00d4ff";
  const Icon = TREND_ICON[p.trend]  || Minus;
  const conf = Math.round((p.confidence || 0) * 100);
  return (
    <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, type: "spring", stiffness: 250, damping: 22 }}
      className="card p-4" style={{ borderTop: `2px solid ${c}` }}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="section-label mb-1">{p.sector}</div>
          <div className="font-orb font-bold capitalize" style={{ fontSize: 11, color: "var(--text)", letterSpacing: "0.06em" }}>
            {p.threat_type?.replace(/_/g, " ")}
          </div>
        </div>
        <div className="p-2 rounded" style={{ background: `${c}14`, border: `1px solid ${c}35` }}>
          <Icon size={14} style={{ color: c }} />
        </div>
      </div>
      <div className="flex items-end gap-2 mb-4">
        <motion.div key={p.forecast_7d} initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }}
          className="font-orb font-black tabular-nums"
          style={{ fontSize: 36, color: c, textShadow: `0 0 16px ${c}70` }}>
          {p.forecast_7d?.toFixed(0)}
        </motion.div>
        <div className="section-label pb-1">ATTACKS / 7D</div>
      </div>
      <div className="flex items-center justify-between">
        <span className="font-orb font-bold" style={{ fontSize: 9, color: c, letterSpacing: "0.12em" }}>{p.trend?.toUpperCase()}</span>
        <div className="flex items-center gap-2">
          <div className="prog-track" style={{ width: 56 }}>
            <motion.div initial={{ width: 0 }} animate={{ width: `${conf}%` }}
              transition={{ delay: delay + 0.3, duration: 0.9 }}
              className="prog-bar" style={{ background: c, boxShadow: `0 0 6px ${c}60` }} />
          </div>
          <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>{conf}%</span>
        </div>
      </div>
    </motion.div>
  );
}

/* ── CVE patch priority card ── */
function CveCard({ p, delay }) {
  const priority = Math.round(p.forecast_7d ?? 0);
  const c = priority >= 70 ? "#ff2d78" : priority >= 40 ? "#ff8c00" : "#ffd700";
  const cveId = p.threat_type.replace("cve:", "").toUpperCase();
  return (
    <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, type: "spring", stiffness: 250, damping: 22 }}
      className="card p-4" style={{ borderTop: `2px solid ${c}`, borderLeft: `1px solid ${c}40` }}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="section-label mb-1">PATCH PRIORITY · {p.sector}</div>
          <div className="font-orb font-bold" style={{ fontSize: 12, color: c, letterSpacing: "0.1em" }}>{cveId}</div>
        </div>
        <div className="p-2 rounded" style={{ background: `${c}14`, border: `1px solid ${c}35` }}>
          <Shield size={14} style={{ color: c }} />
        </div>
      </div>
      <div className="flex items-end gap-2 mb-3">
        <motion.div key={priority} initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }}
          className="font-orb font-black tabular-nums"
          style={{ fontSize: 36, color: c, textShadow: `0 0 16px ${c}70` }}>
          {priority}
        </motion.div>
        <div className="section-label pb-1">/ 100 PRIORITY</div>
      </div>
      <div className="prog-track mb-1">
        <motion.div initial={{ width: 0 }} animate={{ width: `${priority}%` }}
          transition={{ delay: delay + 0.3, duration: 0.9 }}
          className="prog-bar" style={{ background: c, boxShadow: `0 0 8px ${c}60` }} />
      </div>
      <div className="section-label mt-1" style={{ color: c }}>PATCH IMMEDIATELY — ACTIVE EXPLOITATION RISK</div>
    </motion.div>
  );
}

/* ── APT campaign card ── */
function AptCard({ p, delay }) {
  const name  = p.threat_type.replace("apt:", "").replace(/-/g, " ").replace(/_/g, " ");
  const known = ["fin7","lazarus","carbanak","silence","cobalt group"].includes(name.toLowerCase());
  const conf  = Math.round((p.confidence || 0) * 100);
  const c     = "#ff2d78";
  return (
    <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, type: "spring", stiffness: 250, damping: 22 }}
      className="card p-4" style={{ borderTop: `2px solid ${c}`, boxShadow: `0 0 20px rgba(255,45,120,0.08)` }}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="section-label mb-1">APT CAMPAIGN · {p.sector}</div>
          <div className="font-orb font-bold uppercase" style={{ fontSize: 13, color: c, letterSpacing: "0.1em", textShadow: `0 0 12px ${c}60` }}>
            {name}
          </div>
        </div>
        <div className="p-2 rounded" style={{ background: `${c}14`, border: `1px solid ${c}35` }}>
          <AlertTriangle size={14} style={{ color: c }} />
        </div>
      </div>
      <div className="flex items-end gap-2 mb-3">
        <motion.div key={p.forecast_7d} initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }}
          className="font-orb font-black tabular-nums"
          style={{ fontSize: 36, color: c, textShadow: `0 0 16px ${c}70` }}>
          {p.forecast_7d?.toFixed(0)}
        </motion.div>
        <div className="section-label pb-1">PROJECTED ATTACKS</div>
      </div>
      <div className="flex items-center justify-between">
        {known
          ? <span className="font-orb font-bold" style={{ fontSize: 9, color: c, letterSpacing: "0.1em" }}>⚠ KNOWN FINANCIAL APT</span>
          : <span className="section-label">EMERGING CLUSTER</span>
        }
        <div className="flex items-center gap-2">
          <div className="prog-track" style={{ width: 56 }}>
            <motion.div initial={{ width: 0 }} animate={{ width: `${conf}%` }}
              transition={{ delay: delay + 0.3, duration: 0.9 }}
              className="prog-bar" style={{ background: c }} />
          </div>
          <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>{conf}%</span>
        </div>
      </div>
    </motion.div>
  );
}

/* ── Anomaly card ── */
function AnomalyCard({ p, delay }) {
  const source = p.threat_type.replace("anomaly:", "");
  const conf   = Math.round((p.confidence || 0) * 100);
  const c      = "#ffd700";
  return (
    <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, type: "spring", stiffness: 250, damping: 22 }}
      className="card p-4" style={{ borderTop: `2px solid ${c}` }}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="section-label mb-1">ANOMALY DETECTED · {p.sector || "UNKNOWN"}</div>
          <div className="font-orb font-bold uppercase" style={{ fontSize: 11, color: c, letterSpacing: "0.08em" }}>
            {source}
          </div>
        </div>
        <div className="p-2 rounded" style={{ background: `${c}14`, border: `1px solid ${c}35` }}>
          <Cpu size={14} style={{ color: c }} />
        </div>
      </div>
      <div className="flex items-end gap-2 mb-3">
        <motion.div key={p.forecast_7d} initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }}
          className="font-orb font-black tabular-nums"
          style={{ fontSize: 36, color: c, textShadow: `0 0 16px ${c}70` }}>
          {p.forecast_7d?.toFixed(0)}
        </motion.div>
        <div className="section-label pb-1">ANOMALY SCORE</div>
      </div>
      <div className="flex items-center justify-between">
        <span className="section-label">ISOLATION FOREST</span>
        <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>{conf}% CONF</span>
      </div>
    </motion.div>
  );
}


export default function Predictions({ predictions }) {
  if (!predictions.length) {
    return (
      <div className="flex flex-col items-center justify-center h-80 gap-6">
        <motion.div animate={{ opacity: [0.2, 0.7, 0.2] }} transition={{ repeat: Infinity, duration: 2.4 }}>
          <TrendingUp size={48} style={{ color: "var(--dim)" }} />
        </motion.div>
        <div className="text-center">
          <p className="font-orb font-bold" style={{ fontSize: 12, color: "var(--muted)", letterSpacing: "0.14em" }}>AWAITING PREDICTIONS</p>
          <p className="mono mt-2" style={{ fontSize: 10, color: "var(--dim)" }}>PC3 Prophet forecasting — live incident data required</p>
        </div>
      </div>
    );
  }

  const byKind = { volume: [], apt: [], cve: [], anomaly: [] };
  predictions.forEach(p => byKind[classifyPrediction(p)].push(p));

  /* Chart only for volume predictions */
  const sectors  = [...new Set(byKind.volume.map(p => p.sector))];
  const types    = [...new Set(byKind.volume.map(p => p.threat_type))];
  const chartData = sectors.map(s => {
    const row = { sector: s };
    byKind.volume.filter(p => p.sector === s).forEach(p => { row[p.threat_type] = p.forecast_7d; });
    return row;
  });

  return (
    <div className="space-y-5">
      {/* APT campaigns */}
      {byKind.apt.length > 0 && (
        <div>
          <div className="section-label mb-3 flex items-center gap-2">
            <AlertTriangle size={9} style={{ color: "var(--critical)" }} />
            APT CAMPAIGNS DETECTED ({byKind.apt.length})
          </div>
          <div className="grid grid-cols-3 gap-3">
            {byKind.apt.map((p, i) => <AptCard key={i} p={p} delay={i * 0.05} />)}
          </div>
        </div>
      )}

      {/* CVE patches */}
      {byKind.cve.length > 0 && (
        <div>
          <div className="section-label mb-3 flex items-center gap-2">
            <Shield size={9} style={{ color: "var(--high)" }} />
            CRITICAL PATCH PRIORITIES ({byKind.cve.length})
          </div>
          <div className="grid grid-cols-3 gap-3">
            {byKind.cve.map((p, i) => <CveCard key={i} p={p} delay={i * 0.05} />)}
          </div>
        </div>
      )}

      {/* Volume forecasts */}
      {byKind.volume.length > 0 && (
        <div>
          <div className="section-label mb-3 flex items-center gap-2">
            <TrendingUp size={9} style={{ color: "var(--cyan)" }} />
            7-DAY VOLUME FORECASTS ({byKind.volume.length})
          </div>
          <div className="grid grid-cols-3 gap-3">
            {byKind.volume.map((p, i) => <VolumeCard key={i} p={p} delay={i * 0.05} />)}
          </div>
        </div>
      )}

      {/* Anomalies */}
      {byKind.anomaly.length > 0 && (
        <div>
          <div className="section-label mb-3 flex items-center gap-2">
            <Activity size={9} style={{ color: "var(--medium)" }} />
            ANOMALIES ({byKind.anomaly.length})
          </div>
          <div className="grid grid-cols-3 gap-3">
            {byKind.anomaly.map((p, i) => <AnomalyCard key={i} p={p} delay={i * 0.05} />)}
          </div>
        </div>
      )}

      {/* Bar chart */}
      {chartData.length > 0 && (
        <Card delay={0.3}>
          <CardTitle icon={TrendingUp} title="7-DAY VOLUME FORECAST BY SECTOR" />
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData} margin={{ left: 0, right: 20, top: 8, bottom: 0 }}>
              <XAxis dataKey="sector" tick={{ fill: "#4a5280", fontSize: 11, fontFamily: "Share Tech Mono" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#4a5280", fontSize: 10, fontFamily: "Share Tech Mono" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TIPS} />
              {types.map((t, i) => (
                <Bar key={t} dataKey={t} fill={CHART_CLR[i % CHART_CLR.length]} radius={[3, 3, 0, 0]} stackId="a" />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}
    </div>
  );
}
