import { motion } from "framer-motion";
import { RadialBarChart, RadialBar, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Activity, AlertTriangle, TrendingUp, Zap, Grid3X3 } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const SEV  = { critical: "#ff2d78", high: "#ff8c00", medium: "#ffd700", low: "#00ff88" };
const TIPS = { background: "#08091a", border: "1px solid #1c1e38", borderRadius: 6, fontSize: 11, color: "#e2e8f8" };

function KpiCard({ label, value, color = "var(--cyan)", delay = 0, sub }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.88 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay, type: "spring", stiffness: 260, damping: 22 }}
      className="kpi-card"
      style={{ borderTop: `2px solid ${color}` }}
    >
      <div className="section-label mb-2">{label}</div>
      <motion.div
        key={value}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        className="font-orb font-bold tabular-nums"
        style={{ fontSize: 28, color, textShadow: `0 0 16px ${color}80` }}
      >
        {value ?? "—"}
      </motion.div>
      {sub && <div className="mono mt-1" style={{ fontSize: 9, color: "var(--muted)" }}>{sub}</div>}
    </motion.div>
  );
}

function RiskGauge({ value }) {
  const color = value >= 60 ? "#ff2d78" : value >= 30 ? "#ff8c00" : "#00ff88";
  const data  = [{ value, fill: color }, { value: 100 - value, fill: "#0e0f22" }];
  return (
    <div className="flex flex-col items-center">
      <RadialBarChart width={200} height={120} cx={100} cy={115}
        innerRadius={70} outerRadius={100} startAngle={180} endAngle={0} data={data} barSize={18}>
        <RadialBar dataKey="value" cornerRadius={6} />
      </RadialBarChart>
      <motion.div
        key={value}
        initial={{ scale: 0.5, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="font-orb font-black -mt-10"
        style={{ fontSize: 48, color, textShadow: `0 0 24px ${color}80, 0 0 48px ${color}30` }}
      >
        {value}
      </motion.div>
      <div className="section-label mt-2">MAX RISK SCORE</div>
      <div className="flex gap-3 mt-2">
        {[["0-30","#00ff88"],["30-60","#ff8c00"],["60-100","#ff2d78"]].map(([r,c]) => (
          <span key={r} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
            <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>{r}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function ThreatsBar({ incidents }) {
  const map = { phishing: "Phishing", malware: "Malware", lateral_movement: "Lateral", exfiltration: "Exfil", c2: "C2" };
  const counts = Object.fromEntries(Object.values(map).map(v => [v, 0]));
  incidents.forEach(inc => inc.iocs?.forEach(ioc => { const k = map[ioc.threat_type]; if (k) counts[k]++; }));
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
  const max  = Math.max(...data.map(d => d.value), 1);
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 36, top: 4, bottom: 4 }}>
        <XAxis type="number" hide domain={[0, max + 1]} />
        <YAxis type="category" dataKey="name" tick={{ fill: "#4a5280", fontSize: 11, fontFamily: "Share Tech Mono" }} width={58} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "rgba(0,212,255,0.04)" }} contentStyle={TIPS} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]}
          fill="#00d4ff"
          label={{ position: "right", fill: "#4a5280", fontSize: 10 }}
        />
      </BarChart>
    </ResponsiveContainer>
  );
}

function RecentAlerts({ incidents }) {
  const sorted = [...incidents]
    .sort((a, b) => ({ critical:0,high:1,medium:2,low:3 }[a.severity]??3) - ({ critical:0,high:1,medium:2,low:3 }[b.severity]??3))
    .slice(0, 9);
  if (!sorted.length)
    return <p className="mono text-center py-8" style={{ color: "var(--muted)", fontSize: 11 }}>NO INCIDENTS — SYSTEM CLEAN</p>;
  return (
    <div>
      <div className="soc-row section-label" style={{ gridTemplateColumns: "80px 100px 1fr 70px 54px", color: "var(--dim)" }}>
        <span>SEVERITY</span><span>INCIDENT ID</span><span>ASSETS / MITRE</span><span>DETECTED</span><span className="text-right">SCORE</span>
      </div>
      {sorted.map((inc, i) => {
        const c = SEV[inc.severity] || "#4a5280";
        return (
          <motion.div
            key={inc.id}
            initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.04 }}
            className={`soc-row row-${inc.severity}`}
            style={{ gridTemplateColumns: "80px 100px 1fr 70px 54px" }}
          >
            <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
            <span className="mono" style={{ color: "var(--muted)", fontSize: 10 }}>{inc.id?.slice(0, 10)}</span>
            <span style={{ color: "var(--text)", fontSize: 11 }} className="truncate">
              {inc.targeted_assets?.join(", ") || inc.mitre_techniques?.slice(0, 2).join(" · ") || "—"}
            </span>
            <span className="mono" style={{ color: "var(--muted)", fontSize: 10 }}>{inc.detected_at?.slice(11, 19)}</span>
            <span className="mono tabular-nums text-right font-bold" style={{ color: c }}>{inc.risk_score}</span>
          </motion.div>
        );
      })}
    </div>
  );
}

const MITRE_TECHNIQUES = [
  { id: "T1566", name: "Phishing" },
  { id: "T1078", name: "Valid Accounts" },
  { id: "T1190", name: "Exploit App" },
  { id: "T1539", name: "Session Hijack" },
  { id: "T1041", name: "Exfiltration" },
  { id: "T1071", name: "C2 Protocol" },
  { id: "T1486", name: "Ransomware" },
];
const HEATMAP_VECTORS = [
  { key: "phishing",         label: "Phishing" },
  { key: "exfiltration",     label: "Exfil" },
  { key: "lateral_movement", label: "Lateral" },
  { key: "malware",          label: "Malware" },
  { key: "c2",               label: "C2" },
];

function cellColor(val, max) {
  if (val === 0) return null;
  const r = val / max;
  if (r < 0.34) return "#ff8c00";
  if (r < 0.67) return "#ff5c00";
  return "#ff2d78";
}

function MitreHeatmap({ incidents }) {
  const matrix = Object.fromEntries(
    MITRE_TECHNIQUES.map(t => [t.id, Object.fromEntries(HEATMAP_VECTORS.map(v => [v.key, 0]))])
  );
  incidents.forEach(inc => {
    const iocTypes = new Set((inc.iocs || []).map(i => i.threat_type).filter(Boolean));
    (inc.mitre_techniques || []).forEach(tech => {
      if (matrix[tech]) iocTypes.forEach(tt => { if (matrix[tech][tt] !== undefined) matrix[tech][tt]++; });
    });
  });
  const maxVal = Math.max(...MITRE_TECHNIQUES.flatMap(t => HEATMAP_VECTORS.map(v => matrix[t.id][v.key])), 1);

  return (
    <div>
      <div className="grid gap-1.5 mb-1.5" style={{ gridTemplateColumns: "120px repeat(5, 1fr)" }}>
        <div />
        {HEATMAP_VECTORS.map(v => (
          <div key={v.key} className="section-label text-center pb-1">{v.label}</div>
        ))}
      </div>
      {MITRE_TECHNIQUES.map((t, ti) => (
        <div key={t.id} className="grid gap-1.5 mb-1.5" style={{ gridTemplateColumns: "120px repeat(5, 1fr)" }}>
          <div className="flex items-center gap-1.5">
            <span className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>{t.id}</span>
            <span className="section-label truncate">{t.name}</span>
          </div>
          {HEATMAP_VECTORS.map((v, vi) => {
            const val = matrix[t.id][v.key];
            const c   = cellColor(val, maxVal);
            return (
              <motion.div key={v.key}
                initial={{ opacity: 0, scale: 0.6 }} animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: (ti * 5 + vi) * 0.01 }}
                title={`${t.id} × ${v.label}: ${val}`}
                className="rounded h-9 flex items-center justify-center font-orb font-black cursor-default"
                style={{
                  fontSize: 13,
                  background: c ? `${c}18` : "var(--bg-row)",
                  border: `1px solid ${c ? `${c}40` : "var(--border)"}`,
                  color: c || "var(--dim)",
                  boxShadow: c ? `0 0 12px ${c}30` : "none",
                }}>
                {val > 0 ? val : "·"}
              </motion.div>
            );
          })}
        </div>
      ))}
      <div className="flex items-center gap-4 mt-3">
        <span className="section-label">FREQUENCY</span>
        {[["none","var(--border)"],["low","#ff8c00"],["med","#ff5c00"],["high","#ff2d78"]].map(([l,c]) => (
          <span key={l} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm" style={{ background: `${c}25`, border: `1px solid ${c}60` }} />
            <span className="section-label">{l}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Overview({ incidents, stats }) {
  const maxRisk       = Math.max(...incidents.map(i => i.risk_score || 0), 0);
  const compBreaches  = incidents.reduce((n, i) => n + (i.compliance_breaches?.length || 0), 0);
  const criticalCount = incidents.filter(i => i.severity === "critical").length;

  return (
    <div className="space-y-4">
      {/* Critical banner */}
      {maxRisk >= 60 && (
        <motion.div
          animate={{ opacity: [1, 0.7, 1] }}
          transition={{ repeat: Infinity, duration: 1.6 }}
          className="rounded-lg px-5 py-3 flex items-center gap-3"
          style={{ background: "rgba(255,45,120,0.08)", border: "1px solid var(--critical-b)", boxShadow: "0 0 24px rgba(255,45,120,0.12)" }}>
          <Zap size={16} style={{ color: "var(--critical)" }} className="blink" />
          <span className="font-orb font-bold" style={{ fontSize: 11, color: "var(--critical)", letterSpacing: "0.12em" }}>
            CRITICAL THREAT ACTIVE — BANQUE ATLAS UNDER ATTACK
          </span>
        </motion.div>
      )}

      {/* KPI bar */}
      <div className="grid grid-cols-5 gap-3">
        <KpiCard label="TOTAL INCIDENTS"   value={incidents.length}     color="var(--critical)" delay={0} />
        <KpiCard label="CRITICAL"          value={criticalCount}        color="var(--critical)" delay={0.04} sub={`${incidents.filter(i=>i.severity==="high").length} HIGH`} />
        <KpiCard label="IOCs DETECTED"     value={stats.iocs}           color="var(--cyan)"     delay={0.08} />
        <KpiCard label="COMPLIANCE HITS"   value={compBreaches || stats.compliance_breaches} color="var(--high)" delay={0.12} />
        <KpiCard label="PREDICTIONS"       value={stats.predictions}    color="var(--green)"    delay={0.16} />
      </div>

      {/* Row 1: gauge + threat bars */}
      <div className="grid grid-cols-3 gap-4">
        <Card danger={maxRisk >= 60} delay={0.1}>
          <CardTitle icon={Activity} title="BANKING SECTOR RISK" />
          <RiskGauge value={maxRisk} />
        </Card>
        <Card className="col-span-2" delay={0.14}>
          <CardTitle icon={TrendingUp} title="TOP THREATS" badge={incidents.length} />
          <ThreatsBar incidents={incidents} />
        </Card>
      </div>

      {/* Row 2: Recent alerts table */}
      <Card delay={0.18}>
        <CardTitle icon={AlertTriangle} title="LIVE THREAT FEED" badge={incidents.length} />
        <RecentAlerts incidents={incidents} />
      </Card>

      {/* Row 3: MITRE heatmap */}
      <Card delay={0.22}>
        <CardTitle icon={Grid3X3} title="MITRE ATT&CK COVERAGE MATRIX" badge="7 TECHNIQUES × 5 VECTORS" />
        <MitreHeatmap incidents={incidents} />
      </Card>
    </div>
  );
}
