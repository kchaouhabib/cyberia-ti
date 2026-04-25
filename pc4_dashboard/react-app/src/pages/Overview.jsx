import { motion } from "framer-motion";
import { RadialBarChart, RadialBar, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, AreaChart, Area } from "recharts";
import { Activity, Shield, AlertTriangle, TrendingUp, Database, Zap } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const SEV_COLOR = { critical: "#ff2d55", high: "#ff9f0a", medium: "#ffd60a", low: "#30d158" };
const SEV_LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MED", low: "LOW" };

function RiskGauge({ value }) {
  const color = value >= 60 ? "#ff2d55" : value >= 30 ? "#ff9f0a" : "#30d158";
  const data = [{ value, fill: color }, { value: 100 - value, fill: "#0a1e38" }];
  return (
    <div className="flex flex-col items-center py-2">
      <RadialBarChart width={220} height={130} cx={110} cy={120}
        innerRadius={75} outerRadius={108} startAngle={180} endAngle={0}
        data={data} barSize={20}>
        <RadialBar dataKey="value" cornerRadius={8} />
      </RadialBarChart>
      <motion.div key={value} initial={{ scale: 0.6, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
        className="text-6xl font-black -mt-12" style={{ color, textShadow: `0 0 20px ${color}80` }}>
        {value}
      </motion.div>
      <div className="text-xs text-[#64748b] mt-1 tracking-widest">MAX RISK SCORE</div>
      <div className="flex gap-4 mt-3 text-xs">
        {[["LOW","#30d158","0–30"], ["MED","#ff9f0a","30–60"], ["HIGH","#ff2d55","60–100"]].map(([l,c,r])=>(
          <span key={l} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{background:c}} />
            <span className="text-[#64748b]">{r}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function ThreatsBar({ incidents }) {
  const map = { phishing:"Phishing", malware:"Malware", lateral_movement:"Lateral", exfiltration:"Exfil", c2:"C2" };
  const counts = Object.fromEntries(Object.values(map).map(v => [v, 0]));
  incidents.forEach(inc => inc.iocs?.forEach(ioc => {
    const k = map[ioc.threat_type]; if (k) counts[k]++;
  }));
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 30, top: 4, bottom: 4 }}>
        <XAxis type="number" hide domain={[0, max + 1]} />
        <YAxis type="category" dataKey="name" tick={{ fill: "#64748b", fontSize: 12 }} width={58} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "#ffffff05" }}
          contentStyle={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 8, fontSize: 12, color: "#e8f4f8" }} />
        <Bar dataKey="value" radius={[0, 6, 6, 0]}>
          {data.map((d, i) => <Cell key={i} fill={d.value === max && max > 0 ? "#ff2d55" : "#00d4ff"} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function KpiCard({ label, value, icon: Icon, color = "#00d4ff", delay = 0 }) {
  return (
    <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
      transition={{ delay }} whileHover={{ scale: 1.04, y: -2 }}
      className="grad-border p-4 flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-[#64748b] uppercase tracking-wider">{label}</span>
        <Icon size={16} style={{ color }} />
      </div>
      <motion.div key={value} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="text-3xl font-black" style={{ color, textShadow: `0 0 12px ${color}60` }}>
        {value ?? "—"}
      </motion.div>
    </motion.div>
  );
}

function RecentAlerts({ incidents }) {
  const sev = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...incidents].sort((a, b) => (sev[a.severity] ?? 3) - (sev[b.severity] ?? 3)).slice(0, 6);
  if (!sorted.length) return <p className="text-xs text-[#64748b] text-center py-6">No incidents yet…</p>;
  return (
    <div className="space-y-2">
      {sorted.map((inc, i) => {
        const c = SEV_COLOR[inc.severity] || "#64748b";
        return (
          <motion.div key={inc.id} initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.05 }}
            className="flex items-center gap-3 px-3 py-2 rounded-lg"
            style={{ background: c + "0d", border: `1px solid ${c}25` }}>
            <span className="w-2 h-2 rounded-full blink shrink-0" style={{ background: c }} />
            <span className="text-xs font-bold w-16 shrink-0" style={{ color: c }}>{SEV_LABEL[inc.severity]}</span>
            <span className="text-xs font-mono text-[#64748b]">{inc.id?.slice(0, 8)}</span>
            <span className="text-xs text-[#e8f4f8] flex-1 truncate">{inc.targeted_assets?.join(", ") || "—"}</span>
            <span className="text-xs font-bold" style={{ color: c }}>{inc.risk_score}</span>
          </motion.div>
        );
      })}
    </div>
  );
}

export default function Overview({ incidents, stats }) {
  const maxRisk = Math.max(...incidents.map(i => i.risk_score || 0), 0);
  const complianceHits = incidents.reduce((n, i) => n + (i.compliance_breaches?.length || 0), 0);

  return (
    <div className="space-y-4">
      {/* Critical banner */}
      {maxRisk >= 60 && (
        <motion.div animate={{ scale: [1, 1.01, 1] }} transition={{ repeat: Infinity, duration: 1.8 }}
          className="rounded-xl px-5 py-3 flex items-center gap-3 border border-red-500/50 bg-red-500/10">
          <Zap size={18} className="text-red-400 blink" />
          <span className="text-red-400 font-bold text-sm">🚨 CRITICAL THREAT ACTIVE — Banque Atlas under attack</span>
        </motion.div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-5 gap-3">
        <KpiCard label="Incidents"     value={incidents.length}          icon={AlertTriangle} color="#ff2d55" delay={0} />
        <KpiCard label="IOCs"          value={stats.iocs}                icon={Shield}        color="#00d4ff" delay={0.05} />
        <KpiCard label="Raw Records"   value={stats.raw_records}         icon={Database}      color="#00d4ff" delay={0.1} />
        <KpiCard label="Compliance"    value={complianceHits || stats.compliance_breaches} icon={Shield} color="#ff9f0a" delay={0.15} />
        <KpiCard label="Predictions"   value={stats.predictions}         icon={TrendingUp}    color="#30d158" delay={0.2} />
      </div>

      {/* Row 1 */}
      <div className="grid grid-cols-3 gap-4">
        <Card danger={maxRisk >= 60} delay={0.1}>
          <CardTitle icon={Activity} title="Banking Sector Risk" />
          <RiskGauge value={maxRisk} />
        </Card>
        <Card className="col-span-2" delay={0.15}>
          <CardTitle icon={TrendingUp} title="Top Threats" badge={incidents.length} />
          <ThreatsBar incidents={incidents} />
        </Card>
      </div>

      {/* Row 2 */}
      <Card delay={0.2}>
        <CardTitle icon={AlertTriangle} title="Recent Alerts" badge={incidents.length} />
        <RecentAlerts incidents={incidents} />
      </Card>
    </div>
  );
}
