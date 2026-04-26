import { motion } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const TREND_COLOR = { rising: "#ff2d78", stable: "#00d4ff", falling: "#00ff88" };
const TREND_ICON  = { rising: TrendingUp, stable: Minus, falling: TrendingDown };
const CHART_CLR   = ["#ff2d78", "#ff8c00", "#ffd700", "#00d4ff", "#00ff88", "#8b5cf6"];
const TIPS        = { background: "#08091a", border: "1px solid #1c1e38", borderRadius: 6, fontSize: 11, color: "#e2e8f8" };

function PredictionCard({ p, delay }) {
  const c    = TREND_COLOR[p.trend] || "#00d4ff";
  const Icon = TREND_ICON[p.trend]  || Minus;
  const conf = Math.round((p.confidence || 0) * 100);

  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, type: "spring", stiffness: 250, damping: 22 }}
      className="card p-4"
      style={{ borderTop: `2px solid ${c}` }}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="section-label mb-1">{p.sector}</div>
          <div className="font-orb font-bold capitalize" style={{ fontSize: 11, color: "var(--text)", letterSpacing: "0.06em" }}>
            {p.threat_type?.replace("apt:", "APT: ").replace(/_/g, " ").replace(/-/g, " ")}
          </div>
        </div>
        <div className="p-2 rounded" style={{ background: `${c}14`, border: `1px solid ${c}35` }}>
          <Icon size={14} style={{ color: c }} />
        </div>
      </div>

      <div className="flex items-end gap-2 mb-4">
        <motion.div
          key={p.forecast_7d}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          className="font-orb font-black tabular-nums"
          style={{ fontSize: 36, color: c, textShadow: `0 0 16px ${c}70` }}
        >
          {p.forecast_7d?.toFixed(0)}
        </motion.div>
        <div className="section-label pb-1">ATTACKS / 7 DAYS</div>
      </div>

      <div className="flex items-center justify-between">
        <span className="font-orb font-bold" style={{ fontSize: 9, color: c, letterSpacing: "0.12em" }}>
          {p.trend?.toUpperCase()}
        </span>
        <div className="flex items-center gap-2">
          <div className="prog-track" style={{ width: 56 }}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${conf}%` }}
              transition={{ delay: delay + 0.3, duration: 0.9 }}
              className="prog-bar"
              style={{ background: c, boxShadow: `0 0 6px ${c}60` }}
            />
          </div>
          <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>{conf}%</span>
        </div>
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
          <p className="font-orb font-bold" style={{ fontSize: 12, color: "var(--muted)", letterSpacing: "0.14em" }}>
            AWAITING PREDICTIONS
          </p>
          <p className="mono mt-2" style={{ fontSize: 10, color: "var(--dim)" }}>
            PC3 Prophet forecasting — live incident data required
          </p>
        </div>
      </div>
    );
  }

  const sectors = [...new Set(predictions.map(p => p.sector))];
  const types   = [...new Set(predictions.map(p => p.threat_type))];
  const chartData = sectors.map(s => {
    const row = { sector: s };
    predictions.filter(p => p.sector === s).forEach(p => { row[p.threat_type] = p.forecast_7d; });
    return row;
  });

  return (
    <div className="space-y-4">
      {/* Cards */}
      <div className="grid grid-cols-3 gap-3">
        {predictions.map((p, i) => <PredictionCard key={i} p={p} delay={i * 0.06} />)}
      </div>

      {/* Bar chart */}
      {chartData.length > 0 && (
        <Card delay={0.25}>
          <CardTitle icon={TrendingUp} title="7-DAY FORECAST BY SECTOR" />
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData} margin={{ left: 0, right: 20, top: 8, bottom: 0 }}>
              <XAxis dataKey="sector" tick={{ fill: "#4a5280", fontSize: 11, fontFamily: "Share Tech Mono" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#4a5280", fontSize: 10, fontFamily: "Share Tech Mono" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TIPS} />
              {types.map((t, i) => (
                <Bar key={t} dataKey={t} fill={CHART_CLR[i % CHART_CLR.length]} radius={[3, 3, 0, 0]} stackId="a"
                  style={{ filter: `drop-shadow(0 0 4px ${CHART_CLR[i % CHART_CLR.length]}60)` }} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      {/* Rising threats area charts */}
      {predictions.filter(p => p.trend === "rising").length > 0 && (
        <Card delay={0.35}>
          <CardTitle icon={TrendingUp} title="RISING THREATS — FORECAST TREND" color="var(--critical)" />
          <div className="space-y-4">
            {predictions.filter(p => p.trend === "rising").map((p, i) => {
              const history = [0.55, 0.65, 0.75, 0.82, 0.9, 1.0].map((m, d) => ({
                day: `D-${5 - d}`, value: Math.round(p.forecast_7d * m * 0.6),
              }));
              history.push({ day: "Now", value: Math.round(p.forecast_7d * 0.8) });
              history.push({ day: "+7d", value: Math.round(p.forecast_7d) });

              return (
                <div key={i}>
                  <div className="section-label mb-2">
                    {p.sector} — {p.threat_type?.replace("_", " ")}
                  </div>
                  <ResponsiveContainer width="100%" height={80}>
                    <AreaChart data={history} margin={{ left: 0, right: 0, top: 4, bottom: 0 }}>
                      <defs>
                        <linearGradient id={`g-${i}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="#ff2d78" stopOpacity={0.5} />
                          <stop offset="95%" stopColor="#ff2d78" stopOpacity={0}   />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="day" tick={{ fill: "#4a5280", fontSize: 9, fontFamily: "Share Tech Mono" }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={TIPS} />
                      <Area type="monotone" dataKey="value" stroke="#ff2d78" fill={`url(#g-${i})`} strokeWidth={1.5} dot={false}
                        style={{ filter: "drop-shadow(0 0 4px rgba(255,45,120,0.5))" }} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}
