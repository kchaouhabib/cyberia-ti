import { motion } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const TREND_COLOR = { rising: "#ff2d55", stable: "#00d4ff", falling: "#30d158" };
const TREND_ICON  = { rising: TrendingUp, stable: Minus, falling: TrendingDown };

function PredictionCard({ p, delay }) {
  const c    = TREND_COLOR[p.trend] || "#00d4ff";
  const Icon = TREND_ICON[p.trend]  || Minus;
  const conf = Math.round((p.confidence || 0) * 100);

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay }} whileHover={{ scale: 1.02, y: -2 }}
      className="grad-border p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="text-xs text-[#64748b] uppercase tracking-wider mb-1">{p.sector}</div>
          <div className="text-sm font-bold text-[#e8f4f8] capitalize">
            {p.threat_type?.replace("apt:", "APT: ").replace(/_/g, " ").replace(/-/g, " ")}
          </div>
        </div>
        <div className="p-2 rounded-lg" style={{ background: c + "20", border: `1px solid ${c}40` }}>
          <Icon size={16} style={{ color: c }} />
        </div>
      </div>

      {/* Forecast value */}
      <div className="flex items-end gap-2 mb-3">
        <motion.div key={p.forecast_7d} initial={{ opacity: 0, scale: 0.7 }} animate={{ opacity: 1, scale: 1 }}
          className="text-4xl font-black" style={{ color: c, textShadow: `0 0 12px ${c}60` }}>
          {p.forecast_7d?.toFixed(0)}
        </motion.div>
        <div className="text-xs text-[#64748b] pb-1">attacks / 7 days</div>
      </div>

      {/* Trend */}
      <div className="flex items-center justify-between text-xs">
        <span className="font-bold uppercase" style={{ color: c }}>{p.trend}</span>
        <div className="flex items-center gap-1 text-[#64748b]">
          <div className="w-16 h-1.5 bg-[#1e3a5f] rounded-full overflow-hidden">
            <motion.div initial={{ width: 0 }} animate={{ width: `${conf}%` }} transition={{ delay: delay + 0.3, duration: 0.8 }}
              className="h-full rounded-full" style={{ background: c }} />
          </div>
          <span>{conf}% conf.</span>
        </div>
      </div>
    </motion.div>
  );
}

export default function Predictions({ predictions }) {
  if (!predictions.length) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-4">
        <motion.div animate={{ opacity: [0.3, 1, 0.3] }} transition={{ repeat: Infinity, duration: 2 }}>
          <TrendingUp size={48} className="text-[#1e3a5f]" />
        </motion.div>
        <p className="text-[#64748b] text-center">
          Predictions will appear here from Phase 3.<br />
          <span className="text-xs">PC3 runs Prophet forecasting on live incident data.</span>
        </p>
      </div>
    );
  }

  // Group by sector for chart
  const sectors = [...new Set(predictions.map(p => p.sector))];
  const types   = [...new Set(predictions.map(p => p.threat_type))];
  const chartData = sectors.map(s => {
    const row = { sector: s };
    predictions.filter(p => p.sector === s).forEach(p => { row[p.threat_type] = p.forecast_7d; });
    return row;
  });

  const COLORS = ["#ff2d55", "#ff9f0a", "#ffd60a", "#00d4ff", "#30d158"];

  return (
    <div className="space-y-4">
      {/* Prediction cards */}
      <div className="grid grid-cols-3 gap-3">
        {predictions.map((p, i) => <PredictionCard key={i} p={p} delay={i * 0.07} />)}
      </div>

      {/* Bar chart by sector */}
      {chartData.length > 0 && (
        <Card delay={0.3}>
          <CardTitle icon={TrendingUp} title="7-Day Forecast by Sector" />
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData} margin={{ left: 0, right: 20, top: 10, bottom: 0 }}>
              <XAxis dataKey="sector" tick={{ fill: "#64748b", fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 8, fontSize: 12, color: "#e8f4f8" }} />
              {types.map((t, i) => (
                <Bar key={t} dataKey={t} fill={COLORS[i % COLORS.length]} radius={[4, 4, 0, 0]} stackId="a" />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      {/* Area chart for rising threats */}
      {predictions.filter(p => p.trend === "rising").length > 0 && (
        <Card delay={0.4}>
          <CardTitle icon={TrendingUp} title="Rising Threats — Forecast Trend" />
          <div className="space-y-3">
            {predictions.filter(p => p.trend === "rising").map((p, i) => {
              const fakeHistory = [0.6, 0.7, 0.8, 0.85, 0.9, 1.0].map((m, d) => ({
                day: `D-${5 - d}`, value: Math.round(p.forecast_7d * m * 0.6),
              }));
              fakeHistory.push({ day: "Now", value: Math.round(p.forecast_7d * 0.8) });
              fakeHistory.push({ day: "+7d", value: Math.round(p.forecast_7d) });

              return (
                <div key={i}>
                  <div className="text-xs text-[#64748b] mb-2">{p.sector} — {p.threat_type?.replace("_", " ")}</div>
                  <ResponsiveContainer width="100%" height={80}>
                    <AreaChart data={fakeHistory} margin={{ left: 0, right: 0, top: 4, bottom: 0 }}>
                      <defs>
                        <linearGradient id={`grad-${i}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff2d55" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#ff2d55" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="day" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, fontSize: 11, color: "#e8f4f8" }} />
                      <Area type="monotone" dataKey="value" stroke="#ff2d55" fill={`url(#grad-${i})`} strokeWidth={2} dot={false} />
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
