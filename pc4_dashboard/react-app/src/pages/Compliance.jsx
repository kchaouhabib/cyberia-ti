import { motion } from "framer-motion";
import { Shield, Clock, AlertOctagon } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const FRAMEWORKS = [
  { key: "PCI-DSS",    label: "PCI-DSS",      color: "#00d4ff", desc: "Payment Card Industry Data Security Standard" },
  { key: "SWIFT CSP",  label: "SWIFT CSP",     color: "#ff9f0a", desc: "SWIFT Customer Security Programme (CSCF 2.x)" },
  { key: "GDPR",       label: "GDPR Art.33",   color: "#ff2d55", desc: "General Data Protection Regulation — 72h notification" },
  { key: "BCT",        label: "BCT Circular",  color: "#bf5af2", desc: "Banque Centrale de Tunisie — Cybersecurity Circular" },
  { key: "Basel III",  label: "Basel III ORR", color: "#30d158", desc: "Operational Risk & Resilience framework" },
];

const DEADLINES = {
  "PCI-DSS Req.3":       { text: "Per acquirer contract",    urgency: "medium" },
  "PCI-DSS Req.10":      { text: "Audit cycle",              urgency: "low" },
  "PCI-DSS Req.11":      { text: "Audit cycle",              urgency: "low" },
  "SWIFT CSP CSCF 2.x":  { text: "24 hours → SWIFT",         urgency: "critical" },
  "GDPR Art.33":          { text: "72 hours → regulator",     urgency: "high" },
  "Basel III ORR":        { text: "Per local implementation", urgency: "medium" },
  "BCT Circular":         { text: "Per local circular",       urgency: "medium" },
};

const URGENCY_COLOR = { critical: "#ff2d55", high: "#ff9f0a", medium: "#ffd60a", low: "#30d158" };

export default function Compliance({ incidents }) {
  const breachRows = [];
  incidents.forEach(inc =>
    inc.compliance_breaches?.forEach(b =>
      breachRows.push({ ...DEADLINES[b], breach: b, incId: inc.id?.slice(0, 8), sev: inc.severity, risk: inc.risk_score })
    )
  );

  const counts = Object.fromEntries(
    FRAMEWORKS.map(fw => [fw.key, incidents.filter(i =>
      i.compliance_breaches?.some(b => b.includes(fw.key))
    ).length])
  );

  const total = Object.values(counts).reduce((s, n) => s + n, 0);

  return (
    <div className="space-y-4">
      {/* Summary header */}
      <Card danger={total > 0} delay={0}>
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20">
            <AlertOctagon size={24} className="text-red-400" />
          </div>
          <div>
            <div className="text-2xl font-black neon-red">{total} Active Breach{total !== 1 ? "es" : ""}</div>
            <div className="text-xs text-[#64748b] mt-0.5">Across {FRAMEWORKS.length} regulatory frameworks</div>
          </div>
          {total === 0 && (
            <div className="ml-auto text-green-400 font-semibold text-sm">✓ All frameworks clear</div>
          )}
        </div>
      </Card>

      {/* Framework cards */}
      <div className="grid grid-cols-5 gap-3">
        {FRAMEWORKS.map(({ key, label, color, desc }, i) => {
          const n = counts[key] || 0;
          return (
            <motion.div key={key} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.07 }} whileHover={{ scale: 1.03, y: -2 }}
              className={`grad-border p-4 text-center ${n > 0 ? "glow-red" : ""}`}>
              <div className="text-xs text-[#64748b] mb-2">{label}</div>
              <motion.div key={n} initial={{ scale: 0.5 }} animate={{ scale: 1 }}
                className="text-4xl font-black mb-1"
                style={{ color: n > 0 ? "#ff2d55" : color, textShadow: n > 0 ? "0 0 16px #ff2d5580" : `0 0 8px ${color}40` }}>
                {n}
              </motion.div>
              <div className="text-xs text-[#64748b]">incident{n !== 1 ? "s" : ""}</div>
              <div className="text-xs text-[#1e3a5f] mt-2 leading-tight">{desc}</div>
            </motion.div>
          );
        })}
      </div>

      {/* Breach table */}
      <Card delay={0.2}>
        <CardTitle icon={Clock} title="Active Breach Details" badge={breachRows.length} />
        {breachRows.length === 0 ? (
          <p className="text-center text-[#64748b] text-sm py-8">No active compliance breaches. System compliant.</p>
        ) : (
          <div className="space-y-2">
            {/* Header */}
            <div className="grid grid-cols-4 gap-3 text-xs text-[#64748b] uppercase tracking-wider px-3 pb-2 border-b border-[#1e3a5f]">
              <span>Incident</span><span>Breach</span><span>Notification Deadline</span><span>Urgency</span>
            </div>
            {breachRows.map((r, i) => {
              const uc = URGENCY_COLOR[r.urgency] || "#64748b";
              return (
                <motion.div key={i} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className="grid grid-cols-4 gap-3 items-center px-3 py-2.5 rounded-lg bg-[#0a1628] border border-[#1e3a5f] text-sm">
                  <span className="font-mono text-xs text-[#64748b]">{r.incId}</span>
                  <span className="text-red-400 font-semibold text-xs">{r.breach}</span>
                  <div className="flex items-center gap-2">
                    <Clock size={12} style={{ color: uc }} />
                    <span className="text-xs" style={{ color: uc }}>{r.text}</span>
                  </div>
                  <span className="text-xs font-bold uppercase" style={{ color: uc }}>{r.urgency}</span>
                </motion.div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Regulation quick reference */}
      <Card delay={0.3}>
        <CardTitle icon={Shield} title="Regulation Quick Reference" />
        <div className="grid grid-cols-2 gap-3 text-xs">
          {[
            ["PCI-DSS Req.3", "Protect stored cardholder data"],
            ["PCI-DSS Req.10", "Track and monitor access to network resources"],
            ["PCI-DSS Req.11", "Test security systems and processes"],
            ["SWIFT CSP CSCF 2.x", "Unauthorized access to SWIFT infrastructure"],
            ["GDPR Art.33", "Personal data breach — notify regulator within 72h"],
            ["Basel III ORR", "Operational risk event — resilience reporting"],
            ["BCT Circular", "Cyber incident affecting bank operations in Tunisia"],
          ].map(([reg, desc]) => (
            <div key={reg} className="flex gap-2 bg-[#0a1628] border border-[#1e3a5f] rounded-lg p-2.5">
              <span className="text-[#00d4ff] font-semibold shrink-0">{reg}</span>
              <span className="text-[#64748b]">{desc}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
