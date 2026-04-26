import { motion } from "framer-motion";
import { Shield, Clock, AlertOctagon, CheckCircle } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const FRAMEWORKS = [
  { key: "PCI-DSS",    label: "PCI-DSS",      color: "#00d4ff", desc: "Payment Card Industry Data Security Standard" },
  { key: "SWIFT CSP",  label: "SWIFT CSP",     color: "#ff8c00", desc: "SWIFT Customer Security Programme (CSCF 2.x)" },
  { key: "GDPR",       label: "GDPR Art.33",   color: "#ff2d78", desc: "General Data Protection Regulation — 72h" },
  { key: "BCT",        label: "BCT Circular",  color: "#8b5cf6", desc: "Banque Centrale de Tunisie — Cybersecurity" },
  { key: "Basel III",  label: "Basel III ORR", color: "#00ff88", desc: "Operational Risk & Resilience framework" },
];

const DEADLINES = {
  "PCI-DSS Req.3":       { text: "Per acquirer contract",    urgency: "medium" },
  "PCI-DSS Req.10":      { text: "Audit cycle",              urgency: "low"    },
  "PCI-DSS Req.11":      { text: "Audit cycle",              urgency: "low"    },
  "SWIFT CSP CSCF 2.x":  { text: "24 HOURS → SWIFT",         urgency: "critical" },
  "GDPR Art.33":          { text: "72 HOURS → REGULATOR",     urgency: "high"   },
  "Basel III ORR":        { text: "Per local implementation", urgency: "medium" },
  "BCT Circular":         { text: "Per local circular",       urgency: "medium" },
};

const URGENCY_COLOR = {
  critical: "var(--critical)",
  high:     "var(--high)",
  medium:   "var(--medium)",
  low:      "var(--low)",
};

export default function Compliance({ incidents }) {
  const breachRows = [];
  incidents.forEach(inc =>
    inc.compliance_breaches?.forEach(b =>
      breachRows.push({ ...DEADLINES[b], breach: b, incId: inc.id?.slice(0, 10), sev: inc.severity, risk: inc.risk_score })
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
      {/* Summary banner */}
      <Card danger={total > 0} delay={0}>
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-lg" style={{ background: total > 0 ? "var(--critical-bg)" : "var(--low-bg)", border: `1px solid ${total > 0 ? "var(--critical-b)" : "var(--low-b)"}` }}>
            {total > 0
              ? <AlertOctagon size={22} style={{ color: "var(--critical)" }} />
              : <CheckCircle  size={22} style={{ color: "var(--low)" }} />
            }
          </div>
          <div>
            <div className="font-orb font-black"
              style={{ fontSize: 26, color: total > 0 ? "var(--critical)" : "var(--low)", textShadow: total > 0 ? "0 0 20px rgba(255,45,120,0.5)" : "0 0 20px rgba(0,255,136,0.4)" }}>
              {total} ACTIVE BREACH{total !== 1 ? "ES" : ""}
            </div>
            <div className="section-label mt-1">ACROSS {FRAMEWORKS.length} REGULATORY FRAMEWORKS</div>
          </div>
          {total === 0 && (
            <div className="ml-auto font-orb font-bold" style={{ fontSize: 11, color: "var(--low)", letterSpacing: "0.1em" }}>
              ✓ ALL FRAMEWORKS CLEAR
            </div>
          )}
        </div>
      </Card>

      {/* Framework score cards */}
      <div className="grid grid-cols-5 gap-3">
        {FRAMEWORKS.map(({ key, label, color, desc }, i) => {
          const n = counts[key] || 0;
          const c = n > 0 ? "var(--critical)" : color;
          return (
            <motion.div key={key}
              initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.07, type: "spring", stiffness: 250, damping: 22 }}
              className="card p-5 text-center"
              style={n > 0 ? { borderColor: "var(--critical-b)", boxShadow: "0 0 20px rgba(255,45,120,0.10)" } : {}}
            >
              <div className="section-label mb-3">{label}</div>
              <motion.div key={n} initial={{ scale: 0.4 }} animate={{ scale: 1 }}
                className="font-orb font-black mb-1"
                style={{ fontSize: 40, color: c, textShadow: `0 0 20px ${c}70` }}>
                {n}
              </motion.div>
              <div className="section-label">INCIDENT{n !== 1 ? "S" : ""}</div>
              <div className="mt-2" style={{ fontSize: 9, color: "var(--dim)", lineHeight: 1.4 }}>{desc}</div>
            </motion.div>
          );
        })}
      </div>

      {/* Breach table */}
      <Card delay={0.2}>
        <CardTitle icon={Clock} title="ACTIVE BREACH DETAILS" badge={breachRows.length} />
        {breachRows.length === 0 ? (
          <p className="mono text-center py-8" style={{ color: "var(--muted)", fontSize: 11, letterSpacing: "0.1em" }}>
            NO ACTIVE COMPLIANCE BREACHES — SYSTEM COMPLIANT
          </p>
        ) : (
          <div>
            <div className="soc-row section-label" style={{ gridTemplateColumns: "110px 1fr 1fr 100px", color: "var(--dim)" }}>
              <span>INCIDENT</span><span>BREACH</span><span>NOTIFICATION DEADLINE</span><span>URGENCY</span>
            </div>
            {breachRows.map((r, i) => {
              const uc = URGENCY_COLOR[r.urgency] || "var(--muted)";
              return (
                <motion.div key={i}
                  initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className={`soc-row row-${r.urgency}`}
                  style={{ gridTemplateColumns: "110px 1fr 1fr 100px" }}>
                  <span className="mono" style={{ fontSize: 10, color: "var(--muted)" }}>{r.incId}</span>
                  <span className="mono font-bold" style={{ fontSize: 10, color: "var(--critical)" }}>{r.breach}</span>
                  <div className="flex items-center gap-2">
                    <Clock size={10} style={{ color: uc }} />
                    <span className="mono" style={{ fontSize: 10, color: uc }}>{r.text}</span>
                  </div>
                  <span className={`badge badge-${r.urgency}`}>{r.urgency}</span>
                </motion.div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Quick reference */}
      <Card delay={0.3}>
        <CardTitle icon={Shield} title="REGULATION QUICK REFERENCE" />
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[
            ["PCI-DSS Req.3",      "Protect stored cardholder data"],
            ["PCI-DSS Req.10",     "Track & monitor access to network resources"],
            ["PCI-DSS Req.11",     "Test security systems and processes"],
            ["SWIFT CSP CSCF 2.x", "Unauthorized access to SWIFT infrastructure"],
            ["GDPR Art.33",        "Personal data breach — notify regulator within 72h"],
            ["Basel III ORR",      "Operational risk event — resilience reporting"],
            ["BCT Circular",       "Cyber incident affecting Tunisian bank operations"],
          ].map(([reg, desc]) => (
            <div key={reg} className="flex gap-2 rounded-lg p-2.5" style={{ background: "var(--bg-row)", border: "1px solid var(--border)" }}>
              <span className="mono font-bold shrink-0" style={{ color: "var(--cyan)", fontSize: 10 }}>{reg}</span>
              <span style={{ color: "var(--muted)", fontSize: 10 }}>{desc}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
