import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, ChevronUp, Filter, Zap, Download, FileJson, FileText, FileDown, Clock } from "lucide-react";
import Card from "../components/Card";
import { fetchTimeline, downloadExport } from "../api";

const SEV   = { critical: "#ff2d78", high: "#ff8c00", medium: "#ffd700", low: "#00ff88" };
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const TABS  = ["all", "critical", "high", "medium", "low"];

const MITRE_NAMES = {
  T1566: "Phishing", T1078: "Valid Accounts", T1190: "Exploit App",
  T1539: "Session Hijack", T1041: "Exfiltration", T1071: "C2 Protocol",
  T1486: "Ransomware", T1059: "Command Exec", T1005: "Data from Local",
};

function TimelinePanel({ incidentId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTimeline(incidentId).then(d => { setData(d); setLoading(false); });
  }, [incidentId]);

  if (loading) return (
    <div className="mono py-4 text-center" style={{ fontSize: 10, color: "var(--muted)" }}>
      LOADING TIMELINE…
    </div>
  );
  if (!data || !data.events?.length) return (
    <div className="mono py-4 text-center" style={{ fontSize: 10, color: "var(--muted)" }}>
      NO TIMELINE EVENTS
    </div>
  );

  const PHASE_COLOR = { phishing: "#ff2d78", lateral_movement: "#ff8c00", exfiltration: "#ffd700", c2: "#8b5cf6", malware: "#ff5c00" };

  return (
    <div>
      <div className="section-label mb-3 flex items-center gap-2">
        <Clock size={9} style={{ color: "var(--cyan)" }} />
        KILL-CHAIN TIMELINE — {data.events.length} EVENT{data.events.length !== 1 ? "S" : ""}
      </div>
      <div className="relative pl-4">
        {/* Vertical line */}
        <div className="absolute left-[7px] top-2 bottom-2 w-px" style={{ background: "rgba(0,212,255,0.15)" }} />
        {data.events.map((ev, i) => {
          const c = PHASE_COLOR[ev.threat_type] || "var(--cyan)";
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.06 }}
              className="relative flex gap-3 mb-3 last:mb-0"
            >
              {/* Dot */}
              <div className="absolute -left-4 top-1.5 w-2.5 h-2.5 rounded-full shrink-0 z-10"
                style={{ background: c, boxShadow: `0 0 10px ${c}`, border: "2px solid var(--bg-card)" }} />

              <div className="flex-1 rounded p-2.5" style={{ background: "var(--bg-row)", border: `1px solid ${c}20` }}>
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className={`badge badge-${ev.threat_type === "c2" || ev.threat_type === "exfiltration" || ev.threat_type === "lateral_movement" ? "high" : ev.threat_type === "phishing" ? "medium" : "info"}`}>
                    {ev.threat_type?.replace("_", " ")}
                  </span>
                  {ev.mitre_technique && (
                    <span className="mono" style={{ fontSize: 9, color: "var(--cyan)", background: "rgba(0,212,255,0.07)", border: "1px solid rgba(0,212,255,0.18)", borderRadius: 2, padding: "1px 5px" }}>
                      {ev.mitre_technique} {MITRE_NAMES[ev.mitre_technique] ? `· ${MITRE_NAMES[ev.mitre_technique]}` : ""}
                    </span>
                  )}
                  {ev.apt_attribution && (
                    <span className="mono font-bold uppercase" style={{ fontSize: 9, color: "var(--high)", background: "var(--high-bg)", border: "1px solid var(--high-b)", borderRadius: 2, padding: "1px 5px" }}>
                      {ev.apt_attribution}
                    </span>
                  )}
                  <span className="ml-auto mono" style={{ fontSize: 9, color: "var(--muted)" }}>
                    {ev.first_seen?.slice(11, 19)}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="mono font-bold" style={{ fontSize: 10, color: "var(--text)" }}>{ev.ioc_value}</span>
                  <span className="section-label">{ev.ioc_type}</span>
                  {ev.geolocation && <span style={{ fontSize: 12 }}>{ev.geolocation}</span>}
                  <span className="mono ml-auto" style={{ fontSize: 9, color: "var(--muted)" }}>
                    conf {Math.round((ev.confidence || 0) * 100)}%
                  </span>
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}

function AlertRow({ inc, index }) {
  const [open, setOpen] = useState(false);
  const c    = SEV[inc.severity] || "#4a5280";
  const apts = [...new Set(inc.iocs?.map(i => i.apt_attribution).filter(Boolean))];
  const isAi = inc.summary && !/^\d+ IOC\(s\) from/.test(inc.summary);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ delay: index * 0.035 }}
      className="rounded-lg overflow-hidden mb-2"
      style={{
        border: `1px solid ${c}28`,
        background: `${c}06`,
        boxShadow: open ? `0 0 20px ${c}12` : "none",
      }}
    >
      {/* Header row */}
      <button
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left"
        style={{ minHeight: 42 }}
        onClick={() => setOpen(o => !o)}
      >
        <div className="w-0.5 self-stretch rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 8px ${c}` }} />
        <span className={`badge badge-${inc.severity} shrink-0`}>{inc.severity}</span>
        <span className="mono shrink-0" style={{ fontSize: 10, color: "var(--muted)" }}>{inc.id?.slice(0, 10)}</span>

        <div className="flex gap-1 flex-wrap flex-1 min-w-0">
          {inc.mitre_techniques?.slice(0, 3).map(t => (
            <span key={t} className="mono"
              style={{ fontSize: 9, background: "rgba(0,212,255,0.07)", color: "var(--cyan)", border: "1px solid rgba(0,212,255,0.18)", borderRadius: 2, padding: "1px 5px" }}>
              {t}
            </span>
          ))}
        </div>

        <span className="font-orb font-black tabular-nums shrink-0"
          style={{ fontSize: 16, color: c, textShadow: `0 0 10px ${c}80` }}>
          {inc.risk_score}
        </span>
        <span className="mono shrink-0" style={{ fontSize: 9, color: "var(--muted)" }}>
          {inc.detected_at?.slice(11, 19)}
        </span>
        {open ? <ChevronUp size={13} style={{ color: "var(--muted)" }} /> : <ChevronDown size={13} style={{ color: "var(--muted)" }} />}
      </button>

      {/* Expanded */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22 }}
            className="border-t px-4 py-3 space-y-4"
            style={{ borderColor: `${c}20` }}
          >
            {/* AI summary */}
            <div className={`rounded-lg px-3 py-2.5`}
              style={isAi
                ? { background: "rgba(0,212,255,0.05)", border: "1px solid rgba(0,212,255,0.15)" }
                : { background: "var(--bg-row)", border: "1px solid var(--border)" }}>
              {isAi && (
                <div className="flex items-center gap-1.5 mb-1.5">
                  <span className="font-orb"
                    style={{ fontSize: 8, background: "rgba(0,212,255,0.10)", color: "var(--cyan)", border: "1px solid rgba(0,212,255,0.25)", borderRadius: 2, padding: "2px 7px", letterSpacing: "0.1em" }}>
                    ✦ AI CISO SUMMARY
                  </span>
                </div>
              )}
              <p className="text-sm leading-relaxed" style={{ color: "var(--text)" }}>
                {inc.summary || "CISO summary — generated by LLM (PC2 Ollama)."}
              </p>
            </div>

            {/* Kill-chain timeline */}
            <TimelinePanel incidentId={inc.id} />

            {/* Asset / Compliance / APT */}
            <div className="grid grid-cols-3 gap-3">
              <div>
                <div className="section-label mb-2">TARGETED ASSETS</div>
                {inc.targeted_assets?.length
                  ? inc.targeted_assets.map(a => (
                    <span key={a} className="block mono rounded px-2 py-1 mb-1"
                      style={{ background: "var(--bg-row)", border: "1px solid var(--border)", fontSize: 10 }}>{a}</span>
                  ))
                  : <span style={{ color: "var(--muted)", fontSize: 10 }}>Unknown</span>
                }
              </div>
              <div>
                <div className="section-label mb-2">COMPLIANCE BREACHES</div>
                {inc.compliance_breaches?.length
                  ? inc.compliance_breaches.map(b => (
                    <span key={b} className="block mono rounded px-2 py-1 mb-1"
                      style={{ background: "var(--critical-bg)", border: "1px solid var(--critical-b)", color: "var(--critical)", fontSize: 10 }}>{b}</span>
                  ))
                  : <span style={{ color: "var(--low)", fontSize: 10 }}>✓ None</span>
                }
              </div>
              <div>
                <div className="section-label mb-2">APT ATTRIBUTION</div>
                {apts.length
                  ? apts.map(a => (
                    <span key={a} className="block mono uppercase rounded px-2 py-1 mb-1"
                      style={{ background: "var(--high-bg)", border: "1px solid var(--high-b)", color: "var(--high)", fontSize: 10 }}>{a}</span>
                  ))
                  : <span style={{ color: "var(--muted)", fontSize: 10 }}>Unknown</span>
                }
              </div>
            </div>

            {/* IOC count + Download PDF */}
            <div className="flex items-center justify-between">
              <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>
                {inc.iocs?.length || 0} IOCs CORRELATED
              </span>
              <button
                onClick={() => downloadExport("pdf", inc.id)}
                className="btn-neon flex items-center gap-1.5"
                style={{ color: "var(--critical)", borderColor: "var(--critical-b)", background: "var(--critical-bg)" }}
              >
                <Download size={9} />
                DOWNLOAD PDF REPORT
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function Alerts({ incidents }) {
  const [filter, setFilter] = useState("all");
  const filtered = [...incidents]
    .filter(i => filter === "all" || i.severity === filter)
    .sort((a, b) => (ORDER[a.severity] ?? 3) - (ORDER[b.severity] ?? 3));

  const counts = TABS.slice(1).reduce((acc, s) =>
    ({ ...acc, [s]: incidents.filter(i => i.severity === s).length }), {});

  return (
    <div className="space-y-4">
      {/* Filter + download bar */}
      <Card delay={0}>
        <div className="flex items-center gap-3 flex-wrap">
          <Filter size={11} style={{ color: "var(--muted)" }} />
          <span className="section-label">FILTER</span>
          {TABS.map(f => {
            const c = SEV[f] || "var(--cyan)";
            return (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`btn-neon ${filter === f ? "active" : ""}`}
                style={filter === f && f !== "all"
                  ? { color: c, borderColor: c, background: `${c}12`, boxShadow: `0 0 12px ${c}25` }
                  : {}}
              >
                {f.toUpperCase()}
                {f !== "all" && counts[f] > 0 && (
                  <span className="ml-1.5" style={{ opacity: 0.7 }}>({counts[f]})</span>
                )}
              </button>
            );
          })}

          {/* Portfolio download buttons */}
          <div className="ml-auto flex items-center gap-2">
            <span className="section-label mr-1">EXPORT</span>
            <button onClick={() => downloadExport("json")} className="btn-neon flex items-center gap-1.5"
              style={{ color: "var(--cyan)", borderColor: "rgba(0,212,255,0.25)" }}>
              <FileJson size={9} /> JSON
            </button>
            <button onClick={() => downloadExport("csv")} className="btn-neon flex items-center gap-1.5"
              style={{ color: "var(--green)", borderColor: "rgba(0,255,136,0.25)" }}>
              <FileText size={9} /> CSV
            </button>
            <button onClick={() => downloadExport("pdf")} className="btn-neon flex items-center gap-1.5"
              style={{ color: "var(--critical)", borderColor: "var(--critical-b)", background: "var(--critical-bg)" }}>
              <FileDown size={9} /> PDF
            </button>
          </div>
        </div>
      </Card>

      {/* Alert list */}
      <div>
        <AnimatePresence mode="popLayout">
          {filtered.length === 0
            ? (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center py-24 gap-4">
                <Zap size={36} style={{ color: "var(--dim)" }} />
                <p className="mono" style={{ color: "var(--muted)", fontSize: 12, letterSpacing: "0.1em" }}>
                  NO {filter !== "all" ? filter.toUpperCase() : ""} INCIDENTS — SYSTEM CLEAN
                </p>
              </motion.div>
            )
            : filtered.map((inc, i) => <AlertRow key={inc.id} inc={inc} index={i} />)
          }
        </AnimatePresence>
      </div>
    </div>
  );
}
