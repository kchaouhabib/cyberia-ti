import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Wifi, WifiOff, Zap, Shield, Radio } from "lucide-react";
import Overview    from "./pages/Overview";
import Alerts      from "./pages/Alerts";
import Compliance  from "./pages/Compliance";
import Assets      from "./pages/Assets";
import Predictions from "./pages/Predictions";
import { fetchIncidents, fetchPredictions, fetchStats } from "./api";

const PAGES = [
  { id: "overview",    label: "Overview" },
  { id: "alerts",      label: "Live Alerts" },
  { id: "compliance",  label: "Compliance" },
  { id: "assets",      label: "Assets" },
  { id: "predictions", label: "Predictions" },
];

const pageVariants = {
  initial: { opacity: 0, y: 10, filter: "blur(4px)" },
  animate: { opacity: 1, y: 0,  filter: "blur(0px)", transition: { duration: 0.3, ease: [0.22, 1, 0.36, 1] } },
  exit:    { opacity: 0, y: -6, filter: "blur(2px)", transition: { duration: 0.18, ease: "easeIn" } },
};

export default function App() {
  const [page,        setPage]        = useState("overview");
  const [incidents,   setIncidents]   = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [stats,       setStats]       = useState({});
  const [time,        setTime]        = useState("—");
  const [pc1Ok,       setPc1Ok]       = useState(false);
  const [tick,        setTick]        = useState(0);

  async function refresh() {
    const [inc, pred, st] = await Promise.all([
      fetchIncidents(), fetchPredictions(), fetchStats()
    ]);
    setIncidents(Array.isArray(inc) ? inc : []);
    setPredictions(Array.isArray(pred) ? pred : []);
    setStats(st && typeof st === "object" ? st : {});
    setPc1Ok(Array.isArray(inc) && inc.length > 0);
    setTime(new Date().toLocaleTimeString());
    setTick(t => t + 1);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);

  const criticalCount = incidents.filter(i => i.severity === "critical").length;
  const compBreaches  = incidents.reduce((n, i) => n + (i.compliance_breaches?.length || 0), 0);

  return (
    <div className="flex flex-col min-h-dvh grid-bg">

      {/* ── Top nav ── */}
      <motion.nav
        initial={{ y: -56, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ type: "spring", stiffness: 240, damping: 26 }}
        className="sticky top-0 z-50 flex items-center gap-0 px-6"
        style={{
          height: 52,
          background: "rgba(4,5,15,0.95)",
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
          borderBottom: "1px solid rgba(0,212,255,0.08)",
          boxShadow: "0 1px 0 rgba(0,212,255,0.04), 0 4px 24px rgba(0,0,0,0.6)",
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5 mr-8 shrink-0">
          <div className="relative flex items-center justify-center w-7 h-7 rounded"
            style={{ background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)" }}>
            <Radio size={13} style={{ color: "var(--cyan)" }} />
            <span className="absolute inset-0 rounded" style={{
              background: "radial-gradient(circle, rgba(0,212,255,0.15) 0%, transparent 70%)",
            }} />
          </div>
          <span className="font-orb font-bold tracking-widest" style={{ fontSize: 13, color: "var(--cyan)", textShadow: "0 0 16px rgba(0,212,255,0.6)" }}>
            CYBERIA
          </span>
          <span className="font-orb" style={{ fontSize: 8, color: "var(--muted)", letterSpacing: "0.2em", marginTop: 1 }}>
            TI · 2026
          </span>
        </div>

        {/* Nav tabs */}
        <div className="flex items-center gap-1">
          {PAGES.map(({ id, label }, i) => {
            const isActive = page === id;
            return (
              <motion.button
                key={id}
                onClick={() => setPage(id)}
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.06 + i * 0.04 }}
                className="relative px-4 py-1.5 rounded font-orb transition-all"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.14em",
                  fontWeight: 700,
                  color: isActive ? "var(--cyan)" : "var(--muted)",
                  background: isActive ? "var(--cyan-dim)" : "transparent",
                  border: `1px solid ${isActive ? "rgba(0,212,255,0.25)" : "transparent"}`,
                  boxShadow: isActive ? "0 0 16px rgba(0,212,255,0.12)" : "none",
                }}
              >
                {isActive && (
                  <motion.div
                    layoutId="nav-pill"
                    className="absolute inset-0 rounded"
                    style={{ border: "1px solid rgba(0,212,255,0.25)", background: "var(--cyan-dim)" }}
                  />
                )}
                <span className="relative">{label.toUpperCase()}</span>
                {id === "alerts" && criticalCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full flex items-center justify-center font-bold"
                    style={{ fontSize: 7, background: "var(--critical)", color: "#fff", boxShadow: "0 0 8px var(--critical)" }}>
                    {criticalCount}
                  </span>
                )}
              </motion.button>
            );
          })}
        </div>

        {/* Right status */}
        <div className="ml-auto flex items-center gap-2">
          {criticalCount > 0 && (
            <motion.div
              animate={{ opacity: [1, 0.5, 1] }}
              transition={{ repeat: Infinity, duration: 1.4 }}
              className="flex items-center gap-1.5 rounded px-2.5 py-1 font-orb"
              style={{ fontSize: 9, background: "var(--critical-bg)", color: "var(--critical)", border: "1px solid var(--critical-b)", boxShadow: "0 0 12px rgba(255,45,120,0.2)" }}>
              <Zap size={9} />
              {criticalCount} CRITICAL
            </motion.div>
          )}
          {compBreaches > 0 && (
            <div className="flex items-center gap-1 rounded px-2.5 py-1 font-orb"
              style={{ fontSize: 9, background: "var(--high-bg)", color: "var(--high)", border: "1px solid var(--high-b)" }}>
              <Shield size={9} />
              {compBreaches} BREACH{compBreaches !== 1 ? "ES" : ""}
            </div>
          )}
          <div className="flex items-center gap-1.5 rounded px-2.5 py-1"
            style={{ fontSize: 9, ...(pc1Ok
              ? { background: "var(--low-bg)", color: "var(--low)", border: "1px solid var(--low-b)" }
              : { background: "var(--critical-bg)", color: "var(--critical)", border: "1px solid var(--critical-b)" }) }}>
            {pc1Ok ? <Wifi size={9} /> : <WifiOff size={9} />}
            <span className="font-orb" style={{ letterSpacing: "0.1em" }}>{pc1Ok ? "LIVE" : "OFFLINE"}</span>
            {pc1Ok && <div className="live-dot" style={{ width: 5, height: 5 }} />}
          </div>
          <div className="mono" style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.05em" }}>
            {time}
          </div>
        </div>
      </motion.nav>

      {/* ── Page content ── */}
      <main className="flex-1 overflow-y-auto">
        <AnimatePresence mode="wait">
          <motion.div
            key={page}
            variants={pageVariants}
            initial="initial"
            animate="animate"
            exit="exit"
            className="p-5 max-w-[1600px] mx-auto w-full"
          >
            {page === "overview"    && <Overview    incidents={incidents} predictions={predictions} stats={stats} />}
            {page === "alerts"      && <Alerts      incidents={incidents} />}
            {page === "compliance"  && <Compliance  incidents={incidents} />}
            {page === "assets"      && <Assets      incidents={incidents} />}
            {page === "predictions" && <Predictions predictions={predictions} />}
          </motion.div>
        </AnimatePresence>
      </main>

      {/* ── Footer ── */}
      <div className="px-6 py-1.5 flex items-center gap-3 mono shrink-0"
        style={{ borderTop: "1px solid rgba(0,212,255,0.04)", fontSize: 9, color: "var(--dim)", letterSpacing: "0.05em" }}>
        <span className="tabular-nums">AUTO-REFRESH 5s</span>
        <span>·</span>
        <span className="tabular-nums">TICK #{tick}</span>
        <span>·</span>
        <span className="tabular-nums">{incidents.length} INCIDENTS · {incidents.reduce((n,i)=>n+(i.iocs?.length||0),0)} IOCs</span>
        <span className="ml-auto">BANQUE ATLAS — CYBERIA 2026</span>
      </div>
    </div>
  );
}
