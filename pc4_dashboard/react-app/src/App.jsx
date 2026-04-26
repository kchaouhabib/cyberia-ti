import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Clock, Wifi, WifiOff, Zap, Shield } from "lucide-react";
import Sidebar from "./components/Sidebar";
import Overview    from "./pages/Overview";
import Alerts      from "./pages/Alerts";
import Compliance  from "./pages/Compliance";
import Assets      from "./pages/Assets";
import Predictions from "./pages/Predictions";
import { fetchIncidents, fetchPredictions, fetchStats } from "./api";

const PAGE_TITLES = {
  overview:    "Overview",
  alerts:      "Live Alerts",
  compliance:  "Compliance Monitor",
  assets:      "Asset Intelligence",
  predictions: "Threat Predictions",
};

const pageVariants = {
  initial: { opacity: 0, x: 14, filter: "blur(3px)" },
  animate: { opacity: 1, x: 0,  filter: "blur(0px)", transition: { duration: 0.26, ease: [0.22, 1, 0.36, 1] } },
  exit:    { opacity: 0, x: -10, filter: "blur(2px)", transition: { duration: 0.16, ease: "easeIn" } },
};

export default function App() {
  const [page,        setPage]        = useState("overview");
  const [incidents,   setIncidents]   = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [stats,       setStats]       = useState({});
  const [lastRefresh, setLastRefresh] = useState("—");
  const [pc1Ok,       setPc1Ok]       = useState(false);
  const [tick,        setTick]        = useState(0);

  async function refresh() {
    const [inc, pred, st] = await Promise.all([
      fetchIncidents(), fetchPredictions(), fetchStats()
    ]);
    setIncidents(Array.isArray(inc) ? inc : []);
    setPredictions(Array.isArray(pred) ? pred : []);
    setStats(st && typeof st === "object" ? st : {});
    setPc1Ok(Array.isArray(inc));
    setLastRefresh(new Date().toLocaleTimeString());
    setTick(t => t + 1);
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);

  const criticalCount = incidents.filter(i => i.severity === "critical").length;
  const compBreaches  = incidents.reduce((n, i) => n + (i.compliance_breaches?.length || 0), 0);
  const pageProps     = { incidents, predictions, stats };

  return (
    <div className="flex min-h-dvh grid-bg">
      <Sidebar active={page} setActive={setPage} pc1Ok={pc1Ok} incidentCount={incidents.length} />

      <div className="flex-1 flex flex-col min-w-0">

        {/* Top bar */}
        <motion.header
          initial={{ y: -36, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ type: "spring", stiffness: 260, damping: 26, delay: 0.08 }}
          className="flex items-center gap-3 px-5 py-2 sticky top-0 z-10"
          style={{
            background: "rgba(13,17,23,0.94)",
            backdropFilter: "blur(12px)",
            WebkitBackdropFilter: "blur(12px)",
            borderBottom: "1px solid var(--border)",
            minHeight: 40,
          }}
        >
          <div className="flex items-center gap-2">
            <div className="live-dot" />
            <span className="text-xs font-semibold tracking-wide" style={{ color: "var(--text)" }}>
              {PAGE_TITLES[page]}
            </span>
          </div>
          <span style={{ color: "var(--dim)", fontSize: 11 }}>·</span>
          <span className="text-[10px] tracking-wider" style={{ color: "var(--muted)" }}>
            Banque Atlas · Banking TI · Cyberia 2026
          </span>

          <div className="flex items-center gap-2 ml-auto">
            {criticalCount > 0 && (
              <motion.div
                animate={{ scale: [1, 1.04, 1] }}
                transition={{ repeat: Infinity, duration: 1.8, ease: "easeInOut" }}
                className="flex items-center gap-1 rounded-full px-2.5 py-0.5 font-bold"
                style={{
                  fontSize: 10,
                  background: "var(--critical-bg)",
                  color: "var(--critical)",
                  border: "1px solid rgba(255,107,107,0.28)",
                }}
              >
                <Zap size={9} />
                {criticalCount} CRITICAL
              </motion.div>
            )}
            {compBreaches > 0 && (
              <div
                className="flex items-center gap-1 rounded-full px-2.5 py-0.5"
                style={{
                  fontSize: 10,
                  background: "var(--high-bg)",
                  color: "var(--high)",
                  border: "1px solid rgba(255,169,77,0.25)",
                }}
              >
                <Shield size={9} />
                {compBreaches} breach{compBreaches !== 1 ? "es" : ""}
              </div>
            )}
            <div
              className="flex items-center gap-1 rounded-full px-2.5 py-0.5"
              style={{
                fontSize: 10,
                ...(pc1Ok
                  ? { background: "var(--low-bg)", color: "var(--low)", border: "1px solid rgba(105,219,124,0.22)" }
                  : { background: "var(--critical-bg)", color: "var(--critical)", border: "1px solid rgba(255,107,107,0.22)" }),
              }}
            >
              {pc1Ok ? <Wifi size={9} /> : <WifiOff size={9} />}
              {pc1Ok ? "Live" : "Offline"}
            </div>
            <div className="flex items-center gap-1 mono" style={{ fontSize: 10, color: "var(--muted)" }}>
              <Clock size={9} />
              {lastRefresh}
            </div>
          </div>
        </motion.header>

        {/* Page content */}
        <main className="flex-1 p-4 overflow-y-auto">
          <AnimatePresence mode="wait">
            <motion.div key={page} variants={pageVariants} initial="initial" animate="animate" exit="exit">
              {page === "overview"    && <Overview    {...pageProps} />}
              {page === "alerts"      && <Alerts      {...pageProps} />}
              {page === "compliance"  && <Compliance  {...pageProps} />}
              {page === "assets"      && <Assets      {...pageProps} />}
              {page === "predictions" && <Predictions {...pageProps} />}
            </motion.div>
          </AnimatePresence>
        </main>

        {/* Footer */}
        <div
          className="px-5 py-1 flex items-center gap-3 mono"
          style={{ borderTop: "1px solid var(--border)", fontSize: 10, color: "var(--dim)" }}
        >
          <span className="tabular-nums">Auto-refresh 5s</span>
          <span>·</span>
          <span className="tabular-nums">Tick #{tick}</span>
          <span>·</span>
          <span className="tabular-nums">
            {incidents.length} incidents · {incidents.reduce((n, i) => n + (i.iocs?.length || 0), 0)} IOCs
          </span>
        </div>
      </div>
    </div>
  );
}
