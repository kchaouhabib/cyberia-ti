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
  initial: { opacity: 0, x: 16, filter: "blur(4px)" },
  animate: { opacity: 1, x: 0,  filter: "blur(0px)", transition: { duration: 0.28, ease: [0.22, 1, 0.36, 1] } },
  exit:    { opacity: 0, x: -12, filter: "blur(2px)", transition: { duration: 0.18, ease: "easeIn" } },
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
          initial={{ y: -40, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ type: "spring", stiffness: 260, damping: 26, delay: 0.1 }}
          className="flex items-center gap-4 px-6 py-3 sticky top-0 z-10"
          style={{
            background: "rgba(4, 9, 26, 0.88)",
            backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)",
            borderBottom: "1px solid rgba(0,212,255,0.07)",
            boxShadow: "0 4px 24px rgba(0,0,0,0.25)",
          }}>
          <div>
            <h1 className="text-sm font-bold tracking-wide" style={{ color: "var(--clr-text)" }}>
              {PAGE_TITLES[page]}
            </h1>
            <p className="text-[10px] tracking-wider mt-0.5" style={{ color: "var(--clr-muted)" }}>
              Banque Atlas · Banking Sector TI · Cyberia 2026
            </p>
          </div>

          <div className="flex items-center gap-2 ml-auto">
            {criticalCount > 0 && (
              <motion.div
                animate={{ scale: [1, 1.04, 1] }}
                transition={{ repeat: Infinity, duration: 1.8, ease: "easeInOut" }}
                className="flex items-center gap-1.5 rounded-full px-3 py-1 font-bold"
                style={{ fontSize: 11, background: "rgba(255,45,85,0.14)", color: "var(--clr-red)", border: "1px solid rgba(255,45,85,0.32)" }}>
                <Zap size={10} />
                {criticalCount} CRITICAL
              </motion.div>
            )}
            {compBreaches > 0 && (
              <div className="flex items-center gap-1.5 rounded-full px-3 py-1"
                style={{ fontSize: 11, background: "rgba(255,159,10,0.11)", color: "var(--clr-orange)", border: "1px solid rgba(255,159,10,0.28)" }}>
                <Shield size={10} />
                {compBreaches} breach{compBreaches !== 1 ? "es" : ""}
              </div>
            )}
            <div className="flex items-center gap-1.5 rounded-full px-3 py-1"
              style={{ fontSize: 11, ...(pc1Ok
                ? { background: "rgba(48,209,88,0.09)", color: "var(--clr-green)", border: "1px solid rgba(48,209,88,0.22)" }
                : { background: "rgba(255,45,85,0.09)", color: "var(--clr-red)",   border: "1px solid rgba(255,45,85,0.22)" }) }}>
              {pc1Ok ? <Wifi size={10} /> : <WifiOff size={10} />}
              {pc1Ok ? "Live" : "Offline"}
            </div>
            <div className="flex items-center gap-1.5" style={{ fontSize: 11, color: "var(--clr-muted)" }}>
              <Clock size={10} />
              {lastRefresh}
            </div>
          </div>
        </motion.header>

        {/* Page content */}
        <main className="flex-1 p-5 overflow-y-auto">
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
        <div className="px-6 py-2 flex items-center gap-3"
          style={{ borderTop: "1px solid rgba(0,212,255,0.06)", fontSize: 10, color: "rgba(100,116,139,0.45)" }}>
          <span className="tabular-nums">Auto-refresh 5s</span>
          <span>·</span>
          <span className="tabular-nums">Tick #{tick}</span>
          <span>·</span>
          <span className="tabular-nums">{incidents.length} incidents · {incidents.reduce((n,i)=>n+(i.iocs?.length||0),0)} IOCs</span>
        </div>
      </div>
    </div>
  );
}
