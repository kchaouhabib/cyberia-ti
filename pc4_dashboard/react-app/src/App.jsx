import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Clock, Wifi, WifiOff } from "lucide-react";
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
  initial: { opacity: 0, x: 20 },
  animate: { opacity: 1, x: 0, transition: { duration: 0.3, ease: "easeOut" } },
  exit:    { opacity: 0, x: -20, transition: { duration: 0.2 } },
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

  const pageProps = { incidents, predictions, stats };

  return (
    <div className="flex min-h-screen grid-bg">
      <Sidebar active={page} setActive={setPage} pc1Ok={pc1Ok} incidentCount={incidents.length} />

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Top bar */}
        <motion.header initial={{ y: -40, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
          className="flex items-center gap-4 px-6 py-3 border-b border-[#1e3a5f] bg-[#070f1f]/80 backdrop-blur-sm sticky top-0 z-10">
          <div>
            <h1 className="text-base font-bold text-[#e8f4f8]">{PAGE_TITLES[page]}</h1>
            <p className="text-xs text-[#64748b]">🏦 Banque Atlas · Banking Sector TI · Cyberia 2026</p>
          </div>

          {/* Status pills */}
          <div className="flex items-center gap-2 ml-auto">
            {criticalCount > 0 && (
              <motion.span animate={{ scale: [1, 1.06, 1] }} transition={{ repeat: Infinity, duration: 1.5 }}
                className="text-xs bg-red-500/20 text-red-400 border border-red-500/40 rounded-full px-3 py-1 font-bold">
                🚨 {criticalCount} CRITICAL
              </motion.span>
            )}
            {compBreaches > 0 && (
              <span className="text-xs bg-orange-500/20 text-orange-400 border border-orange-500/40 rounded-full px-3 py-1">
                ⚠ {compBreaches} breach{compBreaches !== 1 ? "es" : ""}
              </span>
            )}
            <div className={`flex items-center gap-1.5 text-xs px-3 py-1 rounded-full border ${
              pc1Ok ? "bg-green-500/10 text-green-400 border-green-500/30" : "bg-red-500/10 text-red-400 border-red-500/30"
            }`}>
              {pc1Ok ? <Wifi size={11} /> : <WifiOff size={11} />}
              {pc1Ok ? "PC1 Live" : "PC1 Down"}
            </div>
            <div className="flex items-center gap-1.5 text-xs text-[#64748b]">
              <Clock size={11} />
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
        <div className="px-6 py-2 border-t border-[#1e3a5f] flex items-center gap-3 text-xs text-[#1e3a5f]">
          <span>Auto-refresh every 5s</span>
          <span>·</span>
          <span>Tick #{tick}</span>
          <span>·</span>
          <span>{incidents.length} incidents · {incidents.reduce((n,i)=>n+(i.iocs?.length||0),0)} IOCs</span>
        </div>
      </div>
    </div>
  );
}
