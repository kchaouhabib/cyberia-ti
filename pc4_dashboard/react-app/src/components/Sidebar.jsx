import { motion } from "framer-motion";
import { LayoutDashboard, AlertTriangle, Shield, Database, TrendingUp, Radio } from "lucide-react";

const pages = [
  { id: "overview",    label: "Overview",     icon: LayoutDashboard },
  { id: "alerts",      label: "Live Alerts",  icon: AlertTriangle },
  { id: "compliance",  label: "Compliance",   icon: Shield },
  { id: "assets",      label: "Assets",       icon: Database },
  { id: "predictions", label: "Predictions",  icon: TrendingUp },
];

export default function Sidebar({ active, setActive, pc1Ok, incidentCount }) {
  return (
    <motion.aside
      initial={{ x: -60, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ type: "spring", stiffness: 260, damping: 28 }}
      style={{
        background: "rgba(4, 9, 26, 0.92)",
        backdropFilter: "blur(24px)",
        WebkitBackdropFilter: "blur(24px)",
        borderRight: "1px solid rgba(0,212,255,0.08)",
      }}
      className="w-56 min-h-screen flex flex-col shrink-0 relative"
    >
      {/* Top accent line */}
      <div className="absolute top-0 left-0 right-0 h-px"
        style={{ background: "linear-gradient(90deg, transparent, rgba(0,212,255,0.4), transparent)" }} />

      {/* Logo */}
      <div className="px-5 pt-6 pb-5" style={{ borderBottom: "1px solid rgba(0,212,255,0.06)" }}>
        <div className="flex items-center gap-2 mb-1">
          <div className="w-6 h-6 rounded-md flex items-center justify-center"
            style={{ background: "linear-gradient(135deg, rgba(0,212,255,0.3), rgba(0,212,255,0.08))", border: "1px solid rgba(0,212,255,0.3)" }}>
            <Radio size={12} style={{ color: "var(--clr-cyan)" }} />
          </div>
          <span className="text-base font-bold tracking-widest neon-cyan">CYBERIA</span>
        </div>
        <div className="text-[10px] tracking-[0.18em] uppercase ml-8"
          style={{ color: "var(--clr-muted)" }}>
          Threat Intelligence
        </div>

        {/* Status bar */}
        <div className="flex items-center gap-2 mt-4 px-2 py-1.5 rounded-lg"
          style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.07)" }}>
          <div className="relative w-2 h-2 shrink-0">
            <span className={`absolute inset-0 rounded-full ${pc1Ok ? "bg-green-400" : "bg-red-500 blink"}`} />
            {pc1Ok && <span className="absolute inset-0 rounded-full bg-green-400 pulse-dot" />}
          </div>
          <span className="text-[10px] font-medium" style={{ color: pc1Ok ? "var(--clr-green)" : "var(--clr-red)" }}>
            {pc1Ok ? "PC1 Connected" : "PC1 Offline"}
          </span>
          {incidentCount > 0 && (
            <span className="ml-auto text-[10px] font-bold rounded-full px-1.5 py-0.5 tabular-nums"
              style={{ background: "rgba(255,45,85,0.2)", color: "var(--clr-red)", border: "1px solid rgba(255,45,85,0.35)" }}>
              {incidentCount}
            </span>
          )}
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        <div className="text-[9px] font-semibold tracking-[0.2em] uppercase px-3 mb-3"
          style={{ color: "rgba(100,116,139,0.5)" }}>
          Navigation
        </div>
        {pages.map(({ id, label, icon: Icon }, i) => {
          const isActive = active === id;
          return (
            <motion.button
              key={id}
              onClick={() => setActive(id)}
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.05 + i * 0.04, type: "spring", stiffness: 300, damping: 25 }}
              whileHover={{ x: isActive ? 0 : 3, transition: { duration: 0.15 } }}
              whileTap={{ scale: 0.97 }}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium transition-colors relative"
              style={isActive ? {
                background: "linear-gradient(135deg, rgba(0,212,255,0.14), rgba(0,212,255,0.04))",
                color: "var(--clr-cyan)",
                border: "1px solid rgba(0,212,255,0.22)",
                boxShadow: "0 2px 12px rgba(0,212,255,0.08)",
              } : {
                color: "var(--clr-muted)",
                border: "1px solid transparent",
              }}
            >
              {/* Active left accent */}
              {isActive && (
                <motion.div layoutId="nav-accent"
                  className="absolute left-0 top-2 bottom-2 w-0.5 rounded-full"
                  style={{ background: "var(--clr-cyan)", boxShadow: "0 0 6px var(--clr-cyan)" }} />
              )}
              <Icon size={15} />
              <span>{label}</span>
              {isActive && (
                <motion.div layoutId="active-dot"
                  className="ml-auto w-1 h-1 rounded-full"
                  style={{ background: "var(--clr-cyan)", boxShadow: "0 0 4px var(--clr-cyan)" }} />
              )}
            </motion.button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4" style={{ borderTop: "1px solid rgba(0,212,255,0.06)" }}>
        <div className="text-[10px] font-semibold" style={{ color: "var(--clr-muted)" }}>
          Banque Atlas — Demo
        </div>
        <div className="text-[9px] tracking-widest mt-0.5 uppercase"
          style={{ color: "rgba(100,116,139,0.35)" }}>
          Cyberia 2026
        </div>
      </div>

      {/* Bottom accent line */}
      <div className="absolute bottom-0 left-0 right-0 h-px"
        style={{ background: "linear-gradient(90deg, transparent, rgba(0,212,255,0.2), transparent)" }} />
    </motion.aside>
  );
}
