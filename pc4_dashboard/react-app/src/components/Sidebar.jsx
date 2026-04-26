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
      initial={{ x: -52, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ type: "spring", stiffness: 260, damping: 28 }}
      className="flex flex-col shrink-0 items-center relative"
      style={{
        width: 52,
        minHeight: "100dvh",
        background: "var(--bg-panel)",
        borderRight: "1px solid var(--border)",
      }}
    >
      {/* Top accent */}
      <div className="absolute top-0 left-0 right-0 h-px"
        style={{ background: "linear-gradient(90deg, transparent, rgba(116,192,252,0.3), transparent)" }} />

      {/* Logo */}
      <div className="py-4 flex flex-col items-center gap-2.5 w-full"
        style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="w-7 h-7 rounded flex items-center justify-center"
          title="CYBERIA TI"
          style={{
            background: "rgba(116,192,252,0.10)",
            border: "1px solid rgba(116,192,252,0.22)",
          }}>
          <Radio size={12} style={{ color: "var(--info)" }} />
        </div>
        {/* PC1 status dot */}
        <div
          title={pc1Ok ? "PC1 Connected" : "PC1 Offline"}
          className="relative w-2 h-2"
        >
          <span
            className={`absolute inset-0 rounded-full ${pc1Ok ? "" : "blink"}`}
            style={{ background: pc1Ok ? "var(--low)" : "var(--critical)" }}
          />
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 flex flex-col items-center gap-1 py-3 w-full px-2">
        {pages.map(({ id, label, icon: Icon }, i) => {
          const isActive = active === id;
          return (
            <motion.button
              key={id}
              onClick={() => setActive(id)}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.06 + i * 0.04, type: "spring", stiffness: 300, damping: 25 }}
              whileTap={{ scale: 0.90 }}
              title={label}
              className="relative w-8 h-8 rounded-lg flex items-center justify-center transition-colors"
              style={isActive ? {
                background: "rgba(116,192,252,0.12)",
                color: "var(--info)",
                border: "1px solid rgba(116,192,252,0.22)",
              } : {
                color: "var(--dim)",
                border: "1px solid transparent",
              }}
            >
              {isActive && (
                <motion.div
                  layoutId="nav-accent"
                  className="absolute -left-2 top-1.5 bottom-1.5 w-0.5 rounded-full"
                  style={{ background: "var(--info)" }}
                />
              )}
              <Icon size={14} />
              {id === "alerts" && incidentCount > 0 && (
                <span
                  className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 rounded-full flex items-center justify-center font-bold"
                  style={{ fontSize: 8, background: "var(--critical)", color: "#fff" }}
                >
                  {incidentCount > 9 ? "9+" : incidentCount}
                </span>
              )}
            </motion.button>
          );
        })}
      </nav>

      {/* Bottom accent */}
      <div className="absolute bottom-0 left-0 right-0 h-px"
        style={{ background: "linear-gradient(90deg, transparent, rgba(116,192,252,0.15), transparent)" }} />
    </motion.aside>
  );
}
