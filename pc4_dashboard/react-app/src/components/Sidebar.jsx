import { motion } from "framer-motion";
import { LayoutDashboard, AlertTriangle, Shield, Database, TrendingUp, Activity } from "lucide-react";

const pages = [
  { id: "overview",    label: "Overview",    icon: LayoutDashboard },
  { id: "alerts",      label: "Alerts",      icon: AlertTriangle },
  { id: "compliance",  label: "Compliance",  icon: Shield },
  { id: "assets",      label: "Assets",      icon: Database },
  { id: "predictions", label: "Predictions", icon: TrendingUp },
];

export default function Sidebar({ active, setActive, pc1Ok, incidentCount }) {
  return (
    <motion.aside
      initial={{ x: -80, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="w-56 min-h-screen bg-[#070f1f] border-r border-[#1e3a5f] flex flex-col shrink-0"
    >
      {/* Logo */}
      <div className="p-5 border-b border-[#1e3a5f]">
        <div className="text-lg font-bold neon-cyan tracking-wide">CYBERIA TI</div>
        <div className="text-xs text-[#64748b] mt-0.5">Banking Edition</div>
        <div className="flex items-center gap-2 mt-3">
          <span className={`w-2 h-2 rounded-full ${pc1Ok ? "bg-green-400" : "bg-red-500 blink"}`} />
          <span className="text-xs text-[#64748b]">{pc1Ok ? "Live" : "Offline"}</span>
          {incidentCount > 0 && (
            <span className="ml-auto text-xs bg-red-500/20 text-red-400 border border-red-500/40 rounded-full px-2 py-0.5">
              {incidentCount}
            </span>
          )}
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1">
        {pages.map(({ id, label, icon: Icon }) => {
          const isActive = active === id;
          return (
            <motion.button
              key={id}
              onClick={() => setActive(id)}
              whileHover={{ x: 4 }}
              whileTap={{ scale: 0.97 }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
                isActive
                  ? "bg-[#00d4ff15] text-[#00d4ff] border border-[#00d4ff30]"
                  : "text-[#64748b] hover:text-[#e8f4f8] hover:bg-[#0a1628]"
              }`}
            >
              <Icon size={16} />
              {label}
              {isActive && (
                <motion.div layoutId="active-dot"
                  className="ml-auto w-1.5 h-1.5 rounded-full bg-[#00d4ff]" />
              )}
            </motion.button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-[#1e3a5f]">
        <div className="flex items-center gap-2">
          <Activity size={12} className="text-[#00d4ff]" />
          <span className="text-xs text-[#64748b]">Banque Atlas Demo</span>
        </div>
        <div className="text-xs text-[#1e3a5f] mt-1">Cyberia 2026</div>
      </div>
    </motion.aside>
  );
}
