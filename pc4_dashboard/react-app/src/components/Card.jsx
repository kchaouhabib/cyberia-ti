import { motion } from "framer-motion";

export default function Card({ children, className = "", danger = false, delay = 0, glow = null }) {
  const glowStyle = danger
    ? { borderColor: "var(--critical-b)", boxShadow: "0 0 24px rgba(255,45,120,0.12), inset 0 0 24px rgba(255,45,120,0.03)" }
    : glow === "cyan"
    ? { borderColor: "rgba(0,212,255,0.25)", boxShadow: "0 0 24px rgba(0,212,255,0.08)" }
    : {};

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 260, damping: 24, delay }}
      className={`card p-4 ${className}`}
      style={glowStyle}
    >
      {children}
    </motion.div>
  );
}

export function CardTitle({ icon: Icon, title, badge, color = "var(--cyan)" }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      {Icon && <Icon size={11} style={{ color }} />}
      <span className="section-label">{title}</span>
      {badge !== undefined && (
        <span className="ml-auto mono tabular-nums"
          style={{
            fontSize: 9, fontWeight: 700,
            background: "rgba(0,212,255,0.08)",
            color: "var(--cyan)",
            border: "1px solid rgba(0,212,255,0.18)",
            borderRadius: 2,
            padding: "2px 7px",
            letterSpacing: "0.06em",
          }}>
          {badge}
        </span>
      )}
    </div>
  );
}
