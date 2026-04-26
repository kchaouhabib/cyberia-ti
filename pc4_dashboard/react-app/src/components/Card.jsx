import { motion } from "framer-motion";

export default function Card({ children, className = "", danger = false, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 280, damping: 24, delay }}
      className={`grad-border p-4 ${className}`}
      style={danger ? {
        borderColor: "rgba(255,107,107,0.35)",
        boxShadow: "0 0 0 1px rgba(255,107,107,0.08) inset",
      } : {}}
    >
      {children}
    </motion.div>
  );
}

export function CardTitle({ icon: Icon, title, badge }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      {Icon && <Icon size={11} style={{ color: "var(--info)" }} />}
      <span className="section-label" style={{ marginBottom: 0 }}>{title}</span>
      {badge !== undefined && (
        <span
          className="ml-auto tabular-nums"
          style={{
            fontSize: 10, fontWeight: 600,
            background: "rgba(116,192,252,0.08)",
            color: "var(--info)",
            border: "1px solid rgba(116,192,252,0.18)",
            borderRadius: 3,
            padding: "1px 6px",
          }}
        >
          {badge}
        </span>
      )}
    </div>
  );
}
