import { motion } from "framer-motion";

export default function Card({ children, className = "", glow = false, danger = false, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 280, damping: 24, delay }}
      whileHover={{ y: -2, transition: { duration: 0.18, ease: "easeOut" } }}
      className={`grad-border p-4 ${glow ? "glow-cyan" : ""} ${danger ? "glow-red" : ""} ${className}`}
    >
      {children}
    </motion.div>
  );
}

export function CardTitle({ icon: Icon, title, badge }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      {Icon && (
        <div className="p-1 rounded-md bg-[rgba(0,212,255,0.08)]">
          <Icon size={13} style={{ color: "var(--clr-cyan)" }} />
        </div>
      )}
      <span className="text-[11px] font-semibold uppercase tracking-[0.12em]"
        style={{ color: "var(--clr-text-sub)" }}>
        {title}
      </span>
      {badge !== undefined && (
        <span className="ml-auto text-[10px] font-semibold rounded-full px-2 py-0.5 tabular-nums"
          style={{
            background: "rgba(0,212,255,0.08)",
            color: "var(--clr-cyan)",
            border: "1px solid rgba(0,212,255,0.18)",
          }}>
          {badge}
        </span>
      )}
    </div>
  );
}
