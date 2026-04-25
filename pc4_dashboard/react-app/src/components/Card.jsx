import { motion } from "framer-motion";

export default function Card({ children, className = "", glow = false, danger = false, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className={`grad-border p-4 ${glow ? "glow-cyan" : ""} ${danger ? "glow-red" : ""} ${className}`}
    >
      {children}
    </motion.div>
  );
}

export function CardTitle({ icon: Icon, title, badge }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      {Icon && <Icon size={15} className="text-[#00d4ff]" />}
      <span className="text-xs font-bold text-[#64748b] uppercase tracking-widest">{title}</span>
      {badge !== undefined && (
        <span className="ml-auto text-xs bg-[#00d4ff15] text-[#00d4ff] border border-[#00d4ff30] rounded-full px-2 py-0.5">
          {badge}
        </span>
      )}
    </div>
  );
}
