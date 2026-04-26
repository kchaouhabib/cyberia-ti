import { motion } from "framer-motion";
import { Database, AlertTriangle, CheckCircle, Zap } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const SEV_COLOR = { critical: "#ff2d55", high: "#ff9f0a", medium: "#ffd60a", low: "#30d158" };

const ASSET_META = {
  treasury:        { label: "🏛 Treasury",        desc: "Core banking, FX, investments" },
  payment_gateway: { label: "💳 Payment Gateway",  desc: "Card processing, SWIFT MT103" },
  customer_db:     { label: "🗄 Customer DB",      desc: "PII, account data, KYC records" },
  swift_terminal:  { label: "⚡ SWIFT Terminal",   desc: "Interbank messaging, wire transfers" },
};

const GEO_MAP = {
  "Russia": "🇷🇺", "RU": "🇷🇺", "China": "🇨🇳", "CN": "🇨🇳",
  "North Korea": "🇰🇵", "KP": "🇰🇵", "Iran": "🇮🇷", "IR": "🇮🇷",
  "Romania": "🇷🇴", "RO": "🇷🇴", "Ukraine": "🇺🇦", "UA": "🇺🇦",
  "United States": "🇺🇸", "US": "🇺🇸", "Germany": "🇩🇪", "DE": "🇩🇪",
  "Netherlands": "🇳🇱", "NL": "🇳🇱", "Brazil": "🇧🇷", "BR": "🇧🇷",
  "India": "🇮🇳", "IN": "🇮🇳", "Turkey": "🇹🇷", "TR": "🇹🇷",
  "Nigeria": "🇳🇬", "NG": "🇳🇬", "France": "🇫🇷", "FR": "🇫🇷",
  "United Kingdom": "🇬🇧", "GB": "🇬🇧", "Tunisia": "🇹🇳", "TN": "🇹🇳",
};

function AssetCard({ assetKey, incidents, delay }) {
  const meta = ASSET_META[assetKey];
  const hot  = incidents.length > 0;
  const maxR = Math.max(...incidents.map(i => i.risk_score || 0), 0);
  const sev  = incidents.find(i => i.severity === "critical") ? "critical"
             : incidents.find(i => i.severity === "high")     ? "high"
             : incidents.find(i => i.severity === "medium")   ? "medium"
             : incidents.length ? "low" : null;
  const c    = SEV_COLOR[sev] || "#30d158";

  return (
    <motion.div initial={{ opacity: 0, scale: 0.92 }} animate={{ opacity: 1, scale: 1 }}
      transition={{ delay }} whileHover={{ scale: 1.02, y: -2 }}
      className={`grad-border p-5 ${hot ? "glow-red" : ""}`}>
      {/* Title */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-base font-bold text-[#e8f4f8]">{meta?.label}</div>
          <div className="text-xs text-[#64748b] mt-0.5">{meta?.desc}</div>
        </div>
        {hot
          ? <AlertTriangle size={20} style={{ color: c }} className="blink" />
          : <CheckCircle size={20} className="text-green-400" />
        }
      </div>

      {/* Stats */}
      <div className="flex items-end gap-4 mb-4">
        <div>
          <div className="text-4xl font-black" style={{ color: hot ? c : "#30d158", textShadow: hot ? `0 0 16px ${c}60` : "0 0 10px #30d15840" }}>
            {incidents.length}
          </div>
          <div className="text-xs text-[#64748b]">incident{incidents.length !== 1 ? "s" : ""}</div>
        </div>
        {hot && (
          <div>
            <div className="text-2xl font-black text-[#ff9f0a]">{maxR}</div>
            <div className="text-xs text-[#64748b]">max risk</div>
          </div>
        )}
      </div>

      {/* Status */}
      <div className="flex items-center gap-2 text-xs mb-3">
        <span className="w-2 h-2 rounded-full" style={{ background: hot ? c : "#30d158" }} />
        <span style={{ color: hot ? c : "#30d158" }}>{hot ? `${sev?.toUpperCase()} THREAT` : "SECURE"}</span>
      </div>

      {/* Recent incidents */}
      {incidents.slice(0, 3).map(inc => (
        <div key={inc.id} className="flex items-center gap-2 text-xs px-2 py-1.5 rounded-lg mb-1"
          style={{ background: (SEV_COLOR[inc.severity] || "#30d158") + "10", border: `1px solid ${SEV_COLOR[inc.severity] || "#30d158"}20` }}>
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_COLOR[inc.severity] || "#30d158" }} />
          <span className="font-mono text-[#64748b]">{inc.id?.slice(0, 8)}</span>
          <span className="ml-auto font-bold" style={{ color: SEV_COLOR[inc.severity] }}>{inc.risk_score}</span>
        </div>
      ))}
      {!hot && <div className="text-xs text-green-400 text-center py-2">✓ No active threats</div>}
    </motion.div>
  );
}

function inferAssets(inc) {
  if (inc.targeted_assets?.length) return inc.targeted_assets;
  const types  = new Set((inc.iocs || []).map(i => i.threat_type).filter(Boolean));
  const techs  = new Set(inc.mitre_techniques || []);
  const assets = new Set();
  if (types.has("phishing")         || techs.has("T1566") || techs.has("T1539")) assets.add("customer_db");
  if (types.has("exfiltration")     || techs.has("T1041"))                        assets.add("treasury");
  if (types.has("lateral_movement") || techs.has("T1078"))                        assets.add("payment_gateway");
  if (types.has("malware"))                                                        assets.add("customer_db");
  if (techs.has("T1486")            || techs.has("T1071"))                        assets.add("swift_terminal");
  if (!assets.size)                                                                assets.add("customer_db");
  return [...assets];
}

export default function Assets({ incidents }) {
  const buckets = { treasury: [], payment_gateway: [], customer_db: [], swift_terminal: [] };
  incidents.forEach(inc => inferAssets(inc).forEach(a => { if (buckets[a]) buckets[a].push(inc); }));

  // Attack origins from IOC geolocation
  const geoHits = {};
  incidents.forEach(inc => inc.iocs?.forEach(ioc => {
    if (ioc.geolocation) geoHits[ioc.geolocation] = (geoHits[ioc.geolocation] || 0) + 1;
  }));
  const geoSorted = Object.entries(geoHits).sort((a, b) => b[1] - a[1]);

  // APT groups
  const aptHits = {};
  incidents.forEach(inc => inc.iocs?.forEach(ioc => {
    if (ioc.apt_attribution) aptHits[ioc.apt_attribution] = (aptHits[ioc.apt_attribution] || 0) + 1;
  }));

  const swiftHit = buckets.swift_terminal.length > 0;

  return (
    <div className="space-y-4">
      {/* SWIFT emergency banner */}
      {swiftHit && (
        <motion.div animate={{ scale: [1, 1.01, 1] }} transition={{ repeat: Infinity, duration: 1.5 }}
          className="rounded-xl p-4 border border-red-500/60 bg-red-500/10 flex items-center gap-3">
          <Zap size={20} className="text-red-400 blink" />
          <div>
            <div className="text-red-400 font-bold">🚨 SWIFT Terminal Compromised</div>
            <div className="text-xs text-red-300/70">{buckets.swift_terminal.length} incident(s) — SWIFT CSP 2.x breach — notify within 24h</div>
          </div>
        </motion.div>
      )}

      {/* Asset cards */}
      <div className="grid grid-cols-2 gap-4">
        {Object.entries(buckets).slice(0, 4).map(([key, incs], i) => (
          <AssetCard key={key} assetKey={key} incidents={incs} delay={i * 0.08} />
        ))}
      </div>

      {/* Attack intelligence */}
      <div className="grid grid-cols-2 gap-4">
        {/* Geo origins */}
        <Card delay={0.3}>
          <CardTitle icon={Database} title="Attack Origins" badge={geoSorted.length} />
          {geoSorted.length === 0 ? (
            <p className="text-xs text-[#64748b] text-center py-6">No geolocated IOCs yet.</p>
          ) : (
            <div className="space-y-2">
              {geoSorted.map(([country, count], i) => (
                <motion.div key={country} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.3 + i * 0.05 }}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#0a1628] border border-[#1e3a5f]">
                  <span className="text-lg">{GEO_MAP[country] || "🌐"}</span>
                  <span className="text-sm text-[#e8f4f8] flex-1">{country}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 rounded-full bg-red-500/30 w-16 overflow-hidden">
                      <motion.div initial={{ width: 0 }} animate={{ width: `${(count / (geoSorted[0]?.[1] || 1)) * 100}%` }}
                        transition={{ delay: 0.5, duration: 0.6 }}
                        className="h-full bg-red-500 rounded-full" />
                    </div>
                    <span className="text-xs font-bold text-red-400 w-4">{count}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </Card>

        {/* APT panel */}
        <Card delay={0.35}>
          <CardTitle icon={AlertTriangle} title="Active APT Groups" badge={Object.keys(aptHits).length} />
          {Object.keys(aptHits).length === 0 ? (
            <p className="text-xs text-[#64748b] text-center py-6">No APT attribution data yet.</p>
          ) : (
            <div className="space-y-3">
              {Object.entries(aptHits).sort((a, b) => b[1] - a[1]).map(([apt, count], i) => (
                <motion.div key={apt} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 + i * 0.08 }}
                  className="p-3 rounded-xl border border-orange-500/30 bg-orange-500/10">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-orange-400 font-bold text-sm uppercase">{apt.replace("-", " ")}</span>
                    <span className="text-xs text-[#64748b]">{count} IOC{count !== 1 ? "s" : ""}</span>
                  </div>
                  <div className="h-1 rounded-full bg-orange-500/20 overflow-hidden">
                    <motion.div initial={{ width: 0 }} animate={{ width: "100%" }} transition={{ delay: 0.6, duration: 0.8 }}
                      className="h-full bg-orange-400 rounded-full" />
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
