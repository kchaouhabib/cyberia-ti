import { motion } from "framer-motion";
import { Database, AlertTriangle, CheckCircle, Zap } from "lucide-react";
import Card, { CardTitle } from "../components/Card";

const SEV = { critical: "#ff2d78", high: "#ff8c00", medium: "#ffd700", low: "#00ff88" };

const ASSET_META = {
  treasury:        { label: "TREASURY",        icon: "🏛", desc: "Core banking, FX, investments" },
  payment_gateway: { label: "PAYMENT GATEWAY", icon: "💳", desc: "Card processing, SWIFT MT103" },
  customer_db:     { label: "CUSTOMER DB",     icon: "🗄", desc: "PII, account data, KYC records" },
  swift_terminal:  { label: "SWIFT TERMINAL",  icon: "⚡", desc: "Interbank messaging, wire transfers" },
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
  "Morocco": "🇲🇦", "MA": "🇲🇦",
};

function inferAssets(inc) {
  if (inc.targeted_assets?.length) return inc.targeted_assets;
  const types = new Set((inc.iocs || []).map(i => i.threat_type).filter(Boolean));
  const techs = new Set(inc.mitre_techniques || []);
  const assets = new Set();
  if (types.has("phishing")         || techs.has("T1566") || techs.has("T1539")) assets.add("customer_db");
  if (types.has("exfiltration")     || techs.has("T1041"))                        assets.add("treasury");
  if (types.has("lateral_movement") || techs.has("T1078"))                        assets.add("payment_gateway");
  if (types.has("malware"))                                                        assets.add("customer_db");
  if (techs.has("T1486")            || techs.has("T1071"))                        assets.add("swift_terminal");
  if (!assets.size)                                                                assets.add("customer_db");
  return [...assets];
}

function AssetCard({ assetKey, incidents, delay }) {
  const meta = ASSET_META[assetKey];
  const hot  = incidents.length > 0;
  const maxR = Math.max(...incidents.map(i => i.risk_score || 0), 0);
  const sev  = incidents.find(i => i.severity === "critical")?.severity
            || incidents.find(i => i.severity === "high")?.severity
            || incidents.find(i => i.severity === "medium")?.severity
            || (incidents.length ? "low" : null);
  const c    = SEV[sev] || "#00ff88";

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay, type: "spring", stiffness: 250, damping: 22 }}
      className="card p-5"
      style={hot ? { borderColor: `${c}35`, boxShadow: `0 0 24px ${c}10` } : {}}
    >
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="text-2xl mb-1">{meta?.icon}</div>
          <div className="font-orb font-bold" style={{ fontSize: 11, color: "var(--text)", letterSpacing: "0.08em" }}>{meta?.label}</div>
          <div className="section-label mt-0.5">{meta?.desc}</div>
        </div>
        {hot
          ? <AlertTriangle size={18} style={{ color: c }} className="blink" />
          : <CheckCircle  size={18} style={{ color: "var(--low)" }} />
        }
      </div>

      <div className="flex items-end gap-4 mb-4">
        <div>
          <div className="font-orb font-black"
            style={{ fontSize: 40, color: hot ? c : "var(--low)", textShadow: `0 0 20px ${hot ? c : "var(--low)"}80` }}>
            {incidents.length}
          </div>
          <div className="section-label">INCIDENT{incidents.length !== 1 ? "S" : ""}</div>
        </div>
        {hot && maxR > 0 && (
          <div>
            <div className="font-orb font-black" style={{ fontSize: 24, color: "var(--high)" }}>{maxR}</div>
            <div className="section-label">MAX RISK</div>
          </div>
        )}
      </div>

      {/* Status pill */}
      <div className="flex items-center gap-2 mb-3">
        <div className="w-1.5 h-1.5 rounded-full" style={{ background: hot ? c : "var(--low)", boxShadow: `0 0 8px ${hot ? c : "var(--low)"}` }} />
        <span className="font-orb" style={{ fontSize: 9, color: hot ? c : "var(--low)", letterSpacing: "0.12em" }}>
          {hot ? `${(sev || "").toUpperCase()} THREAT ACTIVE` : "SECURE"}
        </span>
      </div>

      {/* Linked incidents */}
      {incidents.slice(0, 3).map(inc => (
        <div key={inc.id} className="flex items-center gap-2 px-2 py-1.5 rounded mb-1"
          style={{ background: `${SEV[inc.severity] || "#00ff88"}0a`, border: `1px solid ${SEV[inc.severity] || "#00ff88"}18` }}>
          <span className="w-1 h-1 rounded-full shrink-0" style={{ background: SEV[inc.severity] || "#00ff88" }} />
          <span className="mono flex-1" style={{ fontSize: 9, color: "var(--muted)" }}>{inc.id?.slice(0, 12)}</span>
          <span className="mono font-bold" style={{ fontSize: 10, color: SEV[inc.severity] }}>{inc.risk_score}</span>
        </div>
      ))}
      {!hot && <div className="mono text-center py-2" style={{ fontSize: 9, color: "var(--low)", letterSpacing: "0.1em" }}>✓ NO ACTIVE THREATS</div>}
    </motion.div>
  );
}

export default function Assets({ incidents }) {
  const buckets = { treasury: [], payment_gateway: [], customer_db: [], swift_terminal: [] };
  incidents.forEach(inc => inferAssets(inc).forEach(a => { if (buckets[a]) buckets[a].push(inc); }));

  const geoHits = {};
  incidents.forEach(inc => inc.iocs?.forEach(ioc => {
    if (ioc.geolocation) geoHits[ioc.geolocation] = (geoHits[ioc.geolocation] || 0) + 1;
  }));
  const geoSorted = Object.entries(geoHits).sort((a, b) => b[1] - a[1]);
  const geoMax = geoSorted[0]?.[1] || 1;

  const aptHits = {};
  incidents.forEach(inc => inc.iocs?.forEach(ioc => {
    if (ioc.apt_attribution) aptHits[ioc.apt_attribution] = (aptHits[ioc.apt_attribution] || 0) + 1;
  }));
  const aptSorted = Object.entries(aptHits).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-4">
      {/* SWIFT emergency */}
      {buckets.swift_terminal.length > 0 && (
        <motion.div
          animate={{ opacity: [1, 0.7, 1] }}
          transition={{ repeat: Infinity, duration: 1.5 }}
          className="rounded-lg p-4 flex items-center gap-3"
          style={{ background: "var(--critical-bg)", border: "1px solid var(--critical-b)", boxShadow: "0 0 24px rgba(255,45,120,0.15)" }}>
          <Zap size={18} style={{ color: "var(--critical)" }} className="blink" />
          <div>
            <div className="font-orb font-bold" style={{ fontSize: 11, color: "var(--critical)", letterSpacing: "0.12em" }}>
              SWIFT TERMINAL COMPROMISED
            </div>
            <div className="mono mt-0.5" style={{ fontSize: 9, color: "rgba(255,45,120,0.7)", letterSpacing: "0.06em" }}>
              {buckets.swift_terminal.length} INCIDENT(S) — SWIFT CSP 2.x BREACH — NOTIFY WITHIN 24H
            </div>
          </div>
        </motion.div>
      )}

      {/* Asset grid */}
      <div className="grid grid-cols-4 gap-4">
        {Object.entries(buckets).map(([key, incs], i) => (
          <AssetCard key={key} assetKey={key} incidents={incs} delay={i * 0.07} />
        ))}
      </div>

      {/* Intelligence panels */}
      <div className="grid grid-cols-2 gap-4">
        {/* Geo origins */}
        <Card delay={0.3}>
          <CardTitle icon={Database} title="ATTACK ORIGINS" badge={geoSorted.length} />
          {geoSorted.length === 0 ? (
            <p className="mono text-center py-6" style={{ color: "var(--muted)", fontSize: 10 }}>NO GEOLOCATED IOCs YET</p>
          ) : (
            <div className="space-y-2">
              {geoSorted.map(([country, count], i) => (
                <motion.div key={country}
                  initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.3 + i * 0.05 }}
                  className="flex items-center gap-3 px-3 py-2 rounded"
                  style={{ background: "var(--bg-row)", border: "1px solid var(--border)" }}>
                  <span className="text-base shrink-0">{GEO_MAP[country] || "🌐"}</span>
                  <span style={{ color: "var(--text)", fontSize: 11, flex: 1 }}>{country}</span>
                  <div className="flex items-center gap-2">
                    <div className="prog-track" style={{ width: 64 }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(count / geoMax) * 100}%` }}
                        transition={{ delay: 0.5, duration: 0.7 }}
                        className="prog-bar"
                        style={{ background: "var(--critical)", boxShadow: "0 0 6px rgba(255,45,120,0.4)" }}
                      />
                    </div>
                    <span className="mono font-bold tabular-nums" style={{ fontSize: 10, color: "var(--critical)", width: 16 }}>{count}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </Card>

        {/* APT groups */}
        <Card delay={0.35}>
          <CardTitle icon={AlertTriangle} title="ACTIVE APT GROUPS" badge={aptSorted.length} color="var(--high)" />
          {aptSorted.length === 0 ? (
            <p className="mono text-center py-6" style={{ color: "var(--muted)", fontSize: 10 }}>NO APT ATTRIBUTION DATA YET</p>
          ) : (
            <div className="space-y-3">
              {aptSorted.map(([apt, count], i) => (
                <motion.div key={apt}
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                  transition={{ delay: 0.4 + i * 0.08 }}
                  className="p-3 rounded-lg"
                  style={{ background: "var(--high-bg)", border: "1px solid var(--high-b)" }}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-orb font-bold uppercase" style={{ fontSize: 10, color: "var(--high)", letterSpacing: "0.12em" }}>
                      {apt.replace("-", " ")}
                    </span>
                    <span className="mono" style={{ fontSize: 9, color: "var(--muted)" }}>{count} IOC{count !== 1 ? "s" : ""}</span>
                  </div>
                  <div className="prog-track">
                    <motion.div
                      initial={{ width: 0 }} animate={{ width: "100%" }}
                      transition={{ delay: 0.6, duration: 0.9 }}
                      className="prog-bar"
                      style={{ background: "var(--high)", boxShadow: "0 0 8px rgba(255,140,0,0.4)" }}
                    />
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
