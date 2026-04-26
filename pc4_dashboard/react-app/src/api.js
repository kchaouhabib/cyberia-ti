const BASE = "/api";

async function get(path, fallback) {
  try {
    const r = await fetch(`${BASE}${path}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return fallback;
    return r.json();
  } catch {
    return fallback;
  }
}

export const fetchIncidents   = () => get("/incidents",   []);
export const fetchPredictions = () => get("/predictions", []);
export const fetchTimeline    = (id) => get(`/incidents/${id}/timeline`, null);

export const fetchStats = async () => {
  const raw = await get("/stats", {});
  return {
    raw_records:         raw.raw_count            ?? raw.raw_records         ?? "—",
    iocs:                raw.ioc_count            ?? raw.iocs                ?? "—",
    incidents:           raw.incident_count       ?? raw.incidents           ?? "—",
    predictions:         raw.prediction_count     ?? raw.predictions         ?? "—",
    compliance_breaches: raw.compliance_breach_count ?? raw.compliance_breaches ?? "—",
  };
};

export function downloadExport(type, id) {
  const url = id ? `${BASE}/export/${type}?id=${id}` : `${BASE}/export/${type}`;
  const a = document.createElement("a");
  a.href = url;
  a.click();
}
