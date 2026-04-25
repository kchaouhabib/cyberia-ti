const PC1 = "http://100.67.61.250:8000";

async function get(path, fallback) {
  try {
    const r = await fetch(`${PC1}${path}`, { signal: AbortSignal.timeout(4000) });
    if (!r.ok) return fallback;
    return r.json();
  } catch {
    return fallback;
  }
}

export const fetchIncidents   = () => get("/incidents",   []);
export const fetchPredictions = () => get("/predictions", []);
export const fetchStats       = () => get("/stats",       {});
export const PC1_URL          = PC1;
