const BASE = import.meta.env.VITE_API_BASE ?? "";

function qs(params = {}) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "" || value === "all") return;
    search.set(key, String(value));
  });
  const query = search.toString();
  return query ? `?${query}` : "";
}

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;
    try {
      const body = await response.json();
      if (body && body.detail) {
        detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      /* response had no JSON body */
    }
    throw new Error(detail);
  }

  if (response.status === 204) return null;
  return response.json();
}

export const api = {
  stats: (days = 14) => request(`/api/stats${qs({ days })}`),
  indicators: (params = {}) => request(`/api/indicators${qs(params)}`),
  indicator: (id) => request(`/api/indicators/${id}`),
  createIndicator: (body) => request("/api/indicators", { method: "POST", body: JSON.stringify(body) }),
  updateIndicator: (id, body) =>
    request(`/api/indicators/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  vulnerabilities: (params = {}) => request(`/api/vulnerabilities${qs(params)}`),
  sources: () => request("/api/sources"),
  pipelineRuns: (limit = 15) => request(`/api/pipeline/runs${qs({ limit })}`),
  pipelineStatus: () => request("/api/pipeline/status"),
  collectAll: (body = {}) => request("/api/pipeline/collect", { method: "POST", body: JSON.stringify(body) }),
  collectSource: (id) => request(`/api/sources/${id}/collect`, { method: "POST", body: JSON.stringify({}) }),
  updateSource: (id, body) => request(`/api/sources/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  investigate: (q) => request(`/api/investigate${qs({ q })}`),
};

export const exportUrl = (params = {}) => `${BASE}/api/indicators/export.csv${qs(params)}`;
