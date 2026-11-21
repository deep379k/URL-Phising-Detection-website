async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}) },
    ...options
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success === false) {
    throw new Error(payload.error || `Request failed with status ${response.status}`);
  }
  return payload;
}

export const api = {
  scanUrl: url => request("/api/predict/url", { method: "POST", body: JSON.stringify({ url, live_checks: true }) }),
  scanManualUrlFeatures: features => request("/api/predict/url/manual", { method: "POST", body: JSON.stringify({ features }) }),
  scanMessage: message => request("/api/predict/message", { method: "POST", body: JSON.stringify({ message }) }),
  scanEmail: email => request("/api/predict/email", { method: "POST", body: JSON.stringify({ email }) }),
  adminSession: () => request("/api/admin/session"),
  adminLogin: (username, password) => request("/api/admin/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  adminLogout: () => request("/api/admin/logout", { method: "POST" }),
  health: () => request("/api/health"),
  modelMetrics: () => request("/api/model-metrics"),
  overview: () => request("/api/analytics/overview"),
  trends: () => request("/api/analytics/trends?days=30"),
  recent: () => request("/api/analytics/recent?limit=8")
};
