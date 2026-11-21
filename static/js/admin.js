let trendChart;

const number = value => new Intl.NumberFormat().format(value);
const percent = value => `${Number(value).toFixed(1)}%`;
const escapeHtml = value => String(value ?? "").replace(/[&<>'"]/g, character => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
}[character]));

async function getJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  return response.json();
}

function setDatabaseState(connected) {
  document.querySelector("#database-alert").hidden = connected;
  document.querySelector("#status-dot").style.background = connected ? "#45f5a8" : "#d8a128";
  document.querySelector("#status-text").textContent = connected ? "All systems connected" : "MySQL setup required";
}

function renderOverview(payload) {
  if (!payload.database_connected || !payload.data) {
    setDatabaseState(false);
    return;
  }
  setDatabaseState(true);
  const data = payload.data;
  document.querySelector("#total-scans").textContent = number(data.total_scans);
  document.querySelector("#phishing-scans").textContent = number(data.potential_phishing);
  document.querySelector("#high-risk").textContent = number(data.high_risk);
  document.querySelector("#phishing-rate").textContent = percent(data.phishing_rate);
}

function renderTrends(payload) {
  const rows = payload.data || [];
  const empty = document.querySelector("#chart-empty");
  empty.hidden = rows.length > 0;
  if (!rows.length || typeof Chart === "undefined") return;
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(document.querySelector("#trend-chart"), {
    type: "line",
    data: {
      labels: rows.map(row => row.date),
      datasets: [
        { label: "All scans", data: rows.map(row => row.total), borderColor: "#55a7ff", backgroundColor: "rgba(85,167,255,.12)", fill: true, tension: .35 },
        { label: "Potential phishing", data: rows.map(row => row.phishing), borderColor: "#ff5c75", backgroundColor: "rgba(255,92,117,.08)", fill: true, tension: .35 }
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#8c9ab0" } } }, scales: { x: { ticks: { color: "#72829b" }, grid: { color: "#162237" } }, y: { beginAtZero: true, ticks: { color: "#72829b", precision: 0 }, grid: { color: "#162237" } } } }
  });
}

function renderRecent(payload) {
  const body = document.querySelector("#recent-scans");
  const rows = payload.data || [];
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No scans have been stored yet.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(row => {
    const predictionClass = row.prediction === "Potential Phishing" ? "phishing" : "safe";
    return `<tr><td>${escapeHtml(row.input_preview || row.input_type)}</td><td><span class="badge ${predictionClass}">${escapeHtml(row.prediction)}</span></td><td><span class="badge ${row.risk_level.toLowerCase()}">${escapeHtml(row.risk_level)}</span></td><td>${escapeHtml(row.model_name)}</td><td>${escapeHtml(new Date(row.created_at).toLocaleString())}</td></tr>`;
  }).join("");
}

function renderModel(payload) {
  const model = payload.url;
  document.querySelector("#model-name").textContent = model.selected_model;
  document.querySelector("#model-recall").textContent = percent(model.holdout.phishing_recall * 100);
  document.querySelector("#model-auc").textContent = percent(model.holdout.roc_auc * 100);
  document.querySelector("#model-features").textContent = number(model.dataset.features.length);
}

async function loadDashboard() {
  const button = document.querySelector("#refresh-button");
  button.disabled = true;
  button.textContent = "Refreshing…";
  try {
    const [overview, trends, recent, model] = await Promise.all([
      getJson("/api/analytics/overview"),
      getJson("/api/analytics/trends?days=30"),
      getJson("/api/analytics/recent?limit=10"),
      getJson("/api/model-metrics")
    ]);
    renderOverview(overview); renderTrends(trends); renderRecent(recent); renderModel(model);
  } catch (error) {
    document.querySelector("#status-text").textContent = "Service check failed";
    console.error(error);
  } finally {
    button.disabled = false;
    button.textContent = "Refresh data";
  }
}

document.querySelector("#refresh-button").addEventListener("click", loadDashboard);
loadDashboard();
