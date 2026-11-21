import { Activity, AlertTriangle, BarChart3, Database, LoaderCircle, LogIn, LogOut, RefreshCw, ScanLine, ShieldAlert, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";

export default function AdminDashboard() {
  const [authenticated, setAuthenticated] = useState(null);
  const [credentials, setCredentials] = useState({ username: "", password: "" });
  const [loginState, setLoginState] = useState({ loading: false, error: "" });
  const [state, setState] = useState({ loading: true, error: "", overview: null, trends: [], recent: [], metrics: null, connected: false });
  const load = useCallback(async () => {
    setState(previous => ({ ...previous, loading: true, error: "" }));
    try {
      const [overview, trends, recent, metrics] = await Promise.all([api.overview(), api.trends(), api.recent(), api.modelMetrics()]);
      setState({ loading: false, error: "", overview: overview.data, trends: trends.data || [], recent: recent.data || [], metrics: metrics.url, connected: overview.database_connected });
    } catch (error) { setState(previous => ({ ...previous, loading: false, error: error.message })); }
  }, []);
  useEffect(() => { api.adminSession().then(data => setAuthenticated(data.authenticated)).catch(() => setAuthenticated(false)); }, []);
  useEffect(() => { if (authenticated) load(); }, [authenticated, load]);

  async function login(event) {
    event.preventDefault(); setLoginState({ loading: true, error: "" });
    try { await api.adminLogin(credentials.username, credentials.password); setAuthenticated(true); }
    catch (error) { setLoginState({ loading: false, error: error.message }); return; }
    setLoginState({ loading: false, error: "" });
  }

  async function logout() {
    await api.adminLogout(); setAuthenticated(false); setState(previous => ({ ...previous, overview: null, trends: [], recent: [] }));
  }

  const cards = [
    { label: "Total scans", value: state.overview?.total_scans, icon: ScanLine },
    { label: "Potential phishing", value: state.overview?.potential_phishing, icon: ShieldAlert },
    { label: "High-risk results", value: state.overview?.high_risk, icon: AlertTriangle },
    { label: "Phishing rate", value: state.overview ? `${state.overview.phishing_rate.toFixed(1)}%` : null, icon: Activity }
  ];

  if (authenticated === null) return <main className="dashboard-page section-wrap"><div className="admin-auth-loader"><LoaderCircle className="spin" /> Checking admin session...</div></main>;
  if (!authenticated) return <main className="dashboard-page section-wrap"><section className="admin-login-card"><span className="admin-login-icon"><ShieldCheck /></span><p className="eyebrow">SECURE ADMIN AREA</p><h1>Analytics sign in</h1><p>Enter the administrator credentials configured on the server.</p><form onSubmit={login}><label>Username<input value={credentials.username} onChange={event => setCredentials(value => ({ ...value, username: event.target.value }))} autoComplete="username" required /></label><label>Password<input type="password" value={credentials.password} onChange={event => setCredentials(value => ({ ...value, password: event.target.value }))} autoComplete="current-password" required /></label>{loginState.error && <div className="form-error"><AlertTriangle /><span>{loginState.error}</span></div>}<button className="button primary" disabled={loginState.loading}>{loginState.loading ? <LoaderCircle className="spin" /> : <LogIn />} {loginState.loading ? "Signing in" : "Sign in"}</button></form></section></main>;

  return <main className="dashboard-page section-wrap">
    <div className="dashboard-header"><div><p className="eyebrow">ADMIN ANALYTICS</p><h1>Threat intelligence overview</h1><p>Real activity from recorded PhishGuard scans.</p></div><div className="dashboard-actions"><button className="button secondary" onClick={load} disabled={state.loading}><RefreshCw className={state.loading ? "spin" : ""} /> Refresh</button><button className="button secondary" onClick={logout}><LogOut /> Sign out</button></div></div>
    {!state.connected && <div className="database-banner"><Database /><div><strong>Connect MySQL to activate analytics</strong><span>The interface is ready, but no metrics are fabricated while persistent storage is unavailable.</span></div></div>}
    {state.error && <div className="form-error"><AlertTriangle /><span>{state.error}</span></div>}
    <section className="metric-grid">{cards.map(({ label, value, icon: Icon }) => <article key={label}><div><span>{label}</span><strong>{value ?? "—"}</strong></div><span className="metric-icon"><Icon /></span></article>)}</section>
    <section className="dashboard-grid">
      <article className="dashboard-panel chart-card"><div className="panel-title"><div><p className="eyebrow">30-DAY ACTIVITY</p><h2>Scan volume and phishing trends</h2></div><BarChart3 /></div>{state.trends.length ? <ResponsiveContainer width="100%" height={320}><AreaChart data={state.trends}><defs><linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#55a7ff" stopOpacity={.35}/><stop offset="100%" stopColor="#55a7ff" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#1b293d" vertical={false}/><XAxis dataKey="date" stroke="#72829b" tickLine={false}/><YAxis stroke="#72829b" allowDecimals={false} tickLine={false}/><Tooltip contentStyle={{background:"#0d1625",border:"1px solid #24344c",borderRadius:12}}/><Area type="monotone" dataKey="total" stroke="#55a7ff" fill="url(#scanFill)" strokeWidth={2}/><Area type="monotone" dataKey="phishing" stroke="#ff5c75" fill="transparent" strokeWidth={2}/></AreaChart></ResponsiveContainer> : <div className="empty-state"><BarChart3 /><strong>No scan activity yet</strong><span>Trend data will appear after MySQL begins storing scans.</span></div>}</article>
      <article className="dashboard-panel model-card"><p className="eyebrow">ACTIVE URL MODEL</p><h2>{state.metrics?.selected_model || "Loading…"}</h2><div className="model-metrics"><div><span>Phishing recall</span><strong>{state.metrics ? `${(state.metrics.holdout.phishing_recall * 100).toFixed(1)}%` : "—"}</strong></div><div><span>ROC-AUC</span><strong>{state.metrics ? `${(state.metrics.holdout.roc_auc * 100).toFixed(1)}%` : "—"}</strong></div><div><span>Features</span><strong>{state.metrics?.dataset.features.length ?? "—"}</strong></div><div><span>Holdout rows</span><strong>{state.metrics?.dataset.test_rows ?? "—"}</strong></div></div><p>Evaluation values are loaded from the generated model artifact.</p></article>
    </section>
    <section className="dashboard-panel history-card"><div className="panel-title"><div><p className="eyebrow">LATEST ACTIVITY</p><h2>Recent scans</h2></div></div><div className="table-scroll"><table><thead><tr><th>Input</th><th>Prediction</th><th>Risk</th><th>Model</th><th>Time</th></tr></thead><tbody>{state.recent.length ? state.recent.map(row => <tr key={row.id}><td>{row.input_preview}</td><td><span className={`status-tag ${row.prediction === "Potential Phishing" ? "danger" : "safe"}`}>{row.prediction}</span></td><td>{row.risk_level}</td><td>{row.model_name}</td><td>{new Date(row.created_at).toLocaleString()}</td></tr>) : <tr><td colSpan="5" className="table-empty">No stored scans to display.</td></tr>}</tbody></table></div></section>
  </main>;
}
