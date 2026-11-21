import { AlertTriangle, CheckCircle2, ChevronRight, ExternalLink, LoaderCircle, LockKeyhole, RotateCcw, ScanSearch, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { useState } from "react";
import { api } from "../api";

const manualFeatures = [
  ["UsingIP", "IP address instead of domain"], ["PrefixSuffix-", "Dash in domain"],
  ["SubDomains", "Multiple subdomains"], ["HTTPS", "Uses HTTPS"],
  ["NonStdPort", "Non-standard port"], ["HTTPSDomainURL", "HTTPS text in domain"],
  ["RequestURL", "External request URLs"], ["AnchorURL", "Suspicious anchor URLs"],
  ["LinksInScriptTags", "Links in scripts"], ["ServerFormHandler", "Form handler"],
  ["InfoEmail", "Email information"], ["AbnormalURL", "Abnormal URL"],
  ["WebsiteForwarding", "URL forwarding"], ["StatusBarCust", "Status-bar customization"],
  ["DisableRightClick", "Right-click disabled"], ["AgeofDomain", "Domain age"],
  ["DNSRecording", "DNS record"], ["WebsiteTraffic", "Traffic level"],
  ["PageRank", "PageRank score"], ["GoogleIndex", "Google indexed"],
  ["StatsReport", "Statistical report"],
];

const emptyManualFeatures = () => Object.fromEntries(manualFeatures.map(([name]) => [name, 0]));

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [manualValues, setManualValues] = useState(emptyManualFeatures);
  const [manualResult, setManualResult] = useState(null);
  const [manualError, setManualError] = useState("");
  const [manualLoading, setManualLoading] = useState(false);

  async function submit(event) {
    event.preventDefault(); setLoading(true); setError(""); setResult(null);
    try { setResult(await api.scanUrl(url)); }
    catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }

  async function submitManual(event) {
    event.preventDefault(); setManualLoading(true); setManualError(""); setManualResult(null);
    try { setManualResult(await api.scanManualUrlFeatures(manualValues)); }
    catch (requestError) { setManualError(requestError.message); }
    finally { setManualLoading(false); }
  }

  function resetManual() {
    setManualValues(emptyManualFeatures()); setManualResult(null); setManualError("");
  }

  const phishing = result?.prediction === "Potential Phishing";
  const unverified = result?.prediction === "Unverified Domain";
  const caution = phishing || unverified;
  return <main className="scanner-page url-scanner section-wrap">
    <div className="page-heading"><p className="eyebrow">URL INTELLIGENCE</p><h1>Inspect a suspicious link</h1><p>Analyze URL structure, DNS, TLS, domain registration, and configured reputation providers.</p></div>
    <section className="scanner-card">
      <form onSubmit={submit}>
        <label htmlFor="url">URL or domain</label>
        <div className="url-input-wrap"><LockKeyhole size={19} /><input id="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://example.com/account" autoComplete="off" maxLength="2048" required /><button disabled={loading}>{loading ? <LoaderCircle className="spin" /> : <ScanSearch />}<span>{loading ? "Analyzing" : "Analyze URL"}</span></button></div>
        <p className="input-help">Page content is not downloaded in the web process. Network metadata and configured reputation providers are checked.</p>
      </form>
      {error && <div className="form-error"><AlertTriangle /> <div><strong>Unable to analyze this URL</strong><span>{error}</span></div></div>}
    </section>

    {result && <section className={`result-card ${phishing ? "result-danger" : unverified ? "result-warning" : "result-safe"}`}>
      <div className="result-summary">
        <span className="result-icon">{caution ? <ShieldAlert /> : <CheckCircle2 />}</span>
        <div><p className="eyebrow">ANALYSIS COMPLETE</p><h2>{result.prediction}</h2><p>{phishing ? "This URL contains signals that warrant additional verification." : unverified ? "No strong phishing pattern was found, but this domain has not been verified as legitimate." : "This recognized official domain has no strong phishing indicators."}</p></div>
        <span className={`risk-badge ${result.risk_level.toLowerCase()}`}>{result.risk_level} risk</span>
      </div>
      <div className="result-meta"><div><span>Analysis source</span><strong>{result.analysis_source === "security-rule" ? "Security safeguard" : result.analysis_source === "verification-policy" ? "Domain verification policy" : result.model_name}</strong></div><div><span>Model phishing probability</span><strong>{result.model_phishing_probability}%</strong></div><div><span>Stored in history</span><strong>{result.stored ? "Yes" : "Database not configured"}</strong></div></div>
      <div className="analyzed-url"><ExternalLink size={16} /><span>{result.url}</span></div>
      <div className="indicator-section"><h3>Detected indicators</h3>{result.indicators.length ? <div className="indicator-list">{result.indicators.map(item => <div key={item.feature}><AlertTriangle /><span>{item.message}</span><ChevronRight /></div>)}</div> : <div className="no-indicators"><CheckCircle2 /> No negative structural indicators were detected.</div>}</div>
      {result.live_intelligence?.checks?.length > 0 && <div className="indicator-section"><h3>Live intelligence checks</h3><div className="intelligence-grid">{result.live_intelligence.checks.map(check => <article key={check.name} className={`intelligence-check ${check.status}`}><span>{check.status === "passed" ? <CheckCircle2 /> : <AlertTriangle />}</span><div><strong>{check.name}</strong><small>{check.detail}</small></div><b>{check.status.replaceAll("_", " ")}</b></article>)}</div></div>}
      <p className="disclaimer">{result.disclaimer} Always verify sensitive requests through official channels.</p>
    </section>}

    <section className="advanced-feature-card">
      <div className="advanced-feature-heading"><span className="advanced-feature-icon"><SlidersHorizontal /></span><div><p className="eyebrow">ADVANCED MANUAL ANALYSIS</p><h2>Predict from model features</h2><p>Enter every legacy feature value, then run the 21-feature model. Use <b>-1</b> for phishing evidence, <b>0</b> for uncertain, and <b>1</b> for legitimate evidence.</p></div></div>
      <form onSubmit={submitManual}>
        <div className="manual-feature-grid">{manualFeatures.map(([name, description]) => <label key={name}><span><strong>{name}</strong><small>{description}</small></span><select value={manualValues[name]} onChange={event => setManualValues(values => ({ ...values, [name]: Number(event.target.value) }))} aria-label={`${name}: ${description}`}><option value="-1">-1 · Phishing</option><option value="0">0 · Uncertain</option><option value="1">1 · Legitimate</option></select></label>)}</div>
        {manualError && <div className="form-error"><AlertTriangle /><div><strong>Unable to run manual prediction</strong><span>{manualError}</span></div></div>}
        {manualResult && <div className={`manual-prediction ${manualResult.risk_level.toLowerCase()}`}><span>{manualResult.risk_level === "Low" ? <CheckCircle2 /> : <ShieldAlert />}</span><div><small>MANUAL MODEL RESULT</small><strong>{manualResult.prediction}</strong><p>{manualResult.feature_count} feature values analyzed · {manualResult.disclaimer}</p></div><b className={`risk-badge ${manualResult.risk_level.toLowerCase()}`}>{manualResult.risk_level} risk</b></div>}
        <div className="manual-actions"><button type="button" className="button secondary" onClick={resetManual}><RotateCcw /> Reset values</button><button type="submit" className="button primary" disabled={manualLoading}>{manualLoading ? <LoaderCircle className="spin" /> : <ScanSearch />} {manualLoading ? "Predicting" : "Predict from features"}</button></div>
      </form>
      <p className="disclaimer">This advanced form does not inspect a live website. Its accuracy depends on entering all feature values correctly.</p>
    </section>
  </main>;
}
