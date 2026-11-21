import { AlertTriangle, CheckCircle2, Link2, LoaderCircle, MessageSquareText, ShieldAlert, Tags } from "lucide-react";
import { useState } from "react";
import { api } from "../api";

export default function MessageScanner() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault(); setLoading(true); setError(""); setResult(null);
    try { setResult(await api.scanMessage(message)); }
    catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }

  const spam = result?.prediction === "Likely Spam";
  return <main className="scanner-page message-scanner section-wrap">
    <div className="page-heading"><p className="eyebrow">MESSAGE INTELLIGENCE</p><h1>Analyze a suspicious message</h1><p>Paste SMS or messaging content. PhishGuard checks spam language, scam themes, and embedded URLs without contacting the sender.</p></div>
    <section className="scanner-card message-card">
      <form onSubmit={submit}>
        <div className="field-heading"><label htmlFor="message">Message text</label><span>{message.length.toLocaleString()} / 10,000</span></div>
        <textarea id="message" value={message} onChange={event => setMessage(event.target.value)} placeholder="Paste the complete SMS or message here…" maxLength="10000" rows="9" required />
        <div className="message-actions"><p className="input-help">Raw private message content is not stored in scan history.</p><button className="button primary" disabled={loading}>{loading ? <LoaderCircle className="spin" /> : <MessageSquareText />} {loading ? "Analyzing" : "Analyze message"}</button></div>
      </form>
      {error && <div className="form-error"><AlertTriangle /><div><strong>Unable to analyze this message</strong><span>{error}</span></div></div>}
    </section>

    {result && <section className={`result-card ${spam ? "result-danger" : "result-safe"}`}>
      <div className="result-summary"><span className="result-icon">{spam ? <ShieldAlert /> : <CheckCircle2 />}</span><div><p className="eyebrow">TEXT CLASSIFICATION</p><h2>{result.prediction}</h2><p>{spam ? "The NLP model found language patterns associated with SMS spam." : "The NLP model did not find strong SMS spam patterns."}</p></div><span className={`risk-badge ${result.risk_level.toLowerCase()}`}>{result.risk_level} risk</span></div>
      <div className="result-meta"><div><span>Model</span><strong>{result.model_name}</strong></div><div><span>Spam probability</span><strong>{result.model_spam_probability}%</strong></div><div><span>Stored in history</span><strong>{result.stored ? "Metadata only" : "Database not configured"}</strong></div></div>

      <div className="message-result-grid">
        <div className="result-subpanel"><h3><Tags /> Scam-theme indicators</h3>{result.scam_themes.length ? <div className="theme-tags">{result.scam_themes.map(theme => <span key={theme.name}>{theme.name}</span>)}</div> : <p>No supported scam theme was detected.</p>}</div>
        <div className="result-subpanel"><h3><AlertTriangle /> Text indicators</h3>{result.indicators.length ? <ul>{result.indicators.map(item => <li key={item.name}><span>{item.name}</span><small>Matched “{item.evidence}”</small></li>)}</ul> : <p>No rule-based text indicators were detected.</p>}</div>
      </div>

      <div className="indicator-section"><h3>Embedded URL analysis</h3>{result.url_results.length ? <div className="embedded-links">{result.url_results.map(item => <div key={item.url}><Link2 /><span><strong>{item.prediction}</strong><small>{item.url}</small></span><b className={`risk-badge ${item.risk_level.toLowerCase()}`}>{item.risk_level}</b></div>)}</div> : <div className="no-indicators"><CheckCircle2 /> No URLs were found in this message.</div>}</div>
      <p className="disclaimer">{result.disclaimer} Theme indicators are rule-based and are not trained category predictions. Hindi and Hinglish accuracy has not yet been validated.</p>
    </section>}
  </main>;
}
