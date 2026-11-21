import { AlertTriangle, CheckCircle2, Link2, LoaderCircle, Mail, ShieldAlert, Tags } from "lucide-react";
import { useState } from "react";
import { api } from "../api";

export default function EmailScanner() {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault(); setLoading(true); setError(""); setResult(null);
    try { setResult(await api.scanEmail(email)); }
    catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }

  const suspicious = result && result.prediction !== "Likely Legitimate";
  return <main className="scanner-page email-scanner section-wrap">
    <div className="page-heading"><p className="eyebrow">EMAIL RISK ANALYSIS</p><h1>Inspect a suspicious email</h1><p>Paste an email body or raw email text with headers. Attachments are not opened, downloaded, or executed.</p></div>
    <section className="scanner-card message-card">
      <form onSubmit={submit}>
        <div className="field-heading"><label htmlFor="email">Email content</label><span>{email.length.toLocaleString()} / 50,000</span></div>
        <textarea id="email" value={email} onChange={event => setEmail(event.target.value)} placeholder={'From: sender@example.com\nReply-To: reply@example.com\nSubject: Account notice\n\nPaste the email body here…'} maxLength="50000" rows="11" required />
        <div className="message-actions"><p className="input-help">Raw email content is analyzed in memory and is not stored in scan history.</p><button className="button primary" disabled={loading}>{loading ? <LoaderCircle className="spin" /> : <Mail />} {loading ? "Analyzing" : "Analyze email"}</button></div>
      </form>
      {error && <div className="form-error"><AlertTriangle /><div><strong>Unable to analyze this email</strong><span>{error}</span></div></div>}
    </section>

    {result && <section className={`result-card ${suspicious ? "result-danger" : "result-safe"}`}>
      <div className="result-summary"><span className="result-icon">{suspicious ? <ShieldAlert /> : <CheckCircle2 />}</span><div><p className="eyebrow">EMAIL ANALYSIS COMPLETE</p><h2>{result.prediction}</h2><p>{suspicious ? "The analysis found language, header, or URL signals requiring verification." : "No strong suspicious signals were identified by the available checks."}</p></div><span className={`risk-badge ${result.risk_level.toLowerCase()}`}>{result.risk_level} risk</span></div>
      <div className="result-meta"><div><span>Text classification</span><strong>{result.text_classification}</strong></div><div><span>Spam probability</span><strong>{result.model_spam_probability}%</strong></div><div><span>Stored in history</span><strong>{result.stored ? "Metadata only" : "Database not configured"}</strong></div></div>

      {(result.sender_domain || result.reply_to_domain || result.subject) && <div className="email-metadata"><div><span>Subject</span><strong>{result.subject || "Not provided"}</strong></div><div><span>Sender domain</span><strong>{result.sender_domain || "Not provided"}</strong></div><div><span>Reply-to domain</span><strong>{result.reply_to_domain || "Not provided"}</strong></div></div>}

      <div className="message-result-grid"><div className="result-subpanel"><h3><AlertTriangle /> Detected indicators</h3>{result.indicators.length ? <ul>{result.indicators.map((item, index) => <li key={`${item.name}-${index}`}><span>{item.name}</span><small>{item.evidence}</small></li>)}</ul> : <p>No email-specific text or header indicators were detected.</p>}</div><div className="result-subpanel"><h3><Tags /> Scam themes</h3>{result.scam_themes.length ? <div className="theme-tags">{result.scam_themes.map(theme => <span key={theme.name}>{theme.name}</span>)}</div> : <p>No supported scam theme was detected.</p>}</div></div>

      <div className="indicator-section"><h3>Embedded URL analysis</h3>{result.url_results.length ? <div className="embedded-links">{result.url_results.map(item => <div key={item.url}><Link2 /><span><strong>{item.prediction}</strong><small>{item.url}</small></span><b className={`risk-badge ${item.risk_level.toLowerCase()}`}>{item.risk_level}</b></div>)}</div> : <div className="no-indicators"><CheckCircle2 /> No URLs were found in this email.</div>}</div>
      <p className="disclaimer">{result.disclaimer} It provides decision support only and may produce false positives or false negatives.</p>
    </section>}
  </main>;
}
