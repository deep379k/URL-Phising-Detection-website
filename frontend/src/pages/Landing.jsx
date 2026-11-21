import { AtSign, CheckCircle2, Link2, Mail, MessageSquareText, ScanSearch, Send, ShieldCheck, Sparkles } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";

const channels = [
  { icon: Link2, title: "URL intelligence", text: "Inspect structural link signals using a reproducible machine-learning pipeline.", active: true },
  { icon: Mail, title: "Email analysis", text: "Inspect suspicious language, header mismatches, and embedded links.", active: true, route: "/scanner/email" },
  { icon: MessageSquareText, title: "Message scams", text: "Analyze pasted SMS and messaging content for spam and scam-theme indicators.", active: true, route: "/scanner/message" }
];

export default function Landing() {
  const [contact, setContact] = useState({ name: "", email: "", subject: "", message: "" });

  function openGmail(event) {
    event.preventDefault();
    const subject = encodeURIComponent(contact.subject || `PhishGuard AI enquiry from ${contact.name}`);
    const body = encodeURIComponent(`Name: ${contact.name}\nEmail: ${contact.email}\n\n${contact.message}`);
    window.open(`https://mail.google.com/mail/?view=cm&fs=1&to=deepanshu739k@gmail.com&su=${subject}&body=${body}`, "_blank", "noopener,noreferrer");
  }

  return <main className="landing-page">
    <section className="hero section-wrap">
      <div className="hero-copy">
        <div className="pill"><Sparkles size={14} /> Explainable phishing analysis</div>
        <h1>Know the risk <span>before you click.</span></h1>
        <p>PhishGuard AI helps you inspect suspicious digital communications through transparent machine-learning analysis and understandable security indicators.</p>
        <div className="trust-row"><span><CheckCircle2 /> No links opened</span><span><CheckCircle2 /> Explainable indicators</span><span><CheckCircle2 /> Honest model metrics</span></div>
      </div>
      <div className="hero-visual">
        <div className="hero-media-frame">
          <img src="/media/phishguard-link-visual.gif" alt="Animated chain link surrounded by web and security symbols" />
          <div className="media-caption"><span><ShieldCheck size={18} /> Multi-signal protection</span><small>URL · Message · Email</small></div>
        </div>
      </div>
    </section>

    <section className="channels-section section-wrap section-block">
      <div className="section-heading"><p className="eyebrow">MULTI-CHANNEL DEFENCE</p><h2>One platform, three analysis paths</h2><p>Each channel uses an independent, measurable model. Results are never merged into an unsupported score.</p></div>
      <div className="channel-grid">{channels.map(({ icon: Icon, title, text, active, route }) => <article className="channel-card" key={title}><span className="channel-icon"><Icon /></span><div className={`availability ${active ? "ready" : "planned"}`}>{active ? "AVAILABLE" : "PLANNED"}</div><h3>{title}</h3><p>{text}</p>{active ? <Link to={route || "/scanner/url"}>Start analysis</Link> : <span className="muted-link">NLP module coming next</span>}</article>)}</div>
    </section>

    <section className="workflow-band section-block">
      <div className="workflow-showcase section-wrap">
        <div className="workflow-media"><img src="/media/url-workflow.gif" alt="Animation showing a URL being entered into a detector" /></div>
        <div className="workflow-copy">
          <p className="eyebrow">DESIGNED FOR CLARITY</p>
          <h2>From suspicious input to useful evidence.</h2>
          <p>PhishGuard keeps the experience simple while showing the signals behind its result. Nothing is opened automatically, and every classification includes practical context.</p>
          <div className="workflow-points">
            <article><CheckCircle2 /><div><h3>Submit safely</h3><p>Paste the suspicious content without visiting its destination.</p></div></article>
            <article><CheckCircle2 /><div><h3>Analyze the signals</h3><p>Purpose-built models evaluate URLs and suspicious language.</p></div></article>
            <article><CheckCircle2 /><div><h3>Understand the result</h3><p>Review the risk level, indicators, and model limitations.</p></div></article>
          </div>
          <Link className="button primary" to="/scanner/url"><ScanSearch size={18} /> Open URL scanner</Link>
        </div>
      </div>
    </section>

    <section className="contact-band section-block" id="contact">
      <div className="contact-layout section-wrap">
        <div className="contact-copy"><p className="eyebrow">CONTACT THE CREATOR</p><h2>Have feedback or want to collaborate?</h2><p>Send a question, report an issue, or share an idea for PhishGuard AI. Your message opens securely in Gmail and is sent from your own account.</p><a className="contact-email" href="mailto:deepanshu739k@gmail.com"><span><AtSign /></span><div><small>EMAIL DEEPANSHU</small><strong>deepanshu739k@gmail.com</strong></div></a></div>
        <form className="contact-form" onSubmit={openGmail}><div className="contact-row"><label>Your name<input value={contact.name} onChange={event => setContact(value => ({ ...value, name: event.target.value }))} placeholder="Enter your name" required /></label><label>Your email<input type="email" value={contact.email} onChange={event => setContact(value => ({ ...value, email: event.target.value }))} placeholder="you@example.com" required /></label></div><label>Subject<input value={contact.subject} onChange={event => setContact(value => ({ ...value, subject: event.target.value }))} placeholder="What would you like to discuss?" required /></label><label>Message<textarea value={contact.message} onChange={event => setContact(value => ({ ...value, message: event.target.value }))} placeholder="Write your message here..." rows="6" maxLength="3000" required /></label><button className="button primary" type="submit"><Send /> Continue in Gmail</button><p>No message content is stored by PhishGuard AI.</p></form>
      </div>
    </section>
  </main>;
}
