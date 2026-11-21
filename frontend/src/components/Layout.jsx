import { BarChart3, Mail, Menu, MessageSquareText, ScanSearch, ShieldCheck, X } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

export default function Layout() {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const close = () => setOpen(false);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="site-header">
        <NavLink className="brand" to="/" onClick={close}>
          <span className="brand-icon"><ShieldCheck size={22} /></span>
          <span className="brand-name"><strong>PHISH</strong><span>GUARD</span><em>AI</em></span>
        </NavLink>
        <button className="menu-button" aria-label="Toggle navigation" onClick={() => setOpen(value => !value)}>
          {open ? <X /> : <Menu />}
        </button>
        <nav className={open ? "nav-open" : ""} aria-label="Primary navigation">
          <NavLink to="/" onClick={close}>Home</NavLink>
          <NavLink to="/scanner/url" onClick={close}><ScanSearch size={16} /> URL Scanner</NavLink>
          <NavLink to="/scanner/message" onClick={close}><MessageSquareText size={16} /> Message Scanner</NavLink>
          <NavLink to="/scanner/email" onClick={close}><Mail size={16} /> Email Scanner</NavLink>
          <NavLink to="/admin" onClick={close}><BarChart3 size={16} /> Analytics</NavLink>
        </nav>
        <NavLink className="header-cta" to="/scanner/url">Analyze a link</NavLink>
      </header>
      <div id="main-content" className="route-stage" key={location.pathname}><Outlet /></div>
      <footer>
        <div className="brand"><span className="brand-icon"><ShieldCheck size={19} /></span><span className="brand-name"><strong>PHISH</strong><span>GUARD</span><em>AI</em></span></div>
        <div className="creator-signature"><strong>Designed & built by Deepanshu</strong><span>Machine-learning risk analysis for informational purposes. Always verify sensitive requests through official channels.</span></div>
      </footer>
    </div>
  );
}
