import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { useUtcClock } from "../hooks.js";
import { Icon, useToast } from "./ui.jsx";

const NAV = [
  { to: "/", label: "Overview", icon: "shield", end: true },
  { to: "/indicators", label: "Indicators", icon: "target" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: "bug" },
  { to: "/feeds", label: "Feeds & Pipeline", icon: "feeds" },
  { to: "/investigate", label: "Investigate", icon: "search" },
];

export default function Layout() {
  const navigate = useNavigate();
  const toast = useToast();
  const clock = useUtcClock();
  const [term, setTerm] = useState("");
  const [collecting, setCollecting] = useState(false);

  const submitSearch = (event) => {
    event.preventDefault();
    const query = term.trim();
    if (!query) return;
    navigate(`/investigate?q=${encodeURIComponent(query)}`);
  };

  const runCollection = async () => {
    setCollecting(true);
    try {
      const result = await api.collectAll({});
      const { collected, stored, duplicates, rejected } = result.totals;
      toast(
        `Collection complete — ${collected} records pulled, ${stored} new indicators, ${duplicates} duplicates merged, ${rejected} rejected.`,
        "success"
      );
      window.dispatchEvent(new CustomEvent("cti:refresh"));
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setCollecting(false);
    }
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="shield" size={20} />
          </span>
          <span className="brand-text">
            <strong>CTI Sentinel</strong>
            <small>Threat Intelligence</small>
          </span>
        </div>

        <nav className="nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-item ${isActive ? "is-active" : ""}`}
            >
              <Icon name={item.icon} size={18} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="feed-indicator">
            <span className="live-dot" />
            <span>Pipeline idle</span>
          </div>
          <p className="sidebar-note">
            Demo corpus uses RFC 2606 / RFC 5737 reserved ranges — no live infrastructure is referenced.
          </p>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <form className="search" onSubmit={submitSearch} role="search">
            <Icon name="search" size={16} />
            <input
              type="search"
              value={term}
              onChange={(event) => setTerm(event.target.value)}
              placeholder="Search indicators, CVEs, tags…"
              aria-label="Search threat intelligence"
            />
            <kbd>↵</kbd>
          </form>

          <div className="topbar-right">
            <span className="utc-clock" title="Coordinated Universal Time">
              <Icon name="clock" size={14} />
              {clock.toISOString().slice(11, 19)} UTC
            </span>
            <button type="button" className="btn btn-primary" onClick={runCollection} disabled={collecting}>
              <Icon name="refresh" size={15} className={collecting ? "spin" : ""} />
              {collecting ? "Collecting…" : "Run collection"}
            </button>
          </div>
        </header>

        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
