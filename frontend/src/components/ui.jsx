import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { statusLabel } from "../utils.js";

const ToastContext = createContext(() => {});
export const useToast = () => useContext(ToastContext);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const push = useCallback((message, tone = "info") => {
    const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    setToasts((current) => [...current, { id, message, tone }]);
    setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 4600);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.tone}`}>
            {toast.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const ICON_PATHS = {
  shield: "M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z",
  radar: "M12 12l5-5 M12 21a9 9 0 1 1 9-9 M12 17a5 5 0 1 1 5-5",
  bug: "M9 4l1.5 2M15 4l-1.5 2M5 9h3M16 9h3M5 15h2.5M16.5 15H19M12 6a5 5 0 0 1 5 5v3a5 5 0 0 1-10 0v-3a5 5 0 0 1 5-5z",
  feeds: "M4 6h16M4 12h10M4 18h7M18 15l2 2 2-2",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-3.5-3.5",
  activity: "M3 12h4l2-6 3 12 2-6h5",
  database: "M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
  refresh: "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
  arrow: "M5 12h14M13 6l6 6-6 6",
  close: "M6 6l12 12M18 6L6 18",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  download: "M12 4v10m0 0l-4-4m4 4l4-4M5 18h14",
  plus: "M12 5v14M5 12h14",
  target: "M12 3v3M12 18v3M3 12h3M18 12h3M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
  alert: "M12 4l9 16H3l9-16zM12 10v4M12 17h.01",
};

export function Icon({ name, size = 18, className = "" }) {
  const path = ICON_PATHS[name] || ICON_PATHS.shield;
  return (
    <svg
      className={`icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={path} />
    </svg>
  );
}

export function SeverityBadge({ severity = "medium" }) {
  return (
    <span className={`badge sev-${severity}`}>
      <i className="dot" />
      {severity}
    </span>
  );
}

export function StatusPill({ status }) {
  return <span className={`status-pill status-${(status || "").split("_")[0]}`}>{statusLabel(status)}</span>;
}

export function Card({ title, subtitle, actions, children, className = "", padded = true }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {subtitle && <p className="card-subtitle">{subtitle}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className={padded ? "card-body" : "card-body card-body-flush"}>{children}</div>
    </section>
  );
}

export function Loading({ label = "Loading intelligence…" }) {
  return (
    <div className="state-block">
      <span className="spinner" />
      <p>{label}</p>
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="state-block state-error">
      <Icon name="alert" size={22} />
      <p>{error?.message || "Something went wrong."}</p>
      {onRetry && (
        <button type="button" className="btn btn-ghost" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title = "Nothing here yet", message }) {
  return (
    <div className="state-block">
      <Icon name="search" size={22} />
      <p className="state-title">{title}</p>
      {message && <p className="state-message">{message}</p>}
    </div>
  );
}

export function Meter({ value = 0, max = 100, tone = "accent", label }) {
  const pct = Math.max(0, Math.min(100, (Number(value) / (max || 1)) * 100));
  return (
    <div className={`meter meter-${tone}`}>
      <div className="meter-track">
        <div className="meter-fill" style={{ width: `${pct}%` }} />
      </div>
      {label && <span className="meter-label">{label}</span>}
    </div>
  );
}

export function Drawer({ open, title, subtitle, onClose, children }) {
  useEffect(() => {
    if (!open) return undefined;
    const handler = (event) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="drawer-layer">
      <button type="button" className="drawer-backdrop" aria-label="Close panel" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <header className="drawer-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="close" size={18} />
          </button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

export function Modal({ open, title, onClose, children, footer }) {
  useEffect(() => {
    if (!open) return undefined;
    const handler = (event) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="modal-layer">
      <button type="button" className="drawer-backdrop" aria-label="Close dialog" onClick={onClose} />
      <div className="modal" role="dialog" aria-modal="true">
        <header className="modal-head">
          <h2>{title}</h2>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="close" size={18} />
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  );
}

export function Pagination({ page, pages, total, pageSize, onChange }) {
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  const pageNumbers = useMemo(() => {
    const numbers = [];
    const from = Math.max(1, page - 2);
    const to = Math.min(pages, from + 4);
    for (let index = from; index <= to; index += 1) numbers.push(index);
    return numbers;
  }, [page, pages]);

  return (
    <div className="pagination">
      <span className="pagination-info">
        {start}–{end} of {total}
      </span>
      <div className="pagination-controls">
        <button type="button" className="btn btn-ghost" disabled={page <= 1} onClick={() => onChange(page - 1)}>
          Prev
        </button>
        {pageNumbers.map((number) => (
          <button
            key={number}
            type="button"
            className={`page-chip ${number === page ? "is-active" : ""}`}
            onClick={() => onChange(number)}
          >
            {number}
          </button>
        ))}
        <button type="button" className="btn btn-ghost" disabled={page >= pages} onClick={() => onChange(page + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}
