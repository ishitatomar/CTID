import { useMemo, useState } from "react";
import { api, exportUrl } from "../api.js";
import { useApi, useDebounced } from "../hooks.js";
import {
  Card,
  Drawer,
  EmptyState,
  ErrorState,
  Icon,
  Loading,
  Modal,
  Pagination,
  SeverityBadge,
  StatusPill,
  useToast,
} from "../components/ui.jsx";
import { SEVERITIES, formatDateTime, formatNumber, timeAgo, truncate, typeLabel } from "../utils.js";

const TYPE_OPTIONS = [
  { value: "all", label: "All types" },
  { value: "ip", label: "IP address" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "File hash" },
];

const EMPTY_FORM = {
  value: "",
  severity: "medium",
  confidence: 70,
  threat_type: "Phishing",
  description: "",
  tags: "",
  source_id: "",
};

export default function Indicators() {
  const toast = useToast();
  const [filters, setFilters] = useState({
    q: "",
    type: "all",
    severity: "all",
    source_id: "",
    status: "all",
    sort: "last_seen",
  });
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState(null);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const debouncedQuery = useDebounced(filters.q, 300);

  const query = useMemo(
    () => ({
      q: debouncedQuery || undefined,
      type: filters.type,
      severity: filters.severity,
      source_id: filters.source_id || undefined,
      status: filters.status,
      sort: filters.sort,
      page,
      page_size: 12,
    }),
    [debouncedQuery, filters.type, filters.severity, filters.source_id, filters.status, filters.sort, page]
  );

  const queryKey = JSON.stringify(query);
  const { data, loading, error, refresh } = useApi(() => api.indicators(query), [queryKey]);
  const detail = useApi(
    () => (selectedId ? api.indicator(selectedId) : Promise.resolve(null)),
    [selectedId]
  );

  const update = (patch) => {
    setFilters((current) => ({ ...current, ...patch }));
    setPage(1);
  };

  const submitForm = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await api.createIndicator({
        value: form.value.trim(),
        severity: form.severity,
        confidence: Number(form.confidence),
        threat_type: form.threat_type.trim() || "Uncategorized",
        description: form.description.trim(),
        tags: form.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        source_id: form.source_id ? Number(form.source_id) : undefined,
      });
      toast("Indicator added and stored in the intelligence database.", "success");
      setFormOpen(false);
      setForm(EMPTY_FORM);
      refresh();
    } catch (submitError) {
      toast(submitError.message, "error");
    } finally {
      setSaving(false);
    }
  };

  const changeStatus = async (status) => {
    try {
      await api.updateIndicator(selectedId, { status });
      toast(`Indicator marked as ${status.replace("_", " ")}.`, "success");
      detail.refresh();
      refresh();
    } catch (updateError) {
      toast(updateError.message, "error");
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">Indicator management</p>
          <h1 className="page-title">Indicators of Compromise</h1>
          <p className="page-subtitle">
            {data ? `${formatNumber(data.total)} indicators match the current filters` : "Searching the corpus…"}
          </p>
        </div>
        <div className="page-actions">
          <a className="btn btn-ghost" href={exportUrl(query)} download>
            <Icon name="download" size={15} /> Export CSV
          </a>
          <button type="button" className="btn btn-primary" onClick={() => setFormOpen(true)}>
            <Icon name="plus" size={15} /> Add indicator
          </button>
        </div>
      </div>

      <Card padded={false} className="filters-card">
        <div className="filters">
          <div className="search-inline">
            <Icon name="search" size={15} />
            <input
              type="search"
              value={filters.q}
              placeholder="Search value, tag, threat type…"
              onChange={(event) => update({ q: event.target.value })}
            />
          </div>

          <div className="chip-group">
            {TYPE_OPTIONS.map((option) => (
              <button
                key={option.value}
                type="button"
                className={`chip ${filters.type === option.value ? "is-active" : ""}`}
                onClick={() => update({ type: option.value })}
              >
                {option.label}
              </button>
            ))}
          </div>

          <select
            className="select"
            value={filters.severity}
            onChange={(event) => update({ severity: event.target.value })}
            aria-label="Filter by severity"
          >
            <option value="all">All severities</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>

          <select
            className="select"
            value={filters.source_id}
            onChange={(event) => update({ source_id: event.target.value })}
            aria-label="Filter by source"
          >
            <option value="">All sources</option>
            {(data?.facets.sources || []).map((source) => (
              <option key={source.id} value={source.id}>
                {source.name}
              </option>
            ))}
          </select>

          <select
            className="select"
            value={filters.status}
            onChange={(event) => update({ status: event.target.value })}
            aria-label="Filter by status"
          >
            <option value="all">Any status</option>
            <option value="active">Active</option>
            <option value="monitoring">Monitoring</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False positive</option>
          </select>

          <select
            className="select"
            value={filters.sort}
            onChange={(event) => update({ sort: event.target.value })}
            aria-label="Sort indicators"
          >
            <option value="last_seen">Newest activity</option>
            <option value="first_seen">First seen</option>
            <option value="severity">Severity</option>
            <option value="confidence">Confidence</option>
            <option value="reports">Report count</option>
          </select>
        </div>
      </Card>

      <Card padded={false}>
        {loading && !data ? (
          <Loading />
        ) : error ? (
          <ErrorState error={error} onRetry={refresh} />
        ) : data.items.length === 0 ? (
          <EmptyState title="No indicators found" message="Adjust the filters or run a new collection cycle." />
        ) : (
          <>
            <table className="data-table data-table-interactive">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Category</th>
                  <th>Source</th>
                  <th>Reports</th>
                  <th>Last seen</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((indicator) => (
                  <tr
                    key={indicator.id}
                    className="row-click"
                    onClick={() => setSelectedId(indicator.id)}
                    tabIndex={0}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") setSelectedId(indicator.id);
                    }}
                  >
                    <td>
                      <span className="mono cell-strong">{truncate(indicator.normalized, 44)}</span>
                      {indicator.hash_algorithm && <span className="cell-sub">{indicator.hash_algorithm}</span>}
                    </td>
                    <td>
                      <span className="type-chip">{typeLabel(indicator.type)}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={indicator.severity} />
                    </td>
                    <td>
                      <div className="confidence">
                        <span className="confidence-track">
                          <span style={{ width: `${indicator.confidence}%` }} />
                        </span>
                        <span className="mono">{indicator.confidence}%</span>
                      </div>
                    </td>
                    <td className="muted">{indicator.threat_type}</td>
                    <td className="muted">{truncate(indicator.source_name, 22)}</td>
                    <td className="mono">{indicator.report_count}</td>
                    <td className="muted">{timeAgo(indicator.last_seen)}</td>
                    <td>
                      <StatusPill status={indicator.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <Pagination
              page={data.page}
              pages={data.pages}
              total={data.total}
              pageSize={data.page_size}
              onChange={setPage}
            />
          </>
        )}
      </Card>

      <Drawer
        open={Boolean(selectedId)}
        onClose={() => setSelectedId(null)}
        title={detail.data ? "Indicator detail" : "Loading indicator"}
        subtitle={detail.data?.threat_type}
      >
        {detail.loading && !detail.data ? (
          <Loading />
        ) : detail.error ? (
          <ErrorState error={detail.error} onRetry={detail.refresh} />
        ) : detail.data ? (
          <>
            <div className="detail-hero">
              <span className="type-chip">{typeLabel(detail.data.type)}</span>
              <SeverityBadge severity={detail.data.severity} />
              <StatusPill status={detail.data.status} />
            </div>
            <p className="detail-value mono">{detail.data.normalized}</p>
            {detail.data.value !== detail.data.normalized && (
              <p className="detail-raw">Reported as: <span className="mono">{detail.data.value}</span></p>
            )}

            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Source</span>
                <span className="detail-value">{detail.data.source_name}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Confidence</span>
                <span className="detail-value mono">{detail.data.confidence}%</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Reports</span>
                <span className="detail-value mono">{detail.data.report_count}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Country</span>
                <span className="detail-value">{detail.data.country || "—"}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">First seen</span>
                <span className="detail-value">{formatDateTime(detail.data.first_seen)}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Last seen</span>
                <span className="detail-value">{formatDateTime(detail.data.last_seen)}</span>
              </div>
            </div>

            {detail.data.tags.length > 0 && (
              <div className="tag-row">
                {detail.data.tags.map((tag) => (
                  <span key={tag} className="tag">
                    {tag}
                  </span>
                ))}
              </div>
            )}

            <p className="detail-description">{detail.data.description || "No analyst notes recorded."}</p>

            <div className="drawer-actions">
              <button type="button" className="btn btn-ghost" onClick={() => changeStatus("monitoring")}>
                Monitor
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => changeStatus("resolved")}>
                Resolve
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => changeStatus("false_positive")}>
                False positive
              </button>
            </div>

            {detail.data.related.length > 0 && (
              <>
                <p className="mini-heading">Related indicators</p>
                <ul className="related-list">
                  {detail.data.related.map((item) => (
                    <li key={item.id}>
                      <button type="button" onClick={() => setSelectedId(item.id)}>
                        <span className="mono">{truncate(item.normalized, 38)}</span>
                        <SeverityBadge severity={item.severity} />
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </>
        ) : null}
      </Drawer>

      <Modal open={formOpen} onClose={() => setFormOpen(false)} title="Add indicator manually">
        <form onSubmit={submitForm} className="form">
          <label className="field">
            <span>Indicator value</span>
            <input
              required
              value={form.value}
              onChange={(event) => setForm({ ...form, value: event.target.value })}
              placeholder="hxxps://login-verify-01[.]example/portal"
            />
            <small>Defanged values (hxxp, [.]) are refanged automatically.</small>
          </label>

          <div className="form-grid">
            <label className="field">
              <span>Severity</span>
              <select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}>
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {severity}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Confidence ({form.confidence}%)</span>
              <input
                type="range"
                min="0"
                max="100"
                value={form.confidence}
                onChange={(event) => setForm({ ...form, confidence: event.target.value })}
              />
            </label>
          </div>

          <div className="form-grid">
            <label className="field">
              <span>Threat category</span>
              <input
                value={form.threat_type}
                onChange={(event) => setForm({ ...form, threat_type: event.target.value })}
                placeholder="Phishing"
              />
            </label>
            <label className="field">
              <span>Source</span>
              <select value={form.source_id} onChange={(event) => setForm({ ...form, source_id: event.target.value })}>
                <option value="">Default source</option>
                {(data?.facets.sources || []).map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="field">
            <span>Tags</span>
            <input
              value={form.tags}
              onChange={(event) => setForm({ ...form, tags: event.target.value })}
              placeholder="phishing, credential-theft"
            />
          </label>

          <label className="field">
            <span>Analyst notes</span>
            <textarea
              rows={3}
              value={form.description}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
              placeholder="Context for this indicator…"
            />
          </label>

          <div className="form-actions">
            <button type="button" className="btn btn-ghost" onClick={() => setFormOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Storing…" : "Store indicator"}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
