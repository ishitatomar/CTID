import { useMemo, useState } from "react";
import { api } from "../api.js";
import { useApi, useDebounced } from "../hooks.js";
import { Card, Drawer, EmptyState, ErrorState, Icon, Loading, Pagination, SeverityBadge } from "../components/ui.jsx";
import { SEVERITIES, formatDate, formatNumber } from "../utils.js";

function cvssTone(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

export default function Vulnerabilities() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [sort, setSort] = useState("cvss");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);

  const debounced = useDebounced(q, 300);
  const query = useMemo(
    () => ({
      q: debounced || undefined,
      severity,
      exploited: exploitedOnly ? true : undefined,
      sort,
      page,
      page_size: 10,
    }),
    [debounced, severity, exploitedOnly, sort, page]
  );

  const { data, loading, error, refresh } = useApi(() => api.vulnerabilities(query), [JSON.stringify(query)]);

  const update = (setter) => (value) => {
    setter(value);
    setPage(1);
  };

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">Vulnerability analysis</p>
          <h1 className="page-title">Vulnerability Intelligence</h1>
          <p className="page-subtitle">CVE records with CVSS severity, exploitation status and patch availability</p>
        </div>
      </div>

      {data && (
        <div className="kpi-grid kpi-grid-compact">
          <div className="stat-strip">
            <div>
              <span>Tracked CVEs</span>
              <strong className="mono">{formatNumber(data.summary.total)}</strong>
            </div>
            <div>
              <span>Exploited in the wild</span>
              <strong className="mono">{formatNumber(data.summary.exploited)}</strong>
            </div>
            <div>
              <span>Critical severity</span>
              <strong className="mono">{formatNumber(data.summary.by_severity.critical)}</strong>
            </div>
            <div>
              <span>Average CVSS</span>
              <strong className="mono">{data.summary.average_cvss}</strong>
            </div>
            <div>
              <span>Patch available</span>
              <strong className="mono">{formatNumber(data.summary.patch_available)}</strong>
            </div>
          </div>
        </div>
      )}

      <Card padded={false} className="filters-card">
        <div className="filters">
          <div className="search-inline">
            <Icon name="search" size={15} />
            <input
              type="search"
              value={q}
              placeholder="Search CVE, product, description…"
              onChange={(event) => update(setQ)(event.target.value)}
            />
          </div>

          <div className="chip-group">
            {["all", ...SEVERITIES].map((option) => (
              <button
                key={option}
                type="button"
                className={`chip ${severity === option ? "is-active" : ""}`}
                onClick={() => update(setSeverity)(option)}
              >
                {option === "all" ? "All severities" : option}
              </button>
            ))}
          </div>

          <label className="toggle">
            <input
              type="checkbox"
              checked={exploitedOnly}
              onChange={(event) => update(setExploitedOnly)(event.target.checked)}
            />
            <span>Exploited only</span>
          </label>

          <select className="select" value={sort} onChange={(event) => update(setSort)(event.target.value)}>
            <option value="cvss">Highest CVSS</option>
            <option value="published">Most recent</option>
            <option value="cve">CVE ID</option>
          </select>
        </div>
      </Card>

      {loading && !data ? (
        <Card>
          <Loading label="Loading vulnerability records…" />
        </Card>
      ) : error ? (
        <Card>
          <ErrorState error={error} onRetry={refresh} />
        </Card>
      ) : data.items.length === 0 ? (
        <Card>
          <EmptyState title="No vulnerabilities match" message="Try clearing the severity or exploitation filters." />
        </Card>
      ) : (
        <>
          <div className="cve-list">
            {data.items.map((cve) => (
              <article key={cve.cve_id} className="cve-card" onClick={() => setSelected(cve)}>
                <div className={`cve-score sev-fill-${cvssTone(cve.cvss)}`}>
                  <strong>{cve.cvss.toFixed(1)}</strong>
                  <span>CVSS</span>
                </div>

                <div className="cve-main">
                  <div className="cve-head">
                    <span className="mono cve-id">{cve.cve_id}</span>
                    <SeverityBadge severity={cve.severity} />
                    {cve.exploited && <span className="flag flag-danger">Exploited in the wild</span>}
                    {cve.patch_available && <span className="flag flag-ok">Patch available</span>}
                  </div>
                  <h3 className="cve-title">{cve.title}</h3>
                  <p className="cve-desc">{cve.description}</p>
                  <div className="cve-meta">
                    <span>
                      <Icon name="database" size={13} /> {cve.affected_products.slice(0, 2).join(", ")}
                    </span>
                    <span>
                      <Icon name="clock" size={13} /> Published {formatDate(cve.published_at)}
                    </span>
                    <span className="muted">{cve.source_name}</span>
                  </div>
                </div>
              </article>
            ))}
          </div>

          <Pagination page={data.page} pages={data.pages} total={data.total} pageSize={data.page_size} onChange={setPage} />
        </>
      )}

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.cve_id}
        subtitle="Vulnerability record"
      >
        {selected && (
          <>
            <div className="detail-hero">
              <SeverityBadge severity={selected.severity} />
              <span className="cvss-pill">CVSS {selected.cvss.toFixed(1)}</span>
              {selected.exploited && <span className="flag flag-danger">KEV listed</span>}
            </div>
            <h3 className="drawer-title">{selected.title}</h3>
            <p className="detail-description">{selected.description}</p>

            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Published</span>
                <span className="detail-value">{formatDate(selected.published_at)}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Last modified</span>
                <span className="detail-value">{formatDate(selected.modified_at)}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Patch available</span>
                <span className="detail-value">{selected.patch_available ? "Yes" : "No"}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Source</span>
                <span className="detail-value">{selected.source_name}</span>
              </div>
            </div>

            <p className="mini-heading">Affected products</p>
            <ul className="bullet-list">
              {selected.affected_products.map((product) => (
                <li key={product}>{product}</li>
              ))}
            </ul>

            <p className="mini-heading">References</p>
            <ul className="link-list">
              {selected.references.map((reference) => (
                <li key={reference}>
                  <a href={reference} target="_blank" rel="noreferrer noopener">
                    {reference}
                  </a>
                </li>
              ))}
            </ul>
          </>
        )}
      </Drawer>
    </>
  );
}
