import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { useApi } from "../hooks.js";
import { Card, EmptyState, ErrorState, Icon, Loading, SeverityBadge, StatusPill } from "../components/ui.jsx";
import { formatDate, timeAgo, truncate, typeLabel } from "../utils.js";

const SUGGESTIONS = ["phishing", "ransomware", "botnet", "CVE-2021-44228", "192.0.2", "example.com", "c2"];

export default function Investigate() {
  const [params, setParams] = useSearchParams();
  const activeQuery = params.get("q") || "";
  const [term, setTerm] = useState(activeQuery);

  useEffect(() => setTerm(activeQuery), [activeQuery]);

  const { data, loading, error, refresh } = useApi(
    () => (activeQuery ? api.investigate(activeQuery) : Promise.resolve(null)),
    [activeQuery]
  );

  const submit = (event) => {
    event.preventDefault();
    const value = term.trim();
    setParams(value ? { q: value } : {});
  };

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">Investigation workspace</p>
          <h1 className="page-title">Investigate an Indicator</h1>
          <p className="page-subtitle">Pivot across indicators, vulnerabilities and feeds with a single query</p>
        </div>
      </div>

      <Card className="search-hero">
        <form className="search-form" onSubmit={submit}>
          <Icon name="search" size={20} />
          <input
            autoFocus
            value={term}
            onChange={(event) => setTerm(event.target.value)}
            placeholder="IP, domain, URL, hash, CVE ID, tag or threat category…"
            aria-label="Investigation query"
          />
          <button type="submit" className="btn btn-primary">
            Investigate
          </button>
        </form>

        <div className="suggestions">
          <span>Try:</span>
          {SUGGESTIONS.map((suggestion) => (
            <button
              key={suggestion}
              type="button"
              className="chip"
              onClick={() => {
                setTerm(suggestion);
                setParams({ q: suggestion });
              }}
            >
              {suggestion}
            </button>
          ))}
        </div>
      </Card>

      {!activeQuery ? (
        <Card>
          <EmptyState
            title="Start an investigation"
            message="Search any observable or CVE to see every feed, indicator and vulnerability that matches."
          />
        </Card>
      ) : loading && !data ? (
        <Card>
          <Loading label={`Searching for “${activeQuery}”…`} />
        </Card>
      ) : error ? (
        <Card>
          <ErrorState error={error} onRetry={refresh} />
        </Card>
      ) : (
        <>
          <div className="stat-strip">
            <div>
              <span>Matching indicators</span>
              <strong className="mono">{data.counts.indicators}</strong>
            </div>
            <div>
              <span>Matching CVEs</span>
              <strong className="mono">{data.counts.vulnerabilities}</strong>
            </div>
            <div>
              <span>Matching feeds</span>
              <strong className="mono">{data.counts.sources}</strong>
            </div>
            <div>
              <span>Total hits</span>
              <strong className="mono">{data.counts.total}</strong>
            </div>
          </div>

          {data.pivots.length > 0 && (
            <div className="pivot-row">
              <span className="pivot-label">Pivots</span>
              {data.pivots.map((pivot) => (
                <span key={`${pivot.threat_type}-${pivot.severity}`} className={`pivot-chip sev-${pivot.severity}`}>
                  {pivot.threat_type} · {pivot.count}
                </span>
              ))}
            </div>
          )}

          {data.indicators.length > 0 && (
            <Card
              title="Indicators"
              subtitle={data.counts.indicators > data.indicators.length ? `Showing ${data.indicators.length} of ${data.counts.indicators}` : undefined}
              padded={false}
            >
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Source</th>
                    <th>Last seen</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.indicators.map((indicator) => (
                    <tr key={indicator.id}>
                      <td className="mono cell-strong">{truncate(indicator.normalized, 52)}</td>
                      <td>
                        <span className="type-chip">{typeLabel(indicator.type)}</span>
                      </td>
                      <td>
                        <SeverityBadge severity={indicator.severity} />
                      </td>
                      <td className="muted">{indicator.threat_type}</td>
                      <td className="muted">{truncate(indicator.source_name, 26)}</td>
                      <td className="muted">{timeAgo(indicator.last_seen)}</td>
                      <td>
                        <StatusPill status={indicator.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          {data.vulnerabilities.length > 0 && (
            <Card title="Vulnerabilities" subtitle="CVEs matching the query" padded={false}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Title</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>Published</th>
                  </tr>
                </thead>
                <tbody>
                  {data.vulnerabilities.map((cve) => (
                    <tr key={cve.cve_id}>
                      <td className="mono cell-strong">{cve.cve_id}</td>
                      <td>{truncate(cve.title, 58)}</td>
                      <td className="mono">{cve.cvss.toFixed(1)}</td>
                      <td>
                        <SeverityBadge severity={cve.severity} />
                      </td>
                      <td className="muted">{formatDate(cve.published_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          {data.sources.length > 0 && (
            <Card title="Feeds" subtitle="Sources related to the query">
              <div className="source-mini-grid">
                {data.sources.map((source) => (
                  <div key={source.id} className="source-mini">
                    <strong>{source.name}</strong>
                    <span className="muted">
                      {source.kind} · {source.indicator_count} indicators
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {data.counts.total === 0 && (
            <Card>
              <EmptyState
                title="No matches found"
                message="Nothing in the corpus matches this query. Try a shorter term, a tag, or a threat category."
              />
            </Card>
          )}
        </>
      )}
    </>
  );
}
