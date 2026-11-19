import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { useApi } from "../hooks.js";
import { Card, ErrorState, Icon, Loading, SeverityBadge, StatusPill } from "../components/ui.jsx";
import { CategoryBars, SeverityDonut, SourceBars, TrendChart } from "../components/charts.jsx";
import { formatNumber, timeAgo, typeLabel, truncate } from "../utils.js";

function Kpi({ label, value, sub, icon, tone = "accent", meter }) {
  return (
    <article className={`kpi kpi-${tone}`}>
      <span className="kpi-icon">
        <Icon name={icon} size={18} />
      </span>
      <div className="kpi-body">
        <p className="kpi-label">{label}</p>
        <strong className="kpi-value">{value}</strong>
        {sub && <p className="kpi-sub">{sub}</p>}
      </div>
      {typeof meter === "number" && (
        <div className="kpi-bar">
          <span style={{ width: `${Math.min(100, Math.max(2, meter))}%` }} />
        </div>
      )}
    </article>
  );
}

export default function Overview() {
  const [days, setDays] = useState(14);
  const { data, loading, error, refresh } = useApi(() => api.stats(days), [days]);

  if (loading && !data) return <Loading label="Aggregating threat intelligence…" />;
  if (error) return <ErrorState error={error} onRetry={refresh} />;

  const totals = data.totals;
  const severity = data.by_severity;
  const critical = severity.find((item) => item.severity === "critical")?.count || 0;
  const high = severity.find((item) => item.severity === "high")?.count || 0;
  const windowTotal = data.trend.reduce((sum, day) => sum + day.total, 0);

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">Security operations · live overview</p>
          <h1 className="page-title">Threat Intelligence Overview</h1>
          <p className="page-subtitle">
            Aggregated from {totals.active_sources} authorized feeds · normalized and deduplicated in the processing pipeline
          </p>
        </div>
        <div className="page-actions">
          <div className="segmented" role="group" aria-label="Trend window">
            {[7, 14, 30].map((option) => (
              <button
                key={option}
                type="button"
                className={days === option ? "is-active" : ""}
                onClick={() => setDays(option)}
              >
                {option}d
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="kpi-grid">
        <Kpi
          label="Tracked indicators"
          value={formatNumber(totals.indicators)}
          sub={`${formatNumber(totals.active_indicators)} currently active`}
          icon="target"
          meter={(totals.active_indicators / Math.max(1, totals.indicators)) * 100}
        />
        <Kpi
          label="Critical exposure"
          value={formatNumber(critical)}
          sub={`${formatNumber(high)} high severity`}
          icon="alert"
          tone="critical"
          meter={(critical / Math.max(1, totals.indicators)) * 100}
        />
        <Kpi
          label="New in 24 hours"
          value={formatNumber(totals.new_24h)}
          sub={`${formatNumber(windowTotal)} added this window`}
          icon="activity"
          tone="info"
        />
        <Kpi
          label="Threat pressure"
          value={`${totals.threat_pressure}%`}
          sub="Severity-weighted index"
          icon="radar"
          tone="warn"
          meter={totals.threat_pressure}
        />
        <Kpi
          label="Exploited CVEs"
          value={formatNumber(totals.cve_exploited)}
          sub={`${formatNumber(totals.cves)} vulnerabilities tracked`}
          icon="bug"
          tone="violet"
        />
      </div>

      <div className="grid">
        <Card
          className="span-8"
          title="Indicator volume by severity"
          subtitle={`Daily intake across the last ${days} days`}
          actions={
            <Link className="link-arrow" to="/indicators">
              Investigate <Icon name="arrow" size={14} />
            </Link>
          }
        >
          <div className="legend">
            {severity.map((item) => (
              <span key={item.severity} className={`legend-item sev-${item.severity}`}>
                <i className="dot" />
                {item.severity} · {formatNumber(item.count)}
              </span>
            ))}
          </div>
          <TrendChart data={data.trend} />
        </Card>

        <Card className="span-4" title="Severity distribution" subtitle="Share of tracked indicators">
          <SeverityDonut data={severity} />
          <div className="severity-rows">
            {severity.map((item) => (
              <div key={item.severity} className="severity-row">
                <SeverityBadge severity={item.severity} />
                <span className="mono">{formatNumber(item.count)}</span>
                <span className="severity-share">
                  {totals.indicators ? Math.round((item.count / totals.indicators) * 100) : 0}%
                </span>
              </div>
            ))}
          </div>
        </Card>

        <Card className="span-5" title="Indicators by source" subtitle="Coverage per authorized feed">
          <SourceBars data={data.by_source} />
        </Card>

        <Card className="span-4" title="Top threat categories" subtitle="Classification of tracked indicators">
          <CategoryBars data={data.by_category} />
        </Card>

        <Card className="span-3" title="Ingestion health" subtitle="Collection pipeline quality">
          <div className="health-list">
            <div className="health-item">
              <span>Records collected</span>
              <strong className="mono">{formatNumber(totals.collected)}</strong>
            </div>
            <div className="health-item">
              <span>Duplicate rate</span>
              <strong className="mono">{totals.duplicate_rate}%</strong>
            </div>
            <div className="health-item">
              <span>Rejected by validation</span>
              <strong className="mono">{formatNumber(totals.rejected)}</strong>
            </div>
            <div className="health-item">
              <span>Pipeline runs</span>
              <strong className="mono">{formatNumber(totals.pipeline_runs)}</strong>
            </div>
          </div>

          <p className="mini-heading">Latest runs</p>
          <ul className="run-list">
            {data.recent_runs.slice(0, 4).map((run) => (
              <li key={run.id} className="run-item">
                <span className={`run-status run-${run.status}`} />
                <div>
                  <p className="run-source">{truncate(run.source_name, 26)}</p>
                  <p className="run-meta">
                    {run.stored} new · {run.duplicates} dup · {timeAgo(run.started_at)}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </Card>

        <Card
          className="span-8"
          title="Latest indicators"
          subtitle="Most recently observed IOCs"
          padded={false}
          actions={
            <Link className="link-arrow" to="/indicators">
              View all <Icon name="arrow" size={14} />
            </Link>
          }
        >
          <table className="data-table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Reports</th>
                <th>First seen</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_indicators.map((indicator) => (
                <tr key={indicator.id}>
                  <td>
                    <span className="mono cell-strong">{truncate(indicator.normalized, 46)}</span>
                    <span className="cell-sub">{indicator.threat_type}</span>
                  </td>
                  <td>
                    <span className="type-chip">{typeLabel(indicator.type)}</span>
                  </td>
                  <td>
                    <SeverityBadge severity={indicator.severity} />
                  </td>
                  <td className="muted">{truncate(indicator.source_name, 24)}</td>
                  <td className="mono">{indicator.report_count}</td>
                  <td className="muted">{timeAgo(indicator.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card className="span-4" title="CVE posture" subtitle="Tracked vulnerability landscape">
          <div className="cve-posture">
            <div className="posture-ring" style={{ "--pct": `${Math.round((totals.cve_exploited / Math.max(1, totals.cves)) * 100)}%` }}>
              <div>
                <strong>{Math.round((totals.cve_exploited / Math.max(1, totals.cves)) * 100)}%</strong>
                <span>exploited</span>
              </div>
            </div>
            <div className="health-list">
              <div className="health-item">
                <span>Critical CVEs</span>
                <strong className="mono">{formatNumber(totals.cve_critical)}</strong>
              </div>
              <div className="health-item">
                <span>In CISA KEV</span>
                <strong className="mono">{formatNumber(totals.cve_exploited)}</strong>
              </div>
              <div className="health-item">
                <span>Patches available</span>
                <strong className="mono">{formatNumber(totals.cve_patched)}</strong>
              </div>
            </div>
          </div>
          <Link className="btn btn-ghost btn-block" to="/vulnerabilities">
            Open vulnerability view
          </Link>
        </Card>
      </div>
    </>
  );
}
