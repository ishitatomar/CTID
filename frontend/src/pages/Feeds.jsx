import { useState } from "react";
import { api } from "../api.js";
import { useApi } from "../hooks.js";
import { Card, ErrorState, Icon, Loading, Meter, StatusPill, useToast } from "../components/ui.jsx";
import { formatDateTime, formatNumber, timeAgo, truncate } from "../utils.js";

export default function Feeds() {
  const toast = useToast();
  const sources = useApi(() => api.sources(), []);
  const runs = useApi(() => api.pipelineRuns(18), []);
  const [busyId, setBusyId] = useState(null);
  const [collecting, setCollecting] = useState(false);

  const reload = () => {
    sources.refresh();
    runs.refresh();
  };

  const collectAll = async () => {
    setCollecting(true);
    try {
      const result = await api.collectAll({});
      toast(
        `Collected ${result.totals.collected} records from ${result.totals.sources} feeds — ${result.totals.stored} new, ${result.totals.duplicates} duplicates, ${result.totals.rejected} rejected.`,
        "success"
      );
      reload();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setCollecting(false);
    }
  };

  const collectOne = async (source) => {
    setBusyId(source.id);
    try {
      const run = await api.collectSource(source.id);
      toast(`${source.name}: ${run.stored} new indicators, ${run.duplicates} duplicates merged.`, "success");
      reload();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusyId(null);
    }
  };

  const toggleSource = async (source) => {
    setBusyId(source.id);
    try {
      await api.updateSource(source.id, { status: source.status === "paused" ? "active" : "paused" });
      toast(`${source.name} ${source.status === "paused" ? "resumed" : "paused"}.`, "success");
      reload();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusyId(null);
    }
  };

  const summary = runs.data?.summary;

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">Collection layer</p>
          <h1 className="page-title">Feeds &amp; Pipeline</h1>
          <p className="page-subtitle">Authorized intelligence sources feeding the collection → processing → storage pipeline</p>
        </div>
        <div className="page-actions">
          <button type="button" className="btn btn-primary" onClick={collectAll} disabled={collecting}>
            <Icon name="refresh" size={15} className={collecting ? "spin" : ""} />
            {collecting ? "Collecting…" : "Run collection cycle"}
          </button>
        </div>
      </div>

      {summary && (
        <div className="stat-strip">
          <div>
            <span>Pipeline runs</span>
            <strong className="mono">{formatNumber(summary.runs)}</strong>
          </div>
          <div>
            <span>Records collected</span>
            <strong className="mono">{formatNumber(summary.collected)}</strong>
          </div>
          <div>
            <span>Indicators stored</span>
            <strong className="mono">{formatNumber(summary.stored)}</strong>
          </div>
          <div>
            <span>Duplicates merged</span>
            <strong className="mono">{formatNumber(summary.duplicates)}</strong>
          </div>
          <div>
            <span>Rejected</span>
            <strong className="mono">{formatNumber(summary.rejected)}</strong>
          </div>
        </div>
      )}

      {sources.loading && !sources.data ? (
        <Card>
          <Loading label="Loading connected feeds…" />
        </Card>
      ) : sources.error ? (
        <Card>
          <ErrorState error={sources.error} onRetry={sources.refresh} />
        </Card>
      ) : (
        <div className="source-grid">
          {sources.data.items.map((source) => (
            <article key={source.id} className="source-card">
              <header className="source-head">
                <div>
                  <h3>{source.name}</h3>
                  <p className="source-kind">
                    {source.kind} · trust {source.trust_score}%
                  </p>
                </div>
                <StatusPill status={source.status} />
              </header>

              <p className="source-desc">{source.description}</p>

              <div className="source-stats">
                <div>
                  <span>Indicators</span>
                  <strong className="mono">{formatNumber(source.indicator_count)}</strong>
                </div>
                <div>
                  <span>Critical</span>
                  <strong className="mono">{formatNumber(source.critical_count)}</strong>
                </div>
                <div>
                  <span>Last sync</span>
                  <strong>{timeAgo(source.last_sync_at)}</strong>
                </div>
              </div>

              <Meter value={source.trust_score} tone="accent" label="Source trust" />

              <div className="source-actions">
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={busyId === source.id || source.status === "paused"}
                  onClick={() => collectOne(source)}
                >
                  <Icon name="refresh" size={13} className={busyId === source.id ? "spin" : ""} /> Collect
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={busyId === source.id}
                  onClick={() => toggleSource(source)}
                >
                  {source.status === "paused" ? "Resume" : "Pause"}
                </button>
              </div>
            </article>
          ))}
        </div>
      )}

      <Card title="Pipeline history" subtitle="Each run records collection, deduplication and validation outcomes" padded={false}>
        {runs.loading && !runs.data ? (
          <Loading label="Loading pipeline history…" />
        ) : runs.error ? (
          <ErrorState error={runs.error} onRetry={runs.refresh} />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Source</th>
                <th>Status</th>
                <th>Collected</th>
                <th>Normalized</th>
                <th>Duplicates</th>
                <th>Rejected</th>
                <th>Stored</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run) => (
                <tr key={run.id}>
                  <td className="mono">#{run.id}</td>
                  <td>{truncate(run.source_name, 30)}</td>
                  <td>
                    <span className={`run-status-label run-${run.status}`}>{run.status}</span>
                  </td>
                  <td className="mono">{run.collected}</td>
                  <td className="mono">{run.normalized}</td>
                  <td className="mono">{run.duplicates}</td>
                  <td className="mono">{run.rejected}</td>
                  <td className="mono">{run.stored}</td>
                  <td className="muted">{formatDateTime(run.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
