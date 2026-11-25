import { useCallback, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, query } from "../api/client";
import { ALERT_STATUSES, SEVERITIES, type Alert, type AlertSource, type Page } from "../api/types";
import { Card, ErrorText, SeverityBadge, SourceTag, StatusText, useLoad } from "../components/common";
import { dateTime, endpoint, label, percent, protocolName } from "../format";
import { useLiveAlerts } from "../live";

interface Filters {
  severity: string;
  status: string;
  predicted_class: string;
  ip: string;
  /** "" = both; "ml" also covers alerts stored before rule alerts existed. */
  source: "" | AlertSource;
}

const EMPTY: Filters = { severity: "", status: "", predicted_class: "", ip: "", source: "" };
const PAGE = 100;

function matches(a: Alert, f: Filters): boolean {
  if (f.severity && a.severity !== f.severity) return false;
  if (f.status && a.status !== f.status) return false;
  if (f.predicted_class && a.predicted_class !== f.predicted_class) return false;
  if (f.ip && a.src_ip !== f.ip && a.dst_ip !== f.ip) return false;
  if (f.source && (a.source ?? "ml") !== f.source) return false;
  return true;
}

export default function Alerts() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const asked = params.get("source");
  const initial: Filters = {
    ...EMPTY, ip: params.get("ip") ?? "", predicted_class: params.get("class") ?? "",
    source: asked === "ml" || asked === "rule" ? asked : "",
  };
  const [draft, setDraft] = useState<Filters>(initial);
  const [filters, setFilters] = useState<Filters>(initial);
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  const { data, error, loading, setData } = useLoad(async () => {
    const page = await api<Page<Alert>>(`/alerts${query({ ...filters, limit: PAGE })}`);
    setCursor(page.next_cursor);
    return page.items;
  }, [filters]);

  const live = useLiveAlerts(useCallback((a: Alert) => {
    if (!matches(a, filters)) return;
    setData((rows) => (rows && !rows.some((r) => r.id === a.id) ? [a, ...rows] : rows));
    setFresh((s) => new Set(s).add(a.id));
  }, [filters, setData]));

  async function loadMore() {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const page = await api<Page<Alert>>(`/alerts${query({ ...filters, limit: PAGE, cursor })}`);
      setData((rows) => [...(rows ?? []), ...page.items]);
      setCursor(page.next_cursor);
    } finally {
      setLoadingMore(false);
    }
  }

  const set = (k: keyof Filters) => (e: { target: { value: string } }) =>
    setDraft((d) => ({ ...d, [k]: e.target.value }));

  return (
    <>
      <h1>Alerts</h1>
      <Card>
        <form className="toolbar" onSubmit={(e) => { e.preventDefault(); setFilters(draft); }}>
          <label className="field">Severity
            <select value={draft.severity} onChange={set("severity")}>
              <option value="">any</option>
              {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="field">Status
            <select value={draft.status} onChange={set("status")}>
              <option value="">any</option>
              {ALERT_STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
            </select>
          </label>
          <label className="field">Raised by
            <select value={draft.source} onChange={set("source")}>
              <option value="">model or rule</option>
              <option value="ml">model</option>
              <option value="rule">Suricata rule</option>
            </select>
          </label>
          <label className="field">Class
            <input value={draft.predicted_class} onChange={set("predicted_class")} placeholder="e.g. PortScan" />
          </label>
          <label className="field">IP (source or destination)
            <input value={draft.ip} onChange={set("ip")} placeholder="10.10.1.10" />
          </label>
          <button className="primary" type="submit">Apply</button>
          <button type="button" onClick={() => { setDraft(EMPTY); setFilters(EMPTY); }}>Clear</button>
          <span className="muted" style={{ marginLeft: "auto" }}>
            <span className={`live-dot ${live ? "on" : "off"}`} />{live ? "Live" : "Live feed offline"}
          </span>
        </form>
        <ErrorText error={error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Received</th><th>Severity</th><th>Class</th><th>Confidence</th>
                <th>Source</th><th>Destination</th><th>Proto</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((a) => (
                <tr key={a.id} className={`clickable${fresh.has(a.id) ? " fresh" : ""}`}
                  onClick={() => navigate(`/alerts/${a.id}`)}>
                  <td>{dateTime(a.received_at)}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>{a.predicted_class} <SourceTag source={a.source} /></td>
                  <td>{a.source === "rule" ? <span className="muted" title="Rule alerts have a severity, not a model confidence">—</span> : percent(a.confidence)}</td>
                  <td className="mono">{endpoint(a.src_ip, a.src_port, a.protocol)}</td>
                  <td className="mono">{endpoint(a.dst_ip, a.dst_port, a.protocol)}</td>
                  <td>{protocolName(a.protocol)}</td>
                  <td><StatusText value={a.status} /></td>
                </tr>
              ))}
              {!loading && data?.length === 0 && (
                <tr><td colSpan={8} className="muted">No alerts match these filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {cursor && (
          <div style={{ marginTop: 10 }}>
            <button onClick={loadMore} disabled={loadingMore}>{loadingMore ? "Loading…" : "Load more"}</button>
          </div>
        )}
      </Card>
    </>
  );
}
