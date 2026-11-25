import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, query } from "../api/client";
import {
  SEVERITIES, type Action, type Alert, type AlertSource, type Block, type DriftLevel, type MetricsSummary, type Page, type Severity, type WouldBlock,
} from "../api/types";
import {
  Card, ConfidenceBar, Countdown, ErrorText, PageHead, Pill, SeverityBadge, SourceTag, StatusText, useLoad, useNow,
} from "../components/common";
import { endpoint, oneLine, percent } from "../format";
import { reporting, useSensors } from "../sensors";
import { useLiveRefresh } from "../useLiveRefresh";
import { actionSummary, who } from "./Response";
import type { Topology } from "./TopologyMap";

/** Threat Center, the home page (wireframe screen 1): map, KPIs, classes by day, live alerts,
 *  firewall, pending decisions, sensor health and a topology summary. */

const WorldMap = lazy(() => import("./WorldMap"));

export const TC_WINDOWS = [1, 24, 168];
const DEFAULT_HOURS = 24;
const LIVE_ROWS = 10;
const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function windowText(h: number): string {
  return h < 24 ? `Last ${h} h` : h === 24 ? "Last 24 h" : `Last ${h / 24} days`;
}

function seconds(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const s = ms / 1000;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

/** "just now", "4 min ago", "3 h ago", "2 d ago". */
export function ago(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:.]+)$/i;

/** Where the search box sends a query: an alert number, an IP, or a class name.
 *  The API matches class names exactly, so a known class is matched ignoring case, and a
 *  part of a name ("dos") picks the class when only one known class contains it. */
export function searchTarget(raw: string, knownClasses: string[] = []): string | null {
  const q = raw.trim();
  if (!q) return null;
  if (/^#?\d+$/.test(q)) return `/alerts/${q.replace("#", "")}`;
  if (IP_RE.test(q)) return `/alerts${query({ ip: q })}`;
  const lower = q.toLowerCase();
  const known = knownClasses.filter((c) => c !== OTHER);
  const exact = known.find((c) => c.toLowerCase() === lower);
  const partial = known.filter((c) => c.toLowerCase().includes(lower));
  const name = exact ?? (partial.length === 1 ? partial[0] : q);
  return `/alerts${query({ class: name })}`;
}

/** The API folds rare classes into this bucket; it isn't a real class name to filter by. */
const OTHER = "(other)";

/** Bars for alerts per time bucket; the tallest bucket is drawn darker. */
function SparkBars({ counts }: { counts: number[] }) {
  if (counts.length === 0) return null;
  const w = 130;
  const h = 54;
  const max = Math.max(1, ...counts);
  const step = w / counts.length;
  const peak = counts.indexOf(Math.max(...counts));
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true" className="sparkbars">
      {counts.map((c, i) => {
        const bh = Math.max(2, (c / max) * (h - 4));
        return <rect key={i} x={i * step + step * 0.15} y={h - bh} width={Math.max(1, step * 0.7)} height={bh}
          rx={Math.min(2, step * 0.3)} className={i === peak && c > 0 ? "peak" : undefined} />;
      })}
    </svg>
  );
}

function Kpi({ title, value, sub, children }: { title: string; value: string; sub?: string; children?: ReactNode }) {
  return (
    <Card title={title} className="kpi">
      <div className="kpi-body">
        <div>
          <div className="kpi-value">{value}</div>
          {sub && <div className="muted small-text">{sub}</div>}
        </div>
        {children}
      </div>
    </Card>
  );
}

type SortKey = "newest" | "severity" | "confidence";

const conf = (a: Alert) => (a.source === "rule" ? -1 : a.confidence);

function LiveAlerts({ blocks, wouldBlocks }: { blocks: Block[]; wouldBlocks: WouldBlock[] }) {
  const navigate = useNavigate();
  const now = useNow(10_000);
  const [sort, setSort] = useState<SortKey>("newest");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [source, setSource] = useState<AlertSource | "">("");
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);
  const { data, error, setData, reload } = useLoad(
    () => api<Page<Alert>>(`/alerts${query({ severity: severity || undefined, source: source || undefined, limit: LIVE_ROWS })}`)
      .then((p) => p.items),
    [severity, source]);

  const live = useLiveRefresh(reload, useCallback((a: Alert) => {
    if (severity && a.severity !== severity) return;
    if (source && (a.source ?? "ml") !== source) return;
    setData((rows) => (rows && !rows.some((r) => r.id === a.id) ? [a, ...rows].slice(0, LIVE_ROWS) : rows));
    setFresh((s) => new Set(s).add(a.id));
    // The highlight animation lasts 1.6 s; forget the id after that.
    const t = setTimeout(() => {
      timers.current.delete(t);
      setFresh((s) => { const next = new Set(s); next.delete(a.id); return next; });
    }, 2000);
    timers.current.add(t);
  }, [severity, source, setData]));

  // The newest unexpired active block on the alert's own sensor decides its Response column
  // (a block on another sensor doesn't stop this traffic).
  const blockedBy = useMemo(() => {
    const m = new Map<string, Block["source"]>();
    for (const b of blocks) {
      const key = `${b.sensor_id}|${b.ip}`;
      if (b.active && (!b.expires_at || Date.parse(b.expires_at) > now) && !m.has(key)) m.set(key, b.source);
    }
    return m;
  }, [blocks, now]);
  // A dry-run decision counts like a block would: for its block time (1 h if the sensor didn't
  // say), and only for alerts from the same sensor.
  const wouldBlock = useMemo(() => {
    const live = new Set<string>();
    for (const w of wouldBlocks) {
      const at = Date.parse(w.at);
      if (!Number.isNaN(at) && at + (w.ttl_seconds ?? 3600) * 1000 > now) live.add(`${w.sensor_id}|${w.ip}`);
    }
    return live;
  }, [wouldBlocks, now]);

  const rows = useMemo(() => {
    const list = [...(data ?? [])];
    if (sort === "severity") list.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.id - a.id);
    // Rule alerts have no model confidence: they sort after the model's.
    else if (sort === "confidence") list.sort((a, b) => conf(b) - conf(a) || b.id - a.id);
    else list.sort((a, b) => b.id - a.id);
    return list;
  }, [data, sort]);

  return (
    <Card title="Live alerts" className="tc-live" actions={
      <div className="row-actions" style={{ alignItems: "center" }}>
        <label className="field inline">Sort
          <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
            <option value="newest">newest</option>
            <option value="severity">severity</option>
            <option value="confidence">confidence</option>
          </select>
        </label>
        <label className="field inline">Severity
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
            <option value="">any</option>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label className="field inline">Raised by
          <select value={source} onChange={(e) => setSource(e.target.value as AlertSource | "")}>
            <option value="">model or rule</option>
            <option value="ml">model</option>
            <option value="rule">rule</option>
          </select>
        </label>
        <span className="muted small-text">
          <span className={`live-dot ${live ? "on" : "off"}`} />{live ? "Live" : "Live feed offline"}
        </span>
      </div>
    }>
      <ErrorText error={error} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Class</th><th>Source → target</th><th>Confidence</th><th>Severity</th><th>Status</th><th>Response</th></tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const src = blockedBy.get(`${a.sensor_id}|${a.src_ip}`);
              return (
                <tr key={a.id} className={`clickable${fresh.has(a.id) ? " fresh" : ""}`} onClick={() => navigate(`/alerts/${a.id}`)}>
                  <td>
                    <Link to={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()}><b>{a.predicted_class}</b></Link>{" "}
                    <SourceTag source={a.source} />
                    <div className="muted small-text">#{a.id} · {ago(a.received_at, now)}</div>
                  </td>
                  <td className="mono">{a.src_ip} → {endpoint(a.dst_ip, a.dst_port, a.protocol)}</td>
                  <td>{a.source === "rule"
                    ? <span className="muted small-text" title="Rule alerts have a severity, not a model confidence">rule</span>
                    : <ConfidenceBar value={a.confidence} digits={1} />}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td><StatusText value={a.status} /></td>
                  <td>{src ? <Pill tone="danger">blocked · {src}</Pill>
                    : wouldBlock.has(`${a.sensor_id}|${a.src_ip}`) ? <Pill tone="warn">would block · dry-run</Pill>
                    : <Pill>observe</Pill>}</td>
                </tr>
              );
            })}
            {data && rows.length === 0 && (
              <tr><td colSpan={6} className="muted">
                No alerts yet{severity ? ` with severity ${severity}` : ""}{source ? ` from ${source === "ml" ? "the model" : "rules"}` : ""}.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
      <Link to="/alerts">Open all alerts →</Link>
    </Card>
  );
}

function Firewall({ blocks, more, error }: { blocks: Block[] | null; more: boolean; error: string | null }) {
  const now = useNow();
  // Hide a block once its time has run out, before the next refresh drops it.
  const active = (blocks ?? []).filter((b) => b.active && (!b.expires_at || Date.parse(b.expires_at) > now));
  const n = `${active.length}${more ? "+" : ""}`;
  return (
    <Card title="Firewall · nftables" actions={blocks && <Pill tone={active.length ? "danger" : "neutral"}>{n} active</Pill>}>
      <ErrorText error={error} />
      <ul className="queue-list tc-stacked">
        {active.slice(0, 3).map((b) => (
          <li key={b.id} className="tc-block">
            <div className="tc-block-head">
              <Link to={`/alerts${query({ ip: b.ip })}`} className="mono"><b>{b.ip}</b></Link>
              <Countdown start={b.blocked_at} end={b.expires_at} />
            </div>
            <span className="muted small-text">{b.source} · {b.reason ? oneLine(b.reason, 300) : "no reason given"}</span>
          </li>
        ))}
        {blocks && active.length === 0 && <li className="muted">No address is blocked right now.</li>}
      </ul>
      <Link to="/response">{active.length > 3 ? `All ${n} blocks →` : "All blocks →"}</Link>
    </Card>
  );
}

function Decisions() {
  const pending = useLoad(() => api<Page<Action>>(`/actions${query({ status: "pending", limit: 20 })}`), []);
  // Pending actions don't change with alerts, so this polls instead of following the live feed.
  const reloadPending = pending.reload;
  useEffect(() => {
    const id = setInterval(() => void reloadPending(), 15_000);
    return () => clearInterval(id);
  }, [reloadPending]);
  const items = pending.data?.items ?? [];
  const n = pending.data ? (pending.data.next_cursor ? `${items.length}+` : String(items.length)) : null;
  return (
    <Card title="Needs your decision" actions={n !== null && <Pill tone={items.length ? "warn" : "neutral"}>{n} pending</Pill>}>
      <ErrorText error={pending.error} />
      <ul className="queue-list tc-stacked">
        {items.slice(0, 3).map((a) => (
          <li key={a.id}>
            <span className="eyebrow">Proposed by {who(a)}</span>
            <b>{actionSummary(a)}</b>
            {a.reason && <span className="muted">“{oneLine(a.reason, 300)}”</span>}
          </li>
        ))}
        {pending.data && items.length === 0 && <li className="muted">Nothing waits for a decision.</li>}
      </ul>
      <Link to="/response" className="button-link">{items.length ? "Decide in Response →" : "Open response queue →"}</Link>
      <p className="muted small-text" style={{ margin: "10px 0 0" }}>
        Review proposed blocks here before a sensor can apply them.
      </p>
    </Card>
  );
}

function SensorHealth() {
  const { data, error } = useSensors();
  const now = useNow(30_000);
  const live = reporting(data);
  const sensors = data?.sensors.filter((x) => !x.revoked) ?? [];
  const liveIds = new Set(live.map((x) => x.sensor_id));
  const pill = !data ? null
    : live.length === 0 ? <Pill tone="danger">offline</Pill>
    : live.length < sensors.length ? <Pill tone="warn">{live.length} of {sensors.length} online</Pill>
    : <Pill tone="ok">online</Pill>;
  return (
    <Card title="Sensor health" actions={pill}>
      <ErrorText error={error} />
      {data && sensors.length === 0 && <p className="muted" style={{ margin: 0 }}>No sensors registered. An admin adds them in Admin.</p>}
      {live.slice(0, 2).map(({ sensor_id, name, status: st, last_seen_at }) => (
        <dl key={sensor_id} className="kv small-kv">
          <dt>Sensor</dt><dd><b>{name}</b> · {st.mode === "live" ? `live on ${st.interface ?? "?"}` : "replaying a capture"}</dd>
          <dt>Mode</dt><dd>{st.dry_run ? "dry-run (blocks only logged)" : st.blocking_enabled ? "blocking" : "not blocking"}</dd>
          <dt>Model</dt>
          <dd>
            {st.model.name} {st.model.checksum_ok ? "· checksum ok" : "· checksum FAILED"}
            {st.model.signed_by
              ? <> · <span title={`Signature checked with key ${st.model.signed_by}`}>signed</span></>
              : " · signature not checked"}
            {st.model.version && <><br /><span className="mono small-text">{st.model.version}</span></>}
          </dd>
          <dt>Rules</dt>
          <dd>{!st.rules ? "—"
            : !st.rules.enabled ? "off"
            : st.rules.error ? <span className="danger-text">{st.rules.error}</span>
            : `Suricata · ${st.rules.alerts_sent.toLocaleString()} sent`}</dd>
          <dt>Heartbeat</dt><dd>{!st.heartbeat.enabled ? "off" : st.heartbeat.ok ? "1 / s · ok" : "failing"}</dd>
          <dt>Outbox</dt><dd>{st.outbox_pending.toLocaleString()} pending</dd>
          <dt>SHAP p95</dt><dd>{st.shap_p95_ms == null ? "—" : `${st.shap_p95_ms.toFixed(2)} ms`}</dd>
          <dt>Allowlist</dt><dd>{(() => {
            const n = st.allowlist_total ?? st.allowlist?.length;
            return n === undefined ? "—" : `${n} ${n === 1 ? "entry" : "entries"}`;
          })()}</dd>
          <dt>Last seen</dt><dd>{last_seen_at ? ago(last_seen_at, now) : "—"}</dd>
        </dl>
      ))}
      {live.length > 2 && <p className="muted small-text">and {live.length - 2} more online.</p>}
      {sensors.filter((x) => !liveIds.has(x.sensor_id)).slice(0, 3).map((x) => (
        <p key={x.sensor_id} className="muted small-text" style={{ margin: "8px 0 0" }}>
          <b>{x.name}</b>: {x.last_seen_at ? `offline, last seen ${ago(x.last_seen_at, now)}` : "has never reported"}
        </p>
      ))}
    </Card>
  );
}

const DRIFT_TONE = { ok: "ok", watch: "warn", drift: "danger", unknown: "neutral" } as const;
const DRIFT_TEXT: Record<DriftLevel, string> = {
  ok: "stable", watch: "watch", drift: "drifting", unknown: "unknown",
};
const DRIFT_RANK: Record<DriftLevel, number> = { unknown: 0, ok: 1, watch: 2, drift: 3 };

/** Whether live traffic still looks like the model's training data, per online sensor (PSI per
 *  feature over the sensor's last few thousand flows, against the training deciles). */
function ModelDrift() {
  const { data, error } = useSensors();
  const live = reporting(data);
  const drifts = live.map((s) => ({ s, d: s.status.drift ?? null }));
  const worst = drifts.reduce<DriftLevel | null>((w, { d }) => {
    const level = d?.level ?? "unknown";
    return w === null || DRIFT_RANK[level] > DRIFT_RANK[w] ? level : w;
  }, null);
  // Unknown ranks lowest, so "stable" must still say when some sensors aren't measured.
  const unknown = drifts.filter(({ d }) => (d?.level ?? "unknown") === "unknown").length;
  return (
    <Card title="Model drift" actions={worst && (
      <Pill tone={DRIFT_TONE[worst]}>
        {DRIFT_TEXT[worst]}{worst !== "unknown" && unknown > 0 ? ` · ${unknown} unknown` : ""}
      </Pill>
    )}>
      <ErrorText error={error} />
      {data && live.length === 0 && <p className="muted" style={{ margin: 0 }}>No sensor is online.</p>}
      {drifts.slice(0, 3).map(({ s, d }) => (
        <div key={s.sensor_id} className="drift-sensor">
          <p style={{ margin: 0 }}>
            <b>{s.name}</b>{" "}
            <Pill tone={DRIFT_TONE[d?.level ?? "unknown"]}>{DRIFT_TEXT[d?.level ?? "unknown"]}</Pill>
          </p>
          {!d ? <p className="muted small-text" style={{ margin: "4px 0 0" }}>This sensor doesn't report drift (older version).</p>
            : d.psi_max === null ? <p className="muted small-text" style={{ margin: "4px 0 0" }}>{d.reason ?? "Not measured yet."}</p>
            : (
              <>
                <p className="small-text" style={{ margin: "4px 0 0" }}>
                  Largest shift PSI {d.psi_max.toFixed(2)}
                  {d.window ? <span className="muted"> over the last {d.window.toLocaleString()} flows</span> : null}
                </p>
                {d.top.length > 0 && (
                  <ul className="small-text drift-top">
                    {d.top.slice(0, 3).map((f) => (
                      <li key={f.feature}><span className="mono">{f.feature}</span> <span className="muted">{f.psi.toFixed(2)}</span></li>
                    ))}
                  </ul>
                )}
              </>
            )}
        </div>
      ))}
      {live.length > 3 && <p className="muted small-text">and {live.length - 3} more online.</p>}
      <p className="muted small-text" style={{ margin: "10px 0 0" }}>
        PSI below 0.1 is stable; 0.1–0.25 is worth watching; above 0.25 the traffic no longer looks like the
        training data. Mark alerts confirmed or false positive, then retrain.
      </p>
    </Card>
  );
}

function TopologySummary({ hours }: { hours: number }) {
  const { data, error, reload } = useLoad(() => api<Topology>(`/topology${query({ hours })}`), [hours]);
  useLiveRefresh(reload, undefined, 60_000);
  const edges = [...(data?.edges ?? [])].sort((a, b) => b.count - a.count).slice(0, 4);
  return (
    <Card title="Topology" actions={<Link to="/maps">Open →</Link>}>
      <ErrorText error={error} />
      {data && (
        <>
          <p className="muted small-text" style={{ marginTop: 0 }}>
            {data.nodes.length} hosts · {data.edges.length} links, {windowText(hours).toLowerCase()}
          </p>
          <ul className="queue-list">
            {edges.map((e) => (
              <li key={`${e.src}>${e.dst}`} className="tc-edge">
                <span className="mono wrap-anywhere">{e.src} → {e.dst}</span>
                <span className={`badge sev-${e.max_severity}`} title={`highest severity: ${e.max_severity}`}>
                  {e.count}<span className="sr-only"> alerts, highest severity {e.max_severity}</span>
                </span>
              </li>
            ))}
            {edges.length === 0 && <li className="muted">No traffic with alerts in this window.</li>}
          </ul>
        </>
      )}
    </Card>
  );
}

const ANOMALY = "Anomaly";
const HEAT_CLASSES = 5;

/** The last 7 UTC days, oldest first, as YYYY-MM-DD. */
export function lastSevenDays(now: number): string[] {
  const today = new Date(now);
  const base = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  return Array.from({ length: 7 }, (_, i) => new Date(base - (6 - i) * 86_400_000).toISOString().slice(0, 10));
}

/** Attack classes by day (wireframe heatmap). "Anomaly" (Isolation Forest outliers) is its own
 *  row: those alerts also have a class, so it isn't part of the class totals. */
function Heatmap({ rows, anomaly }: {
  rows: NonNullable<MetricsSummary["by_class_per_day"]>; anomaly: MetricsSummary["anomaly_per_day"];
}) {
  const days = lastSevenDays(Date.now());
  const counts = new Map<string, number>();
  const totals = new Map<string, number>();
  for (const r of rows) {
    counts.set(`${r.class}|${r.day}`, r.count);
    totals.set(r.class, (totals.get(r.class) ?? 0) + r.count);
  }
  // Outliers come in their own field, so a class that happens to be called "Anomaly" can't mix
  // with them: their row has its own key.
  const ANOMALY_KEY = "\u0000anomaly";
  for (const a of anomaly ?? []) counts.set(`${ANOMALY_KEY}|${a.day}`, a.count);
  const ranked = [...totals.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([c]) => c);
  const classes = ranked.filter((c) => c !== OTHER).slice(0, HEAT_CLASSES);
  // Everything past the top rows (and the API's own "(other)") is summed into one row.
  const rest = ranked.filter((c) => !classes.includes(c));
  if (rest.length > 0) {
    for (const d of days) {
      const n = rest.reduce((sum, c) => sum + (counts.get(`${c}|${d}`) ?? 0), 0);
      counts.set(`${OTHER}|${d}`, n);
    }
  }
  const names = [...classes, ...(rest.length > 0 ? [OTHER] : []), ...(anomaly ? [ANOMALY_KEY] : [])];
  const max = Math.max(1, ...names.flatMap((c) => days.map((d) => counts.get(`${c}|${d}`) ?? 0)));
  const level = (n: number) => (n === 0 ? 0 : Math.min(4, 1 + Math.floor((n / max) * 3.999)));
  const weekday = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString([], { weekday: "short", timeZone: "UTC" });
  return (
    <div className="table-wrap">
      <table className="heatmap">
        <caption className="sr-only">Alerts per class per day, last 7 days (UTC)</caption>
        <thead>
          <tr><th scope="col"><span className="sr-only">Class</span></th>
            {days.map((d) => <th key={d} scope="col" title={d}>{weekday(d)}<span className="sr-only"> {d}</span></th>)}</tr>
        </thead>
        <tbody>
          {names.map((c) => (
            <tr key={c} className={c === ANOMALY_KEY ? "anomaly" : undefined}>
              <th scope="row">{c === OTHER ? "other classes" : c === ANOMALY_KEY ? ANOMALY : c}</th>
              {days.map((d) => {
                const n = counts.get(`${c}|${d}`) ?? 0;
                const name = c === ANOMALY_KEY ? ANOMALY : c === OTHER ? "other classes" : c;
                return <td key={d} className={`heat-${level(n)}`} title={`${name}, ${d}: ${n}`}>{n || ""}<span className="sr-only">{n ? "" : "0"}</span></td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Classes({ m }: { m: MetricsSummary }) {
  const byClass = Object.entries(m.by_class).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...byClass.map(([, c]) => c));
  return (
    <Card title="Attack classes" className="tc-classes">
      {byClass.length === 0
        ? <p className="muted">No alerts in this window.</p>
        : (
          <ul className="class-bars">
            {byClass.slice(0, 6).map(([name, count]) => (
              <li key={name}>
                {name === OTHER
                  ? <span className="muted">other classes</span>
                  : <Link to={`/alerts${query({ class: name })}`}>{name}</Link>}
                <span className="class-track" aria-hidden="true"><span style={{ width: `${(count / max) * 100}%` }} /></span>
                <span className="num">{count.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
      <p className="muted small-text">Totals for the window.</p>
      {m.by_class_per_day && (
        <>
          <h3 style={{ marginTop: 14 }}>By day, last 7 days (UTC)</h3>
          <Heatmap rows={m.by_class_per_day} anomaly={m.anomaly_per_day} />
          <p className="muted small-text">
            “Anomaly”: alerts the Isolation Forest also flags as unusual; they count under their class too.
            Flows the classifier calls benign aren't sent to the SOC, so unusual benign-looking traffic isn't in this row.
          </p>
        </>
      )}
      <h3 style={{ marginTop: 14 }}>Top source IPs</h3>
      <ul className="queue-list">
        {m.top_sources.slice(0, 4).map((s) => (
          <li key={s.ip} className="tc-edge">
            <Link to={`/alerts${query({ ip: s.ip })}`} className="mono">{s.ip}</Link>
            <span className="muted">{s.count.toLocaleString()} alerts</span>
          </li>
        ))}
        {m.top_sources.length === 0 && <li className="muted">None in this window.</li>}
      </ul>
    </Card>
  );
}

export default function ThreatCenter() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const asked = Number(params.get("hours"));
  const hours = TC_WINDOWS.includes(asked) ? asked : DEFAULT_HOURS;
  const [search, setSearch] = useState("");

  const metrics = useLoad(() => api<MetricsSummary>(`/metrics/summary${query({ hours })}`), [hours]);
  const blocks = useLoad(() => api<Page<Block>>(`/blocks${query({ active: true, limit: 200 })}`), []);
  const would = useLoad(() => api<Page<WouldBlock>>(`/blocks/would${query({ since_hours: 24, limit: 200 })}`).then((p) => p.items), []);
  const reloadAll = useCallback(() => {
    void metrics.reload(); void blocks.reload(); void would.reload();
  }, [metrics.reload, blocks.reload, would.reload]);
  useLiveRefresh(reloadAll);

  function onSearch(e: FormEvent) {
    e.preventDefault();
    const to = searchTarget(search, Object.keys(metrics.data?.by_class ?? {}));
    if (to) navigate(to);
  }

  const m = metrics.data;
  const latency = m?.detection_latency;
  const classLine = m
    ? Object.entries(m.by_class).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([c, n]) => `${c} ${n.toLocaleString()}`).join(" · ")
    : "";
  const sourceLine = m?.by_source && m.by_source.rule > 0
    ? `model ${m.by_source.ml.toLocaleString()} · rules ${m.by_source.rule.toLocaleString()}` : "";

  return (
    <>
      <PageHead title="Threat Center">
        <Link to="/cases?new=1" className="button-link">Create case</Link>
        <form role="search" onSubmit={onSearch} className="tc-search">
          <input type="search" aria-label="Search alerts" value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="IP, alert #, or class" />
          <button type="submit">Search</button>
        </form>
        <label className="field inline">Window
          <select value={hours} onChange={(e) => {
            const h = Number(e.target.value);
            setParams(h === DEFAULT_HOURS ? {} : { hours: String(h) }, { replace: true });
          }}>
            {TC_WINDOWS.map((h) => <option key={h} value={h}>{windowText(h)}</option>)}
          </select>
        </label>
      </PageHead>
      <ErrorText error={metrics.error} />

      <div className="tc-row1">
        <div className="stack">
          <Suspense fallback={<Card title="Live attack map"><p className="muted">Loading map…</p></Card>}>
            <WorldMap hours={hours} compact />
          </Suspense>
        </div>
        <div className="stack">
          <div className="tc-kpis">
            <Kpi title="Alerts" value={m ? m.alerts_total.toLocaleString() : "…"}
              sub={[sourceLine, classLine].filter(Boolean).join(" — ") || undefined}>
              <SparkBars counts={(m?.alerts_per_bucket ?? []).map((b) => b.count)} />
            </Kpi>
            <Kpi title="Detection latency (p50)" value={seconds(latency?.p50_ms)}
              sub={latency ? `p95 ${seconds(latency.p95_ms)}` : undefined} />
            <Kpi title="Active blocks" value={m ? String(m.active_blocks) : "…"}
              sub={m?.would_blocks ? `+ ${m.would_blocks.toLocaleString()} dry-run decisions` : undefined} />
            <Kpi title="False positives" value={m ? percent(m.false_positive_rate, 1) : "…"}
              sub={m ? `${m.false_positives} of ${m.triaged} triaged` : undefined} />
          </div>
          <p className="muted small-text" style={{ margin: 0 }}>
            A flow is reported when it ends (120 s idle timeout), so alerts trail the traffic by about 2 minutes.
          </p>
          {m && <Classes m={m} />}
        </div>
      </div>

      <LiveAlerts blocks={blocks.data?.items ?? []} wouldBlocks={would.data ?? []} />

      <div className="tc-row3">
        <Firewall blocks={blocks.data?.items ?? null} more={!!blocks.data?.next_cursor} error={blocks.error} />
        <Decisions />
        <SensorHealth />
        <ModelDrift />
        <TopologySummary hours={hours} />
      </div>
    </>
  );
}
