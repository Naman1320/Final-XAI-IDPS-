import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, query } from "../api/client";
import type { Action, ActionStatus, Alert, Block, Page } from "../api/types";
import {
  Card, Countdown, ErrorText, PageHead, Pill, Segmented, useAction, useLoad, useNow, type Tone,
} from "../components/common";
import { dateTime, label, oneLine } from "../format";
import { reporting, useSensors } from "../sensors";
import { useLiveRefresh } from "../useLiveRefresh";

/** Response: firewall blocks, the action queue and the block form (wireframe screen 3).
 *  One page owns every list, so an unblock or a confirm refreshes all of them. */

type QueueTab = "pending" | "confirmed" | "done";
type DoneStatus = Extract<ActionStatus, "executed" | "failed" | "rejected">;

const DURATIONS = [
  { seconds: 900, text: "15 min" },
  { seconds: 3600, text: "1 h" },
  { seconds: 86400, text: "24 h" },
];

export function ttlText(seconds: unknown): string | null {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return null;
  if (seconds === 86400) return "24 h";
  if (seconds % 86400 === 0) return `${seconds / 86400} d`;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

/** "block ip 10.10.1.10 · 15 min · sensor #1". A block without a time uses the sensor's default. */
export function actionSummary(a: Action): string {
  const parts = [`${label(a.kind)} ${String(a.params.ip ?? "")}`];
  const ttl = ttlText(a.params.ttl_seconds);
  if (ttl) parts.push(ttl);
  else if (a.kind === "block_ip") parts.push("sensor's default block time");
  parts.push(`sensor #${a.sensor_id}`);
  return parts.join(" · ");
}

export function who(a: Action): string {
  return a.proposed_by === "user" ? "an analyst" : a.proposed_by === "assistant" ? "the assistant" : a.proposed_by;
}

/** A sensor's result as one readable line: its error or message, else the JSON. */
function resultText(result: Record<string, unknown> | null): string {
  if (!result || Object.keys(result).length === 0) return "";
  const pick = result.error ?? result.message;
  if (typeof pick === "string") return pick;
  try {
    return JSON.stringify(pick ?? result);
  } catch {
    return "";
  }
}

const STATUS_TONE: Record<string, Tone> = {
  executed: "ok", failed: "danger", rejected: "neutral", confirmed: "warn", pending: "warn",
};

function count(page: Page<Action> | null): string {
  if (!page) return "…";
  return page.next_cursor ? `${page.items.length}+` : String(page.items.length);
}

/** Unblock button, hidden once the block's time has run out (before the next poll drops the row).
 *  It keeps its own clock, so the page doesn't re-render every second. */
function UnblockButton({ block, busy, onUnblock }: { block: Block; busy: boolean; onUnblock: (b: Block) => void }) {
  const now = useNow();
  if (!block.active || (block.expires_at && Date.parse(block.expires_at) <= now)) return null;
  return (
    <button className="danger-soft small" disabled={busy} onClick={() => onUnblock(block)}
      aria-label={`Unblock ${block.ip}`}>Unblock</button>
  );
}

/** A 0..1 setting as a percentage without rounding it up or down ("92.5%", "90%"). */
export function exactPercent(x: number): string {
  return `${Number((x * 100).toFixed(4))}%`;
}

/** The sensors' own response settings, as they last reported them. */
function PolicyCard() {
  const { data, error } = useSensors();
  const live = reporting(data);
  if (data?.redacted) {
    return (
      <Card title="Response policy">
        <p className="muted" style={{ margin: 0 }}>
          Only admins can see the sensors' auto-block thresholds. {live.length > 0 && (live.some((s) => !s.status.dry_run)
            ? "At least one online sensor is blocking." : "The online sensors are in dry-run: blocks are only logged.")}
        </p>
      </Card>
    );
  }
  return (
    <Card title="Response policy">
      <ErrorText error={error} />
      {data && live.length === 0 && (
        <p className="muted" style={{ margin: 0 }}>No sensor is online, so its policy isn't known right now.</p>
      )}
      {live.map(({ sensor_id, name, status: st }) => {
        const p = st.policy;
        if (!p) return null;
        return (
          <div key={sensor_id} style={{ marginBottom: 12 }}>
            {live.length > 1 && <h3>{name}</h3>}
            <dl className="kv small-kv">
              <dt>Mode</dt>
              <dd>{st.dry_run ? <Pill tone="warn">dry-run: blocks are only logged</Pill>
                : st.blocking_enabled ? <Pill tone="danger">blocking on</Pill> : <Pill>not blocking</Pill>}</dd>
              <dt>Auto-block</dt>
              <dd>{p.min_flows} flows ≥ {exactPercent(p.confidence_threshold)} confidence from one address within {ttlText(p.window_seconds) ?? `${p.window_seconds} s`}</dd>
              <dt>Alert floor</dt><dd>alerts below {exactPercent(p.min_alert_confidence)} confidence aren't sent</dd>
              <dt>Block time</dt><dd>{ttlText(p.block_ttl_seconds)}</dd>
              <dt>After an unblock</dt>
              <dd>{p.unblock_grace_seconds > 0
                ? `no auto-block of that address for ${ttlText(p.unblock_grace_seconds)}`
                : "the address can be auto-blocked again at once"}</dd>
              <dt>Analyst blocks</dt><dd>at most {p.max_analyst_blocks.toLocaleString()} at once</dd>
            </dl>
          </div>
        );
      })}
    </Card>
  );
}

/** Both allowlists: the SOC refuses these before sending an action, the sensor again before blocking. */
function AllowlistCard() {
  const { data, error } = useSensors();
  const live = reporting(data);
  if (data?.redacted) {
    return (
      <Card title="Never blocked · allowlist">
        <p className="muted" style={{ margin: 0 }}>
          Only admins can see the allowlists. Allowlisted addresses are still refused, by the SOC and again by the sensor.
        </p>
      </Card>
    );
  }
  const list = (items: string[] | null) => !items || items.length === 0
    ? <p className="muted small-text" style={{ margin: 0 }}>empty</p>
    : <ul className="detail-pairs mono">{items.map((n, i) => <li key={`${i}-${n}`}>{n}</li>)}</ul>;
  return (
    <Card title="Never blocked · allowlist">
      <ErrorText error={error} />
      {data && (
        <>
          <h3>SOC <span className="muted small-text">(IDPS_SOC_BLOCK_ALLOWLIST)</span></h3>
          {list(data.soc_allowlist)}
          {live.map(({ sensor_id, name, status: st }) => (
            <div key={sensor_id} style={{ marginTop: 12 }}>
              <h3>Sensor {name} <span className="muted small-text">(IDPS_ALLOWLIST)</span></h3>
              {list(st.allowlist)}
              {st.allowlist && st.allowlist_total !== undefined && st.allowlist_total > st.allowlist.length && (
                <p className="muted small-text" style={{ margin: "6px 0 0" }}>
                  and {st.allowlist_total - st.allowlist.length} more not shown (the sensor reports the first {st.allowlist.length}).
                </p>
              )}
            </div>
          ))}
          {live.length === 0 && <p className="muted small-text" style={{ marginTop: 12 }}>No sensor online to report its own list.</p>}
        </>
      )}
    </Card>
  );
}

interface Older { status: DoneStatus; items: Action[]; cursor: string | null }

export default function Response() {
  const [params, setParams] = useSearchParams();
  const [activeOnly, setActiveOnly] = useState(true);
  const [tab, setTab] = useState<QueueTab>("pending");
  const [doneStatus, setDoneStatus] = useState<DoneStatus>("executed");
  const [notice, setNotice] = useState<string | null>(null);
  const act = useAction();

  const blocks = useLoad(
    () => api<Page<Block>>(`/blocks${query({ active: activeOnly ? true : undefined, limit: 200 })}`), [activeOnly]);
  // Pending and confirmed are fetched by status, so neither drops out behind newer actions.
  const pending = useLoad(() => api<Page<Action>>(`/actions${query({ status: "pending", limit: 200 })}`), []);
  const confirmed = useLoad(() => api<Page<Action>>(`/actions${query({ status: "confirmed", limit: 200 })}`), []);
  const done = useLoad(() => api<Page<Action>>(`/actions${query({ status: doneStatus, limit: 50 })}`), [doneStatus]);
  // Older pages of the Done list. Tagged with their status, so a late response for another status
  // is never shown. While older pages are open, the poll leaves page 1 alone: refetching it would
  // shift rows between the pages and drop some from view.
  const search = params.toString();
  const [formKey, setFormKey] = useState(0);
  const lastSearch = useRef(search);
  useEffect(() => {
    if (search === lastSearch.current) return;
    lastSearch.current = search;
    if (search) setFormKey((k) => k + 1);
  }, [search]);

  const [olderState, setOlder] = useState<Older | null>(null);
  const older = olderState && olderState.status === doneStatus ? olderState : null;
  const olderOpen = useRef(false);
  olderOpen.current = older !== null;

  const reloadBlocks = blocks.reload;
  const reloadPending = pending.reload;
  const reloadConfirmed = confirmed.reload;
  const reloadDone = done.reload;
  const reloadAll = useCallback(() => {
    void reloadBlocks();
    void reloadPending();
    void reloadConfirmed();
    if (!olderOpen.current) void reloadDone();
  }, [reloadBlocks, reloadPending, reloadConfirmed, reloadDone]);
  // Blocks follow alerts, but expiries and sensor results arrive on no feed: also poll every 10 s.
  useLiveRefresh(reloadAll, undefined, 10_000);

  const [olderBusy, setOlderBusy] = useState(false);
  const [olderError, setOlderError] = useState<string | null>(null);
  async function loadOlder() {
    const status = doneStatus;
    const prev = older;
    const cursor = prev ? prev.cursor : done.data?.next_cursor;
    if (!cursor) return;
    setOlderBusy(true);
    setOlderError(null);
    try {
      const page = await api<Page<Action>>(`/actions${query({ status, limit: 50, cursor })}`);
      setOlder((cur) => {
        // Only append to the pages this request continued; anything else is a stale answer.
        const base = cur && cur.status === status ? cur : null;
        if ((base?.cursor ?? null) !== (prev?.cursor ?? null)) return cur;
        return { status, items: [...(base?.items ?? []), ...page.items], cursor: page.next_cursor };
      });
    } catch (err) {
      setOlderError(err instanceof Error ? err.message : String(err));
    } finally {
      setOlderBusy(false);
    }
  }

  function changeDoneStatus(s: DoneStatus) {
    setOlder(null);
    setOlderError(null);
    setDoneStatus(s);
  }

  async function unblock(b: Block) {
    if (!window.confirm(`Ask sensor #${b.sensor_id} to unblock ${b.ip}?`)) return;
    setNotice(null);
    const a = await act.run(() => api<Action>("/actions", {
      method: "POST",
      json: { kind: "unblock_ip", ip: b.ip, sensor_id: b.sensor_id, reason: `analyst unblock of block #${b.id}` },
    }));
    if (a) {
      setNotice(`Unblock requested (action #${a.id}). The block ends when the sensor reports back.`);
      reloadAll();
    }
  }

  async function decide(a: Action, decision: "confirm" | "reject") {
    if (decision === "confirm" && !window.confirm(`Confirm: ${oneLine(actionSummary(a))}?\n\nReason: ${oneLine(a.reason)}`)) return;
    setNotice(null);
    const res = await act.run(() => api<Action>(`/actions/${a.id}/${decision}`, { method: "POST" }));
    if (res) {
      setNotice(decision === "confirm"
        ? `Action #${a.id} confirmed. The sensor picks it up within a few seconds.`
        : `Action #${a.id} rejected.`);
      reloadAll();
    }
  }

  function goToForm(e: React.MouseEvent) {
    e.preventDefault();
    const input = document.getElementById("block-ip") as HTMLInputElement | null;
    input?.scrollIntoView({ block: "center" });
    input?.focus({ preventScroll: true });
  }

  const pendingItems = pending.data?.items ?? [];
  const doneItems = [...(done.data?.items ?? []), ...(older?.items ?? [])];
  const moreDone = older ? older.cursor : done.data?.next_cursor;
  const listed = tab === "confirmed" ? confirmed.data?.items ?? [] : doneItems;
  const listLoaded = tab === "confirmed" ? !!confirmed.data : !!done.data;

  return (
    <>
      <PageHead title="Response">
        <a className="button-link danger" href="#new-block" onClick={goToForm}>Block an IP…</a>
      </PageHead>
      <ErrorText error={act.error} />
      <div className="notice" role="status" aria-live="polite">{notice}</div>

      <div className="grid cols-main-side">
        <div className="stack">
          <Card title="Firewall blocks · nftables" actions={
            <label className="field inline">Show
              <select value={activeOnly ? "active" : "all"} onChange={(e) => setActiveOnly(e.target.value === "active")}>
                <option value="active">active only</option>
                <option value="all">all</option>
              </select>
            </label>
          }>
            <ErrorText error={blocks.error} />
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>IP</th><th>Source</th><th>Reason</th><th>Blocked</th><th>Ends</th>
                    <th><span className="sr-only">Action</span></th></tr>
                </thead>
                <tbody>
                  {(blocks.data?.items ?? []).map((b) => {
                    return (
                      <tr key={b.id}>
                        <td>
                          <b className="mono">{b.ip}</b>
                          <div className="muted small-text">
                            sensor #{b.sensor_id}
                            {b.alert_id ? <> · <Link to={`/alerts/${b.alert_id}`}>alert #{b.alert_id}</Link></> : null}
                          </div>
                        </td>
                        <td><Pill tone={b.source === "analyst" ? "accent" : "neutral"}>{b.source}</Pill></td>
                        <td>{oneLine(b.reason, 300)}</td>
                        <td>{dateTime(b.blocked_at)}</td>
                        <td>
                          {b.active
                            ? <Countdown start={b.blocked_at} end={b.expires_at} />
                            : <span className="muted">ended {dateTime(b.unblocked_at ?? b.expires_at)}</span>}
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <UnblockButton block={b} busy={act.busy} onUnblock={unblock} />
                        </td>
                      </tr>
                    );
                  })}
                  {blocks.data?.items.length === 0 && (
                    <tr><td colSpan={6} className="muted">{activeOnly ? "No active blocks." : "No blocks."}</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            <p className="muted small-text" style={{ margin: "8px 0 0" }}>
              Blocks end by themselves when their time runs out, and leave "active only" at the next refresh.
            </p>
          </Card>

          <Card title="Action queue" actions={
            <Segmented<QueueTab> label="Filter actions" value={tab} onChange={setTab} options={[
              { value: "pending", label: `Pending · ${count(pending.data)}` },
              { value: "confirmed", label: `Confirmed · ${count(confirmed.data)}` },
              { value: "done", label: "Done" },
            ]} />
          }>
            {/* Shown on every tab, so a failed load never looks like "0 waiting". */}
            <ErrorText error={pending.error ?? confirmed.error ?? (tab === "done" ? done.error : null)} />
            {tab === "pending" && (
              <div className="stack" style={{ gap: 10 }}>
                {pendingItems.map((a) => (
                  <div key={a.id} className="queue-item">
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
                      <span className="eyebrow">
                        {a.proposed_by === "assistant" ? "Proposed by the assistant" : `Requested by ${who(a)}`}
                        {" · waiting for an analyst"}
                      </span>
                      <span style={{ fontSize: 15, fontWeight: 600 }}>#{a.id} {actionSummary(a)}</span>
                      <span className="muted wrap-anywhere">“{oneLine(a.reason, 300)}”</span>
                    </div>
                    <div className="row-actions">
                      <button className="primary" disabled={act.busy} onClick={() => decide(a, "confirm")}
                        aria-label={`Confirm action #${a.id}`}>Confirm</button>
                      <button disabled={act.busy} onClick={() => decide(a, "reject")}
                        aria-label={`Reject action #${a.id}`}>Reject</button>
                    </div>
                  </div>
                ))}
                {pending.data && pendingItems.length === 0 && (
                  <p className="muted" style={{ margin: 0 }}>
                    Nothing waits for a decision. Blocks the assistant proposes appear here until an analyst confirms them.
                  </p>
                )}
              </div>
            )}
            {tab !== "pending" && (
              <>
                {tab === "done" && (
                  <label className="field inline" style={{ marginBottom: 10 }}>Status
                    <select value={doneStatus} onChange={(e) => changeDoneStatus(e.target.value as DoneStatus)}>
                      <option value="executed">executed</option>
                      <option value="failed">failed</option>
                      <option value="rejected">rejected</option>
                    </select>
                  </label>
                )}
                <ol className="queue-list">
                  {listed.map((a) => {
                    const result = resultText(a.result);
                    return (
                      <li key={a.id}>
                        <span className="wrap-anywhere" style={{ minWidth: 0 }}>
                          #{a.id} {actionSummary(a)} · by {who(a)}
                          <span className="muted small-text"> · {dateTime(a.created_at)}</span>
                          <span className="muted small-text" style={{ display: "block" }}>“{oneLine(a.reason, 300)}”</span>
                          {result && <span className="small-text" style={{ display: "block" }}>Sensor: {result}</span>}
                        </span>
                        <Pill tone={STATUS_TONE[a.status] ?? "neutral"}>
                          {a.status === "confirmed" ? "confirmed · waiting for the sensor" : a.status}
                        </Pill>
                      </li>
                    );
                  })}
                  {listLoaded && listed.length === 0 && <li className="muted">Nothing here.</li>}
                </ol>
                {tab === "done" && <ErrorText error={olderError} />}
                {tab === "done" && moreDone && (
                  <button className="small" style={{ marginTop: 10 }} disabled={olderBusy} onClick={loadOlder}>
                    {olderBusy ? "Loading…" : "Load older"}
                  </button>
                )}
                {tab === "done" && older && (
                  <p className="muted small-text" style={{ margin: "8px 0 0" }}>
                    Older pages are open, so this list doesn't refresh by itself.{" "}
                    <button type="button" className="link-button" onClick={() => { setOlder(null); void reloadDone(); }}>
                      Back to the newest
                    </button>
                  </p>
                )}
              </>
            )}
          </Card>
        </div>

        <div className="stack">
          <PolicyCard />
          <AllowlistCard />
          {/* Remounted when a link brings new prefill (?ip=…&sensor=…&reason=…), so values from two
              links never mix; clearing the prefill after a block keeps the form as it is. */}
          <BlockForm key={formKey}
            initial={{
              ip: params.get("ip") ?? "", sensor: params.get("sensor") ?? "",
              // A link never carries free text for the audit log: only an alert number (checked
              // against the address before it's used) or the topology panel's two numbers.
              reason: linkReason(params),
              linkAlert: /^[1-9]\d{0,17}$/.test(params.get("alert") ?? "") ? Number(params.get("alert")) : undefined,
              fromLink: !!params.get("ip"),
              // A link that only guessed the sensor (from the address's newest alert) says so.
              sensorGuessed: params.get("sensor_guess") === "1" && !!params.get("sensor"),
            }}
            onStart={() => setNotice(null)}
            onDone={(a) => {
              setNotice(`Block requested (action #${a.id}, ${a.status}). The sensor picks it up within a few seconds.`);
              // Drop the prefill from the address, so the same link fills the form again next time.
              if (params.toString()) setParams({}, { replace: true });
              reloadAll();
            }} />
        </div>
      </div>
    </>
  );
}

type Field = "ip" | "sensor" | "reason";

/** The reason a link may pre-fill: only the topology panel's numbers (an alert number is checked
 *  against the address first, in the form). Anything else in the address is ignored. */
export function linkReason(params: URLSearchParams): string {
  const num = (k: string) => (/^\d{1,9}$/.test(params.get(k) ?? "") ? Number(params.get(k)) : null);
  if (params.get("from") === "topology") {
    const count = num("count");
    const hours = num("hours");
    if (count !== null && hours !== null && hours > 0) return `topology: ${count} alerts in the last ${hours} h`;
  }
  return "";
}

function BlockForm({ initial, onStart, onDone }: {
  initial: { ip: string; sensor: string; reason: string; sensorGuessed?: boolean; fromLink?: boolean; linkAlert?: number };
  onStart: () => void;
  onDone: (a: Action) => void;
}) {
  const [ip, setIp] = useState(initial.ip);
  const [ttl, setTtl] = useState(DURATIONS[0].seconds);
  const [sensor, setSensor] = useState(initial.sensor);
  const [guessed, setGuessed] = useState(!!initial.sensorGuessed);
  const [reason, setReason] = useState(initial.reason);
  const [invalid, setInvalid] = useState<{ field: Field; message: string } | null>(null);
  const act = useAction();
  const sensorNow = useRef(sensor);
  sensorNow.current = sensor;
  const inputs = { ip: useRef<HTMLInputElement>(null), sensor: useRef<HTMLInputElement>(null), reason: useRef<HTMLInputElement>(null) };

  // Opened from a "Block…" link: bring the form into view (it is at the bottom on phones).
  useEffect(() => {
    if (!initial.ip) return;
    const input = inputs.ip.current;
    input?.scrollIntoView?.({ block: "center" });
    input?.focus({ preventScroll: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A link's alert number becomes the reason only if that alert really involves the address, so a
  // crafted link can't cite an unrelated alert in the audit log.
  const [alertNote, setAlertNote] = useState<string | null>(null);
  useEffect(() => {
    const id = initial.linkAlert;
    if (!id || !initial.ip) return;
    let cancelled = false;
    api<Alert>(`/alerts/${id}`)
      .then((a) => {
        if (cancelled) return;
        const ipNow = initial.ip.trim();
        if (a.src_ip === ipNow || a.dst_ip === ipNow) setReason((r) => r || `alert #${id}: ${a.predicted_class}`);
        else setAlertNote(`Alert #${id} doesn't involve ${ipNow}, so the reason was left empty.`);
      })
      .catch(() => { if (!cancelled) setAlertNote(`Alert #${id} couldn't be loaded, so the reason was left empty.`); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Analysts can't list sensors, so suggest the sensor of the newest alert, and say it is a guess.
  // Decided once, when the form opens: clearing the link's prefill later must not fetch again.
  const [linkedSensor] = useState(initial.sensor);
  useEffect(() => {
    if (linkedSensor) return;
    let cancelled = false;
    api<Page<Alert>>(`/alerts${query({ limit: 1 })}`)
      .then((p) => {
        const id = p.items[0]?.sensor_id;
        if (cancelled || !id || sensorNow.current) return; // the analyst typed one meanwhile
        setSensor(String(id));
        setGuessed(true);
      })
      .catch(() => { /* leave it empty: the analyst types it */ });
    return () => { cancelled = true; };
  }, [linkedSensor]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const cleanIp = ip.trim();
    const cleanReason = reason.trim();
    // Check everything before the confirm dialog, so the analyst never confirms a request that fails.
    const fail = (field: Field, message: string) => {
      setInvalid({ field, message });
      inputs[field].current?.focus();
    };
    act.setError(null);
    if (!cleanIp) return fail("ip", "Enter the IP address to block.");
    if (!/^[1-9]\d*$/.test(sensor.trim())) return fail("sensor", "Sensor must be a sensor number, e.g. 1.");
    if (!cleanReason) return fail("reason", "Enter a reason: it is kept in the audit log.");
    setInvalid(null);
    const sensorId = Number(sensor.trim());
    const duration = DURATIONS.find((d) => d.seconds === ttl)?.text ?? `${ttl} s`;
    if (!window.confirm(`Ask sensor #${sensorId} to block ${oneLine(cleanIp, 60)} for ${duration}?\n\nReason: ${oneLine(cleanReason)}`)) return;
    onStart();
    const a = await act.run(() => api<Action>("/actions", {
      method: "POST",
      json: { kind: "block_ip", ip: cleanIp, sensor_id: sensorId, reason: cleanReason, ttl_seconds: ttl },
    }));
    if (a) {
      setIp("");
      setReason("");
      onDone(a);
    }
  }

  function fieldProps(field: Field, hint?: string) {
    const bad = invalid?.field === field;
    const describedBy = [hint, bad ? "block-error" : undefined].filter(Boolean).join(" ") || undefined;
    return { "aria-invalid": bad || undefined, "aria-describedby": describedBy };
  }

  return (
    <section id="new-block" className="card" aria-labelledby="new-block-title">
      <h2 id="new-block-title">Block an IP</h2>
      {initial.fromLink && (
        <p className="hint" role="note" style={{ marginTop: 0 }}>
          Filled in from a link. Check the address and the sensor before you request the block.
        </p>
      )}
      <form className="stack" style={{ gap: 12 }} onSubmit={submit} noValidate>
        <label className="field">IP address
          <input id="block-ip" ref={inputs.ip} {...fieldProps("ip")} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 10.10.1.10"
            required maxLength={45} autoComplete="off" spellCheck={false} />
        </label>
        <div className="row-actions" style={{ flexWrap: "nowrap" }}>
          <label className="field" style={{ flex: 1 }}>For
            <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
              {DURATIONS.map((d) => <option key={d.seconds} value={d.seconds}>{d.text}</option>)}
            </select>
          </label>
          <label className="field" style={{ flex: 1 }}>Sensor #
            <input ref={inputs.sensor} value={sensor} onChange={(e) => { setSensor(e.target.value); setGuessed(false); }}
              inputMode="numeric" required placeholder="1" {...fieldProps("sensor", guessed ? "sensor-guess" : undefined)} />
          </label>
        </div>
        {guessed && (
          <p id="sensor-guess" className="muted small-text" style={{ margin: "-4px 0 0" }}>
            Sensor #{sensor} sent the newest alert. Check it is the sensor this address passes through.
          </p>
        )}
        <label className="field">Reason
          <input ref={inputs.reason} {...fieldProps("reason")} value={reason} onChange={(e) => setReason(e.target.value)} required maxLength={500}
            placeholder="Why (kept in the audit log)" />
        </label>
        {alertNote && <p className="muted small-text" style={{ margin: "-4px 0 0" }}>{alertNote}</p>}
        {invalid && <div id="block-error" className="error" role="alert">{invalid.message}</div>}
        <ErrorText error={act.error} />
        <button className="danger" type="submit" disabled={act.busy}>{act.busy ? "Requesting…" : "Request block"}</button>
        <p className="muted small-text" style={{ margin: 0 }}>
          Allowlisted addresses are refused, by the SOC and again by the sensor.
        </p>
      </form>
    </section>
  );
}
