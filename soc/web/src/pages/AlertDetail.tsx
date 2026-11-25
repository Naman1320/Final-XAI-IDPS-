import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useLiveRefresh } from "../useLiveRefresh";
import { api, query } from "../api/client";
import {
  ALERT_STATUSES, ATTACK_CLASSES, type AlertDetail as AlertDetailT, type AlertStatus, type Block, type CaseDetail,
  type CaseSummary, type Page, type Reputation, type RuleInfo,
} from "../api/types";
import {
  Card, ErrorText, Pill, Segmented, SeverityBadge, SourceTag, Timeline, useAction, useLoad, useNow, type TimelineItem, type Tone,
} from "../components/common";
import ExplanationChart from "../components/ExplanationChart";
import type { FaithfulnessMethod } from "../api/types";
import { dateTime, endpoint, label, num, percent, protocolName } from "../format";
import { useSensors } from "../sensors";

/** Alert detail with its explanation (wireframe screen 2). */

/** What marking this alert teaches the model at the next retrain. */
function Learning({ alert, busy, onTrueClass }: {
  alert: AlertDetailT; busy: boolean; onTrueClass: (value: string) => void;
}) {
  if (alert.source === "rule") {
    return (
      <p className="muted small-text" style={{ margin: 0 }}>
        Raised by a Suricata rule, not the model: marking it doesn't change the model at the next retrain.
      </p>
    );
  }
  const confirmed = alert.status === "confirmed";
  // A correction equal to the prediction is the same as none; anything else outside the list shows as itself.
  const current = alert.true_class && alert.true_class !== alert.predicted_class ? alert.true_class : "";
  const choices = ATTACK_CLASSES.filter((c) => c !== alert.predicted_class) as string[];
  if (current && !choices.includes(current)) choices.unshift(current);
  const row = !alert.has_features ? null
    : confirmed ? (alert.true_class ?? alert.predicted_class)
    : alert.status === "false_positive" ? "BENIGN" : null;
  return (
    <div className="stack" style={{ gap: 8 }}>
      {confirmed && (
        <label className="field">Real class
          <select value={current} disabled={busy} onChange={(e) => onTrueClass(e.target.value)}>
            <option value="">As predicted ({alert.predicted_class})</option>
            {choices.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
      )}
      <p className="muted small-text" style={{ margin: 0 }} aria-live="polite">
        {!alert.has_features
          ? "This sensor didn't send the flow's feature values, so this alert can't be used for retraining."
          : row
            ? <>Used as a training row labelled <b>{row}</b> at the next retrain.</>
            : "Mark it confirmed or false positive to use it for retraining."}
      </p>
    </div>
  );
}

/** Time of day, with the date too when it isn't the same day as `ref`. */
const time = (v: string | number, ref?: string | number) => {
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  const r = ref === undefined ? null : new Date(ref);
  return r && !Number.isNaN(r.getTime()) && r.toDateString() !== d.toDateString()
    ? d.toLocaleString() : d.toLocaleTimeString();
};

/** "+2 min" between the end of the flow and the SOC receiving it. */
function delayText(fromMs: number, to: string): string | null {
  const ms = Date.parse(to) - fromMs;
  if (!Number.isFinite(ms) || ms < 0) return null;
  if (ms < 60_000) return `+${Math.round(ms / 1000)} s`;
  return `+${Math.round(ms / 60_000)} min`;
}

const sameSource = (alert: AlertDetailT, b: Block) => b.sensor_id === alert.sensor_id && b.ip === alert.src_ip;

/** When a block ended, or will end; Infinity for one with no end. */
function blockEnd(b: Block): number {
  const end = b.unblocked_at ?? b.expires_at;
  return end ? Date.parse(end) : Infinity;
}

/** The block of this alert's source on its sensor that is in force now, if any. A sensor that
 *  re-blocks an address only extends the existing block (its blocked_at stays the old one), so
 *  this looks at every block of the address, whenever it started. */
export function activeBlock(alert: AlertDetailT, blocks: Block[], now = Date.now()): Block | undefined {
  return blocks.find((b) => sameSource(alert, b) && b.active && blockEnd(b) > now);
}

/** Blocks of this alert's source on its sensor that belong in its story: the block it caused, and
 *  blocks in force at any time from the start of the flow until an hour after the alert arrived. */
export function relatedBlocks(alert: AlertDetailT, blocks: Block[]): Block[] {
  const from = alert.start_ms;
  const to = Date.parse(alert.received_at) + 3600_000;
  return blocks
    .filter((b) => sameSource(alert, b))
    .filter((b) => b.alert_id === alert.id || (Date.parse(b.blocked_at) <= to && blockEnd(b) >= from))
    .slice(0, 10);
}

export function timeline(alert: AlertDetailT, blocks: Block[], now = Date.now()): TimelineItem[] {
  const method = typeof alert.explanation?.method === "string" ? alert.explanation.method.toUpperCase() : null;
  const ref = alert.received_at;
  const received = Date.parse(alert.received_at);
  const events: (TimelineItem & { t: number })[] = [
    { key: "flow", t: alert.start_ms, at: time(alert.start_ms, ref),
      text: `flow seen: ${protocolName(alert.protocol)} ${endpoint(alert.src_ip, alert.src_port, alert.protocol)} → ${endpoint(alert.dst_ip, alert.dst_port, alert.protocol)}` },
    { key: "scored", t: received, at: time(alert.received_at, ref), tone: "accent",
      text: alert.source === "rule"
        ? `Suricata rule matched${alert.rule ? ` (sid ${alert.rule.sid})` : ""}: ${alert.predicted_class}`
        : `scored ${alert.predicted_class} ${percent(alert.confidence, 2)}${method ? `, explained (${method})` : ""}` },
  ];
  for (const b of blocks) {
    const started = Date.parse(b.blocked_at);
    // Say how a block relates to this alert: caused by it, already in force, or started later.
    const how = b.alert_id === alert.id ? "" : started < alert.start_ms ? " (already in force)"
      : started > received ? " (later block of this address)" : "";
    events.push({ key: `b${b.id}`, t: started, at: time(b.blocked_at, ref), tone: "danger",
      text: `${b.ip} blocked (${b.source})${how}: ${b.reason}` });
    if (b.unblocked_at) {
      events.push({ key: `u${b.id}`, t: Date.parse(b.unblocked_at), at: time(b.unblocked_at, ref), text: "unblocked" });
    } else if (b.expires_at) {
      const e = Date.parse(b.expires_at);
      events.push({ key: `e${b.id}`, t: e, at: time(b.expires_at, ref),
        text: e <= now ? "block expired by itself" : "block ends" });
    }
  }
  return events.sort((a, b) => a.t - b.t).map(({ t: _t, ...item }) => item);
}

export default function AlertDetail() {
  const { id: rawId } = useParams();
  // Only numeric ids reach the API path (a crafted link like /alerts/..%2Fadmin must not).
  const id = /^\d{1,18}$/.test(rawId ?? "") ? rawId! : "0";
  // A fresh page per alert: nothing (data, notice, chosen case) carries over to the next one, and
  // no action can target one alert while another is still on screen.
  return <AlertPage key={id} id={id} />;
}

function AlertPage({ id }: { id: string }) {
  const { data: alert, error, setData } = useLoad(() => api<AlertDetailT>(`/alerts/${id}`), [id]);
  const srcIp = alert?.src_ip;
  const blocks = useLoad(
    () => (srcIp ? api<Page<Block>>(`/blocks${query({ ip: srcIp, limit: 100 })}`) : Promise.resolve(null)), [srcIp]);
  const { data: cases } = useLoad(
    () => api<Page<CaseSummary>>(`/cases${query({ status: "open", limit: 100 })}`), []);
  const act = useAction();
  // Blocks start and end without an alert for this page: refresh them, and re-check expiry each 15 s.
  useLiveRefresh(blocks.reload, undefined, 30_000);
  const now = useNow(15_000);
  const [notice, setNotice] = useState<string | null>(null);
  const [caseId, setCaseId] = useState("");
  const [newCase, setNewCase] = useState("");

  if (error) return <ErrorText error={error} />;
  if (!alert) return <p className="muted">Loading…</p>;

  const allBlocks = blocks.data?.items ?? [];
  const related = relatedBlocks(alert, allBlocks);
  const blocked = activeBlock(alert, allBlocks, now);
  const delay = delayText(alert.end_ms, alert.received_at);
  // The form writes the reason itself from the alert number: a link never carries free text.
  const blockLink = `/response${query({ ip: alert.src_ip, sensor: alert.sensor_id, alert: alert.id })}`;

  async function setStatus(status: AlertStatus) {
    if (status === alert!.status) return;
    setNotice(null);
    // A correction only belongs to a confirmed alert: clear it when the alert stops being one, and
    // never carry a BENIGN correction (from a false positive) into a confirmed alert.
    const tc = alert!.true_class;
    const clear = !!tc && (status !== "confirmed" || tc === "BENIGN");
    const json = clear ? { status, true_class: null } : { status };
    const updated = await act.run(() =>
      api<AlertDetailT>(`/alerts/${id}`, { method: "PATCH", json }));
    if (updated) setData(updated);
  }

  async function setTrueClass(value: string) {
    setNotice(null);
    const updated = await act.run(() => api<AlertDetailT>(`/alerts/${id}`, {
      method: "PATCH", json: { status: "confirmed", true_class: value || null } }));
    if (updated) setData(updated);
  }

  async function addToCase() {
    if (!caseId) return;
    setNotice(null);
    const c = await act.run(() => api<CaseDetail>(`/cases/${caseId}/alerts`, {
      method: "POST", json: { alert_ids: [alert!.id] } }));
    if (c) {
      setData({ ...alert!, case_id: c.id });
      setNotice(`Added to case #${c.id}.`);
    }
  }

  async function createCase() {
    const title = newCase.trim();
    if (!title) return;
    setNotice(null);
    const c = await act.run(() => api<CaseDetail>("/cases", {
      method: "POST", json: { title, alert_ids: [alert!.id] } }));
    if (c) {
      setData({ ...alert!, case_id: c.id });
      setNotice(`Created case #${c.id}.`);
      setNewCase("");
    }
  }

  return (
    <>
      <nav aria-label="Breadcrumb" className="small-text">
        <Link to="/alerts">← Alerts</Link>
      </nav>
      <div className="page-head" style={{ justifyContent: "flex-start" }}>
        <h1>{alert.predicted_class} · alert #{alert.id}</h1>
        <SeverityBadge severity={alert.severity} />
        <SourceTag source={alert.source} />
        {alert.source === "rule"
          ? alert.rule && <Pill tone="neutral">rule severity {alert.rule.severity}</Pill>
          : <Pill tone="neutral">confidence {percent(alert.confidence, 1)}</Pill>}
        {blocked && <Pill tone="danger">source blocked · {blocked.source}</Pill>}
      </div>
      <ErrorText error={act.error} />
      <div className="notice" role="status" aria-live="polite">{notice}</div>

      <div className="grid cols-detail">
        <div className="stack">
          <Card title="Flow">
            <dl className="kv">
              <dt>Source</dt>
              <dd>
                <span className="mono">{endpoint(alert.src_ip, alert.src_port, alert.protocol)}</span>{" "}
                <Link className="small-text" to={`/alerts${query({ ip: alert.src_ip })}`}>all alerts involving this IP</Link>
              </dd>
              <dt>Destination</dt><dd className="mono">{endpoint(alert.dst_ip, alert.dst_port, alert.protocol)}</dd>
              <dt>Protocol</dt><dd>{protocolName(alert.protocol)}</dd>
              <dt>Flow time</dt><dd>{dateTime(alert.start_ms)} → {time(alert.end_ms, alert.start_ms)}</dd>
              <dt>Received</dt>
              <dd>
                {dateTime(alert.received_at)}
                {delay && <span className="muted small-text"> ({delay} after the flow ended)</span>}
              </dd>
              {alert.source !== "rule" && (
                <>
                  <dt>Anomaly score</dt>
                  <dd>{num(alert.anomaly_score)} {alert.anomaly_score !== null && <span className="muted small-text">Isolation Forest</span>}</dd>
                </>
              )}
              <dt>Sensor</dt><dd>#{alert.sensor_id}</dd>
              <dt>Model</dt>
              <dd>{alert.source === "rule" ? <span className="muted">Suricata rule (no model)</span>
                : alert.model_version
                ? <span className="mono small-text">{alert.model_version}</span>
                : alert.model_sha256 ? <span className="mono small-text">sha256 {alert.model_sha256.slice(0, 12)}</span>
                : <span className="muted">not reported by this sensor</span>}</dd>
              <dt>Case</dt><dd>{alert.case_id ? <Link to={`/cases/${alert.case_id}`}>#{alert.case_id}</Link> : "—"}</dd>
            </dl>
          </Card>

          <ReputationCard alertId={alert.id} ip={alert.src_ip} />

          <Card title="Triage">
            <div className="stack" style={{ gap: 14 }}>
              <Segmented<AlertStatus> label="Status" value={alert.status} onChange={(s) => void setStatus(s)} disabled={act.busy}
                options={ALERT_STATUSES.map((s) => ({ value: s, label: label(s) }))} />
              <Learning alert={alert} busy={act.busy} onTrueClass={(v) => void setTrueClass(v)} />
              {blocked ? (
                <p style={{ margin: 0 }}>
                  {alert.src_ip} is blocked on sensor #{alert.sensor_id}
                  {blocked.expires_at ? ` until ${dateTime(blocked.expires_at)}` : ""}.{" "}
                  <Link to="/response">See it on Response</Link>
                </p>
              ) : (
                <div>
                  <Link className="button-link danger" to={blockLink}>Block source IP…</Link>
                  <p className="muted small-text" style={{ margin: "6px 0 0" }}>
                    Opens the block form with {alert.src_ip} and sensor #{alert.sensor_id} filled in; you choose how long.
                  </p>
                </div>
              )}
              {alert.case_id ? (
                <p style={{ margin: 0 }}>In <Link to={`/cases/${alert.case_id}`}>case #{alert.case_id}</Link>.</p>
              ) : (
                <>
                  <div className="row-actions" style={{ alignItems: "flex-end" }}>
                    <label className="field" style={{ flex: "1 1 160px" }}>Add to open case
                      <select value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                        <option value="">Choose…</option>
                        {(cases?.items ?? []).map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
                      </select>
                    </label>
                    <button disabled={!caseId || act.busy} onClick={addToCase}>Add</button>
                  </div>
                  <div className="row-actions" style={{ alignItems: "flex-end" }}>
                    <label className="field" style={{ flex: "1 1 160px" }}>Or open a new case
                      <input value={newCase} maxLength={200} onChange={(e) => setNewCase(e.target.value)}
                        placeholder="Case title" />
                    </label>
                    <button disabled={!newCase.trim() || act.busy} onClick={createCase}>Create</button>
                  </div>
                </>
              )}
            </div>
          </Card>

          <Card title="What happened">
            <ErrorText error={blocks.error} />
            <Timeline items={timeline(alert, related, now)} />
            {blocks.data && related.length === 0 && (
              <p className="muted small-text" style={{ margin: "10px 0 0" }}>No block of {alert.src_ip} on this sensor around this alert.</p>
            )}
          </Card>
        </div>

        <div className="stack">
          {alert.source === "rule" ? (
            alert.rule ? <RuleCard rule={alert.rule} alertId={alert.id} />
              : <Card title="Why the rule fired"><p className="muted" style={{ margin: 0 }}>The sensor didn't send the rule's details.</p></Card>
          ) : (
            <>
              <Card title="Why the model flagged this flow">
                <ExplanationChart explanation={alert.explanation} />
                <Link className="button-link" style={{ marginTop: 16 }} to={`/assistant${query({ alert: alert.id })}`}>
                  Explain this alert with the assistant
                </Link>
              </Card>
              <TrustCard sensorId={alert.sensor_id}
                method={typeof alert.explanation?.method === "string" ? alert.explanation.method.toLowerCase() : null} />
            </>
          )}
        </div>
      </div>
    </>
  );
}

/** True for addresses the SOC never sends to AbuseIPDB (private, loopback, link-local, CGNAT,
 *  documentation and other reserved ranges). The server decides; this only avoids a pointless click. */
export function isReservedIp(ip: string): boolean {
  if (ip.includes(":")) {
    const v = ip.toLowerCase();
    return v === "::1" || v.startsWith("fe80:") || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("::ffff:") || v.startsWith("2001:db8:");
  }
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  const [a, b, c] = o;
  return a === 10 || a === 127 || a === 0 || a >= 224
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)
    || (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0 && (c === 0 || c === 2))
    || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
}

/** AbuseIPDB reputation of the source IP. Looked up only when the analyst asks: the lookup sends the
 *  IP to a third party, and the free quota is small. Private addresses are never looked up. */
function ReputationCard({ alertId, ip }: { alertId: number; ip: string }) {
  const act = useAction();
  const [rep, setRep] = useState<Reputation | null>(null);
  async function check() {
    const r = await act.run(() => api<Reputation>(`/alerts/${alertId}/reputation`));
    if (r) setRep(r);
  }
  const score = rep?.available ? rep.abuse_confidence : null;
  const tone: Tone = score === null ? "neutral" : score >= 75 ? "danger" : score >= 25 ? "warn" : "ok";
  const reserved = isReservedIp(ip);
  return (
    <Card title="Source reputation" actions={score !== null ? <Pill tone={tone}>abuse score {score}%</Pill> : undefined}>
      <ErrorText error={act.error} />
      {/* One live region that stays mounted, so the result is announced when it arrives. */}
      <div role="status" aria-live="polite">
        {reserved ? (
          <p className="muted" style={{ margin: 0 }}>{ip} is a private or reserved address: it has no public reputation and is never looked up.</p>
        ) : rep && !rep.available ? (
          <p className="muted" style={{ margin: "0 0 8px" }}>No reputation for {rep.ip}: {rep.reason ?? "not available"}.</p>
        ) : rep ? (
          <dl className="kv small-kv">
            <dt>Abuse score</dt>
            <dd>{score === null ? "—" : `${score}%`} <span className="muted small-text">(AbuseIPDB confidence; 25%+ suspicious, 75%+ high)</span></dd>
            <dt>Reports</dt><dd>{rep.total_reports?.toLocaleString() ?? "—"}</dd>
            <dt>Last reported</dt><dd>{rep.last_reported_at ? dateTime(rep.last_reported_at) : "never"}</dd>
            <dt>Country</dt><dd>{rep.country ?? "—"}</dd>
            <dt>Network</dt><dd className="wrap-anywhere">{[rep.isp, rep.usage_type].filter(Boolean).join(" · ") || "—"}</dd>
            <dt>Checked</dt><dd>{rep.checked_at ? dateTime(rep.checked_at) : "—"}{rep.cached && <span className="muted small-text"> (cached)</span>}</dd>
          </dl>
        ) : null}
      </div>
      {!reserved && (!rep || !rep.available) && (
        <div>
          <button type="button" onClick={() => void check()} disabled={act.busy}>
            {act.busy ? "Checking…" : rep ? "Try again" : `Check ${ip} on AbuseIPDB`}
          </button>
          {!rep && (
            <p className="muted small-text" style={{ margin: "6px 0 0" }}>
              If the SOC has an AbuseIPDB key, only the IP address is sent to AbuseIPDB.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

const SURICATA_SEVERITY: Record<number, string> = { 1: "high", 2: "medium", 3: "low", 4: "informational" };

/** A rule alert's reason: the Suricata signature that matched, instead of a model explanation. */
function RuleCard({ rule, alertId }: { rule: RuleInfo; alertId: number }) {
  return (
    <Card title="Why the rule fired">
      <p style={{ margin: "0 0 12px" }}>
        Suricata matched the signature <b className="wrap-anywhere">{rule.signature}</b>.
        {rule.count > 1 ? <> It matched {rule.count.toLocaleString()} times for this source, target and port within the folding window.</> : null}
      </p>
      <dl className="kv small-kv">
        <dt>Rule</dt>
        <dd className="mono">sid {rule.sid}{rule.rev != null ? ` · rev ${rule.rev}` : ""}</dd>
        <dt>Category</dt><dd>{rule.category ?? "—"}</dd>
        <dt>Rule severity</dt>
        <dd>{rule.severity} <span className="muted small-text">({SURICATA_SEVERITY[rule.severity] ?? "?"}; 1 is the most severe)</span></dd>
        <dt>Matches</dt><dd>{rule.count.toLocaleString()}</dd>
      </dl>
      <p className="muted small-text" style={{ margin: "12px 0 0" }}>
        Signatures look at packet contents (for example the text of a web request), which the model never sees.
        A rule alert doesn't block on its own unless an admin has allowed its sid to.
      </p>
      <Link className="button-link" style={{ marginTop: 12 }} to={`/assistant${query({ alert: alertId })}`}>
        Explain this alert with the assistant
      </Link>
    </Card>
  );
}

/** "38.6×", "1.2×", "<0.1×"; "—" when the test couldn't compute one (null). */
export function ratioText(r: number | null): string {
  if (r === null || !Number.isFinite(r)) return "—";
  if (r < 0) return "worse than random";
  if (r < 0.1) return "<0.1×";
  return `${Number(r >= 10 ? r.toFixed(1) : r.toFixed(2))}×`;
}

/** How a method did against random features. Passing = clearly better than random (≥ 2×). */
export function verdict(r: FaithfulnessMethod): { tone: Tone; text: string } {
  const x = r.ratio_to_random;
  if (x === null || !Number.isFinite(x)) return { tone: "neutral", text: "no result" };
  if (x >= 2) return { tone: "ok", text: "better than random" };
  if (x > 1) return { tone: "warn", text: "barely better than random" };
  return { tone: "danger", text: "no better than random" };
}

/** Can I trust it? The deletion test the sensor's model passed offline: remove the top features an
 *  explanation names and see how much more the confidence drops than when removing random ones.
 *  Model-level numbers (decided: no live LIME), not a score for this one alert. */
function TrustCard({ sensorId, method }: { sensorId: number; method: string | null }) {
  const { data, error } = useSensors();
  const sensor = data?.sensors.find((s) => s.sensor_id === sensorId);
  const f = sensor?.status?.faithfulness ?? null;
  const stale = sensor && f ? (sensor.revoked ? "revoked" : !sensor.online ? "offline" : null) : null;
  const methods = f ? (["shap", "lime"] as const).filter((m) => f.methods[m]) : [];
  const weakMatch = f?.model_check === "name";
  return (
    <Card title="Can I trust it?" actions={f && !f.model_matches ? <Pill tone="warn">test was for another model</Pill> : undefined}>
      <p className="muted small-text" style={{ marginTop: 0 }}>
        Whether the explanation reflects what the model really used, not whether the prediction is right.
      </p>
      <ErrorText error={error} />
      {!data && !error && <p className="muted" style={{ margin: 0 }}>Loading…</p>}
      {data && !f && (
        <p className="muted" style={{ margin: 0 }}>
          {sensor ? `Sensor ${sensor.name}` : `Sensor #${sensorId}`} hasn't reported an explanation test. It reports one when
          its <code>IDPS_FAITHFULNESS_REPORT</code> points at the output of <code>python -m idps.explain faithfulness</code>.
        </p>
      )}
      {f && (
        <>
          <p style={{ marginTop: 0 }}>
            If an explanation is faithful, removing the {f.top_k} features it ranks highest hurts the model far
            more than removing {f.top_k} random ones. Measured on a sample of {f.flows.toLocaleString()} flows:
          </p>
          <ul className="trust-list">
            {methods.map((m) => {
              const r = f.methods[m]!;
              const used = method === m;
              const v = verdict(r);
              return (
                <li key={m} className={used ? "used" : undefined}>
                  <div className="trust-head">
                    <b>{m.toUpperCase()}</b>
                    {used && <Pill tone="accent">used for this alert</Pill>}
                    <Pill tone={v.tone}>{v.text}</Pill>
                    <span className="trust-ratio">
                      {ratioText(r.ratio_to_random)}
                      {r.ratio_to_random !== null && r.ratio_to_random >= 0 &&
                        <span className="sr-only"> the confidence drop of random features</span>}
                    </span>
                  </div>
                  <span className="muted small-text">
                    confidence drop vs random features ({percent(r.mean_drop, 1)} vs {percent(f.random_mean_drop, 1)});
                    the predicted class changed in {percent(r.label_flip_rate)} of flows; beat random on {percent(r.share_flows_beating_random)} of flows.
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="muted small-text" style={{ marginBottom: 0 }}>
            Measured offline for model <b>{f.model}</b>. It describes this model's explanations in general, not this one alert.
            {stale && ` This is the sensor's last report: it is ${stale} now, so it may run a different model.`}
            {!f.model_matches && " The sensor runs a different model than the one tested, so these numbers may not apply."}
            {f.model_matches && weakMatch && " The report only names the algorithm, so a retrained model of the same kind would also match."}
          </p>
        </>
      )}
    </Card>
  );
}
