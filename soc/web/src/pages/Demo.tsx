import { useEffect, useId, useState } from "react";
import { Link } from "react-router-dom";
import { phoneBuild, workspace } from "../workspace";
import { api } from "../api/client";
import type { DemoRun, DemoRunStatus, DemoState, DemoStepStatus } from "../api/types";
import { useAuth } from "../auth";
import { Card, ErrorText, PageHead, Pill, useAction, useLoad, useNow, type Tone } from "../components/common";
import { dateTime } from "../format";
import { reporting, useSensors } from "../sensors";

/** Poll every 2 s while a run is queued or running, otherwise every 10 s (to see the runner come online). */
export const ACTIVE_POLL_MS = 2000;
export const IDLE_POLL_MS = 10_000;

/** What to point at on screen while each step runs. Keyed by the SOC's fixed step keys. */
export const STEP_HINTS: Record<string, string> = {
  portscan: "Alerts appear in about 2 minutes: open an alert to show its SHAP explanation.",
  ssh_bruteforce: "Watch the SSH brute-force alerts arrive on Alerts, then open Response to show the block "
    + "decision for the attacker (a dry-run record when blocking is off).",
  syn_flood: "Show the flood on the Dashboard (alerts by class and severity) and the attacker on Maps.",
  settle: "The last flows end and their alerts arrive. Finish on the Dashboard counts and a case or the weekly report.",
};

const STEP_CHIP: Record<DemoStepStatus, { tone: Tone; mark: string; text: string }> = {
  pending: { tone: "neutral", mark: "○", text: "Pending" },
  running: { tone: "accent", mark: "▶", text: "Running" },
  done: { tone: "ok", mark: "✓", text: "Done" },
  failed: { tone: "danger", mark: "✕", text: "Failed" },
  skipped: { tone: "neutral", mark: "–", text: "Skipped" },
};

const RUN_CHIP: Record<DemoRunStatus, { tone: Tone; text: string }> = {
  queued: { tone: "neutral", text: "Queued: waiting for the runner" },
  running: { tone: "accent", text: "Running" },
  done: { tone: "ok", text: "Finished" },
  failed: { tone: "danger", text: "Failed" },
  cancelled: { tone: "warn", text: "Cancelled" },
  expired: { tone: "warn", text: "Expired (over 15 minutes)" },
};

export function isActive(run: DemoRun | null | undefined): boolean {
  return run?.status === "queued" || run?.status === "running";
}

/** "1:05" (or "1:02:03") between two times; "" when it has not started. */
export function elapsed(from: string | null, to: string | null, now: number): string {
  if (!from) return "";
  const start = Date.parse(from);
  const end = to ? Date.parse(to) : now;
  if (Number.isNaN(start) || Number.isNaN(end)) return "";
  const secs = Math.max(0, Math.floor((end - start) / 1000));
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = String(secs % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
}

/** Why the Run button is off, or null when a run can start. */
export function runBlocker(data: DemoState | null): string | null {
  if (!data) return "Loading the demo status…";
  if (!data.enabled) return "Demo mode is off in the SOC: set IDPS_SOC_DEMO_TOKEN (see docs/soc.md, \"Live demo\").";
  if (isActive(data.run)) return "A run is already in progress: wait for it to finish, or cancel it.";
  if (!data.runner_online) return "The demo runner is offline: start scripts/demo_runner.py on the lab host.";
  return null;
}

function StepChip({ status }: { status: DemoStepStatus }) {
  const c = STEP_CHIP[status];
  // Only status changes are announced; the per-second timers are never inside a live region.
  return <span aria-live="polite"><Pill tone={c.tone}><span aria-hidden="true">{c.mark}</span> {c.text}</Pill></span>;
}

function LabSensorActivity({ admin }: { admin: boolean }) {
  const { data, error } = useSensors();
  const sensors = reporting(data).filter(sensor => sensor.status.mode === "live");
  return (
    <Card title="Live sensor activity" actions={admin && <Link to="/c6">Open C6 replay</Link>}>
      <ErrorText error={error} />
      {!data && !error && <p>Checking sensor reports…</p>}
      {data && sensors.length === 0 && <p>No live sensor is reporting.</p>}
      {sensors.length > 0 && <>
        <p className="muted">Totals since each sensor started. Reports refresh every 30 seconds.</p>
        <div className="table-wrap"><table>
          <thead><tr><th>Sensor</th><th>Flows</th><th>Alerts</th><th>Would block</th><th>Blocked</th><th>Last report</th></tr></thead>
          <tbody>{sensors.map(({ sensor_id, name, status, last_seen_at }) => (
            <tr key={sensor_id}><th scope="row">{name}</th><td>{status.counters.flows.toLocaleString()}</td>
              <td>{status.counters.alerts.toLocaleString()}</td><td>{status.counters.would_block.toLocaleString()}</td>
              <td>{status.counters.blocked.toLocaleString()}</td><td>{dateTime(last_seen_at)}</td></tr>
          ))}</tbody>
        </table></div>
      </>}
    </Card>
  );
}

/** Live demo: an admin starts the fixed lab attack run; everyone signed in can follow it. */
export default function Demo() {
  const { me } = useAuth();
  const admin = me?.role === "admin";
  const { data, error, reload } = useLoad(() => api<DemoState>("/demo"), []);
  const act = useAction();
  const now = useNow(1000);
  const reasonId = useId();
  const [reloading, setReloading] = useState(false);
  const run = data?.run ?? null;
  const active = isActive(run);

  useEffect(() => {
    const id = setInterval(() => void reload(), active ? ACTIVE_POLL_MS : IDLE_POLL_MS);
    return () => clearInterval(id);
  }, [active, reload]);

  // Keep both buttons off from the click until the reload has shown the new state, so a second
  // click cannot slip in between the POST finishing and the page knowing about the run.
  async function post(path: string) {
    const r = await act.run(() => api<DemoRun>(path, { method: "POST" }));
    if (!r) return;
    setReloading(true);
    try {
      await reload();
    } finally {
      setReloading(false);
    }
  }

  const start = () => post("/admin/demo/run");
  const cancel = () => post("/admin/demo/cancel");

  const blocker = runBlocker(data);
  return (
    <>
      <PageHead title="Live demo">
        {data && !data.enabled && <Pill tone="neutral" round>Demo mode off</Pill>}
        {data?.enabled && (data.runner_online
          ? <Pill tone="ok" round dot>Runner online</Pill>
          : <Pill tone="warn" round dot>Runner offline</Pill>)}
      </PageHead>
      {workspace.lab && <LabSensorActivity admin={admin} />}
      <Card title={workspace.lab ? "Live run progress" : "Attack run"}
        actions={admin && (
          <div className="row-actions">
            {!phoneBuild && !workspace.lab && <button type="button" className="primary" disabled={blocker !== null || act.busy || reloading}
              aria-describedby={blocker ? reasonId : undefined} onClick={() => void start()}>
              {(act.busy || reloading) && !active ? "Starting…" : "Run demo"}
            </button>}
            {active && (
              <button type="button" disabled={act.busy || reloading} onClick={() => void cancel()}>Cancel run</button>
            )}
          </div>
        )}>
        <p className="muted" style={{ marginTop: 0 }}>
          {workspace.lab ? "This workspace follows runs started on the lab host. Each step appears here when the runner reports it." : <>
          A fixed sequence of attacks from the lab's attacker container against the victims, run by the demo
          runner on the lab host. The SOC only records the request and shows progress; it never reaches the
          attacker. Results show up on the <Link to="/alerts">Alerts</Link>, <Link to="/response">Response</Link>{" "}
          and <Link to="/">Dashboard</Link> pages like any other traffic.</>}
        </p>
        {data && !data.enabled && (
          <div className="card notice-box" role="note">
            <b>Demo mode is off.</b>{" "}
            <span className="muted">The SOC has no IDPS_SOC_DEMO_TOKEN set, so no run can be started.</span>
          </div>
        )}
        {data?.enabled && !data.runner_online && (
          <div className="card notice-box" role="note">
            <b>The demo runner is offline.</b>{" "}
            <span className="muted">It has not checked in during the last 30 seconds.</span>
          </div>
        )}
        {admin && !phoneBuild && !workspace.lab && blocker && data && <p id={reasonId} className="muted small-text">{blocker}</p>}
        <ErrorText error={error ?? act.error} />

        {!data ? <p className="muted">Loading…</p> : !run ? (
          <p className="muted">No demo has run since the SOC started.</p>
        ) : (
          <div>
            <div className="toolbar" style={{ alignItems: "center" }}>
              <span>Run status:</span>{" "}
              <span aria-live="polite"><Pill tone={RUN_CHIP[run.status].tone}>{RUN_CHIP[run.status].text}</Pill></span>
              <span className="muted small-text">
                requested by <b>{run.requested_by}</b> at {dateTime(run.requested_at)}
                {" · "}elapsed {elapsed(run.requested_at, run.finished_at, now)}
              </span>
            </div>
            <ol className="demo-steps">
              {run.steps.map((s) => {
                const time = elapsed(s.started_at, s.ended_at, now);
                return (
                  <li key={s.key} className={`demo-step ${s.status}`} aria-current={s.status === "running" ? "step" : undefined}>
                    <div className="demo-step-head">
                      <b>{s.label}</b>
                      <StepChip status={s.status} />
                      {time && <span className="muted small-text">{s.status === "running" ? "running for" : "took"} {time}</span>}
                    </div>
                    {s.note && <p className="small-text wrap-anywhere demo-note">{s.note}</p>}
                    {STEP_HINTS[s.key] && <p className="muted small-text demo-hint"><b>What to show:</b> {STEP_HINTS[s.key]}</p>}
                  </li>
                );
              })}
            </ol>
          </div>
        )}
      </Card>
    </>
  );
}
