import { useEffect } from "react";
import { api } from "../api/client";
import { Card, ErrorText, PageHead, Pill, useAction, useLoad } from "../components/common";
import { dateTime } from "../format";

const stages = {
  capture: "Input", lab_alert: "Lab detection", lab_block: "Sensor firewall",
  baseline: "ACL before response", cloud_alert: "Cloud detection",
  response: "Automatic ACL response", acl: "AWS CLI verification", error: "Execution error",
};
type Mode = "replay" | "observe";
interface Observation { stage: keyof typeof stages; at: string; evidence: string }
interface Run {
  id: string; mode: Mode; status: "queued" | "running" | "verified" | "failed" | "incomplete";
  started_at: string; ended_at: string | null; events: Observation[];
}
interface View { enabled: boolean; worker_online: boolean; run: Run | null; demo_status: string | null }

function elapsed(start: string, end: string) {
  return ((Date.parse(end) - Date.parse(start)) / 1000).toFixed(1) + " s";
}

export default function C6() {
  const { data, error, reload } = useLoad(() => api<View>("/c6"), []);
  const action = useAction();
  const run = data?.run;
  const active = run?.status === "queued" || run?.status === "running";
  useEffect(() => {
    const interval = window.setInterval(() => void reload(), active ? 1500 : 5000);
    return () => window.clearInterval(interval);
  }, [active, reload]);
  async function start(mode: Mode) {
    await action.run(() => api<Run>("/admin/c6/run", { method: "POST", json: { mode } }));
    await reload();
  }
  function saveEvidence() {
    if (!run) return;
    const file = new Blob([JSON.stringify(run, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = `c6-${run.id}.json`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const disabled = !data?.enabled || !data.worker_online || active || action.busy || !!error;
  return <>
    <PageHead title="C6 security demonstration">
      <Pill tone={run?.status === "verified" ? "ok" : run?.status === "failed" ? "danger" : "neutral"}>
        {run?.status ?? "Idle"}
      </Pill>
    </PageHead>
    <ErrorText error={error || action.error} />
    <Card title="Start a demonstration">
      <p>Replay a recorded capture through the sensor and cloud models, or collect evidence from an independently running lab. ACL verification uses the local Moto emulator.</p>
      <div className="row-actions">
        <button className="primary" disabled={disabled} onClick={() => void start("replay")}>Start C6 replay</button>
        <button disabled={disabled} onClick={() => void start("observe")}>Observe live lab</button>
      </div>
      <p className="muted" role="status">{!data ? "Reading SOC status…" : !data.enabled ? "C6 worker credential is unset."
        : !data.worker_online && !active ? "C6 worker offline. Start the host worker to enable runs."
        : active ? "Collecting evidence…" : "Evidence worker online."}
        {" "}Live Demo runner session: {data?.demo_status ?? "none reported"}.</p>
    </Card>
    {run && <>
      <Card title={run.mode === "replay" ? "Recorded capture · isolated sensor" : "Live lab observation"}>
        <dl>
          <dt>Run ID</dt><dd><code>{run.id}</code></dd>
          <dt>Started</dt><dd>{dateTime(run.started_at)}</dd>
          <dt>Run duration</dt><dd>{run.ended_at ? elapsed(run.started_at, run.ended_at) : "In progress"}</dd>
        </dl>
        <div className="row-actions">{Object.entries(stages).filter(([key]) => key !== "error").map(([key, label]) => {
          const found = run.events.some(event => event.stage === key);
          return <Pill key={key} tone={found ? "ok" : "neutral"}>{label} · {found ? "observed" : "no evidence"}</Pill>;
        })}</div>
      </Card>
      <Card title="Evidence timeline" actions={<button onClick={saveEvidence}>Save evidence</button>}>
        {run.events.length === 0 ? <p>Waiting for the first observation.</p> : <div className="table-wrap"><table>
          <thead><tr><th>Observed at</th><th>Since start</th><th>Stage</th><th>Evidence</th></tr></thead>
          <tbody>{run.events.map(event => <tr key={event.stage}>
            <td><time dateTime={event.at}>{dateTime(event.at)}</time></td>
            <td>{elapsed(run.started_at, event.at)}</td><td>{stages[event.stage]}</td>
            <td style={{ overflowWrap: "anywhere" }}>{event.evidence}</td>
          </tr>)}</tbody>
        </table></div>}
      </Card>
    </>}
  </>;
}
