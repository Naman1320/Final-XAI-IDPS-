import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { cloudApi } from "../../api/cloud";
import type { InstanceMetrics, MetricRange } from "../../api/cloudTypes";
import { Card, PageHead, Segmented } from "../../components/common";
import { LineChart } from "../../components/cloud/charts";
import {
  Async, ConfirmDialog, HealthPill, PERM, StatePill, WriteButton, useCloudLoad, useToast,
} from "../../components/cloud/ui";
import { dateTime, label } from "../../format";
import { EditInstance } from "./Compute";

type Verb = "start" | "stop" | "reboot" | "terminate";
const VERBS: Record<Verb, { button: string; title: string; text: string; danger: boolean; done: string }> = {
  start: { button: "Start", title: "Start this instance?", text: "A stopped instance becomes pending, then running about 10 seconds later.", danger: false, done: "is starting" },
  stop: { button: "Stop", title: "Stop this instance?", text: "A running instance stops and releases its public address.", danger: true, done: "was stopped" },
  reboot: { button: "Reboot", title: "Reboot this instance?", text: "A running instance restarts.", danger: false, done: "is rebooting" },
  terminate: { button: "Terminate", title: "Terminate this instance?", text: "Terminating is permanent: the instance cannot be started again, its public address is released and its volumes are detached. The record stays, as terminated.", danger: true, done: "was terminated" },
};

const RANGES: { value: MetricRange; label: string }[] = [
  { value: "1h", label: "1 hour" }, { value: "24h", label: "24 hours" }, { value: "7d", label: "7 days" },
];

export function timeFormatter(range: MetricRange) {
  return (iso: string) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return range === "7d"
      ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
      : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  };
}

export function MetricCharts({ m, range }: { m: InstanceMetrics; range: MetricRange }) {
  const f = timeFormatter(range);
  const s = m.series;
  return (
    <div className="grid cols-2">
      <LineChart title="CPU utilisation" unit="%" yMax={100} timestamps={m.timestamps} formatTime={f} series={[{ key: "cpu", label: "CPU", values: s.cpu_pct }]} />
      <LineChart title="Memory utilisation" unit="%" yMax={100} timestamps={m.timestamps} formatTime={f} series={[{ key: "mem", label: "Memory", values: s.memory_pct }]} />
      <LineChart title="Disk utilisation" unit="%" yMax={100} timestamps={m.timestamps} formatTime={f} series={[{ key: "disk", label: "Disk", values: s.disk_pct }]} />
      <LineChart title="Network throughput" unit=" Mbps" decimals={2} timestamps={m.timestamps} formatTime={f}
        series={[{ key: "in", label: "Network in", values: s.net_in_mbps }, { key: "out", label: "Network out", values: s.net_out_mbps }]} />
    </div>
  );
}

export default function InstanceDetail() {
  const { id = "" } = useParams();
  const toast = useToast();
  const [range, setRange] = useState<MetricRange>("1h");
  const [verb, setVerb] = useState<Verb | null>(null);
  const [editing, setEditing] = useState(false);
  const inst = useCloudLoad(() => cloudApi.instance(id), [id], { pollMs: 3000, poll: (d) => d.state === "pending" });
  const metrics = useCloudLoad(() => cloudApi.instanceMetrics(id, range), [id, range], { pollMs: 3000, poll: () => false });

  const afterChange = () => { void inst.reload(); void metrics.reload(); };
  const doVerb = async (v: Verb) => {
    const r = v === "terminate" ? await cloudApi.terminateInstance(id) : await cloudApi.instanceAction(id, v);
    toast(`Instance ${r.name} ${VERBS[v].done}.`);
    afterChange();
  };

  return (
    <div className="stack">
      <PageHead title={inst.data ? <>{inst.data.name} <StatePill state={inst.data.state} /></> : "Instance"}>
        <Link to=".." relative="path" className="button-link">All instances</Link>
        <button type="button" onClick={afterChange}>Refresh</button>
      </PageHead>
      <Async state={inst} what="Loading the instance">
        {(i) => (
          <>
            <Card title="Actions">
              <div className="row-actions">
                {(Object.keys(VERBS) as Verb[]).map((v) => (
                  <WriteButton key={v} permission={PERM.instances} className={v === "terminate" ? "danger-soft" : undefined} onClick={() => setVerb(v)}>
                    {VERBS[v].button}
                  </WriteButton>
                ))}
                <WriteButton permission={PERM.instances} disabled={i.state === "terminated"}
                  title={i.state === "terminated" ? "A terminated instance cannot be changed" : undefined} onClick={() => setEditing(true)}>
                  Edit name and tags
                </WriteButton>
              </div>
              <p className="muted small-text">The backend decides which action is allowed in which state and explains a refusal.</p>
            </Card>

            <div className="grid cols-2">
              <Card title="Details">
                <dl className="kv">
                  <dt>ID</dt><dd><code>{i.id}</code></dd>
                  <dt>Type</dt><dd>{i.instance_type} ({i.vcpus} vCPU, {i.memory_gb} GB memory)</dd>
                  <dt>Operating system</dt><dd>{i.os}</dd>
                  <dt>Zone</dt><dd>{i.az}</dd>
                  <dt>VPC / subnet</dt><dd><code>{i.vpc_id}</code> / <code>{i.subnet_id}</code></dd>
                  <dt>Private IP</dt><dd><code>{i.private_ip}</code></dd>
                  <dt>Public IP</dt><dd>{i.public_ip ? <code>{i.public_ip}</code> : <span className="muted">none</span>}</dd>
                  <dt>Disk</dt><dd>{i.disk_gb} GB</dd>
                  <dt>Security groups</dt><dd>{i.security_group_ids.map((g) => <code key={g} className="cl-chip">{g}</code>)}</dd>
                  <dt>Launched</dt><dd>{dateTime(i.launched_at)}</dd>
                  <dt>Updated</dt><dd>{dateTime(i.updated_at)}</dd>
                  <dt>Tags</dt>
                  <dd>{Object.keys(i.tags).length === 0 ? <span className="muted">none</span> :
                    Object.entries(i.tags).map(([k, v]) => <span key={k} className="cl-chip">{k}={v}</span>)}</dd>
                </dl>
              </Card>
              <Card title={<>Health <HealthPill status={i.health.status} /></>}>
                <div className="table-wrap">
                  <table>
                    <caption className="cl-sr">Health checks</caption>
                    <thead><tr><th scope="col">Check</th><th scope="col">Status</th><th scope="col">Value</th><th scope="col">Warning / critical at</th></tr></thead>
                    <tbody>
                      {i.health.checks.map((c) => (
                        <tr key={c.name}>
                          <td>{label(c.name)}</td>
                          <td><HealthPill status={c.status} /></td>
                          <td>{typeof c.value === "number" ? c.value.toFixed(1) : c.value}</td>
                          <td>{c.threshold ? `${c.threshold.degraded} / ${c.threshold.critical}` : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </div>
            {editing && <EditInstance instance={i} onClose={() => setEditing(false)} onSaved={afterChange} />}
          </>
        )}
      </Async>

      <Card title="Metrics" actions={<Segmented label="Time range" options={RANGES} value={range} onChange={setRange} />}>
        <Async state={metrics} what="Loading metrics">
          {(m) => (
            <>
              <p className="muted small-text">{m.metrics_label}. {m.state === "running" ? "" : `The instance is ${m.state}: its CPU, memory and network read 0.`}</p>
              <MetricCharts m={m} range={range} />
            </>
          )}
        </Async>
      </Card>

      {verb && (
        <ConfirmDialog title={VERBS[verb].title} confirmLabel={VERBS[verb].button} danger={VERBS[verb].danger}
          onConfirm={() => doVerb(verb)} onClose={() => setVerb(null)}>
          <p>{VERBS[verb].text}</p>
          <p>Instance: <b>{inst.data?.name ?? id}</b> <code>{id}</code></p>
        </ConfirmDialog>
      )}
    </div>
  );
}
