import { useMemo } from "react";
import { Link } from "react-router-dom";
import { cloudApi } from "../../api/cloud";
import type { HealthCheck, Instance } from "../../api/cloudTypes";
import { Card, PageHead } from "../../components/common";
import { BarList, Gauge, LineChart } from "../../components/cloud/charts";
import { Async, HealthPill, StatePill, useCloudLoad } from "../../components/cloud/ui";
import { label } from "../../format";
import { timeFormatter } from "./InstanceDetail";

const SERIES: { name: string; title: string }[] = [
  { name: "cpu_pct", title: "CPU" }, { name: "memory_pct", title: "Memory" }, { name: "disk_pct", title: "Disk" },
];

function CheckCell({ check }: { check: HealthCheck | undefined }) {
  if (!check) return <span className="muted">—</span>;
  const v = typeof check.value === "number" ? `${check.value.toFixed(1)}%` : String(check.value);
  return (
    <span>
      <HealthPill status={check.status} /> {v}
      {check.threshold && <span className="muted small-text"> (warn {check.threshold.degraded}, critical {check.threshold.critical})</span>}
    </span>
  );
}

/** Thresholds are the backend's: read from the health checks of any instance that has them. */
function thresholdOf(items: Instance[], name: string): { degraded: number; critical: number } | undefined {
  for (const i of items) {
    const t = i.health.checks.find((c) => c.name === name)?.threshold;
    if (t) return t;
  }
  return undefined;
}

export default function Monitoring() {
  const fleet = useCloudLoad(() => cloudApi.fleetMetrics(), []);
  const instances = useCloudLoad(() => cloudApi.instances({ limit: 200 }), []);
  const live = useMemo(() => (instances.data?.items ?? []).filter((i) => i.state !== "terminated"), [instances.data]);
  const cpuT = thresholdOf(live, "cpu_pct"), memT = thresholdOf(live, "memory_pct"), diskT = thresholdOf(live, "disk_pct");

  return (
    <div className="stack">
      <PageHead title="Monitoring">
        <button type="button" onClick={() => { void fleet.reload(); void instances.reload(); }}>Refresh</button>
      </PageHead>
      <Card title="Fleet metrics">
        <Async state={fleet} what="Loading fleet metrics">
          {(f) => (
            <>
              <div className="grid cols-3-gauges">
                <Gauge label="CPU (average)" value={f.fleet.avg_cpu_pct} warnAt={cpuT?.degraded} critAt={cpuT?.critical}
                  detail={`${f.fleet.running_instances} running, busiest ${f.fleet.max_cpu_pct.toFixed(1)}%`} />
                <Gauge label="Memory (average)" value={f.fleet.avg_memory_pct} warnAt={memT?.degraded} critAt={memT?.critical} />
                <Gauge label="Disk used" value={f.storage.instance_disk_used_pct} warnAt={diskT?.degraded} critAt={diskT?.critical}
                  detail={`${f.storage.instance_disk_used_gb} of ${f.storage.instance_disk_gb} GB`} />
              </div>
              <dl className="kv cl-kv-row">
                <dt>Network in (average)</dt><dd>{f.fleet.avg_net_in_mbps.toFixed(2)} Mbps</dd>
                <dt>Network out (average)</dt><dd>{f.fleet.avg_net_out_mbps.toFixed(2)} Mbps</dd>
                <dt>Volumes in use</dt><dd>{f.storage.volumes_in_use_gb} of {f.storage.volumes_gb} GB ({f.storage.volumes_in_use_pct}%)</dd>
                <dt>Bucket data</dt><dd>{f.storage.buckets_gb} GB</dd>
              </dl>
              <p className="muted small-text">{f.metrics_label}</p>
              <div className="grid cols-main-side">
                <LineChart title="Fleet average CPU, last 24 hours" unit="%" yMax={100} timestamps={f.cpu_trend_24h.timestamps} formatTime={timeFormatter("24h")}
                  series={[{ key: "avg", label: "Average CPU", values: f.cpu_trend_24h.avg_cpu_pct }]} />
                <BarList title="Busiest instances by CPU" empty="No running instances."
                  items={f.busiest.map((b) => ({ key: b.id, label: b.name, value: b.cpu_pct, text: `${b.cpu_pct.toFixed(1)}%`, detail: b.id }))} />
              </div>
            </>
          )}
        </Async>
      </Card>

      <Card title="Instance health">
        <Async state={instances} what="Loading instance health">
          {() => live.length === 0 ? <p className="muted">No instances.</p> : (
            <div className="table-wrap">
              <table>
                <caption className="cl-sr">Health of each instance, with its thresholds</caption>
                <thead><tr><th scope="col">Instance</th><th scope="col">State</th><th scope="col">Health</th>{SERIES.map((s) => <th key={s.name} scope="col">{s.title}</th>)}</tr></thead>
                <tbody>
                  {live.map((i) => (
                    <tr key={i.id}>
                      <td><Link to={`../compute/${encodeURIComponent(i.id)}`}>{i.name}</Link><div className="muted small-text"><code>{i.id}</code></div></td>
                      <td><StatePill state={i.state} /></td>
                      <td><HealthPill status={i.health.status} /></td>
                      {SERIES.map((s) => <td key={s.name}>{i.state === "running" ? <CheckCell check={i.health.checks.find((c) => c.name === s.name)} /> : <span className="muted">{label(i.state)}: nothing to measure</span>}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Async>
      </Card>
    </div>
  );
}
