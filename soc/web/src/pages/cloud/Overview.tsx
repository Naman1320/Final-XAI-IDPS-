import { Link } from "react-router-dom";
import { cloudApi } from "../../api/cloud";
import { Card, Pill, PageHead } from "../../components/common";
import { Gauge } from "../../components/cloud/charts";
import { Async, AlertSeverityPill, HealthPill, StatePill, ago, money, useCloudLoad } from "../../components/cloud/ui";
import { dateTime } from "../../format";

const STATE_ORDER = ["running", "pending", "stopped", "terminated"];

function Stat({ title, value, children, to }: { title: string; value: string | number; children?: React.ReactNode; to?: string }) {
  return (
    <Card title={title} className="cl-stat">
      <div className="cl-stat-value">{value}</div>
      <div className="muted small-text">{children}</div>
      {to && <Link to={to} className="small-text">Open {title.toLowerCase()}</Link>}
    </Card>
  );
}

export default function Overview() {
  const overview = useCloudLoad(() => cloudApi.overview(), []);
  const fleet = useCloudLoad(() => cloudApi.fleetMetrics(), []);
  const alerts = useCloudLoad(() => cloudApi.alerts({ status: "open", limit: 5 }), []);
  const activity = useCloudLoad(() => cloudApi.activity({ limit: 8 }), []);

  return (
    <div className="stack">
      <PageHead title="Cloud overview">
        <button type="button" onClick={() => { void overview.reload(); void fleet.reload(); void alerts.reload(); void activity.reload(); }}>Refresh</button>
      </PageHead>

      <Async state={overview} what="Loading the infrastructure summary">
        {(o) => (
          <>
            <div className="grid cols-4" aria-label="Infrastructure summary">
              <Stat title="Instances" value={o.instances.total} to="compute">
                <span className="cl-pills">
                  {STATE_ORDER.filter((s) => o.instances.by_state[s] !== undefined).map((s) => (
                    <span key={s}><StatePill state={s} /> {o.instances.by_state[s]}</span>
                  ))}
                </span>
              </Stat>
              <Stat title="Volumes" value={o.totals.volumes} to="storage">
                {o.totals.volume_gb} GB, {o.totals.volumes_in_use} in use
              </Stat>
              <Stat title="Buckets" value={o.totals.buckets} to="storage">
                {o.totals.bucket_objects.toLocaleString()} objects, {o.totals.bucket_gb} GB
              </Stat>
              <Stat title="VPCs" value={o.totals.vpcs} to="network">
                {o.totals.subnets} subnets, {o.totals.security_groups} security groups
              </Stat>
            </div>

            <div className="grid cols-2">
              <Card title="Health">
                <ul className="cl-health-list" aria-label="Instances by health">
                  {Object.entries(o.health).map(([k, n]) => <li key={k}><HealthPill status={k} /> <b>{n}</b></li>)}
                </ul>
                <p className="muted small-text">Unknown means the instance is not running, so there is nothing to measure. Metrics are {o.metrics_source}.</p>
                <Link to="monitoring">Open monitoring</Link>
              </Card>
              <Card title="Cost this month">
                {o.cost.available ? (
                  <dl className="kv">
                    <dt>Month to date ({o.cost.month})</dt><dd><b>{money(o.cost.month_to_date, o.cost.currency)}</b></dd>
                    <dt>Last month</dt><dd>{money(o.cost.last_month_total, o.cost.currency)}</dd>
                    <dt>Same days last month</dt><dd>{money(o.cost.last_month_same_period, o.cost.currency)}</dd>
                    <dt>Change</dt>
                    <dd>{o.cost.change_vs_same_period_pct === null ? "—"
                      : <Pill tone={o.cost.change_vs_same_period_pct > 0 ? "warn" : "ok"}>
                        {o.cost.change_vs_same_period_pct > 0 ? "▲ up " : "▼ down "}{Math.abs(o.cost.change_vs_same_period_pct)}%
                      </Pill>}</dd>
                    <dt>Forecast for the month</dt><dd>{money(o.cost.forecast_month_total, o.cost.currency)}</dd>
                  </dl>
                ) : <p className="muted">This data source has no cost data.</p>}
                <Link to="cost">Open cost and usage</Link>
              </Card>
            </div>
          </>
        )}
      </Async>

      <Card title="Fleet utilisation">
        <Async state={fleet} what="Loading utilisation">
          {(f) => (
            <>
              <div className="grid cols-3-gauges">
                <Gauge label="CPU (fleet average)" value={f.fleet.avg_cpu_pct} detail={`${f.fleet.running_instances} running, busiest ${f.fleet.max_cpu_pct.toFixed(1)}%`} />
                <Gauge label="Memory (fleet average)" value={f.fleet.avg_memory_pct} detail={`${f.fleet.running_instances} running`} />
                <Gauge label="Storage used" value={f.storage.instance_disk_used_pct}
                  detail={`${f.storage.instance_disk_used_gb} of ${f.storage.instance_disk_gb} GB on instance disks`} />
              </div>
              <p className="muted small-text">{f.metrics_label}</p>
            </>
          )}
        </Async>
      </Card>

      <div className="grid cols-2">
        <Card title="Open alerts" actions={<Link to="alerts">All alerts</Link>}>
          <Async state={alerts} what="Loading alerts">
            {(a) => (
              <>
                <p>{a.total} open</p>
                {a.items.length === 0 ? <p className="muted">No open alerts.</p> : (
                  <ul className="queue-list">
                    {a.items.map((al) => (
                      <li key={al.id}>
                        <span><AlertSeverityPill severity={al.severity} /> {al.message}</span>
                        <span className="muted small-text">{al.resource_type} {al.resource_id}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </Async>
        </Card>
        <Card title="Recent activity" actions={<Link to="activity">All activity</Link>}>
          <Async state={activity} what="Loading activity">
            {(a) => a.items.length === 0 ? <p className="muted">No activity yet.</p> : (
              <ol className="timeline">
                {a.items.map((it) => (
                  <li key={it.id}>
                    <span className="tl-dot accent" aria-hidden="true" />
                    <span>
                      <b title={dateTime(it.at)}>{ago(it.at)}</b> {it.actor} <code>{it.action}</code> {it.resource_type} <code>{it.resource_id}</code>
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </Async>
        </Card>
      </div>
    </div>
  );
}
