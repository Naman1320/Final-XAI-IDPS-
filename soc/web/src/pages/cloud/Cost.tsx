import { useState } from "react";
import { cloudApi } from "../../api/cloud";
import type { CostRange } from "../../api/cloudTypes";
import { Card, PageHead, Segmented } from "../../components/common";
import { BarList, StackedColumns } from "../../components/cloud/charts";
import { Async, money, useCloudLoad } from "../../components/cloud/ui";

const RANGES: { value: CostRange; label: string }[] = [
  { value: "7d", label: "7 days" }, { value: "30d", label: "30 days" }, { value: "90d", label: "90 days" },
];

export default function Cost() {
  const [range, setRange] = useState<CostRange>("30d");
  const state = useCloudLoad(() => cloudApi.cost(range), [range]);

  return (
    <div className="stack">
      <PageHead title="Cost and usage">
        <Segmented label="Time range" options={RANGES} value={range} onChange={setRange} />
      </PageHead>
      <Async state={state} what="Loading cost">
        {(c) => {
          const m = (x: number) => money(x, c.currency);
          if (!c.available) return <Card><p className="muted">This data source has no cost data.</p></Card>;
          const services = Object.keys(c.by_service);
          return (
            <>
              <div className="grid cols-4">
                <Card title={`Total, ${c.first_day} to ${c.last_day}`} className="cl-stat"><div className="cl-stat-value">{m(c.total)}</div><div className="muted small-text">{c.range} range</div></Card>
                <Card title="Month to date" className="cl-stat"><div className="cl-stat-value">{m(c.forecast.month_to_date)}</div><div className="muted small-text">{c.forecast.month}, day {c.forecast.days_elapsed} of {c.forecast.days_in_month}</div></Card>
                <Card title="Forecast for the month" className="cl-stat"><div className="cl-stat-value">{m(c.forecast.projected_month_total)}</div><div className="muted small-text">{c.forecast.method}</div></Card>
              </div>
              <div className="grid cols-main-side">
                <Card title="Cost by day">
                  <StackedColumns title={`Daily cost by service (${c.currency})`} format={m} partKeys={services}
                    columns={c.by_day.map((d) => ({ key: d.day, label: d.day, parts: d.services, total: d.total }))} />
                </Card>
                <Card title="Cost by service">
                  <BarList title="Cost by service" items={services.map((s) => ({ key: s, label: s, value: c.by_service[s], text: m(c.by_service[s]), detail: c.total ? `${((c.by_service[s] / c.total) * 100).toFixed(1)}% of the total` : undefined }))} />
                  <div className="table-wrap">
                    <table>
                      <caption className="cl-sr">Cost by service</caption>
                      <thead><tr><th scope="col">Service</th><th scope="col">Cost</th></tr></thead>
                      <tbody>{services.map((s) => <tr key={s}><th scope="row">{s}</th><td>{m(c.by_service[s])}</td></tr>)}</tbody>
                    </table>
                  </div>
                </Card>
              </div>
              <Card title="Top cost drivers">
                {c.top_drivers.length === 0 ? <p className="muted">No instance ran in this range.</p> : (
                  <>
                    <BarList title="Estimated cost by instance" items={c.top_drivers.map((d) => ({ key: d.instance_id, label: d.name, value: d.estimated_usd, text: m(d.estimated_usd), detail: `${d.instance_type}, ${d.running_hours} running hours at ${m(d.hourly_usd)} per hour` }))} />
                    <div className="table-wrap">
                      <table>
                        <caption className="cl-sr">Top cost drivers</caption>
                        <thead><tr><th scope="col">Instance</th><th scope="col">Type</th><th scope="col">Running hours</th><th scope="col">Price per hour</th><th scope="col">Estimate</th></tr></thead>
                        <tbody>{c.top_drivers.map((d) => (
                          <tr key={d.instance_id}><td>{d.name} <code>{d.instance_id}</code></td><td>{d.instance_type}</td><td>{d.running_hours}</td><td>{m(d.hourly_usd)}</td><td>{m(d.estimated_usd)}</td></tr>
                        ))}</tbody>
                      </table>
                    </div>
                  </>
                )}
                {c.by_instance_type.length > 0 && (
                  <>
                    <h3>By instance type</h3>
                    <div className="table-wrap">
                      <table>
                        <caption className="cl-sr">Estimated cost by instance type</caption>
                        <thead><tr><th scope="col">Type</th><th scope="col">Instances</th><th scope="col">Running hours</th><th scope="col">Estimate</th></tr></thead>
                        <tbody>{c.by_instance_type.map((t) => <tr key={t.instance_type}><td>{t.instance_type}</td><td>{t.instances}</td><td>{t.running_hours}</td><td>{m(t.estimated_usd)}</td></tr>)}</tbody>
                      </table>
                    </div>
                  </>
                )}
                <p className="muted small-text">{c.cost_note}</p>
              </Card>
            </>
          );
        }}
      </Async>
    </div>
  );
}
