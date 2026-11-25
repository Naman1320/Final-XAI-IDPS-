import { useEffect, useState } from "react";
import { cloudApi } from "../../api/cloud";
import { Card, PageHead } from "../../components/common";
import { Async, Pager, ago, useCloudLoad } from "../../components/cloud/ui";
import { dateTime, oneLine } from "../../format";

const LIMIT = 20;

export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

function details(d: Record<string, unknown>): string {
  const { data_source: _ds, ...rest } = d;
  const text = Object.entries(rest).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(", ");
  return oneLine(text, 160);
}

export default function Activity() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [rtype, setRtype] = useState("");
  const [rid, setRid] = useState("");
  const [offset, setOffset] = useState(0);
  const f = useDebounced({ actor: actor.trim(), action: action.trim(), rtype, rid: rid.trim() });
  const state = useCloudLoad(
    () => cloudApi.activity({ actor: f.actor, action: f.action, resource_type: f.rtype, resource_id: f.rid, limit: LIMIT, offset }),
    [f.actor, f.action, f.rtype, f.rid, offset]);
  const setFilter = (fn: () => void) => { fn(); setOffset(0); };

  return (
    <div className="stack">
      <PageHead title="Activity" />
      <Card>
        <form className="toolbar" onSubmit={(e) => e.preventDefault()} aria-label="Activity filters">
          <label className="field">Actor
            <input value={actor} maxLength={64} onChange={(e) => setFilter(() => setActor(e.target.value))} placeholder="e.g. demo-admin" />
          </label>
          <label className="field">Action (exact)
            <input value={action} maxLength={48} onChange={(e) => setFilter(() => setAction(e.target.value))} placeholder="e.g. instance.stop" />
          </label>
          <label className="field">Resource type
            <select value={rtype} onChange={(e) => setFilter(() => setRtype(e.target.value))}>
              <option value="">All</option>
              {["instance", "volume", "bucket", "security_group", "alert", "demo_data"].map((t) => <option key={t} value={t}>{t.replace("_", " ")}</option>)}
            </select>
          </label>
          <label className="field">Resource id
            <input value={rid} maxLength={64} onChange={(e) => setFilter(() => setRid(e.target.value))} placeholder="e.g. i-1234abcd" />
          </label>
          <button type="button" onClick={() => { setActor(""); setAction(""); setRtype(""); setRid(""); setOffset(0); }}>Clear filters</button>
        </form>
        <Async state={state} what="Loading activity">
          {(d) => (
            <>
              {d.items.length === 0 ? <p className="muted">No activity matches these filters.</p> : (
                <div className="table-wrap">
                  <table>
                    <caption className="cl-sr">Cloud activity, newest first</caption>
                    <thead><tr><th scope="col">When</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Resource</th><th scope="col">Details</th></tr></thead>
                    <tbody>
                      {d.items.map((a) => (
                        <tr key={a.id}>
                          <td title={dateTime(a.at)}>{ago(a.at)}<div className="muted small-text">{dateTime(a.at)}</div></td>
                          <td>{a.actor}</td>
                          <td><code>{a.action}</code></td>
                          <td>{a.resource_type} <code>{a.resource_id}</code></td>
                          <td className="muted small-text wrap-anywhere">{details(a.details)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Pager total={d.total} limit={d.limit} offset={d.offset} onChange={setOffset} noun="events" />
            </>
          )}
        </Async>
      </Card>
    </div>
  );
}
