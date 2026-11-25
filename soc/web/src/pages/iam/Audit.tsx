import { useState } from "react";
import { iam, PAGE_SIZE } from "../../api/iam";
import { Card, PageHead } from "../../components/common";
import { FilterBar, Guard, useFilters } from "../../components/iam/shared";
import { TimeRangeFields, rangeError, rangeParams } from "../../components/iam/TimeFilters";
import { Pager, QueryState, usePaged } from "../../components/iam/ui";
import { dateTime, label } from "../../format";

export const IAM_ACTIONS = [
  "iam_user_create", "iam_user_update", "iam_user_deactivate", "iam_user_activate", "iam_user_delete",
  "iam_role_create", "iam_role_update", "iam_role_delete",
  "iam_group_create", "iam_group_update", "iam_group_delete", "iam_group_members", "iam_group_roles",
  "iam_policy_create", "iam_policy_update", "iam_policy_delete", "iam_policy_attach",
];

export default function Audit() {
  return (
    <Guard permission="iam.audit.view" what="the audit log">
      <AuditPage />
    </Guard>
  );
}

function AuditPage() {
  const f = useFilters({ actor: "", action: "", target: "", since: "", until: "" });
  const [rangeErr, setRangeErr] = useState<string | null>(null);
  const a = f.applied;
  const key = JSON.stringify(a);
  const list = usePaged((cursor) => iam.audit({
    actor: a.actor, action: a.action, target: a.target, ...rangeParams(a.since, a.until), limit: PAGE_SIZE, cursor,
  }), key);

  function apply() {
    const err = rangeError(f.draft.since, f.draft.until);
    setRangeErr(err);
    if (!err) f.apply();
  }

  return (
    <div className="stack">
      <PageHead title="Audit log" />
      <Card title="Changes and events">
        <FilterBar label="Filter the audit log" onApply={apply} onReset={() => { setRangeErr(null); f.reset(); }} error={rangeErr}>
          <label className="field">Actor (exact)
            <input value={f.draft.actor} maxLength={64} onChange={(e) => f.set("actor", e.target.value)} />
          </label>
          <label className="field">Action (exact)
            <input list="iam-actions" value={f.draft.action} maxLength={64} onChange={(e) => f.set("action", e.target.value)} />
            <datalist id="iam-actions">{IAM_ACTIONS.map((x) => <option key={x} value={x} />)}</datalist>
          </label>
          <label className="field">Target (exact, e.g. user:bob)
            <input value={f.draft.target} maxLength={128} onChange={(e) => f.set("target", e.target.value)} />
          </label>
          <TimeRangeFields since={f.draft.since} until={f.draft.until} onChange={f.set} />
        </FilterBar>
        <QueryState q={list.q} what="the audit log">
          {(d) => d.items.length === 0 ? <p className="muted">No audit entries match.</p> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
                <tbody>
                  {d.items.map((e) => (
                    <tr key={e.id}>
                      <td>{dateTime(e.at)}</td>
                      <td className="wrap-anywhere">{e.actor_name} <span className="muted small-text">({e.actor_type})</span></td>
                      <td>{label(e.action)}</td>
                      <td className="wrap-anywhere mono">{e.target}</td>
                      <td>
                        {Object.keys(e.details).length === 0 ? <span className="muted">—</span> : (
                          <details className="iam-details">
                            <summary>Show details<span className="sr-only"> of entry {e.id}</span></summary>
                            <pre>{JSON.stringify(e.details, null, 2)}</pre>
                          </details>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryState>
        <Pager page={list.page} hasPrev={list.hasPrev} hasNext={list.hasNext} onPrev={list.prev} onNext={list.next} busy={list.q.loading} />
      </Card>
    </div>
  );
}
