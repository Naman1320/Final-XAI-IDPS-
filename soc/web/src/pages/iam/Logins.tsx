import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { iam, PAGE_SIZE } from "../../api/iam";
import { Card, PageHead } from "../../components/common";
import { FilterBar, Guard, LoginTable, useFilters } from "../../components/iam/shared";
import { TimeRangeFields, rangeError, rangeParams } from "../../components/iam/TimeFilters";
import { Pager, QueryState, usePaged } from "../../components/iam/ui";

const REASONS = ["ok", "bad_password", "unknown_user", "disabled", "locked", "mfa_failed", "sso_failed", "sso_refused"];

export default function Logins() {
  return (
    <Guard permission="iam.logins.view" what="the login history">
      <LoginsPage />
    </Guard>
  );
}

function LoginsPage() {
  const [params] = useSearchParams();
  const f = useFilters({ username: params.get("username") ?? "", success: "", reason: "", since: "", until: "" });
  const [rangeErr, setRangeErr] = useState<string | null>(null);
  const a = f.applied;
  const key = JSON.stringify(a);
  const list = usePaged((cursor) => iam.logins({
    username: a.username, success: a.success, reason: a.reason, ...rangeParams(a.since, a.until), limit: PAGE_SIZE, cursor,
  }), key);

  function apply() {
    const err = rangeError(f.draft.since, f.draft.until);
    setRangeErr(err);
    if (!err) f.apply();
  }

  return (
    <div className="stack">
      <PageHead title="Login history" />
      <Card title="Sign-in attempts">
        <FilterBar label="Filter sign-ins" onApply={apply} onReset={() => { setRangeErr(null); f.reset(); }} error={rangeErr}>
          <label className="field">Username (exact)
            <input value={f.draft.username} maxLength={64} onChange={(e) => f.set("username", e.target.value)} />
          </label>
          <label className="field">Result
            <select value={f.draft.success} onChange={(e) => f.set("success", e.target.value)}>
              <option value="">Any</option><option value="true">Success</option><option value="false">Failure</option>
            </select>
          </label>
          <label className="field">Reason
            <select value={f.draft.reason} onChange={(e) => f.set("reason", e.target.value)}>
              <option value="">Any</option>
              {REASONS.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
            </select>
          </label>
          <TimeRangeFields since={f.draft.since} until={f.draft.until} onChange={f.set} />
        </FilterBar>
        <QueryState q={list.q} what="the login history">{(d) => <LoginTable rows={d.items} />}</QueryState>
        <Pager page={list.page} hasPrev={list.hasPrev} hasNext={list.hasNext} onPrev={list.prev} onNext={list.next} busy={list.q.loading} />
      </Card>
    </div>
  );
}
