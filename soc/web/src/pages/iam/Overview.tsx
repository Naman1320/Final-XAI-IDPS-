import { Link } from "react-router-dom";
import { fetchAll, iam } from "../../api/iam";
import type { IamGroup, IamPolicy, IamRole, IamUser } from "../../api/iamTypes";
import { Card, PageHead, Pill } from "../../components/common";
import { LoginTable, useBase } from "../../components/iam/shared";
import { QueryState, Skeleton, errorText, isForbidden, useCan, useQuery, type Query } from "../../components/iam/ui";
import { percent } from "../../format";

export const SECTIONS = [
  { path: "users", title: "Users", perm: "iam.users.view" },
  { path: "roles", title: "Roles", perm: "iam.roles.view" },
  { path: "groups", title: "Groups", perm: "iam.groups.view" },
  { path: "policies", title: "Policies", perm: "iam.policies.view" },
  { path: "logins", title: "Login history", perm: "iam.logins.view" },
  { path: "audit", title: "Audit log", perm: "iam.audit.view" },
] as const;

type All<T> = { items: T[]; more: boolean };

function count(q: Query<All<unknown>>): string {
  if (q.data) return `${q.data.items.length}${q.data.more ? "+" : ""}`;
  if (q.error) return "n/a";
  return "…";
}

function Stat({ label, value, note, error }: { label: string; value: string; note?: string; error?: unknown }) {
  return (
    <div className="iam-stat">
      <span className="value">{value}</span>
      <span className="label">{label}</span>
      {note && <span className="label">{note}</span>}
      {error != null && <span className="label danger-text">{isForbidden(error) ? "No permission" : errorText(error)}</span>}
    </div>
  );
}

export default function Overview() {
  const can = useCan();
  const base = useBase();
  const users = useQuery(() => fetchAll<IamUser>("/iam/users"), [], can("iam.users.view"));
  const roles = useQuery(() => fetchAll<IamRole>("/iam/roles"), [], can("iam.roles.view"));
  const groups = useQuery(() => fetchAll<IamGroup>("/iam/groups"), [], can("iam.groups.view"));
  const policies = useQuery(() => fetchAll<IamPolicy>("/iam/policies"), [], can("iam.policies.view"));
  const logins = useQuery(() => iam.logins({ limit: 8 }), [], can("iam.logins.view"));
  const visible = SECTIONS.filter((s) => can(s.perm));

  const u = users.data?.items ?? [];
  const active = u.filter((x) => !x.disabled);
  const withMfa = active.filter((x) => x.mfa_enabled).length;
  const adminsNoMfa = active.filter((x) => x.role === "admin" && !x.mfa_enabled).length;

  return (
    <div className="stack">
      <PageHead title="Identity and access" />
      {visible.length === 0 && <p className="hint">Your account holds no IAM permissions, so there is nothing to show here.</p>}
      <Card title="At a glance">
        <div className="iam-stats">
          {can("iam.users.view") && <Stat label="Users" value={count(users)} error={users.error}
            note={users.data ? `${active.length} active, ${u.length - active.length} deactivated` : undefined} />}
          {can("iam.users.view") && (
            <Stat label="Active users with MFA" value={users.data ? (active.length ? percent(withMfa / active.length) : "—") : "…"}
              note={users.data ? `${withMfa} of ${active.length}` : undefined} />
          )}
          {can("iam.roles.view") && <Stat label="Roles" value={count(roles)} error={roles.error} />}
          {can("iam.groups.view") && <Stat label="Groups" value={count(groups)} error={groups.error} />}
          {can("iam.policies.view") && <Stat label="Policies" value={count(policies)} error={policies.error} />}
        </div>
        {adminsNoMfa > 0 && (
          <p style={{ marginTop: 12 }}><Pill tone="warn">Attention</Pill> {adminsNoMfa} active admin account(s) have no two-factor sign-in.</p>
        )}
      </Card>
      {can("iam.logins.view") && (
        <Card title="Recent sign-ins" actions={<Link to={`${base}/logins`}>All sign-ins</Link>}>
          <QueryState q={logins} what="the login history">{(d) => <LoginTable rows={d.items} />}</QueryState>
        </Card>
      )}
      {visible.length > 0 && (
        <Card title="Shortcuts">
          <div className="iam-shortcuts">
            {can("iam.users.write") && <Link className="button-link" to={`${base}/users`}>Manage users</Link>}
            {visible.map((s) => <Link key={s.path} className="button-link" to={`${base}/${s.path}`}>{s.title}</Link>)}
          </div>
        </Card>
      )}
      {users.loading && users.data === null && can("iam.users.view") && <Skeleton lines={1} label="Loading counts" />}
    </div>
  );
}
