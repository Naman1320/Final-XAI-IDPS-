// Pieces shared by several IAM pages: filter bars, option loading, login table, guards.
import { useState, type FormEvent, type ReactNode } from "react";
import { useLocation, useParams } from "react-router-dom";
import { fetchAll } from "../../api/iam";
import type { IamGroup, IamRole, IamUser, LoginRecord } from "../../api/iamTypes";
import { Pill } from "../common";
import { dateTime, label } from "../../format";
import { Forbidden, Skeleton, useCan, useQuery } from "./ui";

/** Draft values being edited, and the applied ones that drive the query (set on Apply). */
export function useFilters<T extends Record<string, string>>(initial: T) {
  const [draft, setDraft] = useState<T>(initial);
  const [applied, setApplied] = useState<T>(initial);
  return {
    draft, applied,
    set: (key: keyof T, value: string) => setDraft((d) => ({ ...d, [key]: value })),
    apply: () => setApplied(draft),
    reset: () => { setDraft(initial); setApplied(initial); },
    dirty: JSON.stringify(draft) !== JSON.stringify(applied),
  };
}

export function FilterBar({ label: aria, onApply, onReset, error, children }: {
  label: string; onApply: () => void; onReset: () => void; error?: string | null; children: ReactNode;
}) {
  function submit(e: FormEvent) {
    e.preventDefault();
    onApply();
  }
  return (
    <form className="iam-filters" role="search" aria-label={aria} onSubmit={submit}>
      {children}
      <div className="row-actions">
        <button type="submit" className="primary">Apply</button>
        <button type="button" onClick={onReset}>Reset</button>
      </div>
      {error && <div className="error" role="alert" style={{ flexBasis: "100%", margin: 0 }}>{error}</div>}
    </form>
  );
}

/** Renders the children only for a user who may view the section (else the 403 state, with no API call). */
export function Guard({ permission, what, children }: { permission: string; what: string; children: ReactNode }) {
  const can = useCan();
  return can(permission) ? <>{children}</> : <Forbidden what={what} detail={`Needs ${permission}.`} />;
}

export function useRoleOptions(enabled = true) {
  return useQuery(() => fetchAll<IamRole>("/iam/roles"), [], enabled);
}
export function useGroupOptions(enabled = true) {
  return useQuery(() => fetchAll<IamGroup>("/iam/groups"), [], enabled);
}
export function useUserOptions(enabled = true) {
  return useQuery(() => fetchAll<IamUser>("/iam/users"), [], enabled);
}

export function StatusPill({ disabled }: { disabled: boolean }) {
  return disabled ? <Pill tone="danger">✕ Deactivated</Pill> : <Pill tone="ok">✓ Active</Pill>;
}

export function MfaPill({ enabled }: { enabled: boolean }) {
  return enabled ? <Pill tone="ok">MFA on</Pill> : <Pill tone="neutral">MFA off</Pill>;
}

export function Names({ items, empty = "none" }: { items: { id: number; name: string }[]; empty?: string }) {
  if (!items.length) return <span className="muted">{empty}</span>;
  return (
    <ul className="iam-chips">
      {items.map((i) => <li key={i.id}><Pill tone="accent">{i.name}</Pill></li>)}
    </ul>
  );
}

export function LoginTable({ rows, showUser = true }: { rows: LoginRecord[]; showUser?: boolean }) {
  if (!rows.length) return <p className="muted">No sign-in attempts match.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>{showUser && <th>User</th>}<th>Result</th><th>MFA</th><th>Address</th><th>Browser</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{dateTime(r.at)}</td>
              {showUser && <td className="wrap-anywhere">{r.username}</td>}
              <td>
                {r.success ? <Pill tone="ok">✓ Success</Pill> : <Pill tone="danger">✕ Failed</Pill>}
                {!r.success && <div className="muted small-text">{label(r.reason)}</div>}
              </td>
              <td>{r.mfa_used ? "yes" : "no"}</td>
              <td className="mono">{r.ip}</td>
              <td className="iam-ua">{r.user_agent || <span className="muted">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TableSkeleton() {
  return <Skeleton lines={5} label="Loading list" />;
}

/** The URL the IAM module is mounted at (e.g. "/iam"), whatever the app mounts it under. */
export function useBase(): string {
  const { pathname } = useLocation();
  const splat = useParams()["*"] ?? "";
  const base = splat ? pathname.slice(0, Math.max(0, pathname.lastIndexOf(splat))) : pathname;
  return base.replace(/\/+$/, "");
}
