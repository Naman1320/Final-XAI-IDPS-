import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { iam, PAGE_SIZE } from "../../api/iam";
import type { LegacyRole } from "../../api/iamTypes";
import { Card, PageHead, Pill } from "../../components/common";
import {
  FilterBar, Guard, MfaPill, Names, StatusPill, useBase, useFilters, useGroupOptions, useRoleOptions,
} from "../../components/iam/shared";
import {
  Checklist, ConfirmDialog, Field, Modal, ModalFooter, Pager, QueryState, errorText, useCan, usePaged,
  useToast, validatePassword, validateUsername, MIN_PASSWORD,
} from "../../components/iam/ui";
import { dateTime } from "../../format";

export function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: (username: string, id: number) => void }) {
  const can = useCan();
  const roles = useRoleOptions(can("iam.roles.view"));
  const groups = useGroupOptions(can("iam.groups.view"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<LegacyRole>("analyst");
  const [roleIds, setRoleIds] = useState<Set<number>>(new Set());
  const [groupIds, setGroupIds] = useState<Set<number>>(new Set());
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const userErr = validateUsername(username);
  const passErr = validatePassword(password);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (userErr || passErr) return;
    setBusy(true);
    setError(null);
    try {
      const u = await iam.createUser({ username, password, role, role_ids: [...roleIds], group_ids: [...groupIds] });
      onCreated(u.username, u.id);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <Modal title="Create user" onClose={onClose} busy={busy} wide>
      <form className="iam-form" onSubmit={submit} noValidate>
        <Field label="Username" error={submitted ? userErr : null}>
          {(a) => <input {...a} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" maxLength={64} required />}
        </Field>
        <Field label="Password" error={submitted ? passErr : null}
          hint={`At least ${MIN_PASSWORD} characters. ${password.length >= MIN_PASSWORD ? "✓ Long enough." : `${password.length}/${MIN_PASSWORD} so far.`}`}>
          {(a) => <input {...a} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />}
        </Field>
        <Field label="Legacy role" hint={role === "admin" ? "An admin holds every permission, and can use the admin pages." : "An analyst holds the analyst system role (cloud.view) plus what is added below."}>
          {(a) => (
            <select {...a} value={role} onChange={(e) => setRole(e.target.value as LegacyRole)}>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
          )}
        </Field>
        {can("iam.roles.view") ? (
          <QueryState q={roles} what="roles" lines={2}>
            {(d) => <Checklist legend="Roles" items={d.items.map((r) => ({ id: r.id, label: r.name, hint: r.system ? "(system)" : undefined }))}
              selected={roleIds} onChange={setRoleIds} empty="No roles yet." />}
          </QueryState>
        ) : <p className="muted small-text">You cannot view roles, so none can be assigned here.</p>}
        {can("iam.groups.view") ? (
          <QueryState q={groups} what="groups" lines={2}>
            {(d) => <Checklist legend="Groups" items={d.items.map((g) => ({ id: g.id, label: g.name }))}
              selected={groupIds} onChange={setGroupIds} empty="No groups yet." />}
          </QueryState>
        ) : <p className="muted small-text">You cannot view groups, so none can be assigned here.</p>}
        {error && <div className="error" role="alert">{error}</div>}
        <ModalFooter busy={busy} onCancel={onClose} submitLabel="Create user" />
      </form>
    </Modal>
  );
}

export default function Users() {
  return (
    <Guard permission="iam.users.view" what="users">
      <UsersList />
    </Guard>
  );
}

function UsersList() {
  const can = useCan();
  const base = useBase();
  const navigate = useNavigate();
  const toast = useToast();
  const f = useFilters({ q: "", status: "", role: "", group_id: "", role_id: "" });
  const roles = useRoleOptions(can("iam.roles.view"));
  const groups = useGroupOptions(can("iam.groups.view"));
  const key = JSON.stringify(f.applied);
  const list = usePaged((cursor) => iam.users({ ...f.applied, limit: PAGE_SIZE, cursor }), key);
  const [creating, setCreating] = useState(false);
  const [deactivating, setDeactivating] = useState<{ id: number; username: string } | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const canWrite = can("iam.users.write");

  async function activate(id: number, username: string) {
    setBusyId(id);
    try {
      await iam.setActive(id, true);
      toast(`Activated ${username}.`);
      await list.q.reload();
    } catch (err) {
      toast(errorText(err), "danger");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="stack">
      <PageHead title="Users">
        {can("iam.users.write") && <button className="primary" onClick={() => setCreating(true)}>Create user</button>}
      </PageHead>
      <Card title="All users">
        <FilterBar label="Filter users" onApply={f.apply} onReset={f.reset}>
          <label className="field">Search username
            <input value={f.draft.q} maxLength={64} onChange={(e) => f.set("q", e.target.value)} />
          </label>
          <label className="field">Status
            <select value={f.draft.status} onChange={(e) => f.set("status", e.target.value)}>
              <option value="">Any</option><option value="active">Active</option><option value="disabled">Deactivated</option>
            </select>
          </label>
          <label className="field">Legacy role
            <select value={f.draft.role} onChange={(e) => f.set("role", e.target.value)}>
              <option value="">Any</option><option value="analyst">analyst</option><option value="admin">admin</option>
            </select>
          </label>
          {roles.data && (
            <label className="field">Role
              <select value={f.draft.role_id} onChange={(e) => f.set("role_id", e.target.value)}>
                <option value="">Any</option>
                {roles.data.items.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
          )}
          {groups.data && (
            <label className="field">Group
              <select value={f.draft.group_id} onChange={(e) => f.set("group_id", e.target.value)}>
                <option value="">Any</option>
                {groups.data.items.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select>
            </label>
          )}
        </FilterBar>
        <QueryState q={list.q} what="users">
          {(d) => d.items.length === 0 ? <p className="muted">No users match.</p> : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>User</th><th>Status</th><th>Legacy role</th><th>Roles</th><th>Groups</th><th>Last login</th><th><span className="sr-only">Actions</span></th></tr>
                </thead>
                <tbody>
                  {d.items.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <Link to={`${base}/users/${u.id}`} className="wrap-anywhere"><b>{u.username}</b></Link>
                        <div className="muted small-text">since {dateTime(u.created_at)}</div>
                      </td>
                      <td><div className="row-actions"><StatusPill disabled={u.disabled} /><MfaPill enabled={u.mfa_enabled} /></div></td>
                      <td><Pill tone={u.role === "admin" ? "warn" : "neutral"}>{u.role}</Pill></td>
                      <td><Names items={u.roles} /></td>
                      <td><Names items={u.groups} /></td>
                      <td>{dateTime(u.last_login)}</td>
                      <td>
                        <div className="row-actions" style={{ justifyContent: "flex-end" }}>
                          <button className="small" onClick={() => navigate(`${base}/users/${u.id}`)} aria-label={`View ${u.username}`}>View</button>
                          {canWrite && (u.disabled
                            ? <button className="small" disabled={busyId === u.id} onClick={() => void activate(u.id, u.username)} aria-label={`Activate ${u.username}`}>Activate</button>
                            : <button className="small danger-soft" onClick={() => setDeactivating(u)} aria-label={`Deactivate ${u.username}`}>Deactivate</button>)}
                        </div>
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
      {creating && (
        <CreateUserModal onClose={() => setCreating(false)} onCreated={(name, id) => {
          setCreating(false);
          toast(`Created ${name}.`);
          navigate(`${base}/users/${id}`);
        }} />
      )}
      {deactivating && (
        <ConfirmDialog title={`Deactivate ${deactivating.username}?`} confirmLabel="Deactivate"
          onClose={() => setDeactivating(null)}
          onConfirm={async () => {
            await iam.setActive(deactivating.id, false);
            toast(`Deactivated ${deactivating.username}.`);
            setDeactivating(null);
            await list.q.reload();
          }}>
          <p>They are signed out at once and cannot sign in until you activate them again.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
