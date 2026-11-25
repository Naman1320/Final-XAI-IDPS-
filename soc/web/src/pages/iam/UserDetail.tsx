import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { iam } from "../../api/iam";
import type { EffectivePermissions, IamUserDetail, LegacyRole, PermissionGroup } from "../../api/iamTypes";
import { useAuth } from "../../auth";
import { Card, PageHead, Pill } from "../../components/common";
import {
  Guard, LoginTable, MfaPill, Names, StatusPill, useBase, useGroupOptions, useRoleOptions,
} from "../../components/iam/shared";
import {
  Checklist, ConfirmDialog, Field, Modal, ModalFooter, QueryState, errorText, useCan, useQuery, useToast,
} from "../../components/iam/ui";
import { dateTime } from "../../format";

function EditAccessModal({ user, onClose, onSaved }: { user: IamUserDetail; onClose: () => void; onSaved: () => void }) {
  const can = useCan();
  const roles = useRoleOptions(can("iam.roles.view"));
  const groups = useGroupOptions(can("iam.groups.view"));
  const [role, setRole] = useState<LegacyRole>(user.role);
  const [roleIds, setRoleIds] = useState(new Set(user.roles.map((r) => r.id)));
  const [groupIds, setGroupIds] = useState(new Set(user.groups.map((g) => g.id)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sameSet = (a: Set<number>, ids: number[]) => a.size === ids.length && ids.every((i) => a.has(i));
  // Send only what changed, and only lists we were allowed to load (else we would wipe what we could not see).
  const body = {
    ...(role !== user.role ? { role } : {}),
    ...(can("iam.roles.view") && !sameSet(roleIds, user.roles.map((r) => r.id)) ? { role_ids: [...roleIds] } : {}),
    ...(can("iam.groups.view") && !sameSet(groupIds, user.groups.map((g) => g.id)) ? { group_ids: [...groupIds] } : {}),
  };
  const changed = Object.keys(body).length > 0;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!changed) return;
    setBusy(true);
    setError(null);
    try {
      await iam.updateUser(user.id, body);
      onSaved();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <Modal title={`Edit access of ${user.username}`} onClose={onClose} busy={busy} wide>
      <form className="iam-form" onSubmit={submit}>
        <Field label="Legacy role" hint="Saving signs this user out everywhere, so their new access applies at once.">
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
        ) : <p className="muted small-text">You cannot view roles, so they are left unchanged.</p>}
        {can("iam.groups.view") ? (
          <QueryState q={groups} what="groups" lines={2}>
            {(d) => <Checklist legend="Groups" items={d.items.map((g) => ({ id: g.id, label: g.name }))}
              selected={groupIds} onChange={setGroupIds} empty="No groups yet." />}
          </QueryState>
        ) : <p className="muted small-text">You cannot view groups, so they are left unchanged.</p>}
        {error && <div className="error" role="alert">{error}</div>}
        <ModalFooter busy={busy} onCancel={onClose} submitLabel="Save changes" disabled={!changed} />
      </form>
    </Modal>
  );
}

function EffectiveView({ eff, catalog }: { eff: EffectivePermissions; catalog: PermissionGroup[] | null }) {
  const held = new Set(eff.permissions);
  const groups: { title: string; names: string[] }[] = catalog
    ? catalog.map((g) => ({ title: g.title, names: g.permissions.map((p) => p.name).filter((n) => held.has(n)) })).filter((g) => g.names.length)
    : [{ title: "Permissions", names: eff.permissions }];
  return (
    <div className="stack">
      {eff.all_access && <p><Pill tone="warn">All access</Pill> <span className="muted">A legacy admin holds every permission and no policy can remove one.</span></p>}
      {groups.length === 0 && <p className="muted">This user holds no permissions.</p>}
      {groups.map((g) => (
        <div key={g.title}>
          <h3>{g.title}</h3>
          <ul className="iam-chips">{g.names.map((n) => <li key={n}><code>{n}</code></li>)}</ul>
        </div>
      ))}
      {eff.denied.length > 0 && (
        <div>
          <h3>Removed by a deny policy</h3>
          <ul className="iam-chips">{eff.denied.map((n) => <li key={n}><code className="denied">{n}</code></li>)}</ul>
        </div>
      )}
      <dl className="kv">
        <dt>Applying roles</dt><dd><Names items={eff.roles} /></dd>
        <dt>Applying groups</dt><dd><Names items={eff.groups} /></dd>
        <dt>Applying policies</dt>
        <dd>
          {eff.policies.length === 0 ? <span className="muted">none</span> : (
            <ul className="iam-chips">
              {eff.policies.map((p) => <li key={p.id}><Pill tone={p.effect === "deny" ? "danger" : "ok"}>{p.effect === "deny" ? "Deny" : "Allow"}: {p.name}</Pill></li>)}
            </ul>
          )}
        </dd>
      </dl>
      <p className="muted small-text">The API lists which roles, groups and policies apply, not which one grants each permission.</p>
    </div>
  );
}

export default function UserDetail() {
  return (
    <Guard permission="iam.users.view" what="users">
      <Detail />
    </Guard>
  );
}

function Detail() {
  const { id: idText } = useParams();
  const id = Number(idText);
  const { me } = useAuth();
  const can = useCan();
  const base = useBase();
  const navigate = useNavigate();
  const toast = useToast();
  const valid = Number.isInteger(id) && id > 0;
  const user = useQuery(() => iam.user(id), [id], valid);
  const eff = useQuery(() => iam.effective(id), [id], valid);
  const catalog = useQuery(() => iam.catalog(), [], can("iam.roles.view"));
  const logins = useQuery(() => iam.logins({ user_id: id, limit: 10 }), [id], valid && can("iam.logins.view"));
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deactivating, setDeactivating] = useState(false);
  const [busy, setBusy] = useState(false);
  const self = me?.id === id;

  if (!valid) return <div className="error" role="alert">That is not a valid user id.</div>;

  async function reloadAll() {
    await Promise.all([user.reload(), eff.reload()]);
  }

  async function activate() {
    setBusy(true);
    try {
      await iam.setActive(id, true);
      toast("User activated.");
      await reloadAll();
    } catch (err) {
      toast(errorText(err), "danger");
    } finally {
      setBusy(false);
    }
  }

  const canWrite = can("iam.users.write");
  const canDelete = can("iam.users.delete");

  return (
    <div className="stack">
      <p><Link to={`${base}/users`}>← All users</Link></p>
      <QueryState q={user} what="this user">
        {(u) => (
          <>
            <PageHead title={<span className="wrap-anywhere">{u.username}</span>}>
              <StatusPill disabled={u.disabled} />
              {canWrite && (
                <button onClick={() => setEditing(true)} disabled={self}
                  title={self ? "You cannot change your own roles, groups or state" : undefined}>Edit roles and groups</button>
              )}
              {canWrite && (u.disabled
                ? <button disabled={busy || self} onClick={() => void activate()}>Activate</button>
                : <button className="danger-soft" disabled={self} onClick={() => setDeactivating(true)}>Deactivate</button>)}
              {canDelete && <button className="danger" disabled={self} onClick={() => setDeleting(true)}>Delete user</button>}
            </PageHead>
            {self && <p className="hint">This is you. The backend does not let you change your own access, state, or delete yourself.</p>}
            <div className="grid cols-2">
              <Card title="Profile">
                <dl className="kv">
                  <dt>Username</dt><dd>{u.username}</dd>
                  <dt>Legacy role</dt><dd><Pill tone={u.role === "admin" ? "warn" : "neutral"}>{u.role}</Pill></dd>
                  <dt>Status</dt><dd><StatusPill disabled={u.disabled} /></dd>
                  <dt>Two-factor</dt>
                  <dd><MfaPill enabled={u.mfa_enabled} /> {u.mfa_required && <span className="muted small-text">required for this account</span>}</dd>
                  <dt>Single sign-on</dt><dd>{u.sso_linked ? "linked" : "not linked"}</dd>
                  <dt>Created</dt><dd>{dateTime(u.created_at)}</dd>
                  <dt>Last login</dt><dd>{dateTime(u.last_login)}</dd>
                </dl>
              </Card>
              <Card title="Roles and groups">
                <dl className="kv">
                  <dt>Roles</dt><dd><Names items={u.roles} /></dd>
                  <dt>Groups</dt><dd><Names items={u.groups} /></dd>
                </dl>
              </Card>
            </div>
            <Card title="Effective permissions">
              <QueryState q={eff} what="effective permissions">
                {(e) => <EffectiveView eff={e} catalog={catalog.data?.groups ?? null} />}
              </QueryState>
            </Card>
            {can("iam.logins.view") && (
              <Card title="Recent sign-ins" actions={<Link to={`${base}/logins?username=${encodeURIComponent(u.username)}`}>Full history</Link>}>
                <QueryState q={logins} what="login history">{(l) => <LoginTable rows={l.items} showUser={false} />}</QueryState>
              </Card>
            )}
            {editing && (
              <EditAccessModal user={u} onClose={() => setEditing(false)} onSaved={() => {
                setEditing(false);
                toast(`Updated ${u.username}. Their sessions were ended.`);
                void reloadAll();
              }} />
            )}
            {deactivating && (
              <ConfirmDialog title={`Deactivate ${u.username}?`} confirmLabel="Deactivate" onClose={() => setDeactivating(false)}
                onConfirm={async () => {
                  await iam.setActive(id, false);
                  setDeactivating(false);
                  toast(`Deactivated ${u.username}.`);
                  await reloadAll();
                }}>
                <p>They are signed out at once and cannot sign in until you activate them again.</p>
              </ConfirmDialog>
            )}
            {deleting && (
              <ConfirmDialog title={`Delete ${u.username}?`} confirmLabel="Delete user" confirmText={u.username}
                onClose={() => setDeleting(false)}
                onConfirm={async () => {
                  await iam.deleteUser(id);
                  toast(`Deleted ${u.username}.`);
                  navigate(`${base}/users`);
                }}>
                <p>This cannot be undone. Their memberships, role assignments and assistant conversations are removed;
                  cases, notes, actions and the login history are kept without a link to them. Deactivating is the reversible alternative.</p>
              </ConfirmDialog>
            )}
          </>
        )}
      </QueryState>
    </div>
  );
}
