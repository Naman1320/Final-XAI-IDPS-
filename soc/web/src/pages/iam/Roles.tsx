import { useState, type FormEvent } from "react";
import { iam, PAGE_SIZE } from "../../api/iam";
import type { IamRole } from "../../api/iamTypes";
import { Card, PageHead, Pill } from "../../components/common";
import { FilterBar, Guard, useFilters } from "../../components/iam/shared";
import {
  ConfirmDialog, Field, Modal, ModalFooter, Pager, PermissionChecklist, QueryState, useCan, usePaged,
  useQuery, useToast, errorText, validateDescription, validateName,
} from "../../components/iam/ui";

function RoleModal({ role, onClose, onSaved }: { role: IamRole | null; onClose: () => void; onSaved: (name: string) => void }) {
  const can = useCan();
  const catalog = useQuery(() => iam.catalog(), []);
  const readOnly = (role?.system ?? false) || (role !== null && !can("iam.roles.write"));
  const [name, setName] = useState(role?.name ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [perms, setPerms] = useState(new Set(role?.permissions ?? []));
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nameErr = validateName(name);
  const descErr = validateDescription(description);

  const body = role
    ? {
      ...(name !== role.name ? { name } : {}),
      ...(description !== role.description ? { description } : {}),
      ...(perms.size !== role.permissions.length || role.permissions.some((p) => !perms.has(p)) ? { permissions: [...perms].sort() } : {}),
    }
    : { name, description, permissions: [...perms].sort() };
  const changed = Object.keys(body).length > 0;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (readOnly || nameErr || descErr || !changed) return;
    setBusy(true);
    setError(null);
    try {
      const saved = role ? await iam.updateRole(role.id, body) : await iam.createRole(body as { name: string; description: string; permissions: string[] });
      onSaved(saved.name);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <Modal title={role ? (readOnly ? `Role ${role.name}` : `Edit role ${role.name}`) : "Create role"} onClose={onClose} busy={busy} wide>
      <form className="iam-form" onSubmit={submit} noValidate>
        {readOnly && <p className="hint">{role?.system ? "System roles are locked: they cannot be edited or deleted." : "You can view this role but not change it."}</p>}
        <Field label="Name" error={submitted ? nameErr : null}>
          {(a) => <input {...a} value={name} onChange={(e) => setName(e.target.value)} maxLength={48} readOnly={readOnly} required />}
        </Field>
        <Field label="Description" error={submitted ? descErr : null}>
          {(a) => <textarea {...a} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={255} readOnly={readOnly} />}
        </Field>
        <QueryState q={catalog} what="the permission catalog" lines={4}>
          {(c) => <PermissionChecklist groups={c.groups} value={perms} onChange={setPerms} readOnly={readOnly} canGrant={can} />}
        </QueryState>
        {error && <div className="error" role="alert">{error}</div>}
        {readOnly
          ? <div className="iam-modal-foot"><button type="button" onClick={onClose}>Close</button></div>
          : <ModalFooter busy={busy} onCancel={onClose} submitLabel={role ? "Save changes" : "Create role"} disabled={!changed} />}
      </form>
    </Modal>
  );
}

export default function Roles() {
  return (
    <Guard permission="iam.roles.view" what="roles">
      <RolesList />
    </Guard>
  );
}

function RolesList() {
  const can = useCan();
  const toast = useToast();
  const f = useFilters({ q: "", system: "" });
  const key = JSON.stringify(f.applied);
  const list = usePaged((cursor) => iam.roles({ ...f.applied, limit: PAGE_SIZE, cursor }), key);
  const [editing, setEditing] = useState<IamRole | "new" | null>(null);
  const [deleting, setDeleting] = useState<IamRole | null>(null);
  const canWrite = can("iam.roles.write");

  return (
    <div className="stack">
      <PageHead title="Roles">
        {canWrite && <button className="primary" onClick={() => setEditing("new")}>Create role</button>}
      </PageHead>
      <Card title="All roles">
        <FilterBar label="Filter roles" onApply={f.apply} onReset={f.reset}>
          <label className="field">Search name
            <input value={f.draft.q} maxLength={48} onChange={(e) => f.set("q", e.target.value)} />
          </label>
          <label className="field">Type
            <select value={f.draft.system} onChange={(e) => f.set("system", e.target.value)}>
              <option value="">All</option><option value="true">System</option><option value="false">Custom</option>
            </select>
          </label>
        </FilterBar>
        <QueryState q={list.q} what="roles">
          {(d) => d.items.length === 0 ? <p className="muted">No roles match.</p> : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Role</th><th>Permissions</th><th>Users</th><th>Groups</th><th><span className="sr-only">Actions</span></th></tr>
                </thead>
                <tbody>
                  {d.items.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <b className="wrap-anywhere">{r.name}</b>{" "}
                        {r.system && <Pill tone="neutral">Locked: system role</Pill>}
                        {r.description && <div className="muted small-text wrap-anywhere">{r.description}</div>}
                      </td>
                      <td>{r.permissions.length}</td>
                      <td>{r.user_count}</td>
                      <td>{r.group_count}</td>
                      <td>
                        <div className="row-actions" style={{ justifyContent: "flex-end" }}>
                          {r.system || !canWrite
                            ? <button className="small" onClick={() => setEditing(r)} aria-label={`View ${r.name}`}>View</button>
                            : <>
                              <button className="small" onClick={() => setEditing(r)} aria-label={`Edit ${r.name}`}>Edit</button>
                              <button className="small danger-soft" onClick={() => setDeleting(r)} aria-label={`Delete ${r.name}`}>Delete</button>
                            </>}
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
      {editing && (
        <RoleModal role={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={(name) => {
          toast(editing === "new" ? `Created role ${name}.` : `Saved role ${name}.`);
          setEditing(null);
          void list.q.reload();
        }} />
      )}
      {deleting && (
        <ConfirmDialog title={`Delete role ${deleting.name}?`} confirmLabel="Delete role" onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await iam.deleteRole(deleting.id);
            toast(`Deleted role ${deleting.name}.`);
            setDeleting(null);
            await list.q.reload();
          }}>
          <p>It is removed from {deleting.user_count} user(s) and {deleting.group_count} group(s), and their sessions end.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
