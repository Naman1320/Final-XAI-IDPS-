import { useState, type FormEvent } from "react";
import { iam, PAGE_SIZE } from "../../api/iam";
import type { IamGroup, IamGroupDetail } from "../../api/iamTypes";
import { Card, PageHead } from "../../components/common";
import { FilterBar, Guard, Names, useFilters, useRoleOptions, useUserOptions } from "../../components/iam/shared";
import {
  Checklist, ConfirmDialog, Field, Modal, ModalFooter, Pager, QueryState, errorText, useCan, usePaged, useQuery,
  useToast, validateDescription, validateName,
} from "../../components/iam/ui";

function GroupModal({ group, onClose, onSaved }: { group: IamGroup | null; onClose: () => void; onSaved: (name: string) => void }) {
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nameErr = validateName(name);
  const descErr = validateDescription(description);
  const body = group
    ? { ...(name !== group.name ? { name } : {}), ...(description !== group.description ? { description } : {}) }
    : { name, description };
  const changed = Object.keys(body).length > 0;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (nameErr || descErr || !changed) return;
    setBusy(true);
    setError(null);
    try {
      const saved = group ? await iam.updateGroup(group.id, body) : await iam.createGroup({ name, description });
      onSaved(saved.name);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <Modal title={group ? `Edit group ${group.name}` : "Create group"} onClose={onClose} busy={busy}>
      <form className="iam-form" onSubmit={submit} noValidate>
        <Field label="Name" error={submitted ? nameErr : null}>
          {(a) => <input {...a} value={name} onChange={(e) => setName(e.target.value)} maxLength={48} required />}
        </Field>
        <Field label="Description" error={submitted ? descErr : null}>
          {(a) => <textarea {...a} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={255} />}
        </Field>
        {error && <div className="error" role="alert">{error}</div>}
        <ModalFooter busy={busy} onCancel={onClose} submitLabel={group ? "Save changes" : "Create group"} disabled={!changed} />
      </form>
    </Modal>
  );
}

function ManageBody({ detail, onClose, onSaved }: { detail: IamGroupDetail; onClose: () => void; onSaved: () => void }) {
  const can = useCan();
  const users = useUserOptions(can("iam.users.view"));
  const roles = useRoleOptions(can("iam.roles.view"));
  const [members, setMembers] = useState(new Set(detail.members.map((m) => m.id)));
  const [roleIds, setRoleIds] = useState(new Set(detail.roles.map((r) => r.id)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const same = (a: Set<number>, list: { id: number }[]) => a.size === list.length && list.every((i) => a.has(i.id));
  const membersChanged = can("iam.users.view") && !same(members, detail.members);
  const rolesChanged = can("iam.roles.view") && !same(roleIds, detail.roles);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (membersChanged) await iam.setMembers(detail.id, [...members]);
      if (rolesChanged) await iam.setGroupRoles(detail.id, [...roleIds]);
      onSaved();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <form className="iam-form" onSubmit={submit}>
      {can("iam.users.view") ? (
        <QueryState q={users} what="users" lines={3}>
          {(d) => <Checklist legend="Members" items={d.items.map((u) => ({ id: u.id, label: u.username, hint: u.disabled ? "(deactivated)" : undefined }))}
            selected={members} onChange={setMembers} empty="No users." />}
        </QueryState>
      ) : <div><h3>Members</h3><Names items={detail.members} /><p className="muted small-text">You cannot view users, so members cannot be changed here.</p></div>}
      {can("iam.roles.view") ? (
        <QueryState q={roles} what="roles" lines={3}>
          {(d) => <Checklist legend="Roles of this group" items={d.items.map((r) => ({ id: r.id, label: r.name, hint: r.system ? "(system)" : undefined }))}
            selected={roleIds} onChange={setRoleIds} empty="No roles." />}
        </QueryState>
      ) : <div><h3>Roles</h3><Names items={detail.roles} /><p className="muted small-text">You cannot view roles, so they cannot be changed here.</p></div>}
      <p className="iam-hint">Saving ends the sessions of the members affected.</p>
      {error && <div className="error" role="alert">{error}</div>}
      <ModalFooter busy={busy} onCancel={onClose} submitLabel="Save" disabled={!membersChanged && !rolesChanged} />
    </form>
  );
}

function ManageModal({ group, onClose, onSaved }: { group: IamGroup; onClose: () => void; onSaved: () => void }) {
  const detail = useQuery(() => iam.group(group.id), [group.id]);
  return (
    <Modal title={`Members and roles of ${group.name}`} onClose={onClose} wide>
      <QueryState q={detail} what="this group">
        {(d) => <ManageBody detail={d} onClose={onClose} onSaved={onSaved} />}
      </QueryState>
    </Modal>
  );
}

export default function Groups() {
  return (
    <Guard permission="iam.groups.view" what="groups">
      <GroupsList />
    </Guard>
  );
}

function GroupsList() {
  const can = useCan();
  const toast = useToast();
  const f = useFilters({ q: "" });
  const key = JSON.stringify(f.applied);
  const list = usePaged((cursor) => iam.groups({ ...f.applied, limit: PAGE_SIZE, cursor }), key);
  const [editing, setEditing] = useState<IamGroup | "new" | null>(null);
  const [managing, setManaging] = useState<IamGroup | null>(null);
  const [deleting, setDeleting] = useState<IamGroup | null>(null);
  const canWrite = can("iam.groups.write");

  return (
    <div className="stack">
      <PageHead title="Groups">
        {canWrite && <button className="primary" onClick={() => setEditing("new")}>Create group</button>}
      </PageHead>
      <Card title="All groups">
        <FilterBar label="Filter groups" onApply={f.apply} onReset={f.reset}>
          <label className="field">Search name
            <input value={f.draft.q} maxLength={48} onChange={(e) => f.set("q", e.target.value)} />
          </label>
        </FilterBar>
        <QueryState q={list.q} what="groups">
          {(d) => d.items.length === 0 ? <p className="muted">No groups match.</p> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Group</th><th>Members</th><th>Roles</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {d.items.map((g) => (
                    <tr key={g.id}>
                      <td>
                        <b className="wrap-anywhere">{g.name}</b>
                        {g.description && <div className="muted small-text wrap-anywhere">{g.description}</div>}
                      </td>
                      <td>{g.member_count}</td>
                      <td>{g.role_count}</td>
                      <td>
                        <div className="row-actions" style={{ justifyContent: "flex-end" }}>
                          <button className="small" onClick={() => setManaging(g)} aria-label={`${canWrite ? "Manage" : "View"} members and roles of ${g.name}`}>
                            {canWrite ? "Members and roles" : "View members"}
                          </button>
                          {canWrite && <button className="small" onClick={() => setEditing(g)} aria-label={`Edit ${g.name}`}>Edit</button>}
                          {canWrite && <button className="small danger-soft" onClick={() => setDeleting(g)} aria-label={`Delete ${g.name}`}>Delete</button>}
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
        <GroupModal group={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={(name) => {
          toast(editing === "new" ? `Created group ${name}.` : `Saved group ${name}.`);
          setEditing(null);
          void list.q.reload();
        }} />
      )}
      {managing && (canWrite
        ? <ManageModal group={managing} onClose={() => setManaging(null)} onSaved={() => {
          toast(`Updated ${managing.name}.`);
          setManaging(null);
          void list.q.reload();
        }} />
        : <ReadOnlyMembers group={managing} onClose={() => setManaging(null)} />)}
      {deleting && (
        <ConfirmDialog title={`Delete group ${deleting.name}?`} confirmLabel="Delete group" onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await iam.deleteGroup(deleting.id);
            toast(`Deleted group ${deleting.name}.`);
            setDeleting(null);
            await list.q.reload();
          }}>
          <p>Its {deleting.member_count} member(s) lose the group's roles and policies and are signed out.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function ReadOnlyMembers({ group, onClose }: { group: IamGroup; onClose: () => void }) {
  const detail = useQuery(() => iam.group(group.id), [group.id]);
  return (
    <Modal title={`Members and roles of ${group.name}`} onClose={onClose}>
      <QueryState q={detail} what="this group">
        {(d) => (
          <div className="iam-form">
            <div><h3>Members</h3><Names items={d.members} /></div>
            <div><h3>Roles</h3><Names items={d.roles} /></div>
            <div className="iam-modal-foot"><button onClick={onClose}>Close</button></div>
          </div>
        )}
      </QueryState>
    </Modal>
  );
}
