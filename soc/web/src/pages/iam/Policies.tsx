import { useState, type FormEvent } from "react";
import { iam, PAGE_SIZE } from "../../api/iam";
import type { Catalog, Effect, IamPolicy, IamPolicyDetail, SubjectType } from "../../api/iamTypes";
import { Card, PageHead, Pill } from "../../components/common";
import { FilterBar, Guard, useFilters, useGroupOptions, useRoleOptions, useUserOptions } from "../../components/iam/shared";
import {
  Checklist, ConfirmDialog, Field, Modal, ModalFooter, Pager, QueryState, UNSAFE_RE, errorText, splitList, useCan,
  usePaged, useQuery, useToast, type Query, validateDescription, validateName,
} from "../../components/iam/ui";

/** Does the pattern ("cloud.*", "*.view") match at least one catalog permission? (The backend refuses typos.) */
export function matchesCatalog(pattern: string, catalog: Catalog): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
  return catalog.groups.some((g) => g.permissions.some((p) => re.test(p.name)));
}

export function validatePatterns(list: string[], catalog: Catalog | null): string | null {
  if (list.length === 0) return "Enter at least one permission or pattern.";
  if (list.length > 50) return "At most 50 patterns.";
  for (const p of list) {
    if (p.length > 64 || !/^[a-z0-9_.*]+$/.test(p)) return `"${p.slice(0, 40)}" is not valid: use lower-case letters, digits, _ . and *.`;
    if (catalog && !matchesCatalog(p, catalog)) return `"${p}" matches no permission in the catalog.`;
  }
  return null;
}

export function validateResources(list: string[]): string | null {
  if (list.length === 0) return "Enter at least one resource pattern (use * for all).";
  if (list.length > 50) return "At most 50 resource patterns.";
  for (const r of list) {
    if (r.length > 128) return `"${r.slice(0, 20)}…" is longer than 128 characters.`;
    if (UNSAFE_RE.test(r)) return "Control or direction-override characters are not allowed.";
  }
  return null;
}

function PolicyModal({ policy, onClose, onSaved }: { policy: IamPolicy | null; onClose: () => void; onSaved: (name: string) => void }) {
  const can = useCan();
  const catalogQ = useQuery(() => iam.catalog(), [], can("iam.roles.view"));
  const catalog = catalogQ.data;
  const readOnly = policy !== null && !can("iam.policies.write");
  const [name, setName] = useState(policy?.name ?? "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [effect, setEffect] = useState<Effect>(policy?.effect ?? "allow");
  const [permText, setPermText] = useState((policy?.permissions ?? []).join("\n"));
  const [resText, setResText] = useState((policy?.resources ?? ["*"]).join("\n"));
  const [disabled, setDisabled] = useState(policy?.disabled ?? false);
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const permissions = splitList(permText);
  const resources = splitList(resText);
  const nameErr = validateName(name);
  const descErr = validateDescription(description);
  const permErr = validatePatterns(permissions, catalog);
  const resErr = validateResources(resources);
  const full = { name, description, effect, permissions, resources, disabled };
  const same = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);
  const body = policy
    ? {
      ...(name !== policy.name ? { name } : {}),
      ...(description !== policy.description ? { description } : {}),
      ...(effect !== policy.effect ? { effect } : {}),
      ...(!same(permissions, policy.permissions) ? { permissions } : {}),
      ...(!same(resources, policy.resources) ? { resources } : {}),
      ...(disabled !== policy.disabled ? { disabled } : {}),
    }
    : full;
  const changed = Object.keys(body).length > 0;
  const anyErr = nameErr || descErr || permErr || resErr;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (readOnly || anyErr || !changed) return;
    setBusy(true);
    setError(null);
    try {
      const saved = policy ? await iam.updatePolicy(policy.id, body) : await iam.createPolicy(full);
      onSaved(saved.name);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  function addPattern(value: string) {
    if (value && !permissions.includes(value)) setPermText([...permissions, value].join("\n"));
  }

  const wildcards = catalog ? Array.from(new Set(["*", ...catalog.groups.flatMap((g) => g.permissions.flatMap((p) => {
    const parts = p.name.split(".");
    return [`${parts[0]}.*`, `${parts.slice(0, -1).join(".")}.*`];
  }))])) : [];

  return (
    <Modal title={policy ? (readOnly ? `Policy ${policy.name}` : `Edit policy ${policy.name}`) : "Create policy"} onClose={onClose} busy={busy} wide>
      <form className="iam-form" onSubmit={submit} noValidate>
        {readOnly && <p className="hint">You can view this policy but not change it.</p>}
        <Field label="Name" error={submitted ? nameErr : null}>
          {(a) => <input {...a} value={name} onChange={(e) => setName(e.target.value)} maxLength={48} readOnly={readOnly} required />}
        </Field>
        <Field label="Description" error={submitted ? descErr : null}>
          {(a) => <textarea {...a} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={255} readOnly={readOnly} />}
        </Field>
        <Field label="Effect">
          {(a) => (
            <select {...a} value={effect} onChange={(e) => setEffect(e.target.value as Effect)} disabled={readOnly}>
              <option value="allow">Allow: grants the permissions</option>
              <option value="deny">Deny: removes the permissions (always wins)</option>
            </select>
          )}
        </Field>
        <Field label="Permissions" error={submitted ? permErr : null}
          hint="One per line or comma separated. * is a wildcard, e.g. cloud.* or *.view.">
          {(a) => <textarea {...a} value={permText} onChange={(e) => setPermText(e.target.value)} readOnly={readOnly} spellCheck={false} />}
        </Field>
        {!readOnly && catalog && (
          <Field label="Add a permission from the catalog">
            {(a) => (
              <select {...a} value="" onChange={(e) => addPattern(e.target.value)}>
                <option value="">Choose…</option>
                <optgroup label="Wildcards">{wildcards.map((x) => <option key={x} value={x}>{x}</option>)}</optgroup>
                {catalog.groups.map((g) => (
                  <optgroup key={g.key} label={g.title}>{g.permissions.map((q) => <option key={q.name} value={q.name}>{q.name}</option>)}</optgroup>
                ))}
              </select>
            )}
          </Field>
        )}
        <Field label="Resources" error={submitted ? resErr : null}
          hint="One per line or comma separated; * matches all. Examples: instance:i-1234abcd, bucket:logs-*. A scoped allow requires a separate general grant to enter a cloud write route. A scoped deny blocks that resource.">
          {(a) => <textarea {...a} value={resText} onChange={(e) => setResText(e.target.value)} readOnly={readOnly} spellCheck={false} />}
        </Field>
        <label className="field inline">
          <input type="checkbox" checked={disabled} disabled={readOnly} onChange={(e) => setDisabled(e.target.checked)} />
          Disabled (kept, but not applied)
        </label>
        {error && <div className="error" role="alert">{error}</div>}
        {readOnly
          ? <div className="iam-modal-foot"><button type="button" onClick={onClose}>Close</button></div>
          : <ModalFooter busy={busy} onCancel={onClose} submitLabel={policy ? "Save changes" : "Create policy"} disabled={!changed} />}
      </form>
    </Modal>
  );
}

const TYPES: { type: SubjectType; perm: string; legend: string }[] = [
  { type: "user", perm: "iam.users.view", legend: "Users" },
  { type: "group", perm: "iam.groups.view", legend: "Groups" },
  { type: "role", perm: "iam.roles.view", legend: "Roles" },
];

function AttachBody({ detail, onClose, onSaved }: { detail: IamPolicyDetail; onClose: () => void; onSaved: () => void }) {
  const can = useCan();
  const users = useUserOptions(can("iam.users.view"));
  const groups = useGroupOptions(can("iam.groups.view"));
  const roles = useRoleOptions(can("iam.roles.view"));
  const initial = (t: SubjectType) => new Set(detail.attachments.filter((a) => a.subject_type === t).map((a) => a.subject_id));
  const [sel, setSel] = useState<Record<SubjectType, Set<number>>>({ user: initial("user"), group: initial("group"), role: initial("role") });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const queries: Record<SubjectType, Query<{ items: unknown[]; more: boolean }>> = { user: users, group: groups, role: roles };
  const items = {
    user: (users.data?.items ?? []).map((u) => ({ id: u.id, label: u.username })),
    group: (groups.data?.items ?? []).map((g) => ({ id: g.id, label: g.name })),
    role: (roles.data?.items ?? []).map((r) => ({ id: r.id, label: r.name })),
  };
  const same = (t: SubjectType) => sel[t].size === initial(t).size && [...sel[t]].every((i) => initial(t).has(i));
  const changed = TYPES.some((t) => can(t.perm) && !same(t.type));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    // PUT replaces the whole list: keep the attachments of a kind we are not allowed to list.
    const attachments = TYPES.flatMap((t) => (can(t.perm)
      ? [...sel[t.type]].map((subject_id) => ({ subject_type: t.type, subject_id }))
      : detail.attachments.filter((a) => a.subject_type === t.type).map(({ subject_type, subject_id }) => ({ subject_type, subject_id }))));
    try {
      await iam.setAttachments(detail.id, attachments);
      onSaved();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <form className="iam-form" onSubmit={submit}>
      <p className="muted">A policy applies to the users attached directly, the members of attached groups and the holders of attached roles.</p>
      {TYPES.map((t) => can(t.perm) ? (
        <QueryState key={t.type} q={queries[t.type]} what={t.legend.toLowerCase()} lines={3}>
          {() => <Checklist legend={t.legend} items={items[t.type]} selected={sel[t.type]}
            onChange={(next) => setSel((s) => ({ ...s, [t.type]: next }))} empty={`No ${t.legend.toLowerCase()}.`} />}
        </QueryState>
      ) : <p key={t.type} className="muted small-text">You cannot view {t.legend.toLowerCase()}; their attachments are kept as they are.</p>)}
      {error && <div className="error" role="alert">{error}</div>}
      <ModalFooter busy={busy} onCancel={onClose} submitLabel="Save attachments" disabled={!changed} />
    </form>
  );
}

function AttachModal({ policy, onClose, onSaved }: { policy: IamPolicy; onClose: () => void; onSaved: () => void }) {
  const detail = useQuery(() => iam.policy(policy.id), [policy.id]);
  return (
    <Modal title={`Attach ${policy.name}`} onClose={onClose} wide>
      <QueryState q={detail} what="this policy">{(d) => <AttachBody detail={d} onClose={onClose} onSaved={onSaved} />}</QueryState>
    </Modal>
  );
}

export default function Policies() {
  return (
    <Guard permission="iam.policies.view" what="policies">
      <PoliciesList />
    </Guard>
  );
}

function PoliciesList() {
  const can = useCan();
  const toast = useToast();
  const f = useFilters({ q: "", effect: "", disabled: "" });
  const key = JSON.stringify(f.applied);
  const list = usePaged((cursor) => iam.policies({ ...f.applied, limit: PAGE_SIZE, cursor }), key);
  const [editing, setEditing] = useState<IamPolicy | "new" | null>(null);
  const [attaching, setAttaching] = useState<IamPolicy | null>(null);
  const [deleting, setDeleting] = useState<IamPolicy | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const canWrite = can("iam.policies.write");

  async function toggle(p: IamPolicy) {
    setBusyId(p.id);
    try {
      await iam.updatePolicy(p.id, { disabled: !p.disabled });
      toast(`${p.disabled ? "Enabled" : "Disabled"} ${p.name}.`);
      await list.q.reload();
    } catch (err) {
      toast(errorText(err), "danger");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="stack">
      <PageHead title="Policies">
        {canWrite && <button className="primary" onClick={() => setEditing("new")}>Create policy</button>}
      </PageHead>
      <Card title="All policies">
        <FilterBar label="Filter policies" onApply={f.apply} onReset={f.reset}>
          <label className="field">Search name
            <input value={f.draft.q} maxLength={48} onChange={(e) => f.set("q", e.target.value)} />
          </label>
          <label className="field">Effect
            <select value={f.draft.effect} onChange={(e) => f.set("effect", e.target.value)}>
              <option value="">Any</option><option value="allow">Allow</option><option value="deny">Deny</option>
            </select>
          </label>
          <label className="field">State
            <select value={f.draft.disabled} onChange={(e) => f.set("disabled", e.target.value)}>
              <option value="">Any</option><option value="false">Enabled</option><option value="true">Disabled</option>
            </select>
          </label>
        </FilterBar>
        <QueryState q={list.q} what="policies">
          {(d) => d.items.length === 0 ? <p className="muted">No policies match.</p> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Policy</th><th>Effect</th><th>Permissions</th><th>Resources</th><th>Attached</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {d.items.map((p) => (
                    <tr key={p.id}>
                      <td>
                        <b className="wrap-anywhere">{p.name}</b>{" "}
                        {p.disabled && <Pill tone="warn">Disabled</Pill>}
                        {p.description && <div className="muted small-text wrap-anywhere">{p.description}</div>}
                      </td>
                      <td><Pill tone={p.effect === "deny" ? "danger" : "ok"}>{p.effect === "deny" ? "✕ Deny" : "✓ Allow"}</Pill></td>
                      <td><ul className="iam-chips">{p.permissions.map((x) => <li key={x}><code>{x}</code></li>)}</ul></td>
                      <td><ul className="iam-chips">{p.resources.map((x) => <li key={x}><code>{x}</code></li>)}</ul></td>
                      <td>{p.attachment_count}</td>
                      <td>
                        <div className="row-actions" style={{ justifyContent: "flex-end" }}>
                          <button className="small" onClick={() => setEditing(p)} aria-label={`${canWrite ? "Edit" : "View"} ${p.name}`}>{canWrite ? "Edit" : "View"}</button>
                          {canWrite && <button className="small" onClick={() => setAttaching(p)} aria-label={`Attach ${p.name}`}>Attach</button>}
                          {canWrite && <button className="small" disabled={busyId === p.id} onClick={() => void toggle(p)}
                            aria-label={`${p.disabled ? "Enable" : "Disable"} ${p.name}`}>{p.disabled ? "Enable" : "Disable"}</button>}
                          {canWrite && <button className="small danger-soft" onClick={() => setDeleting(p)} aria-label={`Delete ${p.name}`}>Delete</button>}
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
        <PolicyModal policy={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={(name) => {
          toast(editing === "new" ? `Created policy ${name}.` : `Saved policy ${name}.`);
          setEditing(null);
          void list.q.reload();
        }} />
      )}
      {attaching && (
        <AttachModal policy={attaching} onClose={() => setAttaching(null)} onSaved={() => {
          toast(`Updated attachments of ${attaching.name}.`);
          setAttaching(null);
          void list.q.reload();
        }} />
      )}
      {deleting && (
        <ConfirmDialog title={`Delete policy ${deleting.name}?`} confirmLabel="Delete policy" onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await iam.deletePolicy(deleting.id);
            toast(`Deleted policy ${deleting.name}.`);
            setDeleting(null);
            await list.q.reload();
          }}>
          <p>It is detached from {deleting.attachment_count} subject(s), and the sessions of the users it applied to end.
            {deleting.effect === "deny" && " It is a deny policy: what it blocked is allowed again."}</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
