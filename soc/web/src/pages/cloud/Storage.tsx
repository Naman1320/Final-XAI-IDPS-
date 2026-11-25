import { useState, type FormEvent } from "react";
import { cloudApi } from "../../api/cloud";
import type { Bucket, Volume } from "../../api/cloudTypes";
import { Card, ErrorText, PageHead, Pill } from "../../components/common";
import {
  Async, ConfirmDialog, Modal, PERM, Pager, StatePill, WriteButton, useCloudLoad, useMutation, useToast, useWriteAccess,
} from "../../components/cloud/ui";
import { VOLUME_TYPES, checkBucketName, checkInt, checkName } from "../../components/cloud/validate";
import { dateTime } from "../../format";
import { useDebounced } from "./Activity";

const LIMIT = 10;

export default function Storage() {
  return (
    <div className="stack">
      <PageHead title="Storage" />
      <Volumes />
      <Buckets />
    </div>
  );
}

// ---- volumes -----------------------------------------------------------------------------------------

type VolumeDialog = { kind: "create" } | { kind: "resize" | "attach" | "detach" | "delete"; volume: Volume } | null;

function Volumes() {
  const toast = useToast();
  const [q, setQ] = useState("");
  const [state, setState] = useState("");
  const [offset, setOffset] = useState(0);
  const [dialog, setDialog] = useState<VolumeDialog>(null);
  const dq = useDebounced(q.trim());
  const list = useCloudLoad(() => cloudApi.volumes({ q: dq, state, limit: LIMIT, offset }), [dq, state, offset]);

  return (
    <Card title="Volumes" actions={<WriteButton permission={PERM.storage} className="primary" onClick={() => setDialog({ kind: "create" })}>Create volume</WriteButton>}>
      <form className="toolbar" onSubmit={(e) => e.preventDefault()} aria-label="Volume filters">
        <label className="field">Search by name
          <input type="search" value={q} maxLength={63} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        </label>
        <label className="field">State
          <select value={state} onChange={(e) => { setState(e.target.value); setOffset(0); }}>
            <option value="">All states</option><option value="available">available</option><option value="in-use">in-use</option>
          </select>
        </label>
      </form>
      <Async state={list} what="Loading volumes">
        {(d) => (
          <>
            {d.items.length === 0 ? <p className="muted">No volumes match.</p> : (
              <div className="table-wrap">
                <table>
                  <caption className="cl-sr">Volumes</caption>
                  <thead><tr><th scope="col">Name</th><th scope="col">ID</th><th scope="col">Size</th><th scope="col">Type</th><th scope="col">State</th><th scope="col">Attached to</th><th scope="col">Encryption</th><th scope="col">Actions</th></tr></thead>
                  <tbody>
                    {d.items.map((v) => (
                      <tr key={v.id}>
                        <td>{v.name}</td>
                        <td><code>{v.id}</code></td>
                        <td>{v.size_gb} GB</td>
                        <td>{v.type}</td>
                        <td><StatePill state={v.state} /></td>
                        <td>{v.instance_id ? <code>{v.instance_id}</code> : <span className="muted">none</span>}</td>
                        <td>{v.encrypted ? <Pill tone="ok">encrypted</Pill> : <Pill tone="warn">not encrypted</Pill>}</td>
                        <td>
                          <div className="row-actions">
                            <WriteButton permission={PERM.storage} className="small" onClick={() => setDialog({ kind: "resize", volume: v })}>Resize</WriteButton>
                            {v.state === "in-use"
                              ? <WriteButton permission={PERM.storage} className="small" onClick={() => setDialog({ kind: "detach", volume: v })}>Detach</WriteButton>
                              : <WriteButton permission={PERM.storage} className="small" onClick={() => setDialog({ kind: "attach", volume: v })}>Attach</WriteButton>}
                            <WriteButton permission={PERM.storage} className="small danger-soft" onClick={() => setDialog({ kind: "delete", volume: v })}>Delete</WriteButton>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pager total={d.total} limit={d.limit} offset={d.offset} onChange={setOffset} noun="volumes" />
          </>
        )}
      </Async>

      {dialog?.kind === "create" && <CreateVolume onClose={() => setDialog(null)} onDone={() => void list.reload()} />}
      {dialog?.kind === "resize" && <ResizeVolume volume={dialog.volume} onClose={() => setDialog(null)} onDone={() => void list.reload()} />}
      {dialog?.kind === "attach" && <AttachVolume volume={dialog.volume} onClose={() => setDialog(null)} onDone={() => void list.reload()} />}
      {dialog?.kind === "detach" && (
        <ConfirmDialog title="Detach this volume?" confirmLabel="Detach" onClose={() => setDialog(null)}
          onConfirm={async () => { const r = await cloudApi.detachVolume(dialog.volume.id); toast(`Volume ${r.name} detached.`); void list.reload(); }}>
          <p>Volume <b>{dialog.volume.name}</b> <code>{dialog.volume.id}</code> will be detached from <code>{dialog.volume.instance_id}</code>.</p>
        </ConfirmDialog>
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDialog title="Delete this volume?" confirmLabel="Delete volume" danger onClose={() => setDialog(null)}
          onConfirm={async () => { const r = await cloudApi.deleteVolume(dialog.volume.id); toast(`Volume ${r.name} deleted.`); void list.reload(); }}>
          <p>Volume <b>{dialog.volume.name}</b> <code>{dialog.volume.id}</code> ({dialog.volume.size_gb} GB) will be deleted for good. A volume that is attached cannot be deleted.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function CreateVolume({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [name, setName] = useState("");
  const [size, setSize] = useState("20");
  const [type, setType] = useState("gp3");
  const [encrypted, setEncrypted] = useState(true);
  const [submitted, setSubmitted] = useState(false);
  const errors = { name: checkName(name), size: checkInt(size, 1, 16384) };
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (errors.name || errors.size) return;
    const r = await m.run(() => cloudApi.createVolume({ name, size_gb: Number(size), type, encrypted }), (x) => `Volume ${x.name} (${x.id}) created.`);
    if (r) { onDone(); onClose(); }
  };
  return (
    <Modal title="Create volume" onClose={onClose}>
      <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
        <label className="field">Name
          <input value={name} maxLength={63} onChange={(e) => setName(e.target.value)} aria-invalid={submitted && Boolean(errors.name)} />
          <span className="cl-field-error" role={submitted && errors.name ? "alert" : undefined}>{submitted ? errors.name : null}</span>
        </label>
        <div className="cl-form-row">
          <label className="field">Size (GB)
            <input inputMode="numeric" value={size} onChange={(e) => setSize(e.target.value)} aria-invalid={submitted && Boolean(errors.size)} />
            <span className="cl-field-error" role={submitted && errors.size ? "alert" : undefined}>{submitted ? errors.size : null}</span>
          </label>
          <label className="field">Type
            <select value={type} onChange={(e) => setType(e.target.value)}>{VOLUME_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
          </label>
        </div>
        <label className="field inline"><input type="checkbox" checked={encrypted} onChange={(e) => setEncrypted(e.target.checked)} /> Encrypted</label>
        <ErrorText error={m.error} />
        <div className="row-actions cl-modal-actions">
          <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
          <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Creating…" : "Create volume"}</button>
        </div>
      </form>
    </Modal>
  );
}

function ResizeVolume({ volume, onClose, onDone }: { volume: Volume; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [size, setSize] = useState(String(volume.size_gb));
  const [submitted, setSubmitted] = useState(false);
  const err = checkInt(size, 1, 16384) ?? (Number(size) < volume.size_gb ? `A volume can only grow (it is ${volume.size_gb} GB).` : null);
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (err) return;
    const r = await m.run(() => cloudApi.resizeVolume(volume.id, Number(size)), (x) => `Volume ${x.name} is now ${x.size_gb} GB.`);
    if (r) { onDone(); onClose(); }
  };
  return (
    <Modal title={`Resize ${volume.name}`} onClose={onClose}>
      <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
        <p className="muted">Currently {volume.size_gb} GB. A volume can only grow.</p>
        <label className="field">New size (GB)
          <input inputMode="numeric" value={size} onChange={(e) => setSize(e.target.value)} aria-invalid={submitted && Boolean(err)} />
          <span className="cl-field-error" role={submitted && err ? "alert" : undefined}>{submitted ? err : null}</span>
        </label>
        <ErrorText error={m.error} />
        <div className="row-actions cl-modal-actions">
          <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
          <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Resizing…" : "Resize"}</button>
        </div>
      </form>
    </Modal>
  );
}

function AttachVolume({ volume, onClose, onDone }: { volume: Volume; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const instances = useCloudLoad(() => cloudApi.instances({ limit: 200 }), []);
  const [target, setTarget] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const choices = (instances.data?.items ?? []).filter((i) => i.state !== "terminated");
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (!target) return;
    const r = await m.run(() => cloudApi.attachVolume(volume.id, target), (x) => `Volume ${x.name} attached to ${target}.`);
    if (r) { onDone(); onClose(); }
  };
  return (
    <Modal title={`Attach ${volume.name}`} onClose={onClose}>
      <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
        <label className="field">Instance
          <select value={target} onChange={(e) => setTarget(e.target.value)} aria-invalid={submitted && !target}>
            <option value="">{instances.loading && !instances.data ? "Loading…" : "Choose an instance…"}</option>
            {choices.map((i) => <option key={i.id} value={i.id}>{i.name} ({i.id}, {i.state})</option>)}
          </select>
          <span className="cl-field-error" role={submitted && !target ? "alert" : undefined}>{submitted && !target ? "Choose an instance." : null}</span>
        </label>
        <ErrorText error={m.error ?? (instances.error ? String((instances.error as Error).message) : null)} />
        <div className="row-actions cl-modal-actions">
          <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
          <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Attaching…" : "Attach"}</button>
        </div>
      </form>
    </Modal>
  );
}

// ---- buckets ------------------------------------------------------------------------------------------

type Flag = "versioning" | "encrypted" | "public_access_blocked";
const FLAGS: { key: Flag; label: string; risky: (on: boolean) => boolean; riskText: string }[] = [
  { key: "versioning", label: "Versioning", risky: () => false, riskText: "" },
  { key: "encrypted", label: "Encryption", risky: (on) => !on, riskText: "Turning encryption off leaves the data in this bucket unencrypted." },
  { key: "public_access_blocked", label: "Block public access", risky: (on) => !on, riskText: "Turning this off allows the bucket to be made public." },
];

function Buckets() {
  const toast = useToast();
  const write = useWriteAccess(PERM.storage);
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Bucket | null>(null);
  const [flag, setFlag] = useState<{ bucket: Bucket; key: Flag; on: boolean } | null>(null);
  const dq = useDebounced(q.trim());
  const list = useCloudLoad(() => cloudApi.buckets({ q: dq, limit: LIMIT, offset }), [dq, offset]);

  const setFlagNow = async (b: Bucket, key: Flag, on: boolean) => {
    const r = await cloudApi.updateBucket(b.name, { [key]: on });
    toast(`Bucket ${r.name}: ${FLAGS.find((f) => f.key === key)!.label.toLowerCase()} ${on ? "on" : "off"}.`);
    void list.reload();
  };
  const toggle = (b: Bucket, key: Flag, on: boolean) => {
    const f = FLAGS.find((x) => x.key === key)!;
    if (f.risky(on)) setFlag({ bucket: b, key, on });
    else void setFlagNow(b, key, on).catch((err) => toast(err instanceof Error ? err.message : String(err), "error"));
  };

  return (
    <Card title="Buckets" actions={<WriteButton permission={PERM.storage} className="primary" onClick={() => setCreating(true)}>Create bucket</WriteButton>}>
      <form className="toolbar" onSubmit={(e) => e.preventDefault()} aria-label="Bucket filters">
        <label className="field">Search by name
          <input type="search" value={q} maxLength={63} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        </label>
      </form>
      <Async state={list} what="Loading buckets">
        {(d) => (
          <>
            {d.items.length === 0 ? <p className="muted">No buckets match.</p> : (
              <div className="table-wrap">
                <table>
                  <caption className="cl-sr">Buckets</caption>
                  <thead><tr><th scope="col">Name</th><th scope="col">Objects</th><th scope="col">Size</th>{FLAGS.map((f) => <th key={f.key} scope="col">{f.label}</th>)}<th scope="col">Created</th><th scope="col">Actions</th></tr></thead>
                  <tbody>
                    {d.items.map((b) => (
                      <tr key={b.name}>
                        <td><code>{b.name}</code></td>
                        <td>{b.object_count.toLocaleString()}</td>
                        <td>{b.size_gb} GB</td>
                        {FLAGS.map((f) => (
                          <td key={f.key}>
                            <label className="field inline">
                              <input type="checkbox" role="switch" checked={b[f.key]} disabled={!write.allowed} title={write.reason}
                                aria-label={`${f.label} for ${b.name}`} onChange={(e) => toggle(b, f.key, e.target.checked)} />
                              {b[f.key] ? "On" : "Off"}
                            </label>
                          </td>
                        ))}
                        <td>{dateTime(b.created_at)}</td>
                        <td><WriteButton permission={PERM.storage} className="small danger-soft" onClick={() => setDeleting(b)}>Delete</WriteButton></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pager total={d.total} limit={d.limit} offset={d.offset} onChange={setOffset} noun="buckets" />
          </>
        )}
      </Async>

      {creating && <CreateBucket onClose={() => setCreating(false)} onDone={() => void list.reload()} />}
      {flag && (
        <ConfirmDialog title={`Turn off ${FLAGS.find((f) => f.key === flag.key)!.label.toLowerCase()}?`} confirmLabel="Turn off" danger onClose={() => setFlag(null)}
          onConfirm={() => setFlagNow(flag.bucket, flag.key, flag.on)}>
          <p>Bucket <code>{flag.bucket.name}</code>. {FLAGS.find((f) => f.key === flag.key)!.riskText}</p>
        </ConfirmDialog>
      )}
      {deleting && (
        <ConfirmDialog title="Delete this bucket?" confirmLabel={deleting.object_count > 0 ? "Delete bucket and its objects" : "Delete bucket"} danger
          requireText={deleting.object_count > 0 ? deleting.name : undefined} onClose={() => setDeleting(null)}
          onConfirm={async () => { const r = await cloudApi.deleteBucket(deleting.name, deleting.object_count > 0); toast(`Bucket ${r.name} deleted.`); void list.reload(); }}>
          {deleting.object_count > 0
            ? <p>Bucket <code>{deleting.name}</code> holds <b>{deleting.object_count.toLocaleString()} objects</b>. Deleting it will force-delete them too, which cannot be undone.</p>
            : <p>Bucket <code>{deleting.name}</code> is empty and will be deleted.</p>}
        </ConfirmDialog>
      )}
    </Card>
  );
}

function CreateBucket({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [name, setName] = useState("");
  const [versioning, setVersioning] = useState(false);
  const [encrypted, setEncrypted] = useState(true);
  const [blocked, setBlocked] = useState(true);
  const [submitted, setSubmitted] = useState(false);
  const nameErr = checkBucketName(name);
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (nameErr) return;
    const r = await m.run(() => cloudApi.createBucket({ name, versioning, encrypted, public_access_blocked: blocked }), (x) => `Bucket ${x.name} created.`);
    if (r) { onDone(); onClose(); }
  };
  return (
    <Modal title="Create bucket" onClose={onClose}>
      <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
        <label className="field">Bucket name
          <input value={name} maxLength={63} onChange={(e) => setName(e.target.value)} aria-invalid={submitted && Boolean(nameErr)} />
          <span className="cl-field-error" role={submitted && nameErr ? "alert" : undefined}>{submitted ? nameErr : null}</span>
        </label>
        <label className="field inline"><input type="checkbox" checked={versioning} onChange={(e) => setVersioning(e.target.checked)} /> Versioning</label>
        <label className="field inline"><input type="checkbox" checked={encrypted} onChange={(e) => setEncrypted(e.target.checked)} /> Encryption</label>
        <label className="field inline"><input type="checkbox" checked={blocked} onChange={(e) => setBlocked(e.target.checked)} /> Block public access</label>
        <ErrorText error={m.error} />
        <div className="row-actions cl-modal-actions">
          <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
          <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Creating…" : "Create bucket"}</button>
        </div>
      </form>
    </Modal>
  );
}
