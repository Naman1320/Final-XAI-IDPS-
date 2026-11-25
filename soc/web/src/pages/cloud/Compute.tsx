import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { cloudApi } from "../../api/cloud";
import type { Instance, InstanceCreate } from "../../api/cloudTypes";
import { Card, ErrorText, PageHead } from "../../components/common";
import {
  Async, HealthPill, Loading, Modal, PERM, Pager, StatePill, WriteButton, describeError, useCloudLoad, useMutation,
} from "../../components/cloud/ui";
import { INSTANCE_TYPES, OPERATING_SYSTEMS, checkInt, checkName, parseTags } from "../../components/cloud/validate";
import { dateTime } from "../../format";
import { useDebounced } from "./Activity";

const LIMIT = 10;
type SortKey = "name" | "state" | "instance_type" | "az" | "launched_at";

export default function Compute() {
  const [q, setQ] = useState("");
  const [state, setState] = useState("");
  const [az, setAz] = useState("");
  const [type, setType] = useState("");
  const [sort, setSort] = useState<SortKey>("name");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);
  const dq = useDebounced(q.trim());

  const subnets = useCloudLoad(() => cloudApi.subnets({ limit: 200 }), []);
  const azs = useMemo(() => [...new Set(subnets.data?.items.map((s) => s.az) ?? [])].sort(), [subnets.data]);
  const list = useCloudLoad(
    () => cloudApi.instances({ q: dq, state, az, type, sort, order, limit: LIMIT, offset }),
    [dq, state, az, type, sort, order, offset],
    { pollMs: 4000, poll: (d) => d.items.some((i) => i.state === "pending") });

  const reset = (fn: () => void) => { fn(); setOffset(0); };
  const sortBy = (k: SortKey) => {
    if (k === sort) setOrder((o) => (o === "asc" ? "desc" : "asc"));
    else { setSort(k); setOrder("asc"); }
    setOffset(0);
  };
  const th = (k: SortKey, text: string) => (
    <th scope="col" aria-sort={sort === k ? (order === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className="link-button cl-sort" onClick={() => sortBy(k)}>{text}{sort === k ? (order === "asc" ? " ▲" : " ▼") : ""}</button>
    </th>
  );

  return (
    <div className="stack">
      <PageHead title="Compute">
        <WriteButton permission={PERM.instances} className="primary" onClick={() => setCreating(true)}>Create instance</WriteButton>
      </PageHead>
      <Card>
        <form className="toolbar" onSubmit={(e) => e.preventDefault()} aria-label="Instance filters">
          <label className="field">Search by name
            <input type="search" value={q} maxLength={63} onChange={(e) => reset(() => setQ(e.target.value))} />
          </label>
          <label className="field">State
            <select value={state} onChange={(e) => reset(() => setState(e.target.value))}>
              <option value="">All states</option>
              {["running", "stopped", "pending", "terminated"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="field">Availability zone
            <select value={az} onChange={(e) => reset(() => setAz(e.target.value))}>
              <option value="">All zones</option>
              {azs.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
          </label>
          <label className="field">Type
            <select value={type} onChange={(e) => reset(() => setType(e.target.value))}>
              <option value="">All types</option>
              {INSTANCE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <button type="button" onClick={() => { setQ(""); setState(""); setAz(""); setType(""); setOffset(0); }}>Clear filters</button>
        </form>
        <Async state={list} what="Loading instances">
          {(d) => (
            <>
              {d.items.length === 0 ? <p className="muted">No instances match these filters.</p> : (
                <div className="table-wrap">
                  <table>
                    <caption className="cl-sr">Instances</caption>
                    <thead>
                      <tr>
                        {th("name", "Name")}<th scope="col">ID</th>{th("state", "State")}<th scope="col">Health</th>
                        {th("instance_type", "Type")}{th("az", "Zone")}<th scope="col">Private IP</th>
                        <th scope="col">Public IP</th>{th("launched_at", "Launched")}
                      </tr>
                    </thead>
                    <tbody>
                      {d.items.map((i) => (
                        <tr key={i.id}>
                          <td><Link to={encodeURIComponent(i.id)}>{i.name}</Link></td>
                          <td><code>{i.id}</code></td>
                          <td><StatePill state={i.state} /></td>
                          <td><HealthPill status={i.health.status} /></td>
                          <td>{i.instance_type}</td>
                          <td>{i.az}</td>
                          <td><code>{i.private_ip}</code></td>
                          <td>{i.public_ip ? <code>{i.public_ip}</code> : <span className="muted">none</span>}</td>
                          <td>{dateTime(i.launched_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Pager total={d.total} limit={d.limit} offset={d.offset} onChange={setOffset} noun="instances" />
            </>
          )}
        </Async>
      </Card>
      {creating && <CreateInstance onClose={() => setCreating(false)} onCreated={() => void list.reload()} />}
    </div>
  );
}

function CreateInstance({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const subnets = useCloudLoad(() => cloudApi.subnets({ limit: 200 }), []);
  const groups = useCloudLoad(() => cloudApi.securityGroups({ limit: 200 }), []);
  const m = useMutation();
  const [name, setName] = useState("");
  const [type, setType] = useState("t3.micro");
  const [subnetId, setSubnetId] = useState("");
  const [sgs, setSgs] = useState<string[]>([]);
  const [os, setOs] = useState("Ubuntu 22.04");
  const [disk, setDisk] = useState("20");
  const [tagText, setTagText] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const subnet = subnets.data?.items.find((s) => s.id === subnetId);
  const vpcGroups = (groups.data?.items ?? []).filter((g) => subnet && g.vpc_id === subnet.vpc_id);
  const tags = parseTags(tagText);
  const errors = {
    name: checkName(name),
    subnet: subnetId ? null : "Choose a subnet.",
    sgs: sgs.length === 0 ? "Choose at least one security group." : sgs.length > 5 ? "At most 5 security groups." : null,
    disk: checkInt(disk, 8, 1000),
    tags: tags.error,
  };
  const bad = Object.values(errors).some(Boolean);
  const err = (k: keyof typeof errors) => (submitted ? errors[k] : null);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (bad) return;
    const body: InstanceCreate = { name, instance_type: type, subnet_id: subnetId, security_group_ids: sgs, az: subnet?.az, os, disk_gb: Number(disk), tags: tags.tags };
    const r = await m.run(() => cloudApi.createInstance(body), (x) => `Instance ${x.name} (${x.id}) created; it starts as pending.`);
    if (r) { onCreated(); onClose(); }
  };

  return (
    <Modal title="Create instance" onClose={onClose} wide>
      {Boolean(subnets.error || groups.error) && <ErrorText error={describeError(subnets.error ?? groups.error)} />}
      {(subnets.loading || groups.loading) && !subnets.data ? <Loading what="Loading subnets and security groups" /> : (
        <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
          <label className="field">Name
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={63} aria-invalid={Boolean(err("name"))} aria-describedby="ci-name-err" />
            <span id="ci-name-err" className="cl-field-error" role={err("name") ? "alert" : undefined}>{err("name")}</span>
          </label>
          <div className="cl-form-row">
            <label className="field">Instance type
              <select value={type} onChange={(e) => setType(e.target.value)}>{INSTANCE_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
            </label>
            <label className="field">Operating system
              <select value={os} onChange={(e) => setOs(e.target.value)}>{OPERATING_SYSTEMS.map((t) => <option key={t}>{t}</option>)}</select>
            </label>
            <label className="field">Disk (GB)
              <input inputMode="numeric" value={disk} onChange={(e) => setDisk(e.target.value)} aria-invalid={Boolean(err("disk"))} aria-describedby="ci-disk-err" />
              <span id="ci-disk-err" className="cl-field-error" role={err("disk") ? "alert" : undefined}>{err("disk")}</span>
            </label>
          </div>
          <label className="field">Subnet
            <select value={subnetId} onChange={(e) => { setSubnetId(e.target.value); setSgs([]); }} aria-invalid={Boolean(err("subnet"))} aria-describedby="ci-subnet-err">
              <option value="">Choose a subnet…</option>
              {(subnets.data?.items ?? []).map((s) => <option key={s.id} value={s.id}>{s.name} ({s.az}, {s.cidr}{s.public ? ", public" : ", private"})</option>)}
            </select>
            <span id="ci-subnet-err" className="cl-field-error" role={err("subnet") ? "alert" : undefined}>{err("subnet")}</span>
          </label>
          <fieldset className="cl-fieldset" aria-describedby="ci-sg-err">
            <legend>Security groups (in the subnet's VPC)</legend>
            {!subnet ? <p className="muted small-text">Choose a subnet first.</p> : vpcGroups.length === 0 ? <p className="muted small-text">No security group in this VPC; create one under Network.</p> : (
              vpcGroups.map((g) => (
                <label key={g.id} className="field inline">
                  <input type="checkbox" checked={sgs.includes(g.id)}
                    onChange={(e) => setSgs((l) => (e.target.checked ? [...l, g.id] : l.filter((x) => x !== g.id)))} />
                  {g.name} <code>{g.id}</code>
                </label>
              ))
            )}
            <span id="ci-sg-err" className="cl-field-error" role={err("sgs") ? "alert" : undefined}>{err("sgs")}</span>
          </fieldset>
          <label className="field">Tags (one key=value per line, optional)
            <textarea value={tagText} onChange={(e) => setTagText(e.target.value)} rows={3} aria-invalid={Boolean(err("tags"))} aria-describedby="ci-tags-err" />
            <span id="ci-tags-err" className="cl-field-error" role={err("tags") ? "alert" : undefined}>{err("tags")}</span>
          </label>
          <ErrorText error={m.error} />
          <div className="row-actions cl-modal-actions">
            <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
            <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Creating…" : "Create instance"}</button>
          </div>
        </form>
      )}
    </Modal>
  );
}

export function EditInstance({ instance, onClose, onSaved }: { instance: Instance; onClose: () => void; onSaved: () => void }) {
  const m = useMutation();
  const [name, setName] = useState(instance.name);
  const [tagText, setTagText] = useState(Object.entries(instance.tags).map(([k, v]) => `${k}=${v}`).join("\n"));
  const [submitted, setSubmitted] = useState(false);
  const tags = parseTags(tagText);
  const nameErr = checkName(name);
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (nameErr || tags.error) return;
    const body: { name?: string; tags?: Record<string, string> } = {};
    if (name !== instance.name) body.name = name;
    body.tags = tags.tags;
    const r = await m.run(() => cloudApi.updateInstance(instance.id, body), `Instance ${instance.id} updated.`);
    if (r) { onSaved(); onClose(); }
  };
  return (
    <Modal title={`Edit ${instance.name}`} onClose={onClose}>
      <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
        <label className="field">Name
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={63} aria-invalid={submitted && Boolean(nameErr)} />
          <span className="cl-field-error" role={submitted && nameErr ? "alert" : undefined}>{submitted ? nameErr : null}</span>
        </label>
        <label className="field">Tags (one key=value per line)
          <textarea value={tagText} onChange={(e) => setTagText(e.target.value)} rows={4} aria-invalid={submitted && Boolean(tags.error)} />
          <span className="cl-field-error" role={submitted && tags.error ? "alert" : undefined}>{submitted ? tags.error : null}</span>
        </label>
        <ErrorText error={m.error} />
        <div className="row-actions cl-modal-actions">
          <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
          <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Saving…" : "Save"}</button>
        </div>
      </form>
    </Modal>
  );
}
