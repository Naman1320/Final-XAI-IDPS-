import { useMemo, useState, type FormEvent } from "react";
import { ApiError } from "../../api/client";
import { cloudApi } from "../../api/cloud";
import type { RuleCreate, SecurityGroup, SgRule } from "../../api/cloudTypes";
import { Card, ErrorText, PageHead, Pill } from "../../components/common";
import {
  Async, ConfirmDialog, Modal, PERM, WriteButton, useCloudLoad, useMutation, useToast,
} from "../../components/cloud/ui";
import { checkCidr, checkInt, checkSgName, checkText } from "../../components/cloud/validate";

export default function Network() {
  const [vpcFilter, setVpcFilter] = useState("");
  const vpcs = useCloudLoad(() => cloudApi.vpcs({ limit: 200 }), []);
  const subnets = useCloudLoad(() => cloudApi.subnets({ vpc_id: vpcFilter, limit: 200 }), [vpcFilter]);

  return (
    <div className="stack">
      <PageHead title="Network" />
      <div className="grid cols-2">
        <Card title="VPCs">
          <Async state={vpcs} what="Loading VPCs">
            {(d) => d.items.length === 0 ? <p className="muted">No VPCs.</p> : (
              <div className="table-wrap">
                <table>
                  <caption className="cl-sr">VPCs</caption>
                  <thead><tr><th scope="col">Name</th><th scope="col">ID</th><th scope="col">CIDR</th><th scope="col">Subnets</th><th scope="col">Instances</th></tr></thead>
                  <tbody>{d.items.map((v) => (
                    <tr key={v.id}><td>{v.name}</td><td><code>{v.id}</code></td><td><code>{v.cidr}</code></td><td>{v.subnet_count}</td><td>{v.instance_count}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </Async>
        </Card>
        <Card title="Subnets">
          <label className="field" style={{ maxWidth: 260 }}>Show subnets of
            <select value={vpcFilter} onChange={(e) => setVpcFilter(e.target.value)}>
              <option value="">All VPCs</option>
              {(vpcs.data?.items ?? []).map((v) => <option key={v.id} value={v.id}>{v.name} ({v.id})</option>)}
            </select>
          </label>
          <Async state={subnets} what="Loading subnets">
            {(d) => d.items.length === 0 ? <p className="muted">No subnets.</p> : (
              <div className="table-wrap">
                <table>
                  <caption className="cl-sr">Subnets</caption>
                  <thead><tr><th scope="col">Name</th><th scope="col">VPC</th><th scope="col">CIDR</th><th scope="col">Zone</th><th scope="col">Access</th></tr></thead>
                  <tbody>{d.items.map((s) => (
                    <tr key={s.id}><td>{s.name}</td><td><code>{s.vpc_id}</code></td><td><code>{s.cidr}</code></td><td>{s.az}</td>
                      <td><Pill tone={s.public ? "warn" : "neutral"}>{s.public ? "public" : "private"}</Pill></td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </Async>
        </Card>
      </div>
      <SecurityGroups vpcs={(vpcs.data?.items ?? []).map((v) => ({ id: v.id, name: v.name }))} />
    </div>
  );
}

// ---- security groups -------------------------------------------------------------------------------------

function ports(r: SgRule): string {
  if (r.protocol === "icmp" || r.protocol === "all") return "all";
  return r.port_from === r.port_to ? String(r.port_from) : `${r.port_from}-${r.port_to}`;
}

function SecurityGroups({ vpcs }: { vpcs: { id: string; name: string }[] }) {
  const toast = useToast();
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<SecurityGroup | null>(null);
  const list = useCloudLoad(() => cloudApi.securityGroups({ limit: 200 }), []);
  const current = useMemo(() => list.data?.items.find((g) => g.id === selected) ?? null, [list.data, selected]);

  return (
    <Card title="Security groups" actions={<WriteButton permission={PERM.network} className="primary" onClick={() => setCreating(true)}>Create security group</WriteButton>}>
      <Async state={list} what="Loading security groups">
        {(d) => d.items.length === 0 ? <p className="muted">No security groups.</p> : (
          <div className="table-wrap">
            <table>
              <caption className="cl-sr">Security groups</caption>
              <thead><tr><th scope="col">Name</th><th scope="col">ID</th><th scope="col">VPC</th><th scope="col">Rules</th><th scope="col">Used by</th><th scope="col">Exposure</th><th scope="col">Actions</th></tr></thead>
              <tbody>
                {d.items.map((g) => (
                  <tr key={g.id} className={g.id === selected ? "cl-selected" : undefined}>
                    <td>{g.name}<div className="muted small-text">{g.description}</div></td>
                    <td><code>{g.id}</code></td>
                    <td><code>{g.vpc_id}</code></td>
                    <td>{g.rules.length}</td>
                    <td>{g.instances_using} instance{g.instances_using === 1 ? "" : "s"}</td>
                    <td>{g.open_to_world_admin_ports ? <Pill tone="danger"><span aria-hidden="true">✕</span> SSH/RDP open to the world</Pill> : <Pill tone="ok"><span aria-hidden="true">✓</span> not open</Pill>}</td>
                    <td>
                      <div className="row-actions">
                        <button type="button" className="small" aria-pressed={g.id === selected} aria-label={`${g.id === selected ? "Hide" : "Show"} rules of ${g.name}`}
                          onClick={() => setSelected(g.id === selected ? null : g.id)}>{g.id === selected ? "Hide rules" : "Rules"}</button>
                        <WriteButton permission={PERM.network} className="small danger-soft" onClick={() => setDeleting(g)}>Delete</WriteButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Async>
      {current && <Rules group={current} onChanged={() => void list.reload()} />}

      {creating && <CreateGroup vpcs={vpcs} onClose={() => setCreating(false)} onDone={() => void list.reload()} />}
      {deleting && (
        <ConfirmDialog title="Delete this security group?" confirmLabel="Delete security group" danger onClose={() => setDeleting(null)}
          onConfirm={async () => {
            const r = await cloudApi.deleteSecurityGroup(deleting.id);
            toast(`Security group ${r.name} deleted.`);
            if (selected === deleting.id) setSelected(null);
            void list.reload();
          }}>
          <p>Security group <b>{deleting.name}</b> <code>{deleting.id}</code> and its {deleting.rules.length} rules will be deleted. A group used by an instance cannot be deleted.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function CreateGroup({ vpcs, onClose, onDone }: { vpcs: { id: string; name: string }[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [vpc, setVpc] = useState(vpcs[0]?.id ?? "");
  const [submitted, setSubmitted] = useState(false);
  const errors = { name: checkSgName(name), description: checkText(description, 255), vpc: vpc ? null : "Choose a VPC." };
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (Object.values(errors).some(Boolean)) return;
    const r = await m.run(() => cloudApi.createSecurityGroup({ name, description, vpc_id: vpc }), (x) => `Security group ${x.name} (${x.id}) created.`);
    if (r) { onDone(); onClose(); }
  };
  return (
    <Modal title="Create security group" onClose={onClose}>
      <form className="cl-form" onSubmit={(e) => void submit(e)} noValidate>
        <label className="field">Name
          <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} aria-invalid={submitted && Boolean(errors.name)} />
          <span className="cl-field-error" role={submitted && errors.name ? "alert" : undefined}>{submitted ? errors.name : null}</span>
        </label>
        <label className="field">Description (optional)
          <input value={description} maxLength={255} onChange={(e) => setDescription(e.target.value)} aria-invalid={submitted && Boolean(errors.description)} />
          <span className="cl-field-error" role={submitted && errors.description ? "alert" : undefined}>{submitted ? errors.description : null}</span>
        </label>
        <label className="field">VPC
          <select value={vpc} onChange={(e) => setVpc(e.target.value)}>
            <option value="">Choose a VPC…</option>
            {vpcs.map((v) => <option key={v.id} value={v.id}>{v.name} ({v.id})</option>)}
          </select>
          <span className="cl-field-error" role={submitted && errors.vpc ? "alert" : undefined}>{submitted ? errors.vpc : null}</span>
        </label>
        <p className="muted small-text">A new group allows all outgoing traffic and no incoming traffic.</p>
        <ErrorText error={m.error} />
        <div className="row-actions cl-modal-actions">
          <button type="button" onClick={onClose} disabled={m.busy}>Cancel</button>
          <button type="submit" className="primary" disabled={m.busy}>{m.busy ? "Creating…" : "Create security group"}</button>
        </div>
      </form>
    </Modal>
  );
}

/** What the server says when an SSH/RDP-to-the-world rule is sent without the confirmation flag. */
const isWorldRefusal = (err: unknown) => err instanceof ApiError && err.status === 422 && err.code === "confirm_open_to_world";

function Rules({ group, onChanged }: { group: SecurityGroup; onChanged: () => void }) {
  const toast = useToast();
  const m = useMutation();
  const [direction, setDirection] = useState<"in" | "out">("in");
  const [protocol, setProtocol] = useState<RuleCreate["protocol"]>("tcp");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [cidr, setCidr] = useState("");
  const [description, setDescription] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [confirmWorld, setConfirmWorld] = useState<{ body: RuleCreate; reason: string } | null>(null);
  const [removing, setRemoving] = useState<SgRule | null>(null);

  const hasPorts = protocol === "tcp" || protocol === "udp";
  const errors = {
    from: hasPorts ? checkInt(from, 0, 65535) : null,
    to: hasPorts && to.trim() ? checkInt(to, 0, 65535) : null,
    range: hasPorts && !checkInt(from, 0, 65535) && to.trim() && !checkInt(to, 0, 65535) && Number(from) > Number(to) ? "The first port must not be above the last port." : null,
    cidr: checkCidr(cidr),
    description: checkText(description, 255),
  };
  const bad = Object.values(errors).some(Boolean);
  const body = (confirm: boolean): RuleCreate => ({
    direction, protocol, cidr: cidr.trim(), description,
    ...(hasPorts ? { port_from: Number(from), port_to: to.trim() ? Number(to) : Number(from) } : {}),
    ...(confirm ? { confirm_open_to_world: true } : {}),
  });

  const send = async (confirm: boolean) => {
    const b = body(confirm);
    try {
      await cloudApi.addRule(group.id, b);
    } catch (err) {
      if (!confirm && isWorldRefusal(err)) { setConfirmWorld({ body: b, reason: (err as Error).message }); return; }
      throw err;
    }
    toast(`Rule added to ${group.name}.`);
    setCidr(""); setFrom(""); setTo(""); setDescription(""); setSubmitted(false);
    onChanged();
  };
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setSubmitted(true);
    if (bad) return;
    await m.run(() => send(false));
  };

  return (
    <section className="cl-rules" aria-label={`Rules of ${group.name}`}>
      <h3>Rules of {group.name}</h3>
      <div className="table-wrap">
        <table>
          <caption className="cl-sr">Rules of {group.name}</caption>
          <thead><tr><th scope="col">Direction</th><th scope="col">Protocol</th><th scope="col">Ports</th><th scope="col">Source / destination</th><th scope="col">Description</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {group.rules.length === 0 && <tr><td colSpan={6} className="muted">No rules: all traffic is refused.</td></tr>}
            {group.rules.map((r) => (
              <tr key={r.id}>
                <td>{r.direction === "in" ? "Inbound" : "Outbound"}</td>
                <td>{r.protocol}</td>
                <td>{ports(r)}</td>
                <td><code>{r.cidr}</code>{r.cidr.endsWith("/0") && r.direction === "in" ? <> <Pill tone="warn">whole internet</Pill></> : null}</td>
                <td className="wrap-anywhere">{r.description}</td>
                <td><WriteButton permission={PERM.network} className="small danger-soft" onClick={() => setRemoving(r)}>Remove</WriteButton></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <form className="inline-panel cl-rule-form" onSubmit={(e) => void submit(e)} noValidate aria-label={`Add a rule to ${group.name}`}>
        <label className="field">Direction
          <select value={direction} onChange={(e) => setDirection(e.target.value as "in" | "out")}><option value="in">Inbound</option><option value="out">Outbound</option></select>
        </label>
        <label className="field">Protocol
          <select value={protocol} onChange={(e) => setProtocol(e.target.value as RuleCreate["protocol"])}>
            {["tcp", "udp", "icmp", "all"].map((p) => <option key={p}>{p}</option>)}
          </select>
        </label>
        <label className="field">Port from
          <input inputMode="numeric" value={from} disabled={!hasPorts} onChange={(e) => setFrom(e.target.value)} aria-invalid={submitted && Boolean(errors.from || errors.range)} />
          <span className="cl-field-error" role={submitted && (errors.from || errors.range) ? "alert" : undefined}>{submitted ? errors.from ?? errors.range : null}</span>
        </label>
        <label className="field">Port to (optional)
          <input inputMode="numeric" value={to} disabled={!hasPorts} onChange={(e) => setTo(e.target.value)} aria-invalid={submitted && Boolean(errors.to)} />
          <span className="cl-field-error" role={submitted && errors.to ? "alert" : undefined}>{submitted ? errors.to : null}</span>
        </label>
        <label className="field">CIDR range
          <input value={cidr} placeholder="10.0.0.0/24" onChange={(e) => setCidr(e.target.value)} aria-invalid={submitted && Boolean(errors.cidr)} />
          <span className="cl-field-error" role={submitted && errors.cidr ? "alert" : undefined}>{submitted ? errors.cidr : null}</span>
        </label>
        <label className="field">Description (optional)
          <input value={description} maxLength={255} onChange={(e) => setDescription(e.target.value)} aria-invalid={submitted && Boolean(errors.description)} />
          <span className="cl-field-error" role={submitted && errors.description ? "alert" : undefined}>{submitted ? errors.description : null}</span>
        </label>
        <WriteButton type="submit" permission={PERM.network} className="primary" disabled={m.busy}>{m.busy ? "Adding…" : "Add rule"}</WriteButton>
      </form>
      <ErrorText error={m.error} />

      {confirmWorld && (
        <ConfirmDialog title="Open this port to the whole internet?" confirmLabel="Add the rule anyway" danger onClose={() => setConfirmWorld(null)}
          onConfirm={async () => { await send(true); }}>
          <p>The server refused this rule until you confirm it:</p>
          <p className="note">{confirmWorld.reason}</p>
        </ConfirmDialog>
      )}
      {removing && (
        <ConfirmDialog title="Remove this rule?" confirmLabel="Remove rule" danger onClose={() => setRemoving(null)}
          onConfirm={async () => { await cloudApi.deleteRule(group.id, removing.id); toast(`Rule removed from ${group.name}.`); onChanged(); }}>
          <p>{removing.direction === "in" ? "Inbound" : "Outbound"} {removing.protocol} {ports(removing)} {removing.direction === "in" ? "from" : "to"} <code>{removing.cidr}</code> will be removed from <b>{group.name}</b>.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}
