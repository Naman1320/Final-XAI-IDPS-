import { useState } from "react";
import { cloudApi } from "../../api/cloud";
import type { CloudAlert } from "../../api/cloudTypes";
import { Card, PageHead } from "../../components/common";
import {
  Async, AlertSeverityPill, AlertStatusPill, ConfirmDialog, PERM, Pager, WriteButton, ago, useCloudLoad, useMutation, useToast,
} from "../../components/cloud/ui";
import { ErrorText } from "../../components/common";
import { dateTime } from "../../format";

const LIMIT = 15;

export default function Alerts() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [rtype, setRtype] = useState("");
  const [offset, setOffset] = useState(0);
  const [deleting, setDeleting] = useState<CloudAlert | null>(null);
  const m = useMutation();
  const toast = useToast();
  const list = useCloudLoad(() => cloudApi.alerts({ status, severity, resource_type: rtype, limit: LIMIT, offset }), [status, severity, rtype, offset]);
  const reset = (fn: () => void) => { fn(); setOffset(0); };

  const evaluate = async () => {
    const r = await m.run(() => cloudApi.evaluateAlerts(),
      (x) => `Evaluation done: ${x.findings} finding${x.findings === 1 ? "" : "s"}, ${x.created.length} new alert${x.created.length === 1 ? "" : "s"}, ${x.escalated.length} escalated, ${x.already_open} already open.`);
    if (r) void list.reload();
  };
  const move = async (a: CloudAlert, verb: "acknowledge" | "resolve") => {
    const r = await m.run(() => cloudApi.alertAction(a.id, verb), `Alert ${a.id} ${verb === "acknowledge" ? "acknowledged" : "resolved"}.`, { toastError: true });
    if (r) void list.reload();
  };

  return (
    <div className="stack">
      <PageHead title="Alerts">
        <WriteButton permission={PERM.alerts} className="primary" disabled={m.busy} onClick={() => void evaluate()}>{m.busy ? "Working…" : "Run evaluation"}</WriteButton>
      </PageHead>
      <ErrorText error={m.error} />
      <Card>
        <p className="muted small-text">Evaluation checks CPU, memory and disk thresholds, public or unencrypted buckets, SSH or RDP open to the world and unencrypted volumes. It never repeats an open alert and never resolves one.</p>
        <form className="toolbar" onSubmit={(e) => e.preventDefault()} aria-label="Alert filters">
          <label className="field">Status
            <select value={status} onChange={(e) => reset(() => setStatus(e.target.value))}>
              <option value="">All statuses</option>{["open", "acknowledged", "resolved"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="field">Severity
            <select value={severity} onChange={(e) => reset(() => setSeverity(e.target.value))}>
              <option value="">All severities</option>{["critical", "warning", "info"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="field">Resource type
            <select value={rtype} onChange={(e) => reset(() => setRtype(e.target.value))}>
              <option value="">All types</option>{["instance", "volume", "bucket", "security_group"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
            </select>
          </label>
          <button type="button" onClick={() => { setStatus(""); setSeverity(""); setRtype(""); setOffset(0); }}>Clear filters</button>
        </form>
        <Async state={list} what="Loading alerts">
          {(d) => (
            <>
              {d.items.length === 0 ? <p className="muted">No alerts match these filters.</p> : (
                <div className="table-wrap">
                  <table>
                    <caption className="cl-sr">Cloud alerts, newest first</caption>
                    <thead><tr><th scope="col">Severity</th><th scope="col">Status</th><th scope="col">Alert</th><th scope="col">Resource</th><th scope="col">Raised</th><th scope="col">Actions</th></tr></thead>
                    <tbody>
                      {d.items.map((a) => (
                        <tr key={a.id}>
                          <td><AlertSeverityPill severity={a.severity} /></td>
                          <td><AlertStatusPill status={a.status} />{a.updated_by && a.status !== "open" ? <div className="muted small-text">by {a.updated_by}</div> : null}</td>
                          <td className="wrap-anywhere">{a.message}<div className="muted small-text">rule <code>{a.rule}</code></div></td>
                          <td>{a.resource_type} <code>{a.resource_id}</code></td>
                          <td title={dateTime(a.created_at)}>{ago(a.created_at)}</td>
                          <td>
                            <div className="row-actions">
                              <WriteButton permission={PERM.alerts} className="small" disabled={m.busy} onClick={() => void move(a, "acknowledge")}>Acknowledge</WriteButton>
                              <WriteButton permission={PERM.alerts} className="small" disabled={m.busy} onClick={() => void move(a, "resolve")}>Resolve</WriteButton>
                              <WriteButton permission={PERM.alerts} className="small danger-soft" onClick={() => setDeleting(a)}>Delete</WriteButton>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Pager total={d.total} limit={d.limit} offset={d.offset} onChange={setOffset} noun="alerts" />
            </>
          )}
        </Async>
      </Card>
      {deleting && (
        <ConfirmDialog title="Delete this alert?" confirmLabel="Delete alert" danger onClose={() => setDeleting(null)}
          onConfirm={async () => { await cloudApi.deleteAlert(deleting.id); toast(`Alert ${deleting.id} deleted.`); void list.reload(); }}>
          <p>Alert {deleting.id} ({deleting.message}) will be deleted for good. Resolve it instead to keep the history.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
