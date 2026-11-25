import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { CASE_STATUSES, type CaseDetail as CaseDetailT, type CaseStatus, type Note } from "../api/types";
import { ConfidenceBar, ErrorText, Segmented, SeverityBadge, SourceTag, useAction, useLoad } from "../components/common";
import { dateTime, endpoint } from "../format";

/** One case: status, linked alerts and notes (the right half of the Cases screen).
 *  `onLoaded` reports the case each time it loads or changes, so the list can follow its status
 *  and refresh when it is out of date; `onDeleted` runs after the case is deleted. */
export default function CasePanel({ id, onLoaded, onDeleted }: {
  id: string; onLoaded: (c: CaseDetailT) => void; onDeleted: () => void;
}) {
  const { data: c, error, setData, reload } = useLoad(() => api<CaseDetailT>(`/cases/${id}`), [id]);
  const report = useRef(onLoaded);
  report.current = onLoaded;
  useEffect(() => { if (c) report.current(c); }, [c]);
  const act = useAction();
  const [note, setNote] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  const loaded = !!c;
  // On a phone the case sits under the whole list: bring it into view once it has loaded.
  useEffect(() => {
    if (!loaded || !window.matchMedia?.("(max-width: 1000px)").matches) return;
    heading.current?.scrollIntoView?.({ block: "start" });
    heading.current?.focus({ preventScroll: true });
  }, [loaded]);

  if (error) {
    return <section className="card" aria-label="Case detail"><ErrorText error={error} /></section>;
  }
  if (!c) return <section className="card" aria-label="Case detail"><p className="muted">Loading…</p></section>;

  async function setStatus(status: CaseStatus) {
    if (status === c!.status) return;
    const updated = await act.run(() => api<CaseDetailT>(`/cases/${id}`, { method: "PATCH", json: { status } }));
    if (updated) setData(updated);
  }

  async function addNote(e: FormEvent) {
    e.preventDefault();
    const text = note.trim();
    if (!text) return;
    const n = await act.run(() => api<Note>(`/cases/${id}/notes`, { method: "POST", json: { text } }));
    if (n) {
      setData({ ...c!, notes: [...c!.notes, n] });
      setNote("");
      void reload(); // picks up the case's new updated_at; the list follows via onLoaded
    }
  }

  async function detach(alertId: number) {
    if (!window.confirm(`Remove alert #${alertId} from case #${c!.id}? The alert itself stays.`)) return;
    const ok = await act.run(() => api(`/cases/${id}/alerts/${alertId}`, { method: "DELETE" }));
    if (ok !== undefined) void reload();
  }

  async function remove() {
    if (!window.confirm(`Delete case #${c!.id}? Its notes are deleted; its alerts stay.`)) return;
    const ok = await act.run(() => api(`/cases/${id}`, { method: "DELETE" }));
    if (ok !== undefined) onDeleted();
  }

  return (
    <section className="card stack" aria-labelledby="case-title" style={{ gap: 18 }}>
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <span className="muted small-text">Case #{c.id} · opened {dateTime(c.created_at)} · updated {dateTime(c.updated_at)}</span>
          <h2 id="case-title" ref={heading} tabIndex={-1} className="wrap-anywhere" style={{ margin: "2px 0 0", fontSize: 22 }}>{c.title}</h2>
        </div>
        <div className="row-actions" style={{ alignItems: "center" }}>
          <Segmented<CaseStatus> label="Case status" value={c.status} disabled={act.busy}
            onChange={(s) => void setStatus(s)} options={CASE_STATUSES.map((s) => ({ value: s, label: s }))} />
          <button className="danger-soft small" onClick={remove} disabled={act.busy}>Delete case</button>
        </div>
      </div>
      <ErrorText error={act.error} />

      <div>
        <h3>Linked alerts ({c.alerts.length})</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Alert</th><th>Source → target</th><th>Confidence</th><th>Received</th>
                <th><span className="sr-only">Remove</span></th></tr>
            </thead>
            <tbody>
              {c.alerts.map((a) => (
                <tr key={a.id}>
                  <td>
                    <Link to={`/alerts/${a.id}`}>#{a.id} {a.predicted_class}</Link>{" "}<SourceTag source={a.source} />{" "}
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="mono">
                    {endpoint(a.src_ip, a.src_port, a.protocol)} → {endpoint(a.dst_ip, a.dst_port, a.protocol)}
                  </td>
                  <td><ConfidenceBar value={a.confidence} /></td>
                  <td>{dateTime(a.received_at)}</td>
                  <td style={{ textAlign: "right" }}>
                    <button className="small" disabled={act.busy} onClick={() => detach(a.id)}
                      aria-label={`Remove alert ${a.id} from case`}>Remove</button>
                  </td>
                </tr>
              ))}
              {c.alerts.length === 0 && (
                <tr><td colSpan={5} className="muted">No alerts yet. Add them from an alert's page (Triage → Add to open case).</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="stack" style={{ gap: 10 }}>
        <h3 style={{ margin: 0 }}>Notes ({c.notes.length})</h3>
        {c.notes.map((n) => (
          <div key={n.id} className="note">
            <b>{n.author ?? "unknown"}</b> <span className="muted small-text">· {dateTime(n.created_at)}</span>
            <div className="wrap-anywhere" style={{ whiteSpace: "pre-wrap" }}>{n.text}</div>
          </div>
        ))}
        {c.notes.length === 0 && <p className="muted" style={{ margin: 0 }}>No notes yet.</p>}
        <form className="row-actions" style={{ alignItems: "flex-end", flexWrap: "nowrap" }} onSubmit={addNote}>
          <label className="field" style={{ flex: 1 }}>Add a note
            <textarea rows={2} value={note} maxLength={10_000} onChange={(e) => setNote(e.target.value)} />
          </label>
          <button className="primary" type="submit" disabled={!note.trim() || act.busy}>Add note</button>
        </form>
      </div>
    </section>
  );
}
