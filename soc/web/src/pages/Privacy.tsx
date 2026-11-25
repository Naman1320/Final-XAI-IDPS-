import { Fragment, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, query } from "../api/client";
import type { AccessEntry, EraseResult, ErasePreview, ErasureRecord, Page, PrivacyNotice } from "../api/types";
import { useAuth } from "../auth";
import { Card, ErrorText, PageHead, useAction, useLoad } from "../components/common";
import { dateTime, label } from "../format";

const RETENTION_LABELS: Record<string, string> = {
  alerts_days: "Alerts",
  audit_log_days: "Audit log",
  access_log_days: "Access log",
  assistant_conversations_days: "Assistant conversations",
  closed_cases_days: "Closed cases",
  would_block_records_days: "Dry-run block records",
  blocks_and_actions: "Blocks and actions",
};

/** "180 days", "kept until deleted" for 0. */
export function days(value: unknown): string {
  if (typeof value !== "number") return String(value ?? "—");
  return value === 0 ? "kept until deleted" : `${value} day${value === 1 ? "" : "s"}`;
}

export function capitalise(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

/** A count key ("case_notes.text") as words. */
export function countLabel(key: string): string {
  return key.replace(/^memory\./, "in memory: ").replace(/[._]/g, " ");
}

export function Notice() {
  const { data, error } = useLoad(() => api<PrivacyNotice>("/privacy/notice"), []);
  if (error) return <Card title="Privacy notice"><ErrorText error={error} /></Card>;
  if (!data) return <Card title="Privacy notice"><p className="muted">Loading…</p></Card>;
  const c = data.controller;
  const retention = Object.entries(data.retention).filter(([k]) => k in RETENTION_LABELS);
  return (
    <Card title="Privacy notice">
      <div className="privacy-notice">
        <section>
          <h3>Who is responsible</h3>
          {c.name || c.contact_email || c.grievance_officer ? (
            <dl className="kv">
              {c.name && <><dt>Data fiduciary</dt><dd>{c.name}</dd></>}
              {c.contact_email && <><dt>Contact</dt><dd>{c.contact_email}</dd></>}
              {c.grievance_officer && <><dt>Grievance officer</dt><dd>{c.grievance_officer}</dd></>}
            </dl>
          ) : <p className="muted">The organisation running this SOC has not published its contact details here yet.</p>}
        </section>
        <section>
          <h3>What is processed</h3>
          <ul>{data.data_categories.map((d) => <li key={d.category}><b>{d.category}</b>: {d.description}</li>)}</ul>
        </section>
        <section>
          <h3>Why</h3>
          <ul>{data.purposes.map((p) => <li key={p}>{p}</li>)}</ul>
        </section>
        <section>
          <h3>How long it is kept</h3>
          <dl className="kv">
            {retention.map(([k, v]) => <Fragment key={k}><dt>{RETENTION_LABELS[k]}</dt><dd>{days(v)}</dd></Fragment>)}
          </dl>
          {data.retention.alerts_kept_if_judged_for_training === true && (
            <p className="muted small-text">Alerts an analyst has judged are kept longer as training data for the model.</p>
          )}
          {typeof data.retention.note === "string" && <p className="muted small-text">{data.retention.note}</p>}
        </section>
        <section>
          <h3>Who else receives it</h3>
          {data.recipients.length
            ? <ul>{data.recipients.map((r) => <li key={r.name}><b>{r.name}</b>: {r.description}</li>)}</ul>
            : <p className="muted">No one: no outside service is configured.</p>}
        </section>
        <section>
          <h3>Your rights</h3>
          <ul>{data.rights.map((r) => <li key={r.right}><b>{capitalise(label(r.right))}</b>: {r.description}</li>)}</ul>
          <p>{data.how_to_exercise}</p>
        </section>
        <p className="muted small-text">{data.note}</p>
      </div>
    </Card>
  );
}

/** Erase one address everywhere: preview the counts, give a reason, type the address again. */
function Erase({ onErased }: { onErased: () => void }) {
  const act = useAction();
  const [ip, setIp] = useState("");
  const [preview, setPreview] = useState<ErasePreview | null>(null);
  const [reason, setReason] = useState("");
  const [confirmIp, setConfirmIp] = useState("");
  const [force, setForce] = useState(false);
  const [done, setDone] = useState<EraseResult | null>(null);

  async function check(e: FormEvent) {
    e.preventDefault();
    setDone(null);
    setPreview(null);
    const asked = ip.trim();
    const p = await act.run(() => api<ErasePreview>("/admin/privacy/erase/preview", { method: "POST", json: { ip: asked } }));
    // The input is locked while the preview loads; this also drops an answer for an older address.
    if (p && asked === ip.trim()) {
      setPreview(p);
      setConfirmIp("");
      setForce(false);
    }
  }

  async function erase(e: FormEvent) {
    e.preventDefault();
    if (!preview) return;
    const r = await act.run(() => api<EraseResult>("/admin/privacy/erase", {
      method: "POST", json: { ip: preview.ip, reason: reason.trim(), ...(force ? { force: true } : {}) } }));
    if (r) {
      setDone(r);
      setPreview(null);
      setIp("");
      setReason("");
      setConfirmIp("");
      onErased();
    }
  }

  const nonZero = (p: ErasePreview) => Object.entries(p.counts).filter(([, n]) => n > 0);
  // The SOC refuses to erase an address with an active block unless told to (its rule would stay).
  const activeBlock = (preview?.active_blocks ?? 0) > 0;
  return (
    <Card title="Erase an address">
      <p className="muted" style={{ marginTop: 0 }}>
        For an erasure request: removes one IP address from every alert, block, action, case note, assistant
        conversation and log entry, and records that an erasure happened (without the address). It cannot recall
        notifications already sent or copies in backups and SIEMs; see the notice.
      </p>
      <form onSubmit={check} className="row-actions" style={{ alignItems: "flex-end" }}>
        <label className="field" style={{ flex: "1 1 220px" }}>
          IP address
          <input value={ip} onChange={(e) => { setIp(e.target.value); setPreview(null); }} disabled={act.busy}
            placeholder="e.g. 203.0.113.7" spellCheck={false} autoComplete="off" required />
        </label>
        <button type="submit" disabled={act.busy || !ip.trim()}>{act.busy && !preview ? "Checking…" : "Preview"}</button>
      </form>
      {!preview && <ErrorText error={act.error} />}
      <div className="notice" role="status" aria-live="polite">
        {done && <>
          Erased: {done.total.toLocaleString()} rows and fields changed (record #{done.record_id}).
          {done.warnings.map((w) => <div key={w} className="warn-text">{w}</div>)}
        </>}
      </div>
      {preview && (
        <div className="erase-preview">
          {Object.entries(preview.manual_review).filter(([, n]) => n > 0).map(([k, n]) => (
            <p key={k} className="warn-text">Also in {n} {countLabel(k)}: change these by hand (they are not rewritten).</p>
          ))}
          {preview.warnings.map((w) => <p key={w} className="warn-text">{w}</p>)}
          {preview.total === 0 && nonZero(preview).length === 0 ? (
            <p>Nothing to erase automatically for <b className="mono">{preview.ip}</b>.</p>
          ) : (
            <>
              <p><b className="mono">{preview.ip}</b> appears in:</p>
              <table className="compact">
                <caption className="sr-only">Where the address appears</caption>
                <tbody>
                  {nonZero(preview).map(([k, n]) => (
                    <tr key={k}><td>{countLabel(k)}</td><td style={{ textAlign: "right" }}>{n.toLocaleString()}</td></tr>
                  ))}
                </tbody>
              </table>
              <form onSubmit={erase} className="stack">
                <label className="field">
                  Reason (recorded; do not include the address)
                  <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} required
                    placeholder="e.g. erasure request received 16 Nov by email" />
                </label>
                <ErrorText error={act.error} />
                <label className="field">
                  Type the address again to confirm
                  <input value={confirmIp} onChange={(e) => setConfirmIp(e.target.value)} spellCheck={false}
                    autoComplete="off" required />
                </label>
                {activeBlock && (
                  <label className="field inline">
                    <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
                    Erase anyway: the sensor keeps blocking this address and the SOC can no longer lift it
                    (better: unblock it on the Response page first)
                  </label>
                )}
                <div className="row-actions">
                  <button type="button" onClick={() => setPreview(null)} disabled={act.busy}>Cancel</button>
                  <button className="danger-soft" type="submit"
                    disabled={act.busy || !reason.trim() || confirmIp.trim() !== preview.ip || (activeBlock && !force)}>
                    {act.busy ? "Erasing…" : "Erase permanently"}
                  </button>
                </div>
              </form>
            </>
          )}
        </div>
      )}
    </Card>
  );
}

/** Rows and fields changed, as the erase result's `total` counts them (cancelled actions apart). */
export function changed(counts: Record<string, number>): number {
  return Object.entries(counts).reduce((a, [k, n]) => a + (k !== "actions.cancelled" && typeof n === "number" ? n : 0), 0);
}

function Erasures({ refresh }: { refresh: number }) {
  const { data, error } = useLoad(() => api<Page<ErasureRecord>>("/admin/privacy/erasures?limit=50"), [refresh]);
  const more = useAction();
  const [older, setOlder] = useState<{ items: ErasureRecord[]; cursor: string | null; base: unknown } | null>(null);
  const extra = older && older.base === data ? older : null;
  const items = [...(data?.items ?? []), ...(extra?.items ?? [])];
  const cursor = extra ? extra.cursor : data?.next_cursor ?? null;
  async function loadMore() {
    if (!cursor) return;
    const page = await more.run(() => api<Page<ErasureRecord>>(`/admin/privacy/erasures${query({ limit: 50, cursor })}`));
    if (page) setOlder({ items: [...(extra?.items ?? []), ...page.items], cursor: page.next_cursor, base: data });
  }
  return (
    <Card title="Erasures">
      <ErrorText error={error} />
      {data && items.length === 0 ? <p className="muted">None yet.</p> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>By</th><th>Reason</th><th style={{ textAlign: "right" }}>Changed</th></tr></thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td>{dateTime(r.at)}</td>
                  <td>{r.requested_by}</td>
                  <td className="wrap-anywhere">{r.reason}</td>
                  <td style={{ textAlign: "right" }}>
                    {changed(r.counts).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ErrorText error={more.error} />
      {cursor && <button className="small" disabled={more.busy} onClick={() => void loadMore()}>
        {more.busy ? "Loading…" : "Load older erasures"}</button>}
    </Card>
  );
}

/** Who read personal data: filter by address (fingerprinted by the SOC), user or action. */
function AccessLog() {
  const act = useAction();
  const [filters, setFilters] = useState({ ip: "", username: "" });
  const [applied, setApplied] = useState({ ip: "", username: "" });
  const [items, setItems] = useState<AccessEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);

  async function load(f: typeof applied, after: string | null) {
    if (!after) { // a new search: never mix its pages with the previous results
      setItems(null);
      setCursor(null);
    }
    const page = await act.run(() => api<Page<AccessEntry>>(
      `/admin/privacy/access-log${query({ ip: f.ip.trim(), username: f.username.trim(), limit: 100, cursor: after })}`));
    if (page) {
      setApplied(f);
      setItems((old) => (after && old ? [...old, ...page.items] : page.items));
      setCursor(page.next_cursor);
    }
  }

  function search(e: FormEvent) {
    e.preventDefault();
    void load(filters, null);
  }

  return (
    <Card title="Access log">
      <p className="muted" style={{ marginTop: 0 }}>
        Every view of personal data (alert details, searches by address, reputation lookups, case views,
        exports and report downloads). Addresses are stored only as fingerprints: search by address to answer
        "who has looked at my data?".
      </p>
      <form onSubmit={search} className="row-actions" style={{ alignItems: "flex-end" }}>
        <label className="field" style={{ flex: "1 1 180px" }}>
          IP address
          <input value={filters.ip} onChange={(e) => setFilters({ ...filters, ip: e.target.value })} spellCheck={false} />
        </label>
        <label className="field" style={{ flex: "1 1 140px" }}>
          User
          <input value={filters.username} onChange={(e) => setFilters({ ...filters, username: e.target.value })} />
        </label>
        <button type="submit" disabled={act.busy}>{act.busy && !items ? "Searching…" : "Search"}</button>
      </form>
      <ErrorText error={act.error} />
      {items && (items.length === 0 ? <p className="muted">No matching entries.</p> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>User</th><th>What</th><th>Target</th></tr></thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td>{dateTime(a.at)}</td>
                  <td>{a.username}</td>
                  <td>{label(a.action)}</td>
                  <td className="mono small-text wrap-anywhere">{[a.target_type, a.target].filter(Boolean).join(" ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {cursor && <button className="small" disabled={act.busy} onClick={() => void load(applied, cursor)}>
        {act.busy ? "Loading…" : "Load older entries"}</button>}
    </Card>
  );
}

/** The notice without signing in: the people whose addresses appear in the data have no account. */
export function PublicPrivacy() {
  return (
    <main className="public-page">
      <h1 className="public-head">IDPS SOC privacy notice · <Link to="/">Sign in</Link></h1>
      <Notice />
    </main>
  );
}

/** Privacy: the notice for everyone; erasure, erasure records and the access log for admins. */
export default function Privacy() {
  const { me } = useAuth();
  const [refresh, setRefresh] = useState(0);
  return (
    <>
      <PageHead title="Privacy" />
      <Notice />
      {me?.role === "admin" && (
        <>
          <Erase onErased={() => setRefresh((n) => n + 1)} />
          <Erasures refresh={refresh} />
          <AccessLog />
        </>
      )}
    </>
  );
}
