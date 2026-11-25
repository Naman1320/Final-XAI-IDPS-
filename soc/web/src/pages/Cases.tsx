import { useCallback, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, query } from "../api/client";
import { CASE_STATUSES, type CaseDetail, type CaseStatus, type CaseSummary, type Page } from "../api/types";
import { ErrorText, PageHead, Pill, Segmented, useAction, useLoad, type Tone } from "../components/common";
import { dateTime } from "../format";
import CasePanel from "./CaseDetail";

/** Cases: the list and the open case side by side (wireframe screen 5). `/cases/:id` opens one. */

const TONE: Record<CaseStatus, Tone> = { open: "neutral", investigating: "warn", closed: "ok" };

export default function Cases() {
  const { id: rawId } = useParams();
  // Only numeric ids reach the API path (a crafted link like /cases/..%2Fadmin must not).
  const selected = rawId === undefined ? null : /^\d{1,18}$/.test(rawId) ? rawId : "0";
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [filter, setFilter] = useState<CaseStatus>("open");
  const [title, setTitle] = useState("");
  // Each status is fetched on its own (newest 200 each), so an old open case never drops out
  // behind newer closed ones.
  const open = useLoad(() => api<Page<CaseSummary>>(`/cases${query({ status: "open", limit: 200 })}`), []);
  const investigating = useLoad(
    () => api<Page<CaseSummary>>(`/cases${query({ status: "investigating", limit: 200 })}`), []);
  const closed = useLoad(() => api<Page<CaseSummary>>(`/cases${query({ status: "closed", limit: 200 })}`), []);
  const lists = { open, investigating, closed };
  const act = useAction();
  const listRef = useRef<HTMLElement>(null);

  const reloadOpen = open.reload;
  const reloadInvestigating = investigating.reload;
  const reloadClosed = closed.reload;
  const reloadAll = useCallback(() => {
    void reloadOpen();
    void reloadInvestigating();
    void reloadClosed();
  }, [reloadOpen, reloadInvestigating, reloadClosed]);

  const current = lists[filter];
  const shown = current.data?.items ?? [];
  const countOf = (s: CaseStatus) => {
    const d = lists[s].data;
    if (!d) return "…";
    return d.next_cursor ? `${d.items.length}+` : String(d.items.length);
  };

  // The open case reports itself on every load: follow its status, and refresh the lists when
  // they disagree with it (changed by someone else, or an alert added from an alert's page).
  const allItems = [...(open.data?.items ?? []), ...(investigating.data?.items ?? []), ...(closed.data?.items ?? [])];
  const itemsRef = useRef(allItems);
  itemsRef.current = allItems;
  const lastStatus = useRef<{ id: number; status: CaseStatus } | null>(null);
  const onLoaded = useCallback((c: CaseDetail) => {
    const prev = lastStatus.current;
    if (!prev || prev.id !== c.id || prev.status !== c.status) setFilter(c.status);
    lastStatus.current = { id: c.id, status: c.status };
    const item = itemsRef.current.find((i) => i.id === c.id);
    const stale = !item || item.status !== c.status || item.updated_at !== c.updated_at
      || item.alert_count !== c.alerts.length;
    if (stale) reloadAll();
  }, [reloadAll]);

  async function create(e: FormEvent) {
    e.preventDefault();
    const t = title.trim();
    if (!t) return;
    const c = await act.run(() => api<CaseDetail>("/cases", { method: "POST", json: { title: t, alert_ids: [] } }));
    if (c) {
      setTitle("");
      setFilter(c.status);
      reloadAll();
      navigate(`/cases/${c.id}`);
    }
  }

  return (
    <>
      <PageHead title="Cases" />
      <section className="card" aria-labelledby="new-case-heading">
        <h2 id="new-case-heading">New case</h2>
        <form className="row-actions" style={{ alignItems: "flex-end" }} onSubmit={create}>
          <label className="field">New case title
            <input autoFocus={params.get("new") === "1"} required value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Port scan from 10.10.1.10" style={{ width: 280, maxWidth: "100%" }} />
          </label>
          <button className="primary" type="submit" disabled={!title.trim() || act.busy}>Create case</button>
        </form>
        <ErrorText error={act.error} />
      </section>

      <div className="grid cols-list-detail">
        <section ref={listRef} tabIndex={-1} className="card stack" aria-label="Case list" style={{ gap: 10, padding: 16 }}>
          <Segmented<CaseStatus> label="Filter cases" value={filter} onChange={setFilter}
            options={CASE_STATUSES.map((s) => ({ value: s, label: `${s[0].toUpperCase()}${s.slice(1)} · ${countOf(s)}` }))} />
          <ErrorText error={current.error} />
          <ul className="case-list">
            {shown.map((c) => (
              <li key={c.id}>
                <Link to={`/cases/${c.id}`} className={`case-item${String(c.id) === selected ? " selected" : ""}`}
                  aria-current={String(c.id) === selected ? "page" : undefined}>
                  <span className="case-item-head">
                    <b className="wrap-anywhere">{c.title}</b>
                    <Pill tone={TONE[c.status]}>{c.status}</Pill>
                  </span>
                  <span className="muted small-text">
                    #{c.id} · {c.alert_count} alert{c.alert_count === 1 ? "" : "s"} · updated {dateTime(c.updated_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          {current.data && shown.length === 0 && <p className="muted" style={{ margin: 0 }}>No {filter} cases.</p>}
          {current.data?.next_cursor && (
            <p className="muted small-text" style={{ margin: 0 }}>Showing the newest 200 {filter} cases.</p>
          )}
        </section>

        {selected ? (
          <CasePanel key={selected} id={selected} onLoaded={onLoaded}
            onDeleted={() => {
              reloadAll();
              lastStatus.current = null;
              // Replace, so Back doesn't return to the deleted case; focus goes back to the list.
              navigate("/cases", { replace: true });
              listRef.current?.focus();
            }} />
        ) : (
          <section className="card" aria-label="Case detail">
            <p className="muted" style={{ margin: 0 }}>
              Choose a case to see its alerts and notes, or open a new one. Alerts are added to a case from the alert's page.
            </p>
          </section>
        )}
      </div>
    </>
  );
}
