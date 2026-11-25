// Small UI helpers for the IAM module: data loading with typed errors, modal and confirm dialogs,
// toasts, skeletons, paging and checklists. Kept here so the shared components stay untouched.
import {
  createContext, useCallback, useContext, useEffect, useId, useRef, useState, type FormEvent, type ReactNode,
} from "react";
import { ApiError } from "../../api/client";
import type { IamPage, PermissionGroup } from "../../api/iamTypes";
import { useAuth } from "../../auth";
import "../../pages/iam/iam.css";

// --- permissions ---------------------------------------------------------------------------

/** UI hint only (the backend enforces). When the SOC does not send `permissions` we cannot know, so we allow. */
export function useCan(): (permission: string) => boolean {
  const { me } = useAuth();
  return useCallback((p: string) => (me?.permissions ? me.permissions.includes(p) : true), [me]);
}

// --- errors --------------------------------------------------------------------------------

export function errorText(err: unknown): string {
  if (err instanceof ApiError && err.status === 403) return `You don't have permission for that: ${err.message}`;
  if (err instanceof ApiError && err.status === 429) return `Too many changes in a short time: ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

export function isForbidden(err: unknown): boolean {
  return err instanceof ApiError && err.status === 403;
}

// --- loading -------------------------------------------------------------------------------

export interface Query<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Load data (again whenever `deps` change), keeping the error object so a 403 can be told apart. */
export function useQuery<T>(load: () => Promise<T>, deps: unknown[], enabled = true): Query<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(enabled);
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const mine = ++seq.current;
    if (!enabled) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const result = await load();
      if (mine === seq.current) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (mine === seq.current) setError(err);
    } finally {
      if (mine === seq.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps]);

  useEffect(() => {
    void reload();
    return () => { seq.current++; };
  }, [reload]);

  return { data, error, loading, reload };
}

export function Skeleton({ lines = 4, label = "Loading" }: { lines?: number; label?: string }) {
  return (
    <div className="iam-skeleton" role="status" aria-busy="true" aria-label={label}>
      {Array.from({ length: lines }, (_, i) => <span key={i} className="iam-skel-line" style={{ width: `${95 - ((i * 13) % 40)}%` }} />)}
    </div>
  );
}

export function Forbidden({ detail, what = "this" }: { detail?: string; what?: string }) {
  return (
    <div className="iam-forbidden" role="alert">
      <b>You don't have permission to view {what}.</b>
      <span className="muted">Ask an administrator for access. {detail ?? ""}</span>
    </div>
  );
}

/** Skeleton while the first load runs, a clear 403 state, or an error with a retry; otherwise the content. */
export function QueryState<T>({ q, what, lines, children }: {
  q: Query<T>; what?: string; lines?: number; children: (data: T) => ReactNode;
}) {
  if (q.data === null) {
    if (q.error) {
      if (isForbidden(q.error)) return <Forbidden what={what} detail={(q.error as Error).message} />;
      return (
        <div className="error" role="alert">
          {errorText(q.error)} <button className="small" onClick={() => void q.reload()}>Retry</button>
        </div>
      );
    }
    return <Skeleton lines={lines} label={`Loading ${what ?? ""}`.trim()} />;
  }
  return (
    <>
      {q.error != null && (
        <div className="error" role="alert">
          {errorText(q.error)} <button className="small" onClick={() => void q.reload()}>Retry</button>
        </div>
      )}
      <div aria-busy={q.loading}>{children(q.data)}</div>
    </>
  );
}

// --- paging (cursor based, newest first) ---------------------------------------------------

export function usePaged<T>(fetchPage: (cursor?: number) => Promise<IamPage<T>>, key: string, enabled = true) {
  const [nav, setNav] = useState<{ key: string; stack: number[] }>({ key, stack: [] });
  const stack = nav.key === key ? nav.stack : [];
  const cursor = stack.length ? stack[stack.length - 1] : undefined;
  const q = useQuery(() => fetchPage(cursor), [key, cursor], enabled);
  const next = q.data?.next_cursor ?? null;
  const go = {
    next: () => { if (next != null) setNav({ key, stack: [...stack, next] }); },
    prev: () => setNav({ key, stack: stack.slice(0, -1) }),
  };
  // Deleting the last row of a later page leaves it empty: step back.
  const empty = q.data !== null && q.data.items.length === 0 && !q.loading;
  useEffect(() => {
    if (empty && stack.length > 0) setNav({ key, stack: stack.slice(0, -1) });
  }, [empty, key, stack]);
  return { q, page: stack.length + 1, hasPrev: stack.length > 0, hasNext: next != null, ...go };
}

export function Pager({ page, hasPrev, hasNext, onPrev, onNext, busy }: {
  page: number; hasPrev: boolean; hasNext: boolean; onPrev: () => void; onNext: () => void; busy?: boolean;
}) {
  if (!hasPrev && !hasNext) return null;
  return (
    <nav className="iam-pager" aria-label="Pagination">
      <button className="small" onClick={onPrev} disabled={!hasPrev || busy}>Previous</button>
      <span aria-live="polite">Page {page}</span>
      <button className="small" onClick={onNext} disabled={!hasNext || busy}>Next</button>
    </nav>
  );
}

// --- toasts --------------------------------------------------------------------------------

interface Toast { id: number; text: string; tone: "ok" | "danger" }
const ToastContext = createContext<((text: string, tone?: Toast["tone"]) => void) | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const push = useCallback((text: string, tone: Toast["tone"] = "ok") => {
    const id = ++counter.current;
    setToasts((t) => [...t.slice(-3), { id, text, tone }]);
    setTimeout(() => dismiss(id), 6000);
  }, [dismiss]);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="iam-toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`iam-toast ${t.tone}`}>
            <span aria-hidden="true">{t.tone === "ok" ? "✓" : "!"}</span>
            <span>{t.text}</span>
            <button className="link-button" aria-label="Dismiss notification" onClick={() => dismiss(t.id)}>×</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): (text: string, tone?: Toast["tone"]) => void {
  return useContext(ToastContext) ?? (() => undefined);
}

// --- dialogs -------------------------------------------------------------------------------

const FOCUSABLE = 'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';

/** A modal dialog: focus moves in, Tab stays inside, Escape closes, focus returns to what opened it. */
export function Modal({ title, onClose, children, wide = false, busy = false }: {
  title: string; onClose: () => void; children: ReactNode; wide?: boolean; busy?: boolean;
}) {
  const titleId = useId();
  const box = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const busyRef = useRef(busy);
  busyRef.current = busy;

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const el = box.current;
    const first = el?.querySelector<HTMLElement>("[data-autofocus], input:not(:disabled), select:not(:disabled), textarea:not(:disabled)")
      ?? el?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? el)?.focus();
    return () => { if (opener && document.contains(opener)) opener.focus(); };
  }, []);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation();
      if (!busyRef.current) closeRef.current();
      return;
    }
    if (e.key !== "Tab" || !box.current) return;
    const items = Array.from(box.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (!items.length) return;
    const firstEl = items[0];
    const lastEl = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === firstEl || document.activeElement === box.current)) {
      e.preventDefault();
      lastEl.focus();
    } else if (!e.shiftKey && document.activeElement === lastEl) {
      e.preventDefault();
      firstEl.focus();
    }
  }

  return (
    <div className="iam-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
      <div ref={box} className={`iam-modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-labelledby={titleId}
        tabIndex={-1} onKeyDown={onKeyDown}>
        <div className="iam-modal-head">
          <h2 id={titleId}>{title}</h2>
          <button className="small" type="button" onClick={onClose} disabled={busy} aria-label="Close dialog">×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

/** Confirm a destructive action. With `confirmText` the button stays off until that exact text is typed. */
export function ConfirmDialog({ title, children, confirmLabel, confirmText, onConfirm, onClose, danger = true }: {
  title: string; children: ReactNode; confirmLabel: string; confirmText?: string;
  onConfirm: () => Promise<unknown>; onClose: () => void; danger?: boolean;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const ok = confirmText === undefined || typed === confirmText;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <Modal title={title} onClose={onClose} busy={busy}>
      <form onSubmit={submit} className="iam-form">
        <div>{children}</div>
        {confirmText !== undefined && (
          <div className="field-block">
            <label htmlFor={inputId} className="field">
              Type <code>{confirmText}</code> to confirm
              <input id={inputId} value={typed} autoComplete="off" spellCheck={false} data-autofocus
                onChange={(e) => setTyped(e.target.value)} />
            </label>
          </div>
        )}
        {error && <div className="error" role="alert">{error}</div>}
        <div className="iam-modal-foot">
          <button type="button" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className={danger ? "danger" : "primary"} disabled={!ok || busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// --- form pieces ---------------------------------------------------------------------------

/** A labelled control with its hint and error outside the label, so the accessible name stays short. */
export function Field({ label, error, hint, children }: {
  label: ReactNode; error?: string | null; hint?: ReactNode;
  children: (props: { id: string; "aria-describedby": string | undefined; "aria-invalid": boolean }) => ReactNode;
}) {
  const id = useId();
  const describedBy = [hint ? `${id}-hint` : "", error ? `${id}-err` : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className="iam-field">
      <label htmlFor={id}>{label}</label>
      {children({ id, "aria-describedby": describedBy, "aria-invalid": Boolean(error) })}
      {hint && <span id={`${id}-hint`} className="iam-hint">{hint}</span>}
      <FieldError id={`${id}-err`} error={error} />
    </div>
  );
}

export function FieldError({ id, error }: { id: string; error?: string | null }) {
  return error ? <span id={id} className="iam-field-error" role="alert">{error}</span> : null;
}

export function ModalFooter({ busy, onCancel, submitLabel, disabled = false }: {
  busy: boolean; onCancel: () => void; submitLabel: string; disabled?: boolean;
}) {
  return (
    <div className="iam-modal-foot">
      <button type="button" onClick={onCancel} disabled={busy}>Cancel</button>
      <button type="submit" className="primary" disabled={busy || disabled}>{busy ? "Saving…" : submitLabel}</button>
    </div>
  );
}

export interface PickItem { id: number; label: string; hint?: string }

/** A filterable list of checkboxes (roles of a user, members of a group, ...). */
export function Checklist({ legend, items, selected, onChange, disabled = false, empty = "Nothing to choose from." }: {
  legend: string; items: PickItem[]; selected: Set<number>; onChange: (next: Set<number>) => void;
  disabled?: boolean; empty?: string;
}) {
  const [filter, setFilter] = useState("");
  const shown = items.filter((i) => i.label.toLowerCase().includes(filter.trim().toLowerCase()));
  function toggle(id: number) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange(next);
  }
  return (
    <fieldset className="iam-checklist" disabled={disabled}>
      <legend>{legend} <span className="muted">({selected.size} selected)</span></legend>
      {items.length > 6 && (
        <input type="search" aria-label={`Filter ${legend}`} placeholder="Filter…" value={filter}
          onChange={(e) => setFilter(e.target.value)} />
      )}
      {items.length === 0 ? <p className="muted small-text">{empty}</p> : (
        <ul className="iam-checks">
          {shown.map((i) => (
            <li key={i.id}>
              <label className="field inline">
                <input type="checkbox" checked={selected.has(i.id)} onChange={() => toggle(i.id)} />
                <span>{i.label}{i.hint && <span className="muted small-text"> {i.hint}</span>}</span>
              </label>
            </li>
          ))}
          {shown.length === 0 && <li className="muted small-text">No match.</li>}
        </ul>
      )}
    </fieldset>
  );
}

function GroupCheck({ group, value, onChange, readOnly, canGrant }: {
  group: PermissionGroup; value: Set<string>; onChange: (next: Set<string>) => void; readOnly: boolean;
  canGrant: (p: string) => boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const names = group.permissions.map((p) => p.name);
  const grantable = names.filter((n) => value.has(n) || canGrant(n));
  const chosen = names.filter((n) => value.has(n)).length;
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = chosen > 0 && chosen < names.length;
  }, [chosen, names.length]);
  function setAll(on: boolean) {
    const next = new Set(value);
    for (const n of on ? grantable : names) {
      if (on) next.add(n);
      else next.delete(n);
    }
    onChange(next);
  }
  return (
    <fieldset className="iam-permgroup" disabled={readOnly}>
      <legend>{group.title}</legend>
      <label className="field inline iam-selectall">
        <input ref={ref} type="checkbox" checked={chosen === names.length}
          onChange={(e) => setAll(e.target.checked)} aria-label={`Select all ${group.title} permissions`} />
        <b>Select all</b> <span className="muted small-text">{chosen} of {names.length}</span>
      </label>
      <ul className="iam-checks">
        {group.permissions.map((p) => {
          const held = value.has(p.name);
          const blocked = !held && !canGrant(p.name);
          return (
            <li key={p.name}>
              <label className="field inline">
                <input type="checkbox" checked={held} disabled={blocked}
                  onChange={(e) => {
                    const next = new Set(value);
                    if (e.target.checked) next.add(p.name);
                    else next.delete(p.name);
                    onChange(next);
                  }} />
                <span>
                  <code>{p.name}</code> <span className="muted small-text">{p.description}</span>
                  {blocked && <span className="muted small-text"> (you do not hold this permission, so you cannot grant it)</span>}
                </span>
              </label>
            </li>
          );
        })}
      </ul>
    </fieldset>
  );
}

/** The permission catalog as one checklist per group, with a select-all for each. */
export function PermissionChecklist({ groups, value, onChange, readOnly = false, canGrant = () => true }: {
  groups: PermissionGroup[]; value: Set<string>; onChange: (next: Set<string>) => void; readOnly?: boolean;
  canGrant?: (permission: string) => boolean;
}) {
  return (
    <div className="iam-permissions">
      {groups.map((g) => (
        <GroupCheck key={g.key} group={g} value={value} onChange={onChange} readOnly={readOnly} canGrant={canGrant} />
      ))}
    </div>
  );
}

// --- validation ----------------------------------------------------------------------------

const NAME_RE = /^[A-Za-z0-9 _-]+$/;
// Control and direction-override characters the backend refuses in names and descriptions.
// eslint-disable-next-line no-control-regex
const UNSAFE_RE = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/;

export function validateName(value: string): string | null {
  if (value !== value.trim()) return "Must not start or end with a space.";
  if (value.length < 3 || value.length > 48) return "Use 3 to 48 characters.";
  if (!NAME_RE.test(value)) return "Use only letters, digits, spaces, _ and -.";
  return null;
}

export function validateDescription(value: string): string | null {
  if (value.length > 255) return "At most 255 characters.";
  if (UNSAFE_RE.test(value.replace(/\n/g, " "))) return "Control or direction-override characters are not allowed.";
  return null;
}

export function validateUsername(value: string): string | null {
  if (!value) return "Enter a username.";
  if (value.length > 64) return "At most 64 characters.";
  if (!/^[A-Za-z0-9._@-]+$/.test(value)) return "Use only letters, digits and . _ @ -";
  return null;
}

export const MIN_PASSWORD = 12;
export function validatePassword(value: string): string | null {
  if (value.length < MIN_PASSWORD) return `At least ${MIN_PASSWORD} characters (${value.length} so far).`;
  if (value.length > 256) return "At most 256 characters.";
  return null;
}

export { UNSAFE_RE };

/** Split a textarea into entries on commas and new lines. */
export function splitList(text: string): string[] {
  return Array.from(new Set(text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)));
}

/** Local `datetime-local` value to an ISO time with Z, as the API needs ("" stays ""). */
export function toIsoZ(local: string): string {
  if (!local) return "";
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}
