import {
  createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode,
} from "react";
import { ApiError } from "../../api/client";
import { useAuth } from "../../auth";
import { Pill, type Tone } from "../common";
import { label as spaced } from "../../format";
import type { HealthStatus } from "../../api/cloudTypes";
import "../../pages/cloud/cloud.css";

// ---- permissions and the data source ---------------------------------------------------------

export const PERM = {
  view: "cloud.view",
  instances: "cloud.instances.write",
  storage: "cloud.storage.write",
  network: "cloud.network.write",
  alerts: "cloud.alerts.manage",
} as const;

export interface SourceInfo { source: string; label: string }
interface CloudCtx { info: SourceInfo | null; setInfo: (i: SourceInfo) => void }
const Ctx = createContext<CloudCtx>({ info: null, setInfo: () => undefined });
export const CloudContextProvider = Ctx.Provider;

export function useSourceState(): CloudCtx {
  const [info, setInfoState] = useState<SourceInfo | null>(null);
  const setInfo = useCallback((i: SourceInfo) => {
    setInfoState((old) => (old && old.source === i.source && old.label === i.label ? old : i));
  }, []);
  return useMemo(() => ({ info, setInfo }), [info, setInfo]);
}

/** UI hint only (the backend enforces every permission): a user whose permission list is missing
 *  (an older SOC) is not blocked here. Anything but the mock inventory is read-only. */
export function useWriteAccess(permission: string): { allowed: boolean; reason: string | undefined } {
  const { me, can } = useAuth();
  const { info } = useContext(Ctx);
  const hasPerm = me?.permissions === undefined ? true : can(permission);
  if (!hasPerm) return { allowed: false, reason: `Needs the ${permission} permission` };
  if (info && info.source !== "mock") return { allowed: false, reason: "Read-only: this data source cannot be changed" };
  return { allowed: true, reason: undefined };
}

/** Shows what the API says the data is. The mock label is a warning, never hidden. */
export function DataSourceBanner() {
  const { info } = useContext(Ctx);
  if (!info) return <div className="cl-banner pending" role="status">Checking the data source…</div>;
  const mock = info.source === "mock";
  return (
    <div className={`cl-banner ${mock ? "mock" : "live"}`} role="status" data-source={info.source}>
      <strong><span aria-hidden="true">{mock ? "⚠ " : "ℹ "}</span>{info.label}</strong>
      <span className="small-text">
        {mock
          ? "Figures are invented demo data. Changes are saved to the mock inventory only; nothing in a real cloud is touched."
          : "Read-only: this view reads a local emulator, and changes are not possible."}
      </span>
    </div>
  );
}

// ---- loading and errors --------------------------------------------------------------------------

export function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) return `No permission: ${err.message}`;
    if (err.status === 429) return `${err.message} (too many changes; wait a minute)`;
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

export function useCloudLoad<T>(load: () => Promise<T>, deps: unknown[], opts: { pollMs?: number; poll?: (d: T) => boolean } = {}) {
  const { setInfo } = useContext(Ctx);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  const reload = useCallback(async (silent = false) => {
    const mine = ++seq.current;
    if (!silent) setLoading(true);
    try {
      const result = await loadRef.current();
      if (mine !== seq.current) return;
      setData(result);
      setError(null);
      const r = result as { data_source?: unknown; data_source_label?: unknown } | null;
      if (r && typeof r.data_source === "string" && typeof r.data_source_label === "string") {
        setInfo({ source: r.data_source, label: r.data_source_label });
      }
    } catch (err) {
      if (mine === seq.current) setError(err);
    } finally {
      if (mine === seq.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setInfo, ...deps]);

  useEffect(() => { void reload(); return () => { seq.current++; }; }, [reload]);

  const polling = Boolean(opts.pollMs && data && opts.poll?.(data));
  useEffect(() => {
    if (!polling || !opts.pollMs) return;
    const id = setInterval(() => void reload(true), opts.pollMs);
    return () => clearInterval(id);
  }, [polling, opts.pollMs, reload]);

  return { data, error, loading, reload: () => reload(), setData };
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <p className="muted cl-loading" role="status" aria-live="polite"><span className="cl-spinner" aria-hidden="true" /> {what}…</p>;
}

/** A failed read. 403 is its own state (the account lacks the permission); the rest show the
 *  backend's detail with a retry. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const status = error instanceof ApiError ? error.status : 0;
  const detail = error instanceof Error ? error.message : String(error);
  if (status === 403) {
    return (
      <div className="cl-denied" role="alert">
        <h2>No permission</h2>
        <p className="muted small-text">{detail}</p>
      </div>
    );
  }
  return (
    <div className="cl-error-state" role="alert">
      <p className="error" style={{ margin: 0 }}>{status === 503 ? `The cloud data source is unavailable: ${detail}` : detail}</p>
      {onRetry && <button type="button" className="small" onClick={onRetry}>Retry</button>}
    </div>
  );
}

/** Loading / error / content for a page section. Keeps showing older data while it reloads. */
export function Async<T>({ state, what, children }: {
  state: { data: T | null; error: unknown; loading: boolean; reload: () => void };
  what?: string; children: (data: T) => ReactNode;
}) {
  if (state.error && !state.data) return <ErrorState error={state.error} onRetry={state.reload} />;
  if (!state.data) return <Loading what={what} />;
  return (
    <div aria-busy={state.loading} className={state.loading ? "cl-refreshing" : undefined}>
      {state.error ? <ErrorState error={state.error} onRetry={state.reload} /> : null}
      {children(state.data)}
    </div>
  );
}

// ---- toasts ----------------------------------------------------------------------------------------

interface ToastItem { id: number; text: string; tone: "ok" | "error" }
const ToastCtx = createContext<(text: string, tone?: "ok" | "error") => void>(() => undefined);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(1);
  const push = useCallback((text: string, tone: "ok" | "error" = "ok") => {
    const id = next.current++;
    setItems((l) => [...l.slice(-3), { id, text, tone }]);
  }, []);
  const dismiss = (id: number) => setItems((l) => l.filter((t) => t.id !== id));
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="cl-toasts" aria-label="Messages">
        {items.map((t) => <Toast key={t.id} item={t} onDone={() => dismiss(t.id)} />)}
      </div>
    </ToastCtx.Provider>
  );
}

function Toast({ item, onDone }: { item: ToastItem; onDone: () => void }) {
  useEffect(() => {
    const id = setTimeout(onDone, item.tone === "error" ? 10_000 : 5000);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div className={`cl-toast ${item.tone}`} role={item.tone === "error" ? "alert" : "status"}>
      <span>{item.text}</span>
      <button type="button" className="link-button" onClick={onDone} aria-label="Dismiss message">Dismiss</button>
    </div>
  );
}

/** Run a change: busy flag, inline error text, success toast. Resolves to undefined on failure. */
export function useMutation() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>, ok?: string | ((r: T) => string),
    opts: { toastError?: boolean } = {}): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      const r = await fn();
      if (ok) toast(typeof ok === "function" ? ok(r) : ok);
      return r;
    } catch (err) {
      const msg = describeError(err);
      if (opts.toastError) toast(msg, "error");
      else setError(msg);
      return undefined;
    } finally {
      setBusy(false);
    }
  }, [toast]);
  return { busy, error, run, setError };
}

// ---- dialogs -----------------------------------------------------------------------------------------

const FOCUSABLE = 'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';

/** A modal dialog: focus moves in, Tab stays inside, Escape and the backdrop close it, and focus
 *  returns to what opened it. */
export function Modal({ title, onClose, children, wide = false }: {
  title: string; onClose: () => void; children: ReactNode; wide?: boolean;
}) {
  const titleId = useId();
  const box = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    const first = box.current?.querySelector<HTMLElement>("[data-autofocus], input, select, textarea") ??
      box.current?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    return () => before?.focus?.();
  }, []);
  const onKeyDown = (ev: React.KeyboardEvent) => {
    if (ev.key === "Escape") { ev.stopPropagation(); closeRef.current(); return; }
    if (ev.key !== "Tab" || !box.current) return;
    const items = [...box.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    if (!items.length) return;
    const a = items[0], z = items[items.length - 1];
    if (ev.shiftKey && document.activeElement === a) { ev.preventDefault(); z.focus(); }
    else if (!ev.shiftKey && document.activeElement === z) { ev.preventDefault(); a.focus(); }
  };
  return (
    <div className="cl-backdrop" onMouseDown={(ev) => { if (ev.target === ev.currentTarget) onClose(); }}>
      <div ref={box} className={`cl-modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-labelledby={titleId} onKeyDown={onKeyDown}>
        <h2 id={titleId}>{title}</h2>
        {children}
      </div>
    </div>
  );
}

/** Ask first. `onConfirm` does the call and throws on failure: the backend's message is shown in
 *  the dialog, which then stays open so the user can read it. */
export function ConfirmDialog({ title, children, confirmLabel, danger = false, onConfirm, onClose, requireText }: {
  title: string; children: ReactNode; confirmLabel: string; danger?: boolean;
  onConfirm: () => Promise<unknown>; onClose: () => void;
  /** The user must type this to enable the button (for the most destructive actions). */
  requireText?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const mounted = useRef(true);
  useEffect(() => () => { mounted.current = false; }, []);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      if (mounted.current) setError(describeError(err));
    } finally {
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <Modal title={title} onClose={() => { if (!busy) onClose(); }}>
      <div className="cl-modal-body">{children}</div>
      {requireText && (
        <label className="field">Type <code>{requireText}</code> to confirm
          <input value={typed} onChange={(ev) => setTyped(ev.target.value)} autoComplete="off" />
        </label>
      )}
      {error && <div className="error" role="alert">{error}</div>}
      <div className="row-actions cl-modal-actions">
        <button type="button" onClick={onClose} disabled={busy} data-autofocus={danger ? "" : undefined}>Cancel</button>
        <button type="button" className={danger ? "danger" : "primary"} onClick={() => void go()}
          disabled={busy || (requireText !== undefined && typed !== requireText)}>
          {busy ? "Working…" : confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

// ---- small display pieces --------------------------------------------------------------------------

const STATE_TONE: Record<string, { tone: Tone; mark: string }> = {
  running: { tone: "ok", mark: "●" },
  stopped: { tone: "neutral", mark: "■" },
  pending: { tone: "warn", mark: "◐" },
  terminated: { tone: "danger", mark: "✕" },
  available: { tone: "ok", mark: "○" },
  "in-use": { tone: "accent", mark: "●" },
};
/** A state with a symbol and its name in text (never colour alone). */
export function StatePill({ state }: { state: string }) {
  const s = STATE_TONE[state] ?? { tone: "neutral" as Tone, mark: "•" };
  return <Pill tone={s.tone}><span aria-hidden="true">{s.mark}</span> {spaced(state)}</Pill>;
}

const HEALTH_TONE: Record<HealthStatus, { tone: Tone; mark: string }> = {
  healthy: { tone: "ok", mark: "✓" },
  degraded: { tone: "warn", mark: "!" },
  critical: { tone: "danger", mark: "✕" },
  unknown: { tone: "neutral", mark: "?" },
};
export function HealthPill({ status }: { status: string }) {
  const s = HEALTH_TONE[status as HealthStatus] ?? HEALTH_TONE.unknown;
  return <Pill tone={s.tone}><span aria-hidden="true">{s.mark}</span> {status}</Pill>;
}

const SEV: Record<string, { tone: Tone; mark: string }> = {
  critical: { tone: "danger", mark: "✕" }, warning: { tone: "warn", mark: "!" }, info: { tone: "accent", mark: "i" },
};
export function AlertSeverityPill({ severity }: { severity: string }) {
  const s = SEV[severity] ?? { tone: "neutral" as Tone, mark: "•" };
  return <Pill tone={s.tone}><span aria-hidden="true">{s.mark}</span> {severity}</Pill>;
}
export function AlertStatusPill({ status }: { status: string }) {
  const tone: Tone = status === "open" ? "danger" : status === "acknowledged" ? "warn" : "ok";
  return <Pill tone={tone}>{status}</Pill>;
}

export function Pager({ total, limit, offset, onChange, noun = "items" }: {
  total: number; limit: number; offset: number; onChange: (offset: number) => void; noun?: string;
}) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <nav className="cl-pager" aria-label={`${noun} pages`}>
      <span className="muted" aria-live="polite">{from}–{to} of {total} {noun}</span>
      <div className="row-actions">
        <button type="button" className="small" disabled={offset <= 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
        <button type="button" className="small" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
      </div>
    </nav>
  );
}

/** Disabled-with-a-reason wrapper for a write button. */
export function WriteButton({ permission, children, className, onClick, disabled, type = "button", title }: {
  permission: string; children: ReactNode; className?: string; onClick?: () => void; disabled?: boolean;
  type?: "button" | "submit"; title?: string;
}) {
  const { allowed, reason } = useWriteAccess(permission);
  return (
    <button type={type} className={className} onClick={onClick} disabled={!allowed || disabled}
      title={!allowed ? reason : title} aria-disabled={!allowed || disabled ? true : undefined}>
      {children}
    </button>
  );
}

export const money = (x: number | null | undefined, currency = "USD") =>
  x === null || x === undefined ? "—" : new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: 2 }).format(x);
export const pct = (x: number | null | undefined, digits = 1) => (x === null || x === undefined ? "—" : `${x.toFixed(digits)}%`);

/** Relative time: "3 min ago". */
export function ago(iso: string, now = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
