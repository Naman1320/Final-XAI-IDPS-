import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";
import type { AlertSource, Severity } from "../api/types";
import { label } from "../format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

/** Marks alerts raised by a Suricata rule; model alerts (the default) carry no mark. */
export function SourceTag({ source }: { source?: AlertSource }) {
  return source === "rule" ? <span className="pill accent source-tag" title="Raised by a Suricata rule">rule</span> : null;
}

export function StatusText({ value }: { value: string }) {
  return <span>{label(value)}</span>;
}

export function ErrorText({ error }: { error: string | null }) {
  return error ? <div className="error" role="alert">{error}</div> : null;
}

export function Card({ title, children, actions, className = "", label: ariaLabel }: {
  title?: ReactNode; children: ReactNode; actions?: ReactNode; className?: string; label?: string;
}) {
  // Named by its own heading (aria-labelledby), so the name isn't announced twice.
  const headingId = useId();
  return (
    <section className={`card ${className}`.trim()} aria-label={ariaLabel}
      aria-labelledby={!ariaLabel && title ? headingId : undefined}>
      {(title || actions) && (
        <div className="toolbar" style={{ justifyContent: "space-between", alignItems: "center" }}>
          {title && <h2 id={headingId} style={{ margin: 0 }}>{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/** Page title row: heading on the left, controls on the right (wrapping on phones). */
export function PageHead({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <div className="page-head">
      <h1>{title}</h1>
      {children && <div className="row-actions" style={{ alignItems: "flex-end" }}>{children}</div>}
    </div>
  );
}

export type Tone = "neutral" | "ok" | "warn" | "danger" | "accent";

export function Pill({ tone = "neutral", round = false, dot = false, children }: {
  tone?: Tone; round?: boolean; dot?: boolean; children: ReactNode;
}) {
  return (
    <span className={`pill ${tone}${round ? " round" : ""}`}>
      {dot && <span className="dot" aria-hidden="true" />}
      {children}
    </span>
  );
}

/** A row of toggle buttons; exactly one is pressed. */
export function Segmented<T extends string>({ label: groupLabel, options, value, onChange, disabled = false }: {
  label: string; options: { value: T; label: ReactNode }[]; value: T; onChange: (v: T) => void; disabled?: boolean;
}) {
  return (
    <div className="segmented" role="group" aria-label={groupLabel}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} disabled={disabled}
          onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** A 0..1 value as a short bar plus its percentage; "—" when there is no valid value. */
export function ConfidenceBar({ value, digits = 2 }: { value: number | null | undefined; digits?: number }) {
  if (value == null || !Number.isFinite(value)) return <span className="muted">—</span>;
  const v = Math.min(1, Math.max(0, value));
  return (
    <span className="meter">
      <span className="meter-track" aria-hidden="true"><span className="meter-fill" style={{ display: "block", width: `${v * 100}%` }} /></span>
      {(v * 100).toFixed(digits)}%
    </span>
  );
}

/** Re-render every `ms` while mounted. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}

/** Time left until `end`, with a bar showing how much of start → end remains. */
export function Countdown({ start, end }: { start: string; end: string | null }) {
  const now = useNow();
  if (!end) return <span className="muted">no expiry</span>;
  const s = Date.parse(start);
  const e = Date.parse(end);
  if (Number.isNaN(e)) return <span className="muted">unknown expiry</span>;
  const left = Math.max(0, e - now);
  const frac = !Number.isNaN(s) && e > s ? Math.min(1, left / (e - s)) : 0;
  const secs = Math.ceil(left / 1000);
  const text = left === 0 ? "expired" : secs >= 3600
    ? `${Math.floor(secs / 3600)}:${String(Math.floor((secs % 3600) / 60)).padStart(2, "0")} h left`
    : `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")} left`;
  return (
    <span className="countdown" style={{ display: "inline-flex", flexDirection: "column", gap: 6 }}>
      <span style={{ fontWeight: 600, color: "var(--danger-text)" }}>{text}</span>
      <span className="meter-track" aria-hidden="true"><span className="meter-fill" style={{ display: "block", width: `${frac * 100}%` }} /></span>
    </span>
  );
}

export interface TimelineItem { key: string; at: ReactNode; text: ReactNode; tone?: "accent" | "danger" }

export function Timeline({ items }: { items: TimelineItem[] }) {
  return (
    <ol className="timeline">
      {items.map((i) => (
        <li key={i.key}>
          <span className={`tl-dot ${i.tone ?? ""}`.trim()} aria-hidden="true" />
          <span><b>{i.at}</b> {i.text}</span>
        </li>
      ))}
    </ol>
  );
}

/** Load data once (and on demand with `reload`), keeping the error message for display. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const mine = ++seq.current;
    setLoading(true);
    try {
      const result = await load();
      if (mine === seq.current) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (mine === seq.current) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (mine === seq.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { data, error, loading, reload, setData };
}

/** Run a mutating call, tracking busy state and errors. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run, setError };
}
