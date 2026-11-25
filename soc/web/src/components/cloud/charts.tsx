import { useId, useRef, useState, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";

/** Hand-drawn SVG charts (the project's own approach; no chart library is used by the dashboard).
 *  Each one has a hover/keyboard tooltip, a text legend, a one-line summary and a data table, so
 *  nothing depends on colour alone. Series are told apart by colour AND line style / label. */

export const SERIES_CLASSES = ["s0", "s1", "s2", "s3", "s4", "s5"];
const DASHES = ["", "6 3", "2 3", "8 3 2 3", "", "1 4"];

const W = 640, H = 240, ML = 46, MR = 14, MT = 12, MB = 28;

export interface LineSeries { key: string; label: string; values: (number | null)[] }

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

function stats(values: (number | null)[]) {
  const v = values.filter((x): x is number => x !== null && Number.isFinite(x));
  if (!v.length) return null;
  const sum = v.reduce((a, b) => a + b, 0);
  return { min: Math.min(...v), max: Math.max(...v), avg: sum / v.length, last: v[v.length - 1], n: v.length };
}

function useCursor(count: number) {
  const [idx, setIdx] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const move = (ev: MouseEvent) => {
    const r = ref.current?.getBoundingClientRect();
    if (!r || r.width === 0 || count === 0) return;
    const x = ((ev.clientX - r.left) / r.width) * W;
    const f = (x - ML) / (W - ML - MR);
    setIdx(Math.min(count - 1, Math.max(0, Math.round(f * (count - 1)))));
  };
  const key = (ev: KeyboardEvent) => {
    if (count === 0) return;
    const step = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : ev.key === "Home" ? -count : ev.key === "End" ? count : 0;
    if (!step) { if (ev.key === "Escape") setIdx(null); return; }
    ev.preventDefault();
    setIdx((i) => Math.min(count - 1, Math.max(0, (i ?? (step > 0 ? -1 : count)) + step)));
  };
  return { idx, setIdx, ref, move, key };
}

function Legend({ items, hidden, toggle }: {
  items: { key: string; label: string; cls: string; dash: string; note?: string }[];
  hidden?: Set<string>; toggle?: (k: string) => void;
}) {
  return (
    <ul className="cl-legend" aria-label="Legend">
      {items.map((it) => (
        <li key={it.key}>
          {toggle ? (
            <button type="button" className="cl-legend-btn" aria-pressed={!hidden?.has(it.key)} onClick={() => toggle(it.key)}>
              <svg width="26" height="10" aria-hidden="true"><line x1="0" y1="5" x2="26" y2="5" className={`cl-line ${it.cls}`} strokeDasharray={it.dash} /></svg>
              {it.label}{it.note ? <span className="muted"> {it.note}</span> : null}
            </button>
          ) : (
            <span className="cl-legend-item">
              <svg width="14" height="14" aria-hidden="true"><rect width="14" height="14" rx="3" className={`cl-fill ${it.cls}`} /></svg>
              {it.label}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

function DataTable({ caption, head, rows, total }: { caption: string; head: string[]; rows: ReactNode[][]; total?: number }) {
  return (
    <details className="cl-data">
      <summary>Show data table</summary>
      <div className="table-wrap">
        <table>
          <caption className="muted small-text" style={{ textAlign: "left" }}>
            {caption}{total && total > rows.length ? ` (showing ${rows.length} of ${total})` : ""}
          </caption>
          <thead><tr>{head.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => (j === 0 ? <th key={j} scope="row">{c}</th> : <td key={j}>{c}</td>))}</tr>)}</tbody>
        </table>
      </div>
    </details>
  );
}

function sample<T>(items: T[], max: number): T[] {
  if (items.length <= max) return items;
  const out: T[] = [];
  for (let i = 0; i < max; i++) out.push(items[Math.round((i * (items.length - 1)) / (max - 1))]);
  return out;
}

// ---- line chart --------------------------------------------------------------------------------------

export function LineChart({ title, timestamps, series, unit = "", yMax, decimals = 1, formatTime, note }: {
  title: string; timestamps: string[]; series: LineSeries[]; unit?: string; yMax?: number; decimals?: number;
  formatTime: (iso: string) => string; note?: string;
}) {
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const cur = useCursor(timestamps.length);
  const tipId = useId();
  const shown = series.filter((s) => !hidden.has(s.key));
  const top = yMax ?? niceMax(Math.max(0, ...shown.flatMap((s) => s.values.filter((v): v is number => v !== null))));
  const n = timestamps.length;
  const x = (i: number) => ML + (n <= 1 ? 0 : (i / (n - 1)) * (W - ML - MR));
  const y = (v: number) => MT + (1 - Math.min(v, top) / top) * (H - MT - MB);
  const fmt = (v: number | null | undefined) => (v === null || v === undefined ? "no data" : `${v.toFixed(decimals)}${unit}`);

  const paths = shown.map((s) => {
    let d = "", pen = false;
    s.values.forEach((v, i) => {
      if (v === null) { pen = false; return; }
      d += `${pen ? "L" : "M"}${x(i).toFixed(1)} ${y(v).toFixed(1)} `;
      pen = true;
    });
    return { s, d };
  });
  const ticks = [0, 0.25, 0.5, 0.75, 1];
  const xTicks = n ? sample(timestamps.map((t, i) => ({ t, i })), 5) : [];
  const summary = series.map((s) => {
    const st = stats(s.values);
    return st ? `${s.label}: latest ${fmt(st.last)}, min ${fmt(st.min)}, average ${fmt(st.avg)}, max ${fmt(st.max)}` : `${s.label}: no data in this range`;
  });
  const rows = sample(timestamps.map((t, i) => ({ t, i })), 24);

  return (
    <figure className="cl-chart">
      <figcaption className="cl-chart-title">{title}</figcaption>
      <div className="cl-plot" ref={cur.ref} tabIndex={0} role="group" aria-label={`${title}. Use the left and right arrow keys to read values.`}
        aria-describedby={cur.idx !== null ? tipId : undefined}
        onMouseMove={cur.move} onMouseLeave={() => cur.setIdx(null)} onKeyDown={cur.key} onBlur={() => cur.setIdx(null)}>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true" className="cl-svg">
          {ticks.map((f) => (
            <g key={f}>
              <line x1={ML} x2={W - MR} y1={y(top * f)} y2={y(top * f)} className="cl-grid" />
              <text x={ML - 6} y={y(top * f) + 4} textAnchor="end" className="cl-axis">{Number((top * f).toFixed(decimals))}</text>
            </g>
          ))}
          {xTicks.map(({ t, i }) => <text key={i} x={x(i)} y={H - 8} textAnchor="middle" className="cl-axis">{formatTime(t)}</text>)}
          {paths.map(({ s, d }) => {
            const k = series.indexOf(s);
            return <path key={s.key} d={d} className={`cl-line ${SERIES_CLASSES[k % 6]}`} strokeDasharray={DASHES[k % 6]} fill="none" />;
          })}
          {cur.idx !== null && (
            <g>
              <line x1={x(cur.idx)} x2={x(cur.idx)} y1={MT} y2={H - MB} className="cl-cursor" />
              {shown.map((s) => {
                const v = s.values[cur.idx!];
                return v === null ? null : <circle key={s.key} cx={x(cur.idx!)} cy={y(v)} r="4" className={`cl-fill ${SERIES_CLASSES[series.indexOf(s) % 6]}`} />;
              })}
            </g>
          )}
        </svg>
        {cur.idx !== null && (
          <div id={tipId} className="cl-tip-box" style={{ left: `${(x(cur.idx) / W) * 100}%` }} data-testid="chart-tooltip">
            <b>{formatTime(timestamps[cur.idx])}</b>
            {shown.map((s) => <div key={s.key}>{s.label}: {fmt(s.values[cur.idx!])}</div>)}
          </div>
        )}
      </div>
      <Legend hidden={hidden} items={series.map((s, k) => ({ key: s.key, label: s.label, cls: SERIES_CLASSES[k % 6], dash: DASHES[k % 6] }))}
        toggle={(k) => setHidden((h) => { const c = new Set(h); if (c.has(k)) c.delete(k); else c.add(k); return c; })} />
      <p className="cl-summary small-text">{summary.join(". ")}.{note ? ` ${note}` : ""}</p>
      <DataTable caption={`${title}: data`} total={n} head={["Time", ...series.map((s) => s.label)]}
        rows={rows.map(({ t, i }) => [formatTime(t), ...series.map((s) => fmt(s.values[i]))])} />
    </figure>
  );
}

// ---- horizontal bars -----------------------------------------------------------------------------------

export interface BarItem { key: string; label: string; value: number; text: string; detail?: string }

/** Ranked bars with the value as text beside each bar and a tooltip on hover or focus. */
export function BarList({ title, items, empty = "Nothing to show." }: { title: string; items: BarItem[]; empty?: string }) {
  const max = Math.max(0, ...items.map((i) => i.value));
  if (!items.length) return <p className="muted">{empty}</p>;
  return (
    <figure className="cl-chart">
      <figcaption className="cl-chart-title">{title}</figcaption>
      <ul className="cl-bars">
        {items.map((it, k) => (
          <li key={it.key} className="cl-bar-row" tabIndex={0} aria-label={`${it.label}: ${it.text}${it.detail ? `, ${it.detail}` : ""}`}>
            <span className="cl-bar-label">{it.label}</span>
            <span className="cl-bar-track" aria-hidden="true"><span className={`cl-bar-fill ${SERIES_CLASSES[k % 6]}`} style={{ width: `${max ? (it.value / max) * 100 : 0}%` }} /></span>
            <span className="cl-bar-value">{it.text}</span>
            <span className="cl-tip-box cl-bar-tip" role="tooltip" aria-hidden="true"><b>{it.label}</b><br />{it.text}{it.detail ? <><br />{it.detail}</> : null}</span>
          </li>
        ))}
      </ul>
    </figure>
  );
}

// ---- stacked columns ------------------------------------------------------------------------------------

export interface Column { key: string; label: string; parts: Record<string, number>; total: number }

export function StackedColumns({ title, columns, partKeys, format }: {
  title: string; columns: Column[]; partKeys: string[]; format: (v: number) => string;
}) {
  const cur = useCursor(columns.length);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const tipId = useId();
  const visible = partKeys.filter((k) => !hidden.has(k));
  const totalOf = (c: Column) => visible.reduce((a, k) => a + (c.parts[k] ?? 0), 0);
  const top = niceMax(Math.max(0, ...columns.map(totalOf)));
  const n = columns.length;
  const slot = (W - ML - MR) / Math.max(1, n);
  const bw = Math.max(1.5, slot * 0.72);
  const sy = (v: number) => (v / top) * (H - MT - MB);
  const xTicks = sample(columns.map((c, i) => ({ c, i })), 6);
  const rows = sample(columns.map((c, i) => ({ c, i })), 31);
  return (
    <figure className="cl-chart">
      <figcaption className="cl-chart-title">{title}</figcaption>
      <div className="cl-plot" ref={cur.ref} tabIndex={0} role="group" aria-label={`${title}. Use the left and right arrow keys to read each day.`}
        aria-describedby={cur.idx !== null ? tipId : undefined}
        onMouseMove={cur.move} onMouseLeave={() => cur.setIdx(null)} onKeyDown={cur.key} onBlur={() => cur.setIdx(null)}>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true" className="cl-svg">
          {[0, 0.5, 1].map((f) => (
            <g key={f}>
              <line x1={ML} x2={W - MR} y1={MT + (1 - f) * (H - MT - MB)} y2={MT + (1 - f) * (H - MT - MB)} className="cl-grid" />
              <text x={ML - 6} y={MT + (1 - f) * (H - MT - MB) + 4} textAnchor="end" className="cl-axis">{format(top * f)}</text>
            </g>
          ))}
          {columns.map((c, i) => {
            let acc = 0;
            return (
              <g key={c.key} opacity={cur.idx === null || cur.idx === i ? 1 : 0.55}>
                {visible.map((k) => {
                  const v = c.parts[k] ?? 0;
                  const h = sy(v);
                  acc += h;
                  return <rect key={k} x={ML + i * slot + (slot - bw) / 2} y={H - MB - acc} width={bw} height={Math.max(0, h)} className={`cl-fill ${SERIES_CLASSES[partKeys.indexOf(k) % 6]}`} />;
                })}
              </g>
            );
          })}
          {xTicks.map(({ c, i }) => <text key={c.key} x={ML + i * slot + slot / 2} y={H - 8} textAnchor="middle" className="cl-axis">{c.label.slice(5)}</text>)}
        </svg>
        {cur.idx !== null && columns[cur.idx] && (
          <div id={tipId} className="cl-tip-box" style={{ left: `${((ML + cur.idx * slot + slot / 2) / W) * 100}%` }} data-testid="chart-tooltip">
            <b>{columns[cur.idx].label}</b>
            {visible.map((k) => <div key={k}>{k}: {format(columns[cur.idx!].parts[k] ?? 0)}</div>)}
            <div>total: {format(totalOf(columns[cur.idx]))}</div>
          </div>
        )}
      </div>
      <Legend hidden={hidden} items={partKeys.map((k, j) => ({ key: k, label: k, cls: SERIES_CLASSES[j % 6], dash: DASHES[j % 6] }))}
        toggle={(k) => setHidden((h) => { const c = new Set(h); if (c.has(k)) c.delete(k); else c.add(k); return c; })} />
      <DataTable caption={`${title}: data`} total={n} head={["Day", ...partKeys, "Total"]}
        rows={rows.map(({ c }) => [c.label, ...partKeys.map((k) => format(c.parts[k] ?? 0)), format(c.total)])} />
    </figure>
  );
}

// ---- gauge ------------------------------------------------------------------------------------------------

/** A ring showing 0 to 100 %, with the value as text in the middle and a text status. */
export function Gauge({ label, value, detail, warnAt, critAt }: {
  label: string; value: number | null | undefined; detail?: string; warnAt?: number; critAt?: number;
}) {
  const ok = value !== null && value !== undefined && Number.isFinite(value);
  const v = ok ? Math.min(100, Math.max(0, value as number)) : 0;
  const graded = warnAt !== undefined || critAt !== undefined;
  const level = !ok ? "unknown" : !graded ? "plain" : critAt !== undefined && v >= critAt ? "critical" : warnAt !== undefined && v >= warnAt ? "warning" : "normal";
  const C = 2 * Math.PI * 40;
  const text = { unknown: "No data", plain: "", critical: "Critical (at or over the limit)", warning: "High (over the warning level)", normal: "Normal" }[level];
  return (
    <div className="cl-gauge" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={ok ? Math.round(v * 10) / 10 : undefined}
      aria-valuetext={ok ? `${v.toFixed(1)} percent${text ? `, ${text}` : ""}` : "no data"}>
      <svg viewBox="0 0 100 100" width="96" height="96" aria-hidden="true">
        <circle cx="50" cy="50" r="40" className="cl-ring-bg" />
        <circle cx="50" cy="50" r="40" className={`cl-ring ${level}`} strokeDasharray={`${(v / 100) * C} ${C}`} transform="rotate(-90 50 50)" />
        <text x="50" y="56" textAnchor="middle" className="cl-ring-text">{ok ? `${v.toFixed(0)}%` : "—"}</text>
      </svg>
      <div>
        <div className="cl-gauge-label">{label}</div>
        {(text || !ok) && <div className={`cl-gauge-status ${level}`}>{ok ? text : "No data"}</div>}
        {detail && <div className="muted small-text">{detail}</div>}
      </div>
    </div>
  );
}
