import "@xyflow/react/dist/style.css";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, query } from "../api/client";
import type { Alert, Block, Page, Severity } from "../api/types";
import { Card, ErrorText, SeverityBadge, useLoad } from "../components/common";
import { dateTime } from "../format";
import { useBlockMarks } from "../liveBlocks";
import { useLiveRefresh } from "../useLiveRefresh";

const PULSE_MS = 3000;

export interface TopoNode { ip: string; alert_count: number; max_severity: Severity }
export interface TopoEdge { src: string; dst: string; count: number; max_severity: Severity }
export interface Topology { hours: number; nodes: TopoNode[]; edges: TopoEdge[] }

interface SimNode extends SimulationNodeDatum { id: string }

type Positions = Map<string, { x: number; y: number }>;

/** Positions from a short force simulation. Hosts already placed start where they were, so a
 *  refresh that adds a host doesn't reshuffle the whole graph; new ones start on a circle. */
function layout(topo: Topology, previous: Positions = new Map()): Positions {
  const n = topo.nodes.length;
  const nodes: SimNode[] = topo.nodes.map((t, i) => ({
    id: t.ip,
    x: previous.get(t.ip)?.x ?? 400 + 300 * Math.cos((2 * Math.PI * i) / Math.max(n, 1)),
    y: previous.get(t.ip)?.y ?? 300 + 300 * Math.sin((2 * Math.PI * i) / Math.max(n, 1)),
  }));
  const links: SimulationLinkDatum<SimNode>[] = topo.edges.map((e) => ({ source: e.src, target: e.dst }));
  const sim = forceSimulation(nodes)
    .force("link", forceLink<SimNode, SimulationLinkDatum<SimNode>>(links).id((d) => d.id).distance(170))
    .force("charge", forceManyBody().strength(-500))
    .force("collide", forceCollide(70))
    .force("center", forceCenter(400, 300))
    .stop();
  // Fewer steps when most hosts are already placed: they only need to settle.
  const placed = topo.nodes.filter((t) => previous.has(t.ip)).length;
  const steps = placed === n && n > 0 ? 0 : placed > n / 2 ? 80 : 300;
  for (let i = 0; i < steps; i++) sim.tick();
  return new Map(nodes.map((d) => [d.id, { x: d.x ?? 0, y: d.y ?? 0 }]));
}

function subnet(ip: string): string {
  if (ip.includes(":")) return "IPv6";
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : "";
}

export type Role = "source" | "target" | "both";

/** A host's role in the alerts: it sent them, received them, or both. */
export function roleOf(ip: string, edges: TopoEdge[]): Role {
  const sends = edges.some((e) => e.src === ip);
  const gets = edges.some((e) => e.dst === ip);
  return sends && gets ? "both" : sends ? "source" : "target";
}

const ROLE_TEXT: Record<Role, string> = {
  source: "source of alerts", target: "target of alerts", both: "source and target of alerts",
};

/** Most hosts drawn at once; beyond this the layout stalls the page. */
export const MAX_NODES = 150;

/** The busiest hosts (the API sends nodes by alert count) and the links between them. */
export function limitGraph(topo: Topology, max = MAX_NODES): { graph: Topology; hidden: number } {
  if (topo.nodes.length <= max) return { graph: topo, hidden: 0 };
  const nodes = [...topo.nodes].sort((a, b) => b.alert_count - a.alert_count).slice(0, max);
  const keep = new Set(nodes.map((n) => n.ip));
  const edges = topo.edges.filter((e) => keep.has(e.src) && keep.has(e.dst));
  return { graph: { ...topo, nodes, edges }, hidden: topo.nodes.length - max };
}

/** Line width from 1.5 to 6 px by alert count. */
export function edgeWidth(count: number, max: number): number {
  return 1.5 + 4.5 * Math.sqrt(Math.max(0, count) / Math.max(1, max));
}

export default function TopologyMap({ hours, onShowWorld }: { hours: number; onShowWorld: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const { data: raw, error, reload } = useLoad(() => api<Topology>(`/topology${query({ hours })}`), [hours]);
  const marks = useBlockMarks();

  // Live: the link and both hosts of each new alert pulse for a few seconds. A host that isn't
  // on the graph yet appears with the next refresh (debounced, at most 5 s later).
  const [hot, setHot] = useState<Set<string>>(new Set());
  const pulseTimers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => { pulseTimers.current.forEach(clearTimeout); }, []);
  const onAlert = useCallback((a: Alert) => {
    const keys = [`${a.src_ip}->${a.dst_ip}`, a.src_ip, a.dst_ip];
    setHot((h) => { const next = new Set(h); keys.forEach((k) => next.add(k)); return next; });
    const t = setTimeout(() => {
      pulseTimers.current.delete(t);
      setHot((h) => { const next = new Set(h); keys.forEach((k) => next.delete(k)); return next; });
    }, PULSE_MS);
    pulseTimers.current.add(t);
  }, []);
  useLiveRefresh(reload, onAlert);
  const { graph: data, hidden } = useMemo(
    () => (raw ? limitGraph(raw) : { graph: null, hidden: 0 }), [raw]);

  // The force layout is the slow part: run it only when the hosts or links change (not on every
  // refresh with the same graph), starting from the previous positions.
  const shape = data
    ? `${data.nodes.map((n) => n.ip).sort().join(",")}|${data.edges.map((e) => `${e.src}>${e.dst}`).sort().join(",")}`
    : "";
  const placed = useRef<Positions>(new Map());
  const positions = useMemo(() => {
    if (!data) return placed.current;
    placed.current = layout(data, placed.current);
    return placed.current;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape]);
  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const maxCount = Math.max(1, ...data.edges.map((e) => e.count));
    const nodes: Node[] = data.nodes.map((t) => {
      const role = roleOf(t.ip, data.edges);
      return {
        id: t.ip,
        position: positions.get(t.ip) ?? { x: 0, y: 0 },
        data: {
          label: (
            <div>
              <div className="mono" style={{ fontWeight: 600 }}>
                <span className={`role-dot ${role}`} aria-hidden="true" />{t.ip}
              </div>
              <div className="muted" style={{ fontSize: 11 }}>{subnet(t.ip)} · {t.alert_count} alerts</div>
            </div>
          ),
        },
        ariaLabel: `${t.ip}, ${ROLE_TEXT[role]}, ${t.alert_count} alerts, highest severity ${t.max_severity}`
          + (marks.get(t.ip) === "blocked" ? ", blocked" : marks.get(t.ip) === "would" ? ", a dry-run sensor would block it" : ""),
        selected: selected === t.ip,
        className: `topo-node sev-border-${t.max_severity}${selected === t.ip ? " selected" : ""}`
          + (marks.get(t.ip) === "blocked" ? " blocked" : marks.get(t.ip) === "would" ? " would-block" : "")
          + (hot.has(t.ip) ? " pulse" : ""),
        style: { width: 170 },
      };
    });
    const edges: Edge[] = data.edges.map((e) => ({
      id: `${e.src}->${e.dst}`,
      source: e.src,
      target: e.dst,
      label: String(e.count),
      animated: e.max_severity === "high" || e.max_severity === "critical",
      className: `topo-edge sev-stroke-${e.max_severity}`
        + (marks.get(e.src) === "blocked" ? " blocked" : "")
        + (hot.has(`${e.src}->${e.dst}`) ? " pulse" : ""),
      style: { strokeWidth: edgeWidth(e.count, maxCount) },
      labelStyle: { fill: "var(--text)", fontSize: 11 },
      labelBgStyle: { fill: "var(--surface)" },
      markerEnd: { type: MarkerType.ArrowClosed },
    }));
    return { nodes, edges };
  }, [data, positions, selected, marks, hot]);

  const sel = data?.nodes.find((n) => n.ip === selected) ?? null;

  // Selecting re-renders the host's element, which drops keyboard focus to the page. After a
  // keyboard select or clear, put focus back on the same host.
  const canvas = useRef<HTMLDivElement>(null);
  const refocus = useRef<string | null>(null);
  useEffect(() => {
    const id = refocus.current;
    if (!id) return;
    const el = [...(canvas.current?.querySelectorAll<HTMLElement>(".react-flow__node") ?? [])]
      .find((n) => n.dataset.id === id);
    // React Flow blurs a host on the next animation frame when its selection toggles, so focus
    // goes back after that. The id is cleared only once focus has moved: if the graph refreshes
    // in between, this effect re-runs (its cleanup cancels the frames) and tries again.
    if (!el) {
      refocus.current = null;
      return;
    }
    let second = 0;
    const first = requestAnimationFrame(() => {
      second = requestAnimationFrame(() => {
        if (refocus.current === id) refocus.current = null;
        // Only if focus is still where the key press left it (on the canvas, or dropped to the
        // page by the re-render): never pull it back from somewhere the user has moved to.
        const active = document.activeElement;
        if (active && active !== document.body && !canvas.current?.contains(active)) return;
        el.focus({ preventScroll: true });
      });
    });
    return () => { cancelAnimationFrame(first); cancelAnimationFrame(second); };
  }, [selected, nodes]);

  return (
    <div className="grid cols-topo">
      <Card title="Who talks to whom" label="Network topology">
        <p className="muted small-text" style={{ marginTop: -4 }}>
          Hosts seen in alerts in the last {hours} h. Arrows point from source to target; moving lines are high or critical.
          New alerts make their link glow. Red ring: blocked; dashed ring: a dry-run sensor would block it.
        </p>
        <ErrorText error={error} />
        {/* React Flow reports clicks but not keyboard activation: Enter or Space on a focused
            host (React Flow gives each host a focusable element with data-id) selects it too. */}
        <div className="topo-canvas" ref={canvas} onKeyDown={(e) => {
          const el = (e.target as HTMLElement).closest<HTMLElement>(".react-flow__node");
          const id = el?.dataset.id;
          // A refocus is only asked for when the selection really changes: otherwise nothing
          // re-renders, and a leftover request would move focus at the next data refresh.
          refocus.current = null;
          if (e.key === "Escape") {
            if (id && selected !== null) refocus.current = id;
            setSelected(null);
            return;
          }
          if (e.key !== "Enter" && e.key !== " ") return;
          if (id && data?.nodes.some((n) => n.ip === id)) {
            e.preventDefault();
            if (selected !== id) refocus.current = id;
            setSelected(id);
          }
        }}>
          {data && data.nodes.length === 0 ? (
            <p className="muted" style={{ padding: 16 }}>No alerts in this window.</p>
          ) : (
            <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2} nodesConnectable={false}
              nodesDraggable={false} edgesFocusable={false}
              onNodeClick={(_, n) => setSelected(n.id)} onPaneClick={() => setSelected(null)}
              proOptions={{ hideAttribution: false }}>
              <Background />
              <Controls showInteractive={false} />
            </ReactFlow>
          )}
        </div>
        {hidden > 0 && (
          <p className="muted small-text" style={{ margin: "8px 0 0" }}>
            Showing the {MAX_NODES} busiest hosts; {hidden} more are left out. Choose a shorter window to see them.
          </p>
        )}
        <div className="row-actions muted small-text" style={{ gap: 16, marginTop: 10 }}>
          <span><span className="role-dot source" aria-hidden="true" />attacking host</span>
          <span><span className="role-dot target" aria-hidden="true" />target</span>
          <span><span className="role-dot both" aria-hidden="true" />both</span>
          <span>
            Border, highest severity:{" "}
            {(["low", "medium", "high", "critical"] as const).map((s) => (
              <span key={s} className={`sev-key sev-border-${s}`}>{s}</span>
            ))}
          </span>
          <span>Line width: alert count</span>
          <span>Scroll to zoom · Tab to a host, Enter to select, Escape to clear</span>
        </div>
      </Card>

      <div className="stack">
        {sel && data ? (
          <HostPanel key={sel.ip} node={sel} edges={data.edges} hours={hours} />
        ) : (
          <Card title="Selected host">
            <p className="muted" style={{ margin: 0 }}>Click a host to see who it talks to.</p>
          </Card>
        )}
        <Card title="World attack map">
          <p className="muted" style={{ marginTop: 0 }}>
            Lines from attacker locations to the protected site, coloured by severity. Lab addresses are private,
            so they show at demo locations until a GeoLite2 key is added.
          </p>
          <button type="button" onClick={onShowWorld}>Open the world map</button>
        </Card>
      </div>
    </div>
  );
}

/** Details of the selected host: role, alerts, peers, block state, and what to do next. */
function HostPanel({ node, edges, hours }: { node: TopoNode; edges: TopoEdge[]; hours: number }) {
  const role = roleOf(node.ip, edges);
  const out = edges.filter((e) => e.src === node.ip);
  const inc = edges.filter((e) => e.dst === node.ip);
  // The topology has no sensor: take it from this host's newest alert, for the block form.
  const latest = useLoad(() => api<Page<Alert>>(`/alerts${query({ ip: node.ip, limit: 1 })}`), [node.ip]);
  const blocks = useLoad(() => api<Page<Block>>(`/blocks${query({ ip: node.ip, active: true, limit: 20 })}`), [node.ip]);
  useLiveRefresh(blocks.reload, undefined, 30_000);
  const sensor = latest.data?.items[0]?.sensor_id;
  const active = (blocks.data?.items ?? []).find((b) => b.ip === node.ip && b.active);
  // The sensor is a guess (the newest alert may be one where this host was the target, on another
  // sensor), so the link says so and the block form shows its "check the sensor" hint.
  // Numbers only: the block form writes the reason itself, so a link never carries free text.
  const blockLink = `/response${query({
    ip: node.ip, sensor, sensor_guess: sensor ? 1 : undefined,
    from: "topology", count: node.alert_count, hours,
  })}`;

  return (
    <Card title={<>Selected: <span className="mono wrap-anywhere">{node.ip}</span></>} label={`Selected host ${node.ip}`}>
      <dl className="kv right">
        <dt>Role</dt><dd>{ROLE_TEXT[role]}</dd>
        <dt>Alerts</dt><dd>{node.alert_count}</dd>
        {out.length > 0 && <><dt>Targets</dt><dd>{out.length} host{out.length === 1 ? "" : "s"}</dd></>}
        {inc.length > 0 && <><dt>Sources</dt><dd>{inc.length} host{inc.length === 1 ? "" : "s"}</dd></>}
        <dt>Max severity</dt><dd><SeverityBadge severity={node.max_severity} /></dd>
        <dt>Block</dt>
        <dd>
          {blocks.error ? <span className="muted">unknown</span>
            : !blocks.data ? "…"
            : active ? <>sensor #{active.sensor_id}{active.expires_at ? ` until ${dateTime(active.expires_at)}` : ""}</>
            : "none active"}
        </dd>
      </dl>
      {(out.length > 0 || inc.length > 0) && (
        <ul className="queue-list" style={{ marginTop: 14 }} aria-label="Flows">
          {[...out, ...inc].slice(0, 12).map((e) => (
            <li key={`${e.src}-${e.dst}`}>
              <span className="mono wrap-anywhere">{e.src === node.ip ? `→ ${e.dst}` : `← ${e.src}`}</span>
              <span>{e.count} alert{e.count === 1 ? "" : "s"}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="row-actions" style={{ marginTop: 14 }}>
        <Link className="button-link" to={`/alerts${query({ ip: node.ip })}`}>Show its alerts</Link>
        {role !== "target" && !active && (
          <Link className="button-link danger" to={blockLink}>Block…</Link>
        )}
      </div>
      {role !== "target" && !active && !latest.data && !latest.error && (
        <p className="muted small-text" style={{ margin: "8px 0 0" }}>Looking up its sensor…</p>
      )}
    </Card>
  );
}
