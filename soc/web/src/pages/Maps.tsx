import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHead, Segmented } from "../components/common";

// Map libraries are large, so each map loads on demand.
const WorldMap = lazy(() => import("./WorldMap"));
const TopologyMap = lazy(() => import("./TopologyMap"));

type View = "topology" | "world" | "recorded";
export const WINDOWS = [1, 6, 24, 72, 168];
// 1 h by default: the topology layout gets slow on big windows of a busy network.
const DEFAULT_HOURS = 1;

/** Network topology and world attack map behind one toggle and one time window (wireframe
 *  screen 6): `/maps?view=world&hours=6`. */
export default function Maps() {
  const [params, setParams] = useSearchParams();
  const requestedView = params.get("view");
  const view: View = requestedView === "world" || requestedView === "recorded" ? requestedView : "topology";
  const asked = Number(params.get("hours"));
  const hours = WINDOWS.includes(asked) ? asked : DEFAULT_HOURS;

  function set(next: { view?: View; hours?: number }) {
    const v = next.view ?? view;
    const h = next.hours ?? hours;
    const p: Record<string, string> = {};
    if (v !== "topology") p.view = v;
    if (h !== DEFAULT_HOURS) p.hours = String(h);
    setParams(p, { replace: true });
  }

  return (
    <>
      <PageHead title="Maps">
        <Segmented<View>
          label="Map type"
          value={view}
          onChange={(v) => set({ view: v })}
          options={[{ value: "topology", label: "Network topology" }, { value: "world", label: "World attack map" },
            { value: "recorded", label: "Recorded alerts" }]}
        />
        <label className="field inline">Window
          <select value={hours} onChange={(e) => set({ hours: Number(e.target.value) })}>
            {WINDOWS.map((h) => <option key={h} value={h}>last {h < 24 ? `${h} h` : h === 24 ? "24 h" : `${h / 24} days`}</option>)}
          </select>
        </label>
      </PageHead>
      <Suspense fallback={<p className="muted">Loading…</p>}>
        {view !== "topology"
          ? <WorldMap key={view === "recorded" ? `recorded-${hours}` : view} hours={hours} playback={view === "recorded"} />
          : <TopologyMap hours={hours} onShowWorld={() => set({ view: "world" })} />}
      </Suspense>
    </>
  );
}
