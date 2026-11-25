import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import WorldMap, { MAX_SHOTS, mergeLivePoints } from "../pages/WorldMap";

const h = vi.hoisted(() => ({
  api: vi.fn(),
  onAlert: null as null | ((a: unknown) => void),
  reload: null as null | (() => void),
  blockFns: new Set<(e: unknown) => void>(),
}));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (f: () => void, onAlert: (a: unknown) => void) => { h.onAlert = onAlert; h.reload = f; return true; },
}));
vi.mock("../live", async () => {
  const { useEffect, useRef } = await import("react");
  return {
    useLiveStatus: () => true,
    useLiveAlerts: () => true,
    useLiveBlocks: (fn: (e: unknown) => void) => {
      const ref = useRef(fn);
      ref.current = fn;
      useEffect(() => {
        const wrapped = (e: unknown) => ref.current(e);
        h.blockFns.add(wrapped);
        return () => { h.blockFns.delete(wrapped); };
      }, []);
      return true;
    },
  };
});

const T0 = Date.parse("2026-03-01T12:00:00Z");
const HOME = { lat: 50, lon: 8, label: "Lab" };
const geo = (o: Record<string, unknown> = {}) => ({
  hours: 6, home: null, geoip_status: "ok", demo: false, points: [], unlocated_sources: 0, ...o,
});
const point = (o: Record<string, unknown> = {}) => ({
  ip: "8.8.8.8", count: 3, max_severity: "high", lat: 37, lon: -122, country: "US", city: "Mountain View", source: "geoip", ...o,
});
const where = (o: Record<string, unknown> = {}) => ({ lat: 35, lon: 139, country: "JP", city: "Tokyo", source: "geoip", ...o });
const liveAlert = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 1, src_ip: "9.9.9.9", dst_ip: "10.0.0.1", dst_port: 80, protocol: 6, severity: "high",
  predicted_class: "PortScan", src_geo: where(), ...o,
});
const blockEv = (o: Record<string, unknown> = {}) => ({
  type: "block", event: "blocked", sensor_id: 2, ip: "8.8.8.8", source: "auto", at: new Date(T0).toISOString(),
  expires_at: new Date(T0 + 600_000).toISOString(), ttl_seconds: 600, reason: "scan", geo: null, ...o,
});

let geoBody: unknown;
let geoError: Error | null;
let blocksBody: unknown[];
let wouldBody: unknown[];

beforeEach(() => {
  geoBody = geo();
  geoError = null;
  blocksBody = [];
  wouldBody = [];
  h.onAlert = null;
  h.reload = null;
  h.blockFns.clear();
  h.api.mockReset();
  h.api.mockImplementation(async (p: string) => {
    if (p.startsWith("/geo/attacks")) { if (geoError) throw geoError; return geoBody; }
    if (p.startsWith("/blocks/would")) return { items: wouldBody, total: wouldBody.length, next_cursor: null };
    if (p.startsWith("/blocks")) return { items: blocksBody, total: blocksBody.length, next_cursor: null };
    throw new Error(`unexpected ${p}`);
  });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); });

const ui = (props: { hours?: number; compact?: boolean } = {}) => (
  <MemoryRouter><WorldMap hours={props.hours ?? 6} compact={props.compact} /></MemoryRouter>
);
const show = (props: { hours?: number; compact?: boolean } = {}) => render(ui(props));
const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
/** Fake timers (and a fixed clock) from the start; the map is loaded when this returns. */
async function mount(props: { hours?: number; compact?: boolean } = {}) {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  vi.setSystemTime(T0);
  const r = show(props);
  await flush();
  return r;
}
const alertNow = (a: unknown) => act(() => { h.onAlert!(a); });
const blockNow = (e: unknown) => act(() => { h.blockFns.forEach((fn) => fn(e)); });
const shots = (c: HTMLElement) => c.querySelectorAll("circle.map-shot");
const mapLabel = (n: number) => screen.getByRole("img", { name: `World map of ${n} attack sources` });
const feedItems = () => Array.from(document.querySelectorAll(".feed-item")) as HTMLElement[];
const stubReducedMotion = () => vi.stubGlobal("matchMedia", vi.fn(() => ({
  matches: true, addEventListener: () => {}, removeEventListener: () => {},
})));

describe("WorldMap", () => {
  it("plays stored alerts in order, pauses, and keeps live events out of playback", async () => {
    vi.useFakeTimers();
    const when = "2026-03-01T09:00:00Z";
    const alerts = [2, 1].map(id => liveAlert({ id, src_ip: "8.8.8.8", received_at: when, predicted_class: `Recorded ${id}` }));
    h.api.mockImplementation(async (path: string) => {
      if (path.startsWith("/alerts?")) return { items: alerts };
      if (path.startsWith("/geo/attacks")) return geo({ home: HOME, points: [point()] });
      return { items: [] };
    });
    render(<MemoryRouter><WorldMap hours={168} playback /></MemoryRouter>);
    await flush();
    await tick(1500);
    expect(feedItems()[0]).toHaveTextContent("Recorded 1");
    expect(screen.getByRole("img")).toHaveAccessibleName("World map of 1 attack sources");
    expect(h.onAlert).toBeUndefined();
    blockNow(blockEv());
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    await tick(3000);
    expect(feedItems()).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Resume" }));
    await tick(1500);
    expect(feedItems()[0]).toHaveTextContent("Recorded 2");
    fireEvent.click(screen.getByRole("button", { name: "Play again" }));
    expect(feedItems()).toHaveLength(0);
    expect(h.api.mock.calls.every(([, opts]) => !opts?.method || opts.method === "GET")).toBe(true);
  });

  it("requests /geo/attacks with the hours prop", async () => {
    show();
    await screen.findByText("Where attacks come from");
    expect(h.api.mock.calls.map(([p]) => p)).toContain("/geo/attacks?hours=6");
  });

  it("re-requests when the hours change", async () => {
    const { rerender } = show();
    await screen.findByText("Where attacks come from");
    rerender(ui({ hours: 72 }));
    await waitFor(() => expect(h.api.mock.calls.map(([p]) => p)).toContain("/geo/attacks?hours=72"));
  });

  it("has no window select of its own", async () => {
    show();
    await screen.findByText("Where attacks come from");
    expect(screen.queryByLabelText("Window")).toBeNull();
  });

  it("lists located sources and the map label", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    show();
    expect(await screen.findByRole("img", { name: "World map of 1 attack sources" })).toBeInTheDocument();
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("Mountain View, US")).toBeInTheDocument();
    expect(screen.getByText("Lab")).toBeInTheDocument();
  });

  it("shows an API error", async () => {
    geoError = new Error("geo down");
    show();
    expect(await screen.findByText("geo down")).toBeInTheDocument();
  });

  it("the old 4 s hot-arc highlight is gone: an alert adds no .hot class", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    const { container } = await mount();
    alertNow(liveAlert({ src_ip: "8.8.8.8" }));
    expect(container.querySelector(".hot")).toBeNull();
  });
});

describe("mergeLivePoints", () => {
  const base = [point() as never];
  const live = (o: Record<string, { count: number; sev: string }>) =>
    new Map(Object.entries(o).map(([ip, v]) => [ip, { geo: where() as never, count: v.count, sev: v.sev as never }]));

  it("returns the points unchanged when nothing is live", () => {
    expect(mergeLivePoints(base, new Map())).toEqual(base);
  });
  it("counts add up for a known address", () => {
    const out = mergeLivePoints(base, live({ "8.8.8.8": { count: 2, sev: "low" } }));
    expect(out).toHaveLength(1);
    expect(out[0].count).toBe(5);
    expect(out[0].max_severity).toBe("high");
  });
  it("the higher severity wins, either way", () => {
    expect(mergeLivePoints(base, live({ "8.8.8.8": { count: 1, sev: "critical" } }))[0].max_severity).toBe("critical");
    expect(mergeLivePoints(base, live({ "8.8.8.8": { count: 1, sev: "medium" } }))[0].max_severity).toBe("high");
    expect(mergeLivePoints(base, live({ "8.8.8.8": { count: 1, sev: "high" } }))[0].max_severity).toBe("high");
  });
  it("a new address is appended with its geo", () => {
    const out = mergeLivePoints(base, live({ "9.9.9.9": { count: 2, sev: "medium" } }));
    expect(out).toHaveLength(2);
    expect(out[1]).toEqual({ ip: "9.9.9.9", count: 2, max_severity: "medium", lat: 35, lon: 139, country: "JP", city: "Tokyo", source: "geoip" });
  });
  it("does not mutate its input", () => {
    const copy = JSON.parse(JSON.stringify(base));
    mergeLivePoints(base, live({ "8.8.8.8": { count: 2, sev: "critical" } }));
    expect(base).toEqual(copy);
  });
  it("works from an empty list", () => {
    expect(mergeLivePoints([], live({ "1.1.1.1": { count: 1, sev: "low" } }))).toHaveLength(1);
  });
});

describe("live alerts on the map", () => {
  it("a new source with a location appears at once", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    await mount();
    expect(mapLabel(1)).toBeInTheDocument();
    alertNow(liveAlert());
    expect(mapLabel(2)).toBeInTheDocument();
    const row = screen.getByText("9.9.9.9").closest("tr")!;
    expect(row).toHaveTextContent("Tokyo, JP");
  });

  it("a known source counts up in the table", async () => {
    geoBody = geo({ home: HOME, points: [point({ count: 3 })] });
    await mount();
    alertNow(liveAlert({ src_ip: "8.8.8.8" }));
    alertNow(liveAlert({ id: 2, src_ip: "8.8.8.8" }));
    expect(mapLabel(1)).toBeInTheDocument();
    expect(screen.getByText("8.8.8.8").closest("tr")!.children[1]).toHaveTextContent("5");
  });

  it("an alert without a location adds no point", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    await mount();
    alertNow(liveAlert({ src_geo: null }));
    alertNow(liveAlert({ id: 3, src_geo: undefined }));
    expect(mapLabel(1)).toBeInTheDocument();
  });

  it("live points reset when the next load arrives", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    await mount();
    alertNow(liveAlert());
    expect(mapLabel(2)).toBeInTheDocument();
    geoBody = geo({ home: HOME, points: [point(), point({ ip: "9.9.9.9", count: 1 })] });
    act(() => { h.reload!(); });
    await flush();
    expect(mapLabel(2)).toBeInTheDocument();
    expect(screen.getByText("9.9.9.9").closest("tr")!.children[1]).toHaveTextContent("1"); // the server's count, not 1 + live
    geoBody = geo({ home: HOME, points: [point()] });
    act(() => { h.reload!(); });
    await flush();
    expect(mapLabel(1)).toBeInTheDocument();
  });

  it("the sources table is sorted by count", async () => {
    geoBody = geo({ home: HOME, points: [point({ ip: "1.1.1.1", count: 1 }), point({ ip: "2.2.2.2", count: 9 }), point({ ip: "3.3.3.3", count: 4 })] });
    await mount();
    const ips = Array.from(document.querySelectorAll("tbody td.mono")).map((e) => e.textContent);
    expect(ips).toEqual(["2.2.2.2", "3.3.3.3", "1.1.1.1"]);
  });
});

describe("shots", () => {
  it("an alert with a location fires a shot with animateMotion and a ripple at home", async () => {
    geoBody = geo({ home: HOME });
    const { container } = await mount();
    expect(shots(container)).toHaveLength(0);
    alertNow(liveAlert({ severity: "critical" }));
    expect(shots(container)).toHaveLength(1);
    const shot = shots(container)[0];
    expect(shot).toHaveClass("sev-fill-critical");
    const motion = shot.querySelector("animateMotion")!;
    expect(motion.getAttribute("path")).toMatch(/^M/);
    expect(container.querySelectorAll("circle.map-ripple")).toHaveLength(1);
  });

  it("each shot is removed after about 2 s", async () => {
    geoBody = geo({ home: HOME });
    const { container } = await mount();
    alertNow(liveAlert());
    await tick(1900);
    expect(shots(container)).toHaveLength(1);
    await tick(200);
    expect(shots(container)).toHaveLength(0);
    expect(container.querySelectorAll("circle.map-ripple")).toHaveLength(0);
  });

  it("no shot without a location, without a home, or with reduced motion", async () => {
    geoBody = geo({ home: HOME });
    const a = await mount();
    alertNow(liveAlert({ src_geo: null }));
    expect(shots(a.container)).toHaveLength(0);
    a.unmount();
    geoBody = geo({ home: null });
    const b = await mount();
    alertNow(liveAlert());
    expect(shots(b.container)).toHaveLength(0);
    b.unmount();
    geoBody = geo({ home: HOME });
    stubReducedMotion();
    const c = await mount();
    alertNow(liveAlert());
    expect(shots(c.container)).toHaveLength(0);
    expect(screen.getByText(/Animation is off/)).toBeInTheDocument();
    // the point itself still appears
    expect(mapLabel(1)).toBeInTheDocument();
  });

  it("no reduced-motion note when motion is allowed", async () => {
    geoBody = geo({ home: HOME });
    await mount();
    expect(screen.queryByText(/Animation is off/)).toBeNull();
  });

  it("at most MAX_SHOTS at once; the rest are counted as +N more, which clears after 3 s", async () => {
    expect(MAX_SHOTS).toBe(30);
    geoBody = geo({ home: HOME });
    const { container } = await mount();
    for (let i = 0; i < MAX_SHOTS + 5; i++) alertNow(liveAlert({ id: i + 1 }));
    expect(shots(container)).toHaveLength(MAX_SHOTS);
    expect(container.querySelector("span.map-overflow")).toHaveTextContent("+5 more");
    await tick(2100);
    expect(shots(container)).toHaveLength(0);
    expect(container.querySelector("span.map-overflow")).not.toBeNull();
    await tick(1000);
    expect(container.querySelector("span.map-overflow")).toBeNull();
  });

  it("room frees up as shots finish", async () => {
    geoBody = geo({ home: HOME });
    const { container } = await mount();
    for (let i = 0; i < MAX_SHOTS; i++) alertNow(liveAlert({ id: i + 1 }));
    await tick(2100);
    alertNow(liveAlert({ id: 99 }));
    expect(shots(container)).toHaveLength(1);
    expect(container.querySelector("span.map-overflow")).toBeNull();
  });

  it("timers are cleared on unmount", async () => {
    geoBody = geo({ home: HOME });
    const { unmount } = await mount();
    alertNow(liveAlert());
    unmount();
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    await tick(5000);
    expect(err).not.toHaveBeenCalled();
    err.mockRestore();
  });
});

describe("block marks", () => {
  it("rings blocked and would-block sources and marks the arc", async () => {
    geoBody = geo({ home: HOME, points: [point({ ip: "8.8.8.8" }), point({ ip: "7.7.7.7", lon: 10 }), point({ ip: "6.6.6.6", lon: 20 })] });
    blocksBody = [{ id: 1, ip: "8.8.8.8", sensor_id: 1, source: "auto", reason: "", alert_id: null, active: true,
      blocked_at: new Date(T0 - 1000).toISOString(), expires_at: new Date(T0 + 600_000).toISOString(), unblocked_at: null }];
    wouldBody = [{ id: 1, sensor_id: 1, ip: "7.7.7.7", reason: "", source: "auto", alert_id: null, at: new Date(T0 - 1000).toISOString(), ttl_seconds: 600 }];
    const { container } = await mount();
    expect(container.querySelectorAll("circle.map-mark")).toHaveLength(2);
    expect(container.querySelectorAll("circle.map-mark.blocked")).toHaveLength(1);
    expect(container.querySelectorAll("circle.map-mark.would")).toHaveLength(1);
    expect(container.querySelectorAll("path.map-arc.blocked")).toHaveLength(1);
    expect(container.querySelectorAll("path.map-arc")).toHaveLength(3);
    const titles = Array.from(container.querySelectorAll("circle.map-point title")).map((t) => t.textContent);
    expect(titles.find((t) => t!.startsWith("8.8.8.8"))).toContain("· blocked");
    expect(titles.find((t) => t!.startsWith("7.7.7.7"))).toContain("would block (dry-run)");
    expect(titles.find((t) => t!.startsWith("6.6.6.6"))).not.toMatch(/blocked|would/);
  });

  it("live events add and remove rings", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    const { container } = await mount();
    expect(container.querySelectorAll("circle.map-mark")).toHaveLength(0);
    blockNow(blockEv());
    expect(container.querySelectorAll("circle.map-mark.blocked")).toHaveLength(1);
    expect(container.querySelectorAll("path.map-arc.blocked")).toHaveLength(1);
    blockNow(blockEv({ event: "unblocked" }));
    expect(container.querySelectorAll("circle.map-mark")).toHaveLength(0);
    blockNow(blockEv({ event: "would_block", at: new Date(T0).toISOString(), ttl_seconds: 600 }));
    expect(container.querySelectorAll("circle.map-mark.would")).toHaveLength(1);
  });

  it("a mark for an address that is not on the map draws nothing", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    const { container } = await mount();
    blockNow(blockEv({ ip: "4.4.4.4" }));
    expect(container.querySelectorAll("circle.map-mark")).toHaveLength(0);
  });

  it("a ring disappears when the block expires", async () => {
    geoBody = geo({ home: HOME, points: [point()] });
    const { container } = await mount();
    blockNow(blockEv({ expires_at: new Date(T0 + 8000).toISOString() }));
    expect(container.querySelectorAll("circle.map-mark")).toHaveLength(1);
    await tick(12_000);
    expect(container.querySelectorAll("circle.map-mark")).toHaveLength(0);
  });

  it("the legend mentions red and dashed rings", async () => {
    await mount();
    expect(screen.getByText(/Red ring: blocked; dashed ring: a dry-run sensor would block it\./)).toBeInTheDocument();
  });
});

describe("alerts per minute", () => {
  it("counts alerts of the last 60 s", async () => {
    geoBody = geo({ home: HOME });
    await mount();
    expect(screen.getByText("0 / min")).toBeInTheDocument();
    alertNow(liveAlert({ id: 1 })); alertNow(liveAlert({ id: 2 })); alertNow(liveAlert({ id: 3 }));
    await tick(2000);
    expect(screen.getByText("3 / min")).toBeInTheDocument();
    await tick(40_000);
    expect(screen.getByText("3 / min")).toBeInTheDocument();
    await tick(21_000);
    expect(screen.getByText("0 / min")).toBeInTheDocument();
  });

  it("alerts without a location still count", async () => {
    geoBody = geo({ home: HOME });
    await mount();
    alertNow(liveAlert({ src_geo: null }));
    await tick(2000);
    expect(screen.getByText("1 / min")).toBeInTheDocument();
  });

  it("the pill is shown in compact mode too", async () => {
    geoBody = geo({ home: HOME });
    await mount({ compact: true });
    alertNow(liveAlert());
    await tick(2000);
    expect(screen.getByText("1 / min")).toBeInTheDocument();
  });
});

describe("live feed", () => {
  it("is empty at first", async () => {
    await mount();
    expect(screen.getByText("Live feed")).toBeInTheDocument();
    expect(screen.getByText(/Waiting for attacks/)).toBeInTheDocument();
    expect(screen.getByText("live")).toHaveClass("pill");
  });

  it("lists alerts newest first with link, badge and flow", async () => {
    await mount();
    alertNow(liveAlert({ id: 1, predicted_class: "PortScan", severity: "high" }));
    alertNow(liveAlert({ id: 2, predicted_class: "DoS", severity: "critical", src_ip: "5.5.5.5" }));
    const items = feedItems();
    expect(items).toHaveLength(2);
    expect(within(items[0]).getByRole("link", { name: "DoS" })).toHaveAttribute("href", "/alerts/2");
    expect(within(items[0]).getByText("critical")).toHaveClass("badge");
    expect(items[0].textContent).toContain("5.5.5.5 →");
    expect(items[0]).toHaveClass("sev-critical");
    expect(within(items[1]).getByRole("link", { name: "PortScan" })).toHaveAttribute("href", "/alerts/1");
  });

  it("says when an alert is not on the map", async () => {
    await mount();
    alertNow(liveAlert({ id: 1, src_geo: null }));
    alertNow(liveAlert({ id: 2 }));
    const [withGeo, without] = feedItems();
    expect(without.textContent).toContain("(not on the map: no known location)");
    expect(withGeo.textContent).not.toContain("not on the map");
  });

  it("block items: blocked with source, unblocked, would block", async () => {
    await mount();
    blockNow(blockEv({ event: "blocked", source: "analyst", ip: "1.1.1.1", sensor_id: 4, reason: "manual" }));
    blockNow(blockEv({ event: "unblocked", ip: "2.2.2.2" }));
    blockNow(blockEv({ event: "would_block", ip: "3.3.3.3", reason: "" }));
    const [would, unblocked, blocked] = feedItems();
    expect(within(blocked).getByText("blocked · analyst")).toHaveClass("pill", "danger");
    expect(blocked.textContent).toContain("1.1.1.1");
    expect(blocked.textContent).toContain("sensor #4 · manual");
    expect(within(unblocked).getByText("unblocked")).toHaveClass("pill");
    expect(within(would).getByText("would block · dry-run")).toHaveClass("pill", "warn");
    expect(would.textContent).toContain("no reason given");
  });

  it("block reasons are shown on one line", async () => {
    await mount();
    blockNow(blockEv({ reason: "first\nsecond‮third" }));
    expect(feedItems()[0].textContent).toContain("sensor #2 · first second third");
  });

  it("keeps only the last 20 items", async () => {
    await mount();
    for (let i = 1; i <= 25; i++) alertNow(liveAlert({ id: i }));
    const items = feedItems();
    expect(items).toHaveLength(20);
    expect(within(items[0]).getByRole("link")).toHaveAttribute("href", "/alerts/25");
    expect(within(items[19]).getByRole("link")).toHaveAttribute("href", "/alerts/6");
  });

  it("alerts and blocks are mixed in arrival order", async () => {
    await mount();
    alertNow(liveAlert({ id: 1 }));
    blockNow(blockEv());
    const items = feedItems();
    expect(items[0]).toHaveClass("block-blocked");
    expect(items[1]).toHaveClass("sev-high");
  });

  it("the list is a polite live region", async () => {
    await mount();
    alertNow(liveAlert());
    const list = document.querySelector("ol.feed-list")!;
    expect(list).toHaveAttribute("aria-live", "polite");
  });

  it("shows a relative time that updates", async () => {
    await mount();
    alertNow(liveAlert());
    expect(feedItems()[0].querySelector(".feed-time")).toHaveTextContent("now");
    await tick(10_000);
    expect(feedItems()[0].querySelector(".feed-time")).toHaveTextContent("10 s ago");
    await tick(60_000);
    expect(feedItems()[0].querySelector(".feed-time")).toHaveTextContent("1 min ago");
  });

  it("the compact map has no feed, no table and no notice boxes", async () => {
    geoBody = geo({ home: null, demo: true, geoip_status: "off", points: [point()] });
    const { container } = await mount({ compact: true });
    expect(screen.queryByText("Live feed")).toBeNull();
    expect(screen.queryByText("Sources on the map")).toBeNull();
    expect(container.querySelector(".notice-box")).toBeNull();
    expect(screen.getByRole("link", { name: "Open maps →" })).toHaveAttribute("href", "/maps?view=world&hours=6");
  });
});

describe("pause", () => {
  const pauseBtn = () => screen.getByRole("button", { name: /^(Pause|Resume)/ });

  it("is a toggle button with aria-pressed", async () => {
    await mount();
    expect(pauseBtn()).toHaveTextContent("Pause");
    expect(pauseBtn()).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(pauseBtn());
    expect(pauseBtn()).toHaveTextContent("Resume");
    expect(pauseBtn()).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("paused")).toHaveClass("pill", "warn");
  });

  it("while paused: no shots, no feed additions, and a count of what was missed", async () => {
    geoBody = geo({ home: HOME });
    const { container } = await mount();
    fireEvent.click(pauseBtn());
    alertNow(liveAlert({ id: 1 }));
    blockNow(blockEv());
    expect(shots(container)).toHaveLength(0);
    expect(feedItems()).toHaveLength(0);
    expect(pauseBtn()).toHaveTextContent("Resume (2 new)");
    expect(screen.getByText("paused · 2 new")).toBeInTheDocument();
  });

  it("Resume clears the count and shots and the feed work again", async () => {
    geoBody = geo({ home: HOME });
    const { container } = await mount();
    fireEvent.click(pauseBtn());
    alertNow(liveAlert({ id: 1 }));
    fireEvent.click(pauseBtn());
    expect(pauseBtn()).toHaveTextContent(/^Pause$/);
    expect(screen.queryByText(/new/)).toBeNull();
    alertNow(liveAlert({ id: 2 }));
    expect(shots(container)).toHaveLength(1);
    expect(feedItems()).toHaveLength(1);
  });

  it("the per-minute count keeps counting while paused", async () => {
    geoBody = geo({ home: HOME });
    await mount();
    fireEvent.click(pauseBtn());
    alertNow(liveAlert());
    await tick(2000);
    expect(screen.getByText("1 / min")).toBeInTheDocument();
  });

  it("the compact map has no pause button", async () => {
    await mount({ compact: true });
    expect(screen.queryByRole("button", { name: /Pause|Resume/ })).toBeNull();
  });
});

describe("sources table Response column", () => {
  it("blocked, would block · dry-run, observe", async () => {
    geoBody = geo({ home: HOME, points: [
      point({ ip: "1.1.1.1", count: 9 }), point({ ip: "2.2.2.2", count: 5 }), point({ ip: "3.3.3.3", count: 1 }),
    ] });
    blocksBody = [{ id: 1, ip: "1.1.1.1", sensor_id: 1, source: "auto", reason: "", alert_id: null, active: true,
      blocked_at: new Date(T0 - 1000).toISOString(), expires_at: null, unblocked_at: null }];
    wouldBody = [{ id: 1, sensor_id: 1, ip: "2.2.2.2", reason: "", source: "auto", alert_id: null, at: new Date(T0 - 1000).toISOString(), ttl_seconds: null }];
    await mount();
    expect(screen.getByRole("columnheader", { name: "Response" })).toBeInTheDocument();
    const row = (ip: string) => screen.getByText(ip).closest("tr")!;
    expect(within(row("1.1.1.1")).getByText("blocked")).toHaveClass("pill", "danger");
    expect(within(row("2.2.2.2")).getByText("would block · dry-run")).toHaveClass("pill", "warn");
    expect(within(row("3.3.3.3")).getByText("observe")).toHaveClass("pill");
  });

  it("a live block changes the pill", async () => {
    geoBody = geo({ home: HOME, points: [point({ ip: "1.1.1.1" })] });
    await mount();
    expect(screen.getByText("observe")).toBeInTheDocument();
    blockNow(blockEv({ ip: "1.1.1.1" }));
    expect(screen.getByText("blocked")).toBeInTheDocument();
    expect(screen.queryByText("observe")).toBeNull();
  });

  it("empty table text spans the five columns", async () => {
    await mount();
    expect(screen.getByText("No located sources in this window.")).toHaveAttribute("colspan", "5");
  });
});

describe("WorldMap compact", () => {
  const compact = (hours = 24) => show({ hours, compact: true });

  it("shows only the Live attack map card, no sources table", async () => {
    geoBody = geo({ home: HOME, points: [point({ city: "MV" })] });
    compact();
    await screen.findByRole("img", { name: "World map of 1 attack sources" });
    expect(screen.getByText("Live attack map")).toBeInTheDocument();
    expect(screen.queryByText("Where attacks come from")).toBeNull();
    expect(screen.queryByText("Sources on the map")).toBeNull();
    expect(screen.queryByText("8.8.8.8")).toBeNull();
  });

  it("Open maps link carries hours unless 1", async () => {
    const { unmount } = compact(24);
    expect(await screen.findByRole("link", { name: "Open maps →" })).toHaveAttribute("href", "/maps?view=world&hours=24");
    unmount();
    compact(1);
    expect(await screen.findByRole("link", { name: "Open maps →" })).toHaveAttribute("href", "/maps?view=world");
  });

  it("turns setup notices into one muted line", async () => {
    geoBody = geo({ geoip_status: "no database", demo: true, home: null });
    const { container } = compact();
    await screen.findByText("Live attack map");
    expect(container.querySelector(".notice-box")).toBeNull();
    const line = screen.getByText(/made-up demo locations/);
    expect(line.textContent).toContain("Public addresses can't be placed: no database.");
    expect(line.textContent).toContain("No protected site set");
  });

  it("no notice line when everything is configured", async () => {
    geoBody = geo({ home: { lat: 1, lon: 1, label: "Lab" } });
    compact();
    await screen.findByText("Live attack map");
    expect(screen.queryByText(/No protected site set/)).toBeNull();
    expect(screen.queryByText(/can't be placed/)).toBeNull();
  });

  it("before data: one Live attack map card with Loading map…", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string) => { if (p.startsWith("/geo/")) await gate; return base(p); });
    const { container } = compact();
    expect(screen.getByText("Live attack map")).toBeInTheDocument();
    expect(screen.getByText("Loading map…")).toBeInTheDocument();
    expect(container.querySelectorAll(".card").length).toBe(1);
    release();
    await screen.findByRole("img", { name: "World map of 0 attack sources" });
    expect(screen.queryByText("Loading map…")).toBeNull();
  });

  it("first load failure shows the error inside the card, without Loading", async () => {
    geoError = new Error("geo down");
    const { container } = compact();
    const err = await screen.findByText("geo down");
    expect(err.closest(".card")).toHaveTextContent("Live attack map");
    expect(screen.queryByText("Loading map…")).toBeNull();
    expect(container.querySelectorAll(".card").length).toBe(1);
  });

  it("a later failed reload keeps the map and shows the error", async () => {
    compact();
    await screen.findByRole("img", { name: "World map of 0 attack sources" });
    geoError = new Error("later boom");
    act(() => { h.reload!(); });
    expect(await screen.findByText("later boom")).toBeInTheDocument();
    expect(screen.getByText("Live attack map")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "World map of 0 attack sources" })).toBeInTheDocument();
  });
});

describe("LiveFeed source tag", () => {
  it("marks rule alerts only", async () => {
    const { LiveFeed } = await import("../pages/WorldMap");
    const mk = (id: number, o: Record<string, unknown>) => ({
      key: id, kind: "alert" as const, at: T0, located: true,
      alert: { id, predicted_class: `Cls${id}`, severity: "high", src_ip: "1.1.1.1", ...o } as never,
    });
    render(<MemoryRouter><LiveFeed items={[mk(1, { source: "rule" }), mk(2, { source: "ml" }), mk(3, {})]} paused={false} missed={0} now={T0} /></MemoryRouter>);
    const tags = document.querySelectorAll(".source-tag");
    expect(tags).toHaveLength(1);
    expect(tags[0].parentElement).toHaveTextContent("Cls1");
  });
});
