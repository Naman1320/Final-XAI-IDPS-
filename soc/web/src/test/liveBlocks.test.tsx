import { act, cleanup, render, renderHook, screen } from "@testing-library/react";
import { applyBlockEvent, useBlockMarks, useReducedMotion } from "../liveBlocks";

const h = vi.hoisted(() => ({ api: vi.fn(), onBlock: null as null | ((e: unknown) => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../live", () => ({
  useLiveBlocks: (fn: (e: unknown) => void) => { h.onBlock = fn; return true; },
}));

const T0 = Date.parse("2026-03-01T12:00:00Z");
const iso = (ms: number) => new Date(T0 + ms).toISOString();
const ev = (o: Record<string, unknown> = {}) => ({
  type: "block", event: "blocked", sensor_id: 1, ip: "1.1.1.1", source: "auto", at: iso(0),
  expires_at: iso(600_000), ttl_seconds: 600, reason: "r", geo: null, ...o,
}) as never;

describe("applyBlockEvent", () => {
  const empty = () => new Map();
  it("blocked sets blocked with until = expires_at", () => {
    const m = applyBlockEvent(empty(), ev());
    expect(m.get("1.1.1.1")).toEqual({ mark: "blocked", until: T0 + 600_000 });
  });
  it("blocked without expiry has until null; a bad date too", () => {
    expect(applyBlockEvent(empty(), ev({ expires_at: null })).get("1.1.1.1")).toEqual({ mark: "blocked", until: null });
    expect(applyBlockEvent(empty(), ev({ expires_at: "garbage" })).get("1.1.1.1")).toEqual({ mark: "blocked", until: null });
  });
  it("blocked replaces a would mark", () => {
    const m = applyBlockEvent(applyBlockEvent(empty(), ev({ event: "would_block" })), ev());
    expect(m.get("1.1.1.1")!.mark).toBe("blocked");
  });
  it("unblocked removes only a blocked entry", () => {
    const blocked = applyBlockEvent(empty(), ev());
    expect(applyBlockEvent(blocked, ev({ event: "unblocked" })).has("1.1.1.1")).toBe(false);
    const would = applyBlockEvent(empty(), ev({ event: "would_block" }));
    expect(applyBlockEvent(would, ev({ event: "unblocked" })).get("1.1.1.1")!.mark).toBe("would");
    expect(applyBlockEvent(empty(), ev({ event: "unblocked" })).size).toBe(0);
  });
  it("unblocked leaves other addresses alone", () => {
    let m = applyBlockEvent(empty(), ev());
    m = applyBlockEvent(m, ev({ ip: "2.2.2.2" }));
    m = applyBlockEvent(m, ev({ event: "unblocked" }));
    expect([...m.keys()]).toEqual(["2.2.2.2"]);
  });
  it("would_block sets would with until = at + ttl", () => {
    const m = applyBlockEvent(empty(), ev({ event: "would_block", ttl_seconds: 300 }));
    expect(m.get("1.1.1.1")).toEqual({ mark: "would", until: T0 + 300_000 });
  });
  it("would_block with null ttl lasts 1 h", () => {
    const m = applyBlockEvent(empty(), ev({ event: "would_block", ttl_seconds: null }));
    expect(m.get("1.1.1.1")!.until).toBe(T0 + 3600_000);
  });
  it("would_block never replaces a block", () => {
    const m = applyBlockEvent(applyBlockEvent(empty(), ev()), ev({ event: "would_block" }));
    expect(m.get("1.1.1.1")!.mark).toBe("blocked");
  });
  it("a newer would_block replaces an older would", () => {
    let m = applyBlockEvent(empty(), ev({ event: "would_block", ttl_seconds: 60 }));
    m = applyBlockEvent(m, ev({ event: "would_block", ttl_seconds: 600 }));
    expect(m.get("1.1.1.1")!.until).toBe(T0 + 600_000);
  });
  it("returns a new map and does not mutate the old one", () => {
    const a = empty();
    const b = applyBlockEvent(a, ev());
    expect(b).not.toBe(a);
    expect(a.size).toBe(0);
  });
});

describe("useBlockMarks", () => {
  let blocks: unknown[];
  let would: unknown[];
  const blk = (o: Record<string, unknown> = {}) => ({ id: 1, ip: "1.1.1.1", sensor_id: 1, source: "auto", reason: "", alert_id: null, active: true,
    blocked_at: iso(-1000), expires_at: iso(600_000), unblocked_at: null, ...o });
  const wb = (o: Record<string, unknown> = {}) => ({ id: 1, sensor_id: 1, ip: "2.2.2.2", reason: "", source: "auto", alert_id: null, at: iso(-1000), ttl_seconds: 600, ...o });
  const paths = () => h.api.mock.calls.map(([p]) => String(p));
  const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
  const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
  const marks = (r: { current: Map<string, string> }) => Object.fromEntries(r.current);

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    vi.setSystemTime(T0);
    blocks = []; would = [];
    h.onBlock = null;
    h.api.mockReset();
    h.api.mockImplementation(async (p: string) => {
      if (p.startsWith("/blocks/would")) return { items: would, total: would.length, next_cursor: null };
      if (p.startsWith("/blocks")) return { items: blocks, total: blocks.length, next_cursor: null };
      throw new Error(`unexpected ${p}`);
    });
  });
  afterEach(() => { cleanup(); vi.useRealTimers(); });

  it("loads active blocks and 24 h would-blocks", async () => {
    blocks = [blk()]; would = [wb()];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    expect(paths()).toContain("/blocks?active=true&limit=200");
    expect(paths()).toContain("/blocks/would?since_hours=24&limit=200");
    expect(marks(result)).toEqual({ "1.1.1.1": "blocked", "2.2.2.2": "would" });
  });

  it("blocked wins over would for the same address", async () => {
    blocks = [blk({ ip: "3.3.3.3" })]; would = [wb({ ip: "3.3.3.3" })];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    expect(marks(result)).toEqual({ "3.3.3.3": "blocked" });
  });

  it("ignores inactive blocks", async () => {
    blocks = [blk({ active: false })];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    expect(marks(result)).toEqual({});
  });

  it("refreshes every 30 s and stops on unmount", async () => {
    const { unmount } = renderHook(() => useBlockMarks());
    await flush();
    const n = paths().length;
    await tick(30_000);
    expect(paths().length).toBe(n * 2);
    unmount();
    await tick(90_000);
    expect(paths().length).toBe(n * 2);
  });

  it("applies live events", async () => {
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    act(() => h.onBlock!(ev({ ip: "5.5.5.5" })));
    expect(marks(result)).toEqual({ "5.5.5.5": "blocked" });
    act(() => h.onBlock!(ev({ ip: "5.5.5.5", event: "unblocked" })));
    expect(marks(result)).toEqual({});
    act(() => h.onBlock!(ev({ ip: "6.6.6.6", event: "would_block", at: new Date(Date.now()).toISOString(), ttl_seconds: 600 })));
    expect(marks(result)).toEqual({ "6.6.6.6": "would" });
  });

  it("drops entries whose time has passed (5 s clock)", async () => {
    blocks = [blk({ expires_at: iso(20_000) })];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    expect(marks(result)).toEqual({ "1.1.1.1": "blocked" });
    await tick(10_000);
    expect(marks(result)).toEqual({ "1.1.1.1": "blocked" });
    await tick(11_000);
    expect(marks(result)).toEqual({});
  });

  it("a block with no expiry never ages out", async () => {
    blocks = [blk({ expires_at: null })];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    await tick(29_000);
    expect(marks(result)).toEqual({ "1.1.1.1": "blocked" });
  });

  it("would-block ages out at at + ttl", async () => {
    would = [wb({ at: iso(0), ttl_seconds: 15 })];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    expect(marks(result)).toEqual({ "2.2.2.2": "would" });
    await tick(20_000);
    // the 30 s refresh has not run yet, so only expiry filtering applies
    expect(marks(result)).toEqual({});
  });

  it("keeps the old marks when a refresh fails", async () => {
    blocks = [blk()];
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    h.api.mockRejectedValue(new Error("down"));
    await tick(30_000);
    expect(marks(result)).toEqual({ "1.1.1.1": "blocked" });
  });

  it("a refresh replaces live-only marks with the server's truth", async () => {
    const { result } = renderHook(() => useBlockMarks());
    await flush();
    act(() => h.onBlock!(ev({ ip: "5.5.5.5" })));
    expect(marks(result)).toEqual({ "5.5.5.5": "blocked" });
    await tick(30_000);
    expect(marks(result)).toEqual({});
  });
});

describe("useReducedMotion", () => {
  type Listener = () => void;
  let matches: boolean;
  let listeners: Set<Listener>;
  beforeEach(() => {
    matches = false;
    listeners = new Set();
    vi.stubGlobal("matchMedia", vi.fn((q: string) => ({
      get matches() { return matches; }, media: q,
      addEventListener: (_: string, fn: Listener) => listeners.add(fn),
      removeEventListener: (_: string, fn: Listener) => listeners.delete(fn),
    })));
  });
  afterEach(() => vi.unstubAllGlobals());

  function Show() { return <span>{String(useReducedMotion())}</span>; }

  it("queries prefers-reduced-motion: reduce", () => {
    render(<Show />);
    expect(window.matchMedia).toHaveBeenCalledWith("(prefers-reduced-motion: reduce)");
  });
  it("starts from the current setting", () => {
    matches = true;
    render(<Show />);
    expect(screen.getByText("true")).toBeInTheDocument();
  });
  it("follows changes while mounted", () => {
    render(<Show />);
    expect(screen.getByText("false")).toBeInTheDocument();
    act(() => { matches = true; listeners.forEach((fn) => fn()); });
    expect(screen.getByText("true")).toBeInTheDocument();
    act(() => { matches = false; listeners.forEach((fn) => fn()); });
    expect(screen.getByText("false")).toBeInTheDocument();
  });
  it("removes its listener on unmount", () => {
    const { unmount } = render(<Show />);
    expect(listeners.size).toBe(1);
    unmount();
    expect(listeners.size).toBe(0);
  });
  it("is false when matchMedia is missing", () => {
    vi.unstubAllGlobals();
    // jsdom has no matchMedia by default
    expect((window as { matchMedia?: unknown }).matchMedia).toBeUndefined();
    render(<Show />);
    expect(screen.getByText("false")).toBeInTheDocument();
  });
});
