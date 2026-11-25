import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { report, sensorState, sensorsStatus } from "./sensor-fixtures";
import ThreatCenter, { ago, lastSevenDays, searchTarget, TC_WINDOWS } from "../pages/ThreatCenter";

const h = vi.hoisted(() => ({ api: vi.fn(), onAlert: null as null | ((a: unknown) => void), reload: null as null | (() => void), reloadAll: null as null | (() => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (f: () => void, onAlert?: (a: unknown) => void, every?: number) => {
    if (onAlert) { h.onAlert = onAlert; h.reload = f; } else if (every === undefined) h.reloadAll = f;
    return true;
  },
}));
vi.mock("../pages/WorldMap", () => ({
  default: (p: { hours: number; compact?: boolean }) => <div>map-stub hours={p.hours} compact={String(!!p.compact)}</div>,
}));

const iso = (ms: number) => new Date(Date.now() + ms).toISOString();
const alert = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 1, predicted_class: "PortScan", confidence: 0.9, severity: "high", status: "new",
  src_ip: "10.0.0.1", src_port: 1000, dst_ip: "10.0.0.9", dst_port: 22, protocol: "TCP",
  received_at: iso(-5 * 60_000), ...o,
});
const block = (o: Record<string, unknown> = {}) => ({
  id: 1, ip: "10.0.0.1", sensor_id: 1, source: "auto", reason: "scan", alert_id: null, active: true,
  blocked_at: iso(-60_000), expires_at: iso(600_000), unblocked_at: null, ...o,
});
const action = (o: Record<string, unknown> = {}) => ({
  id: 3, kind: "block_ip", status: "pending", proposed_by: "assistant", sensor_id: 1, reason: "looks bad",
  params: { ip: "10.0.0.5", ttl_seconds: 900 }, result: null, created_at: iso(-1000), ...o,
});
const metrics = (o: Record<string, unknown> = {}) => ({
  alerts_total: 1234, by_class: { PortScan: 50, DoS: 10 }, top_sources: [{ ip: "10.0.0.1", count: 7 }],
  alerts_per_bucket: [{ count: 1 }, { count: 4 }], detection_latency: { p50_ms: 1500, p95_ms: 4000 },
  active_blocks: 2, false_positive_rate: 0.2, false_positives: 2, triaged: 10, ...o,
});

let d: {
  would: unknown[]; sensors: unknown;
  metrics: unknown; blocks: unknown[]; alerts: unknown[]; actions: unknown[]; next: string | null; topo: unknown;
};
const page = (items: unknown[], next_cursor: string | null = null) => ({ items, total: items.length, next_cursor });
const calls = (prefix: string) => h.api.mock.calls.map(([p]) => String(p)).filter((p) => p.startsWith(prefix));

beforeEach(() => {
  d = { would: [], sensors: sensorsStatus(), metrics: metrics(), blocks: [], alerts: [], actions: [], next: null, topo: { hours: 24, nodes: [], edges: [] } };
  h.api.mockReset();
  h.onAlert = null;
  h.api.mockImplementation(async (path: string) => {
    if (path.startsWith("/metrics/summary")) return d.metrics;
    if (path.startsWith("/sensors/status")) return d.sensors;
    if (path.startsWith("/blocks/would")) return page(d.would);
    if (path.startsWith("/blocks")) return page(d.blocks);
    if (path.startsWith("/alerts")) return page(d.alerts);
    if (path.startsWith("/actions")) return page(d.actions, d.next);
    if (path.startsWith("/topology")) return d.topo;
    throw new Error(`unexpected ${path}`);
  });
});

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname + l.search}</div>; }
const show = (url = "/") => render(<MemoryRouter initialEntries={[url]}><ThreatCenter /><Loc /></MemoryRouter>);
const loc = () => screen.getByTestId("loc").textContent;
const liveCard = () => screen.getByText("Live alerts").closest(".card") as HTMLElement;
const cardOf = (title: string) => screen.getByText(title).closest(".card") as HTMLElement;
const bodyRows = () => within(liveCard()).getAllByRole("row").slice(1);

describe("ago", () => {
  const now = Date.parse("2026-01-01T12:00:00Z");
  it.each([
    ["2026-01-01T11:59:30Z", "just now"],
    ["2026-01-01T12:00:30Z", "just now"], // future clamps to 0
    ["2026-01-01T11:56:00Z", "4 min ago"],
    ["2026-01-01T09:00:00Z", "3 h ago"],
    ["2025-12-30T12:00:00Z", "2 d ago"],
    ["2026-01-01T11:59:00Z", "1 min ago"],
    ["nonsense", "—"],
  ])("%s -> %s", (iso_, text) => { expect(ago(iso_, now)).toBe(text); });
});

describe("searchTarget", () => {
  it.each([
    ["42", "/alerts/42"], ["#42", "/alerts/42"], ["  #7 ", "/alerts/7"],
    ["10.0.0.1", "/alerts?ip=10.0.0.1"], ["::1", "/alerts?ip=%3A%3A1"], ["fe80::1", "/alerts?ip=fe80%3A%3A1"],
    ["PortScan", "/alerts?class=PortScan"], ["DoS Hulk", "/alerts?class=DoS+Hulk"],
  ])("%s -> %s", (raw, to) => {
    const got = searchTarget(raw)!;
    expect(decodeURIComponent(got.replace(/\+/g, " "))).toBe(decodeURIComponent(to.replace(/\+/g, " ")));
  });
  it.each([[""], ["   "]])("blank -> null", (raw) => { expect(searchTarget(raw)).toBeNull(); });
});

it("TC_WINDOWS is 1, 24, 168", () => { expect(TC_WINDOWS).toEqual([1, 24, 168]); });

describe("requests and window", () => {
  it("fetches every endpoint with defaults and passes compact to the map", async () => {
    show();
    await screen.findByText("1,234");
    expect(calls("/metrics/summary")).toEqual(["/metrics/summary?hours=24"]);
    expect(calls("/blocks")).toEqual(["/blocks?active=true&limit=200", "/blocks/would?since_hours=24&limit=200"]);
    expect(calls("/sensors/status")).toEqual(["/sensors/status"]);
    expect(calls("/alerts")).toEqual(["/alerts?limit=10"]);
    expect(calls("/actions")).toEqual(["/actions?status=pending&limit=20"]);
    expect(calls("/topology")).toEqual(["/topology?hours=24"]);
    expect(await screen.findByText("map-stub hours=24 compact=true")).toBeInTheDocument();
  });

  it("?hours=168 is honoured; an invalid value falls back to 24", async () => {
    show("/?hours=168");
    await screen.findByText("1,234");
    expect(calls("/metrics/summary")).toEqual(["/metrics/summary?hours=168"]);
    expect(screen.getByLabelText("Window")).toHaveValue("168");
  });

  it("invalid hours -> 24", async () => {
    show("/?hours=5");
    await screen.findByText("1,234");
    expect(screen.getByLabelText("Window")).toHaveValue("24");
  });

  it("changing the window sets ?hours=, default 24 is omitted, and data refetches", async () => {
    show();
    await screen.findByText("1,234");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "1" } });
    await waitFor(() => expect(loc()).toBe("/?hours=1"));
    await waitFor(() => expect(calls("/metrics/summary")).toContain("/metrics/summary?hours=1"));
    expect(calls("/topology")).toContain("/topology?hours=1");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "24" } });
    await waitFor(() => expect(loc()).toBe("/"));
  });
});

describe("search", () => {
  const submit = (text: string) => {
    fireEvent.change(screen.getByLabelText("Search alerts"), { target: { value: text } });
    fireEvent.submit(screen.getByRole("search"));
  };
  it.each([
    ["#12", "/alerts/12"], ["12", "/alerts/12"], ["1.2.3.4", "/alerts?ip=1.2.3.4"], ["PortScan", "/alerts?class=PortScan"],
  ])("%s navigates to %s", async (text, to) => {
    show();
    await screen.findByText("1,234");
    submit(text);
    expect(loc()).toBe(to);
  });
  it("blank does not navigate", async () => {
    show();
    await screen.findByText("1,234");
    submit("  ");
    expect(loc()).toBe("/");
  });
});

describe("KPIs", () => {
  it("shows values, latency, false positives and class line", async () => {
    show();
    expect(await screen.findByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("p95 4.0 s")).toBeInTheDocument();
    expect(screen.getByText("2 of 10 triaged")).toBeInTheDocument();
    expect(screen.getByText("PortScan 50 · DoS 10")).toBeInTheDocument();
    expect(within(cardOf("Active blocks")).getByText("2")).toBeInTheDocument();
  });
  it("shows placeholders while loading and a dash without latency", async () => {
    d.metrics = metrics({ detection_latency: null });
    show();
    expect(within(cardOf("Alerts")).getByText("…")).toBeInTheDocument();
    await screen.findByText("1,234");
    expect(within(cardOf("Detection latency (p50)")).getByText("—")).toBeInTheDocument();
  });
  it("shows a metrics error", async () => {
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string) => {
      if (p.startsWith("/metrics")) throw new Error("metrics down");
      return base(p);
    });
    show();
    expect(await screen.findByText("metrics down")).toBeInTheDocument();
  });
});

describe("attack classes and sources", () => {
  it("links classes and top sources", async () => {
    show();
    const classes = within(await screen.findByText("Attack classes").then((e) => e.closest(".card") as HTMLElement));
    expect(classes.getByRole("link", { name: "PortScan" })).toHaveAttribute("href", "/alerts?class=PortScan");
    expect(classes.getByRole("link", { name: "10.0.0.1" })).toHaveAttribute("href", "/alerts?ip=10.0.0.1");
    expect(classes.getByText("7 alerts")).toBeInTheDocument();
  });
  it("empty states", async () => {
    d.metrics = metrics({ by_class: {}, top_sources: [] });
    show();
    expect(await screen.findByText("No alerts in this window.")).toBeInTheDocument();
    expect(screen.getByText("None in this window.")).toBeInTheDocument();
  });
});

describe("live alerts table", () => {
  beforeEach(() => {
    d.alerts = [
      alert({ id: 1, severity: "low", confidence: 0.99, src_ip: "10.0.0.1" }),
      alert({ id: 2, severity: "critical", confidence: 0.5, src_ip: "10.0.0.2" }),
      alert({ id: 3, severity: "high", confidence: 0.7, src_ip: "10.0.0.3" }),
    ];
  });
  const ids = () => bodyRows().map((r) => /#(\d+)/.exec(r.textContent ?? "")![1]);

  it("sorts newest first by default, then by severity and confidence", async () => {
    show();
    await within(liveCard()).findByText("#3 · 5 min ago");
    expect(ids()).toEqual(["3", "2", "1"]);
    fireEvent.change(within(liveCard()).getByLabelText("Sort"), { target: { value: "severity" } });
    expect(ids()).toEqual(["2", "3", "1"]);
    fireEvent.change(within(liveCard()).getByLabelText("Sort"), { target: { value: "confidence" } });
    expect(ids()).toEqual(["1", "3", "2"]);
    expect(calls("/alerts").length).toBe(1);
  });

  it("severity filter refetches with severity", async () => {
    show();
    await within(liveCard()).findByText("#3 · 5 min ago");
    fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
    await waitFor(() => expect(calls("/alerts")).toContain("/alerts?severity=high&limit=10"));
  });

  it("empty states", async () => {
    d.alerts = [];
    show();
    expect(await screen.findByText("No alerts yet.")).toBeInTheDocument();
    fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
    expect(await screen.findByText("No alerts yet with severity high.")).toBeInTheDocument();
  });

  it("clicking a row opens the alert; the class link too", async () => {
    show();
    const links = await within(liveCard()).findAllByRole("link", { name: "PortScan" });
    expect(links[0]).toHaveAttribute("href", "/alerts/3");
    fireEvent.click(bodyRows()[1]);
    expect(loc()).toBe("/alerts/2");
  });

  it("Response column: blocked with source, else observe", async () => {
    d.blocks = [
      block({ id: 1, ip: "10.0.0.1", source: "auto" }),
      block({ id: 2, ip: "10.0.0.2", source: "analyst" }),
      block({ id: 3, ip: "10.0.0.2", source: "auto" }), // newest-first: first one wins
      block({ id: 4, ip: "10.0.0.3", source: "auto", active: false }),
    ];
    show();
    await within(liveCard()).findByText("blocked · auto");
    const rows = Object.fromEntries(bodyRows().map((r) => [/#(\d+)/.exec(r.textContent!)![1], r.textContent]));
    expect(rows["1"]).toContain("blocked · auto");
    expect(rows["2"]).toContain("blocked · analyst");
    expect(rows["3"]).toContain("observe");
  });

  describe("live feed", () => {
    it("prepends new alerts, dedupes, and caps at 10", async () => {
      d.alerts = Array.from({ length: 10 }, (_, i) => alert({ id: i + 1 }));
      show();
      await within(liveCard()).findByText("#10 · 5 min ago");
      act(() => h.onAlert!(alert({ id: 11, predicted_class: "Fresh" })));
      expect(bodyRows().length).toBe(10);
      expect(ids()[0]).toBe("11");
      expect(ids()).not.toContain("10"); // the last row falls off the end
      const before = bodyRows().length;
      act(() => h.onAlert!(alert({ id: 11 })));
      expect(bodyRows().length).toBe(before);
      expect(bodyRows()[0]).toHaveClass("fresh");
    });

    it("ignores alerts that do not match the severity filter", async () => {
      show();
      await within(liveCard()).findByText("#3 · 5 min ago");
      fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
      await waitFor(() => expect(calls("/alerts").length).toBe(2));
      act(() => h.onAlert!(alert({ id: 20, severity: "low" })));
      expect(ids()).not.toContain("20");
      act(() => h.onAlert!(alert({ id: 21, severity: "high" })));
      expect(ids()).toContain("21");
    });

    it("shows Live status", async () => {
      show();
      expect(await screen.findByText("Live")).toBeInTheDocument();
    });
  });
});

describe("firewall card", () => {
  it("hides expired blocks, shows 3 and an All N link", async () => {
    d.blocks = [
      block({ id: 1, ip: "1.1.1.1" }), block({ id: 2, ip: "2.2.2.2" }), block({ id: 3, ip: "3.3.3.3" }),
      block({ id: 4, ip: "4.4.4.4" }),
      block({ id: 5, ip: "5.5.5.5", blocked_at: iso(-120_000), expires_at: iso(-60_000) }),
    ];
    show();
    const card = within(await screen.findByText("Firewall · nftables").then((e) => e.closest(".card") as HTMLElement));
    await waitFor(() => expect(card.getByText("4 active")).toBeInTheDocument());
    expect(card.getByRole("link", { name: "1.1.1.1" })).toHaveAttribute("href", "/alerts?ip=1.1.1.1");
    expect(card.queryByText("4.4.4.4")).toBeNull();
    expect(card.queryByText("5.5.5.5")).toBeNull();
    expect(card.getByRole("link", { name: "All 4 blocks →" })).toHaveAttribute("href", "/response");
  });

  it("3 or fewer: plain link; none: empty text", async () => {
    show();
    expect(await screen.findByText("No address is blocked right now.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All blocks →" })).toHaveAttribute("href", "/response");
    expect(screen.getByText("0 active")).toBeInTheDocument();
  });

  it("shows the reason or a fallback", async () => {
    d.blocks = [block({ reason: "scan" }), block({ id: 2, ip: "9.9.9.9", reason: "" })];
    show();
    expect(await screen.findByText("auto · scan")).toBeInTheDocument();
    expect(screen.getByText("auto · no reason given")).toBeInTheDocument();
  });
});

describe("decisions card", () => {
  it("empty", async () => {
    show();
    expect(await screen.findByText("Nothing waits for a decision.")).toBeInTheDocument();
    expect(screen.getByText("0 pending")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open response queue →" })).toHaveAttribute("href", "/response");
    expect(screen.getByRole("link", { name: "Create case" })).toHaveAttribute("href", "/cases?new=1");
  });

  it("count, up to 3 items, summary text and link", async () => {
    d.actions = [1, 2, 3, 4].map((i) => action({ id: i, proposed_by: i === 2 ? "user" : "assistant" }));
    show();
    const card = within(await screen.findByText("Needs your decision").then((e) => e.closest(".card") as HTMLElement));
    expect(await card.findByText("4 pending")).toBeInTheDocument();
    expect(card.getAllByText("block ip 10.0.0.5 · 15 min · sensor #1")).toHaveLength(3);
    expect(card.getByText("Proposed by an analyst")).toBeInTheDocument();
    expect(card.getAllByText("Proposed by the assistant")).toHaveLength(2);
    expect(card.getAllByText("“looks bad”")).toHaveLength(3);
    expect(card.getByRole("link", { name: "Decide in Response →" })).toHaveAttribute("href", "/response");
  });

  it("next_cursor makes the count N+", async () => {
    d.actions = [action()];
    d.next = "more";
    show();
    expect(await screen.findByText("1+ pending")).toBeInTheDocument();
  });
});

describe("sensor health and topology", () => {
  it("sensor health with no sensors registered", async () => {
    show();
    expect(await screen.findByText(/No sensors registered/)).toBeInTheDocument();
  });

  it("topology summary: counts, top 4 edges by count, link opens Maps", async () => {
    d.topo = {
      hours: 168,
      nodes: [{ ip: "a" }, { ip: "b" }, { ip: "c" }],
      edges: ["1", "2", "3", "4", "5"].map((n, i) => ({ src: `s${n}`, dst: "t", count: i + 1, max_severity: "high" })),
    };
    show("/?hours=168");
    expect(await screen.findByText("3 hosts · 5 links, last 7 days")).toBeInTheDocument();
    const card = within(cardOf("Topology"));
    expect(card.getAllByRole("listitem")).toHaveLength(4);
    expect(card.getByText("s5 → t")).toBeInTheDocument();
    expect(card.queryByText("s1 → t")).toBeNull();
    expect(card.getByRole("link", { name: "Open →" })).toHaveAttribute("href", "/maps");
  });

  it("topology link omits hours for 1 h; empty edges text", async () => {
    show("/?hours=1");
    expect(await screen.findByText("No traffic with alerts in this window.")).toBeInTheDocument();
    expect(within(cardOf("Topology")).getByRole("link", { name: "Open →" })).toHaveAttribute("href", "/maps");
  });
});

describe("searchTarget with known classes", () => {
  const known = ["PortScan", "DoS Hulk", "DDoS", "(other)"];
  it("matches a known class ignoring case", () => {
    expect(searchTarget("portscan", known)).toBe("/alerts?class=PortScan");
  });
  it("a unique partial picks the class", () => {
    expect(searchTarget("hulk", known)).toBe("/alerts?class=DoS+Hulk");
  });
  it("an ambiguous partial is sent as typed", () => {
    expect(searchTarget("dos", known)).toBe("/alerts?class=dos");
  });
  it("(other) is never chosen, by exact or partial match", () => {
    expect(searchTarget("(other)", known)).toBe("/alerts?class=%28other%29");
    expect(searchTarget("other", known)).toBe("/alerts?class=other");
  });
  it("unknown text and no known list are sent as typed; numbers and IPs win", () => {
    expect(searchTarget("zzz", known)).toBe("/alerts?class=zzz");
    expect(searchTarget("portscan")).toBe("/alerts?class=portscan");
    expect(searchTarget("7", known)).toBe("/alerts/7");
    expect(searchTarget("1.2.3.4", known)).toBe("/alerts?ip=1.2.3.4");
  });
  it("the page passes the by_class keys", async () => {
    d.metrics = metrics({ by_class: { "DoS Hulk": 5, PortScan: 3 } });
    show();
    await screen.findByText("1,234");
    fireEvent.change(screen.getByLabelText("Search alerts"), { target: { value: "hulk" } });
    fireEvent.submit(screen.getByRole("search"));
    expect(loc()).toBe("/alerts?class=DoS+Hulk");
  });
});

describe("review fixes", () => {
  afterEach(() => vi.useRealTimers());

  it("(other) is plain text, not a link", async () => {
    d.metrics = metrics({ by_class: { PortScan: 5, "(other)": 2 } });
    show();
    const card = within(await screen.findByText("Attack classes").then((e) => e.closest(".card") as HTMLElement));
    expect(card.getByText("other classes")).toBeInTheDocument();
    expect(card.queryByRole("link", { name: /other/ })).toBeNull();
    expect(card.getByRole("link", { name: "PortScan" })).toBeInTheDocument();
  });

  it("Response column ignores blocks that have expired", async () => {
    d.alerts = [alert({ id: 1, src_ip: "10.0.0.1" }), alert({ id: 2, src_ip: "10.0.0.2" })];
    d.blocks = [
      block({ ip: "10.0.0.1", blocked_at: iso(-120_000), expires_at: iso(-60_000) }),
      block({ id: 2, ip: "10.0.0.2" }),
    ];
    show();
    await within(liveCard()).findByText("blocked · auto");
    const txt = bodyRows().map((r) => r.textContent!);
    expect(txt.find((t) => t.includes("#1 "))).toContain("observe");
    expect(txt.find((t) => t.includes("#2 "))).toContain("blocked · auto");
  });

  it("a paged /blocks shows N+ active and All N+ blocks", async () => {
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (path: string) => {
      if (path.startsWith("/blocks?")) return page([1, 2, 3, 4].map((i) => block({ id: i, ip: `1.1.1.${i}` })), "more");
      return base(path);
    });
    show();
    expect(await screen.findByText("4+ active")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All 4+ blocks →" })).toHaveAttribute("href", "/response");
  });

  it("without next_cursor there is no plus", async () => {
    d.blocks = [block()];
    show();
    expect(await screen.findByText("1 active")).toBeInTheDocument();
  });

  it("the empty row stays visible while a reload is in flight", async () => {
    show();
    expect(await screen.findByText("No alerts yet.")).toBeInTheDocument();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (path: string) => {
      if (path.startsWith("/alerts")) { await gate; return page([]); }
      return base(path);
    });
    act(() => { h.reload!(); });
    expect(screen.getByText("No alerts yet.")).toBeInTheDocument();
    release();
    await waitFor(() => expect(screen.getByText("No alerts yet.")).toBeInTheDocument());
  });

  it("a live row loses fresh after 2 s; timers are cleared on unmount", async () => {
    d.alerts = [alert({ id: 1 })];
    const { unmount } = show();
    await within(liveCard()).findByText("#1 · 5 min ago");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    act(() => h.onAlert!(alert({ id: 2 })));
    expect(bodyRows()[0]).toHaveClass("fresh");
    act(() => { vi.advanceTimersByTime(1900); });
    expect(bodyRows()[0]).toHaveClass("fresh");
    act(() => { vi.advanceTimersByTime(200); });
    expect(bodyRows()[0]).not.toHaveClass("fresh");
    act(() => h.onAlert!(alert({ id: 3 })));
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("decisions poll /actions every 15 s and a live alert does not refetch them", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "setTimeout", "clearTimeout"] });
    show();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    expect(calls("/actions").length).toBe(1);
    act(() => h.onAlert!(alert({ id: 50 })));
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(calls("/actions").length).toBe(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(calls("/actions").length).toBe(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    expect(calls("/actions").length).toBe(3);
  });

  it("the decisions interval stops on unmount", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "setTimeout", "clearTimeout"] });
    const { unmount } = show();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(calls("/actions").length).toBe(1);
  });

  it("topology edge badge has sr-only text and a title", async () => {
    d.topo = { hours: 24, nodes: [{ ip: "a" }], edges: [{ src: "a", dst: "b", count: 3, max_severity: "high" }] };
    show();
    const sr = await screen.findByText("alerts, highest severity high", { exact: false });
    expect(sr).toHaveClass("sr-only");
    expect(sr.closest(".badge")).toHaveAttribute("title", "highest severity: high");
    expect(sr.closest(".badge")).toHaveTextContent("3 alerts, highest severity high");
  });

  it("the lazy map sits in one .stack cell", async () => {
    show();
    const map = await screen.findByText(/map-stub/);
    expect(map.parentElement).toHaveClass("stack");
    expect(map.parentElement!.children.length).toBe(1);
  });
});

describe("lastSevenDays", () => {
  it("is 7 UTC dates, oldest first", () => {
    expect(lastSevenDays(Date.UTC(2026, 5, 15, 12))).toEqual(
      ["2026-06-09", "2026-06-10", "2026-06-11", "2026-06-12", "2026-06-13", "2026-06-14", "2026-06-15"]);
  });
  it("crosses a month boundary", () => {
    expect(lastSevenDays(Date.UTC(2026, 2, 1, 0, 0, 1))).toEqual(
      ["2026-02-23", "2026-02-24", "2026-02-25", "2026-02-26", "2026-02-27", "2026-02-28", "2026-03-01"]);
  });
  it("includes 29 Feb in a leap year", () => {
    expect(lastSevenDays(Date.UTC(2024, 2, 1, 5))).toEqual(
      ["2024-02-24", "2024-02-25", "2024-02-26", "2024-02-27", "2024-02-28", "2024-02-29", "2024-03-01"]);
  });
  it("crosses a year boundary", () => {
    expect(lastSevenDays(Date.UTC(2026, 0, 2, 9))[0]).toBe("2025-12-27");
    expect(lastSevenDays(Date.UTC(2026, 0, 2, 9))[6]).toBe("2026-01-02");
  });
  it("flips exactly at UTC midnight", () => {
    expect(lastSevenDays(Date.UTC(2026, 1, 28, 23, 59, 59))[6]).toBe("2026-02-28");
    expect(lastSevenDays(Date.UTC(2026, 2, 1, 0, 0, 0))[6]).toBe("2026-03-01");
  });
});

describe("class by day heatmap", () => {
  const days = lastSevenDays(Date.now());
  const row = (cls: string, counts: number[]) => counts.map((count, i) => ({ day: days[i], class: cls, count })).filter((r) => r.count);
  const heatRows = (t: HTMLElement) => Array.from(t.querySelectorAll("tbody tr")) as HTMLElement[];
  const names = (t: HTMLElement) => heatRows(t).map((r) => r.querySelector("th")!.textContent);

  it("is absent without by_class_per_day", async () => {
    show();
    await screen.findByText("1,234");
    expect(screen.queryByText(/Alerts per class per day/)).toBeNull();
    expect(document.querySelector("table.heatmap")).toBeNull();
  });

  it("shows the top 5 classes, the rest summed into other classes before Anomaly", async () => {
    d.metrics = metrics({
      anomaly_per_day: [{ day: days[6], count: 999 }],
      by_class_per_day: [
        ...row("C1", [0, 0, 0, 0, 0, 0, 60]), ...row("C2", [0, 0, 0, 0, 0, 0, 50]), ...row("C3", [0, 0, 0, 0, 0, 0, 40]),
        ...row("C4", [0, 0, 0, 0, 0, 0, 30]), ...row("C5", [0, 0, 0, 0, 0, 0, 20]),
        ...row("C6", [0, 0, 0, 0, 0, 5, 10]), ...row("C7", [0, 0, 0, 0, 0, 1, 2]),
        ...row("(other)", [0, 0, 0, 0, 0, 0, 1]),
      ],
    });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    expect(names(t)).toEqual(["C1", "C2", "C3", "C4", "C5", "other classes", "Anomaly"]);
    const other = Array.from(heatRows(t)[5].querySelectorAll("td")).map((c) => c.textContent);
    expect(other.slice(5)).toEqual(["6", "13"]); // C6 + C7 (+ the API's (other) on the last day)
    expect(heatRows(t).at(-1)).toHaveClass("anomaly");
    expect(heatRows(t).filter((r) => r.classList.contains("anomaly")).length).toBe(1);
    expect(heatRows(t).at(-1)!.querySelectorAll("td")[6].textContent).toBe("999");
  });

  it("the Anomaly row exists, with zeros, whenever anomaly_per_day exists, even empty", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: row("A", [0, 0, 0, 0, 0, 0, 1]) });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    expect(heatRows(t).at(-1)).toHaveClass("anomaly");
    expect(names(t).at(-1)).toBe("Anomaly");
    expect(Array.from(heatRows(t).at(-1)!.querySelectorAll("td")).every((c) => c.classList.contains("heat-0"))).toBe(true);
  });

  it("no Anomaly row when anomaly_per_day is absent", async () => {
    d.metrics = metrics({ by_class_per_day: row("A", [0, 0, 0, 0, 0, 0, 1]) });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    expect(names(t)).toEqual(["A"]);
    expect(t.querySelector("tr.anomaly")).toBeNull();
  });

  it("anomaly counts fill the Anomaly row by day and count in the heat scale", async () => {
    d.metrics = metrics({ anomaly_per_day: row("x", [0, 4, 0, 0, 0, 0, 8]).map(({ day, count }) => ({ day, count })), by_class_per_day: row("A", [0, 0, 0, 0, 0, 0, 2]) });
    show();
    await screen.findByText("1,234");
    const cells = Array.from(document.querySelector("tr.anomaly")!.querySelectorAll("td"));
    expect(cells[1].textContent).toBe("4");
    expect(cells[6].textContent).toBe("8");
    expect(cells[6]).toHaveClass("heat-4");
    expect(cells[1]).toHaveClass("heat-2");
    expect(cells[6]).toHaveAttribute("title", `Anomaly, ${days[6]}: 8`);
  });

  it("a real class named Anomaly is an ordinary class row and does not mix with the outlier row", async () => {
    d.metrics = metrics({
      anomaly_per_day: [{ day: days[6], count: 3 }],
      by_class_per_day: [...row("Anomaly", [0, 0, 0, 0, 0, 0, 50]), ...row("B", [0, 0, 0, 0, 0, 0, 10])],
    });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    expect(names(t)).toEqual(["Anomaly", "B", "Anomaly"]);
    const rows = heatRows(t);
    expect(rows[0]).not.toHaveClass("anomaly");
    expect(rows[0].querySelectorAll("td")[6].textContent).toBe("50");
    expect(rows[2]).toHaveClass("anomaly");
    expect(rows[2].querySelectorAll("td")[6].textContent).toBe("3");
  });

  it("(other) from the API is never a top row, even when it is the biggest", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: [...row("(other)", [0, 0, 0, 0, 0, 0, 500]), ...row("A", [0, 0, 0, 0, 0, 0, 1])] });
    show();
    await screen.findByText("1,234");
    expect(names(document.querySelector("table.heatmap") as HTMLElement)).toEqual(["A", "other classes", "Anomaly"]);
  });

  it("no other row when nothing lies beyond the top 5", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: ["A", "B", "C", "D", "E"].flatMap((c, i) => row(c, [0, 0, 0, 0, 0, 0, 10 - i])) });
    show();
    await screen.findByText("1,234");
    expect(names(document.querySelector("table.heatmap") as HTMLElement)).toEqual(["A", "B", "C", "D", "E", "Anomaly"]);
  });

  it("column headers carry an sr-only full date", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: row("A", [0, 0, 0, 0, 0, 0, 1]) });
    show();
    await screen.findByText("1,234");
    const heads = Array.from(document.querySelectorAll("table.heatmap thead th")).slice(1);
    heads.forEach((th, i) => {
      expect(th.querySelector(".sr-only")).toHaveTextContent(days[i]);
    });
  });

  it("Anomaly is its own last row even with no anomaly data; totals use the sum over days", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: [...row("Small", [5, 5, 5, 5, 5, 5, 5]), ...row("Big", [0, 0, 0, 0, 0, 0, 30])] });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    expect(names(t)).toEqual(["Small", "Big", "Anomaly"]);
  });

  it("(other) is shown as other classes", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: row("(other)", [0, 0, 0, 0, 0, 0, 3]) });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    expect(names(t)[0]).toBe("other classes");
  });

  it("has 7 day columns, empty cells with sr-only 0, and heat levels 0 to 4", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: row("Hot", [0, 1, 25, 50, 75, 100, 0]) });
    show();
    await screen.findByText("1,234");
    const t = document.querySelector("table.heatmap") as HTMLElement;
    const heads = t.querySelectorAll("thead th");
    expect(heads.length).toBe(8);
    expect(heads[1]).toHaveAttribute("title", days[0]);
    const cells = Array.from(heatRows(t)[0].querySelectorAll("td")) as HTMLElement[];
    expect(cells.length).toBe(7);
    expect(cells[0]).toHaveClass("heat-0");
    expect(cells[0].querySelector(".sr-only")).toHaveTextContent("0");
    expect(cells[0].textContent).toBe("0");
    expect(cells[1]).toHaveClass("heat-1");
    expect(cells[1].textContent).toBe("1");
    expect(cells[2]).toHaveClass("heat-1");
    expect(cells[3]).toHaveClass("heat-2");
    expect(cells[4]).toHaveClass("heat-3");
    expect(cells[5]).toHaveClass("heat-4");
    expect(cells[5].textContent).toBe("100");
    expect(cells[5].querySelector(".sr-only")).toHaveTextContent("");
    expect(cells[6]).toHaveClass("heat-0");
    // the Anomaly row is all zeros
    const anomaly = Array.from(heatRows(t).at(-1)!.querySelectorAll("td"));
    expect(anomaly.every((c) => c.classList.contains("heat-0"))).toBe(true);
  });

  it("ties in the weekly total sort by name", async () => {
    d.metrics = metrics({ anomaly_per_day: [], by_class_per_day: [...row("Zed", [0, 0, 0, 0, 0, 0, 5]), ...row("Abe", [0, 0, 0, 0, 0, 0, 5])] });
    show();
    await screen.findByText("1,234");
    expect(names(document.querySelector("table.heatmap") as HTMLElement).slice(0, 2)).toEqual(["Abe", "Zed"]);
  });
});

describe("sensor health card", () => {
  const sensorCard = () => within(cardOf("Sensor health"));
  const st = (id: number, name: string, o: Record<string, unknown> = {}, report_: Record<string, unknown> = {}) =>
    sensorState({ sensor_id: id, name, status: report(report_), last_seen_at: iso(-3 * 60_000), ...o });

  it("pill online when every sensor reports", async () => {
    d.sensors = sensorsStatus([st(1, "gw")]);
    show();
    expect(await sensorCard().findByText("online")).toHaveClass("pill");
  });

  it("pill offline when no sensor reports, with never-reported and offline lines", async () => {
    d.sensors = sensorsStatus([
      sensorState({ sensor_id: 1, name: "gw", online: false, status: null, last_seen_at: iso(-2 * 3600_000) }),
      sensorState({ sensor_id: 2, name: "fresh", online: false, status: null, last_seen_at: null }),
    ]);
    show();
    expect(await sensorCard().findByText("offline")).toHaveClass("pill");
    const text = cardOf("Sensor health").textContent!;
    expect(text).toContain("gw: offline, last seen 2 h ago");
    expect(text).toContain("fresh: has never reported");
    expect(cardOf("Sensor health").querySelector("dl")).toBeNull();
  });

  it("N of M online counts only non-revoked sensors", async () => {
    d.sensors = sensorsStatus([
      st(1, "a"), sensorState({ sensor_id: 2, name: "b", online: false, status: null }),
      sensorState({ sensor_id: 3, name: "gone", revoked: true, online: false, status: null }),
    ]);
    show();
    expect(await sensorCard().findByText("1 of 2 online")).toHaveClass("pill");
    expect(cardOf("Sensor health").textContent).not.toContain("gone");
  });

  it("No sensors registered when the list is empty", async () => {
    show();
    expect(await sensorCard().findByText(/No sensors registered/)).toBeInTheDocument();
    expect(sensorCard().getByText("offline")).toBeInTheDocument();
  });

  it("shows live sensor details", async () => {
    d.sensors = sensorsStatus([st(1, "gw", {}, { shap_p95_ms: 12.5, outbox_pending: 1234, allowlist: ["a", "b"] })]);
    show();
    await sensorCard().findByText("gw");
    const card = cardOf("Sensor health");
    expect(card.textContent).toContain("live on eth0");
    expect(card.textContent).toContain("blocking");
    expect(card.textContent).toContain("rf-v3 · checksum ok");
    expect(card.textContent).toContain("1 / s · ok");
    expect(card.textContent).toContain("1,234 pending");
    expect(card.textContent).toContain("12.50 ms");
    expect(card.textContent).toContain("2 entries");
    expect(card.textContent).toContain("3 min ago");
  });

  it.each([
    [{ dry_run: true }, "dry-run (blocks only logged)"],
    [{ dry_run: false, blocking_enabled: false }, "not blocking"],
  ])("mode text %j", async (o, text) => {
    d.sensors = sensorsStatus([st(1, "gw", {}, o)]);
    show();
    await sensorCard().findByText("gw");
    expect(cardOf("Sensor health").textContent).toContain(text);
  });

  it("heartbeat off or failing, SHAP dash, checksum failure, replay, one entry", async () => {
    d.sensors = sensorsStatus([st(1, "gw", {}, {
      heartbeat: { enabled: true, ok: false }, shap_p95_ms: null, model: { name: "m", checksum_ok: false },
      mode: "replay", allowlist: ["x"],
    })]);
    show();
    await sensorCard().findByText("gw");
    const t = cardOf("Sensor health").textContent!;
    expect(t).toContain("failing");
    expect(t).toContain("SHAP p95—");
    expect(t).toContain("checksum FAILED");
    expect(t).toContain("replaying a capture");
    expect(t).toContain("1 entry");
  });

  it("heartbeat disabled says off", async () => {
    d.sensors = sensorsStatus([st(1, "gw", {}, { heartbeat: { enabled: false, ok: false } })]);
    show();
    await sensorCard().findByText("gw");
    expect(cardOf("Sensor health").textContent).toContain("Heartbeatoff");
  });

  it("the allowlist count uses allowlist_total when present", async () => {
    d.sensors = sensorsStatus([st(1, "gw", {}, { allowlist: ["a", "b"], allowlist_total: 300 })]);
    show();
    await sensorCard().findByText("gw");
    expect(cardOf("Sensor health").textContent).toContain("300 entries");
    expect(cardOf("Sensor health").textContent).not.toContain("2 entries");
  });

  it("allowlist shows a dash when neither total nor list is known (redacted, older sensor)", async () => {
    d.sensors = { redacted: true, soc_allowlist: null, sensors: [st(1, "gw", {}, { allowlist: null })] };
    show();
    await sensorCard().findByText("gw");
    const t = cardOf("Sensor health").textContent!;
    expect(t).toContain("Allowlist—");
    expect(t).not.toContain("0 entries");
  });

  it("redacted status keeps the total when the list is null", async () => {
    d.sensors = { redacted: true, soc_allowlist: null, sensors: [st(1, "gw", {}, { allowlist: null, allowlist_total: 12 })] };
    show();
    await sensorCard().findByText("gw");
    expect(cardOf("Sensor health").textContent).toContain("12 entries");
  });

  it("allowlist_total of 1 says entry", async () => {
    d.sensors = sensorsStatus([st(1, "gw", {}, { allowlist: ["a"], allowlist_total: 1 })]);
    show();
    await sensorCard().findByText("gw");
    expect(cardOf("Sensor health").textContent).toContain("1 entry");
  });

  it("shows at most 2 sensors and 'and N more online'", async () => {
    d.sensors = sensorsStatus([st(1, "s1"), st(2, "s2"), st(3, "s3"), st(4, "s4")]);
    show();
    await sensorCard().findByText("and 2 more online.");
    expect(cardOf("Sensor health").querySelectorAll("dl").length).toBe(2);
    expect(sensorCard().queryByText("s3")).toBeNull();
  });

  it("a status error is shown", async () => {
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string) => { if (p.startsWith("/sensors")) throw new Error("no status"); return base(p); });
    show();
    expect(await sensorCard().findByText("no status")).toBeInTheDocument();
  });
});

describe("dry-run decisions", () => {
  const would = (ip: string) => ({ id: 1, sensor_id: 1, ip, reason: "r", source: "auto", alert_id: null, at: iso(-1000), ttl_seconds: 900 });
  const cellFor = (id: string) => bodyRows().find((r) => r.textContent!.includes(`#${id} `))!.textContent!;

  it("Response column: blocked beats would block beats observe", async () => {
    d.alerts = [alert({ id: 1, src_ip: "10.0.0.1" }), alert({ id: 2, src_ip: "10.0.0.2" }), alert({ id: 3, src_ip: "10.0.0.3" })];
    d.blocks = [block({ ip: "10.0.0.1" })];
    d.would = [would("10.0.0.1"), would("10.0.0.2")];
    show();
    await within(liveCard()).findByText("would block · dry-run");
    expect(cellFor("1")).toContain("blocked · auto");
    expect(cellFor("1")).not.toContain("would block");
    expect(cellFor("2")).toContain("would block · dry-run");
    expect(cellFor("3")).toContain("observe");
  });

  it("a would-block counts only while at + ttl is in the future", async () => {
    d.alerts = [1, 2, 3, 4].map((i) => alert({ id: i, src_ip: `10.0.0.${i}` }));
    d.would = [
      { ...would("10.0.0.1"), at: iso(-30 * 60_000), ttl_seconds: 900 },   // expired 15 min ago
      { ...would("10.0.0.2"), at: iso(-30 * 60_000), ttl_seconds: 7200 },  // still running
      { ...would("10.0.0.3"), at: iso(-30 * 60_000), ttl_seconds: null },  // default 1 h, still running
      { ...would("10.0.0.4"), at: iso(-90 * 60_000), ttl_seconds: null },  // default 1 h, over
    ];
    show();
    await within(liveCard()).findAllByText("would block · dry-run");
    expect(cellFor("1")).toContain("observe");
    expect(cellFor("2")).toContain("would block");
    expect(cellFor("3")).toContain("would block");
    expect(cellFor("4")).toContain("observe");
  });

  it("a would-block only matches alerts from the same sensor", async () => {
    d.alerts = [alert({ id: 1, sensor_id: 1, src_ip: "10.0.0.1" }), alert({ id: 2, sensor_id: 2, src_ip: "10.0.0.1" })];
    d.would = [{ ...would("10.0.0.1"), sensor_id: 2 }];
    show();
    await within(liveCard()).findByText("would block · dry-run");
    expect(cellFor("1")).toContain("observe");
    expect(cellFor("2")).toContain("would block");
  });

  it("a block on another sensor does not mark the alert blocked", async () => {
    d.alerts = [alert({ id: 1, sensor_id: 1, src_ip: "10.0.0.1" }), alert({ id: 2, sensor_id: 2, src_ip: "10.0.0.1" })];
    d.blocks = [block({ sensor_id: 2, ip: "10.0.0.1" })];
    show();
    await within(liveCard()).findByText("blocked · auto");
    expect(cellFor("1")).toContain("observe");
    expect(cellFor("2")).toContain("blocked · auto");
  });

  it("a block on another sensor falls through to would block", async () => {
    d.alerts = [alert({ id: 1, sensor_id: 1, src_ip: "10.0.0.1" })];
    d.blocks = [block({ sensor_id: 2, ip: "10.0.0.1" })];
    d.would = [would("10.0.0.1")];
    show();
    await within(liveCard()).findByText("would block · dry-run");
    expect(cellFor("1")).not.toContain("blocked ·");
  });

  it("an expired block falls through to would block", async () => {
    d.alerts = [alert({ id: 1, src_ip: "10.0.0.1" })];
    d.blocks = [block({ ip: "10.0.0.1", blocked_at: iso(-120_000), expires_at: iso(-60_000) })];
    d.would = [would("10.0.0.1")];
    show();
    await within(liveCard()).findByText("would block · dry-run");
  });

  it("would-blocks reload with the page reload", async () => {
    show();
    await screen.findByText("1,234");
    await waitFor(() => expect(calls("/blocks/would").length).toBe(1));
    act(() => { h.reloadAll!(); });
    await waitFor(() => expect(calls("/blocks/would").length).toBe(2));
    expect(calls("/blocks?").length).toBe(2);
    expect(calls("/metrics/summary").length).toBe(2);
  });

  it("Active blocks KPI shows the dry-run count only when positive", async () => {
    d.metrics = metrics({ would_blocks: 1234 });
    const { unmount } = show();
    expect(await within(cardOf("Active blocks")).findByText("+ 1,234 dry-run decisions")).toBeInTheDocument();
    unmount();
    d.metrics = metrics({ would_blocks: 0 });
    show();
    await screen.findByText("1,234");
    expect(screen.queryByText(/dry-run decisions/)).toBeNull();
  });

  it("no dry-run line when would_blocks is missing", async () => {
    show();
    await screen.findByText("1,234");
    expect(screen.queryByText(/dry-run decisions/)).toBeNull();
  });
});

describe("untrusted reasons are one line, capped at 300", () => {
  const evil = "first\nsecond‮third";
  const long = "y".repeat(400);
  it("firewall card block reason", async () => {
    d.blocks = [block({ reason: evil }), block({ id: 2, ip: "9.9.9.9", reason: long })];
    show();
    expect(await screen.findByText("auto · first second third")).toBeInTheDocument();
    const el = screen.getByText(/^auto · y+…$/);
    expect([...el.textContent!.slice("auto · ".length)]).toHaveLength(300);
  });
  it("decisions card reason", async () => {
    d.actions = [action({ reason: evil }), action({ id: 4, reason: long })];
    show();
    expect(await screen.findByText("“first second third”")).toBeInTheDocument();
    expect(screen.getByText(/^“y+…”$/).textContent!.length).toBe(302);
  });
});

describe("model version and drift", () => {
  const drift = (o: Record<string, unknown> = {}) => ({
    level: "ok", window: 5000, psi_max: 0.05, top: [], reference_sha256: "abc", reason: null, ...o,
  });
  const withDrift = (name: string, id: number, dr: unknown, st: Record<string, unknown> = {}) =>
    sensorState({ sensor_id: id, name, status: report({ drift: dr, ...st }) });
  const drifts = () => cardOf("Model drift");

  it("sensor health shows the model version when reported", async () => {
    d.sensors = sensorsStatus([sensorState({ status: report({ model: { name: "rf-v3", checksum_ok: true, sha256: "x", version: "v-2026-11" } }) })]);
    show();
    expect(await within(await screen.findByText("Sensor health").then((e) => e.closest(".card") as HTMLElement)).findByText("v-2026-11")).toBeInTheDocument();
  });

  it("no online sensor", async () => {
    show();
    expect(await within(await screen.findByText("Model drift").then(() => drifts())).findByText("No sensor is online.")).toBeInTheDocument();
  });

  it("shows PSI, window and the top 3 features of a sensor", async () => {
    d.sensors = sensorsStatus([withDrift("gw", 1, drift({
      level: "watch", psi_max: 0.18, window: 4000,
      top: [{ feature: "f1", psi: 0.18 }, { feature: "f2", psi: 0.12 }, { feature: "f3", psi: 0.11 }, { feature: "f4", psi: 0.1 }],
    }))]);
    show();
    await within(await screen.findByText("Model drift").then(() => drifts())).findByText(/Largest shift PSI 0\.18/);
    const c = within(drifts());
    expect(c.getByText(/over the last 4,000 flows/)).toBeInTheDocument();
    expect(c.getAllByText("watch")).toHaveLength(2); // header + sensor
    expect(c.getByText("f3")).toBeInTheDocument();
    expect(c.queryByText("f4")).toBeNull();
  });

  it("header pill is the worst level; unknown ranks lowest", async () => {
    d.sensors = sensorsStatus([
      withDrift("a", 1, drift()), withDrift("b", 2, drift({ level: "drift", psi_max: 0.4 })),
      withDrift("c", 3, drift({ level: "unknown", psi_max: null, reason: "x" })),
    ]);
    show();
    await within(await screen.findByText("Model drift").then(() => drifts())).findByText("a");
    const c = within(drifts());
    expect(c.getByText("drifting · 1 unknown")).toBeInTheDocument(); // header
    expect(c.getAllByText("drifting")).toHaveLength(1); // sensor b
    expect(c.getAllByText("stable")).toHaveLength(1);
    expect(c.getAllByText("unknown")).toHaveLength(1); // sensor c
  });

  it("psi_max null shows the reason; missing drift says older version and counts as unknown", async () => {
    d.sensors = sensorsStatus([
      withDrift("a", 1, drift({ level: "unknown", psi_max: null, reason: "too few flows" })),
      withDrift("b", 2, undefined),
    ]);
    show();
    await within(await screen.findByText("Model drift").then(() => drifts())).findByText("too few flows");
    const c = within(drifts());
    expect(c.getByText(/older version/)).toBeInTheDocument();
    expect(c.getAllByText("unknown")).toHaveLength(3); // header + two sensors
  });

  it("lists at most 3 sensors and says how many more", async () => {
    d.sensors = sensorsStatus([1, 2, 3, 4, 5].map((i) => withDrift(`s${i}`, i, drift())));
    show();
    await within(await screen.findByText("Model drift").then(() => drifts())).findByText("and 2 more online.");
    expect(within(drifts()).queryByText("s4")).toBeNull();
  });

  it("header has no unknown suffix when all sensors are known, or when the worst is unknown", async () => {
    d.sensors = sensorsStatus([withDrift("a", 1, drift()), withDrift("b", 2, drift({ level: "watch", psi_max: 0.2 }))]);
    const a = show();
    await within(await screen.findByText("Model drift").then(() => drifts())).findByText("a");
    expect(within(drifts()).queryByText(/unknown/)).toBeNull();
    a.unmount();
    d.sensors = sensorsStatus([withDrift("a", 1, undefined), withDrift("b", 2, drift({ level: "unknown", psi_max: null }))]);
    show();
    await within(await screen.findByText("Model drift").then(() => drifts())).findByText("a");
    expect(within(drifts()).queryByText(/· \d+ unknown/)).toBeNull();
  });
});
