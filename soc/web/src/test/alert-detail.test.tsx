import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import AlertDetail, { activeBlock, ratioText, relatedBlocks, timeline, verdict } from "../pages/AlertDetail";
import ExplanationChart from "../components/ExplanationChart";
import { ALERT_STATUSES } from "../api/types";
import { label, percent } from "../format";
import { report, sensorState, sensorsStatus } from "./sensor-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), live: null as null | { fn: () => void; ms: number | undefined } }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (fn: () => void, _a: unknown, ms?: number) => { h.live = { fn, ms }; return true; },
}));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));

const T = 1_700_000_000_000;
const iso = (ms: number) => new Date(ms).toISOString();
const H24 = 24 * 3600_000;

const mkAlert = (o: Record<string, unknown> = {}) => ({
  id: 7, sensor_id: 3, received_at: iso(T + 60_000), src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80,
  protocol: 6, start_ms: T, end_ms: T + 1000, predicted_class: "PortScan", confidence: 0.95, anomaly_score: 0.5,
  severity: "high", status: "new", case_id: null,
  explanation: { method: "shap", predicted_class: "PortScan", top_features: [{ feature: "syn_count", value: 4, contribution: 1.2 }] },
  ...o,
}) as never;
const mkBlock = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 3, ip: "10.0.0.1", reason: "scan", source: "auto", alert_id: null, blocked_at: iso(T + 5000),
  expires_at: iso(T + 3600_000), unblocked_at: null, active: true, ...o,
}) as never;

describe("relatedBlocks", () => {
  const a = mkAlert();
  const ids = (bs: unknown[]) => (relatedBlocks(a, bs as never) as { id: number }[]).map((b) => b.id);

  it("filters by sensor and ip", () => {
    expect(ids([mkBlock({ id: 1 }), mkBlock({ id: 2, sensor_id: 9 }), mkBlock({ id: 3, ip: "10.0.0.9" })])).toEqual([1]);
  });
  it("includes an alert_id match outside the window, but only for the same sensor and ip", () => {
    expect(ids([mkBlock({ id: 1, alert_id: 7, blocked_at: iso(T - 10 * H24) })])).toEqual([1]);
    expect(ids([mkBlock({ id: 2, alert_id: 7, sensor_id: 9, blocked_at: iso(T - 10 * H24) })])).toEqual([]);
  });
  it("is overlap based: in force during the flow, or started up to 1 h after receipt", () => {
    const recv = T + 60_000;
    expect(ids([
      mkBlock({ id: 1, blocked_at: iso(T - 5 * H24), expires_at: iso(T + 1) }),       // started before, still in force
      mkBlock({ id: 2, blocked_at: iso(T - 5 * H24), expires_at: iso(T - 1) }),       // ended before the flow
      mkBlock({ id: 3, blocked_at: iso(T - 5 * H24), expires_at: null }),             // no end
      mkBlock({ id: 4, blocked_at: iso(recv + 3600_000), expires_at: iso(recv + 9e6) }), // exactly 1 h after
      mkBlock({ id: 5, blocked_at: iso(recv + 2 * 3600_000), expires_at: iso(recv + 9e6) }), // 2 h after
      mkBlock({ id: 6, blocked_at: iso(T - 5 * H24), expires_at: iso(T - 9e6), unblocked_at: iso(T + 10) }), // unblocked during
      mkBlock({ id: 7, blocked_at: iso(T - 5 * H24), expires_at: iso(T + 9e6), unblocked_at: iso(T - 10) }), // unblocked before
    ])).toEqual([1, 3, 4, 6]);
  });
  it("caps at 10", () => {
    const many = Array.from({ length: 12 }, (_, i) => mkBlock({ id: i + 1 }));
    expect(ids(many).length).toBe(10);
  });
});

describe("activeBlock", () => {
  const a = mkAlert();
  const now = T + 10_000;
  const pick = (bs: unknown[]) => (activeBlock(a, bs as never, now) as { id: number } | undefined)?.id;
  it("finds a same sensor and ip block that is active and not over, whenever it started", () => {
    expect(pick([mkBlock({ id: 1, blocked_at: iso(T - 5 * H24), expires_at: iso(now + 1) })])).toBe(1);
    expect(pick([mkBlock({ id: 1, blocked_at: iso(now + H24), expires_at: iso(now + 2 * H24) })])).toBe(1);
  });
  it("no end means in force", () => {
    expect(pick([mkBlock({ expires_at: null })])).toBe(1);
  });
  it("ignores other sensors, other ips, inactive, and ended blocks", () => {
    expect(pick([
      mkBlock({ id: 1, sensor_id: 9 }), mkBlock({ id: 2, ip: "9.9.9.9" }),
      mkBlock({ id: 3, active: false }), mkBlock({ id: 4, expires_at: iso(now) }),
      mkBlock({ id: 5, expires_at: iso(now + 5000), unblocked_at: iso(now - 1) }),
    ])).toBeUndefined();
  });
});

describe("timeline", () => {
  const texts = (items: { text: unknown }[]) => items.map((i) => i.text);
  it("lists flow then scored, sorted by time", () => {
    const items = timeline(mkAlert(), [], T + 10);
    expect(texts(items)).toEqual([
      "flow seen: TCP 10.0.0.1:1234 → 10.0.0.2:80",
      "scored PortScan 95.00%, explained (SHAP)",
    ]);
  });
  it("omits the explained part without a method", () => {
    const items = timeline(mkAlert({ explanation: {} }), [], T);
    expect(texts(items)[1]).toBe("scored PortScan 95.00%");
  });
  it("adds block events in time order: unblocked, expired, ends", () => {
    const now = T + 10_000_000;
    const items = timeline(mkAlert(), [
      mkBlock({ id: 1, blocked_at: iso(T + 5000), unblocked_at: iso(T + 9000), reason: "r1" }),
      mkBlock({ id: 2, blocked_at: iso(T + 6000), expires_at: iso(now - 1), reason: "r2", source: "analyst" }),
      mkBlock({ id: 3, blocked_at: iso(T + 7000), expires_at: iso(now + 1000), reason: "r3" }),
    ], now);
    expect(texts(items)).toEqual([
      "flow seen: TCP 10.0.0.1:1234 → 10.0.0.2:80",
      "10.0.0.1 blocked (auto): r1",
      "10.0.0.1 blocked (analyst): r2",
      "10.0.0.1 blocked (auto): r3",
      "unblocked",
      "scored PortScan 95.00%, explained (SHAP)",
      "block expired by itself",
      "block ends",
    ]);
  });
  it("labels blocks already in force and later blocks, but not the alert's own", () => {
    const items = timeline(mkAlert(), [
      mkBlock({ id: 1, blocked_at: iso(T - 1000), reason: "old" }),
      mkBlock({ id: 2, blocked_at: iso(T - 1000), alert_id: 7, reason: "own" }),
      mkBlock({ id: 3, blocked_at: iso(T + 120_000), reason: "later" }),
      mkBlock({ id: 4, blocked_at: iso(T + 5000), reason: "during" }),
    ], T);
    const t = texts(items);
    expect(t).toContain("10.0.0.1 blocked (auto) (already in force): old");
    expect(t).toContain("10.0.0.1 blocked (auto): own");
    expect(t).toContain("10.0.0.1 blocked (auto) (later block of this address): later");
    expect(t).toContain("10.0.0.1 blocked (auto): during");
  });
  it("includes the date for events not on the received day", () => {
    const items = timeline(mkAlert(), [mkBlock({ id: 1, blocked_at: iso(T + 3 * H24), expires_at: null })], T);
    const at = (text: string) => items.find((i) => String(i.text).startsWith(text))!.at;
    expect(at("scored")).toBe(new Date(T + 60_000).toLocaleTimeString());
    expect(at("flow")).toBe(new Date(T).toLocaleTimeString());
    expect(at("10.0.0.1 blocked")).toBe(new Date(T + 3 * H24).toLocaleString());
  });
  it("expiry exactly now counts as expired", () => {
    const items = timeline(mkAlert(), [mkBlock({ expires_at: iso(T + 20_000) })], T + 20_000);
    expect(texts(items)).toContain("block expired by itself");
  });
});

// ---- page ----
let alert: Record<string, unknown>;
let blocks: unknown[];
let blocksError: Error | null;
let cases: unknown[];
let gates: Record<string, Promise<void>>;
let patchGate: Promise<void> | null;
let sensorsBody: unknown;
let sensorsGate: Promise<void> | null;
let sensorsError: Error | null;
const future = () => iso(Date.now() + 3600_000);

const calls = (method: string, prefix = "") =>
  h.api.mock.calls.filter(([p, o]) => (o?.method ?? "GET") === method && String(p).startsWith(prefix));

beforeEach(() => {
  alert = mkAlert() as never;
  blocks = [];
  blocksError = null;
  cases = [{ id: 5, title: "Case A" }];
  gates = {};
  patchGate = null;
  sensorsBody = sensorsStatus();
  sensorsGate = null;
  sensorsError = null;
  h.live = null;
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string; json?: Record<string, unknown> }) => {
    const m = opts?.method ?? "GET";
    if (m === "PATCH") { if (patchGate) await patchGate; return { ...alert, ...opts!.json }; }
    if (m === "POST" && path === "/cases") return { id: 8 };
    if (m === "POST" && path.endsWith("/alerts")) return { id: Number(path.split("/")[2]) };
    if (path === "/sensors/status") {
      if (sensorsGate) await sensorsGate;
      if (sensorsError) throw sensorsError;
      return sensorsBody;
    }
    if (path.startsWith("/blocks")) {
      if (blocksError) throw blocksError;
      return { items: blocks, total: blocks.length };
    }
    if (path.startsWith("/cases")) return { items: cases, total: cases.length };
    if (path === "/alerts/0") throw new Error("not found");
    const mm = /^\/alerts\/(\d+)$/.exec(path);
    if (mm) {
      const g = gates[mm[1]] as Promise<void> | undefined;
      if (g) await g;
      return mm[1] === "7" ? alert : { ...(alert as object), id: Number(mm[1]), predicted_class: "DoS", case_id: null };
    }
    throw new Error(`unexpected ${path}`);
  });
});

const show = (url = "/alerts/7") =>
  render(<MemoryRouter initialEntries={[url]}><Routes><Route path="/alerts/:id" element={<AlertDetail />} /></Routes></MemoryRouter>);
// The page has other live regions (the reputation card); the notice is the one outside that card.
const notice = () => screen.getAllByRole("status").find((e) => !e.closest(".card")?.textContent?.startsWith("Source reputation"))!;
const loaded = () => screen.findByRole("heading", { level: 1 });

describe("AlertDetail page", () => {
  it("heading, severity, neutral confidence pill; blocked pill only for an active, unexpired same-sensor block", async () => {
    blocks = [mkBlock({ id: 1, sensor_id: 9, expires_at: future() })];
    const { unmount } = show();
    expect(await loaded()).toHaveTextContent("PortScan · alert #7");
    expect(screen.getByText(/high/i)).toBeInTheDocument();
    const conf = screen.getByText("confidence 95.0%");
    expect(conf).toHaveClass("pill", "neutral");
    expect(conf).not.toHaveClass("ok");
    await screen.findByText(/No block of 10.0.0.1/);
    expect(screen.queryByText(/source blocked/)).toBeNull();
    expect(screen.getByRole("link", { name: "Block source IP…" })).toBeInTheDocument();
    unmount();

    blocks = [mkBlock({ id: 1, sensor_id: 9 }), mkBlock({ id: 2, expires_at: future() })];
    show();
    expect(await screen.findByText("source blocked · auto")).toBeInTheDocument();
  });

  it("a block that began before the flow still shows the pill and the Triage text instead of the link", async () => {
    const until = future();
    blocks = [mkBlock({ blocked_at: iso(T - 5 * H24), expires_at: until, source: "analyst" })];
    show();
    expect(await screen.findByText("source blocked · analyst")).toBeInTheDocument();
    const p = screen.getByText(/is blocked on sensor #3/);
    expect(p).toHaveTextContent(/^10\.0\.0\.1 is blocked on sensor #3 until .+\. See it on Response$/);
    expect(within(p).getByRole("link", { name: "See it on Response" })).toHaveAttribute("href", "/response");
    expect(screen.queryByRole("link", { name: "Block source IP…" })).toBeNull();
  });

  it("the pill disappears when the block's expiry passes (15 s clock)", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    try {
      blocks = [mkBlock({ blocked_at: iso(Date.now() - 1000), expires_at: iso(Date.now() + 20_000) })];
      show();
      expect(await screen.findByText("source blocked · auto")).toBeInTheDocument();
      await act(async () => {}); // flush passive effects so the useNow interval exists
      act(() => { vi.advanceTimersByTime(30_000); });
      expect(screen.queryByText(/source blocked/)).toBeNull();
      expect(screen.getByRole("link", { name: "Block source IP…" })).toBeInTheDocument();
    } finally { vi.useRealTimers(); }
  });

  it("refreshes blocks through useLiveRefresh every 30 s", async () => {
    show();
    await loaded();
    await screen.findByText(/No block of/);
    expect(h.live!.ms).toBe(30_000);
    expect(calls("GET", "/blocks").length).toBe(1);
    blocks = [mkBlock({ expires_at: future() })];
    act(() => { h.live!.fn(); });
    expect(await screen.findByText("source blocked · auto")).toBeInTheDocument();
    expect(calls("GET", "/blocks").length).toBe(2);
  });

  it("two quick status clicks send one PATCH and the buttons are disabled meanwhile", async () => {
    let release!: () => void;
    patchGate = new Promise<void>((r) => { release = r; });
    show();
    await loaded();
    const group = within(screen.getByRole("group", { name: "Status" }));
    const other = ALERT_STATUSES.find((s) => s !== "new")!;
    fireEvent.click(group.getByRole("button", { name: label(other) }));
    await waitFor(() => expect(group.getByRole("button", { name: label("new") })).toBeDisabled());
    fireEvent.click(group.getByRole("button", { name: label(other) }));
    release();
    await waitFor(() => expect(group.getByRole("button", { name: label(other) })).toBeEnabled());
    expect(calls("PATCH").length).toBe(1);
  });

  it("flow time shows a date for an end on another day", async () => {
    alert = mkAlert({ end_ms: T + 2 * H24 }) as never;
    show();
    await loaded();
    expect(screen.getByText(new RegExp(new Date(T + 2 * H24).toLocaleString().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toBeInTheDocument();
  });

  it("navigating to another alert clears notice and case and never shows the old data while loading", async () => {
    function Nav() { const n = useNavigate(); return <button onClick={() => n("/alerts/2")}>next</button>; }
    render(<MemoryRouter initialEntries={["/alerts/7"]}>
      <Routes><Route path="/alerts/:id" element={<AlertDetail />} /></Routes><Nav />
    </MemoryRouter>);
    await loaded();
    fireEvent.change(screen.getByLabelText("Add to open case"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await screen.findByText("Added to case #5.");
    let release!: () => void;
    gates["2"] = new Promise<void>((r) => { release = r; });
    fireEvent.click(screen.getByText("next"));
    expect(await screen.findByText("Loading…")).toBeInTheDocument();
    expect(screen.queryByText(/PortScan · alert #7/)).toBeNull();
    release();
    expect(await screen.findByRole("heading", { level: 1, name: "DoS · alert #2" })).toBeInTheDocument();
    expect(notice()).toBeEmptyDOMElement();
    expect(screen.getByLabelText("Add to open case")).toHaveValue("");
  });

  it("an ended block gives no blocked pill", async () => {
    blocks = [mkBlock({ active: false, unblocked_at: iso(T + 9000) })];
    show();
    await loaded();
    await screen.findByText("unblocked");
    expect(screen.queryByText(/source blocked/)).toBeNull();
  });

  it("a non-numeric id requests /alerts/0, never the raw string", async () => {
    show("/alerts/abc");
    expect(await screen.findByText("not found")).toBeInTheDocument();
    const paths = h.api.mock.calls.map(([p]) => String(p));
    expect(paths).toContain("/alerts/0");
    expect(paths.some((p) => p.includes("abc"))).toBe(false);
  });

  it("links to all alerts from the IP, the assistant, and shows the sensor", async () => {
    show();
    await loaded();
    expect(screen.getByRole("link", { name: "all alerts involving this IP" })).toHaveAttribute("href", "/alerts?ip=10.0.0.1");
    expect(screen.getByRole("link", { name: "Explain this alert with the assistant" })).toHaveAttribute("href", "/assistant?alert=7");
  });

  it("shows the receive delay, and nothing for a negative gap", async () => {
    alert = mkAlert({ received_at: iso(T + 1000 + 120_000) }) as never;
    const { unmount } = show();
    expect(await screen.findByText("(+2 min after the flow ended)")).toBeInTheDocument();
    unmount();
    alert = mkAlert({ received_at: iso(T + 500) }) as never;
    show();
    await loaded();
    expect(screen.queryByText(/after the flow ended/)).toBeNull();
  });

  it("status buttons: aria-pressed, PATCH on change, nothing for the current one", async () => {
    show();
    await loaded();
    const group = within(screen.getByRole("group", { name: "Status" }));
    const [cur, other] = [ALERT_STATUSES[0], ALERT_STATUSES.find((s) => s !== "new")!];
    expect(alert.status).toBe("new");
    expect(group.getByRole("button", { name: label("new") })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(group.getByRole("button", { name: label(cur) }));
    expect(calls("PATCH").length).toBe(0);
    fireEvent.click(group.getByRole("button", { name: label(other) }));
    await waitFor(() => expect(calls("PATCH").length).toBe(1));
    expect(calls("PATCH")[0][0]).toBe("/alerts/7");
    expect(calls("PATCH")[0][1].json).toEqual({ status: other });
    await waitFor(() => expect(group.getByRole("button", { name: label(other) })).toHaveAttribute("aria-pressed", "true"));
    expect(group.getByRole("button", { name: label("new") })).toHaveAttribute("aria-pressed", "false");
  });

  it("Block source IP is an encoded link and posts nothing", async () => {
    show();
    await loaded();
    const link = screen.getByRole("link", { name: "Block source IP…" });
    expect(link).toHaveAttribute("href", "/response?ip=10.0.0.1&sensor=3&alert=7");
    fireEvent.click(link);
    expect(calls("POST").length).toBe(0);
  });

  it("add to an open case", async () => {
    show();
    await loaded();
    const add = screen.getByRole("button", { name: "Add" });
    expect(add).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Add to open case"), { target: { value: "5" } });
    fireEvent.click(add);
    await waitFor(() => expect(calls("POST", "/cases/5/alerts").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ alert_ids: [7] });
    expect(await screen.findByRole("link", { name: "case #5" })).toHaveAttribute("href", "/cases/5");
    expect(screen.getByRole("link", { name: "case #5" }).parentElement).toHaveTextContent("In case #5.");
    expect(notice()).toHaveTextContent("Added to case #5.");
    expect(screen.queryByRole("button", { name: "Add" })).toBeNull();
  });

  it("create a case with a trimmed title", async () => {
    show();
    await loaded();
    const create = screen.getByRole("button", { name: "Create" });
    expect(create).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Or open a new case"), { target: { value: "  Scan wave  " } });
    fireEvent.click(create);
    await waitFor(() => expect(calls("POST", "/cases").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ title: "Scan wave", alert_ids: [7] });
    expect(await screen.findByText(/^In/)).toBeInTheDocument();
    expect(notice()).toHaveTextContent("Created case #8.");
  });

  it("hides case controls when the alert already has a case", async () => {
    alert = mkAlert({ case_id: 4 }) as never;
    show();
    await loaded();
    expect(screen.queryByLabelText("Add to open case")).toBeNull();
    expect(screen.queryByRole("button", { name: "Create" })).toBeNull();
    expect(screen.getAllByRole("link", { name: /case #4|#4/ }).length).toBeGreaterThan(0);
  });

  it("what happened: empty message, blocks request, and an error", async () => {
    const { unmount } = show();
    expect(await screen.findByText("No block of 10.0.0.1 on this sensor around this alert.")).toBeInTheDocument();
    expect(calls("GET", "/blocks?ip=10.0.0.1&limit=100").length).toBe(1);
    expect(calls("GET", "/cases?status=open&limit=100").length).toBe(1);
    unmount();
    blocksError = new Error("blocks down");
    show();
    expect(await screen.findByText("blocks down")).toBeInTheDocument();
    expect(screen.queryByText(/No block of/)).toBeNull();
  });

  it("renders untrusted text as text", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    alert = mkAlert({
      predicted_class: evil,
      explanation: { method: "shap", predicted_class: evil, top_features: [{ feature: evil, value: 1, contribution: 1 }] },
    }) as never;
    blocks = [mkBlock({ reason: evil })];
    const { container } = show();
    await loaded();
    await screen.findByText(new RegExp("blocked \\(auto\\)"));
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(evil);
    expect(container.textContent).toContain(`blocked (auto): ${evil}`);
  });
});

describe("ExplanationChart summary", () => {
  const norm = (c: HTMLElement) => c.textContent!.replace(/\s+/g, " ");
  const feats = [
    { feature: "a", value: 1, contribution: 0.5 },
    { feature: "b", value: 2, contribution: -0.5 },
  ];
  it("shows the summary with base value and confidence", () => {
    const { container } = render(<ExplanationChart explanation={{
      method: "shap", predicted_class: "PortScan", base_value: 0.1234, confidence: 0.9999, output_space: "log_odds", top_features: feats,
    }} />);
    expect(norm(container)).toContain("SHAP: top 2 features behind the decision for PortScan.");
    expect(norm(container)).toContain("Contributions in log odds. Base value 0.123 → confidence 99.99%.");
    expect(norm(container)).toContain("pushes towards PortScan");
    expect(norm(container)).toContain("pushes away");
  });
  it("shows the output space even without a base value", () => {
    const { container } = render(<ExplanationChart explanation={{
      method: "lime", predicted_class: "PortScan", output_space: "probability", top_features: feats,
    }} />);
    expect(norm(container)).toContain("LIME: top 2 features behind the decision for PortScan. Contributions in probability.");
    expect(norm(container)).not.toContain("Base value");
  });
  it("omits the base part without base_value", () => {
    const { container } = render(<ExplanationChart explanation={{
      method: "shap", predicted_class: "PortScan", confidence: 0.9999, top_features: feats,
    }} />);
    expect(norm(container)).toContain("SHAP: top 2 features behind the decision for PortScan.");
    expect(norm(container)).not.toContain("Base value");
    expect(norm(container)).not.toContain("confidence 99.99%");
  });
});

describe("ratioText", () => {
  it.each([[38.64, "38.6×"], [1.25, "1.25×"], [1.2, "1.2×"], [0.05, "<0.1×"], [10, "10×"], [9.999, "10×"], [9.9, "9.9×"], [2, "2×"], [0.1, "0.1×"], [0, "<0.1×"],
    [NaN, "—"], [Infinity, "—"], [-Infinity, "—"]])("%s -> %s", (r, t) => { expect(ratioText(r)).toBe(t); });
});

describe("verdict", () => {
  const v = (ratio_to_random: number | null) => verdict({ mean_drop: 0.1, ratio_to_random, label_flip_rate: 0, share_flows_beating_random: 0 });
  it.each([
    [null, "neutral", "no result"], [NaN, "neutral", "no result"], [Infinity, "neutral", "no result"],
    [38.6, "ok", "better than random"], [2, "ok", "better than random"],
    [1.99, "warn", "barely better than random"], [1.01, "warn", "barely better than random"],
    [1, "danger", "no better than random"], [0.5, "danger", "no better than random"], [0, "danger", "no better than random"],
    [-3, "danger", "no better than random"],
  ])("%s -> %s / %s", (r, tone, text) => { expect(v(r)).toEqual({ tone, text }); });
});

describe("Can I trust it? card", () => {
  const meth = (o: Record<string, unknown> = {}) => ({ mean_drop: 0.4, ratio_to_random: 38.64, label_flip_rate: 0.25, share_flows_beating_random: 0.9, ...o });
  const faith = (o: Record<string, unknown> = {}) => ({
    model: "rf-v3", model_matches: true, flows: 12345, top_k: 5, random_mean_drop: 0.01,
    methods: { shap: meth(), lime: meth({ mean_drop: 0.2, ratio_to_random: 1.25, label_flip_rate: 0.1, share_flows_beating_random: 0.5 }) }, ...o,
  });
  const sensorWith = (f: unknown, o: Record<string, unknown> = {}) =>
    sensorState({ sensor_id: 3, name: "gw", status: report({ faithfulness: f }), ...o });
  const card = async () => within((await screen.findByText("Can I trust it?")).closest(".card") as HTMLElement);

  it("shows Loading… before the status arrives", async () => {
    let release!: () => void;
    sensorsGate = new Promise<void>((r) => { release = r; });
    show();
    await loaded();
    const c = await card();
    expect(c.getByText("Loading…")).toBeInTheDocument();
    release();
    await waitFor(() => expect(c.queryByText("Loading…")).toBeNull());
  });

  it("shows a status error and not the Loading text", async () => {
    sensorsError = new Error("status broke");
    show();
    await loaded();
    const c = await card();
    expect(await c.findByText("status broke")).toBeInTheDocument();
    expect(c.queryByText("Loading…")).toBeNull();
  });

  it("asks for the right endpoint", async () => {
    show();
    await loaded();
    await card();
    await waitFor(() => expect(h.api.mock.calls.some(([p]) => p === "/sensors/status")).toBe(true));
  });

  it("sensor not in the list: names it by number", async () => {
    sensorsBody = sensorsStatus([sensorState({ sensor_id: 99, name: "other" })]);
    show();
    await loaded();
    const c = await card();
    expect(await c.findByText(/Sensor #3 hasn't reported an explanation test/)).toBeInTheDocument();
    expect(c.getByText("IDPS_FAITHFULNESS_REPORT")).toBeInTheDocument();
  });

  it.each([["absent", undefined], ["null", null]])("sensor with faithfulness %s: names it by name", async (_n, f) => {
    sensorsBody = sensorsStatus([sensorWith(f)]);
    show();
    await loaded();
    const c = await card();
    expect(await c.findByText(/Sensor gw hasn't reported an explanation test/)).toBeInTheDocument();
    expect(c.queryByText(/test flows/)).toBeNull();
  });

  it("an offline sensor with a stored status still shows its faithfulness", async () => {
    sensorsBody = sensorsStatus([sensorWith(faith(), { online: false })]);
    show();
    await loaded();
    const c = await card();
    expect(await c.findByText("SHAP")).toBeInTheDocument();
  });

  it("an offline sensor without any status says it hasn't reported", async () => {
    sensorsBody = sensorsStatus([sensorState({ sensor_id: 3, name: "gw", online: false, status: null })]);
    show();
    await loaded();
    expect(await (await card()).findByText(/Sensor gw hasn't reported/)).toBeInTheDocument();
  });

  it("uses the alert's sensor, not another one", async () => {
    sensorsBody = sensorsStatus([
      sensorState({ sensor_id: 1, name: "first", status: report({ faithfulness: faith({ flows: 1, top_k: 9 }) }) }),
      sensorWith(faith({ flows: 2000, top_k: 4 })),
    ]);
    show();
    await loaded();
    const c = await card();
    expect(await c.findByText(/removing the 4 features it ranks highest/)).toBeInTheDocument();
    expect(c.queryByText(/removing the 9 features/)).toBeNull();
  });

  it("intro sentence uses top_k and the flow count", async () => {
    sensorsBody = sensorsStatus([sensorWith(faith())]);
    show();
    await loaded();
    const c = await card();
    const p = await c.findByText(/removing the 5 features it ranks highest/);
    expect(p.textContent).toMatch(/^If an explanation is faithful, removing the 5 features it ranks highest hurts the model far more than removing 5 random ones\./);
    expect(p.textContent).toContain(`Measured on a sample of ${(12345).toLocaleString()} flows:`);
    expect(c.getByText("Whether the explanation reflects what the model really used, not whether the prediction is right.")).toBeInTheDocument();
  });

  it("one row per method, SHAP then LIME, with ratio and the detail line", async () => {
    sensorsBody = sensorsStatus([sensorWith(faith())]);
    show();
    await loaded();
    const c = await card();
    await c.findByText("SHAP");
    const items = Array.from(c.getAllByRole("listitem")) as HTMLElement[];
    expect(items.map((li) => li.querySelector("b")!.textContent)).toEqual(["SHAP", "LIME"]);
    expect(items[0].querySelector(".trust-ratio")).toHaveTextContent("38.6×");
    expect(items[1].querySelector(".trust-ratio")).toHaveTextContent("1.25×");
    expect(items[0].textContent).toContain(`(${percent(0.4, 1)} vs ${percent(0.01, 1)})`);
    expect(items[0].textContent).toContain(`changed in ${percent(0.25)} of flows`);
    expect(items[0].textContent).toContain(`beat random on ${percent(0.9)} of flows`);
    expect(items[1].textContent).toContain(`(${percent(0.2, 1)} vs ${percent(0.01, 1)})`);
    expect(items[1].textContent).toContain(`changed in ${percent(0.1)} of flows`);
    expect(items[1].textContent).toContain(`beat random on ${percent(0.5)} of flows`);
  });

  it("only SHAP present: one row; only LIME present: one row", async () => {
    sensorsBody = sensorsStatus([sensorWith(faith({ methods: { shap: meth() } }))]);
    const { unmount } = show();
    await loaded();
    let c = await card();
    await c.findByText("SHAP");
    expect(c.queryByText("LIME")).toBeNull();
    expect(c.getAllByRole("listitem")).toHaveLength(1);
    unmount();
    sensorsBody = sensorsStatus([sensorWith(faith({ methods: { lime: meth() } }))]);
    show();
    await loaded();
    c = await card();
    await c.findByText("LIME");
    expect(c.queryByText("SHAP")).toBeNull();
  });

  it("no methods: intro but no rows", async () => {
    sensorsBody = sensorsStatus([sensorWith(faith({ methods: {} }))]);
    show();
    await loaded();
    const c = await card();
    await c.findByText(/removing the 5 features it ranks highest/);
    expect(c.queryAllByRole("listitem")).toHaveLength(0);
  });

  describe("used for this alert", () => {
    const usedRows = (_c: ReturnType<typeof within>) =>
      Array.from(document.querySelectorAll(".trust-list li.used")).map((li) => li.querySelector("b")!.textContent);

    it("marks the method the explanation used", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith())]);
      show();
      await loaded();
      const c = await card();
      expect(await c.findByText("used for this alert")).toHaveClass("pill");
      expect(usedRows(c)).toEqual(["SHAP"]);
      expect(c.getAllByText("used for this alert")).toHaveLength(1);
    });

    it("matches case-insensitively and can be LIME", async () => {
      alert = mkAlert({ explanation: { method: "LIME", predicted_class: "PortScan", top_features: [] } });
      sensorsBody = sensorsStatus([sensorWith(faith())]);
      show();
      await loaded();
      const c = await card();
      await c.findByText("used for this alert");
      expect(usedRows(c)).toEqual(["LIME"]);
    });

    it.each([["missing", { predicted_class: "PortScan", top_features: [] }], ["unknown", { method: "anchors", top_features: [] }],
      ["not a string", { method: 5, top_features: [] }]])("none when the method is %s", async (_n, ex) => {
      alert = mkAlert({ explanation: ex });
      sensorsBody = sensorsStatus([sensorWith(faith())]);
      show();
      await loaded();
      const c = await card();
      await c.findByText("SHAP");
      expect(c.queryByText("used for this alert")).toBeNull();
      expect(usedRows(c)).toEqual([]);
    });

    it("none when the alert has no explanation", async () => {
      alert = mkAlert({ explanation: null });
      sensorsBody = sensorsStatus([sensorWith(faith())]);
      show();
      await loaded();
      const c = await card();
      await c.findByText("SHAP");
      expect(c.queryByText("used for this alert")).toBeNull();
    });

    it("a method the sensor did not test is not shown as used", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith({ methods: { lime: meth() } }))]);
      show();
      await loaded();
      const c = await card();
      await c.findByText("LIME");
      expect(c.queryByText("used for this alert")).toBeNull();
    });
  });

  it("the first line is shown even before data and without faithfulness", async () => {
    show();
    await loaded();
    const c = await card();
    expect(c.getByText(/Whether the explanation reflects what the model really used/)).toBeInTheDocument();
    await c.findByText(/hasn't reported/);
    expect(c.getByText(/Whether the explanation reflects/)).toBeInTheDocument();
  });

  describe("verdict pill and ratio text in rows", () => {
    const rows = async () => {
      const c = await card();
      await c.findByText("SHAP");
      return Array.from(document.querySelectorAll(".trust-list li")) as HTMLElement[];
    };
    it("each row has a verdict pill", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith({ methods: { shap: meth({ ratio_to_random: 38.64 }), lime: meth({ ratio_to_random: 1.25 }) } }))]);
      show();
      await loaded();
      const [shap, lime] = await rows();
      expect(within(shap).getByText("better than random")).toHaveClass("pill", "ok");
      expect(within(lime).getByText("barely better than random")).toHaveClass("pill", "warn");
    });
    it("danger and neutral verdicts, with their ratio text", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith({ methods: { shap: meth({ ratio_to_random: -2 }), lime: meth({ ratio_to_random: null }) } }))]);
      show();
      await loaded();
      const [shap, lime] = await rows();
      expect(within(shap).getByText("no better than random")).toHaveClass("pill", "danger");
      expect(shap.querySelector(".trust-ratio")).toHaveTextContent("worse than random");
      expect(within(lime).getByText("no result")).toHaveClass("pill", "neutral");
      expect(lime.querySelector(".trust-ratio")).toHaveTextContent("—");
    });
    it("sr-only text follows the ratio when it is non-null and not negative", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith({ methods: { shap: meth({ ratio_to_random: 0 }), lime: meth({ ratio_to_random: 3 }) } }))]);
      show();
      await loaded();
      const [shap, lime] = await rows();
      expect(shap.querySelector(".trust-ratio .sr-only")).toHaveTextContent("the confidence drop of random features");
      expect(lime.querySelector(".trust-ratio .sr-only")).toHaveTextContent("the confidence drop of random features");
      expect(lime.querySelector(".trust-ratio")).toHaveTextContent("3× the confidence drop of random features");
    });
    it("no sr-only text for a null or negative ratio", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith({ methods: { shap: meth({ ratio_to_random: null }), lime: meth({ ratio_to_random: -1 }) } }))]);
      show();
      await loaded();
      const [shap, lime] = await rows();
      expect(shap.querySelector(".trust-ratio .sr-only")).toBeNull();
      expect(lime.querySelector(".trust-ratio .sr-only")).toBeNull();
    });
  });

  describe("stale last report", () => {
    const STALE = (w: string) => `This is the sensor's last report: it is ${w} now, so it may run a different model.`;
    const note = async () => (await (await card()).findByText(/Measured offline for model/)).textContent!;
    it("offline sensor", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith(), { online: false })]);
      show();
      await loaded();
      expect(await note()).toContain(STALE("offline"));
    });
    it("revoked sensor", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith(), { revoked: true, online: false })]);
      show();
      await loaded();
      expect(await note()).toContain(STALE("revoked"));
    });
    it("a revoked sensor that is still marked online says revoked", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith(), { revoked: true })]);
      show();
      await loaded();
      expect(await note()).toContain(STALE("revoked"));
    });
    it("online sensor: no stale sentence", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith())]);
      show();
      await loaded();
      expect(await note()).not.toContain("last report");
    });
    it("a revoked sensor shown to analysts has no status, so the card says it hasn't reported", async () => {
      sensorsBody = sensorsStatus([sensorState({ sensor_id: 3, name: "gw", revoked: true, online: false, status: null })]);
      show();
      await loaded();
      expect(await (await card()).findByText(/Sensor gw hasn't reported/)).toBeInTheDocument();
    });
  });

  describe("model_check", () => {
    const note = async (o: Record<string, unknown>) => {
      sensorsBody = sensorsStatus([sensorWith(faith(o))]);
      show();
      await loaded();
      return (await (await card()).findByText(/Measured offline for model/)).textContent!;
    };
    const SENT = "The report only names the algorithm, so a retrained model of the same kind would also match.";
    it("name + matching: adds the sentence", async () => { expect(await note({ model_check: "name" })).toContain(SENT); });
    it("digest: no sentence", async () => { expect(await note({ model_check: "digest" })).not.toContain(SENT); });
    it("absent (older SOC): no sentence", async () => { expect(await note({})).not.toContain(SENT); });
    it("name but not matching: only the different-model sentence", async () => {
      const t = await note({ model_check: "name", model_matches: false });
      expect(t).not.toContain(SENT);
      expect(t).toContain("different model than the one tested");
    });
  });

  describe("model_matches", () => {
    it("true: no warning pill and no extra sentence", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith())]);
      show();
      await loaded();
      const c = await card();
      const note = await c.findByText(/Measured offline for model/);
      expect(note.textContent).toContain("rf-v3");
      expect(note.textContent).not.toContain("different model");
      expect(c.queryByText("test was for another model")).toBeNull();
    });

    it("false: pill and the extra sentence", async () => {
      sensorsBody = sensorsStatus([sensorWith(faith({ model_matches: false }))]);
      show();
      await loaded();
      const c = await card();
      expect(await c.findByText("test was for another model")).toHaveClass("pill");
      expect(c.getByText(/Measured offline for model/).textContent)
        .toContain("The sensor runs a different model than the one tested, so these numbers may not apply.");
    });

    it("no pill when there is no faithfulness data", async () => {
      sensorsBody = sensorsStatus([sensorWith(null)]);
      show();
      await loaded();
      const c = await card();
      await c.findByText(/hasn't reported/);
      expect(c.queryByText("test was for another model")).toBeNull();
    });
  });
});

describe("step 7: model row and learning", () => {
  const sha = "0123456789abcdef0123";
  const patches = () => calls("PATCH", "/alerts/7").map(([, o]) => o.json);

  it("Model row: version, else first 12 of sha256, else not reported", async () => {
    alert = mkAlert({ model_version: "v-2026-11", model_sha256: sha }) as never;
    const a = show();
    await loaded();
    expect(screen.getByText("v-2026-11")).toBeInTheDocument();
    a.unmount();
    alert = mkAlert({ model_version: null, model_sha256: sha }) as never;
    const b = show();
    await loaded();
    expect(screen.getByText("sha256 0123456789ab")).toBeInTheDocument();
    b.unmount();
    alert = mkAlert({ model_version: null, model_sha256: null }) as never;
    show();
    await loaded();
    expect(screen.getByText("not reported by this sensor")).toBeInTheDocument();
  });

  it("status control has all five statuses, including confirmed", async () => {
    show();
    await loaded();
    const group = screen.getByRole("group", { name: "Status" });
    expect(within(group).getAllByRole("button")).toHaveLength(5);
    expect(ALERT_STATUSES).toContain("confirmed");
    expect(within(group).getByRole("button", { name: label("confirmed") })).toBeInTheDocument();
  });

  it("no Real class select unless confirmed", async () => {
    alert = mkAlert({ has_features: true, status: "new" }) as never;
    show();
    await loaded();
    expect(screen.queryByLabelText("Real class")).toBeNull();
    expect(screen.getByText("Mark it confirmed or false positive to use it for retraining.")).toBeInTheDocument();
  });

  it("confirmed: select lists As predicted then other classes, without the predicted one; text names predicted class", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: null }) as never;
    show();
    await loaded();
    const sel = screen.getByLabelText("Real class") as HTMLSelectElement;
    const opts = within(sel).getAllByRole("option").map((o) => o.textContent);
    expect(opts[0]).toBe("As predicted (PortScan)");
    expect(opts).not.toContain("PortScan");
    expect(opts).toHaveLength(14); // 1 + 14 classes - predicted
    expect(sel.value).toBe("");
    expect(screen.getByText(/Used as a training row labelled/).querySelector("b")).toHaveTextContent("PortScan");
  });

  it("confirmed with a correction: text names true_class; picking one PATCHes confirmed + true_class", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: "Bot" }) as never;
    show();
    await loaded();
    expect(screen.getByText("Bot", { selector: "b" })).toBeInTheDocument();
    const sel = screen.getByLabelText("Real class") as HTMLSelectElement;
    expect(sel.value).toBe("Bot");
    fireEvent.change(sel, { target: { value: "DDoS" } });
    await waitFor(() => expect(patches()).toEqual([{ status: "confirmed", true_class: "DDoS" }]));
  });

  it("choosing As predicted sends true_class null", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: "Bot" }) as never;
    show();
    await loaded();
    fireEvent.change(screen.getByLabelText("Real class"), { target: { value: "" } });
    await waitFor(() => expect(patches()).toEqual([{ status: "confirmed", true_class: null }]));
  });

  it("false positive trains as BENIGN", async () => {
    alert = mkAlert({ has_features: true, status: "false_positive" }) as never;
    show();
    await loaded();
    expect(screen.getByText("BENIGN", { selector: "b" })).toBeInTheDocument();
  });

  it("without features the alert can't be used, even when confirmed", async () => {
    alert = mkAlert({ has_features: false, status: "confirmed" }) as never;
    show();
    await loaded();
    expect(screen.getByText(/can't be used for retraining/)).toBeInTheDocument();
  });

  it("leaving confirmed with a correction clears true_class; without one it sends status only", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: "Bot" }) as never;
    const a = show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: label("false_positive") }));
    await waitFor(() => expect(patches()).toEqual([{ status: "false_positive", true_class: null }]));
    a.unmount();
    h.api.mockClear();
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: null }) as never;
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: label("false_positive") }));
    await waitFor(() => expect(patches()).toEqual([{ status: "false_positive" }]));
  });

  it("choosing confirmed from new sends status only", async () => {
    alert = mkAlert({ has_features: true }) as never;
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: label("confirmed") }));
    await waitFor(() => expect(patches()).toEqual([{ status: "confirmed" }]));
  });

  it("moving to confirmed with a stored BENIGN true_class clears it; other stored classes are kept", async () => {
    alert = mkAlert({ has_features: true, status: "false_positive", true_class: "BENIGN" }) as never;
    const a = show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: label("confirmed") }));
    await waitFor(() => expect(patches()).toEqual([{ status: "confirmed", true_class: null }]));
    a.unmount();
    h.api.mockClear();
    alert = mkAlert({ has_features: true, status: "new", true_class: "Bot" }) as never;
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: label("confirmed") }));
    await waitFor(() => expect(patches()).toEqual([{ status: "confirmed" }]));
  });

  it("select shows As predicted when true_class equals predicted_class", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: "PortScan" }) as never;
    show();
    await loaded();
    expect((screen.getByLabelText("Real class") as HTMLSelectElement).value).toBe("");
  });

  it("a stored class outside the list (BENIGN) is its own first option and selected", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: "BENIGN" }) as never;
    show();
    await loaded();
    const sel = screen.getByLabelText("Real class") as HTMLSelectElement;
    const opts = within(sel).getAllByRole("option").map((o) => o.textContent);
    expect(opts.slice(0, 2)).toEqual(["As predicted (PortScan)", "BENIGN"]);
    expect(opts).toHaveLength(15);
    expect(sel.value).toBe("BENIGN");
  });

  it("the training-label text is a polite live region", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed" }) as never;
    show();
    await loaded();
    expect(screen.getByText(/Used as a training row/).closest("p")).toHaveAttribute("aria-live", "polite");
  });

  it("a failed select PATCH keeps the previous value and shows the error", async () => {
    alert = mkAlert({ has_features: true, status: "confirmed", true_class: "Bot" }) as never;
    show();
    await loaded();
    const impl = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (path: string, opts?: { method?: string }) => {
      if (opts?.method === "PATCH") throw new Error("save failed");
      return impl(path, opts);
    });
    const sel = screen.getByLabelText("Real class") as HTMLSelectElement;
    fireEvent.change(sel, { target: { value: "DDoS" } });
    expect(await screen.findByText(/save failed/)).toBeInTheDocument();
    expect((screen.getByLabelText("Real class") as HTMLSelectElement).value).toBe("Bot");
    expect(screen.getByText("Bot", { selector: "b" })).toBeInTheDocument();
  });
});
