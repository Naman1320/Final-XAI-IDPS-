import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { report, sensorState, sensorsStatus } from "./sensor-fixtures";
import ThreatCenter from "../pages/ThreatCenter";

const h = vi.hoisted(() => ({ api: vi.fn(), onAlert: null as null | ((a: unknown) => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (_f: () => void, onAlert?: (a: unknown) => void) => { if (onAlert) h.onAlert = onAlert; return true; },
}));
vi.mock("../pages/WorldMap", () => ({ default: () => <div>map-stub</div> }));

const iso = (ms: number) => new Date(Date.now() + ms).toISOString();
const alert = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 1, predicted_class: "PortScan", confidence: 0.9, severity: "high", status: "new",
  src_ip: "10.0.0.1", src_port: 1000, dst_ip: "10.0.0.9", dst_port: 22, protocol: "TCP", received_at: iso(-5 * 60_000), ...o,
});
const metrics = (o: Record<string, unknown> = {}) => ({
  alerts_total: 1234, by_class: { PortScan: 50 }, top_sources: [], alerts_per_bucket: [{ count: 1 }],
  detection_latency: { p50_ms: 1500, p95_ms: 4000 }, active_blocks: 2, false_positive_rate: 0.2,
  false_positives: 2, triaged: 10, ...o,
});
const page = (items: unknown[]) => ({ items, total: items.length, next_cursor: null });

let d: { metrics: unknown; sensors: unknown; alerts: unknown[] };
beforeEach(() => {
  d = { metrics: metrics(), sensors: sensorsStatus(), alerts: [] };
  h.api.mockReset();
  h.onAlert = null;
  h.api.mockImplementation(async (path: string) => {
    if (path.startsWith("/metrics/summary")) return d.metrics;
    if (path.startsWith("/sensors/status")) return d.sensors;
    if (path.startsWith("/blocks/would")) return page([]);
    if (path.startsWith("/blocks")) return page([]);
    if (path.startsWith("/alerts")) return page(d.alerts);
    if (path.startsWith("/actions")) return page([]);
    if (path.startsWith("/topology")) return { hours: 24, nodes: [], edges: [] };
    throw new Error(`unexpected ${path}`);
  });
});
const show = () => render(<MemoryRouter><ThreatCenter /></MemoryRouter>);
const cardOf = (t: string) => screen.getByText(t).closest(".card") as HTMLElement;
const liveCard = () => cardOf("Live alerts");
const alertCalls = () => h.api.mock.calls.map(([p]) => String(p)).filter((p) => p.startsWith("/alerts"));

describe("Live alerts Raised by", () => {
  it("adds source= to GET /alerts and drops it when cleared", async () => {
    show();
    await within(liveCard()).findByText(/No alerts yet/);
    expect(alertCalls().at(-1)).not.toContain("source");
    const sel = within(liveCard()).getByLabelText("Raised by");
    fireEvent.change(sel, { target: { value: "rule" } });
    await waitFor(() => expect(alertCalls().at(-1)).toContain("source=rule"));
    fireEvent.change(sel, { target: { value: "ml" } });
    await waitFor(() => expect(alertCalls().at(-1)).toContain("source=ml"));
    fireEvent.change(sel, { target: { value: "" } });
    await waitFor(() => expect(alertCalls().at(-1)).not.toContain("source"));
  });

  it("filters websocket alerts; no source counts as ml", async () => {
    show();
    await within(liveCard()).findByText(/No alerts yet/);
    fireEvent.change(within(liveCard()).getByLabelText("Raised by"), { target: { value: "rule" } });
    await waitFor(() => expect(alertCalls().at(-1)).toContain("source=rule"));
    await within(liveCard()).findByText(/No alerts yet/);
    act(() => h.onAlert!(alert({ id: 11, predicted_class: "NoSrc" })));
    act(() => h.onAlert!(alert({ id: 12, predicted_class: "IsMl", source: "ml" })));
    act(() => h.onAlert!(alert({ id: 13, predicted_class: "IsRule", source: "rule" })));
    expect(await within(liveCard()).findByText("IsRule")).toBeInTheDocument();
    expect(within(liveCard()).queryByText("NoSrc")).toBeNull();
    expect(within(liveCard()).queryByText("IsMl")).toBeNull();

    fireEvent.change(within(liveCard()).getByLabelText("Raised by"), { target: { value: "ml" } });
    await waitFor(() => expect(alertCalls().at(-1)).toContain("source=ml"));
    await within(liveCard()).findByText(/No alerts yet/);
    act(() => h.onAlert!(alert({ id: 21, predicted_class: "NoSrc2" })));
    act(() => h.onAlert!(alert({ id: 22, predicted_class: "IsRule2", source: "rule" })));
    expect(await within(liveCard()).findByText("NoSrc2")).toBeInTheDocument();
    expect(within(liveCard()).queryByText("IsRule2")).toBeNull();
  });

  it("shows the rule tag only on rule rows", async () => {
    d.alerts = [alert({ id: 1, source: "rule" }), alert({ id: 2, source: "ml" }), alert({ id: 3 })];
    show();
    await within(liveCard()).findByText("#1 · 5 min ago");
    expect(liveCard().querySelectorAll(".source-tag")).toHaveLength(1);
  });

  it.each([["rule", "No alerts yet from rules."], ["ml", "No alerts yet from the model."]])("empty message for %s", async (v, text) => {
    show();
    await within(liveCard()).findByText(/No alerts yet/);
    fireEvent.change(within(liveCard()).getByLabelText("Raised by"), { target: { value: v } });
    expect(await within(liveCard()).findByText(text)).toBeInTheDocument();
  });

  it("empty message combines severity and source", async () => {
    show();
    await within(liveCard()).findByText(/No alerts yet/);
    fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
    fireEvent.change(within(liveCard()).getByLabelText("Raised by"), { target: { value: "rule" } });
    expect(await within(liveCard()).findByText("No alerts yet with severity high from rules.")).toBeInTheDocument();
  });
});

describe("Alerts KPI source line", () => {
  const kpi = () => cardOf("Alerts").textContent ?? "";
  it("shows model X · rules Y when rule alerts exist", async () => {
    d.metrics = metrics({ by_source: { ml: 1200, rule: 34 } });
    show();
    await waitFor(() => expect(kpi()).toContain("model 1,200 · rules 34"));
    expect(kpi()).toContain("PortScan 50");
  });
  it("hides it when by_source.rule is 0 or by_source is absent", async () => {
    d.metrics = metrics({ by_source: { ml: 1234, rule: 0 } });
    const { unmount } = show();
    await waitFor(() => expect(kpi()).toContain("1,234"));
    expect(kpi()).not.toContain("rules");
    unmount();
    d.metrics = metrics();
    show();
    await waitFor(() => expect(kpi()).toContain("1,234"));
    expect(kpi()).not.toMatch(/model \d|rules/);
  });
});

describe("Sensor health Rules row", () => {
  const rules = (o: Record<string, unknown> = {}) => ({
    enabled: true, eve_path: "/var/log/eve.json", alerts_sent: 1234, dropped_engine: 0, dropped_info: 0, deduped: 0,
    dropped_invalid: 0, last_event_at: null, error: null, include_info: false, dedupe_seconds: 60, block_sids: 0, ...o,
  });
  const rulesText = async (status: Record<string, unknown>) => {
    d.sensors = sensorsStatus([sensorState({ status: report(status), last_seen_at: iso(-3 * 60_000) })]);
    show();
    await within(cardOf("Sensor health")).findByText("Rules");
    return (within(cardOf("Sensor health")).getByText("Rules").nextElementSibling as HTMLElement).textContent;
  };
  it("dash when rules is missing or null", async () => {
    expect(await rulesText({})).toBe("—");
  });
  it("dash when rules is null", async () => {
    expect(await rulesText({ rules: null })).toBe("—");
  });
  it("off when disabled, even with an error", async () => {
    expect(await rulesText({ rules: rules({ enabled: false, error: "boom" }) })).toBe("off");
  });
  it("the error text when set", async () => {
    expect(await rulesText({ rules: rules({ error: "eve.json not found" }) })).toBe("eve.json not found");
  });
  it("Suricata with a formatted sent count otherwise", async () => {
    expect(await rulesText({ rules: rules() })).toBe("Suricata · 1,234 sent");
  });
});

describe("Live alerts rule rows", () => {
  const ids = () => within(liveCard()).getAllByRole("row").slice(1).map((r) => /#(\d+)/.exec(r.textContent ?? "")![1]);
  it("shows rule instead of the confidence bar for rule alerts", async () => {
    d.alerts = [alert({ id: 1, source: "rule", confidence: 0.99 }), alert({ id: 2, confidence: 0.8 })];
    show();
    await within(liveCard()).findByText("#1 · 5 min ago");
    const rows = within(liveCard()).getAllByRole("row").slice(1);
    const r1 = rows.find((r) => /#1 /.test(r.textContent!))!;
    const r2 = rows.find((r) => /#2 /.test(r.textContent!))!;
    expect(r1.querySelector(".source-tag")).not.toBeNull();
    expect(r1.textContent).not.toMatch(/99/);
    expect(within(r1).getAllByText("rule").length).toBeGreaterThan(1);
    expect(r2.textContent).toMatch(/80/);
    expect(r2.querySelector(".source-tag")).toBeNull();
  });

  it("confidence sort puts rule alerts after model alerts", async () => {
    d.alerts = [
      alert({ id: 1, source: "rule", confidence: 1 }), alert({ id: 2, confidence: 0.2 }),
      alert({ id: 3, confidence: 0.9 }), alert({ id: 4, source: "rule", confidence: 1 }),
    ];
    show();
    await within(liveCard()).findByText("#4 · 5 min ago");
    fireEvent.change(within(liveCard()).getByLabelText("Sort"), { target: { value: "confidence" } });
    expect(ids()).toEqual(["3", "2", "4", "1"]);
  });
});
