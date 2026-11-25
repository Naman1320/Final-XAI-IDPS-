import { act, cleanup, render, screen } from "@testing-library/react";
import { blockingMode, reporting, useSensors } from "../sensors";
import { report, sensorState, sensorsStatus } from "./sensor-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn() }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));

function Probe({ id }: { id: string }) {
  const { data, error } = useSensors();
  return <div data-testid={id}>{data ? `${data.sensors.length} sensors` : "none"}|{error ?? "ok"}</div>;
}
const txt = (id: string) => screen.getByTestId(id).textContent;
const status = (n: number) => sensorsStatus(Array.from({ length: n }, (_, i) => sensorState({ sensor_id: i + 1 })));
const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  h.api.mockReset();
  h.api.mockResolvedValue(status(1));
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("useSensors store", () => {
  it("fetches on the first subscriber, and many components share one request", async () => {
    render(<><Probe id="a" /><Probe id="b" /><Probe id="c" /></>);
    await flush();
    expect(h.api).toHaveBeenCalledTimes(1);
    expect(h.api).toHaveBeenCalledWith("/sensors/status");
    expect(txt("a")).toBe("1 sensors|ok");
    expect(txt("b")).toBe("1 sensors|ok");
    expect(txt("c")).toBe("1 sensors|ok");
  });

  it("a later subscriber gets the current snapshot without a new request", async () => {
    const { rerender } = render(<Probe id="a" />);
    await flush();
    rerender(<><Probe id="a" /><Probe id="b" /></>);
    await flush();
    expect(h.api).toHaveBeenCalledTimes(1);
    expect(txt("b")).toBe("1 sensors|ok");
  });

  it("polls every 30 s while mounted", async () => {
    render(<Probe id="a" />);
    await flush();
    await tick(29_999);
    expect(h.api).toHaveBeenCalledTimes(1);
    h.api.mockResolvedValue(status(2));
    await tick(1);
    expect(h.api).toHaveBeenCalledTimes(2);
    expect(txt("a")).toBe("2 sensors|ok");
    await tick(30_000);
    expect(h.api).toHaveBeenCalledTimes(3);
  });

  it("keeps the last good data on a failed poll and recovers", async () => {
    render(<Probe id="a" />);
    await flush();
    h.api.mockRejectedValue(new Error("status down"));
    await tick(30_000);
    expect(txt("a")).toBe("1 sensors|status down");
    h.api.mockResolvedValue(status(3));
    await tick(30_000);
    expect(txt("a")).toBe("3 sensors|ok");
  });

  it("a failed first load shows the error with no data", async () => {
    h.api.mockRejectedValue(new Error("boom"));
    render(<Probe id="a" />);
    await flush();
    expect(txt("a")).toBe("none|boom");
  });

  it("stops polling and resets when the last subscriber unmounts", async () => {
    const { unmount } = render(<><Probe id="a" /><Probe id="b" /></>);
    await flush();
    unmount();
    await tick(120_000);
    expect(h.api).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    // the next user starts from nothing and refetches
    let release!: (v: unknown) => void;
    h.api.mockReturnValue(new Promise((r) => { release = r; }));
    render(<Probe id="a" />);
    expect(txt("a")).toBe("none|ok");
    expect(h.api).toHaveBeenCalledTimes(2);
    release(status(2));
    await flush();
    expect(txt("a")).toBe("2 sensors|ok");
  });

  it("keeps polling while at least one subscriber remains", async () => {
    const { rerender } = render(<><Probe id="a" /><Probe id="b" /></>);
    await flush();
    rerender(<Probe id="a" />);
    await tick(30_000);
    expect(h.api).toHaveBeenCalledTimes(2);
  });

  it("ignores a response that lands after everyone left", async () => {
    let r1!: (v: unknown) => void;
    let r2!: (v: unknown) => void;
    h.api.mockReturnValueOnce(new Promise((r) => { r1 = r; }));
    const first = render(<Probe id="a" />);
    first.unmount();
    h.api.mockReturnValueOnce(new Promise((r) => { r2 = r; }));
    render(<Probe id="a" />);
    r1(status(5)); // stale
    await flush();
    expect(txt("a")).toBe("none|ok");
    r2(status(2));
    await flush();
    expect(txt("a")).toBe("2 sensors|ok");
  });

  it("a stale error after unmount is ignored too", async () => {
    let rej!: (e: Error) => void;
    h.api.mockReturnValueOnce(new Promise((_, r) => { rej = r; }));
    render(<Probe id="a" />).unmount();
    h.api.mockResolvedValueOnce(status(1));
    render(<Probe id="a" />);
    rej(new Error("late"));
    await flush();
    expect(txt("a")).toBe("1 sensors|ok");
  });
});

describe("reporting", () => {
  it("keeps online, non-revoked sensors that have a status", () => {
    const data = sensorsStatus([
      sensorState({ sensor_id: 1 }),
      sensorState({ sensor_id: 2, online: false }),
      sensorState({ sensor_id: 3, revoked: true }),
      sensorState({ sensor_id: 4, status: null }),
    ]) as never;
    expect(reporting(data).map((s) => s.sensor_id)).toEqual([1]);
  });
  it("null data is empty", () => { expect(reporting(null)).toEqual([]); });
});

describe("blockingMode", () => {
  const mk = (...o: Record<string, unknown>[]) =>
    sensorsStatus(o.map((r, i) => sensorState({ sensor_id: i + 1, status: report(r) }))) as never;
  it("unknown without data or reporting sensors", () => {
    expect(blockingMode(null)).toBe("unknown");
    expect(blockingMode(sensorsStatus([sensorState({ online: false })]) as never)).toBe("unknown");
  });
  it("on, dry-run, mixed", () => {
    expect(blockingMode(mk({}, {}))).toBe("on");
    expect(blockingMode(mk({ dry_run: true }, { blocking_enabled: false }))).toBe("dry-run");
    expect(blockingMode(mk({}, { dry_run: true }))).toBe("mixed");
  });
  it("dry_run wins over blocking_enabled", () => {
    expect(blockingMode(mk({ dry_run: true, blocking_enabled: true }))).toBe("dry-run");
  });
});
