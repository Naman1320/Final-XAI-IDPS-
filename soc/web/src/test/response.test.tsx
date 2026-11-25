import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import Response, { exactPercent, linkReason, ttlText } from "../pages/Response";
import { policy, report, sensorState, sensorsStatus } from "./sensor-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), reload: null as null | (() => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({ useLiveRefresh: (fn: () => void) => { h.reload = fn; return true; } }));

interface P { items: unknown[]; next_cursor?: string | null }
interface Data {
  blocks: unknown[]; pending: P; confirmed: P; alerts: unknown[];
  done: Record<string, P>; older: Record<string, P>;
}
let data: Data;
let sensorsBody: unknown;
let postError: Error | null;
let postGate: Promise<void> | null;
let alertGate: Promise<void> | null;
let alertById: Record<string, unknown>;
let alertByIdGate: Promise<void> | null;
let olderGate: Promise<void> | null;
let olderFail: Error | null;

// user-event is not installed; fireEvent is enough for these controls.
const userEvent = {
  click: async (el: Element) => { fireEvent.click(el); },
  type: async (el: Element, text: string) => { fireEvent.change(el, { target: { value: text } }); },
  selectOptions: async (el: Element, v: string) => {
    const sel = el as HTMLSelectElement;
    const opt = Array.from(sel.options).find((o) => o.value === v || o.text === v)!;
    fireEvent.change(sel, { target: { value: opt.value } });
  },
};

const iso = (ms: number) => new Date(Date.now() + ms).toISOString();
const block = (o: Record<string, unknown> = {}) => ({
  id: 1, ip: "10.10.1.10", sensor_id: 1, source: "auto", reason: "port scan", alert_id: null, active: true,
  blocked_at: iso(-60_000), expires_at: iso(600_000), unblocked_at: null, ...o,
});
const action = (o: Record<string, unknown> = {}) => ({
  id: 3, kind: "block_ip", status: "pending", proposed_by: "assistant", sensor_id: 1, reason: "looks bad",
  params: { ip: "10.10.1.10", ttl_seconds: 900 }, result: null, created_at: iso(-1000), ...o,
});

function calls(method: string, prefix: string) {
  return h.api.mock.calls.filter(([p, o]) => (o?.method ?? "GET") === method && String(p).startsWith(prefix));
}
const posts = () => h.api.mock.calls.filter(([, o]) => o?.method === "POST");
const LISTS = ["/blocks", "/actions?status=pending", "/actions?status=confirmed", "/actions?status=executed"];
async function expectAllReloaded(n: number) {
  await waitFor(() => { for (const l of LISTS) expect(calls("GET", l).length).toBe(n); });
}

beforeEach(() => {
  data = { blocks: [], pending: { items: [] }, confirmed: { items: [] }, alerts: [], done: {}, older: {} };
  sensorsBody = sensorsStatus();
  postError = null;
  postGate = null;
  alertGate = null;
  alertById = {};
  alertByIdGate = null;
  olderGate = null;
  olderFail = null;
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string; json?: Record<string, unknown> }) => {
    if (opts?.method === "POST") {
      if (postGate) await postGate;
      if (postError) throw postError;
      if (path === "/actions") return { id: 9, status: "pending", ...opts.json };
      return { id: 3, status: "confirmed" };
    }
    if (path === "/sensors/status") return sensorsBody;
    const page = (items: unknown[], next_cursor: string | null = null) => ({ items, total: items.length, next_cursor });
    if (path.startsWith("/blocks")) return page(data.blocks);
    const byId = /^\/alerts\/(\d+)$/.exec(path);
    if (byId) {
      if (alertByIdGate) await alertByIdGate;
      if (!(byId[1] in alertById)) throw new Error("not found");
      return alertById[byId[1]];
    }
    if (path.startsWith("/alerts?limit=1")) {
      if (alertGate) await alertGate;
      return page(data.alerts);
    }
    const m = /^\/actions\?status=(\w+)&limit=(\d+)(?:&cursor=(\w+))?$/.exec(path);
    if (!m) throw new Error(`unexpected ${path}`);
    const [, status, , cursor] = m;
    if (cursor) {
      if (olderGate) await olderGate;
      if (olderFail) throw olderFail;
    }
    const src: P = cursor ? (data.older[cursor] ?? { items: [] })
      : status === "pending" ? data.pending : status === "confirmed" ? data.confirmed : (data.done[status] ?? { items: [] });
    return page(src.items, src.next_cursor ?? null);
  });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  Element.prototype.scrollIntoView = vi.fn(); // not implemented by jsdom
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname + l.search}</div>; }
function Nav({ to }: { to: string }) { const n = useNavigate(); return <button onClick={() => n(to)}>go-there</button>; }
const show = (url = "/response", to = "/response") =>
  render(<MemoryRouter initialEntries={[url]}><Response /><Loc /><Nav to={to} /></MemoryRouter>);
const form = () => within(document.getElementById("new-block") as HTMLElement);

describe("ttlText", () => {
  it.each([[900, "15 min"], [3600, "1 h"], [86400, "24 h"], [172800, "2 d"], [90, "90 s"]])("%s -> %s", (s, t) => {
    expect(ttlText(s)).toBe(t);
  });
  it.each([["900"], [null], [undefined], [NaN], [Infinity]])("%s -> null", (v) => {
    expect(ttlText(v)).toBeNull();
  });
});

describe("exactPercent", () => {
  it.each([[0.925, "92.5%"], [0.9, "90%"], [0.6, "60%"], [1, "100%"], [0, "0%"], [0.1 + 0.2, "30%"], [0.07, "7%"], [0.12345, "12.345%"]])(
    "%s -> %s", (x, t) => { expect(exactPercent(x)).toBe(t); });
  it("has no float noise", () => { expect(exactPercent(0.57)).toBe("57%"); expect(exactPercent(0.29)).toBe("29%"); });
});

describe("blocks table", () => {
  it("shows countdown + unblock for active, ended text and no button for ended", async () => {
    data.blocks = [
      block(),
      block({ id: 2, ip: "10.10.1.20", active: false, source: "analyst", unblocked_at: iso(-5000) }),
    ];
    show();
    expect(await screen.findByRole("button", { name: "Unblock 10.10.1.10" })).toBeInTheDocument();
    expect(screen.getByText(/left$/)).toBeInTheDocument();
    expect(screen.getByText(/^ended /)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unblock 10.10.1.20" })).toBeNull();
    expect(screen.getByText("auto")).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
  });

  it("an active block already past its expiry has no Unblock button", async () => {
    data.blocks = [block({ blocked_at: iso(-120_000), expires_at: iso(-60_000) })];
    show();
    expect(await screen.findByText("expired")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Unblock/ })).toBeNull();
  });

  it("empty state", async () => {
    show();
    expect(await screen.findByText("No active blocks.")).toBeInTheDocument();
  });

  it("links to the alert", async () => {
    data.blocks = [block({ alert_id: 7 })];
    show();
    expect(await screen.findByRole("link", { name: "alert #7" })).toHaveAttribute("href", "/alerts/7");
  });

  it("show=all drops active=true", async () => {
    show();
    await screen.findByText("No active blocks.");
    expect(String(calls("GET", "/blocks")[0][0])).toContain("active=true");
    await userEvent.selectOptions(screen.getByLabelText("Show"), "all");
    await waitFor(() => expect(calls("GET", "/blocks").length).toBe(2));
    expect(String(calls("GET", "/blocks")[1][0])).not.toContain("active");
    expect(await screen.findByText("No blocks.")).toBeInTheDocument();
  });
});

describe("unblock", () => {
  it("posts unblock_ip and reloads all four lists", async () => {
    data.blocks = [block({ id: 5, sensor_id: 2 })];
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Unblock 10.10.1.10" }));
    await waitFor(() => expect(posts().length).toBe(1));
    expect(posts()[0][0]).toBe("/actions");
    expect(posts()[0][1].json).toEqual({
      kind: "unblock_ip", ip: "10.10.1.10", sensor_id: 2, reason: "analyst unblock of block #5",
    });
    await expectAllReloaded(2);
    expect(screen.getByRole("status")).toHaveTextContent("Unblock requested (action #9");
  });

  it("cancelled confirm sends nothing", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    data.blocks = [block()];
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Unblock 10.10.1.10" }));
    expect(posts().length).toBe(0);
    expect(calls("GET", "/blocks").length).toBe(1);
  });
});

describe("action queue", () => {
  it("pending count, provenance and summary", async () => {
    data.pending = { items: [action(), action({ id: 4, proposed_by: "user" })] };
    show();
    expect(await screen.findByRole("button", { name: "Pending · 2" })).toBeInTheDocument();
    expect(screen.getByText(/Proposed by the assistant/)).toBeInTheDocument();
    expect(screen.getByText(/Requested by an analyst/)).toBeInTheDocument();
    expect(screen.getByText("#3 block ip 10.10.1.10 · 15 min · sensor #1")).toBeInTheDocument();
  });

  it("tab labels: loading ellipsis, n and n+", async () => {
    data.pending = { items: [action()], next_cursor: "more" };
    data.confirmed = { items: [action({ id: 8, status: "confirmed" })] };
    show();
    expect(screen.getByRole("button", { name: "Pending · …" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirmed · …" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Pending · 1+" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Confirmed · 1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Done" })).toBeInTheDocument();
  });

  it("requests each list by status", async () => {
    show();
    await expectAllReloaded(1);
    expect(calls("GET", "/actions?status=pending&limit=200").length).toBe(1);
    expect(calls("GET", "/actions?status=confirmed&limit=200").length).toBe(1);
    expect(calls("GET", "/actions?status=executed&limit=50").length).toBe(1);
    expect(h.api.mock.calls.some(([p]) => String(p) === "/actions?limit=100")).toBe(false);
  });

  it("a block without ttl says the sensor's default block time", async () => {
    data.pending = { items: [action({ params: { ip: "10.10.1.10" } })] };
    show();
    expect(await screen.findByText("#3 block ip 10.10.1.10 · sensor's default block time · sensor #1"))
      .toBeInTheDocument();
  });

  it("confirm shows the reason in the dialog, posts and reloads everything", async () => {
    data.pending = { items: [action()] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Confirm action #3" }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("Reason: looks bad"));
    await waitFor(() => expect(posts().map((c) => c[0])).toEqual(["/actions/3/confirm"]));
    await expectAllReloaded(2);
  });

  it("cancelled confirm sends nothing", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    data.pending = { items: [action()] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Confirm action #3" }));
    expect(posts().length).toBe(0);
  });

  it("reject posts without a confirm dialog and reloads everything", async () => {
    data.pending = { items: [action()] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Reject action #3" }));
    await waitFor(() => expect(posts().map((c) => c[0])).toEqual(["/actions/3/reject"]));
    expect(window.confirm).not.toHaveBeenCalled();
    await expectAllReloaded(2);
  });

  it("confirmed tab lists the confirmed fetch with reason", async () => {
    data.confirmed = { items: [action({ id: 10, status: "confirmed", reason: "because" })] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Confirmed · 1" }));
    expect(await screen.findByText(/^#10 /)).toBeInTheDocument();
    expect(screen.getByText("confirmed · waiting for the sensor")).toBeInTheDocument();
    expect(screen.getByText("“because”")).toBeInTheDocument();
  });

  it("done tab: status select, sensor text, load older", async () => {
    data.done.executed = { items: [action({ id: 11, status: "executed", result: { message: "blocked ok" } })], next_cursor: "c1" };
    data.older.c1 = { items: [action({ id: 12, status: "executed" })], next_cursor: "c2" };
    data.older.c2 = { items: [action({ id: 13, status: "executed" })], next_cursor: null };
    data.done.failed = { items: [action({ id: 14, status: "failed", result: { error: "nft exploded" } })] };
    data.done.rejected = { items: [action({ id: 15, status: "rejected", reason: "nope" })] };
    show();
    await screen.findByText("No active blocks.");
    await userEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByText(/^#11 /)).toBeInTheDocument();
    expect(screen.getByText("Sensor: blocked ok")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Load older" }));
    expect(await screen.findByText(/^#12 /)).toBeInTheDocument();
    expect(screen.getByText(/^#11 /)).toBeInTheDocument();
    expect(calls("GET", "/actions?status=executed&limit=50&cursor=c1").length).toBe(1);
    await userEvent.click(screen.getByRole("button", { name: "Load older" }));
    expect(await screen.findByText(/^#13 /)).toBeInTheDocument();
    expect(calls("GET", "/actions?status=executed&limit=50&cursor=c2").length).toBe(1);
    expect(screen.queryByRole("button", { name: "Load older" })).toBeNull();

    await userEvent.selectOptions(screen.getByLabelText("Status"), "failed");
    expect(await screen.findByText(/^#14 /)).toBeInTheDocument();
    expect(screen.getByText("Sensor: nft exploded")).toBeInTheDocument();
    expect(screen.queryByText(/^#11 /)).toBeNull();
    expect(calls("GET", "/actions?status=failed&limit=50").length).toBe(1);

    await userEvent.selectOptions(screen.getByLabelText("Status"), "rejected");
    expect(await screen.findByText(/^#15 /)).toBeInTheDocument();
    expect(screen.getByText("“nope”")).toBeInTheDocument();
  });

  it("an object error is shown as JSON, never [object Object]", async () => {
    data.done.executed = { items: [
      action({ id: 20, status: "failed", result: { error: { code: 5 } } }),
      action({ id: 21, status: "failed", result: { detail: "x" } }),
    ] };
    const { container } = show();
    await userEvent.click(await screen.findByRole("button", { name: "Done" }));
    expect(await screen.findByText('Sensor: {"code":5}')).toBeInTheDocument();
    expect(screen.getByText('Sensor: {"detail":"x"}')).toBeInTheDocument();
    expect(container.textContent).not.toContain("[object Object]");
  });
});

describe("notice", () => {
  it("is always present, empty at first", () => {
    show();
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });

  it("is cleared when a new action starts", async () => {
    data.pending = { items: [action(), action({ id: 4 })] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Reject action #3" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Action #3 rejected."));
    let release!: () => void;
    postGate = new Promise<void>((r) => { release = r; });
    await userEvent.click(screen.getByRole("button", { name: "Reject action #4" }));
    await waitFor(() => expect(screen.getByRole("status")).toBeEmptyDOMElement());
    release();
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Action #4 rejected."));
  });
});

describe("block form", () => {
  it("prefills ip, sensor and reason from the URL and skips /alerts", async () => {
    show("/response?ip=1.2.3.4&sensor=4&from=topology&count=12&hours=24");
    await screen.findByText("No active blocks.");
    expect(form().getByLabelText("IP address")).toHaveValue("1.2.3.4");
    expect(form().getByLabelText("Sensor #")).toHaveValue("4");
    expect(form().getByLabelText("Reason")).toHaveValue("topology: 12 alerts in the last 24 h");
    expect(calls("GET", "/alerts").length).toBe(0);
  });

  it("navigating to another prefill link refills all three fields", async () => {
    show("/response?ip=A&sensor=1&from=topology&count=1&hours=24", "/response?ip=B&sensor=2&from=topology&count=2&hours=24");
    expect(form().getByLabelText("IP address")).toHaveValue("A");
    await userEvent.type(form().getByLabelText("Reason"), "edited");
    await userEvent.click(screen.getByText("go-there"));
    await waitFor(() => expect(form().getByLabelText("IP address")).toHaveValue("B"));
    expect(form().getByLabelText("Sensor #")).toHaveValue("2");
    expect(form().getByLabelText("Reason")).toHaveValue("topology: 2 alerts in the last 24 h");
  });

  describe("sensor from the newest alert", () => {
    it("fills the sensor and shows a hint that goes away on edit", async () => {
      data.alerts = [{ id: 1, sensor_id: 6 }];
      show();
      await waitFor(() => expect(form().getByLabelText("Sensor #")).toHaveValue("6"));
      expect(screen.getByText(/Sensor #6 sent the newest alert/)).toBeInTheDocument();
      expect(form().getByLabelText("Sensor #")).toHaveAttribute("aria-describedby", "sensor-guess");
      await userEvent.type(form().getByLabelText("Sensor #"), "7");
      expect(screen.queryByText(/sent the newest alert/)).toBeNull();
      expect(form().getByLabelText("Sensor #")).not.toHaveAttribute("aria-describedby");
    });

    it("does not overwrite a sensor typed before the fetch resolves", async () => {
      data.alerts = [{ id: 1, sensor_id: 6 }];
      let release!: () => void;
      alertGate = new Promise<void>((r) => { release = r; });
      show();
      await userEvent.type(form().getByLabelText("Sensor #"), "3");
      release();
      await waitFor(() => expect(calls("GET", "/alerts").length).toBe(1));
      await new Promise((r) => setTimeout(r, 20));
      expect(form().getByLabelText("Sensor #")).toHaveValue("3");
      expect(screen.queryByText(/sent the newest alert/)).toBeNull();
    });
  });

  describe("validation happens before the confirm dialog", () => {
    const fill = async (ip: string, sensor: string, reason: string) => {
      await userEvent.type(form().getByLabelText("IP address"), ip);
      await userEvent.type(form().getByLabelText("Sensor #"), sensor);
      await userEvent.type(form().getByLabelText("Reason"), reason);
      await userEvent.click(form().getByRole("button", { name: "Request block" }));
    };
    it.each([
      ["blank ip", "  ", "1", "r", "Enter the IP address to block."],
      ["hex sensor", "1.2.3.4", "0x10", "r", "Sensor must be a sensor number, e.g. 1."],
      ["zero sensor", "1.2.3.4", "0", "r", "Sensor must be a sensor number, e.g. 1."],
      ["text sensor", "1.2.3.4", "abc", "r", "Sensor must be a sensor number, e.g. 1."],
      ["blank reason", "1.2.3.4", "1", "   ", "Enter a reason: it is kept in the audit log."],
    ])("%s", async (_n, ip, sensor, reason, msg) => {
      show();
      await screen.findByText("No active blocks.");
      await fill(ip, sensor, reason);
      expect(await screen.findByText(msg)).toBeInTheDocument();
      expect(window.confirm).not.toHaveBeenCalled();
      expect(posts().length).toBe(0);
    });
  });

  it.each([["15 min", 900], ["1 h", 3600], ["24 h", 86400]])("submits with duration %s", async (text, secs) => {
    show("/response?sensor=2");
    await userEvent.type(form().getByLabelText("IP address"), "  1.2.3.4 ");
    await userEvent.type(form().getByLabelText("Reason"), "  scanning  ");
    await userEvent.selectOptions(form().getByLabelText("For"), text);
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    await waitFor(() => expect(posts().length).toBe(1));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("Reason: scanning"));
    expect(posts()[0][1].json).toEqual({
      kind: "block_ip", ip: "1.2.3.4", sensor_id: 2, reason: "scanning", ttl_seconds: secs,
    });
  });

  it("cancelled confirm posts nothing", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    show("/response?sensor=2&ip=1.2.3.4&from=topology&count=5&hours=24");
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    expect(window.confirm).toHaveBeenCalled();
    expect(posts().length).toBe(0);
  });

  it("on success clears ip and reason, clears the query string, keeps the notice", async () => {
    show("/response?ip=1.2.3.4&sensor=2&from=topology&count=5&hours=24");
    expect(screen.getByTestId("loc").textContent).toBe("/response?ip=1.2.3.4&sensor=2&from=topology&count=5&hours=24");
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/response"));
    expect(screen.getByRole("status")).toHaveTextContent(/Block requested \(action #9/);
    expect(form().getByLabelText("IP address")).toHaveValue("");
    expect(form().getByLabelText("Reason")).toHaveValue("");
    await expectAllReloaded(2);
  });

  it("shows an API error and keeps the input", async () => {
    postError = new Error("blocking refused");
    show("/response?sensor=2");
    await userEvent.type(form().getByLabelText("IP address"), "1.2.3.4");
    await userEvent.type(form().getByLabelText("Reason"), "r");
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    expect(await screen.findByText("blocking refused")).toBeInTheDocument();
    expect(form().getByLabelText("IP address")).toHaveValue("1.2.3.4");
  });
});

describe("sensor_guess link", () => {
  it("shows the hint for a guessed sensor and skips /alerts", async () => {
    show("/response?ip=1.2.3.4&sensor=3&sensor_guess=1");
    await screen.findByText("No active blocks.");
    expect(screen.getByText(/Sensor #3 sent the newest alert/)).toBeInTheDocument();
    expect(form().getByLabelText("Sensor #")).toHaveValue("3");
    expect(form().getByLabelText("Sensor #").getAttribute("aria-describedby")).toContain("sensor-guess");
    expect(calls("GET", "/alerts").length).toBe(0);
  });
  it("shows no hint without sensor_guess", async () => {
    show("/response?ip=1.2.3.4&sensor=3");
    await screen.findByText("No active blocks.");
    expect(screen.queryByText(/sent the newest alert/)).toBeNull();
    expect(form().getByLabelText("Sensor #")).not.toHaveAttribute("aria-describedby");
  });
  it("sensor_guess without a sensor shows no hint from the link, and the alert lookup still runs", async () => {
    show("/response?ip=1.2.3.4&sensor_guess=1");
    await screen.findByText("No active blocks.");
    await waitFor(() => expect(calls("GET", "/alerts").length).toBe(1));
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText(/sent the newest alert/)).toBeNull();
    expect(form().getByLabelText("Sensor #")).toHaveValue("");
  });
});

describe("opened with ?ip=", () => {
  it("focuses the IP input on mount", async () => {
    show("/response?ip=1.2.3.4");
    await waitFor(() => expect(document.activeElement).toBe(document.getElementById("block-ip")));
  });
  it("does not steal focus without ?ip=", async () => {
    show("/response");
    await screen.findByText("No active blocks.");
    expect(document.activeElement).not.toBe(document.getElementById("block-ip"));
  });
});

describe("Block an IP link", () => {
  it("focuses the IP input", async () => {
    show();
    await userEvent.click(screen.getByRole("link", { name: "Block an IP…" }));
    expect(document.activeElement).toBe(document.getElementById("block-ip"));
  });
});

describe("untrusted strings", () => {
  it("renders them as text, not HTML", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    data.blocks = [block({ reason: evil, ip: "<b>9.9.9.9</b>" })];
    data.pending = { items: [action({ reason: evil, params: { ip: "<i>8.8.8.8</i>", ttl_seconds: 900 } })] };
    data.done.executed = { items: [action({ id: 30, status: "executed", reason: evil, result: { message: "<u>m</u>" } })] };
    const { container } = show();
    expect(await screen.findAllByText(evil, { exact: false })).not.toHaveLength(0);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b.mono")?.textContent).toBe("<b>9.9.9.9</b>");
    expect(container.querySelector("i")).toBeNull();
    expect(screen.getByText(/<i>8\.8\.8\.8<\/i>/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByText("Sensor: <u>m</u>")).toBeInTheDocument();
    expect(container.querySelector("u")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });
});

const gate = () => { let release!: () => void; const p = new Promise<void>((r) => { release = r; }); return { p, release }; };
const openDone = async () => { await userEvent.click(await screen.findByRole("button", { name: "Done" })); };

describe("form is remounted only by a new prefill", () => {
  it("keeps sensor and duration after success, clears ip/reason, no new /alerts call", async () => {
    show("/response?ip=A&sensor=2&from=topology&count=5&hours=24", "/response?ip=B&sensor=3&from=topology&count=2&hours=24");
    await userEvent.selectOptions(form().getByLabelText("For"), "1 h");
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/response"));
    await expectAllReloaded(2);
    expect(form().getByLabelText("Sensor #")).toHaveValue("2");
    expect(form().getByLabelText("For")).toHaveValue("3600");
    expect(form().getByLabelText("IP address")).toHaveValue("");
    expect(form().getByLabelText("Reason")).toHaveValue("");
    expect(calls("GET", "/alerts").length).toBe(0);

    await userEvent.click(screen.getByText("go-there"));
    await waitFor(() => expect(form().getByLabelText("IP address")).toHaveValue("B"));
    expect(form().getByLabelText("Sensor #")).toHaveValue("3");
    expect(form().getByLabelText("Reason")).toHaveValue("topology: 2 alerts in the last 24 h");
  });
});

describe("Load older", () => {
  beforeEach(() => {
    data.done.executed = { items: [action({ id: 11, status: "executed" })], next_cursor: "c1" };
    data.older.c1 = { items: [action({ id: 12, status: "executed" })], next_cursor: "c2" };
  });

  it("the 10 s refresh skips page 1 while older rows are open; Back to the newest resets", async () => {
    show();
    await openDone();
    await screen.findByText(/^#11 /);
    await userEvent.click(screen.getByRole("button", { name: "Load older" }));
    await screen.findByText(/^#12 /);
    act(() => h.reload!());
    await waitFor(() => {
      for (const l of ["/blocks", "/actions?status=pending", "/actions?status=confirmed"]) {
        expect(calls("GET", l).length).toBe(2);
      }
    });
    expect(calls("GET", "/actions?status=executed&limit=50").filter(([p]) => !String(p).includes("cursor")).length).toBe(1);

    await userEvent.click(screen.getByRole("button", { name: "Back to the newest" }));
    await waitFor(() => expect(calls("GET", "/actions?status=executed&limit=50").filter(([p]) => !String(p).includes("cursor")).length).toBe(2));
    expect(screen.queryByText(/^#12 /)).toBeNull();
    expect(screen.getByText(/^#11 /)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Back to the newest" })).toBeNull();
  });

  it("without older rows the refresh reloads page 1 too", async () => {
    show();
    await openDone();
    await screen.findByText(/^#11 /);
    act(() => h.reload!());
    await expectAllReloaded(2);
  });

  it("a late response is dropped after the Status select changes", async () => {
    data.done.failed = { items: [action({ id: 14, status: "failed" })] };
    const g = gate();
    olderGate = g.p;
    show();
    await openDone();
    await screen.findByText(/^#11 /);
    await userEvent.click(screen.getByRole("button", { name: "Load older" }));
    await userEvent.selectOptions(screen.getByLabelText("Status"), "failed");
    await screen.findByText(/^#14 /);
    g.release();
    await new Promise((r) => setTimeout(r, 30));
    expect(screen.queryByText(/^#12 /)).toBeNull();
    expect(screen.getByText(/^#14 /)).toBeInTheDocument();
    // and back on executed there are no leaked older rows
    await userEvent.selectOptions(screen.getByLabelText("Status"), "executed");
    await screen.findByText(/^#11 /);
    expect(screen.queryByText(/^#12 /)).toBeNull();
  });

  it("shows Loading… while busy", async () => {
    const g = gate();
    olderGate = g.p;
    show();
    await openDone();
    await userEvent.click(await screen.findByRole("button", { name: "Load older" }));
    const b = await screen.findByRole("button", { name: "Loading…" });
    expect(b).toBeDisabled();
    g.release();
    expect(await screen.findByText(/^#12 /)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Loading…" })).toBeNull();
  });

  it("a failure is shown in the Done tab and leaves other buttons enabled", async () => {
    olderFail = new Error("older boom");
    data.blocks = [block()];
    data.pending = { items: [action()] };
    show();
    await openDone();
    await userEvent.click(await screen.findByRole("button", { name: "Load older" }));
    const err = await screen.findByText("older boom");
    expect(err.closest(".card")).toHaveTextContent("Action queue");
    expect(screen.getByRole("button", { name: "Unblock 10.10.1.10" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Load older" })).toBeEnabled();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: /^Pending/ }));
    expect(screen.getByRole("button", { name: "Confirm action #3" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Reject action #3" })).toBeEnabled();
  });
});

describe("notice and block-form submit", () => {
  it("a confirmed, valid submit clears an old notice before the request", async () => {
    data.pending = { items: [action()] };
    show("/response?ip=1.2.3.4&sensor=2&from=topology&count=5&hours=24");
    await userEvent.click(await screen.findByRole("button", { name: "Reject action #3" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Action #3 rejected."));
    const g = gate();
    postGate = g.p;
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    await waitFor(() => expect(posts().length).toBe(2));
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
    g.release();
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/Block requested/));
  });

  it("the status element stays in the DOM when empty", () => {
    show();
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("a cancelled confirm leaves the old notice alone", async () => {
    data.pending = { items: [action()] };
    show("/response?ip=1.2.3.4&sensor=2&from=topology&count=5&hours=24");
    await userEvent.click(await screen.findByRole("button", { name: "Reject action #3" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("rejected"));
    vi.spyOn(window, "confirm").mockReturnValue(false);
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    expect(screen.getByRole("status")).toHaveTextContent("Action #3 rejected.");
  });
});

describe("per-field validation", () => {
  const submitForm = () => userEvent.click(form().getByRole("button", { name: "Request block" }));

  it("blank IP: aria-invalid, describedby, focus and message", async () => {
    show("/response?sensor=2&from=topology&count=5&hours=24");
    const ip = form().getByLabelText("IP address");
    expect(ip).not.toHaveAttribute("aria-invalid");
    await submitForm();
    expect(ip).toHaveAttribute("aria-invalid", "true");
    expect(ip.getAttribute("aria-describedby")).toContain("block-error");
    expect(document.activeElement).toBe(ip);
    expect(document.getElementById("block-error")).toHaveTextContent("Enter the IP address to block.");
    expect(form().getByLabelText("Sensor #")).not.toHaveAttribute("aria-invalid");
    await userEvent.type(ip, "1.2.3.4");
    await submitForm();
    await waitFor(() => expect(posts().length).toBe(1));
    expect(ip).not.toHaveAttribute("aria-invalid");
    expect(document.getElementById("block-error")).toBeNull();
  });

  it("bad sensor keeps sensor-guess in aria-describedby", async () => {
    data.alerts = [{ id: 1, sensor_id: -1 }];
    show("/response?ip=1.2.3.4&from=topology&count=5&hours=24");
    await waitFor(() => expect(form().getByLabelText("Sensor #")).toHaveValue("-1"));
    await submitForm();
    const s = form().getByLabelText("Sensor #");
    expect(s).toHaveAttribute("aria-invalid", "true");
    expect(s.getAttribute("aria-describedby")).toBe("sensor-guess block-error");
    expect(document.activeElement).toBe(s);
    expect(document.getElementById("block-error")).toHaveTextContent("Sensor must be a sensor number, e.g. 1.");
    await userEvent.type(s, "2");
    expect(screen.queryByText(/sent the newest alert/)).toBeNull();
    expect(s.getAttribute("aria-describedby")).toBe("block-error"); // the error stays until the next submit
    await submitForm();
    await waitFor(() => expect(posts().length).toBe(1));
    expect(s).not.toHaveAttribute("aria-invalid");
  });

  it("blank reason is flagged on the reason input", async () => {
    show("/response?ip=1.2.3.4&sensor=2");
    await submitForm();
    const r = form().getByLabelText("Reason");
    expect(r).toHaveAttribute("aria-invalid", "true");
    expect(document.activeElement).toBe(r);
    expect(document.getElementById("block-error")).toHaveTextContent("Enter a reason: it is kept in the audit log.");
  });
});

describe("unblock hides at expiry by its own timer", () => {
  it("shows Unblock, then removes it 3 s later without a page reload", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    data.blocks = [block({ blocked_at: iso(-58_000), expires_at: iso(2000) })];
    show();
    expect(await screen.findByRole("button", { name: "Unblock 10.10.1.10" })).toBeInTheDocument();
    await act(async () => {}); // flush passive effects so the useNow interval exists
    act(() => { vi.advanceTimersByTime(3000); });
    expect(screen.queryByRole("button", { name: "Unblock 10.10.1.10" })).toBeNull();
    expect(calls("GET", "/blocks").length).toBe(1);
    expect(screen.getByText("10.10.1.10")).toBeInTheDocument();
  });
});

describe("sensor guess", () => {
  it("no hint when the alert list is empty", async () => {
    show();
    await waitFor(() => expect(calls("GET", "/alerts").length).toBe(1));
    await new Promise((r) => setTimeout(r, 20));
    expect(form().getByLabelText("Sensor #")).toHaveValue("");
    expect(screen.queryByText(/sent the newest alert/)).toBeNull();
  });
});

describe("policy and allowlist cards", () => {
  const card = (t: string) => within(screen.getByText(t, { selector: "h2" }).closest(".card") as HTMLElement);
  const live = (id: number, name: string, o: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) =>
    sensorState({ sensor_id: id, name, status: report(o), ...extra });

  it("policy: no sensor online", async () => {
    show();
    expect(await screen.findByText(/No sensor is online/)).toBeInTheDocument();
  });

  it("policy: offline, revoked and status-less sensors do not count", async () => {
    sensorsBody = sensorsStatus([
      live(1, "a", {}, { online: false }), live(2, "b", {}, { revoked: true }), sensorState({ sensor_id: 3, status: null }),
    ]);
    show();
    expect(await screen.findByText(/No sensor is online/)).toBeInTheDocument();
  });

  it("policy: one sensor, mode pill and sentences, no sensor heading", async () => {
    sensorsBody = sensorsStatus([live(1, "gw", { policy: policy({ window_seconds: 60, block_ttl_seconds: 900, unblock_grace_seconds: 3600, max_analyst_blocks: 1000 }) })]);
    show();
    const c = card("Response policy");
    expect(await c.findByText("blocking on")).toHaveClass("pill");
    const t = c.getByText(/flows/).textContent!;
    expect(t).toMatch(/^5 flows ≥ .*90.* confidence from one address within 1 min$/);
    expect(c.getByText(/aren't sent/).textContent).toMatch(/alerts below .*60.* confidence aren't sent/);
    expect(c.getByText("15 min")).toBeInTheDocument();
    expect(c.getByText("no auto-block of that address for 1 h")).toBeInTheDocument();
    expect(c.getByText("at most 1,000 at once")).toBeInTheDocument();
    expect(c.queryByRole("heading", { name: "gw" })).toBeNull();
  });

  it("policy: thresholds are shown exactly, not rounded", async () => {
    sensorsBody = sensorsStatus([live(1, "gw", { policy: policy({ confidence_threshold: 0.925, min_alert_confidence: 0.6 }) })]);
    show();
    const c = card("Response policy");
    expect(await c.findByText(/5 flows ≥ 92\.5% confidence from one address/)).toBeInTheDocument();
    expect(c.getByText("alerts below 60% confidence aren't sent")).toBeInTheDocument();
  });

  it("policy: unblock grace 0 says the address can be auto-blocked again at once", async () => {
    sensorsBody = sensorsStatus([live(1, "gw", { policy: policy({ unblock_grace_seconds: 0 }) })]);
    show();
    const c = card("Response policy");
    expect(await c.findByText("the address can be auto-blocked again at once")).toBeInTheDocument();
    expect(c.queryByText(/no auto-block of that address/)).toBeNull();
  });

  it("policy: dry-run and not-blocking pills; a window that is not a whole minute uses seconds", async () => {
    sensorsBody = sensorsStatus([
      live(1, "gw", { dry_run: true, policy: policy({ window_seconds: 45 }) }),
      live(2, "lab", { blocking_enabled: false }),
    ]);
    show();
    const c = card("Response policy");
    expect(await c.findByText("dry-run: blocks are only logged")).toHaveClass("pill");
    expect(c.getByText("not blocking")).toHaveClass("pill");
    expect(c.getByText(/within 45 s$/)).toBeInTheDocument();
  });

  it("policy: names each sensor only when there are several", async () => {
    sensorsBody = sensorsStatus([live(1, "gw"), live(2, "lab", { policy: policy({ block_ttl_seconds: 3600 }) })]);
    show();
    const c = card("Response policy");
    expect(await c.findByRole("heading", { name: "gw" })).toBeInTheDocument();
    expect(c.getByRole("heading", { name: "lab" })).toBeInTheDocument();
    expect(c.getByText("1 h")).toBeInTheDocument();
  });

  it("allowlist: SOC list and each reporting sensor's list", async () => {
    sensorsBody = sensorsStatus([
      live(1, "gw", { allowlist: ["10.0.0.254", "192.168.1.1"] }),
      live(2, "off", { allowlist: ["9.9.9.9"] }, { online: false }),
    ], ["10.9.9.9"]);
    show();
    const c = card("Never blocked · allowlist");
    expect(await c.findByText("10.9.9.9")).toBeInTheDocument();
    expect(c.getByText("10.0.0.254")).toBeInTheDocument();
    expect(c.getByText("192.168.1.1")).toBeInTheDocument();
    expect(c.getByRole("heading", { name: /^Sensor gw/ })).toBeInTheDocument();
    expect(c.queryByText("9.9.9.9")).toBeNull();
    expect(c.queryByText(/No sensor online/)).toBeNull();
  });

  it("allowlist: says how many entries the sensor did not send", async () => {
    sensorsBody = sensorsStatus([live(1, "gw", { allowlist: ["1.1.1.1", "2.2.2.2"], allowlist_total: 7 })], []);
    show();
    const c = card("Never blocked · allowlist");
    expect(await c.findByText("and 5 more not shown (the sensor reports the first 2).")).toBeInTheDocument();
  });

  it.each([[undefined], [2], [1]])("allowlist: no 'more not shown' line when allowlist_total is %s", async (total) => {
    sensorsBody = sensorsStatus([live(1, "gw", { allowlist: ["1.1.1.1", "2.2.2.2"], allowlist_total: total })], []);
    show();
    const c = card("Never blocked · allowlist");
    expect(await c.findByText("1.1.1.1")).toBeInTheDocument();
    expect(c.queryByText(/more not shown/)).toBeNull();
  });

  it("allowlist: duplicate entries render without React key warnings", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    sensorsBody = sensorsStatus([live(1, "gw", { allowlist: ["1.1.1.1", "1.1.1.1"] })], ["9.9.9.9", "9.9.9.9"]);
    show();
    const c = card("Never blocked · allowlist");
    await waitFor(() => expect(c.getAllByText("1.1.1.1")).toHaveLength(2));
    expect(c.getAllByText("9.9.9.9")).toHaveLength(2);
    expect(err.mock.calls.filter(([m]) => /same key|unique "key"/.test(String(m)))).toEqual([]);
  });

  it("allowlist: empty lists say empty; no sensor says so", async () => {
    sensorsBody = sensorsStatus([], []);
    show();
    const c = card("Never blocked · allowlist");
    expect(await c.findByText("empty")).toBeInTheDocument();
    expect(c.getByText("No sensor online to report its own list.")).toBeInTheDocument();
  });

  it("allowlist: a reporting sensor with an empty list shows empty twice", async () => {
    sensorsBody = sensorsStatus([live(1, "gw", { allowlist: [] })], []);
    show();
    const c = card("Never blocked · allowlist");
    await waitFor(() => expect(c.getAllByText("empty")).toHaveLength(2));
  });

  it("shows a status error in both cards", async () => {
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string, o?: unknown) => { if (p === "/sensors/status") throw new Error("sensors down"); return base(p, o); });
    show();
    await waitFor(() => expect(screen.getAllByText("sensors down")).toHaveLength(2));
  });
});

describe("linkReason", () => {
  const r = (q: string) => linkReason(new URLSearchParams(q));
  it("topology link with counts gives the sentence", () => {
    expect(r("from=topology&count=5&hours=24")).toBe("topology: 5 alerts in the last 24 h");
    expect(r("from=topology&count=0&hours=1")).toBe("topology: 0 alerts in the last 1 h");
    expect(r("from=topology&count=123456789&hours=168")).toBe("topology: 123456789 alerts in the last 168 h");
  });
  it.each([
    [""], ["reason=anything"], ["from=other&count=5&hours=24"], ["count=5&hours=24"], ["from=topology"],
    ["from=topology&count=5"], ["from=topology&hours=24"], ["from=topology&count=5&hours=0"],
    ["from=topology&count=x&hours=24"], ["from=topology&count=5&hours=2x"], ["from=topology&count=-1&hours=24"],
    ["from=topology&count=1.5&hours=24"], ["from=topology&count=1234567890&hours=24"], ["from=topology&count=5&hours=1234567890"],
    ["from=topology&count=5&hours=24&reason=evil"], ["alert=7"],
  ])("%j gives an empty reason (or ignores extras)", (q) => {
    const out = r(q);
    expect(out === "" || out === "topology: 5 alerts in the last 24 h").toBe(true);
    if (q.includes("reason=")) expect(out).not.toContain("evil");
  });
  it("hours 0 is empty", () => { expect(r("from=topology&count=5&hours=0")).toBe(""); });
});

describe("block form prefill from a link", () => {
  const reasonBox = () => form().getByLabelText("Reason");
  const alertFetches = () => calls("GET", "/alerts/");
  it("a topology link fills the reason", async () => {
    show("/response?ip=1.2.3.4&sensor=2&from=topology&count=3&hours=6");
    await screen.findByText("No active blocks.");
    expect(reasonBox()).toHaveValue("topology: 3 alerts in the last 6 h");
    expect(alertFetches().length).toBe(0);
  });
  it("?alert=N fetches the alert and fills the reason when src_ip matches", async () => {
    alertById["42"] = { id: 42, src_ip: "1.2.3.4", dst_ip: "9.9.9.9", predicted_class: "PortScan" };
    show("/response?ip=1.2.3.4&sensor=2&alert=42");
    await waitFor(() => expect(reasonBox()).toHaveValue("alert #42: PortScan"));
    expect(alertFetches().map(([p]) => p)).toEqual(["/alerts/42"]);
    expect(screen.queryByText(/so the reason was left empty/)).toBeNull();
  });
  it("matches on dst_ip too", async () => {
    alertById["42"] = { id: 42, src_ip: "9.9.9.9", dst_ip: "1.2.3.4", predicted_class: "DoS" };
    show("/response?ip=1.2.3.4&sensor=2&alert=42");
    await waitFor(() => expect(reasonBox()).toHaveValue("alert #42: DoS"));
  });
  it("an alert that does not involve the ip leaves the reason empty and says so", async () => {
    alertById["42"] = { id: 42, src_ip: "5.5.5.5", dst_ip: "6.6.6.6", predicted_class: "PortScan" };
    show("/response?ip=1.2.3.4&sensor=2&alert=42");
    expect(await screen.findByText("Alert #42 doesn't involve 1.2.3.4, so the reason was left empty.")).toBeInTheDocument();
    expect(reasonBox()).toHaveValue("");
  });
  it("a failed fetch leaves the reason empty and says so", async () => {
    show("/response?ip=1.2.3.4&sensor=2&alert=404");
    expect(await screen.findByText("Alert #404 couldn't be loaded, so the reason was left empty.")).toBeInTheDocument();
    expect(reasonBox()).toHaveValue("");
  });
  it("does not overwrite a reason typed before the alert arrives", async () => {
    alertById["42"] = { id: 42, src_ip: "1.2.3.4", dst_ip: "9.9.9.9", predicted_class: "PortScan" };
    let release!: () => void;
    alertByIdGate = new Promise<void>((r) => { release = r; });
    show("/response?ip=1.2.3.4&sensor=2&alert=42");
    await userEvent.type(reasonBox(), "my own reason");
    release();
    await waitFor(() => expect(calls("GET", "/alerts/").length).toBe(1));
    await new Promise((r) => setTimeout(r, 30));
    expect(reasonBox()).toHaveValue("my own reason");
  });
  it("the alert note does not show without an alert param", async () => {
    show("/response?ip=1.2.3.4&sensor=2");
    await screen.findByText("No active blocks.");
    expect(screen.queryByText(/so the reason was left empty/)).toBeNull();
  });
  it.each([["abc"], ["12abc"], ["0"], ["-3"], ["007"], [""], ["1.5"], ["12345678901234567890"]])("?alert=%j does not fetch and leaves the reason empty", async (v) => {
    show(`/response?ip=1.2.3.4&sensor=2&alert=${v}`);
    await screen.findByText("No active blocks.");
    expect(reasonBox()).toHaveValue("");
    expect(alertFetches().length).toBe(0);
  });
  it("without ?ip= an alert param does not fetch", async () => {
    show("/response?sensor=2&alert=42");
    await screen.findByText("No active blocks.");
    expect(alertFetches().length).toBe(0);
  });
  it("no alert param leaves the reason empty", async () => {
    show("/response?ip=1.2.3.4&sensor=2");
    await screen.findByText("No active blocks.");
    expect(reasonBox()).toHaveValue("");
  });
  it("?reason= is ignored entirely, also next to other params", async () => {
    const { unmount } = show("/response?ip=1.2.3.4&sensor=2&reason=sneaky+text");
    await screen.findByText("No active blocks.");
    expect(reasonBox()).toHaveValue("");
    unmount();
    show("/response?ip=1.2.3.4&sensor=2&reason=x&from=topology&count=2&hours=3");
    await screen.findByText("No active blocks.");
    expect(reasonBox()).toHaveValue("topology: 2 alerts in the last 3 h");
    expect(screen.queryByDisplayValue("x")).toBeNull();
  });
  it("shows the check-the-address hint only when ?ip= is present", async () => {
    const { unmount } = show("/response?ip=1.2.3.4&sensor=2&alert=1");
    await screen.findByText("No active blocks.");
    expect(screen.getByRole("note")).toHaveTextContent("Filled in from a link. Check the address and the sensor before you request the block.");
    unmount();
    show("/response?sensor=2");
    await screen.findByText("No active blocks.");
    expect(screen.queryByText(/Filled in from a link/)).toBeNull();
  });
});

describe("confirm dialogs flatten untrusted text", () => {
  it("block request: IP and reason are one line", async () => {
    show("/response?sensor=2");
    await userEvent.type(form().getByLabelText("IP address"), "1.2.3.4");
    await userEvent.type(form().getByLabelText("Reason"), "scan\t\tReason: fake\u202Eevil");
    await userEvent.click(form().getByRole("button", { name: "Request block" }));
    const msg = (window.confirm as unknown as { mock: { calls: string[][] } }).mock.calls[0][0];
    expect(msg).toContain("Reason: scan Reason: fake evil");
    expect(msg.split("\n").filter((l) => l.startsWith("Reason:")).length).toBe(1);
    expect(msg).not.toContain("\u202E");
  });
  it("action confirm: reason with line breaks is one line", async () => {
    data.pending = { items: [action({ reason: "line1\nline2\u2066x" })] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Confirm action #3" }));
    const msg = (window.confirm as unknown as { mock: { calls: string[][] } }).mock.calls[0][0];
    expect(msg).toContain("Reason: line1 line2 x");
    expect(msg).not.toContain("\u2066");
  });
});

describe("redacted sensor status (analysts)", () => {
  const redacted = (sensors: unknown[]) => ({ redacted: true, soc_allowlist: null, sensors });
  const analystSensor = (id: number, name: string, o: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) =>
    sensorState({ sensor_id: id, name, status: report({ policy: null, allowlist: null, allowlist_total: 3, ...o }), ...extra });
  const card = (t: string) => within(screen.getByText(t, { selector: "h2" }).closest(".card") as HTMLElement);

  it("policy card: only-admins text, and says a sensor is blocking", async () => {
    sensorsBody = redacted([analystSensor(1, "gw")]);
    show();
    const c = card("Response policy");
    expect(await c.findByText(/Only admins can see the sensors' auto-block thresholds\./)).toBeInTheDocument();
    expect(c.getByText(/At least one online sensor is blocking\./)).toBeInTheDocument();
    expect(c.queryByText(/flows/)).toBeNull();
    expect(c.queryByText(/No sensor is online/)).toBeNull();
  });
  it("policy card: dry-run sentence when every online sensor is in dry-run", async () => {
    sensorsBody = redacted([analystSensor(1, "gw", { dry_run: true })]);
    show();
    expect(await card("Response policy").findByText(/The online sensors are in dry-run: blocks are only logged\./)).toBeInTheDocument();
  });
  it("policy card: no mode sentence when no sensor is online", async () => {
    sensorsBody = redacted([analystSensor(1, "gw", {}, { online: false })]);
    show();
    const c = card("Response policy");
    const t = (await c.findByText(/Only admins can see/)).textContent!;
    expect(t).not.toMatch(/blocking\.|dry-run/);
  });
  it("allowlist card: only-admins text, no lists", async () => {
    sensorsBody = redacted([analystSensor(1, "gw")]);
    show();
    const c = card("Never blocked · allowlist");
    expect(await c.findByText("Only admins can see the allowlists. Allowlisted addresses are still refused, by the SOC and again by the sensor.")).toBeInTheDocument();
    expect(c.queryByText("empty")).toBeNull();
    expect(c.queryByRole("heading", { level: 3 })).toBeNull();
  });
  it("a sensor with a null policy is skipped in the admin view", async () => {
    sensorsBody = { redacted: false, soc_allowlist: [], sensors: [analystSensor(1, "nopol"), sensorState({ sensor_id: 2, name: "withpol", status: report() })] };
    show();
    const c = card("Response policy");
    expect(await c.findByRole("heading", { name: "withpol" })).toBeInTheDocument();
    expect(c.queryByRole("heading", { name: "nopol" })).toBeNull();
    expect(c.getAllByText(/flows/)).toHaveLength(1);
  });
  it("allowlist card with a null sensor allowlist (admin view) says empty rather than crashing", async () => {
    sensorsBody = { redacted: false, soc_allowlist: [], sensors: [analystSensor(1, "gw")] };
    show();
    const c = card("Never blocked · allowlist");
    await waitFor(() => expect(c.getAllByText("empty").length).toBeGreaterThan(0));
  });
});

describe("untrusted reasons in lists are one line, capped at 300", () => {
  const evil = "first\nsecond\u202Ethird";
  const long = "x".repeat(400);
  it("blocks table", async () => {
    data.blocks = [block({ reason: evil }), block({ id: 2, ip: "10.10.1.20", reason: long })];
    show();
    expect(await screen.findByText("first second third")).toBeInTheDocument();
    const cell = screen.getByText(/^x+…$/);
    expect([...cell.textContent!]).toHaveLength(300);
  });
  it("pending action list", async () => {
    data.pending = { items: [action({ reason: evil }), action({ id: 4, reason: long })] };
    show();
    expect(await screen.findByText("“first second third”")).toBeInTheDocument();
    expect(screen.getByText(/^“x+…”$/).textContent!.length).toBe(302);
  });
  it("history list (Done tab)", async () => {
    data.done.executed = { items: [action({ id: 30, status: "executed", reason: evil })] };
    show();
    await userEvent.click(await screen.findByRole("button", { name: "Done" }));
    expect(await screen.findByText("“first second third”")).toBeInTheDocument();
  });
});
