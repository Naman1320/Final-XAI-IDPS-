import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { sensorState, sensorsStatus } from "./sensor-fixtures";
import { ApiError } from "../api/client";
import Admin, { AUDIT_GROUPS, DetailPairs, auditGroup, auditQuery } from "../pages/Admin";

const h = vi.hoisted(() => ({ api: vi.fn() }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: { id: 1, username: "root", role: "admin" }, loading: false, logout: vi.fn() }),
}));

const user = (o: Record<string, unknown> = {}) => ({
  id: 2, username: "alice", role: "analyst", disabled: false, created_at: "2026-01-05T10:00:00Z", ...o,
});
const sensor = (o: Record<string, unknown> = {}) => ({ id: 1, name: "gw", revoked: false, created_at: "2026-01-06T10:00:00Z", ...o });
const entry = (o: Record<string, unknown> = {}) => ({
  id: 1, at: "2026-02-01T10:00:00Z", actor_type: "user", actor_name: "ann", action: "case_created", target: "case:5",
  details: { title: "x" }, ...o,
});

let users: Record<string, unknown>[];
let sensors: Record<string, unknown>[];
let status: unknown;
let models: Record<string, unknown>[];
let integrations: unknown;
let integrationTest: (channel: string) => unknown;
let auditAll: Record<string, unknown>[];
let auditCursor: string | null;
let auditOlder: Record<string, { items: unknown[]; next_cursor?: string | null }>;
let olderGate: Promise<void> | null;
let firstGate: Promise<void> | null;

const calls = (method: string, prefix = "") =>
  h.api.mock.calls.filter(([p, o]) => (o?.method ?? "GET") === method && String(p).startsWith(prefix));

beforeEach(() => {
  users = [user({ id: 1, username: "root", role: "admin" }), user(), user({ id: 3, username: "bob", disabled: true })];
  sensors = [sensor(), sensor({ id: 2, name: "old", revoked: true })];
  status = sensorsStatus([sensorState({ sensor_id: 1, name: "gw" })]);
  models = [];
  integrationTest = (channel) => ({ channel, ok: true, error: null, duration_ms: 42, tested_at: "2026-02-01T10:00:00Z" });
  integrations = { channels: [], abuseipdb: { configured: false, cache_hours: 24 } };
  auditAll = [];
  auditCursor = null;
  auditOlder = {};
  olderGate = null;
  firstGate = null;
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string; json?: Record<string, unknown> }) => {
    const m = opts?.method ?? "GET";
    if (m === "GET" && path === "/admin/users") return users;
    if (m === "GET" && path === "/admin/sensors") return sensors;
    if (m === "GET" && path === "/sensors/status") return status;
    if (m === "GET" && path === "/models") return { models };
    if (m === "GET" && path === "/admin/integrations") return integrations;
    const itest = /^\/admin\/integrations\/(\w+)\/test$/.exec(path);
    if (m === "POST" && itest) return integrationTest(itest[1]);
    if (m === "GET" && path.startsWith("/admin/audit")) {
      const u = new URL(path, "http://x");
      const c = u.searchParams.get("cursor");
      if (c) {
        if (olderGate) await olderGate;
        const o = auditOlder[c];
        return { items: o.items, total: o.items.length, next_cursor: o.next_cursor ?? null };
      }
      if (firstGate) await firstGate;
      const acts = u.searchParams.getAll("action");
      const actor = u.searchParams.get("actor");
      const items = auditAll.filter((e) => (!acts.length || acts.includes(String(e.action))) && (!actor || e.actor_name === actor));
      return { items, total: items.length, next_cursor: auditCursor };
    }
    if (m === "POST" && path === "/admin/users") return user({ id: 9, username: opts!.json!.username, role: opts!.json!.role });
    const role = /^\/admin\/users\/(\d+)\/role$/.exec(path);
    if (m === "PATCH" && role) return user({ id: Number(role[1]), username: users.find((u) => String(u.id) === role[1])!.username, role: opts!.json!.role });
    const act = /^\/admin\/users\/(\d+)\/(disable|enable|reset-password)$/.exec(path);
    if (m === "POST" && act) return user({ id: Number(act[1]), username: users.find((u) => String(u.id) === act[1])!.username });
    if (m === "POST" && path === "/admin/sensors") return sensor({ id: 7, name: opts!.json!.name, token: "tok-SECRET-123" });
    if (m === "POST" && /^\/admin\/sensors\/\d+\/revoke$/.test(path)) return sensor({ revoked: true });
    throw new Error(`unexpected ${m} ${path}`);
  });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.spyOn(window, "prompt").mockImplementation(() => null);
  Object.defineProperty(navigator, "clipboard", { value: { writeText: vi.fn().mockResolvedValue(undefined) }, configurable: true });
});
afterEach(() => vi.restoreAllMocks());

const show = () => render(<Admin />);
const row = (name: string) => screen.getByText(name, { selector: "b" }).closest("tr")!;
const loaded = () => screen.findByText("alice", { selector: "b" });

describe("auditGroup", () => {
  it.each(Object.entries(AUDIT_GROUPS).flatMap(([g, names]) => names.map((n) => [n, g])))("%s -> %s", (a, g) => {
    expect(auditGroup(a)).toBe(g);
  });
  it("the groups hold the real names the API writes", () => {
    expect(AUDIT_GROUPS.actions).toEqual(["action_request", "action_confirmed", "action_rejected", "action_refused", "action_result"]);
    expect(AUDIT_GROUPS.assistant).toEqual(["assistant_message", "assistant_propose_block"]);
    expect(AUDIT_GROUPS.blocks).toEqual(["ingest_blocks"]);
    expect(AUDIT_GROUPS.alerts).toEqual(["ingest_alerts", "alert_status", "reputation_lookup"]);
    expect(AUDIT_GROUPS.cases).toEqual(["case_create", "case_update", "case_delete", "case_note", "case_attach", "case_detach"]);
    expect(AUDIT_GROUPS.users).toEqual(["user_create", "user_role", "user_disable", "user_enable", "user_reset_password", "user_mfa_reset",
      "user_sso_unlink", "mfa_enable", "mfa_disable", "mfa_recovery_code_used", "mfa_recovery_codes_replaced", "sso_link",
      "sensor_create", "sensor_revoke", "sensor_status_first", "sensor_status_changed", "integration_test"]);
  });
  it.each(["action_proposed", "user_login", "assistant_chat", "case_created", "ingest_other", "alert_", "action_", "", "login_failed"])(
    "%j is other (exact names only)", (a) => { expect(auditGroup(a)).toBe("other"); });
});

describe("auditQuery users group", () => {
  it("sends the sensor status actions too", () => {
    const q = new URLSearchParams(auditQuery("users", ""));
    expect(q.getAll("action")).toEqual(expect.arrayContaining(["sensor_status_first", "sensor_status_changed", "sensor_create", "sensor_revoke"]));
  });
  it.each(["sensor_status_first", "sensor_status_changed"])("%s belongs to the users group", (a) => { expect(auditGroup(a)).toBe("users"); });
});

describe("auditQuery", () => {
  it("is just the limit for all", () => { expect(auditQuery("all", "")).toBe("?limit=100"); });
  it("has one action per name of a group", () => {
    expect(auditQuery("blocks", "")).toBe("?action=ingest_blocks&limit=100");
    expect(auditQuery("alerts", "")).toBe("?action=ingest_alerts&action=alert_status&action=reputation_lookup&limit=100");
    const p = new URLSearchParams(auditQuery("users", ""));
    expect(p.getAll("action")).toEqual(AUDIT_GROUPS.users);
  });
  it("adds a trimmed actor, and ignores a blank one", () => {
    expect(auditQuery("all", "  ann  ")).toBe("?actor=ann&limit=100");
    expect(auditQuery("all", "   ")).toBe("?limit=100");
  });
  it("adds the cursor last, when given", () => {
    expect(auditQuery("all", "", "c9")).toBe("?limit=100&cursor=c9");
    expect(auditQuery("cases", "ann", "c9")).toMatch(/^\?actor=ann&action=case_create.*&limit=100&cursor=c9$/);
    expect(auditQuery("all", "", null)).toBe("?limit=100");
  });
});

describe("DetailPairs", () => {
  it("renders each pair as its own item, strings quoted, others as JSON", () => {
    render(<DetailPairs details={{ k: "v", n: 2, o: { a: 1 }, nul: null, x: "x · to: admin" }} />);
    const items = screen.getAllByRole("listitem").map((li) => li.textContent);
    expect(items).toEqual(["k: “v”", "n: 2", 'o: {"a":1}', "nul: null", "x: “x · to: admin”"]);
  });
  it("renders nothing for empty or missing details", () => {
    const { container, rerender } = render(<DetailPairs details={{}} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<DetailPairs details={undefined as never} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("users", () => {
  it("shows rows with since, role select and status pill", async () => {
    show();
    await loaded();
    const r = row("alice");
    expect(within(r).getByText(/^since /)).toBeInTheDocument();
    expect(within(r).getByLabelText("Role of alice")).toHaveValue("analyst");
    expect(within(r).getByText("active")).toHaveClass("pill");
    expect(within(row("bob")).getByText("disabled")).toHaveClass("pill");
    expect(within(row("root")).getByLabelText("Role of root")).toHaveValue("admin");
  });

  it("your own row has a disabled select, 'you', Change password and no Disable", async () => {
    show();
    await loaded();
    const me = row("root");
    expect(within(me).getByLabelText("Role of root")).toBeDisabled();
    expect(within(me).getByText("you")).toBeInTheDocument();
    expect(within(me).getByRole("button", { name: "Change your password" })).toHaveTextContent("Change password");
    expect(within(me).queryByRole("button", { name: /Disable|Enable|Reset password of/ })).toBeNull();
    expect(within(me).getAllByRole("button").length).toBe(1);
    expect(within(row("alice")).getByLabelText("Role of alice")).toBeEnabled();
  });

  it("role change: cancel sends nothing; confirm PATCHes and shows a notice", async () => {
    vi.spyOn(window, "confirm").mockReturnValueOnce(false);
    show();
    await loaded();
    fireEvent.change(screen.getByLabelText("Role of alice"), { target: { value: "admin" } });
    expect(calls("PATCH").length).toBe(0);
    fireEvent.change(screen.getByLabelText("Role of alice"), { target: { value: "admin" } });
    await waitFor(() => expect(calls("PATCH").length).toBe(1));
    expect(calls("PATCH")[0][0]).toBe("/admin/users/2/role");
    expect(calls("PATCH")[0][1].json).toEqual({ role: "admin" });
    expect(await screen.findByText("alice is now an admin.")).toBeInTheDocument();
    await waitFor(() => expect(calls("GET", "/admin/users").length).toBe(2));
  });

  it("making someone an analyst says 'an analyst'; the same role does nothing", async () => {
    users = [user({ id: 1, username: "root", role: "admin" }), user({ role: "admin" })];
    show();
    await loaded();
    fireEvent.change(screen.getByLabelText("Role of alice"), { target: { value: "admin" } });
    expect(calls("PATCH").length).toBe(0);
    expect(window.confirm).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Role of alice"), { target: { value: "analyst" } });
    expect(await screen.findByText("alice is now an analyst.")).toBeInTheDocument();
  });

  it("disable asks to confirm (cancel sends nothing), then posts and notices", async () => {
    vi.spyOn(window, "confirm").mockReturnValueOnce(false);
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Disable alice" }));
    expect(calls("POST").length).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "Disable alice" }));
    await waitFor(() => expect(calls("POST", "/admin/users/2/disable").length).toBe(1));
    expect(await screen.findByText("Disabled alice.")).toBeInTheDocument();
  });

  it("enable does not ask to confirm", async () => {
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Enable bob" }));
    await waitFor(() => expect(calls("POST", "/admin/users/3/enable").length).toBe(1));
    expect(window.confirm).not.toHaveBeenCalled();
    expect(await screen.findByText("Enabled bob.")).toBeInTheDocument();
  });

  describe("reset password", () => {
    const open = async () => {
      show();
      await loaded();
      fireEvent.click(screen.getByRole("button", { name: "Reset password of alice" }));
      return screen.getByRole("form", { name: "Reset password of alice" });
    };
    it("opens an inline form with a focused password input; no prompt", async () => {
      const form = await open();
      const input = within(form).getByLabelText(/New password for alice/);
      expect(input).toHaveAttribute("type", "password");
      expect(document.activeElement).toBe(input);
      expect(window.prompt).not.toHaveBeenCalled();
    });
    it("Set password needs 12 characters", async () => {
      const form = await open();
      const btn = within(form).getByRole("button", { name: "Set password" });
      const input = within(form).getByLabelText(/New password for alice/);
      expect(btn).toBeDisabled();
      fireEvent.change(input, { target: { value: "a".repeat(11) } });
      expect(btn).toBeDisabled();
      fireEvent.change(input, { target: { value: "a".repeat(12) } });
      expect(btn).toBeEnabled();
    });
    it("submitting posts the password, shows the notice and closes", async () => {
      const form = await open();
      fireEvent.change(within(form).getByLabelText(/New password for alice/), { target: { value: "correct horse battery" } });
      fireEvent.submit(form);
      await waitFor(() => expect(calls("POST", "/admin/users/2/reset-password").length).toBe(1));
      expect(calls("POST")[0][1].json).toEqual({ password: "correct horse battery" });
      expect(await screen.findByText(/Password reset for alice; their existing sessions were signed out\./)).toBeInTheDocument();
      expect(screen.queryByRole("form", { name: "Reset password of alice" })).toBeNull();
      expect(window.prompt).not.toHaveBeenCalled();
    });
    it("shows a visible, labelled read-only User field for password managers", async () => {
      const form = await open();
      const u = within(form).getByLabelText("User") as HTMLInputElement;
      expect(u.value).toBe("alice");
      expect(u.readOnly).toBe(true);
      expect(u.hidden).toBe(false);
      expect(u).toBeVisible();
      expect(u.getAttribute("autocomplete")).toBe("username");
      expect(within(form).queryByText(/signs you out everywhere/)).toBeNull();
    });
    it("for yourself it warns that you are signed out everywhere", async () => {
      show();
      await loaded();
      fireEvent.click(screen.getByRole("button", { name: "Change your password" }));
      const form = screen.getByRole("form", { name: "Reset password of root" });
      expect(within(form).getByText(/This signs you out everywhere, this browser included/)).toBeInTheDocument();
      fireEvent.change(within(form).getByLabelText(/New password for root/), { target: { value: "x".repeat(13) } });
      fireEvent.submit(form);
      await waitFor(() => expect(calls("POST", "/admin/users/1/reset-password").length).toBe(1));
    });
    it("switching from one user to another remounts the form and focuses the new field", async () => {
      const form = await open();
      fireEvent.change(within(form).getByLabelText(/New password for alice/), { target: { value: "typed-for-alice" } });
      fireEvent.click(screen.getByRole("button", { name: "Reset password of bob" }));
      const bob = screen.getByRole("form", { name: "Reset password of bob" });
      const input = within(bob).getByLabelText(/New password for bob/);
      expect(input).toHaveValue("");
      expect(document.activeElement).toBe(input);
      expect(screen.queryByRole("form", { name: "Reset password of alice" })).toBeNull();
    });
    describe("focus after closing", () => {
      afterEach(() => vi.useRealTimers());
      it("returns to the row's button after Cancel and after Set password", async () => {
        const form = await open();
        vi.useFakeTimers({ toFake: ["requestAnimationFrame", "cancelAnimationFrame"] });
        fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
        act(() => { vi.advanceTimersByTime(20); });
        expect(document.activeElement).toBe(screen.getByRole("button", { name: "Reset password of alice" }));

        fireEvent.click(screen.getByRole("button", { name: "Reset password of bob" }));
        const bob = screen.getByRole("form", { name: "Reset password of bob" });
        fireEvent.change(within(bob).getByLabelText(/New password for bob/), { target: { value: "a".repeat(12) } });
        fireEvent.submit(bob);
        await vi.waitFor(() => expect(calls("POST", "/admin/users/3/reset-password").length).toBe(1));
        await act(async () => {});
        act(() => { vi.advanceTimersByTime(20); });
        expect(document.activeElement).toBe(screen.getByRole("button", { name: "Reset password of bob" }));
      });
    });
    it("Cancel closes without a request", async () => {
      const form = await open();
      fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
      expect(screen.queryByRole("form", { name: "Reset password of alice" })).toBeNull();
      expect(calls("POST").length).toBe(0);
    });
    it("reopening starts with an empty password", async () => {
      const form = await open();
      fireEvent.change(within(form).getByLabelText(/New password for alice/), { target: { value: "x".repeat(14) } });
      fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
      fireEvent.click(screen.getByRole("button", { name: "Reset password of alice" }));
      expect(screen.getByLabelText(/New password for alice/)).toHaveValue("");
    });
  });

  it("add user posts the trimmed name, password and role, clears, notices and reloads", async () => {
    show();
    await loaded();
    const username = screen.getByLabelText("Username");
    const password = screen.getByLabelText(/^Password \(12\+ characters\)/);
    fireEvent.change(username, { target: { value: "  carol  " } });
    fireEvent.change(password, { target: { value: "a long password!" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "admin" } });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    await waitFor(() => expect(calls("POST", "/admin/users").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ username: "carol", password: "a long password!", role: "admin" });
    expect(await screen.findByText("Created admin carol.")).toBeInTheDocument();
    expect(username).toHaveValue("");
    expect(password).toHaveValue("");
    expect(screen.getByLabelText("Role")).toHaveValue("analyst");
    await waitFor(() => expect(calls("GET", "/admin/users").length).toBe(2));
  });
});

describe("sensors", () => {
  it("lists sensors with date, pill and Revoke only for active ones", async () => {
    show();
    const item = (await screen.findByText("#1 gw")).closest("li")!;
    expect(within(item).getByText(/^created /)).toBeInTheDocument();
    expect(within(item).getByText("online")).toHaveClass("pill");
    expect(within(item).getByRole("button", { name: "Revoke sensor gw" })).toBeInTheDocument();
    const old = screen.getByText("#2 old").closest("li")!;
    expect(within(old).getByText("revoked")).toHaveClass("pill");
    expect(within(old).queryByRole("button")).toBeNull();
  });
  it("pill states: online, offline (seen before), never reported; suffix only with status data", async () => {
    sensors = [sensor(), sensor({ id: 3, name: "lab" }), sensor({ id: 4, name: "new" })];
    status = sensorsStatus([
      sensorState({ sensor_id: 1, name: "gw" }),
      sensorState({ sensor_id: 3, name: "lab", online: false, status: null, last_seen_at: "2026-02-01T10:00:00Z" }),
      sensorState({ sensor_id: 4, name: "new", online: false, status: null, last_seen_at: null }),
    ]);
    show();
    const gw = (await screen.findByText("#1 gw")).closest("li")!;
    await waitFor(() => expect(within(gw).getByText("online")).toHaveClass("pill"));
    expect(gw.textContent).toMatch(/· last seen /);
    const lab = screen.getByText("#3 lab").closest("li")!;
    expect(within(lab).getByText("offline")).toHaveClass("pill");
    expect(lab.textContent).toMatch(/· last seen /);
    const nw = screen.getByText("#4 new").closest("li")!;
    expect(within(nw).getByText("never reported")).toHaveClass("pill");
    expect(nw.textContent).toContain("· never reported");
  });
  it("a revoked sensor says revoked, with no last-seen suffix, even if status lists it online", async () => {
    status = sensorsStatus([sensorState({ sensor_id: 2, name: "old", revoked: true })]);
    show();
    const old = (await screen.findByText("#2 old")).closest("li")!;
    await waitFor(() => expect(within(old).getByText("revoked")).toHaveClass("pill"));
    expect(within(old).queryByText("online")).toBeNull();
    expect(old.textContent).not.toMatch(/last seen|never reported/);
  });
  it("shows checking… until the status loads", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string, o?: unknown) => { if (p === "/sensors/status") await gate; return base(p, o); });
    show();
    const item = (await screen.findByText("#1 gw")).closest("li")!;
    expect(within(item).getByText("checking…")).toHaveClass("pill");
    expect(item.textContent).not.toMatch(/last seen|never reported/);
    release();
    await waitFor(() => expect(within(item).getByText("online")).toBeInTheDocument());
  });
  it("shows status unavailable when the status fetch fails and there is no data", async () => {
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string, o?: unknown) => { if (p === "/sensors/status") throw new Error("nope"); return base(p, o); });
    show();
    const item = (await screen.findByText("#1 gw")).closest("li")!;
    await waitFor(() => expect(within(item).getByText("status unavailable")).toHaveClass("pill"));
    expect(item.textContent).not.toMatch(/last seen|never reported/);
    expect(within(screen.getByText("#2 old").closest("li")!).getByText("revoked")).toBeInTheDocument();
  });
  it("a sensor missing from the status list is never reported (not offline)", async () => {
    status = sensorsStatus([]);
    show();
    const item = (await screen.findByText("#1 gw")).closest("li")!;
    await waitFor(() => expect(within(item).getByText("never reported")).toHaveClass("pill"));
  });
  it("revoke: cancel sends nothing; confirm posts and reloads", async () => {
    vi.spyOn(window, "confirm").mockReturnValueOnce(false);
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Revoke sensor gw" }));
    expect(calls("POST").length).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "Revoke sensor gw" }));
    await waitFor(() => expect(calls("POST", "/admin/sensors/1/revoke").length).toBe(1));
    await waitFor(() => expect(calls("GET", "/admin/sensors").length).toBe(2));
  });
  it("empty state", async () => {
    sensors = [];
    show();
    expect(await screen.findByText("No sensors yet.")).toBeInTheDocument();
  });
  const srStatus = () => document.querySelector<HTMLElement>("p.sr-only[role=status]")!;
  it("Add sensor needs a name, posts it trimmed and shows the token once", async () => {
    show();
    await screen.findByText("#1 gw");
    expect(srStatus()).toBeEmptyDOMElement(); // always present, empty until a sensor is added
    expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
    const btn = screen.getByRole("button", { name: "Add sensor" });
    const input = screen.getByLabelText("New sensor name");
    expect(btn).toBeDisabled();
    fireEvent.change(input, { target: { value: "   " } });
    expect(btn).toBeDisabled();
    fireEvent.change(input, { target: { value: "  edge-1  " } });
    fireEvent.click(btn);
    await waitFor(() => expect(calls("POST", "/admin/sensors").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ name: "edge-1" });
    expect(await screen.findByText("Sensor edge-1 added.", { selector: "b" })).toBeInTheDocument();
    expect(srStatus()).toHaveTextContent("Sensor edge-1 added. Its token is shown below, once.");
    expect(screen.getByText("Sensor edge-1 added.", { selector: "b" }).closest("p")).toHaveTextContent("Copy its token now: it is shown only once.");
    const label = screen.getByText("Token for edge-1:");
    expect(label).toHaveAttribute("id", "sensor-token-label");
    const pre = screen.getByLabelText("Token for edge-1:");
    expect(pre.tagName).toBe("PRE");
    expect(pre).toHaveAttribute("aria-labelledby", "sensor-token-label");
    expect(pre).not.toHaveAttribute("aria-label");
    expect(pre).toHaveTextContent("tok-SECRET-123");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(input).toHaveValue("");
    await waitFor(() => expect(calls("GET", "/admin/sensors").length).toBe(2));
    fireEvent.click(screen.getByRole("button", { name: "I've stored it" }));
    expect(screen.queryByText("tok-SECRET-123")).toBeNull();
  });

  describe("copy token", () => {
    const secure = (v: boolean) => Object.defineProperty(window, "isSecureContext", { value: v, configurable: true });
    afterEach(() => { delete (window as { isSecureContext?: unknown }).isSecureContext; });
    const addSensor = async (name = "edge-1") => {
      show();
      await screen.findByText("#1 gw");
      fireEvent.change(screen.getByLabelText("New sensor name"), { target: { value: name } });
      fireEvent.click(screen.getByRole("button", { name: "Add sensor" }));
      await screen.findByText(`Sensor ${name} added.`, { selector: "b" });
    };
    it("copies the token and the label turns Copied", async () => {
      secure(true);
      await addSensor();
      fireEvent.click(screen.getByRole("button", { name: "Copy token" }));
      await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("tok-SECRET-123"));
      expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
      expect(screen.queryByText(/Select the token and copy it/)).toBeNull();
    });
    it("a rejected clipboard says so and the button stays Copy token", async () => {
      secure(true);
      (navigator.clipboard.writeText as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("denied"));
      await addSensor();
      fireEvent.click(screen.getByRole("button", { name: "Copy token" }));
      expect(await screen.findByText("Couldn't copy. Select the token and copy it.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Copy token" })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Copied" })).toBeNull();
    });
    it("without a secure context there is no Copy button, only the manual hint", async () => {
      secure(false);
      await addSensor();
      expect(screen.queryByRole("button", { name: "Copy token" })).toBeNull();
      expect(screen.getByText("Select the token and copy it.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "I've stored it" })).toBeInTheDocument();
      expect(screen.getByLabelText("Token for edge-1:")).toHaveTextContent("tok-SECRET-123");
    });
    it("without a clipboard API there is no Copy button either", async () => {
      secure(true);
      Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
      await addSensor();
      expect(screen.queryByRole("button", { name: "Copy token" })).toBeNull();
      expect(screen.getByText("Select the token and copy it.")).toBeInTheDocument();
    });
    it("a new sensor's box starts at Copy token again", async () => {
      secure(true);
      await addSensor();
      fireEvent.click(screen.getByRole("button", { name: "Copy token" }));
      await screen.findByRole("button", { name: "Copied" });
      fireEvent.change(screen.getByLabelText("New sensor name"), { target: { value: "edge-2" } });
      fireEvent.click(screen.getByRole("button", { name: "Add sensor" }));
      expect(await screen.findByText("Sensor edge-2 added.", { selector: "b" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Copy token" })).toBeInTheDocument();
      expect(srStatus()).toHaveTextContent("Sensor edge-2 added. Its token is shown below, once.");
    });
  });
});

describe("audit log", () => {
  const rows = () => [
    entry({ id: 1, action: "case_create", actor_name: "ann", target: "case:5" }),
    entry({ id: 2, action: "action_confirmed", actor_name: "ann", target: "action:3", details: { reason: "x" } }),
    entry({ id: 3, action: "ingest_alerts", actor_type: "sensor", actor_name: "gw", target: "alerts-batch", details: { n: 4, ids: [1, 2] } }),
    entry({ id: 4, action: "user_create", actor_name: "root", target: "user:alice", details: {} }),
    entry({ id: 5, action: "assistant_propose_block", actor_name: "ann", target: "ip:1.2.3.4" }),
    entry({ id: 6, action: "ingest_blocks", actor_type: "sensor", actor_name: "gw", target: "blocks-batch" }),
    entry({ id: 7, action: "alert_status", actor_name: "ann", target: "alert:9" }),
    entry({ id: 8, action: "mystery", actor_name: "ann", target: "x" }),
  ];
  const auditPaths = () => calls("GET", "/admin/audit").map(([p]) => String(p));
  const tr = (t: string) => screen.getByText(t).closest("tr")!;

  it("requests the first page with limit=100 and renders who, event, target, details", async () => {
    auditAll = rows();
    show();
    await screen.findByText("case:5");
    expect(auditPaths()).toEqual(["/admin/audit?limit=100"]);
    expect(within(tr("case:5")).getByText("ann")).toBeInTheDocument();
    expect(within(tr("case:5")).getByText("case create")).toBeInTheDocument();
    expect(within(tr("case:5")).getByRole("listitem")).toHaveTextContent("title: “x”");
    expect(within(tr("user:alice")).queryByRole("list")).toBeNull();
    expect(within(tr("alerts-batch")).getByText("sensor:gw")).toBeInTheDocument();
    expect(within(tr("alerts-batch")).getAllByRole("listitem").map((l) => l.textContent)).toEqual(["n: 4", "ids: [1,2]"]);
    expect(within(tr("action:3")).getByText("reason:").closest("li")).toHaveTextContent("reason: “x”");
    expect(within(tr("ip:1.2.3.4")).getByText("assistant propose block")).toBeInTheDocument();
    expect(screen.getByText("8 entries shown.")).toBeInTheDocument();
  });

  it("footer wording: singular, and 'more are older' with a cursor", async () => {
    auditAll = [entry()];
    const { unmount } = show();
    expect(await screen.findByText("1 entry shown.")).toBeInTheDocument();
    unmount();
    auditCursor = "c1";
    show();
    expect(await screen.findByText("1 entry shown; more are older.")).toBeInTheDocument();
  });

  it("has the event options", async () => {
    show();
    await screen.findByText("No matching events.");
    const opts = Array.from((screen.getByLabelText("Event") as HTMLSelectElement).options).map((o) => o.text);
    expect(opts).toEqual(["all", "analyst actions", "blocks", "alerts", "cases", "users and sensors", "assistant, including proposals"]);
  });

  it("choosing an event asks the API for that group and shows what it returns", async () => {
    auditAll = rows();
    show();
    await screen.findByText("case:5");
    fireEvent.change(screen.getByLabelText("Event"), { target: { value: "cases" } });
    await waitFor(() => expect(auditPaths()).toContain(
      "/admin/audit?action=case_create&action=case_update&action=case_delete&action=case_note&action=case_attach&action=case_detach&limit=100"));
    await waitFor(() => expect(screen.queryByText("action:3")).toBeNull());
    expect(screen.getByText("case:5")).toBeInTheDocument();
    expect(screen.getByText("1 entry shown.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Event"), { target: { value: "alerts" } });
    await waitFor(() => expect(auditPaths()).toContain("/admin/audit?action=ingest_alerts&action=alert_status&action=reputation_lookup&limit=100"));
    expect(await screen.findByText("2 entries shown.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Event"), { target: { value: "all" } });
    expect(await screen.findByText("8 entries shown.")).toBeInTheDocument();
  });

  it("an empty result says so", async () => {
    auditAll = [entry({ action: "user_create", target: "user:z" })];
    show();
    await screen.findByText("user:z");
    fireEvent.change(screen.getByLabelText("Event"), { target: { value: "cases" } });
    expect(await screen.findByText("No matching events.")).toBeInTheDocument();
  });

  describe("Who filter", () => {
    it("applies on Filter or Enter, not while typing; Clear resets", async () => {
      auditAll = rows();
      show();
      await screen.findByText("case:5");
      expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
      fireEvent.change(screen.getByLabelText("Who"), { target: { value: "  root " } });
      expect(auditPaths().length).toBe(1);
      fireEvent.click(screen.getByRole("button", { name: "Filter" }));
      await waitFor(() => expect(auditPaths()).toContain("/admin/audit?actor=root&limit=100"));
      expect(await screen.findByText("user:alice")).toBeInTheDocument();
      expect(screen.queryByText("case:5")).toBeNull();
      fireEvent.change(screen.getByLabelText("Who"), { target: { value: "ann" } });
      expect(auditPaths().length).toBe(2);
      fireEvent.submit(screen.getByLabelText("Who").closest("form")!); // Enter
      await waitFor(() => expect(auditPaths()).toContain("/admin/audit?actor=ann&limit=100"));
      fireEvent.click(await screen.findByRole("button", { name: "Clear" }));
      await waitFor(() => expect(auditPaths().at(-1)).toBe("/admin/audit?limit=100"));
      expect(screen.getByLabelText("Who")).toHaveValue("");
      expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
    });
    it("combines with the event group", async () => {
      auditAll = rows();
      show();
      await screen.findByText("case:5");
      fireEvent.change(screen.getByLabelText("Who"), { target: { value: "ann" } });
      fireEvent.click(screen.getByRole("button", { name: "Filter" }));
      fireEvent.change(screen.getByLabelText("Event"), { target: { value: "blocks" } });
      await waitFor(() => expect(auditPaths()).toContain("/admin/audit?actor=ann&action=ingest_blocks&limit=100"));
    });
  });

  describe("Load older entries", () => {
    beforeEach(() => {
      auditAll = [entry({ id: 1, target: "first" })];
      auditCursor = "c1";
      auditOlder.c1 = { items: [entry({ id: 2, target: "second" })], next_cursor: "c2" };
      auditOlder.c2 = { items: [entry({ id: 3, target: "third" })], next_cursor: null };
    });
    it("requests the same filter with the cursor, appends, and disappears at the end", async () => {
      show();
      await screen.findByText("first");
      fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
      expect(await screen.findByText("second")).toBeInTheDocument();
      expect(screen.getByText("first")).toBeInTheDocument();
      expect(auditPaths()).toContain("/admin/audit?limit=100&cursor=c1");
      expect(screen.getByText("2 entries shown; more are older.")).toBeInTheDocument();
      fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
      expect(await screen.findByText("third")).toBeInTheDocument();
      expect(auditPaths()).toContain("/admin/audit?limit=100&cursor=c2");
      expect(screen.queryByRole("button", { name: "Load older entries" })).toBeNull();
      expect(screen.getByText("3 entries shown.")).toBeInTheDocument();
    });
    it("keeps the group and actor in the cursor request", async () => {
      auditAll = [entry({ id: 1, action: "ingest_blocks", actor_name: "ann", target: "first" })];
      show();
      await screen.findByText("first");
      fireEvent.change(screen.getByLabelText("Who"), { target: { value: "ann" } });
      fireEvent.click(screen.getByRole("button", { name: "Filter" }));
      fireEvent.change(screen.getByLabelText("Event"), { target: { value: "blocks" } });
      await waitFor(() => expect(auditPaths()).toContain("/admin/audit?actor=ann&action=ingest_blocks&limit=100"));
      fireEvent.click(await screen.findByRole("button", { name: "Load older entries" }));
      await waitFor(() => expect(auditPaths()).toContain("/admin/audit?actor=ann&action=ingest_blocks&limit=100&cursor=c1"));
    });
    describe("is hidden while the first page reloads", () => {
      const hold = () => { let release!: () => void; firstGate = new Promise<void>((r) => { release = r; }); return release; };
      const older = () => screen.queryByRole("button", { name: "Load older entries" });
      const setup = async () => { show(); await screen.findByText("first"); expect(older()).not.toBeNull(); };

      it("after an event change", async () => {
        await setup();
        const release = hold();
        fireEvent.change(screen.getByLabelText("Event"), { target: { value: "alerts" } });
        await waitFor(() => expect(older()).toBeNull());
        release();
        expect(await screen.findByRole("button", { name: "Load older entries" })).toBeInTheDocument();
      });
      it("after applying the actor filter", async () => {
        await setup();
        const release = hold();
        fireEvent.change(screen.getByLabelText("Who"), { target: { value: "ann" } });
        fireEvent.click(screen.getByRole("button", { name: "Filter" }));
        await waitFor(() => expect(older()).toBeNull());
        release();
        expect(await screen.findByRole("button", { name: "Load older entries" })).toBeInTheDocument();
      });
      it("after a refresh caused by a change", async () => {
        await setup();
        await screen.findByText("#1 gw");
        const release = hold();
        fireEvent.click(screen.getByRole("button", { name: "Revoke sensor gw" }));
        await waitFor(() => expect(older()).toBeNull());
        release();
        expect(await screen.findByRole("button", { name: "Load older entries" })).toBeInTheDocument();
      });
    });
    it("no button without a cursor", async () => {
      auditCursor = null;
      show();
      await screen.findByText("first");
      expect(screen.queryByRole("button", { name: "Load older entries" })).toBeNull();
    });
    it("a late older page for a previous filter is ignored", async () => {
      let release!: () => void;
      olderGate = new Promise<void>((r) => { release = r; });
      show();
      await screen.findByText("first");
      fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
      fireEvent.change(screen.getByLabelText("Event"), { target: { value: "cases" } });
      await waitFor(() => expect(auditPaths().some((p) => p.includes("action=case_create"))).toBe(true));
      await act(async () => {});
      release();
      await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
      expect(screen.queryByText("second")).toBeNull();
    });
  });
});

describe("audit reloads after changes", () => {
  const audits = () => calls("GET", "/admin/audit").length;
  it("after adding a user", async () => {
    show();
    await loaded();
    await waitFor(() => expect(audits()).toBe(1));
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "carol" } });
    fireEvent.change(screen.getByLabelText(/^Password \(12\+ characters\)/), { target: { value: "a long password!" } });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    await waitFor(() => expect(audits()).toBe(2));
  });
  it("after a role change", async () => {
    show();
    await loaded();
    fireEvent.change(screen.getByLabelText("Role of alice"), { target: { value: "admin" } });
    await waitFor(() => expect(audits()).toBe(2));
  });
  it("after disable and enable", async () => {
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Disable alice" }));
    await waitFor(() => expect(audits()).toBe(2));
    fireEvent.click(screen.getByRole("button", { name: "Enable bob" }));
    await waitFor(() => expect(audits()).toBe(3));
  });
  it("after a password reset", async () => {
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Reset password of alice" }));
    const form = screen.getByRole("form", { name: "Reset password of alice" });
    fireEvent.change(within(form).getByLabelText(/New password for alice/), { target: { value: "a".repeat(12) } });
    fireEvent.submit(form);
    await waitFor(() => expect(audits()).toBe(2));
  });
  it("after adding and revoking a sensor", async () => {
    show();
    await screen.findByText("#1 gw");
    fireEvent.change(screen.getByLabelText("New sensor name"), { target: { value: "edge" } });
    fireEvent.click(screen.getByRole("button", { name: "Add sensor" }));
    await waitFor(() => expect(audits()).toBe(2));
    fireEvent.click(screen.getByRole("button", { name: "Revoke sensor gw" }));
    await waitFor(() => expect(audits()).toBe(3));
  });
  it("not after a cancelled confirm", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    show();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Disable alice" }));
    await act(async () => {});
    expect(audits()).toBe(1);
  });
});

describe("untrusted text", () => {
  it("renders usernames, sensor names, targets and details as text", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    users = [user({ id: 1, username: "root", role: "admin" }), user({ username: evil })];
    sensors = [sensor({ name: evil })];
    auditAll = [entry({ actor_name: evil, target: evil, details: { k: evil } }), entry({ id: 2, actor_type: "sensor", actor_name: evil })];
    const { container } = show();
    await screen.findByText(`#1 ${evil}`);
    await act(async () => {});
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(evil, { selector: "b" })).toBeInTheDocument();
    expect(screen.getByLabelText(`Role of ${evil}`)).toBeInTheDocument();
    expect(container.querySelector(".detail-pairs li")?.textContent).toBe(`k: “${evil}”`);
    expect(screen.getByText(`sensor:${evil}`)).toBeInTheDocument();
    expect(container.querySelector("td.mono")?.textContent).toBe(evil);
  });
});

describe("model versions card", () => {
  const mv = (o: Record<string, unknown> = {}) => ({
    sha256: "abcdef0123456789", version: "2026-11-01-rf", name: "rf-v3", first_seen: "2026-11-01T10:00:00Z",
    last_seen: "2026-11-02T10:00:00Z", running_now: 1,
    sensors: [{ sensor_id: 1, name: "gw", first_seen: "2026-11-01T10:00:00Z", last_seen: "2026-11-02T10:00:00Z", running_now: true, online: true }],
    ...o,
  });
  it("says so when no sensor has reported a model", async () => {
    show();
    expect(await screen.findByText("No sensor has reported a model yet.")).toBeInTheDocument();
  });
  it("lists version, sha prefix, running pill and per-sensor state; falls back to the name", async () => {
    models = [
      mv(),
      mv({ sha256: "112233445566778899", version: null, name: "rf-old", running_now: 0,
        sensors: [{ sensor_id: 1, name: "gw", first_seen: "2026-10-01T10:00:00Z", last_seen: "2026-10-02T10:00:00Z", running_now: false, online: true }] }),
    ];
    show();
    expect(await screen.findByText("2026-11-01-rf")).toBeInTheDocument();
    expect(screen.getByText("sha256 abcdef012345")).toBeInTheDocument();
    expect(screen.getAllByText("running")).toHaveLength(1);
    expect(screen.getByText("now")).toBeInTheDocument();
    expect(screen.getByText("rf-old")).toBeInTheDocument();
    expect(screen.getByText(/^until /)).toBeInTheDocument();
  });

  it("reloads after a sensor is added or revoked", async () => {
    show();
    await screen.findByText("#1 gw");
    await waitFor(() => expect(calls("GET", "/models").length).toBe(1));
    fireEvent.change(screen.getByLabelText("New sensor name"), { target: { value: "edge-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Add sensor" }));
    await waitFor(() => expect(calls("GET", "/models").length).toBe(2));
    fireEvent.click(screen.getAllByRole("button", { name: /^Revoke/ })[0]);
    await waitFor(() => expect(calls("GET", "/models").length).toBe(3));
  });
});

describe("Integrations card", () => {
  const chan = (o: Record<string, unknown> = {}) => ({
    channel: "webhook", configured: true, enabled: true, min_severity: "high", include_rules: true, target_hint: "https://hooks.example/…abc",
    last_success_at: null, last_error: null, last_error_at: null, queued: 0, sent: 0, failed: 0, dropped: 0, rate_limited: 0, deduped: 0, ...o,
  });
  const setup = (channels: unknown[], abuseipdb = { configured: false, cache_hours: 24 }) => { integrations = { channels, abuseipdb }; };
  const card = async () => {
    show();
    await loaded();
    const c = (await screen.findByText("Integrations", { selector: ".card h2, .card h3, .card *" })).closest(".card") as HTMLElement;
    return c;
  };
  const rowOf = (c: HTMLElement, name: string) => within(c).getByText(name, { selector: "b" }).closest("tr") as HTMLElement;

  it("pills: not configured, off, on; dash for unconfigured Sends and Delivery; target hint", async () => {
    setup([
      chan({ channel: "webhook", configured: false, enabled: false, target_hint: null }),
      chan({ channel: "slack", enabled: false, target_hint: "slack-hint" }),
      chan({ channel: "email", target_hint: "ops@example.org" }),
    ]);
    const c = await card();
    await within(c).findByText("Slack");
    const w = rowOf(c, "Webhook");
    expect(within(w).getByText("not configured")).toBeInTheDocument();
    expect(within(w).getAllByText("—")).toHaveLength(2);
    expect(within(rowOf(c, "Slack")).getByText("off")).toBeInTheDocument();
    expect(within(rowOf(c, "Slack")).getByText("slack-hint")).toBeInTheDocument();
    expect(within(rowOf(c, "Email")).getByText("on")).toBeInTheDocument();
    expect(within(rowOf(c, "Email")).getByText("ops@example.org")).toBeInTheDocument();
  });

  it("Sends text covers severity and rule inclusion", async () => {
    setup([chan({ channel: "webhook", min_severity: "high", include_rules: true }), chan({ channel: "slack", min_severity: "critical", include_rules: false })]);
    const c = await card();
    await within(c).findByText("Slack");
    expect(rowOf(c, "Webhook")).toHaveTextContent("high and above, model and rule alerts");
    expect(rowOf(c, "Slack")).toHaveTextContent("critical and above, model alerts only");
  });

  it("delivery counts: sent only, then failed, held back, dropped, last sent, last error", async () => {
    setup([
      chan({ channel: "webhook", sent: 1234 }),
      chan({ channel: "slack", sent: 5, failed: 2, rate_limited: 3, deduped: 4, dropped: 1, last_success_at: "2026-02-01T10:00:00Z", last_error: "HTTP 500" }),
    ]);
    const c = await card();
    await within(c).findByText("Slack");
    const w = rowOf(c, "Webhook");
    expect(w).toHaveTextContent("1,234 sent");
    expect(w.textContent).not.toMatch(/failed|held back|dropped|last sent|last error/);
    const s = rowOf(c, "Slack");
    expect(within(s).getByText("2 failed")).toHaveClass("danger-text");
    expect(s).toHaveTextContent("7 held back");
    expect(s).toHaveTextContent("1 dropped");
    expect(s).toHaveTextContent("last sent");
    expect(within(s).getByText("last error: HTTP 500")).toHaveClass("danger-text");
  });

  it("Test is disabled unless the channel is enabled", async () => {
    setup([chan({ channel: "webhook", configured: false, enabled: false }), chan({ channel: "slack", enabled: false }), chan({ channel: "email" })]);
    const c = await card();
    await within(c).findByText("Slack");
    expect(within(c).getByRole("button", { name: "Send a test message to Webhook" })).toBeDisabled();
    expect(within(c).getByRole("button", { name: "Send a test message to Slack" })).toBeDisabled();
    expect(within(c).getByRole("button", { name: "Send a test message to Email" })).toBeEnabled();
  });

  it("Test posts, shows 'sent in N ms' in a status element and reloads the status", async () => {
    setup([chan({ channel: "slack" })]);
    const c = await card();
    await within(c).findByText("Slack");
    const before = calls("GET", "/admin/integrations").length;
    fireEvent.click(within(c).getByRole("button", { name: "Send a test message to Slack" }));
    await waitFor(() => expect(calls("POST", "/admin/integrations/slack/test")).toHaveLength(1));
    const st = await within(rowOf(c, "Slack")).findByText("sent in 42 ms");
    expect(st.closest("[role=status]")).not.toBeNull();
    await waitFor(() => expect(calls("GET", "/admin/integrations").length).toBe(before + 1));
  });

  it("a failed test shows failed: <error> in danger text", async () => {
    setup([chan({ channel: "email" })]);
    integrationTest = (channel) => ({ channel, ok: false, error: "SMTP refused", duration_ms: 5, tested_at: "2026-02-01T10:00:00Z" });
    const c = await card();
    await within(c).findByText("Email");
    fireEvent.click(within(c).getByRole("button", { name: "Send a test message to Email" }));
    const msg = await within(c).findByText("failed: SMTP refused");
    expect(msg).toHaveClass("danger-text");
    expect(msg.closest("[role=status]")).not.toBeNull();
  });

  it("AbuseIPDB line: on with cache hours, or not configured", async () => {
    setup([], { configured: true, cache_hours: 24 });
    const c = await card();
    await waitFor(() => expect(c.textContent).toContain("AbuseIPDB reputation: on, cached 24 h."));
    cleanup();
    setup([], { configured: false, cache_hours: 24 });
    const c2 = await card();
    await waitFor(() => expect(c2.textContent).toContain("AbuseIPDB reputation: not configured."));
  });
});

describe("Integrations card test results and errors", () => {
  const chan = (o: Record<string, unknown> = {}) => ({
    channel: "webhook", configured: true, enabled: true, min_severity: "high", include_rules: true, target_hint: null,
    last_success_at: null, last_error: null, last_error_at: null, queued: 0, sent: 0, failed: 0, dropped: 0, rate_limited: 0, deduped: 0, ...o,
  });
  const open = async (channels: unknown[]) => {
    integrations = { channels, abuseipdb: { configured: false, cache_hours: 24 } };
    show();
    await loaded();
    const c = (await screen.findByText("Integrations", { selector: ".card *" })).closest(".card") as HTMLElement;
    await within(c).findAllByRole("button", { name: /Send a test message/ });
    return c;
  };
  const btn = (c: HTMLElement, name: string) => within(c).getByRole("button", { name: `Send a test message to ${name}` });

  it.each([
    [429, "Too many", "not sent: too many tests; wait a minute"],
    [409, "conflict", "not sent: not configured or notifications are off"],
    [500, "boom", "not sent: boom"],
  ])("HTTP %i shows %s", async (status, msg, text) => {
    integrationTest = () => { throw new ApiError(status, msg); };
    const c = await open([chan()]);
    fireEvent.click(btn(c, "Webhook"));
    const el = await within(c).findByText(text);
    expect(el).toHaveClass("danger-text");
    expect(el.closest("[role=status]")).not.toBeNull();
  });

  it("a plain Error shows its message", async () => {
    integrationTest = () => { throw new Error("network down"); };
    const c = await open([chan()]);
    fireEvent.click(btn(c, "Webhook"));
    expect(await within(c).findByText("not sent: network down")).toBeInTheDocument();
  });

  it("clears the row result when a new test starts and disables every Test button meanwhile", async () => {
    const c = await open([chan({ channel: "webhook" }), chan({ channel: "slack" })]);
    fireEvent.click(btn(c, "Webhook"));
    await within(c).findByText("sent in 42 ms");
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const base = h.api.getMockImplementation()!;
    h.api.mockImplementation(async (p: string, o?: { method?: string }) => {
      if (o?.method === "POST" && p === "/admin/integrations/webhook/test") { await gate; return { channel: "webhook", ok: true, error: null, duration_ms: 7, tested_at: "x" }; }
      return base(p, o);
    });
    fireEvent.click(btn(c, "Webhook"));
    await waitFor(() => expect(within(c).queryByText("sent in 42 ms")).toBeNull());
    expect(within(c).getByRole("button", { name: "Send a test message to Webhook" })).toHaveTextContent("Sending…");
    expect(btn(c, "Webhook")).toBeDisabled();
    expect(btn(c, "Slack")).toBeDisabled();
    release();
    expect(await within(c).findByText("sent in 7 ms")).toBeInTheDocument();
    await waitFor(() => expect(btn(c, "Slack")).toBeEnabled());
  });

  it("disabled buttons explain why", async () => {
    const c = await open([chan({ channel: "webhook", configured: false, enabled: false }), chan({ channel: "slack", enabled: false }), chan({ channel: "email" })]);
    expect(btn(c, "Webhook")).toHaveAttribute("title", "Not configured in the SOC's environment");
    expect(btn(c, "Slack").getAttribute("title")).toMatch(/switched off/);
    expect(btn(c, "Email")).not.toHaveAttribute("title");
  });

  it("an error older than the last success is 'earlier error' in muted text, with its time", async () => {
    const c = await open([chan({ last_success_at: "2026-02-02T10:00:00Z", last_error_at: "2026-02-01T10:00:00Z", last_error: "HTTP 500" })]);
    const el = within(c).getByText(/earlier error/);
    expect(el).toHaveClass("muted");
    expect(el).not.toHaveClass("danger-text");
    expect(el.textContent).toMatch(/^earlier error \(.+\): HTTP 500$/);
    expect(el.textContent).not.toContain("()");
  });

  it.each([
    ["error after the last success", "2026-02-01T10:00:00Z", "2026-02-02T10:00:00Z"],
    ["no success at all", null, "2026-02-02T10:00:00Z"],
  ])("%s is 'last error' in danger text", async (_n, ok, err) => {
    const c = await open([chan({ last_success_at: ok, last_error_at: err, last_error: "HTTP 500" })]);
    const el = within(c).getByText(/last error/);
    expect(el).toHaveClass("danger-text");
    expect(el).not.toHaveClass("muted");
    expect(el.textContent).toMatch(/^last error \(.+\): HTTP 500$/);
  });

  it("error without a timestamp has no parentheses", async () => {
    const c = await open([chan({ last_error: "oops", last_error_at: null })]);
    expect(within(c).getByText("last error: oops")).toBeInTheDocument();
  });
});
