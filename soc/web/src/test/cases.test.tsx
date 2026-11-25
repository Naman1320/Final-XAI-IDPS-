import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import Cases from "../pages/Cases";

const h = vi.hoisted(() => ({ api: vi.fn() }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));

const iso = (n = 0) => new Date(1_700_000_000_000 + n * 1000).toISOString();
const summary = (o: Record<string, unknown> = {}) => ({
  id: 1, title: "Case one", status: "open", created_by_id: 1, created_at: iso(), updated_at: iso(60), alert_count: 2, ...o,
});
const alertRow = (o: Record<string, unknown> = {}) => ({
  id: 11, sensor_id: 1, received_at: iso(5), src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80, protocol: 6,
  start_ms: 0, end_ms: 0, predicted_class: "PortScan", confidence: 0.9, anomaly_score: null, severity: "high",
  status: "new", case_id: 5, ...o,
});
const note = (o: Record<string, unknown> = {}) => ({
  id: 1, case_id: 5, author_id: 1, author: "ann", text: "first note", created_at: iso(10), ...o,
});
const detail = (o: Record<string, unknown> = {}) => ({
  ...summary({ id: 5, title: "Case five", status: "investigating", alert_count: 1 }),
  alerts: [alertRow()], notes: [note()], ...o,
});

let list: Record<string, unknown>[];
let cursors: Record<string, string | null>;
let details: Record<string, Record<string, unknown>>;
let patchGate: Promise<void> | null;

const calls = (method: string, prefix = "") =>
  h.api.mock.calls.filter(([p, o]) => (o?.method ?? "GET") === method && String(p).startsWith(prefix));
const listCalls = (status = "") => calls("GET", `/cases?status=${status}`).length;
const caseCalls = (id: string) => calls("GET", `/cases/${id}`).filter(([p]) => p === `/cases/${id}`).length;
const settle = () => act(async () => { await new Promise((r) => setTimeout(r, 30)); });

beforeEach(() => {
  list = [
    summary({ id: 1, title: "Case one", status: "open", alert_count: 2 }),
    summary({ id: 2, title: "Case two", status: "open", alert_count: 1 }),
    summary({ id: 5, title: "Case five", status: "investigating", alert_count: 1 }),
    summary({ id: 7, title: "Case seven", status: "closed", alert_count: 0 }),
  ];
  cursors = { open: null, investigating: null, closed: null };
  details = { "5": detail() };
  patchGate = null;
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string; json?: Record<string, unknown> }) => {
    const m = opts?.method ?? "GET";
    const lst = /^\/cases\?status=(\w+)&limit=200$/.exec(path);
    if (m === "GET" && lst) {
      const items = list.filter((c) => c.status === lst[1]);
      return { items, total: items.length, next_cursor: cursors[lst[1]] };
    }
    const one = /^\/cases\/(\d+)$/.exec(path);
    if (m === "GET" && one) {
      if (one[1] === "0") throw new Error("case not found");
      return details[one[1]];
    }
    if (m === "POST" && path === "/cases") {
      const c = detail({ id: 99, title: opts!.json!.title, status: "open", alerts: [], notes: [], alert_count: 0 });
      details["99"] = c;
      list = [...list, summary({ id: 99, title: opts!.json!.title })];
      return c;
    }
    if (m === "PATCH" && one) {
      if (patchGate) await patchGate;
      const u = { ...details[one[1]], ...opts!.json, updated_at: iso(120) };
      details[one[1]] = u;
      list = list.map((c) => (String(c.id) === one[1] ? { ...c, ...opts!.json, updated_at: iso(120) } : c));
      return u;
    }
    const notes = /^\/cases\/(\d+)\/notes$/.exec(path);
    if (m === "POST" && notes) {
      const n = note({ id: 50, author: "bob", text: opts!.json!.text });
      details[notes[1]] = { ...details[notes[1]], notes: [...(details[notes[1]].notes as unknown[]), n], updated_at: iso(200) };
      list = list.map((c) => (String(c.id) === notes[1] ? { ...c, updated_at: iso(200) } : c));
      return n;
    }
    const det = /^\/cases\/(\d+)\/alerts\/(\d+)$/.exec(path);
    if (m === "DELETE" && det) {
      const left = (details[det[1]].alerts as { id: number }[]).filter((a) => String(a.id) !== det[2]);
      details[det[1]] = { ...details[det[1]], alerts: left, updated_at: iso(150), alert_count: left.length };
      list = list.map((c) => (String(c.id) === det[1] ? { ...c, alert_count: left.length, updated_at: iso(150) } : c));
      return null;
    }
    if (m === "DELETE" && one) { list = list.filter((c) => String(c.id) !== one[1]); return null; }
    throw new Error(`unexpected ${m} ${path}`);
  });
  vi.spyOn(window, "confirm").mockReturnValue(true);
});
afterEach(() => { vi.restoreAllMocks(); delete (window as { matchMedia?: unknown }).matchMedia; });

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname}</div>; }
function Back() { const n = useNavigate(); return <button onClick={() => n(-1)}>go-back</button>; }
const show = (url: string | string[] = "/cases", index?: number) => render(
  <MemoryRouter initialEntries={Array.isArray(url) ? url : [url]} initialIndex={index}>
    <Routes><Route path="/cases" element={<Cases />} /><Route path="/cases/:id" element={<Cases />} /></Routes>
    <Loc /><Back />
  </MemoryRouter>);
const tab = (name: string | RegExp) => screen.findByRole("button", { name });
const panel = () => document.getElementById("case-title")!;
const pressed = (name: string) => expect(screen.getByRole("button", { name })).toHaveAttribute("aria-pressed", "true");

describe("case list", () => {
  it("makes one request per status, shows counts and the Open tab", async () => {
    show();
    expect(screen.getByRole("button", { name: "Open · …" })).toBeInTheDocument();
    expect(await tab("Open · 2")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Investigating · 1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Closed · 1" })).toBeInTheDocument();
    const paths = calls("GET").map(([p]) => String(p)).sort();
    expect(paths).toEqual([
      "/cases?status=closed&limit=200", "/cases?status=investigating&limit=200", "/cases?status=open&limit=200",
    ]);
    expect(screen.getByText("Case one")).toBeInTheDocument();
    expect(screen.queryByText("Case five")).toBeNull();
  });

  it("tabs show their own list without refetching", async () => {
    show();
    fireEvent.click(await tab("Investigating · 1"));
    expect(screen.getByText("Case five")).toBeInTheDocument();
    expect(screen.queryByText("Case one")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Closed · 1" }));
    expect(screen.getByText("Case seven")).toBeInTheDocument();
    expect(listCalls()).toBe(3);
  });

  it("empty message for a tab", async () => {
    list = [summary()];
    show();
    fireEvent.click(await tab("Closed · 0"));
    expect(screen.getByText("No closed cases.")).toBeInTheDocument();
  });

  it("items link to the case with status pill and meta, singular alert", async () => {
    show();
    await tab("Open · 2");
    const link = screen.getByRole("link", { name: /Case two/ });
    expect(link).toHaveAttribute("href", "/cases/2");
    expect(within(link).getByText("open")).toHaveClass("pill");
    expect(within(link).getByText(/^#2 · 1 alert · updated /)).toBeInTheDocument();
    expect(screen.getByText(/^#1 · 2 alerts · updated /)).toBeInTheDocument();
  });

  it("a list's next_cursor gives n+ for that list only, and the note for the current tab only", async () => {
    cursors.investigating = "more";
    show();
    expect(await tab("Investigating · 1+")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open · 2" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Closed · 1" })).toBeInTheDocument();
    expect(screen.queryByText(/Showing the newest/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Investigating · 1+" }));
    expect(screen.getByText("Showing the newest 200 investigating cases.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Closed · 1" }));
    expect(screen.queryByText(/Showing the newest/)).toBeNull();
  });
});

describe("selection", () => {
  it("/cases shows the placeholder", async () => {
    show();
    await tab("Open · 2");
    expect(screen.getByText(/Choose a case/)).toBeInTheDocument();
    expect(panel()).toBeNull();
    expect(calls("GET", "/cases/").length).toBe(0);
  });

  it("/cases/5 renders its panel, marks it current and switches to its status tab", async () => {
    show("/cases/5");
    expect(await screen.findByRole("heading", { level: 2, name: "Case five" })).toBeInTheDocument();
    await waitFor(() => pressed("Investigating · 1"));
    expect(screen.getByRole("link", { name: /Case five/ })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByText(/Choose a case/)).toBeNull();
  });

  it("/cases/abc requests /cases/0, never the raw string", async () => {
    show("/cases/abc");
    expect(await screen.findByText("case not found")).toBeInTheDocument();
    const paths = h.api.mock.calls.map(([p]) => String(p));
    expect(paths).toContain("/cases/0");
    expect(paths.some((p) => p.includes("abc"))).toBe(false);
  });
});

describe("keeping the lists in step with the open case", () => {
  it("does not reload the lists when they agree with the case", async () => {
    show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    await settle();
    expect(listCalls()).toBe(3);
  });

  it.each([
    ["missing from the lists", () => { list = list.filter((c) => c.id !== 5); }],
    ["different status", () => { list = list.map((c) => (c.id === 5 ? { ...c, status: "open" } : c)); }],
    ["different updated_at", () => { list = list.map((c) => (c.id === 5 ? { ...c, updated_at: iso(1) } : c)); }],
    ["different alert_count", () => { list = list.map((c) => (c.id === 5 ? { ...c, alert_count: 4 } : c)); }],
  ])("reloads all three lists when the case is %s", async (_n, tweak) => {
    tweak();
    show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    await waitFor(() => expect(listCalls()).toBe(6));
    for (const st of ["open", "investigating", "closed"]) expect(listCalls(st)).toBe(2);
  });
});

describe("create", () => {
  it("blank title disables the button", async () => {
    show();
    await tab("Open · 2");
    const btn = screen.getByRole("button", { name: "Create case" });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText("New case title"), { target: { value: "   " } });
    expect(btn).toBeDisabled();
  });

  it("posts the trimmed title, clears, reloads and navigates", async () => {
    show();
    await tab("Open · 2");
    const input = screen.getByLabelText("New case title");
    fireEvent.change(input, { target: { value: "  Brand new  " } });
    fireEvent.click(screen.getByRole("button", { name: "Create case" }));
    await waitFor(() => expect(calls("POST", "/cases").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ title: "Brand new", alert_ids: [] });
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/cases/99"));
    expect(input).toHaveValue("");
    await waitFor(() => expect(listCalls()).toBeGreaterThanOrEqual(6));
    expect(await screen.findByRole("heading", { level: 2, name: "Brand new" })).toBeInTheDocument();
  });
});

describe("case panel", () => {
  it("heading, meta line", async () => {
    show("/cases/5");
    const h2 = await screen.findByRole("heading", { level: 2, name: "Case five" });
    expect(h2).toHaveAttribute("id", "case-title");
    expect(screen.getByText(/^Case #5 · opened .+ · updated .+/)).toBeInTheDocument();
  });

  it("status buttons: current one pressed and sends nothing; another PATCHes, lists reload, tab follows", async () => {
    show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    const group = within(screen.getByRole("group", { name: "Case status" }));
    expect(group.getByRole("button", { name: "investigating" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(group.getByRole("button", { name: "investigating" }));
    expect(calls("PATCH").length).toBe(0);
    fireEvent.click(group.getByRole("button", { name: "closed" }));
    await waitFor(() => expect(calls("PATCH").length).toBe(1));
    expect(calls("PATCH")[0][0]).toBe("/cases/5");
    expect(calls("PATCH")[0][1].json).toEqual({ status: "closed" });
    await waitFor(() => expect(listCalls()).toBe(6));
    await waitFor(() => pressed("Closed · 2"));
    expect(group.getByRole("button", { name: "closed" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("link", { name: /Case five/ })).toBeInTheDocument();
  });

  it("the status buttons are disabled while the request runs", async () => {
    let release!: () => void;
    patchGate = new Promise<void>((r) => { release = r; });
    show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    const group = within(screen.getByRole("group", { name: "Case status" }));
    fireEvent.click(group.getByRole("button", { name: "closed" }));
    await waitFor(() => expect(group.getByRole("button", { name: "open" })).toBeDisabled());
    fireEvent.click(group.getByRole("button", { name: "open" }));
    expect(screen.getByRole("button", { name: "Delete case" })).toBeDisabled();
    release();
    await waitFor(() => expect(group.getByRole("button", { name: "open" })).toBeEnabled());
    expect(calls("PATCH").length).toBe(1);
  });

  it("the tab does not jump back when the case reloads with the same status", async () => {
    show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    await waitFor(() => pressed("Investigating · 1"));
    fireEvent.click(screen.getByRole("button", { name: "Open · 2" }));
    pressed("Open · 2");
    fireEvent.change(screen.getByLabelText("Add a note"), { target: { value: "more" } });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    await waitFor(() => expect(caseCalls("5")).toBe(2));
    await waitFor(() => expect(listCalls()).toBe(6));
    await settle();
    pressed("Open · 2");
  });
});

describe("linked alerts", () => {
  it("shows the alert row", async () => {
    show("/cases/5");
    const link = await screen.findByRole("link", { name: "#11 PortScan" });
    expect(link).toHaveAttribute("href", "/alerts/11");
    const row = link.closest("tr")!;
    expect(within(row).getByText("high")).toHaveClass("badge");
    expect(within(row).getByText("10.0.0.1:1234 → 10.0.0.2:80")).toBeInTheDocument();
    expect(within(row).getByText("90.00%")).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Remove alert 11 from case" })).toBeInTheDocument();
  });

  it("empty state", async () => {
    details["5"] = detail({ alerts: [], alert_count: 0 });
    show("/cases/5");
    expect(await screen.findByText(/No alerts yet\./)).toBeInTheDocument();
  });

  it("remove: cancel sends nothing", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    show("/cases/5");
    fireEvent.click(await screen.findByRole("button", { name: "Remove alert 11 from case" }));
    expect(window.confirm).toHaveBeenCalled();
    expect(calls("DELETE").length).toBe(0);
  });

  it("remove: confirm deletes, reloads the case, and the list follows", async () => {
    show("/cases/5");
    await screen.findByRole("button", { name: "Remove alert 11 from case" });
    await settle();
    expect(listCalls()).toBe(3);
    fireEvent.click(screen.getByRole("button", { name: "Remove alert 11 from case" }));
    await waitFor(() => expect(calls("DELETE", "/cases/5/alerts/11").length).toBe(1));
    await waitFor(() => expect(caseCalls("5")).toBe(2));
    await waitFor(() => expect(listCalls()).toBe(6));
    expect(await screen.findByText(/No alerts yet\./)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Investigating · 1" })).toBeInTheDocument();
    expect(screen.getByText(/^#5 · 0 alerts · updated /)).toBeInTheDocument();
  });
});

describe("notes", () => {
  it("lists notes with author, 'unknown' for none", async () => {
    details["5"] = detail({ notes: [note(), note({ id: 2, author: null, text: "orphan" })] });
    show("/cases/5");
    expect(await screen.findByText("ann")).toBeInTheDocument();
    expect(screen.getByText("first note")).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.queryByText("No notes yet.")).toBeNull();
  });

  it("empty state and blank disables Add note", async () => {
    details["5"] = detail({ notes: [] });
    show("/cases/5");
    expect(await screen.findByText("No notes yet.")).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: "Add note" });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Add a note"), { target: { value: "  \n " } });
    expect(btn).toBeDisabled();
  });

  it("adds a trimmed note, appends it, clears the box, reloads the case and the list follows", async () => {
    show("/cases/5");
    await screen.findByText("first note");
    await settle();
    expect(listCalls()).toBe(3);
    const box = screen.getByLabelText("Add a note");
    fireEvent.change(box, { target: { value: "  hello there  " } });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    await waitFor(() => expect(calls("POST", "/cases/5/notes").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ text: "hello there" });
    expect(await screen.findByText("hello there")).toBeInTheDocument();
    expect(screen.getByText("bob")).toBeInTheDocument();
    expect(screen.getByText("first note")).toBeInTheDocument();
    expect(box).toHaveValue("");
    await waitFor(() => expect(caseCalls("5")).toBe(2));
    await waitFor(() => expect(listCalls()).toBe(6));
  });
});

describe("delete case", () => {
  it("cancel does nothing", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    show("/cases/5");
    fireEvent.click(await screen.findByRole("button", { name: "Delete case" }));
    expect(calls("DELETE").length).toBe(0);
    expect(screen.getByTestId("loc").textContent).toBe("/cases/5");
  });

  it("confirm deletes, reloads the lists, goes to /cases and focuses the list", async () => {
    show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Delete case" }));
    await waitFor(() => expect(calls("DELETE", "/cases/5").length).toBe(1));
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/cases"));
    await waitFor(() => expect(listCalls()).toBe(6));
    expect(await screen.findByText(/Choose a case/)).toBeInTheDocument();
    expect(screen.queryByText("Case five")).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("region", { name: "Case list" }));
  });

  it("replaces history: Back does not return to the deleted case", async () => {
    show(["/cases", "/cases/5"], 1);
    await screen.findByRole("heading", { level: 2, name: "Case five" });
    fireEvent.click(screen.getByRole("button", { name: "Delete case" }));
    await waitFor(() => expect(screen.getByTestId("loc").textContent).toBe("/cases"));
    fireEvent.click(screen.getByText("go-back"));
    await settle();
    expect(screen.getByTestId("loc").textContent).toBe("/cases");
    expect(screen.queryByRole("heading", { level: 2, name: "Case five" })).toBeNull();
  });
});

describe("narrow screens", () => {
  const stub = (matches: boolean) => {
    window.matchMedia = vi.fn().mockImplementation((q: string) => ({ matches, media: q, addEventListener() {}, removeEventListener() {} })) as never;
  };
  it("focuses the case title after it loads", async () => {
    stub(true);
    show("/cases/5");
    const h2 = await screen.findByRole("heading", { level: 2, name: "Case five" });
    await waitFor(() => expect(document.activeElement).toBe(h2));
    expect(h2).toHaveAttribute("tabindex", "-1");
    expect(window.matchMedia).toHaveBeenCalledWith("(max-width: 1000px)");
  });
  it("does not when the screen is wide", async () => {
    stub(false);
    show("/cases/5");
    const h2 = await screen.findByRole("heading", { level: 2, name: "Case five" });
    await settle();
    expect(document.activeElement).not.toBe(h2);
  });
});

describe("untrusted text", () => {
  it("renders titles, notes and class names as text", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    list = [summary({ id: 5, title: evil, status: "investigating" })];
    details["5"] = detail({
      title: evil, notes: [note({ text: evil, author: "<b>x</b>" })], alerts: [alertRow({ predicted_class: evil })],
    });
    const { container } = show("/cases/5");
    await screen.findByRole("heading", { level: 2, name: evil });
    await act(async () => {});
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")?.textContent).not.toBeUndefined();
    expect(screen.getByRole("heading", { level: 2, name: evil })).toHaveTextContent(evil);
    expect(screen.getByText(evil, { selector: ".note div" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: `#11 ${evil}` })).toBeInTheDocument();
    expect(screen.getByText("<b>x</b>")).toBeInTheDocument();
  });
});

describe("case alert list source tag", () => {
  it("marks rule alerts only", async () => {
    details["5"] = detail({ alerts: [alertRow({ id: 11, source: "rule" }), alertRow({ id: 12 }), alertRow({ id: 13, source: "ml" })], alert_count: 3 });
    show("/cases/5");
    await screen.findByText(/#11 PortScan/);
    const rows = panel().closest("section, div")!.ownerDocument.querySelectorAll(".source-tag");
    expect(rows).toHaveLength(1);
    expect(rows[0].closest("td")).toHaveTextContent("#11 PortScan");
  });
});
