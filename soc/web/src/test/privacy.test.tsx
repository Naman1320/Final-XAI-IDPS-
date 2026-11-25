import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Privacy, { PublicPrivacy, capitalise, changed, countLabel, days } from "../pages/Privacy";

const h = vi.hoisted(() => ({ api: vi.fn(), role: "admin" }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: { id: 1, username: "u", role: h.role }, loading: false, logout: vi.fn() }),
}));

const notice = (o: Record<string, unknown> = {}) => ({
  controller: { name: "Acme Ltd", contact_email: "dpo@acme.test", grievance_officer: "G. Officer" },
  data_categories: [{ category: "IP addresses", description: "source of traffic" }],
  purposes: ["Detect attacks"],
  rights: [{ right: "access_and_erasure", description: "ask us" }],
  retention: { alerts_days: 180, audit_log_days: 0, access_log_days: 1, bogus_days: 5,
    alerts_kept_if_judged_for_training: true, note: "Retention note." },
  recipients: [],
  how_to_exercise: "Write to the contact above.",
  note: "General note.",
  ...o,
});
const preview = (o: Record<string, unknown> = {}) => ({
  ip: "203.0.113.7", subject_fp: "fp", counts: { "alerts.src_ip": 4, "case_notes.text": 2, "blocks.ip": 0, "memory.cache": 1 },
  total: 7, manual_review: { sensors_name: 2, users_username: 0 }, warnings: ["Backups keep copies."], active_blocks: 0, ...o,
});
let N: Record<string, unknown>;
let erasures: unknown[];
let accessPages: Record<string, unknown>;
let reqs: [string, any][];

beforeEach(() => {
  h.role = "admin";
  N = notice();
  erasures = [];
  accessPages = {};
  reqs = [];
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: any) => {
    reqs.push([path, opts]);
    if (path === "/privacy/notice") return N;
    if (path.startsWith("/admin/privacy/erasures")) return { items: erasures, next_cursor: null };
    if (path === "/admin/privacy/erase/preview") return preview();
    if (path === "/admin/privacy/erase") return { ...preview(), record_id: 9, erased_at: "x", total: 7 };
    if (path.startsWith("/admin/privacy/access-log")) {
      const key = path.includes("cursor=c1") ? "next" : "first";
      return accessPages[key];
    }
    throw new Error(`unexpected ${path}`);
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const calls = (p: string) => reqs.filter(([x]) => x.startsWith(p));

describe("helpers", () => {
  it("days()", () => {
    expect(days(0)).toBe("kept until deleted");
    expect(days(1)).toBe("1 day");
    expect(days(180)).toBe("180 days");
    expect(days(null)).toBe("—");
    expect(days("x")).toBe("x");
  });
  it("countLabel()", () => {
    expect(countLabel("case_notes.text")).toBe("case notes text");
    expect(countLabel("memory.cache")).toBe("in memory: cache");
  });
});

describe("Notice", () => {
  it("renders sections, retention and rights", async () => {
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    expect(screen.getByText("dpo@acme.test")).toBeInTheDocument();
    expect(screen.getByText("IP addresses")).toBeInTheDocument();
    expect(screen.getByText("Detect attacks")).toBeInTheDocument();
    const alerts = screen.getByText("Alerts", { selector: "dt" });
    expect(alerts.nextElementSibling).toHaveTextContent("180 days");
    expect(screen.getByText("Audit log").nextElementSibling).toHaveTextContent("kept until deleted");
    expect(screen.getByText("Access log", { selector: "dt" }).nextElementSibling).toHaveTextContent("1 day");
    expect(screen.queryByText(/bogus/i)).toBeNull();
    expect(screen.getByText(/judged are kept longer/)).toBeInTheDocument();
    expect(screen.getByText("Retention note.")).toBeInTheDocument();
    expect(screen.getByText(/No one/)).toBeInTheDocument();
    expect(screen.getByText("Write to the contact above.")).toBeInTheDocument();
    // label() turns underscores into spaces (see report: it does not capitalise)
    expect(screen.getByText("Access and erasure")).toBeInTheDocument();
  });

  it("lists recipients when present", async () => {
    N = notice({ recipients: [{ name: "AbuseIPDB", description: "reputation lookups" }] });
    render(<Privacy />);
    await screen.findByText("AbuseIPDB");
    expect(screen.queryByText(/No one/)).toBeNull();
  });

  it("unset controller shows a neutral sentence without setting names", async () => {
    N = notice({ controller: { name: null, contact_email: null, grievance_officer: null } });
    render(<Privacy />);
    const p = await screen.findByText(/has not published its contact details/);
    expect(p.textContent).not.toMatch(/[A-Z]+_[A-Z_]+|IDPS_|\benv|setting/i);
    expect(screen.queryByText("Data fiduciary")).toBeNull();
  });

  it("shows an error when the notice fails", async () => {
    h.role = "analyst";
    h.api.mockImplementation(async () => { throw new Error("boom"); });
    render(<Privacy />);
    expect(await screen.findByText("boom")).toBeInTheDocument();
  });
});

describe("PublicPrivacy", () => {
  it("shows the notice and a Sign in link", async () => {
    render(<MemoryRouter><PublicPrivacy /></MemoryRouter>);
    await screen.findByText("Acme Ltd");
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/");
    expect(screen.queryByText("Erase an address")).toBeNull();
  });
});

describe("roles", () => {
  it("analysts see only the notice", async () => {
    h.role = "analyst";
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    for (const t of ["Erase an address", "Erasures", "Access log"]) expect(screen.queryByText(t, { selector: ".card-title, h2, h3" })).toBeNull();
    expect(calls("/admin")).toHaveLength(0);
  });
  it("admins also see Erase, Erasures and Access log", async () => {
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    expect(screen.getByText("Erase an address")).toBeInTheDocument();
    expect(screen.getByText("Erasures")).toBeInTheDocument();
    expect(screen.getByText("Access log", { selector: "h2, h3, .card-title, div, span" })).toBeInTheDocument();
  });
});

describe("Erase", () => {
  async function open(ip = "  203.0.113.7 ") {
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    fireEvent.change(screen.getByLabelText("IP address", { selector: "input[placeholder]" }), { target: { value: ip } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await screen.findByText("appears in:");
  }
  const erase = () => screen.getByRole("button", { name: "Erase permanently" });
  const reason = () => screen.getByLabelText(/^Reason/);
  const again = () => screen.getByLabelText(/Type the address again/);

  it("previews with the trimmed address and lists non-zero counts", async () => {
    await open();
    expect(calls("/admin/privacy/erase/preview")[0][1]).toEqual({ method: "POST", json: { ip: "203.0.113.7" } });
    expect(screen.getByText("alerts src ip")).toBeInTheDocument();
    expect(screen.getByText("case notes text")).toBeInTheDocument();
    expect(screen.getByText("in memory: cache")).toBeInTheDocument();
    expect(screen.queryByText("blocks ip")).toBeNull();
    expect(screen.getByText(/Also in 2 sensors name/)).toBeInTheDocument();
    expect(screen.queryByText(/users username/)).toBeNull();
    expect(screen.getByText("Backups keep copies.")).toBeInTheDocument();
  });

  it("enables Erase only with a reason and the retyped address", async () => {
    await open();
    expect(erase()).toBeDisabled();
    fireEvent.change(reason(), { target: { value: "request 16 Nov" } });
    expect(erase()).toBeDisabled();
    fireEvent.change(again(), { target: { value: "203.0.113.8" } });
    expect(erase()).toBeDisabled();
    fireEvent.change(again(), { target: { value: "203.0.113.7" } });
    expect(erase()).toBeEnabled();
    fireEvent.change(reason(), { target: { value: "   " } });
    expect(erase()).toBeDisabled();
  });

  it("erases, shows the notice and reloads Erasures", async () => {
    await open();
    expect(calls("/admin/privacy/erasures")).toHaveLength(1);
    fireEvent.change(reason(), { target: { value: " request 16 Nov " } });
    fireEvent.change(again(), { target: { value: "203.0.113.7" } });
    fireEvent.click(erase());
    await waitFor(() => expect(calls("/admin/privacy/erase")
      .filter(([p]) => p === "/admin/privacy/erase")).toHaveLength(1));
    expect(reqs.find(([p]) => p === "/admin/privacy/erase")![1])
      .toEqual({ method: "POST", json: { ip: "203.0.113.7", reason: "request 16 Nov" } });
    expect(await screen.findByText(/Erased: 7 rows and fields changed \(record #9\)/)).toBeInTheDocument();
    await waitFor(() => expect(calls("/admin/privacy/erasures")).toHaveLength(2));
    expect(screen.queryByText("appears in:")).toBeNull();
  });

  it("says Nothing holds when every count is zero", async () => {
    h.api.mockImplementation(async (path: string, opts?: any) => {
      reqs.push([path, opts]);
      if (path === "/privacy/notice") return N;
      if (path.startsWith("/admin/privacy/erasures")) return { items: [], next_cursor: null };
      if (path === "/admin/privacy/erase/preview") return preview({ counts: { a: 0 }, total: 0, manual_review: {}, warnings: [] });
      throw new Error(path);
    });
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    fireEvent.change(screen.getByLabelText("IP address", { selector: "input[placeholder]" }), { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    expect(await screen.findByText(/Nothing to erase automatically/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Erase permanently" })).toBeNull();
  });

  it("lists past erasures", async () => {
    erasures = [{ id: 1, at: "2026-11-10T10:00:00Z", requested_by: "root", reason: "legal request", subject_fp: "f", counts: { a: 2, b: 3 } }];
    render(<Privacy />);
    expect(await screen.findByText("legal request")).toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });
});

describe("AccessLog", () => {
  const entry = (id: number, o: Record<string, unknown> = {}) => ({
    id, at: "2026-11-10T10:00:00Z", user_id: 1, username: `user${id}`, action: "view_alert",
    target_type: "alert", target: String(id), subject_fp: null, ...o });
  const accessCard = () => screen.getByText(/Every view of personal data/).closest(".card") as HTMLElement;

  it("searches with ip and username, renders rows, loads older", async () => {
    accessPages.first = { items: [entry(1), entry(2)], next_cursor: "c1" };
    accessPages.next = { items: [entry(3)], next_cursor: null };
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    const card = within(accessCard());
    fireEvent.change(card.getByLabelText("IP address"), { target: { value: " 198.51.100.2 " } });
    fireEvent.change(card.getByLabelText("User"), { target: { value: "alice" } });
    fireEvent.click(card.getByRole("button", { name: "Search" }));
    await card.findByText("user1");
    const url = calls("/admin/privacy/access-log")[0][0];
    expect(url).toBe("/admin/privacy/access-log?ip=198.51.100.2&username=alice&limit=100");
    expect(card.getAllByText("view alert")).toHaveLength(2);
    fireEvent.click(card.getByRole("button", { name: "Load older entries" }));
    await card.findByText("user3");
    expect(calls("/admin/privacy/access-log")[1][0]).toContain("cursor=c1");
    expect(calls("/admin/privacy/access-log")[1][0]).toContain("ip=198.51.100.2");
    expect(card.getByText("user1")).toBeInTheDocument();
    expect(card.queryByRole("button", { name: "Load older entries" })).toBeNull();
  });

  it("shows No matching entries when empty", async () => {
    accessPages.first = { items: [], next_cursor: null };
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    const card = within(accessCard());
    fireEvent.click(card.getByRole("button", { name: "Search" }));
    expect(await card.findByText("No matching entries.")).toBeInTheDocument();
    expect(calls("/admin/privacy/access-log")[0][0]).toBe("/admin/privacy/access-log?limit=100");
  });
});


describe("helpers", () => {
  it("capitalise", () => {
    expect(capitalise("access")).toBe("Access");
    expect(capitalise("")).toBe("");
  });
  it("changed() leaves out cancelled actions, like the erase total", () => {
    expect(changed({ alerts: 3, "case_notes.text": 1, "actions.cancelled": 5 })).toBe(4);
  });
});

describe("erase safeguards (review fixes)", () => {
  it("locks the address while the preview loads and confirms against the previewed address", async () => {
    let release: (v: unknown) => void = () => {};
    h.api.mockImplementation(async (path: string) => {
      if (path === "/privacy/notice") return N;
      if (path.startsWith("/admin/privacy/erasures")) return { items: [], next_cursor: null };
      if (path === "/admin/privacy/erase/preview") return new Promise((r) => { release = r; });
      throw new Error(path);
    });
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    const box = screen.getByLabelText("IP address", { selector: "input[placeholder]" });
    fireEvent.change(box, { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(box).toBeDisabled()); // can't switch addresses mid-preview
    release(preview({ ip: "203.0.113.7" }));
    const erase = await screen.findByRole("button", { name: "Erase permanently" });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "request" } });
    fireEvent.change(screen.getByLabelText("Type the address again to confirm"), { target: { value: "203.0.113.8" } });
    expect(erase).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Type the address again to confirm"), { target: { value: "203.0.113.7" } });
    expect(erase).toBeEnabled();
  });

  it("still shows manual-review findings when nothing is erased automatically", async () => {
    h.api.mockImplementation(async (path: string) => {
      if (path === "/privacy/notice") return N;
      if (path.startsWith("/admin/privacy/erasures")) return { items: [], next_cursor: null };
      if (path === "/admin/privacy/erase/preview") {
        return preview({ counts: { alerts: 0 }, total: 0, manual_review: { "users.username": 1 }, warnings: [] });
      }
      throw new Error(path);
    });
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    fireEvent.change(screen.getByLabelText("IP address", { selector: "input[placeholder]" }), { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    expect(await screen.findByText(/change these by hand/)).toBeInTheDocument();
    expect(screen.getByText(/Nothing to erase automatically/)).toBeInTheDocument();
  });
});


describe("active block", () => {
  it("needs the force box before erasing, and sends force: true", async () => {
    h.api.mockImplementation(async (path: string, opts?: any) => {
      reqs.push([path, opts]);
      if (path === "/privacy/notice") return N;
      if (path.startsWith("/admin/privacy/erasures")) return { items: [], next_cursor: null };
      if (path === "/admin/privacy/erase/preview") {
        return preview({ active_blocks: 1, warnings: ["1 active block(s) of this address: erasing removes them from the SOC. Unblock first, or erase with force: true"] });
      }
      if (path === "/admin/privacy/erase") return { ...preview(), record_id: 3, erased_at: "x", total: 7 };
      throw new Error(path);
    });
    render(<Privacy />);
    await screen.findByText("Acme Ltd");
    fireEvent.change(screen.getByLabelText("IP address", { selector: "input[placeholder]" }), { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const erase = await screen.findByRole("button", { name: "Erase permanently" });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "request" } });
    fireEvent.change(screen.getByLabelText("Type the address again to confirm"), { target: { value: "203.0.113.7" } });
    expect(erase).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/Erase anyway/));
    expect(erase).toBeEnabled();
    fireEvent.click(erase);
    await waitFor(() => expect(reqs.some(([p, o]) => p === "/admin/privacy/erase" && o?.json?.force === true)).toBe(true));
  });
});
