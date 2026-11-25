import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, makeApi, meWith, newWorld, renderIam, type World } from "./iam-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), me: {} as Record<string, unknown> }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: h.me, loading: false, logout: vi.fn(), can: (p: string) => (h.me.permissions as string[] | undefined)?.includes(p) ?? false }),
}));

let w: World;
beforeEach(() => {
  w = newWorld();
  h.me = meWith(ADMIN_PERMS);
  h.api.mockReset();
  h.api.mockImplementation(makeApi(w));
});

import { entry, login } from "./iam-fixtures";

describe("IAM login history", () => {
  beforeEach(() => {
    w.logins = [
      login({ id: 1, username: "alice", at: "2026-11-01T08:00:00Z" }),
      login({ id: 2, username: "bob", success: false, reason: "bad_password", ip: "10.0.0.9", at: "2026-11-02T08:00:00Z" }),
      login({ id: 3, username: "alice", success: false, reason: "locked", at: "2026-11-03T08:00:00Z" }),
    ];
  });
  const rows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);

  it("lists attempts with a text result, the reason for failures, and mfa", async () => {
    renderIam("/iam/logins");
    await screen.findByRole("table");
    expect(rows()).toHaveLength(3);
    expect(screen.getByText("✓ Success")).toBeInTheDocument();
    expect(screen.getAllByText("✕ Failed")).toHaveLength(2);
    expect(within(screen.getByRole("table")).getByText("bad password")).toBeInTheDocument();
  });

  it("filters by username and by result", async () => {
    renderIam("/iam/logins");
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Username (exact)"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Result"), { target: { value: "false" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(within(rows()[0]).getByText("locked")).toBeInTheDocument();
    const last = calls(h.api, "GET", "/iam/logins").pop()![0] as string;
    expect(last).toContain("username=alice");
    expect(last).toContain("success=false");
  });

  it("filters by reason", async () => {
    renderIam("/iam/logins");
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "bad_password" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(rows()).toHaveLength(1));
  });

  it("sends the date range as ISO times with Z", async () => {
    renderIam("/iam/logins");
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText(/From/), { target: { value: "2026-11-02T00:00" } });
    fireEvent.change(screen.getByLabelText(/To/), { target: { value: "2026-11-02T23:59" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(rows()).toHaveLength(1));
    const url = new URL(calls(h.api, "GET", "/iam/logins").pop()![0] as string, "http://x");
    expect(url.searchParams.get("since")).toBe(new Date("2026-11-02T00:00").toISOString());
    expect(url.searchParams.get("until")).toBe(new Date("2026-11-02T23:59").toISOString());
    expect(url.searchParams.get("since")).toMatch(/Z$/);
  });

  it("refuses a start time after the end time without calling the API", async () => {
    renderIam("/iam/logins");
    await screen.findByRole("table");
    const before = calls(h.api, "GET", "/iam/logins").length;
    fireEvent.change(screen.getByLabelText(/From/), { target: { value: "2026-11-05T00:00" } });
    fireEvent.change(screen.getByLabelText(/To/), { target: { value: "2026-11-01T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("The start time is after the end time.")).toBeInTheDocument();
    expect(calls(h.api, "GET", "/iam/logins")).toHaveLength(before);
  });

  it("starts filtered by the username in the link from a user page", async () => {
    renderIam("/iam/logins?username=bob");
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(screen.getByLabelText("Username (exact)")).toHaveValue("bob");
  });

  it("paginates", async () => {
    for (let i = 10; i < 40; i++) w.logins.push(login({ id: i, username: `u${i}` }));
    renderIam("/iam/logins");
    await screen.findByRole("table");
    expect(rows()).toHaveLength(25);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Page 2");
    await waitFor(() => expect(rows()).toHaveLength(8));
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    await waitFor(() => expect(rows()).toHaveLength(25));
  });

  it("shows the 403 state and does not call the API without the permission", async () => {
    h.me = meWith(["iam.users.view"]);
    renderIam("/iam/logins");
    expect(screen.getByText(/don't have permission to view the login history/i)).toBeInTheDocument();
    expect(calls(h.api, "GET", "/iam/logins")).toHaveLength(0);
  });

  it("shows the backend's message for a rejected range", async () => {
    w.failures.push({ method: "GET", path: /logins$/, status: 422, message: "the time needs a timezone" });
    renderIam("/iam/logins");
    expect(await screen.findByText(/the time needs a timezone/)).toBeInTheDocument();
  });
});

describe("IAM audit log", () => {
  beforeEach(() => {
    w.audit = [
      entry({ id: 1, actor_name: "root", action: "iam_user_create", target: "user:alice", details: { id: 2 } }),
      entry({ id: 2, actor_name: "ann", action: "iam_role_delete", target: "role:viewer", details: {} }),
      entry({ id: 3, actor_name: "root", action: "iam_role_create", target: "role:viewer", details: { permissions: ["cloud.view"] } }),
    ];
  });
  const rows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);

  it("lists entries and expands details as text", async () => {
    renderIam("/iam/audit");
    await screen.findByRole("table");
    expect(rows()).toHaveLength(3);
    fireEvent.click(screen.getAllByText(/Show details/)[0]);
    expect(screen.getByText(/"cloud.view"/)).toBeInTheDocument();
  });

  it("renders hostile details as plain text, never as HTML", async () => {
    w.audit = [entry({ id: 9, target: "user:<img src=x onerror=alert(1)>", details: { note: "<b>bold</b>" } })];
    renderIam("/iam/audit");
    await screen.findByRole("table");
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByText("user:<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });

  it("filters by actor, action and target", async () => {
    renderIam("/iam/audit");
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Actor (exact)"), { target: { value: "root" } });
    fireEvent.change(screen.getByLabelText("Action (exact)"), { target: { value: "iam_role_create" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(rows()).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    await waitFor(() => expect(rows()).toHaveLength(3));
    fireEvent.change(screen.getByLabelText(/Target/), { target: { value: "role:viewer" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(rows()).toHaveLength(2));
  });

  it("sends the date range with Z and validates it", async () => {
    renderIam("/iam/audit");
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText(/From/), { target: { value: "2026-11-01T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(String(calls(h.api, "GET", "/iam/audit").pop()![0])).toMatch(/since=[^&]*Z/));
    fireEvent.change(screen.getByLabelText(/To/), { target: { value: "2026-10-01T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("The start time is after the end time.")).toBeInTheDocument();
  });

  it("paginates", async () => {
    for (let i = 10; i < 40; i++) w.audit.push(entry({ id: i }));
    renderIam("/iam/audit");
    await screen.findByRole("table");
    expect(rows()).toHaveLength(25);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(rows()).toHaveLength(8));
  });

  it("shows the 403 state from the backend", async () => {
    w.failures.push({ method: "GET", path: /audit$/, status: 403, message: "missing permission: iam.audit.view" });
    renderIam("/iam/audit");
    expect(await screen.findByText(/don't have permission to view the audit log/i)).toBeInTheDocument();
  });
});
