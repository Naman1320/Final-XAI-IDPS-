import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, makeApi, meWith, newWorld, renderIam, role, group, user, type World } from "./iam-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), me: {} as Record<string, unknown> }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: h.me, loading: false, logout: vi.fn(), can: (p: string) => (h.me.permissions as string[] | undefined)?.includes(p) ?? false }),
}));

let w: World;
beforeEach(() => {
  w = newWorld();
  w.roles.push(role({ id: 11, name: "auditor" }));
  w.groups.push(group({ id: 21, name: "night-shift" }));
  h.me = meWith(ADMIN_PERMS);
  h.api.mockReset();
  h.api.mockImplementation(makeApi(w));
});

const table = async () => within(await screen.findByRole("table"));

describe("IAM users list", () => {
  it("renders users with status, legacy role, roles and groups", async () => {
    w.users[1] = user({ roles: [{ id: 10, name: "viewer" }], groups: [{ id: 20, name: "ops" }] });
    renderIam("/iam/users");
    const t = await table();
    expect(t.getByRole("link", { name: "alice" })).toHaveAttribute("href", "/iam/users/2");
    expect(t.getByText("viewer")).toBeInTheDocument();
    expect(t.getByText("ops")).toBeInTheDocument();
    expect(t.getByText("✕ Deactivated")).toBeInTheDocument(); // bob: status is text, not only colour
    expect(t.getAllByText("✓ Active")).toHaveLength(2);
  });

  it("shows a loading state first", async () => {
    renderIam("/iam/users");
    expect(screen.getByRole("status", { name: /loading users/i })).toBeInTheDocument();
    await table();
  });

  it("sends the filters to the API and can reset them", async () => {
    renderIam("/iam/users");
    await table();
    fireEvent.change(screen.getByLabelText("Search username"), { target: { value: "ali" } });
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "active" } });
    fireEvent.change(screen.getByLabelText("Legacy role"), { target: { value: "analyst" } });
    await screen.findByLabelText("Group");
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "20" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(calls(h.api, "GET", "/iam/users?").some(([p]) =>
      /q=ali/.test(String(p)) && /status=active/.test(String(p)) && /role=analyst/.test(String(p)) && /group_id=20/.test(String(p)))).toBe(true));
    expect(await screen.findByText("No users match.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    expect(await screen.findByRole("link", { name: "alice" })).toBeInTheDocument();
    expect(screen.getByLabelText("Search username")).toHaveValue("");
  });

  it("filters by status for real", async () => {
    renderIam("/iam/users");
    await table();
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "disabled" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(screen.queryByRole("link", { name: "alice" })).toBeNull());
    expect(screen.getByRole("link", { name: "bob" })).toBeInTheDocument();
  });

  it("pages through results with Next and Previous", async () => {
    for (let i = 10; i < 40; i++) w.users.push(user({ id: i, username: `user${i}` }));
    renderIam("/iam/users");
    await table();
    expect(screen.getByRole("link", { name: "user39" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "user10" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByRole("link", { name: "user10" })).toBeInTheDocument();
    expect(screen.getByText("Page 2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByRole("link", { name: "user39" })).toBeInTheDocument();
  });

  it("shows a clear no-permission state on 403", async () => {
    w.failures.push({ method: "GET", path: /^\/iam\/users$/, status: 403, message: "missing permission: iam.users.view" });
    renderIam("/iam/users");
    expect(await screen.findByText(/don't have permission to view users/i)).toBeInTheDocument();
  });

  it("shows the server's message for other errors, with a retry", async () => {
    w.failures.push({ method: "GET", path: /^\/iam\/users$/, status: 500, message: "database is down" });
    renderIam("/iam/users");
    expect(await screen.findByText(/database is down/)).toBeInTheDocument();
    w.failures = [];
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("link", { name: "alice" })).toBeInTheDocument();
  });

  it("does not call the API when the user lacks iam.users.view", () => {
    h.me = meWith(["iam.roles.view"]);
    renderIam("/iam/users");
    expect(screen.getByText(/don't have permission to view users/i)).toBeInTheDocument();
    expect(calls(h.api, "GET", "/iam/users")).toHaveLength(0);
  });
});

describe("IAM users: permissions in the UI", () => {
  it("hides create, deactivate and activate without iam.users.write", async () => {
    h.me = meWith(["iam.users.view"]);
    renderIam("/iam/users");
    await table();
    expect(screen.queryByRole("button", { name: "Create user" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Deactivate/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Activate/ })).toBeNull();
    expect(screen.getByRole("button", { name: "View alice" })).toBeInTheDocument();
  });

  it("keeps the controls when the SOC sends no permissions list", async () => {
    h.me = meWith(undefined);
    renderIam("/iam/users");
    await table();
    expect(screen.getByRole("button", { name: "Create user" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deactivate alice" })).toBeInTheDocument();
  });
});

describe("IAM create user", () => {
  async function open() {
    renderIam("/iam/users");
    await table();
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));
    return await screen.findByRole("dialog", { name: "Create user" });
  }

  it("moves focus into the dialog and closes on Escape, returning focus", async () => {
    renderIam("/iam/users");
    await table();
    const opener = screen.getByRole("button", { name: "Create user" });
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByRole("dialog", { name: "Create user" });
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(opener).toHaveFocus();
  });

  it("validates the username and password before sending", async () => {
    const dialog = await open();
    const d = within(dialog);
    fireEvent.change(d.getByLabelText("Password"), { target: { value: "short" } });
    expect(d.getByText(/5\/12 so far/)).toBeInTheDocument();
    fireEvent.click(d.getByRole("button", { name: "Create user" }));
    expect(await d.findByText("Enter a username.")).toBeInTheDocument();
    expect(d.getByText(/At least 12 characters \(5 so far\)/)).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Username"), { target: { value: "bad name!" } });
    fireEvent.click(d.getByRole("button", { name: "Create user" }));
    expect(await d.findByText(/Use only letters, digits and/)).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
  });

  it("creates the user with roles and groups, then opens the detail page with a toast", async () => {
    const dialog = await open();
    const d = within(dialog);
    fireEvent.change(d.getByLabelText("Username"), { target: { value: "carol" } });
    fireEvent.change(d.getByLabelText("Password"), { target: { value: "a-long-enough-pass" } });
    fireEvent.change(d.getByLabelText("Legacy role"), { target: { value: "admin" } });
    fireEvent.click(await d.findByRole("checkbox", { name: /auditor/ }));
    fireEvent.click(await d.findByRole("checkbox", { name: "night-shift" }));
    fireEvent.click(d.getByRole("button", { name: "Create user" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/users")).toHaveLength(1));
    expect(calls(h.api, "POST", "/iam/users")[0][1]).toMatchObject({
      json: { username: "carol", password: "a-long-enough-pass", role: "admin", role_ids: [11], group_ids: [21] },
    });
    expect(await screen.findByText("Created carol.")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "carol", level: 1 })).toBeInTheDocument();
  });

  it("shows the backend's error and keeps the dialog open", async () => {
    const dialog = await open();
    const d = within(dialog);
    fireEvent.change(d.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(d.getByLabelText("Password"), { target: { value: "a-long-enough-pass" } });
    fireEvent.click(d.getByRole("button", { name: "Create user" }));
    expect(await d.findByText("user 'alice' already exists")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("shows a 403 from the backend as a permission message", async () => {
    w.failures.push({ method: "POST", path: /^\/iam\/users$/, status: 403, message: "only someone holding every permission can make an administrator" });
    const dialog = await open();
    const d = within(dialog);
    fireEvent.change(d.getByLabelText("Username"), { target: { value: "dave" } });
    fireEvent.change(d.getByLabelText("Password"), { target: { value: "a-long-enough-pass" } });
    fireEvent.click(d.getByRole("button", { name: "Create user" }));
    expect(await d.findByText(/You don't have permission for that: only someone holding every permission/)).toBeInTheDocument();
  });
});

describe("IAM deactivate and activate from the list", () => {
  it("confirms before deactivating, then calls the API and reloads", async () => {
    renderIam("/iam/users");
    await table();
    fireEvent.click(screen.getByRole("button", { name: "Deactivate alice" }));
    const dialog = await screen.findByRole("dialog", { name: "Deactivate alice?" });
    expect(calls(h.api, "POST")).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/users/2/deactivate")).toHaveLength(1));
    expect(await screen.findByText("Deactivated alice.")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Activate alice" })).toBeInTheDocument();
  });

  it("activates without a dialog", async () => {
    renderIam("/iam/users");
    await table();
    fireEvent.click(screen.getByRole("button", { name: "Activate bob" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/users/3/activate")).toHaveLength(1));
    expect(await screen.findByText("Activated bob.")).toBeInTheDocument();
  });

  it("shows the server's refusal inside the dialog", async () => {
    w.failures.push({ method: "POST", path: /deactivate$/, status: 409, message: "the last enabled admin cannot be removed" });
    renderIam("/iam/users");
    await table();
    fireEvent.click(screen.getByRole("button", { name: "Deactivate alice" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));
    expect(await within(dialog).findByText(/last enabled admin/)).toBeInTheDocument();
  });
});
