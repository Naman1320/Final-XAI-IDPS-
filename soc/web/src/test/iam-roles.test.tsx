import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, makeApi, meWith, newWorld, renderIam, user, type World } from "./iam-fixtures";

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

const row = async (name: string) => (await screen.findByRole("cell", { name: new RegExp(name) })).closest("tr") as HTMLElement;

describe("IAM roles", () => {
  it("lists roles with permission and member counts, and locks system roles", async () => {
    w.users[1] = user({ roles: [{ id: 10, name: "viewer" }] });
    renderIam("/iam/roles");
    const viewer = within(await row("viewer"));
    expect(viewer.getAllByRole("cell").map((c) => c.textContent).slice(1, 4)).toEqual(["1", "1", "0"]); // perms, users, groups
    const admin = within(await row("admin"));
    expect(admin.getByText("Locked: system role")).toBeInTheDocument();
    expect(admin.queryByRole("button", { name: /^Delete/ })).toBeNull();
    expect(admin.queryByRole("button", { name: /^Edit/ })).toBeNull();
    expect(admin.getByRole("button", { name: "View admin" })).toBeInTheDocument();
    expect(viewer.getByRole("button", { name: "Edit viewer" })).toBeInTheDocument();
  });

  it("filters by name and type", async () => {
    renderIam("/iam/roles");
    await row("viewer");
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "true" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(screen.queryByRole("cell", { name: /viewer/ })).toBeNull());
    expect(screen.getAllByRole("cell", { name: /Locked/ })).toHaveLength(2);
    fireEvent.change(screen.getByLabelText("Search name"), { target: { value: "zzz" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No roles match.")).toBeInTheDocument();
  });

  it("shows the no-permission state on 403", async () => {
    w.failures.push({ method: "GET", path: /^\/iam\/roles$/, status: 403, message: "missing permission: iam.roles.view" });
    renderIam("/iam/roles");
    expect(await screen.findByText(/don't have permission to view roles/i)).toBeInTheDocument();
  });

  it("hides create, edit and delete without iam.roles.write", async () => {
    h.me = meWith(["iam.roles.view"]);
    renderIam("/iam/roles");
    await row("viewer");
    expect(screen.queryByRole("button", { name: "Create role" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Edit/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Delete/ })).toBeNull();
    expect(screen.getByRole("button", { name: "View viewer" })).toBeInTheDocument();
  });

  it("opens a system role read-only", async () => {
    renderIam("/iam/roles");
    fireEvent.click(await screen.findByRole("button", { name: "View analyst" }));
    const d = within(await screen.findByRole("dialog", { name: "Role analyst" }));
    expect(d.getByText(/System roles are locked/)).toBeInTheDocument();
    expect(d.getByLabelText("Name")).toHaveAttribute("readonly");
    expect(await d.findByRole("checkbox", { name: /cloud.view/ })).toBeDisabled();
    expect(d.queryByRole("button", { name: /Save/ })).toBeNull();
  });
});

describe("IAM role form and permission checklist", () => {
  async function openCreate() {
    renderIam("/iam/roles");
    await row("viewer");
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    const dialog = await screen.findByRole("dialog", { name: "Create role" });
    await within(dialog).findByRole("group", { name: "Cloud" });
    return within(dialog);
  }

  it("groups permissions and selects all of a group at once, with a partial state", async () => {
    const d = await openCreate();
    const cloud = within(d.getByRole("group", { name: "Cloud" }));
    const all = cloud.getByRole("checkbox", { name: "Select all Cloud permissions" }) as HTMLInputElement;
    expect(all.checked).toBe(false);
    fireEvent.click(cloud.getByRole("checkbox", { name: /cloud.view/ }));
    expect(all.indeterminate).toBe(true);
    fireEvent.click(all);
    expect(cloud.getByRole("checkbox", { name: /cloud.view/ })).toBeChecked();
    expect(cloud.getByRole("checkbox", { name: /cloud.instances.write/ })).toBeChecked();
    expect(all.indeterminate).toBe(false);
    fireEvent.click(all); // again: clears the group
    expect(cloud.getByRole("checkbox", { name: /cloud.view/ })).not.toBeChecked();
    expect(d.getByRole("group", { name: "Monitoring" })).toBeInTheDocument();
  });

  it("validates the name and description before sending", async () => {
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "ab" } });
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText("Use 3 to 48 characters.")).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "bad/name" } });
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText(/Use only letters, digits, spaces/)).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: " padded " } });
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText(/must not start or end with a space/i)).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "okay name" } });
    fireEvent.change(d.getByLabelText("Description"), { target: { value: "ok" + "\u202e" } });
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText(/direction-override/)).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Description"), { target: { value: "x".repeat(256) } });
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText("At most 255 characters.")).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
  });

  it("creates a role with the checked permissions", async () => {
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "responders" } });
    fireEvent.change(d.getByLabelText("Description"), { target: { value: "on call" } });
    fireEvent.click(d.getByRole("checkbox", { name: "Select all Monitoring permissions" }));
    fireEvent.click(d.getByRole("checkbox", { name: /cloud.view/ }));
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/roles")).toHaveLength(1));
    expect(calls(h.api, "POST", "/iam/roles")[0][1]).toMatchObject({
      json: { name: "responders", description: "on call", permissions: ["cloud.view", "iam.audit.view", "iam.logins.view"] },
    });
    expect(await screen.findByText("Created role responders.")).toBeInTheDocument();
    expect(await screen.findByRole("cell", { name: /responders/ })).toBeInTheDocument();
  });

  it("shows the backend's duplicate-name error and keeps the form", async () => {
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "VIEWER" } });
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText("the name 'VIEWER' is already used")).toBeInTheDocument();
  });

  it("shows a 403 about granting permissions you do not hold", async () => {
    w.failures.push({ method: "POST", path: /^\/iam\/roles$/, status: 403, message: "you cannot grant permissions you do not hold: iam.users.delete" });
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "greedy" } });
    fireEvent.click(d.getByRole("checkbox", { name: /iam.users.delete/ }));
    fireEvent.click(d.getByRole("button", { name: "Create role" }));
    expect(await d.findByText(/You don't have permission for that: you cannot grant permissions/)).toBeInTheDocument();
  });

  it("disables permissions you do not hold so you cannot grant them", async () => {
    h.me = meWith(["iam.roles.view", "iam.roles.write", "cloud.view"]);
    const d = await openCreate();
    expect(d.getByRole("checkbox", { name: /cloud.view/ })).toBeEnabled();
    expect(d.getByRole("checkbox", { name: /iam.users.delete/ })).toBeDisabled();
    // "select all" only takes what you hold
    fireEvent.click(d.getByRole("checkbox", { name: "Select all Cloud permissions" }));
    expect(d.getByRole("checkbox", { name: /cloud.view/ })).toBeChecked();
    expect(d.getByRole("checkbox", { name: /cloud.instances.write/ })).not.toBeChecked();
  });

  it("edits a custom role and sends only the changed fields", async () => {
    renderIam("/iam/roles");
    fireEvent.click(await screen.findByRole("button", { name: "Edit viewer" }));
    const d = within(await screen.findByRole("dialog", { name: "Edit role viewer" }));
    await d.findByRole("group", { name: "Cloud" });
    expect(d.getByRole("checkbox", { name: /cloud.view/ })).toBeChecked();
    expect(d.getByRole("button", { name: "Save changes" })).toBeDisabled();
    fireEvent.click(d.getByRole("checkbox", { name: /cloud.instances.write/ }));
    fireEvent.click(d.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls(h.api, "PATCH", "/iam/roles/10")).toHaveLength(1));
    expect((calls(h.api, "PATCH")[0][1] as { json: object }).json).toEqual({ permissions: ["cloud.instances.write", "cloud.view"] });
    expect(await screen.findByText("Saved role viewer.")).toBeInTheDocument();
  });
});

describe("IAM delete role", () => {
  it("asks first, then deletes and reloads", async () => {
    renderIam("/iam/roles");
    fireEvent.click(await screen.findByRole("button", { name: "Delete viewer" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete role viewer?" });
    expect(calls(h.api, "DELETE")).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete role" }));
    await waitFor(() => expect(calls(h.api, "DELETE", "/iam/roles/10")).toHaveLength(1));
    expect(await screen.findByText("Deleted role viewer.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("cell", { name: /viewer/ })).toBeNull());
  });

  it("shows the server's error", async () => {
    w.failures.push({ method: "DELETE", path: /roles\/10$/, status: 403, message: "you cannot lift restrictions on permissions you do not hold" });
    renderIam("/iam/roles");
    fireEvent.click(await screen.findByRole("button", { name: "Delete viewer" }));
    const dialog = within(await screen.findByRole("dialog"));
    fireEvent.click(dialog.getByRole("button", { name: "Delete role" }));
    expect(await dialog.findByText(/lift restrictions/)).toBeInTheDocument();
  });
});
