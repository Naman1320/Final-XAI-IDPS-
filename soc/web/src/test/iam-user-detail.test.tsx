import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, login, makeApi, meWith, newWorld, renderIam, role, group, user, type World } from "./iam-fixtures";

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
  w.users[1] = user({ roles: [{ id: 10, name: "viewer" }], groups: [{ id: 20, name: "ops" }], mfa_enabled: true });
  w.effective[2] = {
    user_id: 2, username: "alice", legacy_role: "analyst", all_access: false, permissions: ["cloud.view", "iam.users.view"],
    denied: ["cloud.instances.write"], roles: [{ id: 2, name: "analyst" }, { id: 10, name: "viewer" }], groups: [{ id: 20, name: "ops" }],
    policies: [{ id: 30, name: "no-delete", effect: "deny" }],
  };
  w.logins = [login({ id: 5, user_id: 2, ip: "10.9.9.9" }), login({ id: 6, user_id: 3, username: "bob", ip: "10.1.1.1" })];
  h.me = meWith(ADMIN_PERMS);
  h.api.mockReset();
  h.api.mockImplementation(makeApi(w));
});

describe("IAM user detail", () => {
  it("shows the profile, roles, groups, MFA and last sign-ins of that user only", async () => {
    renderIam("/iam/users/2");
    expect(await screen.findByRole("heading", { name: "alice", level: 1 })).toBeInTheDocument();
    const profile = within(screen.getByRole("region", { name: "Profile" }));
    expect(profile.getByText("MFA on")).toBeInTheDocument();
    const access = within(screen.getByRole("region", { name: "Roles and groups" }));
    expect(access.getByText("viewer")).toBeInTheDocument();
    expect(access.getByText("ops")).toBeInTheDocument();
    expect(await screen.findByText("10.9.9.9")).toBeInTheDocument();
    expect(screen.queryByText("10.1.1.1")).toBeNull();
    expect(calls(h.api, "GET", "/iam/logins?user_id=2")).toHaveLength(1);
  });

  it("shows effective permissions grouped, the denied ones with text, and applying policies", async () => {
    renderIam("/iam/users/2");
    const eff = within(await screen.findByRole("region", { name: "Effective permissions" }));
    expect(await eff.findByText("cloud.view")).toBeInTheDocument();
    expect(eff.getByText("iam.users.view")).toBeInTheDocument();
    expect(eff.getByText("Removed by a deny policy")).toBeInTheDocument();
    expect(eff.getByText("cloud.instances.write")).toHaveClass("denied");
    expect(eff.getByText("Deny: no-delete")).toBeInTheDocument();
  });

  it("shows a message for an unknown user", async () => {
    renderIam("/iam/users/99");
    expect(await screen.findByText("user not found")).toBeInTheDocument();
  });

  it("hides the logins card without iam.logins.view and does not request them", async () => {
    h.me = meWith(ADMIN_PERMS.filter((p) => p !== "iam.logins.view"));
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    expect(screen.queryByRole("region", { name: "Recent sign-ins" })).toBeNull();
    expect(calls(h.api, "GET", "/iam/logins")).toHaveLength(0);
  });

  it("hides edit, deactivate and delete for a read-only viewer", async () => {
    h.me = meWith(["iam.users.view"]);
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    expect(screen.queryByRole("button", { name: /Edit roles/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deactivate" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete user" })).toBeNull();
  });

  it("shows delete only with iam.users.delete", async () => {
    h.me = meWith(["iam.users.view", "iam.users.write"]);
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    expect(screen.getByRole("button", { name: "Edit roles and groups" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Delete user" })).toBeNull();
  });

  it("disables changes to your own account", async () => {
    h.me = meWith(ADMIN_PERMS, { id: 2, username: "alice" });
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    expect(screen.getByRole("button", { name: "Edit roles and groups" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Deactivate" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Delete user" })).toBeDisabled();
  });

  it("edits roles and groups and sends only what changed", async () => {
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    fireEvent.click(screen.getByRole("button", { name: "Edit roles and groups" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit access of alice" });
    const d = within(dialog);
    expect(await d.findByRole("checkbox", { name: /viewer/ })).toBeChecked();
    expect(d.getByRole("button", { name: "Save changes" })).toBeDisabled(); // nothing changed yet
    fireEvent.click(d.getByRole("checkbox", { name: /auditor/ }));
    fireEvent.click(d.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls(h.api, "PATCH", "/iam/users/2")).toHaveLength(1));
    expect(calls(h.api, "PATCH", "/iam/users/2")[0][1]).toMatchObject({ json: { role_ids: [10, 11] } });
    expect((calls(h.api, "PATCH", "/iam/users/2")[0][1] as { json: object }).json).not.toHaveProperty("group_ids");
    expect(await screen.findByText(/Updated alice/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("shows the backend's refusal when editing", async () => {
    w.failures.push({ method: "PATCH", path: /users\/2$/, status: 403, message: "you cannot grant permissions you do not hold: cloud.instances.write" });
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    fireEvent.click(screen.getByRole("button", { name: "Edit roles and groups" }));
    const d = within(await screen.findByRole("dialog"));
    fireEvent.click(await d.findByRole("checkbox", { name: /auditor/ }));
    fireEvent.click(d.getByRole("button", { name: "Save changes" }));
    expect(await d.findByText(/You don't have permission for that: you cannot grant permissions/)).toBeInTheDocument();
  });

  it("changes the legacy role", async () => {
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    fireEvent.click(screen.getByRole("button", { name: "Edit roles and groups" }));
    const d = within(await screen.findByRole("dialog"));
    fireEvent.change(d.getByLabelText("Legacy role"), { target: { value: "admin" } });
    fireEvent.click(d.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls(h.api, "PATCH")[0][1]).toMatchObject({ json: { role: "admin" } }));
  });

  it("deactivates after a confirmation and activates again", async () => {
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    const dialog = await screen.findByRole("dialog", { name: "Deactivate alice?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/users/2/deactivate")).toHaveLength(1));
    const activate = await screen.findByRole("button", { name: "Activate" });
    fireEvent.click(activate);
    await waitFor(() => expect(calls(h.api, "POST", "/iam/users/2/activate")).toHaveLength(1));
    expect(await screen.findByRole("button", { name: "Deactivate" })).toBeInTheDocument();
  });
});

describe("IAM delete user (typed confirmation)", () => {
  async function openDelete() {
    renderIam("/iam/users/2");
    await screen.findByRole("heading", { name: "alice", level: 1 });
    fireEvent.click(screen.getByRole("button", { name: "Delete user" }));
    return within(await screen.findByRole("dialog", { name: "Delete alice?" }));
  }

  it("keeps the button off until the exact username is typed", async () => {
    const d = await openDelete();
    const button = d.getByRole("button", { name: "Delete user" });
    expect(button).toBeDisabled();
    fireEvent.change(d.getByLabelText(/Type/), { target: { value: "alic" } });
    expect(button).toBeDisabled();
    fireEvent.change(d.getByLabelText(/Type/), { target: { value: "Alice" } }); // case matters
    expect(button).toBeDisabled();
    fireEvent.change(d.getByLabelText(/Type/), { target: { value: "alice" } });
    expect(button).toBeEnabled();
    expect(calls(h.api, "DELETE")).toHaveLength(0);
  });

  it("deletes, shows a toast and returns to the list", async () => {
    const d = await openDelete();
    fireEvent.change(d.getByLabelText(/Type/), { target: { value: "alice" } });
    fireEvent.click(d.getByRole("button", { name: "Delete user" }));
    await waitFor(() => expect(calls(h.api, "DELETE", "/iam/users/2")).toHaveLength(1));
    expect(await screen.findByText("Deleted alice.")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("link", { name: "alice" })).toBeNull());
  });

  it("shows the backend's error and does not leave the page", async () => {
    w.failures.push({ method: "DELETE", path: /users\/2$/, status: 409, message: "the last enabled admin cannot be removed" });
    const d = await openDelete();
    fireEvent.change(d.getByLabelText(/Type/), { target: { value: "alice" } });
    fireEvent.click(d.getByRole("button", { name: "Delete user" }));
    expect(await d.findByText(/last enabled admin/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "alice", level: 1 })).toBeInTheDocument();
  });

  it("Cancel closes the dialog without deleting", async () => {
    const d = await openDelete();
    fireEvent.click(d.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(calls(h.api, "DELETE")).toHaveLength(0);
  });
});
