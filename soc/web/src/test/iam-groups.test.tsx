import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, makeApi, meWith, newWorld, renderIam, group, user, type World } from "./iam-fixtures";

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

describe("IAM groups", () => {
  beforeEach(() => {
    w.users.push(user({ id: 4, username: "carol" }));
    w.groups[0] = group({ members: [{ id: 2, name: "alice" }], roles: [{ id: 10, name: "viewer" }] });
  });

  it("lists groups with member and role counts", async () => {
    renderIam("/iam/groups");
    const tr = within((await screen.findByRole("cell", { name: /ops/ })).closest("tr")!);
    expect(tr.getAllByRole("cell").map((c) => c.textContent).slice(1, 3)).toEqual(["1", "1"]);
  });

  it("filters by name", async () => {
    renderIam("/iam/groups");
    await screen.findByRole("cell", { name: /ops/ });
    fireEvent.change(screen.getByLabelText("Search name"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No groups match.")).toBeInTheDocument();
  });

  it("shows 403 and read-only controls", async () => {
    w.failures.push({ method: "GET", path: /^\/iam\/groups$/, status: 403, message: "missing permission: iam.groups.view" });
    renderIam("/iam/groups");
    expect(await screen.findByText(/don't have permission to view groups/i)).toBeInTheDocument();
  });

  it("hides write controls without iam.groups.write", async () => {
    h.me = meWith(["iam.groups.view"]);
    renderIam("/iam/groups");
    await screen.findByRole("cell", { name: /ops/ });
    expect(screen.queryByRole("button", { name: "Create group" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Delete/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Edit/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /View members and roles of ops/ }));
    const d = within(await screen.findByRole("dialog"));
    expect(await d.findByText("alice")).toBeInTheDocument();
    expect(d.queryByRole("button", { name: "Save" })).toBeNull();
  });

  it("validates then creates a group", async () => {
    renderIam("/iam/groups");
    await screen.findByRole("cell", { name: /ops/ });
    fireEvent.click(screen.getByRole("button", { name: "Create group" }));
    const d = within(await screen.findByRole("dialog", { name: "Create group" }));
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.click(d.getByRole("button", { name: "Create group" }));
    expect(await d.findByText("Use 3 to 48 characters.")).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "night-shift" } });
    fireEvent.click(d.getByRole("button", { name: "Create group" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/groups")).toHaveLength(1));
    expect(await screen.findByText("Created group night-shift.")).toBeInTheDocument();
    expect(await screen.findByRole("cell", { name: /night-shift/ })).toBeInTheDocument();
  });

  it("edits a group", async () => {
    renderIam("/iam/groups");
    fireEvent.click(await screen.findByRole("button", { name: "Edit ops" }));
    const d = within(await screen.findByRole("dialog", { name: "Edit group ops" }));
    fireEvent.change(d.getByLabelText("Description"), { target: { value: "operators" } });
    fireEvent.click(d.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls(h.api, "PATCH", "/iam/groups/20")[0][1]).toMatchObject({ json: { description: "operators" } }));
    expect(await screen.findByText("operators")).toBeInTheDocument();
  });

  it("adds and removes members and roles with the two PUT calls", async () => {
    renderIam("/iam/groups");
    fireEvent.click(await screen.findByRole("button", { name: "Manage members and roles of ops" }));
    const d = within(await screen.findByRole("dialog", { name: "Members and roles of ops" }));
    expect(await d.findByRole("checkbox", { name: "alice" })).toBeChecked();
    fireEvent.click(d.getByRole("checkbox", { name: "carol" }));
    fireEvent.click(d.getByRole("checkbox", { name: "alice" }));
    fireEvent.click(d.getByRole("checkbox", { name: /viewer/ })); // remove the role
    fireEvent.click(d.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls(h.api, "PUT")).toHaveLength(2));
    expect(calls(h.api, "PUT", "/iam/groups/20/members")[0][1]).toMatchObject({ json: { user_ids: [4] } });
    expect(calls(h.api, "PUT", "/iam/groups/20/roles")[0][1]).toMatchObject({ json: { role_ids: [] } });
    expect(await screen.findByText("Updated ops.")).toBeInTheDocument();
  });

  it("does not touch members when only roles changed", async () => {
    renderIam("/iam/groups");
    fireEvent.click(await screen.findByRole("button", { name: "Manage members and roles of ops" }));
    const d = within(await screen.findByRole("dialog"));
    fireEvent.click(await d.findByRole("checkbox", { name: /analyst/ }));
    fireEvent.click(d.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls(h.api, "PUT")).toHaveLength(1));
    expect(calls(h.api, "PUT")[0][0]).toBe("/iam/groups/20/roles");
  });

  it("shows the server's error when saving members", async () => {
    w.failures.push({ method: "PUT", path: /members$/, status: 403, message: "you cannot change your own group membership" });
    renderIam("/iam/groups");
    fireEvent.click(await screen.findByRole("button", { name: "Manage members and roles of ops" }));
    const d = within(await screen.findByRole("dialog"));
    fireEvent.click(await d.findByRole("checkbox", { name: "carol" }));
    fireEvent.click(d.getByRole("button", { name: "Save" }));
    expect(await d.findByText(/cannot change your own group membership/)).toBeInTheDocument();
  });

  it("confirms before deleting a group", async () => {
    renderIam("/iam/groups");
    fireEvent.click(await screen.findByRole("button", { name: "Delete ops" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete group ops?" });
    expect(calls(h.api, "DELETE")).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete group" }));
    await waitFor(() => expect(calls(h.api, "DELETE", "/iam/groups/20")).toHaveLength(1));
    expect(await screen.findByText("No groups match.")).toBeInTheDocument();
  });
});
