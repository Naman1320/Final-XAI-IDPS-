import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ADMIN_PERMS, calls, makeApi, meWith, newWorld, renderIam, policy, type World } from "./iam-fixtures";

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

describe("IAM policies", () => {
  it("lists policies with effect as text, patterns, resources and attachment count", async () => {
    w.policies[0] = policy({ attachments: [{ subject_type: "user", subject_id: 2, subject_name: "alice" }], resources: ["instance:i-1"] });
    renderIam("/iam/policies");
    const tr = within(await row("no-delete"));
    expect(tr.getByText("✕ Deny")).toBeInTheDocument();
    expect(tr.getByText("cloud.instances.write")).toBeInTheDocument();
    expect(tr.getByText("instance:i-1")).toBeInTheDocument();
    expect(tr.getAllByRole("cell")[4]).toHaveTextContent("1");
  });

  it("filters by effect and state", async () => {
    w.policies.push(policy({ id: 31, name: "ok-all", effect: "allow", disabled: true }));
    renderIam("/iam/policies");
    await row("no-delete");
    fireEvent.change(screen.getByLabelText("Effect"), { target: { value: "allow" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(screen.queryByRole("cell", { name: /no-delete/ })).toBeNull());
    expect(screen.getByRole("cell", { name: /ok-all/ })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("State"), { target: { value: "false" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No policies match.")).toBeInTheDocument();
  });

  it("shows the 403 state", async () => {
    w.failures.push({ method: "GET", path: /^\/iam\/policies$/, status: 403, message: "missing permission: iam.policies.view" });
    renderIam("/iam/policies");
    expect(await screen.findByText(/don't have permission to view policies/i)).toBeInTheDocument();
  });

  it("hides write controls without iam.policies.write and shows the policy read-only", async () => {
    h.me = meWith(["iam.policies.view"]);
    renderIam("/iam/policies");
    await row("no-delete");
    for (const name of [/Create policy/, /^Attach/, /^Disable/, /^Delete/]) expect(screen.queryByRole("button", { name })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "View no-delete" }));
    const d = within(await screen.findByRole("dialog", { name: "Policy no-delete" }));
    expect(d.getByLabelText("Permissions")).toHaveAttribute("readonly");
    expect(d.queryByRole("button", { name: /Save/ })).toBeNull();
  });
});

describe("IAM policy form", () => {
  async function openCreate() {
    renderIam("/iam/policies");
    await row("no-delete");
    fireEvent.click(screen.getByRole("button", { name: "Create policy" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Create policy" }));
    await dialog.findByLabelText("Add a permission from the catalog");
    return dialog;
  }

  it("validates the name, permission patterns and resources inline", async () => {
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(d.getByLabelText("Resources"), { target: { value: "" } });
    fireEvent.click(d.getByRole("button", { name: "Create policy" }));
    expect(await d.findByText("Use 3 to 48 characters.")).toBeInTheDocument();
    expect(d.getByText("Enter at least one permission or pattern.")).toBeInTheDocument();
    expect(d.getByText(/Enter at least one resource pattern/)).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Permissions"), { target: { value: "Cloud.View" } });
    fireEvent.click(d.getByRole("button", { name: "Create policy" }));
    expect(await d.findByText(/is not valid: use lower-case/)).toBeInTheDocument();
    fireEvent.change(d.getByLabelText("Permissions"), { target: { value: "cloud.typo" } });
    fireEvent.click(d.getByRole("button", { name: "Create policy" }));
    expect(await d.findByText(/"cloud.typo" matches no permission in the catalog/)).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
  });

  it("accepts wildcard patterns that match the catalog", async () => {
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "no-cloud-writes" } });
    fireEvent.change(d.getByLabelText("Permissions"), { target: { value: "cloud.*, *.view" } });
    fireEvent.change(d.getByLabelText("Effect"), { target: { value: "deny" } });
    fireEvent.change(d.getByLabelText("Resources"), { target: { value: "instance:i-1\nprod-*" } });
    fireEvent.click(d.getByLabelText(/Disabled/));
    fireEvent.click(d.getByRole("button", { name: "Create policy" }));
    await waitFor(() => expect(calls(h.api, "POST", "/iam/policies")).toHaveLength(1));
    expect(calls(h.api, "POST")[0][1]).toMatchObject({
      json: { name: "no-cloud-writes", description: "", effect: "deny", permissions: ["cloud.*", "*.view"], resources: ["instance:i-1", "prod-*"], disabled: true },
    });
    expect(await screen.findByText("Created policy no-cloud-writes.")).toBeInTheDocument();
  });

  it("adds a pattern from the catalog dropdown", async () => {
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Add a permission from the catalog"), { target: { value: "iam.users.*" } });
    fireEvent.change(d.getByLabelText("Add a permission from the catalog"), { target: { value: "cloud.view" } });
    expect(d.getByLabelText("Permissions")).toHaveValue("iam.users.*\ncloud.view");
  });

  it("shows the backend's error and keeps the dialog", async () => {
    w.failures.push({ method: "POST", path: /^\/iam\/policies$/, status: 403, message: "you cannot grant permissions you do not hold: iam.users.delete" });
    const d = await openCreate();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "grant-all" } });
    fireEvent.change(d.getByLabelText("Effect"), { target: { value: "allow" } });
    fireEvent.change(d.getByLabelText("Permissions"), { target: { value: "iam.users.delete" } });
    fireEvent.click(d.getByRole("button", { name: "Create policy" }));
    expect(await d.findByText(/You don't have permission for that: you cannot grant permissions/)).toBeInTheDocument();
  });

  it("edits a policy and sends only the changes", async () => {
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Edit no-delete" }));
    const d = within(await screen.findByRole("dialog", { name: "Edit policy no-delete" }));
    expect(d.getByRole("button", { name: "Save changes" })).toBeDisabled();
    fireEvent.change(d.getByLabelText("Effect"), { target: { value: "allow" } });
    fireEvent.click(d.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect((calls(h.api, "PATCH", "/iam/policies/30")[0][1] as { json: object }).json).toEqual({ effect: "allow" }));
    expect(await screen.findByText("Saved policy no-delete.")).toBeInTheDocument();
  });
});

describe("IAM policy actions", () => {
  it("disables and enables a policy", async () => {
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Disable no-delete" }));
    await waitFor(() => expect(calls(h.api, "PATCH", "/iam/policies/30")[0][1]).toMatchObject({ json: { disabled: true } }));
    fireEvent.click(await screen.findByRole("button", { name: "Enable no-delete" }));
    await waitFor(() => expect(calls(h.api, "PATCH")[1][1]).toMatchObject({ json: { disabled: false } }));
  });

  it("shows a toast when the toggle is refused", async () => {
    w.failures.push({ method: "PATCH", path: /policies\/30$/, status: 403, message: "you cannot lift restrictions on permissions you do not hold" });
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Disable no-delete" }));
    expect(await screen.findByText(/You don't have permission for that: you cannot lift restrictions/)).toBeInTheDocument();
  });

  it("attaches a policy to users, groups and roles", async () => {
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Attach no-delete" }));
    const d = within(await screen.findByRole("dialog", { name: "Attach no-delete" }));
    fireEvent.click(await d.findByRole("checkbox", { name: "alice" }));
    fireEvent.click(await d.findByRole("checkbox", { name: "ops" }));
    fireEvent.click(await d.findByRole("checkbox", { name: "viewer" }));
    fireEvent.click(d.getByRole("button", { name: "Save attachments" }));
    await waitFor(() => expect(calls(h.api, "PUT", "/iam/policies/30/attachments")).toHaveLength(1));
    expect((calls(h.api, "PUT")[0][1] as { json: { attachments: unknown[] } }).json.attachments).toEqual([
      { subject_type: "user", subject_id: 2 }, { subject_type: "group", subject_id: 20 }, { subject_type: "role", subject_id: 10 },
    ]);
    expect(await screen.findByText("Updated attachments of no-delete.")).toBeInTheDocument();
  });

  it("keeps attachments of a kind you cannot list, since the API replaces the whole list", async () => {
    w.policies[0] = policy({ attachments: [{ subject_type: "user", subject_id: 2, subject_name: "alice" }] });
    h.me = meWith(["iam.policies.view", "iam.policies.write", "iam.roles.view", "iam.groups.view"]);
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Attach no-delete" }));
    const d = within(await screen.findByRole("dialog"));
    expect(await d.findByText(/You cannot view users; their attachments are kept/)).toBeInTheDocument();
    fireEvent.click(await d.findByRole("checkbox", { name: "viewer" }));
    fireEvent.click(d.getByRole("button", { name: "Save attachments" }));
    await waitFor(() => expect(calls(h.api, "PUT")).toHaveLength(1));
    expect((calls(h.api, "PUT")[0][1] as { json: { attachments: unknown[] } }).json.attachments).toEqual([
      { subject_type: "user", subject_id: 2 }, { subject_type: "role", subject_id: 10 },
    ]);
  });

  it("shows the server's error when attaching to yourself", async () => {
    w.failures.push({ method: "PUT", path: /attachments$/, status: 403, message: "you cannot change the policies attached to yourself" });
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Attach no-delete" }));
    const d = within(await screen.findByRole("dialog"));
    fireEvent.click(await d.findByRole("checkbox", { name: "root" }));
    fireEvent.click(d.getByRole("button", { name: "Save attachments" }));
    expect(await d.findByText(/attached to yourself/)).toBeInTheDocument();
  });

  it("confirms and deletes", async () => {
    renderIam("/iam/policies");
    fireEvent.click(await screen.findByRole("button", { name: "Delete no-delete" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete policy no-delete?" });
    expect(within(dialog).getByText(/deny policy: what it blocked is allowed again/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete policy" }));
    await waitFor(() => expect(calls(h.api, "DELETE", "/iam/policies/30")).toHaveLength(1));
    expect(await screen.findByText("No policies match.")).toBeInTheDocument();
  });
});
