import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ApiError } from "../api/client";
import { ALL_PERMS, MOCK, calls, cloudApiFake, freshDb, renderCloud, type Db } from "./cloud-fixtures";

const h = vi.hoisted(() => ({ api: vi.fn(), perms: undefined as string[] | undefined }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({
    me: { id: 1, username: "u", role: "admin", permissions: h.perms }, loading: false, logout: vi.fn(),
    can: (p: string) => Boolean(h.perms?.includes(p)),
  }),
}));

let db: Db;
beforeEach(() => {
  db = freshDb();
  h.perms = ALL_PERMS;
  h.api.mockReset();
  h.api.mockImplementation(cloudApiFake(db));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const row = (name: string) => screen.getByRole("link", { name }).closest("tr")!;

describe("cloud compute list", () => {
  it("lists instances with text status pills and filters by state, zone and type through the API", async () => {
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    expect(within(row("web-1")).getByText("running")).toBeInTheDocument();
    expect(within(row("db-1")).getByText("stopped")).toBeInTheDocument();
    expect(within(row("old-1")).getByText("terminated")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("State"), { target: { value: "stopped" } });
    await waitFor(() => expect(screen.queryByRole("link", { name: "web-1" })).not.toBeInTheDocument());
    expect(screen.getByRole("link", { name: "db-1" })).toBeInTheDocument();
    expect(calls(h.api, "GET", "/cloud/instances?").some(([p]) => String(p).includes("state=stopped"))).toBe(true);

    fireEvent.change(screen.getByLabelText("State"), { target: { value: "" } });
    await screen.findByRole("link", { name: "web-1" });
    await waitFor(() => expect(screen.getByLabelText("Availability zone")).toHaveTextContent("eu-west-1b"));
    fireEvent.change(screen.getByLabelText("Availability zone"), { target: { value: "eu-west-1b" } });
    await waitFor(() => expect(screen.queryByRole("link", { name: "web-1" })).not.toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Availability zone"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "t3.small" } });
    await waitFor(() => expect(screen.queryByRole("link", { name: "db-1" })).not.toBeInTheDocument());
    expect(screen.getByRole("link", { name: "web-1" })).toBeInTheDocument();
  });

  it("searches by name, sorts by a column header and pages", async () => {
    for (let n = 0; n < 12; n++) db.instances.push({ ...db.instances[0], id: `i-x${n}`, name: `bulk-${String(n).padStart(2, "0")}` });
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    expect(screen.getByText("1–10 of 15 instances")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("11–15 of 15 instances");
    expect(calls(h.api, "GET", "/cloud/instances?").some(([p]) => String(p).includes("offset=10"))).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: /^Type/ }));
    await waitFor(() => expect(calls(h.api, "GET", "/cloud/instances?").some(([p]) => String(p).includes("sort=instance_type") && String(p).includes("offset=0"))).toBe(true));
    expect(screen.getByRole("columnheader", { name: /^Type/ })).toHaveAttribute("aria-sort", "ascending");
    fireEvent.click(screen.getByRole("button", { name: /^Type/ }));
    await waitFor(() => expect(screen.getByRole("columnheader", { name: /^Type/ })).toHaveAttribute("aria-sort", "descending"));

    fireEvent.change(screen.getByLabelText("Search by name"), { target: { value: "db-" } });
    await waitFor(() => expect(screen.getAllByRole("link").filter((a) => /^(db|bulk|web|old)-/.test(a.textContent ?? "")).map((a) => a.textContent)).toEqual(["db-1"]));
    expect(screen.getByText("1–1 of 1 instances")).toBeInTheDocument();
  });

  it("validates the create form inline, then creates the instance and toasts", async () => {
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Create instance" }));
    const dialog = await screen.findByRole("dialog", { name: "Create instance" });
    await within(dialog).findByRole("option", { name: /pub-a/ });

    fireEvent.click(within(dialog).getByRole("button", { name: "Create instance" }));
    expect(within(dialog).getByText(/Enter a name/)).toBeInTheDocument();
    expect(within(dialog).getByText("Choose a subnet.")).toBeInTheDocument();
    expect(within(dialog).getByText("Choose at least one security group.")).toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);

    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "-bad name" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create instance" }));
    expect(within(dialog).getByText(/Start with a letter or digit/)).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText(/^Disk/), { target: { value: "4" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create instance" }));
    expect(within(dialog).getByText("Between 8 and 1000.")).toBeInTheDocument();

    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "api-1" } });
    fireEvent.change(within(dialog).getByLabelText(/^Disk/), { target: { value: "30" } });
    fireEvent.change(within(dialog).getByLabelText(/^Subnet/), { target: { value: "subnet-1" } });
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /web/ }));
    fireEvent.change(within(dialog).getByLabelText(/Tags/), { target: { value: "team=blue" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create instance" }));

    await waitFor(() => expect(calls(h.api, "POST", "/cloud/instances")).toHaveLength(1));
    expect(calls(h.api, "POST", "/cloud/instances")[0][1]).toMatchObject({
      json: { name: "api-1", instance_type: "t3.micro", subnet_id: "subnet-1", security_group_ids: ["sg-1"], az: "eu-west-1a", os: "Ubuntu 22.04", disk_gb: 30, tags: { team: "blue" } },
    });
    expect(await screen.findByText("Instance api-1 (i-new00001) created; it starts as pending.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("shows the backend's refusal inside the create form", async () => {
    db.override["POST /cloud/instances"] = () => { throw new ApiError(422, "a security group belongs to another VPC than the subnet"); };
    renderCloud("/cloud/compute");
    await screen.findByRole("link", { name: "web-1" });
    fireEvent.click(screen.getByRole("button", { name: "Create instance" }));
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByRole("option", { name: /pub-a/ });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "x1" } });
    fireEvent.change(within(dialog).getByLabelText(/^Subnet/), { target: { value: "subnet-1" } });
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /web/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Create instance" }));
    expect(await within(dialog).findByText("a security group belongs to another VPC than the subnet")).toBeInTheDocument();
  });
});

describe("cloud instance detail", () => {
  const open = async (id = "i-aaaa1111") => {
    renderCloud(`/cloud/compute/${id}`);
    await screen.findByRole("heading", { level: 1 });
    await screen.findByText(/Mock metrics: not measured/);
  };

  it("stops a running instance after a confirmation", async () => {
    await open();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("web-1");
    fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    const dialog = await screen.findByRole("dialog", { name: "Stop this instance?" });
    expect(calls(h.api, "POST", "/cloud/instances/i-aaaa1111/stop")).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Stop" }));
    await waitFor(() => expect(calls(h.api, "POST", "/cloud/instances/i-aaaa1111/stop")).toHaveLength(1));
    expect(await screen.findByText("Instance web-1 was stopped.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("stopped"));
  });

  it("starts a stopped instance (pending afterwards)", async () => {
    await open("i-bbbb2222");
    fireEvent.click(screen.getByRole("button", { name: "Start" }));
    const dialog = await screen.findByRole("dialog", { name: "Start this instance?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Start" }));
    expect(await screen.findByText("Instance db-1 is starting.")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("pending"));
  });

  it("shows the backend's 409 state-machine error in the dialog and keeps it open", async () => {
    await open("i-bbbb2222");
    fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Stop" }));
    expect(await within(dialog).findByText("cannot stop an instance that is stopped (allowed from: running)")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("terminates with a warning, and shows the 409 for an already terminated instance", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Terminate" }));
    const dialog = await screen.findByRole("dialog", { name: "Terminate this instance?" });
    expect(within(dialog).getByText(/permanent/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Terminate" }));
    expect(await screen.findByText("Instance web-1 was terminated.")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("terminated"));

    fireEvent.click(screen.getByRole("button", { name: "Terminate" }));
    const again = await screen.findByRole("dialog");
    fireEvent.click(within(again).getByRole("button", { name: "Terminate" }));
    expect(await within(again).findByText(/cannot terminate an instance that is terminated/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit name and tags" })).toBeDisabled();
  });

  it("closes the dialog with Escape and never sends the call", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Reboot" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(calls(h.api, "POST")).toHaveLength(0);
  });

  it("edits name and tags", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Edit name and tags" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "web 1" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    expect(within(dialog).getByText(/Start with a letter or digit/)).toBeInTheDocument();
    db.override["PATCH /cloud/instances/i-aaaa1111"] = (_p, init) => ({ ...MOCK, ...db.instances[0], ...init.json });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "web-2" } });
    fireEvent.change(within(dialog).getByLabelText(/Tags/), { target: { value: "env=prod\nowner=ann" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls(h.api, "PATCH")).toHaveLength(1));
    expect(calls(h.api, "PATCH")[0][1]).toMatchObject({ json: { name: "web-2", tags: { env: "prod", owner: "ann" } } });
    expect(await screen.findByText("Instance i-aaaa1111 updated.")).toBeInTheDocument();
  });

  it("switches the metrics range and gives each chart a text alternative and a tooltip", async () => {
    await open();
    expect(calls(h.api, "GET", "/cloud/instances/i-aaaa1111/metrics?range=1h")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "24 hours" }));
    await waitFor(() => expect(calls(h.api, "GET", "/cloud/instances/i-aaaa1111/metrics?range=24h")).toHaveLength(1));
    expect(screen.getByRole("button", { name: "24 hours" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByRole("button", { name: "7 days" }));
    await waitFor(() => expect(calls(h.api, "GET", "/cloud/instances/i-aaaa1111/metrics?range=7d")).toHaveLength(1));

    for (const title of ["CPU utilisation", "Memory utilisation", "Disk utilisation", "Network throughput"]) {
      const fig = screen.getByText(title, { selector: "figcaption" }).closest("figure")!;
      expect(within(fig).getByText(/latest .*min .*average .*max/)).toBeInTheDocument();
      expect(within(fig).getByText("Show data table")).toBeInTheDocument();
      expect(within(fig).getByRole("list", { name: "Legend" })).toBeInTheDocument();
    }
    const cpu = screen.getByText("CPU utilisation", { selector: "figcaption" }).closest("figure")!;
    const plot = within(cpu).getByRole("group", { name: /CPU utilisation/ });
    expect(within(cpu).queryByTestId("chart-tooltip")).not.toBeInTheDocument();
    fireEvent.keyDown(plot, { key: "ArrowRight" });
    expect(within(cpu).getByTestId("chart-tooltip")).toHaveTextContent(/CPU: no data/);
    fireEvent.keyDown(plot, { key: "ArrowRight" });
    expect(within(cpu).getByTestId("chart-tooltip")).toHaveTextContent(/CPU: 21\.0%/);
    fireEvent.keyDown(plot, { key: "Escape" });
    expect(within(cpu).queryByTestId("chart-tooltip")).not.toBeInTheDocument();
    fireEvent.click(within(cpu).getByRole("button", { name: "CPU" }));
    expect(within(cpu).getByRole("button", { name: "CPU" })).toHaveAttribute("aria-pressed", "false");
  });
});
