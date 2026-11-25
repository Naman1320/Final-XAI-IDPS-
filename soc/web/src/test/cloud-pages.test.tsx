import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
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

const costCalls = () => calls(h.api, "GET", "/cloud/cost").map(([p]) => String(p));

describe("cloud cost", () => {
  it("switches the range through the API and shows total, forecast, services, days and drivers", async () => {
    renderCloud("/cloud/cost");
    await screen.findByText("Cost by service", { selector: "h2" });
    expect(costCalls()).toEqual(["/cloud/cost?range=30d"]);
    expect(screen.getByRole("button", { name: "30 days" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("\$300.00")).toBeInTheDocument(); // 30 days x 10
    expect(screen.getByText("\$220.50")).toBeInTheDocument(); // forecast
    expect(screen.getByText("Estimated cost by instance", { selector: "figcaption" })).toBeInTheDocument();
    expect(screen.getAllByText("web-1").length).toBeGreaterThan(0);
    expect(screen.getByText("Mock cost: estimate, not a bill.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "7 days" }));
    await waitFor(() => expect(costCalls()).toContain("/cloud/cost?range=7d"));
    expect(await screen.findByText("\$70.00")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "90 days" }));
    await waitFor(() => expect(costCalls()).toContain("/cloud/cost?range=90d"));
    expect(await screen.findByText("\$900.00")).toBeInTheDocument();
  });

  it("gives the day chart a legend, a tooltip and a data table", async () => {
    renderCloud("/cloud/cost?x=1");
    const fig = (await screen.findByText(/Daily cost by service/, { selector: "figcaption" })).closest("figure")!;
    const legend = within(fig).getByRole("list", { name: "Legend" });
    expect(within(legend).getAllByRole("listitem").map((l) => l.textContent)).toEqual(["compute", "storage", "network", "other"]);
    fireEvent.keyDown(within(fig).getByRole("group", { name: /Daily cost/ }), { key: "ArrowRight" });
    expect(within(fig).getByTestId("chart-tooltip")).toHaveTextContent(/compute: \$6\.00/);
    expect(within(fig).getByTestId("chart-tooltip")).toHaveTextContent(/total: \$10\.00/);
    expect(within(fig).getByText("Show data table")).toBeInTheDocument();
    expect(within(fig).getByRole("table")).toBeInTheDocument();
  });
});

describe("cloud alerts", () => {
  it("filters, acknowledges and resolves", async () => {
    renderCloud("/cloud/alerts");
    const crit = (await screen.findByText("Security group web opens SSH to the world")).closest("tr")!;
    expect(within(crit).getByText("critical")).toBeInTheDocument();
    expect(within(crit).getByText("open")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "acknowledged" } });
    await waitFor(() => expect(screen.queryByText("Security group web opens SSH to the world")).not.toBeInTheDocument());
    expect(screen.getByText("CPU utilisation is high on web-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "" } });
    await screen.findByText("Security group web opens SSH to the world");
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "critical" } });
    await waitFor(() => expect(screen.queryByText("CPU utilisation is high on web-1")).not.toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "" } });

    const open = (await screen.findByText("Security group web opens SSH to the world")).closest("tr")!;
    fireEvent.click(within(open).getByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByText("Alert 1 acknowledged.")).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByText("Security group web opens SSH to the world").closest("tr")!).getByText("acknowledged")).toBeInTheDocument());

    fireEvent.click(within(screen.getByText("Security group web opens SSH to the world").closest("tr")!).getByRole("button", { name: "Resolve" }));
    expect(await screen.findByText("Alert 1 resolved.")).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByText("Security group web opens SSH to the world").closest("tr")!).getByText("resolved")).toBeInTheDocument());
    expect(calls(h.api, "POST", "/cloud/alerts/1/acknowledge")).toHaveLength(1);
    expect(calls(h.api, "POST", "/cloud/alerts/1/resolve")).toHaveLength(1);
  });

  it("shows the backend's 409 when acknowledging an alert that is not open", async () => {
    renderCloud("/cloud/alerts");
    const ack = (await screen.findByText("CPU utilisation is high on web-1")).closest("tr")!;
    fireEvent.click(within(ack).getByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByText("cannot acknowledge an alert that is acknowledged")).toBeInTheDocument();
  });

  it("runs the evaluation and reports the result", async () => {
    renderCloud("/cloud/alerts");
    await screen.findByText("CPU utilisation is high on web-1");
    fireEvent.click(screen.getByRole("button", { name: "Run evaluation" }));
    expect(await screen.findByText("Evaluation done: 3 findings, 2 new alerts, 0 escalated, 1 already open.")).toBeInTheDocument();
    expect(calls(h.api, "POST", "/cloud/alerts/evaluate")).toHaveLength(1);
  });

  it("deletes an alert only after a confirmation", async () => {
    renderCloud("/cloud/alerts");
    const row = (await screen.findByText("CPU utilisation is high on web-1")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete this alert?" });
    expect(calls(h.api, "DELETE")).toHaveLength(0);
    db.override["DELETE /cloud/alerts/2"] = () => ({ ...MOCK, ...db.alerts[1] });
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete alert" }));
    await waitFor(() => expect(calls(h.api, "DELETE", "/cloud/alerts/2")).toHaveLength(1));
    expect(await screen.findByText("Alert 2 deleted.")).toBeInTheDocument();
  });
});

describe("cloud activity and monitoring", () => {
  it("filters the activity feed and renders details as plain text", async () => {
    renderCloud("/cloud/activity");
    await screen.findByText("instance.stop");
    expect(screen.getByText("from: running")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Actor"), { target: { value: "system" } });
    await waitFor(() => expect(screen.queryByText("instance.stop")).not.toBeInTheDocument());
    expect(screen.getByText("alert.create")).toBeInTheDocument();
    expect(calls(h.api, "GET", "/cloud/activity?").some(([p]) => String(p).includes("actor=system"))).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await screen.findByText("instance.stop");
  });

  it("never renders API text as HTML", async () => {
    db.alerts[0].message = "<img src=x onerror=alert(1)> <b>bold</b>";
    renderCloud("/cloud/alerts");
    expect(await screen.findByText("<img src=x onerror=alert(1)> <b>bold</b>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("shows fleet metrics with thresholds and per-instance health", async () => {
    renderCloud("/cloud/monitoring");
    const table = await screen.findByRole("table", { name: /Health of each instance/ });
    const web = within(table).getByRole("link", { name: "web-1" }).closest("tr")!;
    expect(within(web).getByText(/35\.0%/)).toBeInTheDocument();
    expect(within(web).getAllByText(/warn 80, critical 95/).length).toBe(1);
    expect(within(table).getAllByText(/stopped: nothing to measure/)).toHaveLength(3);
    expect(within(table).queryByText("old-1")).not.toBeInTheDocument();
    const cpu = await screen.findByRole("meter", { name: "CPU (average)" });
    expect(cpu).toHaveAttribute("aria-valuetext", expect.stringContaining("Normal"));
    expect(screen.getByText("Fleet average CPU, last 24 hours", { selector: "figcaption" })).toBeInTheDocument();
    expect(screen.getByText("Busiest instances by CPU", { selector: "figcaption" })).toBeInTheDocument();
  });
});
