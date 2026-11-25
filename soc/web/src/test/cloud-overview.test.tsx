import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, within } from "@testing-library/react";
import { ApiError } from "../api/client";
import { ALL_PERMS, MOCK, cloudApiFake, freshDb, renderCloud, type Db } from "./cloud-fixtures";

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

describe("cloud overview", () => {
  it("shows the mock banner from the API label, the summary cards, gauges, health, cost and activity", async () => {
    renderCloud("/cloud");
    const banner = await screen.findByText(MOCK.data_source_label);
    expect(banner.closest(".cl-banner")).toHaveAttribute("data-source", "mock");
    expect(screen.getByText(/nothing in a real cloud is touched/)).toBeInTheDocument();

    const summary = await screen.findByLabelText("Infrastructure summary");
    expect(within(summary).getByRole("heading", { name: "Instances" })).toBeInTheDocument();
    expect(within(summary).getByRole("heading", { name: "Volumes" })).toBeInTheDocument();
    expect(within(summary).getByRole("heading", { name: "Buckets" })).toBeInTheDocument();
    expect(within(summary).getByRole("heading", { name: "VPCs" })).toBeInTheDocument();
    expect(within(summary).getByText("150 GB, 1 in use")).toBeInTheDocument();
    expect(within(summary).getByText(/running/)).toBeInTheDocument();

    const cpu = await screen.findByRole("meter", { name: "CPU (fleet average)" });
    expect(cpu).toHaveAttribute("aria-valuenow", "35.2");
    expect(screen.getByRole("meter", { name: "Memory (fleet average)" })).toHaveAttribute("aria-valuenow", "40.1");
    expect(screen.getByRole("meter", { name: "Storage used" })).toHaveAttribute("aria-valuenow", "30");

    const health = screen.getByRole("list", { name: "Instances by health" });
    expect(within(health).getByText("healthy")).toBeInTheDocument();
    expect(within(health).getByText("unknown")).toBeInTheDocument();

    expect(screen.getByText("$123.45")).toBeInTheDocument();
    expect(screen.getByText(/down 38.3%/)).toBeInTheDocument();
    expect(await screen.findByText("Security group web opens SSH to the world")).toBeInTheDocument();
    expect(await screen.findByText("instance.stop")).toBeInTheDocument();
  });

  it("uses a different label when the API says emulated-aws", async () => {
    db.source = { data_source: "emulated-aws", data_source_label: "Emulated AWS (local Moto, read-only)" };
    renderCloud("/cloud");
    const banner = (await screen.findByText("Emulated AWS (local Moto, read-only)")).closest(".cl-banner")!;
    expect(banner).toHaveAttribute("data-source", "emulated-aws");
    expect(screen.queryByText(MOCK.data_source_label)).not.toBeInTheDocument();
    expect(await screen.findByText("This data source has no cost data.")).toBeInTheDocument();
  });

  it("keeps the banner while moving between sections", async () => {
    renderCloud("/cloud");
    await screen.findByText(MOCK.data_source_label);
    fireEvent.click(screen.getByRole("link", { name: "Compute" }));
    await screen.findByRole("heading", { name: "Compute" });
    expect(screen.getByText(MOCK.data_source_label)).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Cloud sections" });
    expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual(
      ["Overview", "Compute", "Storage", "Network", "Monitoring", "Cost", "Alerts", "Activity"]);
  });

  it("shows a clear no-permission state on a 403 and an error with retry otherwise", async () => {
    h.api.mockImplementation(async () => { throw new ApiError(403, "missing permission cloud.view"); });
    renderCloud("/cloud");
    expect((await screen.findAllByText("No permission")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("missing permission cloud.view").length).toBeGreaterThan(0);
    cleanup();
    h.api.mockImplementation(async () => { throw new ApiError(503, "endpoint refused"); });
    renderCloud("/cloud");
    expect((await screen.findAllByText(/cloud data source is unavailable: endpoint refused/)).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Retry" }).length).toBeGreaterThan(0);
  });
});
