import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ApiError } from "../api/client";
import Reports, { isoWeek } from "../pages/Reports";

const h = vi.hoisted(() => ({ api: vi.fn(), download: vi.fn(), role: "admin" }));
vi.mock("../api/client", async (orig) => ({
  ...(await orig<typeof import("../api/client")>()), api: h.api, download: h.download,
}));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: { id: 1, username: "u", role: h.role }, loading: false, logout: vi.fn() }),
}));

const week = (w: string, o: Record<string, unknown> = {}) => ({
  week: w, start: "2026-11-09T00:00:00Z", end: "2026-11-16T00:00:00Z", alerts: 1234, run: false,
  emailed: false, emailed_at: null, recipients_count: 0, error: null, ...o,
});
let weeks: Record<string, unknown>;
let confirm: ReturnType<typeof vi.spyOn>;
let emailImpl: () => Promise<unknown>;

beforeEach(() => {
  h.role = "admin";
  weeks = { default_week: "2026-W46", email_enabled: true, email_configured: true,
    weeks: [week("2026-W46"), week("2026-W45", { emailed: true, recipients_count: 3, emailed_at: "2026-11-10T08:00:00Z" }),
      week("2026-W44", { error: "smtp down" })] };
  emailImpl = async () => ({ week: "2026-W45", recipients: 3, emailed_at: "x", size_bytes: 20480 });
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string }) => {
    if (path === "/reports/weeks") return weeks;
    if (opts?.method === "POST") return emailImpl();
    throw new Error(`unexpected ${path}`);
  });
  h.download.mockReset();
  h.download.mockResolvedValue(undefined);
  confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const posts = () => h.api.mock.calls.filter(([, o]) => o?.method === "POST");

describe("Reports page", () => {
  it("lists weeks with the latest marker, counts and email state", async () => {
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W46");
    expect(screen.getAllByText(/· latest/)).toHaveLength(1);
    expect(screen.getByText("2026-W46").parentElement).toHaveTextContent("latest");
    expect(screen.getByText("2026-W45").parentElement).not.toHaveTextContent("latest");
    expect(screen.getAllByText("1,234")).toHaveLength(3);
    expect(screen.getByText("sent to 3")).toBeInTheDocument();
    expect(screen.getByText("failed: smtp down")).toBeInTheDocument();
    expect(screen.getByText("emailed every week")).toBeInTheDocument();
  });

  it("shows 'email off' when email is not enabled", async () => {
    weeks.email_enabled = false;
    render(<MemoryRouter><Reports /></MemoryRouter>);
    expect(await screen.findByText("email off")).toBeInTheDocument();
  });

  it("Download PDF calls download with the week path and filename", async () => {
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    fireEvent.click(screen.getByRole("button", { name: "Download PDF, week 2026-W45" }));
    await waitFor(() => expect(h.download).toHaveBeenCalledTimes(1));
    expect(h.download).toHaveBeenCalledWith("/reports/weekly?week=2026-W45", "idps-weekly-2026-W45.pdf");
  });

  it("'This week so far' downloads the current ISO week", async () => {
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    fireEvent.click(screen.getByRole("button", { name: "This week so far (PDF)" }));
    const w = isoWeek(new Date());
    await waitFor(() => expect(h.download).toHaveBeenCalledWith(`/reports/weekly?week=${w}`, `idps-weekly-${w}.pdf`));
  });

  it("shows a download error", async () => {
    h.download.mockRejectedValue(new ApiError(404, "No data for that week"));
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    fireEvent.click(screen.getByRole("button", { name: "Download PDF, week 2026-W45" }));
    expect(await screen.findByText("No data for that week")).toBeInTheDocument();
  });

  it("admin sees Email buttons when configured; cancelled confirm sends nothing", async () => {
    confirm.mockReturnValue(false);
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    expect(screen.getAllByRole("button", { name: /^Email the report for/ })).toHaveLength(3);
    fireEvent.click(screen.getByRole("button", { name: "Email the report for 2026-W45" }));
    expect(confirm).toHaveBeenCalled();
    expect(posts()).toHaveLength(0);
  });

  it("accepted confirm posts and shows the recipients notice", async () => {
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    fireEvent.click(screen.getByRole("button", { name: "Email the report for 2026-W45" }));
    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(posts()[0]).toEqual(["/admin/reports/weekly/email?week=2026-W45", { method: "POST" }]);
    expect(await screen.findByText("Report for 2026-W45 emailed to 3 recipients (20 KB).")).toBeInTheDocument();
  });

  it("singular recipient", async () => {
    emailImpl = async () => ({ week: "2026-W46", recipients: 1, emailed_at: "x", size_bytes: 1024 });
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W46");
    fireEvent.click(screen.getByRole("button", { name: "Email the report for 2026-W46" }));
    expect(await screen.findByText("Report for 2026-W46 emailed to 1 recipient (1 KB).")).toBeInTheDocument();
  });

  it("maps a 409 to a friendly message", async () => {
    emailImpl = async () => { throw new ApiError(409, "smtp_not_configured"); };
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    fireEvent.click(screen.getByRole("button", { name: "Email the report for 2026-W45" }));
    expect(await screen.findByText("Email is not configured in the SOC.")).toBeInTheDocument();
  });

  it("admin without email_configured sees no Email button but a hint", async () => {
    weeks.email_configured = false;
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    expect(screen.queryByRole("button", { name: /^Email the report/ })).toBeNull();
    expect(screen.getByText(/Emailing needs the SOC's email settings/)).toBeInTheDocument();
  });

  it("analysts never see Email", async () => {
    h.role = "analyst";
    render(<MemoryRouter><Reports /></MemoryRouter>);
    await screen.findByText("2026-W45");
    expect(screen.queryByRole("button", { name: /^Email the report/ })).toBeNull();
    expect(screen.queryByText(/Emailing needs/)).toBeNull();
    expect(screen.getAllByRole("button", { name: /^Download PDF, week/ })).toHaveLength(3);
  });
});
