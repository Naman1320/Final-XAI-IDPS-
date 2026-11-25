import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Admin from "../pages/Admin";

const h = vi.hoisted(() => ({ api: vi.fn() }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: { id: 1, username: "root", role: "admin" }, loading: false, logout: vi.fn() }),
}));

const u = (o: Record<string, unknown>) => ({ id: 2, username: "alice", role: "analyst", disabled: false, created_at: "2026-01-05T10:00:00Z", ...o });
let users: Record<string, unknown>[];
let confirm: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  users = [
    u({ id: 1, username: "root", role: "admin", mfa_enabled: true }),
    u({ id: 2, username: "alice", mfa_enabled: true, sso_linked: true }),
    u({ id: 3, username: "bob" }),
    u({ id: 4, username: "adm2", role: "admin", mfa_enabled: false }),
  ];
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string }) => {
    const m = opts?.method ?? "GET";
    if (m === "GET" && path === "/admin/users") return users;
    if (m === "GET" && path === "/admin/sensors") return [];
    if (m === "GET" && path === "/sensors/status") return { sensors: [], summary: {}, generated_at: "2026-01-01T00:00:00Z" };
    if (m === "GET" && path === "/models") return { models: [] };
    if (m === "GET" && path === "/admin/integrations") return { channels: [], abuseipdb: { configured: false, cache_hours: 24 } };
    if (m === "GET" && path.startsWith("/admin/audit")) return { items: [], total: 0, next_cursor: null };
    if (m === "POST" && path === "/admin/users/2/mfa/reset") return u({ id: 2, username: "alice" });
    throw new Error(`unexpected ${m} ${path}`);
  });
  confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const row = (name: string) => screen.getByText(name, { selector: "b" }).closest("tr")!;
const resets = () => h.api.mock.calls.filter(([p]) => String(p).includes("/mfa/reset"));
const pill = (tr: HTMLElement, text: string) => Array.from(tr.querySelectorAll(".pill")).find((e) => e.textContent === text);

describe("Admin users 2FA", () => {
  it("shows 2FA pill states and the SSO pill", async () => {
    render(<Admin />);
    await screen.findByText("alice", { selector: "b" });
    expect(pill(row("root"), "2FA on")).toHaveClass("ok");
    expect(pill(row("alice"), "2FA on")).toBeTruthy();
    expect(pill(row("alice"), "SSO")).toBeTruthy();
    expect(pill(row("bob"), "2FA off")).toHaveClass("neutral");
    expect(pill(row("bob"), "SSO")).toBeUndefined();
    expect(pill(row("adm2"), "2FA off")).toHaveClass("warn");
  });

  it("Reset 2FA only for other users with 2FA on", async () => {
    render(<Admin />);
    await screen.findByText("alice", { selector: "b" });
    expect(screen.getAllByRole("button", { name: /Reset two-factor sign-in/ })).toHaveLength(1);
    expect(row("alice").textContent).toContain("Reset 2FA");
    expect(row("root").textContent).not.toContain("Reset 2FA");
    expect(row("bob").textContent).not.toContain("Reset 2FA");
    expect(row("adm2").textContent).not.toContain("Reset 2FA");
  });

  it("does nothing when the confirmation is cancelled", async () => {
    confirm.mockReturnValue(false);
    render(<Admin />);
    await screen.findByText("alice", { selector: "b" });
    fireEvent.click(screen.getByRole("button", { name: "Reset two-factor sign-in of alice" }));
    expect(confirm).toHaveBeenCalled();
    expect(resets()).toHaveLength(0);
  });

  it("posts the reset and shows a notice when confirmed", async () => {
    render(<Admin />);
    await screen.findByText("alice", { selector: "b" });
    fireEvent.click(screen.getByRole("button", { name: "Reset two-factor sign-in of alice" }));
    await waitFor(() => expect(resets()).toHaveLength(1));
    expect(resets()[0]).toEqual(["/admin/users/2/mfa/reset", { method: "POST" }]);
    expect(await screen.findByText("Two-factor sign-in reset for alice.")).toBeInTheDocument();
  });
});
