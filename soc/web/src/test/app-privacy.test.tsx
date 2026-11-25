import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "../App";
import Login from "../pages/Login";

const auth = vi.hoisted(() => ({ me: null as null | { username: string; role: string } }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: auth.me, loading: false, logout: vi.fn(), login: vi.fn(), finish: vi.fn(), can: () => false }),
}));
vi.mock("../api/client", async (orig) => ({
  ...(await orig<typeof import("../api/client")>()),
  api: vi.fn(async (path: string) => {
    if (path === "/privacy/notice") return {
      controller: { name: "Acme Ltd", contact_email: null, grievance_officer: null }, data_categories: [], purposes: [],
      rights: [], retention: {}, recipients: [], how_to_exercise: "", note: "" };
    if (path === "/auth/oidc/config") return { enabled: false, label: null };
    if (path === "/reports/weeks") return { default_week: "", email_enabled: false, email_configured: false, weeks: [] };
    return null;
  }),
}));
vi.mock("../live", () => ({ useLiveStatus: () => false, useLiveAlerts: () => false, useLiveBlocks: () => false }));
vi.mock("../sensors", async (orig) => ({ ...(await orig<typeof import("../sensors")>()), useSensors: () => ({ data: null, error: null }) }));
vi.mock("../pages/ThreatCenter", () => ({ default: () => <div>threat-center-stub</div> }));

const go = (url: string) => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>);
beforeEach(() => { auth.me = null; });
afterEach(cleanup);

describe("signed-out routing", () => {
  it("/privacy shows the notice, not Login", async () => {
    go("/privacy");
    expect(await screen.findByText("Acme Ltd")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).toBeNull();
    expect(screen.getByRole("link", { name: "Sign in" })).toBeInTheDocument();
  });
  it.each(["/", "/reports", "/alerts"])("%s shows Login", async (p) => {
    go(p);
    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
    expect(screen.queryByText("Privacy notice", { selector: ".card-title, h2" })).toBeNull();
  });
});

describe("Login footer", () => {
  it("links to /privacy", () => {
    render(<MemoryRouter><Login /></MemoryRouter>);
    expect(screen.getByRole("link", { name: "Privacy notice" })).toHaveAttribute("href", "/privacy");
  });
});

describe("signed-in nav", () => {
  it.each(["analyst", "admin"])("%s sees Reports and Privacy and the routes work", async (role) => {
    auth.me = { username: "ann", role };
    go("/reports");
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(nav).toHaveTextContent("Reports");
    expect(nav.querySelector('a[href="/privacy"]')).toHaveTextContent("Privacy");
    expect(await screen.findByText("Weekly report")).toBeInTheDocument();
  });
  it("/privacy renders the notice when signed in", async () => {
    auth.me = { username: "ann", role: "analyst" };
    go("/privacy");
    expect(await screen.findByText("Acme Ltd")).toBeInTheDocument();
  });
});
