import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Account from "../pages/Account";

const h = vi.hoisted(() => ({ api: vi.fn(), refresh: vi.fn(), me: {} as Record<string, unknown> }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../auth", () => ({ useAuth: () => ({ me: h.me, refresh: h.refresh, loading: false, logout: vi.fn() }) }));

const codes = ["AAAAA-00001", "AAAAA-00002"];
const calls = (p: string) => h.api.mock.calls.filter(([path]) => path === p);

beforeEach(() => {
  h.me = { id: 1, username: "alice", role: "analyst", mfa_enabled: false, mfa_required: false };
  h.refresh.mockReset().mockResolvedValue(undefined);
  h.api.mockReset();
  h.api.mockImplementation(async (path: string) => {
    if (path === "/auth/mfa/enrol/start") return { secret: "S", otpauth_uri: "otpauth://x", qr_svg: "<svg/>", issuer: "IDPS" };
    if (path === "/auth/mfa/enrol/confirm") return { access_token: "t", expires_in: 60, recovery_codes: codes };
    if (path === "/auth/mfa/disable") return { access_token: "t2", expires_in: 60 };
    if (path === "/auth/mfa/recovery-codes") return { recovery_codes: ["NEW00-00001"] };
    throw new Error(`unexpected ${path}`);
  });
});
afterEach(cleanup);

describe("Account", () => {
  it("off: set up asks for the password, enrols without an mfa_token, then the codes and refresh", async () => {
    render(<Account />);
    fireEvent.click(screen.getByRole("button", { name: "Set up an authenticator app" }));
    expect(calls("/auth/mfa/enrol/start")).toHaveLength(0); // nothing before the password
    fireEvent.change(screen.getByLabelText("Your password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("img", { name: /QR code/ });
    expect(calls("/auth/mfa/enrol/start")[0][1].json).toEqual({ password: "pw" });
    fireEvent.change(screen.getByLabelText(/Code from your authenticator app/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on two-factor sign-in" }));
    expect(await screen.findByLabelText("Recovery codes")).toBeInTheDocument();
    expect(calls("/auth/mfa/enrol/confirm")[0][1].json).toEqual({ code: "123456" });
    codes.forEach((c) => expect(screen.getByText(c)).toBeInTheDocument());
    expect(h.refresh).toHaveBeenCalled();
  });

  it("required: no Turn off button", () => {
    h.me = { ...h.me, mfa_enabled: true, mfa_required: true };
    render(<Account />);
    expect(screen.queryByRole("button", { name: "Turn off" })).toBeNull();
    expect(screen.getByRole("button", { name: "New recovery codes" })).toBeInTheDocument();
  });

  it("turn off needs password and code, then posts", async () => {
    h.me = { ...h.me, mfa_enabled: true };
    render(<Account />);
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    const submit = screen.getByRole("button", { name: "Turn off two-factor sign-in" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Code from your authenticator app/), { target: { value: "123456" } });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() => expect(calls("/auth/mfa/disable")).toHaveLength(1));
    expect(calls("/auth/mfa/disable")[0][1]).toMatchObject({ method: "POST", json: { password: "pw", code: "123456" } });
    await waitFor(() => expect(h.refresh).toHaveBeenCalled());
  });

  it("new recovery codes posts the code and shows them", async () => {
    h.me = { ...h.me, mfa_enabled: true };
    render(<Account />);
    fireEvent.click(screen.getByRole("button", { name: "New recovery codes" }));
    fireEvent.change(screen.getByLabelText(/Code from your authenticator app/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Make new codes" }));
    expect(await screen.findByText("NEW00-00001")).toBeInTheDocument();
    expect(calls("/auth/mfa/recovery-codes")[0][1].json).toEqual({ code: "123456" });
  });
});
