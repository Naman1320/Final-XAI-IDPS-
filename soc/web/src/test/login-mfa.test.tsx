import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AuthProvider } from "../auth";
import { setToken } from "../api/client";
import Login from "../pages/Login";
import { svgDataUrl } from "../components/Mfa";

type Handler = (body: any) => { status?: number; body?: unknown };
let routes: Record<string, Handler>;
let sent: { key: string; body: any }[];
const assign = vi.fn();

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const posts = (key: string) => sent.filter((s) => s.key === key);
const SVG = '<svg xmlns="http://www.w3.org/2000/svg"><text>é€ QR</text></svg>';
const codes = Array.from({ length: 10 }, (_, i) => `AAAAA-0000${i}`);

beforeEach(() => {
  setToken(null);
  sessionStorage.clear();
  sent = [];
  assign.mockReset();
  routes = {
    "GET /auth/oidc/config": () => ({ body: { enabled: false, label: null } }),
    "GET /auth/me": () => ({ body: { id: 1, username: "alice", role: "analyst" } }),
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${String(url).replace(/^\/api/, "")}`;
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    sent.push({ key, body });
    const h = routes[key];
    if (!h) return json(404, { detail: `no route ${key}` });
    const r = h(body);
    return json(r.status ?? 200, r.body ?? null);
  }));
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...window.location, assign, get pathname() { return "/"; }, search: "" },
  });
  window.history.pushState(null, "", "/");
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); setToken(null); });

const show = () => render(<MemoryRouter><AuthProvider><Login /></AuthProvider></MemoryRouter>);
const fillPassword = async () => {
  fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "alice" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
};
const codeInput = () => screen.getByLabelText(/Code from your authenticator app/);

describe("svgDataUrl", () => {
  it("round-trips UTF-8 text", () => {
    const url = svgDataUrl(SVG);
    expect(url.startsWith("data:image/svg+xml;base64,")).toBe(true);
    const bin = atob(url.slice("data:image/svg+xml;base64,".length));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    expect(new TextDecoder().decode(bytes)).toBe(SVG);
  });
});

describe("Login password and code", () => {
  it("signs in with an access token and loads /auth/me", async () => {
    routes["POST /auth/login"] = () => ({ body: { access_token: "tok", expires_in: 60 } });
    show();
    await fillPassword();
    await waitFor(() => expect(posts("GET /auth/me").length).toBeGreaterThanOrEqual(1));
    expect(posts("POST /auth/login")[0].body).toEqual({ username: "alice", password: "pw", request_email_code: true });
  });

  it("verifies a code then signs in", async () => {
    routes["POST /auth/login"] = () => ({ body: { access_token: null, expires_in: null, mfa: "verify", mfa_token: "mt" } });
    routes["POST /auth/mfa/verify"] = () => ({ body: { access_token: "tok", expires_in: 60 } });
    show();
    await fillPassword();
    fireEvent.change(await screen.findByLabelText(/Code from your authenticator app/), { target: { value: " 123456 " } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(posts("GET /auth/me")).toHaveLength(1));
    expect(posts("POST /auth/mfa/verify")[0].body).toEqual({ mfa_token: "mt", code: "123456" });
  });

  it("submits an emailed code with its original challenge", async () => {
    routes["POST /auth/login"] = () => ({ body: { mfa: "verify", mfa_token: "email-step", email_status: "sent" } });
    routes["POST /auth/mfa/verify"] = () => ({ body: { access_token: "tok", expires_in: 60 } });
    show();
    await fillPassword();
    fireEvent.change(await screen.findByLabelText("Sign-in code"), { target: { value: "01234567" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(posts("GET /auth/me")).toHaveLength(1));
    expect(posts("POST /auth/mfa/verify")[0].body).toEqual({ mfa_token: "email-step", code: "01234567" });
  });

  it("shows an incorrect-code error and clears the field", async () => {
    routes["POST /auth/login"] = () => ({ body: { access_token: null, expires_in: null, mfa: "verify", mfa_token: "mt" } });
    routes["POST /auth/mfa/verify"] = () => ({ status: 401, body: { detail: "incorrect code" } });
    show();
    await fillPassword();
    fireEvent.change(await screen.findByLabelText(/Code from your authenticator app/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("incorrect code");
    expect(codeInput()).toHaveValue("");
  });

  it("returns to the password step when the sign-in expired", async () => {
    routes["POST /auth/login"] = () => ({ body: { access_token: null, expires_in: null, mfa: "verify", mfa_token: "mt" } });
    routes["POST /auth/mfa/verify"] = () => ({ status: 401, body: { detail: "sign-in expired, start again" } });
    show();
    await fillPassword();
    fireEvent.change(await screen.findByLabelText(/Code from your authenticator app/), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("expired");
  });
});

describe("Login enrolment", () => {
  it("enrols, shows recovery codes, and finishes with the returned token", async () => {
    routes["POST /auth/login"] = () => ({ body: { access_token: null, expires_in: null, mfa: "enrol", mfa_token: "mt" } });
    routes["POST /auth/mfa/enrol/start"] = () => ({ body: { secret: "SECRETKEY", otpauth_uri: "otpauth://x", qr_svg: SVG, issuer: "IDPS" } });
    routes["POST /auth/mfa/enrol/confirm"] = () => ({ body: { access_token: "new-tok", expires_in: 60, recovery_codes: codes } });
    const { container } = show();
    await fillPassword();
    const img = await screen.findByRole("img", { name: /QR code/ });
    expect(img.getAttribute("src")!.startsWith("data:image/svg+xml;base64,")).toBe(true);
    expect(container.querySelector("svg")).toBeNull();
    expect(posts("POST /auth/mfa/enrol/start")[0].body).toEqual({ mfa_token: "mt" });
    expect(screen.queryByText("SECRETKEY")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Show the key/ }));
    expect(screen.getByText("SECRETKEY")).toBeInTheDocument();
    fireEvent.change(codeInput(), { target: { value: "654321" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on two-factor sign-in" }));
    expect(await screen.findByLabelText("Recovery codes")).toBeInTheDocument();
    expect(posts("POST /auth/mfa/enrol/confirm")[0].body).toEqual({ code: "654321", mfa_token: "mt" });
    expect(screen.getAllByRole("listitem")).toHaveLength(10);
    codes.forEach((c) => expect(screen.getByText(c)).toBeInTheDocument());
    expect(posts("GET /auth/me")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Saved, continue" }));
    await waitFor(() => expect(posts("GET /auth/me")).toHaveLength(1));
    expect(sessionStorage.getItem("idps-soc-token")).toBe("new-tok");
  });
});

describe("Login single sign-on", () => {
  it("hides the SSO button when disabled", async () => {
    show();
    await screen.findByLabelText("Username");
    await waitFor(() => expect(posts("GET /auth/oidc/config")).toHaveLength(1));
    expect(screen.queryByRole("button", { name: /single sign-on|Corp/i })).toBeNull();
  });

  it("starts SSO: stores the binding and redirects", async () => {
    routes["GET /auth/oidc/config"] = () => ({ body: { enabled: true, label: "Sign in with Corp" } });
    routes["POST /auth/oidc/start"] = () => ({ body: { authorization_url: "https://idp.example/auth?x=1", binding: "bnd" } });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Sign in with Corp" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://idp.example/auth?x=1"));
    expect(sessionStorage.getItem("idps-sso-binding")).toBe("bnd");
  });

  it("refuses a non-http(s) authorization_url", async () => {
    routes["GET /auth/oidc/config"] = () => ({ body: { enabled: true, label: "Corp" } });
    routes["POST /auth/oidc/start"] = () => ({ body: { authorization_url: "javascript:alert(1)", binding: "bnd" } });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Corp" }));
    await waitFor(() => expect(posts("POST /auth/oidc/start")).toHaveLength(1));
    await waitFor(() => expect(screen.getByRole("button", { name: "Corp" })).toBeEnabled());
    expect(assign).not.toHaveBeenCalled();
    expect(sessionStorage.getItem("idps-sso-binding")).toBeNull();
  });

  const callback = (search: string) => {
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...window.location, assign, pathname: "/auth/callback", search },
    });
  };

  it("finishes a callback with a token", async () => {
    sessionStorage.setItem("idps-sso-binding", "bnd");
    callback("?code=c&state=s");
    const replace = vi.spyOn(window.history, "replaceState");
    routes["POST /auth/oidc/callback"] = () => ({ body: { access_token: "tok", expires_in: 60 } });
    show();
    await waitFor(() => expect(posts("GET /auth/me")).toHaveLength(1));
    expect(posts("POST /auth/oidc/callback")[0].body).toEqual({ code: "c", state: "s", binding: "bnd" });
    expect(sessionStorage.getItem("idps-sso-binding")).toBeNull();
    expect(replace).toHaveBeenCalledWith(null, "", "/");
  });

  it("continues to the MFA step from a callback", async () => {
    sessionStorage.setItem("idps-sso-binding", "bnd");
    callback("?code=c&state=s");
    routes["POST /auth/oidc/callback"] = () => ({ body: { access_token: null, expires_in: null, mfa: "verify", mfa_token: "mt" } });
    show();
    expect(await screen.findByText(/Two-factor sign-in is on/)).toBeInTheDocument();
  });

  it("posts nothing without a binding", async () => {
    callback("?code=c&state=s");
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent(/can't be used/);
    expect(posts("POST /auth/oidc/callback")).toHaveLength(0);
  });

  it("posts nothing when the provider returned an error", async () => {
    sessionStorage.setItem("idps-sso-binding", "bnd");
    callback("?error=access_denied&state=s");
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent(/cancelled or refused/);
    expect(posts("POST /auth/oidc/callback")).toHaveLength(0);
    expect(sessionStorage.getItem("idps-sso-binding")).toBeNull();
  });
});
