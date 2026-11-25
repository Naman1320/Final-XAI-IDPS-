import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api/client";
import { useAuth, type LoginResult } from "../auth";
import { CodeField, MfaEnrol, RecoveryCodes, type MfaEnabled } from "../components/Mfa";

import WorkspacePicker from "../components/WorkspacePicker";
import { workspace } from "../workspace";

/** Where single sign-on keeps the browser binding between leaving for the provider and coming
 *  back (soc/api/oidc.py: only the browser that started a sign-in can finish it). */
const SSO_KEY = workspace.storageKey("idps-sso-binding");
export const SSO_CALLBACK_PATH = "/auth/callback";

interface SsoConfig { enabled: boolean; label: string | null }

function errorText(err: unknown): string {
  return err instanceof ApiError ? err.message : "Can't reach the SOC API";
}

type Step =
  | { kind: "password" }
  | { kind: "verify"; token: string; email?: LoginResult["email_status"] }
  | { kind: "enrol"; token: string }
  | { kind: "codes"; result: MfaEnabled };

export default function Login() {
  const { login, finish } = useAuth();
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState<SsoConfig | null>(null);
  const callbackDone = useRef(false);

  /** A sign-in result: signed in, or the next MFA step. */
  async function next(res: LoginResult) {
    if (res.access_token) {
      await finish(res);
    } else if (res.mfa_token && (res.mfa === "verify" || res.mfa === "enrol")) {
      setCode("");
      setStep(res.mfa === "verify"
        ? { kind: "verify", token: res.mfa_token, email: res.email_status }
        : { kind: "enrol", token: res.mfa_token });
    } else {
      setError("Unexpected answer from the SOC API");
    }
  }

  useEffect(() => {
    api<SsoConfig>("/auth/oidc/config").then(setSso, () => setSso(null));
  }, []);

  // Back from the identity provider: finish the sign-in, then drop the code from the address.
  useEffect(() => {
    if (window.location.pathname !== workspace.base + SSO_CALLBACK_PATH || callbackDone.current) return;
    callbackDone.current = true;
    const params = new URLSearchParams(window.location.search);
    let binding: string | null = null;
    try {
      binding = sessionStorage.getItem(SSO_KEY);
      sessionStorage.removeItem(SSO_KEY);
    } catch { /* storage unavailable */ }
    window.history.replaceState(null, "", workspace.base + "/");
    const codeParam = params.get("code");
    const state = params.get("state");
    if (params.get("error")) {
      setError("Single sign-on was cancelled or refused by the provider.");
      return;
    }
    if (!codeParam || !state || !binding) {
      setError("This sign-in link can't be used here. Start the sign-in again.");
      return;
    }
    setBusy(true);
    api<LoginResult>("/auth/oidc/callback", { method: "POST", json: { code: codeParam, state, binding } })
      .then(next)
      .catch((err) => setError(errorText(err)))
      .finally(() => setBusy(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await next(await login(username, password));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    if (step.kind !== "verify") return;
    setBusy(true);
    setError(null);
    try {
      await next(await api<LoginResult>("/auth/mfa/verify", {
        method: "POST", json: { mfa_token: step.token, code: code.trim() } }));
    } catch (err) {
      const msg = errorText(err);
      if (err instanceof ApiError && err.status === 401 && msg.includes("expired")) setStep({ kind: "password" });
      setError(msg);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  async function startSso() {
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ authorization_url: string; binding: string }>("/auth/oidc/start", { method: "POST" });
      if (!/^https?:\/\//.test(res.authorization_url)) throw new Error("bad provider address");
      sessionStorage.setItem(SSO_KEY, res.binding);
      window.location.assign(res.authorization_url);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  function restart() {
    setStep({ kind: "password" });
    setError(null);
    setCode("");
  }

  return (
    <div className="login-wrap">
      <div className="card login">
        <h1>IDPS SOC</h1>
        <WorkspacePicker />
        {step.kind === "password" && (
          <form onSubmit={submitPassword}>
            <label className="field">
              Username
              <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
            </label>
            <label className="field">
              Password
              <input type="password" autoComplete="current-password" value={password}
                onChange={(e) => setPassword(e.target.value)} required />
            </label>
            {error && <div className="error" role="alert">{error}</div>}
            <button className="primary" type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
            {sso?.enabled && (
              <>
                <div className="login-or muted" aria-hidden="true">or</div>
                <button type="button" onClick={() => void startSso()} disabled={busy}>
                  {sso.label ?? "Sign in with single sign-on"}
                </button>
              </>
            )}
          </form>
        )}
        {step.kind === "verify" && (
          <form onSubmit={submitCode}>
            <p className="muted">{step.email === "sent" ? "We sent an eight-digit sign-in code to your account email. Enter it here within five minutes. You can also use your authenticator or a recovery code."
              : step.email === "cooldown" ? "A code was recently requested. Use the original sign-in tab, or wait one minute and sign in again to receive a new email."
              : step.email === "unavailable" ? "Email delivery failed. Use your authenticator or a recovery code, or try signing in again in one minute."
              : "Two-factor sign-in is on for this account."}</p>
            <CodeField value={code} onChange={setCode} allowRecovery emailSent={step.email === "sent"} />
            {error && <div className="error" role="alert">{error}</div>}
            <button className="primary" type="submit" disabled={busy || code.trim().length < 6}>
              {busy ? "Checking…" : "Verify"}
            </button>
            <button type="button" onClick={restart} disabled={busy}>Back</button>
          </form>
        )}
        {step.kind === "enrol" && (
          <div className="login-steps">
            <p><b>Admins must use two-factor sign-in.</b> Set it up now to continue.</p>
            <MfaEnrol mfaToken={step.token} onCancel={restart}
              onEnabled={(result) => setStep({ kind: "codes", result })} />
          </div>
        )}
        {step.kind === "codes" && (
          <RecoveryCodes codes={step.result.recovery_codes} doneLabel="Saved, continue"
            onDone={() => void finish(step.result).catch((err) => { setError(errorText(err)); restart(); })} />
        )}
        {step.kind !== "password" && step.kind !== "verify" && error && <div className="error" role="alert">{error}</div>}
        <p className="muted small-text login-foot"><Link to="/privacy">Privacy notice</Link></p>
      </div>
    </div>
  );
}
