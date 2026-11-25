import { useState, type FormEvent } from "react";
import { api, ApiError, setToken } from "../api/client";
import { useAuth, type LoginResult } from "../auth";
import { Card, PageHead, Pill } from "../components/common";
import { CodeField, MfaEnrol, RecoveryCodes, type MfaEnabled } from "../components/Mfa";

/** Your account: two-factor sign-in (authenticator app and recovery codes). */
export default function Account() {
  const { me, refresh } = useAuth();
  const [mode, setMode] = useState<"idle" | "enrol" | "disable" | "regenerate">("idle");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!me) return null;
  const on = Boolean(me.mfa_enabled);

  function reset() {
    setMode("idle");
    setPassword("");
    setCode("");
    setError(null);
  }

  /** A changed MFA setting logs out other sessions; this one continues with the new token. */
  async function useToken(res: LoginResult) {
    if (res.access_token) setToken(res.access_token);
    await refresh();
  }

  async function enabled(res: MfaEnabled) {
    setCodes(res.recovery_codes);
    reset();
    await useToken(res);
    setNotice("Two-factor sign-in is on. Your other sessions were signed out.");
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "disable") {
        await useToken(await api<LoginResult>("/auth/mfa/disable", {
          method: "POST", json: { password, code: code.trim() } }));
        setNotice("Two-factor sign-in is off. Your other sessions were signed out.");
      } else if (mode === "regenerate") {
        const res = await api<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", {
          method: "POST", json: { code: code.trim() } });
        setCodes(res.recovery_codes);
        setNotice("New recovery codes: the old ones no longer work.");
      }
      reset();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Can't reach the SOC API");
      setCode("");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHead title="Account" />
      <Card title="Two-factor sign-in" actions={<Pill tone={on ? "ok" : "warn"}>{on ? "on" : "off"}</Pill>}>
        <div className="notice" role="status" aria-live="polite">{notice}</div>
        {codes ? (
          <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />
        ) : mode === "enrol" ? (
          <MfaEnrol onEnabled={(res) => void enabled(res)} onCancel={reset} />
        ) : mode === "idle" ? (
          <>
            <p className="muted">
              {on
                ? "You sign in with your password and a code from your authenticator app."
                : "Add a code from an authenticator app to your sign-in, so a stolen password alone is not enough."}
              {me.mfa_required && " Required for admins."}
            </p>
            <div className="row-actions">
              {!on && <button className="primary" onClick={() => { setNotice(null); setMode("enrol"); }}>Set up an authenticator app</button>}
              {on && <button onClick={() => { setNotice(null); setMode("regenerate"); }}>New recovery codes</button>}
              {on && !me.mfa_required && (
                <button className="danger-soft" onClick={() => { setNotice(null); setMode("disable"); }}>Turn off</button>
              )}
            </div>
          </>
        ) : (
          <form onSubmit={submit} className="stack">
            {mode === "disable" && (
              <label className="field">
                Password
                <input type="password" autoComplete="current-password" value={password}
                  onChange={(e) => setPassword(e.target.value)} required />
              </label>
            )}
            <CodeField value={code} onChange={setCode} allowRecovery={mode === "disable"} />
            {error && <div className="error" role="alert">{error}</div>}
            <div className="row-actions">
              <button type="button" onClick={reset} disabled={busy}>Cancel</button>
              <button className={mode === "disable" ? "danger-soft" : "primary"} type="submit"
                disabled={busy || code.trim().length < 6 || (mode === "disable" && !password)}>
                {mode === "disable" ? "Turn off two-factor sign-in" : "Make new codes"}
              </button>
            </div>
          </form>
        )}
      </Card>
    </>
  );
}
