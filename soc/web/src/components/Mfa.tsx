import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { LoginResult } from "../auth";

/** Shapes of the MFA endpoints (soc/api/auth.py). */
export interface MfaEnrolment {
  secret: string;
  otpauth_uri: string;
  /** The QR code as SVG text, drawn by the SOC. Shown as an image, never as markup. */
  qr_svg: string;
  issuer: string;
}

export interface MfaEnabled extends LoginResult {
  recovery_codes: string[];
}

function errorText(err: unknown): string {
  return err instanceof ApiError ? err.message : "Can't reach the SOC API";
}

/** An SVG string as an <img> source: the browser draws it as a picture (no scripts, no markup). */
export function svgDataUrl(svg: string): string {
  const bytes = new TextEncoder().encode(svg);
  let bin = "";
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return `data:image/svg+xml;base64,${btoa(bin)}`;
}

/** Six digits from an authenticator app, or a recovery code (XXXXX-XXXXX). */
export function CodeField({ value, onChange, allowRecovery, emailSent = false, autoFocus = true }: {
  value: string; onChange: (v: string) => void; allowRecovery: boolean; emailSent?: boolean; autoFocus?: boolean;
}) {
  return (
    <label className="field">
      {emailSent ? "Sign-in code" : allowRecovery ? "Code from your authenticator app (or a recovery code)" : "Code from your authenticator app"}
      <input value={value} onChange={(e) => onChange(e.target.value)} required autoFocus={autoFocus}
        autoComplete="one-time-code" inputMode={allowRecovery ? "text" : "numeric"}
        maxLength={allowRecovery ? 16 : 8} spellCheck={false} />
    </label>
  );
}

/** The recovery codes, shown once, with a copy button and an explicit "saved" step. */
export function RecoveryCodes({ codes, onDone, doneLabel = "I have saved these codes" }: {
  codes: string[]; onDone: () => void; doneLabel?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mfa-codes">
      <p>
        <b>Recovery codes.</b> Each works once, instead of a code from the app, if you lose your phone.
        Store them somewhere safe: they are not shown again.
      </p>
      <ul className="code-list" aria-label="Recovery codes">
        {codes.map((c) => <li key={c}><code>{c}</code></li>)}
      </ul>
      <div className="row-actions">
        <button type="button" className="small" onClick={() => {
          void navigator.clipboard?.writeText(codes.join("\n")).then(() => setCopied(true), () => setCopied(false));
        }}>{copied ? "Copied" : "Copy codes"}</button>
        <button type="button" className="primary" onClick={onDone}>{doneLabel}</button>
      </div>
    </div>
  );
}

/** Set up an authenticator app: scan the QR code (or type the key), then confirm with a code.
 *  `mfaToken` is the "enrol" sign-in step (an admin at login); without it the signed-in user
 *  enrols and must type their password first (a stolen session alone can't add an
 *  authenticator). `onEnabled` gets the result: a fresh access token and the recovery codes. */
export function MfaEnrol({ mfaToken, onEnabled, onCancel }: {
  mfaToken?: string; onEnabled: (res: MfaEnabled) => void; onCancel?: () => void;
}) {
  const [enrolment, setEnrolment] = useState<MfaEnrolment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (!mfaToken) return; // signed in: start after the password (startWithPassword)
    let live = true;
    api<MfaEnrolment>("/auth/mfa/enrol/start", { method: "POST", json: { mfa_token: mfaToken } })
      .then((e) => { if (live) setEnrolment(e); })
      .catch((err) => { if (live) setError(errorText(err)); });
    return () => { live = false; };
  }, [mfaToken]);

  async function startWithPassword(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setEnrolment(await api<MfaEnrolment>("/auth/mfa/enrol/start", { method: "POST", json: { password } }));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  async function confirm(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<MfaEnabled>("/auth/mfa/enrol/confirm", {
        method: "POST", json: { code: code.trim(), ...(mfaToken ? { mfa_token: mfaToken } : {}) },
      });
      onEnabled(res);
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (!enrolment && !mfaToken) {
    return (
      <form onSubmit={startWithPassword} className="mfa-enrol">
        <label className="field">
          Your password
          <input type="password" autoComplete="current-password" value={password} autoFocus
            onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <div className="error" role="alert">{error}</div>}
        <div className="row-actions">
          {onCancel && <button type="button" onClick={onCancel} disabled={busy}>Cancel</button>}
          <button className="primary" type="submit" disabled={busy || !password}>Continue</button>
        </div>
      </form>
    );
  }
  if (!enrolment) {
    return error ? <div className="error" role="alert">{error}</div> : <p className="muted">Preparing…</p>;
  }
  return (
    <form onSubmit={confirm} className="mfa-enrol">
      <p>Scan this code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy…).</p>
      <img className="mfa-qr" src={svgDataUrl(enrolment.qr_svg)} width={200} height={200}
        alt="QR code for your authenticator app" />
      {showKey ? (
        <p className="small-text">Key: <code className="wrap-anywhere">{enrolment.secret}</code> ({enrolment.issuer}, time-based, 6 digits)</p>
      ) : (
        <button type="button" className="small" onClick={() => setShowKey(true)}>Can't scan? Show the key</button>
      )}
      <CodeField value={code} onChange={setCode} allowRecovery={false} />
      {error && <div className="error" role="alert">{error}</div>}
      <div className="row-actions">
        {onCancel && <button type="button" onClick={onCancel} disabled={busy}>Cancel</button>}
        <button className="primary" type="submit" disabled={busy || code.trim().length < 6}>
          {busy ? "Checking…" : "Turn on two-factor sign-in"}
        </button>
      </div>
    </form>
  );
}
