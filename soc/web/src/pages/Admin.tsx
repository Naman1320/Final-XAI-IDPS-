import { useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type {
  AdminUser, AuditEntry, IntegrationChannel, IntegrationsResponse, IntegrationTestResult, ModelVersion, Page, Role, Sensor,
} from "../api/types";
import { useAuth } from "../auth";
import { Card, ErrorText, PageHead, Pill, useAction, useLoad } from "../components/common";
import { useSensors } from "../sensors";
import { dateTime, label } from "../format";

/** Admin: users, sensors, model versions and the audit log (wireframe screen 7). Only admins get this route. */

function Users({ onChanged }: { onChanged: () => void }) {
  const { me } = useAuth();
  const { data, error, reload } = useLoad(() => api<AdminUser[]>("/admin/users"), []);
  const act = useAction();
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" as Role });
  const [notice, setNotice] = useState<string | null>(null);
  const [resetFor, setResetFor] = useState<AdminUser | null>(null);
  const [newPassword, setNewPassword] = useState("");

  async function create(e: FormEvent) {
    e.preventDefault();
    setNotice(null);
    const u = await act.run(() => api<AdminUser>("/admin/users", {
      method: "POST", json: { ...form, username: form.username.trim() } }));
    if (u) {
      setForm({ username: "", password: "", role: "analyst" });
      setNotice(`Created ${u.role} ${u.username}.`);
      void reload();
      onChanged();
    }
  }

  async function setRole(u: AdminUser, role: Role) {
    if (role === u.role) return;
    if (!window.confirm(`Make ${u.username} ${role === "admin" ? "an admin" : "an analyst"}?`)) return;
    setNotice(null);
    const r = await act.run(() => api<AdminUser>(`/admin/users/${u.id}/role`, { method: "PATCH", json: { role } }));
    if (r) {
      setNotice(`${r.username} is now ${r.role === "admin" ? "an admin" : "an analyst"}.`);
      void reload();
      onChanged();
    }
  }

  async function resetMfa(u: AdminUser) {
    if (!window.confirm(`Reset two-factor sign-in for ${u.username}? They are signed out, and `
      + (u.role === "admin" ? "must set it up again at their next sign-in." : "can sign in with their password only."))) return;
    setNotice(null);
    const r = await act.run(() => api<AdminUser>(`/admin/users/${u.id}/mfa/reset`, { method: "POST" }));
    if (r) {
      setNotice(`Two-factor sign-in reset for ${r.username}.`);
      void reload();
    }
  }

  async function toggle(u: AdminUser) {
    const verb = u.disabled ? "Enable" : "Disable";
    if (!u.disabled && !window.confirm(`Disable ${u.username}? They are signed out and can't sign in.`)) return;
    setNotice(null);
    const r = await act.run(() => api<AdminUser>(`/admin/users/${u.id}/${u.disabled ? "enable" : "disable"}`, { method: "POST" }));
    if (r) {
      setNotice(`${verb}d ${r.username}.`);
      void reload();
      onChanged();
    }
  }

  async function resetPassword(e: FormEvent) {
    e.preventDefault();
    if (!resetFor) return;
    setNotice(null);
    const r = await act.run(() => api<AdminUser>(`/admin/users/${resetFor.id}/reset-password`, {
      method: "POST", json: { password: newPassword } }));
    if (r) {
      setNotice(`Password reset for ${r.username}; their existing sessions were signed out.`);
      closeReset();
      onChanged();
    }
  }

  // Focus goes back to the row's "Reset password" button when the form closes.
  const resetButtons = useRef(new Map<number, HTMLButtonElement>());
  function closeReset() {
    const id = resetFor?.id;
    setResetFor(null);
    setNewPassword("");
    if (id !== undefined) requestAnimationFrame(() => resetButtons.current.get(id)?.focus());
  }

  return (
    <Card title="Users">
      <ErrorText error={error ?? act.error} />
      <div className="notice" role="status" aria-live="polite">{notice}</div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {(data ?? []).map((u) => {
              const self = u.id === me?.id;
              return (
                <tr key={u.id}>
                  <td>
                    <b className="wrap-anywhere">{u.username}</b>
                    <div className="muted small-text">since {dateTime(u.created_at)}</div>
                  </td>
                  <td>
                    {/* Your own role can't be changed here: it could lock you out of this page. */}
                    <select value={u.role} disabled={act.busy || self} aria-label={`Role of ${u.username}`}
                      onChange={(e) => void setRole(u, e.target.value as Role)}>
                      <option value="analyst">analyst</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>
                    <div className="row-actions">
                      <Pill tone={u.disabled ? "danger" : "ok"}>{u.disabled ? "disabled" : "active"}</Pill>
                      {u.mfa_enabled
                        ? <Pill tone="ok">2FA on</Pill>
                        : <Pill tone={u.role === "admin" ? "warn" : "neutral"}>2FA off</Pill>}
                      {u.sso_linked && <Pill tone="neutral">SSO</Pill>}
                    </div>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div className="row-actions" style={{ justifyContent: "flex-end", alignItems: "center" }}>
                      {/* The only way to change a password in the app, so it stays on your own row too. */}
                      <button className="small" disabled={act.busy}
                        ref={(el) => { if (el) resetButtons.current.set(u.id, el); else resetButtons.current.delete(u.id); }}
                        onClick={() => { setResetFor(u); setNewPassword(""); }}
                        aria-label={`${self ? "Change your password" : `Reset password of ${u.username}`}`}>
                        {self ? "Change password" : "Reset password"}
                      </button>
                      {/* For a lost phone: they set it up again at their next sign-in. */}
                      {u.mfa_enabled && !self && (
                        <button className="small" disabled={act.busy} onClick={() => void resetMfa(u)}
                          aria-label={`Reset two-factor sign-in of ${u.username}`}>
                          Reset 2FA
                        </button>
                      )}
                      {/* Disabling or demoting yourself would lock you out of this page. */}
                      {self ? <span className="muted">you</span> : (
                        <button className={`small${u.disabled ? "" : " danger-soft"}`} disabled={act.busy}
                          onClick={() => void toggle(u)}
                          aria-label={`${u.disabled ? "Enable" : "Disable"} ${u.username}`}>
                          {u.disabled ? "Enable" : "Disable"}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {resetFor && (
        <form key={resetFor.id} className="inline-panel" onSubmit={resetPassword}
          aria-label={`Reset password of ${resetFor.username}`}>
          {/* Tells password managers whose password this is, so they don't file it under the admin's own login. */}
          <label className="field" style={{ flex: "0 1 160px" }}>User
            <input type="text" autoComplete="username" value={resetFor.username} readOnly />
          </label>
          <label className="field" style={{ flex: "1 1 200px" }}>New password for {resetFor.username} (12+ characters)
            <input type="password" autoComplete="new-password" value={newPassword} minLength={12} required autoFocus
              onChange={(e) => setNewPassword(e.target.value)} />
          </label>
          <button className="primary" type="submit" disabled={act.busy || newPassword.length < 12}>Set password</button>
          <button type="button" onClick={closeReset}>Cancel</button>
          {resetFor.id === me?.id && (
            <p className="small-text" style={{ margin: 0, flexBasis: "100%" }}>
              This signs you out everywhere, this browser included; sign in again with the new password.
            </p>
          )}
        </form>
      )}

      <form className="row-actions" style={{ marginTop: 14, alignItems: "flex-end" }} onSubmit={create}>
        <label className="field" style={{ flex: "1 1 140px" }}>Username
          <input value={form.username} maxLength={64} required autoComplete="off"
            onChange={(e) => setForm({ ...form, username: e.target.value })} />
        </label>
        <label className="field" style={{ flex: "1 1 160px" }}>Password (12+ characters)
          <input type="password" autoComplete="new-password" value={form.password} minLength={12} required
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </label>
        <label className="field">Role
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <button className="primary" type="submit" disabled={act.busy}>Add user</button>
      </form>
      <p className="muted small-text" style={{ margin: "10px 0 0" }}>
        Passwords are stored as argon2id hashes; sign-ins are throttled after repeated failures.
      </p>
    </Card>
  );
}

function Sensors({ onChanged }: { onChanged: () => void }) {
  const { data, error, reload } = useLoad(() => api<Sensor[]>("/admin/sensors"), []);
  const { data: seen, error: seenError } = useSensors();
  const stateOf = (id: number) => seen?.sensors.find((x) => x.sensor_id === id);
  const act = useAction();
  const [name, setName] = useState("");
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const s = await act.run(() => api<Sensor & { token: string }>("/admin/sensors", { method: "POST", json: { name: name.trim() } }));
    if (s) {
      setToken({ name: s.name, token: s.token });
      setName("");
      setCopied("no");
      void reload();
      onChanged();
    }
  }

  async function revoke(s: Sensor) {
    if (!window.confirm(`Revoke sensor ${s.name}? It can no longer send alerts or pick up actions.`)) return;
    const r = await act.run(() => api<Sensor>(`/admin/sensors/${s.id}/revoke`, { method: "POST" }));
    if (r) {
      void reload();
      onChanged();
    }
  }

  const [copied, setCopied] = useState<"no" | "yes" | "failed">("no");
  // The clipboard API exists only on HTTPS or localhost; a lab SOC on plain http has none.
  const canCopy = typeof window !== "undefined" && window.isSecureContext && !!navigator.clipboard;
  async function copy() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token.token);
      setCopied("yes");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <Card title="Sensors">
      <ErrorText error={error ?? act.error} />
      {/* Always present, so screen readers announce it when a sensor is added. */}
      <p className="sr-only" role="status">{token ? `Sensor ${token.name} added. Its token is shown below, once.` : ""}</p>
      {token && (
        <div className="token-box">
          <p style={{ margin: 0 }}><b>Sensor {token.name} added.</b> Copy its token now: it is shown only once.</p>
          <p style={{ margin: "8px 0 0" }} id="sensor-token-label">Token for {token.name}:</p>
          <pre className="mono" aria-labelledby="sensor-token-label">{token.token}</pre>
          <div className="row-actions" style={{ alignItems: "center" }}>
            {canCopy && (
              <button type="button" onClick={() => void copy()}>{copied === "yes" ? "Copied" : "Copy token"}</button>
            )}
            <button type="button" onClick={() => setToken(null)}>I've stored it</button>
            {(copied === "failed" || !canCopy) && (
              <span className="muted small-text">
                {copied === "failed" ? "Couldn't copy. " : ""}Select the token and copy it.
              </span>
            )}
          </div>
        </div>
      )}
      <ul className="queue-list">
        {(data ?? []).map((s) => (
          <li key={s.id}>
            <span>
              <b>#{s.id} {s.name}</b>
              <span className="muted small-text" style={{ display: "block" }}>
                created {dateTime(s.created_at)}
                {seen && !s.revoked && ` · ${stateOf(s.id)?.last_seen_at ? `last seen ${dateTime(stateOf(s.id)!.last_seen_at)}` : "never reported"}`}
              </span>
            </span>
            <span className="row-actions" style={{ alignItems: "center" }}>
              {/* Until the status loads (or if it fails) the pill can't say online or offline. */}
              {s.revoked ? <Pill>revoked</Pill>
                : !seen ? <Pill>{seenError ? "status unavailable" : "checking…"}</Pill>
                : stateOf(s.id)?.online ? <Pill tone="ok">online</Pill>
                : stateOf(s.id)?.last_seen_at ? <Pill tone="warn">offline</Pill>
                : <Pill>never reported</Pill>}
              {!s.revoked && (
                <button className="small danger-soft" disabled={act.busy} onClick={() => void revoke(s)}
                  aria-label={`Revoke sensor ${s.name}`}>Revoke</button>
              )}
            </span>
          </li>
        ))}
        {data?.length === 0 && <li className="muted">No sensors yet.</li>}
      </ul>
      <form className="row-actions" style={{ marginTop: 14, alignItems: "flex-end" }} onSubmit={create}>
        <label className="field" style={{ flex: "1 1 180px" }}>New sensor name
          <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="e.g. office-gateway" />
        </label>
        <button className="primary" type="submit" disabled={!name.trim() || act.busy}>Add sensor</button>
      </form>
      <p className="muted small-text" style={{ margin: "10px 0 0" }}>
        Adding a sensor issues its token. The token is shown <b>once</b>, then only its hash is kept: put it in the
        sensor's <code>IDPS_SOC_SENSOR_TOKEN</code>. A lost token can't be shown again: revoke the sensor and add a new one.
      </p>
    </Card>
  );
}

export type AuditGroup = "all" | "actions" | "blocks" | "alerts" | "cases" | "users" | "assistant";

/** The audit action names in each group: the API filters by exact names, so the server pages
 *  through matching entries only (ingest rows from busy sensors don't push them out of view). */
export const AUDIT_GROUPS: Record<Exclude<AuditGroup, "all">, string[]> = {
  actions: ["action_request", "action_confirmed", "action_rejected", "action_refused", "action_result"],
  assistant: ["assistant_message", "assistant_propose_block"],
  blocks: ["ingest_blocks"],
  alerts: ["ingest_alerts", "alert_status", "reputation_lookup"],
  cases: ["case_create", "case_update", "case_delete", "case_note", "case_attach", "case_detach"],
  users: ["user_create", "user_role", "user_disable", "user_enable", "user_reset_password", "user_mfa_reset",
    "user_sso_unlink", "mfa_enable", "mfa_disable", "mfa_recovery_code_used", "mfa_recovery_codes_replaced", "sso_link",
    "sensor_create", "sensor_revoke",
    "sensor_status_first", "sensor_status_changed", "integration_test"],
};

/** Which group an audit action belongs to. */
export function auditGroup(action: string): Exclude<AuditGroup, "all"> | "other" {
  for (const [g, names] of Object.entries(AUDIT_GROUPS)) {
    if (names.includes(action)) return g as Exclude<AuditGroup, "all">;
  }
  return "other";
}

/** /admin/audit query string: actor, one `action` per name of the group, limit and cursor. */
export function auditQuery(group: AuditGroup, actor: string, cursor?: string | null): string {
  const p = new URLSearchParams();
  if (actor.trim()) p.set("actor", actor.trim());
  if (group !== "all") AUDIT_GROUPS[group].forEach((a) => p.append("action", a));
  p.set("limit", "100");
  if (cursor) p.set("cursor", cursor);
  return `?${p.toString()}`;
}

/** The details as separate "key: value" pairs, string values quoted, so one value can't pass
 *  itself off as several pairs. */
export function DetailPairs({ details }: { details: Record<string, unknown> }) {
  const pairs = Object.entries(details ?? {});
  if (pairs.length === 0) return null;
  return (
    <ul className="detail-pairs">
      {pairs.map(([k, v]) => (
        <li key={k}><span className="muted">{k}:</span> {typeof v === "string" ? `“${v}”` : JSON.stringify(v)}</li>
      ))}
    </ul>
  );
}

const CHANNEL_NAME: Record<IntegrationChannel, string> = {
  webhook: "Webhook", slack: "Slack", email: "Email", syslog: "Syslog / CEF (SIEM)",
};

/** Notification and SIEM channels: configured in the SOC's environment (never here), with a test
 *  button that sends one clearly labelled test message. */
function Integrations({ onChanged }: { onChanged: () => void }) {
  const { data, error, reload } = useLoad(() => api<IntegrationsResponse>("/admin/integrations"), []);
  // Each row shows its own last test: the delivery result, or why the SOC refused to test.
  const [results, setResults] = useState<Partial<Record<IntegrationChannel, { ok: boolean; text: string }>>>({});
  const [testing, setTesting] = useState<IntegrationChannel | null>(null);

  async function test(channel: IntegrationChannel) {
    setTesting(channel);
    setResults((m) => ({ ...m, [channel]: undefined }));
    let res: { ok: boolean; text: string };
    try {
      const r = await api<IntegrationTestResult>(`/admin/integrations/${channel}/test`, { method: "POST" });
      res = r.ok ? { ok: true, text: `sent in ${r.duration_ms} ms` } : { ok: false, text: `failed: ${r.error ?? "unknown error"}` };
    } catch (err) {
      const why = err instanceof ApiError && err.status === 429 ? "too many tests; wait a minute"
        : err instanceof ApiError && err.status === 409 ? "not configured or notifications are off"
        : err instanceof Error ? err.message : String(err);
      res = { ok: false, text: `not sent: ${why}` };
    }
    setTesting(null);
    setResults((m) => ({ ...m, [channel]: res }));
    void reload();
    onChanged();
  }

  return (
    <Card title="Integrations">
      <ErrorText error={error} />
      {data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Channel</th><th>Sends</th><th>Delivery</th><th><span className="sr-only">Test</span></th></tr></thead>
            <tbody>
              {data.channels.map((c) => {
                const r = results[c.channel];
                return (
                  <tr key={c.channel}>
                    <td>
                      <b>{CHANNEL_NAME[c.channel]}</b>{" "}
                      {!c.configured ? <Pill>not configured</Pill> : !c.enabled ? <Pill tone="warn">off</Pill> : <Pill tone="ok">on</Pill>}
                      {c.target_hint && <div className="muted small-text mono wrap-anywhere">{c.target_hint}</div>}
                    </td>
                    <td className="small-text">
                      {c.configured
                        ? <>{c.min_severity} and above{c.include_rules ? ", model and rule alerts" : ", model alerts only"}</>
                        : "—"}
                    </td>
                    <td className="small-text">
                      {c.configured ? (
                        <>
                          {c.sent.toLocaleString()} sent
                          {c.failed > 0 && <> · <span className="danger-text">{c.failed.toLocaleString()} failed</span></>}
                          {c.rate_limited + c.deduped > 0 && <> · {(c.rate_limited + c.deduped).toLocaleString()} held back</>}
                          {c.dropped > 0 && <> · {c.dropped.toLocaleString()} dropped</>}
                          {c.last_success_at && <div className="muted">last sent {dateTime(c.last_success_at)}</div>}
                          {c.last_error && (() => {
                            // An error older than the last success is history, not the current state.
                            const old = !!c.last_success_at && !!c.last_error_at && Date.parse(c.last_success_at) > Date.parse(c.last_error_at);
                            return (
                              <div className={`wrap-anywhere ${old ? "muted" : "danger-text"}`}>
                                {old ? "earlier error" : "last error"}{c.last_error_at ? ` (${dateTime(c.last_error_at)})` : ""}: {c.last_error}
                              </div>
                            );
                          })()}
                        </>
                      ) : "—"}
                    </td>
                    <td>
                      <button type="button" disabled={!c.enabled || testing !== null} onClick={() => void test(c.channel)}
                        aria-label={`Send a test message to ${CHANNEL_NAME[c.channel]}`}
                        title={!c.configured ? "Not configured in the SOC's environment" : !c.enabled ? "Notifications are switched off (IDPS_SOC_NOTIFY_ENABLED)" : undefined}>
                        {testing === c.channel ? "Sending…" : "Test"}
                      </button>
                      <div role="status" className="small-text">
                        {r && <span className={r.ok ? undefined : "danger-text wrap-anywhere"}>{r.text}</span>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small-text" style={{ margin: "10px 0 0" }}>
        Channels and their secrets are set in the SOC's environment (see docs/soc.md, "Integrations"); this page never
        shows them. Bursts are summarised and repeats held back, so one attack doesn't send hundreds of messages.
        AbuseIPDB reputation: {data ? (data.abuseipdb.configured ? `on, cached ${data.abuseipdb.cache_hours} h` : "not configured") : "…"}.
      </p>
    </Card>
  );
}

/** Which model version each sensor runs, and which ones it ran before (GET /models, newest first). */
function Models({ refresh }: { refresh: number }) {
  const { data, error } = useLoad(() => api<{ models: ModelVersion[] }>("/models"), [refresh]);
  const models = data?.models ?? [];
  return (
    <Card title="Model versions">
      <ErrorText error={error} />
      {data && models.length === 0 && <p className="muted" style={{ margin: 0 }}>No sensor has reported a model yet.</p>}
      {models.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Version</th><th>Sensors</th><th>Seen</th></tr></thead>
            <tbody>
              {models.map((m) => (
                <tr key={m.sha256}>
                  <td>
                    <span className="mono wrap-anywhere">{m.version ?? m.name}</span>{" "}
                    {m.running_now > 0 && <Pill tone="ok">running</Pill>}
                    <div className="muted small-text mono">sha256 {m.sha256.slice(0, 12)}</div>
                  </td>
                  <td>
                    {m.sensors.length === 0 ? "—" : m.sensors.map((s) => (
                      <div key={s.sensor_id}>
                        {s.name}{" "}
                        <span className="muted small-text">
                          {s.running_now ? (s.online ? "now" : "last report, offline") : `until ${dateTime(s.last_seen)}`}
                        </span>
                      </div>
                    ))}
                  </td>
                  <td className="small-text">{dateTime(m.first_seen)} → {dateTime(m.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function Audit({ refresh }: { refresh: number }) {
  const [group, setGroup] = useState<AuditGroup>("all");
  const [actor, setActor] = useState("");
  const [actorInput, setActorInput] = useState("");
  const first = useLoad(() => api<Page<AuditEntry>>(`/admin/audit${auditQuery(group, actor)}`), [group, actor, refresh]);
  // Older pages, tagged with the filter they belong to, so a late answer never mixes filters.
  const key = `${group}|${actor}|${refresh}`;
  const [olderState, setOlder] = useState<{ key: string; items: AuditEntry[]; cursor: string | null } | null>(null);
  const older = olderState?.key === key ? olderState : null;
  const act = useAction();

  const rows = [...(first.data?.items ?? []), ...(older?.items ?? [])];
  const cursor = older ? older.cursor : first.data?.next_cursor ?? null;

  async function loadOlder() {
    if (!cursor) return;
    const k = key;
    const page = await act.run(() => api<Page<AuditEntry>>(`/admin/audit${auditQuery(group, actor, cursor)}`));
    if (page) {
      setOlder((o) => ({ key: k, items: [...(o?.key === k ? o.items : []), ...page.items], cursor: page.next_cursor }));
    }
  }

  return (
    <Card title="Audit log" actions={
      <div className="row-actions" style={{ alignItems: "center" }}>
        <form className="row-actions" style={{ alignItems: "center" }}
          onSubmit={(e) => { e.preventDefault(); setActor(actorInput); }}>
          <label className="field inline">Who
            <input value={actorInput} maxLength={64} placeholder="any" style={{ width: 140 }}
              onChange={(e) => setActorInput(e.target.value)} />
          </label>
          <button type="submit" className="small">Filter</button>
          {actor && <button type="button" className="small" onClick={() => { setActor(""); setActorInput(""); }}>Clear</button>}
        </form>
        <label className="field inline">Event
          <select value={group} onChange={(e) => setGroup(e.target.value as AuditGroup)}>
            <option value="all">all</option>
            <option value="actions">analyst actions</option>
            <option value="blocks">blocks</option>
            <option value="alerts">alerts</option>
            <option value="cases">cases</option>
            <option value="users">users and sensors</option>
            <option value="assistant">assistant, including proposals</option>
          </select>
        </label>
      </div>
    }>
      <ErrorText error={first.error ?? act.error} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Who</th><th>Event</th><th>Target</th><th>Details</th></tr></thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td style={{ whiteSpace: "nowrap" }}>{dateTime(e.at)}</td>
                <td className="wrap-anywhere">{e.actor_type === "user" ? e.actor_name : `${e.actor_type}:${e.actor_name}`}</td>
                <td>{label(e.action)}</td>
                <td className="mono wrap-anywhere">{e.target}</td>
                <td className="wrap-anywhere" style={{ maxWidth: 420 }}><DetailPairs details={e.details} /></td>
              </tr>
            ))}
            {first.data && rows.length === 0 && (
              <tr><td colSpan={5} className="muted">No matching events.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="row-actions" style={{ marginTop: 10, alignItems: "center" }}>
        {/* Not while the first page reloads: its cursor may still be the previous filter's. */}
        {cursor && !first.loading && <button className="small" disabled={act.busy} onClick={loadOlder}>{act.busy ? "Loading…" : "Load older entries"}</button>}
        <span className="muted small-text">{rows.length} entr{rows.length === 1 ? "y" : "ies"} shown{cursor ? "; more are older" : ""}.</span>
      </div>
    </Card>
  );
}

export default function Admin() {
  // Changes made on this page add audit entries: reload the log after each one.
  const [refresh, setRefresh] = useState(0);
  const changed = () => setRefresh((n) => n + 1);
  return (
    <>
      <PageHead title="Admin"><span className="muted small-text">Only the admin role sees this page.</span></PageHead>
      <div className="grid cols-2">
        <Users onChanged={changed} />
        <Sensors onChanged={changed} />
      </div>
      <Integrations onChanged={changed} />
      <Models refresh={refresh} />
      <Audit refresh={refresh} />
    </>
  );
}
