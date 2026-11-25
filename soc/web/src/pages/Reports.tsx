import { useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, download } from "../api/client";
import type { ReportEmailResult, ReportWeeks } from "../api/types";
import { useAuth } from "../auth";
import { Card, ErrorText, PageHead, Pill, useAction, useLoad } from "../components/common";
import { dateTime } from "../format";

/** "1 Nov – 7 Nov" for a week's start and (exclusive) end. */
export function weekRange(start: string, end: string): string {
  const fmt = (d: Date) => d.toLocaleDateString(undefined, { day: "numeric", month: "short", timeZone: "UTC" });
  const last = new Date(new Date(end).getTime() - 1);
  return `${fmt(new Date(start))} – ${fmt(last)}`;
}

/** The ISO week (UTC) a date falls in, as "YYYY-Www". */
export function isoWeek(d: Date): string {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = t.getUTCDay() || 7; // Monday 1 … Sunday 7
  t.setUTCDate(t.getUTCDate() + 4 - day); // the Thursday of this week decides the year
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((t.getTime() - yearStart.getTime()) / 86_400_000 + 1) / 7);
  return `${t.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

/** Weekly PDF reports: download any of the last 12 weeks; admins can also email one now. */
export default function Reports() {
  const { me } = useAuth();
  const admin = me?.role === "admin";
  const { data, error, loading, reload } = useLoad(() => api<ReportWeeks>("/reports/weeks"), []);
  const act = useAction();
  const [working, setWorking] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function get(week: string) {
    setNotice(null);
    setWorking(`get:${week}`);
    await act.run(() => download(`/reports/weekly?week=${encodeURIComponent(week)}`, `idps-weekly-${week}.pdf`));
    setWorking(null);
  }

  async function email(week: string) {
    if (!window.confirm(`Email the report for ${week} to the configured recipients now?`)) return;
    setNotice(null);
    setWorking(`mail:${week}`);
    const r = await act.run(async () => {
      try {
        return await api<ReportEmailResult>(`/admin/reports/weekly/email?week=${encodeURIComponent(week)}`, { method: "POST" });
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) throw new Error("Email is not configured in the SOC.");
        throw err;
      }
    });
    setWorking(null);
    if (r) {
      setNotice(`Report for ${r.week} emailed to ${r.recipients} recipient${r.recipients === 1 ? "" : "s"} (${Math.round(r.size_bytes / 1024)} KB).`);
      void reload();
    }
  }

  const weeks = data?.weeks ?? [];
  // The week in progress, by the SOC's clock: the one that starts where the newest complete week ends.
  const current = weeks[0] ? isoWeek(new Date(weeks[0].end)) : null;
  return (
    <>
      <PageHead title="Reports" />
      <Card title="Weekly report"
        actions={data && (data.email_enabled && data.email_configured
          ? <Pill tone="ok">emailed every week</Pill>
          : data.email_enabled ? <Pill tone="warn">email on, not configured</Pill>
          : <Pill tone="neutral">email off</Pill>)}>
        <p className="muted" style={{ marginTop: 0 }}>
          A PDF of one ISO week (Monday to Sunday, UTC): alerts by day, class and severity, the top sources,
          blocks, analyst triage and model health. It contains IP addresses: share it only under the{" "}
          <Link to="/privacy">privacy notice</Link>.
        </p>
        {current && (
          <div className="row-actions" style={{ marginBottom: 12 }}>
            <button className="small" aria-disabled={working !== null}
              onClick={() => { if (working === null) void get(current); }}>
              {working === `get:${current}` ? "Preparing…" : "This week so far (PDF)"}
            </button>
          </div>
        )}
        <ErrorText error={error ?? act.error} />
        <div className="notice" role="status" aria-live="polite">{notice}</div>
        {loading && !data ? <p className="muted">Loading…</p> : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Week</th><th>Dates</th><th style={{ textAlign: "right" }}>Alerts</th><th>Email</th>
                  <th><span className="sr-only">Actions</span></th></tr>
              </thead>
              <tbody>
                {weeks.map((w) => (
                  <tr key={w.week}>
                    <td><b>{w.week}</b>{w.week === data?.default_week && <span className="muted small-text"> · latest</span>}</td>
                    <td>{weekRange(w.start, w.end)}</td>
                    <td style={{ textAlign: "right" }}>{w.alerts.toLocaleString()}</td>
                    <td>
                      {w.emailed ? <span title={w.emailed_at ? dateTime(w.emailed_at) : undefined}>sent to {w.recipients_count}</span>
                        : w.error ? <span className="danger-text">failed: {w.error}</span>
                        : <span className="muted">—</span>}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div className="row-actions" style={{ justifyContent: "flex-end" }}>
                        <button className="small" disabled={working !== null} onClick={() => void get(w.week)}
                          aria-label={`Download PDF, week ${w.week}`}>
                          {working === `get:${w.week}` ? "Preparing…" : "Download PDF"}
                        </button>
                        {admin && data?.email_configured && (
                          <button className="small" disabled={working !== null} onClick={() => void email(w.week)}
                            aria-label={`Email the report for ${w.week}`}>
                            {working === `mail:${w.week}` ? "Sending…" : "Email"}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {admin && data && !data.email_configured && (
          <p className="muted small-text">Emailing needs the SOC's email settings (SMTP); see docs/soc.md, "Reports".</p>
        )}
      </Card>
    </>
  );
}
