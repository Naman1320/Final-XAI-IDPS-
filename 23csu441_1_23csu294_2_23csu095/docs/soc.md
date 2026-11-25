# SOC API

The FastAPI backend in `soc/api/`. Sensors send alerts and block reports to it; the dashboard
(and later the assistant) reads them, triages, and asks sensors to act.

## Running it

```bash
pip install -e ".[dev]"
export IDPS_SOC_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m soc.api create-user alice --role admin      # asks for the password (12+ characters)
python -m soc.api create-sensor lab-sensor-1          # prints the sensor token once
uvicorn soc.api.main:app --ws-max-size 65536 --reload   # one process, see "Live feed" below
```

Settings (environment variables, prefix `IDPS_SOC_`):

| Variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | none, required | Signs login tokens, 32+ characters |
| `DATABASE_URL` | `sqlite:///./soc.db` | SQLAlchemy URL; PostgreSQL: `postgresql+psycopg://user:pass@host/idps` |
| `ACCESS_TOKEN_MINUTES` | 30 | Login token lifetime (5 to 1440) |
| `LOGIN_MAX_FAILURES` / `LOGIN_MAX_FAILURES_PER_IP` / `LOGIN_LOCKOUT_MINUTES` | 5 / 20 / 15 | Lockout, see below |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated browser origins |
| `SEVERITY_BY_CLASS` | built-in map | JSON, e.g. `{"Bot": "critical"}`; class names match case-insensitively |
| `DEFAULT_SEVERITY` | `medium` | For classes not in the map |
| `LOW_CONFIDENCE_BELOW` | 0.6 | Below this confidence, severity drops one level (never below low) |
| `WS_MAX_CONNECTIONS` / `WS_QUEUE_SIZE` | 50 / 200 | Live feed limits |
| `ENABLE_DOCS` | false | Serves `/docs` and `/openapi.json` (unauthenticated, so off by default) |
| `CLOUD_ENDPOINT_URL` | unset | Cloud management: unset = the MOCK provider. Set to the URL of the LOCAL Moto emulator (`http://127.0.0.1:4566`) to read it instead; only a loopback or private `http://` address is accepted (see "Cloud management") |
| `WOULD_BLOCK_RETENTION_DAYS` | 7 | Dry-run would-block records older than this are deleted (1 to 365) |
| `AUTO_MIGRATE` | true | Upgrade the database schema at start-up; when false, refuse to start unless it is already at the current revision (see "Database") |
| `ALERT_RETENTION_DAYS` | 180 | Delete alerts older than this many days; 0 = keep forever (see "Retention") |
| `ALERT_RETENTION_KEEP_LABELLED` | true | Keep alerts an analyst confirmed or marked false positive that carry features (training rows), whatever their age |
| `AUDIT_RETENTION_DAYS` | 365 | Delete audit entries older than this; 0 = keep forever |
| `ASSISTANT_RETENTION_DAYS` | 90 | Delete assistant conversations not updated for this long; 0 = keep forever |
| `CLOSED_CASE_RETENTION_DAYS` | 0 | Delete closed cases and their notes not updated for this long; 0 = keep forever (the default) |
| `ACCESS_LOG_RETENTION_DAYS` | 365 | Delete access-log rows (who looked at personal data) older than this; 0 = keep forever (see "Privacy") |
| `PRIVACY_CONTROLLER_NAME` / `PRIVACY_CONTACT_EMAIL` / `PRIVACY_GRIEVANCE_OFFICER` | unset | Who the public privacy notice names; blank = unset (see "Privacy") |
| `REPORT_MASK_IPS` | false | Weekly report shows source addresses with the last octet hidden (see "Reports") |
| `REPORT_EMAIL_ENABLED` / `REPORT_EMAIL_WEEKDAY` / `REPORT_EMAIL_HOUR_UTC` / `REPORT_EMAIL_TO` | false / 0 (Monday) / 6 / `SMTP_TO` | Email the weekly report once a week (see "Reports") |
| `BLOCK_ALLOWLIST` | **empty: blocking refused** | Comma-separated addresses/networks the SOC must never ask to block: gateways, DNS, the SOC host, the sensors, the analysts. Required before any block request is accepted |

Notification, syslog and reputation settings (`NOTIFY_*`, `WEBHOOK_*`, `SLACK_*`, `SMTP_*`, `SYSLOG_*`,
`ABUSEIPDB_*`, `PUBLIC_URL`) are listed under "Integrations" below.

The SOC owns its block allowlist (`IDPS_SOC_BLOCK_ALLOWLIST`). Sensors keep their own
(`IDPS_ALLOWLIST`) as a second, independent check; set both.

For a production install (PostgreSQL, a TLS proxy serving the dashboard, certificates and secrets
generated for you), use `deploy/install.sh`: see [deploy.md](deploy.md).

## Endpoints

"User" means a logged-in analyst or admin. Lists use keyset pagination: `limit` (1 to 500) and
`cursor` (the `next_cursor` of the previous page); newest first.

| Method and path | Who | Purpose |
|---|---|---|
| `GET /health` | public | Liveness |
| `POST /auth/login`, `GET /auth/me` | public, user | Login (an access token, or an MFA step: see "Security"); current user, with `mfa_enabled` and `mfa_required` |
| `POST /auth/mfa/verify` | MFA step token | The code (or a recovery code) after the password: an access token |
| `POST /auth/mfa/enrol/start`, `/enrol/confirm` | user, or an admin's "enrol" step token | New secret with its QR code; turn MFA on with a code (returns the recovery codes, once) |
| `POST /auth/mfa/disable`, `/auth/mfa/recovery-codes` | user | Turn MFA off (password and code; not where it is required); replace the recovery codes |
| `GET /auth/oidc/config`, `POST /auth/oidc/start`, `/auth/oidc/callback` | public | Single sign-on, when configured: whether it is on, the provider address, finishing the sign-in |
| `POST /ingest/alerts` | sensor | Batch of 1 to 500 alerts; stores and broadcasts them |
| `GET /alerts` | user | Filters: `severity` (repeatable), `predicted_class`, `ip` (source or destination), `status`, `source` (`ml` or `rule`), `since`, `until` (timezone required) |
| `GET /alerts/{id}`, `PATCH /alerts/{id}` | user | Detail with explanation (empty for rule alerts); set `status` (new, acknowledged, false_positive, resolved) |
| `WS /ws/alerts` | user | Live feed: alerts (as `GET /alerts` plus `src_geo`) and typed block messages; see "Live feed" |
| `POST /ingest/blocks` | sensor | Up to 100 `blocked` / `unblocked` / `would_block` events (`would_block` = a dry-run decision, stored in its own table, never a block) |
| `GET /blocks` | user | `active=true/false`, `ip` |
| `GET /blocks/would` | user | Dry-run `would_block` decisions, newest first: `ip`, `since_hours` (1 to 720, default 24), `limit`, `cursor` |
| `POST /sensor/status` | sensor | The sensor's status snapshot (mode, policy, allowlist, health, counters); every 30 s; overwrites the sensor's one row |
| `GET /sensors/status` | user | `{redacted, soc_allowlist, sensors: [{sensor_id, name, revoked, last_seen_at, online, status}]}`; `status` is null for a sensor never seen (and, for non-admins, for a revoked one); **non-admins get `redacted: true`, `soc_allowlist: null` and `allowlist: null`, `policy: null` in each status** (admins get all of it); online = reported within 120 s and not revoked; no tokens or hashes |
| `POST /actions` | user | Request `block_ip` / `unblock_ip` on a sensor; starts confirmed |
| `GET /actions`, `GET /actions/{id}` | user | List (filter by `status`), detail |
| `POST /actions/{id}/confirm`, `/reject` | user | Decide a pending action (for assistant proposals) |
| `GET /sensor/actions` | sensor | Confirmed actions for this sensor |
| `POST /sensor/actions/{id}/result` | sensor | `{"success": bool, "result": {...}}` |
| `GET/POST /cases`, `GET/PATCH/DELETE /cases/{id}` | user | Cases |
| `POST /cases/{id}/notes` | user | Note, up to 10,000 characters |
| `GET /alerts/{id}/reputation` | user | AbuseIPDB reputation of the alert's source address, on demand; see "Integrations" |
| `GET /admin/integrations` | admin | Status of the notification and syslog channels (never any secret); see "Integrations" |
| `POST /admin/integrations/{channel}/test` | admin | Send a labelled test message (`webhook`, `slack`, `email`, `syslog`); audited, 3 per minute per channel |
| `POST /cases/{id}/alerts`, `DELETE /cases/{id}/alerts/{alert_id}` | user | Attach or detach alerts (an alert is in at most one case) |
| `GET /metrics/summary?hours=24` | user | Alerts per bucket (hourly up to 72 h, else daily), by class and severity, `by_source` (`{"ml": n, "rule": n}`, always both keys), top 10 sources, false-positive rate, detection latency p50/p95, active blocks, `would_blocks` (dry-run decisions in the window), `by_class_per_day` (cached for 60 s; last 7 UTC days whatever `hours` is: `[{day, class, count}]`, non-zero pairs only, classes beyond the top 25 as `(other)`), `anomaly_per_day` (same 7 days and cache: `[{day, count}]`, alerts the Isolation Forest also flagged, non-zero days only) |
| `GET /topology?hours=1` | user | Nodes (host, alert count, max severity) and edges (src to dst, count, max severity) |
| `GET/POST /admin/users`, `PATCH /admin/users/{id}/role`, `POST /admin/users/{id}/disable`, `/enable`, `/reset-password`, `/mfa/reset`, `/sso/unlink` | admin | User management |
| `/iam/...` | permission | Users, roles, groups, policies, login history and audit by permission; see "IAM and permissions" |
| `/cloud/...` | permission | Cloud management on a MOCK inventory (instances, storage, network, metrics, cost, alerts, activity); see "Cloud management" |
| `GET/POST /admin/sensors`, `POST /admin/sensors/{id}/revoke` | admin | Sensors; the token is returned once, on creation |
| `GET /admin/retention` | admin | The retention policy and the last run (time, rows deleted per table, error); see "Retention" |
| `GET /reports/weekly?week=2026-W45` | user | The weekly report as a PDF attachment (default: the last complete ISO week, UTC); access-logged; 422 for a bad or future week, 429 when two are already being built; see "Reports" |
| `GET /reports/weeks` | user | `{default_week, email_enabled, email_configured, weeks: [{week, start, end, alerts, run, emailed, emailed_at, recipients_count, error}]}`: the last 12 complete weeks, newest first |
| `POST /admin/reports/weekly/email?week=` | admin | Email that week's report now to the configured recipients: `{week, recipients, emailed_at, size_bytes}`; audited; 409 when email is not configured, 502 when sending fails, 413 over 10 MB |
| `GET /demo` | user | Live demo status: `{enabled, runner_online, run}`; see "Live demo" |
| `POST /admin/demo/run`, `POST /admin/demo/cancel` | admin | Queue the fixed demo run (202; 409 if a run is active or the runner has not polled in 30 s; 503 while demo mode is off) / cancel the active run (404 if none); audited |
| `GET /demo/runner/next`, `POST /demo/runner/report` | `X-Demo-Token` | The host-side demo runner only: heartbeat and hand-over of the queued run / step progress; see "Live demo" |
| `GET /privacy/notice` | **public** | The privacy notice for the people whose traffic is monitored: controller, data categories, purposes, the retention periods in force, recipients (channel names only), rights; see "Privacy" |
| `POST /admin/privacy/erase/preview` | admin | `{ip}`: what erasing the address would remove or rewrite, per table and field (`{ip, subject_fp, counts, total, active_blocks, manual_review, warnings}`); changes nothing; access-logged |
| `POST /admin/privacy/erase` | admin | `{ip, reason, force?}` (reason 1 to 500 characters, must not contain the address): erase the address everywhere in one transaction; same shape plus `record_id`, `erased_at`; 422 for an invalid address or a CIDR; 409 while the address has an active block (unless `force: true`) or while any assistant reply is running |
| `GET /admin/privacy/erasures` | admin | Erasure records, newest first (`id, at, requested_by, reason, subject_fp, counts`); no addresses; `ip` filter ("was this address erased?") |
| `GET /admin/privacy/access-log` | admin | Who looked at personal data: filters `ip` (fingerprinted by the server), `username`, `action`, `since`, `until` (timezone required); rows `{id, at, user_id, username, action, target_type, target, subject_fp}` |
| `GET /admin/audit` | admin | Audit log, filter by `actor` and `action` (repeat `action` for several, up to 20) |

Rules worth knowing:

- **Severity** comes from the predicted class and the confidence (see `SEVERITY_BY_CLASS`).
  BENIGN alerts in a batch are skipped and counted in `skipped_benign`.
- **Allowlist.** `block_ip` is refused (422) for any address in `IDPS_SOC_BLOCK_ALLOWLIST`
  and for loopback, multicast, link-local, reserved and unspecified addresses. IP fields reject
  IPv6 zone IDs (`%eth0`) and anything longer than 45 characters. The check runs when the
  action is created, when it is confirmed, and again when the sensor polls for it. While the
  allowlist is empty, every block request is refused (503); already-confirmed actions are then
  held back, not failed, and are handed out once the allowlist is set again.
- **Concurrency.** Confirm and reject, and a sensor's result report, use conditional updates,
  so of two simultaneous requests exactly one wins and the other gets 409. The login lockout
  counts an attempt before the password check, so parallel guesses can't exceed the limit.
- **Actions.** pending, then confirmed or rejected by an analyst; then the sensor reports
  executed or failed. A sensor only sees and answers its own actions.
  The live sensor polls and executes them (see "Analyst actions" in `live.md`); in dry-run it
  reports them failed with `sensor is in dry-run: not applied`.
- **Would-block events.** A dry-run sensor reports each block it *would* have applied as
  `{"event": "would_block", "ip", "reason", "ttl_seconds", "decided_at"}` through `/ingest/blocks`. They go to
  the `would_blocks` table, never `blocks`, so active-block counts and the firewall are unaffected;
  a sensor that blocks for real never sends them. `expires_at` is refused on them. `decided_at`
  (timezone required, optional) is the sensor's decision time and is stored as `at`, so an event
  delayed in the outbox keeps its real time; absent (older sensors) or more than 60 s in the future
  it, or older than 24 h (a wrong sensor clock), is replaced by the receive time. Retention: would-block rows older than
  `IDPS_SOC_WOULD_BLOCK_RETENTION_DAYS` (default 7, 1 to 365) are deleted by a background task started
  by the block ingest path (it runs after the response, with its own database session), at most once
  per 10 minutes per process, one at a time, and at most 10,000 rows per run (1,000 per DELETE, the
  ids chosen by a subquery so SQLite's old 999-variable limit does not apply), so a large backlog is
  worked off over several runs. The 10 minutes count from when a prune starts: a prune that fails
  is logged (with its traceback) and not retried until the interval has passed; batches already
  deleted stay deleted. It only ever touches `would_blocks`, never `blocks`.
  A failed prune is logged and does not fail the ingest. `at` is indexed (`ix_would_blocks_at`);
  the table is new, so `create_all` creates it with the index and nothing needs adding by hand.
- **Sensor status.** The live sensor posts a status report at start and every 30 s
  (`IDPS_LIVE_STATUS_SECONDS`, 5 to 3600). The SOC's bounds on the policy fields cover everything the
  sensor's settings allow (`unblock_grace_seconds` is capped at one year on both sides), so a valid
  sensor never gets a 422 on its status. A stored status that no longer validates (older schema)
  is listed as `status: null` instead of failing the listing. The body is strict (unknown fields refused; strings,
  lists, numbers bounded; at most 100 allowlist entries). `last_seen_at` is the SOC's clock, not
  the sensor's. These posts are not audited (one every 30 s would bury the audit log). Shape of one
  entry's `status`: `dry_run`, `blocking_enabled`, `interface` (null in replay), `mode`
  (`live`/`replay`), `model {name, checksum_ok}`, `policy {confidence_threshold, min_flows,
  window_seconds, min_alert_confidence, block_ttl_seconds, unblock_grace_seconds,
  max_analyst_blocks}`, `allowlist` (the sensor's `IDPS_ALLOWLIST`), `allowlist_total` (the real count; `allowlist` is cut at 100), `outbox_pending`, `shap_p95_ms`, `heartbeat {enabled, ok}`, `counters {flows, alerts, blocked, would_block}`,
  `faithfulness` (optional, absent from older sensors or when the sensor has no report):
  `{model, model_matches, model_check, flows, top_k, random_mean_drop, methods: {shap?, lime?}}` with
  each method `{mean_drop, ratio_to_random, label_flip_rate, share_flows_beating_random}`.
  `ratio_to_random` may be `null` (random removal changed nothing) or negative (deleting the
  explanation raised confidence): the worst outcomes are reported, not dropped. `model_check` is
  `"digest"` (report and loaded model compared by sha256) or `"name"` (older report without a
  digest, or older sensor: only the algorithm name was compared, a weak match), absent from older
  sensors; at least one
  method; unknown keys are refused. Model-level numbers from the offline faithfulness report, not
  live LIME. `sensor_version`, `sent_at` (the sensor's clock, informational).
- **Anomaly series.** `anomaly_per_day` counts alerts whose stored `anomaly_score` is above 0:
  exactly the Isolation Forest's outlier flag (score = -decision_function). It is a separate
  series, not a synthetic class row, so no class name can collide with it; ingest also refuses a
  `predicted_class` starting with `(` so nothing real collides with the `(other)` fold bucket.
  The result is one grouped query over the week's alerts, cached in-process for 60 s per database
  and UTC day (new alerts show up to a minute late; a new day never reuses yesterday's buckets).
  The cost still grows with the alerts of the last 7 days. The model now declares an index
  `ix_alerts_received_class_anomaly` on `alerts (received_at, predicted_class, anomaly_score)`, so
  new databases get it from `create_all`; an **existing** database does not (create_all never
  touches existing tables), so add it by hand:
  `CREATE INDEX ix_alerts_received_class_anomaly ON alerts (received_at, predicted_class, anomaly_score);`
  An alert has a class and may also be an outlier, so the series overlaps the class rows; alerts
  with no score (a model without an anomaly detector) are ignored.
- **Last admin.** Demoting or disabling the last enabled admin, including yourself, returns 409.
- **Request body limits.** `soc/api/limits.py` (pure ASGI middleware, constants in one place)
  answers 413 before anything is read or parsed (so before authentication, even for a revoked
  sensor): by `Content-Length` when sent, and by counting streamed bytes (chunked bodies) until the
  limit. 10 MiB for `/ingest/alerts` (500 alerts x 16 KiB explanation fit), 128 KiB `/ingest/blocks`
  and `/cases`, 64 KiB `/sensor/status` and `/assistant`, 16 KiB `/actions`, `/sensor/actions` and
  `/admin`, 64 KiB `/iam` (4 KiB `/admin/privacy`, 1 KiB `/admin/reports`), 4 KiB `/auth/login`, 8 KiB the rest of `/auth`, 256 KiB anything else. A malformed `Content-Length` is a 400. The
  Caddyfile in `infra/templates/soc-user-data.sh.tftpl` also sets `request_body { max_size 11MiB }`,
  `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.
- **Sensor-supplied text.** Interface, model and sensor-version names in a status report are
  refused (422) if they contain control, formatting (bidi override, zero-width) or separator
  characters; would-block and block reasons, the `reason` of `POST /actions` and the assistant's
  `propose_block` reason have those characters removed (a reason that is blank afterwards is
  refused); a NUL anywhere in a
  stored string (alert class, explanation, reason, action result, status) is refused because
  PostgreSQL cannot store it. Allowlist entries must be IP addresses or networks (stored
  normalised, e.g. `10.1.1.1/32`), `allowlist_total` must be at least the list's length, and
  booleans and integers are strict (`"yes"` is not a bool). A `would_block` event always has
  `source: "auto"`, whatever the sensor says.
- **WebSocket size.** The body-limit middleware does not see WebSocket messages, and the live feed
  reads the first message before checking its 4096 characters, so start uvicorn with
  `--ws-max-size 65536` (every start script in the repo does; its default is 16 MiB). The server
  then closes an oversized message with 1009 before any handler runs.
- **What analysts can see (decided, deliberate).** `GET /sensors/status` withholds the SOC
  allowlist and each sensor's allowlist and block policy from non-admins, and the 422 for a blocked
  address on the allowlist names the matching network only to admins (analysts, and the assistant,
  get "this address is on the block allowlist"). Block reasons and action results stay visible to
  analysts because they need them to triage. An analyst can therefore still infer from a reason
  such as "5 flows >= 0.9 confidence in 60s" the sensor's threshold, flow count, window and block
  length, and from refused actions the analyst-block cap. That is accepted: redacting reasons would
  make blocks impossible to review; the allowlist (who is never blocked) is the part that matters.
- **Sensor status audit.** One audit row (`sensor_status_first`) on a sensor's first report, and
  `sensor_status_changed` when `dry_run`, `blocking_enabled`, `mode`, `model`, the `policy`, the
  allowlist (or its total) or `faithfulness.model_matches` changes: `details.changed` maps each
  field to `[old, new]` (policy: per sub-field; allowlist: counts, totals and at most 20 added and
  removed entries plus `more`). Counters, outbox size and times never cause a row. At most one row
  per sensor per field per 10 minutes (`AUDIT_WINDOW_SECONDS`): a change inside the window is not
  lost, the next post after it compares with the last *audited* value and writes one row (old to
  latest) with `details.folded[field]` counting the changes it absorbed; the throttle state is in
  memory, after a restart the stored status is the baseline. Stored allowlists from before entries
  were normalised (`10.10.1.1`) are normalised before comparing, so an upgrade is not a change.
- **Audit.** Every mutating request writes one audit row in the same transaction as the change
  (an alert or block batch is one row). `POST /auth/login` is not audited.

## Auth model

- **Users** log in at `/auth/login` with a username and password (argon2id) and get a bearer
  token (JWT, HS256). Send it as `Authorization: Bearer ...`. The role is read from the database
  on every request, so demotions and disabling apply at once; a password reset or disable also
  invalidates existing tokens.
- **Sensors** use API tokens (`idps_sensor_...`, created by `python -m soc.api create-sensor` or
  by an admin). Only a SHA-256 of the token is stored. Sensor tokens work only on `/ingest/*`
  and `/sensor/*`; user tokens do not work there.
- **WebSocket.** Browsers can't set headers on a WebSocket, so after connecting, the client's
  first message must be `{"token": "<access token>"}`, sent within 5 seconds. Any failure closes
  the socket with code **4401**, as does the token expiring or the user being disabled while
  connected (re-checked every 30 s). Other close codes: 4429 too many connections, 4408 client
  too slow. The server then sends `{"type": "ready"}` followed by one JSON object per new alert
  (the same fields as `GET /alerts`, without the explanation; fetch `/alerts/{id}` for that).
  Reconnect when the token is renewed.
- **Lockout.** After `LOGIN_MAX_FAILURES` failed logins for a (username, client IP) pair, or
  `LOGIN_MAX_FAILURES_PER_IP` for one IP, logins are refused (429) for `LOGIN_LOCKOUT_MINUTES`,
  even with the right password. The counters are **in memory**: they reset when the process
  restarts and are not shared between processes, so run one process or move them to the
  database or Redis before scaling out. Behind a reverse proxy, use uvicorn's `--proxy-headers`
  so the client IP is the real one.

## IAM and permissions

Roles, groups and policies on top of the two legacy roles (`soc/api/iam/`, migration `0004_iam`).
Everything is enforced on the backend by permission; the dashboard only reads what the API says.

**How the legacy roles map.** Nothing about existing endpoints changed: every endpoint that
exists today still checks the legacy role (`analyst` or `admin`) exactly as before, and holding
IAM permissions does not open them. A user's legacy role decides their starting point:

| Legacy role | Holds |
| --- | --- |
| `admin` | **Every permission, always.** No deny policy can remove one (so a bad policy can never lock the SOC out of its own administration). |
| `analyst` | The system role `analyst`: `cloud.view` |

**Model.** `iam_roles` (named permission sets; the two **system roles** `admin` (every permission)
and `analyst` (`cloud.view`) are seeded by the migration and cannot be edited or deleted),
`iam_role_permissions`, `iam_groups`, `iam_group_members`, `iam_group_roles`, `iam_user_roles`,
`iam_policies` (allow or deny, permission patterns such as `cloud.*`, resource globs, default
`["*"]`, can be disabled), `iam_policy_attachments` (to a user, group or role) and `login_history`.
Names are 3 to 48 characters of `A-Za-z0-9 _-`, unique ignoring case; descriptions up to 255
characters. The catalog is a constant in `soc/api/iam/catalog.py`, not stored: a permission named
in the database but missing from the catalog is ignored.

**Catalog** (`GET /iam/permissions`):

| Group | Permissions |
| --- | --- |
| Cloud | `cloud.view`, `cloud.instances.write`, `cloud.storage.write`, `cloud.network.write`, `cloud.alerts.manage` (enforced by `/cloud`, see "Cloud management") |
| Users | `iam.users.view`, `iam.users.write`, `iam.users.delete` |
| Roles | `iam.roles.view`, `iam.roles.write` |
| Groups | `iam.groups.view`, `iam.groups.write` |
| Policies | `iam.policies.view`, `iam.policies.write` |
| Monitoring | `iam.audit.view`, `iam.logins.view` |

**Effective permissions** (`soc/api/iam/engine.py`, computed from the database on every request,
nothing cached, so a change is in force at once):

1. A legacy admin holds everything and is not subject to any policy.
2. Anyone else holds the union of the system role named like their legacy role, the roles assigned
   to them, the roles of their groups, and what **allow** policies attached to them, their groups
   or their roles grant.
3. Then every permission matched by an enabled **deny** policy attached to them, to one of their
   groups or to one of their roles is removed. Deny always wins.
4. Patterns use `*` (`cloud.*`, `*.view`). A policy applies to resources matching one of its globs;
   roles grant on every resource. `engine.allows(db, user, permission, resource="*")` is the helper
   for code that has a resource: a deny scoped to `prod-*` stops the permission on `prod-db` but
   does not remove it "in general" (what `/auth/me` and the permission dependency ask), and a
   scoped allow does not grant it in general.

**Enforcement.** `require_permission(*perms)` (`soc/api/iam/deps.py`) is a dependency: 401 when not
signed in or disabled, 403 unless the user holds **all** the permissions. `GET /auth/me` gained
`permissions: [...]` (additive).

**Endpoints** (all under `/iam`; lists take `limit` and `cursor` like the others, newest first;
bodies reject unknown fields; names and descriptions refuse control and direction-override
characters; at most 120 writes per user per minute (429); bodies over 64 KiB are 413):

| Endpoint | Needs | Notes |
| --- | --- | --- |
| `GET /iam/permissions` | `iam.roles.view` | The catalog, grouped, with descriptions |
| `GET /iam/me/permissions` | any signed-in user | `{username, role, all_access, permissions}` |
| `GET /iam/users/{id}/effective-permissions` | `iam.users.view` | Permissions, which were `denied`, the roles, groups and policies that apply |
| `GET /iam/users` | `iam.users.view` | Filters `q` (username contains), `status` (`active`/`disabled`), `role` (legacy), `role_id`, `group_id` |
| `POST /iam/users` | `iam.users.write` | `{username, password, role?, role_ids?, group_ids?}`; the password policy of every other path |
| `GET /iam/users/{id}` | `iam.users.view` | Roles, groups, `mfa_enabled`, `mfa_required`, `last_login`, `disabled` |
| `PATCH /iam/users/{id}` | `iam.users.write` | `role`, `role_ids`, `group_ids`, `disabled` (the lists replace) |
| `POST /iam/users/{id}/deactivate`, `/activate` | `iam.users.write` | Idempotent |
| `DELETE /iam/users/{id}` | `iam.users.delete` | See "Deleting a user" |
| `GET/POST /iam/roles`, `GET/PATCH/DELETE /iam/roles/{id}` | `iam.roles.view` / `iam.roles.write` | Permissions and member counts; system roles: 409 |
| `GET/POST /iam/groups`, `GET/PATCH/DELETE /iam/groups/{id}`, `PUT /iam/groups/{id}/members`, `PUT /iam/groups/{id}/roles` | `iam.groups.view` / `iam.groups.write` | The `PUT`s replace the list |
| `GET/POST /iam/policies`, `GET/PATCH/DELETE /iam/policies/{id}`, `PUT /iam/policies/{id}/attachments` | `iam.policies.view` / `iam.policies.write` | `{effect, permissions, resources, disabled}`; attachments `[{subject_type: user\|group\|role, subject_id}]` |
| `GET /iam/logins` | `iam.logins.view` | Filters `user_id`, `username`, `success`, `reason`, `since`, `until` (a timezone is required, use `Z`) |
| `GET /iam/audit` | `iam.audit.view` | The audit log of `/admin/audit` plus `target`, `since`, `until` |

**Security rules** (each has tests in `tests/test_soc_iam_security.py`):

- **No privilege escalation.** You cannot grant what you do not hold: a role's permissions, a role
  or group given to a user, a role given to a group, a member added to a group, an allow policy
  (created, widened, enabled, flipped from deny, or attached). Only newly added things are checked,
  so you can always remove permissions. Only a legacy administrator can create or manage a legacy administrator account. Delegation requires the permission across all resources. After upgrading, sign in again so that access and MFA tokens are bound to the account creation time.
- **No lifting a restriction you are under.** Deleting, disabling, narrowing or detaching a deny
  policy (or removing someone from a deny-carrying group or role) needs the denied permissions
  yourself, so a user cannot simply delete the deny that limits them.
- **No managing someone more powerful.** Editing, deactivating or deleting a user who holds a
  permission you do not is 403.
- **Not yourself.** You cannot change your own legacy role, roles, groups or active state, deactivate
  or delete yourself, join or leave a group, or have a policy attached to or removed from you.
- **Last admin.** The last enabled legacy admin cannot be deactivated, demoted or deleted (409);
  the same check as `/admin/users`.
- **System roles** cannot be edited or deleted (409); roles with their name cannot be created.
- **Sessions end.** Any change to a user's legacy role, roles, groups or active state adds one to
  their `token_version`, so their existing tokens stop working. Changes that reach many users
  indirectly (a role's permissions or deletion, a group's members, roles or deletion, a policy's
  change, attachment or deletion) do the same for every affected user, except the person making
  the change.
- **Audit.** Every mutation writes one entry in the same transaction (`iam_user_create`,
  `iam_user_update`, `iam_user_deactivate`, `iam_user_activate`, `iam_user_delete`,
  `iam_role_create/update/delete`, `iam_group_create/update/delete/members/roles`,
  `iam_policy_create/update/delete/attach`), with the actor, a target such as `user:bob` and short
  details (ids, added and removed). Never a password. A refused request writes nothing.

**Deleting a user.** The database does not enforce foreign keys on SQLite, so the code clears
everything itself, in the same transaction (PostgreSQL's `ON DELETE CASCADE` is a second line).
History is kept but loses its link to the user: cases (`created_by`), case notes (`author`) and
actions (`proposed_by`, `decided_by`) keep their rows with an empty user, and the login history
keeps its rows with `user_id` empty (the username stays, as in the audit log, which names the
deleted user in `iam_user_delete`). What belongs to the user alone is removed: their assistant
conversations, group memberships, role assignments and policy attachments. Deactivating is the
reversible alternative.

**Login history** at `GET /iam/logins` records password, MFA and OIDC outcomes. A completed
second factor records the successful sign-in. Failed OIDC callbacks distinguish provider failures
from a refusal by the SOC. Unknown account names are stored as keyed pseudonyms. The history
deduplicates repeated unknown or locked attempts and caps failure rows per address per minute.
`IDPS_SOC_LOGIN_HISTORY_RETENTION_DAYS` defaults to 365. A value of zero keeps rows indefinitely.
Each entry includes the peer address and a bounded user agent. Access requires `iam.logins.view`.

## Cloud management

A backend for a cloud dashboard (`soc/api/cloud/`, migration `0005_cloud`, routes under `/cloud`).
**There is no real cloud behind it.** The project has no cloud account and no billing, so by
default every instance, volume, bucket, network, metric and cost figure is **mock data**: an
invented inventory kept in the SOC's own database. Every response that returns inventory,
metrics, cost or alerts carries `data_source` (`"mock"`) and `data_source_label` (`"Mock data: no
live cloud connected"`), and every change says in `note` that it was "applied to the persisted mock
inventory only; nothing in any real cloud was changed". A UI must show the label.

**Providers** (`soc/api/cloud/provider.py`). `CloudProvider` is the interface (list instances,
volumes, buckets, VPCs, subnets, security groups, daily cost). `MockProvider` (default) reads the
database and is the only one that accepts changes. `EmulatedAwsProvider` reads the local Moto
emulator with boto3 and is used **only** when `IDPS_SOC_CLOUD_ENDPOINT_URL` is set; it returns
`data_source: "emulated-aws"`, is read-only (every change is 409), has no cost data
(`available: false`), uses the fake `test`/`test` credentials passed explicitly (the environment, profiles
and roles are never read), region `eu-west-1`, and refuses a different account than
`000000000000`. The guard (`guard.py`, the same idea as `lab/cloud/guard.py`) accepts only
`http://` and `localhost` or an IP address that is loopback or private; HTTPS, DNS names, public,
link-local (the metadata address) and multicast addresses, credentials in the URL and a configured
proxy are refused, and then every `/cloud` request answers 503 (it never falls back silently, and
no boto3 client is built). Metrics stay synthetic with either provider (`metrics_source: "mock"`).
**The emulated provider is covered by unit tests against fake boto3 clients only; it has not been
run against a live Moto.**

**Permissions** (the catalog of "IAM and permissions"; a legacy admin holds all, an analyst holds
`cloud.view`). All checked on the backend with `require_permission`; 401 without a token, 403
without the permission.

| Permission | Endpoints |
| --- | --- |
| `cloud.view` | every `GET` under `/cloud` |
| `cloud.instances.write` | `POST /cloud/instances`, `PATCH /cloud/instances/{id}`, `POST /cloud/instances/{id}/start`, `/stop`, `/reboot`, `DELETE /cloud/instances/{id}` (terminate) |
| `cloud.storage.write` | `POST/PATCH/DELETE /cloud/volumes...`, `POST /cloud/volumes/{id}/attach`, `/detach`, `POST/PATCH/DELETE /cloud/buckets...` |
| `cloud.network.write` | `POST/DELETE /cloud/network/security-groups`, `POST/DELETE /cloud/network/security-groups/{id}/rules...` |
| `cloud.alerts.manage` | `POST /cloud/alerts/evaluate`, `/{id}/acknowledge`, `/{id}/resolve`, `DELETE /cloud/alerts/{id}` |
| all four write permissions | `POST /cloud/demo-data/reset` |

**Resource-scoped policies.** Instance-level changes also ask the IAM engine
`allows(user, permission, resource)` with `instance:{id}`; volumes use `volume:{id}`, buckets
`bucket:{name}`, security groups `securitygroup:{id}`. A deny policy scoped to
`instance:i-1234abcd` stops that instance and leaves the others (403 naming the resource). The
general check (route level) asks about "any resource", so a user needs the permission from a role or
an unscoped allow policy; a scoped allow alone does not pass the route check (decided: the spec's
`require_permission` stays the gate, scoping can only narrow).

**Endpoints.** Lists take `limit` (1 to 200, default 50) and `offset` and answer
`{data_source, data_source_label, items, total, limit, offset}`. Errors are `{"detail": ...}` as
everywhere (422 validation and references to something that does not exist, 409 a state or
dependency conflict, 403, 404, 429, 413).

| Endpoint | Notes |
| --- | --- |
| `GET /cloud/overview` | Instances by state and type, totals (vCPUs and memory running, disk, volumes, buckets, VPCs...), health counts, alerts (`open`, `acknowledged`, `critical_open`), cost (`month_to_date`, `last_month_total`, `last_month_same_period`, `change_vs_same_period_pct`, linear `forecast_month_total`) |
| `GET /cloud/instances` | `q`, `state`, `az`, `type`, `sort` (`name`, `state`, `instance_type`, `az`, `launched_at`, `updated_at`, `id`), `order`, `limit`, `offset` |
| `GET /cloud/instances/{id}` | Includes `health` (below) |
| `POST /cloud/instances` | `{name, instance_type, subnet_id, security_group_ids, az?, os?, disk_gb?, tags?}`: type from a fixed catalog (`t3.micro` ... `r5.large`), `az` must match the subnet, groups must be in the subnet's VPC, at most 100 live instances. Starts `pending`, becomes `running` 10 s later (on the next request: there are no background threads) |
| `PATCH /cloud/instances/{id}` | `name`, `tags` (not on a terminated instance) |
| `POST /cloud/instances/{id}/start` `/stop` `/reboot`, `DELETE /cloud/instances/{id}` | State machine: start from `stopped`; stop and reboot from `running`; terminate from `running` or `stopped`; anything else is 409. A stop releases the public address, terminating detaches the volumes. The terminated record stays |
| `GET /cloud/instances/{id}/metrics?range=1h\|24h\|7d` | `timestamps` and `series` (`cpu_pct`, `memory_pct`, `disk_pct`, `net_in_mbps`, `net_out_mbps`; steps 1 min, 15 min, 1 h; null before the instance existed), `current`, `metrics_source: "mock"` |
| `GET /cloud/metrics/summary` | Fleet CPU, memory and network averages, storage utilisation, busiest instances, 24 h CPU trend |
| `GET /cloud/volumes`, `GET /cloud/volumes/{id}` | `q`, `state`, `instance_id`, `sort`, `order` |
| `POST /cloud/volumes`, `PATCH /cloud/volumes/{id}` (grow only), `POST /cloud/volumes/{id}/attach` (`{instance_id}`), `/detach`, `DELETE /cloud/volumes/{id}` (not while in use) | 1 to 16384 GB, types `gp3`, `gp2`, `io1`, `st1` |
| `GET /cloud/buckets`, `GET /cloud/buckets/{name}`, `POST` (DNS-style unique name), `PATCH` (`versioning`, `encrypted`, `public_access_blocked`), `DELETE` | A bucket with objects needs `?force=true` (409 otherwise) |
| `GET /cloud/network/vpcs`, `/subnets`, `/security-groups`, `/security-groups/{id}` | Filters `vpc_id`, `az`, `q` |
| `POST /cloud/network/security-groups`, `DELETE /cloud/network/security-groups/{id}` (409 while an instance uses it) | |
| `POST /cloud/network/security-groups/{id}/rules`, `DELETE .../rules/{rule_id}` | `{direction: in\|out, protocol: tcp\|udp\|icmp\|all, port_from?, port_to?, cidr, description?, confirm_open_to_world?}`; CIDR validated with `ipaddress` and normalised, ports 0 to 65535 (not for `icmp`/`all`), duplicates 409. An ingress rule that exposes port 22 or 3389 to an entire address family, alone or combined with existing rules, returns 422 with code `confirm_open_to_world` unless `confirm_open_to_world` is true |
| `GET /cloud/cost?range=7d\|30d\|90d` | `total`, `by_service` (`compute`, `storage`, `network`, `other`), `by_day`, `forecast` (month to date divided by days elapsed, times days in the month), `top_drivers` (instances by price x running hours) and `by_instance_type`; the drivers are an estimate, not a bill |
| `GET /cloud/alerts` | `status`, `severity`, `resource_type`, `resource_id` |
| `POST /cloud/alerts/evaluate` | Mock provider only. Raises an alert for each threshold crossed (below), once: an open or acknowledged alert for the same rule and resource is not repeated (a worse severity raises the existing one); a resolved one is raised anew if the problem is still there. Nothing resolves automatically |
| `POST /cloud/alerts/{id}/acknowledge`, `/resolve`, `DELETE /cloud/alerts/{id}` | `open` to `acknowledged` to `resolved`; a wrong state is 409 |
| `GET /cloud/notifications` | The unresolved alerts, most severe first, with `open` and `acknowledged` counts |
| `GET /cloud/activity` | `actor`, `action` (exact, e.g. `instance.stop`), `resource_type`, `resource_id`; newest first |
| `POST /cloud/demo-data/reset` | Needs all four write permissions. Wipes the mock inventory, alerts, activity and cost and seeds the demo data again (same ids every time) |

**Mock metrics and health.** A sample is computed from the instance id, the series name and the
timestamp (rounded down to the step), with a daily wave and stable noise; nothing is stored, so the
same history comes back on every call and in every process. Each instance has a load profile fixed
by its id (idle, normal, busy, hot, full). The activity log says when it last started or stopped:
before a stop it ran, after it CPU, memory and network are exactly 0 and the disk is flat; after a
start they come back (a pending instance is still 0). Health checks (`instance_state`, `cpu_pct`,
`memory_pct`, `disk_pct`) are computed from the latest sample: degraded at 80 % CPU, 85 % memory,
80 % disk, critical at 95, 95 and 90 %; the instance status is the worst check. An instance that
is not running is `unknown` (nothing to measure), not healthy.

**Alert rules** (`evaluate`): CPU, memory or disk over the degraded (warning) or critical
threshold on a running instance; a bucket that does not block public access (critical) or is not
encrypted (warning); a security group opening SSH or RDP to the world (critical); an unencrypted
volume (info).

**Data and seed.** Tables: `cloud_instances`, `cloud_instance_sgs`, `cloud_volumes`,
`cloud_buckets`, `cloud_vpcs`, `cloud_subnets`, `cloud_security_groups`, `cloud_sg_rules`,
`cloud_alerts` (with a `rule` column, the dedupe key), `cloud_activity`, `cloud_cost_daily` (`day`
is an ISO date string). On the first authorised `/cloud` request, if the instance, VPC, bucket and
security group tables are all empty, the demo data is created: 8 instances (6 running, 1 stopped,
1 terminated) in two availability zones of `eu-west-1`, 6 volumes, 4 buckets
(`idps-demo-*`), 2 VPCs with 6 subnets, 3 security groups (one deliberately opens SSH to the world,
and one bucket does not block public access: demo findings), 5 alerts, 52 activity rows (26 of them
spread over the last 14 days) (actor `demo-seed`, `demo-admin`, `demo-analyst`, `system`) and **90** days of
cost (the 30 days asked for, extended so the `90d` range and "last month" are complete). The
seed is deterministic (same ids and figures every time, dates relative to now), idempotent and safe
when two first requests race. Addresses are private ranges or RFC 5737 documentation addresses
(`203.0.113.x`), never a real one. A refused (401/403) request never seeds.

**What is mock.** Everything: the inventory, its states, the metrics, the cost figures (which do not
change when you change the inventory; the cost drivers do) and the demo alerts. Changes are real
only in the sense that they persist in the SOC database, are audited (`cloud_<resource>_<verb>`
rows in the audit log, with `data_source: mock`) and appear in `/cloud/activity`.
Not mock: the permissions, the audit trail and the validation.

**Rules and limits.** Bodies reject unknown fields and control or direction-override characters
(names, descriptions, tags); at most 120 writes per user per minute across `/cloud` (429), bodies
over 32 KiB are 413; at most 100 live instances, 200 volumes, 50 buckets, 50 security groups, 60
rules per group, 20 tags. Every change and its activity and audit rows are one transaction: a
refused or failed change leaves nothing behind. The new tables are exempt from privacy erasure (they
hold fictional data; the decision and reason are in `EXEMPT_TABLES` in `soc/api/privacy.py`).

## Security (roadmap step 11)

### Two-factor sign-in (TOTP)

- **Admins must use it** (`IDPS_SOC_MFA_REQUIRED_FOR_ADMINS`, default on). An admin who has not
  set it up gets no access token at login: the answer is `{"mfa": "enrol", "mfa_token": ...}` and
  the dashboard walks them through it (scan a QR code with Google/Microsoft Authenticator, Authy
  …, type a code, save the 10 recovery codes). Analysts can turn it on from the Account page.
- **Login with MFA:** `POST /auth/login` answers `{"mfa": "verify", "mfa_token": ...}`; then
  `POST /auth/mfa/verify {"mfa_token", "code"}` gives the access token. The `mfa_token` is a JWT
  with its own audience (`idps-soc-mfa`): it can never be used as an access token, works for
  `IDPS_SOC_MFA_CHALLENGE_MINUTES` (10), and stops working when the user's sessions are revoked.
- **Codes:** RFC 6238 (6 digits, 30 s, SHA-1), one step of clock skew either way. A code is never
  accepted twice: the last used step is stored and moved forward with a conditional UPDATE, so of
  two requests with the same code only one wins. Wrong codes count per user (from any address):
  after `IDPS_SOC_MFA_MAX_FAILURES` (5) the account's MFA step is locked for
  `IDPS_SOC_LOGIN_LOCKOUT_MINUTES`. Trade-off: someone who already knows the password can keep a
  user locked out of the MFA step by sending wrong codes (so can someone with a stolen session,
  with wrong passwords at enrolment) (a per-address limit alone would let a
  botnet guess codes). Treat repeated lockouts as a sign the password is stolen: change it.
- **Recovery codes:** 10 codes of 10 characters (50 bits each), shown once. Only an HMAC-SHA256
  of each is stored. Using one logs out the user's other sessions and is audited
  (`mfa_recovery_code_used`, with how many are left). `POST /auth/mfa/recovery-codes` replaces them.
- **Stored secret:** encrypted with AES-256-GCM, the user id as associated data. The key comes
  from `IDPS_SOC_MFA_KEY` (32+ characters; `_FILE` works too), or from the JWT secret when that is
  not set. Changing that key, or restoring a backup into a SOC with another key, means users set
  MFA up again (an admin resets it). Backups contain the encrypted secrets, never the key.
- **Turning it on or off** logs out every other session (`token_version`). Turning it on from a
  signed-in session needs the password again (`enrol/start` with `password`), so a stolen session
  token cannot put its own authenticator on the account. Analysts turn it off with their password
  and a code (`POST /auth/mfa/disable`); admins cannot while it is required. On these signed-in
  calls a wrong password or code is a **403**, not a 401, so a typo does not end the session.
- **Lost phone and codes:** an admin presses *Reset 2FA* on the Admin page
  (`POST /admin/users/{id}/mfa/reset`, audited). The last admin: `python -m soc.api mfa-reset
  <username>` on the SOC host. Scripted accounts: `python -m soc.api mfa-enrol <user>
  --secret-file PATH` writes the secret to a 0600 file and never prints it.
- **Known gap:** the first enrolment of an admin is protected by the password only. Set up MFA
  for every admin right after creating them (or pre-enrol with `mfa-enrol`), and keep the
  password policy (12+ characters).

### Single sign-on (OpenID Connect, optional)

Off unless `IDPS_SOC_OIDC_ISSUER` is set (with `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URI`
= the dashboard's `/auth/callback`, e.g. `https://soc.example.com/auth/callback`). The login page
then shows a *Sign in with single sign-on* button. Authorization code flow with PKCE (S256); the
SOC is a confidential client (client secret at the token endpoint). The ID token is checked
completely: signature with the provider's published keys (asymmetric algorithms only, never
`none` or a shared-secret HS*), issuer, audience, `azp`, expiry, issued-at and the nonce. The
state works once and only in the browser that started the sign-in (a binding secret kept in
sessionStorage), which stops login CSRF.

- **Nobody gets an account by signing in.** An admin creates the user first. The first sign-in
  matches `IDPS_SOC_OIDC_USERNAME_CLAIM` (default `preferred_username`; `email` only when the
  provider says it is verified) to the SOC username and links the provider's subject id to the
  account (`sso_link`, audited); after that only the subject id is used. Use a claim users cannot
  change themselves at the provider. An **admin is linked only once they have MFA**: otherwise a
  provider account with the same name could reach the "enrol" step and register an attacker's
  authenticator. Disabled accounts are never linked. *Unlink SSO* on the Admin page undoes a link.
- **MFA still applies:** an admin who signs in through the provider is asked for their
  authenticator code (or to enrol) exactly as after a password.
- The provider's metadata and keys are cached for an hour; a token with an unknown key id makes
  the SOC fetch the keys again once (a key the provider removes keeps working for up to that
  hour). The SOC needs outbound HTTPS to the provider (in the lab, add its host to
  `LAB_SOC_EGRESS_HOSTS`), and every endpoint in the provider's metadata must be https. Pending
  sign-ins are kept in memory (one process), at most 10 per client address (older ones are
  dropped), so a flood of starts cannot lock single sign-on out. Pass the client secret as
  `IDPS_SOC_OIDC_CLIENT_SECRET_FILE` rather than in the environment where you can.

### Sensor certificates (mutual TLS)

`python -m soc.api.serve` runs the API on two listeners in one process: the main port (dashboard)
and a **sensor port** that requires a client certificate signed by `--sensor-ca`:

```sh
python -m soc.api sensor-ca --out-dir ca/                       # once; keep ca/sensor-ca.key offline
python -m soc.api create-sensor edge-1                          # the token
python -m soc.api sensor-cert edge-1 --ca-dir ca/ --out-dir certs/
IDPS_SOC_SENSOR_MTLS_REQUIRED=true python -m soc.api.serve --host 0.0.0.0 --port 8443 \
    --ssl-keyfile server.key --ssl-certfile server.pem --sensor-port 8444 --sensor-ca ca/sensor-ca.pem
```

On the sensor: `IDPS_SOC_URL=https://soc:8444`, `IDPS_SOC_CLIENT_CERT=certs/edge-1.pem`,
`IDPS_SOC_CLIENT_KEY=certs/edge-1.key`, plus the token as before.

- A client without a certificate, or with one from another CA, fails the TLS handshake: it never
  reaches the application.
- The certificate's common name must be the name of the sensor whose token comes with the
  request, so a stolen token is useless without that sensor's private key, and one sensor's
  certificate cannot speak for another.
- The sensor port serves only `/ingest/*`, `/sensor/*` and `/health`.
- With `IDPS_SOC_SENSOR_MTLS_REQUIRED=true`, sensor requests on the main port get 401.
- To cut a sensor off, revoke its token (Admin page); its certificate alone is not enough.
  There is no certificate revocation list.
- `soc.api.serve` gives the sensor listener its own certificate (`--sensor-ssl-keyfile`,
  `--sensor-ssl-certfile`; default: `--ssl-keyfile`/`--ssl-certfile`) and always requires TLS
  there. The main listener may run without TLS (omit both `--ssl-*` options) behind a proxy, with
  `--proxy-headers --forwarded-allow-ips`: that is how [deploy.md](deploy.md) runs it, with the
  sensor port published directly and the main port reachable only by the proxy.
- The sensor port must be served by `soc.api.serve` itself. Behind a TLS-terminating proxy, such as the
  Caddy of the AWS deployment (`infra/`), the client certificate never reaches the SOC: there,
  leave `IDPS_SOC_SENSOR_MTLS_REQUIRED` off.
- uvicorn does not pass client certificates to applications, so the sensor listener uses a small
  subclass of uvicorn's h11 protocol (`MtlsH11Protocol`); `tests/test_soc_mtls.py` runs a real
  server and fails if a uvicorn upgrade breaks it.

### Signed models

See [live.md](live.md#signed-models): the sensor refuses a model without a valid Ed25519
signature from the configured public key, and reports the key id it checked (`model.signed_by`
in `/sensors/status`).

## Live feed (single process)

New alerts reach WebSocket clients through an in-process broadcaster (`soc/api/broadcast.py`).
Each client has a bounded queue; one that falls behind is disconnected (4408) and ingest never
waits for it. Because it lives in memory, run **one** API process. With several workers, a
client would only see alerts ingested by its own worker. Scaling out needs a shared bus
(PostgreSQL LISTEN/NOTIFY or Redis pub/sub) behind the same `publish` interface.

**Messages** (any signed-in user receives all of them; after the auth message the server sends
`{"type": "ready"}`, unchanged). Older clients ignore messages without an `id`.

- *Alert* (published after `POST /ingest/alerts` commits): the fields of `GET /alerts` (with `id`)
  plus `src_geo`, only in this message (not stored, not in `/alerts`):
  `{"lat": float, "lon": float, "country": str|null, "city": str|null, "source": "geoip"|"demo"}`
  or `null` when the source has no location. It comes from the same `GeoLocator` as
  `/geo/attacks` (same demo rules; it caches per address, 50,000 at most, so a lookup on the ingest
  path is a dictionary hit for repeat sources and a lookup failure only gives `null`).
- *Block event* (one per event of an accepted `POST /ingest/blocks`, published after the commit;
  nothing for a refused batch):
  `{"type": "block", "event": "blocked"|"unblocked"|"would_block", "sensor_id": int, "ip": str,
  "source": "auto"|"analyst", "at": ISO8601, "expires_at": ISO8601|null, "ttl_seconds": int|null,
  "reason": str, "geo": <as src_geo>|null}`. `at` is the SOC's time (for `would_block` the stored
  decision time); `expires_at` is set for `blocked` only and `ttl_seconds` is the given one or the
  remaining seconds; an analyst-confirmed unblock arrives as `unblocked`. An `unblocked` event that
  closed no active block (already expired or never known) is not published.
- *Bounds:* block messages may use at most half of a client's queue (`BLOCK_SHARE`); beyond that
  they are dropped for that client (counted in `Subscriber.blocks_dropped`, the client stays
  connected), so a burst of block reports cannot push alerts out or get a client disconnected. A
  client that falls behind on alerts is still disconnected (4408) as before.

## Rule alerts (roadmap step 8)

A sensor that runs Suricata next to the model (`docs/live.md`, "Rules next to ML") sends its alerts
through the same `POST /ingest/alerts`, marked `"source": "rule"` with a `rule` object. A sensor that
does not send `source` (every older sensor) is `"ml"`; so is every alert stored before the column existed
(NULL in the database, shown as `"ml"`).

```json
{"src_ip": "10.10.1.10", "src_port": 40000, "dst_ip": "10.10.2.11", "dst_port": 80, "protocol": 6,
 "start_ms": 1763200800250, "end_ms": 1763200800250,
 "predicted_class": "Scan", "confidence": 0.95, "source": "rule",
 "rule": {"sid": 2009358, "rev": 7, "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
          "category": "Web Application Attack", "severity": 1, "count": 1}}
```

- **Validation.** `source` is `ml` or `rule`. `source: "rule"` needs `rule`; `rule` on a model alert is a
  422. `rule`: `sid` 0 to 2^32, `rev` optional, `signature` 1 to 300 characters, `category` optional up to
  100, `severity` 1 to 4 (Suricata's, 1 most severe), `count` at least 1 (default 1); unknown keys, control
  and direction-override characters are refused. The rest is the model alert's validation
  (`predicted_class` 1 to 64 characters, `confidence` 0 to 1). `explanation` may be left out (it is then
  stored empty). `features`, `model_sha256`, `model_version` and `anomaly_score` on a rule alert are
  ignored (set to null) without counting them in `features_dropped`.
- **predicted_class** is the family the sensor derives (Scan, DoS, Web Attack, Brute Force, Malware,
  Exploit, Policy, or "Rule match"); **confidence** comes from Suricata's severity (1 -> 0.95, 2 -> 0.85,
  3 -> 0.70, 4 -> 0.55). **Severity** is the existing rule unchanged: the family's base severity
  (`SEVERITY_BY_CLASS`; the table now also has scan low, malware high, exploit high, policy low, and
  "Rule match" gets `default_severity`), lowered one level when confidence is under
  `IDPS_SOC_LOW_CONFIDENCE_BELOW` (0.6), which only a Suricata severity-4 rule reaches.
- **Reading.** `AlertOut` (lists, the live feed, cases) and `AlertDetail` both carry `source` and `rule`
  (`rule` is `null` for model alerts). `GET /alerts?source=ml|rule` filters (`ml` includes rows stored
  without a source). `GET /metrics/summary` has `by_source` for the window; its other figures count both
  sources. Rule alerts are triaged like any alert (status, cases). The assistant's `get_alert` and
  `search_alerts` show the `rule` object (inside the escaped `<soc_data>` wrapper), its prompt says a rule alert has
  no model score or SHAP explanation, and `get_playbook` knows the Scan and Malware families (Exploit, Policy and
  Rule match answer with a note).
- **Not training data.** `judged_alerts` (used by `GET /training/feedback` and `python -m
  soc.api.export_feedback`) only returns model alerts (`ml_alerts_clause`), so a rule alert an analyst
  confirmed or rejected is never exported, even if someone attached features to it.
- **Sensor status.** `POST /sensor/status` accepts `rules` (`enabled`, `eve_path`, `alerts_sent`,
  `dropped_engine`, `dropped_info`, `deduped`, `dropped_invalid`, `rate_limited`, `block_skipped`,
  `last_event_at`, `error`, `include_info`, `dedupe_seconds`, `max_per_minute`, `block_sids`); a sensor with the
  forwarder off sends no `rules` key; `GET /sensors/status` returns it in each sensor's
  `status` (`null` for sensors that do not send it). It is not redacted for analysts.
- **Upgrade.** Start the new SOC first: `init_db` adds `alerts.source` (indexed) and `alerts.rule`
  (JSON) to an existing database (nullable, no backfill). An SOC from before this step answers 422 to
  `source`/`rule` and to the `rules` status block.

## Integrations (roadmap step 9, B3)

Everything here is optional and off until configured. **Configuration is environment only** (or a
secret file, below): there is no API to set or read a URL, token or password, the admin endpoints
show only a host or a masked address, and nothing secret is logged or written to the audit log.
Set the variables in the API's environment (the lab: `lab/.env`, see `lab/README.md`).

Secrets (`WEBHOOK_URL`, `WEBHOOK_SECRET`, `SLACK_WEBHOOK_URL`, `SMTP_PASSWORD`, `ABUSEIPDB_KEY`) may
instead be read from a file, e.g. a Docker secret: `IDPS_SOC_WEBHOOK_URL_FILE=/run/secrets/hook`.
A blank value counts as unset. If both `IDPS_SOC_X` and `IDPS_SOC_X_FILE` are set, the direct
variable wins.

| Variable (`IDPS_SOC_` prefix) | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | none | Dashboard address, e.g. `https://soc.example.com`; alerts in messages link to `<url>/alerts/<id>` |
| `NOTIFY_ENABLED` | true | Kill switch for every channel |
| `NOTIFY_MIN_SEVERITY` | `high` | Notify for alerts at or above this (`low`, `medium`, `high`, `critical`): high and critical by default |
| `NOTIFY_QUEUE_SIZE` | 500 | Per-channel in-memory queue; when full, messages are dropped (counted) |
| `NOTIFY_MAX_ATTEMPTS` / `NOTIFY_BACKOFF_SECONDS` | 3 / 1.0 | Tries per message; wait doubles each time (1 s, 2 s, ...; at most 30 s) |
| `NOTIFY_RATE_PER_MINUTE` | 20 | Per channel. Beyond it alerts are held back and, as soon as there is room, one message says "and K more" with counts by severity and class |
| `NOTIFY_DEDUPE_SECONDS` | 300 | The same (class, source address), or (rule, source, destination, port), is sent once per window; a higher severity is still sent. A folded rule alert (a follow-up with a larger count) is a repeat of its first. 0 = off |
| `NOTIFY_TIMEOUT_SECONDS` | 5 | Deadline for the WHOLE exchange of one send (connect, handshake, request, answer; SMTP: the whole conversation), so a server dribbling bytes cannot hold a worker. Answers are read only up to 4 KB |
| `NOTIFY_ALLOW_PRIVATE`, `NOTIFY_ALLOW_HTTP` | false | **Dev/lab only**, see "Webhook destinations" |
| `WEBHOOK_URL`, `WEBHOOK_SECRET` | none | Generic webhook; with a secret every body is signed |
| `WEBHOOK_MIN_SEVERITY`, `WEBHOOK_INCLUDE_RULES` | global, true | Per-channel threshold, and whether Suricata (`rule`) alerts are sent |
| `SLACK_WEBHOOK_URL`, `SLACK_MIN_SEVERITY`, `SLACK_INCLUDE_RULES` | none, global, true | Slack incoming webhook |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` | none, 587 (465 for `ssl`), `starttls` | `starttls`, `ssl`, or `none` (a local test receiver only; a password is never sent without TLS). With `starttls`, a server that does not offer STARTTLS is a permanent failure: there is no plaintext fallback |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | none | Optional login |
| `SMTP_FROM`, `SMTP_TO` | none | One sender; up to 20 comma-separated recipients. Email needs host, from and to |
| `EMAIL_MIN_SEVERITY`, `EMAIL_INCLUDE_RULES` | global, true | |
| `SYSLOG_HOST`, `SYSLOG_PORT`, `SYSLOG_PROTOCOL` | none, 514, `udp` | `udp`, `tcp` or `tls` |
| `SYSLOG_CA_FILE` | system CAs | TLS: the CA that signed the receiver's certificate (the host name is checked) |
| `SYSLOG_MIN_SEVERITY`, `SYSLOG_INCLUDE_RULES`, `SYSLOG_INCLUDE_BLOCKS` | `low`, true, true | A SIEM wants the whole stream: every alert, and block events |
| `SYSLOG_RATE_PER_MINUTE` | 0 (off) | The syslog channel has no dedupe and, by default, no rate limit |
| `SYSLOG_IDLE_SECONDS` | 60 | TCP/TLS: a link idle this long is reopened; a link the receiver has closed is always replaced before sending |
| `ABUSEIPDB_KEY`, `ABUSEIPDB_CACHE_HOURS` | none, 24 | See "Reputation" |
| `ABUSEIPDB_TIMEOUT_SECONDS`, `ABUSEIPDB_MAX_PER_MINUTE`, `ABUSEIPDB_MAX_PER_DAY` | 5, 30, 900 | Timeout for the whole exchange; most uncached lookups per minute and per day (the free tier allows 1,000 a day) |

### How delivery works

New alerts are offered to the channels after the ingest transaction has committed. That step only
filters (severity, source, duplicates) and puts a small record on a bounded in-memory queue; it does
no network I/O and never raises into the request, so a dead Slack or SIEM cannot slow or fail
ingest. One background thread per channel sends, with retries and backoff for transient errors
(network failure, timeout, HTTP 408/425/429/5xx, SMTP 4xx) and none for permanent ones (other 4xx,
refused login, a refused destination). Counters per channel: `sent`, `failed` (given up after the
last try), `dropped` (queue full), `rate_limited` (held back, covered by a digest), `deduped`.
The queue is in memory: alerts queued when the API stops are not sent. The SOC runs as one process
(see "Live feed"), so there is one queue per channel.

Messages are small: class, severity, source (`ml` or `rule`) and rule signature and sid, source and
destination address and port, sensor, time and a link. Never the features or the explanation.
Text an attacker can influence (the class, a rule signature) is cleaned of control and
direction-override characters and escaped for where it lands: Slack text is put in code spans with
`& < >` escaped (so `<!channel>` or a link cannot be injected), email HTML is escaped and no newline
can reach a header, CEF values are escaped.

### Channels

- **Generic webhook.** `POST` of JSON (`Content-Type: application/json`). With `WEBHOOK_SECRET` the
  request carries `X-IDPS-Timestamp: <unix seconds>` and `X-IDPS-Signature: sha256=<hex>`, the
  HMAC-SHA256 of `"<timestamp>." + <exact body bytes>`. A receiver must verify the signature over
  the raw body, compare it in constant time, and **reject a timestamp more than a few minutes
  (say 5) from its own clock**, so a captured message cannot be replayed later. Body for an alert:
  `{"type":"idps.alert","version":1,"id":12,"severity":"high","class":"DoS","source":"ml","rule":null,
  "src":{"ip":"203.0.113.7","port":51514},"dst":{"ip":"10.10.1.5","port":80},"protocol":6,
  "sensor":"lab-sensor","at":"2026-11-15T12:00:00Z","url":"https://soc.example.com/alerts/12"}`.
  For a rule alert `rule` is `{"sid","signature","category","count"}`. Other types: `idps.digest`
  (`more`, `blocks`, `by_severity`, `top_classes`; `blocks` counts held-back block events, which
  only syslog receives) and `idps.test`.
- **Slack.** An incoming-webhook message with Slack blocks: a header ("HIGH alert: <class or
  signature>"), fields (severity, source, class, sensor, from to, rule and sid) and an "Open alert"
  button when `PUBLIC_URL` is set.
- **Email.** Plain text plus HTML, one message per alert to all recipients; the subject is
  `[IDPS] HIGH alert: DoS`.
- **Syslog/CEF.** RFC 5424 messages (facility local0, app `idps-soc`, MSGID `ALERT`, `BLOCK`, `TEST`
  or `DIGEST`) whose text is CEF:
  `CEF:0|IDPS|IDPS SOC|<version>|<class or rule sid>|<name>|<0-10>|rt=... src=... dst=... spt=... dpt=... proto=TCP cat=<class> cs1Label=source cs1=ml|rule dvchost=<sensor> externalId=<alert id>`;
  rule alerts add `cs2Label=ruleSignature cs2=<signature>`, `cs3Label=ruleCategory` and `cnt`. CEF
  severity: low 3, medium 5, high 8, critical 10. In the header `\` and `|` are escaped; in values `\`
  and `=` are, and newlines become `\n`. Block events (`blocked`, `unblocked`, `would_block`) are sent as
  `CEF:0|IDPS|IDPS SOC|<v>|blocked|IP blocked|6|rt=... act=blocked src=<ip> dvchost=... reason=...`.
  UDP is one datagram per message; TCP and TLS use RFC 6587 octet counting (`<length> <message>`) on
  a connection that is kept open and reopened after an error. TLS verifies the receiver's
  certificate against `SYSLOG_CA_FILE`.

### Webhook destinations (SSRF guard)

The webhook and Slack URLs are checked every time before connecting: **https only**; the host name
is resolved by the SOC and the connection goes to that checked address (a second DNS answer cannot
redirect it, and the certificate is still checked against the name); a name that resolves to any
private, loopback, link-local, multicast or otherwise non-public address is refused (IPv6 forms
that carry an IPv4 address (mapped, NAT64, 6to4, Teredo, IPv4-compatible) are judged by the address
inside; decimal, octal and short spellings are judged by what the resolver returns); no credentials in the URL; **redirects are never followed** (a 3xx
is a failure); timeouts are short and responses are read only up to 4 KB. Errors shown to admins
never include the URL. `NOTIFY_ALLOW_HTTP=true` and `NOTIFY_ALLOW_PRIVATE=true` switch the https
and the public-address rules off. **They are for development and the lab only** (a receiver on
127.0.0.1); do not set them in a real deployment. Syslog and SMTP hosts are chosen by the operator
and are not subject to this check.

### Admin endpoints

`GET /admin/integrations` (admin):

```json
{"channels": [
  {"channel": "webhook", "configured": true, "enabled": true, "min_severity": "high",
   "include_rules": true, "target_hint": "hooks.example.com",
   "last_success_at": "2026-11-15T12:00:03Z", "last_error": null, "last_error_at": null,
   "queued": 0, "sent": 12, "failed": 0, "dropped": 0, "rate_limited": 0, "deduped": 3},
  {"channel": "slack", "...": "same keys"}, {"channel": "email", "target_hint": "smtp.example.com:587 to ***@example.org", "...": "..."},
  {"channel": "syslog", "target_hint": "tcp://siem.example.com:6514", "min_severity": "low", "...": "..."}],
 "abuseipdb": {"configured": true, "cache_hours": 24.0}}
```

`channel` is always in the order webhook, slack, email, syslog. `configured`: the settings are
there; `enabled`: configured and `NOTIFY_ENABLED`. `target_hint` is the host only (webhook, Slack),
the SMTP host and port with masked recipient domains, or `protocol://host:port` (syslog); null when
not configured. `last_error` is a short fixed-form text such as `HTTP 500`, `timed out`,
`connection failed (ConnectionRefusedError)` or `destination refused: ...`. Dedupe only remembers
an alert once it is queued, and forgets it again if its delivery finally fails, so a failed or
dropped message does not suppress the next one. At shutdown, queued and held-back messages are
counted as `dropped`.

`POST /admin/integrations/{channel}/test` (admin, no body) sends a message labelled as a test
("IDPS SOC test message: this is not an alert") once, without retries, and answers 200:

```json
{"channel": "webhook", "ok": false, "error": "HTTP 500", "duration_ms": 41,
 "tested_at": "2026-11-15T12:00:00Z"}
```

`ok: true` gives `error: null`. A failed delivery is still a 200 with `ok: false`. 409: the channel
is not configured (or `NOTIFY_ENABLED` is false); 429: more than 3 tests for that channel in a
minute; 422: unknown channel. Each test is audited as `integration_test` on
`integration:<channel>` with `{"ok": ..., "error": ...}` (no destination). A test does not change the
counters but does update `last_success_at` / `last_error`.

### Reputation (AbuseIPDB)

`GET /alerts/{id}/reputation` (analyst or admin) answers with AbuseIPDB's view of the alert's
**source** address. The dashboard calls it only when an analyst opens it; nothing is looked up at
ingest or for lists.

```json
{"ip": "45.33.32.156", "available": true, "reason": null, "abuse_confidence": 87,
 "total_reports": 42, "country": "NL", "isp": "Example Hosting BV",
 "usage_type": "Data Center/Web Hosting/Transit", "last_reported_at": "2026-11-14T10:00:00+00:00",
 "checked_at": "2026-11-15T12:00:00Z", "cached": false}
```

All keys are always present. When nothing is available: `available: false`, `reason` is one of
`"private address"` (private, loopback, link-local, documentation or other non-public: never sent
anywhere), `"not configured"` (no `IDPS_SOC_ABUSEIPDB_KEY`), `"lookup failed: <short reason>"`
(timeout, quota, rejected key, bad answer) or `"too many lookups; try again in a minute"`; the
other fields are null. 404 for an unknown alert. Results are cached in memory for
`ABUSEIPDB_CACHE_HOURS` (24); `cached: true` repeats the original `checked_at`. Errors are not
cached. The cache is per process and empty after a restart.

Each real lookup is audited as `reputation_lookup` on `alert:<id>` with `{"ip", "available"}` (who
looked up which address); cache hits and refused addresses are not. Concurrent lookups of one address
share one request. Limits: `ABUSEIPDB_MAX_PER_MINUTE` and `ABUSEIPDB_MAX_PER_DAY` (reason
`"daily lookup limit reached"`); the cache is an LRU of at most 10,000 addresses.

**Privacy.** A lookup sends the alert's source IP address to AbuseIPDB, a third party, together
with your API key, and nothing else (no alert, destination, sensor or user data). Only public
addresses are sent, and only when someone opens the reputation of that alert. AbuseIPDB sees the
SOC's server address and which addresses you are investigating. Leave `ABUSEIPDB_KEY` unset if that
is not acceptable.

## Learning from analysts (roadmap B1)

**What a sensor sends.** Each alert may carry `features` (the flow's model features, a JSON object
of `MODEL_FEATURES` names to finite numbers, at most 4 KiB; unknown names are refused),
`model_sha256` (64 hex) and `model_version` (at most 80 characters). All optional: older sensors
send none and their alerts simply cannot become training rows. **Upgrade the SOC before the
sensors.** A newer SOC tolerates version skew: an unusable `features` (unknown or missing names,
not finite, over the cap, too big a number, `{}`) or an odd `model_sha256` / `model_version` is
dropped from that alert, the alert is stored, and the ingest answer counts them
(`features_dropped`, `model_info_dropped`; the audit row too). An older SOC refuses unknown
fields outright (422 for the whole batch), so a new sensor against an old SOC must run with
`IDPS_LIVE_SEND_FEATURES=false`. `features` must hold every `MODEL_FEATURES` name or be absent. `GET /alerts/{id}` shows
`model_sha256`, `model_version`, `true_class` and `has_features`; the feature vector itself is only
in `GET /training/feedback`.

**Verdicts.** `PATCH /alerts/{id}` takes `status` (now also `confirmed`, a true positive) and an
optional `true_class`: one of the CIC-IDS2017 class names (`idps.features.labels.CIC_CLASSES`,
exact spelling) or `BENIGN`. Left out it is kept, unless it contradicts the new status (BENIGN on a confirmed alert, an attack
class on a false positive), in which case it is cleared. A false positive may only carry `BENIGN`;
a confirmed alert may not be `BENIGN`, and the export labels a confirmed alert with its predicted
class when it has no other `true_class`. The audit row `alert_status` records
`{from, to, true_class: [old, new]}`.

**Model versions.** Every `POST /sensor/status` with a model digest upserts a `model_versions` row
per (sensor, sha256) (`name`, `version`, `first_seen`, `last_seen`). `GET /models` (analyst; revoked sensors, and models only they ran, are hidden from analysts, admins see all) lists
the versions, newest first, with the sensors that ran each and which of them run it now (that
sensor's latest status names this sha256). `GET /sensors/status` shows each sensor's
`model.sha256` / `model.version` and its `drift` object (see `docs/live.md`, "Model version and
drift").

**Export and retrain.**

```sh
python -m soc.api.export_feedback --db sqlite:///soc.db --model models/week_xgboost.joblib \
    -o data/processed/feedback.parquet
python -m idps.detect retrain --data data/processed/{monday,tuesday,wednesday,thursday,friday}_labelled.parquet \
    --feedback data/processed/feedback.parquet --current models/week_xgboost.joblib \
    -o models/week_xgboost_v2.joblib
```

The export keeps alerts that are `false_positive` (label `BENIGN`) or `confirmed` (label
`true_class`, else the predicted class), have features, and were scored by exactly this model
(`alert.model_sha256` equals the model's digest, so rows an earlier round already trained on are
not used twice). Repeated ingests of one flow (same sensor, 5-tuple, start and end) count once
(`duplicates`). Others are skipped and counted (`no_features`, `other_model`, `bad_features`). The
file has the model's extraction metadata, so `read_features` / `check_same_extraction` work on it.
`retrain` first drops duplicate feedback vectors, then splits each label by time (oldest 70% train,
newest 30% holdout) and trains the same model type on the base training rows plus the training part
(weighted `--feedback-weight`, default 5; a class only the feedback has is weighted 1 and named in
the report as a new class). It refuses data that does not reproduce the current model's split
(`--allow-different-base` overrides, and the report says so). It never keeps a model when the
holdout has fewer than `--min-holdout` (5) rows. It writes the new model only if macro-F1 on the
current model's own base test split is within `--tolerance` (0.005) of the current model's AND
accuracy on the feedback holdout is at least the current model's. Otherwise it exits 3 and writes
nothing; it never writes over `--current`. A comparison report goes to
`reports/retrain_<version>.json` either way. `GET /training/feedback` (admin only, audited as
`training_feedback_read`; `limit` up to 1000, `after_id`, `model_sha256`) returns the same rows as
JSON.

## Database

SQLite (`sqlite:///./soc.db`) for development and small labs; PostgreSQL for deployment:

```bash
pip install -e ".[postgres]"        # the psycopg 3 driver
export IDPS_SOC_DATABASE_URL='postgresql+psycopg://idps:PASSWORD@db-host:5432/idps'
```

Timestamps are stored and returned as timezone-aware UTC. Tables: `users`, `sensor_tokens`,
`alerts`, `blocks`, `actions`, `cases`, `case_notes`, `audit_log`, `would_blocks`,
`sensor_status`, `model_versions`, `assistant_conversations`, and Alembic's `alembic_version`.

### Migrations

The schema is made by Alembic migrations (`soc/api/migrations/versions/`, shipped with the
package), not by `create_all`. Revision `0001_initial` is the schema as of roadmap step 10 and is
written out by hand: it never imports the models, so later model changes cannot alter it.

At start-up (`python -m soc.api ...` commands and the API) the SOC looks at the database:

| Database | What happens |
|---|---|
| empty | `upgrade head` |
| has tables, no `alembic_version` (made before step 10) | **adopted**, see below, then `upgrade head` |
| versioned, `AUTO_MIGRATE=true` (default) | `upgrade head` |
| versioned, `AUTO_MIGRATE=false` | refuses to start unless already at head, naming `python -m soc.api db upgrade` |
| versioned at a revision this version does not know | refuses to start (the database is newer than the SOC) |

On PostgreSQL the migration runs under `pg_advisory_lock`, so two processes starting together
cannot both migrate (the second waits, then finds nothing to do), and each migration is one
transaction. Set `AUTO_MIGRATE=false` when several SOC versions may start against one database or
you want to run the upgrade yourself as a deployment step.

```bash
python -m soc.api db upgrade     # empty / adopt / upgrade to head (also with --database-url URL)
python -m soc.api db current     # prints the revision
python -m soc.api db check       # exit 1 if not at head, or the schema differs from the models
```

**Adopting a database made before step 10.** Such a database has the tables but no
`alembic_version`. The SOC first runs the old temporary `compare_metadata` check of the
database against revision 0001 (its own table definitions, not the live models) **before changing
anything**. Only plain additions an older release could lack are allowed: a missing nullable
column, a missing table, a missing non-unique declared index (the old stop-gap only indexed the
columns it added). Anything else (a missing NOT NULL column, a different type or nullability, a
missing unique index) makes the SOC refuse to start with a one-line message saying what differs,
and **nothing has been changed**; fix it by hand or restore a backup. Extra tables and indexes the
SOC does not know are ignored. If only additions are needed, they are made (`soc.api.db.upgrade_schema`
for columns, `CREATE TABLE`/`CREATE INDEX` for the rest), the result is checked again, and the SOC
stamps `0001_initial` and upgrades to head. Take a backup first (below).

**Making a new migration** (developers): change `soc/api/models.py`, then

```bash
export IDPS_SOC_JWT_SECRET=... IDPS_SOC_DATABASE_URL=sqlite:///./dev.db   # a database at head
alembic revision --autogenerate --rev-id 0002 -m "what changed"          # uses ./alembic.ini
```

and **review the file**: autogenerate misses renames (it writes a drop and an add, which loses
data), server defaults and some type changes, and a new NOT NULL column on a table with rows needs
a default or a backfill. Migrations run in batch mode on SQLite (`render_as_batch`), which rebuilds
the table; constraints in the models that have no name cannot be dropped in batch mode, so give
new constraints a name. Do not edit a migration that has been released. Then run `db check` on a
copy of production data, and `python -m pytest`.

### Retention

A background thread (started with the API, first pass about 30 seconds after start, then hourly;
never on a request) deletes old rows in batches of 500, one transaction per batch, so writers are
not blocked for long. Errors are logged and never stop the app. `0` keeps a kind of data forever.

| Setting | Default | Deletes |
|---|---|---|
| `ALERT_RETENTION_DAYS` | 180 | alerts by `received_at` |
| `ALERT_RETENTION_KEEP_LABELLED` | true | exception: confirmed / false-positive alerts that carry features |
| `AUDIT_RETENTION_DAYS` | 365 | audit entries |
| `ASSISTANT_RETENTION_DAYS` | 90 | assistant conversations, by last update |
| `CLOSED_CASE_RETENTION_DAYS` | 0 | closed cases and their notes, by last update; their alerts stay (unlinked) unless old enough themselves |
| `WOULD_BLOCK_RETENTION_DAYS` | 7 | would-block records (also pruned on the block ingest path, as before) |
| `ACCESS_LOG_RETENTION_DAYS` | 365 | access-log rows (who looked at personal data) |

Rules: an alert linked to a case that is **open or investigating** is never deleted. Blocks and
actions are never deleted; when an alert goes, the `alert_id` of its blocks and would-blocks is set
to NULL. Every run that deleted something writes one audit entry `retention_prune` (actor
`system`/`retention`) with the per-table counts; that entry is itself only subject to
`AUDIT_RETENTION_DAYS`. `GET /admin/retention` (admin) shows the policy and the last run.
Deletes recheck the rules under a row lock, so an alert an analyst attaches to an open case (or a
case reopened) while a run is in progress is not deleted. A run that fails part-way still writes
its audit entry (with the counts so far and an `error` field), and `GET /admin/retention` shows
them. The first run after start logs the active policy as a warning. `python -m soc.api prune
--dry-run` prints what would go; `prune` runs one pass now. Both need the database at head (`db
upgrade` first), but not the JWT secret.

Privacy trade-off of `ALERT_RETENTION_KEEP_LABELLED`: analyst-judged alerts are the training rows
for `python -m soc.api.export_feedback` and retraining, so they are kept past the alert retention.
They contain source and destination IP addresses and flow features, for as long as you run the SOC.
Set it to `false` if your retention promise to the people whose traffic this is must be absolute;
you then lose that training data once alerts age out (export it first).

### Backup and restore

```bash
export IDPS_SOC_DATABASE_URL='sqlite:///./soc.db'      # or the PostgreSQL URL
python -m soc.api backup  /secure/soc-2026-11-15.jsonl.gz
python -m soc.api restore /secure/soc-2026-11-15.jsonl.gz     # empty database only
```

Both take `--database-url URL` too (to back up one database and restore into another from one
shell), but prefer the environment variable: a URL on the command line, with its password, shows
up in `ps` and in your shell history.

A **portable logical backup**: a gzip of JSON lines. Line 1 is a header (format, version,
Alembic revision, creation time, dialect, rows per table, sha256 of the rest), then every table's
rows in foreign-key order with lossless values (datetimes with time zone, JSON, bytes as base64).
Backup reads everything in one transaction (a single read transaction on SQLite, `REPEATABLE READ`
on PostgreSQL), so it is consistent while the SOC runs, and it streams: memory use does not grow
with the database (progress per table goes to stderr). The SOC opens file-based SQLite databases
in **WAL mode** with a 5 s busy timeout, so a backup's read snapshot does not block ingest (the
writer keeps going; the backup simply does not see rows written after it began; the `-wal` and
`-shm` files next to `soc.db` are part of the database, copy them together or use `backup`). WAL
needs a local filesystem. The file is written with mode 0600 through a
temporary file and renamed into place; an existing file is never overwritten. Nothing outside the
database goes in: not the JWT secret, not the environment.

Restore refuses unless the target has no SOC rows (an empty, freshly migrated database is fine),
checks the sha256 before touching it, migrates to the backup's revision, inserts in batches, resets
PostgreSQL id sequences, then upgrades to head, all in one transaction on PostgreSQL (a failed
restore leaves it empty). SQLite cannot roll schema changes back, so after a failed restore the
tables the restore itself created are dropped again and the database is empty. If a restore is
killed outright (SIGKILL, power loss) on SQLite, the database may be left with empty SOC tables and
no revision; restore treats exactly that (only SOC tables, all empty, no `alembic_version`) as an
empty target, drops them and starts over. Any rows, or any table that is not the SOC's, make it
refuse.

**Moving from SQLite to PostgreSQL:** stop the SOC, `backup` from the SQLite URL, create an empty
PostgreSQL database, `restore` into it with the PostgreSQL URL, point `DATABASE_URL` at it, start
the SOC. The same works the other way.

A backup holds **personal data** (IP addresses, usernames, analyst notes, assistant conversations)
and **password and sensor-token hashes**. Store it encrypted, keep access to the people who
administer the SOC, and delete old backups on the same schedule as the retention above: a backup
outlives retention for as long as it exists.

## Reports (roadmap step 13)

A weekly PDF: `GET /reports/weekly?week=YYYY-Www` (any signed-in user; default the last complete ISO
week, Monday 00:00 to Monday 00:00 UTC; the current week gives a report marked partial; a future or
nonexistent week is 422). `GET /reports/weeks` lists the last 12 complete weeks with their alert
counts and whether a run or email exists. Every download is access-logged (see "Privacy").

Contents (`soc/api/reports.py`, reportlab): title block (week, generated at, SOC version), headline
numbers (alerts by severity, model versus rule alerts, blocks, would-blocks, false-positive rate,
detection latency p50 and p95), an alerts-per-day chart, a by-class table, the top 10 source
addresses, blocks and would-blocks, analyst triage (alert statuses, cases opened and closed), model
health (models seen that week, each sensor's online state, model and version, drift level,
explanation faithfulness and outbox size as of generation time), and a footer on every page with the
page number and "Contains personal data (IP addresses): handle under the SOC privacy notice".
`IDPS_SOC_REPORT_MASK_IPS=true` hides the last octet of the addresses shown (IPv6: keeps the first
48 bits). Text that came from sensors (class names, model names) is escaped, never read as markup.

Speed: everything is aggregated in SQL over the week's window (the `received_at` index), two passes
over that week's alerts, seven index-only counts for the chart and a sample of the newest 20,000 for
the latency percentiles. No alert is loaded into memory. On a synthetic SQLite database of 1.08 million alerts
(668,000 of them in the week) the report took 2.6 s; at most two reports are built at once per process (a third
request gets 429). Would-block records only exist for `WOULD_BLOCK_RETENTION_DAYS` (7), so an older
week shows fewer than were made (the report says so).

Emailing is off by default. With `IDPS_SOC_REPORT_EMAIL_ENABLED=true` and the SMTP settings (see
"Integrations"), a background thread (`ReportRunner`, like retention) checks every 5 minutes and, once
`REPORT_EMAIL_WEEKDAY` (0 = Monday) and `REPORT_EMAIL_HOUR_UTC` after the end of the last complete week
have passed, emails that week's PDF as one attachment (at most 10 MB) to `REPORT_EMAIL_TO` (default
`SMTP_TO`) through the same SMTP code as the alert email (STARTTLS or SSL, never plaintext with a
password). The week is claimed first by inserting a row in `report_runs` (the week is unique), so a
restart or a second process never sends it twice; a claim that did not end in a sent email (the
process died, or the server refused) is tried again after an hour, until a day after the scheduled
time, and the error (never an address) is in `report_runs.error` and `GET /reports/weeks`.
`POST /admin/reports/weekly/email` sends now whether or not the schedule is on; it is only audited
(`report_email`) and never touches `report_runs`, so a manual send of an unfinished week does not
stop the scheduled full-week email and a failed manual re-send does not undo a sent one.

## Privacy (roadmap step 13)

The full picture, what the admin does for a request and what erasure cannot reach, is in
[privacy.md](privacy.md). In short:

- **Privacy notice.** `GET /privacy/notice` is public (people whose traffic is monitored have no
  SOC account). It returns the controller and contacts from `PRIVACY_CONTROLLER_NAME`,
  `PRIVACY_CONTACT_EMAIL` and `PRIVACY_GRIEVANCE_OFFICER` (blank = null), the categories of personal
  data, the purposes, the retention settings actually in force, the recipients (configured
  integrations by channel name only, never a URL, host or address) and the rights with how to use them.
- **Access log.** Individual reads of an address write rows in `access_log`, committed before the
  answer is returned (together with the request's audit entry, if any): an alert's detail (source and
  destination address), a search of alerts, blocks or would-blocks by `ip`, an alert's reputation, a
  case (itself, then each attached alert's addresses, at most 100), the assistant's read tools
  (`search_alerts`, `get_alert`, `top_attackers`, `list_blocks`, `get_case`, with the addresses they
  returned), the training export, a report download (the addresses the PDF prints in full) and an
  erasure preview. NOT logged: the unfiltered alert, block, case and action lists, metrics,
  topology, the live feed and sensor status, which show many addresses at once. One row per address; the
  address is never stored, only `subject_fp`, an HMAC-SHA256 of the normalised address under a key
  derived (HKDF, info `access-log-subject-v1`) from `IDPS_SOC_MFA_KEY` or the JWT secret. If a row cannot
  be written the request fails with 500 and nothing is served. `GET /admin/privacy/access-log?ip=`
  fingerprints the question and answers "who looked at this address". Rows older than
  `ACCESS_LOG_RETENTION_DAYS` are deleted. Rotating the secret changes every fingerprint: older rows
  stay but stop matching a lookup.
- **Erasure.** `POST /admin/privacy/erase/preview` then `POST /admin/privacy/erase` (admin, which
  already needs MFA) remove an address in one transaction: the alerts it is source or destination of,
  its blocks and would-blocks, and every textual mention elsewhere becomes `[erased]` (matched as a
  token: `10.0.0.1` never hits `10.0.0.10`; IPv6 in any spelling and IPv4-mapped forms count).
  `soc/api/privacy.py` lists every field it rewrites (`REDACTION_TARGETS`) and a test fails when a
  table or column is added without deciding. A record (`erasure_records`) and an audit entry
  `privacy_erase` keep the fingerprint and the counts, never the address. A CIDR is refused: erase
  addresses one at a time.
- **Migration 0003** adds `access_log`, `erasure_records` and `report_runs`.

## Maps

- **Attack map** (`GET /geo/attacks?hours=24`, dashboard "Attack map"): the busiest attack
  sources placed on a world map, with lines to the protected site.
  - Real locations need the free MaxMind **GeoLite2 City** database: create a MaxMind
    account, download `GeoLite2-City.mmdb`, and set `IDPS_SOC_GEOIP_DB` to its path.
    Without it, public addresses can't be placed (the page says so).
  - Lab addresses are private and have no real location. `IDPS_SOC_GEO_DEMO=true` gives them
    made-up, stable locations named "Demo: ..."; the page labels these as not real. Keep it off
    for real results.
  - `IDPS_SOC_HOME_LAT`, `IDPS_SOC_HOME_LON` and `IDPS_SOC_HOME_LABEL` set where the attack
    lines end (the protected site).
- **Topology** (`GET /topology?hours=1`, dashboard "Topology"): hosts seen in alerts and the
  source-to-target pairs between them, coloured by highest severity. Both maps refresh on new
  alerts from the live feed.

## SOC assistant

A chat panel ("Assistant", and "Explain this alert with the assistant" on every alert) backed
by Claude, Google Gemini or Groq (`soc/assistant/`).

**Turning it on.** Set `ANTHROPIC_API_KEY` in the API server's environment (never in the
browser), or set `GEMINI_API_KEY` for the Gemini Developer API. A configured Gemini key selects
Gemini. `IDPS_SOC_GEMINI_MODEL` defaults to `gemini-3.8-flash`. For Groq set `GROQ_API_KEY`. It takes precedence over the other providers and uses
`IDPS_SOC_GROQ_MODEL` (default `openai/gpt-oss-20b`). Without any provider credential the
assistant is switched off. Each message costs API usage; limits below keep it bounded.

| Setting (`IDPS_SOC_` prefix) | Default | Meaning |
|---|---|---|
| `ASSISTANT_MODEL` | `claude-opus-5-5` | Model used |
| `ASSISTANT_EFFORT` | `medium` | Reasoning effort (`low` is cheaper and faster) |
| `ASSISTANT_RATE_PER_10MIN` | 20 | Messages per user per 10 minutes |
| `ASSISTANT_MAX_TURNS` | 30 | Messages per conversation |

Claude requests use server-side fallbacks (`fallbacks: "default"`), so if the model declines a
request the API retries it on a fallback model automatically. The system prompt and tool list
are constant and prompt-cached.

**What it can do.** It calls fixed tools (`soc/assistant/tools.py`); it never writes SQL:
`search_alerts`, `get_alert` (with the SHAP/LIME explanation), `top_attackers`, `list_blocks`,
`get_case`, `metrics_summary`, `get_playbook` (the response playbooks in `docs/playbooks/`,
mapped to MITRE ATT&CK), and `propose_block`. Tool arguments are validated before anything
runs, and at most 8 tool rounds run per reply.

**Safety.**
- `propose_block` only creates a **pending** action. Nothing happens until an analyst confirms
  it on the Actions page, and the usual block allowlist checks apply.
- Alert fields come from network traffic, so an attacker can influence them (prompt
  injection). Tool results are wrapped in `<soc_data>` and the system prompt tells the model to
  treat them as data and point out embedded instructions. The confirm-before-act rule is what
  makes this safe even if the model is fooled.
- Conversations are private to their user. API errors are reported without internal details.

**Endpoints.** `GET /assistant/status`, `GET /assistant/conversations`,
`GET /assistant/conversations/{id}`, and `POST /assistant/chat` (streams NDJSON events:
`conversation`, `text`, `tool`, `tool_result`, `action_proposed`, `error`, `done`).

**Evaluation.** For the report, write about 30 questions with answers you can check against the
database (for example "top attacker in the last hour") and score answer accuracy, the share of
correct block proposals, and response time.

## Upgrading an existing database

Start the new SOC against it: a database made before roadmap step 10 is adopted automatically
(see "Database", "Adopting a database made before step 10"), after which every later change is an
Alembic migration. Back it up first with `python -m soc.api backup` once adopted, or `pg_dump`; to copy the SQLite
file instead, copy `soc.db` together with its `-wal` and `-shm` files (SQLite may hold recent writes
there), with the SOC stopped: `backup` needs a
database that has been adopted already (`python -m soc.api db upgrade` does that). `python -m soc.api db
check` afterwards confirms the schema. The temporary `ALTER TABLE` stop-gap that earlier releases
ran at every start-up now runs once, during adoption only.

## Live demo

An admin can start a fixed attack run from the dashboard's "Live demo" page (port scan, SSH brute
force, SYN flood, then a wait of about 150 s for the flows to end) and everyone signed in can follow
the steps. It is **off by default**: set `IDPS_SOC_DEMO_TOKEN` (32 to 256 printable ASCII characters,
for the lab put it in `lab/.env`; `python -c "import secrets;print(secrets.token_urlsafe(32))"`).
While it is unset the runner endpoints answer 404 and `POST /admin/demo/run` answers 503.

Why a host runner: the SOC is isolated from the lab attacker on purpose and never connects to it,
and the browser can send no parameters. The SOC only keeps the request in memory (one run slot, no
migration, forgotten on restart). `scripts/demo_runner.py`, started on the lab host with the same
token in its environment (`python scripts/demo_runner.py --ca-file <ca.pem>`), polls
`GET /demo/runner/next` (this is also its heartbeat), runs the fixed scripts in the attacker
container with `docker compose exec` and reports each step to `POST /demo/runner/report`. The
runner authenticates with the `X-Demo-Token` header (constant-time comparison). Step keys, order and
labels are fixed in `soc/api/routes/demo.py`; reports are strict (unknown fields refused, notes plain
text up to 200 characters) and steps only move forward. A failed step skips the rest and fails the
run; a run not finished 15 minutes after it was requested expires; a running run whose runner has
not been heard from for 60 s (it reports at least every 15 s) is failed early with the note "runner
went away"; cancelling tells the runner to stop at its next report. Starting and cancelling are
written to the audit log (`demo_run`, `demo_cancel`) in the same transaction as the change: if the
audit row cannot be saved the run slot is put back as it was.

Token lockout trade-off: wrong tokens are counted per client address (10 in 10 minutes, then 429
for wrong tokens). A **correct** token is always accepted, even during a lockout. Every host-side
request reaches the SOC from the same address (127.0.0.1), so refusing the right token while locked
out would let anything on the host cut off a run in progress by sending ten bad tokens. The cost is
that the lockout only slows guessing; the 32 to 256 character secret is what makes guessing
infeasible, so use a long random one.

Runner safety: commands run in the attacker container under `timeout` (so they end even if the host
client is killed), and on cancel, timeout or Ctrl-C the runner also runs `pkill -f <fixed script>`
there (best effort; it needs `pkill` in the attacker image). Subprocesses get only `PATH`, `HOME`
and `DOCKER_*` (plus the lab password for the SSH step); the token is never passed on. The runner
refuses HTTP redirects, ignores proxy environment variables, and accepts `--poll-seconds` from 1 to
10 with an error backoff of at most 15 s, so it never looks offline (the SOC's threshold is 30 s).
`lab/.env` is read as plain text: inline comments and `$VAR` interpolation are not interpreted.
