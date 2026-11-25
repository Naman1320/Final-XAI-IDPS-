# SOC dashboard redesign: implementation plan

Source: the Claude Design wireframe "IDPS SOC Dashboard Wireframe" (7 screens), 13 Nov 2026.
Every screen in it already exists as a page in `soc/web/src/pages/`, so this is a **redesign
plus a few backend additions**, not a new app. Fits between week 14 (done) and week 17
(end-to-end tests and audit). Estimate: about 2 weeks.

## Progress (13 Nov 2026)

Each step: build, check in the browser preview, then tests by the test-runner subagent and a
review by the reviewer subagent, with their findings fixed before moving on.

| Step | State |
|---|---|
| Phase 1: tokens (light + dark), top-bar shell, one shared live socket, shared components | ✅ Done, tested, reviewed |
| Response (blocks + action queue + block form; replaces Blocks and Actions pages) | ✅ Done, tested, reviewed twice |
| Alert detail (flow, triage, "what happened" timeline, SHAP chart) | ✅ Done, tested, reviewed |
| Cases (list + open case side by side; one request per status) | ✅ Done, tested, reviewed |
| Maps (topology + world, one window in the URL, host panel, keyboard selection) | ✅ Done, tested, reviewed |
| Assistant (conversations + playbooks aside, proposal cards, switched-off state) | ✅ Done, tested, reviewed |
| Admin (users, sensors, audit log with event groups) | ✅ Done, tested, reviewed twice. Backend: `/admin/audit` takes `action` repeated (up to 20) |
| Threat Center (home page; replaces Metrics) | ✅ Done, tested, reviewed. Heatmap by day, sensor health and mode badge wait for Phase 3; traffic chart left for Phase 4 |
| Phase 3 backend (sensor status, class by day, would-block events) | ✅ Done, tested, reviewed; frontend wired (mode badge, heatmap, sensor health, policy + both allowlists, Admin last seen, "would block · dry-run") |
| "Can I trust it?" faithfulness card | ✅ Done, tested, reviewed twice |

Phase 1 and 2 are committed together on the `ui-redesign` branch (13 Nov 2026), not merged into `main` yet. Phase 3 and the trust card followed as 00685f6 (14 Nov 2026).

Things decided along the way:
- "Block…" links from Alert detail and Maps open the Response form filled in; the analyst
  picks the duration and confirms there. A sensor guessed from an address's newest alert is
  marked `sensor_guess=1`, so the form says to check it.
- Maps default window is 1 h (the force layout is slow on big windows); at most 150 hosts drawn.
- Admins can't change their own role or disable themselves from the page, but can change their
  own password; password resets use an inline password field (no browser prompt).
- The audit Event filter sends each group's exact action names to the API (server-side), so busy
  sensors' ingest rows don't hide older user or case events.
- The dev API started in an earlier session (port 8000) doesn't auto-reload: restart it to see
  backend changes in the browser preview.
- The assistant also accepts "port scan" and "web attacks" as playbook names.
- Threat Center: confirm/reject stay on Response (the home card links there); topology is a list of
  the busiest links, not the graph. The search box matches class names ignoring case (the API filter
  is exact), using the window's known classes. Live refreshes wait at most 5 s during a steady
  stream of alerts (`useLiveRefresh` max wait), and pending actions poll every 15 s instead.
- Phase 3: sensor data lives in new tables only (`sensor_status`, `would_blocks`), since the SOC has
  no migrations. A sensor shows online if it reported in the last 2 min; a revoked one is always
  offline. `checksum_ok` is always true (a sensor with a bad model file refuses to start).
  Would-block events carry the sensor's `decided_at`; the dashboard counts one for its block time
  and only for the same sensor. "Anomaly" in the heatmap = alerts the Isolation Forest also flags
  (benign-classified outliers never reach the SOC). Class-by-day is one query, cached 60 s; an
  existing DB needs the manual `CREATE INDEX` in docs/soc.md. `would_blocks` rows are deleted after IDPS_SOC_WOULD_BLOCK_RETENTION_DAYS (default 7).
- "Can I trust it?" (Alert detail): model-level SHAP/LIME deletion-test numbers, sent in the sensor
  status from `IDPS_FAITHFULNESS_REPORT`, with a verdict per method (≥2× better than random = ok).
  Bad results (null or negative ratios) are shown, not dropped. The model match is by file checksum
  (`model_check: "digest"`); `reports/friday_xgboost_faithfulness.json` was re-run on 14 Nov 2026
  (same numbers, now with `model_sha256`).
- Lab check (14 Nov 2026, rebuilt sensor + SOC, isolation checks passed; port scan from the
  attacker, `models/friday_xgboost.joblib`):
  - Dry-run: 1,024 flows → 1,024 PortScan alerts accepted by the SOC, 1 would-block sent, status
    every 30 s, no errors; SHAP p50 0.20 ms / p95 0.57 ms; flow end → alert ≈ 121 s.
  - Blocking (60 s and 300 s TTL): 1 real block, no would-block events; the attacker's port 22
    showed "filtered" during the block and "open" after it expired.
  - Dashboard against the lab SOC: "Blocking ON" badge, sensor health (online, model, heartbeat,
    allowlist), policy and both allowlists on Response, Admin last seen, firewall card with the
    countdown, "blocked · auto" in live alerts, the timeline's block and its end, the trust card
    matched by checksum with SHAP marked "used for this alert". All matched what the sensor did.
  - Known: about 200 alerts per 1,024-flow scan go out without SHAP (cap of 50 explanations per
    batch), so their trust card highlights no method.
- The old Metrics page's "by severity" table and alerts-over-time chart are gone with it;
  `recharts` is now unused but kept for the Phase 4 traffic chart.

## What the wireframe changes

| Wireframe screen | Today | Change |
|---|---|---|
| 1 · Threat Center | `/alerts` list and `/metrics` | New home page `/`: map, KPIs, class-by-day heatmap, live alerts, firewall, pending decisions, sensor health, topology preview |
| 2 · Alert detail | `AlertDetail.tsx` | Two columns: flow + triage + "what happened" timeline; explanation + trust card |
| 3 · Response | `Blocks.tsx` + `Actions.tsx` | One page `/response`: blocks table with countdown, action queue, policy, allowlist, block form |
| 4 · Assistant | `Assistant.tsx` | Conversation list on the left, tool-call chips, proposal card linking to the queue |
| 5 · Cases | `Cases.tsx` + `CaseDetail.tsx` | List and the open case side by side (`/cases/:id` keeps working) |
| 6 · Maps | `TopologyMap.tsx` + `WorldMap.tsx` | One page `/maps` with a toggle and a "selected host" side panel |
| 7 · Admin | `Admin.tsx` | Inline role select, sensors with "last seen", audit filter by event group, "load older" |

Shell: the left sidebar becomes the top bar with rounded tabs (Dashboard, Alerts, Response,
Cases, Maps, Assistant, Admin), a "Live feed" badge and a "Blocking ON / dry-run" badge.

## Data check: what exists and what doesn't

Already served by the API (frontend work only):
- Alerts, filters, triage status, explanation top features: `/alerts`, `/alerts/{id}`.
- KPIs, top sources, latency p50/p95, false-positive rate: `/metrics/summary`.
- Blocks with `source`, `expires_at`, `alert_id`: `/blocks`. Actions and confirm/reject: `/actions`.
- Cases, notes, attach alerts; topology; geo; assistant conversations; users, sensors, audit.
- "Response" column in live alerts: join alerts with `GET /blocks?active=true` by source IP on
  the client ("blocked · auto/analyst", else "observe").
- "What happened" timeline: built on the client from the alert's times, `/blocks?ip=` and
  `/actions` for that IP.
- Search box: a number opens `/alerts/:id`, an IP filters `/alerts?ip=`, anything else filters by class.

**Missing: needs backend work:**
1. **Sensor status** (sensor health card, policy card, allowlist card, mode badge, "last seen"
   in Admin). The SOC knows nothing about a sensor beyond its token today.
2. **Attack classes by day** (the heatmap). `/metrics/summary` has class totals only.
3. **LIME and faithfulness per alert.** The live loop runs SHAP only; LIME exists offline
   (`idps/explain/lime_explain.py`) and faithfulness is a model-level number in
   `reports/friday_xgboost_faithfulness.json`. **Decision needed, see below.**
4. **Network traffic chart** (flows/s vs alerts/s). Marked PLANNED in the wireframe itself.
5. **"Would block · dry-run"** response state. The engine logs `would_block` locally but never
   reports it to the SOC.

## Phases

### Phase 1: design tokens and shell (Opus, this session)
- `styles.css`: replace the tokens with the wireframe's palette (ground `#EEF1F4`, panel `#F8FAFB`,
  cards white with `#E2E6EA` borders, teal accent `#0F766E` / `#99F6E4`, red `#DC2626` for
  blocking, radii 22 px cards / 12 px controls, Inter). **Keep dark mode:** derive a dark set
  for every token (the wireframe is light only; the app supports both today).
- Severity colours: keep blue/amber/red/rose but check 4.5:1 text contrast on both themes.
- `App.tsx`: top-bar nav, wrapping at phone width; Live badge from `useLiveAlerts`; mode badge
  hidden until Phase 3 provides data.
- Routes: `/` → Threat Center; `/response` (redirect `/blocks`, `/actions`); `/maps?view=world|topology`
  (redirect `/map`, `/topology`); others unchanged.
- Shared components in `components/`: `Panel` (replaces `Card`), `Pill`, `Segmented`
  (`aria-pressed` buttons), `KeyValue` (`<dl>`), `TableBox` (horizontal scroll), `ConfidenceBar`,
  `Countdown` (block expiry bar), `Timeline`.

### Phase 2: screens on existing data (Opus, this session)
In this order, each a separate commit:
1. **Response**: merge Blocks + Actions. Block form takes `?ip=` so "Block source IP…" on an
   alert pre-fills it. Countdown re-renders each second; a block leaves "active only" when it expires.
2. **Alert detail**: header badges, flow `<dl>`, triage segmented control, add-to-open-case
   select + new case, timeline, SHAP bars (restyle `ExplanationChart`), "Explain with the
   assistant" link (`/assistant?alert=<id>`). Leave out the "In plain words" box for now: no
   source provides that text (the assistant can, once its API key is set).
3. **Cases**: split view with status filter; selecting a case updates the URL.
4. **Maps**: toggle, window select, node click fills the side panel (alerts, targets, max
   severity, active block), "Show its alerts", "Block…".
5. **Assistant**: conversation list, tool-call chips from the stream events, proposal card →
   `/response`, playbook list. Keep the "switched off" state when there's no key.
6. **Admin**: inline role select, audit event-group filter (all / actions / blocks / users,
   mapped to action names on the client), "Load older entries" via `next_cursor`.
7. **Threat Center** last, because it reuses pieces from the other screens: world map (lazy),
   KPI cards, live alerts table (sort, filter), firewall card, "needs your decision" card,
   topology preview (lazy). Heatmap and sensor health show a "waiting for data" state until Phase 3.

### Phase 3: backend additions (implementer subagent, Sonnet)
1. **Sensor status.** `POST /sensor/status` (sensor token), sent by the live loop every 30 s:
   dry-run flag, blocking enabled, policy (threshold, count, window, alert floor, block TTL,
   unblock grace, analyst-block cap), allowlist entries, model name + checksum ok, outbox size,
   SHAP p95, heartbeat state, interface. Stored as one row per sensor with `last_seen_at`.
   `GET /sensors/status` for any user (no tokens or hashes in it). Sensor side: a method in
   `idps/soc_client.py`, called from `idps/live/__main__.py`. A sensor not seen for 2 min shows offline.
   The Response allowlist card shows **both** lists: the SOC's `IDPS_SOC_BLOCK_ALLOWLIST` and the sensor's.
2. **Class by day.** `/metrics/summary` gains `by_class_per_day: [{day, class, count}]` for the
   last 7 days (Anomaly = Isolation Forest flag).
3. **Would-block events.** Report dry-run `would_block` decisions through `/ingest/blocks` as a
   new event type so the alerts table can say "would block · dry-run". Small; optional.
4. Tests for each in `tests/` (test-runner subagent); update `docs/soc.md` endpoint table.

Then wire Phase 2's waiting states to the new data.

### Phase 4: stretch
- Network traffic chart: add per-interval flow counts (from `idps/live/metrics.py`) to the sensor
  status payload, keep 60 min in memory on the SOC, draw with Recharts.
- LIME, depending on the decision below.

## Decided: LIME stays model-level (13 Nov 2026)

The wireframe shows a SHAP/LIME toggle, a "second opinion · LIME" card and a "Can I trust it?" card.
Chosen: **drop the toggle and the LIME card.** "Can I trust it?" shows the model-level
faithfulness (SHAP 38.6×, LIME 16.9×), sent in the sensor status from the faithfulness report.
Rejected: running LIME live on the sensor for high/critical alerts (seconds per flow, needs a
queue off the detection path, about 2 extra days). LIME stays an offline result for the report.

## Checks for every phase
- `npm run typecheck`, `npm test` (update `components.test.tsx`), `pytest` for backend changes.
- Look at it in the browser preview (`soc-api` + `soc-web` in `.claude/launch.json`) at desktop and
  phone width, light and dark.
- Code review by the reviewer subagent before each merge (never the model that wrote it).
- Keep the security rules: no tokens in URLs, allowlist checks unchanged, the assistant still
  only proposes.
