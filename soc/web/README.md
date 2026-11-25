# SOC web dashboard

React + Vite + TypeScript dashboard for the SOC API (see ../../docs/soc.md for the API).

## Run in development

1. Start the API (from the repository root), with a development database and secret:

   ```sh
   export IDPS_SOC_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
   export IDPS_SOC_DATABASE_URL=sqlite:///./dev-soc.db
   python scripts/dev_seed.py --i-understand-this-adds-demo-logins   # optional demo data
   uvicorn soc.api.main:app --port 8040 --ws-max-size 65536
   ```

2. Start the dashboard (from this folder):

   ```sh
   npm install
   npm run dev                          # http://localhost:5173
   ```

   The dev server proxies `/api` (including the `/api/ws/alerts` live feed) to
   `http://127.0.0.1:8040`; set `IDPS_SOC_API` to select another development API. For a single-backend checkout, use `npm run dev:single` (default API port 8000).

Set `IDPS_DEMO_ADMIN_PASSWORD` and `IDPS_DEMO_ANALYST_PASSWORD` before seeding. Use distinct passwords of at least 12 characters. They are for a local development database only.

## Unified development and lab dashboard

Open **http://127.0.0.1:5173**. Choose **Development SOC** or **Lab SOC** on the sign-in screen or in the dashboard header. The two workspaces use the same React application, navigation and API client. Switching keeps the current section and clears record IDs and filters. Each workspace uses its own accounts, MFA, authorization and database.

For the existing project previews, start the **soc-api** launch profile, then **soc-web**. The latter now serves both workspaces. For a terminal launch, start your development SOC with its existing database, JWT and MFA settings, then run these commands from the repository root:

```sh
# The project development API normally listens on 8040. Override this for a different local API.
IDPS_SOC_API=http://127.0.0.1:8040 npm --prefix soc/web run dev
```

The lab SOC listens on HTTPS port 8443. The dashboard reads its public CA certificate from the running `idps-soc` container, or from a PEM file supplied in `IDPS_SOC_LAB_CA`. Restart the frontend after changing the certificate. A lab outage affects only the lab workspace. No second frontend server is required. For a built version, use `npm run build:unified` followed by `npm run preview:unified` in this folder. The regular `dist/` build still serves a single SOC; the dual-workspace build is in `dist-unified/`.

### Feature inventory

| Area | Functionality |
| --- | --- |
| Threat Center, alerts and maps | Live alert and block feeds, filters, alert explanations, triage, sensor health, model drift, world map and topology |
| Response and cases | Response policy, firewall and dry-run decisions, action approval, case membership and notes |
| Assistant and reports | Conversation history, streamed assistant replies, weekly reports, PDF download and email |
| Accounts and administration | Password and SSO login, MFA and recovery, account controls, users, sensor registration, model versions, integration checks and audit records |
| Privacy | Public notice, access log, erasure preview and erasure records |
| Cloud | Compute, storage, network, monitoring, cost, alerts and activity |
| IAM | Users, roles, groups, policies, effective permissions, login history and audit |
| Demonstrations | Live Demo status, steps and timing, plus C6 replay and observation on backends that provide C6. The unified lab view supports observation and cancellation of an existing live run. |

The lab image inspected for this integration predates Cloud, IAM and C6. Opening one of those sections identifies the missing lab endpoint and offers the development module. The dashboard checks the running API again after sign-in or refresh, so an upgraded lab can serve its own modules. Existing RBAC still controls access within each SOC.

Development browser requests use `/api`; lab requests use `/lab-api`, including WebSockets, streaming and authenticated downloads. The lab gateway exposes browser-facing operations. Sensor and runner clients continue using their existing backend addresses. Configure OIDC callbacks at `/auth/callback` for development and `/lab/auth/callback` for the lab on the unified origin if SSO is enabled.

## Checks

```sh
npm test            # vitest
npm run typecheck   # tsc
npm run build       # production bundle in dist/
```

## Security notes

- The access token is kept in memory and sessionStorage (cleared when the tab closes), sent
  only in the Authorization header, and never put in a URL. The live feed sends it as the
  WebSocket's first message.
- API data is always rendered as text; the dashboard never uses `dangerouslySetInnerHTML`.
- In production, serve `dist/` from the same origin as the API behind HTTPS, with a
  Content-Security-Policy such as `default-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'`,
  plus `X-Frame-Options: DENY` (the SOC's Caddyfile in `infra/templates/soc-user-data.sh.tftpl` sets
  both on API responses and caps request bodies with `request_body { max_size 11MiB }`).

## macOS application

Double-click **IDPS SOC.app** in `dist/macos/` to open the dashboard in a native Mac window. Choose the workspace on the sign-in screen and use its usual password and MFA. The desktop window has its own sign-in session. Use **View → Dashboard Home** to return to the dashboard, or **⌘R** to reload.

To build or rebuild the app on a Mac with Xcode Command Line Tools, Node and the dashboard's npm dependencies installed, run this from the repository root:

```sh
python3 scripts/build_macos_app.py
open "dist/macos/IDPS SOC.app"
```

The app first checks for the dashboard on loopback port 5173. If that frontend is offline, it serves the bundled dashboard using this checkout's Vite installation. If you move the checkout or replace Node, rebuild the app to refresh those paths. Quit closes the frontend only when the Mac app started it.

The Development SOC API on port 8040 and the Lab SOC API on port 8443 are separate services. Start the backend for the workspace you want to use as described above. Building the client copies the web assets and uses a local ad-hoc signature. The bundle is built for the architecture of the build Mac.
