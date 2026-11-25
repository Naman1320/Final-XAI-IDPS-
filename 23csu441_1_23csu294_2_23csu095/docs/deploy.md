# Deploying the IDPS (roadmap step 12)

`deploy/install.sh` installs the SOC (dashboard, API, PostgreSQL) on one host with Docker Compose,
and a sensor on another. Version 0.2.0 is the first release with this packaging.

You need: Docker Engine with the Compose plugin 2.24+ (`docker compose version`), a Linux or
macOS host, and for building the images (`--build`) internet access to PyPI, npm and Docker Hub.
The IDPS images are not published anywhere: you build them on the host (`--build`) or load them
yourself (`docker load`) and pass `--image-tag`. The database image (`postgres:16-alpine`, or
`IDPS_DB_IMAGE` in the environment of the first run) is the one image the installer **pulls**
when it is missing; on an offline host, `docker load` it too, together with the base images
(`python:3.12-slim`, `node:22-alpine`, `caddy:2.11.9`) if you build there.

**Status of this packaging.** Tested here: install with a local address (`--host`), the sensor
port with and without client certificates, upgrade, restore, a failed upgrade with rollback, on
Docker Desktop for macOS (arm64). Not tested: `--domain` (Let's Encrypt needs a public host), a
Linux host, the sensor container capturing packets (`install.sh sensor` was only run with
`--no-start`, and the image was run once without host networking).

## Install the SOC

```sh
git clone <this repository> && cd idps-final-year-project
deploy/install.sh soc --host 203.0.113.10 --build        # an address or an internal name
deploy/install.sh soc --domain soc.example.org --build   # a public name: Let's Encrypt
```

It prints the dashboard URL and the path of the generated admin password (`deploy/secrets/admin_password`,
mode 0600; the password itself is never printed). The first admin must set up two-factor sign-in
(an authenticator app) at the first login: the dashboard walks you through it. Without `--host` or
`--domain` the dashboard is at `https://localhost/`.

Options: `--http-port N` (default 80), `--https-port N` (443), `--sensor-port N` (8444), `--project NAME`
(Compose project, default `idps`), `--build` (build the images from this checkout) or `--image-tag TAG`
(use `idps-soc:TAG` and `idps-proxy:TAG` that exist locally). Running it again is safe: secrets and
certificates that exist are kept, the stack is brought up to date.

### What `install.sh soc` does

1. Checks Docker and Compose versions.
2. Writes `deploy/.env` (0600) and, unless they exist, `deploy/secrets/db_password`,
   `jwt_secret`, `mfa_key` (0600, 256+ random bits from `/dev/urandom`, never printed).
3. Builds `idps-soc`, `idps-proxy` (`--build`), each tagged `:<version>` and `:<version>-<gitsha7>`
   (version from `pyproject.toml`; OCI labels version, revision and source).
4. Pulls the database image if it is missing, starts PostgreSQL, then runs `idps-init-pki` in the
   SOC image: a **sensor CA** (signs sensor client certificates) and a **server certificate for the
   sensor port** from a CA of its own (`server-ca.pem`), valid for the `--host`/`--domain` name plus
   `localhost` and `127.0.0.1`. The two CA private keys live in the `cakeys` volume, which only the
   one-off `soc-admin` service mounts; the running API gets the certificates and the server key
   (`pki` volume, read-only) and cannot sign anything. Changing `--host` re-issues the server
   certificate from the same CA (existing bundles stay valid) and restarts the SOC, which reads it
   only at start-up.
5. `docker compose up -d`, waits for the health checks (database migrations run at start-up).
6. Creates the first admin `admin` with the generated password (`python -m soc.api create-user
   --password-file`, the policy still applies; the password goes in on stdin to the container's
   tmpfs, never to its disk). If that fails the installer fails, unless the user `admin` exists
   already (then it says so and leaves the password alone).

The installer refuses to generate new secrets when `deploy/secrets` is gone but the database
volume still exists (a new `db_password` or `mfa_key` would not match the data): restore the
files from your backup first.

### What it does not do

It does not install Docker, open firewall ports, get you a DNS name, back up automatically, rotate
secrets or certificates (the server certificate lasts 365 days and is re-issued when you run
`install.sh soc` within 30 days of expiry; client certificates last 365 days: see "Renewing a
sensor certificate"), or manage several SOC
hosts: the SOC is one process (the live feed is in-process). It makes no model: train and sign
models as in [training.md](training.md) and [live.md](live.md). Helm and Kubernetes manifests are
not provided; Compose on one host is the supported shape.

## Ports

| Port (default) | Where | What |
|---|---|---|
| 443 | proxy | Dashboard and `/api/*` over HTTPS (`--https-port`) |
| 80 | proxy | Redirects to HTTPS (`--http-port`); Let's Encrypt validation for `--domain` |
| 8444 | soc | Sensor port: TLS with a **required client certificate** (`--sensor-port`) |
| 8000 | soc | The API itself, plain HTTP. **Not published**: only the proxy reaches it. The compose network has a fixed subnet (`IDPS_SUBNET`, default `172.28.77.0/24`; if it clashes with a network you have, set `IDPS_SUBNET`, `IDPS_IP_RANGE` (a part of it for the other containers) and `IDPS_PROXY_IP` (inside the subnet, outside the range) in `deploy/.env`: all three or none, and the installer checks they are consistent and that the subnet overlaps no existing Docker network, before it starts anything) and the proxy a fixed address (`IDPS_PROXY_IP`, `.200`), and only that address may set the client address with `X-Forwarded-For` (`IDPS_FORWARDED_ALLOW_IPS`): another container or the Linux host reaching port 8000 directly cannot spoof its IP to dodge the login throttle |
| 5432 | db | **Not published** |

The proxy serves the built dashboard (single-page app) and forwards `/api/*` to the SOC with the
`/api` prefix removed (WebSockets included). Request bodies are limited to 11 MiB. Responses carry
`X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy: no-referrer` and a
Content-Security-Policy that allows only the dashboard's own origin (`default-src 'self'`, inline
styles, `data:` images for the MFA QR code, `frame-ancestors 'none'`); the maps are drawn from data
bundled in the dashboard, so nothing is loaded from other sites. Sensors use the sensor port, never
the proxy (a TLS-terminating proxy cannot pass client certificates), and
`IDPS_SOC_SENSOR_MTLS_REQUIRED` defaults to true, so a token alone on the dashboard port is refused.

## TLS choices

- `--domain NAME`: Caddy gets a Let's Encrypt certificate (**this path is untested**: it needs a
  public host, which was not available when it was written). Needs ports 80 and 443 reachable from the
  internet and a DNS name pointing at the host (so `--http-port`/`--https-port` must stay default).
  HSTS (`max-age=31536000`) is sent for a domain only.
- `--host IP_OR_NAME` (or neither): Caddy's own CA signs the certificate (`tls internal`). Browsers
  warn until you trust its root. The installer saves it (public) as `deploy/caddy-root.crt` and prints
  how to trust it:

  ```sh
  docker compose --env-file deploy/.env -f deploy/compose/soc.yml -p idps cp proxy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt   # macOS
  sudo cp caddy-root.crt /usr/local/share/ca-certificates/idps-caddy.crt && sudo update-ca-certificates  # Debian/Ubuntu
  ```

  No HSTS is sent, so a wrong certificate never locks a browser out.
- The sensor port always uses the SOC's own CA (`ca.pem` in each sensor bundle), independent of
  these choices.

## Add a sensor

On the SOC host:

```sh
deploy/install.sh add-sensor edge-1
```

It creates the sensor token and a client certificate whose common name is the sensor's name and
writes `deploy/sensors/edge-1/` (0700; `token` and `client.key` 0600): `token`, `client.pem`,
`client.key`, `ca.pem` (the CA that signed the sensor port's server certificate) and `sensor.env`
(`IDPS_SOC_URL=https://<host>:<sensor-port>`). The SOC makes the sensor's private key here, so copy
the directory over a secure channel (scp) and delete your copy. To cut a sensor off, revoke its
token in the dashboard (there is no certificate revocation list).

### Renewing a sensor certificate

Client certificates last 365 days. On the SOC host, `deploy/install.sh renew-sensor edge-1` issues a
new certificate and key for the same sensor (the token is unchanged) into `deploy/sensors/edge-1/`;
copy `client.pem` and `client.key` to the sensor host and run `install.sh sensor ...` again there.
The new certificate and the existing bundle are staged in a temporary directory and swapped in one
step; only an existing, non-revoked sensor gets one. To retire a sensor instead, revoke its token and add a new one with another name.

On the sensor host (the checkout is needed there too, or at least `deploy/` and the images):

```sh
deploy/install.sh sensor --bundle ./edge-1 --interface eth0 \
    --model models/friday_xgboost.joblib --public-key model-signing.pub --build
```

This copies the model (and its `.sha256`, `.sig` and `.drift.json` when present) into
`deploy/sensor-data/models/` (world-readable, nothing secret), loads the bundle (token, client key,
certificates, public key) into the Docker volume `<project>_sensor_enrol` with a short-lived
network-less container, writes `deploy/.env.sensor` and (re)starts `deploy/compose/sensor.yml`: the
`idps-sensor` image on the host network with `NET_ADMIN` and `NET_RAW` and **no other capability**, a
read-only root filesystem and read-only mounts. The bundle is in a volume, written by root inside a
container, so the sensor can read the 0600 key without `DAC_READ_SEARCH`: that capability would let
a compromised container read any file of the host (`open_by_handle_at`, the "Shocker" escape). Models are never baked into the image. Without `--public-key` the sensor does not
check model signatures (a warning says so). Blocking stays in dry-run unless you set
`IDPS_ALLOWLIST` and the other settings in `deploy/sensor.extra.env` (see [live.md](live.md)).
Running it again stops the sensor, reloads bundle and model, and recreates the container (a renewed
certificate or a new model of the same name is picked up). `--no-start` only writes the files and validates the Compose file. A sensor on the SOC host itself
works the same (`--host` must then be an address the sensor can reach).

## Configuration and secrets

| File | Purpose |
|---|---|
| `deploy/.env` | Ports, host name, image tag, project (no secrets) |
| `deploy/secrets/db_password`, `jwt_secret`, `mfa_key` | Compose secrets, mounted at `/run/secrets/` and read by the SOC entrypoint into `IDPS_SOC_DATABASE_URL`, `IDPS_SOC_JWT_SECRET`, `IDPS_SOC_MFA_KEY`; never in `docker inspect` or the image |
| `deploy/secrets/admin_password` | The first admin's generated password. Delete it once you have changed the password |
| `deploy/soc.env` | Optional extra `IDPS_SOC_*` settings that are **not secret** (retention, block allowlist, severity map, ...; see [soc.md](soc.md)) |
| `deploy/sensors/NAME/` | Enrolment bundles |
| `deploy/sensor-data/`, `deploy/.env.sensor`, `deploy/sensor.extra.env` | Sensor host state |

All of these are in `.gitignore` and `.dockerignore`. The SOC container starts as root only to read the
secret files (they belong to whoever ran the installer) and runs the API as uid 10001, with a read-only
root filesystem and `no-new-privileges`; it holds `SETUID`, `SETGID` and `DAC_READ_SEARCH` only during that
short root phase (the API process has no capabilities: the fresh-install check reads `CapEff` of pid 1). Losing `jwt_secret` logs everyone out;
losing `mfa_key` makes stored MFA secrets unreadable (users re-enrol: `python -m soc.api mfa-reset`).
Keep `deploy/secrets` in your backups.

### Integration secrets

Webhook, Slack, SMTP, AbuseIPDB and similar secrets must not go in `deploy/soc.env` (it is passed as
plain environment variables, visible in `docker inspect`). The SOC reads
`IDPS_SOC_<NAME>_FILE=path` for each of them ([soc.md](soc.md), "Integrations"). Put the value in a
file under `deploy/secrets/` (mode 0600) and add a compose secret by hand to `compose/soc.yml`, e.g.

```yaml
services:
  soc:
    secrets: [jwt_secret, mfa_key, db_password, smtp_password]
    environment:
      IDPS_SOC_SMTP_PASSWORD_FILE: /run/secrets/smtp_password
secrets:
  smtp_password:
    file: ../secrets/smtp_password
```

The entrypoint starts as root, so the file's owner does not matter; the API reads the value at
start-up.

## Upgrade, rollback

```sh
git pull                              # or load newer images
deploy/install.sh upgrade --build     # or: --image-tag 0.3.0
```

1. Tags the running images `idps-soc:<old>-previous` and `idps-proxy:<old>-previous` (a rebuild of the
   same version cannot overwrite them) and records `IDPS_PREVIOUS_TAG`.
2. Takes a database backup **with the running (old) image**: `pre-upgrade-<old>-to-<new>-<time>.jsonl.gz`
   in the `<project>_backups` volume. If the backup fails nothing is changed.
3. Switches `IDPS_TAG`, starts the SOC (migrations run at start-up), waits for health, prints
   `python -m soc.api db current` and `db check`.
4. If the new version does not become healthy, it puts the old images back, exits non-zero and says
   so. If the old version cannot start either (a migration already changed the schema), it tells
   you to restore the backup.

`install.sh rollback` goes back to `IDPS_PREVIOUS_TAG` by hand. It first asks the previous image
whether it knows the database's schema revision: if the upgrade ran a migration it does not, and
rollback is **refused** (the SOC keeps running) with a pointer to `install.sh restore <pre-upgrade
backup>`. If the previous version still fails to start, the current one is started again. A plain
`install.sh soc` re-run keeps the current image tag (it does not jump back to the project version);
use `--build` or `--image-tag` to change it. The caller's `IDPS_*` environment never overrides
`deploy/.env`.
Upgrade the SOC first, then the sensors (an old sensor may send fields a new SOC refuses to, and the
reverse: see [live.md](live.md)).

**What the upgrade test proves.** `deploy/tests/upgrade.sh` starts from a *hybrid* 0.1.0: commit
6767ebb has no Dockerfiles, so its code is built with the new Dockerfiles, and three packaging files
(`serve.py`, `__main__.py`, `pki.py`) come from the new tree. Both versions have the same schema
revision, so the script first downgrades the database to `0001_initial`, which makes the upgrade
apply migration 0002 for real. It does not prove an upgrade from a historical release image (none
exists).

## Backup and restore

```sh
P=idps   # your project name
docker compose --env-file deploy/.env -f deploy/compose/soc.yml -p $P run --rm -T soc-admin \
    python -m soc.api backup /var/lib/idps-backups/manual-$(date -u +%Y%m%d).jsonl.gz
# copy one out of the volume:
docker run --rm -v ${P}_backups:/b --entrypoint cat idps-soc:<tag> /b/manual-YYYYMMDD.jsonl.gz > manual.jsonl.gz
```

```sh
deploy/install.sh restore pre-upgrade-0.1.0-to-0.2.0-20261116T111435Z.jsonl.gz   # a file in the backups volume
deploy/install.sh restore ./manual.jsonl.gz                                       # or a file on this host
```

`restore` checks the file (it is restored into a scratch SQLite database: that proves it is complete,
undamaged and of a schema this version knows, not which SOC made it), asks for confirmation (`--yes`
to skip), stops the SOC, makes a safety copy `pre-restore-<time>.jsonl.gz` of the current database
(**fatal if it fails**, the SOC is started again and nothing is deleted; `--no-safety-copy` to replace
the database anyway), then **replaces only the database volume** (`<project>_pgdata`) with an empty one, restores
the backup into it (the schema goes to the backup's revision, then the SOC's start-up migrates it to
head) and starts the SOC again. Secrets, certificates (`pki`, `cakeys`), `.env` and the backups
themselves are kept, so sensors and sessions' keys keep working. Do **not** use `uninstall
--delete-data` for this: it deletes the backups too. Details of the format are in
[soc.md](soc.md#backup-and-restore). Keep `deploy/secrets` and the `cakeys` volume in your own backups.

## Status and uninstall

```sh
deploy/install.sh status
deploy/install.sh uninstall                 # containers and network only; data, secrets and .env stay
# on a sensor-only host (only .env.sensor) both forms remove just the sensor
deploy/install.sh uninstall --delete-data   # also the volumes (database, certificates, backups), secrets, .env, soc.env, sensor bundles, and the sensor's data (sensor-data/, .env.sensor, its volumes)
```

Both ask for confirmation unless `--yes`. Data is deleted only with `--delete-data`
(`--keep-data` is the default, accepted for clarity). Images are never removed.

## Checking an install

`deploy/tests/fresh-install.sh` copies the working tree to an empty directory, installs it (project
`idps-pkg-fresh`, ports 18080/18443/18444) and checks the dashboard, API, MFA requirement, headers,
the sensor port with and without a client certificate and a sensor bundle; it removes everything
afterwards. `deploy/tests/upgrade.sh` installs 0.1.0 (project `idps-pkg-upgrade`), adds data, runs
`install.sh upgrade` and compares the data, the schema revision and the backup. Both need Docker
and several minutes. `tests/test_deploy_files.py` and `tests/test_deploy_options.py` need no Docker
daemon (the first uses `docker compose config` when the CLI exists).

Both scripts also check the installer's refusals and the compose properties above. On Docker Desktop for macOS, bind mounts from `~/Desktop`, `~/Documents` and `~/Downloads` may be
refused (the secret files are bind-mounted): clone the repository somewhere else.
