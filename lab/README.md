# Lab

Docker network: `attacker` (10.10.1.10) on `attack_net` (10.10.1.0/24), `victim`
(10.10.2.10) and `dvwa` (10.10.2.11) on `victim_net` (10.10.2.0/24). The `sensor`
(10.10.1.2 / 10.10.2.2) is on both and routes between them, so it is inline and can block.
The lab SOC (10.10.3.10) is on a third network, `mgmt_net`, that only the sensor joins
(10.10.3.2). Run attacks only here.

```sh
cp .env.example .env      # then set the lab-only passwords (victim, SOC admin)
docker compose up -d --build
./check_isolation.sh      # run after every start; all checks must pass
docker compose exec attacker /attacks/portscan.sh
```

## How the lab is isolated

The networks are **not** Docker `internal` networks: Docker drops packets on internal
networks whose destination is outside the subnet, which would stop the sensor routing.
Instead:

- **No default route anywhere.** No container can send traffic out of the lab (the one opt-in
  exception is the SOC's HTTPS to listed hosts, below).
- **Endpoints can't change their own network.** `attacker`, `victim` and `dvwa` have no
  `NET_ADMIN`. Each shares the network namespace of a small `*-net` container
  ([netns/setup.sh](netns/setup.sh)) that sets the routes and firewall rules and then idles.
  The rules block Docker's DNS (so no name lookups or DNS tunnelling out) and the Docker VM
  gateway (`10.10.x.1`).
- **The sensor forwards only lab-to-lab traffic** ([sensor/nftables.conf](sensor/nftables.conf)),
  with each rule bound to its interface and strict reverse-path filtering. It never forwards to
  or from `lab_mgmt`, and nothing on `mgmt_net` can open a connection to it.
- **The SOC can't reach anything by default.** It runs with no capabilities in the namespace of
  `soc-net` ([soc/netguard.sh](soc/netguard.sh)): no default route, inbound TCP 8443 only (and 8444 from the sensor),
  outbound replies only. Its port is published on `127.0.0.1` only, for the dashboard.
  - **Opt-in exception:** `LAB_SOC_EGRESS_HOSTS` in `.env` (for example `api.abuseipdb.com`,
    `hooks.slack.com`) allows HTTPS, TCP 443 only, to the public IPv4 addresses those names
    resolve to. Each address gets a /32 route (still no default route), private answers are
    refused, names are looked up again every 2 minutes and an address expires an hour after it
    was last seen. If the names can't be resolved the SOC still starts, with nothing allowed.
  - **Email exception:** when `LAB_SMTP_HOST` is a public mail server (for example
    `smtp.gmail.com`), the SOC may reach that one host on `LAB_SMTP_PORT` (25, 465 or 587;
    default 587, or 465 with `LAB_SMTP_SECURITY=ssl`), in a separate rule refreshed the same
    way. A local test receiver (127.0.0.1) needs nothing. A host or port it can't use leaves
    email blocked (logged by `soc-net`), never the SOC down. The rule follows `.env`, so change
    the mail server there, not only in the SOC. Same accepted risk: other services on that
    provider's addresses and port.
  - **Accepted risks when it is on:** the rule is per address, so other sites behind the same
    CDN addresses are reachable too, and a compromised SOC (it holds the API keys and the
    webhook) could send data out that way. It is meant for trying the integrations, not for a
    hostile-SOC threat model. Separately, and with it off too, the SOC's DNS queries reach the
    internet through Docker's resolver on its loopback (a slow covert channel; the endpoints
    block it, the SOC does not).
- **Fails closed.** If any setup step fails, that container exits and the containers that
  depend on it never start.

The containers that do have `NET_ADMIN` are the sensor (it's the IPS) and the `*-net` and
`soc-net` holders.
Don't run anything else in them.

## Scripts

`attacks/`: `portscan.sh`, `ssh_bruteforce.sh [EXTRA]` (EXTRA more wrong guesses), `dos.sh [syn [hping3-interval]|slow]`
(for example `syn u500` = 2,000 SYN/s instead of a flood), `webattack.sh`
(sqlmap vs DVWA), `replay.sh` (tcpreplay of dataset PCAPs), `benign.sh [SECONDS]`
(normal traffic for the false-positive test, see [../docs/live.md](../docs/live.md)). They all refuse to run unless
the targets are exactly 10.10.2.10 / 10.10.2.11 **and** they run inside the attacker container.

Export `LAB_VICTIM_PASSWORD` in the attacker shell for the brute-force script to hit the real password.

To replay a dataset capture (frames are sent only to the sensor's MAC address):

```sh
docker compose cp capture.pcap attacker:/tmp/capture.pcap
docker compose exec attacker /attacks/replay.sh /tmp/capture.pcap
```

## The lab SOC and dashboard

`soc` runs the SOC API (same image as the sensor) on `https://10.10.3.10:8443`. On first start
[soc/start.sh](soc/start.sh) makes a private CA and server certificate, the JWT secret, the
admin user `admin` (password `LAB_SOC_ADMIN_PASSWORD` from `.env`; change it later in the
dashboard's Admin page) and a sensor token. The certificate and the token go to a volume the
sensor mounts read-only at `/run/idps-soc`; keys, secret and database stay in the SOC's own volume.

**Step 11 security in the lab** (docs/soc.md, "Security"):

- **Two-factor sign-in.** The first time `admin` signs in to the dashboard, it asks you to set up
  an authenticator app (scan the QR code with your phone) and shows 10 recovery codes: keep them.
  The lab check user used by the scripts was enrolled with `python -m soc.api mfa-enrol labcheck
  --secret-file /var/lib/idps-soc/labcheck_totp`; `scripts/bench_benign.py` reads that file from
  the SOC container (never printing it). A lost phone (both settings come from the SOC process, PID 1; without the
  same JWT secret the CLI would encrypt with another MFA key):

  ```sh
  docker compose exec soc sh -c 'export IDPS_SOC_DATABASE_URL=$(tr "\0" "\n" </proc/1/environ | sed -n "s/^IDPS_SOC_DATABASE_URL=//p") IDPS_SOC_JWT_SECRET=$(cat /var/lib/idps-soc/jwt_secret); cd /opt/idps && python -m soc.api mfa-reset admin'
  ```

  `mfa-enrol` is run the same way.
- **Sensor certificate.** `bootstrap.py` issues the sensor a client certificate (common name =
  its name at the SOC) from a sensor CA whose key is deleted right after. The SOC listens on 8443
  (dashboard) and 8444 (sensors only, certificate required; the firewall accepts 8444 only from
  10.10.3.2, plus the addresses in `LAB_SOC_EXTRA_SENSOR_ADDRS`, e.g. the cloud collector 10.10.3.3, see cloud/README.md), and `live.sh` uses 8444 with the certificate. `LAB_SOC_SENSOR_MTLS=false` in `.env`
  goes back to the token alone on 8443.
- **Signed models.** With `lab/keys/model-signing.pub` present (see [keys/README.md](keys/README.md)),
  the sensor refuses models without a valid signature from your key.

Open the unified dashboard from the repository root:

```sh
npm --prefix soc/web run dev
```

At **http://127.0.0.1:5173**, choose **Lab SOC** and use your lab account. The frontend trusts the public CA from the running SOC container. The [dashboard guide](../soc/web/README.md) covers the development workspace, certificate overrides and available modules.

### Live map: demo locations and the home marker

The dashboard's live attack map listens to the SOC's `/ws/alerts` feed: each alert carries where
its source is (`src_geo`) and each block event (blocked, unblocked, and dry-run would-block) carries
where the blocked address is (`geo`). Lab addresses are private, so with `LAB_SOC_GEO_DEMO=true`
they get made-up locations, stable per address and labelled "Demo: <city>" (`source: "demo"`);
without it they have none and the map shows nothing for them. Set `LAB_SOC_HOME_LAT`,
`LAB_SOC_HOME_LON` (and optionally `LAB_SOC_HOME_LABEL`, default "Lab (demo)") in `.env` to draw
the protected site; left blank, there is no home marker (blank values count as unset). Restart the
SOC after changing them: `docker compose up -d soc`.

### Real map locations (optional)

Lab addresses are private, so the map places them only with `LAB_SOC_GEO_DEMO=true` (made-up,
labelled "Demo" locations). Public addresses (a replayed CIC-IDS2017 capture, for example) are
placed with MaxMind's free GeoLite2 City database. Put `MAXMIND_ACCOUNT_ID` and
`MAXMIND_LICENSE_KEY` in `.env`, download the file into `../data/geoip/` (git-ignored; the licence
forbids redistributing it), then copy it into the SOC's volume:

```sh
docker compose cp ../data/geoip/GeoLite2-City.mmdb soc:/var/lib/idps-soc/GeoLite2-City.mmdb
echo 'LAB_SOC_GEOIP_DB=/var/lib/idps-soc/GeoLite2-City.mmdb' >> .env
docker compose up -d soc && ./check_isolation.sh
```

## The SOC's database (PostgreSQL)

The lab SOC keeps its data in PostgreSQL 16 (`soc-db`), which shares the SOC's network namespace:
it listens on the SOC's loopback only, nothing is published, and netguard drops everything else.
On its first start `soc-db` makes a random password into the `soc_db_secret` volume (root-owned,
0600, mounted read-only in the SOC only), so there is nothing to type or put in `lab/.env`. The
SOC logs in as `idps`, an ordinary role that owns the `idps` database, not as the superuser.

- **Moving an older lab SOC.** If the SOC's volume still has a `soc.db` (SQLite), the first start
  copies it into PostgreSQL once: `db upgrade` (adopts the old database), `backup`, then
  `restore` into the empty PostgreSQL. `soc.db` is renamed `soc.db.moved-to-postgres`, and the
  backup (`sqlite-to-postgres-<time>.jsonl.gz`, 0600) stays in the volume as the way back. An
  interrupted start carries on where it stopped. 1.08 million alerts took under 3 minutes; the
  SOC's health check allows 30 minutes for it.
- **Staying on SQLite.** Set `LAB_SOC_DATABASE=sqlite` in `lab/.env`. After a move that starts an
  empty SQLite database (the history is in PostgreSQL), and the SOC warns about it.
- **Backups.** From the SOC container, with the SOC running:

  ```sh
  docker compose exec soc sh -c 'export IDPS_SOC_DATABASE_URL=$(tr "\0" "\n" </proc/1/environ | sed -n "s/^IDPS_SOC_DATABASE_URL=//p"); python -m soc.api backup /var/lib/idps-soc/backup-$(date -u +%Y%m%d).jsonl.gz'
  ```

  Restore only goes into an empty database (`python -m soc.api restore FILE`). A backup holds
  password and token hashes and the alerts' IP addresses: keep it encrypted and delete it with
  the same retention as the data.
- **Retention.** The SOC deletes old data hourly: alerts after 180 days (alerts an analyst
  confirmed or marked false positive are kept as training rows), audit entries after 365 days.
  `LAB_ALERT_RETENTION_DAYS` / `LAB_AUDIT_RETENTION_DAYS` in `lab/.env` change it (0 = forever).
  Admins see the policy and the last run at `GET /admin/retention`; `python -m soc.api prune
  --dry-run` shows what a run would delete.
- **Starting over.** `docker compose down -v` deletes the database with the other lab volumes.
  Removing `soc_db_secret` alone is refused (the new password would not match the database).

## Trying the integrations (notifications, syslog, reputation)

The SOC can send high and critical alerts to a webhook, Slack and email and export a syslog/CEF
stream (see [../docs/soc.md](../docs/soc.md), "Integrations"). By default the lab SOC **cannot
open outbound connections** (see "How the lab is isolated"), so you try them against receivers
inside the SOC's own container, on its loopback address: nothing leaves the lab and no real
Slack, mail server or SIEM is involved. To use a real HTTPS service instead (AbuseIPDB, Slack, an
HTTPS webhook), put its key or URL in `.env`, list its host in `LAB_SOC_EGRESS_HOSTS` and run
`docker compose up -d --no-build --force-recreate soc-net soc-db soc`. For real email, set the
`LAB_SMTP_*` lines for your provider (Gmail: `smtp.gmail.com`, port 587, `starttls`, and an App
Password, not your normal password); the SOC may then reach that mail server and no other. Syslog
stays blocked.

1. In `lab/.env` set (placeholders; `.env` is git-ignored):

   ```sh
   LAB_NOTIFY_ALLOW_PRIVATE=true     # dev/lab only: lets the webhook go to 127.0.0.1
   LAB_NOTIFY_ALLOW_HTTP=true        # dev/lab only
   LAB_WEBHOOK_URL=http://127.0.0.1:9000/hook
   LAB_WEBHOOK_SECRET=lab-shared-secret-change-me
   LAB_SLACK_WEBHOOK_URL=http://127.0.0.1:9000/slack   # same receiver, shows the Slack JSON
   LAB_SMTP_HOST=127.0.0.1
   LAB_SMTP_PORT=2525
   LAB_SMTP_SECURITY=none
   LAB_SMTP_FROM=idps@lab.invalid
   LAB_SMTP_TO=oncall@lab.invalid
   LAB_SYSLOG_HOST=127.0.0.1
   LAB_SYSLOG_PORT=5514
   LAB_SYSLOG_PROTOCOL=tcp           # or udp
   LAB_SOC_PUBLIC_URL=http://localhost:5173
   ```

2. Recreate the SOC and start the receivers, each in its own terminal:

   ```sh
   docker compose up -d soc && ./check_isolation.sh
   docker compose exec soc python /opt/idps/lab/soc/listen.py http 9000     # LISTEN_HMAC_SECRET=... checks the signature
   docker compose exec soc python /opt/idps/lab/soc/listen.py smtp 2525
   docker compose exec soc python /opt/idps/lab/soc/listen.py syslog 5514
   ```

   To check the HMAC (signature over `<X-IDPS-Timestamp>.<body>`, timestamp within 5 minutes), start the web receiver with the same secret:
   `docker compose exec -e LISTEN_HMAC_SECRET=lab-shared-secret-change-me soc python /opt/idps/lab/soc/listen.py http 9000`.

3. In the dashboard's Admin page (or `POST /admin/integrations/<channel>/test`) press the test
   button of each channel, then run an attack (`docker compose exec attacker /attacks/dos.sh syn u500`
   or `portscan.sh`): high and critical alerts appear in the receivers, every alert in the syslog
   one, as CEF.

The reputation of a lab alert says "private address": lab addresses are never sent to AbuseIPDB, and
the lab SOC could not reach it anyway. Real lookups need a deployed SOC with outbound access and
`IDPS_SOC_ABUSEIPDB_KEY`.

## Running detection on the sensor

`live.sh` runs `python -m idps.live` with the SOC's address, CA and token, so alerts and
blocks show up on the dashboard (about 2 minutes after the traffic: NFStream reports a flow
when its 120 s idle timeout fires). Run it on the attack-side interface while an attack script
runs from the attacker container:

```sh
docker compose exec \
    -e IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24,10.10.3.0/24 \
    sensor live.sh --interface lab_attack --model models/friday_xgboost.joblib
docker compose exec attacker sh /attacks/portscan.sh      # in a second terminal
```

`IDPS_ALLOWLIST` must contain the servers you protect (here the whole victim network
10.10.2.0/24, which includes the victim and DVWA) plus the gateway, the sensor and the SOC. It is
the real guarantee that a server is never blocked: a flow can start with the server's reply, so
the server can appear as the source (the loop corrects the obvious cases, but an allowlist is what
you can rely on). Do not allowlist the attacker's network.

Dry-run is on by default: detections that would be blocked are logged (`would_block`), nothing is
changed in nftables. To try real blocking with a short block time, add
`-e IDPS_DRY_RUN=false -e IDPS_BLOCK_TTL_SECONDS=60`. The block appears on the dashboard's Blocks
page and disappears from "active only" when nftables removes it
(`docker compose exec sensor nft list table inet idps` shows it on the sensor). Measured results
are in the "Lab sensor check" section of [../docs/live.md](../docs/live.md).

Without the SOC (`python -m idps.live` directly, or before the SOC has made its token) it writes alerts as JSON lines to
`/opt/idps/data/processed/live_alerts.jsonl` (read with `docker compose exec sensor cat ...`).
Settings, metrics and expected latency: [../docs/live.md](../docs/live.md).

Code and scripts are copied into the images (macOS blocks Docker from mounting folders under
`~/Desktop`), so rebuild after changing them: `docker compose up -d --build sensor soc`.

## Rules next to the model (Suricata)

An optional `suricata` service (profile `rules`) runs Suricata 7.0.10 with the ET Open rules on the
sensor's `lab_attack` interface and writes only alert events to a volume the sensor mounts read-only.
The sensor's rule forwarder (`IDPS_RULES_EVE`) sends them to the lab SOC as rule alerts. A plain
`docker compose up` does not start it.

Needs once: the rules volume `idps-suricata` (made for `scripts/suricata_compare.py`, see
[../docs/live.md](../docs/live.md), "Suricata comparison"). The service loads it read-only.

```sh
docker compose --profile rules up -d --build suricata     # start (first time: builds lab/suricata)
docker compose logs -f suricata                           # "engine started" once the rules are loaded (about a minute)
docker compose exec \
    -e IDPS_RULES_EVE=/run/idps-rules/eve.json \
    -e IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24,10.10.3.0/24 \
    sensor live.sh --interface lab_attack --model models/friday_xgboost.joblib
docker compose exec attacker sh /attacks/portscan.sh      # rule alerts appear within seconds
docker compose --profile rules stop suricata              # stop (the log volume is kept)
docker compose --profile rules rm -f suricata && docker volume rm idps-lab_suricata_eve   # reset the log
```

- Rule alerts show up in a few seconds, because Suricata alerts per packet; model alerts still wait
  for the flow timeout. In the dashboard, filter `source=rule`.
- It shares the sensor's network namespace (`network_mode: service:sensor`): no network of its own, but
  the sensor's interfaces, addresses and gateway (including `lab_mgmt`), so treat it as trusted as the
  sensor. It is hardened: all capabilities dropped except `NET_RAW` (capture) and `DAC_READ_SEARCH` (read
  the rules volume), `no-new-privileges`, `mem_limit: 3g`, `pids_limit: 512`, the rules volume read-only.
  `run.sh` starts `suricata` directly as root without the image's entrypoint (which would need CHOWN, SETUID,
  SETGID and NET_ADMIN). Without `NET_ADMIN` Suricata cannot change offload settings or enter promiscuous
  mode; it only warns, and promisc is off in `suricata.yaml` because the sensor routes the traffic (every
  packet is addressed to its own interface). If capture shows nothing, check the logs and, as a last resort,
  add `NET_ADMIN`.
- **After rebuilding or restarting the sensor, restart Suricata too** (`docker compose --profile rules restart
  suricata`): it lives in the sensor's network namespace, which a recreated sensor replaces. A stale
  `last_event_at` in the sensor's status while attacks run is the sign.
- HOME_NET is the victim network `10.10.2.0/24` and EXTERNAL_NET is `any`; `-k none` is needed because
  lab captures have unfilled checksums (otherwise every packet raises "SURICATA TCPv4 invalid
  checksum"). Engine events and informational alerts are dropped by the forwarder.
- `lab/suricata/suricata.yaml` writes only `alert` events (no flow, http, dns, tls, anomaly or stats
  events, no fast.log). `lab/suricata/run.sh` (log folder `/eve`) empties `eve.json` when it passes 32 MB (`EVE_MAX_MB`);
  the forwarder notices and starts again from the beginning. The ET Open rule set needs about 1 to 2 GB
  of RAM (the container is limited to 3 GB).
- Rules never block unless you list their SID: add `-e IDPS_RULES_BLOCK_SIDS=2009358` (still subject
  to the allowlist, dry-run and `IDPS_RULES_PROTECTED_NETS`, which `live.sh` sets to the victim network; see [../docs/live.md](../docs/live.md)).
- Rebuild the sensor and the SOC first (`docker compose up -d --build sensor soc`): the new
  `idps/rules` package is copied into the image like all code, and an older SOC refuses rule alerts.
