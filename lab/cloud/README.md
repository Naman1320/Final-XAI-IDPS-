# Emulated cloud for the lab (docs/cloud-plan.md)

No AWS account, no card, no billing. Everything here talks only to the Moto emulator
(account `000000000000`, region `eu-west-1`) with the fake credentials `test`/`test`.

- **C1** the emulator (`docker-compose.yml`: `moto-net`, `moto`), the billing guard (`guard.py`),
  `env.sh`, and Terraform through `tf.sh`.
- **C3** the live flow-log exporter (this page): `flowlog-writer`, `flowlog-shipper-net`,
  `flowlog-shipper`.
- **C4** the live collector (section "C4" below): `collector-net`, `collector`.

## Run C3

    docker compose -f lab/cloud/docker-compose.yml up -d            # the emulator (once)
    lab/cloud/tf.sh apply -auto-approve                            # creates the bucket (twice on a fresh emulator)
    lab/cloud/build_flowlog.sh                                     # builds the exporter images, offline
    docker compose -f lab/cloud/docker-compose.yml --profile flowlog up -d --no-build \
        flowlog-writer flowlog-shipper                              # the lab (sensor) must be running

    docker exec idps-attacker sh -c '. /attacks/common.sh && nmap -n -Pn -sS -p 1-200 -T4 "$VICTIM_IP"'
    # a minute and a few seconds later (the shipper polls every 10 s):
    source lab/cloud/env.sh && .venv/bin/python - <<'PY'
    import boto3; s3 = boto3.client("s3")
    for o in s3.list_objects_v2(Bucket="idps-fyp-flowlogs-000000000000", Prefix="AWSLogs/")["Contents"]:
        print(o["Key"])
    PY

Read what was delivered with the collector's parser: `python -m idps.cloud parse <file.log.gz>`, or let
the C4 collector list `AWSLogs/000000000000/vpcflowlogs/eu-west-1/`.

Stop: `docker compose -f lab/cloud/docker-compose.yml --profile flowlog stop flowlog-writer flowlog-shipper flowlog-shipper-net`
(`down` also removes them; the volumes `flowlog_out` and `flowlog_state` stay unless you add `-v`).

After **recreating the sensor** (`docker compose up -d --build sensor ...` in `lab/`), recreate the writer
too (`... up -d --force-recreate flowlog-writer`): it lives in the sensor's network namespace, which a
new sensor replaces. Same rule as Suricata. The setting `LAB_FLOWLOG_ALLOW_PORTS` (default `22 80`)
changes the emulated security group's open victim ports.

Without the lab or a bucket: `python -m idps.cloud export offline --pcap x.pcap --out DIR` writes the window
files, `python -m idps.cloud export ship --once --in DIR --state-dir DIR2` ships them (guard first). Both need
the same environment as `env.sh`.

## Design

    attacker --> sensor (lab_attack | lab_victim) --> victim          (the lab, unchanged)
                   |  shared network namespace
          flowlog-writer: AF_PACKET on lab_attack, aggregates, writes 60 s window files
                   |  volume flowlog_out (writer: read-write, shipper: READ-ONLY)
          flowlog-shipper: guard, gzip, PUT, remembers what it shipped
                   |  its own namespace (flowlog-shipper-net, on cloud_net only)
          Moto 10.10.4.10:4566, bucket idps-fyp-flowlogs-000000000000

**What is captured.** The "ENI" is the victim's side: the writer records traffic that has exactly one end among
the victim hosts, by default the lab's victim `10.10.2.10` and dvwa `10.10.2.11` (`IDPS_FLOWLOG_VICTIM_HOSTS`,
`--victim-hosts`; `all` or `--victim-cidr` = a whole network). The sensor (`.2`) and the gateway (`.1`) are not
victims, so a sweep makes no records for addresses that are not there. Each direction is its own record, like a
real ENI log. It listens on `lab_attack` only, so every forwarded packet is counted once (on `lab_victim` it would be
the same packet a second time). That interface also shows what the attacker sent even after the lab sensor
has started to block (the sensor's block rules sit after the capture point), which is the traffic the cloud path
should judge. Fake ids: `eni-...` and `fl-...` are derived from the account and region, so they are the same in
both containers and in every run.

**Records.** One line per direction, 5-tuple and wall-clock minute: `2 <account> <eni> <src> <dst> <sport>
<dport> <proto> <packets> <bytes> start end <ACCEPT|REJECT> OK`. `start`/`end` are the first and last packet
second inside the minute (so a long connection appears once per minute), `bytes` are IP total lengths (as in
AWS), ICMP has ports 0. Non-first IP fragments take the ports and the decision of their first fragment
(matched by source, destination, protocol and IP id); a later fragment whose first fragment was never seen is
ignored and counted. Only IPv4 (one 802.1Q tag is skipped; IPv6 and QinQ are ignored). The writer waits 3 s after a minute ends, then writes `YYYYMMDDTHHMMZ-<run>.flows`
(temp file, then rename). A live window holds at most 50,000 records (`IDPS_FLOWLOG_MAX_RECORDS`; an `nmap -p-`
scan makes about 65,000 records a minute, so its tail is cut): a new flow beyond that is not recorded, but it
is counted in `skipped_records`, logged and noted in the window's loss sidecar (below); the offline mode
runs on the host and allows 200,000. The writer deletes its window files, sidecars and stray temp files
after 12 hours.

**Loss is measured, not hidden.** The capture socket asks for an 8 MB buffer (the kernel caps it at
`net.core.rmem_max`) and reads only the packet headers (256 bytes each). Every second the writer reads the
kernel's drop counter (`PACKET_STATISTICS`) and adds it to the current window. For every window the log line says
how many packets were seen and ignored, and if anything was lost (kernel drops, records over the cap, tracker
evictions, orphan fragments) the line is a WARNING containing `LOSS {...}` and a sidecar
`<window>-<run>.flows.loss.json` is written next to the window file with the same counters. **To tell whether a
minute is complete: no `.loss.json` for it, and no `LOSS` in `docker logs idps-flowlog-writer`.** The shipper
does not upload sidecars. A window that cannot be written (full or read-only volume) is retried for 5 seconds,
then dropped and counted (`DROPPED window ...` in the log); the healthcheck stays unhealthy while a write is
failing.

**Objects.** The shipper validates each file with `idps.cloud.flowlogs.parse_lines` (right account, records
inside the window named by the file, no malformed lines; a bad file is logged once and skipped), adds the header
line, gzips (fixed mtime) and PUTs
`AWSLogs/<account>/vpcflowlogs/<region>/YYYY/MM/DD/<account>_vpcflowlogs_<region>_fl-<id>_<YYYYMMDD>T<HHMM>Z_<hash>.log.gz`
where the time is the window start and the hash is the first 8 hex of the content's SHA-256. One object per
window. The key is a function of the content, so shipping twice, restarting the shipper, or losing its state
file (`flowlog_state`, `shipped.json`) never creates a second object: it checks `head_object` before each PUT.
The shipper streams a file line by line (peak memory about 10 MB for a 50,000-record window, measured in
`tests/test_cloud_export.py`), accepts only lines that are exactly one v2 record (no header, NODATA, blank,
control-character or non-ASCII lines; symbolic links are refused; a bad file is logged once and skipped, a
transient read error is retried) and uploads the record rebuilt from its parsed fields.

**After an emulator restart.** Moto's state is in memory. After `docker compose ... restart moto` and
`lab/cloud/tf.sh apply` the bucket is empty again but `shipped.json` still says the last 12 hours were sent.
At start the shipper therefore asks the bucket about the newest 1,000 entries and sends again the windows it no
longer holds (it exits 3 with the `tf.sh apply` message until the bucket exists; with `restart: on-failure` it
keeps trying). To force it: `docker compose ... run --rm flowlog-shipper export ship --once --reship`, or
delete the `flowlog_state` volume. Objects already in the bucket are never duplicated.

**Refusals.** The shipper runs `lab/cloud/guard.py` (copied into the image, the same code `tf.sh` uses, not
weakened; `lab/cloud/build_flowlog.sh` fails if the image's copy differs from the repo's, `--check` verifies an
existing image) at start and every 5 minutes: fake `test`/`test` credentials, no profile/role/token/proxy/CA bundle,
no per-service endpoint, endpoint `127.0.0.1`/`localhost`/`::1`/`10.10.4.10` on port 4566, the endpoint answers as
Moto, STS says `000000000000`. Otherwise exit 1 with the reasons and nothing is sent. If the bucket does not
exist it exits 3 and says to run `lab/cloud/tf.sh apply`; it never creates the bucket. The boto3 client is
built with the fake keys and the endpoint passed explicitly.

**Restarts and health.** Both containers use `restart: on-failure`; `docker compose ... up -d` also works.
The writer's healthcheck needs a recently touched `/tmp/alive`, which it only touches while its last window
write succeeded; the shipper touches its file after every cycle without a failure. A recreated sensor needs a
recreated writer (`up -d --force-recreate flowlog-writer`): its old network namespace is gone.

## Why the lab stays isolated

- Nothing was added to `lab/docker-compose.yml`, to attacker, victim or dvwa, or to the lab networks. The
  attacker and victim still have no route to `cloud_net` or the internet (`lab/check_isolation.sh` passes
  with the exporter running; `tests/test_lab_guard.py` and `tests/test_lab_netguard.py` pass).
- `flowlog-writer` joins the sensor's namespace (`network_mode: container:idps-sensor`; `service:` cannot cross
  compose projects) the way Suricata does, so it is exactly as trusted as the sensor for what it can see, but it
  can do very little: all capabilities dropped except `NET_RAW` (the capture socket) and `SETUID`/`SETGID`;
  it opens the socket, then gives up root (uid 65534, no capabilities left, checked in `/proc`), so no
  `NET_ADMIN`: it can't change the sensor's interfaces, routes or nftables. It has no AWS code path, no
  credentials and writes only to its volume. Read-only root, `no-new-privileges`, 256 MB, 32 processes.
  **"Read-only" describes what the code does, not what the process could do:** the AF_PACKET socket it
  keeps after dropping root can still send frames, and as a process in the sensor's namespace it could open
  TCP or UDP connections to the lab subnets. What it cannot do is leave the lab or reach the SOC or
  `cloud_net`: that rests on the sensor's namespace having no default route and the sensor's nftables
  (the same limits as the sensor and Suricata), and an nft rule keyed to the writer's uid cannot be added
  without `NET_ADMIN`. Treat the writer as exactly as trusted as the sensor.
- `flowlog-shipper` has no lab network at all. Its namespace is held by `flowlog-shipper-net`
  (`netguard_shipper.sh`, same pattern as the emulator's): no default route, outbound only TCP 4566 to
  `10.10.4.10` and replies, so even a wrong endpoint cannot reach the internet ("Network is unreachable"
  was checked). It mounts the packet files read-only, is non-root with no capabilities, 128 MB.
- The only link between the two halves is a folder of text lines that the shipper re-validates.

## What differs from real VPC Flow Logs (an emulation)

- Amazon's flow logs are produced by the VPC. Here the writer builds them from the lab's packets. It
  reproduces the version-2 format, 60 s windows, per-direction records and the S3 key layout; nothing else.
- **ACCEPT/REJECT is emulated.** In the real design the victim's security group allows only the web port and
  the attacker test ports (`attacker_ports`, default 22 and 80, `infra/target.tf`), so a scan shows closed
  ports as REJECT. The writer applies the same list (`IDPS_FLOWLOG_ALLOW_PORTS`; UDP and ICMP are closed unless
  `IDPS_FLOWLOG_ALLOW_UDP_PORTS` / `IDPS_FLOWLOG_ALLOW_ICMP`): TCP to a listed port is ACCEPT, everything else
  toward the victim is REJECT. Answers the lab victim sends to a packet that was REJECTed (its RST, ICMP
  unreachable) are dropped, because behind a real security group the victim never saw the packet. Packets
  from the victim that answer nothing rejected, or that open a connection, are ACCEPT. **In the lab itself
  the sensor's nftables and the victim host decide what really happens**; the log records what the cloud
  design would have decided.
- Not produced: NODATA/SKIPDATA lines, version 3+ fields, IPv6, VLANs beyond one tag, flow direction
  `ingress`/`egress` and TCP flags. Non-first IP fragments have ports 0.
- Timing: the window is the wall clock of the writer's container, files appear about 3 s after the minute
  and objects up to 10 s later, not the 5 to 10 minutes of the real delivery. The collector's 300 s settle time
  still applies. At stop the writer also writes the partial minute; a restart inside one minute gives two
  records for the same flow in that minute.
- Live capture is a Python loop: a very heavy flood can overflow the kernel's socket buffer. Counts are then
  low, never invented, and it is visible: see "Loss is measured" above (`.loss.json` sidecars and `LOSS` log
  lines).
- The object key's timestamp is the START of the 60 s window; Amazon uses the delivery time. This is harmless
  for the collector, which lists by day folder and LastModified and reads the times inside the records.
- `lab/cloud/tf.sh plan` showing "No changes" proves the emulator matches the emulator's configuration (with the
  bucket-policy override below), **not** that the real TLS-only policy in `infra/` is applied or correct;
  `infra/modules/secure_bucket/main.tf` is checked separately (`tests/test_cloud_emulator.py`).
- The ACCEPT/REJECT tracking (which victim packets answer a REJECTed one) keeps its memory for one to two
  minutes and at most 100,000 tuples per minute. If that bound ever overflows, the victim's unexplained
  packets are dropped and counted (`ambiguous_dropped`) instead of being guessed as ACCEPT.
- **Moto ignores policy conditions**, so the real bucket policy's TLS-only Deny (`aws:SecureTransport` false)
  would deny every request in the emulator. `terraform/secure_bucket_override.tf` (copied by `tf.sh` into the
  work copy of the bucket module only) keeps that statement's shape but names an action nobody uses. `infra/`
  is unchanged and still has the real statement. (This was needed before any object could be written; run
  `lab/cloud/tf.sh apply` once to update the two emulated bucket policies, then `plan` shows no changes.)

## Files

`Dockerfile.flowlog` (writer and shipper image: a layer on `idps-lab-sensor:latest`, plus boto3 from the wheel
cache, built with `--network none`), `Dockerfile.shipper-net` + `netguard_shipper.sh`, `build_flowlog.sh`,
the three services in `docker-compose.yml` (profile `flowlog`), the code in `idps/cloud/flowlog_export.py`
(`python -m idps.cloud export writer|offline|ship`), tests in `tests/test_cloud_export.py`.

# C4: the cloud collector, live

`collector` reads the flow-log objects the shipper PUT into the emulated bucket, scores them with the signed
cloud model, sends alerts to the lab SOC as the sensor **`cloud`**, and adds DENY /32 entries (rules 1 to 90,
ingress and egress) to the **emulated** network ACL of the target VPC. **Those entries are only recorded by
Moto: they stop no packets.** The lab sensor does the real blocking. No real AWS, ever: fake keys, endpoint
pinned to `10.10.4.10:4566`, `guard.py` (unchanged) at start and every 5 minutes, fail closed.

## Run

    lab/cloud/build_flowlog.sh                 # once (writer, shipper, guard); then the collector layers:
    lab/cloud/build_collector.sh               # idps-lab-collector (code, guard, signed model, public key), collector-net
    lab/cloud/build_soc_net.sh                 # once: soc-net image with the new netguard.sh (old one kept as :pre-c4)
    # in lab/.env: LAB_SOC_EXTRA_SENSOR_ADDRS=10.10.3.3 ; then (in lab/):
    docker compose up -d --no-build --force-recreate soc-net soc-db soc
    lab/cloud/collector_provision.sh           # once: token + certificate for sensor "cloud"; then restart the SOC
    docker restart idps-soc                    #   (only if the provision script said it added a CA)
    docker compose -f lab/cloud/docker-compose.yml --profile flowlog up -d --no-build flowlog-writer flowlog-shipper
    lab/cloud/start_collector.sh               # checks everything, reads the ACL id from `tf.sh output`, starts it
    lab/cloud/start_collector.sh stop          # stops collector and collector-net (credentials and state stay)
    docker logs -f idps-collector

`build_collector.sh` rebuilds the image when `models/cloud_xgboost.joblib` (or its `.sig`/`.sha256`), the public
key, the code or `guard.py` change; `--check` fails while the image holds other bytes than the repo (and loads the baked
model with the baked public key). `start_collector.sh` runs that check. Stop the collector before `docker compose down`
in `lab/` (it holds an address on `lab_mgmt_net`).

## Design: why a second leg on mgmt_net

The SOC accepts the sensor port (8444, mutual TLS) only from the sensor's `mgmt_net` address, and `cloud_net` has no
route to `mgmt_net`. Options: (a) run the collector in the sensor's namespace (it would then share the sensor's
lab_attack access and NET_ADMIN-less but trusted position: too much); (b) publish 8444 on the host (the SOC's firewall and
lack of default route would still need a path, and it widens what can reach the SOC); (c) **chosen**: `collector-net`,
a small container like `flowlog-shipper-net` that holds the namespace of the collector, on **both** `cloud_net`
(`10.10.4.30`) and `mgmt_net` (`10.10.3.3`), and nothing else:

- no default route; `ip_forward` 0 and a forward chain that drops everything (the two legs are never bridged);
- output: TCP 4566 to `10.10.4.10`, TCP 8444 to `10.10.3.10` (never the dashboard port 8443) and replies; input: replies only;
- it refuses to start if a default route exists, forwarding is on, or a network other than the two /24s is attached;
- the collector shares that namespace, has no capabilities, is non-root (65534), read-only root, no-new-privileges,
  512 MB (no swap), 0.5 CPU, 64 processes, restart `on-failure`, healthcheck on a file touched after each cycle that did not fail.

The SOC side: `lab/soc/netguard.sh` keeps its rule for `10.10.3.2` and adds, per address in `SOC_EXTRA_SENSOR_ADDRS`
(compose: `LAB_SOC_EXTRA_SENSOR_ADDRS`, blank by default), one rule `ip saddr <addr> tcp dport 8444 accept`. Only host addresses
`10.10.3.2` to `.254` other than the SOC, at most 4; anything else is ignored and logged (a typo leaves the port closed). Blank = exactly
the old behaviour (tested). The moto-net rule (4566 from `10.10.4.0/24`) already admitted the collector's `cloud_net` leg.
Attacker, victim and dvwa got no route; `lab/check_isolation.sh` passes with the collector running.

## Credentials (nothing secret in the repo, an image or `docker inspect`)

`collector_provision.sh` runs `collector_provision.py` inside the SOC (piped in on stdin, no image rebuild): it makes a client
certificate (common name `cloud`) from a new CA whose key is never written, and then, as the LAST step, the sensor token `cloud`
(so a failure earlier changes nothing at the SOC). The lab's sensor CA key was deleted after it signed the lab sensor's certificate,
so the SOC's sensor CA file becomes a bundle of both CAs (the SOC reads it at start: restart it once). Token, certificate and key go
through a tar pipe into the volume `idps-cloud_collector_secrets` (owner 65534, mounted read-only; token and key 0600); the temporary
archive is in a 0700 folder that is removed on any exit. The SOC's server CA is public and is copied there too (`IDPS_SOC_CA_FILE`);
verification of the SOC is never disabled. On a re-run the script sends the SHA-256 of the volume's token (the value the SOC stores,
not the token): a token that is not the SOC's, e.g. one that never reached the volume, is replaced and the old row revoked.
`--force-token` replaces it anyway (`lab/cloud/collector_provision.sh --force-token`).

**The SOC's own bootstrap can drop the cloud CA.** `lab/soc/bootstrap.py` rewrites `sensor-ca.pem` with the lab CA alone whenever it
re-issues the lab sensor's certificate: on a new SOC data volume, when the lab sensor token is replaced, and 30 days before that
certificate expires (not only once a year). `start_collector.sh` therefore checks the file first (public certificates, by fingerprint):
if the cloud CA is gone it re-runs the provisioning and tells you to `docker restart idps-soc` (the SOC reads the file only at start);
the same message appears if the CA was added after the SOC last started. Symptom if you start the collector some other way: TLS
failures and a growing outbox in `docker logs idps-collector`.

**Certificate lifetimes:** the collector's certificate 365 days, the cloud CA 400 days. `start_collector.sh` warns when either has
under 30 days left; re-running `collector_provision.sh` re-issues the certificate (and its CA) when under 30 days remain.

**Wrong or revoked token or certificate:** a 401/403/404 from the SOC does not drop alerts (the way the lab sensor treats them): they stay
queued in the outbox, the log says `SOC refused our credentials`, the cycle reports `soc_config_error` and the container goes
unhealthy (the alive file is not touched). Fix with `collector_provision.sh` (add `--force-token`), then `docker restart idps-soc` if it
said a CA was added. Other 4xx (a batch the SOC finds invalid, 422) are dropped as before.

## Response settings (and why)

`IDPS_DRY_RUN=false` (deny entries really are created in the emulated ACL), `IDPS_CLOUD_NACL_ID` from `tf.sh output target_nacl_id`.
`IDPS_ALLOWLIST` = `10.10.1.1,10.10.1.2,10.10.2.0/24,10.10.3.0/24,10.10.4.0/24`: the lab gateway and sensor, the victim network
(a flow's source can be a victim's reply), mgmt_net (SOC, sensor, collector) and cloud_net. The policy refuses only unspecified,
loopback, multicast, link-local, reserved and allowlisted addresses, **not private ones**, so the attacker `10.10.1.10` (deliberately
not listed) is blockable, as the demo needs. The lab has no benign client address outside these networks (benign traffic is
generated from the attacker's container too, so it is blockable like an attacker: a limitation). Confidence threshold 0.9,
`IDPS_CLOUD_MIN_FLOWS` 5 rows in 60 s, TTL 300 s, at most 10 deny entries; the entries are removed when the TTL runs out.
Alerts go to the SOC from confidence 0.5. `IDPS_CLOUD_SETTLE_SECONDS=30` (the collector's default is 300: the real S3 lags, the emulator does not).
`IDPS_MODEL_PUBLIC_KEY` makes the collector refuse an unsigned or tampered model.

**What the SOC sees.** The collector posts **alerts only**. The SOC never shows the NACL deny entries or block events: those are
in the collector's log (`nacl_blocked`) and in the emulated ACL (`describe-network-acls`). **Benign traffic from 10.10.1.10 will show
false alerts** (the cloud model has 8.5 to 17 % false positives and the alert threshold is 0.5); with confidence 0.9 and 5 rows in 60 s
a noisy benign run can also be denied in the emulated ACL.

## Memory

Image: `OMP_NUM_THREADS=1`, `MALLOC_ARENA_MAX=2`. Limit 512m (and no swap): 256m was at the edge (idle 224 to 236 MiB, about 228 MB
anonymous). A flow-log object is parsed, then **scored in chunks of 2,000 rows** (alerts and blocking decisions per chunk), and at most
`IDPS_CLOUD_MAX_ROWS` rows (default 20,000; 0 = no cap) are scored per object: the excess is skipped, counted (`rows_skipped` in the
cycle line) and logged once (`"event": "rows_skipped"`); the object still counts as processed, so it is not read again. Skipped rows are
the LAST rows of the object (the file's order), so a very large scan loses its tail: raise the cap if you want them. The exporter's live
cap is 50,000 records per window (`LAB_FLOWLOG_MAX_RECORDS`); for the demo you can lower it (e.g. `LAB_FLOWLOG_MAX_RECORDS=5000` in the
environment of `compose up flowlog-writer`), which this change deliberately does not do by default, because it would change the
exporter's behaviour for everyone. Measurements are in the section "Measured" below.

## Operations

- **After a Moto restart** (state is in memory): `lab/cloud/tf.sh apply` (twice), which makes a new bucket AND a new network ACL id; the
  shipper re-sends its windows (see C3); then `lab/cloud/start_collector.sh` again. The collector reads `IDPS_CLOUD_NACL_ID` once at
  start: until it is restarted with the new id, every block attempt fails and is only logged (alerts to the SOC still work), and a bucket
  that does not exist makes the cycles fail (`S3 request failed`, retried with a growing pause).
- **`GuardRefused`** (the guard found a problem) ends the process with exit code 1 and a message; `restart: on-failure` retries it with
  Docker's growing delay. That is safe: the guard runs before any boto3 client is built, so nothing is read or written meanwhile.
- **If `collector-net` restarts alone** (`docker restart idps-collector-net`), the collector's namespace is the old, dead one. The
  collector notices (`IDPS_CLOUD_REQUIRE_NETWORK`: no `eth` interface), exits with code 1, and `restart: on-failure` starts it in the new
  namespace (checked: about a minute, `RestartCount` 1). If it ever does not, `lab/cloud/start_collector.sh` (or
  `docker compose -f lab/cloud/docker-compose.yml --profile collector up -d --force-recreate collector`) fixes it.

## Tests

`tests/test_cloud_live.py` (compose wiring, credential errors, chunking and the row cap, provisioning order and the CA check, guard refusals, signed-model checks, a run against a stub S3 and a stub SOC that demands a
client certificate, provisioning, and a live isolation probe that is skipped unless the collector is running) and the new cases in
`tests/test_lab_netguard.py`.
