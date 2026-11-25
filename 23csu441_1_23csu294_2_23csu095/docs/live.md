# Live detection (`python -m idps.live`)

One process joins the pieces: capture, features, model, SHAP, alert and response engine.

```
interface or PCAP ─> NFStream flows ─> micro-batch ─> model ─> (non-BENIGN) ─> SHAP top 5 ─┬─> response engine (dry-run by default)
                                                                                           └─> alert: SOC outbox, or a JSON-lines file
```

## Run it

Replay a capture (as fast as possible; for demos and tests):

```sh
python -m idps.live --pcap capture.pcap --model models/friday_xgboost.joblib \
    --alerts-file data/processed/live_alerts.jsonl
```

Live, on an interface (root or `CAP_NET_RAW`):

```sh
python -m idps.live --interface eth0 --model models/friday_xgboost.joblib
```

Options: `--max-flows N`, `--duration SECONDS` (live only), `--batch-size`, `--batch-seconds`,
`--min-alert-confidence`, `--alerts-file`. `--model` defaults to `IDPS_MODEL_PATH`
(`models/model.joblib`). Ctrl-C or SIGTERM flushes the last batch and the outbox, then stops.

Exit codes: 0 normal stop, 1 the capture failed while running, 2 it could not start.

### It refuses to run without a matching model

The bundle is loaded once at startup with the sha256 check and with the capture settings this
process will use (extractor from `IDPS_EXTRACTOR`, default `nfstream`, idle and active timeout
120 s). A missing, tampered or unreadable model, or one trained with a different extractor or
timeouts, ends the run with exit code 2 and a message. There is no "detection without a model" mode.

## Signed models

Unpickling a model runs code, so the sensor must only load models you made. The `.sha256` file
next to a bundle catches accidents, but whoever can write the bundle can write that file too. A
signature closes the gap: the private key stays with whoever approves models (never on a sensor).

```sh
python -m idps.detect keygen --out ~/.idps/model-signing        # .key (0600) and .pub
python -m idps.detect sign models/week_xgboost_fb1.joblib --key ~/.idps/model-signing.key
python -m idps.detect verify models/week_xgboost_fb1.joblib --public-key ~/.idps/model-signing.pub
IDPS_MODEL_PUBLIC_KEY=~/.idps/model-signing.pub python -m idps.live --model models/week_xgboost_fb1.joblib ...
```

With `IDPS_MODEL_PUBLIC_KEY` set, the sensor refuses to start on a model without a valid
`<model>.sig` from that key: unsigned, signed by another key, or changed by even one byte since
it was signed (also when the `.sha256` was rewritten to match). The check runs on the exact bytes
that are then unpickled. `verify` checks a signature without unpickling anything. The status
report carries the key id (`model.signed_by`), so the dashboard shows which sensors check
signatures. Without the setting the sensor logs a warning and loads as before.

- **Retrained models must be signed again.** `python -m idps.detect retrain` writes a new bundle
  without a `.sig`; a sensor that checks signatures refuses it until you run `sign`.
- **Rollback is not prevented.** The signature covers the bundle's bytes, not its version or a
  date, so someone who can write the sensor's model folder could put back an older model you
  signed. Keep that folder writable by root only, and delete the signatures of models you retire.
- In the lab, signatures are checked only when `lab/keys/model-signing.pub` exists (it is your
  own key, so a fresh clone has none and runs unsigned with a warning).

## Settings

Shared with the rest of the IDPS: `IDPS_MODEL_PATH`, `IDPS_DRY_RUN` (default `true`),
`IDPS_ALLOWLIST` (see the next section), `IDPS_CONFIDENCE_THRESHOLD` (block threshold, default 0.9),
`IDPS_BLOCK_TTL_SECONDS`, `IDPS_EXTRACTOR`.

| Variable | Default | Meaning |
|---|---|---|
| `IDPS_LIVE_MIN_ALERT_CONFIDENCE` | 0.5 | Alerts below this are not sent. Blocking is not affected: it uses `IDPS_CONFIDENCE_THRESHOLD` |
| `IDPS_LIVE_BATCH_SIZE` | 64 | Score a micro-batch at this many flows... |
| `IDPS_LIVE_BATCH_SECONDS` | 2.0 | ...or this long after its first flow, whichever comes first |
| `IDPS_LIVE_TOP_K` | 5 | Features per SHAP explanation |
| `IDPS_LIVE_MAX_EXPLANATIONS_PER_BATCH` | 50 | Alerts per batch that get SHAP; the rest are sent without |
| `IDPS_LIVE_BACKGROUND_SIZE` | 50 | First BENIGN flows kept as SHAP background (only models that need one) |
| `IDPS_LIVE_OUTBOX_MAX_ALERTS` | 5000 | Cap of the SOC outbox for model alerts |
| `IDPS_LIVE_OUTBOX_MAX_RULE_ALERTS` | 1000 | Separate cap for rule (Suricata) alerts, see "Rules next to ML" |
| `IDPS_LIVE_OUTBOX_FILE` | `data/processed/live_outbox.json` | Where unsent alerts are saved |
| `IDPS_LIVE_ALERTS_FILE` | `data/processed/live_alerts.jsonl` | Alerts when no SOC is configured (mode 0600) |
| `IDPS_LIVE_METRICS_SECONDS` | 10 | Period of the metrics log line |
| `IDPS_SOC_URL` | unset | SOC base URL, `https://` (plain `http://` only for localhost) |
| `IDPS_SOC_SENSOR_TOKEN` (alias `IDPS_SOC_TOKEN`) | unset | Sensor token from `python -m soc.api create-sensor`. Never logged |
| `IDPS_SOC_CA_FILE` | unset | PEM of the CA that signed the SOC certificate |

The rule forwarder has its own `IDPS_RULES_*` settings (see "Rules next to ML").

Setting only one of URL and token is an error (exit 2), not a silent fallback to the file. Only
the `IDPS_`-prefixed names are read; a bare `SOC_URL` or `SOC_TOKEN` in the environment is ignored.
The token is stripped, must not contain whitespace or control characters (exit 2 otherwise, without
printing it), is held as a secret and never appears in logs or error messages.

## Protect your servers: the allowlist is the safeguard

**Every server you protect MUST be in `IDPS_ALLOWLIST`**, next to the gateway, DNS, the SOC host
and the analyst's address, for example `IDPS_ALLOWLIST=10.10.1.1,10.10.2.0/24`. Real blocking
(`IDPS_DRY_RUN=false`) refuses to start with an empty allowlist, but it cannot know which servers
matter; you have to say so.

Why: NFStream names the sender of a flow's *first captured packet* `src_ip`. A capture that starts
mid-conversation, or a long flow cut by the 120 s timeout, yields flows that begin with the
server's reply, so the server shows up as the source. A full replay of the Friday capture produced
1,207 such alerts for the victim web server. Two layers handle it:

1. **Reply direction heuristic** (`block_candidate` in `idps/live/detector.py`). For TCP/UDP, if
   `src_port < dst_port`, `dst_port >= 32768` and `src_port < 32768`, the flow is read as a reply
   and the response engine is given `dst_ip` (the likely offender) instead of `src_ip`. Ports 0
   and other protocols use `src_ip`. The alert payload is not changed (it shows the flow as
   observed). Redirected detections are counted in the metric `reply_direction` and logged.
2. **The allowlist**, which is the real guarantee. The heuristic can be imitated (an attacker
   sending from port 80 to a high port makes the *victim* the block candidate) and it can be wrong
   in the other direction; an allowlisted address is never blocked, whatever the model says.

## Alerts: SOC or file

* **No SOC configured:** each alert is appended to the JSON-lines file, in the format the SOC
  ingests (`soc/api/routes/alerts.py`), so the file can be posted later.
* **SOC configured:** alerts go into an in-memory outbox and a sender thread posts them in batches
  of at most 500 (the SOC's `MAX_BATCH`). If the SOC is down or slow, detection and blocking do not
  wait: the outbox grows, the sender retries with a pause that doubles up to 60 s. A 4xx answer
  drops that batch (retrying cannot help) and is counted. At shutdown one last attempt is made
  and anything unsent is saved to the outbox file, which the next run sends first.

## Bounded memory and what is shed

| Pressure | What happens | Counted as |
|---|---|---|
| More alerts in a batch than `MAX_EXPLANATIONS_PER_BATCH` | The most confident ones get SHAP, the rest go out with an empty `top_features` | `dropped.explanations` |
| Outbox 80% full | No SHAP until it drains, except for detections that can lead to a block (below) | `dropped.explanations` |
| Outbox over its cap | Oldest alerts are dropped | `dropped.alerts` |
| Alert file not writable | The alerts of that batch are lost, detection continues | `dropped.alerts` |
| SOC answers 401/403/404 | The alerts are kept (it is the sensor's URL/token that is wrong), one ERROR line per streak, retried with backoff | `errors.soc_config` |
| A batch fails unexpectedly | Logged with a traceback, the batch is skipped, detection continues (never re-run: some of its flows may already have reached the response engine) | `errors.batch` |
| Scoring slower than capture | The flow queue is bounded (4 batches); the reader waits instead of growing memory | none |

A block is always audited with its explanation: whatever the budget, the first `min_flows` (5)
detections at or above the block threshold per blockable address in a batch are explained, because
the block is triggered by one of them. That is at most 5 SHAP calls per distinct address per
batch, and addresses on the allowlist are skipped.

Explanations are shed first because the alert itself (who, what, how sure) matters more than
its detail. Every shedding event is also logged as a warning.

On stop (SIGINT/SIGTERM, `--duration`) or end of input every flow that already left the capture is
scored, including the ones queued behind the open batch. With `--max-flows` the queue's surplus
beyond the limit is discarded and counted (`flows_discarded`). What NFStream still holds inside
the capture is not processed.

The outbox file and the JSONL file are created with mode 0600 and a symbolic link at their path is
refused. An outbox file is checked when loaded (batches of JSON objects, re-chunked to 500, trimmed
to the cap, at most 64 MiB); one that fails is moved to `<name>.corrupt-<timestamp>`, never
overwritten.

The SHAP background is the first `IDPS_LIVE_BACKGROUND_SIZE` BENIGN flows the loop sees. Tree
models (XGBoost, random forest) need none, so for them it is unused. A kernel explainer (MLP, slow,
not meant for live use) is built once from that sample. A fixed first-N sample is simple and
reproducible, but it reflects the start of the run, not later traffic.

## Blocks are reported to the SOC

When the response engine really blocks an address (not dry-run, and the nftables call succeeded),
the detector queues a block event `{"event": "blocked", "ip", "reason" (max 500 characters),
"expires_at", "source": "auto"}`. `expires_at` is the absolute end of the block (UTC, ISO), fixed
when the block is applied, so a report delayed by an outage still shows the right end; the SOC's
Blocks page shows the block as inactive after it, so no unblock event is sent. Failed blocks are
never reported.

In dry-run the detector instead queues `{"event": "would_block", "ip", "reason", "source": "auto",
"ttl_seconds"}` (no `expires_at`). The SOC stores these in their own table and lists them at
`GET /blocks/would`; they are never blocks. A sensor that blocks for real never sends them. They
share the queue, retries and drop rules below.

## Status report

With a SOC configured, a daemon thread (`idps/live/status.py`) posts the sensor's status to
`POST /sensor/status` once at start and then every `IDPS_LIVE_STATUS_SECONDS` (default 30): dry-run
and blocking flags, interface and mode, model name and checksum result, the response policy, the
allowlist (at most 100 entries), outbox size, SHAP p95, heartbeat state and the flows / alerts /
blocked / would_block counters and the rule forwarder's `rules` block (see "Rules next to ML"). No token or URL is in it. A failure is logged once per streak and
retried at the next interval; detection is never affected. The thread stops before the sink closes.

`IDPS_FAITHFULNESS_REPORT` (optional path) points at the JSON written by
`python -m idps.explain faithfulness` (for example `reports/friday_xgboost_faithfulness.json`).
It is read and validated once at start-up (`idps/live/faithfulness.py`: at most 1 MB, finite
bounded numbers, unknown keys ignored) and its model-level numbers go into the status as
`faithfulness` (the dashboard's "Can I trust it?" card). A missing or invalid file logs one warning
and the sensor runs without it; a report whose `config.model` differs from the loaded model is still
reported, with `model_matches: false` and a warning. `python -m idps.explain faithfulness` writes
the bundle's sha256 as `config.model_sha256`; when present it is compared with the loaded model's
digest (`model_check: "digest"`, so a retrained model of the same algorithm does not match). Older
reports without it fall back to the algorithm name (`model_check: "name"`, a weak match).
`ratio_to_random` may be `null` or negative and is passed on as is. The report is opened once
(a symlink is fine, it is the operator's own setting; a pipe or a directory is refused, and the
file is read with a 1 MB cap); an absurd number in it (a
400-digit integer) or a control character in its model name makes it invalid, with the same single
warning, and the sensor starts without it. The interface and model names in the status are cleaned
of control and direction-override characters, because the SOC refuses a status that has them.

Block events travel through the same sender thread as the alerts (detection never waits), in
batches of at most 100 (`POST /ingest/blocks`), and are retried while the SOC is unavailable, with
their own backoff: a failing block endpoint never holds back alerts. They wait in a small in-memory
queue of 1000: beyond that the oldest are dropped and counted in `dropped.blocks`, as are events
whose block ended before they could be sent (the SOC refuses a past `expires_at`). A permanent 4xx
answer (for example 422) drops the batch (`dropped.blocks_rejected_by_soc`). Retryable answers
(5xx, 408/425/429) and configuration errors (401/403/404, e.g. an older SOC without the endpoint)
keep the events queued; the failure is logged once per streak. The queue is **not** saved in the
outbox file, so a crash, or a stop while the SOC is down, loses the unsent block reports (the block
itself stays in nftables and in the audit log). Without a SOC, block events are appended to the
alerts file as lines with `"type": "block"`.

## Model version and drift

Alerts carry the model that scored them (`model_sha256`, `model_version`) and the flow's model
features, which is what the SOC needs to turn an analyst's verdict into a training row (`docs/soc.md`,
"Learning from analysts"). The status report's `model` is `{name, sha256, version, checksum_ok}`.
**Upgrade the SOC before the sensors.** A new SOC accepts older sensors and drops unusable optional
fields instead of refusing the batch, but an older SOC answers 422 to the new fields. To run a new
sensor against an old SOC set `IDPS_LIVE_SEND_FEATURES=false`: alerts then carry no `features`,
`model_sha256` or `model_version`, and the status no model digest/version and no drift. The model
version in an alert is cleaned (printable characters, at most 80).

A bundle's `version` is `<model>-<UTC yyyymmddHHMM>-<8 hex of its training rows>`; a bundle saved
before versions existed reports `<model>-<first 8 of its sha256>` and loads unchanged.

**Drift.** `python -m idps.detect train` (and `retrain`) writes `<model>.drift.json`: per model
feature the decile bin edges and the share of training rows in each bin, plus the model's sha256.
For an existing model make one with `python -m idps.detect drift-reference --model M --data <the
labelled parquets it was trained on>` (it rebuilds the model's training split and refuses data that
does not give the same row count). The sensor keeps the last `IDPS_LIVE_DRIFT_WINDOW` (default
5000) scored flows, all of them and not only alerts, as bin counts updated per batch, and reports
the Population Stability Index per feature: `{window, psi_max, top (5), level, reference_sha256}`.
`level` is `ok` below 0.1, `watch` from 0.1, `drift` above 0.25. Until 200 flows have been seen,
and when the sidecar is missing, unreadable or made for another model (sha256 mismatch), the level
is `unknown` with a `reason` (at most 300 characters). A corrupt sidecar (bad numbers, edges not
increasing, wrong lengths) is also `unknown`, never an error. Drift is advisory: a failure in it is logged and never stops detection.

## Analyst actions

When a SOC is configured and the sensor captures live (`--interface`; there is no poller in
`--pcap` replay: it can apply real blocks and no analyst waits on a capture file), a daemon thread polls `GET /sensor/actions` every
`IDPS_LIVE_ACTION_POLL_SECONDS` (default 5, range 1 to 300), with a doubling backoff (up to 300 s)
while the SOC is unreachable; a failure streak is logged once. It never blocks detection and is
stopped on shutdown before the sink closes (it checks for the stop request between actions and
reports, and is given up to 15 s to finish the request in progress; results applied but not yet
reported are logged and lost). At most 50 actions are handled per poll. It carries out the `block_ip` / `unblock_ip` requests
an analyst makes (Blocks page "Unblock", Alert page "Block source IP", confirmed assistant
proposals) and reports each outcome with `POST /sensor/actions/{id}/result`.

* **Untrusted input.** Kind, address and `ttl_seconds` are validated; an unknown kind, an invalid
  address or a bad TTL is reported as failed. The TTL defaults to `IDPS_BLOCK_TTL_SECONDS` and is
  capped at 86400. Scoped IPv6 addresses (`fe80::1%eth0`) and text over 45 characters are
  refused everywhere (`normalise_ip`, and again in the nft backend).
* **Same safety rules as automatic blocks**, because everything goes through the response engine:
  the sensor's own `IDPS_ALLOWLIST` (and non-blockable addresses) is checked first and a refused
  block is reported as failed with the reason.
* **Dry-run.** Nothing is applied and the action is reported as failed with
  `sensor is in dry-run: not applied`, so the analyst is not told a block exists when it does not.
* **The override sticks.** After an analyst unblock, the automatic policy does not block that
  address for `IDPS_UNBLOCK_GRACE_SECONDS` (default 3600; 0 disables). Alerts for it are still
  produced and sent; the suppressed block is logged as `block_suppressed_by_analyst` and counted in
  `blocks_suppressed`. An analyst `block_ip` for the address ends the grace period. The window
  restarts counting flows afterwards. The grace period runs on the sensor's own monotonic clock
  while the auto policy's windows use flow time, so in a fast `--pcap` replay the grace covers the
  whole capture.
* **Analyst blocks win over automatic ones.** While an analyst block is active, the auto policy
  does not touch that address (no nft call, no block event), so it can never shorten a 24 h
  block to the default TTL. An unblock clears it. At most `IDPS_MAX_ANALYST_BLOCKS` (default
  1000) analyst blocks are active at once; further ones are reported failed.
* **Blocks page.** A real analyst block is queued like an automatic one (`"source": "analyst"`,
  absolute `expires_at`); a real unblock queues `{"event": "unblocked", "ip"}`.
* **Delivery.** If reporting a result fails (SOC unreachable, 5xx), the outcome is kept (at most
  1000) and re-reported on the next poll without applying the action again. A 409 or 404 means
  the SOC no longer lists the action: forgotten. Any other 4xx (for example 422) gets one minimal
  failed result `{"error": "result refused by the SOC (HTTP n)"}`, because the action would
  otherwise stay confirmed. Ids already executed (at most 5000 remembered) are never executed
  again, including duplicates within one response.
  Counters: `actions.executed`, `actions.failed`.
* **Limitations.** The grace period and the unreported outcomes are in memory: a sensor restart
  forgets them (an action the SOC still lists would then be applied again), and the analyst
  block map with them: after a restart the auto policy may refresh such a block. An analyst unblock only removes the nftables entry; it does not
  stop alerts. Block and unblock events for the Blocks page are not persisted across a restart (see above).

## Metrics

Every `IDPS_LIVE_METRICS_SECONDS` and once at the end, one JSON line on logger `idps.live`:

```json
{"event": "metrics", "uptime_s": 12.0, "flows": 62, "flows_per_s": 422.1, "alerts": 60,
 "dry_run": true, "blocks": 1, "would_block": 1, "blocked": 0,
 "dropped": {"explanations": 0, "alerts": 0, "alerts_rejected_by_soc": 0, "blocks": 0,
             "blocks_rejected_by_soc": 0}, "blocks_sent": 0,
 "shap_ms_per_alert": {"p50": 0.3, "p95": 0.4, "n": 60},
 "latency_flow_end_to_alert_s": {"p50": 1.1, "p95": 2.3, "n": 60}, "outbox_pending": 0}
```

`blocks` is would-block in dry-run and real blocks otherwise. Percentiles cover the last 2000
samples. The plan's budget is SHAP under 50 ms per alert: XGBoost TreeExplainer takes well under
1 ms in the replay test; a kernel explainer would not meet it. `latency_flow_end_to_alert_s` is
recorded in live mode only; in replay the flows are old, so it would just measure the file's age.

## What latency to expect

From the end of a flow to its alert is the wait for the micro-batch (up to `IDPS_LIVE_BATCH_SECONDS`,
2 s by default) plus a few milliseconds for scoring and SHAP. But **NFStream only emits a flow when
it ends or when a timeout fires** (idle 120 s, active 120 s). In the lab a port scan's flows (a
SYN answered by a RST) were not treated as ended: they came out when the 120 s idle timeout fired,
so their alerts arrived about 121 s after the scan (p50 121.2 s, p95 121.8 s). A long-lived
connection, such as a slow attack or a brute-force session kept open, is only reported when the
120 s active timeout cuts it, so its alert is also up to two minutes late. The timeouts are not changed for this: the model was trained on flows made
with 120 s timeouts, and different ones would produce different features (the startup check
refuses a model trained with other settings). If lower latency matters, the fix is to retrain
with shorter timeouts, not to change them here.

### The heartbeat (live mode)

NFStream's flow clock only moves when a packet arrives. On a quiet link (the lab right after an
attack) nothing arrives, so finished flows are never emitted: a scan followed by silence produced
no flows at all in 200 s. In live mode with the NFStream backend, the loop therefore sends one
1-byte UDP broadcast (`255.255.255.255:9`, the discard port) out of the capture interface every
second. NFStream captures it and its clock moves on.

Only the heartbeat's own flow is dropped before scoring: UDP from the heartbeat socket's own
address and port to that broadcast address, with nothing coming back. It is counted in
`heartbeat_flows` and never reaches the model, the SOC or the response engine. Anyone else's
traffic to `255.255.255.255:9`, an attacker's broadcast flood included, is scored as usual, and
nothing is dropped when no heartbeat is running.

It needs Linux (`SO_BINDTODEVICE`). If it can't start for good (no such interface, no permission)
the loop logs a warning and runs without it; if the interface is only down for a while, it keeps
retrying every second. The scapy backend expires flows on a wall-clock timer and doesn't need
it. Turn it off with `--no-heartbeat`.

**Burst mode.** Each packet lets NFStream 6.6 expire at most 1,000 idle flows. After an attack
burst the heartbeat is often the only packet left, so with one a second, finished flows came out
at about 1,000 a second, and a 100,000-flow burst took minutes to reach the SOC (lab benchmark,
docs/results.md). So when the sensor sees at least 900 flows come out in one second (the output
is capped), the heartbeat sends every 50 ms (20 packets a second) until the output has stayed
under 250 flows a second for 3 s. Then it goes back to once a second, so a quiet link still
sees one packet a second. Each switch is logged once. A busy link that really produces 900
flows a second also switches it on, which costs 20 small broadcasts a second on a link that
is already that busy. `--heartbeat-burst-interval SECONDS` changes the fast interval, and
`--heartbeat-burst-interval 0` keeps the 1 s heartbeat at all times.

Replay uses the flows' own timestamps for the response engine's windows, so blocks in a replay are
deterministic.

## Performance benchmark

`scripts/bench_sensor.py` measures how much traffic the lab sensor keeps up with. It runs on the
host (standard library only) and needs the lab up (`docker compose up -d --build` in `lab/`) and
Wireshark's `editcap`/`mergecap`.

```sh
python scripts/bench_sensor.py                 # 10, 50, 100, 200 Mbit/s, about 30 minutes in all
python scripts/bench_sensor.py --rates 50      # one rate, for a smoke test
python scripts/bench_sensor.py --prepare-only  # make the sample and count its flows only
```

- **Sample.** The first run cuts `data/processed/bench_sample.pcap` (git-ignored, about 230 MB)
  from `data/raw/pcap/Friday-WorkingHours.pcap`: four minutes of the PortScan burst and sixteen minutes
  of the DDoS, so there are real alerts. Frames over 1514 bytes (offload artefacts that tcpreplay
  cannot send) are dropped from it. Cutting scans the 8.8 GB file twice and
  takes a few minutes; the whole capture is never copied. The sample is reused afterwards
  (`--rebuild-sample` cuts it again).
- **Ground truth.** The sample is extracted offline with the project's own NFStream pipeline in the
  sensor container. `capture_ratio` is live flows / offline flows. It is a proxy for drops, not a
  proof: live flows are timed by arrival, offline ones by the capture's timestamps, so a ratio a
  little off 1.0 at 10 Mbit/s is normal; what matters is how it falls as the rate rises.
- **Per rate.** The script starts the dry-run sensor, waits for two metrics lines, replays the
  sample with `lab/attacks/replay.sh FILE RATE`, samples the sensor container's CPU and memory
  every 2 s, then keeps the sensor running until its flow count has stopped rising (steady for
  about 40 s, and at least 130 s after the replay, at most `--flush-seconds`, default 600). Flows
  only come out of NFStream when they time out, and a fast replay leaves a backlog (before the
  heartbeat's burst mode, about 1,000 flows a second came out, so draining took minutes);
  stopping at a fixed time would under-count. Each rate takes about 6-8 minutes (the replay is 3 minutes at 10 Mbit/s and
  under 40 s at the others; start-up is about 25 s; the drain is 2-5 minutes), so the full run
  is about 30 minutes. `tcpreplay-edit` itself tops out near 120-140 Mbit/s in the lab, so the
  "actual" rate at 200 is lower than the target; the report shows both.
- **Fairness.** Flow-level recall is unfair to Suricata: many ET rules are thresholded (one alert per source per period) and fire on a single packet of a scan or flood, so thousands of attack flows can raise a few alerts. The report therefore also gives, per truth label and per lab session, whether Suricata raised any alert at all (`any_alert`, attack-level table). The Friday ML side is in-distribution (same day and tools as training, and part of the test rows have a feature vector that also occurs in train: the share is in `split.friday_identical_to_train`), so its recall there is optimistic; the lab data is the unseen test.
- **Failures.** A failing pcap, lab session or dataset is recorded with its error (`suricata_run_errors`, `errors`, `datasets.<name>.error`), the rest is still run and reported, and the exit code is 1 at the end if anything failed.
- **Output.** `reports/perf.json` (one entry per rate plus the sample's size, packets, offline
  flows and SHA-256) and a markdown table on stdout: actual replay rate, flows, capture ratio,
  peak flows/s, alerts and alerts sent, dropped alerts, flow-end-to-alert latency p50/p95, SHAP
  p50/p95, CPU mean/max during the replay (docker's convention: 100 % is one core, 800 % the whole
  8-CPU VM) and peak memory. These come from `docker stats`; if it reports 0 for the sensor (it
  does on some Docker Desktop states) the sensor's own cgroup files are used, and `stats_source`
  says which. Latency percentiles cover the last 2,000 alerts (see Metrics), and `flows_timeline`
  shows the flow count over time. The file
  is rewritten after each rate, so a failed run keeps what finished.
- **Drop counters.** The sensor does not expose NFStream's own packet-drop counter. The report
  gives the `lab_attack` interface counters (`rx_packets`, `rx_dropped`, `rx_errors` and the
  kernel's softnet drops) as deltas over the replay, next to tcpreplay's sent and failed packets.
- **Ctrl-C** stops the sensor inside the container and the replay, then prints what was measured.
- `lab/attacks/replay.sh` takes the rate as an optional second argument (or `REPLAY_MBPS`);
  the default stays 10 Mbit/s. Rebuild the attacker after changing it:
  `docker compose up -d --build attacker`.

## False-positive test

`scripts/bench_benign.py` counts what the sensor raises on purely normal traffic in the lab. It
runs on the host (standard library only) and needs the lab up, `lab/.env` with
`LAB_VICTIM_PASSWORD`, `LAB_SOC_CHECK_USER` and `LAB_SOC_CHECK_PASSWORD`, and an attacker image
with the ssh client. The attack scripts are copied into the image, so rebuild it whenever
`lab/attacks/` changes: `docker compose build attacker && docker compose up -d --no-deps attacker`.

```sh
python scripts/bench_benign.py                 # 60 minutes of normal traffic, about 65 minutes in all
python scripts/bench_benign.py --minutes 4     # a short smoke run
```

- **Traffic.** `lab/attacks/benign.sh [SECONDS]` runs in the attacker container (the lab's only
  client) as one busy user, with random think times (1-8 s, sometimes 15-40 s). Web requests are
  browser-like: a page of 10-50 KB (`/benign/index.html`, `page2.html`, `page3.html`, sometimes
  nginx's default page) with its assets on one keep-alive connection, or the page and then the assets on up
  to 6 parallel connections; DVWA pages the same way, with a login now and then; downloads of
  100 KB - 50 MB; interactive-looking ssh sessions; small scp transfers; bursts of 15-40 requests
  (an API poller on one connection, or a page with many assets); pings; and, at low weight, a
  **connection-per-request** activity (`connreq`: a script or health check opening a new connection
  for each request) so that pattern's rate shows apart. `TERM`/`INT` stop it at once.
- **Logs.** One line per activity, plus one line per request with its client port
  (`benign req ACTIVITY LPORT SERVER:PORT STATUS SECONDS PATH`). The run saves them to
  `reports/lab_benign_activity.log`.
- **Test files.** The script creates the pages, assets and files in the victim's nginx root
  (`/var/www/html/benign/`, random data) before the run and deletes them afterwards, even after
  Ctrl-C. To run `benign.sh` by hand, create them yourself (see the header of
  `lab/attacks/benign.sh` and `setup_victim_files()` in the script) and pass the password:
  `docker compose exec -e LAB_VICTIM_PASSWORD attacker /attacks/benign.sh 300`. Without the
  password ssh and scp are skipped. `BENIGN_SEED=n` repeats the choices (activity, page, file,
  counts) but not the timings.
- **DVWA database.** If DVWA redirects the login to `setup.php` (no database), `benign.sh` creates
  the database once, as `webattack.sh` does. An existing database is never reset.
- **Sensor.** Dry-run, with the allowlist `10.10.1.1,10.10.1.2,10.10.3.0/24`. The client
  (10.10.1.10) and the victims (10.10.2.0/24) are **not** allowlisted, so a false alert or
  would-block on them shows. The script waits for two metrics lines, runs the traffic, keeps the
  sensor running at least 150 s afterwards (flows are reported when their 120 s idle timeout fires)
  until the flow count is steady, stops it and waits until it has gone.
- **Only this run counts.** Before starting, the run aborts if the sensor's outbox file
  (`/opt/idps/data/processed/live_outbox.json`) holds alerts or the sensor's first metrics line
  has `outbox_pending` above 0 (old alerts would be re-sent and counted). It logs in to the SOC
  before the traffic starts. The alerts are then read from the SOC and kept only if they are not
  duplicates (same source, destination, ports, protocol and start), the flow ended no earlier than
  10 s before the traffic began, both addresses are in 10.10.0.0/16 and they come from the lab
  sensor. The rest are counted under `reconciliation.excluded` with their classes.
- **Valid or not.** The report has `valid` and `invalid_reasons`. A run is invalid if
  `benign.sh` exits non-zero, logs no activity or ends well before the time asked, the sensor
  was stopped before draining, Ctrl-C was pressed, `outbox_pending` is not 0 at the end, the
  sensor's `alerts` differ from `alerts_sent` or from the SOC's count for this run, alerts were
  dropped, or the SOC could not be read at the end (then the report still has the sensor's counters
  and a `soc_error`). The exit code is 1 for an invalid run.
- **Result.** Every alert is a false positive, because nothing but normal traffic ran.
  `reports/lab_benign.json` has the flows scored, malicious predictions, alerts, would-blocks (and
  their addresses), false alerts per hour, the false-positive rate (alerts / flows scored), the
  same by predicted class, source, destination and port, the confidence spread, and
  **by activity**: requests, connections, false alerts and alerts per connection for each
  activity type. An alert is matched to an activity by client port, server address:port and
  time from the request lines (ssh, scp and ping have no known client port and match on address
  and time); alerts that match nothing are listed as `unmatched`. A markdown table goes to stdout.
- **Caveats.** The client is the attacker container, the address earlier attack runs used. The
  model keeps no state between flows, so that history does not change the result. **The lab's
  round-trip time is about 0.1 ms**, far below a real network's, so timing features (inter-arrival
  times, flow durations) are unrealistically short and the model may react differently to the same
  traffic on a real network. The traffic is one synthetic user on two servers, so the numbers say
  how the model behaves on that mix, not on a real network. Do not run it together with an attack
  script.
- **Ctrl-C** (also `SIGTERM` and `SIGHUP`) stops the traffic and the sensor, removes the test
  files and writes the report, marked `interrupted` and invalid.

## Known limitations

* **Heuristic direction.** See above; spoofable, which is why the allowlist is mandatory for servers.
* **Late alerts for long flows** (NFStream timeouts, see above).
* **The SHAP background is the first N benign flows**, not a rolling sample.
* **A batch that fails unexpectedly is skipped**, not retried, so its alerts are lost (counted in
  `errors.batch`).
* **A crash loses the unsent block reports** (they are not in the outbox file).
* **A crash loses the unsent alerts** since the last checkpoint (every metrics period) and the
  batch that was in flight; a clean stop saves them.
* **The outbox file is rewritten whole** at each checkpoint, which costs a little I/O when the
  backlog is large.
* **Dropped alerts are not spilled to disk** when the outbox is over its cap: only counted.
* **NFStream starts its worker processes from the reader thread**, which Python 3.12 reports as a
  "multi-threaded fork" warning. It has caused no problem in replay or in the lab.
* **The heartbeat is visible on the link**: one 1-byte broadcast a second from the sensor's
  address (20 a second while a burst drains), so it shows that a sensor is there. On a switch
  with strict broadcast storm control, use `--heartbeat-burst-interval 0`. A host that listens on UDP 9 receives it.
* **The heartbeat needs an IPv4 address on the capture interface.** On a port without one (a
  SPAN port) Linux may pick another interface's address as the source. Not tested.
* **Heartbeat flows count towards `--max-flows`**: about one per 120 s, so slightly fewer real
  flows are scored than the number given.
* **Latency is per flow end**, not per packet: nothing is detected before a flow is emitted.
* **Detection of the same attacker is per flow**: the response engine decides on N flows in a
  window, so the first flows of an attack are alerted but not yet blocked.
* **Shutdown race with a slow SOC.** If the sender thread is still posting when the 30 s join
  times out, the batch in flight may end up neither delivered nor saved. A crash right after a
  successful post re-sends that batch on restart, and the SOC has no idempotency key, so it may
  store the same alerts twice.
* **MLP models only:** the SHAP background for the kernel explainer is fixed when the first BENIGN
  flow arrives, so it can be a single row.
* **Collector log text:** in the cloud collector, `CollectorError` is now an alias of `SocError`,
  so S3 failures are logged as `SocError`. Its behaviour is unchanged.
* **Flows NFStream is still tracking at shutdown are never scored.** On the way out the loop
  stops NFStream's capture process itself (SIGTERM, then SIGKILL after 2 s), because that process
  ignores SIGTERM and Python would otherwise wait for it forever at exit. Before this fix a live
  run with `--duration` stopped detecting on time but never exited (found in the lab, 12 Nov).
* **Redirects from the SOC URL are retried forever** as "SOC unavailable" instead of being
  reported as a configuration error. Fix the URL.
* **`live_alerts.jsonl` is not rotated.** Rotate it with logrotate or a similar tool on long runs.

## Friday replay check (12 Nov 2026)

`python -m idps.live --pcap Friday-WorkingHours.pcap --model models/friday_xgboost.joblib`, run
in dry-run:

- **Speed:** 513,501 flows in about 2 min 16 s, about 3,800–5,000 flows/s. SHAP p50 0.12 ms and
  p95 0.28 ms per alert, with no errors.
- **Alerts:** 223,421.
- **Reply detection:** it moved 1,127 detections to the other side of the flow.
- **Without the allowlist:** the protected web server 192.168.10.50 still collected 2 would-blocks.
  These came from scan replies sent from high ports (for example 58080 → 39492), which port
  numbers alone can't tell apart from real attacks.
- **With `IDPS_ALLOWLIST=192.168.10.50,192.168.10.3`:** only the attacker 172.16.0.1 and the five
  bot-infected hosts were marked for blocking.

## Lab sensor check (12 Nov 2026)

Live capture on `lab_attack` in the Docker lab, `models/friday_xgboost.joblib`,
`IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24`, attack `lab/attacks/portscan.sh` (nmap SYN scan
of ports 1–1024 on the victim):

- **Dry-run (180 s):** all 1,024 scan flows were scored and alerted as PortScan, 121 s after the
  scan (the idle timeout). One `would_block`, for the attacker 10.10.1.10 (confidence 0.99999);
  no victim, gateway or sensor address was marked. 810 alerts had a SHAP explanation (p95 0.42 ms),
  214 went out without one because of the 50-per-batch cap. No errors.
- **Real blocking** (`IDPS_DRY_RUN=false`, `IDPS_BLOCK_TTL_SECONDS=60`): 10.10.1.10 was added to
  `inet idps blocked4` with a 60 s timeout. While it was blocked the attacker got no answer from
  DVWA (HTTP timeout) or the victim (ping 100% loss), and the drop rule counted 6 packets. At
  exactly 60 s nftables removed the element by itself, and DVWA (HTTP 302) and ping worked again.
- **Without the heartbeat** the same scan produced no flows at all, which is why it exists.

### With the lab SOC and dashboard (12 Nov 2026)

`lab/sensor/live.sh` with the lab SOC (`lab/README.md`):

- **Dry-run:** a port scan's 1,024 PortScan alerts reached the SOC about 2 minutes after the scan
  (all sent, none left in the outbox) and appeared on the dashboard's Alerts page through its live
  feed, each with its SHAP explanation.
- **Real blocking** (60 s): the block of 10.10.1.10 appeared on the Blocks page without a reload,
  with the same 60 s end time as nftables, and left the "active only" list when nftables removed
  it. The Metrics page showed the alerts by class, top source and a detection latency of 2.0 min.

### Analyst actions in the lab (12 Nov 2026)

Live loop with real blocking (`IDPS_DRY_RUN=false`), actions sent through the SOC API as the
dashboard buttons send them:

- **Analyst block** of 10.10.1.10 (5 min): applied by the sensor 5 s after the request (one
  poll), reported `executed`, added to `inet idps blocked4` with a 5 min timeout, listed on the
  Blocks page with source `analyst`. The attacker got no answer from DVWA.
- **Analyst unblock**: applied within a second, reported `executed`; the element left nftables,
  the Blocks page showed the block as ended, and DVWA answered the attacker again (HTTP 302).
- **Grace period**: a new port scan right after produced 1,024 alerts, all delivered to the SOC,
  but no new block: the automatic block decisions (204) were suppressed because an analyst had
  unblocked that address.

This run used the new code copied into the running sensor container, because Docker's network
kept timing out while rebuilding the image; the image picks the code up on its next build.

## Every lab attack

`scripts/lab_attacks.py` runs each lab attack (port scan, SSH brute force, rate-limited SYN flood, slow HTTP DoS, sqlmap) against the live sensor, in dry-run and with real 60 s blocks:

- **Ground truth:** tcpdump on the sensor records the attacker's traffic, and the recording is scored offline with the same model, so capture loss and model mistakes can be told apart.
- **Blocking:** it polls `inet idps blocked4` and checks the attacker's HTTP access to the victim before, during and after each block.
- **Before each run:** it refuses to start while the sensor's outbox still holds alerts, and drops alerts for flows that ended before the run.

The script needs `models/week_xgboost.joblib` in the sensor: `docker compose cp ../models/week_xgboost.joblib sensor:/opt/idps/models/`, the same for the `.sha256` file, then `chmod 644` them in the container. Results are in docs/results.md, "Every lab attack with the full-week model".

## Unseen lab data

`scripts/lab_unseen.py` scores the full-week model on labelled flows from our own lab traffic, to compare with the CIC-IDS2017 test split (roadmap step 5, A3b). It is offline only: no live sensor and no SOC are needed, but the lab must be up and `lab/.env` needs `LAB_VICTIM_PASSWORD`. Run it on the host with the project venv (it needs pandas and the `idps` package). Rebuild the attacker image first (`docker compose build attacker && docker compose up -d --no-deps attacker`): `webattack.sh` now prints a `sqlmap-start` marker that the script needs.

```sh
python scripts/lab_unseen.py                                   # every attack + 10 min benign, 2 repeats
python scripts/lab_unseen.py --sessions portscan benign --repeats 1 --benign-minutes 2 \
    --out data/processed/lab_smoke.parquet                     # smoke run with its own files
python scripts/lab_unseen.py --sessions slow_dos --append      # add or replace sessions in the full data
python scripts/lab_unseen.py --score-only                      # re-score data/processed/lab_labelled.parquet
```

- **Sessions.** One per entry of `ATTACKS` in `scripts/lab_attacks.py` plus `benign` (`benign.sh`, `--benign-minutes`, at least 1, default 10), each run `--repeats` times. Per session: tcpdump on the sensor (found and stopped by its pcap path, SIGKILL if SIGINT is not enough), the traffic in the attacker container, then the flows are extracted from the pcap inside the sensor (NFStream, the live sensor's features) and copied to the host. No 120 s wait: NFStream cuts the open flows at the end of the file.
- **Failed sessions.** An attack that exits with an unexpected status, or hits its time limit, is recorded as an error in `runs` and contributes no flows (`syn_flood` may exit 124: `timeout 20 hping3` ending is normal). So does a failed `benign.sh`. Benign activity problems (a failed DVWA login, ssh errors) are listed in the run record as warnings. The exit code is non-zero if any session failed.
- **Labels.** In an attack session the flows with 10.10.1.10 as an endpoint get the attack's label (`PortScan`, `SSH-Patator`, `DoS SYN flood`, `DoS slowloris`, `Web Attack - Sql Injection`); the others are dropped. For `web_sqli`, flows that started before sqlmap (DVWA setup and login curls) are dropped too: `webattack.sh` prints `webattack: sqlmap-start <epoch seconds>` just before sqlmap, and flows starting before the next second are left out (the attacker and the sensor share the Docker VM clock). That is more robust than matching URLs, which would miss the other setup flows and the login page's assets. In the benign session every flow is `BENIGN`. `DoS SYN flood` and the SQL injection are not model classes, so only their family recall (PortScan, BruteForce, DoS, WebAttack, BENIGN) counts.
- **Data file.** `data/processed/lab_labelled.parquet` (git-ignored) with `session`, `repeat`, `label`, `family` and the features. It is written once at the end through a temporary file; the previous file is kept as `lab_labelled.parquet.bak`. `--append` merges new sessions into the existing file (the same session and repeat are replaced); without it the file is replaced. If no session succeeded nothing is written or scored and the exit code is 1. `--out` picks another data file (the report then goes to `reports/<name>.json` unless `--report` says otherwise), so a trial run cannot overwrite a full collection.
- **Scoring.** `models/week_xgboost.joblib` (sha256 checked on load), reported twice in `reports/lab_unseen.json`: `with_floor` (a prediction below the 0.5 alert floor counts as BENIGN, as deployed) and `no_floor` (plain argmax). The test-split scores in `reports/week_xgboost.json` use no floor, so the printed lab-against-test table uses `no_floor`. The report also holds the BENIGN false-positive rate, per-label recall and top predictions, family-level macro-F1, a truth-by-predicted confusion table, the model checksum and notes.
- **Reading it.** Recall is the fair column; F1 depends on the class mix. The family-level macro-F1 covers about five families and the test-split macro-F1 covers 14 classes, so they are not the same measure. The lab has one client, a round-trip time of about 0.1 ms and repeats that are not independent (see `notes` in the report).

## Rules next to ML (roadmap step 8)

The sensor can run Suricata next to the model and send its alerts to the SOC as **rule alerts**
(`source: "rule"`), so an analyst sees what the rules caught beside what the model caught, and can
filter by either. Off by default; nothing about rules is sent unless `IDPS_RULES_EVE` names Suricata's
`eve.json`.

```
Suricata (ET Open, lab_attack) --eve.json (alert events only)--> forwarder thread in idps.live
   --> drop engine events and informational alerts --> fold repeats --> the SOC outbox --> SOC
```

- **Settings** (read by `idps/rules/config.py`; live mode only, ignored with `--pcap`):

  | Variable | Default | Meaning |
  |---|---|---|
  | `IDPS_RULES_EVE` | unset (off) | Path of Suricata's `eve.json`. The lab: `/run/idps-rules/eve.json` |
  | `IDPS_RULES_INCLUDE_INFO` | `false` | Also send informational alerts (ET INFO, ET POLICY, GPL ICMP_INFO, GPL INFO, GPL POLICY, or the categories Not Suspicious Traffic, Misc activity, Potential Corporate Privacy Violation), as family "Policy" |
  | `IDPS_RULES_DEDUPE_SECONDS` | 60 | Repeats of the same (sid, source, destination, destination port) inside this window are folded (see below); 0 sends every event |
  | `IDPS_RULES_MAX_PER_MINUTE` | 120 | At most this many rule alerts are queued per minute; the excess is dropped and counted as `rate_limited`. 0 = no limit. Blocking is not affected |
  | `IDPS_RULES_BLOCK_SIDS` | empty | Comma list of Suricata signature ids whose alerts may trigger an automatic block. Empty: rules never block. A listed SID is also exempt from the informational filter (engine events are never exempt) |
  | `IDPS_RULES_PROTECTED_NETS` | empty (the lab's `live.sh` sets `10.10.2.0/24`) | Comma list of the networks you protect. A rule hit whose source is inside one is never handed to the response engine, on top of `IDPS_ALLOWLIST` |
  | `IDPS_RULES_FROM_START` | `false` | Read an existing eve file from its start (replays history; tests) |
  | `IDPS_RULES_POLL_SECONDS` | 0.5 | How often the file is polled |

- **Reading the file** (`idps/rules/tail.py`). Starts at the **end** of a file that already exists
  (what Suricata wrote before the sensor started is history); a file that appears later is read from
  its start. A line is used only when its newline has arrived. A file that gets smaller (the lab's size
  cap empties it) is read again from its start; a rotated file (new inode) is finished and the new one
  is followed. A line over 1 MiB is skipped. Small losses to know: the lines written between the last poll and
  a truncation (the lab's size cap) are lost with the old content; a truncation followed, before the next poll, by
  more new data than the old size is not seen (a 32 MB burst in 0.5 s); one poll reads at most 8 MiB or 50,000
  lines and carries on at the next.
- **What is dropped** (counted in the status, never sent): Suricata engine events (text starting
  `SURICATA `, e.g. `SURICATA STREAM Packet with invalid ack`, which fire on ordinary traffic) and
  informational alerts. The classification helpers are shared with `scripts/suricata_compare.py`
  (`idps/rules/eve.py`). A line that is not valid JSON (including a fragment, the tail of a line cut by a restart or
  a truncation), has no UTC offset in its timestamp, or has an unusable address, protocol or sid is counted in
  `dropped_invalid`, as is a half line the tailer drops when the file is truncated or rotated, and a line over 1 MiB.
- **Family and confidence.** `predicted_class` is a short family, decided in this order: a keyword in
  the signature (BRUTE FORCE, SQL INJECTION, XSS, DIRECTORY TRAVERSAL), the signature's ruleset prefix
  (ET SCAN -> Scan, ET DOS -> DoS, ET WEB_ -> Web Attack, ET MALWARE / TROJAN / CNC -> Malware, ET
  EXPLOIT / SHELLCODE -> Exploit, ET INFO / POLICY -> Policy), then the Suricata category (e.g. Web
  Application Attack, Attempted Denial of Service, A Network Trojan was detected), else **Rule match**.
  Malware, Exploit and DoS prefixes come first (a malware rule that mentions SQLi is malware), then
  whole-word keywords (`SQLI` does not match `SQLITE`), then the other prefixes, then the category.
  An attack ruleset (ET SCAN / WEB_ / MALWARE / TROJAN / EXPLOIT / DOS ...) is never informational,
  whatever its category says: the prefix wins over the category (this also applies to the Suricata
  comparison, so its informational split can differ slightly from the 15 November run).
  `confidence` comes from Suricata's severity (1 is the most severe): 1 -> 0.95, 2 -> 0.85, 3 -> 0.70,
  4 -> 0.55 (anything else counts as 3). The SOC then applies its normal severity rule to the family
  and confidence (`docs/soc.md`).
- **Repeats are folded** by EVENT time (the eve timestamp, so a backlog read in one go folds the same
  as live). The first event of a (sid, src, dst, dst port) is sent at once with `rule.count` 1. Repeats
  inside the window are not sent but counted; when the window ends, if there were repeats, ONE
  follow-up alert is sent with `rule.count` = all events of the window, `start_ms` the first and
  `end_ms` the last. The same rule hitting the same source, destination and port 500 times is two
  alerts per window; a scan across many ports or hosts is one key each and can still make many, which is
  what `IDPS_RULES_MAX_PER_MINUTE` is for. At shutdown the open windows are flushed. At most 10,000 windows
  are open; the oldest is closed first.
- **A rule flood cannot push model alerts out.** Rule alerts have their own outbox cap
  (`IDPS_LIVE_OUTBOX_MAX_RULE_ALERTS`, default 1000): beyond it the oldest RULE alerts are dropped, and
  model alerts are only ever dropped by model alerts (cap `IDPS_LIVE_OUTBOX_MAX_ALERTS`). The two kinds
  also never share a POST.
- **Rule alerts do not block, unless you say so.** Automatic blocking is the model plus the policy
  only. A rule can trigger a block only if its SID is in `IDPS_RULES_BLOCK_SIDS` **and** the event is in
  the `to_server` direction (the source of a `to_client` event is the server) **and** its source is not
  inside `IDPS_RULES_PROTECTED_NETS` **and** it is not an engine event. It then goes through the same
  response engine as a model detection: the allowlist is checked first, dry-run only records a
  would-block (reported to the SOC as `would_block`), an analyst's unblock grace period is respected, and
  a real block is reported to the SOC like any other, with the reason "Suricata rule sid N (signature)
  matched". **Decision:** the engine gets the detection with confidence 1.0, and it counts as the policy's
  `min_flows` flows (one hit is enough) only when it is TCP on an **established flow**: Suricata logged an
  application protocol, or packets in both directions. Anything else (UDP, ICMP, a bare SYN) is forgeable
  with one spoofed packet and counts as ONE flow, like a single confident model detection; the policy then
  needs `min_flows` such hits in its window. Events that are kept from the engine (not `to_server`, in a
  protected net) are counted in `block_skipped` and logged for the first one and then every 100th. Every
  hit of a listed rule reaches the policy, also the ones folded into a window, but once an address is
  blocked the policy answers `already_blocked`. Protected servers must still be in `IDPS_ALLOWLIST`.
- **Status.** The report has `rules: {enabled, eve_path, alerts_sent, dropped_engine, dropped_info,
  last_event_at, error, deduped, dropped_invalid, rate_limited, block_skipped, include_info,
  dedupe_seconds, max_per_minute, block_sids}` (counters since start; `alerts_sent` is what was queued for the SOC after folding; `block_sids` is how many
  rules may block; `error` says why the file cannot be read, for example "does not exist yet (is
  Suricata running?)"). With the forwarder off the status has **no `rules` key at all**, so a sensor that does not use rules still
  reports to an SOC from before this step. It is part of the extended status, so
  `IDPS_LIVE_SEND_FEATURES=false` leaves it out. A `last_event_at` that stops moving while attacks run
  means Suricata stopped (or lost the sensor's network, see the lab README); there is no separate stale flag.
- **Upgrade order: SOC first.** An SOC from before this step refuses the new alert fields (422) and
  the `rules` block of the status. Upgrade the SOC, then the sensors; do not set `IDPS_RULES_EVE`
  against an old SOC. As a safety net rule alerts never share an outbox batch with model alerts (also
  after a restart), so an old SOC that refuses them costs only the rule alerts (logged with a hint,
  counted in `dropped.alerts_rejected_by_soc`), never the model's.
- **The lab.** `docker compose --profile rules up -d --build suricata` starts the Suricata service
  next to the sensor; see `lab/README.md`. Rule alerts need the rules volume `idps-suricata` (made by
  the Suricata comparison setup below).
- **Not covered:** the dashboard's summary charts (`by_class`, severity, buckets) count both sources
  together; only `by_source` splits them. Rule alerts carry no SHAP explanation and no features, so
  they are never retraining data.

## Suricata comparison

`scripts/suricata_compare.py` compares the rule-based IDS Suricata 7 (ET Open rules) with our ML model, per attack (roadmap step 6, A4). Run Suricata offline on the pcaps; the host side needs the project venv. Docker Desktop cannot mount folders under `~/Desktop`, so each pcap is streamed to the container on stdin (`suricata -r /dev/stdin`; `-r -` does not work). The ET Open rules live in the Docker volume `idps-suricata`, image `jasonish/suricata:7.0.10`.

```sh
# pcaps and labelled flows from the same recordings (the lab must be up)
python scripts/lab_unseen.py --keep-pcaps            # copies each session's pcap to data/raw/lab_pcaps/<session>_<repeat>.pcap
python scripts/suricata_compare.py all --friday      # Suricata on every lab pcap and the Friday pcap, then compare
python scripts/suricata_compare.py run data/raw/lab_pcaps/portscan_1.pcap --dataset lab   # one pcap
python scripts/suricata_compare.py compare --friday  # compare saved alerts only (add --include-engine)
```

- **Run.** Saves `data/raw/suricata/<name>.alerts.jsonl` (alert events only) and `<name>.meta.json` (image, rules `updated_at` and sha256 of `suricata.rules` read inside the volume, number of enabled rules, HOME_NET, packets read, duration). `all` skips a pcap whose alerts were saved for the same file size, mtime, HOME_NET and image (`--force` reruns). Errors Suricata logs (for example a truncated pcap) are shown as a warning and kept in the metadata, and such a run is never reused from the cache. `all` also reruns when the rules (sha256 or `updated_at`) changed, and reuses saved alerts if the pcap file itself is gone.
- **HOME_NET.** Suricata's default HOME_NET is every private range, which would make the lab attacker (10.10.1.10) and the CIC hosts "home", and most ET rules (`$EXTERNAL_NET -> $HOME_NET`) would never fire. The script passes `--set vars.address-groups.HOME_NET=[...]` and `EXTERNAL_NET=any`: lab `[10.10.2.0/24]`, CIC-IDS2017 `[192.168.10.0/24]` (`--dataset lab|cic`, `--home-net` overrides).
- **Matching.** An alert belongs to a labelled flow when protocol and 5-tuple match in either direction and the alert time is within 1 s of the flow's `[start_ms, end_ms]`. Each alert is credited to one flow: the one whose window contains it, else the nearest (ties: nearest start); ICMP matches by the two addresses only. Eve timestamps carry the local UTC offset (`+0000` in the container) and are parsed with it; `compare` refuses a dataset when most of its alerts (over half) fall outside the time span of all the flows (for Friday the whole day's labelled flows, not only the test rows), a wrong pcap or time base. A minority outside is normal.
- **A run that loaded no rules is refused.** The container runs `suricata --init-errors-fatal` with the rules volume mounted read-only, and `run` raises (and saves nothing, keeping any earlier files) when Suricata exits non-zero, the log has no `N rules successfully loaded` line or says 0, the log mentions no rule files or no rules, or the rules sha256 or enabled-rule count is missing; the whole run.log is searched, not only its tail. Otherwise a silently empty rule set would show up as 0% recall. Only alert events are written: eve.json in the container is a named pipe read by a `grep` that keeps the alert lines (the complete eve.json of the 8.8 GB Friday pcap would take many GB), fast.log and stats.log go to /dev/null, and the metadata records the container's output size (`out_kb`). `--full-eve` switches back to a normal eve.json. This pipe setup has not been run yet: check it once with a small pcap (`run` on a slice, then see `alert_only_eve`, `rules_loaded` and `out_kb` in the metadata) before the Friday run.
- **Attack signatures, informational ones and engine events.** Messages starting `SURICATA ` (for example `SURICATA STREAM Packet with invalid ack`) fire on ordinary traffic. They are counted and reported separately; the headline uses attack signatures (ET and others) only, unless `--include-engine`. Within the attack signatures, a second set of figures (`_security`) leaves out informational ones: messages starting `ET INFO`, `ET POLICY`, `GPL ICMP_INFO`, `GPL INFO` or `GPL POLICY`, or category `Not Suspicious Traffic`, `Misc activity` or `Potential Corporate Privacy Violation`. Both are reported for recall and for the BENIGN false-positive rate, so a high false-positive rate made of ET INFO alerts is visible.
- **ML side.** The full-week model (sha256 checked), a flow is detected when its predicted class is not BENIGN, reported with and without the 0.5 alert floor, plus the stricter same-family recall. Friday is scored only on the Friday rows that were in the week model's test split, rebuilt with the trainer's own `make_split` on the five labelled days (the script checks the test size against `reports/week_xgboost.json`); Suricata is scored on the same rows. The lab flows were never in training.
- **Fairness.** Flow-level recall is unfair to Suricata: many ET rules are thresholded (one alert per source per period) and fire on a single packet of a scan or flood, so thousands of attack flows can raise a few alerts. The report therefore also gives, per truth label and per lab session, whether Suricata raised any alert at all (`any_alert`, attack-level table). The Friday ML side is in-distribution (same day and tools as training, and part of the test rows have a feature vector that also occurs in train: the share is in `split.friday_identical_to_train`), so its recall there is optimistic; the lab data is the unseen test.
- **Failures.** A failing pcap, lab session or dataset is recorded with its error (`suricata_run_errors`, `errors`, `datasets.<name>.error`), the rest is still run and reported, and the exit code is 1 at the end if anything failed.
- **Output.** `reports/suricata_compare.json` and markdown tables: per truth label the flows, Suricata recall, ML recall (floor and no floor), either-detects recall and the top signatures; the BENIGN false-positive rate of each and the alert counts (attack, engine); and per lab session and repeat whether Suricata raised any attack alert on attacker traffic (attack-level detection, since sqlmap makes only a few flows).
