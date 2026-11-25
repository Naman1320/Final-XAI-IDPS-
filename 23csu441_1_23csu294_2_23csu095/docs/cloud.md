# Cloud collector (`idps/cloud`)

Reads VPC Flow Logs of the target VPC from S3, scores them with a cloud model, sends alerts to the
SOC, and blocks attacker addresses with network ACL deny entries. The AWS side (VPC, flow logs,
network ACL, IAM role) is in `infra/`; the cost budget is a separate stack in `infra/budget/`; read `infra/README.md` first.

```
target VPC --flow logs (every 60 s window, delivered in batches)--> S3 bucket
                                                                       |
   idps.cloud collector  <---------- list + read new objects -----------+
     parse -> NetFlow-style rows -> cloud model -> alerts --POST /ingest/alerts--> SOC
                                        |
                                  response engine (allowlist, threshold, N flows, dry-run)
                                        |
                              NaclBlocker: DENY /32 entries, rule numbers 1-90
```

## Install and run

```bash
pip install -e ".[dev,cloud]"          # boto3 is an optional extra, imported only when used

python -m idps.cloud parse tests/data/flowlogs_sample.log          # summary and first rows
python -m idps.cloud collect --once                                # one cycle, then exit
python -m idps.cloud collect --interval 60                         # loop (Ctrl+C to stop)
```

AWS credentials come from the usual boto3 chain. Use the collector role from
`terraform output collector_role_arn` (it exists once `collector_trusted_principal_arns` is set;
for example a profile with `role_arn` and `source_profile` in `~/.aws/config`), not your admin
credentials. Install with `pip install -c requirements-cloud.lock -e ".[dev,cloud]"`: use that
file instead of `requirements.lock` (botocore needs `python-dateutil<3`, the main lock pins 4).

| Variable | Meaning |
|---|---|
| `IDPS_CLOUD_BUCKET` | Flow-log bucket (`terraform output flow_log_bucket`). Required |
| `IDPS_CLOUD_PREFIX` | Key prefix `AWSLogs/<account-id>/vpcflowlogs/<region>/` (`terraform output flow_log_prefix`). **Required**: real keys continue with `YYYY/MM/DD/`, so a shorter prefix such as `AWSLogs/` lists nothing. It must end in `vpcflowlogs/<region>/` and the region must match `IDPS_CLOUD_REGION` if that is set |
| `IDPS_CLOUD_NACL_ID` | Target network ACL (`terraform output target_nacl_id`); needed only for real blocking |
| `IDPS_CLOUD_REGION` | Region (else `AWS_REGION`) |
| `IDPS_CLOUD_MODEL` | Cloud model bundle; without it flow logs are only counted and logged |
| `IDPS_CLOUD_STATE_DIR` | Checkpoint and block state, default `./cloud_state` |
| `IDPS_CLOUD_MAX_DENIES` | Active deny cap, default and maximum 10 (a network ACL allows 20 rules per direction) |
| `IDPS_CLOUD_MIN_FLOWS` | Malicious rows from one source before a block, default 5 |
| `IDPS_CLOUD_LOOKBACK_HOURS` | How far back the very first run looks, default 1 |
| `IDPS_CLOUD_MIN_ALERT_CONFIDENCE` | Alerts below this are not sent, default 0.5 |
| `IDPS_SOC_URL`, `IDPS_SOC_SENSOR_TOKEN` | SOC base URL (must be `https://`, except localhost) and a sensor token (`python -m soc.api create-sensor`). Without them alerts are not sent |
| `IDPS_SOC_CA_FILE` | PEM file of the CA that signed the SOC's certificate. The lab SOC uses Caddy's own CA: copy its root certificate (`infra/README.md`, "Trust the SOC certificate"). Verification is never disabled; without this the system trust store is used and the lab SOC is not trusted |
| `IDPS_DRY_RUN`, `IDPS_ALLOWLIST`, `IDPS_CONFIDENCE_THRESHOLD`, `IDPS_BLOCK_TTL_SECONDS` | The same settings as the lab sensor (`idps/config.py`) |

The collector's own machine must be in the SOC security group (`sensor_cidrs` in Terraform).

## Flow logs are much coarser than the lab features

A flow log record is one line per interface, 5-tuple, direction and **capture window** (60 s here):
addresses, ports, protocol, packets, bytes, start, end, ACCEPT or REJECT. There are no TCP flags,
no packet sizes (only a byte total), no inter-arrival times, and a long connection appears as one
record per window. The lab sensor (`idps/features`) computes about 40 CICFlowMeter-style features
from every packet. The two feature sets are therefore **not interchangeable**, and a model trained
on the lab data cannot score flow logs.

`idps.cloud.flowlogs` turns records into rows with a stable list of columns,
`CLOUD_FEATURE_COLUMNS` (identity columns, then `duration_ms`, `fwd_/bwd_packets`, `fwd_/bwd_bytes`,
`bytes_per_s`, `packets_per_s`, `down_up_ratio`, `fwd_/bwd_pkt_len_mean`, `rejected`). The two
directions of a connection are paired into one row. Real flow logs give each direction its own
`start` and `end` (first and last packet seen in that direction), which differ by a second or two,
so records are paired on interface, protocol and the unordered endpoint pair when they are in the
same 60 s window (same aligned minute, or overlapping `[start, end]`). The initiator is the side
whose destination is a well-known port (below 1024), else the side with the higher source port
(both heuristics); a REJECTed or one-way record has zero `bwd_*`. `fwd` is NetFlow's
`IN_*` and `bwd` is `OUT_*`.

So the cloud needs **its own model**, trained later on NetFlow-style datasets such as
NF-UNSW-NB15 or NF-CSE-CIC-IDS2018 (map their `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`,
`FLOW_DURATION_MILLISECONDS`, `L4_DST_PORT`, `PROTOCOL` onto `CLOUD_MODEL_FEATURES`; features
that have no flow-log equivalent must be dropped from the dataset, not guessed). A bundle for the
collector must be saved with `extraction_meta=cloud_extraction_meta()` and features from
`CLOUD_MODEL_FEATURES`. The collector loads it with the same integrity checks as
`idps.detect.bundle.load_bundle` (sha256 file, permissions) but checks the cloud column layout
instead of the lab one, and refuses a lab bundle.

Latency: flow logs are written per 60 s window and delivered to S3 every few minutes, so cloud
detection is near-real-time at best (minutes), unlike the lab sensor. Measure and report it.

## Blocking with the network ACL

`NaclBlocker` (`idps/cloud/nacl.py`) plugs into the same `ResponseEngine` as the nftables blocker,
so the **same policy code** decides: allowlist first (and loopback, multicast, link-local,
reserved, unspecified), confidence threshold, N malicious rows in a window, TTL. Dry-run is the
default (`IDPS_DRY_RUN` true): it logs `would_block`, makes **no EC2 calls at all**, and writes no
state. Turning dry-run off requires `IDPS_ALLOWLIST` and `IDPS_CLOUD_NACL_ID`. Put the target VPC
CIDR on the allowlist: a flow row can have the victim as its source (an unpaired reply), and the
victim must never be denied.

- A block is two DENY entries (ingress and egress, protocol all) for one `/32` (or `/128`) in rule
  numbers **1 to 90**. The code refuses to create, replace or delete any other number. Terraform
  owns 100 and up (see `infra/README.md`), so they never fight.
- Network ACL entries cannot expire, so expiry times are in a JSON state file
  (`<state dir>/nacl_state.json`, mode 600). The collector deletes expired entries at the start of
  every cycle.
- **Reconciliation** at start-up (`DescribeNetworkAcls`): an expired block is deleted; a deny in
  1 to 90 that the state does not know is adopted with a fresh TTL; a deny for an address that is
  now allowlisted is deleted; a block whose entry someone removed is recreated; entries in 1 to 90
  that are not single-host denies are left alone (their numbers count as taken).
- **Cap.** At most `IDPS_CLOUD_MAX_DENIES` (default 10) addresses are denied at once, because
  network ACLs default to 20 rules per direction and Terraform's allow rules count against that.
  At the cap a new block is **refused** (logged as `nacl_block_refused`; the engine records a failed
  block and tries again on a later flow), so an attacker spraying many source addresses cannot
  flush the real blocks. Only a block with less than 2 minutes left may be evicted for a new one
  (its entries are replaced with `ReplaceNetworkAclEntry`), and an evicted address is released in
  the policy so it can be blocked again. `NetworkAclEntryLimitExceeded` from AWS counts as "at the
  cap" and pauses new blocks for 5 minutes instead of retrying. A block that was only half
  installed (ingress without egress) is completed by the next `block()` call for that address.
  **Put the addresses you administer from (admin IP, sensors, the SOC host, the target VPC) on
  `IDPS_ALLOWLIST`**: allowlisted addresses are never blocked, so they cannot fill the cap.
- One collector process per network ACL; the state file is not locked.

## Checkpoint and delivery

S3 can publish an object after newer ones, so the collector does not use a "newest LastModified"
mark. `<state dir>/checkpoint.json` holds the keys of processed objects (with their
`LastModified`) for a sliding 2 hours behind the newest one, and each cycle lists the day folders
(`.../YYYY/MM/DD/`) from 2 hours before that and processes every unseen object. Only objects
older than 5 minutes are read, because delivery may still be writing earlier-stamped objects. The
first run looks back `IDPS_CLOUD_LOOKBACK_HOURS`. An object published more than 2 hours late is
not read. A corrupt, oversized (64 MB decompressed) or out-of-range object is logged and skipped. A
version 1 checkpoint is converted on load.

Each object is handled in this order: score, **response engine**, queue the alerts, mark the
object processed. Blocking therefore never waits for the SOC. Alerts go to
`<state dir>/outbox.json` (at most 20,000; the oldest are dropped beyond that) and are sent in
batches of 500, oldest first, at the end of every cycle:

- accepted batch: removed from the outbox at once, so it is never sent twice;
- 5xx, timeout or network error (and 408/425/429): retried 3 times with backoff, then the rest
  stays queued for the next cycle;
- other 4xx (a rejected batch, a bad token): permanent, so the batch is logged and dropped, not
  retried forever.

`run_forever` never exits on an error: any exception in a cycle (S3, AWS throttling, a full disk)
is logged and the loop pauses with a growing delay (up to 15 minutes) before the next cycle. A
`BlockerError` while expiring old blocks is logged and the cycle continues. Hive-style
partitioned keys are not supported (the Terraform flow log uses the default layout).

## The SOC payload

`POST /ingest/alerts` with `Authorization: Bearer <sensor token>` and
`{"alerts": [...]}`, at most 500 per request. Each alert is one flow row: `src_ip`, `src_port`,
`dst_ip`, `dst_port`, `protocol`, `start_ms`, `end_ms` (window start and end), `predicted_class`,
`confidence`, optional `anomaly_score`, and an `explanation` with no features yet (there is no
SHAP for the cloud model). The tests validate the payload against the SOC's own `AlertIn` model.
Rows that would make the SOC reject the whole batch (confidence outside 0 to 1, times beyond
year 2100) are dropped by the collector.

Not done yet: reporting blocks to `POST /ingest/blocks` (blocks appear in the collector's log
only), and polling `GET /sensor/actions` for analyst block requests.

## Tests

`tests/test_cloud_*.py` use local sample files (`tests/data/flowlogs_sample.log`) and botocore's
`Stubber`: no network, no AWS, no credentials. They are skipped if boto3 is not installed
(`pip install -e ".[dev,cloud]"`).

## The cloud model

Code: `idps/cloud/train_data.py` (CIC-IDS2017 flows -> flow-log rows), `idps/cloud/train_model.py`
(train, evaluate, bundle, compare), `scripts/cloud_lab_eval.py` (lab replay),
`scripts/cloud_byte_parity.py` (byte check against the lab's flow logs), tests in
`tests/test_cloud_model.py`. Reports: `reports/cloud_xgboost.json`, `cloud_xgboost_noport.json`,
`cloud_vs_lab.json`, `cloud_byte_parity.json`, `cloud_lab_eval*.json`, `cloud_reject_experiment.json`.
Models: `models/staging/cloud_xgboost.joblib` and `cloud_xgboost_noport.joblib` (+ `.sha256`, `.sig`),
version `xgboost-202611180322-714e4cee` (full) and `xgboost-202611180323-11a10936` (no port). They replace
the first pair in `models/` when promoted. Experiments live in `models/experiments/` (see "REJECT").

```bash
python -m idps.cloud.train_data convert --out data/processed/cloud   # 48 s, one CSV at a time
python -m idps.cloud.train_model --models-dir models/staging         # 110 s, peak about 0.9 GB
python -m idps.detect sign models/staging/cloud_xgboost.joblib --cloud --key ~/.idps-lab/model-signing.key
python scripts/cloud_lab_eval.py --model models/staging/cloud_xgboost.joblib --public-key lab/keys/model-signing.pub
```

### Method

No dataset was downloaded. The labelled CIC-IDS2017 flows (`data/raw/cic-ids2017/TrafficLabelling`,
2.83 million flows; 14 columns read per file) become the records a 60 s VPC flow log would have
written, and those records go through **the collector's own `idps.cloud.flowlogs.to_flow_rows`**, so
training rows and live rows are built by one function (pairing is always within one window: the
converter hands `to_flow_rows` whole windows only).

1. Each flow's time span is cut at the wall-clock minute boundaries; each direction's packets are
   divided over the windows in proportion to the time overlap by cumulative rounding, so the
   pieces add up to the CIC totals (a test checks it on random flows). Bytes follow the packets of
   their piece. A duration above one hour is corrupt and is capped (none occurred).
2. One record per direction and window, `ACCEPT`, start/end as whole seconds inside the window.
   Records with the same directed 5-tuple and window are added up, as in a real flow log.
3. **Bytes (`ip_bytes`).** A flow log counts the IP packet. CIC's "Total Length" is payload plus the
   padding Ethernet adds to frames under 60 bytes (a RST/ACK of 54 bytes shows 6 bytes of "payload", a
   SYN with an MSS option 2). The converter now uses CIC's own TCP "Header Length" columns: IP
   bytes = 20 per packet + TCP header + payload, with the payload removed when a direction's
   whole "payload" is no more than the padding allowance (max(0, 26 - TCP header) per packet). UDP and
   ICMP get 28 header bytes per packet, other protocols 20. Residual: pure ACKs inside a data
   flow keep up to 6 padding bytes each. The first version added a flat 40 bytes per TCP packet.
   Before and after, against the lab's flow logs from the exporter (`reports/cloud_byte_parity.json`):

   | TCP scan probe, 1 packet each way | (fwd, bwd) bytes |
   |---|---|
   | CIC rows, first version (157,447 flows) | (40, 46) 50.5%, (42, 46) 49.5% |
   | CIC rows, now (148,732 rows) | (60, 40) 48.2%, (44, 40) 47.3%, reversed pairs 4.4% |
   | lab nmap through the exporter (2,044 rows) | (44, 40) 100% |

   CIC has two nmap SYN variants (TCP header 24 -> 44 bytes, header 40 -> 60 bytes); the lab's nmap
   sends only the 44-byte one. For SSH brute force the median mean packet length fwd/bwd was 113/117
   (first version, flows), is 144/135 now and 151/147 in the lab. The first version's byte values were
   not what a flow log holds, so its scan detection and every replay number from it are void.
4. `to_flow_rows` pairs the directions into one row (the initiator is re-derived from the ports,
   as live). 2.83 million flows gave 2.58 million rows; the per-(day, label) cap of
   `idps.public.sampling` (250,000 BENIGN and 150,000 attack rows per file) was applied to rows
   before the records were built and left **1.98 million rows** (1.54 million BENIGN, 0.44 million
   attack; Heartbleed 22, Infiltration 65, SQL injection 13). Every row keeps a `key_id`, and
   `data/processed/cloud/links/` lists which CIC flows went into which row.
5. **Label of a row** = the label with the most packets among the CIC flows merged into it; on a
   tie an attack beats BENIGN, between attacks the alphabetically first wins. The rows also carry
   `label_any` (the heaviest attack label if any attack flow is in the row) and `mixed_label` (more
   than one label). Mixed rows are 0.8% of BENIGN rows, 18.9% of DDoS rows, 71% and 80% of the two
   web-attack classes with the most rows, 30% of FTP-Patator (`mixed_label_share_by_class` in the
   report).

Split and training are the lab pipeline's: `idps.detect.split` class-time split (per UTC day and
class: earliest 60% train, then 20% validation, 20% test; rows within the gap of a cut dropped; gap
120 s, shrunk only as far as needed so that at most 10% of a bunched group is dropped, as
`idps.public` does), exact duplicates dropped inside each part (the no-port variant again on its own
vector), XGBoost with the lab's hyperparameters (200 trees, depth 6), class weights from the train
rows only, and the BENIGN-only IsolationForest the bundle format carries.

**Split limits and the fix.** Seven of eight CSVs have minute resolution plus a seeded jitter, so the
order of rows inside a minute is noise, and the shrunk gaps are far below the 60 s window for nine
classes: PortScan 6 s, DoS Hulk 9 s, Slowhttptest 15 s, GoldenEye 17 s, DDoS 26 s, XSS 30 s, slowloris 35 s,
web brute force 56 s, SQL injection 0 s (`gap_below_window_s` in the report; the others have 60 s to
98 s). A flow of up to 120 s gives rows in several windows, so train and test could hold rows of one
flow: before the fix **2,892 CIC flows were shared between train and test, 1,352 between train and
validation, 1,902 between validation and test**. `cloud_split(links=...)` now removes from validation
and test every row that shares a flow with an earlier part (1,312 validation rows, 4,795 test rows) and
asserts zero shared flows afterwards (`flow_overlap` in the report). What remains: rows of
different flows from the same minute, same tool and same attacker lie on both sides of a cut in those
nine classes, so the cloud model's per-class scores for them are tilted **in its favour**. The lab
week model used a fixed 120 s gap and loses more rows; the cloud PortScan F1 (0.98) against the lab's
0.70 (1,660 test rows) is therefore not evidence that flow logs see scans better.

### Features, and what dst_port and protocol can leak

Exactly `CLOUD_MODEL_FEATURES` (13): `dst_port`, `protocol`, `duration_ms`, `fwd_packets`,
`bwd_packets`, `fwd_bytes`, `bwd_bytes`, `bytes_per_s`, `packets_per_s`, `down_up_ratio`,
`fwd_pkt_len_mean`, `bwd_pkt_len_mean`, `rejected` (unchanged; the no-port variant has 12). `rejected` is 0
in every training row, so the model never uses it.

- `dst_port` names the service an attack went for (21 and 22 brute force, 80 DoS, 444 Heartbleed).
  Without it, SSH brute force drops from 100% to 41% of replayed rows alerted.
- `protocol` is almost always TCP in CIC; UDP and ICMP rows are nearly all benign (DNS, ping), so
  a UDP flood or an ICMP scan is classed benign by construction.
- Exact byte values: a scan probe is (44, 40) or (60, 40) bytes, so the model can key on them. It
  matches the lab's nmap, and a scanner with other option sets would be missed or mislabelled.
- Time and addresses are not features.

### Results on the CIC test split

Headline numbers are on the deduplicated test rows; every number below is in `reports/cloud_xgboost*.json`.
Deduplication keeps each distinct feature vector once. It removed 55% of all rows, 54% of the BENIGN
test rows but 91% of the PortScan test rows (26,195 rows become 2,443), so it up-weights rare shapes.
`metrics.test_not_deduplicated` is the same cut with duplicates kept, i.e. **traffic-weighted**, and
neither one is pessimistic or optimistic in general: the deduplicated BENIGN false-positive rate is
6.5% and the traffic-weighted one 5.7% (full model), 7.1% and 11.4% (no port).

| | cloud, with dst_port | cloud, no dst_port | lab week model | lab week, no port | lab Friday model |
|---|---|---|---|---|---|
| Features | 13 flow-log counters | 12 | about 40 CICFlowMeter | same | same |
| Test rows (deduplicated) | 165,280 | 159,390 | 194,543 | | 41,126 |
| macro-F1, own class set | 0.681 | 0.631 | 0.662 | 0.616 | 0.729 |
| 95% CI, rows resampled | 0.658 to 0.693 | 0.605 to 0.648 | none | none | none |
| 95% CI, minutes resampled | **0.601 to 0.713** | 0.544 to 0.662 | none | none | none |
| macro-F1, 13 shared classes (cloud / lab) | 0.717 / 0.713 | 0.660 / 0.663 | | | |
| macro-F1, classes with at least 100 test rows in both | 0.755 / 0.710 (9 classes) | 0.780 / 0.797 (8) | | | cloud 0.634 / lab 0.729 (4) |
| BENIGN false-positive rate | 6.5% | 7.1% | 1.1% | 1.2% | 1.5% |
| not deduplicated (traffic-weighted) | macro-F1 0.674, FPR 5.7% | 0.577, 11.4% | | | |
| ROC-AUC (macro) | 0.994 | 0.981 | 0.996 | 0.987 | 0.996 |
| Train / inference | 23 s on 491k rows, 5.6 us per row | 31 s, 8.5 us | | | |

Before the byte and split fixes the cloud model had macro-F1 0.672, false-positive rate 8.5%
(deduplicated), ROC-AUC 0.993; the changes are the converter's byte accounting and the removal of
shared flows.

The lab numbers come from `reports/week_xgboost*.json` and `friday_xgboost*.json` (`reports/cloud_vs_lab.json`
has the table). **They are not a controlled comparison:** other features, other splits (the lab one with
a fixed 120 s gap, which tilts it against the lab model, see above), other test sizes and class sets;
the lab side has no interval and the bootstrap of the cloud side is by minute, because rows of one minute are
not independent. Read it as indicative.

What the table says. The finding "the cloud model is less accurate because the features are much
coarser" is supported on **false alarms**: the false-positive rate is 4 to 6 times the lab's, and the
BENIGN class is the only one with enough rows to be sure. It is **not visible in the macro-F1
headline**: the cloud model's 0.681 (minute interval 0.601 to 0.713) against 0.662 for the lab week
model, and on the nine solid classes 0.755 against 0.710. Those scores include classes the lab model
fails (GoldenEye, Slowhttptest had no or few lab test rows) and favour the cloud side through the shorter gaps. A
fair summary is that, on this dataset and these splits, the two are not separable, except that the cloud
model raises many more false alarms and is weak on classes that live in payloads.

**Where the false alarms come from (label rule).** Mixed rows are 3.8% of the BENIGN test rows but 58% of
the benign false positives; the model calls 99.5% of them DDoS, against 2.4% of the non-mixed BENIGN rows. These
are rows where benign flows outweigh in packets an attack flow that is inside them, i.e. the labelling
rule (or CIC's labels) and not a measured "same shape as LOIC" claim. Under the three rules, same model
(trained with (a)):

| Truth rule for the test rows | BENIGN false-positive rate | DDoS precision |
|---|---|---|
| (a) majority label, the rule used (6.5% = 8,748 of 133,759 BENIGN rows) | 6.5% | 0.418 |
| (b) without the mixed rows (157,621 rows) | 2.8% | 0.582 |
| (c) any attack flow in the row makes it an attack row | 2.8% | 0.780 |

The no-port model gives the same pattern (7.1%, 3.3%, 3.3%). DDoS precision is therefore mostly a labelling
effect: the model finds the DDoS-like rows, and rule (a) calls part of them benign.

Per class, with dst_port (test rows after deduplication; the interval is by minute, which for
classes with few rows or a single burst is very wide, e.g. DDoS 0.08 to 0.73):

| Class | Rows | P | R | F1 (minute interval) | Flow-log view |
|---|---|---|---|---|---|
| BENIGN | 133,759 | 0.994 | 0.935 | 0.964 (0.95 to 0.98) | |
| PortScan | 2,443 | 0.994 | 0.972 | 0.983 (0.69 to 0.99) | visible; see "what remains" above |
| DDoS | 5,897 | 0.418 | 0.998 | 0.589 (0.08 to 0.73) | visible, label-rule artefact above |
| DoS Hulk | 19,328 | 0.994 | 0.968 | 0.981 (0.94 to 0.99) | visible |
| DoS GoldenEye | 1,569 | 0.850 | 0.971 | 0.906 (0.00 to 0.96) | visible |
| DoS slowloris | 588 | 0.898 | 0.585 | 0.709 (0.40 to 0.91) | partly |
| DoS Slowhttptest | 307 | 0.483 | 0.759 | 0.591 (0.03 to 0.84) | partly |
| FTP-Patator | 667 | 0.975 | 0.999 | 0.987 (0.96 to 1.0) | visible (port 21) |
| SSH-Patator | 437 | 0.989 | 1.000 | 0.994 (0.97 to 1.0) | visible (port 22) |
| Web Attack - Brute Force | 100 | 0.192 | 0.410 | 0.262 (0.10 to 0.36) | not visible |
| Web Attack - XSS | 62 | 0.217 | 0.774 | 0.339 (0.04 to 0.56) | not visible |
| Web Attack - Sql Injection | 3 | 0 | 0 | 0 | not visible; 3 rows |
| Infiltration | 11 | 0.846 | 1.0 | 0.917 (0.74 to 1.0) | not visible; 11 rows, not a result |
| Bot | 106 | 0 | 0 | 0 | not visible |
| Heartbleed | 3 | 1.0 | 1.0 | 1.0 | 3 rows, not a result |

Classes a flow log can plausibly see: port scans, DoS/DDoS floods, brute force (volume or fan-out
in packets and bytes). Over just those and BENIGN the macro-F1 is 0.856 (with port) and 0.791
(without). Classes it cannot see: web attacks (the attack is in the HTTP payload; the web classes
are confused with each other, F1 about 0.3), infiltration and bots (normal-looking
connections), Heartbleed (one long flow, a handful of rows). Most web-attack rows are mixed (71% to 80%).

### Lab replay (`scripts/cloud_lab_eval.py`)

**Produced with the exporter after the C3 review fixes, 18 Nov 2026** (repo uncommitted; the ENI is
the victim hosts 10.10.2.10 and 11 only, no `.flows.loss.json` sidecar was written, so no records were
lost), with `models/staging/cloud_xgboost*.joblib`. The lab's recorded sessions (`data/raw/lab_pcaps`,
two sessions per attack, one benign session pair) go through the exporter's offline mode
(`python -m idps.cloud export offline`), the collector's parser (rows are paired per window file, as
the collector pairs per S3 object) and `score_frame`. Rows to or from the client 10.10.1.10 are used and
take the session's label (as `reports/lab_unseen.json`). Modes: `sg` = the emulated security group,
passed explicitly (`--allow-ports "22 80"`, other ports REJECT, replies to rejected packets dropped:
what the live path sees) and `open` = every TCP port accepted. "Alerted" = any attack class with
confidence 0.5 or more (the collector's default). **n = rows, over 2 sessions each; the two portscan
sessions give identical counts, so that is effectively one trial, and the web-attack session has 4 flows
(9 rows) each.**

| Attack | Rows (sessions) | Cloud, sg | Cloud, open | Cloud no port, sg | Lab model (flows) |
|---|---|---|---|---|---|
| portscan (nmap) | 2,048 (2) | **0.3%** (6 rows) | 100% PortScan | 100% but as DDoS | 100% (2,048) |
| ssh_bruteforce (hydra) | 114 (2) | 100% SSH-Patator | 100% | 41% | 98.9% (90) |
| syn_flood (hping3, 2,000 SYN/s) | 57,526 (2) | 100% but as **PortScan** | 100% as PortScan | 100% as PortScan | 100% as PortScan (53,742) |
| slow_dos (slowhttptest) | 2,046 (2) | 0% | 0% | 3.7% (as FTP-Patator) | 0% (1,046) |
| web_sqli (sqlmap) | 18 (2) | 33% (6 rows, as web-attack classes) | 33% | 33% | 0% (8) |
| benign (mixed traffic) | 288 (2) | 19.1% false alarms (55 rows) | 19.1% | 24.0% | 8.3% (386) |

- **Caught:** SSH brute force; a scan when the probes get replies (`open`); the SYN flood is alerted
  (28,549 and 28,976 rows) but **as a PortScan**, the same wrong family the lab model gives: each SYN is
  a short row (two 40-byte packets forward, one 44-byte reply) that looks like a scan probe, and the model has no way to count them. Earlier runs gave 0% for the
  flood, an artefact of the first converter's byte values. **Missed:** the slow DoS, and most of the SQL
  injection (12 of 18 rows; the 6 alerted rows are labelled as web-attack classes, but with 4 flows per
  session this is not a detection result).
- **False alarms:** 55 of 288 benign rows (two sessions, one client) are alerted as DoS Hulk, SSH or FTP-Patator,
  GoldenEye; with the default of 5 alerted rows in one window the benign client would be blocked in both
  sessions. At this n the 19% is a rough figure (the lab model has 8.3%).
- The first alert comes 34 to 50 s after the first packet of SSH and scan sessions (window close; S3
  delivery and the collector's 5 minute settling add minutes; the lab sensor alerts in seconds).
- Caveats: rows are labelled by address and session, not by packet; two short sessions per attack.

**REJECT.** The exporter logs a REJECT for every packet to a victim port other than 22 and 80 and drops
the victim's reply, so a scan probe becomes one forward packet, no reply, `rejected` = 1. CIC has no such
rows: every CIC scan probe got an RST. The model never saw `rejected` = 1 (the column is constant in
training) and calls those rows benign: 6 of 2,048 rows alerted in `sg` mode against 2,048 of 2,048 in `open`
mode. Experiment (`python -m idps.cloud.train_model --reject-experiment`): add REJECT copies of half
the PortScan training rows. On CIC test rows converted to REJECT, PortScan recall goes from 0.04% to
99.96%, and in the lab `sg` replay the scan is detected (2,048 of 2,048); the lab benign false alarms are 17.4%
(50 rows) against 19.1% for the model without it, so the replay shows no cost, but the benign session has
only a few REJECT rows (2.2% and 3.7% of its rows). The cost the replay cannot show: 51% of the 14,318 short
benign CIC rows converted to REJECT are then flagged (49% as PortScan), against 7.9% (0% PortScan) for the unmodified model.
That 51% is a **worst case by construction** (CIC has no benign REJECT rows; the only REJECT rows the
augmented model saw are scans), and 7.9% is the fairer reference. **Decision: not adopted as a default**,
because the benign side of `rejected = 1` is unknown and the augmentation hard-codes this lab's security group into
the model. `CLOUD_MODEL_FEATURES` and the parser are unchanged, and no per-source feature was added (that is
the user's decision). The experiment model is `models/experiments/cloud_xgboost_reject_experiment.joblib`,
unsigned, with `extractor = "experiment-not-for-the-collector"`, so `load_cloud_bundle` refuses it
(`scripts/cloud_lab_eval.py --allow-experiment` reads it).

### Signing

`python -m idps.detect sign models/staging/cloud_xgboost.joblib --cloud --key ~/.idps-lab/model-signing.key`
(and the `_noport` bundle); `verify` with `lab/keys/model-signing.pub` reports key 0cb723d4e5506565 for both.
`--cloud` is needed because `sign` checks that a bundle loads before signing, and the lab loader refuses
the flow-log layout. `load_cloud_bundle(path, public_key=None)` verifies the `.sig` when given a key; the
collector reads it from `IDPS_MODEL_PUBLIC_KEY` (`model_public_key`). Tests: a tampered file fails the sha256
check; with a key, a tampered file with a rewritten sha256 fails the signature; an unsigned file and a file
signed by another key are refused; a lab bundle and an experiment bundle are not accepted.
**Limit:** the signature covers the file's bytes only, not its name, role or version, so a validly signed
older or different cloud bundle (for example the experiment model, if it were signed) loads as a cloud model.
A loader change that would close this: the signed `.sig` fields or the bundle's `extraction_meta` should
carry a `role` and a minimum version that the loader checks (not done here).

### Approximations and limits

- Timestamps: seven of eight CSVs have minute resolution, so the start second inside the minute is a
  seeded uniform draw (Monday has second resolution and gets a draw inside the second). Timestamps are
  as published (CIC local clock; 12-hour files corrected by a heuristic).
- CICFlowMeter ends flows after 120 s and at FINs; merging by 5-tuple and window undoes part of this.
- Packets are spread uniformly over a flow's duration; both directions share one first/last second.
- Bytes: see item 3; pure ACKs in data flows keep up to 6 padding bytes; UDP and ICMP padding is not modelled.
- All records are ACCEPT; `rejected` carries no information in training.
- CIC labels contain known errors and the majority rule for mixed rows is a choice (see the label-rule table).
- Rows per class are capped per day and file; one capture week, one tool per class, so scores are
  optimistic about new tools; the split limits above tilt the per-class scores of nine classes in the cloud model's favour.
- A row-level model sees no volume across rows (the SYN flood is flagged only because one SYN looks like a
  scan probe); there is no explanation (no SHAP) for the cloud model.
- Result pending: the live run against the emulated cloud (C6); the replay above uses recorded pcaps, not the live path.
