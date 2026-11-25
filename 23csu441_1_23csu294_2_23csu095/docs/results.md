# Results — CIC-IDS2017 Friday

First run of the full pipeline on real data, 12 November 2026. The raw numbers are in `reports/friday_*.json`.

## Data

- **Capture:** `Friday-WorkingHours.pcap` (8,839,309,056 bytes), from the Hugging Face mirror
  `bencorn/CICIDS2017`. SHA-256 `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0`,
  which matches the mirror's own checksum.
- **Labels:** the three Friday CSVs from `TrafficLabelling/` (GeneratedLabelledFlows).

```
python -m idps.features extract data/raw/pcap/Friday-WorkingHours.pcap -o data/processed/friday_flows.parquet --backend nfstream
python -m idps.features label data/processed/friday_flows.parquet <3 Friday CSVs> -o data/processed/friday_labelled.parquet --utc-offset-hours -3
python -m idps.detect train data/processed/friday_labelled.parquet --model xgboost --seed 42 -o models/friday_xgboost.joblib --report reports/friday_xgboost.json
```

- **Extraction:** 513,501 flows in 46 seconds.
- **Label time offset:** UTC−3 (the dataset's local time). It matched **99.76%** of flows, against 0.98% at −4 and 0.50% at 0.
- **Training rows:** 486,005, after dropping unmatched and ambiguous flows.

| Label | Flows |
|---|---|
| BENIGN | 289,177 |
| PortScan | 158,734 |
| DDoS | 36,866 |
| Bot | 1,228 |

## Split

- **Method:** class-time split, cut 60/20/20 by time within each class.
- **Gap:** rows starting within 120 seconds of a cut were dropped.
- **Duplicates:** exact duplicates within each split were dropped.
- **PortScan in validation:** the PortScan flows are very repetitive, so 158,734 flows reduce to a few thousand distinct ones, and the validation split has **no PortScan rows** after the gap. Validation macro-F1 (≈0.50) therefore counts PortScan as F1 = 0 because of BENIGN rows wrongly predicted as PortScan. **Use the test split** for comparing models.
- **Identical rows:** 18% of test rows are identical to some training row.

## Detection (test split)

| Model | Macro-F1 | Accuracy | BENIGN false-positive rate |
|---|---|---|---|
| XGBoost | 0.729 | 0.983 | 1.54% |
| Random forest | 0.729 | 0.983 | 1.54% |
| MLP | 0.729 | 0.982 | 1.72% |
| XGBoost without `dst_port` | 0.729 | 0.983 | 1.53% |

XGBoost per class:

| Class | Precision | Recall | F1 | Test rows |
|---|---|---|---|---|
| BENIGN | 0.996 | 0.985 | 0.990 | 35,697 |
| PortScan | 1.000 | 0.999 | 1.000 | 1,660 |
| DDoS | 0.869 | 0.995 | 0.927 | 3,646 |
| Bot | 0.000 | 0.000 | 0.000 | 123 |

- **Without `dst_port`:** dropping the port changes nothing, so the model isn't relying on port numbers.
- **Anomaly detector:** the Isolation Forest scores ROC-AUC 0.91 for attack versus normal on test. Its detection rate at the chosen threshold is near zero, so it adds nothing on this day.

## Known limitation: Bot labels

**Bot recall is 0 for every model. This is caused by the dataset's labels, not the model.**

- **The traffic:** the bot (Ares) calls its control server `205.174.165.73:8080` all day.
- **The labels:** the CSVs mark those flows **Bot from 10:04 to 12:59** and **BENIGN from 13:01 to 17:01** local time, although they come from the same infected hosts.
- **The conflict:** the bot's late check-in flow has a fixed shape: 3 packets each way, 194 and 180 bytes. It appears 490 times labelled Bot and 972 times labelled BENIGN, with identical features.
- **Why the split makes it worse:** the class-time split puts the late Bot rows in test, where the model has learnt that this exact flow shape is BENIGN.
- **AUC still high:** Bot ROC-AUC is still 0.99, so the model ranks Bot flows correctly but never predicts them.

**Decision (12 Nov 2026):** keep the published labels unchanged and report Bot as a dataset limitation. Relabelling all flows to or from the control server is a documented alternative, and it would have to be reported as a change to the dataset.

## Explanations (XGBoost)

```
python -m idps.explain faithfulness models/friday_xgboost.joblib data/processed/friday_labelled.parquet -o reports/friday_xgboost_faithfulness.json -n 100 --top-k 5
python -m idps.explain global models/friday_xgboost.joblib data/processed/friday_labelled.parquet -o reports/friday_xgboost_importance.json --plot reports/friday_xgboost_importance.png
```

**Deletion test:** 100 flows. For each flow, the top 5 features an explanation names are replaced with typical values. The bigger the drop in the model's confidence, the more faithful the explanation.

| Method | Mean confidence drop | Compared with random | Prediction changes | Beats random |
|---|---|---|---|---|
| SHAP | 0.377 | 38.6× | 42% | 100% of flows |
| LIME | 0.165 | 16.9× | 14% | 83% of flows |
| Random 5 features | 0.010 | — | — | — |

- **The median drop is small** (SHAP 0.002). The model is very confident, and many flows keep their class even with 5 features changed. The mean is driven by the 42% that change class.
- **SHAP is the better choice** for the per-alert explanations shown in the SOC.

**Global importance** (mean |SHAP|, `reports/friday_xgboost_importance.png`):

| Class | Main features | Why |
|---|---|---|
| PortScan | `bwd_bytes`, `bwd_pkt_len_max`, `rst_count` | Closed ports reply with a tiny RST |
| DDoS | `bwd_pkt_len_std`, `fwd_pkt_len_max`, `pkt_len_std` | — |
| Bot | `dst_port` (8080), `down_up_ratio` | — |
| BENIGN | `dst_port`, `syn_count`, `bwd_pkt_len_min` | — |

## Limits of these numbers

- **Single day:** all training and testing is on one day. Nothing is tested across days or datasets, so the scores show the pipeline works, not that it generalises.
- **Small Bot sample:** Bot has only 123 test rows, and their labels are unreliable (see above).

## Sensor performance (lab, 14 November 2026)

**What was run:** `python3 scripts/bench_sensor.py`. A 226 MB sample of the Friday capture (1,301,052 packets, PortScan and DDoS windows) was replayed through the lab sensor at four rates. The offline extraction of the same sample gives **191,362 flows**. The Docker VM has 8 CPUs and 4 GB of memory, and the sensor runs in dry-run mode.

The first run found a limit of about 1,000 flows/s. After fixing it (below), the benchmark was run again. The before numbers are in `reports/perf_before_burst.json`, the after numbers in `reports/perf.json`. A run with a batch of 1,024 flows is in `reports/perf_batch1024.json`.

| Target Mbit/s (actual after) | Flows captured, before → after | Peak flows/s, before → after | Burst drain time*, before → after | CPU during drain | Peak memory |
|---|---|---|---|---|---|
| 10 (10.0) | 93% → 90% | 1,055 → 3,205 | (still draining at 400 s) → ~60 s | 54% | 927 MiB |
| 50 (50.0) | 29% → **73%** | 1,017 → 4,505 | 70 s → 70 s | 39% | 830 MiB |
| 100 (100.0) | 58% → **64%** | 1,037 → 3,943 | 120 s → **50 s** | 33% | 774 MiB |
| 200 (126.9, the replay tool's maximum) | 31% → **79%** | 1,011 → 4,516 | 60 s → 70 s | 39% | 875 MiB |

\*From the first flow coming out of the capture to the last, read from `flows_timeline`, which samples every 10 s. After the fix, the same or shorter drain times hold up to 2.5× more flows.

- **Alerts:** none were dropped or rejected by the SOC, and no errors occurred.
- **SHAP time:** p95 stayed at 0.23–0.29 ms per alert.
- **Interfaces:** the capture interface showed 0 `rx_dropped`, 0 errors and 0 softnet drops.

### The limit and the fix

**The model wasn't the limit.**
- A run at 100 Mbit/s with a scoring batch of 1,024 flows instead of 64 gave the same rate (1,104 flows/s peak).
- The limit is NFStream 6.6.0. It expires idle flows only when a packet arrives, and expires at most 1,000 per scan (`nfstream/meter.py`, `meter_scan`).
- After a burst, the only packet left was the sensor's 1 s heartbeat. So finished flows came out at about 1,000 a second, and a 100,000-flow burst took minutes to reach the SOC.

**The fix: a burst mode for the heartbeat** (`idps/live/heartbeat.py`).
- **When it starts:** when at least 900 flows come out in one second, which means the output is capped. The heartbeat then sends every 50 ms.
- **When it stops:** once fewer than 250 flows a second have come out for 3 s, it goes back to once a second.
- **Cost:** 20 one-byte broadcasts a second, and only while a backlog drains.
- **Off switch:** `--heartbeat-burst-interval 0` turns it off.

After the fix, peak output is 3,200–4,500 flows/s, and the model's scoring speed is now the limit.

### What these numbers don't show

- **Alert delay (not in the table).** The sensor's latency figure covers only its last 2,000 alerts (its metrics window). In runs with 70,000–120,000 alerts that is the end of the drain, so it isn't a fair typical figure. Every alert waits at least the 120 s idle timeout. The drain time above is how much longer the slowest alert of a burst waits.
- **Packet loss inside the capture.** The interface counters don't include the capture library's own ring buffer, and that buffer's drop counter isn't read yet. So "no packets dropped" can't be claimed.
- **Why captured flows stay under 100%.** Two possible causes are not yet separated:
  - **Time compression:** replay squeezes 20 minutes of traffic into 10–165 s, so connections that were separate in the original capture fall within one 120 s idle timeout and are counted as one flow.
  - **Real losses:** flows may be lost in that ring buffer.
- **Next step for this:** read NFStream's drop statistics, and count offline flows with the replay's own timing.

## False positives on normal traffic (lab, 15 November 2026)

**What was run:** `python3 scripts/bench_benign.py --minutes 60`. One busy user's normal activity went from the lab client (10.10.1.10) to the victim (nginx, sshd) and DVWA, through the dry-run sensor with the Friday XGBoost model. The mix was:
- page views fetched like a browser does, with keep-alive and up to 6 parallel connections
- DVWA logins
- downloads of 100 KB to 50 MB
- SSH sessions and scp copies
- request bursts and pings
- a small share of one-connection-per-request traffic, the way scripts and health checks behave

Neither the client nor the victims were allowlisted. Only normal traffic ran, so **every alert is a false positive**. Each alert was matched to the activity that caused it by its client port. The raw data is in `reports/lab_benign.json`.

| Measure | Result |
|---|---|
| Traffic | 60.3 min, 1,031 flows scored |
| False alerts | **153**: 152 per hour, **14.8% of flows** |
| Class and severity | all PortScan, all low severity |
| Would-blocks | **0**: no alert was confident enough for the blocking policy |
| Run checks | valid: the sensor and SOC counts agree (153 = 153), no alerts were waiting from earlier runs, nothing was excluded or duplicated |

| Activity | Connections | False alerts | Rate per connection |
|---|---|---|---|
| Web page views (nginx) | 303 | 90 | 29.7% |
| DVWA pages and logins | 274 | 45 | 16.4% |
| One connection per request | 122 | 17 | 13.9% |
| Request bursts (keep-alive) | 156 | 1 | 0.6% |
| Downloads | 27 | 0 | 0 |
| SSH sessions | 48 | 0 | 0 |
| scp | 72 | 0 | 0 |
| Ping | 20 | 0 | 0 |

**All false alerts are short HTTP connections on port 80.**
- **The traffic:** connections that carry one or two small requests and close. Browsers make these when they open several connections in parallel for a page's assets.
- **The model's view:** it learnt PortScan from Friday's data, where a scan probe is a short TCP exchange with a tiny reply (`bwd_bytes`, `bwd_pkt_len_max`, see the explanations above). A short HTTP connection looks similar.
- **What it never confused:** long transfers, SSH and keep-alive bursts.
- **Lab caveat:** the lab's round-trip time is about 0.1 ms. On a real network, timing features would differ, so the rate there may be higher or lower.

### Confidence separates false alerts from real scans

| | Alerts | Median confidence | Confidence ≥ 0.8 | Confidence ≥ 0.9 |
|---|---|---|---|---|
| False alerts (this run) | 153 | 0.60 | 3 (2%) | 0 |
| Real lab port scans (14 Nov runs, 10.10.1.10 → victim) | 5,122 | 0.99999 | 5,122 (100%) | 5,122 (100%) |

- **The finding:** raising the alert threshold from 0.5 to 0.9 would have removed **all 153 false alerts**, and every real lab port-scan alert would still have fired.
- **At 0.8:** 3 false alerts an hour would remain.
- **Why the default is unchanged:**
  - Only one attack type (nmap port scans) was checked this way.
  - The model is still the Friday-only model.
  - The threshold must be checked again for each attack class after the full-week model (roadmap step 3) and the lab attack tests (step 4).
- **Recommendation:** pick a threshold per class from those runs.

**Possible bias:** the "normal" client is the same container the attack scripts run from. The model keeps no state between flows, so earlier attacks don't affect these scores.

## Full-week model (CIC-IDS2017 Monday–Friday, 15 November 2026)

```
python -m idps.detect train data/processed/{monday,tuesday,wednesday,thursday,friday}_labelled.parquet --model xgboost -o models/week_xgboost.joblib --report reports/week_xgboost.json
python -m idps.detect train (same files) --model xgboost --drop-feature dst_port -o models/week_xgboost_noport.joblib --report reports/week_xgboost_noport.json
```

**Data:** each day's capture was downloaded (SHA-256 checked against the Hugging Face mirror), extracted with NFStream, labelled with `--utc-offset-hours -3` and then deleted.

| Day | Flows | Labelled | Attack flows |
|---|---|---|---|
| Monday | 372,070 | 99.7% | none (normal day) |
| Tuesday | 321,856 | 99.2% | SSH-Patator 2,922, FTP-Patator 2,468 |
| Wednesday | 422,751 | 99.8% | DoS Hulk 77,934, GoldenEye 7,565, slowloris 5,355, Slowhttptest 4,502, Heartbleed 9 |
| Thursday | 355,130 | 99.3% | Web brute force 143, Infiltration 34, XSS 21, SQL injection 9 |
| Friday | 513,501 | 99.8% | PortScan, DDoS, Bot |

The training set is 1,942,434 rows, split by class and time (60/20/20, with a 120 s gap). Training takes about 2 minutes. The model's SHA-256 starts `4a59a3564377`.

| Model | Macro-F1 | Accuracy | BENIGN false-positive rate |
|---|---|---|---|
| Week XGBoost | 0.662 | 0.984 | 1.14% |
| Week XGBoost without `dst_port` | 0.616 | 0.983 | 1.17% |
| Friday XGBoost (for comparison, Friday only) | 0.729 | 0.983 | 1.54% |

Week XGBoost per class (test split):

| Class | Precision | Recall | F1 | Test rows |
|---|---|---|---|---|
| BENIGN | 0.995 | 0.989 | 0.992 | 177,097 |
| DoS Hulk | 1.000 | 0.925 | 0.961 | 10,701 |
| DDoS | 0.855 | 0.995 | 0.920 | 3,646 |
| PortScan | 0.544 | 0.999 | 0.704 | 1,660 |
| SSH-Patator | 1.000 | 0.979 | 0.990 | 485 |
| FTP-Patator | 0.959 | 1.000 | 0.979 | 398 |
| DoS slowloris | 1.000 | 0.731 | 0.845 | 275 |
| DoS Slowhttptest | 0.000 | 0.000 | 0.000 | 127 |
| Bot | 0.000 | 0.000 | 0.000 | 123 |
| Web Attack - Brute Force | 0.913 | 1.000 | 0.955 | 21 |
| Infiltration | 0.857 | 1.000 | 0.923 | 6 |
| Web Attack - XSS | 0.000 | 0.000 | 0.000 | 3 |
| Heartbleed | 1.000 | 1.000 | 1.000 | 1 |
| DoS GoldenEye | — | — | 0.000 | 0 |

### Most false alarms are label errors in the dataset

Of the 2,014 BENIGN test flows flagged as attacks:

- **1,360 (PortScan)** all come from **192.168.10.8 between 15:39 and 15:45 on Thursday**, to internal hosts on many ports. That is the infected machine scanning the internal network after the infiltration. The dataset labels it BENIGN; the model calls it a port scan, which it is.
- **614 (DDoS)** are flows between the **attacker's address 172.16.0.1 and the Friday web server 192.168.10.50 on port 80** that fall outside the labelled DDoS window.
- **40 remain**, about **0.02%** of normal test flows. That is the real false-positive rate on this data.

So the PortScan precision of 0.544 and much of the 1.14% understate the model. The labels were kept as published (the same decision as for Bot), and the correction is reported here.

### Why some classes score 0, and why macro-F1 is lower than Friday's

- **Slowhttptest:** its test rows have a median duration of 1 ms and go to high ports (median 38098). Its train rows last about 105 s and go to port 80. The test rows are reply-like flows inside the labelled window, not the attack itself, so this is a labelling artefact.
- **Bot:** the same label conflict as on Friday (see above).
- **GoldenEye and SQL injection:** the attacks are short bursts, and the 120 s gap removed all their test rows (GoldenEye loses 5,519 rows, SQL injection all 9). GoldenEye still counts as F1 0 in the macro average because the model predicts it 239 times, mostly for DoS Hulk.
- **XSS (3 rows) and Heartbleed (1 row)** are too small to score.

Macro-F1 averages over all of these equally, so it falls even though most attack classes score above 0.9.

### Confidence threshold

Raising the alert threshold barely lowers false alarms here (1.13% at 0.5, 1.10% at 0.9), because the label-error flows above are predicted with confidence about 1. It costs attack recall (93% at 0.5, 85% at 0.9, 68% at 0.99). On real normal lab traffic (see the false-positive section), a higher threshold still helps; this is checked per class in the lab test of every attack.

### Without `dst_port`

Macro-F1 drops from 0.662 to 0.616. Most of the drop is Infiltration (F1 0.92 to 0.29). The other classes change by 0.01–0.03, so the model mostly isn't relying on port numbers.

### Explanations

The flows tested are a stratified test-split sample: up to 40 per class, plus 200 normal flows, 551 in all (`data/processed/week_explain_sample.parquet`).

| Method | Mean confidence drop | Compared with random | Prediction changes | Beats random |
|---|---|---|---|---|
| SHAP | 0.416 | 7.8× | 42% | 87% of flows |
| LIME | 0.239 | 4.5× | 25% | 64% of flows |
| Random 5 features | 0.053 | — | — | — |

SHAP is still the more faithful method. The ratio is lower than on Friday because removing random features also moves this model's confidence more (0.053 against 0.010).

Global importance (top 3 by mean |SHAP|, `reports/week_xgboost_importance.png`):

| Class | Main features |
|---|---|
| PortScan | `rst_count`, `fwd_bytes`, `fwd_iat_std` |
| DoS Hulk | `rst_count`, `pkt_len_std`, `bwd_iat_max` |
| DoS slowloris | `bwd_iat_mean`, `pkt_len_max`, `bwd_bytes` |
| DDoS | `down_up_ratio`, `fwd_pkt_len_max`, `fwd_pkt_len_mean` |
| SSH-Patator | `dst_port`, `fwd_pkt_len_max`, `packets_per_s` |
| FTP-Patator | `dst_port`, `packets_per_s`, `iat_mean` |
| Web brute force | `fwd_pkt_len_std`, `duration_ms`, `pkt_len_max` |
| Infiltration | `dst_port`, `bwd_pkt_len_min`, `fin_count` |

The slow DoS class is explained by gaps between packets, and port scans by reset packets. Both match how these attacks work.

## Every lab attack with the full-week model (lab, 15 November 2026)

```
python scripts/lab_attacks.py      # writes reports/lab_attacks.json
```

**Method:**

1. Each attack script runs from the attacker container against the lab victim, once in dry-run and once with real blocking. Both modes use a 60 s block time.
2. The sensor runs `models/week_xgboost.joblib` and sends its alerts to the lab SOC.
3. tcpdump on the sensor records every packet to and from the attacker. The recording is the ground truth: it gives the attacker's flows, and the same model scores them offline.
4. **Detection rate** = the attacker's flows alerted as the right attack family, divided by all the attacker's flows.

| Attack | Attacker flows | Flagged as an attack | Right family | Class given | Median confidence | First alert | Dry-run: would block | Blocking: blocked at | Attacker's HTTP before → during → after the block |
|---|---|---|---|---|---|---|---|---|---|
| Port scan (nmap SYN, ports 1–1024) | 1,024 | 100% | 100% | PortScan | 0.995 | 122 s | yes | 123 s | 200 → none → 200 |
| SSH brute force (hydra, 210 passwords) | 45 | 100% | 100% | SSH-Patator | 0.992 | 126 s | yes | 175 s, during the attack | 200 → none → 200 |
| SYN flood (hping3, 2,000/s for 20 s) | 26,606 | 100% | 0% | PortScan | 0.996 | 122 s | yes | 123 s | 200 → none → 200 |
| Slow HTTP DoS (slowhttptest, 500 connections) | 523 | 0% | 0% | — | — | — | no | no block | — |
| SQL injection (sqlmap against DVWA) | 9 | 0% | 0% | — | — | — | no | no block | — |

The flow counts are from the dry-run; the blocking runs match within a few flows. The offline score of each recording equals the live result, so no flows were lost by the live capture and every result comes from the model itself.

### What this shows

- **Port scan and SSH brute force are detected, alerted and blocked.**
  - The first alert comes about 2 minutes after the first packet. That is NFStream's 120 s idle timeout: a flow is only scored once it has ended.
  - The port scan is over in half a second, so its block comes after the scan. The block still works: during it the attacker gets no answer from the victim, and access returns by itself after 60 s.
  - The SSH brute force runs for minutes. It was **blocked while it was still running** (at 175 s), which cut the rest of the attack off. Hydra took 428 s instead of 191 s, and 7 of its later flows were connection attempts that never got through (scored BENIGN, as they carry no data).
- **The SYN flood is caught and blocked, but named PortScan.** Each spoofed-port SYN is its own flow: one SYN, the victim's SYN-ACK and a reset. That is exactly what one probe of a SYN port scan looks like, so the flow features can't tell the two apart. CIC-IDS2017's DoS classes come from HTTP floods (Hulk, GoldenEye), not SYN floods, so the model has never seen this attack. The response is right (block the source); the label is wrong.
- **Slow HTTP DoS is missed.** All 523 flows score BENIGN, live and offline.
  - The lab's nginx closes a connection that hasn't finished its headers after 60 s (the default `client_header_timeout`), so the attack's flows last about a minute.
  - The model learnt slowloris from CIC-IDS2017's Apache server, whose flows lasted 75–105 s.
  - A different server with a different timeout changes the features enough to hide the attack. This is a limit of training on one dataset, examined in the next step (unseen data).
- **SQL injection is missed, and flow features can't catch it.**
  - sqlmap sent about 77 requests per run, all reaching DVWA. But it reuses each connection for many requests, so the whole attack is a handful of flows that look like ordinary web browsing.
  - The attack is in the request text (`' AND 1506=(SELECT ...`), which a flow model never sees.
  - This needs payload inspection: the rule-based Suricata comparison in the next steps.
  - The first sqlmap run had replayed results cached from an earlier run, and only the rerun with `--flush-session` is reported.

### Summary for the report

Of five lab attacks, **three are detected and blocked** (port scan, SSH brute force, SYN flood) and **two are missed** (slow HTTP DoS, SQL injection). None of the attacks produced a false block of a protected server, and every block ended by itself after its 60 s. The misses come from the limits of flow features and of a single training dataset, not from the sensor: the offline score of each recording matches the live result exactly. These are the cases where adding rules next to the model is worth it.

## Unseen data: our own labelled lab traffic (lab, 15 November 2026)

The full-week model was scored on traffic it never trained on: two rounds of every lab attack plus 2 × 10 minutes of normal traffic (web browsing, downloads, SSH and SCP sessions, ping), recorded on the sensor with tcpdump and turned into flows with the same NFStream features as the live sensor. The true label comes from the recording itself: in an attack recording, every flow to or from the attacker (10.10.1.10) is that attack, and in a normal-traffic recording every flow is BENIGN. DVWA's setup and login requests before sqlmap starts are left out. Script: `scripts/lab_unseen.py`; data: `data/processed/lab_labelled.parquet` (git-ignored); report: `reports/lab_unseen.json` (model checksum 4a59a3564377…).

The test split was scored without the 0.5 alert floor, so the comparison below uses the lab scores without it too. The floor changed nothing here.

| Class | Lab flows | Lab recall | Test-split recall | Test-split F1 |
|---|---|---|---|---|
| BENIGN | 386 | 91.7% | 98.9% | 0.992 |
| PortScan | 2,048 | 100% | 99.9% | 0.704 |
| SSH-Patator | 90 | 98.9% | 97.9% | 0.990 |
| DoS slowloris | 1,046 | **0%** | 73.1% | 0.845 |
| SYN flood (not a model class) | 53,742 | 0% as DoS (100% as PortScan) | — | — |
| SQL injection (not a model class) | 8 | 0% (all BENIGN) | — | — |

Recall is the fair column. F1 and precision depend on how many normal flows there are per attack flow, and the lab has far fewer normal flows than the test split.

### What this shows

- **Attacks that look the same everywhere carry over.** Port scan and SSH brute force score as well on our own network as on the test split, even though the hosts, addresses, operating systems and tools (nmap, hydra) are all different.
- **Normal web traffic is now clean.** All 353 normal web flows score BENIGN. With the Friday-only model, 14.8% of normal lab flows were false PortScan alerts (step 2), so training on the whole week fixed that.
- **Every normal SSH session is flagged as SSH brute force** (28 of 28, median confidence 0.89, up to 0.99). Most of the generator's SSH flows are SCP copies of a small file (median 0.2 s), plus a few interactive sessions of up to 32 s. Each one is a password login followed by a short exchange, which looks like one brute-force attempt. CIC-IDS2017 has very little normal SSH, so the model learnt "short SSH session means attack". The remaining false positives are 4 ping flows called FTP-Patator, at low confidence (0.52–0.81). So the lab false-positive rate, 8.3% (32 of 386), is much higher than the test split's 1.1%. No block is likely: blocking needs 5 confident flows from one source within 60 s, and the normal traffic makes about 1–2 SSH logins a minute. But an analyst would see these alerts.
- **Slow HTTP DoS doesn't carry over at all.** The lab's nginx cuts the slow connections at 60 s (median flow 60.0 s), while the CIC-IDS2017 Apache flows the model learnt from lasted 75–105 s. A change of web server is enough to hide the attack.
- **Attacks the dataset doesn't have are missed or misnamed.** The SYN flood is called PortScan (each flood packet looks like one scan probe), and SQL injection looks like browsing.

### Summary for the report

On unseen traffic the model keeps its scores for attacks whose flows look the same on any network (scans and brute force) and loses them where the training data was narrow: one web server's timeout (slowloris), too little normal SSH (false SSH-Patator alerts), and attack types the dataset never had (SYN flood, SQL injection). This is the dataset-generalisation gap reported in the literature on CIC-IDS2017, measured on our own network. The fixes are more varied training data (B1's analyst feedback, or a second dataset like CSE-CIC-IDS2018) and rules next to the model for what flows can't show (B2).

Limitations: 386 normal flows is a small sample, and the normal traffic comes from one generator on one host. CSE-CIC-IDS2018 was not tested (optional, needs a download).

## ML against rules: Suricata with ET Open (lab and CIC-IDS2017 Friday, 15 November 2026)

Suricata 7.0.10 with the free ET Open ruleset (updated 13 November 2026, 53,510 rules loaded) was run on the same traffic as the full-week model. Lab: two new recordings of every attack and of normal traffic (`data/raw/lab_pcaps/`, labelled the same way as the unseen-data test). CIC-IDS2017: the whole Friday capture, scored on the 34,687 Friday flows in the model's test split. HOME_NET is set to the protected network (lab 10.10.2.0/24, CIC 192.168.10.0/24) and EXTERNAL_NET to any, so the inbound-attack rules can fire. Suricata alerts are matched to flows by addresses, ports and time. Its own protocol-anomaly alerts ("SURICATA …") are counted separately. Almost all of them here are "TCPv4 invalid checksum", from checksum offload in the capture, and Suricata is told to ignore checksums. Script: `scripts/suricata_compare.py`; report: `reports/suricata_compare.json` (lab only: `reports/suricata_compare_lab.json`).

Suricata's rules often fire once per attack (after a threshold, or on one request) rather than on every flow. So the table gives both: does each attack raise any alert at all, and what share of its flows were flagged. "Security" leaves out informational rules (ET INFO, ET POLICY, ping notices).

### Lab

| Attack | Suricata: any alert | Suricata: flows flagged | ML: flows flagged | Either |
|---|---|---|---|---|
| Port scan (nmap) | **no** | 0% | 100% | 100% |
| SYN flood (hping3) | **no** | 0% | 100% (as PortScan) | 100% |
| SSH brute force (hydra) | yes (4–6 alerts per run) | 10% | 100% | 100% |
| SQL injection (sqlmap) | **yes** (41 alerts per run) | 25% | 0% | 25% |
| Slow HTTP DoS (slowhttptest) | no | 0% | 0% | 0% |

| Normal traffic (277 flows) | False-positive rate |
|---|---|
| Suricata, security rules | 2.9% (phpinfo page access; "Potential SSH Scan" from back-to-back SCP copies) |
| Suricata, all rules | 4.7% (adds ping notices) |
| ML model | 15.2% (the normal SSH sessions called SSH-Patator, as in the unseen-data test; SSH is a larger share of this recording) |

### CIC-IDS2017 Friday (test-split flows)

| Class | Flows | Suricata: any alert | Suricata: flows flagged | ML: flows flagged |
|---|---|---|---|---|
| PortScan | 1,660 | yes (3 in these flows; about 40 per database port over the day) | 0.3% | 99.9% |
| DDoS (LOIC) | 3,646 | yes ("ET DOS Terse HTTP GET", 1 here, 20 over the day) | 0.0% | 99.6% |
| Bot (Ares) | 123 | no | 0% | 0% |

BENIGN false-positive rate on the 29,258 normal test flows: Suricata 0.1% (security rules) or 0.3% (all rules); ML 2.1%. The ML side is in-distribution here: same day and tools as its training data, and 13.1% of these test flows have the same features as a training flow.

### What this shows

- **The two catch different attacks.** In the lab, the model catches the port scan and the SYN flood, which the default ET Open rules miss: ET Open ships its nmap SYN-scan rules switched off, and none of its enabled rules fired on the SYN flood. Suricata catches sqlmap, which the model can't see, because the attack is in the request text and the database's error replies (`ET WEB_SERVER SQL Errors in HTTP 200 Response`). Together they catch 4 of the 5 lab attacks; either alone catches 3.
- **Rules raise fewer false alarms.** Suricata's false-positive rate is 5–20× lower than the model's, in the lab and on CIC-IDS2017. Its rules describe specific bad behaviour, while the model flags anything that looks like an attack class.
- **Rules flag attacks, not flows.** Suricata usually alerts once per attack, so it notices each scan, brute force and DDoS but flags few of their flows. The model scores every flow. That makes the model better for blocking decisions (step 4's policy counts confident flows) and Suricata better as a high-precision signal for analysts.
- **Neither catches slow HTTP DoS.** ET Open has no slowloris rule, and the model learnt it from a different web server (see the unseen-data test).
- **Neither catches the CIC-IDS2017 Bot in the test split.** No ET Open rule matches the Ares bot's traffic. The model's Bot result comes from the label conflict described in the full-week model section.

### Summary for the report

A flow-based ML model and a signature-based IDS are complementary. The model finds volumetric and behavioural attacks (scans, floods, brute force) without any rule, including traffic the rules ignore by default. Signatures find attacks that live in the payload (SQL injection) and raise far fewer false alarms. This supports step 8: run Suricata next to the model, send both to the SOC, and keep automatic blocking on the ML policy.

LightGBM was not added (optional; see the roadmap).

## Learning from analysts: one feedback round in the lab (15 November 2026)

The full loop was run once in the lab with the step 7 code: the live sensor (dry-run, `week_xgboost`) watched 15 minutes of normal traffic; an analyst marked its false alerts as false positives in the SOC; `python -m soc.api.export_feedback` turned them into training rows; `python -m idps.detect retrain` trained a new model on the CIC-IDS2017 week plus the feedback and decided whether to keep it; the kept model was loaded on the sensor and the same normal traffic was run again.

**Feedback.** 300 normal flows gave 24 false alerts (21 SSH-Patator on SSH logins and SCP copies, 3 FTP-Patator on pings). All 24 arrived with their feature values and the model version. Marked false positive, they became 24 BENIGN training rows (no duplicates).

**Retrain decision.** The feedback was split by time: the oldest 17 rows were added to training (weight 5), the newest 7 held back. The new model is kept only if its macro-F1 on the original test split drops by no more than 0.005, its accuracy on the held-back feedback is at least the current model's, and at least 5 feedback rows were held back. All three held, so the model was kept (`models/week_xgboost_fb1.joblib`, version `xgboost-202611151051-57954de3`; report `reports/retrain_xgboost-202611151051-57954de3.json`).

| | Current model | Retrained model |
|---|---|---|
| CIC-IDS2017 test split (194,543 flows): macro-F1 | 0.6620 | 0.6627 |
| CIC-IDS2017 test split: BENIGN false-positive rate | 1.14% | 1.13% |
| Held-back feedback (7 flows): accuracy | 0% | 100% |

**On traffic the retrain never saw.** The lab recordings from the unseen-data test and the Suricata comparison were scored again with both models. They were recorded before the feedback round, so none of their flows were used.

| Recording | Normal flows passed (old → new) | SSH brute-force flows caught (old → new) | Port scan |
|---|---|---|---|
| Unseen-data test | 91.7% → **100%** | 98.9% → 95.6% | 100% → 100% |
| Suricata comparison | 84.8% → **100%** | 100% → 94.4% | 100% → 100% |

**Live, after the switch.** With the retrained model on the sensor, 15 more minutes of normal traffic (239 flows) gave **0 alerts**, against 24 before. The SOC's model list shows the sensor moving from `xgboost-4a59a356` to the new version at the time it was loaded.

**Drift.** The drift card reported "drifting" both before and after (largest PSI about 7, in packet sizes and timings). That is expected: drift compares live traffic with the training data, and the lab's short, fast LAN connections look nothing like CIC-IDS2017's. A few feedback rows fix specific false alarms; they don't make the training data look like the lab. It is the same dataset gap as in the unseen-data test, now visible on the dashboard while the sensor runs.

### Summary for the report

Analyst feedback closes the loop the unseen-data test opened: 24 marked alerts removed every false alarm on normal lab traffic, live and on recordings the retrain never saw, without hurting the CIC-IDS2017 test scores. The cost was a small drop in SSH brute-force recall (about 5% of its flows), because normal SSH and brute-force SSH logins look alike in flow statistics; the blocking policy needs 5 confident flows, so a brute force is still blocked. The keep-or-reject gate means a bad feedback round can't replace a working model. Limitations: one round, one kind of false alarm, and a 7-row holdout.

## Rules next to the model: Suricata live on the sensor (lab, 15 November 2026)

Suricata 7.0.10 with ET Open now runs next to the model on the sensor (`docker compose --profile rules up -d suricata`). It shares the sensor's network namespace, reads the same `lab_attack` interface, and writes only alert events; the sensor's rule forwarder (`IDPS_RULES_EVE`) follows that log and sends rule alerts to the SOC marked `source: "rule"`, next to the model's alerts. Engine events and informational rules are dropped, and repeats of the same rule between the same source, target and port within 60 s are folded into one alert with a count. Rule alerts never block on their own unless an admin lists the rule's SID, and even then only for an established TCP connection, never for an address in the protected network, and always through the allowlist and dry-run setting.

**Live check.** With the forwarder on and the retrained model (`week_xgboost_fb1`), sqlmap against DVWA and an nmap port scan were run while the sensor was live:

| Attack | Model alerts | Rule alerts |
|---|---|---|
| sqlmap (SQL injection) | 0 | **17** (47 matches folded; 11 signatures, such as `ET WEB_SERVER SQL Injection Select Sleep Time Delay`, `ET SCAN Sqlmap SQL Injection Scan`, `ET WEB_SERVER SQL Errors in HTTP 200 Response`) |
| nmap port scan | 1,024 (PortScan) | 0 |

The forwarder reported 17 alerts sent, 30 folded, and nothing dropped, rate-limited or invalid. The two detectors now cover each other live, as the offline comparison predicted: the SQL injection the model can't see arrives as rule alerts, and the scan the default rules ignore arrives as model alerts. Rules are also faster: the first alert of each rule reached the SOC 0.1–0.5 s after the matching packet (11 of the 17), and the 6 folded follow-ups when their 60 s window closed (49–60 s). Model alerts wait for the flow to end (about 2 minutes, from the 120 s idle timeout).

**In the SOC.** Alerts carry a "rule" tag; the Alerts page and the Threat Center's live alerts filter by "Raised by" (model, rule or both); a rule alert's page shows the matched signature, SID, category and Suricata severity instead of a model explanation; the Alerts number splits model and rule counts; Sensor health shows the forwarder's state. Rule alerts are never used as training rows.

**Hardening** (from the review): the Suricata container keeps only the `NET_RAW` and `DAC_READ_SEARCH` capabilities, with `no-new-privileges`, a 3 GB memory limit and a process limit; capture works without `NET_ADMIN`. Rule alerts have their own outbox cap and a per-minute limit, so a flood of them can't push model alerts out during an SOC outage.

## Integrations: notifications, SIEM export and IP reputation (15 November 2026)

The SOC can now send new alerts to people and to other tools. All channels are optional and configured only in the SOC's environment (or `_FILE` secrets); the API never returns a URL, token or password, and errors are scrubbed before they are shown or audited. Docs: `docs/soc.md`, "Integrations".

| Channel | What it sends | Default |
|---|---|---|
| Webhook | JSON per alert, signed with HMAC-SHA256 over a timestamp and the body | high and critical, model and rule alerts |
| Slack | One message per alert (class, severity, rule signature, source → target, sensor, link) | high and critical |
| Email (SMTP, STARTTLS or SSL) | Plain-text and HTML message | high and critical |
| Syslog / CEF (UDP, TCP or TLS, RFC 5424) | Every alert from low up, plus blocks, in CEF for SIEMs such as Splunk or Elastic | low and above |

Delivery never slows alert ingest: each channel has a bounded queue and one worker, with retries, a per-minute limit that turns a burst into one "and K more" summary, and suppression of repeats (the same class from the same source, or the same rule between the same addresses) for a few minutes. Admin → Integrations shows each channel's state (configured, last success, last error, counts) and a test button that sends one labelled test message.

**Check.** On a local SOC with receivers on loopback (`lab/soc/listen.py`), the test buttons delivered to all three configured channels (Slack had no webhook and showed "not configured"). A critical alert then arrived as a signed webhook, an email and a CEF syslog line at severity 10, and a low-severity port scan only as syslog, as configured. After restarting the syslog receiver, which is what a SIEM restart looks like, the next alert still arrived.

**Reputation.** An alert's page can look up the source IP on AbuseIPDB, but only when the analyst clicks: only the IP is sent, private and reserved addresses are never sent (and the page says so without a button), results are cached for 24 hours, lookups are capped per minute and per day (900, under the free plan's 1,000), and each real lookup is audited because it discloses an IP to a third party. Without a key it reports "not configured".

**Security review.** The review checked the outbound requests most closely, because a webhook URL is a way to make the SOC open connections. Webhook and Slack URLs must be https and resolve only to public addresses (IPv4 inside IPv6 forms such as NAT64 and 6to4 are decoded and checked); the SOC connects to the address it checked, never follows redirects and ignores proxy settings; every exchange has an overall deadline, so a server that answers one byte at a time can't freeze a channel. Attacker-influenced text (rule signatures, class names) is escaped for Slack, email headers and HTML, and CEF. Private destinations and plain http need an explicit lab-only flag.

**Lab note.** The lab SOC container blocks all outbound connections by design, so it can't reach Slack, a mail server or a SIEM. Trying the channels in the lab uses receivers inside the SOC container (`lab/README.md`, "Trying the integrations").

## Production database: PostgreSQL, migrations, retention and backup (15 November 2026)

The SOC now runs on PostgreSQL as well as SQLite. Its schema is managed by Alembic migrations
(revision `0001_initial` is the schema as it stood before this step), old data is deleted on a
schedule, and a portable backup can be restored into either database. The lab SOC was moved
from its SQLite file onto PostgreSQL 16 with all of its data.

### The lab move

| | |
|---|---|
| Data moved | 1,093,056 rows: 1,076,526 alerts, 16,472 audit entries, users, sensor token, blocks, would-blocks, model versions |
| Row counts after the move | identical in all 12 tables |
| Time for the whole move (adopt, back up, restore) | 2 min 40 s |
| Backup file (gzip JSON lines) | 21 MB, from an 894 MB SQLite file |
| PostgreSQL database after the move | 844 MB |
| Backup of the running PostgreSQL SOC | 30 s; restored into a new SQLite file in 39 s, identical counts |
| Schema check after the move (`db check`) | at head, matches the models |

The first attempt was refused, without changing the data, because the old lab database lacked
an index the models declare (`ix_alerts_received_class_anomaly`; the old temporary upgrade only
indexed columns it added itself). Adoption now adds missing declared indexes, and refuses
anything that is not purely additive before it changes anything.

### Live check on PostgreSQL

With the sensor live and the attacker running the port scan, 1,024 PortScan alerts reached the
PostgreSQL SOC, with explanations and the model version. New alert ids carried on from the
restored ones (1,076,527 on), so the sequences were reset correctly, and the sensor's outbox
drained to 0. The SOC logs in as an ordinary database role, not as the superuser.

### Speed with a million alerts

Dashboard summary (`/metrics/summary`), same data, inside the SOC container:

| Window | SQLite | PostgreSQL |
|---|---|---|
| 24 hours (≈490k alerts) | 18.9 s | 9.7 s |
| 7 days (≈1.08M alerts) | 29.7 s | 9.5 s |

PostgreSQL is 2–3 times faster at this size. Both are too slow for a dashboard that refreshes
often; this is the existing grouped query over every alert in the window, not something the move
introduced. Counting alerts per hour as they arrive, instead of on every request, would fix it.

Retention, after the reviews' fixes (keyset batches, a plan that scans by id on SQLite, indexes
on the alert links, case-then-alert lock order): deleting 200,000 old alerts took 2.25 s on SQLite
(24.5 s before the fixes) and 14.9 s on PostgreSQL; 1 million took 14.7 s on SQLite, close to
linear. 20,000 alerts with 20,000 linked blocks and would-blocks took 2.2 s on PostgreSQL (17.4 s
before the link indexes). The first retention pass over the lab's 1.08M alerts took 8.5 s and correctly
deleted nothing, as all of them are younger than 180 days.

### Tests

Full suite on SQLite: 1,686 passed, 24 skipped (the PostgreSQL-only tests). SOC tests on
PostgreSQL 16: 850 passed, 1 skipped (SQLite-only). New
tests cover: migration 0001 equals the models on both databases, downgrade and upgrade, adoption
of old databases (additive changes only, refusals change nothing), four processes migrating at
once on PostgreSQL, backup and restore of every table and type (timezones, JSON null versus SQL
null, enums, large integers) across SQLite and PostgreSQL in both directions, refusals (non-empty
target, tampered file, existing output), ingest continuing during a SQLite backup (WAL), every
retention rule at its boundary, on PostgreSQL an analyst attaching an alert or reopening a case
while a prune runs (no deletion against the rules, no deadlock), a manual prune not starving
alert intake on SQLite, and partial runs being audited.

### Summary for the report

The SOC can run on a production database and be upgraded safely: migrations replace the
add-columns stop-gap, an old database is adopted only when the change is purely additive, and a
portable, checksummed backup moves a SOC between SQLite and PostgreSQL. Old data is deleted on a
schedule (alerts 180 days, audit 365, assistant chats 90; labelled alerts kept as training data),
which step 13's privacy work builds on. Moving the lab's 1.08M alerts took under 3 minutes with no
loss, and PostgreSQL made the dashboard summary 2–3 times faster.

## Security: MFA, single sign-on, sensor certificates and signed models (16 November 2026)

Roadmap step 11. Built by Opus; reviewed and security-audited by a separate Sonnet reviewer.

### Lab checks

| Check | Result |
|---|---|
| Admin signs in with password only | No access token: asked to set up an authenticator app (QR code), then 10 recovery codes |
| Same TOTP code used twice; 8 requests with one code at once | Refused; exactly one of the 8 succeeds |
| Recovery code | Works once, logs out other sessions, audited |
| Sensor on the sensor port (8444) without a certificate | Cut off in the TLS handshake, before any HTTP |
| Sensor token alone on the main port (8443) | 401 |
| One sensor's certificate with another sensor's token | 401 (tests) |
| Real lab sensor over mutual TLS during a port scan | 1,280 alerts delivered, outbox empty |
| Signed model | Loads; the sensor reports the key id (`0cb723d4e5506565`) to the SOC |
| Unsigned model / model changed by one byte (sha256 rewritten to match) | Refused before unpickling |
| Migration 0002 on the lab's PostgreSQL (1.08M alerts) | Applied at start-up; `db check` clean |

### Security audit

No critical findings and no way around MFA, the certificate check or the signature check. Fixed
before commit: the cloud SOC's package list (it lacked cryptography, segno and alembic), turning
MFA on from a session now needs the password (a stolen session token could otherwise lock the
owner out), atomic enrolment, provider network errors returning 500, wrong lab instructions, and a
typo on the Account page logging the user out. Hardened: an admin is linked to a single sign-on
account only once they have MFA; disabled users are never linked; a flood of SSO starts cannot
lock sign-on out. Accepted and documented: someone with the password can keep a user's MFA step
locked; a signed older model can be put back (rollback); mutual TLS needs the SOC to terminate
TLS itself (not behind the AWS deployment's Caddy); the first enrolment of an admin is protected
by the password only.

### Tests

Full suite: 1,996 Python tests passed, 29 skipped (PostgreSQL-only); 981 dashboard tests passed.
New: TOTP vectors and replay (also concurrent), MFA flows and lockouts, 80 single sign-on cases
against a fake provider (algorithm confusion, nonce, audience, issuer, azp, state reuse, browser
binding, key rotation, account linking), a real two-port server for mutual TLS (no certificate,
wrong CA, another sensor's certificate, keep-alive), 57 model-signing cases, migration 0002 up and
down, and the dashboard's MFA and SSO screens.

### Summary for the report

The IDPS now protects itself, not only the network: admins need a second factor, sensors prove
who they are with certificates bound to their names, and the sensor refuses any model that is not
signed by the person who approved it, so a tampered model cannot quietly blind detection.

## Packaging: images, install script and upgrades (16 November 2026)

Roadmap step 12. Built by a Sonnet implementer; reviewed twice by an Opus reviewer; checked in
the browser by this session.

### What a fresh machine gets

`deploy/install.sh soc` builds (or loads) three versioned images: `idps-soc` (610 MB),
`idps-proxy` (Caddy plus the built dashboard, 89 MB) and `idps-sensor` (1.52 GB, 0.4 GB less
after dropping unused GPU libraries). It generates the secrets into 0600 files, starts
PostgreSQL, the SOC and Caddy, issues the sensor-port certificates and creates the first admin,
whose password goes only to a file. The admin must set up two-factor sign-in at the first login.
`install.sh add-sensor NAME` makes an enrolment bundle; `install.sh sensor` installs a sensor on
another host. `upgrade`, `rollback`, `restore`, `renew-sensor`, `status` and `uninstall` cover the
rest (docs/deploy.md).

### Checks

| Test | Result |
|---|---|
| Fresh install from a clean copy, on a host that had never pulled the database image | 42/42 checks: dashboard over HTTPS (verified against Caddy's root), security headers, `/api` works, port 8000 unpublished, admin asked to enrol MFA, sensor port refuses a client without a certificate and accepts one with it, secrets 0600 and never printed, a second run changes nothing |
| Every dashboard page under the production Content-Security-Policy | No violations (this session, in the browser) |
| Upgrade 0.1.0 to 0.2.0 | 57/57 checks: database migrated from revision 0001 to 0002, data and MFA kept, backup taken first with the old version; a broken new version is rolled back automatically; `rollback` refuses when the old version cannot read the newer schema; `restore` puts back a backup and refuses a damaged one; `renew-sensor` |

The reviews found, among others, that a truly fresh machine never got PostgreSQL, that a sensor
capability allowed reading host files from a compromised sensor, and that the documented restore
deleted its own backup; all were fixed and are covered by the scripts above.

Not tested: the `--domain` (Let's Encrypt) path, a real Linux host, and live capture by the
packaged sensor. The "0.1.0" of the upgrade test is the step 11 code with the new packaging, since
that release had no installer. A Helm chart is not provided.

### Tests

2,043 Python tests passed (29 skipped, PostgreSQL-only), 981 dashboard tests passed.

## Reports and privacy: weekly PDF and DPDP controls (16 November 2026)

Roadmap step 13. Backend by a Sonnet implementer, reviewed three times by an Opus reviewer;
dashboard pages (Reports, Privacy) by this session, reviewed by a Sonnet reviewer.

### Weekly PDF report from the lab's data

Generated from the lab's PostgreSQL database (1.08M alerts) in **1.8 s**, 6 KB, two pages:
1,077,550 alerts in week 2026-W46 (Saturday the busiest day with 1.02M), 99.98% port scans,
the top 10 source addresses, 10 blocks of the attacker 10.10.1.10 (9 automatic, 1 by an analyst),
41 dry-run would-blocks, the analysts' false-positive rate (24 of 25 triaged), detection latency
(p50 121 s), and model health (drift level 9.86 flagged, the two model versions seen). Every page
carries a personal-data footer. It is downloadable from the Reports page and can be emailed every
Monday through the SOC's email settings (off by default).

### Erasing an address everywhere (lab, PostgreSQL)

The acceptance test erased 50.63.243.230 (a CIC-IDS2017 replay address), after a backup:

| Check | Before | After |
|---|---|---|
| Erasure preview | 7 alerts, 1 audit entry | all zero |
| Independent scan of all 16 tables (each whole row as text) | 7 alerts, 1 audit entry | none |
| Weekly PDF for the same week | address in the top 10 | absent |
| Erasure record | | kept with its reason, without the address |

The erasure took 4.7 s; the preview 4.9 s. Writers wait only for the short write phase (0.01 s
for this address; about 1 s for an address with 50,000 alerts), since the scan runs outside the
write lock. The access log keeps only keyed fingerprints of addresses, so it needs no erasure
and still answers "who looked at this address?". What erasure cannot reach is documented in
docs/privacy.md: notifications and SIEM copies already sent, backups until they are deleted,
AbuseIPDB, and web server logs.

### Reviews

The Opus reviews found, among others: a running assistant reply that could write an erased address
back, a manual "send now" that stopped the scheduled email, IPv6 spellings the search missed, a
scan that blocked writes for about 19 s on SQLite, rows written during an erasure surviving it, and
reads by the assistant's tools that were not access-logged. All were fixed and tested, on SQLite
and on PostgreSQL. The UI review found a stale preview that could erase an address the admin had
not retyped; fixed.

### Tests

2,300 Python tests passed on SQLite (34 skipped, PostgreSQL-only); the privacy, report, access-log,
migration and assistant suites also passed on PostgreSQL 16 (257). 1,038 dashboard tests passed.

### Summary for the report

The SOC now documents itself to the people whose data it holds: a public privacy notice with the
real retention periods, an access log of who viewed which address, and a verified way to erase an
address from every table on request, as India's DPDP Act expects of a data fiduciary. A weekly PDF
gives management the same numbers without a login to the dashboard.

