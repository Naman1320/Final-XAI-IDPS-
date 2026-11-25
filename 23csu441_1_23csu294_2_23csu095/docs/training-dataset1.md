# Training dataset1: three more public datasets (plan, 17 Nov 2026)

Requirement: the method must be evaluated on at least 3 publicly available datasets. Today only one
is used (CIC-IDS2017; the lab captures are our own, not public). This plan adds three, giving four.
**Not started: wait for the user's "proceed" and the download steps below.** Order agreed:
this plan, then the cloud plan (`docs/cloud-plan.md`), then step 14 (write-up), then step 15 (demo).

## The datasets

| Dataset | Year | Download | Files to use | Features | Classes |
|---|---|---|---|---|---|
| [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | 2018 | **No form, no account, no billing**: public AWS open-data bucket, anonymous: `aws s3 sync --no-sign-request "s3://cse-cic-ids2018/" ...` (or plain HTTPS). Only the "Processed Traffic Data for ML Algorithms" CSVs, not the PCAPs | per-day CSVs | CICFlowMeter-V3, 80 features (same family as our CIC-IDS2017 work) | Brute force (FTP, SSH), Heartbleed, Botnet, DoS, DDoS, Web attacks, Infiltration |
| [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) | 2023 | **Request form the user fills in** (first/last name, email, organisation, job title, country) at cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/. Never filled in by Claude | `CSV/` folder only (not `PCAP/`) | DPKT-extracted flow features (flow_duration, Header_Length, protocol type, IAT, ...) | 33 attacks in 7 classes: DDoS, DoS, Recon, Web, Brute force, Spoofing, Mirai |
| [CIC IIoT 2025 (DataSense)](https://www.unb.ca/cic/datasets/iiot-dataset-2025.html) | 2025 | **Request form the user fills in** (same fields) at cicresearch.ca/IOTDataset/Datasense/. The form showed "Server error" on 17 Nov: retry later | network-traffic feature files only (the release also has sensor time series; use them only if time allows) | not stated on the page: check after download | 50 attacks in 7 categories: DDoS, DoS, Recon, Web, Brute force, MITM, Malware (Mirai) |

Citations:
- **CSE-CIC-IDS2018:** Sharafaldin, Habibi Lashkari, Ghorbani, ICISSP 2018. The licence allows redistribution, but you must cite the paper and link the AWS page.
- **CICIoT2023:** Neto et al., Sensors 23(13):5941, 2023.
- **CIC IIoT 2025 (DataSense):** Firouzi, Dadkhah, Maret, Ghorbani, Electronics 14:4095, 2025.
- **Also cite** for the CIC-IDS2017 label errors (limitations section): Engelen et al. (LYCOS-IDS2017).

## Disk space (about 12 GB free on 17 Nov)

Sizes are not stated on the pages, so they are checked before each download and nothing is downloaded that would leave under about 5 GB free.

- **CSVs only:** never the PCAPs.
- **CICIoT2023:** a stratified subset if its CSVs are very large.
- **Space to free first, only with the user's yes:**
  - the 8.2 GB Friday pcap;
  - old `idps-lab-*:pre-step*` image tags;
  - the unused `idps-lab_soc_db` volume.

## Method (the same code for every dataset; the methods match, the difficulty does not)

1. **Load and clean:**
   - map labels to a common scheme;
   - drop identifier columns (IPs, ports where they leak the label, timestamps, flow ids);
   - remove duplicates and inf/NaN rows;
   - record the class counts.
2. **Split without leakage:** by time where timestamps exist (CSE-CIC-IDS2018 has a per-day attack schedule); otherwise stratified, with exact-duplicate rows kept on one side only.
3. **Train the same pipeline as CIC-IDS2017:**
   - XGBoost multiclass, plus the Isolation Forest anomaly score;
   - the same hyperparameter budget;
   - class weights for imbalance.
4. **Measure:**
   - macro-F1, per-class precision/recall, false-positive rate on benign traffic;
   - training and inference time;
   - SHAP (and LIME) explanation faithfulness with the existing deletion test.
5. **Cross-dataset generalisation:**
   - CIC-IDS2017 <-> CSE-CIC-IDS2018 on their shared CICFlowMeter features, in both directions;
   - CICIoT2023 <-> CIC IIoT 2025 on shared features where they exist.

   A drop here is expected and must be reported honestly.
6. **Output:**
   - one comparison table and charts in `docs/results.md`;
   - signed model bundles for each dataset (`python -m idps.detect sign`);
   - each dataset's preprocessing documented.

## Who does what

| Part | Model |
|---|---|
| Loaders, cleaning, splits, training, evaluation scripts | implementer subagent (Sonnet) |
| Review of that code (leakage, label mapping, splits) | reviewer subagent (Opus) |
| Tests (loaders, label maps, split leakage checks) | test-runner subagent (Sonnet) |
| Results tables, charts, interpretation for the report | main session (Opus) |

Never Fable.

## What the user does

1. Fill in the two CIC request forms (CICIoT2023, CIC IIoT 2025) with their own details, and download
   the CSV folders the forms give access to into `data/raw/ciciot2023/` and `data/raw/ciciiot2025/`
   (or paste the download links in chat so Claude can fetch them, after a yes).
2. Say yes to the CSE-CIC-IDS2018 CSV download (no form) and to freeing disk space if needed.

## Time estimate

| Part | Time |
|---|---|
| Downloads (depends on the internet speed and the file sizes; CIC servers can be slow) | 1-3 h, mostly waiting |
| CSE-CIC-IDS2018: loader, cleaning, train, evaluate | 1.5-2 h |
| CICIoT2023: loader, subset, train, evaluate | 1.5-2 h |
| CIC IIoT 2025: inspect format, loader, train, evaluate | 1.5-2.5 h (format unknown until downloaded) |
| Cross-dataset tests | 1 h |
| Opus review, fixes, tests | 1.5-2 h |
| Results tables, charts and write-up text | 1-1.5 h |
| **Total** | **about 9-13 h of work, plus download waiting** |

Usage-limit pauses add waiting time on top. If the IIoT 2025 form stays broken, CIC-IDS2017 +
CSE-CIC-IDS2018 + CICIoT2023 still make three public datasets, which meets the minimum; IIoT 2025
then becomes an optional fourth.

## CSE-CIC-IDS2018: preprocessing and results (code built 17 Nov 2026)

Code: `idps/public/` (kept apart from the PCAP/flow pipeline, which uses our own `MODEL_FEATURES`).
Tests: `tests/test_public_cse2018.py`. Data: `data/raw/cse-cic-ids2018/*.parquet` (every column text,
written by `scripts/fetch_cse_cic_ids2018.py`), `data/raw/cic-ids2017/TrafficLabelling/*.csv`.

### Run

```
python -m idps.public run      # the whole thing: 2018 and 2017 (through this pipeline) train/evaluate, SHAP/LIME, cross-dataset
python -m idps.public cse2018  # only the CSE-CIC-IDS2018 part
python -m idps.public cross    # only the 2017 <-> 2018 test (loads both samples again; trains 2017 in-domain too, --no-2017-report skips that)
python -m idps.public labels   # the label table below

# smoke run on whatever files exist so far
python -m idps.public run --max-rows 200000 --cap-benign 5000 --cap-attack 3000 \
       --faith-n 20 --lime-samples 200 --models-dir /tmp/m --reports-dir /tmp/r
```

Options: `--cap-benign` (default 250000) and `--cap-attack` (150000) flows per day and label;
`--max-rows N` reads only the first N rows of each file; `--only 01-03 ...` restricts the day files;
`--gap-s` (120) and `--max-gap-loss` (0.10, see Split); `--faith-n` (100), `--lime-samples`,
`--no-lime`, `--no-faithfulness`; `--cross-train-cap` (200000 training rows per class in the
cross-dataset test); `--no-2017-report`; `--models-dir`, `--reports-dir`, `--seed`. Memory: the file is
read in batches of 262144 rows, twice (pass 1: Label, Timestamp, Dst Port to choose the rows; pass 2:
the 78 feature columns of the chosen rows only), so memory follows the sample, not the 16 million rows.
Only files listed in `manifest.json` are read (a half-downloaded file is ignored).

**Memory of `run` at full size (arithmetic, not measured: the full run has not been done on this
machine).** A float32 row of 78 features is 312 bytes, so a sample of 3 million rows is about 0.94 GB.
Alive together: the 2018 sample (0.94 GB) while it is split, then its train and test parts (about
0.9 GB; the validation part is dropped after the 2018 reports), then ONE deduplicated 2018 frame
(about 0.9 GB; the undeduplicated `df18` is released before 2017 is loaded: `run` hands it over in a
dict and `cross.dedupe` returns the only copy that is kept; duplicates are found with chunked row
hashes, never a second float64 copy), then the 2017 sample and its split (about 1 GB at the default caps).
The 2017 loader reads one CSV at a time and turns only the rows kept by the caps into float32 (it used
to build a float64 frame of every row of the file first). Peak estimate: about 3 to 4 GB plus XGBoost's
own working memory; cross-dataset prediction runs in chunks of 250,000 rows. If memory is short, run
`cse2018` and `cross --no-2017-report` as separate commands (each process frees everything at exit).

### Preprocessing, in order (class counts after every step are in `reports/cse_cic_ids2018_preprocessing.json`, `class_counts_by_step`)

1. **Header rows.** Some files repeat the header inside the data; a row whose Label, Timestamp or
   Dst Port equals its own column name is dropped (counted as `header_rows`). The published Tuesday 20-02
   file has 4 extra columns (Flow ID, Src IP, Src Port, Dst IP); columns are read by name, so they would
   be ignored. **That file is not in the data**: only nine of the ten day files were downloaded
   (`manifest.json`), Tuesday 20-02 is missing. It matters: it holds DDoS attacks-LOIC-HTTP, the only 2018
   DDoS tool that resembles 2017's DDoS, The 2018 DDoS class here is
   HOIC + LOIC-UDP only, so DDoS-vs-DDoS in the cross-dataset test compares different tools (see below).
2. **Timestamp.** `dd/mm/yyyy hh:mm:ss`, whole seconds, taken as published: the dataset's timezone is
   not known or converted and the value is only used to order flows (`start_ms` = seconds x 1000, read as
   UTC). **The hour is on a 12-hour clock without AM/PM**, not a 24 h clock. Evidence, per file, in
   `raw_hour_histogram`: the hours that occur are only 1-5 and 8-12 (a handful of stray rows have 6 or 7);
   0 and 13-23 never occur. The attack windows against the dataset's published schedule:

   | File | Attack | Raw hours in the file | After the rule | Published schedule |
   |---|---|---|---|---|
   | Wed 14-02 | FTP-BruteForce | 10-12 | 10:33-12:10 | 10:32-12:09 |
   | Wed 14-02 | SSH-Bruteforce | 2-3 | 14:01-15:32 | 14:01-15:31 |
   | Fri 16-02 | DoS-SlowHTTPTest | 10 | 10:12-10:58 | 10:12-11:08 |
   | Fri 16-02 | DoS-Hulk | 1 | 13:45-13:48 (the file is cut at 1,048,575 rows) | 13:45-14:19 |

   (The "after the rule" column is measured by the loader on the real files.) **The rule: hours 1-7 are
   afternoon (+12 h), hours 8-12 stay (12 = noon).** The row order in the files is NOT chronological (the
   hour at each decile of Wednesday 14-02 is 8, 11, 2, 3, 9, 12, 10, 10, 10, 2), so the file order cannot be
   used instead. The hours 6 and 7 are ambiguous (18:xx/19:xx or 06:xx/07:xx): 3 rows in all the data (hour
   7 twice in Wed 14-02, hour 6 once in Thu 22-02, all Benign); they are unfolded like the other hours 1-7
   and counted per file (`ambiguous_hour_rows`, in total in the load report). A row with hour 0 or 13-23
   cannot come from this clock: it is dropped and counted (`hour_outside_12h`; none in the real files), and a
   file where more than 1% of the rows do that is refused (it would be a 24 h file). Rows whose DATE is not
   the day in the file name are dropped and counted per file (`wrong_date`, with the dates in
   `wrong_date_by_date`): 5 in Wed 14-02 (stamped January 1970; 05/01, 08/01, 12/01) and 9 in Thu 22-02
   (1970-01-10, -11, -12); none in the other files, and no January-2018 stamps. (The old filter only checked the year, so a
   January-2018 stamp would have passed.) A file name without a date only gets the year check. Unparseable
   text is `bad_timestamp`; a file with more than 5% of those is refused.
3. **Labels** are mapped to a common scheme shared with CIC-IDS2017 (table below). The original label is
   kept in `label_original`. An unknown label is an error, never a silent drop.
4. **Sample** (`idps/public/sampling.py`): at most `cap` flows per (day, original label), 250000 for
   BENIGN and 150000 per attack label by default. Within a group the flows are put in time order and
   evenly spaced ones are taken (systematic sampling, seeded random start), so the sample covers the
   whole attack window and the time split still has early and late flows. Groups under the cap are
   kept whole. Same input and seed give the same sample; one group's pick does not depend on another's.
   The caps apply before step 5, so a group can end slightly under its cap.
5. **Numbers.** 78 feature columns are parsed to float32. A row with any "Infinity", "NaN", empty,
   unparseable or float32-overflowing cell is dropped whole (counted, with the columns responsible);
   nothing is filled in. Negative values (for example Flow Duration, Init Win Bytes = -1) are
   real CICFlowMeter output and are kept.
6. **Identifier columns** are never features: Flow ID, Src IP, Src Port, Dst IP, Timestamp (used only
   to split). **Dst Port** is trained both ways, like the `*_noport` models:
   `cse2018_xgboost.joblib` (78 features) and `cse2018_xgboost_noport.joblib` (77), on the same split.
7. **Split** (`idps.detect.split.split_by_class_time`, same function as CIC-IDS2017): per (day, original
   label) sorted by Timestamp, first 60% train, next 20% validation, last 20% test. Rows starting less
   than the gap (120 s, the flow timeout) from a cut are dropped. Two additions for this dataset,
   both options of the existing function: groups are the *original* label, so every attack (Hulk,
   GoldenEye, ...) is cut, not only the merged DoS class; and the gap shrinks so that at most 10% of a
   group is dropped (`--max-gap-loss 1` restores the fixed gap). Without that, a burst of a few minutes
   (the Friday 16-02 DoS-Hulk flows span 3 minutes, and that day's benign flows sit inside them) is
   removed entirely and the class vanishes. The shrunk gap is the 10% quantile of the rows' distances to the
   cuts, taken as an actual distance (`method="lower"`) and never above the nominal gap; a group of fewer
   than about 10 rows can end up with a gap of 0, which drops nothing and lets train and test touch at the
   cut: such groups are listed in `groups_with_zero_effective_gap`. (An earlier version interpolated the
   quantile: a 2-row group with a 1000 s gap could get a larger gap than that and lose half its rows.) The
   report lists the gap used (`effective_gap_ms`), the rows dropped by the gap per label and the share of
   each label lost, and every report's per-class table prints the effective gap next to the test support.
   Timestamps have 1 s resolution, so flows with the same second as a cut can fall on either side of it.
8. **Exact duplicates** (all 78 features plus the common label) are removed inside each split, so a
   vector can still occur in train and test; each trained variant then deduplicates its own parts again
   on its own vector (the no-port variant on 77 features, `variant_duplicates_removed` in its report), so
   its train overlap is computed on the vector it trains on; `train_overlap` gives the share of validation/test rows
   whose feature vector (the features the model uses) is identical to a train row. A high share means
   the score measures memorisation. The comparison uses 64-bit row hashes (flat memory on millions of
   rows).
9. **Training** is the CIC-IDS2017 pipeline: XGBoost multi:softprob (200 trees, depth 6, learning
   rate 0.1, subsample/colsample 0.9, hist), class weights from the train split only, an IsolationForest
   (200 trees, contamination 0.01) on BENIGN train rows. Measured: macro-F1, per-class P/R/F1,
   BENIGN false-positive rate, ROC-AUC (one-vs-rest), the anomaly detector's detection rates, training
   and inference time, and the SHAP and LIME deletion test on a class-balanced test sample
   (`--faith-n` flows, background 200 train rows).

### Label mapping (CIC-IDS2017 <-> CSE-CIC-IDS2018 -> common class)

| Common class | CIC-IDS2017 label | CSE-CIC-IDS2018 label |
|---|---|---|
| BENIGN | BENIGN | Benign |
| DoS | DoS Hulk | DoS attacks-Hulk |
| DoS | DoS GoldenEye | DoS attacks-GoldenEye |
| DoS | DoS slowloris | DoS attacks-Slowloris |
| DoS | DoS Slowhttptest | DoS attacks-SlowHTTPTest |
| DDoS | DDoS | DDoS attacks-LOIC-HTTP |
| DDoS | (not in dataset) | DDOS attack-HOIC |
| DDoS | (not in dataset) | DDOS attack-LOIC-UDP |
| PortScan | PortScan | (not in dataset) |
| BruteForce | FTP-Patator | FTP-BruteForce |
| BruteForce | SSH-Patator | SSH-Bruteforce |
| WebAttack | Web Attack – Brute Force | Brute Force -Web |
| WebAttack | Web Attack – XSS | Brute Force -XSS |
| WebAttack | Web Attack – Sql Injection | SQL Injection |
| Bot | Bot | Bot |
| Infiltration | Infiltration | Infilteration |
| Heartbleed | Heartbleed | Heartbleed |

(The sample has no Tuesday 20-02 file, so `DDoS attacks-LOIC-HTTP` is absent from it.)

Matching ignores case, spaces and dashes (`Brute Force -Web`, `Web Attack \u2013 Brute Force` and the
Windows-1252 byte 0x96 all work). PortScan exists only in 2017; the 2018 HOIC and LOIC-UDP DDoS
tools only in 2018. The table is `LABEL_TABLE` in `idps/public/labels.py`.

### Cross-dataset test (CIC-IDS2017 <-> CSE-CIC-IDS2018)

The 2017 side is read from `TrafficLabelling` (it has Timestamp and the label; MachineLearningCSV has no
Timestamp). **All 78 CICFlowMeter feature NAMES match** (`FEATURE_NAMES` in `idps/public/labels.py` holds the
2017 -> 2018 mapping; 2017's duplicate "Fwd Header Length" column is read once). That is true for names
only, not for meaning: in 2017 the RST, ECE, CWE and Fwd URG flag counts are 0 everywhere except in one file
(Thursday afternoon, where all four equal 62.9%: a column-shift defect), while in 2018 RST equals ECE and
varies from 0 to 50% per day. So the cross test excludes every shared feature that is degenerate in either
dataset (`degenerate_features` in `idps/public/cross.py`, the list with the reasons is in
`reports/cross_2017_2018.json`, `features_excluded_from_cross`): a constant feature, a feature that is
non-zero in only one file of a dataset with at least three files, and the four flag columns above. The
bulk-transfer columns (`Fwd/Bwd Byts/b Avg`, `Pkts/b Avg`, `Blk Rate Avg`) and `Bwd PSH/URG Flags` are
constant 0 in 2017 and drop out through the automatic rule. The **in-domain runs of the main pipeline keep
every feature**; the `in_domain_test` block inside the cross report uses the same reduced set as the cross
model, so that in-domain and cross compare one model.

For each direction and with/without Dst Port: the training dataset's class-time train split (at most
`--cross-train-cap` rows per class) trains XGBoost; `in_domain_test` is that model on its own test split,
`cross` is the model on every row of the other dataset's sample (exact duplicates removed).

**How to read the numbers.**
- The two datasets do not have the same classes: PortScan is only in 2017; the 2018 DDoS class is HOIC +
  LOIC-UDP only because the Tuesday 20-02 file (LOIC-HTTP, the only 2018 DDoS tool resembling 2017's) was
  not downloaded, so DDoS-vs-DDoS compares different tools; Bot is a different malware in each dataset.
- `evaluate.py`'s macro-F1 averages over the union of the true and predicted labels, so a class that is
  predicted but absent from the data adds an F1 of 0 (PortScan in 2018; the tiny classes Heartbleed, 11 flows,
  and Infiltration, 36 flows, swing the mean). Subtracting a cross score from an in-domain score over
  different class sets is therefore meaningless.
- So the headline pair is scored on the **intersection of the classes** (`shared_classes`: in the
  training set, in the other dataset and in the in-domain test part): rows of other true classes are
  excluded and counted (`cross_rows_excluded_true_class_outside`), a prediction outside the list counts as
  a miss for the true class (counted in `cross_rows_predicted_outside_shared`), and
  `drop_shared_classes` = `in_domain_macro_f1_shared_classes` - `cross_macro_f1_shared_classes`, two
  macro-F1 over the same classes. `cross_per_class_recall_shared` gives recall and support per class.
- The all-classes numbers stay, clearly labelled: `cross_macro_f1_all_classes_union_convention` and
  `in_domain_macro_f1_all_classes`; `cross.seen_classes_only` and `attack_vs_benign` (which still means
  something for classes the model never saw) are unchanged. Classes missing from the training set are listed
  in `absent_from_train` and score recall 0. A drop is expected.

### Output files

| File | Content |
|---|---|
| `reports/cse_cic_ids2018_preprocessing.json` | files, caps, per-file cleaning counts, class counts after each step, sampling table, split description, label mapping |
| `reports/cse_cic_ids2018_xgboost.json`, `..._xgboost_noport.json` | metrics (validation, test) with bootstrap 95% intervals, per-class test table (support, F1 with interval, effective gap), train overlap, timing, split |
| `reports/cse_cic_ids2018_xgboost[_noport]_faithfulness.json` | SHAP and LIME deletion test |
| `reports/cic_ids2017_preprocessing.json`, `cic_ids2017_xgboost[_noport].json`, `..._faithfulness.json` | CIC-IDS2017 through THIS pipeline (loader `cic2017.py`, 78 features, merged labels, the 2018 sampling and split), same layout as the 2018 files; bundles `models/cic2017_xgboost[_noport].joblib` |
| `reports/cross_2017_2018.json` | both directions, both variants: shared-class and all-class scores, per-class recall with support, excluded features |
| `models/cse2018_xgboost.joblib`, `models/cse2018_xgboost_noport.joblib` (+ `.sha256`) | bundles; sign with `python -m idps.detect sign` |

The bundles use the normal bundle format. Their `extraction_meta` says the features are the dataset's
published columns, so `load_bundle(live_meta=...)` refuses flows from our own sensor: these models are for
the comparison, not for live detection. (`feature_columns` holds our layout only because `load_bundle`
requires it.)

### Results (full run, 18 Nov 2026)

Run: `python -m idps.public run --cap-benign 150000 --cap-attack 100000` (15.6 min, peak memory footprint
4.2 GB). The caps are lower than the defaults (250000 / 150000) because the machine was short of memory;
every report records the caps used. 9 of the 10 day files (the 4 GB Tuesday-20-02 file is not downloaded,
see above). All numbers are on the deduplicated test set; the intervals are bootstrap 95% intervals.

| | with Dst Port | without Dst Port |
|---|---|---|
| Macro-F1 (test) | 0.802 (0.795-0.810) | 0.795 (0.789-0.802) |
| BENIGN false-positive rate | 34.3% (see below: almost all of it is "Infiltration") | 35.7% |
| Test rows identical to a train row | 10.4% | 12.6% |
| Training time / inference time per flow | 46 s / 2.6 us | 148 s / 4.6 us |
| SHAP / LIME mean drop vs random | 8.9x / 4.0x (both faithful) | 13.7x / 10.0x (both faithful) |
| Cross 2017 -> 2018 macro-F1, 7 shared classes (in-domain / cross) | 0.758 / 0.469 | 0.662 / 0.162 |
| Cross 2018 -> 2017 macro-F1, 7 shared classes (in-domain / cross) | 0.794 / 0.287 | 0.797 / 0.150 |

**Reading the 2018 false-positive rate.** Of 238,486 normal test flows, 81,643 were labelled Infiltration
and only 224 (0.09%) were labelled anything else. The Infiltration class (Wednesday 28-02 and Thursday
01-03) is mostly ordinary-looking activity of compromised hosts: the model finds 85.7% of it but with
precision 0.23 (F1 0.36). BruteForce, DDoS and DoS score F1 0.997 to 0.998, Bot 0.92, and WebAttack 0.56
on only 157 test rows. So the rate says "Infiltration is hard to
tell from normal", not "the model alarms on normal traffic in general".

### Results across the three public datasets

| Dataset | Rows used (after dedup and gap) | Classes | Features | Macro-F1 with ports (95% CI) | Macro-F1 without ports (95% CI) | BENIGN FPR (with ports) | SHAP / LIME faithful? (with ports) |
|---|---|---|---|---|---|---|---|
| CIC-IDS2017 (this pipeline) | 1,333,655 | 9 | 78 | 0.795 (0.756-0.816) | 0.655 (0.612-0.658) | 6.8% | faithful / inconclusive |
| CSE-CIC-IDS2018 | 1,574,057 | 7 | 78 | 0.802 (0.795-0.810) | 0.795 (0.789-0.802) | 34.3% (Infiltration) | faithful / faithful |
| UNSW-NB15 | 545,644 | 10 | 43 | 0.708 (0.693-0.722) | 0.645 (0.630-0.657) | 1.2% | faithful / faithful |

The old `week_*` CIC-IDS2017 numbers (macro-F1 0.662, FPR 1.1%) come from a different pipeline (own
42-feature extractor, 14 unmerged labels, all rows, fixed gap) and are listed in
`reports/public_datasets_comparison.json` only as "not comparable".

What the table does and does not say:

- **Macro-F1 is not comparable across datasets.** The class sets differ (7, 9 and 10 classes), and
  macro-F1 averages over them equally, so a dataset with a hard rare class (Infiltration in 2018,
  Analysis and Backdoor in UNSW-NB15) scores lower whatever the model does on the rest. Compare
  per-class tables, not the headline.
- **Destination port matters a lot on CIC-IDS2017** (macro-F1 0.795 with, 0.655 without) and little on
  CSE-CIC-IDS2018 (0.802 / 0.795) and UNSW-NB15 (0.708 / 0.645 with both ports dropped): part of the
  2017 score is "which port the attack tool uses".
- **Tiny classes make the intervals wide.** CIC-IDS2017 has Heartbleed (11 flows) and Infiltration (36)
  in its sample; UNSW-NB15's Worms has 32 test rows. The bursty classes have effective split gaps far
  below the flow timeout, so their per-class scores partly measure interpolation inside a burst.
- **Cross-dataset results drop sharply**: 0.758 to 0.469 (2017 to 2018) and 0.794 to 0.287 (2018 to
  2017) on the 7 shared classes. The models learn each dataset's tools, network and timing, not
  attacks in general, which is the honest limit of any single-dataset score. The 2017-to-2018 direction
  has few false alarms (1.1%) but detects only 37% of attacks; 2018-to-2017 detects 37% and raises
  false alarms on 47% of normal flows. Caveats: the 2018 DDoS class has no LOIC-HTTP (that day is not
  downloaded), the name-matched features are not identical in meaning, and the degenerate flag columns
  were removed from the cross test only (`reports/cross_2017_2018.json` lists them).
- **UNSW-NB15 is the weakest evidence on generalisation to our lab**: its 2015 testbed has two capture
  sessions a model can tell apart (AUC about 0.92) and different traffic from CIC. Per-session and
  cross-session scores are in `reports/unsw_nb15_cross_session.json` (cross-session macro-F1 0.60 to
  0.71, no collapse, but more false alarms from January to February).
- **Explanations are faithful by the deletion test in every case but one**: SHAP beats a random feature
  ordering on all runs; LIME is inconclusive on CIC-IDS2017 with ports and no better than random
  without ports. The faithfulness runs use 87 to 100 flows, so a verdict near the 0.5 line is weak
  evidence either way.

### Known limitations

- The sample is capped, so class balance differs from the dataset's; the numbers describe the sample.
- Train and test come from the same day and attack tool (as in CIC-IDS2017); the cross-dataset test is
  the check on other tools and networks.
- Seven of the nine downloaded day files have exactly 1,048,575 data rows (Excel's row limit; the list is
  generated from `manifest.json`, not typed by hand): Wednesday 14-02, Thursday 15-02, Friday 16-02,
  Wednesday 21-02, Thursday 22-02, Friday 23-02 and Friday 02-03. Only Thursday 01-03 (331,125 rows) and
  Wednesday 28-02 (613,104) are shorter. The CSVs were probably truncated by Excel and the tail of those
  days is missing (that also explains why the Friday 16-02 benign flows all sit in the DoS-Hulk window and
  why Hulk ends at 13:48 instead of 14:19). `reports/cse_cic_ids2018_preprocessing.json` marks such files
  `truncated_at_excel_limit: true` (per file and in a list) and gives each file's first and last
  Timestamp so the missing tail is visible. The rows are not recovered (that needs the PCAPs).
- The Tuesday 20-02 file is not in the data (see Preprocessing 1).
- Timestamps: the hours 6/7 rows (3 rows) are ambiguous, see Preprocessing 2.
- CSE-CIC-IDS2018 Infiltration is mostly benign-looking traffic from compromised hosts; expect low
  scores and BENIGN confusion for it.
- The class-time split gap shrinks for bursts (see Split), so near a cut a train and a test flow can
  start closer than the flow timeout, and with 1 s timestamps they can share a second. Classes scored on
  such bursts (small effective gap in the per-class table) partly measure interpolation inside the burst.
  Read per-class scores with their bootstrap interval and test support; the macro-F1 headline has the same
  caveat.
- Every BENIGN false-positive rate in these reports is on the deduplicated test set: removing exact repeats
  removed easy flows, so the rate is pessimistic.
- Tiny classes can lose all rows in the gap or the dedup; they are listed in
  `classes_missing_from_train`.

## UNSW-NB15: preprocessing and results (code built 18 Nov 2026)

Code: `idps/public/unsw.py` (loader, encoder), `idps/public/pipeline.py` (`unsw_split`, `run_unsw`),
`idps/public/compare.py`, entries in `idps/public/labels.py` and `__main__.py`.
Tests: `tests/test_public_unsw.py`. Data: `data/raw/unsw-nb15/UNSW-NB15_1.csv .. _4.csv` (no header row),
`NUSW-NB15_features.csv` (the 49 column names), `checksums.json` (SHA-256 of the four files; the loader
checks them).

**Source and licence.** UNSW Canberra Cyber, the Australian Centre for Cyber Security. Free for academic
research. Cite Moustafa and Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection
systems", Military Communications and Information Systems Conference (MilCIS), 2015. The dataset page
gives 2,540,044 records, 49 features and nine attack categories (Fuzzers, Analysis, Backdoors, DoS,
Exploits, Generic, Reconnaissance, Shellcode, Worms). Features come from Argus and Bro-IDS, not from CICFlowMeter.

### Run

```
python -m idps.public unsw      # load, split, train both variants, evaluate, SHAP/LIME, cross-session test (about 90 s without the cross-session part, 3.5 min with it, on the 8-core, 8 GB machine under memory pressure)
python -m idps.public compare   # reports/public_datasets_comparison.json from the reports that exist
python -m idps.public labels --dataset unsw   # the label table below

# smoke run
python -m idps.public unsw --max-rows 150000 --cap-benign 5000 --cap-attack 3000 \
       --faith-n 20 --lime-samples 200 --models-dir /tmp/m --reports-dir /tmp/r
```

Options as for CSE-CIC-IDS2018: `--cap-benign` (250000) and `--cap-attack` (150000) flows per capture
session and attack category; `--max-rows N` reads the first N rows of every file; `--only _1 _2` restricts
the files; `--gap-s` (120) and `--max-gap-loss` (0.10); `--faith-n` (100), `--lime-samples`, `--no-lime`,
`--no-faithfulness`; `--models-dir`, `--reports-dir`, `--seed`. New: `--data-unsw` (default
`data/raw/unsw-nb15`) and `--max-categories` (30, see Features). The CSVs are read twice in batches of
262144 rows (pass 1: Stime, Ltime, attack_cat, Label and the odd-value counts of every row; pass 2: the
feature columns of the chosen rows only). Measured: the load takes about 20 s and 0.6 GB.

### What the real files contain (checked on the data, counts in `reports/unsw_nb15_preprocessing.json`)

- **Rows.** The four files hold 2,540,047 rows (700,001 / 700,001 / 700,001 / 440,044), every row has
  exactly 49 fields. The last row of each of files 1, 2 and 3 is repeated as the first row of the next
  file: 3 rows, the difference to the 2,540,044 of the dataset page. The loader drops them
  (`file_boundary_overlap`). After that the class counts equal the dataset page's: 321,283 attacks (Generic
  215,481; Exploits 44,525; Fuzzers 24,246; DoS 16,353; Reconnaissance 13,987; Analysis 2,677; Backdoor
  2,329; Shellcode 1,511; Worms 174) and 2,218,761 Normal.
- **Encoding of the files.** File 1 starts with a UTF-8 byte order mark that sits inside the first field
  (srcip, never used). Line ends are CRLF. The feature file has the column header `Type ` with a trailing
  blank and descriptions with non-ASCII bytes: both are read as Latin-1.
- **Column names.** The feature file spells the names `Sload`, `Dload`, `Spkts`, `Dpkts`, `Sjit`, `Djit`,
  `Stime`, `Ltime`, `Sintpkt`, `Dintpkt`, `Label` with capitals and has one name with a blank inside,
  `ct_src_ ltm`. `clean_name()` removes all whitespace and lower-cases the name (`ct_src_ltm`, `sload`,
  `stime`); the 0/1 column `Label` becomes `label_binary` so that it cannot be confused with `label`, the
  class the models learn. Every renaming is listed in the report (`load.feature_names.columns`). The
  cleaned 49 names must equal the expected list in code, otherwise the loader stops. The feature file's
  names (for example `smeansz`) are kept, whatever other copies of the dataset call them.
- **attack_cat.** Blank for Normal traffic (2,218,764 rows). Attack names are padded or spelled in two ways:
  ` Fuzzers ` 19,195, ` Fuzzers` 5,051, ` Reconnaissance ` 12,228 (plain: 1,759), ` Shellcode ` 1,288
  (plain: 223), `Backdoor` 1,795 and `Backdoors` 534. The spelling depends on the capture: the first capture
  (22-23 Jan) has the plain forms and `Backdoors`, the second (18 Feb) the padded ones and `Backdoor`.
  The 0/1 `Label` agrees with attack_cat on every row (no contradiction); the loader still checks and would
  drop and count one.
- **sport / dsport.** Mostly decimal (0 to 65535). Hex strings in 6 sport and 297 dsport values
  (`0x000b`, `0x000c`, `0xcc09` 241, `0xc0a8` 54, `0x20205321` 2) and `-` in 2 sport and 7 dsport values.
  All of those are Normal rows of ICMP, ESP and similar protocols (no real port).
- **Blank cells.** `ct_flw_http_mthd` is blank in 1,348,145 rows, `is_ftp_login` in 1,429,879 and
  `ct_ftp_cmd` is a single space in the same 1,429,879 rows. It is a capture artefact, not noise: the first
  capture has **no** blanks in these columns, the second has them in 95% of its attack rows and 92% of its Normal rows (measured
  on `ct_flw_http_mthd`: 1,064,988 Normal and 22,215 attack rows in the first capture, none blank; 1,153,776
  Normal rows, 92.3% blank, and 299,068 attack rows, 94.6% blank, in the second). `is_ftp_login` is not binary: 2 occurs 30 times and 4 occurs 156 times.
  `service` is `-` (1,246,397 rows) when not recognised. `proto` has 135 values, `service` 13, `state` 16.
- **Time.** `Stime` and `Ltime` are epoch seconds (1 s resolution, whole numbers). `Ltime < Stime` never
  occurs; 24 flows last longer than 120 s (longest 8,896 s). **The rows are ordered by Ltime, not Stime**
  (Stime goes backwards 107,672 times in file 1 alone), and the four files follow each other in time.
  There are two captures: 22 Jan 2015 11:49:37 to 23 Jan 00:25:24 UTC (1,087,202 rows, 22,215 attacks) and
  18 Feb 2015 00:23:28 to 12:21:08 UTC (1,452,842 rows, 299,068 attacks); 26 days apart. The first one runs
  past UTC midnight: 34,340 Normal rows are stamped 23 Jan.
- **Exact duplicates.** 480,633 rows (3 of them the file-boundary repeats) equal another row in all 49
  columns; 522,732 rows repeat another row in all non-identifier, non-port features plus the label.
  The share is 6% in the first capture and 29% in the second (Generic: 88%, DoS: 65%, Normal: 12%).
  Examples: ARP records with all zeros, repeated DNS exchanges.
- **Not recorded in the files but worth knowing:** `stcpb` and `dtcpb` are TCP base sequence numbers
  (random 32-bit values for TCP, 0 otherwise). They are kept because they are part of the published
  features, but they carry no behaviour; see the limitations.

### Preprocessing, in order (class counts after every step: `reports/unsw_nb15_preprocessing.json`, `class_counts_by_step`)

1. **Read** the 4 files without a header, with the names from the feature file (cleaned, see above), as text.
2. **Labels.** `attack_cat` is stripped; blank + Label 0 = `Normal` (kept as `label_original`; the stripped
   original, so `Backdoor` and `Backdoors` stay distinct there). The class is looked up in the table below;
   an unknown value is an error, never a silent drop. A row whose Label is not 0/1, or whose Label
   contradicts attack_cat, is dropped and counted (none in the real data).
3. **File overlap.** The row repeated across a file boundary is dropped (3 rows).
4. **Timestamp.** Stime must be a number inside 2015; other rows are dropped and counted (none); a file with
   more than 5% bad values is refused.
5. **Capture session.** Flows are grouped into capture sessions: a gap of more than one day without any
   flow starts a new one (two sessions). The session replaces the calendar day as the "day" of the caps and
   of the split, because a UTC-day key would cut the first capture at midnight. (`split_by_class_time` got
   an optional `day_col` for this; the default is unchanged.)
6. **Sample** (`idps/public/sampling.py`, the same code as 2018): at most `cap` flows per (session,
   attack_cat), 250000 for Normal and 150000 per attack category; evenly spaced in time with a seeded random
   start; one global pass, because a group runs across files. Default result: 763,324 rows (500,000 Normal;
   Generic 157,522; every other class whole). Same input and seed give the same sample.
7. **Numbers** (float32). Blank `ct_flw_http_mthd`, `is_ftp_login`, `ct_ftp_cmd` become 0 (they are blank in
   one capture and 0 in the other for the same situation: treating them as different would let a model tell
   the captures apart); `is_ftp_login` > 1 becomes 1; hex ports are read as hex values; `-` or blank ports
   become -1; any other unparseable, infinite or float32-overflowing cell drops the whole row. The
   counts are in `load.coercions` (the sampled rows) and `load.odd_values_all_rows` (every row).
8. **Identifier columns** are never features: `srcip`, `dstip`, `Stime` (used only to order and split) and
   `Ltime`. `attack_cat` and `Label` are labels.
9. **Ports.** `sport` and `dsport` are trained both ways: `unsw_nb15_xgboost.joblib` has 43 features
   (both ports), `unsw_nb15_xgboost_noport.joblib` has 41. Difference to 2018: there only Dst Port is
   toggled and Src Port is always dropped; here both port columns go together, so the pair of numbers measures
   all port memorisation the table offers.
10. **Split** (`unsw_split` -> `make_split` -> `split_by_class_time`, as in 2018): per (capture session,
    class) sorted by Stime, first 60% train, next 20% validation, last 20% test; rows starting less than the
    gap (120 s) from a cut are dropped, with the gap shrinking so that at most 10% of a group is dropped
    (`effective_gap_ms`, `dropped_by_gap` and `gap_loss_share_by_label` in the report). Stime has 1 s
    resolution, so flows of the same second can fall on either side of a cut. Groups use the class, not the
    raw spelling, so `Backdoor` and `Backdoors` are one group. A class that cannot be split is
    listed under `classes_missing_from_train`.
11. **Exact duplicates** (all features plus the class) are removed inside each split; `train_overlap`
    reports the share of validation/test rows identical to a train row (64-bit row hashes). This
    matters more here than in 2018: roughly a quarter of the second capture is duplicated. The split
    removes duplicates once, on the numeric features plus the raw category ids; each trained variant then
    deduplicates its own parts AGAIN on the vector it actually trains on (the encoded categories, with or
    without the port columns, `variant_duplicates_removed`), so the no-port variant no longer keeps rows
    that are duplicates in its own feature space, and its `train_overlap` is on its own vector. (Before this
    there were three different overlap numbers, 1.22%, 1.33% and 2.59%, for one run.) Every BENIGN false-positive
    rate below is on this deduplicated test set: the removal took out easy repeats (Generic went from 30k
    rows to 3.9k), so the rate is pessimistic.
12. **Categorical encoding, after the split, from the train split only** (`CategoryEncoder`): `proto`,
    `state`, `service` become one integer column each. Per column the 30 most frequent *training* values get
    the codes 1, 2, ... by decreasing training frequency (ties alphabetical); every other value, and every
    value that occurs only in validation/test data, gets the reserved code 0 ("other"). The mapping uses
    training rows alone, so a held-out value cannot influence it or even be told from another unseen one.
    The split itself needs numbers to find duplicates, so it runs on arbitrary integer ids of the strings
    (`factorize`), compared for equality only and never given to a model. Chosen over one-hot (135 protocols
    would add about 160 columns and make SHAP/LIME and the comparison with the other datasets harder) and over
    alphabetical codes (an accidental order). The mapping and the share of rows sent to "other" per split are
    in the report (`categorical_encoding`); the mapping is stored in the bundle (`extraction_meta`), and
    `CategoryEncoder.from_dict(bundle.extraction_meta["categorical_encoding"])` reproduces it at inference.
13. **Training** is the CIC-IDS2017 pipeline, unchanged: XGBoost multi:softprob (200 trees, depth 6, learning
    rate 0.1, subsample/colsample 0.9, hist), class weights from the train split only, IsolationForest (200
    trees, contamination 0.01) on Normal (BENIGN) train rows. Measured: macro-F1, per-class P/R/F1, BENIGN
    false-positive rate, ROC-AUC (one-vs-rest), the anomaly detector's rates, training and inference time,
    SHAP and LIME deletion test on a class-balanced test sample (`--faith-n`, background 200 train rows).

14. **Per-session scores and the cross-session test** (finding: the capture session is a learnable shortcut).
    The test part is also scored per capture session (`metrics.test.by_session`: macro-F1, accuracy, BENIGN
    FPR, attack share, and the macro-F1 on the classes both sessions have). Then
    `reports/unsw_nb15_cross_session.json`: a model is trained on all rows of one capture (at most 200,000 per
    class, duplicates removed on the variant's own vector, encoder fitted on that session alone) and tested on
    every row of the other capture, in both orders and for both variants, scored on the classes both sessions
    have (`shared_classes`; here all ten) with the all-classes numbers next to them and per-class recall with
    support. `session_predictability` is a probe: an XGBoost model predicts the capture session from the 41
    no-port features, scored by ROC-AUC on the test part of the main split, for all classes and for BENIGN
    rows only. See the results and the limitations below.

### Label mapping (UNSW-NB15 attack_cat -> class)

| Class (this project) | UNSW-NB15 attack_cat spelling |
|---|---|
| BENIGN | Normal (blank in the files) |
| Analysis | Analysis |
| Backdoor | Backdoor |
| Backdoor | Backdoors |
| DoS | DoS |
| Exploits | Exploits |
| Fuzzers | Fuzzers (also ` Fuzzers `, ` Fuzzers`) |
| Generic | Generic |
| Reconnaissance | Reconnaissance (also ` Reconnaissance `) |
| Shellcode | Shellcode (also ` Shellcode `) |
| Worms | Worms |

The table is `UNSW_LABEL_TABLE` in `idps/public/labels.py`; matching ignores blanks, case and punctuation.
The UNSW class names stay their own. Only two aliases were added: Normal -> BENIGN and Backdoors -> Backdoor.

### No cross-dataset test with CIC-IDS2017/2018

A CIC-IDS2017/2018 <-> UNSW-NB15 cross-test is **not done**, and no class mapping between them is invented:
- **Different features.** CICFlowMeter (78 flow statistics: packet-length, inter-arrival and flag counts)
  against Argus/Bro (43 columns here: TTLs, window sizes, jitter, TCP round-trip times, connection-count
  features over the last 100 connections, and text-like fields such as service and state). Almost no column
  has the same meaning in both; a "shared feature set" would be a handful of columns (duration, bytes,
  packets, protocol) and would say little.
- **Different attack taxonomies.** UNSW has Fuzzers, Exploits, Generic, Shellcode, Worms and Analysis, which
  CIC does not have; CIC has Bot, Infiltration, Heartbleed, PortScan and the brute-force and web-attack
  classes, which UNSW does not have. "DoS" is the same word but a different traffic generator in a different
  network. Merging them would be a guess.

The generalisation evidence of this method therefore comes from the 2017 <-> 2018 test only.

### Output files

| File | Content |
|---|---|
| `reports/unsw_nb15_preprocessing.json` | files, BOM and checksum checks, name mapping, sessions, caps, odd-value counts, class counts after each step, sampling table, split description, label table, encoding |
| `reports/unsw_nb15_xgboost.json`, `..._xgboost_noport.json` | metrics (validation, test), train overlap, timing, split, `classes_missing_from_train` |
| `reports/unsw_nb15_xgboost[_noport]_faithfulness.json` | SHAP and LIME deletion test |
| `reports/public_datasets_comparison.json` | one row per dataset (from `python -m idps.public compare`) |
| `models/unsw_nb15_xgboost.joblib`, `models/unsw_nb15_xgboost_noport.joblib` (+ `.sha256`) | bundles; sign with `python -m idps.detect sign` (not signed by the code: the key is yours) |

The bundles use the normal bundle format and, like the 2018 ones, refuse live flows from our sensor
(`extraction_meta` names the Argus/Bro columns). They are for the comparison, not for live detection.

### Comparison table (`python -m idps.public compare`)

Reads `cic_ids2017_xgboost*.json`, `cse_cic_ids2018_xgboost*.json`, `unsw_nb15_xgboost*.json` and the older
`week_xgboost*.json` from `reports/`, skips datasets whose main report is missing, and writes one row per
report set: rows used, classes, macro-F1 with its bootstrap interval and BENIGN false-positive rate (on the
deduplicated test set) with and without ports, SHAP/LIME verdicts, training time. **Every row has a
`pipeline` field**, because the rows do not come from one pipeline:
- `idps.public`: CIC-IDS2017 rebuilt through `idps/public/cic2017.py` ("CIC-IDS2017 (idps.public pipeline)"),
  CSE-CIC-IDS2018 and UNSW-NB15. Same method (sampling, class-time split, XGBoost, SHAP/LIME test), not the
  same difficulty.
- `idps.detect (week_* reports): different pipeline, not comparable`: the older CIC-IDS2017 row (own 42-feature
  extractor, 14 unmerged labels, all 958k rows, a fixed 120 s gap, 16.5% of the test rows identical to a train
  row, 551 unbalanced faithfulness flows). Kept for reference only (`comparable_with_idps_public_rows: false`).

The SHAP/LIME verdict is a fixed rule (written into the file as `verdict_rule`). The deletion test replaces
the top 5 features by the background median and compares the drop with the drop of 5 random features, so
the random baseline is 5 of N features, and N (41, 43 or 78) is reported with the verdict, with the number of
flows. The share of flows that beat their random drop gets a binomial 95% Wilson interval (about +-10 points at
100 flows, which is about 10 per class): "inconclusive" if it includes 0.5; otherwise "faithful" (mean drop
at least 2x random and the interval above 0.5), "weak" (interval above 0.5 and ratio from 1.5 to 2),
"not better than random" (interval below 0.5 or ratio under 1). A ratio of 1.01 is no longer "weak".

### Results (full run, 18 Nov 2026, `python -m idps.public unsw`; seed 42, default caps)

| | with sport/dsport (43 features) | without sport/dsport (41) |
|---|---|---|
| Rows used (train / validation / test, after the variant's own deduplication) | 328,682 / 105,584 / 110,591 | 325,097 / 104,727 / 109,658 |
| Macro-F1 (test), bootstrap 95% interval | 0.708 (0.693-0.722) | 0.645 (0.630-0.657) |
| Accuracy | 0.961 | 0.954 |
| BENIGN false-positive rate (deduplicated test set) | 0.0117 | 0.0116 |
| Test rows identical to a train row (variant's own vector) | 1.3% (1,463) | 2.0% (2,149) |
| Macro-F1 on the test rows NOT identical to a train row | 0.711 | 0.644 |
| Per capture session, macro-F1 (Jan / Feb), BENIGN FPR (Jan / Feb) | 0.703 / 0.705, 0.000 / 0.025 | 0.584 / 0.654, 0.000 / 0.025 |
| Attack share of the test rows (Jan / Feb) | 5.5% / 28.1% | 5.4% / 27.3% |
| Training time / inference time per flow | 17 s / 4.0 us | 17 s / 4.0 us |
| SHAP mean drop vs random (ratio), share of flows beating random with its 95% interval, verdict | 0.64 vs 0.20 (3.2x), 0.90 (0.83-0.94), faithful | 0.59 vs 0.23 (2.6x), 0.89, faithful |
| LIME, same | 0.51 (2.6x), 0.73 (0.64-0.81), faithful | 0.64 (2.8x), 0.93, faithful |
| Classes missing from train | none | none |
| Cross-session macro-F1, trained on Jan, tested on Feb (10 shared classes) | 0.670 (BENIGN FPR 0.028) | 0.602 (0.028) |
| Cross-session macro-F1, trained on Feb, tested on Jan | 0.709 (0.004) | 0.618 (0.004) |

Compared with the first run (before the review fixes): macro-F1 0.703 / 0.652 and BENIGN FPR 0.0117 became
0.708 / 0.645 and 0.0117. The changes come from the gap rule (the shrunk gaps of Backdoor, Worms and Generic
moved by a few seconds) and from deduplicating each variant on its own vector (the no-port variant lost 4,125
train rows it had kept as distinct, and its overlap went from 2.59% to 2.0%).

Per-class test table, with ports (support, F1 with its bootstrap 95% interval, effective split gap; 120 s is the
nominal gap, a smaller value means the gap shrank for that class's bursts):

| Class | Test rows | Precision | Recall | F1 (95% interval) | Effective gap |
|---|---|---|---|---|---|
| BENIGN | 91,271 | 0.999 | 0.988 | 0.994 (0.993-0.994) | 120 s |
| Generic | 3,905 | 0.978 | 0.903 | 0.939 (0.932-0.944) | 64 s |
| Fuzzers | 4,310 | 0.815 | 0.934 | 0.871 (0.863-0.878) | 76 s |
| Reconnaissance | 2,635 | 0.869 | 0.872 | 0.871 (0.861-0.881) | 120 s |
| Shellcode | 295 | 0.777 | 0.966 | 0.861 (0.835-0.888) | 120 s |
| Exploits | 6,110 | 0.897 | 0.802 | 0.847 (0.840-0.855) | 120 s |
| DoS | 1,245 | 0.509 | 0.476 | 0.491 (0.464-0.515) | 17 s |
| Worms | 32 | 0.543 | 0.781 | 0.641 (0.493-0.761) | 23 s |
| Analysis | 428 | 0.186 | 0.692 | 0.293 (0.266-0.322) | 6 s |
| Backdoor | 360 | 0.235 | 0.322 | 0.272 (0.238-0.310) | 4 s |

**Caveat next to the headline macro-F1.** The classes with the smallest effective gaps (Backdoor 4 s, Analysis
6 s, DoS 17 s, Worms 23 s, Generic 64 s, Fuzzers 76 s) are bursts: with the gap that small, train and test
flows of the same burst start seconds apart, so their scores partly measure interpolation inside a burst and
not generalisation to later traffic. The tiny classes (Worms 32 test rows, interval 0.49-0.76) are noisy. The
interval covers only the resampling of the test rows, not the choice of split, the seed or the dataset.

**Per-session and cross-session.** Within a session the scores are similar in January and February (0.703 and
0.705 with ports), but the January test part is 5.5% attacks and the February one 28.1%, and the BENIGN false-positive rate is
0.000 against 0.025. Training on one capture and testing on the other gives macro-F1 0.670 (Jan -> Feb) and 0.709
(Feb -> Jan) with ports, 0.602 and 0.618 without: not a collapse (the main run has 0.708 and 0.645), but the
Jan -> Feb direction has a BENIGN false-positive rate of 2.8% against 1.2%, and some classes lose recall across
sessions (with ports: Analysis 0.69 in the main run, 0.26 and 0.15 across; DoS 0.48, 0.32 and 0.46).
The capture is predictable from the features: an XGBoost model separates the sessions with ROC-AUC 0.92 on the
no-port features (0.90 on BENIGN rows only; the review measured 0.96 and 0.94 with another probe), so a within-session
split lets a model use the capture as a hint (the attack prior differs: 22k attacks against 299k). The blank-versus-0 cells
are not the cause (verified in the review).

### Known limitations

- **2015 testbed.** Synthetic attacks (IXIA PerfectStorm) against a lab network, 2015 traffic mix; the
  services and attack tools are old.
- **Two capture days only**, 26 days apart, and classes are not spread evenly over them: the first has 22,215
  attacks (all nine categories, but few Analysis, Worms and Shellcode rows), the second 299,068. A (session, class)
  group lives on one day, so in the main run train and test come from the same day and tool.
- **The capture session is a learnable shortcut.** A model predicts the session from the 41 no-port features with
  ROC-AUC 0.92 (0.90 on BENIGN rows alone), and both sessions are in train and test. The cross-session runs
  (above) are the check: they do not collapse (macro-F1 0.60 to 0.71) but BENIGN false positives and the weak
  classes get worse. There is still no cross-dataset evidence for UNSW.
- **Argus/Bro features** are connection summaries computed by the dataset's authors; `ct_*` features are
  counts over the last 100 connections, so a flow's features depend on its neighbours in time (they were
  computed on the whole capture, which includes the future rows of the same split cut). `stcpb`/`dtcpb` are
  random sequence numbers.
- **Capture artefacts.** The blank-cell pattern differs between the two captures (see above) and so do the
  attack_cat spellings; blanks are mapped to 0, but other differences between the captures may remain that a
  model can use. The with/without port gap does not measure these.
- **Heavy duplication** (about a quarter of the second capture): duplicates are dropped inside each split
  (and again per variant) but a vector can still occur in train and test; `train_overlap` says how much.
- **The sample is capped**, so class balance differs from the dataset's (Normal is 66% of the sample, 87%
  of the dataset); the numbers describe the sample.
- **Tiny classes and bursts.** Worms (174 rows; 32 test rows), Shellcode and Backdoor have few rows after the
  60/20/20 cut; their per-class scores are noisy (see the bootstrap intervals), and classes with a small
  effective gap (Analysis, Backdoor, DoS, Worms, Generic, Fuzzers) are scored partly on burst interpolation. Classes that lose all rows are listed in `classes_missing_from_train`.
- **Gap rule.** Flows last up to 8,896 s (24 flows over 120 s), and the gap shrinks for bursts (never above the
  nominal gap; a group of a few rows can get 0 and is flagged), so a train flow can still be running when a test
  flow starts; timestamps are whole seconds.
- **BENIGN false-positive rate is on the deduplicated test set**, which removed easy repeats: pessimistic.
- **No cross-test with CIC-IDS2017/2018** (see above); the cross-session test is within UNSW-NB15.
