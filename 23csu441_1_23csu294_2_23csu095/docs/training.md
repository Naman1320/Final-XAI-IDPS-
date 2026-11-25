# Training

```
python -m idps.detect train labelled.parquet [more.parquet ...] --model xgboost|rf|mlp \
       --split class-time|day|window -o models/model.joblib --report reports/metrics.json
```

Inputs are the files written by `python -m idps.features label` (see docs/features.md).

## Splits (never random)

Near-duplicate flows are close together in time, so a random split would leak copies into the
test set. All splits are by time; train is earlier than validation, which is earlier than test.

- **`class-time` (default, recommended for CIC-IDS2017).** CIC-IDS2017 has one attack type per
  day, so a split by day leaves most attack classes out of train. Here every (UTC day, label)
  group is sorted by `start_ms` and cut 60/20/20 (`--val`, `--test` are the validation and test
  fractions, default 0.2 each). Rows starting less than `--gap-ms` (default 120000, the active
  timeout) from a cut are dropped, so no train flow is still running when a test flow starts. Every
  class is then in train and tested on later traffic. Limit: train and test come from the same
  day and the same attack tool, so scores say little about new tools or days. The report lists
  how many rows the gap removed, in total and per class; very short bursts (Heartbleed, 11 flows)
  can lose most of their rows.
- **`day`.** Last `--test` days are test, the `--val` days before are validation (default 1 each).
  Fails when a validation/test class is not in train, which is the normal case on CIC-IDS2017.
  Pass `--allow-unseen-test-classes` for leave-one-day-out experiments (measuring detection of
  attack types the model never saw); the unseen classes then score recall 0 by construction.
- **`window`.** Rows sorted by time, cut at `--val`/`--test` fractions.

## Duplicates

After splitting, exact duplicate rows (all `MODEL_FEATURES` plus the label) are dropped inside each
split (`--keep-duplicates` turns this off). Dropping happens per split, so a vector can still occur
in both train and test. The split description and `metrics.<validation|test>.train_overlap` report
`rows` and `share` of validation/test rows whose feature vector (the features the model uses,
after `--drop-feature`) is identical to some train row: a high share means the score measures
memorisation. `class-time` on scan or flood classes typically has a high share.

## Match-rate guard

`load_labelled` reads `match_summary.match_rate` from each file and refuses a file below 0.5, or
with no match summary, because training on mostly-unmatched labels is training on guesses (wrong
`--utc-offset-hours`, wrong PCAP/CSV pair). It also refuses to mix files labelled with different
`utc_offset_hours`. Override the rate check only on purpose with `--allow-low-match-rate`
(`allow_low_match=True`); the offset check has no override. The same flag exists for `evaluate`.

## Metrics conventions

- **Macro-F1** is the unweighted mean F1 over the union of labels in the true and predicted
  values (scikit-learn's default). A class that was predicted but never occurs in the test
  set counts as F1 = 0, so false-alarm classes lower the score. `per_class` lists all those labels.
- BENIGN false-positive rate = BENIGN flows predicted as anything else / all BENIGN flows.
- ROC-AUC is one-vs-rest, only for classes with positives and negatives in the evaluated part.

## Models

XGBoost (`binary:logistic` for exactly two classes, `multi:softprob` otherwise), RandomForest and
an MLP with early stopping (needs at least 2 training rows per class). RandomForest and XGBoost
use all cores; runs with the same `--seed` give identical predictions (tested for XGBoost and MLP).
Class weights come from the training split only.

## Model files

`save_bundle` writes `<model>.sha256` next to the model. `load_bundle` refuses a model whose digest
file is missing or does not match, or that is group- or world-writable, before unpickling it.
This catches tampering by someone who cannot also rewrite the digest; it is not a signature.
Retrain or re-save models made before this change.

## Caveat: dst_port

`dst_port` is a model feature and is a strong shortcut in CIC-IDS2017, because each attack tool
used a fixed port (DoS to 80, SSH-Patator to 22, FTP-Patator to 21, PortScan to many). A model can
score high by learning the lab's ports rather than traffic behaviour, and then fail on other
networks or on an attacker who changes the port. Always also train with `--drop-feature dst_port`
and report both results; the gap is the part of the score that is port memorisation.

## Public datasets (CSE-CIC-IDS2018)

`python -m idps.public run` trains the same pipeline on CSE-CIC-IDS2018's own feature table and tests
CIC-IDS2017 <-> CSE-CIC-IDS2018 generalisation; see `docs/training-dataset1.md`. For that, `split_by_class_time`
(and `make_split`) take three optional arguments that default to the behaviour above: `dup_columns`
(the columns that define an exact duplicate, default `MODEL_FEATURES`), `group_col` (which column forms
the (day, group) groups, default `label`) and `max_drop_share` (shrink the gap so at most this share
of a group is dropped, default off). The train-overlap share is computed with 64-bit row hashes.

Shrinking gap rule (`max_drop_share`): when a group would lose more than that share, the gap becomes
the `max_drop_share` quantile of the rows' distances to the two cuts, taken with `method="lower"` (an
actual distance, no interpolation) and never above the nominal `gap_ms`. A group of fewer than about 10
rows can therefore end up with a gap of 0 (nothing dropped, train and test touch at the cut): those
groups are listed in the split description as `groups_with_zero_effective_gap` ("day:label"). With the
defaults (no `max_drop_share`) the split is unchanged; `tests/test_split_regression.py` compares it row
for row with the version before these options.

Bundles from the public datasets (`extraction_meta.public_dataset`) are comparison-only: `resplit`
(used by `drift-reference` and `retrain`) refuses them with an error, because their split used group,
day-key and duplicate settings that the split description does not record.

`python -m idps.public unsw` does the same for UNSW-NB15 (Argus/Bro features, two capture days); see the
UNSW-NB15 section of `docs/training-dataset1.md`. It uses one more optional argument of `split_by_class_time`
and `make_split`: `day_col` (default None = the UTC day of `start_ms`), a column that names the capture session
used as the "day" of the groups.
