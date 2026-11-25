"""Retrain a model with analyst feedback, and keep the result only if it is not worse.

    python -m idps.detect retrain --data labelled.parquet [...] --feedback feedback.parquet \\
        --current models/week_xgboost.joblib -o models/week_xgboost_v2.joblib

The new model is the same type as the current one, trained on the base training rows plus the
feedback rows (counted `feedback_weight` times as much). Feedback is split 70/30, stratified by
label where it can be: 70% is trained on, 30% is a holdout. Neither model trained on the holdout,
so it shows whether the new model learned from the analysts without just memorising them.

The new bundle is written only when BOTH hold:
  (a) macro-F1 on the base test split (the current model's own split, rebuilt) is at least the
      current model's minus `tolerance`, and
  (b) accuracy on the feedback holdout is at least the current model's.
Otherwise nothing is written (an existing output file is left as it is) and the CLI exits 3.
A JSON comparison report is written either way.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

from idps.detect import drift
from idps.detect.bundle import (
    Bundle,
    digest_path,
    make_version,
    model_version,
    read_digest,
    save_bundle,
)
from idps.detect.data import SEED
from idps.detect.evaluate import evaluate_classifier
from idps.detect.models import train_all
from idps.detect.train import _metrics_for, resplit
from idps.features import check_same_extraction

HOLDOUT_FRACTION = 0.3
DEFAULT_FEEDBACK_WEIGHT = 5.0
DEFAULT_TOLERANCE = 0.005
DEFAULT_MIN_HOLDOUT = 5
EXIT_REJECTED = 3


def split_feedback(fb: pd.DataFrame, holdout_fraction: float = HOLDOUT_FRACTION
                   ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Train/holdout split by time, per label: the oldest 70% of each label's rows (by `end_ms`,
    then `alert_id`; row order if neither column exists) train, the newest 30% are the holdout.
    A label with two or more rows puts at least one row on each side; a label with one row goes
    to train. Time order keeps near-identical consecutive flows (a scan burst) on one side, so
    the holdout is not a copy of the training rows."""
    if fb.empty:
        raise ValueError("the feedback file has no usable rows")
    keys = [c for c in ("end_ms", "alert_id") if c in fb.columns]
    train_parts, hold_parts = [], []
    for _, group in fb.groupby("label", sort=True):
        group = group.sort_values(keys, kind="stable") if keys else group
        n = len(group)
        n_hold = 0 if n < 2 else min(max(round(n * holdout_fraction), 1), n - 1)
        train_parts.append(group.iloc[:n - n_hold])
        hold_parts.append(group.iloc[n - n_hold:])
    train, hold = pd.concat(train_parts), pd.concat(hold_parts)
    if hold.empty:
        raise ValueError("the feedback is too small to hold anything out: need at least one "
                         "label with two or more rows")
    return train.reset_index(drop=True), hold.reset_index(drop=True)


def evaluate_on(bundle: Bundle, df: pd.DataFrame) -> dict:
    X = df[bundle.features]
    return evaluate_classifier(df["label"], bundle.predict(X), bundle.predict_proba(X),
                               list(bundle.label_encoder.classes_))


def _brief(m: dict) -> dict:
    return {"n": m["n"], "accuracy": m["accuracy"], "macro_f1": m["macro_f1"],
            "benign_false_positive_rate": m["benign_false_positive_rate"]}


@dataclass
class RetrainResult:
    keep: bool
    report: dict
    bundle: Bundle  # the candidate, even when rejected
    train_rows: pd.DataFrame  # what it was trained on (the drift reference is made from it)


def retrain(base: pd.DataFrame, base_meta: dict, feedback: pd.DataFrame, feedback_meta: dict,
            current: Bundle, *, current_sha256: str | None = None,
            feedback_weight: float = DEFAULT_FEEDBACK_WEIGHT,
            tolerance: float = DEFAULT_TOLERANCE, seed: int = SEED,
            min_holdout: int = DEFAULT_MIN_HOLDOUT,
            allow_different_base: bool = False) -> RetrainResult:
    if feedback_weight <= 0 or not np.isfinite(feedback_weight):
        raise ValueError("--feedback-weight must be positive")
    if tolerance < 0:
        raise ValueError("--tolerance must not be negative")
    for name, meta in (("the labelled data", base_meta), ("the feedback file", feedback_meta)):
        if not meta:
            raise ValueError(f"{name} has no extraction metadata; refusing to use it")
        check_same_extraction(current.extraction_meta, meta)
    need = [*current.features, "label"]
    missing = [c for c in need if c not in feedback.columns]
    if missing:
        raise ValueError(f"the feedback file is missing column(s): {missing}")
    feedback = feedback.dropna(subset=need).copy()
    feedback["label"] = feedback["label"].astype(str)
    n_before = len(feedback)
    # The same feature vector with the same label twice would land on both sides of the split.
    feedback = feedback.drop_duplicates(subset=need).reset_index(drop=True)
    if feedback.empty:
        raise ValueError("the feedback file has no usable rows")

    sp = resplit(current, base)
    base_matches = (sp.description["parts"]["train"]["rows"]
                    == current.split["parts"]["train"]["rows"])
    if not base_matches and not allow_different_base:
        raise ValueError(
            "the labelled data do not reproduce the current model's training split "
            f"({sp.description['parts']['train']['rows']} train rows, the model trained on "
            f"{current.split['parts']['train']['rows']}), so the comparison with the current "
            "model would not be on its own test data; pass the files it was trained on, or "
            "--allow-different-base to go on anyway")
    fb_train, fb_hold = split_feedback(feedback)
    # A class that only the feedback has would get the full feedback weight on top of its
    # balancing weight (few rows, so a large one): it counts like any other class instead.
    known = set(sp.train["label"])
    new_classes = sorted(set(feedback["label"]) - known)
    fb_weight = np.where(fb_train["label"].isin(known), feedback_weight, 1.0)
    train = pd.concat([sp.train[need], fb_train[need]], ignore_index=True)
    weight = np.concatenate([np.ones(len(sp.train)), fb_weight])
    trained = train_all(current.model_name, train, list(current.features), seed, weight)
    version = make_version(current.model_name, train, list(current.features))
    metrics = {"validation": _metrics_for(trained, sp.validation),
               "test": _metrics_for(trained, sp.test),
               "feedback_holdout": _metrics_for(trained, fb_hold)}
    description = {**sp.description, "retrain": {
        "parent_version": model_version(current, current_sha256),
        "parent_sha256": current_sha256, "feedback_rows": len(feedback),
        "feedback_train_rows": len(fb_train), "feedback_holdout_rows": len(fb_hold),
        "feedback_weight": feedback_weight}}
    new = Bundle(model_name=current.model_name, model=trained.model,
                 label_encoder=trained.label_encoder, features=list(current.features),
                 extraction_meta=current.extraction_meta, split=description, metrics=metrics,
                 anomaly=trained.anomaly, version=version)

    cur_a, new_a = evaluate_on(current, sp.test), evaluate_on(new, sp.test)
    cur_b, new_b = evaluate_on(current, fb_hold), evaluate_on(new, fb_hold)
    floor = cur_a["macro_f1"] - tolerance
    f1_ok = new_a["macro_f1"] >= floor
    acc_ok = new_b["accuracy"] >= cur_b["accuracy"]
    reasons = []
    if not f1_ok:
        reasons.append(f"macro-F1 on the base test split fell from {cur_a['macro_f1']:.4f} to "
                       f"{new_a['macro_f1']:.4f} (allowed down to {floor:.4f})")
    if not acc_ok:
        reasons.append(f"accuracy on the feedback holdout is {new_b['accuracy']:.4f}, below the "
                       f"current model's {cur_b['accuracy']:.4f}")
    size_ok = len(fb_hold) >= min_holdout
    if not size_ok:
        reasons.append(f"the feedback holdout has {len(fb_hold)} rows, fewer than the "
                       f"{min_holdout} needed to trust criterion (b) (--min-holdout)")
    keep = f1_ok and acc_ok and size_ok
    counts = lambda d: {str(k): int(v) for k, v in d["label"].value_counts().items()}
    report = {
        "created_at": datetime.now(UTC).isoformat(),
        "current": {"version": model_version(current, current_sha256),
                    "sha256": current_sha256, "model": current.model_name},
        "new": {"version": version, "model": new.model_name},
        "settings": {"feedback_weight": feedback_weight, "tolerance": tolerance, "seed": seed,
                     "split_mode": current.split["mode"]},
        "data": {"base_train_rows": len(sp.train), "base_test_rows": len(sp.test),
                 "base_reproduces_current": bool(base_matches),
                 "base_override": bool(allow_different_base and not base_matches),
                 "feedback_duplicates_dropped": n_before - len(feedback),
                 "new_classes": new_classes,
                 "new_classes_note": (
                     "classes the current model has never seen: it cannot predict them (so it "
                     "gets those holdout rows wrong), and their feedback rows are weighted 1 "
                     "instead of --feedback-weight" if new_classes else None),
                 "feedback_rows": len(feedback), "feedback_train_rows": len(fb_train),
                 "feedback_holdout_rows": len(fb_hold),
                 "feedback_labels": counts(feedback), "holdout_labels": counts(fb_hold)},
        "base_test": {"current": _brief(cur_a), "new": _brief(new_a)},
        "feedback_holdout": {"current": _brief(cur_b), "new": _brief(new_b)},
        "criteria": {"min_macro_f1": floor, "macro_f1_ok": bool(f1_ok),
                     "holdout_accuracy_ok": bool(acc_ok),
                     "min_holdout": min_holdout, "holdout_size_ok": bool(size_ok)},
        "decision": {"keep": bool(keep), "reasons": reasons},
    }
    return RetrainResult(keep, report, new, train)


def same_file(a: str | Path, b: str | Path) -> bool:
    a, b = Path(a), Path(b)
    if a.resolve() == b.resolve():
        return True
    return a.exists() and b.exists() and os.path.samefile(a, b)


def write_kept(result: RetrainResult, output: str | Path) -> None:
    """Write the new model, its `.sha256` and its drift sidecar so that a failure leaves nothing
    half-written: everything is built under temporary names first, the sidecar and digest are
    moved into place, and the bundle itself is moved LAST (a bundle without its digest is
    refused by load_bundle, so nobody can load a half-installed model)."""
    out = Path(output)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp_side = drift.sidecar_path(tmp)
    made = [tmp, digest_path(tmp), tmp_side]
    try:
        save_bundle(result.bundle, tmp)
        digest = read_digest(tmp)
        tmp_side.write_text(drift.reference_text(result.train_rows, digest,
                                                 list(result.bundle.features)))
        digest_path(tmp).write_text(f"{digest}  {out.name}\n")
        os.replace(tmp_side, drift.sidecar_path(out))
        os.replace(digest_path(tmp), digest_path(out))
        os.replace(tmp, out)
    finally:
        for p in made:
            p.unlink(missing_ok=True)
