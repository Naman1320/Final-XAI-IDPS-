"""Evaluation: per-class P/R/F1, macro-F1, BENIGN false-positive rate, confusion matrix,
ROC-AUC (one-vs-rest, only where defined), and anomaly-detector results."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from idps.detect.data import BENIGN


def evaluate_classifier(y_true, y_pred, proba: np.ndarray | None = None,
                        classes: list[str] | None = None) -> dict:
    """Metrics for string labels. `proba` columns follow `classes` (the model's classes).

    False-positive rate on BENIGN = BENIGN flows predicted as anything else / all BENIGN flows
    (None if there are no BENIGN flows). ROC-AUC is one-vs-rest per class, only for classes
    with both positive and negative examples in y_true; macro is the mean of those.

    Macro-F1 convention (same as scikit-learn's default): the unweighted mean of the F1 of
    every label in the UNION of y_true and y_pred. A class that was predicted but never occurs
    in y_true therefore counts with F1 = 0 (it is a false-alarm class), and per_class lists
    all those labels too. Classes only in `classes` (never true, never predicted) are listed
    but do not enter the mean.
    """
    y_true = np.asarray(y_true, dtype=object)
    y_pred = np.asarray(y_pred, dtype=object)
    labels = sorted(set(y_true) | set(y_pred) | set(classes or []))
    p, r, f, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0)
    per_class = {lab: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                       "support": int(support[i])} for i, lab in enumerate(labels)}
    scored = sorted(set(y_true) | set(y_pred))  # the macro-F1 labels
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    fpr = None
    benign = y_true == BENIGN
    if benign.any():
        fpr = float((y_pred[benign] != BENIGN).mean())

    auc: dict[str, float | None] = {}
    if proba is not None and classes is not None:
        for i, lab in enumerate(classes):
            pos = y_true == lab
            auc[lab] = float(roc_auc_score(pos, proba[:, i])) if 0 < pos.sum() < len(pos) else None
    defined = [v for v in auc.values() if v is not None]
    return {
        "n": len(y_true),
        "accuracy": float((y_true == y_pred).mean()) if len(y_true) else None,
        "macro_f1": float(np.mean([per_class[lab]["f1"] for lab in scored])) if scored else None,
        "per_class": per_class,
        "benign_false_positive_rate": fpr,
        "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "roc_auc": {"per_class": auc, "macro": float(np.mean(defined)) if defined else None},
    }


def evaluate_anomaly(y_true, scores: np.ndarray, flags: np.ndarray) -> dict:
    """Anomaly detector as BENIGN-vs-attack: detection rate per attack class, BENIGN
    false-positive rate and ROC-AUC of the score (None if only one side is present)."""
    y_true = np.asarray(y_true, dtype=object)
    benign = y_true == BENIGN
    out: dict = {"n": len(y_true),
                 "benign_false_positive_rate": float(flags[benign].mean()) if benign.any() else None,
                 "detection_rate_per_class": {
                     str(lab): float(flags[y_true == lab].mean())
                     for lab in sorted(set(y_true) - {BENIGN})}}
    out["roc_auc"] = (float(roc_auc_score(~benign, scores))
                      if benign.any() and (~benign).any() else None)
    return out


def evaluate_bundle(bundle, df: pd.DataFrame, meta: dict) -> dict:
    """Evaluate a loaded Bundle on a labelled frame (checks the extraction metadata first)."""
    X = bundle.select(df, meta)
    pred = bundle.predict(X)
    result = evaluate_classifier(df["label"], pred, bundle.predict_proba(X),
                                 list(bundle.label_encoder.classes_))
    if bundle.anomaly is not None:
        result["anomaly"] = evaluate_anomaly(df["label"], bundle.anomaly_scores(X),
                                             bundle.anomaly_flags(X))
    return result


def write_report(report: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True))
