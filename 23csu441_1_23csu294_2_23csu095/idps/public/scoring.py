"""Scoring helpers for the public-dataset reports: scores on a fixed class set, bootstrap
confidence intervals, and a binomial interval.

`idps.detect.evaluate.evaluate_classifier` takes the macro-F1 over the UNION of true and predicted
labels, so a class that is predicted but absent from the truth adds an F1 of 0 to the mean. That is
right for one test set, but it makes two scores comparable only if both cover the same classes.
`restricted_metrics` scores a fixed class list (for example the classes both datasets have) and
counts what it leaves out.
"""

import time

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

from idps.detect.data import BENIGN

BOOTSTRAP_RESAMPLES = 200
BOOTSTRAP_SEED = 20260518


def restricted_metrics(y_true, y_pred, classes: list[str]) -> dict:
    """Macro-F1 and per-class scores over exactly `classes`.

    - rows whose TRUE class is not in `classes` are excluded (counted per class);
    - a kept row whose PREDICTION is outside `classes` stays in as an error (a miss for its true
      class); the outside label is not scored as a class of its own (counted);
    - macro-F1 is the mean of the F1 of every class in `classes`, including a class with no rows
      (F1 = 0), so two runs over the same list average over the same classes.
    """
    y_true = np.asarray(y_true, dtype=object)
    y_pred = np.asarray(y_pred, dtype=object)
    classes = list(classes)
    keep = np.isin(y_true, classes)
    excluded: dict[str, int] = {}
    for lab in sorted(set(y_true[~keep])):
        excluded[str(lab)] = int((y_true[~keep] == lab).sum())
    yt, yp = y_true[keep], y_pred[keep]
    outside = ~np.isin(yp, classes)
    if len(yt):
        p, r, f, s = precision_recall_fscore_support(yt, yp, labels=classes, zero_division=0)
    else:
        p = r = f = np.zeros(len(classes))
        s = np.zeros(len(classes), dtype=int)
    per_class = {
        c: {
            "precision": float(p[i]),
            "recall": float(r[i]),
            "f1": float(f[i]),
            "support": int(s[i]),
        }
        for i, c in enumerate(classes)
    }
    benign = yt == BENIGN
    return {
        "classes": classes,
        "n": int(keep.sum()),
        "accuracy": float((yt == yp).mean()) if len(yt) else None,
        "macro_f1": float(np.mean(f)) if len(classes) else None,
        "per_class": per_class,
        "benign_false_positive_rate": float((yp[benign] != BENIGN).mean())
        if benign.any()
        else None,
        "excluded_rows_true_class_outside": excluded,
        "excluded_rows_total": int((~keep).sum()),
        "kept_rows_predicted_outside": int(outside.sum()),
        "note": "macro-F1 over exactly these classes; rows of other true classes excluded; a "
        "prediction outside the list counts as a miss for the true class",
    }


def bootstrap_ci(
    y_true,
    y_pred,
    n_resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
    level: float = 0.95,
) -> dict:
    """Percentile bootstrap interval of the macro-F1 and of every class's F1: the test rows are
    resampled with replacement `n_resamples` times (fixed seed), predictions stay attached to
    their rows. The macro-F1 uses the same convention as evaluate_classifier (mean over labels
    that occur in the resample's truth or predictions). A class absent from a resample has no F1
    there (it is left out of that class's interval)."""
    y_true = np.asarray(y_true, dtype=object)
    y_pred = np.asarray(y_pred, dtype=object)
    labels = sorted(set(y_true) | set(y_pred))
    k, n = len(labels), len(y_true)
    if n == 0 or k == 0:
        return {"n_resamples": n_resamples, "seed": seed, "level": level, "macro_f1": None,
                "per_class_f1": {}}  # fmt: skip
    code = {lab: i for i, lab in enumerate(labels)}
    t = np.fromiter((code[v] for v in y_true), dtype=np.int64, count=n)
    q = np.fromiter((code[v] for v in y_pred), dtype=np.int64, count=n)
    rng = np.random.default_rng(seed)
    macro = np.empty(n_resamples)
    per = np.full((n_resamples, k), np.nan)
    for b in range(n_resamples):
        idx = rng.integers(0, n, n)
        cm = np.bincount(t[idx] * k + q[idx], minlength=k * k).reshape(k, k)
        tp = np.diag(cm).astype(float)
        support, called = cm.sum(axis=1), cm.sum(axis=0)
        denom = support + called
        f1 = np.divide(2 * tp, denom, out=np.zeros(k), where=denom > 0)
        present = denom > 0
        per[b, present] = f1[present]
        macro[b] = f1[present].mean()
    lo, hi = (1 - level) / 2 * 100, (1 + level) / 2 * 100
    out = {
        "n_resamples": n_resamples,
        "seed": seed,
        "level": level,
        "method": "percentile bootstrap over test rows",
        "macro_f1": [float(np.percentile(macro, lo)), float(np.percentile(macro, hi))],
        "per_class_f1": {},
    }
    for i, lab in enumerate(labels):
        col = per[:, i][~np.isnan(per[:, i])]
        if len(col):
            out["per_class_f1"][str(lab)] = [
                float(np.percentile(col, lo)),
                float(np.percentile(col, hi)),
            ]
    return out


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """Binomial 95% Wilson score interval of a share; None when n = 0."""
    if n <= 0:
        return None
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def timed(fn, *args, **kwargs):
    """(fn(*args, **kwargs), seconds it took)."""
    start = time.perf_counter()
    out = fn(*args, **kwargs)
    return out, time.perf_counter() - start


def dedupe_by_hash(df: pd.DataFrame, features: list[str], label: str = "label") -> pd.DataFrame:
    """The frame without rows whose `features` and label equal an earlier row's (first one kept).

    Decided on 64-bit row hashes, chunked, so a frame of millions of rows is never copied to
    float64 or factorised column by column (a false match needs a 2**-64 collision per pair).
    -0.0 counts as 0.0. Returns a new frame (a copy), the index reset."""
    from idps.detect.split import _row_hashes

    key = _row_hashes(df, features)
    lab = pd.util.hash_pandas_object(df[label].astype(str), index=False).to_numpy()
    with np.errstate(over="ignore"):
        key = key * np.uint64(0x9E3779B97F4A7C15) ^ lab
    dup = pd.Series(key).duplicated().to_numpy()
    return df[~dup].reset_index(drop=True)


def identical_mask(train: pd.DataFrame, part: pd.DataFrame, features: list[str]) -> np.ndarray:
    """True for the rows of `part` whose feature vector equals some row of `train` (row hashes)."""
    from idps.detect.split import _row_hashes

    return np.isin(_row_hashes(part, features), _row_hashes(train, features))
