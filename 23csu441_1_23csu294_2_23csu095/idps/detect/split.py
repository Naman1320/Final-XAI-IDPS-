"""Time-based train/validation/test splits (never random).

Near-duplicate flows (scan bursts, DoS floods) are close together in time, so a random split
would put copies of the same flow in train and test and inflate every score. Here, train is
always strictly earlier than validation, which is strictly earlier than test.

Three modes: `class-time` (default; per day and class, earliest 60% train, then validation,
then test, with a gap around each cut), `day` (whole days) and `window` (rows by time).
After splitting, exact duplicate rows are dropped inside each split, and the share of test
rows whose feature vector also occurs in train is reported.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

from idps.detect.data import BENIGN
from idps.features import MODEL_FEATURES

_DAY_MS = 86_400_000
# Flows last up to the active timeout (120 s), so a flow that starts this close to a cut can
# still be running on the other side of it.
DEFAULT_GAP_MS = 120_000


@dataclass
class Split:
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    description: dict


def _iso(ms: int) -> str:
    return pd.Timestamp(ms, unit="ms", tz="UTC").isoformat()


def _describe(mode: str, parts: dict[str, pd.DataFrame], extra: dict) -> dict:
    out = {"mode": mode, **extra, "parts": {}}
    for name, df in parts.items():
        lo, hi = int(df["start_ms"].min()), int(df["start_ms"].max())
        out["parts"][name] = {
            "rows": len(df),
            "first_start_ms": lo,
            "last_start_ms": hi,
            "first_start": _iso(lo),
            "last_start": _iso(hi),
            "class_counts": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        }
    return out


_HASH_CHUNK = 200_000


def _row_hashes(df: pd.DataFrame, features: list[str]) -> np.ndarray:
    """64-bit hash of each row's feature vector (equal vectors, equal hashes; -0.0 counts as 0.0).
    Chunked, so a frame of millions of rows is never copied to float64 in one piece."""
    out = np.empty(len(df), dtype=np.uint64)
    for i in range(0, len(df), _HASH_CHUNK):
        chunk = df[features].iloc[i : i + _HASH_CHUNK].astype("float64") + 0.0
        out[i : i + _HASH_CHUNK] = pd.util.hash_pandas_object(chunk, index=False).to_numpy()
    return out


def _identical_to_train(train: pd.DataFrame, part: pd.DataFrame, features: list[str]) -> dict:
    """How many rows of `part` have a feature vector identical to some train row.

    Compares 64-bit row hashes (a false match needs a 2**-64 collision per pair), which keeps
    memory flat on millions of rows where a merge on dozens of float columns would not."""
    hit = np.isin(_row_hashes(part, features), _row_hashes(train, features))
    return {"rows": int(hit.sum()), "share": float(hit.mean()) if len(part) else 0.0}


def _finish(
    mode: str,
    tr,
    va,
    te,
    extra: dict,
    allow_unseen_test_classes: bool = False,
    drop_duplicates: bool = True,
    features: list[str] | None = None,
    dropped_by_gap: dict | None = None,
    dup_columns: list[str] | None = None,
) -> Split:
    """`dup_columns`: the feature columns two rows must share (with the label) to be exact
    duplicates; default MODEL_FEATURES. Public datasets with their own columns pass theirs."""
    features = list(features or MODEL_FEATURES)
    dup_cols = [*(dup_columns or MODEL_FEATURES), "label"]
    dups = {}
    before = {}
    if drop_duplicates:
        out = []
        for name, df in (("train", tr), ("validation", va), ("test", te)):
            before[name] = {str(k): int(v) for k, v in df["label"].value_counts().items()}
            kept = df.drop_duplicates(subset=dup_cols)
            dups[name] = len(df) - len(kept)
            out.append(kept)
        tr, va, te = out
    for name, df in (("train", tr), ("validation", va), ("test", te)):
        if df.empty:
            raise ValueError(f"{mode} split left the {name} part empty; {extra}")
    classes_all = set(tr["label"]) | set(va["label"]) | set(te["label"])
    missing_train = sorted(classes_all - set(tr["label"]))
    if missing_train and not allow_unseen_test_classes:
        raise ValueError(
            f"class(es) {missing_train} are in the validation/test data but not in the "
            f"training split ({mode} split, {extra}); choose other boundaries or add data, "
            f"or pass allow_unseen_test_classes (--allow-unseen-test-classes) for a "
            f"leave-one-day-out experiment"
        )
    if BENIGN not in set(tr["label"]):
        raise ValueError(f"no {BENIGN} rows in the training split ({mode} split)")
    parts = {"train": tr, "validation": va, "test": te}
    extra = {
        **extra,
        "allow_unseen_test_classes": allow_unseen_test_classes,
        "duplicates_dropped": dups if drop_duplicates else None,
        "class_counts_before_duplicates": before if drop_duplicates else None,
        "train_overlap_features": features,
    }
    if dropped_by_gap is not None:
        extra["dropped_by_gap"] = dropped_by_gap
    desc = _describe(mode, parts, extra)
    desc["identical_to_train"] = {
        "validation": _identical_to_train(tr, va, features),
        "test": _identical_to_train(tr, te, features),
    }
    return Split(
        tr.reset_index(drop=True), va.reset_index(drop=True), te.reset_index(drop=True), desc
    )


def split_by_class_time(
    df: pd.DataFrame,
    val_frac: float = 0.2,
    test_frac: float = 0.2,
    gap_ms: int = DEFAULT_GAP_MS,
    allow_unseen_test_classes: bool = False,
    drop_duplicates: bool = True,
    features: list[str] | None = None,
    dup_columns: list[str] | None = None,
    group_col: str = "label",
    max_drop_share: float | None = None,
    day_col: str | None = None,
) -> Split:
    """Per (UTC day, label) group, sorted by start_ms: the first 1 - val - test of the rows
    (default 60%) are train, the next `val_frac` validation, the last `test_frac` test. Rows
    that start less than `gap_ms` from a cut (the start time of the first row after it) are
    dropped, so no train flow can still be running when a test flow begins.

    This suits CIC-IDS2017, where most attack types occur on a single day: every class
    is then in train and is tested on later traffic of the same class. The cost is that
    train and test come from the same day and attack tool, so scores are optimistic about
    new attack tools or days; use --split day with allow_unseen_test_classes for that.

    `group_col` names the column that defines the groups (default the label the model learns).
    A public dataset whose model labels merge several attacks (DoS) groups by the original
    attack name instead, so every attack is cut 60/20/20 and not only the merged class.

    `day_col` (default None: the UTC day of start_ms) names a column that says which capture
    day or session a row belongs to. UNSW-NB15 uses it: its two captures are 26 days apart and
    the first one runs past UTC midnight, so a calendar-day key would cut a capture in two.

    `max_drop_share` (default None: off) shrinks the gap of a group so that at most this share
    of its rows is dropped. Needed when a group's rows are bunched in time (a 3-minute attack
    burst, or a benign class whose flows sit inside it): a fixed 120 s gap would then remove
    the whole group and the class would vanish from train or test. The gap actually used is
    reported per group label in `effective_gap_ms` (never above `gap_ms`; the shrunk gap is
    an actual distance between a row and a cut, so a group of fewer than about 10 rows can end
    up with a gap of 0, and those groups are listed in `groups_with_zero_effective_gap`); when
    the gap shrinks, flows that start close to a cut but on opposite sides are not separated by
    the full active timeout.
    """
    if val_frac <= 0 or test_frac <= 0 or val_frac + test_frac >= 1:
        raise ValueError("val_frac and test_frac must be > 0 and sum to < 1")
    if gap_ms < 0:
        raise ValueError("gap_ms must not be negative")
    t = df["start_ms"].astype("int64").to_numpy()
    day = t // _DAY_MS if day_col is None else df[day_col].to_numpy()
    keys = pd.DataFrame({"day": day, "label": df[group_col].astype(str).to_numpy(), "t": t})
    part = np.full(len(df), -1)  # 0 train, 1 validation, 2 test, -1 dropped by the gap
    dropped: dict[str, int] = {}
    shrunk: dict[str, float] = {}
    zero_gap: list[str] = []
    if max_drop_share is not None and not 0 <= max_drop_share <= 1:
        raise ValueError("max_drop_share must be between 0 and 1")
    for (day_key, label), group in keys.groupby(["day", "label"], sort=False):
        rows = group.sort_values("t", kind="stable").index.to_numpy()
        n, tt = len(rows), t[rows]
        i1, i2 = int(n * (1 - val_frac - test_frac)), int(n * (1 - test_frac))
        b1, b2 = tt[i1], tt[i2]  # i2 <= n - 1 because test_frac > 0
        idx = np.arange(n)
        grp = np.where(idx < i1, 0, np.where(idx < i2, 1, 2))
        dist = np.minimum(np.abs(tt - b1), np.abs(tt - b2))
        use = float(gap_ms)
        if max_drop_share is not None and (dist < use).mean() > max_drop_share:
            # 'lower' takes an actual distance (no interpolation between two rows' distances,
            # which let a 2-row group end up with a gap far above the nominal one); the minimum
            # keeps the shrunk gap from ever exceeding the nominal gap.
            use = min(float(np.quantile(dist, max_drop_share, method="lower")), float(gap_ms))
            shrunk[label] = min(shrunk.get(label, use), use)
            if use == 0:
                zero_gap.append(f"{day_key}:{label}")
        near = dist < use
        grp[near] = -1
        part[rows] = grp
        if near.any():
            dropped[label] = dropped.get(label, 0) + int(near.sum())
    pick = lambda k: df[part == k].sort_values("start_ms", kind="stable")
    extra = {
        "val_frac": val_frac,
        "test_frac": test_frac,
        "train_frac": 1 - val_frac - test_frac,
        "gap_ms": gap_ms,
        "max_drop_share": max_drop_share,
        "effective_gap_ms": shrunk,
    }
    if zero_gap:
        # A gap of 0 drops nothing: train, validation and test flows of the group touch at the
        # cuts (the group is too small or too bunched for the drop limit). Listed as "day:label".
        extra["groups_with_zero_effective_gap"] = zero_gap
    return _finish(
        "class-time",
        pick(0),
        pick(1),
        pick(2),
        extra,
        allow_unseen_test_classes,
        drop_duplicates,
        features,
        {"total": int((part == -1).sum()), "per_class": dropped},
        dup_columns,
    )


def split_by_day(
    df: pd.DataFrame,
    val_days: int = 1,
    test_days: int = 1,
    allow_unseen_test_classes: bool = False,
    drop_duplicates: bool = True,
    features: list[str] | None = None,
    dup_columns: list[str] | None = None,
) -> Split:
    """Last `test_days` calendar days (UTC, from start_ms) are test, the `val_days` before
    them validation, everything earlier is train. Days without data are ignored."""
    if val_days < 1 or test_days < 1:
        raise ValueError("val_days and test_days must be at least 1")
    day = df["start_ms"].astype("int64") // _DAY_MS
    days = sorted(day.unique())
    if len(days) < val_days + test_days + 1:
        raise ValueError(
            f"need at least {val_days + test_days + 1} distinct UTC days for a day split, "
            f"found {len(days)}; use --split window instead"
        )
    test_set = days[-test_days:]
    val_set = days[-(test_days + val_days) : -test_days]
    train_set = days[: -(test_days + val_days)]
    fmt = lambda ds: [str(pd.Timestamp(int(d) * _DAY_MS, unit="ms").date()) for d in ds]
    return _finish(
        "day",
        df[day.isin(train_set)],
        df[day.isin(val_set)],
        df[day.isin(test_set)],
        {"train_days": fmt(train_set), "validation_days": fmt(val_set), "test_days": fmt(test_set)},
        allow_unseen_test_classes,
        drop_duplicates,
        features,
        dup_columns=dup_columns,
    )


def split_by_window(
    df: pd.DataFrame,
    val_frac: float = 0.2,
    test_frac: float = 0.2,
    allow_unseen_test_classes: bool = False,
    drop_duplicates: bool = True,
    features: list[str] | None = None,
    dup_columns: list[str] | None = None,
) -> Split:
    """Sort by start_ms and cut into three contiguous windows with about the given row
    fractions. Cuts fall on a start_ms value; rows with the same start_ms stay together
    (they go to the later window)."""
    if val_frac <= 0 or test_frac <= 0 or val_frac + test_frac >= 1:
        raise ValueError("val_frac and test_frac must be > 0 and sum to < 1")
    t = df["start_ms"].astype("int64")
    s = t.sort_values().to_numpy()
    n = len(s)
    if n < 3:
        raise ValueError("too few rows to split")
    cut_val = int(s[int(n * (1 - val_frac - test_frac))])
    cut_test = int(s[min(int(n * (1 - test_frac)), n - 1)])
    extra = {
        "val_frac": val_frac,
        "test_frac": test_frac,
        "validation_starts_ms": cut_val,
        "test_starts_ms": cut_test,
        "validation_starts": _iso(cut_val),
        "test_starts": _iso(cut_test),
    }
    return _finish(
        "window",
        df[t < cut_val],
        df[(t >= cut_val) & (t < cut_test)],
        df[t >= cut_test],
        extra,
        allow_unseen_test_classes,
        drop_duplicates,
        features,
        dup_columns=dup_columns,
    )
