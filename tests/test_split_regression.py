"""Regression test for the class-time split: with the default arguments it must equal, row for
row, what the committed version before the public-dataset options (`group_col`, `max_drop_share`,
`day_col`, `dup_columns`) produced. The reference below is that version's assignment code."""

import numpy as np
import pandas as pd
import pytest

from idps.detect.split import split_by_class_time
from idps.features import FEATURE_COLUMNS

DAY_MS = 86_400_000
T0 = 1_500_000_000_000 // DAY_MS * DAY_MS  # a UTC midnight


def synthetic(days=5, per_class=40, seed=0) -> pd.DataFrame:
    """3 classes spread over several days (feature values are irrelevant for the assignment)."""
    rng = np.random.default_rng(seed)
    rows = []
    for d in range(days):
        for label in ("BENIGN", "DoS", "PortScan"):
            for _ in range(per_class):
                r = dict.fromkeys(FEATURE_COLUMNS, 0)
                r["start_ms"] = T0 + d * DAY_MS + int(rng.integers(0, DAY_MS - 1))
                r["fwd_packets"] = int(rng.integers(1, 50))
                r["label"] = label
                rows.append(r)
    return pd.DataFrame(rows)


def _head_class_time_parts(df, val_frac=0.2, test_frac=0.2, gap_ms=120_000):
    """The class-time assignment exactly as the committed version of split.py (HEAD, before the
    public-dataset options) computed it: 0 train, 1 validation, 2 test, -1 dropped by the gap."""
    t = df["start_ms"].astype("int64").to_numpy()
    keys = pd.DataFrame({"day": t // DAY_MS, "label": df["label"].astype(str).to_numpy(), "t": t})
    part = np.full(len(df), -1)
    dropped: dict[str, int] = {}
    for (_, label), group in keys.groupby(["day", "label"], sort=False):
        rows = group.sort_values("t", kind="stable").index.to_numpy()
        n, tt = len(rows), t[rows]
        i1, i2 = int(n * (1 - val_frac - test_frac)), int(n * (1 - test_frac))
        b1, b2 = tt[i1], tt[i2]
        idx = np.arange(n)
        grp = np.where(idx < i1, 0, np.where(idx < i2, 1, 2))
        near = (np.abs(tt - b1) < gap_ms) | (np.abs(tt - b2) < gap_ms)
        grp[near] = -1
        part[rows] = grp
        if near.any():
            dropped[label] = dropped.get(label, 0) + int(near.sum())
    return part, dropped


@pytest.mark.parametrize("seed", [0, 1, 2])
@pytest.mark.parametrize("gap_ms", [0, 30_000, 120_000, 3_600_000])
def test_default_class_time_split_equals_the_head_version(seed, gap_ms):
    """Defaults (no group_col, day_col or max_drop_share) must give exactly what the version
    before the public-dataset options gave, including bunched groups and tiny ones."""
    df = synthetic(days=4, per_class=25, seed=seed)
    # a tiny group and a bunched one, where the gap rules differ the most
    extra = df.iloc[:5].copy()
    extra["label"] = "Tiny"
    extra["start_ms"] = T0 + 10_000 * np.arange(5)
    bunch = df.iloc[:30].copy()
    bunch["label"] = "Bunch"
    bunch["start_ms"] = T0 + 2 * DAY_MS + 1000 * np.arange(30)
    df = pd.concat([df, extra, bunch], ignore_index=True)
    df["uid"] = np.arange(len(df))
    part, dropped = _head_class_time_parts(df, gap_ms=gap_ms)
    sp = split_by_class_time(
        df, gap_ms=gap_ms, drop_duplicates=False, allow_unseen_test_classes=True
    )
    for k, got in enumerate((sp.train, sp.validation, sp.test)):
        want = df[part == k].sort_values("start_ms", kind="stable")
        assert got["uid"].tolist() == want["uid"].tolist()
    assert sp.description["dropped_by_gap"] == {
        "total": int((part == -1).sum()),
        "per_class": dropped,
    }
    assert sp.description["effective_gap_ms"] == {}  # the default never shrinks a gap
    assert "groups_with_zero_effective_gap" not in sp.description
