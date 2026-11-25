"""CIC-IDS2017 loader for the cross-dataset test: the "TrafficLabelling" CSVs (they carry the
Timestamp and the attack label), with the CICFlowMeter columns renamed to the CSE-CIC-IDS2018
names (idps.public.labels.FEATURE_NAMES), so both datasets give the same frame layout.

(The "MachineLearningCSV" variant has no Timestamp, so it cannot be cut by time.)

The files are small enough (up to 700k flows) to read one at a time with pandas. The same cleaning
and per-(day, label) sampling as CSE-CIC-IDS2018 is applied, so the two samples are comparable.
Timestamps are parsed by idps.features.labels.parse_cic_timestamps (day first, minute or second
resolution, 12-hour clock without AM/PM in some files; the afternoon heuristic is documented
there) and are as published, with no timezone conversion.
"""

from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from idps.features.labels import parse_cic_timestamps
from idps.public.labels import (
    FEATURES_2018,
    common_label,
    rename_2017,
)
from idps.public.sampling import DAY_SECONDS, Caps, select_rows

_ID_COLUMNS = {"Flow ID", "Source IP", "Source Port", "Destination IP"}


def list_files(data_dir: str | Path) -> list[Path]:
    data_dir = Path(data_dir)
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise ValueError(f"no CIC-IDS2017 CSV files found in {data_dir}")
    return files


def clean_frame(raw: pd.DataFrame, caps: Caps, seed: int, source: str) -> tuple[pd.DataFrame, dict]:
    """One raw TrafficLabelling frame (header names as published) -> (frame, stats), the same
    columns as the CSE-CIC-IDS2018 frame."""
    raw = raw.rename(columns=lambda c: str(c).strip())
    rename, unmatched, missing = rename_2017(raw.columns)
    if missing:
        raise ValueError(f"{source} lacks CICFlowMeter column(s) {missing}")
    n_in = len(raw)
    has_label = raw["Label"].notna() & raw["Timestamp"].notna()
    # Rows that repeat the header, as in the 2018 files, if there are any.
    is_header = (raw["Label"] == "Label").to_numpy(dtype=bool)
    ts = parse_cic_timestamps(raw["Timestamp"].astype(str))
    ok = has_label.to_numpy(dtype=bool) & ~is_header & ts.notna().to_numpy(dtype=bool)
    label_original = raw["Label"].astype(str).str.replace("\x96", "-", regex=False).str.strip()
    label_original = label_original.str.replace("–", "-", regex=False)
    common = pd.Series(np.nan, index=raw.index, dtype=object)
    common[ok] = [common_label(x) for x in label_original[ok]]
    start_s = ((ts - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)).fillna(0)
    start_s = start_s.to_numpy(dtype=np.int64)

    steps = {
        "raw": common[~is_header & has_label.to_numpy(dtype=bool)].value_counts().to_dict(),
        "valid_timestamp": common[ok].value_counts().to_dict(),
    }
    idx = np.flatnonzero(ok)
    cap_of = {x: caps.for_class(common_label(x)) for x in label_original[ok].unique()}
    keep = select_rows(
        start_s[idx] // DAY_SECONDS,
        label_original.to_numpy(dtype=object)[idx],
        start_s[idx],
        cap_of.__getitem__,
        seed,
    )
    sel = idx[keep]
    steps["sampled"] = common.iloc[sel].value_counts().to_dict()

    # Sample first, convert after: only the chosen rows are turned into numbers (a float64 frame
    # of every row of a 700k-row file, 78 columns, would be 440 MB before the cap is applied).
    old_of = {new: old for old, new in rename.items()}
    chosen = raw.iloc[sel]
    mat32 = np.empty((len(sel), len(FEATURES_2018)), dtype=np.float32)
    with np.errstate(over="ignore"):
        for j, name in enumerate(FEATURES_2018):
            col = pd.to_numeric(chosen[old_of[name]], errors="coerce")
            mat32[:, j] = col.to_numpy(dtype="float64", na_value=np.nan).astype(np.float32)
    finite = np.isfinite(mat32).all(axis=1)
    nonfinite_cols = {
        FEATURES_2018[j]: int((~np.isfinite(mat32[:, j])).sum())
        for j in range(mat32.shape[1])
        if not np.isfinite(mat32[:, j]).all()
    }
    out = pd.DataFrame(mat32[finite], columns=FEATURES_2018)
    out["start_ms"] = start_s[sel[finite]] * 1000
    out["label_original"] = label_original.iloc[sel[finite]].to_numpy(dtype=object)
    out["label"] = common.iloc[sel[finite]].to_numpy(dtype=object)
    out["source"] = source
    steps["finite"] = out["label"].value_counts().to_dict()
    stats = {
        "file": source,
        "rows_read": n_in,
        "header_rows": int(is_header.sum()),
        "missing_label_or_timestamp": int((~has_label).sum()),
        "bad_timestamp": int((has_label.to_numpy(dtype=bool) & ~is_header & ts.isna()).sum()),
        "nonfinite_dropped": int((~finite).sum()),
        "nonfinite_by_column": nonfinite_cols,
        "rows_kept": len(out),
        "unmatched_2017_columns": unmatched,
        "steps": {k: {str(a): int(b) for a, b in v.items()} for k, v in steps.items()},
    }
    return out, stats


def load_cic2017(
    data_dir: str | Path, caps: Caps | None = None, seed: int = 42, max_rows: int | None = None
) -> tuple[pd.DataFrame, dict]:
    """Every CSV of data_dir (the TrafficLabelling folder) -> (one frame, report)."""
    caps = caps or Caps()
    frames, per_file = [], []
    for path in list_files(data_dir):
        raw = pd.read_csv(
            path,
            encoding="latin-1",
            nrows=max_rows,
            usecols=lambda c: str(c).strip() not in _ID_COLUMNS,
            low_memory=False,
        )
        frame, stats = clean_frame(raw, caps, seed, path.name)
        del raw
        frames.append(frame)
        per_file.append(stats)
    df = pd.concat(frames, ignore_index=True)
    steps: dict[str, Counter] = {}
    for s in per_file:
        for step, counts in s["steps"].items():
            steps.setdefault(step, Counter()).update(counts)
    report = {
        "dataset": "CIC-IDS2017 (TrafficLabelling CSVs)",
        "timestamp_note": "as published (CIC machines' local clock), minute or second "
        "resolution, 12-hour files corrected by idps.features.labels.parse_cic_timestamps; "
        "no timezone conversion",
        "caps": caps.as_dict(),
        "caps_scope": "per (day, original label), before the Infinity/NaN drop",
        "seed": seed,
        "max_rows_per_file": max_rows,
        "files": per_file,
        "unmatched_2017_columns": sorted(
            {u for s in per_file for u in s["unmatched_2017_columns"]}
        ),
        "steps": {k: {a: int(b) for a, b in sorted(v.items())} for k, v in steps.items()},
        "rows_total": len(df),
    }
    return df, report
