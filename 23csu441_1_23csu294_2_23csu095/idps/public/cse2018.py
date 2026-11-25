"""CSE-CIC-IDS2018 loader: per-day Parquet files (every column text, see
scripts/fetch_cse_cic_ids2018.py) -> one clean, memory-bounded float32 frame.

Cleaning, in this order, with the class counts after each step in the report:
1. `raw`: rows read, minus the header rows that some files repeat inside the data (a row whose
   Label, Timestamp or Dst Port equals its own column name);
2. `valid_timestamp`: rows with a parseable Timestamp and a Label (an unknown label is an error);
3. `sampled`: at most `caps` rows per (day, original label), evenly spaced in time
   (idps.public.sampling); the caps apply before step 4, so a group can end a little under its cap;
4. `finite`: rows whose 78 features all parse to finite numbers; "Infinity", "NaN", empty and
   unparseable cells drop the whole row (a row is never filled in or guessed).
Duplicate rows are removed later, inside each split (see idps.public.pipeline).

The file is read twice, one batch at a time (never all rows): pass 1 reads only Label, Timestamp
and Dst Port to choose the rows; pass 2 reads the 78 feature columns of the chosen rows.

Timestamps: "01/03/2018 08:17:11" (TIMESTAMP_FORMAT_2018: day/month/year, whole seconds) as
published. THE HOUR IS ON A 12-HOUR CLOCK WITHOUT AM/PM: the hours that occur in the files are 1-5
and 8-12 (a few stray rows have 6 or 7), never 0 or 13-23. The attack windows show the rule: on
Wednesday 14-02 FTP-BruteForce sits at hours 10-12 (the dataset's schedule: 10:32-12:09) and
SSH-Bruteforce at hours 2-3 (schedule 14:01-15:31); on Friday 16-02 DoS-Hulk is at hour 1
(schedule 13:45-14:19). So hours 1-7 are afternoon (+12 h) and 8-12 stay as they are (12 = noon).
The unfolded time is what `start_ms` holds. The 6 and 7 are ambiguous (18:xx/19:xx or 06:xx/07:xx);
they are folded like the other hours 1-7 and counted per file (`ambiguous_hour_rows`). Row order in
the files is NOT chronological, so the file order cannot be used instead. A row with hour 0 or
13-23 cannot come from this clock: it is dropped and counted (`hour_outside_12h`), and a file where
more than 1% of the rows do that is refused (it would be a 24 h file, and the rule would be wrong).

A row whose DATE is not the day in the file name (junk stamps such as 05/01/1970 or a January-2018
date) is dropped and counted per file (`wrong_date`); for a file without a date in its name only
the year (2018) is checked. The dataset's timezone is not known or converted; the values only order
flows, so `start_ms` (seconds x 1000, read as if UTC) is correct up to a constant shift.
One-second resolution means many flows share a start time.
"""

import datetime
import json
import re
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from idps.public.labels import (
    DST_PORT,
    FEATURES_2018,
    LABEL,
    TIMESTAMP,
    TIMESTAMP_FORMAT_2018,
    common_label,
)
from idps.public.sampling import DAY_SECONDS, Caps, select_rows

BATCH_ROWS = 262_144
# More unparseable timestamps than this in a file means the format changed: stop, do not guess.
MAX_BAD_TIMESTAMP_SHARE = 0.05
_KEY_COLUMNS = (LABEL, TIMESTAMP, DST_PORT)
# The capture ran 14 Feb - 2 Mar 2018. Some files hold flows stamped 1970 (a CICFlowMeter clock
# bug, five rows in the Wednesday 14-02 file): they would form their own "day", so a row whose date
# is not the file's day (or, without a date in the file name, whose year is not 2018) is dropped.
EXCEL_ROW_LIMIT = 1_048_575  # data rows of a worksheet: 1,048,576 minus the header
MIN_SECONDS = 1514764800  # 2018-01-01 00:00:00
MAX_SECONDS = 1546300800  # 2019-01-01 00:00:00
# The hour is on a 12-hour clock without AM/PM (see the module docstring): hours 1-7 are afternoon.
AFTERNOON_HOURS = range(1, 8)
MORNING_HOURS = range(8, 13)  # 12 = noon
AMBIGUOUS_HOURS = (6, 7)
MAX_OUTSIDE_12H_SHARE = 0.01  # more rows with hour 0 or 13-23 than this: a 24 h file, refuse
_HALF_DAY = 43_200
_DATE_IN_NAME = re.compile(r"(?<!\d)(\d{2})-(\d{2})-(20\d{2})(?!\d)")


def list_files(data_dir: str | Path, only: list[str] | None = None) -> list[Path]:
    """The finished Parquet files: those listed in manifest.json (the downloader writes the
    manifest entry after the file is complete, so a half-written file is never read), or every
    *.parquet if there is no manifest. `only`: keep files whose name contains one of these."""
    data_dir = Path(data_dir)
    manifest = data_dir / "manifest.json"
    if manifest.exists():
        entries = json.loads(manifest.read_text()).values()
        names = [e["parquet"] for e in entries if isinstance(e, dict) and "parquet" in e]
        files = [data_dir / n for n in names if (data_dir / n).exists()]
    else:
        files = list(data_dir.glob("*.parquet"))
    if only:
        files = [f for f in files if any(o in f.name for o in only)]
    if not files:
        raise ValueError(f"no CSE-CIC-IDS2018 Parquet files found in {data_dir}")
    return sorted(files)


def header_row_mask(df: pd.DataFrame) -> np.ndarray:
    """Rows that repeat the header: Label, Timestamp or Dst Port holds its own column name."""
    mask = np.zeros(len(df), dtype=bool)
    for col in _KEY_COLUMNS:
        if col in df.columns:
            mask |= (df[col] == col).to_numpy(dtype=bool, na_value=False)
    return mask


def file_date(name: str) -> datetime.date | None:
    """The day a file name states ("Wednesday-14-02-2018_..." = 14 Feb 2018, day-month-year), or
    None if the name has no valid date."""
    m = _DATE_IN_NAME.search(name)
    if not m:
        return None
    try:
        return datetime.date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    except ValueError:
        return None


def parse_timestamps_detailed(column, expected_date: datetime.date | None = None) -> dict:
    """Parse text timestamps (TIMESTAMP_FORMAT_2018) and unfold the 12-hour clock.

    Returns arrays with one value per row: `seconds` (int64 since 1970, hours 1-7 moved to the
    afternoon), `ok` (usable), `raw_hour`, and the reasons a row is not usable, which never
    overlap: `unparseable` (text does not match, or without `expected_date` the year is not 2018),
    `wrong_date` (parsed, but not `expected_date`), `outside_12h` (right date, hour 0 or 13-23)."""
    parsed = pc.strptime(column, format=TIMESTAMP_FORMAT_2018, unit="s", error_is_null=True)
    valid = pc.is_valid(parsed).to_numpy(zero_copy_only=False).astype(bool)
    raw = parsed.cast(pa.int64()).fill_null(0).to_numpy(zero_copy_only=False).astype(np.int64)
    if expected_date is None:
        date_ok = (raw >= MIN_SECONDS) & (raw < MAX_SECONDS)
        unparseable = ~(valid & date_ok)
        wrong_date = np.zeros(len(raw), dtype=bool)
    else:
        day = (expected_date - datetime.date(1970, 1, 1)).days
        date_ok = raw // 86_400 == day
        unparseable = ~valid
        wrong_date = valid & ~date_ok
    hour = (raw % 86_400) // 3_600
    outside = valid & date_ok & ((hour == 0) | (hour >= 13))
    ok = valid & date_ok & ~outside
    fold = (hour >= AFTERNOON_HOURS.start) & (hour < AFTERNOON_HOURS.stop)
    return {
        "seconds": raw + _HALF_DAY * fold,
        "ok": ok,
        "raw_hour": hour,
        "unparseable": unparseable,
        "wrong_date": wrong_date,
        "outside_12h": outside,
    }


def parse_timestamps(
    column, expected_date: datetime.date | None = None
) -> tuple[np.ndarray, np.ndarray]:
    """(seconds since 1970 as int64 on the unfolded clock, valid mask); see
    parse_timestamps_detailed."""
    d = parse_timestamps_detailed(column, expected_date)
    return d["seconds"], d["ok"]


def to_float32(column) -> np.ndarray:
    """Text column -> float32; "Infinity" gives inf, "NaN" nan, anything unparseable nan."""
    try:
        out = pc.cast(column, pa.float32())
        return out.fill_null(np.nan).to_numpy(zero_copy_only=False).astype(np.float32)
    except pa.ArrowInvalid:
        values = pd.to_numeric(column.to_pandas(), errors="coerce")
        with np.errstate(over="ignore"):
            return values.to_numpy(dtype="float64", na_value=np.nan).astype(np.float32)


def feature_matrix(table) -> tuple[np.ndarray, np.ndarray]:
    """(float32 matrix with one column per FEATURES_2018, finite mask per row) of a batch."""
    mat = np.empty((table.num_rows, len(FEATURES_2018)), dtype=np.float32)
    for j, name in enumerate(FEATURES_2018):
        mat[:, j] = to_float32(table.column(name))
    return mat, np.isfinite(mat).all(axis=1)


def _scan(pf: pq.ParquetFile, n: int, expected_date: datetime.date | None = None) -> dict:
    """Pass 1: header rows, timestamps and label codes of the first n rows."""
    ts = np.zeros(n, dtype=np.int64)
    code = np.full(n, -1, dtype=np.int32)  # index into `names`; -1 = not usable
    names: dict[str, int] = {}
    header = missing_label = bad_ts = wrong_date = outside_12h = 0
    wrong_dates: Counter = Counter()
    raw_hours: Counter = Counter()
    ambiguous: Counter = Counter()
    ts_ok_all = np.zeros(n, dtype=bool)
    offset = 0
    for batch in pf.iter_batches(batch_size=BATCH_ROWS, columns=list(_KEY_COLUMNS)):
        if offset >= n:
            break
        batch = batch.slice(0, n - offset)
        df = batch.to_pandas()
        hdr = header_row_mask(df)
        stamp = parse_timestamps_detailed(batch.column(TIMESTAMP), expected_date)
        sec, ok = stamp["seconds"], stamp["ok"]
        raw_label = df[LABEL].str.strip()
        has_label = raw_label.notna().to_numpy(dtype=bool) & ~hdr
        header += int(hdr.sum())
        missing_label += int((~hdr & ~has_label).sum())
        bad_ts += int((has_label & stamp["unparseable"]).sum())
        wrong = has_label & stamp["wrong_date"]
        wrong_date += int(wrong.sum())
        for d, k in zip(*np.unique(sec[wrong] // 86_400, return_counts=True), strict=True):
            wrong_dates[str(datetime.date(1970, 1, 1) + datetime.timedelta(days=int(d)))] += int(k)
        outside_12h += int((has_label & stamp["outside_12h"]).sum())
        used = has_label & ok
        for h, k in zip(*np.unique(stamp["raw_hour"][used], return_counts=True), strict=True):
            raw_hours[int(h)] += int(k)
        for h in AMBIGUOUS_HOURS:
            ambiguous[h] += int((used & (stamp["raw_hour"] == h)).sum())
        sl = slice(offset, offset + len(df))
        ts[sl], ts_ok_all[sl] = sec, ok
        codes = np.full(len(df), -1, dtype=np.int32)
        for lab in raw_label[has_label].unique():
            codes[(raw_label == lab).to_numpy(dtype=bool) & has_label] = names.setdefault(
                lab, len(names)
            )
        code[sl] = codes
        offset += len(df)
    return {
        "ts": ts,
        "ts_ok": ts_ok_all,
        "code": code,
        "names": list(names),
        "header_rows": header,
        "missing_label": missing_label,
        "bad_timestamp": bad_ts,
        "wrong_date": wrong_date,
        "wrong_date_by_date": dict(wrong_dates),
        "hour_outside_12h": outside_12h,
        "raw_hour_histogram": dict(sorted(raw_hours.items())),
        "ambiguous_hour_rows": {str(h): ambiguous[h] for h in AMBIGUOUS_HOURS},
    }


def _iso(seconds) -> str:
    return pd.Timestamp(int(seconds), unit="s").isoformat()


def _count(codes: np.ndarray, common_of: list[str]) -> dict[str, int]:
    counts = np.bincount(codes[codes >= 0], minlength=len(common_of))
    out: Counter = Counter()
    for c, k in zip(common_of, counts, strict=True):
        out[c] += int(k)
    return dict(out)


def load_file(
    path: str | Path, caps: Caps, seed: int, max_rows: int | None = None
) -> tuple[pd.DataFrame, dict]:
    """One day file -> (frame, stats). Frame columns: the 78 FEATURES_2018 (float32), `start_ms`,
    `label` (common class), `label_original` and `source` (the file name)."""
    path = Path(path)
    pf = pq.ParquetFile(path)
    missing = [c for c in (*FEATURES_2018, TIMESTAMP, LABEL) if c not in pf.schema_arrow.names]
    if missing:
        raise ValueError(f"{path.name} lacks column(s) {missing}")
    n = pf.metadata.num_rows if max_rows is None else min(max_rows, pf.metadata.num_rows)
    expected = file_date(path.name)
    scan = _scan(pf, n, expected)
    names, code = scan["names"], scan["code"]
    common_of = [common_label(x) for x in names]  # an unknown label raises here
    if n and scan["bad_timestamp"] > MAX_BAD_TIMESTAMP_SHARE * n:
        raise ValueError(
            f"{path.name}: {scan['bad_timestamp']} of {n} timestamps do not match "
            f"{TIMESTAMP_FORMAT_2018!r}; check the file's date format"
        )
    if n and scan["hour_outside_12h"] > MAX_OUTSIDE_12H_SHARE * n:
        raise ValueError(
            f"{path.name}: {scan['hour_outside_12h']} of {n} timestamps have hour 0 or 13-23, which "
            "a 12-hour clock without AM/PM cannot produce; this looks like a 24-hour file, so the "
            "unfolding rule (hours 1-7 are afternoon) would be wrong"
        )
    usable = (code >= 0) & scan["ts_ok"]
    raw_codes = code
    usable_codes = np.where(usable, code, -1)
    idx = np.flatnonzero(usable)
    ts = scan["ts"]
    original = np.array(names, dtype=object)[code[idx]]
    cap_of = {x: caps.for_class(c) for x, c in zip(names, common_of, strict=True)}
    keep = select_rows(ts[idx] // DAY_SECONDS, original, ts[idx], cap_of.__getitem__, seed)
    selected = np.zeros(n, dtype=bool)
    selected[idx[keep]] = True
    sampled_codes = np.where(selected, code, -1)
    groups = pd.DataFrame({"day": ts[idx] // DAY_SECONDS, "label_original": original})
    available = groups.value_counts().rename("available")
    picked = groups[keep].value_counts().rename("sampled")

    frames, nonfinite_cols = [], Counter()
    nonfinite_codes = []
    offset = 0
    for batch in pf.iter_batches(batch_size=BATCH_ROWS, columns=FEATURES_2018):
        if offset >= n:
            break
        batch = batch.slice(0, n - offset)
        sel = selected[offset : offset + len(batch)]
        if sel.any():
            mat, finite = feature_matrix(batch.filter(pa.array(sel)))
            for j in np.flatnonzero(~np.isfinite(mat).all(axis=0)):
                nonfinite_cols[FEATURES_2018[j]] += int((~np.isfinite(mat[:, j])).sum())
            pos = np.flatnonzero(sel)
            nonfinite_codes.append(code[offset + pos[~finite]])
            pos = pos[finite]
            frame = pd.DataFrame(mat[finite], columns=FEATURES_2018)
            frame["start_ms"] = ts[offset + pos] * 1000
            frame["label_original"] = np.array(names, dtype=object)[code[offset + pos]]
            frames.append(frame)
        offset += len(batch)
    out = (
        pd.concat(frames, ignore_index=True)
        if frames
        else pd.DataFrame(columns=[*FEATURES_2018, "start_ms", "label_original"])
    )
    out["label"] = out["label_original"].map(dict(zip(names, common_of, strict=True)))
    out["source"] = path.name
    dropped = np.concatenate(nonfinite_codes) if nonfinite_codes else np.array([], dtype=np.int32)
    steps = {
        "raw": _count(raw_codes, common_of),
        "valid_timestamp": _count(usable_codes, common_of),
        "sampled": _count(sampled_codes, common_of),
        "finite": out["label"].value_counts().astype(int).to_dict(),
    }
    kept = out.groupby(["label_original"]).size()
    stats = {
        "file": path.name,
        "truncated_at_excel_limit": int(pf.metadata.num_rows) == EXCEL_ROW_LIMIT,
        "first_timestamp": _iso(ts[idx].min()) if len(idx) else None,
        "last_timestamp": _iso(ts[idx].max()) if len(idx) else None,
        "rows_in_file": int(pf.metadata.num_rows),
        "rows_read": int(n),
        "header_rows": scan["header_rows"],
        "missing_label": scan["missing_label"],
        "bad_timestamp": scan["bad_timestamp"],
        "file_date": None if expected is None else expected.isoformat(),
        "wrong_date": scan["wrong_date"],
        "wrong_date_by_date": scan["wrong_date_by_date"],
        "hour_outside_12h": scan["hour_outside_12h"],
        "raw_hour_histogram": scan["raw_hour_histogram"],
        "ambiguous_hour_rows": scan["ambiguous_hour_rows"],
        "nonfinite_dropped": len(dropped),
        "nonfinite_by_column": dict(nonfinite_cols),
        "rows_kept": len(out),
        "steps": {k: {a: int(b) for a, b in v.items()} for k, v in steps.items()},
        "groups": [
            {
                "day": str(pd.Timestamp(int(d) * DAY_SECONDS, unit="s").date()),
                "label_original": lab,
                "label": common_label(lab),
                "cap": cap_of[lab],
                "available": int(av),
                "sampled": int(picked.get((d, lab), 0)),
            }
            for (d, lab), av in available.items()
        ],
        "kept_by_original_label": {str(k): int(v) for k, v in kept.items()},
    }
    return out, stats


def load_cse2018(
    data_dir: str | Path,
    caps: Caps | None = None,
    seed: int = 42,
    max_rows: int | None = None,
    only: list[str] | None = None,
) -> tuple[pd.DataFrame, dict]:
    """Every finished day file of data_dir -> (one frame, report). Files are read one at a time,
    each keeping at most the capped sample, so memory is bounded by the sample, not the dataset.
    `max_rows`: read only the first rows of every file (smoke tests)."""
    caps = caps or Caps()
    files = list_files(data_dir, only)
    frames, per_file = [], []
    for path in files:
        frame, stats = load_file(path, caps, seed, max_rows)
        frames.append(frame)
        per_file.append(stats)
    df = pd.concat(frames, ignore_index=True)
    steps: dict[str, Counter] = {}
    for s in per_file:
        for step, counts in s["steps"].items():
            steps.setdefault(step, Counter()).update(counts)
    report = {
        "dataset": "CSE-CIC-IDS2018 (Processed Traffic Data for ML Algorithms)",
        "timestamp_format": TIMESTAMP_FORMAT_2018,
        "timestamp_note": "as published: the dataset's own clock and timezone, not converted; "
        "1 s resolution; the hour is a 12-hour clock without AM/PM and is unfolded (hours 1-7 + "
        "12 h, 8-12 unchanged); start_ms = unfolded seconds x 1000 read as UTC",
        "timestamp_rule": "hours 1-7 are afternoon (+12 h), 8-12 stay (12 = noon); hour 0 and "
        "13-23 rows are dropped (hour_outside_12h); rows whose date is not the file name's day are "
        "dropped (wrong_date)",
        "ambiguous_hour_rows": {
            h: sum(int(f["ambiguous_hour_rows"][h]) for f in per_file) for h in ("6", "7")
        },
        "wrong_date_rows": sum(int(f["wrong_date"]) for f in per_file),
        "caps": caps.as_dict(),
        "caps_scope": "per (day, original label), before the Infinity/NaN drop",
        "seed": seed,
        "max_rows_per_file": max_rows,
        "files": per_file,
        "truncated_at_excel_limit": [f["file"] for f in per_file if f["truncated_at_excel_limit"]],
        "n_features": len(FEATURES_2018),
        "steps": {k: {a: int(b) for a, b in sorted(v.items())} for k, v in steps.items()},
        "rows_total": len(df),
    }
    return df, report
