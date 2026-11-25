"""Attach dataset labels (CIC-IDS2017 label CSVs) to flows extracted from the same PCAPs.

Matching rule (details and limits in docs/features.md):
  a flow matches a label row when they have the same protocol and the same pair of
  (ip, port) endpoints in EITHER direction, and their time windows overlap, where the label
  window is [start - tolerance, end + ts_resolution + tolerance]: most CIC-IDS2017 files only
  have minute-resolution timestamps, so the true start is anywhere in [ts, ts + 60 s) and the
  window widens forward by `ts_resolution_ms` (a missing column counts as 0). If several rows
  match, the one with the largest overlap wins (ties: earliest start); if the candidates
  disagree on the label the flow is also marked ambiguous.
"""

import warnings
from collections.abc import Iterable
from pathlib import Path

import numpy as np
import pandas as pd

UNMATCHED = "UNMATCHED"
# Every class of the CIC-IDS2017 label files (what the trainer's data can contain), plus BENIGN.
# The SOC accepts only these as an analyst's corrected class.
CIC_CLASSES = (
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
    "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
    "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS",
)
LABEL_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms", "end_ms", "label"]
# Optional extra column written by normalize_cic_labels: how coarse the row's timestamp is.
RESOLUTION_COLUMN = "ts_resolution_ms"
MINUTE_MS, SECOND_MS = 60_000, 1_000

# CIC-IDS2017 "TrafficLabelling" CSV headers (note the leading spaces in the real files).
_CIC_RENAME = {
    "source ip": "src_ip", "source port": "src_port",
    "destination ip": "dst_ip", "destination port": "dst_port",
    "protocol": "protocol", "timestamp": "timestamp",
    "flow duration": "flow_duration_us", "label": "label",
}


# Lab working hours: in a file written on a 12-hour clock without AM/PM, times before this
# hour are afternoon times (1:30 means 13:30).
AFTERNOON_BEFORE_HOUR = 8


def parse_cic_timestamps(values: pd.Series, twelve_hour: bool | None = None) -> pd.Series:
    """Parse CIC-IDS2017 timestamps: day first ("3/7/2017" is 3 July), with or without seconds.

    Some files use a 12-hour clock without AM/PM. `twelve_hour=None` detects that per file
    (no hour above 12 means 12-hour); then hours before AFTERNOON_BEFORE_HOUR get +12 h.
    Unparseable values become NaT. This is a heuristic: always check the match rate.
    """
    text = values.astype(str).str.strip()
    ts = pd.to_datetime(text, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    ts = ts.where(ts.notna(), pd.to_datetime(text, format="%d/%m/%Y %H:%M", errors="coerce"))
    hours = ts.dt.hour
    if twelve_hour is None:
        twelve_hour = bool(ts.notna().any()) and int(hours.max()) <= 12
    if twelve_hour:
        afternoon = hours.between(1, AFTERNOON_BEFORE_HOUR - 1)
        ts = ts + pd.to_timedelta(afternoon.astype(int) * 12, unit="h")
    return ts


def normalize_cic_labels(df: pd.DataFrame, utc_offset_hours: float = 0.0,
                         twelve_hour: bool | None = None) -> pd.DataFrame:
    """Turn ONE raw CIC-IDS2017 label CSV frame into the LABEL_COLUMNS layout.

    Call it once per CSV file (the 12-hour-clock detection is per file).
    `utc_offset_hours` is the timezone the CSV timestamps are written in (the CIC machines
    used local time, roughly UTC-3/-4); it is subtracted to get UTC epoch milliseconds,
    which is what extracted flows use. Check it against one known flow before trusting it.
    Rows with an unparseable timestamp, port or protocol are dropped (with a warning).
    The result also has `ts_resolution_ms` per row: 60000 if the raw timestamp has no seconds,
    1000 if it does.
    """
    df = df.rename(columns=lambda c: _CIC_RENAME.get(str(c).strip().lower(), str(c).strip()))
    ts = parse_cic_timestamps(df["timestamp"], twelve_hour)
    # "7/7/2017 9:03" has one colon (minute resolution), "7/7/2017 9:03:41" has two.
    resolution = np.where(df["timestamp"].astype(str).str.count(":") >= 2, SECOND_MS, MINUTE_MS)
    resolution = pd.Series(resolution, index=df.index)
    nums = {c: pd.to_numeric(df[c], errors="coerce")
            for c in ("src_port", "dst_port", "protocol", "flow_duration_us")}
    ok = ts.notna()
    for v in nums.values():
        ok &= v.notna()
    if (~ok).any():
        warnings.warn(f"dropped {int((~ok).sum())} label rows with unparseable values",
                      stacklevel=2)
    ts, df, resolution = ts[ok], df[ok], resolution[ok]
    nums = {c: v[ok].astype("int64") for c, v in nums.items()}
    start = (ts - pd.Timestamp("1970-01-01")) // pd.Timedelta(milliseconds=1)
    start = start - int(utc_offset_hours * 3_600_000)
    # A few CIC rows have a negative Flow Duration; treat those as zero-length.
    duration_ms = nums["flow_duration_us"].clip(lower=0) // 1000
    out = pd.DataFrame({
        "src_ip": df["src_ip"].astype(str).str.strip(), "src_port": nums["src_port"],
        "dst_ip": df["dst_ip"].astype(str).str.strip(), "dst_port": nums["dst_port"],
        "protocol": nums["protocol"],
        "start_ms": start.astype("int64"),
        "end_ms": (start + duration_ms).astype("int64"),
        # The CSVs are Windows-1252: "Web Attack – Brute Force" has an en dash (byte 0x96),
        # which reads as "\x96" with latin-1. Store a plain hyphen instead.
        "label": df["label"].astype(str).str.replace("\x96", "-", regex=False)
                 .str.replace("–", "-", regex=False).str.strip(),
    })
    out[RESOLUTION_COLUMN] = resolution.astype("int64").to_numpy()
    return out[[*LABEL_COLUMNS, RESOLUTION_COLUMN]].reset_index(drop=True)


def load_cic_labels(paths: Iterable[str | Path], utc_offset_hours: float = 0.0) -> pd.DataFrame:
    """Read one or more CIC-IDS2017 label CSVs, normalising each file on its own."""
    frames = []
    for p in paths:
        raw = pd.read_csv(p, encoding="latin-1", skipinitialspace=True, low_memory=False)
        raw = raw.rename(columns=lambda c: str(c).strip())
        # Some CIC files repeat a column name (e.g. "Fwd Header Length"); keep the first.
        raw = raw.loc[:, ~raw.columns.duplicated()]
        raw = raw.dropna(subset=[c for c in raw.columns if c.lower() in
                                 ("source ip", "destination ip", "timestamp", "label")])
        frames.append(normalize_cic_labels(raw, utc_offset_hours))
    if not frames:
        return pd.DataFrame(columns=[*LABEL_COLUMNS, RESOLUTION_COLUMN])
    return pd.concat(frames, ignore_index=True)


def _canonical_key(df: pd.DataFrame) -> pd.Series:
    # Ports and protocol go through int64 first, so 80 and 80.0 give the same key.
    port = lambda c: df[c].astype("int64").astype(str)
    a = df["src_ip"].astype(str) + "|" + port("src_port")
    b = df["dst_ip"].astype(str) + "|" + port("dst_port")
    lo, hi = a.where(a <= b, b), b.where(a <= b, a)
    return df["protocol"].astype("int64").astype(str) + "#" + lo + "#" + hi


def join_labels(flows_df: pd.DataFrame, labels_df: pd.DataFrame,
                tolerance_ms: int = 1000) -> pd.DataFrame:
    """Return a copy of flows_df plus `label`, `label_matched` and `label_ambiguous`.

    flows_df needs the to_frame() identity columns; labels_df needs LABEL_COLUMNS (see
    normalize_cic_labels; an optional `ts_resolution_ms` column widens each label window
    forward, a missing one counts as 0). Unmatched flows get label == UNMATCHED and label_matched False.
    Use summarize_matches() on the result for the match rate.
    """
    missing = set(LABEL_COLUMNS) - set(labels_df.columns)
    if missing:
        raise ValueError(f"labels_df is missing columns: {sorted(missing)}")
    flows = flows_df.reset_index(drop=True).copy()
    lab = labels_df[LABEL_COLUMNS].reset_index(drop=True).copy()
    resolution = (labels_df[RESOLUTION_COLUMN].reset_index(drop=True).fillna(0).astype("int64")
                  if RESOLUTION_COLUMN in labels_df.columns else 0)
    flows["_key"] = _canonical_key(flows)
    flows["_row"] = np.arange(len(flows))
    lab["_key"] = _canonical_key(lab)
    lab["_lo"] = lab["start_ms"] - tolerance_ms
    lab["_hi"] = lab["end_ms"] + resolution + tolerance_ms

    pairs = flows[["_row", "_key", "start_ms", "end_ms"]].merge(
        lab[["_key", "_lo", "_hi", "start_ms", "label"]].rename(columns={"start_ms": "_lab_start"}),
        on="_key", how="inner")
    pairs = pairs[(pairs["start_ms"] <= pairs["_hi"]) & (pairs["end_ms"] >= pairs["_lo"])]
    pairs = pairs.assign(_overlap=np.minimum(pairs["end_ms"], pairs["_hi"])
                         - np.maximum(pairs["start_ms"], pairs["_lo"]))
    ambiguous = pairs.groupby("_row")["label"].nunique().gt(1)
    best = (pairs.sort_values(["_row", "_overlap", "_lab_start"], ascending=[True, False, True])
            .drop_duplicates("_row").set_index("_row")["label"])

    flows["label"] = flows["_row"].map(best).astype(object).fillna(UNMATCHED)
    flows["label_matched"] = flows["_row"].isin(best.index)
    flows["label_ambiguous"] = flows["_row"].map(ambiguous).astype(object).fillna(False).astype(bool)
    return flows.drop(columns=["_key", "_row"])


def summarize_matches(joined: pd.DataFrame) -> dict:
    """Match statistics for the output of join_labels()."""
    total = len(joined)
    matched = int(joined["label_matched"].sum())
    return {
        "flows": total,
        "matched": matched,
        "unmatched": total - matched,
        "match_rate": matched / total if total else 0.0,
        "ambiguous": int(joined["label_ambiguous"].sum()),
        "per_label": joined["label"].value_counts().to_dict(),
    }


def training_rows(joined: pd.DataFrame) -> pd.DataFrame:
    """Only the rows that are safe to train on: matched and not ambiguous.

    Use this instead of filtering on `label` yourself: UNMATCHED is a string label too, and
    a filter like `label != "BENIGN"` would count it as an attack.
    """
    keep = joined["label_matched"] & ~joined["label_ambiguous"]
    return joined[keep].reset_index(drop=True)


def training_xy(joined: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """(X, y) for model training: MODEL_FEATURES only (no times, IPs or match flags)."""
    from idps.features import MODEL_FEATURES

    rows = training_rows(joined)
    return rows[MODEL_FEATURES], rows["label"]
