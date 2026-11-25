"""Flow-to-feature-vector extraction shared by training and live detection."""

import json
from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from idps.capture.flow import Flow

# Identity and timing columns: needed to join labels and to report alerts, not model inputs
# (except dst_port and protocol, which are listed in MODEL_FEATURES too).
ID_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms", "end_ms"]

_STAT = ("min", "max", "mean", "std")
STAT_FEATURES = (
    ["duration_ms", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
     "bytes_per_s", "packets_per_s", "down_up_ratio"]
    + [f"{p}_{s}" for p in ("pkt_len", "fwd_pkt_len", "bwd_pkt_len",
                            "iat", "fwd_iat", "bwd_iat") for s in _STAT]
    + [f"{f}_count" for f in ("syn", "fin", "rst", "psh", "ack", "urg", "cwr", "ece")]
)

# Everything to_frame() returns, in this exact order. Do not reorder: saved models rely on it.
FEATURE_COLUMNS: list[str] = ID_COLUMNS + STAT_FEATURES
# What a model should be trained on.
MODEL_FEATURES: list[str] = ["dst_port", "protocol"] + STAT_FEATURES


def _row(f: Flow) -> dict:
    duration = f.end_ms - f.start_ms
    seconds = duration / 1000.0
    packets = f.fwd_packets + f.bwd_packets
    total_bytes = f.fwd_bytes + f.bwd_bytes
    row = {c: getattr(f, c) for c in FEATURE_COLUMNS if hasattr(f, c)}
    row.update(
        duration_ms=duration,
        # Rates are 0 for flows shorter than 1 ms (single packets) rather than infinite.
        bytes_per_s=total_bytes / seconds if seconds > 0 else 0.0,
        packets_per_s=packets / seconds if seconds > 0 else 0.0,
        down_up_ratio=f.bwd_bytes / f.fwd_bytes if f.fwd_bytes else 0.0,
    )
    return row


def to_frame(flows: Iterable[Flow]) -> pd.DataFrame:
    """Flows -> DataFrame with exactly FEATURE_COLUMNS, in order (empty input gives 0 rows)."""
    rows = [_row(f) for f in flows]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


# --- Feature files carry how they were made -------------------------------------------------
# A model trained on NFStream features must not be fed scapy features (or other timeouts),
# so every feature file records its extractor settings, and readers can check them.

_META_KEY = b"idps"


def write_features(df: pd.DataFrame, path: str | Path, meta: dict) -> None:
    """Write a feature table with `meta` (extractor, timeouts, ...) stored alongside it.

    Parquet keeps it in the file's schema metadata; CSV gets a `<file>.meta.json` sidecar.
    """
    path = Path(path)
    if path.suffix == ".csv":
        df.to_csv(path, index=False)
        Path(f"{path}.meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        return
    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pa.Table.from_pandas(df, preserve_index=False)
    existing = table.schema.metadata or {}
    table = table.replace_schema_metadata(
        {**existing, _META_KEY: json.dumps(meta, sort_keys=True).encode()})
    pq.write_table(table, path)


def read_features(path: str | Path) -> tuple[pd.DataFrame, dict]:
    """Read a file written by write_features(); returns (frame, meta). Missing meta -> {}."""
    path = Path(path)
    if path.suffix == ".csv":
        side = Path(f"{path}.meta.json")
        meta = json.loads(side.read_text()) if side.exists() else {}
        return pd.read_csv(path), meta
    import pyarrow.parquet as pq

    table = pq.read_table(path)
    raw = (table.schema.metadata or {}).get(_META_KEY)
    return table.to_pandas(), json.loads(raw) if raw else {}


def check_same_extraction(train_meta: dict, live_meta: dict) -> None:
    """Raise if two feature sets were made with different extractor settings."""
    keys = ("extractor", "idle_timeout", "active_timeout", "feature_columns")
    diff = {k: (train_meta.get(k), live_meta.get(k)) for k in keys
            if train_meta.get(k) != live_meta.get(k)}
    if diff:
        raise ValueError(f"feature extraction settings differ (train, live): {diff}")


def extraction_meta(extractor: str, idle_timeout: float, active_timeout: float) -> dict:
    return {
        "extractor": extractor,
        "idle_timeout": int(idle_timeout),
        "active_timeout": int(active_timeout),
        "feature_columns": FEATURE_COLUMNS,
    }
