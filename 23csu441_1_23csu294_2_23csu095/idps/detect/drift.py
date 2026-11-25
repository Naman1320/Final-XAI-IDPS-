"""Drift: does live traffic still look like the training data?

At train time a sidecar `<model>.drift.json` records, per model feature, decile bin edges and the
share of training rows in each bin. The live sensor keeps a rolling window of the last N scored
flows (all of them, not just alerts), counts them into the same bins, and reports the Population
Stability Index (PSI) per feature:

    PSI = sum over bins of (live_share - train_share) * ln(live_share / train_share)

Common reading: < 0.1 ok, 0.1 to 0.25 watch, > 0.25 drift. Bin counts are updated incrementally
(a ring buffer of bin indexes), so adding a batch costs a few numpy calls, not a re-count of the
window.

The sidecar names the sha256 of the model it was made for. A sidecar of another model (a stale
file after a retrain) is refused: its numbers would describe the wrong training data.
"""

from __future__ import annotations

import json
import logging
import math
import threading
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

from idps.features import MODEL_FEATURES

log = logging.getLogger("idps.drift")

REFERENCE_FORMAT = 1
N_BINS = 10  # deciles
DEFAULT_WINDOW = 5000
# PSI on a handful of flows is noise; below this many the monitor says "warming up".
MIN_WINDOW = 200
WATCH_AT, DRIFT_AT = 0.1, 0.25
EPS = 1e-4  # an empty bin counts as this share, so the logarithm exists
TOP_N = 5
MAX_REASON = 300  # soc/api/routes/sensors.py DriftInfo.reason (mirrored)


def sidecar_path(model_path: str | Path) -> Path:
    return Path(f"{model_path}.drift.json")


def level_for(psi_max: float) -> str:
    if psi_max > DRIFT_AT:
        return "drift"
    if psi_max >= WATCH_AT:
        return "watch"
    return "ok"


def clean(text: str) -> str:
    """Without control / format characters (the SOC refuses them; mirrors idps.live.text, which
    is not imported here because importing idps.live pulls in the whole sensor)."""
    return "".join(c for c in text if unicodedata.category(c) not in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


def _bin_index(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    # bin 0 is x <= edges[0]; bin len(edges) is x > edges[-1]
    return np.searchsorted(edges, values, side="left")


def build_reference(df: pd.DataFrame, model_sha256: str,
                    features: list[str] | None = None) -> dict:
    """Decile edges and training shares per feature, from the training rows `df`."""
    features = list(features or MODEL_FEATURES)
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(f"training rows are missing feature column(s): {missing}")
    out: dict[str, dict] = {}
    for name in features:
        values = pd.to_numeric(df[name], errors="coerce").to_numpy(dtype=float)
        values = values[np.isfinite(values)]
        if values.size == 0:
            raise ValueError(f"feature {name} has no finite training values")
        edges = np.unique(np.quantile(values, np.linspace(0, 1, N_BINS + 1)[1:-1]))
        counts = np.bincount(_bin_index(values, edges), minlength=len(edges) + 1)
        out[name] = {"edges": [float(e) for e in edges],
                     "proportions": [float(c) / values.size for c in counts]}
    return {"format": REFERENCE_FORMAT, "model_sha256": model_sha256.lower(),
            "created_at": datetime.now(UTC).isoformat(), "rows": len(df),
            "bins": N_BINS, "features": out}


def reference_text(df: pd.DataFrame, model_sha256: str, features: list[str] | None = None) -> str:
    return json.dumps(build_reference(df, model_sha256, features), indent=1, sort_keys=True)


def write_reference(model_path: str | Path, df: pd.DataFrame, model_sha256: str,
                    features: list[str] | None = None) -> Path:
    """Write `<model>.drift.json`. `features`: the model's own feature list (a model trained
    without some features has none of those in its data)."""
    path = sidecar_path(model_path)
    path.write_text(reference_text(df, model_sha256, features))
    return path


def _numbers(values: object) -> np.ndarray | None:
    """`values` as a finite float array, or None."""
    if not isinstance(values, list) or any(isinstance(v, bool) or not isinstance(v, int | float)
                                           for v in values):
        return None
    try:
        arr = np.asarray(values, dtype=float)
    except (OverflowError, ValueError):
        return None
    return arr if np.isfinite(arr).all() else None


def read_reference(path: str | Path) -> dict:
    """The sidecar's content; ValueError if it is not a well-formed reference (finite numbers,
    strictly increasing edges, shares in [0, 1] one more than the edges)."""
    try:
        ref = json.loads(Path(path).read_text())
    except RecursionError as exc:
        raise ValueError(f"{path} is not valid JSON") from exc
    if not isinstance(ref, dict) or ref.get("format") != REFERENCE_FORMAT \
            or not isinstance(ref.get("features"), dict) or not ref["features"] \
            or not isinstance(ref.get("model_sha256"), str):
        raise ValueError(f"{path} is not a drift reference (format {REFERENCE_FORMAT})")
    for name, f in ref["features"].items():
        edges = _numbers(f.get("edges") if isinstance(f, dict) else None)
        props = _numbers(f.get("proportions") if isinstance(f, dict) else None)
        if (edges is None or props is None or len(props) != len(edges) + 1
                or (np.diff(edges) <= 0).any() or (props < 0).any() or (props > 1).any()):
            raise ValueError(f"{path}: feature {name} has inconsistent bins")
    return ref


def psi(expected: np.ndarray, actual: np.ndarray) -> float:
    """PSI of two share vectors (same length); both are clipped at EPS first."""
    e = np.clip(np.asarray(expected, dtype=float), EPS, None)
    a = np.clip(np.asarray(actual, dtype=float), EPS, None)
    return float(np.sum((a - e) * np.log(a / e)))


class DriftMonitor:
    """Rolling-window PSI against a reference. update() and report() are thread-safe."""

    def __init__(self, reference: dict, window: int = DEFAULT_WINDOW,
                 min_window: int = MIN_WINDOW) -> None:
        if window < 1:
            raise ValueError("window must be at least 1")
        self.reference_sha256 = str(reference["model_sha256"])
        self.names = list(reference["features"])
        self._edges = [np.asarray(reference["features"][n]["edges"], dtype=float)
                       for n in self.names]
        self._expected = [np.asarray(reference["features"][n]["proportions"], dtype=float)
                          for n in self.names]
        self.window = window
        self.min_window = min(min_window, window)
        width = max(len(e) for e in self._expected)
        self._counts = np.zeros((len(self.names), width), dtype=np.int64)
        self._ring = np.zeros((window, len(self.names)), dtype=np.int16)
        self._next = 0  # where the next row goes
        self._size = 0
        self._lock = threading.Lock()

    def update(self, frame: pd.DataFrame) -> None:
        """Count the rows of `frame` (needs every reference feature as a column)."""
        if frame.empty:
            return
        cols = []
        for name, edges in zip(self.names, self._edges, strict=True):
            v = pd.to_numeric(frame[name], errors="coerce").to_numpy(dtype=float)
            # A non-finite value cannot be binned; count it in the last bin rather than skip
            # the row, so every flow in the window has one bin per feature.
            v = np.where(np.isfinite(v), v, np.inf)
            cols.append(_bin_index(v, edges))
        idx = np.stack(cols, axis=1).astype(np.int16)
        if len(idx) > self.window:
            idx = idx[-self.window:]
        with self._lock:
            n = len(idx)
            slots = (self._next + np.arange(n)) % self.window
            free = self.window - self._size  # slots not yet used; the rest are overwritten
            if n > free:  # the oldest rows leave the window
                gone = self._ring[slots[free:]]
                for j in range(len(self.names)):
                    self._counts[j] -= np.bincount(gone[:, j], minlength=self._counts.shape[1])
            self._ring[slots] = idx
            for j in range(len(self.names)):
                self._counts[j] += np.bincount(idx[:, j], minlength=self._counts.shape[1])
            self._next = int((self._next + n) % self.window)
            self._size = min(self.window, self._size + n)

    def psi_by_feature(self) -> dict[str, float]:
        with self._lock:
            size, counts = self._size, self._counts.copy()
        if size == 0:
            return {}
        out = {}
        for j, name in enumerate(self.names):
            k = len(self._expected[j])
            out[name] = psi(self._expected[j], counts[j, :k] / size)
        return out

    def report(self) -> dict:
        with self._lock:
            size = self._size
        base = {"reference_sha256": self.reference_sha256, "window": size}
        if size < self.min_window:
            return {"level": "unknown", "reason": f"warming up: {size} of {self.min_window} "
                                                  "flows seen", **base}
        by = self.psi_by_feature()
        top = sorted(by.items(), key=lambda kv: -kv[1])[:TOP_N]
        psi_max = top[0][1]
        if not math.isfinite(psi_max):  # cannot happen with EPS; belt and braces
            return {"level": "unknown", "reason": "non-finite PSI", **base}
        return {**base, "psi_max": round(psi_max, 6), "level": level_for(psi_max),
                "top": [{"feature": f, "psi": round(v, 6)} for f, v in top]}


class NoDrift:
    """Stands in when there is no usable reference: always reports level 'unknown'."""

    def __init__(self, reason: str) -> None:
        self.reason = clean(reason)[:MAX_REASON]  # fits the SOC's DriftInfo.reason

    def update(self, frame: pd.DataFrame) -> None:
        return

    def report(self) -> dict:
        return {"level": "unknown", "reason": self.reason}


def load_monitor(model_path: str | Path, model_sha256: str | None,
                 window: int = DEFAULT_WINDOW) -> DriftMonitor | NoDrift:
    """The monitor for the sidecar of `model_path`, or a NoDrift saying why there is none."""
    path = sidecar_path(model_path)
    if not path.exists():
        return NoDrift(f"no drift reference ({path.name}); create it with "
                       "'python -m idps.detect drift-reference'")
    try:
        ref = read_reference(path)
    except (OSError, ValueError) as exc:  # includes bad JSON
        return NoDrift(f"unreadable drift reference: {exc}")
    if not model_sha256 or str(ref.get("model_sha256", "")).lower() != model_sha256.lower():
        return NoDrift("drift reference belongs to a different model (sha256 mismatch); "
                       "re-create it with 'python -m idps.detect drift-reference'")
    missing = [n for n in ref["features"] if n not in MODEL_FEATURES]
    if missing:
        return NoDrift(f"drift reference has unknown feature(s): {missing[:3]}")
    try:
        return DriftMonitor(ref, window)
    except Exception as exc:  # noqa: BLE001  a bad sidecar must never stop the sensor
        return NoDrift(f"drift reference cannot be used: {type(exc).__name__}")
