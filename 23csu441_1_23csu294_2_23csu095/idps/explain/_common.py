"""Shared helpers: input coercion, JSON-safe numbers, the common explanation record."""

import math

import numpy as np
import pandas as pd

from idps.detect.bundle import Bundle

DEFAULT_SEED = 0


def jfloat(x) -> float | None:
    """A plain Python float; NaN and infinities become None (they are not valid JSON)."""
    x = float(x)
    return x if math.isfinite(x) else None


def as_frame(bundle: Bundle, data) -> pd.DataFrame:
    """A dict, Series or DataFrame -> float DataFrame with exactly bundle.features, in order."""
    if isinstance(data, dict):
        data = pd.DataFrame([data])
    elif isinstance(data, pd.Series):
        data = data.to_frame().T
    elif not isinstance(data, pd.DataFrame):
        raise TypeError(f"expected a dict, Series or DataFrame, got {type(data).__name__}")
    missing = [c for c in bundle.features if c not in data.columns]
    if missing:
        raise ValueError(f"data is missing model feature column(s): {missing}")
    return data[bundle.features].astype(float).reset_index(drop=True)


def class_names(bundle: Bundle) -> list[str]:
    return [str(c) for c in bundle.label_encoder.classes_]


def make_record(method: str, bundle: Bundle, features: list[str], row: np.ndarray, proba: np.ndarray,
                class_idx: int, base: float, contrib: np.ndarray, output_space: str,
                top_k: int) -> dict:
    """The explanation record shared by SHAP and LIME. `contrib` has one value per feature,
    toward the predicted class; features are sorted by |contribution|, largest first."""
    order = np.argsort(-np.abs(contrib), kind="stable")[:top_k]
    return {
        "method": method,
        "predicted_class": class_names(bundle)[class_idx],
        "confidence": jfloat(proba[class_idx]),
        "base_value": jfloat(base),
        "output_space": output_space,
        "top_features": [{"feature": features[i], "value": jfloat(row[i]),
                          "contribution": jfloat(contrib[i])} for i in order],
    }


def sample_rows(df: pd.DataFrame, n: int, seed: int = DEFAULT_SEED) -> pd.DataFrame:
    """Up to n rows, chosen with a fixed seed (all rows if there are fewer)."""
    if len(df) <= n:
        return df.reset_index(drop=True)
    return df.sample(n=n, random_state=seed).reset_index(drop=True)
