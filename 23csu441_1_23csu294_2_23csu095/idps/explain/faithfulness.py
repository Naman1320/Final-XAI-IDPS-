"""Deletion test: do the features an explanation names actually drive the prediction?

For N sample flows: take the model's predicted class and its probability p0. Replace the
explanation's top-k features with a baseline (the median of a background sample) and measure
the drop p0 - p1 in that class's probability. Compare with replacing k RANDOM features
(seeded; averaged over `repeats` draws). A faithful explanation causes a clearly larger drop
than random features. Done for SHAP and for LIME on the same flows.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd

from idps.detect.bundle import Bundle
from idps.explain._common import DEFAULT_SEED, as_frame, jfloat, sample_rows
from idps.explain.lime_explain import LimeExplainer
from idps.explain.shap_explain import Explainer


def _prob_of(bundle: Bundle, X: pd.DataFrame, classes: np.ndarray) -> np.ndarray:
    return bundle.predict_proba(X)[np.arange(len(X)), classes]


def _delete(X: pd.DataFrame, masks: np.ndarray, baseline: np.ndarray) -> pd.DataFrame:
    """Copy of X with masked cells (bool, same shape) replaced by the baseline."""
    return pd.DataFrame(np.where(masks, baseline[None, :], X.to_numpy()), columns=X.columns)


def _top_masks(contrib: np.ndarray, k: int) -> np.ndarray:
    masks = np.zeros(contrib.shape, dtype=bool)
    idx = np.argsort(-np.abs(contrib), axis=1, kind="stable")[:, :k]
    np.put_along_axis(masks, idx, True, axis=1)
    return masks


def _lime_contrib(lime: LimeExplainer, X: pd.DataFrame) -> np.ndarray:
    """LIME weight of every feature toward the predicted class, shape (n, features)."""
    pos = {f: j for j, f in enumerate(lime.features)}
    out = np.zeros((len(X), len(pos)))
    for i in range(len(X)):
        for t in lime.explain(X.iloc[[i]], top_k=len(pos))[0]["top_features"]:
            out[i, pos[t["feature"]]] = t["contribution"] or 0.0
    return out


def faithfulness(bundle: Bundle, data: pd.DataFrame, background: pd.DataFrame | None = None, *,
                 n: int = 100, k: int = 5, repeats: int = 20, seed: int = DEFAULT_SEED,
                 include_lime: bool = True, lime_samples: int = 1000,
                 explainer: Explainer | None = None, model_sha256: str | None = None) -> dict:
    """Run the deletion test; returns a JSON-serialisable results dict.

    `data`: flows to sample from. `background`: where baseline medians (and the MLP/LIME
    background) come from; defaults to `data`. Ideally a TRAINING-like sample.
    """
    X_all = as_frame(bundle, data)
    bg = as_frame(bundle, background) if background is not None else X_all
    k = min(k, len(bundle.features))
    X = sample_rows(X_all, n, seed)
    baseline = bg.median().to_numpy()
    proba = bundle.predict_proba(X)
    classes = proba.argmax(axis=1)
    p0 = proba[np.arange(len(X)), classes]
    rng = np.random.default_rng(seed)

    # Random baseline: same draws for every method, so methods are compared fairly.
    rand_drops = np.zeros((repeats, len(X)))
    for r in range(repeats):
        masks = np.zeros(X.shape, dtype=bool)
        for i in range(len(X)):
            masks[i, rng.choice(X.shape[1], size=k, replace=False)] = True
        p1 = _prob_of(bundle, _delete(X, masks, baseline), classes)
        rand_drops[r] = p0 - p1
    rand_per_flow = rand_drops.mean(axis=0)
    rand_means = rand_drops.mean(axis=1)  # one number per repeat

    explainer = explainer or Explainer(bundle, background=bg)
    values, _ = explainer.shap_values(X)
    contribs = {"shap": values[np.arange(len(X)), :, classes]}
    if include_lime:
        lime = LimeExplainer(bundle, bg, num_samples=lime_samples, seed=seed)
        contribs["lime"] = _lime_contrib(lime, X)

    results = {}
    for name, contrib in contribs.items():
        masks = _top_masks(contrib, k)
        Xd = _delete(X, masks, baseline)
        p1 = _prob_of(bundle, Xd, classes)
        drop = p0 - p1
        results[name] = {
            "mean_drop": jfloat(drop.mean()),
            "median_drop": jfloat(np.median(drop)),
            "mean_confidence_after": jfloat(p1.mean()),
            "label_flip_rate": jfloat((bundle.predict_proba(Xd).argmax(axis=1) != classes).mean()),
            "share_flows_beating_random": jfloat((drop > rand_per_flow).mean()),
            "ratio_to_random": jfloat(drop.mean() / rand_per_flow.mean())
            if rand_per_flow.mean() > 1e-12 else None,
        }
    return {
        "config": {"n_flows": len(X), "top_k": k, "random_repeats": repeats, "seed": seed,
                   "model": bundle.model_name, "model_sha256": model_sha256,
                   "baseline": "median of background sample",
                   "background_rows": len(bg), "lime_samples": lime_samples if include_lime else None,
                   "classes_explained": {str(c): int((classes == i).sum()) for i, c in
                                         enumerate(bundle.label_encoder.classes_)}},
        "mean_confidence_before": jfloat(p0.mean()),
        "random": {"mean_drop": jfloat(rand_per_flow.mean()),
                   "std_of_mean_across_repeats": jfloat(rand_means.std()),
                   "median_drop": jfloat(np.median(rand_per_flow))},
        "methods": results,
    }


def write_json(results: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2))
