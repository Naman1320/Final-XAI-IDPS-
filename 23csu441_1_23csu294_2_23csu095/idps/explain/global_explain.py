"""Global feature importance: mean |SHAP| per class over a sample of flows."""

import numpy as np
import pandas as pd

from idps.explain._common import DEFAULT_SEED, as_frame, class_names, jfloat, sample_rows
from idps.explain.shap_explain import Explainer


def global_importance(explainer: Explainer, data: pd.DataFrame, sample: int = 500,
                      seed: int = DEFAULT_SEED) -> dict:
    """Mean |SHAP| of every feature for every class, as JSON-serialisable data.

    Each class's list is sorted by importance, largest first. The sample is random (seeded),
    over all flows, whatever their true class. Values are in the explainer's output space.
    """
    X = sample_rows(as_frame(explainer.bundle, data), sample, seed)
    values, _ = explainer.shap_values(X)
    mean_abs = np.abs(values).mean(axis=0)  # (features, classes)
    names = class_names(explainer.bundle)

    def ranked(vec):
        order = np.argsort(-vec, kind="stable")
        return [{"feature": explainer.features[i], "importance": jfloat(vec[i])} for i in order]

    return {
        "method": "mean_abs_shap",
        "output_space": explainer.output_space,
        "n_samples": len(X),
        "classes": {name: ranked(mean_abs[:, c]) for c, name in enumerate(names)},
        "overall": ranked(mean_abs.mean(axis=1)),
    }


def save_summary_plot(importance: dict, path: str, top_n: int = 10) -> None:
    """Bar charts of the top features per class (one panel per class) saved to `path`.

    Uses matplotlib's Agg canvas directly, so it works with no display."""
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    classes = importance["classes"]
    cols = min(3, len(classes))
    rows = -(-len(classes) // cols)
    fig = Figure(figsize=(5.5 * cols, 3.6 * rows), layout="constrained")
    FigureCanvasAgg(fig)
    for ax, (name, items) in zip(fig.subplots(rows, cols, squeeze=False).ravel(),
                                 classes.items(), strict=False):
        top = items[:top_n][::-1]
        ax.barh([t["feature"] for t in top], [t["importance"] for t in top])
        ax.set_title(name)
        ax.set_xlabel(f"mean |SHAP| ({importance['output_space']})")
    for ax in fig.axes[len(classes):]:
        ax.set_visible(False)
    fig.savefig(path, dpi=120)
