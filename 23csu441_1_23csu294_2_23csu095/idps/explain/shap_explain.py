"""Per-alert SHAP explanations.

Build one `Explainer` per loaded bundle and reuse it; construction is the slow part.

Which explainer, and what the numbers mean (`output_space` in every record):
- XGBoost, RandomForest: shap.TreeExplainer (fast, exact). XGBoost values are in the model's
  margin space (log-odds), base_value + sum(all contributions) = the raw margin of the predicted
  class. RandomForest values are in probability space: base + sum(all) = predicted probability.
- MLP: shap.KernelExplainer on predict_proba with a small background sample (SLOW PATH:
  roughly `nsamples` model evaluations per flow, tens to hundreds of ms; and an approximation
  that depends on the background). Values are in probability space. It is not used for live
  alerts; use a tree model for those. KernelExplainer samples with numpy's global RNG, so
  we seed it (and restore the global state) per call to keep results reproducible.

Contributions are always toward the PREDICTED class. For multi-class models SHAP gives one set
of values per class and we take the predicted class's. For a binary XGBoost, SHAP explains the
positive class only; the other class is its mirror image (negated values and base).
"""

import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from idps.detect.bundle import Bundle
from idps.explain._common import DEFAULT_SEED, as_frame, make_record


def _to_class_axis(values, expected, n_classes: int) -> tuple[np.ndarray, np.ndarray]:
    """Normalise SHAP output to values (n, features, classes) and base (classes,)."""
    if isinstance(values, list):  # older shap: list of (n, features), one per class
        values = np.stack(values, axis=-1)
    values = np.asarray(values, dtype=float)
    base = np.atleast_1d(np.asarray(expected, dtype=float))
    if values.ndim == 2:  # single output: binary XGBoost explains the positive class
        if n_classes != 2:
            raise ValueError(f"unexpected single-output SHAP values for {n_classes} classes")
        values = np.stack([-values, values], axis=-1)
        base = np.array([-base[0], base[0]])
    if values.shape[-1] != n_classes or base.shape[0] != n_classes:
        raise ValueError(f"SHAP output shape {values.shape}/{base.shape} does not match "
                         f"{n_classes} classes")
    return values, base


class Explainer:
    """SHAP explainer for a model bundle.

    `background` (a frame containing the model features) is required for the MLP and ignored
    by tree models. `kernel_samples` is KernelExplainer's nsamples (MLP only).
    """

    def __init__(self, bundle: Bundle, background: pd.DataFrame | None = None, *,
                 background_size: int = 20, kernel_samples: int = 200, seed: int = DEFAULT_SEED):
        self.bundle = bundle
        self.features = list(bundle.features)
        self.n_classes = len(bundle.label_encoder.classes_)
        self.kernel_samples = kernel_samples
        self.seed = seed
        model = bundle.model
        if isinstance(model, XGBClassifier):
            self.kind, self.output_space = "tree", "log_odds"
            self._explainer = shap.TreeExplainer(model)
        elif isinstance(model, RandomForestClassifier):
            self.kind, self.output_space = "tree", "probability"
            self._explainer = shap.TreeExplainer(model)
        elif bundle.model_name == "mlp" or hasattr(model, "predict_proba"):
            if background is None or len(background) == 0:
                raise ValueError("the MLP explainer needs a background sample (KernelExplainer)")
            self.kind, self.output_space = "kernel", "probability"
            bg = as_frame(bundle, background)
            if len(bg) > background_size:
                bg = bg.sample(n=background_size, random_state=seed)
            self._explainer = shap.KernelExplainer(
                lambda a: bundle.model.predict_proba(
                    pd.DataFrame(a, columns=self.features)), bg.to_numpy())
        else:
            raise TypeError(f"no SHAP explainer for {type(model).__name__}")

    def shap_values(self, data) -> tuple[np.ndarray, np.ndarray]:
        """(values (n, features, classes), base (classes,)) in this explainer's output space."""
        X = as_frame(self.bundle, data)
        if self.kind == "tree":
            raw = self._explainer.shap_values(X, check_additivity=False)
        else:
            state = np.random.get_state()
            np.random.seed(self.seed)
            try:
                raw = self._explainer.shap_values(X.to_numpy(), nsamples=self.kernel_samples,
                                                  silent=True)
            finally:
                np.random.set_state(state)
        return _to_class_axis(raw, self._explainer.expected_value, self.n_classes)

    def explain(self, data, top_k: int = 5) -> list[dict]:
        """One JSON-serialisable record per flow (always a list, also for a single row).

        Record: method, predicted_class, confidence (model probability), base_value,
        output_space, top_features = [{feature, value, contribution}] sorted by |contribution|.
        """
        X = as_frame(self.bundle, data)
        if X.empty:
            return []
        proba = self.bundle.predict_proba(X)
        values, base = self.shap_values(X)
        out = []
        for i in range(len(X)):
            c = int(np.argmax(proba[i]))
            out.append(make_record("shap", self.bundle, self.features, X.iloc[i].to_numpy(),
                                   proba[i], c, base[c], values[i, :, c], self.output_space,
                                   top_k))
        return out
