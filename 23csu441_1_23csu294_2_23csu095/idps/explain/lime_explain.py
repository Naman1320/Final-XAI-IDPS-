"""LIME explanations (on demand, for comparison with SHAP).

Same record shape as the SHAP `Explainer.explain` so the dashboard can show either. LIME fits a
local linear model on perturbed copies of the flow, in PROBABILITY space: `contribution` is that
model's weight for the feature (not additive in the SHAP sense) and `base_value` is its
intercept. Results are stochastic, so each call is reseeded: the same flow, background and seed
always give the same explanation. Slow compared with TreeExplainer (about `num_samples`
model evaluations per flow).
"""

import numpy as np
import pandas as pd
from lime.lime_tabular import LimeTabularExplainer
from sklearn.utils import check_random_state

from idps.detect.bundle import Bundle
from idps.explain._common import DEFAULT_SEED, as_frame, class_names, make_record


class LimeExplainer:
    def __init__(self, bundle: Bundle, background: pd.DataFrame, *, num_samples: int = 1000,
                 seed: int = DEFAULT_SEED):
        if background is None or len(background) == 0:
            raise ValueError("LIME needs a background sample to learn feature distributions")
        self.bundle = bundle
        self.features = list(bundle.features)
        self.num_samples = num_samples
        self.seed = seed
        self._lime = LimeTabularExplainer(
            as_frame(bundle, background).to_numpy(), feature_names=self.features,
            class_names=class_names(bundle), mode="classification",
            discretize_continuous=True, random_state=seed)

    def _predict(self, a: np.ndarray) -> np.ndarray:
        return self.bundle.model.predict_proba(pd.DataFrame(a, columns=self.features))

    def explain(self, data, top_k: int = 5) -> list[dict]:
        X = as_frame(self.bundle, data)
        out = []
        for i in range(len(X)):
            row = X.iloc[i].to_numpy()
            proba = self._predict(row[None, :])[0]
            c = int(np.argmax(proba))
            self._lime.random_state = check_random_state(self.seed)  # reseed: per-flow determinism
            exp = self._lime.explain_instance(
                row, self._predict, labels=(c,), num_features=len(self.features),
                num_samples=self.num_samples)
            contrib = np.zeros(len(self.features))
            for idx, w in exp.as_map()[c]:
                contrib[idx] = w
            intercept = exp.intercept[c]
            out.append(make_record("lime", self.bundle, self.features, row, proba, c, intercept,
                                   contrib, "probability", top_k))
        return out


def lime_explain(bundle: Bundle, row, background: pd.DataFrame, num_features: int = 5, *,
                 num_samples: int = 1000, seed: int = DEFAULT_SEED) -> dict:
    """Explain one flow (dict, Series or one-row frame) with LIME; returns one record."""
    records = LimeExplainer(bundle, background, num_samples=num_samples,
                            seed=seed).explain(row, top_k=num_features)
    if len(records) != 1:
        raise ValueError(f"lime_explain takes one flow, got {len(records)}")
    return records[0]
