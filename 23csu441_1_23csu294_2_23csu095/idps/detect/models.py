"""Model construction and training: XGBoost (main), RandomForest and MLP (baselines),
IsolationForest (anomaly detector, BENIGN-only).

Class imbalance is handled with weights computed from the TRAINING split only.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from idps.detect.data import BENIGN, SEED
from idps.features import MODEL_FEATURES

MODEL_NAMES = ("xgboost", "rf", "mlp")
# Share of BENIGN training rows the anomaly detector may flag; sets its threshold.
# ("auto" would flag about half of normal rows on low-variance data.)
ANOMALY_CONTAMINATION = 0.01


def select_features(drop: list[str] | tuple[str, ...] = ()) -> list[str]:
    """MODEL_FEATURES minus `drop` (for experiments such as leaving out dst_port)."""
    unknown = sorted(set(drop) - set(MODEL_FEATURES))
    if unknown:
        raise ValueError(f"cannot drop unknown feature(s) {unknown}; "
                         f"model features are {MODEL_FEATURES}")
    features = [f for f in MODEL_FEATURES if f not in set(drop)]
    if not features:
        raise ValueError("all features were dropped")
    return features


def balanced_sample_weights(y_encoded: np.ndarray) -> np.ndarray:
    """weight = n_rows / (n_classes * class_count), so every class counts equally in total."""
    counts = np.bincount(y_encoded)
    weights = len(y_encoded) / (len(counts) * counts)
    return weights[y_encoded]


def _signed_log1p(x):
    # Flow features are heavy-tailed (bytes, durations); compress them before scaling.
    return np.sign(x) * np.log1p(np.abs(x))


def build_model(name: str, seed: int = SEED, n_classes: int = 3):
    """`n_classes` only matters for XGBoost: exactly 2 classes need binary:logistic (the
    multi-class objective fails on them); predict() and predict_proba() then still return
    class indices and one probability column per class, like the multi-class model."""
    if name == "xgboost":
        objective = "binary:logistic" if n_classes == 2 else "multi:softprob"
        return XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                             subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                             objective=objective, random_state=seed, n_jobs=-1)
    if name == "rf":
        return RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                      random_state=seed, n_jobs=-1)
    if name == "mlp":
        return Pipeline([
            ("log", FunctionTransformer(_signed_log1p)),
            ("scale", StandardScaler()),
            ("mlp", MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300,
                                  early_stopping=True, validation_fraction=0.1,
                                  n_iter_no_change=10, random_state=seed)),
        ])
    raise ValueError(f"unknown model {name!r}; choose from {MODEL_NAMES}")


@dataclass
class TrainedModels:
    name: str
    model: object
    label_encoder: LabelEncoder
    features: list[str]
    anomaly: IsolationForest | None


def train_classifier(name: str, X: pd.DataFrame, y: pd.Series, seed: int = SEED,
                     extra_weight: np.ndarray | None = None):
    """Fit one classifier on the training split; returns (model, fitted LabelEncoder).

    `extra_weight` (one value per row) multiplies the class-balancing weights; retraining uses it
    to count analyst feedback rows more than one. Without it the fit is exactly as before."""
    encoder = LabelEncoder().fit(y)
    y_enc = encoder.transform(y)
    if len(encoder.classes_) < 2:
        raise ValueError("need at least two classes in the training split")
    if name == "mlp" and np.bincount(y_enc).min() < 2:
        rare = [str(c) for c, n in zip(encoder.classes_, np.bincount(y_enc), strict=True) if n < 2]
        raise ValueError(f"the mlp model uses early stopping with a stratified validation split "
                         f"and needs at least 2 training rows per class; too few for {rare}")
    model = build_model(name, seed, len(encoder.classes_))
    weights = balanced_sample_weights(y_enc)
    if extra_weight is not None:
        extra = np.asarray(extra_weight, dtype=float)
        if extra.shape != weights.shape or not np.all(np.isfinite(extra)) or (extra <= 0).any():
            raise ValueError("extra_weight must be positive, finite, one per training row")
        weights = weights * extra
    if name == "xgboost":
        model.fit(X, y_enc, sample_weight=weights)
    elif name == "mlp":
        model.fit(X, y_enc, mlp__sample_weight=weights)
    elif extra_weight is not None:  # rf: class_weight="balanced" stays; this multiplies it
        model.fit(X, y_enc, sample_weight=np.asarray(extra_weight, dtype=float))
    else:
        model.fit(X, y_enc)
    return model, encoder


def train_anomaly(X: pd.DataFrame, y: pd.Series, seed: int = SEED) -> IsolationForest:
    """IsolationForest on BENIGN-only training rows (log-compressed features)."""
    benign = X[(y == BENIGN).to_numpy()]
    if benign.empty:
        raise ValueError(f"no {BENIGN} rows to train the anomaly detector on")
    forest = Pipeline([
        ("log", FunctionTransformer(_signed_log1p)),
        ("iso", IsolationForest(n_estimators=200, contamination=ANOMALY_CONTAMINATION, random_state=seed,
                                n_jobs=1)),
    ])
    return forest.fit(benign)


def train_all(name: str, train: pd.DataFrame, features: list[str],
              seed: int = SEED, extra_weight: np.ndarray | None = None) -> TrainedModels:
    X, y = train[features], train["label"]
    model, encoder = train_classifier(name, X, y, seed, extra_weight)
    return TrainedModels(name, model, encoder, list(features), train_anomaly(X, y, seed))


def predict_labels(model, encoder: LabelEncoder, X: pd.DataFrame) -> np.ndarray:
    return encoder.inverse_transform(np.asarray(model.predict(X)).astype(int))


def anomaly_scores(anomaly, X: pd.DataFrame) -> np.ndarray:
    """Higher = more anomalous."""
    return -anomaly.decision_function(X)


def anomaly_flags(anomaly, X: pd.DataFrame) -> np.ndarray:
    return anomaly.predict(X) == -1
