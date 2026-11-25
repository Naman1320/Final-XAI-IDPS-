"""Train + evaluate + bundle in one call."""

import pandas as pd

from idps.detect.bundle import Bundle, make_version
from idps.detect.data import SEED
from idps.detect.evaluate import evaluate_anomaly, evaluate_classifier
from idps.detect.models import select_features, train_all
from idps.detect.split import (
    DEFAULT_GAP_MS,
    Split,
    split_by_class_time,
    split_by_day,
    split_by_window,
)

SPLIT_MODES = ("class-time", "day", "window")


def make_split(
    df: pd.DataFrame,
    mode: str,
    val: float | None = None,
    test: float | None = None,
    *,
    gap_ms: int = DEFAULT_GAP_MS,
    allow_unseen_test_classes: bool = False,
    drop_duplicates: bool = True,
    features: list[str] | None = None,
    dup_columns: list[str] | None = None,
    group_col: str = "label",
    max_drop_share: float | None = None,
    day_col: str | None = None,
) -> Split:
    """`val`/`test`: number of days for the day split (default 1 each), fractions of rows
    for class-time and window (default 0.2 each). `gap_ms`, `group_col`, `max_drop_share`
    and `day_col` only apply to class-time. `features` / `dup_columns`: the columns the
    train-overlap share and the duplicate check use (default MODEL_FEATURES); public datasets
    pass their own."""
    common = {
        "allow_unseen_test_classes": allow_unseen_test_classes,
        "drop_duplicates": drop_duplicates,
        "features": features,
        "dup_columns": dup_columns,
    }
    if mode == "class-time":
        return split_by_class_time(
            df,
            val_frac=0.2 if val is None else float(val),
            test_frac=0.2 if test is None else float(test),
            gap_ms=gap_ms,
            group_col=group_col,
            max_drop_share=max_drop_share,
            day_col=day_col,
            **common,
        )
    if mode == "day":
        return split_by_day(
            df,
            val_days=1 if val is None else int(val),
            test_days=1 if test is None else int(test),
            **common,
        )
    if mode == "window":
        return split_by_window(
            df,
            val_frac=0.2 if val is None else float(val),
            test_frac=0.2 if test is None else float(test),
            **common,
        )
    raise ValueError(f"unknown split mode {mode!r}; choose from {SPLIT_MODES}")


def _metrics_for(trained, part: pd.DataFrame) -> dict:
    X = part[trained.features]
    classes = list(trained.label_encoder.classes_)
    pred = trained.label_encoder.inverse_transform(trained.model.predict(X).astype(int))
    res = evaluate_classifier(part["label"], pred, trained.model.predict_proba(X), classes)
    if trained.anomaly is not None:
        from idps.detect.models import anomaly_flags, anomaly_scores

        res["anomaly"] = evaluate_anomaly(
            part["label"], anomaly_scores(trained.anomaly, X), anomaly_flags(trained.anomaly, X)
        )
    return res


def resplit(bundle: Bundle, df: pd.DataFrame) -> Split:
    """The split `bundle` was trained with, rebuilt from the same labelled rows (its description
    holds the mode and sizes). Gives the training rows (drift reference) and the held-out test
    rows (retrain comparison) of a model that is already trained."""
    meta = bundle.extraction_meta or {}
    if meta.get("public_dataset"):
        raise ValueError(
            f"{meta['public_dataset']} bundles are comparison-only: they were trained with "
            "group, day-key and duplicate settings that the split description does not record, "
            "so their split cannot be rebuilt here (resplit, drift references and retraining "
            "would silently use a different split); train a new model on your own labelled "
            "flows instead"
        )
    d = bundle.split
    mode = d["mode"]
    if mode == "day":
        val, test = len(d["validation_days"]), len(d["test_days"])
    else:
        val, test = d["val_frac"], d["test_frac"]
    return make_split(
        df,
        mode,
        val,
        test,
        gap_ms=d.get("gap_ms", DEFAULT_GAP_MS),
        allow_unseen_test_classes=bool(d.get("allow_unseen_test_classes")),
        drop_duplicates=d.get("duplicates_dropped") is not None,
        features=list(bundle.features),
    )


def train_bundle_with_split(
    df: pd.DataFrame,
    meta: dict,
    model: str = "xgboost",
    split: str = "class-time",
    drop_features: list[str] | tuple[str, ...] = (),
    val: float | None = None,
    test: float | None = None,
    seed: int = SEED,
    *,
    gap_ms: int = DEFAULT_GAP_MS,
    allow_unseen_test_classes: bool = False,
    drop_duplicates: bool = True,
) -> tuple[Bundle, dict, Split]:
    """Like train_bundle, but also returns the Split (the CLI needs the training rows for the
    drift reference).

    Split by time, train on the train split, evaluate on validation and test.

    Exact duplicate rows are dropped inside each split (drop_duplicates=False keeps them),
    and each part's metrics carry `train_overlap`: how many of its rows have a feature
    vector identical to a train row.

    Returns (bundle, report). The report holds the validation and test metrics.
    """
    features = select_features(drop_features)
    sp = make_split(
        df,
        split,
        val,
        test,
        gap_ms=gap_ms,
        allow_unseen_test_classes=allow_unseen_test_classes,
        drop_duplicates=drop_duplicates,
        features=features,
    )
    trained = train_all(model, sp.train, features, seed)
    metrics = {
        "validation": _metrics_for(trained, sp.validation),
        "test": _metrics_for(trained, sp.test),
    }
    for part in ("validation", "test"):
        metrics[part]["train_overlap"] = sp.description["identical_to_train"][part]
    bundle = Bundle(
        model_name=model,
        model=trained.model,
        label_encoder=trained.label_encoder,
        features=features,
        extraction_meta=meta,
        split=sp.description,
        metrics=metrics,
        anomaly=trained.anomaly,
        version=make_version(model, sp.train, features),
    )
    report = {
        "model": model,
        "features": features,
        "dropped_features": list(drop_features),
        "seed": seed,
        "split": sp.description,
        "metrics": metrics,
        "versions": bundle.versions,
        "version": bundle.version,
    }
    return bundle, report, sp


def train_bundle(df: pd.DataFrame, meta: dict, *args, **kwargs) -> tuple[Bundle, dict]:
    """Same arguments as train_bundle_with_split; returns (bundle, report)."""
    bundle, report, _ = train_bundle_with_split(df, meta, *args, **kwargs)
    return bundle, report
