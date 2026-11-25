"""Train and evaluate the CIC-IDS2017 pipeline on a public dataset's own feature table.

The same pieces as `python -m idps.detect train`, with the dataset's columns instead of
MODEL_FEATURES: the class-time split (per day and original attack name, 60/20/20 by time, a
gap around each cut, exact duplicates dropped inside each split), XGBoost with the same
hyperparameters and class weights from the training split only, an IsolationForest on BENIGN
training rows, the same metrics, and the SHAP/LIME deletion test.

Model bundles use the normal bundle format, so `python -m idps.detect sign` signs them. Their
`extraction_meta` says the features are the dataset's published CICFlowMeter columns, not our
extractor's: `Bundle.select` / `load_bundle(live_meta=...)` therefore refuse live flows from our
sensor (the feature names and extractor differ), which is the intended protection. The
`feature_columns` key only has our layout because load_bundle insists on it.
"""

from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd

from idps.detect.bundle import Bundle, make_version, read_digest, save_bundle
from idps.detect.evaluate import evaluate_classifier
from idps.detect.models import (
    TrainedModels,
    anomaly_scores,
    train_anomaly,
    train_classifier,
)
from idps.detect.split import DEFAULT_GAP_MS, Split, _identical_to_train
from idps.detect.train import _metrics_for, make_split
from idps.explain._common import sample_rows
from idps.explain.faithfulness import faithfulness, write_json
from idps.features import FEATURE_COLUMNS
from idps.public.cross import run_unsw_cross_session, session_probe
from idps.public.labels import DST_PORT, FEATURES_2018, FEATURES_NOPORT
from idps.public.scoring import (
    bootstrap_ci,
    dedupe_by_hash,
    identical_mask,
    restricted_metrics,
    timed,
)
from idps.public.unsw import (
    CATEGORICAL,
    DEFAULT_MAX_CATEGORIES,
    FEATURES_UNSW,
    FEATURES_UNSW_NOPORT,
    NUMERIC_FEATURES,
    PORT_COLUMNS,
    CategoryEncoder,
)

MODEL = "xgboost"
DEFAULT_MAX_GAP_LOSS = 0.10
VARIANTS = {"": FEATURES_2018, "_noport": FEATURES_NOPORT}  # suffix -> features


def public_split(
    df: pd.DataFrame,
    gap_ms: int = DEFAULT_GAP_MS,
    max_gap_loss: float | None = DEFAULT_MAX_GAP_LOSS,
) -> Split:
    """The class-time split of a public-dataset frame (`start_ms`, `label`, `label_original`
    and FEATURES_2018 columns). Groups are (day, original label). A class that has no training
    rows left (a tiny group lost to the gap) is allowed and listed in the report.

    `max_gap_loss`: the gap shrinks until at most this share of a group's rows is dropped (see
    split_by_class_time); several CSE-CIC-IDS2018 groups are bursts of a few minutes that a
    fixed 120 s gap would remove completely. None keeps the fixed gap."""
    sp = make_split(
        df,
        "class-time",
        gap_ms=gap_ms,
        allow_unseen_test_classes=True,
        features=FEATURES_2018,
        dup_columns=FEATURES_2018,
        group_col="label_original",
        max_drop_share=max_gap_loss,
    )
    sp.description["identical_to_train_note"] = (
        "shared-split figure on the vector the split deduplicated on; every variant's own train "
        "overlap (on the vector it trains on, after its own deduplication) is metrics.<part>."
        "train_overlap in that variant's report"
    )
    return sp


def bundle_meta(dataset: str) -> dict:
    return {
        "extractor": f"{dataset} published CICFlowMeter columns (not idps.features)",
        "idle_timeout": None,
        "active_timeout": None,
        "feature_columns": FEATURE_COLUMNS,  # required by load_bundle; see the module docstring
        "public_dataset": dataset,
        "public_feature_columns": FEATURES_2018,
    }


_timed = timed


def balanced_sample(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """About n rows, the same number from every class (all rows of a class with fewer)."""
    per = max(1, n // max(1, df["label"].nunique()))
    parts = [g.sample(n=min(per, len(g)), random_state=seed) for _, g in df.groupby("label")]
    return pd.concat(parts).reset_index(drop=True)


def variant_split(sp: Split, features: list[str]) -> tuple[Split, dict]:
    """The split with exact duplicates removed AGAIN inside each part, on this variant's own
    vector (`features` plus the label). The split itself removed duplicates once, on the vector
    that includes the port columns (UNSW: and on the raw category strings), so the no-port variant
    would otherwise keep rows that are duplicates in its own feature space and report a different
    train overlap. Returns (split, rows removed per part)."""
    removed, parts = {}, {}
    for name in ("train", "validation", "test"):
        frame = getattr(sp, name)
        kept = dedupe_by_hash(frame, features)
        removed[name] = len(frame) - len(kept)
        parts[name] = kept
    return replace(sp, **parts), removed


def class_gap_table(sp: Split, group_to_class: dict[str, str] | None = None) -> dict[str, dict]:
    """{class: {effective_gap_s, shrunk, zero}}: the gap used at the cuts of the class's groups
    (the smallest one if a class has several groups), the nominal gap if no group shrank."""
    desc = sp.description
    nominal = desc.get("gap_ms")
    shrunk: dict[str, float] = {}
    for group, gap in (desc.get("effective_gap_ms") or {}).items():
        cls = (group_to_class or {}).get(group, group)
        shrunk[cls] = min(shrunk.get(cls, gap), gap)
    classes = set(desc["parts"]["test"]["class_counts"]) | set(shrunk)
    return {
        c: {
            "effective_gap_s": shrunk.get(c, nominal) / 1000,
            "shrunk": c in shrunk,
            "zero": c in shrunk and shrunk[c] == 0,
        }
        for c in sorted(classes)
    }


def per_class_table(test: dict, ci: dict, gaps: dict[str, dict]) -> list[dict]:
    """One row per class: test support, P/R/F1 with the bootstrap interval of the F1, and the
    split gap in force. The F1 of a class with a small support or a short gap is soft."""
    rows = []
    for cls, v in test["per_class"].items():
        g = gaps.get(cls, {})
        rows.append(
            {
                "class": cls,
                "test_support": v["support"],
                "precision": v["precision"],
                "recall": v["recall"],
                "f1": v["f1"],
                "f1_ci95": (ci.get("per_class_f1") or {}).get(cls),
                "effective_gap_s": g.get("effective_gap_s"),
                "gap_shrunk": g.get("shrunk"),
                "gap_zero": g.get("zero"),
            }
        )
    return rows


def _scores_of(y, pred) -> dict:
    m = evaluate_classifier(y, pred)
    return {k: m[k] for k in ("n", "accuracy", "macro_f1", "benign_false_positive_rate")}


def extra_test_views(trained, sp: Split, features: list[str], session_col: str | None) -> dict:
    """Test-set views beyond the headline numbers (computed on the deduplicated test part):
    the bootstrap intervals, the score on the rows whose vector is NOT in train, and, if
    `session_col` is given, one score per capture session (plus a score on the classes both
    sessions have)."""
    test = sp.test
    classes = list(trained.label_encoder.classes_)
    pred = trained.label_encoder.inverse_transform(
        np.asarray(trained.model.predict(test[features])).astype(int)
    )
    y = test["label"].to_numpy(dtype=object)
    out = {"bootstrap": bootstrap_ci(y, pred)}
    new = ~identical_mask(sp.train, test, features)
    out["not_identical_to_train"] = {
        "note": "test rows whose feature vector (this variant's) is in no train row",
        **(_scores_of(y[new], pred[new]) if new.any() else {"n": 0}),
    }
    if session_col is not None and session_col in test:
        sess = test[session_col].to_numpy()
        by = {str(k): np.flatnonzero(sess == k) for k in sorted(set(sess))}
        common = sorted(set.intersection(*(set(y[i]) for i in by.values())) & set(classes))
        out["by_session"] = {
            "note": "scores on the deduplicated test rows of one capture session each; the "
            "attack prior and the class set differ between sessions",
            "classes_in_every_session": common,
            "sessions": {
                k: {
                    **_scores_of(y[i], pred[i]),
                    "attack_share": float((y[i] != "BENIGN").mean()),
                    "class_counts": {
                        str(c): int(n)
                        for c, n in zip(*np.unique(y[i], return_counts=True), strict=True)
                    },
                    "common_classes": restricted_metrics(y[i], pred[i], common),
                }
                for k, i in by.items()
            },
        }
    return out


def train_variant(
    sp: Split,
    features: list[str],
    suffix: str,
    *,
    seed: int,
    models_dir: Path,
    reports_dir: Path,
    model_prefix: str,
    report_prefix: str,
    dataset: str,
    faith_n: int = 100,
    lime_samples: int = 1000,
    include_lime: bool = True,
    meta: dict | None = None,
    dropped_features: list[str] | None = None,
    session_col: str | None = None,
    group_to_class: dict[str, str] | None = None,
) -> dict:
    """Train, evaluate and save one variant (with or without the port column(s)). Returns its
    report. `meta` (the bundle's extraction_meta) and `dropped_features` default to the
    CSE-CIC-IDS2018 ones. The parts are first deduplicated on this variant's own vector
    (`variant_split`), so every number below is on a deduplicated test set. `session_col`: add
    per-session test scores; `group_to_class`: maps the split's group names to classes (2018
    groups by the original attack name) for the per-class gap column."""
    shared_sp = sp
    sp, removed = variant_split(shared_sp, features)
    X, y = sp.train[features], sp.train["label"]
    (model, encoder), t_clf = _timed(train_classifier, MODEL, X, y, seed)
    anomaly, t_iso = _timed(train_anomaly, X, y, seed)
    trained = TrainedModels(MODEL, model, encoder, list(features), anomaly)

    test_X = sp.test[features]
    _, t_pred = _timed(model.predict_proba, test_X)
    _, t_score = _timed(anomaly_scores, anomaly, test_X)
    metrics = {
        "validation": _metrics_for(trained, sp.validation),
        "test": _metrics_for(trained, sp.test),
    }
    for part, frame in (("validation", sp.validation), ("test", sp.test)):
        metrics[part]["train_overlap"] = _identical_to_train(sp.train, frame, features)
    views = extra_test_views(trained, sp, features, session_col)
    metrics["test"]["bootstrap_95ci"] = views.pop("bootstrap")
    metrics["test"].update(views)
    gaps = class_gap_table(shared_sp, group_to_class)
    table = per_class_table(metrics["test"], metrics["test"]["bootstrap_95ci"], gaps)

    bundle = Bundle(
        model_name=MODEL,
        model=model,
        label_encoder=encoder,
        features=list(features),
        extraction_meta=meta if meta is not None else bundle_meta(dataset),
        split=sp.description,
        metrics=metrics,
        anomaly=anomaly,
        version=make_version(MODEL, sp.train, features),
    )
    path = models_dir / f"{model_prefix}_{MODEL}{suffix}.joblib"
    save_bundle(bundle, path)

    all_classes = set().union(*(set(p["label"]) for p in (sp.validation, sp.test, sp.train)))
    report = {
        "model": MODEL,
        "dataset": dataset,
        "features": list(features),
        "dropped_features": (
            dropped_features
            if dropped_features is not None
            else ([DST_PORT] if DST_PORT not in features else [])
        ),
        "seed": seed,
        "split": sp.description,
        "classes_in_train": sorted(set(sp.train["label"])),
        "classes_missing_from_train": sorted(all_classes - set(sp.train["label"])),
        "metrics": metrics,
        "test_set_note": "every number is on the DEDUPLICATED test set (exact duplicates removed "
        "inside each part, on this variant's own vector); that removed easy repeats, so the "
        "BENIGN false-positive rate is pessimistic",
        "variant_duplicates_removed": removed,
        "variant_parts": {
            name: {"rows": len(getattr(sp, name)), "class_counts": class_counts(getattr(sp, name))}
            for name in ("train", "validation", "test")
        },
        "per_class_test_table": table,
        "macro_f1_caveat": "per-class and macro scores of classes with few test rows or an "
        "effective gap far below the flow timeout (see per_class_test_table) are soft: read them "
        "with the bootstrap interval, and the gap column shows which classes are scored on bursts "
        "that the shrunk gap barely separates",
        "timing_seconds": {
            "train_classifier": t_clf,
            "train_isolation_forest": t_iso,
            "train_rows": len(sp.train),
            "classifier_inference_on_test": t_pred,
            "isolation_forest_scoring_on_test": t_score,
            "test_rows": len(sp.test),
            "classifier_inference_us_per_flow": 1e6 * t_pred / max(1, len(sp.test)),
        },
        "model_file": str(path),
        "versions": bundle.versions,
        "version": bundle.version,
    }
    if faith_n > 0:
        sample = balanced_sample(sp.test, faith_n, seed)
        background = sample_rows(sp.train, 200, seed)
        faith = faithfulness(
            bundle,
            sample,
            background,
            n=len(sample),
            include_lime=include_lime,
            lime_samples=lime_samples,
            model_sha256=read_digest(path),
        )
        faith["config"]["test_sample"] = "class-balanced sample of the test split"
        faith_path = reports_dir / f"{report_prefix}_{MODEL}{suffix}_faithfulness.json"
        write_json(faith, faith_path)
        report["faithfulness"] = {
            "file": str(faith_path),
            **{m: v for m, v in faith["methods"].items()},
            "random_mean_drop": faith["random"]["mean_drop"],
        }
    return report


def class_counts(df: pd.DataFrame) -> dict[str, int]:
    return {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()}


def brief(report: dict) -> str:
    t = report["metrics"]["test"]
    fpr = t["benign_false_positive_rate"]
    lo, hi = (t.get("bootstrap_95ci") or {}).get("macro_f1") or (None, None)
    ci = "" if lo is None else f" (95% CI {lo:.3f}-{hi:.3f})"
    return (
        f"macro-F1 {t['macro_f1']:.3f}{ci}, accuracy {t['accuracy']:.3f}, BENIGN FPR "
        f"{'n/a' if fpr is None else f'{fpr:.4f}'} (deduplicated test set), "
        f"{t['train_overlap']['share']:.1%} of test "
        f"rows identical to a train row, train {report['timing_seconds']['train_classifier']:.0f} s"
    )


def run_cic_family(
    df: pd.DataFrame,
    load_report: dict,
    *,
    prefix: str,
    dataset: str,
    model_prefix: str,
    seed: int,
    gap_ms: int,
    max_gap_loss: float | None,
    models_dir: Path,
    reports_dir: Path,
    faith_n: int,
    lime_samples: int,
    include_lime: bool,
    log=print,
) -> tuple[Split, dict]:
    """Split a loaded CICFlowMeter sample (CSE-CIC-IDS2018 or CIC-IDS2017 through idps.public) and
    train/evaluate both variants (with and without Dst Port) on that one split. Writes
    reports/<prefix>_*.json and models/<model_prefix>_xgboost[_noport].joblib. Returns (the
    split, a summary)."""
    from idps.detect.evaluate import write_report
    from idps.public.labels import LABEL_TABLE

    sp = public_split(df, gap_ms, max_gap_loss)
    desc = sp.description
    steps = dict(load_report["steps"])
    parts = ("train", "validation", "test")
    steps["after_gap_before_duplicates"] = desc["class_counts_before_duplicates"]
    steps["after_duplicates"] = {p: desc["parts"][p]["class_counts"] for p in parts}
    pre = {
        "dataset": dataset,
        "load": load_report,
        "class_counts_by_step": steps,
        "split": desc,
        "label_mapping": [
            {"common": c, "cic_ids2017": a, "cse_cic_ids2018": b} for c, a, b in LABEL_TABLE
        ],
        "features_with_port": FEATURES_2018,
        "features_without_port": FEATURES_NOPORT,
        "dropped_columns": ["Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp (split only)"],
        "classes_missing_from_train": sorted(
            set(df["label"]) - set(sp.train["label"]),
        ),
        "gap_loss_share_by_original_label": {
            str(k): desc["dropped_by_gap"]["per_class"].get(str(k), 0) / int(v)
            for k, v in df["label_original"].value_counts().items()
        },
    }
    write_report(pre, reports_dir / f"{prefix}_preprocessing.json")
    log(
        f"split: train {len(sp.train)}, validation {len(sp.validation)}, test {len(sp.test)} rows "
        f"(gap dropped {desc['dropped_by_gap']['total']}, duplicates dropped "
        f"{desc['duplicates_dropped']})"
    )
    group_to_class = dict(zip(df["label_original"], df["label"], strict=True))
    summary = {}
    for suffix, features in VARIANTS.items():
        name = f"{MODEL}{suffix}"
        report = train_variant(
            sp,
            list(features),
            suffix,
            seed=seed,
            models_dir=models_dir,
            reports_dir=reports_dir,
            model_prefix=model_prefix,
            report_prefix=prefix,
            dataset=dataset,
            faith_n=faith_n,
            lime_samples=lime_samples,
            include_lime=include_lime,
            group_to_class=group_to_class,
        )
        write_report(report, reports_dir / f"{prefix}_{name}.json")
        log(f"{name}: {brief(report)}")
        summary[name] = report
    return sp, summary


def run_cse2018(df: pd.DataFrame, load_report: dict, **kwargs) -> tuple[Split, dict]:
    """CSE-CIC-IDS2018: reports/cse_cic_ids2018_*.json, models/cse2018_xgboost[_noport].joblib."""
    return run_cic_family(
        df,
        load_report,
        prefix="cse_cic_ids2018",
        dataset="CSE-CIC-IDS2018",
        model_prefix="cse2018",
        **kwargs,
    )


def run_cic2017(df: pd.DataFrame, load_report: dict, **kwargs) -> tuple[Split, dict]:
    """CIC-IDS2017 through THIS pipeline (cic2017.py loader, 78 shared features, 14 labels merged
    to the common classes, the same sampling and split as 2018): reports/cic_ids2017_*.json,
    models/cic2017_xgboost[_noport].joblib. Not the same as the older week_* reports (own
    extractor, 42 features)."""
    return run_cic_family(
        df,
        load_report,
        prefix="cic_ids2017",
        dataset="CIC-IDS2017 (idps.public pipeline)",
        model_prefix="cic2017",
        **kwargs,
    )


# --- UNSW-NB15 -----------------------------------------------------------------------------------

UNSW_VARIANTS = {"": FEATURES_UNSW, "_noport": FEATURES_UNSW_NOPORT}  # suffix -> features
_ID_SUFFIX = "_id"


def unsw_split(
    df: pd.DataFrame,
    gap_ms: int = DEFAULT_GAP_MS,
    max_gap_loss: float | None = DEFAULT_MAX_GAP_LOSS,
    max_categories: int = DEFAULT_MAX_CATEGORIES,
) -> tuple[Split, CategoryEncoder]:
    """The class-time split of a UNSW-NB15 frame (`start_ms`, `session`, `label`, text proto /
    state / service and the numeric features), then the categorical encoding.

    Same rules as `public_split` (60/20/20 by time per group, shrinking gap, exact duplicates
    removed inside each split), with two differences: the groups are (capture session, class), the
    session being the capture day (see idps.public.unsw), and the categorical columns are encoded
    AFTER the split. The split itself needs numbers to find exact duplicates and train overlap, so
    it runs on arbitrary integer ids of the category strings (`factorize`: equal strings, equal
    id): those ids are only compared for equality, never given to a model. Then the encoder is
    fitted on the training rows alone and applied to all three parts, so no validation or test
    row can influence the categories. Returns (split with encoded frames, the fitted encoder)."""
    ids = {f"{c}{_ID_SUFFIX}": pd.factorize(df[c])[0].astype(np.float32) for c in CATEGORICAL}
    compare_cols = [*NUMERIC_FEATURES, *ids]
    sp = make_split(
        df.assign(**ids),
        "class-time",
        gap_ms=gap_ms,
        allow_unseen_test_classes=True,
        features=compare_cols,
        dup_columns=compare_cols,
        group_col="label",
        max_drop_share=max_gap_loss,
        day_col="session",
    )
    raw = {"train": sp.train, "validation": sp.validation, "test": sp.test}
    encoder = CategoryEncoder.fit(sp.train, max_categories=max_categories)
    desc = sp.description
    desc["categorical_encoding"] = encoder.describe(raw)
    desc["train_overlap_features"] = [
        c.removesuffix(_ID_SUFFIX) for c in desc["train_overlap_features"]
    ]
    desc["day_key"] = "capture session (UNSW-NB15 has two captures, 26 days apart)"
    desc["split_features_note"] = (
        "duplicates and train overlap are decided on the numeric features plus the raw "
        "proto/state/service strings (as ids); the model sees the train-fitted codes"
    )
    sp.description["identical_to_train_note"] = (
        "shared-split figure on the numeric features plus raw category ids; every variant's own "
        "train overlap (on the encoded vector it trains on, after its own deduplication) is "
        "metrics.<part>.train_overlap in that variant's report"
    )
    drop = list(ids)
    for name, part in raw.items():
        setattr(sp, name, encoder.transform(part).drop(columns=drop))
    return sp, encoder


def bundle_meta_unsw(encoder: CategoryEncoder, features: list[str]) -> dict:
    return {
        "extractor": "UNSW-NB15 published Argus/Bro columns (not idps.features)",
        "idle_timeout": None,
        "active_timeout": None,
        "feature_columns": FEATURE_COLUMNS,  # required by load_bundle; see the module docstring
        "public_dataset": "UNSW-NB15",
        "public_feature_columns": list(features),
        "categorical_encoding": encoder.to_dict(),  # inference: CategoryEncoder.from_dict(...)
    }


def run_unsw(
    df: pd.DataFrame,
    load_report: dict,
    *,
    seed: int,
    gap_ms: int,
    max_gap_loss: float | None,
    models_dir: Path,
    reports_dir: Path,
    faith_n: int,
    lime_samples: int,
    include_lime: bool,
    max_categories: int = DEFAULT_MAX_CATEGORIES,
    log=print,
) -> tuple[Split, dict]:
    """Split a loaded UNSW-NB15 sample and train/evaluate both variants (with and without sport /
    dsport) on that one split, then the cross-session test (train on one capture, test on the
    other). Writes reports/unsw_nb15_*.json (incl. unsw_nb15_cross_session.json) and
    models/unsw_nb15_xgboost[_noport].joblib. Returns (the split, a summary)."""
    from idps.detect.evaluate import write_report
    from idps.public.labels import UNSW_LABEL_TABLE

    prefix, dataset = "unsw_nb15", "UNSW-NB15"
    sp, encoder = unsw_split(df, gap_ms, max_gap_loss, max_categories)
    desc = sp.description
    steps = dict(load_report["steps"])
    parts = ("train", "validation", "test")
    steps["after_gap_before_duplicates"] = desc["class_counts_before_duplicates"]
    steps["after_duplicates"] = {p: desc["parts"][p]["class_counts"] for p in parts}
    pre = {
        "dataset": dataset,
        "load": load_report,
        "class_counts_by_step": steps,
        "split": desc,
        "label_mapping": [{"class": c, "unsw_attack_cat": s} for c, s in UNSW_LABEL_TABLE],
        "cross_test_with_cic": "not done: CICFlowMeter and Argus/Bro features share no columns, "
        "and the attack taxonomies differ; no mapping is invented",
        "features_with_port": FEATURES_UNSW,
        "features_without_port": FEATURES_UNSW_NOPORT,
        "categorical_columns": list(CATEGORICAL),
        "categorical_encoding": desc["categorical_encoding"],
        "dropped_columns": [
            "srcip",
            "dstip",
            "Stime (split only)",
            "Ltime",
            "attack_cat (label)",
            "Label (check)",
        ],
        "classes_missing_from_train": sorted(set(df["label"]) - set(sp.train["label"])),
        "gap_loss_share_by_label": {
            str(k): desc["dropped_by_gap"]["per_class"].get(str(k), 0) / int(v)
            for k, v in df["label"].value_counts().items()
        },
    }
    write_report(pre, reports_dir / f"{prefix}_preprocessing.json")
    log(
        f"split: train {len(sp.train)}, validation {len(sp.validation)}, test {len(sp.test)} rows "
        f"(gap dropped {desc['dropped_by_gap']['total']}, duplicates dropped "
        f"{desc['duplicates_dropped']})"
    )
    summary = {}
    for suffix, features in UNSW_VARIANTS.items():
        name = f"{MODEL}{suffix}"
        report = train_variant(
            sp,
            list(features),
            suffix,
            seed=seed,
            models_dir=models_dir,
            reports_dir=reports_dir,
            model_prefix=prefix,
            report_prefix=prefix,
            dataset=dataset,
            faith_n=faith_n,
            lime_samples=lime_samples,
            include_lime=include_lime,
            meta=bundle_meta_unsw(encoder, features),
            dropped_features=[c for c in PORT_COLUMNS if c not in features],
            session_col="session",
        )
        write_report(report, reports_dir / f"{prefix}_{name}.json")
        log(f"{name}: {brief(report)}")
        for k, v in report["metrics"]["test"].get("by_session", {}).get("sessions", {}).items():
            log(
                f"  session {k}: macro-F1 {v['macro_f1']:.3f}, accuracy {v['accuracy']:.3f}, "
                f"attack share {v['attack_share']:.1%}, {v['n']} test rows"
            )
        summary[name] = report
    cross_session = run_unsw_cross_session(
        df, seed=seed, max_categories=max_categories, sessions=load_report.get("sessions"), log=log
    )
    if "skipped" not in cross_session:
        cross_session["session_predictability"] = session_probe(
            sp.train, sp.test, list(FEATURES_UNSW_NOPORT), seed
        )
        log(
            "session predictable from the no-port features: AUC "
            f"{cross_session['session_predictability']['all_classes']['auc']} (all classes), "
            f"{cross_session['session_predictability']['benign_only']['auc']} (BENIGN only)"
        )
    write_report(cross_session, reports_dir / f"{prefix}_cross_session.json")
    summary["cross_session"] = cross_session
    return sp, summary
