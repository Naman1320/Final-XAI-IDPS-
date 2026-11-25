"""Train, evaluate, bundle and compare the cloud model (flow-log features only).

Input: the rows `idps.cloud.train_data` made from CIC-IDS2017 (flow-log fields, built by the
collector's own `to_flow_rows`). Pipeline = the lab's, with the cloud columns:

  - class-time split (idps.detect.split via idps.detect.train.make_split): per (UTC day, class)
    the earliest 60% train, then 20% validation, 20% test, rows within a gap of a cut dropped
    (120 s, shrunk at most until 10% of a bunched group is dropped, as idps.public does; the
    shrunk gaps are in the report), exact duplicates dropped inside every part;
  - XGBoost with the lab's hyperparameters and class weights from the TRAIN rows only
    (idps.detect.models.train_classifier), plus the BENIGN-only IsolationForest the bundle format
    carries;
  - features exactly CLOUD_MODEL_FEATURES, and a variant without dst_port (`_noport`);
  - metrics from idps.detect.evaluate (macro-F1, per class, benign false-positive rate, ROC-AUC),
    a bootstrap 95% interval (idps.public.scoring), timing, the classes a flow log can and cannot
    see, and a table against the lab model's reports (indicative only: other features, split,
    pipeline).

    python -m idps.cloud.train_model --data data/processed/cloud
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from idps.cloud.flowlogs import CLOUD_MODEL_FEATURES, cloud_extraction_meta
from idps.cloud.train_data import load_links, load_rows
from idps.detect.bundle import Bundle, make_version, save_bundle
from idps.detect.data import BENIGN, SEED
from idps.detect.evaluate import evaluate_classifier
from idps.detect.models import TrainedModels, train_anomaly, train_classifier
from idps.detect.split import DEFAULT_GAP_MS, Split, _identical_to_train
from idps.detect.train import _metrics_for, make_split
from idps.public.scoring import (
    bootstrap_ci,
    dedupe_by_hash,
    identical_mask,
    restricted_metrics,
    timed,
)

MODEL = "xgboost"
MAX_GAP_LOSS = 0.10
MIN_CLASS_ROWS = 100  # classes with fewer test rows are left out of the "solid classes" macro-F1
EXPERIMENT_EXTRACTOR = "experiment-not-for-the-collector"
WINDOW_MS = 60_000
VARIANTS = {"": list(CLOUD_MODEL_FEATURES),
            "_noport": [f for f in CLOUD_MODEL_FEATURES if f != "dst_port"]}  # fmt: skip

# What a flow log can plausibly show (volume or fan-out in the five counters) and what it cannot.
VISIBLE = {
    "PortScan": "many one-packet flows to many ports of one host",
    "DDoS": "very many flows or packets per window",
    "DoS Hulk": "very many flows or packets per window",
    "DoS GoldenEye": "many connections to one port",
    "DoS slowloris": "many long, tiny connections",
    "DoS Slowhttptest": "many long, tiny connections",
    "FTP-Patator": "many short connections to port 21",
    "SSH-Patator": "many short connections to port 22",
}
BLIND = {
    "Web Attack - Brute Force": "ordinary HTTP connections; the attack is in the payload",
    "Web Attack - XSS": "ordinary HTTP connections; the attack is in the payload",
    "Web Attack - Sql Injection": "ordinary HTTP connections; the attack is in the payload",
    "Infiltration": "a few normal-looking connections (a dropped file, a reverse shell)",
    "Bot": "periodic small connections that look like normal web traffic",
    "Heartbleed": "one long connection on port 444 (a handful of flows)",
}
LAB_REPORTS = {
    "friday_xgboost": ("lab model, Friday only (4 classes)", "friday_xgboost.json"),
    "friday_xgboost_noport": ("lab model, Friday only, no dst_port", "friday_xgboost_noport.json"),
    "week_xgboost": ("lab model, whole week (14 classes)", "week_xgboost.json"),
    "week_xgboost_noport": ("lab model, whole week, no dst_port", "week_xgboost_noport.json"),
}  # fmt: skip


def flow_overlap_filter(sp: Split, links: pd.DataFrame) -> tuple[Split, dict]:
    """Remove from validation and test every row that shares a CIC flow with an earlier part, and
    assert that none is left. A flow of up to 120 s can produce rows in several windows (and, when
    windows merged different labels, in several label groups with their own cuts), so the gap
    around the cuts alone cannot guarantee the parts are flow-disjoint. `links`: (key_id, flow_id).
    Returns the split and {before: rows sharing flows per part pair, removed: rows per part}."""
    from dataclasses import replace

    def flows_of(frame: pd.DataFrame) -> np.ndarray:
        return np.unique(links.loc[links["key_id"].isin(frame["key_id"]), "flow_id"].to_numpy())

    def drop_shared(frame: pd.DataFrame, earlier: np.ndarray) -> tuple[pd.DataFrame, int]:
        sub = links[links["key_id"].isin(frame["key_id"])]
        bad = sub.loc[sub["flow_id"].isin(earlier), "key_id"].unique()
        keep = ~frame["key_id"].isin(bad)
        return frame[keep].reset_index(drop=True), int((~keep).sum())

    f_train, f_val, f_test = flows_of(sp.train), flows_of(sp.validation), flows_of(sp.test)
    before = {
        "train_validation": int(np.intersect1d(f_train, f_val).size),
        "train_test": int(np.intersect1d(f_train, f_test).size),
        "validation_test": int(np.intersect1d(f_val, f_test).size),
    }
    val, removed_val = drop_shared(sp.validation, f_train)
    test, removed_test = drop_shared(sp.test, np.union1d(f_train, f_val))
    out = replace(sp, validation=val, test=test)
    after = {
        "train_validation": int(np.intersect1d(f_train, flows_of(val)).size),
        "train_test": int(np.intersect1d(f_train, flows_of(test)).size),
        "validation_test": int(np.intersect1d(flows_of(val), flows_of(test)).size),
    }
    assert not any(after.values()), f"flows still shared across parts: {after}"
    return out, {
        "flows_shared_before": before, "flows_shared_after": after,
        "rows_removed": {"validation": removed_val, "test": removed_test},
    }  # fmt: skip


def cloud_split(
    df: pd.DataFrame,
    gap_ms: int = DEFAULT_GAP_MS,
    max_gap_loss: float | None = MAX_GAP_LOSS,
    links: pd.DataFrame | None = None,
    drop_duplicates: bool = True,
) -> Split:
    """The class-time split of the cloud rows (groups: UTC day and label).

    With `links` (key_id, flow_id from idps.cloud.train_data) the parts are made flow-disjoint
    (flow_overlap_filter) and the description records how many rows that cost. The description
    also lists the classes whose effective gap is below the 60 s aggregation window
    (`gap_below_window_s`): in those, rows from nearby minutes sit on both sides of a cut."""
    sp = make_split(
        df, "class-time", gap_ms=gap_ms, allow_unseen_test_classes=True,
        features=CLOUD_MODEL_FEATURES, dup_columns=CLOUD_MODEL_FEATURES,
        group_col="label", max_drop_share=max_gap_loss, drop_duplicates=drop_duplicates,
    )  # fmt: skip
    gaps = sp.description.get("effective_gap_ms") or {}
    sp.description["gap_below_window_s"] = {
        k: v / 1000 for k, v in sorted(gaps.items()) if v < WINDOW_MS
    }
    if links is not None:
        sp, info = flow_overlap_filter(sp, links)
        sp.description["flow_overlap"] = info
    return sp


def variant_split(sp: Split, features: list[str]) -> tuple[Split, dict]:
    """Remove exact duplicates again inside each part on this variant's own vector (the split
    removed them on the full vector, so the no-port variant has new ones)."""
    from dataclasses import replace

    removed, parts = {}, {}
    for name in ("train", "validation", "test"):
        frame = getattr(sp, name)
        kept = dedupe_by_hash(frame, features)
        removed[name] = len(frame) - len(kept)
        parts[name] = kept
    return replace(sp, **parts), removed


def detection_rates(y_true, pred) -> dict:
    """Per true class: share of rows predicted as ANY attack class (what an alert would need),
    and share predicted as the right class."""
    y_true = np.asarray(y_true, dtype=object)
    pred = np.asarray(pred, dtype=object)
    out = {}
    for lab in sorted(set(y_true) - {BENIGN}):
        m = y_true == lab
        out[lab] = {"rows": int(m.sum()), "any_attack": float((pred[m] != BENIGN).mean()),
                    "right_class": float((pred[m] == lab).mean())}  # fmt: skip
    return out


def visibility_table(per_class: dict, rates: dict) -> list[dict]:
    rows = []
    for group, classes in (("visible in a flow log", VISIBLE), ("not visible", BLIND)):
        for cls, why in classes.items():
            v, r = per_class.get(cls), rates.get(cls)
            rows.append({
                "class": cls, "group": group, "why": why,
                "test_rows": v["support"] if v else 0,
                "f1": v["f1"] if v else None, "recall": v["recall"] if v else None,
                "precision": v["precision"] if v else None,
                "predicted_as_any_attack": r["any_attack"] if r else None,
            })  # fmt: skip
    return rows


def cluster_bootstrap_ci(
    y_true,
    y_pred,
    cluster,
    n_resamples: int = 200,
    seed: int = 20260518,
    level: float = 0.95,
    min_rows: int = MIN_CLASS_ROWS,
) -> dict:
    """Bootstrap by cluster: whole clusters (here wall-clock minutes of row start) are resampled
    with replacement, so rows of one minute (one flow's windows, one scan burst) stay together;
    the row bootstrap of idps.public.scoring treats them as independent and is too narrow.
    Same macro-F1 convention as evaluate_classifier (labels present in the resample), plus the
    macro-F1 over the classes that have at least `min_rows` test rows (fixed from the full test)."""
    y_true = np.asarray(y_true, dtype=object)
    y_pred = np.asarray(y_pred, dtype=object)
    labels = sorted(set(y_true) | set(y_pred))
    k = len(labels)
    code = {lab: i for i, lab in enumerate(labels)}
    t = np.fromiter((code[v] for v in y_true), dtype=np.int64, count=len(y_true))
    q = np.fromiter((code[v] for v in y_pred), dtype=np.int64, count=len(y_pred))
    _, cl = np.unique(np.asarray(cluster), return_inverse=True)
    m = int(cl.max()) + 1
    counts = np.bincount(cl * (k * k) + t * k + q, minlength=m * k * k).reshape(m, k, k)
    solid = [code[lab] for lab in labels if (y_true == lab).sum() >= min_rows]
    rng = np.random.default_rng(seed)
    macro, solid_macro = np.empty(n_resamples), np.empty(n_resamples)
    per = np.full((n_resamples, k), np.nan)
    for b in range(n_resamples):
        cm = counts[rng.integers(0, m, m)].sum(axis=0)
        tp = np.diag(cm).astype(float)
        denom = cm.sum(axis=1) + cm.sum(axis=0)
        f1 = np.divide(2 * tp, denom, out=np.zeros(k), where=denom > 0)
        present = denom > 0
        per[b, present] = f1[present]
        macro[b] = f1[present].mean()
        solid_macro[b] = f1[solid].mean() if solid else np.nan
    lo, hi = (1 - level) / 2 * 100, (1 + level) / 2 * 100
    ci = lambda a: [float(np.percentile(a, lo)), float(np.percentile(a, hi))]
    out = {
        "method": "percentile bootstrap over clusters (wall-clock minute of the row start)",
        "n_resamples": n_resamples, "seed": seed, "clusters": m,
        "macro_f1": ci(macro), "per_class_f1": {},
        "classes_with_min_rows": [labels[i] for i in solid], "min_rows": min_rows,
        "macro_f1_classes_with_min_rows": ci(solid_macro) if solid else None,
    }  # fmt: skip
    for i, lab in enumerate(labels):
        col = per[:, i][~np.isnan(per[:, i])]
        if len(col):
            out["per_class_f1"][str(lab)] = ci(col)
    return out


def _fpr_and_ddos_precision(truth: np.ndarray, pred: np.ndarray) -> dict:
    benign = truth == BENIGN
    called = pred == "DDoS"
    return {
        "rows": len(truth),
        "benign_rows": int(benign.sum()),
        "benign_false_positive_rate": float((pred[benign] != BENIGN).mean()) if benign.any() else None,
        "ddos_predicted": int(called.sum()),
        "ddos_precision": float((truth[called] == "DDoS").mean()) if called.any() else None,
    }  # fmt: skip


def label_rule_analysis(test: pd.DataFrame, pred: np.ndarray) -> dict:
    """How much of the benign false-positive rate comes from rows that merged several labels.

    (a) the rule the model is trained and scored with (the label with the most packets; a tie goes
    to the attack); (b) the same rows without the `mixed_label` rows; (c) truth = `label_any`
    (any attack flow in the row makes it an attack row). The model is the one trained with (a)."""
    pred = np.asarray(pred, dtype=object)
    truth = test["label"].astype(str).to_numpy(dtype=object)
    mixed = test["mixed_label"].to_numpy(dtype=bool)
    any_truth = test["label_any"].astype(str).to_numpy(dtype=object)
    benign = truth == BENIGN
    fp = benign & (pred != BENIGN)
    return {
        "a_current_rule": _fpr_and_ddos_precision(truth, pred),
        "b_without_mixed_rows": _fpr_and_ddos_precision(truth[~mixed], pred[~mixed]),
        "c_any_attack_flow_is_attack": _fpr_and_ddos_precision(any_truth, pred),
        "mixed_share_of_test_rows": float(mixed.mean()),
        "mixed_share_of_benign_rows": float(mixed[benign].mean()) if benign.any() else None,
        "mixed_share_of_benign_false_positives": float(mixed[fp].mean()) if fp.any() else None,
        "benign_false_positive_rate_mixed": float(fp[benign & mixed].mean()) if (benign & mixed).any() else None,
        "benign_false_positive_rate_not_mixed": float(fp[benign & ~mixed].mean()) if (benign & ~mixed).any() else None,
        "benign_mixed_rows_predicted_ddos": float((pred[benign & mixed] == "DDoS").mean()) if (benign & mixed).any() else None,
        "benign_not_mixed_rows_predicted_ddos": float((pred[benign & ~mixed] == "DDoS").mean()) if (benign & ~mixed).any() else None,
    }  # fmt: skip


def view_metrics(model, encoder, features: list[str], frame: pd.DataFrame) -> dict:
    """Headline scores of a trained model on any frame of rows (the not-deduplicated test)."""
    proba = model.predict_proba(frame[features])
    classes = list(encoder.classes_)
    pred = encoder.inverse_transform(np.argmax(proba, axis=1))
    res = evaluate_classifier(frame["label"].to_numpy(dtype=object), pred, proba, classes)
    return {
        "n": res["n"], "accuracy": res["accuracy"], "macro_f1": res["macro_f1"],
        "benign_false_positive_rate": res["benign_false_positive_rate"],
        "roc_auc_macro": res["roc_auc"]["macro"],
        "per_class": {k: {"f1": v["f1"], "precision": v["precision"], "recall": v["recall"],
                          "support": v["support"]} for k, v in res["per_class"].items()},
    }  # fmt: skip


def train_variant(
    sp: Split,
    features: list[str],
    suffix: str,
    *,
    seed: int,
    models_dir: Path,
    meta: dict | None = None,
    raw_test: pd.DataFrame | None = None,
    mixed_share: dict | None = None,
) -> tuple[dict, Bundle]:
    """Train, evaluate and save one variant. The headline numbers are on the deduplicated test
    part; `raw_test` (the same cut with duplicates kept, traffic-weighted) is scored next to it."""
    shared = sp
    sp, removed = variant_split(shared, features)
    X, y = sp.train[features], sp.train["label"]
    (model, encoder), t_clf = timed(train_classifier, MODEL, X, y, seed)
    anomaly, t_iso = timed(train_anomaly, X, y, seed)
    trained = TrainedModels(MODEL, model, encoder, list(features), anomaly)
    test_X = sp.test[features]
    proba, t_pred = timed(model.predict_proba, test_X)
    metrics = {"validation": _metrics_for(trained, sp.validation),
               "test": _metrics_for(trained, sp.test)}  # fmt: skip
    for part, frame in (("validation", sp.validation), ("test", sp.test)):
        metrics[part]["train_overlap"] = _identical_to_train(sp.train, frame, features)
    classes = list(encoder.classes_)
    pred = encoder.inverse_transform(np.argmax(proba, axis=1))
    y_test = sp.test["label"].to_numpy(dtype=object)
    metrics["test"]["bootstrap_95ci"] = bootstrap_ci(y_test, pred)
    metrics["test"]["cluster_bootstrap_95ci"] = cluster_bootstrap_ci(
        y_test, pred, sp.test["start_ms"].to_numpy() // WINDOW_MS
    )
    metrics["test"]["label_rule_analysis"] = label_rule_analysis(sp.test, pred)
    if raw_test is not None:
        metrics["test_not_deduplicated"] = view_metrics(model, encoder, features, raw_test)
    metrics["test"]["detection_rates"] = detection_rates(y_test, pred)
    visible = list(VISIBLE)
    metrics["test"]["visible_classes_only"] = restricted_metrics(
        y_test, pred, [BENIGN, *[c for c in visible if c in classes]]
    )
    new = ~identical_mask(sp.train, sp.test, features)
    only_new = evaluate_classifier(y_test[new], pred[new]) if new.any() else {}
    metrics["test"]["not_identical_to_train"] = {
        "note": "test rows whose feature vector (this variant's) is in no train row",
        "n": int(new.sum()), "macro_f1": only_new.get("macro_f1"),
        "benign_false_positive_rate": only_new.get("benign_false_positive_rate"),
    }  # fmt: skip
    bundle = Bundle(
        model_name=MODEL, model=model, label_encoder=encoder, features=list(features),
        extraction_meta=meta if meta is not None else cloud_extraction_meta(),
        split=sp.description, metrics=metrics, anomaly=anomaly,
        version=make_version(MODEL, sp.train, features),
    )  # fmt: skip
    path = models_dir / f"cloud_{MODEL}{suffix}.joblib"
    save_bundle(bundle, path)
    per_class = metrics["test"]["per_class"]
    report = {
        "model": MODEL, "dataset": "CIC-IDS2017 reduced to VPC flow-log fields",
        "features": list(features),
        "dropped_features": [f for f in CLOUD_MODEL_FEATURES if f not in features],
        "seed": seed, "split": sp.description, "classes_in_train": sorted(set(sp.train["label"])),
        "classes": classes, "metrics": metrics,
        "test_set_note": "metrics.test is the DEDUPLICATED test set (exact duplicates removed "
        "inside each part, on this variant's own vector): it weights every distinct vector once, "
        "so it up-weights rare shapes and down-weights bulk traffic. metrics.test_not_deduplicated "
        "is the same cut with duplicates kept: that one is traffic-weighted",
        "mixed_label_share_by_class": mixed_share,
        "variant_duplicates_removed": removed,
        "classes_by_visibility": visibility_table(per_class, metrics["test"]["detection_rates"]),
        "timing_seconds": {
            "train_classifier": t_clf, "train_isolation_forest": t_iso,
            "train_rows": len(sp.train), "classifier_inference_on_test": t_pred,
            "test_rows": len(sp.test),
            "classifier_inference_us_per_row": 1e6 * t_pred / max(1, len(sp.test)),
        },
        "model_file": str(path), "versions": bundle.versions, "version": bundle.version,
    }  # fmt: skip
    return report, bundle


# --- Comparison with the lab model -------------------------------------------------------------


def _test_of(report: dict) -> dict:
    return report["metrics"]["test"]


def compare_with_lab(cloud: dict, lab: dict, label: str) -> dict:
    """One cloud report against one lab report (both read from their JSON files).

    The two were trained on different features (flow log vs CICFlowMeter), different splits and
    pipelines, so every number here is indicative."""
    c, l = _test_of(cloud), _test_of(lab)
    cpc, lpc = c["per_class"], l["per_class"]
    scored = lambda pc: {k for k, v in pc.items() if v["support"] > 0}
    common = sorted(scored(cpc) & scored(lpc))
    mean = lambda pc: float(np.mean([pc[k]["f1"] for k in common])) if common else None
    solid = sorted(
        k
        for k in common
        if cpc[k]["support"] >= MIN_CLASS_ROWS and lpc[k]["support"] >= MIN_CLASS_ROWS
    )
    mean_solid = lambda pc: float(np.mean([pc[k]["f1"] for k in solid])) if solid else None
    cluster = c.get("cluster_bootstrap_95ci") or {}
    return {
        "lab_model": label,
        "cloud_macro_f1": c["macro_f1"],
        "cloud_macro_f1_cluster_ci95": cluster.get("macro_f1"),
        "solid_classes": solid,
        "solid_classes_note": f"classes with at least {MIN_CLASS_ROWS} test rows in BOTH test sets; "
        "the lab side has no interval",
        "cloud_macro_f1_on_solid_classes": mean_solid(cpc),
        "lab_macro_f1_on_solid_classes": mean_solid(lpc),
        "lab_macro_f1": l["macro_f1"],
        "cloud_macro_f1_ci95": (c.get("bootstrap_95ci") or {}).get("macro_f1"),
        "common_classes": common,
        "cloud_macro_f1_on_common_classes": mean(cpc),
        "lab_macro_f1_on_common_classes": mean(lpc),
        "cloud_benign_fpr": c["benign_false_positive_rate"],
        "lab_benign_fpr": l["benign_false_positive_rate"],
        "cloud_roc_auc_macro": c["roc_auc"]["macro"],
        "lab_roc_auc_macro": l["roc_auc"]["macro"],
        "per_class_f1": {
            k: {
                "cloud": cpc.get(k, {}).get("f1"),
                "lab": lpc.get(k, {}).get("f1"),
                "cloud_support": cpc.get(k, {}).get("support"),
                "lab_support": lpc.get(k, {}).get("support"),
            }
            for k in sorted(set(cpc) | set(lpc))
        },
        "caveat": "different feature sets (13 flow-log counters vs about 40 CICFlowMeter "
        "features), different splits (the lab week model: 5 days, one split; the cloud model: "
        "rows capped per day and class, windowed rows), different class sets and test sizes: "
        "indicative, not a controlled experiment",
    }


def comparison(cloud_reports: dict[str, dict], reports_dir: Path) -> dict:
    out = {}
    for lab_key, (title, fname) in LAB_REPORTS.items():
        path = reports_dir / fname
        if not path.exists():
            continue
        lab = json.loads(path.read_text())
        suffix = "_noport" if "noport" in lab_key else ""
        out[lab_key] = compare_with_lab(cloud_reports[suffix], lab, title)
    return out


# --- REJECT experiment ---------------------------------------------------------------------------


def as_rejected(frame: pd.DataFrame) -> pd.DataFrame:
    """The rows as a security group that REJECTs them would log them: the reply is gone (the
    lab exporter drops the victim's answer to a rejected packet), so the bwd_* columns and the
    ratios built from them are 0, and `rejected` is 1."""
    out = frame.copy()
    for col in ("bwd_packets", "bwd_bytes", "down_up_ratio", "bwd_pkt_len_mean"):
        out[col] = np.float32(0)
    out["rejected"] = np.float32(1)
    return out


def reject_experiment(
    sp: Split, seed: int, models_dir: Path, reports_dir: Path, share: float = 0.5
) -> dict:
    """Is training with synthetic REJECT scan traffic justified? Train the full-feature model on
    the train rows PLUS REJECT copies of `share` of the PortScan train rows, and measure on the
    normal CIC test rows, on the test PortScan rows converted to REJECT, and on short BENIGN test
    rows (at most 2 packets forward, 1 back: the kind a client that hits a closed port produces)
    converted to REJECT. CIC has no REJECT traffic, so the last number is a WORST CASE by
    construction (the only REJECT rows the augmented model ever saw are scans); the unmodified
    model's number on the same rows is the fairer reference. The experiment model is saved
    UNSIGNED, outside models/, with an extractor name the collector's loader refuses."""
    features = VARIANTS[""]
    sp, _ = variant_split(sp, features)
    scans = sp.train[sp.train["label"].astype(str) == "PortScan"]
    extra = as_rejected(scans.sample(frac=share, random_state=seed))
    train = pd.concat([sp.train, extra], ignore_index=True)
    model, encoder = train_classifier(MODEL, train[features], train["label"], seed)
    bmodel, benc = train_classifier(MODEL, sp.train[features], sp.train["label"], seed)

    def predicted(m, enc, frame: pd.DataFrame) -> np.ndarray:
        return enc.inverse_transform(np.argmax(m.predict_proba(frame[features]), axis=1))

    test = sp.test
    y = test["label"].to_numpy(dtype=object)
    plain = evaluate_classifier(y, predicted(model, encoder, test), None, None)
    is_benign = test["label"].astype(str) == BENIGN
    test_scans = test[test["label"].astype(str) == "PortScan"]
    short = test[is_benign & (test["fwd_packets"] <= 2) & (test["bwd_packets"] <= 1)]

    def rates(m, enc) -> dict:
        scan_pred = predicted(m, enc, as_rejected(test_scans))
        short_pred = predicted(m, enc, as_rejected(short))
        return {
            "reject_portscan_recall": float((scan_pred == "PortScan").mean()),
            "reject_portscan_any_attack": float((scan_pred != BENIGN).mean()),
            "benign_short_reject_flagged_attack": float((short_pred != BENIGN).mean()),
            "benign_short_reject_flagged_portscan": float((short_pred == "PortScan").mean()),
        }

    out = {
        "note": "experiment, not a shipped model: CIC contains no REJECT traffic, so the benign "
        "side of 'rejected = 1' is a guess (short benign rows converted to REJECT)",
        "synthetic_reject_scan_rows_added": len(extra),
        "train_rows": len(train),
        "reject_portscan_test_rows": len(test_scans),
        "benign_short_rows_as_reject": len(short),
        "with_synthetic_reject_rows": {
            **rates(model, encoder),
            "cic_test_macro_f1": plain["macro_f1"],
            "cic_test_benign_false_positive_rate": plain["benign_false_positive_rate"],
        },
        "unmodified_model": rates(bmodel, benc),
    }
    bundle = Bundle(
        model_name=MODEL,
        model=model,
        label_encoder=encoder,
        features=list(features),
        # Another extractor name: load_cloud_bundle refuses this bundle (it is not a model to deploy).
        extraction_meta={**cloud_extraction_meta(), "extractor": EXPERIMENT_EXTRACTOR},
        split=sp.description,
        metrics=out,
        version=make_version(MODEL, train, features),
    )
    models_dir.mkdir(parents=True, exist_ok=True)
    save_bundle(bundle, models_dir / "cloud_xgboost_reject_experiment.joblib")
    (reports_dir / "cloud_reject_experiment.json").write_text(json.dumps(out, indent=2))
    return out


def run(
    data_dir: str | Path,
    models_dir: str | Path = "models",
    reports_dir: str | Path = "reports",
    seed: int = SEED,
    max_rows: int | None = None,
    report_prefix: str = "cloud",
    lab_reports_dir: str | Path = "reports",
) -> dict:
    models_dir, reports_dir = Path(models_dir), Path(reports_dir)
    df = load_rows(data_dir)
    if max_rows is not None and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=seed).sort_values("start_ms").reset_index(drop=True)
    links = load_links(data_dir)
    mixed_share = {
        str(k): float(v)
        for k, v in df.groupby("label", observed=True)["mixed_label"].mean().items()
    }
    sp = cloud_split(df, links=links)
    raw_test = cloud_split(df, links=links, drop_duplicates=False).test
    del df, links
    out, reports = {}, {}
    for suffix, features in VARIANTS.items():
        t0 = time.perf_counter()
        report, _ = train_variant(
            sp, features, suffix, seed=seed, models_dir=models_dir, raw_test=raw_test,
            mixed_share=mixed_share,
        )  # fmt: skip
        report["seconds_total"] = time.perf_counter() - t0
        path = reports_dir / f"{report_prefix}_{MODEL}{suffix}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True))
        reports[suffix] = report
        t = report["metrics"]["test"]
        ci = (t["bootstrap_95ci"] or {}).get("macro_f1")
        out[suffix or "full"] = {"macro_f1": t["macro_f1"], "ci95": ci,
                                 "benign_fpr": t["benign_false_positive_rate"],
                                 "roc_auc_macro": t["roc_auc"]["macro"], "report": str(path)}  # fmt: skip
    comp = comparison(reports, Path(lab_reports_dir))
    (reports_dir / f"{report_prefix}_vs_lab.json").write_text(
        json.dumps(comp, indent=2, sort_keys=True)
    )
    out["comparison"] = {k: {"cloud": v["cloud_macro_f1"], "lab": v["lab_macro_f1"]}
                         for k, v in comp.items()}  # fmt: skip
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m idps.cloud.train_model", description="Train and evaluate the cloud model"
    )
    ap.add_argument("--data", default="data/processed/cloud")
    ap.add_argument("--models-dir", default="models")
    ap.add_argument("--reports-dir", default="reports")
    ap.add_argument("--report-prefix", default="cloud")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument(
        "--max-rows", type=int, default=None, help="random sample of the rows (smoke tests)"
    )
    ap.add_argument(
        "--lab-reports-dir", default="reports", help="where friday_/week_xgboost*.json are"
    )
    ap.add_argument("--experiments-dir", default="models/experiments")
    ap.add_argument(
        "--reject-experiment",
        action="store_true",
        help="only the synthetic-REJECT experiment (writes an unsigned experiment model)",
    )
    args = ap.parse_args(argv)
    if args.reject_experiment:
        df = load_rows(args.data)
        out = reject_experiment(
            cloud_split(df, links=load_links(args.data)),
            args.seed,
            Path(args.experiments_dir),
            Path(args.reports_dir),
        )
        print(json.dumps(out, indent=2))
        return 0
    print(
        json.dumps(
            run(
                args.data,
                args.models_dir,
                args.reports_dir,
                args.seed,
                args.max_rows,
                args.report_prefix,
                args.lab_reports_dir,
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
