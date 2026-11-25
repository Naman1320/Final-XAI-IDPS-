"""One comparison table over the public datasets: `python -m idps.public compare`.

Reads the per-dataset reports that already exist in the reports directory and writes
reports/public_datasets_comparison.json with one row per report set. A dataset whose main report is
missing is skipped (and listed under `skipped`), so the command works at any stage of the work.

Every row has a `pipeline` field, because the rows do NOT all come from the same pipeline:

- `idps.public`: CIC-IDS2017 (rebuilt through idps/public/cic2017.py), CSE-CIC-IDS2018 and
  UNSW-NB15 run through the same code (idps.public: common sampling, the class-time split per day
  and original attack name with a shrinking gap, XGBoost, the SHAP/LIME deletion test, 100
  class-balanced flows). Their methods match; their difficulty does not (different classes,
  networks, attack tools and feature sets).
- `idps.detect (week_* reports)`: the older CIC-IDS2017 row. It comes from a different pipeline
  (our own 42-feature extractor, 14 unmerged labels, all 958k rows, a fixed 120 s gap, 16.5% of
  the test rows identical to a train row, 551 unbalanced faithfulness flows, no timing of the
  same kind). It is kept for reference and marked "different pipeline, not comparable".
"""

import json
from pathlib import Path

from idps.public.scoring import wilson_interval

PIPELINE_PUBLIC = "idps.public"
PIPELINE_WEEK = "idps.detect (week_* reports): different pipeline, not comparable"
PIPELINE_WEEK_NOTE = (
    "own 42-feature extractor, 14 unmerged labels, all rows, fixed 120 s gap, 16.5% of test rows "
    "identical to a train row, 551 unbalanced faithfulness flows: do not compare its numbers "
    "with the idps.public rows"
)
# (name, report file prefix, pipeline, pipeline note). The reports are <prefix>_xgboost[_noport].json
# and <prefix>_xgboost[_noport]_faithfulness.json.
DATASETS: tuple[tuple[str, str, str, str | None], ...] = (
    ("CIC-IDS2017 (idps.public pipeline)", "cic_ids2017", PIPELINE_PUBLIC, None),
    ("CSE-CIC-IDS2018", "cse_cic_ids2018", PIPELINE_PUBLIC, None),
    ("UNSW-NB15", "unsw_nb15", PIPELINE_PUBLIC, None),
    ("CIC-IDS2017 (week_* reports)", "week", PIPELINE_WEEK, PIPELINE_WEEK_NOTE),
)
OUTPUT_NAME = "public_datasets_comparison.json"
VERDICT_RULE = (
    "per explanation method, from the deletion test (top 5 features replaced by the background "
    "median; the random baseline deletes 5 random features, so it is 5 of N features and N is "
    "reported): the share of flows whose drop beats their random drop gets a binomial 95% Wilson "
    "interval (n = the flows tested, reported). 'inconclusive' if that interval includes 0.5; "
    "otherwise 'faithful' if the mean drop is at least 2x the random drop and the interval lies "
    "above 0.5; 'weak' if the interval lies above 0.5 and the ratio is at least 1.5 (but under "
    "2); 'not better than random' if the interval lies below 0.5 or the ratio is under 1; "
    "'inconclusive' otherwise; 'not run' if the method or file is absent. With about 10 flows per "
    "class the interval is wide (about +-10 points at 100 flows): a verdict is a summary, not a test"
)
WEAK_RATIO = 1.5
FAITHFUL_RATIO = 2.0


def _load(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


def verdict(method: dict | None, n_flows: int | None = None, n_features: int | None = None) -> dict:
    """Verdict and the numbers behind it for one method's entry of a faithfulness file."""
    base = {
        "ratio_to_random": None,
        "share_flows_beating_random": None,
        "share_ci95": None,
        "flows": n_flows,
        "features": n_features,
        "random_baseline_features": 5,
    }
    if not method:
        return {"verdict": "not run", **base}
    ratio, share = method.get("ratio_to_random"), method.get("share_flows_beating_random")
    base.update({"ratio_to_random": ratio, "share_flows_beating_random": share})
    if ratio is None or share is None or not n_flows:
        return {"verdict": "not run", **base}
    ci = wilson_interval(round(share * n_flows), n_flows)
    base["share_ci95"] = list(ci)
    if ci[0] <= 0.5 <= ci[1]:
        label = "inconclusive"
    elif ci[0] > 0.5 and ratio >= FAITHFUL_RATIO:
        label = "faithful"
    elif ci[0] > 0.5 and ratio >= WEAK_RATIO:
        label = "weak"
    elif ci[1] < 0.5 or ratio < 1:
        label = "not better than random"
    else:
        label = "inconclusive"
    return {"verdict": label, **base}


def _variant(reports: Path, prefix: str, suffix: str) -> dict | None:
    """One variant's numbers. Every number is on the deduplicated test set."""
    rep = _load(reports / f"{prefix}_xgboost{suffix}.json")
    if rep is None:
        return None
    test = rep["metrics"]["test"]
    faith = _load(reports / f"{prefix}_xgboost{suffix}_faithfulness.json")
    methods = (faith or {}).get("methods", {})
    timing = rep.get("timing_seconds") or {}
    n_features = len(rep.get("features", []))
    n_flows = (faith or {}).get("config", {}).get("n_flows")
    ci = (test.get("bootstrap_95ci") or {}).get("macro_f1")
    return {
        "n_features": n_features,
        "dropped_features": rep.get("dropped_features"),
        "test_rows": test.get("n"),
        "macro_f1": test.get("macro_f1"),
        "macro_f1_ci95": ci,
        "accuracy": test.get("accuracy"),
        "benign_false_positive_rate": test.get("benign_false_positive_rate"),
        "benign_fpr_note": "on the deduplicated test set (easy repeats removed): pessimistic",
        "roc_auc_macro": (test.get("roc_auc") or {}).get("macro"),
        "test_rows_identical_to_a_train_row": (test.get("train_overlap") or {}).get("share"),
        "train_seconds": timing.get("train_classifier"),
        "inference_us_per_flow": timing.get("classifier_inference_us_per_flow"),
        "shap": verdict(methods.get("shap"), n_flows, n_features),
        "lime": verdict(methods.get("lime"), n_flows, n_features),
        "faithfulness_flows": n_flows,
        "faithfulness_run": faith is not None,
        "report": f"{prefix}_xgboost{suffix}.json",
    }


def compare(reports_dir: str | Path = "reports", datasets=DATASETS) -> dict:
    """The comparison as a dict (see the module docstring)."""
    reports = Path(reports_dir)
    rows, skipped = [], []
    for name, prefix, pipeline, pipeline_note in datasets:
        with_port = _variant(reports, prefix, "")
        if with_port is None:
            skipped.append({"dataset": name, "reason": f"{prefix}_xgboost.json not found"})
            continue
        rep = json.loads((reports / f"{prefix}_xgboost.json").read_text())
        parts = rep["split"]["parts"]
        classes = sorted({c for p in parts.values() for c in p["class_counts"]})
        rows.append(
            {
                "dataset": name,
                "pipeline": pipeline,
                "pipeline_note": pipeline_note,
                "comparable_with_idps_public_rows": pipeline == PIPELINE_PUBLIC,
                "rows_used": sum(p["rows"] for p in parts.values()),
                "rows_by_split": {k: p["rows"] for k, p in parts.items()},
                "classes": classes,
                "n_classes": len(classes),
                "classes_missing_from_train": rep.get("classes_missing_from_train", []),
                "with_ports": with_port,
                "without_ports": _variant(reports, prefix, "_noport"),
            }
        )
    return {
        "verdict_rule": VERDICT_RULE,
        "note": "rows marked pipeline 'idps.public' use the same method (sampling, class-time "
        "split, XGBoost, SHAP/LIME deletion test) but not the same difficulty (classes, networks, "
        "attack tools and features differ); the week_* CIC-IDS2017 row comes from a different "
        "pipeline and is not comparable with them. CIC-IDS2017/2018 <-> UNSW-NB15 cross-tests are "
        "not done: different feature sets and attack taxonomies. All BENIGN false-positive rates "
        "are on the deduplicated test set.",
        "rows": rows,
        "skipped": skipped,
    }


def write_comparison(reports_dir: str | Path = "reports", output: str | Path | None = None) -> Path:
    out = Path(output) if output else Path(reports_dir) / OUTPUT_NAME
    result = compare(reports_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True))
    return out
