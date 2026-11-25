"""Cross-dataset generalisation: train on one of CIC-IDS2017 / CSE-CIC-IDS2018, test on the other.
Also the UNSW-NB15 cross-session test (train on one capture, test on the other).

Both datasets are CICFlowMeter tables; `idps.public.labels.FEATURE_NAMES` maps the 2017 column
names to the 2018 ones. ALL 78 NAMES MATCH, BUT A MATCHING NAME IS NOT A MATCHING MEANING: in 2017
the RST, ECE, CWE and Fwd URG flag counts are 0 in every file except one (Thursday afternoon, where
all four equal 62.9%: a column-shift defect of the published file), while in 2018 RST equals ECE
and varies from 0 to 50% per day. Such features are removed from the cross test (see
`degenerate_features`, the list is in the report); the in-domain runs of the main pipeline keep
every feature. For each direction and for each variant (with and without Dst Port):

- the training dataset is split with the usual class-time split; its train part (at most
  `train_cap` rows per class, a seeded random pick) trains XGBoost with the pipeline's
  hyperparameters on the non-degenerate features;
- `in_domain`: that model on its own test part;
- `cross`: that model on EVERY row of the other dataset's sample (after exact-duplicate removal).

HOW TO READ THE NUMBERS. The two datasets do not have the same classes (PortScan is only in 2017;
the 2018 sample lacks Tuesday 20-02, which holds LOIC-HTTP, the only 2018 DDoS tool that resembles
2017's DDoS: the 2018 DDoS class is HOIC + LOIC-UDP only, so DDoS-vs-DDoS compares different tools;
Bot is likewise a different malware). A macro-F1 over different class sets is not comparable, and
evaluate.py's macro-F1 (the union of true and predicted labels) adds F1 = 0 for a class that is
predicted but absent from the truth. So the headline pair is scored on the INTERSECTION of the
classes (`shared_classes`: in the training set, in the other dataset and in the in-domain test
part): rows of other true classes are excluded and counted, a prediction outside the list is a miss,
and `drop_shared_classes` is the difference of two macro-F1 over the same classes. The all-classes
numbers stay in the report, labelled as such, with per-class recall and support.
"""

import numpy as np
import pandas as pd

from idps.detect.data import BENIGN
from idps.detect.evaluate import evaluate_classifier
from idps.detect.models import predict_labels, train_classifier
from idps.detect.split import Split, _identical_to_train
from idps.public.labels import FEATURES_2018, FEATURES_NOPORT
from idps.public.scoring import dedupe_by_hash, restricted_metrics, timed

DEFAULT_TRAIN_CAP = 200_000
PREDICT_CHUNK = 250_000
# Shared feature names whose meaning differs between the two files (see the module docstring).
KNOWN_DEFECT_FEATURES = {
    "RST Flag Cnt": "2017: 0 except in one file (column shift); 2018: equals ECE, 0-50% per day",
    "ECE Flag Cnt": "2017: 0 except in one file (column shift); 2018: equals RST, 0-50% per day",
    "CWE Flag Count": "2017: 0 except in one file (column shift)",
    "Fwd URG Flags": "2017: 0 except in one file (column shift)",
}
MIN_FILES_FOR_SINGLE_FILE_RULE = 3


def cross_features(excluded: dict | list | set) -> dict[str, list[str]]:
    """The two variants' feature lists without the excluded features."""
    skip = set(excluded)
    return {
        "with_port": [f for f in FEATURES_2018 if f not in skip],
        "without_port": [f for f in FEATURES_NOPORT if f not in skip],
    }


def degenerate_features(frames: dict[str, pd.DataFrame]) -> dict[str, list[str]]:
    """{feature: reasons} of the shared features that must not be used in the cross test.

    Automatic rules, per dataset (`frames`: name -> sample with a `source` file column): a feature
    that is CONSTANT; a feature that is non-zero in only ONE file of a dataset that has at least
    three files (the signature of the 2017 column-shift defect); plus the fixed list
    KNOWN_DEFECT_FEATURES (the defect is known for those four, and the 2018 side is checked by hand
    in the docs). A feature degenerate in either dataset is excluded."""
    out: dict[str, list[str]] = {}
    for name, df in frames.items():
        if len(df) == 0:
            continue
        files = df["source"].astype("category").cat.codes.to_numpy() if "source" in df else None
        n_files = len(set(files.tolist())) if files is not None else 0
        for f in FEATURES_2018:
            col = df[f].to_numpy()
            if (col == col[0]).all():
                out.setdefault(f, []).append(f"constant ({col[0]:g}) in {name}")
            elif n_files >= MIN_FILES_FOR_SINGLE_FILE_RULE:
                nonzero = np.unique(files[col != 0])
                if len(nonzero) == 1:
                    src = df["source"].iloc[int(np.flatnonzero(files == nonzero[0])[0])]
                    out.setdefault(f, []).append(f"non-zero only in one file of {name} ({src})")
    for f, why in KNOWN_DEFECT_FEATURES.items():
        out.setdefault(f, []).append(f"known defect: {why}")
    return out


def cap_per_class(df: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    """At most `cap` rows of every class, a seeded random pick (the training budget)."""
    parts = [g.sample(n=min(cap, len(g)), random_state=seed) for _, g in df.groupby("label")]
    return pd.concat(parts).sort_index()


def predict_chunked(model, encoder, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """(labels, class probabilities) in chunks, so a multi-million-row frame is scored without
    a second copy of it."""
    labels, probs = [], []
    for i in range(0, len(X), PREDICT_CHUNK):
        chunk = X.iloc[i : i + PREDICT_CHUNK]
        labels.append(predict_labels(model, encoder, chunk))
        probs.append(model.predict_proba(chunk))
    if not labels:
        return np.array([], dtype=object), np.zeros((0, len(encoder.classes_)), dtype=np.float32)
    return np.concatenate(labels), np.concatenate(probs)


def evaluate_frame(
    model, encoder, features: list[str], df: pd.DataFrame, shared: list[str] | None = None
) -> dict:
    """Full metrics of a trained classifier on a labelled frame (`all_classes`: evaluate.py's
    union convention), the metrics restricted to the classes it was trained on, the scores on the
    `shared` class list if given (restricted_metrics), and the attack-vs-BENIGN detection rates."""
    classes = list(encoder.classes_)
    pred, proba = predict_chunked(model, encoder, df[features])
    y = df["label"].to_numpy(dtype=object)
    full = evaluate_classifier(y, pred, proba, classes)
    seen = np.isin(y, classes)
    on_seen = evaluate_classifier(y[seen], pred[seen], proba[seen], classes) if seen.any() else None
    attack = y != BENIGN
    flagged = pred != BENIGN
    binary = {
        "benign_false_positive_rate": float(flagged[~attack].mean()) if (~attack).any() else None,
        "attack_detection_rate": float(flagged[attack].mean()) if attack.any() else None,
        "detection_rate_per_class": {
            str(c): float(flagged[y == c].mean()) for c in sorted(set(y[attack]))
        },
    }
    out = {
        "n": len(df),
        "all_classes": full,
        "all_classes_note": "macro-F1 over the union of true and predicted labels: a class that "
        "is predicted but absent from the data adds F1 = 0, and different class sets are not "
        "comparable",
        "seen_classes_only": on_seen,
        "attack_vs_benign": binary,
        "class_counts": {str(k): int(v) for k, v in pd.Series(y).value_counts().items()},
    }
    if shared is not None:
        out["shared_classes"] = restricted_metrics(y, pred, shared)
    return out


def _headline(m: dict | None) -> dict | None:
    if not m:
        return None
    return {k: m[k] for k in ("n", "accuracy", "macro_f1", "benign_false_positive_rate")}


def _recall_table(block: dict) -> dict:
    return {
        c: {"recall": v["recall"], "support": v["support"]} for c, v in block["per_class"].items()
    }


def _shared_summary(in_domain: dict, cross: dict, shared: list[str]) -> dict:
    i, c = in_domain["shared_classes"], cross["shared_classes"]
    drop = None if i["macro_f1"] is None or c["macro_f1"] is None else i["macro_f1"] - c["macro_f1"]
    return {
        "shared_classes": shared,
        "in_domain_macro_f1_shared_classes": i["macro_f1"],
        "cross_macro_f1_shared_classes": c["macro_f1"],
        "drop_shared_classes": drop,
        "cross_per_class_recall_shared": _recall_table(c),
        "in_domain_per_class_recall_shared": _recall_table(i),
        "cross_rows_excluded_true_class_outside": c["excluded_rows_true_class_outside"],
        "in_domain_rows_excluded_true_class_outside": i["excluded_rows_true_class_outside"],
        "cross_rows_predicted_outside_shared": c["kept_rows_predicted_outside"],
    }


def one_direction(
    train_sp: Split, other: pd.DataFrame, features: list[str], seed: int, train_cap: int
) -> dict:
    train = cap_per_class(train_sp.train, train_cap, seed)
    (model, encoder), seconds = timed(
        train_classifier, "xgboost", train[features], train["label"], seed
    )
    classes = list(encoder.classes_)
    other_classes = set(other["label"])
    shared = sorted(set(classes) & other_classes & set(train_sp.test["label"]))
    in_domain = evaluate_frame(model, encoder, features, train_sp.test, shared)
    cross = evaluate_frame(model, encoder, features, other, shared)
    absent = {c: n for c, n in cross["class_counts"].items() if c not in classes}
    seen_f1 = (cross["seen_classes_only"] or {}).get("macro_f1")
    return {
        "features": list(features),
        "train_rows": len(train),
        "train_class_counts": {str(k): int(v) for k, v in train["label"].value_counts().items()},
        "train_seconds": seconds,
        "classes_in_train": classes,
        "absent_from_train": absent,
        "train_overlap_with_other_dataset": _identical_to_train(train, other, features),
        "in_domain_test": in_domain,
        "cross": cross,
        "summary": {
            **_shared_summary(in_domain, cross, shared),
            "in_domain_macro_f1_all_classes": in_domain["all_classes"]["macro_f1"],
            "cross_macro_f1_all_classes_union_convention": cross["all_classes"]["macro_f1"],
            "cross_macro_f1_seen_classes": seen_f1,
            "cross_benign_false_positive_rate": cross["all_classes"]["benign_false_positive_rate"],
            "cross_attack_detection_rate": cross["attack_vs_benign"]["attack_detection_rate"],
            "how_to_read": "compare in_domain_macro_f1_shared_classes with "
            "cross_macro_f1_shared_classes (same classes, same model); the all-classes numbers "
            "cover different class sets",
        },
    }


def dedupe(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Drop exact duplicate rows (all shared features plus the label); count per class. Uses row
    hashes (flat memory); the result is the only copy the caller needs to keep."""
    before = df["label"].value_counts()
    out = dedupe_by_hash(df, FEATURES_2018)
    after = out["label"].value_counts()
    return out, {
        "class_counts_before": {str(k): int(v) for k, v in before.items()},
        "class_counts_after": {str(k): int(v) for k, v in after.items()},
    }


def run_cross(
    sp17: Split,
    df17: pd.DataFrame,
    sp18: Split,
    df18: pd.DataFrame,
    report17: dict,
    report18: dict,
    *,
    seed: int,
    train_cap: int = DEFAULT_TRAIN_CAP,
    log=print,
    dedupe_stats: tuple[dict, dict] | None = None,
) -> dict:
    """Both directions, both variants. `df17`/`df18` are the whole samples, `sp17`/`sp18` their
    class-time splits. If `dedupe_stats` = (stats17, stats18) is given, the frames are taken as
    ALREADY deduplicated with `dedupe` (the CLI does that early so the undeduplicated copies can
    be freed before training)."""
    if dedupe_stats is None:
        all17, dups17 = dedupe(df17)
        all18, dups18 = dedupe(df18)
        n17, n18 = len(df17), len(df18)
    else:
        all17, all18 = df17, df18
        dups17, dups18 = dedupe_stats
        n17 = sum(dups17["class_counts_before"].values())
        n18 = sum(dups18["class_counts_before"].values())
    degenerate = degenerate_features({"CIC-IDS2017": all17, "CSE-CIC-IDS2018": all18})
    variants = cross_features(degenerate)
    out = {
        "method": "train on one dataset's class-time train split, test on the other dataset's "
        "whole sample; see idps/public/cross.py",
        "train_cap_per_class": train_cap,
        "seed": seed,
        "features_name_matched": len(FEATURES_2018),
        "features_name_matched_note": "78 column NAMES match between the two datasets; that does "
        "not mean the columns mean the same (see features_excluded_from_cross)",
        "features_excluded_from_cross": degenerate,
        "features_used_in_cross": {k: len(v) for k, v in variants.items()},
        "in_domain_note": "the in_domain_test blocks here use the same reduced feature set as "
        "the cross model, so that in-domain and cross compare one model; the main pipeline's "
        "in-domain runs keep every feature",
        "unmatched_2017_columns": report17.get("unmatched_2017_columns", []),
        "unmatched_2018_features": [],  # the 2017 loader refuses a file that lacks one
        "missing_from_the_2018_sample": "Tuesday 20-02-2018 (not downloaded): it holds "
        "DDoS attacks-LOIC-HTTP, the only 2018 DDoS tool that resembles 2017's DDoS, so the 2018 "
        "DDoS class is HOIC + LOIC-UDP only and DDoS-vs-DDoS compares different tools; Bot is a "
        "different malware in each dataset",
        "datasets": {
            "cic_ids2017": {"caps": report17["caps"], "rows": n17, "duplicates": dups17},
            "cse_cic_ids2018": {"caps": report18["caps"], "rows": n18, "duplicates": dups18},
        },
        "directions": {},
    }
    plan = (
        ("train_2017_test_2018", sp17, all18),
        ("train_2018_test_2017", sp18, all17),
    )
    for direction, train_sp, other in plan:
        out["directions"][direction] = {}
        for variant, features in variants.items():
            res = one_direction(train_sp, other, list(features), seed, train_cap)
            out["directions"][direction][variant] = res
            s = res["summary"]
            log(
                f"{direction} {variant}: macro-F1 on the {len(s['shared_classes'])} shared "
                f"classes in-domain {_fmt(s['in_domain_macro_f1_shared_classes'])} -> cross "
                f"{_fmt(s['cross_macro_f1_shared_classes'])} (all classes, union convention: "
                f"{_fmt(s['cross_macro_f1_all_classes_union_convention'])}), attack detection "
                f"{_fmt(s['cross_attack_detection_rate'])}, BENIGN FPR "
                f"{_fmt(s['cross_benign_false_positive_rate'])}"
            )
    return out


def _fmt(x) -> str:
    return "n/a" if x is None else f"{x:.3f}"


# --- UNSW-NB15: train on one capture session, test on the other ----------------------------------


def run_unsw_cross_session(
    df: pd.DataFrame,
    *,
    seed: int,
    train_cap: int = DEFAULT_TRAIN_CAP,
    max_categories: int | None = None,
    sessions: list[dict] | None = None,
    log=print,
) -> dict:
    """Train on every row of one capture session, test on every row of the other (both orders,
    both variants). The two UNSW-NB15 captures are 26 days apart with very different attack
    priors, and a model can tell the session from the no-port features alone (AUC 0.96 in the
    original review), so the within-session split of the main run partly rewards recognising the
    capture. Here no row of the test session is seen in training.

    The categorical encoder is fitted on the training session alone. Duplicates are removed inside
    the training and the test part on the variant's own vector. The scores are on the classes both
    sessions have (restricted_metrics) next to the all-classes numbers."""
    from idps.public.unsw import (
        DEFAULT_MAX_CATEGORIES,
        FEATURES_UNSW,
        FEATURES_UNSW_NOPORT,
        CategoryEncoder,
    )

    max_categories = max_categories or DEFAULT_MAX_CATEGORIES
    ids = sorted(df["session"].unique())
    if len(ids) != 2:
        return {"skipped": f"needs exactly two capture sessions, the sample has {len(ids)}"}
    info = {int(s["session"]): s for s in sessions or []}
    variants = {"with_ports": FEATURES_UNSW, "without_ports": FEATURES_UNSW_NOPORT}
    out = {
        "method": "train on all (capped per class) rows of one capture session, test on all rows "
        "of the other; encoder fitted on the training session",
        "sessions": {str(i): info.get(int(i), {}) for i in ids},
        "train_cap_per_class": train_cap,
        "seed": seed,
        "directions": {},
    }
    for a, b in ((ids[0], ids[1]), (ids[1], ids[0])):
        name = f"train_session_{int(a)}_test_session_{int(b)}"
        out["directions"][name] = {}
        raw_train, raw_test = df[df["session"] == a], df[df["session"] == b]
        encoder = CategoryEncoder.fit(raw_train, max_categories=max_categories)
        enc_train, enc_test = encoder.transform(raw_train), encoder.transform(raw_test)
        for variant, features in variants.items():
            features = list(features)
            tr = dedupe_by_hash(enc_train, features)
            te = dedupe_by_hash(enc_test, features)
            train = cap_per_class(tr, train_cap, seed)
            (model, enc), seconds = timed(
                train_classifier, "xgboost", train[features], train["label"], seed
            )
            shared = sorted(set(enc.classes_) & set(te["label"]))
            res = evaluate_frame(model, enc, features, te, shared)
            res.update(
                {
                    "train_session": int(a),
                    "test_session": int(b),
                    "train_rows_after_dedupe": len(tr),
                    "train_rows_used": len(train),
                    "test_rows_after_dedupe": len(te),
                    "train_class_counts": {
                        str(k): int(v) for k, v in train["label"].value_counts().items()
                    },
                    "train_seconds": seconds,
                    "classes_absent_from_train": sorted(set(te["label"]) - set(enc.classes_)),
                    "test_rows_identical_to_a_train_row": _identical_to_train(train, te, features),
                }
            )
            out["directions"][name][variant] = res
            sc = res["shared_classes"]
            log(
                f"unsw {name} {variant}: macro-F1 on {len(shared)} shared classes "
                f"{_fmt(sc['macro_f1'])}, accuracy {_fmt(sc['accuracy'])}, BENIGN FPR "
                f"{_fmt(sc['benign_false_positive_rate'])} (all classes, union convention "
                f"{_fmt(res['all_classes']['macro_f1'])})"
            )
    return out


def session_probe(
    train: pd.DataFrame, test: pd.DataFrame, features: list[str], seed: int, session_col="session"
) -> dict:
    """Can the capture session be told from the features alone? An XGBoost classifier is trained
    to predict the session from `features` (train rows) and scored by ROC-AUC on the test rows,
    on all classes and on BENIGN rows only. An AUC far above 0.5 means the within-session split
    of the main run lets a model use the capture as a shortcut (attack prior, tool settings), which
    the cross-session test is there to check."""
    from sklearn.metrics import roc_auc_score
    from xgboost import XGBClassifier

    def one(tr: pd.DataFrame, te: pd.DataFrame) -> dict:
        y_tr, y_te = tr[session_col].to_numpy(), te[session_col].to_numpy()
        if len(set(y_tr)) < 2 or len(set(y_te)) < 2:
            return {"auc": None, "train_rows": len(tr), "test_rows": len(te)}
        pos = max(set(y_tr))
        model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, tree_method="hist",
                              n_jobs=-1, random_state=seed)  # fmt: skip
        model.fit(tr[features], (y_tr == pos).astype(int))
        score = model.predict_proba(te[features])[:, 1]
        return {
            "auc": float(roc_auc_score((y_te == pos).astype(int), score)),
            "train_rows": len(tr),
            "test_rows": len(te),
            "predicts_session": int(pos),
        }

    return {
        "features": list(features),
        "all_classes": one(train, test),
        "benign_only": one(train[train["label"] == BENIGN], test[test["label"] == BENIGN]),
        "reading": "ROC-AUC of predicting the capture session from the features on the test part "
        "of the main split; 0.5 = cannot tell, 1.0 = always can",
    }
