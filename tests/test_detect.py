import json
import os
import pickle

import numpy as np
import pandas as pd
import pytest

from idps.detect.__main__ import main
from idps.detect.bundle import DEFAULT_MODEL_PATH, load_bundle, save_bundle
from idps.detect.data import load_labelled
from idps.detect.evaluate import evaluate_bundle, evaluate_classifier
from idps.detect.models import MODEL_NAMES
from idps.detect.split import split_by_class_time, split_by_day, split_by_window
from idps.detect.train import train_bundle
from idps.features import (
    FEATURE_COLUMNS,
    MODEL_FEATURES,
    extraction_meta,
    write_features,
)

DAY_MS = 86_400_000
T0 = 1_500_000_000_000 // DAY_MS * DAY_MS  # a UTC midnight
META = extraction_meta("scapy", 60, 120)
# What 'features label' writes next to a labelled file: extraction settings plus join quality.
LABELLED = {**META, "utc_offset_hours": -3.0, "match_summary": {"match_rate": 0.9}}


def synthetic(days=5, per_class=40, seed=0) -> pd.DataFrame:
    """3 separable classes: BENIGN (small flows), DoS (many packets), PortScan (tiny, rst)."""
    rng = np.random.default_rng(seed)
    rows = []
    for d in range(days):
        for label, port, pk, rst in (("BENIGN", 443, 20, 0), ("DoS", 80, 2000, 0),
                                     ("PortScan", 22, 1, 5)):
            for _ in range(per_class):
                r = dict.fromkeys(FEATURE_COLUMNS, 0)
                r.update(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234,
                         dst_port=port, protocol=6,
                         start_ms=T0 + d * DAY_MS + int(rng.integers(0, DAY_MS - 1)),
                         fwd_packets=int(pk * rng.uniform(0.8, 1.2)),
                         rst_count=rst, fwd_bytes=int(pk * 60 * rng.uniform(0.8, 1.2)))
                r["end_ms"] = r["start_ms"] + 10
                r["label"] = label
                rows.append(r)
    return pd.DataFrame(rows)


def test_day_split_never_mixes_days():
    sp = split_by_day(synthetic(), drop_duplicates=False)
    day = lambda df: set(df.start_ms // DAY_MS)
    assert day(sp.train).isdisjoint(day(sp.validation)) and day(sp.train).isdisjoint(day(sp.test))
    assert day(sp.validation).isdisjoint(day(sp.test))
    assert max(day(sp.train)) < min(day(sp.validation)) < min(day(sp.test))
    assert len(sp.train) + len(sp.validation) + len(sp.test) == 5 * 120
    assert sp.description["mode"] == "day" and len(sp.description["test_days"]) == 1


def test_window_split_is_contiguous_in_time():
    sp = split_by_window(synthetic(days=3))
    assert sp.train.start_ms.max() < sp.validation.start_ms.min()
    assert sp.validation.start_ms.max() < sp.test.start_ms.min()
    assert "validation_starts_ms" in sp.description


def test_split_fails_when_class_missing_from_train():
    df = synthetic()
    df.loc[df.start_ms >= T0 + 4 * DAY_MS, "label"] = "Rare"  # only in the test day
    with pytest.raises(ValueError, match="Rare"):
        split_by_day(df)
    with pytest.raises(ValueError, match="distinct UTC days"):
        split_by_day(synthetic(days=2))


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_every_model_trains_and_beats_chance(name):
    bundle, report = train_bundle(synthetic(), META, model=name)
    test = report["metrics"]["test"]
    assert test["macro_f1"] > 0.9  # chance for 3 balanced classes is ~0.33
    assert bundle.features == MODEL_FEATURES
    assert list(bundle.label_encoder.classes_) == ["BENIGN", "DoS", "PortScan"]
    assert test["roc_auc"]["macro"] > 0.9


def test_drop_feature_and_unknown_feature():
    bundle, _ = train_bundle(synthetic(), META, drop_features=["dst_port"])
    assert "dst_port" not in bundle.features
    with pytest.raises(ValueError, match="unknown"):
        train_bundle(synthetic(), META, drop_features=["src_ip"])


def test_training_is_reproducible():
    a, _ = train_bundle(synthetic(), META, model="rf")
    b, _ = train_bundle(synthetic(), META, model="rf")
    X = synthetic(seed=3)[MODEL_FEATURES]
    assert (a.predict(X) == b.predict(X)).all()


def test_anomaly_detector_flags_outliers():
    bundle, report = train_bundle(synthetic(), META)
    outliers = synthetic(days=1, per_class=10)
    outliers = outliers[outliers.label == "BENIGN"].copy()
    outliers[["fwd_packets", "fwd_bytes", "bwd_bytes", "duration_ms", "syn_count"]] = 10**9
    flags = bundle.anomaly_flags(outliers)
    assert flags.mean() > 0.9
    normal = synthetic(seed=5)
    normal = normal[normal.label == "BENIGN"]
    assert bundle.anomaly_flags(normal).mean() < 0.2
    assert report["metrics"]["test"]["anomaly"]["roc_auc"] > 0.9


def test_metrics_fields():
    _, report = train_bundle(synthetic(), META)
    m = report["metrics"]["test"]
    for k in ("per_class", "macro_f1", "benign_false_positive_rate", "confusion_matrix",
              "roc_auc", "accuracy"):
        assert k in m
    assert set(m["per_class"]["DoS"]) == {"precision", "recall", "f1", "support"}
    cm = m["confusion_matrix"]
    assert cm["labels"] == ["BENIGN", "DoS", "PortScan"] and len(cm["matrix"]) == 3
    assert 0 <= m["benign_false_positive_rate"] <= 1
    json.dumps(report)  # must be serialisable


def test_bundle_round_trip_and_mismatch_refused(tmp_path):
    df = synthetic()
    bundle, _ = train_bundle(df, META)
    path = save_bundle(bundle, tmp_path / "m.joblib")
    loaded = load_bundle(path, live_meta=META, live_columns=list(df.columns))
    X = df[MODEL_FEATURES]
    assert (loaded.predict(X) == bundle.predict(X)).all()
    assert loaded.features == bundle.features and loaded.extraction_meta == META
    assert loaded.split == bundle.split and "test" in loaded.metrics
    assert "xgboost" in loaded.versions and "scikit-learn" in loaded.versions

    other = extraction_meta("nfstream", 60, 120)
    with pytest.raises(ValueError, match="differ"):
        load_bundle(path, live_meta=other)
    with pytest.raises(ValueError, match="differ"):
        loaded.select(df, other)
    with pytest.raises(ValueError, match="no extraction metadata"):
        loaded.select(df, {})
    with pytest.raises(ValueError, match="missing"):
        load_bundle(path, live_columns=["dst_port"])
    with pytest.raises(ValueError, match="missing"):
        loaded.select(df.drop(columns=["rst_count"]), META)
    assert evaluate_bundle(loaded, df, META)["macro_f1"] > 0.9


def test_default_model_path_matches_settings():
    from idps.config import Settings
    assert DEFAULT_MODEL_PATH == Settings().model_path == "models/model.joblib"


def test_load_labelled_requires_metadata_and_same_extraction(tmp_path):
    df = synthetic(days=1)
    write_features(df, tmp_path / "a.parquet", LABELLED)
    write_features(df, tmp_path / "b.parquet", {**LABELLED, **extraction_meta("nfstream", 60, 120)})
    write_features(df, tmp_path / "c.parquet", {})
    out, meta = load_labelled([tmp_path / "a.parquet"])
    assert len(out) == len(df) and meta["extractor"] == "scapy"
    with pytest.raises(ValueError, match="differ"):
        load_labelled([tmp_path / "a.parquet", tmp_path / "b.parquet"])
    with pytest.raises(ValueError, match="no extraction metadata"):
        load_labelled([tmp_path / "c.parquet"])


def test_cli_train_and_evaluate_end_to_end(tmp_path, capsys):
    data = tmp_path / "labelled.parquet"
    write_features(synthetic(), data, LABELLED)
    model, report = tmp_path / "out" / "model.joblib", tmp_path / "reports" / "metrics.json"
    rc = main(["train", str(data), "--model", "rf", "--split", "day", "-o", str(model),
               "--report", str(report), "--drop-feature", "dst_port"])
    assert rc == 0 and model.exists()
    rep = json.loads(report.read_text())
    assert rep["dropped_features"] == ["dst_port"] and "test" in rep["metrics"]

    out_json = tmp_path / "eval.json"
    assert main(["evaluate", str(model), str(data), "--report", str(out_json)]) == 0
    assert json.loads(capsys.readouterr().out)["macro_f1"] > 0.9
    assert "confusion_matrix" in json.loads(out_json.read_text())

    # Evaluating data made with other extraction settings fails with a clear error.
    bad = tmp_path / "bad.parquet"
    write_features(synthetic(days=1), bad, {**LABELLED, **extraction_meta("nfstream", 60, 120)})
    assert main(["evaluate", str(model), str(bad)]) == 2
    assert "differ" in capsys.readouterr().err
    assert main(["train", str(data), "--split", "window", "-o", str(tmp_path / "w.joblib")]) == 0
    # class-time is the default split
    default = tmp_path / "d.joblib"
    assert main(["train", str(data), "--model", "rf", "-o", str(default)]) == 0
    assert load_bundle(default).split["mode"] == "class-time"


# --- review findings: splits, match-rate guard, metrics, bundle safety ----------------------

def cic_like(per_class=60) -> pd.DataFrame:
    """CIC-IDS2017 layout: BENIGN every day, each attack class on ONE day only."""
    df = synthetic(days=5, per_class=per_class)
    day = (df.start_ms - T0) // DAY_MS
    keep = ((df.label == "BENIGN") | ((df.label == "DoS") & (day == 1))
            | ((df.label == "PortScan") & (day == 3)))
    return df[keep].reset_index(drop=True)


def _group_times(part: pd.DataFrame, label: str, d: int) -> pd.Series:
    """start_ms of the rows of one (UTC day, class) group inside a split part."""
    return part[(part.label == label) & (part.start_ms // DAY_MS == d)].start_ms


def test_class_time_split_has_every_class_in_train_and_tests_later_traffic():
    df = cic_like()
    sp = split_by_class_time(df, gap_ms=0, drop_duplicates=False)
    for part in (sp.train, sp.validation, sp.test):
        assert set(part.label) == {"BENIGN", "DoS", "PortScan"}
    for label in ("BENIGN", "DoS", "PortScan"):
        for d in set(df[df.label == label].start_ms // DAY_MS):
            tr, va, te = (_group_times(p, label, d) for p in (sp.train, sp.validation, sp.test))
            assert tr.max() <= va.min() and va.max() <= te.min()
    n = (df.label == "DoS").sum()  # one group: 60 rows -> 36 / 12 / 12
    assert (sp.train.label == "DoS").sum() == int(n * 0.6)
    assert (sp.test.label == "DoS").sum() == n - int(n * 0.8)
    assert sp.description["mode"] == "class-time"


def test_class_time_gap_drops_rows_near_each_cut():
    df = cic_like()
    sp = split_by_class_time(df, gap_ms=3_600_000, drop_duplicates=False)
    kept = len(sp.train) + len(sp.validation) + len(sp.test)
    assert kept < len(df) and sp.description["dropped_by_gap"]["total"] == len(df) - kept
    for label in ("BENIGN", "DoS", "PortScan"):
        # within one (day, class) group, parts are separated by at least the gap
        for d in set(df[df.label == label].start_ms // DAY_MS):
            tr, va, te = (_group_times(p, label, d) for p in (sp.train, sp.validation, sp.test))
            if len(tr) and len(va):
                assert va.min() - tr.max() >= 3_600_000
            if len(va) and len(te):
                assert te.min() - va.max() >= 3_600_000


def test_class_time_works_where_day_split_fails():
    df = cic_like()
    with pytest.raises(ValueError, match="PortScan"):
        split_by_day(df)  # PortScan only exists on a validation/test day
    sp = split_by_day(df, allow_unseen_test_classes=True)
    assert "PortScan" not in set(sp.train.label) and "PortScan" in set(sp.validation.label)
    assert sp.description["allow_unseen_test_classes"] is True
    split_by_class_time(df)  # default settings: no error
    # the unseen class flows through training and metrics without crashing
    _, report = train_bundle(df, META, model="rf", split="day", allow_unseen_test_classes=True)
    assert "PortScan" in report["metrics"]["validation"]["per_class"]
    with pytest.raises(ValueError, match="PortScan"):
        train_bundle(df, META, model="rf", split="day")


def test_class_time_validates_arguments():
    df = cic_like()
    with pytest.raises(ValueError):
        split_by_class_time(df, val_frac=0.6, test_frac=0.4)
    with pytest.raises(ValueError):
        split_by_class_time(df, gap_ms=-1)


def test_load_labelled_refuses_low_or_unknown_match_rate(tmp_path):
    df = synthetic(days=1)
    write_features(df, tmp_path / "low.parquet", {**LABELLED, "match_summary": {"match_rate": 0.3}})
    write_features(df, tmp_path / "none.parquet", {**META, "utc_offset_hours": -3.0})
    write_features(df, tmp_path / "ok.parquet", LABELLED)
    with pytest.raises(ValueError, match="match rate of 30.0%"):
        load_labelled([tmp_path / "ok.parquet", tmp_path / "low.parquet"])
    with pytest.raises(ValueError, match="no match_summary"):
        load_labelled([tmp_path / "none.parquet"])
    with pytest.raises(ValueError, match="match rate"):
        load_labelled([tmp_path / "low.parquet"], min_match_rate=0.5)
    load_labelled([tmp_path / "low.parquet"], min_match_rate=0.2)
    out, _ = load_labelled([tmp_path / "low.parquet", tmp_path / "none.parquet"],
                           allow_low_match=True)
    assert len(out) == 2 * len(df)


def test_load_labelled_refuses_mixed_utc_offsets(tmp_path):
    df = synthetic(days=1)
    write_features(df, tmp_path / "a.parquet", LABELLED)
    write_features(df, tmp_path / "b.parquet", {**LABELLED, "utc_offset_hours": 0.0})
    with pytest.raises(ValueError, match="utc_offset_hours"):
        load_labelled([tmp_path / "a.parquet", tmp_path / "b.parquet"])
    with pytest.raises(ValueError, match="utc_offset_hours"):  # not waived by the override
        load_labelled([tmp_path / "a.parquet", tmp_path / "b.parquet"], allow_low_match=True)


def test_cli_train_low_match_needs_explicit_flag(tmp_path, capsys):
    data = tmp_path / "low.parquet"
    write_features(synthetic(), data, {**LABELLED, "match_summary": {"match_rate": 0.1}})
    out = tmp_path / "m.joblib"
    assert main(["train", str(data), "--model", "rf", "-o", str(out)]) == 2
    assert "match rate" in capsys.readouterr().err and not out.exists()
    assert main(["train", str(data), "--model", "rf", "-o", str(out),
                 "--allow-low-match-rate"]) == 0


def test_xgboost_with_exactly_two_classes():
    df = synthetic()
    df = df[df.label != "PortScan"]
    bundle, report = train_bundle(df, META, model="xgboost")
    assert bundle.model.get_params()["objective"] == "binary:logistic"
    assert list(bundle.label_encoder.classes_) == ["BENIGN", "DoS"]
    X = synthetic(seed=4)[MODEL_FEATURES]
    X = X.iloc[:50]
    proba = bundle.predict_proba(X)
    assert proba.shape == (50, 2) and np.allclose(proba.sum(axis=1), 1)
    assert set(bundle.predict(X)) <= {"BENIGN", "DoS"}
    assert report["metrics"]["test"]["macro_f1"] > 0.9
    three, _ = train_bundle(synthetic(), META, model="xgboost")
    assert three.model.get_params()["objective"] == "multi:softprob"


def test_macro_f1_includes_predicted_but_absent_classes():
    m = evaluate_classifier(["BENIGN"] * 4, ["BENIGN", "BENIGN", "BENIGN", "DoS"])
    # BENIGN: precision 1, recall 0.75, F1 6/7; DoS never occurs but was predicted: F1 0
    assert m["macro_f1"] == pytest.approx((6 / 7 + 0.0) / 2)
    assert set(m["per_class"]) == {"BENIGN", "DoS"} and m["per_class"]["DoS"]["support"] == 0
    perfect = evaluate_classifier(["BENIGN", "DoS"], ["BENIGN", "DoS"])
    assert perfect["macro_f1"] == 1.0
    # a class that is neither true nor predicted (only known to the model) is not scored
    assert evaluate_classifier(["BENIGN"], ["BENIGN"], classes=["BENIGN", "X"])["macro_f1"] == 1.0


def _dup_frame() -> pd.DataFrame:
    rows = []
    for i in range(100):
        r = dict.fromkeys(FEATURE_COLUMNS, 0)
        dos = i % 2
        r.update(src_ip="a", dst_ip="b", protocol=6, dst_port=80 if dos else 443,
                 start_ms=T0 + i * 1000, end_ms=T0 + i * 1000 + 5,
                 fwd_packets=500 if dos else 5, label="DoS" if dos else "BENIGN")
        rows.append(r)
    rows[-2]["fwd_packets"] = 77  # the one test row (BENIGN) with a vector not seen in train
    rows[-2]["label"] = "BENIGN"
    return pd.DataFrame(rows)


def test_duplicates_dropped_per_split_and_train_overlap_reported():
    df = _dup_frame()
    sp = split_by_window(df)  # rows 0-59 train, 60-79 validation, 80-99 test
    assert (len(sp.train), len(sp.validation)) == (2, 2)  # one row per class survives
    assert len(sp.test) == 3
    assert sp.description["duplicates_dropped"] == {"train": 58, "validation": 18, "test": 17}
    assert sp.description["parts"]["test"]["rows"] == 3
    assert sp.description["identical_to_train"]["test"] == {"rows": 2, "share": pytest.approx(2 / 3)}

    raw = split_by_window(df, drop_duplicates=False)
    assert len(raw.train) == 60 and raw.description["duplicates_dropped"] is None
    assert raw.description["identical_to_train"]["test"] == {"rows": 19, "share": pytest.approx(0.95)}

    _, report = train_bundle(df, META, model="rf", split="window")
    assert report["metrics"]["test"]["train_overlap"]["rows"] == 2
    _, kept = train_bundle(df, META, model="rf", split="window", drop_duplicates=False)
    assert kept["metrics"]["test"]["train_overlap"]["rows"] == 19


def test_overlap_uses_the_features_the_model_trains_on():
    df = _dup_frame()
    df.loc[df.label == "BENIGN", "dst_port"] = np.arange((df.label == "BENIGN").sum())
    full = split_by_window(df, drop_duplicates=False).description["identical_to_train"]["test"]
    no_port = split_by_window(df, drop_duplicates=False,
                              features=[f for f in MODEL_FEATURES if f != "dst_port"])
    assert no_port.description["identical_to_train"]["test"]["rows"] > full["rows"]


def test_cli_keep_duplicates_flag(tmp_path):
    data = tmp_path / "d.parquet"
    write_features(_dup_frame(), data, LABELLED)
    rep = tmp_path / "r.json"
    args = ["train", str(data), "--model", "rf", "--split", "window", "--report", str(rep)]
    assert main([*args, "-o", str(tmp_path / "a.joblib")]) == 0
    assert json.loads(rep.read_text())["split"]["parts"]["train"]["rows"] == 2
    assert main([*args, "-o", str(tmp_path / "b.joblib"), "--keep-duplicates"]) == 0
    assert json.loads(rep.read_text())["split"]["parts"]["train"]["rows"] == 60


@pytest.mark.parametrize("name", ["xgboost", "mlp"])
def test_same_seed_gives_identical_predictions(name):
    a, _ = train_bundle(synthetic(), META, model=name, seed=7)
    b, _ = train_bundle(synthetic(), META, model=name, seed=7)
    X = synthetic(seed=3)[MODEL_FEATURES]
    assert (a.predict(X) == b.predict(X)).all()
    assert np.allclose(a.predict_proba(X), b.predict_proba(X))


def test_bundle_digest_written_and_tampering_refused(tmp_path):
    bundle, _ = train_bundle(synthetic(), META, model="rf")
    path = save_bundle(bundle, tmp_path / "m.joblib")
    sha = tmp_path / "m.joblib.sha256"
    assert sha.exists() and path.stat().st_mode & 0o022 == 0 and sha.stat().st_mode & 0o022 == 0
    load_bundle(path)

    # An attacker's pickle must be refused BEFORE it runs.
    marker = tmp_path / "pwned"

    class Evil:
        def __reduce__(self):
            return (os.mkdir, (str(marker),))

    good = path.read_bytes()
    path.write_bytes(pickle.dumps(Evil()))
    with pytest.raises(ValueError, match="does not match"):
        load_bundle(path)
    assert not marker.exists()
    path.write_bytes(good)
    load_bundle(path)

    # same size, one flipped byte
    path.write_bytes(good[:-1] + bytes([good[-1] ^ 1]))
    with pytest.raises(ValueError, match="does not match"):
        load_bundle(path)
    path.write_bytes(good)

    sha.write_text("0" * 64 + "  m.joblib\n")
    with pytest.raises(ValueError, match="does not match"):
        load_bundle(path)
    sha.unlink()
    with pytest.raises(ValueError, match="missing"):
        load_bundle(path)
    assert load_bundle(path, trust_unverified=True).model_name == "rf"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_bundle_refused_when_group_or_world_writable(tmp_path):
    bundle, _ = train_bundle(synthetic(), META, model="rf")
    path = save_bundle(bundle, tmp_path / "m.joblib")
    for mode in (0o664, 0o646, 0o666):
        path.chmod(mode)
        with pytest.raises(ValueError, match="writable"):
            load_bundle(path)
        assert load_bundle(path, trust_unverified=True)
    path.chmod(0o640)
    assert load_bundle(path)


def test_training_uses_all_cores_and_mlp_early_stopping():
    from idps.detect.models import build_model
    assert build_model("xgboost").get_params()["n_jobs"] == -1
    assert build_model("rf").get_params()["n_jobs"] == -1
    mlp = build_model("mlp").named_steps["mlp"]
    assert mlp.early_stopping is True and mlp.random_state is not None
    assert build_model("xgboost", n_classes=2).get_params()["objective"] == "binary:logistic"
