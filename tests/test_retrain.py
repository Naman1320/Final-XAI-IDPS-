"""Retraining with analyst feedback: keep/reject logic, files, versions, drift sidecars."""

import hashlib
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from test_detect import DAY_MS, LABELLED, META, T0, synthetic

import idps.detect.retrain as retrain_mod
from idps.detect.__main__ import main
from idps.detect.bundle import (
    Bundle,
    load_bundle,
    model_version,
    read_digest,
    save_bundle,
)
from idps.detect.drift import read_reference, sidecar_path
from idps.detect.retrain import retrain, split_feedback
from idps.features import FEATURE_COLUMNS, read_features, write_features

VERSION_RE = re.compile(r"^xgboost-\d{12}-[0-9a-f]{8}$")


def feedback_rows(label, n, *, packets, port=8080, seed=5, start=0) -> pd.DataFrame:
    """Rows shaped like flows the model gets wrong: `label` on a flow with `packets` packets."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        r = dict.fromkeys(FEATURE_COLUMNS, 0)
        r.update(src_ip="10.0.0.9", dst_ip="10.0.0.2", src_port=4000 + i, dst_port=port,
                 protocol=6, start_ms=T0 + 6 * DAY_MS + i, end_ms=T0 + 6 * DAY_MS + i + 10,
                 fwd_packets=int(packets * rng.uniform(0.8, 1.2)),
                 fwd_bytes=int(packets * 60 * rng.uniform(0.8, 1.2)))
        r.update(label=label, alert_id=start + i)
        rows.append(r)
    return pd.DataFrame(rows)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    d = tmp_path_factory.mktemp("retrain")
    data = d / "base.parquet"
    write_features(synthetic(), data, LABELLED)
    current = d / "current.joblib"
    assert main(["train", str(data), "--model", "xgboost", "-o", str(current)]) == 0
    # busy BENIGN servers the model calls DoS (many packets, port 8080): the analysts' fix
    fp = d / "fp.parquet"
    write_features(feedback_rows("BENIGN", 40, packets=2000), fp, META)
    # poison: DoS-looking flows labelled PortScan, counted 1000x: ruins the base test split
    poison = d / "poison.parquet"
    write_features(pd.concat([feedback_rows("PortScan", 40, packets=2000, port=80),
                              feedback_rows("BENIGN", 4, packets=20, port=443, start=100)]),
                   poison, META)
    return {"dir": d, "data": data, "current": current, "fp": fp, "poison": poison}


def run(world, tmp_path, feedback, out_name="new.joblib", *extra):
    out = tmp_path / out_name
    code = main(["retrain", "--data", str(world["data"]), "--feedback", str(feedback),
                 "--current", str(world["current"]), "-o", str(out),
                 "--report", str(tmp_path / "rep.json"), *extra])
    return code, out, json.loads((tmp_path / "rep.json").read_text()) \
        if (tmp_path / "rep.json").exists() else None


# --- train: version and sidecar ---------------------------------------------------------------

def test_train_writes_a_version_and_a_drift_sidecar(world):
    cur = world["current"]
    bundle = load_bundle(cur)
    assert VERSION_RE.match(bundle.version)
    ref = read_reference(sidecar_path(cur))
    assert ref["model_sha256"] == read_digest(cur)
    assert set(ref["features"]) >= set(bundle.features)
    assert ref["rows"] == bundle.split["parts"]["train"]["rows"]


# --- keep path --------------------------------------------------------------------------------

def test_a_better_model_is_kept_with_report_version_and_sidecar(world, tmp_path):
    before = hashlib.sha256(world["current"].read_bytes()).hexdigest()
    code, out, rep = run(world, tmp_path, world["fp"])
    assert code == 0 and out.exists()
    assert hashlib.sha256(world["current"].read_bytes()).hexdigest() == before  # never touched
    assert rep["decision"]["keep"] is True and rep["written"] is True
    assert rep["feedback_holdout"]["new"]["accuracy"] > rep["feedback_holdout"]["current"]["accuracy"]
    assert rep["base_test"]["new"]["macro_f1"] >= rep["criteria"]["min_macro_f1"]
    assert rep["data"]["feedback_train_rows"] + rep["data"]["feedback_holdout_rows"] == 40
    new = load_bundle(out)
    assert VERSION_RE.match(new.version) and new.version != load_bundle(world["current"]).version
    assert new.split["retrain"]["parent_sha256"] == read_digest(world["current"])
    assert new.split["retrain"]["parent_version"] == load_bundle(world["current"]).version
    assert read_reference(sidecar_path(out))["model_sha256"] == read_digest(out)
    # the model learned the analysts' verdict
    X = feedback_rows("BENIGN", 10, packets=2000, seed=99)
    assert set(new.predict(X)) == {"BENIGN"}
    assert "DoS" in set(load_bundle(world["current"]).predict(X))


def test_the_default_report_path_is_named_after_the_version(world, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "n.joblib"
    code = main(["retrain", "--data", str(world["data"]), "--feedback", str(world["fp"]),
                 "--current", str(world["current"]), "-o", str(out)])
    assert code == 0
    (rep,) = list((tmp_path / "reports").glob("retrain_*.json"))
    assert rep.name == f"retrain_{load_bundle(out).version}.json"


# --- reject path ------------------------------------------------------------------------------

def test_a_worse_model_exits_3_writes_nothing_and_keeps_an_existing_output(world, tmp_path, capsys):
    out = tmp_path / "existing.joblib"
    out.write_bytes(b"precious")
    code, _, rep = run(world, tmp_path, world["poison"], "existing.joblib",
                       "--feedback-weight", "1000")
    assert code == 3
    assert out.read_bytes() == b"precious"
    assert not Path(f"{out}.sha256").exists() and not sidecar_path(out).exists()
    assert rep["decision"]["keep"] is False and rep["written"] is False
    assert rep["new"]["output"] is None and rep["criteria"]["macro_f1_ok"] is False
    err = capsys.readouterr().err
    assert "rejected: macro-F1 on the base test split fell" in err and "NOT written" in err


def test_tolerance_decides_the_f1_criterion(world, tmp_path):
    # An absurd tolerance lets the poisoned model through on (a); (b) passes too.
    code, out, rep = run(world, tmp_path, world["poison"], "t.joblib",
                         "--feedback-weight", "1000", "--tolerance", "1.0")
    assert code == 0 and out.exists() and rep["criteria"]["macro_f1_ok"] is True


def _fake_eval(monkeypatch, *, f1_new, acc_cur, acc_new):
    def fake(bundle, df):
        is_new = bundle.version is not None and "retrain" in bundle.split
        if len(df) == retrain_state["holdout"]:
            return {"n": len(df), "accuracy": acc_new if is_new else acc_cur, "macro_f1": 0.5,
                    "benign_false_positive_rate": 0.0}
        return {"n": len(df), "accuracy": 1.0, "macro_f1": f1_new if is_new else 0.90,
                "benign_false_positive_rate": 0.0}
    retrain_state = {"holdout": 12}
    monkeypatch.setattr(retrain_mod, "evaluate_on", fake)


@pytest.mark.parametrize("f1_new, acc_new, keep, mentions", [
    (0.90, 0.80, False, "feedback holdout"),
    (0.896, 0.80, False, "feedback holdout"),
    (0.894, 0.90, False, "base test split"),  # 0.90 - 0.005 = 0.895 is the floor
    (0.895, 0.90, True, None),                  # exactly at the floor, equal accuracy: kept
    (0.95, 0.95, True, None),
])
def test_decision_boundaries(world, monkeypatch, f1_new, acc_new, keep, mentions):
    base, meta = pd.read_parquet(world["data"]), LABELLED
    fb = feedback_rows("BENIGN", 40, packets=2000)  # 12 of 40 go to the holdout
    cur = load_bundle(world["current"])
    _fake_eval(monkeypatch, f1_new=f1_new, acc_cur=0.90, acc_new=acc_new)
    res = retrain(base, meta, fb, META, cur, tolerance=0.005)
    assert res.report["data"]["feedback_holdout_rows"] == 12
    assert res.keep is keep
    reasons = " ".join(res.report["decision"]["reasons"])
    assert (mentions in reasons) if mentions else reasons == ""


# --- refusals ---------------------------------------------------------------------------------

def test_output_may_not_be_the_current_model(world, tmp_path, capsys):
    before = world["current"].read_bytes()
    for spelling in (world["current"], world["current"].parent / "." / world["current"].name):
        code = main(["retrain", "--data", str(world["data"]), "--feedback", str(world["fp"]),
                     "--current", str(world["current"]), "-o", str(spelling),
                     "--report", str(tmp_path / "r.json")])
        assert code == 2
    assert "must not be the --current model" in capsys.readouterr().err
    assert world["current"].read_bytes() == before and not (tmp_path / "r.json").exists()


def test_output_may_not_be_a_link_to_the_current_model(world, tmp_path):
    link = tmp_path / "link.joblib"
    link.symlink_to(world["current"])
    code = main(["retrain", "--data", str(world["data"]), "--feedback", str(world["fp"]),
                 "--current", str(world["current"]), "-o", str(link)])
    assert code == 2


def test_feedback_from_another_extraction_is_refused(world, tmp_path, capsys):
    from idps.features import extraction_meta

    bad = tmp_path / "bad.parquet"
    write_features(feedback_rows("BENIGN", 10, packets=20), bad, extraction_meta("nfstream", 120, 120))
    code, out, _ = run(world, tmp_path, bad)
    assert code == 2 and not out.exists() and "differ" in capsys.readouterr().err


def test_feedback_without_metadata_or_columns_is_refused(world, tmp_path, capsys):
    nometa = tmp_path / "nometa.parquet"
    feedback_rows("BENIGN", 10, packets=20).to_parquet(nometa)
    assert run(world, tmp_path, nometa)[0] == 2
    nocol = tmp_path / "nocol.parquet"
    write_features(feedback_rows("BENIGN", 10, packets=20).drop(columns=["fwd_packets"]),
                   nocol, META)
    assert run(world, tmp_path, nocol)[0] == 2
    assert "missing column" in capsys.readouterr().err


def test_too_little_feedback_to_hold_anything_out_is_refused(world, tmp_path, capsys):
    one = tmp_path / "one.parquet"
    write_features(feedback_rows("BENIGN", 1, packets=20), one, META)
    code, out, _ = run(world, tmp_path, one)
    assert code == 2 and "too small" in capsys.readouterr().err and not out.exists()


# --- split_feedback ---------------------------------------------------------------------------

def test_feedback_split_is_by_time_per_label():
    fb = pd.concat([feedback_rows("BENIGN", 20, packets=20),
                    feedback_rows("DoS", 10, packets=2000, start=100),
                    feedback_rows("Bot", 1, packets=5, start=200)]).sample(frac=1, random_state=0)
    tr, ho = split_feedback(fb)
    assert ho["label"].value_counts().to_dict() == {"BENIGN": 6, "DoS": 3}
    assert tr["label"].value_counts().to_dict() == {"BENIGN": 14, "DoS": 7, "Bot": 1}
    assert not set(tr["alert_id"]) & set(ho["alert_id"])
    for label in ("BENIGN", "DoS"):  # the holdout is the NEWEST rows of each label
        assert tr[tr.label == label].end_ms.max() <= ho[ho.label == label].end_ms.min()
    assert list(split_feedback(fb)[1]["alert_id"]) == list(ho["alert_id"])  # deterministic


def test_empty_feedback_is_a_friendly_error():
    with pytest.raises(ValueError, match="no usable rows"):
        split_feedback(feedback_rows("BENIGN", 3, packets=20).iloc[:0])


def test_two_rows_of_a_label_put_one_on_each_side():
    tr, ho = split_feedback(feedback_rows("BENIGN", 2, packets=20))
    assert len(tr) == 1 and len(ho) == 1


# --- drift-reference CLI ----------------------------------------------------------------------

def test_drift_reference_for_an_existing_model(world, tmp_path, capsys):
    model = tmp_path / "m.joblib"
    save_bundle(load_bundle(world["current"]), model)  # a model without a sidecar
    assert not sidecar_path(model).exists()
    assert main(["drift-reference", "--model", str(model), "--data", str(world["data"])]) == 0
    ref = read_reference(sidecar_path(model))
    assert ref["model_sha256"] == read_digest(model)
    assert ref["rows"] == load_bundle(model).split["parts"]["train"]["rows"]
    assert ref == {**read_reference(sidecar_path(world["current"])),
                   "model_sha256": ref["model_sha256"], "created_at": ref["created_at"]}


def test_drift_reference_refuses_data_the_model_did_not_train_on(world, tmp_path, capsys):
    other = tmp_path / "other.parquet"
    write_features(synthetic(days=5, per_class=25, seed=3), other, LABELLED)
    model = tmp_path / "m2.joblib"
    save_bundle(load_bundle(world["current"]), model)
    assert main(["drift-reference", "--model", str(model), "--data", str(other)]) == 2
    assert "do not reproduce" in capsys.readouterr().err and not sidecar_path(model).exists()


# --- versions of old bundles ------------------------------------------------------------------

def test_a_bundle_saved_before_versions_reports_a_version_from_its_digest(world, tmp_path):
    b = load_bundle(world["current"])
    old = Bundle(b.model_name, b.model, b.label_encoder, b.features, b.extraction_meta, b.split,
                 b.metrics)
    del old.__dict__["version"]  # what an old pickle looks like
    path = save_bundle(old, tmp_path / "old.joblib")
    loaded = load_bundle(path)
    sha = read_digest(path)
    assert loaded.version is None
    assert model_version(loaded, sha) == f"xgboost-{sha[:8]}"
    assert model_version(loaded) == "xgboost-unversioned"


def test_the_shipped_week_model_still_loads_unchanged():
    path = Path(__file__).parent.parent / "models" / "week_xgboost.joblib"
    if not path.exists():
        pytest.skip("models/week_xgboost.joblib is not in this checkout")
    b = load_bundle(path)
    assert model_version(b, read_digest(path)) == f"xgboost-{read_digest(path)[:8]}"


def test_read_features_round_trips_the_feedback_file(world):
    df, meta = read_features(world["fp"])
    assert meta["feature_columns"] == FEATURE_COLUMNS and len(df) == 40


# --- review fixes -----------------------------------------------------------------------------

def test_a_model_without_some_features_retrains_and_gets_a_sidecar(world, tmp_path):
    noport = tmp_path / "noport.joblib"
    assert main(["train", str(world["data"]), "--model", "xgboost", "--drop-feature", "dst_port",
                 "-o", str(noport)]) == 0
    assert "dst_port" not in load_bundle(noport).features
    assert "dst_port" not in read_reference(sidecar_path(noport))["features"]
    out = tmp_path / "np2.joblib"
    code = main(["retrain", "--data", str(world["data"]), "--feedback", str(world["fp"]),
                 "--current", str(noport), "-o", str(out), "--report", str(tmp_path / "r.json"),
                 "--tolerance", "1.0", "--min-holdout", "1"])
    assert code == 0
    ref = read_reference(sidecar_path(out))
    assert ref["model_sha256"] == read_digest(out)
    assert "dst_port" not in ref["features"] and "dst_port" not in load_bundle(out).features
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".")) == []  # no temps


def test_a_failure_while_installing_leaves_nothing_behind(world, tmp_path, monkeypatch):
    existing = tmp_path / "existing.joblib"
    existing.write_bytes(b"precious")

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(retrain_mod.drift, "reference_text", boom)
    with pytest.raises(OSError, match="disk full"):
        main(["retrain", "--data", str(world["data"]), "--feedback", str(world["fp"]),
              "--current", str(world["current"]), "-o", str(existing),
              "--report", str(tmp_path / "r.json")])
    assert existing.read_bytes() == b"precious"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["existing.joblib", "r.json"]
    rep = json.loads((tmp_path / "r.json").read_text())
    assert rep["written"] is False and "disk full" in rep["error"]


def test_a_base_that_does_not_reproduce_the_model_is_refused(world, tmp_path, capsys):
    other = tmp_path / "other.parquet"
    write_features(synthetic(days=5, per_class=25, seed=3), other, LABELLED)
    out = tmp_path / "o.joblib"
    args = ["retrain", "--data", str(other), "--feedback", str(world["fp"]),
            "--current", str(world["current"]), "-o", str(out), "--report", str(tmp_path / "r.json"),
            "--tolerance", "1.0", "--min-holdout", "1"]
    assert main(args) == 2
    assert "do not reproduce" in capsys.readouterr().err and not out.exists()
    assert main([*args, "--allow-different-base"]) == 0
    rep = json.loads((tmp_path / "r.json").read_text())
    assert rep["data"]["base_override"] is True and rep["data"]["base_reproduces_current"] is False


def test_duplicate_feature_vectors_are_dropped_before_the_split(world, tmp_path):
    base = feedback_rows("BENIGN", 20, packets=2000)
    dup = pd.concat([base, base.assign(alert_id=base.alert_id + 1000)])  # same vectors, same label
    cur = load_bundle(world["current"])
    res = retrain(pd.read_parquet(world["data"]), LABELLED, dup, META, cur, min_holdout=1)
    d = res.report["data"]
    assert d["feedback_duplicates_dropped"] == 20 and d["feedback_rows"] == 20
    assert d["feedback_train_rows"] + d["feedback_holdout_rows"] == 20


def test_a_class_new_to_the_model_is_allowed_capped_and_reported(world):
    fb = pd.concat([feedback_rows("BENIGN", 20, packets=20), feedback_rows(
        "Heartbleed", 20, packets=3, port=443, start=100, seed=8)])
    cur = load_bundle(world["current"])
    res = retrain(pd.read_parquet(world["data"]), LABELLED, fb, META, cur, tolerance=1.0,
                  min_holdout=1, feedback_weight=50)
    assert "Heartbleed" not in cur.label_encoder.classes_
    assert "Heartbleed" in res.bundle.label_encoder.classes_
    d = res.report["data"]
    assert d["new_classes"] == ["Heartbleed"] and "weighted 1" in d["new_classes_note"]
    assert res.report["feedback_holdout"]["new"]["accuracy"] > \
        res.report["feedback_holdout"]["current"]["accuracy"]  # the current one cannot know it


def test_the_new_class_weight_is_capped(world, monkeypatch):
    seen = {}
    real = retrain_mod.train_all

    def spy(name, train, features, seed, weight):
        seen["w"] = weight
        return real(name, train, features, seed, weight)

    monkeypatch.setattr(retrain_mod, "train_all", spy)
    fb = pd.concat([feedback_rows("BENIGN", 20, packets=20), feedback_rows(
        "Heartbleed", 20, packets=300, port=443, start=100, seed=8)])
    retrain(pd.read_parquet(world["data"]), LABELLED, fb, META, load_bundle(world["current"]),
            tolerance=1.0, min_holdout=1, feedback_weight=50)
    w = seen["w"]  # feedback train rows come last, by label: 14 BENIGN, then 14 Heartbleed
    assert (w[-28:-14] == 50.0).all() and (w[-14:] == 1.0).all()  # known class 50x, new class 1x
    assert (w[:-28] == 1.0).all()


def test_empty_feedback_is_refused_with_a_clear_message(world, tmp_path, capsys):
    empty = tmp_path / "empty.parquet"
    write_features(feedback_rows("BENIGN", 3, packets=20).iloc[:0], empty, META)
    code, out, _ = run(world, tmp_path, empty)
    assert code == 2 and "no usable rows" in capsys.readouterr().err and not out.exists()


def test_a_holdout_that_is_too_small_never_keeps_the_model(world, tmp_path, capsys):
    small = tmp_path / "small.parquet"
    write_features(feedback_rows("BENIGN", 8, packets=2000), small, META)  # 2 held out
    code, out, rep = run(world, tmp_path, small)
    assert code == 3 and not out.exists()
    assert rep["criteria"]["holdout_size_ok"] is False and rep["criteria"]["min_holdout"] == 5
    assert "fewer than the 5" in capsys.readouterr().err
    code, out, rep = run(world, tmp_path, small, "ok.joblib", "--min-holdout", "2")
    assert code == 0 and rep["criteria"]["holdout_size_ok"] is True
