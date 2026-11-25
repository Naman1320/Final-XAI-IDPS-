import json
import statistics
import time

import numpy as np
import pytest
from test_detect import LABELLED, META, synthetic

from idps.detect.bundle import save_bundle
from idps.detect.train import train_bundle
from idps.explain.__main__ import main
from idps.explain.faithfulness import faithfulness
from idps.explain.global_explain import global_importance, save_summary_plot
from idps.explain.lime_explain import lime_explain
from idps.explain.shap_explain import Explainer
from idps.features import MODEL_FEATURES, write_features

DATA = synthetic(per_class=60)
BINARY = DATA[DATA.label != "PortScan"].reset_index(drop=True)
# Only these features differ between the classes (the rest are constant zeros).
INFORMATIVE = {"dst_port", "fwd_packets", "fwd_bytes", "rst_count"}


@pytest.fixture(scope="module")
def bundles():
    return {name: train_bundle(DATA, META, model=name)[0] for name in ("xgboost", "rf", "mlp")}


@pytest.fixture(scope="module")
def binary_bundles():
    return {name: train_bundle(BINARY, META, model=name)[0] for name in ("xgboost", "rf")}


def _explainer(bundle):
    return Explainer(bundle, background=DATA.sample(30, random_state=0))


def _check_record(rec, bundle, top_k):
    assert json.loads(json.dumps(rec)) == rec  # plain JSON types only
    assert rec["predicted_class"] in set(bundle.label_encoder.classes_)
    assert 0.0 <= rec["confidence"] <= 1.0
    assert isinstance(rec["base_value"], float)
    top = rec["top_features"]
    assert len(top) == top_k
    for t in top:
        assert set(t) == {"feature", "value", "contribution"}
        assert t["feature"] in MODEL_FEATURES
        assert type(t["value"]) is float and type(t["contribution"]) is float
    mags = [abs(t["contribution"]) for t in top]
    assert mags == sorted(mags, reverse=True)


@pytest.mark.parametrize("name", ["xgboost", "rf", "mlp"])
def test_shap_records_shape_and_json(bundles, name):
    b = bundles[name]
    rows = DATA.iloc[[0, 70, 130]]  # one of each class
    recs = _explainer(b).explain(rows, top_k=5)
    assert len(recs) == 3
    for r in recs:
        _check_record(r, b, 5)
    assert [r["predicted_class"] for r in recs] == ["BENIGN", "DoS", "PortScan"]
    # a single Series or dict also works, and still returns a list
    assert len(_explainer(b).explain(DATA.iloc[0])) == 1
    assert len(_explainer(b).explain(DATA.iloc[0].to_dict())) == 1


def test_shap_missing_column_and_mlp_needs_background(bundles):
    with pytest.raises(ValueError, match="missing"):
        _explainer(bundles["rf"]).explain(DATA[["dst_port"]])
    with pytest.raises(ValueError, match="background"):
        Explainer(bundles["mlp"])


def test_top_k_ordering_and_top_features_are_informative(bundles):
    ex = _explainer(bundles["xgboost"])
    rec = ex.explain(DATA.iloc[[70]], top_k=len(MODEL_FEATURES))[0]
    mags = [abs(t["contribution"]) for t in rec["top_features"]]
    assert mags == sorted(mags, reverse=True) and len(mags) == len(MODEL_FEATURES)
    assert {t["feature"] for t in rec["top_features"][:2]} <= INFORMATIVE
    small = ex.explain(DATA.iloc[[70]], top_k=3)[0]["top_features"]
    assert small == rec["top_features"][:3]


@pytest.mark.parametrize("name", ["xgboost", "rf", "mlp"])
@pytest.mark.parametrize("binary", [False, True])
def test_shap_additivity(bundles, binary_bundles, name, binary):
    if binary and name == "mlp":
        pytest.skip("binary MLP covered by multi-class path")
    b = (binary_bundles if binary else bundles)[name]
    data = BINARY if binary else DATA
    X = data.sample(20, random_state=1)
    ex = _explainer(b)
    values, base = ex.shap_values(X)
    assert values.shape == (20, len(MODEL_FEATURES), len(b.label_encoder.classes_))
    total = base[None, :] + values.sum(axis=1)  # (n, classes)
    if name == "xgboost":  # log-odds space
        margin = b.model.predict(X[b.features], output_margin=True)
        if binary:
            margin = np.stack([-margin, margin], axis=1)
        np.testing.assert_allclose(total, margin, atol=1e-3)
        assert ex.output_space == "log_odds"
    else:  # probability space
        np.testing.assert_allclose(total, b.predict_proba(X), atol=1e-3)
        assert ex.output_space == "probability"
    # records agree with the matrix: full-length record contributions + base = class output
    rec = ex.explain(X.iloc[[0]], top_k=len(MODEL_FEATURES))[0]
    c = list(b.label_encoder.classes_).index(rec["predicted_class"])
    assert rec["base_value"] + sum(t["contribution"] for t in rec["top_features"]) == \
        pytest.approx(total[0, c], abs=1e-3)


@pytest.mark.parametrize("name", ["xgboost", "rf"])
def test_binary_records(binary_bundles, name):
    b = binary_bundles[name]
    recs = _explainer(b).explain(BINARY.iloc[[0, 70]], top_k=4)
    for r in recs:
        _check_record(r, b, 4)
    assert [r["predicted_class"] for r in recs] == ["BENIGN", "DoS"]


def test_tree_latency_smoke(bundles):
    for name in ("xgboost", "rf"):
        ex = _explainer(bundles[name])
        ex.explain(DATA.iloc[[0]])  # warm up
        times = []
        for i in range(20):
            t = time.perf_counter()
            ex.explain(DATA.iloc[[i * 10]])
            times.append((time.perf_counter() - t) * 1000)
        med = statistics.median(times)
        print(f"{name}: median {med:.1f} ms per alert")
        assert med < 50, f"{name} median {med:.1f} ms exceeds the 50 ms budget"


def test_lime_shape_and_reproducible(bundles):
    b = bundles["xgboost"]
    bg = DATA.sample(100, random_state=0)
    row = DATA.iloc[70]
    a = lime_explain(b, row, bg, num_features=5, seed=7)
    again = lime_explain(b, row, bg, num_features=5, seed=7)
    assert a == again
    _check_record(a, b, 5)
    assert a["method"] == "lime" and a["predicted_class"] == "DoS"
    assert {t["feature"] for t in a["top_features"][:2]} <= INFORMATIVE
    other = lime_explain(b, row, bg, num_features=5, seed=8)
    assert other["top_features"] != a["top_features"] or other != a  # seed matters
    # same keys as SHAP records
    shap_rec = _explainer(b).explain(DATA.iloc[[70]])[0]
    assert set(shap_rec) == set(a)


def test_global_importance_and_plot(bundles, tmp_path):
    ex = _explainer(bundles["xgboost"])
    imp = global_importance(ex, DATA, sample=100)
    assert json.loads(json.dumps(imp)) == imp
    assert set(imp["classes"]) == {"BENIGN", "DoS", "PortScan"}
    for items in imp["classes"].values():
        vals = [i["importance"] for i in items]
        assert vals == sorted(vals, reverse=True) and len(items) == len(MODEL_FEATURES)
        assert items[0]["feature"] in INFORMATIVE
    png = tmp_path / "g.png"
    save_summary_plot(imp, str(png))
    assert png.read_bytes()[:4] == b"\x89PNG"


@pytest.mark.parametrize("name", ["xgboost", "rf"])
def test_faithfulness_topk_beats_random(bundles, name):
    res = faithfulness(bundles[name], DATA, n=60, k=3, repeats=10, lime_samples=500)
    assert json.loads(json.dumps(res)) == res
    rand = res["random"]["mean_drop"]
    for method in ("shap", "lime"):
        assert res["methods"][method]["mean_drop"] > rand + 0.1, (method, res)
    assert res["methods"]["shap"]["share_flows_beating_random"] > 0.5
    assert res["config"]["n_flows"] == 60


def test_faithfulness_is_reproducible(bundles):
    kw = {"n": 20, "k": 3, "repeats": 5, "include_lime": False}
    assert faithfulness(bundles["rf"], DATA, **kw) == faithfulness(bundles["rf"], DATA, **kw)


def test_cli_flow_global_faithfulness(tmp_path, capsys):
    bundle, _ = train_bundle(DATA, META, model="xgboost")
    model = save_bundle(bundle, tmp_path / "m.joblib")
    feats = tmp_path / "f.parquet"
    write_features(DATA, feats, LABELLED)

    assert main(["flow", str(model), str(feats), "--row", "70", "--top-k", "3"]) == 0
    rec = json.loads(capsys.readouterr().out)
    assert rec["predicted_class"] == "DoS" and len(rec["top_features"]) == 3
    assert main(["flow", str(model), str(feats), "--row", "70", "--method", "lime"]) == 0
    assert json.loads(capsys.readouterr().out)["method"] == "lime"
    assert main(["flow", str(model), str(feats), "--row", "99999"]) == 2

    out, png = tmp_path / "g.json", tmp_path / "g.png"
    assert main(["global", str(model), str(feats), "-o", str(out), "--plot", str(png),
                 "--sample", "50"]) == 0
    assert "classes" in json.loads(out.read_text()) and png.exists()

    out = tmp_path / "faith.json"
    assert main(["faithfulness", str(model), str(feats), "-o", str(out), "-n", "20",
                 "--repeats", "3", "--lime-samples", "300"]) == 0
    assert set(json.loads(out.read_text())["methods"]) == {"shap", "lime"}


def test_the_real_faithfulness_output_loads_for_the_sensor_status(bundles, tmp_path):
    """What faithfulness() really writes (not a hand-made dict) passes the sensor's loader and the
    SOC's schema, with a digest match when the report carries the bundle's digest."""
    from idps.live.faithfulness import load_faithfulness
    from soc.api.routes.sensors import Faithfulness

    digest = "ab" * 32
    res = faithfulness(bundles["xgboost"], DATA, n=40, k=3, repeats=5, lime_samples=300,
                       model_sha256=digest)
    path = tmp_path / "f.json"
    from idps.explain.faithfulness import write_json
    write_json(res, path)
    got = load_faithfulness(str(path), "xgboost", digest)
    assert got["model_check"] == "digest" and got["model_matches"] is True
    assert set(got["methods"]) == {"shap", "lime"}
    Faithfulness.model_validate(got)
    other = load_faithfulness(str(path), "xgboost", "cd" * 32)
    assert other["model_check"] == "digest" and other["model_matches"] is False
    legacy = load_faithfulness(str(path), "xgboost")  # sensor without a digest: weak, by name
    assert legacy["model_check"] == "name" and legacy["model_matches"] is True


def test_the_worst_outcomes_are_reported_not_dropped(bundles, tmp_path):
    """ratio_to_random is null when random removal changes nothing, negative when deleting the
    explanation raised confidence. Both reach the status."""
    import json as _json

    from idps.explain.faithfulness import write_json
    from idps.live.faithfulness import load_faithfulness
    from soc.api.routes.sensors import Faithfulness

    res = faithfulness(bundles["xgboost"], DATA, n=20, k=3, repeats=3, include_lime=False)
    res["methods"]["shap"]["ratio_to_random"] = None
    res["methods"]["shap"]["mean_drop"] = -0.2
    path = tmp_path / "f.json"
    write_json(res, path)
    got = load_faithfulness(str(path), "xgboost")
    assert got["methods"]["shap"]["ratio_to_random"] is None
    assert got["methods"]["shap"]["mean_drop"] == -0.2
    Faithfulness.model_validate(_json.loads(_json.dumps(got)))
    res["methods"]["shap"]["ratio_to_random"] = -12.5
    write_json(res, path)
    got = load_faithfulness(str(path), "xgboost")
    assert got["methods"]["shap"]["ratio_to_random"] == -12.5
    Faithfulness.model_validate(got)


def test_the_cli_writes_the_bundle_digest_into_the_report(tmp_path):
    from idps.detect.bundle import read_digest

    bundle, _ = train_bundle(DATA, META, model="xgboost")
    model = save_bundle(bundle, tmp_path / "m.joblib")
    feats = tmp_path / "f.parquet"
    write_features(DATA, feats, LABELLED)
    out = tmp_path / "faith.json"
    assert main(["faithfulness", str(model), str(feats), "-o", str(out), "-n", "10",
                 "--repeats", "2", "--no-lime"]) == 0
    sha = json.loads(out.read_text())["config"]["model_sha256"]
    assert sha == read_digest(model) and len(sha) == 64
