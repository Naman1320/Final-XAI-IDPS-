"""Drift: PSI math, levels, rolling window, sidecar handling, status report."""

import json

import numpy as np
import pandas as pd
import pytest

from idps.detect.drift import (
    MIN_WINDOW,
    DriftMonitor,
    NoDrift,
    build_reference,
    level_for,
    load_monitor,
    psi,
    read_reference,
    sidecar_path,
    write_reference,
)
from idps.features import MODEL_FEATURES

SHA = "d" * 64
FEATS = ["fwd_packets", "dst_port"]


def frame(n, seed=0, shift=0.0, scale=1.0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame({"fwd_packets": rng.normal(shift, scale, n),
                         "dst_port": rng.integers(0, 1000, n).astype(float)})


def monitor(window=1000, train=20_000):
    ref = build_reference(frame(train, seed=1), SHA, FEATS)
    return DriftMonitor(ref, window=window)


def test_psi_math_matches_the_formula():
    assert psi([0.5, 0.5], [0.5, 0.5]) == pytest.approx(0.0)
    expected = 0.4 * np.log(0.9 / 0.5) + (-0.4) * np.log(0.1 / 0.5)
    assert psi([0.5, 0.5], [0.9, 0.1]) == pytest.approx(expected)
    assert psi([0.5, 0.5], [0.9, 0.1]) == pytest.approx(psi([0.9, 0.1], [0.5, 0.5]))  # symmetric
    assert np.isfinite(psi([0.5, 0.5], [1.0, 0.0]))  # an empty bin does not blow up


def test_levels_at_the_thresholds():
    assert level_for(0.0) == "ok" and level_for(0.0999) == "ok"
    assert level_for(0.1) == "watch" and level_for(0.25) == "watch"
    assert level_for(0.2501) == "drift"


def test_reference_has_decile_edges_and_training_shares():
    df = pd.DataFrame({"fwd_packets": np.arange(1000.0), "dst_port": np.full(1000, 80.0)})
    ref = build_reference(df, SHA.upper(), FEATS)
    f = ref["features"]["fwd_packets"]
    assert len(f["edges"]) == 9 and f["proportions"] == pytest.approx([0.1] * 10, abs=0.01)
    assert sum(f["proportions"]) == pytest.approx(1.0)
    c = ref["features"]["dst_port"]  # a constant feature: one edge, everything in the first bin
    assert c["edges"] == [80.0] and c["proportions"] == [1.0, 0.0]
    assert ref["model_sha256"] == SHA and ref["rows"] == 1000


def test_reference_defaults_to_every_model_feature():
    df = pd.DataFrame(dict.fromkeys(MODEL_FEATURES, 1.0), index=range(50))
    assert list(build_reference(df, SHA)["features"]) == MODEL_FEATURES
    with pytest.raises(ValueError, match="missing"):
        build_reference(df.drop(columns=["fwd_packets"]), SHA)


def test_same_distribution_is_ok_and_a_shift_is_drift():
    m = monitor()
    m.update(frame(1000, seed=2))
    r = m.report()
    assert r["level"] == "ok" and r["psi_max"] < 0.1 and r["window"] == 1000
    assert r["reference_sha256"] == SHA and len(r["top"]) == 2
    m2 = monitor()
    m2.update(frame(1000, seed=2, shift=3.0))
    r2 = m2.report()
    assert r2["level"] == "drift" and r2["psi_max"] > 0.25
    assert r2["top"][0]["feature"] == "fwd_packets"  # the one that moved, not dst_port
    assert r2["top"][0]["psi"] > r2["top"][1]["psi"]


def test_a_modest_shift_is_watch():
    m = monitor(window=4000)
    m.update(frame(4000, seed=3, shift=0.4))
    assert m.report()["level"] == "watch"


def test_top_is_capped_at_five():
    names = MODEL_FEATURES[:8]
    ref = build_reference(pd.DataFrame(np.random.default_rng(0).normal(size=(2000, 8)),
                                       columns=names), SHA, names)
    m = DriftMonitor(ref, window=500)
    m.update(pd.DataFrame(np.random.default_rng(1).normal(2, 1, size=(500, 8)), columns=names))
    assert len(m.report()["top"]) == 5


def test_few_flows_are_warming_up_not_a_verdict():
    m = monitor()
    m.update(frame(MIN_WINDOW - 1, seed=2, shift=5.0))
    r = m.report()
    assert r["level"] == "unknown" and "warming up" in r["reason"] and "psi_max" not in r


def test_rolling_window_counts_equal_a_full_recount():
    ref = build_reference(frame(5000, seed=1), SHA, FEATS)
    m = DriftMonitor(ref, window=300, min_window=10)
    parts = [frame(n, seed=10 + i, shift=i * 0.5) for i, n in enumerate((120, 50, 400, 7, 250))]
    for p in parts:
        m.update(p)
    last = pd.concat(parts, ignore_index=True).iloc[-300:]
    fresh = DriftMonitor(ref, window=300, min_window=10)
    fresh.update(last)
    assert m.report()["window"] == 300
    assert (m._counts == fresh._counts).all()
    assert m.psi_by_feature() == pytest.approx(fresh.psi_by_feature())


def test_non_finite_values_do_not_break_the_window():
    m = monitor(window=300)
    df = frame(300, seed=2)
    df.loc[:5, "fwd_packets"] = [np.nan, np.inf, -np.inf, np.nan, 1.0, 2.0]
    m.update(df)
    assert m.report()["window"] == 300


# --- sidecar ----------------------------------------------------------------------------------

def test_missing_sidecar_is_unknown_with_a_reason(tmp_path):
    mon = load_monitor(tmp_path / "m.joblib", SHA)
    assert isinstance(mon, NoDrift)
    r = mon.report()
    assert r["level"] == "unknown" and "no drift reference" in r["reason"]
    mon.update(frame(5))  # harmless


def test_sidecar_with_another_models_sha_is_refused(tmp_path):
    model = tmp_path / "m.joblib"
    path = sidecar_path(model)
    path.write_text(json.dumps(build_reference(frame(500), "e" * 64, FEATS)))
    mon = load_monitor(model, SHA)
    assert isinstance(mon, NoDrift) and "different model" in mon.report()["reason"]
    assert isinstance(load_monitor(model, None), NoDrift)
    assert isinstance(load_monitor(model, "e" * 64), DriftMonitor)
    assert isinstance(load_monitor(model, ("E" * 64)), DriftMonitor)  # digest case does not matter


def test_unreadable_sidecar_is_unknown(tmp_path):
    model = tmp_path / "m.joblib"
    sidecar_path(model).write_text("{not json")
    r = load_monitor(model, SHA).report()
    assert r["level"] == "unknown" and "unreadable" in r["reason"]
    sidecar_path(model).write_text(json.dumps({"format": 1, "features": {"x": {"edges": [1],
                                                                                "proportions": [1]}}}))
    assert load_monitor(model, SHA).report()["level"] == "unknown"


def test_write_and_read_reference_round_trip(tmp_path):
    model = tmp_path / "m.joblib"
    df = pd.DataFrame(dict.fromkeys(MODEL_FEATURES, 0.0), index=range(10))
    path = write_reference(model, df, SHA)
    assert path == tmp_path / "m.joblib.drift.json"
    assert read_reference(path)["model_sha256"] == SHA
    assert isinstance(load_monitor(model, SHA), DriftMonitor)


# --- review fixes: corrupt sidecars never stop the sensor -------------------------------------

def good_ref(**over):
    ref = build_reference(frame(500), SHA, FEATS)
    return {**ref, **over}


@pytest.mark.parametrize("mutate", [
    lambda r: r["features"]["fwd_packets"].update(edges=["a", "b"]),
    lambda r: r["features"]["fwd_packets"].update(edges=[1.0, 1.0]),  # not increasing
    lambda r: r["features"]["fwd_packets"].update(edges=[5.0, 1.0]),
    lambda r: r["features"]["fwd_packets"].update(edges=[1.0, float("nan")]),
    lambda r: r["features"]["fwd_packets"].update(edges=[1.0, float("inf")]),
    lambda r: r["features"]["fwd_packets"].update(proportions=[0.5, float("nan"), 0.5]),
    lambda r: r["features"]["fwd_packets"].update(proportions=[2.0, -1.0, 0.0]),
    lambda r: r["features"]["fwd_packets"].update(proportions=[1.0]),
    lambda r: r["features"]["fwd_packets"].update(edges=[True, 2.0]),
    lambda r: r["features"].update(fwd_packets=None),
    lambda r: r["features"].update(fwd_packets="x"),
    lambda r: r.update(model_sha256=None),
    lambda r: r.update(features={}),
    lambda r: r.update(format=99),
])
def test_a_corrupt_sidecar_is_unknown_with_a_reason_never_an_error(tmp_path, mutate):
    model = tmp_path / "m.joblib"
    ref = good_ref()
    mutate(ref)
    sidecar_path(model).write_text(json.dumps(ref))  # NaN/Infinity are written as such
    mon = load_monitor(model, SHA)
    assert isinstance(mon, NoDrift)
    r = mon.report()
    assert r["level"] == "unknown" and r["reason"]
    mon.update(frame(10))


def test_a_deeply_nested_or_binary_sidecar_is_unknown(tmp_path):
    model = tmp_path / "m.joblib"
    sidecar_path(model).write_text("[" * 100_000)
    assert load_monitor(model, SHA).report()["level"] == "unknown"
    sidecar_path(model).write_bytes(b"\xff\xfe\x00bad")
    assert load_monitor(model, SHA).report()["level"] == "unknown"


def test_unknown_reasons_fit_the_socs_limit_even_with_a_long_name(tmp_path):
    from soc.api.routes.sensors import DriftInfo

    model = tmp_path / ("m" * 200 + ".joblib")
    r = load_monitor(model, SHA).report()
    assert r["level"] == "unknown" and len(r["reason"]) <= 300
    DriftInfo.model_validate(r)
    nd = NoDrift("x\u202ey" * 400).report()
    assert len(nd["reason"]) <= 300 and "\u202e" not in nd["reason"]
    DriftInfo.model_validate(nd)
    sidecar_path(model).write_text("{" + "x" * 5000)
    DriftInfo.model_validate(load_monitor(model, SHA).report())
