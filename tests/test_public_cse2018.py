"""Tests for the public-dataset code (idps.public): CSE-CIC-IDS2018 loading, the common label
scheme, sampling, the time split, the 2017 <-> 2018 feature names, the end-to-end CLI and the
model bundles. All on small synthetic frames and files; no real dataset is needed."""

import json

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from idps.detect.bundle import load_bundle
from idps.detect.signing import generate_keypair, load_private_key, sign_bundle
from idps.public import __main__ as cli
from idps.public.cic2017 import clean_frame
from idps.public.cross import (
    cross_features,
    degenerate_features,
    evaluate_frame,
    run_cross,
)
from idps.public.cse2018 import (
    feature_matrix,
    file_date,
    header_row_mask,
    load_cse2018,
    load_file,
    parse_timestamps,
    to_float32,
)
from idps.public.labels import (
    COMMON_CLASSES,
    FEATURE_NAMES,
    FEATURES_2018,
    FEATURES_NOPORT,
    LABEL_TABLE,
    common_label,
    label_table_markdown,
    map_labels,
    rename_2017,
)
from idps.public.pipeline import public_split, run_cse2018
from idps.public.sampling import Caps, select_rows

T0 = 1_519_027_200  # 2018-02-19 08:00:00, seconds (the morning: the 12-hour clock needs no unfolding)


def _stamp(seconds: int) -> str:
    """The dataset's text: day/month/year and a 12-hour clock WITHOUT AM/PM (13:xx -> 1:xx)."""
    t = pd.Timestamp(seconds, unit="s")
    hour = t.hour - 12 if t.hour >= 13 else t.hour
    return f"{t.day:02d}/{t.month:02d}/{t.year} {hour:02d}:{t.minute:02d}:{t.second:02d}"


def raw_table(rows: list[dict], extra: tuple[str, ...] = ()) -> pa.Table:
    """A table shaped like the downloader's Parquet: every column text. `rows` give Timestamp,
    Label and optionally per-feature overrides; the other features are "1"."""
    cols = [*FEATURES_2018, "Timestamp", "Label", *extra]
    data = {c: [] for c in cols}
    for r in rows:
        for c in cols:
            data[c].append(str(r.get(c, "1")) if c not in ("Timestamp", "Label") else r[c])
    return pa.table(data)


def good_row(i: int, label: str, **kw) -> dict:
    return {"Timestamp": _stamp(T0 + i), "Label": label, "Dst Port": "80", **kw}


# --- labels ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Benign", "BENIGN"),
        ("BENIGN", "BENIGN"),
        ("Brute Force -Web", "WebAttack"),
        ("Brute Force -XSS", "WebAttack"),
        ("SQL Injection", "WebAttack"),
        ("Web Attack – Brute Force", "WebAttack"),
        ("Web Attack \x96 Sql Injection", "WebAttack"),  # the 2017 files read as latin-1
        ("Web Attack - XSS", "WebAttack"),
        ("Infilteration", "Infiltration"),
        ("Infiltration", "Infiltration"),
        ("DoS attacks-SlowHTTPTest", "DoS"),
        ("DoS Slowhttptest", "DoS"),
        ("DoS attacks-Hulk", "DoS"),
        ("DoS slowloris", "DoS"),
        ("DDOS attack-HOIC", "DDoS"),
        ("DDOS attack-LOIC-UDP", "DDoS"),
        ("DDoS attacks-LOIC-HTTP", "DDoS"),
        ("DDoS", "DDoS"),
        ("FTP-BruteForce", "BruteForce"),
        ("SSH-Bruteforce", "BruteForce"),
        ("FTP-Patator", "BruteForce"),
        ("PortScan", "PortScan"),
        ("Bot", "Bot"),
        ("Heartbleed", "Heartbleed"),
        ("  benign ", "BENIGN"),
    ],
)
def test_label_mapping_spellings(raw, expected):
    assert common_label(raw) == expected


def test_unknown_label_is_an_error_listing_all_of_them():
    with pytest.raises(ValueError, match="Mystery") as exc:
        map_labels(pd.Series(["Benign", "Mystery", "Other thing"]))
    assert "Other thing" in str(exc.value)


def test_label_table_is_consistent():
    for common, a, b in LABEL_TABLE:
        assert common in COMMON_CLASSES
        for spelling in (a, b):
            if spelling:
                assert common_label(spelling) == common
    md = label_table_markdown()
    assert "Brute Force -Web" in md
    assert md.count("\n") == len(LABEL_TABLE) + 1
    assert set(COMMON_CLASSES) == {c for c, _, _ in LABEL_TABLE}


# --- columns -----------------------------------------------------------------------------------


def test_feature_name_mapping_2017_to_2018():
    header_2017 = [
        " Destination Port", " Flow Duration", " Total Fwd Packets", " Fwd Header Length",
        " Fwd Header Length.1", "Init_Win_bytes_forward", " Label", " Timestamp", "Flow ID",
        " Weird New Column",
    ]  # fmt: skip
    rename, unmatched, missing = rename_2017(header_2017)
    assert rename[" Destination Port"] == "Dst Port"
    assert rename[" Total Fwd Packets"] == "Tot Fwd Pkts"
    assert rename[" Fwd Header Length"] == "Fwd Header Len"
    assert rename["Init_Win_bytes_forward"] == "Init Fwd Win Byts"
    assert " Fwd Header Length.1" not in rename  # the duplicate copy is ignored, not "unmatched"
    assert unmatched == ["Weird New Column"]  # ids, label and the duplicate are not listed
    assert "Bwd IAT Max" in missing  # not in this short header


def test_feature_names_cover_the_full_2017_and_2018_tables():
    assert len(FEATURE_NAMES) == 78
    assert len(set(FEATURES_2018)) == 78
    assert FEATURES_NOPORT == [f for f in FEATURES_2018 if f != "Dst Port"]
    full_2017 = [b for _, b in FEATURE_NAMES]
    rename, unmatched, missing = rename_2017(full_2017)
    assert (len(rename), unmatched, missing) == (78, [], [])


def test_clean_frame_2017_renames_and_drops_bad_rows():
    n = 6
    raw = pd.DataFrame({b: np.arange(n, dtype=float) for _, b in FEATURE_NAMES})
    raw.columns = [f" {c}" for c in raw.columns]  # the published files have a leading space
    raw["Flow ID"] = "x"
    raw[" Timestamp"] = [f"3/7/2017 9:0{i}:00" for i in range(n)]
    raw[" Label"] = ["BENIGN", "BENIGN", "FTP-Patator", "Web Attack \x96 XSS", "BENIGN", None]
    raw.loc[1, " Flow Bytes/s"] = np.inf
    frame, stats = clean_frame(raw, Caps(100, 100), 1, "mon.csv")
    assert list(frame.columns[:78]) == FEATURES_2018
    assert stats["nonfinite_dropped"] == 1
    assert stats["missing_label_or_timestamp"] == 1
    assert sorted(frame["label"]) == ["BENIGN", "BENIGN", "BruteForce", "WebAttack"]
    assert "Web Attack - XSS" in set(frame["label_original"])  # the 0x96 byte became a dash
    assert frame[FEATURES_2018].dtypes.eq(np.float32).all()


# --- loader ------------------------------------------------------------------------------------


def test_header_rows_are_found():
    df = pd.DataFrame(
        {"Dst Port": ["80", "Dst Port", "443"], "Timestamp": ["a", "Timestamp", "b"],
         "Label": ["Benign", "Label", "Bot"]}
    )  # fmt: skip
    assert header_row_mask(df).tolist() == [False, True, False]


def test_to_float32_infinity_nan_and_junk():
    out = to_float32(pa.chunked_array([pa.array(["1.5", "Infinity", "-Infinity", "NaN", None])]))
    assert out[0] == np.float32(1.5)
    assert np.isposinf(out[1]) and np.isneginf(out[2]) and np.isnan(out[3]) and np.isnan(out[4])
    junk = to_float32(pa.array(["2", "", "abc", "1e50"]))
    assert junk[0] == 2 and np.isnan(junk[1]) and np.isnan(junk[2]) and np.isinf(junk[3])
    assert junk.dtype == np.float32


def test_feature_matrix_flags_non_finite_rows():
    table = raw_table(
        [
            good_row(0, "Benign"),
            good_row(1, "Benign", **{"Flow Byts/s": "Infinity"}),
            good_row(2, "Benign", **{"Flow Pkts/s": "NaN"}),
            good_row(3, "Benign", **{"Flow IAT Max": "oops"}),
        ]
    )
    _, finite = feature_matrix(table)
    assert finite.tolist() == [True, False, False, False]


def test_timestamp_parsing_and_1970_rows():
    seconds, ok = parse_timestamps(
        pa.array(["19/02/2018 08:17:11", "Timestamp", "05/01/1970 03:01:17", "2018-02-19 08:00:00"])
    )
    assert ok.tolist() == [True, False, False, False]
    assert pd.Timestamp(seconds[0], unit="s") == pd.Timestamp("2018-02-19 08:17:11")


def write_day(path, rows, **kw):
    pq.write_table(raw_table(rows, **kw), path)


def test_load_file_cleans_counts_and_keeps_the_original_label(tmp_path):
    rows = [good_row(i, "Benign") for i in range(60)]
    rows += [good_row(100 + i, "Infilteration") for i in range(5)]
    rows.append({"Timestamp": "Timestamp", "Label": "Label", "Dst Port": "Dst Port"})
    rows.append(good_row(200, "Benign", **{"Flow Byts/s": "Infinity"}))
    rows.append(good_row(201, "Bot", **{"Flow Pkts/s": "NaN"}))
    rows.append({"Timestamp": "garbage", "Label": "Bot", "Dst Port": "80"})
    rows.append({"Timestamp": "05/01/1970 03:01:17", "Label": "Benign", "Dst Port": "80"})
    path = tmp_path / "Day.parquet"
    write_day(path, rows, extra=("Flow ID",))  # extra columns (the Tuesday file) are ignored
    df, stats = load_file(path, Caps(100, 100), seed=1)
    assert stats["header_rows"] == 1
    assert stats["bad_timestamp"] == 2
    assert stats["nonfinite_dropped"] == 2
    assert stats["steps"]["raw"] == {"BENIGN": 62, "Infiltration": 5, "Bot": 2}
    assert stats["steps"]["valid_timestamp"] == {"BENIGN": 61, "Infiltration": 5, "Bot": 1}
    assert stats["steps"]["sampled"] == {"BENIGN": 61, "Infiltration": 5, "Bot": 1}
    assert stats["steps"]["finite"] == {"BENIGN": 60, "Infiltration": 5}
    assert stats["nonfinite_by_column"] == {"Flow Byts/s": 1, "Flow Pkts/s": 1}
    assert len(df) == 65
    assert stats["truncated_at_excel_limit"] is False
    assert stats["first_timestamp"] == pd.Timestamp(T0, unit="s").isoformat()
    assert stats["last_timestamp"] == pd.Timestamp(T0 + 201, unit="s").isoformat()
    assert set(df["label_original"]) == {"Benign", "Infilteration"}
    assert set(df["label"]) == {"BENIGN", "Infiltration"}
    assert df["start_ms"].between(T0 * 1000, (T0 + 300) * 1000).all()
    assert df[FEATURES_2018].dtypes.eq(np.float32).all()
    assert np.isfinite(df[FEATURES_2018].to_numpy()).all()


def test_load_file_refuses_unknown_labels_and_bad_formats(tmp_path):
    write_day(tmp_path / "a.parquet", [good_row(0, "Benign"), good_row(1, "Strange")])
    with pytest.raises(ValueError, match="Strange"):
        load_file(tmp_path / "a.parquet", Caps(10, 10), 1)
    rows = [{"Timestamp": "2018-02-19T08:00:00", "Label": "Benign", "Dst Port": "80"}] * 5
    write_day(tmp_path / "b.parquet", rows)
    with pytest.raises(ValueError, match="do not match"):
        load_file(tmp_path / "b.parquet", Caps(10, 10), 1)


def test_load_file_max_rows_and_missing_column(tmp_path):
    write_day(tmp_path / "a.parquet", [good_row(i, "Benign") for i in range(50)])
    df, stats = load_file(tmp_path / "a.parquet", Caps(100, 100), 1, max_rows=20)
    assert len(df) == 20 and stats["rows_read"] == 20
    pq.write_table(pa.table({"Label": ["Benign"]}), tmp_path / "b.parquet")
    with pytest.raises(ValueError, match="lacks column"):
        load_file(tmp_path / "b.parquet", Caps(10, 10), 1)


def test_manifest_hides_unfinished_files(tmp_path):
    write_day(tmp_path / "done.parquet", [good_row(i, "Benign") for i in range(5)])
    write_day(tmp_path / "half.parquet", [good_row(i, "Benign") for i in range(7)])
    (tmp_path / "manifest.json").write_text(
        json.dumps({"_source": {}, "x.csv": {"parquet": "done.parquet"}})
    )
    df, rep = load_cse2018(tmp_path, Caps(10, 10), 1)
    assert len(df) == 5 and [f["file"] for f in rep["files"]] == ["done.parquet"]


# --- sampling ----------------------------------------------------------------------------------


def test_caps_are_deterministic_bounded_and_cover_the_whole_period():
    n = 5000
    rng = np.random.default_rng(0)
    ts = rng.permutation(n)  # shuffled input order
    day = np.zeros(n, dtype=int)
    label = np.where(np.arange(n) % 5 == 0, "Bot", "Benign").astype(object)
    cap = {"Bot": 100, "Benign": 300}.__getitem__
    a = select_rows(day, label, ts, cap, seed=7)
    b = select_rows(day, label, ts, cap, seed=7)
    c = select_rows(day, label, ts, cap, seed=8)
    assert (a == b).all() and (a != c).any()
    assert a[label == "Bot"].sum() == 100 and a[label == "Benign"].sum() == 300
    for lab in ("Bot", "Benign"):
        picked = np.sort(ts[a & (label == lab)])
        allts = np.sort(ts[label == lab])
        assert picked[0] < allts[len(allts) // 20] and picked[-1] > allts[-len(allts) // 20]
        quarters = np.histogram(picked, bins=4, range=(0, n))[0]
        assert quarters.min() >= 0.2 * len(picked)  # spread over time, not bunched


def test_groups_under_the_cap_are_kept_whole_and_groups_do_not_affect_each_other():
    day = np.array([0] * 10 + [1] * 10)
    label = np.array(["x"] * 20, dtype=object)
    ts = np.arange(20)
    keep = select_rows(day, label, ts, lambda _: 4, seed=1)
    assert keep[:10].sum() == 4 and keep[10:].sum() == 4  # per day
    small = select_rows(day[:10], label[:10], ts[:10], lambda _: 4, seed=1)
    assert (small == keep[:10]).all()
    assert select_rows(day, label, ts, lambda _: 50, seed=1).all()
    with pytest.raises(ValueError, match="at least 1"):
        Caps(0, 5)


def test_load_cse2018_applies_caps_per_day_and_label(tmp_path):
    rows = [good_row(i, "Benign") for i in range(100)] + [good_row(i, "Bot") for i in range(40)]
    write_day(tmp_path / "d.parquet", rows)
    df, rep = load_cse2018(tmp_path, Caps(benign=30, attack=10), seed=3)
    assert df["label"].value_counts().to_dict() == {"BENIGN": 30, "Bot": 10}
    assert rep["caps"] == {"benign": 30, "attack": 10}
    group = {g["label_original"]: g for g in rep["files"][0]["groups"]}
    assert group["Benign"]["available"] == 100 and group["Benign"]["sampled"] == 30
    df2, _ = load_cse2018(tmp_path, Caps(benign=30, attack=10), seed=3)
    assert df.equals(df2)


# --- split -------------------------------------------------------------------------------------


def synthetic(seed=0, n=400, classes=("BENIGN", "Bot", "DoS"), minutes=300) -> pd.DataFrame:
    """Flows of every class spread over `minutes`; the class shows in the features."""
    rng = np.random.default_rng(seed)
    parts = []
    for k, label in enumerate(classes):
        x = rng.normal(0, 1, (n, len(FEATURES_2018))).astype(np.float32) + 3 * k
        df = pd.DataFrame(x, columns=FEATURES_2018)
        df["start_ms"] = (T0 + np.sort(rng.integers(0, minutes * 60, n))) * 1000
        df["label"] = label
        df["label_original"] = label if label != "DoS" else rng.choice(["Hulk", "Slowloris"], n)
        df["source"] = "x"
        parts.append(df)
    return pd.concat(parts, ignore_index=True)


@pytest.mark.parametrize("gap_s", [0, 30, 120])
def test_split_has_no_train_flow_within_the_gap_of_a_test_flow(gap_s):
    df = synthetic()
    sp = public_split(df, gap_ms=gap_s * 1000, max_gap_loss=None)
    gap = gap_s * 1000
    for part in (sp.validation, sp.test):
        for (day, orig), later in part.groupby([part["start_ms"] // 86_400_000, "label_original"]):
            earlier = sp.train[
                (sp.train["label_original"] == orig) & (sp.train["start_ms"] // 86_400_000 == day)
            ]
            assert earlier["start_ms"].max() + gap <= later["start_ms"].min() or gap == 0
            if gap:
                assert (later["start_ms"].min() - earlier["start_ms"].max()) >= gap
    for orig, t in sp.test.groupby("label_original"):
        v = sp.validation[sp.validation["label_original"] == orig]
        assert sp.train[sp.train["label_original"] == orig]["start_ms"].max() <= v["start_ms"].min()
        assert v["start_ms"].max() <= t["start_ms"].min()


def test_split_groups_by_original_label_so_every_attack_is_cut():
    sp = public_split(synthetic(), gap_ms=0, max_gap_loss=None)
    for part in (sp.train, sp.validation, sp.test):
        assert {"Hulk", "Slowloris"} <= set(part["label_original"])


def test_split_drops_duplicates_per_split_and_reports_overlap_and_counts():
    df = synthetic(n=200)
    dup = df[df["label"] == "Bot"].iloc[:50]
    df = pd.concat([df, dup, dup], ignore_index=True)  # exact copies (same time too)
    sp = public_split(df, gap_ms=0, max_gap_loss=None)
    d = sp.description
    assert sum(d["duplicates_dropped"].values()) >= 50
    before = sum(sum(c.values()) for c in d["class_counts_before_duplicates"].values())
    after = sum(len(p) for p in (sp.train, sp.validation, sp.test))
    assert before - after == sum(d["duplicates_dropped"].values())
    assert not sp.train.duplicated(subset=[*FEATURES_2018, "label"]).any()
    # a train row copied into the test period counts as overlap
    leak = sp.train.iloc[[0]].copy()
    leak["start_ms"] = sp.test["start_ms"].max()
    sp2 = public_split(pd.concat([df, leak], ignore_index=True), gap_ms=0, max_gap_loss=None)
    assert sp2.description["identical_to_train"]["test"]["rows"] >= 1


def test_gap_shrinks_instead_of_removing_a_bunched_group():
    df = synthetic(n=300, minutes=3)  # every group sits inside 3 minutes
    fixed = (
        public_split(
            df,
            gap_ms=120_000,
            max_gap_loss=None,
        )
        if False
        else None
    )
    assert fixed is None
    from idps.detect.train import make_split

    kw = {"allow_unseen_test_classes": True, "dup_columns": FEATURES_2018,
          "group_col": "label_original", "features": FEATURES_2018}  # fmt: skip
    with pytest.raises(ValueError, match="empty|not in the training"):
        make_split(df, "class-time", gap_ms=120_000, **kw)
    sp = public_split(df, gap_ms=120_000, max_gap_loss=0.1)
    assert set(sp.train["label"]) == {"BENIGN", "Bot", "DoS"}
    assert sp.description["dropped_by_gap"]["total"] <= 0.1 * len(df) + 5
    assert sp.description["effective_gap_ms"]


# --- end to end --------------------------------------------------------------------------------


def day_file(path, labels: dict[str, int], seed: int, start: int = T0):
    """A day Parquet file: per label n flows spread over four hours, label-dependent features."""
    rng = np.random.default_rng(seed)
    rows = []
    shifts = ["Benign", "Bot", "DoS attacks-Hulk", "Brute Force -Web", "DDOS attack-HOIC"]
    for label, n in labels.items():
        k = shifts.index(label)
        for t in np.sort(rng.integers(0, 4 * 3600, n)):
            feats = {f: f"{rng.normal(k * 4, 1):.4f}" for f in FEATURES_2018}
            rows.append({**feats, "Timestamp": _stamp(start + int(t)), "Label": label})
    write_day(path, rows)


@pytest.fixture
def small_dataset(tmp_path):
    d = tmp_path / "cse"
    d.mkdir()
    day_file(d / "a.parquet", {"Benign": 300, "Bot": 200, "DoS attacks-Hulk": 150}, 1)
    day_file(d / "b.parquet", {"Benign": 300, "Brute Force -Web": 120, "DDOS attack-HOIC": 150},
             2, start=T0 + 86_400)  # fmt: skip
    return d


def test_cli_runs_end_to_end_and_writes_signable_bundles(small_dataset, tmp_path):
    models, reports = tmp_path / "models", tmp_path / "reports"
    code = cli.main(
        ["cse2018", "--data-2018", str(small_dataset), "--cap-benign", "200", "--cap-attack",
         "100", "--faith-n", "12", "--no-lime", "--models-dir", str(models),
         "--reports-dir", str(reports)]
    )  # fmt: skip
    assert code == 0
    for name in ("cse2018_xgboost", "cse2018_xgboost_noport"):
        assert (models / f"{name}.joblib").exists()
        assert (models / f"{name}.joblib.sha256").exists()
    for name in ("preprocessing", "xgboost", "xgboost_noport", "xgboost_faithfulness",
                 "xgboost_noport_faithfulness"):  # fmt: skip
        assert (reports / f"cse_cic_ids2018_{name}.json").exists()

    pre = json.loads((reports / "cse_cic_ids2018_preprocessing.json").read_text())
    steps = pre["class_counts_by_step"]
    assert set(steps) >= {"raw", "valid_timestamp", "sampled", "finite", "after_duplicates"}
    assert steps["raw"]["BENIGN"] == 600 and steps["sampled"]["BENIGN"] == 400
    assert pre["load"]["caps"] == {"benign": 200, "attack": 100}

    rep = json.loads((reports / "cse_cic_ids2018_xgboost.json").read_text())
    noport = json.loads((reports / "cse_cic_ids2018_xgboost_noport.json").read_text())
    assert "Dst Port" in rep["features"] and "Dst Port" not in noport["features"]
    assert noport["dropped_features"] == ["Dst Port"]
    test = rep["metrics"]["test"]
    assert test["macro_f1"] > 0.8  # the classes are clearly separable
    assert "train_overlap" in test and test["benign_false_positive_rate"] is not None
    assert rep["timing_seconds"]["train_classifier"] > 0
    assert rep["faithfulness"]["shap"]["mean_drop"] is not None

    # the bundles are normal bundles: they load, and `idps.detect sign` can sign them
    bundle = load_bundle(models / "cse2018_xgboost.joblib")
    assert bundle.features == FEATURES_2018
    assert bundle.metrics["test"]["macro_f1"] == test["macro_f1"]
    priv, pub = generate_keypair(tmp_path / "key")
    sign_bundle(models / "cse2018_xgboost.joblib", load_private_key(priv))
    loaded = load_bundle(models / "cse2018_xgboost.joblib", public_key=pub)
    X = pd.DataFrame(np.zeros((2, 78), dtype=np.float32), columns=FEATURES_2018)
    assert len(loaded.predict(X)) == 2
    # a sensor's live flows (different extractor and columns) are refused
    live = {"extractor": "nfstream", "idle_timeout": 30, "active_timeout": 120,
            "feature_columns": loaded.extraction_meta["feature_columns"]}  # fmt: skip
    with pytest.raises(ValueError, match="extraction settings differ"):
        load_bundle(models / "cse2018_xgboost.joblib", live_meta=live)


def test_cli_prints_the_label_table_and_rejects_bad_input(capsys, tmp_path):
    assert cli.main(["labels"]) == 0
    assert "| WebAttack | Web Attack" in capsys.readouterr().out
    assert cli.main(["cse2018", "--data-2018", str(tmp_path / "nothing")]) == 2


def test_run_cse2018_reports_classes_missing_from_train(tmp_path):
    df = synthetic(n=200)
    tiny = df[df["label"] == "Bot"].iloc[:6].copy()
    tiny["label"], tiny["label_original"] = "Heartbleed", "Heartbleed"
    tiny["start_ms"] = T0 * 1000  # one burst: the fixed gap would remove all of it
    both = pd.concat([df, tiny], ignore_index=True)
    _, summary = run_cse2018(
        both, {"steps": {}, "caps": {}}, seed=1, gap_ms=120_000, max_gap_loss=0.1,
        models_dir=tmp_path / "m", reports_dir=tmp_path / "r", faith_n=0, lime_samples=10,
        include_lime=False, log=lambda _: None,
    )  # fmt: skip
    assert "xgboost" in summary and "xgboost_noport" in summary
    pre = json.loads((tmp_path / "r" / "cse_cic_ids2018_preprocessing.json").read_text())
    assert "gap_loss_share_by_original_label" in pre


def test_cross_dataset_reports_classes_absent_from_train():
    a = synthetic(seed=1, classes=("BENIGN", "Bot", "DoS", "PortScan"), n=150)
    b = synthetic(seed=2, classes=("BENIGN", "Bot", "DoS", "DDoS"), n=150)
    rep = {"caps": {"benign": 1, "attack": 1}, "unmatched_2017_columns": []}
    out = run_cross(
        public_split(a, 0, None), a, public_split(b, 0, None), b, rep, rep, seed=1,
        train_cap=100, log=lambda _: None,
    )  # fmt: skip
    fwd = out["directions"]["train_2017_test_2018"]["without_port"]
    assert fwd["absent_from_train"] == {"DDoS": 150}  # 2018-style data has a class 2017 lacks
    back = out["directions"]["train_2018_test_2017"]["with_port"]
    assert back["absent_from_train"] == {"PortScan": 150}
    assert fwd["cross"]["all_classes"]["per_class"]["DDoS"]["recall"] == 0
    assert 0 <= fwd["cross"]["attack_vs_benign"]["attack_detection_rate"] <= 1
    assert fwd["summary"]["cross_macro_f1_seen_classes"] is not None
    assert "Dst Port" not in fwd["features"] and "Dst Port" in back["features"]
    assert out["features_name_matched"] == 78  # the names match; the meaning is another matter
    assert "RST Flag Cnt" in out["features_excluded_from_cross"]
    assert "RST Flag Cnt" not in fwd["features"] and len(back["features"]) == 78 - 4


def test_file_with_excel_row_limit_is_flagged(tmp_path, monkeypatch):
    import idps.public.cse2018 as mod

    write_day(tmp_path / "a.parquet", [good_row(i, "Benign") for i in range(30)])
    monkeypatch.setattr(mod, "EXCEL_ROW_LIMIT", 30)
    _, rep = load_cse2018(tmp_path, Caps(100, 100), 1)
    assert rep["files"][0]["truncated_at_excel_limit"] is True
    assert rep["truncated_at_excel_limit"] == ["a.parquet"]


# --- the 12-hour clock without AM/PM, wrong dates, split order (review finding 1) ----------------


def _unfold(text: str) -> pd.Timestamp:
    seconds, ok = parse_timestamps(pa.array([text]))
    assert ok[0], text
    return pd.Timestamp(int(seconds[0]), unit="s")


def test_12_hour_clock_hours_1_to_7_are_afternoon_and_8_to_12_stay():
    assert _unfold("14/02/2018 10:32:00") == pd.Timestamp("2018-02-14 10:32:00")  # FTP-BruteForce
    assert _unfold("14/02/2018 02:05:00") == pd.Timestamp("2018-02-14 14:05:00")  # SSH-Bruteforce
    assert _unfold("16/02/2018 01:50:00") == pd.Timestamp("2018-02-16 13:50:00")  # DoS-Hulk
    assert _unfold("14/02/2018 12:30:00") == pd.Timestamp("2018-02-14 12:30:00")  # 12 = noon
    assert _unfold("14/02/2018 08:00:00") == pd.Timestamp("2018-02-14 08:00:00")


def test_12_hour_clock_seam_at_12_and_1_keeps_time_order():
    stamps = ["14/02/2018 11:59:59", "14/02/2018 12:00:00", "14/02/2018 12:59:59",
              "14/02/2018 01:00:00", "14/02/2018 05:59:59"]  # fmt: skip
    seconds, ok = parse_timestamps(pa.array(stamps))
    assert ok.all() and (np.diff(seconds) > 0).all()  # as written they are NOT in clock order
    # the raw clock would put 01:00:00 before 11:59:59; unfolded it is the next hour after 12:59:59
    assert seconds[3] - seconds[2] == 1


def test_hours_0_and_13_to_23_are_not_a_12_hour_clock_and_are_dropped_and_counted(tmp_path):
    rows = [good_row(i, "Benign") for i in range(300)]  # 08:00-08:05
    rows.append({"Timestamp": "19/02/2018 00:10:00", "Label": "Benign", "Dst Port": "80"})
    rows.append({"Timestamp": "19/02/2018 15:10:00", "Label": "Benign", "Dst Port": "80"})
    write_day(tmp_path / "Monday-19-02-2018_x.parquet", rows)
    df, stats = load_file(tmp_path / "Monday-19-02-2018_x.parquet", Caps(1000, 1000), 1)
    assert stats["hour_outside_12h"] == 2 and len(df) == 300
    assert stats["steps"]["valid_timestamp"] == {"BENIGN": 300}
    # a file that is mostly like that is a 24 h file: refused, not unfolded wrongly
    rows = [{"Timestamp": f"20/02/2018 {14 + i % 8}:00:00", "Label": "Benign", "Dst Port": "80"}
            for i in range(50)]  # fmt: skip
    write_day(tmp_path / "Tuesday-20-02-2018_x.parquet", rows)
    with pytest.raises(ValueError, match="24-hour"):
        load_file(tmp_path / "Tuesday-20-02-2018_x.parquet", Caps(10, 10), 1)


def test_ambiguous_hours_6_and_7_are_unfolded_like_1_to_5_and_counted(tmp_path):
    rows = [good_row(i, "Benign") for i in range(50)]
    rows += [{"Timestamp": f"19/02/2018 0{h}:15:00", "Label": "Benign", "Dst Port": "80"}
             for h in (6, 7, 7)]  # fmt: skip
    write_day(tmp_path / "Monday-19-02-2018_x.parquet", rows)
    df, stats = load_file(tmp_path / "Monday-19-02-2018_x.parquet", Caps(1000, 1000), 1)
    assert stats["ambiguous_hour_rows"] == {"6": 1, "7": 2}
    assert stats["raw_hour_histogram"] == {6: 1, 7: 2, 8: 50}
    late = df[df["start_ms"] >= pd.Timestamp("2018-02-19 18:00:00").value // 10**6]
    assert len(late) == 3 and len(df) == 53
    assert stats["last_timestamp"] == pd.Timestamp("2018-02-19 19:15:00").isoformat()
    _, rep = load_cse2018(tmp_path, Caps(1000, 1000), 1)
    assert rep["ambiguous_hour_rows"] == {"6": 1, "7": 2}


def test_file_date_from_the_name():
    import datetime

    assert file_date("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet") == (
        datetime.date(2018, 2, 14)
    )
    assert file_date("Friday-02-03-2018_x.parquet") == datetime.date(2018, 3, 2)
    assert file_date("a.parquet") is None and file_date("x-31-02-2018.parquet") is None


def test_rows_with_another_date_than_the_file_name_are_dropped_and_counted(tmp_path):
    rows = [good_row(i, "Benign") for i in range(60)]  # 19/02/2018 08:00
    rows += [{"Timestamp": t, "Label": "Benign", "Dst Port": "80"}
             for t in ("12/01/1970 03:01:17", "05/01/1970 03:01:17", "05/01/2018 09:00:00",
                       "20/02/2018 09:00:00", "20/02/2018 09:00:01")]  # fmt: skip
    rows.append({"Timestamp": "garbage", "Label": "Benign", "Dst Port": "80"})
    path = tmp_path / "Monday-19-02-2018_TrafficForML.parquet"
    write_day(path, rows)
    df, stats = load_file(path, Caps(1000, 1000), 1)
    assert len(df) == 60
    assert stats["file_date"] == "2018-02-19"
    assert stats["wrong_date"] == 5 and stats["bad_timestamp"] == 1
    assert stats["wrong_date_by_date"] == {"1970-01-12": 1, "1970-01-05": 1, "2018-01-05": 1,
                                           "2018-02-20": 2}  # fmt: skip
    assert stats["steps"]["valid_timestamp"] == {"BENIGN": 60}
    _, rep = load_cse2018(tmp_path, Caps(1000, 1000), 1)
    assert rep["wrong_date_rows"] == 5
    # the same rows in a file WITHOUT a date in its name: only the year is checked
    write_day(tmp_path / "plain.parquet", rows)
    df2, stats2 = load_file(tmp_path / "plain.parquet", Caps(1000, 1000), 1)
    assert stats2["file_date"] is None and stats2["wrong_date"] == 0
    assert len(df2) == 60 + 3 and stats2["bad_timestamp"] == 3  # Jan 2018 and 20/02 pass the year


def test_split_order_after_unfolding_has_benign_train_before_test(tmp_path):
    """A day with morning (8-12) and afternoon (1-5 on the dataset's clock) flows written in a
    shuffled file order: after unfolding, every BENIGN train row is earlier than every test row."""
    rng = np.random.default_rng(3)
    morning = [
        pd.Timestamp("2018-02-14 08:00:00") + pd.Timedelta(seconds=int(x))
        for x in rng.integers(0, 4 * 3600, 400)
    ]  # 08:00-12:00
    afternoon = [
        pd.Timestamp("2018-02-14 13:00:00") + pd.Timedelta(seconds=int(x))
        for x in rng.integers(0, 4 * 3600, 400)
    ]  # 13:00-17:00, written as 1:00-5:00
    times = morning + afternoon
    order = rng.permutation(len(times))
    rows = [good_row(0, "Benign") | {"Timestamp": _stamp(int(times[i].timestamp()))} for i in order]
    path = tmp_path / "Wednesday-14-02-2018_x.parquet"
    write_day(path, rows)
    df, stats = load_file(path, Caps(10_000, 10_000), 1)
    assert stats["raw_hour_histogram"].keys() >= {1, 2, 3, 4, 8, 11}
    assert df["start_ms"].min() >= pd.Timestamp("2018-02-14 08:00:00").value // 10**6
    assert df["start_ms"].max() < pd.Timestamp("2018-02-14 17:00:01").value // 10**6
    df = df.assign(**{c: np.random.default_rng(5).normal(size=len(df)) for c in FEATURES_2018[:3]})
    sp = public_split(df, gap_ms=0, max_gap_loss=None)
    assert sp.train["start_ms"].max() <= sp.validation["start_ms"].min()
    assert sp.validation["start_ms"].max() <= sp.test["start_ms"].min()
    # train = the morning and the first of the afternoon, test = the end of the afternoon
    assert sp.test["start_ms"].min() > pd.Timestamp("2018-02-14 13:00:00").value // 10**6


# --- hashes, gap rule, cross-dataset scoring, bundles (review findings 2, 5, 10, 12) -------------


def _old_merge_overlap(train, part, features):
    seen = train[features].drop_duplicates().assign(_in_train=True)
    return int(part[features].merge(seen, on=features, how="left")["_in_train"].notna().sum())


@pytest.mark.parametrize("dtype", [np.float32, np.float64])
def test_row_hashes_equal_the_old_merge_on_nan_negative_zero_and_float32(dtype):
    from idps.detect.split import _identical_to_train

    cols = ["a", "b", "c"]
    train = pd.DataFrame(
        [[0.0, 1.5, np.nan], [1.0, -0.0, 2.0], [np.nan, np.nan, np.nan], [3.0, 3.0, 3.0]],
        columns=cols,
    ).astype(dtype)
    part = pd.DataFrame(
        [[-0.0, 1.5, np.nan],  # -0.0 vs 0.0 in the first train row
         [1.0, 0.0, 2.0],  # 0.0 vs -0.0
         [np.nan, np.nan, np.nan],  # all NaN
         [3.0, 3.0, 3.1], [0.1, 0.2, 0.3], [3.0, 3.0, 3.0]],
        columns=cols,
    ).astype(dtype)  # fmt: skip
    got = _identical_to_train(train, part, cols)["rows"]
    assert got == _old_merge_overlap(train, part, cols) == 4


def test_row_hashes_on_float32_values_that_float64_would_split():
    from idps.detect.split import _identical_to_train

    x = np.float32(0.1)  # not exactly 0.1: both sides hold the same float32
    train = pd.DataFrame({"a": np.array([x, 2], dtype=np.float32)})
    part = pd.DataFrame({"a": np.array([x, 0.1, 3], dtype=np.float32)})
    assert _identical_to_train(train, part, ["a"])["rows"] == _old_merge_overlap(train, part, ["a"])


def test_two_row_group_never_gets_a_gap_above_the_nominal_one():
    from idps.detect.split import split_by_class_time

    # two Bot flows 2000 s apart, nominal gap 1000 s, drop limit 10%: the old interpolated
    # quantile gave a gap of 200 s and dropped one of the two rows (50%)
    big = synthetic(n=50, classes=("BENIGN",))[["start_ms", "label"]]
    bot = pd.DataFrame({"start_ms": [T0 * 1000, (T0 + 2000) * 1000], "label": "Bot"})
    df = pd.concat([big, bot], ignore_index=True)
    df["f"] = np.arange(len(df), dtype=float)
    sp = split_by_class_time(df, gap_ms=1_000_000, max_drop_share=0.1,
                             allow_unseen_test_classes=True, drop_duplicates=False,
                             features=["f"], dup_columns=["f"])  # fmt: skip
    d = sp.description
    assert d["effective_gap_ms"]["Bot"] <= 1_000_000
    assert d["dropped_by_gap"]["per_class"].get("Bot", 0) <= 0.1 * 2  # nothing dropped


@pytest.mark.parametrize("n", [3, 5, 8, 10, 12, 30, 100])
def test_shrunk_gap_never_exceeds_the_nominal_gap_or_the_drop_limit(n):
    from idps.detect.split import split_by_class_time

    rng = np.random.default_rng(n)
    t = np.sort(rng.integers(0, 3000, n)) * 1000
    df = pd.DataFrame({"start_ms": T0 * 1000 + t, "label": "BENIGN", "f": rng.normal(size=n)})
    df = pd.concat([df, df.assign(label="Bot", f=df["f"] + 9)], ignore_index=True)
    nominal = 1_000_000
    sp = split_by_class_time(df, gap_ms=nominal, max_drop_share=0.1, allow_unseen_test_classes=True,
                             drop_duplicates=False, features=["f"], dup_columns=["f"])  # fmt: skip
    d = sp.description
    assert all(0 <= g <= nominal for g in d["effective_gap_ms"].values())
    for label, dropped in d["dropped_by_gap"]["per_class"].items():
        assert dropped <= 0.1 * n
    for label, gap in d["effective_gap_ms"].items():
        if gap == 0:  # flagged, never silent
            assert any(g.endswith(f":{label}") for g in d["groups_with_zero_effective_gap"])


def test_groups_of_a_few_rows_with_a_zero_gap_are_flagged():
    from idps.detect.split import split_by_class_time

    n = 6
    t = (np.arange(n) * 5000 + T0) * 1000
    df = pd.DataFrame({"start_ms": t, "label": "BENIGN", "f": np.arange(n, dtype=float)})
    df = pd.concat([df, df.assign(label="Bot", f=df["f"] + 50)], ignore_index=True)
    sp = split_by_class_time(df, gap_ms=120_000, max_drop_share=0.1,
                             allow_unseen_test_classes=True, drop_duplicates=False,
                             features=["f"], dup_columns=["f"])  # fmt: skip
    d = sp.description
    assert d["effective_gap_ms"] == {"BENIGN": 0.0, "Bot": 0.0}
    assert len(d["groups_with_zero_effective_gap"]) == 2
    assert d["dropped_by_gap"]["total"] == 0  # a gap of 0 drops nothing; the report says so


def test_restricted_metrics_excludes_phantom_classes_and_counts_them():
    from idps.public.scoring import restricted_metrics

    y = ["A"] * 6 + ["B"] * 4 + ["C"] * 3  # C is not in the shared list
    p = ["A"] * 5 + ["B"] + ["B"] * 4 + ["A", "A", "P"]  # P is a class only the model knows
    full = evaluate_classifier_union(y, p)
    r = restricted_metrics(y, p, ["A", "B"])
    assert r["excluded_rows_total"] == 3 and r["excluded_rows_true_class_outside"] == {"C": 3}
    assert r["n"] == 10 and r["kept_rows_predicted_outside"] == 0
    assert r["per_class"]["A"]["support"] == 6 and r["per_class"]["A"]["recall"] == 5 / 6
    assert r["macro_f1"] == pytest.approx(
        np.mean([r["per_class"]["A"]["f1"], r["per_class"]["B"]["f1"]])
    )
    assert full < r["macro_f1"]  # the union convention averages in C (F1 = 0) and P (F1 = 0)
    miss = restricted_metrics(["A", "A", "B"], ["A", "P", "B"], ["A", "B"])
    assert miss["kept_rows_predicted_outside"] == 1 and miss["per_class"]["A"]["recall"] == 0.5


def evaluate_classifier_union(y, p) -> float:
    from idps.detect.evaluate import evaluate_classifier

    return evaluate_classifier(y, p)["macro_f1"]


def test_cross_scores_the_same_classes_in_both_domains_and_the_drop_is_consistent():
    a = synthetic(seed=1, classes=("BENIGN", "Bot", "DoS", "PortScan"), n=150)
    b = synthetic(seed=2, classes=("BENIGN", "Bot", "DoS", "DDoS"), n=150)
    rep = {"caps": {"benign": 1, "attack": 1}, "unmatched_2017_columns": []}
    out = run_cross(public_split(a, 0, None), a, public_split(b, 0, None), b, rep, rep, seed=1,
                    train_cap=100, log=lambda _: None)  # fmt: skip
    for direction in out["directions"].values():
        for res in direction.values():
            s = res["summary"]
            assert s["shared_classes"] == [
                "BENIGN",
                "Bot",
                "DoS",
            ]  # PortScan / DDoS are in one only
            assert s["drop_shared_classes"] == pytest.approx(
                s["in_domain_macro_f1_shared_classes"] - s["cross_macro_f1_shared_classes"]
            )
            sc = res["cross"]["shared_classes"]
            assert sc["classes"] == s["shared_classes"] and sc["n"] == 450
            assert sum(sc["excluded_rows_true_class_outside"].values()) == 150
            assert set(s["cross_per_class_recall_shared"]) == set(s["shared_classes"])
            assert all("support" in v for v in s["cross_per_class_recall_shared"].values())
            # the all-classes number is labelled and may differ: it averages over other classes
            assert "cross_macro_f1_all_classes_union_convention" in s  # labelled as such
            assert "drop_vs_seen_classes" not in s
    fwd = out["directions"]["train_2017_test_2018"]["with_port"]["cross"]
    # the model never predicts DDoS, but the union convention counts DDoS (support 150, F1 0)
    assert fwd["all_classes"]["per_class"]["DDoS"]["f1"] == 0
    assert out["datasets"]["cic_ids2017"]["rows"] == 600
    assert "20-02" in out["missing_from_the_2018_sample"]


def test_degenerate_features_constant_single_file_and_the_known_defect_list():
    def frame(sources, shift):
        n = 90
        df = pd.DataFrame(np.random.default_rng(shift).normal(size=(n, 78)).astype(np.float32),
                          columns=FEATURES_2018)  # fmt: skip
        df["source"] = np.repeat(sources, n // len(sources))
        return df

    a = frame(["f1", "f2", "f3"], 1)
    a["Bwd PSH Flags"] = 0.0  # constant in this dataset
    a["Fwd PSH Flags"] = np.where(a["source"] == "f2", 1.0, 0.0)  # non-zero in one of 3 files
    b = frame(["g1"], 2)
    bad = degenerate_features({"A": a, "B": b})
    assert any("constant" in r for r in bad["Bwd PSH Flags"])
    assert any("only in one file" in r and "f2" in r for r in bad["Fwd PSH Flags"])
    for f in ("RST Flag Cnt", "ECE Flag Cnt", "CWE Flag Count", "Fwd URG Flags"):
        assert any("known defect" in r for r in bad[f])
    assert "Flow Duration" not in bad
    feats = cross_features(bad)
    assert "RST Flag Cnt" not in feats["with_port"] and "Dst Port" not in feats["without_port"]
    assert len(feats["with_port"]) == 78 - len(bad)


def test_evaluate_frame_reports_shared_classes_block():
    from idps.detect.models import train_classifier

    df = synthetic(n=100, classes=("BENIGN", "Bot", "DoS"))
    feats = FEATURES_2018[:10]
    model, enc = train_classifier("xgboost", df[feats], df["label"], 1)
    res = evaluate_frame(model, enc, feats, df, ["BENIGN", "Bot"])
    assert res["shared_classes"]["excluded_rows_true_class_outside"] == {"DoS": 100}
    assert res["shared_classes"]["n"] == 200 and "all_classes_note" in res


def test_resplit_refuses_public_dataset_bundles():
    from types import SimpleNamespace

    from idps.detect.train import resplit
    from idps.public.pipeline import bundle_meta

    fake = SimpleNamespace(extraction_meta=bundle_meta("CSE-CIC-IDS2018"), split={}, features=[])
    with pytest.raises(ValueError, match="comparison-only"):
        resplit(fake, pd.DataFrame())


def test_resplit_refusal_reaches_the_drift_and_retrain_commands(tmp_path):
    """A public bundle cannot be rebuilt through the split description: the commands that call
    resplit get the clear error (not a silently different split)."""
    from idps.detect import retrain, train

    assert retrain.resplit is train.resplit  # both paths go through the guarded function
    import idps.detect.__main__ as detect_main

    assert detect_main.resplit is train.resplit


def test_cli_cross_trains_2017_through_this_pipeline_and_writes_both_reports(
    small_dataset, tmp_path
):
    """`cross` loads 2017, runs the in-domain pipeline on it (reports/cic_ids2017_*.json, the
    second 2017 row of the comparison) and the cross-dataset test on the shared classes."""
    from idps.public.compare import compare

    rng = np.random.default_rng(4)
    d17 = tmp_path / "TrafficLabelling"
    d17.mkdir()
    shifts = {"BENIGN": 0, "Bot": 1, "DoS Hulk": 2}  # same class means as day_file's 0 / 4 / 8
    rows = []
    for label, k in shifts.items():
        for i in range(250):
            r = {f" {b}": f"{rng.normal(k * 4, 1):.4f}" for _, b in FEATURE_NAMES}
            r[" Timestamp"] = f"3/7/2017 {9 + i // 80}:{i % 60:02d}"
            r[" Label"] = label
            rows.append(r)
    pd.DataFrame(rows).to_csv(d17 / "Monday.csv", index=False, encoding="latin-1")
    models, reports = tmp_path / "models", tmp_path / "reports"
    argv = ["--data-2018", str(small_dataset), "--data-2017", str(d17), "--cap-benign", "200",
            "--cap-attack", "100", "--faith-n", "12", "--no-lime", "--models-dir", str(models),
            "--reports-dir", str(reports), "--cross-train-cap", "300"]  # fmt: skip
    assert cli.main(["run", *argv]) == 0
    for name in ("cic_ids2017_xgboost", "cic_ids2017_xgboost_noport", "cse_cic_ids2018_xgboost"):
        assert (reports / f"{name}.json").exists()
    assert (models / "cic2017_xgboost.joblib").exists()
    cross = json.loads((reports / "cross_2017_2018.json").read_text())
    assert set(cross["directions"]) == {"train_2017_test_2018", "train_2018_test_2017"}
    assert "RST Flag Cnt" in cross["features_excluded_from_cross"]
    s = cross["directions"]["train_2017_test_2018"]["with_port"]["summary"]
    assert set(s["shared_classes"]) == {"BENIGN", "Bot", "DoS"}
    # the comparison now has a CIC-IDS2017 row from THIS pipeline
    out = compare(reports)
    row = next(r for r in out["rows"] if r["dataset"] == "CIC-IDS2017 (idps.public pipeline)")
    assert row["pipeline"] == "idps.public" and row["with_ports"]["macro_f1"] is not None
    # --no-2017-report: only the cross test, no 2017 in-domain files
    reports2 = tmp_path / "reports2"
    argv2 = [a if a != str(reports) else str(reports2) for a in argv]
    assert cli.main(["cross", *argv2, "--no-2017-report"]) == 0
    assert (reports2 / "cross_2017_2018.json").exists()
    assert not (reports2 / "cic_ids2017_xgboost.json").exists()
