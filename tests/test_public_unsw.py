"""Tests for the UNSW-NB15 part of idps.public: the header-less CSV loader and the quirks of the real
files, the label table, capture sessions, the categorical encoding (fitted on train only), the time
split, the caps, the end-to-end CLI, the model bundles and the comparison table. All on small
synthetic files that copy the quirks found in the real data; no real dataset is needed."""

import json

import numpy as np
import pandas as pd
import pytest

from idps.detect.bundle import load_bundle
from idps.detect.signing import generate_keypair, load_private_key, sign_bundle
from idps.public import __main__ as cli
from idps.public.compare import compare, verdict
from idps.public.labels import (
    UNSW_CLASSES,
    UNSW_LABEL_TABLE,
    common_label,
    unsw_label,
    unsw_label_table_markdown,
)
from idps.public.pipeline import run_unsw, unsw_split
from idps.public.sampling import Caps
from idps.public.unsw import (
    ALL_COLUMNS,
    CATEGORICAL,
    FEATURES_UNSW,
    FEATURES_UNSW_NOPORT,
    NUMERIC_FEATURES,
    CategoryEncoder,
    assign_sessions,
    clean_name,
    list_files,
    load_unsw,
    parse_ports,
    read_feature_names,
)

JAN = 1_421_927_377  # 2015-01-22 11:49:37 UTC, the first capture
FEB = 1_424_219_008  # 2015-02-18 00:23:28 UTC, the second capture
CATEGORY = {"BENIGN": "", "Fuzzers": " Fuzzers ", "Backdoors": "Backdoors", "Worms": "Worms",
            "Generic": "Generic", "Exploits": "Exploits", "DoS": "DoS"}  # fmt: skip
SHIFT = {name: k for k, name in enumerate(CATEGORY)}
FEATURE_FILE_NAMES = [  # as spelled in NUSW-NB15_features.csv, odd ones included
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl",
    "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime",
    "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label",
]  # fmt: skip


def write_feature_file(directory, names=None):
    names = names or FEATURE_FILE_NAMES
    lines = ["No.,Name,Type ,Description"]
    lines += [
        f'{i + 1},{n},nominal,"a description, with a comma \xd5"' for i, n in enumerate(names)
    ]
    (directory / "NUSW-NB15_features.csv").write_bytes("\r\n".join(lines).encode("latin-1"))


def make_row(rng, label: str, stime: int, **over) -> dict:
    """One record as text. The class shows in dur / sbytes / dbytes / sload; the rest is noise."""
    k = SHIFT[label]
    row = dict.fromkeys(ALL_COLUMNS, "0")
    row.update(
        srcip="59.166.0.1", dstip="149.171.126.1", sport=str(int(rng.integers(1024, 65535))),
        dsport=str(int(rng.choice([80, 53, 25]))), proto=str(rng.choice(["tcp", "udp"])),
        state="FIN", service="-", dur=f"{abs(rng.normal(k, 0.3)):.6f}",
        sbytes=str(int(abs(rng.normal(300 * k + 100, 30)))), dbytes=str(int(rng.integers(0, 90))),
        sload=f"{abs(rng.normal(1000 * k, 100)):.2f}", spkts=str(int(rng.integers(1, 40))),
        stime=str(stime), ltime=str(stime + 1), ct_srv_src=str(int(rng.integers(1, 30))),
        attack_cat=CATEGORY[label], label_binary="0" if label == "BENIGN" else "1",
    )  # fmt: skip
    row.update(over)
    return row


def line(row: dict) -> str:
    return ",".join(row[c] for c in ALL_COLUMNS)


def write_csvs(directory, rows: list[dict], sizes: list[int], repeat_boundary=True, bom=True):
    """The rows in Ltime order, cut into numbered header-less CSVs with CRLF line ends; the last
    row of a file is repeated as the first of the next (as in the real files); file 1 has a BOM."""
    rows = sorted(rows, key=lambda r: int(r["ltime"]))
    start, prev_last = 0, None
    for n, size in enumerate(sizes, 1):
        chunk = rows[start : start + size]
        start += size
        if repeat_boundary and n > 1:
            chunk = [prev_last, *chunk]
        prev_last = chunk[-1]
        text = "\r\n".join(line(r) for r in chunk) + "\r\n"
        data = text.encode("latin-1")
        (directory / f"UNSW-NB15_{n}.csv").write_bytes(
            (b"\xef\xbb\xbf" + data) if bom and n == 1 else data
        )


def synth(rng, per_class: dict[str, int], base: int, span: int = 3 * 3600) -> list[dict]:
    rows = []
    for label, n in per_class.items():
        for t in np.sort(rng.integers(0, span, n)):
            rows.append(make_row(rng, label, base + int(t)))
    return rows


@pytest.fixture
def small(tmp_path):
    """Two captures (Jan, Feb), three files; every quirk of the real data once or more."""
    rng = np.random.default_rng(0)
    d = tmp_path / "unsw"
    d.mkdir()
    write_feature_file(d)
    rows = synth(rng, {"BENIGN": 300, "Fuzzers": 120, "Backdoors": 60}, JAN)
    rows += synth(rng, {"BENIGN": 300, "Generic": 200, "Exploits": 90, "DoS": 70}, FEB)
    write_csvs(d, rows, [300, 300, 600])
    return d


# --- names and the feature file ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "clean"),
    [("ct_src_ ltm", "ct_src_ltm"), ("Sload", "sload"), ("Stime", "stime"), ("Label", "label_binary"),
     ("attack_cat", "attack_cat"), (" Spkts ", "spkts"), ("ct_dst_src_ltm", "ct_dst_src_ltm")],
)  # fmt: skip
def test_clean_name(raw, clean):
    assert clean_name(raw) == clean


def test_feature_file_gives_the_49_names_and_records_the_renames(tmp_path):
    write_feature_file(tmp_path)
    names, rep = read_feature_names(tmp_path)
    assert names == list(ALL_COLUMNS) and len(names) == 49
    renamed = {m["file_name"]: m["name"] for m in rep["columns"] if m["renamed"]}
    assert renamed["ct_src_ ltm"] == "ct_src_ltm" and renamed["Label"] == "label_binary"
    assert renamed["Sload"] == "sload" and "srcip" not in renamed


def test_a_different_feature_file_is_refused(tmp_path):
    write_feature_file(tmp_path, [*FEATURE_FILE_NAMES[:-1], "label2"])
    with pytest.raises(ValueError, match="differ from the expected 49"):
        read_feature_names(tmp_path)
    with pytest.raises(FileNotFoundError):
        read_feature_names(tmp_path / "missing")


def test_feature_lists():
    assert len(FEATURES_UNSW) == 43 and len(FEATURES_UNSW_NOPORT) == 41
    assert FEATURES_UNSW_NOPORT == [f for f in FEATURES_UNSW if f not in ("sport", "dsport")]
    for banned in ("srcip", "dstip", "stime", "ltime", "attack_cat", "label_binary", "label"):
        assert banned not in FEATURES_UNSW
    assert set(CATEGORICAL) <= set(FEATURES_UNSW)
    assert set(NUMERIC_FEATURES) | set(CATEGORICAL) == set(FEATURES_UNSW)


# --- labels --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("Normal", "BENIGN"), ("Backdoor", "Backdoor"), ("Backdoors", "Backdoor"),
     (" Fuzzers ", "Fuzzers"), (" Fuzzers", "Fuzzers"), (" Reconnaissance ", "Reconnaissance"),
     (" Shellcode ", "Shellcode"), ("Generic", "Generic"), ("Worms", "Worms"), ("DoS", "DoS"),
     ("Exploits", "Exploits"), ("Analysis", "Analysis")],
)  # fmt: skip
def test_unsw_label_spellings(raw, expected):
    assert unsw_label(raw) == expected


def test_unsw_label_table_and_no_cic_mapping():
    assert {c for c, _ in UNSW_LABEL_TABLE} == set(UNSW_CLASSES) and len(UNSW_CLASSES) == 10
    assert unsw_label_table_markdown().count("\n") == len(UNSW_LABEL_TABLE) + 1
    with pytest.raises(ValueError, match="unknown UNSW-NB15"):
        unsw_label("Mystery")
    # the CIC table is untouched: UNSW classes are not silently accepted as CIC classes
    with pytest.raises(ValueError, match="unknown label"):
        common_label("Generic")
    assert common_label("DoS Hulk") == "DoS"


# --- ports and sessions --------------------------------------------------------------------------


def test_parse_ports_decimal_hex_dash_and_junk():
    out, c = parse_ports(
        pd.Series(["80", "0xcc09", "0x000c", "0x20205321", "-", "", " 53 ", "ftp"])
    )
    assert out[:3].tolist() == [80, 0xCC09, 12] and out[3] == 0x20205321
    assert out[4] == -1 and out[5] == -1 and out[6] == 53 and np.isnan(out[7])
    assert c == {"decimal": 2, "hex": 3, "dash_or_blank": 2, "unparseable": 1}


def test_sessions_follow_the_capture_not_the_calendar_day():
    # the first capture runs past UTC midnight, the second is 26 days later
    midnight = JAN + 12 * 3600 + 20 * 60
    ts = np.array([JAN, midnight - 5, midnight + 5, midnight + 600, FEB, FEB + 7200])
    sid, info = assign_sessions(ts)
    assert sid.tolist() == [0, 0, 0, 0, 1, 1]
    assert [s["rows"] for s in info] == [4, 2]
    assert info[0]["first_stime"] == "2015-01-22T11:49:37"
    empty, no_info = assign_sessions(np.array([], dtype=np.int64))
    assert len(empty) == 0 and no_info == []


# --- loader --------------------------------------------------------------------------------------


def quirky_dataset(tmp_path):
    rng = np.random.default_rng(1)
    d = tmp_path / "q"
    d.mkdir()
    write_feature_file(d)
    rows = synth(rng, {"BENIGN": 40, "Fuzzers": 12, "Backdoors": 6}, JAN, span=600)
    rows[0].update(sport="0x000c", dsport="0xcc09", proto="icmp", ct_flw_http_mthd="", is_ftp_login="",
                   ct_ftp_cmd=" ")  # fmt: skip
    rows[1].update(dsport="-", is_ftp_login="4")
    rows[2].update(is_ftp_login="1", ct_ftp_cmd="2", ct_flw_http_mthd="3", dsport="0x20205321")
    rows.append(make_row(rng, "Fuzzers", JAN + 5, sbytes="abc"))  # unparseable number: dropped
    rows.append(make_row(rng, "Fuzzers", JAN + 6, sload="inf"))  # infinite: dropped
    rows.append(make_row(rng, "Worms", JAN + 7, attack_cat="", label_binary="1"))  # contradiction
    rows.append(make_row(rng, "BENIGN", JAN + 8, attack_cat="DoS", label_binary="0"))  # ditto
    rows.append(make_row(rng, "BENIGN", JAN + 9, label_binary="2"))  # not 0/1
    rows.append(make_row(rng, "BENIGN", 5))  # Stime far outside 2015
    write_csvs(d, rows, [32, 32])
    return d


def test_loader_reads_headerless_files_and_counts_every_quirk(tmp_path):
    d = quirky_dataset(tmp_path)
    df, rep = load_unsw(d, Caps(1000, 1000), seed=1)
    assert [f["file"] for f in rep["files"]] == ["UNSW-NB15_1.csv", "UNSW-NB15_2.csv"]
    assert rep["files"][0]["bom"] is True and rep["files"][1]["bom"] is False
    assert rep["file_boundary_overlap_rows"] == 1  # the row repeated at the file boundary
    assert rep["file_boundary_overlap"] == [
        {"file": "UNSW-NB15_2.csv", "repeats_last_row_of": "UNSW-NB15_1.csv"}
    ]
    assert sum(f["label_contradictions"] for f in rep["files"]) == 2
    assert sum(f["bad_label"] for f in rep["files"]) == 1
    assert sum(f["bad_timestamp"] for f in rep["files"]) == 1
    assert rep["coercions"]["nonfinite_by_column"] == {"sbytes": 1, "sload": 1}
    odd = rep["odd_values_all_rows"]
    assert odd["sport_hex"] == 1 and odd["dsport_hex"] == 2 and odd["dsport_dash_or_blank"] == 1
    assert odd["is_ftp_login_over_1"] == 1 and odd["ct_flw_http_mthd_blank"] >= 1
    co = rep["coercions"]
    assert co["flag_clipped"]["is_ftp_login"] == 1 and co["blank_to_zero"]["ct_ftp_cmd"] >= 1
    assert co["hex_port"] == {"sport": 1, "dsport": 2}

    steps = rep["steps"]
    assert (
        steps["raw"]["Fuzzers"] + steps["raw"]["Backdoor"] + steps["raw"]["BENIGN"]
        == 41 + 14 + 6 + 1
    )
    assert "Worms" not in steps["raw"]  # its only row was contradictory
    assert sum(steps["raw"].values()) - sum(steps["after_file_overlap"].values()) == 1
    assert sum(steps["valid_timestamp"].values()) == sum(steps["after_file_overlap"].values()) - 1
    assert steps["finite"]["Fuzzers"] == steps["sampled"]["Fuzzers"] - 2

    # values: ports, blanks, clipped flag; names are the cleaned feature-file names
    assert set(FEATURES_UNSW) <= set(df.columns)
    assert "ct_src_ltm" in df.columns and "sload" in df.columns
    assert df[NUMERIC_FEATURES].dtypes.eq(np.float32).all()
    assert np.isfinite(df[NUMERIC_FEATURES].to_numpy()).all()
    assert df["is_ftp_login"].isin([0, 1]).all()
    assert (df["dsport"] == -1).sum() == 1 and (df["dsport"] == 0xCC09).sum() == 1
    assert (df["sport"] == 12).sum() == 1
    # labels: padded and plural spellings are normalised, the original (stripped) is kept
    assert set(df["label"]) == {"BENIGN", "Fuzzers", "Backdoor"}
    assert set(df["label_original"]) == {"Normal", "Fuzzers", "Backdoors"}
    assert (df.loc[df["label"] == "BENIGN", "label_original"] == "Normal").all()
    assert rep["attack_cat_raw_values"]["' Fuzzers '"] >= 12
    assert df["start_ms"].between(JAN * 1000, (JAN + 700) * 1000).all()
    assert set(df["session"]) == {0}


def test_unknown_attack_category_and_bad_files_are_errors(tmp_path):
    rng = np.random.default_rng(2)
    d = tmp_path / "u"
    d.mkdir()
    write_feature_file(d)
    rows = synth(rng, {"BENIGN": 10}, JAN, span=100)
    rows.append(make_row(rng, "DoS", JAN + 1, attack_cat="Mystery"))
    write_csvs(d, rows, [11])
    with pytest.raises(ValueError, match="Mystery"):
        load_unsw(d, Caps(10, 10), 1)
    with pytest.raises(ValueError, match="no UNSW-NB15"):
        list_files(tmp_path / "u" / "none")
    # too many Stime values outside 2015 means a changed format: refused, not guessed at
    d2 = tmp_path / "v"
    d2.mkdir()
    write_feature_file(d2)
    write_csvs(d2, [make_row(rng, "BENIGN", 5 + i) for i in range(20)], [20])
    with pytest.raises(ValueError, match="not epoch seconds"):
        load_unsw(d2, Caps(10, 10), 1)


def test_max_rows_and_only(small):
    df, rep = load_unsw(small, Caps(1000, 1000), 1, max_rows=50)
    assert all(f["rows_read"] == 50 for f in rep["files"]) and rep["rows_total"] == len(df)
    _, rep1 = load_unsw(small, Caps(1000, 1000), 1, only=["_1"])
    assert [f["file"] for f in rep1["files"]] == ["UNSW-NB15_1.csv"]
    assert rep1["file_boundary_overlap_rows"] == 0  # the previous file is not loaded


# --- caps ----------------------------------------------------------------------------------------


def test_caps_are_per_session_and_label_deterministic_and_span_the_files(small):
    caps = Caps(benign=100, attack=40)
    a, rep = load_unsw(small, caps, seed=7)
    b, _ = load_unsw(small, caps, seed=7)
    c, _ = load_unsw(small, caps, seed=8)
    assert a.equals(b) and not a.equals(c)
    counts = a.groupby(["session", "label"]).size()
    assert counts[(0, "BENIGN")] == 100 and counts[(1, "BENIGN")] == 100  # per capture session
    assert counts[(1, "Generic")] == 40 and counts[(0, "Fuzzers")] == 40
    assert counts[(0, "Backdoor")] == 40 and counts[(1, "DoS")] == 40
    group = {(g["session"], g["label_original"]): g for g in rep["groups"]}
    assert group[(1, "Generic")]["available"] == 200 and group[(1, "Generic")]["sampled"] == 40
    # time-stratified: the kept Generic flows cover the whole capture, not just the start
    g = np.sort(a.loc[a["label"] == "Generic", "start_ms"].to_numpy()) // 1000 - FEB
    assert g[0] < 600 and g[-1] > 3 * 3600 - 600
    assert rep["caps"] == {"benign": 100, "attack": 40}


# --- categorical encoding --------------------------------------------------------------------------


def cat_frame(protos, services=None, states=None):
    n = len(protos)
    return pd.DataFrame(
        {"proto": protos, "service": services or ["-"] * n, "state": states or ["FIN"] * n}
    )


def test_encoder_is_fitted_on_train_only_and_unseen_values_get_the_other_code():
    train = cat_frame(["tcp"] * 5 + ["udp"] * 3 + ["arp"] * 3 + ["ospf"])
    enc = CategoryEncoder.fit(train)
    # most frequent first, ties alphabetical, codes start at 1; 0 is reserved
    assert enc.mapping["proto"] == {"tcp": 1, "arp": 2, "udp": 3, "ospf": 4}
    test = cat_frame(["tcp", "sctp", "udp", "zzz"], services=["-", "dns", "-", "-"])
    out = enc.transform(test)
    assert out["proto"].tolist() == [1, 0, 3, 0] and out["service"].tolist() == [1, 0, 1, 1]
    assert out["proto"].dtype == np.float32
    assert "sctp" not in enc.mapping["proto"]  # the test values did not reach the mapping
    # fitting on different held-out data cannot change a train-only mapping
    assert CategoryEncoder.fit(train).mapping == enc.mapping
    assert enc.transform(test)["state"].tolist() == [1, 1, 1, 1]
    assert test["proto"].tolist() == ["tcp", "sctp", "udp", "zzz"]  # input not modified


def test_encoder_cap_describe_and_round_trip():
    train = cat_frame(["a"] * 9 + ["b"] * 5 + ["c"] * 3 + ["d"] * 1)
    enc = CategoryEncoder.fit(train, max_categories=2)
    assert enc.mapping["proto"] == {"a": 1, "b": 2}
    out = enc.transform(train)["proto"].tolist()
    assert out.count(0) == 4  # c and d share the other code
    desc = enc.describe({"train": train, "test": cat_frame(["a", "x"])})
    assert desc["share_other_by_split"]["train"]["proto"] == pytest.approx(4 / 18)
    assert desc["values_coded_other_by_split"]["test"]["proto"] == ["x"]
    assert desc["other_code"] == 0 and desc["fitted_on_rows"] == 18
    again = CategoryEncoder.from_dict(json.loads(json.dumps(enc.to_dict())))
    assert again.transform(train).equals(enc.transform(train))
    with pytest.raises(ValueError, match="at least 1"):
        CategoryEncoder.fit(train, max_categories=0)


# --- split ---------------------------------------------------------------------------------------


def split_frame(seed=0, n=300, protos=("tcp", "udp"), sessions=(0, 1)) -> pd.DataFrame:
    """Rows of three classes in two sessions. The second session is a month later."""
    rng = np.random.default_rng(seed)
    parts = []
    for session in sessions:
        for k, label in enumerate(("BENIGN", "Generic", "Worms")):
            df = pd.DataFrame(
                rng.normal(3 * k, 1, (n, len(NUMERIC_FEATURES))).astype(np.float32),
                columns=NUMERIC_FEATURES,
            )
            base = (JAN if session == 0 else FEB) * 1000
            df["start_ms"] = base + np.sort(rng.integers(0, 4 * 3600, n)) * 1000
            df["session"] = session
            df["label"] = df["label_original"] = label
            df["proto"] = rng.choice(list(protos), n)
            df["service"], df["state"] = "-", "FIN"
            parts.append(df)
    return pd.concat(parts, ignore_index=True)


def test_split_is_per_session_and_label_with_no_leakage():
    df = split_frame()
    sp, enc = unsw_split(df, gap_ms=60_000, max_gap_loss=None)
    for session in (0, 1):
        for label in ("BENIGN", "Generic", "Worms"):
            tr, va, te = (
                p[(p["session"] == session) & (p["label"] == label)]
                for p in (sp.train, sp.validation, sp.test)
            )
            assert len(tr) and len(va) and len(te)
            assert tr["start_ms"].max() + 60_000 <= va["start_ms"].min()
            assert va["start_ms"].max() + 60_000 <= te["start_ms"].min()
    d = sp.description
    assert d["mode"] == "class-time" and d["max_drop_share"] is None and d["gap_ms"] == 60_000
    assert d["day_key"].startswith("capture session")
    assert d["dropped_by_gap"]["total"] > 0 and "effective_gap_ms" in d
    assert "identical_to_train" in d and "proto" in d["train_overlap_features"]
    assert not any(c.endswith("_id") for c in sp.train.columns)
    assert sp.train[["proto", "service", "state"]].isin(range(40)).all().all()
    assert enc.mapping["proto"].keys() == {"tcp", "udp"}


def test_split_encoder_uses_train_rows_only_and_test_only_values_become_other():
    df = split_frame(protos=("tcp", "udp"))
    late = df.groupby(["session", "label"])["start_ms"].transform("max") == df["start_ms"]
    df.loc[late & (df["label"] == "Generic"), "proto"] = "ospf"  # only in the last rows: test
    sp, enc = unsw_split(df, gap_ms=0, max_gap_loss=None)
    assert "ospf" not in enc.mapping["proto"]
    seen = sp.description["categorical_encoding"]
    assert "ospf" in seen["values_coded_other_by_split"]["test"]["proto"]
    assert seen["fitted_on_rows"] == len(sp.train)
    assert (sp.test.loc[sp.test["start_ms"].isin(df.loc[late, "start_ms"]), "proto"] == 0).any()
    assert (sp.train["proto"] > 0).all()  # everything in train is a fitted category


def test_split_drops_duplicates_inside_each_split_and_tells_apart_categories():
    df = split_frame(n=120)
    dup = df[df["label"] == "Generic"].iloc[:30]
    df = pd.concat([df, dup, dup], ignore_index=True)
    other = dup.iloc[:5].copy()
    other["proto"] = "sctp"  # same numbers, another protocol: NOT a duplicate
    df = pd.concat([df, other], ignore_index=True)
    sp, _ = unsw_split(df, gap_ms=0, max_gap_loss=None)
    d = sp.description
    before = sum(sum(c.values()) for c in d["class_counts_before_duplicates"].values())
    after = len(sp.train) + len(sp.validation) + len(sp.test)
    assert before - after == sum(d["duplicates_dropped"].values()) >= 60
    assert 0 <= d["identical_to_train"]["test"]["share"] <= 1


def test_tiny_group_is_reported_as_missing_from_train_not_hidden(tmp_path):
    df = split_frame(n=200)
    tiny = df[df["label"] == "Worms"].iloc[:6].copy()
    tiny["label"] = tiny["label_original"] = "Shellcode"
    tiny["start_ms"] = JAN * 1000  # one burst: the fixed 120 s gap removes all of it
    both = pd.concat([df, tiny], ignore_index=True)
    sp, _ = unsw_split(both, 120_000, 0.1)  # the shrinking gap keeps it
    assert sp.description["effective_gap_ms"] and "Shellcode" in set(sp.train["label"])
    _, summary = run_unsw(
        both, {"steps": {}, "caps": {}}, seed=1, gap_ms=120_000, max_gap_loss=None,
        models_dir=tmp_path / "m", reports_dir=tmp_path / "r", faith_n=0, lime_samples=10,
        include_lime=False, log=lambda _: None,
    )  # fmt: skip
    pre = json.loads((tmp_path / "r" / "unsw_nb15_preprocessing.json").read_text())
    assert pre["classes_missing_from_train"] == ["Shellcode"]
    assert pre["gap_loss_share_by_label"]["Shellcode"] == 1.0
    assert summary["xgboost"]["classes_missing_from_train"] == []  # it is not in any split
    assert "Shellcode" not in summary["xgboost"]["classes_in_train"]


# --- end to end ----------------------------------------------------------------------------------


@pytest.fixture
def run_outputs(small, tmp_path):
    models, reports = tmp_path / "models", tmp_path / "reports"
    code = cli.main(
        ["unsw", "--data-unsw", str(small), "--cap-benign", "200", "--cap-attack", "120",
         "--faith-n", "12", "--no-lime", "--models-dir", str(models), "--reports-dir", str(reports)]
    )  # fmt: skip
    assert code == 0
    return models, reports


def test_cli_writes_the_reports_and_signable_bundles(run_outputs, tmp_path):
    models, reports = run_outputs
    for name in ("unsw_nb15_xgboost", "unsw_nb15_xgboost_noport"):
        assert (models / f"{name}.joblib").exists() and (models / f"{name}.joblib.sha256").exists()
    for name in ("preprocessing", "xgboost", "xgboost_noport", "xgboost_faithfulness",
                 "xgboost_noport_faithfulness"):  # fmt: skip
        assert (reports / f"unsw_nb15_{name}.json").exists()

    pre = json.loads((reports / "unsw_nb15_preprocessing.json").read_text())
    steps = pre["class_counts_by_step"]
    assert set(steps) >= {"raw", "after_file_overlap", "valid_timestamp", "sampled", "finite",
                          "after_gap_before_duplicates", "after_duplicates"}  # fmt: skip
    assert steps["raw"]["BENIGN"] == 600 and steps["sampled"]["BENIGN"] == 400
    assert pre["load"]["caps"] == {"benign": 200, "attack": 120}
    assert pre["load"]["file_boundary_overlap_rows"] == 2
    assert "not done" in pre["cross_test_with_cic"]
    assert pre["categorical_encoding"]["other_code"] == 0 and pre["load"]["sessions"]
    assert {m["unsw_attack_cat"] for m in pre["label_mapping"]} >= {"Backdoors", "Backdoor"}

    rep = json.loads((reports / "unsw_nb15_xgboost.json").read_text())
    noport = json.loads((reports / "unsw_nb15_xgboost_noport.json").read_text())
    assert rep["features"] == FEATURES_UNSW and noport["features"] == FEATURES_UNSW_NOPORT
    assert rep["dropped_features"] == [] and noport["dropped_features"] == ["sport", "dsport"]
    test = rep["metrics"]["test"]
    assert test["macro_f1"] > 0.8 and test["benign_false_positive_rate"] is not None
    assert "train_overlap" in test and rep["timing_seconds"]["train_classifier"] > 0
    assert (
        "classes_missing_from_train" in rep and rep["faithfulness"]["shap"]["mean_drop"] is not None
    )
    assert rep["model"] == "xgboost" and rep["dataset"] == "UNSW-NB15"
    assert "deduplicated" in rep["test_set_note"].lower() and "variant_duplicates_removed" in rep
    ci = test["bootstrap_95ci"]
    assert ci["n_resamples"] == 200 and ci["macro_f1"][0] <= test["macro_f1"] <= ci["macro_f1"][1]
    table = {r["class"]: r for r in rep["per_class_test_table"]}
    assert table["BENIGN"]["test_support"] > 0 and table["BENIGN"]["f1_ci95"]
    assert table["BENIGN"]["effective_gap_s"] is not None
    assert "not_identical_to_train" in test
    sessions = test["by_session"]["sessions"]
    assert set(sessions) == {"0", "1"} and sessions["0"]["n"] + sessions["1"]["n"] == test["n"]
    assert all("macro_f1" in v and "attack_share" in v for v in sessions.values())
    # the train overlap of a variant is on the variant's own (deduplicated) vector
    assert rep["variant_parts"]["test"]["rows"] == test["n"]

    cross = json.loads((reports / "unsw_nb15_cross_session.json").read_text())
    assert set(cross["directions"]) == {"train_session_0_test_session_1",
                                        "train_session_1_test_session_0"}  # fmt: skip
    one = cross["directions"]["train_session_0_test_session_1"]["without_ports"]
    assert one["train_session"] == 0 and one["test_session"] == 1
    assert "macro_f1" in one["shared_classes"] and one["all_classes"]["macro_f1"] is not None

    # normal bundles: they load, `idps.detect sign` can sign them, the encoding travels with them
    path = models / "unsw_nb15_xgboost.joblib"
    bundle = load_bundle(path)
    assert (
        bundle.features == FEATURES_UNSW and bundle.metrics["test"]["macro_f1"] == test["macro_f1"]
    )
    enc = CategoryEncoder.from_dict(bundle.extraction_meta["categorical_encoding"])
    assert set(enc.mapping) == set(CATEGORICAL)
    assert bundle.extraction_meta["public_feature_columns"] == FEATURES_UNSW
    priv, pub = generate_keypair(tmp_path / "key")
    sign_bundle(path, load_private_key(priv))
    loaded = load_bundle(path, public_key=pub)
    raw = pd.DataFrame(
        np.zeros((2, len(NUMERIC_FEATURES)), dtype=np.float32), columns=NUMERIC_FEATURES
    )
    raw["proto"], raw["service"], raw["state"] = ["tcp", "never-seen"], ["-", "-"], ["FIN", "FIN"]
    assert len(loaded.predict(enc.transform(raw)[FEATURES_UNSW])) == 2  # reproducible inference
    live = {"extractor": "nfstream", "idle_timeout": 30, "active_timeout": 120,
            "feature_columns": loaded.extraction_meta["feature_columns"]}  # fmt: skip
    with pytest.raises(ValueError, match="extraction settings differ"):
        load_bundle(path, live_meta=live)


def test_compare_skips_missing_datasets_and_reads_the_unsw_reports(run_outputs):
    _, reports = run_outputs
    out = compare(reports)
    assert [r["dataset"] for r in out["rows"]] == ["UNSW-NB15"]
    assert {s["dataset"] for s in out["skipped"]} == {
        "CIC-IDS2017 (idps.public pipeline)", "CSE-CIC-IDS2018", "CIC-IDS2017 (week_* reports)"
    }  # fmt: skip
    row = out["rows"][0]
    assert row["pipeline"] == "idps.public" and row["comparable_with_idps_public_rows"]
    assert row["n_classes"] == len(row["classes"]) >= 5 and row["rows_used"] > 0
    assert (
        row["with_ports"]["macro_f1"] is not None and row["without_ports"]["macro_f1"] is not None
    )
    shap = row["with_ports"]["shap"]
    assert shap["verdict"] in {"faithful", "weak", "not better than random", "inconclusive"}
    assert shap["flows"] and shap["features"] == len(FEATURES_UNSW) and shap["share_ci95"]
    assert row["with_ports"]["macro_f1_ci95"] and "deduplicated" in row["with_ports"][
        "benign_fpr_note"
    ]  # fmt: skip
    assert row["with_ports"]["lime"]["verdict"] == "not run"  # --no-lime
    assert row["with_ports"]["train_seconds"] > 0
    assert cli.main(["compare", "--reports-dir", str(reports)]) == 0
    written = json.loads((reports / "public_datasets_comparison.json").read_text())
    assert written["rows"][0]["dataset"] == "UNSW-NB15" and "verdict_rule" in written


def test_compare_with_several_datasets_and_the_week_row_is_a_different_pipeline(tmp_path):
    def report(prefix, f1):
        parts = {p: {"rows": 10, "class_counts": {"BENIGN": 6, "X": 4}} for p in ("train", "test")}
        rep = {"features": ["a"], "dropped_features": [], "split": {"parts": parts},
               "metrics": {"test": {"n": 10, "macro_f1": f1, "benign_false_positive_rate": 0.01}}}  # fmt: skip
        (tmp_path / f"{prefix}_xgboost.json").write_text(json.dumps(rep))

    report("week", 0.7)
    report("unsw_nb15", 0.6)
    report("cic_ids2017", 0.9)
    out = compare(tmp_path)
    names = [r["dataset"] for r in out["rows"]]
    assert names == ["CIC-IDS2017 (idps.public pipeline)", "UNSW-NB15",
                     "CIC-IDS2017 (week_* reports)"]  # fmt: skip
    by = {r["dataset"]: r for r in out["rows"]}
    week = by["CIC-IDS2017 (week_* reports)"]
    assert all("pipeline" in r for r in out["rows"])
    assert "different pipeline, not comparable" in week["pipeline"]
    assert (
        week["comparable_with_idps_public_rows"] is False and "42-feature" in week["pipeline_note"]
    )
    assert by["UNSW-NB15"]["pipeline"] == by["CIC-IDS2017 (idps.public pipeline)"]["pipeline"]
    assert by["UNSW-NB15"]["comparable_with_idps_public_rows"] is True
    assert week["without_ports"] is None and out["skipped"][0]["dataset"] == "CSE-CIC-IDS2018"
    assert by["UNSW-NB15"]["rows_used"] == 20
    assert "same method on every dataset" not in out["note"]
    assert "not comparable" in out["note"]


def test_verdict_rule():
    def m(ratio, share):
        return {"ratio_to_random": ratio, "share_flows_beating_random": share}

    good = verdict(m(5.0, 0.9), 100, 41)
    assert good["verdict"] == "faithful" and good["features"] == 41 and good["flows"] == 100
    assert good["random_baseline_features"] == 5 and good["share_ci95"][0] > 0.5
    assert verdict(m(1.6, 0.9), 100, 41)["verdict"] == "weak"
    assert verdict(m(1.01, 0.9), 100, 41)["verdict"] == "inconclusive"  # 'weak' needs real margin
    assert verdict(m(0.8, 0.2), 100, 41)["verdict"] == "not better than random"
    # 11 of 20 flows: the interval is wide and includes 0.5, whatever the ratio says
    assert verdict(m(5.0, 0.55), 20, 78)["verdict"] == "inconclusive"
    assert (
        verdict(m(5.0, 0.55), 20, 78)["share_ci95"][0]
        < 0.5
        < verdict(m(5.0, 0.55), 20, 78)["share_ci95"][1]
    )
    assert verdict(None)["verdict"] == "not run" and verdict(None, 100, 41)["flows"] == 100
    assert verdict(m(None, 0.5), 100, 41)["verdict"] == "not run"
    assert verdict(m(5.0, 0.9))["verdict"] == "not run"  # without the flow count no interval


def test_wilson_interval_and_bootstrap_are_sane_and_seeded():
    from idps.public.scoring import bootstrap_ci, wilson_interval

    lo, hi = wilson_interval(50, 100)
    assert lo < 0.5 < hi and wilson_interval(0, 0) is None
    lo, hi = wilson_interval(100, 100)
    assert hi == pytest.approx(1.0) and lo > 0.95
    rng = np.random.default_rng(0)
    y = rng.choice(["BENIGN", "A", "B"], 400, p=[0.6, 0.3, 0.1])
    p = np.where(rng.random(400) < 0.8, y, "BENIGN")
    one, two = bootstrap_ci(y, p), bootstrap_ci(y, p)
    assert one == two and one["n_resamples"] == 200
    from idps.detect.evaluate import evaluate_classifier

    point = evaluate_classifier(y, p)
    assert one["macro_f1"][0] <= point["macro_f1"] <= one["macro_f1"][1]
    for cls in ("A", "B"):
        lo, hi = one["per_class_f1"][cls]
        assert lo <= point["per_class"][cls]["f1"] <= hi
    # the smaller class has the wider interval
    w = lambda c: one["per_class_f1"][c][1] - one["per_class_f1"][c][0]
    assert w("B") > w("A")
    assert bootstrap_ci([], [])["macro_f1"] is None


def test_variant_split_dedupes_in_the_variants_own_vector():
    from idps.public.pipeline import variant_split

    df = split_frame(n=60)
    sp, _ = unsw_split(df, gap_ms=0, max_gap_loss=None)
    # two rows that differ only in a port column are duplicates for the no-port variant
    twin = sp.train.iloc[[0]].copy()
    twin["sport"] = twin["sport"] + 1
    sp.train = pd.concat([sp.train, twin], ignore_index=True)
    with_ports, removed_with = variant_split(sp, FEATURES_UNSW)
    no_port, removed_no = variant_split(sp, FEATURES_UNSW_NOPORT)
    assert removed_no["train"] == removed_with["train"] + 1
    assert len(no_port.train) == len(with_ports.train) - 1
    assert len(sp.train) == len(with_ports.train) + removed_with["train"]  # input untouched


def test_cli_labels_and_bad_input(capsys, tmp_path):
    assert cli.main(["labels", "--dataset", "unsw"]) == 0
    assert "| Backdoor | Backdoors |" in capsys.readouterr().out
    assert cli.main(["labels"]) == 0 and "WebAttack" in capsys.readouterr().out
    assert cli.main(["unsw", "--data-unsw", str(tmp_path / "nothing")]) == 2


def test_session_probe_finds_a_session_shortcut_and_none_when_there_is_not_one():
    from idps.public.cross import session_probe

    rng = np.random.default_rng(1)
    n = 600
    sess = np.repeat([0, 1], n // 2)
    feats = ["x", "y"]
    leaky = pd.DataFrame({"x": rng.normal(sess * 3, 1), "y": rng.normal(size=n)})
    clean = pd.DataFrame({"x": rng.normal(size=n), "y": rng.normal(size=n)})
    for frame in (leaky, clean):
        frame["session"], frame["label"] = sess, "BENIGN"
    shuffled = rng.permutation(n)  # train and test rows differ; sessions are balanced in both
    tr, te = shuffled[: n // 2], shuffled[n // 2 :]
    bad = session_probe(leaky.iloc[tr], leaky.iloc[te], feats, 1)
    ok = session_probe(clean.iloc[tr], clean.iloc[te], feats, 1)
    assert bad["all_classes"]["auc"] > 0.9 and bad["benign_only"]["auc"] > 0.9
    assert 0.35 < ok["all_classes"]["auc"] < 0.65
    assert session_probe(leaky.iloc[:5], leaky.iloc[:5], feats, 1)["all_classes"]["auc"] is None
