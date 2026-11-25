import pandas as pd
import pytest

from idps.features import FEATURE_COLUMNS
from idps.features.labels import (
    LABEL_COLUMNS,
    UNMATCHED,
    join_labels,
    normalize_cic_labels,
    summarize_matches,
)


def _flows(rows):
    base = dict.fromkeys(FEATURE_COLUMNS, 0)
    return pd.DataFrame([{**base, **r} for r in rows], columns=FEATURE_COLUMNS)


def _labels(rows):
    return pd.DataFrame(rows, columns=LABEL_COLUMNS)


A = {"src_ip": "1.1.1.1", "src_port": 1000, "dst_ip": "2.2.2.2", "dst_port": 80, "protocol": 6}
REV = {"src_ip": "2.2.2.2", "src_port": 80, "dst_ip": "1.1.1.1", "dst_port": 1000, "protocol": 6}


def test_matches_either_direction_and_marks_unmatched():
    flows = _flows([
        {**A, "start_ms": 10_000, "end_ms": 10_500},
        {**A, "start_ms": 99_000, "end_ms": 99_100},  # far outside any label window
        {**A, "src_port": 1001, "start_ms": 10_000, "end_ms": 10_500},  # other 5-tuple
        {**A, "protocol": 17, "start_ms": 10_000, "end_ms": 10_500},  # other protocol
    ])
    labels = _labels([[*REV.values(), 9_900, 10_600, "DoS Hulk"]])  # reversed direction
    out = join_labels(flows, labels)
    assert list(out.label) == ["DoS Hulk", UNMATCHED, UNMATCHED, UNMATCHED]
    assert list(out.label_matched) == [True, False, False, False]
    s = summarize_matches(out)
    assert (s["flows"], s["matched"], s["unmatched"]) == (4, 1, 3)
    assert s["match_rate"] == 0.25
    assert s["per_label"]["DoS Hulk"] == 1


def test_time_window_overlap_and_tolerance():
    flows = _flows([{**A, "start_ms": 20_000, "end_ms": 20_100}])
    labels = _labels([[*A.values(), 10_000, 19_500, "BENIGN"]])
    assert not join_labels(flows, labels, tolerance_ms=0).label_matched[0]
    assert not join_labels(flows, labels, tolerance_ms=100).label_matched[0]
    assert join_labels(flows, labels, tolerance_ms=500).label_matched[0]


def test_port_reuse_picks_best_overlap_and_flags_ambiguity():
    flows = _flows([{**A, "start_ms": 50_000, "end_ms": 60_000}])
    labels = _labels([
        [*A.values(), 49_000, 50_500, "BENIGN"],  # overlaps 500 ms
        [*A.values(), 50_400, 60_000, "PortScan"],  # overlaps 9.6 s
    ])
    out = join_labels(flows, labels, tolerance_ms=0)
    assert out.label[0] == "PortScan" and out.label_ambiguous[0]
    same = _labels([[*A.values(), 49_000, 55_000, "X"], [*A.values(), 55_000, 61_000, "X"]])
    assert not join_labels(flows, same, tolerance_ms=0).label_ambiguous[0]


def test_input_not_modified_and_empty_inputs():
    flows = _flows([{**A, "start_ms": 1, "end_ms": 2}])
    cols = list(flows.columns)
    out = join_labels(flows, _labels([]))
    assert list(flows.columns) == cols and out.label[0] == UNMATCHED
    assert summarize_matches(join_labels(_flows([]), _labels([])))["match_rate"] == 0.0
    with pytest.raises(ValueError):
        join_labels(flows, flows)


def test_normalize_cic_labels():
    raw = pd.DataFrame({
        " Source IP": ["1.1.1.1"], " Source Port": [1000], " Destination IP": ["2.2.2.2"],
        " Destination Port": [80], " Protocol": [6], " Timestamp": ["7/7/2017 8:59"],
        " Flow Duration": [2_000_000], " Label": ["BENIGN "],
    })
    out = normalize_cic_labels(raw, utc_offset_hours=-3)
    ts = pd.Timestamp("2017-07-07 11:59", tz="UTC")
    assert out.start_ms[0] == int(ts.timestamp() * 1000)
    assert out.end_ms[0] - out.start_ms[0] == 2000
    assert out.label[0] == "BENIGN"
    assert list(out.columns) == [*LABEL_COLUMNS, "ts_resolution_ms"]
    assert out.ts_resolution_ms[0] == 60_000  # "8:59" has no seconds


# --- review findings: CIC timestamp format, port types, training safety ----------------

from idps.features import MODEL_FEATURES
from idps.features.labels import parse_cic_timestamps, training_rows, training_xy


def _ts(values, **kw):
    return list(parse_cic_timestamps(pd.Series(values), **kw))


def test_dates_are_day_first():
    assert _ts(["3/7/2017 8:55:58"]) == [pd.Timestamp("2017-07-03 08:55:58")]
    assert _ts(["4/7/2017 9:01"]) == [pd.Timestamp("2017-07-04 09:01")]


def test_twelve_hour_files_get_afternoon_times():
    # No hour above 12 in this "file": 3:56 is 15:56, 9:10 stays morning, 12:30 is noon.
    out = _ts(["7/7/2017 9:10", "7/7/2017 12:30", "7/7/2017 3:56"])
    assert [t.hour for t in out] == [9, 12, 15]


def test_twenty_four_hour_files_are_left_alone():
    out = _ts(["7/7/2017 3:56", "7/7/2017 15:00"])
    assert [t.hour for t in out] == [3, 15]


def test_afternoon_label_matches_its_flow():
    raw = pd.DataFrame({
        " Source IP": ["1.1.1.1"], " Source Port": [1000], " Destination IP": ["2.2.2.2"],
        " Destination Port": [80], " Protocol": [6], " Timestamp": ["7/7/2017 3:56"],
        " Flow Duration": [1_000_000], " Label": ["PortScan"],
    })
    labels = normalize_cic_labels(raw, utc_offset_hours=-3)
    start = int(pd.Timestamp("2017-07-07 18:56", tz="UTC").timestamp() * 1000)  # 15:56 local
    flows = _flows([{**A, "start_ms": start + 100, "end_ms": start + 600}])
    assert join_labels(flows, labels).label[0] == "PortScan"


def test_bad_rows_dropped_and_negative_duration_clipped():
    raw = pd.DataFrame({
        " Source IP": ["1.1.1.1", "1.1.1.1"], " Source Port": [1000, None],
        " Destination IP": ["2.2.2.2", "2.2.2.2"], " Destination Port": [80, 80],
        " Protocol": [6, 6], " Timestamp": ["7/7/2017 9:00", "7/7/2017 9:00"],
        " Flow Duration": [-1, 5], " Label": ["BENIGN", "BENIGN"],
    })
    with pytest.warns(UserWarning, match="dropped 1"):
        out = normalize_cic_labels(raw)
    assert len(out) == 1 and out.end_ms[0] == out.start_ms[0]


def test_float_ports_still_match():
    flows = _flows([{**A, "start_ms": 10_000, "end_ms": 10_500}])
    flows["src_port"] = flows["src_port"].astype(float)
    labels = _labels([[*A.values(), 9_900, 10_600, "BENIGN"]])
    assert join_labels(flows, labels).label_matched[0]


def test_training_rows_drop_unmatched_and_ambiguous():
    flows = _flows([
        {**A, "start_ms": 10_000, "end_ms": 10_500},  # matched
        {**A, "start_ms": 99_000, "end_ms": 99_100},  # unmatched
        {**A, "src_port": 2000, "start_ms": 50_000, "end_ms": 60_000},  # ambiguous
    ])
    B = {**A, "src_port": 2000}
    labels = _labels([
        [*A.values(), 9_900, 10_600, "BENIGN"],
        [*B.values(), 49_000, 50_500, "BENIGN"], [*B.values(), 50_400, 60_000, "PortScan"],
    ])
    joined = join_labels(flows, labels, tolerance_ms=0)
    rows = training_rows(joined)
    assert list(rows.label) == ["BENIGN"]
    X, y = training_xy(joined)
    assert list(X.columns) == MODEL_FEATURES and "label_matched" not in X and len(y) == 1


def test_windows_dash_in_labels_becomes_hyphen():
    raw = pd.DataFrame({
        " Source IP": ["1.1.1.1"], " Source Port": [1000], " Destination IP": ["2.2.2.2"],
        " Destination Port": [80], " Protocol": [6], " Timestamp": ["6/7/2017 9:20"],
        " Flow Duration": [1], " Label": ["Web Attack \x96 Brute Force"],
    })
    assert normalize_cic_labels(raw).label[0] == "Web Attack - Brute Force"


def _raw(timestamp, duration_us=1_000_000):
    return pd.DataFrame({
        " Source IP": ["1.1.1.1"], " Source Port": [1000], " Destination IP": ["2.2.2.2"],
        " Destination Port": [80], " Protocol": [6], " Timestamp": [timestamp],
        " Flow Duration": [duration_us], " Label": ["DoS Hulk"],
    })


def test_ts_resolution_is_per_row():
    raw = pd.concat([_raw("7/7/2017 9:03"), _raw("7/7/2017 9:03:41")], ignore_index=True)
    assert list(normalize_cic_labels(raw).ts_resolution_ms) == [60_000, 1_000]


def test_minute_resolution_label_matches_flow_45s_into_the_minute():
    labels = normalize_cic_labels(_raw("7/7/2017 9:03"))  # true start is in [9:03:00, 9:04:00)
    minute = int(labels.start_ms[0])
    flows = _flows([{**A, "start_ms": minute + 45_000, "end_ms": minute + 45_500}])
    assert join_labels(flows, labels).label[0] == "DoS Hulk"
    # Without the resolution column the old, narrow window would have missed it.
    assert join_labels(flows, labels.drop(columns="ts_resolution_ms")).label[0] == UNMATCHED
    # The widening is forward only: a flow well before the label minute still misses.
    early = _flows([{**A, "start_ms": minute - 45_000, "end_ms": minute - 44_500}])
    assert join_labels(early, labels).label[0] == UNMATCHED
    # A second-resolution label only widens by one second.
    exact = normalize_cic_labels(_raw("7/7/2017 9:03:00"))
    assert join_labels(flows, exact).label[0] == UNMATCHED
