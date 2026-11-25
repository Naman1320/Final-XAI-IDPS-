"""Cloud model: CIC flows -> flow-log rows, label rule, feature parity, split, signed bundle."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from idps.cloud import train_data as td
from idps.cloud.collector import load_cloud_bundle
from idps.cloud.flowlogs import (
    CLOUD_FEATURE_COLUMNS,
    CLOUD_MODEL_FEATURES,
    FlowLogRecord,
    cloud_extraction_meta,
    rows_to_frame,
    to_flow_rows,
)

MIN = 60_000
T0 = 1_499_432_400_000  # a minute boundary (2017-07-07 13:00:00 UTC, divisible by 60 000)
assert T0 % MIN == 0


def flows_frame(rows: list[dict]) -> pd.DataFrame:
    """Canonical CIC flows (the read_cic_csv layout) from a few dicts; defaults fill the rest."""
    base = {
        "src_ip": "192.168.10.5", "src_port": 40000, "dst_ip": "192.168.10.50", "dst_port": 80,
        "protocol": 6, "duration_us": 1_000_000.0, "fwd_packets": 4, "bwd_packets": 3,
        "fwd_payload": 200.0, "bwd_payload": 3000.0, "label_raw": "BENIGN", "start_ms": T0,
        "resolution_ms": 1000,
    }  # fmt: skip
    return pd.DataFrame([{**base, **r} for r in rows])


def convert(rows: list[dict], **kwargs) -> pd.DataFrame:
    out, _ = td.convert_flows(flows_frame(rows), jitter=False, **kwargs)
    return out


# --- window splitting ---------------------------------------------------------------------------


def test_window_pieces_conserve_packets_and_bytes():
    rng = np.random.default_rng(1)
    n = 500
    start = T0 + rng.integers(0, 10 * MIN, n)
    duration = np.where(rng.random(n) < 0.2, 0, rng.integers(0, 120_000, n))
    fp, bp = rng.integers(0, 400, n), rng.integers(0, 400, n)
    fb, bb = fp * rng.integers(40, 1500, n), bp * rng.integers(40, 1500, n)
    p = td.window_pieces(start, duration, fp, bp, fb, bb)
    for key, total in (("fwd_pk", fp), ("bwd_pk", bp), ("fwd_by", fb), ("bwd_by", bb)):
        summed = np.bincount(p["flow"], weights=p[key], minlength=n)
        assert np.array_equal(summed, total), key
    assert (p["fwd_pk"] >= 0).all() and (p["bwd_by"] >= 0).all()
    assert (p["window"] % MIN == 0).all()
    assert ((p["lo"] >= p["window"]) & (p["hi"] <= p["window"] + MIN)).all()


def test_flow_over_a_minute_boundary_is_split_by_overlap():
    # 30 s before the boundary and 90 s after: 25% / 75%, 3 windows? no: 30 + 90 = 120 s.
    p = td.window_pieces(
        np.array([T0 + 30_000]), np.array([120_000]), np.array([100]), np.array([40]),
        np.array([10_000]), np.array([4_000]),
    )  # fmt: skip
    assert list(p["window"]) == [T0, T0 + MIN, T0 + 2 * MIN]
    assert list(p["fwd_pk"]) == [25, 50, 25]
    assert list(p["bwd_pk"]) == [10, 20, 10]
    assert list(p["fwd_by"]) == [2_500, 5_000, 2_500]
    # A flow that ends exactly on a boundary does not open an empty window.
    q = td.window_pieces(
        np.array([T0]), np.array([MIN]), np.array([7]), np.array([0]), np.array([700]), np.array([0])
    )  # fmt: skip
    assert list(q["window"]) == [T0] and list(q["fwd_pk"]) == [7]


def test_bytes_follow_packets_and_zero_packet_pieces_have_no_bytes():
    p = td.window_pieces(
        np.array([T0 + 59_000]), np.array([2_000]), np.array([1]), np.array([0]),
        np.array([60]), np.array([0]),
    )  # fmt: skip
    assert int(p["fwd_pk"].sum()) == 1 and int(p["fwd_by"].sum()) == 60
    for pk, by in zip(p["fwd_pk"], p["fwd_by"], strict=True):
        assert (pk == 0) == (by == 0)


# --- direction records and header bytes --------------------------------------------------------


def test_one_flow_gives_one_row_with_both_directions_and_header_bytes():
    rows = convert([{}])
    assert len(rows) == 1
    r = rows.iloc[0]
    # 4 fwd packets (200 B payload) and 3 bwd (3000 B) plus 40 B of IP + TCP header per packet.
    assert (r["fwd_packets"], r["bwd_packets"]) == (4, 3)
    assert (r["fwd_bytes"], r["bwd_bytes"]) == (200 + 4 * 40, 3000 + 3 * 40)
    assert r["dst_port"] == 80 and r["protocol"] == 6 and r["rejected"] == 0  # ACCEPT only
    assert r["duration_ms"] == 1000
    assert r["fwd_pkt_len_mean"] == pytest.approx(360 / 4)


def test_udp_and_icmp_headers_and_one_way_flow():
    rows = convert([{"protocol": 17, "dst_port": 53, "bwd_packets": 0, "bwd_payload": 0.0,
                     "fwd_packets": 2, "fwd_payload": 60.0}])  # fmt: skip
    r = rows.iloc[0]
    assert r["fwd_bytes"] == 60 + 2 * 28 and r["bwd_packets"] == 0 and r["bwd_bytes"] == 0
    assert r["down_up_ratio"] == 0.0


def test_flow_spanning_two_windows_gives_two_rows_that_add_up():
    rows = convert([{"start_ms": T0 + 50_000, "duration_us": 20_000_000.0, "fwd_packets": 10,
                     "bwd_packets": 10, "fwd_payload": 1000.0, "bwd_payload": 1000.0}])  # fmt: skip
    assert len(rows) == 2
    assert rows["fwd_packets"].sum() == 10 and rows["bwd_packets"].sum() == 10
    assert rows["fwd_bytes"].sum() == 1000 + 10 * 40
    assert rows["start_ms"].tolist() == [T0 + 50_000, T0 + MIN]


def test_same_five_tuple_in_one_window_is_one_record():
    rows = convert([{}, {"start_ms": T0 + 5000}])  # two connections reusing the 5-tuple
    assert len(rows) == 1
    assert rows.iloc[0]["fwd_packets"] == 8 and rows.iloc[0]["bwd_packets"] == 6
    assert rows.iloc[0]["duration_ms"] == 6000  # first packet T0, last T0 + 5 s + 1 s


# --- label rule -----------------------------------------------------------------------------------


def test_label_is_the_packet_weighted_majority_and_a_tie_goes_to_the_attack():
    mostly_benign = convert([{"fwd_packets": 50, "bwd_packets": 50},
                             {"label_raw": "DoS Hulk", "fwd_packets": 5, "bwd_packets": 5}])  # fmt: skip
    assert mostly_benign["label"].astype(str).tolist() == ["BENIGN"]
    assert bool(mostly_benign["mixed_label"].iloc[0])
    tie = convert([{"fwd_packets": 5, "bwd_packets": 5},
                   {"label_raw": "DoS Hulk", "fwd_packets": 5, "bwd_packets": 5}])  # fmt: skip
    assert tie["label"].astype(str).tolist() == ["DoS Hulk"]
    two_attacks = convert([{"label_raw": "SSH-Patator"}, {"label_raw": "FTP-Patator"}])
    assert two_attacks["label"].astype(str).tolist() == ["FTP-Patator"]  # alphabetical
    plain = convert([{"label_raw": "PortScan"}])
    assert not plain["mixed_label"].iloc[0]


# --- parity with the collector's to_flow_rows ---------------------------------------------------


def test_rows_equal_to_flow_rows_of_the_expected_records():
    """The training rows are what the collector builds from the records a flow log would hold."""
    out = convert([{"start_ms": T0 + 10_000, "duration_us": 8_000_000.0}])
    common = {"account_id": "1", "interface_id": "eni-x", "action": "ACCEPT"}
    records = [
        FlowLogRecord(src_ip="192.168.10.5", dst_ip="192.168.10.50", src_port=40000, dst_port=80,
                      protocol=6, packets=4, byte_count=360, start=T0 // 1000 + 10,
                      end=T0 // 1000 + 18, **common),
        FlowLogRecord(src_ip="192.168.10.50", dst_ip="192.168.10.5", src_port=80, dst_port=40000,
                      protocol=6, packets=3, byte_count=3120, start=T0 // 1000 + 10,
                      end=T0 // 1000 + 18, **common),
    ]  # fmt: skip
    expected = rows_to_frame(to_flow_rows(records))
    assert len(out) == 1 and len(expected) == 1
    for col in CLOUD_MODEL_FEATURES:
        assert float(out.iloc[0][col]) == pytest.approx(float(expected.iloc[0][col]), rel=1e-6), col
    assert set(CLOUD_MODEL_FEATURES) <= set(CLOUD_FEATURE_COLUMNS)
    assert out.iloc[0]["start_ms"] == expected.iloc[0]["start_ms"]


def test_initiator_comes_from_the_ports_not_from_cic_direction():
    # CIC lists the server as source (a CICFlowMeter direction error): to_flow_rows flips it back.
    out = convert([{"src_ip": "192.168.10.50", "src_port": 80, "dst_ip": "192.168.10.5",
                    "dst_port": 40000, "fwd_packets": 3, "bwd_packets": 4}])  # fmt: skip
    r = out.iloc[0]
    assert r["dst_port"] == 80 and (r["fwd_packets"], r["bwd_packets"]) == (4, 3)


# --- reading a CSV ----------------------------------------------------------------------------------


def test_read_cic_csv_and_convert_file(tmp_path):
    header = (" Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,"
              " Flow Duration, Total Fwd Packets, Total Backward Packets,"
              "Total Length of Fwd Packets, Total Length of Bwd Packets, Label")  # fmt: skip
    lines = [header,
             "10.0.0.1,5555,10.0.0.2,22,6,7/7/2017 1:00,2000000,5,5,300,400,SSH-Patator",
             "10.0.0.1,5556,10.0.0.2,22,6,7/7/2017 1:00,2000000,5,5,300,400,Mystery",
             "10.0.0.1,5557,10.0.0.2,22,6,garbage,2000000,5,5,300,400,BENIGN",
             "10.0.0.3,9999,10.0.0.4,80,6,7/7/2017 1:01,100,1,0,0,0,BENIGN"]  # fmt: skip
    path = tmp_path / "x.csv"
    path.write_text("\n".join(lines) + "\n", encoding="latin-1")
    flows, stats = td.read_cic_csv(path)
    assert len(flows) == 2 and stats["dropped_unknown_label"] == 1
    assert stats["rows_read"] == 4 and stats["timestamp_resolution_ms"] == {"60000": 2}
    rows, report = td.convert_file(path)
    assert len(rows) == 2
    assert report["conversion"]["packets_in"] == report["conversion"]["packets_in_records"]
    assert set(rows["label"].astype(str)) == {"SSH-Patator", "BENIGN"}


def test_caps_keep_both_directions_of_a_row():
    many = [{"src_port": 30000 + i, "start_ms": T0 + i * 100} for i in range(40)]
    out, stats = td.convert_flows(
        flows_frame(many), caps=td.Caps(benign=10, attack=10), jitter=False
    )
    assert len(out) == 10 and stats.keys == 40 and stats.keys_kept == 10
    assert (out["bwd_packets"] == 3).all()  # a kept row never lost its reply direction


# --- split without leakage ----------------------------------------------------------------------------


def synthetic_rows(n: int = 300) -> pd.DataFrame:
    rng = np.random.default_rng(3)
    frames = []
    for label, rate in (("BENIGN", 1.0), ("PortScan", 0.5)):
        t = T0 + np.sort(rng.integers(0, 3 * 3600, n)) * 1000
        frame = pd.DataFrame({"start_ms": t, "end_ms": t, "dst_port": rng.integers(1, 9999, n),
                              "protocol": 6})  # fmt: skip
        for c in td.CLOUD_STAT_FEATURES:
            frame[c] = rng.random(n).astype("float32") * (1 + rate)
        frame["label"] = label
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def test_split_is_time_ordered_per_class_with_the_gap():
    from idps.cloud.train_model import cloud_split

    df = synthetic_rows()
    sp = cloud_split(df, gap_ms=120_000, max_gap_loss=None)
    for label in ("BENIGN", "PortScan"):
        tr = sp.train[sp.train["label"] == label]["start_ms"]
        va = sp.validation[sp.validation["label"] == label]["start_ms"]
        te = sp.test[sp.test["label"] == label]["start_ms"]
        assert tr.max() + 120_000 <= va.min() and va.max() + 120_000 <= te.min()
    assert sp.description["mode"] == "class-time"
    assert sp.description["train_overlap_features"] == CLOUD_MODEL_FEATURES
    # exact duplicates are removed inside each part
    dup = pd.concat([df, df.iloc[:20]], ignore_index=True)
    sp2 = cloud_split(dup, max_gap_loss=None)
    assert sum(sp2.description["duplicates_dropped"].values()) >= 20


# --- signed bundle -------------------------------------------------------------------------------------


@pytest.fixture
def signed_bundle(tmp_path):
    from idps.detect.bundle import Bundle, save_bundle
    from idps.detect.models import train_classifier
    from idps.detect.signing import generate_keypair, load_private_key, sign_bundle

    df = synthetic_rows(120)
    model, encoder = train_classifier("xgboost", df[CLOUD_MODEL_FEATURES], df["label"])
    bundle = Bundle(model_name="xgboost", model=model, label_encoder=encoder,
                    features=list(CLOUD_MODEL_FEATURES), extraction_meta=cloud_extraction_meta(),
                    split={}, metrics={})  # fmt: skip
    path = save_bundle(bundle, tmp_path / "cloud_xgboost.joblib")
    priv, pub = generate_keypair(tmp_path / "key")
    sign_bundle(path, load_private_key(priv))
    return path, pub


def test_collector_loads_a_signed_cloud_bundle(signed_bundle):
    path, pub = signed_bundle
    assert load_cloud_bundle(path).features == CLOUD_MODEL_FEATURES
    assert load_cloud_bundle(path, pub).features == CLOUD_MODEL_FEATURES


def test_collector_refuses_a_tampered_bundle(signed_bundle):
    path, _ = signed_bundle
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="does not match"):  # the sha256 file catches it
        load_cloud_bundle(path)


def test_signature_catches_a_bundle_whose_sha256_was_rewritten(signed_bundle):
    import hashlib

    path, pub = signed_bundle
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    (path.parent / f"{path.name}.sha256").write_text(
        f"{hashlib.sha256(bytes(data)).hexdigest()}  {path.name}\n"
    )
    with pytest.raises(ValueError, match="changed after it was signed"):
        load_cloud_bundle(path, pub)


def test_unsigned_bundle_is_refused_when_a_key_is_given(signed_bundle):
    path, pub = signed_bundle
    (path.parent / f"{path.name}.sig").unlink()
    with pytest.raises(ValueError, match="not signed"):
        load_cloud_bundle(path, pub)
    assert load_cloud_bundle(path).model_name == "xgboost"  # the sha256 alone still loads it


def test_a_lab_bundle_is_not_a_cloud_bundle(tmp_path):
    from idps.detect.bundle import Bundle, save_bundle
    from idps.features import FEATURE_COLUMNS

    df = synthetic_rows(60)
    from idps.detect.models import train_classifier

    model, encoder = train_classifier("xgboost", df[CLOUD_MODEL_FEATURES], df["label"])
    lab = Bundle(model_name="xgboost", model=model, label_encoder=encoder,
                 features=list(CLOUD_MODEL_FEATURES),
                 extraction_meta={"extractor": "nfstream", "feature_columns": FEATURE_COLUMNS},
                 split={}, metrics={})  # fmt: skip
    path = save_bundle(lab, tmp_path / "lab.joblib")
    with pytest.raises(ValueError, match="not trained on VPC flow log"):
        load_cloud_bundle(path)


# =====================================================================================================
# Byte accounting, parity with the live exporter, labels, jitter, caps
# =====================================================================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pcap_factory import CLIENT, SERVER, tcp_session, write_pcap

from idps.cloud import flowlog_export as fx
from idps.cloud import train_model as tm

TS0 = T0 // 1000  # epoch seconds of a minute boundary


def ip_int(text: str) -> int:
    import socket

    return int.from_bytes(socket.inet_aton(text), "big")


def test_ip_bytes_removes_ethernet_padding_and_uses_the_tcp_header():
    arr = np.array
    # a RST/ACK (54-byte frame, 6 bytes of padding counted as payload): 40 IP bytes
    b, pad = td.ip_bytes(arr([6.0]), arr([1]), arr([20.0]), arr([6]))
    assert (b[0], pad[0]) == (40, 6)
    # a SYN with an MSS option (header 24, 2 bytes of padding): 44; with a 40-byte header, 60
    assert td.ip_bytes(arr([2.0]), arr([1]), arr([24.0]), arr([6]))[0][0] == 44
    assert td.ip_bytes(arr([0.0]), arr([1]), arr([40.0]), arr([6]))[0][0] == 60
    # a direction with real data keeps its payload
    assert td.ip_bytes(arr([2180.0]), arr([3]), arr([60.0]), arr([6]))[0][0] == 2180 + 3 * 20 + 60
    # UDP: payload + 28 per packet; a corrupt header average falls back to 20 per packet
    assert td.ip_bytes(arr([30.0]), arr([1]), None, arr([17]))[0][0] == 58
    assert td.ip_bytes(arr([100.0]), arr([2]), arr([5000.0]), arr([6]))[0][0] == 100 + 2 * 40
    assert td.ip_bytes(arr([0.0]), arr([0]), arr([0.0]), arr([6]))[0][0] == 0


def live_rows(packets: list) -> list[dict]:
    agg = fx.Aggregator(fx.ExportConfig())
    for p in packets:
        agg.add(p)
    lines = [line for window in agg.pop_all().values() for line in window]
    return to_flow_rows(flowlogs_parse(lines))


def flowlogs_parse(lines):
    from idps.cloud.flowlogs import parse_lines

    return parse_lines(lines)


def assert_same_features(converted: pd.Series, live: dict):
    for col in CLOUD_MODEL_FEATURES:
        assert float(converted[col]) == pytest.approx(float(live[col]), rel=1e-6), col


def test_converted_scan_probe_equals_the_live_exporters_row():
    """CIC's view of an nmap SYN probe and its RST/ACK (payload 2 and 6 bytes of padding,
    TCP headers 24 and 20) must give the row the exporter makes from the real 44 and 40 byte packets."""
    cl, sv = ip_int(CLIENT), ip_int(SERVER)
    live = live_rows([fx.Packet(TS0 + 3, cl, sv, 6, 40000, 22, 44),
                      fx.Packet(TS0 + 3, sv, cl, 6, 22, 40000, 40)])  # fmt: skip
    out = convert([{"src_ip": CLIENT, "dst_ip": SERVER, "dst_port": 22, "src_port": 40000,
                    "start_ms": T0 + 3000, "duration_us": 0.0, "fwd_packets": 1, "bwd_packets": 1,
                    "fwd_payload": 2.0, "bwd_payload": 6.0, "fwd_hdr": 24.0, "bwd_hdr": 20.0}])  # fmt: skip
    assert len(out) == 1 and len(live) == 1
    assert_same_features(out.iloc[0], live[0])
    assert out.iloc[0]["fwd_bytes"] == 44 and out.iloc[0]["bwd_bytes"] == 40


def test_converted_data_flow_equals_the_live_exporters_row():
    cl, sv = ip_int(CLIENT), ip_int(SERVER)
    pk = [fx.Packet(TS0 + 1, cl, sv, 6, 41000, 80, 100), fx.Packet(TS0 + 2, cl, sv, 6, 41000, 80, 1500),
          fx.Packet(TS0 + 3, cl, sv, 6, 41000, 80, 700), fx.Packet(TS0 + 1, sv, cl, 6, 80, 41000, 1500),
          fx.Packet(TS0 + 3, sv, cl, 6, 80, 41000, 1500)]  # fmt: skip
    live = live_rows(pk)
    out = convert([{"src_ip": CLIENT, "dst_ip": SERVER, "src_port": 41000, "dst_port": 80,
                    "start_ms": T0 + 1000, "duration_us": 2_000_000.0, "fwd_packets": 3,
                    "bwd_packets": 2, "fwd_payload": 2180.0, "bwd_payload": 2920.0,
                    "fwd_hdr": 60.0, "bwd_hdr": 40.0}])  # fmt: skip
    assert_same_features(out.iloc[0], live[0])


def test_flows_without_header_columns_assume_20_byte_tcp_headers():
    out = convert([{}])  # the default frame has no fwd_hdr/bwd_hdr
    assert out.iloc[0]["fwd_bytes"] == 200 + 4 * 40


def test_jitter_is_seeded_and_deterministic():
    frame = flows_frame([{"src_port": 30000 + i, "resolution_ms": MIN} for i in range(30)])
    a, _ = td.convert_flows(frame, jitter=True, file_key="x")
    b, _ = td.convert_flows(frame, jitter=True, file_key="x")
    c, _ = td.convert_flows(frame, jitter=True, file_key="y")
    d, _ = td.convert_flows(frame, jitter=True, seed=7, file_key="x")
    assert a["start_ms"].tolist() == b["start_ms"].tolist()
    assert a["start_ms"].tolist() != c["start_ms"].tolist()
    assert a["start_ms"].tolist() != d["start_ms"].tolist()
    assert ((a["start_ms"] >= T0) & (a["start_ms"] < T0 + 2 * MIN)).all()


def test_three_way_tie_goes_to_the_alphabetically_first_attack():
    out = convert([{"label_raw": "SSH-Patator"}, {"label_raw": "FTP-Patator"},
                   {"label_raw": "DoS Hulk"}])  # fmt: skip
    assert out["label"].astype(str).tolist() == ["DoS Hulk"]
    assert out["label_any"].astype(str).tolist() == ["DoS Hulk"] and out["mixed_label"].iloc[0]


def test_label_any_marks_an_attack_flow_hidden_in_a_benign_majority():
    out = convert([{"fwd_packets": 50, "bwd_packets": 50},
                   {"label_raw": "DoS Hulk", "fwd_packets": 2, "bwd_packets": 2}])  # fmt: skip
    assert out["label"].astype(str).tolist() == ["BENIGN"]
    assert out["label_any"].astype(str).tolist() == ["DoS Hulk"]


def test_a_corrupt_duration_is_capped_not_expanded():
    rows, stats = td.convert_flows(flows_frame([{"duration_us": 9e15}]), jitter=False)
    assert stats.durations_capped == 1 and len(rows) <= 62


def test_links_name_the_flows_of_every_row_and_are_prefixed_per_file():
    flows = flows_frame([{"start_ms": T0 + 50_000, "duration_us": 20_000_000.0}, {"src_port": 1}])
    rows, _, links = td.convert_flows_links(flows, jitter=False, file_key="a.csv")
    assert set(rows["key_id"]) == set(links["key_id"])
    assert links.groupby("flow_id")["key_id"].nunique().max() == 2  # the long flow: two rows
    _rows2, _, links2 = td.convert_flows_links(flows, jitter=False, file_key="b.csv")
    assert not set(links["flow_id"]) & set(links2["flow_id"])


# --- split: production setting, flow disjointness ------------------------------------------------------


def split_frame(n: int = 300) -> pd.DataFrame:
    df = synthetic_rows(n)
    df["key_id"] = np.arange(len(df), dtype="int64")
    df["mixed_label"] = False
    df["label_any"] = df["label"]
    return df


def test_split_with_the_production_gap_setting_is_time_ordered_and_reports_short_gaps():
    df = split_frame()
    sp = tm.cloud_split(df)  # max_gap_loss = 0.10, the setting of the real run
    for label in ("BENIGN", "PortScan"):
        tr = sp.train[sp.train["label"] == label]["start_ms"]
        va = sp.validation[sp.validation["label"] == label]["start_ms"]
        te = sp.test[sp.test["label"] == label]["start_ms"]
        assert tr.max() < va.min() and va.max() < te.min()
    assert isinstance(sp.description["gap_below_window_s"], dict)
    for gap in sp.description["gap_below_window_s"].values():
        assert gap < 60


def test_flow_overlap_filter_removes_rows_that_share_a_flow_across_parts():
    df = split_frame()
    base = tm.cloud_split(df, max_gap_loss=None)
    tr_key = int(base.train["key_id"].iloc[0])
    va_key = int(base.validation["key_id"].iloc[0])
    te_key = int(base.test["key_id"].iloc[0])
    links = pd.DataFrame({"key_id": df["key_id"].to_numpy(), "flow_id": df["key_id"].to_numpy()})
    links.loc[links["key_id"] == te_key, "flow_id"] = tr_key  # one flow, a train and a test row
    links.loc[links["key_id"] == va_key, "flow_id"] = tr_key
    sp, info = tm.flow_overlap_filter(base, links)
    assert info["flows_shared_before"]["train_test"] == 1
    assert info["flows_shared_after"] == {"train_validation": 0, "train_test": 0,
                                          "validation_test": 0}  # fmt: skip
    assert info["rows_removed"] == {"validation": 1, "test": 1}
    assert te_key not in set(sp.test["key_id"]) and va_key not in set(sp.validation["key_id"])
    assert tr_key in set(sp.train["key_id"])


# --- train_model helpers ----------------------------------------------------------------------------------


def test_variant_split_deduplicates_on_the_variants_own_vector():
    df = split_frame()
    df["dst_port"] = np.arange(len(df)) % 5000  # distinct ports: no duplicates with the port
    sp = tm.cloud_split(df, max_gap_loss=None)
    twin = sp.train.iloc[:10].copy()
    twin["dst_port"] = twin["dst_port"] + 1  # same vector without the port
    sp2 = sp.__class__(pd.concat([sp.train, twin], ignore_index=True), sp.validation, sp.test, {})
    out, removed = tm.variant_split(sp2, tm.VARIANTS["_noport"])
    assert removed["train"] >= 10 and len(out.train) == len(sp.train)


def test_detection_rates_count_any_attack_and_the_right_class():
    y = ["BENIGN", "PortScan", "PortScan", "DDoS"]
    p = ["BENIGN", "PortScan", "DDoS", "BENIGN"]
    rates = tm.detection_rates(y, p)
    assert rates["PortScan"] == {"rows": 2, "any_attack": 1.0, "right_class": 0.5}
    assert rates["DDoS"]["any_attack"] == 0.0


def test_as_rejected_zeroes_the_reply_and_sets_the_flag():
    r = tm.as_rejected(synthetic_rows(5))
    assert (r["rejected"] == 1).all() and (r["bwd_packets"] == 0).all()
    assert (r["bwd_bytes"] == 0).all() and (r["down_up_ratio"] == 0).all()


def test_cluster_bootstrap_is_wider_than_the_row_bootstrap_for_clustered_errors():
    from idps.public.scoring import bootstrap_ci

    rng = np.random.default_rng(0)
    cluster = np.repeat(np.arange(100), 20)
    y = np.where(rng.random(100)[cluster] < 0.5, "A", "B")
    wrong = rng.random(100)[cluster] < 0.3  # errors come in whole clusters
    pred = np.where(wrong, np.where(y == "A", "B", "A"), y)
    row = bootstrap_ci(y, pred)["macro_f1"]
    cl = tm.cluster_bootstrap_ci(y, pred, cluster, min_rows=10)
    assert cl["macro_f1"][1] - cl["macro_f1"][0] > row[1] - row[0]
    assert cl["clusters"] == 100 and cl["macro_f1_classes_with_min_rows"] is not None


def test_label_rule_analysis_separates_mixed_rows():
    test = pd.DataFrame({"label": ["BENIGN"] * 4 + ["DDoS"], "label_any": ["BENIGN", "BENIGN", "DDoS", "DDoS", "DDoS"],
                         "mixed_label": [False, False, True, True, False]})  # fmt: skip
    pred = np.array(["BENIGN", "BENIGN", "DDoS", "DDoS", "DDoS"], dtype=object)
    r = tm.label_rule_analysis(test, pred)
    assert r["a_current_rule"]["benign_false_positive_rate"] == 0.5
    assert r["b_without_mixed_rows"]["benign_false_positive_rate"] == 0.0
    assert r["c_any_attack_flow_is_attack"]["benign_false_positive_rate"] == 0.0
    assert r["mixed_share_of_benign_false_positives"] == 1.0


def test_compare_with_lab_uses_common_and_solid_classes():
    def report(pc, macro):
        return {"metrics": {"test": {"per_class": {k: {"f1": f, "support": n, "precision": f, "recall": f}
                                                   for k, (f, n) in pc.items()},
                                     "macro_f1": macro, "benign_false_positive_rate": 0.1,
                                     "roc_auc": {"macro": 0.9}}}}  # fmt: skip

    cloud = report({"BENIGN": (0.9, 500), "DDoS": (0.5, 200), "Bot": (0.0, 5)}, 0.5)
    lab = report({"BENIGN": (0.99, 900), "DDoS": (0.9, 300), "Bot": (0.0, 7), "XSS": (0.0, 3)}, 0.7)
    out = tm.compare_with_lab(cloud, lab, "lab")
    assert out["common_classes"] == ["BENIGN", "Bot", "DDoS"]
    assert out["solid_classes"] == ["BENIGN", "DDoS"]
    assert out["cloud_macro_f1_on_solid_classes"] == pytest.approx(0.7)
    assert out["lab_macro_f1_on_solid_classes"] == pytest.approx(0.945)


def test_train_variant_and_experiment_on_small_data(tmp_path):
    df = split_frame(400)
    sp = tm.cloud_split(df, max_gap_loss=None)
    report, _bundle = tm.train_variant(sp, tm.VARIANTS[""], "", seed=1, models_dir=tmp_path,
                                      raw_test=sp.test, mixed_share={"BENIGN": 0.0})  # fmt: skip
    assert report["features"] == CLOUD_MODEL_FEATURES
    assert "cluster_bootstrap_95ci" in report["metrics"]["test"]
    assert report["metrics"]["test_not_deduplicated"]["n"] == len(sp.test)
    assert load_cloud_bundle(tmp_path / "cloud_xgboost.joblib").features == CLOUD_MODEL_FEATURES
    out = tm.reject_experiment(sp, 1, tmp_path / "experiments", tmp_path)
    assert out["synthetic_reject_scan_rows_added"] > 0
    with pytest.raises(ValueError, match="not trained on VPC flow log"):
        load_cloud_bundle(tmp_path / "experiments" / "cloud_xgboost_reject_experiment.joblib")


# --- signing through the CLI, wrong key -----------------------------------------------------------------


def test_sign_cloud_cli_and_verify(signed_bundle, tmp_path, capsys):
    from idps.detect.__main__ import main as detect_main
    from idps.detect.signing import generate_keypair

    path, pub = signed_bundle
    (path.parent / f"{path.name}.sig").unlink()
    priv = path.parent / "key.key"
    assert detect_main(["sign", str(path), "--cloud", "--key", str(priv)]) == 0
    assert detect_main(["verify", str(path), "--public-key", str(pub)]) == 0
    assert load_cloud_bundle(path, pub).features == CLOUD_MODEL_FEATURES
    # without --cloud the lab loader refuses the flow-log layout
    assert detect_main(["sign", str(path), "--key", str(priv)]) != 0
    _, other_pub = generate_keypair(tmp_path / "other")
    with pytest.raises(ValueError, match="another key"):
        load_cloud_bundle(path, other_pub)


# --- scripts/cloud_lab_eval.py ------------------------------------------------------------------------------


def test_lab_eval_replays_a_pcap_and_scores_it(tmp_path, signed_bundle, monkeypatch):
    import cloud_lab_eval as ev

    bundle_path, _ = signed_bundle
    bundle = ev.load_bundle(str(bundle_path), None, False)
    pcap = write_pcap(
        tmp_path / "x.pcap", tcp_session(dport=80) + tcp_session(sport=40001, dport=9999)
    )
    monkeypatch.setattr(ev, "ATTACKER", CLIENT)
    files = ev.export_pcap(pcap, tmp_path / "w" / "sg", "sg")
    rows, stats = ev.read_rows(files)
    assert stats["malformed"] == 0 and len(rows) >= 2
    sg = ev.evaluate_session(bundle, rows, {"PortScan"})
    assert (
        sg["rows"] == len(rows) and 0 < sg["rejected_share"] < 1
    )  # port 9999 is REJECT in sg mode
    open_files = ev.export_pcap(pcap, tmp_path / "w" / "open", "open")
    open_rows, _ = ev.read_rows(open_files)
    assert ev.evaluate_session(bundle, open_rows, {"PortScan"})["rejected_share"] == 0
    # a second export into the same folder starts clean (no stale window files)
    again = ev.export_pcap(pcap, tmp_path / "w" / "sg", "sg")
    assert len(again) == len(files)


def test_lab_eval_experiment_bundles_need_the_flag(tmp_path):
    import cloud_lab_eval as ev

    df = split_frame(300)
    sp = tm.cloud_split(df, max_gap_loss=None)
    tm.reject_experiment(sp, 1, tmp_path / "e", tmp_path)
    path = str(tmp_path / "e" / "cloud_xgboost_reject_experiment.joblib")
    with pytest.raises(ValueError):
        ev.load_bundle(path, None, False)
    assert ev.load_bundle(path, None, True).model_name == "xgboost"
