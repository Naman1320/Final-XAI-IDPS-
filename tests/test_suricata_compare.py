"""Tests for scripts/suricata_compare.py: the pure parts (no Docker, no model)."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pandas as pd
import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_SCRIPTS))
_spec = importlib.util.spec_from_file_location("suricata_compare", _SCRIPTS / "suricata_compare.py")
sc = importlib.util.module_from_spec(_spec)
sys.modules["suricata_compare"] = sc
_spec.loader.exec_module(sc)

A, V = "10.10.1.10", "10.10.2.10"


def eve(ts="2026-11-15T10:00:01.500000+0000", src=A, sport=4444, dst=V, dport=80, proto="TCP",
        sig="ET SCAN Nmap", sid=1, event="alert"):
    return json.dumps({"timestamp": ts, "event_type": event, "src_ip": src, "src_port": sport,
                       "dest_ip": dst, "dest_port": dport, "proto": proto,
                       "alert": {"signature": sig, "signature_id": sid, "category": "x", "severity": 1}})


NEAR = "2026-11-15T10:00:00.050000+0000"  # 50 ms after T0, inside the short test flows


def flows(rows):
    """rows: (src, sport, dst, dport, proto, start_ms, end_ms, label)"""
    return pd.DataFrame(rows, columns=["src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                                       "start_ms", "end_ms", "label"])


T0 = sc.eve_timestamp_ms("2026-11-15T10:00:00.000000+0000")


# ---- eve parsing ---------------------------------------------------------------------------------

def test_timestamp_utc_and_offsets():
    assert sc.eve_timestamp_ms("1970-01-01T00:00:01.250000+0000") == 1250
    # the same instant written with a local offset gives the same epoch
    assert sc.eve_timestamp_ms("2017-07-07T09:00:00.000000-0300") == sc.eve_timestamp_ms("2017-07-07T12:00:00.000000+0000")
    assert sc.eve_timestamp_ms("2017-07-07T14:00:00.500000+0200") == sc.eve_timestamp_ms("2017-07-07T12:00:00.500000+0000")


def test_timestamp_without_offset_refused():
    with pytest.raises(ValueError, match="offset"):
        sc.eve_timestamp_ms("2017-07-07T12:00:00.000000")


def test_parse_alert_line_fields_and_skips():
    a = sc.parse_alert_line(eve(sig="ET SCAN Nmap", sid=2000537))
    assert a["src_ip"] == A and a["dst_port"] == 80 and a["protocol"] == 6
    assert a["signature"] == "ET SCAN Nmap" and a["sid"] == 2000537 and a["engine"] is False
    assert a["ts_ms"] == T0 + 1500
    assert sc.parse_alert_line(eve(event="flow")) is None
    assert sc.parse_alert_line("@@END") is None and sc.parse_alert_line("") is None


def test_parse_alert_icmp_without_ports():
    line = json.dumps({"timestamp": "2026-11-15T10:00:00.000000+0000", "event_type": "alert", "src_ip": A,
                       "dest_ip": V, "proto": "ICMP", "alert": {"signature": "ET X", "signature_id": 5}})
    a = sc.parse_alert_line(line)
    assert (a["src_port"], a["dst_port"], a["protocol"]) == (0, 0, 1)


def test_engine_vs_attack_split():
    assert sc.is_engine_event("SURICATA STREAM Packet with invalid ack")
    assert sc.is_engine_event("SURICATA Applayer Mismatch protocol both directions")
    assert not sc.is_engine_event("ET SCAN Potential SSH Scan")
    assert not sc.is_engine_event("GPL ICMP_INFO PING")
    df = sc.alerts_frame([eve(sig="SURICATA STREAM x"), eve(sig="ET SCAN y"), eve(event="stats")])
    assert df["engine"].tolist() == [True, False]
    c = sc.alert_counts(df)
    assert (c["total"], c["attack"], c["engine"], c["attack_signatures"]) == (2, 1, 1, 1)
    assert sc.alert_counts(sc.alerts_frame([]))["total"] == 0


# ---- HOME_NET arguments --------------------------------------------------------------------------

def test_home_net_args():
    assert sc.home_net_args(["10.10.2.0/24"]) == ["--set", "vars.address-groups.HOME_NET=[10.10.2.0/24]",
                                                  "--set", "vars.address-groups.EXTERNAL_NET=any"]
    assert "HOME_NET=[192.168.10.0/24,10.0.0.1]" in sc.home_net_args(["192.168.10.0/24", " 10.0.0.1"])[1]
    for bad in ([], [""], ["[1.2.3.0/24]"], ["1.2.3.0/24,4.5.6.0/24"], ["!1.2.3.0/24"]):
        with pytest.raises(ValueError):
            sc.home_net_args(bad)
    assert sc.HOME_NETS == {"lab": ["10.10.2.0/24"], "cic": ["192.168.10.0/24"]}


def test_container_script_has_args_and_markers():
    s = sc.container_script(["10.10.2.0/24"])
    assert "-r /dev/stdin" in s and "-k none" in s and "--init-errors-fatal" in s and "HOME_NET=[10.10.2.0/24]" in s and "EXTERNAL_NET=any" in s
    assert sc.M_ALERTS in s and sc.M_END in s and "sha256sum" in s
    assert "suricata -v " in s                                   # 'rules successfully loaded' needs -v
    assert "read [0-9]+ files?, [0-9]+ packets" in s              # the packet count line is in the whole-log grep
    assert "Error|Critical|Alert|Emergency" in s


def test_split_run_output_and_packets():
    out = io.StringIO()
    lines = ["@@META suricata_version=This is Suricata version 7.0.10 RELEASE\n", "@@META rc=0\n", "@@ALERTS\n",
             eve() + "\n", "not json\n", eve(sig="ET Y") + "\n", "@@LOG\n",
             "Notice: pcap-file: read 1 files, 5321 packets, 2200 bytes\n", "@@END\n"]
    meta, log_lines = sc.split_run_output(iter(lines), out)
    assert meta["rc"] == "0" and meta["suricata_version"].startswith("This is Suricata")
    assert len(out.getvalue().splitlines()) == 2
    assert sc.packets_read(log_lines) == 5321
    assert sc.packets_read(["nothing"]) is None
    with pytest.raises(RuntimeError, match="early"):
        sc.split_run_output(iter(["@@ALERTS\n"]), io.StringIO())


# ---- matching ------------------------------------------------------------------------------------

def test_match_both_directions_and_protocol():
    f = flows([(A, 4444, V, 80, 6, T0, T0 + 2000, "x")])
    f_rev = flows([(V, 80, A, 4444, 6, T0, T0 + 2000, "x")])
    fwd = sc.alerts_frame([eve()])
    rev = sc.alerts_frame([eve(src=V, sport=80, dst=A, dport=4444)])
    for fl in (f, f_rev):
        for al in (fwd, rev):
            assert sc.match_alerts(fl, al)["flow"].tolist() == [0]
    # another protocol or port does not match
    assert sc.match_alerts(f, sc.alerts_frame([eve(proto="UDP")])).empty
    assert sc.match_alerts(f, sc.alerts_frame([eve(sport=4445)])).empty
    assert sc.match_alerts(f, sc.alerts_frame([eve(dst="10.10.2.11")])).empty


def test_match_time_window_with_slack():
    f = flows([(A, 4444, V, 80, 6, T0, T0 + 2000, "x")])
    ts = lambda ms: sc.alerts_frame([eve(ts=pd.Timestamp(T0 + ms, unit="ms", tz="UTC").strftime("%Y-%m-%dT%H:%M:%S.%f+0000"))])
    assert len(sc.match_alerts(f, ts(-1000))) == 1      # exactly 1 s before the start
    assert len(sc.match_alerts(f, ts(3000))) == 1       # exactly 1 s after the end
    assert sc.match_alerts(f, ts(-1001)).empty
    assert sc.match_alerts(f, ts(3001)).empty
    assert len(sc.match_alerts(f, ts(-1001), slack_ms=2000)) == 1


def test_match_same_tuple_reused_matches_only_the_right_flow():
    f = flows([(A, 4444, V, 80, 6, T0, T0 + 1000, "x"), (A, 4444, V, 80, 6, T0 + 60_000, T0 + 61_000, "x")])
    m = sc.match_alerts(f, sc.alerts_frame([eve(ts="2026-11-15T10:01:00.500000+0000")]))
    assert m["flow"].tolist() == [1]


def test_match_icmp_and_ipv6_keys():
    f = flows([(A, 0, V, 0, 1, T0, T0 + 10, "x"), ("fe80::1", 1234, "fe80::2", 53, 17, T0, T0 + 10, "x")])
    icmp = json.dumps({"timestamp": "2026-11-15T10:00:00.005000+0000", "event_type": "alert", "src_ip": V,
                       "dest_ip": A, "proto": "ICMP", "alert": {"signature": "ET P", "signature_id": 1}})
    v6 = eve(ts=NEAR, src="fe80::2", sport=53, dst="fe80::1", dport=1234, proto="UDP")
    m = sc.match_alerts(f, sc.alerts_frame([icmp, v6]))
    assert sorted(m["flow"]) == [0, 1]


def test_match_empty_inputs():
    f = flows([(A, 4444, V, 80, 6, T0, T0 + 10, "x")])
    assert sc.match_alerts(f, sc.alerts_frame([])).empty
    assert sc.match_alerts(f.iloc[0:0], sc.alerts_frame([eve()])).empty


def test_check_time_base():
    f = flows([(A, 4444, V, 80, 6, T0, T0 + 1000, "x")])
    span = sc.flow_span(f)
    sc.check_time_base(sc.alerts_frame([eve()]), span)  # fine
    shifted = sc.alerts_frame([eve(ts="2026-11-15T13:00:00.000000+0000")])  # 3 h off, as a wrong offset would be
    with pytest.raises(ValueError, match="time base"):
        sc.check_time_base(shifted, span, "x")
    sc.check_time_base(sc.alerts_frame([]), span)


def test_check_time_base_refuses_only_when_most_alerts_are_outside():
    span = (T0, T0 + 10_000)
    inside, outside = eve(ts="2026-11-15T10:00:05.000000+0000"), eve(ts="2026-11-15T14:00:00.000000+0000")
    sc.check_time_base(sc.alerts_frame([inside, inside, outside]), span)          # one in three outside: fine
    with pytest.raises(ValueError, match="33%"):
        sc.check_time_base(sc.alerts_frame([inside, outside, outside]), span)


# ---- metrics -------------------------------------------------------------------------------------

def _scenario():
    """4 PortScan flows, 2 BENIGN flows. Suricata attack alerts hit PortScan flows 0,1 and BENIGN flow 4;
    an engine event hits PortScan flow 2 and BENIGN flow 5."""
    rows = [(A, 1000 + i, V, 20 + i, 6, T0, T0 + 100, "PortScan") for i in range(4)]
    rows += [("10.10.2.50", 5000, V, 80, 6, T0, T0 + 100, "BENIGN"), ("10.10.2.51", 5001, V, 80, 6, T0, T0 + 100, "BENIGN")]
    f = flows(rows)
    al = [eve(ts=NEAR, sport=1000, dport=20, sid=1, sig="ET SCAN a"), eve(ts=NEAR, sport=1001, dport=21, sid=1, sig="ET SCAN a"),
          eve(ts=NEAR, sport=1002, dport=22, sid=2, sig="SURICATA STREAM z"),
          eve(ts=NEAR, src="10.10.2.50", sport=5000, dport=80, sid=3, sig="ET POLICY b"),
          eve(ts=NEAR, src="10.10.2.51", sport=5001, dport=80, sid=2, sig="SURICATA STREAM z")]
    return f, sc.match_alerts(f, sc.alerts_frame(al))


CLASSES = ["BENIGN", "PortScan"]


def test_compare_frame_recall_fpr_union():
    f, m = _scenario()
    # ML: flows 1,2 are detected with and without floor? flow 2 only without the floor; flow 4 is a BENIGN FP
    plain = ["BENIGN", "PortScan", "PortScan", "BENIGN", "PortScan", "BENIGN"]
    floored = ["BENIGN", "PortScan", "BENIGN", "BENIGN", "BENIGN", "BENIGN"]
    r = sc.compare_frame(f, m, plain, floored, CLASSES)
    p = r["per_label"]["PortScan"]
    assert p["flows"] == 4
    assert p["suricata_recall"] == 0.5 and p["suricata_recall_attack_only"] == 0.5
    assert p["suricata_recall_with_engine"] == 0.75 and p["engine_only_flows"] == 1
    assert p["ml_recall_no_floor"] == 0.5 and p["ml_recall_floor"] == 0.25
    assert p["union_recall_no_floor"] == 0.75          # flows 0,1 (Suricata) + 2 (ML) -> 3 of 4
    assert p["union_recall_floor"] == 0.5              # flows 0,1 + flow 1 again
    assert p["suricata_only_flows_no_floor"] == 1 and p["ml_only_flows_no_floor"] == 1
    assert p["top_signatures"] == [{"signature": "ET SCAN a", "flows": 2}]
    b = r["benign"]
    assert b["flows"] == 2
    assert b["suricata_fpr_attack_only"] == 0.5 and b["suricata_fpr_with_engine"] == 1.0
    assert b["suricata_false_positive_rate"] == 0.5
    assert b["ml_fpr_no_floor"] == 0.5 and b["ml_fpr_floor"] == 0.0
    assert b["suricata_top_attack_signatures"] == [{"signature": "ET POLICY b", "flows": 1}]
    assert b["suricata_top_engine_signatures"] == [{"signature": "SURICATA STREAM z", "flows": 1}]


def test_include_engine_changes_headline_only():
    f, m = _scenario()
    plain = floored = ["BENIGN"] * 6
    r = sc.compare_frame(f, m, plain, floored, CLASSES, include_engine=True)
    assert r["per_label"]["PortScan"]["suricata_recall"] == 0.75
    assert r["per_label"]["PortScan"]["suricata_recall_attack_only"] == 0.5
    assert r["benign"]["suricata_false_positive_rate"] == 1.0
    assert r["include_engine"] is True


def test_compare_frame_no_matches_and_no_benign():
    f = flows([(A, 1, V, 2, 6, T0, T0 + 1, "PortScan")])
    r = sc.compare_frame(f, pd.DataFrame(columns=["flow", "signature", "sid", "engine"]), ["PortScan"], ["PortScan"], CLASSES)
    assert r["per_label"]["PortScan"]["suricata_recall"] == 0.0
    assert r["per_label"]["PortScan"]["union_recall_no_floor"] == 1.0
    assert r["benign"]["suricata_false_positive_rate"] is None and r["benign"]["flows"] == 0


def test_flow_hits():
    m = pd.DataFrame({"flow": [0, 0, 2, 1], "signature": ["a", "b", "c", "ET INFO d"], "sid": [1, 2, 3, 4],
                      "engine": [False, True, True, False], "informational": [False, False, False, True]})
    attack, engine, security = sc.flow_hits(3, m)
    assert attack.tolist() == [True, True, False] and engine.tolist() == [True, False, True]
    assert security.tolist() == [True, False, False]   # flow 1 only has an informational alert


def test_informational_split():
    assert sc.is_informational("ET INFO Observed DNS Query", "Potentially Bad Traffic")
    assert sc.is_informational("ET POLICY curl User-Agent", None)
    assert sc.is_informational("GPL ICMP_INFO PING *NIX", "Misc activity")
    assert sc.is_informational("ET FOO bar", "Not Suricata Traffic") is False
    assert sc.is_informational("ET FOO bar", "Misc activity")
    assert not sc.is_informational("ET SCAN Nmap", "Attempted Information Leak")
    assert not sc.is_informational("SURICATA STREAM x", "Generic Protocol Command Decode")


def test_security_vs_all_recall_and_any_alert():
    rows = [(A, 1000 + i, V, 20 + i, 6, T0, T0 + 100, "PortScan") for i in range(2)]
    f = flows(rows + [("10.10.2.50", 5000, V, 80, 6, T0, T0 + 100, "BENIGN")])
    al = [eve(ts=NEAR, sport=1000, dport=20, sig="ET SCAN a", sid=1),
          eve(ts=NEAR, sport=1001, dport=21, sig="ET INFO b", sid=2),
          eve(ts=NEAR, src="10.10.2.50", sport=5000, dport=80, sig="ET POLICY c", sid=3)]
    m = sc.match_alerts(f, sc.alerts_frame(al))
    r = sc.compare_frame(f, m, ["BENIGN"] * 3, ["BENIGN"] * 3, CLASSES)
    p = r["per_label"]["PortScan"]
    assert p["suricata_recall"] == 1.0 and p["suricata_recall_security"] == 0.5
    assert p["any_alert"] == {"suricata": True, "suricata_security": True, "ml_floor": False, "ml_no_floor": False,
                              "suricata_flows_alerted": 2}
    assert r["benign"]["suricata_fpr_attack_only"] == 1.0 and r["benign"]["suricata_fpr_security"] == 0.0
    c = sc.alert_counts(sc.alerts_frame(al))
    assert (c["attack"], c["security"], c["informational"]) == (3, 1, 2)


# ---- one flow per alert -----------------------------------------------------------------------------

def test_alert_is_credited_to_one_flow_the_one_containing_it():
    # same 5-tuple reused three times, windows overlapping within the slack: the alert goes to one flow only
    f = flows([(A, 4444, V, 80, 6, T0, T0 + 1000, "x"), (A, 4444, V, 80, 6, T0 + 1500, T0 + 2500, "x"),
               (A, 4444, V, 80, 6, T0 + 2200, T0 + 3000, "x")])
    m = sc.match_alerts(f, sc.alerts_frame([eve(ts="2026-11-15T10:00:02.300000+0000")]))
    assert m["flow"].tolist() == [2]            # contained by flows 1 and 2; flow 2 starts nearest
    m = sc.match_alerts(f, sc.alerts_frame([eve(ts="2026-11-15T10:00:01.200000+0000")]))
    assert m["flow"].tolist() == [0]            # none contains it: flow 0 ends 200 ms before it, flow 1 starts 300 ms after


def test_icmp_alert_credits_one_flow_by_addresses_and_nearest_time():
    # ICMP flows have no real ports (dst_port may hold type/code): match by addresses, one flow per alert
    f = flows([(A, 0, V, 2048, 1, T0, T0 + 100, "x"), (A, 0, V, 2048, 1, T0 + 5000, T0 + 5100, "x"),
               (A, 0, V, 0, 1, T0 + 5200, T0 + 5300, "x")])
    icmp = json.dumps({"timestamp": "2026-11-15T10:00:05.050000+0000", "event_type": "alert", "src_ip": V,
                       "dest_ip": A, "proto": "ICMP", "alert": {"signature": "ET P", "signature_id": 1}})
    m = sc.match_alerts(f, sc.alerts_frame([icmp]))
    assert m["flow"].tolist() == [1]            # inside flow 1 only; the other flows are 150 ms or more away
    far = json.dumps({"timestamp": "2026-11-15T10:00:30.000000+0000", "event_type": "alert", "src_ip": V,
                      "dest_ip": A, "proto": "ICMP", "alert": {"signature": "ET P", "signature_id": 1}})
    assert sc.match_alerts(f, sc.alerts_frame([far])).empty


# ---- per-session detection -----------------------------------------------------------------------

def test_session_detection_attacker_traffic_only():
    al = sc.alerts_frame([eve(sig="ET SCAN a"), eve(sig="ET SCAN a"), eve(sig="SURICATA STREAM z"),
                          eve(src="10.10.2.50", dst=V, sig="ET OTHER")])
    s = sc.session_detection(al, A, 12, 3, 5)
    assert s["suricata_detected"] is True and s["suricata_attack_alerts"] == 2 and s["suricata_engine_alerts"] == 1
    assert s["suricata_signatures"] == [{"signature": "ET SCAN a", "alerts": 2}]
    assert s["ml_detected_floor"] is True and s["ml_flows_flagged_no_floor"] == 5


def test_session_detection_only_engine_events_is_not_detection():
    al = sc.alerts_frame([eve(sig="SURICATA STREAM z")])
    s = sc.session_detection(al, A, 1, 0, 0)
    assert s["suricata_detected"] is False and s["suricata_engine_alerts"] == 1
    assert s["ml_detected_floor"] is False
    assert sc.session_detection(sc.alerts_frame([]), A, 1, 0, 0)["suricata_detected"] is False


# ---- run bookkeeping and report ------------------------------------------------------------------

def _cached(tmp_path, **meta):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"abc")
    out = tmp_path / "o"
    out.mkdir(exist_ok=True)
    sc.alerts_path("x", out).write_text("")
    st = pcap.stat()
    m = {"pcap_bytes": st.st_size, "pcap_mtime_ns": st.st_mtime_ns, "home_net": ["10.10.2.0/24"],
         "image": sc.IMAGE, "rules_sha256": "aa", "rules_updated_at": "2026_11_13", "rules_loaded": 100,
         "log_errors": []}
    m.update(meta)
    sc.meta_path("x", out).write_text(json.dumps(m))
    return pcap, out


def test_up_to_date(tmp_path):
    pcap, out = _cached(tmp_path)
    nets = ["10.10.2.0/24"]
    assert sc.up_to_date(pcap, "x", nets, out)
    assert not sc.up_to_date(pcap, "x", ["192.168.10.0/24"], out)
    assert not sc.up_to_date(pcap, "nothing", nets, out)
    pcap.write_bytes(b"abcd")
    assert not sc.up_to_date(pcap, "x", nets, out)


def test_up_to_date_keys_on_rules(tmp_path):
    pcap, out = _cached(tmp_path)
    nets = ["10.10.2.0/24"]
    assert sc.up_to_date(pcap, "x", nets, out, {"rules_sha256": "aa", "rules_updated_at": "2026_11_13"})
    assert not sc.up_to_date(pcap, "x", nets, out, {"rules_sha256": "bb", "rules_updated_at": "2026_11_13"})
    assert not sc.up_to_date(pcap, "x", nets, out, {"rules_sha256": "aa", "rules_updated_at": "2026_12_01"})


def test_up_to_date_never_caches_a_run_with_errors_or_without_rules(tmp_path):
    nets = ["10.10.2.0/24"]
    pcap, out = _cached(tmp_path, log_errors=["Error: pcap-file: truncated"])
    assert not sc.up_to_date(pcap, "x", nets, out)
    pcap, out = _cached(tmp_path, rules_loaded=0)
    assert not sc.up_to_date(pcap, "x", nets, out)
    pcap, out = _cached(tmp_path, rules_sha256=None)
    assert not sc.up_to_date(pcap, "x", nets, out)


def test_up_to_date_with_missing_pcap_uses_cached_alerts(tmp_path):
    pcap, out = _cached(tmp_path)
    pcap.unlink()
    assert sc.up_to_date(pcap, "x", ["10.10.2.0/24"], out) is True          # does not crash
    assert not sc.up_to_date(pcap, "x", ["10.10.2.0/24"], out, {"rules_sha256": "other", "rules_updated_at": ""})


def test_build_tables_renders():
    f, m = _scenario()
    r = sc.compare_frame(f, m, ["PortScan"] * 6, ["BENIGN"] * 6, CLASSES)
    r["sessions"] = [{"session": "portscan", "repeat": 1, "flows": 4, **sc.session_detection(sc.alerts_frame([eve()]), A, 4, 0, 4)}]
    r["split"] = {"friday_test_rows": 6, "friday_rows_total": 10}
    text = sc.build_tables("T", r)
    assert "| PortScan | 4 | 50.0% |" in text and "ET SCAN a (2)" in text
    assert "BENIGN false-positive rate over 2 flows" in text and "portscan #1" in text and "test split" in text


def test_friday_split_uses_trainers_function():
    """The Friday rows come from idps.detect.train.make_split, not from a copy of its logic."""
    src = (_SCRIPTS / "suricata_compare.py").read_text()
    assert "from idps.detect.train import make_split" in src and "make_split(df, \"class-time\")" in src


def test_log_errors_levels():
    lines = ["Info: suricata: ok", "i: ok", "Warning: detect: x", "W: y", "Notice: z", "Error: pcap-file: truncated",
             "Critical: x", "E: pcap: bad", "  Error: indented", "Alert: a", "Emergency: e", "Em: e", "C: c", "A: a",
             "Info: an Error: in the middle"]
    got = sc.log_errors(lines)
    assert got == ["Error: pcap-file: truncated", "Critical: x", "E: pcap: bad", "  Error: indented", "Alert: a",
                   "Emergency: e", "Em: e", "C: c", "A: a"]


def test_packets_read_and_rules_lines_from_verbose_log():
    assert sc.packets_read(["Info: pcap: read 1 file, 1301052 packets, 205588056 bytes"]) == 1301052
    assert sc.packets_read(["read 3 files, 9 packets, 1 bytes"]) == 9
    line = "Info: detect: 1 rule files processed. 53510 rules successfully loaded, 0 rules failed, 0"
    assert sc.rules_loaded([line]) == 53510 and sc.rules_failed([line]) == 0
    assert sc.rules_loaded(["Info: detect: 1 rule files processed. 0 rules successfully loaded, 0 rules failed, 0"]) == 0
    assert sc.rules_loaded(["Info: nothing"]) is None and sc.rules_failed(["Info: nothing"]) is None


def test_split_run_output_dedupes_log_lines():
    lines = ["@@LOG", "Info: a", "Info: b", "Info: b", "Info: c", "@@END"]
    _, log_lines = sc.split_run_output(iter(lines), io.StringIO())
    assert log_lines == ["Info: a", "Info: b", "Info: c"]


# ---- run_suricata with the container mocked --------------------------------------------------------------

GOOD_LOG = ["Info: detect: 1 rule files processed. 53510 rules successfully loaded, 0 rules failed, 0",
            "Info: pcap: read 1 file, 77 packets, 5000 bytes"]


def fake_container(meta=None, log_lines=None, alerts=None, rc=0, end=True):
    base = {"suricata_version": "This is Suricata version 7.0.10 RELEASE", "rules_sha256": "ab" * 32,
            "rules_updated_at": "2026_11_13", "rules_enabled": "53510", "rc": "0", "out_kb": "12"}
    base.update(meta or {})
    lines = [f"@@META {k}={v}" for k, v in base.items() if v is not None]
    lines += ["@@ALERTS", *(alerts if alerts is not None else [eve()]), "@@LOG", *(GOOD_LOG if log_lines is None else log_lines)]
    if end:
        lines.append("@@END")
    text = "\n".join(lines) + "\n"

    def run(cmd, stdin=None, stdout=None, stderr=None, text=None, env=None, timeout=None, **kw):
        run.cmd = cmd
        stdout.write(text_out)
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="boom" if rc else "")
    text_out = text
    return run


import subprocess  # noqa: E402


@pytest.fixture
def pcap(tmp_path):
    p = tmp_path / "t.pcap"
    p.write_bytes(b"x" * 10)
    return p


def _run(monkeypatch, pcap, tmp_path, **kw):
    monkeypatch.setattr(sc.subprocess, "run", fake_container(**kw))
    return sc.run_suricata(pcap, "lab", out_dir=tmp_path / "out")


def test_run_suricata_saves_alerts_and_meta(monkeypatch, pcap, tmp_path):
    info = _run(monkeypatch, pcap, tmp_path)
    out = tmp_path / "out"
    assert len((out / "t.alerts.jsonl").read_text().splitlines()) == 1
    meta = json.loads((out / "t.meta.json").read_text())
    assert meta["rules_loaded"] == 53510 and meta["rules_enabled"] == 53510 and meta["packets_read"] == 77
    assert meta["home_net"] == ["10.10.2.0/24"] and meta["rules_updated_at"] == "2026_11_13" and info["log_errors"] == []
    assert not list(out.glob("*.tmp"))
    cmd = sc.subprocess.run.cmd
    assert f"{sc.VOLUME}:/var/lib/suricata:ro" in cmd           # rules volume read-only
    assert "--init-errors-fatal" in cmd[-1]


@pytest.mark.parametrize("kw,msg", [
    ({"meta": {"rc": "1"}}, "status 1"),
    ({"log_lines": ["Info: detect: 1 rule files processed. 0 rules successfully loaded, 0 rules failed, 0"]}, "no rules were loaded"),
    ({"log_lines": ["Info: pcap: read 1 file, 5 packets, 9 bytes"]}, "rules successfully loaded"),
    ({"log_lines": ["Info: detect: 1 rule files processed. 5 rules successfully loaded, 2 rules failed, 0"]}, "2 rules failed"),
    ({"log_lines": [*GOOD_LOG, "Warning: detect: No rule files match the pattern /x"]}, "No rule files match"),
    ({"log_lines": [*GOOD_LOG, "Warning: detect: 1 rule files specified, but no rules were loaded!"]}, "no rules were loaded"),
    ({"meta": {"rules_sha256": None}}, "rules_sha256 missing"),
    ({"meta": {"rules_enabled": "0"}}, "rules_enabled"),
    ({"meta": {"rules_enabled": None}}, "rules_enabled"),
])
def test_run_suricata_refuses_untrustworthy_runs(monkeypatch, pcap, tmp_path, kw, msg):
    with pytest.raises(RuntimeError, match=msg):
        _run(monkeypatch, pcap, tmp_path, **kw)
    out = tmp_path / "out"
    assert not list(out.glob("*.alerts.jsonl")) and not list(out.glob("*.meta.json")) and not list(out.glob("*.tmp"))


def test_run_suricata_keeps_previous_files_when_a_rerun_fails(monkeypatch, pcap, tmp_path):
    _run(monkeypatch, pcap, tmp_path)
    before = (tmp_path / "out" / "t.alerts.jsonl").read_text()
    with pytest.raises(RuntimeError):
        _run(monkeypatch, pcap, tmp_path, log_lines=["i: 0 rules successfully loaded"], alerts=[])
    assert (tmp_path / "out" / "t.alerts.jsonl").read_text() == before
    assert not list((tmp_path / "out").glob("*.tmp"))


def test_run_suricata_nonzero_docker_and_missing_end_marker(monkeypatch, pcap, tmp_path):
    with pytest.raises(RuntimeError, match="docker run failed"):
        _run(monkeypatch, pcap, tmp_path, rc=125)
    with pytest.raises(RuntimeError, match="early"):
        _run(monkeypatch, pcap, tmp_path, end=False)
    assert not list((tmp_path / "out").glob("*.tmp")) and not list((tmp_path / "out").glob("*.alerts.jsonl"))
    with pytest.raises(FileNotFoundError):
        sc.run_suricata(tmp_path / "nope.pcap", "lab", out_dir=tmp_path / "out")


def test_run_suricata_records_log_errors(monkeypatch, pcap, tmp_path):
    info = _run(monkeypatch, pcap, tmp_path, log_lines=[*GOOD_LOG, "Error: pcap-file: error code -1 truncated dump file"])
    assert info["log_errors"] == ["Error: pcap-file: error code -1 truncated dump file"]
    assert not sc.up_to_date(pcap, "t", ["10.10.2.0/24"], tmp_path / "out")   # never cached


# ---- friday_test_rows: day filter and count check ----------------------------------------------------------

DAY = 86_400_000


class FakeSplit:
    def __init__(self, test, train):
        self.test, self.train = test, train


def _friday_env(monkeypatch, tmp_path, expected_rows):
    import idps.detect.data as data_mod
    import idps.detect.split as split_mod
    import idps.detect.train as train_mod
    import idps.features as feat_mod

    thursday, friday = 1499300000000 // DAY * DAY + 3600_000, 1499400000000 // DAY * DAY + 3600_000
    week = pd.DataFrame({"start_ms": [thursday, thursday + 5, friday, friday + 5, friday + 9],
                         "end_ms": [thursday + 1, thursday + 6, friday + 1, friday + 6, friday + 10],
                         "label": ["BENIGN"] * 5})
    fri = week.iloc[2:].reset_index(drop=True)
    test = week.iloc[[1, 2, 4]]       # one Thursday row and two Friday rows
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"split": {"parts": {"test": {"rows": expected_rows}}}}))
    monkeypatch.setattr(data_mod, "load_labelled", lambda files: (week, {"m": 1}))
    monkeypatch.setattr(train_mod, "make_split", lambda df, mode: FakeSplit(test, week.iloc[:1]))
    monkeypatch.setattr(feat_mod, "read_features", lambda p: (fri, {}))
    monkeypatch.setattr(split_mod, "_identical_to_train", lambda tr, rows, feats: {"rows": 1, "share": 0.5})
    return report, friday


def test_friday_test_rows_keeps_only_friday_rows_of_the_test_split(monkeypatch, tmp_path):
    report, friday = _friday_env(monkeypatch, tmp_path, 3)
    rows, meta, desc = sc.friday_test_rows(tmp_path, report)
    assert rows["start_ms"].tolist() == [friday, friday + 5 + 4]
    assert rows.index.tolist() == [0, 1] and meta == {"m": 1}
    assert desc["week_test_rows"] == 3 and desc["friday_test_rows"] == 2 and desc["friday_rows_total"] == 3
    assert desc["friday_span_ms"] == [friday, friday + 10]            # all Friday flows, not just the test rows
    assert desc["friday_identical_to_train"] == {"rows": 1, "share": 0.5}


def test_friday_test_rows_refuses_a_split_that_does_not_match_the_model_report(monkeypatch, tmp_path):
    report, _ = _friday_env(monkeypatch, tmp_path, 194543)
    with pytest.raises(RuntimeError, match="194543"):
        sc.friday_test_rows(tmp_path, report)


# ---- compare_lab: index remap, sessions without alerts, one bad session -----------------------------------

def _lab_env(monkeypatch, tmp_path, sessions):
    """sessions: {(session, repeat): [flow rows]}; returns the flow frame saved for compare_lab."""
    import idps.features as feat_mod
    rows = []
    for (sess, rep), rs in sessions.items():
        for r in rs:
            rows.append((sess, rep, *r))
    df = pd.DataFrame(rows, columns=["session", "repeat", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                                     "start_ms", "end_ms", "label"])
    monkeypatch.setattr(feat_mod, "read_features", lambda p: (df, {}))
    n = len(df)
    monkeypatch.setattr(sc, "predict_week", lambda d, m: (["PortScan"] * n, ["PortScan"] * n, CLASSES, "sha"))
    return df


def _write_alerts(out, name, lines):
    out.mkdir(exist_ok=True)
    sc.alerts_path(name, out).write_text("\n".join(lines) + ("\n" if lines else ""))


def test_compare_lab_remaps_flows_when_sessions_are_missing(monkeypatch, tmp_path):
    out = tmp_path / "o"
    scan = lambda i, label="PortScan": (A, 1000 + i, V, 20 + i, 6, T0, T0 + 100, label)
    ben = lambda i: ("10.10.2.50", 5000 + i, V, 80, 6, T0, T0 + 100, "BENIGN")
    _lab_env(monkeypatch, tmp_path, {("benign", 1): [ben(0), ben(1)],
                                     ("portscan", 1): [scan(0), scan(1)],     # no alerts file: left out
                                     ("portscan", 2): [scan(0), scan(1), scan(2)]})
    # alerts only for benign_1 (flow 1 of it) and portscan_2 (flow 2 of it)
    _write_alerts(out, "benign_1", [eve(ts=NEAR, src="10.10.2.50", sport=5001, dport=80, sig="ET POLICY x")])
    _write_alerts(out, "portscan_2", [eve(ts=NEAR, sport=1002, dport=22, sig="ET SCAN a")])
    res = sc.compare_lab(tmp_path / "lab.parquet", out)
    assert res["missing_alert_files"] == ["portscan_1"] and res["errors"] == {}
    assert res["flows"] == 5                                   # 2 benign + 3 portscan_2
    p = res["per_label"]["PortScan"]
    assert p["flows"] == 3 and p["suricata_recall"] == round(1 / 3, 4)      # only portscan_2's flow 2 is credited
    assert p["top_signatures"] == [{"signature": "ET SCAN a", "flows": 1}]
    assert res["benign"]["flows"] == 2 and res["benign"]["suricata_false_positives"] == 1
    assert {(x["session"], x["repeat"]) for x in res["sessions"]} == {("benign", 1), ("portscan", 2)}
    assert res["sessions"][1]["suricata_detected"] is True


def test_compare_lab_records_a_bad_session_and_goes_on(monkeypatch, tmp_path):
    out = tmp_path / "o"
    _lab_env(monkeypatch, tmp_path, {("portscan", 1): [(A, 1000, V, 20, 6, T0, T0 + 100, "PortScan")],
                                     ("portscan", 2): [(A, 1000, V, 20, 6, T0, T0 + 100, "PortScan")]})
    _write_alerts(out, "portscan_1", [eve(ts="2026-11-15T20:00:00.000000+0000")])      # wrong time base
    _write_alerts(out, "portscan_2", [eve(ts=NEAR, sport=1000, dport=20)])
    res = sc.compare_lab(tmp_path / "lab.parquet", out)
    assert list(res["errors"]) == ["portscan_1"] and res["flows"] == 1
    assert res["per_label"]["PortScan"]["suricata_recall"] == 1.0
    assert "FAILED portscan_1" in sc.build_tables("t", res)


def test_compare_lab_excludes_failed_runs_and_raises_when_nothing_usable(monkeypatch, tmp_path):
    out = tmp_path / "o"
    _lab_env(monkeypatch, tmp_path, {("portscan", 1): [(A, 1000, V, 20, 6, T0, T0 + 100, "PortScan")]})
    _write_alerts(out, "portscan_1", [eve(ts=NEAR, sport=1000, dport=20)])
    with pytest.raises(RuntimeError, match="no usable"):
        sc.compare_lab(tmp_path / "lab.parquet", out, exclude={"portscan_1"})


# ---- all: one failing pcap or dataset does not stop the rest -----------------------------------------------

def _args(tmp_path, **kw):
    import argparse
    ns = argparse.Namespace(pcaps_dir=tmp_path / "pc", friday=False, friday_pcap=tmp_path / "fri.pcap", force=True,
                            full_eve=False, out_dir=tmp_path / "out", include_engine=False,
                            report=tmp_path / "rep.json", lab_data=tmp_path / "lab.parquet", lab=True)
    ns.__dict__.update(kw)
    return ns


def test_all_continues_after_a_failed_run_and_exits_nonzero(monkeypatch, tmp_path):
    pc = tmp_path / "pc"
    pc.mkdir()
    for n in ("a_1", "b_1"):
        (pc / f"{n}.pcap").write_bytes(b"x")
    ran = []

    def fake_run(pcap, dataset, name, out_dir, alert_only=True, **kw):
        ran.append(name)
        if name == "a_1":
            raise RuntimeError("no rules were loaded")
    seen = {}
    monkeypatch.setattr(sc, "run_suricata", fake_run)
    monkeypatch.setattr(sc, "compare_lab", lambda data, out, eng, exclude: seen.update(exclude=exclude) or {
        "include_engine": False, "per_label": {}, "benign": {"flows": 0, "suricata_fpr_attack_only": None,
        "suricata_fpr_security": None, "suricata_fpr_with_engine": None, "ml_fpr_floor": None, "ml_fpr_no_floor": None},
        "errors": {}})
    rc = sc.run_all(_args(tmp_path))
    assert ran == ["a_1", "b_1"] and rc == 1 and seen["exclude"] == {"a_1"}
    rep = json.loads((tmp_path / "rep.json").read_text())
    assert rep["suricata_run_errors"] == {"a_1": "no rules were loaded"}


def test_compare_reports_a_failed_friday_and_still_writes_the_report(monkeypatch, tmp_path):
    monkeypatch.setattr(sc, "compare_friday", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("alerts missing")))
    rc = sc.run_compare(_args(tmp_path, friday=True, lab=False, out_dir=tmp_path))
    assert rc == 1
    assert json.loads((tmp_path / "rep.json").read_text())["datasets"]["friday"] == {"error": "alerts missing"}


def test_all_skips_cached_runs_by_rules(monkeypatch, tmp_path):
    pc = tmp_path / "pc"
    pc.mkdir()
    (pc / "a_1.pcap").write_bytes(b"x")
    out = tmp_path / "out"
    out.mkdir()
    sc.alerts_path("a_1", out).write_text("")
    st = (pc / "a_1.pcap").stat()
    sc.meta_path("a_1", out).write_text(json.dumps({
        "pcap_bytes": st.st_size, "pcap_mtime_ns": st.st_mtime_ns, "home_net": ["10.10.2.0/24"], "image": sc.IMAGE,
        "rules_sha256": "aa", "rules_updated_at": "u", "rules_loaded": 5, "log_errors": []}))
    ran = []
    monkeypatch.setattr(sc, "run_suricata", lambda *a, **k: ran.append(a[2]))
    monkeypatch.setattr(sc, "run_compare", lambda args, exclude=None: 0)
    monkeypatch.setattr(sc, "current_rules_info", lambda: {"rules_sha256": "aa", "rules_updated_at": "u"})
    sc.run_all(_args(tmp_path, force=False))
    assert ran == []
    monkeypatch.setattr(sc, "current_rules_info", lambda: {"rules_sha256": "NEW", "rules_updated_at": "u"})
    sc.run_all(_args(tmp_path, force=False))
    assert ran == ["a_1"]
