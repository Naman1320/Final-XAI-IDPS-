"""idps.rules.eve: eve alert parsing, engine/informational classification, families, the payload."""
import json

import pytest

from idps.rules import eve


def event(sig="ET SCAN Nmap Scripting Engine User-Agent Detected", sid=2009358, cat="Web Application Attack",
          severity=1, src="10.10.1.10", dst="10.10.2.11", dport=80, proto="TCP", direction="to_server",
          ts="2026-11-15T10:00:00.250000+0000", **extra):
    ev = {"timestamp": ts, "event_type": "alert", "src_ip": src, "src_port": 40000, "dest_ip": dst,
          "dest_port": dport, "proto": proto, "direction": direction,
          "alert": {"gid": 1, "signature_id": sid, "rev": 7, "signature": sig, "category": cat,
                    "severity": severity}}
    return json.dumps(ev | extra)


def test_parse_alert_line_fields():
    a = eve.parse_alert_line(event())
    assert a["ts_ms"] == eve.eve_timestamp_ms("2026-11-15T10:00:00.250000+0000")
    assert (a["src_ip"], a["dst_ip"], a["dst_port"], a["protocol"]) == ("10.10.1.10", "10.10.2.11", 80, 6)
    assert (a["sid"], a["rev"], a["severity"], a["direction"]) == (2009358, 7, 1, "to_server")
    assert a["engine"] is False and a["informational"] is False


def test_parse_skips_non_alerts_and_rejects_bad_lines():
    assert eve.parse_alert_line(event().replace('"alert"', '"flow"', 1)) is None
    assert eve.parse_alert_line("") is None and eve.parse_alert_line("not json") is None
    with pytest.raises(ValueError):
        eve.parse_alert_line("{broken")
    with pytest.raises(ValueError):  # a timestamp without an offset
        eve.parse_alert_line(event(ts="2026-11-15T10:00:00.000000"))


def test_engine_and_informational_classification():
    assert eve.is_engine_event("SURICATA STREAM Packet with invalid ack")
    assert not eve.is_engine_event("ET SCAN x")
    for sig in ("ET INFO Something", "ET POLICY Dropbox", "GPL ICMP_INFO PING", "GPL INFO x", "GPL POLICY y"):
        assert eve.is_informational(sig, "Attempted Information Leak"), sig
    for cat in ("Not Suspicious Traffic", "Misc activity", "Potential Corporate Privacy Violation"):
        assert eve.is_informational("ET FOO bar", cat), cat
    assert not eve.is_informational("ET SCAN x", "Detection of a Network Scan")
    assert not eve.is_informational("SURICATA STREAM x", "Generic Protocol Command Decode")  # engine, not info
    a = eve.parse_alert_line(event(sig="SURICATA TCPv4 invalid checksum", cat="Generic Protocol Command Decode"))
    assert a["engine"] is True and a["informational"] is False


@pytest.mark.parametrize("sig,cat,family", [
    ("ET SCAN Nmap Scripting Engine User-Agent Detected", "Web Application Attack", "Scan"),
    ("ET WEB_SERVER SQL Injection Attempt", "Web Application Attack", "Web Attack"),
    ("ET WEB_SPECIFIC_APPS DVWA thing", "Web Application Attack", "Web Attack"),
    ("ET SCAN Potential SSH Scan", "Attempted Information Leak", "Scan"),
    ("ET DOS Possible SSDP Amplification", "Attempted Denial of Service", "DoS"),
    ("ET MALWARE Win32/Foo Checkin", "A Network Trojan was detected", "Malware"),
    ("ET TROJAN Foo CnC", "A Network Trojan was detected", "Malware"),
    ("ET EXPLOIT Apache Struts RCE", "Attempted Administrator Privilege Gain", "Exploit"),
    ("ET POLICY Outbound Dropbox", "Potential Corporate Privacy Violation", "Policy"),
    ("ET INFO Observed DNS Query", "Misc activity", "Policy"),
    ("ET SCAN Possible Brute Force Login Attempt", "Attempted Information Leak", "Brute Force"),
    ("ET FTP FTP Login Attempt (cwd)", "Misc activity", "Policy"),
    ("ET SOMETHING Odd", "Web Application Attack", "Web Attack"),   # category decides
    ("ET WEB_SERVER SQLite database dump", "Web Application Attack", "Web Attack"),  # by prefix, not "SQLI"
    ("ET SOMETHING SQLite error", "Unknown Traffic", "Rule match"),        # SQLI must not match SQLITE
    ("ET SOMETHING Possible SQLi attempt", "Unknown Traffic", "Web Attack"),
    ("ET SOMETHING Hexxss Thing", "Unknown Traffic", "Rule match"),        # whole words only
    ("ET TROJAN Foo SQL Injection Brute Force", "A Network Trojan was detected", "Malware"),  # prefix first
    ("ET EXPLOIT Foo brute force", "Misc activity", "Exploit"),
    ("ET SCAN Possible brute force", "Misc activity", "Brute Force"),
    ("ET SOMETHING Odd", "Executable Code was Detected", "Exploit"),
    ("ET SOMETHING Odd", "Unknown Traffic", "Rule match"),
    ("ET SOMETHING Odd", None, "Rule match"),
])
def test_rule_family(sig, cat, family):
    assert eve.rule_family(sig, cat) == family


def test_severity_maps_to_confidence_and_is_clamped():
    assert [eve.severity_confidence(s) for s in (1, 2, 3, 4)] == [0.95, 0.85, 0.70, 0.55]
    assert eve.clamp_severity(0) == 1 and eve.clamp_severity(9) == 4
    assert eve.clamp_severity(None) == 3 and eve.clamp_severity("x") == 3


def test_rule_alert_payload_shape():
    a = eve.parse_alert_line(event())
    p = eve.rule_alert_payload(a)
    assert p == {
        "src_ip": "10.10.1.10", "src_port": 40000, "dst_ip": "10.10.2.11", "dst_port": 80, "protocol": 6,
        "start_ms": a["ts_ms"], "end_ms": a["ts_ms"], "predicted_class": "Scan", "confidence": 0.95,
        "source": "rule",
        "rule": {"sid": 2009358, "rev": 7,
                 "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                 "category": "Web Application Attack", "severity": 1, "count": 1}}
    f = eve.rule_alert_payload(a, 12, start_ms=a["ts_ms"] - 5000, end_ms=a["ts_ms"] + 1000)
    assert f["rule"]["count"] == 12 and f["start_ms"] == a["ts_ms"] - 5000 and f["end_ms"] == a["ts_ms"] + 1000


def test_rule_alert_payload_refuses_unusable_events_and_cleans_text():
    base = eve.parse_alert_line(event())
    assert eve.rule_alert_payload({**base, "src_ip": "nope"}) is None
    assert eve.rule_alert_payload({**base, "protocol": None}) is None
    assert eve.rule_alert_payload({**base, "sid": None}) is None
    p = eve.rule_alert_payload({**base, "signature": "ET X \x00" + chr(0x202E) + "" + "y" * 400, "severity": 99})
    assert p["rule"]["severity"] == 4 and len(p["rule"]["signature"]) == 300
    assert "\x00" not in p["rule"]["signature"] and chr(0x202E) not in p["rule"]["signature"]


def test_suricata_compare_still_uses_the_shared_helpers():
    """The comparison script imports its eve helpers from the package; same objects, same behaviour."""
    import importlib.util
    import sys
    from pathlib import Path

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    spec = importlib.util.spec_from_file_location("suricata_compare_moved", scripts / "suricata_compare.py")
    sc = importlib.util.module_from_spec(spec)
    sys.modules["suricata_compare_moved"] = sc
    spec.loader.exec_module(sc)
    assert sc.parse_alert_line is eve.parse_alert_line and sc.is_informational is eve.is_informational
    assert sc.is_engine_event is eve.is_engine_event and sc.eve_timestamp_ms is eve.eve_timestamp_ms
    df = sc.alerts_frame([event(), event(sig="SURICATA STREAM x"), event().replace('"alert"', '"flow"', 1)])
    assert list(df.columns) == sc.ALERT_COLUMNS and len(df) == 2
    assert df["engine"].tolist() == [False, True]


@pytest.mark.parametrize("sig", ["ET EXPLOIT Foo", "ET SCAN Nmap", "ET MALWARE Bar", "ET TROJAN Baz", "ET DOS X",
                                 "ET WEB_SERVER Y", "GPL EXPLOIT Z", "ET CNC Host"])
def test_an_attack_ruleset_is_not_informational_whatever_its_category(sig):
    for cat in ("Misc activity", "Not Suspicious Traffic", "Potential Corporate Privacy Violation"):
        assert not eve.is_informational(sig, cat), (sig, cat)
    assert eve.is_informational("ET INFO Foo", "Misc activity") and eve.is_informational("ET FOO", "Misc activity")


def test_is_established_tcp():
    est = eve.is_established_tcp
    base = eve.parse_alert_line(event())
    assert not est(base)  # no app_proto, no flow counters: a bare SYN
    assert est({**base, "app_proto": "http"})
    assert est({**base, "pkts_toserver": 2, "pkts_toclient": 1})
    assert not est({**base, "pkts_toserver": 2, "pkts_toclient": 0})
    assert not est({**base, "app_proto": "failed"})
    assert not est({**base, "protocol": 17, "app_proto": "dns", "pkts_toserver": 1, "pkts_toclient": 1})
    parsed = eve.parse_alert_line(event(app_proto="http", flow={"pkts_toserver": 2, "pkts_toclient": 1}))
    assert parsed["app_proto"] == "http" and (parsed["pkts_toserver"], parsed["pkts_toclient"]) == (2, 1)
