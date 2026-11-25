"""scripts/lab_attacks.py: the pure helpers, the OFFLINE_PY snippet and the ATTACKS table.
Nothing here starts docker or touches the lab."""

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
_spec = importlib.util.spec_from_file_location("lab_attacks", _SCRIPTS / "lab_attacks.py")
la = importlib.util.module_from_spec(_spec)
sys.modules["lab_attacks"] = la
_spec.loader.exec_module(la)

BASE = datetime(2026, 11, 14, 10, 0, 0, tzinfo=UTC)
BASE_MS = BASE.timestamp() * 1000

MODEL_CLASSES = {
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
    "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
    "Web Attack - Brute Force", "Web Attack - XSS",
}
NOT_A_CLASS = "Web Attack - Sql Injection"  # in web_sqli's family, but the model has no such class


def ts(offset_s: float) -> str:
    return (BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def alert(cls="PortScan", conf=0.9, src="10.10.1.10", sport=40000, dst="10.10.2.10", dport=80,
          start=20.0, end=30.0, recv=None):
    return {"predicted_class": cls, "confidence": conf, "src_ip": src, "src_port": sport,
            "dst_ip": dst, "dst_port": dport, "protocol": 6,
            "start_ms": BASE_MS + start * 1000, "end_ms": BASE_MS + end * 1000,
            "received_at": ts(end + 1 if recv is None else recv)}


# ---- attacker_alerts ----------------------------------------------------------------------------

def test_attacker_alerts_dedupes_by_alert_key():
    a = alert()
    assert la.attacker_alerts([a, dict(a), alert(sport=40001)], BASE_MS) == [a, alert(sport=40001)]


def test_attacker_alerts_keeps_src_or_dst_drops_others():
    out = la.attacker_alerts([
        alert(src="10.10.1.10", dst="10.10.2.10", sport=1),
        alert(src="10.10.2.10", dst="10.10.1.10", sport=2),
        alert(src="10.10.1.100", dst="10.10.2.10", sport=3),
        alert(src="10.10.3.3", dst="10.10.2.10", sport=4),
    ], BASE_MS)
    assert [a["src_port"] for a in out] == [1, 2]


def test_attacker_alerts_drops_old_flows_by_slack():
    slack = la.WINDOW_SLACK_MS / 1000
    old = alert(sport=1, start=-100, end=-slack - 1)
    edge = alert(sport=2, start=-100, end=-slack)
    assert [a["src_port"] for a in la.attacker_alerts([old, edge], BASE_MS)] == [2]


def test_attacker_alerts_custom_attacker():
    a = alert(src="10.10.9.9")
    assert la.attacker_alerts([a], BASE_MS, attacker="10.10.9.9") == [a]
    assert la.attacker_alerts([a], BASE_MS) == []


# ---- summarize ----------------------------------------------------------------------------------

FAM = ("PortScan",)


def test_summarize_rates_and_class_counts():
    al = [alert("PortScan", 0.95, sport=1), alert("PortScan", 0.6, sport=2),
          alert("Bot", 0.95, sport=3)]
    s = la.summarize(al, started=BASE, truth_flows=10, family=FAM)
    assert s["alerts"] == 3
    assert s["by_class"] == {"PortScan": 2, "Bot": 1}
    assert s["right_family"] == 2
    assert s["right_family_share"] == round(2 / 3, 4)
    assert s["detection_rate"] == 0.2
    assert s["any_attack_rate"] == 0.3


def test_summarize_first_alert_uses_right_family_only():
    al = [alert("Bot", recv=5), alert("PortScan", recv=40), alert("PortScan", recv=25)]
    assert la.summarize(al, started=BASE, truth_flows=3, family=FAM)["time_to_first_alert_s"] == 25.0


def test_summarize_no_right_family_gives_none_ttd():
    s = la.summarize([alert("Bot")], started=BASE, truth_flows=1, family=FAM)
    assert s["time_to_first_alert_s"] is None
    assert s["right_family"] == 0
    assert s["detection_rate"] == 0.0


def test_summarize_ttd_zero_is_zero():
    s = la.summarize([alert(recv=0)], started=BASE, truth_flows=1, family=FAM)
    assert s["time_to_first_alert_s"] == 0.0


def test_summarize_truth_flows_none_or_zero():
    for tf in (None, 0):
        s = la.summarize([alert()], started=BASE, truth_flows=tf, family=FAM)
        assert s["detection_rate"] is None and s["any_attack_rate"] is None
        assert s["alerts"] == 1


def test_summarize_no_alerts_is_none_safe():
    s = la.summarize([], started=BASE, truth_flows=None, family=FAM)
    assert s["alerts"] == 0 and s["by_class"] == {} and s["right_family"] == 0
    for k in ("right_family_share", "detection_rate", "any_attack_rate", "time_to_first_alert_s",
              "flow_end_to_soc_p50_s", "confidence_median", "confident_share"):
        assert s[k] is None, k


def test_summarize_confident_share_threshold_is_inclusive_090():
    al = [alert(conf=0.9, sport=1), alert(conf=0.89, sport=2), alert(conf=0.99, sport=3),
          alert(conf=0.5, sport=4)]
    assert la.summarize(al, started=BASE, truth_flows=4, family=FAM)["confident_share"] == 0.5


# ---- detected / in_set --------------------------------------------------------------------------

def test_detected():
    assert la.detected({"live": {"right_family": 3}})
    assert not la.detected({"live": {"right_family": 0}})
    assert not la.detected({"live": {}})
    assert not la.detected({})


def test_in_set_matches_exact_ip_only():
    listing = "table inet idps {\n set blocked4 {\n  elements = { %s }\n }\n}"
    assert la.in_set(listing % "10.10.1.10")
    assert la.in_set(listing % "10.10.1.5 timeout 1m, 10.10.1.10 expires 59s")
    assert not la.in_set(listing % "10.10.1.100")
    assert not la.in_set(listing % "110.10.1.10")
    assert not la.in_set(listing % "10.10.1.10.5")
    assert not la.in_set("")


# ---- build_table --------------------------------------------------------------------------------

def test_build_table_error_entry_renders_dashes():
    rows = la.build_table([{"attack": "portscan", "mode": "dry-run", "error": "boom"}]).splitlines()
    assert len(rows) == 3
    assert rows[2] == "| portscan | dry-run | — | — | — | — | — | — | — | — |"


def test_build_table_ttd_zero_is_not_a_dash():
    e = {"attack": "portscan", "mode": "blocking",
         "live": {"alerts": 4, "by_class": {"PortScan": 4}, "detection_rate": 0.5,
                  "right_family_share": 1.0, "time_to_first_alert_s": 0.0},
         "offline": {"flows": 8, "attack": 4}, "block": {"summary": "no block"}}
    cells = [c.strip() for c in la.build_table([e]).splitlines()[2].strip("|").split("|")]
    assert cells == ["portscan", "blocking", "8", "4", "50.0%", "100.0%", "PortScan", "0.0",
                     "50.0%", "no block"]


# ---- OFFLINE_PY / ATTACKS -----------------------------------------------------------------------

def test_offline_py_is_safe_inside_sh_c_single_quotes():
    for ch in ("'", "$", "`"):
        assert ch not in la.OFFLINE_PY, repr(ch)


def test_attacks_commands_and_families():
    assert la.ATTACKS
    unknown = set()
    for name, (cmd, max_s, family) in la.ATTACKS.items():
        assert cmd.startswith("sh /attacks/"), name
        assert max_s > 0 and family, name
        unknown |= set(family) - MODEL_CLASSES
    # 'Web Attack - Sql Injection' is not a class of the week model, so it can never match.
    assert unknown <= {NOT_A_CLASS}, unknown - {NOT_A_CLASS}


# ---- extract_cmd / start_tcpdump ----------------------------------------------------------------

import subprocess  # noqa: E402

import pytest  # noqa: E402


def test_extract_cmd_uses_the_live_sensors_backend():
    assert la.extract_cmd() == f"python -m idps.features extract {la.PCAP} -o {la.FLOWS} --backend nfstream"
    assert la.extract_cmd("/tmp/a.pcap", "/tmp/a.parquet") == (
        "python -m idps.features extract /tmp/a.pcap -o /tmp/a.parquet --backend nfstream")


def test_tcpdump_pattern_does_not_match_its_own_shell():
    import re
    pat = la.tcpdump_pattern("/tmp/x.pcap")
    assert re.search(pat, "tcpdump -i lab_attack -s 0 -U -w /tmp/x.pcap host 10.10.1.10")
    assert not re.search(pat, "tcpdump -i lab_attack -s 0 -U -w /tmp/other.pcap host 10.10.1.10")
    assert not re.search(pat, f"sh -c pgrep -f '{pat}'")  # the pgrep's own command line


class _Lab:
    def __init__(self, running_polls):
        self.polls = list(running_polls)   # what tcpdump_running answers, in order
        self.started, self.compose_calls, self.scripts = False, [], []

    def sh(self, service, script, timeout=120, check=False, secrets=None):
        self.scripts.append(script)
        assert "pgrep -f" in script and la.tcpdump_pattern("/tmp/t.pcap") in script
        rc = 0 if (self.polls.pop(0) if self.polls else self.started) else 1
        return subprocess.CompletedProcess([], rc, stdout="", stderr="")

    def compose(self, *args, **kw):
        self.compose_calls.append(args)
        self.started = True


def _install(monkeypatch, polls):
    lab = _Lab(polls)
    monkeypatch.setattr(la, "sh", lab.sh)
    monkeypatch.setattr(la.bs, "compose", lab.compose)
    monkeypatch.setattr(la.time, "sleep", lambda s: None)
    return lab


def test_start_tcpdump_starts_and_checks_by_path(monkeypatch):
    lab = _install(monkeypatch, [False])  # no old one; afterwards it reports running
    la.start_tcpdump("/tmp/t.pcap", "10.10.1.10")
    assert lab.compose_calls == [("exec", "-d", "sensor", "tcpdump", "-i", la.bs.INTERFACE, "-s", "0", "-U",
                                  "-w", "/tmp/t.pcap", "host", "10.10.1.10")]


def test_start_tcpdump_waits_for_the_old_one_to_exit(monkeypatch):
    lab = _install(monkeypatch, [True, True, False])
    la.start_tcpdump("/tmp/t.pcap")
    assert len(lab.compose_calls) == 1 and len(lab.scripts) == 4  # 3 old-one polls + 1 check


def test_start_tcpdump_raises_if_old_one_stays(monkeypatch):
    lab = _install(monkeypatch, [True] * 1000)
    with pytest.raises(RuntimeError, match="still running"):
        la.start_tcpdump("/tmp/t.pcap", old_wait=0)
    assert lab.compose_calls == []


def test_start_tcpdump_raises_if_it_did_not_start(monkeypatch):
    lab = _install(monkeypatch, [False, False])
    with pytest.raises(RuntimeError, match="did not start"):
        la.start_tcpdump("/tmp/t.pcap")
    assert len(lab.compose_calls) == 1
