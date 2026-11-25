"""scripts/bench_benign.py and lab/attacks/benign.sh: the pure parts, the SOC paging, the run
orchestration with fake lab processes, and the script's guards."""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
_spec = importlib.util.spec_from_file_location("bench_benign", _SCRIPTS / "bench_benign.py")
bb = importlib.util.module_from_spec(_spec)
sys.modules["bench_benign"] = bb
_spec.loader.exec_module(bb)

BASE = datetime(2026, 11, 14, 10, 0, 0, tzinfo=UTC)
BASE_MS = BASE.timestamp() * 1000


def ts(offset_s: float) -> str:
    return (BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def alert(cls="PortScan", conf=0.9, src="10.10.1.10", sport=40000, dst="10.10.2.10", dport=80,
          sev="low", start=20.0, end=30.0, proto=6, sensor=1, id=1):
    return {"id": id, "predicted_class": cls, "confidence": conf, "src_ip": src, "src_port": sport,
            "dst_ip": dst, "dst_port": dport, "protocol": proto, "severity": sev,
            "start_ms": BASE_MS + start * 1000, "end_ms": BASE_MS + end * 1000, "sensor_id": sensor}


def req_line(offset, act="web", lport="40000", dst="10.10.2.10:80", status="200", secs="0.01",
             path="/", extra=""):
    return f"{ts(offset)} benign req {act} {lport} {dst} {status} {secs} {path}{extra}"


# ---- env, numbers, parsing --------------------------------------------------------------------

def test_parse_env():
    text = ("# c\n\nA=1\nB = 'two words'\nC=\"x # y\"\nD=a=b\nexport E=5\nF=6 # comment\n"
            "not a pair\n  # indented comment\nG=\n")
    assert bb.parse_env(text) == {"A": "1", "B": "two words", "C": "x # y", "D": "a=b", "E": "5",
                                  "F": "6", "G": ""}


def test_percentile():
    assert bb.percentile([], 50) is None
    assert bb.percentile([5.0], 90) == 5.0
    assert bb.percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.5
    assert bb.percentile([1.0, 2.0, 3.0, 4.0], 100) == 4.0


def test_confidence_summary_bins_cover_everything():
    vals = [0.45, 0.5, 0.55, 0.75, 0.95, 0.999, 1.0]
    s = bb.confidence_summary(vals)
    assert s["n"] == 7 and s["below_0.5"] == 1
    assert sum(b["count"] for b in s["histogram"]) + s["below_0.5"] == 7
    assert s["histogram"][-1]["count"] == 2 and s["histogram"][-1]["to"] == 1.0
    assert bb.confidence_summary([])["p50"] is None


def test_parse_req_line():
    r = bb.parse_req_line(req_line(5, lport="41234", dst="10.10.2.11:80", status="302", secs="0.5",
                                   path="/login.php", act="dvwa"))
    assert r["activity"] == "dvwa" and r["lport"] == 41234 and r["dst_ip"] == "10.10.2.11"
    assert r["dst_port"] == 80 and r["status"] == 302 and r["secs"] == 0.5
    assert r["t"] == BASE.timestamp() + 5 and not r["expect_404"]
    ssh = bb.parse_req_line(req_line(5, act="ssh", lport="-", dst="10.10.2.10:22", status="0", secs="25"))
    assert ssh["lport"] is None and ssh["dst_port"] == 22
    ping = bb.parse_req_line(req_line(5, act="ping", lport="-", dst="10.10.2.10:icmp", status="0", secs="3"))
    assert ping["dst_port"] == "icmp"
    assert bb.parse_req_line(req_line(5, status="404", extra=" expect=404"))["expect_404"]
    for bad in ["", "garbage", f"{ts(0)} benign web nginx 404 status=404",
                req_line(0, act="nope"), req_line(0, lport="x")]:
        assert bb.parse_req_line(bad) is None


def test_parse_activity_line_ignores_request_lines():
    assert bb.parse_activity_line(f"{ts(0)} benign web nginx keep-alive requests=5") == "web"
    assert bb.parse_activity_line(f"{ts(0)} benign connreq requests=4") == "connreq"
    assert bb.parse_activity_line(f"{ts(0)} benign start duration=60s") is None
    assert bb.parse_activity_line(req_line(0)) is None


def test_activity_summary_counts_and_problems():
    lines = [
        f"{ts(0)} benign start duration=60s",
        f"{ts(1)} benign web nginx keep-alive requests=5",
        req_line(1), req_line(1, status="404", extra=" expect=404"),   # deliberate 404: fine
        req_line(2, act="download", status="404", path="/benign/files/f_1m.bin"),  # a real problem
        req_line(2, act="burst", status="000"),                         # no answer
        req_line(3, act="ssh", lport="-", dst="10.10.2.10:22", status="255", secs="2"),
        req_line(3, act="ping", lport="-", dst="10.10.2.10:icmp", status="1", secs="3"),
        req_line(3, act="scp", lport="-", dst="10.10.2.10:22", status="0", secs="1"),
        f"{ts(4)} benign dvwa login failed (index.php status=302)",
        f"{ts(5)} benign note: LAB_VICTIM_PASSWORD not set, ssh and scp skipped",
        f"{ts(6)} benign ping 10.10.2.10 count=3 exit=0",
    ]
    s = bb.activity_summary(lines)
    assert s["counts"]["web"] == 1 and s["counts"]["dvwa"] == 1 and s["counts"]["ping"] == 1
    assert s["total"] == 3
    assert s["problem_count"] == 6  # download 404, burst 000, ssh 255, ping 1, dvwa failed, note
    assert any("download" in p for p in s["problems"]) and any("ping" in p for p in s["problems"])


def test_check_traffic():
    ok = dict(rc=0, stopped=False, activity_total=50, elapsed_s=3700, requested_s=3600)
    assert bb.check_traffic(**ok) == []
    assert "exited with status 2" in bb.check_traffic(**{**ok, "rc": 2})[0]
    assert "no activities" in bb.check_traffic(**{**ok, "activity_total": 0})[0]
    assert "ran 100 s" in bb.check_traffic(**{**ok, "elapsed_s": 100})[0]
    assert bb.check_traffic(**{**ok, "stopped": True, "rc": None, "elapsed_s": 5}) == []


def test_outbox_alerts():
    assert bb.outbox_alerts(None) == 0 and bb.outbox_alerts("") == 0
    assert bb.outbox_alerts('{"version": 1, "batches": []}') == 0
    assert bb.outbox_alerts('{"version": 1, "batches": [[{}, {}], [{}]]}') == 3
    with pytest.raises(bb.Abort):
        bb.outbox_alerts("not json")


def test_pick_sensor_id():
    sensors = [{"sensor_id": 1, "revoked": True, "online": True, "last_seen_at": "2026-11-14T09:00:00Z"},
               {"sensor_id": 2, "revoked": False, "online": False, "last_seen_at": "2026-11-13T09:00:00Z"},
               {"sensor_id": 3, "revoked": False, "online": True, "last_seen_at": "2026-11-14T09:00:00Z"}]
    assert bb.pick_sensor_id(sensors) == 3
    with pytest.raises(bb.Abort):
        bb.pick_sensor_id([sensors[0]])


# ---- which alerts belong to this run ----------------------------------------------------------

def test_filter_alerts_window_addresses_sensor_and_duplicates():
    start_ms = BASE_MS + 100_000
    good = alert(sport=1, start=100, end=110, id=1)
    edge = alert(sport=2, start=85, end=91, id=2)           # ended 9 s before the traffic: kept
    old = alert(sport=3, start=10, end=20, id=3)            # ended long before: excluded
    foreign = alert(sport=4, dst="8.8.8.8", start=100, end=110, id=4)
    foreign_src = alert(sport=5, src="192.168.1.5", cls="DoS Hulk", start=100, end=110, id=5)
    other = alert(sport=6, sensor=9, start=100, end=110, id=6)
    dup = {**good, "id": 7}                                  # same flow key as `good`
    kept, ex = bb.filter_alerts([good, edge, old, foreign, foreign_src, other, dup],
                                traffic_start_ms=start_ms, sensor_id=1)
    assert [a["id"] for a in kept] == [1, 2]
    assert ex["duplicates"] == 1 and ex["count"] == 4
    assert ex["by_reason"] == {"before_run": 1, "foreign_address": 2, "other_sensor": 1}
    assert ex["by_class"] == {"PortScan": 3, "DoS Hulk": 1}


def test_filter_alerts_dedup_key_includes_start_and_protocol():
    a = alert(sport=1, start=100, end=110)
    b = {**a, "start_ms": a["start_ms"] + 1}   # a different flow on the same 5-tuple
    c = {**a, "protocol": 17}
    kept, ex = bb.filter_alerts([a, b, c], traffic_start_ms=BASE_MS, sensor_id=None)
    assert len(kept) == 3 and ex["duplicates"] == 0


# ---- matching alerts to activities ------------------------------------------------------------

def test_match_by_client_port_server_and_time():
    reqs = bb.parse_requests([
        req_line(30, act="web", lport="40000", dst="10.10.2.10:80"),
        req_line(30, act="dvwa", lport="40001", dst="10.10.2.11:80"),
        req_line(30, act="connreq", lport="40002", dst="10.10.2.10:80"),
        req_line(30, act="ssh", lport="-", dst="10.10.2.10:22", status="0", secs="20"),
        req_line(30, act="ping", lport="-", dst="10.10.2.11:icmp", status="0", secs="3"),
    ])
    m = bb.match_activity
    assert m(alert(sport=40000), reqs) == "web"
    assert m(alert(sport=40001, dst="10.10.2.11"), reqs) == "dvwa"
    assert m(alert(sport=40002), reqs) == "connreq"
    assert m(alert(sport=40003), reqs) is None                      # port nobody used
    assert m(alert(sport=40001), reqs) is None                      # right port, wrong server
    assert m(alert(sport=40000, start=500, end=510), reqs) is None  # port reused much later
    # a flow first seen from the server's reply: addresses and ports swapped
    assert m(alert(src="10.10.2.10", sport=80, dst="10.10.1.10", dport=40000), reqs) == "web"
    # ssh: no client port known, matched by server address:port and time
    assert m(alert(sport=55555, dport=22, start=12, end=30), reqs) == "ssh"
    assert m(alert(sport=55555, dport=22, start=500, end=510), reqs) is None
    # ping: ICMP flows
    assert m(alert(proto=1, sport=0, dport=0, dst="10.10.2.11", start=27, end=30), reqs) == "ping"
    assert m(alert(proto=6, sport=0, dport=0, dst="10.10.2.11", start=27, end=30), reqs) is None


def test_match_prefers_the_request_with_a_known_port():
    reqs = bb.parse_requests([
        req_line(30, act="ssh", lport="-", dst="10.10.2.10:80", status="0", secs="20"),
        req_line(30, act="web", lport="40000", dst="10.10.2.10:80")])
    assert bb.match_activity(alert(sport=40000), reqs) == "web"


def test_per_activity_counts_connections_and_rates():
    lines = [req_line(30, lport="40000"), req_line(30, lport="40000", path="/a.css"),  # one connection
             req_line(31, lport="40001"),
             req_line(31, act="connreq", lport="40002"), req_line(32, act="connreq", lport="40003"),
             req_line(33, act="ssh", lport="-", dst="10.10.2.10:22", status="0", secs="5")]
    reqs = bb.parse_requests(lines)
    assert bb.connections_per_activity(reqs)["web"] == 2
    alerts = [alert(sport=40002, id=1), alert(sport=40003, id=2), alert(sport=49999, id=3)]
    r = bb.per_activity(alerts, reqs)
    assert r["web"] == {"requests": 3, "connections": 2, "false_alerts": 0, "rate_per_connection": 0.0}
    assert r["connreq"]["false_alerts"] == 2 and r["connreq"]["rate_per_connection"] == 1.0
    assert r["ssh"]["connections"] == 1 and r["burst"]["rate_per_connection"] is None
    assert r["unmatched"]["false_alerts"] == 1


# ---- the SOC client ---------------------------------------------------------------------------

class PagedSoc(bb.Soc):
    """Soc whose _req serves `total` items in pages (newest id first), without a network."""

    def __init__(self, total):
        super().__init__("u", "p")
        self.total, self.calls = total, []

    def _req(self, path, body=None):
        q = dict(p.split("=") for p in path.split("?", 1)[1].split("&"))
        self.calls.append(q)
        limit = int(q["limit"])
        start = int(q.get("cursor", self.total + 1)) - 1
        ids = list(range(start, max(start - limit, 0), -1))
        more = bool(ids) and ids[-1] > 1
        return {"items": [{"id": i} for i in ids], "next_cursor": ids[-1] if more else None}


def test_pages_follows_the_cursor():
    soc = PagedSoc(1200)
    items = soc.pages("/alerts", {"since": "x"})
    assert len(items) == 1200 and items[0]["id"] == 1200 and items[-1]["id"] == 1
    assert [c.get("cursor") for c in soc.calls] == [None, "701", "201"]
    assert not soc.truncated


def test_pages_exact_fit_is_not_truncated():
    soc = PagedSoc(1000)
    assert len(soc.pages("/alerts", {}, max_items=1000)) == 1000 and not soc.truncated


def test_pages_cap_warns_and_flags(capsys):
    soc = PagedSoc(1200)
    items = soc.pages("/alerts", {}, max_items=700)
    assert len(items) == 700 and soc.truncated
    assert "stopped reading /alerts at 700" in capsys.readouterr().err


def test_alerts_between_passes_since_and_until():
    soc = PagedSoc(3)
    soc.alerts_between(BASE, BASE + timedelta(hours=1))
    assert soc.calls[0]["since"].startswith("2026-11-14T10%3A00") and "until" in soc.calls[0]


# ---- the report -------------------------------------------------------------------------------

GOOD_FINAL = {"flows": 100, "malicious": 2, "alerts": 2, "alerts_sent": 2, "below_floor": 0,
              "would_block": 0, "outbox_pending": 0, "dropped": {"alerts": 0}}


def _report(**kw):
    args = dict(minutes=60, started=BASE - timedelta(seconds=30), traffic_started=BASE,
                traffic_ended=BASE + timedelta(hours=1), drained=True, final=GOOD_FINAL,
                kept=[alert(sport=1, id=1), alert(sport=2, id=2)],
                excluded={"count": 0, "duplicates": 0, "by_reason": {}, "by_class": {}},
                would_blocks=[], activity={"counts": {}, "total": 10, "problems": [], "problem_count": 0},
                reqs=[], traffic_errors=[], soc_error=None, sensor_id=1)
    args.update(kw)
    return bb.build_report(**args)


def test_report_valid_and_numbers():
    r = _report()
    assert r["valid"] and r["invalid_reasons"] == []
    assert r["summary"]["false_alerts_per_hour"] == 2.0
    assert r["summary"]["false_positive_rate"] == 0.02
    assert r["reconciliation"]["difference"] == 0 and r["reconciliation"]["outbox_pending"] == 0
    assert "10.10.2.0/24" not in r["allowlist"] and "10.10.1.10" not in r["allowlist"]
    assert "0.1 ms" in r["notes"]
    table = bb.build_table(r)
    assert "| Flows scored | 100 |" in table and "| Valid | yes |" in table
    assert "| PortScan | 2 |" in table and "| web |" in table


@pytest.mark.parametrize("change,text", [
    (dict(final={**GOOD_FINAL, "outbox_pending": 4}), "outbox_pending"),
    (dict(final={**GOOD_FINAL, "alerts_sent": 1}), "sent 1"),
    (dict(final={**GOOD_FINAL, "alerts": 3, "alerts_sent": 3}), "SOC holds 2"),
    (dict(final={**GOOD_FINAL, "dropped": {"alerts": 2}}), "dropped 2"),
    (dict(drained=False), "flow count"),
    (dict(interrupted=True), "interrupted"),
    (dict(truncated=True), "more alerts"),
    (dict(traffic_errors=["benign.sh exited with status 1"]), "status 1"),
    (dict(activity={"counts": {}, "total": 10, "problems": [], "problem_count": 5}), "problem lines"),
])
def test_report_invalid(change, text):
    r = _report(**change)
    assert not r["valid"] and any(text in x for x in r["invalid_reasons"])


def test_report_without_soc_keeps_sensor_counters():
    r = _report(kept=None, excluded=None, soc_error="URLError: refused")
    assert not r["valid"] and r["soc_error"] == "URLError: refused"
    assert r["summary"] is None and r["sensor"]["flows"] == 100 and r["sensor"]["alerts"] == 2
    assert "SOC error" in bb.build_table(r)


# ---- Traffic and the sensor wrapper -----------------------------------------------------------

class FakeProc:
    def __init__(self):
        self.stdout = iter([])

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class FakeThread:
    def join(self, timeout=None):
        pass


def test_password_is_not_in_the_command_line(monkeypatch):
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw["env"]
        return FakeProc()

    monkeypatch.setattr(bb.subprocess, "Popen", fake_popen)
    bb.Traffic(60, "s3cret-pw")
    assert "s3cret-pw" not in " ".join(seen["cmd"])
    assert "LAB_VICTIM_PASSWORD" in seen["cmd"] and seen["env"]["LAB_VICTIM_PASSWORD"] == "s3cret-pw"


def test_traffic_stop_polls_until_the_script_is_gone(monkeypatch):
    t = bb.Traffic.__new__(bb.Traffic)
    t.proc, t._thread, t.stopped = FakeProc(), FakeThread(), False
    running = iter([True, True, True, False])
    sent = []
    monkeypatch.setattr(bb, "traffic_running", lambda: next(running, False))
    monkeypatch.setattr(bb.bs, "compose", lambda *a, **k: sent.append(a[-1]))
    monkeypatch.setattr(bb.time, "sleep", lambda s: None)
    t.stop()
    assert t.stopped and len(sent) == 1 and "kill -TERM" in sent[0]  # gone after TERM: no KILL


def test_sensor_stop_waits_for_idps_live_to_go(monkeypatch):
    s = bb.RunSensor.__new__(bb.RunSensor)
    s.proc, s._thread = FakeProc(), FakeThread()
    running = iter([True, True, True, False])
    sent = []
    monkeypatch.setattr(bb.bs, "sensor_running", lambda: next(running, False))
    monkeypatch.setattr(bb.bs, "compose", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(bb.time, "sleep", lambda s: None)
    s.stop()
    assert len(sent) == 1 and "-TERM" in sent[0]


# ---- main() with fake lab processes -----------------------------------------------------------

class Clock:
    def __init__(self):
        self.t = BASE

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += timedelta(seconds=s)


class Lab:
    """Everything main() touches, replaced; `cfg` says what each fake does."""

    def __init__(self, tmp_path, monkeypatch):
        self.clock = Clock()
        self.events = []
        self.cfg = dict(outbox_file=0, first_pending=0, traffic_rc=0, traffic_advance=60,
                        lines=None, flush="drained", wait_ready_exc=None, traffic_wait_exc=None,
                        soc_login_exc=None, soc_fetch_exc=None,
                        alerts=[alert(sport=40000, start=20, end=30, id=1)],
                        final=dict(GOOD_FINAL, alerts=1, alerts_sent=1))
        lab = self
        env = tmp_path / ".env"
        env.write_text("LAB_VICTIM_PASSWORD=pw\nLAB_SOC_CHECK_USER=u\nLAB_SOC_CHECK_PASSWORD=p\n")
        self.report = tmp_path / "report.json"

        class FakeSensor:
            def __init__(self, duration):
                lab.events.append("sensor_start")
                lab.sensor = self
                self.metrics = []
                self.stopped = False

            def wait_ready(self):
                if lab.cfg["wait_ready_exc"]:
                    raise lab.cfg["wait_ready_exc"]
                self.metrics = [{"outbox_pending": lab.cfg["first_pending"], "flows": 0},
                                {"flows": 0}, dict(lab.cfg["final"])]

            def wait_drained(self, mn, mx):
                lab.clock.advance(150)
                if lab.cfg["flush"] == "interrupt":
                    raise KeyboardInterrupt
                return lab.cfg["flush"] == "drained"

            def stop(self):
                lab.events.append("sensor_stop")
                self.stopped = True

        class FakeTraffic:
            def __init__(self, seconds, password):
                lab.events.append("traffic_start")
                lab.traffic = self
                self.stopped = False
                self.lines = lab.cfg["lines"] if lab.cfg["lines"] is not None else [
                    f"{ts(1)} benign start duration=60s",
                    req_line(31, lport="40000"), f"{ts(31)} benign web nginx keep-alive requests=1"]

            def wait(self, timeout):
                if lab.cfg["traffic_wait_exc"]:
                    raise lab.cfg["traffic_wait_exc"]
                lab.clock.advance(lab.cfg["traffic_advance"])
                return lab.cfg["traffic_rc"]

            def stop(self):
                lab.events.append("traffic_stop")

        class FakeSoc:
            truncated = False

            def __init__(self, user, password, ca=None):
                pass

            def login(self):
                if lab.cfg["soc_login_exc"]:
                    raise lab.cfg["soc_login_exc"]

            def sensor_id(self):
                return 1

            def alerts_between(self, since, until):
                if lab.cfg["soc_fetch_exc"]:
                    raise lab.cfg["soc_fetch_exc"]
                return list(lab.cfg["alerts"])

            def would_blocks_since(self, since, hours):
                return []

        monkeypatch.setattr(bb, "ENV_FILE", env)
        monkeypatch.setattr(bb, "REPORT", self.report)
        monkeypatch.setattr(bb, "ACTIVITY_LOG", tmp_path / "activity.log")
        monkeypatch.setattr(bb, "_now", self.clock)
        monkeypatch.setattr(bb.bs, "sensor_running", lambda: False)
        monkeypatch.setattr(bb.bs, "log", lambda m: None)
        monkeypatch.setattr(bb, "outbox_file_alerts", lambda: lab.cfg["outbox_file"])
        monkeypatch.setattr(bb, "fetch_ca", lambda: "ca")
        monkeypatch.setattr(bb, "setup_victim_files", lambda: lab.events.append("setup"))
        monkeypatch.setattr(bb, "cleanup_victim_files", lambda: lab.events.append("cleanup"))
        monkeypatch.setattr(bb, "RunSensor", FakeSensor)
        monkeypatch.setattr(bb, "Traffic", FakeTraffic)
        monkeypatch.setattr(bb, "Soc", FakeSoc)
        self.sensor = self.traffic = None

    def run(self, minutes="1"):
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        rc = bb.main(["--minutes", minutes])
        assert {s: signal.getsignal(s) for s in before} == before  # handlers restored
        return rc

    def load(self):
        return json.loads(self.report.read_text())


@pytest.fixture
def lab(tmp_path, monkeypatch):
    return Lab(tmp_path, monkeypatch)


def test_main_happy_path(lab):
    assert lab.run() == 0
    r = lab.load()
    assert r["valid"] and r["summary"]["false_alerts"] == 1
    assert r["by_activity"]["web"]["false_alerts"] == 1 and r["traffic_minutes"] == 1.0
    assert lab.events == ["setup", "sensor_start", "traffic_start", "traffic_stop",
                                           "sensor_stop", "cleanup"]


def test_main_failed_benign_script(lab):
    lab.cfg["traffic_rc"] = 3
    assert lab.run() == 1
    r = lab.load()
    assert not r["valid"] and any("status 3" in x for x in r["invalid_reasons"])


def test_main_no_activities(lab):
    lab.cfg["lines"] = [f"{ts(1)} benign start duration=60s"]
    assert lab.run() == 1
    assert any("no activities" in x for x in lab.load()["invalid_reasons"])


def test_main_script_ended_early(lab):
    lab.cfg["traffic_advance"] = 10
    assert lab.run() == 1
    assert any("ran 10 s" in x for x in lab.load()["invalid_reasons"])


def test_main_outbox_file_guard(lab):
    lab.cfg["outbox_file"] = 3
    assert lab.run() == 1
    assert "sensor_start" not in lab.events and not lab.report.exists()
    assert lab.events[-1] == "cleanup"


def test_main_first_metrics_outbox_guard(lab):
    lab.cfg["first_pending"] = 7
    assert lab.run() == 1
    assert "traffic_start" not in lab.events and not lab.report.exists()
    assert lab.events[-2:] == ["sensor_stop", "cleanup"]


def test_main_ctrl_c_in_the_flush_keeps_the_traffic_end(lab):
    lab.cfg["flush"] = "interrupt"
    assert lab.run() == 130
    r = lab.load()
    assert r["interrupted"] and not r["valid"]
    assert r["traffic_minutes"] == 1.0   # not stretched by the 150 s spent in the flush
    assert r["traffic_ended"] == (BASE + timedelta(seconds=60)).isoformat(timespec="seconds")
    assert lab.events[-3:] == ["traffic_stop", "sensor_stop", "cleanup"]


@pytest.mark.parametrize("where", ["wait_ready_exc", "traffic_wait_exc"])
def test_main_any_exception_still_stops_everything(lab, where):
    lab.cfg[where] = ValueError("boom")
    assert lab.run() == 1
    assert "sensor_stop" in lab.events and lab.events[-1] == "cleanup"
    assert ("traffic_stop" in lab.events) == (where == "traffic_wait_exc")


def test_main_soc_unreadable_at_the_end_still_writes_the_report(lab):
    lab.cfg["soc_fetch_exc"] = urllib.error.URLError("refused")
    assert lab.run() == 1
    r = lab.load()
    assert "refused" in r["soc_error"] and r["summary"] is None
    assert r["sensor"]["flows"] == 100 and not r["valid"]


def test_main_soc_login_failure_before_the_traffic(lab):
    lab.cfg["soc_login_exc"] = urllib.error.URLError("refused")
    assert lab.run() == 1
    assert "traffic_start" not in lab.events and "sensor_start" not in lab.events
    assert lab.events[-1] == "cleanup" and not lab.report.exists()


def test_main_foreign_and_stale_alerts_are_excluded_not_counted(lab):
    lab.cfg["alerts"] = [alert(sport=40000, start=20, end=30, id=1),
                         alert(sport=1, start=-500, end=-490, id=2, cls="DoS Hulk"),
                         alert(sport=2, dst="1.2.3.4", start=20, end=30, id=3)]
    assert lab.run() == 0
    r = lab.load()
    assert r["summary"]["false_alerts"] == 1
    assert r["reconciliation"]["excluded"]["count"] == 2


# ---- benign.sh guards -------------------------------------------------------------------------

BENIGN = Path(__file__).resolve().parent.parent / "lab" / "attacks" / "benign.sh"


def test_benign_script_syntax():
    assert subprocess.run(["bash", "-n", str(BENIGN)]).returncode == 0


def test_benign_refuses_a_foreign_target():
    env = {**os.environ, "VICTIM_IP": "192.0.2.1"}
    r = subprocess.run(["bash", str(BENIGN), "1"], capture_output=True, text=True, env=env)
    assert r.returncode == 1 and "not a lab target" in r.stderr and "benign" not in r.stdout


def test_benign_refuses_outside_the_attacker_container():
    r = subprocess.run(["bash", str(BENIGN), "1"], capture_output=True, text=True)
    assert r.returncode == 1 and "Refusing" in r.stderr
