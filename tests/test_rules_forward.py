"""idps.rules.forward: filtering, de-duplication, status and block gating of rule alerts."""
import json
from ipaddress import ip_network

import pytest
from pydantic import ValidationError
from test_live import META, attack_packets, bundle, model_file, write_pcap  # noqa: F401  (fixtures)
from test_live import ListSink as LiveSink
from test_rules_eve import event

from idps.config import Settings
from idps.live.config import LiveSettings
from idps.live.detector import LiveDetector
from idps.live.metrics import Metrics
from idps.live.status import build_status
from idps.respond.engine import ResponseEngine
from idps.respond.policy import Action, Detection, ResponsePolicy
from idps.rules.config import RulesSettings
from idps.rules.eve import eve_timestamp_ms
from idps.rules.forward import RuleForwarder
from idps.soc_client import Outbox, is_rule_alert


class ListSink:
    def __init__(self):
        self.alerts, self.blocks = [], []

    def submit(self, alerts):
        self.alerts.extend(alerts)

    def submit_blocks(self, events):
        self.blocks.extend(events)

    def pending(self):
        return 0


T0 = eve_timestamp_ms("2026-11-15T10:00:00.000000+0000") / 1000.0


def at(seconds: float) -> str:
    """An eve timestamp `seconds` after T0."""
    from datetime import UTC, datetime

    return datetime.fromtimestamp(T0 + seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


class Clock:
    """Both the monotonic clock (rate limit) and the wall clock (closing idle windows): starts at the
    time of the events in these tests, so a window is open until the test moves it."""

    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def make(tmp_path, **kw):
    clock = kw.pop("clock", None) or Clock()
    respond = kw.pop("respond", None)
    weight = kw.pop("block_weight", 5)
    sink = ListSink()
    settings = RulesSettings(eve=str(tmp_path / "eve.json"), **kw)
    return RuleForwarder(settings, sink, respond=respond, block_weight=weight, clock=clock,
                         wall=clock), sink, clock


def feed(fw, *lines):
    fw.handle_lines(list(lines))


# --- settings ------------------------------------------------------------------------------------

def test_off_unless_an_eve_path_is_set(monkeypatch):
    for n in [n for n in __import__("os").environ if n.startswith("IDPS_RULES_")]:
        monkeypatch.delenv(n)
    s = RulesSettings()
    assert not s.enabled and s.include_info is False and s.dedupe_seconds == 60.0 and s.block_sids == []
    monkeypatch.setenv("IDPS_RULES_EVE", "   ")
    assert not RulesSettings().enabled
    monkeypatch.setenv("IDPS_RULES_EVE", "/x/eve.json")
    monkeypatch.setenv("IDPS_RULES_BLOCK_SIDS", "2009358, 2100366,2009358")
    monkeypatch.setenv("IDPS_RULES_INCLUDE_INFO", "true")
    monkeypatch.setenv("IDPS_RULES_DEDUPE_SECONDS", "5")
    s = RulesSettings()
    assert s.enabled and s.block_sids == [2009358, 2100366] and s.include_info and s.dedupe_seconds == 5


@pytest.mark.parametrize("bad", ["abc", "0", "-5", "1.5"])
def test_bad_block_sids_are_refused(monkeypatch, bad):
    monkeypatch.setenv("IDPS_RULES_BLOCK_SIDS", bad)
    with pytest.raises(ValidationError):
        RulesSettings()


# --- filtering -----------------------------------------------------------------------------------

def test_engine_events_and_informational_alerts_are_dropped_and_counted(tmp_path):
    fw, sink, _ = make(tmp_path)
    feed(fw,
         event(sig="SURICATA TCPv4 invalid checksum", sid=2200073, cat="Generic Protocol Command Decode"),
         event(sig="ET INFO Something", sid=2000001, cat="Not Suspicious Traffic"),
         event(sig="GPL ICMP_INFO PING *NIX", sid=2100366, cat="Misc activity"),
         event(sid=2009358))
    assert [a["rule"]["sid"] for a in sink.alerts] == [2009358]
    st = fw.status()
    assert (st["alerts_sent"], st["dropped_engine"], st["dropped_info"]) == (1, 1, 2)


def test_include_info_keeps_informational_alerts_as_policy(tmp_path):
    fw, sink, _ = make(tmp_path, include_info=True)
    feed(fw, event(sig="ET POLICY Dropbox", sid=2012648, cat="Potential Corporate Privacy Violation", severity=1),
         event(sig="SURICATA STREAM x", sid=2210000))
    assert [a["predicted_class"] for a in sink.alerts] == ["Policy"]
    assert fw.status()["dropped_engine"] == 1 and fw.status()["dropped_info"] == 0


def test_bad_lines_and_other_event_types_do_not_stop_it(tmp_path):
    fw, sink, _ = make(tmp_path)
    feed(fw, "garbage", "{broken", event(ts="2026-11-15T10:00:00"),  # no UTC offset
         event().replace('"alert"', '"flow"', 1),
         event(src="not-an-ip"), event(proto="WEIRD"), event(sid=2009358))
    assert [a["rule"]["sid"] for a in sink.alerts] == [2009358]
    assert fw.status()["dropped_invalid"] == 5  # garbage (a fragment), broken, no offset, bad ip, bad proto


def test_alerts_use_source_rule_and_no_features_or_explanation(tmp_path):
    fw, sink, _ = make(tmp_path)
    feed(fw, event())
    (a,) = sink.alerts
    assert a["source"] == "rule" and a["predicted_class"] == "Scan" and a["confidence"] == 0.95
    assert not {"features", "model_sha256", "explanation", "anomaly_score"} & set(a)
    assert a["rule"]["count"] == 1


# --- de-duplication ------------------------------------------------------------------------------

def test_repeats_in_the_window_become_one_alert_and_one_follow_up_with_the_count(tmp_path):
    fw, sink, clock = make(tmp_path, dedupe_seconds=60)
    feed(fw, event(ts=at(0)))
    assert len(sink.alerts) == 1 and sink.alerts[0]["rule"]["count"] == 1  # sent at once
    for sec in (1, 2, 3, 4):
        feed(fw, event(ts=at(sec)))
    assert len(sink.alerts) == 1 and fw.status()["deduped"] == 4  # held back, counted
    clock.t = T0 + 61
    feed(fw)  # a poll after the window
    assert len(sink.alerts) == 2
    follow = sink.alerts[1]
    assert follow["rule"]["count"] == 5 and follow["end_ms"] - follow["start_ms"] == 4000
    assert fw.status()["alerts_sent"] == 2


def test_the_window_is_event_time_not_arrival_time(tmp_path):
    """A backlog read in one go: events 70 s apart are two windows even though they arrive together."""
    fw, sink, _ = make(tmp_path, dedupe_seconds=60)
    feed(fw, event(ts=at(0)), event(ts=at(10)), event(ts=at(70)))
    assert [a["rule"]["count"] for a in sink.alerts] == [1, 2, 1]
    assert fw.status()["deduped"] == 1


def test_a_single_hit_has_no_follow_up(tmp_path):
    fw, sink, clock = make(tmp_path)
    feed(fw, event(ts=at(0)))
    clock.t += 120
    feed(fw)
    assert len(sink.alerts) == 1


def test_the_key_is_sid_src_dst_and_dst_port(tmp_path):
    fw, sink, _ = make(tmp_path)
    feed(fw, event(), event(sid=1), event(src="10.10.1.11"), event(dst="10.10.2.12"), event(dport=8080),
         event(), event(src_port_ignored=1))
    assert len(sink.alerts) == 5 and fw.status()["deduped"] == 2


def test_zero_disables_folding(tmp_path):
    fw, sink, _ = make(tmp_path, dedupe_seconds=0)
    feed(fw, event(), event(), event())
    assert len(sink.alerts) == 3 and fw.status()["deduped"] == 0


def test_closing_sends_the_open_windows_follow_ups(tmp_path):
    fw, sink, _ = make(tmp_path)
    feed(fw, event(), event(), event(sid=7))
    fw.close_all_windows()
    assert [(a["rule"]["sid"], a["rule"]["count"]) for a in sink.alerts] == [(2009358, 1), (7, 1), (2009358, 2)]


def test_the_number_of_open_windows_is_bounded(tmp_path, monkeypatch):
    import idps.rules.forward as fwd

    monkeypatch.setattr(fwd, "MAX_TRACKED_KEYS", 3)
    fw, _, _ = make(tmp_path)
    feed(fw, *[event(sid=i) for i in range(1, 8)], event(sid=1))
    assert len(fw._windows) <= 3


def test_a_flood_of_distinct_keys_is_rate_limited_and_counted(tmp_path):
    fw, sink, clock = make(tmp_path, max_per_minute=10)
    feed(fw, *[event(sid=i) for i in range(1, 31)])  # 30 different rules at once
    assert len(sink.alerts) == 10 and fw.status()["rate_limited"] == 20
    assert fw.status()["alerts_sent"] == 10 and fw.status()["max_per_minute"] == 10
    clock.t += 61  # the next minute has a fresh quota
    feed(fw, event(sid=99))
    assert len(sink.alerts) == 11


def test_the_rate_limit_can_be_switched_off(tmp_path):
    fw, sink, _ = make(tmp_path, max_per_minute=0)
    feed(fw, *[event(sid=i) for i in range(1, 301)])
    assert len(sink.alerts) == 300 and fw.status()["rate_limited"] == 0


def test_the_rate_limit_never_stops_blocking(tmp_path):
    engine, blocker = engine_for(dry_run=False, allowlist=["10.10.2.0/24"])
    rec = Recorder(engine)
    fw, _sink, _ = make(tmp_path, respond=rec, block_sids="5000", max_per_minute=1,
                       block_weight=engine.policy.min_flows)
    feed(fw, event(sid=1), event(sid=2), event(sid=5000, src="203.0.113.9", **ESTABLISHED))
    assert fw.status()["rate_limited"] >= 1 and blocker.blocked == ["203.0.113.9"]


# --- status --------------------------------------------------------------------------------------

def test_status_fields(tmp_path):
    fw, _, _ = make(tmp_path, block_sids="2009358")
    st = fw.status()
    assert st["enabled"] is True and st["eve_path"].endswith("eve.json")
    assert st["last_event_at"] is None and st["error"] is None
    feed(fw, event(ts="2026-11-15T10:00:00.000000+0000"))
    assert fw.status()["last_event_at"] == "2026-11-15T10:00:00+00:00"
    assert set(st) >= {"enabled", "eve_path", "alerts_sent", "dropped_engine", "dropped_info", "last_event_at",
                       "error"}
    assert st["block_sids"] == 1 and st["include_info"] is False and st["dedupe_seconds"] == 60.0
    json.dumps(fw.status())  # plain JSON


def test_status_error_when_the_file_is_missing_or_unreadable(tmp_path):
    fw, _, _ = make(tmp_path)
    fw.poll_once()
    assert "does not exist yet" in fw.status()["error"]
    (tmp_path / "eve.json").write_text("")
    fw.poll_once()
    assert fw.status()["error"] is None

    class Boom:
        exists = True

        def read_new(self):
            raise PermissionError(13, "denied\x00\n")

        def close(self):
            pass

    fw.tailer = Boom()
    assert fw.poll_once() == 0
    err = fw.status()["error"]
    assert "PermissionError" in err and "\x00" not in err and "\n" not in err


def test_build_status_carries_rules_only_when_enabled_and_extended():
    class P:
        confidence_threshold, min_flows, window_seconds, ttl_seconds, allowlist = 0.9, 5, 60.0, 900, ()

    class E:
        dry_run, grace_seconds, max_analyst_blocks, policy = True, 3600, 1000, P()

    class B:
        model_name = "xgboost"

    class S:
        min_alert_confidence = 0.5

    kw = {"engine": E(), "bundle": B(), "live_settings": S(), "metrics": Metrics(), "sink": ListSink(),
          "interface": "x"}
    st = {"enabled": True}
    assert "rules" not in build_status(**kw, extended=False, rules=st)
    assert build_status(**kw, extended=True, rules=st)["rules"] == st
    # forwarder off: the status has no `rules` key at all, so an SOC from before step 8 still accepts it
    assert "rules" not in build_status(**kw, extended=True, rules=None)


# --- the tailer end to end -----------------------------------------------------------------------

def test_poll_reads_new_lines_from_the_end_of_an_existing_file(tmp_path):
    eve_file = tmp_path / "eve.json"
    eve_file.write_text(event(sid=1) + "\n")  # history: not sent
    fw, sink, _ = make(tmp_path)
    assert fw.poll_once() == 0
    with open(eve_file, "a") as f:
        f.write(event(sid=2) + "\n" + event(sid=3)[:30])  # the last line is half written
    assert fw.poll_once() == 1
    assert [a["rule"]["sid"] for a in sink.alerts] == [2]


def test_the_thread_forwards_and_flushes_on_stop(tmp_path):
    eve_file = tmp_path / "eve.json"
    eve_file.write_text("")
    fw, sink, _ = make(tmp_path, poll_seconds=0.05)
    fw.start()
    try:
        with open(eve_file, "a") as f:
            f.write(event() + "\n" + event() + "\n")
        import time
        deadline = time.time() + 5
        while time.time() < deadline and not sink.alerts:
            time.sleep(0.02)
        assert sink.alerts
    finally:
        fw.stop()
    assert sorted(a["rule"]["count"] for a in sink.alerts) == [1, 2]  # the follow-up came at stop


# --- the outbox keeps rule alerts apart ----------------------------------------------------------

def test_outbox_never_mixes_model_and_rule_alerts_in_a_batch(tmp_path):
    ml = {"src_ip": "1.2.3.4"}
    rule = {"src_ip": "1.2.3.4", "source": "rule", "rule": {}}
    box = Outbox(tmp_path / "ob.json", merge=True)
    box.add([ml, ml, rule, rule, ml], save=True)
    box.add([ml, rule])
    kinds = [{is_rule_alert(a) for a in b} for b in box.batches]
    assert all(len(k) == 1 for k in kinds) and len(box) == 7
    # and after a restart, the file is re-chunked without mixing
    again = Outbox(tmp_path / "ob.json", merge=True)
    assert all(len({is_rule_alert(a) for a in b}) == 1 for b in again.batches) and len(again) == 7


# --- block gating --------------------------------------------------------------------------------

# What Suricata logs for an event on a flow the server answered: an application protocol and packets
# both ways. Without it (a bare SYN, UDP, ICMP) a listed rule counts as one flow only.
ESTABLISHED = {"app_proto": "http", "flow": {"pkts_toserver": 4, "pkts_toclient": 3}}


class FakeBlocker:
    def __init__(self):
        self.blocked = []

    def ensure_ruleset(self):
        pass

    def block(self, ip, ttl_seconds):
        self.blocked.append(ip)

    def unblock(self, ip):
        pass


def engine_for(**kw):
    blocker = FakeBlocker()
    return ResponseEngine(Settings(**kw), blocker=blocker), blocker


class Recorder:
    """What the detector's respond() does, with the decisions kept."""

    def __init__(self, engine):
        self.engine, self.decisions = engine, []

    def __call__(self, detection):
        self.decisions.append(self.engine.handle(detection))


def listed(tmp_path, *, dry_run=False, allowlist=("10.10.2.0/24",), sids="2009358", **kw):
    engine, blocker = engine_for(dry_run=dry_run, allowlist=list(allowlist) if not dry_run or allowlist else [])
    rec = Recorder(engine)
    fw, sink, _clock = make(tmp_path, respond=rec, block_sids=sids, block_weight=engine.policy.min_flows, **kw)
    return fw, rec, blocker, sink


ATTACKER = "203.0.113.9"


def test_rules_never_block_by_default(tmp_path):
    engine, blocker = engine_for(dry_run=False, allowlist=["10.10.2.0/24"])
    rec = Recorder(engine)
    fw, sink, _ = make(tmp_path, respond=rec, block_weight=engine.policy.min_flows)  # no block_sids
    feed(fw, *[event(src=ATTACKER, sid=2009358, **ESTABLISHED) for _ in range(20)])
    assert rec.decisions == [] and blocker.blocked == [] and sink.blocks == []


def test_a_sid_that_is_not_listed_never_blocks_even_when_others_are(tmp_path):
    fw, rec, blocker, _ = listed(tmp_path, sids="111")
    feed(fw, event(src=ATTACKER, sid=2009358, **ESTABLISHED))
    assert rec.decisions == [] and blocker.blocked == []


def test_a_listed_sid_on_an_established_flow_blocks_after_one_hit_through_the_policy(tmp_path):
    fw, rec, blocker, _ = listed(tmp_path)
    feed(fw, event(src=ATTACKER, **ESTABLISHED))
    assert [d.action for d in rec.decisions] == [Action.BLOCK] and blocker.blocked == [ATTACKER]
    assert rec.decisions[0].reason == ("Suricata rule sid 2009358 (ET SCAN Nmap Scripting Engine "
                                       "User-Agent Detected) matched")
    feed(fw, event(src=ATTACKER, **ESTABLISHED))  # the policy remembers: no second block
    assert rec.decisions[-1].action is Action.ALREADY_BLOCKED and blocker.blocked == [ATTACKER]


def test_packets_both_ways_count_as_established_without_an_app_protocol(tmp_path):
    fw, _rec, blocker, _ = listed(tmp_path)
    feed(fw, event(src=ATTACKER, flow={"pkts_toserver": 3, "pkts_toclient": 1}))
    assert blocker.blocked == [ATTACKER]


@pytest.mark.parametrize("forged", [
    {"proto": "UDP"},                                            # one spoofed UDP datagram
    {"proto": "ICMP"},                                           # one spoofed ping
    {},                                                          # a bare SYN: nothing from the server
    {"flow": {"pkts_toserver": 1, "pkts_toclient": 0}},          # one-way TCP
    {"proto": "UDP", "app_proto": "dns", "flow": {"pkts_toserver": 1, "pkts_toclient": 1}},  # UDP is never "established"
    {"app_proto": "failed"},
])
def test_a_forged_or_stateless_event_of_a_listed_sid_counts_as_one_flow_and_does_not_block(tmp_path, forged):
    fw, rec, blocker, _ = listed(tmp_path)
    feed(fw, event(src=ATTACKER, **forged))
    assert [d.action for d in rec.decisions] == [Action.OBSERVE] and blocker.blocked == []
    assert rec.decisions[0].flows_in_window == 1


def test_repeated_stateless_hits_still_reach_min_flows_like_repeated_flows(tmp_path):
    """Five confident one-flow detections are what the policy asks of the model too."""
    fw, rec, _blocker, _ = listed(tmp_path, dedupe_seconds=0)
    feed(fw, *[event(src=ATTACKER, proto="UDP") for _ in range(5)])
    assert [d.action for d in rec.decisions] == [Action.OBSERVE] * 4 + [Action.BLOCK]


def test_a_listed_sid_respects_the_allowlist(tmp_path):
    fw, rec, blocker, _ = listed(tmp_path, allowlist=("203.0.113.0/24", "10.10.2.0/24"))
    feed(fw, event(src=ATTACKER, **ESTABLISHED))
    assert [d.action for d in rec.decisions] == [Action.ALLOWLISTED] and blocker.blocked == []


def test_a_listed_sid_respects_dry_run(tmp_path):
    fw, rec, blocker, _ = listed(tmp_path, dry_run=True)
    feed(fw, event(src=ATTACKER, **ESTABLISHED))
    assert [d.action for d in rec.decisions] == [Action.BLOCK]  # a would-block decision ...
    assert blocker.blocked == []  # ... that never reaches the firewall


def test_a_source_inside_the_protected_net_is_never_handed_to_the_engine(tmp_path):
    fw, rec, blocker, _ = listed(tmp_path, allowlist=("198.51.100.0/24",), protected_nets="10.10.2.0/24,2001:db8::/32")
    feed(fw, event(src="10.10.2.11", **ESTABLISHED), event(src="2001:db8::5", **ESTABLISHED))
    assert rec.decisions == [] and blocker.blocked == [] and fw.status()["block_skipped"] == 2
    feed(fw, event(src=ATTACKER, **ESTABLISHED))  # outside it: normal path
    assert blocker.blocked == [ATTACKER]


def test_protected_nets_parse_from_the_environment(monkeypatch):
    monkeypatch.setenv("IDPS_RULES_PROTECTED_NETS", "10.10.2.0/24, 192.168.1.5")
    assert [str(n) for n in RulesSettings().protected_nets] == ["10.10.2.0/24", "192.168.1.5/32"]
    monkeypatch.setenv("IDPS_RULES_PROTECTED_NETS", "not-a-net")
    with pytest.raises(ValidationError):
        RulesSettings()


def test_only_to_server_events_can_block_and_the_skips_are_counted_not_logged_each_time(tmp_path, caplog):
    fw, rec, blocker, _ = listed(tmp_path, dedupe_seconds=0)
    with caplog.at_level("INFO", logger="idps.live"):
        feed(fw, *[event(src=ATTACKER, direction="to_client", **ESTABLISHED) for _ in range(30)],
             event(src="203.0.113.10", direction=None, **ESTABLISHED))
    assert rec.decisions == [] and blocker.blocked == []
    assert fw.status()["block_skipped"] == 31
    assert len([r for r in caplog.records if "may block" in r.message]) == 1  # first one only


def test_a_listed_informational_sid_is_not_dropped_but_an_unlisted_one_is(tmp_path):
    fw, _rec, blocker, sink = listed(tmp_path, sids="2000001")
    feed(fw, event(src=ATTACKER, sid=2000001, sig="ET INFO Something", cat="Not Suspicious Traffic",
                   **ESTABLISHED),
         event(src=ATTACKER, sid=2000002, sig="ET INFO Other", cat="Not Suspicious Traffic"))
    assert [a["rule"]["sid"] for a in sink.alerts] == [2000001]
    assert sink.alerts[0]["predicted_class"] == "Policy"
    assert fw.status()["dropped_info"] == 1 and blocker.blocked == [ATTACKER]


def test_engine_events_never_pass_even_when_listed(tmp_path):
    fw, rec, _blocker, sink = listed(tmp_path, sids="2200073")
    feed(fw, event(src=ATTACKER, sid=2200073, sig="SURICATA STREAM x", cat="Generic Protocol Command Decode",
                   **ESTABLISHED))
    assert sink.alerts == [] and rec.decisions == [] and fw.status()["dropped_engine"] == 1


def test_repeats_inside_the_window_still_reach_the_policy_but_do_not_block_twice(tmp_path):
    fw, _rec, blocker, sink = listed(tmp_path)
    feed(fw, *[event(src=ATTACKER, **ESTABLISHED) for _ in range(4)])
    assert blocker.blocked == [ATTACKER] and len(sink.alerts) == 1


def test_policy_weight_counts_but_never_skips_the_other_checks():
    p = ResponsePolicy([ip_network("10.0.0.0/8")], confidence_threshold=0.9, min_flows=5)
    d = p.evaluate(Detection("203.0.113.9", "x", 1.0, 100.0, weight=5))
    assert d.action is Action.BLOCK
    p = ResponsePolicy([ip_network("10.0.0.0/8")], confidence_threshold=0.9, min_flows=5)
    assert p.evaluate(Detection("203.0.113.9", "x", 0.5, 100.0, weight=5)).action is Action.BELOW_THRESHOLD
    assert p.evaluate(Detection("10.1.1.1", "x", 1.0, 100.0, weight=5)).action is Action.ALLOWLISTED
    assert p.evaluate(Detection("203.0.113.9", "BENIGN", 1.0, 100.0, weight=5)).action is Action.BENIGN
    # a weight above min_flows counts as min_flows, a weight of 1 is the old behaviour
    q = ResponsePolicy([], confidence_threshold=0.9, min_flows=5)
    assert q.evaluate(Detection("203.0.113.9", "x", 1.0, 100.0)).action is Action.OBSERVE
    assert q.evaluate(Detection("203.0.113.9", "x", 1.0, 100.0, weight=99)).action is Action.BLOCK


def test_the_detector_reports_a_rule_block_like_a_model_block(tmp_path, bundle):  # noqa: F811
    """LiveDetector.respond: counts and reports the decision (here dry-run: a would-block event)."""
    engine, _ = engine_for(dry_run=True)
    sink = LiveSink()
    det = LiveDetector(bundle, engine, sink, LiveSettings(), META, live=False)
    fw, _, _ = make(tmp_path, respond=det.respond, block_sids="2009358", block_weight=5)
    feed(fw, event(src="203.0.113.9", **ESTABLISHED))
    assert det.metrics.counts["would_block"] == 1
    assert sink.blocks and sink.blocks[0]["event"] == "would_block" and sink.blocks[0]["ip"] == "203.0.113.9"


# --- the CLI -------------------------------------------------------------------------------------

def test_a_bad_block_sid_list_is_a_startup_error(model_file, tmp_path, monkeypatch, capsys):  # noqa: F811
    from idps.live.__main__ import main

    monkeypatch.setenv("IDPS_RULES_BLOCK_SIDS", "abc")
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(tmp_path / "a.jsonl")]) == 2
    assert "block_sids" in capsys.readouterr().err


def test_replay_ignores_the_eve_file_and_still_works(model_file, tmp_path, monkeypatch, caplog):  # noqa: F811
    import logging

    from idps.live.__main__ import main

    monkeypatch.setenv("IDPS_RULES_EVE", str(tmp_path / "eve.json"))
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets(n=3))
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        assert main(["--pcap", str(pcap), "--model", str(model_file),
                     "--alerts-file", str(tmp_path / "a.jsonl")]) == 0
    assert "IDPS_RULES_EVE is ignored in replay mode" in caplog.text


def test_an_old_soc_that_refuses_rule_alerts_costs_only_the_rule_alerts(tmp_path, caplog):
    """SOC older than the rules feature: AlertIn forbids unknown fields, so a rule batch is a 422. The
    model alerts must not share that batch (they would be dropped with it)."""
    from idps.live.sinks import SocSink
    from idps.soc_client import SocRejectedError

    delivered = []

    def old_soc(batch):
        if any("source" in a for a in batch):
            raise SocRejectedError("SOC rejected the alerts: HTTP 422", 422)
        delivered.extend(batch)
        return {}

    metrics = Metrics()
    sink = SocSink(old_soc, Outbox(None, merge=True), metrics, start=False)
    ml = {"src_ip": "203.0.113.1", "predicted_class": "DDoS"}
    rule = {"src_ip": "203.0.113.1", "source": "rule", "rule": {"sid": 1}}
    sink.submit([ml])
    sink.submit([rule])
    sink.submit([ml, ml])
    with caplog.at_level("ERROR", logger="idps.live"):
        assert sink.drain() is True
    assert len(delivered) == 3  # every model alert arrived
    assert metrics.counts["alerts_rejected"] == 1 and metrics.counts["alerts_sent"] == 3
    assert "upgrade the SOC first" in caplog.text


def test_fragments_and_over_long_lines_lost_by_the_tailer_count_as_dropped_invalid(tmp_path):
    eve_file = tmp_path / "eve.json"
    eve_file.write_text("")
    fw, sink, _ = make(tmp_path)
    fw.poll_once()
    with open(eve_file, "a") as f:
        f.write(event(sid=1) + "\n" + event(sid=2)[:25])
    fw.poll_once()
    eve_file.write_text("")  # truncated while a half line was buffered
    with open(eve_file, "a") as f:
        f.write(event(sid=3) + "\n")
    fw.poll_once()
    assert [a["rule"]["sid"] for a in sink.alerts] == [1, 3]
    assert fw.status()["dropped_invalid"] == 1


def test_a_rule_flood_never_evicts_model_alerts_from_the_outbox(tmp_path):
    box = Outbox(None, max_alerts=5, merge=True, max_rule_alerts=3)
    ml = [{"n": i} for i in range(5)]
    box.add(ml)
    flood = [{"n": i, "source": "rule", "rule": {}} for i in range(50)]
    assert box.add(flood) == 47  # only rule alerts were dropped
    flat = [a for b in box.batches for a in b]
    assert [a for a in flat if not is_rule_alert(a)] == ml
    assert [a["n"] for a in flat if is_rule_alert(a)] == [47, 48, 49]  # the newest three
    assert len(box) == 8


def test_model_alerts_are_only_dropped_by_model_alerts(tmp_path):
    box = Outbox(None, max_alerts=3, merge=True, max_rule_alerts=3)
    box.add([{"source": "rule", "n": i} for i in range(3)])
    assert box.add([{"n": i} for i in range(5)]) == 2  # the two oldest MODEL alerts
    flat = [a for b in box.batches for a in b]
    assert sum(is_rule_alert(a) for a in flat) == 3 and [a["n"] for a in flat if not is_rule_alert(a)] == [2, 3, 4]


def test_the_outbox_file_is_trimmed_per_kind_on_load(tmp_path):
    path = tmp_path / "ob.json"
    box = Outbox(path, max_alerts=100, max_rule_alerts=100, merge=True)
    box.add([{"n": i} for i in range(6)] + [{"n": i, "source": "rule"} for i in range(6)])
    again = Outbox(path, max_alerts=4, max_rule_alerts=2, merge=True)
    flat = [a for b in again.batches for a in b]
    assert [a["n"] for a in flat if not is_rule_alert(a)] == [2, 3, 4, 5]
    assert [a["n"] for a in flat if is_rule_alert(a)] == [4, 5]
