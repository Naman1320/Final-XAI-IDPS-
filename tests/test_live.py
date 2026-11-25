"""Live detection loop: replay end to end, batching, SOC outage, response safety, shedding."""

import errno
import json
import logging
import os
import re
import threading
import time
from dataclasses import fields
from datetime import UTC, datetime, timedelta

import numpy as np
import pandas as pd
import pytest
from pcap_factory import CLIENT, T0, tcp_session, udp_exchange, write_pcap
from scapy.layers.inet import IP, TCP
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from idps.capture import flows_from_pcap
from idps.capture.flow import Flow
from idps.config import Settings
from idps.detect.bundle import Bundle, load_bundle, save_bundle
from idps.features import FEATURE_COLUMNS, MODEL_FEATURES, extraction_meta
from idps.live.__main__ import main
from idps.live.config import LiveSettings
from idps.live.detector import LiveDetector
from idps.live.metrics import Metrics
from idps.live.sinks import JsonlSink, SocSink
from idps.respond.engine import ResponseEngine
from idps.soc_client import MAX_BATCH, Outbox, Prediction, SocError, SocRejectedError
from soc.api.routes.alerts import AlertBatch

META = extraction_meta("nfstream", 120, 120)
ATTACKER = "10.10.1.10"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in [n for n in os.environ if n.startswith("IDPS_")]:
        monkeypatch.delenv(name)


# --- A tiny model: dst_port 80 is the attack, everything else is benign ---------------------------

def _train(meta) -> Bundle:
    rng = np.random.default_rng(0)
    rows, labels = [], []
    for label, ports in (("BENIGN", (53, 443, 8080, 0)), ("DDoS", (80,))):
        for _ in range(120):
            r = dict.fromkeys(MODEL_FEATURES, 0.0)
            r.update(dst_port=float(rng.choice(ports)), protocol=6.0,
                     fwd_packets=float(rng.integers(1, 60)), fwd_bytes=float(rng.integers(60, 5000)))
            rows.append(r)
            labels.append(label)
    X, enc = pd.DataFrame(rows)[MODEL_FEATURES], LabelEncoder().fit(labels)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0)
    model.fit(X, enc.transform(labels))
    return Bundle("xgboost", model, enc, list(MODEL_FEATURES), meta, {"mode": "test"}, {})


@pytest.fixture(scope="module")
def model_file(tmp_path_factory):
    return save_bundle(_train(META), tmp_path_factory.mktemp("model") / "tiny.joblib")


@pytest.fixture(scope="module")
def bundle(model_file):
    return load_bundle(model_file, live_meta=META, live_columns=FEATURE_COLUMNS)


# --- Traffic ---------------------------------------------------------------------------------------

def attack_packets(src=CLIENT, n=6, t0=T0):
    """n TCP sessions to port 80 from `src`, one second apart (n distinct flows)."""
    packets = []
    for i in range(n):
        for p in tcp_session(sport=40000 + i, dport=80, t0=t0 + i):
            if p[IP].src == CLIENT:
                p[IP].src = src
            if p[IP].dst == CLIENT:
                p[IP].dst = src
            del p[IP].chksum, p[TCP].chksum
            packets.append(p)
    return packets


def make_flow(dst_port=80, i=0, end_ms=None) -> Flow:
    values = dict.fromkeys((f.name for f in fields(Flow)), 0)
    start = 1_700_000_000_000 + i * 10
    values.update(src_ip=ATTACKER, dst_ip="10.10.2.10", src_port=40000 + i, dst_port=dst_port,
                  protocol=6, start_ms=start, end_ms=end_ms or start + 5, fwd_packets=20,
                  fwd_bytes=1200)
    return Flow(**values)


class ListSink:
    def __init__(self):
        self.alerts = []
        self.blocks = []

    def submit_blocks(self, events):
        self.blocks.extend(events)

    def submit(self, alerts):
        self.alerts.extend(alerts)

    def pending(self):
        return 0

    def checkpoint(self):
        pass

    def close(self):
        pass


class FakeBlocker:
    def __init__(self):
        self.ensured, self.blocked = 0, []

    def ensure_ruleset(self):
        self.ensured += 1

    def block(self, ip, ttl_seconds):
        self.blocked.append(ip)

    def unblock(self, ip):
        pass


def detector(bundle, sink, *, engine=None, live=False, outbox_capacity=None, **overrides):
    overrides.setdefault("metrics_seconds", 3600.0)
    engine = engine or ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker())
    return LiveDetector(bundle, engine, sink, LiveSettings(**overrides), META, live=live,
                        outbox_capacity=outbox_capacity)


def wait_for(condition, timeout=5.0):
    """Poll instead of sleeping a fixed time."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met in time")


def quiet_engine():
    """Dry-run engine that allowlists the attacker: no block-driven explanations in the way."""
    return ResponseEngine(Settings(dry_run=True, allowlist=["10.10.1.0/24"]), blocker=FakeBlocker())


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- Replay end to end (CLI) -----------------------------------------------------------------------

def test_replay_writes_alerts_with_explanations_and_the_soc_accepts_them(model_file, tmp_path, caplog):
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=3) + udp_exchange())
    out = tmp_path / "alerts.jsonl"
    with caplog.at_level(logging.INFO, logger="idps.live"):
        code = main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)])
    assert code == 0
    alerts = lines(out)
    assert len(alerts) == 3  # the DNS exchange is benign
    for a in alerts:
        assert a["predicted_class"] == "DDoS" and a["dst_port"] == 80
        top = a["explanation"]["top_features"]
        assert len(top) == 5 and a["explanation"]["method"] == "shap"
        assert top[0]["feature"] == "dst_port"
    AlertBatch.model_validate({"alerts": alerts})  # exactly what POST /ingest/alerts accepts
    final = [json.loads(r.message) for r in caplog.records if '"event": "metrics"' in r.message][-1]
    assert final["flows"] == 4 and final["alerts"] == 3 and final["explained"] == 3
    assert final["shap_ms_per_alert"]["n"] == 3
    assert final["latency_flow_end_to_alert_s"]["n"] == 0  # replay: no latency recorded
    assert (out.stat().st_mode & 0o777) == 0o600


def test_benign_traffic_produces_no_alerts(model_file, tmp_path):
    pcap = write_pcap(tmp_path / "benign.pcap", udp_exchange())
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)]) == 0
    assert lines(out) == []


def test_max_flows_stops_early(model_file, tmp_path):
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=6))
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out),
                 "--max-flows", "2"]) == 0
    assert len(lines(out)) == 2


# --- Fail closed -----------------------------------------------------------------------------------

def test_a_model_trained_with_another_extractor_refuses_to_start(tmp_path, capsys):
    path = save_bundle(_train(extraction_meta("scapy", 60, 120)), tmp_path / "scapy.joblib")
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    out = tmp_path / "alerts.jsonl"
    code = main(["--pcap", str(pcap), "--model", str(path), "--alerts-file", str(out)])
    assert code == 2
    err = capsys.readouterr().err
    assert "differ" in err and "refusing to run without a model" in err
    assert not out.exists()


def test_missing_or_tampered_model_refuses_to_start(model_file, tmp_path, capsys):
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    out = tmp_path / "alerts.jsonl"
    argv = ["--pcap", str(pcap), "--alerts-file", str(out)]
    assert main([*argv, "--model", str(tmp_path / "nope.joblib")]) == 2
    tampered = tmp_path / "tampered.joblib"
    tampered.write_bytes(model_file.read_bytes() + b"x")
    (tmp_path / "tampered.joblib.sha256").write_text(model_file.with_name(
        model_file.name + ".sha256").read_text())
    assert main([*argv, "--model", str(tampered)]) == 2
    assert "cannot load the model" in capsys.readouterr().err
    assert not out.exists()


def test_a_half_configured_soc_is_an_error_not_a_silent_fallback(model_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IDPS_SOC_URL", "https://soc.example")
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file),
                 "--alerts-file", str(tmp_path / "a.jsonl")]) == 2
    assert "IDPS_SOC_SENSOR_TOKEN" in capsys.readouterr().err


def test_a_plain_http_soc_is_refused(model_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IDPS_SOC_URL", "http://soc.example")
    monkeypatch.setenv("IDPS_SOC_TOKEN", "idps_sensor_x")  # the short alias works too
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file)]) == 2
    assert "https" in capsys.readouterr().err


# --- SOC down / SOC unset --------------------------------------------------------------------------

def test_soc_down_keeps_alerts_in_the_outbox_and_detection_continues(bundle, tmp_path):
    attempts = []

    def down(batch):
        attempts.append(len(batch))
        raise SocError("cannot reach the SOC")

    metrics = Metrics()
    outbox = Outbox(tmp_path / "outbox.json", max_alerts=1000, merge=True)
    sink = SocSink(down, outbox, metrics, retry_seconds=0.01, max_retry_seconds=0.02)
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=5))
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    det = LiveDetector(bundle, engine, sink, LiveSettings(batch_size=2, metrics_seconds=3600),
                       META, metrics=metrics, live=False, outbox_capacity=1000)
    det.run(flows_from_pcap(pcap))
    assert metrics.counts["flows"] == 5 and metrics.counts["alerts"] == 5
    assert blocker.blocked == [CLIENT]  # blocking did not wait for, or depend on, the SOC
    wait_for(lambda: len(attempts) >= 2)  # the sender retried in the background
    assert sink.pending() == 5 and metrics.counts["alerts_sent"] == 0
    sink.close()
    saved = Outbox(tmp_path / "outbox.json")
    assert len(saved) == 5  # kept on disk for the next run

    # The SOC comes back: a new run sends what is waiting.
    received = []
    sink2 = SocSink(lambda batch: received.extend(batch) or {}, Outbox(tmp_path / "outbox.json"),
                    Metrics(), retry_seconds=0.01)
    wait_for(lambda: len(received) >= 5)
    sink2.close()
    assert len(received) == 5 and len(Outbox(tmp_path / "outbox.json")) == 0


def test_a_batch_the_soc_refuses_is_dropped_not_retried_forever(tmp_path):
    metrics, calls = Metrics(), []

    def refuse(batch):
        calls.append(batch)
        raise SocRejectedError("HTTP 422")

    sink = SocSink(refuse, Outbox(None), metrics, start=False)
    sink.submit([{"a": 1}, {"a": 2}])
    assert sink.drain() is True
    assert len(calls) == 1 and metrics.counts["alerts_rejected"] == 2 and sink.pending() == 0


def test_posts_never_exceed_the_soc_batch_limit(tmp_path):
    sizes = []
    sink = SocSink(lambda b: sizes.append(len(b)) or {}, Outbox(None, merge=True), Metrics(),
                   start=False)
    sink.submit([{"i": i} for i in range(MAX_BATCH + 120)])
    sink.submit([{"i": i} for i in range(30)])  # tops up the partial batch
    assert sink.drain()
    assert sizes == [MAX_BATCH, 150] and max(sizes) <= MAX_BATCH


def test_without_a_soc_alerts_go_to_the_jsonl_file(bundle, tmp_path):
    metrics = Metrics()
    sink = JsonlSink(tmp_path / "sub" / "alerts.jsonl", metrics)
    detector(bundle, sink).run(iter([make_flow(80, i) for i in range(3)] + [make_flow(443, 9)]))
    sink.close()
    assert [a["src_port"] for a in lines(tmp_path / "sub" / "alerts.jsonl")] == [40000, 40001, 40002]


def test_a_failing_alert_file_never_stops_detection(bundle, tmp_path):
    metrics = Metrics()
    sink = JsonlSink(tmp_path / "alerts.jsonl", metrics)
    sink._file.close()  # simulate the disk going away
    det = LiveDetector(bundle, ResponseEngine(Settings(), blocker=FakeBlocker()), sink,
                       LiveSettings(batch_size=2), META, metrics=metrics, live=False)
    det.run(iter([make_flow(80, i) for i in range(4)]))
    assert metrics.counts["flows"] == 4 and metrics.counts["alerts_dropped"] == 4


# --- Response engine -------------------------------------------------------------------------------

def test_dry_run_never_calls_the_blocker(bundle):
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=True), blocker=blocker)
    det = detector(bundle, ListSink(), engine=engine)
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert det.metrics.counts["would_block"] == 1 and det.metrics.counts["blocked"] == 0
    assert blocker.blocked == [] and blocker.ensured == 0


def test_real_blocking_blocks_the_attacker_once(bundle):
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    det = detector(bundle, ListSink(), engine=engine)
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert blocker.blocked == [ATTACKER] and det.metrics.counts["blocked"] == 1


def test_an_allowlisted_source_is_never_blocked_but_is_still_alerted(bundle):
    blocker, sink = FakeBlocker(), ListSink()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.0/24"]), blocker=blocker)
    det = detector(bundle, sink, engine=engine)
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert blocker.blocked == [] and len(sink.alerts) == 8
    assert det.metrics.counts["blocked"] == 0


def test_the_alert_floor_does_not_change_blocking(bundle):
    blocker, sink = FakeBlocker(), ListSink()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    det = detector(bundle, sink, engine=engine, min_alert_confidence=1.0)  # nothing reaches 1.0
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert sink.alerts == [] and det.metrics.counts["below_floor"] == 8
    assert blocker.blocked == [ATTACKER]


def test_a_crashing_response_engine_does_not_stop_detection(bundle):
    class Broken:
        dry_run = True

        def handle(self, detection):
            raise RuntimeError("boom")

    sink = ListSink()
    det = LiveDetector(bundle, Broken(), sink, LiveSettings(), META, live=False)
    det.run(iter([make_flow(80, i) for i in range(3)]))
    assert len(sink.alerts) == 3 and det.metrics.counts["response_errors"] == 3


# --- Batching ----------------------------------------------------------------------------------------

def spy_batches(det):
    sizes, real = [], det.handle_batch

    def wrapper(flows):
        sizes.append(len(flows))
        return real(flows)

    det.handle_batch = wrapper
    return sizes


def test_batches_flush_on_size(bundle):
    det = detector(bundle, ListSink(), batch_size=3, batch_seconds=60.0)
    sizes = spy_batches(det)
    det.run(iter([make_flow(80, i) for i in range(7)]))
    assert sizes == [3, 3, 1]  # two full batches, then the last one at the end


def test_batches_flush_on_time_even_when_no_more_flows_arrive(bundle):
    release, sink = threading.Event(), ListSink()

    def quiet_link():
        yield make_flow(80, 0)
        yield make_flow(80, 1)
        release.wait(10)  # nothing else arrives, like an idle interface

    det = detector(bundle, sink, batch_size=100, batch_seconds=0.1)
    sizes = spy_batches(det)
    worker = threading.Thread(target=det.run, args=(quiet_link(),))
    worker.start()
    deadline = time.time() + 5
    while not sink.alerts and time.time() < deadline:
        time.sleep(0.02)
    assert sizes == [2] and len(sink.alerts) == 2  # flushed by the timer, source still open
    release.set()
    worker.join(5)
    assert not worker.is_alive()


def test_stopping_flushes_the_last_batch(bundle):
    release, stop, sink = threading.Event(), threading.Event(), ListSink()

    def source():
        yield from (make_flow(80, i) for i in range(3))
        release.wait(10)

    det = detector(bundle, sink, batch_size=100, batch_seconds=60.0)
    worker = threading.Thread(target=det.run, args=(source(), stop))
    worker.start()
    time.sleep(0.5)
    assert sink.alerts == []  # still waiting for a full batch
    stop.set()  # what SIGTERM does
    worker.join(5)
    assert not worker.is_alive() and len(sink.alerts) == 3
    release.set()


def test_a_failing_capture_flushes_what_it_read_and_then_raises(bundle):
    def source():
        yield make_flow(80, 0)
        yield make_flow(80, 1)
        raise OSError("interface went down")

    sink = ListSink()
    with pytest.raises(OSError, match="interface went down"):
        detector(bundle, sink, batch_size=100, batch_seconds=60.0).run(source())
    assert len(sink.alerts) == 2


# --- Shedding and bounds -----------------------------------------------------------------------------

def test_explanations_are_shed_before_alerts_and_counted(bundle):
    sink = ListSink()
    det = detector(bundle, sink, engine=quiet_engine(), batch_size=10, max_explanations_per_batch=2)
    det.run(iter([make_flow(80, i) for i in range(10)]))
    assert len(sink.alerts) == 10  # every alert still goes out
    explained = [a for a in sink.alerts if a["explanation"]["top_features"]]
    assert len(explained) == 2
    assert det.metrics.counts["explanations_shed"] == 8 and det.metrics.counts["explained"] == 2


def test_a_full_outbox_sheds_explanations_first_then_drops_the_oldest_alerts(bundle):
    metrics = Metrics()
    sink = SocSink(lambda b: (_ for _ in ()).throw(SocError("down")),
                   Outbox(None, max_alerts=4, merge=True), metrics, retry_seconds=60, start=False)
    det = LiveDetector(bundle, quiet_engine(), sink,
                       LiveSettings(batch_size=10, metrics_seconds=3600), META, metrics=metrics,
                       live=False, outbox_capacity=4)
    det.run(iter([make_flow(80, i) for i in range(30)]))
    assert metrics.counts["alerts"] == 30
    assert sink.pending() == 4  # the cap holds
    assert metrics.counts["alerts_dropped"] == 26  # counted, not silent
    # Batch 1 had room (explained); once the outbox was nearly full, explanations were shed.
    assert metrics.counts["explained"] == 10 and metrics.counts["explanations_shed"] == 20
    newest = sink.outbox.batches[-1]
    assert [a["src_port"] for a in newest][-1] == 40029  # the newest alerts are the ones kept


def test_outbox_trims_exactly_to_its_cap():
    box = Outbox(None, max_alerts=10, merge=True)
    assert box.add([{"i": i} for i in range(7)]) == 0
    assert box.add([{"i": i} for i in range(7, 14)]) == 4
    assert [a["i"] for b in box.batches for a in b] == list(range(4, 14))


def test_metrics_report_latency_and_shap_time_when_live(bundle, caplog):
    sink = ListSink()
    det = detector(bundle, sink, live=True, batch_size=5)
    det.run(iter([make_flow(80, i, end_ms=int(time.time() * 1000) - 1500) for i in range(5)]))
    snap = det.metrics.snapshot()
    assert snap["latency_flow_end_to_alert_s"]["n"] == 5
    assert 1.4 <= snap["latency_flow_end_to_alert_s"]["p50"] < 5
    shap = snap["shap_ms_per_alert"]
    # The plan's budget (< 50 ms) is checked by hand on the real model, not here: CI machines vary.
    assert shap["n"] == 5 and shap["p95"] is not None and shap["p95"] > 0
    assert json.loads(json.dumps(snap)) == snap
    assert set(snap) >= {"flows_per_s", "alerts", "blocks", "dropped"}


def test_the_background_keeps_the_first_benign_flows(bundle):
    det = detector(bundle, ListSink(), background_size=3, batch_size=4)
    det.run(iter([make_flow(443, i) for i in range(10)]))
    assert len(det._background) == 3
    assert [r["dst_port"] for r in det._background] == [443.0] * 3


# --- Reply direction: never block the protected server -----------------------------------------------

SERVER = "192.168.10.50"
SERVER_NET = "192.168.10.0/24"


def reply_flow(i=0, src=SERVER, dst=ATTACKER) -> Flow:
    """What NFStream reports when the first captured packet was the server's reply."""
    flow = make_flow(80, i)
    values = {f.name: getattr(flow, f.name) for f in fields(Flow)}
    values.update(src_ip=src, dst_ip=dst, src_port=80, dst_port=50000 + i, protocol=6)
    return Flow(**values)


class _RecordingEngine:
    dry_run = True

    def __init__(self, real):
        self.real, self.detections = real, []
        self.policy = real.policy

    def handle(self, detection):
        self.detections.append(detection)
        return self.real.handle(detection)


def test_block_candidate_rules():
    from idps.live.detector import block_candidate

    base = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": 6}
    reply = {**base, "src_port": 80, "dst_port": 50000}
    assert block_candidate(reply) == "2.2.2.2"
    assert block_candidate({**reply, "protocol": 17}) == "2.2.2.2"
    assert block_candidate({**reply, "protocol": 1}) == "1.1.1.1"  # not TCP/UDP
    assert block_candidate({**base, "src_port": 50000, "dst_port": 80}) == "1.1.1.1"  # forward
    assert block_candidate({**base, "src_port": 0, "dst_port": 0}) == "1.1.1.1"
    assert block_candidate({**base, "src_port": 40000, "dst_port": 50000}) == "1.1.1.1"  # both high
    assert block_candidate({**base, "src_port": 80, "dst_port": 8080}) == "1.1.1.1"  # both low
    assert block_candidate({**base, "src_port": 32768, "dst_port": 50000}) == "1.1.1.1"


def test_a_reply_flow_leads_to_a_detection_for_the_attacker_not_the_server(bundle, monkeypatch):
    import idps.live.detector as module

    # The tiny model keys on dst_port 80; a real model (DDoS, PortScan) also flags such replies.
    monkeypatch.setattr(module, "score_frame", lambda b, df: [Prediction("DDoS", 0.99)] * len(df))
    blocker, sink = FakeBlocker(), ListSink()
    engine = _RecordingEngine(ResponseEngine(
        Settings(dry_run=False, allowlist=[SERVER_NET]), blocker=blocker))
    det = detector(bundle, sink, engine=engine)
    det.run(iter([reply_flow(i) for i in range(6)]))
    assert {d.src_ip for d in engine.detections} == {ATTACKER}
    assert blocker.blocked == [ATTACKER]
    assert det.metrics.counts["reply_direction"] == 6
    assert {a["src_ip"] for a in sink.alerts} == {SERVER}  # the alert shows the flow as observed


def test_an_allowlisted_server_is_never_blocked_even_as_a_forward_looking_source(bundle):
    # The heuristic can be fooled (attacker sends from port 80 to a high port; or the server's
    # flow looks forward): the allowlist is what keeps the server safe.
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=[SERVER_NET]), blocker=blocker)
    det = detector(bundle, ListSink(), engine=engine)
    forward = [make_flow(80, i) for i in range(8)]
    forward = [Flow(**{**{f.name: getattr(x, f.name) for f in fields(Flow)}, "src_ip": SERVER})
               for x in forward]
    det.run(iter(forward))
    assert blocker.blocked == [] and det.metrics.counts["blocked"] == 0


def test_blocks_are_audited_with_their_explanation_even_when_shedding(bundle, caplog):
    sink = ListSink()
    engine = ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker())
    det = detector(bundle, sink, engine=engine, max_explanations_per_batch=0)
    with caplog.at_level(logging.WARNING, logger="idps.respond"):
        det.run(iter([make_flow(80, i) for i in range(6)]))
    record = json.loads(next(r.message for r in caplog.records if "would_block" in r.message))
    assert record["explanation"]["top_features"]  # the why is there although the budget was 0


# --- Robustness: bad batches, draining, SOC configuration errors -------------------------------------

def test_a_failing_batch_is_logged_counted_and_never_handled_twice(bundle, monkeypatch, caplog):
    import idps.live.detector as module

    real, calls = module.alert_payload, []

    def flaky(row, pred, explanation=None, **kwargs):
        calls.append(row["src_port"])
        if len(calls) == 2:
            raise RuntimeError("bug")
        return real(row, pred, explanation, **kwargs)

    monkeypatch.setattr(module, "alert_payload", flaky)
    sink = ListSink()
    engine = _RecordingEngine(quiet_engine())
    det = detector(bundle, sink, engine=engine, batch_size=3)
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        det.run(iter([make_flow(80, i) for i in range(6)]))
    assert det.metrics.counts["batch_errors"] == 1
    assert any("failed and was skipped" in r.message for r in caplog.records)
    # batch 1 (flows 0-2) died on its 2nd alert: its detections were handled once, not retried
    stamps = [d.timestamp for d in engine.detections]
    assert len(stamps) == len(set(stamps)) == 5  # none twice; flow 2 died with its batch
    assert len(sink.alerts) == 3  # batch 2 went through; detection did not end
    assert det.metrics.snapshot()["errors"]["batch"] == 1


def test_stop_scores_every_flow_that_was_read(bundle):
    produced, stop, scored = [], threading.Event(), []
    started = threading.Event()

    def source():
        for i in range(40):
            produced.append(i)
            yield make_flow(80, i)

    det = detector(bundle, ListSink(), batch_size=5, batch_seconds=60.0)
    real = det.handle_batch

    def slow(flows):
        started.set()
        time.sleep(0.15)  # scoring is slower than the capture, so flows pile up in the queue
        scored.extend(flows)
        return real(flows)

    det.handle_batch = slow
    worker = threading.Thread(target=det.run, args=(source(), stop))
    worker.start()
    assert started.wait(5)
    stop.set()
    worker.join(10)
    assert not worker.is_alive()
    counts = det.metrics.counts
    # nothing is lost silently: every flow the generator produced was scored or counted as discarded
    assert len(scored) + counts["flows_discarded"] == len(produced)
    assert len(scored) > 5  # the queue was drained into the final batches, not dropped


def test_max_flows_discards_and_counts_the_surplus(bundle):
    det = detector(bundle, ListSink(), batch_size=2, batch_seconds=60.0)
    det.run(iter([make_flow(80, i) for i in range(50)]), max_flows=4)
    counts = det.metrics.counts
    assert counts["flows"] == 4  # exactly the limit is scored
    assert counts["flows"] + counts["flows_discarded"] <= 50


def test_the_final_snapshot_has_a_sane_flow_rate(bundle):
    det = detector(bundle, ListSink())
    snap = det.run(iter([make_flow(443, i) for i in range(20)]))
    assert snap["flows"] == 20 and snap["flows_per_s"] > 0


@pytest.mark.parametrize("status", [401, 403, 404])
def test_soc_configuration_errors_keep_the_alerts_and_log_once(status, caplog):
    metrics, calls = Metrics(), []

    def wrong_config(batch):
        calls.append(len(batch))
        raise SocRejectedError(f"HTTP {status}", status)

    sink = SocSink(wrong_config, Outbox(None), metrics, start=False)
    sink.submit([{"a": 1}, {"a": 2}])
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        for _ in range(3):
            assert sink.drain() is False
    assert sink.pending() == 2 and metrics.counts["alerts_rejected"] == 0  # kept, not dropped
    assert metrics.counts["soc_config_errors"] == 3
    assert len([r for r in caplog.records if "check IDPS_SOC_URL" in r.message]) == 1
    assert metrics.snapshot()["errors"]["soc_config"] == 3


# --- Outbox file hygiene -----------------------------------------------------------------------------

def test_outbox_load_validates_rechunks_and_trims(tmp_path):
    path = tmp_path / "outbox.json"
    alerts = [{"i": i} for i in range(1200)]
    path.write_text(json.dumps({"version": 1, "batches": [alerts[:700], alerts[700:]]}))
    box = Outbox(path, max_alerts=1100)
    assert [len(b) for b in box.batches] == [MAX_BATCH, MAX_BATCH, 100]
    assert box.batches[0][0] == {"i": 100}  # the oldest 100 were trimmed


@pytest.mark.parametrize("content", ["not json", '{"batches": [[1, 2]]}', '{"batches": "x"}',
                                     '{"nothing": 1}'])
def test_a_corrupt_outbox_is_moved_aside_not_overwritten(tmp_path, content):
    path = tmp_path / "outbox.json"
    path.write_text(content)
    box = Outbox(path)
    assert len(box) == 0 and not path.exists()
    (kept,) = list(tmp_path.glob("outbox.json.corrupt-*"))
    assert kept.read_text() == content


def test_an_oversized_outbox_file_is_not_read(tmp_path, monkeypatch):
    import idps.soc_client as module

    monkeypatch.setattr(module, "MAX_OUTBOX_FILE_BYTES", 10)
    path = tmp_path / "outbox.json"
    path.write_text(json.dumps({"batches": [[{"a": 1}]]}))
    assert len(Outbox(path)) == 0 and list(tmp_path.glob("outbox.json.corrupt-*"))


def test_outbox_files_are_private_and_symlinks_are_refused(tmp_path):
    path = tmp_path / "outbox.json"
    box = Outbox(path)
    box.add([{"a": 1}])
    assert (path.stat().st_mode & 0o777) == 0o600
    target = tmp_path / "target.txt"
    target.write_text("precious")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symbolic link"):
        Outbox(link).save()
    assert target.read_text() == "precious" and len(Outbox(link)) == 0
    with pytest.raises(OSError):
        JsonlSink(link, Metrics())
    assert target.read_text() == "precious"


def test_an_oversized_post_is_a_rejection_not_a_valueerror():
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_x")
    with pytest.raises(SocRejectedError):
        client.post_alerts([{}] * (MAX_BATCH + 1))


# --- Configuration and the token ---------------------------------------------------------------------

def test_bare_soc_variable_names_are_ignored(monkeypatch):
    for name in ("SOC_URL", "SOC_TOKEN", "SOC_SENSOR_TOKEN", "SOC_CA_FILE", "soc_url", "soc_token"):
        monkeypatch.setenv(name, "https://evil.example" if "URL" in name.upper() else "x")
    s = LiveSettings()
    assert s.soc_url is None and s.soc_token is None and s.soc_ca_file is None
    monkeypatch.setenv("IDPS_SOC_TOKEN", "  idps_sensor_abc  ")
    assert LiveSettings().soc_token.get_secret_value() == "idps_sensor_abc"  # stripped


@pytest.mark.parametrize("token", ["idps sensor", "idps_sensor\nX-Evil: 1", "idps\x07sensor"])
def test_a_token_with_whitespace_or_control_characters_exits_2_without_echoing_it(
        model_file, tmp_path, monkeypatch, capsys, token):
    monkeypatch.setenv("IDPS_SOC_URL", "https://soc.example")
    monkeypatch.setenv("IDPS_SOC_SENSOR_TOKEN", token)
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file)]) == 2
    err = capsys.readouterr().err
    assert "token" in err and token not in err and "X-Evil" not in err


def test_the_token_never_reaches_the_logs(bundle, tmp_path, caplog):
    from idps.soc_client import SocClient

    secret = "idps_sensor_SUPERSECRETVALUE"
    client = SocClient("http://127.0.0.1:9", secret, timeout=1)  # nothing listens on port 9
    metrics = Metrics()
    sink = SocSink(client.post_alerts, Outbox(None), metrics, start=False)
    sink.submit([{"a": 1}])
    with caplog.at_level(logging.DEBUG):
        assert sink.drain() is False
        with pytest.raises(SocError) as caught:
            client.post_alerts([{"a": 1}])
    assert secret not in caplog.text and secret not in str(caught.value)
    assert secret not in repr(LiveSettings(soc_url="https://s", soc_token=secret))


def test_header_errors_do_not_quote_the_token(monkeypatch):
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_SECRET1")

    def explode(*a, **k):
        raise ValueError("Invalid header value b'Bearer idps_sensor_SECRET1'")

    monkeypatch.setattr(client._opener, "open", explode)
    with pytest.raises(SocError) as caught:
        client.post_alerts([{"a": 1}])
    assert "SECRET1" not in str(caught.value) and "SECRET1" not in repr(caught.value.__cause__)


def _ignores_sigterm(ready):  # top level, so the spawn start method can import it
    import signal as _signal
    import time as _time

    _signal.signal(_signal.SIGTERM, _signal.SIG_IGN)
    ready.set()
    while True:
        _time.sleep(0.1)


def test_stop_capture_processes_kills_a_child_that_ignores_sigterm():
    import multiprocessing as mp

    from idps.live.__main__ import stop_capture_processes

    ctx = mp.get_context("spawn")
    ready = ctx.Event()
    proc = ctx.Process(target=_ignores_sigterm, args=(ready,), daemon=True)
    proc.start()
    assert ready.wait(30), "child did not start"
    started = time.monotonic()
    assert stop_capture_processes(timeout=0.5) == 1
    assert not proc.is_alive()
    assert time.monotonic() - started < 5  # terminate, wait 0.5 s, kill: not forever


def test_live_mode_stops_capture_processes_on_the_way_out(model_file, tmp_path, monkeypatch):
    import idps.live.__main__ as cli

    calls = []
    monkeypatch.setattr(cli, "stop_capture_processes", lambda *a, **k: calls.append(1) or 0)
    monkeypatch.setattr("idps.capture.flows_from_interface", lambda *a, **k: iter(()))
    out = tmp_path / "alerts.jsonl"
    assert cli.main(["--interface", "lab0", "--no-heartbeat", "--model", str(model_file),
                     "--alerts-file", str(out)]) == 0
    assert calls == [1]


def test_startup_errors_of_the_capture_exit_2_and_close_the_sink(model_file, tmp_path, monkeypatch, capsys):
    import idps.live.__main__ as cli

    def boom(*a, **k):
        raise ValueError("no such interface")

    monkeypatch.setattr("idps.capture.flows_from_interface", boom)
    out = tmp_path / "alerts.jsonl"
    assert cli.main(["--interface", "nope0", "--model", str(model_file),
                     "--alerts-file", str(out)]) == 2
    assert "cannot start the capture" in capsys.readouterr().err


# --- Heartbeat: keeps NFStream's flow clock moving on a quiet link ------------------------------

HB_KEY = ("10.10.1.2", 50000)


def heartbeat_flow(i=0, **changes) -> Flow:
    from idps.live.heartbeat import HEARTBEAT_DST, HEARTBEAT_PORT

    values = dict.fromkeys((f.name for f in fields(Flow)), 0)
    start = 1_700_000_000_000 + i * 1000
    values.update(src_ip=HB_KEY[0], dst_ip=HEARTBEAT_DST, src_port=HB_KEY[1],
                  dst_port=HEARTBEAT_PORT, protocol=17, start_ms=start, end_ms=start + 120_000,
                  fwd_packets=120, fwd_bytes=120 * 29)
    values.update(changes)
    return Flow(**values)


class FakeHeartbeat:
    key = HB_KEY


def test_is_heartbeat_matches_only_our_own_socket():
    from idps.live.heartbeat import is_heartbeat

    assert is_heartbeat(heartbeat_flow(), HB_KEY)
    assert not is_heartbeat(heartbeat_flow(), None)  # no heartbeat running: nothing is dropped
    assert not is_heartbeat(make_flow(9), HB_KEY)  # TCP to port 9
    assert not is_heartbeat(heartbeat_flow(dst_ip="10.10.2.10"), HB_KEY)
    assert not is_heartbeat(heartbeat_flow(protocol=6), HB_KEY)
    # An attacker broadcasting to the same address and port is not our heartbeat ...
    assert not is_heartbeat(heartbeat_flow(src_ip="10.10.1.10", src_port=4444), HB_KEY)
    assert not is_heartbeat(heartbeat_flow(src_port=50001), HB_KEY)
    # ... and neither is a flow that got an answer.
    assert not is_heartbeat(heartbeat_flow(bwd_packets=1), HB_KEY)


def test_heartbeat_flows_never_reach_the_model_sink_or_engine(bundle):
    sink = ListSink()
    engine = _RecordingEngine(ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker()))
    det = detector(bundle, sink, engine=engine)
    det.heartbeat = FakeHeartbeat()
    det.run(iter([heartbeat_flow(i) for i in range(5)] + [make_flow(80, i) for i in range(8)]))
    assert det.metrics.counts["heartbeat_flows"] == 5
    assert det.metrics.counts["flows"] == 8  # only the real flows were scored
    assert sink.alerts, "the real flows must produce alerts, or this test checks nothing"
    assert all(a["dst_ip"] != "255.255.255.255" for a in sink.alerts)
    assert engine.detections, "the real flows must reach the engine"
    assert all(d.src_ip != HB_KEY[0] for d in engine.detections)


def test_a_batch_of_only_heartbeats_is_a_no_op(bundle):
    sink = ListSink()
    det = detector(bundle, sink)
    det.heartbeat = FakeHeartbeat()
    assert det.handle_batch([heartbeat_flow(0), heartbeat_flow(1)]) == []
    assert det.metrics.counts["flows"] == 0 and det.metrics.counts["batch_errors"] == 0


def test_foreign_broadcasts_are_scored_and_nothing_is_dropped_without_a_heartbeat(bundle):
    sink = ListSink()
    det = detector(bundle, sink)
    det.heartbeat = FakeHeartbeat()
    det.handle_batch([heartbeat_flow(0, src_ip="10.10.1.10", src_port=4444)])
    assert det.metrics.counts["flows"] == 1 and det.metrics.counts["heartbeat_flows"] == 0
    det.heartbeat = None
    det.handle_batch([heartbeat_flow(1)])
    assert det.metrics.counts["flows"] == 2


def test_the_detector_reports_every_batch_to_the_heartbeat(bundle):
    class CountingHeartbeat(FakeHeartbeat):
        def __init__(self):
            self.noted = []

        def note_flows(self, n):
            self.noted.append(n)

    det = detector(bundle, ListSink())
    det.heartbeat = hb = CountingHeartbeat()
    det.handle_batch([heartbeat_flow(0)] + [make_flow(80, i) for i in range(3)])
    det.handle_batch([heartbeat_flow(1)])
    assert hb.noted == [4, 1]  # heartbeat flows count too: they left the capture


class FakeSocket:
    def __init__(self, *args, fail=0, error=errno.ENETDOWN):
        self.options, self.sent, self.closed = [], [], False
        self.fail, self.error, self.connected = fail, error, None  # fail the first `fail` sends

    def setsockopt(self, level, option, value):
        self.options.append((option, value))

    def connect(self, address):
        self.connected = address

    def getsockname(self):
        return HB_KEY

    def send(self, data):
        if self.fail > 0:
            self.fail -= 1
            raise OSError(self.error, os.strerror(self.error))
        self.sent.append((data, self.connected))

    def close(self):
        self.closed = True


@pytest.fixture
def bindtodevice(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "SO_BINDTODEVICE", 25, raising=False)  # Linux's value
    return 25


def test_heartbeat_sends_broadcasts_bound_to_the_interface_until_stopped(bindtodevice):
    from idps.live.heartbeat import HEARTBEAT_DST, HEARTBEAT_PAYLOAD, HEARTBEAT_PORT, Heartbeat

    sock = FakeSocket()
    hb = Heartbeat("lab_attack", interval=0.01, sock_factory=lambda *a: sock)
    hb.start()
    assert hb.key == HB_KEY
    wait_for(lambda: len(sock.sent) >= 3)
    hb.stop()
    hb.stop()  # idempotent
    assert sock.closed
    assert (bindtodevice, b"lab_attack\0") in sock.options
    assert set(sock.sent) == {(HEARTBEAT_PAYLOAD, (HEARTBEAT_DST, HEARTBEAT_PORT))}


def test_heartbeat_permanent_start_failure_closes_the_socket_and_raises(bindtodevice):
    from idps.live.heartbeat import Heartbeat

    sock = FakeSocket(fail=1, error=errno.ENODEV)
    hb = Heartbeat("nope0", sock_factory=lambda *a: sock)
    with pytest.raises(OSError):
        hb.start()
    assert sock.closed


def test_heartbeat_temporary_failure_is_retried_and_recovers(bindtodevice, caplog):
    from idps.live.heartbeat import Heartbeat

    sock = FakeSocket(fail=3)  # the interface is down for the first three tries
    hb = Heartbeat("lab_attack", interval=0.01, sock_factory=lambda *a: sock)
    with caplog.at_level(logging.INFO, logger="idps.live"):
        hb.start()  # does not raise
        assert hb.failing
        wait_for(lambda: len(sock.sent) >= 2)
        hb.stop()
    assert not hb.failing
    failures = [r for r in caplog.records if "failed" in r.getMessage()]
    assert len(failures) == 1  # logged once per streak
    assert any("works again" in r.getMessage() for r in caplog.records)


def test_heartbeat_without_so_bindtodevice_raises_oserror(monkeypatch):
    import socket

    from idps.live.heartbeat import Heartbeat

    monkeypatch.delattr(socket, "SO_BINDTODEVICE", raising=False)
    with pytest.raises(OSError, match="Linux only"):
        Heartbeat("lab_attack", sock_factory=FakeSocket).start()


def test_heartbeat_interval_must_be_positive():
    from idps.live.heartbeat import Heartbeat

    with pytest.raises(ValueError):
        Heartbeat("lab_attack", interval=0)


def test_heartbeat_burst_mode_enters_at_the_cap_and_leaves_after_a_quiet_hold(caplog):
    """On at >= burst_flows in the last second; off only after staying under burst_exit_flows
    for BURST_HOLD seconds, so output near the threshold doesn't flip modes every second."""
    from idps.live.heartbeat import BURST_HOLD, Heartbeat

    now = [100.0]
    hb = Heartbeat("lab_attack", interval=1.0, fast_interval=0.05, burst_flows=900,
                   burst_exit_flows=250, clock=lambda: now[0])
    with caplog.at_level(logging.INFO, logger="idps.live"):
        assert hb.next_wait() == 1.0 and not hb.fast  # quiet link
        hb.note_flows(899)
        assert hb.next_wait() == 1.0  # one short of the cap
        hb.note_flows(1)
        assert hb.next_wait() == 0.05 and hb.fast  # exactly at the cap: burst
        assert hb.next_wait() == 0.05  # stays on, logged once
        for _ in range(10):  # the output hovers around 300/s: above the exit level, stays on
            now[0] += 1.0
            hb.note_flows(300)
            assert hb.next_wait() == 0.05
        now[0] += 1.01  # nothing for a second: under the exit level, but the hold isn't over
        assert hb.next_wait() == 0.05
        now[0] += BURST_HOLD
        assert hb.next_wait() == 1.0 and not hb.fast
        now[0] += 0.5
        hb.note_flows(400)  # a normal busy second: not a capped output, stays at 1 s
        assert hb.next_wait() == 1.0
    assert hb.bursts == 1
    msgs = [r.getMessage() for r in caplog.records]
    assert sum("burst mode" in m for m in msgs) == 1
    assert sum("back to every" in m for m in msgs) == 1


def test_heartbeat_window_is_one_second_and_stays_bounded():
    from idps.live.heartbeat import Heartbeat

    now = [0.0]
    hb = Heartbeat("lab_attack", burst_flows=1000, clock=lambda: now[0])
    for _ in range(10_000):  # an hour of tiny batches, nobody calling next_wait
        now[0] += 0.36
        hb.note_flows(1)
    assert len(hb._recent) <= 3  # pruned on every note, not only by the heartbeat thread
    hb.note_flows(500)
    now[0] += 1.0
    hb.note_flows(500)
    assert hb._recent_flows(now[0]) == 1001  # 1.0 s old still counts; older is gone
    now[0] += 0.01
    assert hb._recent_flows(now[0]) == 500


def test_heartbeat_burst_mode_can_be_turned_off_and_settings_are_checked():
    from idps.live.heartbeat import Heartbeat

    off = Heartbeat("lab_attack", fast_interval=None, burst_flows=1, clock=lambda: 0.0)
    off.note_flows(10_000)
    assert off.next_wait() == 1.0 and not off.fast and not off._recent
    assert Heartbeat("lab_attack", fast_interval=0).fast_interval is None
    assert Heartbeat("lab_attack", interval=0.005, fast_interval=0.05).fast_interval == 0.005
    hb = Heartbeat("lab_attack", burst_flows=1, clock=lambda: 0.0)
    hb.note_flows(0)
    hb.note_flows(-3)
    assert hb.next_wait() == 1.0
    for bad in ({"burst_flows": 0}, {"fast_interval": -1}, {"interval": 0}):
        with pytest.raises(ValueError):
            Heartbeat("lab_attack", **bad)


def test_a_real_heartbeat_speeds_up_from_the_detectors_batches(bundle):
    from idps.live.heartbeat import Heartbeat

    now = [0.0]
    hb = Heartbeat("lab_attack", burst_flows=5, clock=lambda: now[0])
    hb.key = HB_KEY
    det = detector(bundle, ListSink())
    det.heartbeat = hb
    det.handle_batch([make_flow(80, i) for i in range(3)])
    assert hb.next_wait() == 1.0
    det.handle_batch([heartbeat_flow(0)] + [make_flow(80, i) for i in range(1)])
    assert hb.next_wait() == hb.fast_interval
    assert det.metrics.counts["heartbeat_flows"] == 1


def test_heartbeat_sends_fast_during_a_burst_and_stops_promptly(bindtodevice):
    import time

    from idps.live.heartbeat import Heartbeat

    sock = FakeSocket()
    now = [0.0]  # a frozen clock: the burst can't expire however slow the machine is
    hb = Heartbeat("lab_attack", interval=5.0, fast_interval=0.01, burst_flows=10,
                   sock_factory=lambda *a: sock, clock=lambda: now[0])
    hb.note_flows(50)
    hb.start()  # one beat at start, then fast: a 5 s heartbeat could never send 5 in time
    wait_for(lambda: len(sock.sent) >= 5)
    t = time.monotonic()
    hb.stop()
    assert time.monotonic() - t < 1.0
    assert hb.bursts == 1


# --- block reports to the SOC -----------------------------------------------------------------

def _run_attack(bundle, sink, tmp_path, dry_run, n=5, blocker=None):
    blocker = blocker or FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=dry_run, allowlist=["10.10.1.1"]), blocker=blocker)
    detector(bundle, sink, engine=engine).run(
        flows_from_pcap(write_pcap(tmp_path / "a.pcap", attack_packets(n=n))))
    return blocker


def test_a_real_block_is_reported_once_with_the_right_fields(bundle, tmp_path):
    sink = ListSink()
    blocker = _run_attack(bundle, sink, tmp_path, dry_run=False)
    assert blocker.blocked == [CLIENT]
    assert len(sink.blocks) == 1
    ev = sink.blocks[0]
    assert set(ev) == {"event", "ip", "reason", "expires_at", "source"}
    assert (ev["event"], ev["ip"], ev["source"]) == ("blocked", CLIENT, "auto")
    assert re.fullmatch(r"\d+ flows >= [\d.]+ confidence \(.+\) in \d+s", ev["reason"])
    expires = datetime.fromisoformat(ev["expires_at"])
    assert expires.tzinfo is not None
    assert abs((expires - datetime.now(UTC)).total_seconds() - 900) < 30


def test_dry_run_reports_a_would_block_and_never_a_block(bundle, tmp_path):
    sink = ListSink()
    _run_attack(bundle, sink, tmp_path, dry_run=True)
    assert [e["event"] for e in sink.blocks] == ["would_block"]
    ev = sink.blocks[0]
    assert set(ev) == {"event", "ip", "reason", "ttl_seconds", "source", "decided_at"}  # no expires_at
    assert abs((datetime.fromisoformat(ev["decided_at"]) - datetime.now(UTC)).total_seconds()) < 30
    assert (ev["ip"], ev["source"], ev["ttl_seconds"]) == (CLIENT, "auto", 900)
    assert re.fullmatch(r"\d+ flows >= [\d.]+ confidence \(.+\) in \d+s", ev["reason"])


def test_real_blocking_never_reports_would_block(bundle, tmp_path):
    sink = ListSink()
    _run_attack(bundle, sink, tmp_path, dry_run=False)
    assert {e["event"] for e in sink.blocks} == {"blocked"}


def test_would_block_events_are_queued_retried_and_sent_like_other_reports():
    metrics, up, sent = Metrics(), [False], []

    def post_blocks(batch):
        if not up[0]:
            raise SocError("down")
        sent.extend(batch)
        return {}

    ev = {"event": "would_block", "ip": "203.0.113.7", "reason": "r", "source": "auto",
          "ttl_seconds": 900}
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False, post_blocks=post_blocks)
    sink.submit_blocks([ev, _event()])
    assert sink.drain() is False and sink._pending_blocks() == 2  # requeued, order kept
    up[0] = True
    assert sink.drain() is True and sent == [ev, _event()]
    assert metrics.counts["blocks_sent"] == 2


def test_a_would_block_has_no_expiry_so_it_is_not_dropped_as_ended():
    metrics, sent = Metrics(), []
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: sent.extend(b) or {})
    past = {"event": "blocked", "ip": "203.0.113.8", "reason": "r", "source": "auto",
            "expires_at": (datetime.now(UTC) - timedelta(seconds=60)).isoformat()}
    ev = {"event": "would_block", "ip": "203.0.113.7", "reason": "r", "source": "auto",
          "ttl_seconds": 900}
    sink.submit_blocks([past, ev])
    assert sink.drain() is True
    assert sent == [ev] and metrics.counts["blocks_dropped"] == 1  # only the ended block


def test_a_would_block_reaches_the_soc_and_not_its_blocks(
        bundle, tmp_path, client, sensor_token, analyst_headers, monkeypatch):
    from idps.soc_client import SocClient

    sensor = SocClient("http://127.0.0.1:9", sensor_token)

    def via_testclient(request, timeout):
        r = client.post(request.full_url.removeprefix("http://127.0.0.1:9"),
                        content=request.data, headers=dict(request.header_items()))
        assert r.status_code == 201, r.text

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return r.content
        return Resp()

    monkeypatch.setattr(sensor._opener, "open", via_testclient)
    sink = SocSink(sensor.post_alerts, Outbox(None), Metrics(), start=False,
                   post_blocks=sensor.post_blocks)
    _run_attack(bundle, sink, tmp_path, dry_run=True)
    assert sink.drain() is True
    assert client.get("/blocks", headers=analyst_headers).json()["items"] == []
    (w,) = client.get("/blocks/would", headers=analyst_headers).json()["items"]
    assert (w["ip"], w["source"], w["ttl_seconds"]) == (CLIENT, "auto", 900)
    assert client.get("/metrics/summary", headers=analyst_headers).json()["active_blocks"] == 0


# --- Sensor status report ---------------------------------------------------------------------------

def _status(bundle, *, dry_run=True, allowlist=(), heartbeat=None, interface="eth1", **live):
    from idps.live.status import build_status

    engine = ResponseEngine(Settings(dry_run=dry_run, allowlist=list(allowlist) or ["10.10.1.1"]),
                            blocker=FakeBlocker())
    metrics = Metrics()
    metrics.add("flows", 10)
    metrics.add("would_block", 2)
    metrics.observe_shap_ms(20.0, 5)
    return build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(**live),
                        metrics=metrics, sink=ListSink(), heartbeat=heartbeat,
                        interface=interface), metrics


def test_status_payload_in_dry_run(bundle):
    p, _ = _status(bundle, allowlist=["10.10.1.1", "10.10.2.0/24"])
    assert p["dry_run"] is True and p["blocking_enabled"] is False
    assert p["mode"] == "live" and p["interface"] == "eth1"
    assert p["model"] == {"name": bundle.model_name, "sha256": None,
                          "version": f"{bundle.model_name}-unversioned", "checksum_ok": True}
    assert p["policy"] == {"confidence_threshold": 0.9, "min_flows": 5, "window_seconds": 60.0,
                           "min_alert_confidence": 0.5, "block_ttl_seconds": 900,
                           "unblock_grace_seconds": 3600, "max_analyst_blocks": 1000}
    assert p["allowlist"] == ["10.10.1.1/32", "10.10.2.0/24"]
    assert p["allowlist_total"] == 2
    assert p["outbox_pending"] == 0 and p["shap_p95_ms"] == 20.0
    assert p["heartbeat"] == {"enabled": False, "ok": False}
    assert p["counters"] == {"flows": 10, "alerts": 0, "blocked": 0, "would_block": 2}
    assert datetime.fromisoformat(p["sent_at"]).tzinfo is not None


def test_status_payload_for_real_blocking_and_replay(bundle):
    p, _ = _status(bundle, dry_run=False, interface=None)
    assert p["dry_run"] is False and p["blocking_enabled"] is True
    assert p["mode"] == "replay" and p["interface"] is None


def test_status_payload_heartbeat_and_allowlist_cap(bundle):
    class HB:
        failing = True

    p, _ = _status(bundle, heartbeat=HB())
    assert p["heartbeat"] == {"enabled": True, "ok": False}
    p, _ = _status(bundle, allowlist=[f"10.{i // 250}.{i % 250}.0/24" for i in range(150)])
    assert len(p["allowlist"]) == 100 and p["allowlist_total"] == 150


def test_status_does_not_disturb_the_metrics_flow_rate(bundle):
    _, metrics = _status(bundle)
    first = metrics.snapshot()
    metrics.status()
    assert metrics._last[1] == first["flows"]


def test_the_status_payload_is_accepted_by_the_soc(bundle, client, sensor_headers, admin_headers):
    p, _ = _status(bundle, allowlist=["10.10.1.1", "10.10.2.0/24"])
    assert client.post("/sensor/status", json=p, headers=sensor_headers).status_code == 200
    (s,) = client.get("/sensors/status", headers=admin_headers).json()["sensors"]
    assert s["status"]["policy"]["min_flows"] == 5 and s["online"] is True


def test_the_client_posts_status_with_the_sensor_token(monkeypatch):
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_TOK")
    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return b'{"last_seen_at": "x"}'

    def fake_open(request, timeout):
        seen.update(url=request.full_url, auth=request.get_header("Authorization"),
                    method=request.get_method(), body=json.loads(request.data))
        return Resp()

    monkeypatch.setattr(client._opener, "open", fake_open)
    client.post_status({"dry_run": True})
    assert seen == {"url": "http://127.0.0.1:9/sensor/status", "auth": "Bearer idps_sensor_TOK",
                    "method": "POST", "body": {"dry_run": True}}


def test_the_reporter_logs_a_failure_streak_once_and_recovers(caplog):
    from idps.live.status import StatusReporter

    class Client:
        def __init__(self):
            self.up, self.sent = False, []

        def post_status(self, payload):
            if not self.up:
                raise SocError("down")
            self.sent.append(payload)

    c = Client()
    reporter = StatusReporter(c, lambda: {"x": 1}, interval=0.01)
    with caplog.at_level(logging.INFO, logger="idps.live"):
        assert [reporter.report_once() for _ in range(3)] == [False] * 3
        assert len([r for r in caplog.records if "status report not delivered" in r.message]) == 1
        c.up = True
        assert reporter.report_once() is True
    assert any("status reports resume" in r.message for r in caplog.records)
    assert c.sent == [{"x": 1}]


def test_the_reporter_survives_a_failing_builder_and_config_errors(caplog):
    from idps.live.status import StatusReporter

    class Client:
        def post_status(self, payload):
            raise SocRejectedError("HTTP 404", 404)

    def broken():
        raise RuntimeError("boom")

    assert StatusReporter(Client(), dict).report_once() is False
    assert StatusReporter(Client(), broken).report_once() is False


def test_the_reporter_thread_reports_at_start_then_periodically_and_stops():
    from idps.live.status import StatusReporter

    calls = []

    class Client:
        def post_status(self, payload):
            calls.append(payload)

    reporter = StatusReporter(Client(), lambda: {"n": len(calls)}, interval=0.02)
    reporter.start()
    wait_for(lambda: len(calls) >= 3)
    reporter.stop()
    assert not reporter._thread.is_alive()
    done = len(calls)
    time.sleep(0.1)
    assert len(calls) == done


def test_status_interval_is_configurable_and_bounded():
    assert LiveSettings().status_seconds == 30.0
    assert LiveSettings(status_seconds=60).status_seconds == 60
    with pytest.raises(ValueError):
        LiveSettings(status_seconds=1)


def test_a_failed_block_is_not_reported(bundle, tmp_path):
    from idps.respond.nft import BlockerError

    class Failing(FakeBlocker):
        def block(self, ip, ttl_seconds):
            raise BlockerError("nft failed")

    sink = ListSink()
    _run_attack(bundle, sink, tmp_path, dry_run=False, n=3, blocker=Failing())
    assert sink.blocks == []


_NOW = datetime.now(UTC)  # fixed, so that equal events compare equal


def _event(ip="203.0.113.7", seconds=600):
    return {"event": "blocked", "ip": ip, "reason": "r", "source": "auto",
            "expires_at": (_NOW + timedelta(seconds=seconds)).isoformat()}


def test_blocks_are_retried_while_the_soc_is_down_then_delivered():
    metrics, up, sent = Metrics(), [False], []

    def post_blocks(batch):
        if not up[0]:
            raise SocError("down")
        sent.extend(batch)
        return {}

    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False, post_blocks=post_blocks)
    sink.submit_blocks([_event()])
    assert sink.drain() is False and sent == [] and metrics.counts["blocks_sent"] == 0
    up[0] = True
    assert sink.drain() is True
    assert sent == [_event()] and metrics.counts["blocks_sent"] == 1
    assert sink._pending_blocks() == 0


def test_a_refused_block_batch_is_dropped_and_counted():
    metrics, calls = Metrics(), []

    def refuse(batch):
        calls.append(batch)
        raise SocRejectedError("HTTP 422", 422)

    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False, post_blocks=refuse)
    sink.submit_blocks([_event(), _event("203.0.113.8")])
    assert sink.drain() is True
    assert len(calls) == 1 and metrics.counts["blocks_rejected"] == 2
    assert sink._pending_blocks() == 0


def test_the_block_queue_is_bounded_and_drops_the_oldest(monkeypatch):
    from idps.live import sinks

    monkeypatch.setattr(sinks, "MAX_QUEUED_BLOCKS", 3)
    metrics, sent = Metrics(), []
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: sent.extend(b) or {})
    sink.submit_blocks([_event(f"203.0.113.{i}") for i in range(5)])
    assert metrics.counts["blocks_dropped"] == 2
    sink.drain()
    assert [e["ip"] for e in sent] == ["203.0.113.2", "203.0.113.3", "203.0.113.4"]
    assert Metrics().snapshot()["dropped"]["blocks"] == 0
    assert metrics.snapshot()["dropped"]["blocks"] == 2


def test_block_batches_respect_the_soc_limit():
    from idps.soc_client import MAX_BLOCK_EVENTS

    sizes = []
    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False,
                   post_blocks=lambda b: sizes.append(len(b)) or {})
    sink.submit_blocks([_event() for _ in range(MAX_BLOCK_EVENTS + 5)])
    sink.drain()
    assert sizes == [MAX_BLOCK_EVENTS, 5]


def test_the_jsonl_sink_writes_blocks_with_a_type(tmp_path):
    sink = JsonlSink(tmp_path / "alerts.jsonl", Metrics())
    sink.submit_blocks([_event()])
    sink.close()
    assert lines(tmp_path / "alerts.jsonl") == [{"type": "block", **_event()}]


def test_the_client_posts_blocks_to_ingest_blocks_with_the_bearer_token(monkeypatch):
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_TOK")
    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return b'{"blocked": 1, "unblocked": 0}'

    def fake_open(request, timeout):
        seen.update(url=request.full_url, auth=request.get_header("Authorization"),
                    body=json.loads(request.data))
        return Resp()

    monkeypatch.setattr(client._opener, "open", fake_open)
    assert client.post_blocks([_event()]) == {"blocked": 1, "unblocked": 0}
    assert seen == {"url": "http://127.0.0.1:9/ingest/blocks",
                    "auth": "Bearer idps_sensor_TOK", "body": {"events": [_event()]}}
    with pytest.raises(SocRejectedError):
        client.post_blocks([_event()] * 101)


def test_a_block_reported_by_the_sensor_client_shows_in_the_socs_blocks_list(
        client, sensor_token, analyst_headers, monkeypatch):
    from idps.soc_client import SocClient

    sensor = SocClient("http://127.0.0.1:9", sensor_token)

    def via_testclient(request, timeout):
        r = client.post(request.full_url.removeprefix("http://127.0.0.1:9"),
                        content=request.data, headers=dict(request.header_items()))

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return r.content
        assert r.status_code == 201, r.text
        return Resp()

    monkeypatch.setattr(sensor._opener, "open", via_testclient)
    sink = SocSink(sensor.post_alerts, Outbox(None), Metrics(), start=False,
                   post_blocks=sensor.post_blocks)
    sink.submit_blocks([_event()])
    assert sink.drain() is True
    items = client.get("/blocks", headers=analyst_headers).json()["items"]
    assert [(b["ip"], b["source"]) for b in items] == [("203.0.113.7", "auto")]


@pytest.mark.parametrize("error", [
    SocRejectedError("HTTP 404", 404), SocRejectedError("HTTP 401", 401), SocError("HTTP 500"),
])
def test_alerts_are_delivered_while_the_block_endpoint_fails(error, caplog):
    metrics, got = Metrics(), []

    def failing(batch):
        raise error

    sink = SocSink(lambda b: got.extend(b) or {}, Outbox(None), metrics, start=False,
                   post_blocks=failing)
    sink.submit([{"a": 1}])
    sink.submit_blocks([_event()])
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        assert sink.drain() is False  # blocks are still queued
        assert sink.drain() is False
    assert got == [{"a": 1}] and metrics.counts["alerts_sent"] == 1
    assert sink._pending_blocks() == 1 and metrics.counts["blocks_sent"] == 0
    assert len([r for r in caplog.records if "block reports cannot be delivered" in r.message]) == 1


def test_a_block_failure_streak_is_logged_again_after_a_success(caplog):
    state = {"fail": True}

    def post_blocks(batch):
        if state["fail"]:
            raise SocError("down")
        return {}

    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False, post_blocks=post_blocks)
    sink.submit_blocks([_event()])
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        sink.drain()
        state["fail"] = False
        sink.drain()
        state["fail"] = True
        sink.submit_blocks([_event()])
        sink.drain()
    assert len([r for r in caplog.records if "cannot be delivered" in r.message]) == 2


def test_close_with_pending_blocks_logs_the_loss(caplog):
    def down(batch):
        raise SocError("down")

    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False, post_blocks=down)
    sink.submit_blocks([_event(), _event("203.0.113.8")])
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        sink.close()
    assert "2 block report(s) were not delivered and are lost" in caplog.text


def test_requeue_overflow_drops_the_oldest_and_counts(monkeypatch, caplog):
    from idps.live import sinks

    monkeypatch.setattr(sinks, "MAX_QUEUED_BLOCKS", 3)
    metrics = Metrics()
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: (_ for _ in ()).throw(SocError("down")))
    sink.submit_blocks([_event("203.0.113.1"), _event("203.0.113.2")])

    # While a batch is in flight, new events queue up; the failed batch then goes back in front.
    def failing(batch):
        sink.submit_blocks([_event("203.0.113.3"), _event("203.0.113.4")])
        raise SocError("down")

    sink.post_blocks = failing
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        sink.drain()
    assert metrics.counts["blocks_dropped"] == 1
    assert [e["ip"] for e in sink._blocks] == ["203.0.113.2", "203.0.113.3", "203.0.113.4"]
    assert "dropped the 1 oldest" in caplog.text


def test_expired_block_events_are_dropped_before_posting_and_counted(caplog):
    metrics, sent = Metrics(), []
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: sent.extend(b) or {})
    gone, alive = _event("203.0.113.1", seconds=-10), _event("203.0.113.2")
    sink.submit_blocks([gone, alive])
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        assert sink.drain() is True
    assert sent == [alive] and metrics.counts["blocks_dropped"] == 1
    assert "already ended" in caplog.text


def test_a_failing_block_file_counts_blocks_not_alerts(tmp_path):
    sink = JsonlSink(tmp_path / "alerts.jsonl", Metrics())
    sink._file.close()
    sink.submit_blocks([_event()])
    assert sink.metrics.counts["blocks_dropped"] == 1 and sink.metrics.counts["alerts_dropped"] == 0


def test_blocks_without_a_block_sender_are_counted_and_logged_once(caplog):
    metrics = Metrics()
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False)
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        sink.submit_blocks([_event()])
        sink.submit_blocks([_event()])
    assert metrics.counts["blocks_dropped"] == 2
    assert caplog.text.count("no post_blocks") == 1


# --- Analyst actions: the sensor polls the SOC and applies block_ip / unblock_ip ---------------------

def _http_error(status):
    import urllib.error

    return urllib.error.HTTPError("http://soc/x", status, "err", {}, None)


class FakeSoc:
    """Stands in for SocClient: serves a list of actions and records the reported results."""

    def __init__(self, actions=()):
        self.actions = list(actions)
        self.results = []  # (id, success, result) accepted
        self.down = False
        self.fail_results = 0  # the next N result POSTs raise SocError
        self.result_status = None  # raise SocRejectedError(status) on result POSTs
        self.polls = 0

    def get_actions(self):
        self.polls += 1
        if self.down:
            raise SocError("down")
        return list(self.actions)

    def post_action_result(self, action_id, success, result):
        if self.down:
            raise SocError("down")
        if self.fail_results:
            self.fail_results -= 1
            raise SocError("HTTP 500")
        if self.result_status:
            raise SocRejectedError("rejected", self.result_status)
        self.results.append((action_id, success, result))
        self.actions = [a for a in self.actions if a["id"] != action_id]
        return {}


def act(id=1, kind="block_ip", ip="203.0.113.7", **params):
    return {"id": id, "kind": kind, "params": {"ip": ip, **params}}


def poller_for(soc, *, dry_run=False, allowlist=("10.10.1.1",), blocker=None, **kw):
    from idps.live.actions import ActionPoller

    blocker = blocker or FakeBlocker()
    clock = kw.pop("clock", None)
    engine_kw = {"clock": clock} if clock else {}
    engine = ResponseEngine(Settings(dry_run=dry_run, allowlist=list(allowlist)), blocker=blocker,
                            **engine_kw)
    sink, metrics = ListSink(), Metrics()
    return ActionPoller(soc, engine, sink, metrics, **kw), engine, blocker, sink, metrics


def test_an_analyst_block_executes_reports_success_and_queues_an_analyst_event():
    soc = FakeSoc([act(7, ttl_seconds=120)])
    poller, _, blocker, sink, metrics = poller_for(soc)
    assert poller.poll_once() is True
    assert blocker.blocked == ["203.0.113.7"]
    assert soc.results == [(7, True, {"ip": "203.0.113.7", "ttl_seconds": 120})]
    (ev,) = sink.blocks
    assert (ev["event"], ev["ip"], ev["source"]) == ("blocked", "203.0.113.7", "analyst")
    assert abs((datetime.fromisoformat(ev["expires_at"]) - datetime.now(UTC)).total_seconds() - 120) < 30
    assert metrics.counts["actions_executed"] == 1 and metrics.counts["actions_failed"] == 0


def test_the_default_ttl_is_the_settings_ttl_and_a_huge_one_is_capped():
    soc = FakeSoc([act(1), act(2, ip="203.0.113.8", ttl_seconds=10**9)])
    poller, *_ = poller_for(soc)
    poller.poll_once()
    assert soc.results[0][2]["ttl_seconds"] == 900
    assert soc.results[1][2]["ttl_seconds"] == 86_400


def test_an_allowlisted_address_is_refused_and_reported_failed():
    soc = FakeSoc([act(1, ip="10.10.1.1"), act(2, ip="::ffff:10.10.1.1"), act(3, ip="127.0.0.1")])
    poller, _, blocker, sink, metrics = poller_for(soc)
    poller.poll_once()
    assert blocker.blocked == [] and sink.blocks == []
    assert [(i, ok) for i, ok, _ in soc.results] == [(1, False), (2, False), (3, False)]
    assert "allowlisted" in soc.results[0][2]["error"]
    assert metrics.counts["actions_failed"] == 3


def test_dry_run_applies_nothing_and_reports_failed():
    soc = FakeSoc([act(1), act(2, kind="unblock_ip")])
    poller, _, blocker, sink, metrics = poller_for(soc, dry_run=True)
    poller.poll_once()
    assert blocker.blocked == [] and sink.blocks == []
    assert soc.results == [(1, False, {"error": "sensor is in dry-run: not applied"}),
                           (2, False, {"error": "sensor is in dry-run: not applied"})]
    assert metrics.counts["actions_failed"] == 2


def test_a_blocker_error_is_reported_failed():
    from idps.respond.nft import BlockerError

    class Failing(FakeBlocker):
        def block(self, ip, ttl_seconds):
            raise BlockerError("nft failed")

    soc = FakeSoc([act(1)])
    poller, _, _, sink, _ = poller_for(soc, blocker=Failing())
    poller.poll_once()
    assert soc.results[0][1] is False and "nft failed" in soc.results[0][2]["error"]
    assert sink.blocks == []


def test_unblock_executes_and_queues_an_unblocked_event():
    unblocked = []

    class Recording(FakeBlocker):
        def unblock(self, ip):
            unblocked.append(ip)

    soc = FakeSoc([act(4, kind="unblock_ip", ip="203.0.113.7")])
    poller, _, _, sink, metrics = poller_for(soc, blocker=Recording())
    poller.poll_once()
    assert unblocked == ["203.0.113.7"]
    assert soc.results[0][:2] == (4, True)
    assert sink.blocks == [{"event": "unblocked", "ip": "203.0.113.7"}]
    assert metrics.counts["actions_executed"] == 1


@pytest.mark.parametrize("action", [
    {"id": 1, "kind": "reboot", "params": {"ip": "203.0.113.7"}},
    {"id": 1, "kind": "block_ip", "params": {"ip": "not-an-ip"}},
    {"id": 1, "kind": "block_ip", "params": {"ip": 5}},
    {"id": 1, "kind": "block_ip", "params": {}},
    {"id": 1, "kind": "block_ip", "params": "x"},
    {"id": 1, "kind": "block_ip", "params": {"ip": "203.0.113.7", "ttl_seconds": 0}},
    {"id": 1, "kind": "block_ip", "params": {"ip": "203.0.113.7", "ttl_seconds": "60"}},
    {"id": 1, "kind": "block_ip", "params": {"ip": "203.0.113.7", "ttl_seconds": True}},
    {"id": 1, "kind": "unblock_ip", "params": {"ip": "999.1.1.1"}},
])
def test_untrusted_actions_are_reported_failed_and_never_applied(action):
    soc = FakeSoc([action])
    poller, _, blocker, sink, _ = poller_for(soc)
    poller.poll_once()
    assert blocker.blocked == [] and sink.blocks == []
    assert len(soc.results) == 1 and soc.results[0][1] is False


def test_an_unblock_stops_the_auto_policy_from_reblocking_until_the_grace_ends(bundle):
    now = [1000.0]
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"],
                                     unblock_grace_seconds=600), blocker=blocker,
                            clock=lambda: now[0])
    sink = ListSink()
    det = detector(bundle, sink, engine=engine)
    engine.unblock(ATTACKER)  # what the poller calls for an analyst unblock
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert blocker.blocked == []
    assert len(sink.alerts) == 8  # alerts still flow
    assert det.metrics.counts["blocks_suppressed"] >= 1
    now[0] += 601
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert blocker.blocked == [ATTACKER]


def test_an_analyst_block_ends_the_grace_period():
    now = [0.0]
    soc = FakeSoc([act(1, kind="unblock_ip", ip=ATTACKER)])
    poller, engine, blocker, _, _ = poller_for(soc, clock=lambda: now[0])
    poller.poll_once()
    assert engine._in_grace(ATTACKER)
    soc.actions = [act(2, ip=ATTACKER)]
    poller.poll_once()
    assert blocker.blocked == [ATTACKER] and not engine._in_grace(ATTACKER)


def test_a_failed_result_report_is_retried_without_applying_again():
    soc = FakeSoc([act(1)])
    soc.fail_results = 1
    poller, _, blocker, sink, metrics = poller_for(soc)
    assert poller.poll_once() is False  # applied, report failed
    assert soc.results == [] and blocker.blocked == ["203.0.113.7"]
    assert poller.poll_once() is True
    assert [r[:2] for r in soc.results] == [(1, True)]
    assert blocker.blocked == ["203.0.113.7"] and len(sink.blocks) == 1
    assert metrics.counts["actions_executed"] == 1
    poller.poll_once()
    assert len(soc.results) == 1


def test_a_409_on_the_result_is_forgotten_not_retried():
    soc = FakeSoc([act(1)])
    soc.result_status = 409
    poller, _, blocker, _, _ = poller_for(soc)
    assert poller.poll_once() is True
    assert poller._unreported == {} and blocker.blocked == ["203.0.113.7"]


def test_the_unreported_outcomes_are_bounded(monkeypatch):
    from idps.live import actions

    monkeypatch.setattr(actions, "MAX_UNREPORTED", 3)
    soc = FakeSoc([act(i, ip=f"203.0.113.{i}") for i in range(1, 7)])
    soc.fail_results = 10**6
    poller, *_ = poller_for(soc)
    poller.poll_once()
    assert len(poller._unreported) <= 3


def test_a_soc_outage_backs_off_logs_once_and_recovers(caplog):
    soc = FakeSoc([act(1)])
    soc.down = True
    poller, _, blocker, _, _ = poller_for(soc, interval=1.0, max_backoff=4.0)
    with caplog.at_level(logging.INFO, logger="idps.live"):
        assert [poller.poll_once() for _ in range(3)] == [False, False, False]
        assert sum("cannot fetch analyst actions" in r.message for r in caplog.records) == 1
        soc.down = False
        assert poller.poll_once() is True
        assert any("reachable again" in r.message for r in caplog.records)
    assert blocker.blocked == ["203.0.113.7"]


def test_the_poller_thread_survives_errors_backs_off_and_stops(monkeypatch):
    soc = FakeSoc()
    poller, *_ = poller_for(soc, interval=0.01, max_backoff=0.05)
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("boom")

    monkeypatch.setattr(poller, "poll_once", boom)
    poller.start()
    wait_for(lambda: len(calls) >= 3)
    assert poller.running
    poller.stop()
    assert not poller.running


def test_the_poller_thread_applies_actions_and_stops_on_request():
    soc = FakeSoc([act(1)])
    poller, _, blocker, _, _ = poller_for(soc, interval=0.01)
    poller.start()
    wait_for(lambda: soc.results)
    poller.stop()
    assert not poller.running and blocker.blocked == ["203.0.113.7"]


def test_the_engine_is_thread_safe_under_concurrent_detections_and_actions():
    from idps.respond.policy import Detection

    class Counting(FakeBlocker):
        def __init__(self):
            super().__init__()
            self.manual, self.unblocked = [], []
            self.lock = threading.Lock()

        def block(self, ip, ttl_seconds):
            with self.lock:
                (self.manual if ip.startswith("203.") else self.blocked).append(ip)

        def unblock(self, ip):
            with self.lock:
                self.unblocked.append(ip)

    blocker = Counting()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker,
                            min_flows=1)

    def detect():
        for i in range(300):
            engine.handle(Detection(f"198.51.100.{i % 50 + 1}", "DoS", 0.99, float(i)))

    def act_():
        for i in range(300):
            engine.manual_block(f"203.0.113.{i % 50 + 1}")
            engine.unblock(f"198.51.100.{i % 50 + 1}")

    threads = [threading.Thread(target=detect), threading.Thread(target=act_)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert not any(t.is_alive() for t in threads)
    assert len(blocker.manual) == 300 and len(blocker.unblocked) == 300
    assert len(engine._manual_until) == 50 and len(engine._grace_until) == 50
    assert len(blocker.blocked) <= 50  # each automatic block is applied at most once per address


def test_a_slow_nft_call_does_not_stall_the_detector_on_other_addresses():
    from idps.respond.policy import Detection

    release, started = threading.Event(), threading.Event()

    class Slow(FakeBlocker):
        def block(self, ip, ttl_seconds):
            if ip == "203.0.113.7":
                started.set()
                release.wait(10)
            self.blocked.append(ip)

    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=Slow(),
                            min_flows=1)
    t = threading.Thread(target=lambda: engine.manual_block("203.0.113.7"))
    t.start()
    assert started.wait(5)
    done = []
    d = threading.Thread(target=lambda: done.append(
        engine.handle(Detection("198.51.100.9", "DoS", 0.99, 1.0))))
    d.start()
    d.join(2)
    release.set()
    t.join(5)
    assert done and done[0].action.value == "block"  # decided while nft was still busy


def test_an_auto_block_never_shortens_an_active_analyst_block():
    from idps.respond.policy import Action, Detection

    now = [0.0]
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker,
                            min_flows=1, clock=lambda: now[0])
    assert engine.manual_block("198.51.100.5", 86_400) == 86_400
    decision = engine.handle(Detection("198.51.100.5", "DoS", 0.99, 1.0))
    assert decision.action is Action.ALREADY_BLOCKED
    assert blocker.blocked == ["198.51.100.5"]  # only the analyst's call, no auto re-add
    now[0] += 86_401  # the analyst block ended: automatic blocking works again
    assert engine.handle(Detection("198.51.100.5", "DoS", 0.99, 2000.0)).action is Action.BLOCK
    assert blocker.blocked == ["198.51.100.5"] * 2
    engine.manual_block("198.51.100.6", 600)
    engine.unblock("198.51.100.6")
    assert "198.51.100.6" not in engine._manual_until


def test_analyst_blocks_are_capped():
    from idps.respond.engine import ActionRefused

    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"], max_analyst_blocks=2),
                            blocker=FakeBlocker())
    engine.manual_block("198.51.100.1")
    engine.manual_block("198.51.100.2")
    engine.manual_block("198.51.100.2")  # renewing one it already holds is fine
    with pytest.raises(ActionRefused, match="analyst blocks"):
        engine.manual_block("198.51.100.3")
    engine.unblock("198.51.100.1")
    engine.manual_block("198.51.100.3")


ZONED = ["2600::1%x } ; flush ruleset ; add rule x", "fe80::1%eth0", "2600::1%1", "::1%",
         "1.2.3.4%x", "2600::1" + "0" * 50]


@pytest.mark.parametrize("text", ZONED)
def test_scoped_and_overlong_addresses_are_refused_everywhere(text):
    from idps.respond.engine import ActionRefused
    from idps.respond.nft import BlockerError, NftBlocker
    from idps.respond.policy import normalise_ip

    assert normalise_ip(text) is None
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    with pytest.raises(ActionRefused):
        engine.manual_block(text)
    with pytest.raises(ActionRefused):
        engine.manual_unblock(text)
    with pytest.raises(BlockerError):
        NftBlocker._target(text)
    soc = FakeSoc([act(1, ip=text), act(2, kind="unblock_ip", ip=text)])
    poller, _, blocker, sink, _ = poller_for(soc)
    poller.poll_once()
    assert blocker.blocked == [] and sink.blocks == []
    assert [(i, ok) for i, ok, _ in soc.results] == [(1, False), (2, False)]


def test_normalise_ip_returns_a_canonical_unscoped_address():
    from idps.respond.policy import normalise_ip

    assert str(normalise_ip(" 2600:0:0:0:0:0:0:1 ")) == "2600::1"
    assert str(normalise_ip("::ffff:10.1.2.3")) == "10.1.2.3"


def test_a_422_on_the_result_gets_one_minimal_failed_result_and_no_reapply():
    class Strict(FakeSoc):
        def post_action_result(self, action_id, success, result):
            if success or len(json.dumps(result)) > 100:
                raise SocRejectedError("HTTP 422", 422)
            return super().post_action_result(action_id, success, result)

    soc = Strict([act(1)])
    poller, _, blocker, _, _ = poller_for(soc)
    assert poller.poll_once() is True
    assert len(soc.results) == 1 and soc.results[0][:2] == (1, False)
    assert "422" in soc.results[0][2]["error"]
    poller.poll_once()
    assert blocker.blocked == ["203.0.113.7"] and len(soc.results) == 1


def test_a_409_keeps_the_id_so_a_relisted_action_is_never_reapplied():
    soc = FakeSoc([act(1)])
    soc.result_status = 409
    poller, _, blocker, _, _ = poller_for(soc)
    poller.poll_once()
    poller.poll_once()  # the SOC (this fake) lists it again
    assert blocker.blocked == ["203.0.113.7"]


def test_duplicate_ids_in_one_response_are_applied_once():
    soc = FakeSoc([act(1), act(1), act(1)])
    poller, _, blocker, sink, metrics = poller_for(soc)
    poller.poll_once()
    assert blocker.blocked == ["203.0.113.7"] and len(sink.blocks) == 1
    assert metrics.counts["actions_executed"] == 1


def test_at_most_fifty_actions_are_processed_per_poll():
    soc = FakeSoc([act(i, ip=f"198.51.100.{i}") for i in range(1, 81)])
    poller, _, blocker, _, _ = poller_for(soc)
    poller.poll_once()
    assert len(blocker.blocked) == 50
    poller.poll_once()
    assert len(blocker.blocked) == 80


def test_the_poller_checks_stop_between_actions():
    soc = FakeSoc([act(i, ip=f"198.51.100.{i}") for i in range(1, 11)])
    poller, engine, blocker, _, _ = poller_for(soc)
    original = engine.manual_block

    def stopping(*a, **kw):
        poller._stop.set()
        return original(*a, **kw)

    engine.manual_block = stopping
    poller.poll_once()
    assert len(blocker.blocked) == 1


def test_stop_reports_unreported_results(caplog):
    soc = FakeSoc([act(1)])
    soc.fail_results = 10
    poller, *_ = poller_for(soc)
    poller.poll_once()
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        poller.stop()
    assert any("never reported" in r.message for r in caplog.records)


def test_an_oversized_soc_answer_is_refused(monkeypatch):
    from idps.soc_client import MAX_RESPONSE_BYTES, SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_TOK")

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return b"[" + b" " * (MAX_RESPONSE_BYTES + 10) + b"]"

    monkeypatch.setattr(client._opener, "open", lambda r, timeout: Resp())
    with pytest.raises(SocError, match="over"):
        client.get_actions()


def test_jsonl_sink_writes_are_locked(tmp_path):
    sink = JsonlSink(tmp_path / "a.jsonl", Metrics())
    threads = [threading.Thread(target=lambda: [sink.submit_blocks([{"event": "blocked", "ip": "1.2.3.4"}])
                                               for _ in range(200)]) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    sink.close()
    assert len(lines(tmp_path / "a.jsonl")) == 800


def test_the_client_gets_actions_and_posts_results(monkeypatch):
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_TOK")
    seen = []

    class Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return self.body

    def fake_open(request, timeout):
        seen.append((request.get_method(), request.full_url, request.data,
                     request.get_header("Authorization")))
        return Resp(b'[{"id": 3}, 5]' if request.get_method() == "GET" else b"{}")

    monkeypatch.setattr(client._opener, "open", fake_open)
    assert client.get_actions() == [{"id": 3}]
    client.post_action_result(3, True, {"ip": "1.2.3.4"})
    assert seen[0] == ("GET", "http://127.0.0.1:9/sensor/actions", None, "Bearer idps_sensor_TOK")
    assert seen[1][:2] == ("POST", "http://127.0.0.1:9/sensor/actions/3/result")
    assert json.loads(seen[1][2]) == {"success": True, "result": {"ip": "1.2.3.4"}}
    monkeypatch.setattr(client._opener, "open", lambda r, timeout: Resp(b'{"x": 1}'))
    with pytest.raises(SocError):
        client.get_actions()


def test_an_unblock_event_survives_the_sinks_expiry_filter():
    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False, post_blocks=lambda b: {})
    sink.submit_blocks([{"event": "unblocked", "ip": "203.0.113.7"}])
    sink._drop_expired()
    assert sink._pending_blocks() == 1


def test_live_settings_validate_the_poll_interval(monkeypatch):
    from pydantic import ValidationError

    assert LiveSettings().action_poll_seconds == 5.0
    monkeypatch.setenv("IDPS_LIVE_ACTION_POLL_SECONDS", "30")
    assert LiveSettings().action_poll_seconds == 30.0
    for bad in ("0.5", "301"):
        monkeypatch.setenv("IDPS_LIVE_ACTION_POLL_SECONDS", bad)
        with pytest.raises(ValidationError):
            LiveSettings()
    assert Settings().unblock_grace_seconds == 3600


def test_end_to_end_an_analyst_unblock_reaches_the_sensor(
        client, sensor_token, analyst_headers, admin_headers, sensor_headers, monkeypatch):
    import urllib.error

    from idps.live.actions import ActionPoller
    from idps.soc_client import SocClient

    sensor = SocClient("http://127.0.0.1:9", sensor_token)

    def via_testclient(request, timeout):
        r = client.request(request.get_method(),
                           request.full_url.removeprefix("http://127.0.0.1:9"),
                           content=request.data, headers=dict(request.header_items()))
        if r.status_code >= 400:
            raise urllib.error.HTTPError(request.full_url, r.status_code, "err", {}, None)

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return r.content
        return Resp()

    monkeypatch.setattr(sensor._opener, "open", via_testclient)
    sensor_id = client.get("/admin/sensors", headers=admin_headers).json()[0]["id"]
    # An active auto block, which the analyst then lifts.
    client.post("/ingest/blocks", headers=sensor_headers, json={"events": [
        {"event": "blocked", "ip": "203.0.113.7", "ttl_seconds": 600, "source": "auto"}]})
    created = client.post("/actions", headers=analyst_headers, json={
        "kind": "unblock_ip", "ip": "203.0.113.7", "sensor_id": sensor_id, "reason": "false positive"})
    assert created.status_code == 201, created.text
    action_id = created.json()["id"]

    unblocked = []

    class Recording(FakeBlocker):
        def unblock(self, ip):
            unblocked.append(ip)

    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=Recording())
    sink = SocSink(sensor.post_alerts, Outbox(None), Metrics(), start=False,
                   post_blocks=sensor.post_blocks)
    poller = ActionPoller(sensor, engine, sink, Metrics())
    assert poller.poll_once() is True
    assert unblocked == ["203.0.113.7"]
    done = client.get(f"/actions/{action_id}", headers=analyst_headers).json()
    assert done["status"] == "executed" and done["result"]["ip"] == "203.0.113.7"
    assert sink.drain() is True  # the unblocked event reaches the Blocks page
    assert client.get("/blocks?active=true", headers=analyst_headers).json()["items"] == []
    assert poller.poll_once() is True and unblocked == ["203.0.113.7"]  # nothing left to do


def test_run_stops_the_status_reporter_before_the_sink_closes(model_file, tmp_path, monkeypatch):
    from idps.live import sinks, status

    order = []
    real_stop, real_close = status.StatusReporter.stop, sinks.SocSink.close

    def stop(self, timeout=10.0):
        order.append("reporter.stop")
        real_stop(self, timeout)

    def close(self):
        order.append("sink.close")
        real_close(self)

    monkeypatch.setattr(status.StatusReporter, "stop", stop)
    monkeypatch.setattr(sinks.SocSink, "close", close)
    monkeypatch.setenv("IDPS_SOC_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("IDPS_SOC_SENSOR_TOKEN", "idps_sensor_TOK")
    monkeypatch.setenv("IDPS_LIVE_OUTBOX_FILE", str(tmp_path / "outbox.json"))
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets(n=3))
    assert main(["--pcap", str(pcap), "--model", str(model_file)]) == 0
    assert order == ["reporter.stop", "sink.close"]


# --- Faithfulness report in the status ---------------------------------------------------------------

_FAITH_METHOD = {"mean_drop": 0.377, "median_drop": 0.002, "mean_confidence_after": 0.62,
                 "label_flip_rate": 0.42, "share_flows_beating_random": 1.0,
                 "ratio_to_random": 38.6}


def _faith_report(**over):
    base = {"config": {"n_flows": 100, "top_k": 5, "model": "xgboost", "seed": 0,
                       "classes_explained": {"BENIGN": 58}},
            "mean_confidence_before": 0.99, "random": {"mean_drop": 0.0097, "median_drop": 0.0},
            "methods": {"shap": _FAITH_METHOD, "lime": _FAITH_METHOD}}
    return base | over


def _write_faith(tmp_path, data, raw=None):
    path = tmp_path / "faith.json"
    path.write_text(raw if raw is not None else json.dumps(data))
    return str(path)


def test_a_valid_faithfulness_report_is_loaded_and_unknown_keys_are_ignored(tmp_path, caplog):
    from idps.live.faithfulness import load_faithfulness

    got = load_faithfulness(_write_faith(tmp_path, _faith_report()), "xgboost")
    keep = {k: _FAITH_METHOD[k] for k in
            ("mean_drop", "ratio_to_random", "label_flip_rate", "share_flows_beating_random")}
    assert got == {"model": "xgboost", "model_matches": True, "model_check": "name", "flows": 100, "top_k": 5,
                   "random_mean_drop": 0.0097, "methods": {"shap": keep, "lime": keep}}
    only = _faith_report(methods={"lime": _FAITH_METHOD})
    assert list(load_faithfulness(_write_faith(tmp_path, only), "xgboost")["methods"]) == ["lime"]


def test_the_real_report_in_the_repo_loads():
    from pathlib import Path

    from idps.live.faithfulness import load_faithfulness

    path = Path(__file__).parent.parent / "reports" / "friday_xgboost_faithfulness.json"
    if not path.exists():
        pytest.skip("no report in this checkout")
    got = load_faithfulness(str(path), "xgboost")
    assert got["methods"]["shap"]["ratio_to_random"] > 1 and got["model_matches"] is True


def test_no_path_or_a_missing_file_means_no_faithfulness(tmp_path, caplog):
    from idps.live.faithfulness import load_faithfulness

    assert load_faithfulness(None, "xgboost") is None
    assert load_faithfulness("", "xgboost") is None
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        assert load_faithfulness(str(tmp_path / "nope.json"), "xgboost") is None
    assert len([r for r in caplog.records if "ignoring the faithfulness" in r.message]) == 1


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("config"),
    lambda d: d["config"].pop("model"),
    lambda d: d["config"].update(n_flows=0),
    lambda d: d["config"].update(n_flows=True),
    lambda d: d["config"].update(top_k="5"),
    lambda d: d["random"].update(mean_drop=7),
    lambda d: d.pop("methods"),
    lambda d: d.update(methods={}),
    lambda d: d.update(methods={"other": _FAITH_METHOD}),
    lambda d: d["methods"]["shap"].update(ratio_to_random=-1e10),
    lambda d: d["methods"]["shap"].update(ratio_to_random="x"),
    lambda d: d["methods"]["shap"].update(mean_drop=None),
    lambda d: d["methods"]["shap"].update(label_flip_rate=2),
    lambda d: d["methods"]["shap"].update(mean_drop="x"),
    lambda d: d["methods"]["shap"].pop("mean_drop"),
])
def test_an_invalid_faithfulness_report_is_ignored_with_one_warning(tmp_path, caplog, mutate):
    from idps.live.faithfulness import load_faithfulness

    data = json.loads(json.dumps(_faith_report()))
    mutate(data)
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        assert load_faithfulness(_write_faith(tmp_path, data), "xgboost") is None
    assert len([r for r in caplog.records if "ignoring the faithfulness" in r.message]) == 1


@pytest.mark.parametrize("raw", ["not json", "[]", '"x"', "",
                                 json.dumps(_faith_report()).replace("38.6", "NaN"),
                                 json.dumps(_faith_report()).replace("38.6", "Infinity"),
                                 "[" * 100_000])
def test_unparseable_or_non_finite_reports_are_ignored(tmp_path, raw):
    from idps.live.faithfulness import load_faithfulness

    assert load_faithfulness(_write_faith(tmp_path, None, raw=raw), "xgboost") is None


def test_a_huge_report_is_not_read(tmp_path, monkeypatch):
    from idps.live import faithfulness as module

    path = _write_faith(tmp_path, _faith_report())
    monkeypatch.setattr(module, "MAX_REPORT_BYTES", 10)
    assert module.load_faithfulness(path, "xgboost") is None


_SHA = "0f" * 32


def test_a_digest_in_the_report_is_compared_with_the_loaded_models_digest(tmp_path, caplog):
    from idps.live.faithfulness import load_faithfulness

    data = _faith_report()
    data["config"]["model_sha256"] = _SHA.upper()  # case does not matter
    path = _write_faith(tmp_path, data)
    same = load_faithfulness(path, "xgboost", _SHA)
    assert (same["model_check"], same["model_matches"]) == ("digest", True)
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        retrained = load_faithfulness(path, "xgboost", "11" * 32)  # same algorithm, other bytes
    assert (retrained["model_check"], retrained["model_matches"]) == ("digest", False)
    assert any("model_matches=false" in r.message for r in caplog.records)
    # no digest known for the loaded model: only the name can be compared
    assert load_faithfulness(path, "xgboost", None)["model_check"] == "name"


@pytest.mark.parametrize("bad", ["short", "zz" * 32, 5, "a" * 65])
def test_a_malformed_digest_makes_the_report_invalid(tmp_path, bad):
    from idps.live.faithfulness import load_faithfulness

    data = _faith_report()
    data["config"]["model_sha256"] = bad
    assert load_faithfulness(_write_faith(tmp_path, data), "xgboost", _SHA) is None


def test_null_and_negative_ratios_are_kept(tmp_path):
    from idps.live.faithfulness import load_faithfulness

    data = _faith_report()
    data["methods"]["shap"] = {**_FAITH_METHOD, "ratio_to_random": None, "mean_drop": -0.1}
    data["methods"]["lime"] = {**_FAITH_METHOD, "ratio_to_random": -3.5}
    got = load_faithfulness(_write_faith(tmp_path, data), "xgboost")
    assert got["methods"]["shap"]["ratio_to_random"] is None
    assert got["methods"]["shap"]["mean_drop"] == -0.1
    assert got["methods"]["lime"]["ratio_to_random"] == -3.5
    data["methods"]["lime"]["ratio_to_random"] = 1e10  # finite but beyond the bound
    assert load_faithfulness(_write_faith(tmp_path, data), "xgboost") is None


def test_a_report_for_another_model_is_kept_but_flagged(tmp_path, caplog):
    from idps.live.faithfulness import load_faithfulness

    with caplog.at_level(logging.WARNING, logger="idps.live"):
        got = load_faithfulness(_write_faith(tmp_path, _faith_report()), "random_forest")
    assert got["model"] == "xgboost" and got["model_matches"] is False
    assert any("model_matches=false" in r.message for r in caplog.records)


def test_the_status_carries_faithfulness_only_when_there_is_one(bundle):
    from idps.live.status import build_status

    def payload(**kw):
        engine = ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker())
        return build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(),
                            metrics=Metrics(), sink=ListSink(), interface="eth1", **kw)

    assert "faithfulness" not in payload()
    assert payload(faithfulness={"model": "x"})["faithfulness"] == {"model": "x"}


def test_the_setting_defaults_to_none_and_reads_the_environment(monkeypatch):
    assert Settings().faithfulness_report is None
    monkeypatch.setenv("IDPS_FAITHFULNESS_REPORT", "reports/x.json")
    assert Settings().faithfulness_report == "reports/x.json"


def test_the_loaded_report_reaches_the_soc_status(model_file, tmp_path, monkeypatch, client,
                                                  sensor_headers, analyst_headers):
    """End to end: main() loads the report, the status payload carries it, the SOC accepts it."""
    from idps.live import status as status_module

    sent = []
    monkeypatch.setattr(status_module.StatusReporter, "start", lambda self: sent.append(self.build()))
    monkeypatch.setenv("IDPS_SOC_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("IDPS_SOC_SENSOR_TOKEN", "idps_sensor_TOK")
    monkeypatch.setenv("IDPS_LIVE_OUTBOX_FILE", str(tmp_path / "outbox.json"))
    monkeypatch.setenv("IDPS_FAITHFULNESS_REPORT", _write_faith(tmp_path, _faith_report()))
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets(n=3))
    assert main(["--pcap", str(pcap), "--model", str(model_file)]) == 0
    (payload,) = sent
    assert payload["faithfulness"]["methods"]["shap"]["ratio_to_random"] == 38.6
    assert client.post("/sensor/status", json=payload, headers=sensor_headers).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"]["flows"] == 100


# --- Faithfulness loader hardening / status text ------------------------------------------------

def test_a_huge_integer_in_the_report_is_a_warning_not_a_crash(tmp_path, caplog):
    from idps.live.faithfulness import load_faithfulness

    big = "9" * 400  # float() of this integer raises OverflowError
    raw = json.dumps(_faith_report()).replace('"mean_drop": 0.377', f'"mean_drop": {big}', 1)
    assert big in raw
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        assert load_faithfulness(_write_faith(tmp_path, None, raw=raw), "xgboost") is None
    assert len([r for r in caplog.records if "ignoring the faithfulness" in r.message]) == 1
    raw = json.dumps(_faith_report()).replace('"top_k": 5', f'"top_k": {big}')
    assert load_faithfulness(_write_faith(tmp_path, None, raw=raw), "xgboost") is None
    raw = json.dumps(_faith_report()).replace('"mean_drop": 0.0097', f'"mean_drop": -{big}')
    assert load_faithfulness(_write_faith(tmp_path, None, raw=raw), "xgboost") is None


def test_the_sensor_starts_with_a_hostile_report(model_file, tmp_path, monkeypatch):
    big = "9" * 400
    path = tmp_path / "f.json"
    path.write_text(json.dumps(_faith_report()).replace('"mean_drop": 0.377', f'"mean_drop": {big}'))
    monkeypatch.setenv("IDPS_FAITHFULNESS_REPORT", str(path))
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets(n=3))
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)]) == 0


def test_only_a_regular_file_is_read(tmp_path):
    from idps.live.faithfulness import load_faithfulness

    good = _write_faith(tmp_path, _faith_report())
    link = tmp_path / "link.json"
    link.symlink_to(good)
    assert load_faithfulness(str(link), "xgboost") is not None  # the operator's own link: fine
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "missing.json")
    assert load_faithfulness(str(dangling), "xgboost") is None
    to_dir = tmp_path / "to_dir.json"
    to_dir.symlink_to(tmp_path)
    assert load_faithfulness(str(to_dir), "xgboost") is None  # still must be a regular file
    assert load_faithfulness(str(tmp_path), "xgboost") is None  # a directory
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    assert load_faithfulness(str(fifo), "xgboost") is None  # does not block on a pipe
    assert load_faithfulness(good, "xgboost") is not None


@pytest.mark.parametrize("bad", ["eth\x1b[0m", "a\u202eb", "a\nb"])
def test_a_report_model_name_with_control_characters_is_invalid(tmp_path, bad):
    from idps.live.faithfulness import load_faithfulness

    data = _faith_report()
    data["config"]["model"] = bad
    assert load_faithfulness(_write_faith(tmp_path, data), "xgboost") is None


def test_the_status_text_is_cleaned_so_the_soc_accepts_it(bundle):
    from idps.live.status import build_status

    engine = ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker())
    p = build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(), metrics=Metrics(),
                     sink=ListSink(), interface="et\u202eh\x001")
    assert p["interface"] == "eth1"
    assert build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(),
                        metrics=Metrics(), sink=ListSink(), interface="\u200b")["interface"] is None


def test_the_sensors_status_always_passes_the_socs_strict_schema(bundle):
    from idps.live.status import build_status
    from soc.api.routes.sensors import StatusReport

    for dry_run in (True, False):
        engine = ResponseEngine(Settings(dry_run=dry_run, allowlist=["10.10.1.1", "10.9.0.0/16"]),
                                blocker=FakeBlocker())
        for interface in ("eth1", None):
            payload = build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(),
                                   metrics=Metrics(), sink=ListSink(), interface=interface)
            StatusReport.model_validate(json.loads(json.dumps(payload)))


# --- Learning from analysts: what the sensor sends -------------------------------------------------

SHA = "ab" * 32


def test_alerts_carry_features_and_the_model_identity(bundle):
    sink = ListSink()
    det = LiveDetector(bundle, quiet_engine(), sink, LiveSettings(metrics_seconds=3600.0), META,
                       live=False, model_sha256=SHA, model_version="tiny-v1")
    alerts = det.handle_batch([make_flow(80, i) for i in range(3)])
    assert len(alerts) == 3
    for a in alerts:
        assert list(a["features"]) == MODEL_FEATURES
        assert all(type(v) is float for v in a["features"].values())
        assert a["features"]["dst_port"] == 80.0 and a["features"]["fwd_packets"] == 20.0
        assert a["model_sha256"] == SHA and a["model_version"] == "tiny-v1"
    AlertBatch.model_validate({"alerts": alerts})  # the SOC accepts exactly this


def test_alert_payload_features_are_opt_in_and_finite_only():
    from idps.soc_client import alert_payload

    row = {**dict.fromkeys(FEATURE_COLUMNS, 1.0), "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
           "start_ms": 1, "end_ms": 2}
    pred = Prediction("DDoS", 0.9)
    assert "features" not in alert_payload(row, pred)
    assert "model_sha256" not in alert_payload(row, pred)
    p = alert_payload(row, pred, model_sha256=SHA, model_version="v", with_features=True)
    assert p["features"] == dict.fromkeys(MODEL_FEATURES, 1.0)
    assert p["model_sha256"] == SHA and p["model_version"] == "v"
    for bad in (float("nan"), float("inf")):
        p = alert_payload({**row, "fwd_packets": bad}, pred, with_features=True)
        assert p is not None and "features" not in p  # no partial vector: the alert still goes
    assert "features" not in alert_payload({k: v for k, v in row.items() if k != "iat_max"},
                                           pred, with_features=True)


def test_the_drift_monitor_sees_every_flow_not_only_alerts(bundle):
    from idps.detect.drift import DriftMonitor, build_reference

    ref = build_reference(pd.DataFrame([dict.fromkeys(MODEL_FEATURES, 0.0)] * 20), SHA)
    mon = DriftMonitor(ref, window=100, min_window=1)
    sink = ListSink()
    det = LiveDetector(bundle, quiet_engine(), sink, LiveSettings(metrics_seconds=3600.0), META,
                       live=False, drift=mon)
    det.handle_batch([make_flow(80, 0), make_flow(443, 1), make_flow(53, 2)])  # 1 alert, 3 flows
    assert len(sink.alerts) == 1 and mon.report()["window"] == 3


def test_a_failing_drift_monitor_never_stops_detection(bundle):
    class Broken:
        def update(self, frame):
            raise RuntimeError("boom")

    sink = ListSink()
    det = LiveDetector(bundle, quiet_engine(), sink, LiveSettings(metrics_seconds=3600.0), META,
                       live=False, drift=Broken())
    assert len(det.handle_batch([make_flow(80, 0)])) == 1


def test_status_carries_model_identity_and_drift_and_the_soc_accepts_it(bundle):
    from idps.detect.drift import DriftMonitor, NoDrift, build_reference
    from idps.live.status import build_status
    from soc.api.routes.sensors import StatusReport

    ref = build_reference(pd.DataFrame([dict.fromkeys(MODEL_FEATURES, 0.0)] * 20), SHA)
    engine = ResponseEngine(Settings(dry_run=True, allowlist=["10.10.1.1"]), blocker=FakeBlocker())
    for drift in (DriftMonitor(ref, window=50), NoDrift("no drift reference"), None):
        p = build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(),
                         metrics=Metrics(), sink=ListSink(), interface="eth1", model_sha256=SHA,
                         drift=drift)
        assert p["model"] == {"name": "xgboost", "sha256": SHA, "version": f"xgboost-{SHA[:8]}",
                              "checksum_ok": True}
        assert ("drift" in p) == (drift is not None)
        StatusReport.model_validate(p)
    p = build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(),
                     metrics=Metrics(), sink=ListSink(), interface="eth1", model_sha256=SHA,
                     drift=NoDrift("why"))
    assert p["drift"] == {"level": "unknown", "reason": "why"}


def test_replay_alerts_name_the_model_that_scored_them(model_file, tmp_path):
    from idps.detect.bundle import model_version, read_digest

    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=2))
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)]) == 0
    sha = read_digest(model_file)
    alerts = lines(out)
    assert alerts and all(a["model_sha256"] == sha and set(a["features"]) == set(MODEL_FEATURES)
                          and a["model_version"] == model_version(load_bundle(model_file), sha)
                          for a in alerts)


def test_send_features_off_sends_nothing_an_older_soc_would_refuse(bundle, model_file, tmp_path,
                                                                  monkeypatch):
    from idps.detect.drift import NoDrift
    from idps.live.status import build_status

    sink = ListSink()
    det = LiveDetector(bundle, quiet_engine(), sink, LiveSettings(metrics_seconds=3600.0), META,
                       live=False, send_features=False)
    (a,) = det.handle_batch([make_flow(80, 0)])
    assert not {"features", "model_sha256", "model_version"} & set(a)
    engine = ResponseEngine(Settings(dry_run=True, allowlist=["10.10.1.1"]), blocker=FakeBlocker())
    p = build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(), metrics=Metrics(),
                     sink=ListSink(), interface=None, model_sha256=SHA, drift=NoDrift("x"),
                     extended=False)
    assert p["model"] == {"name": "xgboost", "checksum_ok": True} and "drift" not in p
    assert LiveSettings().send_features is True
    monkeypatch.setenv("IDPS_LIVE_SEND_FEATURES", "false")
    assert LiveSettings().send_features is False
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets(n=2))
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)]) == 0
    assert lines(out) and not any("features" in a or "model_sha256" in a for a in lines(out))


def test_the_model_version_in_an_alert_is_printable_and_at_most_80_characters():
    from idps.soc_client import alert_payload

    row = {**dict.fromkeys(FEATURE_COLUMNS, 1.0), "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
           "start_ms": 1, "end_ms": 2}
    p = alert_payload(row, Prediction("DDoS", 0.9), model_version="v\u202e1\n" + "x" * 200)
    assert len(p["model_version"]) == 80 and p["model_version"].startswith("v1x")
    AlertBatch.model_validate({"alerts": [p]})
    assert "model_version" not in alert_payload(row, Prediction("DDoS", 0.9), model_version="\n")
