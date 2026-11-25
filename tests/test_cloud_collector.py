"""Collector: checkpointing, scoring, the SOC ingest payload, dry-run (Stubber, no network)."""

import gzip
import http.server
import io
import json
import logging
import shutil
import socketserver
import ssl
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("boto3")
import boto3
from botocore.response import StreamingBody
from botocore.stub import Stubber
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import LabelEncoder

from idps.cloud.collector import (
    Checkpoint,
    Collector,
    CollectorConfig,
    CollectorError,
    Outbox,
    Prediction,
    SocClient,
    SocRejectedError,
    alert_payload,
    list_new_objects,
    load_cloud_bundle,
    score_frame,
)
from idps.cloud.flowlogs import (
    CLOUD_MODEL_FEATURES,
    cloud_extraction_meta,
    read_path,
    rows_to_frame,
    to_flow_rows,
)
from idps.cloud.nacl import NaclBlocker
from idps.config import Settings
from idps.detect.bundle import Bundle, save_bundle
from idps.features import extraction_meta
from idps.respond.engine import ResponseEngine
from idps.respond.nft import BlockerError
from idps.respond.policy import ResponsePolicy
from soc.api.routes.alerts import AlertBatch

SAMPLE = Path(__file__).parent / "data" / "flowlogs_sample.log"
BUCKET = "idps-fyp-flowlogs-test"
PREFIX = "AWSLogs/123456789010/vpcflowlogs/eu-west-1/"
NOW = datetime(2023, 11, 14, 22, 30, tzinfo=UTC)  # 1700000000 is 2023-11-14 22:13:20 UTC


@pytest.fixture(autouse=True)
def _no_ambient_config(monkeypatch):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for name in [n for n in __import__("os").environ if n.startswith("IDPS_")]:
        monkeypatch.delenv(name)


def aws(service):
    return boto3.client(service, region_name="eu-west-1",
                        aws_access_key_id="AKIAFAKEFAKEFAKEFAKE", aws_secret_access_key="fake")


@pytest.fixture
def s3():
    client = aws("s3")
    with Stubber(client) as stubber:
        client.stubber = stubber
        yield client
        stubber.assert_no_pending_responses()


def key_for(name, day="2023/11/14"):
    return f"{PREFIX}{day}/123456789010_vpcflowlogs_eu-west-1_fl-0abc_{name}.log.gz"


def obj(name, minutes, day="2023/11/14"):
    return {"Key": key_for(name, day), "LastModified": NOW - timedelta(minutes=minutes), "Size": 10}


def stub_listing(s3, per_day):
    """Expect one list call per day folder (the day before the start, then the start day)."""
    for day, contents in per_day.items():
        response = {"Contents": contents} if contents else {}
        s3.stubber.add_response("list_objects_v2", response,
                                {"Bucket": BUCKET, "Prefix": f"{PREFIX}{day}/"})


def stub_get(s3, name, data=None, day="2023/11/14"):
    data = gzip.compress(SAMPLE.read_bytes()) if data is None else data
    s3.stubber.add_response(
        "get_object", {"Body": StreamingBody(io.BytesIO(data), len(data)), "ContentLength": len(data)},
        {"Bucket": BUCKET, "Key": key_for(name, day)})


class FakeBundle:
    """Shaped like idps.detect.bundle.Bundle: flags a flow when it was REJECTed."""

    features = CLOUD_MODEL_FEATURES
    label_encoder = LabelEncoder().fit(["benign", "portscan"])
    anomaly = None

    def predict_proba(self, X):
        bad = X["rejected"].to_numpy() > 0
        return np.where(bad[:, None], [[0.03, 0.97]], [[0.95, 0.05]])


def config(tmp_path, **kw):
    return CollectorConfig(bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path / "state", **kw)


# --- Checkpoint and listing -------------------------------------------------------------------

def test_first_run_looks_back_and_then_only_new_objects_are_processed(s3, tmp_path):
    posted = []
    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(),
                          post=lambda alerts: posted.append(alerts) or {}, now=lambda: NOW)
    old = obj("old", 120)  # before the 1 hour lookback: ignored on the first run
    a, b = obj("a", 20), obj("b", 10)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [old, b, a]})
    stub_get(s3, "a")
    stub_get(s3, "b")
    result = collector.run_once()
    assert result.objects == 2 and result.rows == 10
    assert len(posted) == 2
    saved = json.loads((tmp_path / "state" / "checkpoint.json").read_text())
    assert set(saved["processed"]) == {a["Key"], b["Key"]}
    assert datetime.fromisoformat(saved["high_water"]) == b["LastModified"]

    # Second cycle (a new Collector reloads the checkpoint from disk): a, b are not repeated;
    # c is new; d shares b's timestamp and is new too.
    collector2 = Collector(config(tmp_path), s3, bundle=FakeBundle(),
                           post=lambda alerts: posted.append(alerts) or {}, now=lambda: NOW)
    c = obj("c", 6)
    d = {"Key": key_for("d"), "LastModified": b["LastModified"], "Size": 1}
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [a, b, c, d]})
    stub_get(s3, "d")  # d sorts before c: same timestamp as b, older than c
    stub_get(s3, "c")
    result = collector2.run_once()
    assert result.objects == 2
    saved = json.loads((tmp_path / "state" / "checkpoint.json").read_text())
    assert set(saved["processed"]) == {a["Key"], b["Key"], c["Key"], d["Key"]}


def test_cloud_status_reports_scored_flows_and_refreshes_in_quiet_cycles(s3, tmp_path):
    from unittest.mock import Mock

    from soc.api.routes.sensors import StatusReport

    client = Mock()
    bundle = FakeBundle()
    bundle.model_name = "cloud-test"
    collector = Collector(config(tmp_path), s3, bundle=bundle, status_client=client,
                          engine=ResponseEngine(Settings(dry_run=True)), post=client.post_alerts,
                          now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    collector.run_once()
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": []})
    collector.run_once()
    assert client.post_status.call_count == 2
    for call in client.post_status.call_args_list:
        status = StatusReport.model_validate(call.args[0])
        assert status.interface == "VPC Flow Logs" and status.dry_run
        assert status.counters.flows == 5 and status.counters.alerts == 2
        assert status.outbox_pending == 0


def test_a_late_object_older_than_the_newest_processed_one_is_still_read(s3, tmp_path):
    ckpt = Checkpoint(tmp_path / "c.json")
    newest = obj("newest", 10)
    ckpt.advance(newest["LastModified"], newest["Key"])
    late = obj("late", 40)  # published after `newest`, but stamped earlier
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [late, newest]})
    found = list_new_objects(s3, BUCKET, PREFIX, ckpt, NOW, timedelta(hours=1))
    assert [o["Key"] for o in found] == [late["Key"]]


def test_objects_younger_than_the_settle_delay_wait_for_a_later_cycle(s3, tmp_path):
    ckpt = Checkpoint(tmp_path / "c.json")
    fresh, settled = obj("fresh", 2), obj("settled", 8)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [fresh, settled]})
    found = list_new_objects(s3, BUCKET, PREFIX, ckpt, NOW, timedelta(hours=1))
    assert [o["Key"] for o in found] == [settled["Key"]]
    # Ten minutes later the fresh one has settled.
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [fresh, settled]})
    found = list_new_objects(s3, BUCKET, PREFIX, ckpt, NOW + timedelta(minutes=10),
                             timedelta(hours=1))
    assert [o["Key"] for o in found] == [settled["Key"], fresh["Key"]]  # oldest first


def test_processed_keys_are_remembered_for_two_hours_only(tmp_path):
    ckpt = Checkpoint(tmp_path / "c.json")
    old, new = obj("old", 600), obj("new", 10)
    ckpt.advance(old["LastModified"], old["Key"])
    ckpt.advance(new["LastModified"], new["Key"])
    assert set(Checkpoint(tmp_path / "c.json").processed) == {new["Key"]}


def test_a_version_1_checkpoint_is_still_read(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"last_modified": NOW.isoformat(), "keys": ["k1"]}))
    ckpt = Checkpoint(path)
    assert ckpt.high_water == NOW and not ckpt.is_new(NOW, "k1") and ckpt.is_new(NOW, "k2")


def test_non_log_objects_and_pagination(s3, tmp_path):
    ckpt = Checkpoint(tmp_path / "c.json")
    junk = {"Key": f"{PREFIX}2023/11/14/readme.txt", "LastModified": NOW, "Size": 1}
    page1 = {"Contents": [obj("a", 10), junk], "IsTruncated": True, "NextContinuationToken": "t1"}
    s3.stubber.add_response("list_objects_v2", {}, {"Bucket": BUCKET, "Prefix": f"{PREFIX}2023/11/13/"})
    s3.stubber.add_response("list_objects_v2", page1, {"Bucket": BUCKET, "Prefix": f"{PREFIX}2023/11/14/"})
    s3.stubber.add_response("list_objects_v2", {"Contents": [obj("b", 5)]},
                            {"Bucket": BUCKET, "Prefix": f"{PREFIX}2023/11/14/", "ContinuationToken": "t1"})
    found = list_new_objects(s3, BUCKET, PREFIX.rstrip("/"), ckpt, NOW, timedelta(hours=1))
    assert [o["Key"] for o in found] == [key_for("a"), key_for("b")]


def test_checkpoint_survives_garbage_and_never_moves_backwards(tmp_path):
    path = tmp_path / "c.json"
    path.write_text("nope")
    ckpt = Checkpoint(path)
    assert ckpt.high_water is None
    ckpt.advance(NOW, "k1")
    ckpt.advance(NOW - timedelta(hours=1), "older")
    ckpt.advance(NOW, "k2")
    again = Checkpoint(path)
    assert again.high_water == NOW and set(again.processed) == {"k1", "older", "k2"}


def test_soc_outage_keeps_the_alerts_queued_and_moves_the_checkpoint(s3, tmp_path):
    calls = []

    def failing(_alerts):
        calls.append(1)
        raise CollectorError("SOC down")

    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), post=failing,
                          now=lambda: NOW, sleep=lambda _s: None)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    result = collector.run_once()  # does not raise: the SOC is not needed to process the object
    assert len(calls) == 3  # SEND_ATTEMPTS, with backoff
    assert result.alerts_queued == 2 and result.alerts_sent == 0 and result.alerts_pending == 2
    assert key_for("a") in json.loads((tmp_path / "state" / "checkpoint.json").read_text())["processed"]
    queued = json.loads((tmp_path / "state" / "outbox.json").read_text())["batches"]
    assert [len(b) for b in queued] == [2]

    # The SOC is back: a new collector sends the queued alerts, from the file, without S3.
    sent = []
    collector2 = Collector(config(tmp_path), s3, bundle=FakeBundle(),
                           post=lambda a: sent.append(a) or {}, now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    result = collector2.run_once()
    assert result.alerts_sent == 2 and len(sent) == 1 and result.alerts_pending == 0
    assert json.loads((tmp_path / "state" / "outbox.json").read_text())["batches"] == []


def test_the_engine_runs_even_when_the_soc_post_fails(s3, tmp_path):
    ec2 = aws("ec2")
    with Stubber(ec2) as ec2_stub:
        settings = Settings(dry_run=True, allowlist=["10.60.0.0/16"])
        policy = ResponsePolicy.from_settings(settings, min_flows=1)
        blocker = NaclBlocker(ec2, "acl-0123456789abcdef0", policy, tmp_path / "nacl.json",
                              dry_run=True)
        engine = ResponseEngine(settings, blocker=blocker, policy=policy)

        def failing(_alerts):
            raise CollectorError("SOC down")

        collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), engine=engine,
                              blocker=blocker, post=failing, now=lambda: NOW, sleep=lambda _s: None)
        stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
        stub_get(s3, "a")
        result = collector.run_once()
        ec2_stub.assert_no_pending_responses()
    assert result.would_block == 1 and result.alerts_pending == 2


def test_a_4xx_batch_is_dropped_and_not_retried(s3, tmp_path):
    calls = []

    def refusing(alerts):
        calls.append(len(alerts))
        raise SocRejectedError("SOC rejected the alerts: HTTP 422")

    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), post=refusing,
                          now=lambda: NOW, sleep=lambda _s: pytest.fail("a 4xx must not back off"))
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    result = collector.run_once()
    assert calls == [2] and result.batches_rejected == 1 and result.alerts_pending == 0
    assert json.loads((tmp_path / "state" / "outbox.json").read_text())["batches"] == []


def test_a_5xx_is_retried_with_backoff_and_an_accepted_batch_is_not_resent(s3, tmp_path):
    outcomes = iter([CollectorError("HTTP 503"), None, None])
    sent, pauses = [], []

    def flaky(alerts):
        outcome = next(outcomes)
        if outcome:
            raise outcome
        sent.append(alerts)
        return {}

    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), post=flaky,
                          now=lambda: NOW, sleep=pauses.append)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10), obj("b", 9)]})
    stub_get(s3, "a")
    stub_get(s3, "b")
    result = collector.run_once()
    assert pauses == [2.0] and len(sent) == 2 and result.alerts_sent == 4  # 503, then a and b once each
    assert result.alerts_pending == 0


def test_a_batch_accepted_before_an_outage_is_not_sent_again(s3, tmp_path):
    state = {"n": 0}
    sent = []

    def first_ok_then_down(alerts):
        state["n"] += 1
        if state["n"] > 1:
            raise CollectorError("SOC down")
        sent.append(alerts)
        return {}

    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), post=first_ok_then_down,
                          now=lambda: NOW, sleep=lambda _s: None)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10), obj("b", 9)]})
    stub_get(s3, "a")
    stub_get(s3, "b")
    result = collector.run_once()
    assert len(sent) == 1 and result.alerts_sent == 2 and result.alerts_pending == 2
    assert [len(b) for b in Outbox(tmp_path / "state" / "outbox.json").batches] == [2]


def test_http_status_classes_from_the_soc_client(local_soc):
    for status, expected in ((422, SocRejectedError), (401, SocRejectedError),
                             (429, CollectorError), (503, CollectorError)):
        _Handler.status = status
        with pytest.raises(expected) as caught:
            SocClient(local_soc, "tok").post_alerts([{}])
        assert (type(caught.value) is SocRejectedError) == (expected is SocRejectedError)


def test_s3_error_is_a_collectorerror_and_does_not_move_the_checkpoint(s3, tmp_path):
    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), post=lambda a: {}, now=lambda: NOW)
    s3.stubber.add_client_error("list_objects_v2", service_error_code="AccessDenied")
    with pytest.raises(CollectorError, match="S3 request failed"):
        collector.run_once()


def test_corrupt_object_is_skipped_and_does_not_block_the_rest(s3, tmp_path):
    posted = []
    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(),
                          post=lambda a: posted.append(a) or {}, now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("bad", 20), obj("good", 10)]})
    stub_get(s3, "bad", data=gzip.compress(b"x" * 5000)[:-20])
    stub_get(s3, "good")
    result = collector.run_once()
    assert (result.objects, result.skipped_objects) == (2, 1) and len(posted) == 1


# --- Scoring and the ingest payload -----------------------------------------------------------

def test_score_frame_picks_the_top_class():
    df = rows_to_frame(to_flow_rows(read_path(SAMPLE)))
    preds = score_frame(FakeBundle(), df)
    assert [p.label for p in preds].count("portscan") == 2  # the two REJECTed flows
    assert all(0 <= p.confidence <= 1 for p in preds)
    assert score_frame(FakeBundle(), rows_to_frame([])) == []


def test_alert_payload_validates_against_the_soc_model():
    rows = to_flow_rows(read_path(SAMPLE))
    alerts = [alert_payload(r, Prediction("portscan", 0.97)) for r in rows]
    batch = AlertBatch.model_validate({"alerts": alerts})  # the SOC's own pydantic model
    assert len(batch.alerts) == len(rows)
    assert {a["src_ip"] for a in alerts} >= {"198.51.100.7", "2001:db8::1"}
    first = alerts[0]
    assert set(first) == {"src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms",
                          "end_ms", "predicted_class", "confidence", "explanation"}
    with_anomaly = alert_payload(rows[0], Prediction("portscan", 0.97, anomaly_score=-0.2))
    AlertBatch.model_validate({"alerts": [with_anomaly]})
    assert with_anomaly["anomaly_score"] == -0.2


@pytest.mark.parametrize("pred", [Prediction("x", float("nan")), Prediction("x", 1.5)])
def test_alert_payload_drops_what_the_soc_would_reject(pred):
    row = to_flow_rows(read_path(SAMPLE))[0]
    assert alert_payload(row, pred) is None


def test_alert_payload_drops_out_of_range_times():
    row = dict(to_flow_rows(read_path(SAMPLE))[0], end_ms=5_000_000_000_000)
    assert alert_payload(row, Prediction("x", 0.9)) is None


def test_collector_posts_only_non_benign_alerts_in_the_soc_format(s3, tmp_path):
    posted = []
    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(),
                          post=lambda a: posted.append(a) or {}, now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    result = collector.run_once()
    assert result.alerts_sent == 2 and len(posted) == 1
    AlertBatch.model_validate({"alerts": posted[0]})
    assert {a["predicted_class"] for a in posted[0]} == {"portscan"}


def test_min_alert_confidence_filters(s3, tmp_path):
    posted = []
    collector = Collector(config(tmp_path, min_alert_confidence=0.99), s3, bundle=FakeBundle(),
                          post=lambda a: posted.append(a) or {}, now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    assert collector.run_once().alerts_sent == 0 and posted == []


def test_without_a_model_it_only_counts(s3, tmp_path, caplog):
    posted = []
    collector = Collector(config(tmp_path), s3, post=lambda a: posted.append(a) or {}, now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    with caplog.at_level(logging.INFO, logger="idps.cloud.collector"):
        result = collector.run_once()
    assert posted == [] and result.rows == 5 and result.alerts_sent == 0
    assert any('"event": "counted"' in r.getMessage() for r in caplog.records)


# --- Dry-run blocking -------------------------------------------------------------------------

def test_dry_run_blocking_logs_and_makes_no_ec2_calls(s3, tmp_path, caplog):
    ec2 = aws("ec2")
    with Stubber(ec2) as ec2_stub:  # nothing queued: any EC2 call would fail the test
        settings = Settings(dry_run=True, allowlist=["10.60.0.0/16"])
        policy = ResponsePolicy.from_settings(settings, min_flows=1)
        blocker = NaclBlocker(ec2, "acl-0123456789abcdef0", policy, tmp_path / "nacl.json",
                              dry_run=settings.dry_run)
        engine = ResponseEngine(settings, blocker=blocker, policy=policy)
        collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), engine=engine,
                              blocker=blocker, post=lambda a: {}, now=lambda: NOW)
        stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
        stub_get(s3, "a")
        with caplog.at_level(logging.WARNING):
            result = collector.run_once()
        ec2_stub.assert_no_pending_responses()
    assert result.would_block == 1 and result.blocked == 0  # 198.51.100.7, once
    assert any("would_block" in r.getMessage() for r in caplog.records)
    assert blocker.active() == {} and not (tmp_path / "nacl.json").exists()


# --- Model loading ----------------------------------------------------------------------------

def _bundle(meta, tmp_path):
    X = rows_to_frame(to_flow_rows(read_path(SAMPLE)))[CLOUD_MODEL_FEATURES].astype(float)
    y = ["benign", "benign", "portscan", "portscan", "benign"]
    enc = LabelEncoder().fit(y)
    model = DummyClassifier(strategy="prior").fit(X, enc.transform(y))
    bundle = Bundle("dummy", model, enc, list(CLOUD_MODEL_FEATURES), meta, {}, {})
    return save_bundle(bundle, tmp_path / "model.joblib")


def test_cloud_bundle_round_trip_and_scoring(tmp_path):
    path = _bundle(cloud_extraction_meta(), tmp_path)
    bundle = load_cloud_bundle(path)
    preds = score_frame(bundle, rows_to_frame(to_flow_rows(read_path(SAMPLE))))
    assert len(preds) == 5 and {p.label for p in preds} <= {"benign", "portscan"}


def test_lab_bundle_is_refused_by_the_cloud_loader(tmp_path):
    path = _bundle(extraction_meta("nfstream", 15, 120), tmp_path)
    with pytest.raises(ValueError, match="not trained on VPC flow log features"):
        load_cloud_bundle(path)


def test_cloud_bundle_without_digest_is_refused(tmp_path):
    path = _bundle(cloud_extraction_meta(), tmp_path)
    Path(f"{path}.sha256").unlink()
    with pytest.raises(ValueError, match="digest"):
        load_cloud_bundle(path)


# --- SOC client -------------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []  # noqa: RUF012  shared with the test on purpose
    redirect = False
    status: int | None = None

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Handler.seen.append((self.path, self.headers.get("Authorization"), json.loads(body)))
        if _Handler.status:
            self.send_response(_Handler.status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if _Handler.redirect:
            self.send_response(307)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
            return
        payload = json.dumps({"accepted": 1, "skipped_benign": 0, "ids": [1]}).encode()
        self.send_response(201)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _Server(http.server.HTTPServer):
    def server_bind(self):  # HTTPServer.server_bind does a slow reverse DNS lookup
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


@pytest.fixture
def local_soc():
    _Handler.seen, _Handler.redirect, _Handler.status = [], False, None
    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_soc_client_sends_the_token_to_ingest_alerts(local_soc):
    client = SocClient(local_soc + "/", "idps_sensor_secret")
    assert client.post_alerts([{"a": 1}])["accepted"] == 1
    path, auth, body = _Handler.seen[0]
    assert path == "/ingest/alerts" and auth == "Bearer idps_sensor_secret"
    assert body == {"alerts": [{"a": 1}]}


def test_soc_client_does_not_follow_redirects(local_soc):
    _Handler.redirect = True
    with pytest.raises(CollectorError, match="HTTP 307"):
        SocClient(local_soc, "tok").post_alerts([{}])


def test_soc_client_refuses_plain_http_off_localhost():
    with pytest.raises(ValueError, match="https"):
        SocClient("http://soc.example.com", "tok")
    SocClient("https://soc.example.com", "tok")
    SocClient("http://localhost:8000", "tok")


def test_soc_client_unreachable_is_a_collectorerror():
    with pytest.raises(CollectorError, match="cannot reach"):
        SocClient("http://127.0.0.1:1", "tok", timeout=2).post_alerts([{}])


def test_config_from_env_reads_the_documented_names():
    cfg = CollectorConfig.from_env({
        "IDPS_CLOUD_BUCKET": "b", "IDPS_SOC_URL": "https://soc", "IDPS_SOC_SENSOR_TOKEN": "tok",
        "IDPS_CLOUD_NACL_ID": "acl-1", "AWS_REGION": "eu-west-1",
    })
    assert (cfg.bucket, cfg.soc_url, cfg.sensor_token, cfg.nacl_id, cfg.region) == (
        "b", "https://soc", "tok", "acl-1", "eu-west-1")
    assert "tok" not in repr(cfg)  # the token must not leak into logs


# --- TLS with the SOC's own CA ----------------------------------------------------------------

@pytest.fixture
def tls_soc(tmp_path):
    """A local HTTPS server whose certificate (valid for 127.0.0.1 only) nobody else trusts."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert, key = tmp_path / "soc.crt", tmp_path / "soc.key"
    made = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", str(key), "-out", str(cert)], check=False, capture_output=True)
    if made.returncode != 0:
        pytest.skip("openssl cannot make a certificate here")
    _Handler.seen, _Handler.redirect, _Handler.status = [], False, None
    server = _Server(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{server.server_port}", cert
    server.shutdown()
    server.server_close()


def test_soc_client_verifies_the_certificate_against_the_given_ca_file(tls_soc):
    url, cert = tls_soc
    assert SocClient(url, "tok", ca_file=str(cert)).post_alerts([{"a": 1}])["accepted"] == 1
    with pytest.raises(CollectorError, match="cannot reach"):  # self-signed: not trusted by default
        SocClient(url, "tok", timeout=5).post_alerts([{"a": 1}])
    assert len(_Handler.seen) == 1  # the untrusted attempt never got as far as sending the token


def test_soc_client_rejects_an_unreadable_ca_file(tmp_path):
    with pytest.raises(ValueError, match="IDPS_SOC_CA_FILE"):
        SocClient("https://soc.example.com", "tok", ca_file=str(tmp_path / "missing.pem"))


def test_ca_file_comes_from_the_environment():
    cfg = CollectorConfig.from_env({"IDPS_SOC_CA_FILE": "/etc/idps/soc-root.crt"})
    assert cfg.soc_ca_file == "/etc/idps/soc-root.crt"


# --- Prefix and configuration -----------------------------------------------------------------

def test_prefix_is_required_and_must_end_in_vpcflowlogs_region(tmp_path):
    for bad in ("", "AWSLogs/", "AWSLogs/123456789010/", "AWSLogs/123456789010/vpcflowlogs/"):
        with pytest.raises(ValueError):
            CollectorConfig(bucket=BUCKET, prefix=bad, state_dir=tmp_path).validate()
    ok = CollectorConfig(bucket=BUCKET, prefix=PREFIX.rstrip("/"), state_dir=tmp_path)
    ok.validate()
    assert ok.prefix == PREFIX  # trailing slash added
    with pytest.raises(ValueError, match="region"):
        CollectorConfig(bucket=BUCKET, prefix=PREFIX, region="us-east-1", state_dir=tmp_path).validate()
    CollectorConfig(bucket=BUCKET, prefix=PREFIX, region="eu-west-1", state_dir=tmp_path).validate()


def test_collector_refuses_a_bad_prefix(s3, tmp_path):
    with pytest.raises(ValueError, match="vpcflowlogs"):
        Collector(CollectorConfig(bucket=BUCKET, prefix="AWSLogs/", state_dir=tmp_path), s3)


def test_a_bad_number_in_the_environment_is_a_clean_error(monkeypatch, capsys):
    from idps.cloud.__main__ import main

    monkeypatch.setenv("IDPS_CLOUD_MAX_DENIES", "ten")
    assert main(["collect", "--once"]) == 2
    assert "IDPS_CLOUD_MAX_DENIES" in capsys.readouterr().err


def test_max_denies_above_the_acl_quota_is_a_clean_error(monkeypatch, capsys):
    from idps.cloud.__main__ import main

    monkeypatch.setenv("IDPS_CLOUD_MAX_DENIES", "50")
    monkeypatch.setenv("IDPS_CLOUD_BUCKET", BUCKET)
    monkeypatch.setenv("IDPS_CLOUD_PREFIX", PREFIX)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    assert main(["collect", "--once"]) == 1
    assert "max_denies" in capsys.readouterr().err


# --- run_forever, expiry errors, oversized numbers ---------------------------------------------

class _Stop(BaseException):
    pass


def test_run_forever_survives_any_error_and_backs_off(s3, tmp_path):
    collector = Collector(config(tmp_path), s3, now=lambda: NOW)
    outcomes = iter([OSError("disk full"), CollectorError("S3"), RuntimeError("bug"), None, None])
    calls = []

    def run_once():
        calls.append(1)
        outcome = next(outcomes)
        if outcome:
            raise outcome

    collector.run_once = run_once
    pauses = []

    def sleep(seconds):
        pauses.append(seconds)
        if len(pauses) == 5:
            raise _Stop

    with pytest.raises(_Stop):
        collector.run_forever(10, sleep=sleep)
    assert len(calls) == 5
    assert pauses == [20, 40, 80, 10, 10]  # grows while failing, resets after a good cycle


def test_a_blockererror_from_expire_does_not_stop_the_cycle(s3, tmp_path, caplog):
    class Failing:
        def expire(self):
            raise BlockerError("RequestLimitExceeded")

    posted = []
    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), blocker=Failing(),
                          post=lambda a: posted.append(a) or {}, now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    with caplog.at_level(logging.ERROR):
        result = collector.run_once()
    assert result.objects == 1 and len(posted) == 1 and result.expired == 0
    assert any("could not expire" in r.getMessage() for r in caplog.records)


def test_an_overflowing_object_is_skipped_so_it_cannot_pin_the_checkpoint(s3, tmp_path, monkeypatch):
    import idps.cloud.collector as module

    real = module.to_flow_rows
    monkeypatch.setattr(module, "to_flow_rows", lambda records: (_ for _ in ()).throw(
        OverflowError("int too large to convert")))
    collector = Collector(config(tmp_path), s3, bundle=FakeBundle(), post=lambda a: {},
                          now=lambda: NOW)
    stub_listing(s3, {"2023/11/13": [], "2023/11/14": [obj("a", 10)]})
    stub_get(s3, "a")
    result = collector.run_once()
    assert result.skipped_objects == 1 and result.objects == 1
    assert key_for("a") in collector.checkpoint.processed
    monkeypatch.setattr(module, "to_flow_rows", real)
