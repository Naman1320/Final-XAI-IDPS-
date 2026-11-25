"""Roadmap step 9: notifications (webhook, Slack, email), syslog/CEF export, AbuseIPDB reputation.

No test touches the network beyond 127.0.0.1: receivers are local threads, DNS is faked, and the
AbuseIPDB client is replaced by a fake. Nothing real (Slack, SMTP, AbuseIPDB) is ever contacted.
"""

import hashlib
import hmac
import json
import logging
import re
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import ClassVar

import pytest
from conftest import ADMIN_PW, ANALYST_PW, TEST_SECRET, alert_payload, ingest, login
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_soc_rules import rule_payload

from soc.api import auth
from soc.api.integrations import channels, formats, netguard
from soc.api.integrations.formats import Digest, Event, TestNotice
from soc.api.integrations.manager import ChannelRunner, NotificationManager
from soc.api.integrations.netguard import DeliveryError, UnsafeDestination
from soc.api.integrations.reputation import ReputationService
from soc.api.main import create_app
from soc.api.models import AuditEntry, Role
from soc.api.settings import SocSettings

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
LAB = {"notify_allow_private": True, "notify_allow_http": True}  # local receivers only


def mk(**kw) -> SocSettings:
    kw.setdefault("mfa_required_for_admins", False)  # these tests log in with a password only
    return SocSettings(jwt_secret=TEST_SECRET, database_url="sqlite://",
                       block_allowlist=["10.10.1.1"], **kw)


def wait_until(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def ev(**kw) -> Event:
    base = {"kind": "alert", "at": NOW, "sensor": "lab-sensor", "severity": "high",
            "predicted_class": "DoS", "source": "ml", "alert_id": 7, "src_ip": "203.0.113.7",
            "src_port": 51514, "dst_ip": "10.10.1.5", "dst_port": 80, "protocol": 6}
    return Event(**(base | kw))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# --- local receivers -------------------------------------------------------------------------

class Receiver:
    """HTTP server on 127.0.0.1 that records requests and answers from a script of statuses."""

    def __init__(self, statuses=(200,), location=None):
        self.requests, self.statuses, self.location = [], list(statuses), location
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append({"path": self.path, "headers": dict(self.headers),
                                       "body": body})
                code = outer.statuses.pop(0) if len(outer.statuses) > 1 else outer.statuses[0]
                self.send_response(code)
                if outer.location:
                    self.send_header("Location", outer.location)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/hook/SECRET-PATH-TOKEN"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    made = []

    def make(**kw):
        r = Receiver(**kw)
        made.append(r)
        return r

    yield make
    for r in made:
        r.close()


class FakeSmtp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.mails = []
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                w = lambda s: self.wfile.write(s.encode() + b"\r\n")
                w("220 fake ESMTP")
                mail = {"from": None, "to": [], "data": b""}
                while line := self.rfile.readline():
                    cmd = line.decode().strip()
                    up = cmd.upper()
                    if up.startswith(("EHLO", "HELO")):
                        w("250 fake")
                    elif up.startswith("MAIL FROM"):
                        mail["from"] = cmd[10:]
                        w("250 ok")
                    elif up.startswith("RCPT TO"):
                        mail["to"].append(cmd[8:])
                        w("250 ok")
                    elif up == "DATA":
                        w("354 go")
                        data = b""
                        while True:
                            chunk = self.rfile.readline()
                            if chunk in (b".\r\n", b""):
                                break
                            data += chunk
                        mail["data"] = data
                        outer.mails.append(mail)
                        w("250 queued")
                    elif up == "QUIT":
                        w("221 bye")
                        return
                    else:
                        w("250 ok")

        super().__init__(("127.0.0.1", 0), Handler)
        self.port = self.server_address[1]
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def close(self):
        self.shutdown()
        self.server_close()


class TcpSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port=0):
        self.data = bytearray()
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                while chunk := self.request.recv(4096):
                    outer.data.extend(chunk)

        super().__init__(("127.0.0.1", port), Handler)
        self.port = self.server_address[1]
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def close(self):
        self.shutdown()
        self.server_close()


class UdpSink:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]

    def recv(self) -> bytes:
        return self.sock.recvfrom(65535)[0]

    def close(self):
        self.sock.close()


# --- app fixture -----------------------------------------------------------------------------

@pytest.fixture
def make_app(soc_settings):
    apps = []

    def build(**kw):
        app = create_app(mk(**kw))
        app.state.assistant_llm = None
        with app.state.session_factory() as db:
            auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
            auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
            token = auth.create_sensor_token(db, "lab-sensor")
        client = TestClient(app)
        apps.append(app)
        return SimpleNamespace(
            app=app, client=client, admin=login(client, "admin", ADMIN_PW),
            analyst=login(client, "analyst", ANALYST_PW),
            sensor={"Authorization": f"Bearer {token}"})

    yield build
    for app in apps:
        app.state.notifier.close()


def runner_for(channel_cls, settings, clock=None):
    return ChannelRunner(channel_cls(settings), settings, clock=clock or Clock(),
                         now=lambda: NOW, start_thread=False)


# --- settings ---------------------------------------------------------------------------------

def test_integrations_are_off_by_default(soc_settings):
    s = mk()
    m = NotificationManager(s, start_threads=False)
    assert not m.any_active()
    assert s.notify_min_severity == "high" and s.webhook_include_rules is True


def test_blank_values_are_unset_and_secret_files_are_read(soc_settings, tmp_path, monkeypatch):
    f = tmp_path / "hook"
    f.write_text("https://hooks.example.com/abc\n")
    monkeypatch.setenv("IDPS_SOC_WEBHOOK_URL_FILE", str(f))
    monkeypatch.setenv("IDPS_SOC_SLACK_WEBHOOK_URL", "")   # docker compose passes "" for unset
    monkeypatch.setenv("IDPS_SOC_SMTP_PORT", "")
    monkeypatch.setenv("IDPS_SOC_SYSLOG_CA_FILE", "")
    s = mk()
    assert s.webhook_url.get_secret_value() == "https://hooks.example.com/abc"
    assert s.slack_webhook_url is None and s.smtp_port is None and s.smtp_port_effective == 587 and s.syslog_ca_file is None
    assert "hooks.example.com" not in repr(s)  # SecretStr


def test_bad_settings_are_refused(soc_settings):
    for bad in ({"notify_min_severity": "urgent"}, {"smtp_to": ["a@b.c", "evil\r\nBcc: x@y.z"]},
                {"smtp_from": "no-at-sign"}, {"public_url": "javascript:alert(1)"},
                {"syslog_protocol": "carrier-pigeon"}):
        with pytest.raises(ValueError):
            mk(**bad)


# --- queue, threshold, include_rules ----------------------------------------------------------

def test_severity_threshold_and_include_rules(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", webhook_include_rules=False)
    r = runner_for(channels.WebhookChannel, s)
    assert r.offer(ev(severity="low")) == "skipped"
    assert r.offer(ev(severity="medium")) == "skipped"
    assert r.offer(ev(severity="high")) == "queued"
    assert r.offer(ev(severity="critical", predicted_class="Heartbleed")) == "queued"
    assert r.offer(ev(severity="critical", source="rule", sid=1, signature="x")) == "skipped"
    assert r.queue.qsize() == 2
    assert r.offer(ev(kind="block", severity=None, block_event="blocked")) == "skipped"


def test_a_channel_can_lower_its_threshold_and_take_rules(soc_settings):
    s = mk(slack_webhook_url="https://hooks.example.com/x", slack_min_severity="medium")
    r = runner_for(channels.SlackChannel, s)
    assert r.offer(ev(severity="medium")) == "queued"
    assert r.offer(ev(severity="low", predicted_class="PortScan")) == "skipped"
    assert r.offer(ev(severity="high", source="rule", sid=5, signature="ET X")) == "queued"


def test_the_queue_is_bounded_and_counts_drops(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_queue_size=2, notify_dedupe_seconds=0)
    r = runner_for(channels.WebhookChannel, s)
    outcomes = [r.offer(ev(src_ip=f"203.0.113.{i}")) for i in range(5)]
    assert outcomes == ["queued", "queued", "dropped", "dropped", "dropped"]
    assert r.status()["dropped"] == 3 and r.status()["queued"] == 2


# --- dedupe -----------------------------------------------------------------------------------

def test_same_class_and_source_in_a_burst_is_sent_once(soc_settings):
    clock = Clock()
    s = mk(webhook_url="https://hooks.example.com/x", notify_dedupe_seconds=300)
    r = runner_for(channels.WebhookChannel, s, clock)
    assert r.offer(ev()) == "queued"
    assert r.offer(ev(alert_id=8)) == "deduped"
    assert r.offer(ev(src_ip="203.0.113.99")) == "queued"      # another source
    assert r.offer(ev(predicted_class="DDoS")) == "queued"      # another class
    clock.t += 301
    assert r.offer(ev(alert_id=9)) == "queued"                  # window over
    assert r.status()["deduped"] == 1


def test_a_higher_severity_is_not_swallowed_by_dedupe(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", webhook_min_severity="medium")
    r = runner_for(channels.WebhookChannel, s)
    assert r.offer(ev(severity="medium")) == "queued"
    assert r.offer(ev(severity="critical")) == "queued"
    assert r.offer(ev(severity="high")) == "deduped"


def test_a_folded_rule_alert_is_a_repeat_of_the_first(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x")
    r = runner_for(channels.WebhookChannel, s)
    first = ev(source="rule", sid=2009358, signature="ET SCAN", predicted_class="Malware", count=1)
    folded = ev(source="rule", sid=2009358, signature="ET SCAN", predicted_class="Malware",
                count=40, alert_id=99)
    assert r.offer(first) == "queued" and r.offer(folded) == "deduped"
    assert r.offer(ev(source="rule", sid=1, signature="other", predicted_class="Malware")) == "queued"


def test_dedupe_can_be_switched_off(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_dedupe_seconds=0)
    r = runner_for(channels.WebhookChannel, s)
    assert r.offer(ev()) == "queued" and r.offer(ev()) == "queued"


# --- retry and backoff ------------------------------------------------------------------------

def scripted(runner, outcomes):
    """Replace the channel's send with one that follows `outcomes` (exception or None)."""
    calls, waits = [], []

    def send(item):
        calls.append(item)
        out = outcomes[min(len(calls), len(outcomes)) - 1]
        if out is not None:
            raise out

    runner.channel.send = send
    runner._stop.wait = lambda d: waits.append(d) or False
    return calls, waits


def test_transient_errors_are_retried_with_doubling_backoff(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_backoff_seconds=1.5)
    r = runner_for(channels.WebhookChannel, s)
    calls, waits = scripted(r, [DeliveryError("HTTP 503"), DeliveryError("HTTP 503"), None])
    r.process(ev())
    assert len(calls) == 3 and waits == [1.5, 3.0]
    st = r.status()
    assert st["sent"] == 1 and st["failed"] == 0 and st["last_success_at"] == NOW
    assert st["last_error"] == "HTTP 503"


def test_gives_up_after_the_attempts_and_records_the_error(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_max_attempts=3)
    r = runner_for(channels.WebhookChannel, s)
    calls, waits = scripted(r, [DeliveryError("HTTP 500")])
    r.process(ev())
    assert len(calls) == 3 and len(waits) == 2
    st = r.status()
    assert st["failed"] == 1 and st["sent"] == 0 and st["last_error"] == "HTTP 500"
    assert st["last_success_at"] is None


def test_a_permanent_error_is_not_retried(soc_settings):
    r = runner_for(channels.WebhookChannel, mk(webhook_url="https://hooks.example.com/x"))
    calls, waits = scripted(r, [DeliveryError("HTTP 404", retryable=False)])
    r.process(ev())
    assert len(calls) == 1 and waits == [] and r.status()["failed"] == 1


def test_an_unexpected_exception_is_contained(soc_settings):
    r = runner_for(channels.WebhookChannel, mk(webhook_url="https://hooks.example.com/x"))
    scripted(r, [RuntimeError("boom with https://hooks.example.com/x inside")])
    r.process(ev())
    st = r.status()
    assert st["failed"] == 1 and "hooks.example.com" not in st["last_error"]


def test_the_error_text_has_the_secret_url_scrubbed(soc_settings):
    url = "https://hooks.example.com/services/T000/B000/SECRETTOKEN"
    r = runner_for(channels.SlackChannel, mk(slack_webhook_url=url))
    scripted(r, [DeliveryError(f"odd failure for {url}", retryable=False)])
    r.process(ev())
    assert "SECRETTOKEN" not in r.status()["last_error"]


# --- rate limit and digest --------------------------------------------------------------------

def test_beyond_the_rate_limit_one_digest_says_and_k_more(soc_settings):
    clock = Clock()
    s = mk(webhook_url="https://hooks.example.com/x", notify_rate_per_minute=3,
           notify_dedupe_seconds=0)
    r = runner_for(channels.WebhookChannel, s, clock)
    sent = []
    r.channel.send = sent.append
    for i in range(10):
        r.process(ev(src_ip=f"203.0.113.{i}", severity="critical" if i % 2 else "high",
                     predicted_class="DDoS" if i % 2 else "DoS"))
        r.tick()
    assert len(sent) == 3 and all(isinstance(m, Event) for m in sent)
    assert r.status()["rate_limited"] == 7
    clock.t += 61
    r.tick()
    assert len(sent) == 4 and isinstance(sent[-1], Digest)
    d = sent[-1]
    assert d.count == 7 and d.by_severity == {"critical": 4, "high": 3}
    assert dict(d.top_classes) == {"DoS": 3, "DDoS": 4}
    r.tick()
    assert len(sent) == 4  # only one digest
    assert r.status()["sent"] == 4
    payload = formats.webhook_payload(d, None)
    assert payload["type"] == "idps.digest" and payload["more"] == 7


def test_the_digest_counts_as_failed_events_when_it_cannot_be_sent(soc_settings):
    clock = Clock()
    s = mk(webhook_url="https://hooks.example.com/x", notify_rate_per_minute=1,
           notify_dedupe_seconds=0, notify_max_attempts=1)
    r = runner_for(channels.WebhookChannel, s, clock)
    r.channel.send = lambda item: None
    for i in range(4):
        r.process(ev(src_ip=f"203.0.113.{i}"))
    scripted(r, [DeliveryError("HTTP 500")])
    clock.t += 61
    r.tick()
    assert r.status()["failed"] == 3


def test_syslog_has_no_dedupe_and_no_rate_limit_by_default(soc_settings):
    r = runner_for(channels.SyslogChannel, mk(syslog_host="127.0.0.1"))
    sent = []
    r.channel.send = sent.append
    for _ in range(100):
        assert r.offer(ev(severity="low", predicted_class="PortScan")) == "queued"
    while not r.queue.empty():
        r.process(r.queue.get())
    assert len(sent) == 100


# --- SSRF guard ---------------------------------------------------------------------------------

def fake_resolver(*addresses):
    return lambda host, port, type=0: [(2, 1, 6, "", (a, port)) for a in addresses]


@pytest.mark.parametrize("address", [
    "10.0.0.5", "192.168.1.1", "172.16.0.9", "127.0.0.1", "169.254.169.254", "0.0.0.0",
    "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"])
def test_private_loopback_and_link_local_destinations_are_refused(address):
    with pytest.raises(UnsafeDestination, match="private"):
        netguard.resolve_target("https://hooks.example.com/x", resolver=fake_resolver(address))


def test_one_private_answer_among_public_ones_refuses(soc_settings):
    with pytest.raises(UnsafeDestination):
        netguard.resolve_target("https://hooks.example.com/x",
                                resolver=fake_resolver("93.184.216.34", "10.0.0.1"))


def test_a_public_https_destination_is_accepted_and_pinned():
    t = netguard.resolve_target("https://hooks.example.com:8443/a/b?c=d",
                                resolver=fake_resolver("93.184.216.34"))
    assert (t.scheme, t.host, t.port, t.path, t.ip) == (
        "https", "hooks.example.com", 8443, "/a/b?c=d", "93.184.216.34")


@pytest.mark.parametrize("url", ["http://hooks.example.com/x", "ftp://hooks.example.com/x",
                                 "file:///etc/passwd", "https:///nohost", "//hooks.example.com",
                                 "https://user:pw@hooks.example.com/x", "https://[::1"])
def test_other_schemes_and_odd_urls_are_refused(url):
    with pytest.raises(UnsafeDestination):
        netguard.resolve_target(url, resolver=fake_resolver("93.184.216.34"))


def test_http_needs_the_explicit_dev_flag_and_private_needs_its_own():
    r = fake_resolver("127.0.0.1")
    with pytest.raises(UnsafeDestination, match="http"):
        netguard.resolve_target("http://localhost/x", allow_private=True, resolver=r)
    with pytest.raises(UnsafeDestination, match="private"):
        netguard.resolve_target("http://localhost/x", allow_http=True, resolver=r)
    t = netguard.resolve_target("http://localhost/x", allow_private=True, allow_http=True,
                                resolver=r)
    assert t.ip == "127.0.0.1"


def test_an_unresolvable_name_is_refused_without_echoing_it():
    def boom(*a, **k):
        raise socket.gaierror("nope")

    with pytest.raises(UnsafeDestination, match="resolved") as e:
        netguard.resolve_target("https://secret-host.example/TOKEN", resolver=boom)
    assert "TOKEN" not in str(e.value)


def test_a_channel_refuses_a_private_destination_and_never_connects(soc_settings, receiver):
    rec = receiver()
    r = runner_for(channels.WebhookChannel, mk(webhook_url=rec.url))  # http + loopback, no flags
    r.process(ev())
    st = r.status()
    assert st["failed"] == 1 and "refused" in st["last_error"]
    assert rec.requests == []
    assert rec.url not in st["last_error"] and "SECRET-PATH-TOKEN" not in st["last_error"]


def test_redirects_are_not_followed(soc_settings, receiver):
    target = receiver()
    redirecting = receiver(statuses=(302,), location=target.url)
    r = runner_for(channels.WebhookChannel, mk(webhook_url=redirecting.url, **LAB))
    r.process(ev())
    assert len(redirecting.requests) == 1 and target.requests == []
    st = r.status()
    assert st["failed"] == 1 and "redirect" in st["last_error"]


def test_connection_uses_the_checked_address_not_a_second_dns_answer(soc_settings, receiver):
    rec = receiver()
    url = f"http://rebind.example:{rec.port}/hook"
    answers = iter(["127.0.0.1", "10.99.99.99"])  # second lookup would be a different host
    s = mk(webhook_url=url, **LAB)
    ch = channels.WebhookChannel(s)
    ch.resolver = lambda host, port, type=0: [(2, 1, 6, "", (next(answers), port))]
    ch.send(ev())
    assert len(rec.requests) == 1 and rec.requests[0]["headers"]["Host"].startswith("rebind.example")


# --- generic webhook ----------------------------------------------------------------------------

def test_webhook_posts_small_json_with_a_valid_hmac(soc_settings, receiver):
    rec = receiver()
    secret = "s3cret-shared-with-receiver"
    s = mk(webhook_url=rec.url, webhook_secret=secret, public_url="https://soc.example.com/", **LAB)
    r = runner_for(channels.WebhookChannel, s)
    r.process(ev(source="rule", sid=2009358, signature="ET SCAN Nmap", category="Scan"))
    (req,) = rec.requests
    stamp = req["headers"]["X-IDPS-Timestamp"]
    assert abs(time.time() - int(stamp)) < 10
    expect = "sha256=" + hmac.new(secret.encode(), stamp.encode() + b"." + req["body"],
                                  hashlib.sha256).hexdigest()
    assert req["headers"]["X-IDPS-Signature"] == expect
    assert req["headers"]["Content-Type"] == "application/json"
    body = json.loads(req["body"])
    assert body == {
        "type": "idps.alert", "version": 1, "id": 7, "severity": "high", "class": "DoS",
        "source": "rule",
        "rule": {"sid": 2009358, "signature": "ET SCAN Nmap", "category": "Scan", "count": 1},
        "src": {"ip": "203.0.113.7", "port": 51514}, "dst": {"ip": "10.10.1.5", "port": 80},
        "protocol": 6, "sensor": "lab-sensor", "at": "2026-11-15T12:00:00Z",
        "url": "https://soc.example.com/alerts/7"}
    assert "explanation" not in body and "features" not in body
    assert r.status()["sent"] == 1


def test_webhook_without_a_secret_sends_no_signature(soc_settings, receiver):
    rec = receiver()
    runner_for(channels.WebhookChannel, mk(webhook_url=rec.url, **LAB)).process(ev())
    assert "X-IDPS-Signature" not in rec.requests[0]["headers"]
    assert "X-IDPS-Timestamp" not in rec.requests[0]["headers"]


def test_a_5xx_is_retried_against_a_real_receiver(soc_settings, receiver):
    rec = receiver(statuses=(503, 200))
    s = mk(webhook_url=rec.url, notify_backoff_seconds=0, **LAB)
    r = runner_for(channels.WebhookChannel, s)
    r.process(ev())
    assert len(rec.requests) == 2 and r.status()["sent"] == 1


def test_a_4xx_is_final(soc_settings, receiver):
    rec = receiver(statuses=(403,))
    r = runner_for(channels.WebhookChannel, mk(webhook_url=rec.url, notify_backoff_seconds=0, **LAB))
    r.process(ev())
    assert len(rec.requests) == 1 and r.status()["last_error"] == "HTTP 403"


def test_a_dead_destination_times_out_or_is_refused_quickly(soc_settings):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens now
    s = mk(webhook_url=f"http://127.0.0.1:{port}/x", notify_max_attempts=1, **LAB)
    r = runner_for(channels.WebhookChannel, s)
    r.process(ev())
    assert r.status()["failed"] == 1 and "connection failed" in r.status()["last_error"]


# --- Slack --------------------------------------------------------------------------------------

def test_slack_message_has_the_fields_and_a_link(soc_settings):
    p = formats.slack_payload(ev(source="rule", sid=2009358, signature="ET SCAN Nmap"),
                              "https://soc.example.com")
    assert p["blocks"][0] == {"type": "header", "text": {"type": "plain_text",
                                                           "text": "HIGH alert: ET SCAN Nmap"}}
    text = json.dumps(p)
    for needle in ("DoS", "high", "ET SCAN Nmap", "2009358", "203.0.113.7:51514",
                   "10.10.1.5:80", "lab-sensor", "https://soc.example.com/alerts/7"):
        assert needle in text
    assert p["blocks"][-1]["elements"][0]["url"] == "https://soc.example.com/alerts/7"
    assert "actions" not in json.dumps(formats.slack_payload(ev(), None))  # no link without URL


def test_slack_text_from_attackers_is_escaped():
    evil = "<!channel> <@U123> <https://evil.example|click> *bold* `code` &amp; \u202e\x00\nline"
    p = formats.slack_payload(ev(source="rule", sid=1, signature=evil, predicted_class=evil), None)
    text = json.dumps(p)
    for raw in ("<!channel>", "<@U123>", "<https://evil", chr(0x202E), "\\u202e"):
        assert raw not in text, raw
    assert "&lt;!channel&gt;" in text
    # no unescaped backtick breaks out of the code span: backticks only delimit
    for f in p["blocks"][1]["fields"]:
        body = f["text"].split("\n", 1)[1]
        if "`" not in body:
            continue  # severity and source: fixed words
        for part in body.split(" → "):
            assert part.count("`") == 2, part
    assert "<" not in p["blocks"][0]["text"]["text"].replace("&lt;", "")
    # the fallback text carries no signature, address or live markup
    assert p["text"].startswith("IDPS high alert: `") and "evil" not in p["text"].split("`")[0]
    assert "<" not in p["text"].replace("&lt;", "") and "ET" not in p["text"]


def test_slack_header_is_plain_text_and_short():
    p = formats.slack_payload(ev(source="rule", sid=1, signature="x" * 400), None)
    assert len(p["blocks"][0]["text"]["text"]) <= 150


def test_slack_channel_posts_to_the_webhook(soc_settings, receiver):
    rec = receiver()
    r = runner_for(channels.SlackChannel, mk(slack_webhook_url=rec.url, **LAB))
    r.process(ev())
    body = json.loads(rec.requests[0]["body"])
    assert body["blocks"][0]["type"] == "header" and rec.requests[0]["path"] == "/hook/SECRET-PATH-TOKEN"


# --- email --------------------------------------------------------------------------------------

@pytest.fixture
def smtp():
    s = FakeSmtp()
    yield s
    s.close()


def email_settings(smtp, **kw):
    return mk(smtp_host="127.0.0.1", smtp_port=smtp.port, smtp_security="none",
              smtp_from="idps@example.com", smtp_to="oncall@example.org, sec@example.net", **kw)


def test_email_goes_to_every_recipient_with_text_and_html(soc_settings, smtp):
    r = runner_for(channels.EmailChannel, email_settings(smtp, public_url="https://soc.example.com"))
    r.process(ev(source="rule", sid=9, signature="ET <script>alert(1)</script>"))
    (mail,) = smtp.mails
    assert "idps@example.com" in mail["from"]
    assert len(mail["to"]) == 2
    data = mail["data"].decode()
    assert "Subject: [IDPS] HIGH alert: ET <script>alert(1)</script>" in data.replace("\r\n ", " ")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in data          # HTML part is escaped
    assert "<script>alert" not in data.split("text/html")[1]
    assert "https://soc.example.com/alerts/7" in data
    assert r.status()["sent"] == 1


def test_email_header_injection_is_impossible():
    evil = "DoS\r\nBcc: attacker@evil.example\r\nX: y"
    msg = formats.build_email(ev(predicted_class=evil), "idps@example.com", ["a@b.example"], None)
    assert "\n" not in msg["Subject"] and "\r" not in msg["Subject"]
    assert msg["Bcc"] is None


def test_email_with_a_password_needs_tls(soc_settings, smtp):
    r = runner_for(channels.EmailChannel,
                   email_settings(smtp, smtp_username="u", smtp_password="hunter2hunter2"))
    r.process(ev())
    assert smtp.mails == [] and "without TLS" in r.status()["last_error"]
    assert "hunter2" not in r.status()["last_error"]


class StubSMTP:
    instances: ClassVar[list] = []

    def __init__(self, timeout=None, context=None):
        self.calls, self.host, self.context = [], None, context
        StubSMTP.instances.append(self)

    def connect(self, host, port):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.calls.append("quit")

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append(("starttls", context is not None and context.check_hostname))

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.calls.append(("send", from_addr, tuple(to_addrs)))

    def quit(self):
        self.calls.append("quit")

    def close(self):
        pass


@pytest.mark.parametrize("mode,cls", [("starttls", "SMTP"), ("ssl", "SMTP_SSL")])
def test_email_uses_starttls_or_ssl_and_logs_in(soc_settings, monkeypatch, mode, cls):
    StubSMTP.instances = []
    monkeypatch.setattr(channels.smtplib, cls, StubSMTP)
    s = mk(smtp_host="smtp.example.com", smtp_security=mode, smtp_username="user",
           smtp_password="pw-pw-pw-pw", smtp_from="idps@example.com", smtp_to="a@example.org")
    r = runner_for(channels.EmailChannel, s)
    r.process(ev())
    (c,) = StubSMTP.instances
    kinds = [x if isinstance(x, str) else x[0] for x in c.calls]
    assert ("starttls" in kinds) == (mode == "starttls")
    assert kinds.index("login") < kinds.index("send")
    if mode == "starttls":
        assert kinds.index("starttls") < kinds.index("login")
        assert ("starttls", True) in c.calls  # certificate and host name are verified
    else:
        assert c.context is not None and c.context.check_hostname
    assert ("login", "user", "pw-pw-pw-pw") in c.calls
    assert r.status()["sent"] == 1


def test_email_hint_masks_the_addresses(soc_settings):
    ch = channels.EmailChannel(mk(smtp_host="smtp.example.com", smtp_from="a@example.com",
                                  smtp_to="boss@example.org,ops@example.org"))
    assert ch.target_hint() == "smtp.example.com:587 to ***@example.org"


# --- syslog / CEF -------------------------------------------------------------------------------

def test_cef_escaping_of_backslash_pipe_equals_and_newlines():
    nasty = "a|b\\c=d\ne\rf"
    line, msgid, sev = formats.cef_message(ev(source="rule", sid=7, signature=nasty,
                                              predicted_class="Mal|ware"))
    assert msgid == "ALERT" and sev == 4
    parts = re.split(r"(?<!\\)\|", line, maxsplit=7)
    header, ext = parts[:7], parts[7]
    assert line.startswith("CEF:0|IDPS|IDPS SOC|")
    assert header[4] == "7"
    assert header[5] == "a\\|b\\\\c=d e f"            # header: \ and | escaped, newline gone
    assert "cs2=a|b\\\\c\\=d e f" in ext or "cs2=a|b\\\\c\\=d" in ext
    assert "\n" not in line and "\r" not in line
    assert "cat=Mal|ware" in ext and "cs1Label=source cs1=rule" in ext


def test_cef_extension_escaping_unit():
    assert formats.cef_ext("a=b\\c\nd\re") == "a\\=b\\\\c\\nd\\re"
    assert formats.cef_header("a|b\\c") == "a\\|b\\\\c"


def test_cef_fields_for_a_model_alert():
    line, _, sev = formats.cef_message(ev(severity="critical"))
    parts = line.split("|")
    assert parts[:3] == ["CEF:0", "IDPS", "IDPS SOC"] and parts[4] == "DoS"
    assert parts[5] == "DoS detected" and parts[6] == "10"
    for kv in ("src=203.0.113.7", "dst=10.10.1.5", "spt=51514", "dpt=80", "proto=TCP",
               "cs1Label=source cs1=ml", "dvchost=lab-sensor", "externalId=7"):
        assert kv in parts[7]
    assert "cs2" not in parts[7] and sev == 2


def test_syslog_framing_is_rfc5424_with_octet_counting_for_tcp():
    plain, counted = formats.syslog_frame(ev(), now=NOW)
    text = plain.decode()
    pri, rest = text.split(">", 1)
    assert pri == "<132" and rest.startswith("1 2026-11-15T12:00:00.000Z ")  # local0.warning
    fields = rest.split(" ", 6)
    assert fields[3] == "idps-soc" and fields[4] == "-" and fields[5] == "ALERT"
    assert fields[6].startswith("- CEF:0|IDPS|")  # structured data "-", then the CEF message
    n, body = counted.split(b" ", 1)
    assert int(n) == len(body) == len(plain)


def test_syslog_over_udp(soc_settings):
    sink = UdpSink()
    try:
        r = runner_for(channels.SyslogChannel,
                       mk(syslog_host="127.0.0.1", syslog_port=sink.port, syslog_protocol="udp"))
        assert r.offer(ev(severity="low", predicted_class="PortScan")) == "queued"
        r.process(r.queue.get())
        data = sink.recv().decode()
        assert data.startswith("<134>1 ") and "|PortScan|PortScan detected|3|" in data
        assert r.status()["sent"] == 1
    finally:
        sink.close()


def test_syslog_over_tcp_is_octet_counted_and_the_connection_is_reused(soc_settings):
    sink = TcpSink()
    try:
        r = runner_for(channels.SyslogChannel,
                       mk(syslog_host="127.0.0.1", syslog_port=sink.port, syslog_protocol="tcp"))
        r.process(ev())
        r.process(ev(kind="block", severity=None, block_event="blocked", src_ip="198.51.100.9",
                     reason="auto | burst=1"))
        assert wait_until(lambda: sink.data.count(b"CEF:0") == 2)
        data = bytes(sink.data)
        frames = []
        while data:
            n, _, data = data.partition(b" ")
            frames.append(data[: int(n)].decode())
            data = data[int(n):]
        assert len(frames) == 2
        assert "|DoS|DoS detected|8|" in frames[0] and " BLOCK - CEF:0|" in frames[1]
        assert "|blocked|IP blocked|6|" in frames[1] and "reason=auto | burst\\=1" in frames[1]
    finally:
        sink.close()


def test_syslog_tcp_reconnects_after_the_receiver_restarts(soc_settings):
    sink = TcpSink()
    port = sink.port
    r = runner_for(channels.SyslogChannel,
                   mk(syslog_host="127.0.0.1", syslog_port=port, syslog_protocol="tcp",
                      notify_backoff_seconds=0))
    r.process(ev())
    assert wait_until(lambda: len(sink.data) > 0)
    sink.close()
    r.channel._sock.close()
    sink2 = None
    for _ in range(50):
        try:
            sink2 = TcpSink(port)
            break
        except OSError:
            time.sleep(0.1)
    if sink2 is None:
        pytest.skip("port not free again")
    try:
        r.process(ev(alert_id=8))
        assert wait_until(lambda: len(sink2.data) > 0)
    finally:
        sink2.close()


def test_syslog_tls_refuses_an_untrusted_receiver(soc_settings):
    sink = TcpSink()  # speaks no TLS at all: the handshake fails
    try:
        r = runner_for(channels.SyslogChannel,
                       mk(syslog_host="127.0.0.1", syslog_port=sink.port, syslog_protocol="tls",
                          notify_max_attempts=1, notify_timeout_seconds=0.5))
        r.process(ev())
        assert r.status()["failed"] == 1 and b"CEF:0" not in sink.data
    finally:
        sink.close()


def test_syslog_forwards_block_events_but_only_when_asked(soc_settings):
    on = runner_for(channels.SyslogChannel, mk(syslog_host="127.0.0.1"))
    off = runner_for(channels.SyslogChannel, mk(syslog_host="127.0.0.1", syslog_include_blocks=False))
    block = ev(kind="block", severity=None, block_event="would_block")
    assert on.offer(block) == "queued" and off.offer(block) == "skipped"


# --- admin endpoints -----------------------------------------------------------------------------

SECRETS = {"url": "SECRET-PATH-TOKEN", "hmac": "hmac-secret-value-123", "smtp": "smtp-pass-value-123",
           "key": "abuse-key-value-123", "slack": "T000SLACKTOKEN"}


def full_config(rec, smtp):
    return dict(
        webhook_url=rec.url, webhook_secret=SECRETS["hmac"],
        slack_webhook_url=f"http://127.0.0.1:{rec.port}/services/{SECRETS['slack']}",
        smtp_host="127.0.0.1", smtp_port=smtp.port, smtp_security="none",
        smtp_from="idps@example.com", smtp_to="oncall@example.org",
        abuseipdb_key=SECRETS["key"], **LAB)


def test_integrations_requires_an_admin(make_app):
    a = make_app()
    assert a.client.get("/admin/integrations").status_code == 401
    assert a.client.get("/admin/integrations", headers=a.analyst).status_code == 403
    assert a.client.get("/admin/integrations", headers=a.sensor).status_code == 401
    for h in ({}, a.analyst, a.sensor):
        assert a.client.post("/admin/integrations/slack/test", headers=h).status_code in (401, 403)


def test_status_of_unconfigured_channels(make_app):
    a = make_app()
    body = a.client.get("/admin/integrations", headers=a.admin).json()
    assert [c["channel"] for c in body["channels"]] == ["webhook", "slack", "email", "syslog"]
    assert body["abuseipdb"] == {"configured": False, "cache_hours": 24.0}
    web = body["channels"][0]
    assert web == {
        "channel": "webhook", "configured": False, "enabled": False, "min_severity": "high",
        "include_rules": True, "target_hint": None, "last_success_at": None, "last_error": None,
        "last_error_at": None, "queued": 0, "sent": 0, "failed": 0, "dropped": 0,
        "rate_limited": 0, "deduped": 0}
    assert body["channels"][3]["min_severity"] == "low"


def test_status_hints_never_leak_secrets(make_app, receiver, smtp, caplog):
    caplog.set_level(logging.DEBUG)
    rec = receiver()
    a = make_app(**full_config(rec, smtp), slack_min_severity="medium", webhook_include_rules=False)
    r = a.client.get("/admin/integrations", headers=a.admin)
    chans = {c["channel"]: c for c in r.json()["channels"]}
    assert chans["webhook"]["target_hint"] == "127.0.0.1" and chans["webhook"]["configured"]
    assert chans["webhook"]["include_rules"] is False
    assert chans["slack"]["min_severity"] == "medium"
    assert chans["email"]["target_hint"] == f"127.0.0.1:{smtp.port} to ***@example.org"
    assert not chans["syslog"]["configured"]
    assert r.json()["abuseipdb"]["configured"] is True
    for secret in SECRETS.values():
        assert secret not in r.text
    for secret in SECRETS.values():
        assert secret not in caplog.text


def test_test_button_sends_a_labelled_message_and_audits(make_app, receiver, smtp, caplog):
    caplog.set_level(logging.DEBUG)
    rec = receiver()
    a = make_app(**full_config(rec, smtp))
    r = a.client.post("/admin/integrations/webhook/test", headers=a.admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"channel", "ok", "error", "duration_ms", "tested_at"}
    assert body["channel"] == "webhook" and body["ok"] is True and body["error"] is None
    sent = json.loads(rec.requests[0]["body"])
    assert sent["type"] == "idps.test" and sent["test"] is True and "not an alert" in sent["message"]
    stamp = rec.requests[0]["headers"]["X-IDPS-Timestamp"]
    expect = "sha256=" + hmac.new(SECRETS["hmac"].encode(),
                                  stamp.encode() + b"." + rec.requests[0]["body"],
                                  hashlib.sha256).hexdigest()
    assert rec.requests[0]["headers"]["X-IDPS-Signature"] == expect
    with a.app.state.session_factory() as db:
        row = db.scalars(select(AuditEntry).where(AuditEntry.action == "integration_test")).one()
    assert (row.actor_name, row.target, row.details) == ("admin", "integration:webhook",
                                                           {"ok": True})
    status = {c["channel"]: c for c in a.client.get("/admin/integrations", headers=a.admin).json()["channels"]}
    assert status["webhook"]["last_success_at"] is not None and status["webhook"]["last_error"] is None
    # the other channels' test messages
    assert a.client.post("/admin/integrations/slack/test", headers=a.admin).json()["ok"] is True
    slack_body = json.loads(rec.requests[1]["body"])
    assert "test message" in json.dumps(slack_body)
    assert a.client.post("/admin/integrations/email/test", headers=a.admin).json()["ok"] is True
    assert b"Subject: [IDPS] Test message" in smtp.mails[0]["data"]
    for secret in SECRETS.values():
        assert secret not in caplog.text


def test_test_button_reports_a_failure_without_secrets(make_app, receiver):
    rec = receiver(statuses=(500,))
    a = make_app(webhook_url=rec.url, notify_backoff_seconds=0, **LAB)
    r = a.client.post("/admin/integrations/webhook/test", headers=a.admin)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["error"] == "HTTP 500"
    assert "SECRET-PATH-TOKEN" not in r.text
    with a.app.state.session_factory() as db:
        row = db.scalars(select(AuditEntry).where(AuditEntry.action == "integration_test")).one()
    assert row.details == {"ok": False, "error": "HTTP 500"}
    st = a.client.get("/admin/integrations", headers=a.admin).json()["channels"][0]
    assert st["last_error"] == "HTTP 500" and st["last_error_at"] is not None


def test_test_button_for_an_unconfigured_channel_is_409(make_app):
    a = make_app()
    assert a.client.post("/admin/integrations/slack/test", headers=a.admin).status_code == 409
    assert a.client.post("/admin/integrations/bogus/test", headers=a.admin).status_code == 422


def test_test_button_is_rate_limited(make_app, receiver):
    rec = receiver()
    a = make_app(webhook_url=rec.url, **LAB)
    codes = [a.client.post("/admin/integrations/webhook/test", headers=a.admin).status_code
             for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert len(rec.requests) == 3


def test_test_button_for_syslog(make_app):
    sink = UdpSink()
    try:
        a = make_app(syslog_host="127.0.0.1", syslog_port=sink.port)
        r = a.client.post("/admin/integrations/syslog/test", headers=a.admin)
        assert r.json()["ok"] is True
        assert "|test|IDPS test message|0|" in sink.recv().decode()
    finally:
        sink.close()


def test_test_button_respects_the_kill_switch(make_app, receiver):
    a = make_app(webhook_url=receiver().url, notify_enabled=False, **LAB)
    c = a.client.get("/admin/integrations", headers=a.admin).json()["channels"][0]
    assert c["configured"] is True and c["enabled"] is False
    assert a.client.post("/admin/integrations/webhook/test", headers=a.admin).status_code == 409


# --- end to end through ingest ---------------------------------------------------------------------

def test_a_high_alert_reaches_the_receiver_and_a_low_one_does_not(make_app, receiver):
    rec = receiver()
    a = make_app(webhook_url=rec.url, public_url="https://soc.example.com", **LAB)
    ids = ingest(a.client, a.sensor, alert_payload(predicted_class="PortScan"),
                 alert_payload(predicted_class="Heartbleed", src_ip="198.51.100.4"))
    assert wait_until(lambda: len(rec.requests) == 1)
    time.sleep(0.2)
    assert len(rec.requests) == 1
    body = json.loads(rec.requests[0]["body"])
    assert body["id"] == ids[1] and body["severity"] == "critical" and body["class"] == "Heartbleed"
    assert body["url"] == f"https://soc.example.com/alerts/{ids[1]}" and body["sensor"] == "lab-sensor"


def test_rule_alerts_and_their_folded_follow_up(make_app, receiver):
    rec = receiver()
    a = make_app(webhook_url=rec.url, **LAB)
    first = rule_payload(predicted_class="Malware")
    folded = rule_payload(predicted_class="Malware") | {"rule": rule_payload()["rule"] | {"count": 30}}
    ingest(a.client, a.sensor, first)
    ingest(a.client, a.sensor, folded)
    assert wait_until(lambda: len(rec.requests) >= 1)
    time.sleep(0.2)
    assert len(rec.requests) == 1
    assert json.loads(rec.requests[0]["body"])["source"] == "rule"
    st = a.client.get("/admin/integrations", headers=a.admin).json()["channels"][0]
    assert st["sent"] == 1 and st["deduped"] == 1


def test_include_rules_false_leaves_rule_alerts_out(make_app, receiver):
    rec = receiver()
    a = make_app(webhook_url=rec.url, webhook_include_rules=False, **LAB)
    ingest(a.client, a.sensor, rule_payload(predicted_class="Malware"))
    time.sleep(0.3)
    assert rec.requests == []


def test_ingest_is_not_slowed_by_a_dead_or_slow_channel(make_app):
    hang = socket.socket()
    hang.bind(("127.0.0.1", 0))
    hang.listen(1)  # accepts connections (kernel backlog) but never answers
    try:
        a = make_app(webhook_url=f"http://127.0.0.1:{hang.getsockname()[1]}/x",
                     notify_timeout_seconds=3, notify_max_attempts=3, notify_backoff_seconds=5,
                     **LAB)
        started = time.monotonic()
        for i in range(5):
            ingest(a.client, a.sensor, alert_payload(predicted_class="DoS", src_ip=f"203.0.113.{i}"))
        assert time.monotonic() - started < 2.0
    finally:
        a.app.state.notifier.close()
        hang.close()


def test_ingest_survives_a_broken_notifier(make_app, monkeypatch, caplog):
    a = make_app(webhook_url="https://hooks.example.com/x")

    def boom(*args):
        raise RuntimeError("notifier exploded")

    monkeypatch.setattr(a.app.state.notifier, "submit_alerts", boom)
    monkeypatch.setattr(a.app.state.notifier, "submit_blocks", boom)
    ids = ingest(a.client, a.sensor, alert_payload(predicted_class="DoS"))
    assert len(ids) == 1
    r = a.client.post("/ingest/blocks", headers=a.sensor, json={"events": [
        {"event": "blocked", "ip": "203.0.113.7", "ttl_seconds": 60}]})
    assert r.status_code == 201
    assert "could not queue" in caplog.text


def test_a_failing_channel_does_not_break_ingest_and_is_reported(make_app, receiver):
    rec = receiver(statuses=(500,))
    a = make_app(webhook_url=rec.url, notify_backoff_seconds=0, notify_max_attempts=2, **LAB)
    ingest(a.client, a.sensor, alert_payload(predicted_class="DoS"))
    assert wait_until(lambda: a.client.get("/admin/integrations", headers=a.admin)
                      .json()["channels"][0]["failed"] == 1)
    st = a.client.get("/admin/integrations", headers=a.admin).json()["channels"][0]
    assert st["last_error"] == "HTTP 500" and st["sent"] == 0
    assert a.client.get("/alerts", headers=a.analyst).json()["items"]  # the alert is stored


def test_a_full_queue_drops_instead_of_blocking(make_app, receiver):
    rec = receiver()
    a = make_app(webhook_url=rec.url, notify_queue_size=1, notify_dedupe_seconds=0, **LAB)
    runner = a.app.state.notifier.runners["webhook"]
    runner._start_thread = False  # nobody drains the queue
    for i in range(4):
        ingest(a.client, a.sensor, alert_payload(predicted_class="DoS", src_ip=f"203.0.113.{i}"))
    st = a.client.get("/admin/integrations", headers=a.admin).json()["channels"][0]
    assert st["queued"] == 1 and st["dropped"] == 3


def test_syslog_gets_alerts_and_blocks_from_ingest(make_app):
    sink = UdpSink()
    try:
        a = make_app(syslog_host="127.0.0.1", syslog_port=sink.port)
        ingest(a.client, a.sensor, alert_payload(predicted_class="PortScan"))
        assert "|PortScan|PortScan detected|3|" in sink.recv().decode()
        r = a.client.post("/ingest/blocks", headers=a.sensor, json={"events": [
            {"event": "blocked", "ip": "203.0.113.7", "ttl_seconds": 60, "reason": "burst"}]})
        assert r.status_code == 201
        msg = sink.recv().decode()
        assert " BLOCK - CEF:0|IDPS|" in msg and "src=203.0.113.7" in msg and "act=blocked" in msg
    finally:
        sink.close()


def test_slack_gets_the_rule_alert_with_its_signature(make_app, receiver):
    rec = receiver()
    a = make_app(slack_webhook_url=rec.url, **LAB)
    ingest(a.client, a.sensor, rule_payload(predicted_class="Malware"))
    assert wait_until(lambda: len(rec.requests) == 1)
    text = rec.requests[0]["body"].decode()
    assert "ET SCAN Nmap Scripting Engine User-Agent Detected" in text and "2009358" in text


# --- reputation ----------------------------------------------------------------------------------

ABUSE = {"ipAddress": "45.33.32.156", "abuseConfidenceScore": 87, "totalReports": 42,
         "countryCode": "NL", "isp": "Example Hosting BV", "usageType": "Data Center/Web Hosting/Transit",
         "lastReportedAt": "2026-11-14T10:00:00+00:00", "domain": "ignored.example"}


@pytest.fixture
def rep(make_app):
    calls = []

    def fetch(ip, key, timeout):
        calls.append((ip, key, timeout))
        return dict(ABUSE)

    a = make_app(abuseipdb_key=SECRETS["key"])
    a.app.state.reputation._fetch = fetch
    a.calls = calls
    (a.alert,) = ingest(a.client, a.sensor, alert_payload(src_ip="45.33.32.156"))
    return a


def test_reputation_shape_and_caching(rep):
    r = rep.client.get(f"/alerts/{rep.alert}/reputation", headers=rep.analyst)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"ip", "available", "reason", "abuse_confidence", "total_reports",
                         "country", "isp", "usage_type", "last_reported_at", "checked_at", "cached"}
    assert body | {"checked_at": None} == {
        "ip": "45.33.32.156", "available": True, "reason": None, "abuse_confidence": 87,
        "total_reports": 42, "country": "NL", "isp": "Example Hosting BV",
        "usage_type": "Data Center/Web Hosting/Transit",
        "last_reported_at": "2026-11-14T10:00:00+00:00", "checked_at": None, "cached": False}
    assert body["checked_at"].endswith("Z")
    again = rep.client.get(f"/alerts/{rep.alert}/reputation", headers=rep.analyst).json()
    assert again["cached"] is True and again["checked_at"] == body["checked_at"]
    assert again["abuse_confidence"] == 87
    assert len(rep.calls) == 1                      # quota saved
    assert rep.calls[0][0] == "45.33.32.156"         # the IP, nothing else, goes out
    assert SECRETS["key"] not in r.text


def test_reputation_cache_expires(soc_settings):
    clock = Clock()
    calls = []
    svc = ReputationService(mk(abuseipdb_key="k" * 20, abuseipdb_cache_hours=24),
                            lambda ip, key, t: calls.append(ip) or dict(ABUSE), clock=clock)
    svc.lookup("45.33.32.156")
    clock.t += 23 * 3600
    assert svc.lookup("45.33.32.156")["cached"] is True
    clock.t += 2 * 3600
    assert svc.lookup("45.33.32.156")["cached"] is False
    assert len(calls) == 2


def test_reputation_for_a_private_address_sends_nothing(make_app):
    calls = []
    a = make_app(abuseipdb_key=SECRETS["key"])
    a.app.state.reputation._fetch = lambda *x: calls.append(x)
    (aid,) = ingest(a.client, a.sensor, alert_payload(src_ip="10.10.1.10"))
    body = a.client.get(f"/alerts/{aid}/reputation", headers=a.analyst).json()
    assert body["available"] is False and body["reason"] == "private address"
    assert body["abuse_confidence"] is None and body["ip"] == "10.10.1.10"
    assert calls == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.1.1", "192.168.0.9", "172.20.0.1",
                                "100.64.0.1", "::1", "fd00::1"])
def test_reputation_never_looks_up_reserved_addresses(soc_settings, ip):
    svc = ReputationService(mk(abuseipdb_key="k" * 20), lambda *a: pytest.fail("sent"))
    assert svc.lookup(ip)["reason"] == "private address"


def test_reputation_without_a_key(make_app):
    a = make_app()
    (aid,) = ingest(a.client, a.sensor, alert_payload(src_ip="45.33.32.156"))
    body = a.client.get(f"/alerts/{aid}/reputation", headers=a.analyst).json()
    assert body["available"] is False and body["reason"] == "not configured"


def test_reputation_errors_are_reported_not_raised_and_not_cached(rep):
    outcomes = [DeliveryError("AbuseIPDB quota or rate limit reached"), RuntimeError("x" * 5)]

    def flaky(ip, key, timeout):
        rep.calls.append(ip)
        if outcomes:
            raise outcomes.pop(0)
        return dict(ABUSE)

    rep.app.state.reputation._fetch = flaky
    url = f"/alerts/{rep.alert}/reputation"
    b1 = rep.client.get(url, headers=rep.analyst)
    assert b1.status_code == 200 and b1.json()["available"] is False
    assert b1.json()["reason"] == "lookup failed: AbuseIPDB quota or rate limit reached"
    b2 = rep.client.get(url, headers=rep.analyst).json()
    assert b2["available"] is False and b2["reason"] == "lookup failed (RuntimeError)"
    b3 = rep.client.get(url, headers=rep.analyst).json()
    assert b3["available"] is True and b3["cached"] is False   # recovered; errors were not cached
    assert SECRETS["key"] not in b1.text


def test_reputation_has_a_lookup_budget(soc_settings):
    svc = ReputationService(mk(abuseipdb_key="k" * 20, abuseipdb_max_per_minute=2),
                            lambda ip, key, t: dict(ABUSE), clock=Clock())
    assert svc.lookup("45.33.32.151")["available"] and svc.lookup("45.33.32.152")["available"]
    third = svc.lookup("45.33.32.153")
    assert third["available"] is False and "too many" in third["reason"]
    assert svc.lookup("45.33.32.151")["cached"] is True  # the cache still answers


def test_reputation_endpoint_authz_and_404(rep):
    url = f"/alerts/{rep.alert}/reputation"
    assert rep.client.get(url).status_code == 401
    assert rep.client.get(url, headers=rep.sensor).status_code == 401
    assert rep.client.get(url, headers=rep.admin).status_code == 200
    assert rep.client.get("/alerts/99999/reputation", headers=rep.analyst).status_code == 404
    assert len(rep.calls) == 1


def test_reputation_is_not_looked_up_by_ingest_or_listing(rep):
    rep.calls.clear()
    ingest(rep.client, rep.sensor, alert_payload(src_ip="45.33.32.157"))
    rep.client.get("/alerts", headers=rep.analyst)
    rep.client.get(f"/alerts/{rep.alert}", headers=rep.analyst)
    assert rep.calls == []


def test_the_real_fetch_sends_only_the_ip_and_key(monkeypatch):
    from soc.api.integrations import reputation as mod

    seen = {}

    class Conn:
        def __init__(self, host, timeout=None, context=None):
            seen["host"] = host

        def request(self, method, path, headers=None):
            seen.update(method=method, path=path, headers=headers)

        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda n: json.dumps({"data": ABUSE}).encode())

        def close(self):
            pass

    monkeypatch.setattr(mod.http.client, "HTTPSConnection", Conn)
    data = mod.abuseipdb_fetch("45.33.32.156", "KEY123", 5)
    assert data["abuseConfidenceScore"] == 87
    assert seen["host"] == "api.abuseipdb.com" and seen["method"] == "GET"
    assert seen["path"] == "/api/v2/check?ipAddress=45.33.32.156&maxAgeInDays=90"
    assert set(seen["headers"]) == {"Key", "Accept", "User-Agent"}


@pytest.mark.parametrize("status,text", [(429, "quota"), (401, "refused the API key"),
                                         (500, "HTTP 500")])
def test_the_real_fetch_maps_errors(monkeypatch, status, text):
    from soc.api.integrations import reputation as mod

    class Conn:
        def __init__(self, *a, **k): ...
        def request(self, *a, **k): ...
        def getresponse(self):
            return SimpleNamespace(status=status, read=lambda n: b"{}")
        def close(self): ...

    monkeypatch.setattr(mod.http.client, "HTTPSConnection", Conn)
    with pytest.raises(DeliveryError, match=text) as e:
        mod.abuseipdb_fetch("45.33.32.156", "KEY123", 5)
    assert "KEY123" not in str(e.value)


# --- audit never holds secrets -------------------------------------------------------------------

def test_no_secret_ends_up_in_the_audit_log(make_app, receiver, smtp):
    rec = receiver()
    a = make_app(**full_config(rec, smtp))
    for name in ("webhook", "slack", "email"):
        a.client.post(f"/admin/integrations/{name}/test", headers=a.admin)
    with a.app.state.session_factory() as db:
        dump = json.dumps([(r.action, r.target, r.details) for r in db.scalars(select(AuditEntry))])
    for secret in SECRETS.values():
        assert secret not in dump
    audit = a.client.get("/admin/audit", headers=a.admin).text
    for secret in SECRETS.values():
        assert secret not in audit


def test_the_notification_manager_closes_cleanly(make_app, receiver):
    rec = receiver()
    a = make_app(webhook_url=rec.url, **LAB)
    ingest(a.client, a.sensor, alert_payload(predicted_class="DoS"))
    assert wait_until(lambda: len(rec.requests) == 1)
    a.app.state.notifier.close()
    t = a.app.state.notifier.runners["webhook"]._thread
    assert t is not None and not t.is_alive()


def test_testnotice_and_digest_render_in_every_format():
    for item in (TestNotice(NOW), Digest(3, {"high": 3}, [("DoS", 3)])):
        formats.webhook_payload(item, None)
        formats.slack_payload(item, None)
        formats.build_email(item, "a@b.example", ["c@d.example"], None)
        line, msgid, _ = formats.cef_message(item)
        assert line.startswith("CEF:0|IDPS|") and msgid in ("TEST", "DIGEST")


# =====================================================================================================
# Review fixes
# =====================================================================================================

# --- M1: addresses that carry an IPv4 address, and odd spellings ------------------------------------

@pytest.mark.parametrize("address,public", [
    ("8.8.8.8", True), ("45.33.32.156", True), ("2606:4700::1111", True),
    ("2001:4860:4860::8888", True),
    ("198.18.0.1", False), ("192.0.0.1", False), ("255.255.255.255", False), ("0.1.2.3", False),
    ("192.88.99.1", False), ("240.0.0.1", False), ("198.51.100.7", False),
    # NAT64 (64:ff9b::/96): the IPv4 address inside decides
    ("64:ff9b::8.8.8.8", True), ("64:ff9b::10.0.0.1", False), ("64:ff9b::7f00:1", False),
    ("64:ff9b::a9fe:a9fe", False),
    ("64:ff9b:1::1", False), ("64:ff9b:1:ffff::1", False),          # local-use NAT64
    # 6to4 (2002::/16)
    ("2002:0808:0808::1", True), ("2002:0a00:0001::1", False), ("2002:7f00:0001::", False),
    ("2002:c0a8:0101::1", False), ("2002:a9fe:a9fe::1", False),
    # Teredo (2001::/32): server and client
    ("2001:0:808:808:0:0:fefd:fcfb", True), ("2001:0:a00:1:0:0:fefd:fcfb", False),
    ("2001:0:808:808:0:0:f5ff:fffe", False),
    # IPv4-compatible and mapped
    ("::10.0.0.1", False), ("::8.8.8.8", True), ("::", False), ("::1", False),
    ("::ffff:8.8.8.8", True), ("::ffff:10.0.0.1", False), ("::ffff:127.0.0.1", False),
    # non-global ranges, listed explicitly
    ("fec0::1", False), ("fe80::1", False), ("fc00::1", False), ("fd12::1", False),
    ("ff02::1", False), ("2001:db8::1", False), ("100::1", False), ("3fff::1", False),
    ("2001:10::1", False), ("5f00::1", False),
])
def test_is_public_decodes_embedded_ipv4_and_lists_non_global_ranges(address, public):
    assert netguard.is_public(address) is public


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0x7f.1",
                                  "017700000001", "localhost", "[::1]", "[::ffff:127.0.0.1]",
                                  "[64:ff9b::7f00:1]", "[2002:7f00:1::]"])
def test_odd_spellings_of_loopback_go_through_the_real_resolver_and_are_refused(host):
    # The real socket.getaddrinfo decides what these mean (libc differs: "0177.0.0.1" is
    # 127.0.0.1 on glibc but 177.0.0.1 on macOS). Either it is refused, or the address we will
    # connect to is public: the guard judges the resolved address, never the spelling.
    try:
        target = netguard.resolve_target(f"https://{host}/hook")
    except UnsafeDestination:
        return
    assert netguard.is_public(target.ip), (host, target.ip)


def test_reputation_uses_the_same_decoding(soc_settings):
    svc = ReputationService(mk(abuseipdb_key="k" * 20), lambda *a: pytest.fail("sent"))
    for ip in ("64:ff9b::10.0.0.1", "2002:0a00:0001::1", "fec0::1", "::ffff:10.0.0.1"):
        assert svc.lookup(ip)["reason"] == "private address"


# --- M2: one deadline for the whole exchange --------------------------------------------------------

class Dribble:
    """Accepts connections and sends one byte every 0.15 s, for ever (never a full answer)."""

    def __init__(self, greeting=b""):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.greeting, self.stop = greeting, False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._drip, args=(conn,), daemon=True).start()

    def _drip(self, conn):
        try:
            data = self.greeting or b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 400
            for byte in data:
                if self.stop:
                    return
                conn.sendall(bytes([byte]))
                time.sleep(0.15)
            while not self.stop:
                conn.sendall(b"a")
                time.sleep(0.15)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop = True
        self.srv.close()


def test_a_server_dribbling_bytes_cannot_hold_an_http_send_past_the_deadline(soc_settings):
    slow = Dribble()
    try:
        s = mk(webhook_url=f"http://127.0.0.1:{slow.port}/x", notify_timeout_seconds=0.8,
               notify_max_attempts=1, **LAB)
        ch = channels.WebhookChannel(s)
        started = time.monotonic()
        with pytest.raises(DeliveryError, match="timed out"):
            ch.send(ev())
        assert time.monotonic() - started < 2.5
    finally:
        slow.close()


def test_a_huge_answer_is_read_only_up_to_the_cap(soc_settings):
    big = socket.socket()
    big.bind(("127.0.0.1", 0))
    big.listen(1)

    def serve():
        conn, _ = big.accept()
        conn.recv(65535)
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 50000000\r\n\r\n" + b"x" * 200_000)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    s = mk(webhook_url=f"http://127.0.0.1:{big.getsockname()[1]}/x", **LAB)
    started = time.monotonic()
    channels.WebhookChannel(s).send(ev())  # status 200: success, without reading 50 MB
    assert time.monotonic() - started < 3
    big.close()


def test_a_dribbling_smtp_server_is_cut_off_at_the_deadline(soc_settings):
    slow = Dribble(greeting=b"220 " + b"x" * 400 + b"\r\n")
    try:
        s = mk(smtp_host="127.0.0.1", smtp_port=slow.port, smtp_security="none",
               smtp_from="a@example.com", smtp_to="b@example.org", notify_timeout_seconds=0.8)
        started = time.monotonic()
        with pytest.raises(DeliveryError, match="timed out"):
            channels.EmailChannel(s).send(ev())
        assert time.monotonic() - started < 2.5
    finally:
        slow.close()


def test_the_reputation_fetch_has_a_whole_exchange_deadline(monkeypatch):
    from soc.api.integrations import reputation as mod

    slow = Dribble()
    try:
        class Plain(mod.http.client.HTTPConnection):
            def __init__(self, host, timeout=None, context=None):
                super().__init__("127.0.0.1", slow.port, timeout=timeout)

        monkeypatch.setattr(mod.http.client, "HTTPSConnection", Plain)
        started = time.monotonic()
        with pytest.raises(DeliveryError, match="timed out"):
            mod.abuseipdb_fetch("45.33.32.156", "KEY", 0.8)
        assert time.monotonic() - started < 2.5
    finally:
        slow.close()


# --- M3: a syslog TCP link the peer has closed ------------------------------------------------------

class ClosingServer:
    """Plain TCP receiver: records frames per connection; `close_after` frames, it hangs up."""

    def __init__(self, port=0, close_after=None):
        self.conns, self.frames, self.close_after = 0, [], close_after
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.conns += 1
            threading.Thread(target=self._read, args=(conn,), daemon=True).start()

    def _read(self, conn):
        got = 0
        while data := conn.recv(65535):
            self.frames.append(data)
            got += 1
            if self.close_after and got >= self.close_after:
                break
        conn.close()

    def count(self):
        return sum(f.count(b"CEF:0") for f in self.frames)

    def close(self):
        self.srv.close()


def test_a_syslog_link_closed_by_the_peer_is_replaced_before_the_next_send(soc_settings):
    srv = ClosingServer(close_after=1)  # hangs up after every first frame
    try:
        ch = channels.SyslogChannel(mk(syslog_host="127.0.0.1", syslog_port=srv.port,
                                       syslog_protocol="tcp"))
        for i in range(4):
            ch.send(ev(alert_id=i))
            time.sleep(0.3)  # the FIN arrives
        assert wait_until(lambda: srv.count() == 4)  # none went into a dead socket
        assert srv.conns == 4
    finally:
        srv.close()


def test_an_idle_syslog_link_is_reopened(soc_settings):
    srv = ClosingServer()
    try:
        ch = channels.SyslogChannel(mk(syslog_host="127.0.0.1", syslog_port=srv.port,
                                       syslog_protocol="tcp", syslog_idle_seconds=0.2))
        ch.send(ev())
        ch.send(ev())
        assert srv.conns == 1                      # busy link is reused
        time.sleep(0.4)
        ch.send(ev())
        assert wait_until(lambda: srv.count() == 3) and srv.conns == 2
    finally:
        srv.close()


def test_closing_syslog_does_not_wait_for_a_send_that_holds_the_lock(soc_settings):
    ch = channels.SyslogChannel(mk(syslog_host="127.0.0.1", syslog_protocol="tcp"))
    ch._lock.acquire()
    try:
        started = time.monotonic()
        ch.close()
        assert time.monotonic() - started < 2
    finally:
        ch._lock.release()


def test_syslog_udp_uses_the_address_family_of_the_host(soc_settings):
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind(("::1", 0))
    except OSError:
        pytest.skip("no IPv6 loopback")
    sock.settimeout(5)
    try:
        ch = channels.SyslogChannel(mk(syslog_host="::1", syslog_port=sock.getsockname()[1]))
        ch.send(ev())
        assert b"CEF:0|IDPS" in sock.recvfrom(65535)[0]
    finally:
        sock.close()


# --- M4: dedupe marks only what was queued and delivered ---------------------------------------------

def test_a_dropped_event_does_not_suppress_the_next_one(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_queue_size=1, notify_dedupe_seconds=300)
    r = runner_for(channels.WebhookChannel, s)
    assert r.offer(ev(src_ip="203.0.113.1")) == "queued"
    assert r.offer(ev(src_ip="203.0.113.2")) == "dropped"          # queue is full
    r.queue.get_nowait()                                            # the worker drained it
    assert r.offer(ev(src_ip="203.0.113.2")) == "queued"            # not wrongly "seen"


def test_a_failed_delivery_does_not_suppress_the_next_one(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_dedupe_seconds=300)
    r = runner_for(channels.WebhookChannel, s)
    scripted(r, [DeliveryError("HTTP 500")])
    assert r.offer(ev()) == "queued"
    r.process(r.queue.get_nowait())
    assert r.status()["failed"] == 1
    assert r.offer(ev()) == "queued"                                # retried from scratch
    r.channel.send = lambda item: None
    r.process(r.queue.get_nowait())
    assert r.offer(ev()) == "deduped"                               # delivered: now it is a repeat


# --- Low 1: shutdown -------------------------------------------------------------------------------

def test_close_counts_unsent_items_as_dropped_and_shares_one_deadline(soc_settings):
    s = mk(webhook_url="https://hooks.example.com/x", notify_dedupe_seconds=0,
           slack_webhook_url="https://hooks.example.com/y", notify_rate_per_minute=1)
    m = NotificationManager(s, start_threads=False)
    for i in range(3):
        m.runners["webhook"].offer(ev(src_ip=f"203.0.113.{i}"))
    slack = m.runners["slack"]
    slack.channel.send = lambda item: None
    slack.offer(ev(src_ip="203.0.113.1"))
    slack.offer(ev(src_ip="203.0.113.2"))
    slack.process(slack.queue.get_nowait())
    slack.process(slack.queue.get_nowait())      # held for a digest
    started = time.monotonic()
    m.close(timeout=1.0)
    assert time.monotonic() - started < 2
    assert m.runners["webhook"].status()["dropped"] == 3
    assert slack.status()["dropped"] == 1 and slack.status()["queued"] == 0


# --- Low 2: held block events in a digest -----------------------------------------------------------

def test_held_block_events_are_counted_separately_in_the_digest(soc_settings):
    clock = Clock()
    s = mk(syslog_host="127.0.0.1", syslog_rate_per_minute=1)
    r = runner_for(channels.SyslogChannel, s, clock)
    sent = []
    r.channel.send = sent.append
    r.process(ev())
    r.process(ev(kind="block", severity=None, predicted_class="", block_event="blocked"))
    r.process(ev(kind="block", severity=None, predicted_class="", block_event="blocked"))
    r.process(ev(severity="critical", predicted_class="DDoS", src_ip="203.0.113.9"))
    clock.t += 61
    r.tick()
    d = sent[-1]
    assert isinstance(d, Digest)
    assert (d.count, d.blocks, d.by_severity, d.top_classes) == (3, 2, {"critical": 1}, [("DDoS", 1)])
    assert "low" not in d.by_severity and ("", 2) not in d.top_classes
    line, _, _ = formats.cef_message(d)
    assert "cnt=3" in line and "cn1=2" in line


# --- Low 3: SMTP ---------------------------------------------------------------------------------------

def test_starttls_not_offered_is_a_permanent_failure_with_no_plaintext_fallback(soc_settings, smtp):
    s = mk(smtp_host="127.0.0.1", smtp_port=smtp.port, smtp_security="starttls",
           smtp_from="idps@example.com", smtp_to="oncall@example.org")  # the fake never offers it
    r = runner_for(channels.EmailChannel, s)
    r.process(ev())
    st = r.status()
    assert smtp.mails == []
    assert st["failed"] == 1 and "STARTTLS" in st["last_error"] and st["sent"] == 0


def test_the_ssl_default_port_is_465_unless_set(soc_settings):
    assert mk(smtp_security="ssl").smtp_port_effective == 465
    assert mk(smtp_security="starttls").smtp_port_effective == 587
    assert mk(smtp_security="none").smtp_port_effective == 587
    assert mk(smtp_security="ssl", smtp_port=2465).smtp_port_effective == 2465
    ch = channels.EmailChannel(mk(smtp_host="smtp.example.com", smtp_security="ssl",
                                  smtp_from="a@example.com", smtp_to="b@example.org"))
    assert ch.target_hint() == "smtp.example.com:465 to ***@example.org"


# --- Low 6: the signed timestamp ---------------------------------------------------------------------------

def test_the_signature_covers_the_timestamp(soc_settings, receiver):
    rec = receiver()
    secret = "shared-secret-123456"
    channels.WebhookChannel(mk(webhook_url=rec.url, webhook_secret=secret, **LAB)).send(ev())
    h, body = rec.requests[0]["headers"], rec.requests[0]["body"]
    key = secret.encode()
    sig = h["X-IDPS-Signature"]
    good = "sha256=" + hmac.new(key, h["X-IDPS-Timestamp"].encode() + b"." + body,
                                hashlib.sha256).hexdigest()
    assert sig == good
    # a signature over the body alone (the old scheme), or with another timestamp, does not match
    assert sig != "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
    assert sig != "sha256=" + hmac.new(key, b"1." + body, hashlib.sha256).hexdigest()


# --- Low 7: reputation audit, daily cap, LRU, coalescing --------------------------------------------------

def test_only_real_third_party_lookups_are_audited(rep):
    url = f"/alerts/{rep.alert}/reputation"
    rep.client.get(url, headers=rep.analyst)           # real lookup
    rep.client.get(url, headers=rep.analyst)           # cache hit
    rep.client.get(url, headers=rep.admin)             # cache hit
    (private,) = ingest(rep.client, rep.sensor, alert_payload(src_ip="10.10.1.10"))
    rep.client.get(f"/alerts/{private}/reputation", headers=rep.analyst)  # never sent
    with rep.app.state.session_factory() as db:
        rows = list(db.scalars(select(AuditEntry).where(AuditEntry.action == "reputation_lookup")))
    assert len(rows) == 1 and len(rep.calls) == 1
    assert (rows[0].actor_name, rows[0].target) == ("analyst", f"alert:{rep.alert}")
    assert rows[0].details == {"ip": "45.33.32.156", "available": True}
    assert SECRETS["key"] not in json.dumps(rows[0].details)


def test_a_failed_lookup_is_audited_too(rep):
    def boom(ip, key, timeout):
        raise DeliveryError("timed out")

    rep.app.state.reputation._fetch = boom
    rep.client.get(f"/alerts/{rep.alert}/reputation", headers=rep.analyst)
    with rep.app.state.session_factory() as db:
        row = db.scalars(select(AuditEntry).where(AuditEntry.action == "reputation_lookup")).one()
    assert row.details == {"ip": "45.33.32.156", "available": False}


def test_reputation_has_a_daily_budget(soc_settings):
    clock = Clock()
    svc = ReputationService(mk(abuseipdb_key="k" * 20, abuseipdb_max_per_minute=100,
                               abuseipdb_max_per_day=3), lambda ip, key, t: dict(ABUSE), clock=clock)
    for i in range(3):
        assert svc.lookup(f"45.33.32.{150 + i}")["available"]
        clock.t += 120
    over = svc.lookup("45.33.32.200")
    assert over["available"] is False and over["reason"] == "daily lookup limit reached"
    clock.t += 86400
    assert svc.lookup("45.33.32.200")["available"] is True


def test_the_reputation_cache_is_a_real_lru(soc_settings, monkeypatch):
    from soc.api.integrations import reputation as mod

    monkeypatch.setattr(mod, "MAX_CACHE", 2)
    calls = []
    svc = ReputationService(mk(abuseipdb_key="k" * 20, abuseipdb_max_per_minute=100),
                            lambda ip, key, t: calls.append(ip) or dict(ABUSE), clock=Clock())
    svc.lookup("45.33.32.1")
    svc.lookup("45.33.32.2")
    assert svc.lookup("45.33.32.1")["cached"] is True      # touch .1: .2 is now the oldest
    svc.lookup("45.33.32.3")                                # evicts .2, not .1
    assert svc.lookup("45.33.32.1")["cached"] is True
    assert svc.lookup("45.33.32.2")["cached"] is False
    assert calls == ["45.33.32.1", "45.33.32.2", "45.33.32.3", "45.33.32.2"]


def test_concurrent_lookups_of_one_address_make_one_request(soc_settings):
    gate, calls = threading.Event(), []

    def slow(ip, key, timeout):
        calls.append(ip)
        gate.wait(5)
        return dict(ABUSE)

    svc = ReputationService(mk(abuseipdb_key="k" * 20), slow)
    results = []
    threads = [threading.Thread(target=lambda: results.append(svc.lookup_ex("45.33.32.156")))
               for _ in range(4)]
    for t in threads:
        t.start()
    assert wait_until(lambda: len(calls) >= 1)
    time.sleep(0.2)
    gate.set()
    for t in threads:
        t.join(5)
    assert len(calls) == 1 and len(results) == 4
    assert sum(sent for _, sent in results) == 1             # one real lookup, three shared
    assert all(r["abuse_confidence"] == 87 for r, _ in results)


# --- Low 8: validation errors do not echo values ----------------------------------------------------------

def test_validation_errors_never_echo_addresses_urls_or_secrets(soc_settings):
    with pytest.raises(ValueError) as e:
        mk(smtp_to="boss@private-company.example, bad address", smtp_from="nope-secret-sender",
           webhook_url="https://hooks.example.com/SECRETTOKEN", notify_min_severity="urgent-ish")
    text = str(e.value)
    for leaked in ("boss@private-company", "nope-secret-sender", "SECRETTOKEN", "urgent-ish"):
        assert leaked not in text
    with pytest.raises(ValueError) as e2:
        SocSettings(jwt_secret="short-secret-value", database_url="sqlite://")
    assert "short-secret-value" not in str(e2.value)


# --- Low 9: a dead worker is restarted -----------------------------------------------------------------------

def test_a_dead_worker_thread_is_replaced(soc_settings, receiver):
    rec = receiver()
    s = mk(webhook_url=rec.url, notify_dedupe_seconds=0, **LAB)
    r = ChannelRunner(channels.WebhookChannel(s), s, now=lambda: NOW)
    try:
        dead = threading.Thread(target=lambda: None)
        dead.start()
        dead.join()
        r._thread = dead
        assert r.offer(ev()) == "queued"
        assert wait_until(lambda: len(rec.requests) == 1)
        assert r._thread is not dead and r._thread.is_alive()
    finally:
        r.close()


# --- missing tests from the review ---------------------------------------------------------------------------

@pytest.fixture
def tls_material(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key), "-out",
                        str(cert), "-days", "2", "-subj", "/CN=good.example", "-addext",
                        "subjectAltName=DNS:good.example"], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl cannot make a test certificate")
    return cert, key


def test_the_certificate_name_is_checked_though_the_connection_goes_to_the_pinned_ip(
        soc_settings, tls_material):
    cert, key = tls_material
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.socket = server_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    trust = ssl.create_default_context(cafile=str(cert))
    try:
        def channel(host):
            ch = channels.WebhookChannel(mk(webhook_url=f"https://{host}:{port}/x",
                                            notify_allow_private=True, notify_timeout_seconds=3))
            ch.resolver = lambda h, p, type=0: [(2, 1, 6, "", ("127.0.0.1", p))]  # DNS says loopback
            ch.ssl_context = trust
            return ch

        channel("good.example").send(ev())                      # name matches the certificate
        assert len(got) == 1
        with pytest.raises(DeliveryError, match="TLS error"):   # same server, wrong name: refused
            channel("other.example").send(ev())
        assert len(got) == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_lifespan_closes_the_notifier(make_app, monkeypatch):
    a = make_app()
    closed = []
    monkeypatch.setattr(a.app.state.notifier, "close", lambda *x, **k: closed.append(1))
    with TestClient(a.app):
        assert closed == []
    assert closed == [1]


def test_a_direct_variable_wins_over_its_file(soc_settings, tmp_path, monkeypatch):
    f = tmp_path / "hook"
    f.write_text("https://from-file.example.com/x\n")
    monkeypatch.setenv("IDPS_SOC_WEBHOOK_URL_FILE", str(f))
    monkeypatch.setenv("IDPS_SOC_WEBHOOK_URL", "https://from-env.example.com/x")
    assert mk().webhook_url.get_secret_value() == "https://from-env.example.com/x"
    monkeypatch.setenv("IDPS_SOC_WEBHOOK_URL", "")            # blank: the file applies
    assert mk().webhook_url.get_secret_value() == "https://from-file.example.com/x"
    monkeypatch.setenv("IDPS_SOC_WEBHOOK_URL_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="cannot be read") as e:
        mk()
    assert "from-" not in str(e.value)


# --- a real STARTTLS conversation (no stubs): the bug that made Gmail fail ----------------------

class _StartTlsServer:
    """A tiny SMTP server on 127.0.0.1 that offers STARTTLS with a certificate for "localhost",
    accepts AUTH PLAIN and records what it got. Just enough of SMTP for smtplib."""

    def __init__(self, tmp_path):
        import socket
        import threading

        from soc.api import pki

        ca_key, ca = pki.make_ca("test smtp CA")
        key, cert = _server_cert_for(ca_key, ca, "localhost")
        self.ca_file = tmp_path / "smtp-ca.pem"
        pki.write_public(self.ca_file, pki.cert_pem(ca))
        (tmp_path / "smtp.pem").write_bytes(pki.cert_pem(cert))
        pki.write_private(tmp_path / "smtp.key", pki.key_pem(key))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(tmp_path / "smtp.pem", tmp_path / "smtp.key")
        self.sock = socket.socket()
        self.sock.settimeout(10)  # never block a test run if the client does not connect
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.got = {"tls": False, "auth": None, "rcpt": [], "data": b""}
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        finally:
            self.sock.close()
        f = conn.makefile("rwb")

        def send(line):
            f.write(line.encode() + b"\r\n")
            f.flush()

        send("220 localhost ESMTP test")
        while True:
            line = f.readline().decode().strip()
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                send("250-localhost")
                send("250-AUTH PLAIN" if self.got["tls"] else "250-STARTTLS")
                send("250 8BITMIME")
            elif verb == "STARTTLS":
                send("220 go ahead")
                f.close()
                conn = self.ctx.wrap_socket(conn, server_side=True)
                f = conn.makefile("rwb")
                self.got["tls"] = True
            elif verb == "AUTH":
                self.got["auth"] = line.split(" ", 2)[1:]
                send("235 ok")
            elif verb == "MAIL":
                send("250 ok")
            elif verb == "RCPT":
                self.got["rcpt"].append(line)
                send("250 ok")
            elif verb == "DATA":
                send("354 go")
                while (chunk := f.readline()) not in (b".\r\n", b""):
                    self.got["data"] += chunk
                send("250 queued")
            elif verb == "QUIT" or not line:
                try:
                    send("221 bye")
                except OSError:
                    pass
                conn.close()
                return
            else:
                send("502 no")


def _server_cert_for(ca_key, ca, name):
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def test_email_over_a_real_starttls_server_verifies_the_host_name(tmp_path, monkeypatch):
    server = _StartTlsServer(tmp_path)
    real = ssl.create_default_context
    monkeypatch.setattr(channels.ssl, "create_default_context",
                        lambda *a, **k: real(cafile=str(server.ca_file)))
    s = mk(smtp_host="localhost", smtp_port=server.port, smtp_security="starttls",
           smtp_username="user@example.com", smtp_password="app pass word xyzw",
           smtp_from="idps@example.com", smtp_to="oncall@example.org")
    r = runner_for(channels.EmailChannel, s)
    r.process(ev())
    status = r.status()
    assert status["sent"] == 1, status
    assert server.got["tls"] and server.got["auth"][0] == "PLAIN"
    assert any("oncall@example.org" in x for x in server.got["rcpt"])


@pytest.mark.parametrize("configured_host", ["127.0.0.1", "smtp.other.test"])
def test_email_refuses_a_certificate_for_another_host_name(tmp_path, monkeypatch, configured_host):
    """The certificate is for "localhost": a SOC configured with any other name must refuse it
    (TLS error) and send nothing, never fall back to unverified TLS or plaintext."""
    server = _StartTlsServer(tmp_path)
    real = ssl.create_default_context
    monkeypatch.setattr(channels.ssl, "create_default_context",
                        lambda *a, **k: real(cafile=str(server.ca_file)))
    real_connect = channels.smtplib.SMTP.connect

    def to_loopback(self, host="localhost", port=0, source_address=None):
        return real_connect(self, "127.0.0.1", port, source_address)  # any name -> the test server

    monkeypatch.setattr(channels.smtplib.SMTP, "connect", to_loopback)
    s = mk(smtp_host=configured_host, smtp_port=server.port, smtp_security="starttls",
           smtp_username="user@example.com", smtp_password="app pass word xyzw",
           smtp_from="idps@example.com", smtp_to="oncall@example.org",
           notify_max_attempts=1)  # the test server takes one connection
    r = runner_for(channels.EmailChannel, s)
    r.process(ev())
    status = r.status()
    assert status["sent"] == 0 and "TLS error" in (status["last_error"] or ""), status
    assert server.got["auth"] is None and server.got["data"] == b""  # no password, no mail
