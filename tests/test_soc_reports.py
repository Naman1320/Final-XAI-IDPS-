"""The weekly PDF report and its email (roadmap step 13)."""

import email
import json
import smtplib
import time
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage
from typing import ClassVar

import pytest
import sqlalchemy as sa
from conftest import ADMIN_PW, ANALYST_PW, login
from fastapi.testclient import TestClient
from pdf_helpers import pdf_text
from pydantic import SecretStr
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from soc.api import auth, reports
from soc.api.integrations import channels
from soc.api.main import create_app
from soc.api.models import (
    AccessLog,
    Alert,
    AlertStatus,
    AuditEntry,
    Block,
    BlockSource,
    Case,
    CaseStatus,
    ModelVersion,
    ReportRun,
    Role,
    SensorStatus,
    SensorToken,
    Severity,
    WouldBlock,
)

NOW = datetime.now(UTC)
WEEK = reports.last_complete_week(NOW)
# The module's idea of "this week" is fixed at import; a run that straddles Monday 00:00 UTC would
# disagree with the server's. Skip in the few minutes around that moment instead of flaking.
_to_monday = (NOW - NOW.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds() \
    if NOW.weekday() == 0 else None
_near_boundary = (_to_monday is not None and _to_monday < 600) or (
    NOW.weekday() == 6 and NOW.hour == 23 and NOW.minute >= 50)
pytestmark = pytest.mark.skipif(_near_boundary, reason="too close to the ISO week boundary")


def add_alerts(app, n=3, at=None, **kw):
    at = at or WEEK.start + timedelta(days=2, hours=3)
    with app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        for i in range(n):
            fields = dict(sensor_id=sensor.id, received_at=at, src_ip=f"203.0.113.{7 + i % 3}",
                          src_port=1, dst_ip="10.10.1.5", dst_port=22, protocol=6,
                          start_ms=1, end_ms=int(at.timestamp() * 1000) - 250,
                          predicted_class="SSH-Patator", confidence=0.9, severity=Severity.HIGH,
                          explanation={}) | kw
            db.add(Alert(**fields))
        db.commit()


@pytest.fixture
def seeded(soc_app, sensor_token):
    add_alerts(soc_app, 4)
    return soc_app


def app_with(soc_settings, **overrides):
    app = create_app(soc_settings.model_copy(update=overrides))
    app.state.assistant_llm = None
    with app.state.session_factory() as db:  # a second app on one PostgreSQL database shares it
        if db.scalar(select(sa.func.count()).select_from(SensorToken)) == 0:
            auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
            auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
            auth.create_sensor_token(db, "sensor-1")
    return app


# --- weeks ------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,start", [
    ("2026-W01", "2025-12-29"), ("2026-W45", "2026-11-02"), ("2020-W53", "2020-12-28"),
    ("2024-W10", "2024-03-04")])
def test_parse_week(text, start):
    w = reports.parse_week(text)
    assert w.label == text and w.start.date().isoformat() == start
    assert w.start.weekday() == 0 and w.end - w.start == timedelta(days=7)
    assert w.start.tzinfo is UTC


@pytest.mark.parametrize("bad", ["", "2026-45", "2026-W5", "2026-W00", "2026-W54", "2025-W53",
                                 "26-W10", "2026-w10", "2026-W10 ", "1999-W10", "2101-W01",
                                 "2026-W10\n", "<b>2026-W10</b>", "../../etc"])
def test_parse_week_refuses(bad):
    with pytest.raises(ValueError):
        reports.parse_week(bad)


def test_last_complete_week():
    assert reports.last_complete_week(datetime(2026, 11, 16, 0, 0, tzinfo=UTC)).label == "2026-W46"
    assert reports.last_complete_week(datetime(2026, 11, 22, 23, 59, tzinfo=UTC)).label == "2026-W46"
    assert reports.last_complete_week(datetime(2026, 11, 23, 0, 0, tzinfo=UTC)).label == "2026-W47"
    assert reports.last_complete_week(datetime(2027, 1, 3, 12, tzinfo=UTC)).label == "2026-W52"
    assert reports.last_complete_week(datetime(2027, 1, 4, 0, tzinfo=UTC)).label == "2026-W53"


# --- the PDF ----------------------------------------------------------------------------------

def test_download_is_a_pdf_attachment_with_the_expected_content(client, seeded, analyst_headers):
    r = client.get("/reports/weekly", headers=analyst_headers)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"] == f'attachment; filename="idps-weekly-{WEEK.label}.pdf"'
    assert r.headers["cache-control"] == "no-store"
    pdf = r.content
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    text = pdf_text(pdf)
    for expected in ("IDPS weekly security report", f"Week {WEEK.label}", "Headline numbers",
                     "Alerts per day", "Alerts by class", "SSH-Patator", "Top 10 source addresses",
                     "203.0.113.7", "Blocks and would-blocks", "Analyst triage", "Model health",
                     "Generated at", "SOC version", "Page 1 of",
                     "Contains personal data (IP addresses): handle under the SOC privacy notice"):
        assert expected in text, expected
    assert text.count("Contains personal data (IP addresses)") >= 1


def test_any_signed_in_user_may_download_but_not_anonymous(client, seeded, admin_headers,
                                                          analyst_headers):
    assert client.get("/reports/weekly", headers=admin_headers).status_code == 200
    assert client.get("/reports/weekly", headers=analyst_headers).status_code == 200
    assert client.get("/reports/weekly").status_code == 401
    assert client.get("/reports/weeks").status_code == 401


def test_a_named_week_has_its_own_numbers(client, seeded, analyst_headers):
    add_alerts(seeded, 2, at=WEEK.start - timedelta(days=3), predicted_class="Heartbleed")
    old = reports.week_of((WEEK.start - timedelta(days=3)).date())
    r = client.get(f"/reports/weekly?week={old.label}", headers=analyst_headers)
    assert r.status_code == 200
    assert f"idps-weekly-{old.label}.pdf" in r.headers["content-disposition"]
    text = pdf_text(r.content)
    assert "Heartbleed" in text and "SSH-Patator" not in text


def test_alerts_outside_the_week_are_not_counted(soc_app, sensor_token):
    add_alerts(soc_app, 3)
    add_alerts(soc_app, 5, at=WEEK.start - timedelta(seconds=1))   # the week before
    add_alerts(soc_app, 7, at=WEEK.end)                              # the week after, exactly
    with soc_app.state.session_factory() as db:
        data = reports.collect(db, soc_app.state.settings, WEEK, NOW)
    assert data.total == 3 and sum(data.per_day) == 3 and data.per_day[2] == 3


@pytest.mark.parametrize("bad", ["abc", "2026-W54", "2025-W53", "2026-W00", "2099-W01",
                                 "2026-W10;drop", "x" * 40])
def test_a_bad_week_is_422(client, analyst_headers, bad):
    for path in (f"/reports/weekly?week={bad}",):
        r = client.get(path, headers=analyst_headers)
        assert r.status_code == 422, bad
    assert client.get("/reports/weekly?week=2099-W01", headers=analyst_headers).status_code == 422


def test_the_current_week_is_a_partial_report(client, soc_app, analyst_headers, sensor_token):
    current = reports.week_of(NOW.date()).label
    r = client.get(f"/reports/weekly?week={current}", headers=analyst_headers)
    assert r.status_code == 200 and "partial" in pdf_text(r.content)


def test_headline_numbers(soc_app, sensor_token):
    at = WEEK.start + timedelta(days=1)
    add_alerts(soc_app, 3, at=at, severity=Severity.CRITICAL, predicted_class="DDoS")
    add_alerts(soc_app, 2, at=at, severity=Severity.LOW, source="rule",
               rule={"sid": 1, "signature": "s", "severity": 3})
    add_alerts(soc_app, 2, at=at, status=AlertStatus.FALSE_POSITIVE)
    add_alerts(soc_app, 1, at=at, status=AlertStatus.CONFIRMED)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        db.add(Block(sensor_id=sensor.id, ip="203.0.113.7", reason="r", source=BlockSource.AUTO,
                     blocked_at=at))
        db.add(Block(sensor_id=sensor.id, ip="203.0.113.8", reason="r", source=BlockSource.ANALYST,
                     blocked_at=at, unblocked_at=at + timedelta(hours=1)))
        db.add(WouldBlock(sensor_id=sensor.id, ip="203.0.113.9", reason="r",
                          source=BlockSource.AUTO, at=at))
        db.add(Case(title="c", status=CaseStatus.OPEN, created_at=at, updated_at=at))
        db.add(Case(title="d", status=CaseStatus.CLOSED, created_at=at - timedelta(days=30),
                    updated_at=at))
        db.commit()
        data = reports.collect(db, soc_app.state.settings, WEEK, NOW)
    assert data.total == 8
    assert data.by_severity == {"low": 2, "medium": 0, "high": 3, "critical": 3}
    assert data.by_source == {"ml": 6, "rule": 2}
    assert data.by_status["false_positive"] == 2 and data.triaged == 3
    assert data.fp_rate == pytest.approx(2 / 3)
    assert data.by_class[0] == ("SSH-Patator", 5) and ("DDoS", 3) in data.by_class
    assert data.blocks["created"] == 2 and data.blocks["unblocked"] == 1
    assert data.blocks["by_source"] == {"auto": 1, "analyst": 1}
    assert data.blocks["active_now"] == 1 and data.would_blocks["total"] == 1
    assert data.cases == {"opened": 1, "closed": 1}
    p50, p95, n = data.latency_ms
    assert n == 8 and p50 == pytest.approx(250, abs=2) and p95 == pytest.approx(250, abs=2)
    text = pdf_text(reports.render_pdf(data))
    assert "66.7% (2 of 3)" in text and "250 ms / 250 ms" in text


def test_an_empty_week_still_makes_a_report(client, soc_app, analyst_headers):
    r = client.get("/reports/weekly", headers=analyst_headers)
    assert r.status_code == 200 and "No alerts this week." in pdf_text(r.content)


def test_model_health_section(soc_app, sensor_token):
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        online = db.scalar(select(SensorToken))
        offline = SensorToken(name="sensor-2", token_hash="b" * 64)
        db.add(offline)
        db.flush()
        db.add(SensorStatus(sensor_id=online.id, last_seen_at=now, payload={
            "model": {"name": "week_xgboost", "version": "2026.11.1"},
            "drift": {"level": "watch", "psi_max": 0.14}, "outbox_pending": 12,
            "faithfulness": {"model_matches": True, "methods": {
                "shap": {"mean_drop": 0.31, "label_flip_rate": 0.42}}}}))
        db.add(SensorStatus(sensor_id=offline.id, last_seen_at=now - timedelta(hours=3),
                            payload={"model": {"name": "week_xgboost"}, "outbox_pending": 0}))
        db.add(ModelVersion(sensor_id=online.id, name="week_xgboost", sha256="c" * 64,
                            version="2026.11.1", first_seen=WEEK.start, last_seen=now))
        db.add(ModelVersion(sensor_id=online.id, name="old", sha256="d" * 64, version="1",
                            first_seen=WEEK.start - timedelta(days=90),
                            last_seen=WEEK.start - timedelta(days=60)))
        db.commit()
        data = reports.collect(db, soc_app.state.settings, WEEK, now)
    assert [(s["name"], s["online"]) for s in data.sensors] == [("sensor-1", True),
                                                                 ("sensor-2", False)]
    assert [m["version"] for m in data.models] == ["2026.11.1"]  # only models seen in the week
    text = pdf_text(reports.render_pdf(data))
    assert "Sensors online now: 1 of 2" in text
    assert "week_xgboost 2026.11.1" in text and "watch (0.14)" in text and "cccccccccccc" in text
    assert "shap mean drop 0.31, label flips 42%" in text


# --- hostile text -----------------------------------------------------------------------------

HOSTILE = ["<b>bold</b><font color='red'>x</font>", "<img src='file:///etc/passwd'/>",
           "&amp; &lt;script&gt;", "<a href='http://evil.example/'>click</a>", "a < b > c &",
           "<para><seq/></para>", "</b></font>", "<unknown tag=1>", "%(x)s {0} \\ ( ) \\(",
           "<\x1bb>esc", "\u202eevil\u202c", "日本語 class"]


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_class_and_sensor_text_is_shown_literally(soc_app, sensor_token, name):
    add_alerts(soc_app, 2, predicted_class=name)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        db.add(SensorStatus(sensor_id=sensor.id, last_seen_at=datetime.now(UTC), payload={
            "model": {"name": name, "version": name}, "drift": {"level": name},
            "faithfulness": {"methods": {name: {"mean_drop": 0.1, "label_flip_rate": 0.2}}}}))
        db.commit()
        pdf = reports.build_pdf(db, soc_app.state.settings, WEEK)
    assert pdf.startswith(b"%PDF-")
    text = pdf_text(pdf)
    shown = reports.clean(name)
    assert shown in text, (name, text[:400])
    # no markup was interpreted: the PDF has no link, image or script objects of our making
    assert b"/URI" not in pdf and b"/Launch" not in pdf and b"/JavaScript" not in pdf


def test_a_very_long_class_name_is_cut(soc_app, sensor_token):
    add_alerts(soc_app, 1, predicted_class="X" * 64)
    with soc_app.state.session_factory() as db:
        pdf = reports.build_pdf(db, soc_app.state.settings, WEEK)
    assert pdf.startswith(b"%PDF-")


def test_clean_and_esc():
    assert reports.clean("a\x00b\x1b[31m\u202e") == "ab[31m"
    assert reports.clean("x" * 300, 20) == "x" * 17 + "..."
    assert reports.esc("<b>&") == "&lt;b&gt;&amp;"
    assert reports.clean("日本") == "??"


# --- masking ----------------------------------------------------------------------------------

@pytest.mark.parametrize("ip,masked", [("203.0.113.7", "203.0.113.x"), ("10.0.0.255", "10.0.0.x"),
                                       ("2001:db8:1:2::9", "2001:db8:1:x"), ("weird", "weird"),
                                       ("::1", "0:0:0:x"), ("2001::abcd:1", "2001:0:0:x"),
                                       ("2001:db8::", "2001:db8:0:x"), ("::ffff:10.1.2.3", "10.1.2.x"),
                                       ("fe80::1:2:3:4", "fe80:0:0:x")])
def test_mask_ip(ip, masked):
    assert reports.mask_ip(ip) == masked


def test_masking_option_hides_the_last_octet(soc_settings, sensor_token):
    app = app_with(soc_settings, report_mask_ips=True)
    add_alerts(app, 3)
    with app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        db.add(Block(sensor_id=sensor.id, ip="198.51.100.77", reason="r", source=BlockSource.AUTO,
                     blocked_at=WEEK.start + timedelta(days=1)))
        db.commit()
    c = TestClient(app)
    r = c.get("/reports/weekly", headers=login(c, "analyst", ANALYST_PW))
    text = pdf_text(r.content)
    assert "203.0.113.x" in text and "198.51.100.x" in text and "last octet masked" in text
    for full in ("203.0.113.7", "203.0.113.8", "198.51.100.77"):
        assert full not in text
    # and by default they are shown
    plain = TestClient(app_with(soc_settings))
    add_alerts(plain.app, 1)
    t = pdf_text(plain.get("/reports/weekly", headers=login(plain, "analyst", ANALYST_PW)).content)
    assert "203.0.113.7" in t and "shown in full" in t


# --- weeks listing ----------------------------------------------------------------------------

def test_weeks_listing(client, seeded, analyst_headers):
    add_alerts(seeded, 2, at=WEEK.start - timedelta(days=10))
    with seeded.state.session_factory() as db:
        db.add(ReportRun(week=WEEK.label, emailed_at=NOW, recipients_count=2))
        db.commit()
    r = client.get("/reports/weeks", headers=analyst_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["default_week"] == WEEK.label
    assert body["email_enabled"] is False and body["email_configured"] is False
    weeks = body["weeks"]
    assert len(weeks) == 12 and weeks[0]["week"] == WEEK.label
    assert [w["week"] for w in weeks] == sorted((w["week"] for w in weeks), reverse=True)
    assert weeks[0]["alerts"] == 4 and weeks[0]["run"] and weeks[0]["emailed"]
    assert weeks[0]["recipients_count"] == 2 and weeks[0]["error"] is None
    assert weeks[1]["alerts"] == 0 and not weeks[1]["run"] and not weeks[1]["emailed"]
    assert sum(w["alerts"] for w in weeks) == 6
    assert set(weeks[0]) == {"week", "start", "end", "alerts", "run", "emailed", "emailed_at",
                             "recipients_count", "error"}


def test_download_is_access_logged(client, seeded, analyst_headers):
    client.get(f"/reports/weekly?week={WEEK.label}", headers=analyst_headers)
    with seeded.state.session_factory() as db:
        row = db.scalar(select(AccessLog).where(AccessLog.action == "report_download"))
    assert row.username == "analyst" and row.target == WEEK.label and row.subject_fp is None
    client.get("/reports/weekly?week=bad", headers=analyst_headers)  # refused: not logged
    with seeded.state.session_factory() as db:
        got = list(db.scalars(select(AccessLog).where(AccessLog.action == "report_download")))
    # the download row, then one per address the PDF prints (the three sources of add_alerts)
    assert len(got) == 1 + 3 and got[0].subject_fp is None


def test_a_download_logs_the_addresses_it_contains_unless_masked(soc_settings, sensor_token):
    from soc.api import access_log

    for mask in (False, True):
        app = app_with(soc_settings, report_mask_ips=mask)
        add_alerts(app, 3)
        with app.state.session_factory() as db:
            sensor = db.scalar(select(SensorToken))
            db.add(Block(sensor_id=sensor.id, ip="198.51.100.77", reason="r",
                         source=BlockSource.AUTO, blocked_at=WEEK.start + timedelta(days=1)))
            db.commit()
        c = TestClient(app)
        with app.state.session_factory() as db:
            seen = db.scalar(select(sa.func.coalesce(sa.func.max(AccessLog.id), 0)))
        assert c.get("/reports/weekly", headers=login(c, "analyst", ANALYST_PW)).status_code == 200
        with app.state.session_factory() as db:
            fps = {r.subject_fp for r in db.scalars(select(AccessLog).where(
                AccessLog.action == "report_download", AccessLog.id > seen))}
        wanted = {access_log.fingerprint(app.state.settings, ip) for ip in (
            "203.0.113.7", "203.0.113.8", "203.0.113.9", "198.51.100.77")}
        assert fps == ({None} if mask else {None} | wanted), mask


def test_two_reports_at_once_is_the_limit(client, seeded, analyst_headers):
    taken = [reports._slots.acquire(blocking=False) for _ in range(2)]
    try:
        r = client.get("/reports/weekly", headers=analyst_headers)
        assert r.status_code == 429 and r.headers["retry-after"]
    finally:
        for t in taken:
            if t:
                reports._slots.release()
    assert client.get("/reports/weekly", headers=analyst_headers).status_code == 200


# --- performance ------------------------------------------------------------------------------

def test_a_week_of_50k_alerts_is_fast_and_uses_the_time_index(soc_app, sensor_token, capsys):
    n = 50_000
    start = WEEK.start
    classes = ["DoS", "PortScan", "SSH-Patator", "Bot", "DDoS", "Web Attack", "(odd)"]
    rows = [dict(sensor_id=1, received_at=start + timedelta(seconds=i * 12), src_ip=f"192.0.2.{i % 250}",
                 src_port=1, dst_ip="10.10.1.5", dst_port=80, protocol=6, start_ms=1,
                 end_ms=int((start + timedelta(seconds=i * 12)).timestamp() * 1000) - 100,
                 predicted_class=classes[i % len(classes)], confidence=0.9,
                 severity=[Severity.LOW, Severity.MEDIUM, Severity.HIGH][i % 3],
                 explanation={}, status=AlertStatus.NEW, source="ml" if i % 5 else "rule")
            for i in range(n)]
    with soc_app.state.session_factory() as db:
        db.execute(insert(Alert), rows)
        db.commit()
        plan = reports.explain(db, WEEK)
        t0 = time.perf_counter()
        pdf = reports.build_pdf(db, soc_app.state.settings, WEEK, NOW)
        took = time.perf_counter() - t0
        data = reports.collect(db, soc_app.state.settings, WEEK, NOW)
    with capsys.disabled():
        print(f"\n[perf] weekly PDF over {n:,} alerts: {took:.2f}s ({len(pdf):,} bytes)")
    assert data.total == n and sum(data.per_day) == n and len(data.top_sources) == 10
    if soc_app.state.engine.dialect.name == "sqlite":
        assert "USING INDEX ix_alerts_received" in plan and "SCAN alerts" not in plan, plan
    else:
        assert "Seq Scan on alerts" not in plan or "received_at" in plan, plan
    assert took < 60, f"{took:.1f}s"  # a generous bound; the figure above is what matters
    assert data.latency_ms[2] == reports.LATENCY_SAMPLE  # bounded sample, not every alert


# --- email ------------------------------------------------------------------------------------

class StubSMTP:
    instances: ClassVar[list] = []
    fail_with: ClassVar[Exception | None] = None

    def __init__(self, timeout=None, context=None):
        self.calls, self.sent = [], []
        self.timeout = timeout
        StubSMTP.instances.append(self)

    def connect(self, host, port):
        self.calls.append(("connect", host, port))

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append("login")

    def send_message(self, msg, from_addr=None, to_addrs=None):
        if StubSMTP.fail_with is not None:
            raise StubSMTP.fail_with
        self.sent.append((msg, from_addr, tuple(to_addrs)))

    def quit(self):
        self.calls.append("quit")

    def close(self):
        pass


@pytest.fixture
def smtp(monkeypatch):
    StubSMTP.instances, StubSMTP.fail_with = [], None
    monkeypatch.setattr(channels.smtplib, "SMTP", StubSMTP)
    return StubSMTP


def mail_settings(soc_settings, **kw):
    return soc_settings.model_copy(update={
        "smtp_host": "smtp.example.com", "smtp_from": "idps@example.com",
        "smtp_to": ["soc@example.org"], "report_email_enabled": True} | kw)


def sent_messages():
    return [m for inst in StubSMTP.instances for m in inst.sent]


def runner_state():
    return reports.RunState()


MONDAY_0630 = datetime(2026, 11, 16, 6, 30, tzinfo=UTC)  # 2026-W47 starts; W46 is the last complete


def test_the_scheduled_week_and_time():
    s = type("S", (), {"report_email_weekday": 0, "report_email_hour_utc": 6})()
    week, due = reports.due_week(s, MONDAY_0630)
    assert week.label == "2026-W46" and due == datetime(2026, 11, 16, 6, tzinfo=UTC)
    assert reports.due_week(s, datetime(2026, 11, 16, 5, 59, tzinfo=UTC)) is None
    s.report_email_weekday, s.report_email_hour_utc = 3, 18  # Thursday 18:00
    assert reports.due_week(s, datetime(2026, 11, 19, 17, 59, tzinfo=UTC)) is None
    week, due = reports.due_week(s, datetime(2026, 11, 19, 18, 0, tzinfo=UTC))
    assert week.label == "2026-W46" and due == datetime(2026, 11, 19, 18, tzinfo=UTC)


def test_the_runner_emails_the_last_week_once_with_the_pdf_attached(soc_settings, smtp):
    settings = mail_settings(soc_settings, smtp_username="u", smtp_password=SecretStr("p" * 12))
    app = create_app(settings)
    week = reports.last_complete_week(MONDAY_0630)
    with app.state.session_factory() as db:
        db.add(SensorToken(name="s", token_hash="a" * 64))
        db.commit()
    add_alerts(app, 3, at=week.start + timedelta(days=1))
    reports.run_once(app.state.session_factory, settings, state := runner_state(), MONDAY_0630)
    assert state.sent and state.week == "2026-W46" and state.error is None
    (msg, sender, to), = sent_messages()
    assert sender == "idps@example.com" and to == ("soc@example.org",)
    assert msg["Subject"] == "IDPS weekly report 2026-W46"
    parsed = email.message_from_bytes(msg.as_bytes(), policy=policy.default)
    (att,) = list(parsed.iter_attachments())
    assert att.get_filename() == "idps-weekly-2026-W46.pdf"
    assert att.get_content_type() == "application/pdf"
    pdf = att.get_content()
    assert pdf.startswith(b"%PDF-") and "Week 2026-W46" in pdf_text(pdf)
    assert "203.0.113" not in parsed.get_body().get_content()  # no addresses in the mail body
    inst = StubSMTP.instances[0]
    assert "starttls" in inst.calls and "login" in inst.calls  # the channel's TLS and login path
    with app.state.session_factory() as db:
        run = db.scalar(select(ReportRun))
    assert run.week == "2026-W46" and run.emailed_at and run.recipients_count == 1 and not run.error
    # a second check, a restart (new runner, same database) and a later check: nothing more
    reports.run_once(app.state.session_factory, settings, runner_state(), MONDAY_0630)
    reports.run_once(app.state.session_factory, settings, runner_state(),
                     MONDAY_0630 + timedelta(days=2))
    assert len(sent_messages()) == 1


def test_the_runner_waits_for_the_time_and_respects_the_switches(soc_settings, smtp):
    app = create_app(mail_settings(soc_settings))
    sf = app.state.session_factory
    reports.run_once(sf, mail_settings(soc_settings), runner_state(),
                     MONDAY_0630.replace(hour=5))  # before the configured hour
    reports.run_once(sf, mail_settings(soc_settings, report_email_enabled=False), runner_state(),
                     MONDAY_0630)
    reports.run_once(sf, mail_settings(soc_settings, smtp_to=[]), runner_state(), MONDAY_0630)
    reports.run_once(sf, mail_settings(soc_settings, smtp_host=None), runner_state(), MONDAY_0630)
    assert sent_messages() == []
    with sf() as db:
        assert db.scalar(select(sa.func.count()).select_from(ReportRun)) == 0
    # report_email_to overrides smtp_to
    reports.run_once(sf, mail_settings(soc_settings, report_email_to=["boss@example.org"]),
                     runner_state(), MONDAY_0630)
    assert sent_messages()[0][2] == ("boss@example.org",)


def test_a_week_is_claimed_by_exactly_one_caller(soc_app):
    sf = soc_app.state.session_factory
    due = datetime(2026, 11, 16, 6, tzinfo=UTC)
    with sf() as a, sf() as b:  # two processes
        assert reports.claim_week(a, "2026-W46", MONDAY_0630, due) is True
        assert reports.claim_week(b, "2026-W46", MONDAY_0630, due) is False
    with sf() as db:  # and the table itself refuses a second row for a week
        db.add(ReportRun(week="2026-W46"))
        with pytest.raises(IntegrityError):
            db.commit()


def test_a_second_process_that_loses_the_insert_race_does_not_send(soc_app, monkeypatch):
    sf = soc_app.state.session_factory
    due = datetime(2026, 11, 16, 6, tzinfo=UTC)
    with sf() as other, sf() as db:
        real = db.scalar

        def racing(*a, **k):  # the other process inserts between our read and our insert
            result = real(*a, **k)
            if result is None and not racing.done:
                racing.done = True
                other.add(ReportRun(week="2026-W46", generated_at=MONDAY_0630))
                other.commit()
            return result
        racing.done = False
        monkeypatch.setattr(db, "scalar", racing)
        assert reports.claim_week(db, "2026-W46", MONDAY_0630, due) is False


def test_a_failed_send_is_recorded_and_retried_later_not_at_once(soc_settings, smtp):
    settings = mail_settings(soc_settings)
    sf = create_app(settings).state.session_factory
    StubSMTP.fail_with = smtplib.SMTPResponseException(451, b"try later")
    state = runner_state()
    reports.run_once(sf, settings, state, MONDAY_0630)
    assert not state.sent and state.error == "SMTP error 451"
    with sf() as db:
        run = db.scalar(select(ReportRun))
        assert run.emailed_at is None and run.error == "SMTP error 451"
    StubSMTP.fail_with = None
    reports.run_once(sf, settings, runner_state(), MONDAY_0630 + timedelta(minutes=30))
    assert sent_messages() == []  # too soon after the failure
    reports.run_once(sf, settings, state := runner_state(), MONDAY_0630 + timedelta(hours=1, minutes=1))
    assert state.sent and len(sent_messages()) == 1
    with sf() as db:
        run = db.scalar(select(ReportRun))
        assert run.emailed_at is not None and run.error is None
    reports.run_once(sf, settings, runner_state(), MONDAY_0630 + timedelta(hours=3))
    assert len(sent_messages()) == 1


def test_retries_stop_a_day_after_the_scheduled_time(soc_settings, smtp):
    settings = mail_settings(soc_settings)
    sf = create_app(settings).state.session_factory
    StubSMTP.fail_with = smtplib.SMTPResponseException(451, b"x")
    reports.run_once(sf, settings, runner_state(), MONDAY_0630)
    StubSMTP.fail_with = None
    reports.run_once(sf, settings, runner_state(), MONDAY_0630 + timedelta(hours=30))
    assert sent_messages() == []


def test_a_claim_left_by_a_dead_process_is_taken_over_after_an_hour(soc_settings, smtp):
    settings = mail_settings(soc_settings)
    sf = create_app(settings).state.session_factory
    with sf() as db:  # claimed, never finished
        db.add(ReportRun(week="2026-W46", generated_at=MONDAY_0630 - timedelta(minutes=10)))
        db.commit()
    reports.run_once(sf, settings, runner_state(), MONDAY_0630)
    assert sent_messages() == []
    reports.run_once(sf, settings, state := runner_state(), MONDAY_0630 + timedelta(hours=1))
    assert state.sent and len(sent_messages()) == 1


def test_an_oversized_report_is_not_sent(soc_settings, smtp, monkeypatch):
    monkeypatch.setattr(reports, "MAX_ATTACHMENT_BYTES", 100)
    settings = mail_settings(soc_settings)
    sf = create_app(settings).state.session_factory
    reports.run_once(sf, settings, state := runner_state(), MONDAY_0630)
    assert sent_messages() == [] and "10 MB" in state.error
    with sf() as db:
        assert "10 MB" in db.scalar(select(ReportRun.error))


def test_the_runner_never_raises(soc_settings, smtp, monkeypatch):
    settings = mail_settings(soc_settings)
    sf = create_app(settings).state.session_factory

    def boom(*a, **k):
        raise RuntimeError("database gone")

    monkeypatch.setattr(reports, "build_pdf", boom)
    reports.run_once(sf, settings, state := runner_state(), MONDAY_0630)
    assert state.error and "unexpected error (RuntimeError)" in state.error
    monkeypatch.setattr(reports, "claim_week", boom)
    reports.run_once(sf, settings, state := runner_state(), MONDAY_0630)
    assert state.error == "run failed (see the SOC log)"


def test_the_runner_thread_starts_only_when_enabled_and_stops(soc_settings, smtp):
    off = reports.ReportRunner(create_app(soc_settings).state.session_factory, soc_settings,
                               first_delay=0.01, interval=0.01)
    off.start()
    assert not off._thread.is_alive()
    settings = mail_settings(soc_settings, report_email_hour_utc=0, report_email_weekday=0)
    app = create_app(settings)
    runner = reports.ReportRunner(app.state.session_factory, settings, first_delay=0.01,
                                  interval=0.01)
    runner.start()
    deadline = time.time() + 10
    while time.time() < deadline and not sent_messages():
        time.sleep(0.02)
    runner.stop()
    assert not runner._thread.is_alive()
    assert len(sent_messages()) == 1  # the due week, once, however many checks ran


def test_the_app_starts_and_stops_the_runner(soc_settings, smtp):
    app = create_app(mail_settings(soc_settings))
    with TestClient(app) as c:  # runs the lifespan
        assert c.get("/health").status_code == 200
        assert app.state.report_runner._thread.is_alive()
    assert not app.state.report_runner._thread.is_alive()


# --- send now ---------------------------------------------------------------------------------

def test_send_now_is_admin_only_and_needs_email_configured(client, admin_headers, analyst_headers):
    assert client.post("/admin/reports/weekly/email", headers=analyst_headers).status_code == 403
    r = client.post("/admin/reports/weekly/email", headers=admin_headers)
    assert r.status_code == 409 and "not configured" in r.text


def test_send_now_emails_audits_and_leaves_the_schedule_alone(soc_settings, smtp):
    app = app_with(mail_settings(soc_settings, report_email_enabled=False,
                                 report_email_to=["a@example.org", "b@example.org"]))
    add_alerts(app, 2)
    c = TestClient(app)
    h = login(c, "admin", ADMIN_PW)
    r = c.post(f"/admin/reports/weekly/email?week={WEEK.label}", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"week", "recipients", "emailed_at", "size_bytes"}
    assert body["week"] == WEEK.label and body["recipients"] == 2 and body["size_bytes"] > 1000
    assert "example.org" not in r.text  # recipients are counted, never listed
    (_, _, to), = sent_messages()
    assert to == ("a@example.org", "b@example.org")
    with app.state.session_factory() as db:
        audit = db.scalar(select(AuditEntry).where(AuditEntry.action == "report_email"))
        assert audit.actor_name == "admin" and audit.target == f"report:{WEEK.label}"
        assert audit.details == {"ok": True, "recipients": 2, "bytes": body["size_bytes"]}
        assert "example.org" not in json.dumps(audit.details)
        assert db.scalar(select(sa.func.count()).select_from(ReportRun)) == 0  # not the schedule's
    weeks = c.get("/reports/weeks", headers=h).json()
    assert weeks["email_configured"] is True and weeks["weeks"][0]["emailed"] is False
    assert c.post("/admin/reports/weekly/email", headers=h).status_code == 200  # again: sends again
    assert len(sent_messages()) == 2


def test_a_manual_send_of_an_unfinished_week_does_not_stop_the_scheduled_email(soc_settings, smtp):
    settings = mail_settings(soc_settings)
    app = app_with(settings)
    c = TestClient(app)
    h = login(c, "admin", ADMIN_PW)
    current = reports.week_of(datetime.now(UTC).date())
    assert c.post(f"/admin/reports/weekly/email?week={current.label}",
                  headers=h).status_code == 200  # the week is not over
    assert len(sent_messages()) == 1
    # the week ends; on the next Monday after 06:00 the scheduler sends its full report
    monday = current.end + timedelta(hours=6, minutes=30)
    reports.run_once(app.state.session_factory, settings, state := runner_state(), monday)
    assert state.sent and state.week == current.label and len(sent_messages()) == 2
    parsed = email.message_from_bytes(sent_messages()[1][0].as_bytes(), policy=policy.default)
    assert "partial" not in pdf_text(next(iter(parsed.iter_attachments())).get_content())


def test_a_failed_manual_resend_does_not_retrigger_or_undo_the_scheduled_email(soc_settings, smtp):
    settings = mail_settings(soc_settings)
    app = app_with(settings)
    c = TestClient(app)
    h = login(c, "admin", ADMIN_PW)
    week = reports.last_complete_week(MONDAY_0630)
    reports.run_once(app.state.session_factory, settings, runner_state(), MONDAY_0630)
    assert len(sent_messages()) == 1
    with app.state.session_factory() as db:
        before = db.scalar(select(ReportRun)).emailed_at
    assert before is not None
    StubSMTP.fail_with = smtplib.SMTPResponseException(451, b"later")
    r = c.post(f"/admin/reports/weekly/email?week={week.label}", headers=h)
    assert r.status_code == 502
    with app.state.session_factory() as db:
        run = db.scalar(select(ReportRun))
        assert run.emailed_at == before and run.error is None  # still "sent"
        failed = db.scalar(select(AuditEntry).where(AuditEntry.action == "report_email"))
        assert failed.details["ok"] is False
    StubSMTP.fail_with = None
    reports.run_once(app.state.session_factory, settings, runner_state(),
                     MONDAY_0630 + timedelta(hours=5))
    assert len(sent_messages()) == 1  # the scheduler did not send it again


def test_send_now_reports_a_failure_without_addresses(soc_settings, smtp):
    app = app_with(mail_settings(soc_settings))
    c = TestClient(app)
    h = login(c, "admin", ADMIN_PW)
    StubSMTP.fail_with = smtplib.SMTPRecipientsRefused({"soc@example.org": (550, b"no")})
    r = c.post("/admin/reports/weekly/email", headers=h)
    assert r.status_code == 502 and "recipients refused" in r.text
    assert "example.org" not in r.text
    with app.state.session_factory() as db:
        audit = db.scalar(select(AuditEntry).where(AuditEntry.action == "report_email"))
        assert audit.details["ok"] is False and "example.org" not in json.dumps(audit.details)
        assert db.scalar(select(sa.func.count()).select_from(ReportRun)) == 0


def test_send_now_refuses_an_oversized_report(soc_settings, smtp, monkeypatch):
    monkeypatch.setattr(reports, "MAX_ATTACHMENT_BYTES", 100)
    c = TestClient(app_with(mail_settings(soc_settings)))
    r = c.post("/admin/reports/weekly/email", headers=login(c, "admin", ADMIN_PW))
    assert r.status_code == 413 and sent_messages() == []


@pytest.mark.parametrize("bad", ["abc", "2025-W53", "2099-W01"])
def test_send_now_validates_the_week(soc_settings, smtp, bad):
    c = TestClient(app_with(mail_settings(soc_settings)))
    r = c.post(f"/admin/reports/weekly/email?week={bad}", headers=login(c, "admin", ADMIN_PW))
    assert r.status_code == 422 and sent_messages() == []


def test_the_email_channel_still_sends_alerts_through_the_shared_function(soc_settings, smtp):
    """send_email is shared: the alert channel's behaviour (STARTTLS, login) is unchanged."""
    s = mail_settings(soc_settings, smtp_username="u", smtp_password=SecretStr("p" * 12))
    channels.send_email(s, EmailMessage(), ["x@example.org"])
    (inst,) = StubSMTP.instances
    assert inst.calls[:4] == [("connect", "smtp.example.com", 587), "ehlo", "starttls", "ehlo"]
    assert "login" in inst.calls
    refusing = mail_settings(soc_settings, smtp_username="u", smtp_security="none")
    from soc.api.integrations.netguard import DeliveryError

    with pytest.raises(DeliveryError, match="without TLS"):
        channels.send_email(refusing, EmailMessage(), ["x@example.org"])


def test_one_attachment_is_added_by_the_shared_function(soc_settings, smtp):
    msg = EmailMessage()
    msg.set_content("hi")
    channels.send_email(mail_settings(soc_settings), msg, ["x@example.org"],
                        attachment=("a.pdf", "application/pdf", b"%PDF-1.4 x"))
    sent = sent_messages()[0][0]
    (att,) = list(sent.iter_attachments())
    assert att.get_filename() == "a.pdf" and att.get_content() == b"%PDF-1.4 x"
