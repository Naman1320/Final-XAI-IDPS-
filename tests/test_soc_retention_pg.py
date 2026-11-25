"""Retention under concurrency on a real PostgreSQL (skipped without IDPS_TEST_DATABASE_URL).

Each test makes another transaction touch a row between the retention batch choosing its ids and
locking them, and commits only after a delay, so the batch has to WAIT on the row lock and then
re-check the rules against what was committed."""

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from conftest import TEST_SECRET
from sqlalchemy import text
from sqlalchemy.orm import Session
from step10_helpers import pg_engine  # noqa: F401  (fixture)

from soc.api import retention
from soc.api.db import init_db
from soc.api.models import Alert, AlertStatus, Case, CaseNote, CaseStatus, SensorToken, Severity
from soc.api.settings import SocSettings

OLD = datetime.now(UTC) - timedelta(days=400)


def settings(**kw):
    return SocSettings(jwt_secret=TEST_SECRET, alert_retention_keep_labelled=False, **kw)


@pytest.fixture
def db(pg_engine):  # noqa: F811
    init_db(pg_engine)
    with Session(pg_engine) as s:
        s.add(SensorToken(id=1, name="s", token_hash="h" * 64))
        s.commit()
    return pg_engine


def add_alert(engine, **kw) -> int:
    with Session(engine) as s:
        a = Alert(sensor_id=1, received_at=OLD, src_ip="1.1.1.1", src_port=1, dst_ip="2.2.2.2",
                  dst_port=2, protocol=6, start_ms=1, end_ms=2, predicted_class="DoS",
                  confidence=0.5, severity=Severity.LOW, explanation={}, status=AlertStatus.NEW,
                  **kw)
        s.add(a)
        s.commit()
        return a.id


def add_case(engine, status) -> int:
    with Session(engine) as s:
        c = Case(title="c", status=status, created_at=OLD, updated_at=OLD)
        s.add(c)
        s.commit()
        return c.id


def interfere(monkeypatch, engine, model, statements, hold=0.8):
    """After the batch has chosen its ids, another connection runs `statements` and commits only
    `hold` seconds later (so the batch's row locks have to wait for it)."""
    real = retention._candidates
    box = {"done": False, "errors": []}
    threads = []

    def hooked(session, m, cond, last):
        ids = real(session, m, cond, last)
        if m is model and ids and not box["done"]:
            box["done"] = True
            ready = threading.Event()

            def other():
                try:
                    with engine.connect() as c:
                        for sql, params in statements[:1]:
                            c.execute(text(sql), params)
                        ready.set()
                        time.sleep(hold)
                        for sql, params in statements[1:]:
                            c.execute(text(sql), params)
                        c.commit()
                except Exception as exc:  # noqa: BLE001
                    box["errors"].append(exc)
                    ready.set()

            t = threading.Thread(target=other)
            t.start()
            threads.append(t)
            ready.wait(5)
        return ids

    monkeypatch.setattr(retention, "_candidates", hooked)
    box["join"] = lambda: [t.join() for t in threads]
    return box


def test_an_alert_attached_to_an_open_case_during_a_batch_survives(db, monkeypatch):
    open_case = add_case(db, CaseStatus.OPEN)
    aid = add_alert(db)
    box = interfere(monkeypatch, db, Alert, [
        ("UPDATE alerts SET case_id = :c WHERE id = :a", {"c": open_case, "a": aid})])
    with Session(db) as s:
        counts = retention.prune(s, settings())
    box["join"]()
    assert box["errors"] == [] and counts["alerts"] == 0
    with Session(db) as s:
        assert s.get(Alert, aid).case_id == open_case


def test_a_case_reopened_during_the_closed_case_prune_keeps_notes_and_links(db, monkeypatch):
    case = add_case(db, CaseStatus.CLOSED)
    aid = add_alert(db, case_id=case)
    with Session(db) as s:
        s.add(CaseNote(case_id=case, text="n", created_at=OLD))
        s.commit()
    box = interfere(monkeypatch, db, Case, [
        ("UPDATE cases SET status = 'open' WHERE id = :c", {"c": case})])
    with Session(db) as s:
        counts = retention.prune(s, settings(alert_retention_days=0,
                                             closed_case_retention_days=30))
    box["join"]()
    assert box["errors"] == [] and counts["cases"] == 0 and counts["case_notes"] == 0
    with Session(db) as s:
        assert s.query(CaseNote).count() == 1 and s.get(Alert, aid).case_id == case


def test_an_analyst_attaching_to_a_closed_case_during_a_batch_deadlocks_neither(db, monkeypatch):
    closed = add_case(db, CaseStatus.CLOSED)
    linked = add_alert(db, case_id=closed)  # makes the batch lock the closed case
    other = add_alert(db)
    # the analyst's order, as the ORM does it: the case row first, then its alerts
    box = interfere(monkeypatch, db, Alert, [
        ("UPDATE cases SET updated_at = now() WHERE id = :c", {"c": closed}),
        ("UPDATE alerts SET case_id = :c WHERE id = :a", {"c": closed, "a": other})], hold=0.5)
    with Session(db) as s:
        counts = retention.prune(s, settings())  # no exception: no deadlock surfaced here
    box["join"]()
    assert box["errors"] == []  # ... nor to the analyst
    assert counts["alerts"] >= 1
    with Session(db) as s:
        assert s.get(Alert, linked) is None


def test_a_deadlock_victim_batch_is_retried_then_skipped(db, monkeypatch):
    aid = add_alert(db)
    calls = {"n": 0}
    real = Session.execute

    def deadlocked(self, stmt, *a, **k):
        if "FOR UPDATE" in str(stmt) and "FROM alerts" in str(stmt):
            calls["n"] += 1
            if calls["n"] == 1:  # the first attempt loses a deadlock
                raise sa.exc.OperationalError("x", {}, type("E", (Exception,), {
                    "sqlstate": "40P01"})("deadlock detected"))
        return real(self, stmt, *a, **k)

    monkeypatch.setattr(Session, "execute", deadlocked)
    monkeypatch.setattr(Session, "scalars", lambda self, stmt, *a, **k: deadlocked(
        self, stmt, *a, **k).scalars())
    with Session(db) as s:
        counts = retention.prune(s, settings())
    assert counts["alerts"] == 1 and calls["n"] >= 2  # tried, rolled back, tried again
    with Session(db) as s:
        assert s.get(Alert, aid) is None
