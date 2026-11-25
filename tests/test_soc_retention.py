# ruff: noqa: F811  (fixtures imported from step10_helpers)
"""Step 10: data retention rules, batches, audit entry, dry run, runner, endpoint, settings."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from step10_helpers import cli_env, migrated, needs_pg, pg_engine, settings  # noqa: F401

from soc.api import __main__ as cli
from soc.api import retention
from soc.api.db import make_engine
from soc.api.models import (
    Action,
    ActionKind,
    ActionStatus,
    Alert,
    AlertStatus,
    AssistantConversation,
    AuditEntry,
    Block,
    BlockSource,
    Case,
    CaseNote,
    CaseStatus,
    Role,
    SensorToken,
    Severity,
    User,
    WouldBlock,
)

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
DAY = timedelta(days=1)
EPS = timedelta(seconds=1)


@pytest.fixture
def db(tmp_path):
    engine = migrated(make_engine(f"sqlite:///{tmp_path / 'r.db'}"))
    with Session(engine) as session:
        session.add(SensorToken(name="s", token_hash="h" * 64))
        session.add(User(username="u", password_hash="x", role=Role.ADMIN))
        session.commit()
        yield session


def mk_alert(db, at, **kw):
    sid = db.scalar(select(func.min(SensorToken.id)))
    a = Alert(sensor_id=sid, received_at=at, src_ip="1.1.1.1", src_port=1, dst_ip="2.2.2.2",
              dst_port=2, protocol=6, start_ms=1, end_ms=2, predicted_class="DoS",
              confidence=0.5, severity=Severity.LOW, explanation={},
              **({"status": AlertStatus.NEW} | kw))
    db.add(a)
    db.flush()
    return a


def ids(db, model):
    return {r for r in db.scalars(select(model.id))}


def run(db, **kw):
    pause = kw.pop("pause", 0)
    return retention.prune(db, settings(**kw), NOW, pause=pause)


# --- alerts -----------------------------------------------------------------------------------

def test_alert_cutoff_boundaries(db):
    older = mk_alert(db, NOW - 10 * DAY - EPS)
    exactly = mk_alert(db, NOW - 10 * DAY)
    newer = mk_alert(db, NOW - 10 * DAY + EPS)
    db.commit()
    older_id, exactly_id, newer_id = older.id, exactly.id, newer.id
    counts = run(db, alert_retention_days=10)
    assert counts["alerts"] == 1
    assert ids(db, Alert) == {exactly_id, newer_id} and older_id not in ids(db, Alert)


def test_zero_means_keep_forever_for_every_rule(db):
    old = NOW - 5000 * DAY
    mk_alert(db, old)
    db.add(AuditEntry(at=old, actor_type="u", actor_name="a", action="x", details={}))
    db.add(AssistantConversation(user_id=1, updated_at=old, created_at=old))
    db.add(Case(title="c", status=CaseStatus.CLOSED, created_at=old, updated_at=old))
    db.commit()
    counts = run(db, alert_retention_days=0, audit_retention_days=0, assistant_retention_days=0,
                 closed_case_retention_days=0)
    assert sum(counts.values()) == 0
    assert db.query(Alert).count() == db.query(AuditEntry).count() == 1
    assert db.query(AssistantConversation).count() == db.query(Case).count() == 1


@pytest.mark.parametrize("keep", [True, False])
@pytest.mark.parametrize("status", list(AlertStatus))
@pytest.mark.parametrize("has_features", [True, False])
def test_keep_labelled_matrix(db, keep, status, has_features):
    a = mk_alert(db, NOW - 400 * DAY, status=status, features={"f": 1.0} if has_features else None)
    db.commit()
    aid = a.id
    run(db, alert_retention_days=180, alert_retention_keep_labelled=keep)
    judged = status in (AlertStatus.CONFIRMED, AlertStatus.FALSE_POSITIVE)
    kept = keep and judged and has_features
    assert (aid in ids(db, Alert)) == kept


def test_json_null_features_count_as_having_features_is_documented_edge(db):
    # features stored as JSON null (not SQL NULL): the column holds a value, so the alert counts
    # as carrying features and a judged one is KEPT (the safe side: nothing is lost).
    import sqlalchemy as sa

    a = mk_alert(db, NOW - 400 * DAY, status=AlertStatus.CONFIRMED, features=sa.JSON.NULL)
    db.commit()
    aid = a.id
    run(db, alert_retention_days=180)
    assert aid in ids(db, Alert)


@pytest.mark.parametrize("status,deleted", [(CaseStatus.OPEN, False),
                                            (CaseStatus.INVESTIGATING, False),
                                            (CaseStatus.CLOSED, True)])
def test_alerts_in_cases(db, status, deleted):
    case = Case(title="c", status=status, created_at=NOW, updated_at=NOW)
    db.add(case)
    db.flush()
    a = mk_alert(db, NOW - 400 * DAY, case_id=case.id)
    db.commit()
    aid = a.id
    run(db, alert_retention_days=180, alert_retention_keep_labelled=False)
    assert (aid not in ids(db, Alert)) == deleted
    assert db.query(Case).count() == 1


def test_blocks_and_would_blocks_are_unlinked_not_deleted_actions_untouched(db):
    old = NOW - 400 * DAY
    gone, kept = mk_alert(db, old), mk_alert(db, NOW)
    db.add_all([
        Block(sensor_id=1, ip="1.1.1.1", source=BlockSource.AUTO, alert_id=gone.id,
              blocked_at=NOW),
        Block(sensor_id=1, ip="3.3.3.3", source=BlockSource.AUTO, alert_id=kept.id,
              blocked_at=NOW),
        WouldBlock(sensor_id=1, ip="1.1.1.1", source=BlockSource.AUTO, alert_id=gone.id, at=NOW),
        WouldBlock(sensor_id=1, ip="3.3.3.3", source=BlockSource.AUTO, alert_id=kept.id, at=NOW),
        Action(kind=ActionKind.BLOCK_IP, params={"ip": "1.1.1.1"}, proposed_by="user",
               sensor_id=1, status=ActionStatus.EXECUTED, created_at=old),
    ])
    db.commit()
    run(db, alert_retention_days=180, alert_retention_keep_labelled=False)
    assert ids(db, Alert) == {kept.id}
    blocks = {b.ip: b.alert_id for b in db.query(Block)}
    assert blocks == {"1.1.1.1": None, "3.3.3.3": kept.id}
    wbs = {b.ip: b.alert_id for b in db.query(WouldBlock)}
    assert wbs == {"1.1.1.1": None, "3.3.3.3": kept.id}
    assert db.query(Action).count() == 1


def test_batches_more_than_one(db, monkeypatch):
    monkeypatch.setattr(retention, "BATCH", 7)
    old = NOW - 400 * DAY
    victims = [mk_alert(db, old) for _ in range(30)]
    db.add_all([Block(sensor_id=1, ip="1.1.1.1", source=BlockSource.AUTO, alert_id=v.id,
                      blocked_at=NOW) for v in victims[:15]])
    survivors = [mk_alert(db, NOW) for _ in range(3)]
    for _ in range(23):
        db.add(AuditEntry(at=old, actor_type="u", actor_name="a", action="x", details={}))
    for _ in range(16):
        db.add(WouldBlock(sensor_id=1, ip="9.9.9.9", source=BlockSource.AUTO, at=old))
    for _ in range(15):
        db.add(AssistantConversation(user_id=1, updated_at=old, created_at=old))
    for _ in range(14):
        c = Case(title="c", status=CaseStatus.CLOSED, created_at=old, updated_at=old)
        db.add(c)
        db.flush()
        db.add(CaseNote(case_id=c.id, text="n"))
    db.commit()
    counts = run(db, alert_retention_days=180, alert_retention_keep_labelled=False,
                 closed_case_retention_days=30)
    assert counts == {"alerts": 30, "case_notes": 14, "cases": 14, "audit_log": 23,
                      "assistant_conversations": 15, "would_blocks": 16, "access_log": 0, "login_history": 0}
    assert ids(db, Alert) == {s.id for s in survivors}
    assert db.query(Block).count() == 15 and all(b.alert_id is None for b in db.query(Block))


def test_exact_multiple_of_batch_terminates(db, monkeypatch):
    monkeypatch.setattr(retention, "BATCH", 5)
    for _ in range(10):
        mk_alert(db, NOW - 400 * DAY)
    db.commit()
    assert run(db, alert_retention_days=180)["alerts"] == 10


# --- other tables -----------------------------------------------------------------------------

def test_audit_boundaries(db):
    for delta in (EPS, 0 * EPS, -EPS):
        db.add(AuditEntry(at=NOW - 365 * DAY - delta, actor_type="u", actor_name="a",
                          action=str(delta), details={}))
    db.commit()
    assert run(db)["audit_log"] == 1  # default 365 days; only the "older" one


def test_assistant_boundaries_and_busy(db):
    cut = NOW - 90 * DAY
    older = AssistantConversation(user_id=1, updated_at=cut - EPS, created_at=cut)
    newer = AssistantConversation(user_id=1, updated_at=cut + EPS, created_at=cut)
    busy = AssistantConversation(user_id=1, updated_at=cut - 50 * DAY, created_at=cut,
                                 busy_since=NOW)
    db.add_all([older, newer, busy])
    db.commit()
    assert run(db)["assistant_conversations"] == 1
    assert ids(db, AssistantConversation) == {newer.id, busy.id}


def test_closed_cases(db):
    cut = NOW - 30 * DAY
    old_closed = Case(title="a", status=CaseStatus.CLOSED, created_at=cut, updated_at=cut - EPS)
    new_closed = Case(title="b", status=CaseStatus.CLOSED, created_at=cut, updated_at=cut + EPS)
    old_open = Case(title="c", status=CaseStatus.OPEN, created_at=cut, updated_at=cut - 99 * DAY)
    old_inv = Case(title="d", status=CaseStatus.INVESTIGATING, created_at=cut,
                   updated_at=cut - 99 * DAY)
    db.add_all([old_closed, new_closed, old_open, old_inv])
    db.flush()
    db.add_all([CaseNote(case_id=old_closed.id, text="1"), CaseNote(case_id=old_closed.id, text="2"),
                CaseNote(case_id=new_closed.id, text="3")])
    recent_alert = mk_alert(db, NOW, case_id=old_closed.id)
    db.commit()
    counts = run(db, closed_case_retention_days=30)
    assert counts["cases"] == 1 and counts["case_notes"] == 2
    assert ids(db, Case) == {new_closed.id, old_open.id, old_inv.id}
    assert db.query(CaseNote).count() == 1
    db.refresh(recent_alert)
    assert recent_alert.case_id is None  # the alert stays, unlinked


def test_would_block_boundaries(db):
    cut = NOW - 7 * DAY
    for d in (EPS, -EPS):
        db.add(WouldBlock(sensor_id=1, ip="1.1.1.1", source=BlockSource.AUTO, at=cut - d))
    db.commit()
    assert run(db)["would_blocks"] == 1
    assert run(db, would_block_retention_days=1)["would_blocks"] == 1  # now the newer one too
    assert db.query(WouldBlock).count() == 0


# --- dry run, audit entry, runner -------------------------------------------------------------

def _populate_old(db):
    old = NOW - 999 * DAY
    mk_alert(db, old)
    db.add(AuditEntry(at=old, actor_type="u", actor_name="a", action="x", details={}))
    db.add(WouldBlock(sensor_id=1, ip="1.1.1.1", source=BlockSource.AUTO, at=old))
    db.commit()


def test_dry_run_deletes_nothing_and_matches_the_real_counts(db):
    _populate_old(db)
    dry = retention.prune(db, settings(), NOW, dry_run=True)
    assert (db.query(Alert).count(), db.query(AuditEntry).count(),
            db.query(WouldBlock).count()) == (1, 1, 1)
    assert retention.prune(db, settings(), NOW) == dry
    assert dry["alerts"] == dry["audit_log"] == dry["would_blocks"] == 1


def test_dry_run_closed_cases_counts_notes(db):
    old = NOW - 99 * DAY
    c = Case(title="c", status=CaseStatus.CLOSED, created_at=old, updated_at=old)
    db.add(c)
    db.flush()
    db.add(CaseNote(case_id=c.id, text="n"))
    db.commit()
    dry = retention.prune(db, settings(closed_case_retention_days=30), NOW, dry_run=True)
    assert dry["cases"] == 1 and dry["case_notes"] == 1 and db.query(Case).count() == 1


def test_run_once_audit_entry_counts_and_silence(tmp_path):
    engine = migrated(make_engine(f"sqlite:///{tmp_path / 'a.db'}"))
    factory = retention.sessionmaker(bind=engine, expire_on_commit=False)
    state = retention.RunState()
    retention.run_once(factory, settings(), state, pause=0)  # nothing to delete
    with factory() as db:
        assert db.query(AuditEntry).filter_by(action="retention_prune").count() == 0
    assert state.error is None and state.at is not None and sum(state.counts.values()) == 0
    with factory() as db:
        old = datetime.now(UTC) - 999 * DAY
        db.add(AuditEntry(at=old, actor_type="u", actor_name="a", action="x", details={}))
        db.add(WouldBlock(sensor_id=1, ip="1.1.1.1", source=BlockSource.AUTO, at=old))
        db.commit()
    retention.run_once(factory, settings(), state, pause=0)
    with factory() as db:
        entry = db.query(AuditEntry).filter_by(action="retention_prune").one()
        assert entry.details == {"counts": {"audit_log": 1, "would_blocks": 1}}
        assert (entry.actor_type, entry.actor_name) == ("system", "retention")
    retention.run_once(factory, settings(), state, pause=0)  # deleted only nothing this time
    with factory() as db:
        assert db.query(AuditEntry).filter_by(action="retention_prune").count() == 1


def test_runner_errors_do_not_crash_and_are_reported(soc_app, client, admin_headers):
    runner = soc_app.state.retention

    def broken():
        raise RuntimeError("boom secret-detail")

    retention.run_once(broken, runner.settings, runner.state)
    body = client.get("/admin/retention", headers=admin_headers).json()
    assert body["last_run"]["error"].startswith("RuntimeError")
    assert "secret-detail" not in body["last_run"]["error"]
    retention.run_once(soc_app.state.session_factory, runner.settings, runner.state, pause=0)
    assert client.get("/admin/retention", headers=admin_headers).json()["last_run"]["error"] is None


def test_runner_thread_runs_and_stops(tmp_path):
    engine = migrated(make_engine(f"sqlite:///{tmp_path / 't.db'}"))
    factory = retention.sessionmaker(bind=engine, expire_on_commit=False)
    runner = retention.RetentionRunner(factory, settings(), first_delay=0.01, interval=0.05)
    runner.start()
    import time

    for _ in range(100):
        if runner.state.at is not None:
            break
        time.sleep(0.02)
    runner.stop()
    assert runner.state.at is not None and runner.state.error is None
    assert not runner._thread.is_alive()


# --- endpoint ---------------------------------------------------------------------------------

def test_endpoint_auth_policy_and_last_run(soc_app, client, admin_headers, analyst_headers):
    assert client.get("/admin/retention").status_code == 401
    assert client.get("/admin/retention", headers=analyst_headers).status_code == 403
    body = client.get("/admin/retention", headers=admin_headers).json()
    assert body["policy"] == {
        "alert_retention_days": 180, "alert_retention_keep_labelled": True,
        "audit_retention_days": 365, "assistant_retention_days": 90,
        "closed_case_retention_days": 0, "would_block_retention_days": 7,
        "access_log_retention_days": 365, "login_history_retention_days": 365}
    assert body["last_run"] is None
    with soc_app.state.session_factory() as db:
        db.add(AuditEntry(actor_type="system", actor_name="retention", action="retention_prune",
                          details={"counts": {"alerts": 4}}))
        db.commit()
    assert client.get("/admin/retention", headers=admin_headers).json()["last_run"]["counts"] == {
        "alerts": 4}  # from the audit entry when this process has not run yet


def test_endpoint_shows_a_custom_policy(soc_settings, admin_headers):
    from fastapi.testclient import TestClient

    from soc.api import auth
    from soc.api.main import create_app

    app = create_app(soc_settings.model_copy(update={"alert_retention_days": 0}))
    with app.state.session_factory() as s:
        try:
            auth.create_user(s, "admin", "admin-password-123", Role.ADMIN)
        except ValueError:
            pass
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "admin", "password": "admin-password-123"}
                 ).json()["access_token"]
    pol = c.get("/admin/retention", headers={"Authorization": f"Bearer {tok}"}).json()["policy"]
    assert pol["alert_retention_days"] == 0


# --- CLI --------------------------------------------------------------------------------------

def test_cli_prune_dry_run_and_real(tmp_path, capsys, cli_env):
    url = f"sqlite:///{tmp_path / 'p.db'}"
    engine = migrated(make_engine(url))
    with Session(engine) as s:
        old = datetime.now(UTC) - 999 * DAY
        s.add(AuditEntry(at=old, actor_type="u", actor_name="a", action="x", details={}))
        s.commit()
    assert cli.main(["prune", "--dry-run", "--database-url", url]) == 0
    assert "would delete" in capsys.readouterr().out
    with Session(engine) as s:
        assert s.query(AuditEntry).count() == 1
    assert cli.main(["prune", "--database-url", url]) == 0
    assert "audit_log: 1" in capsys.readouterr().out
    with Session(engine) as s:
        # the old row is gone; the prune wrote its audit entry
        assert [e.action for e in s.query(AuditEntry)] == ["retention_prune"]


# --- settings ---------------------------------------------------------------------------------

BLANKS = ("ALERT_RETENTION_DAYS", "ALERT_RETENTION_KEEP_LABELLED", "AUDIT_RETENTION_DAYS",
          "ASSISTANT_RETENTION_DAYS", "CLOSED_CASE_RETENTION_DAYS", "AUTO_MIGRATE")


def test_blank_env_values_fall_back_to_defaults(monkeypatch):
    for name in BLANKS:
        monkeypatch.setenv(f"IDPS_SOC_{name}", "")
    s = settings()
    assert (s.alert_retention_days, s.alert_retention_keep_labelled, s.audit_retention_days,
            s.assistant_retention_days, s.closed_case_retention_days, s.auto_migrate
            ) == (180, True, 365, 90, 0, True)


def test_env_values_are_read(monkeypatch):
    monkeypatch.setenv("IDPS_SOC_ALERT_RETENTION_DAYS", "30")
    monkeypatch.setenv("IDPS_SOC_AUTO_MIGRATE", "false")
    monkeypatch.setenv("IDPS_SOC_ALERT_RETENTION_KEEP_LABELLED", "0")
    s = settings()
    assert (s.alert_retention_days, s.auto_migrate, s.alert_retention_keep_labelled
            ) == (30, False, False)


@pytest.mark.parametrize("field,value", [
    ("alert_retention_days", -1), ("alert_retention_days", 36_501),
    ("audit_retention_days", -1), ("audit_retention_days", 36_501),
    ("assistant_retention_days", -1), ("assistant_retention_days", 36_501),
    ("closed_case_retention_days", -1), ("closed_case_retention_days", 36_501),
    ("would_block_retention_days", 0), ("would_block_retention_days", 366)])
def test_out_of_range_values_are_rejected(field, value):
    with pytest.raises(ValidationError):
        settings(**{field: value})


def test_out_of_range_env_value_is_rejected(monkeypatch):
    monkeypatch.setenv("IDPS_SOC_ALERT_RETENTION_DAYS", "-5")
    with pytest.raises(ValidationError):
        settings()
    monkeypatch.setenv("IDPS_SOC_ALERT_RETENTION_DAYS", "abc")
    with pytest.raises(ValidationError):
        settings()


def test_boundary_values_are_accepted():
    s = settings(alert_retention_days=36_500, audit_retention_days=0, would_block_retention_days=365)
    assert s.alert_retention_days == 36_500 and s.audit_retention_days == 0


# --- PostgreSQL -------------------------------------------------------------------------------

@needs_pg
def test_retention_on_postgres(pg_engine):
    migrated(pg_engine)
    with Session(pg_engine) as s:
        s.add(SensorToken(name="s", token_hash="h" * 64))
        s.flush()
        case = Case(title="c", status=CaseStatus.OPEN, created_at=NOW, updated_at=NOW)
        s.add(case)
        s.flush()
        old = NOW - 400 * DAY
        a_gone, a_open = mk_alert(s, old), mk_alert(s, old, case_id=case.id)
        a_lab = mk_alert(s, old, status=AlertStatus.CONFIRMED, features={"f": 1})
        s.add(Block(sensor_id=s.scalar(select(func.min(SensorToken.id))), ip="1.1.1.1",
                    source=BlockSource.AUTO, alert_id=a_gone.id, blocked_at=NOW))
        s.commit()
        counts = retention.prune(s, settings(), NOW)
        assert counts["alerts"] == 1
        assert ids(s, Alert) == {a_open.id, a_lab.id}
        assert s.query(Block).one().alert_id is None
        counts = retention.prune(s, settings(alert_retention_keep_labelled=False), NOW)
        assert counts["alerts"] == 1 and ids(s, Alert) == {a_open.id}
