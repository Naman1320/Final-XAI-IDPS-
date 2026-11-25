"""Smoke tests for roadmap step 10: migrations, adoption, backup/restore, retention."""

import gzip
import json
import os
import stat
from datetime import UTC, datetime, timedelta

import pytest
from conftest import TEST_SECRET
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from soc.api import backup, migrate, retention
from soc.api.db import Base, init_db, make_engine
from soc.api.models import (
    Alert,
    AlertStatus,
    AuditEntry,
    Block,
    BlockSource,
    Case,
    CaseStatus,
    SensorToken,
    Severity,
)
from soc.api.settings import SocSettings


def fresh(tmp_path, name="a.db"):
    engine = make_engine(f"sqlite:///{tmp_path / name}")
    init_db(engine)
    return engine


def test_a_new_database_is_migrated_and_matches_the_models(tmp_path):
    engine = fresh(tmp_path)
    assert set(inspect(engine).get_table_names()) == {*Base.metadata.tables, "alembic_version"}
    assert migrate.check(engine) == []
    init_db(engine)  # idempotent


def test_adoption_stamps_a_matching_old_database_and_refuses_a_different_one(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'old.db'}")
    migrate.baseline_metadata().create_all(engine)  # as made before migrations existed
    init_db(engine)  # adopted (stamped 0001), then upgraded to the newest revision
    with engine.connect() as conn:
        assert migrate.current_revision(conn) == migrate.head_revision()
    other = make_engine(f"sqlite:///{tmp_path / 'odd.db'}")
    migrate.baseline_metadata().create_all(other)
    with other.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN role"))  # a required column is gone
    with pytest.raises(migrate.SchemaError, match="users.role"):
        init_db(other)
    assert "alembic_version" not in inspect(other).get_table_names()


def test_auto_migrate_off_refuses_a_database_that_is_not_at_head(tmp_path, monkeypatch):
    engine = fresh(tmp_path)
    init_db(engine, auto_migrate=False)  # at head: fine
    monkeypatch.setattr(migrate, "head_revision", lambda: "0002_next")
    with pytest.raises(migrate.SchemaError, match="db upgrade"):
        init_db(engine, auto_migrate=False)


def seed(engine):
    now = datetime.now(UTC)
    with Session(engine) as db:
        s = SensorToken(name="s", token_hash="h" * 64)
        db.add(s)
        db.flush()
        db.add(Alert(sensor_id=s.id, received_at=now, src_ip="1.2.3.4", src_port=1, dst_ip="5.6.7.8",
                     dst_port=2, protocol=6, start_ms=1, end_ms=2, predicted_class="DoS",
                     confidence=0.5, severity=Severity.HIGH, explanation={"x": [1.5, None]},
                     status=AlertStatus.NEW, features=None))
        db.commit()


def rows(engine):
    with engine.connect() as c:
        return {t: c.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in Base.metadata.tables}


def test_backup_restore_round_trip_and_its_refusals(tmp_path):
    src = fresh(tmp_path, "src.db")
    seed(src)
    out = tmp_path / "b.jsonl.gz"
    header = backup.backup(src, out, progress=lambda _m: None)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert header["tables"]["alerts"]["rows"] == 1 and header["alembic_revision"]
    with pytest.raises(backup.BackupError, match="overwrite"):
        backup.backup(src, out, progress=lambda _m: None)
    dst = make_engine(f"sqlite:///{tmp_path / 'dst.db'}")
    backup.restore(dst, out, progress=lambda _m: None)
    assert rows(dst) == rows(src)
    with pytest.raises(backup.BackupError, match="not empty"):
        backup.restore(dst, out, progress=lambda _m: None)
    bad = tmp_path / "bad.gz"
    bad.write_bytes(gzip.compress(gzip.decompress(out.read_bytes()).replace(b"DoS", b"DoX")))
    with pytest.raises(backup.BackupError, match="checksum"):
        backup.restore(make_engine("sqlite://"), bad, progress=lambda _m: None)
    assert json.loads(gzip.decompress(out.read_bytes()).split(b"\n")[0])["format"] == backup.FORMAT


def retention_settings(**kw):
    return SocSettings(jwt_secret=TEST_SECRET, **kw)


def test_retention_rules(tmp_path):
    engine = fresh(tmp_path)
    now = datetime.now(UTC)
    old = now - timedelta(days=400)
    with Session(engine) as db:
        s = SensorToken(name="s", token_hash="h" * 64)
        open_case, closed = Case(title="o", status=CaseStatus.OPEN), Case(
            title="c", status=CaseStatus.CLOSED)
        db.add_all([s, open_case, closed])
        db.flush()

        def alert(**kw):
            kw.setdefault("status", AlertStatus.NEW)
            a = Alert(sensor_id=s.id, received_at=old, src_ip="1.1.1.1", src_port=1,
                      dst_ip="2.2.2.2", dst_port=2, protocol=6, start_ms=1, end_ms=2,
                      predicted_class="DoS", confidence=0.5, severity=Severity.LOW,
                      explanation={}, **kw)
            db.add(a)
            return a

        plain, in_open, labelled = alert(), alert(case_id=open_case.id), alert(
            status=AlertStatus.CONFIRMED, features={"a": 1.0})
        alert(case_id=closed.id)
        db.flush()
        db.add(Block(sensor_id=s.id, ip="1.1.1.1", reason="r", source=BlockSource.AUTO,
                     alert_id=plain.id, blocked_at=old))
        db.add(AuditEntry(actor_type="user", actor_name="a", action="x", at=old, details={}))
        db.commit()
        keep = {in_open.id, labelled.id}
        dry = retention.prune(db, retention_settings(), dry_run=True)
        assert dry["alerts"] == 2 and dry["audit_log"] == 1
        counts = retention.prune(db, retention_settings())
        assert counts["alerts"] == 2 and db.query(Alert).count() == 2
        assert {a.id for a in db.query(Alert)} == keep
        assert db.query(Block).one().alert_id is None  # the block stays, unlinked
        counts = retention.prune(db, retention_settings(alert_retention_keep_labelled=False))
        assert counts["alerts"] == 1 and {a.id for a in db.query(Alert)} == {in_open.id}
        forever = retention.prune(db, retention_settings(alert_retention_days=0,
                                                         audit_retention_days=0))
        assert forever["alerts"] == 0


def test_the_retention_endpoint_is_admin_only(client, admin_headers, analyst_headers):
    assert client.get("/admin/retention").status_code == 401
    assert client.get("/admin/retention", headers=analyst_headers).status_code == 403
    r = client.get("/admin/retention", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["policy"]["alert_retention_days"] == 180 and r.json()["last_run"] is None


def test_a_run_writes_one_audit_entry_and_never_raises(soc_app):
    runner = soc_app.state.retention
    with soc_app.state.session_factory() as db:
        db.add(AuditEntry(actor_type="user", actor_name="a", action="old", details={},
                          at=datetime.now(UTC) - timedelta(days=999)))
        db.commit()
    retention.run_once(soc_app.state.session_factory, runner.settings, runner.state, pause=0)
    assert runner.state.counts["audit_log"] == 1 and runner.state.error is None
    with soc_app.state.session_factory() as db:
        entry = db.query(AuditEntry).filter_by(action="retention_prune").one()
        assert entry.details["counts"] == {"audit_log": 1}
    broken = retention.RunState()
    retention.run_once(lambda: (_ for _ in ()).throw(RuntimeError("boom")), runner.settings,
                       broken)
    assert broken.error and "RuntimeError" in broken.error


def test_blank_retention_settings_mean_default(monkeypatch):
    for name in ("ALERT_RETENTION_DAYS", "AUDIT_RETENTION_DAYS", "AUTO_MIGRATE",
                 "ALERT_RETENTION_KEEP_LABELLED"):
        monkeypatch.setenv(f"IDPS_SOC_{name}", "")
    s = SocSettings(jwt_secret=TEST_SECRET)
    assert (s.alert_retention_days, s.audit_retention_days, s.auto_migrate) == (180, 365, True)


# --- review fixes -----------------------------------------------------------------------------

def _shape(engine):
    insp = inspect(engine)
    return {t: (sorted(c["name"] for c in insp.get_columns(t)),
                sorted(i["name"] for i in insp.get_indexes(t)))
            for t in insp.get_table_names()}


def test_a_refused_adoption_changes_nothing(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'odd.db'}")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:  # an addable difference (index) AND an unfixable one
        conn.execute(text("DROP INDEX ix_alerts_dst_ip"))
        conn.execute(text("DROP TABLE model_versions"))
        conn.execute(text("ALTER TABLE users DROP COLUMN role"))
    before = _shape(engine)
    with pytest.raises(migrate.SchemaError, match="users.role"):
        init_db(engine)
    assert _shape(engine) == before


def test_the_baseline_does_not_depend_on_the_live_models():
    meta = migrate.baseline_metadata()
    # 0001 is frozen: the tables added by later migrations (0003: privacy and reports; 0004: IAM;
    # 0005: cloud) are not in it
    assert set(meta.tables) == set(Base.metadata.tables) - {
        "access_log", "erasure_records", "report_runs", "iam_roles", "iam_role_permissions",
        "iam_groups", "iam_group_members", "iam_group_roles", "iam_user_roles", "iam_policies",
        "iam_policy_attachments", "login_history", "cloud_vpcs", "cloud_subnets",
        "cloud_security_groups", "cloud_sg_rules", "cloud_instances", "cloud_instance_sgs",
        "cloud_volumes", "cloud_buckets", "cloud_alerts", "cloud_activity", "cloud_cost_daily"}
    assert meta is not Base.metadata
    assert "ix_blocks_alert_id" in {i.name for i in meta.tables["blocks"].indexes}


def test_ingest_keeps_working_during_a_sqlite_backup(tmp_path):
    import threading
    import time

    src = fresh(tmp_path, "live.db")
    seed(src)
    errors: list[Exception] = []
    stop = threading.Event()
    written = [0]

    def writer():
        eng = make_engine(f"sqlite:///{tmp_path / 'live.db'}")
        while not stop.is_set():
            try:
                with Session(eng) as db:
                    db.add(AuditEntry(actor_type="user", actor_name="w", action="x", details={}))
                    db.commit()
                written[0] += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
                return
            time.sleep(0.01)

    t = threading.Thread(target=writer)
    t.start()
    try:
        # progress() runs between tables while the backup's read snapshot is open: stretch it
        header = backup.backup(src, tmp_path / "b.gz", progress=lambda _m: time.sleep(0.4))
    finally:
        stop.set()
        t.join()
    assert errors == [] and written[0] > 3
    assert header["tables"]["alerts"]["rows"] == 1  # the snapshot predates later writes
    seen = header["tables"]["audit_log"]["rows"]
    with src.connect() as c:
        assert c.execute(text("SELECT count(*) FROM audit_log")).scalar() > seen


def _old_alerts(engine, n, days=400):
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(SensorToken.__table__.insert(), [
            {"id": 1, "name": "s", "token_hash": "h", "revoked": False, "created_at": now}])
        conn.execute(Alert.__table__.insert(), [
            {"sensor_id": 1, "received_at": now - timedelta(days=days, seconds=i),
             "src_ip": "1.1.1.1", "src_port": 1, "dst_ip": "2.2.2.2", "dst_port": 2, "protocol": 6,
             "start_ms": i, "end_ms": i, "predicted_class": "DoS", "confidence": 0.5,
             "severity": "low", "explanation": {}, "status": "new"} for i in range(n)])


def test_the_sqlite_candidate_query_walks_the_primary_key(tmp_path):
    from sqlalchemy import select

    engine = fresh(tmp_path)
    cond = retention._alert_condition(retention_settings(), datetime.now(UTC), plain_scan=True)
    sql = str(select(Alert.id).where(Alert.id > 5, cond).order_by(Alert.id).limit(500).compile(
        engine, compile_kwargs={"literal_binds": True}))
    with engine.connect() as conn:
        plan = " | ".join(r[3] for r in conn.exec_driver_sql("EXPLAIN QUERY PLAN " + sql))
    assert "TEMP B-TREE" not in plan and "MULTI-INDEX OR" not in plan, plan
    assert "INTEGER PRIMARY KEY" in plan, plan


def test_retention_time_grows_linearly(tmp_path):
    import time

    times = {}
    for n in (10_000, 40_000):
        engine = fresh(tmp_path, f"{n}.db")
        _old_alerts(engine, n)
        t0 = time.monotonic()
        with Session(engine) as db:
            assert retention.prune(db, retention_settings())["alerts"] == n
        times[n] = time.monotonic() - t0
    assert times[40_000] < times[10_000] * 4 * 2.5, times  # 4x the rows, well under quadratic (16x)


def test_a_foreign_key_column_is_not_an_additive_difference():
    import sqlalchemy as sa

    col = sa.Column("created_by_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    assert "foreign key" in migrate._not_additive(("add_column", None, "cases", col))
    plain = sa.Column("note", sa.Text, nullable=True)
    assert migrate._not_additive(("add_column", None, "cases", plain)) is None


def test_a_read_only_sqlite_file_can_be_read(tmp_path):
    import sqlite3

    path = tmp_path / "ro.db"
    conn = sqlite3.connect(path)  # rollback-journal mode, as an old SOC left it
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()
    path.chmod(0o444)
    try:
        engine = make_engine(f"sqlite:///{path}")
        with engine.connect() as c:
            assert c.execute(text("SELECT x FROM t")).scalar() == 1
    finally:
        path.chmod(0o644)


def test_a_failed_run_keeps_and_audits_what_it_deleted(soc_app, monkeypatch):
    runner = soc_app.state.retention
    _old_alerts(soc_app.state.engine, 5)
    monkeypatch.setattr(retention, "BATCH", 2)
    real, calls = retention._candidates, [0]

    def flaky(*a, **k):
        calls[0] += 1
        if calls[0] == 3:
            raise RuntimeError("boom")
        return real(*a, **k)

    monkeypatch.setattr(retention, "_candidates", flaky)
    retention.run_once(soc_app.state.session_factory, runner.settings, runner.state, pause=0)
    assert runner.state.counts["alerts"] == 4 and "RuntimeError" in runner.state.error
    with soc_app.state.session_factory() as db:
        entry = db.query(AuditEntry).filter_by(action="retention_prune").one()
        assert entry.details["counts"] == {"alerts": 4} and "RuntimeError" in entry.details["error"]


def test_a_case_reopened_during_the_run_keeps_its_notes_and_alerts(tmp_path, monkeypatch):
    from soc.api.models import CaseNote

    engine = fresh(tmp_path)
    old = datetime.now(UTC) - timedelta(days=400)
    with Session(engine) as db:
        db.add(SensorToken(id=1, name="s", token_hash="h" * 64))
        case = Case(title="c", status=CaseStatus.CLOSED, created_at=old, updated_at=old)
        db.add(case)
        db.flush()
        db.add(CaseNote(case_id=case.id, text="n", created_at=old))
        db.add(Alert(sensor_id=1, received_at=datetime.now(UTC), src_ip="1.1.1.1", src_port=1,
                     dst_ip="2.2.2.2", dst_port=2, protocol=6, start_ms=1, end_ms=2,
                     predicted_class="DoS", confidence=0.5, severity=Severity.LOW,
                     explanation={}, status=AlertStatus.NEW, case_id=case.id))
        db.commit()
    real = retention._candidates

    def reopen_after_choosing(db, model, cond, last):
        ids = real(db, model, cond, last)
        if model is Case and ids:
            with Session(engine) as other:  # an analyst reopens it between choose and delete
                other.query(Case).update({"status": CaseStatus.OPEN})
                other.commit()
        return ids

    monkeypatch.setattr(retention, "_candidates", reopen_after_choosing)
    with Session(engine) as db:
        counts = retention.prune(db, retention_settings(closed_case_retention_days=30))
    assert counts["cases"] == 0 and counts["case_notes"] == 0
    with Session(engine) as db:
        assert db.query(CaseNote).count() == 1 and db.query(Alert).one().case_id is not None


def test_prune_cli_needs_neither_the_jwt_secret_nor_a_migrated_database(tmp_path, monkeypatch,
                                                                        capsys):
    from soc.api import __main__ as cli

    monkeypatch.delenv("IDPS_SOC_JWT_SECRET", raising=False)
    url = f"sqlite:///{tmp_path / 'p.db'}"
    assert cli.main(["prune", "--dry-run", "--database-url", url]) == 1
    assert "db upgrade" in capsys.readouterr().err
    init_db(make_engine(url))
    assert cli.main(["prune", "--dry-run", "--database-url", url]) == 0
    assert "would delete" in capsys.readouterr().out


def test_prune_cli_audits_a_partial_run_with_its_error(tmp_path, monkeypatch, capsys):
    from soc.api import __main__ as cli

    url = f"sqlite:///{tmp_path / 'q.db'}"
    init_db(make_engine(url))

    def failing(db, settings, now=None, *, dry_run=False, counts=None, **_):
        counts["alerts"] = 3
        raise RuntimeError("boom")

    monkeypatch.setattr(retention, "prune", failing)
    assert cli.main(["prune", "--database-url", url]) == 1
    assert "RuntimeError" in capsys.readouterr().err
    with Session(make_engine(url)) as db:
        entry = db.query(AuditEntry).filter_by(action="retention_prune").one()
        assert entry.details["counts"] == {"alerts": 3} and "RuntimeError" in entry.details["error"]


def test_the_prune_cli_does_not_starve_a_concurrent_sqlite_writer(tmp_path, monkeypatch):
    import threading

    from soc.api import __main__ as cli
    from soc.api import db as db_module

    monkeypatch.setattr(db_module, "SQLITE_BUSY_TIMEOUT_MS", 200)  # a short wait: starvation shows
    path = tmp_path / "busy.db"
    url = f"sqlite:///{path}"
    engine = make_engine(url)
    init_db(engine)
    _old_alerts(engine, 60_000)
    errors, written, stop = [], [0], threading.Event()

    def writer():
        eng = make_engine(url)
        while not stop.is_set():
            try:
                with Session(eng) as db:
                    db.add(AuditEntry(actor_type="user", actor_name="w", action="x", details={}))
                    db.commit()
                written[0] += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
                return

    t = threading.Thread(target=writer)
    t.start()
    try:
        assert cli.main(["prune", "--database-url", url]) == 0
    finally:
        stop.set()
        t.join()
    assert errors == [] and written[0] > 5


def test_a_pass_that_gives_up_is_reported_in_the_error_and_the_audit_entry(soc_app, monkeypatch):
    import sqlalchemy as sa

    runner = soc_app.state.retention
    _old_alerts(soc_app.state.engine, 5)
    monkeypatch.setattr(retention, "BATCH", 2)
    monkeypatch.setattr(retention.time, "sleep", lambda _s: None)
    real, calls = retention._candidates, [0]

    def busy(*a, **k):
        calls[0] += 1
        if calls[0] >= 2:  # the first batch works; every attempt after that meets a lock
            raise sa.exc.OperationalError("x", {}, Exception("database is locked"))
        return real(*a, **k)

    monkeypatch.setattr(retention, "_candidates", busy)
    retention.run_once(soc_app.state.session_factory, runner.settings, runner.state, pause=0)
    assert runner.state.counts["alerts"] == 2
    assert "alerts: pass stopped after a lock conflict" in runner.state.error
    with soc_app.state.session_factory() as db:
        entry = db.query(AuditEntry).filter_by(action="retention_prune").one()
        assert "lock conflict" in entry.details["error"]
