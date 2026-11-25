"""Migration 0003 (access log, erasure records, report runs): upgrade, downgrade, upgrade again,
and that it matches the models. Runs on SQLite, and on PostgreSQL when IDPS_TEST_DATABASE_URL is set."""

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text
from step10_helpers import any_engine  # noqa: F401

from soc.api import migrate

NEW_TABLES = {"access_log", "erasure_records", "report_runs"}
INDEXES = {
    "access_log": {"ix_access_log_at", "ix_access_log_username", "ix_access_log_action",
                   "ix_access_log_subject_fp"},
    "erasure_records": {"ix_erasure_records_at", "ix_erasure_records_subject_fp"},
    "report_runs": {"ix_report_runs_week"},
}


def _step(engine, op, target):
    with engine.begin() as conn:
        getattr(migrate.command, op)(migrate.alembic_config(conn), target)


def _revision(engine):
    with engine.connect() as conn:
        rev = migrate.current_revision(conn)
        conn.rollback()
    return rev


def _tables(engine):
    return set(inspect(engine).get_table_names())


def _indexes(engine, table):
    return {i["name"] for i in inspect(engine).get_indexes(table)}


def test_0003_is_in_the_chain():
    assert migrate._script().get_revision("0004_iam").down_revision == "0003_privacy_reports"


def test_upgrade_creates_the_tables_and_matches_the_models(any_engine):
    _step(any_engine, "upgrade", "0002_mfa_oidc")
    assert not NEW_TABLES & _tables(any_engine)
    _step(any_engine, "upgrade", "head")
    assert _revision(any_engine) == migrate.head_revision()
    assert NEW_TABLES <= _tables(any_engine)
    for table, names in INDEXES.items():
        assert names <= _indexes(any_engine, table), table
    assert migrate.check(any_engine) == []  # no drift from soc.api.models


def test_columns(any_engine):
    _step(any_engine, "upgrade", "head")
    cols = {t: {c["name"]: c for c in inspect(any_engine).get_columns(t)} for t in NEW_TABLES}
    assert set(cols["access_log"]) == {"id", "at", "user_id", "username", "action", "target_type",
                                       "target", "subject_fp"}
    assert cols["access_log"]["subject_fp"]["nullable"] is True
    assert cols["access_log"]["user_id"]["nullable"] is True
    assert set(cols["erasure_records"]) == {"id", "at", "requested_by", "reason", "subject_fp",
                                            "counts"}
    assert cols["erasure_records"]["subject_fp"]["nullable"] is False
    assert set(cols["report_runs"]) == {"id", "week", "generated_at", "emailed_at",
                                        "recipients_count", "error"}
    assert cols["report_runs"]["emailed_at"]["nullable"] is True


def test_report_runs_week_is_unique(any_engine):
    _step(any_engine, "upgrade", "head")
    insert = text("INSERT INTO report_runs (week, generated_at, recipients_count) "
                  "VALUES (:w, '2026-01-02 03:04:05.000000', 0)")
    with any_engine.begin() as conn:
        conn.execute(insert, {"w": "2026-W01"})
    with pytest.raises(sa.exc.IntegrityError):
        with any_engine.begin() as conn:
            conn.execute(insert, {"w": "2026-W01"})
    with any_engine.begin() as conn:
        conn.execute(insert, {"w": "2026-W02"})


def test_downgrade_removes_only_the_new_tables_and_keeps_data(any_engine):
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (at, actor_type, actor_name, action, target, "
                          "details) VALUES ('2026-01-02 03:04:05.000000', 'user', 'a', 'x', '', "
                          "'{}')"))
        conn.execute(text("INSERT INTO access_log (at, username, action, target_type, target) "
                          "VALUES ('2026-01-02 03:04:05.000000', 'a', 'alert_view', '', '')"))
    _step(any_engine, "downgrade", "0002_mfa_oidc")
    assert _revision(any_engine) == "0002_mfa_oidc"
    assert not NEW_TABLES & _tables(any_engine)
    assert {"users", "alerts", "audit_log"} <= _tables(any_engine)
    with any_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() == 1
        conn.rollback()
    _step(any_engine, "upgrade", "head")  # and up again
    assert NEW_TABLES <= _tables(any_engine) and migrate.check(any_engine) == []


def test_fresh_database_goes_straight_to_head(any_engine):
    with any_engine.begin() as conn:
        migrate.upgrade(conn)
    assert NEW_TABLES <= _tables(any_engine)
    assert _revision(any_engine) == migrate.head_revision()


def test_the_migration_does_not_import_the_models():
    import soc.api.migrations.versions as v

    path = v.__path__[0] + "/0003_privacy_reports.py"
    source = open(path).read()
    imports = [ln for ln in source.splitlines() if ln.startswith(("import ", "from "))]
    assert not [ln for ln in imports if "soc" in ln], imports
