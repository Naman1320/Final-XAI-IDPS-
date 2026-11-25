# ruff: noqa: F811  (fixtures imported from step10_helpers)
"""Migration 0004 (IAM tables and the seeded system roles): upgrade, downgrade, upgrade again, no
drift from the models, foreign keys. SQLite always; PostgreSQL when IDPS_TEST_DATABASE_URL is set."""

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text
from step10_helpers import any_engine, pg_engine  # noqa: F401

from soc.api import migrate
from soc.api.iam.catalog import ALL_PERMISSIONS

NEW_TABLES = {"iam_roles", "iam_role_permissions", "iam_groups", "iam_group_members",
              "iam_group_roles", "iam_user_roles", "iam_policies", "iam_policy_attachments",
              "login_history"}
NOW = "'2026-01-02 03:04:05.000000'"


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


def _scalar(engine, sql):
    with engine.connect() as conn:
        value = conn.execute(text(sql)).scalar()
        conn.rollback()
    return value


def test_the_chain():
    script = migrate._script()
    assert script.get_revision("0005_cloud").down_revision == "0004_iam"
    assert script.get_revision("0004_iam").down_revision == "0003_privacy_reports"


def test_upgrade_creates_the_tables_and_matches_the_models(any_engine):
    _step(any_engine, "upgrade", "0003_privacy_reports")
    assert not NEW_TABLES & _tables(any_engine)
    _step(any_engine, "upgrade", "head")
    assert _revision(any_engine) == migrate.head_revision()
    assert NEW_TABLES <= _tables(any_engine)
    assert migrate.check(any_engine) == []  # no drift from soc.api.models


def test_indexes_and_uniqueness(any_engine):
    _step(any_engine, "upgrade", "0004_iam")
    assert {"ix_login_history_at", "ix_login_history_username",
            "ix_login_history_user_id"} <= _indexes(any_engine, "login_history")
    insert_role = text("INSERT INTO iam_roles (name, description, system, created_at, updated_at) "
                       f"VALUES (:n, '', false, {NOW}, {NOW})")
    with any_engine.begin() as conn:
        conn.execute(insert_role, {"n": "custom"})
    with pytest.raises(sa.exc.IntegrityError), any_engine.begin() as conn:
        conn.execute(insert_role, {"n": "custom"})
    with pytest.raises(sa.exc.IntegrityError), any_engine.begin() as conn:  # the seeded name
        conn.execute(insert_role, {"n": "admin"})


def test_system_roles_are_seeded(any_engine):
    _step(any_engine, "upgrade", "head")
    with any_engine.connect() as conn:
        roles = conn.execute(text("SELECT id, name, system FROM iam_roles ORDER BY id")).all()
        perms = conn.execute(text("SELECT role_id, permission FROM iam_role_permissions")).all()
        conn.rollback()
    assert [(r[1], bool(r[2])) for r in roles] == [("admin", True), ("analyst", True)]
    by_role: dict[int, set[str]] = {}
    for rid, perm in perms:
        by_role.setdefault(rid, set()).add(perm)
    assert by_role[roles[0][0]] == ALL_PERMISSIONS  # the seed equals today's catalog
    assert by_role[roles[1][0]] == {"cloud.view"}


def test_columns_and_nullability(any_engine):
    _step(any_engine, "upgrade", "head")
    cols = {c["name"]: c for c in inspect(any_engine).get_columns("login_history")}
    assert set(cols) == {"id", "at", "user_id", "username", "success", "reason", "ip",
                         "user_agent", "mfa_used"}
    assert cols["user_id"]["nullable"] is True and cols["username"]["nullable"] is False
    pol = {c["name"] for c in inspect(any_engine).get_columns("iam_policies")}
    assert pol == {"id", "name", "description", "effect", "permissions", "resources", "disabled",
                   "created_at"}


def test_foreign_keys_cascade(any_engine):
    _step(any_engine, "upgrade", "head")
    fks = {}
    for table in NEW_TABLES:
        for fk in inspect(any_engine).get_foreign_keys(table):
            fks[(table, fk["referred_table"])] = (fk.get("options") or {}).get("ondelete")
    assert fks[("iam_role_permissions", "iam_roles")] == "CASCADE"
    assert fks[("iam_group_members", "iam_groups")] == "CASCADE"
    assert fks[("iam_group_members", "users")] == "CASCADE"
    assert fks[("iam_group_roles", "iam_roles")] == "CASCADE"
    assert fks[("iam_user_roles", "users")] == "CASCADE"
    assert fks[("iam_policy_attachments", "iam_policies")] == "CASCADE"
    assert fks[("login_history", "users")] == "SET NULL"


def test_the_database_cascades_when_foreign_keys_are_enforced(any_engine):
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        if any_engine.dialect.name == "sqlite":
            conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.execute(text("INSERT INTO users (username, password_hash, role, disabled, "
                          f"token_version, created_at, mfa_enabled) VALUES ('u', 'x', 'analyst', "
                          f"false, 0, {NOW}, false)"))
        uid = conn.execute(text("SELECT id FROM users")).scalar()
        conn.execute(text("INSERT INTO iam_groups (name, description, created_at) "
                          f"VALUES ('g', '', {NOW})"))
        gid = conn.execute(text("SELECT id FROM iam_groups")).scalar()
        conn.execute(text("INSERT INTO iam_group_members (group_id, user_id) VALUES (:g, :u)"),
                     {"g": gid, "u": uid})
        conn.execute(text("INSERT INTO iam_user_roles (user_id, role_id) VALUES (:u, 1)"),
                     {"u": uid})
        conn.execute(text("INSERT INTO login_history (at, user_id, username, success, reason, "
                          f"ip, user_agent, mfa_used) VALUES ({NOW}, :u, 'u', true, 'ok', '', '', "
                          "false)"), {"u": uid})
        conn.execute(text("DELETE FROM users WHERE id = :u"), {"u": uid})
        assert conn.execute(text("SELECT count(*) FROM iam_group_members")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM iam_user_roles")).scalar() == 0
        # the history stays, with no user
        assert conn.execute(text("SELECT user_id FROM login_history")).all() == [(None,)]
        conn.execute(text("DELETE FROM iam_roles WHERE id = 2"))
        assert conn.execute(text("SELECT count(*) FROM iam_role_permissions "
                                 "WHERE role_id = 2")).scalar() == 0


def test_downgrade_removes_only_the_new_tables_and_keeps_data(any_engine):
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (at, actor_type, actor_name, action, target, "
                          f"details) VALUES ({NOW}, 'user', 'a', 'x', '', '{{}}')"))
    _step(any_engine, "downgrade", "0003_privacy_reports")
    assert _revision(any_engine) == "0003_privacy_reports"
    assert not NEW_TABLES & _tables(any_engine)
    assert {"users", "alerts", "audit_log", "access_log"} <= _tables(any_engine)
    assert _scalar(any_engine, "SELECT count(*) FROM audit_log") == 1
    _step(any_engine, "upgrade", "head")  # and up again, seeds included
    assert NEW_TABLES <= _tables(any_engine) and migrate.check(any_engine) == []
    assert _scalar(any_engine, "SELECT count(*) FROM iam_roles") == 2


def test_downgrade_all_the_way_and_back(any_engine):
    _step(any_engine, "upgrade", "head")
    _step(any_engine, "downgrade", "0001_initial")
    assert not NEW_TABLES & _tables(any_engine)
    _step(any_engine, "upgrade", "head")
    assert migrate.check(any_engine) == []


def test_fresh_database_goes_straight_to_head_with_seeds(any_engine):
    with any_engine.begin() as conn:
        migrate.upgrade(conn)
    assert _revision(any_engine) == migrate.head_revision()
    assert _scalar(any_engine, "SELECT count(*) FROM iam_roles WHERE system") == 2


def test_the_migration_does_not_import_the_models():
    import soc.api.migrations.versions as v

    with open(v.__path__[0] + "/0004_iam.py") as f:
        source = f.read()
    imports = [ln for ln in source.splitlines() if ln.startswith(("import ", "from "))]
    assert not [ln for ln in imports if "soc" in ln], imports


def test_previous_postgres_seed_is_repaired(pg_engine):
    _step(pg_engine, "upgrade", "0005_cloud")
    with pg_engine.begin() as conn:
        conn.execute(text("SELECT setval(pg_get_serial_sequence('iam_roles', 'id'), 1, false)"))
    _step(pg_engine, "upgrade", "head")
    with pg_engine.begin() as conn:
        assert conn.scalar(text("SELECT nextval(pg_get_serial_sequence('iam_roles','id'))")) > 2
