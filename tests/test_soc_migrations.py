# ruff: noqa: F811  (fixtures imported from step10_helpers)
"""Step 10: migration 0001, adoption of old databases, ensure_schema modes, concurrency."""

import threading

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text
from step10_helpers import ON_PG, any_engine, migrated, needs_pg, pg_engine, tables_in  # noqa: F401

from soc.api import __main__ as cli
from soc.api import migrate
from soc.api.db import Base, init_db, make_engine

OLD = migrate.baseline_metadata  # the schema of every pre-migration database (0001)

BASE = migrate.BASELINE
HEAD = migrate.head_revision()  # what a fresh or adopted database ends at


def _versions(engine):
    with engine.connect() as c:
        return [r[0] for r in c.execute(text("SELECT version_num FROM alembic_version"))]


def test_migration_matches_models_exactly(any_engine):
    migrated(any_engine)
    assert tables_in(any_engine) == {*Base.metadata.tables, "alembic_version"}
    with any_engine.connect() as conn:
        from alembic.autogenerate import compare_metadata
        from alembic.runtime.migration import MigrationContext

        ctx = MigrationContext.configure(conn, opts={"compare_type": True,
                                                     "compare_server_default": False})
        assert compare_metadata(ctx, Base.metadata) == []
        conn.rollback()
    assert migrate.check(any_engine) == []
    assert _versions(any_engine) == [HEAD]


def test_db_check_cli_exit_codes(tmp_path, capsys):
    url = f"sqlite:///{tmp_path / 'c.db'}"
    assert cli.main(["db", "check", "--database-url", url]) == 1  # empty: not at head
    assert "head" in capsys.readouterr().err
    assert cli.main(["db", "upgrade", "--database-url", url]) == 0
    assert cli.main(["db", "current", "--database-url", url]) == 0
    assert HEAD in capsys.readouterr().out
    assert cli.main(["db", "check", "--database-url", url]) == 0
    engine = make_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_alerts_src_ip"))
    assert cli.main(["db", "check", "--database-url", url]) == 1
    assert "ix_alerts_src_ip" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        cli.main(["db", "bogus"])
    assert exc.value.code == 2


def test_downgrade_to_base_then_upgrade(any_engine):
    migrated(any_engine)
    with any_engine.begin() as conn:
        migrate.command.downgrade(migrate.alembic_config(conn), "base")
    assert tables_in(any_engine) == {"alembic_version"}
    with any_engine.begin() as conn:
        migrate.upgrade(conn)
    assert migrate.check(any_engine) == []


def _old_db(engine, drop_cols=(), drop_tables=()):
    """A database as before step 10: create_all, then rebuild some tables without columns."""
    OLD().create_all(engine)
    with engine.begin() as conn:
        for t in drop_tables:
            conn.execute(text(f"DROP TABLE {t}"))
        for table, col in drop_cols:
            idx = [i for i in inspect(conn).get_indexes(table) if col in i["column_names"]]
            for i in idx:
                conn.execute(text(f"DROP INDEX {i['name']}"))
            conn.execute(text(f"ALTER TABLE {table} DROP COLUMN {col}"))


def test_adoption_of_a_pre_step_10_database_keeps_data(any_engine):
    _old_db(any_engine, drop_cols=[("alerts", "features"), ("alerts", "model_version"),
                                   ("alerts", "model_sha256"), ("alerts", "rule")],
            drop_tables=["model_versions"])
    with any_engine.begin() as conn:
        conn.execute(text("INSERT INTO users (username, password_hash, role, disabled, "
                          "token_version, created_at) VALUES ('keep','h','admin',false,0,"
                          "'2026-01-01 00:00:00')"))
    assert "model_versions" not in tables_in(any_engine)
    init_db(any_engine)
    assert _versions(any_engine) == [HEAD]
    assert "model_versions" in tables_in(any_engine)
    cols = {c["name"] for c in inspect(any_engine).get_columns("alerts")}
    assert {"features", "model_version", "model_sha256", "rule"} <= cols
    assert migrate.check(any_engine) == []
    with any_engine.connect() as c:
        assert c.execute(text("SELECT username FROM users")).scalar() == "keep"


def test_adoption_refuses_a_missing_non_nullable_column(any_engine):
    _old_db(any_engine, drop_cols=[("alerts", "src_ip")])
    with pytest.raises(migrate.SchemaError, match="src_ip"):
        init_db(any_engine)
    assert "alembic_version" not in tables_in(any_engine)


def test_adoption_adds_a_missing_index(any_engine):
    # The old temporary upgrade only indexed columns it added, so old databases lack some of the
    # declared indexes on older columns (the lab had no ix_alerts_received_class_anomaly).
    OLD().create_all(any_engine)
    with any_engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_alerts_dst_ip"))
        conn.execute(text("DROP INDEX ix_alerts_received_class_anomaly"))
    assert sorted(migrate.adopt(any_engine)) == [
        "index ix_alerts_dst_ip", "index ix_alerts_received_class_anomaly"]
    names = {i["name"] for i in inspect(any_engine).get_indexes("alerts")}
    assert {"ix_alerts_dst_ip", "ix_alerts_received_class_anomaly"} <= names
    with any_engine.begin() as conn:  # adoption stamps the baseline; later revisions follow
        migrate.upgrade(conn)
    assert migrate.check(any_engine) == []


def test_adoption_refuses_a_missing_required_column_with_a_one_line_error(any_engine):
    OLD().create_all(any_engine)
    with any_engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN role"))
    with pytest.raises(migrate.SchemaError, match="users.role") as exc:
        init_db(any_engine)
    assert "alembic_version" not in tables_in(any_engine)
    assert "\n" not in str(exc.value)


def test_adoption_via_cli_reports_a_clear_error(tmp_path, capsys):
    url = f"sqlite:///{tmp_path / 'o.db'}"
    engine = make_engine(url)
    _old_db(engine, drop_cols=[("alerts", "src_ip")])
    assert cli.main(["db", "upgrade", "--database-url", url]) == 1
    assert "cannot adopt" in capsys.readouterr().err


def test_auto_migrate_off_behind_refused_empty_still_migrates(tmp_path, monkeypatch):
    empty = make_engine(f"sqlite:///{tmp_path / 'e.db'}")
    init_db(empty, auto_migrate=False)  # empty database: migrates anyway
    assert _versions(empty) == [HEAD]
    monkeypatch.setattr(migrate, "head_revision", lambda: "0002_next")
    with pytest.raises(migrate.SchemaError, match="db upgrade"):
        init_db(empty, auto_migrate=False)
    # an unknown (newer) revision is refused whatever auto_migrate says
    with empty.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num='9999_future'"))
    for flag in (True, False):
        with pytest.raises(migrate.SchemaError, match="newer"):
            init_db(empty, auto_migrate=flag)


def test_a_database_with_no_model_tables_is_treated_as_empty(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'b.db'}")
    init_db(engine)
    with engine.begin() as conn:
        migrate.command.downgrade(migrate.alembic_config(conn), "base")
        conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version "
                          "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"))
    init_db(engine, auto_migrate=False)  # no revision, no model tables: treated as empty
    assert _versions(engine) == [HEAD]


@needs_pg
def test_concurrent_ensure_schema_on_postgres(pg_engine):
    errors, barrier = [], threading.Barrier(4)

    def go():
        engine = make_engine(pg_engine.url.render_as_string(hide_password=False))
        try:
            barrier.wait()
            migrate.ensure_schema(engine)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
        finally:
            engine.dispose()

    threads = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    assert _versions(pg_engine) == [HEAD]
    assert migrate.check(pg_engine) == []


@needs_pg
def test_concurrent_adoption_on_postgres(pg_engine):
    OLD().create_all(pg_engine)
    errors, barrier = [], threading.Barrier(3)

    def go():
        engine = make_engine(pg_engine.url.render_as_string(hide_password=False))
        try:
            barrier.wait()
            migrate.ensure_schema(engine)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
        finally:
            engine.dispose()

    threads = [threading.Thread(target=go) for _ in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    assert _versions(pg_engine) == [HEAD]


@needs_pg
def test_advisory_lock_is_released(pg_engine):
    migrated(pg_engine)
    with pg_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM pg_locks WHERE locktype='advisory'")
                         ).scalar() == 0
    assert sa.inspect(pg_engine).has_table("alembic_version")


def test_adoption_refuses_when_a_missing_unique_index_breaks_on_the_data(any_engine):
    OLD().create_all(any_engine)
    with any_engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_users_username"))
        for _ in range(2):  # raw SQL: the old schema has no MFA columns for the ORM to fill
            conn.execute(text("INSERT INTO users (username, password_hash, role, disabled, "
                              "token_version, created_at) VALUES ('dup', 'x', 'analyst', false, "
                              "0, '2026-01-01 00:00:00')"))
    with pytest.raises(migrate.SchemaError, match="ix_users_username") as exc:
        migrate.adopt(any_engine)
    assert "\n" not in str(exc.value)
    assert "alembic_version" not in tables_in(any_engine)
