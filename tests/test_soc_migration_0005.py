# ruff: noqa: F811  (fixtures imported from step10_helpers)
"""Migration 0005 (the cloud tables): upgrade, downgrade, upgrade again, no drift from the models.
SQLite always; PostgreSQL when IDPS_TEST_DATABASE_URL is set."""

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text
from step10_helpers import any_engine  # noqa: F401

from soc.api import migrate

NEW_TABLES = {"cloud_vpcs", "cloud_subnets", "cloud_security_groups", "cloud_sg_rules",
              "cloud_instances", "cloud_instance_sgs", "cloud_volumes", "cloud_buckets",
              "cloud_alerts", "cloud_activity", "cloud_cost_daily"}
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


def test_the_chain():
    script = migrate._script()
    assert script.get_revision(migrate.head_revision()).down_revision == "0005_cloud"
    assert script.get_revision("0005_cloud").down_revision == "0004_iam"


def test_upgrade_creates_the_tables_and_matches_the_models(any_engine):
    _step(any_engine, "upgrade", "0004_iam")
    assert not NEW_TABLES & _tables(any_engine)
    _step(any_engine, "upgrade", "head")
    assert _revision(any_engine) == migrate.head_revision()
    assert NEW_TABLES <= _tables(any_engine)
    assert migrate.check(any_engine) == []  # no drift from soc.api.models
    with any_engine.connect() as conn:  # no rows: the application seeds on first access
        for table in NEW_TABLES:
            assert conn.execute(text(f"SELECT count(*) FROM {table}")).scalar() == 0
        conn.rollback()


def test_indexes_columns_and_keys(any_engine):
    _step(any_engine, "upgrade", "head")
    insp = inspect(any_engine)
    idx = {i["name"] for t in NEW_TABLES for i in insp.get_indexes(t)}
    assert {"ix_cloud_instances_state", "ix_cloud_instances_az", "ix_cloud_alerts_status",
            "ix_cloud_activity_at", "ix_cloud_activity_actor", "ix_cloud_sg_rules_sg_id",
            "ix_cloud_volumes_instance_id"} <= idx
    cols = {c["name"]: c for c in insp.get_columns("cloud_instances")}
    assert set(cols) == {"id", "name", "instance_type", "state", "az", "vpc_id", "subnet_id",
                         "private_ip", "public_ip", "os", "vcpus", "memory_gb", "disk_gb", "tags",
                         "launched_at", "updated_at"}
    assert cols["public_ip"]["nullable"] is True and cols["tags"]["nullable"] is False
    assert insp.get_pk_constraint("cloud_cost_daily")["constrained_columns"] == ["day", "service"]
    assert insp.get_pk_constraint("cloud_buckets")["constrained_columns"] == ["name"]
    fks = {(t, fk["referred_table"]): (fk.get("options") or {}).get("ondelete")
           for t in NEW_TABLES for fk in insp.get_foreign_keys(t)}
    assert fks[("cloud_subnets", "cloud_vpcs")] == "CASCADE"
    assert fks[("cloud_sg_rules", "cloud_security_groups")] == "CASCADE"
    assert fks[("cloud_instance_sgs", "cloud_instances")] == "CASCADE"
    assert fks[("cloud_volumes", "cloud_instances")] == "SET NULL"
    with pytest.raises(sa.exc.IntegrityError), any_engine.begin() as conn:
        for _ in range(2):
            conn.execute(text("INSERT INTO cloud_cost_daily (day, service, amount_usd, currency) "
                              "VALUES ('2026-01-01', 'compute', 1.0, 'USD')"))


def test_the_database_cascades_when_foreign_keys_are_enforced(any_engine):
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        if any_engine.dialect.name == "sqlite":
            conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.execute(text("INSERT INTO cloud_vpcs (id, name, cidr) VALUES ('vpc-1', 'v', "
                          "'10.0.0.0/16')"))
        conn.execute(text("INSERT INTO cloud_security_groups (id, name, description, vpc_id) "
                          "VALUES ('sg-1', 'g', '', 'vpc-1')"))
        conn.execute(text("INSERT INTO cloud_sg_rules (sg_id, direction, protocol, port_from, "
                          "port_to, cidr, description) VALUES ('sg-1', 'in', 'tcp', 1, 1, "
                          "'10.0.0.0/8', '')"))
        conn.execute(text("DELETE FROM cloud_vpcs WHERE id = 'vpc-1'"))
        assert conn.execute(text("SELECT count(*) FROM cloud_security_groups")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM cloud_sg_rules")).scalar() == 0


def test_downgrade_removes_only_the_cloud_tables_and_keeps_the_rest(any_engine):
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (at, actor_type, actor_name, action, target, "
                          f"details) VALUES ({NOW}, 'user', 'a', 'x', '', '{{}}')"))
    _step(any_engine, "downgrade", "0004_iam")
    assert _revision(any_engine) == "0004_iam"
    assert not NEW_TABLES & _tables(any_engine)
    assert {"users", "alerts", "audit_log", "iam_roles", "login_history"} <= _tables(any_engine)
    with any_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() == 1
        assert conn.execute(text("SELECT count(*) FROM iam_roles")).scalar() == 2
        conn.rollback()
    _step(any_engine, "upgrade", "head")
    assert NEW_TABLES <= _tables(any_engine) and migrate.check(any_engine) == []


def test_downgrade_all_the_way_and_back(any_engine):
    _step(any_engine, "upgrade", "head")
    _step(any_engine, "downgrade", "0001_initial")
    assert not NEW_TABLES & _tables(any_engine)
    _step(any_engine, "upgrade", "head")
    assert migrate.check(any_engine) == []


def test_the_migration_does_not_import_the_models():
    import soc.api.migrations.versions as v

    with open(v.__path__[0] + "/0005_cloud.py") as f:
        source = f.read()
    imports = [ln for ln in source.splitlines() if ln.startswith(("import ", "from "))]
    assert not [ln for ln in imports if "soc" in ln], imports
