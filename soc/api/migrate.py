"""Running the SOC's Alembic migrations: start-up, adoption of old databases, drift checks.

The Alembic configuration is built here in code (script location "soc.api:migrations"), so it
works from an installed package without an alembic.ini. Every command runs on a connection that
the caller owns and commits (see migrations/env.py).
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator

import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Connection, Engine

from soc.api.db import Base, upgrade_schema

log = logging.getLogger("soc.migrate")

BASELINE = "0001_initial"  # the schema of every database made before migrations existed
# pg_advisory_lock key (arbitrary, fixed): two SOC processes starting together must not migrate
# at once. Session-level, so it is held on its own connection around the whole migration.
ADVISORY_KEY = 7_319_204_551


class SchemaError(RuntimeError):
    """The database cannot be used as it is (message is one line, for the operator)."""


def alembic_config(connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "soc.api:migrations")
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(alembic_config())


def head_revision() -> str:
    return _script().get_current_head()


def known_revision(revision: str) -> bool:
    try:
        return _script().get_revision(revision) is not None
    except Exception:  # noqa: BLE001  alembic raises CommandError/ResolutionError
        return False


def current_revision(conn: Connection) -> str | None:
    return MigrationContext.configure(conn).get_current_revision()


def upgrade(conn: Connection, target: str = "head") -> None:
    command.upgrade(alembic_config(conn), target)


def stamp(conn: Connection, revision: str) -> None:
    command.stamp(alembic_config(conn), revision)


@contextlib.contextmanager
def migration_lock(engine: Engine) -> Iterator[None]:
    """PostgreSQL: hold pg_advisory_lock(ADVISORY_KEY) for the block (a second process waits, then
    finds the work done). No-op on other databases (SQLite serialises writers itself)."""
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as conn:
        conn.execute(sa.text("SELECT pg_advisory_lock(:k)"), {"k": ADVISORY_KEY})
        conn.commit()
        try:
            yield
        finally:
            conn.rollback()
            conn.execute(sa.text("SELECT pg_advisory_unlock(:k)"), {"k": ADVISORY_KEY})
            conn.commit()


# --- schema comparison ------------------------------------------------------------------------

def baseline_metadata() -> sa.MetaData:
    """The schema of revision BASELINE, with the migration's own dialect-neutral types
    (versions/0001_initial.tables): independent of the live models, which move on."""
    metadata = sa.MetaData()
    _script().get_revision(BASELINE).module.tables(metadata)
    return metadata


def _name(x: object) -> str:
    if isinstance(x, sa.Table):
        return x.name
    if isinstance(x, sa.Column):
        return f"{x.table.name}.{x.name}" if x.table is not None else x.name
    if isinstance(x, sa.Index | sa.Constraint):
        return str(x.name or getattr(x, "table", "")) or type(x).__name__
    return str(x)


def raw_differences(conn: Connection, metadata: sa.MetaData | None = None) -> list[tuple]:
    """Alembic's compare_metadata tuples between the database and `metadata` (default: the live
    models), flattened. Ignored as harmless: tables and indexes the database has and the metadata
    does not."""
    if metadata is None:
        from soc.api import models  # noqa: F401

        metadata = Base.metadata
    ctx = MigrationContext.configure(
        conn, opts={"compare_type": True, "compare_server_default": False})
    found: list[tuple] = []

    def walk(items) -> None:
        for d in items:
            if isinstance(d, list):
                walk(d)
            elif d[0] not in ("remove_table", "remove_index"):
                found.append(d)

    walk(compare_metadata(ctx, metadata))
    return found


def describe(d: tuple) -> str:
    op = d[0]
    if op.startswith("modify_"):  # (op, schema, table, column, kw, existing, new)
        return f"{d[2]}.{d[3]}: {op[7:]} is {d[5]!r} in the database, {d[6]!r} expected"
    if op in ("add_column", "remove_column"):  # (op, schema, table, column)
        return f"{op.replace('_', ' ')} {d[2]}.{d[3].name}"
    return f"{op.replace('_', ' ')} {_name(d[1])}"


def schema_differences(conn: Connection, metadata: sa.MetaData | None = None) -> list[str]:
    return [describe(d) for d in raw_differences(conn, metadata)]


def _not_additive(d: tuple) -> str | None:
    """Why adoption may not fix difference `d` (None: it is a plain addition it may make)."""
    op = d[0]
    if op == "add_table":
        return None
    if op == "add_column":
        col = d[3]
        if col.foreign_keys:  # upgrade_schema adds the column without its REFERENCES
            return f"{d[2]}.{col.name} is missing and cannot be added (it is a foreign key)"
        return None if col.nullable and not col.primary_key else (
            f"{d[2]}.{col.name} is missing and cannot be added (it is not nullable)")
    if op == "add_index":
        return (f"unique index {d[1].name} is missing and cannot be added safely"
                if d[1].unique else None)
    return describe(d)


# --- start-up ---------------------------------------------------------------------------------

def _run(engine: Engine, fn) -> None:
    with engine.begin() as conn:  # one transaction: PostgreSQL rolls a failed migration back
        fn(conn)


def adopt(engine: Engine) -> list[str]:
    """Take over a database made before migrations existed (it has tables but no
    alembic_version). First compare it with the baseline schema WITHOUT touching it: only
    additions an old release could lack are allowed (missing nullable columns, tables, and
    non-unique declared indexes); anything else raises SchemaError and nothing is changed. Then
    add them (db.upgrade_schema for columns, create_all for tables, the missing indexes), check it
    now equals the baseline, and stamp BASELINE. Returns what was added."""
    reference = baseline_metadata()
    with engine.connect() as conn:
        diffs = raw_differences(conn, reference)
        conn.rollback()
    refused = [why for d in diffs if (why := _not_additive(d))]
    if refused:
        raise SchemaError(
            "cannot adopt this database, it differs from the expected schema: "
            + "; ".join(refused[:10]) + (" ..." if len(refused) > 10 else "")
            + ". Fix it by hand or restore from a backup; nothing was changed")
    try:
        added = upgrade_schema(engine, reference)
    except RuntimeError as exc:
        raise SchemaError(f"cannot adopt this database: {exc}") from exc
    before = set(inspect(engine).get_table_names())
    reference.create_all(engine)  # tables an older release did not have yet (never alters others)
    added += [f"table {t}" for t in sorted(set(inspect(engine).get_table_names()) - before)]
    # Indexes the baseline declares on columns an older release already had: the old temporary
    # upgrade only indexed columns it added itself, so such databases lack them (seen in the lab:
    # ix_alerts_received_class_anomaly). Adding an index changes no data.
    for table in reference.sorted_tables:
        have = {i["name"] for i in inspect(engine).get_indexes(table.name)}
        for index in sorted(table.indexes, key=lambda i: i.name or ""):
            if index.name and index.name not in have:
                try:
                    index.create(engine)
                except sa.exc.DBAPIError as exc:
                    raise SchemaError(
                        f"cannot adopt this database: index {index.name} could not be created "
                        f"({type(exc.orig).__name__}); fix the data or restore from a backup"
                    ) from exc
                added.append(f"index {index.name}")
    with engine.connect() as conn:
        left = schema_differences(conn, reference)
        conn.rollback()
    if left:
        raise SchemaError("cannot adopt this database, it still differs after the additions: "
                          + "; ".join(left[:10]))
    _run(engine, lambda c: stamp(c, BASELINE))
    log.warning("adopted a pre-migration database (stamped %s)%s", BASELINE,
                f"; added {', '.join(added)}" if added else "")
    return added


def ensure_schema(engine: Engine, auto_migrate: bool = True) -> None:
    from soc.api import models  # noqa: F401

    with migration_lock(engine):
        with engine.connect() as conn:
            current = current_revision(conn)
            conn.rollback()
        head = head_revision()
        if current is not None:
            if current == head:
                return
            if not known_revision(current):
                raise SchemaError(
                    f"the database is at revision {current!r}, which this version of the SOC does "
                    "not know (it is newer): upgrade the SOC")
            if not auto_migrate:
                raise SchemaError(
                    f"the database is at revision {current!r} but this SOC needs {head!r} and "
                    "IDPS_SOC_AUTO_MIGRATE is off: run `python -m soc.api db upgrade`")
            _run(engine, upgrade)
            return
        existing = set(inspect(engine).get_table_names()) & set(Base.metadata.tables)
        if existing:
            adopt(engine)
        _run(engine, upgrade)


def check(engine: Engine) -> list[str]:
    """Problems for `db check`: not at head, or the schema differs from the models. Empty = ok."""
    problems: list[str] = []
    with engine.connect() as conn:
        current = current_revision(conn)
        head = head_revision()
        if current != head:
            problems.append(f"database revision is {current!r}, head is {head!r}")
        else:
            problems += [f"schema drift: {d}" for d in schema_differences(conn)]
        conn.rollback()
    return problems
