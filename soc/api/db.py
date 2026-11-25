"""Database engine and sessions (SQLAlchemy 2)."""

import logging
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy import DateTime, MetaData, create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class UtcDateTime(TypeDecorator):
    """A timezone-aware UTC datetime. SQLite drops the timezone on storage; this puts it back."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime: use timezone-aware UTC datetimes")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


SQLITE_BUSY_TIMEOUT_MS = 5000
_wal_warned = False
log = logging.getLogger("soc.db")


def _sqlite_is_file(url: str) -> bool:
    from sqlalchemy.engine import make_url

    u = make_url(url)
    return bool(u.database) and u.database != ":memory:" and "mode=memory" not in str(u.query)


def make_engine(url: str) -> Engine:
    kwargs: dict = {}
    if url.startswith("sqlite"):
        # FastAPI runs sync endpoints in a thread pool, so SQLite must allow that.
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool  # one shared in-memory database (tests)
    else:
        kwargs["pool_pre_ping"] = True  # a connection that died (database restart) is replaced
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite") and _sqlite_is_file(url):
        from sqlalchemy import event

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            # busy_timeout first (the WAL switch may need to wait for another connection): a
            # writer that meets another writer waits instead of failing at once with "database is
            # locked". WAL: readers (a backup, a long query) and the one writer don't block each
            # other, so ingest keeps working during a backup. A read-only file cannot be switched:
            # carry on in its current journal mode (reading still works).
            global _wal_warned
            cur = dbapi_conn.cursor()
            cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
            try:
                cur.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError as exc:
                if not _wal_warned:
                    _wal_warned = True
                    log.warning("SQLite: cannot switch to WAL mode (%s); continuing as is", exc)
            cur.close()
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def upgrade_schema(engine: Engine, metadata: MetaData | None = None) -> list[str]:
    """Only for ADOPTING a database made before migrations existed (roadmap step 10; see
    soc.api.migrate.adopt): add the nullable columns that `metadata` (default: the models) has
    and the old database lacks, with ALTER TABLE ADD COLUMN, and the indexes declared on those
    new columns. Never part of the normal start-up: schema changes are Alembic migrations now.
    Idempotent (also when two processes start at once: a "duplicate
    column" answer is fine if the column is there afterwards); returns what it added
    ("table.column"). Only plain nullable columns are added, with no defaults or constraints, and
    nothing is ever dropped, renamed or retyped; anything else is refused."""
    quote = engine.dialect.identifier_preparer.quote
    added: list[str] = []
    for table in (metadata or Base.metadata).sorted_tables:
        insp = inspect(engine)
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        new_cols = []
        for col in table.columns:
            if col.name in have:
                continue
            if not col.nullable or col.primary_key:
                raise RuntimeError(
                    f"{table.name}.{col.name} is missing and is not a nullable column: "
                    "this needs a real migration")
            ddl = f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(col.name)} " \
                  f"{col.type.compile(dialect=engine.dialect)}"
            try:
                with engine.begin() as conn:  # one transaction each: PostgreSQL aborts on error
                    conn.execute(text(ddl))
            except (OperationalError, ProgrammingError):
                again = {c["name"] for c in inspect(engine).get_columns(table.name)}
                if col.name not in again:
                    raise
                continue  # another process added it first
            added.append(f"{table.name}.{col.name}")
            new_cols.append(col.name)
        if new_cols:
            existing = {i["name"] for i in inspect(engine).get_indexes(table.name)}
            for index in table.indexes:
                if index.name not in existing and {c.name for c in index.columns} & set(new_cols):
                    try:
                        index.create(engine)
                    except (OperationalError, ProgrammingError):
                        names = {i["name"] for i in inspect(engine).get_indexes(table.name)}
                        if index.name not in names:
                            raise
    return added


def init_db(engine: Engine, auto_migrate: bool = True) -> None:
    """Bring the database to the current schema with Alembic migrations (soc.api.migrate):
    empty -> upgrade head; a pre-migration database -> adopted (checked, stamped), then upgraded;
    a versioned one -> upgraded when `auto_migrate`, else refused unless already at head.
    Raises soc.api.migrate.SchemaError when it must not start."""
    from soc.api import migrate

    migrate.ensure_schema(engine, auto_migrate)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request, closed afterwards."""
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def serialize_writes(session: Session, model) -> None:
    """Hold a database write lock through commit for a check spanning several rows.

    SQLite serializes writers after the first DML. PostgreSQL serializes the named
    table's mutations while leaving plain SELECTs available.
    """
    from sqlalchemy import false, text, update

    table = model.__table__
    if session.get_bind().dialect.name == "postgresql":
        name = session.get_bind().dialect.identifier_preparer.format_table(table)
        session.execute(text(f"LOCK TABLE {name} IN SHARE ROW EXCLUSIVE MODE"))
    else:
        key = next(iter(table.primary_key.columns))
        session.execute(update(table).where(false()).values({key: key}))
