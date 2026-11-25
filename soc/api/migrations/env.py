"""Alembic environment of the SOC database.

Online only (the SOC never needs generated SQL scripts). The connection comes from
`config.attributes["connection"]` when the caller passes one (soc.api.migrate: the start-up path,
which holds the PostgreSQL advisory lock on it, and the tests); the caller commits. Otherwise an
engine is built from the SOC's database_url, so `alembic upgrade head` works for a developer
with only the IDPS_SOC_* environment set. `target_metadata` is the live models: used by
`--autogenerate` and the schema check only; the migrations themselves never import the models.
"""

from alembic import context

from soc.api import models  # noqa: F401  registers the tables on Base.metadata
from soc.api.db import Base, make_engine

config = context.config
target_metadata = Base.metadata


def configure(connection) -> None:
    context.configure(
        connection=connection, target_metadata=target_metadata,
        render_as_batch=True,  # SQLite cannot ALTER most things: batch mode rebuilds the table
        compare_type=True)


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        configure(connection)
        with context.begin_transaction():
            context.run_migrations()
        return
    from soc.api.settings import get_settings

    engine = make_engine(get_settings().database_url)
    try:
        with engine.connect() as connection:
            configure(connection)
            with context.begin_transaction():
                context.run_migrations()
            connection.commit()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline (--sql) mode is not supported: run against the database")
run_migrations_online()
