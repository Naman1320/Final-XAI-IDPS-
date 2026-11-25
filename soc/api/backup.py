"""Portable logical backup and restore of the SOC database (`python -m soc.api backup|restore`).

File: gzip of JSON lines. Line 1 is the header
    {"format": "idps-soc-backup", "version": 1, "alembic_revision": ..., "created_at": ...,
     "dialect": ..., "tables": {name: {"rows": n, "columns": [...]}, ...}, "body_sha256": ...}
followed by one line per row, {"t": table, "r": [values in the header's column order]}, tables in
foreign-key order. The sha256 covers the uncompressed row lines. Values are lossless: datetimes
{"$dt": ISO-8601 UTC}, JSON columns {"$json": value} (so SQL NULL and JSON null stay apart), bytes
{"$b64": ...}, non-finite floats {"$f": "nan"|"inf"|"-inf"}, decimals {"$dec": str}; enums are
their stored strings. Nothing outside the database goes in (not the JWT secret).

Backup streams (server-side cursor, 1,000 rows at a time) inside ONE read transaction, so the
file is a consistent snapshot of a running SOC; the body goes to a temporary file while its hash
and counts accumulate, then the header is written in front of it (a gzip file may be several
members, so the body is copied as is, not recompressed). Memory does not depend on database size.
Restore reads line by line, verifies the hash BEFORE touching the database, and inserts in
batches in one transaction.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import gzip
import hashlib
import json
import math
import os
import shutil
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine

from soc.api import migrate
from soc.api.db import Base

FORMAT = "idps-soc-backup"
VERSION = 1
BATCH = 1000
Progress = Callable[[str], None]


class BackupError(RuntimeError):
    """A refusal or failure with a one-line message for the operator."""


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --- value encoding ---------------------------------------------------------------------------

def encode(value, is_json: bool):
    if is_json:
        if value is None:
            return None  # SQL NULL (JSON columns are read as text, see backup())
        return {"$json": json.loads(value)}
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return {"$f": "nan" if math.isnan(value) else ("inf" if value > 0 else "-inf")}
    if isinstance(value, datetime):
        value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return {"$dt": value.isoformat()}
    if isinstance(value, bytes | bytearray | memoryview):
        return {"$b64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, Decimal):
        return {"$dec": str(value)}
    raise BackupError(f"cannot back up a value of type {type(value).__name__}")


def decode(value):
    if not isinstance(value, dict):
        return value
    if "$dt" in value:
        return datetime.fromisoformat(value["$dt"])
    if "$json" in value:
        return sa.JSON.NULL if value["$json"] is None else value["$json"]
    if "$b64" in value:
        return base64.b64decode(value["$b64"])
    if "$f" in value:
        return float(value["$f"])
    if "$dec" in value:
        return Decimal(value["$dec"])
    raise BackupError("the backup holds a value of an unknown kind")


def _is_json(column: sa.Column) -> bool:
    return isinstance(column.type, sa.JSON)


# --- backup -----------------------------------------------------------------------------------

def _open_new(path: Path):
    """A new file, mode 0600, that must not exist yet."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)


def _fsync_dir(path: Path) -> None:
    """Make a new directory entry durable (no-op where directories cannot be opened)."""
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _begin_snapshot(engine: Engine) -> Connection:
    if engine.dialect.name == "postgresql":
        conn = engine.connect().execution_options(isolation_level="REPEATABLE READ",
                                                  postgresql_readonly=True)
        conn.begin()
    else:
        conn = engine.connect()
        conn.exec_driver_sql("BEGIN")  # pysqlite does not start a transaction for SELECTs
    return conn


def backup(engine: Engine, out: str | os.PathLike, progress: Progress = _stderr) -> dict:
    """Write the backup to `out` (must not exist). Returns the header."""
    out = Path(out)
    if out.exists() or out.is_symlink():
        raise BackupError(f"{out} already exists: refusing to overwrite a backup")
    body_tmp = out.with_name(out.name + ".body.tmp")
    final_tmp = out.with_name(out.name + ".tmp")
    for p in (body_tmp, final_tmp):
        if p.exists():
            raise BackupError(f"{p} exists (an earlier backup was interrupted?): remove it first")
    created: list[Path] = []  # only what THIS call made is ever removed
    sha = hashlib.sha256()
    tables: dict[str, dict] = {}
    try:
        conn = _begin_snapshot(engine)
        try:
            revision = migrate.current_revision(conn)
            if revision is None:
                raise BackupError("the database has no migration revision (empty or from before "
                                  "migrations): run `python -m soc.api db upgrade` first")
            meta = sa.MetaData()
            meta.reflect(conn, only=lambda name, _m: name != "alembic_version")
            fd = _open_new(body_tmp)
            created.append(body_tmp)
            with os.fdopen(fd, "wb") as raw, \
                    gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                for table in meta.sorted_tables:
                    cols = list(table.columns)
                    flags = [_is_json(c) for c in cols]
                    # JSON as text: the driver's parsing would turn SQL NULL and JSON null alike
                    # into None.
                    sel = sa.select(*[sa.cast(c, sa.Text) if j else c
                                      for c, j in zip(cols, flags, strict=True)])
                    if table.primary_key.columns:
                        sel = sel.order_by(*table.primary_key.columns)
                    n = 0
                    result = conn.execution_options(stream_results=True, yield_per=BATCH
                                                    ).execute(sel)
                    for row in result:
                        line = json.dumps({"t": table.name, "r": [
                            encode(v, j) for v, j in zip(row, flags, strict=True)]},
                            separators=(",", ":")).encode("ascii") + b"\n"
                        sha.update(line)
                        gz.write(line)
                        n += 1
                    tables[table.name] = {"rows": n, "columns": [c.name for c in cols]}
                    progress(f"backup {table.name}: {n} rows")
                raw.flush()
                os.fsync(raw.fileno())
        finally:
            with contextlib.suppress(Exception):
                conn.rollback()
            conn.close()
        header = {"format": FORMAT, "version": VERSION, "alembic_revision": revision,
                  "created_at": datetime.now(UTC).isoformat(), "dialect": engine.dialect.name,
                  "tables": tables, "body_sha256": sha.hexdigest()}
        fd = _open_new(final_tmp)
        created.append(final_tmp)
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                gz.write(json.dumps(header, separators=(",", ":")).encode("ascii") + b"\n")
            with open(body_tmp, "rb") as body:
                shutil.copyfileobj(body, raw)  # a second gzip member: no recompression
            raw.flush()
            os.fsync(raw.fileno())
        try:
            os.link(final_tmp, out)  # atomic, and fails if `out` appeared meanwhile
        except FileExistsError as exc:
            raise BackupError(f"{out} already exists: refusing to overwrite a backup") from exc
        except OSError as exc:
            if exc.errno not in (errno.EPERM, errno.ENOTSUP, errno.EXDEV, errno.EOPNOTSUPP):
                raise
            if out.exists():
                raise BackupError(f"{out} already exists: refusing to overwrite") from exc
            os.replace(final_tmp, out)  # no hard links here: plain rename
        _fsync_dir(out.parent)
    finally:
        for p in created:
            with contextlib.suppress(FileNotFoundError):
                p.unlink()
    progress(f"backup written: {out} ({sum(t['rows'] for t in tables.values())} rows, "
             f"revision {revision})")
    return header


# --- restore ----------------------------------------------------------------------------------

def _read_header(f) -> dict:
    try:
        header = json.loads(f.readline())
    except (ValueError, OSError, EOFError) as exc:
        raise BackupError("not a SOC backup file (unreadable header)") from exc
    if not isinstance(header, dict) or header.get("format") != FORMAT:
        raise BackupError("not a SOC backup file")
    if header.get("version") != VERSION:
        raise BackupError(f"backup format version {header.get('version')!r} is not supported")
    for key in ("alembic_revision", "tables", "body_sha256"):
        if key not in header:
            raise BackupError(f"the backup header lacks {key!r}")
    return header


def _open_backup(path: Path):
    try:
        return gzip.open(path, "rb")
    except OSError as exc:
        raise BackupError(f"cannot read {path}: {exc.strerror or exc}") from exc


def _verify(path: Path) -> dict:
    try:
        with _open_backup(path) as f:
            header = _read_header(f)
            sha = hashlib.sha256()
            while chunk := f.read(1 << 20):
                sha.update(chunk)
    except (OSError, EOFError) as exc:  # a truncated or corrupt gzip
        raise BackupError(f"the backup file is damaged: {exc}") from exc
    if sha.hexdigest() != header["body_sha256"]:
        raise BackupError("the backup file is damaged: its checksum does not match")
    return header


def _rows(f, sha) -> Iterator[tuple[str, list]]:
    for line in f:
        sha.update(line)
        item = json.loads(line)
        yield item["t"], item["r"]


def _reset_sequences(conn: Connection, tables: sa.MetaData) -> None:
    quote = conn.dialect.identifier_preparer.quote
    for table in tables.sorted_tables:
        pk = list(table.primary_key.columns)
        if len(pk) != 1 or not isinstance(pk[0].type, sa.Integer):
            continue
        seq = conn.scalar(sa.text("SELECT pg_get_serial_sequence(:t, :c)"),
                          {"t": quote(table.name), "c": pk[0].name})
        if seq is None:
            continue
        # is_called false on an empty table: the next id is 1, not 2.
        col, tab = quote(pk[0].name), quote(table.name)
        conn.execute(sa.text(f"SELECT setval(CAST(:s AS regclass), COALESCE(MAX({col}), 1), "
                             f"MAX({col}) IS NOT NULL) FROM {tab}"), {"s": seq})


# Tables a migration fills with starting rows (0004: the system IAM roles), children first. A
# backup made at that revision or later contains them, so they are emptied before its rows go in.
SEEDED_TABLES = ("iam_role_permissions", "iam_roles")


def _only_seed_rows(conn: Connection, name: str) -> bool:
    # Compare with the frozen revision's rows. A custom grant or an edited system
    # role is user data and must make restore refuse the destination.
    from importlib import import_module

    seeds = import_module("soc.api.migrations.versions.0004_iam")._SYSTEM_ROLES
    if name == "iam_roles":
        expected = {(i, role, description, True)
                    for i, (role, description, _) in enumerate(seeds, 1)}
        sql = "SELECT id, name, description, system FROM iam_roles"
    else:
        expected = {(i, p) for i, (_, _, perms) in enumerate(seeds, 1) for p in perms}
        sql = "SELECT role_id, permission FROM iam_role_permissions"
    for row in conn.execute(sa.text(sql)):
        if tuple(row) not in expected:
            return False
        expected.remove(tuple(row))
    return not expected


def restore(engine: Engine, src: str | os.PathLike, progress: Progress = _stderr) -> dict:
    """Restore `src` into an EMPTY database. Returns the header."""
    src = Path(src)
    header = _verify(src)
    revision = header["alembic_revision"]
    if not migrate.known_revision(revision):
        raise BackupError(f"the backup is of schema revision {revision!r}, which this version of "
                          "the SOC does not know: restore with the SOC version that made it")
    progress(f"restore: backup checksum ok ({sum(t['rows'] for t in header['tables'].values())} "
             f"rows, revision {revision}, made on {header.get('dialect')})")
    with migrate.migration_lock(engine), engine.connect() as conn:
        trans = conn.begin()
        started_empty = False
        try:
            cleared = _check_empty(conn)
            started_empty = cleared or not [n for n in sa.inspect(conn).get_table_names()
                                            if n != "alembic_version"]
            current = migrate.current_revision(conn)
            if current != revision:
                try:
                    migrate.upgrade(conn, revision)
                except Exception as exc:
                    raise BackupError(f"cannot bring the database to revision {revision!r} "
                                      f"(it is at {current!r}): use a new database") from exc
            reflected = sa.MetaData()
            reflected.reflect(conn, only=lambda name, _m: name != "alembic_version")
            inserts = _insert_tables(reflected, header)
            for name in SEEDED_TABLES:  # rows a migration seeds: the backup brings its own
                if name in header["tables"] and name in reflected.tables:
                    conn.execute(sa.delete(reflected.tables[name]))
            counts = dict.fromkeys(header["tables"], 0)
            sha = hashlib.sha256()  # again, over what is actually inserted (the file may have
            # been swapped since the first pass)
            pending: list[dict] = []
            current_table: str | None = None

            def flush() -> None:
                nonlocal pending
                if pending:
                    conn.execute(sa.insert(inserts[current_table]), pending)
                    counts[current_table] += len(pending)
                    pending = []

            with _open_backup(src) as f:
                f.readline()  # header
                for name, values in _rows(f, sha):
                    if name != current_table:
                        flush()
                        if current_table is not None:
                            progress(f"restore {current_table}: {counts[current_table]} rows")
                        current_table = name
                    if name not in inserts:
                        raise BackupError(f"the backup has rows of an unknown table {name!r}")
                    cols = header["tables"][name]["columns"]
                    pending.append({c: decode(v) for c, v in zip(cols, values, strict=True)})
                    if len(pending) >= BATCH:
                        flush()
                flush()
                if current_table is not None:
                    progress(f"restore {current_table}: {counts[current_table]} rows")
            if sha.hexdigest() != header["body_sha256"]:
                raise BackupError("the backup file changed while it was being restored")
            for name, info in header["tables"].items():
                if counts[name] != info["rows"]:
                    raise BackupError(f"table {name}: {counts[name]} rows restored, "
                                      f"{info['rows']} expected")
            if engine.dialect.name == "postgresql":
                _reset_sequences(conn, reflected)
            migrate.upgrade(conn, "head")
            trans.commit()
        except BaseException:
            trans.rollback()
            if started_empty and engine.dialect.name != "postgresql":
                _drop_created_tables(conn)  # SQLite does not roll DDL back
            raise
    progress("restore complete")
    return header


def _drop_created_tables(conn: Connection) -> None:
    """After a failed restore into a database that had no tables: remove the tables the restore
    made, so the database is empty again and the restore can be retried."""
    with contextlib.suppress(Exception):
        meta = sa.MetaData()
        meta.reflect(conn)
        meta.drop_all(conn)
        conn.commit()


def _insert_tables(reflected: sa.MetaData, header: dict) -> dict[str, sa.TableClause]:
    """Lightweight tables for the INSERTs, in the database's own column types, except that JSON
    columns map None to SQL NULL (the backup says JSON null explicitly)."""
    out = {}
    for name, info in header["tables"].items():
        if name not in reflected.tables:
            raise BackupError(f"the database has no table {name!r} at the backup's revision")
        table = reflected.tables[name]
        missing = set(info["columns"]) - {c.name for c in table.columns}
        if missing:
            raise BackupError(f"table {name} lacks the columns {sorted(missing)}")
        out[name] = sa.table(name, *[
            sa.column(c.name, sa.JSON(none_as_null=True) if _is_json(c) else c.type)
            for c in table.columns if c.name in info["columns"]])
    return out


def _check_empty(conn: Connection) -> bool:
    """Refuse unless the target holds no SOC rows. Returns True when it only held EMPTY SOC
    tables without a revision (an earlier restore killed half way, or a bare create_all) and
    those were dropped, so the restore starts from nothing."""
    quote = conn.dialect.identifier_preparer.quote
    names = [n for n in sa.inspect(conn).get_table_names() if n != "alembic_version"]
    pristine_seed = (set(SEEDED_TABLES).issubset(names) and migrate.current_revision(conn)
                     and all(_only_seed_rows(conn, table) for table in SEEDED_TABLES))
    for name in names:
        if pristine_seed and name in SEEDED_TABLES:
            continue
        if conn.execute(sa.text(f"SELECT 1 FROM {quote(name)} LIMIT 1")).first() is not None:
            raise BackupError(f"the database is not empty (table {name} has rows): "
                              "restore only into an empty database")
    if names and migrate.current_revision(conn) is None:
        from soc.api import models  # noqa: F401

        if not set(names) <= set(Base.metadata.tables):
            raise BackupError("the database has tables but no migration revision: run "
                              "`python -m soc.api db upgrade` first, or use an empty database")
        meta = sa.MetaData()
        meta.reflect(conn)
        meta.drop_all(conn)  # nothing but empty SOC tables: leftovers, start over
        return True
    return False
