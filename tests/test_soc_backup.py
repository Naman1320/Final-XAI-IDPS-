# ruff: noqa: F811  (fixtures imported from step10_helpers)
"""Step 10: portable backup and restore."""

import gzip
import json
import os
import stat
import tracemalloc
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.orm import Session
from step10_helpers import (  # noqa: F401
    ON_PG,
    PG_URL,
    cli_env,
    dump,
    migrated,
    needs_pg,
    pg_engine,
    populate,
    tables_in,
    wipe_pg,
)

from soc.api import __main__ as cli
from soc.api import backup, migrate
from soc.api.db import Base, make_engine
from soc.api.models import Alert, AlertStatus, SensorToken, Severity, User

quiet = {"progress": lambda _m: None}


def sqlite(tmp_path, name):
    return make_engine(f"sqlite:///{tmp_path / name}")


def pg():
    wipe_pg()
    return make_engine(PG_URL)


def test_round_trip_sqlite_every_table_identical(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    before = dump(src)
    assert all(before[t] for t in Base.metadata.tables), "every table must be populated"
    out = tmp_path / "b.gz"
    header = backup.backup(src, out, **quiet)
    assert set(header["tables"]) == set(Base.metadata.tables)
    assert header["tables"]["alerts"]["rows"] == 3
    dst = sqlite(tmp_path, "d.db")
    backup.restore(dst, out, **quiet)
    assert dump(dst) == before
    assert migrate.check(dst) == []


def test_restore_into_a_migrated_empty_database(tmp_path):
    """Migration 0004 seeds the system IAM roles: that is not "data", so a freshly migrated
    database still counts as empty, and the backup's own roles replace the seeded ones."""
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    before = dump(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    dst = migrated(sqlite(tmp_path, "d.db"))
    with dst.connect() as c:
        assert c.execute(text("SELECT count(*) FROM iam_roles")).scalar() > 0  # the seed
    backup.restore(dst, out, **quiet)
    assert dump(dst) == before


def test_a_custom_role_makes_a_migrated_database_not_empty(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    dst = migrated(sqlite(tmp_path, "d.db"))
    with dst.begin() as c:
        c.execute(text("INSERT INTO iam_roles (name, description, system, created_at, updated_at)"
                       " VALUES ('mine', '', 0, '2026-01-01', '2026-01-01')"))
    with pytest.raises(backup.BackupError, match="not empty"):
        backup.restore(dst, out, **quiet)


def test_restore_preserves_an_intentionally_removed_seed_grant(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    dst = migrated(sqlite(tmp_path, "d.db"))
    with dst.begin() as c:
        c.execute(text("DELETE FROM iam_role_permissions WHERE permission='cloud.view'"))
    before = dump(dst)
    with pytest.raises(backup.BackupError, match="not empty"):
        backup.restore(dst, out, **quiet)
    assert dump(dst) == before


def test_sql_null_and_json_null_survive(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    dst = sqlite(tmp_path, "d.db")
    backup.restore(dst, out, **quiet)
    with dst.connect() as c:
        rows = c.execute(text("SELECT id, features IS NULL, CAST(features AS TEXT) FROM alerts "
                              "ORDER BY id")).all()
        assert [bool(r[1]) for r in rows] == [False, False, True]
        assert rows[1][2] == "null"
        results = c.execute(text("SELECT result IS NULL, CAST(result AS TEXT) FROM actions "
                                 "ORDER BY id")).all()
        assert bool(results[0][0]) is False and results[0][1] == "null"
        assert bool(results[1][0]) is True


def test_file_mode_header_and_secret_free(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir() if "-wal" not in p.name and "-shm" not in p.name
                  ) == ["b.gz", "s.db"]  # no temp leftovers (SQLite's WAL files are not ours)
    lines = gzip.decompress(out.read_bytes()).split(b"\n")
    header = json.loads(lines[0])
    assert header["format"] == backup.FORMAT and header["version"] == 1
    assert header["alembic_revision"] == migrate.head_revision() and len(header["body_sha256"]) == 64


def test_refusals(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    original = out.read_bytes()
    with pytest.raises(backup.BackupError, match="overwrite"):
        backup.backup(src, out, **quiet)
    assert out.read_bytes() == original
    link = tmp_path / "link.gz"
    link.symlink_to(tmp_path / "nowhere.gz")
    with pytest.raises(backup.BackupError, match="overwrite"):
        backup.backup(src, link, **quiet)
    # non-empty target
    with pytest.raises(backup.BackupError, match="not empty"):
        backup.restore(src, out, **quiet)
    # tampered body, wrong format, wrong version, garbage, truncated
    body = gzip.decompress(original)
    tampered = tmp_path / "t.gz"
    tampered.write_bytes(gzip.compress(body.replace(b"DoS", b"DoX")))
    header_line, rest = body.split(b"\n", 1)
    header = json.loads(header_line)

    def variant(name, **changes):
        p = tmp_path / name
        p.write_bytes(gzip.compress(json.dumps(header | changes).encode() + b"\n" + rest))
        return p

    cases = {
        "checksum": tampered,
        "not a SOC backup": variant("f.gz", format="other"),
        "not supported": variant("v.gz", version=99),
        "does not know": variant("r.gz", alembic_revision="9999_x"),
    }
    for match, path in cases.items():
        target = sqlite(tmp_path, f"t_{abs(hash(match))}.db")
        with pytest.raises(backup.BackupError, match=match):
            backup.restore(target, path, **quiet)
        assert not tables_in(target), "a refused restore must not touch the database"
    junk = tmp_path / "junk.gz"
    junk.write_bytes(b"this is not gzip")
    plain = tmp_path / "plain.gz"
    plain.write_bytes(gzip.compress(b"hello\n"))
    cut = tmp_path / "cut.gz"
    cut.write_bytes(original[: len(original) // 2])
    for path in (junk, plain, cut, tmp_path / "missing.gz"):
        with pytest.raises(backup.BackupError):
            backup.restore(sqlite(tmp_path, "x.db"), path, **quiet)


def test_unversioned_source_and_unversioned_target_refused(tmp_path):
    raw = sqlite(tmp_path, "raw.db")
    Base.metadata.create_all(raw)  # tables, but never migrated
    with pytest.raises(backup.BackupError, match="no migration revision"):
        backup.backup(raw, tmp_path / "o.gz", **quiet)
    assert not (tmp_path / "o.gz").exists()
    assert [p.name for p in tmp_path.iterdir() if "-wal" not in p.name and "-shm" not in p.name
            ] == ["raw.db"]
    src = migrated(sqlite(tmp_path, "s.db"))
    out = tmp_path / "ok.gz"
    backup.backup(src, out, **quiet)
    # a target with only EMPTY SOC tables and no revision (a killed restore) is reused
    backup.restore(raw, out, **quiet)
    assert migrate.check(raw) == []
    odd = sqlite(tmp_path, "odd.db")
    with odd.begin() as conn:
        conn.execute(text("CREATE TABLE something_else (x INTEGER)"))
    with pytest.raises(backup.BackupError, match="no migration revision"):
        backup.restore(odd, out, **quiet)
    empty = sqlite(tmp_path, "empty.db")
    with pytest.raises(backup.BackupError, match="no migration revision"):
        backup.backup(empty, tmp_path / "o2.gz", **quiet)


def test_a_failed_restore_leaves_no_rows(tmp_path, monkeypatch):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    dst = sqlite(tmp_path, "d.db")
    real = backup.decode
    seen = {"n": 0}

    def boom(v):
        seen["n"] += 1
        if seen["n"] > 40:
            raise RuntimeError("disk on fire")
        return real(v)

    monkeypatch.setattr(backup, "decode", boom)
    with pytest.raises(RuntimeError):
        backup.restore(dst, out, **quiet)
    monkeypatch.undo()
    # nothing committed: no tables with rows (the schema creation rolled back too)
    names = tables_in(dst) - {"alembic_version"}
    with dst.connect() as c:
        assert all(c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0 for t in names)
    backup.restore(dst, out, **quiet)  # and it can be retried
    assert dump(dst) == dump(src)


def test_row_count_mismatch_in_header_rolls_back(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    body = gzip.decompress(out.read_bytes())
    header_line, rest = body.split(b"\n", 1)
    header = json.loads(header_line)
    header["tables"]["alerts"]["rows"] += 1
    bad = tmp_path / "bad.gz"
    bad.write_bytes(gzip.compress(json.dumps(header).encode() + b"\n" + rest))
    dst = sqlite(tmp_path, "d.db")
    with pytest.raises(backup.BackupError, match="alerts"):
        backup.restore(dst, bad, **quiet)
    names = tables_in(dst) - {"alembic_version"}
    with dst.connect() as c:
        assert all(c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0 for t in names)


def test_insert_after_restore_works_on_sqlite(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    populate(src)
    out = tmp_path / "b.gz"
    backup.backup(src, out, **quiet)
    dst = sqlite(tmp_path, "d.db")
    backup.restore(dst, out, **quiet)
    with Session(dst) as db:
        db.add(User(username="new", password_hash="z", role="analyst"))
        db.commit()
        assert db.query(User).count() == 3


def test_backup_of_many_alerts_streams(tmp_path):
    src = migrated(sqlite(tmp_path, "s.db"))
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with Session(src) as db:
        db.add(SensorToken(name="s", token_hash="h" * 64))
        db.commit()
    rows = [dict(sensor_id=1, received_at=now, src_ip="1.1.1.1", src_port=i % 65535,
                 dst_ip="2.2.2.2", dst_port=2, protocol=6, start_ms=i, end_ms=i + 1,
                 predicted_class="DoS", confidence=0.5, severity=Severity.LOW.value,
                 explanation={"i": i, "pad": "x" * 200}, status=AlertStatus.NEW.value)
            for i in range(20_000)]
    with src.begin() as conn:
        conn.execute(sa.insert(Alert.__table__), rows)
    del rows
    out = tmp_path / "big.gz"
    tracemalloc.start()
    header = backup.backup(src, out, **quiet)
    _, peak_backup = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    dst = sqlite(tmp_path, "d.db")
    backup.restore(dst, out, **quiet)
    _, peak_restore = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert header["tables"]["alerts"]["rows"] == 20_000
    with dst.connect() as c:
        assert c.execute(text("SELECT count(*) FROM alerts")).scalar() == 20_000
    # 20k rows of ~330 bytes is ~7 MB of JSON; streaming must stay well under holding it all
    # in Python objects (which would be several times that).
    assert peak_backup < 12_000_000, peak_backup
    assert peak_restore < 25_000_000, peak_restore


# --- CLI --------------------------------------------------------------------------------------

def test_cli_round_trip_and_exit_codes(tmp_path, capsys):
    s_url, d_url = f"sqlite:///{tmp_path / 's.db'}", f"sqlite:///{tmp_path / 'd.db'}"
    populate(migrated(make_engine(s_url)))
    out = str(tmp_path / "c.gz")
    assert cli.main(["backup", out, "--database-url", s_url]) == 0
    assert cli.main(["backup", out, "--database-url", s_url]) == 1  # refuses to overwrite
    assert "overwrite" in capsys.readouterr().err
    assert cli.main(["restore", out, "--database-url", d_url]) == 0
    assert cli.main(["restore", out, "--database-url", d_url]) == 1  # not empty
    assert "not empty" in capsys.readouterr().err
    assert dump(make_engine(d_url)) == dump(make_engine(s_url))
    with pytest.raises(SystemExit) as exc:
        cli.main(["backup"])
    assert exc.value.code == 2


def test_cli_never_prints_the_password(tmp_path, capsys, cli_env):
    secret = "Sup3rS3cretPw"
    # an unreachable server: the failure path must not echo the URL either
    bad = f"postgresql+psycopg://idps:{secret}@127.0.0.1:1/idps"
    for argv in (["backup", str(tmp_path / "x.gz")], ["restore", str(tmp_path / "x.gz")],
                 ["db", "upgrade"], ["db", "check"], ["db", "current"], ["prune"],
                 ["prune", "--dry-run"]):
        code = cli.main([*argv, "--database-url", bad])
        cap = capsys.readouterr()
        assert secret not in cap.out + cap.err, argv
        assert code == 1, argv


@needs_pg
def test_cli_never_prints_the_real_postgres_password(tmp_path, capsys, pg_engine, cli_env):
    url = pg_engine.url.render_as_string(hide_password=False)
    pw = pg_engine.url.password
    out = str(tmp_path / "p.gz")
    assert cli.main(["db", "upgrade", "--database-url", url]) == 0
    populate(pg_engine)
    assert cli.main(["backup", out, "--database-url", url]) == 0
    wipe_pg()
    assert cli.main(["restore", out, "--database-url", url]) == 0
    assert cli.main(["restore", out, "--database-url", url]) == 1
    assert cli.main(["prune", "--database-url", url]) == 0
    assert cli.main(["db", "check", "--database-url", url]) == 0
    cap = capsys.readouterr()
    assert pw not in cap.out + cap.err


# --- PostgreSQL -------------------------------------------------------------------------------

@needs_pg
def test_postgres_round_trip_and_sequences(tmp_path):
    src = migrated(pg())
    populate(src)
    before = dump(src)
    out = tmp_path / "pg.gz"
    header = backup.backup(src, out, **quiet)
    assert header["dialect"] == "postgresql"
    dst = pg()
    backup.restore(dst, out, **quiet)
    assert dump(dst) == before
    assert migrate.check(dst) == []
    with Session(dst) as db:  # sequences were reset past the restored ids
        for model_args in range(2):
            db.add(User(username=f"n{model_args}", password_hash="z", role="analyst"))
        db.add(SensorToken(name="new", token_hash="e" * 64))
        db.commit()
        db.add(Alert(sensor_id=1, received_at=datetime.now(UTC), src_ip="1.1.1.1", src_port=1,
                     dst_ip="2.2.2.2", dst_port=2, protocol=6, start_ms=1, end_ms=2,
                     predicted_class="x", confidence=0.1, severity=Severity.LOW, explanation={}))
        db.commit()
        assert db.query(Alert).count() == 4


@needs_pg
def test_sequences_after_restoring_an_empty_backup(tmp_path):
    src = migrated(pg())
    out = tmp_path / "e.gz"
    backup.backup(src, out, **quiet)
    dst = pg()
    backup.restore(dst, out, **quiet)
    with Session(dst) as db:
        u = User(username="first", password_hash="z", role="admin")
        db.add(u)
        db.commit()
        assert u.id == 1  # is_called false on an empty table


@needs_pg
def test_postgres_to_sqlite_and_sqlite_to_postgres(tmp_path):
    lite = migrated(sqlite(tmp_path, "l.db"))
    populate(lite)
    expected = dump(lite)
    f1 = tmp_path / "l.gz"
    backup.backup(lite, f1, **quiet)
    pgdb = pg()
    backup.restore(pgdb, f1, **quiet)
    assert dump(pgdb) == expected
    f2 = tmp_path / "p.gz"
    backup.backup(pgdb, f2, **quiet)
    back = sqlite(tmp_path, "back.db")
    backup.restore(back, f2, **quiet)
    assert dump(back) == expected
    with Session(pgdb) as db:
        db.add(User(username="after", password_hash="z", role="analyst"))
        db.commit()


@needs_pg
def test_postgres_refusals_and_rollback(tmp_path):
    src = migrated(pg())
    populate(src)
    out = tmp_path / "pg.gz"
    backup.backup(src, out, **quiet)
    with pytest.raises(backup.BackupError, match="not empty"):
        backup.restore(src, out, **quiet)
    body = gzip.decompress(out.read_bytes())
    header_line, rest = body.split(b"\n", 1)
    header = json.loads(header_line)
    header["tables"]["alerts"]["rows"] += 1  # passes the checksum, fails the row count
    bad = tmp_path / "bad.gz"
    bad.write_bytes(gzip.compress(json.dumps(header).encode() + b"\n" + rest))
    dst = pg()
    with pytest.raises(backup.BackupError, match="alerts"):
        backup.restore(dst, bad, **quiet)
    names = tables_in(dst)
    assert not names or names == {"alembic_version"}  # PostgreSQL DDL rolls back too
    backup.restore(dst, out, **quiet)  # same database, now fine
    assert dump(dst) == dump(src)


@needs_pg
def test_postgres_backup_is_a_consistent_snapshot(tmp_path):
    src = migrated(pg())
    populate(src)
    out = tmp_path / "s.gz"
    real = backup.encode
    state = {"n": 0}

    def writing(value, is_json):
        state["n"] += 1
        if state["n"] == 5:  # mid-backup, another connection commits a new user
            with Session(src) as db:
                db.add(User(username="late", password_hash="z", role="analyst"))
                db.commit()
        return real(value, is_json)

    backup.encode = writing
    try:
        header = backup.backup(src, out, **quiet)
    finally:
        backup.encode = real
    assert header["tables"]["users"]["rows"] == 2  # the snapshot predates "late"
