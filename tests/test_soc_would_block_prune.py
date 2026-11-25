"""SOC API: would_blocks retention (pruning on the block ingest path)."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import TEST_SECRET
from pydantic import ValidationError

from soc.api.models import Block, BlockSource, SensorToken, WouldBlock
from soc.api.routes import blocks as blocks_module
from soc.api.routes.blocks import prune_would_blocks
from soc.api.settings import SocSettings


def sensor_id(db) -> int:
    return db.query(SensorToken).one().id  # the sensor_token fixture's sensor (FK-safe)


def add_would(db, age: timedelta, ip="203.0.113.7"):
    db.add(WouldBlock(sensor_id=sensor_id(db), ip=ip, reason="r", source=BlockSource.AUTO,
                      at=datetime.now(UTC) - age))


def count(soc_app, model=WouldBlock):
    with soc_app.state.session_factory() as db:
        return db.query(model).count()


def ingest_one(client, headers, ip="198.51.100.9"):
    r = client.post("/ingest/blocks", headers=headers, json={"events": [
        {"event": "would_block", "ip": ip, "reason": "r", "ttl_seconds": 60}]})
    assert r.status_code == 201, r.text


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(blocks_module, "_monotonic", lambda: now[0])
    return now


def test_setting_default_and_bounds():
    assert SocSettings(jwt_secret=TEST_SECRET).would_block_retention_days == 7
    assert SocSettings(jwt_secret=TEST_SECRET, would_block_retention_days=1
                       ).would_block_retention_days == 1
    assert SocSettings(jwt_secret=TEST_SECRET, would_block_retention_days=365
                       ).would_block_retention_days == 365
    for bad in (0, -1, 366):
        with pytest.raises(ValidationError):
            SocSettings(jwt_secret=TEST_SECRET, would_block_retention_days=bad)


def test_setting_reads_the_environment(monkeypatch):
    monkeypatch.setenv("IDPS_SOC_WOULD_BLOCK_RETENTION_DAYS", "30")
    assert SocSettings(jwt_secret=TEST_SECRET).would_block_retention_days == 30


def test_old_rows_go_new_rows_stay_and_blocks_are_untouched(
        client, soc_app, sensor_token, sensor_headers, clock):
    with soc_app.state.session_factory() as db:
        add_would(db, timedelta(days=8), "203.0.113.1")
        add_would(db, timedelta(days=7, hours=1), "203.0.113.2")
        add_would(db, timedelta(days=6), "203.0.113.3")
        add_would(db, timedelta(hours=1), "203.0.113.4")
        db.add(Block(sensor_id=sensor_id(db), ip="203.0.113.5", reason="old but real", source=BlockSource.AUTO,
                     blocked_at=datetime.now(UTC) - timedelta(days=400),
                     expires_at=datetime.now(UTC) - timedelta(days=399)))
        db.commit()
    ingest_one(client, sensor_headers)  # triggers the first prune
    with soc_app.state.session_factory() as db:
        ips = {w.ip for w in db.query(WouldBlock)}
    assert ips == {"203.0.113.3", "203.0.113.4", "198.51.100.9"}
    assert count(soc_app, Block) == 1


def test_retention_follows_the_setting(client, soc_app, sensor_token, sensor_headers, clock):
    soc_app.state.settings.would_block_retention_days = 2
    with soc_app.state.session_factory() as db:
        add_would(db, timedelta(days=3))
        add_would(db, timedelta(days=1))
        db.commit()
    ingest_one(client, sensor_headers)
    assert count(soc_app) == 2  # the 1-day-old one and the new one


def test_pruning_is_rate_limited(client, soc_app, sensor_token, sensor_headers, clock):
    ingest_one(client, sensor_headers)  # first prune: nothing to do
    with soc_app.state.session_factory() as db:
        add_would(db, timedelta(days=30))
        db.commit()
    clock[0] += blocks_module.PRUNE_EVERY_SECONDS - 1
    ingest_one(client, sensor_headers)
    assert count(soc_app) == 3  # too soon: the old row is still there
    clock[0] += 2
    ingest_one(client, sensor_headers)
    assert count(soc_app) == 3 - 1 + 1  # pruned the old one; the new ingest added one
    with soc_app.state.session_factory() as db:
        assert all(w.at > datetime.now(UTC) - timedelta(days=1) for w in db.query(WouldBlock))


def test_a_prune_is_bounded_and_the_next_one_continues(soc_app, sensor_token, monkeypatch):
    monkeypatch.setattr(blocks_module, "PRUNE_BATCH", 3)
    monkeypatch.setattr(blocks_module, "PRUNE_MAX_BATCHES", 2)
    with soc_app.state.session_factory() as db:
        for i in range(10):
            add_would(db, timedelta(days=30), f"203.0.113.{i + 1}")
        add_would(db, timedelta(hours=1), "203.0.113.200")
        db.commit()
        now = datetime.now(UTC)
        assert prune_would_blocks(db, 7, now) == 6
        assert db.query(WouldBlock).count() == 5
        assert prune_would_blocks(db, 7, now) == 6 - 2  # 4 old ones left
        assert db.query(WouldBlock).count() == 1
        assert prune_would_blocks(db, 7, now) == 0


def test_a_failing_prune_does_not_fail_the_ingest(client, soc_app, sensor_token, sensor_headers,
                                                  clock, monkeypatch, caplog):
    import logging

    def boom(*a, **k):
        raise RuntimeError("db is unhappy")

    monkeypatch.setattr(blocks_module, "prune_would_blocks", boom)
    with caplog.at_level(logging.ERROR, logger="soc.api"):
        ingest_one(client, sensor_headers)
    assert count(soc_app) == 1  # the event itself was stored
    (rec,) = [r for r in caplog.records if "pruning would_blocks failed" in r.message]
    assert rec.exc_info is not None  # with the traceback


def test_a_failure_mid_prune_keeps_the_ingest_and_the_first_batchs_deletions(
        client, soc_app, sensor_token, sensor_headers, clock, monkeypatch):
    from sqlalchemy import event

    monkeypatch.setattr(blocks_module, "PRUNE_BATCH", 3)
    monkeypatch.setattr(blocks_module, "PRUNE_MAX_BATCHES", 10)
    with soc_app.state.session_factory() as db:
        for i in range(8):
            add_would(db, timedelta(days=30), f"203.0.113.{i + 1}")
        db.commit()
    deletes = []

    def hook(conn, cursor, statement, *rest):
        if statement.lstrip().upper().startswith("DELETE"):
            deletes.append(statement)
            if len(deletes) == 2:
                raise RuntimeError("disk on fire")

    engine = soc_app.state.engine
    event.listen(engine, "before_cursor_execute", hook)
    try:
        ingest_one(client, sensor_headers)  # still answers 201 (ingest_one asserts it)
    finally:
        event.remove(engine, "before_cursor_execute", hook)
    assert len(deletes) == 2
    with soc_app.state.session_factory() as db:
        ips = {w.ip for w in db.query(WouldBlock)}
    assert "198.51.100.9" in ips  # the ingested event is kept
    assert len(ips) == 8 - 3 + 1  # the first batch (3 rows) is gone, nothing else


def test_a_failed_prune_is_not_retried_within_the_interval(client, soc_app, sensor_token,
                                                           sensor_headers, clock, monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise RuntimeError("down")

    monkeypatch.setattr(blocks_module, "prune_would_blocks", boom)
    ingest_one(client, sensor_headers)
    clock[0] += blocks_module.PRUNE_EVERY_SECONDS - 1
    ingest_one(client, sensor_headers)
    assert len(calls) == 1
    clock[0] += 2
    ingest_one(client, sensor_headers)
    assert len(calls) == 2


def test_a_failing_rollback_cannot_raise_out_of_the_prune(soc_app, sensor_token, clock,
                                                          monkeypatch, caplog):
    from sqlalchemy.orm import Session

    def boom(*a, **k):
        raise RuntimeError("down")

    def bad_rollback(self):
        raise RuntimeError("rollback failed too")

    monkeypatch.setattr(blocks_module, "prune_would_blocks", boom)
    monkeypatch.setattr(Session, "rollback", bad_rollback)
    blocks_module.prune_in_background(soc_app, datetime.now(UTC))  # does not raise
    assert any("pruning would_blocks failed" in r.message for r in caplog.records)


def test_only_one_prune_runs_at_a_time(soc_app, sensor_token, clock, monkeypatch):
    calls = []
    monkeypatch.setattr(blocks_module, "prune_would_blocks", lambda *a: calls.append(1) or 0)
    assert blocks_module._prune_lock.acquire(blocking=False)
    try:
        blocks_module.prune_in_background(soc_app, datetime.now(UTC))  # skipped, not blocked
    finally:
        blocks_module._prune_lock.release()
    assert calls == [] and getattr(soc_app.state, "would_block_pruned_at", None) is None
    blocks_module.prune_in_background(soc_app, datetime.now(UTC))
    assert calls == [1]


def test_an_exact_multiple_of_the_batch_size(soc_app, sensor_token, monkeypatch):
    monkeypatch.setattr(blocks_module, "PRUNE_BATCH", 3)
    monkeypatch.setattr(blocks_module, "PRUNE_MAX_BATCHES", 10)
    with soc_app.state.session_factory() as db:
        for i in range(6):
            add_would(db, timedelta(days=30), f"203.0.113.{i + 1}")
        add_would(db, timedelta(hours=1), "203.0.113.200")
        db.commit()
        assert prune_would_blocks(db, 7, datetime.now(UTC)) == 6  # a third batch finds none
        assert db.query(WouldBlock).count() == 1
        assert prune_would_blocks(db, 7, datetime.now(UTC)) == 0


def test_a_full_size_batch_works_on_sqlite_without_binding_ids(soc_app, sensor_token,
                                                               monkeypatch):
    """1000 ids as bound variables fail on SQLite < 3.32 (limit 999). The subquery form binds no id:
    prove it by lowering this connection's variable limit below the batch size."""
    import sqlite3

    assert blocks_module.PRUNE_BATCH == 1000
    monkeypatch.setattr(blocks_module, "PRUNE_MAX_BATCHES", 1)  # one full batch per call
    with soc_app.state.session_factory() as db:
        sid = sensor_id(db)
        old = datetime.now(UTC) - timedelta(days=30)
        db.execute(WouldBlock.__table__.insert(), [
            {"sensor_id": sid, "ip": f"10.0.{i // 250}.{i % 250 + 1}", "reason": "r",
             "source": "auto", "at": old} for i in range(1500)])
        db.commit()
        raw = soc_app.state.engine.raw_connection().driver_connection
        if not hasattr(raw, "setlimit"):
            pytest.skip("sqlite3.Connection.setlimit needs Python 3.11+")
        previous = raw.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 20)
        try:
            now = datetime.now(UTC)
            assert prune_would_blocks(db, 7, now) == 1000
            assert prune_would_blocks(db, 7, now) == 500
        finally:
            raw.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous)
        assert db.query(WouldBlock).count() == 0


def test_the_ingest_response_does_not_wait_for_the_prune(soc_app, sensor_token, clock):
    """The handler only schedules the prune (a background task, own session); it runs afterwards."""
    import asyncio
    from types import SimpleNamespace

    from fastapi import BackgroundTasks

    from soc.api.routes.blocks import BlockBatch, ingest_blocks

    with soc_app.state.session_factory() as db:
        add_would(db, timedelta(days=30), "203.0.113.1")
        db.commit()
        sensor = db.query(SensorToken).one()
        background = BackgroundTasks()
        batch = BlockBatch.model_validate({"events": [
            {"event": "would_block", "ip": "198.51.100.9", "reason": "r"}]})
        result = ingest_blocks(batch, sensor, SimpleNamespace(app=soc_app), background, db)
        assert result.would_block == 1
        assert db.query(WouldBlock).count() == 2  # nothing pruned yet
        assert len(background.tasks) == 1
    asyncio.run(background())  # what the server does after sending the response
    with soc_app.state.session_factory() as db:
        assert [w.ip for w in db.query(WouldBlock)] == ["198.51.100.9"]


def test_the_at_column_is_indexed():
    assert any(col.name == "at" for ix in WouldBlock.__table__.indexes for col in ix.columns)
