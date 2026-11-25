"""Blocks reported by sensors, and the list of blocks for the dashboard."""

import contextlib
import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from soc.api import access_log
from soc.api.auth import AnyUser, Sensor
from soc.api.common import Cursor, IPAddress, Limit, Page, audit, paginate, strip_unsafe
from soc.api.db import get_db
from soc.api.geo import GeoOut, geo_out
from soc.api.models import Alert, Block, BlockSource, WouldBlock

log = logging.getLogger("soc.api")
router = APIRouter(tags=["blocks"])

MAX_EVENTS = 100
MAX_TTL_SECONDS = 30 * 24 * 3600


PRUNE_EVERY_SECONDS = 600.0  # at most one prune per app per this long
PRUNE_BATCH = 1000  # rows per DELETE
PRUNE_MAX_BATCHES = 10  # so one prune removes at most 10,000 rows; the next one continues
_prune_lock = threading.Lock()  # one prune at a time; a request that finds it taken skips


def _monotonic() -> float:
    return time.monotonic()  # tests replace this to move the rate limit's clock


def prune_would_blocks(db: Session, retention_days: int, now: datetime) -> int:
    """Delete would-block rows older than `retention_days`, in bounded batches. Only touches
    `would_blocks` (never `blocks`: those are the firewall's record). Returns rows deleted.

    One statement per batch with the ids chosen by a subquery, so no id is a bound parameter: a
    list of 1000 ids would exceed SQLite's 999-variable limit before version 3.32."""
    cutoff = now - timedelta(days=retention_days)
    deleted = 0
    for _ in range(PRUNE_MAX_BATCHES):
        oldest = (select(WouldBlock.id).where(WouldBlock.at < cutoff)
                  .order_by(WouldBlock.id).limit(PRUNE_BATCH))
        n = db.execute(delete(WouldBlock).where(WouldBlock.id.in_(oldest))).rowcount
        db.commit()  # each batch stands on its own: a later failure keeps the earlier ones
        deleted += n
        if n < PRUNE_BATCH:
            break
    return deleted


def prune_in_background(app, now: datetime) -> None:
    """Runs after the ingest response (FastAPI BackgroundTasks), with its OWN session: the
    request's is closed by then and must not be shared. At most once per PRUNE_EVERY_SECONDS per
    app, one at a time. The time is taken when a prune STARTS, so a failing prune is not retried
    for the whole interval (a broken database would otherwise be hit by every ingest). Never
    raises."""
    if not _prune_lock.acquire(blocking=False):
        return  # another thread is pruning
    try:
        state = app.state
        last = getattr(state, "would_block_pruned_at", None)
        if last is not None and _monotonic() - last < PRUNE_EVERY_SECONDS:
            return
        state.would_block_pruned_at = _monotonic()
        days = state.settings.would_block_retention_days
        try:
            with state.session_factory() as db:
                try:
                    n = prune_would_blocks(db, days, now)
                except Exception:
                    with contextlib.suppress(Exception):  # a failing rollback must not raise
                        db.rollback()
                    raise
        except Exception:
            log.exception("pruning would_blocks failed; not retried for %d s",
                          int(PRUNE_EVERY_SECONDS))
            return
        if n:
            log.info("pruned %d would-block record(s) older than %d day(s)", n, days)
    finally:
        _prune_lock.release()


def active_clause(now: datetime):
    return and_(Block.unblocked_at.is_(None),
                or_(Block.expires_at.is_(None), Block.expires_at > now))


class BlockEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: Literal["blocked", "unblocked", "would_block"]
    ip: IPAddress
    reason: str = Field(default="", max_length=500)
    ttl_seconds: int | None = Field(default=None, ge=1, le=MAX_TTL_SECONDS)
    expires_at: datetime | None = None
    alert_id: int | None = Field(default=None, ge=1, le=2**62)
    source: BlockSource = BlockSource.AUTO
    # When the sensor decided (would_block only; optional so older sensors still work).
    decided_at: datetime | None = None

    @field_validator("reason")
    @classmethod
    def _plain_reason(cls, value: str) -> str:
        return strip_unsafe(value)  # control/bidi characters dropped; NUL refused

    @field_validator("expires_at", "decided_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.ttl_seconds is not None and self.expires_at is not None:
            raise ValueError("give ttl_seconds or expires_at, not both")
        if self.event == "unblocked" and (self.ttl_seconds or self.expires_at):
            raise ValueError("an unblock event has no ttl_seconds or expires_at")
        if self.event == "would_block" and self.expires_at is not None:
            raise ValueError("a would_block event has ttl_seconds, not expires_at")
        if self.event != "would_block" and self.decided_at is not None:
            raise ValueError("decided_at is only for would_block events")
        if self.event == "would_block":
            self.source = BlockSource.AUTO  # a sensor cannot claim an analyst made this decision
        return self


class BlockMessage(BaseModel):
    """One block event on the live feed (`/ws/alerts`). It has no `id`, so clients written for
    alert-only messages ignore it."""

    type: Literal["block"] = "block"
    event: Literal["blocked", "unblocked", "would_block"]
    sensor_id: int
    ip: str
    source: BlockSource
    at: datetime
    expires_at: datetime | None
    ttl_seconds: int | None
    reason: str
    geo: GeoOut | None


class BlockBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[BlockEvent] = Field(min_length=1, max_length=MAX_EVENTS)


class BlockIngestResult(BaseModel):
    blocked: int
    unblocked: int  # active blocks that were closed (0 if the IP wasn't blocked)
    would_block: int = 0  # dry-run decisions recorded (not blocks: nothing was applied)


class BlockOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sensor_id: int
    ip: str
    reason: str
    source: BlockSource
    alert_id: int | None
    blocked_at: datetime
    expires_at: datetime | None
    unblocked_at: datetime | None
    active: bool = False


def block_out(block: Block, now: datetime) -> BlockOut:
    out = BlockOut.model_validate(block)
    out.active = block.unblocked_at is None and (block.expires_at is None
                                                 or block.expires_at > now)
    return out


FUTURE_SLACK_SECONDS = 60  # a decision time further ahead than this is a wrong sensor clock
MAX_DECISION_AGE = timedelta(hours=24)  # older than any plausible outbox delay: a wrong clock


def decision_time(decided_at: datetime | None, now: datetime) -> datetime:
    """The sensor's decision time, or the receive time when absent (older sensors), in the future
    beyond clock skew, or older than MAX_DECISION_AGE (a wrong sensor clock must not put events
    ahead of now or bury them far in the past, outside every window)."""
    if (decided_at is None or decided_at > now + timedelta(seconds=FUTURE_SLACK_SECONDS)
            or decided_at < now - MAX_DECISION_AGE):
        return now
    return min(decided_at, now)


def _message(request: Request, sensor, ev: BlockEvent, at: datetime,
             expires_at: datetime | None, ttl_seconds: int | None) -> BlockMessage:
    return BlockMessage(event=ev.event, sensor_id=sensor.id, ip=ev.ip, source=ev.source, at=at,
                        expires_at=expires_at, ttl_seconds=ttl_seconds, reason=ev.reason,
                        geo=geo_out(request.app.state.geo, ev.ip))


def _publish(request: Request, messages: list[BlockMessage], sensor_name: str = "") -> None:
    """Hand the messages to the live feed; a failure here never fails the committed ingest."""
    try:
        request.app.state.broadcaster.publish_many(
            [m.model_dump(mode="json") for m in messages])
    except Exception:
        log.exception("could not publish block events to the live feed")
    try:  # syslog/CEF export of block events: queued in memory, never blocks or fails the ingest
        request.app.state.notifier.submit_blocks(messages, sensor_name)
    except Exception:
        log.exception("could not queue block notifications")


@router.post("/ingest/blocks", response_model=BlockIngestResult, status_code=201)
def ingest_blocks(batch: BlockBatch, sensor: Sensor, request: Request,
                  background: BackgroundTasks, db: Annotated[Session, Depends(get_db)]):
    now = datetime.now(UTC)
    alert_ids = {e.alert_id for e in batch.events if e.alert_id is not None}
    if alert_ids:
        found = set(db.scalars(select(Alert.id).where(Alert.id.in_(alert_ids))))
        if alert_ids - found:
            raise HTTPException(422, f"unknown alert_id(s): {sorted(alert_ids - found)}")
    blocked = unblocked = would = 0
    messages: list[BlockMessage] = []
    for ev in batch.events:
        if ev.event == "would_block":  # never touches `blocks`: nothing is in the firewall
            db.add(WouldBlock(sensor_id=sensor.id, ip=ev.ip, reason=ev.reason, source=ev.source,
                              alert_id=ev.alert_id, at=decision_time(ev.decided_at, now),
                              ttl_seconds=ev.ttl_seconds))
            would += 1
            at = decision_time(ev.decided_at, now)
            messages.append(_message(request, sensor, ev, at, None, ev.ttl_seconds))
            continue
        active = list(db.scalars(select(Block).where(
            Block.sensor_id == sensor.id, Block.ip == ev.ip, active_clause(now))))
        if ev.event == "blocked":
            expires = ev.expires_at or (now + timedelta(seconds=ev.ttl_seconds)
                                        if ev.ttl_seconds else None)
            if expires is not None and expires <= now:
                raise HTTPException(422, "expires_at is in the past")
            if active:  # already blocked: just refresh the existing record
                active[0].expires_at, active[0].reason = expires, ev.reason
            else:
                db.add(Block(sensor_id=sensor.id, ip=ev.ip, reason=ev.reason, source=ev.source,
                             alert_id=ev.alert_id, blocked_at=now, expires_at=expires))
            blocked += 1
            ttl = ev.ttl_seconds or (max(round((expires - now).total_seconds()), 1)
                                     if expires else None)
            messages.append(_message(request, sensor, ev, now, expires, ttl))
        else:
            for b in active:
                b.unblocked_at = now
            unblocked += len(active)
            if active:  # an unblock that closed nothing changes nothing on the map
                messages.append(_message(request, sensor, ev, now, None, None))
    audit(db, sensor, "ingest_blocks", f"sensor:{sensor.name}",
          {"events": len(batch.events), "blocked": blocked, "unblocked": unblocked,
           "would_block": would})
    db.commit()
    _publish(request, messages, sensor.name)  # only after the commit, never for a refused batch
    background.add_task(prune_in_background, request.app, now)  # after the response
    return BlockIngestResult(blocked=blocked, unblocked=unblocked, would_block=would)


@router.get("/blocks", response_model=Page[BlockOut])
def list_blocks(user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)],
                active: Annotated[bool | None, Query()] = None,
                ip: Annotated[IPAddress | None, Query()] = None,
                limit: Limit = 50, cursor: Cursor = None):
    now = datetime.now(UTC)
    query = select(Block).order_by(Block.id.desc()).limit(limit + 1)
    if active is True:
        query = query.where(active_clause(now))
    elif active is False:
        query = query.where(~active_clause(now))
    if ip:
        query = query.where(Block.ip == ip)
    if cursor:
        query = query.where(Block.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    page = Page[BlockOut](items=[block_out(b, now) for b in rows], next_cursor=next_cursor)
    if ip:  # logged before the answer is served (soc/api/access_log.py)
        access_log.log_access(db, request.app.state.settings, user, "block_search_by_ip",
                              target_type="block_list", ips=[ip])
    return page


class WouldBlockOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sensor_id: int
    ip: str
    reason: str
    source: BlockSource
    alert_id: int | None
    at: datetime
    ttl_seconds: int | None


@router.get("/blocks/would", response_model=Page[WouldBlockOut])
def list_would_blocks(user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)],
                      ip: Annotated[IPAddress | None, Query()] = None,
                      since_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
                      limit: Limit = 50, cursor: Cursor = None):
    """Dry-run decisions: blocks a sensor would have applied. Newest first."""
    since = datetime.now(UTC) - timedelta(hours=since_hours)
    query = (select(WouldBlock).where(WouldBlock.at >= since)
             .order_by(WouldBlock.id.desc()).limit(limit + 1))
    if ip:
        query = query.where(WouldBlock.ip == ip)
    if cursor:
        query = query.where(WouldBlock.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    page = Page[WouldBlockOut](items=[WouldBlockOut.model_validate(r) for r in rows],
                               next_cursor=next_cursor)
    if ip:
        access_log.log_access(db, request.app.state.settings, user, "would_block_search_by_ip",
                              target_type="would_block_list", ips=[ip])
    return page
