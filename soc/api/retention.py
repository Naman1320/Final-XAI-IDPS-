"""Data retention: delete old rows in the background (never on the request path).

Policy (settings, 0 = keep forever; docs/soc.md "Retention"):
- alerts older than alert_retention_days, EXCEPT alerts an analyst judged (confirmed or
  false_positive) that carry model features while alert_retention_keep_labelled is on: those are
  the training rows of `python -m soc.api.export_feedback` and retraining. Privacy trade-off: their
  IP addresses and features then stay until that setting is turned off.
- an alert linked to a case that is open or investigating is never deleted;
- blocks and actions are never deleted: when an alert goes, the alert_id of its blocks and
  would-blocks is set to NULL;
- audit entries older than audit_retention_days, assistant conversations not updated for
  assistant_retention_days, closed cases (and their notes) not updated for
  closed_case_retention_days (their alerts stay unless old enough themselves: the link is cleared),
  would-block records older than would_block_retention_days, access-log rows older than
  access_log_retention_days, login-history rows older than login_history_retention_days.

Rows go in batches of BATCH, one transaction per batch, so writers are never blocked for long.
A run that deleted anything writes one audit entry `retention_prune` with the per-table counts.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from soc.api.models import (
    AccessLog,
    Alert,
    AlertStatus,
    AssistantConversation,
    AuditEntry,
    Block,
    Case,
    CaseNote,
    CaseStatus,
    LoginHistory,
    WouldBlock,
)
from soc.api.settings import SocSettings

log = logging.getLogger("soc.retention")

BATCH = 500
INTERVAL_SECONDS = 3600.0
FIRST_RUN_DELAY_SECONDS = 30.0
PAUSE_SECONDS = 0.05  # between batches of a background run, so other writers get in
TABLES = ("alerts", "case_notes", "cases", "audit_log", "assistant_conversations",
          "would_blocks", "access_log", "login_history")


def policy(settings: SocSettings) -> dict:
    return {
        "alert_retention_days": settings.alert_retention_days,
        "alert_retention_keep_labelled": settings.alert_retention_keep_labelled,
        "audit_retention_days": settings.audit_retention_days,
        "assistant_retention_days": settings.assistant_retention_days,
        "closed_case_retention_days": settings.closed_case_retention_days,
        "would_block_retention_days": settings.would_block_retention_days,
        "access_log_retention_days": settings.access_log_retention_days,
        "login_history_retention_days": settings.login_history_retention_days,
    }


def _alert_condition(settings: SocSettings, now: datetime, plain_scan: bool = False):
    """The alerts that may go. `plain_scan` (SQLite) writes `case_id + 0` so the planner cannot
    answer the "no case, or a closed one" test with a MULTI-INDEX OR on ix_alerts_case_id plus a
    temp b-tree sort of everything above the cursor on every batch: it walks the primary key
    instead. `case_id + 0 IS NULL` means exactly what `case_id IS NULL` does."""
    case_id = Alert.case_id + 0 if plain_scan else Alert.case_id
    closed = select(Case.id).where(Case.status == CaseStatus.CLOSED)
    cond = [Alert.received_at < now - timedelta(days=settings.alert_retention_days),
            # an open or investigating case needs its alerts
            or_(case_id.is_(None), case_id.in_(closed))]
    if settings.alert_retention_keep_labelled:
        judged = and_(Alert.status.in_((AlertStatus.CONFIRMED, AlertStatus.FALSE_POSITIVE)),
                      Alert.features.is_not(None))
        cond.append(~judged)
    return and_(*cond)


def _stopped(stop: threading.Event | None) -> bool:
    return stop is not None and stop.is_set()


def _candidates(db: Session, model, cond, last: int) -> list[int]:
    """The next up to BATCH ids after `last` (keyset: every batch starts where the previous one
    ended, so a long run is linear, not a rescan from the start each time)."""
    return list(db.scalars(select(model.id).where(model.id > last, cond)
                           .order_by(model.id).limit(BATCH)))


def _retryable(exc: Exception) -> bool:
    """A deadlock or serialization failure (PostgreSQL), or a busy database (SQLite): another
    writer got in the way of this one batch, which is worth one more try."""
    orig = getattr(exc, "orig", exc)
    if getattr(orig, "sqlstate", None) in ("40P01", "40001"):
        return True
    return "locked" in str(orig).lower() or "busy" in str(orig).lower()


def _batches(db: Session, model, cond, pause: float, counts: dict, stop, problems: list[str],
             work) -> None:
    """Delete in batches of BATCH, one transaction each. Per batch: read the candidate ids (those
    matching `cond` after the cursor), call `work(ids)` which locks, re-checks and deletes and
    returns {table: rows} to add, then commit. Counts are added only after the commit. A deadlock
    or busy database rolls the batch back and retries it once; if that fails too, this pass over
    the table ends (the next run continues) instead of failing the whole run, and says so in
    `problems`."""
    last = 0
    sqlite = db.get_bind().dialect.name == "sqlite"

    def one() -> tuple[list[int], dict]:
        if sqlite:  # take the write lock first: the re-check, unlink and delete see one state
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        ids = _candidates(db, model, cond, last)
        done = work(ids) if ids else {}
        db.commit()  # each batch stands alone: a later failure keeps the earlier ones
        return ids, done

    while not _stopped(stop):
        for attempt in (1, 2):
            try:
                ids, done = one()
                break
            except DBAPIError as exc:
                db.rollback()
                if not _retryable(exc):
                    raise
                if attempt == 2:
                    log.warning("retention: a batch of %s failed twice (%s); continuing at the "
                                "next run", model.__tablename__, type(exc.orig).__name__)
                    problems.append(f"{model.__tablename__}: pass stopped after a lock conflict; "
                                    "the next run continues")
                    return
                time.sleep(0.2)
        for table, n in done.items():
            counts[table] += n
        if len(ids) < BATCH:
            return
        last = ids[-1]
        if pause:
            time.sleep(pause)


def _simple(db: Session, model, cond):
    """work() for a table nothing refers to: delete the chosen ids that still match."""
    def work(ids):
        return {model.__tablename__: db.execute(
            delete(model).where(model.id.in_(ids), cond)).rowcount}
    return work


def _count(db: Session, model, cond) -> int:
    return db.scalar(select(func.count()).select_from(model).where(cond)) or 0


def prune(db: Session, settings: SocSettings, now: datetime | None = None, *,
          dry_run: bool = False, pause: float = 0.0, counts: dict[str, int] | None = None,
          stop: threading.Event | None = None, problems: list[str] | None = None) -> dict[str, int]:
    """One retention pass; returns {table: rows deleted (or that would be, on a dry run)}.
    `counts`, if given, is the dict that is filled as batches commit (so the caller still has
    the partial result when a later batch fails); `stop` ends the pass between batches."""
    now = now or datetime.now(UTC)
    counts = counts if counts is not None else {}
    problems = problems if problems is not None else []  # passes that gave up (lock conflicts)
    for t in TABLES:
        counts.setdefault(t, 0)
    dialect = db.get_bind().dialect.name
    pg, sqlite = dialect == "postgresql", dialect == "sqlite"

    def cutoff(days: int) -> datetime:
        return now - timedelta(days=days)

    if settings.alert_retention_days:
        cond = _alert_condition(settings, now, plain_scan=sqlite)
        if dry_run:
            counts["alerts"] = _count(db, Alert, cond)
        else:
            recheck = _alert_condition(settings, now)

            def work(ids):
                if pg:
                    # Lock order cases -> alerts, the same as an analyst attaching an alert (the
                    # case row first): only the closed cases THIS batch refers to, in id order,
                    # so a case cannot be reopened under us and nothing deadlocks.
                    refs = select(Alert.case_id).where(Alert.id.in_(ids),
                                                       Alert.case_id.is_not(None))
                    db.execute(select(Case.id).where(Case.status == CaseStatus.CLOSED,
                                                     Case.id.in_(refs)).order_by(Case.id)
                               .with_for_update(read=True)).all()
                # Accepted narrow race: an alert attached to a CLOSED case, and that case reopened,
                # both within the milliseconds of one batch, after the case locks above were taken
                # and before this statement reads them: such an alert can be deleted although its
                # case is open again. (Attaching to an open case, and reopening a case whose
                # alerts are in the batch, are both covered.)
                mine = list(db.scalars(select(Alert.id).where(Alert.id.in_(ids), recheck)
                                       .order_by(Alert.id).with_for_update()))
                if not mine:
                    return {}
                # exactly the alerts about to be deleted (locked, and the delete repeats the rule)
                for model in (Block, WouldBlock):
                    db.execute(update(model).where(model.alert_id.in_(mine))
                               .values(alert_id=None))
                return {"alerts": db.execute(
                    delete(Alert).where(Alert.id.in_(mine), recheck)).rowcount}
            _batches(db, Alert, cond, pause, counts, stop, problems, work)
    if settings.closed_case_retention_days and not _stopped(stop):
        cond = and_(Case.status == CaseStatus.CLOSED,
                    Case.updated_at < cutoff(settings.closed_case_retention_days))
        if dry_run:
            counts["cases"] = _count(db, Case, cond)
            counts["case_notes"] = db.scalar(
                select(func.count()).select_from(CaseNote)
                .where(CaseNote.case_id.in_(select(Case.id).where(cond)))) or 0
        else:
            def work(ids):
                # lock the cases (in id order) and re-check: a case reopened since is left whole.
                # Notes go with their case; alerts stay, without the link.
                mine = list(db.scalars(select(Case.id).where(Case.id.in_(ids), cond)
                                       .order_by(Case.id).with_for_update()))
                if not mine:
                    return {}
                db.execute(update(Alert).where(Alert.case_id.in_(mine)).values(case_id=None))
                notes = db.execute(delete(CaseNote).where(CaseNote.case_id.in_(mine))).rowcount
                return {"case_notes": notes, "cases": db.execute(
                    delete(Case).where(Case.id.in_(mine), cond)).rowcount}
            _batches(db, Case, cond, pause, counts, stop, problems, work)
    if settings.audit_retention_days and not _stopped(stop):
        cond = AuditEntry.at < cutoff(settings.audit_retention_days)
        if dry_run:
            counts["audit_log"] = _count(db, AuditEntry, cond)
        else:
            _batches(db, AuditEntry, cond, pause, counts, stop, problems, _simple(db, AuditEntry, cond))
    if settings.assistant_retention_days and not _stopped(stop):
        cond = and_(AssistantConversation.updated_at < cutoff(settings.assistant_retention_days),
                    AssistantConversation.busy_since.is_(None))
        if dry_run:
            counts["assistant_conversations"] = _count(db, AssistantConversation, cond)
        else:
            _batches(db, AssistantConversation, cond, pause, counts, stop, problems,
                     _simple(db, AssistantConversation, cond))
    if settings.access_log_retention_days and not _stopped(stop):
        cond = AccessLog.at < cutoff(settings.access_log_retention_days)
        if dry_run:
            counts["access_log"] = _count(db, AccessLog, cond)
        else:
            _batches(db, AccessLog, cond, pause, counts, stop, problems,
                     _simple(db, AccessLog, cond))
    if settings.login_history_retention_days and not _stopped(stop):
        cond = LoginHistory.at < cutoff(settings.login_history_retention_days)
        if dry_run:
            counts["login_history"] = _count(db, LoginHistory, cond)
        else:
            _batches(db, LoginHistory, cond, pause, counts, stop, problems,
                     _simple(db, LoginHistory, cond))
    if not _stopped(stop):
        cond = WouldBlock.at < cutoff(settings.would_block_retention_days)
        if dry_run:
            counts["would_blocks"] = _count(db, WouldBlock, cond)
        else:
            _batches(db, WouldBlock, cond, pause, counts, stop, problems,
                     _simple(db, WouldBlock, cond))
    return counts


# --- background runner ------------------------------------------------------------------------

@dataclass
class RunState:
    at: datetime | None = None
    counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    duration_seconds: float | None = None


def run_once(session_factory: sessionmaker[Session], settings: SocSettings, state: RunState,
             *, pause: float = PAUSE_SECONDS, stop: threading.Event | None = None) -> None:
    """One pass with its own session. Never raises; the outcome is in `state`. Whatever was
    deleted before a failure is counted, audited (`retention_prune`) and shown."""
    started = datetime.now(UTC)
    t0 = time.monotonic()
    counts: dict[str, int] = {}
    problems: list[str] = []
    error = None
    try:
        with session_factory() as db:
            try:
                prune(db, settings, started, pause=pause, counts=counts, stop=stop,
                      problems=problems)
            except Exception:
                db.rollback()
                raise
    except Exception as exc:  # logged, never raised: the app must keep running
        log.exception("retention run failed")
        error = type(exc).__name__ + " (see the SOC log)"
    if problems and error is None:
        error = "; ".join(problems)
    if sum(counts.values()):
        try:
            _audit(session_factory, counts, error)
            log.info("retention pruned %s", {k: v for k, v in counts.items() if v})
        except Exception:  # a broken database must not kill the thread
            log.exception("retention: writing the audit entry failed")
    state.at, state.counts, state.error = started, dict(counts), error
    state.duration_seconds = round(time.monotonic() - t0, 3)


def _audit(session_factory, counts: dict[str, int], error: str | None = None) -> None:
    details: dict = {"counts": {k: v for k, v in counts.items() if v}}
    if error:
        details["error"] = error
    with session_factory() as db:
        db.add(AuditEntry(actor_type="system", actor_name="retention", action="retention_prune",
                          target="", details=details))
        db.commit()


class RetentionRunner:
    """A daemon thread: a first pass shortly after start, then every INTERVAL_SECONDS."""

    def __init__(self, session_factory, settings: SocSettings, *,
                 first_delay: float = FIRST_RUN_DELAY_SECONDS,
                 interval: float = INTERVAL_SECONDS) -> None:
        self.session_factory, self.settings = session_factory, settings
        self.first_delay, self.interval = first_delay, interval
        self.state = RunState()
        self._announced = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="soc-retention", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        wait = self.first_delay
        while not self._stop.wait(wait):
            if not self._announced:
                self._announced = True
                log.warning("retention policy (days, 0 = keep forever): %s", policy(self.settings))
            run_once(self.session_factory, self.settings, self.state, stop=self._stop)
            wait = self.interval
