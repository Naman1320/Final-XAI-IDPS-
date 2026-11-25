"""Where alerts go: a JSON-lines file (no SOC) or the SOC through an outbox and a sender thread."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from idps.live.metrics import Metrics
from idps.soc_client import MAX_BLOCK_EVENTS, Outbox, SocRejectedError, is_rule_alert

log = logging.getLogger("idps.live")

EXPIRY_MARGIN_SECONDS = 5.0  # a block this close to its end is not worth a POST (SOC: 422 if past)
MAX_QUEUED_BLOCKS = 1000  # unsent block reports kept in memory; beyond this the oldest are dropped


class Sink(Protocol):
    def submit(self, alerts: list[dict]) -> None: ...
    def submit_blocks(self, events: list[dict]) -> None: ...
    def pending(self) -> int: ...
    def checkpoint(self) -> None: ...
    def close(self) -> None: ...


class JsonlSink:
    """Append each alert as one JSON line. A write error (disk full, permissions) is counted and
    logged; it never stops detection."""

    def __init__(self, path: str | Path, metrics: Metrics) -> None:
        self.path = Path(path)
        self.metrics = metrics
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 0600: alerts name internal hosts. Opened once; flushed after every batch.
        # O_NOFOLLOW: a symlink planted at this path is an error, not a way to write elsewhere.
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        self._file = os.fdopen(fd, "a", encoding="utf-8")
        self._lock = threading.Lock()  # the detector and the action poller both write

    def submit(self, alerts: list[dict]) -> None:
        self._write(alerts, "alerts_dropped", "alert")

    def submit_blocks(self, events: list[dict]) -> None:
        """Block reports go to the same file, told apart from alerts by `"type": "block"`."""
        self._write([{"type": "block", **e} for e in events], "blocks_dropped", "block report")

    def _write(self, records: list[dict], counter: str, what: str) -> None:
        if not records:
            return
        try:
            with self._lock:
                self._file.write("".join(json.dumps(r, separators=(",", ":")) + "\n"
                                         for r in records))
                self._file.flush()
        except (OSError, ValueError) as exc:
            self.metrics.add(counter, len(records))
            log.error("cannot write %d %s(s) to %s: %s", len(records), what, self.path, exc)

    def pending(self) -> int:
        return 0

    def checkpoint(self) -> None:
        pass

    def close(self) -> None:
        try:
            with self._lock:
                self._file.close()
        except OSError as exc:
            log.error("closing %s failed: %s", self.path, exc)


class SocSink:
    """Queue alerts in the outbox; a background thread posts them in batches of at most
    MAX_BATCH. A SOC outage only makes the outbox grow (up to its cap, then the oldest alerts are
    dropped and counted); the detection loop never waits for the network.

    Failed rounds are retried with a growing pause (`retry_seconds` doubling up to
    `max_retry_seconds`). A batch the SOC refuses with a 4xx is dropped and counted: retrying
    cannot help. On close() one last attempt is made and what is still unsent is written to the
    outbox file, which the next run loads and sends first.

    Block reports (a real nftables block the SOC should show) use a small in-memory queue
    (MAX_QUEUED_BLOCKS, oldest dropped and counted) sent by the same thread, in batches of at most
    MAX_BLOCK_EVENTS, and retried like alerts. They are NOT written to the outbox file: a crash or a
    shutdown while the SOC is down loses the unsent ones (the block itself stays in nftables and in
    the audit log)."""

    def __init__(self, post: Callable[[list[dict]], dict], outbox: Outbox, metrics: Metrics, *,
                 retry_seconds: float = 2.0, max_retry_seconds: float = 60.0,
                 start: bool = True,
                 post_blocks: Callable[[list[dict]], dict] | None = None) -> None:
        self.post = post
        self.post_blocks = post_blocks
        self._blocks: deque[dict] = deque()
        self._blocks_lock = threading.Lock()
        self._blocks_streak = False  # a block failure was logged and no success has followed
        self._blocks_delay = 0.0  # pause between block attempts after failures (sender thread)
        self._blocks_next = 0.0  # monotonic time before which the sender does not retry blocks
        self._warned_no_blocks = False
        self.outbox = outbox
        self.metrics = metrics
        self.retry_seconds = retry_seconds
        self.max_retry_seconds = max_retry_seconds
        self._config_error_streak = False  # log a 401/403/404 once per streak, not per retry
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="soc-sender", daemon=True)
        if len(outbox):
            log.info("outbox has %d alert(s) from an earlier run; sending them first", len(outbox))
        if start:
            self._thread.start()
            self._wake.set()

    def submit(self, alerts: list[dict]) -> None:
        if alerts:
            dropped = self.outbox.add(alerts, save=False)
            if dropped:
                self.metrics.add("alerts_dropped", dropped)
            self._wake.set()

    def submit_blocks(self, events: list[dict]) -> None:
        if not events:
            return
        if self.post_blocks is None:
            self.metrics.add("blocks_dropped", len(events))
            if not self._warned_no_blocks:
                self._warned_no_blocks = True
                log.warning("this SocSink has no post_blocks: block reports are dropped")
            return
        dropped = 0
        with self._blocks_lock:
            self._blocks.extend(events)
            while len(self._blocks) > MAX_QUEUED_BLOCKS:
                self._blocks.popleft()
                dropped += 1
        if dropped:
            self.metrics.add("blocks_dropped", dropped)
            log.error("block report queue over %d: dropped the %d oldest", MAX_QUEUED_BLOCKS,
                      dropped)
        self._wake.set()

    def pending(self) -> int:
        return len(self.outbox)

    def _pending_blocks(self) -> int:
        with self._blocks_lock:
            return len(self._blocks)

    def _drain_blocks(self) -> bool:
        """Send queued block reports, oldest first; never raises. False if some stay queued.

        Events whose block already ended are dropped first: the SOC refuses a past `expires_at`
        (422) and would reject the whole batch."""
        self._drop_expired()
        while True:
            with self._blocks_lock:
                batch = [self._blocks.popleft()
                         for _ in range(min(MAX_BLOCK_EVENTS, len(self._blocks)))]
            if not batch:
                return True
            try:
                self.post_blocks(batch)
            except SocRejectedError as exc:
                if not exc.is_config_error:
                    log.error("SOC refused %d block report(s), dropping them: %s", len(batch), exc)
                    self.metrics.add("blocks_rejected", len(batch))
                    continue
                self._requeue_blocks(batch)
                self.metrics.add("soc_config_errors")
                if exc.status == 404:
                    self._log_blocks_streak("the SOC has no /ingest/blocks endpoint (HTTP 404, "
                                            "an older SOC?)")
                else:
                    self._log_blocks_streak(f"the SOC answered HTTP {exc.status} to block reports")
                return False
            except Exception as exc:  # noqa: BLE001  the sender thread must survive anything
                self._requeue_blocks(batch)
                self._log_blocks_streak(f"{type(exc).__name__}: {exc}")
                return False
            else:
                self._blocks_streak = False
                self.metrics.add("blocks_sent", len(batch))

    def _log_blocks_streak(self, why: str) -> None:
        if not self._blocks_streak:
            self._blocks_streak = True
            log.error("block reports cannot be delivered (%s); %d stay queued (at most %d, the "
                      "oldest are dropped). Alerts are not affected", why, self._pending_blocks(),
                      MAX_QUEUED_BLOCKS)

    def _drop_expired(self) -> None:
        limit = datetime.now(UTC).timestamp() + EXPIRY_MARGIN_SECONDS
        with self._blocks_lock:
            keep = [e for e in self._blocks if not _expired(e, limit)]
            gone = len(self._blocks) - len(keep)
            if gone:
                self._blocks = deque(keep)
        if gone:
            self.metrics.add("blocks_dropped", gone)
            log.warning("dropped %d block report(s) whose block had already ended", gone)

    def _requeue_blocks(self, batch: list[dict]) -> None:
        with self._blocks_lock:
            self._blocks.extendleft(reversed(batch))
            dropped = 0
            while len(self._blocks) > MAX_QUEUED_BLOCKS:
                self._blocks.popleft()
                dropped += 1
        if dropped:
            self.metrics.add("blocks_dropped", dropped)
            log.error("block report queue over %d: dropped the %d oldest", MAX_QUEUED_BLOCKS,
                      dropped)

    def checkpoint(self) -> None:
        self._save()

    def _save(self) -> None:
        try:
            self.outbox.save()
        except OSError as exc:
            log.error("cannot save the outbox to %s: %s", self.outbox.path, exc)

    def drain(self) -> bool:
        """Send queued block reports, then alerts, oldest first; the two are independent (a block
        endpoint that fails never holds back alerts). False if the SOC could not be reached for
        either."""
        blocks_ok = True
        if self.post_blocks is not None:
            blocks_ok = self._drain_blocks()
        return self._drain_alerts() and blocks_ok

    def _drain_alerts(self) -> bool:
        while (batch := self.outbox.take_first()) is not None:
            try:
                self.post(batch)
            except SocRejectedError as exc:
                if exc.is_config_error:
                    # The batch is fine; the sensor's URL, token or registration is not. Keep
                    # the alerts (the operator can fix the setting) and say so, once per streak.
                    self.outbox.requeue_front(batch)
                    self.metrics.add("soc_config_errors")
                    if not self._config_error_streak:
                        self._config_error_streak = True
                        log.error("SOC answered HTTP %s: check IDPS_SOC_URL and the sensor token. "
                                  "Alerts are kept and retried; nothing is dropped", exc.status)
                    return False
                log.error("SOC refused a batch of %d alerts, dropping it: %s%s", len(batch), exc,
                          " (rule alerts: an SOC older than the rules feature refuses them; "
                          "upgrade the SOC first, see docs/live.md)" if is_rule_alert(batch[0]) else "")
                self.metrics.add("alerts_rejected", len(batch))
            except Exception as exc:  # noqa: BLE001  the sender thread must survive anything
                self.outbox.requeue_front(batch)
                log.warning("SOC unavailable, %d alert(s) stay queued: %s: %s",
                            len(self.outbox), type(exc).__name__, exc)
                return False
            else:
                self._config_error_streak = False
                self.metrics.add("alerts_sent", len(batch))
        return True

    def _run(self) -> None:
        delay = 0.0
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            if self._stop.is_set():
                continue
            if self._pending_blocks() and time.monotonic() >= self._blocks_next:
                if self._drain_blocks():
                    self._blocks_delay = 0.0
                else:  # blocks back off on their own so they never slow the alerts down
                    self._blocks_delay = (min(self._blocks_delay * 2, self.max_retry_seconds)
                                          if self._blocks_delay else self.retry_seconds)
                    self._blocks_next = time.monotonic() + self._blocks_delay
            if not len(self.outbox):
                continue
            if self._drain_alerts():
                delay = 0.0
            else:
                delay = min(delay * 2, self.max_retry_seconds) if delay else self.retry_seconds
                self._stop.wait(delay)

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread.is_alive():
            self._thread.join(timeout=30)
        if len(self.outbox) or self._pending_blocks():
            self.drain()
        self._save()
        if self._pending_blocks():
            log.warning("%d block report(s) were not delivered and are lost (not persisted)",
                        self._pending_blocks())
        left = len(self.outbox)
        if left:
            log.warning("%d alert(s) were not delivered; kept in %s for the next run", left,
                        self.outbox.path)


def _expired(event: dict, limit: float) -> bool:
    """True if the event's `expires_at` (ISO, timezone-aware) is at or before `limit` (epoch s)."""
    raw = event.get("expires_at")
    if not raw:
        return False
    try:
        return datetime.fromisoformat(raw).timestamp() <= limit
    except (ValueError, TypeError):
        return False  # let the SOC judge it
