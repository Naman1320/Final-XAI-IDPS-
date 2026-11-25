"""Queues, workers, retries, rate limit and digest, dedupe and status for the channels.

Ingest only calls `submit_alerts` / `submit_blocks`: they build small records, drop what a channel
doesn't want (severity, source, duplicates) and `put_nowait` on a bounded queue. A full queue
drops the message (counted). Nothing on that path does I/O or waits, so a dead Slack can't slow
ingest. One daemon thread per channel (started on the first message) sends:

* retries with exponential backoff for transient errors (network, 5xx, 429, SMTP 4xx);
* a per-channel rate limit (messages per minute); beyond it events are held back and, as soon as
  there is room, ONE digest message says "and K more";
* dedupe: the same (class, source address) or (rule, source, destination, port) within a window
  is sent once, unless a higher severity turns up (a folded rule alert is a repeat of its first).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from datetime import UTC, datetime

from soc.api.integrations import formats
from soc.api.integrations.channels import CHANNEL_NAMES, Channel, build_channels
from soc.api.integrations.formats import Event, Item, TestNotice
from soc.api.integrations.netguard import DeliveryError
from soc.api.settings import SocSettings

log = logging.getLogger("soc.integrations")

RATE_WINDOW = 60.0
MAX_BACKOFF = 30.0
TEST_LIMIT = 3  # test messages per channel per minute
DEDUPE_MAX_KEYS = 5000
DIGEST_CLASS_KEYS = 20


class NotConfigured(Exception):
    """The channel has no configuration (or notifications are switched off)."""


class TestRateLimited(Exception):
    __test__ = False  # not a pytest class


class ChannelRunner:
    def __init__(self, channel: Channel, settings: SocSettings, *,
                 clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC),
                 start_thread: bool = True) -> None:
        self.channel = channel
        self.s = settings
        self._clock, self._now = clock, now
        self._start_thread = start_thread
        self.queue: queue.Queue[Event] = queue.Queue(maxsize=settings.notify_queue_size)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()  # dedupe table, stats, thread start
        self._dedupe: dict[tuple, tuple[float, int]] = {}
        self._sent_times: deque[float] = deque()
        self._test_times: deque[float] = deque()
        # held back by the rate limit (worker thread only)
        self._held = 0
        self._held_sev: Counter = Counter()
        self._held_cls: Counter = Counter()
        self._held_blocks = 0
        self.stats = {"sent": 0, "failed": 0, "dropped": 0, "rate_limited": 0, "deduped": 0}
        self.last_success_at: datetime | None = None
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None

    # --- state ------------------------------------------------------------------------------
    @property
    def active(self) -> bool:
        return self.s.notify_enabled and self.channel.configured

    def status(self) -> dict:
        ch = self.channel
        with self._lock:
            return {
                "channel": ch.name, "configured": ch.configured, "enabled": self.active,
                "min_severity": ch.min_severity, "include_rules": ch.include_rules,
                "target_hint": ch.target_hint() if ch.configured else None,
                "last_success_at": self.last_success_at, "last_error": self.last_error,
                "last_error_at": self.last_error_at, "queued": self.queue.qsize(),
                **self.stats}

    def _safe(self, text: str) -> str:
        for secret in self.channel.secrets():
            if secret and len(secret) >= 4:
                text = text.replace(secret, "***")
        return text[:200]

    def _ok(self) -> None:
        with self._lock:
            self.last_success_at = self._now()

    def _fail(self, text: str) -> None:
        with self._lock:
            self.last_error, self.last_error_at = self._safe(text), self._now()

    def _bump(self, key: str, n: int = 1) -> None:
        with self._lock:
            self.stats[key] += n

    # --- producer side (ingest threads): never blocks, never does I/O ----------------------
    def offer(self, event: Event) -> str:
        ch = self.channel
        key = None
        if event.kind == "block":
            if not (ch.accepts_blocks and getattr(ch, "include_blocks", False)):
                return "skipped"
        else:
            if event.rank < formats.SEVERITY_RANK[ch.min_severity]:
                return "skipped"
            if event.source == "rule" and not ch.include_rules:
                return "skipped"
            if ch.dedupe_seconds > 0:
                key = event.dedupe_key()
        now = self._clock()
        with self._lock:
            if key is not None and self._seen_recently(key, event.rank, now):
                self.stats["deduped"] += 1
                return "deduped"
            try:
                self.queue.put_nowait(event)
            except queue.Full:
                self.stats["dropped"] += 1  # not marked as seen: the next one may get through
                return "dropped"
            if key is not None:  # only a queued event counts as "already notified"
                self._mark_seen(key, event.rank, now)
        self._ensure_thread()
        return "queued"

    def _seen_recently(self, key: tuple, rank: int, now: float) -> bool:
        seen = self._dedupe.get(key)
        return (seen is not None and now - seen[0] < self.channel.dedupe_seconds
                and rank <= seen[1])

    def _mark_seen(self, key: tuple, rank: int, now: float) -> None:
        window = self.channel.dedupe_seconds
        if len(self._dedupe) >= DEDUPE_MAX_KEYS:
            self._dedupe = {k: v for k, v in self._dedupe.items() if now - v[0] < window}
            if len(self._dedupe) >= DEDUPE_MAX_KEYS:
                self._dedupe.clear()
        self._dedupe[key] = (now, rank)

    def forget_ips(self, ips: set[str], *, dry_run: bool = False) -> int:
        """Drop de-duplication entries that name one of these addresses (erasure on request)."""
        with self._lock:
            hits = [k for k in self._dedupe if any(part in ips for part in k)]
            if not dry_run:
                for k in hits:
                    del self._dedupe[k]
        return len(hits)

    def _forget(self, item: Item) -> None:
        """Delivery finally failed: the next alert of this kind must be allowed to try again."""
        key = item.dedupe_key() if isinstance(item, Event) else None
        if key is not None:
            with self._lock:
                seen = self._dedupe.get(key)
                if seen is not None and seen[1] == item.rank:
                    del self._dedupe[key]

    def _ensure_thread(self) -> None:
        if not self._start_thread or self._stop.is_set():
            return
        thread = self._thread
        if thread is not None and thread.is_alive():
            return
        with self._lock:
            thread = self._thread
            if self._stop.is_set() or (thread is not None and thread.is_alive()):
                return
            if thread is not None:
                log.warning("notification worker (%s) had died; restarting", self.channel.name)
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name=f"notify-{self.channel.name}")
            self._thread.start()

    # --- worker side -------------------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self.queue.get(timeout=self._idle_wait())
            except queue.Empty:
                item = None
            try:
                if item is not None:
                    self.process(item)
                self.tick()
            except Exception:  # a bug here must not kill the worker
                log.exception("notification worker (%s) error", self.channel.name)

    def _idle_wait(self) -> float:
        if self._held and self.rate_limit:
            return 0.2
        return 0.25  # how quickly a worker notices it should stop

    @property
    def rate_limit(self) -> int:
        return self.channel.rate_per_minute if self.channel.use_limits else 0

    def _budget(self) -> int:
        limit = self.rate_limit
        if limit <= 0:
            return 1 << 30
        now = self._clock()
        while self._sent_times and now - self._sent_times[0] >= RATE_WINDOW:
            self._sent_times.popleft()
        return limit - len(self._sent_times)

    def process(self, event: Event) -> None:
        """Send `event`, or hold it back (rate limit). Called by the worker; tests call it too."""
        if self._held or self._budget() <= 0:
            self._hold(event)
            return
        self._deliver(event, 1)

    def _hold(self, event: Event) -> None:
        self._held += 1
        self._bump("rate_limited")
        if event.kind == "block":
            self._held_blocks += 1
            return
        self._held_sev[event.severity or "low"] += 1
        key = event.predicted_class
        if key not in self._held_cls and len(self._held_cls) >= DIGEST_CLASS_KEYS:
            key = "(other)"
        self._held_cls[key] += 1

    def tick(self) -> None:
        """Send the digest for held-back events once the rate limit has room."""
        if self._held and self._budget() > 0:
            digest = formats.digest_of(self._held_sev, self._held_cls, self._held,
                                       self._held_blocks)
            n = self._held
            self._held, self._held_sev, self._held_cls = 0, Counter(), Counter()
            self._held_blocks = 0
            self._deliver(digest, n)

    def _deliver(self, item: Item, covers: int) -> None:
        """Send with retries. `covers` = events this message stands for (failure accounting)."""
        if self.rate_limit > 0:
            self._sent_times.append(self._clock())
        attempts = self.s.notify_max_attempts
        for attempt in range(attempts):
            try:
                self.channel.send(item)
            except DeliveryError as exc:
                error, retry = str(exc), exc.retryable
            except Exception as exc:  # noqa: BLE001  never let a channel bug escape
                error, retry = f"unexpected error ({type(exc).__name__})", False
            else:
                self._bump("sent")
                self._ok()
                return
            self._fail(error)
            if not retry or attempt == attempts - 1:
                break
            delay = min(self.s.notify_backoff_seconds * (2 ** attempt), MAX_BACKOFF)
            if self._stop.wait(delay):  # shutting down
                self._bump("dropped", covers)
                return
        self._bump("failed", covers)
        self._forget(item)
        log.warning("notification channel %s failed: %s", self.channel.name, self.last_error)

    # --- test button (called from a request thread) --------------------------------------------
    def send_test(self) -> dict:
        if not self.active:
            raise NotConfigured(self.channel.name)
        now = self._clock()
        with self._lock:
            while self._test_times and now - self._test_times[0] >= RATE_WINDOW:
                self._test_times.popleft()
            if len(self._test_times) >= TEST_LIMIT:
                raise TestRateLimited(self.channel.name)
            self._test_times.append(now)
        started = time.monotonic()
        error = None
        try:
            self.channel.send(TestNotice(self._now()))
        except DeliveryError as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001
            error = f"unexpected error ({type(exc).__name__})"
        if error is None:
            self._ok()
        else:
            self._fail(error)
        return {"channel": self.channel.name, "ok": error is None,
                "error": None if error is None else self._safe(error),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "tested_at": self._now()}

    def request_stop(self) -> None:
        self._stop.set()

    def finish(self, deadline: float) -> None:
        """Wait (until the monotonic `deadline`) for the worker, then count what was never
        sent (still queued, or held for a digest) as dropped, and close the channel."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        lost = self._held
        self._held = 0
        while True:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break
            lost += 1
        if lost:
            self._bump("dropped", lost)
        self.channel.close()

    def close(self, timeout: float = 2.0) -> None:
        self.request_stop()
        self.finish(time.monotonic() + timeout)


class NotificationManager:
    def __init__(self, settings: SocSettings, *, start_threads: bool = True,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.settings = settings
        self.runners: dict[str, ChannelRunner] = {
            name: ChannelRunner(ch, settings, start_thread=start_threads, clock=clock)
            for name, ch in build_channels(settings).items()}
        assert tuple(self.runners) == CHANNEL_NAMES

    def any_active(self) -> bool:
        return any(r.active for r in self.runners.values())

    def submit_alerts(self, alerts, sensor_name: str) -> None:
        """Offer new alerts (ORM rows) to every active channel. Never raises, never blocks."""
        if not self.any_active():
            return
        events = [formats.event_from_alert(a, sensor_name) for a in alerts]
        self._offer(events)

    def submit_blocks(self, messages, sensor_name: str) -> None:
        """Offer block events (BlockMessage objects) to the channels that take them."""
        if not any(r.active and r.channel.accepts_blocks for r in self.runners.values()):
            return
        self._offer([Event(kind="block", at=m.at, sensor=sensor_name, src_ip=m.ip,
                           block_event=m.event, reason=m.reason) for m in messages])

    def _offer(self, events: list[Event]) -> None:
        for runner in self.runners.values():
            if not runner.active:
                continue
            for event in events:
                runner.offer(event)

    def status(self) -> list[dict]:
        return [r.status() for r in self.runners.values()]

    def forget_ips(self, ips: set[str], *, dry_run: bool = False) -> int:
        return sum(r.forget_ips(ips, dry_run=dry_run) for r in self.runners.values())

    def send_test(self, name: str) -> dict:
        return self.runners[name].send_test()

    def close(self, timeout: float = 3.0) -> None:
        """Stop every worker, waiting at most `timeout` seconds in total."""
        deadline = time.monotonic() + timeout
        for r in self.runners.values():
            r.request_stop()  # all stop at once; then the joins share one deadline
        for r in self.runners.values():
            r.finish(deadline)
