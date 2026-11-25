"""In-process fan-out of new alerts to WebSocket clients.

One `AlertBroadcaster` lives in `app.state`. It only works inside a single API process: a
second uvicorn worker would have its own subscribers and never see alerts ingested by the
first. Scaling out needs a shared bus (Redis pub/sub or PostgreSQL LISTEN/NOTIFY) behind the
same `publish` / `subscribe` interface.

Ingest runs in a thread pool while subscribers live on the event loop, so `publish` hands the
message to each subscriber's loop with `call_soon_threadsafe` and never waits. Each subscriber
has a bounded queue; one that is full is marked `overflowed` and dropped, so a slow client
can't slow ingest or grow memory.
"""

import asyncio
import threading

# Block events (type "block") may use at most this share of a subscriber's queue; the rest is
# kept for alerts, so a burst of block reports can never push alerts out or overflow the client.
BLOCK_SHARE = 0.5


class Subscriber:
    def __init__(self, loop: asyncio.AbstractEventLoop, size: int):
        self.loop = loop
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=size)
        self.overflowed = False
        self.block_limit = max(1, int(size * BLOCK_SHARE))
        self.blocks_queued = 0
        self.blocks_dropped = 0  # block messages not queued because their share was used up
        self.wakeup = asyncio.Event()  # set when the subscriber should stop (overflow)

    def offer(self, message: dict) -> bool:  # runs on self.loop
        if self.overflowed:
            return False
        is_block = message.get("type") == "block"
        if is_block and self.blocks_queued >= self.block_limit:
            self.blocks_dropped += 1  # shed the block message; the client stays connected
            return True
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            self.overflowed = True
            self.wakeup.set()
            return False
        if is_block:
            self.blocks_queued += 1
        return True

    async def next(self) -> dict:  # runs on self.loop
        message = await self.queue.get()
        if message.get("type") == "block":  # no await after the get: cancel-safe
            self.blocks_queued -= 1
        return message


class AlertBroadcaster:
    def __init__(self, max_subscribers: int, queue_size: int):
        self.max_subscribers = max_subscribers
        self.queue_size = queue_size
        self._subs: set[Subscriber] = set()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._subs)

    def subscribe(self) -> Subscriber | None:
        """Call from the event loop. None if the connection cap is reached."""
        with self._lock:
            if len(self._subs) >= self.max_subscribers:
                return None
            sub = Subscriber(asyncio.get_running_loop(), self.queue_size)
            self._subs.add(sub)
            return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        with self._lock:
            self._subs.discard(sub)

    def publish(self, message: dict) -> None:
        """Thread-safe and non-blocking."""
        with self._lock:
            subs = list(self._subs)
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(sub.offer, message)
            except RuntimeError:  # that client's event loop is closed
                self.unsubscribe(sub)

    def publish_many(self, messages: list[dict]) -> None:
        for message in messages:
            self.publish(message)
