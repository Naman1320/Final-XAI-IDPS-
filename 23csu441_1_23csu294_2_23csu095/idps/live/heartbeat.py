"""Clock ticks for NFStream live capture.

NFStream's flow clock only moves forward when a packet arrives: it expires idle flows by
comparing them with the newest packet's timestamp. On a quiet link (the lab right after an
attack, a server at night) nothing arrives, so finished flows are never emitted and never scored.
Measured in the lab sensor: a port scan followed by silence produced no flows at all in 200 s;
the same scan followed by one packet every 2 s produced all its flows right after the idle
timeout.

So in live mode the loop sends one tiny UDP broadcast out of the capture interface every second.
NFStream sees it (outgoing packets are captured too) and its clock advances. The heartbeat's own
flow is dropped before scoring, so it never reaches the model, the SOC or the response engine.

Burst mode. Each packet lets NFStream expire at most 1,000 idle flows (nfstream 6.6 `meter_scan`,
one scan per 10 ms of packet time). After an attack burst the link goes quiet, the heartbeat is
the only packet left, and finished flows come out at about 1,000 a second: measured in the lab
benchmark (docs/results.md), a 100,000-flow burst took minutes to reach the SOC. So when the
output looks capped (at least `burst_flows`, default 900, in the last second, reported by the
detector through note_flows()), the heartbeat runs every `fast_interval` (default 50 ms: 20
packets/s, room for 20,000 flows/s, well above what the model scores). It returns to once a
second after the output has stayed under `burst_exit_flows` (250/s) for `BURST_HOLD` seconds,
so a link near the threshold doesn't flip modes every second. A busy link that really produces
900 flows/s also switches on; that costs 20 small broadcasts a second on a link already that
busy. `--heartbeat-burst-interval 0` turns burst mode off and keeps the 1 s heartbeat.

Only that exact flow is dropped: UDP from the socket's own address and port (`Heartbeat.key`,
known once the socket is connected) to 255.255.255.255:9, with no packet coming back. Anyone
else's traffic to that address, an attacker's broadcast flood included, is scored like any other
flow. Nothing is dropped when the heartbeat isn't running (replay, --no-heartbeat, a failed start).

The datagram goes to the limited broadcast address on the discard port (9): no ARP, no reply,
and hosts with nothing listening on UDP 9 ignore it. Its payload is a single zero byte, so it
doesn't announce what it is. Linux only (SO_BINDTODEVICE); elsewhere the loop runs without it.
"""

from __future__ import annotations

import errno
import logging
import socket
import threading
import time
from collections import deque

log = logging.getLogger("idps.live")

HEARTBEAT_DST = "255.255.255.255"
HEARTBEAT_PORT = 9  # discard
HEARTBEAT_PAYLOAD = b"\0"
UDP = 17

FAST_INTERVAL = 0.05   # 20 scans/s x 1,000 flows: far above the model's scoring rate
BURST_FLOWS = 900      # flows in the last second that mean the 1 s heartbeat caps the output
BURST_EXIT_FLOWS = 250 # ... and below this for BURST_HOLD seconds, the backlog is gone
BURST_HOLD = 3.0
BURST_WINDOW = 1.0    # seconds of recent flow output that decide the mode

# Errors that won't go away by waiting: no such interface, not allowed. Anything else (the
# interface is down or has no address yet) is retried every interval.
PERMANENT_ERRNOS = {errno.ENODEV, errno.EPERM, errno.EACCES, errno.EINVAL}


def is_heartbeat(flow, key: tuple[str, int] | None) -> bool:
    """True for the flow our own heartbeat socket `key` = (source ip, source port) creates.
    With no key (no heartbeat running) nothing is a heartbeat."""
    if key is None:
        return False
    return (getattr(flow, "protocol", None) == UDP
            and getattr(flow, "dst_port", None) == HEARTBEAT_PORT
            and getattr(flow, "dst_ip", None) == HEARTBEAT_DST
            and (getattr(flow, "src_ip", None), getattr(flow, "src_port", None)) == key
            and not getattr(flow, "bwd_packets", 0))  # nothing ever answers a heartbeat


class Heartbeat:
    """Send HEARTBEAT_PAYLOAD out of `interface` every `interval` seconds until stopped."""

    def __init__(self, interface: str, interval: float = 1.0, *, sock_factory=socket.socket,
                 fast_interval: float | None = FAST_INTERVAL, burst_flows: int = BURST_FLOWS,
                 burst_exit_flows: int = BURST_EXIT_FLOWS, clock=time.monotonic) -> None:
        """`fast_interval` None or 0 turns burst mode off (always `interval`)."""
        if interval <= 0 or (fast_interval is not None and fast_interval < 0):
            raise ValueError("heartbeat interval must be positive")
        if burst_flows < 1 or burst_exit_flows < 0:
            raise ValueError("burst_flows must be at least 1")
        self.interface = interface
        self.interval = interval
        # never slower than normal; None when burst mode is off
        self.fast_interval = min(fast_interval, interval) if fast_interval else None
        self.burst_flows = burst_flows
        self.burst_exit_flows = min(burst_exit_flows, burst_flows)
        self._clock = clock
        self._recent: deque[tuple[float, int]] = deque()  # (time, flows) noted in the last window
        self._recent_total = 0
        self._recent_lock = threading.Lock()
        self._busy_at = 0.0  # last time the output was at or above burst_exit_flows in burst mode
        self.fast = False  # burst mode is on
        self.bursts = 0    # times burst mode was switched on
        self._sock_factory = sock_factory
        self._sock = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.key: tuple[str, int] | None = None  # (source ip, source port) once connected
        self.failing = False

    def start(self) -> None:
        """Open the socket and start sending. Raises OSError for problems that won't fix
        themselves (no SO_BINDTODEVICE, no such interface, no permission); the caller decides
        whether to go on without a heartbeat. A temporary failure (the interface is down) is
        logged and retried by the sending thread."""
        bind_option = getattr(socket, "SO_BINDTODEVICE", None)
        if bind_option is None:
            raise OSError("SO_BINDTODEVICE is not available on this platform (Linux only)")
        sock = self._sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, bind_option, self.interface.encode() + b"\0")
        except OSError:
            sock.close()
            raise
        self._sock = sock
        try:
            self._send(sock)
        except OSError as exc:
            if exc.errno in PERMANENT_ERRNOS:
                sock.close()
                self._sock = None
                raise
            self._failed(exc)
        self._thread = threading.Thread(target=self._loop, args=(sock,), daemon=True,
                                        name="heartbeat")
        self._thread.start()

    def _send(self, sock) -> None:
        if self.key is None:
            # connect() fixes the source address and port, which is how our flow is recognised.
            sock.connect((HEARTBEAT_DST, HEARTBEAT_PORT))
            ip, port = sock.getsockname()[:2]
            self.key = (ip, port)
        sock.send(HEARTBEAT_PAYLOAD)
        self.sent += 1
        if self.failing:
            log.info("heartbeat on %s works again", self.interface)
            self.failing = False

    def _failed(self, exc: OSError) -> None:
        if not self.failing:  # once per streak, not once a second
            log.warning("heartbeat on %s failed (%s): flows on a quiet link may be late; "
                        "retrying every %g s", self.interface, exc, self.interval)
            self.failing = True

    def note_flows(self, n: int) -> None:
        """The detector reports `n` flows that left the capture (heartbeat flows included)."""
        if n <= 0 or self.fast_interval is None:
            return
        now = self._clock()
        with self._recent_lock:
            self._recent.append((now, n))
            self._recent_total += n
            self._prune(now)

    def _prune(self, now: float) -> None:  # caller holds the lock
        cutoff = now - BURST_WINDOW
        while self._recent and self._recent[0][0] < cutoff:
            self._recent_total -= self._recent.popleft()[1]

    def _recent_flows(self, now: float) -> int:
        with self._recent_lock:
            self._prune(now)
            return self._recent_total

    def next_wait(self) -> float:
        """Seconds until the next heartbeat: fast while a backlog of finished flows drains,
        else the normal interval. Logs each switch, not each packet."""
        if self.fast_interval is None:
            return self.interval
        now = self._clock()
        recent = self._recent_flows(now)
        if not self.fast:
            if recent >= self.burst_flows:
                self.fast, self._busy_at = True, now
                self.bursts += 1
                log.info("heartbeat on %s: burst mode (every %g s) while finished flows drain",
                         self.interface, self.fast_interval)
        elif recent >= self.burst_exit_flows:
            self._busy_at = now
        elif now - self._busy_at >= BURST_HOLD:
            self.fast = False
            log.info("heartbeat on %s: back to every %g s", self.interface, self.interval)
        return self.fast_interval if self.fast else self.interval

    def _loop(self, sock) -> None:  # its own reference: stop() may clear self._sock meanwhile
        while not self._stop.wait(self.next_wait()):
            try:
                self._send(sock)
            except OSError as exc:
                self._failed(exc)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._sock is not None:
            self._sock.close()
            self._sock = None
