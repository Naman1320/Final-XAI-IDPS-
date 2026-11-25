"""The rule forwarder: Suricata's alerts, read from its eve.json, sent to the SOC as rule alerts.

    eve.json --tail--> parse --> drop engine events / informational alerts --> fold repeats --> rate limit --> sink
                                                                         \\--> (only listed SIDs) response engine

It runs in its own thread next to the detection loop and shares its sink (the SOC outbox), so a
rule alert travels like a model alert: queued, retried, never blocking detection. Rule alerts have
their own outbox cap (idps.soc_client.Outbox), so a rule flood cannot push model alerts out.

Folding repeats: the first event of a (sid, src ip, dst ip, dst port) is sent at once with count 1
(an analyst sees an attack as it starts). Repeats of the same key inside `dedupe_seconds` of EVENT
time (the eve timestamp) are not sent but counted; when the window ends and there were repeats, ONE
follow-up alert goes out with `count` = all events of the window, `start_ms` the first event and
`end_ms` the last. The same rule hitting the same source, destination and port 500 times is two
alerts per window. A scan touches many ports or hosts, and each of those is its own key, so it can
still produce many alerts; `max_per_minute` (IDPS_RULES_MAX_PER_MINUTE, default 120) caps what is
queued per minute and counts the excess as `rate_limited`.

Blocking: rule alerts never block, unless the rule's SID is in IDPS_RULES_BLOCK_SIDS. A listed rule
is handed to the response engine as a detection with confidence 1.0. Evidence: only a TCP event on an
established flow (Suricata saw an application protocol, or packets both ways) counts as the policy's
`min_flows` flows, so one hit of a rule the operator explicitly trusted is enough; any other event
(UDP, ICMP, a bare SYN: all forgeable with one spoofed packet) counts as ONE flow, like a single
confident model detection. Everything else is the model's path unchanged: the allowlist is checked
first, dry-run only records a would-block, an analyst's unblock grace period is respected, and a block
is reported to the SOC the same way. Further refusals before the engine: only "to_server" events (the
source of a "to_client" event is the server) and no source inside IDPS_RULES_PROTECTED_NETS; engine
events never block, and informational alerts only when their SID is listed (a listed SID bypasses the
informational filter, as the operator asked for it by number).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address

from idps.respond.policy import Detection
from idps.rules.config import RulesSettings
from idps.rules.eve import is_established_tcp, parse_alert_line, printable, rule_alert_payload
from idps.rules.tail import EveTailer

log = logging.getLogger("idps.live")

MAX_TRACKED_KEYS = 10_000  # de-duplication windows kept at once; the oldest is closed beyond this
ERROR_TEXT_LIMIT = 300  # soc/api/routes/sensors.py RulesInfo.error (mirrored)
MAX_PATH_TEXT = 256
LOG_EVERY = 100  # a repeated condition is logged for the first event and then every this many


@dataclass
class _Window:
    first: dict  # the first event of the window (parsed), the template of the follow-up
    first_ms: int
    last_ms: int
    count: int
    expires_ms: int  # event time: first event + dedupe window


class RuleForwarder:
    """`sink` needs `submit(list[dict])`. `respond(Detection)` is the detection loop's entry to the
    response engine (LiveDetector.respond); without it nothing can block. `block_weight` is the
    policy's min_flows."""

    def __init__(self, settings: RulesSettings, sink, *, respond: Callable[[Detection], None] | None = None,
                 block_weight: int = 1, tailer: EveTailer | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time) -> None:
        self.settings = settings
        self.sink = sink
        self.respond = respond
        self.block_weight = max(1, int(block_weight))
        self.block_sids = frozenset(settings.block_sids)
        self.tailer = tailer or EveTailer(settings.eve or "", from_start=settings.from_start)
        self._clock, self._wall = clock, wall
        self._windows: OrderedDict[tuple, _Window] = OrderedDict()
        self._out: list[dict] = []
        self._lock = threading.Lock()  # counters and last_event_at: the status reporter reads them
        self._c = dict.fromkeys(("alerts_sent", "dropped_engine", "dropped_info", "deduped",
                                 "dropped_invalid", "rate_limited", "block_skipped"), 0)
        self._rate_start, self._rate_n = clock(), 0
        self._tail_losses = 0  # tailer fragments / over-long lines already added to dropped_invalid
        self._last_event_ms: int | None = None
        self._error: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="rule-forwarder", daemon=True)

    # --- status ---------------------------------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            last = (datetime.fromtimestamp(self._last_event_ms / 1000, UTC).isoformat()
                    if self._last_event_ms is not None else None)
            return {"enabled": True, "eve_path": printable(self.settings.eve, MAX_PATH_TEXT), **self._c,
                    "last_event_at": last, "error": self._error,
                    "include_info": self.settings.include_info,
                    "dedupe_seconds": self.settings.dedupe_seconds,
                    "max_per_minute": self.settings.max_per_minute,
                    "block_sids": len(self.block_sids)}

    def _count(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._c[name] += n

    def _set_error(self, text: str | None) -> None:
        with self._lock:
            self._error = printable(text, ERROR_TEXT_LIMIT) or None

    # --- one poll -------------------------------------------------------------------------------

    def poll_once(self) -> int:
        """Read what Suricata wrote since the last poll, handle it and close the finished
        de-duplication windows; returns the number of lines read. Never raises."""
        try:
            lines = self.tailer.read_new()
        except OSError as exc:
            self._set_error(f"cannot read {self.settings.eve}: {type(exc).__name__}: {exc}")
            lines = []
        else:
            self._set_error(None if self.tailer.exists
                            else f"{self.settings.eve} does not exist yet (is Suricata running?)")
        lost = getattr(self.tailer, "fragments_dropped", 0) + getattr(self.tailer, "skipped_lines", 0)
        if lost > self._tail_losses:  # half lines dropped by a truncation, over-long lines
            self._count("dropped_invalid", lost - self._tail_losses)
            self._tail_losses = lost
        self.handle_lines(lines)
        return len(lines)

    def handle_lines(self, lines: list[str]) -> None:
        for line in lines:
            try:
                self.handle_line(line)
            except Exception:
                log.exception("rule forwarder: cannot handle an eve line")
                self._count("dropped_invalid")
        self._close_windows(int(self._wall() * 1000))
        self._flush()

    def handle_line(self, line: str) -> None:
        if not line.lstrip().startswith("{"):  # a fragment, e.g. the tail of a line cut by a restart
            self._count("dropped_invalid")
            return
        try:
            ev = parse_alert_line(line)
        except (ValueError, KeyError, TypeError):
            self._count("dropped_invalid")
            return
        if ev is None:
            return  # not an alert event (this setup writes none, but a shared file might)
        with self._lock:
            self._last_event_ms = ev["ts_ms"]
        if ev["engine"]:
            self._count("dropped_engine")
            return
        listed = ev["sid"] in self.block_sids
        if ev["informational"] and not self.settings.include_info and not listed:
            self._count("dropped_info")  # a listed SID is not dropped: the operator asked for it
            return
        payload = rule_alert_payload(ev)
        if payload is None:
            self._count("dropped_invalid")
            return
        self._dedupe(ev, payload)
        if listed:
            self._maybe_block(ev, payload)

    # --- de-duplication ---------------------------------------------------------------------------

    def _dedupe(self, ev: dict, payload: dict) -> None:
        window_s = self.settings.dedupe_seconds
        if window_s <= 0:
            self._emit(payload)
            return
        key = (ev["sid"], ev["src_ip"], ev["dst_ip"], ev["dst_port"])
        win = self._windows.get(key)
        if win is not None and ev["ts_ms"] >= win.expires_ms:
            self._finish(self._windows.pop(key))
            win = None
        if win is not None:
            win.count += 1
            win.last_ms = max(win.last_ms, ev["ts_ms"])
            self._count("deduped")
            return
        self._windows[key] = _Window(ev, ev["ts_ms"], ev["ts_ms"], 1, ev["ts_ms"] + int(window_s * 1000))
        self._emit(payload)
        while len(self._windows) > MAX_TRACKED_KEYS:
            self._finish(self._windows.popitem(last=False)[1])

    def _finish(self, win: _Window) -> None:
        """A window ended: if the rule repeated, queue the follow-up alert with the count."""
        if win.count > 1:
            follow = rule_alert_payload(win.first, win.count, start_ms=win.first_ms, end_ms=win.last_ms)
            if follow is not None:
                self._emit(follow)

    def _emit(self, payload: dict) -> None:
        """Queue one alert unless this minute's quota is used up."""
        limit = self.settings.max_per_minute
        if limit:
            now = self._clock()
            if now - self._rate_start >= 60.0:
                self._rate_start, self._rate_n = now, 0
            if self._rate_n >= limit:
                self._count("rate_limited")
                return
            self._rate_n += 1
        self._out.append(payload)

    def _close_windows(self, now_ms: int) -> None:
        while self._windows:
            key, win = next(iter(self._windows.items()))
            if now_ms < win.expires_ms:
                break  # windows are in creation order, so the rest are younger
            del self._windows[key]
            self._finish(win)

    def close_all_windows(self) -> None:
        """Send the follow-ups of every open window (at shutdown)."""
        while self._windows:
            self._finish(self._windows.popitem(last=False)[1])
        self._flush()

    def _flush(self) -> None:
        if not self._out:
            return
        batch, self._out = self._out, []
        try:
            self.sink.submit(batch)
        except Exception as exc:  # noqa: BLE001  the sink must never stop the forwarder
            log.error("cannot queue %d rule alert(s): %s: %s", len(batch), type(exc).__name__, exc)
            return
        self._count("alerts_sent", len(batch))

    # --- blocking -------------------------------------------------------------------------------

    def _skip_block(self, why: str, sid: int) -> None:
        self._count("block_skipped")
        n = self._c["block_skipped"]
        if n == 1 or n % LOG_EVERY == 0:
            log.info("rule %s may block but this event was not handed to the response engine (%s); "
                     "%d such event(s) so far", sid, why, n)

    def _maybe_block(self, ev: dict, payload: dict) -> None:
        if self.respond is None:
            return
        rule = payload["rule"]
        if ev.get("direction") != "to_server":
            return self._skip_block("not to_server", rule["sid"])
        try:
            addr = ip_address(ev["src_ip"])
        except ValueError:
            return self._skip_block("bad source address", rule["sid"])
        if any(addr.version == net.version and addr in net for net in self.settings.protected_nets):
            return self._skip_block("source is in IDPS_RULES_PROTECTED_NETS", rule["sid"])
        weight = self.block_weight if is_established_tcp(ev) else 1
        detection = Detection(
            src_ip=ev["src_ip"], label=f"rule {rule['sid']}"[:64], confidence=1.0,
            timestamp=self._wall(), weight=weight,
            note=f"Suricata rule sid {rule['sid']} ({rule['signature'][:200]}) matched",
            explanation={"source": "rule", "sid": rule["sid"], "rev": rule["rev"],
                         "signature": rule["signature"], "category": rule["category"],
                         "severity": rule["severity"]})
        try:
            self.respond(detection)
        except Exception as exc:  # noqa: BLE001
            log.error("response engine failed for rule %s: %s: %s", rule["sid"],
                      type(exc).__name__, exc)

    # --- thread ---------------------------------------------------------------------------------

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self.tailer.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                log.exception("rule forwarder poll failed")
            self._stop.wait(self.settings.poll_seconds)
        try:
            self.poll_once()  # what Suricata wrote since the last poll
            self.close_all_windows()
        except Exception:
            log.exception("rule forwarder: final flush failed")
