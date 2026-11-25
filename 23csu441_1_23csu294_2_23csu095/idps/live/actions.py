"""Analyst actions: poll the SOC for confirmed block_ip / unblock_ip requests and apply them.

Everything the SOC sends is untrusted and goes through the ResponseEngine (never the blocker
directly), so the sensor's own allowlist and dry-run setting always win. The poller runs in a
daemon thread and never touches the detection loop except through the engine's lock.

Delivery: an action stays listed by the SOC until a result is reported. The outcome of every
action is kept in memory until the report is accepted, so a failed report is retried on the next
poll WITHOUT applying the action again. A 409 (already reported) means the SOC has the answer:
forget it.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from datetime import UTC, datetime, timedelta

from idps.live.metrics import Metrics
from idps.respond.engine import ActionRefused, ResponseEngine
from idps.respond.policy import normalise_ip
from idps.soc_client import SocError, SocRejectedError

log = logging.getLogger("idps.live")

MAX_UNREPORTED = 1_000  # outcomes kept while the SOC cannot take the report; oldest forgotten
MAX_APPLIED = 5_000  # ids already executed, never executed again; oldest forgotten
MAX_ACTIONS_PER_POLL = 50  # soc/api/routes/actions.py POLL_LIMIT (mirrored)
FORGET_STATUSES = frozenset({404, 409})
MAX_BACKOFF_SECONDS = 300.0
MAX_ERROR_CHARS = 300


class ActionPoller:
    def __init__(self, client, engine: ResponseEngine, sink, metrics: Metrics, *,
                 interval: float = 5.0, max_backoff: float = MAX_BACKOFF_SECONDS) -> None:
        self.client = client
        self.engine = engine
        self.sink = sink
        self.metrics = metrics
        self.interval = interval
        self.max_backoff = max_backoff
        self._unreported: OrderedDict[int, tuple[bool, dict, bool]] = OrderedDict()
        self._applied: OrderedDict[int, None] = OrderedDict()
        self._streak = False  # a failure was logged and no success has followed
        self._delay = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="action-poller", daemon=True)

    # --- thread ---------------------------------------------------------------------------

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                log.warning("the action poller is still busy after %g s; abandoning it", timeout)
        if self._unreported:
            log.warning("%d analyst action result(s) were applied but never reported to the SOC "
                        "(it will list them again and the next run applies them again)",
                        len(self._unreported))

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                ok = self.poll_once()
            except Exception as exc:  # noqa: BLE001  the poller must survive anything
                log.error("action poller error: %s: %s", type(exc).__name__, exc)
                ok = False
            if ok:
                self._delay = self.interval
            else:
                self._delay = min(self._delay * 2, self.max_backoff)
            self._stop.wait(self._delay)

    # --- one round ------------------------------------------------------------------------

    def poll_once(self) -> bool:
        """Retry unsent reports, fetch, apply and report new actions. False if the SOC failed."""
        if not self._flush_unreported():
            return False
        try:
            actions = self.client.get_actions()
        except SocError as exc:
            self._fail(f"cannot fetch analyst actions: {exc}")
            return False
        for action in actions[:MAX_ACTIONS_PER_POLL]:  # the SOC never hands out more
            if self._stop.is_set():
                break
            action_id = action.get("id") if isinstance(action, dict) else None
            if isinstance(action_id, bool) or not isinstance(action_id, int) or action_id < 1:
                log.warning("ignoring an analyst action without a valid id")
                continue
            if action_id in self._applied:
                continue  # executed already (also a duplicate within this response)
            self._mark_applied(action_id)
            success, result = self._execute(action_id, action)
            self._remember(action_id, success, result)
            if not self._flush_unreported():
                return False
        self._streak_over()
        return True

    def _flush_unreported(self) -> bool:
        for action_id in list(self._unreported):
            if self._stop.is_set():
                return True
            success, result, minimal = self._unreported[action_id]
            while True:
                try:
                    self.client.post_action_result(action_id, success, result)
                except SocRejectedError as exc:
                    if exc.status in FORGET_STATUSES:
                        # 409 already reported, 404 not ours: the SOC stops listing it.
                        log.info("action %d: the SOC answered HTTP %s; forgetting it",
                                 action_id, exc.status)
                    elif exc.is_config_error:  # 401 / 403: keep it, fix the token
                        self._fail(f"the SOC answered HTTP {exc.status} to an action result: "
                                   "check the sensor token")
                        return False
                    elif not minimal:
                        # 400 / 413 / 422: the action stays confirmed at the SOC, so say something
                        # it will accept, once: a failed result with a short fixed message.
                        log.warning("action %d: the SOC refused the result (HTTP %s); sending a "
                                    "minimal one", action_id, exc.status)
                        success, result, minimal = False, {
                            "error": f"result refused by the SOC (HTTP {exc.status})"}, True
                        self._unreported[action_id] = (success, result, minimal)
                        continue
                    else:
                        log.error("action %d: the SOC refused even a minimal result (HTTP %s); "
                                  "giving up on it", action_id, exc.status)
                except SocError as exc:
                    self._fail(f"cannot report the result of action {action_id}: {exc}")
                    return False
                break
            self._unreported.pop(action_id, None)
        return True

    def _mark_applied(self, action_id: int) -> None:
        self._applied[action_id] = None
        while len(self._applied) > MAX_APPLIED:
            self._applied.popitem(last=False)

    def _remember(self, action_id: int, success: bool, result: dict) -> None:
        self._unreported[action_id] = (success, result, False)
        while len(self._unreported) > MAX_UNREPORTED:
            dropped, _ = self._unreported.popitem(last=False)
            log.error("dropping the unsent result of action %d (over %d waiting)", dropped,
                      MAX_UNREPORTED)

    def _fail(self, why: str) -> None:
        if not self._streak:
            self._streak = True
            log.error("%s; retrying with backoff (further failures are not logged until it "
                      "recovers)", why)

    def _streak_over(self) -> None:
        if self._streak:
            self._streak = False
            log.info("the SOC is reachable again; analyst actions resume")

    # --- executing ------------------------------------------------------------------------

    def _execute(self, action_id: int, action: dict) -> tuple[bool, dict]:
        try:
            result = self._apply(action_id, action)
        except ActionRefused as exc:
            self.metrics.add("actions_failed")
            log.warning("analyst action %d not applied: %s", action_id, exc)
            return False, {"error": str(exc)[:MAX_ERROR_CHARS]}
        except Exception as exc:  # noqa: BLE001  e.g. an unexpected blocker error
            self.metrics.add("actions_failed")
            log.error("analyst action %d failed: %s: %s", action_id, type(exc).__name__, exc)
            return False, {"error": f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]}
        self.metrics.add("actions_executed")
        return True, result

    def _apply(self, action_id: int, action: dict) -> dict:
        kind = action.get("kind")
        params = action.get("params")
        if not isinstance(params, dict):
            raise ActionRefused("invalid action parameters")
        raw_ip = params.get("ip")
        addr = normalise_ip(raw_ip) if isinstance(raw_ip, str) else None
        if kind not in ("block_ip", "unblock_ip"):
            raise ActionRefused("unknown action kind")
        if addr is None:
            raise ActionRefused("invalid ip")
        ip = str(addr)
        if kind == "block_ip":
            ttl = params.get("ttl_seconds")
            if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1):
                raise ActionRefused("ttl_seconds must be a positive integer")
            applied = self.engine.manual_block(ip, ttl, action_id=action_id)  # caps the TTL
            expires = (datetime.now(UTC) + timedelta(seconds=applied)).isoformat()
            self._queue({"event": "blocked", "ip": ip, "source": "analyst",
                         "reason": f"analyst action {action_id}", "expires_at": expires})
            return {"ip": ip, "ttl_seconds": applied}
        self.engine.manual_unblock(ip, action_id=action_id)
        self._queue({"event": "unblocked", "ip": ip})
        return {"ip": ip, "grace_seconds": self.engine.grace_seconds}

    def _queue(self, event: dict) -> None:
        try:
            self.sink.submit_blocks([event])
        except Exception as exc:  # noqa: BLE001  reporting to the Blocks page is best effort
            log.error("cannot queue the %s report for %s: %s: %s", event["event"], event["ip"],
                      type(exc).__name__, exc)
            self.metrics.add("blocks_dropped")
