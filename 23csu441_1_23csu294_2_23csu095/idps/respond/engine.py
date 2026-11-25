"""Response engine: feed detections in, get blocks (or dry-run log lines) out.

Two threads use it: the detector (`handle`) and the analyst-action poller (`manual_block`,
`unblock`). One lock guards the policy and the override maps; it is NOT held during nft calls
(they can take seconds and would stall detection). Those run under a per-address lock instead,
which keeps an automatic and an analyst change of the same address from interleaving.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from idps.config import Settings
from idps.respond.nft import BlockerError, NftBlocker
from idps.respond.policy import Action, Decision, Detection, ResponsePolicy, normalise_ip

log = logging.getLogger("idps.respond")

MAX_MANUAL_TTL_SECONDS = 86_400  # same ceiling as Settings.block_ttl_seconds
MAX_GRACE_ENTRIES = 10_000
DRY_RUN_ERROR = "sensor is in dry-run: not applied"


class ActionRefused(Exception):
    """An analyst action was not applied; the message is safe to show to the analyst."""


class Blocker(Protocol):
    def ensure_ruleset(self) -> None: ...
    def block(self, ip: str, ttl_seconds: int) -> None: ...
    def unblock(self, ip: str) -> None: ...


class ResponseEngine:
    def __init__(
        self,
        settings: Settings,
        blocker: Blocker | None = None,
        policy: ResponsePolicy | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        **policy_options,
    ) -> None:
        self.dry_run = settings.dry_run
        self.policy = policy or ResponsePolicy.from_settings(settings, **policy_options)
        self.blocker = blocker if blocker is not None else NftBlocker()
        self.grace_seconds = settings.unblock_grace_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self.max_analyst_blocks = settings.max_analyst_blocks
        self._grace_until: OrderedDict[str, float] = OrderedDict()  # ip -> clock() deadline
        self._manual_until: dict[str, float] = {}  # analyst blocks still active -> clock() end
        self._ip_locks = [threading.Lock() for _ in range(64)]  # serialise nft calls per address
        if not self.dry_run:
            self.blocker.ensure_ruleset()  # fail at startup, not on the first attack

    def handle(self, detection: Detection) -> Decision:
        with self._lock:
            decision = self.policy.evaluate(detection)
            if decision.action is not Action.BLOCK:
                return decision
            early = self._override_decision(decision)
            if early is not None:
                return early
            if self.dry_run:
                self._audit("would_block", decision)
                return decision
        return self._apply(decision)

    def _override_decision(self, decision: Decision) -> Decision | None:
        """An analyst's decision beats the automatic one (caller holds the lock): an analyst block
        that is still active is left alone (no nft call, so it is never shortened), and a recently
        unblocked address is not blocked again."""
        ip = decision.ip
        if self._manual_active(ip):
            return Decision(Action.ALREADY_BLOCKED, ip, "blocked by an analyst",
                            flows_in_window=decision.flows_in_window, detection=decision.detection)
        if self._in_grace(ip):
            self.policy.release(ip)  # not blocked: the next flows count afresh
            suppressed = Decision(
                Action.SUPPRESSED, ip, "an analyst unblocked this address recently",
                flows_in_window=decision.flows_in_window, detection=decision.detection)
            self._audit("block_suppressed_by_analyst", suppressed)
            return suppressed
        return None

    def _apply(self, decision: Decision) -> Decision:
        # The nft call runs outside the main lock (it can take seconds), under the address's own
        # lock, which analyst actions on the same address also take: the two never interleave.
        with self._ip_lock(decision.ip):
            with self._lock:  # an analyst may have acted since the policy decided
                early = self._override_decision(decision)
                if early is not None:
                    return early
            try:
                self.blocker.block(decision.ip, decision.ttl_seconds)
            except BlockerError as exc:
                with self._lock:
                    self.policy.release(decision.ip)  # so the next flow retries
                    self._audit("block_failed", decision, error=str(exc))
                return Decision(
                    Action.OBSERVE, decision.ip, f"block failed: {exc}",
                    flows_in_window=decision.flows_in_window, detection=decision.detection,
                )
            with self._lock:
                self._audit("blocked", decision)
            return decision

    # --- analyst overrides ---------------------------------------------------------------

    def manual_block(self, ip: str, ttl_seconds: int | None = None, *,
                     action_id: int | None = None) -> int:
        """Analyst block under the same safety rules as an automatic one. Returns the TTL applied
        (default: the policy's, capped at MAX_MANUAL_TTL_SECONDS). Raises ActionRefused."""
        addr = normalise_ip(ip)
        if addr is None:
            raise ActionRefused("not an IP address")
        ip = str(addr)
        ttl = self.policy.ttl_seconds if ttl_seconds is None else ttl_seconds
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1:
            raise ActionRefused("ttl_seconds must be a positive integer")
        ttl = min(ttl, MAX_MANUAL_TTL_SECONDS)
        with self._ip_lock(ip):
            with self._lock:
                if self.policy.is_protected(addr):  # the sensor's allowlist always comes first
                    raise ActionRefused(
                        "refused: the address is allowlisted or not blockable on this sensor")
                if self.dry_run:
                    self._audit_manual("would_block", ip, action_id, ttl_seconds=ttl)
                    raise ActionRefused(DRY_RUN_ERROR)
                self._prune_manual()
                if ip not in self._manual_until and len(self._manual_until) >= self.max_analyst_blocks:
                    raise ActionRefused(
                        f"refused: this sensor already holds {self.max_analyst_blocks} analyst blocks")
            try:
                self.blocker.block(ip, ttl)
            except BlockerError as exc:
                with self._lock:
                    self._audit_manual("block_failed", ip, action_id, ttl_seconds=ttl, error=str(exc))
                raise ActionRefused(f"block failed: {exc}"[:300]) from exc
            with self._lock:
                self._grace_until.pop(ip, None)  # an analyst block ends the unblock grace period
                self._manual_until.pop(ip, None)
                self._manual_until[ip] = self._clock() + ttl
                self._audit_manual("blocked", ip, action_id, ttl_seconds=ttl)
            return ttl

    def unblock(self, ip: str, *, action_id: int | None = None) -> None:
        """Analyst unblock. Safe to call in dry-run (nothing was blocked). Starts the grace period
        during which the automatic policy does not block the address again."""
        addr = normalise_ip(ip)
        if addr is None:
            raise ValueError(f"not an IP address: {ip!r}")
        ip = str(addr)
        with self._ip_lock(ip):
            if not self.dry_run:
                self.blocker.unblock(ip)
            with self._lock:
                self.policy.release(ip)
                self._manual_until.pop(ip, None)
                if self.grace_seconds > 0:
                    self._grace_until.pop(ip, None)
                    self._grace_until[ip] = self._clock() + self.grace_seconds
                    self._prune_grace()
                log.info(json.dumps({"event": "unblocked", "ip": ip, "dry_run": self.dry_run,
                                     "source": "analyst", "action_id": action_id,
                                     "grace_seconds": self.grace_seconds}))

    def manual_unblock(self, ip: str, *, action_id: int | None = None) -> None:
        """`unblock` for the action poller: refused in dry-run, so the analyst is not misled."""
        if self.dry_run:
            raise ActionRefused(DRY_RUN_ERROR)
        try:
            self.unblock(ip, action_id=action_id)
        except (ValueError, BlockerError) as exc:
            raise ActionRefused(f"unblock failed: {exc}"[:300]) from exc

    def _ip_lock(self, ip: str) -> threading.Lock:
        return self._ip_locks[hash(ip) % len(self._ip_locks)]

    def _manual_active(self, ip: str) -> bool:
        until = self._manual_until.get(ip)
        if until is None:
            return False
        if self._clock() >= until:
            del self._manual_until[ip]
            return False
        return True

    def _prune_manual(self) -> None:
        now = self._clock()
        for key in [k for k, v in self._manual_until.items() if v <= now]:
            del self._manual_until[key]

    def _in_grace(self, ip: str) -> bool:
        until = self._grace_until.get(ip)
        if until is None:
            return False
        if self._clock() >= until:
            del self._grace_until[ip]
            return False
        return True

    def _prune_grace(self) -> None:
        now = self._clock()
        for key in [k for k, v in self._grace_until.items() if v <= now]:
            del self._grace_until[key]
        while len(self._grace_until) > MAX_GRACE_ENTRIES:
            self._grace_until.popitem(last=False)

    def _audit_manual(self, event: str, ip: str, action_id: int | None, **extra) -> None:
        log.warning(json.dumps({"event": event, "ip": ip, "dry_run": self.dry_run,
                                "source": "analyst", "action_id": action_id, **extra}))

    def _audit(self, event: str, d: Decision, **extra) -> None:
        det = d.detection
        record = {
            "event": event, "ip": d.ip, "dry_run": self.dry_run, "ttl_seconds": d.ttl_seconds,
            "reason": d.reason, "flows": d.flows_in_window,
            "label": det.label if det else None,
            "confidence": det.confidence if det else None,
            "explanation": det.explanation if det else None,  # every block is logged with its why
            **extra,
        }
        log.warning(json.dumps(record, default=str))
