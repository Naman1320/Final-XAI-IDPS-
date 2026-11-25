"""Block decisions: allowlist, confidence threshold, N malicious flows in a window, TTL.

The policy is pure logic (no nftables, no clock of its own): it is fed one
`Detection` at a time and answers with a `Decision`. Time comes from the
detection's timestamp, so replayed PCAPs and tests behave deterministically.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address

from idps.config import Settings

MAX_IP_TEXT = 45  # the longest textual IPv6 address (with an embedded IPv4 tail)
BENIGN_LABELS = frozenset({"benign", "normal"})


class Action(str, Enum):
    BLOCK = "block"  # caller should block this IP now
    ALREADY_BLOCKED = "already_blocked"
    OBSERVE = "observe"  # malicious, but not enough evidence yet
    BELOW_THRESHOLD = "below_threshold"
    BENIGN = "benign"
    ALLOWLISTED = "allowlisted"  # never blocked, whatever the model says
    INVALID = "invalid"  # not a blockable address
    SUPPRESSED = "suppressed_by_analyst"  # would block, but an analyst unblocked it recently


@dataclass(frozen=True)
class Detection:
    """One classified flow, as the detection loop hands it over."""

    src_ip: str
    label: str
    confidence: float
    timestamp: float  # seconds; any monotone-ish clock, used for windows and TTLs
    explanation: dict | None = None  # SHAP summary etc., stored with the block
    # How many flows this detection counts as in the window. 1 for a model detection. The rule
    # forwarder (idps.rules) gives a rule the operator explicitly allowed to block min_flows, so
    # one hit of it is enough evidence; everything else in evaluate() applies unchanged.
    weight: int = 1
    # Replaces the evidence text of a BLOCK decision's reason ("5 flows >= 0.9 confidence ...") for
    # detections that are not flows, e.g. "Suricata rule sid 2009358 (...) matched".
    note: str | None = None


@dataclass(frozen=True)
class Decision:
    action: Action
    ip: str  # normalised address, or the raw input when INVALID
    reason: str
    ttl_seconds: int | None = None
    flows_in_window: int = 0
    detection: Detection | None = field(default=None, repr=False)


def normalise_ip(value: str) -> IPv4Address | IPv6Address | None:
    """Parse an address; unwrap IPv4-mapped IPv6 so ::ffff:10.0.0.1 can't dodge the allowlist.

    Scoped addresses (`fe80::1%eth0`) are refused, and so is anything over MAX_IP_TEXT characters:
    the result is printed into nft commands, and the scope text is arbitrary. The address is
    rebuilt from its integer value, so what comes back never carries a scope."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > MAX_IP_TEXT or "%" in value:
        return None
    try:
        addr = ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, IPv6Address):
        if addr.scope_id is not None:
            return None
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        return IPv6Address(int(addr))
    return IPv4Address(int(addr))


class ResponsePolicy:
    def __init__(
        self,
        allowlist,
        *,
        confidence_threshold: float = 0.9,
        ttl_seconds: int = 900,
        min_flows: int = 5,
        window_seconds: float = 60.0,
        max_tracked_ips: int = 10_000,
    ) -> None:
        if min_flows < 1:
            raise ValueError("min_flows must be at least 1")
        if window_seconds <= 0 or ttl_seconds <= 0:
            raise ValueError("window_seconds and ttl_seconds must be positive")
        self.allowlist = tuple(allowlist)
        self.confidence_threshold = confidence_threshold
        self.ttl_seconds = ttl_seconds
        self.min_flows = min_flows
        self.window_seconds = window_seconds
        self.max_tracked_ips = max_tracked_ips
        self._flows: OrderedDict[str, deque[float]] = OrderedDict()
        self._blocked_until: dict[str, float] = {}

    @classmethod
    def from_settings(cls, settings: Settings, **overrides) -> ResponsePolicy:
        return cls(
            settings.allowlist,
            confidence_threshold=settings.confidence_threshold,
            ttl_seconds=settings.block_ttl_seconds,
            **overrides,
        )

    def is_protected(self, addr: IPv4Address | IPv6Address) -> bool:
        """True for allowlisted networks and for addresses that make no sense to block."""
        if (
            addr.is_unspecified
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_reserved
        ):
            return True
        if isinstance(addr, IPv4Address) and int(addr) == 0xFFFFFFFF:  # limited broadcast
            return True
        return any(addr in net for net in self.allowlist)

    def evaluate(self, d: Detection) -> Decision:
        addr = normalise_ip(d.src_ip)
        if addr is None:
            return Decision(Action.INVALID, str(d.src_ip), "not an IP address", detection=d)
        ip = str(addr)

        # The allowlist comes first: nothing below can override it.
        if self.is_protected(addr):
            return Decision(Action.ALLOWLISTED, ip, "allowlisted or non-blockable", detection=d)

        if d.label.strip().lower() in BENIGN_LABELS:
            return Decision(Action.BENIGN, ip, "benign flow", detection=d)

        if not (d.confidence >= self.confidence_threshold):  # also rejects NaN
            return Decision(
                Action.BELOW_THRESHOLD, ip,
                f"confidence {d.confidence:.3f} < {self.confidence_threshold}", detection=d,
            )

        until = self._blocked_until.get(ip)
        if until is not None:
            if d.timestamp < until:
                return Decision(Action.ALREADY_BLOCKED, ip, f"blocked until t={until:.0f}", detection=d)
            del self._blocked_until[ip]  # expired; nftables dropped it too

        count = self._count(ip, d.timestamp, d.weight)
        if count < self.min_flows:
            return Decision(
                Action.OBSERVE, ip,
                f"{count}/{self.min_flows} malicious flows in {self.window_seconds:g}s",
                flows_in_window=count, detection=d,
            )

        self._blocked_until[ip] = d.timestamp + self.ttl_seconds
        self._flows.pop(ip, None)  # start fresh after the ban
        return Decision(
            Action.BLOCK, ip,
            d.note or f"{count} flows >= {self.confidence_threshold} confidence ({d.label}) in {self.window_seconds:g}s",
            ttl_seconds=self.ttl_seconds, flows_in_window=count, detection=d,
        )

    def release(self, ip: str) -> None:
        """Forget a block (unblocked by an analyst, or the nftables call failed)."""
        addr = normalise_ip(ip)
        if addr is not None:
            self._blocked_until.pop(str(addr), None)

    def _count(self, ip: str, now: float, weight: int = 1) -> int:
        times = self._flows.pop(ip, None)
        if times is None:
            times = deque()
        times.extend([now] * min(max(int(weight), 1), self.min_flows))
        while times and times[0] < now - self.window_seconds:
            times.popleft()
        self._flows[ip] = times  # most recently seen goes last
        while len(self._flows) > self.max_tracked_ips:  # bound memory against spoofed sources
            self._flows.popitem(last=False)
        return len(times)
