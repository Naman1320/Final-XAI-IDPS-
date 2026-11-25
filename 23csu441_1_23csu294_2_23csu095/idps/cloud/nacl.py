"""Block attacker IPs with network ACL deny entries.

Security groups cannot deny, so a block is a pair of DENY entries (ingress and egress) for one
address in the target subnet's network ACL.

Rule numbers: this module only ever creates, replaces or deletes entries numbered 1 to 90
(RESERVED_MIN..RESERVED_MAX). Terraform manages the ALLOW rules at 100 and above, so the two
never touch the same entry (see infra/README.md). A deny in 1..90 beats every allow, because a
network ACL is evaluated from the lowest rule number up.

NACLs have a default quota of 20 rules per direction, and Terraform's allow rules count toward
it, so `max_denies` is small (at most MAX_DENIES_LIMIT). At the cap a new block is REFUSED, so an
attacker who sprays many source addresses cannot flush the real blocks; the only thing evicted
is a block that is about to expire anyway (EVICT_IF_EXPIRES_WITHIN), and an evicted address is
released in the policy so it can be blocked again. Put admin and sensor addresses on the
allowlist: an address that is never blocked cannot be used to fill the cap.

Safety rules are the same as the lab's, and the code is shared: idps.respond.policy decides
what is never blocked (allowlist, loopback, multicast, link-local, reserved, unspecified), and
dry-run is the default and makes no AWS calls at all.

State: expiry times live in a small JSON file, because NACL entries cannot expire by
themselves. `reconcile()` compares it with DescribeNetworkAcls at start-up.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from collections.abc import Callable
from ipaddress import IPv4Address, ip_address
from pathlib import Path

from idps.respond.nft import BlockerError
from idps.respond.policy import ResponsePolicy, normalise_ip

log = logging.getLogger("idps.cloud.nacl")

RESERVED_MIN = 1
RESERVED_MAX = 90
DEFAULT_MAX_DENIES = 10
MAX_DENIES_LIMIT = 10  # 20 rules per direction by default, minus Terraform's allow rules
EVICT_IF_EXPIRES_WITHIN = 120.0  # seconds: only a block this close to expiry may be evicted
LIMIT_BACKOFF = 300.0  # seconds without new blocks after NetworkAclEntryLimitExceeded
DIRECTIONS = ("ingress", "egress")
_NOT_FOUND = "InvalidNetworkAclEntry.NotFound"
_ALREADY_EXISTS = "NetworkAclEntryAlreadyExists"
_LIMIT_EXCEEDED = "NetworkAclEntryLimitExceeded"
_STATE_VERSION = 1


class CapReached(BlockerError):
    """No room for another deny (our cap, or AWS's NetworkAclEntryLimitExceeded)."""


def _aws_errors() -> tuple[type[Exception], ...]:
    from botocore.exceptions import BotoCoreError, ClientError

    return (ClientError, BotoCoreError)


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def _check_number(number: int) -> int:
    """The invariant of this module: never touch a rule number outside 1..90."""
    if not (isinstance(number, int) and RESERVED_MIN <= number <= RESERVED_MAX):
        raise BlockerError(
            f"rule number {number!r} is outside the reserved range "
            f"{RESERVED_MIN}-{RESERVED_MAX}; refusing to touch it")
    return number


def _host_cidr(addr) -> str:
    return f"{addr}/32" if isinstance(addr, IPv4Address) else f"{addr}/128"


def _entry_host(entry: dict) -> str | None:
    """The single address a deny-all entry blocks, or None if it is anything else."""
    if entry.get("RuleAction") != "deny" or str(entry.get("Protocol")) != "-1":
        return None
    cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
    if not cidr or "/" not in cidr:
        return None
    host, _, length = cidr.partition("/")
    try:
        addr = ip_address(host)
    except ValueError:
        return None
    if length != ("32" if isinstance(addr, IPv4Address) else "128"):
        return None
    return str(addr)


class NaclBlocker:
    """Implements idps.respond.engine.Blocker for one network ACL."""

    def __init__(
        self,
        client,
        acl_id: str,
        policy: ResponsePolicy,
        state_path: str | Path,
        *,
        dry_run: bool = True,
        max_denies: int = DEFAULT_MAX_DENIES,
        now: Callable[[], float] = time.time,
    ) -> None:
        if not acl_id.startswith("acl-"):
            raise ValueError(f"not a network ACL id: {acl_id!r}")
        if not (1 <= max_denies <= MAX_DENIES_LIMIT):
            raise ValueError(f"max_denies must be between 1 and {MAX_DENIES_LIMIT} "
                             "(a network ACL allows 20 rules per direction by default)")
        if client is None and not dry_run:
            raise ValueError("a boto3 EC2 client is required unless dry_run is on")
        self.client = client
        self.acl_id = acl_id
        self.policy = policy
        self.state_path = Path(state_path)
        self.dry_run = dry_run
        self.max_denies = max_denies
        self._now = now
        # ip -> {"created_at", "expires_at", "ingress": int|None, "egress": int|None}
        self._blocks: dict[str, dict] = {}
        self._occupied: dict[str, set[int]] = {d: set() for d in DIRECTIONS}
        self._ready = False
        self._limit_until = 0.0  # no new blocks before this time (AWS said the ACL is full)

    # --- Blocker protocol --------------------------------------------------------------------

    def ensure_ruleset(self) -> None:
        """Compare state with the real NACL (called at start-up). No AWS calls in dry-run."""
        if self.dry_run:
            log.info("dry-run: not contacting AWS; no network ACL entries will be changed")
            return
        self.reconcile()

    def block(self, ip: str, ttl_seconds: int) -> None:
        addr = normalise_ip(ip)
        if addr is None:
            raise BlockerError(f"not an IP address: {ip!r}")
        if self.policy.is_protected(addr):
            raise BlockerError(f"{addr} is allowlisted or not blockable; refusing")
        if ttl_seconds <= 0:
            raise BlockerError("ttl_seconds must be positive")
        key = str(addr)
        if self.dry_run:
            log.warning(json.dumps({"event": "nacl_would_block", "ip": key, "acl": self.acl_id,
                                    "ttl_seconds": ttl_seconds}))
            return
        self._ensure_ready()
        self.expire()
        now = self._now()
        rec = self._blocks.get(key)
        if rec is not None:  # already denied: extend, never shorten, and finish a half-installed block
            rec["expires_at"] = max(rec["expires_at"], now + ttl_seconds)
            try:
                if now >= self._limit_until:
                    for direction in DIRECTIONS:
                        if rec[direction] is None:
                            self._install(rec, direction, addr, {})
            finally:
                self._save()
            return
        if now < self._limit_until:
            self._refuse(key, "acl_full_backoff")
        reuse: dict[str, int] = {}
        if len(self._blocks) >= self.max_denies:
            oldest = min(self._blocks, key=lambda k: self._blocks[k]["expires_at"])
            if self._blocks[oldest]["expires_at"] - now > EVICT_IF_EXPIRES_WITHIN:
                self._refuse(key, "cap")
            victim = self._blocks.pop(oldest)  # its slots are replaced below, or deleted
            reuse = {d: victim[d] for d in DIRECTIONS if victim.get(d) is not None}
            self.policy.release(oldest)  # no longer denied: let the policy block it again
            log.warning(json.dumps({"event": "nacl_evicted", "ip": oldest, "reason": "cap",
                                    "cap": self.max_denies}))
        rec = {"created_at": now, "expires_at": now + ttl_seconds, "ingress": None, "egress": None}
        self._blocks[key] = rec
        try:
            for direction in DIRECTIONS:
                self._install(rec, direction, addr, reuse)
        except BaseException:
            if rec["ingress"] is None and rec["egress"] is None:
                self._blocks.pop(key, None)
            raise
        finally:
            self._drop_leftover(reuse)
            self._save()
        log.warning(json.dumps({"event": "nacl_blocked", "ip": key, "acl": self.acl_id,
                                "ttl_seconds": ttl_seconds, "ingress": rec["ingress"],
                                "egress": rec["egress"]}))

    def _refuse(self, ip: str, reason: str):
        log.warning(json.dumps({"event": "nacl_block_refused", "ip": ip, "reason": reason,
                                "active": len(self._blocks), "cap": self.max_denies}))
        raise CapReached(f"cannot block {ip}: {reason} ({len(self._blocks)}/{self.max_denies} "
                         "denies active)")

    def unblock(self, ip: str) -> None:
        addr = normalise_ip(ip)
        if addr is None:
            raise BlockerError(f"not an IP address: {ip!r}")
        if self.dry_run:
            log.info(json.dumps({"event": "nacl_would_unblock", "ip": str(addr)}))
            return
        self._ensure_ready()
        if str(addr) in self._blocks:
            self._remove(str(addr))

    # --- Extras the collector uses -----------------------------------------------------------

    def expire(self) -> list[str]:
        """Delete the entries of blocks whose TTL has run out; returns the addresses."""
        if self.dry_run:
            return []
        self._ensure_ready()
        now = self._now()
        due = [ip for ip, rec in self._blocks.items() if rec["expires_at"] <= now]
        for ip in due:
            self._remove(ip)
            log.info(json.dumps({"event": "nacl_expired", "ip": ip}))
        return due

    def active(self) -> dict[str, dict]:
        return {ip: dict(rec) for ip, rec in self._blocks.items()}

    def reconcile(self) -> None:
        """Make state and the real NACL agree, using only rule numbers 1..90.

        - an expired block is deleted from the NACL;
        - a deny entry in 1..90 that state doesn't know is adopted with a fresh TTL (state lost);
        - a deny entry for an address that is now protected is deleted (never lock ourselves out);
        - a block missing a direction in the NACL gets that direction recreated;
        - entries in 1..90 that are not single-host denies are left alone, but their numbers
          are treated as taken; entries at 91 and above are never looked at.
        """
        if self.dry_run:
            return
        now = self._now()
        self._load()
        entries = self._describe()
        for direction in DIRECTIONS:
            self._occupied[direction] = {n for (d, n) in entries if d == direction}
        seen: dict[str, dict[str, int]] = {}
        for (direction, number), entry in sorted(entries.items()):
            host = _entry_host(entry)
            if host is not None:
                seen.setdefault(host, {})[direction] = number

        # Rebuild the block table from what the NACL really holds, keeping known expiry times.
        known = self._blocks
        self._blocks = {}
        for ip, numbers in seen.items():
            old = known.get(ip)
            self._blocks[ip] = {
                "created_at": old["created_at"] if old else now,
                "expires_at": old["expires_at"] if old else now + self.policy.ttl_seconds,
                "ingress": numbers.get("ingress"), "egress": numbers.get("egress"),
            }
            if old is None:
                log.warning(json.dumps({"event": "nacl_adopted", "ip": ip, "numbers": numbers}))
        for ip, old in known.items():
            if ip not in seen and old["expires_at"] > now:  # someone deleted it: put it back
                self._blocks[ip] = {**old, "ingress": None, "egress": None}

        for ip in sorted(self._blocks):
            rec = self._blocks[ip]
            addr = normalise_ip(ip)
            if addr is None or self.policy.is_protected(addr) or rec["expires_at"] <= now:
                self._remove(ip)
                continue
            for direction in DIRECTIONS:
                if rec[direction] is None:
                    self._install(rec, direction, addr, {})
        self._ready = True
        self._save()

    # --- Internals ---------------------------------------------------------------------------

    def _ensure_ready(self) -> None:
        if not self._ready:
            self.reconcile()

    def _api(self, name: str, **params):
        try:
            return getattr(self.client, name)(**params)
        except _aws_errors() as exc:
            code = _error_code(exc)
            if name == "delete_network_acl_entry" and code == _NOT_FOUND:
                return {}
            if code == _LIMIT_EXCEEDED:  # the ACL is full: stop asking for a while
                self._limit_until = self._now() + LIMIT_BACKOFF
                raise CapReached(f"{name} failed: network ACL entry limit reached") from exc
            raise BlockerError(f"{name} failed: {exc}") from exc

    def _describe(self) -> dict[tuple[str, int], dict]:
        """Entries numbered 1..90 only, keyed by (direction, number)."""
        response = self._api("describe_network_acls", NetworkAclIds=[self.acl_id])
        acls = response.get("NetworkAcls", [])
        if len(acls) != 1:
            raise BlockerError(f"network ACL {self.acl_id} not found")
        out: dict[tuple[str, int], dict] = {}
        for entry in acls[0].get("Entries", []):
            number = entry.get("RuleNumber")
            if isinstance(number, int) and RESERVED_MIN <= number <= RESERVED_MAX:
                out[("egress" if entry.get("Egress") else "ingress", number)] = entry
        return out

    def _params(self, number: int, direction: str, addr) -> dict:
        params = {
            "NetworkAclId": self.acl_id, "RuleNumber": _check_number(number),
            "Protocol": "-1", "RuleAction": "deny", "Egress": direction == "egress",
        }
        params["CidrBlock" if isinstance(addr, IPv4Address) else "Ipv6CidrBlock"] = _host_cidr(addr)
        return params

    def _allocate(self, direction: str) -> int:
        taken = self._occupied[direction]
        for number in range(RESERVED_MIN, RESERVED_MAX + 1):
            if number not in taken:
                return number
        raise BlockerError(f"no free {direction} rule number in {RESERVED_MIN}-{RESERVED_MAX}")

    def _install(self, rec: dict, direction: str, addr, reuse: dict[str, int]) -> None:
        """Put a deny for addr into one direction: replace an evicted slot, else create."""
        if direction in reuse:
            number = reuse[direction]
            self._api("replace_network_acl_entry", **self._params(number, direction, addr))
            del reuse[direction]  # consumed: no longer something to delete
        else:
            for attempt in (1, 2):
                number = self._allocate(direction)
                try:
                    self._api("create_network_acl_entry", **self._params(number, direction, addr))
                    break
                except BlockerError as exc:
                    if attempt == 2 or _ALREADY_EXISTS not in str(exc):
                        raise
                    # Someone took the number since we looked: refresh and pick again.
                    fresh = self._describe()
                    self._occupied[direction] = {n for (d, n) in fresh if d == direction}
        self._occupied[direction].add(number)
        rec[direction] = number

    def _drop_leftover(self, reuse: dict[str, int]) -> None:
        """Delete evicted slots that the new block did not take over (best effort)."""
        for direction, number in list(reuse.items()):
            try:
                self._delete(number, direction)
            except BlockerError as exc:
                log.error("could not delete leftover %s entry %s: %s", direction, number, exc)

    def _delete(self, number: int, direction: str) -> None:
        self._api("delete_network_acl_entry", NetworkAclId=self.acl_id,
                  RuleNumber=_check_number(number), Egress=direction == "egress")
        self._occupied[direction].discard(number)

    def _remove(self, ip: str) -> None:
        rec = self._blocks[ip]
        try:
            for direction in DIRECTIONS:
                if rec.get(direction) is not None:
                    self._delete(rec[direction], direction)
                    rec[direction] = None
                    self._save()
        finally:
            if rec["ingress"] is None and rec["egress"] is None:
                del self._blocks[ip]
                self._save()

    # --- State file --------------------------------------------------------------------------

    def _load(self) -> None:
        self._blocks = {}
        try:
            data = json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            log.error("ignoring unreadable state file %s: %s", self.state_path, exc)
            return
        if not isinstance(data, dict) or data.get("acl_id") != self.acl_id:
            log.warning("state file %s is for another network ACL; ignoring it", self.state_path)
            return
        for ip, rec in (data.get("blocks") or {}).items():
            try:
                clean = {
                    "created_at": float(rec["created_at"]),
                    "expires_at": float(rec["expires_at"]),
                    "ingress": None, "egress": None,
                }
                for d in DIRECTIONS:
                    n = rec.get(d)
                    clean[d] = _check_number(n) if n is not None else None
                if normalise_ip(ip) is None:
                    raise ValueError("bad address")
            except (KeyError, TypeError, ValueError, BlockerError) as exc:
                log.error("dropping bad state entry %r: %s", ip, exc)
                continue
            self._blocks[str(normalise_ip(ip))] = clean

    def _save(self) -> None:
        payload = {"version": _STATE_VERSION, "acl_id": self.acl_id, "blocks": self._blocks}
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.state_path.parent, prefix=".nacl-state-")
        try:
            with os.fdopen(fd, "w") as fh:  # mkstemp creates it 0600
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.state_path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
