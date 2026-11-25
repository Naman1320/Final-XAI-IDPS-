"""nftables backend: a set with per-element timeouts in its own table, via the `nft` CLI.

The lab firewall lives in `inet labfw` (lab/sensor/nftables.conf). We use a separate
table, `inet idps`, hooked before it (priority -10), so unblocking never touches lab rules.
Expiry is done by nftables itself: when a TTL runs out the element disappears.
"""

from __future__ import annotations

import re
import subprocess
from ipaddress import IPv4Address

from idps.respond.policy import normalise_ip

TABLE = "idps"
SET_V4 = "blocked4"
SET_V6 = "blocked6"

# One atomic transaction. `add` is idempotent; the flush makes the rules idempotent too.
# Sets are not flushed, so active blocks survive a restart of the engine.
RULESET = f"""\
add table inet {TABLE}
add set inet {TABLE} {SET_V4} {{ type ipv4_addr; flags timeout; }}
add set inet {TABLE} {SET_V6} {{ type ipv6_addr; flags timeout; }}
add chain inet {TABLE} prevent {{ type filter hook forward priority -10; policy accept; }}
flush chain inet {TABLE} prevent
add rule inet {TABLE} prevent ip saddr @{SET_V4} counter drop comment "idps block"
add rule inet {TABLE} prevent ip6 saddr @{SET_V6} counter drop comment "idps block"
"""


class BlockerError(RuntimeError):
    pass


class NftBlocker:
    def __init__(self, nft_binary: str = "nft", timeout: float = 5.0) -> None:
        self.nft = nft_binary
        self.timeout = timeout

    def _run(self, args: list[str], stdin: str | None = None) -> str:
        try:
            proc = subprocess.run(
                [self.nft, *args], input=stdin, capture_output=True, text=True,
                timeout=self.timeout, check=False,  # return code handled below
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BlockerError(f"nft failed to run: {exc}") from exc
        if proc.returncode != 0:
            raise BlockerError(f"nft {' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}")
        return proc.stdout

    @staticmethod
    def _target(ip: str) -> tuple[str, str]:
        # nft parses its joined arguments as a script, so only a canonical address may reach it:
        # re-parse here (no scope ids, no stray text) and check the characters once more.
        addr = normalise_ip(ip)
        if addr is None or not re.fullmatch(r"[0-9a-fA-F:.]+", str(addr)):
            raise BlockerError(f"refusing to use invalid address {ip!r}"[:120])
        return (SET_V4 if isinstance(addr, IPv4Address) else SET_V6), str(addr)

    def ensure_ruleset(self) -> None:
        self._run(["-f", "-"], stdin=RULESET)

    def block(self, ip: str, ttl_seconds: int) -> None:
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise BlockerError("ttl_seconds must be a positive integer")
        name, addr = self._target(ip)
        # `add element` on an existing element is a no-op, so a repeat block won't extend it;
        # delete first (ignoring "not found") to refresh the timeout.
        self._delete(name, addr, missing_ok=True)
        self._run(["add", "element", "inet", TABLE, name, f"{{ {addr} timeout {ttl_seconds}s }}"])

    def unblock(self, ip: str) -> None:
        name, addr = self._target(ip)
        self._delete(name, addr, missing_ok=True)

    def _delete(self, name: str, addr: str, missing_ok: bool) -> None:
        try:
            self._run(["delete", "element", "inet", TABLE, name, f"{{ {addr} }}"])
        except BlockerError as exc:
            if not (missing_ok and "No such file or directory" in str(exc)):
                raise

    def list_blocked(self) -> list[str]:
        out: list[str] = []
        for name in (SET_V4, SET_V6):
            text = self._run(["-j", "list", "set", "inet", TABLE, name])
            out.extend(_parse_elements(text))
        return out


def _parse_elements(json_text: str) -> list[str]:
    import json

    found: list[str] = []
    for item in json.loads(json_text).get("nftables", []):
        for el in item.get("set", {}).get("elem", []):
            val = el["elem"]["val"] if isinstance(el, dict) else el
            found.append(str(val))
    return found
