"""Outbound HTTP with an SSRF guard, for webhook and Slack URLs.

The URL is operator configuration, but it can point at the wrong place (a typo, a hijacked DNS
name) and the SOC sits next to private networks, so before connecting we require https (http
only with IDPS_SOC_NOTIFY_ALLOW_HTTP), resolve the name ourselves and refuse private, loopback,
link-local, multicast and other non-public addresses (unless IDPS_SOC_NOTIFY_ALLOW_PRIVATE; dev
and lab only). The connection then goes to the address we checked, not to a second DNS answer
(no rebinding). Redirects are never followed, bodies are tiny and timeouts short.

Error messages never contain the URL: the path or query of a Slack webhook is its secret.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Self
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 4096


class UnsafeDestination(ValueError):
    """The URL is refused by policy (the message is safe to show to an admin)."""


class DeliveryError(Exception):
    """A send failed. `retryable` says whether trying again can help. The message is safe to
    store and show: it never contains a URL, a secret or an address book."""

    def __init__(self, message: str, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str  # path and query, as given
    ip: str  # the address that was checked and will be connected to


_V4_NOT_PUBLIC = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]
# IPv6: only global unicast 2000::/3 can be public, minus these (listed explicitly so the answer
# does not depend on the Python patch version's idea of "global").
_V6_NOT_PUBLIC = [ipaddress.ip_network(n) for n in (
    "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16",
    "64:ff9b:1::/48")]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_V4_COMPAT = ipaddress.ip_network("::/96")
_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")


def _v4_public(addr: ipaddress.IPv4Address) -> bool:
    return not any(addr in net for net in _V4_NOT_PUBLIC)


def _v6_public(addr: ipaddress.IPv6Address) -> bool:
    packed = addr.packed
    if addr.ipv4_mapped is not None:
        return _v4_public(addr.ipv4_mapped)
    if addr in _NAT64:  # NAT64: the IPv4 address is the last 32 bits
        return _v4_public(ipaddress.IPv4Address(packed[12:]))
    if addr in ipaddress.ip_network("64:ff9b:1::/48"):  # local-use NAT64: not decodable, refuse
        return False
    if addr in _SIXTOFOUR:  # 6to4: bits 16-47
        return _v4_public(ipaddress.IPv4Address(packed[2:6]))
    if addr in _TEREDO:  # Teredo: the server (bits 32-63) and the client (inverted last 32 bits)
        client = ipaddress.IPv4Address(bytes(b ^ 0xFF for b in packed[12:]))
        return _v4_public(ipaddress.IPv4Address(packed[4:8])) and _v4_public(client)
    if addr in _V4_COMPAT:  # deprecated IPv4-compatible ::a.b.c.d (and :: and ::1)
        return _v4_public(ipaddress.IPv4Address(packed[12:]))
    if addr not in _GLOBAL_UNICAST:  # fe80::/10, fec0::/10, fc00::/7, ff00::/8, ...
        return False
    return not any(addr in net for net in _V6_NOT_PUBLIC)


def is_public(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for a globally routable unicast address. IPv6 forms that carry an IPv4 address
    (mapped, NAT64, 6to4, Teredo, IPv4-compatible) are judged by the address inside them."""
    addr = ipaddress.ip_address(address) if isinstance(address, str) else address
    return _v4_public(addr) if addr.version == 4 else _v6_public(addr)


Resolver = Callable[..., list]


def resolve_target(url: str, *, allow_private: bool = False, allow_http: bool = False,
                   resolver: Resolver = socket.getaddrinfo) -> Target:
    """Check `url` against the policy and return where to connect. Raises UnsafeDestination."""
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError as exc:
        raise UnsafeDestination("the URL is not valid") from exc
    if parts.scheme not in ("https", "http") or not host:
        raise UnsafeDestination("the URL must be an https address")
    if parts.scheme == "http" and not allow_http:
        raise UnsafeDestination("http is refused; use https (IDPS_SOC_NOTIFY_ALLOW_HTTP is for "
                                "lab use only)")
    if parts.username or parts.password:
        raise UnsafeDestination("credentials inside the URL are refused")
    port = port or (443 if parts.scheme == "https" else 80)
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeDestination("the host name cannot be resolved") from exc
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise UnsafeDestination("the host name cannot be resolved")
    if not allow_private:
        for a in addresses:  # every answer must be public, not just the one we would use
            if not is_public(a.split("%")[0]):
                raise UnsafeDestination("the destination is a private, loopback or link-local "
                                        "address (IDPS_SOC_NOTIFY_ALLOW_PRIVATE is for lab use "
                                        "only)")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(parts.scheme, host, port, path, addresses[0].split("%")[0])


class Watchdog:
    """Overall deadline for one network exchange. Socket timeouts are per operation, so a peer
    that dribbles a byte at a time could hold a worker for ever; when the deadline passes this
    shuts the socket down from a timer thread, which makes any blocked read or write fail.
    Use as a context manager; set `.target` to the object to close (a socket, or a connection
    with `.sock`) once it exists, and check `.expired` when an error comes out."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.expired = False
        self.target = None
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True

    def _fire(self) -> None:
        self.expired = True
        target = self.target
        sock = getattr(target, "sock", target)
        for action in (lambda: sock.shutdown(socket.SHUT_RDWR), lambda: sock.close()):
            try:
                action()
            except Exception:  # noqa: BLE001, S110  best effort: the socket may be gone already
                pass
        if target is not sock:  # an http.client or smtplib object
            try:
                target.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def __enter__(self) -> Self:
        self._timer.start()
        return self

    def __exit__(self, *exc) -> None:
        self._timer.cancel()


class _Pinned(http.client.HTTPConnection):
    def __init__(self, target: Target, timeout: float) -> None:
        super().__init__(target.host, target.port, timeout=timeout)
        self._target = target

    def connect(self) -> None:
        self.sock = socket.create_connection((self._target.ip, self._target.port), self.timeout)


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, target: Target, timeout: float,
                 context: ssl.SSLContext | None = None) -> None:
        super().__init__(target.host, target.port, timeout=timeout,
                         context=context or ssl.create_default_context())
        self._target = target

    def connect(self) -> None:
        sock = socket.create_connection((self._target.ip, self._target.port), self.timeout)
        # Certificate and host name are checked against the NAME, though we dial the address.
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self._target.host)
        except BaseException:
            sock.close()
            raise


def post(target: Target, body: bytes, headers: dict[str, str], timeout: float,
         context: ssl.SSLContext | None = None) -> int:
    """POST `body`; return the HTTP status. `timeout` is the deadline for the WHOLE exchange
    (connect, handshake, send, answer). The answer is read only up to 4 KB. Raises DeliveryError
    (never with the URL in it)."""
    conn = (_PinnedTLS(target, timeout, context) if target.scheme == "https"
            else _Pinned(target, timeout))
    with Watchdog(timeout) as dog:
        dog.target = conn
        try:
            conn.request("POST", target.path, body=body, headers=headers)
            response = conn.getresponse()
            response.read(MAX_RESPONSE_BYTES)
            return response.status
        except ssl.SSLError as exc:
            if dog.expired:
                raise DeliveryError("timed out") from exc
            raise DeliveryError("TLS error (certificate not trusted or handshake failed)") from exc
        except (OSError, http.client.HTTPException) as exc:
            if dog.expired or isinstance(exc, TimeoutError):
                raise DeliveryError("timed out") from exc
            raise DeliveryError(f"connection failed ({type(exc).__name__})") from exc
        finally:
            conn.close()


def check_status(status: int) -> None:
    """2xx is success; a redirect is refused; 408/425/429/5xx are worth retrying."""
    if 200 <= status < 300:
        return
    if 300 <= status < 400:
        raise DeliveryError(f"HTTP {status}: redirects are not followed", retryable=False)
    raise DeliveryError(f"HTTP {status}", retryable=status in (408, 425, 429) or status >= 500)
