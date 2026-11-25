"""The emulator-only guard (the same idea as lab/cloud/guard.py, "no billing, ever").

IDPS_SOC_CLOUD_ENDPOINT_URL may only name a local emulator: an http URL whose host is `localhost`
or an IP address literal that is loopback or private (RFC 1918 / unique-local). Anything else is
refused: https, DNS names (a search domain could send them elsewhere), link-local addresses
(including the instance-metadata address), public addresses, credentials in the URL. The
provider also never uses real credentials: it passes the fake test/test pair explicitly, so the
environment, profiles and instance roles are never consulted, and it refuses to start while a
proxy variable is set.
"""

import ipaddress
import os
from urllib.parse import urlparse

FAKE_KEY = "test"
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


class EndpointRefused(ValueError):
    """The endpoint is not a local emulator (the message says why; it never echoes the URL's
    credentials)."""


def check_endpoint(url: str, env: dict[str, str] | None = None) -> str:
    """Return the endpoint if it is safe to talk to; raise EndpointRefused otherwise."""
    env = os.environ if env is None else env
    if not isinstance(url, str) or not url or len(url) > 200 or not url.isprintable():
        raise EndpointRefused("the endpoint is not a plain URL")
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise EndpointRefused("the endpoint must be an http:// URL of a local emulator")
    if parsed.username or parsed.password:
        raise EndpointRefused("the endpoint must not contain credentials")
    host = parsed.hostname
    try:
        parsed.port  # noqa: B018 (raises ValueError for a bad port)
    except ValueError as exc:
        raise EndpointRefused("the endpoint has an invalid port") from exc
    if not host:
        raise EndpointRefused("the endpoint has no host")
    if host != "localhost":
        try:
            addr = ipaddress.ip_address(host)
        except ValueError as exc:
            raise EndpointRefused("the endpoint must be localhost or an IP address, not a DNS "
                                  "name") from exc
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped  # ::ffff:8.8.8.8 is 8.8.8.8
        if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            raise EndpointRefused("the endpoint must be a loopback or private address")
        if not addr.is_loopback and (not addr.is_private or addr.is_reserved):
            raise EndpointRefused("the endpoint must be a loopback or private address")
    if any(env.get(name) for name in PROXY_VARS):
        raise EndpointRefused("a proxy variable is set; refusing to talk to the emulator "
                              "through it")
    return url
