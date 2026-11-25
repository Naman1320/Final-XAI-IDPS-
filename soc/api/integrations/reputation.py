"""AbuseIPDB reputation for an alert's source address, on demand.

Privacy: a lookup sends the (public) IP address to AbuseIPDB and nothing else: no alert, sensor,
destination or user data. It happens only when an analyst opens the reputation of one alert,
never for every alert. Private and reserved addresses are never sent. Results are cached in memory
for IDPS_SOC_ABUSEIPDB_CACHE_HOURS (24) so the free quota lasts; the cache is per process and is
empty after a restart. Errors are never cached.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from concurrent.futures import Future
from datetime import UTC, datetime
from urllib.parse import urlencode

from soc.api.integrations.netguard import DeliveryError, Watchdog, is_public
from soc.api.settings import SocSettings

API_HOST = "api.abuseipdb.com"
API_PATH = "/api/v2/check"
MAX_AGE_DAYS = 90
MAX_CACHE = 10_000
MAX_BODY = 64 * 1024

Fetch = Callable[[str, str, float], dict]  # (ip, key, timeout) -> AbuseIPDB "data" object


def abuseipdb_fetch(ip: str, key: str, timeout: float) -> dict:
    """Ask AbuseIPDB about `ip`. Raises DeliveryError with a safe message (never the key)."""
    query = urlencode({"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS})
    conn = http.client.HTTPSConnection(API_HOST, timeout=timeout,
                                       context=ssl.create_default_context())
    with Watchdog(timeout) as dog:  # `timeout` bounds the whole exchange, not each read
        dog.target = conn
        try:
            conn.request("GET", f"{API_PATH}?{query}",
                         headers={"Key": key, "Accept": "application/json",
                                  "User-Agent": "idps-soc"})
            response = conn.getresponse()
            body = response.read(MAX_BODY)
            status = response.status
        except (OSError, http.client.HTTPException) as exc:
            if dog.expired or isinstance(exc, TimeoutError):
                raise DeliveryError("timed out") from exc
            raise DeliveryError(f"connection failed ({type(exc).__name__})") from exc
        finally:
            conn.close()
    if status == 429:
        raise DeliveryError("AbuseIPDB quota or rate limit reached")
    if status in (401, 403):
        raise DeliveryError("AbuseIPDB refused the API key")
    if status != 200:
        raise DeliveryError(f"AbuseIPDB answered HTTP {status}")
    try:
        data = json.loads(body)["data"]
        if not isinstance(data, dict):
            raise TypeError
    except (ValueError, KeyError, TypeError) as exc:
        raise DeliveryError("AbuseIPDB sent an unreadable answer") from exc
    return data


def _unavailable(ip: str, reason: str) -> dict:
    return {"ip": ip, "available": False, "reason": reason, "abuse_confidence": None,
            "total_reports": None, "country": None, "isp": None, "usage_type": None,
            "last_reported_at": None, "checked_at": None, "cached": False}


def _text(value: object, limit: int) -> str | None:
    return None if value is None else str(value)[:limit]


class ReputationService:
    def __init__(self, settings: SocSettings, fetch: Fetch = abuseipdb_fetch, *,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.s = settings
        self._fetch = fetch
        self._clock = clock
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()  # LRU: newest last
        self._calls: deque[float] = deque()  # times of actual lookups, for the limits
        self._inflight: dict[str, Future] = {}
        self._erased: set[str] = set()  # looked up while being erased: never cached (see forget)
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return self.s.abuseipdb_key is not None

    def lookup(self, ip: str) -> dict:
        return self.lookup_ex(ip)[0]

    def lookup_ex(self, ip: str) -> tuple[dict, bool]:
        """(result, whether this call sent `ip` to AbuseIPDB). Cache hits, refused addresses,
        limit hits and calls that waited for another thread's lookup of the same IP send nothing."""
        if not is_public(ip):
            return _unavailable(ip, "private address"), False
        if not self.configured:
            return _unavailable(ip, "not configured"), False
        now = self._clock()
        ttl = self.s.abuseipdb_cache_hours * 3600
        with self._lock:
            hit = self._cache.get(ip)
            if hit is not None and now - hit[0] < ttl:
                self._cache.move_to_end(ip)  # least recently USED goes first when full
                return hit[1] | {"cached": True}, False
            waiting = self._inflight.get(ip)
            if waiting is None:
                while self._calls and now - self._calls[0] >= 86400:
                    self._calls.popleft()
                recent = sum(1 for t in self._calls if now - t < 60)
                if recent >= self.s.abuseipdb_max_per_minute:
                    return _unavailable(ip, "too many lookups; try again in a minute"), False
                if len(self._calls) >= self.s.abuseipdb_max_per_day:
                    return _unavailable(ip, "daily lookup limit reached"), False
                self._calls.append(now)
                mine = self._inflight[ip] = Future()
        if waiting is not None:  # someone is already asking about this address: share the answer
            return waiting.result() | {"cached": True}, False
        result = self._do_fetch(ip, now)
        with self._lock:
            del self._inflight[ip]
        mine.set_result(result)
        return result, True

    def forget(self, ips: Iterable[str], *, dry_run: bool = False) -> int:
        """Drop the cached results for these (normalised) addresses; returns how many entries.
        A lookup in flight for one of them is not cached when it finishes. Nothing is persisted
        anywhere else: the cache is per process and in memory only."""
        wanted = set(ips)
        with self._lock:
            hits = [k for k in self._cache if _same_address(k, wanted)]
            if not dry_run:
                for k in hits:
                    del self._cache[k]
                self._erased |= {k for k in self._inflight if _same_address(k, wanted)}
        return len(hits)

    def _do_fetch(self, ip: str, now: float) -> dict:
        try:
            data = self._fetch(ip, self.s.abuseipdb_key.get_secret_value(),
                               self.s.abuseipdb_timeout_seconds)
            result = {
                "ip": ip, "available": True, "reason": None,
                "abuse_confidence": _int(data.get("abuseConfidenceScore")),
                "total_reports": _int(data.get("totalReports")),
                "country": _text(data.get("countryCode"), 2),
                "isp": _text(data.get("isp"), 200),
                "usage_type": _text(data.get("usageType"), 100),
                "last_reported_at": _text(data.get("lastReportedAt"), 40),
                "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "cached": False}
        except DeliveryError as exc:
            return _unavailable(ip, f"lookup failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            return _unavailable(ip, f"lookup failed ({type(exc).__name__})")
        with self._lock:
            if ip in self._erased:  # erased while this lookup ran: forget it, do not cache it
                self._erased.discard(ip)
                return result
            self._cache[ip] = (now, result)
            self._cache.move_to_end(ip)
            while len(self._cache) > MAX_CACHE:
                self._cache.popitem(last=False)
        return result


def _same_address(text: str, wanted: set[str]) -> bool:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text in wanted
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr) in wanted


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
