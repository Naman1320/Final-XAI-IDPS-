"""IP geolocation for the attack map: MaxMind GeoLite2 City, plus an optional demo mode.

GeoLite2 is free but needs a MaxMind account: download GeoLite2-City.mmdb and set
IDPS_SOC_GEOIP_DB to its path. Private and other non-public addresses (all of the lab's) have
no real location. With IDPS_SOC_GEO_DEMO=true they get a made-up but stable location so the
map can be demonstrated in the lab; every such point is marked `source: "demo"` and the
dashboard labels it, so demo positions can't be mistaken for real ones.
"""

import hashlib
import ipaddress
import threading
from dataclasses import dataclass

from pydantic import BaseModel

# Well-spread city coordinates used only for demo locations.
_DEMO_PLACES = [
    ("Demo: São Paulo", -23.55, -46.63), ("Demo: Lagos", 6.52, 3.38),
    ("Demo: Frankfurt", 50.11, 8.68), ("Demo: Moscow", 55.76, 37.62),
    ("Demo: Mumbai", 19.08, 72.88), ("Demo: Singapore", 1.35, 103.82),
    ("Demo: Beijing", 39.90, 116.40), ("Demo: Tokyo", 35.68, 139.69),
    ("Demo: Sydney", -33.87, 151.21), ("Demo: Los Angeles", 34.05, -118.24),
    ("Demo: Chicago", 41.88, -87.63), ("Demo: Toronto", 43.65, -79.38),
    ("Demo: London", 51.51, -0.13), ("Demo: Johannesburg", -26.20, 28.05),
    ("Demo: Cairo", 30.04, 31.24), ("Demo: Seoul", 37.57, 126.98),
    ("Demo: Jakarta", -6.21, 106.85), ("Demo: Mexico City", 19.43, -99.13),
    ("Demo: Istanbul", 41.01, 28.98), ("Demo: Kyiv", 50.45, 30.52),
]


@dataclass(frozen=True)
class Location:
    lat: float
    lon: float
    country: str | None
    city: str | None
    source: str  # "geoip" or "demo"


class GeoOut(BaseModel):
    """A location as the live feed sends it (alerts: `src_geo`; blocks: `geo`)."""

    lat: float
    lon: float
    country: str | None
    city: str | None
    source: str  # "geoip" or "demo"


def geo_out(locator: "GeoLocator", ip: str) -> dict | None:
    """`ip`'s location for a live message, or None (private address without demo mode, no
    database, not found). Never raises: a lookup problem must not fail an ingest that already
    committed. The locator caches per address (50,000 at most), so repeated sources are O(1)."""
    try:
        loc = locator.locate(ip)
    except Exception:  # noqa: BLE001
        return None
    if loc is None:
        return None
    return GeoOut(lat=loc.lat, lon=loc.lon, country=loc.country, city=loc.city,
                  source=loc.source).model_dump()


class GeoLocator:
    def __init__(self, db_path: str | None, demo: bool):
        self.db_path = db_path
        self.demo = demo
        self._reader = None
        self._reader_error: str | None = None
        self._lock = threading.Lock()
        self._cache: dict[str, Location | None] = {}

    def _get_reader(self):
        if self.db_path is None or self._reader_error is not None:
            return None
        with self._lock:
            if self._reader is None:
                try:
                    import geoip2.database

                    self._reader = geoip2.database.Reader(self.db_path)
                except Exception as exc:  # noqa: BLE001  missing or unreadable file
                    import logging

                    logging.getLogger(__name__).warning("can't open GeoLite2 database: %s", exc)
                    self._reader_error = type(exc).__name__  # no server paths for the browser
                    return None
        return self._reader

    @property
    def available(self) -> bool:
        return self._get_reader() is not None

    @property
    def status(self) -> str:
        if self.db_path is None:
            return "no GeoLite2 database configured (IDPS_SOC_GEOIP_DB)"
        if self._get_reader() is None:
            return f"GeoLite2 database could not be opened ({self._reader_error})"
        return "ok"

    def forget(self, ips, *, dry_run: bool = False) -> int:
        """Drop cached locations of these addresses (erasure on request); returns how many."""
        hits = [ip for ip in ips if ip in self._cache]
        if not dry_run:
            for ip in hits:
                self._cache.pop(ip, None)
        return len(hits)

    def locate(self, ip: str) -> Location | None:
        if ip in self._cache:
            return self._cache[ip]
        loc = self._locate(ip)
        if len(self._cache) < 50_000:
            self._cache[ip] = loc
        return loc

    def _locate(self, ip: str) -> Location | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.is_global:
            reader = self._get_reader()
            if reader is None:
                return None
            try:
                r = reader.city(ip)
            except Exception:  # noqa: BLE001  address not in the database
                return None
            if r.location.latitude is None or r.location.longitude is None:
                return None
            return Location(r.location.latitude, r.location.longitude,
                            r.country.iso_code, r.city.name, "geoip")
        if self.demo:
            digest = hashlib.sha256(ip.encode()).digest()
            name, lat, lon = _DEMO_PLACES[digest[0] % len(_DEMO_PLACES)]
            # small, stable jitter so several IPs in one demo city don't overlap exactly
            lat += (digest[1] - 128) / 128 * 1.5
            lon += (digest[2] - 128) / 128 * 1.5
            return Location(round(lat, 3), round(lon, 3), None, name, "demo")
        return None
