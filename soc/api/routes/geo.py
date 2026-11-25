"""Data for the live attack world map: where attack sources are, and where the protected site is."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser
from soc.api.db import get_db
from soc.api.models import SEVERITY_RANK, Alert, Severity

router = APIRouter(tags=["geo"])

MAX_POINTS = 300  # busiest sources only; the map can't show more usefully anyway


class GeoPoint(BaseModel):
    ip: str
    count: int
    max_severity: Severity
    lat: float
    lon: float
    country: str | None
    city: str | None
    source: str  # "geoip" (real lookup) or "demo" (made-up location for a lab address)


class Home(BaseModel):
    lat: float
    lon: float
    label: str


class GeoAttacks(BaseModel):
    hours: int
    home: Home | None
    geoip_status: str
    demo: bool
    points: list[GeoPoint]
    unlocated_sources: int  # sources with no known location (e.g. private addresses)


@router.get("/geo/attacks", response_model=GeoAttacks)
def geo_attacks(request: Request, user: AnyUser, db: Annotated[Session, Depends(get_db)],
                hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24):
    settings = request.app.state.settings
    locator = request.app.state.geo
    since = datetime.now(UTC) - timedelta(hours=hours)
    rank = case(*[(Alert.severity == sev, r) for sev, r in SEVERITY_RANK.items()], else_=0)
    rows = db.execute(
        select(Alert.src_ip, func.count(), func.max(rank))
        .where(Alert.received_at >= since).group_by(Alert.src_ip)
        .order_by(func.count().desc(), Alert.src_ip).limit(MAX_POINTS))
    by_rank = {r: sev for sev, r in SEVERITY_RANK.items()}
    points, unlocated = [], 0
    for ip, n, r in rows:
        loc = locator.locate(ip)
        if loc is None:
            unlocated += 1
            continue
        points.append(GeoPoint(ip=ip, count=n, max_severity=by_rank[int(r or 0)], lat=loc.lat,
                               lon=loc.lon, country=loc.country, city=loc.city, source=loc.source))
    home = None
    if settings.home_lat is not None and settings.home_lon is not None:
        home = Home(lat=settings.home_lat, lon=settings.home_lon, label=settings.home_label)
    return GeoAttacks(hours=hours, home=home, geoip_status=locator.status, demo=locator.demo,
                      points=points, unlocated_sources=unlocated)
