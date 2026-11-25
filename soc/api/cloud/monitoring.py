"""Overview, fleet metrics and cost."""

import calendar
from datetime import date, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from soc.api.cloud import catalog, clock, metrics
from soc.api.cloud.common import Ctx, Read, Sourced
from soc.api.cloud.instances import MOCK_METRICS_LABEL, sample_of
from soc.api.models import CloudAlert

router = APIRouter(prefix="/cloud", tags=["cloud"])
COST_NOTE = ("Mock cost: invented daily figures, generated per day from the date (they do not "
             "change when the mock inventory does). "
             "Top drivers are an estimate (list price x running hours), not a bill.")


# --- cost ---------------------------------------------------------------------------------------------

def _round(x: float) -> float:
    return round(x + 0.0, 2)


def _sum(rows: list[dict], key=lambda r: True) -> float:
    return _round(sum(r["amount_usd"] for r in rows if key(r)))


def _month_bounds(day: date) -> tuple[date, date]:
    first = day.replace(day=1)
    return first, day.replace(day=calendar.monthrange(day.year, day.month)[1])


def cost_summary(ctx: Ctx, now: datetime) -> dict:
    """Month to date, last month, the same stretch of last month, and a linear forecast."""
    today = now.date()
    first, _last = _month_bounds(today)
    prev_last = first - timedelta(days=1)
    prev_first = prev_last.replace(day=1)
    provider = ctx.provider
    this_rows = provider.cost_daily(first.isoformat(), today.isoformat())
    prev_rows = provider.cost_daily(prev_first.isoformat(), prev_last.isoformat())
    mtd = _sum(this_rows)
    same = _sum(prev_rows, lambda r: int(r["day"][8:10]) <= today.day)
    days_in_month = calendar.monthrange(today.year, today.month)[1]
    return {
        "available": provider.cost_available, "currency": "USD",
        "month": first.strftime("%Y-%m"), "month_to_date": mtd,
        "last_month_total": _sum(prev_rows), "last_month_same_period": same,
        "change_vs_same_period_pct": round((mtd - same) / same * 100, 1) if same else None,
        "forecast_month_total": _round(mtd / today.day * days_in_month),
        "forecast_method": "linear: month-to-date daily average x days in the month",
    }


class Driver(BaseModel):
    instance_id: str
    name: str
    instance_type: str
    running_hours: float
    hourly_usd: float
    estimated_usd: float


class TypeDriver(BaseModel):
    instance_type: str
    instances: int
    running_hours: float
    estimated_usd: float


class DayCost(BaseModel):
    day: str
    total: float
    services: dict[str, float]


class Forecast(BaseModel):
    month: str
    month_to_date: float
    days_elapsed: int
    days_in_month: int
    projected_month_total: float
    method: str


class CostOut(Sourced):
    range: str
    available: bool
    currency: str
    first_day: str
    last_day: str
    total: float
    by_service: dict[str, float]
    by_day: list[DayCost]
    forecast: Forecast
    top_drivers: list[Driver]
    by_instance_type: list[TypeDriver]
    cost_note: str = COST_NOTE


def running_hours(rec: dict, start: datetime, end: datetime) -> float:
    if rec["run_start"] is None:
        return 0.0
    lo = max(rec["run_start"], start)
    hi = min(rec["run_end"] or end, end)
    return max(0.0, (hi - lo).total_seconds() / 3600)


@router.get("/cost", response_model=CostOut)
def cost(ctx: Read, range_: Annotated[Literal["7d", "30d", "90d"], Query(alias="range")] = "30d"):
    now = clock.now()
    days = int(range_[:-1])
    today = now.date()
    first = today - timedelta(days=days - 1)
    rows = ctx.provider.cost_daily(first.isoformat(), today.isoformat())
    by_service = {s: _sum(rows, lambda r, s=s: r["service"] == s) for s in catalog.COST_SERVICES}
    by_service.update({s: _sum(rows, lambda r, s=s: r["service"] == s)
                       for s in {r["service"] for r in rows} - set(by_service)})
    by_day = []
    for n in range(days):
        d = (first + timedelta(days=n)).isoformat()
        day_rows = [r for r in rows if r["day"] == d]
        by_day.append(DayCost(day=d, total=_sum(day_rows),
                              services={r["service"]: r["amount_usd"] for r in day_rows}))
    summary = cost_summary(ctx, now)
    start = now - timedelta(days=days)
    drivers, types = [], {}
    for rec in ctx.provider.list_instances():
        hours = running_hours(rec, start, now)
        price = catalog.INSTANCE_TYPES.get(rec["instance_type"], (0, 0, 0.0))[2]
        if hours <= 0:
            continue
        drivers.append(Driver(instance_id=rec["id"], name=rec["name"],
                              instance_type=rec["instance_type"], running_hours=round(hours, 1),
                              hourly_usd=price, estimated_usd=round(hours * price, 2)))
        t = types.setdefault(rec["instance_type"], [0, 0.0, 0.0])
        t[0] += 1
        t[1] += hours
        t[2] += hours * price
    drivers.sort(key=lambda d: -d.estimated_usd)
    by_type = sorted((TypeDriver(instance_type=k, instances=v[0], running_hours=round(v[1], 1),
                                 estimated_usd=round(v[2], 2)) for k, v in types.items()),
                     key=lambda t: -t.estimated_usd)
    return CostOut(
        **ctx.sourced(), range=range_, available=summary["available"], currency="USD",
        first_day=first.isoformat(), last_day=today.isoformat(), total=_sum(rows),
        by_service=by_service, by_day=by_day,
        forecast=Forecast(month=summary["month"], month_to_date=summary["month_to_date"],
                          days_elapsed=today.day,
                          days_in_month=calendar.monthrange(today.year, today.month)[1],
                          projected_month_total=summary["forecast_month_total"],
                          method=summary["forecast_method"]),
        top_drivers=drivers[:5], by_instance_type=by_type)


# --- overview ---------------------------------------------------------------------------------------

class Overview(Sourced):
    region: str
    instances: dict
    totals: dict
    health: dict[str, int]
    alerts: dict[str, int]
    cost: dict
    metrics_source: str = "mock"


@router.get("/overview", response_model=Overview)
def overview(ctx: Read):
    now = clock.now()
    p = ctx.provider
    instances = p.list_instances()
    live = [i for i in instances if i["state"] != "terminated"]
    running = [i for i in instances if i["state"] == "running"]
    by_state = dict.fromkeys(catalog.INSTANCE_STATES, 0)
    for i in instances:
        by_state[i["state"]] = by_state.get(i["state"], 0) + 1
    by_type: dict[str, int] = {}
    for i in live:
        by_type[i["instance_type"]] = by_type.get(i["instance_type"], 0) + 1
    health = {"healthy": 0, "degraded": 0, "critical": 0, "unknown": 0}
    for i in live:
        health[metrics.health(i["state"], sample_of(i, now))["status"]] += 1
    volumes, buckets = p.list_volumes(), p.list_buckets()
    counts, critical_open = {}, 0
    if p.writable:
        counts = dict(ctx.db.execute(select(CloudAlert.status, func.count())
                                     .group_by(CloudAlert.status)).all())
        critical_open = ctx.db.scalar(select(func.count()).select_from(CloudAlert).where(
            CloudAlert.status == "open", CloudAlert.severity == "critical")) or 0
    return Overview(
        **ctx.sourced(), region=catalog.REGION,
        instances={"total": len(live), "by_state": by_state, "by_type": by_type},
        totals={"vcpus_running": sum(i["vcpus"] for i in running),
                "memory_gb_running": sum(i["memory_gb"] for i in running),
                "instance_disk_gb": sum(i["disk_gb"] for i in live),
                "volumes": len(volumes), "volume_gb": sum(v["size_gb"] for v in volumes),
                "volumes_in_use": sum(v["state"] == "in-use" for v in volumes),
                "buckets": len(buckets), "bucket_objects": sum(b["object_count"] for b in buckets),
                "bucket_gb": round(sum(b["size_gb"] for b in buckets), 2),
                "vpcs": len(p.list_vpcs()), "subnets": len(p.list_subnets()),
                "security_groups": len(p.list_security_groups())},
        health=health,
        alerts={"open": counts.get("open", 0), "acknowledged": counts.get("acknowledged", 0),
                "critical_open": critical_open},
        cost=cost_summary(ctx, now))


# --- fleet metrics -------------------------------------------------------------------------------------

class FleetMetrics(Sourced):
    fleet: dict
    storage: dict
    busiest: list[dict]
    cpu_trend_24h: dict
    metrics_source: str = "mock"
    metrics_label: str = MOCK_METRICS_LABEL


@router.get("/metrics/summary", response_model=FleetMetrics)
def metrics_summary(ctx: Read):
    now = clock.now()
    p = ctx.provider
    instances = p.list_instances()
    running = [i for i in instances if i["state"] == "running"]
    samples = {i["id"]: sample_of(i, now) for i in running}

    def col(series: str) -> list[float]:
        return [s[series] for s in samples.values()]

    live = [i for i in instances if i["state"] != "terminated"]
    disk_total = sum(i["disk_gb"] for i in live)
    disk_used = sum(i["disk_gb"] * sample_of(i, now)["disk_pct"] / 100 for i in live)
    volumes = p.list_volumes()
    vol_total = sum(v["size_gb"] for v in volumes)
    vol_used = sum(v["size_gb"] for v in volumes if v["state"] == "in-use")
    busiest = sorted(running, key=lambda i: -samples[i["id"]]["cpu_pct"])[:5]
    trend = [metrics.series_for(i["id"], i["state"], i["launched_at"], i["run_start"],
                                i["run_end"], "24h", now) for i in running]
    stamps = trend[0]["timestamps"] if trend else \
        metrics.series_for("-", "stopped", now, None, None, "24h", now)["timestamps"]
    avg = [metrics.mean([t["series"]["cpu_pct"][n] for t in trend
                         if t["series"]["cpu_pct"][n] is not None]) for n in range(len(stamps))]
    return FleetMetrics(
        **ctx.sourced(),
        fleet={"running_instances": len(running), "avg_cpu_pct": metrics.mean(col("cpu_pct")),
               "max_cpu_pct": max(col("cpu_pct"), default=0.0),
               "avg_memory_pct": metrics.mean(col("memory_pct")),
               "avg_net_in_mbps": metrics.mean(col("net_in_mbps")),
               "avg_net_out_mbps": metrics.mean(col("net_out_mbps"))},
        storage={"instance_disk_gb": disk_total, "instance_disk_used_gb": round(disk_used, 1),
                 "instance_disk_used_pct": round(disk_used / disk_total * 100, 1)
                 if disk_total else 0.0,
                 "volumes_gb": vol_total, "volumes_in_use_gb": vol_used,
                 "volumes_in_use_pct": round(vol_used / vol_total * 100, 1) if vol_total else 0.0,
                 "buckets_gb": round(sum(b["size_gb"] for b in p.list_buckets()), 2)},
        busiest=[{"id": i["id"], "name": i["name"], "cpu_pct": samples[i["id"]]["cpu_pct"]}
                 for i in busiest],
        cpu_trend_24h={"step_seconds": 900, "timestamps": stamps, "avg_cpu_pct": avg})
