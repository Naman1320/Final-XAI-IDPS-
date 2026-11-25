"""Dashboard metrics and the topology data for the map."""

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated

import numpy as np
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser
from soc.api.db import get_db
from soc.api.models import SEVERITY_RANK, Alert, AlertStatus, Block, Severity, WouldBlock
from soc.api.routes.blocks import active_clause

router = APIRouter(tags=["metrics"])

MAX_HOURS = 24 * 30
MAX_TOPOLOGY_EDGES = 1000
# Bounded work per request, however many alerts arrive (e.g. during a flood):
MAX_CLASSES = 25  # classes listed in by_class; the rest are summed as "(other)"
CLASS_DAYS = 7  # by_class_per_day covers this many UTC days, today included
LATENCY_SAMPLE = 20_000  # latency percentiles use the newest alerts only
Hours = Annotated[int, Query(ge=1, le=MAX_HOURS)]


class Bucket(BaseModel):
    start: datetime
    count: int


class TopSource(BaseModel):
    ip: str
    count: int


class LatencyStats(BaseModel):
    p50_ms: float | None
    p95_ms: float | None
    samples: int


class ClassDay(BaseModel):
    day: str  # YYYY-MM-DD, UTC
    # "class" is a Python keyword, so the field is aliased
    class_: str = Field(alias="class")
    count: int

    model_config = ConfigDict(populate_by_name=True)


class AnomalyDay(BaseModel):
    day: str  # YYYY-MM-DD, UTC
    count: int


class MetricsSummary(BaseModel):
    hours: int
    since: datetime
    bucket_seconds: int
    alerts_total: int
    alerts_per_bucket: list[Bucket]
    by_class: dict[str, int]
    by_severity: dict[str, int]
    # Alerts in the window by where they came from; always both keys. alerts_total, by_class and
    # the other figures count both sources together.
    by_source: dict[str, int]
    top_sources: list[TopSource]
    triaged: int
    false_positives: int
    false_positive_rate: float | None
    detection_latency: LatencyStats
    active_blocks: int
    would_blocks: int  # dry-run block decisions in the window (not blocks)
    # Last CLASS_DAYS UTC days whatever `hours` is; only non-zero (day, class) pairs.
    by_class_per_day: list[ClassDay]
    # Same 7 days: alerts per day that the Isolation Forest also flagged as outliers (alerts of
    # any class; non-zero days only). A separate series, so it can't collide with a class name.
    anomaly_per_day: list[AnomalyDay]


_cache_lock = threading.Lock()
_class_day_cache: dict[tuple, tuple[float, tuple[tuple[ClassDay, ...], tuple[AnomalyDay, ...]]]] = {}
CLASS_DAY_CACHE_SECONDS = 60.0


def _utcnow() -> datetime:
    return datetime.now(UTC)  # tests replace this to pin "today"


def _monotonic() -> float:
    return time.monotonic()  # tests replace this to age the cache


def clear_class_per_day_cache() -> None:
    with _cache_lock:
        _class_day_cache.clear()


def class_per_day(db: Session, now: datetime) -> tuple[list[ClassDay], list[AnomalyDay]]:
    """Alerts per UTC day and class for the last CLASS_DAYS days (oldest day first), and the
    per-day count of alerts flagged as outliers.

    One grouped query over the last 7 days of alerts (day, class, and the number of outliers);
    the work grows with the alerts of those 7 days (it is served by the index on
    (received_at, predicted_class, anomaly_score), but still reads every matching entry). So the
    result is cached in-process for CLASS_DAY_CACHE_SECONDS, per database and per UTC day: the
    dashboard can refresh every few seconds during a flood, and a new day never serves yesterday's
    buckets. New alerts show up in this view up to that long late.

    The busiest MAX_CLASSES classes over the whole period keep their name, the rest are
    "(other)"; ingest refuses a class starting with "(" so nothing real collides with it. The
    outlier series counts alerts whose anomaly_score is above 0, which is exactly what the
    Isolation Forest calls an outlier (-decision_function > 0 <=> predict == -1); an alert has a
    class AND may be an outlier, so it is a separate series, not extra class rows."""
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    key = (id(db.get_bind()), today.date().isoformat(), MAX_CLASSES)
    with _cache_lock:
        hit = _class_day_cache.get(key)
        if hit is not None and _monotonic() - hit[0] < CLASS_DAY_CACHE_SECONDS:
            return list(hit[1][0]), list(hit[1][1])  # copies: the cache stays unchanged
    days = [today - timedelta(days=n) for n in range(CLASS_DAYS - 1, -1, -1)]
    # Portable "which day" without date functions (they depend on the database's time zone):
    # compare with the day starts, newest first.
    day_index = case(*[(Alert.received_at >= lo, i) for i, lo in reversed(list(enumerate(days)))],
                     else_=0)
    outliers = func.sum(case((Alert.anomaly_score > 0, 1), else_=0))
    rows = db.execute(
        select(day_index, Alert.predicted_class, func.count(), outliers)
        .where(Alert.received_at >= days[0], Alert.received_at < today + timedelta(days=1))
        .group_by(day_index, Alert.predicted_class))
    per_day: list[dict[str, int]] = [{} for _ in days]
    anomalies = [0] * len(days)
    totals: dict[str, int] = {}
    for i, name, n, out in rows:
        per_day[int(i)][str(name)] = n
        anomalies[int(i)] += int(out or 0)
        totals[str(name)] = totals.get(str(name), 0) + n
    keep = {name for name, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_CLASSES]}
    result: list[ClassDay] = []
    outlier_days: list[AnomalyDay] = []
    for lo, counts, n_anomaly in zip(days, per_day, anomalies, strict=True):
        day = lo.strftime("%Y-%m-%d")
        merged: dict[str, int] = {}
        for name, n in counts.items():
            k = name if name in keep else "(other)"
            merged[k] = merged.get(k, 0) + n
        result += [ClassDay(day=day, **{"class": name}, count=n)
                   for name, n in sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))]
        if n_anomaly:
            outlier_days.append(AnomalyDay(day=day, count=n_anomaly))
    with _cache_lock:
        if len(_class_day_cache) > 32:  # a few databases at most; never grow without bound
            _class_day_cache.clear()
        _class_day_cache[key] = (_monotonic(), (tuple(result), tuple(outlier_days)))
    return list(result), list(outlier_days)


@router.get("/metrics/summary", response_model=MetricsSummary)
def metrics_summary(user: AnyUser, db: Annotated[Session, Depends(get_db)], hours: Hours = 24):
    now = _utcnow()
    since = now - timedelta(hours=hours)
    in_window = Alert.received_at >= since

    def grouped(column):
        rows = db.execute(select(column, func.count()).where(in_window).group_by(column))
        return {str(getattr(k, "value", k)): n for k, n in rows}

    by_class_all = sorted(grouped(Alert.predicted_class).items(), key=lambda kv: (-kv[1], kv[0]))
    by_class = dict(by_class_all[:MAX_CLASSES])
    if len(by_class_all) > MAX_CLASSES:
        by_class["(other)"] = sum(n for _, n in by_class_all[MAX_CLASSES:])
    by_severity = {s.value: 0 for s in Severity} | grouped(Alert.severity)
    by_status = grouped(Alert.status)
    # NULL = stored before sources existed = the model's
    by_source = {"ml": 0, "rule": 0}
    for k, n in grouped(func.coalesce(Alert.source, "ml")).items():
        by_source[k] = by_source.get(k, 0) + n
    top = db.execute(select(Alert.src_ip, func.count().label("n")).where(in_window)
                     .group_by(Alert.src_ip).order_by(func.count().desc(), Alert.src_ip).limit(10))

    # Hourly buckets up to 3 days, daily beyond, aligned to the bucket size. One indexed
    # COUNT per bucket (at most 72 + 30), so the cost doesn't grow with the number of alerts.
    step = 3600 if hours <= 72 else 86400
    first = int(since.timestamp()) // step * step
    series = []
    for t in range(first, int(now.timestamp()) + 1, step):
        lo, hi = datetime.fromtimestamp(t, UTC), datetime.fromtimestamp(t + step, UTC)
        n = db.scalar(select(func.count()).select_from(Alert).where(
            in_window, Alert.received_at >= lo, Alert.received_at < hi)) or 0
        series.append(Bucket(start=lo, count=n))
    # Detection latency from a bounded sample of the newest alerts in the window.
    latencies = [max(received.timestamp() * 1000 - end_ms, 0.0)  # clock skew -> 0
                 for received, end_ms in db.execute(
                     select(Alert.received_at, Alert.end_ms).where(in_window)
                     .order_by(Alert.id.desc()).limit(LATENCY_SAMPLE))]

    triaged = sum(n for s, n in by_status.items() if s != AlertStatus.NEW.value)
    fp = by_status.get(AlertStatus.FALSE_POSITIVE.value, 0)
    p50, p95 = (float(np.percentile(latencies, q)) for q in (50, 95)) if latencies else (None,) * 2
    by_day, outliers = class_per_day(db, now)
    return MetricsSummary(
        hours=hours, since=since, bucket_seconds=step, alerts_total=sum(by_class.values()),
        alerts_per_bucket=series, by_class=by_class, by_severity=by_severity,
        by_source=by_source,
        top_sources=[TopSource(ip=ip, count=n) for ip, n in top],
        triaged=triaged, false_positives=fp,
        false_positive_rate=fp / triaged if triaged else None,
        detection_latency=LatencyStats(p50_ms=p50, p95_ms=p95, samples=len(latencies)),
        active_blocks=db.scalar(select(func.count()).select_from(Block)
                                .where(active_clause(now))) or 0,
        would_blocks=db.scalar(select(func.count()).select_from(WouldBlock)
                               .where(WouldBlock.at >= since)) or 0,
        by_class_per_day=by_day, anomaly_per_day=outliers)


# --- topology ---------------------------------------------------------------------------

class TopologyNode(BaseModel):
    ip: str
    alert_count: int
    max_severity: Severity


class TopologyEdge(BaseModel):
    src: str
    dst: str
    count: int
    max_severity: Severity


class Topology(BaseModel):
    hours: int
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


def _max_sev(a: Severity | None, b: Severity) -> Severity:
    return b if a is None or SEVERITY_RANK[b] > SEVERITY_RANK[a] else a


@router.get("/topology", response_model=Topology)
def topology(user: AnyUser, db: Annotated[Session, Depends(get_db)], hours: Hours = 1):
    since = datetime.now(UTC) - timedelta(hours=hours)
    # Aggregated and cut in SQL, so a flood of distinct pairs doesn't load into memory.
    rank = case(*[(Alert.severity == sev, r) for sev, r in SEVERITY_RANK.items()], else_=0)
    rows = db.execute(
        select(Alert.src_ip, Alert.dst_ip, func.count().label("n"), func.max(rank))
        .where(Alert.received_at >= since).group_by(Alert.src_ip, Alert.dst_ip)
        .order_by(func.count().desc(), Alert.src_ip, Alert.dst_ip).limit(MAX_TOPOLOGY_EDGES))
    by_rank = {r: sev for sev, r in SEVERITY_RANK.items()}
    top = [((src, dst), (n, by_rank[int(r or 0)])) for src, dst, n, r in rows]
    nodes: dict[str, list] = {}
    for (src, dst), (n, sev) in top:
        for ip in {src, dst}:  # a self-edge counts once
            node = nodes.setdefault(ip, [0, None])
            node[0] += n
            node[1] = _max_sev(node[1], sev)
    return Topology(
        hours=hours,
        nodes=[TopologyNode(ip=ip, alert_count=n, max_severity=s)
               for ip, (n, s) in sorted(nodes.items(), key=lambda kv: (-kv[1][0], kv[0]))],
        edges=[TopologyEdge(src=s, dst=d, count=n, max_severity=sev)
               for (s, d), (n, sev) in top])
