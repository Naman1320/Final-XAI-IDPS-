"""MOCK metrics, generated deterministically from (instance id, timestamp).

Nothing is stored and nothing is random per call: a value depends only on the instance id, the
series name and the timestamp rounded down to the step, so asking again (or from another
process) returns the same history. Whether an instance was running at a time comes from its
`run_start` / `run_end` (see provider.py); outside that window CPU, memory and network are zero
and the disk is flat. Every response built from this says `metrics_source: "mock"`.
"""

import hashlib
import math
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from soc.api.cloud import catalog

SERIES = ("cpu_pct", "memory_pct", "disk_pct", "net_in_mbps", "net_out_mbps")
# range -> (window, step)
RANGES: dict[str, tuple[timedelta, timedelta]] = {
    "1h": (timedelta(hours=1), timedelta(minutes=1)),
    "24h": (timedelta(hours=24), timedelta(minutes=15)),
    "7d": (timedelta(days=7), timedelta(hours=1)),
}
# How hard an instance works is decided by its id: (cpu base, memory base, disk base, net base)
_TIERS = {
    "idle": (6.0, 28.0, 22.0, 0.4),
    "normal": (28.0, 48.0, 38.0, 4.0),
    "busy": (55.0, 66.0, 55.0, 14.0),
    "hot": (86.0, 78.0, 72.0, 30.0),
    "full": (35.0, 88.0, 86.0, 6.0),  # little memory and disk left, CPU fine
}
TIER_NAMES = tuple(_TIERS)


def _unit(*parts: object) -> float:
    """A stable number in [0, 1) from the parts."""
    digest = hashlib.blake2b("|".join(map(str, parts)).encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") / 2**64


def tier(instance_id: str) -> str:
    return TIER_NAMES[int(_unit(instance_id, "tier") * len(TIER_NAMES))]


def floor_ts(ts: datetime, step: timedelta) -> datetime:
    """`ts` rounded down to a multiple of `step` since the epoch."""
    seconds = int(step.total_seconds())
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, UTC)


def _active(ts: datetime, run_start: datetime | None, run_end: datetime | None) -> bool:
    return run_start is not None and ts >= run_start and (run_end is None or ts < run_end)


def value(instance_id: str, series: str, ts: datetime, *, running_at: bool,
          alive_at: bool = True) -> float:
    """One sample. `ts` must already be on the step grid for the result to be reproducible."""
    if not alive_at:
        return 0.0
    cpu_b, mem_b, disk_b, net_b = _TIERS[tier(instance_id)]
    epoch = int(ts.timestamp())
    day_phase = (epoch % 86400) / 86400 * 2 * math.pi + _unit(instance_id, "phase") * math.pi
    wave = math.sin(day_phase)
    noise = _unit(instance_id, series, epoch) - 0.5
    if series == "disk_pct":  # allocated whether or not it runs: flat when it does not
        slow = math.sin(epoch / 86400 / 9 + _unit(instance_id, "disk") * 6) * 0.8
        return round(min(100.0, max(0.0, disk_b + (slow if running_at else 0.0))), 2)
    if not running_at:
        return 0.0
    if series == "cpu_pct":
        out = cpu_b + 9 * wave + 14 * noise
    elif series == "memory_pct":
        out = mem_b + 2.5 * wave + 3 * noise
    elif series in ("net_in_mbps", "net_out_mbps"):
        share = 1.0 if series == "net_in_mbps" else 0.6
        out = max(0.0, net_b * share * (1 + 0.45 * wave) + 1.2 * noise * share)
        return round(out, 3)
    else:
        raise ValueError(series)
    return round(min(100.0, max(0.0, out)), 2)


def series_for(instance_id: str, state: str, launched_at: datetime, run_start: datetime | None,
               run_end: datetime | None, rng: str, now: datetime) -> dict:
    """The time series of the range ending at `now`: {timestamps, series, step_seconds}. A sample
    before the instance existed is null."""
    window, step = RANGES[rng]
    end = floor_ts(now, step)
    points = int(window / step)
    stamps = [end - step * (points - 1 - i) for i in range(points)]
    out: dict[str, list[float | None]] = {s: [] for s in SERIES}
    for ts in stamps:
        existed = ts >= floor_ts(launched_at, step)
        running = _active(ts, run_start, run_end)
        # a terminated instance's disk is gone from the moment it was terminated
        alive = state != "terminated" or (run_end is not None and ts < run_end)
        for name in SERIES:
            out[name].append(value(instance_id, name, ts, running_at=running, alive_at=alive)
                             if existed else None)
    return {"step_seconds": int(step.total_seconds()),
            "timestamps": [t.isoformat().replace("+00:00", "Z") for t in stamps], "series": out}


def current(instance_id: str, state: str, launched_at: datetime, run_start: datetime | None,
            run_end: datetime | None, now: datetime) -> dict[str, float]:
    """The latest sample of every series (the one-minute slot ending now)."""
    ts = floor_ts(now, timedelta(minutes=1))
    running = state == "running" and _active(ts, run_start, run_end)
    alive = state != "terminated" and ts >= launched_at
    return {name: value(instance_id, name, ts, running_at=running, alive_at=alive)
            for name in SERIES}


# --- health ---------------------------------------------------------------------------------

_RANK = {"healthy": 0, "degraded": 1, "critical": 2}


def _level(series: str, v: float) -> str:
    degraded, critical = catalog.HEALTH_THRESHOLDS[series]
    return "critical" if v >= critical else "degraded" if v >= degraded else "healthy"


def health(state: str, sample: dict[str, float]) -> dict:
    """Status checks from the latest sample. An instance that is not running has no checks: its
    status is "unknown" (nothing to measure), not "healthy"."""
    if state != "running":
        return {"status": "unknown", "checks": [
            {"name": "instance_state", "status": "unknown", "value": state, "threshold": None}]}
    checks = [{"name": "instance_state", "status": "healthy", "value": state, "threshold": None}]
    for series in catalog.HEALTH_THRESHOLDS:
        v = sample[series]
        checks.append({"name": series, "status": _level(series, v), "value": v,
                       "threshold": {"degraded": catalog.HEALTH_THRESHOLDS[series][0],
                                     "critical": catalog.HEALTH_THRESHOLDS[series][1]}})
    status = max((c["status"] for c in checks), key=_RANK.__getitem__)
    return {"status": status, "checks": checks}


def mean(values: Sequence[float]) -> float:
    return round(sum(values) / len(values), 2) if values else 0.0
