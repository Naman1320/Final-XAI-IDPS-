"""Alerts: evaluate thresholds, triage, and the notifications feed (unresolved alerts)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select

from soc.api.cloud import clock, metrics
from soc.api.cloud.common import (
    ALERTS,
    Limit,
    ManageAlerts,
    Offset,
    Paged,
    Read,
    Sourced,
    atomic,
    conflict,
    not_found,
    record,
)
from soc.api.cloud.instances import sample_of
from soc.api.cloud.network import exposed_admin_ports
from soc.api.models import CloudAlert

router = APIRouter(prefix="/cloud", tags=["cloud"])
AlertId = Annotated[int, Path(ge=1, le=2**62)]
_RANK = {"info": 0, "warning": 1, "critical": 2}
_SEVERITY_OF = {"degraded": "warning", "critical": "critical"}
_METRIC_RULES = (("cpu_pct", "cpu_high", "CPU utilisation is high on {name}"),
                 ("memory_pct", "memory_high", "Memory utilisation is high on {name}"),
                 ("disk_pct", "disk_high", "Disk utilisation is high on {name}"))


class Alert(BaseModel):
    id: int
    severity: str
    rule: str
    resource_type: str
    resource_id: str
    message: str
    status: str
    created_at: datetime
    updated_at: datetime
    updated_by: str | None


class AlertOut(Sourced, Alert):
    pass


def _alert(a: CloudAlert) -> Alert:
    return Alert(id=a.id, severity=a.severity, rule=a.rule, resource_type=a.resource_type,
                 resource_id=a.resource_id, message=a.message, status=a.status,
                 created_at=a.created_at, updated_at=a.updated_at, updated_by=a.updated_by)


@router.get("/alerts", response_model=Paged[Alert])
def list_alerts(ctx: Read, status: Literal["open", "acknowledged", "resolved"] | None = None,
                severity: Literal["info", "warning", "critical"] | None = None,
                resource_type: Annotated[str | None, Query(max_length=24)] = None,
                resource_id: Annotated[str | None, Query(max_length=64)] = None,
                limit: Limit = 50, offset: Offset = 0):
    if not ctx.provider.writable:
        return Paged[Alert](**ctx.sourced(), items=[], total=0, limit=limit, offset=offset)
    query = select(CloudAlert)
    if status:
        query = query.where(CloudAlert.status == status)
    if severity:
        query = query.where(CloudAlert.severity == severity)
    if resource_type:
        query = query.where(CloudAlert.resource_type == resource_type)
    if resource_id:
        query = query.where(CloudAlert.resource_id == resource_id)
    total = ctx.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = ctx.db.scalars(query.order_by(CloudAlert.created_at.desc(), CloudAlert.id.desc())
                          .limit(limit).offset(offset))
    return Paged[Alert](**ctx.sourced(), items=[_alert(a) for a in rows], total=total,
                        limit=limit, offset=offset)


class Notifications(Sourced):
    items: list[Alert]
    total: int
    open: int
    acknowledged: int


@router.get("/notifications", response_model=Notifications)
def notifications(ctx: Read, limit: Limit = 20):
    """The unresolved alerts, most severe first, then newest."""
    if not ctx.provider.writable:
        return Notifications(**ctx.sourced(), items=[], total=0, open=0, acknowledged=0)
    unresolved = CloudAlert.status != "resolved"
    severity_rank = case((CloudAlert.severity == "critical", 2),
                         (CloudAlert.severity == "warning", 1), else_=0)
    rows = ctx.db.scalars(select(CloudAlert).where(unresolved)
                          .order_by(severity_rank.desc(), CloudAlert.created_at.desc(),
                                    CloudAlert.id.desc()).limit(limit))
    counts = dict(ctx.db.execute(select(CloudAlert.status, func.count())
                                 .where(unresolved).group_by(CloudAlert.status)).all())
    return Notifications(**ctx.sourced(), items=[_alert(a) for a in rows],
                         total=sum(counts.values()), open=counts.get("open", 0),
                         acknowledged=counts.get("acknowledged", 0))


# --- evaluation -------------------------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str
    resource_type: str
    resource_id: str
    message: str


def findings(ctx, now: datetime) -> list[Finding]:
    """What is wrong right now, from the provider's inventory and the (mock) metrics."""
    p = ctx.provider
    out: list[Finding] = []
    for i in p.list_instances():
        if i["state"] != "running":
            continue
        sample = sample_of(i, now)
        for series, rule, text in _METRIC_RULES:
            level = metrics._level(series, sample[series])
            if level in _SEVERITY_OF:
                out.append(Finding(rule, _SEVERITY_OF[level], "instance", i["id"],
                                   text.format(name=i["name"])))
    for b in p.list_buckets():
        if not b["public_access_blocked"]:
            out.append(Finding("bucket_public", "critical", "bucket", b["name"],
                               f"Bucket {b['name']} does not block public access"))
        if not b["encrypted"]:
            out.append(Finding("bucket_unencrypted", "warning", "bucket", b["name"],
                               f"Bucket {b['name']} is not encrypted"))
    for g in p.list_security_groups():
        if exposed_admin_ports(g["rules"]):
            out.append(Finding("sg_open_admin", "critical", "security_group", g["id"],
                               f"Security group {g['name']} opens SSH or RDP to the whole "
                               "internet"))
    for v in p.list_volumes():
        if not v["encrypted"]:
            out.append(Finding("volume_unencrypted", "info", "volume", v["id"],
                               f"Volume {v['name']} is not encrypted"))
    return out


class EvaluateResult(Sourced):
    checked_at: datetime
    findings: int
    created: list[Alert]
    escalated: list[Alert]
    already_open: int


@router.post("/alerts/evaluate", response_model=EvaluateResult)
def evaluate(ctx: ManageAlerts):
    """Create an alert for every threshold crossed that has no open (or acknowledged) alert yet;
    raise the severity of one that got worse. Nothing is resolved automatically."""
    now = clock.now()
    found = findings(ctx, now)
    created, escalated, existing_count = [], [], 0
    with atomic(ctx.db):
        active = {(a.rule, a.resource_type, a.resource_id): a for a in ctx.db.scalars(
            select(CloudAlert).where(CloudAlert.status != "resolved"))}
        for f in found:
            current = active.get((f.rule, f.resource_type, f.resource_id))
            if current is None:
                a = CloudAlert(severity=f.severity, rule=f.rule, resource_type=f.resource_type,
                               resource_id=f.resource_id, message=f.message[:255], status="open",
                               created_at=now, updated_at=now, updated_by=ctx.user.username)
                ctx.db.add(a)
                ctx.db.flush()
                active[(f.rule, f.resource_type, f.resource_id)] = a
                created.append(a)
                record(ctx.db, ctx.user, "alert.create", "alert", str(a.id),
                       {"rule": f.rule, "severity": f.severity,
                        "resource": f"{f.resource_type}:{f.resource_id}", "by": "evaluate"})
            elif _RANK[f.severity] > _RANK[current.severity]:
                record(ctx.db, ctx.user, "alert.escalate", "alert", str(current.id),
                       {"rule": f.rule, "from": current.severity, "to": f.severity})
                current.severity, current.updated_at = f.severity, now
                current.updated_by = ctx.user.username
                escalated.append(current)
            else:
                existing_count += 1
        record(ctx.db, ctx.user, "alert.evaluate", "alert", "*",
               {"findings": len(found), "created": len(created), "escalated": len(escalated)})
    return EvaluateResult(**ctx.sourced(), checked_at=now, findings=len(found),
                          created=[_alert(a) for a in created],
                          escalated=[_alert(a) for a in escalated], already_open=existing_count)


# --- triage -----------------------------------------------------------------------------------------------

def _move(ctx, alert_id: int, verb: str, allowed: tuple[str, ...], new: str) -> AlertOut:
    ctx.allowed_on(ALERTS, f"alert:{alert_id}")
    with atomic(ctx.db):
        a = ctx.db.get(CloudAlert, alert_id, with_for_update=True)
        if a is None:
            raise not_found("alert")
        if a.status not in allowed:
            raise conflict(f"cannot {verb} an alert that is {a.status}")
        before = a.status
        a.status, a.updated_at, a.updated_by = new, clock.now(), ctx.user.username
        record(ctx.db, ctx.user, f"alert.{verb}", "alert", str(a.id),
               {"from": before, "to": new, "rule": a.rule})
    return AlertOut(**ctx.sourced(), **_alert(a).model_dump())


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge(alert_id: AlertId, ctx: ManageAlerts):
    return _move(ctx, alert_id, "acknowledge", ("open",), "acknowledged")


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut)
def resolve(alert_id: AlertId, ctx: ManageAlerts):
    return _move(ctx, alert_id, "resolve", ("open", "acknowledged"), "resolved")


@router.delete("/alerts/{alert_id}", response_model=AlertOut)
def delete_alert(alert_id: AlertId, ctx: ManageAlerts):
    ctx.allowed_on(ALERTS, f"alert:{alert_id}")
    with atomic(ctx.db):
        a = ctx.db.get(CloudAlert, alert_id, with_for_update=True)
        if a is None:
            raise not_found("alert")
        out = _alert(a)
        ctx.db.delete(a)
        record(ctx.db, ctx.user, "alert.delete", "alert", str(alert_id),
               {"rule": a.rule, "status": a.status})
    return AlertOut(**ctx.sourced(), **out.model_dump())

