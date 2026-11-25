"""Instances: list, read, create, change, start, stop, reboot, terminate, metrics."""

import ipaddress
import random
import secrets
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from soc.api.cloud import catalog, clock, metrics
from soc.api.cloud.common import (
    INSTANCES,
    Ctx,
    Limit,
    Name,
    Offset,
    Paged,
    Read,
    ResourceId,
    Sourced,
    Tags,
    WriteInstances,
    atomic,
    conflict,
    not_found,
    page,
    record,
    unprocessable,
)
from soc.api.models import (
    CloudInstance,
    CloudInstanceSg,
    CloudSecurityGroup,
    CloudSubnet,
    CloudVolume,
)

router = APIRouter(prefix="/cloud/instances", tags=["cloud"])
MOCK_METRICS_LABEL = "Mock metrics: generated deterministically from the instance id, not measured"


class HealthCheck(BaseModel):
    name: str
    status: str
    value: float | str
    threshold: dict[str, float] | None = None


class Health(BaseModel):
    status: Literal["healthy", "degraded", "critical", "unknown"]
    checks: list[HealthCheck]


class Instance(BaseModel):
    id: str
    name: str
    instance_type: str
    state: str
    az: str
    vpc_id: str
    subnet_id: str
    private_ip: str
    public_ip: str | None
    os: str
    vcpus: int
    memory_gb: float
    disk_gb: int
    tags: dict[str, str]
    security_group_ids: list[str]
    launched_at: datetime
    updated_at: datetime
    health: Health
    metrics_source: str = "mock"  # the health checks are computed from MOCK metrics


class InstanceOut(Sourced, Instance):
    pass


class Series(BaseModel):
    cpu_pct: list[float | None]
    memory_pct: list[float | None]
    disk_pct: list[float | None]
    net_in_mbps: list[float | None]
    net_out_mbps: list[float | None]


class InstanceMetrics(Sourced):
    instance_id: str
    state: str
    range: str
    step_seconds: int
    timestamps: list[str]
    series: Series
    current: dict[str, float]
    metrics_source: str = "mock"
    metrics_label: str = MOCK_METRICS_LABEL


def sample_of(rec: dict, now: datetime) -> dict[str, float]:
    return metrics.current(rec["id"], rec["state"], rec["launched_at"], rec["run_start"],
                           rec["run_end"], now)


def instance_view(rec: dict, now: datetime) -> Instance:
    sample = sample_of(rec, now)
    keys = ("id", "name", "instance_type", "state", "az", "vpc_id", "subnet_id", "private_ip",
            "public_ip", "os", "vcpus", "memory_gb", "disk_gb", "tags", "security_group_ids",
            "launched_at", "updated_at")
    return Instance(**{k: rec[k] for k in keys}, health=Health(**metrics.health(rec["state"],
                                                                                 sample)))


def _find(ctx: Ctx, instance_id: str) -> dict:
    for rec in ctx.provider.list_instances():
        if rec["id"] == instance_id:
            return rec
    raise not_found("instance")


def _out(ctx: Ctx, instance_id: str, *, changed: bool) -> InstanceOut:
    rec = _find(ctx, instance_id)
    head = ctx.changed() if changed else ctx.sourced()
    return InstanceOut(**head, **instance_view(rec, clock.now()).model_dump())


# --- reads --------------------------------------------------------------------------------------------

_SORTS = ("name", "state", "instance_type", "az", "launched_at", "updated_at", "id")


@router.get("", response_model=Paged[Instance])
def list_instances(
        ctx: Read, q: Annotated[str | None, Query(max_length=63, description="name contains")] = None,
        state: Literal["running", "stopped", "pending", "terminated"] | None = None,
        az: Annotated[str | None, Query(max_length=24)] = None,
        type: Annotated[str | None, Query(max_length=24, description="instance type")] = None,
        sort: Literal["name", "state", "instance_type", "az", "launched_at", "updated_at",
                      "id"] = "name",
        order: Literal["asc", "desc"] = "asc", limit: Limit = 50, offset: Offset = 0):
    rows = ctx.provider.list_instances()
    if q:
        rows = [r for r in rows if q.lower() in r["name"].lower()]
    if state:
        rows = [r for r in rows if r["state"] == state]
    if az:
        rows = [r for r in rows if r["az"] == az]
    if type:
        rows = [r for r in rows if r["instance_type"] == type]
    rows.sort(key=lambda r: (r[sort], r["id"]), reverse=order == "desc")
    chosen, total = page(rows, limit, offset)
    now = clock.now()
    return Paged[Instance](**ctx.sourced(), items=[instance_view(r, now) for r in chosen],
                           total=total, limit=limit, offset=offset)


@router.get("/{instance_id}", response_model=InstanceOut)
def get_instance(instance_id: ResourceId, ctx: Read):
    return _out(ctx, instance_id, changed=False)


@router.get("/{instance_id}/metrics", response_model=InstanceMetrics)
def instance_metrics(instance_id: ResourceId, ctx: Read,
                     range_: Annotated[Literal["1h", "24h", "7d"], Query(alias="range")] = "1h"):
    rec = _find(ctx, instance_id)
    now = clock.now()
    data = metrics.series_for(rec["id"], rec["state"], rec["launched_at"], rec["run_start"],
                              rec["run_end"], range_, now)
    return InstanceMetrics(**ctx.sourced(), instance_id=rec["id"], state=rec["state"],
                           range=range_, current=sample_of(rec, now), **data)


# --- changes (the mock inventory only) ------------------------------------------------------------------

def _instance_type(value: str) -> str:
    if value not in catalog.INSTANCE_TYPES:
        raise ValueError("unknown instance type; one of " + ", ".join(catalog.INSTANCE_TYPES))
    return value


def _unique(values: list[str]) -> list[str]:
    if len(set(values)) != len(values):
        raise ValueError("ids must not repeat")
    return values


Ident = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")]


class InstanceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name
    instance_type: Annotated[str, AfterValidator(_instance_type)]
    subnet_id: Ident
    security_group_ids: Annotated[list[Ident], Field(min_length=1, max_length=5),
                                  AfterValidator(_unique)]
    az: Annotated[str, Field(max_length=24, pattern=r"^[a-z0-9-]+$")] | None = None
    os: Literal["Ubuntu 22.04", "Ubuntu 24.04", "Debian 12", "Amazon Linux 2023",
                "Windows Server 2022"] = "Ubuntu 22.04"
    disk_gb: Annotated[int, Field(ge=8, le=1000)] = 20
    tags: Tags = {}


class InstanceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name | None = None
    tags: Tags | None = None


def _lock(ctx: Ctx, instance_id: str) -> CloudInstance:
    inst = ctx.db.get(CloudInstance, instance_id, with_for_update=True)
    if inst is None:
        raise not_found("instance")
    return inst


def _free_private_ip(ctx: Ctx, subnet: CloudSubnet) -> str:
    used = set(ctx.db.scalars(select(CloudInstance.private_ip).where(
        CloudInstance.subnet_id == subnet.id, CloudInstance.state != "terminated")))
    for host in list(ipaddress.ip_network(subnet.cidr).hosts())[3:]:  # .1-.3 are reserved
        if str(host) not in used:
            return str(host)
    raise conflict("the subnet has no free addresses")


def _free_public_ip(ctx: Ctx) -> str:
    used = set(ctx.db.scalars(select(CloudInstance.public_ip)
                              .where(CloudInstance.public_ip.is_not(None))))
    pool = [f"203.0.113.{n}" for n in range(10, 251)]  # RFC 5737 documentation addresses
    random.SystemRandom().shuffle(pool)
    for ip in pool:
        if ip not in used:
            return ip
    raise conflict("no free public addresses")


@router.post("", response_model=InstanceOut, status_code=201)
def create_instance(body: InstanceCreate, ctx: WriteInstances):
    ctx.require_mock()
    db = ctx.db
    live = db.scalar(select(func.count()).select_from(CloudInstance)
                     .where(CloudInstance.state != "terminated")) or 0
    if live >= catalog.MAX_INSTANCES:
        raise conflict(f"at most {catalog.MAX_INSTANCES} instances (terminate some first)")
    subnet = db.get(CloudSubnet, body.subnet_id)
    if subnet is None:
        raise unprocessable("unknown subnet_id")
    if body.az is not None and body.az != subnet.az:
        raise unprocessable(f"the subnet is in {subnet.az}, not {body.az}")
    groups = list(db.scalars(select(CloudSecurityGroup)
                             .where(CloudSecurityGroup.id.in_(body.security_group_ids))))
    if len(groups) != len(body.security_group_ids):
        raise unprocessable("unknown security group id")
    if any(g.vpc_id != subnet.vpc_id for g in groups):
        raise unprocessable("a security group belongs to another VPC than the subnet")
    vcpus, memory, _price = catalog.INSTANCE_TYPES[body.instance_type]
    now = clock.now()
    with atomic(db):
        while True:
            iid = "i-" + secrets.token_hex(4)
            if db.get(CloudInstance, iid) is None:
                break
        db.add(CloudInstance(
            id=iid, name=body.name, instance_type=body.instance_type, state="pending",
            az=subnet.az, vpc_id=subnet.vpc_id, subnet_id=subnet.id,
            private_ip=_free_private_ip(ctx, subnet),
            public_ip=_free_public_ip(ctx) if subnet.public else None, os=body.os, vcpus=vcpus,
            memory_gb=memory, disk_gb=body.disk_gb, tags=body.tags, launched_at=now,
            updated_at=now))
        db.flush()
        db.add_all(CloudInstanceSg(instance_id=iid, sg_id=g.id) for g in groups)
        record(db, ctx.user, "instance.create", "instance", iid,
               {"name": body.name, "instance_type": body.instance_type, "subnet_id": subnet.id,
                "security_group_ids": sorted(body.security_group_ids)})
    return _out(ctx, iid, changed=True)


@router.patch("/{instance_id}", response_model=InstanceOut)
def update_instance(instance_id: ResourceId, body: InstanceUpdate, ctx: WriteInstances):
    ctx.allowed_on(INSTANCES, f"instance:{instance_id}")
    ctx.require_mock()
    if not body.model_fields_set:
        raise unprocessable("nothing to change")
    with atomic(ctx.db):
        inst = _lock(ctx, instance_id)
        if inst.state == "terminated":
            raise conflict("a terminated instance cannot be changed")
        changed = []
        if body.name is not None and body.name != inst.name:
            inst.name = body.name
            changed.append("name")
        if body.tags is not None and body.tags != inst.tags:
            inst.tags = body.tags
            changed.append("tags")
        if changed:
            if inst.state != "pending":  # pending uses this timestamp for the boot transition
                inst.updated_at = clock.now()
            record(ctx.db, ctx.user, "instance.update", "instance", inst.id,
                   {"name": inst.name, "changed": changed})
    return _out(ctx, instance_id, changed=True)


def _transition(ctx: Ctx, instance_id: str, verb: str, allowed: tuple[str, ...],
                new_state: str | None) -> InstanceOut:
    ctx.allowed_on(INSTANCES, f"instance:{instance_id}")
    ctx.require_mock()
    with atomic(ctx.db):
        inst = _lock(ctx, instance_id)
        if inst.state not in allowed:
            raise conflict(f"cannot {verb} an instance that is {inst.state} "
                           f"(allowed from: {', '.join(allowed)})")
        before = inst.state
        extra: dict = {}
        if new_state is not None:
            inst.state = new_state
        if verb == "start":
            subnet = ctx.db.get(CloudSubnet, inst.subnet_id)
            if subnet is not None and subnet.public:
                inst.public_ip = _free_public_ip(ctx)
        elif verb in ("stop", "terminate"):
            inst.public_ip = None  # released, as in a real cloud
            if verb == "terminate":
                attached = list(ctx.db.scalars(select(CloudVolume).where(
                    CloudVolume.instance_id == inst.id)))
                for v in attached:  # the volumes survive, unattached
                    v.state, v.instance_id = "available", None
                extra["volumes_detached"] = sorted(v.id for v in attached)
        inst.updated_at = clock.now()
        record(ctx.db, ctx.user, f"instance.{verb}", "instance", inst.id,
               {"name": inst.name, "from": before, "to": inst.state, **extra})
    return _out(ctx, instance_id, changed=True)


@router.post("/{instance_id}/start", response_model=InstanceOut)
def start_instance(instance_id: ResourceId, ctx: WriteInstances):
    return _transition(ctx, instance_id, "start", ("stopped",), "pending")


@router.post("/{instance_id}/stop", response_model=InstanceOut)
def stop_instance(instance_id: ResourceId, ctx: WriteInstances):
    return _transition(ctx, instance_id, "stop", ("running",), "stopped")


@router.post("/{instance_id}/reboot", response_model=InstanceOut)
def reboot_instance(instance_id: ResourceId, ctx: WriteInstances):
    return _transition(ctx, instance_id, "reboot", ("running",), None)


@router.delete("/{instance_id}", response_model=InstanceOut)
def terminate_instance(instance_id: ResourceId, ctx: WriteInstances):
    """Terminate (the record stays, as "terminated"). Only from running or stopped."""
    return _transition(ctx, instance_id, "terminate", ("running", "stopped"), "terminated")

