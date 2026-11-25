"""Network: VPCs, subnets, security groups and their rules (the mock inventory)."""

import ipaddress
import secrets
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import delete, func, select

from soc.api.cloud import catalog
from soc.api.cloud.common import (
    NETWORK,
    Description,
    Limit,
    Offset,
    Paged,
    Read,
    ResourceId,
    Sourced,
    WriteNetwork,
    atomic,
    conflict,
    not_found,
    page,
    record,
    unprocessable,
)
from soc.api.common import plain_text
from soc.api.models import CloudInstanceSg, CloudSecurityGroup, CloudSgRule, CloudVpc

router = APIRouter(prefix="/cloud/network", tags=["cloud"])
RuleId = Annotated[int, Path(ge=1, le=2**62)]


class Vpc(BaseModel):
    id: str
    name: str
    cidr: str
    subnet_count: int
    instance_count: int


class Subnet(BaseModel):
    id: str
    vpc_id: str
    name: str
    cidr: str
    az: str
    public: bool


class Rule(BaseModel):
    id: int
    direction: str
    protocol: str
    port_from: int
    port_to: int
    cidr: str
    description: str


class SecurityGroup(BaseModel):
    id: str
    name: str
    description: str
    vpc_id: str
    rules: list[Rule]
    instances_using: int
    open_to_world_admin_ports: bool  # a rule opens SSH or RDP to the whole internet


class SecurityGroupOut(Sourced, SecurityGroup):
    pass


def exposed_admin_ports(rules: list[dict]) -> set[tuple[int, int]]:
    """Internet-wide TCP management access, including a union of narrower networks."""
    networks: dict[tuple[int, int], list] = {}
    for rule in rules:
        if rule["direction"] != "in" or rule["protocol"] not in ("tcp", "all"):
            continue
        net = ipaddress.ip_network(rule["cidr"], strict=False)
        for port in catalog.SENSITIVE_PORTS:
            if rule["port_from"] <= port <= rule["port_to"]:
                networks.setdefault((net.version, port), []).append(net)
    return {key for key, nets in networks.items()
            if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(nets))}


def _sg(rec: dict) -> SecurityGroup:
    return SecurityGroup(**rec, open_to_world_admin_ports=bool(exposed_admin_ports(rec["rules"])))


# --- reads ----------------------------------------------------------------------------------------------

@router.get("/vpcs", response_model=Paged[Vpc])
def list_vpcs(ctx: Read, limit: Limit = 50, offset: Offset = 0):
    subnets = ctx.provider.list_subnets()
    instances = [i for i in ctx.provider.list_instances() if i["state"] != "terminated"]
    rows = [Vpc(**v, subnet_count=sum(s["vpc_id"] == v["id"] for s in subnets),
                instance_count=sum(i["vpc_id"] == v["id"] for i in instances))
            for v in ctx.provider.list_vpcs()]
    chosen, total = page(rows, limit, offset)
    return Paged[Vpc](**ctx.sourced(), items=chosen, total=total, limit=limit, offset=offset)


@router.get("/subnets", response_model=Paged[Subnet])
def list_subnets(ctx: Read, vpc_id: Annotated[str | None, Query(max_length=64)] = None,
                 az: Annotated[str | None, Query(max_length=24)] = None,
                 limit: Limit = 50, offset: Offset = 0):
    rows = [s for s in ctx.provider.list_subnets()
            if (not vpc_id or s["vpc_id"] == vpc_id) and (not az or s["az"] == az)]
    chosen, total = page(rows, limit, offset)
    return Paged[Subnet](**ctx.sourced(), items=[Subnet(**s) for s in chosen], total=total,
                         limit=limit, offset=offset)


@router.get("/security-groups", response_model=Paged[SecurityGroup])
def list_security_groups(ctx: Read, vpc_id: Annotated[str | None, Query(max_length=64)] = None,
                         q: Annotated[str | None, Query(max_length=64)] = None,
                         limit: Limit = 50, offset: Offset = 0):
    rows = [g for g in ctx.provider.list_security_groups()
            if (not vpc_id or g["vpc_id"] == vpc_id) and (not q or q.lower() in g["name"].lower())]
    chosen, total = page(rows, limit, offset)
    return Paged[SecurityGroup](**ctx.sourced(), items=[_sg(g) for g in chosen], total=total,
                                limit=limit, offset=offset)


def _find_sg(ctx, sg_id: str) -> dict:
    for g in ctx.provider.list_security_groups():
        if g["id"] == sg_id:
            return g
    raise not_found("security group")


@router.get("/security-groups/{sg_id}", response_model=SecurityGroupOut)
def get_security_group(sg_id: ResourceId, ctx: Read):
    return SecurityGroupOut(**ctx.sourced(), **_sg(_find_sg(ctx, sg_id)).model_dump())


# --- changes ----------------------------------------------------------------------------------------------

SgName = Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.-]*$"),
                   AfterValidator(plain_text)]


class SecurityGroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: SgName
    description: Description = ""
    vpc_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")]


def _cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError("not a valid IPv4 or IPv6 network in CIDR notation") from exc


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    direction: Literal["in", "out"]
    protocol: Literal["tcp", "udp", "icmp", "all"]
    port_from: Annotated[int, Field(ge=0, le=65535)] | None = None
    port_to: Annotated[int, Field(ge=0, le=65535)] | None = None
    cidr: Annotated[str, Field(min_length=1, max_length=43), AfterValidator(_cidr)]
    description: Description = ""
    # Opening SSH or RDP to the whole internet is refused unless this is true.
    confirm_open_to_world: bool = False

    @model_validator(mode="after")
    def _ports(self):
        if self.protocol in ("tcp", "udp"):
            if self.port_from is None:
                raise ValueError("port_from is required for tcp and udp")
            if self.port_to is None:
                self.port_to = self.port_from
            if self.port_from > self.port_to:
                raise ValueError("port_from must not be above port_to")
        else:
            if self.port_from is not None or self.port_to is not None:
                raise ValueError("ports do not apply to icmp and all")
            self.port_from, self.port_to = 0, 65535
        return self


def _reload(ctx, sg_id: str) -> SecurityGroupOut:
    return SecurityGroupOut(**ctx.changed(), **_sg(_find_sg(ctx, sg_id)).model_dump())


@router.post("/security-groups", response_model=SecurityGroupOut, status_code=201)
def create_security_group(body: SecurityGroupCreate, ctx: WriteNetwork):
    ctx.require_mock()
    db = ctx.db
    if db.get(CloudVpc, body.vpc_id) is None:
        raise unprocessable("unknown vpc_id")
    if (db.scalar(select(func.count()).select_from(CloudSecurityGroup)) or 0) \
            >= catalog.MAX_SECURITY_GROUPS:
        raise conflict(f"at most {catalog.MAX_SECURITY_GROUPS} security groups")
    if db.scalar(select(CloudSecurityGroup.id).where(
            CloudSecurityGroup.vpc_id == body.vpc_id,
            func.lower(CloudSecurityGroup.name) == body.name.lower())):
        raise conflict("a security group with that name exists in the VPC")
    with atomic(db):
        while True:
            sid = "sg-" + secrets.token_hex(4)
            if db.get(CloudSecurityGroup, sid) is None:
                break
        db.add(CloudSecurityGroup(id=sid, name=body.name, description=body.description,
                                  vpc_id=body.vpc_id))
        db.flush()
        db.add(CloudSgRule(sg_id=sid, direction="out", protocol="all", port_from=0,
                           port_to=65535, cidr="0.0.0.0/0", description="all out"))
        record(db, ctx.user, "security_group.create", "security_group", sid,
               {"name": body.name, "vpc_id": body.vpc_id})
    return _reload(ctx, sid)


@router.delete("/security-groups/{sg_id}", response_model=SecurityGroupOut)
def delete_security_group(sg_id: ResourceId, ctx: WriteNetwork):
    ctx.allowed_on(NETWORK, f"securitygroup:{sg_id}")
    ctx.require_mock()
    with atomic(ctx.db):
        sg = ctx.db.get(CloudSecurityGroup, sg_id, with_for_update=True)
        if sg is None:
            raise not_found("security group")
        snapshot = _find_sg(ctx, sg_id)
        if snapshot["instances_using"] > 0:
            raise conflict(f"the security group is used by {snapshot['instances_using']} "
                           "instance(s); change them first")
        # associations left by terminated instances go with it
        ctx.db.execute(delete(CloudInstanceSg).where(CloudInstanceSg.sg_id == sg_id))
        ctx.db.execute(delete(CloudSgRule).where(CloudSgRule.sg_id == sg_id))
        ctx.db.delete(sg)
        record(ctx.db, ctx.user, "security_group.delete", "security_group", sg_id,
               {"name": sg.name, "rules": len(snapshot["rules"])})
    return SecurityGroupOut(**ctx.changed(), **_sg(snapshot).model_dump())


@router.post("/security-groups/{sg_id}/rules", response_model=SecurityGroupOut, status_code=201)
def add_rule(sg_id: ResourceId, body: RuleCreate, ctx: WriteNetwork):
    ctx.allowed_on(NETWORK, f"securitygroup:{sg_id}")
    ctx.require_mock()
    rule = {"direction": body.direction, "protocol": body.protocol, "port_from": body.port_from,
            "port_to": body.port_to, "cidr": body.cidr}
    with atomic(ctx.db):
        sg = ctx.db.get(CloudSecurityGroup, sg_id, with_for_update=True)
        if sg is None:
            raise not_found("security group")
        existing = list(ctx.db.scalars(select(CloudSgRule).where(CloudSgRule.sg_id == sg_id)))
        rows = [{k: getattr(r, k) for k in rule} for r in existing]
        risky = bool(exposed_admin_ports([rule]) or
                     exposed_admin_ports([*rows, rule]) - exposed_admin_ports(rows))
        if risky and not body.confirm_open_to_world:
            raise HTTPException(422, detail={
                "code": "confirm_open_to_world",
                "message": "The combined inbound rules open SSH or RDP to the whole internet. "
                           "Confirm this exposure or choose a narrower source range."})
        if len(existing) >= catalog.MAX_RULES_PER_GROUP:
            raise conflict(f"at most {catalog.MAX_RULES_PER_GROUP} rules per security group")
        if any(all(getattr(r, k) == v for k, v in rule.items()) for r in existing):
            raise conflict("that rule already exists")
        new = CloudSgRule(sg_id=sg_id, description=body.description, **rule)
        ctx.db.add(new)
        ctx.db.flush()
        record(ctx.db, ctx.user, "security_group.rule_add", "security_group", sg_id,
               {**rule, "rule_id": new.id, "confirmed_open_to_world": risky})
    return _reload(ctx, sg_id)


@router.delete("/security-groups/{sg_id}/rules/{rule_id}", response_model=SecurityGroupOut)
def delete_rule(sg_id: ResourceId, rule_id: RuleId, ctx: WriteNetwork):
    ctx.allowed_on(NETWORK, f"securitygroup:{sg_id}")
    ctx.require_mock()
    with atomic(ctx.db):
        if ctx.db.get(CloudSecurityGroup, sg_id, with_for_update=True) is None:
            raise not_found("security group")
        rule = ctx.db.get(CloudSgRule, rule_id)
        if rule is None or rule.sg_id != sg_id:
            raise not_found("rule")
        ctx.db.delete(rule)
        record(ctx.db, ctx.user, "security_group.rule_delete", "security_group", sg_id,
               {"rule_id": rule_id, "direction": rule.direction, "protocol": rule.protocol,
                "port_from": rule.port_from, "port_to": rule.port_to, "cidr": rule.cidr})
    return _reload(ctx, sg_id)
