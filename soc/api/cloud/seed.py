"""Idempotent demo data for the MOCK cloud. Everything here is invented: addresses are private or
RFC 5737 documentation ranges, bucket names carry "demo", and the actor of the back-filled
activity is "demo-seed". Created on first access when every inventory table is empty, and by
POST /cloud/demo-data/reset after wiping.
"""

import random
from datetime import date, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from soc.api.cloud import catalog, clock, metrics
from soc.api.models import (
    CloudActivity,
    CloudAlert,
    CloudBucket,
    CloudCostDaily,
    CloudInstance,
    CloudInstanceSg,
    CloudSecurityGroup,
    CloudSgRule,
    CloudSubnet,
    CloudVolume,
    CloudVpc,
)

SEED_ACTOR = "demo-seed"
COST_DAYS = 90  # covers the 90d range and last month in full
_RNG_SEED = 20260101

# Tables wiped by reset, children first.
_WIPE = (CloudInstanceSg, CloudVolume, CloudSgRule, CloudInstance, CloudSecurityGroup,
         CloudSubnet, CloudVpc, CloudBucket, CloudAlert, CloudActivity, CloudCostDaily)

# name, type, os, subnet key, wanted load tier, state, launched days ago, disk GB
_INSTANCES = (
    ("web-1", "t3.medium", "Ubuntu 22.04", "prod-public-a", "normal", "running", 58, 30),
    ("web-2", "t3.medium", "Ubuntu 22.04", "prod-public-b", "busy", "running", 58, 30),
    ("api-1", "m5.large", "Amazon Linux 2023", "prod-private-a", "hot", "running", 41, 40),
    ("api-2", "m5.large", "Amazon Linux 2023", "prod-private-b", "normal", "running", 41, 40),
    ("db-1", "r5.large", "Debian 12", "prod-private-a", "full", "running", 33, 100),
    ("worker-1", "c5.xlarge", "Ubuntu 24.04", "prod-private-b", "busy", "running", 25, 40),
    ("build-1", "c5.large", "Ubuntu 22.04", "dev-a", "idle", "stopped", 19, 60),
    ("batch-old", "t3.large", "Windows Server 2022", "dev-b", "idle", "terminated", 27, 80),
)
_SGS_FOR = {"web-1": ("web-sg",), "web-2": ("web-sg",), "api-1": ("app-sg",),
            "api-2": ("app-sg",), "db-1": ("app-sg",), "worker-1": ("app-sg",),
            "build-1": ("legacy-ssh",), "batch-old": ("legacy-ssh",)}


_COST_BASE = {"compute": 31.0, "storage": 8.5, "network": 5.2, "other": 3.1}


def cost_rows(first: date, last: date) -> list[CloudCostDaily]:
    """Mock cost rows for first..last inclusive: a pure function of the date (weekday rhythm plus
    stable noise), so any day can be produced later and always comes out the same."""
    out = []
    for n in range((last - first).days + 1):
        day = first + timedelta(days=n)
        weekend = 0.82 if day.weekday() >= 5 else 1.0
        for service, level in _COST_BASE.items():
            noise = 0.9 + 0.2 * metrics._unit("cost", service, day.isoformat())
            out.append(CloudCostDaily(day=day.isoformat(), service=service, currency="USD",
                                      amount_usd=round(level * weekend * noise, 2)))
    return out


def top_up_cost(db: Session) -> int:
    """Add the days after the newest stored one up to today (at most COST_DAYS of them), so the
    mock cost keeps pace with the clock. Does nothing while the table is empty (the seed owns
    that case) or already current. Two requests racing for the same days: the loser conflicts on
    the primary key, rolls back and finds them there. Returns the days added."""
    today = clock.now().date()
    newest = db.scalar(select(func.max(CloudCostDaily.day)))
    if newest is None or newest >= today.isoformat():
        return 0
    first = max(date.fromisoformat(newest) + timedelta(days=1),
                today - timedelta(days=COST_DAYS - 1))
    rows = cost_rows(first, today)
    try:
        db.add_all(rows)
        db.commit()
    except IntegrityError:
        db.rollback()
        return 0
    return len(rows) // len(_COST_BASE)


def _is_empty(db: Session) -> bool:
    return all(db.scalar(select(m).limit(1)) is None
               for m in (CloudInstance, CloudVpc, CloudBucket, CloudSecurityGroup))


def seed_if_empty(db: Session) -> bool:
    """Seed when every inventory table is empty. Two requests racing for the first seed: the
    loser hits a primary-key conflict, rolls back and finds the data there."""
    if not _is_empty(db):
        return False
    try:
        seed(db)
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        if _is_empty(db):
            raise
        return False


def wipe(db: Session) -> None:
    for model in _WIPE:
        db.execute(delete(model))


def _hex(rng: random.Random, prefix: str, n: int = 8) -> str:
    return prefix + "".join(rng.choice("0123456789abcdef") for _ in range(n))


def seed(db: Session) -> dict[str, int]:
    """Add the demo data (the caller commits). The tables must be empty."""
    rng = random.Random(_RNG_SEED)
    now = clock.now()
    act: list[CloudActivity] = []

    def log(days_ago: float, action: str, rtype: str, rid: str, details: dict | None = None,
            actor: str = SEED_ACTOR) -> None:
        act.append(CloudActivity(at=now - timedelta(days=days_ago), actor=actor, action=action,
                                 resource_type=rtype, resource_id=rid,
                                 details={"demo": True, **(details or {})}))

    # -- network ---------------------------------------------------------------------------------
    vpcs = {"prod": CloudVpc(id=_hex(rng, "vpc-"), name="prod-vpc", cidr="10.0.0.0/16"),
            "dev": CloudVpc(id=_hex(rng, "vpc-"), name="dev-vpc", cidr="10.1.0.0/16")}
    az_a, az_b = f"{catalog.REGION}a", f"{catalog.REGION}b"
    subnet_defs = (("prod-public-a", "prod", "10.0.1.0/24", az_a, True),
                   ("prod-private-a", "prod", "10.0.2.0/24", az_a, False),
                   ("prod-public-b", "prod", "10.0.3.0/24", az_b, True),
                   ("prod-private-b", "prod", "10.0.4.0/24", az_b, False),
                   ("dev-a", "dev", "10.1.1.0/24", az_a, True),
                   ("dev-b", "dev", "10.1.2.0/24", az_b, False))
    subnets = {n: CloudSubnet(id=_hex(rng, "subnet-"), vpc_id=vpcs[v].id, name=n, cidr=c, az=az,
                              public=p) for n, v, c, az, p in subnet_defs}
    sg_defs = (("web-sg", "Public web tier", "prod",
                (("in", "tcp", 80, 80, "0.0.0.0/0", "http"),
                 ("in", "tcp", 443, 443, "0.0.0.0/0", "https"),
                 ("in", "tcp", 22, 22, "10.0.0.0/8", "ssh from inside"),
                 ("out", "all", 0, 65535, "0.0.0.0/0", "all out"))),
               ("app-sg", "Application and database tier", "prod",
                (("in", "tcp", 8080, 8080, "10.0.0.0/16", "app port"),
                 ("in", "tcp", 5432, 5432, "10.0.0.0/16", "postgres"),
                 ("in", "tcp", 22, 22, "10.0.0.0/8", "ssh from inside"),
                 ("out", "all", 0, 65535, "0.0.0.0/0", "all out"))),
               ("legacy-ssh", "Old dev access: SSH open to the world (a demo finding)", "dev",
                (("in", "tcp", 22, 22, "0.0.0.0/0", "ssh from anywhere"),
                 ("out", "all", 0, 65535, "0.0.0.0/0", "all out"))))
    sgs = {}
    db.add_all(vpcs.values())
    db.flush()  # The subnet and security-group rows reference these VPCs.
    for name, desc, v, rules in sg_defs:
        sg = CloudSecurityGroup(id=_hex(rng, "sg-"), name=name, description=desc,
                                vpc_id=vpcs[v].id)
        sgs[name] = sg
        db.add(sg)
    db.add_all(subnets.values())
    db.flush()
    for name, _d, _v, rules in sg_defs:
        db.add_all(CloudSgRule(sg_id=sgs[name].id, direction=d, protocol=p, port_from=lo,
                               port_to=hi, cidr=c, description=de)
                   for d, p, lo, hi, c, de in rules)
    for name, sg in sgs.items():
        log(40, "security_group.create", "security_group", sg.id, {"name": name})

    # -- instances ---------------------------------------------------------------------------------
    used_ids: set[str] = set()
    used_ips: set[str] = set()
    inst: dict[str, CloudInstance] = {}
    for name, itype, os_, sub_key, want_tier, state, age, disk in _INSTANCES:
        while True:  # an id whose (hash-decided) load matches what the demo wants to show
            iid = _hex(rng, "i-")
            if iid not in used_ids and metrics.tier(iid) == want_tier:
                break
        used_ids.add(iid)
        sub = subnets[sub_key]
        host = next(f"{sub.cidr.rsplit('.', 1)[0]}.{n}" for n in range(10, 250)
                    if f"{sub.cidr.rsplit('.', 1)[0]}.{n}" not in used_ips)
        used_ips.add(host)
        public = f"203.0.113.{rng.randint(10, 250)}" if sub.public and state == "running" \
            else None
        vcpus, mem, _price = catalog.INSTANCE_TYPES[itype]
        launched = now - timedelta(days=age, hours=rng.randint(0, 20))
        inst[name] = CloudInstance(
            id=iid, name=name, instance_type=itype, state=state, az=sub.az, vpc_id=sub.vpc_id,
            subnet_id=sub.id, private_ip=host, public_ip=public, os=os_, vcpus=vcpus,
            memory_gb=mem, disk_gb=disk,
            tags={"env": "dev" if sub.vpc_id == vpcs["dev"].id else "prod", "owner": "demo-team"},
            launched_at=launched, updated_at=launched)
        log(age, "instance.create", "instance", iid, {"name": name, "instance_type": itype})
    # state history the metrics follow: build-1 stopped, batch-old terminated, worker-1 bounced
    inst["build-1"].updated_at = now - timedelta(days=3)
    log(3, "instance.stop", "instance", inst["build-1"].id, {"name": "build-1"})
    inst["batch-old"].updated_at = now - timedelta(days=6)
    log(6, "instance.stop", "instance", inst["batch-old"].id, {"name": "batch-old"})
    log(6, "instance.terminate", "instance", inst["batch-old"].id, {"name": "batch-old"})
    inst["worker-1"].updated_at = now - timedelta(days=9)
    log(10, "instance.stop", "instance", inst["worker-1"].id, {"name": "worker-1"})
    log(9, "instance.start", "instance", inst["worker-1"].id, {"name": "worker-1"})
    db.add_all(inst.values())
    db.flush()
    for name, groups in _SGS_FOR.items():
        db.add_all(CloudInstanceSg(instance_id=inst[name].id, sg_id=sgs[g].id) for g in groups)

    # -- storage -----------------------------------------------------------------------------------
    volume_defs = (("db-data", 500, "io1", "db-1", True), ("api-1-data", 100, "gp3", "api-1", True),
                   ("web-1-cache", 50, "gp3", "web-1", True),
                   ("backup-scratch", 200, "st1", None, True),
                   ("old-restore", 50, "gp2", None, False),
                   ("build-1-cache", 120, "gp3", "build-1", True))
    for name, size, vtype, owner, enc in volume_defs:
        vid = _hex(rng, "vol-")
        db.add(CloudVolume(id=vid, name=name, size_gb=size, type=vtype, encrypted=enc,
                           state="in-use" if owner else "available",
                           instance_id=inst[owner].id if owner else None))
        log(30, "volume.create", "volume", vid, {"name": name, "size_gb": size})
    bucket_defs = (("idps-demo-logs", True, True, True, 125_000, 84.2),
                   ("idps-demo-backups", True, True, True, 320, 410.0),
                   ("idps-demo-static-assets", False, True, False, 5_400, 2.1),
                   ("idps-demo-scratch", False, False, True, 12, 0.4))
    for name, ver, enc, blocked, objs, gb in bucket_defs:
        db.add(CloudBucket(name=name, region=catalog.REGION, versioning=ver, encrypted=enc,
                           public_access_blocked=blocked, object_count=objs, size_gb=gb,
                           created_at=now - timedelta(days=50)))
        log(50, "bucket.create", "bucket", name)

    # -- back-filled activity (the last 14 days) -----------------------------------------------------
    names = list(inst)
    for _ in range(26):
        n = rng.choice(names)
        day = rng.uniform(0.2, 14)
        kind = rng.choice(("tag", "reboot", "rule", "bucket"))
        actor = rng.choice(("demo-admin", "demo-analyst", "system"))
        if kind == "tag":
            log(day, "instance.update", "instance", inst[n].id, {"name": n, "changed": ["tags"]},
                actor)
        elif kind == "reboot" and inst[n].state == "running":
            log(day, "instance.reboot", "instance", inst[n].id, {"name": n}, actor)
        elif kind == "rule":
            sg = rng.choice(list(sgs.values()))
            log(day, "security_group.rule_add", "security_group", sg.id,
                {"direction": "in", "protocol": "tcp", "port_from": 8080, "port_to": 8080}, actor)
        else:
            b = rng.choice(bucket_defs)[0]
            log(day, "bucket.update", "bucket", b, {"changed": ["versioning"]}, actor)

    # -- alerts ------------------------------------------------------------------------------------
    def alert(sev, rule, rtype, rid, msg, status, hours_ago, by=None):
        db.add(CloudAlert(severity=sev, rule=rule, resource_type=rtype, resource_id=rid,
                          message=msg, status=status, created_at=now - timedelta(hours=hours_ago),
                          updated_at=now - timedelta(hours=max(hours_ago - 2, 0)), updated_by=by))

    alert("warning", "cpu_high", "instance", inst["api-1"].id,
          "CPU utilisation is high on api-1", "open", 5)
    alert("critical", "bucket_public", "bucket", "idps-demo-static-assets",
          "Bucket idps-demo-static-assets does not block public access", "open", 30)
    alert("critical", "sg_open_admin", "security_group", sgs["legacy-ssh"].id,
          "Security group legacy-ssh opens SSH or RDP to the whole internet", "open", 70)
    alert("warning", "memory_high", "instance", inst["db-1"].id,
          "Memory utilisation is high on db-1", "acknowledged", 26, "demo-analyst")
    alert("warning", "disk_high", "instance", inst["build-1"].id,
          "Disk utilisation is high on build-1", "resolved", 120, "demo-admin")

    # -- cost: 90 days, four services, a weekday rhythm and stable noise -----------------------------
    db.add_all(cost_rows(now.date() - timedelta(days=COST_DAYS - 1), now.date()))
    db.add_all(act)
    return {"instances": len(inst), "volumes": len(volume_defs), "buckets": len(bucket_defs),
            "vpcs": len(vpcs), "subnets": len(subnets), "security_groups": len(sgs),
            "alerts": 5, "activity": len(act), "cost_days": COST_DAYS}
