"""The provider seam: where the cloud inventory comes from.

A provider answers read questions with plain dicts (the same keys whichever provider it is) and
says what it is (`data_source`, `data_source_label`) so every response can be honest about it.

  * MockProvider (default): the inventory lives in the SOC's database (models CloudInstance and
    friends), seeded with demo data on first access. It is the only provider that accepts
    changes, and the changes only ever touch that database.
  * EmulatedAwsProvider: read-only boto3 calls against the local Moto emulator, used only when
    IDPS_SOC_CLOUD_ENDPOINT_URL is set to a loopback or private http URL (guard.py). It uses the
    fake test/test credentials, account 000000000000 and region eu-west-1, and never real AWS.
"""

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from soc.api.cloud import catalog, clock, guard
from soc.api.models import (
    CloudActivity,
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

log = logging.getLogger("soc.cloud")

MOCK = "mock"
EMULATED = "emulated-aws"
MOCK_LABEL = "Mock data: no live cloud connected"
EMULATED_LABEL = ("Emulated AWS (local Moto emulator, account 000000000000): not a real cloud; "
                  "read-only")
MOCK_NOTE = ("Applied to the persisted mock inventory only; nothing in any real cloud was "
             "changed.")


class ProviderUnavailable(RuntimeError):
    """The provider cannot answer (the emulator is down or the endpoint was refused). The message
    is safe to show: it never contains a URL's credentials or any secret."""


class CloudProvider(ABC):
    name: str
    data_source: str
    data_source_label: str
    writable: bool
    cost_available: bool

    @abstractmethod
    def list_instances(self) -> list[dict]: ...

    @abstractmethod
    def list_volumes(self) -> list[dict]: ...

    @abstractmethod
    def list_buckets(self) -> list[dict]: ...

    @abstractmethod
    def list_vpcs(self) -> list[dict]: ...

    @abstractmethod
    def list_subnets(self) -> list[dict]: ...

    @abstractmethod
    def list_security_groups(self) -> list[dict]: ...

    @abstractmethod
    def cost_daily(self, first_day: str, last_day: str) -> list[dict]: ...


# --- the mock (database-backed) provider ----------------------------------------------------------

_RUN_STARTS = ("instance.create", "instance.start")
_RUN_ENDS = ("instance.stop", "instance.terminate")


class MockProvider(CloudProvider):
    name = "mock"
    data_source = MOCK
    data_source_label = MOCK_LABEL
    writable = True
    cost_available = True

    def __init__(self, db: Session) -> None:
        self.db = db

    # -- first use: demo data, and pending -> running -----------------------------------------
    def prepare(self) -> None:
        """Seed the demo data if every inventory table is empty, and move instances that have
        been pending long enough to running (there are no background threads: this happens on
        the next request)."""
        from soc.api.cloud import seed

        seed.seed_if_empty(self.db)
        seed.top_up_cost(self.db)  # the mock cost keeps pace with the clock
        self.settle()

    def settle(self) -> None:
        cutoff = clock.now() - timedelta(seconds=catalog.PENDING_SECONDS)
        ids = list(self.db.scalars(select(CloudInstance.id).where(
            CloudInstance.state == "pending", CloudInstance.updated_at <= cutoff)))
        if not ids:
            return
        now = clock.now()
        ids = list(self.db.scalars(update(CloudInstance).where(
            CloudInstance.id.in_(ids), CloudInstance.state == "pending",
            CloudInstance.updated_at <= cutoff).values(state="running", updated_at=now)
            .returning(CloudInstance.id)))
        self.db.add_all(CloudActivity(at=now, actor="system", action="instance.running",
                                      resource_type="instance", resource_id=i,
                                      details={"data_source": MOCK}) for i in ids)
        self.db.commit()

    # -- reads ---------------------------------------------------------------------------------
    def _last_events(self) -> dict[str, tuple[str, datetime]]:
        """The latest start/stop-type event of every instance: {id: (action, at)}."""
        newest = (select(func.max(CloudActivity.id))
                  .where(CloudActivity.resource_type == "instance",
                         CloudActivity.action.in_(_RUN_STARTS + _RUN_ENDS))
                  .group_by(CloudActivity.resource_id))
        return {r: (a, at) for r, a, at in self.db.execute(
            select(CloudActivity.resource_id, CloudActivity.action, CloudActivity.at)
            .where(CloudActivity.id.in_(newest)))}

    def list_instances(self) -> list[dict]:
        events = self._last_events()
        sgs: dict[str, list[str]] = {}
        for iid, sid in self.db.execute(select(CloudInstanceSg.instance_id, CloudInstanceSg.sg_id)
                                        .order_by(CloudInstanceSg.sg_id)):
            sgs.setdefault(iid, []).append(sid)
        out = []
        for i in self.db.scalars(select(CloudInstance).order_by(CloudInstance.id)):
            action, at = events.get(i.id, (None, None))
            if i.state in ("running", "pending"):
                run_start = at if action in _RUN_STARTS else i.launched_at
                run_end = None
            else:  # stopped or terminated: ran until the last stop (or never, with no record)
                run_start = i.launched_at
                run_end = at if action in _RUN_ENDS else i.launched_at
            out.append({"id": i.id, "name": i.name, "instance_type": i.instance_type,
                        "state": i.state, "az": i.az, "vpc_id": i.vpc_id,
                        "subnet_id": i.subnet_id, "private_ip": i.private_ip,
                        "public_ip": i.public_ip, "os": i.os, "vcpus": i.vcpus,
                        "memory_gb": i.memory_gb, "disk_gb": i.disk_gb,
                        "tags": dict(i.tags or {}), "launched_at": i.launched_at,
                        "updated_at": i.updated_at, "security_group_ids": sgs.get(i.id, []),
                        "run_start": run_start, "run_end": run_end})
        return out

    def list_volumes(self) -> list[dict]:
        return [{"id": v.id, "name": v.name, "size_gb": v.size_gb, "type": v.type,
                 "state": v.state, "instance_id": v.instance_id, "encrypted": v.encrypted}
                for v in self.db.scalars(select(CloudVolume).order_by(CloudVolume.id))]

    def list_buckets(self) -> list[dict]:
        return [{"name": b.name, "region": b.region, "versioning": b.versioning,
                 "encrypted": b.encrypted, "public_access_blocked": b.public_access_blocked,
                 "object_count": b.object_count, "size_gb": b.size_gb, "created_at": b.created_at}
                for b in self.db.scalars(select(CloudBucket).order_by(CloudBucket.name))]

    def list_vpcs(self) -> list[dict]:
        return [{"id": v.id, "name": v.name, "cidr": v.cidr}
                for v in self.db.scalars(select(CloudVpc).order_by(CloudVpc.id))]

    def list_subnets(self) -> list[dict]:
        return [{"id": s.id, "vpc_id": s.vpc_id, "name": s.name, "cidr": s.cidr, "az": s.az,
                 "public": s.public}
                for s in self.db.scalars(select(CloudSubnet).order_by(CloudSubnet.id))]

    def list_security_groups(self) -> list[dict]:
        rules: dict[str, list[dict]] = {}
        for r in self.db.scalars(select(CloudSgRule).order_by(CloudSgRule.id)):
            rules.setdefault(r.sg_id, []).append(
                {"id": r.id, "direction": r.direction, "protocol": r.protocol,
                 "port_from": r.port_from, "port_to": r.port_to, "cidr": r.cidr,
                 "description": r.description})
        used = dict(self.db.execute(
            select(CloudInstanceSg.sg_id, func.count())
            .join(CloudInstance, CloudInstance.id == CloudInstanceSg.instance_id)
            .where(CloudInstance.state != "terminated").group_by(CloudInstanceSg.sg_id)).all())
        return [{"id": g.id, "name": g.name, "description": g.description, "vpc_id": g.vpc_id,
                 "rules": rules.get(g.id, []), "instances_using": used.get(g.id, 0)}
                for g in self.db.scalars(select(CloudSecurityGroup)
                                         .order_by(CloudSecurityGroup.id))]

    def cost_daily(self, first_day: str, last_day: str) -> list[dict]:
        return [{"day": c.day, "service": c.service, "amount_usd": c.amount_usd,
                 "currency": c.currency}
                for c in self.db.scalars(select(CloudCostDaily)
                                         .where(CloudCostDaily.day >= first_day,
                                                CloudCostDaily.day <= last_day)
                                         .order_by(CloudCostDaily.day, CloudCostDaily.service))]


# --- the emulated AWS provider (read-only, Moto only) -----------------------------------------------

_EC2_STATES = {"pending": "pending", "running": "running", "stopping": "stopped",
               "stopped": "stopped", "shutting-down": "terminated", "terminated": "terminated"}
MAX_EMULATED_ITEMS = 500  # never page through more than this of one kind


def _tags(raw) -> dict[str, str]:
    out = {}
    for t in (raw or [])[:catalog.MAX_TAGS]:
        key, val = str(t.get("Key", ""))[:64], str(t.get("Value", ""))[:128]
        if key:
            out[key] = val
    return out


class EmulatedAwsProvider(CloudProvider):
    name = "emulated-aws"
    data_source = EMULATED
    data_source_label = EMULATED_LABEL
    writable = False
    cost_available = False  # the emulator has no billing data

    def __init__(self, ec2, s3, sts) -> None:
        self.ec2, self.s3, self.sts = ec2, s3, sts
        self._verified = False

    @classmethod
    def from_endpoint(cls, url: str) -> "EmulatedAwsProvider":
        """Build the boto3 clients for `url` after the guard has accepted it. Credentials are the
        fake test/test pair passed explicitly, so nothing from the environment, a profile or an
        instance role is ever used."""
        try:
            guard.check_endpoint(url)
        except guard.EndpointRefused as exc:
            raise ProviderUnavailable(f"cloud endpoint refused: {exc}") from exc
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise ProviderUnavailable("boto3 is not installed") from exc
        session = boto3.session.Session(aws_access_key_id=guard.FAKE_KEY,
                                        aws_secret_access_key=guard.FAKE_KEY,
                                        region_name=catalog.REGION)
        cfg = Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 1},
                     proxies={})
        kw = {"endpoint_url": url, "config": cfg}
        return cls(session.client("ec2", **kw), session.client("s3", **kw),
                   session.client("sts", **kw))

    # -- plumbing ------------------------------------------------------------------------------
    def _call(self, fn, **kw):
        try:
            return fn(**kw)
        except Exception as exc:  # botocore errors, timeouts, refused connections
            log.warning("emulated cloud call failed: %s", type(exc).__name__)
            raise ProviderUnavailable(
                f"the emulated cloud did not answer ({type(exc).__name__})") from exc

    def _verify(self) -> None:
        if self._verified:
            return
        account = self._call(self.sts.get_caller_identity).get("Account")
        if account != catalog.ACCOUNT_ID:
            raise ProviderUnavailable("the endpoint is not the emulator account; refusing it")
        self._verified = True

    def _items(self, fn, key: str, **kw) -> list[dict]:
        self._verify()
        out: list[dict] = []
        token = None
        while len(out) < MAX_EMULATED_ITEMS:
            page = self._call(fn, **kw, **({"NextToken": token} if token else {}))
            out += page.get(key, [])
            token = page.get("NextToken")
            if not token:
                break
        return out[:MAX_EMULATED_ITEMS]

    # -- reads ---------------------------------------------------------------------------------
    def list_instances(self) -> list[dict]:
        disks: dict[str, int] = {}
        for v in self.list_volumes():
            if v["instance_id"]:
                disks[v["instance_id"]] = disks.get(v["instance_id"], 0) + v["size_gb"]
        out = []
        for res in self._items(self.ec2.describe_instances, "Reservations"):
            groups = [g.get("GroupId") for g in res.get("Groups", [])]
            for i in res.get("Instances", []):
                tags = _tags(i.get("Tags"))
                itype = str(i.get("InstanceType", ""))
                vcpus, mem, _price = catalog.INSTANCE_TYPES.get(itype, (0, 0.0, 0.0))
                state = _EC2_STATES.get(i.get("State", {}).get("Name", ""), "stopped")
                launched = i.get("LaunchTime")
                if not isinstance(launched, datetime):
                    launched = clock.now()
                elif launched.tzinfo is None:
                    launched = launched.replace(tzinfo=UTC)
                sgs = [g["GroupId"] for g in i.get("SecurityGroups", []) if g.get("GroupId")]
                out.append({
                    "id": i["InstanceId"], "name": tags.get("Name", i["InstanceId"]),
                    "instance_type": itype, "state": state,
                    "az": i.get("Placement", {}).get("AvailabilityZone", ""),
                    "vpc_id": i.get("VpcId", ""), "subnet_id": i.get("SubnetId", ""),
                    "private_ip": i.get("PrivateIpAddress", ""),
                    "public_ip": i.get("PublicIpAddress"),
                    "os": str(i.get("PlatformDetails") or "Linux/UNIX")[:48],
                    "vcpus": vcpus, "memory_gb": mem, "disk_gb": disks.get(i["InstanceId"], 0),
                    "tags": tags, "launched_at": launched, "updated_at": launched,
                    "security_group_ids": sgs or [g for g in groups if g],
                    "run_start": launched if state == "running" else None, "run_end": None})
        return out

    def list_volumes(self) -> list[dict]:
        out = []
        for v in self._items(self.ec2.describe_volumes, "Volumes"):
            att = (v.get("Attachments") or [{}])[0]
            tags = _tags(v.get("Tags"))
            out.append({"id": v["VolumeId"], "name": tags.get("Name", v["VolumeId"]),
                        "size_gb": int(v.get("Size", 0)), "type": str(v.get("VolumeType", "")),
                        "state": "in-use" if v.get("State") == "in-use" else "available",
                        "instance_id": att.get("InstanceId"),
                        "encrypted": bool(v.get("Encrypted"))})
        return out

    def list_buckets(self) -> list[dict]:
        self._verify()
        out = []
        for b in self._call(self.s3.list_buckets).get("Buckets", [])[:catalog.MAX_BUCKETS * 4]:
            name = b["Name"]
            ver = self._optional(self.s3.get_bucket_versioning, Bucket=name) or {}
            enc = self._optional(self.s3.get_bucket_encryption, Bucket=name)
            pab = (self._optional(self.s3.get_public_access_block, Bucket=name) or {}).get(
                "PublicAccessBlockConfiguration") or {}
            page = self._optional(self.s3.list_objects_v2, Bucket=name, MaxKeys=1000) or {}
            objs = page.get("Contents", [])
            created = b.get("CreationDate")
            out.append({
                "name": name, "region": catalog.REGION,
                "versioning": ver.get("Status") == "Enabled", "encrypted": enc is not None,
                "public_access_blocked": bool(pab) and all(pab.values()),
                # one page only: a lower bound for a big bucket
                "object_count": int(page.get("KeyCount", len(objs))),
                "size_gb": round(sum(o.get("Size", 0) for o in objs) / 1024**3, 4),
                "created_at": created if isinstance(created, datetime) else clock.now()})
        return out

    def _optional(self, fn, **kw):
        """A call whose 'not configured' answer is an error (no encryption, no public-access
        block): None then. A dead emulator is still a ProviderUnavailable."""
        try:
            return fn(**kw)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") \
                if hasattr(exc, "response") else ""
            if code in ("ServerSideEncryptionConfigurationNotFoundError",
                        "NoSuchPublicAccessBlockConfiguration", "NoSuchBucket", "AccessDenied"):
                return None
            log.warning("emulated cloud call failed: %s", type(exc).__name__)
            raise ProviderUnavailable(
                f"the emulated cloud did not answer ({type(exc).__name__})") from exc

    def list_vpcs(self) -> list[dict]:
        return [{"id": v["VpcId"], "name": _tags(v.get("Tags")).get("Name", v["VpcId"]),
                 "cidr": v.get("CidrBlock", "")}
                for v in self._items(self.ec2.describe_vpcs, "Vpcs")]

    def list_subnets(self) -> list[dict]:
        return [{"id": s["SubnetId"], "vpc_id": s.get("VpcId", ""),
                 "name": _tags(s.get("Tags")).get("Name", s["SubnetId"]),
                 "cidr": s.get("CidrBlock", ""), "az": s.get("AvailabilityZone", ""),
                 "public": bool(s.get("MapPublicIpOnLaunch"))}
                for s in self._items(self.ec2.describe_subnets, "Subnets")]

    def list_security_groups(self) -> list[dict]:
        used: dict[str, int] = {}
        for i in self.list_instances():
            if i["state"] != "terminated":
                for g in i["security_group_ids"]:
                    used[g] = used.get(g, 0) + 1
        out = []
        for g in self._items(self.ec2.describe_security_groups, "SecurityGroups"):
            rules: list[dict] = []
            for direction, key in (("in", "IpPermissions"), ("out", "IpPermissionsEgress")):
                for p in g.get(key, []):
                    proto = str(p.get("IpProtocol", "-1"))
                    proto = "all" if proto == "-1" else "icmp" if proto.startswith("icmp") \
                        else proto
                    lo = int(p.get("FromPort", 0)) if proto in ("tcp", "udp") else 0
                    hi = int(p.get("ToPort", 65535)) if proto in ("tcp", "udp") else 65535
                    for r in p.get("IpRanges", []):
                        rules.append({"id": len(rules) + 1, "direction": direction,
                                      "protocol": proto, "port_from": max(lo, 0),
                                      "port_to": max(hi, 0), "cidr": r.get("CidrIp", ""),
                                      "description": str(r.get("Description", ""))[:255]})
            out.append({"id": g["GroupId"], "name": g.get("GroupName", g["GroupId"]),
                        "description": str(g.get("Description", ""))[:255],
                        "vpc_id": g.get("VpcId", ""), "rules": rules,
                        "instances_using": used.get(g["GroupId"], 0)})
        return out

    def cost_daily(self, first_day: str, last_day: str) -> list[dict]:
        return []
