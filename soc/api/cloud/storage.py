"""Storage: volumes and buckets (the mock inventory)."""

import re
import secrets
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from soc.api.cloud import catalog, clock
from soc.api.cloud.common import (
    STORAGE,
    Limit,
    Name,
    Offset,
    Paged,
    Read,
    ResourceId,
    Sourced,
    WriteStorage,
    atomic,
    conflict,
    not_found,
    page,
    record,
    unprocessable,
)
from soc.api.models import CloudBucket, CloudInstance, CloudVolume

router = APIRouter(prefix="/cloud", tags=["cloud"])


# --- volumes --------------------------------------------------------------------------------------------

class Volume(BaseModel):
    id: str
    name: str
    size_gb: int
    type: str
    state: Literal["available", "in-use"]
    instance_id: str | None
    encrypted: bool


class VolumeOut(Sourced, Volume):
    pass


class VolumeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name
    size_gb: Annotated[int, Field(ge=1, le=16384)]
    type: Literal["gp3", "gp2", "io1", "st1"] = "gp3"
    encrypted: bool = True


class VolumeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name | None = None
    size_gb: Annotated[int, Field(ge=1, le=16384)] | None = None  # grow only


class VolumeAttach(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: Annotated[str, Field(min_length=1, max_length=64,
                                      pattern=r"^[A-Za-z0-9._:-]+$")]


def _volume(v: CloudVolume) -> Volume:
    return Volume(id=v.id, name=v.name, size_gb=v.size_gb, type=v.type, state=v.state,
                  instance_id=v.instance_id, encrypted=v.encrypted)


def _locked_volume(ctx, volume_id: str) -> CloudVolume:
    v = ctx.db.get(CloudVolume, volume_id, with_for_update=True)
    if v is None:
        raise not_found("volume")
    return v


@router.get("/volumes", response_model=Paged[Volume])
def list_volumes(ctx: Read, q: Annotated[str | None, Query(max_length=63)] = None,
                 state: Literal["available", "in-use"] | None = None,
                 instance_id: Annotated[str | None, Query(max_length=64)] = None,
                 sort: Literal["name", "size_gb", "type", "state", "id"] = "name",
                 order: Literal["asc", "desc"] = "asc", limit: Limit = 50, offset: Offset = 0):
    rows = ctx.provider.list_volumes()
    if q:
        rows = [r for r in rows if q.lower() in r["name"].lower()]
    if state:
        rows = [r for r in rows if r["state"] == state]
    if instance_id:
        rows = [r for r in rows if r["instance_id"] == instance_id]
    rows.sort(key=lambda r: (r[sort], r["id"]), reverse=order == "desc")
    chosen, total = page(rows, limit, offset)
    return Paged[Volume](**ctx.sourced(), items=[Volume(**r) for r in chosen], total=total,
                         limit=limit, offset=offset)


@router.get("/volumes/{volume_id}", response_model=VolumeOut)
def get_volume(volume_id: ResourceId, ctx: Read):
    for r in ctx.provider.list_volumes():
        if r["id"] == volume_id:
            return VolumeOut(**ctx.sourced(), **r)
    raise not_found("volume")


@router.post("/volumes", response_model=VolumeOut, status_code=201)
def create_volume(body: VolumeCreate, ctx: WriteStorage):
    ctx.require_mock()
    db = ctx.db
    if (db.scalar(select(func.count()).select_from(CloudVolume)) or 0) >= catalog.MAX_VOLUMES:
        raise conflict(f"at most {catalog.MAX_VOLUMES} volumes")
    with atomic(db):
        while True:
            vid = "vol-" + secrets.token_hex(4)
            if db.get(CloudVolume, vid) is None:
                break
        vol = CloudVolume(id=vid, name=body.name, size_gb=body.size_gb, type=body.type,
                          state="available", instance_id=None, encrypted=body.encrypted)
        db.add(vol)
        record(db, ctx.user, "volume.create", "volume", vid,
               {"name": body.name, "size_gb": body.size_gb, "type": body.type})
    return VolumeOut(**ctx.changed(), **_volume(vol).model_dump())


@router.patch("/volumes/{volume_id}", response_model=VolumeOut)
def update_volume(volume_id: ResourceId, body: VolumeUpdate, ctx: WriteStorage):
    ctx.allowed_on(STORAGE, f"volume:{volume_id}")
    ctx.require_mock()
    if not body.model_fields_set:
        raise unprocessable("nothing to change")
    with atomic(ctx.db):
        vol = _locked_volume(ctx, volume_id)
        changed: dict = {}
        if body.size_gb is not None and body.size_gb != vol.size_gb:
            if body.size_gb < vol.size_gb:
                raise unprocessable(f"a volume can only grow (it is {vol.size_gb} GB)")
            changed["size_gb"] = [vol.size_gb, body.size_gb]
            vol.size_gb = body.size_gb
        if body.name is not None and body.name != vol.name:
            changed["name"] = [vol.name, body.name]
            vol.name = body.name
        if changed:
            record(ctx.db, ctx.user, "volume.update", "volume", vol.id, changed)
    return VolumeOut(**ctx.changed(), **_volume(vol).model_dump())


@router.post("/volumes/{volume_id}/attach", response_model=VolumeOut)
def attach_volume(volume_id: ResourceId, body: VolumeAttach, ctx: WriteStorage):
    ctx.allowed_on(STORAGE, f"volume:{volume_id}")
    ctx.require_mock()
    with atomic(ctx.db):
        vol = _locked_volume(ctx, volume_id)
        if vol.state != "available":
            raise conflict(f"the volume is {vol.state}; detach it first")
        inst = ctx.db.get(CloudInstance, body.instance_id)
        if inst is None:
            raise unprocessable("unknown instance_id")
        if inst.state == "terminated":
            raise conflict("a volume cannot be attached to a terminated instance")
        vol.state, vol.instance_id = "in-use", inst.id
        record(ctx.db, ctx.user, "volume.attach", "volume", vol.id,
               {"name": vol.name, "instance_id": inst.id})
    return VolumeOut(**ctx.changed(), **_volume(vol).model_dump())


@router.post("/volumes/{volume_id}/detach", response_model=VolumeOut)
def detach_volume(volume_id: ResourceId, ctx: WriteStorage):
    ctx.allowed_on(STORAGE, f"volume:{volume_id}")
    ctx.require_mock()
    with atomic(ctx.db):
        vol = _locked_volume(ctx, volume_id)
        if vol.state != "in-use":
            raise conflict("the volume is not attached")
        old = vol.instance_id
        vol.state, vol.instance_id = "available", None
        record(ctx.db, ctx.user, "volume.detach", "volume", vol.id,
               {"name": vol.name, "instance_id": old})
    return VolumeOut(**ctx.changed(), **_volume(vol).model_dump())


@router.delete("/volumes/{volume_id}", response_model=VolumeOut)
def delete_volume(volume_id: ResourceId, ctx: WriteStorage):
    ctx.allowed_on(STORAGE, f"volume:{volume_id}")
    ctx.require_mock()
    with atomic(ctx.db):
        vol = _locked_volume(ctx, volume_id)
        if vol.state == "in-use":
            raise conflict("the volume is attached; detach it before deleting it")
        out = _volume(vol)
        ctx.db.delete(vol)
        record(ctx.db, ctx.user, "volume.delete", "volume", vol.id,
               {"name": vol.name, "size_gb": vol.size_gb})
    return VolumeOut(**ctx.changed(), **out.model_dump())


# --- buckets ----------------------------------------------------------------------------------------------

_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _bucket_name(value: str) -> str:
    if not _BUCKET.match(value):
        raise ValueError("a bucket name is 3 to 63 lower-case letters, digits, dots or hyphens, "
                         "starting and ending with a letter or digit")
    if ".." in value or ".-" in value or "-." in value:
        raise ValueError("a bucket name must not have '..', '.-' or '-.'")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
        raise ValueError("a bucket name must not look like an IP address")
    return value


BucketName = Annotated[str, Field(min_length=3, max_length=63), AfterValidator(_bucket_name)]
BucketPath = Annotated[str, Path(min_length=3, max_length=63, pattern=r"^[a-z0-9.-]+$")]


class Bucket(BaseModel):
    name: str
    region: str
    versioning: bool
    encrypted: bool
    public_access_blocked: bool
    object_count: int
    size_gb: float
    created_at: str


class BucketOut(Sourced, Bucket):
    pass


class BucketCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: BucketName
    versioning: bool = False
    encrypted: bool = True
    public_access_blocked: bool = True


class BucketUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    versioning: bool | None = None
    encrypted: bool | None = None
    public_access_blocked: bool | None = None


def _bucket(b) -> Bucket:
    get = b.get if isinstance(b, dict) else lambda k: getattr(b, k)
    return Bucket(name=get("name"), region=get("region"), versioning=get("versioning"),
                  encrypted=get("encrypted"), public_access_blocked=get("public_access_blocked"),
                  object_count=get("object_count"), size_gb=get("size_gb"),
                  created_at=get("created_at").isoformat().replace("+00:00", "Z"))


@router.get("/buckets", response_model=Paged[Bucket])
def list_buckets(ctx: Read, q: Annotated[str | None, Query(max_length=63)] = None,
                 sort: Literal["name", "size_gb", "object_count", "created_at"] = "name",
                 order: Literal["asc", "desc"] = "asc", limit: Limit = 50, offset: Offset = 0):
    rows = ctx.provider.list_buckets()
    if q:
        rows = [r for r in rows if q.lower() in r["name"].lower()]
    rows.sort(key=lambda r: (r[sort], r["name"]), reverse=order == "desc")
    chosen, total = page(rows, limit, offset)
    return Paged[Bucket](**ctx.sourced(), items=[_bucket(r) for r in chosen], total=total,
                         limit=limit, offset=offset)


@router.get("/buckets/{name}", response_model=BucketOut)
def get_bucket(name: BucketPath, ctx: Read):
    for r in ctx.provider.list_buckets():
        if r["name"] == name:
            return BucketOut(**ctx.sourced(), **_bucket(r).model_dump())
    raise not_found("bucket")


@router.post("/buckets", response_model=BucketOut, status_code=201)
def create_bucket(body: BucketCreate, ctx: WriteStorage):
    ctx.require_mock()
    db = ctx.db
    if (db.scalar(select(func.count()).select_from(CloudBucket)) or 0) >= catalog.MAX_BUCKETS:
        raise conflict(f"at most {catalog.MAX_BUCKETS} buckets")
    if db.get(CloudBucket, body.name) is not None:
        raise conflict("a bucket with that name already exists")
    with atomic(db):
        bucket = CloudBucket(name=body.name, region=catalog.REGION, versioning=body.versioning,
                             encrypted=body.encrypted,
                             public_access_blocked=body.public_access_blocked, object_count=0,
                             size_gb=0.0, created_at=clock.now())
        db.add(bucket)
        record(db, ctx.user, "bucket.create", "bucket", body.name,
               {"versioning": body.versioning, "encrypted": body.encrypted,
                "public_access_blocked": body.public_access_blocked})
    return BucketOut(**ctx.changed(), **_bucket(bucket).model_dump())


@router.patch("/buckets/{name}", response_model=BucketOut)
def update_bucket(name: BucketPath, body: BucketUpdate, ctx: WriteStorage):
    ctx.allowed_on(STORAGE, f"bucket:{name}")
    ctx.require_mock()
    if not body.model_fields_set:
        raise unprocessable("nothing to change")
    with atomic(ctx.db):
        bucket = ctx.db.get(CloudBucket, name, with_for_update=True)
        if bucket is None:
            raise not_found("bucket")
        changed: dict = {}
        for field in ("versioning", "encrypted", "public_access_blocked"):
            new = getattr(body, field)
            if new is not None and new != getattr(bucket, field):
                changed[field] = [getattr(bucket, field), new]
                setattr(bucket, field, new)
        if changed:
            record(ctx.db, ctx.user, "bucket.update", "bucket", name,
                   {"changed": sorted(changed), **changed})
    return BucketOut(**ctx.changed(), **_bucket(bucket).model_dump())


@router.delete("/buckets/{name}", response_model=BucketOut)
def delete_bucket(name: BucketPath, ctx: WriteStorage, force: bool = False):
    ctx.allowed_on(STORAGE, f"bucket:{name}")
    ctx.require_mock()
    with atomic(ctx.db):
        bucket = ctx.db.get(CloudBucket, name, with_for_update=True)
        if bucket is None:
            raise not_found("bucket")
        if bucket.object_count > 0 and not force:
            raise conflict(f"the bucket holds {bucket.object_count} objects; "
                           "pass ?force=true to delete it with them")
        out = _bucket(bucket)
        ctx.db.delete(bucket)
        record(ctx.db, ctx.user, "bucket.delete", "bucket", name,
               {"objects": bucket.object_count, "forced": force})
    return BucketOut(**ctx.changed(), **out.model_dump())
