"""IAM: groups."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from soc.api.common import Cursor, Limit, Page, audit, get_or_404, paginate
from soc.api.db import get_db
from soc.api.iam import engine, util
from soc.api.iam.deps import require_permission, require_write
from soc.api.models import (
    IamGroup,
    IamGroupMember,
    IamGroupRole,
    IamPolicyAttachment,
    IamRole,
    User,
)

router = APIRouter(prefix="/iam", tags=["iam"])


class Ref(BaseModel):
    id: int
    name: str


class GroupOut(BaseModel):
    id: int
    name: str
    description: str
    created_at: datetime
    member_count: int
    role_count: int


class GroupDetail(GroupOut):
    members: list[Ref]
    roles: list[Ref]


class GroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: util.Name
    description: util.Description = ""


class GroupUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: util.Name | None = None
    description: util.Description | None = None


class MembersSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_ids: util.UniqueIds


class RolesSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_ids: util.UniqueIds


def groups_out(db: Session, groups: list[IamGroup]) -> list[GroupOut]:
    ids = [g.id for g in groups]
    members = dict(db.execute(select(IamGroupMember.group_id, func.count())
                              .where(IamGroupMember.group_id.in_(ids))
                              .group_by(IamGroupMember.group_id)).all())
    roles = dict(db.execute(select(IamGroupRole.group_id, func.count())
                            .where(IamGroupRole.group_id.in_(ids))
                            .group_by(IamGroupRole.group_id)).all())
    return [GroupOut(id=g.id, name=g.name, description=g.description, created_at=g.created_at,
                     member_count=members.get(g.id, 0), role_count=roles.get(g.id, 0))
            for g in groups]


def group_detail(db: Session, group: IamGroup) -> GroupDetail:
    base = groups_out(db, [group])[0]
    members = db.execute(select(User.id, User.username).join(
        IamGroupMember, IamGroupMember.user_id == User.id)
        .where(IamGroupMember.group_id == group.id).order_by(User.username)).all()
    roles = db.execute(select(IamRole.id, IamRole.name).join(
        IamGroupRole, IamGroupRole.role_id == IamRole.id)
        .where(IamGroupRole.group_id == group.id).order_by(IamRole.name)).all()
    return GroupDetail(**base.model_dump(), members=[Ref(id=i, name=n) for i, n in members],
                       roles=[Ref(id=i, name=n) for i, n in roles])


@router.get("/groups", response_model=Page[GroupOut])
def list_groups(user: Annotated[User, Depends(require_permission("iam.groups.view"))],
                db: Annotated[Session, Depends(get_db)],
                q: Annotated[str | None, Query(max_length=48, description="name contains")] = None,
                member_id: Annotated[int | None, Query(ge=1, le=2**62)] = None,
                limit: Limit = 100, cursor: Cursor = None):
    query = select(IamGroup).order_by(IamGroup.id.desc()).limit(limit + 1)
    if q:
        query = query.where(IamGroup.name.ilike(util.like_pattern(q), escape="\\"))
    if member_id is not None:
        query = query.where(IamGroup.id.in_(
            select(IamGroupMember.group_id).where(IamGroupMember.user_id == member_id)))
    if cursor:
        query = query.where(IamGroup.id < cursor)
    rows, nxt = paginate(list(db.scalars(query)), limit)
    return Page[GroupOut](items=groups_out(db, rows), next_cursor=nxt)


@router.post("/groups", response_model=GroupDetail, status_code=201)
def create_group(body: GroupCreate,
                 actor: Annotated[User, Depends(require_write("iam.groups.write"))],
                 db: Annotated[Session, Depends(get_db)]):
    util.check_name_free(db, IamGroup, body.name)
    group = IamGroup(name=body.name, description=body.description)
    db.add(group)
    db.flush()
    audit(db, actor, "iam_group_create", f"group:{group.name}", {"id": group.id})
    db.commit()
    return group_detail(db, group)


@router.get("/groups/{group_id}", response_model=GroupDetail)
def get_group(group_id: int, user: Annotated[User, Depends(require_permission("iam.groups.view"))],
              db: Annotated[Session, Depends(get_db)]):
    return group_detail(db, get_or_404(db, IamGroup, group_id, "group"))


@router.patch("/groups/{group_id}", response_model=GroupDetail)
def update_group(group_id: int, body: GroupUpdate,
                 actor: Annotated[User, Depends(require_write("iam.groups.write"))],
                 db: Annotated[Session, Depends(get_db)]):
    group = get_or_404(db, IamGroup, group_id, "group")
    if not body.model_fields_set:
        raise HTTPException(422, "nothing to change")
    changes: dict = {}
    if body.name is not None and body.name != group.name:
        util.check_name_free(db, IamGroup, body.name, group.id)
        changes["name"] = [group.name, body.name]
        group.name = body.name
    if body.description is not None and body.description != group.description:
        group.description = body.description
        changes["description"] = True
    if changes:
        audit(db, actor, "iam_group_update", f"group:{group.name}", {"id": group.id, **changes})
    db.commit()
    return group_detail(db, group)


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(group_id: int,
                 actor: Annotated[User, Depends(require_write("iam.groups.write"))],
                 db: Annotated[Session, Depends(get_db)]):
    group = get_or_404(db, IamGroup, group_id, "group")
    util.must_hold(util.actor_permissions(db, actor),
                   engine.subject_denies(db, "group", group.id), "lift restrictions on")
    affected = util.users_of_group(db, group.id)
    for model, column in ((IamGroupMember, IamGroupMember.group_id),
                          (IamGroupRole, IamGroupRole.group_id)):
        db.execute(delete(model).where(column == group.id))
    db.execute(delete(IamPolicyAttachment).where(IamPolicyAttachment.subject_type == "group",
                                                 IamPolicyAttachment.subject_id == group.id))
    util.bump_tokens(db, affected, actor)
    audit(db, actor, "iam_group_delete", f"group:{group.name}",
          {"id": group.id, "members": len(affected)})
    db.delete(group)
    db.commit()


@router.put("/groups/{group_id}/members", response_model=GroupDetail)
def set_members(group_id: int, body: MembersSet,
                actor: Annotated[User, Depends(require_write("iam.groups.write"))],
                db: Annotated[Session, Depends(get_db)]):
    """Replace the member list. Only the users added or removed are touched."""
    group = get_or_404(db, IamGroup, group_id, "group")
    util.user_ids_checked(db, body.user_ids)
    old = util.users_of_group(db, group.id)
    new = set(body.user_ids)
    added, removed = new - old, old - new
    if actor.id in added | removed:
        raise HTTPException(403, "you cannot change your own group membership")
    held = util.actor_permissions(db, actor)
    if added:
        util.must_hold(held, engine.subject_grants(db, "group", group.id))
    if removed:  # leaving a group that carries a deny policy lifts that restriction
        util.must_hold(held, engine.subject_denies(db, "group", group.id), "lift restrictions on")
    for uid in removed:
        db.execute(delete(IamGroupMember).where(IamGroupMember.group_id == group.id,
                                                IamGroupMember.user_id == uid))
    db.add_all(IamGroupMember(group_id=group.id, user_id=uid) for uid in added)
    if added or removed:
        # Each member's permissions are read live; the version bump ends their sessions too.
        util.bump_tokens(db, added | removed)
        audit(db, actor, "iam_group_members", f"group:{group.name}",
              {"id": group.id, "added": sorted(added), "removed": sorted(removed)})
    db.commit()
    return group_detail(db, group)


@router.put("/groups/{group_id}/roles", response_model=GroupDetail)
def set_group_roles(group_id: int, body: RolesSet,
                    actor: Annotated[User, Depends(require_write("iam.groups.write"))],
                    db: Annotated[Session, Depends(get_db)]):
    group = get_or_404(db, IamGroup, group_id, "group")
    util.role_ids_checked(db, body.role_ids)
    old = set(db.scalars(select(IamGroupRole.role_id).where(IamGroupRole.group_id == group.id)))
    new = set(body.role_ids)
    added, removed = new - old, old - new
    held = util.actor_permissions(db, actor)
    for rid in added:
        util.must_hold(held, engine.subject_grants(db, "role", rid))
    for rid in removed:
        util.must_hold(held, engine.subject_denies(db, "role", rid), "lift restrictions on")
    if removed:
        db.execute(delete(IamGroupRole).where(IamGroupRole.group_id == group.id,
                                              IamGroupRole.role_id.in_(removed)))
    db.add_all(IamGroupRole(group_id=group.id, role_id=rid) for rid in added)
    if added or removed:
        util.bump_tokens(db, util.users_of_group(db, group.id), actor)
        audit(db, actor, "iam_group_roles", f"group:{group.name}",
              {"id": group.id, "added": sorted(added), "removed": sorted(removed)})
    db.commit()
    return group_detail(db, group)
