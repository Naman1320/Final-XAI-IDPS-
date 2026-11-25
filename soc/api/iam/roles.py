"""IAM: the permission catalog and roles."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from soc.api.auth import current_user
from soc.api.common import Cursor, Limit, Page, audit, get_or_404, paginate
from soc.api.db import get_db
from soc.api.iam import engine, util
from soc.api.iam.catalog import CATALOG
from soc.api.iam.deps import require_permission, require_write
from soc.api.models import (
    IamGroupRole,
    IamPolicyAttachment,
    IamRole,
    IamRolePermission,
    IamUserRole,
    Role,
    User,
    utcnow,
)

router = APIRouter(prefix="/iam", tags=["iam"])


class PermissionOut(BaseModel):
    name: str
    description: str


class PermissionGroupOut(BaseModel):
    key: str
    title: str
    permissions: list[PermissionOut]


class CatalogOut(BaseModel):
    groups: list[PermissionGroupOut]


class MyPermissions(BaseModel):
    username: str
    role: Role
    all_access: bool  # a legacy administrator: every permission, whatever the policies say
    permissions: list[str]


class RoleOut(BaseModel):
    id: int
    name: str
    description: str
    system: bool
    permissions: list[str]
    user_count: int  # users the role is assigned to directly
    group_count: int
    created_at: datetime
    updated_at: datetime


class RoleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: util.Name
    description: util.Description = ""
    permissions: util.PermissionList = []


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: util.Name | None = None
    description: util.Description | None = None
    permissions: util.PermissionList | None = None


def role_out(db: Session, role: IamRole) -> RoleOut:
    return roles_out(db, [role])[0]


def roles_out(db: Session, roles: list[IamRole]) -> list[RoleOut]:
    ids = [r.id for r in roles]
    perms = engine.role_permissions(db, ids)
    users = dict(db.execute(select(IamUserRole.role_id, func.count())
                            .where(IamUserRole.role_id.in_(ids)).group_by(IamUserRole.role_id)).all())
    groups = dict(db.execute(select(IamGroupRole.role_id, func.count())
                             .where(IamGroupRole.role_id.in_(ids)).group_by(IamGroupRole.role_id)).all())
    return [RoleOut(id=r.id, name=r.name, description=r.description, system=r.system,
                    permissions=sorted(perms.get(r.id, ())), user_count=users.get(r.id, 0),
                    group_count=groups.get(r.id, 0), created_at=r.created_at,
                    updated_at=r.updated_at) for r in roles]


@router.get("/permissions", response_model=CatalogOut)
def permission_catalog(user: Annotated[User, Depends(require_permission("iam.roles.view"))]):
    return CatalogOut(groups=[PermissionGroupOut(**g) for g in CATALOG])


@router.get("/me/permissions", response_model=MyPermissions)
def my_permissions(user: Annotated[User, Depends(current_user)],
                   db: Annotated[Session, Depends(get_db)]):
    res = engine.resolve(db, user)
    return MyPermissions(username=user.username, role=user.role, all_access=res.all_access,
                         permissions=sorted(res.permissions()))


@router.get("/roles", response_model=Page[RoleOut])
def list_roles(user: Annotated[User, Depends(require_permission("iam.roles.view"))],
               db: Annotated[Session, Depends(get_db)],
               q: Annotated[str | None, Query(max_length=48, description="name contains")] = None,
               system: bool | None = None, limit: Limit = 100, cursor: Cursor = None):
    query = select(IamRole).order_by(IamRole.id.desc()).limit(limit + 1)
    if q:
        query = query.where(IamRole.name.ilike(util.like_pattern(q), escape="\\"))
    if system is not None:
        query = query.where(IamRole.system.is_(system))
    if cursor:
        query = query.where(IamRole.id < cursor)
    rows, nxt = paginate(list(db.scalars(query)), limit)
    return Page[RoleOut](items=roles_out(db, rows), next_cursor=nxt)


@router.post("/roles", response_model=RoleOut, status_code=201)
def create_role(body: RoleCreate,
                actor: Annotated[User, Depends(require_write("iam.roles.write"))],
                db: Annotated[Session, Depends(get_db)]):
    util.check_name_free(db, IamRole, body.name)
    util.must_hold(util.actor_permissions(db, actor), set(body.permissions))
    role = IamRole(name=body.name, description=body.description, system=False)
    db.add(role)
    db.flush()
    db.add_all(IamRolePermission(role_id=role.id, permission=p) for p in body.permissions)
    audit(db, actor, "iam_role_create", f"role:{role.name}",
          {"id": role.id, "permissions": sorted(body.permissions)})
    db.commit()
    return role_out(db, role)


@router.get("/roles/{role_id}", response_model=RoleOut)
def get_role(role_id: int, user: Annotated[User, Depends(require_permission("iam.roles.view"))],
             db: Annotated[Session, Depends(get_db)]):
    return role_out(db, get_or_404(db, IamRole, role_id, "role"))


def _editable(role: IamRole) -> None:
    if role.system:
        raise HTTPException(409, "system roles cannot be changed or deleted")


@router.patch("/roles/{role_id}", response_model=RoleOut)
def update_role(role_id: int, body: RoleUpdate,
                actor: Annotated[User, Depends(require_write("iam.roles.write"))],
                db: Annotated[Session, Depends(get_db)]):
    role = get_or_404(db, IamRole, role_id, "role")
    _editable(role)
    if not body.model_fields_set:
        raise HTTPException(422, "nothing to change")
    changes: dict = {}
    if body.name is not None and body.name != role.name:
        util.check_name_free(db, IamRole, body.name, role.id)
        changes["name"] = [role.name, body.name]
        role.name = body.name
    if body.description is not None and body.description != role.description:
        role.description = body.description
        changes["description"] = True
    if body.permissions is not None:
        old = engine.role_permissions(db, [role.id])[role.id]
        new = set(body.permissions)
        util.must_hold(util.actor_permissions(db, actor), new - old)
        if new != old:
            db.execute(delete(IamRolePermission).where(IamRolePermission.role_id == role.id))
            db.add_all(IamRolePermission(role_id=role.id, permission=p) for p in new)
            changes["permissions"] = {"added": sorted(new - old), "removed": sorted(old - new)}
            util.bump_tokens(db, util.users_of_role(db, role), actor)
    if changes:
        role.updated_at = utcnow()
        audit(db, actor, "iam_role_update", f"role:{role.name}", {"id": role.id, **changes})
    db.commit()
    return role_out(db, role)


@router.delete("/roles/{role_id}", status_code=204)
def delete_role(role_id: int, actor: Annotated[User, Depends(require_write("iam.roles.write"))],
                db: Annotated[Session, Depends(get_db)]):
    role = get_or_404(db, IamRole, role_id, "role")
    _editable(role)
    # Deleting a role also detaches the policies attached to it: a deny among them is lifted.
    util.must_hold(util.actor_permissions(db, actor),
                   engine.subject_denies(db, "role", role.id), "lift restrictions on")
    affected = util.users_of_role(db, role)
    holders = db.scalar(select(func.count()).select_from(IamUserRole)
                        .where(IamUserRole.role_id == role.id)) or 0
    for model, column in ((IamRolePermission, IamRolePermission.role_id),
                          (IamUserRole, IamUserRole.role_id), (IamGroupRole, IamGroupRole.role_id)):
        db.execute(delete(model).where(column == role.id))
    db.execute(delete(IamPolicyAttachment).where(IamPolicyAttachment.subject_type == "role",
                                                 IamPolicyAttachment.subject_id == role.id))
    util.bump_tokens(db, affected, actor)
    audit(db, actor, "iam_role_delete", f"role:{role.name}",
          {"id": role.id, "users": holders, "users_affected": len(affected)})
    db.delete(role)
    db.commit()

