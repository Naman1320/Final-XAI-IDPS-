"""IAM: users, their roles and groups, and their effective permissions."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from soc.api import security
from soc.api.auth import mfa_required
from soc.api.common import Cursor, Limit, Page, audit, get_or_404, paginate
from soc.api.db import get_db
from soc.api.iam import engine, util
from soc.api.iam.deps import require_permission, require_write
from soc.api.iam.groups import Ref
from soc.api.models import (
    Action,
    AssistantConversation,
    Case,
    CaseNote,
    IamGroup,
    IamGroupMember,
    IamPolicyAttachment,
    IamRole,
    IamUserRole,
    LoginHistory,
    Role,
    User,
)
from soc.api.routes.admin import (
    _LAST_ADMIN,
    Password,
    Username,
    _would_remove_last_admin,
)
from soc.api.security import PasswordPolicyError

router = APIRouter(prefix="/iam", tags=["iam"])


class UserItem(BaseModel):
    id: int
    username: str
    role: Role  # the legacy role
    disabled: bool
    created_at: datetime
    mfa_enabled: bool
    last_login: datetime | None
    roles: list[Ref]
    groups: list[Ref]


class UserDetail(UserItem):
    mfa_required: bool
    sso_linked: bool


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Username
    password: Password
    role: Role = Role.ANALYST
    role_ids: util.UniqueIds = []
    group_ids: util.UniqueIds = []


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    role_ids: util.UniqueIds | None = None
    group_ids: util.UniqueIds | None = None
    disabled: bool | None = None


class PolicyRef(BaseModel):
    id: int
    name: str
    effect: str


class EffectiveOut(BaseModel):
    user_id: int
    username: str
    legacy_role: Role
    all_access: bool
    permissions: list[str]
    denied: list[str]  # granted by a role or allow policy, then removed by a deny policy
    roles: list[Ref]  # every role that applies: direct, through groups, and the system role
    groups: list[Ref]
    policies: list[PolicyRef]  # enabled policies that apply


def _items(db: Session, users: list[User]) -> list[UserItem]:
    ids = [u.id for u in users]
    last = dict(db.execute(select(LoginHistory.user_id, func.max(LoginHistory.at))
                           .where(LoginHistory.user_id.in_(ids), LoginHistory.success.is_(True))
                           .group_by(LoginHistory.user_id)).all())
    roles: dict[int, list[Ref]] = {i: [] for i in ids}
    for uid, rid, name in db.execute(
            select(IamUserRole.user_id, IamRole.id, IamRole.name)
            .join(IamRole, IamRole.id == IamUserRole.role_id)
            .where(IamUserRole.user_id.in_(ids)).order_by(IamRole.name)):
        roles[uid].append(Ref(id=rid, name=name))
    groups: dict[int, list[Ref]] = {i: [] for i in ids}
    for uid, gid, name in db.execute(
            select(IamGroupMember.user_id, IamGroup.id, IamGroup.name)
            .join(IamGroup, IamGroup.id == IamGroupMember.group_id)
            .where(IamGroupMember.user_id.in_(ids)).order_by(IamGroup.name)):
        groups[uid].append(Ref(id=gid, name=name))
    return [UserItem(id=u.id, username=u.username, role=u.role, disabled=u.disabled,
                     created_at=u.created_at, mfa_enabled=u.mfa_enabled, last_login=last.get(u.id),
                     roles=roles[u.id], groups=groups[u.id]) for u in users]


def _detail(db: Session, request: Request, user: User) -> UserDetail:
    item = _items(db, [user])[0]
    return UserDetail(**item.model_dump(),
                      mfa_required=mfa_required(user, request.app.state.settings),
                      sso_linked=user.oidc_subject is not None)


@router.get("/users", response_model=Page[UserItem])
def list_users(user: Annotated[User, Depends(require_permission("iam.users.view"))],
               db: Annotated[Session, Depends(get_db)],
               q: Annotated[str | None, Query(max_length=64, description="username contains")
                            ] = None,
               status: Literal["active", "disabled"] | None = None, role: Role | None = None,
               role_id: Annotated[int | None, Query(ge=1, le=2**62, description="holds this "
                                                    "role directly")] = None,
               group_id: Annotated[int | None, Query(ge=1, le=2**62)] = None,
               limit: Limit = 100, cursor: Cursor = None):
    query = select(User).order_by(User.id.desc()).limit(limit + 1)
    if q:
        query = query.where(User.username.ilike(util.like_pattern(q), escape="\\"))
    if status:
        query = query.where(User.disabled.is_(status == "disabled"))
    if role:
        query = query.where(User.role == role)
    if role_id is not None:
        query = query.where(User.id.in_(select(IamUserRole.user_id)
                                        .where(IamUserRole.role_id == role_id)))
    if group_id is not None:
        query = query.where(User.id.in_(select(IamGroupMember.user_id)
                                        .where(IamGroupMember.group_id == group_id)))
    if cursor:
        query = query.where(User.id < cursor)
    rows, nxt = paginate(list(db.scalars(query)), limit)
    return Page[UserItem](items=_items(db, rows), next_cursor=nxt)


@router.post("/users", response_model=UserDetail, status_code=201)
def create_user(body: UserCreate, request: Request,
                actor: Annotated[User, Depends(require_write("iam.users.write"))],
                db: Annotated[Session, Depends(get_db)]):
    held = util.actor_permissions(db, actor)
    if body.role == Role.ADMIN:
        util.require_legacy_admin(actor)
    else:
        legacy = db.scalar(select(IamRole.id).where(IamRole.system.is_(True),
                                                    IamRole.name == body.role.value))
        grants = engine.subject_grants(db, "role", legacy) if legacy else {"cloud.view"}
        util.must_hold(held, grants)
    for role in util.role_ids_checked(db, body.role_ids):
        util.must_hold(held, engine.subject_grants(db, "role", role.id))
    for group in util.group_ids_checked(db, body.group_ids):
        util.must_hold(held, engine.subject_grants(db, "group", group.id))
    if db.scalar(select(User.id).where(User.username == body.username)) is not None:
        raise HTTPException(409, f"user {body.username!r} already exists")
    try:  # the same password policy as every other way of setting a password
        password_hash = security.hash_password(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    user = User(username=body.username, password_hash=password_hash, role=body.role)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"user {body.username!r} already exists") from None
    db.add_all(IamUserRole(user_id=user.id, role_id=r) for r in body.role_ids)
    db.add_all(IamGroupMember(group_id=g, user_id=user.id) for g in body.group_ids)
    audit(db, actor, "iam_user_create", f"user:{user.username}",
          {"id": user.id, "role": body.role.value, "role_ids": body.role_ids,
           "group_ids": body.group_ids})
    db.commit()
    return _detail(db, request, user)


@router.get("/users/{user_id}", response_model=UserDetail)
def get_user(user_id: int, request: Request,
             actor: Annotated[User, Depends(require_permission("iam.users.view"))],
             db: Annotated[Session, Depends(get_db)]):
    return _detail(db, request, get_or_404(db, User, user_id, "user"))


@router.get("/users/{user_id}/effective-permissions", response_model=EffectiveOut)
def effective(user_id: int, actor: Annotated[User, Depends(require_permission("iam.users.view"))],
              db: Annotated[Session, Depends(get_db)]):
    user = get_or_404(db, User, user_id, "user")
    res = engine.resolve(db, user)
    perms = res.permissions()
    roles = db.execute(select(IamRole.id, IamRole.name).where(IamRole.id.in_(res.role_ids))
                       .order_by(IamRole.name)).all() if res.role_ids else []
    groups = db.execute(select(IamGroup.id, IamGroup.name).where(IamGroup.id.in_(res.group_ids))
                        .order_by(IamGroup.name)).all() if res.group_ids else []
    return EffectiveOut(
        user_id=user.id, username=user.username, legacy_role=user.role,
        all_access=res.all_access, permissions=sorted(perms),
        denied=sorted(res.granted_before_deny() - perms),
        roles=[Ref(id=i, name=n) for i, n in roles], groups=[Ref(id=i, name=n) for i, n in groups],
        policies=[PolicyRef(id=p.id, name=p.name, effect=p.effect)
                  for p in sorted(res.allow + res.deny, key=lambda p: p.id)])


def _manage_target(db: Session, actor: User, user_id: int, message: str) -> tuple[User, set[str]]:
    """The user to change, after the rules every write to a user shares."""
    user = get_or_404(db, User, user_id, "user")
    util.must_not_be_self(actor, user.id, message)
    held = util.actor_permissions(db, actor)
    if user.role == Role.ADMIN:
        util.require_legacy_admin(actor)
    util.must_outrank(db, held, user)
    return user, held


@router.patch("/users/{user_id}", response_model=UserDetail)
def update_user(user_id: int, body: UserUpdate, request: Request,
                actor: Annotated[User, Depends(require_write("iam.users.write"))],
                db: Annotated[Session, Depends(get_db)]):
    if not body.model_fields_set:
        raise HTTPException(422, "nothing to change")
    user, held = _manage_target(db, actor, user_id,
                                "you cannot change your own roles, groups, legacy role or state")
    changes: dict = {}
    if body.role is not None and body.role != user.role:
        if body.role == Role.ADMIN:
            util.require_legacy_admin(actor)
        elif _would_remove_last_admin(db, user):
            raise HTTPException(409, _LAST_ADMIN)
        changes["role"] = [user.role.value, body.role.value]
        user.role = body.role
    if body.role_ids is not None:
        roles = util.role_ids_checked(db, body.role_ids)
        old = set(db.scalars(select(IamUserRole.role_id).where(IamUserRole.user_id == user.id)))
        new = set(body.role_ids)
        for role in roles:
            if role.id not in old:
                util.must_hold(held, engine.subject_grants(db, "role", role.id))
        for rid in old - new:
            util.must_hold(held, engine.subject_denies(db, "role", rid), "lift restrictions on")
        if old != new:
            db.execute(delete(IamUserRole).where(IamUserRole.user_id == user.id))
            db.add_all(IamUserRole(user_id=user.id, role_id=r) for r in new)
            changes["roles"] = {"added": sorted(new - old), "removed": sorted(old - new)}
    if body.group_ids is not None:
        util.group_ids_checked(db, body.group_ids)
        old = set(db.scalars(select(IamGroupMember.group_id)
                             .where(IamGroupMember.user_id == user.id)))
        new = set(body.group_ids)
        for gid in new - old:
            util.must_hold(held, engine.subject_grants(db, "group", gid))
        for gid in old - new:
            util.must_hold(held, engine.subject_denies(db, "group", gid), "lift restrictions on")
        if old != new:
            db.execute(delete(IamGroupMember).where(IamGroupMember.user_id == user.id))
            db.add_all(IamGroupMember(group_id=g, user_id=user.id) for g in new)
            changes["groups"] = {"added": sorted(new - old), "removed": sorted(old - new)}
    if body.disabled is not None and body.disabled != user.disabled:
        if body.disabled and _would_remove_last_admin(db, user):
            raise HTTPException(409, _LAST_ADMIN)
        user.disabled = body.disabled
        changes["disabled"] = body.disabled
    if changes:
        user.token_version += 1  # every existing session of this user ends
        audit(db, actor, "iam_user_update", f"user:{user.username}", {"id": user.id, **changes})
    db.commit()
    return _detail(db, request, user)


def _set_active(user_id: int, request: Request, actor: User, db: Session,
                active: bool) -> UserDetail:
    user, _ = _manage_target(db, actor, user_id, "you cannot deactivate or activate yourself")
    if user.disabled == (not active):
        return _detail(db, request, user)  # already so: nothing to do, nothing to audit
    if not active and _would_remove_last_admin(db, user):
        raise HTTPException(409, _LAST_ADMIN)
    user.disabled = not active
    user.token_version += 1
    audit(db, actor, "iam_user_activate" if active else "iam_user_deactivate",
          f"user:{user.username}", {"id": user.id})
    db.commit()
    return _detail(db, request, user)


@router.post("/users/{user_id}/deactivate", response_model=UserDetail)
def deactivate_user(user_id: int, request: Request,
                    actor: Annotated[User, Depends(require_write("iam.users.write"))],
                    db: Annotated[Session, Depends(get_db)]):
    return _set_active(user_id, request, actor, db, False)


@router.post("/users/{user_id}/activate", response_model=UserDetail)
def activate_user(user_id: int, request: Request,
                  actor: Annotated[User, Depends(require_write("iam.users.write"))],
                  db: Annotated[Session, Depends(get_db)]):
    return _set_active(user_id, request, actor, db, True)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, actor: Annotated[User, Depends(require_write("iam.users.delete"))],
                db: Annotated[Session, Depends(get_db)]):
    """Delete the user for good. What referred to them is kept where it is history (cases, notes,
    actions: the reference becomes empty; the audit log and the login history keep the
    username) and removed where it is theirs alone (their assistant conversations, memberships,
    role assignments and policy attachments)."""
    user, _ = _manage_target(db, actor, user_id, "you cannot delete yourself")
    if _would_remove_last_admin(db, user):
        raise HTTPException(409, _LAST_ADMIN)
    detached = 0
    for model, column in ((Case, Case.created_by_id), (CaseNote, CaseNote.author_id),
                          (Action, Action.proposed_by_user_id), (Action, Action.decided_by_id),
                          (LoginHistory, LoginHistory.user_id)):
        detached += db.execute(update(model).where(column == user.id).values({column.key: None})
                               .execution_options(synchronize_session=False)).rowcount
    conversations = db.execute(delete(AssistantConversation)
                               .where(AssistantConversation.user_id == user.id)).rowcount
    for model, column in ((IamGroupMember, IamGroupMember.user_id),
                          (IamUserRole, IamUserRole.user_id)):
        db.execute(delete(model).where(column == user.id))
    db.execute(delete(IamPolicyAttachment).where(IamPolicyAttachment.subject_type == "user",
                                                 IamPolicyAttachment.subject_id == user.id))
    audit(db, actor, "iam_user_delete", f"user:{user.username}",
          {"id": user.id, "role": user.role.value, "references_cleared": detached,
           "conversations_deleted": conversations})
    db.delete(user)
    db.commit()
