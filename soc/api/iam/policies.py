"""IAM: allow and deny policies."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from soc.api.common import Cursor, Limit, Page, audit, get_or_404, paginate
from soc.api.db import get_db
from soc.api.iam import engine, util
from soc.api.iam.deps import require_permission, require_write
from soc.api.models import (
    IamGroup,
    IamPolicy,
    IamPolicyAttachment,
    IamRole,
    User,
)

router = APIRouter(prefix="/iam", tags=["iam"])

Effect = Literal["allow", "deny"]
SubjectType = Literal["user", "group", "role"]


class AttachmentOut(BaseModel):
    subject_type: SubjectType
    subject_id: int
    subject_name: str | None = None  # None: the subject no longer exists


class PolicyOut(BaseModel):
    id: int
    name: str
    description: str
    effect: Effect
    permissions: list[str]
    resources: list[str]
    disabled: bool
    created_at: datetime
    attachment_count: int


class PolicyDetail(PolicyOut):
    attachments: list[AttachmentOut]


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: util.Name
    description: util.Description = ""
    effect: Effect
    permissions: util.PatternList
    resources: util.ResourceList = ["*"]
    disabled: bool = False


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: util.Name | None = None
    description: util.Description | None = None
    effect: Effect | None = None
    permissions: util.PatternList | None = None
    resources: util.ResourceList | None = None
    disabled: bool | None = None


class AttachmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_type: SubjectType
    subject_id: Annotated[int, Field(ge=1, le=2**62)]


class AttachmentsSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attachments: Annotated[list[AttachmentIn], Field(max_length=200)]


def _attachments(db: Session, policy: IamPolicy) -> list[IamPolicyAttachment]:
    return list(db.scalars(select(IamPolicyAttachment)
                           .where(IamPolicyAttachment.policy_id == policy.id)
                           .order_by(IamPolicyAttachment.subject_type,
                                     IamPolicyAttachment.subject_id)))


def _subject_names(db: Session, attachments) -> dict[tuple[str, int], str]:
    names: dict[tuple[str, int], str] = {}
    for stype, model, column in (("user", User, User.username), ("group", IamGroup, IamGroup.name),
                                 ("role", IamRole, IamRole.name)):
        ids = [a.subject_id for a in attachments if a.subject_type == stype]
        if ids:
            for i, n in db.execute(select(model.id, column).where(model.id.in_(ids))):
                names[(stype, i)] = n
    return names


def policy_out(db: Session, policy: IamPolicy, detail: bool = False):
    att = _attachments(db, policy)
    base = {"id": policy.id, "name": policy.name, "description": policy.description,
            "effect": policy.effect, "permissions": list(policy.permissions),
            "resources": list(policy.resources), "disabled": policy.disabled,
            "created_at": policy.created_at, "attachment_count": len(att)}
    if not detail:
        return PolicyOut(**base)
    names = _subject_names(db, att)
    return PolicyDetail(**base, attachments=[
        AttachmentOut(subject_type=a.subject_type, subject_id=a.subject_id,
                      subject_name=names.get((a.subject_type, a.subject_id))) for a in att])


@router.get("/policies", response_model=Page[PolicyOut])
def list_policies(user: Annotated[User, Depends(require_permission("iam.policies.view"))],
                  db: Annotated[Session, Depends(get_db)],
                  q: Annotated[str | None, Query(max_length=48)] = None,
                  effect: Effect | None = None, disabled: bool | None = None,
                  limit: Limit = 100, cursor: Cursor = None):
    query = select(IamPolicy).order_by(IamPolicy.id.desc()).limit(limit + 1)
    if q:
        query = query.where(IamPolicy.name.ilike(util.like_pattern(q), escape="\\"))
    if effect:
        query = query.where(IamPolicy.effect == effect)
    if disabled is not None:
        query = query.where(IamPolicy.disabled.is_(disabled))
    if cursor:
        query = query.where(IamPolicy.id < cursor)
    rows, nxt = paginate(list(db.scalars(query)), limit)
    return Page[PolicyOut](items=[policy_out(db, p) for p in rows], next_cursor=nxt)


@router.post("/policies", response_model=PolicyDetail, status_code=201)
def create_policy(body: PolicyCreate,
                  actor: Annotated[User, Depends(require_write("iam.policies.write"))],
                  db: Annotated[Session, Depends(get_db)]):
    util.check_name_free(db, IamPolicy, body.name)
    policy = IamPolicy(name=body.name, description=body.description, effect=body.effect,
                       permissions=body.permissions, resources=body.resources,
                       disabled=body.disabled)
    util.must_hold(util.actor_permissions(db, actor), engine.policy_grants(policy))
    db.add(policy)
    db.flush()
    audit(db, actor, "iam_policy_create", f"policy:{policy.name}",
          {"id": policy.id, "effect": policy.effect, "permissions": policy.permissions,
           "resources": policy.resources})
    db.commit()
    return policy_out(db, policy, detail=True)


@router.get("/policies/{policy_id}", response_model=PolicyDetail)
def get_policy(policy_id: int,
               user: Annotated[User, Depends(require_permission("iam.policies.view"))],
               db: Annotated[Session, Depends(get_db)]):
    return policy_out(db, get_or_404(db, IamPolicy, policy_id, "policy"), detail=True)


@router.patch("/policies/{policy_id}", response_model=PolicyDetail)
def update_policy(policy_id: int, body: PolicyUpdate,
                  actor: Annotated[User, Depends(require_write("iam.policies.write"))],
                  db: Annotated[Session, Depends(get_db)]):
    policy = get_or_404(db, IamPolicy, policy_id, "policy")
    if not body.model_fields_set:
        raise HTTPException(422, "nothing to change")
    old_resources = set(policy.resources)
    old_grants, old_denies = engine.policy_grants(policy), engine.policy_denies(policy)
    held = util.actor_permissions(db, actor)  # before anything changes
    changes: dict = {}
    if body.name is not None and body.name != policy.name:
        util.check_name_free(db, IamPolicy, body.name, policy.id)
        changes["name"] = [policy.name, body.name]
    updated = {"name": body.name, "description": body.description, "effect": body.effect,
               "permissions": body.permissions, "resources": body.resources,
               "disabled": body.disabled}
    for key, value in updated.items():
        if value is not None and getattr(policy, key) != value:
            if key != "name":
                changes[key] = value if key != "description" else True
            setattr(policy, key, value)
    if changes:
        # Gaining power (a deny became an allow, wider patterns, enabled) or losing a
        # restriction (an allow became a deny, narrower patterns, disabled) both need the
        # permissions involved to be held by the actor.
        if "resources" in changes:
            # Changing resource globs can widen a grant or narrow a deny even
            # when the permission names stay the same.
            new_resources = set(policy.resources)
            if not (new_resources <= old_resources or "*" in old_resources):
                util.must_hold(held, engine.policy_grants(policy))
            if not (old_resources <= new_resources or "*" in new_resources):
                util.must_hold(held, old_denies, "lift restrictions on")
        util.must_hold(held, engine.policy_grants(policy) - old_grants)
        util.must_hold(held, old_denies - engine.policy_denies(policy), "lift restrictions on")
        if set(changes) - {"name", "description"}:
            util.bump_tokens(db, util.users_of_policy(db, policy.id), actor)
        audit(db, actor, "iam_policy_update", f"policy:{policy.name}",
              {"id": policy.id, **changes})
    db.commit()
    return policy_out(db, policy, detail=True)


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: int,
                  actor: Annotated[User, Depends(require_write("iam.policies.write"))],
                  db: Annotated[Session, Depends(get_db)]):
    policy = get_or_404(db, IamPolicy, policy_id, "policy")
    util.must_hold(util.actor_permissions(db, actor), engine.policy_denies(policy),
                   "lift restrictions on")
    affected = util.users_of_policy(db, policy.id)
    db.execute(delete(IamPolicyAttachment).where(IamPolicyAttachment.policy_id == policy.id))
    util.bump_tokens(db, affected, actor)
    audit(db, actor, "iam_policy_delete", f"policy:{policy.name}",
          {"id": policy.id, "users_affected": len(affected)})
    db.delete(policy)
    db.commit()


@router.put("/policies/{policy_id}/attachments", response_model=PolicyDetail)
def set_attachments(policy_id: int, body: AttachmentsSet,
                    actor: Annotated[User, Depends(require_write("iam.policies.write"))],
                    db: Annotated[Session, Depends(get_db)]):
    """Replace the subjects (users, groups, roles) the policy is attached to."""
    policy = get_or_404(db, IamPolicy, policy_id, "policy")
    new = {(a.subject_type, a.subject_id) for a in body.attachments}
    if len(new) != len(body.attachments):
        raise HTTPException(422, "an attachment is listed twice")
    for stype, model in (("user", User), ("group", IamGroup), ("role", IamRole)):
        ids = {i for t, i in new if t == stype}
        if ids and len(list(db.scalars(select(model.id).where(model.id.in_(ids))))) != len(ids):
            raise HTTPException(422, f"unknown {stype} id")
    old = {(a.subject_type, a.subject_id) for a in _attachments(db, policy)}
    added, removed = new - old, old - new
    if any(t == "user" and i == actor.id for t, i in added | removed):
        raise HTTPException(403, "you cannot change the policies attached to yourself")
    held = util.actor_permissions(db, actor)
    util.must_hold(held, engine.policy_grants(policy) if added else set())
    util.must_hold(held, engine.policy_denies(policy) if removed else set(),
                   "lift restrictions on")
    for stype, sid in removed:
        db.execute(delete(IamPolicyAttachment).where(
            IamPolicyAttachment.policy_id == policy.id, IamPolicyAttachment.subject_type == stype,
            IamPolicyAttachment.subject_id == sid))
    db.add_all(IamPolicyAttachment(policy_id=policy.id, subject_type=t, subject_id=i)
               for t, i in added)
    if added or removed:
        affected: set[int] = set()
        for stype, sid in added | removed:
            affected |= util.users_of_subject(db, stype, sid)
        util.bump_tokens(db, affected, actor)
        audit(db, actor, "iam_policy_attach", f"policy:{policy.name}",
              {"id": policy.id, "added": [f"{t}:{i}" for t, i in sorted(added)],
               "removed": [f"{t}:{i}" for t, i in sorted(removed)]})
    db.commit()
    return policy_out(db, policy, detail=True)
