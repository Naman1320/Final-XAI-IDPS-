"""Shared pieces of the IAM routes: field types, escalation guards, session invalidation."""

from typing import Annotated

from fastapi import HTTPException, status
from pydantic import AfterValidator, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from soc.api.common import plain_text
from soc.api.db import serialize_writes
from soc.api.iam import engine
from soc.api.iam.catalog import ALL_PERMISSIONS, expand, valid_pattern
from soc.api.models import (
    IamGroup,
    IamGroupMember,
    IamGroupRole,
    IamPolicyAttachment,
    IamRole,
    IamUserRole,
    Role,
    User,
)

# --- field types ------------------------------------------------------------------------------

NAME_PATTERN = r"^[A-Za-z0-9 _-]+$"


def _trimmed(value: str) -> str:
    if value != value.strip():
        raise ValueError("must not start or end with a space")
    return plain_text(value)


Name = Annotated[str, Field(min_length=3, max_length=48, pattern=NAME_PATTERN),
                 AfterValidator(_trimmed)]
Description = Annotated[str, Field(max_length=255), AfterValidator(plain_text)]
IdList = Annotated[list[Annotated[int, Field(ge=1, le=2**62)]], Field(max_length=1000)]


def _unique_ids(ids: list[int]) -> list[int]:
    if len(set(ids)) != len(ids):
        raise ValueError("ids must not repeat")
    return ids


UniqueIds = Annotated[IdList, AfterValidator(_unique_ids)]


def _catalog_names(values: list[str]) -> list[str]:
    bad = [v for v in values if v not in ALL_PERMISSIONS]
    if bad:
        raise ValueError(f"unknown permission: {bad[0][:64]}")
    if len(set(values)) != len(values):
        raise ValueError("permissions must not repeat")
    return values


PermissionList = Annotated[list[Annotated[str, Field(max_length=64)]],
                           Field(max_length=len(ALL_PERMISSIONS)), AfterValidator(_catalog_names)]


def _patterns(values: list[str]) -> list[str]:
    if not values:
        raise ValueError("at least one permission is needed")
    bad = [v for v in values if not valid_pattern(v)]
    if bad:
        raise ValueError(f"not a permission or pattern in the catalog: {bad[0][:64]}")
    return list(dict.fromkeys(values))


PatternList = Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=50),
                        AfterValidator(_patterns)]


def _resources(values: list[str]) -> list[str]:
    for v in values:
        plain_text(v)
        if not v:
            raise ValueError("a resource pattern must not be empty")
    return list(dict.fromkeys(values))


ResourceList = Annotated[list[Annotated[str, Field(max_length=128)]],
                         Field(min_length=1, max_length=50), AfterValidator(_resources)]


def like_pattern(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# --- name uniqueness -------------------------------------------------------------------------

def check_name_free(db: Session, model, name: str, ignore_id: int | None = None) -> None:
    """409 if another row has this name (compared case-insensitively: "Ops" and "ops" clash)."""
    serialize_writes(db, model)
    query = select(model.id).where(func.lower(model.name) == name.lower())
    if ignore_id is not None:
        query = query.where(model.id != ignore_id)
    if db.scalar(query) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"the name {name!r} is already used")


# --- escalation guards -----------------------------------------------------------------------

def actor_permissions(db: Session, actor: User) -> set[str]:
    # Delegating a role or changing a policy can affect every resource.
    res = engine.resolve(db, actor)
    held = res.permissions()
    for rule in res.deny:
        held -= expand(rule.permissions)
    return held


def must_hold(held: set[str], perms: set[str], what: str = "grant") -> None:
    """403 unless the actor holds every permission in `perms` (no granting, or lifting a
    restriction on, what you do not hold yourself)."""
    missing = sorted(set(perms) - held)
    if missing:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"you cannot {what} permissions you do not hold: " + ", ".join(missing[:5])
            + (" ..." if len(missing) > 5 else ""))


def must_outrank(db: Session, held: set[str], target: User) -> None:
    """403 if the target holds a permission the actor does not (a lesser user must not be able
    to deactivate, edit or delete a more powerful one)."""
    res = engine.resolve(db, target)
    possible = res.permissions()
    for rule in res.allow:
        possible |= expand(rule.permissions)
    if not possible <= held:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "that user holds permissions you do not hold")


def must_not_be_self(actor: User, target_id: int, message: str) -> None:
    if actor.id == target_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, message)


def require_legacy_admin(actor: User) -> None:
    if actor.role != Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "only an administrator can manage administrator accounts")


def role_ids_checked(db: Session, ids: list[int]) -> list[IamRole]:
    roles = list(db.scalars(select(IamRole).where(IamRole.id.in_(ids)))) if ids else []
    if len(roles) != len(set(ids)):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown role id")
    return roles


def group_ids_checked(db: Session, ids: list[int]) -> list[IamGroup]:
    groups = list(db.scalars(select(IamGroup).where(IamGroup.id.in_(ids)))) if ids else []
    if len(groups) != len(set(ids)):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown group id")
    return groups


def user_ids_checked(db: Session, ids: list[int]) -> list[User]:
    users = list(db.scalars(select(User).where(User.id.in_(ids)))) if ids else []
    if len(users) != len(set(ids)):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown user id")
    return users


# --- who is affected (to end their sessions) -------------------------------------------------

def users_of_group(db: Session, group_id: int) -> set[int]:
    return set(db.scalars(select(IamGroupMember.user_id)
                          .where(IamGroupMember.group_id == group_id)))


def users_of_role(db: Session, role: IamRole) -> set[int]:
    ids = set(db.scalars(select(IamUserRole.user_id).where(IamUserRole.role_id == role.id)))
    for gid in db.scalars(select(IamGroupRole.group_id).where(IamGroupRole.role_id == role.id)):
        ids |= users_of_group(db, gid)
    if role.system:  # held by everyone with the legacy role of the same name
        try:
            legacy = Role(role.name)
        except ValueError:
            legacy = None
        if legacy is not None:
            ids |= set(db.scalars(select(User.id).where(User.role == legacy)))
    return ids


def users_of_subject(db: Session, subject_type: str, subject_id: int) -> set[int]:
    if subject_type == "user":
        return {subject_id}
    if subject_type == "group":
        return users_of_group(db, subject_id)
    role = db.get(IamRole, subject_id)
    return users_of_role(db, role) if role else set()


def users_of_policy(db: Session, policy_id: int) -> set[int]:
    ids: set[int] = set()
    for stype, sid in db.execute(select(IamPolicyAttachment.subject_type,
                                        IamPolicyAttachment.subject_id)
                                 .where(IamPolicyAttachment.policy_id == policy_id)):
        ids |= users_of_subject(db, stype, sid)
    return ids


def bump_tokens(db: Session, user_ids: set[int], actor: User | None = None) -> None:
    """End the sessions of these users (token_version + 1). The acting user is left out of an
    indirect change (editing a role they hold) so they are not logged out by their own click;
    direct changes to a user bump that user explicitly in the route."""
    ids = set(user_ids) - ({actor.id} if actor is not None else set())
    if ids:
        db.execute(update(User).where(User.id.in_(ids))
                   .values(token_version=User.token_version + 1)
                   .execution_options(synchronize_session=False))
