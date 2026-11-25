"""Effective permissions. Nothing is cached: every call reads the database, so a change is in
force on the very next request.

Rules (docs/soc.md, "IAM and permissions"):
  * A user whose legacy role is ADMIN holds every permission and no policy can take one away
    (so a bad deny policy can never lock the SOC out of its own administration).
  * Anyone else holds the union of: the system role named like their legacy role ("analyst"),
    the custom roles assigned to them, the roles of their groups, and what ALLOW policies
    attached to them, their groups or their roles grant.
  * Then every permission matched by an enabled DENY policy attached to the user, one of their
    groups or one of their roles is removed. Deny always wins.
  * A policy applies to resources matching one of its globs (default "*"). A role grants a
    permission on every resource. A check without a resource asks about "*": only a policy whose
    globs include "*" applies to it, so a deny scoped to "i-123*" does not remove a permission
    from the user in general, only on those resources (`allows(..., resource="i-1234")`).
"""

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from soc.api.iam.catalog import ALL_PERMISSIONS, expand
from soc.api.models import (
    IamGroupMember,
    IamGroupRole,
    IamPolicy,
    IamPolicyAttachment,
    IamRole,
    IamRolePermission,
    IamUserRole,
    Role,
    User,
)

ADMIN_ROLE_NAME = "admin"  # the system role with every permission
ANY = "*"
# If the seeded system role rows are missing (a hand-edited database), the legacy analyst still
# gets this much.
_LEGACY_FALLBACK = {Role.ANALYST.value: frozenset({"cloud.view"})}


@dataclass
class PolicyRule:
    id: int
    name: str
    effect: str
    permissions: list[str]
    resources: list[str]

    def covers(self, permission: str, resource: str) -> bool:
        return (any(fnmatchcase(permission, p) for p in self.permissions)
                and resource_matches(self.resources, resource))


def resource_matches(patterns: list[str], resource: str) -> bool:
    if resource == ANY:  # "no particular resource": only match-everything globs apply
        return any(p and set(p) == {"*"} for p in patterns)
    return any(fnmatchcase(resource, p) for p in patterns)


@dataclass
class Resolution:
    all_access: bool  # legacy admin: everything, immune to deny policies
    base: set[str] = field(default_factory=set)  # granted by roles (any resource)
    role_ids: set[int] = field(default_factory=set)
    group_ids: set[int] = field(default_factory=set)
    allow: list[PolicyRule] = field(default_factory=list)
    deny: list[PolicyRule] = field(default_factory=list)

    def allows(self, permission: str, resource: str = ANY) -> bool:
        if self.all_access:
            return True
        granted = permission in self.base or any(
            p.covers(permission, resource) for p in self.allow)
        return granted and not any(p.covers(permission, resource) for p in self.deny)

    def permissions(self) -> set[str]:
        return {p for p in ALL_PERMISSIONS if self.allows(p)}

    def granted_before_deny(self) -> set[str]:
        if self.all_access:
            return set(ALL_PERMISSIONS)
        return {p for p in ALL_PERMISSIONS
                if p in self.base or any(r.covers(p, ANY) for r in self.allow)}


def _rule(p: IamPolicy) -> PolicyRule:
    return PolicyRule(p.id, p.name, p.effect, list(p.permissions or []), list(p.resources or []))


def role_permissions(db: Session, role_ids) -> dict[int, set[str]]:
    """Permissions of each role (the system "admin" role: the whole catalog)."""
    ids = set(role_ids)
    out: dict[int, set[str]] = {i: set() for i in ids}
    if not ids:
        return out
    for role in db.scalars(select(IamRole).where(IamRole.id.in_(ids))):
        if role.system and role.name == ADMIN_ROLE_NAME:
            out[role.id] = set(ALL_PERMISSIONS)
    for rid, perm in db.execute(select(IamRolePermission.role_id, IamRolePermission.permission)
                                .where(IamRolePermission.role_id.in_(ids))):
        if perm in ALL_PERMISSIONS:
            out[rid].add(perm)
    return out


def resolve(db: Session, user: User) -> Resolution:
    if user.role == Role.ADMIN:
        return Resolution(all_access=True)
    group_ids = set(db.scalars(select(IamGroupMember.group_id)
                               .where(IamGroupMember.user_id == user.id)))
    role_ids = set(db.scalars(select(IamUserRole.role_id).where(IamUserRole.user_id == user.id)))
    if group_ids:
        role_ids |= set(db.scalars(select(IamGroupRole.role_id)
                                   .where(IamGroupRole.group_id.in_(group_ids))))
    legacy = db.scalar(select(IamRole.id).where(IamRole.system.is_(True),
                                                IamRole.name == user.role.value))
    base: set[str] = set()
    if legacy is None:
        base |= _LEGACY_FALLBACK.get(user.role.value, frozenset())
    else:
        role_ids.add(legacy)
    for perms in role_permissions(db, role_ids).values():
        base |= perms
    subjects = [and_(IamPolicyAttachment.subject_type == "user",
                     IamPolicyAttachment.subject_id == user.id)]
    if group_ids:
        subjects.append(and_(IamPolicyAttachment.subject_type == "group",
                             IamPolicyAttachment.subject_id.in_(group_ids)))
    if role_ids:
        subjects.append(and_(IamPolicyAttachment.subject_type == "role",
                             IamPolicyAttachment.subject_id.in_(role_ids)))
    policies = db.scalars(
        select(IamPolicy).join(IamPolicyAttachment, IamPolicyAttachment.policy_id == IamPolicy.id)
        .where(IamPolicy.disabled.is_(False), or_(*subjects))).unique().all()
    res = Resolution(all_access=False, base=base, role_ids=role_ids, group_ids=group_ids)
    for p in policies:
        (res.deny if p.effect == "deny" else res.allow).append(_rule(p))
    return res


def effective_permissions(db: Session, user: User) -> set[str]:
    return resolve(db, user).permissions()


def allows(db: Session, user: User, permission: str, resource: str = ANY) -> bool:
    """May `user` use `permission` (on `resource`, a name matched against policy globs)?"""
    return resolve(db, user).allows(permission, resource)


# --- what a role, group or policy would give or take away (privilege-escalation checks) ----------

def policy_grants(p: IamPolicy) -> set[str]:
    return expand(p.permissions or []) if p.effect == "allow" and not p.disabled else set()


def policy_denies(p: IamPolicy) -> set[str]:
    return expand(p.permissions or []) if p.effect == "deny" and not p.disabled else set()


def _attached(db: Session, subject_type: str, subject_id: int) -> list[IamPolicy]:
    subjects = and_(IamPolicyAttachment.subject_type == subject_type,
                    IamPolicyAttachment.subject_id == subject_id)
    if subject_type == "group":
        role_ids = select(IamGroupRole.role_id).where(IamGroupRole.group_id == subject_id)
        subjects = or_(subjects, and_(IamPolicyAttachment.subject_type == "role",
                                      IamPolicyAttachment.subject_id.in_(role_ids)))
    return list(db.scalars(select(IamPolicy).join(IamPolicyAttachment)
                           .where(subjects)).unique())


def _group_role_ids(db: Session, group_id: int) -> list[int]:
    return list(db.scalars(select(IamGroupRole.role_id).where(IamGroupRole.group_id == group_id)))


def subject_grants(db: Session, subject_type: str, subject_id: int) -> set[str]:
    """Permissions that being a member of this group / holding this role would give."""
    out: set[str] = set()
    if subject_type == "role":
        out |= role_permissions(db, [subject_id]).get(subject_id, set())
    elif subject_type == "group":
        for perms in role_permissions(db, _group_role_ids(db, subject_id)).values():
            out |= perms
    for p in _attached(db, subject_type, subject_id):
        out |= policy_grants(p)
    return out


def subject_denies(db: Session, subject_type: str, subject_id: int) -> set[str]:
    """Permissions this group / role / user takes away from whoever has it (via deny policies)."""
    out: set[str] = set()
    for p in _attached(db, subject_type, subject_id):
        out |= policy_denies(p)
    return out
