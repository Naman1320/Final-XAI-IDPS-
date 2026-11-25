"""Helpers for the IAM tests: users, roles, groups and policies created straight in the database
(so a test can set up a world without depending on the endpoints it is about to test)."""

from conftest import login

from soc.api import auth
from soc.api.models import (
    IamGroup,
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

PW = "iam-test-password-1"


def add_user(app, name, legacy=Role.ANALYST, perms=(), *, disabled=False) -> int:
    """A user; with `perms`, also a custom role of exactly those permissions assigned to them."""
    with app.state.session_factory() as db:
        user = auth.create_user(db, name, PW, legacy)
        user.disabled = disabled
        if perms:
            role = add_role(db, f"role of {name}", perms)
            db.add(IamUserRole(user_id=user.id, role_id=role.id))
        db.commit()
        return user.id


def add_role(db, name, perms=()) -> IamRole:
    role = IamRole(name=name, description="", system=False)
    db.add(role)
    db.flush()
    db.add_all(IamRolePermission(role_id=role.id, permission=p) for p in perms)
    db.commit()
    return role


def add_group(db, name, *, roles=(), members=()) -> IamGroup:
    group = IamGroup(name=name, description="")
    db.add(group)
    db.flush()
    db.add_all(IamGroupRole(group_id=group.id, role_id=r) for r in roles)
    db.add_all(IamGroupMember(group_id=group.id, user_id=u) for u in members)
    db.commit()
    return group


def add_policy(db, name, effect, permissions, resources=("*",), *, attach=(),
               disabled=False) -> IamPolicy:
    policy = IamPolicy(name=name, description="", effect=effect, permissions=list(permissions),
                       resources=list(resources), disabled=disabled)
    db.add(policy)
    db.flush()
    db.add_all(IamPolicyAttachment(policy_id=policy.id, subject_type=t, subject_id=i)
               for t, i in attach)
    db.commit()
    return policy


def headers(client, name):
    return login(client, name, PW)


def user_row(app, name) -> User:
    with app.state.session_factory() as db:
        from sqlalchemy import select

        return db.scalar(select(User).where(User.username == name))


def audit_actions(client, admin_headers, **params) -> list[dict]:
    r = client.get("/admin/audit", headers=admin_headers, params={"limit": 500, **params})
    assert r.status_code == 200, r.text
    return r.json()["items"]
