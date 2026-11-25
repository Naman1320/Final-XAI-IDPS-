"""IAM: the effective-permission engine (soc/api/iam/engine.py)."""

import pytest
from iam_helpers import add_group, add_policy, add_role, add_user

from soc.api.iam import engine
from soc.api.iam.catalog import ALL_PERMISSIONS, CATALOG, expand, valid_pattern
from soc.api.models import IamGroupMember, IamUserRole, Role, User


@pytest.fixture
def db(soc_app):
    with soc_app.state.session_factory() as session:
        yield session


def _user(db, name) -> User:
    return db.query(User).filter_by(username=name).one()


def test_the_catalog_has_the_agreed_permissions():
    assert ALL_PERMISSIONS == {
        "cloud.view", "cloud.instances.write", "cloud.storage.write", "cloud.network.write",
        "cloud.alerts.manage", "iam.users.view", "iam.users.write", "iam.users.delete",
        "iam.roles.view", "iam.roles.write", "iam.groups.view", "iam.groups.write",
        "iam.policies.view", "iam.policies.write", "iam.audit.view", "iam.logins.view"}
    assert all(p["description"] for g in CATALOG for p in g["permissions"])
    assert sum(len(g["permissions"]) for g in CATALOG) == len(ALL_PERMISSIONS)


def test_patterns():
    assert expand(["cloud.*"]) == {p for p in ALL_PERMISSIONS if p.startswith("cloud.")}
    assert expand(["*.view"]) == {"cloud.view", "iam.users.view", "iam.roles.view",
                                  "iam.groups.view", "iam.policies.view", "iam.audit.view",
                                  "iam.logins.view"}
    assert expand(["*"]) == ALL_PERMISSIONS
    assert valid_pattern("iam.*") and valid_pattern("cloud.view")
    assert not valid_pattern("cloud.nothing") and not valid_pattern("CLOUD.*")
    assert not valid_pattern("") and not valid_pattern("cloud.[a]*")


def test_a_legacy_analyst_holds_cloud_view_only(soc_app, db):
    assert engine.effective_permissions(db, _user(db, "analyst")) == {"cloud.view"}


def test_a_legacy_admin_holds_everything(soc_app, db):
    admin = _user(db, "admin")
    assert engine.effective_permissions(db, admin) == ALL_PERMISSIONS
    assert engine.allows(db, admin, "iam.users.delete")


def test_union_of_direct_roles_and_group_roles(soc_app, db):
    uid = add_user(soc_app, "u1")
    direct = add_role(db, "direct", ["iam.users.view"])
    via_group = add_role(db, "via group", ["iam.audit.view", "cloud.storage.write"])
    db.add(IamUserRole(user_id=uid, role_id=direct.id))
    add_group(db, "g1", roles=[via_group.id], members=[uid])
    assert engine.effective_permissions(db, _user(db, "u1")) == {
        "cloud.view", "iam.users.view", "iam.audit.view", "cloud.storage.write"}


def test_a_group_the_user_is_not_in_grants_nothing(soc_app, db):
    add_user(soc_app, "u1")
    other = add_role(db, "other", ["iam.audit.view"])
    add_group(db, "g1", roles=[other.id])
    assert engine.effective_permissions(db, _user(db, "u1")) == {"cloud.view"}


def test_allow_policy_adds_permissions_for_user_group_and_role(soc_app, db):
    uid = add_user(soc_app, "u1")
    role = add_role(db, "r")
    group = add_group(db, "g", members=[uid])
    db.add(IamUserRole(user_id=uid, role_id=role.id))
    db.commit()
    add_policy(db, "p-user", "allow", ["iam.users.view"], attach=[("user", uid)])
    add_policy(db, "p-group", "allow", ["iam.audit.view"], attach=[("group", group.id)])
    add_policy(db, "p-role", "allow", ["iam.logins.view"], attach=[("role", role.id)])
    assert engine.effective_permissions(db, _user(db, "u1")) == {
        "cloud.view", "iam.users.view", "iam.audit.view", "iam.logins.view"}


def test_an_unattached_or_disabled_policy_does_nothing(soc_app, db):
    uid = add_user(soc_app, "u1")
    add_policy(db, "loose", "allow", ["iam.audit.view"])
    add_policy(db, "off", "allow", ["iam.users.view"], attach=[("user", uid)], disabled=True)
    add_policy(db, "off-deny", "deny", ["cloud.view"], attach=[("user", uid)], disabled=True)
    assert engine.effective_permissions(db, _user(db, "u1")) == {"cloud.view"}


@pytest.mark.parametrize("attach_to", ["user", "group", "role"])
def test_deny_wins_over_allow_wherever_it_is_attached(soc_app, db, attach_to):
    uid = add_user(soc_app, "u1", perms=["iam.users.view", "iam.audit.view"])
    role = db.query(engine.IamRole).filter_by(name="role of u1").one()
    group = add_group(db, "g", members=[uid])
    target = {"user": uid, "group": group.id, "role": role.id}[attach_to]
    add_policy(db, "deny audit", "deny", ["iam.audit.view"], attach=[(attach_to, target)])
    # also allowed by a policy attached to the user: the deny still wins
    add_policy(db, "allow audit", "allow", ["iam.audit.view"], attach=[("user", uid)])
    perms = engine.effective_permissions(db, _user(db, "u1"))
    assert "iam.audit.view" not in perms and "iam.users.view" in perms


def test_deny_wildcard_removes_a_whole_family(soc_app, db):
    uid = add_user(soc_app, "u1", perms=["cloud.instances.write", "cloud.network.write",
                                         "iam.users.view"])
    add_policy(db, "no cloud", "deny", ["cloud.*"], attach=[("user", uid)])
    assert engine.effective_permissions(db, _user(db, "u1")) == {"iam.users.view"}


def test_allow_wildcard_grants_a_whole_family(soc_app, db):
    uid = add_user(soc_app, "u1")
    add_policy(db, "all iam views", "allow", ["iam.*.view"], attach=[("user", uid)])
    assert engine.effective_permissions(db, _user(db, "u1")) == {
        "cloud.view", "iam.users.view", "iam.roles.view", "iam.groups.view", "iam.policies.view",
        "iam.audit.view", "iam.logins.view"}


def test_a_deny_policy_cannot_touch_a_legacy_admin(soc_app, db):
    admin = _user(db, "admin")
    add_policy(db, "everything", "deny", ["*"], attach=[("user", admin.id)])
    assert engine.effective_permissions(db, admin) == ALL_PERMISSIONS
    assert engine.allows(db, admin, "iam.users.write", "anything")


def test_the_system_admin_role_gives_everything_but_denies_still_apply(soc_app, db):
    uid = add_user(soc_app, "u1")
    admin_role = db.query(engine.IamRole).filter_by(name="admin", system=True).one()
    db.add(IamUserRole(user_id=uid, role_id=admin_role.id))
    db.commit()
    add_policy(db, "no delete", "deny", ["iam.users.delete"], attach=[("user", uid)])
    perms = engine.effective_permissions(db, _user(db, "u1"))
    assert perms == ALL_PERMISSIONS - {"iam.users.delete"}


def test_a_deny_on_the_system_analyst_role_hits_every_analyst(soc_app, db):
    analyst_role = db.query(engine.IamRole).filter_by(name="analyst", system=True).one()
    add_policy(db, "no view", "deny", ["cloud.view"], attach=[("role", analyst_role.id)])
    assert engine.effective_permissions(db, _user(db, "analyst")) == set()


def test_resources_scope_policies(soc_app, db):
    uid = add_user(soc_app, "u1", perms=["cloud.instances.write"])
    add_policy(db, "protect prod", "deny", ["cloud.instances.write"], ["prod-*"],
               attach=[("user", uid)])
    user = _user(db, "u1")
    assert engine.allows(db, user, "cloud.instances.write", "dev-1")
    assert not engine.allows(db, user, "cloud.instances.write", "prod-db")
    # asked in general, a deny scoped to some resources does not remove the permission
    assert engine.allows(db, user, "cloud.instances.write")
    assert "cloud.instances.write" in engine.effective_permissions(db, user)


def test_a_deny_over_every_resource_applies_to_any_resource_and_in_general(soc_app, db):
    uid = add_user(soc_app, "u1", perms=["cloud.instances.write"])
    add_policy(db, "none", "deny", ["cloud.instances.write"], ["*"], attach=[("user", uid)])
    user = _user(db, "u1")
    assert not engine.allows(db, user, "cloud.instances.write", "dev-1")
    assert not engine.allows(db, user, "cloud.instances.write")


def test_a_scoped_allow_grants_only_on_its_resources(soc_app, db):
    uid = add_user(soc_app, "u1")
    add_policy(db, "dev only", "allow", ["cloud.instances.write"], ["dev-*"],
               attach=[("user", uid)])
    user = _user(db, "u1")
    assert engine.allows(db, user, "cloud.instances.write", "dev-7")
    assert not engine.allows(db, user, "cloud.instances.write", "prod-7")
    assert not engine.allows(db, user, "cloud.instances.write")  # not held in general


def test_a_question_mark_glob_does_not_pass_for_match_everything():
    assert not engine.resource_matches(["?"], "*")
    assert engine.resource_matches(["*"], "*") and engine.resource_matches(["**"], "*")
    assert engine.resource_matches(["a?c"], "abc")


def test_role_changes_are_seen_at_once(soc_app, db):
    uid = add_user(soc_app, "u1")
    role = add_role(db, "r", ["iam.audit.view"])
    db.add(IamUserRole(user_id=uid, role_id=role.id))
    db.commit()
    assert "iam.audit.view" in engine.effective_permissions(db, _user(db, "u1"))
    db.query(IamUserRole).delete()
    db.commit()
    assert "iam.audit.view" not in engine.effective_permissions(db, _user(db, "u1"))


def test_leaving_a_group_ends_its_grants(soc_app, db):
    uid = add_user(soc_app, "u1")
    role = add_role(db, "r", ["iam.audit.view"])
    add_group(db, "g", roles=[role.id], members=[uid])
    assert "iam.audit.view" in engine.effective_permissions(db, _user(db, "u1"))
    db.query(IamGroupMember).delete()
    db.commit()
    assert "iam.audit.view" not in engine.effective_permissions(db, _user(db, "u1"))


def test_unknown_stored_permissions_are_ignored(soc_app, db):
    uid = add_user(soc_app, "u1")
    role = add_role(db, "r", ["cloud.retired", "iam.audit.view"])
    db.add(IamUserRole(user_id=uid, role_id=role.id))
    db.commit()
    assert engine.effective_permissions(db, _user(db, "u1")) == {"cloud.view", "iam.audit.view"}


def test_legacy_role_enum_is_what_decides_admin(soc_app, db):
    add_user(soc_app, "boss", Role.ADMIN)
    assert engine.resolve(db, _user(db, "boss")).all_access
    assert not engine.resolve(db, _user(db, "analyst")).all_access
