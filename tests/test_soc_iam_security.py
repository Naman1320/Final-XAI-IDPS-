"""IAM security rules: no privilege escalation, self-protection, the last admin, immutable system
roles, session invalidation, deactivation, legacy behaviour and the audit trail."""

from conftest import ADMIN_PW, login
from iam_helpers import (
    PW,
    add_group,
    add_policy,
    add_role,
    add_user,
    audit_actions,
    headers,
    user_row,
)
from sqlalchemy import select

from soc.api.iam.catalog import ALL_PERMISSIONS
from soc.api.models import (
    Action,
    ActionKind,
    ActionStatus,
    AssistantConversation,
    AuditEntry,
    Case,
    CaseNote,
    IamGroupMember,
    IamPolicyAttachment,
    IamRole,
    IamUserRole,
    LoginHistory,
    Role,
    SensorToken,
    User,
)


def id_of(client, h, kind, name):
    items = client.get(f"/iam/{kind}?limit=500", headers=h).json()["items"]
    return next(i["id"] for i in items if i["name"] == name)


def uid(app, name) -> int:
    return user_row(app, name).id


def alive(client, h) -> bool:
    return client.get("/auth/me", headers=h).status_code == 200


# --- no privilege escalation --------------------------------------------------------------------

def test_cannot_create_or_grow_a_role_beyond_your_own_permissions(client, soc_app, admin_headers):
    add_user(soc_app, "rw", perms=["iam.roles.write", "iam.roles.view", "iam.audit.view"])
    h = headers(client, "rw")
    r = client.post("/iam/roles", json={"name": "Sneaky", "permissions": ["iam.users.delete"]},
                    headers=h)
    assert r.status_code == 403 and "iam.users.delete" in r.json()["detail"]
    assert client.get("/iam/roles?q=sneaky", headers=h).json()["items"] == []
    ok = client.post("/iam/roles", json={"name": "Fine", "permissions": ["iam.audit.view",
                                                                        "cloud.view"]}, headers=h)
    assert ok.status_code == 201
    rid = ok.json()["id"]
    assert client.patch(f"/iam/roles/{rid}", json={"permissions": ["iam.audit.view",
                                                                   "iam.users.write"]},
                        headers=h).status_code == 403
    assert client.get(f"/iam/roles/{rid}", headers=h).json()["permissions"] \
        == ["cloud.view", "iam.audit.view"]
    # taking permissions away is fine, even ones the editor does not hold
    admin_role = client.post("/iam/roles", json={"name": "Wide", "permissions": [
        "iam.users.delete", "iam.audit.view"]}, headers=admin_headers).json()
    r = client.patch(f"/iam/roles/{admin_role['id']}", json={"permissions": ["iam.audit.view"]},
                     headers=h)
    assert r.status_code == 200


def test_cannot_hand_out_a_role_you_could_not_have_created(client, soc_app, admin_headers):
    big = client.post("/iam/roles", json={"name": "Big", "permissions": ["iam.users.delete"]},
                      headers=admin_headers).json()["id"]
    add_user(soc_app, "um", perms=["iam.users.write", "iam.users.view"])
    victim = add_user(soc_app, "victim")
    h = headers(client, "um")
    assert client.patch(f"/iam/users/{victim}", json={"role_ids": [big]},
                        headers=h).status_code == 403
    assert client.post("/iam/users", json={"username": "newbie", "password": PW,
                                           "role_ids": [big]}, headers=h).status_code == 403
    assert user_row(soc_app, "newbie") is None
    assert client.get(f"/iam/users/{victim}", headers=admin_headers).json()["roles"] == []


def test_cannot_escalate_through_a_group(client, soc_app, admin_headers):
    big = client.post("/iam/roles", json={"name": "Big", "permissions": ["iam.users.delete"]},
                      headers=admin_headers).json()["id"]
    gid = client.post("/iam/groups", json={"name": "Powerful"}, headers=admin_headers).json()["id"]
    client.put(f"/iam/groups/{gid}/roles", json={"role_ids": [big]}, headers=admin_headers)
    add_user(soc_app, "um", perms=["iam.users.write"])
    add_user(soc_app, "gm", perms=["iam.groups.write"])
    victim = add_user(soc_app, "victim")
    hu, hg = headers(client, "um"), headers(client, "gm")
    # joining a group that carries permissions you lack: by user edit, creation and membership
    assert client.patch(f"/iam/users/{victim}", json={"group_ids": [gid]},
                        headers=hu).status_code == 403
    assert client.post("/iam/users", json={"username": "newbie", "password": PW,
                                           "group_ids": [gid]}, headers=hu).status_code == 403
    assert client.put(f"/iam/groups/{gid}/members", json={"user_ids": [victim]},
                      headers=hg).status_code == 403
    # and giving a group a role you lack
    plain = client.post("/iam/groups", json={"name": "Plain"}, headers=admin_headers).json()["id"]
    assert client.put(f"/iam/groups/{plain}/roles", json={"role_ids": [big]},
                      headers=hg).status_code == 403
    assert "iam.users.delete" not in client.get(
        f"/iam/users/{victim}/effective-permissions", headers=admin_headers
    ).json()["permissions"]


def test_cannot_escalate_through_a_policy(client, soc_app, admin_headers):
    add_user(soc_app, "pw", perms=["iam.policies.write", "iam.audit.view"])
    victim = add_user(soc_app, "victim")
    h = headers(client, "pw")
    body = {"name": "Grant", "effect": "allow", "permissions": ["iam.users.*"]}
    assert client.post("/iam/policies", json=body, headers=h).status_code == 403
    # a harmless allow can be created, but not widened or attached beyond one's own permissions
    ok = client.post("/iam/policies", json={**body, "name": "Small",
                                            "permissions": ["iam.audit.view"]}, headers=h)
    assert ok.status_code == 201
    pid = ok.json()["id"]
    assert client.patch(f"/iam/policies/{pid}", json={"permissions": ["iam.users.*"]},
                        headers=h).status_code == 403
    # a deny flipped to allow grants what it names
    deny = client.post("/iam/policies", json={"name": "Deny", "effect": "deny",
                                              "permissions": ["iam.users.delete"]},
                       headers=h).json()["id"]
    assert client.patch(f"/iam/policies/{deny}", json={"effect": "allow"},
                        headers=h).status_code == 403
    # an admin-made allow policy cannot be attached by someone who lacks what it grants
    big = client.post("/iam/policies", json={**body, "name": "Big"}, headers=admin_headers
                      ).json()["id"]
    r = client.put(f"/iam/policies/{big}/attachments", headers=h, json={
        "attachments": [{"subject_type": "user", "subject_id": victim}]})
    assert r.status_code == 403
    assert client.get(f"/iam/policies/{big}", headers=admin_headers).json()["attachments"] == []
    # ... nor re-enabled: a disabled admin-made allow policy stays disabled
    off = client.post("/iam/policies", json={**body, "name": "Off", "disabled": True},
                      headers=admin_headers).json()["id"]
    assert client.patch(f"/iam/policies/{off}", json={"disabled": False},
                        headers=h).status_code == 403


def test_cannot_lift_a_restriction_you_do_not_hold_the_permission_for(client, soc_app,
                                                                      admin_headers):
    """Otherwise a user who is denied a permission could simply delete the deny."""
    victim = add_user(soc_app, "denied", perms=["iam.policies.write", "iam.audit.view"])
    pid = client.post("/iam/policies", json={"name": "No audit", "effect": "deny",
                                             "permissions": ["iam.audit.view"]},
                      headers=admin_headers).json()["id"]
    client.put(f"/iam/policies/{pid}/attachments", headers=admin_headers, json={
        "attachments": [{"subject_type": "role", "subject_id": id_of(
            client, admin_headers, "roles", "role of denied")}]})
    h = headers(client, "denied")  # holds iam.policies.write; the deny removed iam.audit.view
    assert client.get("/iam/me/permissions", headers=h).json()["permissions"] == [
        "cloud.view", "iam.policies.write"]
    assert client.delete(f"/iam/policies/{pid}", headers=h).status_code == 403
    assert client.patch(f"/iam/policies/{pid}", json={"disabled": True},
                        headers=h).status_code == 403
    assert client.patch(f"/iam/policies/{pid}", json={"permissions": ["iam.roles.view"]},
                        headers=h).status_code == 403
    assert client.put(f"/iam/policies/{pid}/attachments", json={"attachments": []},
                      headers=h).status_code == 403
    assert victim and "iam.audit.view" not in client.get(
        "/iam/me/permissions", headers=h).json()["permissions"]


def test_leaving_a_deny_group_needs_the_permission_too(client, soc_app, admin_headers):
    u = add_user(soc_app, "gw", perms=["iam.groups.write"])
    other = add_user(soc_app, "other")
    with soc_app.state.session_factory() as db:
        group = add_group(db, "Restricted", members=[other])
        add_policy(db, "deny audit", "deny", ["iam.audit.view"], attach=[("group", group.id)])
    h = headers(client, "gw")
    r = client.put(f"/iam/groups/{group.id}/members", json={"user_ids": []}, headers=h)
    assert r.status_code == 403
    assert u and client.put(f"/iam/groups/{group.id}/members", json={"user_ids": []},
                            headers=admin_headers).status_code == 200


def test_only_a_legacy_admin_can_make_an_admin(client, soc_app, admin_headers):
    add_user(soc_app, "um", perms=["iam.users.write", "iam.users.view"])
    victim = add_user(soc_app, "victim")
    h = headers(client, "um")
    assert client.patch(f"/iam/users/{victim}", json={"role": "admin"},
                        headers=h).status_code == 403
    assert client.post("/iam/users", json={"username": "boss2", "password": PW, "role": "admin"},
                       headers=h).status_code == 403
    assert user_row(soc_app, "victim").role == Role.ANALYST
    # Catalog permissions do not include the legacy administrator endpoints.
    add_user(soc_app, "root", perms=sorted(ALL_PERMISSIONS))
    r = client.patch(f"/iam/users/{victim}", json={"role": "admin"}, headers=headers(client, "root"))
    assert r.status_code == 403
    assert client.patch(f"/iam/users/{victim}", json={"role": "admin"},
                        headers=admin_headers).status_code == 200


def test_cannot_manage_a_user_who_holds_more_than_you(client, soc_app):
    add_user(soc_app, "um", perms=["iam.users.write", "iam.users.delete", "iam.users.view"])
    add_user(soc_app, "power", perms=["iam.audit.view"])
    h = headers(client, "um")
    admin_id, power = uid(soc_app, "admin"), uid(soc_app, "power")
    for method, path, body in (("POST", f"/iam/users/{admin_id}/deactivate", None),
                               ("PATCH", f"/iam/users/{admin_id}", {"disabled": True}),
                               ("PATCH", f"/iam/users/{power}", {"disabled": True}),
                               ("DELETE", f"/iam/users/{admin_id}", None),
                               ("DELETE", f"/iam/users/{power}", None)):
        assert client.request(method, path, json=body, headers=h).status_code == 403, path
    assert not user_row(soc_app, "admin").disabled and user_row(soc_app, "power")


def test_view_only_users_cannot_write(client, soc_app, admin_headers):
    views = [p for p in ALL_PERMISSIONS if p.startswith("iam.") and p.endswith(".view")]
    add_user(soc_app, "viewer", perms=views)
    h = headers(client, "viewer")
    victim = add_user(soc_app, "victim")
    with soc_app.state.session_factory() as db:
        role = add_role(db, "R")
        group = add_group(db, "G")
        policy = add_policy(db, "P", "deny", ["cloud.view"])
    writes = [
        ("POST", "/iam/users", {"username": "x1", "password": PW}),
        ("PATCH", f"/iam/users/{victim}", {"disabled": True}),
        ("POST", f"/iam/users/{victim}/deactivate", None),
        ("POST", f"/iam/users/{victim}/activate", None),
        ("DELETE", f"/iam/users/{victim}", None),
        ("POST", "/iam/roles", {"name": "Role X"}),
        ("PATCH", f"/iam/roles/{role.id}", {"description": "x"}),
        ("DELETE", f"/iam/roles/{role.id}", None),
        ("POST", "/iam/groups", {"name": "Group X"}),
        ("PATCH", f"/iam/groups/{group.id}", {"description": "x"}),
        ("DELETE", f"/iam/groups/{group.id}", None),
        ("PUT", f"/iam/groups/{group.id}/members", {"user_ids": [victim]}),
        ("PUT", f"/iam/groups/{group.id}/roles", {"role_ids": [role.id]}),
        ("POST", "/iam/policies", {"name": "Policy X", "effect": "deny",
                                   "permissions": ["cloud.view"]}),
        ("PATCH", f"/iam/policies/{policy.id}", {"description": "x"}),
        ("DELETE", f"/iam/policies/{policy.id}", None),
        ("PUT", f"/iam/policies/{policy.id}/attachments", {"attachments": []}),
    ]
    for method, path, body in writes:
        assert client.request(method, path, json=body, headers=h).status_code == 403, path
    assert client.get("/iam/users", headers=h).status_code == 200  # reading is fine
    assert not user_row(soc_app, "victim").disabled


# --- protecting yourself and the last admin -----------------------------------------------------

def test_cannot_change_yourself(client, soc_app, admin_headers):
    with soc_app.state.session_factory() as db:
        role = add_role(db, "R")
        group = add_group(db, "G")
        policy = add_policy(db, "P", "deny", ["cloud.view"])
    add_user(soc_app, "boss", Role.ADMIN)
    me = uid(soc_app, "boss")
    h = headers(client, "boss")
    for body in ({"role": "analyst"}, {"role_ids": [role.id]}, {"group_ids": [group.id]},
                 {"disabled": True}):
        assert client.patch(f"/iam/users/{me}", json=body, headers=h).status_code == 403, body
    assert client.post(f"/iam/users/{me}/deactivate", headers=h).status_code == 403
    assert client.delete(f"/iam/users/{me}", headers=h).status_code == 403
    assert client.put(f"/iam/groups/{group.id}/members", json={"user_ids": [me]},
                      headers=h).status_code == 403
    assert client.put(f"/iam/policies/{policy.id}/attachments", headers=h, json={
        "attachments": [{"subject_type": "user", "subject_id": me}]}).status_code == 403
    # still the same admin, session intact
    assert alive(client, h) and user_row(soc_app, "boss").role == Role.ADMIN
    assert not user_row(soc_app, "boss").disabled


def test_admin_management_requires_a_legacy_admin(client, soc_app, admin_headers):
    add_user(soc_app, "root", perms=sorted(ALL_PERMISSIONS))
    h = headers(client, "root")
    second = add_user(soc_app, "boss2", Role.ADMIN)
    path = f"/iam/users/{second}"
    assert client.patch(path, json={"role": "analyst"}, headers=h).status_code == 403
    assert client.post(path + "/deactivate", headers=h).status_code == 403
    assert client.delete(path, headers=h).status_code == 403
    assert client.post(path + "/deactivate", headers=admin_headers).status_code == 200
    assert client.delete(path, headers=admin_headers).status_code == 204


def test_system_roles_are_immutable(client, soc_app, admin_headers):
    for name in ("admin", "analyst"):
        rid = id_of(client, admin_headers, "roles", name)
        before = client.get(f"/iam/roles/{rid}", headers=admin_headers).json()
        for body in ({"permissions": ["cloud.view"]}, {"description": "x"}, {"name": "Renamed"}):
            assert client.patch(f"/iam/roles/{rid}", json=body, headers=admin_headers
                                ).status_code == 409
        assert client.delete(f"/iam/roles/{rid}", headers=admin_headers).status_code == 409
        assert client.get(f"/iam/roles/{rid}", headers=admin_headers).json() == before
    with soc_app.state.session_factory() as db:
        assert db.scalar(select(IamRole).where(IamRole.name == "admin")) is not None


# --- sessions end when access changes -----------------------------------------------------------

def test_user_changes_end_that_users_sessions(client, soc_app, admin_headers):
    with soc_app.state.session_factory() as db:
        role = add_role(db, "R", ["iam.audit.view"])
        group = add_group(db, "G")
    victim = add_user(soc_app, "victim")
    changes = [
        {"role_ids": [role.id]}, {"group_ids": [group.id]}, {"role": "admin"},
        {"role": "analyst"}, {"disabled": True},
    ]
    for body in changes:
        h = headers(client, "victim")
        assert alive(client, h)
        before = user_row(soc_app, "victim").token_version
        assert client.patch(f"/iam/users/{victim}", json=body, headers=admin_headers
                            ).status_code == 200, body
        assert user_row(soc_app, "victim").token_version == before + 1, body
        assert not alive(client, h), body
        if body.get("disabled"):
            client.post(f"/iam/users/{victim}/activate", headers=admin_headers)


def test_a_change_that_changes_nothing_keeps_sessions(client, soc_app, admin_headers):
    victim = add_user(soc_app, "victim")
    h = headers(client, "victim")
    client.patch(f"/iam/users/{victim}", json={"role_ids": [], "disabled": False, "role": "analyst"},
                 headers=admin_headers)
    assert alive(client, h)


def test_deactivate_and_activate_end_sessions_and_block_login(client, soc_app, admin_headers):
    victim = add_user(soc_app, "victim")
    h = headers(client, "victim")
    assert client.post(f"/iam/users/{victim}/deactivate", headers=admin_headers).status_code == 200
    assert not alive(client, h)
    assert client.post("/auth/login", json={"username": "victim", "password": PW}
                       ).status_code == 401
    assert client.post(f"/iam/users/{victim}/activate", headers=admin_headers).status_code == 200
    assert not alive(client, h)  # the old token stays dead
    assert login(client, "victim", PW)


def test_a_disabled_user_with_permissions_is_refused_by_the_dependency(client, soc_app,
                                                                       admin_headers):
    add_user(soc_app, "rv", perms=["iam.roles.view"])
    h = headers(client, "rv")
    assert client.get("/iam/roles", headers=h).status_code == 200
    with soc_app.state.session_factory() as db:
        db.query(User).filter_by(username="rv").update({"disabled": True})
        db.commit()
    assert client.get("/iam/roles", headers=h).status_code == 401


def test_group_role_and_policy_changes_end_the_sessions_of_those_affected(
        client, soc_app, admin_headers):
    m1, m2 = add_user(soc_app, "m1"), add_user(soc_app, "m2")
    outsider = add_user(soc_app, "outsider")
    with soc_app.state.session_factory() as db:
        role = add_role(db, "R", ["iam.audit.view"])
        group = add_group(db, "G", roles=[role.id], members=[m1])
        policy = add_policy(db, "P", "deny", ["iam.audit.view"], attach=[("user", m2)])
    h1, h2, ho = (headers(client, n) for n in ("m1", "m2", "outsider"))
    # editing the role's permissions ends the sessions of whoever holds it (via the group)
    r = client.patch(f"/iam/roles/{role.id}", json={"permissions": ["iam.logins.view"]},
                     headers=admin_headers)
    assert r.status_code == 200
    assert not alive(client, h1) and alive(client, h2) and alive(client, ho)
    # a policy change reaches the users it is attached to
    client.patch(f"/iam/policies/{policy.id}", json={"permissions": ["iam.logins.view"]},
                 headers=admin_headers)
    assert not alive(client, h2) and alive(client, ho)
    # membership changes
    h1 = headers(client, "m1")
    client.put(f"/iam/groups/{group.id}/members", json={"user_ids": [m2]}, headers=admin_headers)
    assert not alive(client, h1)
    h2 = headers(client, "m2")
    # deleting the group
    client.delete(f"/iam/groups/{group.id}", headers=admin_headers)
    assert not alive(client, h2) and alive(client, ho) and outsider
    # attaching and deleting a policy
    h2 = headers(client, "m2")
    client.put(f"/iam/policies/{policy.id}/attachments", headers=admin_headers, json={
        "attachments": [{"subject_type": "user", "subject_id": uid(soc_app, "outsider")}]})
    assert not alive(client, ho) and not alive(client, h2)  # m2 was detached, outsider attached
    ho = headers(client, "outsider")
    client.delete(f"/iam/policies/{policy.id}", headers=admin_headers)
    assert not alive(client, ho)


def test_deleting_a_role_removes_assignments_and_ends_sessions(client, soc_app, admin_headers):
    u = add_user(soc_app, "holder", perms=["iam.audit.view"])
    h = headers(client, "holder")
    assert client.get("/iam/audit", headers=h).status_code == 200
    rid = id_of(client, admin_headers, "roles", "role of holder")
    with soc_app.state.session_factory() as db:
        group = add_group(db, "G", roles=[rid])
        add_policy(db, "P", "allow", ["iam.audit.view"], attach=[("role", rid)])
    assert client.delete(f"/iam/roles/{rid}", headers=admin_headers).status_code == 204
    assert not alive(client, h)
    with soc_app.state.session_factory() as db:
        assert db.scalar(select(IamUserRole).where(IamUserRole.user_id == u)) is None
        assert db.scalar(select(IamPolicyAttachment).where(
            IamPolicyAttachment.subject_type == "role")) is None
    assert client.get(f"/iam/groups/{group.id}", headers=admin_headers).json()["roles"] == []
    assert client.get("/iam/audit", headers=headers(client, "holder")).status_code == 403


def test_the_actor_is_not_logged_out_by_an_indirect_change(client, soc_app, admin_headers):
    add_user(soc_app, "rw", perms=["iam.roles.write", "iam.roles.view"])
    h = headers(client, "rw")
    rid = id_of(client, admin_headers, "roles", "role of rw")
    r = client.patch(f"/iam/roles/{rid}", json={"permissions": ["iam.roles.view",
                                                                "iam.roles.write"]}, headers=h)
    assert r.status_code == 200 and alive(client, h)


# --- legacy roles are unchanged -------------------------------------------------------------------

def test_iam_permissions_do_not_open_legacy_admin_endpoints(client, soc_app, analyst_headers):
    add_user(soc_app, "iamall", perms=sorted(ALL_PERMISSIONS))
    h = headers(client, "iamall")
    assert client.get("/admin/users", headers=h).status_code == 403
    assert client.get("/admin/audit", headers=h).status_code == 403
    assert client.get("/alerts", headers=h).status_code == 200  # an analyst still triages alerts
    assert client.get("/iam/users", headers=analyst_headers).status_code == 403


def test_legacy_admin_and_analyst_keep_their_endpoints(client, admin_headers, analyst_headers):
    assert client.get("/admin/users", headers=admin_headers).status_code == 200
    assert client.get("/admin/users", headers=analyst_headers).status_code == 403
    assert client.get("/alerts", headers=analyst_headers).status_code == 200
    assert client.get("/alerts", headers=admin_headers).status_code == 200


def test_the_legacy_admin_endpoints_still_work_on_the_new_tables(client, soc_app, admin_headers):
    uid_ = add_user(soc_app, "legacy")
    assert client.patch(f"/admin/users/{uid_}/role", json={"role": "admin"},
                        headers=admin_headers).status_code == 200
    assert client.get(f"/iam/users/{uid_}/effective-permissions", headers=admin_headers
                      ).json()["all_access"] is True


# --- deleting a user and what refers to them ----------------------------------------------------

def test_deleting_a_user_keeps_history_and_clears_what_is_theirs(client, soc_app, admin_headers):
    from datetime import UTC, datetime

    victim = add_user(soc_app, "victim")
    other = add_user(soc_app, "other")
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        sensor = SensorToken(name="s", token_hash="a" * 64)
        db.add(sensor)
        db.flush()
        case = Case(title="c", created_by_id=victim)
        db.add(case)
        db.flush()
        db.add(CaseNote(case_id=case.id, author_id=victim, text="hello"))
        db.add(Action(kind=ActionKind.BLOCK_IP, params={}, proposed_by="user",
                      proposed_by_user_id=victim, decided_by_id=victim, sensor_id=sensor.id,
                      status=ActionStatus.PENDING, created_at=now))
        db.add(AssistantConversation(user_id=victim, title="t"))
        db.add(LoginHistory(user_id=victim, username="victim", success=True, reason="ok"))
        group = add_group(db, "G", members=[victim, other])
        role = add_role(db, "R")
        db.add(IamUserRole(user_id=victim, role_id=role.id))
        pol = add_policy(db, "P", "deny", ["iam.audit.view"], attach=[("user", victim)])
        db.commit()
        ids = (case.id, group.id, pol.id)
    # run with foreign keys enforced, as PostgreSQL does
    with soc_app.state.engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.commit()
    r = client.delete(f"/iam/users/{victim}", headers=admin_headers)
    assert r.status_code == 204, r.text
    with soc_app.state.session_factory() as db:
        assert db.get(User, victim) is None
        case = db.get(Case, ids[0])
        assert case is not None and case.created_by_id is None
        note = db.scalar(select(CaseNote))
        assert note.text == "hello" and note.author_id is None
        action = db.scalar(select(Action))
        assert action.proposed_by_user_id is None and action.decided_by_id is None
        assert db.scalar(select(AssistantConversation)) is None
        entry = db.scalar(select(LoginHistory).where(LoginHistory.username == "victim"))
        assert entry is not None and entry.user_id is None  # kept, anonymised of the link
        members = list(db.scalars(select(IamGroupMember.user_id)))
        assert members == [other]
        assert db.scalar(select(IamUserRole).where(IamUserRole.user_id == victim)) is None
        assert db.scalar(select(IamPolicyAttachment).where(
            IamPolicyAttachment.subject_id == victim,
            IamPolicyAttachment.subject_type == "user")) is None
        audit = db.scalar(select(AuditEntry).where(AuditEntry.action == "iam_user_delete"))
        assert audit.target == "user:victim" and audit.details["conversations_deleted"] == 1


def test_a_deleted_users_token_stops_working(client, soc_app, admin_headers):
    victim = add_user(soc_app, "victim")
    h = headers(client, "victim")
    assert client.delete(f"/iam/users/{victim}", headers=admin_headers).status_code == 204
    assert not alive(client, h)
    add_user(soc_app, "replacement", Role.ADMIN)
    assert not alive(client, h)


# --- audit ----------------------------------------------------------------------------------

def test_every_mutation_is_audited_without_secrets(client, soc_app, admin_headers):
    victim = add_user(soc_app, "victim")
    r = client.post("/iam/users", json={"username": "fresh", "password": "very-secret-pw-123"},
                    headers=admin_headers)
    fresh = r.json()["id"]
    role = client.post("/iam/roles", json={"name": "Role1", "permissions": ["cloud.view"]},
                       headers=admin_headers).json()["id"]
    group = client.post("/iam/groups", json={"name": "Group1"}, headers=admin_headers).json()["id"]
    pol = client.post("/iam/policies", json={"name": "Policy1", "effect": "deny",
                                             "permissions": ["cloud.view"]},
                      headers=admin_headers).json()["id"]
    calls = [
        ("PATCH", f"/iam/users/{victim}", {"role_ids": [role]}),
        ("POST", f"/iam/users/{victim}/deactivate", None),
        ("POST", f"/iam/users/{victim}/activate", None),
        ("PATCH", f"/iam/roles/{role}", {"description": "d"}),
        ("PATCH", f"/iam/groups/{group}", {"description": "d"}),
        ("PUT", f"/iam/groups/{group}/members", {"user_ids": [victim]}),
        ("PUT", f"/iam/groups/{group}/roles", {"role_ids": [role]}),
        ("PATCH", f"/iam/policies/{pol}", {"disabled": True}),
        ("PUT", f"/iam/policies/{pol}/attachments", {"attachments": [
            {"subject_type": "group", "subject_id": group}]}),
        ("DELETE", f"/iam/policies/{pol}", None),
        ("DELETE", f"/iam/groups/{group}", None),
        ("DELETE", f"/iam/roles/{role}", None),
        ("DELETE", f"/iam/users/{fresh}", None),
    ]
    for method, path, body in calls:
        assert client.request(method, path, json=body, headers=admin_headers).status_code in (
            200, 204), (method, path)
    entries = audit_actions(client, admin_headers)
    actions = {e["action"] for e in entries}
    assert actions >= {
        "iam_user_create", "iam_user_update", "iam_user_deactivate", "iam_user_activate",
        "iam_user_delete", "iam_role_create", "iam_role_update", "iam_role_delete",
        "iam_group_create", "iam_group_update", "iam_group_members", "iam_group_roles",
        "iam_group_delete", "iam_policy_create", "iam_policy_update", "iam_policy_attach",
        "iam_policy_delete"}
    assert all(e["actor_name"] == "admin" and e["actor_type"] == "user" for e in entries
               if e["action"].startswith("iam_"))
    assert all(e["target"] for e in entries if e["action"].startswith("iam_"))
    blob = str(entries)
    assert "very-secret-pw-123" not in blob and "argon2" not in blob and ADMIN_PW not in blob


def test_a_refused_change_leaves_no_audit_row_and_no_change(client, soc_app, admin_headers):
    add_user(soc_app, "um", perms=["iam.users.write"])
    victim = add_user(soc_app, "victim")
    big = client.post("/iam/roles", json={"name": "Big", "permissions": ["iam.users.delete"]},
                      headers=admin_headers).json()["id"]
    before = len(audit_actions(client, admin_headers))
    r = client.patch(f"/iam/users/{victim}", json={"role_ids": [big], "disabled": True},
                     headers=headers(client, "um"))
    assert r.status_code == 403
    assert len(audit_actions(client, admin_headers)) == before
    row = user_row(soc_app, "victim")
    assert not row.disabled and row.token_version == 0


def test_scoped_and_inherited_permissions_limit_delegation(client, soc_app):
    manager = add_user(soc_app, "manager", perms=["iam.groups.write", "iam.policies.write",
                                                 "iam.roles.write", "cloud.storage.write"])
    member = add_user(soc_app, "member")
    with soc_app.state.session_factory() as db:
        role = add_role(db, "restricted")
        group = add_group(db, "team", roles=[role.id])
        grant = add_policy(db, "grant", "allow", ["iam.audit.view"], ["team-*"],
                           attach=[("role", role.id)])
        deny = add_policy(db, "protect", "deny", ["cloud.storage.write"], ["prod-*"],
                          attach=[("role", role.id), ("user", manager)])
        gid, allow_id, deny_id = group.id, grant.id, deny.id
    h = headers(client, "manager")
    assert client.post("/iam/roles", json={"name": "writer", "permissions": ["cloud.storage.write"]},
                       headers=h).status_code == 403
    assert client.put(f"/iam/groups/{gid}/members", json={"user_ids": [member]},
                      headers=h).status_code == 403
    assert client.put(f"/iam/groups/{gid}/roles", json={"role_ids": []}, headers=h).status_code == 403
    for pid, resources in [(allow_id, ["*"]), (deny_id, ["other-*"])]:
        assert client.patch(f"/iam/policies/{pid}", json={"resources": resources},
                            headers=h).status_code == 403
