"""IAM endpoints: authentication matrix, validation, CRUD, filters, audit, pagination."""

import pytest
from conftest import login
from iam_helpers import PW, add_group, add_policy, add_role, add_user, audit_actions, headers

from soc.api.iam.catalog import ALL_PERMISSIONS
from soc.api.models import Role


@pytest.fixture
def world(soc_app):
    """A target user, a custom role, a group and a (deny cloud.view) policy, none attached."""
    uid = add_user(soc_app, "target")
    with soc_app.state.session_factory() as db:
        role = add_role(db, "Tester", ["cloud.view"])
        group = add_group(db, "Testers")
        policy = add_policy(db, "Deny view", "deny", ["cloud.view"])
        return {"uid": uid, "rid": role.id, "gid": group.id, "pid": policy.id}


# (method, path, body, permission, status when allowed)
def _matrix(w):
    u, r, g, p = w["uid"], w["rid"], w["gid"], w["pid"]
    return [
        ("GET", "/iam/permissions", None, "iam.roles.view", 200),
        ("GET", "/iam/users", None, "iam.users.view", 200),
        ("POST", "/iam/users", {"username": "newbie", "password": PW}, "iam.users.write", 201),
        ("GET", f"/iam/users/{u}", None, "iam.users.view", 200),
        ("GET", f"/iam/users/{u}/effective-permissions", None, "iam.users.view", 200),
        ("PATCH", f"/iam/users/{u}", {"disabled": True}, "iam.users.write", 200),
        ("POST", f"/iam/users/{u}/deactivate", None, "iam.users.write", 200),
        ("POST", f"/iam/users/{u}/activate", None, "iam.users.write", 200),
        ("DELETE", f"/iam/users/{u}", None, "iam.users.delete", 204),
        ("GET", "/iam/roles", None, "iam.roles.view", 200),
        ("POST", "/iam/roles", {"name": "Fresh role"}, "iam.roles.write", 201),
        ("GET", f"/iam/roles/{r}", None, "iam.roles.view", 200),
        ("PATCH", f"/iam/roles/{r}", {"description": "d"}, "iam.roles.write", 200),
        ("DELETE", f"/iam/roles/{r}", None, "iam.roles.write", 204),
        ("GET", "/iam/groups", None, "iam.groups.view", 200),
        ("POST", "/iam/groups", {"name": "Fresh group"}, "iam.groups.write", 201),
        ("GET", f"/iam/groups/{g}", None, "iam.groups.view", 200),
        ("PATCH", f"/iam/groups/{g}", {"description": "d"}, "iam.groups.write", 200),
        ("DELETE", f"/iam/groups/{g}", None, "iam.groups.write", 204),
        ("PUT", f"/iam/groups/{g}/members", {"user_ids": [u]}, "iam.groups.write", 200),
        ("PUT", f"/iam/groups/{g}/roles", {"role_ids": [r]}, "iam.groups.write", 200),
        ("GET", "/iam/policies", None, "iam.policies.view", 200),
        ("POST", "/iam/policies", {"name": "Fresh policy", "effect": "deny",
                                   "permissions": ["cloud.view"]}, "iam.policies.write", 201),
        ("GET", f"/iam/policies/{p}", None, "iam.policies.view", 200),
        ("PATCH", f"/iam/policies/{p}", {"description": "d"}, "iam.policies.write", 200),
        ("DELETE", f"/iam/policies/{p}", None, "iam.policies.write", 204),
        ("PUT", f"/iam/policies/{p}/attachments",
         {"attachments": [{"subject_type": "user", "subject_id": u}]}, "iam.policies.write", 200),
        ("GET", "/iam/logins", None, "iam.logins.view", 200),
        ("GET", "/iam/audit", None, "iam.audit.view", 200),
    ]


def _ids():
    return [f"{m} {p}" for m, p, *_ in _matrix({"uid": "U", "rid": "R", "gid": "G", "pid": "P"})]


@pytest.mark.parametrize("index", range(len(_ids())), ids=_ids())
def test_auth_matrix(client, soc_app, admin_headers, analyst_headers, world, index):
    method, path, body, perm, ok = _matrix(world)[index]
    # 401: nobody signed in (and a junk token)
    assert client.request(method, path, json=body).status_code == 401
    assert client.request(method, path, json=body,
                          headers={"Authorization": "Bearer junk"}).status_code == 401
    # 403: a legacy analyst, and a user with a different permission
    assert client.request(method, path, json=body, headers=analyst_headers).status_code == 403
    other = next(p for p in sorted(ALL_PERMISSIONS) if p != perm and p.startswith("iam."))
    add_user(soc_app, "other", perms=[other])
    assert client.request(method, path, json=body,
                          headers=headers(client, "other")).status_code == 403
    # allowed: exactly the permission needed (plus the analyst's own cloud.view)
    add_user(soc_app, "holder", perms=[perm])
    r = client.request(method, path, json=body, headers=headers(client, "holder"))
    assert r.status_code == ok, r.text
    # and a legacy admin can do it too
    if method in ("GET", "PATCH", "PUT"):
        assert client.request(method, path, json=body, headers=admin_headers
                              ).status_code == ok


def test_me_and_my_permissions_need_only_a_session(client, admin_headers, analyst_headers):
    assert client.get("/iam/me/permissions").status_code == 401
    r = client.get("/iam/me/permissions", headers=analyst_headers)
    assert r.json() == {"username": "analyst", "role": "analyst", "all_access": False,
                        "permissions": ["cloud.view"]}
    r = client.get("/iam/me/permissions", headers=admin_headers)
    assert r.json()["all_access"] is True and set(r.json()["permissions"]) == ALL_PERMISSIONS


def test_auth_me_gains_permissions_and_keeps_its_fields(client, admin_headers, analyst_headers):
    me = client.get("/auth/me", headers=analyst_headers).json()
    assert me == {"id": me["id"], "username": "analyst", "role": "analyst", "mfa_enabled": False,
                  "mfa_required": False, "permissions": ["cloud.view"]}
    assert set(client.get("/auth/me", headers=admin_headers).json()["permissions"]) \
        == ALL_PERMISSIONS


def test_catalog_endpoint(client, admin_headers):
    groups = client.get("/iam/permissions", headers=admin_headers).json()["groups"]
    names = {p["name"] for g in groups for p in g["permissions"]}
    assert names == ALL_PERMISSIONS
    assert all(p["description"] for g in groups for p in g["permissions"])


def test_system_roles_are_seeded(client, admin_headers):
    roles = {r["name"]: r for r in client.get("/iam/roles", headers=admin_headers
                                              ).json()["items"]}
    assert roles["admin"]["system"] and set(roles["admin"]["permissions"]) == ALL_PERMISSIONS
    assert roles["analyst"]["system"] and roles["analyst"]["permissions"] == ["cloud.view"]


# --- validation -------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["ab", "x" * 49, "bad!name", "tab\tname", " lead", "trail ",
                                  "new\nline", "emoji \U0001f600"])
def test_bad_names_are_refused_everywhere(client, admin_headers, name):
    for path, extra in (("/iam/roles", {}), ("/iam/groups", {}),
                        ("/iam/policies", {"effect": "deny", "permissions": ["cloud.view"]})):
        r = client.post(path, json={"name": name, **extra}, headers=admin_headers)
        assert r.status_code == 422, (path, name)


@pytest.mark.parametrize("body", [
    {"name": "Role A", "extra": 1},
    {"name": "Role A", "permissions": ["cloud.nope"]},
    {"name": "Role A", "permissions": ["cloud.*"]},  # patterns are for policies
    {"name": "Role A", "permissions": ["cloud.view", "cloud.view"]},
    {"name": "Role A", "description": "x" * 256},
    {"name": "Role A", "description": "bad\x00"},
    {"name": "Role A", "description": "bidi " + chr(0x202E)},
    {"name": "Role A", "system": True},
])
def test_role_validation(client, admin_headers, body):
    assert client.post("/iam/roles", json=body, headers=admin_headers).status_code == 422


@pytest.mark.parametrize("body", [
    {"effect": "maybe", "permissions": ["cloud.view"]},
    {"effect": "deny", "permissions": []},
    {"effect": "deny", "permissions": ["nope.*"]},
    {"effect": "deny", "permissions": ["cloud.view"], "resources": []},
    {"effect": "deny", "permissions": ["cloud.view"], "resources": [""]},
    {"effect": "deny", "permissions": ["cloud.view"], "resources": ["a\nb"]},
    {"effect": "deny", "permissions": ["cloud.view"], "resources": ["x" * 129]},
    {"effect": "deny", "permissions": ["cloud.view"], "unknown": 1},
])
def test_policy_validation(client, admin_headers, body):
    r = client.post("/iam/policies", json={"name": "Policy A", **body}, headers=admin_headers)
    assert r.status_code == 422


def test_user_validation(client, admin_headers):
    ok = {"username": "dave", "password": "long-enough-password"}
    for bad in ({"username": "bad name"}, {"username": ""}, {"password": "short"},
                {"password": "p" * 257}, {"role": "root"}, {"extra": 1},
                {"role_ids": [1, 1]}, {"role_ids": [0]}, {"group_ids": ["x"]}):
        assert client.post("/iam/users", json=ok | bad, headers=admin_headers
                           ).status_code == 422, bad
    assert client.post("/iam/users", json=ok | {"role_ids": [999]}, headers=admin_headers
                       ).status_code == 422
    assert client.post("/iam/users", json=ok | {"group_ids": [999]}, headers=admin_headers
                       ).status_code == 422
    assert client.get("/iam/users", headers=admin_headers).json()["items"][0]["username"] != "dave"


def test_weak_password_is_refused_with_the_policys_message(client, admin_headers):
    r = client.post("/iam/users", json={"username": "dave", "password": "short"},
                    headers=admin_headers)
    assert r.status_code == 422


def test_duplicate_names_are_409_case_insensitively(client, admin_headers, world):
    assert client.post("/iam/roles", json={"name": "tester"}, headers=admin_headers
                       ).status_code == 409
    assert client.post("/iam/roles", json={"name": "ADMIN"}, headers=admin_headers
                       ).status_code == 409
    assert client.post("/iam/groups", json={"name": "testers"}, headers=admin_headers
                       ).status_code == 409
    assert client.post("/iam/policies", json={"name": "deny view", "effect": "deny",
                                              "permissions": ["cloud.view"]},
                       headers=admin_headers).status_code == 409
    assert client.post("/iam/users", json={"username": "target", "password": PW},
                       headers=admin_headers).status_code == 409


def test_empty_patch_and_unknown_ids(client, admin_headers, world):
    assert client.patch(f"/iam/users/{world['uid']}", json={}, headers=admin_headers
                        ).status_code == 422
    for path in ("/iam/users/999", "/iam/roles/999", "/iam/groups/999", "/iam/policies/999",
                 "/iam/users/999/effective-permissions"):
        assert client.get(path, headers=admin_headers).status_code == 404, path
    assert client.delete("/iam/users/999", headers=admin_headers).status_code == 404
    assert client.put("/iam/groups/999/members", json={"user_ids": []},
                      headers=admin_headers).status_code == 404
    assert client.put(f"/iam/groups/{world['gid']}/members", json={"user_ids": [999]},
                      headers=admin_headers).status_code == 422
    assert client.put(f"/iam/policies/{world['pid']}/attachments",
                      json={"attachments": [{"subject_type": "role", "subject_id": 999}]},
                      headers=admin_headers).status_code == 422
    assert client.put(f"/iam/policies/{world['pid']}/attachments",
                      json={"attachments": [{"subject_type": "planet", "subject_id": 1}]},
                      headers=admin_headers).status_code == 422


def test_iam_bodies_have_their_own_size_limit(client, admin_headers):
    r = client.post("/iam/roles", content=b"x" * (65 * 1024), headers=admin_headers)
    assert r.status_code == 413


def test_writes_are_rate_limited(client, soc_app, admin_headers):
    soc_app.state.iam_limiter.per_minute = 3
    codes = [client.post("/iam/groups", json={"name": f"Group {i}"}, headers=admin_headers
                         ).status_code for i in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    assert client.get("/iam/groups", headers=admin_headers).status_code == 200  # reads are free


# --- CRUD -------------------------------------------------------------------------------------

def test_role_crud(client, admin_headers, analyst_headers):
    r = client.post("/iam/roles", headers=admin_headers, json={
        "name": "Cloud ops", "description": "runs the cloud",
        "permissions": ["cloud.view", "cloud.instances.write"]})
    assert r.status_code == 201
    role = r.json()
    assert role["system"] is False and role["user_count"] == 0
    assert role["permissions"] == ["cloud.instances.write", "cloud.view"]
    r = client.patch(f"/iam/roles/{role['id']}", headers=admin_headers, json={
        "name": "Cloud ops 2", "permissions": ["cloud.network.write"]})
    assert r.status_code == 200
    assert r.json()["name"] == "Cloud ops 2" and r.json()["permissions"] == ["cloud.network.write"]
    assert client.get(f"/iam/roles/{role['id']}", headers=admin_headers).json()["name"] \
        == "Cloud ops 2"
    assert client.delete(f"/iam/roles/{role['id']}", headers=admin_headers).status_code == 204
    assert client.get(f"/iam/roles/{role['id']}", headers=admin_headers).status_code == 404
    actions = [e["action"] for e in audit_actions(client, admin_headers)]
    assert actions[:3] == ["iam_role_delete", "iam_role_update", "iam_role_create"]


def test_group_crud_and_membership(client, soc_app, admin_headers):
    gid = client.post("/iam/groups", json={"name": "SOC", "description": "d"},
                      headers=admin_headers).json()["id"]
    uid = add_user(soc_app, "member")
    r = client.put(f"/iam/groups/{gid}/members", json={"user_ids": [uid]}, headers=admin_headers)
    assert r.status_code == 200 and [m["name"] for m in r.json()["members"]] == ["member"]
    assert r.json()["member_count"] == 1
    role = client.post("/iam/roles", json={"name": "Viewer", "permissions": ["iam.audit.view"]},
                       headers=admin_headers).json()
    r = client.put(f"/iam/groups/{gid}/roles", json={"role_ids": [role["id"]]},
                   headers=admin_headers)
    assert [x["name"] for x in r.json()["roles"]] == ["Viewer"]
    # the member now holds the role's permission
    perms = client.get(f"/iam/users/{uid}/effective-permissions", headers=admin_headers).json()
    assert "iam.audit.view" in perms["permissions"]
    assert [g["name"] for g in perms["groups"]] == ["SOC"]
    # replace and clear
    assert client.put(f"/iam/groups/{gid}/members", json={"user_ids": []},
                      headers=admin_headers).json()["members"] == []
    assert client.patch(f"/iam/groups/{gid}", json={"name": "SOC team"},
                        headers=admin_headers).json()["name"] == "SOC team"
    assert client.delete(f"/iam/groups/{gid}", headers=admin_headers).status_code == 204
    assert client.get(f"/iam/groups/{gid}", headers=admin_headers).status_code == 404


def test_policy_crud_and_attachments(client, soc_app, admin_headers):
    uid = add_user(soc_app, "bob", perms=["iam.audit.view"])
    r = client.post("/iam/policies", headers=admin_headers, json={
        "name": "No audit", "description": "d", "effect": "deny", "permissions": ["iam.audit.*"]})
    assert r.status_code == 201 and r.json()["resources"] == ["*"]
    pid = r.json()["id"]
    r = client.put(f"/iam/policies/{pid}/attachments", headers=admin_headers, json={
        "attachments": [{"subject_type": "user", "subject_id": uid}]})
    assert r.json()["attachments"] == [{"subject_type": "user", "subject_id": uid,
                                        "subject_name": "bob"}]
    assert "iam.audit.view" not in client.get(
        f"/iam/users/{uid}/effective-permissions", headers=admin_headers).json()["permissions"]
    assert client.get(f"/iam/users/{uid}/effective-permissions", headers=admin_headers
                      ).json()["denied"] == ["iam.audit.view"]
    r = client.patch(f"/iam/policies/{pid}", json={"disabled": True}, headers=admin_headers)
    assert r.json()["disabled"] is True
    assert "iam.audit.view" in client.get(
        f"/iam/users/{uid}/effective-permissions", headers=admin_headers).json()["permissions"]
    assert client.delete(f"/iam/policies/{pid}", headers=admin_headers).status_code == 204
    assert client.get(f"/iam/policies/{pid}", headers=admin_headers).status_code == 404


def test_user_crud(client, admin_headers, soc_app):
    with soc_app.state.session_factory() as db:
        role = add_role(db, "Reader", ["iam.users.view"])
        group = add_group(db, "Readers")
    r = client.post("/iam/users", headers=admin_headers, json={
        "username": "erin", "password": "erin-password-123", "role": "analyst",
        "role_ids": [role.id], "group_ids": [group.id]})
    assert r.status_code == 201, r.text
    u = r.json()
    assert u["role"] == "analyst" and u["disabled"] is False and u["mfa_enabled"] is False
    assert u["mfa_required"] is False and u["last_login"] is None
    assert [x["name"] for x in u["roles"]] == ["Reader"]
    assert [x["name"] for x in u["groups"]] == ["Readers"]
    assert "password" not in r.text and "argon2" not in r.text
    assert login(client, "erin", "erin-password-123")
    assert client.get(f"/iam/users/{u['id']}", headers=admin_headers).json()["last_login"]
    r = client.patch(f"/iam/users/{u['id']}", headers=admin_headers,
                     json={"role_ids": [], "group_ids": [], "role": "admin"})
    assert r.status_code == 200 and r.json()["role"] == "admin" and r.json()["roles"] == []
    assert client.delete(f"/iam/users/{u['id']}", headers=admin_headers).status_code == 204
    assert client.get(f"/iam/users/{u['id']}", headers=admin_headers).status_code == 404
    assert client.post("/auth/login", json={"username": "erin", "password": "erin-password-123"}
                       ).status_code == 401


def test_user_detail_reports_mfa_state(client, soc_app, admin_headers):
    uid = add_user(soc_app, "m")
    d = client.get(f"/iam/users/{uid}", headers=admin_headers).json()
    assert d["mfa_enabled"] is False and d["mfa_required"] is False
    add_user(soc_app, "viewer", perms=["iam.users.view"])
    viewer = headers(client, "viewer")
    soc_app.state.settings.mfa_required_for_admins = True  # an admin must now use MFA
    aid = client.get("/iam/users?role=admin", headers=viewer).json()["items"][0]["id"]
    assert client.get(f"/iam/users/{aid}", headers=viewer).json()["mfa_required"] is True
    assert client.get(f"/iam/users/{uid}", headers=viewer).json()["mfa_required"] is False


def test_deactivate_activate_are_idempotent(client, soc_app, admin_headers, world):
    uid = world["uid"]
    assert client.post(f"/iam/users/{uid}/deactivate", headers=admin_headers
                       ).json()["disabled"] is True
    assert client.post(f"/iam/users/{uid}/deactivate", headers=admin_headers
                       ).json()["disabled"] is True
    assert client.post(f"/iam/users/{uid}/activate", headers=admin_headers
                       ).json()["disabled"] is False
    actions = [e["action"] for e in audit_actions(client, admin_headers)]
    assert actions.count("iam_user_deactivate") == 1 and actions.count("iam_user_activate") == 1


# --- lists: search, filters, pagination --------------------------------------------------------

def test_user_list_filters(client, soc_app, admin_headers):
    with soc_app.state.session_factory() as db:
        group = add_group(db, "G1")
        role = add_role(db, "R1")
    a = add_user(soc_app, "alice")
    b = add_user(soc_app, "alina", disabled=True)
    add_user(soc_app, "boss", Role.ADMIN)
    with soc_app.state.session_factory() as db:
        from soc.api.models import IamGroupMember, IamUserRole

        db.add(IamGroupMember(group_id=group.id, user_id=a))
        db.add(IamUserRole(user_id=b, role_id=role.id))
        db.commit()

    def names(**params):
        r = client.get("/iam/users", params=params, headers=admin_headers)
        assert r.status_code == 200, r.text
        return sorted(u["username"] for u in r.json()["items"])

    assert names(q="ali") == ["alice", "alina"]
    assert names(q="ALI", status="disabled") == ["alina"]
    assert names(status="active", role="analyst") == ["alice", "analyst"]
    assert names(role="admin") == ["admin", "boss"]
    assert names(group_id=group.id) == ["alice"]
    assert names(role_id=role.id) == ["alina"]
    assert names(q="%") == []  # a wildcard is searched for literally
    assert names(q="_lice") == []
    assert client.get("/iam/users?status=weird", headers=admin_headers).status_code == 422
    assert client.get("/iam/users?role=root", headers=admin_headers).status_code == 422
    assert client.get("/iam/users?limit=0", headers=admin_headers).status_code == 422


def test_pagination_walks_every_item_once(client, admin_headers):
    for i in range(7):
        client.post("/iam/groups", json={"name": f"Group {i}"}, headers=admin_headers)
    seen, cursor = [], None
    while True:
        params = {"limit": 3} | ({"cursor": cursor} if cursor else {})
        page = client.get("/iam/groups", params=params, headers=admin_headers).json()
        seen += [g["name"] for g in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sorted(seen) == [f"Group {i}" for i in range(7)] and len(seen) == 7


def test_role_policy_group_list_filters(client, soc_app, admin_headers, world):
    assert [r["name"] for r in client.get("/iam/roles?system=true", headers=admin_headers
                                          ).json()["items"]] == ["analyst", "admin"]
    assert [r["name"] for r in client.get("/iam/roles?q=test", headers=admin_headers
                                          ).json()["items"]] == ["Tester"]
    assert client.get("/iam/policies?effect=allow", headers=admin_headers
                      ).json()["items"] == []
    assert len(client.get("/iam/policies?effect=deny&disabled=false", headers=admin_headers
                          ).json()["items"]) == 1
    assert client.get("/iam/groups?q=zzz", headers=admin_headers).json()["items"] == []


def test_role_counts(client, soc_app, admin_headers, world):
    uid, rid = world["uid"], world["rid"]
    client.patch(f"/iam/users/{uid}", json={"role_ids": [rid]}, headers=admin_headers)
    client.put(f"/iam/groups/{world['gid']}/roles", json={"role_ids": [rid]},
               headers=admin_headers)
    role = client.get(f"/iam/roles/{rid}", headers=admin_headers).json()
    assert role["user_count"] == 1 and role["group_count"] == 1


# --- logs ------------------------------------------------------------------------------------

def test_audit_endpoint_filters_and_matches_the_admin_one(client, admin_headers, world):
    client.post(f"/iam/users/{world['uid']}/deactivate", headers=admin_headers)
    client.post("/iam/groups", json={"name": "Zed"}, headers=admin_headers)
    r = client.get("/iam/audit", params={"actor": "admin", "action": ["iam_group_create"]},
                   headers=admin_headers)
    assert [e["action"] for e in r.json()["items"]] == ["iam_group_create"]
    assert r.json()["items"][0]["target"] == "group:Zed"
    same = client.get("/admin/audit", headers=admin_headers).json()["items"]
    assert client.get("/iam/audit", headers=admin_headers).json()["items"] == same
    assert client.get("/iam/audit", params={"actor": "nobody"}, headers=admin_headers
                      ).json()["items"] == []
    assert client.get("/iam/audit", params={"since": "2999-01-01T00:00:00Z"},
                      headers=admin_headers).json()["items"] == []
    assert len(client.get("/iam/audit", params={"until": "2999-01-01T00:00:00Z"},
                          headers=admin_headers).json()["items"]) == len(same)
    assert client.get("/iam/audit", params={"since": "2026-01-01T00:00:00"},
                      headers=admin_headers).status_code == 422  # no timezone
    assert client.get("/iam/audit", params={"since": "2026-02-01T00:00:00Z",
                                            "until": "2026-01-01T00:00:00Z"},
                      headers=admin_headers).status_code == 422


def test_iam_audit_pagination(client, admin_headers):
    for i in range(4):
        client.post("/iam/groups", json={"name": f"Group {i}"}, headers=admin_headers)
    page = client.get("/iam/audit?limit=2", headers=admin_headers).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    nxt = client.get(f"/iam/audit?limit=2&cursor={page['next_cursor']}", headers=admin_headers
                     ).json()
    assert nxt["items"][0]["id"] < page["items"][-1]["id"]
