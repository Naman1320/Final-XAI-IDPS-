# ruff: noqa: F811  (the `pinned` fixture is imported from cloud_helpers)
"""Cloud management: permissions matrix, seed, CRUD, validation and state machines."""

import pytest
from cloud_helpers import ALL_WRITES, activity, by_name, denied_user, pinned, user_with  # noqa: F401
from iam_helpers import add_policy, add_user, audit_actions, headers

from soc.api.iam.deps import WriteLimiter

MOCK = "Mock data: no live cloud connected"

# (method, path, body, permission that must be held besides cloud.view)
ENDPOINTS = [
    ("GET", "/cloud/overview", None, None),
    ("GET", "/cloud/instances", None, None),
    ("GET", "/cloud/instances/{iid}", None, None),
    ("GET", "/cloud/instances/{iid}/metrics", None, None),
    ("GET", "/cloud/volumes", None, None),
    ("GET", "/cloud/volumes/{vid}", None, None),
    ("GET", "/cloud/buckets", None, None),
    ("GET", "/cloud/buckets/idps-demo-logs", None, None),
    ("GET", "/cloud/network/vpcs", None, None),
    ("GET", "/cloud/network/subnets", None, None),
    ("GET", "/cloud/network/security-groups", None, None),
    ("GET", "/cloud/network/security-groups/{sid}", None, None),
    ("GET", "/cloud/metrics/summary", None, None),
    ("GET", "/cloud/cost", None, None),
    ("GET", "/cloud/alerts", None, None),
    ("GET", "/cloud/notifications", None, None),
    ("GET", "/cloud/activity", None, None),
    ("POST", "/cloud/instances", {"name": "x"}, "cloud.instances.write"),
    ("PATCH", "/cloud/instances/{iid}", {"name": "renamed-1"}, "cloud.instances.write"),
    ("POST", "/cloud/instances/{iid}/start", None, "cloud.instances.write"),
    ("POST", "/cloud/instances/{iid}/stop", None, "cloud.instances.write"),
    ("POST", "/cloud/instances/{iid}/reboot", None, "cloud.instances.write"),
    ("DELETE", "/cloud/instances/{iid}", None, "cloud.instances.write"),
    ("POST", "/cloud/volumes", {"name": "v"}, "cloud.storage.write"),
    ("PATCH", "/cloud/volumes/{vid}", {"size_gb": 9999}, "cloud.storage.write"),
    ("POST", "/cloud/volumes/{vid}/attach", {"instance_id": "i-0"}, "cloud.storage.write"),
    ("POST", "/cloud/volumes/{vid}/detach", None, "cloud.storage.write"),
    ("DELETE", "/cloud/volumes/{vid}", None, "cloud.storage.write"),
    ("POST", "/cloud/buckets", {"name": "x"}, "cloud.storage.write"),
    ("PATCH", "/cloud/buckets/idps-demo-logs", {"versioning": True}, "cloud.storage.write"),
    ("DELETE", "/cloud/buckets/idps-demo-logs", None, "cloud.storage.write"),
    ("POST", "/cloud/network/security-groups", {"name": "x"}, "cloud.network.write"),
    ("DELETE", "/cloud/network/security-groups/{sid}", None, "cloud.network.write"),
    ("POST", "/cloud/network/security-groups/{sid}/rules", {"direction": "in"},
     "cloud.network.write"),
    ("DELETE", "/cloud/network/security-groups/{sid}/rules/1", None, "cloud.network.write"),
    ("POST", "/cloud/alerts/evaluate", None, "cloud.alerts.manage"),
    ("POST", "/cloud/alerts/{aid}/acknowledge", None, "cloud.alerts.manage"),
    ("POST", "/cloud/alerts/{aid}/resolve", None, "cloud.alerts.manage"),
    ("DELETE", "/cloud/alerts/{aid}", None, "cloud.alerts.manage"),
    ("POST", "/cloud/demo-data/reset", None, "ALL"),
]


def _ids(client, h):
    return {"iid": client.get("/cloud/instances", headers=h).json()["items"][0]["id"],
            "vid": client.get("/cloud/volumes", headers=h).json()["items"][0]["id"],
            "sid": client.get("/cloud/network/security-groups",
                              headers=h).json()["items"][0]["id"],
            "aid": client.get("/cloud/alerts", headers=h).json()["items"][0]["id"]}


def _url(path, ids):
    return path.format(**ids)


def test_every_cloud_route_is_in_the_matrix(soc_app):
    from test_soc_routes_auth import http_endpoints

    routes = {(m, p) for m, p in http_endpoints(soc_app) if p.startswith("/cloud")}

    def norm(path):
        for old, new in (("{iid}", "{instance_id}"), ("{vid}", "{volume_id}"),
                         ("{sid}", "{sg_id}"), ("{aid}", "{alert_id}")):
            path = path.replace(old, new)
        return path

    matrix = {(m, norm(p).replace("/idps-demo-logs", "/{name}").replace("/rules/1",
                                                                       "/rules/{rule_id}"))
              for m, p, _b, _p in ENDPOINTS}
    assert routes == matrix


def test_no_token_is_401_everywhere(client, soc_app, admin_headers):
    ids = _ids(client, admin_headers)
    for method, path, body, _perm in ENDPOINTS:
        r = client.request(method, _url(path, ids), json=body)
        assert r.status_code == 401, (method, path, r.status_code)
        r = client.request(method, _url(path, ids), json=body,
                           headers={"Authorization": "Bearer junk"})
        assert r.status_code == 401, (method, path)


def test_a_user_without_cloud_view_is_403_everywhere(client, soc_app, admin_headers):
    ids = _ids(client, admin_headers)
    h = denied_user(client, soc_app)
    for method, path, body, _perm in ENDPOINTS:
        r = client.request(method, _url(path, ids), json=body, headers=h)
        assert r.status_code == 403, (method, path, r.status_code)


def test_each_write_needs_its_own_permission(client, soc_app, admin_headers, analyst_headers):
    """cloud.view plus every write permission EXCEPT the one the route needs: always 403."""
    ids = _ids(client, admin_headers)
    for n, perm in enumerate(ALL_WRITES):
        h = user_with(client, soc_app, f"without{n}", [p for p in ALL_WRITES if p != perm])
        for method, path, body, need in ENDPOINTS:
            if need == perm or need == "ALL":
                r = client.request(method, _url(path, ids), json=body, headers=h)
                assert r.status_code == 403, (perm, method, path, r.status_code)
    # and the analyst, who holds cloud.view only, cannot write anything
    for method, path, body, need in ENDPOINTS:
        if need:
            r = client.request(method, _url(path, ids), json=body, headers=analyst_headers)
            assert r.status_code == 403, (method, path)


def test_holding_the_permission_gets_past_the_check(client, soc_app, admin_headers):
    """Never 401/403 (the answer may be 404, 409 or 422 for the made-up bodies, never a 5xx)."""
    ids = _ids(client, admin_headers)
    for need in ALL_WRITES:
        h = user_with(client, soc_app, f"has-{need}", [need])
        for method, path, body, perm in ENDPOINTS:
            if perm == need or perm is None:
                r = client.request(method, _url(path, ids), json=body, headers=h)
                assert r.status_code not in (401, 403) and r.status_code < 500, \
                    (need, method, path, r.status_code, r.text)
    h = user_with(client, soc_app, "everything", ALL_WRITES)
    r = client.post("/cloud/demo-data/reset", headers=h)
    assert r.status_code == 200, r.text
    # one write permission short of all: the reset is refused
    h = user_with(client, soc_app, "almost", ALL_WRITES[:3])
    assert client.post("/cloud/demo-data/reset", headers=h).status_code == 403


def test_a_refused_request_does_not_seed_the_inventory(client, soc_app):
    h = denied_user(client, soc_app)
    assert client.get("/cloud/instances", headers=h).status_code == 403
    assert client.get("/cloud/instances").status_code == 401
    with soc_app.state.session_factory() as db:
        from soc.api.models import CloudInstance

        assert db.query(CloudInstance).count() == 0


def test_the_legacy_admin_holds_every_cloud_permission(client, admin_headers):
    assert client.post("/cloud/alerts/evaluate", headers=admin_headers).status_code == 200


# --- seed ---------------------------------------------------------------------------------------

def test_seed_shape_and_honesty(client, pinned, admin_headers):
    r = client.get("/cloud/instances", headers=admin_headers, params={"limit": 200})
    body = r.json()
    assert body["data_source"] == "mock" and body["data_source_label"] == MOCK
    assert body["total"] == 8
    items = body["items"]
    assert len({i["az"] for i in items}) == 2
    assert {i["state"] for i in items} == {"running", "stopped", "terminated"}
    assert len({i["instance_type"] for i in items}) >= 5
    assert len(client.get("/cloud/buckets", headers=admin_headers).json()["items"]) == 4
    assert len(client.get("/cloud/network/vpcs", headers=admin_headers).json()["items"]) == 2
    assert len(client.get("/cloud/network/security-groups",
                          headers=admin_headers).json()["items"]) == 3
    assert len(client.get("/cloud/volumes", headers=admin_headers).json()["items"]) >= 5
    acts = activity(client, admin_headers)
    assert len(acts) >= 30 and {a["actor"] for a in acts} >= {"demo-seed", "demo-admin"}
    assert min(a["at"] for a in acts) <= "2026-03-02"  # 14 days of history behind T0
    cost = client.get("/cloud/cost", headers=admin_headers, params={"range": "90d"}).json()
    assert len([d for d in cost["by_day"] if d["total"] > 0]) == 90
    for path in ("overview", "metrics/summary", "cost", "alerts", "notifications", "activity",
                 "volumes", "buckets", "network/vpcs"):
        assert client.get(f"/cloud/{path}", headers=admin_headers).json()[
            "data_source"] == "mock"


def test_seed_is_idempotent(client, soc_app, pinned, admin_headers):
    from soc.api.cloud import seed
    from soc.api.models import CloudActivity, CloudCostDaily, CloudInstance

    first = client.get("/cloud/instances", headers=admin_headers).json()["items"]
    for _ in range(3):
        client.get("/cloud/overview", headers=admin_headers)
    with soc_app.state.session_factory() as db:
        assert seed.seed_if_empty(db) is False
        counts = (db.query(CloudInstance).count(), db.query(CloudActivity).count(),
                  db.query(CloudCostDaily).count())
    assert counts[0] == 8 and counts[2] == 90 * 4
    assert client.get("/cloud/instances", headers=admin_headers).json()["items"] == first
    with soc_app.state.session_factory() as db:
        assert db.query(CloudActivity).count() == counts[1]


def test_reset_wipes_changes_and_reseeds_the_same_demo_data(client, pinned, admin_headers):
    ids = [i["id"] for i in client.get("/cloud/instances", headers=admin_headers,
                                       params={"limit": 200}).json()["items"]]
    client.post("/cloud/buckets", json={"name": "my-new-bucket"}, headers=admin_headers)
    r = client.post("/cloud/demo-data/reset", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["demo_data"] is True and r.json()["created"]["instances"] == 8
    assert "mock" in r.json()["note"]
    after = client.get("/cloud/instances", headers=admin_headers, params={"limit": 200}).json()
    assert [i["id"] for i in after["items"]] == ids  # deterministic demo ids
    names = [b["name"] for b in client.get("/cloud/buckets", headers=admin_headers).json()["items"]]
    assert "my-new-bucket" not in names and len(names) == 4
    assert activity(client, admin_headers)[0]["action"] == "demo_data.reset"


# --- instances ----------------------------------------------------------------------------------

def _create_body(client, h, **over):
    subnets = client.get("/cloud/network/subnets", headers=h).json()["items"]
    sub = next(s for s in subnets if s["name"] == "prod-public-a")
    sg = next(g for g in client.get("/cloud/network/security-groups", headers=h).json()["items"]
              if g["name"] == "web-sg")
    return {"name": "new-vm", "instance_type": "t3.small", "subnet_id": sub["id"],
            "security_group_ids": [sg["id"]], **over}


def test_instance_list_filters_sort_and_pages(client, pinned, admin_headers):
    def get(**p):
        return client.get("/cloud/instances", headers=admin_headers, params=p).json()

    assert {i["state"] for i in get(state="running")["items"]} == {"running"}
    assert get(state="running")["total"] == 6
    assert [i["name"] for i in get(q="WEB")["items"]] == ["web-1", "web-2"]
    assert {i["instance_type"] for i in get(type="m5.large")["items"]} == {"m5.large"}
    az = get()["items"][0]["az"]
    assert {i["az"] for i in get(az=az)["items"]} == {az}
    names = [i["name"] for i in get(sort="name", order="desc")["items"]]
    assert names == sorted(names, reverse=True)
    first, second = get(limit=3, offset=0), get(limit=3, offset=3)
    assert len(first["items"]) == 3 and first["total"] == 8 and second["offset"] == 3
    assert not {i["id"] for i in first["items"]} & {i["id"] for i in second["items"]}
    for bad in ({"limit": 0}, {"limit": 201}, {"offset": -1}, {"state": "paused"},
                {"sort": "password"}, {"order": "up"}):
        assert client.get("/cloud/instances", headers=admin_headers, params=bad).status_code == 422


def test_instance_get_and_404(client, pinned, admin_headers):
    one = by_name(client, admin_headers, "api-1")
    r = client.get(f"/cloud/instances/{one['id']}", headers=admin_headers)
    assert r.status_code == 200 and r.json()["name"] == "api-1"
    assert r.json()["health"]["status"] in ("healthy", "degraded", "critical")
    assert r.json()["data_source"] == "mock" and r.json()["metrics_source"] == "mock"
    assert client.get("/cloud/instances/i-ffffffff", headers=admin_headers).status_code == 404
    assert client.get("/cloud/instances/bad id", headers=admin_headers).status_code == 422


def test_create_instance_then_it_settles_to_running(client, pinned, admin_headers):
    body = _create_body(client, admin_headers, tags={"team": "blue"}, disk_gb=50)
    r = client.post("/cloud/instances", json=body, headers=admin_headers)
    assert r.status_code == 201, r.text
    inst = r.json()
    assert inst["state"] == "pending" and inst["vcpus"] == 2 and inst["memory_gb"] == 2.0
    assert inst["id"].startswith("i-") and inst["private_ip"].startswith("10.0.1.")
    assert inst["public_ip"].startswith("203.0.113.")  # a documentation address, never a real one
    assert inst["tags"] == {"team": "blue"} and inst["disk_gb"] == 50
    assert "mock inventory only" in inst["note"]
    assert inst["health"]["status"] == "unknown"
    from datetime import timedelta
    pinned.set(pinned.value + timedelta(seconds=8))
    assert client.patch(f"/cloud/instances/{inst['id']}", json={"name": "renamed-pending"},
                        headers=admin_headers).status_code == 200
    pinned.set(pinned.value + timedelta(seconds=3))
    got = client.get(f"/cloud/instances/{inst['id']}", headers=admin_headers).json()
    assert got["state"] == "running" and got["health"]["status"] != "unknown"
    assert any(a["action"] == "instance.running" and a["actor"] == "system"
               for a in activity(client, admin_headers, resource_id=inst["id"]))


def test_create_instance_validation(client, pinned, admin_headers):
    base = _create_body(client, admin_headers)
    sub = base["subnet_id"]
    dev_sg = next(g["id"] for g in client.get("/cloud/network/security-groups",
                                              headers=admin_headers).json()["items"]
                  if g["name"] == "legacy-ssh")
    cases = [
        {"instance_type": "x99.huge"}, {"name": ""}, {"name": "bad name"},
        {"name": "x\u202ey"}, {"name": "a" * 64}, {"subnet_id": "subnet-nope"},
        {"security_group_ids": []}, {"security_group_ids": ["sg-nope"]},
        {"security_group_ids": [base["security_group_ids"][0]] * 2},
        {"security_group_ids": [dev_sg]},  # another VPC than the subnet
        {"az": "eu-west-1b"},  # the subnet is in a
        {"os": "Plan 9"}, {"disk_gb": 7}, {"disk_gb": 1001},
        {"tags": {f"k{n}": "v" for n in range(21)}}, {"tags": {"k": "v" * 129}},
        {"tags": {"bad\nkey": "v"}}, {"tags": {"k": "bell\x07"}}, {"unknown": 1},
        {"state": "running"},
    ]
    for over in cases:
        r = client.post("/cloud/instances", json={**base, **over}, headers=admin_headers)
        assert r.status_code == 422, (over, r.status_code, r.text)
    ok = client.post("/cloud/instances", json={**base, "az": "eu-west-1a"}, headers=admin_headers)
    assert ok.status_code == 201 and sub == ok.json()["subnet_id"]


def test_patch_instance(client, pinned, admin_headers):
    one = by_name(client, admin_headers, "web-1")
    r = client.patch(f"/cloud/instances/{one['id']}", headers=admin_headers,
                     json={"name": "web-one", "tags": {"env": "prod", "tier": "web"}})
    assert r.status_code == 200 and r.json()["name"] == "web-one"
    assert r.json()["tags"] == {"env": "prod", "tier": "web"}
    for bad in ({}, {"name": "bad name"}, {"state": "stopped"}, {"tags": {"k": 1}}, {"name": None,
                                                                                   "x": 1}):
        assert client.patch(f"/cloud/instances/{one['id']}", json=bad,
                            headers=admin_headers).status_code == 422, bad
    assert client.patch("/cloud/instances/i-ffffffff", json={"name": "abc"},
                        headers=admin_headers).status_code == 404


def test_instance_state_machine(client, pinned, admin_headers):
    from datetime import timedelta

    web = by_name(client, admin_headers, "web-1")["id"]
    build = by_name(client, admin_headers, "build-1")["id"]
    old = by_name(client, admin_headers, "batch-old")["id"]

    def act(verb, iid, method="POST"):
        url = f"/cloud/instances/{iid}" + ("" if method == "DELETE" else f"/{verb}")
        return client.request(method, url, headers=admin_headers)

    # wrong-state requests are 409 and change nothing
    for verb, iid in (("start", web), ("stop", build), ("reboot", build), ("start", old),
                      ("stop", old), ("reboot", old)):
        assert act(verb, iid).status_code == 409, (verb, iid)
    assert act("", old, "DELETE").status_code == 409  # already terminated
    assert client.patch(f"/cloud/instances/{old}", json={"name": "zombie"},
                        headers=admin_headers).status_code == 409
    # running: reboot, stop
    assert act("reboot", web).json()["state"] == "running"
    r = act("stop", web)
    assert r.json()["state"] == "stopped" and r.json()["public_ip"] is None
    assert r.json()["health"]["status"] == "unknown"
    # stopped: start (pending, then running with a new public address), terminate while pending: 409
    r = act("start", web)
    assert r.json()["state"] == "pending" and r.json()["public_ip"].startswith("203.0.113.")
    assert act("", web, "DELETE").status_code == 409
    assert act("stop", web).status_code == 409 and act("reboot", web).status_code == 409
    pinned.set(pinned.value + timedelta(seconds=11))
    assert client.get(f"/cloud/instances/{web}", headers=admin_headers).json()["state"] == "running"
    # terminate from stopped and from running; volumes of a terminated instance are released
    r = act("", build, "DELETE")
    assert r.status_code == 200 and r.json()["state"] == "terminated"
    vols = client.get("/cloud/volumes", headers=admin_headers, params={"instance_id": build})
    assert vols.json()["items"] == []
    assert act("", web, "DELETE").json()["state"] == "terminated"
    assert act("start", web).status_code == 409


def test_terminating_releases_volumes_and_logs_them(client, pinned, admin_headers):
    db1 = by_name(client, admin_headers, "db-1")["id"]
    attached = client.get("/cloud/volumes", headers=admin_headers,
                          params={"instance_id": db1}).json()["items"]
    assert attached
    assert client.delete(f"/cloud/instances/{db1}", headers=admin_headers).status_code == 200
    for v in attached:
        got = client.get(f"/cloud/volumes/{v['id']}", headers=admin_headers).json()
        assert got["state"] == "available" and got["instance_id"] is None
    ev = activity(client, admin_headers, action="instance.terminate", resource_id=db1)
    assert ev[0]["details"]["volumes_detached"] == sorted(v["id"] for v in attached)


# --- volumes ------------------------------------------------------------------------------------

def test_volume_lifecycle(client, pinned, admin_headers):
    r = client.post("/cloud/volumes", json={"name": "scratch-1", "size_gb": 20, "type": "gp2"},
                    headers=admin_headers)
    assert r.status_code == 201 and r.json()["state"] == "available"
    assert r.json()["encrypted"] is True and "mock inventory only" in r.json()["note"]
    vid = r.json()["id"]
    web = by_name(client, admin_headers, "web-2")["id"]
    assert client.post(f"/cloud/volumes/{vid}/detach", headers=admin_headers).status_code == 409
    r = client.post(f"/cloud/volumes/{vid}/attach", json={"instance_id": web},
                    headers=admin_headers)
    assert r.status_code == 200 and r.json()["state"] == "in-use"
    assert r.json()["instance_id"] == web
    assert client.post(f"/cloud/volumes/{vid}/attach", json={"instance_id": web},
                       headers=admin_headers).status_code == 409
    assert client.delete(f"/cloud/volumes/{vid}", headers=admin_headers).status_code == 409
    # grow only
    assert client.patch(f"/cloud/volumes/{vid}", json={"size_gb": 10},
                        headers=admin_headers).status_code == 422
    r = client.patch(f"/cloud/volumes/{vid}", json={"size_gb": 40, "name": "scratch-2"},
                     headers=admin_headers)
    assert r.status_code == 200 and r.json()["size_gb"] == 40 and r.json()["name"] == "scratch-2"
    assert client.post(f"/cloud/volumes/{vid}/detach",
                       headers=admin_headers).json()["state"] == "available"
    assert client.delete(f"/cloud/volumes/{vid}", headers=admin_headers).status_code == 200
    assert client.get(f"/cloud/volumes/{vid}", headers=admin_headers).status_code == 404


def test_volume_validation_and_attach_rules(client, pinned, admin_headers):
    for bad in ({"name": "v", "size_gb": 0}, {"name": "v", "size_gb": 16385},
                {"name": "v", "size_gb": 5, "type": "floppy"}, {"name": "v"},
                {"name": "v\x00", "size_gb": 5}, {"name": "v", "size_gb": 5, "x": 1}):
        assert client.post("/cloud/volumes", json=bad, headers=admin_headers).status_code == 422
    free = next(v for v in client.get("/cloud/volumes", headers=admin_headers).json()["items"]
                if v["state"] == "available")
    old = by_name(client, admin_headers, "batch-old")["id"]
    assert client.post(f"/cloud/volumes/{free['id']}/attach", json={"instance_id": old},
                       headers=admin_headers).status_code == 409
    assert client.post(f"/cloud/volumes/{free['id']}/attach", json={"instance_id": "i-nope"},
                       headers=admin_headers).status_code == 422
    assert client.patch(f"/cloud/volumes/{free['id']}", json={},
                        headers=admin_headers).status_code == 422
    assert client.patch("/cloud/volumes/vol-nope", json={"size_gb": 5},
                        headers=admin_headers).status_code == 404


# --- buckets ------------------------------------------------------------------------------------

def test_bucket_lifecycle(client, pinned, admin_headers):
    r = client.post("/cloud/buckets", json={"name": "demo.logs-2026"}, headers=admin_headers)
    assert r.status_code == 201
    assert r.json()["encrypted"] and r.json()["public_access_blocked"] and not r.json()["versioning"]
    assert client.post("/cloud/buckets", json={"name": "demo.logs-2026"},
                       headers=admin_headers).status_code == 409
    r = client.patch("/cloud/buckets/demo.logs-2026", headers=admin_headers,
                     json={"versioning": True, "encrypted": False, "public_access_blocked": False})
    assert r.json()["versioning"] is True and r.json()["encrypted"] is False
    assert r.json()["public_access_blocked"] is False
    assert client.patch("/cloud/buckets/demo.logs-2026", json={},
                        headers=admin_headers).status_code == 422
    assert client.delete("/cloud/buckets/demo.logs-2026", headers=admin_headers).status_code == 200
    assert client.get("/cloud/buckets/demo.logs-2026", headers=admin_headers).status_code == 404
    assert client.delete("/cloud/buckets/demo.logs-2026",
                         headers=admin_headers).status_code == 404


@pytest.mark.parametrize("name", ["ab", "UpperCase", "has_underscore", "-lead", "trail-",
                                  "a..b", "a.-b", "192.168.0.1", "x" * 64, "with space",
                                  "café-bucket", ".dot-lead"])
def test_bucket_names_must_be_dns_style(client, pinned, admin_headers, name):
    r = client.post("/cloud/buckets", json={"name": name}, headers=admin_headers)
    assert r.status_code == 422, name


def test_deleting_a_bucket_with_objects_needs_force(client, pinned, admin_headers):
    r = client.delete("/cloud/buckets/idps-demo-logs", headers=admin_headers)
    assert r.status_code == 409 and "125000" in r.json()["detail"]
    assert client.get("/cloud/buckets/idps-demo-logs", headers=admin_headers).status_code == 200
    r = client.delete("/cloud/buckets/idps-demo-logs", params={"force": "true"},
                      headers=admin_headers)
    assert r.status_code == 200
    ev = activity(client, admin_headers, action="bucket.delete")
    assert ev[0]["details"]["forced"] is True


# --- network ------------------------------------------------------------------------------------

def _sg(client, h, name):
    return next(g for g in client.get("/cloud/network/security-groups", headers=h).json()["items"]
                if g["name"] == name)


def test_network_reads(client, pinned, admin_headers):
    vpcs = client.get("/cloud/network/vpcs", headers=admin_headers).json()["items"]
    assert {v["name"] for v in vpcs} == {"prod-vpc", "dev-vpc"}
    assert all(v["subnet_count"] >= 2 for v in vpcs)
    prod = next(v for v in vpcs if v["name"] == "prod-vpc")
    subs = client.get("/cloud/network/subnets", headers=admin_headers,
                      params={"vpc_id": prod["id"]}).json()["items"]
    assert len(subs) == 4 and {s["az"] for s in subs} == {"eu-west-1a", "eu-west-1b"}
    assert _sg(client, admin_headers, "legacy-ssh")["open_to_world_admin_ports"] is True
    assert _sg(client, admin_headers, "web-sg")["open_to_world_admin_ports"] is False


def test_security_group_rules(client, pinned, admin_headers):
    sg = _sg(client, admin_headers, "app-sg")
    url = f"/cloud/network/security-groups/{sg['id']}/rules"
    r = client.post(url, headers=admin_headers, json={
        "direction": "in", "protocol": "udp", "port_from": 5000, "port_to": 5010,
        "cidr": "10.0.9.7/24", "description": "metrics"})
    assert r.status_code == 201, r.text
    rule = next(x for x in r.json()["rules"] if x["port_from"] == 5000)
    assert rule["cidr"] == "10.0.9.0/24"  # normalised
    assert client.post(url, headers=admin_headers, json={  # the same rule again
        "direction": "in", "protocol": "udp", "port_from": 5000, "port_to": 5010,
        "cidr": "10.0.9.0/24"}).status_code == 409
    r = client.post(url, headers=admin_headers, json={"direction": "out", "protocol": "icmp",
                                                       "cidr": "::/0"})
    assert r.status_code == 201
    assert any(x["protocol"] == "icmp" and x["port_to"] == 65535 for x in r.json()["rules"])
    r = client.delete(f"{url}/{rule['id']}", headers=admin_headers)
    assert r.status_code == 200 and all(x["id"] != rule["id"] for x in r.json()["rules"])
    assert client.delete(f"{url}/{rule['id']}", headers=admin_headers).status_code == 404
    other = _sg(client, admin_headers, "web-sg")["rules"][0]["id"]
    assert client.delete(f"{url}/{other}", headers=admin_headers).status_code == 404  # not its rule


@pytest.mark.parametrize("rule", [
    {"direction": "sideways", "protocol": "tcp", "port_from": 1, "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "sctp", "port_from": 1, "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "tcp", "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "tcp", "port_from": 70000, "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "tcp", "port_from": -1, "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "tcp", "port_from": 90, "port_to": 80, "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "all", "port_from": 80, "cidr": "10.0.0.0/8"},
    {"direction": "in", "protocol": "tcp", "port_from": 80, "cidr": "10.0.0.0/33"},
    {"direction": "in", "protocol": "tcp", "port_from": 80, "cidr": "not-a-cidr"},
    {"direction": "in", "protocol": "tcp", "port_from": 80, "cidr": "10.0.0.0/8; drop"},
    {"direction": "in", "protocol": "tcp", "port_from": 80, "cidr": "10.0.0.0/8", "x": 1},
    {"direction": "in", "protocol": "tcp", "port_from": 80, "cidr": "10.0.0.0/8",
     "description": "a\x00b"},
])
def test_rule_validation(client, pinned, admin_headers, rule):
    sg = _sg(client, admin_headers, "app-sg")
    r = client.post(f"/cloud/network/security-groups/{sg['id']}/rules", json=rule,
                    headers=admin_headers)
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("rule", [
    {"protocol": "tcp", "port_from": 22, "cidr": "0.0.0.0/0"},
    {"protocol": "tcp", "port_from": 3389, "cidr": "0.0.0.0/0"},
    {"protocol": "tcp", "port_from": 20, "port_to": 30, "cidr": "0.0.0.0/0"},  # covers 22
    {"protocol": "tcp", "port_from": 0, "port_to": 65535, "cidr": "::/0"},
    {"protocol": "all", "cidr": "0.0.0.0/0"},
])
def test_ssh_and_rdp_to_the_world_need_an_explicit_confirmation(client, pinned, admin_headers,
                                                                  rule):
    sg = _sg(client, admin_headers, "app-sg")
    url = f"/cloud/network/security-groups/{sg['id']}/rules"
    body = {"direction": "in", **rule}
    r = client.post(url, json=body, headers=admin_headers)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "confirm_open_to_world" and "internet" in r.json()["detail"]["message"]
    r = client.post(url, json={**body, "confirm_open_to_world": True}, headers=admin_headers)
    assert r.status_code == 201
    assert r.json()["open_to_world_admin_ports"] is True
    ev = activity(client, admin_headers, action="security_group.rule_add", resource_id=sg["id"])
    assert ev[0]["details"]["confirmed_open_to_world"] is True


def test_safe_world_and_private_rules_need_no_confirmation(client, pinned, admin_headers):
    sg = _sg(client, admin_headers, "app-sg")
    url = f"/cloud/network/security-groups/{sg['id']}/rules"
    for rule in ({"direction": "in", "protocol": "tcp", "port_from": 443, "cidr": "0.0.0.0/0"},
                 {"direction": "in", "protocol": "tcp", "port_from": 22, "cidr": "10.5.0.0/16"},
                 {"direction": "out", "protocol": "all", "cidr": "10.9.0.0/16"},
                 {"direction": "in", "protocol": "udp", "port_from": 22, "cidr": "0.0.0.0/0"}):
        assert client.post(url, json=rule, headers=admin_headers).status_code == 201, rule


def test_create_and_delete_security_group(client, pinned, admin_headers):
    vpc = client.get("/cloud/network/vpcs", headers=admin_headers).json()["items"][0]["id"]
    r = client.post("/cloud/network/security-groups", headers=admin_headers,
                    json={"name": "batch-sg", "description": "for batch", "vpc_id": vpc})
    assert r.status_code == 201 and r.json()["instances_using"] == 0
    assert [x["direction"] for x in r.json()["rules"]] == ["out"]  # egress open, nothing in
    sid = r.json()["id"]
    assert client.post("/cloud/network/security-groups", headers=admin_headers,
                       json={"name": "BATCH-SG", "vpc_id": vpc}).status_code == 409
    for bad in ({"name": "ab", "vpc_id": vpc}, {"name": "ok-name", "vpc_id": "vpc-nope"},
                {"name": "bad\x01name", "vpc_id": vpc}, {"name": "x" * 65, "vpc_id": vpc}):
        assert client.post("/cloud/network/security-groups", headers=admin_headers,
                           json=bad).status_code == 422, bad
    # in use: refused
    subnet = next(s for s in client.get("/cloud/network/subnets", headers=admin_headers,
                                        params={"vpc_id": vpc}).json()["items"])
    made = client.post("/cloud/instances", headers=admin_headers, json={
        "name": "uses-sg", "instance_type": "t3.micro", "subnet_id": subnet["id"],
        "security_group_ids": [sid]})
    assert made.status_code == 201, made.text
    r = client.delete(f"/cloud/network/security-groups/{sid}", headers=admin_headers)
    assert r.status_code == 409 and "used by 1" in r.json()["detail"]
    # a terminated instance no longer holds it
    assert client.post(f"/cloud/instances/{made.json()['id']}/stop",
                       headers=admin_headers).status_code == 409  # still pending
    from datetime import timedelta
    pinned.set(pinned.value + timedelta(seconds=15))
    client.get("/cloud/overview", headers=admin_headers)  # settles
    assert client.delete(f"/cloud/instances/{made.json()['id']}",
                         headers=admin_headers).status_code == 200
    assert client.delete(f"/cloud/network/security-groups/{sid}",
                         headers=admin_headers).status_code == 200
    assert client.delete(f"/cloud/network/security-groups/{sid}",
                         headers=admin_headers).status_code == 404


# --- activity, audit, limits ---------------------------------------------------------------------

def test_every_mutation_writes_activity_and_an_audit_row(client, pinned, admin_headers):
    h = admin_headers
    web = by_name(client, h, "web-1")["id"]
    build = by_name(client, h, "build-1")["id"]
    sg = _sg(client, h, "app-sg")["id"]
    vol = next(v["id"] for v in client.get("/cloud/volumes", headers=h).json()["items"]
               if v["state"] == "available")
    alert = client.get("/cloud/alerts", headers=h, params={"status": "open"}).json()["items"][0]
    steps = [
        ("POST", "/cloud/instances", _create_body(client, h), "instance.create"),
        ("PATCH", f"/cloud/instances/{web}", {"name": "web-x"}, "instance.update"),
        ("POST", f"/cloud/instances/{web}/reboot", None, "instance.reboot"),
        ("POST", f"/cloud/instances/{web}/stop", None, "instance.stop"),
        ("POST", f"/cloud/instances/{web}/start", None, "instance.start"),
        ("DELETE", f"/cloud/instances/{build}", None, "instance.terminate"),
        ("POST", "/cloud/volumes", {"name": "vv", "size_gb": 5}, "volume.create"),
        ("PATCH", f"/cloud/volumes/{vol}", {"size_gb": 999}, "volume.update"),
        ("POST", f"/cloud/volumes/{vol}/attach", {"instance_id": web}, "volume.attach"),
        ("POST", f"/cloud/volumes/{vol}/detach", None, "volume.detach"),
        ("DELETE", f"/cloud/volumes/{vol}", None, "volume.delete"),
        ("POST", "/cloud/buckets", {"name": "act-bucket"}, "bucket.create"),
        ("PATCH", "/cloud/buckets/act-bucket", {"versioning": True}, "bucket.update"),
        ("DELETE", "/cloud/buckets/act-bucket", None, "bucket.delete"),
        ("POST", "/cloud/network/security-groups",
         {"name": "act-sg", "vpc_id": _sg(client, h, "app-sg")["vpc_id"]}, "security_group.create"),
        ("POST", f"/cloud/network/security-groups/{sg}/rules",
         {"direction": "in", "protocol": "tcp", "port_from": 9, "cidr": "10.0.0.0/8"},
         "security_group.rule_add"),
        ("POST", "/cloud/alerts/evaluate", None, "alert.evaluate"),
        ("POST", f"/cloud/alerts/{alert['id']}/acknowledge", None, "alert.acknowledge"),
        ("POST", f"/cloud/alerts/{alert['id']}/resolve", None, "alert.resolve"),
        ("DELETE", f"/cloud/alerts/{alert['id']}", None, "alert.delete"),
        ("POST", "/cloud/demo-data/reset", None, "demo_data.reset"),
    ]
    for method, path, body, action in steps:
        before = len(activity(client, h, action=action))
        audit_before = len([a for a in audit_actions(client, h)
                            if a["action"] == "cloud_" + action.replace(".", "_")])
        r = client.request(method, path, json=body, headers=h)
        assert r.status_code in (200, 201), (action, r.status_code, r.text)
        if action != "demo_data.reset":
            assert len(activity(client, h, action=action)) == before + 1, action
        rows = [a for a in audit_actions(client, h)
                if a["action"] == "cloud_" + action.replace(".", "_")]
        assert len(rows) == audit_before + 1, action
        assert rows[0]["actor_name"] == "admin" and rows[0]["details"]["data_source"] == "mock"
    sgid = next(g["id"] for g in client.get("/cloud/network/security-groups",
                                            headers=h).json()["items"] if g["name"] == "app-sg")
    rid = client.get(f"/cloud/network/security-groups/{sgid}", headers=h).json()["rules"][0]["id"]
    assert client.delete(f"/cloud/network/security-groups/{sgid}/rules/{rid}",
                         headers=h).status_code == 200
    assert activity(client, h, action="security_group.rule_delete")
    new = client.post("/cloud/network/security-groups", headers=h,
                      json={"name": "gone-sg", "vpc_id": _sg(client, h, "app-sg")["vpc_id"]})
    assert client.delete(f"/cloud/network/security-groups/{new.json()['id']}",
                         headers=h).status_code == 200
    assert activity(client, h, action="security_group.delete")


def test_a_failed_change_leaves_no_trace(client, pinned, admin_headers):
    h = admin_headers
    web = by_name(client, h, "web-1")["id"]
    n_act = len(activity(client, h))
    n_audit = len(audit_actions(client, h))
    assert client.post(f"/cloud/instances/{web}/start", headers=h).status_code == 409
    assert client.post("/cloud/buckets", json={"name": "Bad Name"}, headers=h).status_code == 422
    assert client.delete("/cloud/buckets/idps-demo-logs", headers=h).status_code == 409
    assert len(activity(client, h)) == n_act and len(audit_actions(client, h)) == n_audit
    assert by_name(client, h, "web-1")["state"] == "running"


def test_activity_filters_and_pages(client, pinned, admin_headers):
    h = admin_headers
    web = by_name(client, h, "web-1")["id"]
    client.post(f"/cloud/instances/{web}/reboot", headers=h)
    assert all(a["actor"] == "admin" for a in activity(client, h, actor="admin"))
    assert activity(client, h, actor="admin")[0]["action"] == "instance.reboot"
    assert {a["resource_id"] for a in activity(client, h, resource_id=web)} == {web}
    assert {a["action"] for a in activity(client, h, action="instance.create")} == {
        "instance.create"}
    assert {a["resource_type"] for a in activity(client, h, resource_type="bucket")} == {"bucket"}
    r = client.get("/cloud/activity", headers=h, params={"limit": 5, "offset": 5}).json()
    assert len(r["items"]) == 5 and r["offset"] == 5 and r["total"] > 10
    ats = [a["at"] for a in activity(client, h)]
    assert ats == sorted(ats, reverse=True)
    assert client.get("/cloud/activity", headers=h, params={"limit": 0}).status_code == 422


def test_writes_are_rate_limited_per_user(client, soc_app, pinned, admin_headers):
    soc_app.state.cloud_limiter = WriteLimiter(per_minute=3)
    codes = [client.post("/cloud/buckets", json={"name": f"rate-{n}-bucket"},
                         headers=admin_headers).status_code for n in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    assert client.get("/cloud/buckets", headers=admin_headers).status_code == 200  # reads are free


def test_a_large_body_is_413(client, pinned, admin_headers):
    r = client.post("/cloud/instances", headers=admin_headers,
                    content=b'{"name": "' + b"a" * 40_000 + b'"}',
                    )
    assert r.status_code == 413


def test_bad_json_and_wrong_types_are_422_not_500(client, pinned, admin_headers):
    for body in ('{"name": ', '[]', '"x"', '{"name": 5}'):
        r = client.post("/cloud/buckets", content=body, headers={
            **admin_headers, "Content-Type": "application/json"})
        assert r.status_code == 422, body


# --- resource-scoped policies ---------------------------------------------------------------------

def test_a_deny_policy_scoped_to_one_instance_blocks_only_that_one(client, soc_app, pinned,
                                                                   admin_headers):
    a = by_name(client, admin_headers, "web-1")["id"]
    b = by_name(client, admin_headers, "web-2")["id"]
    uid = add_user(soc_app, "ops", perms=["cloud.instances.write", "cloud.storage.write"])
    with soc_app.state.session_factory() as db:
        add_policy(db, "Protect web-1", "deny", ["cloud.instances.write"],
                   resources=[f"instance:{a}"], attach=[("user", uid)])
    h = headers(client, "ops")
    # the generic check still passes: she can create instances and change the other one
    assert client.post(f"/cloud/instances/{b}/reboot", headers=h).status_code == 200
    assert client.patch(f"/cloud/instances/{b}", json={"name": "web-two"},
                        headers=h).status_code == 200
    for method, url, body in (("POST", f"/cloud/instances/{a}/reboot", None),
                              ("POST", f"/cloud/instances/{a}/stop", None),
                              ("PATCH", f"/cloud/instances/{a}", {"name": "mine-now"}),
                              ("DELETE", f"/cloud/instances/{a}", None)):
        r = client.request(method, url, json=body, headers=h)
        assert r.status_code == 403, (method, url)
        assert "instance:" + a in r.json()["detail"]
    assert by_name(client, admin_headers, "web-1")["state"] == "running"
    assert by_name(client, admin_headers, "web-1")["name"] == "web-1"
    assert client.post(f"/cloud/instances/{a}/reboot", headers=admin_headers).status_code == 200
    # nothing was logged for the refused changes by "ops" on that instance
    assert not [x for x in activity(client, admin_headers, resource_id=a) if x["actor"] == "ops"]


def test_a_scoped_deny_on_a_bucket_and_a_security_group(client, soc_app, pinned, admin_headers):
    sg = _sg(client, admin_headers, "app-sg")["id"]
    uid = add_user(soc_app, "ops2", perms=["cloud.storage.write", "cloud.network.write"])
    with soc_app.state.session_factory() as db:
        add_policy(db, "Protect", "deny", ["cloud.storage.write", "cloud.network.write"],
                   resources=["bucket:idps-demo-logs", f"securitygroup:{sg}"],
                   attach=[("user", uid)])
    h = headers(client, "ops2")
    assert client.patch("/cloud/buckets/idps-demo-logs", json={"versioning": False},
                        headers=h).status_code == 403
    assert client.patch("/cloud/buckets/idps-demo-backups", json={"versioning": False},
                        headers=h).status_code == 200
    rule = {"direction": "in", "protocol": "tcp", "port_from": 9, "cidr": "10.0.0.0/8"}
    assert client.post(f"/cloud/network/security-groups/{sg}/rules", json=rule,
                       headers=h).status_code == 403
    web = _sg(client, admin_headers, "web-sg")["id"]
    assert client.post(f"/cloud/network/security-groups/{web}/rules", json=rule,
                       headers=h).status_code == 201


def test_a_policy_change_applies_at_once(client, soc_app, pinned, admin_headers):
    uid = add_user(soc_app, "ops3", perms=["cloud.instances.write"])
    h = headers(client, "ops3")
    web = by_name(client, admin_headers, "web-1")["id"]
    assert client.post(f"/cloud/instances/{web}/reboot", headers=h).status_code == 200
    with soc_app.state.session_factory() as db:
        add_policy(db, "Freeze", "deny", ["cloud.instances.write"], attach=[("user", uid)])
    # a deny on every resource also removes the general permission
    assert client.post(f"/cloud/instances/{web}/reboot", headers=h).status_code == 403

def test_combined_ranges_need_confirmation_and_generate_a_finding(client, pinned, admin_headers):
    sg = _sg(client, admin_headers, "app-sg")
    url = f"/cloud/network/security-groups/{sg['id']}/rules"
    rule = {"direction": "in", "protocol": "tcp", "port_from": 22, "cidr": "0.0.0.0/1"}
    assert client.post(url, json=rule, headers=admin_headers).status_code == 201
    rule["cidr"] = "128.0.0.0/1"
    refusal = client.post(url, json=rule, headers=admin_headers)
    assert refusal.status_code == 422 and refusal.json()["detail"]["code"] == "confirm_open_to_world"
    assert client.post(url, json={**rule, "confirm_open_to_world": True},
                       headers=admin_headers).json()["open_to_world_admin_ports"]
    findings = client.post("/cloud/alerts/evaluate", headers=admin_headers).json()["created"]
    assert any(a["rule"] == "sg_open_admin" and a["resource_id"] == sg["id"] for a in findings)


def test_scoped_alert_deny_applies_to_all_triage_writes(client, soc_app, pinned, admin_headers):
    aid = client.get("/cloud/alerts", headers=admin_headers).json()["items"][0]["id"]
    uid = add_user(soc_app, "triage", perms=["cloud.alerts.manage"])
    with soc_app.state.session_factory() as db:
        add_policy(db, "Protected alert", "deny", ["cloud.alerts.manage"],
                   resources=[f"alert:{aid}"], attach=[("user", uid)])
    h = headers(client, "triage")
    for method, suffix in [("POST", "/resolve"), ("POST", "/acknowledge"), ("DELETE", "")]:
        assert client.request(method, f"/cloud/alerts/{aid}{suffix}", headers=h).status_code == 403
