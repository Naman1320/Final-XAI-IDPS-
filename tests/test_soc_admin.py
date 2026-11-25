"""SOC API: admin routes, the last-admin rule, sensors and the audit log."""

import pytest
from conftest import ADMIN_PW, alert_payload, ingest, login

from soc.api.models import User


def users(client, headers):
    return {u["username"]: u for u in client.get("/admin/users", headers=headers).json()}


def test_list_users_never_leaks_secrets(client, admin_headers):
    r = client.get("/admin/users", headers=admin_headers)
    assert r.status_code == 200
    assert set(r.json()[0]) == {"id", "username", "role", "disabled", "created_at", "mfa_enabled",
                                "sso_linked"}  # never the TOTP secret, recovery codes or SSO ids
    assert "argon2" not in r.text and "password" not in r.text


def test_create_user_and_login(client, admin_headers):
    r = client.post("/admin/users", headers=admin_headers, json={
        "username": "carol", "password": "carol-password-123", "role": "analyst"})
    assert r.status_code == 201 and r.json()["role"] == "analyst"
    assert login(client, "carol", "carol-password-123")


@pytest.mark.parametrize("body,code", [
    ({"username": "analyst", "password": "another-password-1", "role": "analyst"}, 409),
    ({"username": "dave", "password": "short", "role": "analyst"}, 422),
    ({"username": "dave", "password": "long-enough-password", "role": "root"}, 422),
    ({"username": "bad name!", "password": "long-enough-password", "role": "analyst"}, 422),
    ({"username": "", "password": "long-enough-password", "role": "analyst"}, 422),
    ({"username": "x" * 65, "password": "long-enough-password", "role": "analyst"}, 422),
    ({"username": "dave", "password": "p" * 257, "role": "analyst"}, 422),
    ({"username": "dave", "password": "long-enough-password", "role": "analyst", "x": 1}, 422),
])
def test_create_user_failures(client, admin_headers, body, code):
    assert client.post("/admin/users", headers=admin_headers, json=body).status_code == code
    # a refused create must not leave an audit entry or a user behind
    assert "dave" not in users(client, admin_headers)
    actions = [e["action"] for e in client.get("/admin/audit", headers=admin_headers
                                               ).json()["items"]]
    assert "user_create" not in actions


def test_change_role_and_disable_take_effect_immediately(client, admin_headers, analyst_headers):
    uid = users(client, admin_headers)["analyst"]["id"]
    assert client.get("/admin/users", headers=analyst_headers).status_code == 403
    client.patch(f"/admin/users/{uid}/role", json={"role": "admin"}, headers=admin_headers)
    assert client.get("/admin/users", headers=analyst_headers).status_code == 200  # same token
    client.patch(f"/admin/users/{uid}/role", json={"role": "analyst"}, headers=admin_headers)
    assert client.get("/admin/users", headers=analyst_headers).status_code == 403
    r = client.post(f"/admin/users/{uid}/disable", headers=admin_headers)
    assert r.json()["disabled"] is True
    assert client.get("/auth/me", headers=analyst_headers).status_code == 401
    assert client.post("/auth/login", json={"username": "analyst",
                                            "password": "analyst-password-123"}).status_code == 401
    assert client.post(f"/admin/users/{uid}/enable", headers=admin_headers).json()["disabled"] is False
    assert login(client, "analyst", "analyst-password-123")


def test_reset_password(client, admin_headers, analyst_headers):
    uid = users(client, admin_headers)["analyst"]["id"]
    assert client.post(f"/admin/users/{uid}/reset-password", json={"password": "short"},
                       headers=admin_headers).status_code == 422
    assert client.get("/auth/me", headers=analyst_headers).status_code == 200  # unchanged
    r = client.post(f"/admin/users/{uid}/reset-password",
                    json={"password": "a-brand-new-password"}, headers=admin_headers)
    assert r.status_code == 200
    assert client.get("/auth/me", headers=analyst_headers).status_code == 401  # sessions ended
    assert login(client, "analyst", "a-brand-new-password")


def test_unknown_user_ids(client, admin_headers):
    assert client.patch("/admin/users/999/role", json={"role": "admin"},
                        headers=admin_headers).status_code == 404
    assert client.post("/admin/users/999/disable", headers=admin_headers).status_code == 404
    assert client.post("/admin/users/999/reset-password", json={"password": "x" * 14},
                       headers=admin_headers).status_code == 404


def test_last_admin_cannot_be_demoted_or_disabled(client, admin_headers):
    admin_id = users(client, admin_headers)["admin"]["id"]
    r = client.patch(f"/admin/users/{admin_id}/role", json={"role": "analyst"},
                     headers=admin_headers)
    assert r.status_code == 409
    assert client.post(f"/admin/users/{admin_id}/disable", headers=admin_headers).status_code == 409
    # still an enabled admin, and re-asserting the admin role is harmless
    assert client.patch(f"/admin/users/{admin_id}/role", json={"role": "admin"},
                        headers=admin_headers).status_code == 200
    assert users(client, admin_headers)["admin"]["disabled"] is False


def test_admins_may_remove_themselves_when_another_admin_exists(client, admin_headers, soc_app):
    client.post("/admin/users", headers=admin_headers, json={
        "username": "boss2", "password": "boss2-password-123", "role": "admin"})
    boss2 = users(client, admin_headers)["boss2"]["id"]
    admin_id = users(client, admin_headers)["admin"]["id"]
    assert client.patch(f"/admin/users/{admin_id}/role", json={"role": "analyst"},
                        headers=admin_headers).status_code == 200
    # now boss2 is the last admin
    boss_headers = login(client, "boss2", "boss2-password-123")
    assert client.post(f"/admin/users/{boss2}/disable", headers=boss_headers).status_code == 409
    assert client.patch(f"/admin/users/{boss2}/role", json={"role": "analyst"},
                        headers=boss_headers).status_code == 409


def test_a_disabled_admin_does_not_count(client, admin_headers):
    client.post("/admin/users", headers=admin_headers, json={
        "username": "boss2", "password": "boss2-password-123", "role": "admin"})
    boss2 = users(client, admin_headers)["boss2"]["id"]
    admin_id = users(client, admin_headers)["admin"]["id"]
    client.post(f"/admin/users/{boss2}/disable", headers=admin_headers)
    # boss2 is disabled, so "admin" is the only enabled admin
    assert client.post(f"/admin/users/{admin_id}/disable", headers=admin_headers).status_code == 409
    # re-enabling boss2 frees admin to step down
    client.post(f"/admin/users/{boss2}/enable", headers=admin_headers)
    assert client.post(f"/admin/users/{admin_id}/disable", headers=admin_headers).status_code == 200


def test_sensor_lifecycle(client, admin_headers):
    r = client.post("/admin/sensors", json={"name": "edge-1"}, headers=admin_headers)
    assert r.status_code == 201
    created = r.json()
    assert created["token"].startswith("idps_sensor_") and created["revoked"] is False
    listing = client.get("/admin/sensors", headers=admin_headers)
    assert "token" not in listing.text and "hash" not in listing.text
    headers = {"Authorization": f"Bearer {created['token']}"}
    assert client.post("/ingest/alerts", json={"alerts": [alert_payload()]},
                       headers=headers).status_code == 201
    assert client.post("/admin/sensors", json={"name": "edge-1"},
                       headers=admin_headers).status_code == 409
    revoked = client.post(f"/admin/sensors/{created['id']}/revoke", headers=admin_headers)
    assert revoked.json()["revoked"] is True
    assert client.post("/ingest/alerts", json={"alerts": [alert_payload()]},
                       headers=headers).status_code == 401
    assert client.post("/admin/sensors/999/revoke", headers=admin_headers).status_code == 404
    for bad in ({"name": ""}, {"name": "a b"}, {"name": "x" * 65}, {}):
        assert client.post("/admin/sensors", json=bad, headers=admin_headers).status_code == 422


def test_audit_log_records_every_mutation(client, admin_headers, analyst_headers, sensor_headers):
    ids = ingest(client, sensor_headers, alert_payload(), alert_payload())  # one batch -> one entry
    client.post("/ingest/blocks", headers=sensor_headers, json={"events": [
        {"event": "blocked", "ip": "198.51.100.9", "ttl_seconds": 60}]})
    sid = client.get("/admin/sensors", headers=admin_headers).json()[0]["id"]
    client.patch(f"/alerts/{ids[0]}", json={"status": "acknowledged"}, headers=analyst_headers)
    act = client.post("/actions", headers=analyst_headers, json={
        "kind": "block_ip", "ip": "198.51.100.9", "sensor_id": sid, "reason": "r"}).json()
    client.post(f"/sensor/actions/{act['id']}/result", headers=sensor_headers,
                json={"success": True})
    case = client.post("/cases", json={"title": "t"}, headers=analyst_headers).json()
    client.patch(f"/cases/{case['id']}", json={"status": "closed"}, headers=analyst_headers)
    client.post(f"/cases/{case['id']}/notes", json={"text": "n"}, headers=analyst_headers)
    client.post(f"/cases/{case['id']}/alerts", json={"alert_ids": ids}, headers=analyst_headers)
    client.delete(f"/cases/{case['id']}/alerts/{ids[0]}", headers=analyst_headers)
    client.delete(f"/cases/{case['id']}", headers=analyst_headers)
    client.post("/admin/users", headers=admin_headers, json={
        "username": "erin", "password": "erin-password-1234", "role": "analyst"})
    client.post("/admin/sensors", json={"name": "s9"}, headers=admin_headers)

    entries = client.get("/admin/audit?limit=500", headers=admin_headers).json()["items"]
    actions = [e["action"] for e in entries]
    for expected in ("ingest_alerts", "ingest_blocks", "alert_status", "action_request",
                     "action_result", "case_create", "case_update", "case_note", "case_attach",
                     "case_detach", "case_delete", "user_create", "sensor_create"):
        assert expected in actions, expected
    assert actions.count("ingest_alerts") == 1  # a batch is one entry
    batch = next(e for e in entries if e["action"] == "ingest_alerts")
    assert batch["actor_type"] == "sensor" and batch["actor_name"] == "sensor-1"
    assert batch["details"]["stored"] == 2
    status = next(e for e in entries if e["action"] == "alert_status")
    assert status["actor_type"] == "user" and status["actor_name"] == "analyst"
    assert status["details"] == {"from": "new", "to": "acknowledged"}
    assert "at" in status and status["target"] == f"alert:{ids[0]}"


def test_audit_records_admin_changes_and_decisions(client, admin_headers, soc_app, sensor_headers,
                                                   analyst_headers):
    uid = users(client, admin_headers)["analyst"]["id"]
    client.patch(f"/admin/users/{uid}/role", json={"role": "admin"}, headers=admin_headers)
    client.post(f"/admin/users/{uid}/disable", headers=admin_headers)
    client.post(f"/admin/users/{uid}/enable", headers=admin_headers)
    client.post(f"/admin/users/{uid}/reset-password", json={"password": "yet-another-pass-1"},
                headers=admin_headers)
    sid = client.get("/admin/sensors", headers=admin_headers).json()[0]["id"]
    client.post(f"/admin/sensors/{sid}/revoke", headers=admin_headers)
    from soc.api.models import Action, ActionKind, ActionStatus
    with soc_app.state.session_factory() as db:
        db.add_all([Action(kind=ActionKind.BLOCK_IP, params={"ip": "198.51.100.4"}, reason="r",
                           proposed_by="assistant", sensor_id=sid, status=ActionStatus.PENDING)
                    for _ in range(2)])
        db.commit()
    headers = login(client, "analyst", "yet-another-pass-1")
    client.post("/actions/1/confirm", headers=headers)
    client.post("/actions/2/reject", headers=headers)
    actions = {e["action"] for e in client.get("/admin/audit?limit=500",
                                               headers=admin_headers).json()["items"]}
    assert {"user_role", "user_disable", "user_enable", "user_reset_password", "sensor_revoke",
            "action_confirmed", "action_rejected"} <= actions
    text = client.get("/admin/audit?limit=500", headers=admin_headers).text
    assert "yet-another-pass-1" not in text


def test_audit_filters_and_pagination(client, admin_headers, analyst_headers, sensor_headers):
    (a,) = ingest(client, sensor_headers, alert_payload())
    for status in ("acknowledged", "resolved", "new"):
        client.patch(f"/alerts/{a}", json={"status": status}, headers=analyst_headers)
    by_actor = client.get("/admin/audit?actor=analyst", headers=admin_headers).json()["items"]
    assert len(by_actor) == 3 and {e["actor_name"] for e in by_actor} == {"analyst"}
    by_action = client.get("/admin/audit?action=ingest_alerts", headers=admin_headers).json()
    assert len(by_action["items"]) == 1
    page = client.get("/admin/audit?limit=2", headers=admin_headers).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    nxt = client.get(f"/admin/audit?limit=500&cursor={page['next_cursor']}",
                     headers=admin_headers).json()
    assert all(e["id"] < page["next_cursor"] for e in nxt["items"])
    assert client.get("/admin/audit?limit=501", headers=admin_headers).status_code == 422


def test_audit_filters_by_several_actions(client, admin_headers, analyst_headers, sensor_headers):
    (a,) = ingest(client, sensor_headers, alert_payload())
    client.patch(f"/alerts/{a}", json={"status": "acknowledged"}, headers=analyst_headers)
    everything = client.get("/admin/audit?limit=500", headers=admin_headers).json()["items"]
    assert {"ingest_alerts", "alert_status"} <= {e["action"] for e in everything}

    both = client.get("/admin/audit?action=ingest_alerts&action=alert_status&limit=500",
                      headers=admin_headers).json()["items"]
    assert {e["action"] for e in both} == {"ingest_alerts", "alert_status"}
    assert len(both) == sum(e["action"] in ("ingest_alerts", "alert_status") for e in everything)

    single = client.get("/admin/audit?action=alert_status", headers=admin_headers).json()["items"]
    assert single and {e["action"] for e in single} == {"alert_status"}

    other = client.get("/admin/audit?action=ingest_alerts&action=no_such_action",
                       headers=admin_headers).json()["items"]
    assert {e["action"] for e in other} == {"ingest_alerts"}


def test_audit_blank_action_values_are_ignored(client, admin_headers, analyst_headers, sensor_headers):
    (a,) = ingest(client, sensor_headers, alert_payload())
    client.patch(f"/alerts/{a}", json={"status": "acknowledged"}, headers=analyst_headers)
    plain = client.get("/admin/audit?limit=500", headers=admin_headers).json()["items"]
    blank = client.get("/admin/audit?limit=500&action=", headers=admin_headers)
    assert blank.status_code == 200
    assert [e["id"] for e in blank.json()["items"]] == [e["id"] for e in plain]
    assert {e["action"] for e in plain} > {"ingest_alerts"}  # the log really holds other kinds

    mixed = client.get("/admin/audit?limit=500&action=&action=ingest_alerts", headers=admin_headers)
    assert mixed.status_code == 200
    items = mixed.json()["items"]
    assert items and {e["action"] for e in items} == {"ingest_alerts"}


def test_audit_action_filter_is_capped_at_20_values(client, admin_headers):
    twenty = "&".join(f"action=a{i}" for i in range(20))
    assert client.get(f"/admin/audit?{twenty}", headers=admin_headers).status_code == 200
    twenty_one = "&".join(f"action=a{i}" for i in range(21))
    assert client.get(f"/admin/audit?{twenty_one}", headers=admin_headers).status_code == 422


def test_password_hash_column_is_never_exposed(client, admin_headers, soc_app):
    with soc_app.state.session_factory() as db:
        hashes = [u.password_hash for u in db.query(User)]
    blob = client.get("/admin/users", headers=admin_headers).text + client.get(
        "/auth/me", headers=admin_headers).text
    assert not any(h in blob for h in hashes) and ADMIN_PW not in blob
