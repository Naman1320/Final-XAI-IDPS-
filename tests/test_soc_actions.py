"""SOC API: blocks reported by sensors, and the action workflow."""

import pytest
from conftest import alert_payload, ingest

from soc.api.models import Action, ActionKind, ActionStatus, SensorToken


@pytest.fixture
def sensor_id(client, admin_headers, sensor_headers):
    return client.get("/admin/sensors", headers=admin_headers).json()[0]["id"]


def block_event(**kw):
    return {"event": "blocked", "ip": "203.0.113.7", "reason": "ssh brute force",
            "ttl_seconds": 600, "source": "auto"} | kw


def post_blocks(client, headers, *events):
    return client.post("/ingest/blocks", headers=headers, json={"events": list(events)})


# --- blocks -----------------------------------------------------------------------------

def test_block_and_unblock_lifecycle(client, sensor_headers, analyst_headers):
    (alert_id,) = ingest(client, sensor_headers, alert_payload())
    r = post_blocks(client, sensor_headers, block_event(alert_id=alert_id),
                    block_event(ip="2001:db8::5", ttl_seconds=None))
    assert r.status_code == 201 and r.json() == {"blocked": 2, "unblocked": 0, "would_block": 0}
    active = client.get("/blocks", params={"active": "true"}, headers=analyst_headers).json()
    assert {b["ip"] for b in active["items"]} == {"203.0.113.7", "2001:db8::5"}
    first = next(b for b in active["items"] if b["ip"] == "203.0.113.7")
    assert first["alert_id"] == alert_id and first["active"] and first["expires_at"]

    r = post_blocks(client, sensor_headers, {"event": "unblocked", "ip": "203.0.113.7"},
                    {"event": "unblocked", "ip": "198.51.100.1"})
    assert r.json() == {"blocked": 0, "unblocked": 1, "would_block": 0}
    now_active = client.get("/blocks?active=true", headers=analyst_headers).json()["items"]
    assert [b["ip"] for b in now_active] == ["2001:db8::5"]
    inactive = client.get("/blocks?active=false", headers=analyst_headers).json()["items"]
    assert [b["ip"] for b in inactive] == ["203.0.113.7"] and not inactive[0]["active"]
    assert len(client.get("/blocks", headers=analyst_headers).json()["items"]) == 2


def test_reblocking_refreshes_instead_of_duplicating(client, sensor_headers, analyst_headers):
    post_blocks(client, sensor_headers, block_event(), block_event(ttl_seconds=3000))
    assert len(client.get("/blocks", headers=analyst_headers).json()["items"]) == 1


def test_expired_blocks_are_not_active(client, sensor_headers, analyst_headers, soc_app):
    from datetime import UTC, datetime, timedelta

    from soc.api.models import Block
    post_blocks(client, sensor_headers, block_event())
    with soc_app.state.session_factory() as db:
        db.query(Block).update({Block.expires_at: datetime.now(UTC) - timedelta(seconds=1)})
        db.commit()
    assert client.get("/blocks?active=true", headers=analyst_headers).json()["items"] == []


@pytest.mark.parametrize("event", [
    block_event(ip="bad"), block_event(event="deleted"), block_event(ttl_seconds=0),
    block_event(ttl_seconds=10**9), block_event(reason="x" * 501), block_event(source="robot"),
    block_event(expires_at="2999-01-01T00:00:00Z"),  # both ttl and expires_at
    block_event(ttl_seconds=None, expires_at="2999-01-01T00:00:00"),  # naive
    block_event(ttl_seconds=None, expires_at="2000-01-01T00:00:00Z"),  # in the past
    block_event(alert_id=424242),
    {"event": "unblocked", "ip": "203.0.113.7", "ttl_seconds": 5},
])
def test_block_validation(client, sensor_headers, event):
    assert post_blocks(client, sensor_headers, event).status_code == 422


def test_block_batch_limits(client, sensor_headers):
    assert post_blocks(client, sensor_headers).status_code == 422
    assert post_blocks(client, sensor_headers, *[block_event()] * 101).status_code == 422


def test_blocks_pagination(client, sensor_headers, analyst_headers):
    post_blocks(client, sensor_headers, *[block_event(ip=f"198.51.100.{i}") for i in range(1, 6)])
    page = client.get("/blocks?limit=2", headers=analyst_headers).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    rest = client.get(f"/blocks?limit=10&cursor={page['next_cursor']}",
                      headers=analyst_headers).json()
    assert len(rest["items"]) == 3 and rest["next_cursor"] is None


# --- actions ----------------------------------------------------------------------------

def request_block(client, headers, sensor_id, /, **kw):
    return client.post("/actions", headers=headers, json={
        "kind": "block_ip", "ip": "203.0.113.50", "sensor_id": sensor_id,
        "reason": "scanning", "ttl_seconds": 300} | kw)


def test_analyst_request_is_confirmed_and_sensor_executes_it(
        client, analyst_headers, sensor_headers, sensor_id):
    r = request_block(client, analyst_headers, sensor_id)
    assert r.status_code == 201
    action = r.json()
    assert action["status"] == "confirmed" and action["proposed_by"] == "user"
    assert action["decided_by_id"] and action["params"] == {"ip": "203.0.113.50",
                                                            "ttl_seconds": 300}
    polled = client.get("/sensor/actions", headers=sensor_headers).json()
    assert [a["id"] for a in polled] == [action["id"]]
    done = client.post(f"/sensor/actions/{action['id']}/result", headers=sensor_headers,
                       json={"success": True, "result": {"rule": "nft #4"}})
    assert done.status_code == 200 and done.json()["status"] == "executed"
    assert done.json()["result"] == {"rule": "nft #4"}
    assert client.get("/sensor/actions", headers=sensor_headers).json() == []
    # a result can only be reported once
    assert client.post(f"/sensor/actions/{action['id']}/result", headers=sensor_headers,
                       json={"success": False}).status_code == 409
    assert client.get(f"/actions/{action['id']}", headers=analyst_headers).status_code == 200


def test_failed_result(client, analyst_headers, sensor_headers, sensor_id):
    action = request_block(client, analyst_headers, sensor_id).json()
    r = client.post(f"/sensor/actions/{action['id']}/result", headers=sensor_headers,
                    json={"success": False, "result": {"error": "nft missing"}})
    assert r.json()["status"] == "failed"


def test_sensors_only_see_and_answer_their_own_actions(
        client, admin_headers, analyst_headers, sensor_headers, sensor_id):
    other = client.post("/admin/sensors", json={"name": "sensor-2"}, headers=admin_headers).json()
    other_headers = {"Authorization": f"Bearer {other['token']}"}
    action = request_block(client, analyst_headers, other["id"]).json()
    assert client.get("/sensor/actions", headers=sensor_headers).json() == []
    assert client.post(f"/sensor/actions/{action['id']}/result", headers=sensor_headers,
                       json={"success": True}).status_code == 404
    assert len(client.get("/sensor/actions", headers=other_headers).json()) == 1


def test_result_validation(client, analyst_headers, sensor_headers, sensor_id):
    action = request_block(client, analyst_headers, sensor_id).json()
    url = f"/sensor/actions/{action['id']}/result"
    assert client.post(url, headers=sensor_headers,
                       json={"success": True, "result": {"x": "y" * 5000}}).status_code == 422
    assert client.post(url, headers=sensor_headers, json={"result": {}}).status_code == 422
    assert client.post("/sensor/actions/999/result", headers=sensor_headers,
                       json={"success": True}).status_code == 404


def test_unblock_action(client, analyst_headers, sensor_id):
    r = client.post("/actions", headers=analyst_headers, json={
        "kind": "unblock_ip", "ip": "203.0.113.50", "sensor_id": sensor_id, "reason": "mistake"})
    assert r.status_code == 201 and r.json()["kind"] == "unblock_ip"


@pytest.mark.parametrize("override", [
    {"ip": "nope"}, {"kind": "reboot"}, {"reason": ""}, {"reason": "x" * 501},
    {"ttl_seconds": 0}, {"sensor_id": 0}, {"sensor_id": 4242}, {"extra": 1},
])
def test_action_validation(client, analyst_headers, sensor_id, override):
    assert request_block(client, analyst_headers, sensor_id, **override).status_code == 422


def test_ttl_only_for_block(client, analyst_headers, sensor_id):
    r = client.post("/actions", headers=analyst_headers, json={
        "kind": "unblock_ip", "ip": "203.0.113.50", "sensor_id": sensor_id, "reason": "r",
        "ttl_seconds": 5})
    assert r.status_code == 422


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "::1", "224.0.0.1", "ff02::1", "169.254.1.1", "fe80::1", "0.0.0.0", "::",
    "::ffff:127.0.0.1", "255.255.255.255",
])
def test_block_refuses_non_routable_addresses(client, analyst_headers, sensor_id, ip):
    r = request_block(client, analyst_headers, sensor_id, ip=ip)
    assert r.status_code == 422, ip
    assert client.get("/actions", headers=analyst_headers).json()["items"] == []


def set_allowlist(soc_app, *nets):
    from ipaddress import ip_network

    soc_app.state.settings = soc_app.state.settings.model_copy(
        update={"block_allowlist": [ip_network(n) for n in nets]})


def test_block_refuses_allowlisted_addresses(client, soc_app, analyst_headers, sensor_id):
    set_allowlist(soc_app, "10.10.1.1", "192.0.2.0/24", "2001:db8:aa::/48")
    for ip in ("10.10.1.1", "192.0.2.77", "2001:db8:aa::9"):
        r = request_block(client, analyst_headers, sensor_id, ip=ip)
        assert r.status_code == 422 and "allowlist" in r.json()["detail"]
    assert request_block(client, analyst_headers, sensor_id, ip="10.10.1.2").status_code == 201
    # unblocking an allowlisted address is harmless and allowed
    assert client.post("/actions", headers=analyst_headers, json={
        "kind": "unblock_ip", "ip": "10.10.1.1", "sensor_id": sensor_id, "reason": "r",
    }).status_code == 201


def test_block_fails_closed_without_an_allowlist(client, soc_app, analyst_headers, sensor_id):
    set_allowlist(soc_app)  # IDPS_SOC_BLOCK_ALLOWLIST not configured
    r = request_block(client, analyst_headers, sensor_id)
    assert r.status_code == 503 and "IDPS_SOC_BLOCK_ALLOWLIST" in r.json()["detail"]
    # ...and the default settings really are empty (the reviewer's H1 scenario)
    from soc.api.settings import SocSettings

    assert SocSettings(jwt_secret="x" * 40).block_allowlist == []


def test_poll_keeps_confirmed_actions_while_blocking_is_unconfigured(
        client, soc_app, analyst_headers, sensor_headers, sensor_id):
    action = request_block(client, analyst_headers, sensor_id, ip="203.0.113.44").json()
    set_allowlist(soc_app)  # a temporary misconfiguration on the SOC host
    assert client.get("/sensor/actions", headers=sensor_headers).json() == []
    assert client.get(f"/actions/{action['id']}", headers=analyst_headers).json()["status"] \
        == "confirmed"
    set_allowlist(soc_app, "10.10.1.1")  # fixed: the action is handed out again
    assert [a["id"] for a in client.get("/sensor/actions", headers=sensor_headers).json()] \
        == [action["id"]]


@pytest.mark.parametrize("ip", ["2606:4700::1%eth0", "fe80::1%x }; flush ruleset",
                                "1" * 46, "2606:4700::1%" + "z" * 20_000])
def test_block_refuses_zone_ids_and_overlong_addresses(client, analyst_headers, sensor_id, ip):
    r = request_block(client, analyst_headers, sensor_id, ip=ip)
    assert r.status_code in (422, 413)  # the 20 KB one is cut by the body limit first
    assert len(r.content) < 2000  # the bad value isn't echoed back


def test_revoked_sensor_cannot_be_targeted(client, soc_app, analyst_headers, sensor_id):
    with soc_app.state.session_factory() as db:
        db.get(SensorToken, sensor_id).revoked = True
        db.commit()
    assert request_block(client, analyst_headers, sensor_id).status_code == 422


def _pending(soc_app, sensor_id, ip="203.0.113.60") -> int:
    with soc_app.state.session_factory() as db:
        action = Action(kind=ActionKind.BLOCK_IP, params={"ip": ip}, reason="assistant idea",
                        proposed_by="assistant", sensor_id=sensor_id,
                        status=ActionStatus.PENDING)
        db.add(action)
        db.commit()
        return action.id


def test_pending_actions_are_not_visible_to_sensors_until_confirmed(
        client, soc_app, analyst_headers, sensor_headers, sensor_id):
    action_id = _pending(soc_app, sensor_id)
    assert client.get("/sensor/actions", headers=sensor_headers).json() == []
    assert client.post(f"/sensor/actions/{action_id}/result", headers=sensor_headers,
                       json={"success": True}).status_code == 409
    r = client.post(f"/actions/{action_id}/confirm", headers=analyst_headers)
    assert r.status_code == 200 and r.json()["status"] == "confirmed"
    assert r.json()["decided_by_id"] and r.json()["proposed_by"] == "assistant"
    assert len(client.get("/sensor/actions", headers=sensor_headers).json()) == 1
    # already decided
    assert client.post(f"/actions/{action_id}/confirm", headers=analyst_headers).status_code == 409
    assert client.post(f"/actions/{action_id}/reject", headers=analyst_headers).status_code == 409


def test_reject(client, soc_app, analyst_headers, sensor_headers, sensor_id):
    action_id = _pending(soc_app, sensor_id)
    r = client.post(f"/actions/{action_id}/reject", headers=analyst_headers)
    assert r.json()["status"] == "rejected"
    assert client.get("/sensor/actions", headers=sensor_headers).json() == []
    pending = client.get("/actions?status=pending", headers=analyst_headers).json()["items"]
    assert pending == []
    assert client.post("/actions/999/confirm", headers=analyst_headers).status_code == 404


def test_confirm_rechecks_the_allowlist(client, soc_app, analyst_headers, sensor_id):
    action_id = _pending(soc_app, sensor_id, ip="10.10.1.1")
    set_allowlist(soc_app, "10.10.1.0/24")
    assert client.post(f"/actions/{action_id}/confirm", headers=analyst_headers).status_code == 422
    still = client.get(f"/actions/{action_id}", headers=analyst_headers).json()
    assert still["status"] == "pending"


def test_poll_refuses_actions_that_became_unsafe(
        client, soc_app, analyst_headers, sensor_headers, sensor_id):
    action = request_block(client, analyst_headers, sensor_id, ip="10.20.0.9").json()
    set_allowlist(soc_app, "10.20.0.0/24")
    assert client.get("/sensor/actions", headers=sensor_headers).json() == []
    done = client.get(f"/actions/{action['id']}", headers=analyst_headers).json()
    assert done["status"] == "failed" and "allowlist" in done["result"]["error"]


def test_actions_pagination(client, analyst_headers, sensor_id):
    for i in range(1, 5):
        request_block(client, analyst_headers, sensor_id, ip=f"198.51.100.{i}")
    page = client.get("/actions?limit=3", headers=analyst_headers).json()
    assert len(page["items"]) == 3 and page["next_cursor"]
    assert client.get("/actions?limit=501", headers=analyst_headers).status_code == 422


def test_the_allowlist_refusal_names_the_network_only_for_admins(
        client, analyst_headers, admin_headers, sensor_id):
    a = request_block(client, analyst_headers, sensor_id, ip="10.10.1.1")
    assert a.status_code == 422
    assert "can't be blocked" in a.json()["detail"] and "10.10.1.1" in a.json()["detail"]
    assert "10.10.1.1/32" not in a.text and "(" not in a.json()["detail"]
    assert "block allowlist (" not in a.text
    adm = request_block(client, admin_headers, sensor_id, ip="10.10.1.1")
    assert adm.status_code == 422 and "10.10.1.1/32" in adm.json()["detail"]


def test_confirming_a_pending_action_after_the_allowlist_changed_is_generic_for_analysts(
        client, soc_app, analyst_headers, admin_headers, sensor_id):
    from soc.api.models import Action, ActionKind, ActionStatus

    with soc_app.state.session_factory() as db:
        db.add(Action(kind=ActionKind.BLOCK_IP, params={"ip": "10.10.2.2"}, reason="x",
                      proposed_by="assistant", sensor_id=sensor_id, status=ActionStatus.PENDING))
        db.commit()
        action_id = db.query(Action).one().id
    r = client.post(f"/actions/{action_id}/confirm", headers=analyst_headers)
    assert r.status_code == 422 and "10.10.2.2/32" not in r.text
    r = client.post(f"/actions/{action_id}/confirm", headers=admin_headers)
    assert r.status_code == 422 and "10.10.2.2/32" in r.text


def test_the_action_reason_loses_control_and_direction_characters(
        client, analyst_headers, sensor_id):
    r = request_block(client, analyst_headers, sensor_id, reason="scan\u202e\n\x1b[31m ok\u200b")
    assert r.status_code == 201
    assert r.json()["reason"] == "scan[31m ok"


def test_a_nul_or_blank_action_reason_is_refused(client, analyst_headers, sensor_id):
    assert request_block(client, analyst_headers, sensor_id, reason="a\x00b").status_code == 422
    assert request_block(client, analyst_headers, sensor_id, reason="\u202e\n").status_code == 422
    assert request_block(client, analyst_headers, sensor_id, reason="   ").status_code == 422
