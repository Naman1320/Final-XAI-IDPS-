"""SOC API: the live attack map on /ws/alerts: src_geo on alerts, typed block messages."""

import asyncio
import threading
from datetime import UTC, datetime, timedelta

import pytest
from conftest import TEST_SECRET, alert_payload, ingest

from soc.api.broadcast import AlertBroadcaster
from soc.api.geo import GeoLocator, Location
from soc.api.settings import SocSettings

GEO_KEYS = {"lat", "lon", "country", "city", "source"}
BLOCK_KEYS = {"type", "event", "sensor_id", "ip", "source", "at", "expires_at", "ttl_seconds",
              "reason", "geo"}


def _token(headers):
    return headers["Authorization"].removeprefix("Bearer ")


def listen(client, headers):
    ws = client.websocket_connect("/ws/alerts")
    sock = ws.__enter__()
    sock.send_json({"token": _token(headers)})
    assert sock.receive_json() == {"type": "ready"}  # unchanged
    return ws, sock


def post_events(client, headers, *events):
    return client.post("/ingest/blocks", headers=headers, json={"events": list(events)})


def use_demo(soc_app):
    soc_app.state.geo = GeoLocator(None, demo=True)


def test_alerts_carry_src_geo_from_the_demo_locator(client, soc_app, analyst_headers,
                                                    sensor_headers):
    use_demo(soc_app)
    ws, sock = listen(client, analyst_headers)
    try:
        (alert_id,) = ingest(client, sensor_headers, alert_payload(src_ip="10.10.1.10"))
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert msg["id"] == alert_id and msg["src_ip"] == "10.10.1.10"
    assert set(msg["src_geo"]) == GEO_KEYS
    assert msg["src_geo"]["source"] == "demo" and msg["src_geo"]["city"].startswith("Demo:")
    assert isinstance(msg["src_geo"]["lat"], float) and msg["src_geo"]["country"] is None
    assert "explanation" not in msg


def test_alerts_carry_src_geo_from_geoip(client, soc_app, analyst_headers, sensor_headers):
    locator = GeoLocator(None, demo=False)
    locator._cache["198.51.100.7"] = Location(48.85, 2.35, "FR", "Paris", "geoip")
    soc_app.state.geo = locator
    ws, sock = listen(client, analyst_headers)
    try:
        ingest(client, sensor_headers, alert_payload(src_ip="198.51.100.7"))
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert msg["src_geo"] == {"lat": 48.85, "lon": 2.35, "country": "FR", "city": "Paris",
                              "source": "geoip"}


def test_src_geo_is_null_when_the_source_has_no_location(client, analyst_headers, sensor_headers):
    ws, sock = listen(client, analyst_headers)  # no GeoIP database, no demo mode
    try:
        ingest(client, sensor_headers, alert_payload(src_ip="10.10.1.10"))
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert "src_geo" in msg and msg["src_geo"] is None
    assert msg["id"] >= 1  # the rest of the alert is as before


def test_src_geo_is_not_stored_or_returned_by_the_api(client, soc_app, analyst_headers,
                                                      sensor_headers):
    use_demo(soc_app)
    (alert_id,) = ingest(client, sensor_headers, alert_payload(src_ip="10.10.1.10"))
    listed = client.get("/alerts", headers=analyst_headers).json()["items"][0]
    assert "src_geo" not in listed
    assert "src_geo" not in client.get(f"/alerts/{alert_id}", headers=analyst_headers).json()


def test_a_failing_locator_does_not_fail_the_ingest(client, soc_app, analyst_headers,
                                                    sensor_headers):
    class Broken:
        demo = False

        def locate(self, ip):
            raise RuntimeError("database is gone")

    soc_app.state.geo = Broken()
    ws, sock = listen(client, analyst_headers)
    try:
        r = client.post("/ingest/alerts", headers=sensor_headers,
                        json={"alerts": [alert_payload()]})
        assert r.status_code == 201
        assert sock.receive_json()["src_geo"] is None
    finally:
        ws.__exit__(None, None, None)


# --- block messages ------------------------------------------------------------------------

def test_a_blocked_event_is_broadcast_with_the_full_shape(client, soc_app, analyst_headers,
                                                          sensor_headers):
    use_demo(soc_app)
    ws, sock = listen(client, analyst_headers)
    try:
        r = post_events(client, sensor_headers, {
            "event": "blocked", "ip": "10.10.1.10", "reason": "5 flows >= 0.9", "ttl_seconds": 600,
            "source": "auto"})
        assert r.status_code == 201
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert set(msg) == BLOCK_KEYS and "id" not in msg
    assert msg["type"] == "block" and msg["event"] == "blocked" and msg["ip"] == "10.10.1.10"
    assert msg["source"] == "auto" and msg["reason"] == "5 flows >= 0.9" and msg["sensor_id"] >= 1
    assert msg["ttl_seconds"] == 600 and msg["geo"]["source"] == "demo"
    at = datetime.fromisoformat(msg["at"])
    expires = datetime.fromisoformat(msg["expires_at"])
    assert abs(datetime.now(UTC) - at) < timedelta(seconds=30)
    assert abs((expires - at).total_seconds() - 600) < 2


def test_blocked_with_an_absolute_expiry_reports_the_remaining_ttl(client, analyst_headers,
                                                                    sensor_headers):
    ws, sock = listen(client, analyst_headers)
    try:
        end = datetime.now(UTC) + timedelta(seconds=300)
        post_events(client, sensor_headers, {"event": "blocked", "ip": "203.0.113.5",
                                             "expires_at": end.isoformat(), "source": "analyst"})
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert msg["source"] == "analyst" and msg["geo"] is None
    assert datetime.fromisoformat(msg["expires_at"]) == end
    assert 290 <= msg["ttl_seconds"] <= 300


def test_an_unblock_that_closed_a_block_is_broadcast(client, analyst_headers, sensor_headers):
    post_events(client, sensor_headers, {"event": "blocked", "ip": "203.0.113.5",
                                         "ttl_seconds": 600})
    ws, sock = listen(client, analyst_headers)
    try:
        post_events(client, sensor_headers, {"event": "unblocked", "ip": "203.0.113.5",
                                             "reason": "analyst action 4", "source": "analyst"})
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert set(msg) == BLOCK_KEYS and msg["event"] == "unblocked"
    assert msg["expires_at"] is None and msg["ttl_seconds"] is None
    assert msg["source"] == "analyst" and msg["reason"] == "analyst action 4"


def test_an_unblock_with_nothing_to_close_is_not_broadcast(client, analyst_headers,
                                                           sensor_headers):
    ws, sock = listen(client, analyst_headers)
    try:
        post_events(client, sensor_headers, {"event": "unblocked", "ip": "203.0.113.5"})
        ingest(client, sensor_headers, alert_payload())  # a marker: the next message is the alert
        assert "id" in sock.receive_json()
    finally:
        ws.__exit__(None, None, None)


def test_a_would_block_is_broadcast_with_its_decision_time(client, soc_app, analyst_headers,
                                                          sensor_headers):
    use_demo(soc_app)
    ws, sock = listen(client, analyst_headers)
    decided = datetime.now(UTC) - timedelta(minutes=5)
    try:
        post_events(client, sensor_headers, {
            "event": "would_block", "ip": "10.10.1.10", "reason": "dry run", "ttl_seconds": 900,
            "source": "analyst", "decided_at": decided.isoformat()})
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert set(msg) == BLOCK_KEYS and msg["event"] == "would_block"
    assert msg["source"] == "auto"  # forced: a sensor cannot claim an analyst
    assert abs((datetime.fromisoformat(msg["at"]) - decided).total_seconds()) < 1
    assert msg["expires_at"] is None and msg["ttl_seconds"] == 900


def test_one_message_per_event_in_order(client, analyst_headers, sensor_headers):
    ws, sock = listen(client, analyst_headers)
    try:
        post_events(client, sensor_headers,
                    {"event": "blocked", "ip": "203.0.113.1", "ttl_seconds": 60},
                    {"event": "would_block", "ip": "203.0.113.2"},
                    {"event": "blocked", "ip": "203.0.113.3", "ttl_seconds": 60})
        got = [sock.receive_json() for _ in range(3)]
    finally:
        ws.__exit__(None, None, None)
    assert [(m["event"], m["ip"]) for m in got] == [
        ("blocked", "203.0.113.1"), ("would_block", "203.0.113.2"), ("blocked", "203.0.113.3")]


def test_a_refused_batch_publishes_nothing(client, analyst_headers, sensor_headers):
    ws, sock = listen(client, analyst_headers)
    try:
        past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        for bad in (
            [{"event": "blocked", "ip": "203.0.113.1", "ttl_seconds": 60},
             {"event": "blocked", "ip": "203.0.113.2", "expires_at": past}],   # 2nd is in the past
            [{"event": "blocked", "ip": "not-an-ip"}],                            # invalid
            [{"event": "blocked", "ip": "203.0.113.4", "alert_id": 999}],         # unknown alert
        ):
            assert post_events(client, sensor_headers, *bad).status_code == 422
        assert post_events(client, {"Authorization": "Bearer idps_sensor_nope"},
                           {"event": "blocked", "ip": "203.0.113.9"}).status_code == 401
        ingest(client, sensor_headers, alert_payload())  # marker
        assert "id" in sock.receive_json()  # the alert is the first thing that arrived
    finally:
        ws.__exit__(None, None, None)


def test_alert_messages_and_ready_keep_their_shape(client, analyst_headers, sensor_headers):
    ws, sock = listen(client, analyst_headers)
    try:
        ingest(client, sensor_headers, alert_payload())
        msg = sock.receive_json()
    finally:
        ws.__exit__(None, None, None)
    assert set(msg) == {"id", "sensor_id", "received_at", "src_ip", "src_port", "dst_ip",
                        "dst_port", "protocol", "start_ms", "end_ms", "predicted_class",
                        "confidence", "anomaly_score", "severity", "status", "case_id", "src_geo",
                        "source", "rule"}
    assert msg["source"] == "ml" and msg["rule"] is None


# --- a flood of block events cannot starve alerts ------------------------------------------------

def test_a_block_flood_cannot_push_alerts_out():
    async def scenario():
        bus = AlertBroadcaster(max_subscribers=2, queue_size=10)
        sub = bus.subscribe()

        def flood():
            for i in range(200):
                bus.publish({"type": "block", "event": "blocked", "ip": f"10.0.0.{i % 250}"})
            for i in range(5):  # alerts after the flood: the half of the queue kept for them
                bus.publish({"id": i})

        thread = threading.Thread(target=flood)
        thread.start()
        thread.join()
        await asyncio.sleep(0.1)
        assert not sub.overflowed  # the client was not dropped for being flooded
        got = [await asyncio.wait_for(sub.next(), 1) for _ in range(sub.queue.qsize())]
        alerts = [m for m in got if "id" in m]
        blocks = [m for m in got if m.get("type") == "block"]
        assert len(alerts) == 5 and len(blocks) == 5  # blocks capped at half the queue
        assert sub.blocks_dropped == 195 and sub.blocks_queued == 0
        # after draining, blocks flow again
        bus.publish({"type": "block", "event": "blocked", "ip": "1.1.1.1"})
        await asyncio.sleep(0.05)
        assert sub.queue.qsize() == 1

    asyncio.run(scenario())


def test_alerts_still_overflow_a_slow_client_as_before():
    async def scenario():
        bus = AlertBroadcaster(max_subscribers=1, queue_size=4)
        sub = bus.subscribe()
        for i in range(20):
            bus.publish({"id": i})
        await asyncio.sleep(0.1)
        assert sub.overflowed and sub.queue.qsize() == 4

    asyncio.run(scenario())


def test_the_block_share_is_released_as_messages_are_consumed():
    async def scenario():
        bus = AlertBroadcaster(max_subscribers=1, queue_size=4)
        sub = bus.subscribe()
        for _ in range(4):
            bus.publish({"type": "block", "event": "blocked", "ip": "1.1.1.1"})
        await asyncio.sleep(0.05)
        assert sub.blocks_queued == 2 and sub.blocks_dropped == 2
        await sub.next()
        assert sub.blocks_queued == 1
        bus.publish({"type": "block", "event": "blocked", "ip": "1.1.1.2"})
        await asyncio.sleep(0.05)
        assert sub.blocks_queued == 2

    asyncio.run(scenario())


def test_a_flood_over_http_keeps_alert_delivery(client, soc_app, analyst_headers,
                                                sensor_headers):
    soc_app.state.broadcaster = AlertBroadcaster(10, 20)
    ws, sock = listen(client, analyst_headers)
    try:
        for i in range(30):  # 30 x 5 block events, far more than the queue holds
            post_events(client, sensor_headers, *[
                {"event": "would_block", "ip": f"203.0.113.{j + 1}"} for j in range(5)])
        ids = ingest(client, sensor_headers, alert_payload(), alert_payload())
        seen = []
        while len(seen) < 2:
            msg = sock.receive_json()  # raises if the socket was closed for being too slow
            if "id" in msg:
                seen.append(msg["id"])
    finally:
        ws.__exit__(None, None, None)
    assert seen == ids


# --- settings: blank values -------------------------------------------------------------------

def test_blank_home_and_geo_env_values_are_unset(monkeypatch):
    for name in ("IDPS_SOC_HOME_LAT", "IDPS_SOC_HOME_LON", "IDPS_SOC_GEOIP_DB"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("IDPS_SOC_HOME_LABEL", "")
    s = SocSettings(jwt_secret=TEST_SECRET)
    assert s.home_lat is None and s.home_lon is None and s.geoip_db is None
    assert s.home_label == "Protected site"


def test_real_home_values_still_parse_and_bad_ones_still_fail(monkeypatch):
    monkeypatch.setenv("IDPS_SOC_HOME_LAT", "28.6")
    monkeypatch.setenv("IDPS_SOC_HOME_LON", "77.2")
    monkeypatch.setenv("IDPS_SOC_HOME_LABEL", "Lab (demo)")
    s = SocSettings(jwt_secret=TEST_SECRET)
    assert (s.home_lat, s.home_lon, s.home_label) == (28.6, 77.2, "Lab (demo)")
    monkeypatch.setenv("IDPS_SOC_HOME_LAT", "north")
    with pytest.raises(ValueError):
        SocSettings(jwt_secret=TEST_SECRET)
    monkeypatch.setenv("IDPS_SOC_HOME_LAT", "91")
    with pytest.raises(ValueError):
        SocSettings(jwt_secret=TEST_SECRET)


def test_the_lab_compose_passes_the_home_settings():
    from pathlib import Path

    text = (Path(__file__).parent.parent / "lab" / "docker-compose.yml").read_text()
    assert "IDPS_SOC_HOME_LAT: ${LAB_SOC_HOME_LAT:-}" in text
    assert "IDPS_SOC_HOME_LON: ${LAB_SOC_HOME_LON:-}" in text
    assert "IDPS_SOC_HOME_LABEL: ${LAB_SOC_HOME_LABEL:-Lab (demo)}" in text


def test_geoip_db_blank_gives_a_locator_without_a_database(monkeypatch):
    monkeypatch.setenv("IDPS_SOC_GEOIP_DB", "")
    s = SocSettings(jwt_secret=TEST_SECRET)
    locator = GeoLocator(s.geoip_db, s.geo_demo)
    assert "IDPS_SOC_GEOIP_DB" in locator.status  # "not configured", not "could not be opened"


