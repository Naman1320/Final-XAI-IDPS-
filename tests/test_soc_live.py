"""SOC API: the /ws/alerts live feed and its authentication."""

import asyncio
import contextlib
import threading
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from conftest import ADMIN_PW, TEST_SECRET, alert_payload, ingest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from soc.api import auth
from soc.api.broadcast import AlertBroadcaster
from soc.api.main import create_app
from soc.api.models import Role, User
from soc.api.routes import live


def _token(headers):
    return headers["Authorization"].removeprefix("Bearer ")


def _expect_close(ws, code=4401):
    with pytest.raises(WebSocketDisconnect) as info:
        ws.receive_json()
    assert info.value.code == code


def test_good_token_receives_ingested_alerts(client, analyst_headers, sensor_headers):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": _token(analyst_headers)})
        assert ws.receive_json() == {"type": "ready"}
        ids = ingest(client, sensor_headers, alert_payload(), alert_payload(predicted_class="Bot"))
        got = [ws.receive_json(), ws.receive_json()]
    assert [a["id"] for a in got] == ids
    assert got[1]["predicted_class"] == "Bot" and got[1]["severity"] == "high"
    assert "explanation" not in got[0]


def test_benign_is_not_broadcast(client, analyst_headers, sensor_headers):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": _token(analyst_headers)})
        ws.receive_json()
        ingest(client, sensor_headers, alert_payload(predicted_class="BENIGN"), alert_payload())
        assert ws.receive_json()["predicted_class"] == "SSH-Patator"


@pytest.mark.parametrize("first", [
    {"token": "garbage"}, {"token": ""}, {"token": 5}, {"nothing": 1}, {}, [1, 2], "text",
])
def test_bad_first_message_is_closed_with_4401(client, first):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json(first)
        _expect_close(ws)


def test_non_json_first_message_is_closed(client):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text("{not json")
        _expect_close(ws)


def test_sensor_token_is_not_accepted(client, sensor_token):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": sensor_token})
        _expect_close(ws)


def test_oversized_first_message_is_closed(client, analyst_headers):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": _token(analyst_headers), "pad": "x" * 10_000})
        _expect_close(ws)


def test_missing_token_times_out(client, monkeypatch):
    monkeypatch.setattr(live, "AUTH_TIMEOUT", 0.3)
    with client.websocket_connect("/ws/alerts") as ws:
        _expect_close(ws)


def test_late_token_is_refused(client, analyst_headers, monkeypatch):
    monkeypatch.setattr(live, "AUTH_TIMEOUT", 0.3)
    with client.websocket_connect("/ws/alerts") as ws:
        time.sleep(0.6)
        with contextlib.suppress(Exception):  # the server may already have hung up
            ws.send_json({"token": _token(analyst_headers)})
        _expect_close(ws)


def test_token_for_a_disabled_user_is_refused(client, soc_app, analyst_headers):
    token = _token(analyst_headers)
    with soc_app.state.session_factory() as db:
        user = db.query(User).filter_by(username="analyst").one()
        auth.set_disabled(db, user, True)
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": token})
        _expect_close(ws)


def test_connection_closes_when_the_token_expires(client, soc_app):
    with soc_app.state.session_factory() as db:
        user = db.query(User).filter_by(username="analyst").one()
        now = datetime.now(UTC)
        token = jwt.encode({"sub": str(user.id), "ver": user.token_version, "iat": now,
                            "account_created": user.created_at.isoformat(),
                            "nbf": now - timedelta(seconds=5), "exp": now + timedelta(seconds=2),
                            "iss": "idps-soc", "aud": "idps-soc"}, TEST_SECRET, algorithm="HS256")
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": token})
        assert ws.receive_json() == {"type": "ready"}
        _expect_close(ws)  # no alert arrives; the server closes at expiry


def test_connection_closes_when_the_user_is_disabled(client, soc_app, analyst_headers,
                                                     monkeypatch):
    monkeypatch.setattr(live, "RECHECK_SECONDS", 0.3)
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": _token(analyst_headers)})
        ws.receive_json()
        with soc_app.state.session_factory() as db:
            auth.set_disabled(db, db.query(User).filter_by(username="analyst").one(), True)
        _expect_close(ws)


def test_connection_cap(soc_settings, soc_app):
    app = create_app(soc_settings.model_copy(update={"ws_max_connections": 1}))
    with app.state.session_factory() as db:
        # SQLite: the second app has its own in-memory database; PostgreSQL: it shares the
        # database of soc_app, where this admin already exists.
        try:
            auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
        except ValueError:
            pass
    client = TestClient(app)
    token = client.post("/auth/login", json={"username": "admin", "password": ADMIN_PW}
                        ).json()["access_token"]
    with client.websocket_connect("/ws/alerts") as first:
        first.send_json({"token": token})
        assert first.receive_json() == {"type": "ready"}
        with client.websocket_connect("/ws/alerts") as second:
            second.send_json({"token": token})
            _expect_close(second, 4429)


def test_subscriber_is_removed_on_disconnect(client, soc_app, analyst_headers):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": _token(analyst_headers)})
        ws.receive_json()
        assert len(soc_app.state.broadcaster) == 1
    for _ in range(50):
        if len(soc_app.state.broadcaster) == 0:
            break
        time.sleep(0.05)
    assert len(soc_app.state.broadcaster) == 0


def test_slow_subscriber_is_dropped_without_blocking_publish():
    async def scenario():
        bus = AlertBroadcaster(max_subscribers=2, queue_size=2)
        slow, other = bus.subscribe(), bus.subscribe()
        assert bus.subscribe() is None  # cap reached
        started = time.monotonic()
        thread = threading.Thread(target=lambda: [bus.publish({"n": i}) for i in range(10)])
        thread.start()
        thread.join()
        assert time.monotonic() - started < 1  # publish never waited for a consumer
        await asyncio.sleep(0.1)
        assert slow.overflowed and slow.wakeup.is_set()
        assert slow.queue.qsize() == 2  # bounded
        assert not other.overflowed or other.queue.qsize() <= 2
        bus.unsubscribe(slow)
        assert len(bus) == 1

    asyncio.run(scenario())
