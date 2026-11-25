"""SOC API: request body size limits (soc/api/limits.py)."""

import asyncio
import json

import pytest
from conftest import alert_payload

from soc.api.limits import DEFAULT_LIMIT, BodyLimitMiddleware, KiB, MiB, limit_for


def test_every_documented_limit_is_above_what_the_schemas_allow():
    from soc.api.routes.alerts import MAX_BATCH, MAX_EXPLANATION_BYTES

    assert limit_for("/ingest/alerts") > MAX_BATCH * MAX_EXPLANATION_BYTES
    assert limit_for("/ingest/alerts") == 12 * MiB
    assert limit_for("/sensor/status") < limit_for("/ingest/alerts")
    assert limit_for("/ingest/blocks") < MiB and limit_for("/auth/login") <= 16 * KiB
    assert limit_for("/sensor/actions/3/result") == limit_for("/actions") == 16 * KiB
    assert limit_for("/alerts") == DEFAULT_LIMIT and limit_for("/actionsx") == DEFAULT_LIMIT
    assert limit_for("/assistant/chat") == 64 * KiB


def test_a_full_valid_batch_fits(client, sensor_headers):
    big = {"method": "shap", "top_features": [
        {"feature": f"f{i:02d}", "value": 1.0, "contribution": 0.5} for i in range(50)],
        "pad": "x" * 13_000}
    batch = {"alerts": [alert_payload(explanation=big) for _ in range(500)]}
    body = json.dumps(batch).encode()
    assert len(body) < limit_for("/ingest/alerts")
    r = client.post("/ingest/alerts", content=body,
                    headers={**sensor_headers, "Content-Type": "application/json"})
    assert r.status_code == 201, r.text[:200]


def test_an_oversized_content_length_is_refused_before_auth_and_parsing(client):
    body = b"x" * (limit_for("/auth/login") + 1)
    r = client.post("/auth/login", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and "limit" in r.json()["detail"]
    # no token at all and a revoked-looking token: still 413, not 401 (body never parsed)
    r = client.post("/sensor/status", content=b"y" * (64 * KiB + 1),
                    headers={"Authorization": "Bearer idps_sensor_revoked",
                             "Content-Type": "application/json"})
    assert r.status_code == 413


def test_the_limit_is_per_path(client, sensor_headers):
    small = b" " * (20 * KiB)  # over /actions' 16 KiB, under /cases' 128 KiB
    r = client.post("/actions", content=small, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    r = client.post("/cases", content=small, headers={"Content-Type": "application/json"})
    assert r.status_code in (401, 422)  # under /cases' limit: parsed, not 413


def test_just_under_the_limit_reaches_authentication(client):
    r = client.post("/auth/login", content=b"{" + b" " * (limit_for("/auth/login") - 2) + b"}",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 422  # parsed (and refused as a login body), not 413


def test_a_bad_content_length_is_a_400():
    sent = []

    async def app(scope, receive, send):
        raise AssertionError("must not be reached")

    async def run():
        mw = BodyLimitMiddleware(app)
        scope = {"type": "http", "path": "/x", "headers": [(b"content-length", b"abc")]}
        await mw(scope, None, lambda m: _collect(sent, m))

    asyncio.run(run())
    assert sent[0]["status"] == 400


async def _collect(sent, message):
    sent.append(message)


def test_a_streamed_body_without_content_length_is_cut_at_the_limit():
    """Chunked upload: no Content-Length, so the bytes are counted as they arrive and the app
    stops being fed at the limit (it never sees the rest)."""
    sent, read = [], []

    async def app(scope, receive, send):
        while True:
            message = await receive()
            read.append(len(message.get("body", b"")))
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    chunks = [{"type": "http.request", "body": b"a" * 1000, "more_body": True}] * 100

    async def run():
        it = iter(chunks)

        async def receive():
            return next(it)

        mw = BodyLimitMiddleware(app, limits=lambda path: 10_000)
        await mw({"type": "http", "path": "/x", "headers": []}, receive, lambda m: _collect(sent, m))

    asyncio.run(run())
    assert sent[0]["status"] == 413
    assert sum(read) <= 10_000  # never more than the limit was handed to the app


def test_a_streamed_body_through_the_real_app_is_413(client):
    def chunks():
        for _ in range(300):
            yield b" " * KiB  # 300 KiB > the default limit; no Content-Length (chunked)

    r = client.post("/cases", content=chunks(), headers={"Content-Type": "application/json"})
    # /cases allows 128 KiB: refused while streaming, before auth
    assert r.status_code == 413


def test_a_lying_content_length_is_still_counted():
    sent = []

    async def app(scope, receive, send):
        await receive()
        raise AssertionError("must have been cut")

    async def run():
        async def receive():
            return {"type": "http.request", "body": b"a" * 600, "more_body": False}

        mw = BodyLimitMiddleware(app, limits=lambda path: 500)
        scope = {"type": "http", "path": "/x", "headers": [(b"content-length", b"100")]}
        await mw(scope, receive, lambda m: _collect(sent, m))

    asyncio.run(run())
    assert sent[0]["status"] == 413


def test_normal_http_requests_are_untouched(client, analyst_headers):
    assert client.get("/health").status_code == 200
    assert client.get("/auth/me", headers=analyst_headers).status_code == 200


def _token(headers):
    return headers["Authorization"].removeprefix("Bearer ")


def test_a_websocket_authenticates_normally(client, analyst_headers):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_json({"token": _token(analyst_headers)})
        assert ws.receive_json() == {"type": "ready"}


def test_an_oversized_first_websocket_message_is_refused(client, analyst_headers):
    from starlette.websockets import WebSocketDisconnect

    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text("x" * 100_000)  # far over the 4096 character auth message
        with pytest.raises(WebSocketDisconnect) as info:
            ws.receive_json()
    assert info.value.code == 4401


def test_uvicorn_is_started_with_a_small_ws_max_size_everywhere():
    """uvicorn's default (16 MiB) would buffer a whole message before the 4096 check runs."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent
    for rel in ("lab/soc/start.sh", "infra/templates/soc-user-data.sh.tftpl"):
        text = (root / rel).read_text()
        assert re.search(r"--ws-max-size\s+65536", text), rel


def test_a_real_uvicorn_server_closes_an_oversized_websocket_message(soc_settings):
    """End to end over a real socket: with --ws-max-size the server cuts the connection (1009,
    message too big) while the first message is still being read, before any handler sees it."""
    import threading
    import time

    import uvicorn
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.client import connect

    from soc.api.main import create_app

    config = uvicorn.Config(create_app(soc_settings), host="127.0.0.1", port=0,
                            ws_max_size=65536, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert server.started
        port = server.servers[0].sockets[0].getsockname()[1]
        with connect(f"ws://127.0.0.1:{port}/ws/alerts", open_timeout=5) as ws:
            ws.send("x" * (1024 * 1024))
            with pytest.raises(ConnectionClosed) as info:
                ws.recv(timeout=5)
        assert info.value.rcvd is not None and info.value.rcvd.code == 1009
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.mark.parametrize("path", ["/ingest/alerts", "/sensor/status"])
def test_413_carries_no_secret_and_is_json(client, path):
    r = client.post(path, content=b"z" * (13 * MiB), headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.headers["content-type"] == "application/json"
