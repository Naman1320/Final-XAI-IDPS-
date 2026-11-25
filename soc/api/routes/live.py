"""Live alert feed over a WebSocket.

Browsers can't set headers on a WebSocket, so the client authenticates with its first message,
`{"token": "<access token>"}`, sent within AUTH_TIMEOUT seconds. Every failure closes the
socket with code 4401, as does the token expiring (or the user being disabled or demoted
out of the system) while connected. After that the server pushes each new alert as JSON
(the same fields as GET /alerts plus an optional `src_geo`; fetch GET /alerts/{id} for the
explanation) and, as typed messages without an `id`, each block event (`{"type": "block", ...}`,
see soc/api/routes/blocks.py). Older clients ignore messages without an `id`.
Anything else the client sends is ignored.
"""

import asyncio
import contextlib
import json
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from soc.api import auth, security

router = APIRouter(tags=["live"])

AUTH_TIMEOUT = 5.0  # seconds to send the token
SEND_TIMEOUT = 5.0  # a client that can't take a message this fast is too slow
RECHECK_SECONDS = 30.0  # how often a connected user is re-validated (disabled, password reset)
MAX_AUTH_MESSAGE = 4096
CLOSE_UNAUTHORIZED = 4401
CLOSE_TOO_SLOW = 4408
CLOSE_FULL = 4429


def _check_token(app, token: str) -> tuple[bool, float]:
    """(valid, expiry as a time.time() value)."""
    with app.state.session_factory() as db:
        user = auth.user_from_token(token, app, db)
        if user is None:
            return False, 0.0
    claims = security.decode_access_token(
        token, secret=app.state.settings.jwt_secret.get_secret_value())
    return True, float(claims["exp"])


async def _authenticate(ws: WebSocket) -> tuple[str, float] | None:
    try:
        raw = await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT)
        if len(raw) > MAX_AUTH_MESSAGE:
            return None
        token = json.loads(raw).get("token")
        if not isinstance(token, str) or not token:
            return None
        valid, exp = await run_in_threadpool(_check_token, ws.app, token)
    except (TimeoutError, WebSocketDisconnect, ValueError, AttributeError, KeyError, RuntimeError):
        return None  # ValueError covers bad JSON; AttributeError a non-object message
    return (token, exp) if valid else None


@router.websocket("/ws/alerts")
async def alert_feed(ws: WebSocket):
    await ws.accept()  # must accept before we can close with a custom code
    creds = await _authenticate(ws)
    if creds is None:
        await _close(ws, CLOSE_UNAUTHORIZED)
        return
    token, exp = creds
    broadcaster = ws.app.state.broadcaster
    sub = broadcaster.subscribe()
    if sub is None:
        await _close(ws, CLOSE_FULL)
        return
    try:
        await ws.send_json({"type": "ready"})
        reader = asyncio.create_task(_drain(ws))  # notices the client going away
        overflow = asyncio.create_task(sub.wakeup.wait())
        next_check = time.monotonic() + RECHECK_SECONDS
        try:
            while True:
                getter = asyncio.create_task(sub.next())
                timeout = max(0.0, min(exp - time.time(), next_check - time.monotonic()))
                done, _ = await asyncio.wait({getter, reader, overflow}, timeout=timeout,
                                             return_when=asyncio.FIRST_COMPLETED)
                if getter not in done:
                    getter.cancel()
                if reader in done:
                    return
                if overflow in done:
                    await _close(ws, CLOSE_TOO_SLOW)
                    return
                if time.time() >= exp:
                    await _close(ws, CLOSE_UNAUTHORIZED)
                    return
                if time.monotonic() >= next_check:
                    next_check = time.monotonic() + RECHECK_SECONDS
                    valid, _ = await run_in_threadpool(_check_token, ws.app, token)
                    if not valid:
                        await _close(ws, CLOSE_UNAUTHORIZED)
                        return
                if getter in done:
                    try:
                        await asyncio.wait_for(ws.send_text(json.dumps(getter.result())),
                                               SEND_TIMEOUT)
                    except (TimeoutError, WebSocketDisconnect, RuntimeError):
                        return
        finally:
            reader.cancel()
            overflow.cancel()
    finally:
        broadcaster.unsubscribe(sub)


async def _drain(ws: WebSocket) -> None:
    try:
        while (await ws.receive())["type"] != "websocket.disconnect":
            pass
    except (WebSocketDisconnect, RuntimeError):
        return


async def _close(ws: WebSocket, code: int) -> None:
    with contextlib.suppress(RuntimeError, WebSocketDisconnect, OSError):
        await ws.close(code=code)
