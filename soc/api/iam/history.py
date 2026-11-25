"""Login history: one row per sign-in attempt. Written by soc.api.auth; a failure to write must
never break a login, so every error here is logged and swallowed."""

import hashlib
import hmac
import logging
import time
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.orm import Session

from soc.api.common import strip_unsafe
from soc.api.models import LoginHistory

log = logging.getLogger("soc.iam.history")

# A flood of attempts must not become a flood of rows. One "locked" or "unknown_user" row per
# (username, address) per minute; and at most _FAILS_PER_MINUTE failure rows of any kind per
# address per minute. The in-process counters are best effort (one per worker, reset on restart).
_LOCKED_EVERY = 60.0
_recent_locked: dict[tuple[str, str, str], float] = {}  # (reason, username, ip) -> monotonic time
_FAILS_PER_MINUTE = 30
_recent_fails: dict[str, tuple[float, int]] = {}  # ip -> (window start, rows written)
_MAX_TRACKED = 10_000
_DEDUPED = ("locked", "unknown_user")

KEY_INFO = b"login-history-username-v1"
KEY_SALT = b"idps-soc-login-history"


@lru_cache(maxsize=8)
def _key(master: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=KEY_SALT,
                info=KEY_INFO).derive(master.encode())


def unknown_label(settings, name: str) -> str:
    """What the history stores instead of a username that matches no account: "?" and 16 hex
    characters of an HMAC-SHA256 of it under a derived key. The name may be a password pasted
    into the wrong box, or someone's email address, so it is never written; the same text still
    gives the same label, so repeated attempts can be told apart and counted."""
    mac = hmac.new(_key(settings.mfa_master_key), name.encode("utf-8", "replace"), hashlib.sha256)
    return "?" + mac.hexdigest()[:16]


def _clean(text: str, limit: int) -> str:
    try:
        text = strip_unsafe(text)
    except ValueError:  # a NUL
        text = text.replace("\x00", "")
        text = strip_unsafe(text)
    return text[:limit]


def _throttled(reason: str, username: str, ip: str) -> bool:
    """True when this failure row should not be written (see the limits above)."""
    now = time.monotonic()
    if len(_recent_locked) > _MAX_TRACKED:
        _recent_locked.clear()
    if len(_recent_fails) > _MAX_TRACKED:
        _recent_fails.clear()
    if reason in _DEDUPED:
        key = (reason, username[:64], ip)
        if now - _recent_locked.get(key, -_LOCKED_EVERY) < _LOCKED_EVERY:
            return True
        _recent_locked[key] = now
    start, n = _recent_fails.get(ip, (now, 0))
    if now - start >= 60.0:
        start, n = now, 0
    if n >= _FAILS_PER_MINUTE:
        return True
    _recent_fails[ip] = (start, n + 1)
    return False


def record_login(db: Session, *, username: str, user_id: int | None, success: bool, reason: str,
                 ip: str, user_agent: str | None, mfa_used: bool = False,
                 settings=None, unknown: bool = False) -> None:
    """Write one attempt. `unknown`: `username` is what was typed and matches no account, so it
    is replaced by unknown_label(settings, ...) (the raw text is never stored)."""
    try:
        if unknown:
            username = unknown_label(settings, username)
        if not success and _throttled(reason, username, ip):
            return
        db.add(LoginHistory(username=_clean(username, 64), user_id=user_id, success=success,
                            reason=reason, ip=_clean(ip, 45),
                            user_agent=_clean(user_agent or "", 255), mfa_used=mfa_used))
        db.commit()
    except Exception:  # history is best effort: never break a login
        log.warning("could not record a login attempt", exc_info=True)
        try:
            db.rollback()
        except Exception:
            log.warning("rollback after a failed history write also failed", exc_info=True)
