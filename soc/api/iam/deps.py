"""FastAPI dependencies: require_permission(*perms) and the write rate limit."""

import time
from collections import deque
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from soc.api.auth import current_user
from soc.api.db import get_db
from soc.api.iam import engine
from soc.api.models import User

WRITES_PER_MINUTE = 120  # per user, across every /iam write endpoint


class WriteLimiter:
    """At most `per_minute` IAM writes per user per minute (in memory, one process)."""

    def __init__(self, per_minute: int = WRITES_PER_MINUTE) -> None:
        self.per_minute = per_minute
        self._seen: dict[int, deque[float]] = {}

    def allow(self, user_id: int) -> bool:
        now = time.monotonic()
        window = self._seen.setdefault(user_id, deque())
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.per_minute:
            return False
        window.append(now)
        return True


def require_permission(*permissions: str) -> Callable[..., User]:
    """Dependency factory: the current user, who must hold ALL `permissions` (403 otherwise; 401
    when not signed in or disabled, as everywhere else). A legacy admin holds them all."""
    wanted = tuple(permissions)

    def dependency(user: Annotated[User, Depends(current_user)],
                   db: Annotated[Session, Depends(get_db)]) -> User:
        resolution = engine.resolve(db, user)
        if not all(resolution.allows(p) for p in wanted):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "missing permission: "
                                + ", ".join(p for p in wanted if not resolution.allows(p)))
        return user

    return dependency


def require_write(*permissions: str) -> Callable[..., User]:
    """require_permission plus the per-user write rate limit (429)."""
    check = require_permission(*permissions)

    def dependency(request: Request, user: Annotated[User, Depends(check)]) -> User:
        limiter: WriteLimiter | None = getattr(request.app.state, "iam_limiter", None)
        if limiter is not None and not limiter.allow(user.id):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many changes; slow down", headers={"Retry-After": "60"})
        return user

    return dependency
