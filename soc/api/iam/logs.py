"""IAM: login history and the audit log."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc.api.common import Cursor, Limit, Page, paginate
from soc.api.db import get_db
from soc.api.iam.deps import require_permission
from soc.api.models import AuditEntry, LoginHistory, User
from soc.api.routes.admin import AuditOut

router = APIRouter(prefix="/iam", tags=["iam"])


class LoginOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    user_id: int | None
    username: str
    success: bool
    reason: str
    ip: str
    user_agent: str
    mfa_used: bool


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        raise ValueError("the time needs a timezone, e.g. 2026-11-18T00:00:00Z")
    return value


def _range(since: datetime | None, until: datetime | None) -> None:
    try:
        _aware(since)
        _aware(until)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if since and until and since > until:
        raise HTTPException(422, "since is after until")


@router.get("/logins", response_model=Page[LoginOut])
def list_logins(user: Annotated[User, Depends(require_permission("iam.logins.view"))],
                db: Annotated[Session, Depends(get_db)],
                user_id: Annotated[int | None, Query(ge=1, le=2**62)] = None,
                username: Annotated[str | None, Query(max_length=64)] = None,
                success: bool | None = None,
                reason: Annotated[str | None, Query(max_length=24)] = None,
                since: datetime | None = None, until: datetime | None = None,
                limit: Limit = 100, cursor: Cursor = None):
    _range(since, until)
    query = select(LoginHistory).order_by(LoginHistory.id.desc()).limit(limit + 1)
    if user_id is not None:
        query = query.where(LoginHistory.user_id == user_id)
    if username:
        query = query.where(LoginHistory.username == username)
    if success is not None:
        query = query.where(LoginHistory.success.is_(success))
    if reason:
        query = query.where(LoginHistory.reason == reason)
    if since:
        query = query.where(LoginHistory.at >= since)
    if until:
        query = query.where(LoginHistory.at <= until)
    if cursor:
        query = query.where(LoginHistory.id < cursor)
    rows, nxt = paginate(list(db.scalars(query)), limit)
    return Page[LoginOut](items=[LoginOut.model_validate(r) for r in rows], next_cursor=nxt)


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(user: Annotated[User, Depends(require_permission("iam.audit.view"))],
               db: Annotated[Session, Depends(get_db)],
               actor: Annotated[str | None, Query(max_length=64)] = None,
               action: Annotated[list[Annotated[str, Field(max_length=64)]] | None,
                                 Query(max_length=20, description="repeat for several")] = None,
               target: Annotated[str | None, Query(max_length=128)] = None,
               since: datetime | None = None, until: datetime | None = None,
               limit: Limit = 100, cursor: Cursor = None):
    """The same audit entries as GET /admin/audit, with time filters; for the permission
    iam.audit.view instead of the admin role."""
    _range(since, until)
    query = select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit + 1)
    if actor:
        query = query.where(AuditEntry.actor_name == actor)
    names = [a for a in action or [] if a]
    if names:
        query = query.where(AuditEntry.action.in_(names))
    if target:
        query = query.where(AuditEntry.target == target)
    if since:
        query = query.where(AuditEntry.at >= since)
    if until:
        query = query.where(AuditEntry.at <= until)
    if cursor:
        query = query.where(AuditEntry.id < cursor)
    rows, nxt = paginate(list(db.scalars(query)), limit)
    return Page[AuditOut](items=[AuditOut.model_validate(r) for r in rows], next_cursor=nxt)

