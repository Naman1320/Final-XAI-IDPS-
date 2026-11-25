"""The cloud activity timeline."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from soc.api.cloud.common import Limit, Offset, Paged, Read
from soc.api.models import CloudActivity

router = APIRouter(prefix="/cloud", tags=["cloud"])


class Activity(BaseModel):
    id: int
    at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    details: dict


@router.get("/activity", response_model=Paged[Activity])
def list_activity(ctx: Read,
                  actor: Annotated[str | None, Query(max_length=64)] = None,
                  action: Annotated[str | None, Query(max_length=48, description="exact action, "
                                                      "e.g. instance.stop")] = None,
                  resource_type: Annotated[str | None, Query(max_length=24)] = None,
                  resource_id: Annotated[str | None, Query(max_length=64)] = None,
                  limit: Limit = 50, offset: Offset = 0):
    query = select(CloudActivity)
    if actor:
        query = query.where(CloudActivity.actor == actor)
    if action:
        query = query.where(CloudActivity.action == action)
    if resource_type:
        query = query.where(CloudActivity.resource_type == resource_type)
    if resource_id:
        query = query.where(CloudActivity.resource_id == resource_id)
    total = ctx.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = ctx.db.scalars(query.order_by(CloudActivity.at.desc(), CloudActivity.id.desc())
                          .limit(limit).offset(offset))
    return Paged[Activity](**ctx.sourced(), total=total, limit=limit, offset=offset,
                           items=[Activity(id=a.id, at=a.at, actor=a.actor, action=a.action,
                                           resource_type=a.resource_type,
                                           resource_id=a.resource_id, details=a.details or {})
                                  for a in rows])
