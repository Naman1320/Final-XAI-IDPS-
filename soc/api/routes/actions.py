"""Actions requested of sensors: analyst requests, assistant proposals, sensor polling.

Lifecycle: pending (assistant proposal) -> confirmed or rejected (an analyst decides);
an analyst's own request starts confirmed. The target sensor polls for confirmed actions and
reports executed or failed. The server refuses block_ip for allowlisted or non-routable
addresses when the action is created, when it is confirmed, and when a sensor polls for it.
"""

import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser, Sensor
from soc.api.common import (
    BlockingUnavailable,
    Cursor,
    IPAddress,
    Limit,
    Page,
    audit,
    check_blockable,
    clean_reason,
    get_or_404,
    no_nul,
    paginate,
)
from soc.api.db import get_db
from soc.api.models import Action, ActionKind, ActionStatus, Role, SensorToken, User
from soc.api.settings import SocSettings

router = APIRouter(tags=["actions"])

MAX_TTL_SECONDS = 30 * 24 * 3600
MAX_RESULT_BYTES = 4096
POLL_LIMIT = 50


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: ActionKind
    ip: IPAddress
    sensor_id: int = Field(ge=1, le=2**62)
    reason: str = Field(min_length=1, max_length=500)
    ttl_seconds: int | None = Field(default=None, ge=1, le=MAX_TTL_SECONDS)

    @field_validator("reason")
    @classmethod
    def _plain_reason(cls, value: str) -> str:
        return clean_reason(value)

    @model_validator(mode="after")
    def _ttl_only_for_block(self) -> Self:
        if self.ttl_seconds is not None and self.kind != ActionKind.BLOCK_IP:
            raise ValueError("ttl_seconds only applies to block_ip")
        return self


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: ActionKind
    params: dict[str, Any]
    reason: str
    proposed_by: str
    proposed_by_user_id: int | None
    sensor_id: int
    status: ActionStatus
    created_at: datetime
    decided_by_id: int | None
    decided_at: datetime | None
    result: dict[str, Any] | None
    completed_at: datetime | None


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result")
    @classmethod
    def _small(cls, value: dict) -> dict:
        try:
            size = len(json.dumps(value, allow_nan=False).encode())
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("result must be plain JSON") from exc
        if size > MAX_RESULT_BYTES:
            raise ValueError(f"result is {size} bytes; the limit is {MAX_RESULT_BYTES}")
        return no_nul(value)


def _check_params(kind: ActionKind, params: dict, settings: SocSettings,
                  user: User | None = None) -> None:
    if kind == ActionKind.BLOCK_IP:
        # Only an admin is told which allowlist network matched.
        check_blockable(params["ip"], settings, reveal=user is not None and user.role == Role.ADMIN)


def create_action(db: Session, settings: SocSettings, *, kind: ActionKind, params: dict,
                  reason: str, sensor_id: int, proposed_by: Literal["user", "assistant"],
                  user: User | None) -> Action:
    """Add an action to the session (the caller audits and commits). Assistant proposals are
    pending; a user's request is confirmed straight away. Used by POST /actions and, later,
    by the assistant's propose_block tool."""
    human = proposed_by == "user"
    if human and user is None:
        # A confirmed action must name the person who confirmed it.
        raise ValueError("a user-proposed action needs the user")
    sensor = db.get(SensorToken, sensor_id)
    if sensor is None or sensor.revoked:
        raise HTTPException(422, "unknown or revoked sensor_id")
    _check_params(kind, params, settings, user)
    now = datetime.now(UTC)
    action = Action(
        kind=kind, params=params, reason=reason, proposed_by=proposed_by,
        proposed_by_user_id=user.id if user else None, sensor_id=sensor_id,
        status=ActionStatus.CONFIRMED if human else ActionStatus.PENDING,
        decided_by_id=user.id if human and user else None, decided_at=now if human else None)
    db.add(action)
    return action


@router.post("/actions", response_model=ActionOut, status_code=201)
def request_action(body: ActionIn, user: AnyUser, request: Request,
                   db: Annotated[Session, Depends(get_db)]):
    params: dict[str, Any] = {"ip": body.ip}
    if body.ttl_seconds:
        params["ttl_seconds"] = body.ttl_seconds
    action = create_action(db, request.app.state.settings, kind=body.kind, params=params, reason=body.reason,
                           sensor_id=body.sensor_id, proposed_by="user", user=user)
    db.flush()
    audit(db, user, "action_request", f"action:{action.id}",
          {"kind": body.kind.value, "ip": body.ip, "sensor_id": body.sensor_id})
    db.commit()
    return ActionOut.model_validate(action)


@router.get("/actions", response_model=Page[ActionOut])
def list_actions(user: AnyUser, db: Annotated[Session, Depends(get_db)],
                 status: Annotated[ActionStatus | None, Query()] = None,
                 limit: Limit = 50, cursor: Cursor = None):
    query = select(Action).order_by(Action.id.desc()).limit(limit + 1)
    if status:
        query = query.where(Action.status == status)
    if cursor:
        query = query.where(Action.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    return Page[ActionOut](items=[ActionOut.model_validate(r) for r in rows],
                           next_cursor=next_cursor)


@router.get("/actions/{action_id}", response_model=ActionOut)
def get_action(action_id: int, user: AnyUser, db: Annotated[Session, Depends(get_db)]):
    return ActionOut.model_validate(get_or_404(db, Action, action_id, "action"))


def _decide(action_id: int, user: User, db: Session, new: ActionStatus,
            settings: SocSettings) -> ActionOut:
    action = get_or_404(db, Action, action_id, "action")
    if action.status != ActionStatus.PENDING:
        raise HTTPException(409, f"action is {action.status.value}, not pending")
    if new == ActionStatus.CONFIRMED:
        _check_params(action.kind, action.params, settings, user)  # the allowlist may have changed
    # Conditional update: of two simultaneous decisions (confirm vs reject), exactly one wins.
    changed = db.execute(
        update(Action).where(Action.id == action_id, Action.status == ActionStatus.PENDING)
        .values(status=new, decided_by_id=user.id, decided_at=datetime.now(UTC))).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, "action was decided by someone else first")
    audit(db, user, f"action_{new.value}", f"action:{action_id}", {"kind": action.kind.value})
    db.commit()
    db.refresh(action)
    return ActionOut.model_validate(action)


@router.post("/actions/{action_id}/confirm", response_model=ActionOut)
def confirm_action(action_id: int, user: AnyUser, request: Request,
                   db: Annotated[Session, Depends(get_db)]):
    return _decide(action_id, user, db, ActionStatus.CONFIRMED, request.app.state.settings)


@router.post("/actions/{action_id}/reject", response_model=ActionOut)
def reject_action(action_id: int, user: AnyUser, request: Request,
                  db: Annotated[Session, Depends(get_db)]):
    return _decide(action_id, user, db, ActionStatus.REJECTED, request.app.state.settings)


# --- sensor side ------------------------------------------------------------------------

@router.get("/sensor/actions", response_model=list[ActionOut])
def poll_actions(sensor: Sensor, request: Request, db: Annotated[Session, Depends(get_db)]):
    """Confirmed actions for this sensor, oldest first. They stay listed until a result is
    reported, so a sensor that crashed mid-way sees them again."""
    rows = list(db.scalars(select(Action).where(
        Action.sensor_id == sensor.id, Action.status == ActionStatus.CONFIRMED)
        .order_by(Action.id).limit(POLL_LIMIT)))
    safe = []
    for action in rows:
        try:
            _check_params(action.kind, action.params, request.app.state.settings)
        except BlockingUnavailable:
            # A configuration problem on this server, not a verdict on the address: keep the
            # action confirmed and hand it out once blocking is configured again.
            continue
        except HTTPException as exc:  # the address became unblockable after confirmation
            action.status = ActionStatus.FAILED
            action.completed_at = datetime.now(UTC)
            action.result = {"error": f"refused by the server: {exc.detail}"}
            audit(db, sensor, "action_refused", f"action:{action.id}", {"reason": exc.detail})
        else:
            safe.append(action)
    db.commit()
    return [ActionOut.model_validate(a) for a in safe]


@router.post("/sensor/actions/{action_id}/result", response_model=ActionOut)
def report_result(action_id: int, body: ActionResult, sensor: Sensor,
                  db: Annotated[Session, Depends(get_db)]):
    action = db.get(Action, action_id)
    if action is None or action.sensor_id != sensor.id:  # same answer: don't reveal others'
        raise HTTPException(404, "action not found")
    if action.status != ActionStatus.CONFIRMED:
        raise HTTPException(409, f"action is {action.status.value}, not confirmed")
    final = ActionStatus.EXECUTED if body.success else ActionStatus.FAILED
    changed = db.execute(
        update(Action).where(Action.id == action_id, Action.status == ActionStatus.CONFIRMED)
        .values(status=final, result=body.result, completed_at=datetime.now(UTC))).rowcount
    if changed != 1:  # a second, simultaneous report
        db.rollback()
        raise HTTPException(409, "a result was already reported for this action")
    audit(db, sensor, "action_result", f"action:{action_id}", {"success": body.success})
    db.commit()
    db.refresh(action)
    return ActionOut.model_validate(action)
