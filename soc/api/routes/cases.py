"""Cases: group alerts into an incident, with notes and a status."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from soc.api import access_log
from soc.api.auth import AnyUser
from soc.api.common import Cursor, Limit, Page, audit, get_or_404, paginate
from soc.api.db import get_db
from soc.api.models import Alert, Case, CaseNote, CaseStatus, User
from soc.api.routes.alerts import AlertOut

router = APIRouter(prefix="/cases", tags=["cases"])

MAX_NOTE = 10_000
MAX_ALERTS_PER_REQUEST = 100


def _clean_title(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("title must not be blank")
    return value


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    alert_ids: list[int] = Field(default_factory=list, max_length=MAX_ALERTS_PER_REQUEST)

    _title = field_validator("title")(_clean_title)


class CasePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=200)
    status: CaseStatus | None = None

    @field_validator("title")
    @classmethod
    def _t(cls, value: str | None) -> str | None:
        return None if value is None else _clean_title(value)


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=MAX_NOTE)

    @field_validator("text")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must not be blank")
        return value


class AttachIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_ids: list[int] = Field(min_length=1, max_length=MAX_ALERTS_PER_REQUEST)


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    author_id: int | None
    author: str | None = None
    text: str
    created_at: datetime


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    status: CaseStatus
    created_by_id: int | None
    created_at: datetime
    updated_at: datetime
    alert_count: int = 0


class CaseDetail(CaseOut):
    notes: list[NoteOut]
    alerts: list[AlertOut]


def _alert_count(db: Session, case_id: int) -> int:
    return db.scalar(select(func.count()).select_from(Alert).where(Alert.case_id == case_id)) or 0


def _detail(db: Session, case: Case) -> CaseDetail:
    alerts = list(db.scalars(select(Alert).where(Alert.case_id == case.id).order_by(Alert.id)))
    notes = list(db.scalars(select(CaseNote).where(CaseNote.case_id == case.id)
                            .order_by(CaseNote.id)))
    names = {u.id: u.username for u in db.scalars(
        select(User).where(User.id.in_({n.author_id for n in notes if n.author_id})))}
    out_notes = []
    for n in notes:
        note = NoteOut.model_validate(n)
        note.author = names.get(n.author_id)
        out_notes.append(note)
    base = CaseOut.model_validate(case)
    return CaseDetail(**base.model_dump(exclude={"alert_count"}), alert_count=len(alerts),
                      notes=out_notes, alerts=[AlertOut.model_validate(a) for a in alerts])


def _attach(db: Session, case: Case, alert_ids: list[int]) -> list[int]:
    ids = sorted(set(alert_ids))
    alerts = {a.id: a for a in db.scalars(select(Alert).where(Alert.id.in_(ids)))}
    missing = [i for i in ids if i not in alerts]
    if missing:
        raise HTTPException(422, f"unknown alert id(s): {missing}")
    taken = [i for i, a in alerts.items() if a.case_id not in (None, case.id)]
    if taken:
        raise HTTPException(409, f"alert(s) already in another case: {taken}")
    for a in alerts.values():
        a.case_id = case.id
    case.updated_at = datetime.now(UTC)
    return ids


@router.post("", response_model=CaseDetail, status_code=201)
def create_case(body: CaseCreate, user: AnyUser, db: Annotated[Session, Depends(get_db)]):
    case = Case(title=body.title, created_by_id=user.id)
    db.add(case)
    db.flush()
    ids = _attach(db, case, body.alert_ids) if body.alert_ids else []
    audit(db, user, "case_create", f"case:{case.id}", {"title": body.title, "alert_ids": ids})
    db.commit()
    return _detail(db, case)


@router.get("", response_model=Page[CaseOut])
def list_cases(user: AnyUser, db: Annotated[Session, Depends(get_db)],
               status: Annotated[CaseStatus | None, Query()] = None,
               limit: Limit = 50, cursor: Cursor = None):
    query = select(Case).order_by(Case.id.desc()).limit(limit + 1)
    if status:
        query = query.where(Case.status == status)
    if cursor:
        query = query.where(Case.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    items = []
    for c in rows:
        out = CaseOut.model_validate(c)
        out.alert_count = _alert_count(db, c.id)
        items.append(out)
    return Page[CaseOut](items=items, next_cursor=next_cursor)


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: int, user: AnyUser, request: Request,
             db: Annotated[Session, Depends(get_db)]):
    detail = _detail(db, get_or_404(db, Case, case_id, "case"))
    # the case itself, then the addresses of its alerts (capped by access_log.MAX_SUBJECTS)
    ips = [ip for a in detail.alerts for ip in (a.src_ip, a.dst_ip)]
    access_log.log_access(db, request.app.state.settings, user, "case_view",
                          target_type="case", target=str(case_id), ips=ips,
                          without_subject=True)
    return detail


@router.patch("/{case_id}", response_model=CaseDetail)
def patch_case(case_id: int, body: CasePatch, user: AnyUser,
               db: Annotated[Session, Depends(get_db)]):
    case = get_or_404(db, Case, case_id, "case")
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(422, "nothing to change")
    details = {k: {"from": str(getattr(case, k)), "to": str(v)} for k, v in changes.items()}
    for key, value in changes.items():
        setattr(case, key, value)
    case.updated_at = datetime.now(UTC)
    audit(db, user, "case_update", f"case:{case.id}", details)
    db.commit()
    return _detail(db, case)


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: int, user: AnyUser, db: Annotated[Session, Depends(get_db)]):
    """Deletes the case and its notes; its alerts stay, detached."""
    case = get_or_404(db, Case, case_id, "case")
    db.execute(update(Alert).where(Alert.case_id == case.id).values(case_id=None))
    db.execute(delete(CaseNote).where(CaseNote.case_id == case.id))
    audit(db, user, "case_delete", f"case:{case.id}", {"title": case.title})
    db.delete(case)
    db.commit()


@router.post("/{case_id}/notes", response_model=NoteOut, status_code=201)
def add_note(case_id: int, body: NoteIn, user: AnyUser, db: Annotated[Session, Depends(get_db)]):
    case = get_or_404(db, Case, case_id, "case")
    note = CaseNote(case_id=case.id, author_id=user.id, text=body.text)
    db.add(note)
    case.updated_at = datetime.now(UTC)
    db.flush()
    audit(db, user, "case_note", f"case:{case.id}", {"note_id": note.id, "length": len(body.text)})
    db.commit()
    out = NoteOut.model_validate(note)
    out.author = user.username
    return out


@router.post("/{case_id}/alerts", response_model=CaseDetail)
def attach_alerts(case_id: int, body: AttachIn, user: AnyUser,
                  db: Annotated[Session, Depends(get_db)]):
    case = get_or_404(db, Case, case_id, "case")
    ids = _attach(db, case, body.alert_ids)
    audit(db, user, "case_attach", f"case:{case.id}", {"alert_ids": ids})
    db.commit()
    return _detail(db, case)


@router.delete("/{case_id}/alerts/{alert_id}", status_code=204)
def detach_alert(case_id: int, alert_id: int, user: AnyUser,
                 db: Annotated[Session, Depends(get_db)]):
    case = get_or_404(db, Case, case_id, "case")
    alert = get_or_404(db, Alert, alert_id, "alert")
    if alert.case_id != case.id:
        raise HTTPException(404, "alert is not in this case")
    alert.case_id = None
    case.updated_at = datetime.now(UTC)
    audit(db, user, "case_detach", f"case:{case.id}", {"alert_id": alert_id})
    db.commit()
