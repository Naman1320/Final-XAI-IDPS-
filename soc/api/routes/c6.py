"""C6 evidence. Only the host worker can claim runs and submit observations."""

import hmac
import threading
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc.api.auth import AdminUser, client_ip
from soc.api.common import audit, plain_text
from soc.api.db import get_db
from soc.api.models import Alert, Block, BlockSource, SensorToken

router = APIRouter(tags=["C6"])
SOURCE = "10.10.1.10"
Mode = Literal["replay", "observe"]
Stage = Literal["baseline", "capture", "lab_alert", "lab_block", "cloud_alert", "response",
                "acl", "error"]
REQUIRED = {"baseline", "capture", "lab_alert", "lab_block", "cloud_alert", "response", "acl"}
SOC_STAGES = {"lab_alert", "lab_block", "cloud_alert"}


def require_worker(request: Request, credential: Annotated[str | None, Header(alias="X-C6-Token")] = None):
    secret = request.app.state.settings.c6_token
    if secret is None:
        raise HTTPException(404, "C6 is disabled")
    if credential and hmac.compare_digest(credential[:257].encode(), secret.get_secret_value().encode()):
        return
    if request.app.state.demo_token_throttle.begin_attempt("c6-worker", client_ip(request)) is None:
        raise HTTPException(429, "Too many invalid worker credentials")
    raise HTTPException(401, "Invalid C6 worker credential")


Runner = Annotated[None, Depends(require_worker)]


class Start(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Mode


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: UUID
    stage: Stage
    evidence: Annotated[str, Field(min_length=1, max_length=1600), AfterValidator(plain_text)]


class Event(BaseModel):
    stage: Stage
    at: datetime
    evidence: str


class Run(BaseModel):
    id: UUID
    mode: Mode
    status: Literal["queued", "running", "verified", "failed", "incomplete"] = "queued"
    started_at: datetime
    ended_at: datetime | None = None
    live_demo_id: str | None = None
    events: list[Event] = Field(default_factory=list)


class Slot:
    """Single-process slot like the existing demo. Each observation is accepted once per run."""
    def __init__(self):
        self.lock = threading.Lock()
        self.seen: datetime | None = None
        self.run: Run | None = None

    def online(self, now):
        return self.seen is not None and now - self.seen < timedelta(seconds=30)

    def expire(self, now):
        if (self.run and self.run.status in ("queued", "running")
                and now - self.run.started_at >= timedelta(minutes=6)):
            self.run.status = "incomplete"
            self.run.ended_at = now

    def record(self, stage: Stage, message: str, at: datetime):
        run = self.run
        if not run or run.status != "running" or any(e.stage == stage for e in run.events):
            return
        run.events.append(Event(stage=stage, evidence=message, at=at))
        run.events.sort(key=lambda e: e.at)
        stages = {e.stage for e in run.events}
        if stage == "error" or REQUIRED <= stages:
            run.status = "failed" if stage == "error" else "verified"
            run.ended_at = datetime.now(UTC)


def observe_soc(slot, db, demo):
    run = slot.run
    if not run or run.mode != "observe" or run.status != "running":
        return
    # Only accept a runner session started inside this observation window.
    if not demo or datetime.fromisoformat(demo["requested_at"]) < run.started_at:
        return
    if run.live_demo_id and run.live_demo_id != demo["id"]:
        return
    starts = [datetime.fromisoformat(s["started_at"]) for s in demo["steps"] if s["started_at"]]
    if not starts:
        return
    start = min(starts)
    now = datetime.now(UTC)
    baseline = next((event for event in run.events if event.stage == "baseline"), None)
    if baseline is None:
        return
    if start < baseline.at:
        slot.record("error", "The live runner started before the ACL baseline was recorded.", now)
        return
    run.live_demo_id = demo["id"]
    slot.record("capture", f"Live Demo {demo['id']} runner reported a step start", start)
    for stage, sensor in (("lab_alert", SensorToken.name.startswith("lab-sensor-")),
                          ("cloud_alert", SensorToken.name == "cloud")):
        if any(e.stage == stage for e in run.events):
            continue
        row = db.execute(select(Alert, SensorToken.name).join(SensorToken)
                         .where(sensor, Alert.src_ip == SOURCE, Alert.dst_ip.in_(("10.10.2.10", "10.10.2.11")),
                                Alert.received_at.between(start, now),
                                Alert.end_ms.between(int(start.timestamp() * 1000), int(now.timestamp() * 1000)))
                         .order_by(Alert.received_at, Alert.id).limit(1)).first()
        if row:
            alert, name = row
            slot.record(stage, f"{name} alert #{alert.id}: {alert.predicted_class} from {SOURCE}",
                        alert.received_at)
    block = db.scalar(select(Block).join(SensorToken).where(
        SensorToken.name.startswith("lab-sensor-"), Block.source == BlockSource.AUTO,
        Block.ip == SOURCE, Block.blocked_at.between(start, now)).order_by(Block.blocked_at).limit(1))
    if block:
        slot.record("lab_block", f"Automatic lab block #{block.id} for {SOURCE}", block.blocked_at)


class View(BaseModel):
    enabled: bool
    worker_online: bool
    run: Run | None
    demo_status: str | None


@router.get("/c6", response_model=View)
def view(admin: AdminUser, request: Request, db: Annotated[Session, Depends(get_db)]):
    slot = request.app.state.c6
    demo = request.app.state.demo.snapshot()[1]
    now = datetime.now(UTC)
    with slot.lock:
        slot.expire(now)
        observe_soc(slot, db, demo)
        return View(enabled=request.app.state.settings.c6_token is not None,
                    worker_online=slot.online(now), run=slot.run.model_copy(deep=True) if slot.run else None,
                    demo_status=demo["status"] if demo else None)


@router.post("/admin/c6/run", status_code=202, response_model=Run)
def start(body: Start, admin: AdminUser, request: Request, db: Annotated[Session, Depends(get_db)]):
    slot = request.app.state.c6
    now = datetime.now(UTC)
    with slot.lock:
        slot.expire(now)
        if slot.run and slot.run.status in ("queued", "running"):
            raise HTTPException(409, "A C6 run is already active")
        if not request.app.state.settings.c6_token or not slot.online(now):
            raise HTTPException(503, "Start the C6 evidence worker on the lab host")
        run = Run(id=uuid4(), mode=body.mode, started_at=now)
        audit(db, admin, "c6_start", f"c6:{run.id}", {"mode": body.mode})
        db.commit()
        slot.run = run
        return run.model_copy(deep=True)


@router.post("/c6/worker/claim", response_model=Run | None)
def claim(worker: Runner, request: Request, db: Annotated[Session, Depends(get_db)]):
    slot = request.app.state.c6
    with slot.lock:
        slot.seen = datetime.now(UTC)
        slot.expire(slot.seen)
        observe_soc(slot, db, request.app.state.demo.snapshot()[1])
        if slot.run and slot.run.status == "queued":
            slot.run.status = "running"
            return slot.run.model_copy(deep=True)
        return None


@router.post("/c6/worker/report")
def report(body: Report, worker: Runner, request: Request, db: Annotated[Session, Depends(get_db)]):
    slot = request.app.state.c6
    with slot.lock:
        now = datetime.now(UTC)
        slot.expire(now)
        run = slot.run
        if not run or run.id != body.run_id or run.status == "queued":
            raise HTTPException(409, "No matching claimed run")
        if run.mode == "observe" and body.stage in SOC_STAGES | {"capture"}:
            raise HTTPException(422, "Live sensor and runner evidence comes from the SOC")
        existing = next((e for e in run.events if e.stage == body.stage), None)
        if existing and existing.evidence != body.evidence:
            raise HTTPException(409, "Conflicting evidence")
        if not existing and run.status != "running":
            raise HTTPException(409, "Run is closed")
        slot.seen = now
        slot.record(body.stage, body.evidence, now)
        observe_soc(slot, db, request.app.state.demo.snapshot()[1])
        capture = next((e for e in run.events if e.stage == "capture"), None)
        return {"status": run.status, "capture_at": capture.at if capture else None}
