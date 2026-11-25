"""Live demo: an admin starts a fixed attack run from the dashboard; a host-side runner does it.

The SOC never runs or reaches the attack tools: the lab keeps it isolated from the attacker, and
this module opens no connection anywhere. A separate demo runner on the lab host
(scripts/demo_runner.py) polls `GET /demo/runner/next` with the shared secret
IDPS_SOC_DEMO_TOKEN, runs the fixed scripts for the steps below and reports each step back.
The browser can only ask for "the demo" (no parameters): the steps, their order and what they
do are fixed here and in the runner, so nothing a user sends becomes a command or a target.

State is in memory (one SOC process, see docs/soc.md "Live feed"): one run slot, no migration.
A restart forgets the run, which is fine for a demo. Demo mode is off unless the token is set.
See docs/soc.md, "Live demo".
"""

from __future__ import annotations

import copy
import hmac
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, get_args

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from soc.api.auth import AdminUser, AnyUser, client_ip
from soc.api.common import audit, plain_text
from soc.api.db import get_db
from soc.api.security import LoginThrottle

router = APIRouter(tags=["demo"])

# The steps, in order. Only these keys are accepted from the runner.
STEPS: tuple[dict[str, str], ...] = (
    {"key": "portscan", "label": "Port scan (nmap)"},
    {"key": "ssh_bruteforce", "label": "SSH brute force (hydra)"},
    {"key": "syn_flood", "label": "SYN flood (hping3)"},
    {"key": "settle", "label": "Wait for flows to end (about 150 s)"},
)
STEP_KEYS = tuple(s["key"] for s in STEPS)

RUNNER_ONLINE_SECONDS = 30  # a runner not heard from for this long is offline
RUN_TTL = timedelta(minutes=15)  # a queued or running run older than this expires
RUNNER_GONE_SECONDS = 60  # a running run whose runner has been silent this long is failed early
MAX_NOTE = 200
MAX_TOKEN_LENGTH = 256
BAD_TOKEN_LIMIT = 10  # wrong X-Demo-Token values per client address ...
BAD_TOKEN_WINDOW = 600  # ... per this many seconds, then 429

ACTIVE = ("queued", "running")
STEP_TERMINAL = ("done", "failed", "skipped")
DEMO_OFF = "demo mode is off (IDPS_SOC_DEMO_TOKEN is not set)"
RUNNER_OFFLINE = "demo runner is not running (start scripts/demo_runner.py on the lab host)"

StepKey = Literal["portscan", "ssh_bruteforce", "syn_flood", "settle"]
StepStatus = Literal["pending", "running", "done", "failed", "skipped"]
RunStatus = Literal["queued", "running", "done", "failed", "cancelled", "expired"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --- state ------------------------------------------------------------------------------

class DemoState:
    """The one run slot and the runner's last heartbeat. Thread-safe (FastAPI runs these sync
    routes in a thread pool). `clock` returns an aware UTC datetime; tests replace it."""

    def __init__(self, clock: Callable[[], datetime] = _utcnow) -> None:
        self.clock = clock
        self._lock = threading.Lock()
        self._run: dict | None = None
        self._runner_seen: datetime | None = None

    # Callers hold the lock for everything below that starts with an underscore.

    def _now(self) -> str:
        return self.clock().isoformat()

    def _expire(self) -> None:
        run = self._run
        if run is None or run["status"] not in ACTIVE:
            return
        if self.clock() - datetime.fromisoformat(run["requested_at"]) >= RUN_TTL:
            self._finish(run, "expired", "run expired after 15 minutes")
        elif run["status"] == "running" and (
                self._runner_seen is None
                or (self.clock() - self._runner_seen).total_seconds() > RUNNER_GONE_SECONDS):
            # The runner reports at least every 15 s while a step runs, so silence means it died
            # (or lost the SOC): nothing is executing, so don't show "running" for 15 minutes.
            self._finish(run, "failed", "runner went away", replace_running_note=True)

    def restore(self, expected_id: str, previous: dict | None) -> None:
        """Undo start/cancel when its audit row could not be saved: put `previous` back, but only
        while the slot still holds the run that change touched."""
        with self._lock:
            if self._run is not None and self._run["id"] == expected_id:
                self._run = copy.deepcopy(previous)

    def _finish(self, run: dict, run_status: str, note: str, replace_running_note: bool = False) -> None:
        now = self._now()
        for step in run["steps"]:
            if step["status"] in ("pending", "running"):
                if step["status"] == "running" and replace_running_note:
                    step["note"] = note
                else:
                    step["note"] = step["note"] or note
                step["status"] = "skipped"
                if step["started_at"] is not None:
                    step["ended_at"] = now
        run["status"] = run_status
        run["finished_at"] = now

    def _runner_online(self) -> bool:
        return (self._runner_seen is not None
                and (self.clock() - self._runner_seen).total_seconds() <= RUNNER_ONLINE_SECONDS)

    # --- public -------------------------------------------------------------------------

    def snapshot(self) -> tuple[bool, dict | None]:
        with self._lock:
            self._expire()
            return self._runner_online(), copy.deepcopy(self._run)

    def start(self, username: str) -> dict:
        """A new queued run; HTTPException 409 if one is active or no runner is polling."""
        with self._lock:
            self._expire()
            if self._run is not None and self._run["status"] in ACTIVE:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"a demo run is already {self._run['status']}")
            if not self._runner_online():
                raise HTTPException(status.HTTP_409_CONFLICT, RUNNER_OFFLINE)
            self._run = {
                "id": str(uuid.uuid4()), "status": "queued", "requested_by": username,
                "requested_at": self._now(), "finished_at": None,
                "steps": [{**s, "status": "pending", "started_at": None, "ended_at": None,
                           "note": ""} for s in STEPS],
            }
            return copy.deepcopy(self._run)

    def cancel(self) -> dict:
        with self._lock:
            self._expire()
            if self._run is None or self._run["status"] not in ACTIVE:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "no demo run is active")
            self._finish(self._run, "cancelled", "cancelled")
            return copy.deepcopy(self._run)

    def next_for_runner(self) -> dict | None:
        """Heartbeat; hands over a queued run once (it becomes running)."""
        with self._lock:
            self._runner_seen = self.clock()
            self._expire()
            run = self._run
            if run is None or run["status"] != "queued":
                return None
            run["status"] = "running"
            return copy.deepcopy(run)

    def report(self, run_id: str, step_key: str, new: str, note: str) -> bool:
        """Apply a step report. Returns True when the runner should stop (cancelled or expired).
        HTTPException 404 for an unknown run, 409 for a transition that isn't allowed."""
        with self._lock:
            self._runner_seen = self.clock()
            self._expire()
            run = self._run
            if run is None or run["id"] != run_id:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "demo run not found")
            stop = run["status"] in ("cancelled", "expired")
            index = STEP_KEYS.index(step_key)
            step = run["steps"][index]
            if step["status"] == new:
                # A repeated report (a retry after a lost reply, or the runner's periodic "still
                # running"): nothing changes, except a running step's progress note.
                if new == "running" and note and not stop:
                    step["note"] = note
                return stop
            if stop:
                return True
            if run["status"] != "running":
                raise HTTPException(status.HTTP_409_CONFLICT, f"the demo run is {run['status']}")
            if step["status"] in STEP_TERMINAL:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"step {step_key} is already {step['status']}")
            if new == "running" and step["status"] != "pending":
                raise HTTPException(status.HTTP_409_CONFLICT, f"step {step_key} already started")
            earlier = [s for s in run["steps"][:index] if s["status"] not in ("done", "skipped")]
            if earlier:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"step {earlier[0]['key']} has not finished yet")
            now = self._now()
            if new == "running":
                step["started_at"] = now
            else:
                if step["started_at"] is None and new != "skipped":
                    step["started_at"] = now
                step["ended_at"] = now
            step["status"] = new
            if note:
                step["note"] = note
            if new == "failed":
                self._finish(run, "failed", f"skipped: {step['label']} failed")
            elif all(s["status"] in ("done", "skipped") for s in run["steps"]):
                run["status"] = "done"
                run["finished_at"] = now
            return False


def demo_state(request: Request) -> DemoState:
    return request.app.state.demo  # created in create_app


def new_token_throttle() -> LoginThrottle:
    return LoginThrottle(BAD_TOKEN_LIMIT, BAD_TOKEN_LIMIT, BAD_TOKEN_WINDOW)


def _demo_on(request: Request) -> bool:
    return request.app.state.settings.demo_token is not None


def require_runner(request: Request, x_demo_token: Annotated[
        str | None, Header(alias="X-Demo-Token")] = None) -> None:
    """The demo runner: X-Demo-Token must equal IDPS_SOC_DEMO_TOKEN (constant-time compare).
    404 while demo mode is off, 401 for a missing or wrong token, 429 for wrong tokens after too
    many wrong ones from the same address.

    A CORRECT token is always accepted, even while the address is locked out: every host-side
    request arrives from the same address (127.0.0.1), so a lockout that also refused the right
    token would let anything on the host cut a run off by sending ten bad tokens. The lockout only
    slows guessing, which the 32+ character secret already makes infeasible (docs/soc.md)."""
    secret = request.app.state.settings.demo_token
    if secret is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, DEMO_OFF)
    given = (x_demo_token or "")[:MAX_TOKEN_LENGTH + 1].encode("utf-8")
    if given and hmac.compare_digest(given, secret.get_secret_value().encode("utf-8")):
        return
    throttle: LoginThrottle = request.app.state.demo_token_throttle
    if throttle.begin_attempt("demo-runner", client_ip(request)) is None:  # counts as a failure
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many wrong demo tokens; try again later")
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or wrong X-Demo-Token")


Runner = Annotated[None, Depends(require_runner)]
State = Annotated[DemoState, Depends(demo_state)]


# --- schemas ----------------------------------------------------------------------------

class StepOut(BaseModel):
    key: str
    label: str
    status: StepStatus
    started_at: datetime | None
    ended_at: datetime | None
    note: str


class RunOut(BaseModel):
    id: str
    status: RunStatus
    requested_by: str
    requested_at: datetime
    finished_at: datetime | None
    steps: list[StepOut]


class DemoOut(BaseModel):
    enabled: bool  # demo mode on (IDPS_SOC_DEMO_TOKEN set)
    runner_online: bool
    run: RunOut | None


class RunnerNext(BaseModel):
    run: RunOut | None


class StepReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: uuid.UUID
    step_key: StepKey
    status: Literal["running", "done", "failed", "skipped"]
    note: Annotated[str, Field(max_length=MAX_NOTE), AfterValidator(plain_text)] = ""


class ReportOut(BaseModel):
    cancelled: bool  # the run was cancelled or expired: the runner should stop


assert get_args(StepKey) == STEP_KEYS  # the schema and the step list must not drift apart


# --- user endpoints ---------------------------------------------------------------------

@router.get("/demo", response_model=DemoOut)
def get_demo(user: AnyUser, request: Request, state: State):
    online, run = state.snapshot()
    return DemoOut(enabled=_demo_on(request), runner_online=online and _demo_on(request), run=run)


@router.post("/admin/demo/run", response_model=RunOut, status_code=status.HTTP_202_ACCEPTED)
def start_run(admin: AdminUser, request: Request, state: State,
              db: Annotated[Session, Depends(get_db)]):
    if not _demo_on(request):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, DEMO_OFF)
    previous = state.snapshot()[1]
    run = state.start(admin.username)
    try:
        audit(db, admin, "demo_run", f"demo:{run['id']}", {"steps": list(STEP_KEYS)})
        db.commit()
    except Exception:
        db.rollback()
        state.restore(run["id"], previous)  # no audit row, so no run
        raise
    return run


@router.post("/admin/demo/cancel", response_model=RunOut)
def cancel_run(admin: AdminUser, state: State, db: Annotated[Session, Depends(get_db)]):
    previous = state.snapshot()[1]
    run = state.cancel()
    try:
        audit(db, admin, "demo_cancel", f"demo:{run['id']}")
        db.commit()
    except Exception:
        db.rollback()
        state.restore(run["id"], previous)
        raise
    return run


# --- runner endpoints -------------------------------------------------------------------

@router.get("/demo/runner/next", response_model=RunnerNext)
def runner_next(runner: Runner, state: State):
    return RunnerNext(run=state.next_for_runner())


@router.post("/demo/runner/report", response_model=ReportOut)
def runner_report(body: StepReport, runner: Runner, state: State):
    stop = state.report(str(body.run_id), body.step_key, body.status, body.note.strip())
    return ReportOut(cancelled=stop)
