"""SOC assistant endpoints: status, conversations, and the streaming chat."""

import asyncio
import json
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from soc.api.auth import AnyUser
from soc.api.common import audit
from soc.api.db import get_db
from soc.api.models import AssistantConversation, User
from soc.assistant.chat import run_reply_safely

router = APIRouter(prefix="/assistant", tags=["assistant"])

MAX_MESSAGE_CHARS = 4000


class _RateLimiter:
    """Messages per user in a sliding 10-minute window (in memory, per API process)."""

    def __init__(self, limit: int, window: float = 600.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[int, deque] = {}
        self._lock = threading.Lock()

    def allow(self, user_id: int) -> bool:
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(user_id, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class Status(BaseModel):
    enabled: bool
    model: str | None
    reason: str | None = None


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)
    conversation_id: int | None = Field(default=None, ge=1)


class ConversationSummary(BaseModel):
    id: int
    title: str
    user_turns: int
    updated_at: datetime


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    text: str
    tools: list[str] = []


class ConversationOut(ConversationSummary):
    messages: list[ChatMessage]


@router.get("/status", response_model=Status)
def assistant_status(request: Request, user: AnyUser):
    llm = request.app.state.assistant_llm
    if llm is None:
        return Status(enabled=False, model=None,
                      reason="No model API key is configured on the SOC server "
                             "(GROQ_API_KEY, GEMINI_API_KEY or ANTHROPIC_API_KEY).")
    return Status(enabled=True, model=llm.model)


def _own(db: Session, conversation_id: int, user: User) -> AssistantConversation:
    conv = db.get(AssistantConversation, conversation_id)
    if conv is None or conv.user_id != user.id:  # same answer: don't reveal others' chats
        raise HTTPException(status.HTTP_404_NOT_FOUND, "conversation not found")
    return conv


def _visible(messages: list[dict]) -> list[ChatMessage]:
    """The readable part of a stored history: user text and assistant text, with tool names."""
    out: list[ChatMessage] = []
    for m in messages:
        content = m.get("content")
        if m.get("role") == "user":
            if isinstance(content, str):
                out.append(ChatMessage(role="user", text=content))
            continue  # tool results
        texts = [b.get("text", "") for b in content or [] if b.get("type") == "text"]
        tools = [b.get("name", "") for b in content or [] if b.get("type") == "tool_use"]
        if out and out[-1].role == "assistant":  # one bubble per reply, across tool rounds
            out[-1].text += "".join(texts)
            out[-1].tools += tools
        else:
            out.append(ChatMessage(role="assistant", text="".join(texts), tools=tools))
    return out


@router.get("/conversations", response_model=list[ConversationSummary])
def list_conversations(user: AnyUser, db: Annotated[Session, Depends(get_db)]):
    rows = db.scalars(select(AssistantConversation)
                      .where(AssistantConversation.user_id == user.id)
                      .order_by(AssistantConversation.updated_at.desc()).limit(50))
    return [ConversationSummary.model_validate(r, from_attributes=True) for r in rows]


@router.get("/conversations/{conversation_id}", response_model=ConversationOut)
def get_conversation(conversation_id: int, user: AnyUser,
                     db: Annotated[Session, Depends(get_db)]):
    conv = _own(db, conversation_id, user)
    return ConversationOut(id=conv.id, title=conv.title, user_turns=conv.user_turns,
                           updated_at=conv.updated_at, messages=_visible(conv.messages))


BUSY_TIMEOUT = timedelta(minutes=10)  # a reply still "running" after this is assumed dead
_SENTINEL = object()


def save_reply(session_factory, conv_id: int, user_message: dict, new_messages: list[dict]) -> None:
    """Store a finished reply: the stored messages as they are NOW (an erasure of an IP address
    may have rewritten them while the reply ran; writing back the copy taken at the start would
    restore what was erased), then this turn's user message and the new messages."""
    with session_factory() as s:
        c = s.get(AssistantConversation, conv_id)
        c.messages = [*c.messages, user_message, *new_messages]  # a new list: the JSON column updates
        c.user_turns += 1
        c.busy_since = None
        c.updated_at = datetime.now(UTC)
        s.commit()


def _start_reply(app, user_id: int, body: ChatIn) -> tuple[int, list[dict]]:
    """Check limits and claim the conversation (sync DB work, run in the thread pool)."""
    settings = app.state.settings
    now = datetime.now(UTC)
    stale = now - BUSY_TIMEOUT
    with app.state.session_factory() as db:
        user = db.get(User, user_id)
        running = db.scalar(select(func.count()).select_from(AssistantConversation).where(
            AssistantConversation.user_id == user_id,
            AssistantConversation.busy_since.is_not(None),
            AssistantConversation.busy_since > stale))
        if running:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "a reply is still running; wait for it or stop it first")
        if body.conversation_id is None:
            conv = AssistantConversation(user_id=user_id, title=body.message.strip()[:120],
                                         messages=[], busy_since=now)
            db.add(conv)
            db.flush()
        else:
            conv = _own(db, body.conversation_id, user)
            if conv.user_turns >= settings.assistant_max_turns:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    "this conversation is full; start a new one")
            # Claim it: of two simultaneous messages, only one gets the conversation.
            claimed = db.execute(
                update(AssistantConversation)
                .where(AssistantConversation.id == conv.id,
                       or_(AssistantConversation.busy_since.is_(None),
                           AssistantConversation.busy_since <= stale))
                .values(busy_since=now)).rowcount
            if claimed != 1:
                db.rollback()
                raise HTTPException(status.HTTP_409_CONFLICT, "a reply is still running")
            db.refresh(conv)
        # Counted only once the request is going to run.
        if not _limiter_for(app).allow(user_id):
            db.rollback()
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many assistant messages; wait a few minutes")
        history = list(conv.messages) + [{"role": "user", "content": body.message}]
        audit(db, user, "assistant_message", f"conversation:{conv.id}",
              {"chars": len(body.message)})
        db.commit()
        return conv.id, history


def _limiter_for(app) -> _RateLimiter:
    if getattr(app.state, "assistant_limiter", None) is None:
        app.state.assistant_limiter = _RateLimiter(app.state.settings.assistant_rate_per_10min)
    return app.state.assistant_limiter


def _slots(app) -> threading.BoundedSemaphore:
    if getattr(app.state, "assistant_slots", None) is None:
        app.state.assistant_slots = threading.BoundedSemaphore(
            app.state.settings.assistant_max_concurrent)
    return app.state.assistant_slots


@router.post("/chat")
async def chat(body: ChatIn, request: Request, user: AnyUser):
    """Stream one reply as NDJSON (one JSON event per line; see soc/assistant/chat.py).

    The model runs in a worker thread and events reach this async generator through an
    asyncio queue, so a long reply doesn't hold one of the server's shared worker threads.
    Closing the connection (or the Stop button) cancels the reply between steps.
    """
    app = request.app
    settings = app.state.settings
    llm = app.state.assistant_llm
    if llm is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "the assistant is switched off (no model API key configured)")
    slots = _slots(app)
    if not slots.acquire(blocking=False):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "the assistant is busy with other analysts; try again shortly")
    try:
        conv_id, history = await run_in_threadpool(_start_reply, app, user.id, body)
    except BaseException:
        slots.release()
        raise

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    cancel = threading.Event()

    def emit(event) -> None:
        try:
            loop.call_soon_threadsafe(queue.put_nowait, event)
        except RuntimeError:  # the event loop is gone (server shutting down)
            cancel.set()

    def save(new_messages: list[dict]) -> None:
        save_reply(app.state.session_factory, conv_id, history[-1], new_messages)

    def work() -> None:
        try:
            run_reply_safely(llm, history, session_factory=app.state.session_factory,
                             user_id=user.id, settings=settings, emit=emit, cancel=cancel,
                             on_finish=save)
        finally:
            slots.release()
            emit(_SENTINEL)

    threading.Thread(target=work, daemon=True).start()

    async def lines():
        try:
            yield json.dumps({"type": "conversation", "conversation_id": conv_id}) + "\n"
            while (event := await queue.get()) is not _SENTINEL:
                yield json.dumps(event, default=str) + "\n"
        finally:
            cancel.set()  # the client went away, or the reply ended: stop between steps

    return StreamingResponse(lines(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
