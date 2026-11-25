"""One assistant reply: the model-and-tools loop, emitted as a stream of small events.

Events (dicts, sent to the browser as NDJSON):
    {"type": "text", "text": "..."}                       a piece of the answer
    {"type": "tool", "name": "...", "input": {...}}       the model called a tool
    {"type": "tool_result", "name": "...", "ok": bool}    the tool finished
    {"type": "action_proposed", "action_id": N, "ip": "..."}
    {"type": "error", "message": "..."}
    {"type": "done", "stop_reason": "..."}
"""

import logging
import threading
from collections.abc import Callable

from sqlalchemy.orm import Session

from soc.api.models import User
from soc.api.settings import SocSettings
from soc.assistant.llm import LLM, LLMError
from soc.assistant.prompt import SYSTEM_PROMPT
from soc.assistant.tools import TOOLS, run_tool

log = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 8  # model -> tools -> model cycles per reply
MAX_CALLS_PER_ROUND = 6  # tool calls the model may make in one turn
MAX_PROPOSALS_PER_REPLY = 3  # propose_block calls per reply


class Cancelled(Exception):
    pass


def _result(tool_use_id: str, content: str, is_error: bool = False) -> dict:
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": content,
            **({"is_error": True} if is_error else {})}


def make_valid(new: list[dict]) -> list[dict]:
    """Make `new` safe to save and resend: every tool call answered, no empty assistant turn.

    Used after a reply ends early (cancelled, model error), so the next message in the
    conversation isn't rejected by the API.
    """
    out = [m for m in new if not (m["role"] == "assistant" and not m["content"])]
    if out and out[-1]["role"] == "assistant":
        pending = [b["id"] for b in out[-1]["content"] if b.get("type") == "tool_use"]
        if pending:
            out.append({"role": "user", "content": [
                _result(i, "not run: the reply was interrupted", True) for i in pending]})
    return out


def run_reply(llm: LLM, messages: list[dict], new: list[dict], *, db: Session, user_id: int,
              settings: SocSettings, emit: Callable[[dict], None],
              cancel: threading.Event) -> None:
    """Run one reply to the last user message in `messages`, appending to `new` as it goes
    (assistant turns and tool results, exactly as the API needs them back next time). `new`
    is the caller's list, so whatever was done is saved even if this stops part-way."""
    proposals = 0
    for _ in range(MAX_TOOL_ROUNDS):
        if cancel.is_set():
            raise Cancelled
        user = db.get(User, user_id)
        if user is None or user.disabled:  # disabled while the reply was running
            raise Cancelled
        turn = llm.stream_turn(system=SYSTEM_PROMPT, tools=TOOLS, messages=messages + new,
                               on_text=lambda t: emit({"type": "text", "text": t}))
        if turn.stop_reason == "refusal":
            # Not saved: a declined turn (possibly with a cut-off tool call) would make the
            # conversation unusable. The analyst can rephrase.
            emit({"type": "error", "message": "The model declined to answer this request."})
            emit({"type": "done", "stop_reason": "refusal"})
            return
        if turn.content:
            new.append({"role": "assistant", "content": turn.content})
        tool_uses = [b for b in turn.content if b.get("type") == "tool_use"]
        if turn.stop_reason == "pause_turn" and not tool_uses:
            continue  # the API paused a long turn; sending the history again resumes it
        if turn.stop_reason != "tool_use" or not tool_uses:
            if turn.stop_reason == "max_tokens":
                emit({"type": "error", "message": "The answer was cut off (too long)."})
            elif turn.stop_reason == "model_context_window_exceeded":
                emit({"type": "error",
                      "message": "This conversation is too long; start a new one."})
            if tool_uses:  # a call cut off mid-way can't be run, but needs a result
                new.append({"role": "user", "content": [
                    _result(b["id"], "not run: the reply ended before the call was complete",
                            True) for b in tool_uses]})
            emit({"type": "done", "stop_reason": turn.stop_reason})
            return
        results = []
        for n, block in enumerate(tool_uses):
            name = block["name"]
            if cancel.is_set():
                results.append(_result(block["id"], "not run: cancelled", True))
                continue
            if n >= MAX_CALLS_PER_ROUND:
                results.append(_result(block["id"], "not run: too many tool calls in one "
                                       f"turn (limit {MAX_CALLS_PER_ROUND})", True))
                continue
            if name == "propose_block":
                if proposals >= MAX_PROPOSALS_PER_REPLY:
                    results.append(_result(block["id"], "not run: at most "
                                           f"{MAX_PROPOSALS_PER_REPLY} block proposals per reply",
                                           True))
                    continue
                proposals += 1
            emit({"type": "tool", "name": name, "input": block.get("input", {})})
            text, is_error, data = run_tool(name, block.get("input"), db=db, user=user,
                                            settings=settings)
            emit({"type": "tool_result", "name": name, "ok": not is_error})
            if name == "propose_block" and not is_error:
                emit({"type": "action_proposed", "action_id": data["action_id"],
                      "ip": data["ip"]})
            results.append(_result(block["id"], text, is_error))
        # All results for one turn go back together, in a single user message.
        new.append({"role": "user", "content": results})
    emit({"type": "error", "message": "Stopped after too many tool calls; try a narrower question."})
    emit({"type": "done", "stop_reason": "tool_limit"})


def run_reply_safely(llm: LLM, messages: list[dict], *, session_factory, user_id: int,
                     settings: SocSettings, emit: Callable[[dict], None],
                     cancel: threading.Event, on_finish: Callable[[list[dict]], None]) -> None:
    """Run a reply in its own database session and always save what was done (on_finish),
    whether it completed, was cancelled or failed. Errors are reported without internals."""
    new: list[dict] = []
    try:
        with session_factory() as db:
            run_reply(llm, messages, new, db=db, user_id=user_id, settings=settings,
                      emit=emit, cancel=cancel)
    except Cancelled:
        emit({"type": "done", "stop_reason": "cancelled"})
    except LLMError as exc:
        emit({"type": "error", "message": str(exc)})
        emit({"type": "done", "stop_reason": "error"})
    except Exception:
        log.exception("assistant reply failed")
        emit({"type": "error", "message": "The assistant hit an internal error."})
        emit({"type": "done", "stop_reason": "error"})
    finally:
        try:
            on_finish(make_valid(new))
        except Exception:
            log.exception("saving the assistant conversation failed")
