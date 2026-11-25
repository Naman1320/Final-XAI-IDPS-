"""The model behind the assistant, behind a small interface so tests can use a scripted fake.

AnthropicLLM uses the official Anthropic Python SDK. Credentials come from the environment
(ANTHROPIC_API_KEY, or an `ant auth login` profile); they are never sent to the browser.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

DEFAULT_MODEL = "claude-opus-5-5"
MAX_TOKENS = 16_000
# Server-side fallback: if the model declines a request, the API retries it on a fallback
# model chosen by refusal category, inside the same call.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AssistantUnavailable(Exception):
    """No credentials, or the SDK isn't installed."""


class LLMError(Exception):
    """The model call failed (network, rate limit, API error). The message is safe to show."""


@dataclass
class Turn:
    content: list[dict[str, Any]]  # the assistant's content blocks, as JSON, to send back as-is
    stop_reason: str | None


class LLM(Protocol):
    model: str

    def stream_turn(self, *, system: str, tools: list[dict], messages: list[dict],
                    on_text: Callable[[str], None]) -> Turn: ...


class AnthropicLLM:
    def __init__(self, model: str = DEFAULT_MODEL, effort: str = "medium"):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - it's a project dependency
            raise AssistantUnavailable("the anthropic package is not installed") from exc
        self._anthropic = anthropic
        try:
            self.client = anthropic.Anthropic(max_retries=2, timeout=120.0)
        except anthropic.AnthropicError as exc:
            raise AssistantUnavailable("no Anthropic credentials (set ANTHROPIC_API_KEY)") from exc
        self.model = model
        self.effort = effort

    def stream_turn(self, *, system: str, tools: list[dict], messages: list[dict],
                    on_text: Callable[[str], None]) -> Turn:
        if any("gemini_call_id" in block or "gemini_signature" in block
               for message in messages if isinstance(message["content"], list)
               for block in message["content"]):
            raise LLMError("Start a new conversation to switch from Gemini to Claude.")
        a = self._anthropic
        try:
            with self.client.beta.messages.stream(
                model=self.model,
                max_tokens=MAX_TOKENS,
                # The system prompt and tool list never change, so they are cached.
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                tools=tools,
                messages=messages,
                # Caches the growing conversation too, so each tool round doesn't resend the
                # whole history at full price.
                cache_control={"type": "ephemeral"},
                output_config={"effort": self.effort},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            ) as stream:
                for event in stream:
                    if event.type == "text":
                        on_text(event.text)
                final = stream.get_final_message()
        except a.RateLimitError as exc:
            raise LLMError("the assistant is rate limited; try again in a minute") from exc
        except a.AuthenticationError as exc:
            raise LLMError("the assistant's API key was rejected") from exc
        except a.APIConnectionError as exc:
            raise LLMError("can't reach the Anthropic API") from exc
        except a.APIStatusError as exc:
            raise LLMError(f"the Anthropic API returned an error ({exc.status_code})") from exc
        # by_alias: the API's field names (a fallback block's "from", not the SDK's "from_").
        content = [b.model_dump(mode="json", by_alias=True, exclude_none=True)
                   for b in final.content]
        return Turn(content=trim_before_fallback(content), stop_reason=final.stop_reason)


# Blocks from a model that declined mid-output and must not be echoed back (or acted on).
_DROP_BEFORE_FALLBACK = {"thinking", "redacted_thinking", "tool_use", "server_tool_use"}


def trim_before_fallback(content: list[dict]) -> list[dict]:
    """Apply the Messages API rule for echoing a turn that contains a `fallback` block.

    Before the LAST fallback block, keep text blocks and fallback blocks and drop thinking,
    tool calls and unknown block types (they belong to a model that declined; its tool calls
    must not run). Everything after the last fallback block is kept as is.
    """
    last = max((i for i, b in enumerate(content) if b.get("type") == "fallback"), default=-1)
    if last < 0:
        return content
    head = [b for b in content[:last] if b.get("type") in ("text", "fallback")
            and b.get("type") not in _DROP_BEFORE_FALLBACK]
    return head + content[last:]


def make_llm(model: str, effort: str) -> LLM | None:
    """Select Groq, Gemini, or Claude according to the available server credentials."""
    if key := os.getenv("GROQ_API_KEY"):
        from soc.assistant.groq import DEFAULT_MODEL as GROQ_DEFAULT
        from soc.assistant.groq import GroqLLM

        return GroqLLM(key, os.getenv("IDPS_SOC_GROQ_MODEL") or GROQ_DEFAULT)
    if key := os.getenv("GEMINI_API_KEY"):
        from soc.assistant.gemini import DEFAULT_MODEL as GEMINI_DEFAULT
        from soc.assistant.gemini import GeminiLLM

        return GeminiLLM(key, os.getenv("IDPS_SOC_GEMINI_MODEL") or GEMINI_DEFAULT)
    try:
        llm = AnthropicLLM(model, effort)
    except AssistantUnavailable:
        return None
    if not (llm.client.api_key or getattr(llm.client, "auth_token", None)):
        return None
    return llm
