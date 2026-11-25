"""Groq Chat Completions adapter for the SOC's existing tool and conversation format."""

import http.client
import json
from collections.abc import Callable, Iterator

from soc.assistant.llm import LLMError, Turn
from soc.assistant.sse import events

DEFAULT_MODEL = "openai/gpt-oss-20b"


def _messages(system: str, history: list[dict]) -> list[dict]:
    result = [{"role": "system", "content": system}]
    for message in history:
        content = message["content"]
        if isinstance(content, str):
            result.append({"role": message["role"], "content": content})
        elif message["role"] == "assistant":
            text = "".join(b["text"] for b in content if b["type"] == "text")
            calls = [{"id": b["id"], "type": "function",
                      "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                     for b in content if b["type"] == "tool_use"]
            if calls or text:
                reply = {"role": "assistant", "content": text or None}
                if calls:
                    reply["tool_calls"] = calls
                result.append(reply)
        else:
            for block in content:
                if block["type"] == "tool_result":
                    result.append({"role": "tool", "tool_call_id": block["tool_use_id"],
                                   "content": block["content"]})
    return result


def _reply(chunks: Iterator[dict], on_text: Callable[[str], None]) -> Turn:
    finish = None
    text = []
    calls = {}
    for chunk in chunks:
        if chunk.get("error"):
            raise LLMError("Groq reported an error while streaming the reply.")
        for choice in chunk.get("choices", []):
            delta = choice.get("delta", {})
            if delta.get("refusal"):
                return Turn([], "refusal")
            if part := delta.get("content"):
                on_text(part)
                text.append(part)
            for fragment in delta.get("tool_calls") or []:
                call = calls.setdefault(fragment["index"], {"id": "", "name": "", "args": ""})
                function = fragment.get("function") or {}
                call["id"] += fragment.get("id") or ""
                call["name"] += function.get("name") or ""
                call["args"] += function.get("arguments") or ""
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    blocks = [{"type": "text", "text": "".join(text)}] if text else []
    if finish == "content_filter":
        return Turn([], "refusal")
    if finish == "length":
        return Turn(blocks, "max_tokens")
    if finish == "tool_calls" and calls:
        for index in sorted(calls):
            call = calls[index]
            args = json.loads(call["args"] or "{}")
            if not call["id"] or not call["name"] or not isinstance(args, dict):
                raise LLMError("Groq returned an incomplete tool request.")
            blocks.append({"type": "tool_use", "id": call["id"], "name": call["name"], "input": args})
        return Turn(blocks, "tool_use")
    if finish == "stop" and blocks and not calls:
        return Turn(blocks, "end_turn")
    raise LLMError("Groq did not finish its reply. Please try again.")


class GroqLLM:
    def __init__(self, key: str, model: str):
        self._key = key
        self.model = model

    def stream_turn(self, *, system: str, tools: list[dict], messages: list[dict],
                    on_text: Callable[[str], None]) -> Turn:
        body = {"model": self.model, "stream": True, "messages": _messages(system, messages)}
        if tools:
            body["tools"] = [{"type": "function", "function": {
                "name": tool["name"], "description": tool["description"],
                "parameters": tool["input_schema"]}} for tool in tools]
        conn = http.client.HTTPSConnection("api.groq.com", timeout=120)
        try:
            conn.request("POST", "/openai/v1/chat/completions", body=json.dumps(body).encode(),
                         headers={"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"})
            response = conn.getresponse()
            if response.status in (401, 403):
                raise LLMError("Groq rejected the API key or its model permissions.")
            if response.status == 429:
                raise LLMError("Groq's quota or rate limit was reached. Try again later.")
            if response.status != 200:
                raise LLMError(f"Groq returned HTTP {response.status}. Check the configured model.")
            return _reply(events(response), on_text)
        except (OSError, http.client.HTTPException) as exc:
            raise LLMError("Could not reach the Groq API over HTTPS.") from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMError("Groq returned an unreadable reply.") from exc
        finally:
            conn.close()
