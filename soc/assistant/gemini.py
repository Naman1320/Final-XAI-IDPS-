"""Gemini's native streaming Messages transport for the SOC's bounded tool loop."""

import http.client
import json
import re
import uuid
from collections.abc import Callable, Iterator

from soc.assistant.llm import LLMError, Turn
from soc.assistant.sse import events

API_HOST = "generativelanguage.googleapis.com"
DEFAULT_MODEL = "gemini-3.8-flash"


def _contents(messages: list[dict]) -> list[dict]:
    contents = []
    calls = {}
    for message in messages:
        content = message["content"]
        parts = []
        if isinstance(content, str):
            parts.append({"text": content})
        else:
            for block in content:
                kind = block["type"]
                if kind == "text":
                    part = {"text": block["text"]}
                elif kind == "tool_use":
                    if "gemini_call_id" not in block:
                        raise LLMError("Start a new conversation to use Gemini with SOC tools.")
                    call = {"name": block["name"], "args": block["input"]}
                    if block["gemini_call_id"]:
                        call["id"] = block["gemini_call_id"]
                    calls[block["id"]] = call
                    part = {"functionCall": call}
                elif kind == "tool_result":
                    call = calls[block["tool_use_id"]]
                    field = "error" if block.get("is_error") else "output"
                    result = {"name": call["name"], "response": {field: block["content"]}}
                    if "id" in call:
                        result["id"] = call["id"]
                    part = {"functionResponse": result}
                else:
                    continue
                if block.get("gemini_signature"):
                    part["thoughtSignature"] = block["gemini_signature"]
                parts.append(part)
        if parts:
            contents.append({"role": "model" if message["role"] == "assistant" else "user",
                             "parts": parts})
    return contents


def _reply(events: Iterator[dict], on_text: Callable[[str], None]) -> Turn:
    blocks = []
    finish = None
    for event in events:
        if event.get("error"):
            raise LLMError("Gemini reported an error while streaming the reply.")
        if event.get("promptFeedback", {}).get("blockReason"):
            return Turn([], "refusal")
        for candidate in event.get("candidates", []):
            finish = candidate.get("finishReason", finish)
            for part in candidate.get("content", {}).get("parts", []):
                if part.get("thought"):
                    continue
                if "functionCall" in part:
                    call = part["functionCall"]
                    block = {"type": "tool_use", "id": uuid.uuid4().hex, "name": call["name"],
                             "input": call.get("args", {}), "gemini_call_id": call.get("id")}
                elif "text" in part or "thoughtSignature" in part:
                    text = part.get("text", "")
                    on_text(text)
                    block = {"type": "text", "text": text}
                else:
                    continue
                if "thoughtSignature" in part:
                    block["gemini_signature"] = part["thoughtSignature"]
                blocks.append(block)
    if finish == "MAX_TOKENS":
        return Turn([b for b in blocks if b["type"] == "text"], "max_tokens")
    if finish in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "MODEL_ARMOR"}:
        return Turn([], "refusal")
    if finish != "STOP" or not blocks:
        raise LLMError("Gemini did not finish the reply. Please try again.")
    return Turn(blocks, "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn")


class GeminiLLM:
    def __init__(self, key: str, model: str):
        if not re.fullmatch(r"gemini-[a-zA-Z0-9.-]+", model):
            raise ValueError("invalid Gemini model name")
        self._key = key
        self.model = model

    def stream_turn(self, *, system: str, tools: list[dict], messages: list[dict],
                    on_text: Callable[[str], None]) -> Turn:
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": _contents(messages)}
        if tools:
            body["tools"] = [{"functionDeclarations": [
                {"name": t["name"], "description": t["description"],
                 "parametersJsonSchema": t["input_schema"]} for t in tools
            ]}]
        conn = http.client.HTTPSConnection(API_HOST, timeout=120)
        try:
            conn.request("POST", f"/v1beta/models/{self.model}:streamGenerateContent?alt=sse",
                         body=json.dumps(body).encode(), headers={"x-goog-api-key": self._key,
                                                                 "Content-Type": "application/json"})
            response = conn.getresponse()
            if response.status in (401, 403):
                raise LLMError("Google rejected the Gemini credential or its permissions. "
                               "Check the Gemini Developer API key configured on the SOC server.")
            if response.status == 429:
                raise LLMError("Gemini quota or rate limit reached. Check the project's quota.")
            if response.status != 200:
                raise LLMError(f"Gemini returned HTTP {response.status}. Check model access and configuration.")
            return _reply(events(response), on_text)
        except (OSError, http.client.HTTPException) as exc:
            raise LLMError("Could not reach the Gemini API over HTTPS.") from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMError("Gemini returned an unreadable reply.") from exc
        finally:
            conn.close()
