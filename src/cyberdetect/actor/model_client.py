"""Minimal OpenAI-compatible chat client with tool-calling, plus a mock client.

The wire format is the widely-implemented ``POST {base_url}/chat/completions`` schema
(Together, Fireworks, DeepInfra, vLLM, Ollama, ...). Only the standard library is used
so the frozen dependency set stays small and the same client works against any provider
or a local server. A ``MockChatClient`` lets the whole actor/defender pipeline run and be
tested without credentials.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatResult:
    content: str | None
    tool_calls: list[ToolCall]
    finish_reason: str
    input_tokens: int
    output_tokens: int
    raw: dict[str, Any] = field(default_factory=dict)


class ModelCallError(RuntimeError):
    """A model call failed after exhausting retries (a rerunnable infrastructure fault)."""


class ChatClient(Protocol):
    model_id: str
    revision: str

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult: ...


def _parse_choice(payload: dict[str, Any]) -> ChatResult:
    choice = (payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    tool_calls: list[ToolCall] = []
    for raw_call in message.get("tool_calls") or []:
        function = raw_call.get("function") or {}
        raw_args = function.get("arguments")
        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args) if raw_args.strip() else {}
            except json.JSONDecodeError:
                arguments = {"__unparsed_arguments__": raw_args}
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            arguments = {}
        tool_calls.append(
            ToolCall(id=str(raw_call.get("id") or f"call_{len(tool_calls)}"), name=str(function.get("name") or ""), arguments=arguments)
        )
    usage = payload.get("usage") or {}
    return ChatResult(
        content=message.get("content"),
        tool_calls=tool_calls,
        finish_reason=str(choice.get("finish_reason") or "stop"),
        input_tokens=int(usage.get("prompt_tokens") or 0),
        output_tokens=int(usage.get("completion_tokens") or 0),
        raw=payload,
    )


class OpenAICompatibleClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        revision: str,
        temperature: float = 0.6,
        top_p: float = 0.95,
        max_output_tokens: int = 4096,
        seed: int | None = None,
        timeout: int = 120,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.model = model
        self.model_id = model
        self.revision = revision
        self.temperature = temperature
        self.top_p = top_p
        self.max_output_tokens = max_output_tokens
        self.seed = seed
        self.timeout = timeout
        self.max_retries = max_retries

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "max_tokens": self.max_output_tokens,
        }
        if self.seed is not None:
            body["seed"] = self.seed
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        data = json.dumps(body).encode()
        url = f"{self.base_url}/chat/completions"
        last_error = "no attempt"
        for attempt in range(self.max_retries):
            request = urllib.request.Request(
                url,
                data=data,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "authorization": f"Bearer {self._api_key}",
                    "accept": "application/json",
                    # A descriptive User-Agent is required: some providers front their API
                    # with a WAF that blocks the stdlib default (Cloudflare error 1010).
                    "user-agent": "cyberdetect/0.1",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = json.loads(response.read().decode())
                return _parse_choice(payload)
            except urllib.error.HTTPError as error:
                detail = error.read().decode(errors="replace")[:500]
                last_error = f"HTTP {error.code}: {detail}"
                # Retry only transient faults; fail fast on client errors like 400/401/403.
                if error.code not in {408, 409, 429, 500, 502, 503, 504}:
                    break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
                last_error = f"{type(error).__name__}: {error}"
            time.sleep(min(2**attempt, 8))
        raise ModelCallError(f"model call to {self.model} failed: {last_error}")


class MockChatClient:
    """Deterministic client driven by a scripted responder, for tests and dry runs.

    ``responder(messages, tools, step)`` returns a ChatResult. It never touches the
    network and requires no credentials.
    """

    def __init__(
        self,
        responder: Callable[[list[dict[str, Any]], list[dict[str, Any]] | None, int], ChatResult],
        *,
        model_id: str = "mock-model",
        revision: str = "mock",
    ):
        self._responder = responder
        self.model_id = model_id
        self.revision = revision
        self._step = 0

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        result = self._responder(messages, tools, self._step)
        self._step += 1
        return result


def tool_call_result(name: str, arguments: dict[str, Any], *, call_id: str | None = None, tokens: int = 20) -> ChatResult:
    return ChatResult(
        content=None,
        tool_calls=[ToolCall(id=call_id or f"call_{name}_{tokens}", name=name, arguments=arguments)],
        finish_reason="tool_calls",
        input_tokens=tokens,
        output_tokens=tokens,
    )
