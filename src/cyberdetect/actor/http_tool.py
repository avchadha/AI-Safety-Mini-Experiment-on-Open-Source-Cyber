from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class HttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None
    form_body: dict[str, str] | None = None
    follow_redirects: bool = False

    @model_validator(mode="after")
    def safe_shape(self) -> "HttpRequest":
        parsed = urlsplit(self.path)
        if not self.path.startswith("/") or self.path.startswith("//"):
            raise ValueError("path must be a single-origin absolute path beginning with /")
        if parsed.scheme or parsed.netloc:
            raise ValueError("absolute URLs and network-path references are forbidden")
        if any(ord(character) < 32 for character in self.path):
            raise ValueError("control characters are forbidden in paths")
        if self.path.startswith("/_cyberdetect/"):
            raise ValueError("orchestrator-only target endpoints are forbidden")
        if self.json_body is not None and self.form_body is not None:
            raise ValueError("json_body and form_body are mutually exclusive")
        unsafe = {"host", "authorization", "cookie", "x-forwarded-for", "forwarded"}
        supplied = {key.lower() for key in self.headers}
        forbidden = sorted(unsafe & supplied)
        if forbidden:
            raise ValueError(f"unsafe headers are forbidden: {', '.join(forbidden)}")
        return self


class SafeHttpTool:
    def __init__(self, gateway: Any):
        self.gateway = gateway

    def request(self, request: HttpRequest | dict[str, Any]) -> dict[str, Any]:
        parsed = request if isinstance(request, HttpRequest) else HttpRequest.model_validate(request)
        response = self.gateway.request(parsed)
        return {
            "event_id": response.event_id,
            "status": response.status,
            "headers": response.public_headers,
            "body": response.body.decode("utf-8", errors="replace"),
        }

    def post_json(self, path: str, value: dict[str, Any]) -> dict[str, Any]:
        return self.request(
            HttpRequest(
                method="POST",
                path=path,
                headers={"content-type": "application/json"},
                json_body=value,
            )
        )
