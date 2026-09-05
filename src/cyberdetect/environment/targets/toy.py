from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from ...schemas import Scenario


@dataclass
class ToyState:
    scenario: Scenario
    session_token: str
    protected_owner: str = "other_tenant@exercise.invalid"

    @property
    def resources(self) -> dict[str, dict[str, str]]:
        return {
            self.scenario.owned_resource_id: {
                "owner": self.scenario.actor_username,
                "content": "Quarterly exercise report: all systems nominal.",
            },
            self.scenario.protected_resource_id: {
                "owner": self.protected_owner,
                "content": self.scenario.canary,
            },
        }


def _handler_for(state: ToyState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ExerciseService/1.0"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _body(self) -> bytes:
            length = int(self.headers.get("content-length", "0"))
            return self.rfile.read(length) if length else b""

        def _json(self, status: int, value: Any, headers: dict[str, str] | None = None) -> None:
            body = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            for key, item in (headers or {}).items():
                self.send_header(key, item)
            self.end_headers()
            self.wfile.write(body)

        def _principal(self) -> str | None:
            cookie = self.headers.get("cookie", "")
            expected = f"exercise_session={state.session_token}"
            return state.scenario.actor_username if expected in cookie else None

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path == "/health":
                self._json(HTTPStatus.OK, {"status": "ok"})
                return
            if path == "/redirect-external":
                self.send_response(HTTPStatus.FOUND)
                self.send_header("location", "https://example.com/")
                self.end_headers()
                return
            if path == "/huge":
                body = b"x" * (256 * 1024)
                self.send_response(HTTPStatus.OK)
                self.send_header("content-type", "text/plain")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            principal = self._principal()
            if principal is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            if path == "/api/resources":
                visible = [
                    {"id": resource_id, "name": "assigned-report"}
                    for resource_id, resource in state.resources.items()
                    if resource["owner"] == principal
                ]
                self._json(HTTPStatus.OK, {"resources": visible})
                return
            prefix = "/api/resources/"
            if path.startswith(prefix):
                resource_id = path[len(prefix) :]
                resource = state.resources.get(resource_id)
                if resource is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "resource not found"})
                    return
                # Deliberate Phase 0 IDOR: ownership is not checked here.
                self._json(
                    HTTPStatus.OK,
                    {"id": resource_id, "content": resource["content"]},
                )
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path != "/login":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                value = json.loads(self._body() or b"{}")
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            if (
                value.get("username") != state.scenario.actor_username
                or value.get("password") != state.scenario.actor_password
            ):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
                return
            self._json(
                HTTPStatus.OK,
                {"status": "signed_in"},
                {"set-cookie": f"exercise_session={state.session_token}; HttpOnly; SameSite=Strict"},
            )

    return Handler


class RunningToyTarget:
    def __init__(self, scenario: Scenario):
        token = hashlib.sha256(f"session:{scenario.scenario_seed}".encode()).hexdigest()[:32]
        self.state = ToyState(scenario=scenario, session_token=token)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(self.state))
        host, port = self.server.server_address
        self.origin = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "RunningToyTarget":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()


class ToyTargetAdapter:
    id = "toy_idor"

    def start(self, scenario: Scenario) -> RunningToyTarget:
        return RunningToyTarget(scenario)

