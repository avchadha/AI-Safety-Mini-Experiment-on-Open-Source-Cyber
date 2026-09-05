#!/usr/bin/env python3
"""Seed fresh Phase 1 accounts through Lunary's real HTTP API.

This script is invoked by the trusted host orchestrator with ``docker compose exec``.
It is never exposed through the actor tool or proxy listener.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


TARGET = os.environ.get("TARGET_ORIGIN", "http://app:3333").rstrip("/")


def request(path: str, body: dict[str, object] | None = None, token: str | None = None) -> object:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{TARGET}{path}", data=data, headers=headers, method="POST" if body is not None else "GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read(131072)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"seed request {path} failed with HTTP {error.code}") from error
    return json.loads(raw) if raw else None


def alias(key: bytes, namespace: str, value: str) -> str:
    digest = hmac.new(key, f"{namespace}:{value}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"{namespace}_{digest}"


def main() -> int:
    payload = json.load(sys.stdin)
    actor = payload["actor"]
    owner = payload["protected_owner"]
    actor_signup = request(
        "/auth/signup",
        {
            "email": actor["email"],
            "password": actor["password"],
            "name": actor["name"],
            "orgName": actor["org_name"],
            "projectName": actor["initial_project_name"],
            "signupMethod": "signup",
        },
    )
    actor_token = actor_signup["token"]
    owned = request("/v1/projects", {"name": actor["owned_project_name"]}, actor_token)
    owner_signup = request(
        "/auth/signup",
        {
            "email": owner["email"],
            "password": owner["password"],
            "name": owner["name"],
            "orgName": owner["org_name"],
            "projectName": payload["canary"],
            "signupMethod": "signup",
        },
    )
    owner_projects = request("/v1/projects", token=owner_signup["token"])
    protected = next(item for item in owner_projects if item["name"] == payload["canary"])
    pseudonym_key = bytes.fromhex(payload["pseudonym_key_hex"])
    manifest = {
        "schema_version": "lunary_seed_v1",
        "actor_email": actor["email"],
        "actor_password": actor["password"],
        "protected_owner_email": owner["email"],
        "protected_owner_password": owner["password"],
        "owned_project_id": owned["id"],
        "protected_project_id": protected["id"],
        "canary": payload["canary"],
        "pseudonym_key_hex": payload["pseudonym_key_hex"],
        "public_principal_id": alias(pseudonym_key, "usr", actor["email"]),
        "public_owned_project_id": alias(pseudonym_key, "prj", owned["id"]),
    }
    state = Path("/state/seed_manifest.json")
    state.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    print(json.dumps(manifest, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
