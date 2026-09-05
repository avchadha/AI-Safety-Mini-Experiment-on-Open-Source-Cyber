from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class EpisodeRedactor:
    key: bytes

    def pseudonym(self, namespace: str, value: str | None) -> str | None:
        if value is None:
            return None
        digest = hmac.new(self.key, f"{namespace}:{value}".encode(), hashlib.sha256).hexdigest()
        prefix = {"user": "usr", "resource": "res", "session": "sess"}.get(namespace, "id")
        return f"{prefix}_{digest[:12]}"

    def path(self, path: str, resource_ids: list[str]) -> str:
        result = path
        for resource_id in sorted(resource_ids, key=len, reverse=True):
            replacement = self.pseudonym("resource", resource_id)
            result = result.replace(resource_id, str(replacement))
        return result

