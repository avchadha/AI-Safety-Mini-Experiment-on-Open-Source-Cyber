"""Leakage tests for the Phase 1 telemetry proxy's public-stream construction.

The proxy in ``docker/phase1/proxy_server.py`` is the only component that turns raw
target traffic into the defender-visible ``access_v1`` stream. These tests exercise its
leakage-critical pure functions directly, without Docker, to guarantee that raw
identifiers, credentials, and oracle annotations never reach the public stream.
"""

from __future__ import annotations

import importlib.util
import secrets
import unittest
from pathlib import Path

_PROXY_PATH = Path(__file__).resolve().parents[2] / "docker" / "phase1" / "proxy_server.py"
_spec = importlib.util.spec_from_file_location("phase1_proxy_server", _PROXY_PATH)
assert _spec and _spec.loader
proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proxy)


def _seed() -> dict[str, str]:
    return {
        "pseudonym_key_hex": secrets.token_hex(32),
        "actor_email": "actor-secret@exercise.invalid",
        "owned_project_id": "raw-owned-0001",
        "protected_project_id": "raw-protected-9999",
        "protected_owner_email": "owner-secret@exercise.invalid",
        "canary": "flag{do-not-leak}",
    }


class ProxyPublicStreamLeakageTests(unittest.TestCase):
    def test_pseudonym_is_namespaced_deterministic_and_hides_raw_value(self) -> None:
        seed = _seed()
        first = proxy.pseudonym(seed, "usr", seed["actor_email"])
        second = proxy.pseudonym(seed, "usr", seed["actor_email"])
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("usr_"))
        self.assertNotIn(seed["actor_email"], first)
        # A different namespace or key must not reproduce the same token.
        self.assertNotEqual(first, proxy.pseudonym(seed, "sess", seed["actor_email"]))
        self.assertNotEqual(first, proxy.pseudonym(_seed(), "usr", seed["actor_email"]))

    def test_pseudonym_passes_through_none(self) -> None:
        self.assertIsNone(proxy.pseudonym(_seed(), "usr", None))

    def test_public_path_pseudonymizes_both_project_ids(self) -> None:
        seed = _seed()
        for raw_id in (seed["owned_project_id"], seed["protected_project_id"]):
            rendered = proxy.public_path(seed, f"/v1/projects/{raw_id}")
            self.assertNotIn(raw_id, rendered)
            self.assertTrue(rendered.startswith("/v1/projects/prj_"))
        # Equality relationships within an episode are preserved.
        owned = proxy.public_path(seed, f"/v1/projects/{seed['owned_project_id']}")
        self.assertEqual(owned, proxy.public_path(seed, f"/v1/projects/{seed['owned_project_id']}"))
        self.assertNotEqual(
            owned, proxy.public_path(seed, f"/v1/projects/{seed['protected_project_id']}")
        )

    def test_public_path_leaves_non_resource_segments_untouched(self) -> None:
        self.assertEqual(proxy.public_path(_seed(), "/v1/projects"), "/v1/projects")
        self.assertEqual(proxy.public_path(_seed(), "/auth/login"), "/auth/login")

    def test_allowlists_exclude_credential_bearing_headers(self) -> None:
        for forbidden in ("authorization", "cookie", "set-cookie", "x-forwarded-for"):
            self.assertNotIn(forbidden, proxy.ALLOWED_REQUEST_HEADERS)
            self.assertNotIn(forbidden, proxy.ALLOWED_RESPONSE_HEADERS)

    def test_public_and_oracle_streams_are_physically_separate(self) -> None:
        self.assertNotEqual(proxy.PUBLIC_PATH, proxy.ORACLE_PATH)
        self.assertNotEqual(proxy.PUBLIC_PATH.parent, proxy.ORACLE_PATH.parent)
        # The raw request/response digest stream stays on the protected side.
        self.assertEqual(proxy.RAW_PATH.parent, proxy.ORACLE_PATH.parent)


if __name__ == "__main__":
    unittest.main()
