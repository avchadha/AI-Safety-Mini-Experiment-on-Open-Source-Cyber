import unittest

from cyberdetect.actor.http_tool import HttpRequest
from cyberdetect.environment.targets.lunary import (
    ContainerGatewayClient,
    LunarySeedManifest,
    LunaryTargetAdapter,
    target_config,
)


class _FakeResponse:
    status = 200

    class _Headers:
        def items(self):
            return [("content-type", "application/json")]

    headers = _Headers()

    def read(self, _n):
        return b"[]"


class LunaryAdapterTests(unittest.TestCase):
    def test_all_upstreams_and_images_are_immutable(self) -> None:
        config = target_config()
        for upstream in config["upstreams"].values():
            self.assertRegex(upstream["commit"], r"^[0-9a-f]{40}$")
        for image in config["images"].values():
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
            self.assertNotRegex(image, r":latest(?:@|$)")

    def test_gateway_infers_json_content_type_for_bodies(self) -> None:
        client = ContainerGatewayClient("http://127.0.0.1:1")
        captured: dict = {}

        def fake_open(request, timeout=30):
            captured["headers"] = {k.lower(): v for k, v in request.headers.items()}
            return _FakeResponse()

        client.opener.open = fake_open  # type: ignore[assignment]
        client.request(HttpRequest(method="POST", path="/auth/login", json_body={"email": "a", "password": "b"}))
        self.assertEqual(captured["headers"].get("content-type"), "application/json")
        # The actor's own gateway identity headers are attached; auth is never actor-set.
        self.assertIn("x-experiment-session", captured["headers"])
        self.assertNotIn("authorization", captured["headers"])

    def test_public_runbook_contains_only_sanitized_mapping(self) -> None:
        seed = LunarySeedManifest(
            actor_email="actor-secret@example.invalid",
            actor_password="secret-password",
            protected_owner_email="owner-secret@example.invalid",
            protected_owner_password="owner-password",
            owned_project_id="private-owned-id",
            protected_project_id="private-protected-id",
            canary="flag{private}",
            public_principal_id="usr_abc",
            public_owned_project_id="prj_def",
        )
        runbook = LunaryTargetAdapter().public_runbook(seed)
        self.assertIn("usr_abc -> prj_def", runbook)
        for private in (seed.actor_email, seed.actor_password, seed.protected_owner_email, seed.protected_project_id, seed.canary):
            self.assertNotIn(private, runbook)


if __name__ == "__main__":
    unittest.main()
