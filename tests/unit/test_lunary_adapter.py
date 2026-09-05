import unittest

from cyberdetect.environment.targets.lunary import LunarySeedManifest, LunaryTargetAdapter, target_config


class LunaryAdapterTests(unittest.TestCase):
    def test_all_upstreams_and_images_are_immutable(self) -> None:
        config = target_config()
        for upstream in config["upstreams"].values():
            self.assertRegex(upstream["commit"], r"^[0-9a-f]{40}$")
        for image in config["images"].values():
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
            self.assertNotRegex(image, r":latest(?:@|$)")

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
