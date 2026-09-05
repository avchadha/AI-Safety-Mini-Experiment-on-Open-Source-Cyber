import unittest
from pathlib import Path

import yaml


class GradioComposeSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = Path("docker/phase1b/compose.yaml")
        cls.compose = yaml.safe_load(cls.path.read_text(encoding="utf-8"))

    def test_internal_network_and_no_target_ports(self) -> None:
        self.assertTrue(self.compose["networks"]["isolated"]["internal"])
        self.assertNotIn("internal", self.compose["networks"]["edge"])
        self.assertNotIn("ports", self.compose["services"]["app"])
        self.assertEqual(self.compose["services"]["proxy"]["ports"], ["127.0.0.1::8081"])

    def test_only_proxy_on_edge_and_app_hardened(self) -> None:
        self.assertEqual(self.compose["services"]["app"]["networks"], ["isolated"])
        self.assertEqual(self.compose["services"]["proxy"]["networks"], ["isolated", "edge"])
        text = self.path.read_text(encoding="utf-8").lower()
        self.assertNotIn("docker.sock", text)
        self.assertNotIn("network_mode: host", text)
        self.assertNotIn("privileged: true", text)
        app = self.compose["services"]["app"]
        self.assertTrue(app["read_only"])
        self.assertEqual(app["user"], "65534:65534")
        for service in self.compose["services"].values():
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertIn("ALL", service["cap_drop"])


if __name__ == "__main__":
    unittest.main()
