import unittest
from pathlib import Path

import yaml


class LunaryComposeSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = Path("docker/phase1/compose.yaml")
        cls.compose = yaml.safe_load(cls.path.read_text(encoding="utf-8"))

    def test_network_is_internal_and_target_has_no_ports(self) -> None:
        self.assertTrue(self.compose["networks"]["isolated"]["internal"])
        self.assertNotIn("ports", self.compose["services"]["app"])
        self.assertNotIn("ports", self.compose["services"]["db"])
        self.assertEqual(self.compose["services"]["proxy"]["ports"], ["127.0.0.1::8081"])

    def test_only_proxy_joins_the_publishable_edge_network(self) -> None:
        # The vulnerable target must never sit on a port-publishable / egress-capable
        # network: app and db are internal-only, and only the proxy ingress joins `edge`.
        self.assertNotIn("internal", self.compose["networks"]["edge"])
        self.assertEqual(self.compose["services"]["app"]["networks"], ["isolated"])
        self.assertEqual(self.compose["services"]["db"]["networks"], ["isolated"])
        self.assertEqual(self.compose["services"]["proxy"]["networks"], ["isolated", "edge"])

    def test_hardening_and_no_host_control_mounts(self) -> None:
        text = self.path.read_text(encoding="utf-8").lower()
        self.assertNotIn("docker.sock", text)
        self.assertNotIn("network_mode: host", text)
        self.assertNotIn("privileged: true", text)
        for service in self.compose["services"].values():
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertIn("ALL", service["cap_drop"])
            self.assertIn("pids_limit", service)
            self.assertIn("mem_limit", service)


if __name__ == "__main__":
    unittest.main()
