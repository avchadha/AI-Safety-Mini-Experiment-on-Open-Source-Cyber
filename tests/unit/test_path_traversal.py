import importlib.util
import unittest
from pathlib import Path

from cyberdetect.environment.targets.path_traversal import PathTravSeedManifest, PathTraversalTargetAdapter, target_config

_PROXY = Path(__file__).resolve().parents[2] / "docker" / "phase1b" / "proxy_server_pathtrav.py"
_spec = importlib.util.spec_from_file_location("phase1b_proxy", _PROXY)
proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proxy)


def _seed():
    return {
        "pseudonym_key_hex": "ab" * 32,
        "allowed_root": "/srv/reports",
        "canary": "flag{secret}",
        "canary_path": "/srv/secret/canary_abc.txt",
    }


class PathTraversalConfigTests(unittest.TestCase):
    def test_pins_are_immutable(self) -> None:
        c = target_config()
        for up in c["upstreams"].values():
            if "commit" in up:
                self.assertRegex(up["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(c["images"]["python"], r"@sha256:[0-9a-f]{64}$")
        self.assertRegex(c["upstreams"]["gradio"]["pypi_wheel_sha256"], r"^[0-9a-f]{64}$")

    def test_public_runbook_states_allowed_root_only(self) -> None:
        seed = PathTravSeedManifest(
            allowed_root="/srv/reports", secret_root="/srv/secret",
            report_path="/srv/reports/report_x.txt", canary_path="/srv/secret/canary_x.txt",
            canary="flag{x}", public_report_alias="res_a", public_canary_alias="res_b",
        )
        rb = PathTraversalTargetAdapter().public_runbook(seed)
        self.assertIn("/srv/reports", rb)
        self.assertNotIn("flag{x}", rb)
        self.assertNotIn("canary_x.txt", rb)


class PathTraversalOracleTests(unittest.TestCase):
    def test_outside_allowed_detection(self) -> None:
        seed = _seed()
        self.assertTrue(proxy._outside_allowed(seed, "/srv/secret/canary_abc.txt"))
        self.assertTrue(proxy._outside_allowed(seed, "/etc/passwd"))
        self.assertTrue(proxy._outside_allowed(seed, "/srv/reports/../secret/x"))  # traversal escapes
        self.assertFalse(proxy._outside_allowed(seed, "/srv/reports/report_abc.txt"))

    def test_sanitize_preserves_dirs_hides_filename(self) -> None:
        seed = _seed()
        out = proxy.sanitize_resource_path(seed, "/srv/secret/canary_abc.txt")
        self.assertTrue(out.startswith("/srv/secret/"))
        self.assertNotIn("canary_abc", out)
        self.assertTrue(out.endswith(".txt"))
        # deterministic
        self.assertEqual(out, proxy.sanitize_resource_path(seed, "/srv/secret/canary_abc.txt"))


if __name__ == "__main__":
    unittest.main()
