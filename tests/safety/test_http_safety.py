import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from cyberdetect.actor.http_tool import HttpRequest, SafeHttpTool
from cyberdetect.doctor import _doctor_scenario
from cyberdetect.environment.proxy import GatewaySafetyError, InstrumentedGateway
from cyberdetect.environment.targets.toy import ToyTargetAdapter
from cyberdetect.schemas import ActorCondition


class HttpSafetyTests(unittest.TestCase):
    def test_rejects_absolute_and_network_path_urls(self) -> None:
        for unsafe in ("https://example.com/", "//example.com/path", "ftp://127.0.0.1/file"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValidationError):
                HttpRequest(method="GET", path=unsafe)

    def test_rejects_sensitive_headers(self) -> None:
        for header in ("Host", "Authorization", "Cookie", "X-Forwarded-For"):
            with self.subTest(header=header), self.assertRaises(ValidationError):
                HttpRequest(method="GET", path="/health", headers={header: "unsafe"})

    def test_external_redirect_is_blocked(self) -> None:
        scenario = _doctor_scenario(100, ActorCondition.ATTACK_STANDARD)
        with tempfile.TemporaryDirectory() as temporary, ToyTargetAdapter().start(scenario) as target:
            gateway = InstrumentedGateway(
                origin=target.origin,
                scenario=scenario,
                raw_directory=Path(temporary) / "raw",
                public_directory=Path(temporary) / "public",
            )
            with self.assertRaises(GatewaySafetyError):
                SafeHttpTool(gateway).request(HttpRequest(method="GET", path="/redirect-external"))

    def test_oversized_response_is_blocked(self) -> None:
        scenario = _doctor_scenario(101, ActorCondition.BENIGN)
        with tempfile.TemporaryDirectory() as temporary, ToyTargetAdapter().start(scenario) as target:
            gateway = InstrumentedGateway(
                origin=target.origin,
                scenario=scenario,
                raw_directory=Path(temporary) / "raw",
                public_directory=Path(temporary) / "public",
                max_response_bytes=1024,
            )
            with self.assertRaises(GatewaySafetyError):
                SafeHttpTool(gateway).request(HttpRequest(method="GET", path="/huge"))

    def test_rejects_orchestrator_only_paths(self) -> None:
        with self.assertRaises(ValidationError):
            HttpRequest(method="GET", path="/_cyberdetect/health")


if __name__ == "__main__":
    unittest.main()
