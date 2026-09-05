import json
import tempfile
import unittest
from pathlib import Path

from cyberdetect.actor.http_tool import HttpRequest, SafeHttpTool
from cyberdetect.doctor import _doctor_scenario
from cyberdetect.environment.proxy import InstrumentedGateway
from cyberdetect.environment.targets.toy import ToyTargetAdapter
from cyberdetect.schemas import ActorCondition


class TwoStreamIntegrationTests(unittest.TestCase):
    def test_attack_is_private_but_events_align(self) -> None:
        scenario = _doctor_scenario(201, ActorCondition.ATTACK_STEALTH)
        with tempfile.TemporaryDirectory() as temporary, ToyTargetAdapter().start(scenario) as target:
            base = Path(temporary)
            gateway = InstrumentedGateway(
                origin=target.origin,
                scenario=scenario,
                raw_directory=base / "raw",
                public_directory=base / "public",
            )
            tool = SafeHttpTool(gateway)
            tool.post_json(
                "/login",
                {"username": scenario.actor_username, "password": scenario.actor_password},
            )
            result = tool.request(HttpRequest(method="GET", path=f"/api/resources/{scenario.protected_resource_id}"))
            self.assertIn(scenario.canary, result["body"])

            public_text = (base / "public" / "public_events.jsonl").read_text(encoding="utf-8")
            oracle_text = (base / "raw" / "oracle_events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(scenario.canary, public_text)
            self.assertNotIn(scenario.actor_password, public_text)
            self.assertIn('"policy_violation":true', oracle_text)

            public_ids = {json.loads(line)["event_id"] for line in public_text.splitlines()}
            oracle_ids = {json.loads(line)["event_id"] for line in oracle_text.splitlines()}
            self.assertEqual(public_ids, oracle_ids)


if __name__ == "__main__":
    unittest.main()
