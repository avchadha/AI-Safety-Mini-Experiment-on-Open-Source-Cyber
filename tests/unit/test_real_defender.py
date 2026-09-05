import json
import tempfile
import unittest
from pathlib import Path

import yaml

from cyberdetect.actor.model_client import ChatResult, MockChatClient
from cyberdetect.defender.real_runner import DEFENDER_SYSTEM, run_real_defenders


ROOT = Path(__file__).resolve().parents[2]


def _public_event(seq: int, event_id: str, status: int) -> dict:
    return {
        "schema_version": "access_v1",
        "event_id": event_id,
        "sequence": seq,
        "t_rel_ms": seq * 10,
        "source": "gateway",
        "session_id": "sess_x",
        "principal_id": "usr_x",
        "method": "DELETE",
        "path": "/v1/projects/prj_y",
        "query_keys": [],
        "request_bytes": 0,
        "status": status,
        "response_bytes": 10,
        "duration_ms": 5,
        "redirected": False,
    }


class RealDefenderTests(unittest.TestCase):
    def test_valid_json_verdict_is_recorded_without_parse_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            episode = data / "episodes" / "ep_test000000000000"
            episode.mkdir(parents=True)
            events = [_public_event(1, "evt_a", 200), _public_event(2, "evt_b", 200)]
            (episode / "public_events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8"
            )
            (episode / "manifest.json").write_text(json.dumps({"experiment_id": "def-test"}), encoding="utf-8")
            (episode / "defender_packet.txt").write_text("RUNBOOK ...\nEVENTS ...\n", encoding="utf-8")

            config = {
                "experiment": {"id": "def-test", "master_seed": 1, "data_root": str(data)},
                "targets": ["lunary_idor"],
                "actor_conditions": ["benign"],
                "actor_model": "best_open_attacker",
                "defender_models": ["small_open"],
                "log_view": "access_v1",
                "analysis": {"primary_label": "observable_attack", "fpr_target": 0.1, "bootstrap_replicates": 10},
                "prompts": {
                    "actor_system": "prompts/actor_system.txt",
                    "benign": "prompts/benign.txt",
                    "attack_standard": "prompts/attack_standard.txt",
                    "attack_stealth_appendix": "prompts/attack_stealth_appendix.txt",
                    "defender": "prompts/defender.txt",
                },
            }
            config_path = data / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

            captured: dict = {}

            def responder(messages, tools, step):
                captured["messages"] = messages
                verdict = {
                    "verdict": "attack",
                    "attack_probability": 0.9,
                    "first_suspicious_event_id": "evt_a",
                    "evidence_event_ids": ["evt_a", "evt_b"],
                    "suspected_tactic": "authorization_abuse",
                    "rationale": "Cross-tenant delete observed.",
                }
                return ChatResult(content=json.dumps(verdict), tool_calls=[], finish_reason="stop", input_tokens=100, output_tokens=40)

            def factory(defender_id: str):
                return MockChatClient(responder, model_id="mock-defender")

            created = run_real_defenders(config_path, client_factory=factory)
            self.assertEqual(len(created), 1)
            record = json.loads(created[0].read_text(encoding="utf-8"))
            self.assertFalse(record["parse_failure"])
            self.assertEqual(record["parsed_output"]["verdict"], "attack")
            self.assertEqual(record["defender_id"], "small_open")
            self.assertEqual(record["input_tokens"], 100)
            # The defender received the schema instruction as a system message + the packet.
            self.assertEqual(captured["messages"][0]["role"], "system")
            self.assertEqual(captured["messages"][0]["content"], DEFENDER_SYSTEM)
            self.assertIn("RUNBOOK", captured["messages"][1]["content"])

    def test_unparseable_output_records_parse_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            episode = data / "episodes" / "ep_test111111111111"
            episode.mkdir(parents=True)
            (episode / "public_events.jsonl").write_text(json.dumps(_public_event(1, "evt_a", 200)) + "\n", encoding="utf-8")
            (episode / "manifest.json").write_text(json.dumps({"experiment_id": "def-test"}), encoding="utf-8")
            (episode / "defender_packet.txt").write_text("packet", encoding="utf-8")
            config = {
                "experiment": {"id": "def-test", "master_seed": 1, "data_root": str(data)},
                "targets": ["lunary_idor"],
                "actor_conditions": ["benign"],
                "actor_model": "best_open_attacker",
                "defender_models": ["small_open"],
                "log_view": "access_v1",
                "analysis": {"primary_label": "observable_attack", "fpr_target": 0.1, "bootstrap_replicates": 10},
                "prompts": {
                    "actor_system": "prompts/actor_system.txt",
                    "benign": "prompts/benign.txt",
                    "attack_standard": "prompts/attack_standard.txt",
                    "attack_stealth_appendix": "prompts/attack_stealth_appendix.txt",
                    "defender": "prompts/defender.txt",
                },
            }
            config_path = data / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

            def factory(defender_id: str):
                return MockChatClient(lambda m, t, s: ChatResult(content="not json at all", tool_calls=[], finish_reason="stop", input_tokens=10, output_tokens=3))

            created = run_real_defenders(config_path, client_factory=factory)
            record = json.loads(created[0].read_text(encoding="utf-8"))
            self.assertTrue(record["parse_failure"])
            self.assertEqual(record["parsed_output"]["attack_probability"], 0.5)


if __name__ == "__main__":
    unittest.main()
