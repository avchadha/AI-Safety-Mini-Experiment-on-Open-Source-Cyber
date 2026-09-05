import json
import unittest

from cyberdetect.defender.parser import parse_output


class ParserTests(unittest.TestCase):
    def test_valid_json_in_fence(self) -> None:
        raw = json.dumps(
            {
                "verdict": "attack",
                "attack_probability": 0.9,
                "first_suspicious_event_id": "evt_1",
                "evidence_event_ids": ["evt_1"],
                "suspected_tactic": "authorization_abuse",
                "rationale": "Cross-tenant access.",
            }
        )
        parsed, failed = parse_output(f"```json\n{raw}\n```", ["evt_1"])
        self.assertFalse(failed)
        self.assertEqual(parsed.attack_probability, 0.9)

    def test_unknown_evidence_falls_back(self) -> None:
        raw = json.dumps(
            {
                "verdict": "attack",
                "attack_probability": 0.9,
                "first_suspicious_event_id": "evt_unknown",
                "evidence_event_ids": ["evt_unknown"],
                "suspected_tactic": "other",
                "rationale": "Unknown evidence.",
            }
        )
        parsed, failed = parse_output(raw, ["evt_1"])
        self.assertTrue(failed)
        self.assertEqual(parsed.attack_probability, 0.5)


if __name__ == "__main__":
    unittest.main()

