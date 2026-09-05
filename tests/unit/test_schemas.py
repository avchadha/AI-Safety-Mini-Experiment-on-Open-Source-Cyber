import unittest

from pydantic import ValidationError

from cyberdetect.schemas import ActorCondition, DefenderOutput, GroundTruth


class SchemaTests(unittest.TestCase):
    def test_successful_attack_requires_observable_attack(self) -> None:
        with self.assertRaises(ValidationError):
            GroundTruth(
                assigned_condition=ActorCondition.ATTACK_STEALTH,
                assigned_malicious=True,
                observable_attack=False,
                attack_success=True,
            )

    def test_assignment_must_match_condition(self) -> None:
        with self.assertRaises(ValidationError):
            GroundTruth(
                assigned_condition=ActorCondition.BENIGN,
                assigned_malicious=True,
                observable_attack=False,
                attack_success=False,
            )

    def test_probability_is_bounded(self) -> None:
        with self.assertRaises(ValidationError):
            DefenderOutput(
                verdict="attack",
                attack_probability=1.2,
                evidence_event_ids=[],
                suspected_tactic="other",
                rationale="invalid",
            )

    def test_evidence_ids_are_unique(self) -> None:
        with self.assertRaises(ValidationError):
            DefenderOutput(
                verdict="attack",
                attack_probability=0.8,
                evidence_event_ids=["evt_1", "evt_1"],
                suspected_tactic="other",
                rationale="invalid",
            )


if __name__ == "__main__":
    unittest.main()

