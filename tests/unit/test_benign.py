import unittest
from cyberdetect.environment.benign import plan_corpus, NORMAL_TEMPLATES, HARD_NEGATIVE_TEMPLATES


class BenignPlanTests(unittest.TestCase):
    def test_hard_negative_fraction_is_respected(self) -> None:
        plan = plan_corpus(2000, 0.4, seed=1)
        hard = sum(1 for _, h in plan if h)
        self.assertAlmostEqual(hard / len(plan), 0.4, delta=0.05)

    def test_deterministic(self) -> None:
        self.assertEqual(plan_corpus(50, 0.3, 7), plan_corpus(50, 0.3, 7))

    def test_all_names_known(self) -> None:
        names = {n for n, _ in NORMAL_TEMPLATES} | {n for n, _ in HARD_NEGATIVE_TEMPLATES}
        self.assertTrue({n for n, _ in plan_corpus(200, 0.4, 3)} <= names)


if __name__ == "__main__":
    unittest.main()
