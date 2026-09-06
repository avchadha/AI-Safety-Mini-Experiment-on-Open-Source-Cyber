import unittest

from cyberdetect.analysis.baserate import (
    alerts_per_n,
    cost_ledger,
    precision_at_prevalence,
    prevalence_sweep,
    rate_at_threshold,
    transfer_fraction,
)


class BaseRateTests(unittest.TestCase):
    def test_rate_at_threshold(self) -> None:
        self.assertEqual(rate_at_threshold([0.1, 0.6, 0.9], 0.5), 2 / 3)
        self.assertIsNone(rate_at_threshold([], 0.5))

    def test_precision_falls_as_prevalence_drops(self) -> None:
        # good detector: recall 0.9, fpr 0.02
        p_balanced = precision_at_prevalence(0.9, 0.02, 0.5)
        p_rare = precision_at_prevalence(0.9, 0.02, 1 / 1000)
        self.assertGreater(p_balanced, 0.9)
        self.assertLess(p_rare, p_balanced)  # base-rate collapse
        # exact value at 1:1000: 0.9*0.001 / (0.9*0.001 + 0.02*0.999)
        self.assertAlmostEqual(p_rare, 0.0009 / (0.0009 + 0.019980), places=6)

    def test_precision_none_when_no_alerts(self) -> None:
        self.assertIsNone(precision_at_prevalence(0.0, 0.0, 0.5))

    def test_alerts_dominated_by_false_at_low_prevalence(self) -> None:
        counts = alerts_per_n(0.9, 0.02, 1 / 1000, n=100_000)
        self.assertGreater(counts["false"], counts["true"])

    def test_prevalence_sweep_shape(self) -> None:
        rows = prevalence_sweep(0.8, 0.05)
        self.assertEqual([r["prevalence"] for r in rows], [1 / 50, 1 / 100, 1 / 1000, 1 / 10000])
        self.assertTrue(all(r["precision"] is not None for r in rows))

    def test_transfer_fraction(self) -> None:
        # attacker halved its own proxy prob (0.9 -> 0.4); eval detector barely moved (0.9 -> 0.85)
        tau = transfer_fraction(0.9, 0.4, 0.9, 0.85)
        self.assertAlmostEqual(tau, 0.05 / 0.5)  # ~0.1 -> idiosyncratic
        # full transfer
        self.assertAlmostEqual(transfer_fraction(0.9, 0.4, 0.9, 0.4), 1.0)
        # unstable: proxy barely moved -> undefined
        self.assertIsNone(transfer_fraction(0.9, 0.88, 0.9, 0.5))

    def test_cost_ledger(self) -> None:
        led = cost_ledger(
            attack_input_tokens=1_000_000, attack_output_tokens=100_000,
            input_price_per_m=3.0, output_price_per_m=15.0,
            successful_attacks=10, screened_sessions=1000,
            screen_input_tokens=1_000_000, screen_output_tokens=100_000,
            screen_input_price_per_m=0.17, screen_output_price_per_m=0.25,
        )
        self.assertAlmostEqual(led["offense_usd_total"], 3.0 + 1.5)
        self.assertAlmostEqual(led["offense_usd_per_successful_attack"], 4.5 / 10)
        self.assertAlmostEqual(led["defense_usd_per_screened_session"], (0.17 + 0.025) / 1000, places=6)


if __name__ == "__main__":
    unittest.main()
