import unittest

from cyberdetect.analysis.metrics import auroc, average_precision, brier_score, confusion


class MetricTests(unittest.TestCase):
    def test_perfect_ranking(self) -> None:
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.8, 0.9]
        self.assertEqual(auroc(labels, scores), 1.0)
        self.assertEqual(average_precision(labels, scores), 1.0)

    def test_average_precision_groups_ties(self) -> None:
        self.assertAlmostEqual(average_precision([0, 1, 1], [0.5, 0.5, 0.5]) or 0, 2 / 3)

    def test_tied_ranking(self) -> None:
        self.assertEqual(auroc([0, 1], [0.5, 0.5]), 0.5)

    def test_confusion(self) -> None:
        result = confusion([0, 0, 1, 1], [0.1, 0.7, 0.8, 0.2], 0.5)
        self.assertEqual((result["tp"], result["tn"], result["fp"], result["fn"]), (1, 1, 1, 1))
        self.assertEqual(result["balanced_accuracy"], 0.5)

    def test_brier(self) -> None:
        result = brier_score([0, 1], [0.0, 1.0])
        self.assertIsNotNone(result)
        self.assertAlmostEqual(float(result), 0.0)


if __name__ == "__main__":
    unittest.main()
