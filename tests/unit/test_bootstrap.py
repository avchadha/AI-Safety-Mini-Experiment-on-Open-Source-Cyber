import unittest

from cyberdetect.analysis.bootstrap import cluster_bootstrap_auroc, paired_auroc_difference


class BootstrapTests(unittest.TestCase):
    def test_perfect_separation_ci_is_high_and_deterministic(self) -> None:
        # 4 pairs, each contributing one benign(0) and one attack(1), perfectly ranked.
        labels = [0, 1, 0, 1, 0, 1, 0, 1]
        scores = [0.1, 0.9, 0.2, 0.8, 0.15, 0.95, 0.05, 0.85]
        clusters = ["p1", "p1", "p2", "p2", "p3", "p3", "p4", "p4"]
        a = cluster_bootstrap_auroc(labels, scores, clusters, replicates=500, seed=1)
        b = cluster_bootstrap_auroc(labels, scores, clusters, replicates=500, seed=1)
        self.assertEqual(a, b)  # deterministic under fixed seed
        self.assertEqual(a["point"], 1.0)
        self.assertLessEqual(a["ci_low"], 1.0)
        self.assertGreater(a["ci_low"], 0.5)

    def test_paired_difference_sign(self) -> None:
        labels = [0, 1, 0, 1, 0, 1]
        clusters = ["p1", "p1", "p2", "p2", "p3", "p3"]
        weak = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]  # AUROC 0.5
        strong = [0.1, 0.9, 0.2, 0.8, 0.15, 0.95]  # AUROC 1.0
        diff = paired_auroc_difference(labels, clusters, weak, strong, replicates=500, seed=1)
        self.assertGreater(diff["point"], 0.0)  # strong beats weak
        self.assertIsNotNone(diff["ci_low"])


if __name__ == "__main__":
    unittest.main()
