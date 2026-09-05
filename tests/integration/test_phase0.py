import json
import tempfile
import unittest
from pathlib import Path

from cyberdetect.actor.runner import run_mock_actors
from cyberdetect.analysis.report import analyze
from cyberdetect.baselines.rules import run_baselines
from cyberdetect.defender.runner import run_mock_defenders
from cyberdetect.freeze import create_lock
from cyberdetect.scenarios import generate_scenarios
from cyberdetect.telemetry.leakage import audit_packets


class PhaseZeroTests(unittest.TestCase):
    config = "configs/pilot.yaml"

    def test_complete_mock_pipeline(self) -> None:
        generate_scenarios(self.config)
        with tempfile.TemporaryDirectory(prefix="phase0-lock-") as temporary:
            lock = create_lock(self.config, Path(temporary) / "experiment.lock.json")
            self.assertTrue(lock.exists())
        episodes = run_mock_actors(self.config)
        self.assertEqual(len(episodes), 3)
        self.assertEqual(audit_packets(self.config), [])
        self.assertEqual(len(run_mock_defenders(self.config)), 9)
        self.assertEqual(len(run_baselines(self.config)), 9)
        metrics_path, report_path = analyze(self.config)
        self.assertTrue(metrics_path.exists())
        self.assertTrue(report_path.exists())
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        self.assertEqual(metrics["episodes_total"], 3)
        self.assertIn("small_mock", metrics["defenders"])


if __name__ == "__main__":
    unittest.main()
