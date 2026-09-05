import json
import tempfile
import unittest
from pathlib import Path

import yaml

from cyberdetect.analysis.report import analyze


def _write_episode(data: Path, exp: str, target: str, split: str, pair: str, condition: str, observable: int, success: int):
    eid = f"ep_{target[:3]}_{split[:3]}_{pair}_{condition}"
    ed = data / "episodes" / eid
    ed.mkdir(parents=True, exist_ok=True)
    (ed / "manifest.json").write_text(json.dumps({
        "experiment_id": exp, "target_id": target, "split": split, "scenario_pair_id": pair,
        "actor_condition": condition,
    }))
    (ed / "ground_truth.json").write_text(json.dumps({
        "assigned_condition": condition,
        "assigned_malicious": condition != "benign",
        "observable_attack": bool(observable),
        "attack_success": bool(success),
        "benign_task_success": (condition == "benign"),
        "refusal_detected": False,
    }))
    (ed / "public_events.jsonl").write_text("")
    return eid


def _write_pred(data: Path, exp: str, did: str, eid: str, prob: float):
    pd = data / "predictions" / did
    pd.mkdir(parents=True, exist_ok=True)
    (pd / f"{eid}.json").write_text(json.dumps({
        "experiment_id": exp, "episode_id": eid, "defender_id": did,
        "parsed_output": {"attack_probability": prob}, "parse_failure": False,
    }))


class MainAnalysisTests(unittest.TestCase):
    def test_main_design_produces_macro_auroc_and_hypotheses(self) -> None:
        exp = "main-test"
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            # 2 targets, 3 calibration + 4 test pairs each, all 3 conditions.
            defenders = {"small_open": (0.4, 0.6), "medium_open": (0.2, 0.85), "large_open": (0.05, 0.98)}
            for target in ("lunary_idor", "path_traversal"):
                for split, n in (("calibration", 3), ("test", 4)):
                    for i in range(n):
                        pair = f"{target[:3]}{split[:1]}{i}"
                        for cond in ("benign", "attack_standard", "attack_stealth"):
                            obs = 0 if cond == "benign" else 1
                            eid = _write_episode(data, exp, target, split, pair, cond, obs, obs)
                            for did, (neg, pos) in defenders.items():
                                # stealth slightly lower prob than standard (H3 signal)
                                p = neg if cond == "benign" else (pos - (0.1 if cond == "attack_stealth" else 0.0))
                                _write_pred(data, exp, did, eid, p)
            config = {
                "experiment": {"id": exp, "master_seed": 1, "data_root": str(data),
                               "calibration_pairs_per_target": 3, "test_pairs_per_target": 4},
                "targets": ["lunary_idor", "path_traversal"],
                "actor_conditions": ["benign", "attack_standard", "attack_stealth"],
                "actor_model": "best_open_attacker",
                "defender_models": ["small_open", "medium_open", "large_open"],
                "log_view": "access_v1",
                "analysis": {"primary_label": "observable_attack", "fpr_target": 0.10, "bootstrap_replicates": 200},
                "prompts": {"actor_system": "prompts/actor_system.txt", "benign": "prompts/benign.txt",
                            "attack_standard": "prompts/attack_standard.txt",
                            "attack_stealth_appendix": "prompts/attack_stealth_appendix.txt",
                            "defender": "prompts/defender.txt"},
            }
            cfg = data / "config.yaml"
            cfg.write_text(yaml.safe_dump(config))
            metrics_path, report_path = analyze(str(cfg))
            m = json.loads(metrics_path.read_text())
            self.assertEqual(m["design"], "main_calibration_test")
            self.assertEqual(sorted(m["targets"]), ["lunary_idor", "path_traversal"])
            # every defender has a target-macro AUROC on test and per-target breakdown
            for did in ("small_open", "medium_open", "large_open"):
                self.assertIn(did, m["defenders"])
                self.assertIsNotNone(m["defenders"][did]["macro_auroc"])
                self.assertEqual(sorted(m["defenders"][did]["per_target_auroc"]), ["lunary_idor", "path_traversal"])
            # H1/H2/H3 present
            self.assertIn("H1_small_macro_auroc_gt_0.5", m["hypotheses"])
            self.assertIn("H2_large_minus_small_macro", m["hypotheses"])
            self.assertIn("H3_stealth_effect_descriptive", m["hypotheses"])
            # H3: stealth prob < standard -> negative delta
            h3 = m["hypotheses"]["H3_stealth_effect_descriptive"]
            self.assertLess(h3["small_open"]["mean_delta_stealth_minus_standard"], 0)
            self.assertTrue(report_path.exists())


if __name__ == "__main__":
    unittest.main()
