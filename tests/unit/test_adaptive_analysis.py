import json
import tempfile
import unittest
from pathlib import Path

import yaml

from cyberdetect.analysis.adaptive import analyze_adaptive


class AdaptiveAnalysisTests(unittest.TestCase):
    def test_tau_and_base_rate_collapse(self) -> None:
        exp = "adap-test"
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)

            def ep(eid, pair, split):
                d = data / "episodes" / eid; d.mkdir(parents=True)
                (d / "manifest.json").write_text(json.dumps({"experiment_id": exp, "scenario_pair_id": pair, "split": split}))
                (d / "ground_truth.json").write_text(json.dumps({"observable_attack": split != "benign"}))

            def proxy(eid, prob):
                r = data / "raw_restricted" / eid; r.mkdir(parents=True)
                (r / "proxy_score.json").write_text(json.dumps({"probability": prob, "attacker_input_tokens": 6000, "attacker_output_tokens": 600, "http_requests": 3}))

            def pred(did, eid, prob):
                pd = data / "predictions" / did; pd.mkdir(parents=True, exist_ok=True)
                (pd / f"{eid}.json").write_text(json.dumps({"experiment_id": exp, "episode_id": eid, "defender_id": did, "parsed_output": {"attack_probability": prob}, "input_tokens": 1000, "output_tokens": 250}))

            for pair, split in [("p1", "test"), ("p2", "test"), ("p3", "calibration")]:
                for arm, pp, dp in [("baseline", 0.9, 0.9), ("evasive", 0.5, 0.7), ("naive_stealth", 0.85, 0.88)]:
                    eid = f"ep_{pair}_{arm}"; ep(eid, pair, split); proxy(eid, pp); pred("small_open", eid, dp)
            for i in range(20):
                eid = f"ep_benign_{i:03d}"; ep(eid, f"b{i}", "benign"); pred("small_open", eid, 0.6 if i < 2 else 0.1)

            config = {"experiment": {"id": exp, "master_seed": 1, "data_root": str(data)}, "targets": ["lunary_idor"],
                      "actor_conditions": ["benign", "attack_standard"], "actor_model": "best_open_attacker",
                      "defender_models": ["small_open"], "log_view": "access_v1",
                      "analysis": {"fpr_target": 0.10, "bootstrap_replicates": 300, "prevalences": [0.01, 0.001]},
                      "prompts": {k: f"prompts/{v}" for k, v in {"actor_system": "actor_system.txt", "benign": "benign.txt",
                                  "attack_standard": "attack_standard.txt", "attack_stealth_appendix": "attack_stealth_appendix.txt",
                                  "defender": "defender.txt"}.items()}}
            cfg = data / "c.yaml"; cfg.write_text(yaml.safe_dump(config))
            mp, rp = analyze_adaptive(str(cfg)); m = json.load(open(mp))
            d = m["defenders"]["small_open"]
            self.assertAlmostEqual(d["fpr"], 0.1, delta=0.01)
            self.assertAlmostEqual(d["transfer_tau"]["point"], 0.5, delta=1e-6)   # proxy -0.4, eval -0.2
            prec = {r["prevalence"]: r["precision"] for r in d["prevalence_sweep"]}
            self.assertGreater(prec[0.01], prec[0.001])                            # base-rate collapse
            self.assertLess(prec[0.001], 0.05)
            self.assertTrue(rp.exists())


if __name__ == "__main__":
    unittest.main()
