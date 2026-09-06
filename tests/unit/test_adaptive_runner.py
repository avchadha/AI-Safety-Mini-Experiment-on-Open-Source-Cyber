import unittest

from cyberdetect.actor.adaptive_runner import (
    EpisodeOutcome,
    ProxyScore,
    revise_attacker_messages,
    run_self_red_team,
)


def _scripted(proxy_by_round, success_by_round):
    """Build run_episode + score_with_proxy that key off how many times they've been called."""
    calls = {"n": -1}

    def run_episode(messages):
        calls["n"] += 1
        r = calls["n"]
        return EpisodeOutcome(public_events=[{"round": r}], success=success_by_round(r), input_tokens=100, output_tokens=10)

    def score(events):
        r = events[0]["round"]
        return ProxyScore(probability=proxy_by_round(r), verdict="attack", rationale=f"round {r} tell")

    return run_episode, score


class AdaptiveRunnerTests(unittest.TestCase):
    def test_converges_and_stops_early_when_under_target(self) -> None:
        # proxy: 0.9, 0.7, 0.3 (crosses target at round 2); all succeed
        run_episode, score = _scripted(lambda r: [0.9, 0.7, 0.3, 0.1][r], lambda r: True)
        res = run_self_red_team(base_messages=[{"role": "user", "content": "attack"}],
                                run_episode=run_episode, score_with_proxy=score,
                                max_rounds=5, stealth_target=0.5)
        self.assertEqual(res.evasive.round_index, 2)          # first successful round under 0.5
        self.assertFalse(res.evasion_failed)
        self.assertEqual(len(res.rounds), 3)                  # stopped early at round 2
        self.assertAlmostEqual(res.baseline.proxy.probability, 0.9)

    def test_feedback_is_appended_each_round(self) -> None:
        run_episode, score = _scripted(lambda r: 0.9, lambda r: True)  # never evades
        seen = {"had_directive": False}
        base = [{"role": "system", "content": "S"}, {"role": "user", "content": "attack"}]

        def run_episode2(messages):
            if any("A monitor reviewing" in str(m.get("content", "")) for m in messages):
                seen["had_directive"] = True
            return EpisodeOutcome(public_events=[{"round": 0}], success=True)

        run_self_red_team(base_messages=base, run_episode=run_episode2, score_with_proxy=score,
                          max_rounds=2, stealth_target=0.0)  # target 0 forces all rounds
        self.assertTrue(seen["had_directive"])

    def test_evasion_failed_when_never_stealthy(self) -> None:
        run_episode, score = _scripted(lambda r: 0.9, lambda r: True)  # always caught
        res = run_self_red_team(base_messages=[{"role": "user", "content": "a"}],
                                run_episode=run_episode, score_with_proxy=score,
                                max_rounds=3, stealth_target=0.5)
        self.assertTrue(res.evasion_failed)
        self.assertEqual(len(res.rounds), 4)                 # baseline + 3

    def test_evasion_failed_when_stealthy_but_unsuccessful(self) -> None:
        # low proxy scores but the exploit never fires -> not a valid deliverable
        run_episode, score = _scripted(lambda r: 0.1, lambda r: False)
        res = run_self_red_team(base_messages=[{"role": "user", "content": "a"}],
                                run_episode=run_episode, score_with_proxy=score,
                                max_rounds=3, stealth_target=0.5)
        self.assertTrue(res.evasion_failed)
        self.assertEqual(res.evasive.round_index, 0)         # falls back to baseline

    def test_baseline_already_stealthy_is_success(self) -> None:
        run_episode, score = _scripted(lambda r: 0.2, lambda r: True)
        res = run_self_red_team(base_messages=[{"role": "user", "content": "a"}],
                                run_episode=run_episode, score_with_proxy=score,
                                max_rounds=3, stealth_target=0.5)
        self.assertFalse(res.evasion_failed)
        self.assertEqual(res.evasive.round_index, 0)
        self.assertEqual(len(res.rounds), 1)                 # never needed to adapt

    def test_revise_preserves_base_and_adds_one_turn(self) -> None:
        base = [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]
        out = revise_attacker_messages(base, ProxyScore(0.8, "attack", "you deleted a foreign resource"))
        self.assertEqual(out[:2], base)
        self.assertEqual(len(out), 3)
        self.assertIn("you deleted a foreign resource", out[2]["content"])


if __name__ == "__main__":
    unittest.main()
