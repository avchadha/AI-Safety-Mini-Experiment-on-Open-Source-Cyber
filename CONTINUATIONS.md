# Continuations — research directions and judgments (2026-09-05)

Companion to FINDINGS_MAIN.md. Records the diagnosis of the pilot, an honest evaluation
of candidate follow-ups, and the chosen next experiment.

## Diagnosis: the main study saturated (ceiling effect)

The results feel rudimentary because detection was measured in an easy regime: (1) the
attack is a single, individually-anomalous action; (2) prevalence was ~50% (balanced),
which flatters AUROC and hides false-alarm volume; (3) the attacker was non-adaptive (a
fixed stealth paragraph). Medium/large detectors hit AUROC 1.000. The valuable science is
not another variant at this difficulty but engineering the regime where detection BREAKS
and mapping that frontier.

## Honest evaluation of candidate directions

- Closed-source defender: premature. Open medium/large are already at 1.000, so a closed
  frontier model is uninformative until the task is hard. Operationally the interesting
  axis is cheaper/smaller, not bigger; keep one closed point only as a capability ceiling.
- Really small open defender: good, but only where models fail gradedly (semantic target,
  low base rate). Belongs in a size sweep, not alone.
- More complex/larger tasks: the crux. The productive kind of "hard" is multi-stage kill
  chains with aggregate-only signal and realistic base rates, not just "bigger."
- Real-time battles: great class demo, weak measurement (reintroduces the interaction
  confound the replay design removed). Disciplined substitute = time-to-detection via
  prefix replay (the "race" without the confound).

## Ranked suggestions

1. Realistic base rate + cost economics. Report precision / alerts-per-N at fixed recall,
   not AUROC; add a $ ledger (per attack vs per screened session). Reframes the question as
   "can log-based defense stay affordable at real base rates?" Highest value, cheapest.
2. Adaptive / optimized evasion. Attacker optimizes footprint against a detector via
   feedback rounds; measure AUROC/precision degradation. The real "can you evade?" question;
   also tests whether "stealth backfired" survives optimization.
3. Multi-stage low-and-slow / cross-session aggregation (natural home for multi-agent
   attackers under a fixed aggregate budget).
4. Defender-size x task-subtlety frontier (folds in "really small open").
5. Time-to-detection / online (the disciplined battle; watchable demo).

## Chosen next experiment

"Detection under realistic base rates and an adaptive attacker, on the semantic (Lunary)
target, as a function of defender size." Covers directions 1 and 2 plus the size slice of 4.

Key design move (preserves the replay discipline): the attacker adapts its footprint
against a FIXED reference detector, its adapted attack logs are frozen, and those frozen
logs are replayed at low base rate to the whole defender-size ladder. This separates
evasion strength (attacker adaptation) from defender capability (size ladder) cleanly.

Three design decisions to settle before the spec:
1. Evasion threat model: transfer (realistic; adapt vs held-out reference, replay to ladder)
   vs white-box (worst-case upper bound). Leaning: transfer primary + a small white-box
   side-arm.
2. Attacker feedback per round: verdict / +probability / +rationale; number of rounds.
   Leaning: full feedback (verdict+prob+rationale) from the proxy, moderate rounds, with the
   attack required to still succeed.
3. Benign-at-scale: physically running 1:1000 (~20k sessions) is infeasible (~weeks of
   container spins). Leaning: estimate per-session FPR on a diverse benign corpus WITH hard
   negatives + recall on attacks, then compute precision/alert-volume across base rates
   analytically. Realism investment goes into benign diversity, not raw volume.

Dependency: a clean size *scaling* curve needs a same-family ladder (dedicated endpoints);
otherwise it is again a cross-family tier comparison.
