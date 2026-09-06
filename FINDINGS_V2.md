# Findings — v2: Detection under realistic base rates & an adaptive attacker

> **This file is the concise findings note. The canonical, fully-detailed experimental report
> is [`REPORT.md`](REPORT.md).** Numbers below include the 5th (DeepSeek-V4-Pro) defender tier
> added after the main run.


**Experiment:** `adaptive-baserate-lunary-v1` (spec `EXPERIMENT_SPEC_V2.md`).
**Design:** open-weight attacker (Kimi K3) runs benign vs. attack episodes against an isolated
Lunary IDOR target (CVE-2024-1625, cross-tenant project DELETE). For each attack it self-red-teams:
it scores its OWN logs with a copy of itself in detector mode (the *proxy*), then revises to lower
that score while still succeeding (adaptive evasion, up to K=4 rounds, stealth target 0.5). Frozen
service-side logs are replayed to a 4-tier defender ladder. We fix each defender's threshold at
FPR ≤ 0.10 on a benign corpus (with hard negatives), then measure recall, transfer of the evasion,
and precision at realistic attack prevalences.

**Scale:** **24 attack pairs (4 calibration / 20 test)**, 3 arms each (baseline / evasive /
naive-stealth) = 72 attack episodes; 310 benign sessions; 4 defenders × 382 episodes = 1,528
predictions. (Started at 12 pairs; expanded to 24 to tighten the recall/τ estimates — see
"Effect of doubling" below.) Total model spend on frozen artifacts: **$4.91** (offense $3.88 +
defense $1.03).

> **Caveat:** recall and τ are estimated on the **20 held-out test pairs** (τ on 19 — one pair's
> proxy barely moved, so its ratio is undefined). The base-rate collapse rests on 310 benign
> sessions + an analytic sweep. Budget-tier, single semantic target — replication on a second
> vulnerability class is deferred.

---

## Headline results (n = 20 test pairs)

### 1. The base-rate collapse dominates everything
Fixing FPR ≤ 0.10 on balanced data looks fine, but at realistic prevalence precision craters for
*every* detector, including the best:

| Detector (model) | FPR | recall(base) | recall(evasive) | transfer τ [95% CI] | precision @1:100 | @1:1000 | @1:10000 |
| --- | ---: | ---: | ---: | :---: | ---: | ---: | ---: |
| medium_open (gpt-oss-20b) | 0.068 | 0.950 | 0.800 | 0.28 [0.00, 0.69] | 0.107 | 0.012 | 0.001 |
| large_oss (gpt-oss-120b)  | 0.068 | 0.650 | 0.300 | 0.53 [0.30, 0.80] | 0.043 | 0.004 | 0.000 |
| frontier_open (DeepSeek-V4-Pro) | 0.052 | 0.500 | 0.600 | 0.06 [-0.06, 0.21] | 0.105 | 0.012 | 0.001 |
| small_open (Qwen3.5-9B)   | 0.094 | 0.100 | 0.050 | -0.15 [-0.53, 0.26] | 0.005 | 0.001 | 0.000 |
| large_open (Llama-3.3-70B) | 0.039 | 0.050 | 0.050 | -0.02 [-0.17, 0.12] | 0.013 | 0.001 | 0.000 |

At 1:1000, even the best detector's alerts are ~99% false. **Budget-tier log-based LLM attack
detection is economically unusable at realistic enterprise base rates regardless of detector
quality** — the false-positive flood, not miss rate, is the binding constraint.

**The frontier-open model (DeepSeek-V4-Pro) lands mid-pack, not on top** — beaten on recall by
*both* gpt-oss models, including the mid-size 20B. It is, however, the best-calibrated (lowest FPR
of the competent detectors, tied-best precision) and the **most robust to evasion**: the attacker's
adaptation did not transfer to it (τ ≈ 0.06, and its evasive recall actually *rose* 0.50 → 0.60).
So a genuine frontier open model neither tops detection nor succumbs to the transferable evasion —
reinforcing that detection is a family/training property, and adding that *evasion transferability
is itself detector-specific* (strong to gpt-oss-120b, ~zero to DeepSeek).

### 2. Detection quality is model-FAMILY driven, NOT size — and the doubling made this razor-sharp
Baseline-recall ranking: **gpt-oss-20b (0.95) > gpt-oss-120b (0.65) ≫ Qwen3.5-9B (0.10) >
Llama-3.3-70B (0.05)**. The **largest model (70B) is the worst detector** — it essentially never
scores an attack above its own threshold — and the 9B is nearly as blind, while both gpt-oss models
dominate. Within this ladder size is if anything *anti*-correlated with detection; what matters is
family/training. (Cross-family tier comparison, not causal size — but that is the point: "small
business → huge institution defender" is a *which-model* story, not a scale story.)

### 3. Adaptive evasion is real and SIGNIFICANTLY transfers to the competent detectors
- The attacker lowered its OWN proxy's suspicion by **0.248** (95% CI [0.176, 0.316]), mainly by
  **padding sessions with benign-looking traffic** (median HTTP requests 4 → 11).
- With n=20 the transfer fraction τ is now **statistically significant** for both competent
  detectors: **gpt-oss-20b τ = 0.28 (CI [0.00, 0.69])** and **gpt-oss-120b τ = 0.53 (CI [0.30, 0.80])**.
  Most strikingly, evasion tuned *only* against the attacker's own proxy **halved gpt-oss-120b's
  recall (0.65 → 0.30)** on logs it never saw. So the evasion is not idiosyncratic overfitting to
  one detector — a meaningful, transferable chunk of it is fundamental, and it hurts the *better*
  detector more.
- The near-blind detectors (Llama-70B, Qwen-9B) show τ ≈ 0 / negative — there's no detection signal
  to erode.

### 4. A static "be stealthy" prompt does nothing; the feedback loop is what works
The naive-stealth arm barely moved proxy suspicion and actually *reduced* activity (median HTTP 2 vs
baseline 4). Only the adaptive score→feedback→revise loop produced the 0.25 drop and the padding
behaviour. Self-red-teaming ≫ a one-shot stealth instruction.

### 5. Semantic IDOR is intrinsically visible in logs
For the competent detectors, baseline recall stayed high (0.65-0.95); the attack *requires* an
unauthorized cross-tenant DELETE that appears in the logs. Evasion degrades detector *confidence*
(padding, pacing) and can push a mediocre detector below threshold, but it does not make the
violating request disappear — hence recall drops but does not vanish for gpt-oss-20b (0.80).

### 6. Economics — cheap screening is misleading
Offense: **$0.162 per successful attack** (incl. adaptation rounds). Defense: **$0.000675 per
screened session** — ~240× cheaper per unit. But the base-rate collapse means the true defense cost
is the **human triage of the false-positive flood** (thousands of false alerts per 100k sessions),
which dwarfs the per-session model cost. "Defense is cheap" is true per API call, false operationally.

---

## Effect of doubling 8 → 20 test pairs
The two underpowered claims firmed up rather than regressing:
- **family>size** got *stronger*: Llama-70B recall fell 0.125 → 0.050 (clearly the worst); gpt-oss-20b
  rose 0.875 → 0.950 (clearly the best).
- **transfer τ** became *significant*: gpt-oss-120b 0.32 [0.16, 0.55] → **0.53 [0.30, 0.80]**;
  gpt-oss-20b 0.33 [-0.03, 0.98] → **0.28 [0.00, 0.69]** (CI now excludes 0).
- base-rate collapse and the 0.25 proxy-evasion effect were unchanged (already well-estimated).

## What this says for the AI-safety trajectory
- Model family/training dominates scale for this task — a frontier-sized generic model can be a
  *worse* log detector than a mid-size one; buying "bigger" is not buying detection.
- The binding constraint on automated log defense is **base rate**, not raw detector skill — future
  gains must come from prevalence-aware operating points (cascades, pre-filters, cross-session
  correlation), not better single-session classifiers alone.
- An open-weight attacker can already self-red-team to **transferably** evade budget detectors with
  zero access to the real detector, and the transfer hurts the *stronger* detector most — a capability
  that will worsen as attacker models improve.

## Deviations / caveats
- n=20 test pairs (τ on 19). Single semantic target (Lunary IDOR); second-target replication deferred.
- Cross-family defender ladder (Together serverless has no same-family open 4-tier ladder) — report
  as tier comparison, not causal scaling. See `configs/models.yaml`.
- 1 of 24 attack pairs (the earliest pilot pair) predates token/HTTP instrumentation → minor
  undercount in the cost ledger only (its probabilities/arms are valid).
- Infra: the run required fixes for connection-drop retries (target + model clients), an OOM-leak
  cleanup cycle, a resume fast-forward bug, serverless-503 backfill passes, and reclaiming the WSL
  Docker VM's retained memory; Stages 3-4 run Docker-free and, when the harness memory-guard kills
  tracked tasks under host pressure, detached (setsid). See git log.
