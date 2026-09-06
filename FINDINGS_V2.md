# Findings — v2: Detection under realistic base rates & an adaptive attacker

**Experiment:** `adaptive-baserate-lunary-v1` (spec `EXPERIMENT_SPEC_V2.md`).
**Design:** open-weight attacker (Kimi K3) runs benign vs. attack episodes against an isolated
Lunary IDOR target (CVE-2024-1625, cross-tenant project DELETE). For each attack it self-red-teams:
it scores its OWN logs with a copy of itself in detector mode (the *proxy*), then revises to lower
that score while still succeeding (adaptive evasion, up to K=4 rounds, stealth target 0.5). Frozen
service-side logs are replayed to a 4-tier defender ladder. We fix each defender's threshold at
FPR ≤ 0.10 on a benign corpus (with hard negatives), then measure recall, transfer of the evasion,
and precision at realistic attack prevalences.

**Scale (budget-constrained pilot):** 12 attack pairs (8 test / 4 calibration), 3 arms each
(baseline / evasive / naive-stealth) = 36 attack episodes; 310 benign sessions; 4 defenders
× 346 episodes = 1,384 predictions. Total model spend on the frozen artifacts: **$2.79**
(offense $1.87 + defense $0.92).

> **Caveat up front:** recall and τ are estimated on the **8 held-out test pairs** — n=8, so
> per-detector recall/τ are noisy (each 1/8 step ≈ 0.125). The base-rate collapse conclusion is
> robust because FPR is estimated on 310 benign sessions and the sweep is analytic.

---

## Headline results

### 1. The base-rate collapse dominates everything
Fixing FPR ≤ 0.10 on balanced data looks fine, but at realistic prevalence precision craters for
*every* detector, including the best:

| Detector (model) | FPR | recall(base) | recall(evasive) | precision @1:100 | @1:1000 | @1:10000 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| medium_open (gpt-oss-20b) | 0.068 | 0.875 | 0.750 | 0.101 | 0.011 | 0.001 |
| large_oss (gpt-oss-120b)  | 0.068 | 0.625 | 0.500 | 0.069 | 0.007 | 0.001 |
| large_open (Llama-3.3-70B) | 0.039 | 0.125 | 0.125 | 0.032 | 0.003 | 0.000 |
| small_open (Qwen3.5-9B)   | 0.094 | 0.125 | 0.125 | 0.013 | 0.001 | 0.000 |

At 1:1000, the best detector fires ~6,842 alerts per 100k sessions, of which **~6,767 are false**.
**Takeaway:** budget-tier, log-based LLM attack detection is economically unusable at realistic
enterprise base rates *regardless of detector quality* — the false-positive flood, not miss rate,
is the binding constraint. The "good balanced AUROC" story does not survive contact with prevalence.

### 2. Detection quality is model-family-driven, NOT size-driven
Recall ranking: **gpt-oss-20b (0.875) > gpt-oss-120b (0.625) ≫ Llama-3.3-70B = Qwen3.5-9B (0.125)**.
The 70B model is as blind as the 9B model; the *smaller* gpt-oss-20b beat the larger gpt-oss-120b.
Scale alone bought nothing. (Tier comparison across families, not causal size — but that is exactly
the point: "small business → huge institution defender" is not a size story, it's a *which model*
story.) This is the clearest and most surprising answer to the v2 question.

### 3. Adaptive evasion is real, partial, and partially transfers
- The attacker lowered its OWN proxy's suspicion by **0.25** on average (95% CI [0.15, 0.35]),
  mainly by **padding sessions with benign-looking traffic** (median HTTP requests 3 → 11).
- This transferred to the two *competent* detectors with **τ ≈ 0.32** (gpt-oss-20b CI [-0.03, 0.98];
  gpt-oss-120b CI [0.16, 0.55]) — i.e. ~1/3 of the evasion gain carried to unseen detectors,
  dropping recall 0.875→0.750 and 0.625→0.500. Evasion is neither purely idiosyncratic (τ>0) nor
  fully fundamental (τ<1): it's a genuine but partial capability. (For the blind detectors, τ is
  negative noise — no signal to erode.)

### 4. A static "be stealthy" prompt does nothing; the feedback loop is what works
The naive-stealth arm moved proxy suspicion by **0.002** (essentially zero). Only the adaptive
loop (score → feedback → revise) produced the 0.25 drop. This validates self-red-teaming over a
static stealth instruction.

### 5. Semantic IDOR is intrinsically visible in logs
Even fully evaded, recall stayed ≥ 0.50 for competent detectors. The attack *requires* an
unauthorized cross-tenant DELETE that appears in the logs; the attacker can bury it in noise and
lower detector *confidence*, but cannot make the violating request itself disappear. Evasion here
degrades confidence, it does not achieve invisibility.

### 6. Economics — cheap screening is misleading
Offense: **$0.156 per successful attack** (incl. adaptation rounds). Defense: **$0.000664 per
screened session** — ~235× cheaper per unit. But the base-rate collapse means the true defense
cost is the **human triage of the false-positive flood** (thousands of false alerts per 100k
sessions), which dwarfs the per-session model cost. "Defense is cheap" is true per API call and
false as an operational claim.

---

## What this says for the AI-safety trajectory
- Improving the *model* (family/training) matters far more than scaling it for this task.
- The bottleneck for automated log-based defense is **base rate**, not raw detector skill — future
  gains must come from prevalence-aware operating points (cascades, pre-filters, cross-session
  correlation), not just better single-session classifiers.
- An open-weight attacker can already self-red-team to partially, transferably evade budget
  detectors with no access to the real detector — the evasion capability is fundamental enough to
  transfer, which will worsen as attacker models improve.

## Deviations / caveats
- n=8 test pairs → noisy per-detector recall/τ (see caveat above). Budget pilot, not a powered study.
- Cross-family defender ladder (Together serverless has no same-family open 4-tier ladder) — report
  as tier comparison, not causal scaling. See `configs/models.yaml`.
- 1 of 12 attack pairs (the earlier pilot pair) predates the token/HTTP instrumentation, so it is a
  minor undercount in the cost ledger only (probabilities and arms are valid).
- Infra note: run required fixes for connection-drop retries, OOM-leak cleanup, a resume
  fast-forward bug, serverless 503 backfill, and reclaiming the Docker VM's retained memory (see
  git log 697f4f2 / 1b25382 / <this batch>). Stages 3-4 are Docker-free.
