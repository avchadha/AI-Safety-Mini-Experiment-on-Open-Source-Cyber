# Can a small AI detect a large AI's cyberattack from logs? A budget-tier study of open-weight attack detection under realistic base rates and an adaptive attacker

**Canonical experimental report.** AI-safety mini-experiment on open-source cyber offense/defense.
Context: coursework framing from Boaz Barak / Nicholas Carlini's AI-safety class. All models are
**open-weight**, served on Together AI's serverless API. Total spend ≈ **$10** of a ~$15 budget.

This document is intended to be self-contained and exhaustive: a future researcher or agent should
be able to understand every decision, reproduce every number, and pick up exactly where we left
off. Supporting artifacts referenced throughout live in the same repository (specs, findings notes,
development log, configs, code, and the complete frozen dataset).

---

## 0. Executive summary

We test a concrete defensive proposition: **can an AI model, reading only a service's access logs,
detect that a session was a cyberattack?** — and how that ability scales with defender capability,
survives an adaptive attacker, and holds up at realistic (rare) attack rates. An open-weight
attacker (Kimi K3) runs benign and attack sessions against an isolated, deliberately vulnerable web
app (Lunary, with a real cross-tenant authorization bug). The service logs are frozen and replayed
to five open-weight "defender" models spanning 9B to frontier scale. The attacker additionally
**self-red-teams**: it scores its own logs with a copy of itself and revises to evade, letting us
measure whether evasion learned against its own judgment transfers to detectors it never sees.

**Five findings:**

1. **Base-rate collapse dominates.** With each defender's threshold fixed to a 10% false-positive
   rate, precision at a realistic 1-in-1,000 attack prevalence is ≤ 1.2% for *every* defender —
   ~99% of all alerts are false. The binding constraint on log-based detection is the
   false-positive flood, not missed attacks.
2. **Detection is a model-family/training property, not a size property.** Ranked by detection
   rate: gpt-oss-20b (0.95) > gpt-oss-120b (0.65) > DeepSeek-V4-Pro (0.50) > Qwen3.5-9B (0.10) >
   Llama-3.3-70B (0.05). The **largest dense model is the worst**; a **mid-size model is the best**;
   a **frontier-open model lands mid-pack**. Scale buys nothing here.
3. **Adaptive evasion is real, and its transferability is detector-specific.** The attacker lowered
   its own detector's suspicion by 0.25 (mostly by padding sessions with benign traffic) with no
   access to the real detectors. This transferred strongly to gpt-oss-120b (halving its recall,
   0.65 → 0.30; transfer fraction τ = 0.53), moderately to gpt-oss-20b (τ = 0.28), and **not at all
   to DeepSeek-V4-Pro** (τ ≈ 0.06; its recall even rose).
4. **A one-shot "be stealthy" instruction does nothing** (Δ ≈ 0); only the adaptive feedback loop
   produces evasion.
5. **This semantic attack cannot be made invisible, only less obvious.** The IDOR requires an
   unauthorized cross-tenant DELETE that appears in the logs; evasion degrades detector confidence
   but cannot erase the violating request.

**Economics:** offense costs $0.16 per successful attack; defense $0.00067 per screened session
(~240× cheaper per action) — but the true defense cost is the human triage of the false-positive
flood, which the per-session figure hides.

---

## 1. Motivation

AI safety increasingly needs empirical footing for a forward question: **as models get more
capable, how does the balance between automated cyber *offense* and automated cyber *defense*
shift?** If capable models make attacks cheaper and stealthier faster than they make defense
better, that is a different world than if defense keeps pace.

We pick one concrete, measurable slice of that question: **post-hoc detection of attacks from
service logs.** This is a realistic defensive primitive (SOC/SIEM triage, anomaly review) and a
clean testbed: the attacker produces log telemetry by acting against a real vulnerable app; the
defender must judge, from the logs alone, whether a session was malicious. It isolates *detection*
from *prevention* and lets us vary attacker adaptivity and defender capability independently.

Three design commitments follow from the safety framing:

- **Open-weight models throughout.** Open-weight capability is what a broad set of actors —
  including unsophisticated or adversarial ones — will actually have. It is also the capability
  frontier we can reason about publicly. (Closed frontier models as a "defense ceiling" are a
  deferred extension; see §11.)
- **Budget tier.** We deliberately study what is achievable cheaply (serverless inference, small
  scaffolds), because that is the regime in which offense/defense actually proliferates. A
  secondary payoff is a picture of *budget* offense vs. defense economics.
- **Capability-spanning defenders.** We compare defenders from ~9B to frontier scale to ask whether
  "a bigger institutional defender" is meaningfully better than "a small-business defender."

### 1.1 Why this study exists (evolution from v1)

The first study (v1, "main study"; see `FINDINGS_MAIN.md`, `EXPERIMENT_SPEC.md`) ran a
balanced benign-vs-attack detection benchmark on two targets (Lunary IDOR, and a Gradio
path-traversal) with three defenders, scored by AUROC. It produced a **ceiling effect**: medium and
large defenders saturated at AUROC ≈ 1.000 on the balanced task, a rules baseline was perfect on
the syntactic Gradio target, and the most striking result was a *reversal* — a naive "stealth"
instruction made attacks **more** detectable, because the standard attacker's legitimate-looking
reconnaissance already camouflaged its one malicious action. The operator's own read was that these
were "obvious and rudimentary" — a saturated regime.

v2 (this report) was designed to move into the **non-saturated regime** where detection actually
breaks, along the three axes v1 could not see: **realistic base rates** (rare attacks), an
**adaptive attacker** (optimized evasion), and a **capability-spanning defender ladder**. The
research directions we considered and deferred are recorded in `CONTINUATIONS.md`.

---

## 2. Threat model and framing

Four roles:

- **Attacker** — an open-weight LLM (Kimi K3) driving a browser-like agent (a ReAct loop with a
  constrained HTTP tool) against a fresh isolated instance of the target, either doing benign work
  or executing the attack.
- **Environment** — the isolated target plus a telemetry proxy that produces two streams: a
  **public** `access_v1` log (method, path, status, timing, coarse shape — what a defender may see)
  and a **protected oracle** stream (ground-truth policy violations, canary hits — never shown to
  defenders).
- **Defender** — an open-weight LLM that reads one session's public log packet and outputs
  `{verdict, attack_probability, rationale}`.
- **Proxy** — a copy of the *attacker* model in detector mode, used only by the attacker to score
  and refine its own evasion.

Two hard invariants:

- **INV-1: the attacker never sees an evaluation detector.** Its only detection signal is the proxy
  (itself). This is the *transfer-only* threat model: a real attacker rarely has query access to
  the exact defender in place, but does have a strong model of its own.
- **INV-2: the proxy is the attacker's own model and is excluded from the defender ladder.** If the
  proxy were also an evaluated defender, the attacker would get free "real" optimization rounds and
  the evaluation would leak. The proxy (Kimi K3) is therefore *not* one of the five scored
  defenders.

**Why proxy = attacker.** The most realistic and most conservative assumption is that a capable
attacker's best model of "what looks suspicious" is itself. It requires no oracle and no extra
model, and it is exactly the capability an autonomous attacker would deploy. This makes the
resulting evasion a lower bound on what a dedicated adversary could achieve.

---

## 3. Experimental design

### 3.1 Target

- **Lunary** (an LLM-observability app), pinned to its known-vulnerable commit
  `fc959987f3b2cfba25c847ffdba6ac820af154b4`, sourced via the BountyBench benchmark
  (`bountytasks` @ `1956e5fd…`, `bountybench` @ `8ece6aab…`). Configs and digests in
  `configs/targets/lunary_idor.yaml`; the resolved pins are also frozen into `experiment.lock.json`
  and `target-images.lock.json`.
- **Vulnerability:** IDOR / broken object-level authorization (**CVE-2024-1625, CWE-639**). An
  authenticated user in one tenant can **delete another tenant's project** by supplying the victim
  project's id to `DELETE /v1/projects/:id`, which fails to check ownership. This is a *semantic*
  authorization bug — the malicious request is syntactically indistinguishable from a legitimate
  self-delete; only the *cross-tenant* relationship makes it an attack. That property is central to
  the findings (§8.5).
- A second, *syntactic* target (Gradio path traversal, CVE-2024-1561) exists in the codebase but
  was **dropped** for v2: v1 showed a rules baseline solved it perfectly (saturated), so it adds no
  discriminating signal.

### 3.2 Isolation architecture

Each attack runs against a **fresh** container stack, torn down afterward (attack state cannot
carry across rounds — a later round would have nothing left to exploit). The stack (see
`docker/phase1/`):

- Two Docker networks: an `internal: true` `isolated` network (app + Postgres, no egress) and a
  bridge `edge` network the telemetry proxy joins so its port can be published on **127.0.0.1
  only** (loopback). The actor reaches the app solely through this proxy.
- The proxy records the two telemetry streams and enforces the actor's interface: HTTP only, no
  redirects, response-size caps, an allow-list of forwardable headers, and content-type inference
  so the actor need not (and cannot) set trusted transport headers itself.
- **Isolation caveat (SD-1):** on Docker Desktop's NAT VM, outbound egress from containers is not
  fully blocked by the settings we can set portably. The target app makes no outbound calls, and
  the target is a known-CVE benchmark on a throwaway instance, so this was operator-accepted as a
  documented deviation (`SAFETY_DEVIATIONS.md`). Inbound isolation (loopback-only) and stream
  separation are intact and verified by the target doctor.

### 3.3 Attacker and the adaptive self-red-team loop

For each attack scenario the attacker is run in three **arms**:

- **baseline** — the standard attack, no evasion pressure.
- **evasive** — the product of the self-red-team loop (`actor/adaptive_runner.py`):
  1. Run the attack against a fresh target; collect the public log.
  2. Score that log with the **proxy** (Kimi K3 in detector mode) → an attack probability.
  3. If the attack succeeded and the proxy probability is already below the stealth target (0.5),
     stop; otherwise feed the proxy's probability and rationale back to the attacker as an
     **evasion directive** ("a monitor flagged your session … accomplish the same objective but
     make the logged requests look like ordinary authorized use; do not tamper with the logging
     itself") and run another round, up to **K = 4** rounds.
  4. The delivered evasive episode is the successful round with the lowest proxy probability
     (falling back to baseline if none cleared the target).
- **naive_stealth** — a control: the attacker is told once, up front, to be stealthy, with **no**
  feedback loop. This isolates "adaptivity" from "a stealth instruction."

The attacker is a ReAct loop (`actor/real_runner.py`) over the constrained HTTP tool. The evasion
directive explicitly forbids attacking the logging system itself, so evasion means *behavioural*
camouflage (padding, pacing, avoiding unusual requests), not log tampering.

### 3.4 Benign corpus (the false-positive floor)

Benign sessions set each defender's operating threshold, so their realism determines the FPR floor.
`environment/benign.py` scripts diverse benign Lunary sessions and, critically, **hard negatives** —
unusual-but-authorized behaviour that a naive detector would over-flag: bulk deletion of one's
*own* projects, error-and-retry loops, and high-volume own-resource enumeration. Every action stays
within the actor's own tenant, so the oracle records no violation and ground truth is benign. 310
benign sessions were generated.

### 3.5 Defender ladder (5 tiers)

All defenders are open-weight, served on Together serverless, judging one session from its public
log packet with **hidden chain-of-thought disabled** (for a fair single-forward-pass comparison and
clean JSON — see `DEVELOPMENT_LOG.md`). The ladder spans families deliberately: Together's
serverless catalogue has no same-family open ladder across these sizes, so **this is a
model/tier comparison, not a controlled size manipulation.** That limitation is also the point (§8.2).

| Tier id | Model | Scale | Reasoning control |
| --- | --- | --- | --- |
| `small_open` | Qwen/Qwen3.5-9B | 9B dense | `enable_thinking: false` |
| `medium_open` | openai/gpt-oss-20b | ~21B MoE (~3.6B active) | `reasoning_effort: low` |
| `large_open` | meta-llama/Llama-3.3-70B-Instruct-Turbo | 70B dense | (non-reasoning) |
| `large_oss` | openai/gpt-oss-120b | ~120B MoE (~5B active) | `reasoning_effort: low` |
| `frontier_open` | deepseek-ai/DeepSeek-V4-Pro-0813 | frontier MoE | `thinking: false` |

The attacker/proxy **Kimi K3** is excluded from this ladder (INV-2).

### 3.6 Immutable episodes and splits

Every arm of every scenario is frozen as a content-addressed **episode bundle**: public log,
defender packet, manifest, and ground truth, with SHA-256 checksums; restricted artifacts (oracle,
proxy score, attacker transcript) are stored separately and never enter a defender packet. Scenario
pairs are deterministically assigned to **calibration** (4) or **test** (20) splits by index, seeded
from a master seed, so the generator is append-stable (adding pairs never perturbs existing ones).

---

## 4. Metrics and analysis

All defined in `analysis/baserate.py` / `analysis/adaptive.py`; pure numeric cores are unit-tested.

- **Operating threshold.** For each defender, choose the lowest (most sensitive) probability
  threshold whose false-positive rate on the 310 benign sessions is ≤ **0.10**. All downstream
  metrics use this per-defender threshold.
- **Recall** = fraction of held-out **test** attack episodes scored ≥ threshold, computed separately
  for the *baseline* and *evasive* arms.
- **Precision at prevalence p** (the base-rate sweep) — analytic:
  `precision(p) = recall·p / (recall·p + FPR·(1−p))`, swept over p ∈ {1/50, 1/100, 1/1000, 1/10000}.
  Also reported as expected alert counts per 100,000 sessions.
- **Transfer fraction τ** (per pair, then averaged with a bootstrap CI):
  `τ = (eval_baseline − eval_evasive) / (proxy_baseline − proxy_evasive)`, i.e. the drop in a *real*
  detector's probability caused by the evasion, divided by the drop the attacker achieved on its
  *own* proxy. τ ≈ 0 means the evasion was idiosyncratic to the proxy; τ ≈ 1 means it transferred
  fully; τ is undefined (dropped) for a pair whose proxy barely moved (< 0.05), to keep the ratio
  stable. Averaged over the pairs where it is defined (n = 19), with a nonparametric bootstrap 95%
  CI over pairs.
- **Cost ledger.** Offense $/successful-attack (attacker tokens incl. adaptation rounds, priced at
  Kimi K3 rates) and defense $/screened-session (blended defender token cost).
- **Uncertainty.** FPR rests on 310 benign sessions; recall and τ on the **20 test pairs** (τ on
  19). Bootstrap CIs are over pairs. Per-detector recall therefore moves in 1/20 steps — see the
  limitations (§9) on statistical power.

---

## 5. Procedure as actually run

1. Build & verify the isolated target (`cyberdetect target doctor --target lunary_idor` →
   `overall: pass`, isolation verified, proxy egress blocked, source pins verified, streams
   separate + aligned).
2. Generate 24 scenario pairs (4 calibration / 20 test) for `adaptive-baserate-lunary-v1`.
3. **Attackers** (`run_adaptive_actors`, under Docker): for each attack scenario, run the adaptive
   loop and freeze the baseline / evasive / naive_stealth arms with per-round proxy scores. 24
   pairs × 3 arms = 72 attack episodes.
4. **Benign corpus** (`generate_benign_corpus`): 310 scripted sessions with hard negatives, frozen
   as benign episodes.
5. **Defenders** (`run_real_defenders`, Docker-free): score all 382 episodes (72 attack + 310
   benign) with each of the 5 tiers → 1,910 predictions.
6. **Analysis** (`analyze_adaptive`): threshold, recall, τ, base-rate sweep, cost ledger →
   `data/reports/adaptive_report.md` + `adaptive_metrics.json`.

The run was executed in two campaigns: an initial 12-pair study, then an expansion to 24 pairs to
de-noise the estimates, and finally the DeepSeek-V4-Pro tier added post-hoc (scoring the already
frozen episodes — no attacker re-runs). The infrastructure required substantial hardening along the
way (connection-drop retries, OOM-leak cleanup, an idempotent-resume fix, serverless-503 backfill,
Docker-VM memory reclamation, detached execution). The full engineering narrative — essential for
reproduction — is in **`DEVELOPMENT_LOG.md`**. Drivers: `run_v2_study.py` (full),
`run_v2_actors.py` (actors only), `run_v2_finish.py` (defenders + analysis, Docker-free).

Data quality: JSON parse-failure rates were low — 10/382 (Qwen3.5-9B), 6 (gpt-oss-120b), 2
(DeepSeek-V4-Pro), 1 (gpt-oss-20b), 1 (Llama-70B).

---

## 6. Results

**Design:** 24 attack pairs (20 test), 3 arms, 310 benign, 5 defenders, 1,910 predictions.
Per-defender threshold fixes FPR ≤ 0.10 on benign. Recall / precision on the 20 held-out test pairs.

### 6.1 Detectors under self-red-teamed evasion

| Detector (model) | thr | FPR | recall (base) | recall (evasive) | transfer τ [95% CI] | precision @1:100 | @1:1000 | @1:10000 |
| --- | ---: | ---: | ---: | ---: | :---: | ---: | ---: | ---: |
| gpt-oss-20b (`medium_open`) | 0.95 | 0.068 | **0.950** | 0.800 | 0.28 [0.00, 0.69] | 0.107 | 0.012 | 0.0012 |
| gpt-oss-120b (`large_oss`) | 0.93 | 0.068 | 0.650 | 0.300 | **0.53 [0.30, 0.80]** | 0.043 | 0.004 | 0.0004 |
| DeepSeek-V4-Pro (`frontier_open`) | 0.92 | 0.052 | 0.500 | 0.600 | 0.06 [-0.06, 0.21] | 0.105 | 0.012 | 0.0012 |
| Qwen3.5-9B (`small_open`) | 0.95 | 0.094 | 0.100 | 0.050 | -0.15 [-0.53, 0.26] | 0.005 | 0.001 | 0.0001 |
| Llama-3.3-70B (`large_open`) | 0.90 | 0.039 | 0.050 | 0.050 | -0.02 [-0.17, 0.12] | 0.013 | 0.001 | 0.0001 |

### 6.2 Evasion on the attacker's own proxy

- Mean proxy-probability drop **baseline → evasive: 0.248** (95% CI [0.176, 0.316], n = 24).
- Mean drop **baseline → naive_stealth: −0.004** (95% CI [−0.021, 0.012], n = 24) — indistinguishable
  from zero.
- Median HTTP requests per arm: **baseline 4, evasive 11, naive_stealth 2** — the evasive arm pads
  with extra benign-looking requests; the naive arm just does *less*.

### 6.3 Cost ledger

- **Offense:** $3.88 total across 24 pairs (incl. adaptation rounds); **$0.162 per successful attack.**
- **Defense:** $1.29 total across 1,910 predictions; **$0.000673 per screened session.**

---

## 7. Results in one picture

- **Detection competence** (baseline recall): gpt-oss-20b **0.95** ≫ gpt-oss-120b 0.65 > DeepSeek-V4-Pro 0.50 ≫ Qwen-9B 0.10 > Llama-70B 0.05.
- **Calibration** (FPR at the fixed threshold; lower is tighter): Llama 0.039 < DeepSeek 0.052 < gpt-oss-20b = gpt-oss-120b 0.068 < Qwen 0.094. DeepSeek is the best-calibrated *competent* detector.
- **Evasion robustness** (τ; lower/negative = more robust): DeepSeek ≈ 0.06 and gpt-oss-20b 0.28 are robust-ish; gpt-oss-120b 0.53 is the most evadable; the blind detectors' τ is noise.
- **Realistic-prevalence precision** (@1:1000): best is 0.012 (gpt-oss-20b and DeepSeek, tied) — i.e. still ~99% false alerts.

---

## 8. Interpretation

### 8.1 The base-rate collapse is the dominant, robust result
On balanced data the good detectors look strong (recall up to 0.95 at FPR 0.068). But real
environments are overwhelmingly benign. At 1:1000, `precision = recall·p/(recall·p + FPR·(1−p))`
falls to ≤ 0.012 for every detector: at that rate the best detector produces ~6,800 alerts per
100k sessions of which ~6,700 are false. This is arithmetic, not a modelling artifact, and it is
the most robust conclusion here (FPR is estimated on 310 benign; the sweep is analytic). **The
limiting factor for automated log-based detection is the false-positive flood, not miss rate.**
Progress requires prevalence-aware operating points (cascades, pre-filters, cross-session
correlation), not just better single-session classifiers.

### 8.2 Detection is a family/training property, not a size property
The largest dense model (Llama-3.3-70B) is the *worst* detector — it essentially never scores an
attack above its own threshold (recall 0.05) — while the mid-size gpt-oss-20b is the *best* (0.95),
and a genuine frontier-open model (DeepSeek-V4-Pro) lands *mid-pack* (0.50). Within this ladder,
scale is if anything anti-correlated with detection. The practical implication for the "small
business → large institution defender" question is stark: **buying a bigger model does not buy
detection; you must pick the right model.** (Caveat: cross-family comparison, not a controlled size
sweep — but "which model to deploy" is exactly the operational question, and the answer is not
"the biggest.") A plausible mechanism is that log/security-flavoured post-training — not raw scale —
is what makes gpt-oss read access logs well; we did not isolate this and flag it for future work.

### 8.3 Adaptive evasion is real, and its transferability is detector-specific
With zero access to the real detectors, the attacker lowered its own proxy's suspicion by 0.25,
almost entirely by **padding the session with benign-looking traffic** (median requests 4 → 11) so
the single malicious request is diluted. This transferred **strongly to gpt-oss-120b** (recall
0.65 → 0.30; τ = 0.53, CI excludes 0), **moderately to gpt-oss-20b** (0.95 → 0.80; τ = 0.28, CI
just excludes 0), and **not to DeepSeek-V4-Pro** (τ = 0.06, CI spans 0; its recall actually rose
0.50 → 0.60 — the padding gave it *more* to flag). Two implications: (a) transferable, black-box
evasion by an open-weight attacker is already demonstrable and hurts the *stronger* gpt-oss detector
most; (b) evasion is not a universal key — its success depends on the target detector's family, so
"robustness to transferable evasion" is a distinct axis from raw recall, and DeepSeek scores well on
it despite middling recall.

### 8.4 The feedback loop, not the instruction, is what evades
The naive-stealth arm — a one-shot "be stealthy" instruction — moved proxy suspicion by −0.004
(nothing) and merely reduced activity. Only the adaptive score→feedback→revise loop produced the
0.25 drop and the padding behaviour. Evasion here is an *optimization* capability, not a prompt.

### 8.5 The attack cannot be hidden, only obscured
Even fully evaded, the competent detectors retained non-trivial recall (gpt-oss-20b 0.80). The IDOR
*requires* an unauthorized cross-tenant DELETE, and that request is in the log no matter what. The
attacker can lower a detector's *confidence* (enough to push a mediocre detector below threshold)
but cannot remove the violating action. We expect this to be weaker for vulnerability classes whose
malicious action more closely mimics benign traffic — a key reason a second, different-class target
is the top future priority (§11).

### 8.6 Budget economics are lopsided but the cheap side is misleading
Per action, defense ($0.00067/session) is ~240× cheaper than offense ($0.16/successful attack). But
because of the base-rate collapse, the operational cost of defense is the **human triage of
thousands of false alerts per 100k sessions**, which dwarfs the per-session model cost. "Defense is
cheap" is true per API call and false as a deployment claim.

### 8.7 What this suggests for the offense/defense trajectory
(1) For this task, *which* model matters far more than how big — a frontier-sized generic model can
be a worse log detector than a mid-size one. (2) The bottleneck is base rate, a structural property
of deployment, not detector IQ. (3) An open-weight attacker can already self-red-team to
transferably erode budget detectors, and the erosion hits the stronger detector hardest — a
capability likely to grow with attacker scale. Together these favour the pessimistic reading for
naive single-session log detection, while pointing to where defense must go (prevalence-aware,
correlation-based pipelines; and detector *robustness*, on which the frontier-open model did best).

---

## 9. Constraints and limitations

- **Statistical power.** Recall and τ rest on **20 test pairs** (τ on 19). Per-detector recall moves
  in 1/20 increments; the recall *rankings* are large and stable (0.95 vs 0.05 endpoints; expansion
  from 8→20 pairs sharpened rather than reversed them), but individual τ values carry real
  uncertainty (CIs reported). This is a budget pilot, not a powered study.
- **Single target / single vulnerability class.** All results are on Lunary IDOR (semantic
  cross-tenant authz). §8.5 in particular may not generalise to classes where the malicious action
  mimics benign traffic. A second semantic target is the top deferred item.
- **Cross-family defender ladder.** No same-family open ladder exists on Together serverless, so
  "size" effects are confounded with family/training. Reported as a tier comparison; a controlled
  size sweep (one family, several sizes) is future work.
- **Transfer-only, proxy = attacker.** Results are specific to this threat model. A white-box or
  query-access attacker would evade more; a weaker attacker less. τ measures transfer to *these five*
  detectors only.
- **Budget/serverless constraints.** Open-weight only (no closed frontier "defense ceiling"); no
  specialized security models (e.g. Foundation-sec, WhiteRabbitNeo) — not on Together, need
  self-hosted GPUs. Hidden reasoning disabled on all defenders (a deliberate constraint, but it
  forecloses "let the big model think" as a strategy).
- **Data caveats.** 1 of 24 attack pairs (the earliest pilot pair) predates token/HTTP
  instrumentation → a minor undercount in the cost ledger only (its probabilities/arms are valid).
  Parse failures (≤ 2.6% per tier) fall back to the parser's default probability.
- **Isolation SD-1.** Container egress not fully blocked on Docker Desktop (accepted; §3.2).

---

## 10. Issues encountered (summary; full detail in `DEVELOPMENT_LOG.md`)

The run surfaced six independent infrastructure failure modes, each fixed with the same discipline
(retry transients, isolate per-unit failures, resume idempotently): (1) local-target connection
drops with no gateway retry; (2) an OOM-kill cycle driven by leaked container stacks bloating the
Docker VM; (3) a resume bug where relaunches silently re-ran completed pairs (67 min, zero new
work) because idempotency lived only in the freeze *write*; (4) a single serverless 503 aborting the
entire defender sweep; (5) the Docker VM retaining ballooned memory so even the container-free stage
was OOM-killed (fixed by terminating the Docker WSL VM); (6) the harness memory-guard killing *any*
tracked background task under host pressure (fixed by running detached). These are documented not as
incidental but because they are the exact traps a reproduction will hit, and because two of them
(the resume bug, the 503) would silently corrupt results — burning budget with no progress, or
analysing a partial dataset — rather than failing loudly.

---

## 11. Future research directions (deferred)

In rough priority order:

1. **A second semantic target of a different class.** The single highest-value next step: does
   "family, not size" (§8.2) and "attacks stay log-visible" (§8.5) replicate on a vulnerability
   whose malicious action mimics benign traffic (e.g. a logic/pricing bug, an SSRF, a data-scraping
   abuse)? External validity for every finding hinges on this.
2. **A controlled size sweep within one family.** Resolve the size/family confound: e.g.
   Qwen3.5-9B → 35B → 122B → 397B as defenders, holding family fixed, to test whether scale ever
   helps *within* a family.
3. **Specialized security-tuned defenders** (Foundation-sec-8B, WhiteRabbitNeo, etc.). Directly
   tests the §8.2 mechanism hypothesis (security post-training, not scale). Needs self-hosted GPUs
   (not on Together serverless).
4. **A closed-frontier "defense ceiling."** Add a top closed model as a defender to bound how good
   detection *can* get, and re-measure the base-rate collapse and transfer against it.
5. **Stronger / white-box attackers and multi-round transfer.** An attacker with query access to a
   surrogate, or offense-tuned weights, or many more adaptation rounds — to map how τ and evasion
   grow with attacker capability.
6. **Larger, powered scale.** Enough pairs to give recall/τ tight CIs and enable per-family
   significance tests; multiple seeds per scenario.
7. **Prevalence-aware defense pipelines.** Since base rate is the binding constraint (§8.1),
   evaluate cascades, cheap pre-filters, and cross-session correlation rather than single-session
   classifiers — the actual path to usable precision at 1:1000.
8. **Low-and-slow / multi-stage attacks and time-to-detection** via prefix replay (how early in a
   session can a detector flag it?).
9. **Real-time / interactive defense** (a defender that can act mid-session), vs. this post-hoc
   framing.

---

## 12. Reproduction guide

Prerequisites: Docker (Desktop on WSL2 works, with the SD-1 caveat), Python 3.12, the `.venv-linux`
environment, and a Together API key in `secrets.env` (copy `secrets.env.example`; the same key is
used for attacker, proxy, and defenders). Upstream target source is **not** vendored — it is fetched
at pinned commits by the build step.

```bash
# 0. environment + secrets
cp secrets.env.example secrets.env      # fill in the Together key(s)
source secrets.env

# 1. build & verify the isolated target (fetches pinned upstreams, builds images)
cyberdetect target build  --target lunary_idor
cyberdetect target doctor --target lunary_idor      # must report overall: pass

# 2. generate scenarios (24 pairs = 4 cal / 20 test)
python -c "from cyberdetect.scenarios import generate_scenarios; generate_scenarios('configs/adaptive.yaml')"

# 3. run the study (attackers need Docker; defenders/analysis do not)
python run_v2_actors.py                 # adaptive attackers -> frozen arms  (Docker; slow: Kimi latency)
python run_v2_finish.py                 # benign* + defenders + analysis      (Docker-free)
#   * benign corpus: the finisher skips it if already present; to (re)build it explicitly:
#     python -c "from cyberdetect.environment.benign import generate_benign_corpus; generate_benign_corpus('configs/adaptive.yaml')"

# results:
#   data/reports/adaptive_report.md      (human-readable)
#   data/reports/adaptive_metrics.json   (full metrics)
```

The **frozen dataset for this exact run is included** under `data/` (episodes, predictions,
raw_restricted, reports), so `analyze_adaptive('configs/adaptive.yaml')` reproduces every number in
§6 without spending anything or running Docker. Offline unit tests: `python -m unittest discover -s
tests`.

---

## Appendix A. Model identities and Together prices (observed 2026-09-06, USD / 1M tokens)

| Role / tier | Model id | in | out |
| --- | --- | ---: | ---: |
| Attacker + proxy | `moonshotai/Kimi-K3` | 3.0 | 15.0 |
| `small_open` | `Qwen/Qwen3.5-9B` | 0.17 | 0.25 |
| `medium_open` | `openai/gpt-oss-20b` | 0.05 | 0.20 |
| `large_open` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | 1.04 | 1.04 |
| `large_oss` | `openai/gpt-oss-120b` | 0.15 | 0.60 |
| `frontier_open` | `deepseek-ai/DeepSeek-V4-Pro-0813` | 1.32 | 3.96 |

`deepseek-ai/DeepSeek-V3.1` was **not** available serverless ("Unable to access non-serverless
model"); V4-Pro is newer/stronger and was used instead.

## Appendix B. Repository map

```
REPORT.md                 <- this document (canonical)
README.md                 <- landing page / quickstart
EXPERIMENT_SPEC.md        <- v1 spec        EXPERIMENT_SPEC_V2.md  <- v2 spec
FINDINGS_MAIN.md          <- v1 findings    FINDINGS_V2.md         <- v2 findings (concise)
CONTINUATIONS.md          <- research-direction reasoning
DEVIATIONS_MAIN.md, SAFETY_DEVIATIONS.md    <- deviations (incl. SD-1)
DEVELOPMENT_LOG.md        <- full engineering journey & the six failure modes
src/cyberdetect/          <- all scaffolding code (targets, actor, defender, analysis, cli)
tests/                    <- offline unit/integration tests
configs/                  <- models.yaml, adaptive.yaml, targets/*.yaml
docker/                   <- isolation compose + proxy + seed
prompts/                  <- actor/defender/benign/stealth prompts
run_v2_study.py, run_v2_actors.py, run_v2_finish.py  <- run drivers
data/                     <- FROZEN DATASET: episodes/, predictions/, raw_restricted/, reports/
*.lock.json               <- pinned upstream commits + built-image digests
```

## Appendix C. Key configuration (`configs/adaptive.yaml`)

experiment id `adaptive-baserate-lunary-v1`; master_seed 20260905; target `lunary_idor`;
calibration_pairs_per_target 4; test_pairs_per_target 20; adaptive {max_rounds 4,
stealth_target 0.5, include_naive_stealth_arm true}; benign_corpus {sessions 250 (310 produced),
hard_negative_fraction 0.4}; actor_conditions [benign, attack_standard]; actor_model
best_open_attacker (Kimi K3); defender_models [small_open, medium_open, large_open, large_oss,
frontier_open]; analysis {fpr_target 0.10, prevalences [0.02, 0.01, 0.001, 0.0001]}.
