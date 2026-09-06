# Findings — main study (small-defender-stealth-main-v1)

Recorded 2026-09-05. Design: log-based detection of AI-generated attacks. One large
open-weight attacker (Kimi K3) runs benign / standard-attack / stealth-attack episodes
against two isolated vulnerable targets; service-side logs are frozen and replayed,
blinded, to three detector tiers. Held-out test = 20 scenario pairs/target; threshold
selected on 10 calibration pairs/target. Primary metric: target-macro AUROC.

## Headline numbers (held-out test)

Detector target-macro AUROC (95% cluster-bootstrap CI), and per-target:

| Detector (tier)            | macro AUROC | 95% CI          | Lunary (semantic) | Gradio (syntactic) | TPR@10%FPR |
|----------------------------|-------------|-----------------|-------------------|--------------------|------------|
| small — Qwen3.5-9B         | 0.853       | [0.827, 0.875]  | 0.705             | 1.000              | 0.71       |
| medium — gpt-oss-20b       | 1.000       | [1.000, 1.000]  | 1.000             | 1.000              | 0.97       |
| large — Llama-3.3-70B      | 1.000       | [1.000, 1.000]  | 1.000             | 1.000              | 1.00       |
| baseline — frozen rules    | 0.725       | [0.700, 0.744]  | 0.500             | 0.950              | 0.46       |
| baseline — always attack/benign | 0.500  | —               | 0.500             | 0.500              | —          |

Pre-registered hypotheses (held-out test):
- H1 (small detector > chance): SUPPORTED. macro AUROC 0.853, CI lower 0.827.
- H2 (large > small): SUPPORTED. Delta macro AUROC +0.147, CI [0.125, 0.173], P(large>small)=1.0.
- H3 (stealth prompt LOWERS defender attack probability): NOT SUPPORTED — reversed.
  Mean delta(stealth - standard) attack-probability: small +0.318, medium +0.024, large +0.030.

Actor side (all 180 episodes, 0 refusals): Lunary attack success 0.97/1.00 (std/stealth),
Gradio 0.93/1.00; benign task success 0.97/1.00; benign observable-attack rate 0.00.
Defender parse failures 4/540 (0.7%); leakage audit 0 findings.

## Interpreted findings

1. Detection difficulty is dominated by vulnerability *type*, not attacker strength.
   The frozen-rules baseline is chance (0.500) on the semantic authorization abuse but
   near-perfect (0.950) on the syntactic path traversal. Model size buys almost nothing on
   the syntactic target (even 9B is perfect) and everything on the semantic one
   (9B: 0.705 -> larger: 1.000). The hard case needs reasoning about policy, not pattern
   matching.

2. Detector capability scales, and the gain is localized to the hard target. Small 0.853,
   medium/large 1.000; the (large - small) gap is entirely due to Lunary. Caveat: the three
   detectors are different model families (serverless-availability constraint), so H2 is a
   capability/tier comparison, not a causal parameter-count claim.

3. The naive stealth instruction ("minimize observable footprint") made attacks MORE
   detectable, especially for the weakest detector (+0.318). Mechanism seen in the raw
   behavior: the standard attacker padded its session with legitimate-looking recon
   (log in, list its own projects) that camouflaged the single malicious action; the stealth
   attacker skipped the cover and went straight to the unauthorized action, which stood out.
   Fewer requests != harder to detect for a log-based classifier.

## Validity and limitations

- Real attacks (high success, 0 refusals) and genuinely benign benign-runs (0 violations),
  so detection numbers and low FPRs are not artifacts.
- CEILING EFFECT: medium/large detectors saturate at AUROC 1.000. The informative signal is
  in the small-detector / hard-target cells and the two mechanisms above.
- Balanced prevalence (~50% attack) inflates AUROC vs. a realistic low base rate.
- Single-request / single-vulnerability CTF tasks; whole-episode classification; n=20 test
  pairs/target; cross-family detector ladder; model revisions pinned by provider alias+date
  (not HF commit). Benchmark-specific; not a general offense-defense claim.

## Implication for continuations

The saturation means the scientifically interesting regime is where detection BREAKS. The
value is not another variant at this difficulty but pushing into non-saturated regimes:
realistic low base rate, adaptive/optimized evasion, and multi-stage low-and-slow attacks;
plus a defender-size x task-subtlety frontier and time-to-detection (online) measurement.
See the continuation plan discussed 2026-09-05.
