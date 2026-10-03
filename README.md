# AI Safety: Mini-Experiment on Open-Source Cyber

**Can a small AI detect a large AI's cyberattack just by reading the service logs — and does that
hold up against an adaptive attacker and at realistic (rare) attack rates?**

An AI-safety mini-experiment on open-weight cyber offense/defense (coursework framing from Boaz
Barak / Nicholas Carlini's class). An open-weight **attacker** (Kimi K3) runs benign and attack
sessions against an isolated, deliberately vulnerable web app (Lunary, CVE-2024-1625 cross-tenant
IDOR); the service logs are frozen and replayed to five open-weight **defender** models from 9B to
frontier scale. The attacker also **self-red-teams** — it scores its own logs with a copy of itself
and revises to evade — so we can measure whether evasion transfers to detectors it never sees.
Everything is open-weight, budget-tier (~$10 of Together serverless), and fully reproducible.

## 📄 Read the report

**[`REPORT.md`](REPORT.md)** is the canonical, fully-detailed experimental report — motivation,
design, procedure, results, interpretation, limitations, and future work. Start there.

## TL;DR findings

1. **Base-rate collapse dominates.** At a fixed 10% false-positive rate, precision at a realistic
   1-in-1,000 attack rate is ≤ 1.2% for *every* defender — ~99% of alerts are false. The binding
   constraint is the false-positive flood, not missed attacks.
2. **Detection is a model-family/training property, not size.** Detection rate: gpt-oss-20b (0.95) >
   gpt-oss-120b (0.65) > DeepSeek-V4-Pro (0.50) > Qwen3.5-9B (0.10) > Llama-3.3-70B (0.05). The
   **largest** model is the **worst**; a mid-size model is best; a frontier-open model is mid-pack.
3. **Adaptive evasion is real and its transfer is detector-specific.** With no access to the real
   detectors, the attacker cut gpt-oss-120b's recall in half (transfer τ = 0.53) but did **not**
   evade DeepSeek-V4-Pro (τ ≈ 0). It works by padding sessions with benign traffic (median requests
   4 → 11).
4. **A one-shot "be stealthy" prompt does nothing** — only the adaptive feedback loop evades.
5. **The attack can't be hidden, only obscured** — the unauthorized cross-tenant DELETE is always
   in the log; evasion lowers confidence, not visibility.

Economics: offense $0.16 / successful attack vs. defense $0.00067 / screened session — but the real
defense cost is human triage of the false-positive flood.

## Repository map

| Path | What |
| --- | --- |
| [`REPORT.md`](REPORT.md) | **Canonical experimental report** (read this) |
| [`FINDINGS_V2.md`](FINDINGS_V2.md) · [`FINDINGS_MAIN.md`](FINDINGS_MAIN.md) | Concise findings (v2 / v1) |
| [`EXPERIMENT_SPEC_V2.md`](EXPERIMENT_SPEC_V2.md) · [`EXPERIMENT_SPEC.md`](EXPERIMENT_SPEC.md) | Pre-registration specs (v2 / v1) |
| [`DEVELOPMENT_LOG.md`](DEVELOPMENT_LOG.md) | Full engineering journey & the six run-time failure modes |
| [`CONTINUATIONS.md`](CONTINUATIONS.md) | Research-direction reasoning |
| [`SAFETY_DEVIATIONS.md`](SAFETY_DEVIATIONS.md) · [`DEVIATIONS_MAIN.md`](DEVIATIONS_MAIN.md) | Deviations (incl. isolation SD-1) |
| `src/cyberdetect/` | All scaffolding code (target isolation, actor, defenders, analysis, CLI) |
| `configs/` · `docker/` · `prompts/` | Model/experiment config, isolation stack, prompts |
| `run_v2_*.py` | Run drivers |
| `data/` | **Frozen dataset** for this run (episodes, predictions, raw_restricted, reports) |
| `tests/` | Offline unit/integration tests |

## Reproduce the numbers without spending anything

The frozen dataset is included, so the analysis reproduces every reported number offline:

```bash
source secrets.env   # only needed to re-run models; not needed for re-analysis
python -c "from cyberdetect.analysis.adaptive import analyze_adaptive; analyze_adaptive('configs/adaptive.yaml')"
cat data/reports/adaptive_report.md
python -m unittest discover -s tests    # offline test suite
```

For a new collection, use the Docker and model setup in [`MANUAL_SETUP.md`](MANUAL_SETUP.md)
with the experiment configuration in [`configs/adaptive.yaml`](configs/adaptive.yaml).

## Scope & safety

Defensive security research in an authorized/educational context. The attacker exercises a
**known, published CVE** on a benchmark app running on an **isolated, throwaway** instance, solely
to generate detection telemetry — it is not a general-purpose exploit tool. Secrets live only in a
gitignored `secrets.env` (template: `secrets.env.example`); the published `data/` contains only
ephemeral throwaway-container credentials and experiment canaries (audited — no real secrets). If
you clone this, **rotate any Together key** you use. Isolation caveat SD-1 is documented in
`SAFETY_DEVIATIONS.md`.
