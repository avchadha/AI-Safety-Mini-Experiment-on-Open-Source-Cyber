# Open Weight Models and the Detection of Cyberattacks

Amrit Chadha  
AI safety mini-experiment for Boaz Barak and Nicholas Carlini's AI-safety course

## I Research Question and Background

Increasing AI capability may change the balance between cyber offense and defense, but attack execution and attack recognition need not improve together. Even strong recognition on a benchmark may offer little operational value when attacks are rare. This study examines that tension through post-hoc detection: an open-weight attacker acts against an isolated vulnerable application, and five open-weight defenders classify its frozen service logs with access to a public authorization runbook.

The results support three claims. Detection varies substantially across the models tested, without a monotonic relationship to parameter count. An attacker adapting against its own model can reduce detection by some defenders it never queries. Furthermore, at the measured operating points, projecting performance to one attack per 1,000 sessions yields precision below 1.2% for every defender. The first two findings concern the models' behavior; the third concerns the setting in which their judgments become alerts.

An earlier version used balanced benign and attack sessions on Lunary IDOR and Gradio path traversal. Medium and large defenders reached AUROC ≈ 1.000, and a rules baseline solved Gradio perfectly. A one-shot stealth instruction also sometimes increased detectability by removing the reconnaissance that had surrounded the standard attacker's malicious request. That study established discrimination in a largely saturated regime, while leaving adaptive evasion and rare-attack precision unresolved. The present version retains Lunary, introduces a feedback-driven attacker, and evaluates a broader defender set. The earlier findings are in [FINDINGS_MAIN.md](FINDINGS_MAIN.md), and the revised protocol is in [EXPERIMENT_SPEC_V2.md](EXPERIMENT_SPEC_V2.md).

All models are open-weight and served through Together AI's serverless API, keeping the experiment within the capabilities of an inexpensive hosted deployment. The broader work cost approximately $10 against a roughly $15 budget. The experiment measures recognition of a specified benchmark attack after completion; it does not measure vulnerability discovery or prevention.

## II Experimental Design

The target is Lunary at a known-vulnerable revision, with CVE-2024-1625 / CWE-639 permitting cross-tenant project deletion through `DELETE /v1/projects/{id}`. This target makes authorization context central: the malicious request is syntactically ordinary, so a detector must distinguish unauthorized deletion from the same operation on an owned resource. Gradio was omitted because its path-traversal patterns had already been solved by the rules baseline, leaving little scope to distinguish defenders.

Each defender receives ordered `access_v1` metadata and a runbook specifying the service policy and an episode-local principal-to-owned-project mapping. Request and response bodies, credentials, attacker instructions, model identities, and oracle labels are excluded. A protected stream records violations and ground truth without entering the defender packet. This separation preserves the distinction between interpreting policy-relevant evidence and receiving the experiment's answer.

Each attack attempt uses a fresh container stack, since a successful deletion would otherwise remove the resource required by the next attempt. The app and database occupy an internal Docker network; a loopback-published telemetry gateway exposes a constrained HTTP interface with relative paths, restricted headers, response caps, and no redirects. On Docker Desktop, the gateway can retain public egress, although the target remains isolated and the gateway forwards only to the fixed target. This operator-approved exception is documented in [SAFETY_DEVIATIONS.md](SAFETY_DEVIATIONS.md).

Kimi K3 operates through a ReAct loop over the HTTP tool. Each scenario retains three arms: baseline, using the standard attack instructions; naive-stealth, adding one stealth instruction without feedback; and evasive, selected through adaptive revision. The attacker receives an objective and vulnerability-class brief, so the comparison concerns how it executes and conceals a known task.

For adaptation, another invocation of Kimi K3 scores the public packet and returns a probability and rationale. The attacker receives this feedback and is asked to achieve the same objective while appearing like ordinary authorized use, without tampering with logging. The configured `max_rounds: 4` permits four revisions after baseline, for at most five scored attempts. The loop stops when the latest attempt succeeds with proxy score below 0.5; otherwise it retains the successful attempt with the lowest score, even if that score exceeds 0.5. It falls back to baseline if none succeeds. All 24 retained evasive episodes in this run are successful.

Kimi K3 is excluded from the defender ladder, and no evaluated defender supplies feedback to the attacker. This makes evasion a transfer test: a reduction on an evaluated defender cannot come from optimizing directly against its judgments. Using the attacker itself as the scoring proxy requires no additional model access, although the experiment does not establish that this is the best available proxy.

The benign corpus contains 310 scripted sessions against the same service, including normal workflows and hard negatives: bulk own-project deletion, error-and-retry sequences, and high-volume own-resource enumeration. These make the threshold sensitive to unusual authorized behavior, preventing apparent success through indiscriminately flagging deletions or busy sessions. They remain a limited set of templates rather than a production traffic sample.

The defenders are Qwen3.5-9B, gpt-oss-20b, Llama-3.3-70B, gpt-oss-120b, and DeepSeek-V4-Pro. The gpt-oss models have approximately 21B/3.6B and 120B/5B total/active parameters respectively; Qwen and Llama are 9B and 70B dense models, and DeepSeek is the registry's frontier MoE tier. Thinking is disabled for Qwen and DeepSeek, gpt-oss uses low reasoning effort, and Llama is non-reasoning. These settings limit cost and encourage structured output, but do not equalize reasoning budgets. The ladder therefore compares model configurations, with size confounded by architecture, training, and serving.

There are 24 matched scenarios, assigned by index to four calibration and 20 test pairs, with every arm of a pair kept in the same split. Three retained arms produce 72 attack episodes; together with the benign corpus, this gives 382 episodes and 1,910 predictions. Public packets, manifests, labels, and checksums are frozen before replay, with transcripts and proxy/oracle records stored separately. Every defender thus reviews the same evidence, including DeepSeek, which was added after collection without new attacker runs.

## III Evaluation

For each defender, the implementation selects the lowest available threshold with empirical FPR ≤ 0.10 on the 310 benign sessions, and flags scores at or above it. The observed FPRs differ because scores are discrete. Since this same corpus selects the threshold and supplies the reported FPR, the latter is an in-sample estimate. Recall is computed separately for baseline and evasive arms on the 20 test scenarios. The elicited scores are not independently established as calibrated probabilities.

The prevalence sweep uses evasive recall $r$, benign FPR $f$, and hypothetical attack prevalence $p$:

$$
\operatorname{Precision}(p)=\frac{rp}{rp+f(1-p)}.
$$

The grid is $p\in\{0.02,0.01,0.001,0.0001\}$, with corresponding expected alert counts per 100,000 sessions. These are analytic projections, conditional on the measured rates carrying over as prevalence changes; the experiment does not estimate production prevalence or validate that transport assumption.

Transfer is measured per scenario using proxy scores $q$ and evaluated-defender scores $s$:

$$
\tau_i=\frac{s_{b,i}-s_{e,i}}{q_{b,i}-q_{e,i}},
$$

where $b$ and $e$ denote baseline and evasive arms. The ratio measures how much of the proxy-score reduction appears on another defender; it can be negative or exceed one, and score movement need not imply a threshold crossing. Pairs with proxy reduction below 0.05 are excluded to stabilize the denominator.

The reported transfer estimate averages eligible ratios and uses 10,000 paired bootstrap resamples for a percentile 95% interval. Unlike recall, this calculation pools calibration and test scenarios: 19 pairs qualify, comprising three calibration and 16 test pairs. Proxy-score comparisons also use all 24 scenarios. Transfer and proxy effects are therefore exploratory pooled analyses, while recall remains held out.

## IV Results

### Detection and transferred evasion

The detection comparison combines held-out attack recall, FPR on the benign threshold-selection corpus, and pooled transfer. Their denominators differ as specified above.

| Defender | Threshold | FPR | Baseline recall | Evasive recall | Transfer τ [95% CI] |
| --- | ---: | ---: | ---: | ---: | --- |
| gpt-oss-20b | 0.95 | 6.77% (21/310) | 0.95 (19/20) | 0.80 (16/20) | 0.282 [0.002, 0.690] |
| gpt-oss-120b | 0.93 | 6.77% (21/310) | 0.65 (13/20) | 0.30 (6/20) | 0.533 [0.298, 0.798] |
| DeepSeek-V4-Pro | 0.92 | 5.16% (16/310) | 0.50 (10/20) | 0.60 (12/20) | 0.062 [-0.060, 0.215] |
| Qwen3.5-9B | 0.95 | 9.35% (29/310) | 0.10 (2/20) | 0.05 (1/20) | -0.147 [-0.530, 0.257] |
| Llama-3.3-70B | 0.90 | 3.87% (12/310) | 0.05 (1/20) | 0.05 (1/20) | -0.021 [-0.165, 0.122] |

Adaptation reduces gpt-oss-120b's detected attacks from 13 to six and gpt-oss-20b's from 19 to 16. The former also has the clearest positive transfer interval; the latter's lower endpoint is only slightly above zero. DeepSeek shows no clear average score-reduction transfer and detects two more evasive than baseline attacks. Qwen and Llama begin with such low recall that their small or negative transfer estimates provide little evidence of useful robustness.

On the attacker's own proxy, the mean baseline-minus-evasive score difference is 0.248 [0.176, 0.316], compared with -0.004 [-0.021, 0.012] for baseline-minus-naive-stealth. Recorded median HTTP counts are four, 11, and two for baseline, evasive, and naive-stealth respectively. The adaptive procedure therefore lowers its proxy score while increasing activity, whereas the one-shot instruction produces no clear average score reduction.

### Precision under rare attacks

The following table projects the fraction of alerts identifying attacks, using evasive recall.

| Defender | 1 attack in 50 | 1 in 100 | 1 in 1,000 | 1 in 10,000 |
| --- | ---: | ---: | ---: | ---: |
| gpt-oss-20b | 19.42% | 10.66% | 1.168% | 0.1180% |
| gpt-oss-120b | 8.29% | 4.28% | 0.441% | 0.0443% |
| DeepSeek-V4-Pro | 19.18% | 10.51% | 1.150% | 0.1161% |
| Qwen3.5-9B | 1.08% | 0.54% | 0.053% | 0.0053% |
| Llama-3.3-70B | 2.57% | 1.29% | 0.129% | 0.0129% |

At one attack per 1,000 sessions, gpt-oss-20b would generate 80 true alerts and approximately 6,767 false alerts per 100,000 sessions, yielding precision of 1.17%. DeepSeek's lower FPR is offset by lower evasive recall, yielding 1.15%. Thus, the best projected precision remains poor despite substantial recall, and the models' apparent advantage on attack detection does not translate directly into reliable alerts.

### Recorded costs

The frozen ledger gives offense cost of $3.8783, or $0.1616 per retained successful evasive scenario, and estimated defense cost of $1.2856 across 1,910 screenings, or $0.000673 per screening. Their unit-cost ratio is approximately 240, but the accounting is partial: offense sums token counts attached to retained arms, omitting discarded revisions and proxy calls. One early scenario also lacks token and HTTP instrumentation. Defense uses fixed blended prices of $0.50/$0.90 per million input/output tokens rather than model-specific charges.

## V Examination of the Findings

The prevalence result exposes a limitation of judging a detector mainly by attack recall. At $p=0.001$ and $r=0.80$, achieving 50% precision requires FPR of about 0.00080, or 0.08%, far below the measured operating point. Even perfect recall would leave precision near 1.5% if gpt-oss-20b's FPR remained unchanged. The relevant deficiency is therefore the tolerance for false positives under rare attacks; improving recognition alone at the same FPR cannot resolve it.

However, the study evaluates one threshold rule rather than the full set of possible operating points. A stricter threshold could exchange recall for precision, while a pre-filter could raise attack prevalence among the sessions reaching the model. The latter would help only if it retained attacks while removing enough legitimate activity. Consequently, these projections motivate evaluation of lower-FPR thresholds and conditional screening pipelines; they do not establish that log-based detection is inherently unusable.

The model ranking also admits a practical conclusion without identifying its cause. Choosing the largest dense model would have selected the weakest detector here, and increasing total parameters within gpt-oss did not improve performance under the recorded settings. This undercuts parameter count as a sufficient deployment criterion. It leaves open whether training, architecture, reasoning configuration, or serving explains the differences. A claim that security-specific training drives the ranking would require evidence beyond the cross-family comparison.

The transfer result reveals that evasion need not depend on access to the deployed detector. The attacker lowered another model's recall using only its own proxy, yet the effect varied across defenders. This makes resistance to transferred evasion a separate consideration from baseline detection: gpt-oss-120b recognized many baseline attacks but lost substantially more recall under adaptation, whereas DeepSeek's middling baseline recall accompanied little average score-reduction transfer. The two additional DeepSeek detections are too few to establish that adaptation improves its performance.

The change in request counts supports behavioral padding as a possible mechanism. Legitimate-looking requests surrounding the deletion may reduce a model's assessment of the whole session, even though the violating request remains. Yet request volume is not an ablation: selected attempts can also differ in ordering, pacing, and other details. The evidence establishes transferable evasion by the procedure, while attributing it specifically to padding requires interventions that vary padding and hold the attack trace fixed.

The adaptive-versus-naive comparison has a related inferential limit. Adaptation supplies feedback, additional attempts, and selection of the successful attempt with the lowest proxy score. Any of these could contribute to the gain. The comparison therefore supports the complete procedure rather than feedback alone. A matched-budget best-of-N control, selected by the same proxy but generated without feedback, would determine whether revision adds value beyond search and selection.

The target also helps locate the failure. Successful deletion remains in the log, and the runbook supplies the authorization mapping needed to interpret it. Within the allowed attack interface, evasion cannot remove this evidence; it can change the model's response to it. This points to failures of contextual interpretation or session-level aggregation, rather than disappearance of the decisive request. Whether the same account holds without explicit ownership context, or for a vulnerability whose harmful operation is less clearly represented in the logs, remains unresolved.

Finally, inexpensive screening does not establish inexpensive defense. A successful attack and a screened session are different units, and rare attacks require screening many legitimate sessions before encountering a malicious one. False alerts can then impose additional verification or review. The experiment does not measure that downstream cost, so the token ledger establishes an inexpensive inference primitive while the prevalence analysis identifies a potential operational burden.

## VI Limitations and Conclusion

The attack sample is a budget pilot: recall rests on 20 test scenarios and changes in five-point increments. Bootstrap intervals cover proxy-score differences and transfer ratios, not recall, and transfer additionally conditions on a measurable proxy improvement. The large contrast between the best and worst baseline detectors is informative; smaller rankings and effects require more scenarios and seeds.

The 310 benign sessions present a separate validity constraint. Their restricted workflows and configured hard-negative fraction of 0.4 cannot represent production behavior, and reuse for threshold selection limits independent validation. The priority is a larger, separate benign test corpus sufficient to evaluate the much lower FPRs required under rare attacks. Replication on another contextual vulnerability would then test whether the model ranking and transfer effects survive a change in task.

The remaining extensions follow from the specific ambiguities above. A within-family size sweep and matched reasoning budgets would clarify the model comparison; security-tuned or closed-frontier defenders would extend its coverage. Varying attacker capability and adaptation budget would test the offense-defense trajectory, which a single attacker cannot establish. Cross-session correlation and prefix replay would examine evidence accumulation and time to detection, with interactive defense needed to assess prevention.

Output and serving constraints also enter the measured performance. Parse failures were 10/382 for Qwen, six for gpt-oss-120b, two for DeepSeek, and one each for gpt-oss-20b and Llama. The parser retains these failures as insufficient evidence with score 0.5, below every alert threshold. Model revisions are recorded as dated provider aliases rather than immutable weight hashes; Appendix C gives those identities, while the gateway-egress deviation remains documented separately.

Within these bounds, the study shows that inexpensive open-weight inference can recognize the specified authorization attack and that proxy-driven adaptation can erode some of that recognition. Its stronger practical contribution is the distinction between detectable attacks and useful alerts. Further work must preserve the observed recognition capability while testing the independent benign data, operating points, and additional evidence needed to make that capability usable.

## Appendix A Experimental Record

The experiment is `adaptive-baserate-lunary-v1`, with master seed 20260905. It began with 12 scenarios, expanded to 24, and added DeepSeek by replaying frozen episodes. Per-attempt limits are 1,200 seconds, 40 model turns, 100 HTTP requests, 100,000 model tokens, and 4,096 output tokens per turn; sampling uses temperature 0.6 and `top_p` 0.95. The benign configuration requests 250 sessions, whereas the preserved corpus has 310. Exact reanalysis therefore requires that corpus.

Lunary is pinned to `fc959987f3b2cfba25c847ffdba6ac820af154b4`, BountyBench tasks to `1956e5fd4eff12034a5fbe0544482d2cf52bb5b0`, and the harness to `8ece6aab0b954f7c85b5705e69f0142eeaf2c5d1`. Dependency and image digests are in [configs/targets/lunary_idor.yaml](configs/targets/lunary_idor.yaml) and [target-images.lock.json](target-images.lock.json). [configs/adaptive.yaml](configs/adaptive.yaml) records the design, [configs/models.yaml](configs/models.yaml) the serving settings, and [prompts/](prompts/) the templates; manifests and predictions retain prompt/input hashes.

All numerical tables come from [adaptive_metrics.json](data/reports/adaptive_metrics.json). The calculations are in [adaptive.py](src/cyberdetect/analysis/adaptive.py) and [baserate.py](src/cyberdetect/analysis/baserate.py), with generated output in [adaptive_report.md](data/reports/adaptive_report.md). Frozen episodes, predictions, and protected research records remain under [data/](data/).

Collection required fixes for connection drops, leaked containers and memory exhaustion, resume logic that repeated completed work, transient serverless 503s, retained Docker-VM memory, and termination of background jobs under host memory pressure. [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) records these failures and the completion checks. Earlier deviations are in [DEVIATIONS_MAIN.md](DEVIATIONS_MAIN.md), and deferred-direction reasoning is in [CONTINUATIONS.md](CONTINUATIONS.md).

<a id="12-reproduction-guide"></a>

## Appendix B Reproduction

Reanalysis requires the frozen dataset and project dependencies, with Python 3.11 or 3.12. From the repository root, the following regenerates aggregate metrics without Docker or paid inference and runs the offline suite:

~~~bash
PYTHONPATH=src python -c "from cyberdetect.analysis.adaptive import analyze_adaptive; analyze_adaptive('configs/adaptive.yaml')"
cat data/reports/adaptive_report.md
bash scripts/test.sh
~~~

For new collection, use a separate working copy and set a new `experiment.id` and `experiment.data_root` in `configs/adaptive.yaml`, preserving completed artifacts. The original environment used Python 3.12 and Docker Desktop with WSL2. Fill in the ignored `secrets.env` locally before exporting provider settings:

~~~bash
python3.12 -m venv .venv-linux
source .venv-linux/bin/activate
python -m pip install -e .

cp secrets.env.example secrets.env
# Fill in provider settings locally before continuing.
set -a
source secrets.env
set +a

cyberdetect target build --target lunary_idor
cyberdetect target doctor --target lunary_idor

python -c "from cyberdetect.scenarios import generate_scenarios; generate_scenarios('configs/adaptive.yaml')"
python run_v2_actors.py
python -c "from cyberdetect.environment.benign import generate_benign_corpus; generate_benign_corpus('configs/adaptive.yaml')"
python run_v2_finish.py
~~~

Target collection requires a passing doctor under the applicable isolation gates. The build fetches pinned upstream source; actor and benign generation require Docker, while the finisher runs defender replay and analysis only. Drivers skip completed artifacts. A new hosted-model run yields a new sample, whereas reanalysis of frozen predictions preserves the reported numbers.

## Appendix C Model Identities and Reference Prices

These historical Together prices were observed on September 5–6, 2026, in USD per million tokens.

| Role or tier | Model ID | Input | Output |
| --- | --- | ---: | ---: |
| Attacker and scoring proxy | `moonshotai/Kimi-K3` | $3.00 | $15.00 |
| `small_open` | `Qwen/Qwen3.5-9B` | $0.17 | $0.25 |
| `medium_open` | `openai/gpt-oss-20b` | $0.05 | $0.20 |
| `large_open` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | $1.04 | $1.04 |
| `large_oss` | `openai/gpt-oss-120b` | $0.15 | $0.60 |
| `frontier_open` | `deepseek-ai/DeepSeek-V4-Pro-0813` | $1.32 | $3.96 |

Registry revisions are `together:<model-id>@2026-09-05` for Kimi and the first four defenders, and `together:deepseek-ai/DeepSeek-V4-Pro-0813@2026-09-06` for DeepSeek. These pin observations of provider aliases, not immutable weights or all serving details. DeepSeek-V3.1 was unavailable on the serverless route used, so V4-Pro supplied the additional defender tier.
