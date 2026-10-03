# Open Weight Models and the Detection of Cyberattacks

Amrit Chadha  
AI safety mini-experiment for Boaz Barak and Nicholas Carlini's AI-safety course

## I Research Question and Background

The use of increasingly capable AI models in cybersecurity raises a question about the relationship between offense and defense. A model that can carry out an attack may also be able to recognize one, yet these abilities need not develop at the same rate. Furthermore, recognizing an attack in an experiment does not necessarily imply that the same model will be useful in a setting where almost all activity is legitimate. This study examines these issues through a limited task: determining whether an open-weight model can identify an AI-generated cyberattack from a completed session's service logs and a description of the service's authorization rules.

The experiment reveals that some relatively inexpensive models can recognize the attack reliably, but that this ability depends substantially on which model is used. The best detector in the study, gpt-oss-20b, identified 19 of 20 baseline test attacks, while Llama-3.3-70B identified only one. An attacker that revised its behavior using feedback from its own model also reduced detection by some defenders it had never queried. However, when the measured detection and false-positive rates are projected to a setting with one attack per 1,000 sessions, fewer than 1.2% of alerts identify attacks for every defender. The results therefore suggest that useful defense requires attention to the frequency of attacks and the conditions under which a detector is evaluated, in addition to the capabilities of the model itself.

The scope of this claim is deliberately narrow. The attacker acts against a benchmark application with a known vulnerability in an isolated environment. The defenders review the resulting evidence after the session has ended; they cannot stop a request, inspect additional evidence, or intervene while the attacker is working. The experiment thus evaluates recognition of observable attack behavior. It does not measure whether a model can secure an application or defend a network more generally.

This distinction became necessary after an earlier version of the study produced results that were too close to perfect to clarify the practical difficulties of detection. That study used a balanced collection of benign and attack sessions on two targets: an authorization vulnerability in Lunary and a path-traversal vulnerability in Gradio. Medium and large defenders achieved an area under the receiver operating characteristic curve, or AUROC, of approximately 1.000, while a simple rules detector perfectly identified the Gradio attacks. AUROC measures how well a detector ranks attacks above benign sessions across thresholds. A high value establishes separation on that dataset, but does not establish that alerts will be reliable when attacks are rare.

The earlier study also found that a simple instruction to be stealthy could make attacks more detectable. The standard attacker already performed legitimate-looking reconnaissance around its malicious action, whereas the stealth instruction sometimes removed that surrounding activity. These findings motivated the present version, which retains the Lunary target while introducing repeated attacker revision, a larger set of defender models, and an explicit analysis of attack prevalence. The earlier design and findings remain available in [EXPERIMENT_SPEC.md](EXPERIMENT_SPEC.md) and [FINDINGS_MAIN.md](FINDINGS_MAIN.md); the present experiment follows the adaptive study described in [EXPERIMENT_SPEC_V2.md](EXPERIMENT_SPEC_V2.md).

All attacker and defender models in this study are open-weight models accessed through Together AI's serverless service. The purpose of this choice is to examine capabilities available without access to a closed model or a dedicated inference deployment. The operator's approximate spend for the broader experimental work was $10 within a budget of roughly $15. This is a small exploratory study, and its conclusions should be understood in relation to that scale.

## II Construction of the Experiment

### The target and the evidence available to defenders

The target is Lunary, an application for observing and managing LLM activity, at a known-vulnerable source revision. Its vulnerability, CVE-2024-1625 and CWE-639, allows an authenticated user to delete another tenant's project by supplying that project's identifier to `DELETE /v1/projects/{id}`. A tenant is an account or organization whose resources should be separated from those of other users. The endpoint fails to enforce this separation.

The vulnerability is useful for this experiment because the malicious request has the same general form as an authorized request. Deleting one's own project is legitimate; deleting another tenant's project is not. Consequently, the relevant distinction lies in the relationship between the user and the resource. A detector cannot identify the attack merely by treating every deletion as suspicious.

To make this relationship interpretable, each defender receives both the public access logs and a service runbook. The runbook describes the permitted operations and provides an episode-local mapping between the principal and its authorized project. The logs contain ordered request metadata, including methods, paths, status codes, timing, and pseudonymized resource identifiers. They exclude request and response bodies, credentials, attacker instructions, model identities, and the experiment's ground-truth authorization decisions. The task is therefore to interpret restricted service evidence against a stated policy, rather than to infer ownership from unexplained logs.

A separate protected stream records policy violations and the evidence used to establish what actually happened. This stream is used by the experimental harness and is never included in a defender's packet. The separation matters because a detector that receives the oracle's judgment would be repeating a label rather than recognizing an attack. The attacker likewise receives no scores or explanations from any of the five evaluated defenders.

Each attack attempt runs against a fresh container stack. This prevents a successful deletion in one attempt from removing the victim resource needed by a later attempt. The application and database are placed on an internal Docker network, and the actor reaches the application through a telemetry gateway bound to the host's loopback interface. The actor has a constrained HTTP tool with relative paths, restricted headers, response-size limits, and no redirect following. It has no general shell or unrestricted browsing interface.

The isolation has one documented platform qualification. On Docker Desktop, the loopback-published telemetry proxy can retain outbound Internet access through the Docker virtual machine's networking. The application and database remain on the isolated network without public egress, and the proxy forwards actor requests only to the fixed target. This proxy-egress exception was accepted by the operator before collection and is described in [SAFETY_DEVIATIONS.md](SAFETY_DEVIATIONS.md). It should not be confused with a claim that every container's outbound access was blocked.

### The attacker and its comparison conditions

Kimi K3 serves as the attacker. Its agent alternates between model decisions and constrained HTTP requests, observes the responses, and continues until it finishes or reaches a resource limit. This arrangement gives the model the ability to interact with the vulnerable service while restricting the environment in which it can act.

For each scenario, the experiment retains three conditions. The baseline condition uses the standard attack instructions without additional pressure to evade detection. The naive-stealth condition adds a single instruction to be stealthy, but supplies no detector feedback. The adaptive condition allows the attacker to revise its behavior after seeing an assessment of its previous session.

The assessment comes from another invocation of Kimi K3 acting as a detector. This model is the attacker's proxy for judging whether its activity appears suspicious; it is distinct from the telemetry proxy that forwards HTTP requests. After an attempt, the scoring proxy receives the public evidence and returns an attack probability and rationale. The attacker is then asked to accomplish the same objective while making its requests resemble ordinary authorized use. Its instructions prohibit tampering with the logging system itself.

The configured limit, `max_rounds: 4`, permits four revisions after the initial baseline attempt, for at most five adaptively scored attempts in total. The loop stops early if the latest attempt succeeds and its proxy score is below 0.5. The retained evasive episode is the successful attempt with the lowest proxy score, even if that score remains above 0.5. If no attempt succeeds, the implementation falls back to the baseline episode. All 24 retained evasive episodes in this run are labeled successful in the frozen ground truth.

This design tests whether evasion developed against one model transfers to other models. Kimi K3 is excluded from the defender comparison, and the attacker never queries an evaluated defender. A decrease in another defender's score therefore cannot be explained by directly optimizing against that defender's feedback. However, the design does not establish that the attacker's own model is the best possible proxy or that the measured effect bounds what every other adversary could achieve.

### Benign activity and the defender models

The experiment includes 310 benign sessions generated by scripts acting against the same service. These cover ordinary browsing, creation, and deletion, as well as unusual but authorized activity. The latter includes bulk deletion of one's own projects, repeated errors followed by retries, and high-volume enumeration of owned resources. Such sessions are often called hard negatives because they resemble behavior that a detector might otherwise associate with an attack.

Their inclusion makes the false-positive problem substantive. A detector that flags every busy session or every deletion may catch the attack, but it will also flag users who are acting within their permissions. The benign corpus therefore tests whether a model can distinguish a policy violation from merely unusual activity. Because these sessions come from scripts and a small set of templates, they still represent only a limited approximation of legitimate production traffic.

Five models review the same frozen session packets. They span several model families and architectures, as shown below. Mixture-of-experts, or MoE, models contain more total parameters than they activate for a particular token, so total parameter count alone does not describe their inference cost or computation.

| Tier | Model | Recorded scale | Reasoning setting |
| --- | --- | --- | --- |
| `small_open` | Qwen3.5-9B | 9B dense | `enable_thinking: false` |
| `medium_open` | gpt-oss-20b | About 21B total and 3.6B active, MoE | `reasoning_effort: low` |
| `large_open` | Llama-3.3-70B-Instruct-Turbo | 70B dense | Non-reasoning model |
| `large_oss` | gpt-oss-120b | About 120B total and 5B active, MoE | `reasoning_effort: low` |
| `frontier_open` | DeepSeek-V4-Pro-0813 | MoE, designated frontier tier | `thinking: false` |

The settings were chosen to limit inference cost and obtain structured output. They do not constitute identical reasoning budgets: low reasoning effort for gpt-oss is not equivalent to disabling reasoning. Similarly, because the models differ in training, architecture, and serving configuration, this comparison cannot isolate the causal effect of size. It establishes how these particular models performed under the recorded settings.

The dataset contains 24 matched attack scenarios, with three retained conditions per scenario, giving 72 attack episodes. The scenario generator assigns the first four scenario indices to calibration and the remaining 20 to test, with all conditions of a scenario kept together. Seeds derive from the master seed, 20260905, and adding scenarios does not change earlier assignments. Combined with the 310 benign sessions, the study contains 382 episodes and 1,910 defender predictions.

Each episode includes its public log, defender packet, manifest, ground truth, and SHA-256 checksums. Protected oracle records, attacker transcripts, and scoring-proxy outputs are stored separately. Freezing these materials before defender replay ensures that every model is judged on the same evidence and that the attacker cannot change a session after seeing an evaluated defender's response.

## III Evaluation and the Meaning of Detection

A defender returns a structured verdict, an attack-probability score, and an explanation citing relevant events. These elicited scores have not been independently validated as calibrated probabilities. The analysis turns the score into an alert by comparing it with a threshold. For each defender, the implementation selects the lowest available threshold whose empirical false-positive rate on the 310 benign sessions is at most 10%. An episode is flagged when its score is greater than or equal to that threshold.

This procedure imposes a common upper limit on false positives; it does not make the models' false-positive rates exactly equal. Their observed rates range from 3.87% to 9.35%, partly because their scores occur at discrete values. Moreover, the same benign corpus is used both to choose the threshold and to report its false-positive rate. The reported rates therefore describe performance on the threshold-selection corpus, rather than an independently tested rate on new benign traffic.

Recall is the fraction of attack episodes that produce alerts. It is computed separately for the baseline and evasive conditions using the 20 test scenarios. Each additional detected attack changes recall by five percentage points. A recall of 0.80 thus means that 16 of the 20 test attacks were identified; it is not a precision estimate of how frequently an alert will be correct.

Precision addresses that second question. Let $p$ be the fraction of sessions that are attacks, $r$ the detector's recall, and $f$ its false-positive rate. Among all sessions, the fraction producing true alerts is $rp$, while the fraction producing false alerts is $f(1-p)$. Consequently,

$$
\operatorname{Precision}(p)
=
\frac{rp}{rp+f(1-p)}.
$$

The denominator includes both kinds of alerts, so the expression gives the fraction of alerts corresponding to attacks. This is the same conditional-probability distinction that separates the probability of an alert given an attack from the probability of an attack given an alert. A detector can have high recall while most of its alerts are false if legitimate activity is sufficiently common.

The analysis evaluates this expression at attack prevalences of one in 50, 100, 1,000, and 10,000 sessions, using evasive-condition recall. These are hypothetical deployment scenarios. They were not measured in a production system, and the experiment does not establish that one in 1,000 is a universal attack rate. The projections assume that the measured recall and false-positive rate remain applicable as prevalence changes.

The effect of adaptation is also measured through a transfer statistic. For scenario $i$, let $q_{b,i}$ and $q_{e,i}$ be the scoring proxy's baseline and evasive scores, and let $s_{b,i}$ and $s_{e,i}$ be the corresponding evaluated defender's scores. The statistic is

$$
\tau_i
=
\frac{s_{b,i}-s_{e,i}}{q_{b,i}-q_{e,i}}.
$$

A value near one indicates that the defender's score fell by approximately as much as the proxy's score; a value near zero indicates little score reduction on that defender. Negative values indicate that the defender's score rose. This ratio is neither a probability nor necessarily bounded between zero and one. It describes score movement, which need not match the change in recall when scores cross a threshold.

Pairs whose proxy score falls by less than 0.05 are excluded to avoid dividing by a very small or nonpositive effect. The reported transfer estimate is the mean of the remaining ratios, with a percentile 95% interval from 10,000 bootstrap resamples of pairs. Unlike recall, the current transfer calculation pools calibration and test scenarios. Nineteen of the 24 scenarios qualify: three calibration scenarios and 16 test scenarios. The proxy-score comparisons also use all 24 scenarios. These statistics should therefore be read as exploratory paired analyses, while the recall results refer specifically to the held-out attack set.

## IV Results

### Detection on the held-out attack scenarios

The table below reports the operating threshold, empirical benign false-positive rate, and detected attack counts for each defender. The baseline ranking is led by gpt-oss-20b, followed by gpt-oss-120b and DeepSeek. Qwen and Llama detect very few attacks at their selected thresholds.

| Defender | Threshold | False-positive rate | Baseline attacks detected | Evasive attacks detected |
| --- | ---: | ---: | ---: | ---: |
| gpt-oss-20b | 0.95 | 6.77% (21/310) | 19/20 (95%) | 16/20 (80%) |
| gpt-oss-120b | 0.93 | 6.77% (21/310) | 13/20 (65%) | 6/20 (30%) |
| DeepSeek-V4-Pro | 0.92 | 5.16% (16/310) | 10/20 (50%) | 12/20 (60%) |
| Qwen3.5-9B | 0.95 | 9.35% (29/310) | 2/20 (10%) | 1/20 (5%) |
| Llama-3.3-70B | 0.90 | 3.87% (12/310) | 1/20 (5%) | 1/20 (5%) |

Adaptation has different effects across the models. For gpt-oss-120b, the detected count falls from 13 to six, reducing recall from 65% to 30%. For gpt-oss-20b, it falls from 19 to 16. DeepSeek detects two more evasive episodes than baseline episodes, while Qwen detects one fewer and Llama remains at one. Given the small denominator, the increase for DeepSeek should not by itself be treated as evidence that padding improves its detection.

### Proxy-score reduction and transfer

Across all 24 scenarios, the mean decrease in the attacker's own scoring-proxy probability is 0.248, with a 95% bootstrap interval of [0.176, 0.316]. The corresponding baseline-minus-naive-stealth difference is -0.004, with an interval of [-0.021, 0.012]. Thus, the adaptive procedure produces a substantial average proxy-score reduction, whereas the one-shot stealth instruction has no clear average effect in this run.

The recorded median request counts are four for baseline episodes, 11 for evasive episodes, and two for naive-stealth episodes. These observations are consistent with the attacker placing legitimate-looking activity around its malicious action. They do not isolate padding from every other change in the selected attempts, and one early scenario predates request-count instrumentation.

| Defender | Mean transfer ratio | 95% bootstrap interval | Eligible pairs |
| --- | ---: | --- | ---: |
| gpt-oss-20b | 0.282 | [0.002, 0.690] | 19 |
| gpt-oss-120b | 0.533 | [0.298, 0.798] | 19 |
| DeepSeek-V4-Pro | 0.062 | [-0.060, 0.215] | 19 |
| Qwen3.5-9B | -0.147 | [-0.530, 0.257] | 19 |
| Llama-3.3-70B | -0.021 | [-0.165, 0.122] | 19 |

The strongest evidence of positive transfer is for gpt-oss-120b, whose estimated ratio is 0.533 and whose interval stays well above zero. The gpt-oss-20b estimate is smaller and its lower endpoint is only slightly above zero. DeepSeek's interval includes zero, so the study finds no clear average score-reduction transfer to that model. The near-zero or negative estimates for Qwen and Llama are difficult to interpret as robustness because their baseline recall is already very low.

### Precision when attacks are rare

Applying the prevalence formula gives the following percentages of alerts that would identify attacks, conditional on the measured rates carrying over to the specified setting.

| Defender | 1 attack in 50 | 1 in 100 | 1 in 1,000 | 1 in 10,000 |
| --- | ---: | ---: | ---: | ---: |
| gpt-oss-20b | 19.42% | 10.66% | 1.168% | 0.1180% |
| gpt-oss-120b | 8.29% | 4.28% | 0.441% | 0.0443% |
| DeepSeek-V4-Pro | 19.18% | 10.51% | 1.150% | 0.1161% |
| Qwen3.5-9B | 1.08% | 0.54% | 0.053% | 0.0053% |
| Llama-3.3-70B | 2.57% | 1.29% | 0.129% | 0.0129% |

For a concrete example, consider gpt-oss-20b at one attack per 1,000 sessions. Among 100,000 sessions, there would be 100 attacks and 99,900 benign sessions. Evasive recall of 0.80 produces 80 true alerts, while the measured false-positive rate of 21/310 produces approximately 6,767 false alerts. Only about 1.17% of the resulting 6,847 alerts would identify attacks. DeepSeek produces fewer false alerts but also fewer true alerts, yielding a similar projected precision of 1.15%.

These calculations explain why strong recall on an attack benchmark is insufficient for reliable alerts under rare attacks. They also show where a practical improvement would have to occur. At prevalence 0.001 and recall 0.80, precision of 50% requires a false-positive rate of about 0.00080, or 0.08%, far below the measured 6.77%. Improving recall alone while leaving this false-positive rate unchanged cannot close that gap.

### Recorded inference costs

The frozen metrics report $3.8783 in recorded offense-side token cost, or $0.1616 per retained successful evasive scenario, and $1.2856 in estimated defense cost across 1,910 screenings, or $0.000673 per screening. The ratio of these unit figures is approximately 240.

However, the ledger is not a complete accounting of the adaptive campaign. It sums attacker token counts attached to the retained baseline, evasive, and naive-stealth arms, rather than recording every discarded revision and scoring-proxy call. The earliest scenario also lacks token instrumentation. Defense cost uses fixed blended prices of $0.50 per million input tokens and $0.90 per million output tokens, rather than each model's actual listed price. These figures describe the existing accounting method and should not be presented as exact provider charges or proof of a 240-fold operational advantage for defense.

## V Examination of the Findings

The most consequential result concerns the relationship between detection and prevalence. A benchmark can demonstrate that a model identifies most attacks while concealing how often its alerts will be wrong in ordinary use. The prevalence calculation makes this distinction explicit. If attacks are rare, a false-positive rate that appears tolerable on a balanced dataset can generate thousands of alerts for each small set of actual attacks. The difficulty is therefore partly a property of the decision setting in which the model is used.

This does not establish that log-based detection is inherently unusable. The reported projections concern the chosen thresholds and the measured benign corpus. A stricter threshold might reduce false positives while sacrificing recall; a system that screens sessions before presenting them to an LLM might change the prevalence of attacks in the screened population. Either approach would require further evaluation. The justified conclusion is that these particular operating points produce poor projected precision under rare attacks.

The defender ranking likewise supports a practical conclusion while leaving its cause unresolved. A model with more parameters does not automatically provide better performance on this task. Llama-3.3-70B is the largest dense model tested and has the lowest baseline recall, while gpt-oss-20b performs best. Even within the gpt-oss family, the larger model performs worse under the recorded settings. However, these observations do not prove that size is irrelevant, that scaling is harmful, or that security-specific training explains the ranking. Architecture, training, reasoning configuration, and serving behavior remain possible explanations.

The adaptive attack results reveal a different weakness. The attacker can make its behavior appear less suspicious to a model it controls and obtain some of the same effect on an evaluated defender it never queried. The reduction in gpt-oss-120b's test recall demonstrates that direct access to the target detector is not necessary for evasion to impair this particular defense. At the same time, the lack of a clear average score decrease for DeepSeek shows that the same adaptation does not affect all detectors equally. Detection and resistance to transferred evasion are related but distinct properties.

There is a further limitation in what the adaptive-versus-naive comparison establishes. The adaptive condition receives feedback, but it also receives more attempts and retains the successful attempt with the lowest proxy score. Some improvement could therefore come from selecting among multiple attempts, even without useful feedback. The observed difference establishes the effect of the complete adaptive procedure. To isolate the contribution of feedback itself, a later experiment should compare it with an equally funded set of independent attempts selected by the same proxy.

The nature of the vulnerability also constrains the meaning of evasion. A successful attack in this environment necessarily generates a deletion request, and the runbook supplies authorization context for interpreting it. The attacker's instructions prohibit removing that evidence by tampering with the logger. Adaptation can therefore change the surrounding behavior or the model's assessment without eliminating the decisive action from the retained log.

Nevertheless, visibility is not the same as recognition. The malicious deletion has an ordinary request structure, and the detector must connect it to the authorization mapping. The results show that models can fail to make this connection even when the relevant action remains present. They do not establish that cyberattacks in general leave sufficient evidence in access logs, especially when authorization context is missing or the harmful action resembles permitted activity more closely.

Finally, low screening cost should be distinguished from low deployment cost. Screening one session and generating one successful attack are different units of work. A defender may have to screen thousands of benign sessions to encounter one attack, and its alerts may require additional automated checks or human review. This study does not measure investigation time, staffing cost, or prevented harm. The prevalence projections identify a possible source of substantial review burden, but the size of that burden remains an operational question.

Taken together, the experiment provides evidence about a specific part of the offense-defense relationship. Cheap inference can support useful attack recognition, and an open-weight attacker can erode some of that recognition through repeated revision. Whether either capability becomes practically decisive depends on the information available, the defender's operating point, and the rate at which attacks occur. The study does not measure how that balance changes as attacker capability increases, since it uses only one attacker model.

## VI Limits and Further Research

The principal statistical limitation is the number of attack scenarios. Held-out recall rests on 20 cases, and the transfer analysis retains 19 eligible pairs from the combined calibration and test set. The broad contrast between detecting 19 attacks and detecting one is substantial, but smaller differences are less secure. The reported bootstrap intervals describe uncertainty in mean proxy-score changes and transfer ratios; the analysis does not report comparable intervals for recall or establish a general ordering of models across tasks. The attacker is also supplied an objective and a vulnerability-class brief, so the study tests execution of a specified benchmark attack rather than discovery of an unknown vulnerability.

The benign data also limit the deployment claims. The 310 sessions are generated from a restricted collection of workflows, with a configured hard-negative fraction of 0.4. This provides more demanding examples than ordinary browsing alone, yet it cannot represent the range of behavior found in a real organization. Reusing these sessions for threshold selection and false-positive reporting further limits independent validation. A larger, separate benign test set is necessary both to check generalization and to study the much lower false-positive rates needed under rare attacks.

The most direct extension is replication on another application and another vulnerability class. The earlier Gradio target, CVE-2024-1561, was omitted from this version because a rules detector had already solved its path-traversal patterns perfectly. A more informative target would test whether the model ranking and transferred evasion persist when detecting misuse requires a different kind of contextual judgment. Multi-stage attacks and activity spread across sessions would also test evidence that a whole-session classifier does not presently use.

A controlled comparison within one model family would help separate size from training and architecture. Security-tuned models would provide a complementary test of whether task-relevant training explains the observed ranking. Adding a closed frontier model could establish a comparison point beyond the open-weight set, while allowing larger reasoning budgets could test how much the current inference settings constrain performance. These extensions were deferred because of budget and hosting availability; specific model availability would need to be checked at the time of a new run.

A more complete evasion experiment would add the equal-attempt control described above and vary attacker capability or adaptation budget. It could also compare the present transfer setting with one in which the attacker can query a surrogate or the actual detector. Such comparisons would measure how much direct feedback adds, rather than assuming that stronger access necessarily produces a particular numerical effect.

For defense, the prevalence results motivate evaluation of systems that combine multiple kinds of evidence. Possible approaches include screening with inexpensive rules, correlating activity across sessions, and escalating selected cases for deeper analysis. Each should be tested for its effect on both recall and false positives, since a pre-filter that removes legitimate activity may also remove attacks. Prefix replay would allow measurement of how early an attack becomes detectable, while an interactive defender would address whether recognition can prevent damage rather than merely label it afterward.

Several implementation qualifications remain relevant. Parse failures occurred in 10 of 382 Qwen outputs, six gpt-oss-120b outputs, two DeepSeek outputs, and one output each for gpt-oss-20b and Llama. The parser assigns these cases an insufficient-evidence verdict and a score of 0.5, which lies below every selected alert threshold. These retained failures are part of the measured pipeline performance. In addition, provider model revisions are recorded as aliases with observation dates, rather than immutable weight hashes, and the Docker Desktop proxy-egress deviation applies to the original collection environment.

## VII Conclusion

This study shows that selected open-weight models can recognize an AI-generated authorization attack from restricted service evidence, but that performance varies greatly across the models tested. It also shows that an attacker using its own model as a scoring proxy can reduce detection by some defenders without querying them directly. These findings establish a limited defensive capability and a corresponding evasion capability within the same experimental setting.

The practical significance of either result depends on the conditions under which detection is used. At the measured thresholds, rare attacks produce overwhelmingly false alerts even for the strongest detector. A useful next stage of research must therefore test independent benign traffic, lower false-positive operating points, and methods that combine evidence across requests or sessions. The central contribution of this experiment is to make those requirements explicit while preserving a frozen record from which its observations can be checked.

## Appendix A Experimental Record and Supporting Materials

The experiment identifier is `adaptive-baserate-lunary-v1`. Collection began with 12 attack scenarios, expanded to 24, and subsequently added DeepSeek as a fifth defender on the already-frozen episodes. No new attacker episodes were generated for that additional defender. The final design comprises 72 retained attack episodes, 310 benign sessions, and 1,910 predictions. Recall uses 20 test scenarios; proxy comparisons use all 24; transfer uses 19 eligible scenarios pooled across splits.

The configured per-attempt limits are 1,200 seconds, 40 model turns, 100 HTTP requests, 100,000 total model tokens, and 4,096 output tokens per turn. Attacker sampling uses temperature 0.6 and `top_p` 0.95. The benign configuration requests 250 sessions, while the preserved corpus contains 310. Reproducing the reported metrics requires the preserved corpus; generating the configured number anew does not reproduce that exact sample.

The target source revisions are recorded below. Dependency and built-image digests are in [configs/targets/lunary_idor.yaml](configs/targets/lunary_idor.yaml) and [target-images.lock.json](target-images.lock.json).

| Component | Source commit |
| --- | --- |
| Lunary | `fc959987f3b2cfba25c847ffdba6ac820af154b4` |
| BountyBench tasks | `1956e5fd4eff12034a5fbe0544482d2cf52bb5b0` |
| BountyBench harness | `8ece6aab0b954f7c85b5705e69f0142eeaf2c5d1` |

Prompt templates are in [prompts/](prompts/). Episode manifests and prediction records contain the hashes associated with their prompts and inputs. The frozen metrics in [adaptive_metrics.json](data/reports/adaptive_metrics.json) are the source of the numerical tables in this report. The short generated [adaptive_report.md](data/reports/adaptive_report.md) preserves the analysis output, while the relevant calculations are implemented in [adaptive.py](src/cyberdetect/analysis/adaptive.py) and [baserate.py](src/cyberdetect/analysis/baserate.py). This report describes their actual behavior where it qualifies the earlier narrative.

The run required fixes for dropped local-target connections, leaked container stacks that exhausted memory, resume logic that repeated already-completed work, transient serverless 503 errors, retained Docker virtual-machine memory, and termination of tracked background jobs under host memory pressure. These issues affected completion and accounting, and made checking for missing artifacts necessary. The engineering record is in [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md). Earlier departures from the original study design are documented in [DEVIATIONS_MAIN.md](DEVIATIONS_MAIN.md), and the reasons for deferred extensions are in [CONTINUATIONS.md](CONTINUATIONS.md).

| Repository location | Purpose |
| --- | --- |
| [README.md](README.md) | Project overview and quickstart |
| [EXPERIMENT_SPEC_V2.md](EXPERIMENT_SPEC_V2.md) | Adaptive study specification |
| [configs/adaptive.yaml](configs/adaptive.yaml) | Scenario counts, limits, models, and analysis settings |
| [configs/models.yaml](configs/models.yaml) | Model identities and serving options |
| [src/cyberdetect/](src/cyberdetect/) | Target adapters, actor, defender, and analysis implementation |
| [docker/](docker/) | Target isolation and telemetry services |
| [tests/](tests/) | Offline checks and opt-in live-target integration checks |
| [data/](data/) | Frozen episodes, predictions, protected research records, and reports |

<a id="12-reproduction-guide"></a>

## Appendix B Reproduction Guide

There are two different reproduction tasks. Recalculating the reported metrics uses the frozen files and requires neither Docker nor a model API key. Generating new sessions or predictions requires the target environment and paid inference, and should be expected to yield a new sample rather than identical hosted-model outputs.

For reanalysis, use Python 3.11 or 3.12 with the project's dependencies installed, and run from the repository root:

~~~bash
PYTHONPATH=src python -c "from cyberdetect.analysis.adaptive import analyze_adaptive; analyze_adaptive('configs/adaptive.yaml')"
cat data/reports/adaptive_report.md
bash scripts/test.sh
~~~

The analysis regenerates the aggregate report and metrics from preserved episodes and predictions. It does not rerun the attacker or a defender. The tests use mock clients by default; live Lunary integration checks require an explicit Docker-test opt-in.

For new collection, use a separate working copy and set a new `experiment.id` and `experiment.data_root` in `configs/adaptive.yaml` so that completed episode and prediction files remain immutable. The original real study used Python 3.12 and Docker Desktop with WSL2. Install the package in a virtual environment, copy `secrets.env.example` to the ignored `secrets.env`, and fill in the provider settings locally. Export them before launching the drivers:

~~~bash
python3.12 -m venv .venv-linux
source .venv-linux/bin/activate
python -m pip install -e .

cp secrets.env.example secrets.env
# Fill in the provider settings locally before continuing.
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

Proceed with target collection only after the doctor passes the applicable isolation and stream-separation checks. The build fetches the upstream target at the recorded source pins; the application source is not vendored. The actor and benign-corpus stages require Docker. The current `run_v2_finish.py` performs defender replay and analysis only, and can run without Docker once the episodes exist. On a copy containing completed frozen artifacts, the drivers skip those artifacts; collecting an independent dataset therefore requires a separate experiment identity or data destination.

The expected aggregate outputs are `data/reports/adaptive_report.md` and `data/reports/adaptive_metrics.json`. Their interpretation must preserve the distinctions made above: held-out attack recall, benign-corpus threshold selection, pooled exploratory transfer, and prevalence projections conditional on the measured rates.

## Appendix C Model Identities and Reference Prices

The following are the model IDs and reference prices recorded for the experiment, observed on September 5-6, 2026. Prices are in US dollars per million tokens and describe the historical run rather than current service offerings.

| Role or tier | Model ID | Input price | Output price |
| --- | --- | ---: | ---: |
| Attacker and scoring proxy | `moonshotai/Kimi-K3` | $3.00 | $15.00 |
| `small_open` | `Qwen/Qwen3.5-9B` | $0.17 | $0.25 |
| `medium_open` | `openai/gpt-oss-20b` | $0.05 | $0.20 |
| `large_open` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | $1.04 | $1.04 |
| `large_oss` | `openai/gpt-oss-120b` | $0.15 | $0.60 |
| `frontier_open` | `deepseek-ai/DeepSeek-V4-Pro-0813` | $1.32 | $3.96 |

The registry records revisions as `together:<model-id>@2026-09-05` for the attacker and first four defenders, and `together:deepseek-ai/DeepSeek-V4-Pro-0813@2026-09-06` for the added DeepSeek tier. These identify the observed provider aliases and dates. They do not pin immutable model weights or all aspects of serverless serving. DeepSeek-V3.1 was attempted but unavailable on the serverless route used, so the experiment used the recorded V4-Pro alias instead.

The scenario and analysis configuration uses four calibration pairs, 20 test pairs, an empirical false-positive cap of 0.10, four permitted adaptive revisions, a proxy-score stopping target of 0.5, and 10,000 bootstrap replicates. The prevalence grid is 0.02, 0.01, 0.001, and 0.0001. These values, together with the preserved packets and predictions, specify the reported numerical analysis.
