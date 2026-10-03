# Open Weight Models and the Detection of Cyberattacks

Amrit Chadha  
AI safety mini-experiment for Boaz Barak and Nicholas Carlini's AI-safety course

## I Research Question and Background

The use of increasingly capable AI models in cybersecurity raises a question about the relationship between offense and defense. A model that can carry out an attack may also be able to recognize one, yet these abilities need not develop at the same rate. Furthermore, recognizing an attack in an experiment does not necessarily imply that the same model will be useful in a setting where almost all activity is legitimate. This study examines these issues through a limited task: determining whether an open-weight model can identify an AI-generated cyberattack from a completed session's service logs and a description of the service's authorization rules.

The experiment reveals that some relatively inexpensive models can recognize the attack reliably, but that this ability depends substantially on which model is used. The best detector in the study, gpt-oss-20b, identified 19 of 20 baseline test attacks, while Llama-3.3-70B identified only one. An attacker that revised its behavior using feedback from its own model also reduced detection by some defenders it had never queried. However, when the measured detection and false-positive rates are projected to a setting with one attack per 1,000 sessions, fewer than 1.2% of alerts identify attacks for every defender. The results therefore suggest that useful defense requires attention to the frequency of attacks and the conditions under which a detector is evaluated, in addition to the capabilities of the model itself.

The scope of this claim is deliberately narrow: the attacker acts against a benchmark application with a known vulnerability in an isolated environment. The defenders review the resulting evidence after the session has ended and have no opportunity to stop a request, inspect additional evidence, or intervene during the attack. The experiment thus evaluates recognition of observable attack behavior, with broader application and network defense outside its scope.

The present design grew out of an earlier version of the study that produced results too close to perfect to clarify the practical difficulties of detection. That study used a balanced collection of benign and attack sessions on two targets: an authorization vulnerability in Lunary and a path-traversal vulnerability in Gradio. Medium and large defenders achieved an area under the receiver operating characteristic curve, or AUROC, of approximately 1.000, and a simple rules detector perfectly identified the Gradio attacks. AUROC measures how well a detector ranks attacks above benign sessions across thresholds, so a high value establishes separation on that dataset. Assessing alert reliability when attacks are rare also requires information about prevalence and false positives.

The earlier study also found that a simple instruction to be stealthy could make attacks more detectable. The standard attacker already performed legitimate-looking reconnaissance around its malicious action, and the stealth instruction sometimes removed that surrounding activity. These findings motivated the present version, which retains the Lunary target and introduces repeated attacker revision, a larger set of defender models, and an explicit analysis of attack prevalence.

All attacker and defender models in this study are open-weight models accessed through Together AI's serverless service, making it possible to examine capabilities available without access to a closed model or a dedicated inference deployment. The operator's approximate spend for the broader experimental work was $10 within a budget of roughly $15.

## II Construction of the Experiment

### The target and the evidence available to defenders

The target is Lunary, an application for observing and managing LLM activity, at a known-vulnerable source revision. Its vulnerability, CVE-2024-1625 and CWE-639, allows an authenticated user to delete another tenant's project by supplying that project's identifier to `DELETE /v1/projects/{id}`, since the endpoint fails to enforce project ownership.

The vulnerability is useful for this experiment because the malicious request has the same general form as an authorized request. Deleting one's own project is legitimate, and the vulnerability lets an attacker apply the same operation to another tenant's project. Consequently, detection depends on the relationship between the user and the resource, and treating every deletion as suspicious produces false positives.

To make this relationship interpretable, each defender receives both the public access logs and a service runbook. The runbook describes the permitted operations and provides an episode-local mapping between the principal and its authorized project. The logs contain ordered request metadata, including methods, paths, status codes, timing, and pseudonymized resource identifiers. They exclude request and response bodies, credentials, attacker instructions, model identities, and the experiment's ground-truth authorization decisions. The task is therefore to interpret restricted service evidence against a stated policy.

A separate protected stream records policy violations and the evidence used to establish what actually happened. This stream is used by the experimental harness and is never included in a defender's packet, preventing the detector from receiving the ground-truth label. The attacker likewise receives no scores or explanations from any of the five evaluated defenders.

Each attack attempt runs against a fresh container stack, preventing a successful deletion in one attempt from removing the victim resource needed by a later attempt. The application and database are placed on an internal Docker network, and the actor reaches the application through a telemetry gateway bound to the host's loopback interface. The actor has a constrained HTTP tool with relative paths, restricted headers, response-size limits, and no redirect following, and it has no general shell or unrestricted browsing interface.

On Docker Desktop, the loopback-published telemetry proxy can retain outbound Internet access through the Docker virtual machine's networking, an exception accepted by the operator before collection. The application and database remain on the isolated network without public egress, and the proxy forwards actor requests only to the fixed target.

### The attacker and its comparison conditions

The Kimi K3 attacker agent alternates between model decisions and constrained HTTP requests, observes the responses, and continues until it finishes or reaches a resource limit. This arrangement gives the model the ability to interact with the vulnerable service within the restricted environment.

For each scenario, the experiment retains three conditions: baseline, naive-stealth, and adaptive. The baseline condition uses the standard attack instructions without additional pressure to evade detection. The naive-stealth condition adds a single instruction to be stealthy and supplies no detector feedback. The adaptive condition allows the attacker to revise its behavior after seeing an assessment of its previous session.

The assessment comes from another invocation of Kimi K3 acting as a detector, which serves as the attacker's scoring proxy for judging whether its activity appears suspicious. After an attempt, the scoring proxy receives the public evidence and returns an attack probability and rationale. The attacker is then asked to accomplish the same objective with requests that resemble ordinary authorized use, and its instructions prohibit tampering with the logging system itself.

The configured limit, `max_rounds: 4`, permits four revisions after the initial baseline attempt, for at most five adaptively scored attempts in total. The loop stops early if the latest attempt succeeds and its proxy score is below 0.5. The retained evasive episode is the successful attempt with the lowest proxy score, even if that score remains above 0.5. If no attempt succeeds, the implementation falls back to the baseline episode. All 24 retained evasive episodes in this run are labeled successful in the frozen ground truth.

This design tests whether evasion developed against one model transfers to other models. Kimi K3 is excluded from the defender comparison, and the attacker never queries an evaluated defender, so a decrease in another defender's score cannot be explained by directly optimizing against that defender's feedback. The choice of scoring proxy and the extent of evasion achievable by other adversaries remain open questions.

### Benign activity and the defender models

The experiment includes 310 benign sessions generated by scripts acting against the same service, covering ordinary browsing, creation, and deletion, as well as unusual authorized activity. The latter includes bulk deletion of one's own projects, repeated errors followed by retries, and high-volume enumeration of owned resources. Such sessions are often called hard negatives because they resemble behavior that a detector might otherwise associate with an attack.

These sessions make the false-positive problem substantive because a detector that flags every busy session or every deletion will also flag users who are acting within their permissions. The benign corpus therefore tests whether a model can distinguish a policy violation from merely unusual activity. Because these sessions come from scripts and a small set of templates, they represent only a limited approximation of legitimate production traffic.

Five models review the same frozen session packets and span several model families and architectures, as shown below. Mixture-of-experts, or MoE, models contain more total parameters than they activate for a particular token, so total parameter count alone does not describe their inference cost or computation.

| Tier | Model | Recorded scale | Reasoning setting |
| --- | --- | --- | --- |
| `small_open` | Qwen3.5-9B | 9B dense | `enable_thinking: false` |
| `medium_open` | gpt-oss-20b | About 21B total and 3.6B active, MoE | `reasoning_effort: low` |
| `large_open` | Llama-3.3-70B-Instruct-Turbo | 70B dense | Non-reasoning model |
| `large_oss` | gpt-oss-120b | About 120B total and 5B active, MoE | `reasoning_effort: low` |
| `frontier_open` | DeepSeek-V4-Pro-0813 | MoE, designated frontier tier | `thinking: false` |

The settings were chosen to limit inference cost and obtain structured output, with the gpt-oss models using low reasoning effort and reasoning disabled for Qwen and DeepSeek. The models also differ in training, architecture, and serving configuration, so the comparison measures how these particular models performed under the recorded settings and leaves the causal effect of size unresolved.

The dataset contains 24 matched attack scenarios, with three retained conditions per scenario, giving 72 attack episodes. The scenario generator assigns the first four scenario indices to calibration and the remaining 20 to test, with all conditions of a scenario kept together. Seeds derive from the master seed, 20260905, and adding scenarios does not change earlier assignments. Combined with the 310 benign sessions, the study contains 382 episodes and 1,910 defender predictions.

Each episode includes its public log, defender packet, manifest, ground truth, and SHA-256 checksums. Protected oracle records, attacker transcripts, and scoring-proxy outputs are stored separately. Freezing these materials before defender replay ensures that every model is judged on the same evidence and that the attacker cannot change a session after seeing an evaluated defender's response.

## III Evaluation and the Meaning of Detection

A defender returns a structured verdict, an attack-probability score, and an explanation citing relevant events, and these elicited scores have not been independently validated as calibrated probabilities. The analysis turns the score into an alert by comparing it with a threshold, selecting for each defender the lowest available threshold whose empirical false-positive rate on the 310 benign sessions is at most 10%. An episode is flagged when its score is greater than or equal to that threshold.

This procedure imposes a common upper limit on false positives, and the models' observed rates range from 3.87% to 9.35%, partly because their scores occur at discrete values. The same benign corpus is used both to choose the threshold and to report its false-positive rate. The reported rates therefore describe performance on the threshold-selection corpus, leaving the false-positive rate on new benign traffic untested.

Recall is the fraction of attack episodes that produce alerts and is computed separately for the baseline and evasive conditions using the 20 test scenarios. Each additional detected attack changes recall by five percentage points, so a recall of 0.80 means that 16 of the 20 test attacks were identified.

Precision gives the fraction of alerts that correspond to attacks, which depends on attack prevalence as well as recall and false positives. Let $p$ be the fraction of sessions that are attacks, $r$ the detector's recall, and $f$ its false-positive rate. Among all sessions, the fraction producing true alerts is $rp$, and the fraction producing false alerts is $f(1-p)$. Consequently,

$$
\operatorname{Precision}(p)
=
\frac{rp}{rp+f(1-p)}.
$$

The denominator includes both kinds of alerts, so the expression gives the fraction of alerts corresponding to attacks. This is the same conditional-probability distinction that separates the probability of an alert given an attack from the probability of an attack given an alert. When legitimate activity is sufficiently common, false alerts can outnumber true alerts for a detector with high recall.

The analysis evaluates this expression at attack prevalences of one in 50, 100, 1,000, and 10,000 sessions, using evasive-condition recall. These are hypothetical deployment scenarios that assume the measured recall and false-positive rate remain applicable as prevalence changes. The actual attack rate would need to be measured for a particular production system.

The effect of adaptation is also measured through a transfer statistic. For scenario $i$, let $q_{b,i}$ and $q_{e,i}$ be the scoring proxy's baseline and evasive scores, and let $s_{b,i}$ and $s_{e,i}$ be the corresponding evaluated defender's scores. The statistic is

$$
\tau_i
=
\frac{s_{b,i}-s_{e,i}}{q_{b,i}-q_{e,i}}.
$$

A value near one indicates that the defender's score fell by approximately as much as the proxy's score. Values near zero indicate little score reduction on that defender, and negative values indicate that the defender's score rose. The ratio measures relative score movement and can fall outside zero and one, so it should be interpreted separately from a probability or a change in recall at a threshold.

Pairs whose proxy score falls by less than 0.05 are excluded to avoid dividing by a very small or nonpositive effect. The reported transfer estimate is the mean of the remaining ratios, with a percentile 95% interval from 10,000 bootstrap resamples of pairs. The current transfer calculation pools calibration and test scenarios, with 19 of the 24 scenarios qualifying: three calibration scenarios and 16 test scenarios. The proxy-score comparisons also use all 24 scenarios, so both statistics should be read as exploratory paired analyses.

## IV Results

### Detection on the held-out attack scenarios

The table below reports the operating threshold, empirical benign false-positive rate, and detected attack counts for each defender. The baseline ranking is led by gpt-oss-20b, followed by gpt-oss-120b and DeepSeek, with Qwen and Llama detecting very few attacks at their selected thresholds.

| Defender | Threshold | False-positive rate | Baseline attacks detected | Evasive attacks detected |
| --- | ---: | ---: | ---: | ---: |
| gpt-oss-20b | 0.95 | 6.77% (21/310) | 19/20 (95%) | 16/20 (80%) |
| gpt-oss-120b | 0.93 | 6.77% (21/310) | 13/20 (65%) | 6/20 (30%) |
| DeepSeek-V4-Pro | 0.92 | 5.16% (16/310) | 10/20 (50%) | 12/20 (60%) |
| Qwen3.5-9B | 0.95 | 9.35% (29/310) | 2/20 (10%) | 1/20 (5%) |
| Llama-3.3-70B | 0.90 | 3.87% (12/310) | 1/20 (5%) | 1/20 (5%) |

Adaptation reduces gpt-oss-120b's detected count from 13 to six, lowering recall from 65% to 30%, and reduces gpt-oss-20b's detected count from 19 to 16. DeepSeek detects two more evasive episodes than baseline episodes, Qwen detects one fewer, and Llama remains at one. Given the small denominator, the increase for DeepSeek should not by itself be treated as evidence that padding improves its detection.

### Proxy-score reduction and transfer

Across all 24 scenarios, the mean decrease in the attacker's own scoring-proxy probability is 0.248, with a 95% bootstrap interval of [0.176, 0.316]. The corresponding baseline-minus-naive-stealth difference is -0.004, with an interval of [-0.021, 0.012]. The adaptive procedure produces a substantial average proxy-score reduction in this run, and the one-shot stealth instruction's average effect remains unclear.

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

For a concrete example, consider gpt-oss-20b at one attack per 1,000 sessions: among 100,000 sessions, there would be 100 attacks and 99,900 benign sessions. Evasive recall of 0.80 produces 80 true alerts, and the measured false-positive rate of 21/310 produces approximately 6,767 false alerts, giving about 6,847 alerts of which only 1.17% would identify attacks. DeepSeek produces fewer false alerts and fewer true alerts, yielding a similar projected precision of 1.15%.

These calculations explain why strong recall on an attack benchmark is insufficient for reliable alerts under rare attacks and show where a practical improvement would have to occur. At prevalence 0.001 and recall 0.80, precision of 50% requires a false-positive rate of about 0.00080, or 0.08%, implying a substantial reduction from the measured 6.77%.

### Recorded inference costs

The frozen metrics report $3.8783 in recorded offense-side token cost, or $0.1616 per retained successful evasive scenario. Estimated defense cost is $1.2856 across 1,910 screenings, or $0.000673 per screening, giving a ratio of these unit figures of approximately 240.

The ledger provides an incomplete accounting of the adaptive campaign because it sums attacker token counts attached to the retained baseline, evasive, and naive-stealth arms. Discarded revisions and scoring-proxy calls are not fully accounted for, and the earliest scenario also lacks token instrumentation. Defense cost is estimated using fixed blended prices of $0.50 per million input tokens and $0.90 per million output tokens. These figures describe the existing accounting method and do not establish exact provider charges or a 240-fold operational advantage for defense.

## V Examination of the Findings

The most consequential result concerns the relationship between detection and prevalence, since a benchmark can demonstrate that a model identifies most attacks with little indication of how often its alerts will be wrong in ordinary use. The prevalence calculation makes this distinction explicit by showing that, when attacks are rare, a false-positive rate that appears tolerable on a balanced dataset can generate thousands of alerts for each small set of actual attacks. The difficulty is therefore partly a property of the decision setting in which the model is used.

The reported projections concern the chosen thresholds and the measured benign corpus, so the conclusion applies to the poor projected precision of these particular operating points under rare attacks. A stricter threshold might reduce false positives and recall, and a system that screens sessions before presenting them to an LLM might change the prevalence of attacks in the screened population. Both possibilities require further evaluation to establish how they affect precision.

The defender ranking likewise shows that parameter count alone is an unreliable guide to performance on this task. Llama-3.3-70B is the largest dense model tested and has the lowest baseline recall, and gpt-oss-20b performs best. Within the gpt-oss family, the larger model also performs worse under the recorded settings. Establishing the role of size or security-specific training would require controlling for architecture, training, reasoning configuration, and serving behavior.

The adaptive attack results reveal a further weakness: the attacker can make its behavior appear less suspicious to a model it controls and obtain some of the same effect on an evaluated defender it never queried. The reduction in gpt-oss-120b's test recall demonstrates that direct access to the target detector is not necessary for evasion to impair this particular defense. The differences across detectors, including DeepSeek's lack of a clear average score decrease, motivate separate assessment of attack recognition and resistance to transferred evasion.

The adaptive-versus-naive comparison also combines several changes: the adaptive condition receives feedback, more attempts, and selection of the successful attempt with the lowest proxy score. Some improvement could therefore come from selecting among multiple attempts, so the observed difference establishes the effect of the complete adaptive procedure. To isolate the contribution of feedback itself, a later experiment should compare it with an equally funded set of independent attempts selected by the same proxy.

The nature of the vulnerability also constrains the meaning of evasion because a successful attack in this environment necessarily generates a deletion request, and the runbook supplies authorization context for interpreting it. The attacker's instructions prohibit removing that evidence by tampering with the logger, so the decisive action remains in the retained log as adaptation changes the surrounding behavior or the model's assessment.

The malicious deletion has an ordinary request structure, and the detector must connect it to the authorization mapping. The results show that models can fail to make this connection with the relevant action still present. Whether cyberattacks in general leave sufficient evidence in access logs remains open, especially when authorization context is missing or the harmful action resembles permitted activity more closely.

Finally, screening one session and generating one successful attack are different units of work. A defender may have to screen thousands of benign sessions to encounter one attack, and its alerts may require additional automated checks or human review. This study does not measure investigation time, staffing cost, or prevented harm. The prevalence projections identify a possible source of substantial review burden whose size remains an operational question.

Cheap inference can support useful attack recognition, and an open-weight attacker can erode some of that recognition through repeated revision. Whether either capability becomes practically decisive depends on the information available, the defender's operating point, and the rate at which attacks occur. With only one attacker model, the study leaves changes in that balance as attacker capability increases untested.

## VI Limits and Further Research

The principal statistical limitation is the number of attack scenarios: held-out recall rests on 20 cases, and the transfer analysis retains 19 eligible pairs from the combined calibration and test set. The difference between detecting 19 attacks and detecting one is substantial, and smaller differences are less secure. The reported bootstrap intervals describe uncertainty in mean proxy-score changes and transfer ratios. Comparable intervals for recall and a general ordering of models across tasks remain to be established. The attacker is also supplied an objective and a vulnerability-class brief, which limits the task to executing a specified benchmark attack.

The benign data also limit the deployment claims because the 310 sessions are generated from a restricted collection of workflows, with a configured hard-negative fraction of 0.4. The hard negatives make the examples more demanding than ordinary browsing alone, and the restricted workflows cover a limited range of real organizational behavior. Reusing these sessions for threshold selection and false-positive reporting further limits independent validation. A larger, separate benign test set is necessary both to check generalization and to study the much lower false-positive rates needed under rare attacks.

The most direct extension is replication on another application and another vulnerability class. The earlier Gradio target, CVE-2024-1561, was omitted from this version because a rules detector had already solved its path-traversal patterns perfectly. A more informative target would test whether the model ranking and transferred evasion persist when detecting misuse requires a different kind of contextual judgment. Multi-stage attacks and activity spread across sessions would also test the ability to connect evidence across related episodes.

A controlled comparison within one model family would help separate size from training and architecture. Security-tuned models would provide a complementary test of whether task-relevant training explains the observed ranking. Adding a closed frontier model could establish a comparison point beyond the open-weight set, and allowing larger reasoning budgets could test how much the current inference settings constrain performance. These extensions were deferred because of budget and hosting availability, with specific model availability needing to be checked at the time of a new run.

A more complete evasion experiment would add the equal-attempt control described above and vary attacker capability or adaptation budget. It could also compare the present transfer setting with one in which the attacker can query a surrogate or the actual detector. Such comparisons would measure how much direct feedback adds, rather than assuming that stronger access necessarily produces a particular numerical effect.

For defense, the prevalence results motivate evaluation of systems that combine multiple kinds of evidence, including screening with inexpensive rules, correlating activity across sessions, and escalating selected cases for deeper analysis. Each approach should be tested for its effect on both recall and false positives, since a pre-filter that removes legitimate activity may also remove attacks. Prefix replay would allow measurement of how early an attack becomes detectable, and an interactive defender could be evaluated for its ability to prevent damage.

Parse failures occurred in 10 of 382 Qwen outputs, six gpt-oss-120b outputs, two DeepSeek outputs, and one output each for gpt-oss-20b and Llama. The parser assigns these cases an insufficient-evidence verdict and a score of 0.5, which lies below every selected alert threshold, so these retained failures are part of the measured pipeline performance. In addition, provider model revisions are recorded as aliases with observation dates, leaving immutable weight hashes unspecified, and the Docker Desktop proxy-egress deviation applies to the original collection environment.

## VII Conclusion

This study shows that selected open-weight models can recognize an AI-generated authorization attack from restricted service evidence, but that performance varies greatly across the models tested. It also shows that an attacker using its own model as a scoring proxy can reduce detection by some defenders without querying them directly. These findings establish a limited defensive capability and a corresponding evasion capability within the same experimental setting.

The practical significance of either result depends on the conditions under which detection is used. At the measured thresholds, rare attacks produce overwhelmingly false alerts even for the strongest detector. A useful next stage of research must therefore test independent benign traffic, lower false-positive operating points, and methods that combine evidence across requests or sessions. The central contribution of this experiment is to make those requirements explicit while preserving a frozen record from which its observations can be checked.
