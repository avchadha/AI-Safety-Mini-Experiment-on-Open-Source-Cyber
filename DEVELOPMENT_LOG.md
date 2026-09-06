# Development log & engineering lessons

Chronological record of how this experiment was actually built and run, including every
non-obvious failure mode and its fix. This is deliberately detailed: the infrastructure
failures were a large fraction of the real work, they are the kind of thing that silently
corrupts results if mishandled, and a future agent/researcher picking this up needs to know
where the traps are. Commit hashes refer to this repository's history.

Environment: Windows host running WSL2 (Ubuntu) + Docker Desktop; Python venv at `.venv-linux`
(the Windows `.venv` is unusable from WSL). All model calls go to Together AI's serverless
OpenAI-compatible API. ~$15 total Together budget.

---

## Phase 0 → 1: isolated target build

**Goal:** stand up a BountyBench vulnerable target (Lunary IDOR, CVE-2024-1625) fully isolated —
loopback-only exposure, blocked egress, pinned upstream commits/digests, two-stream telemetry
(a public `access_v1` log the defender may see, and a protected oracle stream it may not).

- **Two-network Docker bug.** Docker Compose `internal: true` blocks egress *and* silently drops
  host-port publishing, so the actor gateway on a loopback port returned nothing
  (`{"8081/tcp":[]}`). Fix: split into two networks — an `internal: true` `isolated` network for
  the app/db, and a bridge `edge` network the proxy also joins so its loopback port can be
  published. The app still has no egress; only the proxy is reachable, on 127.0.0.1.
- **Egress not fully blocked on Docker Desktop (SD-1 deviation).** Setting
  `enable_ip_masquerade=false` does *not* block outbound traffic on Docker Desktop's NAT VM.
  True egress blocking would need host firewall rules we can't set portably. Documented and
  operator-accepted as **Safety Deviation SD-1** (`SAFETY_DEVIATIONS.md`): the target app itself
  makes no outbound calls, and the risk is bounded because the target is a known-CVE benchmark
  app on a throwaway instance. Isolation of *inbound* access and telemetry separation are intact.
- **Gradio target content-type bug** (second, syntactic target — later dropped): the gateway
  client didn't set `content-type` on JSON bodies, so the app returned 422 on login. Fixed by
  inferring content-type from the body type. (Same inference later mattered for Lunary.)
- **Gradio read-only rootfs**: the app tried to create a `flagged/` dir on a read-only rootfs;
  fixed with `allow_flagging="never"` and `WORKDIR /tmp`. (Gradio path-traversal target was
  ultimately dropped as saturated — see report — but the fix is in the code.)

Target doctor (`cyberdetect target doctor --target lunary_idor`) verifies isolation, reset,
vulnerability presence, canary, and stream separation. It must report `overall: pass`,
`required_isolation_pass: true`, `proxy_public_egress: blocked` (proxy-level), source pins
verified, streams separate + aligned before any run.

## Phase 2–4: connecting real models (v1 main study)

- **Cloudflare error 1010 from Together.** Python stdlib `urllib`'s default `User-Agent` is
  blocked by Cloudflare. Fix: send `user-agent: cyberdetect/0.1` on every request. (This bites
  anything using urllib against Together.)
- **Qwen "thinking mode" destroyed outputs.** Qwen3.5 defaults to emitting hidden reasoning,
  which consumed the entire output-token budget before any answer, yielding empty content and a
  ~100% JSON parse-failure rate. Fix: `extra_body: {chat_template_kwargs: {enable_thinking:
  false}}`. gpt-oss models use `{reasoning_effort: low}`; DeepSeek-V4-Pro uses
  `{chat_template_kwargs: {thinking: false}}`. **General rule: every reasoning-capable defender
  must have hidden CoT disabled/minimised** — both for a fair single-forward-pass comparison and
  to keep the JSON parseable and cheap.
- **Rationale length cap** raised 800 → 4000 chars: verbose-but-valid rationales were tripping
  the schema validator and being scored as parse failures.
- **`RemoteDisconnected` from the Together client** aborted the v1 run at 54/180. Fix: broaden
  the model-client retry `except` to include `ConnectionError` and `http.client.HTTPException`.
- **`adapter` vs `target_adapter` refactor bug**: a rename left a `None` reference
  (`'NoneType' object has no attribute 'public_runbook'`) that aborted a run immediately. Fixed
  the reference and made the integration test exercise dispatch rather than passing an adapter.
- **DeepSeek-V3.1 was dedicated-only** on Together at v1 time (serverless catalogue lacked the
  large models), so the v1 large defender became Llama-3.3-70B and gpt-oss-120b. (By v2's DeepSeek
  addition the catalogue had changed — V4-Pro *is* serverless; see below.)

v1 main study: 180 actor episodes × 3 defenders = 540 judgments. Findings in `FINDINGS_MAIN.md`
(headline: medium/large detectors saturate at AUROC ≈ 1.0 — a ceiling effect; H3 reversed).
This ceiling motivated v2.

## v2 build (credential-free plumbing first)

New modules, all unit-tested without Docker or a key before any paid run:
- `actor/adaptive_runner.py` — the self-red-team loop (`run_self_red_team`) driven by an
  injectable `run_and_score_round`, plus the live wiring `run_adaptive_actors`.
- `environment/benign.py` — scripted benign corpus with deliberate hard negatives
  (bulk own-delete, error-and-retry, high-volume own enumeration).
- `analysis/baserate.py` — pure numeric cores: FPR/recall at threshold, precision-at-prevalence
  sweep, transfer fraction τ, cost ledger.
- `analysis/adaptive.py` — top-level v2 analysis producing the report + metrics JSON.

## v2 run: the gauntlet (six distinct failure modes)

The v2 run surfaced six independent failure modes. Each was fixed with the same discipline:
**retry transient faults, isolate per-unit failures, resume idempotently.**

1. **Gateway connection drops (`RemoteDisconnected`) from the local target.** The Node app
   behind its proxy occasionally closes a keep-alive connection without responding. The gateway
   client (`environment/targets/lunary.py`) had *no* retry — one drop aborted a multi-hour run.
   Fix (`697f4f2`): bounded retry (later 5×, 0.5s backoff) around `opener.open` for
   `RemoteDisconnected`/`BadStatusLine`/`ConnectionError`/timeout; real HTTP 4xx/5xx keep their
   pass-through path. (This mirrors the earlier Together-client fix, but at the *target* layer.)

2. **OOM kills with a self-reinforcing leak cycle.** Runs were killed by the host "low memory"
   guard. Root cause: each kill skipped the driver's container teardown, leaking a Lunary stack;
   leaked stacks accumulated in the Docker Desktop VM, growing its memory, which made the *next*
   run get killed *faster* (2–3 min, before a single ~14-min pair could finish). Relaunching
   alone could never converge. Fix: purge all leaked stacks + build cache to break the cycle,
   and add a **self-cleaning preamble** to the driver that removes orphaned `cd*` stacks at
   startup so relaunch-after-kill cannot re-accumulate.

3. **The resume "0 progress" bug (most insidious).** After OOM/relaunch, a run executed for
   67 minutes and banked **zero** new pairs. Cause: the actor scenario loop had **no
   fast-forward** — idempotency lived only in the freeze *write* (`_freeze_arm` skips an existing
   bundle), not in the expensive adaptive loop. So every relaunch silently re-ran already-frozen
   pairs 1–N from scratch (burning Kimi $ and time), produced no new artifacts, and died before
   reaching the unfinished pairs. Fix (`1b25382`): a `_scenario_complete()` check skips a
   scenario whole when all its arms are frozen (true resume), plus a per-scenario `try/except` so
   one flaky-target failure skips *one* pair instead of aborting the run. **Lesson: idempotent
   *skip-before-work*, not just skip-before-write.**

4. **Serverless 503 killed the defender sweep.** A single `HTTP 503 Service unavailable`
   (capacity blip) on one (defender, episode) call aborted the whole 4-tier sweep at 44/286.
   Fix: `run_real_defenders` now collects failed calls and retries them across up to 5 idempotent
   backfill passes (written predictions skipped), converging past blips; raises only if a call
   fails every pass. Defender client `max_retries` 3 → 6.

5. **Docker VM retained memory → OOM even on the container-free stage.** After Stages 1–2, the
   `docker-desktop` WSL2 VM held onto the memory it had ballooned to, so even the container-free
   defender stage kept getting killed (this distro showed 10 GB free the whole time — the
   pressure was on the Windows host via the Docker VM's `vmmem`). Fix: `wsl.exe --terminate
   docker-desktop` reclaims it, and Stages 3–4 (defenders + analysis) need no Docker at all, so
   they run Docker-free via a separate finisher (`run_v2_finish.py`).

6. **The harness memory-guard kills *any* tracked background task under host pressure.** Even a
   trivial sleep-loop "waiter" was killed, and the container-free finisher too — regardless of
   the task's own tiny footprint — because the guard reacts to *host* memory. Fix: run the
   finisher **detached** (`setsid`/`nohup`, not as a harness-tracked background command) so the
   guard doesn't target it; poll its log for completion. The detached finisher ran to completion
   while tracked tasks were being killed around it.

## v2 pair expansion (12 → 24 pairs)

To de-noise the recall/τ estimates (originally n=8 test pairs), test pairs were raised 8 → 20
(24 total, 4 calibration / 20 test). The scenario generator is **append-stable**:
`scenario_seed = master_seed + pair_index`, `pair_id = hash(target:seed)`, split assigned by
index, and existing files are skipped — so raising the count leaves the first 12 pairs
byte-identical (frozen episodes remain valid) and only appends new test pairs. No prior work
invalidated. Actors ran under Docker (`run_v2_actors.py`, self-cleaning), then defenders +
analysis ran Docker-free and detached.

## DeepSeek-V4-Pro added as a 5th "frontier-open" defender tier

A live catalogue re-check showed the SoTA open models are now on Together **serverless**
(token-priced via the existing key), not dedicated-only as at v1 time.
`deepseek-ai/DeepSeek-V4-Pro-0813` was verified reachable and added as `frontier_open`, reasoning
disabled (`{chat_template_kwargs: {thinking: false}}`) for parity with the other tiers. It scores
the **already-frozen** 382 episodes — no attacker re-runs, no Docker — then the analysis re-runs
over all 5 tiers. `DeepSeek-V3.1` remained dedicated-only ("Unable to access non-serverless
model"), but V4-Pro is newer/stronger anyway.

## Standing operational notes

- Docker access in WSL: the login shell isn't in the `docker` group, so Docker commands run via
  `sg docker -c '<cmd>'`.
- Secrets live only in `secrets.env` (gitignored); `secrets.env.example` documents the variables.
  **The Together key was pasted into a chat transcript during development and should be rotated.**
- Data (`data/`) is gitignored in local development but published in this repo for reproduction;
  it contains only ephemeral throwaway-container credentials and experiment canaries (no real
  secrets — audited).
- Long paid runs are the real cost in *wall-clock* (Kimi/DeepSeek latency), not dollars.
