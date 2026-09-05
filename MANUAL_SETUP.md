# Manual setup for the Docker/BountyBench phase

Phase 0 needs no manual setup and has already passed. Phase 1 requires a machine or
Codex environment that can run Docker Compose.

## Recommended: Codex local environment

1. Install the ChatGPT desktop app and Docker Desktop.
2. Install Git and `uv`. The `uv` command will install the project-specific
   Python 3.11 runtime in step 5.
3. Extract the archive and open PowerShell in `ai-cyber-log-detection`.
4. Verify:

   ```powershell
   docker version
   docker compose version
   uv --version
   git --version
   ```

5. From `ai-cyber-log-detection`, run:

   ```powershell
   uv python install 3.11
   uv python pin 3.11
   uv sync --extra analysis
   powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1
   powershell -ExecutionPolicy Bypass -File .\scripts\run_phase0.ps1
   ```

6. In the ChatGPT desktop app, select Codex and open the
   `ai-cyber-log-detection` project directory. Configure a local environment in the
   app settings. Use `uv sync --extra analysis` as the Windows setup script, and add
   `powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1` as a test action if
   useful.

Official instructions:
[Codex local environments](https://learn.chatgpt.com/docs/environments/local-environment).

This is the preferred route for Phase 1 because the project can use your local Docker
Desktop installation. Do not add model API keys yet.

## Alternative: Codex cloud through GitHub

Create a private GitHub repository, commit the project and specification, then set up a
Codex cloud environment for that repository. Add dependencies and secrets through the
environment settings rather than committing them.

Official instructions:
[Codex cloud setup](https://learn.chatgpt.com/docs/cloud).

Before using this route for BountyBench, verify that the selected cloud environment can
run the required Docker Compose workloads. If it cannot, use the local environment.

## Phase 2 model settings (real engineering pilot)

The Phase 1 target doctor now passes, so the real pilot can be run. Model identities are
pinned in `configs/models.yaml` (no secrets there). Endpoints and keys live only in
environment variables. Never paste keys into YAML files, chat messages, source code, or
experiment artifacts.

Recommended hosted endpoints (open-weight, OpenAI-compatible, verified 2026-09-05):

- Attacker `best_open_attacker`: `moonshotai/Kimi-K3` (Together AI).
- Small defender `small_open`: `Qwen/Qwen3.5-9B` (Together AI).

Steps (from `ai-cyber-log-detection`):

1. Create a Together AI account and API key (or another OpenAI-compatible provider that
   hosts the same pinned model IDs).
2. Export the endpoint and key into the shell only (they are read at run time):

   ```bash
   export ACTOR_MODEL_BASE_URL=https://api.together.xyz/v1
   export ACTOR_MODEL_API_KEY=...            # your key; never commit it
   export DEFENDER_MODEL_BASE_URL=https://api.together.xyz/v1
   export DEFENDER_MODEL_API_KEY=...         # same key is fine
   ```

3. Make sure Docker Desktop is running (the actor drives the live Lunary target), then:

   ```bash
   uv run cyberdetect scenarios generate --config configs/pilot_real.yaml
   uv run cyberdetect run actors     --config configs/pilot_real.yaml   # ~9 episodes, live target
   uv run cyberdetect run defenders  --config configs/pilot_real.yaml
   uv run cyberdetect pilot report   --config configs/pilot_real.yaml   # go/no-go + cost estimate
   ```

The pilot is 3 scenario pairs x 3 actor conditions (9 attacker episodes) plus the small
defender. Estimated cost at the reference prices is roughly USD 1-2 total. `pilot report`
evaluates the Phase 2 go/no-go gate (benign success, observable-attack and success rates,
defender parse-failure rate, context headroom, and leakage) and projects MVS/main cost
from the observed token medians. Do not scale to MVS/main until the gate passes and the
prompts are frozen.
