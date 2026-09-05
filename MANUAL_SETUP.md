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

## Phase 2 model settings

Only after the BountyBench target doctor passes, configure model endpoints through
environment variables referenced by `configs/models.example.yaml`. Never paste keys
into YAML files, chat messages, source code, or experiment artifacts.
