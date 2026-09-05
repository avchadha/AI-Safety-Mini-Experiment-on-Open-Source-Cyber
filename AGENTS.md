# Codex project instructions

The normative research and implementation requirements are in
`EXPERIMENT_SPEC.md`.

## Current phase

Phase 0 is implemented and passing. Do not connect a real vulnerable target or real
actor model until Phase 1 safety gates pass.

## Required boundaries

- Preserve the two-stream public/oracle separation.
- Never pass `data/raw_restricted/` to a defender.
- Do not add unrestricted shell, browser, network, or arbitrary-URL tools to actors.
- Real targets must be isolated, loopback-only from the host, and have no public egress.
- Do not rerun valid model failures, refusals, or unsuccessful attacks.
- Never place credentials in tracked files.
- Keep completed episode and prediction artifacts immutable.

## Verification

Run:

```bash
./scripts/test.sh
./scripts/run_phase0.sh
```

On Windows PowerShell, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\run_phase0.ps1
```

Before Phase 1, also require:

```bash
docker version
docker compose version
uv run python --version
```
