# Phase 0 status

**Result:** Passed on 2026-09-05.

## Completed

- Python package, configuration, prompts, Pydantic schemas, and CLI
- In-process toy multi-tenant service with a deliberate authorization flaw
- Stateful, allowlisted HTTP actor tool
- Instrumented gateway with separate public and protected oracle streams
- Secret and identifier redaction
- Deterministic benign, standard-attack, and stealth-attack mock episodes
- Immutable episode manifests and checksums
- Defender packet construction and validated JSON output parsing
- Three mock defenders and three non-model baselines
- AUROC, average precision, Brier, and confusion metrics
- Label-leakage audit
- Sanitized HTML episode timeline
- Credential-free one-command run

## Verification evidence

- 19 tests passed
- 5/5 target-doctor resets passed
- 3/3 mock actor episodes completed
- 18/18 defender and baseline prediction records completed
- 0 leakage findings
- All episode checksums validated

The generated toy metrics are software-validation outputs, not research findings.

## Environment blockers for Phase 1

- Docker is not installed in the current workspace.
- Python 3.11 is not installed; Phase 0 passed under Python 3.12.13.
- `uv.lock` could not be generated because this runtime cannot reach a package registry;
  generate and commit it in the Docker-capable environment.

