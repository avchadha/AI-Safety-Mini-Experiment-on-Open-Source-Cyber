# AI Cyber Log Detection

This repository implements the experiment specified in
`EXPERIMENT_SPEC.md`: generate benign and malicious sessions
against an isolated vulnerable service, preserve defender-visible telemetry separately
from protected ground truth, and replay identical logs to multiple detectors.

Phase 0 is credential-free and uses an in-process toy authorization service. It proves
the artifact, safety, replay, and analysis pipeline before any real model or vulnerable
target is connected.

## Run Phase 0

From this directory:

```bash
./scripts/run_phase0.sh
```

The command creates a frozen mock experiment, runs three matched actor conditions,
audits defender packets, runs three mock defenders and baselines, computes metrics,
and generates an HTML timeline. It writes only beneath `data/` and will not silently
overwrite completed artifacts.

Run the test suite with:

```bash
./scripts/test.sh
```

On Windows PowerShell, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\run_phase0.ps1
```

The platform scripts prefer the project virtual environment when available.
For a portable development environment, run `uv python install 3.11` and
`uv sync`.

## Main commands

```text
cyberdetect doctor
cyberdetect target doctor --target toy_idor
cyberdetect scenarios generate --config configs/pilot.yaml
cyberdetect freeze --config configs/pilot.yaml
cyberdetect run actors --lock experiment.lock.json
cyberdetect audit leakage --lock experiment.lock.json
cyberdetect run defenders --lock experiment.lock.json
cyberdetect run baselines --lock experiment.lock.json
cyberdetect analyze --lock experiment.lock.json
cyberdetect visualize --episode <episode_id>
cyberdetect status --lock experiment.lock.json
```

`cyberdetect phase0` executes the Phase 0 sequence in one command.

## Safety

The actor interface accepts only relative paths to a preconfigured loopback origin.
Absolute URLs, origin-changing redirects, unsafe headers, and oversized responses are
rejected. The mock pipeline has no external target and needs no API credential.

Do not connect a real vulnerable target until `doctor`, the target-specific doctor,
the two-stream telemetry tests, and the leakage audit pass.
