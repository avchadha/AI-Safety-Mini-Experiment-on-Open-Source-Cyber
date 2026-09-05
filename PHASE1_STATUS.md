# Phase 1 status

**Result:** Passed on 2026-09-05 (Docker Desktop engine, one approved safety deviation).

## Completed

- Pinned BountyBench Lunary bounty 0 target (CVE-2024-1625 / CWE-639 cross-tenant
  project-deletion IDOR) wired into the two-stream pipeline through a thin adapter.
- Isolated Docker Compose stack: `db` + `app` on an `internal` network (no host port,
  no egress); instrumented `proxy` published loopback-only on `127.0.0.1`, on both the
  `internal` network (to reach the target) and an `edge` bridge (solely to publish the
  loopback port).
- Allowlisted, stateful, relative-path-only HTTP path from host to proxy; no shell,
  browser, arbitrary URL, Docker socket, or host access for the actor side.
- Instrumented proxy emits physically separate public `access_v1` and protected
  oracle/raw streams sharing a random `event_id`; pseudonymized identities and paths.
- Target adapter: build, start (fresh Compose project + ephemeral volumes = reset),
  wait_healthy, seed (fresh accounts/canary/pseudonym key, host-only), public_runbook,
  verify_final_state (exploit verification), telemetry read/export, and stop (cleanup).
- Target doctor: 5 benign + 5 attack fresh environments verifying isolation,
  deterministic reset, known-vulnerability behavior, canary observability, public-log
  schema/redaction, two-stream separation, and clean teardown.
- Unit, integration, leakage, and safety tests; environment-independent temp handling.

## Verification evidence (2026-09-05)

- `cyberdetect target doctor --target lunary_idor`: **overall: pass** on Docker Desktop.
- 10/10 fresh environments healthy; 5/5 benign produced no oracle violation, 5/5 attack
  produced a `cross_tenant_delete` violation; final-state verification correct in all 10.
- Deterministic reset: yes. Two streams aligned and separate in all 10. Public leakage:
  none. Canary observable to the private verifier in all 10. All 10 teardowns clean;
  zero residual containers, networks, volumes, or run directories.
- Required isolation (hard-gated): target egress blocked, actor-probe egress blocked,
  no target host ports, proxy loopback-only, target network internal — all true.
- 31/31 offline tests pass (unit, integration, leakage, safety).

## Pinned inputs

- Upstream commits: bountybench `8ece6aab0b954f7c85b5705e69f0142eeaf2c5d1`,
  bountytasks `1956e5fd4eff12034a5fbe0544482d2cf52bb5b0`,
  lunary `fc959987f3b2cfba25c847ffdba6ac820af154b4`
  (BountyBench `vulnerable_commit` verified equal to the pinned Lunary commit).
- Base image digests: node `18-bookworm@sha256:c6ae79e3…`,
  postgres `groonga/pgroonga:3.2.4-debian-15@sha256:c523446a…`,
  python `3.11-slim-bookworm@sha256:528257d4…`.
- Built local images (this host): app `sha256:8616f0af…`, db `sha256:311765941e04…`,
  proxy `sha256:1b8f70712d44…` (recorded in `target-images.lock.json`).

## Approved safety deviation

- **SD-1:** On Docker Desktop the loopback-published proxy has Internet egress that
  cannot be network-blocked (VM NAT; `internal` networks cannot publish ports). The
  vulnerable target and any actor-side container remain fully egress-blocked. Operator
  approved on 2026-09-05. Retire by re-running the doctor on a native Linux engine,
  where proxy egress stays a hard gate. See `SAFETY_DEVIATIONS.md`.

## Phase 2 gate

Phase 1 safety gates are satisfied. Model integration is not started (no endpoints,
no API keys) per the Phase 1 directive. Phase 2 requires the operator to supply model
endpoints and freeze the attacker/defender model selection.
