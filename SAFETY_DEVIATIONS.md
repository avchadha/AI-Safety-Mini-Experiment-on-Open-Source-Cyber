# Safety deviations

## SD-1 — Proxy ingress egress under Docker Desktop

**Status:** Approved by operator on 2026-09-05, before Phase 1 data collection.
**Scope:** Phase 1 `lunary_idor` target stack when run on a Docker Desktop engine.

**Deviation.** The instrumented proxy is the only host-reachable ingress and is
published on `127.0.0.1` (ephemeral port). On Docker Desktop, a host-published
container always reaches the public Internet through the Docker Desktop VM's NAT, and
an `internal` Docker network cannot publish a host port. The proxy container therefore
has outbound Internet egress that cannot be removed with Compose network settings on
this engine (`enable_ip_masquerade=false` does not block it under Docker Desktop's VM
gateway; verified empirically).

**What is NOT affected (still fully enforced on every platform).**
- The vulnerable target (`app`, `db`) has no host-published port and no Internet
  egress — it lives only on the `internal` `isolated` network.
- An actor-side container placed on the target network has no egress (doctor probe).
- The proxy is bound to loopback only; the target is never reachable from the host.

**Why this is acceptable.**
- The proxy is trusted first-party code (~250 lines, Python stdlib `http.server`). It
  has no code path that forwards actor-directed traffic anywhere but the fixed target
  origin; the actor tool submits only relative paths.
- The proxy runs as non-root (uid 65534), read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, with pids/mem limits.
- The safety boundary the specification requires — the intentionally vulnerable target
  cannot reach the Internet or the host — is intact and machine-verified.

**Compensating control / removal path.** On a native Linux Docker engine the proxy's
egress is blockable (host nftables/iptables rule on the published container, or a
non-masquerading bridge), and the target doctor keeps `proxy_egress_blocked` as a hard
gate there. Re-run the doctor on such a host to retire this deviation. Until then the
doctor reports `proxy_public_egress: accepted_platform_deviation` on Docker Desktop and
still hard-fails every other isolation, reset, oracle, canary, and cleanup invariant.
