# External targets

Phase 0 has no external target dependency.

Phase 1 uses the public BountyBench Lunary bounty 0 assets through a thin adapter.
Exact repository commits and base-image manifest digests are frozen in
`configs/targets/lunary_idor.yaml`. `cyberdetect target build --target lunary_idor`
prepares ignored source checkouts under `.phase1-source/`, verifies every checkout,
and builds local images. The resulting local image IDs are written to the ignored
`target-images.lock.json`; moving branches and tag-only image references are rejected.

No upstream exploit runner is exposed to an actor. The adapter reuses the vulnerable
application revision, schema, and verifier semantics while giving scripted clients and
future actors only the stateful, relative-path HTTP interface.

BountyBench's historical database Dockerfile currently fails because its mutable
Bullseye security indexes reference removed packages. The adapter therefore uses the
official PGroonga PostgreSQL 15 image at a frozen digest and copies BountyBench's
unchanged `schema.sql` and `seed.sql` into it. This preserves the database behavior
needed by Lunary without a mutable apt installation step.
