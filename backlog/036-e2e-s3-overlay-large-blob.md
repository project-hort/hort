# 036 — Compose S3/Garage overlay + one large-blob E2E scenario

- **Source:** GitLab issue #54. **Scope narrowed 2026-07-20** after a necessity review — the original item 2 (run the full scenario suite against both backends in CI) is dropped.
- **Type:** test infrastructure. `deploy/compose/` + `scripts/native-tests/`.
- **Model hint:** **capable** — compose wiring, Garage bootstrap, and a scenario that must be deterministic about blob size.
- **Reviewable unit:** one directive.

## Why the original scope is dropped

Issue #54 argued the backend matrix was needed because "zero test coverage of the real-S3 multipart path let #53 ship." **That premise is falsified.** #53's root cause was found and it was not S3 multipart:

- the real-Garage repro test **passed** at 76 MiB *and* 200 MiB, on Garage v1.0.1 **and** v2.2.0
- the cluster→quay fetch of the failing blob took **1.57s**
- the actual cause was a **wedged pull-dedup coalesce leader**, fixed in !168 (#55)

Both halves worked in isolation; the bug lived in the composition, on a code path identical across backends. A backend matrix would not have caught it.

Running every scenario group twice would permanently roughly double E2E wall-clock and CI cost to guard a defect class with **zero** confirmed instances. That is not a trade worth making on the current evidence.

## What to build instead

**Keep item 1 (the overlay) — it has standalone value. Drop item 2 (the CI matrix).**

1. **`deploy/compose/docker-compose.s3.yml`** — a Garage service matching production, bucket/key bootstrap, and hort-server/worker env overridden to `HORT_STORAGE_BACKEND=s3` with endpoint, bucket, keys, `force_path_style`, `allow_http`. Invoked through the **existing** `--compose-overlay=s3` mechanism in `scripts/native-tests/run.sh` (already implemented — see the `OVERLAYS` handling at run.sh:25–26; no harness change needed).
2. **One scenario** exercising the only genuinely divergent code path: a blob **> 5 MiB**, so the S3 backend takes a true multi-part upload (`put_multipart` → `put_part` → `complete` → server-side `copy`) rather than the single-part path every smaller blob uses. Push it, pull it back, verify the digest round-trips.

That covers the real-S3 multipart path — the thing that actually differs between backends — at a small fraction of a full matrix.

## Explicitly not doing

- **No CI backend matrix.** Not wired into `e2e.yml` or GitLab CI as a doubled run. The overlay is available for manual/targeted use. **Revisit trigger:** a genuinely backend-specific defect appears in production or staging; the overlay is then already in place to expand into a matrix.
- **No parameterisation of every scenario group.** One targeted scenario, not a harness-wide backend sweep.

## Acceptance

1. `./scripts/native-tests/run.sh --hort=compose --compose-overlay=s3` brings up a stack running `HORT_STORAGE_BACKEND=s3` against Garage, and tears down cleanly.
2. A new scenario pushes a **> 5 MiB** blob (so multipart is genuinely exercised, not the single-part path) and pulls it back with a matching digest. The size threshold and its rationale are stated in the scenario's header comment — a future reader must not "optimise" it below the multipart boundary.
3. The scenario is self-describing per `scripts/native-tests/README.md` and appears in `--list`.
4. The default (filesystem) run is unchanged — no existing scenario is altered, and no CI job is doubled.

## Starter prompt

/hort-architect

Implement backlog item 036 (issue #54) on branch `agent/54-e2e-s3-overlay`.

Build `deploy/compose/docker-compose.s3.yml` (Garage + `HORT_STORAGE_BACKEND=s3`, invoked via the existing `--compose-overlay=s3` mechanism — no harness change needed) plus **one** scenario that pushes and pulls back a blob larger than 5 MiB so the S3 multipart path is genuinely exercised.

Read `scripts/native-tests/README.md` for the scenario contract and `deploy/compose/docker-compose.federation.yml` for the overlay shape. Note `crates/hort-adapters-storage/tests/s3_multipart.rs` already has an external-Garage mode from #53 — reuse its Garage config knowledge (rpc_secret must be 32 bytes; key-id is "GK" + 12 hex bytes).

Do **not** wire a backend matrix into CI and do **not** parameterise the whole suite — both are deliberately out of scope. See the backlog item for why.
