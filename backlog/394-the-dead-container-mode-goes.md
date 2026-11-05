# 394 — The dead container mode goes

**Issue:** #417 · **Branch:** `agent/417-the-dead-container-mode-goes` · item 1
of 2. **No production code changes** — this deletes a test file and one
`[dev-dependencies]` entry.

**Governing decisions:** none govern a removal. The rationale recorded in
`.cargo/audit.toml`'s RUSTSEC-2026-0440 entry names this cleanup as the
follow-up it expects; that entry itself stays untouched here (see *Out of
scope*).

## The property

**`hort-adapters-storage` stops depending on `testcontainers`**, because its
single use is a container mode that has never worked and whose replacement is
already in the tree and already run by CI.

## Why this is a deletion and not a repair — measured 2026-11-05

- `crates/hort-adapters-storage/tests/s3_multipart.rs` is the crate's **only**
  consumer of `testcontainers`.
- **Its container mode is non-functional, and the file says so.**
  `skip_without_external_endpoint()` returns `true` with a skip note whenever
  `HORT_TEST_S3_ENDPOINT` is unset, because `dxflrs/garage` is a shell-free
  (scratch) image and the in-container `garage`-CLI bootstrap would need a
  shell-free rewrite. The module header adds that the bootstrap sequence "was
  written from documentation/knowledge, not iteratively debugged against a live
  Garage container".
- **Nothing runs it.** The gate is `HORT_TEST_S3=1`, which is set in no CI
  config — verified across `.gitlab-ci.yml` and all of `.github/workflows/`;
  the only `HORT_TEST` hit there is an unrelated `HORT_TEST_CLIENT_IMAGE`.
- **The replacement landed, and nothing runs it automatically either.** The
  defect this file reproduced and the work that was to replace it are both
  closed, and the deliverables are in the tree:
  `deploy/compose/docker-compose.s3.yml`, `deploy/compose/s3/garage.toml`,
  `deploy/compose/s3/garage-bootstrap.sh`, and the scenario
  `scripts/native-tests/scenarios/storage/s3-multipart-blob.sh`. But that
  scenario declares `# requires: compose:s3`, and the runner emits that token
  only for an explicitly-passed overlay. **No CI lane passes it** — the only
  two invocations are `./scripts/native-tests/run.sh --hort=compose` and
  `… --compose-overlay=native-tokens` (`.github/workflows/e2e.yml:139,178`) —
  so the scenario is skipped on every CI run, the release gate included, and an
  unavailable scenario is skipped silently rather than failed.

So the only mode of this file that ever worked is the one that needs an
operator-provisioned Garage, and that ground is now covered by a scenario that
provisions its own — but by a **manual** one either way. Automated
S3-multipart coverage is zero before this change and zero after it, so the
deletion gives up no working coverage. What it does not do is leave the ground
watched; wiring `--compose-overlay=s3` into an E2E lane is what would, and
that is not this unit.

## What to do

1. Delete `crates/hort-adapters-storage/tests/s3_multipart.rs`.
2. Remove the `testcontainers = { workspace = true }` entry **and its
   explanatory comment** from `[dev-dependencies]` in
   `crates/hort-adapters-storage/Cargo.toml`.
3. Correct `.agents/manifest.yaml`. Its comment block justifying the removed
   Garage env block names this file as one of "the two things that actually
   talk to this Garage", with its `HORT_TEST_S3_*` namespace. After the
   deletion that justification names a file that does not exist, so it must
   stop claiming a live consumer. Leave the second consumer
   (`.agents/garage-smoke.bats`) and the surrounding reasoning intact.

## Out of scope — and one of these is a trap

- **The workspace pin stays.** `testcontainers = "0.28"` in the root
  `Cargo.toml` and the `[dev-dependencies]` entry in `hort-notifier-nats` are
  item 2's business. Do not touch either.
- **`Cargo.lock` moves by exactly one line, and must not move by more.**
  Removing one crate's dev-dependency while another crate still uses the
  workspace dependency leaves the resolved **package set** identical — but the
  lockfile also records each workspace member's own dependency edge list, and
  edit 2 necessarily removes `"testcontainers"` from the
  `[[package]] name = "hort-adapters-storage"` block's `dependencies` array.
  That one deletion is the forced consequence of the edit; anything beyond it
  means something else was edited.
- **Do not touch `.cargo/audit.toml` or `deny.toml`.** `astral-tokio-tar` stays
  in the lockfile because the NATS suite still pulls `testcontainers`, so the
  RUSTSEC-2026-0440 ignore still matches something. Deleting it now makes
  `cargo deny` fail with `advisory-not-detected` — a hard failure. The entry
  comes out in item 2, in the same change that drops the dependency.
- **No `CHANGELOG.md` entry.** A deleted opt-in test harness is not something
  an operator can observe; the changelog deliberately leaves out test-harness
  work.
- **No third-party attribution regeneration.** It follows from the unchanged
  lockfile: the dependency graph does not move.

## Acceptance

- `crates/hort-adapters-storage/tests/s3_multipart.rs` no longer exists.
- `grep -rn testcontainers crates/hort-adapters-storage/` finds nothing.
- `.agents/manifest.yaml` no longer presents the deleted file as a consumer of
  the Garage sidecar.
- `git diff origin/develop -- Cargo.lock` is **exactly one line** — the removal
  of `"testcontainers"` from the `hort-adapters-storage` `[[package]]` block's
  `dependencies` array — and the resolved package set is unchanged (750
  packages, no additions, no removals). State the command's output in the
  report.
- `cargo fmt --all --check` clean, `cargo clippy --workspace --all-targets`
  with no warnings, and `cargo test --workspace` green. Run the workspace suite
  **once** for the branch.
