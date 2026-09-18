# 195 — Test-client image gets `cargo`, so `dogfood/registry-supply-chain` runs instead of skipping

**Issue:** #268 · **Branch:** `agent/268-client-image-cargo` · single item · harness-only.

## Defect

`scripts/native-tests/scenarios/dogfood/registry-supply-chain.sh:84` skips with "cargo not found in
PATH"; `scripts/native-tests/Dockerfile.client` ships no Rust toolchain. Every CI and harness run
lists the scenario under `skip:`, so its part (h) — the only record-mode OSV scan precedent — has
never executed on the native-tests runner.

## Change

1. `Dockerfile.client`: add `cargo` + `rustc` matching the workspace toolchain (`rust-toolchain`/
   `RUST_VERSION` used by `docker/Dockerfile.hort-server`), via a `rust:<ver>-slim` stage copied in
   or the same base; keep the image's other tools untouched. Pin by digest like the other images.
2. Ensure the scenario's other prerequisites (registry token, `hort-cli`) are already satisfied;
   fix only what makes it skip.
3. Document in `scripts/native-tests/README.md`'s tool list.

## Acceptance

- `run.sh --list` shows `dogfood/registry-supply-chain … yes`; a full compose run executes it
  (PASS, not skip) — human's harness, branch-first; then the GitHub run on `develop` after merge.
- Gate: harness-only (`bash -n`, Dockerfile builds on the harness), audit/deny unconditional.
