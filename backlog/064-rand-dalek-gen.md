# 064 — #99: en-bloc batch 4b — rand 0.10 + rand_core 0.10 + ed25519-dalek 3

**Issue:** #99 (spec on the issue is the contract; severed from #98 per report 049 —
read that report in `handover/archive/049-98-rustcrypto-new-gen-report.md`: it
contains the already-validated full fix set for exactly this scope).
**Read first:** the #99 issue description; report 049 §2 (the call-site inventory);
CLAUDE.md → *Pre-push Quality Checklist*.

## Work

1. Bump: `rand` 0.8 → 0.10 (workspace), `ed25519-dalek` 2 → 3 (workspace; keep
   `pkcs8`/`rand_core`/`pem` feature parity or 3.x equivalents). **`p256` stays
   0.13** (upstream-blocked, see #98).
2. `hort-adapters-provenance-cosign-key`: its direct `rand_core` 0.6 dep exists to
   feed `p256` 0.13's `SigningKey::random` — it may STAY at 0.6 if that is the
   clean solution for the dual-generation seam (p256 0.13 gen alongside dalek 3
   gen). Report 049 used `rand_core::UnwrapErr(getrandom::SysRng)` + the
   `sys_rng` feature under p256 0.14; with p256 0.13 retained, re-derive the
   minimal clean shape. **If the seam cannot compile cleanly without feature
   hacks, STOP and report.**
3. Call-site migration per report 049's validated sweep (~25 sites: hort-app,
   hort-http-oci, hort-cli, hort-worker, hort-server,
   hort-adapters-checkpoint-anchor, cosign-key): `thread_rng()`→`rng()`,
   `gen()`→`random()`, `rand_core::OsRng` removal on the dalek/rand paths.
   No behavioral change; signing/verification suites pass with assertions
   unmodified.
4. Scoped `cargo update` (expected: curve25519-dalek 5, signature 3,
   getrandom 0.4). No unrelated lock drift.
5. Every compile-fixed site covered by an existing test; add missing coverage.
6. Attribution regen in the same change (ADR 0049); `# AUDIT-ONLY` re-check
   (`cargo tree -i <crate> -e normal`).

## Scope / acceptance

- Out of scope: `p256` 0.14, `x509-cert`/`const-oid`, `password-hash`,
  sha-family 0.11, batches 5–7, deferred human decisions.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` — all
  in the report as evidence.
- Renovate !287/!288 resolve on merge; no dashboard checkboxes.

**Model hint:** capable (signing-surface migration; the dual-generation seam in
cosign-key needs judgment).
