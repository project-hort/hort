# 063 — #98: en-bloc batch 4 — RustCrypto new-generation move

**Issue:** #98 (spec on the issue is the contract; batch 4 of the #95 en-bloc plan,
re-sliced: password-hash and x509-cert/const-oid are upstream-blocked and deferred).
**Read first:** the #98 issue description; CLAUDE.md → *Pre-push Quality Checklist*;
rand 0.9/0.10 migration notes; ed25519-dalek 3 changelog; ecdsa 0.17/elliptic-curve
0.14 notes for the p256 bump.

## Work

1. Bump as ONE coupled set (workspace root + per-crate declarations):
   - `rand` 0.8 → 0.10 (workspace; consumers: hort-server, hort-worker, hort-app,
     hort-cli, hort-adapters-checkpoint-anchor)
   - `rand_core` 0.6 → 0.10 (`hort-adapters-provenance-cosign-key`)
   - `ed25519-dalek` 2 → 3 (workspace; consumers: hort-app,
     hort-adapters-checkpoint-anchor, hort-http-oci — keep `pkcs8`/`rand_core`/
     `pem` feature parity or the 3.x equivalents)
   - `p256` 0.13 → 0.14 (`hort-adapters-provenance-cosign-key`)
   - Rider: `rcgen` 0.13 → 0.14 (dev-only, 6 crates' test-TLS fixtures)
2. Scoped `cargo update` for the set + pulled-in transitives (curve25519-dalek 5,
   ecdsa 0.17, elliptic-curve 0.14, signature 3, getrandom 0.4). No unrelated drift.
3. Call-site migration, no behavioral change:
   - rand rename sweep (`thread_rng()`→`rng()`, `gen()`→`random()`, etc.)
   - dalek 3 fallout (keypair generation RNG now rand_core-0.10; pkcs8/pem surface)
   - cosign-key adapter: `p256::ecdsa::SigningKey` 0.17-generation fallout
4. **Signing/checkpoint/provenance surfaces**: existing suites pin the wire/verify
   contracts — assertions unmodified. Every compile-fixed site must be covered by
   an existing test; add the missing test if one is not.
5. Coupled-set rule: if any member (other than the rcgen rider) cannot land, STOP
   and report — no partial merge of the set. The rcgen rider may drop-and-report
   independently.
6. Attribution regen in the same change (ADR 0049); re-check every `# AUDIT-ONLY`
   marker (`cargo tree -i <crate> -e normal`, the rc.10 trap).

## Scope / acceptance

- Out of scope: `password-hash` 0.6 (argon2 0.6 still RC), `x509-cert` 0.3 /
  `const-oid` 0.10 (sigstore 0.14 pins the old generation), sha-family 0.11
  bumps, batches 5–7, deferred human decisions.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` — all
  in the report as evidence.
- Renovate !286/!287/!288/!292: no checkboxes; superseded/deferred as the issue
  describes.

**Model hint:** capable (cross-crate migration over signing/provenance surfaces;
correctness rides on the sweep being exhaustive and the coupled-set rule).
