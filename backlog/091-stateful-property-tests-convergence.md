# 091 — #135 item 3: stateful property tests for lifecycle convergence

**Issue:** #135. Dispatched AFTER item 090 (asserts against the declared
tables as the reference model).

## Work

1. `proptest`-based stateful suite over `hort-domain` (pure Rust, zero I/O):
   random interleavings of ingest orders / verify timing / sweep ticks
   against invariants:
   (a) anti-stranding liveness — every artifact reaches terminal-or-released
       once its subject verifies;
   (b) never released without one of the five ADR 0007 authorities (+
       provenance clearance under Required);
   (c) never `Rejected` → `Released`;
   (d) idempotency under event replay.
2. New dev-dependency (`proptest`) ⇒ attribution regen
   (`scripts/regenerate-attribution.sh`) + `cargo audit`/`cargo deny` in the
   SAME change, per the dependency rules; re-check `# AUDIT-ONLY` markers.
3. Deterministic seeds in CI (no wall-clock/random-seed flakes); failure
   minimization output documented in the test module header.

## Scope / acceptance

- Runs via plain `cargo test --workspace`; runtime budget: the suite stays
  under ~60s locally (bound case count accordingly).
- Full pre-push suite (Rust + Cargo.lock diff).

**Model hint:** sonnet.
