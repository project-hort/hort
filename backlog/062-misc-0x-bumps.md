# 062 — #97: en-bloc batch 3 — misc 0.x requirement bumps

**Issue:** #97 (spec on the issue is the contract; batch 3 of the #95 en-bloc plan).
**Read first:** the #97 issue description; CLAUDE.md → *Pre-push Quality Checklist*
(attribution + audit/deny + AUDIT-ONLY marker rules) and *DB-backed test isolation*
(the `#[serial(hort_pg_db)]` contract — load-bearing for the serial_test bump).

## Work

1. Bump `Cargo.toml` requirements (workspace root + every per-crate declaration):
   `base64` 0.22 → 0.23, `governor` 0.8 → 0.10, `object_store` 0.13 → 0.14,
   `zip` 2 → 8, `serial_test` 3 → 4, `clap_complete` `=4.5.55` → `=4.6.8`.
2. `cargo update` for the bumped crates only, plus the lockfile rider
   `cargo update -p ipnet --precise 2.12.1`. No unrelated lock drift.
3. Fix small mechanical API fallout at the call sites:
   - `governor`: `crates/hort-http-core/src/middleware/rate_limit.rs`
   - `object_store`: `crates/hort-adapters-storage/src/*`,
     `crates/hort-adapters-checkpoint-anchor/src/lib.rs`
   - `zip`: `crates/hort-formats/src/{archive_bounds,test_support}.rs`,
     `crates/hort-adapters-advisory-osv/src/bulk.rs`
   - `serial_test`: attribute-macro call sites — **`#[serial(hort_pg_db)]` key
     semantics must survive byte-identical** (parallel-safety contract).
4. **Drop-and-report rule:** any bump demanding more than small mechanical
   call-site fixes gets dropped from the batch and noted in the report (it
   becomes its own later batch) — do NOT absorb a real migration here.
5. No behavioral changes; existing suites pin the contracts and pass unmodified
   except mechanical API-rename fallout inside test code.
6. Regenerate `THIRD-PARTY-LICENSES.{md,json}` in the same change (ADR 0049);
   re-check every `# AUDIT-ONLY` marker with `cargo tree -i <crate> -e normal`
   (the rc.10 trap) — mirror to `deny.toml` if anything became active-reachable.

## Scope / acceptance

- One MR from this branch. Renovate !282/!283/!285 auto-close post-merge; no
  dashboard checkboxes.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` — all
  in the report as evidence.
- `bergshamra`/`cron`/`lettre` are NOT in this batch — dead entries removed in !293.

**Model hint:** small model (mechanical), escalate to capable only if the zip 2→8
fallout turns out non-trivial (then likely drop-and-report instead).
