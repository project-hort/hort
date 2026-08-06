# 071 — #125: shared-DB test pools must migrate — fix the replay_guard CI failure + close the pattern

**Issue:** #125 (release-blocker: `v0.10.0-alpha.1` tag pipeline #5227 red at
`test:integration`, job #44764 — 4 `replay_guard_repo` tests fail on the fresh CI
database with `relation "jwt_replay_seen" does not exist`).

**Read first:** the root-cause analysis on #125;
`crates/hort-adapters-postgres/src/test_support.rs` (module docs + `isolated_db_from`
— note its migrate-with-retry loop and why per-test DBs migrate themselves);
`crates/hort-adapters-postgres/src/replay_guard_repo.rs:193` (`test_pool()` — connects,
never migrates); `retention_scan_reader.rs:293` (the correct sibling shape: connect,
then `sqlx::migrate!("../../migrations").run(&pool)`); CLAUDE.md → *DB-backed test
isolation* (the `#[serial(hort_pg_db)]` contract).

## Verified defect map (architect sweep, all inline `#[cfg(test)]` direct-connect sites)

| File | Connect sites | Migrate calls | State |
|---|---|---|---|
| `replay_guard_repo.rs` | 1 | 0 | **fails in CI** (runs before any migrator in serial name order) |
| `sbom_components.rs` | 1 | 0 | latent — passes only because `s…` sorts after `retention…`'s migrator |
| `scan_findings_repository.rs` | 3 | 2 | one site unmigrated (the `insert_batch(&[])` early-return test at ~:196) |
| `retention_scan_reader.rs` | 1 | 1 | correct |

## Work

1. **Add a shared helper instead of a third ad-hoc copy:** in `test_support.rs`, add a
   `shared_migrated_pool() -> Option<PgPool>`-shaped helper (name per crate convention)
   that reads `DATABASE_URL`, connects, and runs `sqlx::migrate!("../../migrations")`
   with the same bounded-retry shape `isolated_db_from` already uses (the thundering-
   herd rationale documented there applies identically to the shared DB). Self-skip
   semantics unchanged: `None` when `DATABASE_URL` is unset/unreachable.
2. **Route all four modules** (`replay_guard_repo`, `sbom_components`,
   `scan_findings_repository` — all three sites — and `retention_scan_reader`) through
   the helper, deleting the per-module `test_pool()`/inline connect+migrate copies.
   This removes the serial-name-order coupling entirely — no shared-DB test may depend
   on an earlier-sorting module having migrated first.
3. **Do not** convert these to `isolated_db_from`: they exercise shared-DB behavior
   under the `#[serial(hort_pg_db)]` contract and the migration cost per throwaway DB
   is the documented reason the shared pool exists. Keep `#[serial(hort_pg_db)]` on
   every touched test.
4. **Sweep confirmation in the report:** grep evidence that no other inline or
   `tests/`-target site in `hort-adapters-postgres` (and `hort-adapters-storage`, same
   contract) connects to `DATABASE_URL` without either migrating or going through
   `isolated_db_from`/the new helper.

## Scope / acceptance

- Test-support and test code only — zero production-code change.
- The four #5227-failing tests pass against a **freshly-created** database (verify:
  point `DATABASE_URL` at a new empty DB in the sandbox and run
  `cargo test -p hort-adapters-postgres --lib` — this reproduces CI's fresh-service
  condition; cite the run in the report).
- Local DB-less `cargo test --workspace` stays green (self-skip preserved).
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check`.

**Model hint:** sonnet (mechanical, pattern established in-repo; the fresh-DB
reproduction is the one non-trivial verification step).
