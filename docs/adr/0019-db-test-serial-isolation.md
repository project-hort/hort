# 0019 — DB-backed tests share one database and must serialize

- **Status:** Accepted
- **Enforced by:** mandatory review check — every `hort-adapters-postgres` (and `hort-adapters-storage`) test that acquires a real connection (`maybe_pool()` / touches the shared DB) must carry the crate-wide `#[serial(hort_pg_db)]` key (or equivalent isolation). A DB-gated test without it is a hard block. Not compile- or lint-enforced; it is a manual review gate.
- **Supersedes:** —

## Context

The DB-backed test suites — inline `#[cfg(test)]` `--lib` tests and `tests/` integration tests — run **in parallel against one shared database with no per-test isolation** (no transaction rollback, no schema-per-test, no truncation). Several adapters do global-scope work (the `save_managed` gitops-partition full-reconcile, `pg_stat_activity` probes, unfiltered `COUNT`/`list_*`). A test that is correct serially but runs concurrently with a sibling doing global-scope work corrupts both — coverage % is necessary but not sufficient.

Production tolerates these global-scope adapters because the only writer is single-flight by design (gitops apply is single-process per boot lock). Tests must honour that same contract.

## Decision

Every new DB-backed test that acquires a real connection carries the crate-wide **`#[serial(hort_pg_db)]`** key (or an equivalent per-test isolation mechanism). This serializes them against each other so the global-scope adapters see the single-writer condition they assume in production. A DB-gated test missing the key is a blocking review finding — it silently reintroduces the identity-shifting flake fixed in `ed79360a`.

## Consequences

- DB tests run correctly under the shared-DB, parallel-suite model without per-test isolation infrastructure.
- The review check is mandatory and human (no lint catches it), so it is called out explicitly in the implementation review checklist.
- DB-free structural guard tests are unaffected and stay in the fast per-push gate.

## Alternatives considered

- **Per-test transaction rollback / schema-per-test / truncation.** Rejected (at present): heavier harness, and it would mask rather than honour the single-writer contract that production actually relies on; serialization mirrors production exactly.
- **Rely on coverage % alone.** Rejected: a test can be fully covering and still corrupt a concurrent sibling; coverage does not detect cross-test interference.

## References

- CLAUDE.md → Test Coverage Tiers → "DB-backed test isolation (parallel-safety contract)".
- `crates/hort-adapters-postgres/` tests; commit `ed79360a` (the flake fix).
- The architect skill → anti-pattern *DB-backed test without `#[serial(hort_pg_db)]`*.
