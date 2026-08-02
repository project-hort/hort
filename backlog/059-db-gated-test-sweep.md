# 059 — #94: DB-gated test sweep — fix, unify on self-skip, remove obsolete; CI runs everything

**Issue:** #94 (direction confirmed by the human on the issue: include and/or fix all
relevant tests, remove deprecated/superseded/obsolete ones — no test population left
silently ignored).
**Read first:** `crates/hort-adapters-postgres/src/jobs_repository.rs:1593-1610` (the
broken test) and `migrations/009_scan_jobs_and_findings.sql:118-121` (the
`trigger_source` CHECK — allowed: `manual, cron, advisory, ingest, seed-import,
prefetch, self_service, scheduled`); `event_store.rs:2459+` (`b9_db_tombstone_…`);
`.gitlab-ci.yml:624-662` (`test:integration` — provisions Postgres + `DATABASE_URL`
but runs `cargo test --workspace --tests` with NO `--include-ignored`, so every
`#[ignore]`-attributed test is skipped in CI); the existing runtime **self-skip**
pattern used by the DB-gated `tests/` targets (grep for the `DATABASE_URL`
early-return / "ignored, requires DATABASE_URL" reporting the CLAUDE.md gate section
describes); CLAUDE.md → *DB-backed test isolation* (the `#[serial(hort_pg_db)]`
contract).

## Findings settled on #94

1. `enqueue_task_inserts_row_and_returns_uuid` is a **test defect**: enqueues
   `trigger_source: "integration-test"`, which the schema CHECK forbids —
   deterministic failure on any correctly-migrated DB. It is also missing
   `#[serial(hort_pg_db)]`.
2. **CI never runs the `#[ignore]`-attributed DB tests at all** (no
   `--include-ignored`), which is why (1) rotted undetected.
3. `b9_db_tombstone_append_failure_aborts_delete_no_rows_removed` fails in
   single-test isolation against the cockpit-sandbox DB — undiagnosed; needs a
   freshly-migrated-DB reproduction (it too has never run in CI).

## Work

1. **Fix (1):** use an allowed `trigger_source` (`'manual'`), add
   `#[serial(hort_pg_db)]`.
2. **Diagnose (3) against a freshly-migrated database** (this container has
   `DATABASE_URL`): if the test's assumptions are wrong → fix the test; if it
   exposes a real adapter defect → STOP and report (the fix is a separate,
   code-owning item — do not bundle a production-code change into this sweep).
   If it is a sandbox-DB-template artifact → document the reproduction and the
   evidence in the report and fix the template assumption in the test if possible.
3. **Unify the whole DB-gated inline population on the runtime self-skip pattern**
   (the convention the pre-push gate documentation already assumes): every
   `#[ignore = "requires DATABASE_URL"]`-attributed test in
   `hort-adapters-postgres` / `hort-adapters-storage` inline suites either
   - converts to the canonical self-skip shape (runs under plain `cargo test`
     when `DATABASE_URL` is set; clean skip + report otherwise; keeps/gains
     `#[serial(hort_pg_db)]`), or
   - is **removed** as deprecated/superseded/obsolete — one justification line
     per removed test in the report (e.g. superseded by a sibling `tests/`
     integration target covering the same behavior). When in doubt, convert —
     removal is for genuine duplication/obsolescence, not for inconvenient tests.
   After the sweep, `#[ignore]` remains only where something other than
   `DATABASE_URL` genuinely requires it (expected: none).
4. **CI effect:** with the self-skip unification, `test:integration` runs the
   whole population automatically — no `--include-ignored` flag, no divergence
   between local `cargo test --workspace` and CI. Verify in the report: run the
   suite once WITH `DATABASE_URL` (all DB tests execute; count them) and once
   WITHOUT (all self-skip; 0 failures) — both counts in the gate evidence.

## Scope / acceptance

- No production code changes (a real defect found under (2) is reported, not fixed here).
- Every DB-touching test carries `#[serial(hort_pg_db)]` after the sweep — zero
  exceptions; this is the item that retires the "no lint enforcement" caveat by
  making the population auditable.
- Local DB-less `cargo test --workspace` stays green and DB-free (gate contract).
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` (with AND without `DATABASE_URL`), `cargo audit --deny
  warnings`, `cargo deny check`.

**Model hint:** small model ok (mechanical sweep + one bounded diagnosis; stop-and-report
on any real defect).
