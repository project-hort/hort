# 0019 — DB-backed tests share one database and must serialize

- **Status:** **Retired 2026-10-11 — folded into `CLAUDE.md`** → *Test Coverage
  Tiers* → "DB-backed test isolation (parallel-safety contract)".
- **Supersedes:** —

## Why this was retired

The decision stands; this record does not. `CLAUDE.md` carries the same rule in
a form this page had fallen behind on, and keeping two versions of one contract
was costing accuracy rather than buying findability:

- **Scope.** This page required the key of *"every `hort-adapters-postgres`
  (and `hort-adapters-storage`) test"*. That crate-scoped wording is exactly
  how 29 `hort-server` / `hort-worker` tests ran unkeyed — they fell through
  the wording, not the reasoning. The rule is crate-agnostic: every test in the
  workspace that acquires a real Postgres connection carries
  `#[serial(hort_pg_db)]`.
- **Enforcement.** This page said *"Not compile- or lint-enforced; it is a
  manual review gate"*. It is enforced:
  `crates/hort-app/tests/db_tests_are_serialized.rs` is a DB-free source scan
  with **no allow-list**, and it runs in the ordinary `cargo test --workspace`.
- **Reach of the mechanism.** `CLAUDE.md` records what the key actually
  reaches, measured: `serial_test` without `file_locks` is a *process-local*
  lock, so it orders tests within one binary and relies on cargo running test
  binaries sequentially — which a move to a parallel runner would void
  silently. That was never on this page.

Retired under the maintainer's 2026-10-11 direction: an ADR sets strategic
architectural direction, and a design detail that a better-maintained document
already carries should not have a second home. The number is not reused, and
this stub stays so existing citations resolve and forward the reader.

## Where it lives now

- `CLAUDE.md` → *Test Coverage Tiers* → "DB-backed test isolation
  (parallel-safety contract)" — the three harness modes, the measured reach of
  the serial key, the guard, and the two reasons the rule holds on both the
  shared and the isolated path.
- `crates/hort-app/tests/db_tests_are_serialized.rs` — the enforcement.
- The architect skill → anti-pattern *DB-backed test without
  `#[serial(hort_pg_db)]`*.
