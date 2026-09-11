# 165 — one schema-compatibility predicate, adopted by both boot gates

**Issue:** #226 · **Branch:** `agent/226-schema-compat` · Item 1 of 2
(item 166 corrects the upgrade how-to; one MR carries both).

## Problem

Four call sites hold a strictness rule about the same question — which
(binary version, schema version) pairs are supported — and answer it
differently:

- `Migrator::run` (via `migrate::run`, the `migrate` subcommand) requires the
  binary to embed every applied migration, and fails with
  `MigrateError::VersionMissing` otherwise.
- `migrate::assert_current` requires `MAX(version)` to equal the binary's
  maximum embedded version exactly, and bails on `applied > expected` as well
  as `applied < expected`. It is called from `cli::serve` and twice from
  `cli::admin`.

Neither answer is derived from the decision that governs the question. The
consequence is that a binary rollback N → N-1 cannot boot after any upgrade
that shipped a migration, even a purely additive one, although ADR 0030
guarantees the N-1 binary *serves* that schema correctly.

Fixing only the migrate runner would not unblock the rollback: the migrate
step would pass and `assert_current` would still refuse to serve. That is why
this item builds a shared predicate rather than a second tolerance switch.

## Governing decisions

- **ADR 0030 (expand/contract)** answers the question. A schema newer than the
  binary is a supported serving state by construction: a contraction ships
  only in a release strictly after the last release whose code referenced the
  identifier, so the immediately preceding release's binary never references
  anything a contraction removed. A schema older than the binary is not
  supported — those are pending migrations.
- **ADR 0022 (frozen migrations)** — the shared prefix is immutable, which is
  what makes checksum validation of it meaningful and what makes a
  below-the-waterline discrepancy a genuine defect rather than a version skew.
- **ADR 0009** — the serve path uses a least-privilege runtime DSN and must
  not issue DDL. `assert_current` deliberately does not create the bookkeeping
  table. Reading the full applied set is still only a `SELECT` and stays
  within that constraint; do not regress it into a `CREATE TABLE IF NOT
  EXISTS`.

## Read first

- `crates/hort-server/src/migrate.rs` in full — `MIGRATOR`, `run`,
  `assert_current`, `map_assert_current_db_err`, `pending_migration_versions`.
  Note that `pending_migration_versions` already reads the applied set through
  `list_applied_migrations`, which is most of the machinery this item needs.
- `crates/hort-server/src/cli/serve.rs` and `crates/hort-server/src/cli/admin.rs`
  — the three `assert_current` call sites.
- `deploy/ansible/roles/hort_systemd/templates/hort-migrate.service.j2` and
  `hort-server.service.j2` — the `Requires=` chain that makes every start
  re-run migrate.
- `deploy/helm/hort-server/templates/job-migrate.yaml` — the same shape as a
  `pre-upgrade` hook.
- `docs/adr/0030-*.md`, `docs/adr/0022-*.md`, `docs/adr/0009-*.md`.

## What to build

A single predicate — name it for what it answers, not for where it is called
— that takes the applied version set and the embedded version set and returns
a three-way verdict:

| relation | verdict |
|---|---|
| embedded ⊆ applied, every extra strictly newer than `max(embedded)` | **supported**: binary older than schema, nothing to apply |
| applied ⊂ embedded | **pending**: migrations to apply, the normal upgrade path |
| an applied version absent from embedded *below* `max(embedded)`, or an embedded version unapplied *below* `max(applied)` | **divergent**: refuse |

The third row is the real value of today's strictness and must not be lost. A
gap below the waterline is a broken history, not a version skew.

Put the predicate in the domain-appropriate place for a pure set computation
with no I/O, and unit-test it exhaustively there. Both gates then consume it:

**Gate 1, the migrate runner.** On `supported`, run with
`ignore_missing` enabled so `VersionMissing` no longer aborts. Do not
short-circuit the run: in this state every embedded migration is already
applied, so `run` applies nothing and reduces to checksum verification of the
shared prefix, which is a property worth keeping. On `divergent`, refuse
before calling `run`, with a message that names the offending versions.

**Gate 2, `assert_current`.** Replace the `applied != expected` comparison
with the predicate. `supported` proceeds and logs that the binary is running
against a newer schema, at a level an operator will actually see. `pending`
keeps today's operator-actionable message. `divergent` refuses.

`assert_current` currently reads only `MAX(version)` and now needs the full
applied set. Keep it `SELECT`-only.

## sqlx facts this rests on (verified against v0.9.0 source, do not re-derive)

- `ignore_missing` suppresses exactly one error, `MigrateError::VersionMissing`.
- Checksum validation of versions present in both sets is **unaffected**:
  `ignore_missing` is read only by `validate_applied_migrations`, which checks
  presence and never touches checksums. `MigrateError::VersionMismatch` still
  fires.
- `MigrateError::Dirty` is evaluated before, and independently of, the flag.
- The flag alone is weaker than this item needs — it tolerates any
  applied-but-not-embedded version including a mid-sequence gap, and permits
  out-of-order application. That is exactly why it sits **behind** the
  predicate rather than replacing it. Do not enable it unconditionally.
- `Migrator` is not `Clone` and `set_ignore_missing` takes `&mut self`, so it
  cannot be applied to a `pub static`. Either assign the field inside the
  static's const initializer or build an owned `Migrator` from the macro at
  the call site. Choose one, and say in the commit body why.

## Explicitly not in this item

- The upgrade how-to correction (item 166).
- Schema rollback. Migrations stay forward-only.
- Any change to the expand/contract authoring guard or
  `migrations/CONTRACTIONS.toml`.
- The runtime fleet fence, which solves a different ordering problem and is
  unaffected. Do not fold the two together.
- Enforcing how many releases back a rollback may go. The binary has no map
  from release to schema version; that bound is documented in item 166, not
  checked in code.

## Acceptance

- One predicate, one definition, consumed by both gates. No second copy of the
  rule anywhere.
- A binary whose embedded set is a strict prefix of the applied set starts:
  migrate succeeds, `assert_current` passes, `serve` comes up.
- A binary with pending migrations still applies them, unchanged.
- A mid-sequence gap in either direction is refused by both gates, with the
  offending versions named.
- A checksum divergence on a shared-prefix migration still fails, with
  `ignore_missing` enabled.
- `assert_current` issues no DDL.
- Exhaustive unit coverage of the predicate, every row and every boundary,
  with no database.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
