# 170 — register every migration the binary embeds, not only the ones this run applied

**Issue:** #226 · **Branch:** `agent/226-schema-compat` · Item 4 of 4
(depends on item 169; item 166's prose is written after this and must describe
the behaviour this item leaves behind).

## Problem

Item 169 writes one register row per migration **that run applied**. That
followed my backlog item's wording, and the wording was wrong. Two consequences,
one cosmetic and one that defeats the point of the feature.

**The inspection answer is empty exactly where it is needed.** Rows exist only
from the release that introduces the register onward, so on any *upgraded*
database — which is every existing production instance, including the public
dogfood — every already-applied migration is unregistered. `schema_rollback_floor`
therefore reports `unrecorded` rather than a version. A fresh install gets a
complete answer; a real deployment gets nothing. The question that motivated
this whole issue is "how far back can I roll *this* database", and on the
databases anyone would ask it about, the answer would be silence for several
release cycles.

**A crash between the migration commit and the register insert is permanent.**
That migration stays unregistered forever, and a later rollback past it is
refused fail-closed with the generic "absent from the register" message instead
of a version an operator can act on. Correct, but needlessly unhelpful.

## Why backfilling is sound, not a guess

The binary holds `migrations/CONTRACTIONS.toml` compiled in, so for **every
migration it embeds** it already knows authoritatively whether that migration
was a contraction and what its `reference_removed_in` is. Writing that is
restating a fact the binary carries, not inferring one it lacks.

ADR 0022 makes migrations frozen, so an entry cannot later become wrong.
`ON CONFLICT (version) DO NOTHING` preserves any row that already exists, so a
backfill never overwrites a value written by the release that shipped the
migration.

This does **not** weaken the fail-closed rule. A migration the binary does
*not* embed still cannot be registered by it, and still counts as intolerable
when it appears among the applied-but-not-embedded set. Only the binary's own
migrations gain rows, and about those it is the authority.

## Governing decisions

- **ADR 0022 (frozen migrations)** — what makes a backfilled row permanently
  correct.
- **ADR 0030** — the manifest whose entries are being restated; unchanged.
- **ADR 0009** — the write stays on the migrate path under the DDL role. The
  serve path still only reads, still issues no DDL.
- **Issue #226** — the register exists to make the rollback bound exact. An
  answer that is empty on upgraded databases does not deliver that.

## Read first

- `crates/hort-server/src/migrate.rs` — the current register write, which
  scopes itself to the migrations this run applied.
- `crates/hort-server/src/contractions.rs` —
  `contraction_minimum_binary_versions()`, the single production reader of the
  manifest.
- `crates/hort-config/src/schema_compat.rs` — `MigrationTolerance`,
  `SchemaCompatRegister`, `schema_rollback_floor` and its `Unrecorded` doc
  comment, which currently documents the caveat this item removes.
- `an_upgrade_registers_only_what_it_applies` — the test that pins today's
  behaviour and must be replaced by its inverse.

## What to build

On the migrate path, after migrations are applied, write a register row for
**every migration the binary embeds**, not only those this run applied. Same
statement shape, same `ON CONFLICT DO NOTHING`, same role.

Update `schema_rollback_floor`'s `Unrecorded` documentation: after this item it
means "this database has never been migrated by a binary carrying the register",
not "this database was upgraded rather than freshly installed".

## Explicitly not in this item

- Registering a migration the binary does not embed. It has no manifest entry
  for one and must not invent a tolerance.
- Any change to the fail-closed rule, the refusal wordings, or the predicate.
- Any DDL on the serve path.
- Item 166's prose. It comes after this and describes the result.

## Acceptance

- A database whose migrations were all applied before the register existed gets
  a complete register on the next `migrate`, and `schema_rollback_floor` then
  reports a version rather than `unrecorded`.
- An existing row is never overwritten.
- A migration the binary does not embed gains no row.
- The crash window closes: a migration applied but unregistered is registered by
  the next migrate run.
- `an_upgrade_registers_only_what_it_applies` is replaced by its inverse, named
  for what it now asserts.
- Full local gate green per the pre-push checklist, `cargo test --workspace`,
  with `DATABASE_URL` set and the skipped-for-no-database count reported as 0.
