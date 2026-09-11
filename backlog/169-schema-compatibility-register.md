# 169 — the schema compatibility register: how far back is answerable, not assumed

**Issue:** #226 · **Branch:** `agent/226-schema-compat` · Item 3 of 3
(depends on item 165; item 166's prose must match what this ships).

## Problem

Item 165's predicate accepts any schema strictly newer than the binary, and
item 166 documents a one-release bound the gate cannot check. That bound is a
proxy, and it is a lossy one: it refuses rollbacks that are provably safe.

An older binary fails against a newer schema for exactly one reason — among the
applied migrations it does not embed, one was a **contraction** that removed
something it still references. Expansions are harmless however many there are.
Five releases without a contraction are as safe as one. A fixed bound throws
that away.

## The knowledge already exists, in the wrong place

`migrations/CONTRACTIONS.toml` records, per destructive migration, the
identifiers it removes and `reference_removed_in` — "the release whose code no
longer references these identifiers". That is exactly *the oldest binary
version this migration tolerates*, and the build-time expand/contract guard
already forces every entry to name precisely what its SQL does, so the data is
enforced rather than aspirational.

The binary can read that manifest only for migrations it embeds. Future
migrations are exactly the ones a rollback cares about. So the schema must
carry the knowledge instead.

## Governing decisions

- **ADR 0030** — the manifest, the guard, and the expand/contract policy this
  register makes machine-readable at boot. The register does not restate the
  policy; it carries the policy's own recorded answer forward in time.
- **ADR 0022 (frozen migrations)** — a migration's contraction status is
  immutable once applied, which is what makes a written row trustworthy
  forever.
- **ADR 0009** — the serve path uses a least-privilege runtime DSN and issues
  no DDL. Reading the register is a `SELECT`; writing it happens only on the
  migrate path, under the DDL role.
- **Issue #226** — the register replaces the documented one-release bound. It
  does not widen what is *safe*; it stops refusing what was already safe.

## Read first

- `migrations/CONTRACTIONS.toml` — the header block documents every field,
  including why `reference_removed_in` is a plain `X.Y.Z`.
- `crates/hort-app/tests/expand_contract_guard.rs` — how the manifest is
  parsed and validated today. Reuse that parsing rather than writing a second
  reader.
- `crates/hort-server/src/migrate.rs` — `run`, `assert_current`,
  `pending_migration_versions`, and item 165's predicate.
- `backlog/165-schema-compatibility-predicate.md` — the predicate this extends.
- `crates/hort-config/src/pg_identity.rs` — `parse_version_core`, the existing
  version comparison used by the fleet fence. Reuse it; do not add a second
  version parser.

## What to build

**The register.** A hort-owned table, one row per applied migration version,
carrying the minimum binary version that migration tolerates. `_sqlx_migrations`
belongs to sqlx and must not be extended, so this is separate. An expansion
records no minimum; a contraction records its `reference_removed_in`.

**Written at migrate time**, by the binary applying the migration — which ships
that migration and therefore holds its manifest entry. The write is part of the
same operation that applies the migration, not a later reconciliation.

**Read by the predicate.** Item 165's `supported` verdict gains a second
condition: over the applied migrations the binary does not embed, take the
maximum minimum-binary-version and compare against this binary's own version.
Above it, `supported`. Below it, refuse — and the refusal names the migration
and the version from which it would work. That message is the whole point;
an operator hitting it mid-incident must learn what to do from the message
alone.

**Fail closed on the unknown.** An unembedded applied migration with no
register row is treated as a contraction requiring a version this binary does
not have. Silence is not evidence of an expansion.

**Bootstrapping is self-resolving and must be stated in code.** Rows exist only
from the release introducing the register. A rollback target predating it has
no register logic and uses the strict gate; that is correct and needs no
special case. The only path to an unembedded-and-unregistered migration is a
downgrade-then-migrate, which the fail-closed rule already covers.

**One operator-facing consequence worth taking.** Once the register exists the
server can answer directly how far back the current schema tolerates. Expose it
wherever the existing schema/version inspection surface lives — do not invent a
new endpoint or a new command for it. This is the question the 0.12.3 incident
actually posed and that nothing can answer today.

## Explicitly not in this item

- Any change to `CONTRACTIONS.toml`'s format, the expand/contract guard, or the
  policy itself.
- Any attempt to infer contraction status from SQL at runtime. The manifest is
  the authority and it is checked at build time; re-deriving it at boot would
  be a second, weaker answer to a settled question.
- Schema rollback. Migrations stay forward-only.
- A second version parser or a second manifest reader.

## Acceptance

- A binary whose unembedded applied migrations are all expansions starts,
  however many releases back it is.
- A binary below a contraction's `reference_removed_in` is refused, by both
  gates, with the migration and the required version named in the message.
- An unembedded applied migration with no register row is refused.
- A pure upgrade path is unaffected: applying migrations writes register rows
  and changes no existing behaviour.
- The register is written under the migrate role only; `assert_current` reads
  it with `SELECT` and issues no DDL.
- The "how far back does this schema tolerate" answer is reachable from an
  existing inspection surface.
- Item 166's prose is updated in the same change to describe the register
  rather than a documented bound. The two must not disagree.
- Exhaustive unit coverage of the extended predicate, with no database.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
