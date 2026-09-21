# 174 — `unrecorded` is two opposite answers; split it

**Issue:** #226 · **Branch:** `agent/226-schema-compat` · Item 5 of 5
(depends on items 169, 170 and the documentation item 166).

## Problem

`SchemaRollbackFloor::Unrecorded` is emitted in two states that give an
operator **opposite** advice, and its own doc comment says so in its first
sentence before asserting only one of them:

> Every register row over the applied set is an expansion, **or** the register
> does not cover the migration at all.

- **Every applied migration is registered and every row is an expansion.**
  Nothing constrains the rollback; any binary carrying the boot gates will
  serve this schema. This is the *common* case — contractions are rare and
  batched, so most databases' whole history is expansions.
- **One or more applied migrations have no register row.** The register cannot
  answer, and the boot gates will fail closed on exactly those migrations.

The doc then states only the second reading, which makes it wrong on the
common case. The documentation item worked around this by describing both
readings in the operator-facing page, which is the right stopgap and the wrong
resting state.

**This is not a comment defect.** The whole purpose of the inspection answer is
that an operator can ask "how far back can I roll this database" before
attempting it. An answer that means both "as far as you like" and "I cannot
tell you, and the gates will refuse" does not answer the question. A value that
requires a second lookup to disambiguate is not an answer.

## Governing decisions

- **Issue #226** — the register exists to make the rollback bound exact. An
  ambiguous answer is not exact.
- **ADR 0015** — the same instinct one layer up: an operator-facing surface
  must be load-bearing, and one that cannot be acted on without a second
  investigation is not.

## Read first

- `crates/hort-config/src/schema_compat.rs` — `SchemaRollbackFloor`, its
  `Display`, `schema_rollback_floor`, and the `Unrecorded` doc comment quoted
  above.
- `crates/hort-server/src/migrate.rs` and `crates/hort-worker/src/composition.rs`
  — the boot lines carrying `tolerates_binaries_from`.
- `docs/architecture/how-to/deploy/upgrade.md` §4.1 — the prose that currently
  disambiguates the two readings by hand.

## What to build

Split the variant so each state carries its own value. Three outcomes, named
for what the operator should do:

| state | meaning |
|---|---|
| every applied migration registered, all expansions | nothing constrains the rollback |
| an applied migration has no register row | the register cannot answer; the gates fail closed on those migrations |
| a minimum is recorded | today's `Version` |

Name them for the operator's question, not for the register's internals — the
value is read off a boot line by someone deciding whether to roll back, and the
`Display` string is the whole interface. "unrecorded" must not survive as
either of the first two.

Then update:

- The doc comments, so each variant states its own meaning and neither carries
  the other's.
- `docs/architecture/how-to/deploy/upgrade.md` §4.1, which currently explains
  both readings of one value by hand. It should name the two outcomes instead
  and say what each means for the decision the operator is about to make.

## Explicitly not in this item

- Any change to the gates, the predicate, the register's contents, or what is
  refused. This is the *inspection* answer only; no boot decision reads it.
- Any new inspection surface. The boot line stays the surface.
- Any change to migration 025.

## Acceptance

- A database whose applied migrations are all registered expansions reports the
  unconstrained outcome, distinguishable at a glance from the cannot-answer
  outcome.
- A database with an applied migration lacking a register row reports the
  cannot-answer outcome.
- A recorded minimum still reports the version.
- No variant's documentation states another variant's meaning.
- The how-to names the outcomes rather than disambiguating one value in prose.
- No gate's behaviour changes; the boot refusal wordings are untouched.
- Full local gate green per the pre-push checklist, `cargo test --workspace`,
  with `DATABASE_URL` set and the skipped-for-no-database count reported.
