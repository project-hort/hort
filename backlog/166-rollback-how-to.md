# 166 — separate additive rollback from contraction rollback in the upgrade how-to

**Issue:** #226 · **Branch:** `agent/226-schema-compat` · Item 2 of 2
(depends on item 165; one MR carries both).

## Problem

`docs/architecture/how-to/deploy/upgrade.md` §4 argues that automated rollback
makes things worse because migrations are forward-only, and that a failed
upgrade needs a human rather than a retry loop. That is correct for a
contraction and wrong by overreach for an additive migration — the case
ADR 0030's expand/contract discipline exists to protect.

The blanket phrasing is why no sanctioned rollback path was findable during
the #225 incident. An operator reading §4 concludes that rolling the binary
back is always harmful, when for an additive migration it is a supported
serving state.

## Read first

- `docs/architecture/how-to/deploy/upgrade.md` — §4 in full, and §2 for the
  two-step upgrade shape it references.
- `docs/adr/0030-*.md` — the guarantee being documented, and its bound.
- `backlog/165-schema-compatibility-predicate.md` — the behaviour this text
  describes must match what item 165 actually implements.
- The `Migration notice` convention the how-to already uses for flagged
  releases.

## What to write

Separate the two cases in §4 and give each its own guidance.

- **Additive migration.** Rolling the binary back one release is supported.
  After item 165, the previous release's binary starts against the newer
  schema: the migrate step verifies the shared prefix and applies nothing, and
  the serve path logs that it is running against a newer schema and proceeds.
  No `_sqlx_migrations` surgery, and none should ever be recommended.
- **Contraction.** Unchanged, and keep the existing warning intact. The schema
  does not roll back, and an automated rollback into a contracted schema
  produces exactly the failure the Migration notice warns about. Suspending
  remediation remains the guidance.

State how far back is supported, in the operator's terms, and describe the
mechanism that decides it rather than a fixed number. Item 169 adds a register
that records, per applied migration, the oldest binary version it tolerates, so
the boot gate answers the question exactly: a rollback across nothing but
expansions is accepted however many releases back it goes, and a rollback
across a contraction is refused with the migration and the required version
named. Write the how-to against that behaviour, not against a one-release rule.

Tell the operator where to ask the question before attempting the rollback,
using whichever inspection surface item 169 exposes it on.

Also state what the boot gate now refuses, so the failure mode is recognisable
before it is hit: a migration history with a gap below the waterline, or a
checksum divergence on a shared-prefix migration, is refused by both gates and
is a genuinely broken database rather than a version skew.

## Two register doc sentences went stale with the backfill

`crates/hort-config/src/schema_compat.rs` says, twice, that **"rows exist only
from the release that introduced the register onwards"** — once on the
`SchemaCompatRegister` type alias and once inside `register_from_rows`'s
bootstrapping paragraph.

That was true when the register recorded only what a run applied. After the
backfill it is not: a register-carrying binary writes a row for every migration
it embeds, so an upgraded database gets a register covering its whole history
on the next `migrate`, not merely the part from the introducing release onward.

The implementer of that change argued the sentence is about *when* a
register-carrying binary starts writing rather than *which* rows exist. That
reading is available, but the sentence as written says "rows exist only from …
onwards", and a reader consulting the register's own documentation would
conclude an upgraded database has a partial register — which is exactly the gap
the backfill closed. Correct both.

The surrounding argument in `register_from_rows` stays sound and should not be
rewritten: bootstrapping still self-resolves, a rollback target predating the
register still has no register logic and is still governed by the structural
gate alone, and a downgrade-then-migrate is still the only route to an
applied-but-unembedded migration with no row. Only the opening claim about
which rows exist is wrong.

## One ADR sentence went stale

`docs/adr/0009-*.md`'s *Alternatives considered* says a stale binary against a
newer schema (or the reverse) would run silently, and that `assert_current`
makes it fail fast. The reverse half still holds. The newer-schema half does
not: that is now an accepted-and-warned state.

Amend that sentence to describe what the gates do after items 165 and 169.
ADR 0009's own decision — no DDL on the serve path — is untouched and still
enforced, so this is a correction to a supporting note, not a reversal. Do not
restate the whole boot-gate model there; ADR 0030 and this issue's own record
carry it, and 0009 only needs to stop asserting something that is no longer
true.

Check `docs/architecture/how-to/deploy/local-bringup.md`'s "refuses to start
against a stale schema" line while you are there; it was accurate as written
and should stay that way, but say in the report whether it still is.

## Explicitly not in this item

- Any code change.
- Any change to §2 or the Flux remediation guidance for contractions.
- A new page. This is an edit to the existing how-to.

## Acceptance

- §4 distinguishes additive from contraction, with the additive rollback path
  stated as supported and the contraction warning preserved verbatim in
  substance.
- The supported window is described as the register computes it, not as a
  fixed number of releases, and the how-to says where to ask before rolling
  back.
- The two refusal modes are named.
- No `_sqlx_migrations` hand-editing appears anywhere as advice.
- ADR 0009's stale alternatives sentence is corrected without touching its
  decision, and the local-bringup line is reported on.
- Both "rows exist only from the release that introduced the register onwards"
  sentences are corrected, and `register_from_rows`'s bootstrapping argument is
  otherwise left intact.
- The described behaviour matches item 165's implementation; if it does not,
  the code is the thing to fix, not the prose.
