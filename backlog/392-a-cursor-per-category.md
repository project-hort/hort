# 392 — The delivery cursor has one writer and only moves forward

**Issue:** #311 · **Branch:** `agent/311-a-cursor-per-category` · single item.

**Governing decisions:** ADR 0061 (the delivery guarantee *and* the decision
about the cursor's shape — read its Decision section, point 2, not only its
guarantee sentence) · #296 (the merged read that closed the other half).

## What this item originally claimed, and why that half is void

This item was first written as two halves: (1) one persisted scalar cannot
serve a filter spanning several categories, and (2) the write is not
monotonic. **Half 1 is not a defect, and the schema change this item
originally specified is the alternative ADR 0061 weighed and declined.**

ADR 0061's Decision, point 2, in its own words: one pass reads the filter's
categories as one `global_position`-ordered stream, *"which is what makes the
single persisted `last_delivered_position` scalar correct by construction
rather than approximately correct: a position at or below the mark has been
read in every subscribed category […] **Per-category persisted positions
would also close it, at the cost of a schema change to `subscriptions` and a
cursor whose width tracks the filter; the merged read closes it with
neither.**"* And its Consequences: *"The persisted `last_delivered_position`
is one scalar per subscription and is now exact for a multi-category filter
[…] **No schema change to `subscriptions` is needed for this, and one would
not have been sufficient on its own.**"*

The mechanism is that `global_position` is **one sequence over the whole
store** (`migrations/004_events.sql:89`, `events_global_position_seq`), so
positions do not advance per category at all; the per-category index is only
the keyset the merged walk uses. Half 1's picture of "one category's head at
9000 and another's at 900" is `stream_position` reasoning applied to a
`global_position` column.

This is recorded rather than deleted because the next reader of this area
needs the ADR's answer in front of them: per-category marks over a single
persisted scalar is a **loss** bug, not a refinement, and the code says so at
`crates/hort-app/src/dispatcher/subscription_task.rs:210-214`.

## The defect that is real

**The cursor must have one writer and must only move forward.** Three
statements touch `subscriptions.last_delivered_position`; two of them could
rewind it.

- `update` (`subscription_repo.rs:1140`) carried the column in its `SET`
  list, so `pause`, `resume`, `disable` and the PATCH path each wrote back a
  position they had only read. The window is not a microsecond race: the
  PATCH path awaits the SSRF/DNS webhook guard between the read and the
  write, so it is a DNS round trip wide, and the competing advance comes from
  the dispatcher's debounced flush, from another task, and at
  `replicaCount > 1` from another process.
- `update_last_delivered` (`:1216`) wrote
  `COALESCE($2, last_delivered_position)` — guarded against NULL, not against
  going backwards.
- `create`'s `INSERT` is the third write and needs no change: a fresh row has
  no prior value.

Rewinding costs duplicates rather than loss, which ADR 0061's at-least-once
guarantee permits — but it is not what the field claims to be, and the
asymmetry is the point: forward is loss, backward is duplicates.

## The shape of the fix

- **Remove** the column from `update`'s `SET` list rather than clamping it
  there. A caller that owns nothing about the cursor should not be a writer
  of it, and pause/resume/disable/PATCH all mean *keep the progress*, which
  is what leaving the column alone does.
- **`GREATEST($2, last_delivered_position)`** in `update_last_delivered` —
  one atomic statement, no read-modify-write. `GREATEST` ignores NULL
  arguments, so a never-delivered subscription stays unset exactly as
  `COALESCE` left it; pin that against a live database rather than against
  the documentation.
- `GREATEST` is the correct reduction and not a tie-break: each writer's
  value is a position it walked contiguously, so the greatest of several is
  still a position below which everything was delivered or filtered.
- **One rule, not one per implementation.** The two clauses live in
  `hort_domain::ports::subscription_repository` and every in-memory double
  calls them. A rule a double re-states in its own words is a rule it will
  state half of.

## Acceptance

- A late writer cannot rewind the cursor, with a DB-bound test that *attempts*
  the rewind through the real statement and reads the row back.
- A subscription over two categories survives a restart without binding
  either category's progress to the other — driven through the seed, which is
  what makes it a statement about the defect rather than about a table.
- No migration, no new table, no column dropped, no `CONTRACTIONS.toml` entry.
- No issue, MR or backlog reference in any code, SQL or YAML comment.
- Gate green, `#[serial(hort_pg_db)]` on every DB-bound test.
