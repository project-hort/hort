# 372 — The clearance verify says what it is

**Issue:** #399 · **Branch:** `agent/399-reassignment` · item 1 of 4.

Follows unit 363, which made `TaskTier` the one definition of *who is waiting*
and moved every producer onto `queue_priority(kind, trigger_source)`.

**One producer still names a number**, and the reason it has to is the point
of this unit.

## What holds

The expiry backstop's final provenance verify
(`crates/hort-app/src/use_cases/quarantine_use_case.rs:2222-2232`) passes an
ordinal directly:

```rust
// Clearance-gating: this verify is the last thing between
// a held artifact and a release decision, so it preempts
// the bulk ingest-time verify backlog.
CLEARANCE_GATING_VERIFY_PRIORITY,
INGEST_TRIGGER_SOURCE, // reuse the ingest-time verify trigger source (CHECK-valid)
```

Two materially different pieces of work therefore arrive on the queue
indistinguishable:

| the work | volume | who waits |
|---|---|---|
| the **ingest-time** verify | one per ingest — this is the backlog | a client waiting on their push to become servable |
| the **clearance** verify | low — one per held artifact reaching its window | the release decision for an artifact already held |

Both carry `('provenance-verify', 'ingest')`, so `TaskTier::classify` gives
both `Interactive` — correct for both — and `queue_priority` cannot tell them
apart. The site compensates by naming a number, and the line below says why it
had to: the trigger source it wanted did not exist, so it **borrowed** one
that was CHECK-valid.

**That is the whole finding.** The distinguishing fact exists in the domain
and was never recorded on the row, because the vocabulary the column admits
was too narrow. Everything downstream that reads the row — the tier
derivation, the ordinal, an audit of what the queue is spending itself on —
sees an ingest that is not one.

## Why now, and why this is not a new decision

Adding a `trigger_source` literal is routine since #402: the set is
single-sourced in `TriggerSource`'s `trigger_source_wire!` list, a variant
the list does not name is a compile error, and the lock-step guard fails until
the migration follows. Before that, borrowing was the only option that built.

And the outcome needs no ADR change: it is ADR 0066 D2 working as intended
("the class is a property of the work item, derived from what caused it to
exist") once the row carries the right cause, plus D6 ("no producer names a
number") actually becoming true at the last site that violates it.

Collapsing the two onto one ordinal instead would lose something real: a held
artifact would wait behind the ingest-verify backlog, and that is release
latency — the quantity this whole issue is about.

## The outcome

1. A new `TriggerSource` variant for the clearance path, with its wire literal
   in the `trigger_source_wire!` list
   (`crates/hort-domain/src/ports/jobs_repository.rs`) and a migration
   widening `jobs_trigger_source_check` in the shape migration 036 uses
   (`DROP CONSTRAINT` + `ADD CONSTRAINT` of the same `_check` name).
2. `TaskTier::classify` gives it `Interactive` — the class is unchanged,
   because who waits is unchanged. The separation this unit buys is **within**
   the class, by volume, which is what the ordinal is for. This is explicitly
   not a fourth class (ADR 0066 D1).
3. `queue_priority` gives it the ordinal the producer names today, so the
   enqueued row is identical to what it is now — this unit changes **what the
   row says about itself**, not what the queue does with it.
4. `CLEARANCE_GATING_VERIFY_PRIORITY` leaves the producer; the site calls
   `queue_priority(kind, trigger_source)` like every other producer.

## Acceptance

1. A test that the clearance enqueue's row carries the new trigger source and
   the same ordinal as before — the row's ordinal does not move in this unit.
2. A test that the new literal classifies as `Interactive` and that the
   ingest-time verify still does too, so the class boundary is visibly
   unchanged.
3. `jobs_trigger_source_check_lockstep_guard` and
   `jobs_trigger_source_register_by_hash` stay green — the guard is what
   proves the SQL side followed.
4. No producer in `crates/**` passes a literal ordinal to `enqueue_task` /
   `enqueue_scan` any more. Assert it rather than claim it: the census that
   finds `queue_priority(` call sites is the shape to use, and the count is
   reported untruncated.
5. The sandbox database carries the new migration, so a later run on a branch
   without it needs a fresh database — state that in the report.
6. `CHANGELOG.md`: one entry — the clearance-gating verify is distinguishable
   from the ingest-time verify on the queue.

## Not in this item

- **The re-assignment** (item 2): making the ordinal agree with the tier. This
  unit deliberately leaves every number where it is.
- Non-displacement and the per-class reservation.
- The starvation audit's reach.
