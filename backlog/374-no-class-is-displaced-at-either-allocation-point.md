# 374 — No class is displaced, at either point where capacity is allocated

**Issue:** #399 · **Branch:** `agent/399-reassignment` · item 3 of 4.

ADR 0066 D4. Depends on item 373: only once the ordinal agrees with the class
is the row's `priority` a faithful projection of its class, which is what lets
the reservation be expressed without teaching SQL the mapping.

## Why ranking alone is not enough

After 373 a client-waited row outranks a bulk one. A **flood at the same
rank** still occupies the whole batch, and that is the reported failure: 2000
rescans at one rank, a batch size of 4, one worker. Ranking decides who wins a
comparison; it does not reserve anything.

ADR 0066 D4 says non-displacement holds **wherever capacity is allocated, not
at one point only**, and that the two points have different victims. Both are
in this tree, and both are open.

## Point one — the claim

`CLAIM_PENDING_BY_KINDS_SQL` (`crates/hort-adapters-postgres/src/jobs_repository.rs:135`)
claims one row by age and the rest by rank:

```sql
oldest AS MATERIALIZED (… ORDER BY created_at ASC, id ASC … LIMIT LEAST($2, 1)),
ranked AS (… AND id NOT IN (SELECT id FROM oldest)
           ORDER BY priority DESC, created_at ASC … LIMIT GREATEST($2 - 1, 0))
```

The reserved slot protects the **oldest** pending row, not the **losing**
class. In the state that matters the oldest row is itself part of the backlog,
so the slot never reaches the starved class — which is ADR 0066's "age is the
wrong axis to reserve on", and the mitigation this unit replaces.

**The outcome:** at least one slot for every non-empty waited-on class.

That default is derived from the domain and needs no measurement: interactive
work is bounded by what clients actually do, bulk work is unbounded by
construction, so a share that can go to zero for a class someone is waiting on
is the defect itself. ADR 0066 states explicitly that the shares are **not**
fixed by the decision — with a single worker replica the share is the whole
control surface, so it is per-deployment configuration with this default, not
a constant.

**The SQL must not learn the mapping.** `TaskTier::classify` is the one
definition (ADR 0066 D6) and lives in the domain layer; a copy of it in SQL is
how the trigger-source set came to be written down three times with no two
agreeing. After 373 the ordinal is a faithful projection of the class, so the
reservation is expressible on `priority` with the band boundaries passed **in**
as parameters from Rust. Any shape that keeps the mapping in one place is
acceptable; one that re-types it in SQL is not.

Mind 373's caveat: a row an older binary wrote carries an ordinal from the
previous scheme, so its band membership is wrong until it drains. Bounded, no
backfill (D7) — but the test for this unit must not accidentally depend on a
clean ordinal space.

## Point two — the permit

`TaskDispatcher::register`
(`crates/hort-app/src/task_dispatcher.rs:390-400`) creates **one semaphore per
kind** (`Semaphore::new(concurrency)`), and the permit is acquired inside the
spawned task (`:542-546`, *"Acquire concurrency permit before calling the
handler"*). `tokio::sync::Semaphore` hands out permits in order of arrival, so
rows of the **same kind** queue for a permit in spawn order.

So a client-waited ingest scan that **won** the claim still waits behind four
bulk rescans of the same kind for the capacity to run. That is D4's second
victim — "at the second point, other classes of the same kind" — and it is
invisible at point one, because such a row is already `running`.

**The outcome:** the per-kind capacity is allocated so that every non-empty
waited-on class is guaranteed at least one permit. Same default, same
reasoning.

**It is not preemption** (ADR 0066, "What this decision does not say").
Nothing interrupts running work or takes capacity from it; a waited-on class
is only guaranteed not to be shut out.

## The reserved-oldest slot and the per-class reservation have to be reconciled

Unit 373's run surfaced this and it belongs here rather than there. The claim
reserves one slot per poll for the globally **oldest** eligible row regardless
of rank (`LIMIT LEAST($2, 1)`), so **at `HORT_SCANNER_BATCH_SIZE = 1` that
reserved slot is the whole batch** and a newer client-waited row is never
claimed, however it is ranked. The compose default is 4, and 373's SQL-level
test carries `const _: () = assert!(REAL_BATCH_SIZE > 1)` with that reasoning
so it cannot silently become vacuous.

That is a property of the claim, not of the ranking, which makes it this
unit's: a per-class reservation layered on top of a reserved-oldest slot has to
decide **which one wins** when the batch is too small to satisfy both. Decide
it explicitly and say why — and note that the age reservation is the mitigation
ADR 0066 replaces ("age is the wrong axis to reserve on"), so "the age slot
wins" needs an argument that is not inertia.

## Acceptance

1. **Both points are closed.** A design that closes one is incomplete rather
   than partial (D4) — if the second turns out to need a change bigger than
   this unit, report it before building half of it.
2. **Point one, at the SQL level:** with the batch size exceeded by bulk rows
   of the same kind, a newer client-waited row is claimed in the same batch.
   Red before the change.
3. **Point two, without a database:** with the per-kind concurrency saturated
   by bulk rows, a client-waited row of that kind acquires a permit without
   waiting for all of them. The seam is the dispatcher's own registration, so
   this is a unit test.
4. **The mapping is not duplicated.** Assert that the classification has one
   definition: no `(kind, trigger_source)` → class table appears in
   `crates/hort-adapters-postgres/**` or in any SQL literal. A guard in the
   family of the existing structural guards is the right home, since
   convention did not hold this the last time.
5. **The share is configuration with a default.** The default is the domain
   one above; the knob is per-deployment, documented where the other worker
   knobs are, and its absence changes nothing.
6. Every DB-backed test carries `#[serial(hort_pg_db)]`.
7. `CHANGELOG.md`: one entry — a flood of background work can no longer shut
   out the paths a client or an operator is waiting on, with the knob named.

## Not in this item

- **The observation side** (D5): per-class service observable and reaching a
  human. Its own unit, and it is what makes a mis-set share visible.
- Aging as a safety net beneath this (ADR 0066 names it as worth having, not
  as a substitute).
- Deadline ordering, which the ADR sets aside rather than rejects.
