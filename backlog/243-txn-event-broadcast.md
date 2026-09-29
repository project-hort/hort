# 243 — Transactionally appended events never reach subscribers

**Issue:** #296 · **Branch:** `agent/296-txn-event-broadcast`
**Governing decisions:** ADR 0020 (event-store single-flight and the event
infrastructure) · #286 (the atomicity that is not given up) · #281 (the finding).

## Why

`ArtifactPurged` is appended transactionally — that is the atomicity #286
deliberately establishes, so the terminal event and the projection's retirement
cannot come apart. The transactional append **does not broadcast**, so it never
reaches the notification dispatcher.

This is not new with #286. `ArtifactDeleted` from the ordinary delete path has
always behaved this way, for the same reason
(`crates/hort-adapters-postgres/src/artifact_repo.rs`, `fn delete`). #286 only
brought the existing crack to a second, more visible place.

## The structural shape — establish this first, it reframes the fix

**`append_in_tx` is not on the `EventStore` port.** It is an inherent
`pub(crate)` method on `PgEventStore`
(`crates/hort-adapters-postgres/src/event_store.rs`), and the adapters that use
it call it on the concrete type. `EventStorePublisher`
(`crates/hort-app/src/event_store_publisher.rs`) is an **application-layer
wrapper around the port** that broadcasts after a successful
`EventStore::append`.

So the transactional path does not *miss* a broadcast — it is architecturally
outside the thing that broadcasts. That matters because it rules out the
obvious fix: making `append_in_tx` send on the broadcast channel would put
application-layer notification concerns inside the Postgres adapter, inverting
the dependency the wrapper exists to express. Whatever the answer is, it is not
one more call at the bottom.

## What the catch-up path does and does not save

Read `crates/hort-app/src/dispatcher/subscription_task.rs` before concluding
anything about severity. Each subscription task does a **catch-up read against
the event store** at startup and again after a `broadcast::error::RecvError::
Lagged`, then runs a live loop on the broadcast receiver. So a missed broadcast
is not automatically a missed event: the store is the source of truth and
catch-up reads it.

**But the cursor is a high-water mark.** Catch-up starts at
`AfterGlobal(last_delivered_position)` and the read is
`… AND global_position > $2 ORDER BY global_position ASC`. Once the live loop
has delivered a *later* event and persisted its position, an earlier position
that was never broadcast is **below the mark and never revisited**. The loss is
permanent from that moment, not until the next restart.

## The question this unit has to answer

Not "broadcast `ArtifactPurged` as well" — that is one more match arm where the
general property is missing, the shape that has already been expensive here.
The general question is: **how does a transactionally appended event reach its
subscribers without giving up the atomicity it is appended transactionally
for?**

The tension is real and does not dissolve by reordering. Broadcasting before
commit announces something that may still roll back; broadcasting after commit
is no longer atomic and is lost on a crash in between. Both naive answers are
wrong, and which compromise is right depends on what subscribers actually need.

### A second hazard to check while you are in here

`global_position` is a sequence default (`migrations/004_events.sql`), so it is
taken at **INSERT** and not at commit. Two concurrent appends can therefore
commit out of position order: the later-committing transaction may hold the
lower number. Against a high-water-mark cursor that is the *same* failure as
the missing broadcast, reached without any transactional append at all — a
reader can advance past a position that is not yet visible.

**Verify whether this is real** against the actual read path and commit
ordering. If it is, the answer is not "broadcast the transactional events" but
"the cursor may not be a bare high-water mark", and that is a different and
larger design. Establish it before choosing a mechanism; it is the difference
between patching one path and fixing the invariant.

## To clarify before building

1. **Who actually subscribes, and what breaks today?** To be measured, not
   assumed: which subscribers exist, which care about `ArtifactPurged` /
   `ArtifactDeleted`, and what precisely fails to arrive. Check whether
   notifications are even enabled by default
   (`HORT_NOTIFICATIONS_ENABLED`; the publisher is a transparent pass-through
   when the sender is `None`). **"Nobody who needs it" is a legitimate
   outcome** — then the crack gets documented where a future subscriber would
   trip over it, and the issue closes on that finding.
2. **Which delivery guarantee is owed.** At-least-once after commit is not
   exactly-once, and the choice determines the mechanism: an outbox row in the
   same transaction plus a deliverer, versus a post-commit broadcast with an
   explicitly accepted gap. **The decision is to be argued, not picked.**
3. **Whether this needs an ADR.** If the answer fixes a delivery guarantee for
   the transactional path, that is a standing decision and not an
   implementation detail. ADR 0020 is the neighbour to amend or extend.

## Read first

- `crates/hort-app/src/event_store_publisher.rs` — the whole module doc; the
  best-effort contract and the `None`-sender pass-through.
- `crates/hort-app/src/dispatcher/subscription_task.rs` — the module doc's
  six-step summary, `CATCHUP_PAGE`, `PROGRESS_DEBOUNCE`, the `Lagged` arm.
- `crates/hort-adapters-postgres/src/event_store.rs` — `append_in_tx` and
  `append`, and how `global_position` is obtained.
- `crates/hort-adapters-postgres/src/artifact_repo.rs` (`fn delete`) and
  `crates/hort-adapters-postgres/src/purge_gc.rs` — two of the transactional
  call sites; `git grep append_in_tx` gives the rest.

## Acceptance

- The subscriber situation is measured and stated in the report **before** a
  mechanism is chosen.
- The out-of-order-commit hazard is checked and its verdict stated, whichever
  way it falls.
- Then **either**: a transactionally appended event reaches its subscribers
  under a named, argued guarantee, with #286's atomicity untouched;
- **or**: it is demonstrated that no subscriber needs it, and the crack is
  documented at the place a future subscriber would trip over it.
- Either way the answer holds for the **path**, not for one event. A fix that
  names `ArtifactPurged` is the wrong fix.
- If a standing decision is fixed, it lands as an ADR change and not only as
  code.
- Gate green; `#[serial(hort_pg_db)]` on every DB-backed test.

## Explicitly not in this item

- No change to #286's transactional composition. The atomicity is the thing
  being preserved, not the thing being traded.
- No new event variant, and no reason enum, to carry notification state.
- No broadcast call inside `hort-adapters-postgres`. If the answer needs one
  there, that is a layering change and needs saying out loud, not doing
  quietly.
