# 0061 — Notification delivery is driven by the event store, not by the broadcast channel

- **Status:** Accepted
- **Enforced by:** `hort_app::dispatcher::subscription_task` — every
  event is delivered by `catch_up` (an `EventStore::read_categories`
  walk); the loop only decides when to run one, and a broadcast receive
  is a trigger whose position is discarded.
  `store_poll_delivers_an_event_the_broadcast_never_carried` and
  `a_broadcast_wake_up_does_not_carry_the_cursor_past_unbroadcast_events`
  are the regression tests; disabling the tick turns the first red, and
  delivering the broadcast payload directly turns the second red.
  `a_restart_mid_pass_does_not_seed_over_an_unread_event_of_another_category`
  pins the merged walk (a per-category walk turns it red) and
  `a_failed_delivery_is_retried_by_every_pass_until_the_budget_runs_out`
  pins the retry (checkpointing past a failure turns it red).
  `crates/hort-adapters-postgres/tests/event_delivery_visibility.rs` pins
  the two store-side properties the decision rests on, and
  `tests/no_broadcast_in_adapter.rs` pins the layering rule against the
  crate rather than against one wiring of it.
  `tests/merged_category_read.rs` pins the merged read's ordering and
  truncation against a live database;
  `tests/merged_category_read_plan_stability.rs` pins its statement shape.
- **Supersedes:** —
- **Relates:** [0002](0002-event-sourced-artifact-lifecycle.md) (the event
  log this rides on), [0004](0004-pluggable-eventstore-port.md) (the
  `EventStore` port whose category reads are now the delivery path),
  [0008](0008-per-format-adapter-free-http-crates.md) (the dependency
  direction that rules out a broadcast from inside an adapter),
  [0020](0020-single-flight-seal-pool-backstop.md) (the seal pool the
  retention sweep deletes through, whose interaction with subscriber lag
  is the residual named below).

## Context

The notification substrate was built around an in-process
`tokio::sync::broadcast` channel. `EventStorePublisher`
(`crates/hort-app/src/event_store_publisher.rs`) — an application-layer
wrapper around the `EventStore` port — sends each persisted event on that
channel after a successful `EventStore::append`, and each
per-subscription dispatcher task consumed the channel in a live loop,
with a `read_category` catch-up run only at startup and after a
`RecvError::Lagged`.

Two structural facts make that channel unable to carry the event set a
subscriber signed up for. Neither is a bug in the channel; both are
properties of where the channel sits.

**The transactional write path is below the sender.** Events that must
land atomically with a projection write do not go through
`EventStore::append` at all. They go through
`PgEventStore::append_in_tx`, an inherent crate-internal method on the
Postgres adapter, reached via the lifecycle ports —
`ArtifactLifecyclePort::commit_transition` / `…_with_score` /
`commit_scan_result`, `RefLifecyclePort`, `ArtifactGroupLifecyclePort`,
`ArtifactRepository::delete`, and the purge sweep. That is not a corner
of the event vocabulary; measured against
`crates/hort-domain/src/entities/subscription.rs`'s `EventTypeKind`, it
is the whole subscribable artifact lifecycle — `ArtifactIngested`,
`ChecksumVerified`, `ArtifactQuarantined`, `ScanRequested`,
`ScanCompleted`, `ArtifactBecameVulnerable`, `ArtifactReleased`,
`ArtifactRejected`, `ScanIndeterminate`, `ProvenanceVerified`,
`ProvenanceRejected`, `ArtifactReEvaluated`, `PromotionRequested`,
`PolicyEvaluated`, `ApprovalRequested`, `ApprovalDecided`,
`ArtifactPromoted`, `PromotionRejected`, `ArtifactDeleted`,
`ArtifactPurged` and `ArtifactCorrupted` — plus `RefMoved` /
`RefRetired` and every `ArtifactGroup*` kind. Exactly two artifact-stream
kinds reached the channel, both appended through the publisher:
`ArtifactExpired` (the retention sweep's decision) and
`CasIntegrityMismatch` (the scrub's audit fact — note its
`ArtifactCorrupted` companion goes through `commit_transition` and did
not).

Closing that by making the transactional path send is not available. A
send from inside the transaction announces a write that may still roll
back. A send from the adapter after commit puts application-layer
notification concerns into `hort-adapters-postgres` and inverts the
dependency `EventStorePublisher` exists to express. And a post-commit
send arranged per port enumerates the paths rather than stating the
property: the next transactional port reopens the gap silently, which is
how this one stayed open through two separate units.

**The channel is per-process.** `tokio::sync::broadcast` reaches the
subscribers of one process. `NotificationDispatcher` is started per
server process with no leader election, and the chart supports
`replicaCount > 1`. So with N replicas each subscription has N tasks,
each seeing only its own replica's appends: an event appended on replica
1 is invisible to replica 2's task no matter which write path produced
it.

**The cursor turned a permitted drop into a permanent one.** Delivery was
documented as best-effort with catch-up bounding the drop volume, and the
prose claimed `last_delivered_position` "is operator visibility, not a
delivery cursor". The code disagreed: catch-up started at
`AfterGlobal(last_delivered_position)`, and the read is
`… AND global_position > $2`. So once any *delivered* event persisted a
higher position, every never-delivered event below it was below the mark
and never revisited. Combined with the first fact, that is not a bounded
drop — it is silent, permanent, total loss of the artifact lifecycle for
any subscription whose filter also matched something the channel did
carry.

## Decision

**A subscription's delivery loop is driven by reads of the event store.
The broadcast channel is a wake-up hint that removes latency on the paths
it happens to cover, and is never the path an event depends on.**

Concretely, in `subscription_task::run`:

1. `catch_up` — the walk that filters, dispatches and records progress —
   runs on every `STORE_POLL_INTERVAL` tick, not only at startup and on
   `Lagged`. It is the delivery path, not a recovery path.
2. **One pass reads the filter's categories as one ordered stream.**
   `EventStore::read_categories(&[StreamCategory], from, max_count)`
   returns the first `max_count` events of the merged,
   `global_position`-ordered stream above `from` — not a concatenation of
   per-category pages. The task therefore holds **one** cursor over
   **one** stream, which is what makes the single persisted
   `last_delivered_position` scalar correct by construction rather than
   approximately correct: a position at or below the mark has been read
   in every subscribed category.

   This is not an optimisation. Walking the categories separately over a
   single persisted scalar is a loss bug: the scalar is seeded into every
   category at spawn, so an advance driven by the first category becomes
   the floor for all of them after a respawn, and a lower-positioned
   event of a later category that the previous life never read is below
   the mark forever. Per-category *persisted* positions would also close
   it, at the cost of a schema change to `subscriptions` and a cursor
   whose width tracks the filter; the merged read closes it with neither.

   The port carries a default implementation that merges `read_category`
   calls — correct for every backend, and the right answer for the
   in-memory doubles that make up most of the trait's ~20 implementations
   (the same rationale `health_check`'s default records). The Postgres
   adapter overrides it with one statement; see *Cost* below, because the
   choice of statement is part of this decision and not an adapter
   detail.
3. The broadcast receiver is a **wake-up**, not a payload. Its
   `global_position` is deliberately discarded: delivering it directly
   would advance the cursor to that position and resume the walk above
   it — skipping exactly the transactional appends below that the channel
   cannot carry, which is the defect this decision closes. Its
   **category** *is* used, as a wake predicate: a hint for a category
   outside the filter cannot change what a pass would return, so it does
   not buy one. That is the same use `GET /api/v1/events`'s long poll
   already makes of a hint. `RecvError::Lagged` is a third trigger and
   always reads, because what it dropped is unknowable.
4. `catch_up` reports failure-budget exhaustion to its caller, so a
   subscription the dispatcher has just disabled is not polled and
   delivered to again on the next tick. It previously returned `()`, so
   its early exit ended only the pass and `run` carried on delivering —
   contradicting both the module documentation and the inline comment
   asserting the opposite, and load-bearing now that the pass repeats.
5. **A failed delivery is not checkpointed past.** On `Failed` /
   `DownstreamRejected` the pass stops at that event, the cursor is not
   advanced over it, and the position persisted alongside the failure is
   the position *before* it (`None` when there is no earlier position,
   which the repository treats as "record the failure, leave the cursor
   alone"). The next tick re-reads the same event and tries again.

**The guarantee is at-least-once for every event visible to a category
read at the moment the cursor passes it, with duplicates possible.** A
delivery that fails is retried on every subsequent pass — one transport
attempt per pass, every `STORE_POLL_INTERVAL` — until it succeeds or the
sliding failure budget (100 failures in 1h, so roughly eight minutes of
ticks) disables the subscription. The budget is what bounds the
head-of-line block that retrying in order necessarily creates: a
subscription blocked on one undeliverable event delivers nothing else
until it clears or the subscription is disabled visibly, with
`SubscriptionDisabled` on the audit stream. That trade is deliberate. The
alternative — advancing past the failure to keep the stream moving —
is the shape this amendment removes, because it turns a thirty-second
receiver outage into permanent, silent loss of everything that arrived in
it, and because "at-least-once" then describes attempts rather than
deliveries.

Duplicates arise on restart (the persisted cursor is debounced 5 minutes
behind), on a retry whose previous attempt actually arrived but reported
failure, and once per replica. That asymmetry is deliberate and is the
reason the cursor is seeded rather than trusted: a duplicate is the
receiver's to drop — every delivery carries a fresh
`X-Hort-Delivery-Id` and a stable `global_position` — and a gap is
recoverable by nobody.

**The event store is the outbox.** An outbox table written in the same
transaction plus a deliverer is the textbook answer to this problem, and
it is rejected here because the first half already exists: an
event-sourced system writes the durable, ordered, transactional record of
what happened as its primary artifact. A second table carrying the same
rows would be a copy to keep consistent, with its own retention and its
own way to skew. Only the deliverer was missing, and `catch_up` already
was one.

### Cost

The per-tick read is not free and is not zero-rows-cheap by accident. An
earlier draft of this ADR claimed "one indexed `read_category` per
(subscription, category) per tick, which returns zero rows when the
subscription is caught up", and the supporting comment in the code called
it "an index-only walk of the `(stream_category, global_position)` index
that returns nothing at all". Neither claim was measured, and the *shape*
of the merged read is where the cost actually lives.

Measured on a seeded 200 000-row `events` table with realistic skew — a
`repository` category holding 16% of rows but none above position
39 999, under `artifact` / `download_audit` / `auth` neighbours that churn
to the head — with `EXPLAIN (ANALYZE, BUFFERS)` of **server-side prepared
statements** on the 7th execution of each, under `plan_cache_mode` left on
`auto` and forced to `force_generic_plan` (identical results):

| Case | Before: C × `read_category` | After: one merged read | If it were `= ANY($1)` |
|---|---|---|---|
| quiet 3-category filter, 160k rows above the mark | 9 buffers, 0.016 ms, 3 round trips | **9 buffers, 0.011 ms, 1 round trip** | 160 641 buffers, 33.9 ms, 160 001 rows discarded |
| single quiet category, 160k rows above | 3 buffers, 0.004 ms | **3 buffers, 0.004 ms** | 160 641 buffers, 30.7 ms |
| 2-category filter, caught up at the head | 6 buffers, 0.007 ms, 2 round trips | **6 buffers, 0.007 ms, 1 round trip** | 3 buffers, 0.003 ms |
| all 7 seeded categories, caught up | 21 buffers, 0.029 ms, 7 round trips | **21 buffers, 0.020 ms, 1 round trip** | 3 buffers, 0.003 ms |
| all 7, 1000 positions behind (full page) | 1 028 buffers, 0.243 ms | **1 028 buffers, 0.322 ms** | 1 006 buffers, 0.255 ms |
| 3 quiet categories from `Start` (full page) | 1 060 buffers, 0.245 ms, 1 101 rows | **1 014 buffers, 0.295 ms, 1 000 rows** | 1 246 buffers, 0.282 ms |

Read across: the steady-state cost per subscription is a handful of
shared buffers and single-digit microseconds, and the merge collapses C
round trips into one without adding work. The column that matters is the
third. The obvious spelling of a merged read —
`stream_category = ANY($1) AND global_position > $2 ORDER BY
global_position LIMIT $3` — cannot satisfy its own `ORDER BY` from the
`(stream_category, global_position)` index without sorting every matching
row, so the planner takes the single-column `events_global_position_key`
index plus a filter and the read costs **O(rows of every other category
above the mark)**: 160 001 rows scanned and discarded to return nothing,
on every tick, for every subscription whose categories have gone quiet
while their neighbours churn. It is plan-mode independent — forcing a
custom plan does not rescue it — and it is the same class of failure as
the array-membership predicate that already cost this project a 64-second
retention preview.

What ships is a `UNION ALL` of per-category keyset arms, each anchored by
an equality on `stream_category` and each ordered by the full composite
key, merged by an outer `ORDER BY global_position LIMIT`. Postgres serves
it with a `Merge Append` over per-category index scans, so it reads
`max_count` rows in total rather than `max_count` per category, and its
plan does not move with the gap. The statement, the rejected alternatives
(including a row-value keyset range, which measures 919 buffers / 2.5 ms
to return *nothing* on a caught-up read because the comparison bounds the
scan only from below), and the numbers are in
`crates/hort-adapters-postgres/src/merged_category_read.rs`;
`tests/merged_category_read_plan_stability.rs` is the guard.

Two honest caveats on the measurement. It was taken on a sandbox
instance with a warm cache at 200 000 rows, so the absolute microseconds
are a floor, not a production figure. And a prior review reported that the
*existing single-category* read does not use the composite index either;
that did not reproduce here under any seeding tried — `read_category`
chose `idx_events_category_global` at every gap, in both plan modes — so
this ADR makes no claim about it. The pull surface
(`GET /api/v1/events`) still uses `read_category` and is unchanged.

The statement text carries one arm per category, so the prepared
statement is per-arity: at most one cached plan per distinct filter width
(1..=13). The category values stay bound parameters; only the arm count is
interpolated.

### The residual, and why it is not closed here

`events.global_position` defaults to `nextval`, evaluated at **INSERT**,
while a row becomes visible at **COMMIT**. The two orders can disagree:
a transaction holding the lower position may commit after a concurrent
reader has already passed it, and that reader — reading
`global_position > cursor` — never sees it again.
`a_later_committing_transaction_can_hold_a_lower_global_position` pins
this against a live database.

This decision does **not** close it, and the distinction matters. The gap
this ADR closes was deterministic and total; this one is a race.

**Its window is the whole transaction tail, not one commit latency.**
Every transactional port appends **first** and does its projection writes
afterwards: `artifact_lifecycle.rs` `commit_transition` (append →
`save_in_tx` → metadata upsert → commit), `commit_transition_with_score`,
`commit_scan_result`, `commit_transition_with_enqueues` (append → upserts
→ job inserts → commit), `artifact_repo.rs` `delete` (append → `UPDATE
artifacts` → commit), `purge_gc.rs` (append → `UPDATE` → `DELETE …
worklist` → commit). The position is taken before those writes, so the
window spans them and any row-lock wait they incur — bounded only by
`lock_timeout`, 120 s on the worker pools. Nothing in the code pins
append-last ordering.

**The widening is measurable, not slight.** Measured on the *shortest
possible* tail — the adapter's own `append`, an INSERT plus an immediate
COMMIT — with concurrent writers on fresh artifact streams and a bare
high-water-mark reader polling every 2 ms:

| Concurrent writers | Appends committed | Stranded (never readable past the cursor) | Per read |
|---|---|---|---|
| 1 | 1 020 | 0 (0%) | 0.000 |
| 2 | 1 547 | 2 (0.13%) | 0.003 |
| 4 | 2 638 | 24 (0.9%) | 0.035 |
| 8 | 4 829 | 46 (0.95%) | 0.088 |

Strands per read depend on how many positions are in flight when the read
happens, not on read cadence, so at the 5 s tick under sustained 4–8-way
concurrent appends this is on the order of one lost event per one to two
minutes per subscription — and the append-first ports have longer tails
than bare `append`, so their in-flight count per unit of concurrency is
higher. Bursts of concurrent ingest (CI fan-out, layer pushes, prefetch)
are exactly when it happens. Two things follow that the earlier draft did
not say: publisher-path categories were *immune* before (the live loop
delivered whatever it received, regardless of position) and now carry this
rate; and the wake-up correlates the read with a commit, which is the
moment a sibling transaction is most likely still in its tail.

**What closing it would take, and what is rejected.**

- An exact *reader-side* fix means the cursor stops being a bare
  high-water mark — a change to the position model itself, which
  `global_position` being on the wire format and on `GET /api/v1/events`'s
  `next_after` makes a public-contract change. Deferred to that decision.
  An `xmin`-horizon read does **not** substitute for it: xid assignment
  and `nextval` are separate atomic operations whose order can disagree in
  both directions.
- A *write-side* fix: a `pg_advisory_xact_lock` taken immediately before
  the events INSERT in `append_with_conn` makes INSERT order equal COMMIT
  order exactly, with no position-model change and no wire impact.
  Rejected here rather than omitted: it serialises every append across the
  remainder of its transaction tail, so it imposes a global write ceiling
  around 1/tail, and with today's append-first ordering that tail includes
  every projection write and lock wait — it would be viable only after the
  reordering below, and it is a throughput decision rather than a
  correctness one.
- The cheap partial fix: reorder the append to be the **last** statement
  before commit in the five transactional ports. That does not close the
  race, but it shrinks the window from the whole tail to the commit
  latency the earlier draft already claimed, which is roughly the
  difference between the table above and its first row. It is not done
  here because it touches five transaction bodies and the constraint of
  this unit is that nothing is added to, removed from, or reordered inside
  any transaction; it should be scheduled with a guard, since nothing
  enforces the ordering today.

### The retention residual

"The event store is the outbox" holds while subscriber lag is shorter than
the gap between an event being written and its stream being swept. An
outbox deletes on delivery; the event store deletes on age, blind to
delivery.

Concretely: `seal_and_remove` deletes whole streams, and for
`StreamCategory::Artifact` the audit floor is proven against the stream's
**oldest** event (`terminal_stream_reader.rs`, `min(stored_at)`). So the
*newest* events of a stream older than the floor — `ArtifactDeleted`,
`ArtifactExpired`, `ArtifactPurged` — can be deleted within one sweep
interval of being written. With the chart's default schedules (purge
`0 4 * * *`, archive `0 5 * * 0`) that interval is one hour. A
subscription paused across it (`resume` keeps
`last_delivered_position`), or whose replicas are all down across it,
never sees those events: the read that would deliver them returns
nothing, and the `StreamSealed` tombstone lands in the admin-only `Admin`
category.

The bound: both sweeps are `enabled: false` by default, so a default
deployment cannot reach this; with the default floor only artifacts older
than 1 080 days are eligible at all; and a running subscription's 5 s poll
is far inside any sweep interval. It is named here because the ADR
otherwise lists "its own retention" only as a cost of the *rejected*
outbox table, which reads as though the event store does not have the
same question. The structural close — a delivery horizon in the sweep,
`min(last_delivered_position)` over non-disabled subscriptions, capped so
a paused subscription cannot pin retention forever — is its own decision
and is not designed here.

## Consequences

- A transactionally appended event reaches its subscribers, and the
  atomicity it is appended transactionally for is untouched: nothing was
  added to, removed from, or reordered inside any transaction.
- The persisted `last_delivered_position` is one scalar per subscription
  and is now exact for a multi-category filter, because the mark and the
  reads describe the same ordered stream. No schema change to
  `subscriptions` is needed for this, and one would not have been
  sufficient on its own.
- A blocked delivery blocks its subscription. The failure budget bounds
  the block to ~8 minutes of ticks, after which the subscription is
  `Disabled` and the operator has a `SubscriptionDisabled` event and a
  `last_failure` to look at. A receiver that rejects one specific event
  permanently (a `DownstreamRejected` on a payload it cannot parse) will
  therefore disable the subscription rather than skip the event — which
  is the intended direction: a gap is recoverable by nobody, a disabled
  subscription is recoverable by an operator.
- A failed *read* is fail-closed the same way — the cursor does not move
  — so a deterministic read failure (one row a replica cannot decode,
  which a mid-rollout version skew produces) stalls the subscription
  indefinitely rather than skipping. `hort_notify_store_read_errors_total`
  is the alertable signal; before it, the only signal was a `warn!` per
  tick.
- `hort-adapters-postgres` still holds no broadcast sender.
  `transactional_append_is_absent_from_the_broadcast_channel` asserts the
  property for the wiring that ships, and `no_broadcast_in_adapter.rs`
  asserts it of the crate — which is the level the rule is stated at, and
  is what a sender reached through a setter or a `OnceLock` would
  otherwise slip past.
- The property holds for the **path**, not for a list of events: a future
  transactional port needs no notification wiring at all, because
  delivery never looks at the write path. A reviewer should treat a new
  broadcast `send` added to reach a subscriber as the smell this ADR
  exists to prevent.
- Delivery latency for events the channel does not carry is bounded by
  `STORE_POLL_INTERVAL` (5s) rather than being unbounded.
- A publisher-path append no longer wakes every subscription in the
  process — only those whose filter covers the appended event's category.
  Before, a retention sweep expiring 1 000 artifacts, or the per-download
  audit stream, made every task in the process run a read per event it
  could not possibly deliver.
- Cross-replica **loss** is closed; cross-replica **duplication** is not.
  N replicas still deliver N times, because there is still no leader
  election over the dispatcher. That was true before this change and is
  unchanged by it; it is now the dominant duplicate source and wants its
  own decision.

## Alternatives considered

- **An outbox table written in the transaction, plus a deliverer.**
  Rejected: the event store already *is* that table, written in the same
  transaction, and it is the one the domain treats as truth. A second
  copy adds a consistency obligation for no new capability. Its one real
  advantage — deleting on delivery rather than on age — is the residual
  named above, and it is bounded.
- **Delivering the broadcast payload directly and de-duplicating it
  against the read cursor.** Rejected, and it is the shape to watch for:
  it looks like it keeps both low latency and one cursor, but the
  delivered position advances the mark over everything below it that the
  channel never carried. A subscription receiving a publisher-path event
  at position 100 would skip the transactional appends at 51..99. Keeping
  both properties would need a bounded set of live-delivered positions
  beside the mark — more machinery, to buy back a latency the wake-up
  already provides.
- **Per-category persisted positions** (a schema change to
  `subscriptions`, or a JSONB map on it). Rejected in favour of the merged
  read: it fixes the same loss, but it makes the cursor's width a function
  of the filter, it needs a migration and a back-compat read path for
  rows written before it, and it leaves the C-reads-per-tick cost in
  place. The merged read fixes the loss and the read multiplication with
  one port method.
- **Per-category marks in memory over a single persisted scalar** (what
  the first implementation of this decision did). Rejected as unsound, not
  as suboptimal: the in-memory marks are exact for the life of a task and
  are discarded at respawn, at which point every category is seeded from
  the one scalar an earlier category advanced.
- **A post-commit broadcast per transactional port** (a decorator over
  each lifecycle port, mirroring `EventStorePublisher`'s shape one layer
  up). Rejected: it enumerates today's five transactional ports instead
  of stating the property, so port six reopens the gap; it needs a
  decorator over `ArtifactRepository`'s whole surface to reach the
  delete; and it closes none of the per-process half, which no number of
  senders can.
- **A broadcast `send` from inside `append_in_tx`.** Rejected twice
  over: it announces writes that may still roll back, and it puts a
  notification concern in the Postgres adapter.
- **Leader-electing the dispatcher and keeping the live loop as the
  delivery path.** Rejected as a fix for *this* problem: it would close
  the per-process half while leaving the transactional half — the larger
  and deterministic one — fully open. It remains the right answer to
  cross-replica duplication, separately.
- **Making category reads return only settled rows** (a visibility
  horizon derived from `pg_snapshot_xmin(pg_current_snapshot())`), so
  every cursor becomes safe. Not rejected — deferred, and see the
  residual above for why it is not sufficient on its own. It changes the
  semantics of a port the low-latency read API also uses, so it belongs
  with the position-model decision rather than inside this loop change.

## References

- `crates/hort-app/src/dispatcher/subscription_task.rs` — `run`,
  `catch_up`, `ReadCursor`, `Disposition`, `STORE_POLL_INTERVAL`.
- `crates/hort-domain/src/ports/event_store.rs` — `read_categories` and
  its default merge.
- `crates/hort-adapters-postgres/src/merged_category_read.rs` — the
  statement, the two shapes it must not become, and the measurements.
- `crates/hort-app/src/event_store_publisher.rs` — the wrapper whose
  best-effort `send` this ADR demotes to a hint.
- `crates/hort-adapters-postgres/src/event_store.rs` — `append_in_tx`
  and `append`, and `global_position` via `RETURNING`.
- `migrations/004_events.sql` — `global_position` as a `nextval` default,
  and `idx_events_category_global`.
- `crates/hort-adapters-postgres/tests/event_delivery_visibility.rs` —
  the two pinned store-side properties.
- `docs/architecture/explanation/event-notifications.md` — the page this
  decision rewrites the delivery-semantics section of.
