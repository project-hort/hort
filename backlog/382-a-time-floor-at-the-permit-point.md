# 382 — A time floor at the permit point

**Issue:** #405 · **Branch:** `agent/405-time-floor-at-the-permit-point` · single item.

**Governing decisions:** ADR 0066 D4 (non-displacement holds wherever capacity
is allocated) and D5 (*"Every class is guaranteed service … A class that is
never served is a defect whatever its share says"*). **No ADR change is
needed** — D5 already requires this outcome; it is observed and reported but
not enforced. ADR 0066's *context* section names weighted fair sharing among
the standard remedies, and its "What this decision does not say" section
explicitly leaves the shares unfixed, so a time floor is inside the decision.
A deficit/round-robin scheduler was considered and **declined** (see
*Alternative declined* below) — do not propose it again in the report.

## The defect

`ClassFairPermits::take_next` (`crates/hort-app/src/class_fair_permits.rs:143-162`)
grants a freed permit in two passes:

1. the first **waited-on** class (`TaskTier::is_waited_on`) that has a waiter
   **and** holds fewer than `reserved_per_class` permits;
2. otherwise the longest-waiting row of any class (global arrival order).

In production `scan` is registered with `max_concurrency = 1`
(`crates/hort-worker/src/composition.rs:705-708`), the share is `1`
(`DEFAULT_RESERVED_SLOTS_PER_CLASS`, `crates/hort-worker/src/config.rs:227-228`),
and `TaskTier::ALL` is `[Interactive, Normal, Bulk]` with both leading classes
`is_waited_on` (`crates/hort-domain/src/types/task_tier.rs:408,440-445`).

At a capacity of one, every class holds **zero** permits after each release, so
every class is below its share, so pass one always matches — and it matches
`Interactive` first, because `ALL` is ordered that way and `find` takes the
first hit. `Normal` is therefore never served while `Interactive` has a
waiter. `classify` puts every client pull-through and OCI register-by-hash in
`Interactive` and the **operator-triggered** scan in `Normal`
(`task_tier.rs:528-548`), so on an instance with live pull-through traffic an
operator's rescan does not run at all — indefinitely, not merely late.

The module's own test comment states the property the shipped configuration
does not have (`:425-433`): *"This is the assertion that separates this design
from strict class priority. Without it the two are indistinguishable at the
default share."* That test runs at capacity **2**.

**Why widening pass one's predicate is not the fix.** The obvious shape — add
*"or has not been served for too long"* as a disjunct inside the existing
`find` — changes nothing at capacity one: `Interactive` still satisfies the
first disjunct and `find` still reaches it first. What decides the outcome here
is the **iteration order**, so the floor has to be a pass that runs *before*
the share pass, not a wider predicate inside it.

## What to build

### a) A precedence pass for a class that has gone unserved too long

`take_next` gains a pass **before** the existing two: among waited-on classes
that have a waiter and are **starved**, grant to the one starved longest;
ties break by `TaskTier::ALL` order, so `Interactive` keeps precedence when
both are equally starved. Passes two and three are today's pass one and pass
two, unchanged.

Keep the structure wildcard-free over `TaskTier::ALL` for the reason the
current code gives at `:136-139`: a class added later must be given an
`is_waited_on` answer before it can be skipped.

### b) "Starved" means what the audit already means by it

Mirror `hort_domain::policy::evaluate_class_service`
(`crates/hort-domain/src/policy/queue_class_service.rs:238-250`) rather than
inventing a second definition. Its reference instant is
`max(last served, oldest waiting item's arrival)`, and **both halves are
load-bearing** — that doc comment explains why, and the same two reasons apply
here:

- the last-served half makes it a *service* test rather than an age test;
- the arrival half keeps a quiet deployment quiet: a class nobody used for an
  hour must not count as an hour starved the moment its first row arrives.

With no grant on record, judge on the arrival half alone — the same answer
the policy gives for `last_served_at: None`. Comparison is **strictly greater
than**, as the policy's boundary semantics are.

This needs two new pieces of state:

- `State` gains the last grant per class (`[Option<Instant>; CLASS_COUNT]`),
  set in `pump` where `held[index]` is incremented;
- `Waiting` gains its arrival **instant**. Keep `seq` as well and do not
  derive one from the other: `seq` is the total order pass three needs, and
  two instants can compare equal.

### c) The interval is derived from the audit's threshold, in the domain

The enforcement interval must be **strictly shorter** than the threshold the
audit reports on. Otherwise the scheduler acts exactly when the audit fires
and the alarm stops meaning anything.

Define the derivation once, in `queue_class_service.rs` beside
`evaluate_class_service`, as a function of the configured threshold (not a
second constant — the threshold is an operator knob,
`HORT_TASK_CLASS_SERVICE_THRESHOLD_SECS`, and the enforcement has to track
it). Half the threshold is the intended ratio, and state the reason in the doc
comment: the audit's `last_served_at` comes from **completed** work, so the
granted run needs room to finish inside the remaining budget. Handle a zero or
absurd threshold the way the policy module handles its own boundaries —
saturating, never wrapping.

### d) Thread it where the share is already threaded

`TaskDispatcher::register` (`crates/hort-app/src/task_dispatcher.rs:490-505`)
builds the allocator and the dispatcher **already holds** the number:
`class_service_threshold` (`:399`), fed by `WorkerConfig` from the same
environment variable the server's gauge reads. No new configuration, no new
environment variable.

Add an accessor on `ClassFairPermits` for the threaded interval and assert in
a test that `register` passed the derived value, for the reason
`TaskDispatcher::class_service_threshold`'s doc comment gives at `:469-475`:
the number is otherwise unobservable from outside the process, and "the value
was configured but never threaded" would look exactly like "the value is the
default".

### e) The clock is a seam, because `Drop` cannot be given one

`pump` is reached from `acquire` **and** from `release` by way of
`Permit::drop` (`:322-328`), so the time cannot be a parameter the way
`FailureBudget`'s is (`crates/hort-app/src/dispatcher/failure_budget.rs:13-18`
states that seam and its purpose). Give `Inner` an injected clock —
`Arc<dyn Fn() -> Instant + Send + Sync>`, production `Instant::now` — read
**once per `pump` call**, with a `#[cfg(test)]` constructor that takes a
controllable one.

The tests must drive that clock, not sleep: the production interval is 150 s at
the default threshold, and the existing tests use `tokio::time::timeout` as a
hang guard rather than as a wait (`:336-342`).

Nothing may `await` while the state lock is held — the module's `State` doc
comment (`:111-115`) rests on that.

## Explicitly out of scope

- **`TaskTier::Bulk`.** The floor is for waited-on classes only. Giving `Bulk`
  one would let it take a permit ahead of a waiting served class, which this
  item's acceptance forbids, and it would reverse what the module comment
  (`:47-61`) argues as ADR 0066's stated trade. Whether D5's *"every class"*
  reaches `Bulk` at a capacity of one is a separate decision, raised with the
  maintainer as such. Leave that comment's claim about `Bulk` standing, and do
  not weaken it to cover the new pass.
- **`reserved_per_class == 0`.** That is the documented escape hatch back to
  pure arrival order (`:239-241`). The new pass is gated on the share being
  non-zero, exactly as pass one effectively is.
- **Preemption**, and any change to how much capacity exists. ADR 0066: the
  total stays the `max_concurrency` the kind was registered with.
- **The share value, and per-class weights.** No new operator surface.
- **The claim query.** `crates/hort-adapters-postgres/src/jobs_repository.rs`
  already bounds starvation at the other allocation point by **age** — the
  `oldest` CTE takes one row by `created_at ASC`, class-blind (`:215-223`) —
  so after this change both allocation points bound starvation by the same
  concept, which is what the issue's "formulated once" criterion asks for. No
  SQL changes.

## Alternative declined

Deficit round robin over the waited-on classes with the share as quantum is
textbook-correct at every capacity and needs no clock. It was declined by the
maintainer because it promises **proportional** fairness that no ADR states —
at a capacity of one with equal quanta `Interactive` and `Normal` would
alternate 1:1, halving client throughput whenever an operator rescan runs —
and because a deficit counter would have to reach the claim query too, which
means persistent per-class state written on every claim across every replica.

## Acceptance

1. At capacity **1** with a *sustained* stream of `Interactive` waiters,
   `Normal` is granted a permit in finite time, shown by a test that builds
   that sustained stream. The existing capacity-1 test
   (`the_higher_waited_on_class_is_served_first_when_both_are_waiting`,
   `:467`) proves one hand-over after the `Interactive` queue drains and
   does **not** cover this.
2. The property asserted at `:425-433` — the doc comment of
   `a_class_at_its_share_does_not_overtake_an_earlier_waiter` (`:435`) — holds at **every** capacity from 1 up,
   not only from 2.
3. `Interactive` still precedes `Normal` when both are waiting and neither has
   been served — the `TaskTier::ALL` order is unchanged at both allocation
   points.
4. No preemption, and `Bulk` gains no precedence over a waiting waited-on
   class.
5. **Mutation evidence, both directions:** removing the new pass must fail the
   new test, and the new pass must not change any existing test's expectation.
   Every test in `class_fair_permits.rs` that exists today passes **unmodified**
   — if one has to be rewritten, say so in the report and stop, because that
   is a behaviour change the issue did not ask for.
6. A test shows the derived interval reached the allocator through `register`.
7. The new pass is skipped entirely when `reserved_per_class == 0`.

## Read first

- `crates/hort-app/src/class_fair_permits.rs` — all of it, module comment
  included; the "What this does not bound" section (`:47-61`) is what this
  change does and does not touch.
- `crates/hort-domain/src/policy/queue_class_service.rs:150-265` — the
  definition of starvation to mirror.
- `crates/hort-app/src/task_dispatcher.rs:378-400,460-505` — the share, the
  threshold, and where the allocator is built.
- `crates/hort-app/src/dispatcher/failure_budget.rs:1-95` — the in-repo
  precedent for a time seam.
- `docs/adr/0066-background-work-never-outranks-a-waiting-client.md` — D4, D5,
  "What this decision does not say", and the consequences.
