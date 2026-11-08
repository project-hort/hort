# 0066 — Background work never outranks the path a client is waiting on

- **Status:** Accepted
- **Enforced by:** *to be built with this decision.* Structurally, by making the
  classification a domain type: a call site that wants a rank names a class, and
  the queue's ordinal is written in one place from that class. The
  non-displacement rule is enforced wherever the system allocates capacity,
  which is a small, countable set of places — not a convention each producer of
  work has to honour.
- **Supersedes:** —
- **Relates:** [0028](0028-destructive-task-idempotency.md) (the task-row
  lifecycle this orders), [0030](0030-sensitive-surface-structural-guards.md)
  (the guard family a non-displacement check joins),
  [0007](0007-fail-closed-quarantine-release-predicate.md) — 0007 decides *when*
  an artifact may be released; this decides that the mechanism performing that
  release is not displaced by maintenance. Source: `backlog/074` and issue #399,
  which hold the measurements and the mechanism analysis, and the
  maintainer's 2026-11-02 decision.

## Context

Hort ranked queued work by one number per kind of work. That expressed
importance and nothing else — not who is waiting, not how long the work runs —
and it twice allowed work nobody was waiting on to displace work someone was.

The two instances have different shapes, which is why one fix does not cover
both. In the first, a kind stopped being claimed at all while the queue kept
serving others; every pending item satisfied every condition for being picked,
and none was picked. In the second, a flood of scheduled rescans was ranked
equal to the sweep that makes quarantined artifacts available, and the
tiebreaker — age — resolved the tie against the sweep, because a backlog is
always older than the next scheduled run. A push completed, its quarantine
window elapsed, and nothing released it.

**This is head-of-line blocking by a bulk class, not priority inversion.**
Nothing holds a resource a higher-ranked task is waiting for, so priority
inheritance and priority ceiling — the remedies for inversion — do not apply.
Naming it correctly matters because it points at the right literature: the
remedies for head-of-line blocking are reserved capacity per class and weighted
fair sharing, not rank repair.

**Age is the wrong axis to reserve on.** Reserving part of each batch for the
oldest waiting item — the mitigation this decision replaces — protects the
oldest item, not the one that is losing, and in the state that matters a
backlog's oldest item is itself part of the backlog. No tuning of that shape
reaches the starved class; the reservation has to be allocated per class.

**There is no priority model to amend, which is why this is a new decision.**
The rank was retyped at each producer of work, with no shared type and no
shared module, so nothing existed for a reviewer to check an assignment
against. That is how "maintenance outranks publishing" came to be written down
in several places without ever reading as wrong.

**One kind of work is several different things.** A scan requested because a
client just pushed, a scan an operator asked for, and a scan a timer enqueued
are the same kind and three different urgencies. A rank per kind cannot express
that, and the distinguishing fact — what caused the work to exist — is already
recorded on each item.

The remedies below are standard queueing practice rather than a local
invention: reserved capacity per class instead of strict ordering, weighted fair
sharing so every class receives a share, separation by expected duration as
well as by importance, and few enough classes that the shares stay meaningful.

## Decision

**Work is classified by who is waiting on it, and work nobody waits on never
displaces work someone waits on.**

1. **The classification axis is who waits**, and it has three answers because
   the question does: a client is waiting on this right now; an operator is
   waiting on an answer; nobody is waiting. A fourth class would have to name a
   fourth answer.
2. **The class is a property of the work item, not of its kind.** It is derived
   from what caused the item to exist, because one kind of work serves several
   intents and the intent is what determines who is waiting.
3. **The path that makes an artifact available is client-waited even when it is
   scheduled.** That a piece of work runs on a timer says how it is triggered,
   never that nobody is waiting for its effect. This is the specific lesson of
   the second instance, where "it is a scheduled task, so it ranks with
   scheduled tasks" produced a stalled release path.
4. **Non-displacement holds wherever capacity is allocated, not at one point
   only.** Guaranteeing a waited-on class its share of the decisions about
   *which work is taken up* does not guarantee it a share of the capacity to
   *run*. A decision that closes one leaves the other's victim, and the two
   victims are different: at the first point, other kinds of work; at the
   second, other classes of the same kind. Both must be closed, and a design
   that closes one is incomplete rather than partial.
5. **Every class is guaranteed service; the guarantee is observable at the
   granularity it is enforced at; and the observation reaches a human.** A
   class that is never served is a defect whatever its share says, so the
   guarantee is part of the decision and not a nicety. *Every* class includes
   the one with no reserved share. Its guarantee rests not on a share but on a
   **priority-blind age fallback beneath the reservation, present at every
   point the reservation is**: past a bound the oldest waiting item is served
   whatever its class. That fallback reorders nothing inside the bound, so the
   class order of (1) is untouched, and it is not a second per-class
   allocation — aging alone would be insufficient (see *Alternatives
   considered*), and beneath the reservation it is what keeps the lowest class
   from never running. "Served more slowly" is the trade this decision makes;
   "never served" is not. An observation coarser than the
   enforcement is a statistic and not an alarm — a guarantee enforced per kind
   and per class, and watched per class alone, can be reported healthy by a
   sibling kind's progress. Both instances were found by a human noticing
   latency, which is the evidence that an instrumented guarantee nobody is
   alerted on is documentation rather than a guarantee.
6. **The vocabulary is defined once, in the domain layer.** A producer of work
   names a class. No producer names a number.

## Compatibility

7. **The classification is derived from what the work item already carries, not
   stored.** No migration and no backfill, and a mixed-version fleet keeps
   working: an older binary writes the ordinal it always wrote, and the
   classification reads it. A new stored field would not have that property.
8. **Introducing the vocabulary and changing which class a path belongs to are
   two changes, and they ship separately.** Re-classifying the paths is the
   behaviour change; shipping it inside the compatibility step would mean that
   rolling back the fix also rolls back the vocabulary.

## What this decision does not say

- **It is not preemption.** Nothing here interrupts running work or takes
  capacity away from it. The rule is about not being displaced, which is a
  weaker and cheaper guarantee than being able to displace.
- **It does not fix the shares, or the boundaries between classes.** With a
  single worker replica the share *is* the whole control surface, so it is a
  per-deployment concern rather than a constant.
- **A share of zero is a waiver of this decision, and it is permitted on one
  condition: that the deployment is told.** Zero turns off the reservation at
  both allocation points and leaves arrival order, which is the behaviour the
  two instances in *Context* came from — so it is not merely the bottom of the
  range above. It stays available because a deployment recovering from a
  scheduling regression needs a way back that is not a new binary under
  incident, and because nothing an attacker controls reaches it: the cost is
  latency, not authority. The condition is that the waiver is never silent.
  A deployment configured this way states at startup which guarantee it has
  given up; a decision switched off without saying so is indistinguishable
  from one that failed, and neither this decision nor (5)'s observation can
  tell a reader which they are looking at.
- **It does not classify every kind of work.** Which class a given kind
  belongs to is a design question answered per kind, from how long it runs and
  what waits on it — not something this decision can enumerate correctly in
  advance.
- **It does not cover work with a real deadline.** The release sweep arguably
  has one, and deadline ordering would express that directly; it is a larger
  model change and is set aside here, not rejected.

## Consequences

- **Bulk work drains measurably slower, by construction.** A backlog does not
  shrink faster under this decision — it stops blocking the paths someone is
  waiting on while it drains. That is the trade being made, not a side effect.
- **A new kind of work states its class and why, as part of its design.** A
  kind whose author cannot say who waits on it has not been thought through.
- **The queue stops being tunable by one number per kind**, which is the point:
  the number was tunable and still produced two outages, because it could not
  express the thing that mattered.
- **The guarantee in (5) will fire falsely the first time its threshold is set
  too low.** That is the intended direction: a false alarm is recoverable, a
  silent stall is the failure being removed.

## Alternatives considered

- **Re-rank the starved path above the flood.** The one-line fix, and it
  relocates the problem rather than removing it: the starved path then ties with
  whatever sits at the higher rank, and the next flood meets the same
  tiebreaker. It also leaves (3)'s misassignment untouched.
- **Aging — raise effective rank with waiting time.** The classic starvation
  remedy, and insufficient alone: it guarantees service *eventually*, while a
  control task that runs every few minutes needs it *soon*. Worth having as a
  safety net beneath (4), not as a substitute for it.
- **More classes.** Contradicted by the practice this decision follows and by
  the evidence above: the producers of work could not agree on three distinct
  values, so they will not agree on seven.
- **Separate worker processes per class.** The strongest isolation and the wrong
  cost here: it makes non-displacement an operator deployment concern rather
  than a property of the system, and the default deployment is a single replica.
- **Deadline ordering (EDF) instead of classes.** Expresses the real
  requirement most directly and needs a defensible deadline on every kind of
  work; revisit if classes prove too coarse.
