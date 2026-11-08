# 386 — The age net at the permit point

**Issue:** #414 · **Branch:** `agent/414-the-age-net-at-the-permit-point` ·
single item, three parts.

**Governing decisions:** ADR 0066 D1, D4 and D5 as amended on `develop`
(`6fbe1146`). **No ADR question is open** — this enforces what D5 now says.

## a) The age net at the permit point

D5 now states that the guarantee of the class with no reserved share rests on a
**priority-blind age fallback beneath the reservation, present at every point
the reservation is**. It exists at one of the two points: the claim query's
class-blind `oldest` CTE, one row by `created_at ASC`
(`crates/hort-adapters-postgres/src/jobs_repository.rs`). The permit allocation
has no counterpart — `TaskTier::Bulk` reaches the arrival pass only when **no**
waited-on class has a waiter, so at a capacity of one under sustained load it
never runs.

**Build** a pass that, past a bound, serves the **oldest waiter of any class**,
placed **before** both waited-on passes. Placing it after them does nothing: at
a capacity of one a waited-on pass always matches, which is #405's lesson —
the iteration order decides the outcome, not the breadth of a condition.

Three constraints fix the design:

1. **Class-blind, oldest first** — like the claim's `oldest` slot. Explicitly:
   past the bound `Bulk` may be served before `Normal` when its waiter is
   older. That is what "priority-blind" means, and the claim point already
   does it.
2. **It must not swallow #405's service pass.** That pass asks *has this class
   been served lately* (`max(last grant, arrival)`); the net asks *has this row
   waited too long* (arrival only). For a never-served class the two coincide;
   a recently-served class with an old waiter is what separates them. So the
   net's bound must be **strictly greater** than the service interval, or the
   service pass is dead code.
3. **One configured number stays one configured number.** The bound is
   **derived** from `HORT_TASK_CLASS_SERVICE_THRESHOLD_SECS` in the same domain
   policy that holds `permit_service_interval`. The factor is the
   implementation's choice, justified in one sentence. No second environment
   variable.

Inside the bound the net reorders nothing: D1's class order is untouched, and
it is not a second per-class allocation.

## b) The waiver states itself

ADR 0066 now permits `HORT_SCANNER_RESERVED_SLOTS_PER_CLASS=0` explicitly, on
**one** condition: *"A deployment configured this way states at startup which
guarantee it has given up."*

Today the zero is silent — and since #409 it is the only configuration the boot
check cannot complain about: at share 0 `minimum_batch_size` is
`0 × bands + 1 = 1`, so every batch clears it while both waited-on passes are
off. The check passes precisely when the guarantee is gone.

**Build** a startup statement — not a refusal, the zero is permitted — naming
what was given up: no reservation at either allocation point, no time floor, no
age net, pure arrival order, and therefore no guarantee that any class is
served. `warn!`, not `debug!`: a silently disabled decision is
indistinguishable from a failed one.

## c) The module comment that cites the ADR for something it does not say

`crates/hort-app/src/class_fair_permits.rs`, the *"What this does not bound"*
section, argues that at a capacity of one no bulk work runs while waited-on
arrivals sustain, and calls that *"ADR 0066's stated trade"*. The ADR's
consequences say *"drains measurably slower"*, which is a different claim, and
since the amendment the attribution is plainly wrong. Part (a) makes that
section true rather than merely sourced — correct it, including the sentence
about `HORT_SCANNER_RESERVED_SLOTS_PER_CLASS=0`, which now describes a **named
waiver** and not an incidental off-switch.

## Acceptance

1. At capacity **1** with a sustained `Interactive` stream, **`Bulk`** is
   granted a permit in finite time — shown by a driven-clock test that builds
   that stream.
2. Past the bound the older waiter wins, even when it is in `Bulk` and a
   `Normal` waiter is younger.
3. Inside the bound behaviour is unchanged: every test from #405 and the ten
   older ones pass **unmodified**. If one must be rewritten, that is a finding
   to report.
4. #405's service pass is not dead code — shown by a test in which it, and not
   the net, decides.
5. At share 0 a startup message names what was given up; shown by a test. At
   share > 0 it is absent.
6. The bound is derived, not configured, and defined in one place.
7. The module comment no longer cites the ADR for a claim it does not make.

## Read first

- `crates/hort-app/src/class_fair_permits.rs` — all of it, module comment
  included; the three passes and why each exists.
- `crates/hort-domain/src/policy/queue_class_service.rs` —
  `permit_service_interval` and the threshold it derives from.
- `crates/hort-adapters-postgres/src/jobs_repository.rs` — the `oldest` CTE,
  the net that already exists at the other point.
- `docs/adr/0066-background-work-never-outranks-a-waiting-client.md` — D5 and
  *What this decision does not say*, both as amended.
