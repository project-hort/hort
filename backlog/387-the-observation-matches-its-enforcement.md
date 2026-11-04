# 387 — The observation matches its enforcement

**Issue:** #415 · **Branch:** `agent/415-the-observation-matches-its-enforcement`
· single item.

**Governing decisions:** ADR 0066 D5 as amended on `develop`. **No ADR change**
— this enforces what the clause requires.

## The finding

D5 now requires the guarantee to be *"observable at the granularity it is
enforced at"*, and says why: *"An observation coarser than the enforcement is a
statistic and not an alarm — a guarantee enforced per kind and per class, and
watched per class alone, can be reported healthy by a sibling kind's
progress."*

That is the state today. `QUEUE_SAMPLE_BY_BAND_SQL`
(`crates/hort-adapters-postgres/src/jobs_repository.rs`) joins `public.jobs`
only on the band's priority bounds — **no `kind` filter** — so its
`last_served_at` is, by its own doc comment, *"the newest `completed_at` of any
row in the band"*: the newest completion of **any** kind in that class.

Enforcement is per registered kind: `ClassFairPermits` is built per `kind`, the
time floor from #405 counts per kind and class, and the age net from #414 does
too.

**Consequence:** a kind whose class is starving at its own permit point can be
reported healthy because a *different* kind of the same class just finished.
The case the audit exists for — the floor did not engage and nobody sees it —
is exactly the one this aggregation can hide.

The project already knows this failure shape: `TaskDispatcher::class_service_threshold`'s
doc comment explains why the metrics catalog names **both readers** of the
threshold, because an operator who sets the variable on one of the two
deployments gets a log and a gauge answering at different thresholds. Here it is
not two readers with different numbers but two **granularities** for one
guarantee.

## What to build

The observation gains the dimension the enforcement has. The gauge already
carries a class label; `kind` is a label, not a new mechanism.

Three constraints:

1. **Name and bound the cardinality.** 26 kinds × 3 classes is harmless, but
   the number belongs in the metrics catalog — and decide whether a kind with
   no registered allocator needs a series at all.
2. **Do not lose the class-wide answer.** An operator asking "is this class
   starving" must still get an answer; the finer series is an addition, not a
   replacement, and how the two coexist is part of the design.
3. **One query per sample, not one per kind.** The SQL answers five questions
   per band in **one** statement and its doc comment gives the reason: the
   facts have to describe the same instant. A loop over kinds would be a set of
   instants, and a class could read "nothing waiting" and "never served" from
   two different moments.

Also answer, in the same pass, the follow-on from #414: the
`awaiting_capacity` verdict means something narrower since both enforcement
times sit below the audit window. Whatever the catalog says about it has to fit
the new granularity.

## Acceptance

1. A kind whose class is starving at its permit point is reported as starving
   even when another kind of the same class has just completed — shown by a
   test that builds exactly that constellation.
2. The class-wide answer is still available.
3. A sample stays **one** statement; the facts of a series describe one
   instant.
4. The cardinality is in the metrics catalog, with the rule for which kinds get
   a series.
5. No test green today has to be rewritten; if one does, that is a finding to
   report.

## Read first

- `crates/hort-adapters-postgres/src/jobs_repository.rs` —
  `QUEUE_SAMPLE_BY_BAND_SQL` and its doc comment, which states the
  one-statement reason and the unbounded `last_served_at` on purpose.
- `crates/hort-domain/src/policy/queue_class_service.rs` —
  `evaluate_class_service`, the verdict and its reference instant.
- `crates/hort-app/src/task_dispatcher.rs` — `audit_class_service`, and
  `class_service_threshold`'s doc comment on naming both readers.
- `docs/metrics-catalog.md` — the per-class series and what #414 added beside
  it.
- `docs/adr/0066-background-work-never-outranks-a-waiting-client.md` — D5 as
  amended.
