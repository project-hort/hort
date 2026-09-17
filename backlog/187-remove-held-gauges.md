# 187 — remove the batch-scoped provenance gauges; point ADR 0039 D4 at the projection surface

**Issue:** #260 · **Branch:** `agent/260-remove-held-gauges` · single item.

## Problem

ADR 0039's D4 holds an unsigned `Required` artifact indefinitely and rests that
on the operator seeing the held set with its age — *"a metric keeps the age, a
status column discards it."* The two gauges introduced for it,
`hort_provenance_held_artifacts{hold}` and
`hort_provenance_hold_oldest_age_seconds{hold}`, do not show the held set.
`QuarantineReleaseSweepHandler::run` sets them from **one tick's candidate
batch**, capped at `BATCH_SIZE` (`quarantine_release_sweep.rs:88`,
`docs/metrics-catalog.md:3320-3321`): they saturate once the population
exceeds a batch, jump as candidates rotate under the anti-starvation order,
and fall without any release. They also live in the worker's recorder, whose
`/metrics` is off by default — the gated server endpoint never carried them.

A metric whose name promises more than its definition delivers is worse than
none. The operator's decision (2026-09-16): remove the batch-bound approach
entirely; the population question moves to retention (#244).

## Correction — the minimum

1. **Remove both gauges completely.** The `gauge!` sets in the sweep handler,
   every mention in `docs/metrics-catalog.md` (the table rows at ~3320-3321,
   the D4 paragraph at ~3347-3360, and any cross-reference), and the tests that
   read them (`quarantine_release_sweep.rs` ~1390-1436 and surroundings).
   `grep -rn hort_provenance_held_artifacts` and
   `grep -rn hort_provenance_hold_oldest_age` over `crates/` and `docs/` must
   return nothing. **No replacement metric** — not batch-independent, not
   server-side. If retention (#244) later derives a gauge from its own count,
   that is a trigger there, and #244's decision.
   The batch-bound approach includes its feeders: `crate::metrics::
   set_provenance_hold_population` and the `ProvenanceHold` label enum
   (`metrics.rs`), `emit_hold_population` in the sweep handler, and the
   `oldest_provenance_pending_hold_secs` / `oldest_parent_gated_hold_secs`
   fields of `ReleaseExpiredSummary` (`ports/quarantine_release.rs`,
   computed in `QuarantineUseCase::release_expired`) together with their
   tests — remove each one whose only consumer was the gauges (grep first;
   the `skipped_provenance_pending` / `held_parent_gated` counts stay, the
   tick log reads them).
2. **Keep the sweep's `info!` tick log** (`candidates / released /
   skipped_provenance_pending / held_parent_gated`). It describes *that tick*
   and claims nothing about the population — honest for a log line. It is not a
   metric and must not be turned into one.
3. **Reword ADR 0039 D4.** The sentence *"a metric keeps the age, a status
   column discards it"* stays as the reason to write **no terminal status**. The
   operator's view of the held set is **not a metric**: it is the authoritative
   surface over the projection — today the admin curation queue (which reads
   `events` via `LATERAL`), and, once it exists, retention's overview (#244),
   where disposal is decided operator-confirmed and never automatically. Say
   that, and point at #244.
4. **Metrics catalog:** replace the D4 paragraph with one that says why the
   gauges are gone and where the view lives instead.

## Must not change

- Candidacy, the authority gates, and the hold-instead-of-reject decision.
- No schema, no migration, no new metric.

## Acceptance

- The two grep commands above return nothing.
- The sweep handler sets no gauge; its tick log is byte-identical.
- ADR 0039 D4 names the projection surface as the operator's view and points at
  #244; the terminal-status sentence remains.
- `docs/metrics-catalog.md` is consistent.
- `cargo test --workspace` green; no test references the removed gauges.
