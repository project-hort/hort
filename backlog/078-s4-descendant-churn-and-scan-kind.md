# 078 — #132 item 2: S4 descendant-churn elimination (design-carrying) + scan-kind poison-row source

**Issue:** #132 (spec approved 2026-08-07). Dispatched AFTER item 077 merges (both
touch the jobs pipeline; sequential keeps the blame surface clean).

**Read first:** #131's closed mechanism (the churn measured at ~43 jobs/min);
`quarantine_use_case.rs::release_expired` (post-#131 shape: S4 now runs before the
authority guard) and `enqueue_final_provenance_verify`;
`provenance_orchestration.rs` — the `is_referenced_descendant` hold arm and the
ADR 0039 cascade comments (cascade-cleared constituents, the "re-judging can only
harm" skip); ADR 0007 (`is_referenced_tree_descendant`, anchor backdating);
report 065 §flags (the scan-kind poison-row finding);
`crates/hort-domain/src/events/authorization_events.rs::VALID_TASK_KINDS`;
`migrations/009_scan_jobs_and_findings.sql` (jobs CHECK constraints; pre-1.0
edit-in-place rule).

## Part A — stop re-enqueueing parent-gated descendant holds (design-carrying)

Today `release_expired`'s S4 enqueues a final verify for EVERY `Required + Pending`
past-deadline candidate each tick. For a referenced-tree descendant that verify
always completes as held (its terminal state comes from the parent's cascade by
construction) — measured at ~43 wasted jobs/min live, and it was the flood side of
#131's feedback loop.

**Direction:** skip the S4 enqueue when the candidate is a referenced-tree
descendant, BUT the edge-case analysis is mandatory and the report must carry it:

- descendant whose parent reached terminal `Rejected` — the cascade is the settling
  mechanism (verify it actually transitions descendants; cite the code path);
- descendant whose parent artifact row is GONE (purged/GC'd) while the descendant
  remains `Quarantined` — this is the case that must NOT strand: define the behavior
  (fall back to enqueueing the final verify when no live parent references the
  descendant? the `is_referenced_tree_descendant` predicate input is the live
  `content_references` rows, so a purged parent's edges may already be deleted —
  verify edge lifecycle on purge, `#49`-adjacent) and pin it in a test;
- mixed trees (one parent resolved, another still pending, shared blob) — held is
  correct while ANY live parent is unresolved; assert the predicate already gives
  this.

If the analysis surfaces a case where skipping strands an artifact and no cheap
fallback exists: STOP and report — that outcome graduates to an ADR question, not a
silent judgment call.

The resolve of `is_referenced_descendant` at the S4 site must follow the
fail-closed error direction documented in `complete_provenance` (propagate, don't
degrade to false — here `false` would re-create the churn, degrade to `true` would
strand; propagate-and-retry is the only safe shape. State this in a comment as an
invariant.)

## Part B — close the scan-kind poison-row source

`"scan"` is admin-invokable via `enqueue_task`, which writes no scan-typed columns;
`decide_kind_fields` then rejects the row at claim (the #131-round claim hardening
now handles it terminally, but the row should never exist). Pick the structural
close after checking consumers:
- if nothing legitimately admin-invokes bare `"scan"` (expected — manual rescans go
  through `manual_rescan_use_case`): drop `"scan"` from `VALID_TASK_KINDS` (keep the
  SQL CHECK in lockstep per the migration's comment) — apply-side rejection;
- otherwise: add the jobs-table CHECK (`kind='scan'` ⇒ scan columns NOT NULL),
  edited in place in migration 009 per the pre-1.0 rule, and update
  `no_sensitive_drops` expectations if the guard trips.

## Scope / acceptance

- `hort-app` 100% tier; DB tests per crate serial conventions; migration edit (if
  any) keeps the `kind IN (...)` list and `VALID_TASK_KINDS` in lockstep.
- The E2E provenance scenario must remain green (no behavioral change for roots or
  for descendants whose parents resolve).
- Gate: full pre-push suite.

**Model hint:** opus (Part A carries real design analysis with strand-risk; the
stop-and-report path is live).
