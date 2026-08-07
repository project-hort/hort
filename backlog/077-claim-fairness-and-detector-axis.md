# 077 — #132 item 1: bounded-starvation claim fairness + detector oldest-row axis

**Issue:** #132 (spec approved 2026-08-07). Both changes close gaps the #131 incident
proved live: priority-0 rows starved for 2h+ behind a sustained priority-10 stream of
the SAME kind, and the (then-new) starvation detector stayed silent because it clocks
per-kind claims.

**Read first:** #131's closed-mechanism comment (the GROUP-BY dump table);
`crates/hort-adapters-postgres/src/jobs_repository.rs::CLAIM_PENDING_BY_KINDS_SQL`
(:114-130) and its shape-pinning test; `crates/hort-app/src/task_dispatcher.rs`
(`detect_starvation`, `audit_starvation`, the poll loop);
`crates/hort-domain/src/ports/jobs_repository.rs::eligible_pending_by_kind`
(`PendingKindBacklog` already carries `oldest_created_at`);
`docs/metrics-catalog.md` (the three #131-round metrics' conventions).

## Work

1. **Fairness — reserved-oldest slot (chosen direction).** Per poll, one claim slot
   (of `batch_size`) is reserved for the single OLDEST eligible row across all
   registered kinds regardless of priority; the remaining `batch_size - 1` keep the
   existing `priority DESC, created_at ASC` order. Rationale over the alternatives
   (groomed choice — argue in the report only if you find it objectively worse):
   aging changes priority semantics for every consumer; tier unification erases
   deliberate prioritization; the reserved slot gives a hard bound — no eligible row
   waits more than ~batch-drain time × queue-of-oldest — with zero semantic change
   for the other slots.
   - Implement inside the claim SQL (one statement, keep `FOR UPDATE SKIP LOCKED`
     semantics for both parts; dedup the reserved row against the ordered part).
   - Update the SQL-shape-pinning test; extend `sort_claimed_jobs` if ordering
     assumptions change.
   - DB-gated regression: the #131 shape (sustained fresh prio-10 stream + old
     prio-0 rows) drains the prio-0 rows within N polls; assert a hard upper bound.
2. **Detector axis:** extend `detect_starvation` with an oldest-eligible-age check —
   alarm when `oldest_created_at` age exceeds `STARVATION_THRESHOLD`, independent of
   last-claim recency, with a distinct `reason = "oldest_row_stalled"` label value on
   the existing `hort_admin_tasks_starved_total` counter (catalog update). The #131
   replay (kind claimed constantly, old rows rotting) must alarm in a unit test.
3. The claim change is shared across every kind — full-workspace gate is the
   regression net; the `claim_starvation.rs` suite from #131 must stay green
   untouched.

## Scope / acceptance

- `hort-app` 100% tier on changed branches; adapter DB tests per the crate's serial
  conventions.
- No changes to enqueue priorities, S4, or handler registration (item 078 territory).
- Gate: full pre-push suite (fmt, clippy -D warnings, test --workspace with and
  without DATABASE_URL, audit, deny).

**Model hint:** sonnet (direction chosen; the SQL is delicate but the test matrix is
prescribed).
