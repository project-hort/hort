# 074 — #131 item 1: root-cause and fix the silent provenance-verify claim starvation (F0+F1)

**Issue:** #131 (release-blocker; spec approved on the issue 2026-08-07). This is the
**investigation-first** item: the defect is evidenced but the mechanism is
deliberately unpinned — the reproduction decides the fix. Item 2
(`backlog/075-s4-guard-and-placement.md`) covers the two already-proven S4 defects
and is dispatched AFTER this item reports.

**Read first (all of it — the evidence eliminates the obvious explanations):** the
full evidence chain on #131 (three comments: mechanism synthesis, jobs-table dump
reading, final spec with candidates C1-C3);
`crates/hort-app/src/task_dispatcher.rs` (`run` :160-232 — claim is NOT
permit-gated; rows go `running` at claim; `dispatch_one`);
`crates/hort-adapters-postgres/src/jobs_repository.rs`
(`CLAIM_PENDING_BY_KINDS_SQL` :114-130 — shared across ALL kinds,
`ORDER BY priority DESC, created_at ASC LIMIT $2`, batch row-mapping with
`?`-propagation AFTER the UPDATE committed; `enqueue_provenance_verify_in_tx` :74);
`crates/hort-worker/src/composition.rs` (`register_provenance_verify`, the
concurrency table ~:550-620, and HOW this dispatcher's kind list is assembled —
candidate C3 lives here); `quarantine_use_case.rs::enqueue_final_provenance_verify`
(the S4 enqueue's **priority argument** — needed for C2).

## Observed facts (from a live compose stack, 2026-08-07)

- Worker processed `provenance-verify` jobs at steady cadence, then stopped
  claiming the kind entirely at ~17:06:50. Every later row (~1450 in 33 min) sits
  `pending, attempts=0, locked_until NULL` for hours. **No `running` rows.**
- The SAME dispatcher kept claiming + completing `quarantine-release-sweep` jobs
  every 5 minutes throughout.
- No panics, no ERRORs, only two unrelated boot WARNs in the whole worker log.
- All pending rows satisfy every predicate of the claim SQL as written.

These facts are mutually contradictory for the code as read — one premise is false
at runtime. Finding which one IS the work item.

## Work

1. **F0 — reproduce in a DB-gated test** (`hort-adapters-postgres` integration or
   `hort-app` with the real adapter; `#[serial(hort_pg_db)]` +
   `shared_migrated_pool()`/`isolated_db_from` per the crate convention): seed the
   observed shape — a large pending `provenance-verify` population (mixed
   priorities: the ingest-enqueue priority AND the S4-enqueue priority — read both
   from the code, do not guess), plus fresh per-tick higher-priority scheduled rows
   — and drive `claim_pending_by_kinds` with the worker's REAL `batch_size` /
   `kinds` wiring. Determine which candidate reproduces:
   - **C1** batch-mapping poison: one unmappable row poisons the whole claimed
     batch after the UPDATE committed (rows leak into unclaimable `running`).
   - **C2** priority inversion: `ORDER BY priority DESC ... LIMIT batch_size`
     starves low-priority kinds whenever ≥batch_size higher-priority rows are
     pending at every poll instant (possibly self-inflicted via the S4 flood).
   - **C3** the provenance kind is claimed by a different poll path than the
     scheduled kinds, and that path can terminate silently.
   If NONE reproduces, report the negative results with the seeded shapes and
   STOP — do not fix blind (the report is then the escalation).
2. **F1 — fix the identified mechanism.** Shape depends on the finding, but the
   acceptance properties are fixed regardless of cause:
   - a claimed-but-not-dispatched row must never be permanently lost: either the
     claim is atomic with successful mapping, or unmapped rows revert to
     `pending` in the same transaction;
   - no kind can silently starve: if eligible pending rows for a registered kind
     exist and none was claimed for longer than a threshold, the worker emits an
     ERROR log + a metric (catalog addition if needed — follow
     `docs/metrics-catalog.md` conventions);
   - the reproduction from F0 becomes the permanent regression test (serial key,
     self-skip without `DATABASE_URL`).
3. **Scope guard:** do NOT touch the S4 guard, the S4 placement, or the E2E
   scenario — that is item 075. If the F0 finding implicates the S4 enqueue
   priority as the trigger (C2 self-flood), still fix only the claim-side
   property here and note the interaction in the report; 075 kills the flood.

## Scope / acceptance

- Production code changes allowed in `hort-app` dispatcher / `hort-adapters-postgres`
  jobs repository / `hort-worker` composition — whatever F0 implicates, and only that.
- `hort-app` tier: 100% coverage on new/changed branches; adapter tier ≥85% with
  `#[serial(hort_pg_db)]` on every DB test.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` (with and without `DATABASE_URL` in the sandbox),
  `cargo audit --deny warnings`, `cargo deny check`.
- Report MUST name the confirmed mechanism with the reproducing test's name, or
  the negative-result escalation.

**Model hint:** opus — this is an investigation with a misleading surface (the
evidence contradicts the code as read); a wrong conclusion here costs a release
cycle.
