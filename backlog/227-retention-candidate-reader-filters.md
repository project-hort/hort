# 227 — The retention candidate reader misses a quarter of the inventory and offers deleted rows

**Issue:** #284 · **Branch:** `agent/284-candidate-reader-filters`
**Order:** first. Every number a policy, a preview or a cleanup proposal reports
is drawn through this query, so it is wrong until this lands.
**Governing decisions:** ADR 0007 (invariant 1 — the excluded evidence set stays
exactly as it is) · the DB-test isolation contract (`#[serial(hort_pg_db)]`).

## Why

Two filter faults sit in the same `WHERE`, and they pull in opposite directions:
the set retention operates on is not the set the use case considers eligible.

### 1. Artifacts with no quarantine status are invisible

`crates/hort-adapters-postgres/src/retention_candidate_reader.rs:151-152`:

```sql
WHERE a.quarantine_status NOT IN ('quarantined', 'rejected', 'scan_indeterminate')
```

`QuarantineStatus::None` is persisted as SQL `NULL`
(`crates/hort-adapters-postgres/src/artifact_repo.rs:1128-1131`, and again at
`1195-1199`). In three-valued logic `NULL NOT IN (…)` is *unknown*, not *true*, so
the row is never selected. Every artifact without a status is unreachable for
every retention policy.

That this is a defect and not a choice is written down twice, in the two doc
comments over this very query: the adapter's header says the filter admits
"`none` / `released`" (`retention_candidate_reader.rs:14-17`) and the port's
enumeration-scope section says the same
(`crates/hort-domain/src/ports/retention_candidate_reader.rs:16-18`). The
evaluator agrees (`crates/hort-app/src/use_cases/retention_use_case.rs:262-288`).
Only the SQL disagrees.

**Scale:** 12 883 artifacts / 1.5 GB in the production instance — the second
largest status block after `released`.

**The NULL-safe form already exists in this repository**, at all three sibling
sites: `crates/hort-adapters-postgres/src/refcount_reconcile.rs:163-165` and
`209-211`, and `crates/hort-adapters-postgres/src/purge_gc.rs:196-198` all write
`(a.quarantine_status IS NULL OR a.quarantine_status NOT IN (…))`. The candidate
reader is the only one of the four that omits the `IS NULL` arm. So the ends of
the pipeline currently disagree: the pending-purge reader would accept a
status-less artifact that the candidate reader can never expire. The fix makes
them agree; it does not open a path the purge side was not already prepared for.

### 2. Soft-deleted artifacts are offered as candidates

The same query has no `deleted_at` predicate — the column appears only in the
select list (line 128). Every other read site in `artifact_repo` filters deleted
rows; this one hands them out.

## Read first

- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` — the query,
  its keyset pagination and the two doc paragraphs to reconcile.
- `crates/hort-domain/src/ports/retention_candidate_reader.rs:10-30` — the port's
  enumeration-scope contract.
- `crates/hort-adapters-postgres/src/refcount_reconcile.rs:155-170` — the
  NULL-safe form to mirror.
- `crates/hort-adapters-postgres/src/purge_gc.rs:180-200` — the pending-purge
  reader, the other end of the pipeline.
- `crates/hort-adapters-postgres/src/artifact_repo.rs:1120-1140,1190-1205` — how
  `QuarantineStatus::None` becomes `NULL`.

## Scope

1. **Make the status filter NULL-safe.** Prefer the positive form — name the
   eligible set rather than negating the excluded one — because the fault was
   exactly that a negation silently stopped being total. If the positive form
   costs an index, mirror the sibling sites' `IS NULL OR NOT IN` instead and say
   so; either way the admitted set is `none` + `released` and nothing else.
2. **Add `AND a.deleted_at IS NULL`.**
3. **Reconcile the two doc paragraphs** with what the query then does. They are
   currently right about the intent and wrong about the behaviour.
4. **One DB-backed test per fault**, both with `#[serial(hort_pg_db)]`: an
   artifact with `quarantine_status IS NULL` **is** enumerated; a soft-deleted
   one is **not**. Neither exists today, which is why neither fault was caught.
5. **Check no other reader repeats the pattern.** The three sites above are
   already NULL-safe; the curation queue uses a positive `IN` and is unaffected.
   Confirm that by search rather than by assumption, and record the result.

## Acceptance

- An artifact with `quarantine_status IS NULL` appears in the candidate
  enumeration.
- A soft-deleted artifact does not.
- Both are pinned by DB-backed tests carrying `#[serial(hort_pg_db)]`.
- Invariant 1 is untouched: `quarantined` / `rejected` / `scan_indeterminate`
  stay excluded, and a test still proves it.
- The adapter and port doc paragraphs describe the query as it now behaves.
- Gate green; `hort-app` and `hort-domain` stay at 100 %; no issue, MR or backlog
  numbers in code comments.

## Explicitly not in this item

No predicate work, no scope work, no purge changes, no preview.

**One consequence to name rather than absorb.** Excluding soft-deleted rows is
required — without it, once a purge retires its row, the next evaluation sweep
would enumerate that row again and append a fresh `ArtifactExpired` after the
terminal `ArtifactPurged`. But a soft delete does not release the artifact's
`content_references` (`crates/hort-app/src/use_cases/artifact_use_case.rs:335-346`:
"blob lifetime stays refcount-gated GC"), so the refcount never reaches zero on
its own. With this exclusion in place, the bytes behind a user-deleted artifact
have no path to reclamation at all: retention will not see the row, and nothing
else drops the references. That is a distinct unit — reclamation should follow
the delete, not wait for a policy predicate to happen to match a row that is
already withdrawn from service — and it is deferred deliberately, not overlooked.
