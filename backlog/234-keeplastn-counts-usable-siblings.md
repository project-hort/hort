# 234 — `KeepLastN` counts usable siblings, not live rows

**Issue:** #292 · **Branch:** `agent/292-keeplastn-usable`
**Governing decisions:** ADR 0007 (Invariant 1 — protected artifacts stay
un-collectable; unchanged here) · #287 D4 (a tag protects against `KeepLastN`
only — confirmed 2026-09-25, unchanged) · #281 §2 P2 (the hosted churn
`KeepLastN` exists for).

## Why

The `ranked` CTE in `crates/hort-adapters-postgres/src/retention_candidate_reader.rs`
ranks over **every live row** of the sibling group — `s.deleted_at IS NULL` is
its only filter. GC-protected siblings (`quarantined`, `rejected`,
`scan_indeterminate`) are filtered out of the candidate `page`, so they can
never expire themselves, but they **occupy a rank slot**. Pinned today by
`keep_rank_counts_gc_protected_siblings`.

The consequence is not that the usable window shrinks. It is that it can reach
**zero**:

> `KeepLastN(3)`, five siblings. The three newest are quarantined — one scan hit
> on a fresh build burst puts them there together. Ranks 1–3 go to the
> quarantined ones; ranks 4 and 5 to the two released ones, both over N, both
> expired.

What survives is three artifacts, none of them downloadable
(`Artifact::is_downloadable()` is true only for `None | Released`) and none of
them collectable under Invariant 1. The operator configured "keep the last
three" and has none.

## Decision (Tom, 2026-09-25)

**`KeepLastN(N)` means N *usable* artifacts, not N live rows.** The stated
reason: in the worst case only unusable ones could be left, and that must be
prevented.

The counter-cost is accepted explicitly: total rows per group then sit at N plus
the protected set rather than at N. That excess is bounded by a population this
knob cannot touch in any case — 257 MB of 142 GB instance-wide (#280).

## What to change

The predicate already exists and is **not** to be re-invented. The `page` CTE
filters with

```sql
(a.quarantine_status IS NULL OR a.quarantine_status <> ALL($4::text[]))
```

bound from `gc_protected_quarantine_status_names()`
(`crates/hort-adapters-postgres/src/lib.rs`). `ranked` gets the same clause on
its own alias and the same binding. The `IS NULL` arm is load-bearing:
`QuarantineStatus::None` persists as SQL `NULL`, and the legacy spellings
`unscanned` / `clean` / `flagged` also resolve to `None` — so the predicate must
**exclude the three protected values** rather than enumerate the usable ones.

After the change `page` and `ranked` agree on what counts. Today they
contradict each other, and that contradiction is the defect.

## What moves with it, and must be written down

- **`sibling_total` changes meaning** to "usable siblings". Find every consumer
  and check each one; the rename-or-document call is yours, but a silent change
  of meaning is not acceptable.
- **A later release re-enters the rank** and can push an older released sibling
  over the edge. That is correct — releasing makes it usable, so it counts — but
  it is behaviour a reader will otherwise take for a bug. Say it in the module
  doc.
- **A soft-deleted sibling still occupies no slot.** Unchanged.
- **The tag exemption is unchanged** (#287 D4).
- The module doc currently *justifies* today's choice — "they are live bytes on
  disk, and 'keep the last n' counts live artifacts". Replace that reasoning,
  do not just delete it: the successor must say why usability is the measure and
  what was given up for it.

## Read first

- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` — the whole
  module doc (it explains why the page is a CTE at all — that property must not
  regress) and the `page` / `sibling_groups` / `ranked` CTEs.
- `crates/hort-adapters-postgres/src/lib.rs` —
  `GC_PROTECTED_QUARANTINE_STATUSES`, `gc_protected_quarantine_status_names`.
- `crates/hort-domain/src/entities/artifact.rs` — `is_downloadable`.
- `crates/hort-domain/src/retention/evaluate.rs` — the `KeepLastN` arm that
  consumes `keep_rank` / `sibling_total`.

## Acceptance

- A test for the scenario above: `KeepLastN(3)`, three quarantined newest
  siblings, two older released — **both released survive**.
- A test showing a released sibling can be pushed out again once a quarantined
  one is released.
- `keep_rank_counts_gc_protected_siblings` is **rewritten, not deleted**: it
  holds the opposite rule today and must hold the new one, under a name that
  states it.
- Ranking stays independent of the page boundary — the property the CTE exists
  for. A sibling group several times the page size must rank identically
  whichever page it is read on.
- `#[serial(hort_pg_db)]` on every test that acquires a real connection.
- Gate green.

## Explicitly not in this item

No change to Invariant 1 or to which statuses are GC-protected. No change to the
tag exemption. No change to the purge path. No new predicate.
