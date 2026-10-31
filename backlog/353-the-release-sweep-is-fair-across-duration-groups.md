# 353 — The release sweep reaches every policy-duration group

**Issue:** #388 · **Branch:** `agent/388-scan-obligation`
**Governing decisions:** ADR 0007 (release authority) · #331 (the collector
this did *not* go to, because it is loss of function rather than a flag).

## What is true today

`select_expired` groups quarantine windows by duration and queries each group
in turn, spending **one global batch budget** across the groups
(`crates/hort-adapters-postgres/src/quarantine_release_candidates.rs:288-328`):

```rust
for (duration_secs, repos) in by_duration {
    let remaining = (batch_size as i64).saturating_sub(candidates.len() as i64);
    if remaining <= 0 { break; }
    // … LIMIT $3 = remaining, ORDER BY release_attempt_at ASC NULLS FIRST
}
```

`by_duration` is a `HashMap`, and the loop `break`s when the batch is full.

The comment above that loop blesses the non-determinism:

> Iteration order over a HashMap is non-deterministic, which is fine — the
> handler does not rely on candidate ordering (release_expired is loop-driven
> and per-artifact).

That answers the wrong question. Ordering *within* the returned candidates is
indeed irrelevant. The `break` makes the iteration order decide **which
duration groups are visited at all**.

## Why this is a defect

**A group that cannot release can starve a group that can.** If the first
group visited yields `batch_size` rows and none of them is releasable — every
one parent-gated, or provenance-pending — the batch is spent and no other
duration group is queried on that tick. The per-group query does carry a
cursor (`ORDER BY release_attempt_at ASC NULLS FIRST`, and the handler stamps
every row it considered), so rows rotate **within** a group. Nothing rotates
*across* groups.

So a releasable artifact in another duration group waits, and the wait has no
bound: `HashMap` iteration order is not stable across processes, so whether it
is reached is re-decided arbitrarily on every boot rather than progressing.

**The reported instance is the shape where this bites**, though not proof of
it: `candidates=1000 released=0 skipped_provenance_pending=126
held_parent_gated=874` — a full batch, nothing releasable. Whether those 1000
all sat in one duration group was not measured, so treat the operator's
numbers as the motivation and the code above as the evidence.

## The change

Make the selection fair across groups. Two shapes, either acceptable:

1. **One ordered query** over all expired candidates, with the per-repository
   duration cutoff expressed in SQL (a `JOIN` or a `VALUES` list of
   `(repo, cutoff)`), ordered by `release_attempt_at ASC NULLS FIRST` so the
   existing cursor becomes global.
2. **A per-group allocation** — each group gets a share of the batch, with
   leftovers redistributed, plus a stable group cursor so the group that was
   cut off last tick is visited first next tick.

(1) is preferable if the query stays readable: it makes the existing
`release_attempt_at` cursor do the fairness work instead of adding a second
mechanism.

Replace the misleading comment either way: what matters is not that ordering
within a batch is irrelevant, but that the budget must not be consumable by
one group.

## Acceptance

1. With two duration groups, the first holding `batch_size` unreleasable rows
   and the second one releasable row, the releasable artifact is released —
   on the first tick under (1), within a bounded number of ticks under (2).
2. The bound in (2), if chosen, is asserted, not assumed: a test fixes the
   number of ticks.
3. An artifact's `release_attempt_at` is still stamped for every row
   considered, so the existing within-group rotation is unchanged.
4. **Counter-assertion.** A test with a single duration group proves the
   change did not quietly alter today's behaviour for the common case.
5. `hort-adapters-postgres` needs ≥ 85%; DB-backed tests carry
   `#[serial(hort_pg_db)]`.

## Out of scope

- The *reason* those 874 rows are parent-gated. A gated artifact is correctly
  withheld; this unit is about the batch it occupies, not its verdict.
- A progress metric for the sweep. The reporter's §7 asked for one and it is
  a dashboard rather than a behaviour — but note that this unit removes the
  starvation that would have made such a metric alarming for the wrong
  reason.
