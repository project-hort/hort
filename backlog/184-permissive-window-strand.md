# 184 — the release sweep selects by deadline, not by current policy

**Issue:** #250 · **Branch:** `agent/250-permissive-strand` · single item.

## Problem

`crates/hort-adapters-postgres/src/quarantine_release_candidates.rs` builds its
candidate set in two steps. Step 1 asks state which repositories hold
quarantined artifacts — correct. It then resolves each repository's *current*
effective window and discards any whose window is not positive:

```rust
if let Some(secs) = effective {
    if secs > 0 {
        by_duration.entry(secs).or_default().push(repo);
    }
}
```

with the comment *"permissive mode is exactly 'no quarantine hold,' so no
release-sweep work."*

That is true for future ingests into a permissive repository and false for
artifacts already held. A repository switched to `quarantine_duration_secs = 0`
while artifacts sit inside their window leaves every one of them `quarantined`
with `release_attempt_at = NULL` forever: the sweep never selects them, no
client action moves `quarantine_window_start`, and the only exit is a manual
per-artifact waive. Observed in production — 29 artifacts held nineteen days,
two of them pinned in a consumer's lockfile, so every `npm ci` through that
repository failed.

## Why the guard is wrong rather than merely incomplete

**It saves nothing.** Under `quarantineDuration: 0` an artifact is never put
into `Quarantined` at ingest at all (`crates/hort-app/src/use_cases/
quarantine_use_case.rs`, the `record_clean_scan` no-op comment). A permissive
repository therefore contributes no rows to the step-1 query in steady state.
The guard's only reachable effect is the transition case, where it is the
defect.

**The general formula already answers zero correctly.** With `secs = 0` the
cutoff is `now`, so `quarantine_window_start <= now` holds for every held
artifact: they become candidates and `release_expired` applies the real gates.
That is precisely what permissive means, and it is the same arithmetic the scan
fast path uses for a zero window. The guard contradicts the rest of the
codebase.

**It is the second defect of this shape in these four lines.** The preceding
one was the missing `DefaultPolicy` fallback on the line above — same failure
(a repository silently outside the candidate set, no signal), different cause.
The responsibility is misplaced: selection decides *which artifacts are past
their deadline*; authority decisions (ADR 0007 release authority, ADR 0027
provenance clearance) are made per artifact in `release_expired`. The fix
removes the policy judgement from the selection step rather than adding a third
special case later.

## Correction

Group by the resolved duration clamped at zero instead of discarding
non-positive values:

```rust
let secs = effective
    .unwrap_or_else(DefaultPolicy::quarantine_duration_secs)
    .max(0);
by_duration.entry(secs).or_default().push(repo);
```

The clamp covers a negative value as well as zero — both mean the window is
behind us — and prevents a cutoff in the future, which would select rows whose
window has *not* elapsed.

The comment states the invariant: this step selects by deadline only;
permissive is a zero-length window, not an absent one; the authority decisions
belong to `release_expired`.

The `if by_duration.is_empty() { return Ok(Vec::new()); }` early return stays.
It is now reachable only when no repository holds a quarantined artifact, which
is the honest meaning of "no candidates".

## Must not change

- **No new release authority.** Candidates still flow through `release_expired`
  and its existing `(ReleaseReason::Timer, ReleaseAuthorization::ScanSucceeded)`
  pair.
- **The provenance gate still applies.** A `Required` + `Pending` artifact in a
  now-permissive repository is still refused and still enqueues its final
  `provenance-verify`. Permissive is a quarantine-window opt-in, not an opt-out
  of ADR 0027.
- **Soft-deleted artifacts stay excluded** in both queries.

## Acceptance

- A repository with a zero window holding artifacts quarantined under a prior
  window releases them on the next sweep tick, with no operator action, no
  migration and no backfill.
- Nothing is released that `release_expired`'s scan-authority or provenance gate
  would refuse.
- The `secs > 0` special case is gone from the adapter, not narrowed.

## Tests

1. Zero-window repository holding artifacts quarantined under a prior window:
   they are candidates and are released. The regression test for the production
   shape.
2. Same, with `provenance_mode: Required` and no `ProvenanceVerified`: the
   artifact is a candidate, is **not** released, and its final
   `provenance-verify` is enqueued.
3. Zero-window repository with no quarantined artifacts contributes nothing —
   step 1 already excludes it.
4. A negative duration behaves as zero and produces no future cutoff.
5. The missing-policy-row `DefaultPolicy` fallback still holds.

DB-touching tests carry `#[serial(hort_pg_db)]`.
