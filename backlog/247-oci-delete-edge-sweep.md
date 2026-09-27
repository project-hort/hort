# 247 — A failed manifest DELETE leaves a live manifest without its keepalive edges

**Issue:** #301 · **Branch:** `agent/301-oci-delete-edge-sweep`
**Governing decisions:** ADR 0054 (CAS-shared bytes) · ADR 0007 (the quarantine
window, which is the other side of the trade) · #295 (the purge now deletes
these edges transactionally, which is what makes the eager deletion redundant).

## Why

The OCI manifest `DELETE` (`crates/hort-http-oci/src/manifests_write.rs`)
removes the `content_references` **before** the state change, non-
transactionally, warn-on-fail:

```rust
// warn and continue on error
content_reference_use_case.delete_by_source_for_repo(repo_id, artifact.id)
// can fail → OciError::Internal
ArtifactUseCase::delete(...)
```

If the second step fails, a **live, servable manifest is left with its
keepalive edges permanently gone** — `oci_config`, `oci_layer`,
`oci_index_member`. `refcount_reconcile` repairs only `primary_content` and
`metadata_blob`, so it does not repair these. The manifest's layers become
collectable while the manifest is still served: at the next purge the bytes
vanish under an artifact every read path considers healthy.

Found while building #295, analysed there and deliberately not fixed — it is
pre-existing, and the fix is a trade rather than an unambiguous improvement.

## The trade

Since #295 the eager edge deletion is **redundant**: `purge_artifact_refs`
performs the same deletion transactionally and at the right moment. Deleting
the eager call would close the defect for free.

**But deleting it opens a different window.** A deleted manifest's edges would
then stand until a purge interval, and
`resolve_referenced_tree_descendant_fail_safe`
(`crates/hort-app/src/use_cases/referenced_descendant.rs:86`) reads the
**unfiltered** inbound edge set to decide a question about the quarantine
window. Exposure is narrow — it requires the edge's target artifact to have
been deleted and re-created inside the window — and referrers are already
guarded (the handler discards tombstoned sources). Narrow is not nil, and it
is security-adjacent.

## The thing that decides it, and it is not in the issue

`resolve_referenced_tree_descendant_fail_safe` carries this comment above its
read:

> The UNFILTERED kind set — `is_referenced_tree_descendant`'s contract;
> filtering at the port would silently narrow it.

So "filter out tombstoned sources" is not a free adjustment: it runs against a
stated contract. Either that contract is about *kinds* and says nothing about
source liveness — in which case filtering by source is compatible and the
comment needs a sentence to say so — or it is broader than it reads, and
variant 1 costs more than it looks. **Establish which before choosing.** This
is the pivot of the whole unit.

## The three options

1. **Drop the eager edge deletion.** The purge does it transactionally.
   Requires the resolver question above to come out compatible; then the trade
   is not a trade but better on both sides.
2. **Keep it, sequenced correctly** — delete first, then the edges, or both in
   one transaction. Closes the data loss without opening the window, but
   leaves the duplication.
3. **Do nothing**, with the defect as accepted residual risk and a comment at
   the site.

**Preference: 1, with the resolver check as part of the unit.** It removes
code rather than adding it, and the duplication is itself a defect source —
two places deleting the same edges with different transactionality and
different timing. If the check shows the quarantine window is genuinely
affected, the unit falls back to 2 and says so.

## Acceptance

- A failed manifest `DELETE` leaves no live manifest with missing keepalive
  edges — with a test that forces the failure and then inspects the edges.
- The effect on `resolve_referenced_tree_descendant_fail_safe` is **measured
  and named**, not assumed, including how it relates to the unfiltered-set
  contract in its own comment.
- No path deletes `content_references` in two places with different
  transactionality any more — or the duplication is explicitly justified.
- Gate green; `#[serial(hort_pg_db)]` on every test that acquires a connection.

## Explicitly not in this item

- No change to `refcount_reconcile`'s repaired kind set.
- No change to the quarantine window itself or to ADR 0007's release
  predicate.
- No change to `purge_artifact_refs`' transaction.
