# 107 — Member-aware self-service prefetch: truthful held-check, enqueue into the serving member, no silent-skip success

**Issue:** #146 · **Branch:** `agent/146-member-aware-prefetch` · **Scope:**
`crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs`,
`crates/hort-app/src/task_handlers/prefetch_ingest.rs`, tests. Domain-layer
change only if member resolution needs a port addition — stop and report if so.

## Why

A prefetch POST against a `type: virtual` repo is functionally inert today,
proven registry-side during the v0.10.0 release (issue trail):

1. **Held-check blind**: `package_version_status(repository.id, …)` uses the
   virtual's own id; artifact rows live in members. Every item classifies as
   not-held → the envelope reports `enqueued: N, already_held: 0`
   unconditionally (17,640 jobs over four days, all no-ops).
2. **Enqueued jobs no-op silently**: the leaf handler's Step-4 branch
   (no catch-all upstream mapping → `short_circuited: true`, `Completed`)
   swallows every such job. A job that reports success and leaves neither an
   artifact nor an error cost four days of misdiagnosis.

Actual ingestion happened only via `on_dist_tag_move` side effects, which
cannot reach versions outside a package's newest-3.

## Change

1. **Member-aware held-check.** For a virtual target, resolve
   `virtualMembers` and query `package_version_status` per member in the
   serve path's aggregation order (ADR 0031); classify each item against the
   aggregate exactly as the single-repo path does today (Released/Quarantined
   → `skipped_already_held`; Rejected → `rejected_packages(ScanRejected)`;
   ScanIndeterminate → rejected; None everywhere → candidate for enqueue).
2. **Enqueue into the serving member.** The enqueue's `repository_id` becomes
   the member that would serve the fetch: the member holding a catch-all
   upstream mapping for the format (the proxy member). Virtual with NO
   upstream-capable member → per-item rejection with a reason naming the
   constraint — loud, never enqueued.
3. **Kill the silent skip.** With (2), a leaf job whose repo lacks a
   catch-all mapping can only mean a broken enqueue path or manual row: the
   Step-4 branch changes from `Completed + short_circuited` to a **failed**
   outcome (non-retryable — the input can never succeed) so it can never
   again masquerade as success. The FormatHandler-missing branch at Step 3
   gets the same treatment. `short_circuited` remains for the legitimate
   format-semantics cases (the OCI-style no-composable-URL arm).
4. **Direct POST to a mapping-less repo** (hosted repo): rejected at POST
   time per item (same reason shape as (2)) — prevention at enqueue, not
   discovery at execution.

## Explicitly unchanged

Direct POSTs against proxy members (the current workaround path) behave
exactly as today — regression-pinned. `on_dist_tag_move`/`transitive_deps`
triggers untouched.

## Tests (hort-app 100% tier, mock ports)

- Virtual: held-in-member → skipped; missing-everywhere → enqueued into the
  proxy member's id; rejected-in-member → rejected(ScanRejected);
  indeterminate-in-member → rejected; no-upstream-capable-member → per-item
  rejection, zero enqueues.
- Member precedence: version held in the first-ordered member wins
  classification over a lower-ordered member's absence.
- Leaf handler: job targeting a mapping-less repo → failed (non-retryable),
  not Completed; legitimate short-circuit arms unchanged.
- Envelope truthfulness end-to-end: full-held set → `skipped ≈ N,
  enqueued: 0`; partial → exactly the missing subset enqueued.

## Post-merge follow-up (report, not code)

Once deployed to the instances, CI warms can target `cargo-virtual` again —
the `HORT_CARGO_SOURCE_REPO=crates-proxy` override and the member-scoped
prefetch grants become unnecessary; note it for the operator, do not revert
config in this item.

## Verification

`cargo test --workspace` green; no new dependency; coverage per tiers.
