# 162 — enqueue eager child ingest at both pull-through legs

**Issue:** #229 · **Branch:** `agent/229-eager-child-ingest` · Item 2 of 3
(depends on item 161; one MR carries all three).

## Problem

Item 161 builds the executor. Nothing enqueues it yet. This item wires the two
places a pull-through mints an image-index artifact so that each one, in the
same breath it registers the index's `oci_index_member` rows, enqueues one
`oci-index-child-ingest` task per declared child.

## Governing decisions

- **Issue #229 D8** — eager child ingest is **unconditional**. It is not gated
  on `prefetchPolicy`, and no `PrefetchPolicy` field is added. An index's
  children are the declared membership of the artifact a client just
  requested, not speculation. The blob warm beside it stays policy-gated; the
  asymmetry is deliberate.
- **Issue #229 D7** — both legs enqueue. A coalesced follower in a second
  repository needs its own children as much as the leader does.
- **ADR 0043** — membership registration is where this belongs, because the
  child enumeration already happens there.
- **ADR 0053** — the cascade's precedent for bounding fan-out with the jobs
  table's own dedupe rather than an ad-hoc guard.

## Read first

- `crates/hort-http-oci/src/manifests.rs` around the digest-arm ingest
  (`try_upstream_manifest_pull_by_digest`) — the block that writes membership
  edges and then calls `warm_manifest_blobs`. The inline comment there records
  that children are deliberately *not* fetched; that comment is the gap this
  item closes and must be rewritten to state the new invariant.
- `crates/hort-http-oci/src/manifests.rs` — `try_upstream_manifest_pull_by_tag`
  (a tag pull of a multi-arch image resolves to an index too) and
  `finalise_manifest_pull` → `register_follower_membership_edges` (the
  coalesced-follower leg).
- `crates/hort-http-oci/src/manifests_write.rs` —
  `register_membership_edges_from_pull`, which already parses `manifests[]` and
  writes one `oci_index_member` edge per child. The enqueue rides the loop that
  exists rather than re-parsing.
- `crates/hort-domain/src/ports/jobs_repository.rs` — `enqueue_task` and its
  `idempotency_key`, and the `jobs.target_key` partial unique index that
  `enqueue_prefetch_batch` relies on. Choose whichever expresses "one row per
  (repository, child digest)" without a read-modify-write race; state the
  choice and why in the commit body.
- `crates/hort-app/src/task_handlers/prefetch_dependencies.rs` — `target_key`
  is the naming precedent for a dedupe key.

## What to build

At each of the three sites above, after the index's membership edges are
registered, enqueue one `oci-index-child-ingest` task per child digest
returned by `hort_domain::oci::index_child_digests`, carrying the
`repository_id`, the `upstream_name` the index was pulled from, and the
`child_digest`.

- **Idempotent per (repository, child digest).** Concurrent pulls of the same
  index, a re-pull after the index releases, and the leader and follower legs
  firing for the same repository must all collapse onto one row.
- **Enqueue failure never fails the pull.** A jobs-table error is logged and
  the index's own response is unaffected — the client still gets its normal
  503 with `Retry-After`. Degrading to today's lazy behaviour is the correct
  fallback.
- **Not an index, no enqueue.** A single-image manifest pull is untouched.

## Tests

- `pull_through_by_digest_index_with_prefetch_enabled_still_warms_nothing`
  pins today's behaviour and must be replaced by its inverse: a proxied index
  pull enqueues one task row per declared child. Rename it accordingly.
- `item4_released_index_does_not_release_held_child` must pass **unchanged**.
  It is the ADR 0043 D4 invariant this whole issue must not disturb; if it
  needs touching, stop and escalate rather than editing it.
- New: the follower leg enqueues for its own repository.
- New: a second pull of the same index adds no second row.
- New: a single-image manifest pull enqueues nothing.
- New: a jobs-table error leaves the pull's response unchanged.

## Explicitly not in this item

- Handler behaviour (item 161).
- Any `PrefetchPolicy` field or operator knob.
- Any change to the blob warm.

## Acceptance

- All three legs enqueue; a proxied pull of a fresh multi-arch index yields one
  task row per declared child before any client requests a child.
- Repeat pulls add no duplicate rows.
- `item4_released_index_does_not_release_held_child` green, untouched.
- `hort-http-oci` coverage ≥ 85%.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
