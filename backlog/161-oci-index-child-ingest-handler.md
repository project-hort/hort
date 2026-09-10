# 161 — `oci-index-child-ingest` task handler

**Issue:** #229 · **Branch:** `agent/229-eager-child-ingest` · Item 1 of 3
(one MR carries all three when they are done).

## Problem

A pull-through ingest of an OCI image index mints the index artifact and
registers one `content_references` row of kind `oci_index_member` per declared
child — and then throws that knowledge away. The child manifests are ingested
only when a client later asks for one, so a fresh multi-arch base image runs
its index window and its child windows **back to back** instead of
concurrently. A base-image bump costs two full observation windows.

This item builds the executor. Item 162 wires the enqueue that feeds it.

## Governing decisions

- **ADR 0043** — the index is a generic manifest artifact; its membership rows
  are `oci_index_member`. D4 stands: releasing an index does **not** release a
  held child. Nothing in this item may weaken that.
- **ADR 0054** — why running the windows concurrently is not a shortcut. The
  anchor is derived from `ArtifactRepository::first_seen_for_checksum`, so a
  child ingested eagerly receives exactly the anchor it would have received on
  a later lazy pull. No window is shortened; one that would have started
  tomorrow starts today.
- **ADR 0006** — every pull-through fetch verifies a checksum. A child
  descriptor carries its digest, so the fetch is verified by the strongest
  available means.
- **ADR 0007** — the release predicate is untouched. Every child still needs
  its own window **and** its own scan verdict.
- **ADR 0008** — layering. The inbound HTTP pull logic in `hort-http-oci` is
  not reachable from `hort-app`; this handler is built from ports only.

## Read first

- `crates/hort-app/src/task_handlers/prefetch_ingest.rs` — the shape to mirror.
  `PrefetchIngestHandler` already proves that a `hort-app` task handler can do
  a verified upstream pull from ports alone: `RepositoryRepository`,
  `UpstreamProxy`, `RepositoryUpstreamMappingRepository`, a format-handler map,
  and `IngestUseCase`. Its constructor, its `LeafSummary` counter struct, its
  `is_upstream_not_found` classification, and its completion-severity rule are
  the precedent for every corresponding decision here.
- `crates/hort-app/src/task_handlers/oci_membership_edge_backfill.rs` — the
  precedent that an **OCI-specific** handler lives in `hort-app` without
  reaching into the format crate, and the precedent for re-deriving membership
  edges through `FormatHandler::extract_oci_manifest_blob_refs`.
- `crates/hort-domain/src/ports/upstream_proxy.rs` — `fetch_manifest(mapping,
  upstream_name, reference, accept) -> ManifestFetchOutcome`, carrying a
  `CachedBodyHandle` plus `media_type` / `declared_digest` / `last_modified`.
- `crates/hort-domain/src/oci.rs` — `is_image_index`, `index_child_digests`,
  `MAX_INDEX_CHILDREN`, the media-type constants.
- `crates/hort-app/src/use_cases/ingest_use_case.rs` — `ingest_verified`, and
  `read_content_age_evidence` (the ADR 0054 anchor derivation you must not
  bypass).
- `crates/hort-worker/src/composition.rs` — the `PrefetchIngestHandler`
  registration block, which explains why a handler needing `ingest_use_case`
  is registered after that use case is constructed.

## What to build

A `TaskHandler` of kind **`oci-index-child-ingest`**, in
`crates/hort-app/src/task_handlers/oci_index_child_ingest.rs`, registered in
`crates/hort-worker/src/composition.rs` alongside `PrefetchIngestHandler`.

**Params** (JSON, validated at handler entry, all required):

| field | type | meaning |
|---|---|---|
| `repository_id` | uuid | the proxy repository the child belongs in |
| `requested_name` | string | the **client-facing** name the parent index was requested under, unstripped |
| `child_digest` | string | `sha256:…`, from the index's `manifests[].digest` |

`requested_name` is the unstripped name, not the upstream one, and the handler
re-resolves it through `hort_domain::ports::upstream_resolver::UpstreamResolver`
— the pull path's own resolution, longest matching prefix wins, returning the
mapping **and** the stripped upstream name. Resolving a catch-all
(`path_prefix == ""`) mapping instead would make the feature inert on a
multi-upstream proxy whose mappings are all prefix-scoped, fetch through the
catch-all when one coexists with prefixed mappings (a spurious
`Failed { retry: false }` on a supported configuration), and diverge the minted
child's `Artifact.name` from what the lazy pull path records. A mapping id or a
prefix param would instead freeze a resolution that can legitimately change
between enqueue and execution.

The child's media type is **not** a param. It is read from the fetch response
and cross-checked, because a param would let a stale or hand-crafted job row
disagree with what upstream actually serves.

**Behaviour, in order:**

1. **Resolve the repository**, then its upstream mapping via
   `UpstreamResolver::resolve(repo_id, requested_name)`. A repository that no
   longer exists, or a requested name no mapping prefixes, is a `Completed`
   no-op with an explicit log line — not an error. The index that enqueued this
   row may be days old.
2. **Short-circuit on local presence.** If the target repository already holds
   an artifact with this content hash, return `Completed` without touching the
   network. This must be scoped to the *target repository*: ADR 0054 keeps the
   anchor per row, and a row in another repository is not this repository's
   row. Never re-mint and never re-anchor.
3. **Fetch by digest** through `UpstreamProxy::fetch_manifest`, with an
   `accept` list covering both OCI and Docker manifest and index media types.
4. **Verify.** The response's `declared_digest`, when present, must equal the
   requested `child_digest`; the ingest itself must be a `ingest_verified`
   call keyed on the requested digest. A mismatch is a hard failure, logged as
   such, and must never reach CAS.
5. **Ingest** via `IngestUseCase::ingest_verified` with the OCI format
   handler, exactly as the pull path does. The row is minted quarantined with
   the anchor `derive_quarantine_anchor` gives it. Do not pass, compute, or
   override an anchor here.
6. **Register the child's own membership edges.** A child image manifest
   ingested by this path needs its `oci_config` and `oci_layer` rows, or its
   blobs have no GC keepalive — the exact defect
   `oci_membership_edge_backfill` exists to repair. Re-derive them through
   `FormatHandler::extract_oci_manifest_blob_refs`, as that handler does.
7. **Recurse when the child is itself an index.** If the fetched body is an
   image index, enumerate its children with `index_child_digests`, register
   the `oci_index_member` rows, and enqueue one `oci-index-child-ingest` row
   per grandchild. The `MAX_INDEX_CHILDREN` cap applies at each level; no
   separate depth knob exists and none is to be added.

**Failure isolation.** An upstream 404 for a child is `Completed` at normal
severity — an index may legitimately declare a manifest the upstream no longer
serves. A genuine hard failure (network, 5xx, digest mismatch, storage)
escalates exactly as `PrefetchIngestHandler::completion_is_error` does. In no
case does a child failure affect the index artifact.

**Idempotency.** The row's dedupe key is the pair (`repository_id`,
`child_digest`); item 162 owns minting it. This handler must additionally be
safe to run twice — step 2 is what makes that true.

## Explicitly not in this item

- The enqueue call sites (item 162).
- Any change to `PrefetchPolicy`. Eager child ingest is unconditional (issue
  #229 D8); adding an operator knob here is out of scope and would need its
  own decision.
- Any change to how a client's request for a held child is answered.
- Eager ingest of layer blobs — the existing `warm_manifest_blobs` spawn
  already covers them, and blobs carry no window of their own.

## Acceptance

- Handler registered and reachable; `kind()` returns `oci-index-child-ingest`.
- A child already present in the target repository produces no upstream
  request, no new row, and no re-anchor.
- A digest mismatch between the requested digest and the upstream-declared
  digest fails the task and stores nothing.
- A child that is an image index enqueues one row per grandchild.
- An ingested child manifest carries `oci_config` and `oci_layer` membership
  rows.
- An upstream 404 completes without escalating; a 5xx escalates.
- `hort-app` coverage contract: 100%, all ports mocked, using
  `crates/hort-app/src/use_cases/test_support.rs` — **not**
  `hort-http-core::test_support::build_mock_ctx`, which is the harness for
  `AppContext`-shaped HTTP tests and does not apply to a task handler.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
