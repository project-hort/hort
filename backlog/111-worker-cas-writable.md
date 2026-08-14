# 111 — Worker CAS mount writable: retire the stale consume-only contract

Issue: #157. One reviewable unit: chart template + comment + helm-template
assertion. No Rust change.

## What

`deploy/helm/hort-server/templates/worker-deployment.yaml` mounts the shared
CAS volume (`filesystem` backend) with `readOnly: true` under a consume-only
contract ("the worker never writes to the CAS") that is stale twice over:

- the worker's scan path persists per-finding blobs to CAS
  (`ScanOrchestrationUseCase::record_outcome`) — the reason compose's worker
  mount is already writable, per its own comment;
- worker-side leaf prefetch ingest (`ingest_verified`) writes the blob it
  verified — proven failing on staging with `Read-only file system
  (os error 30)` on every prefetch job, any format.

The chart comment even claims to mirror a compose `:ro` mount that no longer
exists. It stayed latent because the native deploy shares a writable FS and
no k8s worker-ingest had run before the first staging smoke.

## Change

1. Remove `readOnly: true` from the worker's `data` volumeMount.
2. Rewrite the comment to state the real invariants:
   - the worker WRITES the CAS: scan-finding blobs and prefetch-ingest
     blobs (mirror compose's writable-mount rationale and reference it);
   - write safety comes from the adapter, not the mount: temp file under
     `.staging/` on the same filesystem + atomic rename, content-addressed
     dedup (`hort-adapters-storage/src/filesystem.rs`);
   - access mode: RWO suffices while server + worker co-schedule on one
     node (RWO is a node-attach constraint); multi-node needs RWX or the
     object-store backend (which has no shared volume at all). This
     replaces the imprecise "RWX volume required when the worker runs as a
     separate Pod" claim.
3. helm-template assertion: the worker's `data` mount renders WITHOUT
   `readOnly` (guards against the contract sneaking back); update any
   fixture pinning the old shape.

## Out of scope

- The observability findings from the same smoke round (#158).
- Any storage-adapter or access-mode change.

## Acceptance

- Rendered worker manifest: `data` mount writable; server manifest
  unchanged.
- helm-template suite green, including the new no-readOnly assertion and
  the (version-normalized) golden checks.
- After deploy, a staging leaf-prefetch job completes with
  `urls_succeeded: 1` and an artifact row — verified in the #154 smoke
  retest, not in this MR.
