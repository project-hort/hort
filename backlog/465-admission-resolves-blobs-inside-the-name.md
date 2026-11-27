# 465 — manifest admission resolves config and layer blobs inside the name

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 5 of 7.
**Found 2026-11-23**, while re-measuring unit 462 against `develop` at
`524b49bc`. It answers the one question the specification left open about
itself.

## The open question this closes

`#459`'s specification says, under *"Was ich NICHT verifiziert habe"*: whether
the **admission path** depends anywhere on cross-name resolution. It does.

`resolve_referenced_blobs` (`crates/hort-http-oci/src/manifests_write.rs:2627`)
branches by role:

```rust
BlobRole::ChildManifest { .. } => find_in_repo_by_path(repo, &oci_manifest_path(&r.hash))
BlobRole::Config | BlobRole::Layer => find_in_repo_by_hash(repo, &r.hash)
```

Unit 462 narrowed the first arm — it now resolves
`oci_manifest_coords(name, &r.hash).path` and falls back to the legacy
name-free path, and that arm is the model to follow here. The second resolves by **content hash** across
every name in the hort repository, so a manifest pushed under `<name> = b` is
admitted while declaring config and layer blobs that exist only under
`<name> = a`.

## Why this is not a judgement call

Unit 460 made a blob `GET` name-scoped: `GET /v2/<repo>/b/blobs/sha256:<hex>`
answers `404` when the blob was pushed under `a`. So the two halves now
disagree — **hort accepts a manifest whose layers it will not serve.**

That is settled by a standing decision rather than weighed here. **ADR 0062**:
*"Hort advertises nothing it will not serve."* An admitted manifest whose
constituent blobs are unservable under the name it was admitted into is
precisely the state that decision forbids, and the admission path exists to
keep admission and delivery in agreement. The narrowing follows; the only
question was whether anyone depended on the old behaviour, and the answer is
that the dependency was an accident of blobs having been name-free.

## Sequence it after unit 463

A client whose blob sits under another name needs a legitimate way to get it
into this one. Two exist: upload it again under this name (always available), or
**cross-mount** it — which is unit 463, `from=` read as an OCI namespace. The
narrowing is correct without 463, but landing 463 first means the cheap path
exists before the strict check does. CAS keeps either from duplicating bytes.

## Acceptance

- A manifest whose config and layers were pushed under the same name is
  admitted, exactly as today.
- A manifest declaring a config or layer blob that exists only under another
  name in the same hort repository answers `MANIFEST_BLOB_UNKNOWN`, carrying
  that blob's digest. The refusal's wire detail is `{"blobs": [digest, …]}` and
  carries **no** descriptor position (`crates/hort-http-oci/src/error.rs:492`) —
  do not add one; that envelope belongs to the descriptor-validation refusals
  and changing it is separate work.
- The out-of-order retry path is untouched: a blob pushed **after** the manifest
  still refuses on the first attempt and succeeds on the retry.
- A legacy name-free blob row still satisfies admission during the expand
  window, with the test naming it as that rather than as a gap — the same
  posture units 460 and 461 took.
- The role branch stays a branch: a child manifest is resolved as a manifest and
  a blob as a blob, because a repository may legitimately hold both at one
  digest. Do not collapse the two arms onto one helper.
- The change adds no uncovered lines.

## Governing decisions

ADR 0062 (advertises nothing it will not serve — decides this), ADR 0003 (CAS,
so the narrowing duplicates no bytes), ADR 0043 (the sibling arm, already
amended for unit 462), and
`docs/architecture/reference/oci-namespace-and-identity.md` (the reach: the
whole OCI surface, maintainer 2026-11-21).
