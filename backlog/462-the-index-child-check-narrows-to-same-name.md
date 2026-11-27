# 462 — an index's children must exist under the same name

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 3 of 7.
**Unblocked 2026-11-23.** The ADR 0043 wording change landed as !1001 and the
maintainer merged it himself, so the record is already in place and this unit
is **code-only**. ADR 0043 decision point 1 now reads *"resolved as **manifests**
through the same existence check a layer uses, **scoped to the OCI `<name>` the
index is pushed under**"* (`docs/adr/0043-oci-image-index-support.md`), with the
client-visible consequence in its `Consequences`. The acceptance criterion about
amending the ADR is therefore already satisfied — do not re-amend it.

## The site

`crates/hort-http-oci/src/manifests_write.rs:2697` (re-measured against
`develop` at `524b49bc`; it was `:2689` when this item was written) resolves
each declared child with

```rust
.find_in_repo_by_path(repo, &oci_manifest_path(&r.hash))
```

`oci_manifest_path` takes only the digest, so an index is accepted when its
children exist **anywhere in the hort repository**. Under the decided model the
check is "same name", and the parent index's own name is in hand at that site.

## Why it was held out of unit 460, and what that leaves to do

ADR 0043 stated the check as a plain same-repo existence check, so shipping the
narrowing first would have left code and ADR disagreeing on a rule the ADR
states explicitly. That is now settled in the ADR's favour and the hold cost
nothing, because unit 460's legacy read fallback keeps this site working.

**One thing to carry from the amendment into the code.** `oci_manifest_path` is
now documented as the **legacy** name-free builder (unit 460 re-documented it
that way), and the site's own comment at
`crates/hort-http-oci/src/manifests_write.rs:2562` says the admission check
*"takes `find_in_repo_by_path` over the legacy name-free manifest path"*. That
sentence is the current truth and becomes false in this unit, so it moves with
the code — and the reason unit 460 kept on the helper (*"admission asks for the
manifest row by path rather than for some row holding these bytes: a repository
may legitimately hold a blob and a manifest at the same digest"*) is the part to
keep, now scoped to the name.

## Acceptance

- An index whose children were pushed under the same name is accepted, exactly
  as today.
- An index whose child exists only under another name in the same hort
  repository answers `MANIFEST_BLOB_UNKNOWN`, carrying that child's digest in
  the refusal. **Corrected 2026-11-23:** this item first said the refusal
  "names the child descriptor position the way the existing refusals do". It
  does not — `ManifestBlobUnknown`'s wire detail is `{"blobs": [digest, …]}`
  and nothing else (`crates/hort-http-oci/src/error.rs:492`); an explicit
  `manifests[N]` position belongs to the descriptor-*validation* refusals, which
  are a different error. The envelope is unchanged by this unit; the test
  instead proves the refused digest is the other-name child's and not the
  present one's.
- The out-of-order retry behaviour 0043 relies on is untouched: a child pushed
  **after** the index still produces `MANIFEST_BLOB_UNKNOWN` on the first
  attempt and succeeds on the retry.
- **No ADR edit.** !1001 already carries the amended sentence and its
  `Consequences` bullet; re-amending it would rewrite a landed decision record.
  Verify the code now matches that sentence and say so in the report.
- The site's own comment no longer claims the lookup is over the legacy
  name-free path, and the admission-resolves-by-path-not-by-bytes reasoning
  survives the edit.
- The change adds no uncovered lines.

## Not in this unit — the config/layer half is unit 465

The same function resolves a single-image manifest's **config and layer** blobs
with `find_in_repo_by_hash` (`manifests_write.rs:2702`), by content hash across
every name. That is the same class of defect and it is **unit 465**, not this
one: this unit touches only the `BlobRole::ChildManifest` arm. Leave the other
arm exactly as it is, including its comment.
