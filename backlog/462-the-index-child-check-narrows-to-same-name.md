# 462 — an index's children must exist under the same name

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 3 of 5.
**Blocked** on the maintainer's word on the ADR 0043 wording change — the behaviour and the record move together.

## The site

`crates/hort-http-oci/src/manifests_write.rs:2689` resolves each declared child
with

```rust
.find_in_repo_by_path(repo, &oci_manifest_path(&r.hash))
```

`oci_manifest_path` takes only the digest, so an index is accepted when its
children exist **anywhere in the hort repository**. Under the decided model the
check is "same name", and the parent index's own name is in hand at that site.

## Why it is held out of unit 460

ADR 0043 writes the check down (`docs/adr/0043-oci-image-index-support.md:56`):

> an index yields its `manifests[*]` child-manifest hashes (bounded by the
> existing `MAX_BLOB_REFERENCES`), which are resolved as **manifests** through
> the same same-repo existence check a layer uses

Shipping the narrowing before that sentence changes would leave code and ADR
disagreeing on a rule the ADR states explicitly. ADR changes land only after an
answered decision, and the maintainer has the wording question with the
classification: it **records a consequence** of the identity decision rather
than reversing an ADR argument — 0043's reasoning there is about *ordering*
("clients push children before the index"), not about naming — **but** it has a
client-visible effect 0043 did not weigh: an index whose children sit under
another name in the same hort repository starts answering
`MANIFEST_BLOB_UNKNOWN` where it is accepted today.

Unit 460's legacy read fallback keeps this site working meanwhile, so the hold
costs nothing.

## Acceptance

- An index whose children were pushed under the same name is accepted, exactly
  as today.
- An index whose child exists only under another name in the same hort
  repository answers `MANIFEST_BLOB_UNKNOWN`, and the refusal names the child
  descriptor position the way the existing refusals do.
- The out-of-order retry behaviour 0043 relies on is untouched: a child pushed
  **after** the index still produces `MANIFEST_BLOB_UNKNOWN` on the first
  attempt and succeeds on the retry.
- The ADR 0043 sentence is amended in the same change, once the maintainer has
  confirmed the wording, and the amendment says what changed and why rather than
  silently rewriting the line.
- The change adds no uncovered lines.
