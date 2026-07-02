# 0043 — OCI image-index support (index-as-generic-manifest; generalized `content_references`)

- **Status:** Accepted
- **Relates to:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  fail-closed release predicate the layer-level-safety rationale rests on),
  [0027](0027-artifact-provenance-verification.md) /
  [0039](0039-keyed-provenance-verification.md) (the issue-#13 hold + the
  write-authorized-HEAD exemption the push-then-sign payoff reuses),
  [0008](0008-per-format-adapter-free-http-crates.md) (the index PUT writes its
  membership rows through the content-reference use case, adapter-free).
- **Closes:** issue #15 — accept, store, quarantine, serve, and sign OCI image
  indexes / Docker manifest lists on the hosted write path; and the inline
  "index support is deferred" note in
  `crates/hort-http-oci/src/manifests_write.rs` that was the only durable record
  of the gap (never an open-items-register row).

## Context

Hort's OCI read/serve path, upstream pull-through, and referrers/provenance path
key on **content hash, not manifest shape**, so they already stored and served
indexes correctly — only the direct **hosted PUT** path rejected an image index
/ manifest list, with `MANIFEST_INVALID`. A `skopeo copy --all` of a multi-arch
image, and any push-then-sign of an index-shaped image (issue #13), therefore
failed at the hosted write boundary.

An OCI image index (`OCI_IMAGE_INDEX_MEDIA_TYPE`) / Docker manifest list
(`DOCKER_MANIFEST_LIST_MEDIA_TYPE`) is a *manifest-of-manifests*: it carries a
`manifests[]` array of child-manifest descriptors and **no `config`, no
`layers`, no runnable content of its own**. The deferral note said the missing
work was "threading manifest-of-manifests membership into the group model" — an
index links to N children, but hort's membership projection could not express
that.

`content_references` is hort's general "an artifact references a content hash (by
`kind`), and that reference keeps the hash alive under GC" projection —
`primary_content`, `oci_subject`, `metadata_blob`, `wheel_metadata`. Its ONLY
limitation was the primary key `(repository_id, source_artifact_id, kind)`:
exactly **one target per `(source, kind)`**. Every existing kind happens to have
exactly one immutable target, so the limitation was never exercised. The OCI
image index is the first consumer needing **N targets per `(source, kind)`**.

## Decision

**Image indexes / manifest lists are accepted and stored as generic manifest
artifacts** that ride the normal quarantine / scan / release / provenance
lifecycle. There is **no index-specific lifecycle** and no group-model overhaul.

1. **Accept on PUT; validate children exist in-repo.** The hosted PUT path
   branches the blob parse by media type: an index yields its `manifests[*]`
   child-manifest hashes (bounded by the existing `MAX_BLOB_REFERENCES`), which
   are resolved as **manifests** through the same same-repo existence check a
   layer uses. A child absent from the repo → `MANIFEST_BLOB_UNKNOWN` (clients
   push children before the index; this is the correct out-of-order-retry
   behavior). The index itself commits as a plain primary `manifest` group
   member — no config, no layer members. Single-image PUTs are byte-for-byte
   unchanged (the parser branches only on the index media types).

2. **Membership via a generalized `content_references` many-to-many** — NOT a
   format-specific side table, NOT a hash-in-`kind` encoding. Migration `013`
   widens the primary key from `(repository_id, source_artifact_id, kind)` to
   `(repository_id, source_artifact_id, target_content_hash, kind)`, making
   `content_references` the proper many-to-many it always semantically was. One
   new **fixed** kind `"oci_index_member"` is added to the allocated vocabulary
   (`content_reference_index.rs`): an index PUT writes one row per child —
   `source = index artifact, target = child manifest's own content hash,
   kind = "oci_index_member"` — through the content-reference use case
   (adapter-free, ADR 0008; mirrors the `oci_subject` write). N children share
   one `(source, kind)`, distinct only by target hash.

3. **Quarantine / scan / release / provenance: the generic manifest lifecycle,
   unchanged.** An index is a routing document; the scanner scans exactly one
   CAS blob — the artifact's own (harmless) JSON — degenerate but consistent
   with how single-image manifests are already scanned. Quarantine-on-ingest,
   the degenerate scan, timer release, and (under `provenanceMode: required`)
   the issue-#13 hold + write-authorized-HEAD exemption + re-verify-on-signature
   + expiry backstop all apply automatically, because the index **is** a
   manifest artifact.

### Why a released index over a held/rejected child is safe (load-bearing)

Releasing an index releases **no runnable bytes**. Pulling a multi-arch image
resolves the index (routing) and then pulls the platform child manifest and its
layers — **each a separate artifact, independently gated by its own
quarantine**. A held child manifest → 503; a rejected layer blob → 404. So a
released index sitting over a held or rejected child still serves no unscanned or
blocked content: consumption safety is enforced **per-child and per-layer**, not
at the index. The ADR 0007 fail-closed release predicate is satisfied **per
artifact** — the index's own release still requires its own scan success /
waiver (plus provenance clearance under `required`), exactly like any manifest.

## Consequences

- **`content_references` is now the proper many-to-many.** The four existing
  kinds are **behaviorally unchanged** — each still has exactly one immutable
  target per `(source, kind)`, so every pre-migration row is already unique under
  the wider key; the migration re-keys in place with **no backfill / rewrite**.
  Only the adapter upsert `ON CONFLICT (…, kind)` clauses widen to
  `(…, target_content_hash, kind)`. GC keep-alive needs **no code change** — the
  refcount query already counts `target_content_hash` across all kinds, so a live
  index keeps each child's CAS blob exactly as an `oci_subject` keeps a subject.
  Teardown mirrors `oci_subject`: the `ON DELETE CASCADE` on the index artifact
  and the `delete_by_source` on manifest DELETE sweep the child set.

- **Push-then-sign works for index-shaped images.** cosign signs the **index**
  digest → the signature manifest's `subject.digest` is the index digest → the
  existing `oci_subject` + provenance-verify path targets the index artifact
  unchanged. Under a quarantine hold, the write-authorized-HEAD exemption (issue
  #13, `write_authorized_existence_probe` in `manifests.rs`) makes the held index
  **signable**: a `Write`-authorized `HEAD` on the index digest returns 200 so a
  signer's cosign preflight resolves the digest and attaches the signature, while
  the content `GET` stays 503 and an anonymous `HEAD` stays 503. This is what
  actually unblocks the operator's real flow for multi-arch pushes.

- **Deferred enhancement — child-status rollup:** v1 does **not** gate the
  index's served visibility on its children's quarantine state (layer-level
  gating is the real control). A future enhancement could roll a child's
  `rejected` status up into the index's served visibility. Not a vulnerability.
  Recorded as the **OCI image-index child-status rollup** row in the ADR 0000
  open-items register (`docs/adr/0000-historical-decisions-index.md`, OPEN) so a
  future Step-0 sweep finds it.

- **Deferred follow-on — promotion cascade:** `PromotionUseCase`
  (`crates/hort-app/src/use_cases/promotion_use_case.rs`) has **no index
  awareness**: promoting an image index copies the index artifact alone and does
  **not** cascade to its `oci_index_member` child manifests, so a promoted index
  would dangle in the target repo with its children absent (a pull of the
  promoted multi-arch tag resolves the index but `MANIFEST_BLOB_UNKNOWN`s on each
  platform child). Teaching promotion to walk the `oci_index_member` edges and
  promote the children (and their blobs) alongside the index is a deferred
  follow-on — recorded as the **OCI image-index promotion cascade** row in the
  ADR 0000 open-items register (OPEN).

- **Out of scope:** Docker schema-1 manifest lists (legacy; mirrors the existing
  single-image posture). No new artifact-schema change — indexes are stored as
  generic manifest artifacts. No metric-name additions — an index ingest is an
  ingest like any manifest.

## Alternatives considered

- **A format-specific `oci_index_children` side table** — rejected. It would add
  a parallel refcount/teardown surface that GC and the retention scrubber must
  each learn about, duplicating what `content_references` already does for every
  other kind. The `content_references` PK was the *only* thing blocking the
  general model; fixing the general model is a smaller, more durable change than
  a bespoke table, and it makes the projection honest about a many-to-many it
  always semantically was.

- **Hash-in-`kind` encoding** (e.g. `kind = "oci_index_child:<hash>"`) — rejected.
  It smuggles the target into the discriminator, defeats the fixed-vocabulary
  `kind` column, breaks any `WHERE kind = …` lookup, and produces unbounded
  `kind` cardinality. An interim attempt of this shape was removed; the fixed
  `"oci_index_member"` kind with the widened PK is the correct model.

- **An index-specific release gate / lifecycle** — rejected. It would duplicate
  the quarantine/scan/provenance machinery for no safety gain: an index carries
  no runnable content, so its release releases nothing, and per-child/per-layer
  quarantine already provides the real control (see the layer-level-safety
  rationale). The generic manifest lifecycle is correct as-is.

## References

- Issue #15 — OCI image-index / manifest-list support.
- [ADR 0007](0007-fail-closed-quarantine-release-predicate.md) — the fail-closed
  release predicate satisfied per-artifact.
- [ADR 0027](0027-artifact-provenance-verification.md) /
  [ADR 0039](0039-keyed-provenance-verification.md) — the issue-#13 hold +
  write-authorized-HEAD exemption the push-then-sign payoff reuses.
- Migration `013_content_references_multivalue_pk.sql` — the widened PK.
- The `oci_index_member` kind vocabulary in
  `crates/hort-domain/src/ports/content_reference_index.rs`.
- E2E regression gate:
  `scripts/native-tests/scenarios/quarantine/oci-image-index.sh` (multi-arch
  push accepted, index served with the index Content-Type, and — under a hold —
  the write-authorized manifest HEAD exempted while content GET / anonymous HEAD
  stay 503).
