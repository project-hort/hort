# 0043 — OCI image-index support (index-as-generic-manifest; generalized `content_references`)

- **Status:** Accepted
- **Relates to:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  fail-closed release predicate the layer-level-safety rationale rests on),
  [0027](0027-artifact-provenance-verification.md) /
  [0039](0039-keyed-provenance-verification.md) (the provenance hold + the
  write-authorized manifest HEAD-and-GET exemption the push-then-sign payoff
  reuses),
  [0008](0008-per-format-adapter-free-http-crates.md) (the index PUT records its
  membership rows adapter-free, through a use case and never an adapter),
  [0054](0054-content-level-age-evidence-anchors-quarantine.md) /
  [0015](0015-apply-time-linter-inert-fields-and-naming.md) (the anchor
  derivation the eager-child-ingest amendment rests on, and the inert-field rule
  that kept it off `PrefetchPolicy`).
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
   kind = "oci_index_member"` — recorded **in the index artifact's own
   minting transaction** and adapter-free (ADR 0008; the same shape as the
   `oci_subject` write — see the 2026-10-07 amendment). N children share
   one `(source, kind)`, distinct only by target hash.

3. **Quarantine / scan / release / provenance: the generic manifest lifecycle,
   unchanged.** An index is a routing document; the scanner scans exactly one
   CAS blob — the artifact's own (harmless) JSON. That stays degenerate for an
   index, which binds references and no runnable filesystem; a **single-image**
   manifest is no longer scanned this way — **amended 2026-10-19 by
   [ADR 0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md)**,
   it is scanned as the composed image it describes. Quarantine-on-ingest,
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
blocked content: consumption safety is enforced **per-child and
per-composition**, not at the index (**amended 2026-10-19 by
[ADR 0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md)**;
this argument read "per-child and per-layer" before, and the layer half moved
up a level without changing the conclusion). Each platform child is itself a
composed image and is gated as one; a layer keeps its own gate for findings
about its bytes, and its filesystem findings are carried by the composition
that contains them. The ADR 0007 fail-closed release predicate is satisfied **per
artifact** — the index's own release still requires its own scan success /
waiver (plus provenance clearance under `required`), exactly like any manifest.

**Narrowed 2026-10-13 — for a terminal child only; the argument above stands
for a held one ([ADR 0062](0062-never-advertise-what-you-will-not-serve.md)).**
A held child's per-leaf `503` is exactly the "not yet" answer and nothing here
changes for it, but where a child is `Rejected` / `ScanIndeterminate` the answer
is already "never", so advertising the index invites a pull that cannot complete
and such an index is not served — ADR 0062 holds that argument; the per-artifact
fail-closed release predicate (ADR 0007) and the provenance cascade (ADR 0039
§11) are untouched.

**Provenance-cascade interaction (ADR 0039 §11).** The per-artifact model has
one deliberate exception on the *provenance* axis: cosign signs only the index
digest, so a child manifest or config/layer blob can never carry its own
signature — under `provenanceMode: required` the per-artifact provenance gate
alone would terminally reject every constituent of a validly signed image and
leave the released index unpullable. When the index's signature **verifies**,
the provenance clearance therefore cascades to the constituents derived from
the verified index bytes (the child digests are inside the signed index bytes;
each child's config/layer digests are inside its manifest bytes — the signature
over the root covers them all), recorded per constituent as a
`ProvenanceVerified` attributed via `cascaded_from` to the root digest. **Only
the provenance conjunct cascades**: each child and blob still needs its own
scan success / waiver and its own observation window to release, so the
layer-level-safety model above is unchanged — a scan-rejected layer under a
signed, released index still 404s, and a never-signed index's constituents
still reject `Unsigned` at window expiry.

### Manifest→blob membership edges + per-node release for descendants (issue #46, amended 2026-07-17)

`content_references` membership is now complete for the whole proxy tree, not
just index→child manifest: a single-image manifest PUT additionally writes one
row per referenced blob — `kind = "oci_config"` for the config blob,
`"oci_layer"` for each layer blob — `source = manifest artifact, target =
blob's own content hash`, recorded the same way as `oci_index_member` — in
the manifest artifact's own minting transaction, adapter-free (ADR 0008; see
the 2026-10-07 amendment). Bounded by the existing
`MAX_BLOB_REFERENCES`; idempotent on re-PUT via the widened PK (point 2 above).
An index PUT is unaffected — it has no config/layers, only `oci_index_member`
for its children. These are GC-active keepalive edges exactly like
`oci_index_member` / `oci_subject` — the refcount query's cross-`kind` count
already covers them with no adapter change, and they are orthogonal to (not
double-counted against) the config/layer blob's `ArtifactGroupUseCase` group
membership.

**Per-node release, no re-window for referenced descendants.** Consistent with
this ADR's existing per-artifact release model (see "Why a released index over
a held/rejected child is safe" above): each constituent — child manifest,
config blob, layer blob — is independently scanned and independently gated.
[ADR 0007](0007-fail-closed-quarantine-release-predicate.md)'s
referenced-tree-descendant carve-out (amended alongside this one) uses the
now-complete membership graph to identify any `content_references` **target**
as a descendant and collapse its ingest-time observation window to zero — it
still releases only on its own `ScanSucceeded`, exactly like every other
artifact in this ADR's per-child model; nothing here changes the release
predicate. This closes the "stacked quarantine waves" operability gap a cold
pull of an already-released multi-arch image previously hit — each descendant
no longer has to sit out a fresh window after its own scan completes.

### Eager child ingest on the pull-through path (issue #229, amended 2026-09-10)

**What changed.** A pull-through ingest of an image index used to mint the index
artifact, write its `oci_index_member` rows, and stop: the children it declares
were fetched only when a client later asked for one. The index's quarantine
window and its children's therefore ran **back to back**, so a fresh multi-arch
base image cost two full observation windows instead of one. Every pull-through
leg that mints an index artifact — the leader's digest arm, the leader's tag
arm, and the coalesced-follower leg — now additionally enqueues one
`oci-index-child-ingest` job row per declared child, in the same breath as the
membership edges that enumerate them. Its handler performs, up front, exactly
the verified upstream ingest a later lazy client pull would have performed:
resolve the mapping through the pull path's own `UpstreamResolver`, short-circuit
if the target repository already holds the content, fetch by digest, verify the
upstream-declared digest against the requested one, ingest through
`IngestUseCase::ingest_verified`, and re-derive the child's own
`oci_config`/`oci_layer` edges so its blobs keep their GC keepalive. Index and
children now run their windows **concurrently**.

The vehicle is a **durable `jobs` row, not a fire-and-forget task**, and that is
the whole point: the change exists to start a clock, and a lost enqueue reverts
to the lazy path *silently* — the operator sees a slow pull weeks later with
nothing to look at. The declared cohort goes in as one
`INSERT … ON CONFLICT (idempotency_key) DO NOTHING` statement
(`JobsRepository::enqueue_idempotent_batch`), dedupe key
`(repository_id, child_digest)`. The statement failing is logged, counted, and
never fails the pull — the client gets its normal response and every child is
still reachable through the lazy path.

**Why this is not a shortcut (load-bearing).** Eager ingest moves *when a
child's window starts*. It does not compute that window's start and it cannot
move *when the window is allowed to close*.
[ADR 0054](0054-content-level-age-evidence-anchors-quarantine.md) derives the
quarantine anchor inside `IngestUseCase` from content-level age evidence read
live through `ArtifactRepository::first_seen_for_checksum` — the same minting
path a lazy client pull goes through, and the only place an anchor is derived.
An eagerly ingested child is therefore given exactly the anchor a later lazy
pull of that child would have given it: same content, same age evidence, same
derived anchor. Nothing on the eager path computes, passes or overrides an
anchor — the `VerifiedIngestRequest` the handler builds carries no
anchor-shaped field, and none may be added. **No window is shortened; a window
that would have started tomorrow starts today.** An auditor of the quarantine
model can settle this without reading the handler's logic: confirm the eager
path reaches `ingest_verified` like any other ingest and hands it no anchor.

**What is unchanged.** [ADR 0007](0007-fail-closed-quarantine-release-predicate.md)'s
fail-closed release predicate: every child still releases only on its own
elapsed window AND its own `ScanSucceeded` / `ScanWaived`. D4 above: a released
index still does not release a held child. The per-child and per-composition
consumption gating that the layer-level-safety rationale now rests on
([ADR 0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md)). And the
answer a client gets when it asks for a held child is the same answer it always
got — a held child manifest is `503`, a rejected layer blob is `404`. Eager
ingest changes the *timing* of a child's own lifecycle, and nothing about which
gate that lifecycle has to pass.

**Why it is unconditional.** An index's children are the **declared membership**
of an artifact a client just asked for — the client that pulled the index is
going to resolve one of them — not a guess about what it might want next. That
makes eager child ingest a completion of the request rather than speculation,
and its cost is bounded metadata: manifest JSON only, capped in count, with the
children's *blobs* untouched. No `PrefetchPolicy` field was added, because
[ADR 0015](0015-apply-time-linter-inert-fields-and-naming.md) requires an
operator-visible field to be load-bearing the day it ships, and there is no
value here an operator would set. The asymmetry with the blob warm beside it in
the same pull-through leg — `warm_manifest_blobs`, which stays gated on
`prefetchPolicy.enabled` — is deliberate: that one spawns background
pull-throughs of *layer bytes*, an unbounded bandwidth and storage cost on
content nobody has asked for yet, which is exactly the kind of trade-off an
operator has the information to make.

**Attestation manifests are included.** The enqueue enumerates `manifests[]`
through the domain's `index_child_descriptors`, with no filter on `platform` or on a
child's media type — an attestation manifest is a declared member of the index
like any other. Excluding it (as a `platform: unknown/unknown` entry, say) would
recreate the second lazy window for precisely the artifact that provenance
verification has to reach, which inverts the point of the change.

**Nested indexes recurse, under two hard internal constants.** When an ingested
child is itself an index, the handler registers its `oci_index_member` rows and
enqueues one row per grandchild — the recursion falls out of the handler
enqueueing its own kind. It is bounded in both directions: **breadth** by the
pre-existing per-index child cap in the domain (`MAX_INDEX_CHILDREN`, which
rejects an over-cap index outright rather than truncating it), and **depth** by
`MAX_CHILD_INGEST_DEPTH` in the handler. Depth is not redundant with breadth: a
chain of distinct nested indexes fans out as (breadth cap)ⁿ, and priority and
worker concurrency bound the *rate* at which such a tree drains, never its
size — so one client pull of a hostile or merely pathological upstream tree
could otherwise enqueue an arbitrarily large job tree. Both are **constants, not
configuration**, and are to stay that way: they are safety bounds rather than
trade-offs, an operator holds no information that would make a different value
right, and a knob here would be operator surface with no demonstrated need
behind it. Nothing is lost at either bound — the refused grandchildren stay
reachable through the lazy pull path with their own full window, so hitting the
depth cap is a completion (`ingested_depth_capped`, with a `warn!`), never a
failure. This supersedes issue #229's D10 as written ("nested indexes recurse
without a depth bound"): D10 remains right that there is no operator-visible
knob, and was wrong that there is no bound.

**The media-type asymmetry between the two write paths is deliberate.** Both
paths decide index-versus-image on the **body's shape** (`is_image_index`), never
on the declared media type; they differ only in what they do when the two
disagree. The hosted PUT path **rejects** the manifest —
`check_declared_media_type_matches_shape` returns 400 `MANIFEST_INVALID` before
any state change — because the client is present, is the author of the
disagreement, and can fix its push. The pull-through path **cannot** reject: the
manifest is already committed to CAS by the time its edges are derived, and the
upstream is not ours to correct. It therefore resolves the disagreement in favour
of the bytes — those are what was hashed and stored — and logs it, because an
upstream serving a structurally-index body under an image-manifest media type
says something real about that upstream. Note that one digest verification cannot
catch this case: the bytes match their digest and only the `Content-Type` lies.
Deciding the pull path on the declared type instead would write no
`oci_index_member` rows for such an index while its children were ingested
anyway — the incomplete-membership defect `oci-membership-edge-backfill` exists
to repair.

**No retroactive backfill.** Only a fresh pull-through mint enqueues. An index
row that already existed when this shipped does not acquire eager children —
there is no sweep that walks existing `oci_index_member` rows and enqueues them.
Its children continue to arrive lazily, on the first client GET, exactly as
before. Deploying this and then wondering why an existing index's children are
still lazy is the expected observation, not a bug.

### Membership edges commit with the artifact that claims them (issue #337, amended 2026-10-07)

*Authorised by the answer on issue #337; implementing work on #335, units
268–270.*

The wording above said these rows are written "through the content-reference
use case". They are not, any more: `oci_index_member`, `oci_config`,
`oci_layer` and `oci_subject` travel into the mint as a
`ContentReferenceClaim` — the edge minus the three fields only the mint can
supply — and commit in the **same transaction** as the claiming artifact's
events, row and metadata, or not at all.

**Why this is the shape.** A `content_references` row is not a projection
that may lag: the storage GC deletes a CAS object exactly when no row targets
its hash, so the row *is* the claim that keeps the bytes alive. Written after
its referrer committed, it leaves a window in which the referrer is live and
its target is collectable — and for a **tree** edge nothing repairs that
afterwards. The refcount reconcile derives `primary_content` and
`metadata_blob` from the artifact row; no relational row records what a
manifest references, so an edge that never landed cannot be re-derived and
the referrer cannot re-assert it.

**The ordering this forces, and it is OCI-specific, which is why it belongs
here.** `oci_config` / `oci_layer` / `oci_index_member` are kinds the
referenced-tree-descendant predicate counts. An edge naming a blob the
repository does not hold would therefore let that blob's own later ingest see
itself already referenced and take the zero-window quarantine carve-out — an
observation window shortened on the strength of an edge written for content
that did not exist. So the declared references are resolved **before** the
mint and the membership claims are built only from a *complete* resolution.
The unknown-blob posture is unchanged: a manifest referencing blobs the client
has not pushed yet is still minted and still answered with 400
`MANIFEST_BLOB_UNKNOWN`, so the retry-after-pushing path stays idempotent — it
simply carries no membership claims, which is what the previous
insert-after-the-gate already left behind on that path.

`oci_subject` is deliberately **not** gated the same way: the Referrers flow
legitimately lets a referrer be pushed for a subject this repository does not
hold, and gating it would refuse a legitimate push. Note what that costs,
because the opposite is easy to assume — `oci_subject` **is** a tree edge on
the descendant predicate, so a referrer for an absent subject does set the
zero-window carve-out for that subject's own later ingest. Pre-existing, and
neither introduced nor repaired by moving the edge into the mint.

**Unchanged by this amendment:** which rows exist, their key, that they are
GC-active, idempotent on re-PUT, bounded by `MAX_BLOB_REFERENCES`, and
adapter-free under [0008](0008-per-format-adapter-free-http-crates.md) — the
format crate still speaks only to a use case.

**A note for whoever edits this next.** The clause that went stale named a
*call site*, and that is why it drifted — twice, since the `oci_subject` half
was already wrong before the membership half caught up. A decision record
holds the decision and its consequences, not the call graph. The two durable
properties here are *adapter-free* and *the edge commits in the transaction of
the artifact that claims it*; neither names a function, and both survive the
next rebuild of the path. State those, not the caller.

**Deliberately not stated here:** the format-agnostic rule that a new
post-commit edge writer on any minting path is a defect. That holds for every
format, not just OCI, so it lives where a developer adding a new `kind` meets
it — the port module documentation in `content_reference_index.rs` — rather
than in a format-specific decision record. The two backfill handlers remain
the only production writers after a commit, which is their entire purpose.

### A manifest is deliverable only while its constituents are (issue #342, amended 2026-10-13)

*Authorised by the human's confirmation on issue #342; the rule itself is
[ADR 0062](0062-never-advertise-what-you-will-not-serve.md), and this is where
its OCI read-path half meets the per-child argument above.*

**The decision.** A manifest or image index is served only while **every
artifact in its closure** carries a non-terminal status. A `Rejected` or
`ScanIndeterminate` constituent — config blob, layer blob, child manifest, or
anything inside a child's own closure — withholds the document. This narrows
the load-bearing argument above exactly as ADR 0062 states: the per-leaf answer
stays correct for a **held** child, whose `503` *is* "not yet", and stops being
correct for a **terminal** one, where "never" is already known at the moment the
document is served.

**Three properties, none of which name a call site** (the note two sections up
applies to this amendment too):

1. **The closure is derived from the document's bytes, never from the
   `content_references` edges.** Edges *nominate*; the bytes decide — the same
   authority ordering [ADR 0039](0039-keyed-provenance-verification.md) §11's
   provenance cascade walks, and for the same reason: the edge projection is
   repairable rather than guaranteed, which is why
   `oci-membership-edge-backfill` exists. This is settled by human decision
   (2026-10-10) **with the 2026-10-07 amendment above already in place**: that
   amendment makes an edge atomic with its claiming artifact, so the projection
   is no longer the lagging thing the objection described, and the decision was
   nevertheless taken for the bytes. It is not reopened by citing the
   amendment; if the measured cost of the byte reads is the problem, that is a
   measurement to bring.
2. **The question is transitive, and bounded by the ingest's own depth cap.**
   One hop would be an arbitrary cut: an index over a child whose layers are
   terminal would answer `200` and then fail at the child, which is the same
   contradiction one level up. The walk reuses `MAX_CHILD_INGEST_DEPTH` —
   walking deeper than the eager child ingest ever fetches would be asking
   about documents this registry declines to pull — plus a total expansion
   budget, because the depth bound alone does not bound the walk: the breadth
   cap is 1024 per level.
3. **Absence is not a hold, and this half is as load-bearing as the rule.** A
   constituent with no catalog row is *not local yet* — the ordinary state of
   every cold pull-through manifest, whose references are registered by digest
   with no existence check (see the unknown-blob posture in the 2026-10-07
   amendment). Only a **present** row in a terminal state changes the answer.
   Inverting this would refuse every cold pull-through in the registry.

**Failing to resolve the question refuses.** The document's own bytes being
unreadable or unparseable, or its closure outgrowing the expansion budget,
leaves hort unable to say what it binds, and
[ADR 0007](0007-fail-closed-quarantine-release-predicate.md) says what to
answer then. A *child's* bytes being unreadable is bounded instead: the child
is still judged on its own catalog row and only its descendants go unasked,
because the alternative would turn every cold index into a refusal.

**No write-authorized exemption.** [ADR 0039](0039-keyed-provenance-verification.md)
§10 / [ADR 0055](0055-write-authorized-hold-read-generalised.md) let a
write-granted principal read a *held* manifest so a subject can be signed. That
does not extend here and the reason is not procedural: a terminal constituent
will not become deliverable by the pusher completing their workflow, so there is
no push-then-sign payoff to protect. The write path's refusal of a terminal
reference means a current push cannot create this shape in the first place.

**The refusal names the offending constituent.** It carries the constituent's
digest and — for a `Rejected` one — its rejection axis, in the same envelope the
manifest's *own* refusal uses (`403 DENIED`, the subject and axis shape ADR 0055
admits for a caller the read gate let through). This is deliberate rather than
incidental: in the incident behind this rule the blob digest was what identified
the cause — identical across repeated pulls of one manifest, different across
manifests, which is how a shared base layer was ruled out — and a concealed
refusal would delete that signal for everyone who cannot read hort's logs. A
server-side line carries the same three facts (which document, which
constituent, which verdict) and is not optional.

**The Referrers asymmetry, stated so it is not left inferable.** `GET
/v2/<name>/referrers/<digest>` keeps reporting a signature manifest as present
while a fetch of that manifest now fails. From outside, that reads like a
registry fault rather than a withheld artifact, and it is the price of refusing
an immutable document rather than editing it. The Referrers answer is
**deliberately out of scope** for this amendment — not overlooked, and not
blessed either: ADR 0062's consequences say a resolution surface that does not
hold the rule is a defect against that record, so closing it is enforcement
work someone may schedule, with its own decision about what an unlistable
referrer does to a signing client. Until then the server-side line above is
what tells an operator which of the two they are looking at.

**Deliberately unchanged:** `Quarantined` constituents (a hold means "not yet",
and the client's own blob fetch already answers it with the deadline), the
per-artifact fail-closed release predicate (ADR 0007), the provenance cascade
(ADR 0039 §11), the unknown-blob posture on the write path, and every answer a
manifest gives about its **own** status.

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
  unchanged. Under a quarantine hold, the write-authorized manifest hold-read
  exemption (ADR 0039 §10, `write_authorized_hold_read` in `manifests.rs`) makes
  the held index **signable**: a `Write`-authorized `HEAD` *and* `GET` on the
  index digest return 200/serve so a signer's keyed cosign resolves the index
  digest (cosign resolves the subject by GET, not only HEAD) and attaches the
  signature, while the child layer blobs stay 503 (HEAD-only probe in
  `blobs.rs`) and a non-writer / anonymous read stays 503. An index is metadata
  (child digests), not runnable content, so serving it to the signer leaks no
  runnable bytes. This is what actually unblocks the operator's real flow for
  multi-arch pushes.

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
  **not** cascade to its `oci_index_member` child manifests, nor — since the
  #46 amendment above — to a manifest's `oci_config`/`oci_layer` blobs, so a
  promoted index would dangle in the target repo with its children/blobs
  absent (a pull of the promoted multi-arch tag resolves the index but
  `MANIFEST_BLOB_UNKNOWN`s on each platform child). Teaching promotion to walk
  the full membership graph (`oci_index_member` + `oci_config` + `oci_layer`
  edges) and promote the descendants alongside the index is a deferred
  follow-on — recorded as the **OCI image-index promotion cascade** row in the
  ADR 0000 open-items register (OPEN). The membership graph this needs is now
  complete (#46 Item 1); the cascade itself is still not implemented, but it
  can reuse the same "descendant inherits parent decision" primitive that
  [ADR 0007](0007-fail-closed-quarantine-release-predicate.md)'s zero-window
  carve-out established on the release-timing axis.

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
  [ADR 0039](0039-keyed-provenance-verification.md) — the provenance hold +
  write-authorized manifest HEAD-and-GET exemption (§10) the push-then-sign
  payoff reuses.
- Migration `013_content_references_multivalue_pk.sql` — the widened PK.
- The `oci_index_member` / `oci_config` / `oci_layer` kind vocabulary in
  `crates/hort-domain/src/ports/content_reference_index.rs`; the `oci_config`
  / `oci_layer` write loop in
  `crates/hort-http-oci/src/manifests_write.rs` (issue #46 Item 1).
- Issue #46 — proxy-tree release without stacked quarantine waves; the
  referenced-tree-descendant zero-window carve-out amended into
  [ADR 0007](0007-fail-closed-quarantine-release-predicate.md) alongside this
  amendment.
- Issue #229 — eager child ingest for proxied OCI image indexes; the
  `oci-index-child-ingest` handler
  (`crates/hort-app/src/task_handlers/oci_index_child_ingest.rs`, holding
  `MAX_CHILD_INGEST_DEPTH`), the pull-through producer
  (`crates/hort-app/src/use_cases/oci_index_child_enqueue.rs`), and the
  `MAX_INDEX_CHILDREN` breadth cap in `crates/hort-domain/src/oci.rs`. D10 of
  that issue is superseded on the depth-bound point by the amendment above.
- [ADR 0054](0054-content-level-age-evidence-anchors-quarantine.md) — the
  `first_seen_for_checksum` anchor derivation that makes eager child ingest
  window-neutral;
  [ADR 0015](0015-apply-time-linter-inert-fields-and-naming.md) — why no
  `PrefetchPolicy` field was added for it.
- E2E regression gate:
  `scripts/native-tests/scenarios/quarantine/oci-image-index.sh` (multi-arch
  push accepted, index served with the index Content-Type, and — under a hold —
  a write-authorized manifest HEAD and GET serve the held index while a held
  child layer blob and an anonymous HEAD stay 503).
