# 422 — A held constituent is not an unknown one, so it does not answer as one

**Issue:** #429 · **Branch:** `agent/429-a-held-constituent-is-not-an-unknown-one` ·
the only item. **No ADR change** — this brings one route's refusal into line
with a decision already recorded. No migration.

**Governing decisions:** ADR 0062 (hort advertises nothing it will not serve —
and §2's "refusal binds both ends of such a document's life"), ADR 0055 (a
refusal naming a status is information rather than access; the read route's
vocabulary for the same fact), ADR 0007 (fail-closed release authority — why a
held constituent withholds at all).

## The property

`resolve_and_check_referenced_blobs`
(`crates/hort-http-oci/src/manifests_write.rs:1020-1088`) folds **two
different facts** into one `ResolvedReferences::Missing(blobs)` list, which
answers `400 MANIFEST_BLOB_UNKNOWN` — "manifest references unknown blobs":

- **no row for the digest** — the client pushed out of order, or an index
  landed ahead of its children. A retry after pushing reconciles cleanly.
- **a row in a terminal state** (`Rejected` / `ScanIndeterminate`) — the bytes
  are *known*. Re-pushing them deduplicates onto the existing row and leaves
  its status untouched, so no retry can ever change the answer.

The code states the conflation as deliberate, and the argument is in the
comment at `:1034-1060`: *"their next move is the same for both (upload or
cross-mount the blob, at which point a terminal row surfaces on its own)."*

**That conclusion is falsified by the same comment's own second bullet**, which
says a re-push deduplicates onto the terminal row and leaves the status
untouched — so the terminal row never surfaces, and the next move is *not* the
same. Measured in the field: a publisher took the answer at face value, pushed
roughly seventy times across two pipeline runs forty minutes apart, and
diagnosed the wrong subsystem entirely, because the refusal named a cause that
did not apply. The read route, asked about the very same blob in the very same
incident, answered `denied: artifact is rejected` and ended the search in one
request.

## What to build

**One fact, one answer, whichever route asks it.** The refusal vocabulary
already exists in `crates/hort-http-oci/src/error.rs` and this item adds no
variant:

- **absent** (no row) → **unchanged**: mint, then `400 MANIFEST_BLOB_UNKNOWN`
  with its `detail.blobs` array. ADR 0062 decides nothing about a thing hort
  has never ingested, so this tier keeps its established answer *and* its
  idempotent retry-after-push path.
- **`Rejected` constituent** → `OciError::ArtifactRejected { subject, axis }`,
  `403 DENIED` — the read route's own answer for this fact.
- **`ScanIndeterminate` constituent** → `OciError::ScanIndeterminate`,
  `503 UNAVAILABLE` — likewise. A hold means *not yet*: a verdict arriving
  later supersedes the absent one, so this push can succeed on a later attempt
  and the status code should say so.
- **A manifest naming both kinds answers the terminal one.** The client can fix
  an absent constituent by pushing and cannot fix a terminal one, so naming the
  absent one first walks them into a second refusal. This is the same ordering
  principle `oci.rs:1448` already applies one layer down ("a layer list the
  config is not about is not a list whose containers are worth naming").

**The type carries the distinction, not the call site.** Replace the single
`Missing(Vec<String>)` with a shape that cannot lose which cause applied, and
match over it **wildcard-free** so a future `QuarantineStatus` variant fails to
compile here rather than silently taking the absent branch.

## Hazards

1. **`ArtifactRejected`'s information discipline is load-bearing and is now
   being applied to a *constituent*.** Its doc (`error.rs:186-189`) is explicit:
   axis plus subject, and deliberately no policy, no `curator_id`, no `rule_id`,
   no findings or CVE identifiers. The subject here is a **constituent blob
   digest**, not the reference the client pushed — state which, in the response
   and in the test, and widen the disclosure no further.
2. **A `503` on a write path invites a harder retry than a `400` did**, and the
   incident above was already seventy pushes against a `400`.
   `OciError::ScanIndeterminate` is a unit variant with no
   `retry_after_seconds`, unlike `Quarantined` and `Unavailable`. Decide
   deliberately whether this refusal carries `Retry-After` and from what real
   quantity, **or** state at the site why a bare `503` is correct here. Do not
   leave it implicit: this is the one way this change could make a publisher's
   behaviour worse rather than better.
3. **Rewrite the comment block, do not annotate it.** It currently argues a
   conclusion this item reverses. State the invariant — why the two causes
   answer differently and what each tells the publisher to do — and carry **no**
   issue, MR or backlog reference in any comment (see CLAUDE.md § *Code
   comments*).

## One thing not to "fix" while you are in here

**OCI answers `503` for `ScanIndeterminate`; at least two other format adapters
answer `403`.** Verified: `crates/hort-http-maven/src/sidecar.rs:30` documents
"`ScanIndeterminate` → 403", and `hort-http-npm` pins a 403 in
`virtual_download_scan_indeterminate_member_returns_403`.

**`503` is the right answer and the others are the stale side**, so do not
"align" this unit onto `403`. ADR 0055's 2026-11-11 amendment reclassified
`ScanIndeterminate` as a **hold, not a verdict**: a verdict arriving later
supersedes the absent one, so the state is "not yet" and `403` states the
opposite. That divergence predates this item and is a separate conversation —
leave the other adapters alone and keep this refusal consistent with the OCI
read route it mirrors.

## Explicitly not in scope

- **Whether the manifest is minted at all on the terminal path.** ADR 0062 §2
  says "one hort will not deliver is also one it does not mint", and this path
  mints and then refuses. That reads like a conformance gap against a standing
  decision, but it carries its own blast radius — idempotency of a later
  re-push, the artifact's event stream, and the `capped_stream_writes`
  discipline — so it is a separate decision, queued for the maintainer. **Keep
  the current mint behaviour exactly as it is.** *(Answered 2026-11-12: ADR
  0062's amendment withdraws the mint half of §2 — a principal holding Write
  may execute a PUT and rely on the artifact existing afterwards — so the mint
  on a refused path is the decided behaviour and no longer a queued decision.
  The instruction above stands, for that reason instead of this one.)*
- The `incomplete_composition` media-type vocabulary gap
  (`layer_media_type_is_openable` accepting the uncompressed OCI spelling but
  not Docker's). Separate finding, separate measurement.
- The write-authorized hold-read on the **read** path. Already landed.

## Acceptance

1. A manifest PUT naming a constituent with **no row** still answers
   `400 MANIFEST_BLOB_UNKNOWN` carrying `detail.blobs` — pinned by a test, so
   the unchanged half is proven unchanged.
2. A manifest PUT naming a **`Rejected`** constituent answers `403 DENIED`
   through `ArtifactRejected`, naming the constituent digest as subject and
   disclosing nothing from hazard 1's list.
3. A manifest PUT naming a **`ScanIndeterminate`** constituent answers
   `503 UNAVAILABLE`, with hazard 2's `Retry-After` decision stated at the site
   and asserted by the test.
4. A manifest naming **both** an absent and a terminal constituent answers the
   **terminal** one.
5. The resolver's return type no longer folds the two causes together, and
   every match over it is wildcard-free.
6. The comment block states the invariant, carries no issue/MR/backlog
   reference, and no longer claims the two causes share a next move.
7. The change adds no uncovered lines (intersect the diff's added line numbers
   with `cargo llvm-cov --show-missing-lines`, per touched file).
