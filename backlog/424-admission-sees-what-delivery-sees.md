# 424 — Admission sees what delivery sees

**Issue:** #429 (open until the promotion; this is the same OCI write/read
boundary) · **Branch:** `agent/429-admission-sees-what-delivery-sees` ·
the only item. **No ADR change** — this brings one route into line with a
decision already recorded. No migration.

**Governing decisions:** ADR 0062 (hort advertises nothing it will not serve;
§2's "refusal binds both ends of such a document's life — one hort will not
deliver is also one it does not mint"), ADR 0007 (fail-closed release
authority), ADR 0020 (the audited read).

Found by the 0.17.4 review, pass 3, on the serving boundary. Three findings,
one property: **a successful push must not name a document this registry will
refuse, and a refused read must answer and record its actual cause.**

## Group A — an image index may name a blob as a child manifest

`check_child_against_descriptor` (`manifests_write.rs:2589-2617`) verifies two
things about a child: that the descriptor declares a readable `size`, and that
it equals `stored.size_bytes`. **Nothing establishes that the row it resolved
is a manifest at all.** The resolution is
`ArtifactUseCase::find_in_repo_by_hash`
(`artifact_use_case.rs:1111-1124`) → `find_by_repo_and_checksum`, which
returns **any** live artifact row in the repository whose checksum matches,
with no kind discrimination.

Sequence: push arbitrary bytes `B` through the OCI **blob** route, leaving a
live `blobs/sha256:<B>` row and no manifest row. PUT an image index whose
`manifests[0]` names `B`'s digest and its true size. Admission is satisfied,
the index and its tag commit, the PUT answers `201`. On the index GET the
unparseable child is warned about and skipped, so the index body leaves; the
client then GETs `/manifests/sha256:<B>`, finds no manifest row, and gets
`MANIFEST_UNKNOWN` `404`. hort advertised a child it will not serve — ADR 0062
directly — and the push reported success for a broken image.

**The existing positive fixture passes for the wrong reason, and that is why
this was invisible.** `seed_index_child` (`manifests_write.rs:3001-3012`) is
documented as "[`seed_blob`] for a child manifest" and literally wraps
`seed_blob`, so `put_image_index_with_present_children_is_committed_as_manifest`
asserts that an index over **blob rows** commits. Fixing admission turns that
fixture into a test of the defect; it has to be re-seeded with real child
manifests, and a negative case added for the blob-row shape.

## Group B — admission checks the direct child, delivery checks the closure

Sequence: publish and release child manifest `M` over layer `L`; a later
rescan rejects `L` while `M`'s own row stays `Released`; PUT an index `I`
naming `M`. Admission reads `M`'s row, sees `Released`, accepts, mints and
tags `I`, answers `201`. Once `I`'s own hold clears, the GET walks `M`'s bytes,
pulls `L` into the closure and refuses `I` for `L`'s terminal status.

**The read path's own module doc already argues why one hop is not enough** —
`manifest_deliverability.rs`: *"One hop is an arbitrary cut: an index over a
child whose layers are terminal would answer 200 and then fail at the child."*
Admission takes exactly that arbitrary cut. The two sides must ask the same
question.

This is **not** the already-known case of a *direct* terminal constituent,
which the PUT now refuses with its own envelope; here the PUT succeeds because
the terminal constituent is one level deeper.

## Group C — a status change mid-GET answers 500 and records nothing

`manifests.rs:574-583` and `blobs.rs:802-814,841-851` map **every** error from
`download` / `download_range` to `OciError::Internal`, and call no
`log_refused_read`. So: a GET loads a `Released` artifact and passes the
handler's quarantine match; a concurrent rescan flips the row to `Rejected`
before `ArtifactUseCase::download` re-reads it; `download` refuses with
`DomainError::Forbidden` (`artifact_use_case.rs:590-605,1142-1148`).

The bytes stay withheld — the fail-closed half is intact — but the caller is
told the server broke, and `refusal.rs`, whose whole purpose is the record a
refused read leaves, has no line for it. A timing window, so lower severity
than A and B; still a wrong answer and an audit gap on a path a rescan reaches
in normal operation.

## What to build

1. **Admission establishes that a child is retrievable as a manifest**, not
   merely that some row shares its checksum. Prefer the narrowest check that
   makes the claim true — the row's own kind/media type is the fact in
   question; do not infer it from a successful parse of bytes the admission
   path does not otherwise read.
2. **Admission asks the same transitive deliverability question delivery
   asks.** Reuse `manifest_deliverability`'s closure rather than re-deriving a
   second traversal — two traversals that can disagree is the defect one level
   up. Note its own depth cap and say how admission inherits it.
3. **Discriminate the refusal from the infrastructure failure** in both OCI
   read handlers: a `Forbidden` / terminal re-read answers the route's own
   refusal envelope for that status and goes through `log_refused_read`;
   anything else stays a logged `500`.

## Hazards

1. **Group A's fix invalidates an existing positive fixture.** Re-seed it with
   real child manifests and add the negative case. A fix that leaves the
   blob-seeded fixture green has not been demonstrated.
2. **Cost on the PUT path.** Group B adds a closure resolution to an index
   admission. State what it costs per push and why it is the right trade; if
   the closure read is already done elsewhere in the same request, say so.
3. **Do not widen the refusal's disclosure.** Group C must answer the status's
   own envelope — the same one the read route already sends for that status —
   and disclose nothing further.
4. **Group C must not swallow a real infrastructure failure** as a refusal.
   The discrimination is on the error, not on a guess about the row.

## Explicitly not in scope

- **Whether a refused PUT mints.** ADR 0062 §2's "does not mint" clause is a
  separate, queued maintainer decision. Groups A and B change what is
  *admitted*; they do not change mint behaviour for anything still admitted.
- The `503`-vs-`403` cross-adapter divergence, and the retired
  `compositeVerdictMode`.

## Acceptance

1. An index PUT naming a digest whose only row is a **blob** is refused, with a
   negative test; `put_image_index_with_present_children_is_committed_as_manifest`
   is re-seeded with real child manifests and still passes.
2. An index PUT naming a `Released` child whose own layer is terminal is
   refused, with a test that builds exactly that shape (released child over a
   rejected layer).
3. An index PUT naming children that are all genuinely deliverable still
   commits — proven unchanged.
4. A mid-GET status flip to a terminal state answers that status's own refusal
   envelope, not `500`, on **both** the manifest and the blob route, and the
   refusal is recorded; asserted per route.
5. A genuine infrastructure failure from `download` still answers `500` and is
   still logged as an error.
6. The change adds no uncovered lines.
