# 345 — The existence probe answers existence

**Issue:** #357 · **Branch:** `agent/357-write-path-existence-probe`
**Governing decisions:** ADR 0055 (the write-authorized hold-read, and its
2026-10-21 amendment D1–D4 at the end of that file — read it first, it is the
decision this unit implements) · ADR 0039 §10 (the exemption's first call
site) · ADR 0007 (quarantine invariants #1 and #5) · ADR 0021 / 0045
(the repository read gate that fires before any of this).

## What is true today

An OCI client issues `HEAD /v2/<name>/blobs/<digest>` before uploading, to
decide whether the upload is needed. Against a terminally rejected artifact
that probe answers `403 DENIED`, and a client reads `403` as a hard failure
rather than as "absent, I will upload it". Every signing run against a
repository whose instance holds such a row stops.

The write-authorized existence probe already exists and already answers this
correctly — for one status only:

```rust
// crates/hort-http-oci/src/blobs.rs:580
let write_authorized_existence_probe = head
    && matches!(artifact.quarantine_status, QuarantineStatus::Quarantined)
    && ctx.repository_access_use_case
        .resolve_granted_write(repo_key, actor).await.is_ok();
```

The comment above it states the reason in full generality — *"The pre-flight
HEAD every pusher (skopeo, `docker push`) issues is a write-path precondition,
NOT a download"* — and nothing in that reason depends on the hold being
time-bounded. The `QuarantineStatus::Rejected` arm (`blobs.rs:629`) therefore
falls through to the read-path refusal.

The manifest route carries the same shape at
`crates/hort-http-oci/src/manifests.rs:304`, with one difference that matters
here: `write_authorized_hold_read` has **no `head` term**, because for
`Quarantined` the exemption deliberately serves the `GET` as well.

## What to build

### 1. The blob route

Widen the probe's status set to `Quarantined | Rejected | ScanIndeterminate`
and let the terminal arms honour the flag, exactly as the `Quarantined` arm
already does. The `head &&` conjunct is what keeps the `GET` out; it stays
first so the extra `resolve_granted_write` still fires only on the narrow
path.

The bounded-await skip (`maybe_bounded_await_release`) needs no new condition:
it only waits on `Quarantined`, so a terminal row passes through it either
way. Keep the existing skip rather than adding a second one.

### 2. The manifest route

A **separate**, `head`-bound predicate for the terminal statuses — not a
widening of `write_authorized_hold_read`. The `serve` function already takes
`head: bool` (`manifests.rs:120`), so the term is available. Widening the
existing predicate would serve a rejected manifest's **body** to a
write-granted `GET`, which the amendment explicitly refuses and which
`rejected_manifest_write_authorized_get_is_403_with_the_axis_never_the_body`
pins.

### 3. Three stale comments, same change

Each describes the pre-#342 world and is now wrong:

- `crates/hort-http-oci/src/blobs.rs:31` — *"Rejected artifacts return `404
  BLOB_UNKNOWN` so the blob's rejected state is invisible to clients."*
- `crates/hort-http-oci/src/manifests.rs` — the `Quarantined` arm's comment
  calling a rejected manifest *"still hidden below"*.
- `crates/hort-app/src/use_cases/provenance_misrejection_repair.rs:21` —
  *"`release` / `waive` never applies — the source-state guard admits only
  `Quarantined` / `ScanIndeterminate`."* Superseded by issue #345's widening of
  `is_curator_overridable`, which admits `RejectionReason::Provenance`
  (`crates/hort-domain/src/entities/artifact.rs:2236`).

State what is true now; do not narrate the change.

### 4. Changelog

One entry under `### Fixed`, two lines at most, naming what an operator
observes: a push that probes before uploading no longer fails against a
rejected blob.

## Acceptance

1. `HEAD` on a rejected blob, caller with granted Write → `200`, the normal
   header set (`Content-Length`, `Docker-Content-Digest`), empty body.
2. `GET` on the same blob, the same caller → unchanged `403 DENIED` with the
   axis.
3. `HEAD` on the same blob, caller **without** the Write grant → unchanged
   `403 DENIED` with the axis.
4. The same three on the manifest route, plus: `GET` on a rejected manifest
   with granted Write serves **no body** — the existing test stays green
   untouched.
5. `ScanIndeterminate` behaves as `Rejected` throughout, on both routes.
6. A caller the repository read gate does not admit never reaches the arm
   (`NAME_UNKNOWN`, ADR 0021 / 0045) — unchanged.
7. A denied or errored `resolve_granted_write` keeps the refusal. Fail closed.
8. **Counter-assertion.** A test pins that the exemption keys on
   `QuarantineStatus` and **not** on the presence of a rejection axis. A
   `Rejected` row with no `ArtifactRejected` behind it is ADR 0039 D6's
   illegal state and exists in the field; an axis-keyed implementation would
   miss exactly those rows and still pass an axis-carrying test.

## Out of scope, stated so it is not hunted for

- Nothing is un-rejected, and **the push still does not complete**. It now
  clears the probe and fails at the mint instead: `resolve_referenced_blobs`
  (`crates/hort-http-oci/src/manifests_write.rs`) counts a terminal reference
  as missing and the `PUT` answers `400 MANIFEST_BLOB_UNKNOWN`. That rule is
  ADR 0062's and it stays; see the amendment's D5. The field case is unblocked
  by repairing the terminal row, which is the second half tracked on the
  issue.
- The upload path itself is untouched: this unit changes what the probe
  answers, not what an upload does.
- No index, packument or tag-list surface changes. `HeldVisibility` keeps
  answering `false` for both terminal statuses.
