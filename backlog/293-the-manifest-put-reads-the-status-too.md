# 293 — The manifest PUT reads the referenced blob's status, not just its row

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Governing decisions:** ADR 0043 (an unknown-blob manifest is rejected in the
same breath as its claims), ADR 0007 (fail-closed quarantine) and ADR 0039 §10
(the push-then-sign hold-read exception, which this unit must not break).

**Introduces the predicate item 294 adopts.** Independent of items 291/292.

## What is true today

`resolve_referenced_blobs`
(`crates/hort-http-oci/src/manifests_write.rs:1762`) resolves each referenced
blob through `ArtifactUseCase::find_in_repo_by_hash`
(`crates/hort-app/src/use_cases/artifact_use_case.rs`), whose port read filters
`deleted_at IS NULL` and **nothing else**. Row present ⇒ reference satisfied.
The blob GET then puts that very same row through an exhaustive
`QuarantineStatus` match (`crates/hort-http-oci/src/blobs.rs:598-624`):

| Row state | Manifest PUT | Blob GET |
|---|---|---|
| `None` / `Released` | accepted | 200 |
| `Quarantined` | accepted | 503 (+ `Retry-After`) |
| `ScanIndeterminate` | **accepted** | **503, no `Retry-After`** |
| `Rejected` | **accepted** | **404 `BLOB_UNKNOWN`** |
| no row | 400 `MANIFEST_BLOB_UNKNOWN` | 404 |

Measured in production on the reported pushes: in **six of seven** the manifest
was accepted while the layer was already terminally rejected (Δ +2.1 s to
+21.5 s). In the seventh the PUT landed 2.06 s *before* the verdict — there the
check legitimately passed, and that case is the reason a PUT-time check alone
cannot be the whole close (item 294 is the other half). All five delivered
manifests carry `quarantine_status = released` while a referenced layer carries
`rejected`, which is how a push reported success and the pull then failed with
`not found` on a layer.

The artifact carries the status the check needs — `find_in_repo_by_hash` already
returns the hydrated row — so the information is in hand at the call site and
is simply not read. This unit adds **no** port call and **no** I/O.

## What to do

1. **Name the state class once, in the domain.** Add an exhaustive,
   wildcard-free predicate on `QuarantineStatus` saying whether the state is
   terminal — `Rejected` and `ScanIndeterminate` — so a future sixth variant is
   a compile error rather than a silent "not terminal". "Terminal is terminal"
   for exactly these two is already this codebase's phrasing
   (`crates/hort-domain/src/entities/artifact.rs:1215`, and
   `ScanIndeterminate`'s own doc at `:31`); do not coin a competing term, and
   add the glossary entry.
2. **Read it at the reference check.** A referenced blob in a terminal state
   counts as **not present**, and joins the existing `missing` list: same
   `MANIFEST_BLOB_UNKNOWN` envelope, same opacity (the client is never told
   *why*, mirroring the hidden-404 posture of the blob GET), same post-mint
   answer, no group attachment and no membership claims. One code path, not a
   second rejection shape.
3. **Correct the comment that path carries.** It currently explains that the
   manifest stays committed "so a client retry after pushing the missing blobs
   reconciles cleanly". For a terminal reference that is false: the row exists,
   so a re-push deduplicates onto it and no retry can help. State both cases —
   a reader who inherits only the old sentence will draw the wrong conclusion
   about what a client can do.
4. **Leave `Quarantined` accepted — including a hold with no self-resolving
   deadline.** Two independent reasons, both load-bearing:
   - Hort quarantines at ingest and the manifest PUT follows seconds later, so
     a quarantine-sensitive check would reject essentially every push.
   - Under `provenance_mode: required` a subject image is held *until its
     signature arrives*, and ADR 0039 §10 exists precisely so a held subject
     can be read and signed. A client re-pushing that manifest after the
     observation window elapsed would be refused if the check keyed on
     `provenance_hold_indefinite`, breaking sign-after-push. The predicate is
     therefore **status-only** and must not consult the hydrated
     `provenance_hold_indefinite` flag. A test must pin that: a manifest whose
     layers are held with no self-resolving deadline still pushes.

## Explicitly out of scope

- The read-time rule (item 294) and the provenance-axis exemption (291/292).
- Telling the client which blob was terminal, or why. The 404/`BLOB_UNKNOWN`
  opacity is deliberate; a diagnostic belongs in the server-side log line,
  which should name the digest and the status.
- Any change to the cross-repo isolation rule or to how an index's children
  are resolved for existence only.

## Acceptance

- A single-image manifest PUT referencing a `Rejected` layer answers
  `MANIFEST_BLOB_UNKNOWN`, and the same PUT referencing a `ScanIndeterminate`
  layer does too — both through the existing missing-reference path.
- A PUT referencing a `Quarantined` layer still succeeds, and so does one whose
  layer carries an indefinite provenance hold. Show the second red when the
  predicate is widened to consult the hold flag — that inversion is the
  regression this acceptance exists to prevent.
- A terminal **config** blob and a terminal **index child** are each caught,
  not just a layer.
- The predicate is defined once; a scan of `crates/*/src` finds no second
  status comparison that re-derives terminality. Report the call sites with
  counts.
- The server-side log line on this path names the digest **and** the status, so
  the next operator does not have to measure event timestamps to find out why a
  push was refused.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc. Do **not** run
  `cargo test --workspace`, `cargo audit`, `cargo deny` or the attribution
  script: together they take 15–25 minutes, longer than a worker's foreground
  tool window, and a backgrounded gate is killed and takes the report with it.
  The architect runs the full gate on the same tree before any MR; a red
  workspace-wide step becomes a new directive, not an in-run fix.
