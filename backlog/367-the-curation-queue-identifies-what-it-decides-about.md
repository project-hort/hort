# 367 — The curation queue says which artifact, and whether it was judged

**Issue:** #400 · **Branch:** `agent/400-operator-messages` · item 1 of 2.

Second wave of the #331 sweep. Both halves sit on **one** read surface — the
curation queue, which is where a curator decides `waive`. Both were found on
2026-10-22 while releasing a held base image: two rows of the same package
stood in the queue, indistinguishable in the output, both reporting
`finding_count: 0`.

The rule that governs this wave: a message exists for the **action** that
follows it. Two situations that call for different actions must not render as
the same text.

## a) `finding_count: 0` means "scanned, nothing found" **or** "never scanned"

**Verified on develop `9202dcbc`.** The findings LATERAL hangs on
`sf.detected_at = a.last_scan_at`
(`crates/hort-adapters-postgres/src/curation_queue_repository.rs:244`); the
anchor is argued from `:92` onwards and is correctly chosen. A `last_scan_at`
of NULL matches no row, and `COALESCE(f.finding_count, 0)` renders that as a
clean row — the module doc says so itself at `:107`. The wire DTO carries
`finding_count` as a bare `u32` with no `Option`
(`crates/hort-http-core/src/handlers/admin/curation/queue.rs:136`, mirrored in
`crates/hort-cli/src/curation/queue.rs`), so there is no representation for
"no verdict yet". `last_scan_at` is not projected
(`curation_queue_repository.rs:204-205` projects `a.name` and `a.version`),
so the reader cannot reconstruct the difference either.

**Why the action differs.** "Nothing found" justifies an early release;
"no verdict yet" merely pulls an unjudged release forward. The surface shows
both identically, and the confusion runs in the unsafe direction.

**The outcome.** `finding_count` and `max_severity` are absent when
`last_scan_at IS NULL`, which means the read path projects `a.last_scan_at`
and the DTO makes both fields `Option`. The CLI renders the unjudged case as
something a curator cannot read as zero findings.

## b) An OCI row carries nothing that identifies it

**Verified on develop `9202dcbc`.** `oci_blob_coords` and
`oci_manifest_coords` both set `version: None`
(`crates/hort-http-oci/src/coords.rs:61` and `:81`; `oci_group_coords` at
`:108` does too, but it mints no artifact row). An OCI artifact's identity is
its `path` — `blobs/sha256:<hex>` against `manifests/sha256:<hex>` — and
uniqueness hangs on exactly that: `UNIQUE (repository_id, path)`
(`migrations/003_artifacts_cas.sql:105`, narrowed to live rows in
`migrations/021_artifacts_soft_delete.sql:47`). The queue projects `a.name` as
`package_name` and `a.version`, but **not** `a.path`. For OCI the version
field is therefore structurally always empty, and the DTO omits it.

**Why the action differs.** Several rows of the same image differ in the
output only by artifact UUID. The curator decides over an identifier that does
not say whether a manifest or a blob is in front of them, nor which one. This
is the whole format, not an edge case — OCI has no version discovery either
(`crates/hort-formats/src/oci.rs:272`), so nothing closes the gap elsewhere.
The CLI's table carries a `VERSION` column that is always `-` for OCI.

**The outcome.** The queue row carries the `path` (or the digest). For the
other formats `version` stays the identifying field.

## Acceptance

1. **Every changed output is shown as rendered text, before and after** — not
   as a format string. A `{}` placeholder does not prove what arrives.
2. One test per half that asserts the **distinction**, not the wording: an
   unjudged row cannot be read as a clean row, and two rows of the same OCI
   image are distinguishable in the output.
3. The anchor at `:244` is not touched. It is correct and argued; this item
   adds the projection the renderer needs beside it.
4. `live_reads_exclude_deleted` stays green — the projection change touches a
   statement that reads `artifacts`.
5. Every DB-backed test carries `#[serial(hort_pg_db)]`.
6. `CHANGELOG.md`: one entry — the curation queue distinguishes an unscanned
   artifact from a clean one and identifies OCI rows.

## Not in this item

- The three messages of item 2 (the retention preview's discarded cause, the
  release preflight's advice, the metrics catalog sentence).
- **E43 — the provenance hold's reason reaching the publisher.** Parked on a
  maintainer decision, not on work: the content route deliberately keeps the
  two holds indistinguishable
  (`crates/hort-http-core/src/artifact_gate.rs:192-196`: *"The body is
  identical either way: which of the two holds this is stays opaque to the
  client"*), and a hold emits no event by design
  (`crates/hort-domain/src/ports/provenance.rs:286-287`). Both halves of the
  outcome are therefore decisions about what a publisher may learn and whether
  a hold gets a record. The typed reason already exists and already reaches
  the per-artifact job-row `result_summary` as `held_indeterminate`
  (`crates/hort-app/src/task_handlers/provenance_verify.rs:181`), so nothing
  is lost by waiting for the decision.
