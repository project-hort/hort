# 464 — contract: rewrite the legacy paths and drop the fallback

**Issue:** #459 · **Branch:** `agent/459-oci-namespace-identity` · Unit 7 of 7.
**Ships one release after unit 460**, per ADR 0030's expand/contract policy. Do not bring it forward.

**The rewrite half is decided** (maintainer, 2026-11-23): the legacy paths are
rewritten rather than left name-free forever. The alternative — keep them
name-free and keep the fallbacks permanently — was the reading
`docs/architecture/reference/oci-namespace-and-identity.md` carried until that
answer, and it is now closed. **The decision is about direction, not timing:**
this unit still ships one release after 460 and is not to be brought forward.

## Why it is a separate release

Unit 460 is the expand half: new writes use the name-carrying path, reads fall
back to the legacy one. This unit removes the fallback and rewrites the rows. If
both shipped together, a rolling upgrade would have the previous release's code
building name-free paths against rewritten rows — it would miss, and mint a
second artifact row for the same bytes. That hazard is already documented at
`crates/hort-app/src/task_handlers/oci_index_child_ingest.rs:539-543`.

## The rewrite is deterministic and lossless — measured

- Every OCI artifact row carries its name: all four builder families set
  `name: name.to_string()` on the coords, so `artifacts.name` is populated for
  manifests and blobs alike.
- The new path is a pure function of `(name, old path)`, so the migration is a
  single `UPDATE` with no lookups.
- **No schema change and no constraint change.** The uniqueness key stays
  `artifacts_repository_id_path_key UNIQUE (repository_id, path)`
  (`migrations/003_artifacts_cas.sql:105`, partial on `deleted_at IS NULL` since
  `migrations/021_artifacts_soft_delete.sql`). Distinct old paths map to
  distinct new paths, so the rewrite cannot collide — and because no identifier
  is dropped, renamed or narrowed, `expand_contract_guard` has nothing to say
  and `CONTRACTIONS.toml` needs no entry. **Verify that claim against the guard
  rather than trusting this paragraph**: a data `UPDATE` is outside the guard's
  corpus, and if it is not, the manifest is not the place to make it pass.

One consequence is **not** lossless and belongs in the release notes rather than
in a fix: an artifact that two names pushed exists as **one** row under the name
of the first push, because the name-free key admitted only one. After the
rewrite it is reachable under that name alone. That is the multi-naming
limitation the model removes going forward, and the cross-name reachability it
ends is the defect, not a feature — but a client that had been pulling a digest
under a name it never pushed starts getting `404`.

## What else this unit cleans up

- Remove the legacy-path read fallback from unit 460, including from
  `scan_kind` / `is_provenance_constituent` if they grew a legacy shape.
- Remove the now-redundant `name` key from the `oci_subject` edge projection
  (`subject_content_reference_claim`, `crates/hort-http-oci/src/manifests_write.rs`)
  and bump `projection_version`. Identity carries the name; a projected copy is
  a second source of truth for one fact. Leave `config_media_type` and
  `annotations` alone — those are a cache of values derivable from the bytes and
  stay.

## Acceptance

- A pre-migration row is reachable at its new path after the migration and
  **not** at its old one.
- The migration is idempotent: running it twice leaves the same paths.
- A row whose name is empty or absent — if any exist, measure before assuming
  none do — is handled by a stated rule, not by producing a path with an empty
  segment.
- No read path consults a legacy path afterwards; grep the diff for the removed
  fallback rather than asserting it.
- `projection_version` is bumped and a row at the previous version still reads
  correctly, because the reader's miss path is what the version exists to drive.
- One `CHANGELOG.md` entry, under the #459 entry, naming the client-visible
  consequence in the upgrade terms an operator needs — not the mechanism.
- The change adds no uncovered lines.

## What unit 462 left for you, measured 2026-11-23

**`oci_manifest_path` (`crates/hort-http-oci/src/coords.rs:92`) has no
production caller any more.** Unit 462 moved the index-child admission lookup
onto `oci_manifest_coords(name, …)` with a domain-level
`legacy_oci_artifact_path` fallback, so the helper survives only in test
fixtures — the `SeededIndexChild` seeder uses it to seed a legacy-shape row
(`manifests_write.rs:3561`, inside the `#[cfg(test)]` module that starts at
`:3294`) and one assertion reads it (`:9166`), plus `coords.rs`'s own tests.

That is its proper remaining role during the expand window: the thing that
builds the old shape so a test can prove the fallback works. Removing it is
therefore **part of removing the fallback**, not a separate cleanup — and the
fixtures that call it are the tests whose expectations change when the fallback
goes.
