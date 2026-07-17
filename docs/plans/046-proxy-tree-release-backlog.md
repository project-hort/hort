# Backlog — #46 Option B (referenced-tree descendants release without a re-window)

Branch: `agent/46-proxy-tree-release-design`. Design doc: `docs/plans/046-proxy-tree-release.md`.
PR-sized, ordered by dependency. Distil the design doc into the ADR amendments before merge (D7).

---

## Item 1 — `content_references` gains manifest→blob edges

**Design doc section:** §4 (scope refinement).
**Read first:** `crates/hort-http-oci/src/manifests_write.rs` (the `oci_index_member` write + `MAX_BLOB_REFERENCES` blob-existence validation), `crates/hort-domain/src/ports/content_reference_index.rs` (the `kind` discriminator, existing `oci_subject`/`oci_index_member`), `crates/hort-app/src/use_cases/content_reference.rs` (insert path).
**Acceptance:**
- On a manifest PUT that has a `config` and/or `layers[]`, a `content_references` row is written per referenced blob digest — `source = manifest artifact`, `target = blob content hash`, `kind = "oci_config"` (config) / `"oci_layer"` (each layer). Mirrors the existing `oci_index_member` write; capped by the existing `MAX_BLOB_REFERENCES = 1024`; idempotent on re-PUT.
- An image **index** PUT is unchanged (it has no config/layers — still only `oci_index_member` for its children).
- Unit tests: a manifest with N layers + config writes N+1 blob edges of the right kinds; cap enforced; DB-backed test carries `#[serial(hort_pg_db)]`.
- No new metric/label without a catalog entry; `hort-http-oci` stays adapter-free (ADR 0008).

### Starter prompt
```
/hort-architect
Implement #46 backlog Item 1 (design doc docs/plans/046-proxy-tree-release.md §4). Read
manifests_write.rs (oci_index_member write + MAX_BLOB_REFERENCES), content_reference_index.rs,
content_reference.rs first. Add manifest→blob content_references edges (kinds oci_config / oci_layer)
at manifest PUT, mirroring the oci_index_member write, capped at MAX_BLOB_REFERENCES, idempotent.
Index PUT unchanged. Add unit tests (blob-edge count + kinds + cap; #[serial(hort_pg_db)] on DB tests).
Acceptance as in the backlog item. Refine with me before coding.
```

---

## Item 2 — zero-length observation window for referenced-tree descendants

**Design doc section:** §4 (final shape) + §4a (ADR 0007 reconciliation). **Depends on Item 1** (blobs must be `content_references` targets to be identified).
**Read first:** the ingest quarantine-window assignment (where `quarantine_until` is set at ingest — trace from `IngestUseCase`), `crates/hort-app/src/use_cases/quarantine_release_sweep.rs` + `quarantine_use_case.rs` (release predicate — unchanged), `crates/hort-domain/src/entities/artifact.rs` (`Artifact::release`), the `content_references` target-lookup (`find_by_target`).
**Acceptance:**
- At artifact ingest, if the artifact's content hash is a `content_references` **target** (of any already-ingested source), set `quarantine_until = ingested_at` (zero-length window) instead of `ingested_at + quarantineDuration`. A non-target artifact is unchanged.
- The release sweep is **unchanged**: the descendant still releases only on its own `ScanSucceeded` (fail-closed — no unscanned release, no timer-only release). It just no longer waits out an observation window.
- Edge case: a blob touched before its referencing manifest exists (no edge yet) takes the normal window; documented as acceptable (the pull flow ingests the manifest before its blobs).
- Tests: a target artifact gets `quarantine_until == ingested_at` and releases on clean scan; a non-target keeps the full window; a descendant with `ScanCompleted(findings)` still → `rejected` (fail-closed intact). `hort-domain`/`hort-app` 100% coverage; `#[serial(hort_pg_db)]` on DB tests.

### Starter prompt
```
/hort-architect
Implement #46 backlog Item 2 (design doc §4 + §4a), after Item 1. Trace where IngestUseCase sets
quarantine_until; read quarantine_release_sweep.rs, quarantine_use_case.rs, artifact.rs, and the
content_references find_by_target lookup first. At ingest, a content_references TARGET gets
quarantine_until = ingested_at (zero window); non-targets unchanged; the release predicate stays
untouched (still needs the descendant's own ScanSucceeded — fail-closed). Add exhaustive tests
(target→zero-window+release-on-clean; non-target→full window; findings→rejected). Acceptance as in
the backlog item. Refine with me before coding.
```

---

## Item 3 — ADR amendments (scoped carve-out) + distil design docs

**Design doc section:** §4a (the crux — scoped, not a reversal).
**Read first:** `docs/adr/0007-fail-closed-quarantine-release-predicate.md` (esp. *Alternatives considered → "Clean scan releases immediately"*), `docs/adr/0043-oci-image-index-support.md`.
**Acceptance:**
- **ADR 0007** amended with a *scoped* carve-out: a scanned-clean artifact that is a `content_references` target of an already-ingested parent (a referenced-tree descendant) releases on its own `ScanSucceeded` **without re-applying the observation window**; forward observation is the standard released-artifact rescan. Explicitly narrow — **not** a general "clean scan releases immediately" (which stays rejected). Preserve the two impossible failure modes verbatim.
- **ADR 0043** amended: `content_references` now captures manifest→blob edges (`oci_config`/`oci_layer`); per-node release for referenced descendants (no re-window). Cross-reference the still-open promotion-cascade deferral (it reuses the completed membership graph).
- Per D7: distil the design doc + backlog into the ADRs; **delete `docs/plans/046-*.md`** before the branch merges to main.

### Starter prompt
```
/hort-architect
Implement #46 backlog Item 3 (design doc §4a). Read ADR 0007 (esp. the rejected "clean scan releases
immediately" alternative) + ADR 0043. Amend ADR 0007 with a SCOPED carve-out for referenced-tree
descendants (justified by no-in-window-rescan + fresher-scan + same-released-rescan-pool; NOT a broad
reversal; keep the two impossible failure modes verbatim). Amend ADR 0043 (manifest→blob edges;
per-node no-re-window release; cross-ref the promotion-cascade deferral). Delete docs/plans/046-*.md
per D7. Acceptance as in the backlog item.
```
