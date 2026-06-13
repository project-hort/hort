//! Content-reference projection port.
//!
//! See `docs/architecture/how-to/oci-pull-through.md` (referrers) and
//! ADR 0003 (CAS) for the refcount role this projection plays.
//!
//! Records cross-artifact relationships keyed by the *target* content
//! hash, with a free-form `kind` discriminator and per-row JSONB
//! `metadata`. One row per `(repository_id, source_artifact_id, kind)` —
//! the same source artifact may carry multiple rows simultaneously, one
//! per `kind` (e.g. an OCI manifest that has both an `oci_subject`
//! relation AND a `primary_content` refcount row).
//!
//! The PK shape `(repository_id, source_artifact_id, kind)` is
//! load-bearing for retention: the GC-eligibility query counts
//! rows per `target_content_hash` across every `kind` to prove a blob is
//! unreferenced. Adding a new `kind` is additive — existing callers see
//! no change.
//!
//! # Allocated `kind` values
//!
//! - `"oci_subject"` — OCI Referrers projection. Seeded by the
//!   OCI manifest-write path on every PUT that carries a
//!   `subject.digest`.
//! - `"primary_content"` — refcount row. Written for every
//!   `ArtifactIngested` (every format) so the GC-eligibility query
//!   can prove a blob is unreferenced.
//! - `"metadata_blob"` — HashReference-strategy row. Written
//!   when an `ArtifactIngested` payload includes a CAS-resident
//!   metadata blob.
//! - `"wheel_metadata"` — PEP 658 wheel METADATA file
//!   bytes — extracted from the wheel's `<dist-info>/METADATA` member
//!   during ingest (the wheel-metadata hook in `IngestUseCase`), linked
//!   back to the parent wheel artifact, and served by
//!   `GET …/files/<wheel>.metadata`.
//!
//! # Why a dedicated projection and not `mutable_refs` / `artifact_groups`
//!
//! The relationship being indexed is a per-source *attribute*, not a
//! named moveable pointer (`mutable_refs`) and not a structural
//! grouping (`artifact_groups`). Overloading either shared primitive
//! with reference-by-hash semantics would leak schema into every format
//! that reads them. The content-reference index stays narrow and
//! purpose-specific; the `kind` column keeps it extensible without
//! tripling the number of projection tables.
//!
//! # Write path
//!
//! On manifest `PUT`, Item 11's use case parses the manifest JSON, and
//! if `.subject.digest` is set, calls
//! [`ContentReferenceIndex::insert`] with
//! `(source = manifest_artifact_id, target = subject_hash,
//! kind = "oci_subject", metadata = {"artifact_type": …, "media_type": …})`.
//! Insert is **upsert-on-PK** (`(repository_id, source_artifact_id,
//! kind)`) — re-pushing the same manifest under the same kind refreshes
//! the row rather than failing; inserting under a different kind adds a
//! sibling row.
//!
//! Refcounting widens the writer set: every successful `ArtifactIngested`
//! commit also writes a `kind = "primary_content"` row, and the
//! HashReference-strategy ingests additionally write a
//! `kind = "metadata_blob"` row.
//!
//! # Read path
//!
//! Item 13's `GET /v2/<name>/referrers/<digest>` calls
//! [`ContentReferenceIndex::find_by_target`] with the path digest and
//! `Some("oci_subject")` as the `kind_filter` (so cross-`kind` rows,
//! which the OCI API must not surface, are excluded at the SQL level).
//!
//! # Delete path
//!
//! Item 11's manifest `DELETE` calls
//! [`ContentReferenceIndex::delete_by_source`] so subsequent
//! target-side lookups don't surface tombstoned source artifacts. The
//! migration's FK cascade on `source_artifact_id → artifacts(id) ON
//! DELETE CASCADE` means every kind on the source row also disappears
//! automatically if the underlying artifact row is hard-deleted — the
//! explicit port method keeps the use-case layer in charge of the
//! ordering and lets tests assert the behaviour directly.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// One row in the content-reference projection.
///
/// The first caller seeds this with `kind = "oci_subject"` on every
/// manifest PUT that carries a `subject.digest`. Future callers reuse
/// the same table with a different `kind`.
#[derive(Debug, Clone)]
pub struct ContentReference {
    /// The artifact that carries the reference (e.g. the OCI manifest
    /// whose `subject.digest` points at `target_content_hash`).
    pub source_artifact_id: Uuid,
    /// Raw SHA-256 hex of the target being pointed at. The OCI-subject
    /// caller strips the `sha256:` prefix at the boundary — this field
    /// stores the hex only, matching every other `ContentHash`-typed
    /// column.
    pub target_content_hash: ContentHash,
    /// Free-form discriminator. The first caller uses `"oci_subject"`;
    /// additional string constants are allocated as new callers land.
    /// Read-side filters pass this through to the adapter's SQL
    /// predicate — do NOT post-filter in application code.
    pub kind: String,
    /// Per-row JSON sidecar for caller-specific detail the projection
    /// doesn't care to index. The OCI-subject caller stores
    /// `{"artifact_type": …, "media_type": …}` (nulls omitted) so the
    /// Referrers-API response body can reconstruct the upstream
    /// manifest descriptor without re-reading the manifest.
    pub metadata: serde_json::Value,
    pub repository_id: Uuid,
    pub recorded_at: DateTime<Utc>,
}

/// Projection port for the content-reference index.
///
/// One row per `(repository_id, source_artifact_id, kind)` — the same
/// source may carry one row per kind, so the composite PK is the right
/// uniqueness boundary. Re-ingesting the same source under the same
/// kind (idempotent PUT) upserts: the `insert` implementation refreshes
/// `target_content_hash` / `metadata` / `recorded_at` on conflict.
pub trait ContentReferenceIndex: Send + Sync {
    /// Record a content reference. Upsert on `(repository_id,
    /// source_artifact_id, kind)`. Inserting the same source under a
    /// *different* kind adds a sibling row, not a replacement; this is
    /// what retention requires to maintain a true refcount.
    /// Repeated calls under the same kind refresh the row — the OCI
    /// manifest-PUT idempotency test relies on this shape.
    fn insert(&self, reference: ContentReference) -> BoxFuture<'_, DomainResult<()>>;

    /// Look up every reference that points at `target` in this repo,
    /// optionally filtered by `kind`.
    ///
    /// The `kind_filter` is passed through as a SQL predicate on the
    /// indexed `kind` column (the OCI Referrers API passes
    /// `Some("oci_subject")`), not as an in-memory post-filter. When
    /// `None`, every reference for the target is returned regardless
    /// of `kind`.
    fn find_by_target(
        &self,
        repo: Uuid,
        target: &ContentHash,
        kind_filter: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Vec<ContentReference>>>;

    /// Delete every reference entry whose source is `source`. Called
    /// by artifact-DELETE paths (e.g. manifest DELETE in the OCI
    /// registry).
    ///
    /// Sweeps every row for the source regardless of kind — the FK
    /// cascade on `source_artifact_id → artifacts(id) ON DELETE
    /// CASCADE` likewise drops every kind on artifact hard-delete.
    /// The explicit port method is belt-and-suspenders but lets the
    /// use-case layer order the cleanup and lets tests assert removal
    /// directly.
    fn delete_by_source(&self, source: Uuid) -> BoxFuture<'_, DomainResult<()>>;

    /// Look up the single reference row for `(repo, source, kind)` —
    /// the PK shape. Returns `Ok(None)` if no row exists; never
    /// returns multiple rows (the PK is unique).
    ///
    /// Used by per-source-attribute read paths — the PEP
    /// 658 `.metadata` endpoint reads the `wheel_metadata` row keyed
    /// by `(repo_id, wheel_artifact_id, "wheel_metadata")` to resolve
    /// the CAS hash of the wheel's METADATA bytes. Future per-source-
    /// attribute consumers (e.g. an "SBOM-attached" sibling row)
    /// would call the same shape.
    ///
    /// Read paths that need to enumerate every reference pointing
    /// AT a target hash (cross-source) use
    /// [`Self::find_by_target`] instead.
    fn find_by_source_and_kind(
        &self,
        repo: Uuid,
        source: Uuid,
        kind: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ContentReference>>>;

    /// **Batched** PK lookup — return the `(repo, source_i, kind)` row
    /// for every `source_i` in `sources`, keyed by `source_artifact_id`.
    ///
    /// The PEP 658 simple-index serve fans out per
    /// artifact (one `<a>` per wheel), and must NOT issue N
    /// `find_by_source_and_kind` round-trips. Adapter implementations
    /// MUST execute exactly ONE SQL statement (e.g. `WHERE
    /// source_artifact_id = ANY($1) AND kind = $2`).
    ///
    /// Sources without a matching row are simply absent from the
    /// returned map — the caller folds them into its own per-source
    /// default (PypiVersionFile.metadata_hash = None → builder emits
    /// no PEP 658 advertisement; pip falls back to whole-wheel
    /// download). A row that exists is keyed by its
    /// `source_artifact_id`, never by the input slice index — the slice
    /// may have duplicates, and the caller is responsible for keying
    /// downstream lookups on the artifact id (not the slice position).
    ///
    /// An empty `sources` slice returns an empty map without touching
    /// the backend.
    fn find_by_sources_and_kind(
        &self,
        repo: Uuid,
        sources: &[Uuid],
        kind: &str,
    ) -> BoxFuture<'_, DomainResult<HashMap<Uuid, ContentReference>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ContentReferenceIndex` is
    /// dyn-compatible — adapters are held as
    /// `Arc<dyn ContentReferenceIndex>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ContentReferenceIndex>();
    }
}
