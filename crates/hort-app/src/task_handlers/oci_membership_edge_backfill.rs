//! TaskHandler for the OCI membership-edge backfill.
//!
//! Retrofit for OCI single-image manifest rows minted before the write
//! path registered `content_references` membership edges on every
//! manifest PUT/pull. A manifest row with no `oci_config`/`oci_layer`
//! edges gives its config and layer blobs no GC keepalive — a blob
//! referenced only by that row is collectable, and a later GC pass
//! breaks pulls from that repository even though the manifest itself
//! still resolves.
//!
//! This task is the retrofit: it walks OCI image-manifest artifacts
//! whose `content_references` row of kind `oci_config` is absent
//! ([`ArtifactRepository::find_oci_image_manifests_without_kind`]),
//! streams each manifest from CAS, invokes
//! [`FormatHandler::extract_oci_manifest_blob_refs`] to re-derive the
//! `config`/`layers[*]` blob set, and inserts the missing edges —
//! mirroring the write path's `register_membership_edges_from_pull` one
//! for one (`hort-http-oci::manifests_write`), which this handler cannot
//! call directly (ADR 0008 layering — format-crate internals are not
//! reachable from `hort-app`).
//!
//! # Image manifests only
//!
//! An OCI image index legitimately carries no `config`/`layers` (it
//! carries `oci_index_member` children instead), so the candidacy query
//! excludes it structurally — see
//! [`ArtifactRepository::find_oci_image_manifests_without_kind`]'s own
//! doc for the media-type discrimination this handler relies on.
//!
//! # Delivery — no CronJob, deliberately
//!
//! Unlike [`super::wheel_metadata_backfill`] (an ongoing, operator-visible
//! gap that new wheels can still fall into if the extraction hook itself
//! regresses), this handler repairs damage from a **defect that can no
//! longer occur**: every manifest PUT and pull-through now registers its
//! membership edges at ingest time, so no new incomplete row can be
//! created from this moment forward. A permanently-scheduled recurring
//! sweep would therefore be scaffolding maintained for a bug class the
//! ingest path cannot reproduce — dead weight from the day it ships. The
//! only delivery path is manual operator invocation through the
//! admin-tasks route (`hort-cli admin task invoke
//! oci-membership-edge-backfill --params-file /tmp/p.json`), kind gated
//! by `ADMIN_INVOKABLE_TASK_KINDS`; an operator runs it once per
//! environment after upgrading past the fix, and re-runs are a no-op
//! (see Resumability below) rather than a maintenance burden.
//!
//! # Params
//!
//! - `batch_size` (int) — the in-run keyset page size; defaults to
//!   [`DEFAULT_BATCH_SIZE`] = 100, capped at [`MAX_BATCH_SIZE`] = 1000.
//!   Mirrors [`super::wheel_metadata_backfill`]'s batch-size contract
//!   verbatim, including the "bounds page size, not total run work"
//!   posture — see Resumability below.
//! - `ignore_skip_markers` (bool) — defaults to `false`. When `true`, the
//!   candidacy query re-surfaces manifests already carrying an
//!   `oci_membership_skipped` durable marker (see "Durable
//!   structural-skip marker" below).
//!
//! # Resumability
//!
//! **In-run keyset advance.** A single invocation walks candidates in
//! pages of `batch_size`, using an in-memory keyset cursor
//! (`after = max(id)` of the previous page, advanced regardless of that
//! page's outcome). The candidacy query is otherwise stateless
//! (manifest-shaped, image-typed, no `oci_config` row, further narrowed
//! by the durable skip marker below); a run keeps fetching pages until
//! one comes back short of `batch_size`, so it visits every current
//! candidate exactly once and always terminates — a page of
//! 100%-skipped manifests no longer stalls the run at the same rows
//! forever.
//!
//! **Durable structural-skip marker.** A *structural* skip (see "Failure
//! modes" below) additionally inserts a `content_references` row
//! (`kind = "oci_membership_skipped"`, target = the manifest's own
//! content hash — the same self-referential shape the `primary_content`
//! refcount row uses) and the candidacy query's `NOT EXISTS` is extended
//! to exclude marked rows. Re-deriving from the same immutable CAS
//! content cannot change a structural outcome, so a structurally
//! unprocessable manifest leaves the candidate pool permanently. A
//! *transient* skip writes no marker — the manifest remains a candidate,
//! and the in-run keyset advance above already keeps it from starving
//! the current run.
//!
//! Across invocations: a failed page leaves the candidate set unchanged;
//! the next invocation starts a fresh cursor at `after = None` and
//! re-derives the same work minus whatever a prior successful invocation
//! completed (repaired, or structurally marked). Two concurrent runs walk
//! overlapping sets harmlessly; the upsert-on-PK semantics of
//! `ContentReferenceIndex::insert` absorb the duplicate work.
//!
//! # Per-row write ordering — config last
//!
//! The candidacy query keys "already repaired" on the presence of the
//! `oci_config` row alone. Writing the config edge before every layer
//! edge has landed would therefore let a partially-repaired row (config
//! present, a layer write failed) drop out of the candidate set
//! permanently — the row would read as complete while a blob it
//! references still has no GC keepalive. This handler writes every layer
//! edge first and the config edge last, and only if every layer write
//! succeeded: a row is only ever removed from candidacy once it is
//! actually complete.
//!
//! # Failure modes per artifact
//!
//! Split by the transient/structural criterion that decides
//! marker-writing (see Resumability above):
//!
//! - **Structural** (re-deriving cannot change the outcome for the same
//!   immutable bytes — a durable marker is written): no `oci_config`-role
//!   reference in the derived set (the stored bytes do not parse as a
//!   manifest declaring a config blob — corrupt CAS content, or a
//!   genuinely index-shaped row that slipped past the media-type filter),
//!   or `extract_oci_manifest_blob_refs` returns `Err` (malformed JSON) →
//!   counts in `skipped_structural`. If the marker insert itself fails,
//!   the manifest remains a candidate for the next run — counted in
//!   `skipped_transient` instead (see below), since what determines the
//!   bucket is whether the manifest stays a candidate, not the
//!   parse-level cause.
//! - **Transient** (infrastructure-class — CAS read failure, any
//!   `content_references` insert failure including a failed marker
//!   insert) → counts in `skipped_transient`; whatever edges DID land
//!   before the failure are still counted in `edges_written` (partial
//!   credit, honestly reported), and the row remains a candidate on the
//!   next invocation (see write-ordering above). No marker is written.
//! - Full success (every edge, including config, written) →
//!   `rows_repaired` + `edges_written` (config + every layer).
//!
//! An operator reading `result_summary` can therefore distinguish
//! "nothing to repair" (`rows_scanned = 0`) from "could not repair"
//! (`skipped_structural > 0` / `skipped_transient > 0`).
//!
//! # No new domain event, no new metrics
//!
//! Same posture as [`super::wheel_metadata_backfill`]: the backfill
//! produces only derived-projection rows (`ContentReference kind in
//! {oci_config, oci_layer, oci_membership_skipped}`), not domain facts,
//! and emits no metrics — the per-tick `result_summary` JSON on the
//! `jobs` row is the operator-visible signal.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::oci::ManifestBlobRole;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default `batch_size` when the operator omits it from `params`.
/// Mirrors [`super::wheel_metadata_backfill::DEFAULT_BATCH_SIZE`]. Bounds
/// page size only — see the module doc's Resumability section.
pub(crate) const DEFAULT_BATCH_SIZE: u32 = 100;

/// Hard cap on `batch_size` regardless of operator input. Mirrors
/// [`super::wheel_metadata_backfill::MAX_BATCH_SIZE`].
pub(crate) const MAX_BATCH_SIZE: u32 = 1_000;

/// `content_references.kind` the candidacy query filters against — the
/// single-target "is this manifest repaired at all" gate (see the
/// write-ordering doc above).
pub(crate) const OCI_CONFIG_KIND: &str = "oci_config";

/// `content_references.kind` written for each layer blob.
pub(crate) const OCI_LAYER_KIND: &str = "oci_layer";

/// `content_references.kind` value written for a **structural** skip —
/// see the module doc's "Durable structural-skip marker" section.
pub(crate) const OCI_MEMBERSHIP_SKIPPED_KIND: &str = "oci_membership_skipped";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Per-artifact repair outcome — the shape [`OciMembershipEdgeBackfillHandler::repair`]
/// returns to the batch loop.
enum RepairOutcome {
    /// Every derived edge (config + all layers) landed.
    Repaired { edges_written: u64 },
    /// Structural skip, durable marker written — the manifest leaves
    /// candidacy permanently.
    SkippedStructural,
    /// Transient skip (CAS read failure, or any edge/marker insert
    /// failure) — no marker; `edges_written` counts whatever DID land
    /// before the failure (partial credit).
    SkippedTransient { edges_written: u64 },
}

/// [`TaskHandler`] for the one-shot OCI membership-edge backfill.
pub struct OciMembershipEdgeBackfillHandler {
    artifacts: Arc<dyn ArtifactRepository>,
    content_references: Arc<dyn ContentReferenceIndex>,
    storage: Arc<dyn StoragePort>,
    /// OCI handler. The backfill is OCI-only by design; the composition
    /// root wires the OCI handler in directly rather than threading the
    /// full per-format registry, mirroring
    /// [`super::wheel_metadata_backfill::WheelMetadataBackfillHandler`]'s
    /// PyPI wiring.
    oci_handler: Arc<dyn FormatHandler>,
}

impl OciMembershipEdgeBackfillHandler {
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        content_references: Arc<dyn ContentReferenceIndex>,
        storage: Arc<dyn StoragePort>,
        oci_handler: Arc<dyn FormatHandler>,
    ) -> Self {
        Self {
            artifacts,
            content_references,
            storage,
            oci_handler,
        }
    }

    /// Read `artifact`'s stored bytes from CAS in full. OCI manifests are
    /// capped at push time (`MANIFEST_BODY_MAX_BYTES`, 1 MiB,
    /// `hort-http-oci::manifests_write`); re-reading an already-stored
    /// manifest is bounded work, not an unbounded buffer.
    async fn read_manifest_bytes(&self, artifact: &Artifact) -> DomainResult<Vec<u8>> {
        let mut stream = self.storage.get(&artifact.sha256_checksum).await?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| DomainError::Invariant(format!("CAS re-read failed: {e}")))?;
        Ok(buf)
    }

    /// Insert one `content_references` row for `artifact` pointing at
    /// `hash` under `kind`. Thin wrapper so [`Self::repair`] reads as a
    /// flat sequence of `write_edge` calls.
    async fn write_edge(
        &self,
        artifact: &Artifact,
        kind: &str,
        hash: &hort_domain::types::ContentHash,
    ) -> DomainResult<()> {
        self.content_references
            .insert(ContentReference {
                source_artifact_id: artifact.id,
                target_content_hash: hash.clone(),
                kind: kind.to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: artifact.repository_id,
                recorded_at: Utc::now(),
            })
            .await
    }

    /// Insert the durable `oci_membership_skipped` marker row for a
    /// structural skip. Target = the manifest's own content hash —
    /// self-referential, mirroring [`Self::write_edge`]'s sibling shape
    /// in [`super::wheel_metadata_backfill::WheelMetadataBackfillHandler::write_skip_marker`].
    ///
    /// A failed insert downgrades the outcome to
    /// [`RepairOutcome::SkippedTransient`]: what decides the bucket is
    /// whether the manifest remains a candidate on the next run, and if
    /// the marker did not land, it does.
    async fn write_skip_marker(&self, artifact: &Artifact) -> RepairOutcome {
        match self
            .content_references
            .insert(ContentReference {
                source_artifact_id: artifact.id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: OCI_MEMBERSHIP_SKIPPED_KIND.to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: artifact.repository_id,
                recorded_at: Utc::now(),
            })
            .await
        {
            Ok(()) => RepairOutcome::SkippedStructural,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "oci-membership-edge-backfill: oci_membership_skipped marker insert \
                     failed; manifest remains a candidate (transient)"
                );
                RepairOutcome::SkippedTransient { edges_written: 0 }
            }
        }
    }

    /// Per-artifact re-derive + persist sequence. See the module doc's
    /// "Per-row write ordering" and "Failure modes per artifact" sections
    /// for the full contract.
    #[tracing::instrument(skip(self, artifact), fields(artifact_id = %artifact.id))]
    async fn repair(&self, artifact: &Artifact) -> RepairOutcome {
        let manifest_bytes = match self.read_manifest_bytes(artifact).await {
            Ok(b) => b,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "oci-membership-edge-backfill: CAS read failed; skipping (transient)"
                );
                return RepairOutcome::SkippedTransient { edges_written: 0 };
            }
        };

        let coords = hort_domain::types::ArtifactCoords {
            name: artifact.name.clone(),
            name_as_published: artifact.name_as_published.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            format: hort_domain::entities::repository::RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        };

        let refs = match self
            .oci_handler
            .extract_oci_manifest_blob_refs(&coords, &mut &manifest_bytes[..])
        {
            Ok(r) => r,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "oci-membership-edge-backfill: manifest did not parse; skipping (structural)"
                );
                return self.write_skip_marker(artifact).await;
            }
        };

        let mut config_hash = None;
        let mut layer_hashes = Vec::new();
        for r in refs {
            match r.role {
                ManifestBlobRole::Config => config_hash = Some(r.hash),
                ManifestBlobRole::Layer => layer_hashes.push(r.hash),
            }
        }
        let Some(config_hash) = config_hash else {
            tracing::debug!(
                "oci-membership-edge-backfill: no config-role reference derived; \
                 skipping (structural)"
            );
            return self.write_skip_marker(artifact).await;
        };

        let mut edges_written: u64 = 0;
        let mut layer_failed = false;
        for hash in &layer_hashes {
            match self.write_edge(artifact, OCI_LAYER_KIND, hash).await {
                Ok(()) => edges_written += 1,
                Err(err) => {
                    layer_failed = true;
                    tracing::warn!(
                        error = %err,
                        "oci-membership-edge-backfill: oci_layer insert failed; \
                         config edge deliberately withheld so this row stays a candidate"
                    );
                }
            }
        }
        if layer_failed {
            return RepairOutcome::SkippedTransient { edges_written };
        }

        match self
            .write_edge(artifact, OCI_CONFIG_KIND, &config_hash)
            .await
        {
            Ok(()) => RepairOutcome::Repaired {
                edges_written: edges_written + 1,
            },
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "oci-membership-edge-backfill: oci_config insert failed"
                );
                RepairOutcome::SkippedTransient { edges_written }
            }
        }
    }
}

impl TaskHandler for OciMembershipEdgeBackfillHandler {
    fn kind(&self) -> &'static str {
        "oci-membership-edge-backfill"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let batch_size = resolve_batch_size(params);
            let ignore_skip_markers = resolve_ignore_skip_markers(params);
            let skip_marker_kind = (!ignore_skip_markers).then_some(OCI_MEMBERSHIP_SKIPPED_KIND);

            let mut rows_scanned: u64 = 0;
            let mut rows_repaired: u64 = 0;
            let mut edges_written: u64 = 0;
            let mut skipped_structural: u64 = 0;
            let mut skipped_transient: u64 = 0;
            let mut cursor: Option<Uuid> = None;

            loop {
                let candidates = match self
                    .artifacts
                    .find_oci_image_manifests_without_kind(
                        OCI_CONFIG_KIND,
                        batch_size,
                        cursor,
                        skip_marker_kind,
                    )
                    .await
                {
                    Ok(c) => c,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "oci-membership-edge-backfill: find_oci_image_manifests_without_kind \
                             failed; will retry on next invocation",
                        );
                        return Ok(TaskOutcome::fail(
                            format!("find_oci_image_manifests_without_kind failed: {err}"),
                            true,
                        ));
                    }
                };
                if candidates.is_empty() {
                    break;
                }
                // Advance the cursor to the last page's max id
                // REGARDLESS of per-artifact outcome — the in-run keyset
                // advance the module doc describes.
                cursor = candidates.last().map(|a| a.id);
                let short_page = (candidates.len() as u32) < batch_size;

                for artifact in &candidates {
                    rows_scanned += 1;
                    match self.repair(artifact).await {
                        RepairOutcome::Repaired {
                            edges_written: n, ..
                        } => {
                            rows_repaired += 1;
                            edges_written += n;
                        }
                        RepairOutcome::SkippedStructural => skipped_structural += 1,
                        RepairOutcome::SkippedTransient {
                            edges_written: n, ..
                        } => {
                            skipped_transient += 1;
                            edges_written += n;
                        }
                    }
                }

                if short_page {
                    break;
                }
            }

            tracing::info!(
                rows_scanned,
                rows_repaired,
                edges_written,
                skipped_structural,
                skipped_transient,
                "oci-membership-edge-backfill complete"
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "rows_scanned":         rows_scanned,
                    "rows_repaired":        rows_repaired,
                    "edges_written":        edges_written,
                    "skipped_structural":   skipped_structural,
                    "skipped_transient":    skipped_transient,
                }),
            })
        })
    }
}

/// Parse `params.batch_size` (u64) into a clamped u32. Identical contract
/// to [`super::wheel_metadata_backfill::resolve_batch_size`] — see that
/// function's doc for the per-input-shape rationale.
pub(crate) fn resolve_batch_size(params: &serde_json::Value) -> u32 {
    let raw = params.get("batch_size").and_then(serde_json::Value::as_u64);
    let requested = match raw {
        Some(0) => DEFAULT_BATCH_SIZE as u64,
        Some(n) => n,
        None => DEFAULT_BATCH_SIZE as u64,
    };
    if requested > MAX_BATCH_SIZE as u64 {
        MAX_BATCH_SIZE
    } else {
        requested as u32
    }
}

/// Parse `params.ignore_skip_markers` (bool). Identical contract to
/// [`super::wheel_metadata_backfill::resolve_ignore_skip_markers`] — see
/// that function's doc.
pub(crate) fn resolve_ignore_skip_markers(params: &serde_json::Value) -> bool {
    params
        .get("ignore_skip_markers")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::DateTime;
    use uuid::Uuid;

    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::events::system_actor;
    use hort_domain::oci::{ManifestBlobRef, ManifestBlobRole};
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::types::ContentHash;

    use crate::use_cases::test_support::{
        MockArtifactRepository, MockContentReferenceIndex, MockStoragePort,
        OciMembershipEdgesStubBehaviour, StubFormatHandler,
    };

    // ---------- helpers -----------------------------------------------

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "oci-membership-edge-backfill".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "test".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(),
        }
    }

    fn deterministic_sha(seed: u32) -> ContentHash {
        let s = format!("{seed:064x}");
        s.parse().expect("64-hex sha")
    }

    /// Synthesise a `manifests/sha256:…`-pathed OCI manifest artifact.
    fn make_manifest(repo_id: Uuid, seed: u32, manifest_bytes_sha: ContentHash) -> Artifact {
        let now = Utc::now();
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: format!("repo-{seed}"),
            name_as_published: format!("repo-{seed}"),
            version: None,
            path: format!("manifests/sha256:{}", deterministic_sha(seed).as_ref()),
            size_bytes: 0,
            sha256_checksum: manifest_bytes_sha,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            quarantine_status: QuarantineStatus::Released,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    async fn put_into_cas(storage: &MockStoragePort, bytes: &[u8]) -> ContentHash {
        storage
            .put(Box::new(std::io::Cursor::new(bytes.to_vec())))
            .await
            .expect("CAS put")
            .hash
    }

    fn config_and_layer_refs(n_layers: u32) -> Vec<ManifestBlobRef> {
        let mut out = vec![ManifestBlobRef {
            hash: deterministic_sha(0xC0FF_EE00),
            role: ManifestBlobRole::Config,
        }];
        for i in 0..n_layers {
            out.push(ManifestBlobRef {
                hash: deterministic_sha(0xDEC0_0000 + i),
                role: ManifestBlobRole::Layer,
            });
        }
        out
    }

    fn make_handler_with(
        artifacts: Arc<MockArtifactRepository>,
        refs: Arc<MockContentReferenceIndex>,
        storage: Arc<MockStoragePort>,
        behaviour: OciMembershipEdgesStubBehaviour,
    ) -> OciMembershipEdgeBackfillHandler {
        let handler: Arc<dyn FormatHandler> =
            Arc::new(StubFormatHandler::new("oci").with_oci_membership_edges(behaviour));
        OciMembershipEdgeBackfillHandler::new(
            artifacts as Arc<dyn ArtifactRepository>,
            refs as Arc<dyn ContentReferenceIndex>,
            storage as Arc<dyn StoragePort>,
            handler,
        )
    }

    // =====================================================================
    // kind()
    // =====================================================================

    #[test]
    fn kind_returns_oci_membership_edge_backfill() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(Vec::new()),
        );
        assert_eq!(handler.kind(), "oci-membership-edge-backfill");
    }

    #[test]
    fn kind_matches_admin_invokable_task_kinds_entry() {
        use hort_domain::events::ADMIN_INVOKABLE_TASK_KINDS;
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(Vec::new()),
        );
        assert!(
            ADMIN_INVOKABLE_TASK_KINDS.contains(&handler.kind()),
            "Handler kind() {:?} MUST appear in ADMIN_INVOKABLE_TASK_KINDS",
            handler.kind()
        );
    }

    // =====================================================================
    // Empty candidates → all-zero summary, no CAS / DB activity
    // =====================================================================

    #[tokio::test]
    async fn run_with_empty_candidates_returns_zero_counts() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let refs_for_assert = refs.clone();

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(1)),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_scanned"], 0);
                assert_eq!(result_summary["rows_repaired"], 0);
                assert_eq!(result_summary["edges_written"], 0);
                assert_eq!(result_summary["skipped_structural"], 0);
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(refs_for_assert.entry_count(), 0);
    }

    // =====================================================================
    // Happy path: config + 2 layers → 3 edges, 1 row repaired
    // =====================================================================

    #[tokio::test]
    async fn run_with_config_and_layers_writes_all_edges() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"manifest-bytes").await;
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(2)),
        );

        let outcome = handler
            .run(&serde_json::json!({"batch_size": 10}), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_scanned"], 1);
                assert_eq!(result_summary["rows_repaired"], 1);
                assert_eq!(result_summary["edges_written"], 3);
                assert_eq!(result_summary["skipped_structural"], 0);
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(refs_for_assert.entry_count(), 3, "config + 2 layers");
    }

    /// A config-only manifest (zero layers) is a legitimate shape and
    /// must repair with exactly one edge.
    #[tokio::test]
    async fn run_config_only_manifest_writes_one_edge() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"manifest-bytes").await;
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(0)),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_repaired"], 1);
                assert_eq!(result_summary["edges_written"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(refs_for_assert.entry_count(), 1);
    }

    // =====================================================================
    // CAS-missing skip (transient)
    // =====================================================================

    #[tokio::test]
    async fn run_cas_get_failure_counts_skipped_transient() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // sha256_checksum has no matching bytes in the mock CAS.
        let missing_sha = deterministic_sha(0xDEAD_BEEF);
        let a = make_manifest(repo_id, 0, missing_sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(1)),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_scanned"], 1);
                assert_eq!(result_summary["rows_repaired"], 0);
                assert_eq!(result_summary["skipped_transient"], 1);
                assert_eq!(result_summary["skipped_structural"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            refs_for_assert.entry_count(),
            0,
            "a transient skip MUST NOT write a marker row"
        );
        assert!(refs_for_assert
            .find_by_source_and_kind(repo_id, id, OCI_MEMBERSHIP_SKIPPED_KIND)
            .await
            .expect("query")
            .is_none());
    }

    /// A CAS stream that fails mid-read (get succeeds, the body errors)
    /// hits the same `skipped_transient` bucket via the second `?` in
    /// `read_manifest_bytes`.
    #[tokio::test]
    async fn run_cas_stream_read_failure_counts_skipped_transient() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = deterministic_sha(0x0B00_B1E5);
        storage.fail_next_get_truncated(sha.clone(), b"partial".to_vec());
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(1)),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["skipped_transient"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Structural skips (marker written)
    // =====================================================================

    #[tokio::test]
    async fn run_extract_error_counts_skipped_structural_and_writes_marker() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"corrupt").await;
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Validation("not a valid OCI manifest"),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["skipped_structural"], 1);
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(
            refs_for_assert
                .find_by_source_and_kind(repo_id, id, OCI_MEMBERSHIP_SKIPPED_KIND)
                .await
                .expect("query")
                .is_some(),
            "marker row present for the unparseable manifest"
        );
    }

    /// Derived refs with no `Config`-role entry (e.g. an index-shaped
    /// body that slipped past the media-type filter) is a structural
    /// skip, not a panic or a silent no-op success.
    #[tokio::test]
    async fn run_no_config_role_derived_counts_skipped_structural_and_writes_marker() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"index-shaped").await;
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        let layer_only = vec![ManifestBlobRef {
            hash: deterministic_sha(1),
            role: ManifestBlobRole::Layer,
        }];
        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(layer_only),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["skipped_structural"], 1);
                assert_eq!(result_summary["rows_repaired"], 0);
                assert_eq!(result_summary["edges_written"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(refs_for_assert
            .find_by_source_and_kind(repo_id, id, OCI_MEMBERSHIP_SKIPPED_KIND)
            .await
            .expect("query")
            .is_some());
    }

    // =====================================================================
    // Partial-write ordering — layer failure withholds config edge
    // =====================================================================

    #[tokio::test]
    async fn run_layer_insert_failure_withholds_config_edge() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"manifest-bytes").await;
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        refs.fail_next_insert_for_kind(
            OCI_LAYER_KIND,
            DomainError::Invariant("simulated layer insert failure".into()),
        );
        let refs_for_assert = refs.clone();

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(1)),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_repaired"], 0);
                assert_eq!(
                    result_summary["skipped_transient"], 1,
                    "layer write failure must count as a transient skip, not a silent \
                     structural one — it may succeed on retry"
                );
                assert_eq!(
                    result_summary["edges_written"], 0,
                    "the single layer failed and the config write is deliberately withheld"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            refs_for_assert.entry_count(),
            0,
            "no oci_config row must land while a layer edge is missing — the row must \
             remain a NOT-EXISTS candidate on the next invocation"
        );
    }

    #[tokio::test]
    async fn run_config_insert_failure_counts_transient_with_partial_credit() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"manifest-bytes").await;
        let a = make_manifest(repo_id, 0, sha);
        let id = a.id;
        artifacts.insert(a);
        artifacts.set_oci_image_manifests_without_kind_filter(Some([id].into_iter().collect()));

        refs.fail_next_insert_for_kind(
            OCI_CONFIG_KIND,
            DomainError::Invariant("simulated config insert failure".into()),
        );
        let refs_for_assert = refs.clone();

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(2)),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_repaired"], 0);
                assert_eq!(result_summary["skipped_transient"], 1);
                assert_eq!(
                    result_summary["edges_written"], 2,
                    "the two layer writes that succeeded before the config write failed \
                     are still counted"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            refs_for_assert.entry_count(),
            2,
            "layers landed, config did not"
        );
    }

    // =====================================================================
    // Batch size
    // =====================================================================

    #[test]
    fn resolve_batch_size_clamps_to_max() {
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": 2000})),
            1_000
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": 500})),
            500
        );
    }

    #[test]
    fn resolve_batch_size_defaults_when_missing_or_zero_or_invalid() {
        assert_eq!(
            resolve_batch_size(&serde_json::Value::Null),
            DEFAULT_BATCH_SIZE
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": 0})),
            DEFAULT_BATCH_SIZE
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": "nope"})),
            DEFAULT_BATCH_SIZE
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": -5})),
            DEFAULT_BATCH_SIZE
        );
    }

    #[test]
    fn resolve_ignore_skip_markers_defaults_false() {
        assert!(!resolve_ignore_skip_markers(&serde_json::Value::Null));
        assert!(resolve_ignore_skip_markers(
            &serde_json::json!({"ignore_skip_markers": true})
        ));
        assert!(!resolve_ignore_skip_markers(
            &serde_json::json!({"ignore_skip_markers": "yes"})
        ));
    }

    /// The `skip_marker_kind` argument reaching the candidacy port call
    /// reflects `ignore_skip_markers` — mirrors the wheel-metadata
    /// handler's equivalent test.
    #[tokio::test]
    async fn run_passes_skip_marker_kind_per_ignore_skip_markers_param() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let artifacts_for_assert = artifacts.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(Vec::new()),
        );

        handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        let default_calls = artifacts_for_assert.oci_calls();
        assert_eq!(default_calls.len(), 1);
        assert_eq!(
            default_calls[0].skip_marker_kind.as_deref(),
            Some(OCI_MEMBERSHIP_SKIPPED_KIND)
        );

        handler
            .run(
                &serde_json::json!({"ignore_skip_markers": true}),
                make_context(),
            )
            .await
            .expect("Ok");
        let calls_after_ignore = artifacts_for_assert.oci_calls();
        assert_eq!(calls_after_ignore.last().unwrap().skip_marker_kind, None);
    }

    #[tokio::test]
    async fn run_with_batch_size_above_cap_clamps_page_size_but_drains_all_candidates() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let shared_sha = put_into_cas(&storage, b"identical-manifest-bytes").await;
        for seed in 0..1_500u32 {
            artifacts.insert(make_manifest(repo_id, seed, shared_sha.clone()));
        }
        let artifacts_for_assert = artifacts.clone();

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(0)),
        );

        let outcome = handler
            .run(&serde_json::json!({"batch_size": 2000}), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                let walked = result_summary["rows_scanned"].as_u64().unwrap();
                assert_eq!(
                    walked, 1_500,
                    "the in-run keyset advance drains every candidate across pages"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        let calls = artifacts_for_assert.oci_calls();
        assert!(calls.iter().all(|c| c.limit == 1_000));
        assert_eq!(calls.len(), 2);
    }

    // =====================================================================
    // In-run keyset advance — a repairable manifest behind > batch-size
    // structurally-skipped manifests is still repaired in the FIRST run.
    // =====================================================================

    /// Name-keyed OCI [`FormatHandler`] stub — mirrors
    /// `NameKeyedWheelMetadataHandler` in the wheel-metadata handler's
    /// tests. Returns a real config+layer ref set for one distinguished
    /// manifest name and an empty (structural-skip-triggering) set for
    /// everything else.
    struct NameKeyedOciHandler {
        repairable_name: String,
    }
    impl FormatHandler for NameKeyedOciHandler {
        fn format_key(&self) -> &str {
            "oci"
        }
        fn parse_download_path(
            &self,
            _path: &str,
        ) -> DomainResult<hort_domain::types::ArtifactCoords> {
            unimplemented!()
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
        fn extract_oci_manifest_blob_refs(
            &self,
            coords: &hort_domain::types::ArtifactCoords,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<ManifestBlobRef>> {
            if coords.name == self.repairable_name {
                Ok(config_and_layer_refs(1))
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[tokio::test]
    async fn run_repairs_valid_manifest_behind_more_than_batch_size_structural_skips() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let mut skip_ids: Vec<Uuid> = Vec::new();
        for seed in 0..5u32 {
            let bytes = format!("skip-manifest-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_manifest(repo_id, seed, sha);
            skip_ids.push(a.id);
            artifacts.insert(a);
        }
        let repairable_sha = put_into_cas(&storage, b"repairable-manifest-bytes").await;
        let repairable = make_manifest(repo_id, 5, repairable_sha);
        let repairable_id = repairable.id;
        let repairable_name = repairable.name.clone();
        artifacts.insert(repairable);

        let artifacts_for_assert = artifacts.clone();
        let oci_handler: Arc<dyn FormatHandler> = Arc::new(NameKeyedOciHandler { repairable_name });
        let handler = OciMembershipEdgeBackfillHandler::new(
            artifacts as Arc<dyn ArtifactRepository>,
            refs.clone() as Arc<dyn ContentReferenceIndex>,
            storage as Arc<dyn StoragePort>,
            oci_handler,
        );

        let outcome = handler
            .run(&serde_json::json!({"batch_size": 3}), make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_scanned"], 6);
                assert_eq!(result_summary["skipped_structural"], 5);
                assert_eq!(
                    result_summary["rows_repaired"], 1,
                    "the repairable manifest behind the > batch-size skip run IS repaired \
                     in the first run"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        for id in &skip_ids {
            assert!(refs
                .find_by_source_and_kind(repo_id, *id, OCI_MEMBERSHIP_SKIPPED_KIND)
                .await
                .expect("query")
                .is_some());
        }
        assert!(refs
            .find_by_source_and_kind(repo_id, repairable_id, OCI_CONFIG_KIND)
            .await
            .expect("query")
            .is_some());

        // A full-length page never short-circuits the loop on its own
        // (only a page shorter than `batch_size` does), so 6 candidates
        // at batch_size 3 costs a third, empty, draining page.
        let calls = artifacts_for_assert.oci_calls();
        assert_eq!(
            calls.len(),
            3,
            "6 candidates at batch_size 3 → two full pages then a draining empty page"
        );
        assert_eq!(calls[0].after, None);
        assert!(calls[1].after.is_some());
        assert!(calls[2].after > calls[1].after);
    }

    // =====================================================================
    // Marker persistence proof — run 2 does not re-read structural skips
    // =====================================================================

    #[tokio::test]
    async fn run_two_does_not_reread_structural_skips_once_marked() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let mut ids: Vec<Uuid> = Vec::new();
        for seed in 0..3u32 {
            let bytes = format!("skip-manifest-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_manifest(repo_id, seed, sha);
            ids.push(a.id);
            artifacts.insert(a);
        }

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts.clone(),
            refs,
            storage,
            OciMembershipEdgesStubBehaviour::Edges(Vec::new()),
        );

        let first = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match first {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["rows_scanned"], 3);
                assert_eq!(result_summary["skipped_structural"], 3);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        for id in &ids {
            assert!(refs_for_assert
                .find_by_source_and_kind(repo_id, *id, OCI_MEMBERSHIP_SKIPPED_KIND)
                .await
                .expect("query")
                .is_some());
        }

        // Mirrors what the real adapter's NOT EXISTS predicate on
        // `oci_membership_skipped` would enforce on a second invocation
        // — see the equivalent wheel-metadata-backfill test for the full
        // rationale (this mock's candidacy is an explicit allowlist, not
        // a live read of `MockContentReferenceIndex`; the DB-level proof
        // lives in the `hort-adapters-postgres` `skip_marker_kind` tests).
        artifacts
            .set_oci_image_manifests_without_kind_filter(Some(std::collections::HashSet::new()));

        let second = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match second {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["rows_scanned"], 0,
                    "the second run must not re-read the now-marked structural skips"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Resumability — retry after a candidacy-query failure re-derives
    // the same work (unit-level: the port call shape, not full drain).
    // =====================================================================

    #[tokio::test]
    async fn run_is_resumable_after_transient_candidate_shrink() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let mut all_ids: Vec<Uuid> = Vec::new();
        for seed in 0..5u32 {
            let bytes = format!("manifest-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_manifest(repo_id, seed, sha);
            all_ids.push(a.id);
            artifacts.insert(a);
        }
        artifacts
            .set_oci_image_manifests_without_kind_filter(Some(all_ids.iter().copied().collect()));

        let handler = make_handler_with(
            artifacts.clone(),
            refs.clone(),
            storage.clone(),
            OciMembershipEdgesStubBehaviour::Edges(config_and_layer_refs(0)),
        );

        // A single run now fully drains the candidate set via the
        // in-run keyset advance (unlike the pre-#141 one-page-per-run
        // shape) — all 5 land `oci_config` rows in one invocation.
        let first = handler
            .run(&serde_json::json!({"batch_size": 3}), make_context())
            .await
            .expect("Ok");
        let first_scanned = match &first {
            TaskOutcome::Completed { result_summary } => {
                result_summary["rows_scanned"].as_u64().unwrap()
            }
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(first_scanned, 5, "the run drains the full candidate set");

        // A second invocation against the SAME (unchanged) allowlist
        // re-derives the same candidates — this mock's allowlist does
        // not read `MockContentReferenceIndex`, so it does not model the
        // adapter's own NOT-EXISTS-on-`oci_config` pruning. The point
        // here is the port call shape: a fresh invocation starts with a
        // fresh `after = None` cursor.
        let second = handler
            .run(&serde_json::json!({"batch_size": 3}), make_context())
            .await
            .expect("Ok");
        let second_scanned = match second {
            TaskOutcome::Completed { result_summary } => {
                result_summary["rows_scanned"].as_u64().unwrap()
            }
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(second_scanned, 5);
    }

    // =====================================================================
    // Candidacy-query failure → TaskOutcome::Failed(retry: true)
    // =====================================================================

    struct FailingArtifactRepo;
    impl ArtifactRepository for FailingArtifactRepo {
        fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>> {
            unimplemented!()
        }
        fn find_by_checksum(
            &self,
            _h: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_repo_and_checksum(
            &self,
            _r: Uuid,
            _h: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_by_repository(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn delete(
            &self,
            _id: Uuid,
            _actor: hort_domain::events::Actor,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_path(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_distinct_names(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<String>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_in_repo(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_as_published(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn list_active_for_repo(
            &self,
            _r: Uuid,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::LimitedList<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_rejected_for_policy(
            &self,
            _p: Uuid,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::LimitedList<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_active_for_policy(
            &self,
            _p: Uuid,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn package_version_status(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn find_pypi_wheels_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn find_oci_image_manifests_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "simulated find_oci_image_manifests_without_kind failure".into(),
                ))
            })
        }
    }

    #[tokio::test]
    async fn run_returns_failed_retry_when_candidacy_query_errors() {
        let artifacts: Arc<dyn ArtifactRepository> = Arc::new(FailingArtifactRepo);
        let refs: Arc<dyn ContentReferenceIndex> = Arc::new(MockContentReferenceIndex::new());
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let oci: Arc<dyn FormatHandler> = Arc::new(StubFormatHandler::new("oci"));
        let handler = OciMembershipEdgeBackfillHandler::new(artifacts, refs, storage, oci);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — candidacy errors surface via TaskOutcome::Failed");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "candidacy failure MUST set retry=true");
                assert!(reason.contains("find_oci_image_manifests_without_kind"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
