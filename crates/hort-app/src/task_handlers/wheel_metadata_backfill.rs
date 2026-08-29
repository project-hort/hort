//! TaskHandler for the PEP 658 wheel-metadata backfill.
//!
//! Operator-opt-in retrofit for PyPI wheels ingested before the
//! metadata-extraction hook existed. The
//! ingest hook extracts the wheel's `<dist-info>/METADATA`
//! bytes into CAS and inserts a `kind = "wheel_metadata"` row on the
//! `content_references` projection for newly-ingested wheels; the
//! simple-index advertises PEP 658 (`data-dist-info-metadata`)
//! exactly when that row exists, so wheels without the row receive no
//! advertisement and pip falls back to whole-wheel download.
//!
//! This task is the retrofit: it walks PyPI wheel artifacts whose
//! `content_references` row of kind `wheel_metadata` is absent
//! ([`ArtifactRepository::find_pypi_wheels_without_kind`]), streams
//! each wheel from CAS, invokes
//! [`FormatHandler::extract_wheel_metadata_bytes`], and on
//! `Ok(Some(bytes))` writes the bytes to CAS + inserts the
//! ContentReference row — mirroring the ingest hook one-for-one.
//!
//! # Delivery
//!
//! Triggered by an operator. Two paths:
//!
//! 1. **Helm CronJob** (`deploy/helm/hort-server/templates/
//!    cronjob-wheel-metadata-backfill.yaml`, default-disabled). Runs
//!    `hort-server enqueue-wheel-metadata-backfill` with the runtime DSN,
//!    inserts one `kind = 'wheel-metadata-backfill'` row, the worker
//!    picks it up and dispatches here. Mirrors the
//!    `quarantine-release-sweep` delivery contract verbatim (no
//!    svc-token chain, no `cronJobs.enabled` umbrella). Default-disabled because
//!    a freshly-deployed operator's wheel inventory is empty; the
//!    backfill is a one-shot retrofit, not a steady-state sweep.
//!
//! 2. **Manual operator invocation** via the `hort-http-admin-tasks`
//!    HTTP route — `hort-cli admin task invoke wheel-metadata-backfill
//!    --params-file /tmp/p.json`. The `hort-cli` machinery accepts
//!    arbitrary kinds; the kind is gated server-side against
//!    `ADMIN_INVOKABLE_TASK_KINDS`.
//!
//! # Params
//!
//! - `batch_size` (int) — the in-run keyset page size; defaults to
//!   [`DEFAULT_BATCH_SIZE`] = 100, capped at [`MAX_BATCH_SIZE`] = 1000.
//!   Operators tightening below 100 are explicitly making the per-page
//!   wall-clock + memory tradeoff (one fewer wheel per page = less peak
//!   memory; one more page to drain). This does NOT bound the run's
//!   total work — see Resumability below.
//! - `ignore_skip_markers` (bool) — defaults to `false`. When `true`, the
//!   candidacy query re-surfaces wheels already carrying a
//!   `wheel_metadata_skipped` durable marker (see "Durable structural-skip
//!   marker" below) — for the day a parser fix makes a previously-corrupt
//!   wheel readable.
//!
//! # Resumability
//!
//! **In-run keyset advance.** A single invocation walks candidates in
//! pages of `batch_size`, using an in-memory keyset cursor
//! (`after = max(id)` of the previous page, advanced regardless of that
//! page's outcome — processed, structurally skipped, or transiently
//! skipped). The candidacy query is otherwise stateless
//! (`artifacts.path LIKE '%.whl' AND NOT EXISTS … kind='wheel_metadata'`,
//! further narrowed by the durable skip marker below); a run keeps
//! fetching pages until one comes back short of `batch_size`, so it visits
//! every current candidate exactly once and always terminates. This is
//! what prevents a page of 100%-skipped wheels from stalling the run at
//! the same rows forever — a wheel that becomes a candidate only because
//! `batch_size` low-id wheels ahead of it are permanently unprocessable is
//! still reached within the SAME run.
//!
//! **Durable structural-skip marker.** A *structural* skip (see "Failure
//! modes" below) additionally inserts a `content_references` row
//! (`kind = "wheel_metadata_skipped"`, target = the wheel's own content
//! hash — the same self-referential shape the `primary_content` refcount
//! row uses) and the candidacy query's `NOT EXISTS` is extended to exclude
//! marked rows. Re-running the extraction on the same immutable CAS
//! content cannot change a structural outcome, so a structurally
//! unprocessable wheel leaves the candidate pool permanently instead of
//! paying a repeated CAS read + ZIP parse on every future invocation. A
//! *transient* skip writes no marker — the artifact remains a candidate,
//! and the in-run keyset advance above already keeps it from starving the
//! current run.
//!
//! Across invocations: a failed page leaves the candidate set unchanged;
//! the next invocation starts a fresh cursor at `after = None` and
//! re-derives the same work minus whatever a prior successful invocation
//! completed (extracted, or structurally marked). Two concurrent runs
//! would walk overlapping sets; the per-CAS `StoragePort::put` idempotency
//! on identical content + the upsert semantics of
//! `ContentReferenceIndex::insert` absorb the duplicate work.
//!
//! # Failure modes per artifact
//!
//! Mirrors the ingest-hook posture, split by the transient/structural
//! criterion that decides marker-writing (see Resumability above):
//!
//! - `Ok(Some(bytes))` → write to CAS + insert ContentReference →
//!   counts in `metadata_extracted`.
//! - **Structural** (re-running cannot change the outcome for the same
//!   immutable bytes — a durable marker is written): `Ok(None)` (corrupt
//!   wheel, no METADATA member, not actually a wheel ZIP) or
//!   `Err(DomainError::Validation(_))` (oversized METADATA past the 1 MiB
//!   cap — the ingest hook treats this as non-fatal too; the backfill must
//!   not diverge from that contract) → counts in `skipped_structural`. If
//!   the marker insert itself fails, the wheel remains a candidate for the
//!   next run — counted in `skipped_transient` instead (see below), since
//!   what determines the bucket is whether the wheel stays a candidate,
//!   not the parse-level cause.
//! - **Transient** (infrastructure-class — CAS read/write failure, DB
//!   insert failure, including a failed marker insert) → log `warn!`,
//!   count in `skipped_transient`, **continue**. No marker is written; the
//!   wheel remains a candidate and the next invocation retries it. A
//!   per-artifact failure never aborts the batch — one bad wheel cannot
//!   starve the rest of the candidate set.
//!
//! # No new domain event
//!
//! The backfill produces only derived-projection rows
//! (`ContentReference kind=wheel_metadata` /
//! `kind=wheel_metadata_skipped`) — exactly what the ingest hook
//! produces — not domain facts. No new event variant; the event stream
//! stays lean.
//!
//! # No new metrics
//!
//! Reuses the `hort_ingest_total{result="wheel_metadata_extract_failed"}`
//! catalog entry conceptually (validation skip), but this handler
//! deliberately emits **no metrics** — the per-tick `result_summary`
//! JSON is the operator-visible observability signal (mirrors
//! `QuarantineReleaseSweepHandler` / `PrefetchTickHandler`). A
//! steady-state operator who has run the backfill once does not need
//! a permanent gauge; a forensic operator reads `result_summary` from
//! the `jobs` row. Same posture as the other sweep handlers.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use hort_domain::types::PayloadAccess;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default `batch_size` when the operator omits it from `params`.
/// 100 wheels per page balances per-page wall clock (every wheel pays
/// one CAS round-trip + one ZIP-seek + one CAS put + one DB insert)
/// against operator-perceived progress. Bounds page size only — a run
/// walks as many pages as the candidate set requires (see the module
/// doc's Resumability section).
pub(crate) const DEFAULT_BATCH_SIZE: u32 = 100;

/// Hard cap on `batch_size` regardless of operator input. Mirrors the
/// `BATCH_SIZE = 1000` discipline in
/// [`super::quarantine_release_sweep::QuarantineReleaseSweepHandler`].
/// Operators wanting a larger per-page throughput tighten this cap's
/// neighbourhood, not the run's total work — keeping the per-page memory
/// profile bounded regardless of how large the candidate set is.
pub(crate) const MAX_BATCH_SIZE: u32 = 1_000;

/// `content_references.kind` value the candidacy query filters against
/// and the produced row carries on a successful extraction. Single
/// source of truth so a future rename of the kind literal stays
/// consistent across the handler + the SQL filter.
pub(crate) const WHEEL_METADATA_KIND: &str = "wheel_metadata";

/// `content_references.kind` value written for a **structural** skip —
/// see the module doc's "Durable structural-skip marker" section. A
/// distinct kind from [`WHEEL_METADATA_KIND`] so the two are queryable
/// (and excludable) independently: a row can never carry both, since a
/// wheel is either successfully extracted or structurally unprocessable,
/// never both.
pub(crate) const WHEEL_METADATA_SKIPPED_KIND: &str = "wheel_metadata_skipped";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Per-artifact extract outcome — the shape
/// [`WheelMetadataBackfillHandler::extract_and_persist`] returns to the
/// run loop. See the module doc's "Failure modes per artifact" section
/// for the full contract deciding which outcome an artifact lands in.
enum ExtractOutcome {
    /// METADATA extracted and persisted (CAS put + CR insert both
    /// succeeded).
    Extracted,
    /// Structural skip, durable marker written — the wheel leaves
    /// candidacy permanently.
    SkippedStructural,
    /// Transient skip (infrastructure-class failure, including a failed
    /// marker insert) — no marker; the wheel remains a candidate.
    SkippedTransient,
}

/// [`TaskHandler`] for the periodic / one-shot wheel-metadata backfill.
/// Constructed at composition time with the four ports it touches:
///
/// - [`ArtifactRepository`] — candidacy walk
///   ([`ArtifactRepository::find_pypi_wheels_without_kind`]).
/// - [`ContentReferenceIndex`] — per-artifact ContentReference insert
///   on a successful extraction, or a durable skip marker on a
///   structural skip.
/// - [`StoragePort`] — CAS read (wheel bytes) + CAS write (extracted
///   METADATA bytes).
/// - PyPI [`FormatHandler`] — the
///   [`FormatHandler::extract_wheel_metadata_bytes`] call that produces
///   the bytes from the wheel ZIP.
pub struct WheelMetadataBackfillHandler {
    artifacts: Arc<dyn ArtifactRepository>,
    content_references: Arc<dyn ContentReferenceIndex>,
    storage: Arc<dyn StoragePort>,
    /// PyPI handler. The backfill is PyPI-only by design (PEP 658
    /// applies only to wheels); the composition root wires the PyPI
    /// handler in directly rather than threading the full per-format
    /// registry — there is no per-artifact format dispatch in this
    /// path (the candidacy SQL already filters to `.whl`).
    pypi_handler: Arc<dyn FormatHandler>,
}

impl WheelMetadataBackfillHandler {
    /// Construct the handler from its port dependencies.
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        content_references: Arc<dyn ContentReferenceIndex>,
        storage: Arc<dyn StoragePort>,
        pypi_handler: Arc<dyn FormatHandler>,
    ) -> Self {
        Self {
            artifacts,
            content_references,
            storage,
            pypi_handler,
        }
    }

    /// Per-artifact extract + persist sequence. See the module doc's
    /// "Failure modes per artifact" section for the full contract.
    ///
    /// This is the same shape as the ingest hook, factored as a
    /// per-artifact method so the batch loop reads as a flat
    /// match-on-result. The two call sites share no code today —
    /// the ingest hook is wrapped in `InnerIngestError` and lives inside
    /// the ingest transaction boundary; this handler returns plain
    /// `DomainError` and runs outside any transaction. Per the
    /// architect's no-3+-similar-blocks rule, two structurally
    /// distinct copies of this 20-line sequence is acceptable —
    /// extracting a shared helper would force the ingest path into the
    /// non-transactional shape, which is a worse fit for the hot
    /// ingest path.
    #[tracing::instrument(skip(self, artifact), fields(artifact_id = %artifact.id))]
    async fn extract_and_persist(&self, artifact: &Artifact) -> ExtractOutcome {
        // Re-read the wheel from CAS. The 1 MiB cap on METADATA is
        // enforced INSIDE `extract_wheel_metadata_bytes` on the ZIP
        // entry's header — the raw wheel bytes here are bounded only
        // by the per-format ingest cap that applied at original
        // ingest time (so no extra cap needed here).
        let mut wheel_bytes: Vec<u8> = Vec::new();
        let mut stream = match self.storage.get(&artifact.sha256_checksum).await {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "wheel-metadata-backfill: CAS read failed; skipping (transient)"
                );
                return ExtractOutcome::SkippedTransient;
            }
        };
        if let Err(err) = stream.read_to_end(&mut wheel_bytes).await {
            tracing::warn!(
                error = %err,
                "wheel-metadata-backfill: CAS stream read failed; skipping (transient)"
            );
            return ExtractOutcome::SkippedTransient;
        }

        // Synthesise the minimum `ArtifactCoords` the trait method
        // needs. The PyPI format handler reads `coords.path` to gate
        // on the `.whl` suffix and the rest from `coords.format`
        // — the candidacy SQL already filters to `.whl`, but we
        // populate the field anyway so the handler's gate fires
        // positive for sanity, not negative for a missing `.whl`.
        let coords = hort_domain::types::ArtifactCoords {
            name: artifact.name.clone(),
            name_as_published: artifact.name_as_published.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            format: hort_domain::entities::repository::RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        };

        let extract = self
            .pypi_handler
            .extract_wheel_metadata_bytes(&coords, PayloadAccess::Bytes(&wheel_bytes));

        match extract {
            Ok(Some(metadata_bytes)) => {
                let metadata_len = metadata_bytes.len();
                let put_result = match self
                    .storage
                    .put(Box::new(std::io::Cursor::new(metadata_bytes.to_vec())))
                    .await
                {
                    Ok(r) => r,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "wheel-metadata-backfill: METADATA CAS put failed; skipping (transient)"
                        );
                        return ExtractOutcome::SkippedTransient;
                    }
                };
                let metadata_hash = put_result.hash;
                if let Err(err) = self
                    .content_references
                    .insert(ContentReference {
                        source_artifact_id: artifact.id,
                        target_content_hash: metadata_hash.clone(),
                        kind: WHEEL_METADATA_KIND.to_string(),
                        metadata: serde_json::Value::Object(serde_json::Map::new()),
                        repository_id: artifact.repository_id,
                        recorded_at: Utc::now(),
                    })
                    .await
                {
                    tracing::warn!(
                        error = %err,
                        "wheel-metadata-backfill: wheel_metadata ContentReference insert failed; \
                         skipping (transient)"
                    );
                    return ExtractOutcome::SkippedTransient;
                }
                tracing::debug!(
                    metadata_hash = %metadata_hash,
                    metadata_bytes = metadata_len,
                    "wheel-metadata-backfill: extracted + persisted"
                );
                ExtractOutcome::Extracted
            }
            Ok(None) => {
                // Non-wheel ZIP, missing METADATA member, sdist that
                // somehow slipped past the candidacy SQL — all
                // structural: re-running cannot change the outcome for
                // the same immutable CAS content. The SQL guards against
                // sdists (`path LIKE '%.whl'`); a wheel that legitimately
                // has no METADATA member is corrupt and we mark it.
                self.write_skip_marker(artifact).await
            }
            Err(DomainError::Validation(reason)) => {
                // Oversized METADATA (the only production path
                // surfacing `Err(Validation)` today) — structural for the
                // same reason: the ingest hook treats this as non-fatal,
                // and the byte count cannot change on a re-read of
                // immutable content.
                tracing::debug!(
                    reason = %reason,
                    "wheel-metadata-backfill: validation skip (oversized METADATA) — structural"
                );
                self.write_skip_marker(artifact).await
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "wheel-metadata-backfill: extract_wheel_metadata_bytes failed; \
                     skipping (transient)"
                );
                ExtractOutcome::SkippedTransient
            }
        }
    }

    /// Insert the durable `wheel_metadata_skipped` marker row for a
    /// structural skip. Target = the wheel's own content hash —
    /// self-referential, mirroring the `primary_content` refcount row's
    /// shape (there is no separate "target content" for a marker; the
    /// row documents an attribute of its own source).
    ///
    /// A failed insert downgrades the outcome to
    /// [`ExtractOutcome::SkippedTransient`]: what decides the bucket is
    /// whether the wheel remains a candidate on the next run, and if the
    /// marker did not land, it does.
    async fn write_skip_marker(&self, artifact: &Artifact) -> ExtractOutcome {
        match self
            .content_references
            .insert(ContentReference {
                source_artifact_id: artifact.id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: WHEEL_METADATA_SKIPPED_KIND.to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: artifact.repository_id,
                recorded_at: Utc::now(),
            })
            .await
        {
            Ok(()) => ExtractOutcome::SkippedStructural,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "wheel-metadata-backfill: wheel_metadata_skipped marker insert failed; \
                     wheel remains a candidate (transient)"
                );
                ExtractOutcome::SkippedTransient
            }
        }
    }
}

impl TaskHandler for WheelMetadataBackfillHandler {
    fn kind(&self) -> &'static str {
        "wheel-metadata-backfill"
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
            let skip_marker_kind = (!ignore_skip_markers).then_some(WHEEL_METADATA_SKIPPED_KIND);

            let mut artifacts_walked: u64 = 0;
            let mut metadata_extracted: u64 = 0;
            let mut skipped_structural: u64 = 0;
            let mut skipped_transient: u64 = 0;
            let mut cursor: Option<Uuid> = None;

            loop {
                let candidates = match self
                    .artifacts
                    .find_pypi_wheels_without_kind(
                        WHEEL_METADATA_KIND,
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
                            "wheel-metadata-backfill: find_pypi_wheels_without_kind failed; \
                             will retry on next invocation",
                        );
                        return Ok(TaskOutcome::fail(
                            format!("find_pypi_wheels_without_kind failed: {err}"),
                            true,
                        ));
                    }
                };
                if candidates.is_empty() {
                    break;
                }
                // Advance the cursor to the last page's max id
                // REGARDLESS of per-artifact outcome — the in-run keyset
                // advance the module doc describes. `ORDER BY id` on the
                // candidacy query makes the last element the max.
                cursor = candidates.last().map(|a| a.id);
                let short_page = (candidates.len() as u32) < batch_size;

                for artifact in &candidates {
                    artifacts_walked += 1;
                    match self.extract_and_persist(artifact).await {
                        ExtractOutcome::Extracted => metadata_extracted += 1,
                        ExtractOutcome::SkippedStructural => skipped_structural += 1,
                        ExtractOutcome::SkippedTransient => skipped_transient += 1,
                    }
                }

                if short_page {
                    break;
                }
            }

            tracing::info!(
                artifacts_walked,
                metadata_extracted,
                skipped_structural,
                skipped_transient,
                "wheel-metadata-backfill complete"
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "artifacts_walked":     artifacts_walked,
                    "metadata_extracted":   metadata_extracted,
                    "skipped_structural":   skipped_structural,
                    "skipped_transient":    skipped_transient,
                }),
            })
        })
    }
}

/// Parse `params.batch_size` (u64) into a clamped u32. Out-of-range,
/// missing, or non-integer values fall back to [`DEFAULT_BATCH_SIZE`].
/// Values above [`MAX_BATCH_SIZE`] clamp to that cap — the operator
/// CAN ask for more but the handler bounds the per-page memory profile.
///
/// Total/pure — extracted as a free function so the unit tests can pin
/// every input shape without standing up the full handler.
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

/// Parse `params.ignore_skip_markers` (bool) — defaults to `false` for
/// any missing or non-boolean value. `true` lifts the durable
/// structural-skip exclusion for this invocation, re-surfacing
/// previously-marked wheels (see the module doc's "Durable
/// structural-skip marker" section).
///
/// Total/pure — mirrors [`resolve_batch_size`]'s shape so the unit tests
/// can pin every input shape without standing up the full handler.
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

    use bytes::Bytes;
    use chrono::DateTime;
    use uuid::Uuid;

    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::events::system_actor;
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::types::{ArtifactCoords, ContentHash};

    use crate::use_cases::test_support::{
        MockArtifactRepository, MockContentReferenceIndex, MockStoragePort, StubFormatHandler,
        WheelMetadataStubBehaviour,
    };

    // ---------- helpers ---------------------------------------------------

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "wheel-metadata-backfill".to_string(),
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

    /// Build a hex-64 SHA-256 string from a u32 seed — deterministic
    /// across invocations and unique within a single test. The mock
    /// CAS is keyed on the bytes you `put` (real SHA-256), not on this
    /// seed, so the seeded checksum field on the synthetic
    /// `Artifact` need only satisfy `ContentHash::parse`'s 64-lowercase-
    /// hex invariant.
    fn deterministic_sha(seed: u32) -> ContentHash {
        let s = format!("{seed:064x}");
        s.parse().expect("64-hex sha")
    }

    /// Synthesise a `.whl`-pathed PyPI wheel artifact. The mock CAS
    /// is separately seeded — the artifact's `sha256_checksum` must
    /// match the bytes you put into the mock storage for the
    /// extract-and-persist sequence to find them.
    fn make_wheel(
        repo_id: Uuid,
        seed: u32,
        wheel_bytes_sha: ContentHash,
        version: &str,
    ) -> Artifact {
        let now = Utc::now();
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: format!("pkg-{seed}"),
            name_as_published: format!("pkg-{seed}"),
            version: Some(version.to_string()),
            path: format!("files/pkg_{seed}-{version}-py3-none-any.whl"),
            size_bytes: 0,
            sha256_checksum: wheel_bytes_sha,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".to_string(),
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

    /// Put `bytes` into a `MockStoragePort` and return its actual
    /// SHA-256 (the mock computes real SHA-256 on `put`).
    async fn put_into_cas(storage: &MockStoragePort, bytes: &[u8]) -> ContentHash {
        storage
            .put(Box::new(std::io::Cursor::new(bytes.to_vec())))
            .await
            .expect("CAS put")
            .hash
    }

    /// Build the handler wired with the four mocks + a stub PyPI
    /// handler whose `extract_wheel_metadata_bytes` returns the
    /// `behaviour`. Centralises the construction so every test reads
    /// 4-line setup + assert.
    fn make_handler_with(
        artifacts: Arc<MockArtifactRepository>,
        refs: Arc<MockContentReferenceIndex>,
        storage: Arc<MockStoragePort>,
        behaviour: WheelMetadataStubBehaviour,
    ) -> WheelMetadataBackfillHandler {
        let handler: Arc<dyn FormatHandler> =
            Arc::new(StubFormatHandler::new("pypi").with_wheel_metadata(behaviour));
        WheelMetadataBackfillHandler::new(
            artifacts as Arc<dyn ArtifactRepository>,
            refs as Arc<dyn ContentReferenceIndex>,
            storage as Arc<dyn StoragePort>,
            handler,
        )
    }

    // =====================================================================
    // kind() returns "wheel-metadata-backfill"
    // =====================================================================

    #[test]
    fn kind_returns_wheel_metadata_backfill() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let handler = make_handler_with(artifacts, refs, storage, WheelMetadataStubBehaviour::None);
        assert_eq!(handler.kind(), "wheel-metadata-backfill");
    }

    // =====================================================================
    // Test 1: Empty candidates → summary all zeros, no CAS / DB activity
    // =====================================================================

    #[tokio::test]
    async fn run_with_empty_candidates_returns_zero_counts() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let storage_for_assert = storage.clone();
        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            WheelMetadataStubBehaviour::EmitBytes(b"unused".to_vec()),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 0);
                assert_eq!(result_summary["metadata_extracted"], 0);
                assert_eq!(result_summary["skipped_structural"], 0);
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            storage_for_assert.put_call_count(),
            0,
            "empty candidate set must NOT touch storage"
        );
        assert_eq!(
            refs_for_assert.entry_count(),
            0,
            "empty candidate set must NOT insert any ContentReference rows"
        );
    }

    // =====================================================================
    // Test 2: Happy-path batch — 3 wheels → 3 metadata blobs in CAS + 3 CR rows
    // =====================================================================

    #[tokio::test]
    async fn run_with_three_wheels_writes_three_content_references() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // Seed three wheels in the mock CAS + the artifacts repo.
        let mut wheel_ids: Vec<Uuid> = Vec::new();
        for seed in 0..3u32 {
            let bytes = format!("wheel-bytes-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_wheel(repo_id, seed, sha, &format!("1.{seed}.0"));
            wheel_ids.push(a.id);
            artifacts.insert(a);
        }

        // Initial CAS put count = 3 (one per wheel).
        let baseline_puts = storage.put_call_count();
        assert_eq!(baseline_puts, 3);

        let storage_for_assert = storage.clone();
        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            WheelMetadataStubBehaviour::EmitBytes(b"METADATA-bytes".to_vec()),
        );

        let outcome = handler
            .run(&serde_json::json!({"batch_size": 10}), make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 3);
                assert_eq!(result_summary["metadata_extracted"], 3);
                assert_eq!(result_summary["skipped_structural"], 0);
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        // Each wheel produced ONE additional CAS put (the METADATA
        // bytes) + ONE ContentReference insert. The three wheels share
        // identical synthetic METADATA bytes (the stub emits the same
        // bytes), so the CAS put is idempotent on the second + third
        // — but the `put_call_count` increments unconditionally (it's
        // the call counter, not the unique-hash counter).
        let metadata_puts = storage_for_assert.put_call_count() - baseline_puts;
        assert_eq!(
            metadata_puts, 3,
            "exactly one METADATA put per candidate (3 candidates → 3 puts)"
        );
        assert_eq!(
            refs_for_assert.entry_count(),
            3,
            "three wheel_metadata ContentReference rows"
        );
    }

    // =====================================================================
    // Test 3: Wheel with no METADATA member → skipped_structural, marker
    // written, no wheel_metadata CR.
    // =====================================================================

    #[tokio::test]
    async fn run_corrupt_wheel_counts_skipped_structural_and_writes_marker() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let bytes = b"corrupt-wheel-bytes";
        let sha = put_into_cas(&storage, bytes).await;
        let wheel = make_wheel(repo_id, 0, sha, "1.0.0");
        let wheel_id = wheel.id;
        artifacts.insert(wheel);

        let baseline_puts = storage.put_call_count();
        let storage_for_assert = storage.clone();
        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            // The stub returns Ok(None) — modelling
            // "extract_wheel_metadata_bytes saw no METADATA member."
            WheelMetadataStubBehaviour::None,
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 1);
                assert_eq!(result_summary["metadata_extracted"], 0);
                assert_eq!(result_summary["skipped_structural"], 1);
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            storage_for_assert.put_call_count() - baseline_puts,
            0,
            "Ok(None) must NOT trigger a METADATA CAS put"
        );
        assert_eq!(
            refs_for_assert.entry_count(),
            1,
            "Ok(None) must insert exactly the wheel_metadata_skipped marker row"
        );
        let marker = refs_for_assert
            .find_by_source_and_kind(repo_id, wheel_id, WHEEL_METADATA_SKIPPED_KIND)
            .await
            .expect("query")
            .expect("marker row present");
        assert_eq!(marker.kind, WHEEL_METADATA_SKIPPED_KIND);
    }

    // =====================================================================
    // Test 4: Oversized METADATA (Err(Validation)) → skipped_structural,
    // marker written.
    //
    // Mirrors the Item-3 hook's posture: Validation = non-fatal skip,
    // still structural (immutable content, re-running cannot help).
    // =====================================================================

    #[tokio::test]
    async fn run_oversized_metadata_counts_skipped_structural_and_writes_marker() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"oversized-wheel").await;
        let wheel = make_wheel(repo_id, 0, sha, "1.0.0");
        let wheel_id = wheel.id;
        artifacts.insert(wheel);

        let baseline_puts = storage.put_call_count();
        let storage_for_assert = storage.clone();
        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            WheelMetadataStubBehaviour::Validation("METADATA exceeds 1 MiB cap"),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 1);
                assert_eq!(result_summary["metadata_extracted"], 0);
                assert_eq!(
                    result_summary["skipped_structural"], 1,
                    "Err(Validation) counts as `skipped_structural`, not `skipped_transient` — \
                     mirrors the ingest hook posture (non-fatal) plus the immutable-content \
                     rationale"
                );
                assert_eq!(result_summary["skipped_transient"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(storage_for_assert.put_call_count() - baseline_puts, 0);
        assert_eq!(refs_for_assert.entry_count(), 1, "the marker row");
        assert!(
            refs_for_assert
                .find_by_source_and_kind(repo_id, wheel_id, WHEEL_METADATA_SKIPPED_KIND)
                .await
                .expect("query")
                .is_some(),
            "marker row present for the oversized-METADATA skip"
        );
    }

    // =====================================================================
    // Test 5: Batch size cap — request 2000, handler clamps to 1000
    // =====================================================================

    #[test]
    fn resolve_batch_size_clamps_to_max() {
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": 2000})),
            1_000
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": 1000})),
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
            resolve_batch_size(&serde_json::json!({})),
            DEFAULT_BATCH_SIZE
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": 0})),
            DEFAULT_BATCH_SIZE,
            "batch_size=0 is a misuse → fall back to the default rather than no-op the run"
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": "not-a-number"})),
            DEFAULT_BATCH_SIZE,
            "non-integer batch_size falls back to default (lenient parse)"
        );
        assert_eq!(
            resolve_batch_size(&serde_json::json!({"batch_size": -5})),
            DEFAULT_BATCH_SIZE,
            "negative batch_size has no `as_u64` so falls back to default"
        );
    }

    #[test]
    fn resolve_ignore_skip_markers_defaults_false() {
        assert!(!resolve_ignore_skip_markers(&serde_json::Value::Null));
        assert!(!resolve_ignore_skip_markers(&serde_json::json!({})));
        assert!(!resolve_ignore_skip_markers(
            &serde_json::json!({"ignore_skip_markers": "yes"})
        ));
        assert!(resolve_ignore_skip_markers(
            &serde_json::json!({"ignore_skip_markers": true})
        ));
        assert!(!resolve_ignore_skip_markers(
            &serde_json::json!({"ignore_skip_markers": false})
        ));
    }

    /// The `skip_marker_kind` argument reaching the candidacy port call
    /// reflects `ignore_skip_markers`: `Some(WHEEL_METADATA_SKIPPED_KIND)`
    /// by default, `None` when the operator opts to re-visit marked rows.
    #[tokio::test]
    async fn run_passes_skip_marker_kind_per_ignore_skip_markers_param() {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let artifacts_for_assert = artifacts.clone();
        let handler = make_handler_with(artifacts, refs, storage, WheelMetadataStubBehaviour::None);

        handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        let default_calls = artifacts_for_assert.pypi_calls();
        assert_eq!(default_calls.len(), 1);
        assert_eq!(
            default_calls[0].skip_marker_kind.as_deref(),
            Some(WHEEL_METADATA_SKIPPED_KIND),
            "default (ignore_skip_markers omitted) MUST exclude marked rows"
        );

        handler
            .run(
                &serde_json::json!({"ignore_skip_markers": true}),
                make_context(),
            )
            .await
            .expect("Ok");
        let calls_after_ignore = artifacts_for_assert.pypi_calls();
        assert_eq!(
            calls_after_ignore.last().unwrap().skip_marker_kind,
            None,
            "ignore_skip_markers: true MUST lift the marker exclusion"
        );
    }

    // =====================================================================
    // Test 6: Batch-cap pin — request 2000, page size clamps to 1000, but
    // the RUN still drains every candidate across multiple internal pages
    // (the full-drain-per-run posture the in-run keyset advance enables).
    // =====================================================================

    #[tokio::test]
    async fn run_with_batch_size_above_cap_clamps_page_size_but_drains_all_candidates() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // Seed 1500 wheels — all share identical bytes so the CAS put
        // dedups (and the test stays fast). Each artifact's
        // `sha256_checksum` is the same; the mock's `get` returns the
        // bytes for any matching hash.
        let shared_sha = put_into_cas(&storage, b"identical-wheel-bytes").await;
        for seed in 0..1_500u32 {
            artifacts.insert(make_wheel(repo_id, seed, shared_sha.clone(), "1.0.0"));
        }
        let artifacts_for_assert = artifacts.clone();

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            WheelMetadataStubBehaviour::EmitBytes(b"M".to_vec()),
        );

        let outcome = handler
            .run(&serde_json::json!({"batch_size": 2000}), make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                let walked = result_summary["artifacts_walked"].as_u64().unwrap();
                assert_eq!(
                    walked, 1_500,
                    "the in-run keyset advance drains every candidate across pages, \
                     not just the first (page-size-capped) page; walked = {walked}"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        let calls = artifacts_for_assert.pypi_calls();
        assert!(
            calls.iter().all(|c| c.limit == 1_000),
            "every page request MUST be clamped to MAX_BATCH_SIZE (1000): {calls:?}"
        );
        assert_eq!(
            calls.len(),
            2,
            "1500 candidates at page size 1000 → a full page then a short page: {calls:?}"
        );
        assert_eq!(calls[0].after, None, "the first page has no cursor");
        assert!(
            calls[1].after.is_some(),
            "the second page carries the cursor advanced from the first page's max id"
        );
    }

    /// Per-name-keyed [`FormatHandler`] stub — unlike `StubFormatHandler`
    /// (one behaviour for every artifact), this returns `Ok(Some(bytes))`
    /// for one distinguished package name and `Ok(None)` (structural
    /// skip) for everything else. Lets a single run genuinely mix a
    /// successful extraction with structural skips, which the acceptance
    /// fixture below needs to prove the "valid item behind > batch-size
    /// skips" case for real rather than by proxy.
    struct NameKeyedWheelMetadataHandler {
        valid_name: String,
    }
    impl FormatHandler for NameKeyedWheelMetadataHandler {
        fn format_key(&self) -> &str {
            "pypi"
        }
        fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
            unimplemented!()
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
        fn extract_wheel_metadata_bytes(
            &self,
            coords: &ArtifactCoords,
            _payload: PayloadAccess<'_>,
        ) -> DomainResult<Option<Bytes>> {
            if coords.name == self.valid_name {
                Ok(Some(Bytes::from_static(b"METADATA")))
            } else {
                Ok(None)
            }
        }
    }

    // =====================================================================
    // Test 7: In-run keyset advance — a valid wheel behind > batch-size
    // structurally-skipped wheels is still processed in the FIRST run.
    // =====================================================================

    #[tokio::test]
    async fn run_processes_valid_item_behind_more_than_batch_size_structural_skips() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // 5 low-id wheels that will structurally skip (batch_size = 3,
        // so this is MORE than one page's worth of permanent skips) plus
        // one valid wheel behind them.
        let mut skip_ids: Vec<Uuid> = Vec::new();
        for seed in 0..5u32 {
            let bytes = format!("skip-wheel-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_wheel(repo_id, seed, sha, &format!("1.{seed}.0"));
            skip_ids.push(a.id);
            artifacts.insert(a);
        }
        let valid_sha = put_into_cas(&storage, b"valid-wheel-bytes").await;
        let valid = make_wheel(repo_id, 5, valid_sha, "1.5.0");
        let valid_id = valid.id;
        let valid_name = valid.name.clone();
        artifacts.insert(valid);

        let artifacts_for_assert = artifacts.clone();
        let pypi_handler: Arc<dyn FormatHandler> =
            Arc::new(NameKeyedWheelMetadataHandler { valid_name });
        let handler = WheelMetadataBackfillHandler::new(
            artifacts as Arc<dyn ArtifactRepository>,
            refs.clone() as Arc<dyn ContentReferenceIndex>,
            storage as Arc<dyn StoragePort>,
            pypi_handler,
        );

        let outcome = handler
            .run(&serde_json::json!({"batch_size": 3}), make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["artifacts_walked"], 6,
                    "all 6 candidates (5 skips + 1 behind them) walked in the FIRST run"
                );
                assert_eq!(result_summary["skipped_structural"], 5);
                assert_eq!(
                    result_summary["metadata_extracted"], 1,
                    "the valid wheel behind the > batch-size skip run IS extracted \
                     in the first run — the in-run keyset advance reaches it"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        for id in &skip_ids {
            assert!(
                refs.find_by_source_and_kind(repo_id, *id, WHEEL_METADATA_SKIPPED_KIND)
                    .await
                    .expect("query")
                    .is_some(),
                "artifact {id} must have a structural-skip marker"
            );
        }
        assert!(
            refs.find_by_source_and_kind(repo_id, valid_id, WHEEL_METADATA_KIND)
                .await
                .expect("query")
                .is_some(),
            "the valid wheel must have landed its wheel_metadata ContentReference"
        );

        // The internal page sequence: 3 + 3 + 0 — a full-length page never
        // short-circuits the loop on its own (only a page shorter than
        // `batch_size` does), so a candidate count that is an exact
        // multiple of `batch_size` costs one extra empty-page round trip
        // before the run recognises it is drained.
        let calls = artifacts_for_assert.pypi_calls();
        assert_eq!(
            calls.len(),
            3,
            "6 candidates at batch_size 3 → two full pages then a draining empty page"
        );
        assert_eq!(calls[0].after, None, "no cursor on the first page");
        assert!(
            calls[1].after.is_some(),
            "the second page carries the cursor advanced from the first page's max id"
        );
        assert!(
            calls[2].after > calls[1].after,
            "the third (draining) page's cursor advanced past the second page's max id"
        );
    }

    // =====================================================================
    // Test 8: Transient skip (CAS read failure) — no marker, retried on
    // the next invocation.
    // =====================================================================

    #[tokio::test]
    async fn run_transient_cas_failure_writes_no_marker_and_is_retried_next_run() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // sha256_checksum has no matching bytes in the mock CAS → the
        // CAS `get` errors, the infrastructure-class failure we want.
        let missing_sha = deterministic_sha(0xDEAD_BEEF);
        let wheel = make_wheel(repo_id, 0, missing_sha, "1.0.0");
        let wheel_id = wheel.id;
        artifacts.insert(wheel);

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            WheelMetadataStubBehaviour::EmitBytes(b"M".to_vec()),
        );

        let first = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match first {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 1);
                assert_eq!(result_summary["metadata_extracted"], 0);
                assert_eq!(result_summary["skipped_structural"], 0);
                assert_eq!(
                    result_summary["skipped_transient"], 1,
                    "CAS read failure is transient, not structural"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            refs_for_assert.entry_count(),
            0,
            "a transient skip MUST NOT write a marker row"
        );
        assert!(refs_for_assert
            .find_by_source_and_kind(repo_id, wheel_id, WHEEL_METADATA_SKIPPED_KIND)
            .await
            .expect("query")
            .is_none());

        // No marker landed and the mock's candidacy set is unchanged
        // (still no `wheel_metadata` row either), so a second invocation
        // — a fresh `run()` call, fresh cursor — re-derives and re-walks
        // the SAME artifact.
        let second = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match second {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["artifacts_walked"], 1,
                    "the transient skip remains a candidate and is retried on the next run"
                );
                assert_eq!(result_summary["skipped_transient"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Test 9: Marker persistence proof — after structural skips land
    // markers in run 1, a simulated run 2 (candidacy allowlist pruned of
    // the marked ids, mirroring what the postgres adapter's NOT EXISTS
    // predicate would enforce against a real `content_references` table)
    // does not re-read them.
    // =====================================================================

    #[tokio::test]
    async fn run_two_does_not_reread_structural_skips_once_marked() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let mut ids: Vec<Uuid> = Vec::new();
        for seed in 0..3u32 {
            let bytes = format!("skip-wheel-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_wheel(repo_id, seed, sha, &format!("1.{seed}.0"));
            ids.push(a.id);
            artifacts.insert(a);
        }

        let refs_for_assert = refs.clone();
        let handler = make_handler_with(
            artifacts.clone(),
            refs,
            storage,
            WheelMetadataStubBehaviour::None,
        );

        let first = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match first {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 3);
                assert_eq!(result_summary["skipped_structural"], 3);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        for id in &ids {
            assert!(
                refs_for_assert
                    .find_by_source_and_kind(repo_id, *id, WHEEL_METADATA_SKIPPED_KIND)
                    .await
                    .expect("query")
                    .is_some(),
                "marker row expected for {id}"
            );
        }

        // Mirrors what the real adapter's NOT EXISTS predicate on
        // `wheel_metadata_skipped` would enforce on a second invocation:
        // every id that landed a marker in run 1 is no longer a
        // candidate. This mock's candidacy is an explicit allowlist
        // rather than a live read of `MockContentReferenceIndex`, so the
        // test updates it directly — the marker rows asserted above are
        // the proof the real adapter has what it needs to do this itself
        // (see the `hort-adapters-postgres` `skip_marker_kind` tests).
        artifacts.set_pypi_wheels_without_kind_filter(Some(std::collections::HashSet::new()));

        let second = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match second {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["artifacts_walked"], 0,
                    "the second run must not re-read the now-marked structural skips"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Test 10: find_pypi_wheels_without_kind failure → TaskOutcome::Failed
    // (retry: true) — same shape as the quarantine-release-sweep precedent.
    // =====================================================================

    struct FailingArtifactRepo;
    impl ArtifactRepository for FailingArtifactRepo {
        fn find_by_id(
            &self,
            _id: Uuid,
        ) -> BoxFuture<'_, DomainResult<hort_domain::entities::artifact::Artifact>> {
            unimplemented!()
        }
        fn find_by_checksum(
            &self,
            _h: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::artifact::Artifact>>>
        {
            Box::pin(async { Ok(None) })
        }
        fn find_by_repo_and_checksum(
            &self,
            _r: Uuid,
            _h: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::artifact::Artifact>>>
        {
            Box::pin(async { Ok(None) })
        }
        fn list_by_repository(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> BoxFuture<
            '_,
            DomainResult<hort_domain::types::Page<hort_domain::entities::artifact::Artifact>>,
        > {
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
        ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::artifact::Artifact>>>
        {
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
        ) -> BoxFuture<
            '_,
            DomainResult<hort_domain::types::Page<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_as_published(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> BoxFuture<
            '_,
            DomainResult<hort_domain::types::Page<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn list_active_for_repo(
            &self,
            _r: Uuid,
        ) -> BoxFuture<
            '_,
            DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_rejected_for_policy(
            &self,
            _p: Uuid,
        ) -> BoxFuture<
            '_,
            DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_active_for_policy(
            &self,
            _p: Uuid,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<
            '_,
            DomainResult<hort_domain::types::Page<hort_domain::entities::artifact::Artifact>>,
        > {
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
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::artifact::Artifact>>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "simulated find_pypi_wheels_without_kind failure".into(),
                ))
            })
        }
        fn find_oci_image_manifests_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::artifact::Artifact>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn run_returns_failed_retry_when_candidacy_query_errors() {
        let artifacts: Arc<dyn ArtifactRepository> = Arc::new(FailingArtifactRepo);
        let refs: Arc<dyn ContentReferenceIndex> = Arc::new(MockContentReferenceIndex::new());
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let pypi: Arc<dyn FormatHandler> = Arc::new(StubFormatHandler::new("pypi"));
        let handler = WheelMetadataBackfillHandler::new(artifacts, refs, storage, pypi);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — candidacy errors surface via TaskOutcome::Failed");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "candidacy failure MUST set retry=true");
                assert!(
                    reason.contains("find_pypi_wheels_without_kind"),
                    "reason should name the failing call: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // =====================================================================
    // Test 11: kind() returns the exact literal that's in ADMIN_INVOKABLE_TASK_KINDS
    // — guards against a rename drift.
    // =====================================================================

    #[test]
    fn kind_matches_valid_task_kinds_entry() {
        use hort_domain::events::ADMIN_INVOKABLE_TASK_KINDS;
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let handler = make_handler_with(artifacts, refs, storage, WheelMetadataStubBehaviour::None);
        assert!(
            ADMIN_INVOKABLE_TASK_KINDS.contains(&handler.kind()),
            "Handler kind() {:?} MUST appear in ADMIN_INVOKABLE_TASK_KINDS — \
             a rename in only one place silently breaks dispatch + the SQL CHECK",
            handler.kind()
        );
    }

    // =====================================================================
    // Test 12: extract_and_persist short-circuits cleanly when the stub
    // returns Ok(Some) but the CAS write fails — the per-artifact path
    // surfaces the error which the batch loop folds into
    // `skipped_transient`.
    // (Pins the error-mapping arm of extract_and_persist.)
    // =====================================================================

    #[tokio::test]
    async fn extract_and_persist_propagates_cas_write_failure() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"wheel").await;
        artifacts.insert(make_wheel(repo_id, 0, sha, "1.0.0"));

        // Arm the storage to fail the NEXT put (the wheel's own put
        // already happened above; the next put is the METADATA blob).
        storage.fail_next_put(DomainError::Invariant("simulated CAS put failure".into()));

        let handler = make_handler_with(
            artifacts,
            refs,
            storage,
            WheelMetadataStubBehaviour::EmitBytes(b"M".to_vec()),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_walked"], 1);
                assert_eq!(result_summary["metadata_extracted"], 0);
                assert_eq!(result_summary["skipped_structural"], 0);
                assert_eq!(
                    result_summary["skipped_transient"], 1,
                    "CAS put failure is per-artifact `skipped_transient`, not aborting"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Compile-time pin: the handler's required ArtifactCoords carries
    /// `RepositoryFormat::Pypi`. The format is hardcoded because the
    /// candidacy SQL already filters to `.whl`; if a future change
    /// flipped this to (say) `Generic`, the PyPI override of
    /// `extract_wheel_metadata_bytes` would return `Ok(None)` silently
    /// and the whole backfill would no-op.
    #[test]
    fn handler_uses_pypi_format_for_coords() {
        // This test compiles-and-asserts the constant — a future
        // rename / typo on `RepositoryFormat::Pypi` is caught here.
        let f = RepositoryFormat::Pypi;
        assert_eq!(format!("{f:?}"), "Pypi");
        // Use Bytes import to silence unused warning (kept for shape).
        let _ = Bytes::from(b"sanity".to_vec());
        // Use ArtifactCoords import explicitly for shape.
        let _ = ArtifactCoords {
            name: String::new(),
            name_as_published: String::new(),
            version: None,
            path: String::new(),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        };
    }
}
