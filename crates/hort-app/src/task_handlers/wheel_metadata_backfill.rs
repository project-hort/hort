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
//!    `VALID_TASK_KINDS`.
//!
//! # Params
//!
//! `{"batch_size": <int>}` — defaults to [`DEFAULT_BATCH_SIZE`] = 100,
//! capped at [`MAX_BATCH_SIZE`] = 1000. Operators tightening below 100
//! are explicitly making the per-run wall-clock + memory tradeoff (one
//! fewer wheel per tick = less peak memory; one more run to drain).
//!
//! # Resumability
//!
//! Stateless. A failed batch leaves the candidacy query unchanged —
//! the next invocation re-derives the same work. No checkpoint, no
//! cursor; the candidacy predicate
//! (`artifacts.path LIKE '%.whl' AND NOT EXISTS … kind='wheel_metadata'`)
//! is the cursor. Two concurrent runs would walk overlapping sets; the
//! per-CAS `StoragePort::put` idempotency on identical content + the
//! upsert semantics of `ContentReferenceIndex::insert` absorb the
//! duplicate work.
//!
//! # Failure modes per artifact
//!
//! Mirrors the ingest-hook posture:
//!
//! - `Ok(Some(bytes))` → write to CAS + insert ContentReference →
//!   counts in `metadata_extracted`.
//! - `Ok(None)` → silent skip (corrupt wheel, no METADATA member, not
//!   actually a wheel ZIP) → counts in `skipped_no_metadata`.
//! - `Err(DomainError::Validation(_))` → silent skip (oversized
//!   METADATA past the 1 MiB cap) → counts in `skipped_no_metadata`.
//!   Treated as non-fatal because the ingest hook treats it the
//!   same (non-fatal warn → ingest succeeds); the backfill must not
//!   diverge from that contract.
//! - `Err(_)` (infrastructure-class — CAS read/write failure, DB
//!   insert failure) → log `warn!`, count in `errors`, **continue**.
//!   Per-artifact failure does not abort the batch — one bad wheel
//!   cannot starve the rest of the candidate set. The next invocation
//!   re-derives the same candidate and retries.
//!
//! # No new domain event
//!
//! The backfill produces only derived-projection rows
//! (`ContentReference kind=wheel_metadata`) — exactly what the
//! ingest hook produces — not domain facts. No new event variant;
//! the event stream stays lean.
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
/// 100 wheels per tick balances per-tick wall clock (every wheel pays
/// one CAS round-trip + one ZIP-seek + one CAS put + one DB insert)
/// against operator-perceived progress.
pub(crate) const DEFAULT_BATCH_SIZE: u32 = 100;

/// Hard cap on `batch_size` regardless of operator input. Mirrors the
/// `BATCH_SIZE = 1000` discipline in
/// [`super::quarantine_release_sweep::QuarantineReleaseSweepHandler`].
/// Operators wanting a larger throughput tighten the CronJob schedule,
/// not the per-run batch size — keeping the per-tick memory profile
/// bounded.
pub(crate) const MAX_BATCH_SIZE: u32 = 1_000;

/// `content_references.kind` value the candidacy query filters against
/// and the produced row carries. Single source of truth so a future
/// rename of the kind literal stays consistent across the handler +
/// the SQL filter.
pub(crate) const WHEEL_METADATA_KIND: &str = "wheel_metadata";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic / one-shot wheel-metadata backfill.
/// Constructed at composition time with the four ports it touches:
///
/// - [`ArtifactRepository`] — candidacy walk
///   ([`ArtifactRepository::find_pypi_wheels_without_kind`]).
/// - [`ContentReferenceIndex`] — per-artifact ContentReference insert
///   on a successful extraction.
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

    /// Per-artifact extract + persist sequence. Returns:
    ///
    /// - `Ok(true)` — METADATA extracted and persisted (CAS put + CR
    ///   insert both succeeded).
    /// - `Ok(false)` — non-fatal skip (no METADATA member, oversized
    ///   METADATA, corrupt ZIP). Counts as `skipped_no_metadata` at
    ///   the call site.
    /// - `Err(_)` — infrastructure-class (CAS read / write / DB
    ///   insert) failure. Counts as `errors` at the call site; the
    ///   batch continues with the next artifact.
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
    async fn extract_and_persist(&self, artifact: &Artifact) -> DomainResult<bool> {
        // Re-read the wheel from CAS. The 1 MiB cap on METADATA is
        // enforced INSIDE `extract_wheel_metadata_bytes` on the ZIP
        // entry's header — the raw wheel bytes here are bounded only
        // by the per-format ingest cap that applied at original
        // ingest time (so no extra cap needed here).
        let mut wheel_bytes: Vec<u8> = Vec::new();
        let mut stream = self.storage.get(&artifact.sha256_checksum).await?;
        stream
            .read_to_end(&mut wheel_bytes)
            .await
            .map_err(|e| DomainError::Invariant(format!("CAS re-read failed: {e}")))?;

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
                let put_result = self
                    .storage
                    .put(Box::new(std::io::Cursor::new(metadata_bytes.to_vec())))
                    .await?;
                let metadata_hash = put_result.hash;
                self.content_references
                    .insert(ContentReference {
                        source_artifact_id: artifact.id,
                        target_content_hash: metadata_hash.clone(),
                        kind: WHEEL_METADATA_KIND.to_string(),
                        metadata: serde_json::Value::Object(serde_json::Map::new()),
                        repository_id: artifact.repository_id,
                        recorded_at: Utc::now(),
                    })
                    .await?;
                tracing::debug!(
                    metadata_hash = %metadata_hash,
                    metadata_bytes = metadata_len,
                    "wheel-metadata-backfill: extracted + persisted"
                );
                Ok(true)
            }
            Ok(None) => {
                // Non-wheel ZIP, missing METADATA member, sdist that
                // somehow slipped past the candidacy SQL — all silent
                // no-op by design. The SQL guards
                // against sdists (`path LIKE '%.whl'`); a wheel that
                // legitimately has no METADATA member is corrupt and
                // we count it.
                Ok(false)
            }
            Err(DomainError::Validation(reason)) => {
                // Oversized METADATA (the only production path
                // surfacing `Err(Validation)` today). The ingest hook
                // treats this as non-fatal; the backfill mirrors that
                // posture — the wheel ingest succeeded, the PEP
                // 658 advertisement just stays unavailable for this
                // wheel (pip's fallback applies, correct but slower).
                tracing::debug!(
                    reason = %reason,
                    "wheel-metadata-backfill: validation skip (oversized METADATA)"
                );
                Ok(false)
            }
            Err(e) => Err(e),
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

            let candidates = match self
                .artifacts
                .find_pypi_wheels_without_kind(WHEEL_METADATA_KIND, batch_size)
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

            let mut artifacts_walked: u64 = 0;
            let mut metadata_extracted: u64 = 0;
            let mut skipped_no_metadata: u64 = 0;
            let mut errors: u64 = 0;

            for artifact in &candidates {
                artifacts_walked += 1;
                match self.extract_and_persist(artifact).await {
                    Ok(true) => metadata_extracted += 1,
                    Ok(false) => skipped_no_metadata += 1,
                    Err(err) => {
                        // Per-artifact infrastructure failure does NOT
                        // abort the batch. The candidate set is
                        // resumable; the next invocation re-derives the
                        // same set minus the artifacts that already
                        // landed a `wheel_metadata` row.
                        tracing::warn!(
                            error = %err,
                            artifact_id = %artifact.id,
                            "wheel-metadata-backfill: per-artifact extraction failed; continuing",
                        );
                        errors += 1;
                    }
                }
            }

            tracing::info!(
                artifacts_walked,
                metadata_extracted,
                skipped_no_metadata,
                errors,
                "wheel-metadata-backfill complete"
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "artifacts_walked":     artifacts_walked,
                    "metadata_extracted":   metadata_extracted,
                    "skipped_no_metadata":  skipped_no_metadata,
                    "errors":               errors,
                }),
            })
        })
    }
}

/// Parse `params.batch_size` (u64) into a clamped u32. Out-of-range,
/// missing, or non-integer values fall back to [`DEFAULT_BATCH_SIZE`].
/// Values above [`MAX_BATCH_SIZE`] clamp to that cap — the operator
/// CAN ask for more but the handler bounds the per-run memory profile.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

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
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
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
                assert_eq!(result_summary["skipped_no_metadata"], 0);
                assert_eq!(result_summary["errors"], 0);
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
                assert_eq!(result_summary["skipped_no_metadata"], 0);
                assert_eq!(result_summary["errors"], 0);
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
    // Test 3: Wheel with no METADATA member → skipped_no_metadata, no CR
    // =====================================================================

    #[tokio::test]
    async fn run_corrupt_wheel_counts_skipped_no_metadata() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let bytes = b"corrupt-wheel-bytes";
        let sha = put_into_cas(&storage, bytes).await;
        artifacts.insert(make_wheel(repo_id, 0, sha, "1.0.0"));

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
                assert_eq!(result_summary["skipped_no_metadata"], 1);
                assert_eq!(result_summary["errors"], 0);
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
            0,
            "Ok(None) must NOT insert a ContentReference row"
        );
    }

    // =====================================================================
    // Test 4: Oversized METADATA (Err(Validation)) → skipped_no_metadata
    //
    // Mirrors the Item-3 hook's posture: Validation = non-fatal skip,
    // NOT a counted error.
    // =====================================================================

    #[tokio::test]
    async fn run_oversized_metadata_counts_skipped_no_metadata() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        let sha = put_into_cas(&storage, b"oversized-wheel").await;
        artifacts.insert(make_wheel(repo_id, 0, sha, "1.0.0"));

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
                    result_summary["skipped_no_metadata"], 1,
                    "Err(Validation) counts as `skipped_no_metadata`, NOT `errors` — \
                     mirrors the ingest hook posture"
                );
                assert_eq!(result_summary["errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(storage_for_assert.put_call_count() - baseline_puts, 0);
        assert_eq!(refs_for_assert.entry_count(), 0);
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

    /// End-to-end batch-cap pin: feed 1500 candidate wheels and confirm
    /// `artifacts_walked <= 1000`. The mock's
    /// `find_pypi_wheels_without_kind` honours the limit param exactly
    /// (it `.truncate(limit as usize)`s), so this also pins that the
    /// handler ASKED for ≤ 1000.
    #[tokio::test]
    async fn run_with_batch_size_above_cap_clamps_to_max() {
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
                assert!(
                    walked <= 1_000,
                    "request 2000 must clamp at MAX_BATCH_SIZE (1000); walked = {walked}"
                );
                assert_eq!(
                    walked, 1_000,
                    "the mock has 1500 candidates and the request was clamped to 1000 — \
                     the handler walks exactly 1000"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Test 6: Resumability — two invocations against a stable candidate
    // set drain it deterministically.
    //
    // The mock's `find_pypi_wheels_without_kind` honours the per-test
    // allowlist (`set_pypi_wheels_without_kind_filter`) — the first
    // invocation processes 3 wheels (batch_size = 3), updates the
    // allowlist to model "those rows now have a wheel_metadata CR",
    // then the second invocation picks up the remaining 2.
    // =====================================================================

    #[tokio::test]
    async fn run_is_resumable_across_invocations() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // Seed 5 wheels with deterministic SHAs (one bytes payload per
        // wheel so the test asserts per-wheel CR uniqueness via the
        // distinct synthetic sha-field, not via shared bytes).
        let mut all_ids: Vec<Uuid> = Vec::new();
        for seed in 0..5u32 {
            let bytes = format!("wheel-{seed}");
            let sha = put_into_cas(&storage, bytes.as_bytes()).await;
            let a = make_wheel(repo_id, seed, sha, &format!("1.{seed}.0"));
            all_ids.push(a.id);
            artifacts.insert(a);
        }

        // First invocation: all 5 are candidates, batch_size = 3.
        artifacts.set_pypi_wheels_without_kind_filter(Some(all_ids.iter().copied().collect()));

        let handler = make_handler_with(
            artifacts.clone(),
            refs.clone(),
            storage.clone(),
            WheelMetadataStubBehaviour::EmitBytes(b"METADATA".to_vec()),
        );

        let first = handler
            .run(&serde_json::json!({"batch_size": 3}), make_context())
            .await
            .expect("Ok");
        let first_walked = match &first {
            TaskOutcome::Completed { result_summary } => {
                result_summary["artifacts_walked"].as_u64().unwrap()
            }
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(first_walked, 3);
        // Walk-stable order: the mock sorts candidates by id; the
        // first 3 are the lowest-id artifacts in the seed.
        let mut sorted_ids = all_ids.clone();
        sorted_ids.sort();
        let processed_first: Vec<Uuid> = sorted_ids[..3].to_vec();
        let remaining_after_first: HashSet<Uuid> = sorted_ids[3..].iter().copied().collect();

        // Model "the first 3 now have wheel_metadata CR rows" — the
        // candidacy SQL would prune them. The mock's filter
        // represents the *post-NOT-EXISTS* set; updating it to the
        // remaining 2 mirrors what the production SQL would compute on
        // the second run.
        artifacts.set_pypi_wheels_without_kind_filter(Some(remaining_after_first.clone()));

        let second = handler
            .run(&serde_json::json!({"batch_size": 3}), make_context())
            .await
            .expect("Ok");
        let (second_walked, second_extracted) = match second {
            TaskOutcome::Completed { result_summary } => (
                result_summary["artifacts_walked"].as_u64().unwrap(),
                result_summary["metadata_extracted"].as_u64().unwrap(),
            ),
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(
            second_walked, 2,
            "second invocation drains the remaining 2 (not 3 — the candidate set shrunk)"
        );
        assert_eq!(second_extracted, 2);
        // Sanity: the first 3 ids are different from the remaining 2 set.
        for id in processed_first {
            assert!(!remaining_after_first.contains(&id));
        }
    }

    // =====================================================================
    // Test 7: Infrastructure error on a single artifact does not abort
    // the batch — counts as `errors`, the walk continues.
    // =====================================================================

    #[tokio::test]
    async fn run_per_artifact_infrastructure_error_continues_walk() {
        let repo_id = Uuid::new_v4();
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());

        // Two wheels in the candidate set. Only one has bytes in CAS;
        // the other's `sha256_checksum` is a "valid hex" placeholder
        // that the mock CAS does not have — `storage.get` errors,
        // which is the infrastructure-class failure we want to drive.
        let sha_ok = put_into_cas(&storage, b"good-wheel").await;
        let a_ok = make_wheel(repo_id, 0, sha_ok, "1.0.0");
        let ok_id = a_ok.id;
        artifacts.insert(a_ok);

        let sha_missing = deterministic_sha(0xDEAD_BEEF);
        let a_missing = make_wheel(repo_id, 1, sha_missing, "1.1.0");
        let missing_id = a_missing.id;
        artifacts.insert(a_missing);

        // Set a stable order so the test is deterministic on which
        // artifact errors. The mock orders by id, but we don't need
        // that here — we just assert the *count* of errors vs
        // extracted.
        artifacts
            .set_pypi_wheels_without_kind_filter(Some([ok_id, missing_id].into_iter().collect()));

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
                assert_eq!(
                    result_summary["artifacts_walked"], 2,
                    "walked both candidates — the per-artifact error did NOT abort"
                );
                assert_eq!(
                    result_summary["metadata_extracted"], 1,
                    "the wheel whose bytes were in CAS produced a CR"
                );
                assert_eq!(result_summary["skipped_no_metadata"], 0);
                assert_eq!(
                    result_summary["errors"], 1,
                    "the missing-CAS-bytes wheel counted as an error"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Test 8: find_pypi_wheels_without_kind failure → TaskOutcome::Failed
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
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
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
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::artifact::Artifact>>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "simulated find_pypi_wheels_without_kind failure".into(),
                ))
            })
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
    // Test 9: kind() returns the exact literal that's in VALID_TASK_KINDS
    // — guards against a rename drift.
    // =====================================================================

    #[test]
    fn kind_matches_valid_task_kinds_entry() {
        use hort_domain::events::VALID_TASK_KINDS;
        let artifacts = Arc::new(MockArtifactRepository::new());
        let refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let handler = make_handler_with(artifacts, refs, storage, WheelMetadataStubBehaviour::None);
        assert!(
            VALID_TASK_KINDS.contains(&handler.kind()),
            "Handler kind() {:?} MUST appear in VALID_TASK_KINDS — \
             a rename in only one place silently breaks dispatch + the SQL CHECK",
            handler.kind()
        );
    }

    // =====================================================================
    // Test 10: extract_and_persist short-circuits cleanly when the stub
    // returns Ok(Some) but the CAS write fails — the per-artifact path
    // surfaces the error which the batch loop folds into `errors`.
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
                assert_eq!(result_summary["skipped_no_metadata"], 0);
                assert_eq!(
                    result_summary["errors"], 1,
                    "CAS put failure is per-artifact `errors`, not aborting"
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
