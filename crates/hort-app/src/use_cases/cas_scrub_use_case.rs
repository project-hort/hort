//! CAS integrity scrubber use case.
//!
//! Walks every blob in the CAS via [`StoragePort::list_all`], re-hashes the
//! bytes via streaming SHA-256, and compares against the CAS key. Emits
//! [`CasIntegrityMismatch`] events + metrics on every mismatch.
//!
//! **Action on mismatch**: operators choose
//! between flag-only [`ActionOnMismatch::Alert`] (the default; the
//! "operator decides the response" posture) and
//! [`ActionOnMismatch::Tombstone`] which additionally emits an
//! [`ArtifactCorrupted`] event and transitions the artifact to
//! `quarantine_status = 'rejected'` via the existing quarantine state
//! machine. Tombstone reuses the existing `Rejected` vocabulary rather
//! than introducing a new state.
//!
//! **Inbound adapter: `hort-server` `scrub` CLI subcommand only.** No HTTP
//! handler may drive this. The scrubber runs as a one-shot cron job: it
//! lists tens of thousands of blobs, issues one `get()` per blob, and
//! runs for minutes. That shape does not fit a web request.
//!
//! **Hex-onion discipline.** Business logic lives here; the CLI
//! parses arguments and maps the report to an exit code. No DB or file
//! I/O leaks into the CLI module.

use std::sync::Arc;

use chrono::Utc;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tracing::{info, warn};
use uuid::Uuid;

use hort_domain::error::DomainError;
use hort_domain::events::{
    system_actor, CasIntegrityMismatch, DomainEvent, StreamCategory, StreamId,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::storage::{StoragePort, StreamItem};
use hort_domain::types::ContentHash;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{labels, CasScrubResult};

/// Per-item outcome of the streaming consume loop.
///
/// `Skipped` is returned for sampled-out hashes (no metric, no count).
/// `Counted(result)` rolls into the per-result counters on the report.
/// `ShardTruncated` is the streaming source's signal that a whole
/// directory was abandoned after the per-step retry — it rolls into
/// `report.shards_truncated`, not `report.read_errors`.
enum ItemOutcome {
    Skipped,
    Counted(CasScrubResult),
    ShardTruncated,
}

/// Streaming-read buffer size (64 KB).
const CHUNK_SIZE: usize = 64 * 1024;

/// What the scrubber does when it finds a hash mismatch.
///
/// `Alert` (the default) is the flag-only response: emit
/// [`CasIntegrityMismatch`] + tracing warn + metric, and leave the artifact
/// row alone. The operator decides the response.
///
/// `Tombstone` additionally locates the artifact row by content hash via
/// [`ArtifactRepository::find_by_checksum`], transitions it through the
/// existing quarantine state machine to
/// [`QuarantineStatus::Rejected`](hort_domain::entities::artifact::QuarantineStatus::Rejected)
/// via [`Artifact::tombstone_from_corruption`](hort_domain::entities::artifact::Artifact::tombstone_from_corruption),
/// and emits an [`ArtifactCorrupted`] event on the artifact stream
/// alongside the persisted state change via
/// [`ArtifactLifecyclePort::commit_transition`]. Subsequent reads via
/// `ArtifactUseCase::download` see the rejected status and return the
/// existing quarantine error — no new admin surface, no new error path.
///
/// Default is `Alert` per the design-doc rationale: the audit named both
/// options as valid; default-alert preserves backwards compatibility
/// within the v2 RC stream so existing operators expecting flag-only
/// behaviour are not surprised by a deploy-time policy shift.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ActionOnMismatch {
    /// Flag-only: emit `CasIntegrityMismatch` and let the operator
    /// decide. The blob remains readable on subsequent `get()` calls
    /// (the read-time `VerifyingReader` will of course also flag it,
    /// but the artifact's `quarantine_status` is unchanged).
    #[default]
    Alert,
    /// Tombstone: emit `CasIntegrityMismatch` AND
    /// [`ArtifactCorrupted`], and transition the artifact to
    /// `quarantine_status = 'rejected'` so subsequent download
    /// attempts are blocked at the application layer.
    Tombstone,
}

impl ActionOnMismatch {
    /// Lower-case string label for tracing / metric labels. Lives on the
    /// type so the same identifier is used at the `tracing::warn!` and
    /// any future metric label without drift.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Tombstone => "tombstone",
        }
    }
}

/// Configuration for a single scrub run.
///
/// - `concurrency` caps the number of in-flight re-hash tasks. The
///   scrubber fans out via `buffer_unordered(concurrency)`; 1 runs
///   strictly sequentially (used by tests that need deterministic
///   metric ordering), values in the low tens are reasonable for
///   production.
/// - `sample_fraction` is the probability, per listed hash, that the
///   blob is re-hashed at all. `1.0` scrubs every blob; `0.1` hits
///   roughly one in ten. **Skipped hashes are not counted** (no
///   increment, no event, no line in the `ScrubReport`). Operators
///   who want a constant-time daily check use a small fraction; audit
///   runs use `1.0`.
/// - `action_on_mismatch` is the operator-chosen response when the
///   scrubber finds a hash mismatch. Defaults to
///   [`ActionOnMismatch::Alert`] (flag-only);
///   `Tombstone` opts in to the auto-block via
///   `HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone`.
#[derive(Debug, Clone)]
pub struct ScrubOpts {
    pub concurrency: usize,
    pub sample_fraction: f64,
    pub action_on_mismatch: ActionOnMismatch,
}

impl ScrubOpts {
    /// Defaults used by the CLI when the operator omits both flags.
    pub fn defaults() -> Self {
        Self {
            concurrency: 4,
            sample_fraction: 1.0,
            action_on_mismatch: ActionOnMismatch::Alert,
        }
    }
}

/// Summary of one scrub run. The CLI maps `mismatches == 0` → exit 0,
/// non-zero otherwise. `missing`, `read_errors`, and `shards_truncated`
/// are observability-only counts; they are already surfaced via the
/// metric and the tracing log line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrubReport {
    /// Total number of hashes the scrubber actually re-hashed. Sampling
    /// subtracts from this — a run with `sample_fraction=0.1` over a
    /// CAS of 10 000 blobs reports roughly 1 000 checked.
    pub checked: u64,
    /// Hashes whose re-computed SHA-256 differed from the CAS key.
    pub mismatches: u64,
    /// Hashes that appeared in `list_all` but whose `get()` returned
    /// `NotFound` (concurrent GC, racing delete, inconsistent listing).
    pub missing: u64,
    /// Hashes for which either `list_all` yielded a `ReadError` or the
    /// streaming read from `get()` failed mid-flight.
    pub read_errors: u64,
    /// Shards that the streaming walk gave up on after the per-step
    /// retry was exhausted. Each shard skipped
    /// after retry contributes 1 here. Distinct from `read_errors`,
    /// which counts per-blob failures; `shards_truncated` counts whole
    /// directories the scrub never finished traversing — operators
    /// reading a non-zero value know the scrub output is partial.
    pub shards_truncated: u64,
}

/// Decide at random whether to keep this hash under the sampling rule.
///
/// Factored out so the tests can mock it — the production path uses
/// `rand::random::<f64>()`. We keep the trait object out of
/// `ScrubOpts` because every production caller wants the same
/// randomness source and the only test that exercises sampling sets
/// `sample_fraction` to boundary values (0.0, 1.0).
fn default_sampler(fraction: f64) -> bool {
    if fraction >= 1.0 {
        return true;
    }
    if fraction <= 0.0 {
        return false;
    }
    rand::random::<f64>() < fraction
}

/// Orchestrates the scrub walk + event/metric emission.
///
/// Holds `Arc<dyn StoragePort>` + `Arc<dyn EventStore>`; both ports come
/// from the same composition root the server uses. The CLI does NOT
/// construct its own adapter instances in isolation — it reuses the
/// server's storage/event-store builders so a scrub against a
/// misconfigured backend fails in the same way the server's first
/// request would.
///
/// `artifacts` + `lifecycle` are optional and only consulted when
/// [`ScrubOpts::action_on_mismatch`] is [`ActionOnMismatch::Tombstone`].
/// When `Tombstone` is selected without
/// these ports wired, the scrubber falls back to alert-mode for the
/// affected hash and emits a tracing warn — the configuration error is
/// surfaced at the per-mismatch site rather than at construction so a
/// misconfigured chart deploy does not block scrub runs entirely on
/// blobs with no hash mismatches at all.
pub struct CasScrubUseCase {
    storage: Arc<dyn StoragePort>,
    events: Arc<EventStorePublisher>,
    artifacts: Option<Arc<dyn ArtifactRepository>>,
    lifecycle: Option<Arc<dyn ArtifactLifecyclePort>>,
}

impl CasScrubUseCase {
    /// Construct a scrub use case wired for [`ActionOnMismatch::Alert`]
    /// only. Existing callers that don't intend to opt into tombstone
    /// mode use this; they get the flag-only behaviour verbatim.
    pub fn new(storage: Arc<dyn StoragePort>, events: Arc<EventStorePublisher>) -> Self {
        Self {
            storage,
            events,
            artifacts: None,
            lifecycle: None,
        }
    }

    /// Wire the artifact-lookup + lifecycle ports needed for
    /// [`ActionOnMismatch::Tombstone`].
    /// Builder-style so existing call sites stay one expression. The
    /// server CLI calls this when
    /// `HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone` is set.
    #[must_use]
    pub fn with_artifact_lifecycle(
        mut self,
        artifacts: Arc<dyn ArtifactRepository>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
    ) -> Self {
        self.artifacts = Some(artifacts);
        self.lifecycle = Some(lifecycle);
        self
    }

    /// Run a scrub with `opts`. Returns a [`ScrubReport`]. Always walks
    /// to completion — per-blob errors do not terminate the scan.
    ///
    /// The concurrency knob uses `futures::StreamExt::buffer_unordered`,
    /// which pre-buffers up to `concurrency` outstanding futures. That's
    /// fine for IO-bound re-hashing: with a typical 10 MiB artifact at
    /// 1 Gbps it's network-bound, not CPU-bound, so `spawn_blocking` is
    /// unnecessary (and would dedicate blocking threads to hashing that
    /// a properly-sized buffer pool already handles).
    pub async fn run(&self, opts: ScrubOpts) -> AppResult<ScrubReport> {
        self.run_with_sampler(opts, default_sampler).await
    }

    /// Test seam: same as [`run`] but with a pluggable sampler. Used by
    /// unit tests to exercise the sampling boundaries deterministically.
    pub async fn run_with_sampler<F>(&self, opts: ScrubOpts, sampler: F) -> AppResult<ScrubReport>
    where
        F: Fn(f64) -> bool + Send + Sync + 'static,
    {
        let backend = self.storage.backend_label();
        let concurrency = opts.concurrency.max(1);
        let sample_fraction = opts.sample_fraction;
        let action = opts.action_on_mismatch;

        info!(
            backend,
            concurrency,
            sample_fraction,
            action = action.as_str(),
            "cas scrub starting"
        );

        let stream = self.storage.list_all().await?;

        // Convert each `StreamItem` into an outcome. `Hash` → dispatch a
        // re-hash; `ReadError` → emit immediately and carry the outcome.
        // `buffer_unordered(concurrency)` drives the fan-out — each
        // future is independent + self-contained.
        let storage = Arc::clone(&self.storage);
        let events = Arc::clone(&self.events);
        let artifacts = self.artifacts.clone();
        let lifecycle = self.lifecycle.clone();
        let sampler = Arc::new(sampler);

        let per_item = stream.map(move |item| {
            let storage = Arc::clone(&storage);
            let events = Arc::clone(&events);
            let artifacts = artifacts.clone();
            let lifecycle = lifecycle.clone();
            let sampler = Arc::clone(&sampler);
            async move {
                match item {
                    StreamItem::Hash(hash) => {
                        if !sampler(sample_fraction) {
                            // Skipped by sampling; do not count, do not
                            // emit a metric, do not log.
                            return ItemOutcome::Skipped;
                        }
                        let outcome = check_one_hash(
                            storage.as_ref(),
                            events.as_ref(),
                            artifacts.as_deref(),
                            lifecycle.as_deref(),
                            &hash,
                            backend,
                            action,
                        )
                        .await;
                        ItemOutcome::Counted(outcome)
                    }
                    StreamItem::ReadError { key, err } => {
                        warn!(
                            backend,
                            key = %key,
                            error = %err,
                            "cas scrub list read_error"
                        );
                        emit_metric(backend, CasScrubResult::ReadError);
                        ItemOutcome::Counted(CasScrubResult::ReadError)
                    }
                    StreamItem::ShardTruncated { key, err } => {
                        // The streaming source abandoned an entire
                        // shard after its per-step retry was exhausted.
                        // We surface this as a
                        // distinct `shards_truncated` count on the
                        // report so the operator sees the scrub output
                        // is partial; the per-item metric still emits
                        // `read_error` for catalog continuity (no new
                        // metric label introduced — see metrics
                        // catalog).
                        warn!(
                            backend,
                            key = %key,
                            error = %err,
                            "cas scrub shard truncated after retry"
                        );
                        emit_metric(backend, CasScrubResult::ReadError);
                        ItemOutcome::ShardTruncated
                    }
                }
            }
        });

        // `buffer_unordered` requires the stream item type to be `Unpin`;
        // `Pin<Box<dyn Future>>` is Unpin. Box the futures explicitly so
        // the compiler resolves unambiguously. We consume the stream
        // incrementally — `next().await` per outcome — without
        // pre-materialising into a `Vec`, preserving the streaming
        // memory shape the source `walk_cas_tree` now provides.
        let mut buffered = per_item
            .map(|fut| {
                Box::pin(fut) as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
            })
            .buffer_unordered(concurrency);

        let mut report = ScrubReport::default();
        while let Some(outcome) = buffered.next().await {
            match outcome {
                ItemOutcome::Skipped => (), // sampled out
                ItemOutcome::Counted(CasScrubResult::Ok) => report.checked += 1,
                ItemOutcome::Counted(CasScrubResult::HashMismatch) => {
                    report.checked += 1;
                    report.mismatches += 1;
                }
                ItemOutcome::Counted(CasScrubResult::Missing) => {
                    report.checked += 1;
                    report.missing += 1;
                }
                ItemOutcome::Counted(CasScrubResult::ReadError) => {
                    // ReadError paths are counted but not "checked" in the
                    // strictest sense — the re-hash did not produce an
                    // attestation. We still surface them via
                    // `read_errors`, leaving `checked` as the count of
                    // blobs that made it through the re-hash pipeline.
                    report.read_errors += 1;
                }
                ItemOutcome::ShardTruncated => {
                    // Whole-shard skip — accounted separately so the
                    // CLI / dashboards can distinguish individual blob
                    // failures from "the walker gave up on a shard."
                    report.shards_truncated += 1;
                }
            }
        }

        info!(
            backend,
            checked = report.checked,
            mismatches = report.mismatches,
            missing = report.missing,
            read_errors = report.read_errors,
            shards_truncated = report.shards_truncated,
            "cas scrub complete"
        );

        Ok(report)
    }
}

/// Re-hash a single blob. Emits the per-hash metric + (on mismatch) the
/// `CasIntegrityMismatch` event + a `tracing::warn!`. When `action` is
/// [`ActionOnMismatch::Tombstone`] AND `artifacts` + `lifecycle` are
/// wired, additionally locates the artifact row and transitions it to
/// `quarantine_status = 'rejected'` via
/// [`ArtifactLifecyclePort::commit_transition`], emitting an
/// [`ArtifactCorrupted`] event on the artifact stream alongside the
/// state change. Returns the classified outcome for the caller's
/// report rollup.
async fn check_one_hash(
    storage: &dyn StoragePort,
    events: &dyn EventStore,
    artifacts: Option<&dyn ArtifactRepository>,
    lifecycle: Option<&dyn ArtifactLifecyclePort>,
    hash: &ContentHash,
    backend: &'static str,
    action: ActionOnMismatch,
) -> CasScrubResult {
    let reader = match storage.get(hash).await {
        Ok(r) => r,
        Err(DomainError::NotFound { .. }) => {
            warn!(
                backend,
                content_hash = %hash,
                "cas scrub missing blob"
            );
            emit_metric(backend, CasScrubResult::Missing);
            return CasScrubResult::Missing;
        }
        Err(err) => {
            warn!(
                backend,
                content_hash = %hash,
                error = %err,
                "cas scrub get failed"
            );
            emit_metric(backend, CasScrubResult::ReadError);
            return CasScrubResult::ReadError;
        }
    };

    match stream_sha256(reader).await {
        Ok(observed) => {
            if observed == *hash {
                emit_metric(backend, CasScrubResult::Ok);
                CasScrubResult::Ok
            } else {
                // The `action` field is the configured response, so log
                // shippers can distinguish an alert deployment
                // from a tombstone deployment without parsing
                // the deployment env.
                //
                // No `artifact_id = tracing::field::Empty` field — `Empty`
                // is meaningful only on spans (later filled via
                // `Span::current().record(...)`), but `warn!` creates
                // an event, not a span. The artifact_id is also not
                // known at this site (the function receives the
                // content_hash; artifact lookup happens in the caller
                // and the matching tombstone path emits its own
                // tracing line with `artifact_id` in scope).
                warn!(
                    backend,
                    computed_hash = %observed,
                    expected_hash = %hash,
                    action = action.as_str(),
                    "CAS integrity mismatch"
                );
                emit_metric(backend, CasScrubResult::HashMismatch);
                // Fire-and-log on event-store failures — the scrub run
                // continues. An event-store outage during a scrub
                // should not abort the sweep; the metric + tracing are
                // the primary observability, the event is the durable
                // audit trail.
                if let Err(err) = emit_mismatch_event(events, hash, &observed, backend).await {
                    warn!(
                        backend,
                        content_hash = %hash,
                        error = %err,
                        "failed to append CasIntegrityMismatch event; metric and tracing still emitted"
                    );
                }
                if action == ActionOnMismatch::Tombstone {
                    if let Err(err) =
                        try_tombstone_artifact(artifacts, lifecycle, hash, &observed, backend).await
                    {
                        warn!(
                            backend,
                            content_hash = %hash,
                            error = %err,
                            "tombstone-on-mismatch failed; CasIntegrityMismatch still emitted"
                        );
                    }
                }
                CasScrubResult::HashMismatch
            }
        }
        Err(err) => {
            // Note: the adapter's `VerifyingReader` surfaces integrity
            // failures as `io::ErrorKind::InvalidData`. Those land here
            // as a `ReadError`, NOT a `HashMismatch`, because the scrub
            // can't assert the observed hash — the inner reader
            // short-circuited and we don't have a clean digest.
            // Operators cross-reference with
            // `hort_storage_integrity_failures_total` which DID fire.
            warn!(
                backend,
                content_hash = %hash,
                error = %err,
                "cas scrub read failed"
            );
            emit_metric(backend, CasScrubResult::ReadError);
            CasScrubResult::ReadError
        }
    }
}

/// Stream bytes through a SHA-256 hasher and return the resulting
/// `ContentHash`. Memory-bounded at `CHUNK_SIZE` bytes.
async fn stream_sha256(
    mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
) -> Result<ContentHash, std::io::Error> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hex = format!("{:x}", hasher.finalize());
    hex.parse::<ContentHash>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SHA-256 produced invalid hex: {e}"),
        )
    })
}

/// Append a `CasIntegrityMismatch` event to a per-hash synthetic stream.
///
/// Stream: `StreamCategory::Artifact` (reuses the existing category — the
/// event is about a CAS blob; `Artifact` is the closest match and
/// `stream_category` is a `TEXT` column so a new category is not needed
/// by the domain, only by the category-read projections). Entity id:
/// derived deterministically from the content hash so repeat scrubs of
/// the same tampered blob append to the same stream and form an
/// auditable history without inflating the stream count.
async fn emit_mismatch_event(
    events: &dyn EventStore,
    content_hash: &ContentHash,
    observed_hash: &ContentHash,
    backend: &'static str,
) -> AppResult<()> {
    let stream_id = StreamId {
        category: StreamCategory::Artifact,
        entity_id: uuid_from_content_hash(content_hash),
    };
    // We don't read-before-write here: the mismatch is an audit fact;
    // concurrent appends from other sources would race, but
    // `ExpectedVersion::Any` accepts any current position — there is
    // no invariant we need to enforce across scrub-generated events.
    events
        .append(AppendEvents {
            stream_id,
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::CasIntegrityMismatch(
                CasIntegrityMismatch {
                    content_hash: content_hash.clone(),
                    backend: backend.to_string(),
                    observed_hash: observed_hash.clone(),
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
        })
        .await
        .map_err(|e| AppError::EventStore(format!("append CasIntegrityMismatch: {e}")))?;
    Ok(())
}

/// Tombstone an artifact whose CAS content failed re-verification.
/// Locates the artifact row by content
/// hash, transitions it through
/// [`Artifact::tombstone_from_corruption`](hort_domain::entities::artifact::Artifact::tombstone_from_corruption),
/// and persists the state change + the [`ArtifactCorrupted`] event in
/// one transaction via [`ArtifactLifecyclePort::commit_transition`].
///
/// Returns `Ok(())` on:
/// - successful tombstone,
/// - "artifact not found" (orphan blob with no matching row — the
///   `CasIntegrityMismatch` event is the only audit trail in that case),
/// - "artifact already rejected" (idempotent skip — duplicate event
///   would only confuse audit consumers).
///
/// Returns `Err(_)` on:
/// - `artifacts` / `lifecycle` ports unwired (operator opted into
///   `Tombstone` without fully wiring the use case — surfaces as a
///   tracing warn so the misconfiguration is loud at the per-mismatch
///   site rather than silent).
/// - any event-store / DB error from `commit_transition` (the scrub
///   run continues; the per-blob warn is the operational signal).
async fn try_tombstone_artifact(
    artifacts: Option<&dyn ArtifactRepository>,
    lifecycle: Option<&dyn ArtifactLifecyclePort>,
    expected_hash: &ContentHash,
    computed_hash: &ContentHash,
    backend: &'static str,
) -> AppResult<()> {
    let artifacts = artifacts.ok_or_else(|| {
        AppError::External(
            "tombstone-on-mismatch enabled but ArtifactRepository port not wired".to_string(),
        )
    })?;
    let lifecycle = lifecycle.ok_or_else(|| {
        AppError::External(
            "tombstone-on-mismatch enabled but ArtifactLifecyclePort port not wired".to_string(),
        )
    })?;

    let Some(mut artifact) = artifacts.find_by_checksum(expected_hash).await? else {
        // Orphan blob — content exists in CAS but no `artifacts`
        // row references it. Common after a failed ingest commits
        // bytes but not the row, or after a row was hard-deleted
        // separately. The `CasIntegrityMismatch` event already
        // landed; nothing more we can transition.
        warn!(
            backend,
            content_hash = %expected_hash,
            "tombstone skipped: no artifact row references this content hash"
        );
        return Ok(());
    };

    let event = match artifact.tombstone_from_corruption(computed_hash.clone(), Utc::now()) {
        Ok(e) => e,
        Err(err) => {
            // Already-rejected (or some future state-machine
            // restriction) — idempotent skip. The event log already
            // carries the `ArtifactCorrupted` from the prior scrub
            // iteration that first tombstoned this artifact; emitting
            // again would only inflate the stream.
            warn!(
                backend,
                content_hash = %expected_hash,
                artifact_id = %artifact.id,
                error = %err,
                "tombstone skipped: state machine refused transition (likely already rejected)"
            );
            return Ok(());
        }
    };

    let stream_id = StreamId::artifact(artifact.id);
    lifecycle
        .commit_transition(
            &artifact,
            AppendEvents {
                stream_id,
                expected_version: ExpectedVersion::Any,
                events: vec![EventToAppend::new(DomainEvent::ArtifactCorrupted(event))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            },
            None, // tombstone never overwrites ingest-time metadata
        )
        .await
        .map_err(AppError::Domain)?;

    info!(
        backend,
        artifact_id = %artifact.id,
        content_hash = %expected_hash,
        "artifact tombstoned after CAS integrity mismatch"
    );

    Ok(())
}

/// Derive a deterministic `Uuid` from a `ContentHash`.
///
/// The hash is 64 hex characters; we take the first 32 and parse as a
/// u128 pair. Collisions between two distinct hashes are astronomically
/// unlikely at the 128-bit prefix level — sufficient for streaming-id
/// granularity. Determinism matters so repeat scrubs target the same
/// stream.
fn uuid_from_content_hash(hash: &ContentHash) -> Uuid {
    let s: &str = hash.as_ref();
    // `ContentHash` is 64 hex chars; first 32 is 16 bytes. Parse in
    // pairs so we don't depend on any specific hex-decoding crate.
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        let off = i * 2;
        *b = u8::from_str_radix(&s[off..off + 2], 16).unwrap_or(0);
    }
    Uuid::from_bytes(bytes)
}

/// Emit the `hort_cas_scrub_checks_total{backend, result}` counter.
fn emit_metric(backend: &'static str, result: CasScrubResult) {
    metrics::counter!(
        "hort_cas_scrub_checks_total",
        labels::BACKEND => backend,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::capture_metrics;
    use crate::use_cases::test_support::{
        sample_artifact, MockArtifactLifecycle, MockArtifactRepository, MockEventStore,
        MockStoragePort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;

    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn hash(hex: &str) -> ContentHash {
        hex.parse().unwrap()
    }

    fn make_case() -> (CasScrubUseCase, Arc<MockStoragePort>, Arc<MockEventStore>) {
        let storage = Arc::new(MockStoragePort::new());
        storage.set_backend_label("filesystem");
        let events = Arc::new(MockEventStore::new());
        let uc = CasScrubUseCase::new(
            storage.clone() as Arc<dyn StoragePort>,
            crate::event_store_publisher::wrap_for_test(events.clone()),
        );
        (uc, storage, events)
    }

    fn opts_sequential() -> ScrubOpts {
        ScrubOpts {
            concurrency: 1,
            sample_fraction: 1.0,
            action_on_mismatch: ActionOnMismatch::Alert,
        }
    }

    fn opts_sequential_tombstone() -> ScrubOpts {
        ScrubOpts {
            concurrency: 1,
            sample_fraction: 1.0,
            action_on_mismatch: ActionOnMismatch::Tombstone,
        }
    }

    /// Tombstone-mode harness: same shape as [`make_case`] but wires
    /// the optional `ArtifactRepository` + `ArtifactLifecyclePort` so
    /// `ActionOnMismatch::Tombstone` runs end-to-end.
    fn make_case_tombstone() -> (
        CasScrubUseCase,
        Arc<MockStoragePort>,
        Arc<MockEventStore>,
        Arc<MockArtifactRepository>,
        Arc<MockArtifactLifecycle>,
    ) {
        let storage = Arc::new(MockStoragePort::new());
        storage.set_backend_label("filesystem");
        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let uc = CasScrubUseCase::new(
            storage.clone() as Arc<dyn StoragePort>,
            crate::event_store_publisher::wrap_for_test(events.clone()),
        )
        .with_artifact_lifecycle(
            artifacts.clone() as Arc<dyn ArtifactRepository>,
            lifecycle.clone() as Arc<dyn ArtifactLifecyclePort>,
        );
        (uc, storage, events, artifacts, lifecycle)
    }

    // ------------------------------------------------------------------
    // Happy path — all blobs verify clean.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_happy_path_reports_checked_with_zero_mismatches() {
        let (uc, storage, events) = make_case();
        storage.insert_content(hash(HELLO_WORLD_SHA256), b"hello world".to_vec());
        storage.insert_content(hash(EMPTY_SHA256), Vec::new());

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.checked, 2);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.missing, 0);
        assert_eq!(report.read_errors, 0);
        // No events emitted on clean scrub.
        assert!(events.appended_batches().is_empty());
    }

    // ------------------------------------------------------------------
    // hash_mismatch — tampered blob.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_hash_mismatch_increments_counter_and_emits_event() {
        let (uc, storage, events) = make_case();
        // Register a tampered entry: the CAS says it is HELLO_WORLD,
        // but `get` returns bytes that hash to EMPTY.
        let tampered_hash = hash(HELLO_WORLD_SHA256);
        storage.inject_tampered(tampered_hash.clone(), Vec::new());

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.mismatches, 1);
        assert_eq!(report.checked, 1);
        assert_eq!(report.missing, 0);
        assert_eq!(report.read_errors, 0);

        // Event was appended with the right shape.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::CasIntegrityMismatch(e) => {
                assert_eq!(e.content_hash, tampered_hash);
                assert_eq!(e.backend, "filesystem");
                assert_eq!(e.observed_hash, hash(EMPTY_SHA256));
            }
            other => panic!("expected CasIntegrityMismatch, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Alert-mode preserves the flag-only shape.
    //
    // RED-then-green pin for the backwards-compat
    // invariant: the default action MUST emit `CasIntegrityMismatch`
    // and ONLY that — no `ArtifactCorrupted`, no `commit_transition`
    // call. Tombstone is opt-in; alert is the deploy-default.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn alert_mode_emits_cas_integrity_mismatch_only_no_state_transition() {
        // Set up a tombstone-shaped harness (lifecycle ports wired)
        // but run with action=Alert. The lifecycle port MUST stay
        // untouched — alert mode is supposed to be flag-only even
        // when the operator wired the optional ports.
        let (uc, storage, events, artifacts, lifecycle) = make_case_tombstone();

        // An artifact row exists for the tampered blob — if the alert
        // path were leaking into the tombstone path, the lifecycle
        // mock would record a transition. We seed the row to make the
        // negative assertion meaningful.
        let tampered_hash = hash(HELLO_WORLD_SHA256);
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.sha256_checksum = tampered_hash.clone();
        artifacts.insert(artifact.clone());

        storage.inject_tampered(tampered_hash.clone(), Vec::new());

        // Alert mode (the default).
        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.mismatches, 1);

        // Exactly one event appended — to the synthetic per-hash
        // stream — and it is `CasIntegrityMismatch`. No
        // `ArtifactCorrupted`.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1, "exactly one append batch in alert mode");
        assert_eq!(batches[0].events.len(), 1);
        assert!(
            matches!(
                &batches[0].events[0].event,
                DomainEvent::CasIntegrityMismatch(_)
            ),
            "alert mode must emit CasIntegrityMismatch only, got {:?}",
            batches[0].events[0].event
        );

        // No artifact-lifecycle transition fired — the row stays
        // `Released`. Subsequent download attempts succeed (the alert
        // path is observability-only; the operator is expected to
        // decide the response).
        assert!(
            lifecycle.committed_transitions().is_empty(),
            "alert mode must not call ArtifactLifecyclePort::commit_transition"
        );
        let stored = artifacts.get(artifact.id).unwrap();
        assert_eq!(stored.quarantine_status, QuarantineStatus::Released);
    }

    // ------------------------------------------------------------------
    // Tombstone-mode end-to-end.
    //
    // The pinned invariant: emits BOTH
    // `CasIntegrityMismatch` (audit fact) AND `ArtifactCorrupted`
    // (artifact state transition) AND moves the artifact to
    // `quarantine_status = 'rejected'` so subsequent download
    // attempts are blocked at the application layer (the same
    // existing quarantine error the rejected state already produces).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn tombstone_mode_emits_artifact_corrupted_and_blocks_subsequent_reads() {
        let (uc, storage, events, artifacts, lifecycle) = make_case_tombstone();

        // Seed an artifact row pointing at the (about-to-be-tampered)
        // CAS hash. Start in `Released` because that's the most
        // common real-world path to corruption: an artifact passed
        // its quarantine window, downloads were served, scrubber
        // catches a later at-rest corruption.
        let tampered_hash = hash(HELLO_WORLD_SHA256);
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.sha256_checksum = tampered_hash.clone();
        let artifact_id = artifact.id;
        artifacts.insert(artifact.clone());

        // Now register the CAS as tampered: the storage `get` returns
        // empty bytes (which hash to EMPTY_SHA256), but the CAS key
        // claims HELLO_WORLD_SHA256.
        storage.inject_tampered(tampered_hash.clone(), Vec::new());

        let report = uc.run(opts_sequential_tombstone()).await.unwrap();
        assert_eq!(report.mismatches, 1);

        // CasIntegrityMismatch on the synthetic per-hash stream
        // (preserves the existing alert-mode audit shape).
        let batches = events.appended_batches();
        assert!(
            batches.iter().any(|b| b
                .events
                .iter()
                .any(|e| matches!(&e.event, DomainEvent::CasIntegrityMismatch(_)))),
            "tombstone mode must still emit CasIntegrityMismatch"
        );

        // ArtifactCorrupted lands via the lifecycle port (atomic with
        // the state-machine transition to Rejected). Inspect the
        // recorded transition.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(
            transitions.len(),
            1,
            "tombstone must call commit_transition exactly once"
        );
        let (saved_artifact, append, _meta) = &transitions[0];
        assert_eq!(saved_artifact.id, artifact_id);
        assert_eq!(
            saved_artifact.quarantine_status,
            QuarantineStatus::Rejected,
            "tombstone must transition the artifact to Rejected"
        );
        assert_eq!(append.events.len(), 1);
        match &append.events[0].event {
            DomainEvent::ArtifactCorrupted(e) => {
                assert_eq!(e.artifact_id, artifact_id);
                assert_eq!(e.computed_hash, hash(EMPTY_SHA256));
                assert_eq!(e.expected_hash, tampered_hash);
            }
            other => panic!("expected ArtifactCorrupted, got {other:?}"),
        }

        // The state-machine transition is what blocks subsequent
        // downloads: `ArtifactUseCase::download` reads
        // `quarantine_status` and, on Rejected, returns the existing
        // quarantine error (`DownloadResult::Rejected` plus
        // `Forbidden`). The post-tombstone artifact row is the
        // observable that drives that path; we assert it directly
        // here. Re-running the download path through a full
        // download-use-case stack would only re-cover code that
        // `artifact_use_case::tests` already exercises.
        let stored = artifacts.get(artifact_id).expect("artifact still exists");
        assert_eq!(stored.quarantine_status, QuarantineStatus::Rejected);
        assert!(
            !stored.is_downloadable(),
            "tombstoned artifact must report not-downloadable"
        );
    }

    // ------------------------------------------------------------------
    // missing — hash listed but `get` returns NotFound.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_missing_increments_missing_counter_and_no_event() {
        let (uc, storage, events) = make_case();
        storage.inject_missing(hash(HELLO_WORLD_SHA256));

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.missing, 1);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.checked, 1);
        assert!(events.appended_batches().is_empty());
    }

    // ------------------------------------------------------------------
    // read_error from list_all.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_list_read_error_increments_read_errors_and_no_event() {
        let (uc, storage, events) = make_case();
        storage.inject_list_error("cas/aa/bb/malformed-name");

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.read_errors, 1);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.missing, 0);
        // Per-item read errors are observability-only (metric + log);
        // no event is emitted. Operator response would be inspection of
        // the backend, not an event-sourced reaction.
        assert!(events.appended_batches().is_empty());
    }

    // ------------------------------------------------------------------
    // shards_truncated — streaming source signals shard abandonment.
    // ------------------------------------------------------------------

    /// Single `ShardTruncated` from `list_all` increments
    /// `report.shards_truncated` and counts as a `ReadError` outcome at
    /// the per-item metric level — but does NOT increment `read_errors`
    /// on the report (the two counts are disjoint by intent so the
    /// CLI / dashboard can distinguish "individual blob failures" from
    /// "whole shard skipped").
    #[tokio::test]
    async fn run_shard_truncation_increments_shards_truncated() {
        let (uc, storage, events) = make_case();
        storage.inject_shard_truncation("cas/aa/bb");

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.shards_truncated, 1);
        assert_eq!(report.read_errors, 0);
        assert_eq!(report.checked, 0);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.missing, 0);
        // Like ReadError, shard truncation is observability-only.
        assert!(events.appended_batches().is_empty());
    }

    /// Multiple shard truncations accumulate under `shards_truncated`
    /// and never spill into the other counters.
    #[tokio::test]
    async fn run_multiple_shard_truncations_accumulate() {
        let (uc, storage, _events) = make_case();
        storage.inject_shard_truncation("cas/aa");
        storage.inject_shard_truncation("cas/bb/cc");
        storage.inject_shard_truncation("cas/zz/yy");

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.shards_truncated, 3);
        assert_eq!(report.checked, 0);
        assert_eq!(report.read_errors, 0);
    }

    /// Default `shards_truncated` is zero — pin so a future struct
    /// rearrangement doesn't accidentally break the assumption every
    /// test outside this section relies on.
    #[test]
    fn scrub_report_default_shards_truncated_is_zero() {
        let r = ScrubReport::default();
        assert_eq!(r.shards_truncated, 0);
    }

    // ------------------------------------------------------------------
    // Scrub continues past individual errors.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_continues_past_mixed_outcomes() {
        let (uc, storage, events) = make_case();
        // 1 ok
        storage.insert_content(hash(HELLO_WORLD_SHA256), b"hello world".to_vec());
        // 1 missing
        let missing_h = "aa".repeat(32).parse::<ContentHash>().unwrap();
        storage.inject_missing(missing_h.clone());
        // 1 mismatch
        let mismatch_h = "bb".repeat(32).parse::<ContentHash>().unwrap();
        storage.inject_tampered(mismatch_h.clone(), b"whatever".to_vec());
        // 1 list read_error
        storage.inject_list_error("cas/zz/malformed");
        // 1 shard truncation
        storage.inject_shard_truncation("cas/cc/dd");

        let report = uc.run(opts_sequential()).await.unwrap();
        assert_eq!(report.checked, 3); // ok + missing + mismatch
        assert_eq!(report.mismatches, 1);
        assert_eq!(report.missing, 1);
        assert_eq!(report.read_errors, 1);
        assert_eq!(report.shards_truncated, 1);

        // Exactly one CasIntegrityMismatch event appended.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::CasIntegrityMismatch(e) => {
                assert_eq!(e.content_hash, mismatch_h);
            }
            other => panic!("expected CasIntegrityMismatch, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Metric emission.
    // ------------------------------------------------------------------

    #[test]
    fn run_emits_hort_cas_scrub_checks_total_with_result_labels() {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let (uc, storage, _events) = make_case();
                storage.insert_content(hash(HELLO_WORLD_SHA256), b"hello world".to_vec());
                storage.inject_missing(hash(EMPTY_SHA256));
                let _ = uc.run(opts_sequential()).await.unwrap();
            });
        });

        // Find counter with backend=filesystem and result=ok (1) and
        // result=missing (1).
        let entries = snap.into_vec();
        let mut ok_seen = 0u64;
        let mut missing_seen = 0u64;
        for (ck, _, _, dv) in &entries {
            if ck.kind() != MetricKind::Counter {
                continue;
            }
            if ck.key().name() != "hort_cas_scrub_checks_total" {
                continue;
            }
            let has_backend = ck
                .key()
                .labels()
                .any(|l| l.key() == "backend" && l.value() == "filesystem");
            if !has_backend {
                continue;
            }
            let result = ck
                .key()
                .labels()
                .find(|l| l.key() == "result")
                .map(|l| l.value().to_string())
                .unwrap_or_default();
            if let DebugValue::Counter(n) = dv {
                match result.as_str() {
                    "ok" => ok_seen = *n,
                    "missing" => missing_seen = *n,
                    _ => {}
                }
            }
        }
        assert_eq!(ok_seen, 1);
        assert_eq!(missing_seen, 1);
    }

    // ------------------------------------------------------------------
    // Sampling boundaries.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn sample_fraction_zero_skips_everything() {
        let (uc, storage, events) = make_case();
        storage.insert_content(hash(HELLO_WORLD_SHA256), b"hello world".to_vec());
        storage.insert_content(hash(EMPTY_SHA256), Vec::new());

        let report = uc
            .run(ScrubOpts {
                concurrency: 1,
                sample_fraction: 0.0,
                action_on_mismatch: ActionOnMismatch::Alert,
            })
            .await
            .unwrap();
        // Everything skipped; nothing counted.
        assert_eq!(report.checked, 0);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.missing, 0);
        assert_eq!(report.read_errors, 0);
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn sample_fraction_one_scrubs_everything() {
        let (uc, storage, _events) = make_case();
        storage.insert_content(hash(HELLO_WORLD_SHA256), b"hello world".to_vec());
        storage.insert_content(hash(EMPTY_SHA256), Vec::new());

        let report = uc
            .run(ScrubOpts {
                concurrency: 1,
                sample_fraction: 1.0,
                action_on_mismatch: ActionOnMismatch::Alert,
            })
            .await
            .unwrap();
        assert_eq!(report.checked, 2);
    }

    // ------------------------------------------------------------------
    // default_sampler boundary helper.
    // ------------------------------------------------------------------

    #[test]
    fn default_sampler_fraction_one_always_true() {
        for _ in 0..100 {
            assert!(default_sampler(1.0));
        }
    }

    #[test]
    fn default_sampler_fraction_zero_always_false() {
        for _ in 0..100 {
            assert!(!default_sampler(0.0));
        }
    }

    #[test]
    fn default_sampler_fraction_negative_always_false() {
        assert!(!default_sampler(-0.5));
    }

    #[test]
    fn default_sampler_fraction_over_one_always_true() {
        assert!(default_sampler(2.0));
    }

    // ------------------------------------------------------------------
    // uuid_from_content_hash determinism.
    // ------------------------------------------------------------------

    #[test]
    fn uuid_from_content_hash_is_deterministic_per_hash() {
        let h1 = hash(HELLO_WORLD_SHA256);
        let h2 = hash(HELLO_WORLD_SHA256);
        assert_eq!(uuid_from_content_hash(&h1), uuid_from_content_hash(&h2));
    }

    #[test]
    fn uuid_from_content_hash_differs_across_hashes() {
        assert_ne!(
            uuid_from_content_hash(&hash(HELLO_WORLD_SHA256)),
            uuid_from_content_hash(&hash(EMPTY_SHA256)),
        );
    }

    // ------------------------------------------------------------------
    // ScrubOpts::defaults matches the CLI contract.
    // ------------------------------------------------------------------

    #[test]
    fn scrub_opts_defaults_are_concurrency_four_sample_one() {
        let d = ScrubOpts::defaults();
        assert_eq!(d.concurrency, 4);
        assert!((d.sample_fraction - 1.0).abs() < f64::EPSILON);
        // Default action is Alert (flag-only). `Tombstone` is opt-in
        // via HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone.
        assert_eq!(d.action_on_mismatch, ActionOnMismatch::Alert);
    }

    #[test]
    fn action_on_mismatch_default_is_alert() {
        assert_eq!(ActionOnMismatch::default(), ActionOnMismatch::Alert);
    }

    #[test]
    fn action_on_mismatch_as_str_pins_label_set() {
        assert_eq!(ActionOnMismatch::Alert.as_str(), "alert");
        assert_eq!(ActionOnMismatch::Tombstone.as_str(), "tombstone");
    }

    // ------------------------------------------------------------------
    // Concurrency > 1 produces the same report.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn concurrency_greater_than_one_produces_equivalent_report() {
        let (uc, storage, _events) = make_case();
        // Many independent ok blobs — the report is order-insensitive so
        // concurrency shouldn't change the counts.
        for i in 0..20u8 {
            let bytes = vec![i];
            let h_hex = format!("{:x}", Sha256::digest(&bytes));
            let h: ContentHash = h_hex.parse().unwrap();
            storage.insert_content(h, bytes);
        }

        let report = uc
            .run(ScrubOpts {
                concurrency: 8,
                sample_fraction: 1.0,
                action_on_mismatch: ActionOnMismatch::Alert,
            })
            .await
            .unwrap();
        assert_eq!(report.checked, 20);
        assert_eq!(report.mismatches, 0);
    }
}
