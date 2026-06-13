//! `PurgeUseCase::process_expired` — the **storage-GC walk**: the
//! destructive second stage of the two-stage retention split.
//!
//! # Two-stage split
//!
//! `RetentionUseCase::evaluate_policies` is stage one — it
//! appends an [`ArtifactExpired`](hort_domain::events::ArtifactExpired)
//! to the artifact stream and deletes nothing. **This** use case is
//! stage two: for every `ArtifactExpired` with no following
//! [`ArtifactPurged`](hort_domain::events::ArtifactPurged) it runs the GC
//! algorithm (decrement `content_references`, delete the CAS blob iff
//! the cross-`kind` refcount hit `0`, append `ArtifactPurged`). It is
//! NOT a scheduler — that is the `RetentionPurgeHandler`
//! `TaskHandler`; this is the pure orchestration the handler calls.
//!
//! # Reconcile-converged start-gate (binding constraint)
//!
//! The `content_references` refcount projection is **eventually
//! authoritative** (post-commit, warn-on-fail ingest/reject
//! writes). Treating a missing / decremented refcount row as
//! GC-authoritative is only safe **after a positive reconcile** — the
//! [`RefcountReconcileUseCase::sweep_drift`] convergence
//! gate, NOT a per-sweep live `NOT EXISTS` against the lagging
//! projection. This use
//! case therefore **refuses to run** unless it is constructed with a
//! [`RefcountReconcileGate`] that reports the reconcile sweep has
//! converged at least once on this deployment.
//!
//! ## The start-gate seam (BLOCK-note — read this)
//!
//! The reconcile sweep ships **no durable convergence signal**: it is a
//! boot-time sweep behind `HORT_REFCOUNT_RECONCILE_ON_STARTUP` (default
//! `true`, `crates/hort-server/src/cli/serve.rs`) and ships **no
//! migration**, so no durable "the sweep has run successfully" signal
//! is reachable from the `hort-app` layer without an out-of-scope
//! change (a durable convergence marker is sweep / scheduler /
//! composition-root territory; reading `_sqlx_migrations` needs a DSN
//! this pure-orchestration layer does not hold). The gate is therefore
//! modelled as an **injected precondition** ([`RefcountReconcileGate`])
//! the composition root satisfies — exactly the layer that already owns
//! `HORT_REFCOUNT_RECONCILE_ON_STARTUP` + the boot sweep. The
//! durable-signal wiring (a persisted "reconcile converged" marker the
//! gate reads) belongs with the `RetentionPurgeHandler` composition +
//! the worker boot path; this use case ships the gate *contract* +
//! enforcement so the invariant cannot be silently dropped.
//!
//! # GC algorithm (faithful, crash-safe)
//!
//! For each pending `ArtifactExpired`:
//! 1. Lock the artifact row `FOR UPDATE`.
//! 2. `DELETE FROM content_references WHERE source_artifact_id = X AND
//!    kind IN ('primary_content','metadata_blob') RETURNING
//!    target_content_hash, kind`.
//! 3. For each returned hash `H`: `SELECT count(*) FROM
//!    content_references WHERE target_content_hash = H` (covers **every**
//!    kind incl. `oci_subject` — a live OCI manifest keeps the blob).
//!    `count = 0` ⇒ `StoragePort::delete(H)`; emit
//!    `ArtifactPurged{ content_hash: H, refs_remaining: count }`.
//! 4. Commit.
//!
//! Walks **both** `artifact.sha256_checksum` (`primary_content`) AND
//! `artifact_metadata.metadata_blob` (`metadata_blob`).
//!
//! ## Two-stage idempotency
//!
//! The durable `ArtifactExpired` event is the work item; `ArtifactPurged`
//! terminates it. The adapter's [`PurgeGcPort::purge_artifact_refs`] is
//! **idempotent**: the deleted-blob hash is recoverable from the
//! authoritative `artifacts.checksum_sha256` /
//! `artifact_metadata.metadata_blob` columns, not only from the
//! (deleted) `content_references` rows. A transient `StoragePort::delete`
//! failure ⇒ **no** `ArtifactPurged` emitted, the content_references
//! deletion rolled back with the failed transaction, the
//! `ArtifactExpired` decision intact ⇒ the next sweep re-reads it and
//! retries. Re-running `StoragePort::delete` on an already-absent blob
//! is a clean no-op (`delete` is success-on-missing);
//! `ArtifactPurged` is idempotent on replay.
//!
//! ## Evidence is never purged (defence-in-depth)
//!
//! Quarantined / rejected / scan-indeterminate artifacts are evidence
//! and must never be purged. Stage one already filters them before appending
//! `ArtifactExpired`, so a pending purge for one of them should not
//! exist; the adapter's `list_pending_purge` excludes them anyway and
//! this use case asserts the invariant a second time and **skips +
//! `warn!`s** rather than trusting the upstream filter (a destructive
//! item is conservative by construction).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::events::{retention_scheduler_actor, ArtifactPurged, DomainEvent, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::purge_gc::{PendingPurge, PurgeGcPort, PurgedRef};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{emit_retention_purged, RetentionPurgedResult};

/// Reports whether the refcount-reconcile sweep
/// ([`RefcountReconcileUseCase::sweep_drift`](super::refcount_reconcile_use_case::RefcountReconcileUseCase))
/// has converged at least once on this deployment.
///
/// **Why an injected gate and not a direct signal read.** The sweep
/// leaves no durable convergence marker (see this module's "start-gate
/// seam" BLOCK-note) and the durable-signal mechanism is not reachable
/// from this pure-orchestration layer without an out-of-scope change.
/// The gate is therefore satisfied by the composition root — the layer
/// that already owns `HORT_REFCOUNT_RECONCILE_ON_STARTUP` and runs the
/// boot sweep. The contract: `is_converged()` returns `true` **only**
/// once a reconcile sweep has completed successfully on this
/// deployment.
pub trait RefcountReconcileGate: Send + Sync {
    /// `true` iff the reconcile sweep (`RefcountReconcileUseCase::sweep_drift`) has
    /// converged at least once on this deployment. While `false`, the
    /// refcount projection may be drifted and no GC consumer may treat
    /// a decremented / missing refcount row as authoritative — the
    /// purge sweep refuses to run.
    fn is_converged(&self) -> bool;
}

/// Outcome summary of one `process_expired` pass — the
/// `result_summary` JSON shape the `RetentionPurgeHandler` `TaskHandler`
/// surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeSummary {
    /// Pending `ArtifactExpired` artifacts the sweep visited.
    pub artifacts_visited: u64,
    /// CAS blobs deleted (cross-`kind` refcount hit `0`).
    pub blobs_deleted: u64,
    /// References removed whose blob stays (a live ref remains).
    pub blobs_kept: u64,
    /// `ArtifactPurged` events appended (one per processed hash).
    pub purged_events: u64,
    /// Artifacts skipped by the evidence-protection re-assertion.
    pub skipped_protected: u64,
    /// Per-artifact failures (port read / storage delete / append).
    /// The `ArtifactExpired` decision is retained; next sweep retries.
    pub errors: u64,
}

/// The storage-GC walk. Pure orchestration over the
/// additive [`PurgeGcPort`], the existing [`StoragePort`], and the
/// event store. Refuses to run unless the [`RefcountReconcileGate`]
/// reports the refcount-reconcile sweep has converged.
pub struct PurgeUseCase {
    gc: Arc<dyn PurgeGcPort>,
    storage: Arc<dyn StoragePort>,
    events: Arc<EventStorePublisher>,
    reconcile_gate: Arc<dyn RefcountReconcileGate>,
}

impl PurgeUseCase {
    /// Construct the use case. `reconcile_gate` is the reconcile-converged
    /// start-gate (see the module BLOCK-note); the composition root
    /// supplies an implementation that is `true` only after a reconcile
    /// sweep converged on this deployment.
    pub fn new(
        gc: Arc<dyn PurgeGcPort>,
        storage: Arc<dyn StoragePort>,
        events: Arc<EventStorePublisher>,
        reconcile_gate: Arc<dyn RefcountReconcileGate>,
    ) -> Self {
        Self {
            gc,
            storage,
            events,
            reconcile_gate,
        }
    }

    /// Run the storage-GC walk for every pending `ArtifactExpired`
    /// at wall-clock `now` (`now` is injected so it is coherent across
    /// retries and pinnable in tests — the retention-sweep convention).
    ///
    /// **Refuses to run** (returns `AppError::Domain` /
    /// `DomainError::Invariant`) when the [`RefcountReconcileGate`]
    /// reports the reconcile sweep has not converged — the binding
    /// constraint: no GC consumer may read the eventually-authoritative
    /// refcount projection until the reconcile gate is satisfied.
    ///
    /// One bad artifact (port / storage / append failure) is recorded
    /// in [`PurgeSummary::errors`] and the sweep continues — the
    /// `ArtifactExpired` decision is retained and the next sweep
    /// retries (per-artifact, not fatal).
    #[tracing::instrument(skip(self))]
    pub async fn process_expired(&self, now: DateTime<Utc>) -> AppResult<PurgeSummary> {
        // -- reconcile-converged start-gate (binding constraint) ----------
        if !self.reconcile_gate.is_converged() {
            tracing::warn!(
                "PurgeUseCase refused to run: the refcount-reconcile sweep \
                 has not converged on this deployment. The content_references \
                 refcount projection is eventually authoritative; a GC walk \
                 over a pre-reconcile projection could delete a live blob. \
                 Run the refcount-reconcile sweep to convergence first."
            );
            return Err(AppError::Domain(
                hort_domain::error::DomainError::Invariant(
                    "PurgeUseCase start-gate: RefcountReconcileUseCase \
                 has not converged; storage GC is refused (reconcile-converged \
                 binding constraint)"
                        .to_owned(),
                ),
            ));
        }

        let pending = self
            .gc
            .list_pending_purge()
            .await
            .map_err(AppError::Domain)?;
        tracing::info!(
            pending_count = pending.len(),
            "storage-GC purge sweep starting (reconcile-converged gate satisfied)"
        );

        let mut summary = PurgeSummary::default();
        for item in &pending {
            summary.artifacts_visited += 1;
            self.process_one(now, item, &mut summary).await;
        }

        tracing::info!(
            artifacts_visited = summary.artifacts_visited,
            blobs_deleted = summary.blobs_deleted,
            blobs_kept = summary.blobs_kept,
            purged_events = summary.purged_events,
            skipped_protected = summary.skipped_protected,
            errors = summary.errors,
            "storage-GC purge sweep complete"
        );
        Ok(summary)
    }

    /// Process one pending-purge artifact. Isolated so any failure maps
    /// to a [`PurgeSummary::errors`] increment and the sweep continues.
    async fn process_one(
        &self,
        now: DateTime<Utc>,
        item: &PendingPurge,
        summary: &mut PurgeSummary,
    ) {
        // -- evidence-protection re-assertion (defence-in-depth) ---------
        match item.quarantine_status {
            QuarantineStatus::Quarantined
            | QuarantineStatus::Rejected
            | QuarantineStatus::ScanIndeterminate => {
                summary.skipped_protected += 1;
                tracing::warn!(
                    artifact_id = %item.artifact_id,
                    status = %item.quarantine_status,
                    "inv1: pending-purge artifact is quarantined/rejected/\
                     indeterminate (evidence) — skipped, NOT purged. This \
                     should have been filtered before ArtifactExpired; \
                     re-asserted here because purge is destructive."
                );
                return;
            }
            QuarantineStatus::None | QuarantineStatus::Released => {}
        }

        // -- GC steps 1-3 (committed, idempotent transaction) ------------
        let purged_refs = match self.gc.purge_artifact_refs(item.artifact_id).await {
            Ok(r) => r,
            Err(e) => {
                summary.errors += 1;
                tracing::error!(
                    artifact_id = %item.artifact_id,
                    error = %e,
                    "purge_artifact_refs failed — ArtifactExpired retained, \
                     retried on next sweep"
                );
                return;
            }
        };

        for pr in purged_refs {
            self.finish_one_ref(now, item.artifact_id, pr, summary)
                .await;
        }
    }

    /// Decide + execute the storage delete for one hash, then append
    /// the terminal `ArtifactPurged`. Two-stage idempotency: a
    /// transient `StoragePort::delete` failure emits **no**
    /// `ArtifactPurged` (the decision survives, next sweep retries).
    async fn finish_one_ref(
        &self,
        now: DateTime<Utc>,
        artifact_id: Uuid,
        pr: PurgedRef,
        summary: &mut PurgeSummary,
    ) {
        let hash_short = truncate_hash(&pr.content_hash);

        if pr.refs_remaining == 0 {
            // GC-eligible: delete the CAS blob. `delete` is
            // success-on-missing: the adapter MAY
            // surface an already-absent blob as `Ok(())` OR as
            // `DomainError::NotFound` (StoragePort doc contract). Both
            // mean "the blob is gone" and are the correct idempotent
            // outcome on a retry — only a NON-`NotFound` error is the
            // transient failure that must NOT lose the decision.
            match self.storage.delete(&pr.content_hash).await {
                Ok(()) => {}
                Err(hort_domain::error::DomainError::NotFound { .. }) => {
                    tracing::info!(
                        %artifact_id,
                        content_hash = %hash_short,
                        "blob already absent on delete — \
                         success-on-missing (idempotent re-purge)"
                    );
                }
                Err(e) => {
                    summary.errors += 1;
                    emit_retention_purged(RetentionPurgedResult::StorageError);
                    tracing::warn!(
                        %artifact_id,
                        content_hash = %hash_short,
                        error = %e,
                        "storage delete failed for a refcount-0 blob — \
                         ArtifactExpired retained (no ArtifactPurged \
                         emitted), retried on next sweep (two-stage \
                         idempotency)"
                    );
                    return;
                }
            }
            summary.blobs_deleted += 1;
        } else {
            // A live reference keeps the blob; only this ref is gone.
            summary.blobs_kept += 1;
        }

        match self
            .append_purged(artifact_id, pr.content_hash.clone(), pr.refs_remaining, now)
            .await
        {
            Ok(()) => {
                summary.purged_events += 1;
                if pr.refs_remaining == 0 {
                    emit_retention_purged(RetentionPurgedResult::Success);
                } else {
                    emit_retention_purged(RetentionPurgedResult::BlobKept);
                }
                tracing::info!(
                    %artifact_id,
                    content_hash = %hash_short,
                    refs_remaining = pr.refs_remaining,
                    "artifact purged"
                );
            }
            Err(e) => {
                summary.errors += 1;
                tracing::error!(
                    %artifact_id,
                    content_hash = %hash_short,
                    error = %e,
                    "ArtifactPurged append failed after storage step — \
                     ArtifactExpired retained, retried on next sweep \
                     (purge_artifact_refs + storage delete are idempotent)"
                );
            }
        }
    }

    /// Append the terminal `ArtifactPurged` to the artifact stream.
    /// `ExpectedVersion::Any` — the purge races nothing on the stream
    /// for this decision (the pending set already proves no
    /// `ArtifactPurged` followed the `ArtifactExpired`; a concurrent
    /// ingest appending in between is harmless and cannot duplicate the
    /// terminal). Same convention as `RetentionUseCase`'s
    /// `append_expired`. Actor is [`retention_scheduler_actor`] (not
    /// `system_actor()`) so the destructive `ArtifactPurged`
    /// audit is attributable to the retention subsystem.
    async fn append_purged(
        &self,
        artifact_id: Uuid,
        content_hash: ContentHash,
        refs_remaining: u32,
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        let event = ArtifactPurged {
            artifact_id,
            content_hash,
            refs_remaining,
            purged_at: now,
        };
        event.validate().map_err(AppError::Domain)?;
        let batch = AppendEvents {
            stream_id: StreamId::artifact(artifact_id),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::ArtifactPurged(event))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            // Destructive purge audit → RetentionScheduler.
            actor: retention_scheduler_actor(),
        };
        self.events.append(batch).await.map_err(AppError::Domain)?;
        Ok(())
    }
}

/// `tracing`-only truncation of a content hash (first 12 hex chars) —
/// the "content_hash (truncated)" tracing convention. Never a
/// metric label (cardinality hard-block).
fn truncate_hash(h: &ContentHash) -> String {
    let s = h.as_ref();
    s.chars().take(12).collect()
}

#[cfg(test)]
#[path = "purge_use_case_tests.rs"]
mod tests;
