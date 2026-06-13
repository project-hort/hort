//! `RefcountReconcileUseCase::sweep_drift` — the refcount-reconcile
//! sweep. **HARD PREREQUISITE for the storage-GC walk (`PurgeUseCase`).**
//!
//! # What this reconciles
//!
//! `content_references` is an *eventually
//! authoritative* refcount projection: the `primary_content` /
//! `metadata_blob` writes on the ingest paths and the
//! `delete_by_source` sweep on the reject paths are **post-commit,
//! warn-on-fail**. A transient PG
//! outage between the event append and the projection write/delete
//! leaves drift. This sweep is the named reconcile for that drift,
//! and the precondition `PurgeUseCase` refuses to start without
//! ("no refcount row" is
//! GC-eligible **only after a positive reconcile** — this is that
//! reconcile gate).
//!
//! For every artifact in every repository it converges:
//!
//! 1. **exactly one** `(repo, artifact, "primary_content")` row with
//!    `target_content_hash = artifacts.checksum_sha256` (create
//!    missing, repair mis-targeted);
//! 2. **exactly one** `(repo, artifact, "metadata_blob")` row whenever
//!    `artifact_metadata.metadata_blob` is non-null, matching that
//!    hash (create missing / repair mis-targeted);
//! 3. **zero** `content_references` rows whose source artifact is
//!    `quarantine_status = 'rejected'` (delete — the `ArtifactRejected`
//!    cascading delete is itself warn-on-fail).
//!
//! It is **idempotent and re-runnable**: a converged projection
//! yields zero repairs (a true no-op — no port writes).
//!
//! # Layering
//!
//! Pure orchestration over the additive
//! [`RefcountReconcilePort`](hort_domain::ports::refcount_reconcile::RefcountReconcilePort).
//! The set-based scan SQL and the idempotent upsert/delete repair SQL
//! live in the Postgres adapter (≥85% integration-tested); this use
//! case owns only the iteration, the tracing contract, and the
//! summary (100% mock-testable, the `hort-app` coverage tier).
//!
//! # Observability (tracing-only, no metric)
//!
//! - `#[tracing::instrument(skip(self))]`, **no `err`** (a per-repo /
//!   per-repair failure is recorded and the sweep continues; it is not
//!   an error return that `err` would double-log).
//! - `info!` at sweep start and at sweep completion carrying the
//!   per-run mode-summary, plus one `info!` per repository with that
//!   repo's drift-repaired / error counts.
//! - `warn!` per drift case repaired, carrying the `(artifact_id,
//!   kind, action)` triple.
//!
//! The sweep emits **no metric** — it is deliberately
//! tracing-only. No `docs/metrics-catalog.md` row is
//! added (correctly — a metric-without-catalog row is a hard block;
//! there is no metric here).

use std::sync::Arc;

use hort_domain::ports::refcount_reconcile::{RefcountReconcilePort, RefcountRepair};

use crate::error::AppResult;

/// Outcome summary of one `sweep_drift` pass. Returned to the caller
/// (the boot-time invocation, or a future `TaskHandler`)
/// and surfaced in the completion `info!` line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Repositories iterated this pass (every repo with ≥1 artifact).
    pub repos_swept: u64,
    /// Drift cases successfully repaired (one per applied
    /// [`RefcountRepair`]).
    pub drift_repaired: u64,
    /// Per-repo scan failures + per-repair apply failures. Each is
    /// recorded and the sweep continues; the run still returns `Ok`.
    /// A non-zero value means the projection may still be drifted —
    /// the next sweep retries.
    pub errors: u64,
}

/// The refcount-reconcile sweep. Pure orchestration over
/// the additive [`RefcountReconcilePort`].
pub struct RefcountReconcileUseCase {
    port: Arc<dyn RefcountReconcilePort>,
}

impl RefcountReconcileUseCase {
    /// Construct the use case from the reconcile port.
    pub fn new(port: Arc<dyn RefcountReconcilePort>) -> Self {
        Self { port }
    }

    /// Bring `content_references` back into agreement with `artifacts`
    /// + `artifact_metadata` across every repository.
    ///
    /// A failure to **list** repositories aborts the run (there is
    /// nothing to sweep — surfaces as `AppError::Domain`). A failure
    /// to **scan** one repo, or to **apply** one repair, is recorded
    /// in [`ReconcileSummary::errors`] and the sweep continues — the
    /// next run retries the still-drifted slots (the projection is
    /// eventually authoritative; one bad repo must not block the rest
    /// from converging).
    #[tracing::instrument(skip(self))]
    pub async fn sweep_drift(&self) -> AppResult<ReconcileSummary> {
        let repo_ids = self.port.list_repository_ids().await?;
        tracing::info!(
            repo_count = repo_ids.len(),
            "refcount-reconcile sweep starting"
        );

        let mut summary = ReconcileSummary::default();
        for repo_id in repo_ids {
            summary.repos_swept += 1;
            let (repaired, errors) = self.sweep_one_repo(repo_id).await;
            summary.drift_repaired += repaired;
            summary.errors += errors;
            tracing::info!(
                %repo_id,
                drift_repaired = repaired,
                errors,
                "refcount-reconcile repo swept"
            );
        }

        tracing::info!(
            repos_swept = summary.repos_swept,
            drift_repaired = summary.drift_repaired,
            errors = summary.errors,
            "refcount-reconcile sweep complete"
        );
        Ok(summary)
    }

    /// Scan one repo's drift and apply every repair. Returns
    /// `(repaired, errors)` for that repo. Isolated so a scan or apply
    /// failure maps to an `errors` increment and the outer loop keeps
    /// sweeping the remaining repos.
    async fn sweep_one_repo(&self, repo_id: uuid::Uuid) -> (u64, u64) {
        let drift = match self.port.scan_repo_drift(repo_id).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(
                    %repo_id,
                    error = %e,
                    "refcount-reconcile scan failed for this repo — \
                     skipped, retried on next sweep"
                );
                return (0, 1);
            }
        };

        let mut repaired = 0u64;
        let mut errors = 0u64;
        for repair in &drift.repairs {
            match self.port.apply_repair(repo_id, repair).await {
                Ok(()) => {
                    repaired += 1;
                    Self::warn_repaired(repo_id, repair);
                }
                Err(e) => {
                    errors += 1;
                    tracing::error!(
                        %repo_id,
                        artifact_id = %repair.source_artifact_id(),
                        kind = repair.kind_label(),
                        action = repair.action_label(),
                        error = %e,
                        "refcount-reconcile repair failed for this drift \
                         case — skipped, retried on next sweep"
                    );
                }
            }
        }
        (repaired, errors)
    }

    /// The `warn!` per drift case repaired, carrying the
    /// `(artifact_id, kind, action)` triple.
    fn warn_repaired(repo_id: uuid::Uuid, repair: &RefcountRepair) {
        tracing::warn!(
            %repo_id,
            artifact_id = %repair.source_artifact_id(),
            kind = repair.kind_label(),
            action = repair.action_label(),
            "refcount-reconcile repaired projection drift"
        );
    }
}

#[cfg(test)]
#[path = "refcount_reconcile_use_case_tests.rs"]
mod tests;
