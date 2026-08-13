use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_lifecycle::{ArtifactLifecyclePort, IngestEnqueue};
use hort_domain::ports::event_store::{AppendEvents, AppendResult};
use hort_domain::ports::repo_security_score_repository::ScoreDelta;
use hort_domain::ports::scan_findings_repository::ScanFindingsRow;
use hort_domain::ports::BoxFuture;
use hort_domain::types::sbom::SbomComponent;

use crate::artifact_metadata_repo::PgArtifactMetadataRepository;
use crate::artifact_repo::PgArtifactRepository;
use crate::event_store::PgEventStore;
use crate::jobs_repository::{enqueue_provenance_verify_in_tx, enqueue_scan_in_tx};
use crate::repo_security_score_repository::apply_delta_in_tx;
use crate::sbom_components::replace_for_artifact_in_tx;
use crate::scan_findings_repository::insert_findings_in_tx;

/// PostgreSQL implementation of [`ArtifactLifecyclePort`].
///
/// Wraps event append + artifact save + artifact-metadata upsert in a
/// single SQL transaction, eliminating the dual-write hazard. Lock
/// acquisition order: events → artifacts → artifact_metadata →
/// repo_security_scores.
pub struct PgArtifactLifecycle {
    event_store: Arc<PgEventStore>,
    artifact_repo: Arc<PgArtifactRepository>,
    metadata_repo: Arc<PgArtifactMetadataRepository>,
}

impl PgArtifactLifecycle {
    pub fn new(
        event_store: Arc<PgEventStore>,
        artifact_repo: Arc<PgArtifactRepository>,
        metadata_repo: Arc<PgArtifactMetadataRepository>,
    ) -> Self {
        Self {
            event_store,
            artifact_repo,
            metadata_repo,
        }
    }
}

impl ArtifactLifecyclePort for PgArtifactLifecycle {
    fn commit_transition(
        &self,
        artifact: &Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
    ) -> BoxFuture<'_, DomainResult<AppendResult>> {
        let artifact = artifact.clone();
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            let result = self.event_store.append_in_tx(&mut uow, events).await?;
            self.artifact_repo.save_in_tx(&mut uow, &artifact).await?;
            if let Some(m) = &metadata {
                self.metadata_repo.upsert_in_tx(&mut uow, m).await?;
            }

            uow.commit().await?;
            Ok(result)
        })
    }

    /// Atomic transition + score-projection upsert.
    ///
    /// Same as [`Self::commit_transition`] plus an in-tx
    /// `repo_security_scores` upsert when `score_delta` is `Some`.
    /// The score upsert is the LAST step in the tx so a failed
    /// upsert (e.g. clamp violation) rolls back the event append +
    /// artifact save together. Lock order:
    /// events → artifacts → artifact_metadata → repo_security_scores.
    fn commit_transition_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
        score_delta: Option<(Uuid, ScoreDelta)>,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let artifact = artifact.clone();
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            let result = self.event_store.append_in_tx(&mut uow, events).await?;
            self.artifact_repo.save_in_tx(&mut uow, &artifact).await?;
            if let Some(m) = &metadata {
                self.metadata_repo.upsert_in_tx(&mut uow, m).await?;
            }

            if let Some((repo_id, delta)) = &score_delta {
                apply_delta_in_tx(uow.conn(), *repo_id, delta).await?;
            }

            uow.commit().await?;
            Ok(result)
        })
    }

    /// Atomic scan-result dual-write, score upsert, and (when an SBOM
    /// was extracted) `sbom_components` REPLACE for the artifact.
    ///
    /// The artifact-state write is column-scoped (`quarantine_status` +
    /// `updated_at` only), NOT the full-row `save_in_tx` — this is a
    /// verdict commit (issue #90): the artifact was loaded at the top of
    /// `record_scan_result`, before findings validation, policy
    /// resolution, and the findings-blob CAS write, so the in-memory
    /// snapshot's other columns (most critically
    /// `quarantine_window_start`) can be stale by the time this commits.
    /// A full-row write-back would clobber whatever a
    /// concurrently-committed transition wrote to those columns.
    #[allow(clippy::too_many_arguments)] // trait-defined shape — see the port.
    fn commit_scan_result_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        scan_findings_rows: &'a [ScanFindingsRow],
        last_scan_at: DateTime<Utc>,
        score_delta: Option<(Uuid, ScoreDelta)>,
        sbom_components: Option<&'a [SbomComponent]>,
        prior_status: QuarantineStatus,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let artifact = artifact.clone();
        let rows = scan_findings_rows.to_vec();
        let components: Option<Vec<SbomComponent>> = sbom_components.map(<[_]>::to_vec);
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            let result = self.event_store.append_in_tx(&mut uow, events).await?;
            // Skip-unchanged (issue #108 H2b): a transition that left the
            // status where it was has no status write to make, so it
            // cannot lose a race with a concurrent one. See the port doc.
            if artifact.quarantine_status != prior_status {
                self.artifact_repo
                    .save_verdict_status_in_tx(
                        &mut uow,
                        artifact.id,
                        artifact.quarantine_status,
                        artifact.updated_at,
                        prior_status,
                    )
                    .await?;
            }

            sqlx::query("UPDATE artifacts SET last_scan_at = $1 WHERE id = $2")
                .bind(last_scan_at)
                .bind(artifact.id)
                .execute(uow.conn())
                .await
                .map_err(|e| {
                    DomainError::Invariant(format!("update artifacts.last_scan_at: {e}"))
                })?;

            insert_findings_in_tx(uow.conn(), &rows).await?;

            // REPLACE the SBOM-component projection for this artifact
            // when an SBOM was extracted. `None` skips the projection
            // write entirely (existing rows stay; the current acceptance
            // criterion is "no extracted SBOM ⇒ existing rows preserved;
            // eventual cleanup is future work"). The DELETE + INSERT lands
            // inside this same scan transaction so a constraint violation
            // here rolls back the event append + artifact save together.
            if let Some(comps) = components.as_ref() {
                replace_for_artifact_in_tx(uow.conn(), artifact.id, comps).await?;
            }

            if let Some((repo_id, delta)) = &score_delta {
                apply_delta_in_tx(uow.conn(), *repo_id, delta).await?;
            }

            uow.commit().await?;
            Ok(result)
        })
    }

    /// Atomic ingest transition + ingest-time job enqueue.
    ///
    /// Fulfils the [`ArtifactLifecyclePort::commit_transition_with_enqueues`]
    /// no-strand guarantee for the Postgres backend by spanning **one** SQL
    /// transaction: the events, the artifact projection, the optional metadata
    /// upsert, and every ingest-time `jobs` insert commit-or-roll-back
    /// together. A `ScanRequested` / provenance-gate event can therefore never
    /// land without its `jobs` row. Lock order:
    /// events → artifacts → artifact_metadata → jobs.
    ///
    /// The scan enqueue is idempotent (`enqueue_scan_in_tx` swallows the
    /// `jobs_scan_unique` conflict); any other insert failure aborts the whole
    /// transition (the ingest fails and is retriable), never a partial commit.
    fn commit_transition_with_enqueues<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
        enqueues: &'a [IngestEnqueue],
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let artifact = artifact.clone();
        let enqueues = enqueues.to_vec();
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            let result = self.event_store.append_in_tx(&mut uow, events).await?;
            self.artifact_repo.save_in_tx(&mut uow, &artifact).await?;
            if let Some(m) = &metadata {
                self.metadata_repo.upsert_in_tx(&mut uow, m).await?;
            }

            for enq in &enqueues {
                match enq {
                    IngestEnqueue::Scan {
                        format,
                        priority,
                        trigger_source,
                    } => {
                        enqueue_scan_in_tx(
                            uow.conn(),
                            artifact.id,
                            artifact.repository_id,
                            &artifact.sha256_checksum,
                            format,
                            *priority,
                            trigger_source,
                        )
                        .await?;
                    }
                    IngestEnqueue::ProvenanceVerify {
                        priority,
                        trigger_source,
                    } => {
                        enqueue_provenance_verify_in_tx(
                            uow.conn(),
                            artifact.id,
                            *priority,
                            trigger_source,
                        )
                        .await?;
                    }
                }
            }

            uow.commit().await?;
            Ok(result)
        })
    }

    /// Atomic provenance-verdict transition (`ProvenanceVerified` /
    /// `ProvenanceRejected`). Column-scoped artifact write — see
    /// [`ArtifactLifecyclePort::commit_provenance_verdict`] (issue #90):
    /// unlike [`Self::commit_transition`], this writes ONLY
    /// `quarantine_status` (+ `updated_at`), never the full row, so it
    /// cannot clobber a concurrently-committed transition's other columns
    /// (most critically `quarantine_window_start`).
    fn commit_provenance_verdict<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        prior_status: QuarantineStatus,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let artifact_id = artifact.id;
        let quarantine_status: QuarantineStatus = artifact.quarantine_status;
        let updated_at = artifact.updated_at;
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            let result = self.event_store.append_in_tx(&mut uow, events).await?;
            // Skip-unchanged (issue #108 H2b) — the `ProvenanceVerified`
            // case leaves the artifact `Quarantined`, so there is no
            // status write to make and therefore no revert vector at all.
            // See the port doc for the full contract.
            if quarantine_status != prior_status {
                self.artifact_repo
                    .save_verdict_status_in_tx(
                        &mut uow,
                        artifact_id,
                        quarantine_status,
                        updated_at,
                        prior_status,
                    )
                    .await?;
            }

            uow.commit().await?;
            Ok(result)
        })
    }
}
