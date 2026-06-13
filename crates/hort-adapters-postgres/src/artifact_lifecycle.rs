use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, ArtifactMetadata};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::event_store::{AppendEvents, AppendResult};
use hort_domain::ports::repo_security_score_repository::ScoreDelta;
use hort_domain::ports::scan_findings_repository::ScanFindingsRow;
use hort_domain::ports::BoxFuture;
use hort_domain::types::sbom::SbomComponent;

use crate::artifact_metadata_repo::PgArtifactMetadataRepository;
use crate::artifact_repo::PgArtifactRepository;
use crate::event_store::PgEventStore;
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
    fn commit_scan_result_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        scan_findings_rows: &'a [ScanFindingsRow],
        last_scan_at: DateTime<Utc>,
        score_delta: Option<(Uuid, ScoreDelta)>,
        sbom_components: Option<&'a [SbomComponent]>,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let artifact = artifact.clone();
        let rows = scan_findings_rows.to_vec();
        let components: Option<Vec<SbomComponent>> = sbom_components.map(<[_]>::to_vec);
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            let result = self.event_store.append_in_tx(&mut uow, events).await?;
            self.artifact_repo.save_in_tx(&mut uow, &artifact).await?;

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
}
