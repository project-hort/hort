//! `ManualRescanUseCase`.
//!
//! Per-artifact "rescan now" operation triggered by
//! `POST /api/v1/artifacts/:id/rescan` (the inbound HTTP route lives in
//! `hort-http-admin-security`).
//!
//! # Responsibilities
//!
//! 1. **Load the artifact.** Missing artifact → `NotFound`.
//! 2. **Anti-enumeration.** Resolve the artifact's parent repository
//!    with [`AccessLevel::Write`] via [`RepositoryAccessUseCase`]. The
//!    `Write` arm of that helper already implements the anti-enumeration
//!    contract:
//!    - Repo invisible to the caller → `NotFound` (so probing via
//!      `POST /artifacts/:id/rescan` cannot enumerate private repos).
//!    - Repo Read-visible but caller lacks `Permission::Write` →
//!      `Forbidden`.
//!    - Caller has Write → returns the resolved [`Repository`].
//!
//!    The artifact-level NotFound also collapses an
//!    invisible-repository result back to "Artifact not found" so the
//!    wire envelope never leaks the existence of a private repo
//!    through the artifact-id probe vector — the same shape as
//!    [`super::artifact_use_case::ArtifactUseCase::find_visible_by_id`].
//! 3. **Conflict detection.** Look up an in-flight `kind='scan'` job
//!    for the artifact via
//!    [`JobsRepository::find_active_scan_for_artifact`] (`status IN
//!    ('pending', 'running')`). If one exists, return
//!    `DomainError::Conflict` carrying the existing job id.
//! 4. **Enqueue.** Insert a new `kind='scan'` row with
//!    `priority=20`, `trigger_source="manual"` via
//!    [`JobsRepository::enqueue_scan`]. The Postgres adapter's
//!    partial-unique-index race is surfaced as `DomainError::Conflict`
//!    too, so the use case yields the same wire response on either
//!    detection path.
//!
//! # RBAC
//!
//! Single gate: `Permission::Write` on the artifact's parent repository
//! (the same enforcement pattern as repository access). The
//! `RepositoryAccessUseCase` handles the live RBAC snapshot
//! (`Arc<ArcSwap<RbacEvaluator>>`) so policy refresh propagates without
//! restart.
//!
//! # Wire shape
//!
//! Returns `Result<Uuid, AppError>` where the `Uuid` is the **newly-
//! inserted `jobs.id`** (NOT the artifact id) — the inbound handler
//! wraps it in `{ "task_job_id": <uuid> }` so the caller can poll
//! `/api/v1/admin/tasks/<id>` for status (the same envelope shape the
//! admin-task surface returns).
//!
//! # Observability
//!
//! - `#[tracing::instrument(skip(self))]` on the public method.
//! - Conflict + Forbidden + NotFound paths are logged at
//!   [`tracing::info!`] (operator-visible audit signals); the happy
//!   path is logged at [`tracing::debug!`].

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::error::DomainError;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::jobs_repository::JobsRepository;

use crate::error::{AppError, AppResult};
use crate::metrics::{emit_scan_jobs_enqueued, TriggerSourceLabel};
use crate::use_cases::repository_access::{AccessLevel, RepositoryAccessUseCase};

/// Priority bucket for manual rescans.
///
/// Higher than cron (10) and advisory (5); manual operator action
/// jumps the queue.
const MANUAL_RESCAN_PRIORITY: i16 = 20;

/// `trigger_source` literal for manual rescans
/// ([`hort_domain::ports::jobs_repository::TriggerSource::Manual`]).
const MANUAL_TRIGGER_SOURCE: &str = "manual";

/// Application use case for the manual rescan endpoint.
pub struct ManualRescanUseCase {
    artifacts: Arc<dyn ArtifactRepository>,
    jobs: Arc<dyn JobsRepository>,
    repository_access: Arc<RepositoryAccessUseCase>,
}

impl ManualRescanUseCase {
    /// Construct a new use case from its three port dependencies.
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        jobs: Arc<dyn JobsRepository>,
        repository_access: Arc<RepositoryAccessUseCase>,
    ) -> Self {
        Self {
            artifacts,
            jobs,
            repository_access,
        }
    }

    /// Trigger a manual rescan for the given artifact.
    ///
    /// Returns the newly-inserted `jobs.id` on success. See module-level
    /// doc for the full step sequence and error mapping.
    #[tracing::instrument(skip(self))]
    pub async fn trigger(
        &self,
        actor: Option<&CallerPrincipal>,
        artifact_id: Uuid,
    ) -> AppResult<Uuid> {
        // 1. Load the artifact. NotFound surfaces directly.
        let artifact = match self.artifacts.find_by_id(artifact_id).await {
            Ok(a) => a,
            Err(DomainError::NotFound { .. }) => {
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    id: artifact_id.to_string(),
                }));
            }
            Err(other) => return Err(AppError::Domain(other)),
        };

        // 2. Resolve the parent repository with Write enforcement.
        //    `resolve_by_id` already applies the anti-enumeration collapse:
        //      - invisible repo → NotFound (anti-enumeration)
        //      - Read-visible but no Write → Forbidden
        //      - Write granted → Ok(Repository)
        //    We additionally collapse a NotFound back to "Artifact not
        //    found" so the wire envelope talks about the artifact, not
        //    the repo (parallels `ArtifactUseCase::find_visible_by_id`).
        let repo = match self
            .repository_access
            .resolve_by_id(artifact.repository_id, actor, AccessLevel::Write)
            .await
        {
            Ok(r) => r,
            Err(AppError::Domain(DomainError::NotFound { .. })) => {
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    id: artifact_id.to_string(),
                }));
            }
            Err(other) => return Err(other),
        };

        // 3. Conflict detection — in-flight scan blocks a fresh enqueue.
        if let Some(existing) = self.jobs.find_active_scan_for_artifact(artifact_id).await? {
            tracing::info!(
                %artifact_id,
                existing_job_id = %existing,
                "manual rescan denied — scan already pending or running",
            );
            return Err(AppError::Domain(DomainError::Conflict(format!(
                "scan job already pending or running for artifact {artifact_id} \
                 (existing job_id: {existing})"
            ))));
        }

        // 4. Enqueue. The format string mirrors the ingest path's
        //    convention — `Repository.format`'s `Display` impl renders
        //    the same lowercase literal the worker dispatches on.
        let format = repo.format.to_string();
        let job_id = self
            .jobs
            .enqueue_scan(
                artifact_id,
                artifact.repository_id,
                &artifact.sha256_checksum,
                &format,
                MANUAL_RESCAN_PRIORITY,
                MANUAL_TRIGGER_SOURCE,
            )
            .await?;

        // `hort_scan_jobs_enqueued_total{trigger_source="manual"}`.
        // Emitted only on successful enqueue (the `?` above short-circuits
        // RBAC denials, conflicts, and port errors before we get here),
        // so failure paths never tick this counter.
        emit_scan_jobs_enqueued(TriggerSourceLabel::Manual, 1);

        tracing::debug!(
            %artifact_id,
            %job_id,
            priority = MANUAL_RESCAN_PRIORITY,
            trigger_source = MANUAL_TRIGGER_SOURCE,
            "manual rescan enqueued",
        );
        Ok(job_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use arc_swap::ArcSwap;
    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};

    use crate::rbac::RbacEvaluator;
    use crate::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use crate::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactRepository, MockJobsRepository,
        MockRepositoryRepository,
    };

    /// Build a `RepositoryAccessUseCase` from a pre-seeded repo store
    /// and a fully-formed `RbacEvaluator`. Mirrors the helper shape used
    /// in the security-score tests.
    fn enabled_access(
        repos: Arc<MockRepositoryRepository>,
        evaluator: RbacEvaluator,
    ) -> Arc<RepositoryAccessUseCase> {
        Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(evaluator))),
            true,
        ))
    }

    /// `Disabled` access — admits everything regardless of caller.
    fn disabled_access(repos: Arc<MockRepositoryRepository>) -> Arc<RepositoryAccessUseCase> {
        Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            true,
        ))
    }

    fn caller_with_roles(roles: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: roles.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Build an evaluator where the `role_name` claim carries `permission`
    /// scoped to `repo_id` (claim-based subject model —
    /// `Claims([role_name])`).
    fn evaluator_with_grant(
        role_name: &str,
        repo_id: Uuid,
        permission: Permission,
    ) -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec![role_name.to_string()]),
            repository_id: Some(repo_id),
            permission,
            created_at: Utc::now(),
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    /// Wire the use case + return handles to the seeded mocks so tests
    /// can assert recorded calls. The repository is seeded inside the
    /// caller's `access` use case (its `MockRepositoryRepository`); we
    /// don't take it again here.
    fn wire(
        artifact: Option<hort_domain::entities::artifact::Artifact>,
        access: Arc<RepositoryAccessUseCase>,
    ) -> (
        ManualRescanUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockJobsRepository>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        if let Some(a) = artifact {
            artifacts.insert(a);
        }
        let jobs = Arc::new(MockJobsRepository::new());
        let uc = ManualRescanUseCase::new(artifacts.clone(), jobs.clone(), access);
        (uc, artifacts, jobs)
    }

    // ---------- happy path ------------------------------------------------

    #[tokio::test]
    async fn trigger_happy_path_returns_new_job_id_and_records_priority_and_trigger_source() {
        let mut repo = sample_repository();
        repo.is_public = false; // exercise the RBAC path, not the public-access shortcut
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());

        let actor = caller_with_roles(&["dev"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("dev", repo_id, Permission::Write),
        );

        let (uc, _artifacts, jobs) = wire(Some(artifact.clone()), access);
        let result = uc.trigger(Some(&actor), artifact_id).await;

        let job_id = result.expect("trigger should succeed");
        assert!(job_id != Uuid::nil(), "use case must return a fresh job id");

        let calls = jobs.enqueue_scan_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.artifact_id, artifact_id);
        assert_eq!(call.repository_id, repo_id);
        assert_eq!(call.priority, MANUAL_RESCAN_PRIORITY);
        assert_eq!(
            call.priority, 20,
            "manual-rescan priority contract: manual = 20"
        );
        assert_eq!(call.trigger_source, MANUAL_TRIGGER_SOURCE);
        assert_eq!(call.trigger_source, "manual");
    }

    // ---------- 404: artifact missing -------------------------------------

    #[tokio::test]
    async fn trigger_returns_not_found_when_artifact_missing() {
        let repo = sample_repository();
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let access = disabled_access(repos);
        let (uc, _artifacts, _jobs) = wire(None, access);

        let unknown_id = Uuid::new_v4();
        let err = uc
            .trigger(Some(&caller_with_roles(&[])), unknown_id)
            .await
            .expect_err("expected NotFound");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    ..
                })
            ),
            "expected NotFound for Artifact, got {err:?}"
        );
    }

    // ---------- 404: caller lacks Read on the parent repo -----------------

    #[tokio::test]
    async fn trigger_returns_not_found_when_caller_cannot_read_parent_repo() {
        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());

        // Empty evaluator → caller has neither Read nor Write on the repo;
        // anti-enumeration collapses pure-invisible to NotFound on Write
        // probes too. The use case further collapses to "Artifact"
        // NotFound to avoid leaking repo existence.
        let access = enabled_access(repos, RbacEvaluator::new(Vec::new()));

        let (uc, _artifacts, jobs) = wire(Some(artifact), access);

        let actor = caller_with_roles(&[]);
        let err = uc
            .trigger(Some(&actor), artifact_id)
            .await
            .expect_err("expected NotFound");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "Artifact",
                    ..
                })
            ),
            "expected Artifact NotFound (anti-enumeration), got {err:?}"
        );
        assert_eq!(jobs.enqueue_scan_calls().len(), 0);
    }

    // ---------- 403: caller has Read but not Write -------------------------

    #[tokio::test]
    async fn trigger_returns_forbidden_when_caller_has_read_but_not_write() {
        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());

        // Reader has Read on the repo (so the Read-collapse anti-
        // enumeration arm does NOT fire), but NOT Write — surfaced
        // as Forbidden.
        let actor = caller_with_roles(&["reader"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("reader", repo_id, Permission::Read),
        );

        let (uc, _artifacts, jobs) = wire(Some(artifact), access);

        let err = uc
            .trigger(Some(&actor), artifact_id)
            .await
            .expect_err("expected Forbidden");
        assert!(
            matches!(err, AppError::Domain(DomainError::Forbidden(_))),
            "expected Forbidden, got {err:?}"
        );
        assert_eq!(
            jobs.enqueue_scan_calls().len(),
            0,
            "Forbidden must not enqueue a scan",
        );
    }

    // ---------- 409: in-flight scan ---------------------------------------

    #[tokio::test]
    async fn trigger_returns_conflict_when_in_flight_scan_exists() {
        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());

        let actor = caller_with_roles(&["dev"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("dev", repo_id, Permission::Write),
        );

        let (uc, _artifacts, jobs) = wire(Some(artifact), access);
        let existing_job_id = Uuid::new_v4();
        jobs.seed_active_scan(artifact_id, existing_job_id);

        let err = uc
            .trigger(Some(&actor), artifact_id)
            .await
            .expect_err("expected Conflict");
        assert!(
            matches!(err, AppError::Domain(DomainError::Conflict(_))),
            "expected Conflict, got {err:?}"
        );
        assert_eq!(
            jobs.enqueue_scan_calls().len(),
            0,
            "Conflict path must not call enqueue_scan",
        );
        // Error message names the existing job id so operators can
        // correlate via `/api/v1/admin/tasks/<id>`.
        if let AppError::Domain(DomainError::Conflict(msg)) = err {
            assert!(
                msg.contains(&existing_job_id.to_string()),
                "conflict message must reference the existing job id: {msg}"
            );
        }
    }

    // ---------- enqueue_scan port-side conflict (race with unique idx) ----

    #[tokio::test]
    async fn trigger_propagates_port_conflict_from_enqueue_scan() {
        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());

        let actor = caller_with_roles(&["dev"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("dev", repo_id, Permission::Write),
        );

        let (uc, _artifacts, jobs) = wire(Some(artifact), access);
        // No `seed_active_scan` — so the use-case-side check passes,
        // but the port returns Conflict (mirroring the postgres
        // partial-unique-index race the adapter maps to Conflict).
        jobs.fail_next_enqueue_scan(DomainError::Conflict(
            "scan job already exists for artifact".into(),
        ));

        let err = uc
            .trigger(Some(&actor), artifact_id)
            .await
            .expect_err("expected Conflict propagated from port");
        assert!(
            matches!(err, AppError::Domain(DomainError::Conflict(_))),
            "expected Conflict, got {err:?}"
        );
    }

    // ---------- access disabled (dev mode) — admits everything -----------

    #[tokio::test]
    async fn trigger_succeeds_under_disabled_access() {
        let repo = sample_repository();
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let access = disabled_access(repos);

        let (uc, _artifacts, jobs) = wire(Some(artifact), access);

        // Anonymous (no actor) — `Disabled` admits everything.
        let job_id = uc
            .trigger(None, artifact_id)
            .await
            .expect("disabled admits");
        assert!(job_id != Uuid::nil());
        assert_eq!(jobs.enqueue_scan_calls().len(), 1);
    }

    // ---------- `hort_scan_jobs_enqueued_total{trigger_source="manual"}` ----

    /// Successful trigger emits the counter once with `trigger_source="manual"`
    /// and no high-cardinality labels (forbidden-label rule).
    #[test]
    fn trigger_emits_scan_jobs_enqueued_metric_on_success() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);

        let actor = caller_with_roles(&["dev"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("dev", repo_id, Permission::Write),
        );
        let (uc, _artifacts, _jobs) = wire(Some(artifact), access);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.trigger(Some(&actor), artifact_id))
                .expect("trigger should succeed");
        });

        let snap = snapshotter.snapshot().into_vec();
        let counter = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_scan_jobs_enqueued_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "trigger_source" && l.value() == "manual")
        });
        let (key, _, _, value) =
            counter.expect("hort_scan_jobs_enqueued_total{trigger_source=manual} must fire");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1, "exactly one increment per success"),
            other => panic!("expected Counter, got {other:?}"),
        }
        for forbidden in &["artifact_id", "purl", "user_id", "actor_id", "content_hash"] {
            assert!(
                !key.key().labels().any(|l| l.key() == *forbidden),
                "forbidden label `{forbidden}` must not appear on hort_scan_jobs_enqueued_total",
            );
        }
    }

    /// RBAC denial path must NOT emit the counter — only landed rows tick.
    #[test]
    fn trigger_does_not_emit_scan_jobs_enqueued_on_rbac_denial() {
        use metrics_util::debugging::DebuggingRecorder;
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);

        // Reader has Read but not Write — surfaced as Forbidden.
        let actor = caller_with_roles(&["reader"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("reader", repo_id, Permission::Read),
        );
        let (uc, _artifacts, _jobs) = wire(Some(artifact), access);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.trigger(Some(&actor), artifact_id))
                .expect_err("must Forbidden — RBAC denial");
        });

        let snap = snapshotter.snapshot().into_vec();
        let any_enqueue_counter = snap.iter().any(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter && ck.key().name() == "hort_scan_jobs_enqueued_total"
        });
        assert!(
            !any_enqueue_counter,
            "RBAC denial must NOT increment hort_scan_jobs_enqueued_total"
        );
    }

    /// Conflict path must NOT emit the counter either — the in-flight
    /// scan check fires before the enqueue, so no row landed.
    #[test]
    fn trigger_does_not_emit_scan_jobs_enqueued_on_conflict() {
        use metrics_util::debugging::DebuggingRecorder;
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let mut repo = sample_repository();
        repo.is_public = false;
        let repo_id = repo.id;
        let mut artifact = sample_artifact(QuarantineStatus::Released);
        artifact.repository_id = repo_id;
        let artifact_id = artifact.id;

        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);

        let actor = caller_with_roles(&["dev"]);
        let access = enabled_access(
            repos,
            evaluator_with_grant("dev", repo_id, Permission::Write),
        );
        let (uc, _artifacts, jobs) = wire(Some(artifact), access);
        // Pre-seed an in-flight scan so the use case returns Conflict
        // before reaching the enqueue + metric-emission step.
        jobs.seed_active_scan(artifact_id, Uuid::new_v4());

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.trigger(Some(&actor), artifact_id))
                .expect_err("must Conflict — in-flight scan");
        });

        let snap = snapshotter.snapshot().into_vec();
        let any_enqueue_counter = snap.iter().any(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter && ck.key().name() == "hort_scan_jobs_enqueued_total"
        });
        assert!(
            !any_enqueue_counter,
            "Conflict must NOT increment hort_scan_jobs_enqueued_total — only landed rows tick",
        );
    }
}
