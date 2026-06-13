use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ApiActor, ApprovalDecided, ApprovalDecision, ApprovalRequested, ArtifactPromoted,
    DomainEvent, PolicyEvaluated, PolicyResult, PolicyScope, PromotionRejected, PromotionRequested,
    StreamId,
};
use hort_domain::policy::{evaluate_promotion, PromotionOutcome};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend};

use crate::event_store_publisher::EventStorePublisher;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;

use crate::error::AppResult;
use crate::metrics::{
    emit_policy_evaluation, emit_policy_violations, policy_decision_point, PolicyEvaluationResult,
};
use crate::use_cases::{read_expected_version, scan_history, CallerPrivileges};

/// Application use case for artifact promotion operations.
///
/// Promotion is a single `evaluate_and_promote` call that
/// computes the policy outcome internally — see
/// [`Self::evaluate_and_promote`].
///
/// The remaining surface is:
/// - [`Self::request_promotion`] — the inbound "I want to promote this
///   artifact" signal that records intent on the artifact stream.
/// - [`Self::evaluate_and_promote`] — the policy-driven promotion gate
///   that emits the appropriate audit + state-transition events
///   atomically (Allow / Warn / RequireApproval / Reject).
/// - [`Self::decide_approval`] — the human-reviewer decision flow used
///   when `evaluate_and_promote` returned `RequireApproval`.
/// - [`Self::reject_promotion`] — the explicit operator-driven
///   rejection flow.
pub struct PromotionUseCase {
    artifacts: Arc<dyn ArtifactRepository>,
    repositories: Arc<dyn RepositoryRepository>,
    events: Arc<EventStorePublisher>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    policy_projections: Arc<dyn PolicyProjectionRepository>,
}

impl PromotionUseCase {
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        repositories: Arc<dyn RepositoryRepository>,
        events: Arc<EventStorePublisher>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
    ) -> Self {
        Self {
            artifacts,
            repositories,
            events,
            lifecycle,
            policy_projections,
        }
    }

    /// Request promotion of an artifact from one repository to another.
    ///
    /// Validates caller write access, artifact promotability, and both
    /// repositories exist. Appends a `PromotionRequested` event and
    /// returns the correlation ID.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn request_promotion(
        &self,
        artifact_id: Uuid,
        source_repo_id: Uuid,
        target_repo_id: Uuid,
        actor: ApiActor,
        privileges: CallerPrivileges,
    ) -> AppResult<Uuid> {
        if let Err(e) = privileges.require_write_access(source_repo_id) {
            tracing::info!(artifact_id = %artifact_id, user_id = %actor.user_id, %source_repo_id, "request_promotion denied: no write access to source");
            return Err(e);
        }

        let correlation_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let artifact = self.artifacts.find_by_id(artifact_id).await?;
        if !artifact.is_promotable() {
            // Caller-reachable state precondition (operator requests
            // promotion of a quarantined/rejected artifact) → InvalidState
            // (HTTP 409), NOT Invariant (HTTP 500). ADR 0025.
            return Err(DomainError::InvalidState(
                "artifact is not promotable (quarantined or rejected)".into(),
            )
            .into());
        }

        self.repositories.find_by_id(source_repo_id).await?;
        self.repositories.find_by_id(target_repo_id).await?;

        let expected_version = read_expected_version(&*self.events, &stream_id, true).await?;

        self.events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::PromotionRequested(
                    PromotionRequested {
                        artifact_id,
                        source_repository_id: source_repo_id,
                        target_repository_id: target_repo_id,
                    },
                ))],
                correlation_id,
                causation_id: None,
                actor: Actor::Api(actor),
            })
            .await?;

        Ok(correlation_id)
    }

    /// Evaluate the active policy against the artifact's most recent
    /// scan summary and atomically emit the promotion outcome.
    ///
    /// The policy result is computed inside the domain layer here, not
    /// handed in by the caller — there is deliberately no surface that
    /// accepts a caller-supplied `result`/`violations`.
    ///
    /// Steps:
    /// 1. `privileges.require_write_access(target_repo_id)` — the
    ///    caller must have write access to the destination.
    /// 2. Load the artifact and assert
    ///    [`Artifact::is_promotable`](hort_domain::entities::artifact::Artifact::is_promotable)
    ///    (quarantine invariant 4 — must be `Released`).
    /// 3. Load the target repository (validates existence; the entity
    ///    reference rides into the pure evaluator for forward
    ///    compatibility).
    /// 4. Resolve the active scan policy via
    ///    `policy_projections.list_active()` + scope match (repo-scoped
    ///    wins over global) — same algorithm as `QuarantineUseCase`.
    /// 5. Load exclusions for the resolved policy (empty when no
    ///    policy resolved).
    /// 6. Read the artifact's most recent `ScanCompleted` payload via
    ///    [`scan_history::read_last_scan_completed`]. `None` is the
    ///    clean-baseline fast path; the evaluator handles it.
    /// 7. Call
    ///    [`evaluate_promotion`](hort_domain::policy::evaluate_promotion)
    ///    → [`PromotionOutcome`].
    /// 8. Emit on the artifact stream:
    ///    - `Allow` → `PolicyEvaluated(Pass, []) + ArtifactPromoted`
    ///      via `commit_transition` (atomic with the artifact-state
    ///      bump implied by promotion).
    ///    - `Warn(violations)` → `PolicyEvaluated(Pass, violations) +
    ///      ArtifactPromoted` via `commit_transition`.
    ///    - `RequireApproval(violations)` → `PolicyEvaluated(Pass,
    ///      violations) + ApprovalRequested` via direct
    ///      `events.append` (no artifact state mutation; the
    ///      reviewer's later `decide_approval` is the next state-
    ///      transition trigger).
    ///    - `Reject(violations)` → `PolicyEvaluated(Fail, violations)
    ///      + PromotionRejected { reason }` via direct `events.append`
    ///      (no artifact state mutation; rejection of a promotion is
    ///      not a quarantine-state transition).
    #[tracing::instrument(skip(self, privileges))]
    pub async fn evaluate_and_promote(
        &self,
        artifact_id: Uuid,
        source_repo_id: Uuid,
        target_repo_id: Uuid,
        actor: ApiActor,
        privileges: CallerPrivileges,
    ) -> AppResult<()> {
        if let Err(e) = privileges.require_write_access(target_repo_id) {
            tracing::info!(
                artifact_id = %artifact_id,
                user_id = %actor.user_id,
                %target_repo_id,
                "promotion denied: no write access to target",
            );
            return Err(e);
        }

        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();
        let actor_envelope = Actor::Api(actor);

        let artifact = self.artifacts.find_by_id(artifact_id).await?;
        if !artifact.is_promotable() {
            tracing::info!(
                artifact_id = %artifact_id,
                quarantine_status = %artifact.quarantine_status,
                "promotion blocked: artifact not promotable",
            );
            // Caller-reachable state precondition (operator requests
            // promotion of a quarantined/rejected artifact) → InvalidState
            // (HTTP 409), NOT Invariant (HTTP 500). ADR 0025.
            return Err(DomainError::InvalidState(
                "artifact is not promotable (quarantined or rejected)".into(),
            )
            .into());
        }

        let target_repo = self.repositories.find_by_id(target_repo_id).await?;

        let policy = self.resolve_active_policy_for_repo(target_repo_id).await?;
        let exclusions: Vec<ExclusionProjection> = match &policy {
            Some(p) => {
                self.policy_projections
                    .list_exclusions_for_policy(p.policy_id)
                    .await?
            }
            None => Vec::new(),
        };

        let last_scan_summary = scan_history::read_last_scan_completed(&*self.events, artifact_id)
            .await?
            .map(|s| s.summary);

        let outcome = evaluate_promotion(
            &artifact,
            &target_repo,
            policy.as_ref(),
            last_scan_summary.as_ref(),
            &exclusions,
            Utc::now(),
        );

        let policy_id_for_audit = policy
            .as_ref()
            .map(|p| p.policy_id)
            .unwrap_or_else(Uuid::nil);

        // Read the expected version once for the atomic append. The
        // event-store enforces optimistic concurrency on the call.
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

        match outcome {
            PromotionOutcome::Allow => {
                let policy_event = PolicyEvaluated {
                    artifact_id,
                    policy_id: policy_id_for_audit,
                    result: PolicyResult::Pass,
                    violations: Vec::new(),
                };
                policy_event.validate()?;

                let promoted = ArtifactPromoted {
                    artifact_id,
                    source_repository_id: source_repo_id,
                    target_repository_id: target_repo_id,
                };

                self.lifecycle
                    .commit_transition(
                        &artifact,
                        AppendEvents {
                            stream_id,
                            expected_version,
                            events: vec![
                                EventToAppend::new(DomainEvent::PolicyEvaluated(policy_event)),
                                EventToAppend::new(DomainEvent::ArtifactPromoted(promoted)),
                            ],
                            correlation_id,
                            causation_id: None,
                            actor: actor_envelope,
                        },
                        None,
                    )
                    .await?;

                tracing::info!(
                    artifact_id = %artifact_id,
                    %target_repo_id,
                    policy_id = %policy_id_for_audit,
                    outcome = "allow",
                    violations_count = 0,
                    "promotion evaluated",
                );

                emit_policy_evaluation(
                    policy_decision_point::PROMOTION,
                    PolicyEvaluationResult::Pass,
                );
            }
            PromotionOutcome::Warn(violations) => {
                let violations_count = violations.len();
                let policy_event = PolicyEvaluated {
                    artifact_id,
                    policy_id: policy_id_for_audit,
                    result: PolicyResult::Pass,
                    violations: violations.clone(),
                };
                policy_event.validate()?;

                let promoted = ArtifactPromoted {
                    artifact_id,
                    source_repository_id: source_repo_id,
                    target_repository_id: target_repo_id,
                };

                self.lifecycle
                    .commit_transition(
                        &artifact,
                        AppendEvents {
                            stream_id,
                            expected_version,
                            events: vec![
                                EventToAppend::new(DomainEvent::PolicyEvaluated(policy_event)),
                                EventToAppend::new(DomainEvent::ArtifactPromoted(promoted)),
                            ],
                            correlation_id,
                            causation_id: None,
                            actor: actor_envelope,
                        },
                        None,
                    )
                    .await?;

                tracing::info!(
                    artifact_id = %artifact_id,
                    %target_repo_id,
                    policy_id = %policy_id_for_audit,
                    outcome = "warn",
                    violations_count,
                    "promotion evaluated",
                );

                emit_policy_evaluation(
                    policy_decision_point::PROMOTION,
                    PolicyEvaluationResult::Warn,
                );
                emit_policy_violations(policy_decision_point::PROMOTION, &violations);
            }
            PromotionOutcome::RequireApproval(violations) => {
                let violations_count = violations.len();
                let policy_event = PolicyEvaluated {
                    artifact_id,
                    policy_id: policy_id_for_audit,
                    result: PolicyResult::Pass,
                    violations: violations.clone(),
                };
                policy_event.validate()?;

                let approval = ApprovalRequested {
                    artifact_id,
                    source_repository_id: source_repo_id,
                    target_repository_id: target_repo_id,
                };

                self.events
                    .append(AppendEvents {
                        stream_id,
                        expected_version,
                        events: vec![
                            EventToAppend::new(DomainEvent::PolicyEvaluated(policy_event)),
                            EventToAppend::new(DomainEvent::ApprovalRequested(approval)),
                        ],
                        correlation_id,
                        causation_id: None,
                        actor: actor_envelope,
                    })
                    .await?;

                tracing::info!(
                    artifact_id = %artifact_id,
                    %target_repo_id,
                    policy_id = %policy_id_for_audit,
                    outcome = "require_approval",
                    violations_count,
                    "promotion evaluated",
                );

                emit_policy_evaluation(
                    policy_decision_point::PROMOTION,
                    PolicyEvaluationResult::RequireApproval,
                );
                emit_policy_violations(policy_decision_point::PROMOTION, &violations);
            }
            PromotionOutcome::Reject(violations) => {
                let violations_count = violations.len();
                // First-violation message drives the
                // `PromotionRejected.reason` string; the full violation
                // list is carried by `PolicyEvaluated.violations` for
                // audit. Mirrors `QuarantineUseCase::record_scan_result`
                // for the rejection path.
                let reason = violations
                    .first()
                    .map(|v| v.message.clone())
                    .unwrap_or_else(|| "policy evaluation rejected promotion".to_string());

                let policy_event = PolicyEvaluated {
                    artifact_id,
                    policy_id: policy_id_for_audit,
                    result: PolicyResult::Fail,
                    violations: violations.clone(),
                };
                policy_event.validate()?;

                let rejection = PromotionRejected {
                    artifact_id,
                    source_repository_id: source_repo_id,
                    target_repository_id: target_repo_id,
                    reason,
                };
                rejection.validate()?;

                self.events
                    .append(AppendEvents {
                        stream_id,
                        expected_version,
                        events: vec![
                            EventToAppend::new(DomainEvent::PolicyEvaluated(policy_event)),
                            EventToAppend::new(DomainEvent::PromotionRejected(rejection)),
                        ],
                        correlation_id,
                        causation_id: None,
                        actor: actor_envelope,
                    })
                    .await?;

                tracing::info!(
                    artifact_id = %artifact_id,
                    %target_repo_id,
                    policy_id = %policy_id_for_audit,
                    outcome = "reject",
                    violations_count,
                    "promotion evaluated",
                );

                emit_policy_evaluation(
                    policy_decision_point::PROMOTION,
                    PolicyEvaluationResult::Reject,
                );
                emit_policy_violations(policy_decision_point::PROMOTION, &violations);
            }
        }

        Ok(())
    }

    /// Record a reviewer's approval or rejection decision.
    ///
    /// Requires reviewer or admin privileges. Always appends `ApprovalDecided`.
    /// If the decision is `Rejected`, also appends `PromotionRejected`.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, privileges))]
    pub async fn decide_approval(
        &self,
        artifact_id: Uuid,
        source_repo_id: Uuid,
        target_repo_id: Uuid,
        decision: ApprovalDecision,
        notes: Option<String>,
        actor: ApiActor,
        privileges: CallerPrivileges,
    ) -> AppResult<()> {
        if let Err(e) = privileges.require_reviewer() {
            tracing::info!(artifact_id = %artifact_id, user_id = %actor.user_id, "decide_approval denied: not reviewer");
            return Err(e);
        }

        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();

        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

        let mut events_to_append = vec![EventToAppend::new(DomainEvent::ApprovalDecided(
            ApprovalDecided {
                artifact_id,
                decision,
                notes: notes.clone(),
            },
        ))];

        if decision == ApprovalDecision::Rejected {
            let reason = notes.unwrap_or_else(|| "approval rejected".into());
            events_to_append.push(EventToAppend::new(DomainEvent::PromotionRejected(
                PromotionRejected {
                    artifact_id,
                    source_repository_id: source_repo_id,
                    target_repository_id: target_repo_id,
                    reason,
                },
            )));
        }

        self.events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: events_to_append,
                correlation_id,
                causation_id: None,
                actor: Actor::Api(actor),
            })
            .await?;

        tracing::info!(artifact_id = %artifact_id, ?decision, "approval decided");
        Ok(())
    }

    /// Explicitly reject a pending promotion request.
    ///
    /// Requires write access to either the source or target repository.
    /// Validates that `reason` is non-empty and within the maximum length.
    /// Appends a `PromotionRejected` event.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn reject_promotion(
        &self,
        artifact_id: Uuid,
        source_repo_id: Uuid,
        target_repo_id: Uuid,
        reason: String,
        actor: ApiActor,
        privileges: CallerPrivileges,
    ) -> AppResult<()> {
        let has_source = privileges.require_write_access(source_repo_id).is_ok();
        let has_target = privileges.require_write_access(target_repo_id).is_ok();
        if !has_source && !has_target {
            tracing::info!(artifact_id = %artifact_id, user_id = %actor.user_id, %source_repo_id, %target_repo_id, "reject_promotion denied: no write access to source or target");
            return Err(DomainError::Forbidden(format!(
                "write access required for repository {source_repo_id} or {target_repo_id}"
            ))
            .into());
        }

        let event = PromotionRejected {
            artifact_id,
            source_repository_id: source_repo_id,
            target_repository_id: target_repo_id,
            reason,
        };
        event.validate()?;

        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();

        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

        self.events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::PromotionRejected(event))],
                correlation_id,
                causation_id: None,
                actor: Actor::Api(actor),
            })
            .await?;

        Ok(())
    }

    /// Resolve the active scan policy for `repo_id`.
    ///
    /// Repo-scoped wins over global; absent both, the caller passes
    /// `None` to the evaluator and `DefaultPolicy::block_on_critical`
    /// supplies the threshold. Mirrors
    /// [`QuarantineUseCase::resolve_active_policy_for_repo`](crate::use_cases::quarantine_use_case::QuarantineUseCase)
    /// — the design doc §4 single source of truth becomes a shared
    /// helper module in a future cleanup if a third caller appears.
    async fn resolve_active_policy_for_repo(
        &self,
        repo_id: Uuid,
    ) -> AppResult<Option<ScanPolicyProjection>> {
        let active = self.policy_projections.list_active().await?;
        let mut repo_scoped: Option<ScanPolicyProjection> = None;
        let mut global: Option<ScanPolicyProjection> = None;
        for projection in active {
            match &projection.scope {
                PolicyScope::Repository(id) if *id == repo_id => {
                    repo_scoped = Some(projection);
                }
                PolicyScope::Global if global.is_none() => {
                    global = Some(projection);
                }
                _ => {}
            }
        }
        Ok(repo_scoped.or(global))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::scan_policy::{
        ExclusionProjection, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::events::{
        system_actor, Actor, ApprovalDecision, DomainEvent, PolicyResult, PolicyScope,
        ScanCompleted, SeveritySummary,
    };
    use hort_domain::types::ContentHash;

    use super::*;
    use crate::use_cases::test_support::*;

    type Harness = (
        PromotionUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockRepositoryRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockPolicyProjectionRepository>,
    );

    fn make_use_case() -> Harness {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let repositories = Arc::new(MockRepositoryRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        let uc = PromotionUseCase::new(
            artifacts.clone(),
            repositories.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            lifecycle.clone(),
            policy_projections.clone(),
        );
        (
            uc,
            artifacts,
            repositories,
            events,
            lifecycle,
            policy_projections,
        )
    }

    fn projection_for_repo(
        policy_id: Uuid,
        target_repo_id: Uuid,
        threshold: SeverityThreshold,
        require_approval: bool,
    ) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id,
            name: format!("policy-{policy_id}"),
            scope: PolicyScope::Repository(target_repo_id),
            severity_threshold: threshold,
            quarantine_duration_secs: 0,
            require_approval,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn seed_scan_completed(events: &MockEventStore, artifact_id: Uuid, critical: u32, high: u32) {
        let stream_id = StreamId::artifact(artifact_id);
        let summary = SeveritySummary {
            critical,
            high,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let finding_count = critical + high;
        // `ScanCompleted` invariant: findings blob iff non-empty findings.
        let findings_blob = if finding_count > 0 {
            Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .parse::<ContentHash>()
                    .expect("static valid SHA-256 hex"),
            )
        } else {
            None
        };
        let scan = DomainEvent::ScanCompleted(ScanCompleted {
            artifact_id,
            scanner: "trivy".into(),
            finding_count,
            severity_summary: summary,
            findings_blob,
        });
        events.set_stream(
            &stream_id,
            vec![dummy_persisted_with_event(&stream_id, 0, scan)],
        );
    }

    fn dummy_persisted_with_event(
        stream_id: &StreamId,
        position: u64,
        event: DomainEvent,
    ) -> hort_domain::events::PersistedEvent {
        hort_domain::events::PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: position,
            global_position: position + 1,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(api_actor()),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    // -- request_promotion ----------------------------------------------------

    #[tokio::test]
    async fn request_promotion_success() {
        let (uc, artifacts, repos, events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::None);
        let source = sample_repository();
        let target = sample_repository();
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        repos.insert(source.clone());
        repos.insert(target.clone());

        let actor = api_actor();
        let privs = write_privileges(vec![source.id]);
        let correlation_id = uc
            .request_promotion(artifact_id, source.id, target.id, actor.clone(), privs)
            .await
            .unwrap();

        assert_ne!(correlation_id, Uuid::nil());
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::PromotionRequested(_)
        ));
        assert_eq!(batches[0].actor, Actor::Api(actor));
        assert_eq!(batches[0].correlation_id, correlation_id);
    }

    #[tokio::test]
    async fn request_promotion_without_write_access_forbidden() {
        let (uc, artifacts, repos, _events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::None);
        let source = sample_repository();
        let target = sample_repository();
        artifacts.insert(artifact.clone());
        repos.insert(source.clone());
        repos.insert(target.clone());

        let err = uc
            .request_promotion(
                artifact.id,
                source.id,
                target.id,
                api_actor(),
                unprivileged(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("write access"));
    }

    #[tokio::test]
    async fn request_promotion_quarantined_artifact_fails() {
        let (uc, artifacts, repos, _events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let source = sample_repository();
        let target = sample_repository();
        artifacts.insert(artifact.clone());
        repos.insert(source.clone());
        repos.insert(target.clone());

        let privs = write_privileges(vec![source.id]);
        let err = uc
            .request_promotion(artifact.id, source.id, target.id, api_actor(), privs)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not promotable"));
    }

    #[tokio::test]
    async fn request_promotion_nonexistent_repo_fails() {
        let (uc, artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::None);
        artifacts.insert(artifact.clone());

        let privs = admin_privileges();
        let err = uc
            .request_promotion(
                artifact.id,
                Uuid::new_v4(),
                Uuid::new_v4(),
                api_actor(),
                privs,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- evaluate_and_promote: Allow path -------------------------------------

    #[tokio::test]
    async fn evaluate_and_promote_no_policy_clean_emits_allow() {
        let (uc, artifacts, repos, _events, lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target.clone());

        let actor = api_actor();
        let privs = write_privileges(vec![target_id]);

        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, actor.clone(), privs)
            .await
            .unwrap();

        // Allow path goes through `commit_transition` (atomic state +
        // event append) — committed transitions, not loose appends.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (_committed_artifact, append, _meta) = &transitions[0];
        let evs = &append.events;
        assert_eq!(evs.len(), 2);
        match &evs[0].event {
            DomainEvent::PolicyEvaluated(pe) => {
                assert_eq!(pe.result, PolicyResult::Pass);
                assert!(pe.violations.is_empty());
            }
            other => panic!("expected PolicyEvaluated, got {other:?}"),
        }
        assert!(matches!(&evs[1].event, DomainEvent::ArtifactPromoted(_)));
        assert_eq!(append.actor, Actor::Api(actor));
    }

    #[tokio::test]
    async fn evaluate_and_promote_missing_scan_summary_treats_as_clean() {
        let (uc, artifacts, repos, _events, lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::None); // None is also promotable
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let evs = &transitions[0].1.events;
        assert!(matches!(&evs[0].event, DomainEvent::PolicyEvaluated(_)));
        assert!(matches!(&evs[1].event, DomainEvent::ArtifactPromoted(_)));
    }

    // -- evaluate_and_promote: Warn path --------------------------------------

    #[tokio::test]
    async fn evaluate_and_promote_warn_violations_promote_with_audit() {
        let (uc, artifacts, repos, events, lifecycle, policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        // Low threshold + low finding → Warn (medium severity not present)
        let policy_id = Uuid::new_v4();
        policies.insert(projection_for_repo(
            policy_id,
            target_id,
            SeverityThreshold::Low,
            false,
        ));

        // Seed a low-only ScanCompleted (low severity → Warn)
        let stream_id = StreamId::artifact(artifact_id);
        events.set_stream(
            &stream_id,
            vec![dummy_persisted_with_event(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 1,
                    severity_summary: SeveritySummary {
                        critical: 0,
                        high: 0,
                        medium: 0,
                        low: 1,
                        negligible: 0,
                    },
                    findings_blob: Some(
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            .parse::<ContentHash>()
                            .expect("static valid SHA-256 hex"),
                    ),
                }),
            )],
        );

        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap();

        // Warn path goes through `commit_transition`.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let evs = &transitions[0].1.events;
        assert_eq!(evs.len(), 2);
        match &evs[0].event {
            DomainEvent::PolicyEvaluated(pe) => {
                assert_eq!(pe.result, PolicyResult::Pass);
                assert_eq!(pe.violations.len(), 1);
                assert_eq!(pe.policy_id, policy_id);
            }
            other => panic!("expected PolicyEvaluated, got {other:?}"),
        }
        assert!(matches!(&evs[1].event, DomainEvent::ArtifactPromoted(_)));
    }

    // -- evaluate_and_promote: RequireApproval path ---------------------------

    #[tokio::test]
    async fn evaluate_and_promote_require_approval_emits_approval_request() {
        let (uc, artifacts, repos, events, _lifecycle, policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        // Clean artifact + require_approval = true → RequireApproval(empty)
        let policy_id = Uuid::new_v4();
        policies.insert(projection_for_repo(
            policy_id,
            target_id,
            SeverityThreshold::Critical,
            true,
        ));

        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap();

        let batches = events.appended_batches();
        let last = batches.last().expect("at least one append");
        let evs = &last.events;
        assert_eq!(evs.len(), 2);
        match &evs[0].event {
            DomainEvent::PolicyEvaluated(pe) => {
                assert_eq!(pe.result, PolicyResult::Pass);
                assert!(pe.violations.is_empty());
                assert_eq!(pe.policy_id, policy_id);
            }
            other => panic!("expected PolicyEvaluated, got {other:?}"),
        }
        assert!(matches!(&evs[1].event, DomainEvent::ApprovalRequested(_)));
    }

    // -- evaluate_and_promote: Reject path ------------------------------------

    #[tokio::test]
    async fn evaluate_and_promote_critical_finding_no_policy_rejects_via_default() {
        let (uc, artifacts, repos, events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        seed_scan_completed(&events, artifact_id, 1, 0);

        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap();

        let batches = events.appended_batches();
        let last = batches.last().expect("at least one append");
        let evs = &last.events;
        assert_eq!(evs.len(), 2);
        match &evs[0].event {
            DomainEvent::PolicyEvaluated(pe) => {
                assert_eq!(pe.result, PolicyResult::Fail);
                assert_eq!(pe.violations.len(), 1);
            }
            other => panic!("expected PolicyEvaluated, got {other:?}"),
        }
        match &evs[1].event {
            DomainEvent::PromotionRejected(pr) => {
                assert!(
                    !pr.reason.is_empty(),
                    "reason populated from first violation"
                );
            }
            other => panic!("expected PromotionRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn evaluate_and_promote_reject_with_policy_uses_real_policy_id() {
        let (uc, artifacts, repos, events, _lifecycle, policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        let policy_id = Uuid::new_v4();
        policies.insert(projection_for_repo(
            policy_id,
            target_id,
            SeverityThreshold::Low,
            false,
        ));

        seed_scan_completed(&events, artifact_id, 1, 0);

        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap();

        let batches = events.appended_batches();
        let last = batches.last().expect("at least one append");
        match &last.events[0].event {
            DomainEvent::PolicyEvaluated(pe) => {
                assert_eq!(pe.result, PolicyResult::Fail);
                assert_eq!(pe.policy_id, policy_id);
            }
            other => panic!("expected PolicyEvaluated, got {other:?}"),
        }
    }

    // -- evaluate_and_promote: metric emission -------------------------------

    #[test]
    fn evaluate_and_promote_emits_evaluation_metrics_per_outcome() {
        use crate::metrics::capture_metrics;

        // Allow path: result=pass, no violations counter.
        let snap_allow = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, repos, _events, _lifecycle, _policies) = make_use_case();
                let artifact = sample_artifact(QuarantineStatus::Released);
                let target = sample_repository();
                let artifact_id = artifact.id;
                let target_id = target.id;
                artifacts.insert(artifact);
                repos.insert(target);
                let privs = write_privileges(vec![target_id]);
                uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
                    .await
                    .unwrap();
            });
        });
        let entries = snap_allow.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "promotion")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "pass")
            }),
            "Allow outcome must emit decision_point=promotion, result=pass"
        );
        assert!(
            !entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_violations_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "promotion")
            }),
            "Allow outcome must NOT emit a promotion violations counter"
        );

        // Reject path: result=reject, plus a per-rule violations counter.
        let snap_reject = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, repos, events, _lifecycle, _policies) = make_use_case();
                let artifact = sample_artifact(QuarantineStatus::Released);
                let target = sample_repository();
                let artifact_id = artifact.id;
                let target_id = target.id;
                artifacts.insert(artifact);
                repos.insert(target);
                seed_scan_completed(&events, artifact_id, 1, 0);
                let privs = write_privileges(vec![target_id]);
                uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
                    .await
                    .unwrap();
            });
        });
        let entries = snap_reject.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "reject")
            }),
            "Reject outcome must emit result=reject"
        );
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_violations_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "promotion")
            }),
            "Reject outcome must emit a promotion violations counter"
        );
    }

    // -- evaluate_and_promote: privilege + state guards -----------------------

    #[tokio::test]
    async fn evaluate_and_promote_without_write_access_forbidden() {
        let (uc, artifacts, _repos, events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        artifacts.insert(artifact.clone());

        let err = uc
            .evaluate_and_promote(
                artifact.id,
                Uuid::new_v4(),
                Uuid::new_v4(),
                api_actor(),
                unprivileged(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("write access"));
        // Privilege failure must not append anything.
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn evaluate_and_promote_quarantined_artifact_returns_invalid_state() {
        let (uc, artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let artifact_id = artifact.id;
        artifacts.insert(artifact);

        let target_id = Uuid::new_v4();
        let privs = write_privileges(vec![target_id]);
        let err = uc
            .evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not promotable"));
    }

    #[tokio::test]
    async fn evaluate_and_promote_rejected_artifact_returns_invalid_state() {
        let (uc, artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let artifact_id = artifact.id;
        artifacts.insert(artifact);

        let target_id = Uuid::new_v4();
        let privs = write_privileges(vec![target_id]);
        let err = uc
            .evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not promotable"));
    }

    #[tokio::test]
    async fn evaluate_and_promote_nonexistent_artifact_fails() {
        let (uc, _artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let target_id = Uuid::new_v4();
        let privs = write_privileges(vec![target_id]);
        let err = uc
            .evaluate_and_promote(
                Uuid::new_v4(),
                Uuid::new_v4(),
                target_id,
                api_actor(),
                privs,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn evaluate_and_promote_nonexistent_target_repo_fails() {
        let (uc, artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let artifact_id = artifact.id;
        artifacts.insert(artifact);

        let target_id = Uuid::new_v4();
        let privs = write_privileges(vec![target_id]);
        let err = uc
            .evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- evaluate_and_promote: exclusion clears finding ----------------------

    #[tokio::test]
    async fn evaluate_and_promote_exclusion_clears_critical_to_allow() {
        let (uc, artifacts, repos, events, lifecycle, policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        let policy_id = Uuid::new_v4();
        policies.insert(projection_for_repo(
            policy_id,
            target_id,
            SeverityThreshold::Critical,
            false,
        ));
        // Active, unscoped exclusion clears the only critical finding.
        policies.insert_exclusion(ExclusionProjection {
            exclusion_id: Uuid::new_v4(),
            policy_id,
            cve_id: "CVE-A".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "test".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        seed_scan_completed(&events, artifact_id, 1, 0);

        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, api_actor(), privs)
            .await
            .unwrap();

        // Allow path → commit_transition. The seeded ScanCompleted in
        // `events` is independent — the lifecycle records the new
        // transition.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let evs = &transitions[0].1.events;
        match &evs[0].event {
            DomainEvent::PolicyEvaluated(pe) => {
                assert_eq!(pe.result, PolicyResult::Pass);
                assert!(pe.violations.is_empty());
            }
            other => panic!("expected PolicyEvaluated(Pass), got {other:?}"),
        }
        assert!(matches!(&evs[1].event, DomainEvent::ArtifactPromoted(_)));
    }

    // -- decide_approval ------------------------------------------------------

    #[tokio::test]
    async fn decide_approval_approved() {
        let (uc, _artifacts, _repos, events, _lifecycle, _policies) = make_use_case();

        uc.decide_approval(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            Some("looks good".into()),
            api_actor(),
            reviewer_privileges(),
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].events.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ApprovalDecided(_)
        ));
    }

    #[tokio::test]
    async fn decide_approval_rejected_appends_promotion_rejected() {
        let (uc, _artifacts, _repos, events, _lifecycle, _policies) = make_use_case();
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        uc.decide_approval(
            Uuid::new_v4(),
            source_id,
            target_id,
            ApprovalDecision::Rejected,
            Some("not ready".into()),
            api_actor(),
            reviewer_privileges(),
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].events.len(), 2);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ApprovalDecided(_)
        ));
        assert!(matches!(
            &batches[0].events[1].event,
            DomainEvent::PromotionRejected(_)
        ));
        if let DomainEvent::PromotionRejected(pr) = &batches[0].events[1].event {
            assert_eq!(pr.source_repository_id, source_id);
            assert_eq!(pr.target_repository_id, target_id);
        } else {
            panic!("expected PromotionRejected");
        }
    }

    #[tokio::test]
    async fn decide_approval_rejected_no_notes_uses_default_reason() {
        let (uc, _artifacts, _repos, events, _lifecycle, _policies) = make_use_case();

        uc.decide_approval(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            ApprovalDecision::Rejected,
            None,
            api_actor(),
            reviewer_privileges(),
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].events.len(), 2);
        if let DomainEvent::PromotionRejected(pr) = &batches[0].events[1].event {
            assert_eq!(pr.reason, "approval rejected");
        } else {
            panic!("expected PromotionRejected");
        }
    }

    #[tokio::test]
    async fn decide_approval_without_reviewer_forbidden() {
        let (uc, _artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();

        let err = uc
            .decide_approval(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                ApprovalDecision::Approved,
                None,
                api_actor(),
                unprivileged(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("reviewer"));
    }

    #[tokio::test]
    async fn decide_approval_actor_recorded_on_event_envelope() {
        let (uc, _artifacts, _repos, events, _lifecycle, _policies) = make_use_case();
        let actor = api_actor();

        uc.decide_approval(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            None,
            actor.clone(),
            reviewer_privileges(),
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].actor, Actor::Api(actor));
    }

    // -- reject_promotion -----------------------------------------------------

    #[tokio::test]
    async fn reject_promotion_success() {
        let (uc, _artifacts, _repos, events, _lifecycle, _policies) = make_use_case();
        let source_id = Uuid::new_v4();
        let privs = write_privileges(vec![source_id]);

        uc.reject_promotion(
            Uuid::new_v4(),
            source_id,
            Uuid::new_v4(),
            "not ready".into(),
            api_actor(),
            privs,
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::PromotionRejected(_)
        ));
    }

    #[tokio::test]
    async fn reject_promotion_write_access_to_target_also_works() {
        let (uc, _artifacts, _repos, events, _lifecycle, _policies) = make_use_case();
        let target_id = Uuid::new_v4();
        let privs = write_privileges(vec![target_id]);

        uc.reject_promotion(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_id,
            "not wanted".into(),
            api_actor(),
            privs,
        )
        .await
        .unwrap();

        assert_eq!(events.appended_batches().len(), 1);
    }

    #[tokio::test]
    async fn reject_promotion_no_access_forbidden() {
        let (uc, _artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();

        let err = uc
            .reject_promotion(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                "reason".into(),
                api_actor(),
                unprivileged(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("write access"));
    }

    #[tokio::test]
    async fn reject_promotion_oversized_reason_fails() {
        let (uc, _artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let source_id = Uuid::new_v4();
        let privs = write_privileges(vec![source_id]);

        let err = uc
            .reject_promotion(
                Uuid::new_v4(),
                source_id,
                Uuid::new_v4(),
                "x".repeat(5000),
                api_actor(),
                privs,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("validation") || err.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn reject_promotion_empty_reason_fails() {
        let (uc, _artifacts, _repos, _events, _lifecycle, _policies) = make_use_case();
        let source_id = Uuid::new_v4();
        let privs = write_privileges(vec![source_id]);

        let err = uc
            .reject_promotion(
                Uuid::new_v4(),
                source_id,
                Uuid::new_v4(),
                "".into(),
                api_actor(),
                privs,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("validation") || err.to_string().contains("empty"));
    }

    // -- system_actor / commit_transition usage -------------------------------

    #[tokio::test]
    async fn evaluate_and_promote_uses_caller_actor_envelope_not_system() {
        // Sanity: the promotion path threads the caller's ApiActor
        // through the event envelope (audit attribution). Only the
        // QuarantineUseCase / PolicyUseCase background passes use
        // `system_actor()`.
        let (uc, artifacts, repos, _events, lifecycle, _policies) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Released);
        let target = sample_repository();
        let artifact_id = artifact.id;
        let target_id = target.id;
        artifacts.insert(artifact);
        repos.insert(target);

        let actor = api_actor();
        let privs = write_privileges(vec![target_id]);
        uc.evaluate_and_promote(artifact_id, Uuid::new_v4(), target_id, actor.clone(), privs)
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions[0].1.actor, Actor::Api(actor));
        assert_ne!(transitions[0].1.actor, system_actor());
    }
}
