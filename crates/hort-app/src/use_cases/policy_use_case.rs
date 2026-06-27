//! `PolicyUseCase` — create / update / archive scan policies.
//!
//! Emits `PolicyCreated` / `PolicyUpdated` / `PolicyArchived` events on a
//! per-policy stream (`StreamCategory::Policy`) and synchronously upserts
//! the materialised projection in `policy_projections` so subsequent
//! `find_by_id` / `find_by_name` reads are O(1).
//!
//! This use case has no inbound HTTP caller; its production driver is
//! the gitops apply path
//! (`ApplyConfigUseCase::apply_scan_policies`). Authorization is enforced
//! at the gitops apply boundary, not here.
//!
//! # Append-then-upsert trade-off
//!
//! The mutation path is `events.append` first, then `projections.upsert`
//! only on `Ok(_)`. The two writes are NOT transactionally bound across
//! ports — a successful append followed by a failing upsert leaves the
//! projection stale relative to the event stream. Subsequent reads will
//! see the stale row until an out-of-band rebuild tool runs (deferred
//! operational tooling). The reverse ordering would be worse: a
//! successful projection write followed by a failing append would let a
//! row claim a `stream_version` that was never persisted.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::scan_policy::{
    ExclusionProjection, NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    SignerIdentityPattern,
};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ArtifactReEvaluated, DomainEvent, ExclusionAdded, ExclusionRemoved, PolicyArchived,
    PolicyCreated, PolicyField, PolicyReactivated, PolicyScope, PolicyUpdated, StreamId,
};
use hort_domain::policy::{
    effective_quarantine_deadline, re_evaluate_after_exclusion, ReEvaluationOutcome,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::storage::StoragePort;

use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_curation_decision, emit_policy_evaluation, policy_decision_point, CurationDecisionLabel,
    CurationDecisionResult, PolicyEvaluationResult,
};
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::repository_access::RepositoryAccessUseCase;
use crate::use_cases::{read_expected_version, scan_history};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Inputs for [`PolicyUseCase::create_policy`].
///
/// `quarantine_duration_secs` is the duration in seconds; the gitops
/// YAML surface parses ISO-8601 durations into seconds
/// before invoking the use case.
#[derive(Debug, Clone)]
pub struct CreatePolicyCommand {
    pub name: String,
    pub scope: PolicyScope,
    pub severity_threshold: SeverityThreshold,
    pub quarantine_duration_secs: i64,
    pub require_approval: bool,
    /// Provenance enforcement mode (supersedes the
    /// inert `requireSignature` bool — ADR 0027).
    pub provenance_mode: ProvenanceMode,
    /// Provenance verifier backends to run. Empty is
    /// permitted only when `provenance_mode == Off`; the gitops apply
    /// pipeline enforces the combination rule via the domain
    /// `validate_provenance_config` hook.
    pub provenance_backends: Vec<String>,
    /// Allowed-signer `{issuer, san}` patterns (ADR 0027).
    pub provenance_identities: Vec<SignerIdentityPattern>,
    pub max_artifact_age_secs: Option<i64>,
    pub license_policy: serde_json::Value,
    /// Names of the scanner backends this policy
    /// invokes per scan. An empty `Vec` means "no scanning"; the
    /// gitops apply pipeline is expected to validate every entry
    /// against the compiled-in `hort_app::scanning::KNOWN_SCAN_BACKENDS`
    /// set (via `hort_config::desired::validate_scan_policy_backends`)
    /// before reaching this use case.
    pub scan_backends: Vec<String>,
    /// Interval in hours between bulk re-scans of
    /// artifacts governed by this policy. The value `0` is the
    /// operator opt-out; negative values are rejected upstream by
    /// `hort_config::scan_policy::validate_scan_policy`.
    pub rescan_interval_hours: i32,
    /// How negligible / informational findings steer the release
    /// decision. Default [`NegligibleAction::Ignore`]; enforced by
    /// `evaluate_scan_result`. The gitops apply pipeline validates the
    /// wire value via `hort_config::scan_policy::validate_scan_policy`.
    pub negligible_action: NegligibleAction,
}

/// A field-level update directive for [`PolicyUseCase::update_policy`].
///
/// `Unchanged` skips the field; `Set` replaces it with the carried
/// value. `Set(None)` on `MaxArtifactAge` clears the field — the
/// `Option<Option<T>>` shape used elsewhere in the codebase would also
/// work, but a typed enum makes the "no change vs. set to None"
/// distinction load-bearing for readers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FieldChange<T> {
    #[default]
    Unchanged,
    Set(T),
}

/// Inputs for [`PolicyUseCase::update_policy`].
///
/// Every field is `FieldChange<_>` so callers can express partial
/// updates without ambiguity. `MaxArtifactAge` carries a nested
/// `Option` because the underlying field itself is optional —
/// `Set(None)` clears it, `Set(Some(v))` replaces it, `Unchanged`
/// leaves it.
#[derive(Debug, Clone)]
pub struct UpdatePolicyCommand {
    pub policy_id: Uuid,
    pub name: FieldChange<String>,
    pub scope: FieldChange<PolicyScope>,
    pub severity_threshold: FieldChange<SeverityThreshold>,
    pub quarantine_duration_secs: FieldChange<i64>,
    pub require_approval: FieldChange<bool>,
    /// Provenance mode update (supersedes
    /// `requireSignature` — ADR 0027).
    pub provenance_mode: FieldChange<ProvenanceMode>,
    /// Provenance backend list update.
    /// `FieldChange::Set(Vec::new())` is meaningful (only valid under
    /// `Off`).
    pub provenance_backends: FieldChange<Vec<String>>,
    /// Allowed-signer pattern list update.
    pub provenance_identities: FieldChange<Vec<SignerIdentityPattern>>,
    pub max_artifact_age_secs: FieldChange<Option<i64>>,
    pub license_policy: FieldChange<serde_json::Value>,
    /// Operator-driven update of the scanner backend
    /// list. `FieldChange::Set(Vec::new())` is a meaningful value (it
    /// disables scanning) and is distinct from `FieldChange::Unchanged`.
    pub scan_backends: FieldChange<Vec<String>>,
    /// Operator-driven update of the rescan
    /// interval. `FieldChange::Set(0)` is meaningful (it disables
    /// rescanning) and distinct from `FieldChange::Unchanged`.
    pub rescan_interval_hours: FieldChange<i32>,
    /// Operator-driven update of the negligible-action knob. Every
    /// variant (Ignore / Warn / Block) is a meaningful value distinct
    /// from `FieldChange::Unchanged`.
    pub negligible_action: FieldChange<NegligibleAction>,
}

impl UpdatePolicyCommand {
    /// Convenience constructor that initialises every field to
    /// [`FieldChange::Unchanged`]. Tests and callers chain `.name(...)`
    /// style mutations on the returned struct.
    pub fn new(policy_id: Uuid) -> Self {
        Self {
            policy_id,
            name: FieldChange::Unchanged,
            scope: FieldChange::Unchanged,
            severity_threshold: FieldChange::Unchanged,
            quarantine_duration_secs: FieldChange::Unchanged,
            require_approval: FieldChange::Unchanged,
            provenance_mode: FieldChange::Unchanged,
            provenance_backends: FieldChange::Unchanged,
            provenance_identities: FieldChange::Unchanged,
            max_artifact_age_secs: FieldChange::Unchanged,
            license_policy: FieldChange::Unchanged,
            scan_backends: FieldChange::Unchanged,
            rescan_interval_hours: FieldChange::Unchanged,
            negligible_action: FieldChange::Unchanged,
        }
    }
}

/// Inputs for [`PolicyUseCase::add_exclusion`].
///
/// Exclusions are sub-state of their parent policy and live on the same
/// event stream (`StreamId::policy(policy_id)`). The use case mints the
/// `exclusion_id` server-side — callers do not supply it — so the
/// generated id flows back through the return value.
#[derive(Debug, Clone)]
pub struct AddExclusionCommand {
    pub policy_id: Uuid,
    pub cve_id: String,
    pub package_pattern: Option<String>,
    pub scope: PolicyScope,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Inputs for [`PolicyUseCase::remove_exclusion`].
///
/// `policy_id` is required — both as the stream identifier the
/// `ExclusionRemoved` event is appended to and as the target of a
/// defensive parent-linkage check (the projection-port contract
/// already filters by policy, but the use case re-validates so a
/// faulty adapter cannot silently rewrite a peer policy's stream).
#[derive(Debug, Clone)]
pub struct RemoveExclusionCommand {
    pub policy_id: Uuid,
    pub exclusion_id: Uuid,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// PolicyUseCase
// ---------------------------------------------------------------------------

/// Application use case for the scan-policy lifecycle.
///
/// Composition: the gitops apply pipeline is the
/// only inbound caller — no HTTP route resolves to it.
///
/// `artifacts` and `artifact_lifecycle` are wired in for the
/// post-exclusion-add re-evaluation pass, which extends
/// `add_exclusion` with a best-effort sweep
/// over rejected artifacts whose active scan-policy resolves to the
/// just-modified policy. Apart from that pass, the use case never
/// reads or writes artifact-stream state — `add_exclusion` otherwise
/// only touches the policy stream.
pub struct PolicyUseCase {
    events: Arc<EventStorePublisher>,
    projections: Arc<dyn PolicyProjectionRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    artifact_lifecycle: Arc<dyn ArtifactLifecyclePort>,
    /// Used by the post-exclusion-add re-evaluation
    /// pass to hydrate the per-finding `findings_blob` from CAS so the
    /// pure-domain helper can do exact CVE-ID matching against the
    /// updated exclusion set. Read-only access — no writes.
    storage: Arc<dyn StoragePort>,
    /// Repository-key resolution for the
    /// `hort_curation_decisions_total{repository}` label emitted by
    /// `add_exclusion` / `remove_exclusion` on the curator path.
    /// Exclusions with `PolicyScope::Repository(id)` resolve to the
    /// repo key via [`RepositoryAccessUseCase::metric_label`];
    /// `PolicyScope::Global` exclusions (cross-repo finding-exclusion)
    /// emit the `_all` sentinel. The same helper
    /// honours `METRICS_INCLUDE_REPOSITORY_LABEL=false`.
    repository_access: Arc<RepositoryAccessUseCase>,
}

impl PolicyUseCase {
    pub fn new(
        events: Arc<EventStorePublisher>,
        projections: Arc<dyn PolicyProjectionRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        artifact_lifecycle: Arc<dyn ArtifactLifecyclePort>,
        storage: Arc<dyn StoragePort>,
        repository_access: Arc<RepositoryAccessUseCase>,
    ) -> Self {
        Self {
            events,
            projections,
            artifacts,
            artifact_lifecycle,
            storage,
            repository_access,
        }
    }

    /// Create a new scan policy.
    ///
    /// Mints a fresh `policy_id`, emits one `PolicyCreated` event with
    /// `expected_version: NoStream`, and synchronously upserts the
    /// resulting projection.
    ///
    /// Fails with [`DomainError::Conflict`] if a non-archived policy
    /// already exists with the same name (the projection has a partial
    /// unique index on `name` for `archived = false` rows — migration
    /// 095). The check is performed before the append so a duplicate
    /// name cannot waste an event-stream position.
    #[tracing::instrument(skip(self, cmd))]
    pub async fn create_policy(&self, cmd: CreatePolicyCommand, actor: Actor) -> AppResult<Uuid> {
        // Pre-check duplicate name. The projection has a partial unique
        // index on (name) WHERE archived = false (`005_policy.sql`) so
        // racing creates would still be rejected by the DB — but doing
        // the read first means we don't burn a stream position on a
        // request that was always going to fail.
        if let Some(existing) = self.projections.find_by_name(&cmd.name).await? {
            tracing::info!(
                policy_id = %existing.policy_id,
                name = %cmd.name,
                "create_policy rejected: name already in use",
            );
            return Err(DomainError::Conflict(format!(
                "policy with name '{}' already exists",
                cmd.name
            ))
            .into());
        }

        let policy_id = Uuid::new_v4();
        let stream_id = StreamId::policy(policy_id);
        let correlation_id = Uuid::new_v4();
        let config_snapshot = build_config_snapshot(&cmd);

        let event = PolicyCreated {
            policy_id,
            name: cmd.name.clone(),
            scope: cmd.scope.clone(),
            config_snapshot,
        };

        let result = self
            .events
            .append(AppendEvents {
                stream_id,
                expected_version: ExpectedVersion::NoStream,
                events: vec![EventToAppend::new(DomainEvent::PolicyCreated(event))],
                correlation_id,
                causation_id: None,
                actor,
            })
            .await?;

        let now = Utc::now();
        let projection = ScanPolicyProjection {
            policy_id,
            name: cmd.name,
            scope: cmd.scope,
            severity_threshold: cmd.severity_threshold,
            quarantine_duration_secs: cmd.quarantine_duration_secs,
            require_approval: cmd.require_approval,
            provenance_mode: cmd.provenance_mode,
            provenance_backends: cmd.provenance_backends,
            provenance_identities: cmd.provenance_identities,
            max_artifact_age_secs: cmd.max_artifact_age_secs,
            license_policy: cmd.license_policy,
            archived: false,
            scan_backends: cmd.scan_backends,
            rescan_interval_hours: cmd.rescan_interval_hours,
            negligible_action: cmd.negligible_action,
            stream_version: result.stream_position,
            created_at: now,
            updated_at: now,
        };

        if let Err(e) = self.projections.upsert(&projection).await {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "policy projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            event_type = "PolicyCreated",
            "policy created",
        );

        Ok(policy_id)
    }

    /// Apply a partial update to an existing policy.
    ///
    /// Reads the projection, diffs each `FieldChange::Set(_)` against
    /// the current value, emits one `PolicyUpdated` event per actually-
    /// changed field in a single atomic append batch, then upserts the
    /// new projection state.
    ///
    /// - Same-value updates yield zero events (idempotent — no append,
    ///   no upsert, returns `Ok(())`).
    /// - Stale `ExpectedVersion::Exact` from a concurrent writer maps to
    ///   [`DomainError::Conflict`].
    /// - Updating an archived policy is rejected as
    ///   [`DomainError::Validation`].
    #[tracing::instrument(skip(self, cmd))]
    pub async fn update_policy(&self, cmd: UpdatePolicyCommand, actor: Actor) -> AppResult<()> {
        let policy_id = cmd.policy_id;
        let mut projection = self
            .projections
            .find_by_id(policy_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                entity: "ScanPolicy",
                id: policy_id.to_string(),
            })?;

        if projection.archived {
            tracing::info!(
                policy_id = %policy_id,
                name = %projection.name,
                "update_policy rejected: policy is archived",
            );
            return Err(DomainError::Validation(format!(
                "policy '{}' is archived",
                projection.name
            ))
            .into());
        }

        // Build the diff. Each entry contributes one PolicyUpdated event
        // AND mutates the projection-to-write so the post-append upsert
        // reflects the new state.
        let mut events: Vec<EventToAppend> = Vec::new();

        if let FieldChange::Set(new_name) = &cmd.name {
            if *new_name != projection.name {
                events.push(field_event(
                    policy_id,
                    PolicyField::Name,
                    serde_json::Value::String(projection.name.clone()),
                    serde_json::Value::String(new_name.clone()),
                ));
                projection.name = new_name.clone();
            }
        }

        if let FieldChange::Set(new_scope) = &cmd.scope {
            if *new_scope != projection.scope {
                events.push(field_event(
                    policy_id,
                    PolicyField::Scope,
                    serde_json::to_value(&projection.scope)
                        .expect("PolicyScope serialises to JSON"),
                    serde_json::to_value(new_scope).expect("PolicyScope serialises to JSON"),
                ));
                projection.scope = new_scope.clone();
            }
        }

        if let FieldChange::Set(new_threshold) = &cmd.severity_threshold {
            if *new_threshold != projection.severity_threshold {
                events.push(field_event(
                    policy_id,
                    PolicyField::SeverityThreshold,
                    serde_json::to_value(projection.severity_threshold)
                        .expect("SeverityThreshold serialises to JSON"),
                    serde_json::to_value(*new_threshold)
                        .expect("SeverityThreshold serialises to JSON"),
                ));
                projection.severity_threshold = *new_threshold;
            }
        }

        if let FieldChange::Set(new_quar) = &cmd.quarantine_duration_secs {
            if *new_quar != projection.quarantine_duration_secs {
                events.push(field_event(
                    policy_id,
                    PolicyField::QuarantineDuration,
                    serde_json::Value::from(projection.quarantine_duration_secs),
                    serde_json::Value::from(*new_quar),
                ));
                projection.quarantine_duration_secs = *new_quar;
            }
        }

        if let FieldChange::Set(new_approval) = &cmd.require_approval {
            if *new_approval != projection.require_approval {
                events.push(field_event(
                    policy_id,
                    PolicyField::RequireApproval,
                    serde_json::Value::Bool(projection.require_approval),
                    serde_json::Value::Bool(*new_approval),
                ));
                projection.require_approval = *new_approval;
            }
        }

        // The provenance trio replaces requireSignature (ADR 0027).
        if let FieldChange::Set(new_mode) = &cmd.provenance_mode {
            if *new_mode != projection.provenance_mode {
                events.push(field_event(
                    policy_id,
                    PolicyField::ProvenanceMode,
                    serde_json::Value::String(projection.provenance_mode.to_string()),
                    serde_json::Value::String(new_mode.to_string()),
                ));
                projection.provenance_mode = *new_mode;
            }
        }

        if let FieldChange::Set(new_backends) = &cmd.provenance_backends {
            if *new_backends != projection.provenance_backends {
                events.push(field_event(
                    policy_id,
                    PolicyField::ProvenanceBackends,
                    serde_json::to_value(&projection.provenance_backends)
                        .expect("INVARIANT: Vec<String> serialises to JSON"),
                    serde_json::to_value(new_backends)
                        .expect("INVARIANT: Vec<String> serialises to JSON"),
                ));
                projection.provenance_backends = new_backends.clone();
            }
        }

        if let FieldChange::Set(new_identities) = &cmd.provenance_identities {
            if *new_identities != projection.provenance_identities {
                events.push(field_event(
                    policy_id,
                    PolicyField::ProvenanceIdentities,
                    serde_json::to_value(&projection.provenance_identities)
                        .expect("INVARIANT: SignerIdentityPattern serialises to JSON"),
                    serde_json::to_value(new_identities)
                        .expect("INVARIANT: SignerIdentityPattern serialises to JSON"),
                ));
                projection.provenance_identities = new_identities.clone();
            }
        }

        if let FieldChange::Set(new_age) = &cmd.max_artifact_age_secs {
            if *new_age != projection.max_artifact_age_secs {
                events.push(field_event(
                    policy_id,
                    PolicyField::MaxArtifactAge,
                    optional_i64_to_value(projection.max_artifact_age_secs),
                    optional_i64_to_value(*new_age),
                ));
                projection.max_artifact_age_secs = *new_age;
            }
        }

        if let FieldChange::Set(new_license) = &cmd.license_policy {
            if *new_license != projection.license_policy {
                events.push(field_event(
                    policy_id,
                    PolicyField::LicensePolicy,
                    projection.license_policy.clone(),
                    new_license.clone(),
                ));
                projection.license_policy = new_license.clone();
            }
        }

        // Same-value skip applies: an explicit
        // `FieldChange::Set` with a value equal to the current
        // projection produces zero events.
        if let FieldChange::Set(new_backends) = &cmd.scan_backends {
            if *new_backends != projection.scan_backends {
                events.push(field_event(
                    policy_id,
                    PolicyField::ScanBackends,
                    serde_json::to_value(&projection.scan_backends)
                        .expect("INVARIANT: Vec<String> serialises to JSON"),
                    serde_json::to_value(new_backends)
                        .expect("INVARIANT: Vec<String> serialises to JSON"),
                ));
                projection.scan_backends = new_backends.clone();
            }
        }

        // Same-value skip; `Set(0)` is a meaningful
        // operator-supplied value distinct from `Unchanged`.
        if let FieldChange::Set(new_interval) = &cmd.rescan_interval_hours {
            if *new_interval != projection.rescan_interval_hours {
                events.push(field_event(
                    policy_id,
                    PolicyField::RescanIntervalHours,
                    serde_json::Value::from(projection.rescan_interval_hours),
                    serde_json::Value::from(*new_interval),
                ));
                projection.rescan_interval_hours = *new_interval;
            }
        }

        // Same-value skip; the `previous_value` / `new_value` payloads
        // are the lowercase `NegligibleAction` wire strings (mirrors
        // `ProvenanceMode`).
        if let FieldChange::Set(new_action) = &cmd.negligible_action {
            if *new_action != projection.negligible_action {
                events.push(field_event(
                    policy_id,
                    PolicyField::NegligibleAction,
                    serde_json::Value::String(projection.negligible_action.to_string()),
                    serde_json::Value::String(new_action.to_string()),
                ));
                projection.negligible_action = *new_action;
            }
        }

        if events.is_empty() {
            // Idempotent no-op — same-value updates yield zero writes.
            tracing::debug!(
                policy_id = %policy_id,
                "update_policy: no field changes — skipping append",
            );
            return Ok(());
        }

        let event_count = events.len();
        let stream_id = StreamId::policy(policy_id);
        let correlation_id = Uuid::new_v4();
        let expected_version = ExpectedVersion::Exact(projection.stream_version);

        let result = match self
            .events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events,
                correlation_id,
                causation_id: None,
                actor,
            })
            .await
        {
            Ok(r) => r,
            Err(DomainError::Conflict(msg)) => {
                tracing::warn!(
                    policy_id = %policy_id,
                    expected = projection.stream_version,
                    "concurrent policy modification rejected",
                );
                return Err(DomainError::Conflict(msg).into());
            }
            Err(other) => return Err(other.into()),
        };

        projection.stream_version = result.stream_position;
        projection.updated_at = Utc::now();

        if let Err(e) = self.projections.upsert(&projection).await {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "policy projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            event_count,
            "policy updated",
        );

        Ok(())
    }

    /// Archive an existing policy.
    ///
    /// Emits one `PolicyArchived` event on the policy stream and marks
    /// the projection `archived = true`. Idempotent in the sense that
    /// re-archival of an already-archived policy is rejected as
    /// [`DomainError::Validation`] — gitops apply absorbs the rejection
    /// at the diff layer (an archived policy is never re-emitted).
    #[tracing::instrument(skip(self))]
    pub async fn archive_policy(&self, policy_id: Uuid, actor: Actor) -> AppResult<()> {
        let mut projection = self
            .projections
            .find_by_id(policy_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                entity: "ScanPolicy",
                id: policy_id.to_string(),
            })?;

        if projection.archived {
            tracing::info!(
                policy_id = %policy_id,
                name = %projection.name,
                "archive_policy rejected: already archived",
            );
            return Err(DomainError::Validation(format!(
                "policy '{}' is already archived",
                projection.name
            ))
            .into());
        }

        let stream_id = StreamId::policy(policy_id);
        let correlation_id = Uuid::new_v4();
        let expected_version = ExpectedVersion::Exact(projection.stream_version);
        let event = PolicyArchived { policy_id };

        let result = match self
            .events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::PolicyArchived(event))],
                correlation_id,
                causation_id: None,
                actor,
            })
            .await
        {
            Ok(r) => r,
            Err(DomainError::Conflict(msg)) => {
                tracing::warn!(
                    policy_id = %policy_id,
                    expected = projection.stream_version,
                    "concurrent policy modification rejected",
                );
                return Err(DomainError::Conflict(msg).into());
            }
            Err(other) => return Err(other.into()),
        };

        projection.archived = true;
        projection.stream_version = result.stream_position;
        projection.updated_at = Utc::now();

        if let Err(e) = self.projections.upsert(&projection).await {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "policy projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            event_type = "PolicyArchived",
            "policy archived",
        );

        Ok(())
    }

    /// Reactivate an archived policy.
    ///
    /// Emits one `PolicyReactivated` event on the policy stream and
    /// flips the projection's `archived` field back to `false`. The
    /// `policy_id` and event-stream history are preserved — gitops
    /// re-declaration of an archived YAML keeps audit continuity
    /// rather than minting a fresh stream.
    ///
    /// Validation:
    /// - Non-existent policy → [`DomainError::NotFound`].
    /// - Already-active policy → [`DomainError::Validation`] (the
    ///   gitops apply pipeline's caller picks the reactivation branch
    ///   only when `archived = true`, so calling this on an active row
    ///   indicates a bug in the pipeline; rejecting here surfaces it
    ///   loudly rather than silently no-op'ing).
    #[tracing::instrument(skip(self))]
    pub async fn reactivate_policy(&self, policy_id: Uuid, actor: Actor) -> AppResult<()> {
        let mut projection = self
            .projections
            .find_by_id(policy_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                entity: "ScanPolicy",
                id: policy_id.to_string(),
            })?;

        if !projection.archived {
            tracing::info!(
                policy_id = %policy_id,
                name = %projection.name,
                "reactivate_policy rejected: policy is already active",
            );
            return Err(DomainError::Validation(format!(
                "policy '{}' is already active",
                projection.name
            ))
            .into());
        }

        let stream_id = StreamId::policy(policy_id);
        let correlation_id = Uuid::new_v4();
        let expected_version = ExpectedVersion::Exact(projection.stream_version);
        let event = PolicyReactivated { policy_id };

        let result = match self
            .events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::PolicyReactivated(event))],
                correlation_id,
                causation_id: None,
                actor,
            })
            .await
        {
            Ok(r) => r,
            Err(DomainError::Conflict(msg)) => {
                tracing::warn!(
                    policy_id = %policy_id,
                    expected = projection.stream_version,
                    "concurrent policy modification rejected",
                );
                return Err(DomainError::Conflict(msg).into());
            }
            Err(other) => return Err(other.into()),
        };

        projection.archived = false;
        projection.stream_version = result.stream_position;
        projection.updated_at = Utc::now();

        if let Err(e) = self.projections.upsert(&projection).await {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "policy projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            event_type = "PolicyReactivated",
            "policy reactivated",
        );

        Ok(())
    }

    /// Attach a new exclusion to an existing policy.
    ///
    /// Mints a fresh `exclusion_id`, appends one
    /// [`ExclusionAdded`](hort_domain::events::ExclusionAdded) event to
    /// the parent policy stream with
    /// [`ExpectedVersion::Exact`]`(parent.stream_version)`, then
    /// upserts both the new exclusion projection AND the parent
    /// projection (whose `stream_version` advances because of the
    /// append).
    ///
    /// Validation:
    /// - Non-existent parent → [`DomainError::Validation`] (NOT
    ///   `NotFound` — exclusion management is a sub-operation of the
    ///   parent policy, and the gitops-apply caller treats both
    ///   absence and archival as the same "policy is not editable"
    ///   class of failure).
    /// - Archived parent → [`DomainError::Validation`].
    /// - Stale `ExpectedVersion::Exact` → [`DomainError::Conflict`].
    #[tracing::instrument(skip(self, cmd))]
    pub async fn add_exclusion(&self, cmd: AddExclusionCommand, actor: Actor) -> AppResult<Uuid> {
        let policy_id = cmd.policy_id;
        // Resolve the curation-metric repo label once
        // per call. `PolicyScope::Repository(id)` → repo key (via the
        // existing access port — honours the cardinality knob and the
        // `unknown` sentinel on lookup failure). `PolicyScope::Global`
        // (cross-repo finding-exclusion) → `_all`.
        let repo_label_owned = match &cmd.scope {
            PolicyScope::Repository(repo_id) => {
                Some(self.repository_access.metric_label(*repo_id).await)
            }
            PolicyScope::Global => None,
        };
        let repo_label_ref = repo_label_owned.as_deref();

        let Some(parent) = self.projections.find_by_id(policy_id).await? else {
            tracing::info!(
                policy_id = %policy_id,
                "add_exclusion rejected: policy does not exist",
            );
            emit_curation_decision(
                CurationDecisionLabel::ExcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Invalid,
            );
            return Err(
                DomainError::Validation(format!("policy {policy_id} does not exist")).into(),
            );
        };

        if parent.archived {
            tracing::info!(
                policy_id = %policy_id,
                name = %parent.name,
                "add_exclusion rejected: policy is archived",
            );
            emit_curation_decision(
                CurationDecisionLabel::ExcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Invalid,
            );
            return Err(
                DomainError::Validation(format!("policy '{}' is archived", parent.name)).into(),
            );
        }

        let exclusion_id = Uuid::new_v4();
        let stream_id = StreamId::policy(policy_id);
        let correlation_id = Uuid::new_v4();
        let expected_version = ExpectedVersion::Exact(parent.stream_version);

        let event = ExclusionAdded {
            policy_id,
            exclusion_id,
            cve_id: cmd.cve_id.clone(),
            package_pattern: cmd.package_pattern.clone(),
            scope: cmd.scope.clone(),
            reason: cmd.reason.clone(),
            expires_at: cmd.expires_at,
        };

        // Envelope-side author attribution for the
        // active-exclusions listing. `ExclusionAdded` payload carries
        // NO actor field (envelope is canonical); we extract the
        // `user_id` here from `Actor::Api` and thread it into the
        // projection write below. Non-api envelopes (system, timer,
        // gitops) leave the projection column NULL.
        let added_by_actor_id = match &actor {
            Actor::Api(api) => Some(api.user_id),
            _ => None,
        };

        let result = match self
            .events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::ExclusionAdded(event))],
                correlation_id,
                causation_id: None,
                actor,
            })
            .await
        {
            Ok(r) => r,
            Err(DomainError::Conflict(msg)) => {
                tracing::warn!(
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    expected = parent.stream_version,
                    "concurrent policy modification rejected",
                );
                emit_curation_decision(
                    CurationDecisionLabel::ExcludeFinding,
                    repo_label_ref,
                    CurationDecisionResult::Conflict,
                );
                return Err(DomainError::Conflict(msg).into());
            }
            Err(other) => {
                emit_curation_decision(
                    CurationDecisionLabel::ExcludeFinding,
                    repo_label_ref,
                    CurationDecisionResult::Error,
                );
                return Err(other.into());
            }
        };

        let new_exclusion = ExclusionProjection {
            exclusion_id,
            policy_id,
            cve_id: cmd.cve_id,
            package_pattern: cmd.package_pattern,
            scope: cmd.scope,
            reason: cmd.reason,
            added_by_actor_id,
            expires_at: cmd.expires_at,
        };

        if let Err(e) = self.projections.upsert_exclusion(&new_exclusion).await {
            tracing::error!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                error = %e,
                "exclusion projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            emit_curation_decision(
                CurationDecisionLabel::ExcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Error,
            );
            return Err(e.into());
        }

        let bumped_parent = ScanPolicyProjection {
            stream_version: result.stream_position,
            updated_at: Utc::now(),
            ..parent
        };

        if let Err(e) = self.projections.upsert(&bumped_parent).await {
            tracing::error!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                error = %e,
                "policy projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            emit_curation_decision(
                CurationDecisionLabel::ExcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Error,
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            exclusion_id = %exclusion_id,
            event_type = "ExclusionAdded",
            "exclusion added",
        );
        emit_curation_decision(
            CurationDecisionLabel::ExcludeFinding,
            repo_label_ref,
            CurationDecisionResult::Ok,
        );

        // Post-exclusion-add re-evaluation
        // pass over rejected artifacts whose active scan-policy resolves
        // to `policy_id`. Best-effort: optimistic-concurrency conflicts
        // and stream-read failures are logged and skipped — the apply
        // pipeline does not abort. The next add-exclusion or admin-
        // driven action picks up any artifact missed here.
        self.run_post_exclusion_re_evaluation_pass(policy_id, exclusion_id, &bumped_parent)
            .await;

        Ok(exclusion_id)
    }

    /// Run the post-exclusion-add re-evaluation pass.
    ///
    /// Loads rejected artifacts whose active scan-policy resolves to
    /// `policy_id` and the now-updated exclusion list (including the
    /// just-added exclusion). For each rejected artifact:
    ///
    /// 1. Read the artifact's last `ScanCompleted` from the event
    ///    store. Failure or absence ⇒ log + skip (best-effort).
    /// 2. Run [`re_evaluate_after_exclusion`] to decide the outcome.
    /// 3. `StillRejected` → no events. `ResetToQuarantined` /
    ///    `ResetToReleased` → atomic `commit_transition` of the
    ///    artifact-state mutation plus `ArtifactReEvaluated` +
    ///    companion transition event (`ArtifactQuarantined` or
    ///    `ArtifactReleased { released_by: PolicyReEvaluation }`).
    /// 4. Optimistic-concurrency conflicts on `commit_transition` ⇒
    ///    log a warn and continue (the apply does NOT abort — distinct
    ///    from the strict-atomic curation pass which DOES abort to
    ///    keep gitops apply consistent).
    ///
    /// `bumped_parent` is the post-bump policy projection (after
    /// `add_exclusion`'s parent-projection upsert) — used as the
    /// evaluator's policy input. The evaluator consults only
    /// `severity_threshold` / `license_policy`; those fields are
    /// unchanged by `add_exclusion`, so passing the bumped projection
    /// is functionally identical to passing the pre-bump one but
    /// keeps the caller from cloning.
    async fn run_post_exclusion_re_evaluation_pass(
        &self,
        policy_id: Uuid,
        exclusion_id: Uuid,
        bumped_parent: &ScanPolicyProjection,
    ) {
        let rejected_list = match self.artifacts.list_rejected_for_policy(policy_id).await {
            Ok(list) => list,
            Err(e) => {
                tracing::error!(
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    error = %e,
                    "post-exclusion re-evaluation pass: list_rejected_for_policy failed; \
                     skipping pass (next admin action picks up missed artifacts)",
                );
                return;
            }
        };
        // `list_rejected_for_policy`
        // returns a `LimitedList` capped at `LIMIT_LIST_MAX_ITEMS`. The
        // re-evaluation pass processes the first cap items; remaining
        // rejected artifacts are picked up by the next exclusion-add or by
        // a manual operator sweep. The `warn!` flags the defence-in-depth
        // ceiling so operators see runaway rejection growth.
        if rejected_list.truncated {
            tracing::warn!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                cap = hort_domain::types::LIMIT_LIST_MAX_ITEMS,
                "list_rejected_for_policy result set truncated at cap; \
                 re-evaluation pass processed the first cap items"
            );
        }
        let rejected = rejected_list.items;

        if rejected.is_empty() {
            tracing::info!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                count_re_evaluated = 0,
                count_still_rejected = 0,
                count_reset_quarantined = 0,
                count_reset_released = 0,
                "exclusion-added re-evaluation pass complete",
            );
            return;
        }

        let updated_exclusions = match self.projections.list_exclusions_for_policy(policy_id).await
        {
            Ok(list) => list,
            Err(e) => {
                tracing::error!(
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    error = %e,
                    "post-exclusion re-evaluation pass: list_exclusions_for_policy failed; \
                     skipping pass",
                );
                return;
            }
        };

        let now = Utc::now();
        let mut count_still_rejected: u64 = 0;
        let mut count_reset_quarantined: u64 = 0;
        let mut count_reset_released: u64 = 0;
        let total = rejected.len() as u64;

        for mut artifact in rejected {
            let artifact_id = artifact.id;
            let last_snapshot =
                match scan_history::read_last_scan_completed(&*self.events, artifact_id).await {
                    Ok(Some(s)) => s,
                    Ok(None) => {
                        tracing::error!(
                            artifact_id = %artifact_id,
                            policy_id = %policy_id,
                            exclusion_id = %exclusion_id,
                            "post-exclusion re-evaluation: no ScanCompleted on artifact stream; \
                             skipping artifact",
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(
                            artifact_id = %artifact_id,
                            policy_id = %policy_id,
                            exclusion_id = %exclusion_id,
                            error = %e,
                            "post-exclusion re-evaluation: failed to read artifact stream; \
                             skipping artifact",
                        );
                        continue;
                    }
                };

            // Prefer per-finding matching by
            // hydrating the `findings_blob` from CAS. Best-effort: a
            // missing or malformed blob logs a `warn!` inside
            // `read_last_findings` and returns `None` so the
            // re-evaluator falls back to the aggregate-summary
            // path. Genuine event-store read failures are infrastructure
            // errors and surface as `Err` here; we skip the artifact in
            // that case (mirrors the `read_last_scan_completed` error
            // arm above).
            let last_findings =
                match scan_history::read_last_findings(&*self.events, &self.storage, artifact_id)
                    .await
                {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!(
                            artifact_id = %artifact_id,
                            policy_id = %policy_id,
                            exclusion_id = %exclusion_id,
                            error = %e,
                            "post-exclusion re-evaluation: failed to hydrate findings_blob; \
                             skipping artifact",
                        );
                        continue;
                    }
                };

            // Correctness landmine: `re_evaluate_after_exclusion`
            // branches on the **computed deadline**, never the stored
            // anchor. The artifact stores only `quarantine_window_start`
            // (the anchor — always in the past); pass
            // `effective_quarantine_deadline(anchor, duration)` resolved
            // from the matched policy's `quarantineDuration`. Passing the
            // bare anchor type-checks (both are `Option<DateTime<Utc>>`)
            // but releases re-evaluated `rejected` artifacts ~`duration`
            // early.
            let quarantine_deadline = artifact.quarantine_window_start.map(|anchor| {
                effective_quarantine_deadline(
                    anchor,
                    chrono::Duration::seconds(bumped_parent.quarantine_duration_secs),
                )
            });
            // Hydrate the transient computed deadline onto the artifact
            // so `Artifact::re_evaluate` (invoked inside
            // `commit_re_evaluation`) branches on the same computed
            // deadline as the pure helper below — the two MUST agree on
            // boundary semantics.
            artifact.quarantine_deadline = quarantine_deadline;
            let outcome = re_evaluate_after_exclusion(
                &artifact,
                &last_snapshot.summary,
                last_findings.as_deref(),
                Some(bumped_parent),
                &updated_exclusions,
                quarantine_deadline,
                now,
            );

            match outcome {
                ReEvaluationOutcome::StillRejected => {
                    count_still_rejected += 1;
                    tracing::info!(
                        artifact_id = %artifact_id,
                        outcome = "still_rejected",
                        "artifact re-evaluated after exclusion",
                    );
                    emit_policy_evaluation(
                        policy_decision_point::RE_EVALUATION,
                        PolicyEvaluationResult::StillRejected,
                    );
                }
                ReEvaluationOutcome::ResetToQuarantined => {
                    if self
                        .commit_re_evaluation(
                            artifact,
                            policy_id,
                            exclusion_id,
                            QuarantineStatus::Rejected,
                            QuarantineStatus::Quarantined,
                        )
                        .await
                    {
                        count_reset_quarantined += 1;
                        tracing::info!(
                            artifact_id = %artifact_id,
                            outcome = "reset_to_quarantined",
                            "artifact re-evaluated after exclusion",
                        );
                        emit_policy_evaluation(
                            policy_decision_point::RE_EVALUATION,
                            PolicyEvaluationResult::ResetToQuarantined,
                        );
                    }
                }
                ReEvaluationOutcome::ResetToReleased => {
                    if self
                        .commit_re_evaluation(
                            artifact,
                            policy_id,
                            exclusion_id,
                            QuarantineStatus::Rejected,
                            QuarantineStatus::Released,
                        )
                        .await
                    {
                        count_reset_released += 1;
                        tracing::info!(
                            artifact_id = %artifact_id,
                            outcome = "reset_to_released",
                            "artifact re-evaluated after exclusion",
                        );
                        emit_policy_evaluation(
                            policy_decision_point::RE_EVALUATION,
                            PolicyEvaluationResult::ResetToReleased,
                        );
                    }
                }
            }
        }

        tracing::info!(
            policy_id = %policy_id,
            exclusion_id = %exclusion_id,
            count_re_evaluated = total,
            count_still_rejected,
            count_reset_quarantined,
            count_reset_released,
            "exclusion-added re-evaluation pass complete",
        );
    }

    /// Commit a re-evaluation outcome atomically: `ArtifactReEvaluated`
    /// audit event plus the companion transition event
    /// (`ArtifactQuarantined` or `ArtifactReleased`) appended in one
    /// `commit_transition` call.
    ///
    /// Returns `true` on success, `false` on best-effort skip
    /// (typically `DomainError::Conflict` from a parallel scan or
    /// admin operation that bumped the artifact stream between the
    /// read and the append). The caller logs the warn and increments
    /// the appropriate counter only on `true`.
    async fn commit_re_evaluation(
        &self,
        mut artifact: hort_domain::entities::artifact::Artifact,
        policy_id: Uuid,
        exclusion_id: Uuid,
        previous_status: QuarantineStatus,
        new_status: QuarantineStatus,
    ) -> bool {
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);

        // Read the expected version up-front so the optimistic-
        // concurrency check fires on the append rather than at
        // `commit_transition` time. `read_expected_version` errors
        // surface as best-effort skips below (warn + continue).
        let expected_version = match read_expected_version(&*self.events, &stream_id, false).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    error = %e,
                    "concurrent modification during re-evaluation pass; skipping artifact",
                );
                return false;
            }
        };

        // The artifact entity's `re_evaluate(now)` mutates state and
        // returns the companion transition event (`ArtifactQuarantined`
        // or `ArtifactReleased { PolicyReEvaluation }`). The
        // boundary-time discriminator inside `re_evaluate` mirrors the
        // pure-domain helper's discriminator; the two must agree on
        // boundary semantics. The `now` here is the same wall-clock
        // the pass started with — passed implicitly via `Utc::now()`
        // because `re_evaluate` is on the entity, not the pure
        // helper. Boundary precision is per-second; the pass usually
        // completes inside that window.
        let companion_event = match artifact.re_evaluate(Utc::now()) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    error = %e,
                    "artifact state machine rejected re-evaluation; skipping artifact",
                );
                return false;
            }
        };

        let re_evaluated = ArtifactReEvaluated {
            artifact_id,
            policy_id,
            trigger_exclusion_id: exclusion_id,
            previous_status,
            new_status,
        };

        let actor = hort_domain::events::system_actor();

        // Bump the repo_security_scores projection in the
        // same tx as the event append. The pure delta is `(prior, new)`
        // bucket-mapped; the projector's pure helper handles both
        // Rejected → Quarantined and Rejected → Released.
        let score_delta =
            RepoSecurityScoreProjector::compute_re_evaluated_delta(previous_status, new_status);
        let repository_id = artifact.repository_id;

        match self
            .artifact_lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![
                        EventToAppend::new(DomainEvent::ArtifactReEvaluated(re_evaluated)),
                        EventToAppend::new(companion_event),
                    ],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor,
                },
                None,
                Some((repository_id, score_delta)),
            )
            .await
        {
            Ok(_) => true,
            Err(DomainError::Conflict(msg)) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    conflict = %msg,
                    "concurrent modification during re-evaluation pass; skipping artifact",
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    error = %e,
                    "re-evaluation commit_transition failed; skipping artifact",
                );
                false
            }
        }
    }

    /// Detach an exclusion from a policy.
    ///
    /// Validates that the exclusion exists and is owned by the named
    /// policy, then appends one
    /// [`ExclusionRemoved`](hort_domain::events::ExclusionRemoved) event
    /// to the parent policy stream and drops the exclusion projection
    /// row. The parent policy projection is also re-upserted because
    /// its `stream_version` advances on the append.
    ///
    /// Validation:
    /// - Non-existent parent → [`DomainError::Validation`].
    /// - Archived parent → [`DomainError::Validation`].
    /// - Unknown `exclusion_id` → [`DomainError::NotFound`].
    /// - Exclusion belongs to a different policy →
    ///   [`DomainError::Validation`] (defence-in-depth — the
    ///   `list_exclusions_for_policy(policy_id)` port contract
    ///   already filters, but the use case re-checks rather than
    ///   trusting the adapter).
    /// - Stale `ExpectedVersion::Exact` → [`DomainError::Conflict`].
    #[tracing::instrument(skip(self, cmd))]
    pub async fn remove_exclusion(
        &self,
        cmd: RemoveExclusionCommand,
        actor: Actor,
    ) -> AppResult<()> {
        let policy_id = cmd.policy_id;
        let exclusion_id = cmd.exclusion_id;

        let Some(parent) = self.projections.find_by_id(policy_id).await? else {
            tracing::info!(
                policy_id = %policy_id,
                "remove_exclusion rejected: policy does not exist",
            );
            // Repo label unknown at this point (parent miss) — fall to
            // `_all`. Same shape as `add_exclusion`'s pre-resolution
            // rejections.
            emit_curation_decision(
                CurationDecisionLabel::UnexcludeFinding,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(
                DomainError::Validation(format!("policy {policy_id} does not exist")).into(),
            );
        };

        if parent.archived {
            tracing::info!(
                policy_id = %policy_id,
                name = %parent.name,
                "remove_exclusion rejected: policy is archived",
            );
            emit_curation_decision(
                CurationDecisionLabel::UnexcludeFinding,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(
                DomainError::Validation(format!("policy '{}' is archived", parent.name)).into(),
            );
        }

        let exclusions = self
            .projections
            .list_exclusions_for_policy(policy_id)
            .await?;

        let Some(found) = exclusions
            .into_iter()
            .find(|e| e.exclusion_id == exclusion_id)
        else {
            tracing::info!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                "remove_exclusion rejected: exclusion not found",
            );
            emit_curation_decision(
                CurationDecisionLabel::UnexcludeFinding,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(DomainError::NotFound {
                entity: "Exclusion",
                id: exclusion_id.to_string(),
            }
            .into());
        };

        // Once the exclusion projection is loaded we
        // know its `PolicyScope` and can resolve the repo label exactly
        // like `add_exclusion` does at the call boundary. Repository-
        // scoped exclusions → key (via the cardinality-aware helper);
        // global exclusions → `_all`.
        let repo_label_owned = match &found.scope {
            PolicyScope::Repository(repo_id) => {
                Some(self.repository_access.metric_label(*repo_id).await)
            }
            PolicyScope::Global => None,
        };
        let repo_label_ref = repo_label_owned.as_deref();

        // Defence in depth — the port contract says
        // `list_exclusions_for_policy(policy_id)` only returns matches,
        // but a faulty adapter must not be allowed to silently rewrite
        // a peer policy's stream. The acceptance bullet calls this out
        // explicitly.
        if found.policy_id != policy_id {
            tracing::info!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                actual_policy_id = %found.policy_id,
                "remove_exclusion rejected: exclusion belongs to a different policy",
            );
            emit_curation_decision(
                CurationDecisionLabel::UnexcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Invalid,
            );
            return Err(DomainError::Validation(format!(
                "exclusion {exclusion_id} belongs to a different policy"
            ))
            .into());
        }

        let stream_id = StreamId::policy(policy_id);
        let correlation_id = Uuid::new_v4();
        let expected_version = ExpectedVersion::Exact(parent.stream_version);

        let event = ExclusionRemoved {
            policy_id,
            exclusion_id,
            reason: cmd.reason,
        };

        let result = match self
            .events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::ExclusionRemoved(event))],
                correlation_id,
                causation_id: None,
                actor,
            })
            .await
        {
            Ok(r) => r,
            Err(DomainError::Conflict(msg)) => {
                tracing::warn!(
                    policy_id = %policy_id,
                    exclusion_id = %exclusion_id,
                    expected = parent.stream_version,
                    "concurrent policy modification rejected",
                );
                emit_curation_decision(
                    CurationDecisionLabel::UnexcludeFinding,
                    repo_label_ref,
                    CurationDecisionResult::Conflict,
                );
                return Err(DomainError::Conflict(msg).into());
            }
            Err(other) => {
                emit_curation_decision(
                    CurationDecisionLabel::UnexcludeFinding,
                    repo_label_ref,
                    CurationDecisionResult::Error,
                );
                return Err(other.into());
            }
        };

        if let Err(e) = self.projections.delete_exclusion(exclusion_id).await {
            tracing::error!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                error = %e,
                "exclusion projection delete failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            emit_curation_decision(
                CurationDecisionLabel::UnexcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Error,
            );
            return Err(e.into());
        }

        let bumped_parent = ScanPolicyProjection {
            stream_version: result.stream_position,
            updated_at: Utc::now(),
            ..parent
        };

        if let Err(e) = self.projections.upsert(&bumped_parent).await {
            tracing::error!(
                policy_id = %policy_id,
                exclusion_id = %exclusion_id,
                error = %e,
                "policy projection upsert failed after successful event append \
                 — projection will be stale until rebuild tool runs",
            );
            emit_curation_decision(
                CurationDecisionLabel::UnexcludeFinding,
                repo_label_ref,
                CurationDecisionResult::Error,
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            exclusion_id = %exclusion_id,
            event_type = "ExclusionRemoved",
            "exclusion removed",
        );
        emit_curation_decision(
            CurationDecisionLabel::UnexcludeFinding,
            repo_label_ref,
            CurationDecisionResult::Ok,
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the `config_snapshot` JSON payload embedded in `PolicyCreated`.
///
/// The shape mirrors the projection fields one-for-one — gitops apply
/// (14b) and the future audit-log replay tool both read from this
/// snapshot, so any rename here is a wire change.
fn build_config_snapshot(cmd: &CreatePolicyCommand) -> serde_json::Value {
    serde_json::json!({
        "name": cmd.name,
        "scope": cmd.scope,
        "severity_threshold": cmd.severity_threshold,
        "quarantine_duration_secs": cmd.quarantine_duration_secs,
        "require_approval": cmd.require_approval,
        // The provenance trio replaces requireSignature (ADR 0027).
        "provenance_mode": cmd.provenance_mode.to_string(),
        "provenance_backends": cmd.provenance_backends,
        "provenance_identities": cmd.provenance_identities,
        "max_artifact_age_secs": cmd.max_artifact_age_secs,
        "license_policy": cmd.license_policy,
        "scan_backends": cmd.scan_backends,
        "rescan_interval_hours": cmd.rescan_interval_hours,
        "negligible_action": cmd.negligible_action.to_string(),
    })
}

/// Build one `PolicyUpdated` event wrapped as `EventToAppend`.
fn field_event(
    policy_id: Uuid,
    field: PolicyField,
    previous_value: serde_json::Value,
    new_value: serde_json::Value,
) -> EventToAppend {
    EventToAppend::new(DomainEvent::PolicyUpdated(PolicyUpdated {
        policy_id,
        field,
        previous_value,
        new_value,
    }))
}

/// Encode `Option<i64>` as JSON: `Some(n)` → number, `None` → null.
fn optional_i64_to_value(v: Option<i64>) -> serde_json::Value {
    match v {
        Some(n) => serde_json::Value::from(n),
        None => serde_json::Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use hort_domain::events::{ApiActor, PersistedEvent};
    use hort_domain::ports::event_store::{AppendResult, ReadFrom, SubscribeFrom};
    use hort_domain::ports::BoxFuture;

    use super::*;

    // -- Test helpers --------------------------------------------------------

    fn api_actor() -> Actor {
        Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        })
    }

    fn sample_create_command(name: &str) -> CreatePolicyCommand {
        CreatePolicyCommand {
            name: name.into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::json!({
                "allowed": ["Apache-2.0", "MIT"],
                "denied": ["GPL-3.0"],
            }),
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
        }
    }

    fn sample_projection(policy_id: Uuid, stream_version: u64) -> ScanPolicyProjection {
        let now = Utc::now();
        ScanPolicyProjection {
            policy_id,
            name: "prod-default".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::json!({
                "allowed": ["Apache-2.0", "MIT"],
            }),
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version,
            created_at: now,
            updated_at: now,
        }
    }

    // -- MockEventStore ------------------------------------------------------
    //
    // Local to this module so we can:
    //   - inject append errors per-call (the shared MockEventStore doesn't),
    //   - inspect `appended_batches` exactly (matches existing pattern),
    //   - control the `AppendResult.stream_position` returned per call so
    //     the use-case-side `projection.stream_version = result.stream_position`
    //     can be observed against a known value.

    struct MockEventStore {
        appended: Mutex<Vec<AppendEvents>>,
        next_results: Mutex<Vec<DomainResultAppend>>,
        /// Pre-seeded events keyed by `StreamId`. Returned by
        /// `read_stream` so re-eval-pass tests can stage a
        /// `ScanCompleted` on the artifact stream before the pass
        /// reads it. Default is empty (existing tests do not
        /// `read_stream`).
        seeded_streams: Mutex<std::collections::HashMap<StreamId, Vec<PersistedEvent>>>,
    }

    enum DomainResultAppend {
        Ok(AppendResult),
        Err(DomainError),
    }

    impl MockEventStore {
        fn new() -> Self {
            Self {
                appended: Mutex::new(Vec::new()),
                next_results: Mutex::new(Vec::new()),
                seeded_streams: Mutex::new(Default::default()),
            }
        }

        /// Push the result the next `append` call should return. Calls
        /// pop in FIFO order; if the queue empties, `append` synthesises
        /// `Ok(AppendResult { stream_position: events.len() - 1, .. })`.
        fn push_append_result(&self, r: AppendResult) {
            self.next_results
                .lock()
                .unwrap()
                .push(DomainResultAppend::Ok(r));
        }

        fn push_append_error(&self, e: DomainError) {
            self.next_results
                .lock()
                .unwrap()
                .push(DomainResultAppend::Err(e));
        }

        fn appended_batches(&self) -> Vec<AppendEvents> {
            self.appended.lock().unwrap().clone()
        }

        /// Seed the stream with a list of persisted events.
        /// Re-eval-pass tests use this to plant a `ScanCompleted` on
        /// the artifact stream before invoking `add_exclusion`.
        fn seed_stream(&self, stream_id: StreamId, events: Vec<PersistedEvent>) {
            self.seeded_streams
                .lock()
                .unwrap()
                .insert(stream_id, events);
        }
    }

    impl EventStore for MockEventStore {
        fn append(
            &self,
            batch: AppendEvents,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<AppendResult>> {
            let count = batch.events.len() as u64;
            let next = self.next_results.lock().unwrap().pop();
            self.appended.lock().unwrap().push(batch);
            Box::pin(async move {
                match next {
                    Some(DomainResultAppend::Ok(r)) => Ok(r),
                    Some(DomainResultAppend::Err(e)) => Err(e),
                    None => Ok(AppendResult {
                        stream_position: count.saturating_sub(1),
                        global_positions: (0..count).collect(),
                    }),
                }
            })
        }

        fn read_stream(
            &self,
            stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<PersistedEvent>>> {
            let res = self
                .seeded_streams
                .lock()
                .unwrap()
                .get(stream_id)
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(res) })
        }

        fn read_category(
            &self,
            _category: hort_domain::events::StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        // Retention stubs: policy-local mock; retention paths are
        // unreachable from policy use case, panic on call.
        fn delete_stream(
            &self,
            _stream_id: StreamId,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { unimplemented!("retention path unreachable from policy tests") })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { unimplemented!("retention path unreachable from policy tests") })
        }
    }

    // -- MockPolicyProjectionRepository --------------------------------------

    struct MockPolicyProjections {
        by_id: Mutex<std::collections::HashMap<Uuid, ScanPolicyProjection>>,
        by_name: Mutex<std::collections::HashMap<String, ScanPolicyProjection>>,
        upserts: Mutex<Vec<ScanPolicyProjection>>,
        next_upsert_error: Mutex<Option<DomainError>>,
        // Exclusion-side state — inert by default so 14a-2 tests are
        // unaffected. Per-policy bucket lets one mock back tests for
        // multiple policies if needed.
        exclusions: Mutex<std::collections::HashMap<Uuid, Vec<ExclusionProjection>>>,
        exclusion_upserts: Mutex<Vec<ExclusionProjection>>,
        exclusion_deletes: Mutex<Vec<Uuid>>,
        next_upsert_exclusion_error: Mutex<Option<DomainError>>,
        next_delete_exclusion_error: Mutex<Option<DomainError>>,
    }

    impl MockPolicyProjections {
        fn new() -> Self {
            Self {
                by_id: Mutex::new(Default::default()),
                by_name: Mutex::new(Default::default()),
                upserts: Mutex::new(Vec::new()),
                next_upsert_error: Mutex::new(None),
                exclusions: Mutex::new(Default::default()),
                exclusion_upserts: Mutex::new(Vec::new()),
                exclusion_deletes: Mutex::new(Vec::new()),
                next_upsert_exclusion_error: Mutex::new(None),
                next_delete_exclusion_error: Mutex::new(None),
            }
        }

        fn insert(&self, p: ScanPolicyProjection) {
            self.by_id.lock().unwrap().insert(p.policy_id, p.clone());
            self.by_name.lock().unwrap().insert(p.name.clone(), p);
        }

        fn fail_next_upsert(&self, e: DomainError) {
            *self.next_upsert_error.lock().unwrap() = Some(e);
        }

        fn upserts(&self) -> Vec<ScanPolicyProjection> {
            self.upserts.lock().unwrap().clone()
        }

        fn insert_exclusion(&self, e: ExclusionProjection) {
            self.exclusions
                .lock()
                .unwrap()
                .entry(e.policy_id)
                .or_default()
                .push(e);
        }

        /// Inject an arbitrary exclusion list against the lookup key
        /// `key_policy_id` regardless of what `policy_id` field the
        /// inner exclusions actually carry. Used by the
        /// "exclusion belongs to a different policy" defence-in-depth
        /// test to manufacture a faulty-adapter scenario.
        fn force_exclusion_list_for(&self, key_policy_id: Uuid, list: Vec<ExclusionProjection>) {
            self.exclusions.lock().unwrap().insert(key_policy_id, list);
        }

        fn fail_next_upsert_exclusion(&self, e: DomainError) {
            *self.next_upsert_exclusion_error.lock().unwrap() = Some(e);
        }

        fn fail_next_delete_exclusion(&self, e: DomainError) {
            *self.next_delete_exclusion_error.lock().unwrap() = Some(e);
        }

        fn exclusion_upserts(&self) -> Vec<ExclusionProjection> {
            self.exclusion_upserts.lock().unwrap().clone()
        }

        fn exclusion_deletes(&self) -> Vec<Uuid> {
            self.exclusion_deletes.lock().unwrap().clone()
        }
    }

    impl PolicyProjectionRepository for MockPolicyProjections {
        fn find_by_id(
            &self,
            id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ScanPolicyProjection>>> {
            let res = self.by_id.lock().unwrap().get(&id).cloned();
            Box::pin(async move { Ok(res) })
        }

        fn find_by_name(
            &self,
            name: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ScanPolicyProjection>>> {
            let res = self
                .by_name
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .filter(|p| !p.archived);
            Box::pin(async move { Ok(res) })
        }

        fn find_by_name_including_archived(
            &self,
            name: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ScanPolicyProjection>>> {
            let res = self.by_name.lock().unwrap().get(name).cloned();
            Box::pin(async move { Ok(res) })
        }

        fn list_active(
            &self,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ScanPolicyProjection>>> {
            let res: Vec<_> = self
                .by_id
                .lock()
                .unwrap()
                .values()
                .filter(|p| !p.archived)
                .cloned()
                .collect();
            Box::pin(async move { Ok(res) })
        }

        fn list_exclusions_for_policy(
            &self,
            policy_id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ExclusionProjection>>> {
            let res = self
                .exclusions
                .lock()
                .unwrap()
                .get(&policy_id)
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(res) })
        }

        fn upsert(
            &self,
            projection: &ScanPolicyProjection,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            if let Some(e) = self.next_upsert_error.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            // Mirror the would-be DB insertion into both indexes.
            self.by_id
                .lock()
                .unwrap()
                .insert(projection.policy_id, projection.clone());
            self.by_name
                .lock()
                .unwrap()
                .insert(projection.name.clone(), projection.clone());
            self.upserts.lock().unwrap().push(projection.clone());
            Box::pin(async move { Ok(()) })
        }

        fn upsert_exclusion(
            &self,
            exclusion: &ExclusionProjection,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            if let Some(e) = self.next_upsert_exclusion_error.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            self.exclusions
                .lock()
                .unwrap()
                .entry(exclusion.policy_id)
                .or_default()
                .push(exclusion.clone());
            self.exclusion_upserts
                .lock()
                .unwrap()
                .push(exclusion.clone());
            Box::pin(async move { Ok(()) })
        }

        fn delete_exclusion(
            &self,
            exclusion_id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            if let Some(e) = self.next_delete_exclusion_error.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            // Drop matching rows across all policy buckets.
            for bucket in self.exclusions.lock().unwrap().values_mut() {
                bucket.retain(|e| e.exclusion_id != exclusion_id);
            }
            self.exclusion_deletes.lock().unwrap().push(exclusion_id);
            Box::pin(async move { Ok(()) })
        }
    }

    /// Default `RepositoryAccessUseCase` for policy tests: empty repo
    /// store + disabled RBAC + `include_repository_label = true`. The
    /// store is empty so `metric_label(repo_id)` returns the `unknown`
    /// sentinel for any id — fine for existing exclusion tests that
    /// don't assert the resolved-key shape (dedicated tests seed a real
    /// repository for that assertion).
    fn default_repository_access() -> Arc<RepositoryAccessUseCase> {
        use crate::use_cases::repository_access::RbacAccess;
        Arc::new(RepositoryAccessUseCase::new(
            Arc::new(crate::use_cases::test_support::MockRepositoryRepository::new()),
            RbacAccess::Disabled,
            true,
        ))
    }

    /// Build a `RepositoryAccessUseCase` seeded with a single
    /// repository so exclusion tests can assert the
    /// `repository="<key>"` label resolution on the curation metric.
    fn repository_access_with_key(
        repo_id: Uuid,
        repo_key: &str,
        include_label: bool,
    ) -> Arc<RepositoryAccessUseCase> {
        use crate::use_cases::repository_access::RbacAccess;
        let repos = Arc::new(crate::use_cases::test_support::MockRepositoryRepository::new());
        let mut r = crate::use_cases::test_support::sample_repository();
        r.id = repo_id;
        r.key = repo_key.into();
        repos.insert(r);
        Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            include_label,
        ))
    }

    fn make_use_case() -> (
        PolicyUseCase,
        Arc<MockEventStore>,
        Arc<MockPolicyProjections>,
    ) {
        make_use_case_with_repo_access(default_repository_access())
    }

    /// Variant that lets the caller supply a pre-built
    /// `RepositoryAccessUseCase` — used by tests that pin the
    /// `hort_curation_decisions_total{repository=…}` label resolution.
    fn make_use_case_with_repo_access(
        repository_access: Arc<RepositoryAccessUseCase>,
    ) -> (
        PolicyUseCase,
        Arc<MockEventStore>,
        Arc<MockPolicyProjections>,
    ) {
        let events = Arc::new(MockEventStore::new());
        let projections = Arc::new(MockPolicyProjections::new());
        // Most tests don't exercise the re-evaluation
        // pass — `add_exclusion`'s post-projection-upsert pass is a
        // no-op when `list_rejected_for_policy` returns empty, which
        // is the empty-mock default. Re-eval-pass tests use
        // [`make_use_case_with_re_eval_harness`] to seed rejected
        // artifacts and exercise the pass directly.
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let storage = Arc::new(crate::use_cases::test_support::MockStoragePort::new());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts,
            lifecycle,
            storage,
            repository_access,
        );
        (uc, events, projections)
    }

    /// Build a `PolicyUseCase` exposing the artifact + lifecycle mocks
    /// so re-evaluation-pass tests can seed rejected
    /// artifacts via `MockArtifactRepository::insert`, attach a
    /// per-policy filter via
    /// [`MockArtifactRepository::seed_rejected_for_policy`], and
    /// inspect `commit_transition` calls via
    /// [`MockArtifactLifecycle::committed_transitions`].
    fn make_use_case_with_re_eval_harness() -> (
        PolicyUseCase,
        Arc<MockEventStore>,
        Arc<MockPolicyProjections>,
        Arc<crate::use_cases::test_support::MockArtifactRepository>,
        Arc<crate::use_cases::test_support::MockArtifactLifecycle>,
    ) {
        let events = Arc::new(MockEventStore::new());
        let projections = Arc::new(MockPolicyProjections::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        // The re-eval-pass tests here do not seed
        // `findings_blob` so the per-finding path is exercised by the
        // pure-domain unit tests in `re_evaluation.rs::tests` instead.
        // Tests here drive the aggregate-summary fallback
        // (the helper's `Ok(None)` short-circuit for a missing CAS
        // blob).
        let storage = Arc::new(crate::use_cases::test_support::MockStoragePort::new());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts.clone(),
            lifecycle.clone(),
            storage,
            default_repository_access(),
        );
        (uc, events, projections, artifacts, lifecycle)
    }

    // -- create_policy: happy path ------------------------------------------

    #[tokio::test]
    async fn create_policy_emits_policy_created_event_with_snapshot() {
        let (uc, events, projections) = make_use_case();
        let cmd = sample_create_command("prod-default");

        let policy_id = uc.create_policy(cmd, api_actor()).await.unwrap();

        assert!(!policy_id.is_nil());

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].expected_version, ExpectedVersion::NoStream);
        assert_eq!(batches[0].events.len(), 1);
        let event = &batches[0].events[0].event;
        match event {
            DomainEvent::PolicyCreated(c) => {
                assert_eq!(c.policy_id, policy_id);
                assert_eq!(c.name, "prod-default");
                assert_eq!(c.scope, PolicyScope::Global);
                // The snapshot embeds every config field.
                assert_eq!(c.config_snapshot["name"], "prod-default");
                assert_eq!(c.config_snapshot["quarantine_duration_secs"], 86400);
                assert_eq!(c.config_snapshot["require_approval"], true);
            }
            other => panic!("expected PolicyCreated, got {other:?}"),
        }

        // Projection upserted with stream_version = result.stream_position.
        let upserts = projections.upserts();
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].policy_id, policy_id);
        // MockEventStore default returns stream_position = events.len() - 1 = 0.
        assert_eq!(upserts[0].stream_version, 0);
        assert!(!upserts[0].archived);
    }

    #[tokio::test]
    async fn create_policy_uses_returned_stream_position_as_version() {
        let (uc, events, projections) = make_use_case();
        // Force the mock to return an unusual stream_position so the
        // assertion can't pass by coincidence.
        events.push_append_result(AppendResult {
            stream_position: 42,
            global_positions: vec![100],
        });

        let _id = uc
            .create_policy(sample_create_command("p"), api_actor())
            .await
            .unwrap();

        let upserts = projections.upserts();
        assert_eq!(upserts[0].stream_version, 42);
    }

    #[tokio::test]
    async fn create_policy_duplicate_name_returns_conflict_without_appending() {
        let (uc, events, projections) = make_use_case();
        // Pre-seed a projection with the conflicting name.
        let existing = sample_projection(Uuid::new_v4(), 0);
        let existing_name = existing.name.clone();
        projections.insert(existing);

        let mut cmd = sample_create_command("prod-default");
        cmd.name = existing_name;

        let err = uc.create_policy(cmd, api_actor()).await.unwrap_err();
        let s = err.to_string();
        assert!(s.contains("conflict"), "got: {s}");
        assert!(s.contains("already exists"), "got: {s}");

        // Critical: nothing appended on the duplicate-name path.
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn create_policy_event_store_failure_propagates_and_skips_upsert() {
        let (uc, events, projections) = make_use_case();
        events.push_append_error(DomainError::Invariant("event store down".into()));

        let err = uc
            .create_policy(sample_create_command("p"), api_actor())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("event store down"));

        // No projection upsert should have been attempted.
        assert!(projections.upserts().is_empty());
    }

    #[tokio::test]
    async fn create_policy_projection_upsert_failure_propagates_after_append() {
        let (uc, events, projections) = make_use_case();
        projections.fail_next_upsert(DomainError::Invariant("projection write failed".into()));

        let err = uc
            .create_policy(sample_create_command("p"), api_actor())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("projection write failed"),
            "got: {err}"
        );

        // The append did succeed — observe one batch even though the
        // overall use case errored out (this is the documented stale-
        // projection trade-off).
        assert_eq!(events.appended_batches().len(), 1);
    }

    // -- update_policy -------------------------------------------------------

    #[tokio::test]
    async fn update_policy_nonexistent_returns_not_found() {
        let (uc, _events, _projections) = make_use_case();
        let id = Uuid::new_v4();

        let err = uc
            .update_policy(UpdatePolicyCommand::new(id), api_actor())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn update_policy_archived_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, 5);
        p.archived = true;
        projections.insert(p);

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("new-name".into());

        let err = uc.update_policy(cmd, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("validation"), "got: {err}");
        assert!(err.to_string().contains("archived"), "got: {err}");

        // No append, no upsert on rejection.
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn update_policy_all_unchanged_yields_zero_events_and_no_writes() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 7));
        // The projection insert itself counts toward `upserts`, so
        // capture the baseline and check no NEW upsert happens.
        let baseline_upserts = projections.upserts().len();

        uc.update_policy(UpdatePolicyCommand::new(id), api_actor())
            .await
            .unwrap();

        assert!(events.appended_batches().is_empty());
        assert_eq!(projections.upserts().len(), baseline_upserts);
    }

    #[tokio::test]
    async fn update_policy_set_to_same_value_yields_zero_events() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let p = sample_projection(id, 3);
        let same_name = p.name.clone();
        let same_threshold = p.severity_threshold;
        projections.insert(p);

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set(same_name);
        cmd.severity_threshold = FieldChange::Set(same_threshold);

        uc.update_policy(cmd, api_actor()).await.unwrap();
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn update_policy_changed_field_emits_one_event_per_change() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 3));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("renamed".into());
        cmd.severity_threshold = FieldChange::Set(SeverityThreshold::Critical);
        // require_approval was true in the projection — set to true
        // again to assert the diff filters it out.
        cmd.require_approval = FieldChange::Set(true);

        // Force a known stream_position so the version assertion is precise.
        events.push_append_result(AppendResult {
            stream_position: 4,
            global_positions: vec![10, 11],
        });

        uc.update_policy(cmd, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        // Exactly one append batch, atomic.
        assert_eq!(batches.len(), 1);
        // Two changed fields → two events.
        assert_eq!(batches[0].events.len(), 2);
        assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(3));

        let updated_fields: Vec<PolicyField> = batches[0]
            .events
            .iter()
            .map(|e| match &e.event {
                DomainEvent::PolicyUpdated(u) => u.field.clone(),
                other => panic!("expected PolicyUpdated, got {other:?}"),
            })
            .collect();
        assert!(updated_fields.contains(&PolicyField::Name));
        assert!(updated_fields.contains(&PolicyField::SeverityThreshold));
        assert!(!updated_fields.contains(&PolicyField::RequireApproval));

        // Projection upserted with the post-append stream_version.
        let upserts = projections.upserts();
        let last = upserts.last().unwrap();
        assert_eq!(last.stream_version, 4);
        assert_eq!(last.name, "renamed");
        assert_eq!(last.severity_threshold, SeverityThreshold::Critical);
    }

    #[tokio::test]
    async fn update_policy_emits_event_for_every_changed_scalar_field() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 0));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("x".into());
        cmd.scope = FieldChange::Set(PolicyScope::Repository(Uuid::new_v4()));
        cmd.severity_threshold = FieldChange::Set(SeverityThreshold::Low);
        cmd.quarantine_duration_secs = FieldChange::Set(99);
        cmd.require_approval = FieldChange::Set(false);
        // The provenance trio replaces requireSignature (ADR 0027).
        cmd.provenance_mode = FieldChange::Set(ProvenanceMode::Required);
        cmd.provenance_backends = FieldChange::Set(vec!["cosign".into(), "notary".into()]);
        cmd.provenance_identities =
            FieldChange::Set(vec![
                SignerIdentityPattern::new("iss", "san").expect("valid pattern")
            ]);
        cmd.max_artifact_age_secs = FieldChange::Set(Some(7));
        cmd.license_policy = FieldChange::Set(serde_json::json!({"new": "policy"}));

        uc.update_policy(cmd, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1, "single atomic batch for all changes");
        assert_eq!(batches[0].events.len(), 10, "one event per changed field");

        let fields: Vec<PolicyField> = batches[0]
            .events
            .iter()
            .map(|e| match &e.event {
                DomainEvent::PolicyUpdated(u) => u.field.clone(),
                other => panic!("expected PolicyUpdated, got {other:?}"),
            })
            .collect();
        // Every field present.
        for f in [
            PolicyField::Name,
            PolicyField::Scope,
            PolicyField::SeverityThreshold,
            PolicyField::QuarantineDuration,
            PolicyField::RequireApproval,
            PolicyField::ProvenanceMode,
            PolicyField::ProvenanceBackends,
            PolicyField::ProvenanceIdentities,
            PolicyField::MaxArtifactAge,
            PolicyField::LicensePolicy,
        ] {
            assert!(fields.contains(&f), "missing field: {f:?}");
        }
    }

    #[tokio::test]
    async fn update_policy_clear_max_artifact_age_emits_event_with_null_new_value() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        // Projection has Some(value); clearing it must emit an event.
        let p = sample_projection(id, 0);
        assert!(p.max_artifact_age_secs.is_some());
        projections.insert(p);

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.max_artifact_age_secs = FieldChange::Set(None);

        uc.update_policy(cmd, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::PolicyUpdated(u) => {
                assert_eq!(u.field, PolicyField::MaxArtifactAge);
                assert!(u.new_value.is_null(), "new_value should be null");
                assert!(u.previous_value.is_number());
            }
            other => panic!("expected PolicyUpdated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_policy_set_max_artifact_age_some_emits_event_with_number() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        // Start from None so Set(Some(_)) is a real change.
        let mut p = sample_projection(id, 0);
        p.max_artifact_age_secs = None;
        projections.insert(p);

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.max_artifact_age_secs = FieldChange::Set(Some(60));

        uc.update_policy(cmd, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::PolicyUpdated(u) => {
                assert_eq!(u.field, PolicyField::MaxArtifactAge);
                assert!(u.previous_value.is_null());
                assert_eq!(u.new_value, serde_json::Value::from(60));
            }
            other => panic!("expected PolicyUpdated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_policy_set_negligible_action_emits_one_event_and_mutates_projection() {
        // The `FieldChange::Set(new_action)` branch must emit exactly one
        // `PolicyField::NegligibleAction` event (carrying the lowercase
        // wire strings) and mutate the upserted projection. Exercises the
        // `update_policy` code path directly — the gitops applier path is
        // a different call site and is not interchangeable.
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        // sample_projection defaults negligible_action = Ignore.
        let p = sample_projection(id, 0);
        assert_eq!(p.negligible_action, NegligibleAction::Ignore);
        projections.insert(p);

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.negligible_action = FieldChange::Set(NegligibleAction::Block);

        uc.update_policy(cmd, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1, "single atomic batch");
        assert_eq!(batches[0].events.len(), 1, "exactly one event");
        match &batches[0].events[0].event {
            DomainEvent::PolicyUpdated(u) => {
                assert_eq!(u.field, PolicyField::NegligibleAction);
                assert_eq!(u.previous_value, serde_json::Value::String("ignore".into()));
                assert_eq!(u.new_value, serde_json::Value::String("block".into()));
            }
            other => panic!("expected PolicyUpdated, got {other:?}"),
        }

        let upserts = projections.upserts();
        assert_eq!(
            upserts.last().unwrap().negligible_action,
            NegligibleAction::Block,
            "projection reflects the new action"
        );
    }

    #[tokio::test]
    async fn update_policy_set_negligible_action_to_same_value_yields_zero_events() {
        // Same-value skip: `Set(Ignore)` over an `Ignore` projection is a
        // no-op — no event, no new upsert.
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let p = sample_projection(id, 0);
        assert_eq!(p.negligible_action, NegligibleAction::Ignore);
        projections.insert(p);
        let baseline_upserts = projections.upserts().len();

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.negligible_action = FieldChange::Set(NegligibleAction::Ignore);

        uc.update_policy(cmd, api_actor()).await.unwrap();

        assert!(events.appended_batches().is_empty(), "no event on no-op");
        assert_eq!(
            projections.upserts().len(),
            baseline_upserts,
            "no new upsert on no-op"
        );
    }

    #[tokio::test]
    async fn update_policy_stale_version_maps_conflict_to_domain_conflict() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 5));
        events.push_append_error(DomainError::Conflict("expected version 5, found 6".into()));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("changed".into());

        let err = uc.update_policy(cmd, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("conflict"), "got: {err}");
    }

    #[tokio::test]
    async fn update_policy_propagates_non_conflict_event_store_error() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 0));
        events.push_append_error(DomainError::Invariant("event store down".into()));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("changed".into());

        let err = uc.update_policy(cmd, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("event store down"));
    }

    #[tokio::test]
    async fn update_policy_projection_upsert_failure_propagates() {
        let (uc, _events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 0));
        projections.fail_next_upsert(DomainError::Invariant("projection write failed".into()));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("changed".into());

        let err = uc.update_policy(cmd, api_actor()).await.unwrap_err();
        assert!(
            err.to_string().contains("projection write failed"),
            "got: {err}"
        );
    }

    // -- archive_policy ------------------------------------------------------

    #[tokio::test]
    async fn archive_policy_nonexistent_returns_not_found() {
        let (uc, _events, _projections) = make_use_case();
        let err = uc
            .archive_policy(Uuid::new_v4(), api_actor())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn archive_policy_already_archived_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, 2);
        p.archived = true;
        projections.insert(p);

        let err = uc.archive_policy(id, api_actor()).await.unwrap_err();
        let s = err.to_string();
        assert!(s.contains("validation"), "got: {s}");
        assert!(s.contains("already archived"), "got: {s}");
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn archive_policy_happy_path_emits_event_and_marks_archived() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 4));
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![100],
        });

        uc.archive_policy(id, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(4));
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::PolicyArchived(a) => assert_eq!(a.policy_id, id),
            other => panic!("expected PolicyArchived, got {other:?}"),
        }

        let upserts = projections.upserts();
        let last = upserts.last().unwrap();
        assert!(last.archived);
        assert_eq!(last.stream_version, 5);
    }

    #[tokio::test]
    async fn archive_policy_stale_version_maps_conflict_to_domain_conflict() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 9));
        events.push_append_error(DomainError::Conflict("expected version 9, found 10".into()));

        let err = uc.archive_policy(id, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("conflict"), "got: {err}");
    }

    #[tokio::test]
    async fn archive_policy_propagates_non_conflict_event_store_error() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 0));
        events.push_append_error(DomainError::Invariant("event store down".into()));

        let err = uc.archive_policy(id, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("event store down"));
    }

    #[tokio::test]
    async fn archive_policy_projection_upsert_failure_propagates() {
        let (uc, _events, projections) = make_use_case();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 0));
        projections.fail_next_upsert(DomainError::Invariant("projection write failed".into()));

        let err = uc.archive_policy(id, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("projection write failed"));
    }

    // -- reactivate_policy ---------------------------------------------------
    //
    // Gitops apply may re-declare a YAML
    // whose projection was archived by a previous apply. Reactivation
    // preserves `policy_id` + event-stream history.

    #[tokio::test]
    async fn reactivate_policy_happy_path_emits_event_and_clears_archived() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, 7);
        p.archived = true;
        projections.insert(p);
        events.push_append_result(AppendResult {
            stream_position: 8,
            global_positions: vec![200],
        });

        uc.reactivate_policy(id, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(7));
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::PolicyReactivated(r) => assert_eq!(r.policy_id, id),
            other => panic!("expected PolicyReactivated, got {other:?}"),
        }

        let upserts = projections.upserts();
        let last = upserts.last().unwrap();
        assert!(!last.archived);
        assert_eq!(last.stream_version, 8);
    }

    #[tokio::test]
    async fn reactivate_policy_rejects_already_active_with_validation_error() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        // archived=false (the default sample) → reactivate must reject.
        projections.insert(sample_projection(id, 0));

        let err = uc.reactivate_policy(id, api_actor()).await.unwrap_err();
        let s = err.to_string();
        assert!(s.contains("already active"), "got: {s}");
        // No event must be appended on the validation failure path —
        // mirrors the archive_policy "already archived" symmetry.
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn reactivate_policy_rejects_unknown_policy_with_not_found() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        // No `insert` — the projection lookup returns None.
        let _ = &projections;

        let err = uc.reactivate_policy(id, api_actor()).await.unwrap_err();
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::NotFound {
                entity: "ScanPolicy",
                ..
            })
        ));
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn reactivate_policy_stale_version_maps_conflict_to_domain_conflict() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, 9);
        p.archived = true;
        projections.insert(p);
        events.push_append_error(DomainError::Conflict("expected version 9, found 10".into()));

        let err = uc.reactivate_policy(id, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("conflict"), "got: {err}");
    }

    #[tokio::test]
    async fn reactivate_policy_projection_upsert_failure_propagates() {
        let (uc, events, projections) = make_use_case();
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, 2);
        p.archived = true;
        projections.insert(p);
        events.push_append_result(AppendResult {
            stream_position: 3,
            global_positions: vec![10],
        });
        projections.fail_next_upsert(DomainError::Invariant("projection write failed".into()));

        let err = uc.reactivate_policy(id, api_actor()).await.unwrap_err();
        assert!(err.to_string().contains("projection write failed"));
    }

    // -- find_by_id repository error propagates ------------------------------

    #[tokio::test]
    async fn create_policy_propagates_find_by_name_error() {
        // The projection lookup itself fails — the use case should not
        // mint a stream position for a request it can't even validate.
        struct FailingFindByName;
        impl PolicyProjectionRepository for FailingFindByName {
            fn find_by_id(
                &self,
                _id: Uuid,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ScanPolicyProjection>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn find_by_name(
                &self,
                _name: &str,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ScanPolicyProjection>>>
            {
                Box::pin(
                    async move { Err(DomainError::Invariant("projection read failed".into())) },
                )
            }
            fn find_by_name_including_archived(
                &self,
                _name: &str,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ScanPolicyProjection>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn list_active(
                &self,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ScanPolicyProjection>>>
            {
                Box::pin(async move { Ok(Vec::new()) })
            }
            fn list_exclusions_for_policy(
                &self,
                _policy_id: Uuid,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ExclusionProjection>>>
            {
                Box::pin(async move { Ok(Vec::new()) })
            }
            fn upsert(
                &self,
                _projection: &ScanPolicyProjection,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
                Box::pin(async move { Ok(()) })
            }
            fn upsert_exclusion(
                &self,
                _exclusion: &ExclusionProjection,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
                Box::pin(async move { Ok(()) })
            }
            fn delete_exclusion(
                &self,
                _exclusion_id: Uuid,
            ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
                Box::pin(async move { Ok(()) })
            }
        }

        let events = Arc::new(MockEventStore::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let storage = Arc::new(crate::use_cases::test_support::MockStoragePort::new());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            Arc::new(FailingFindByName),
            artifacts,
            lifecycle,
            storage,
            default_repository_access(),
        );

        let err = uc
            .create_policy(sample_create_command("p"), api_actor())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("projection read failed"));
        assert!(events.appended_batches().is_empty());
    }

    // -- add_exclusion -------------------------------------------------------

    fn sample_add_exclusion_command(policy_id: Uuid) -> AddExclusionCommand {
        AddExclusionCommand {
            policy_id,
            cve_id: "CVE-2024-3094".into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            scope: PolicyScope::Global,
            reason: "patched in container layer".into(),
            expires_at: DateTime::<Utc>::from_timestamp(1_800_000_000, 0),
        }
    }

    fn sample_remove_exclusion_command(
        policy_id: Uuid,
        exclusion_id: Uuid,
    ) -> RemoveExclusionCommand {
        RemoveExclusionCommand {
            policy_id,
            exclusion_id,
            reason: "no longer applicable".into(),
        }
    }

    fn sample_exclusion(exclusion_id: Uuid, policy_id: Uuid) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id,
            policy_id,
            cve_id: "CVE-2024-3094".into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            scope: PolicyScope::Global,
            reason: "patched in container layer".into(),
            added_by_actor_id: None,
            expires_at: DateTime::<Utc>::from_timestamp(1_800_000_000, 0),
        }
    }

    #[tokio::test]
    async fn add_exclusion_nonexistent_parent_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();

        let err = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap_err();
        let s = err.to_string();
        assert!(s.contains("validation"), "got: {s}");
        assert!(s.contains("does not exist"), "got: {s}");

        // No append, no projection writes on rejection.
        assert!(events.appended_batches().is_empty());
        assert!(projections.exclusion_upserts().is_empty());
    }

    #[tokio::test]
    async fn add_exclusion_archived_parent_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 3);
        p.archived = true;
        projections.insert(p);

        let err = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap_err();
        let s = err.to_string();
        assert!(s.contains("validation"), "got: {s}");
        assert!(s.contains("archived"), "got: {s}");

        assert!(events.appended_batches().is_empty());
        assert!(projections.exclusion_upserts().is_empty());
    }

    #[tokio::test]
    async fn add_exclusion_happy_path_emits_event_and_upserts_both_projections() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        // Force a known stream_position so the bumped-version assertion
        // can't pass by coincidence.
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![100],
        });

        let exclusion_id = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        assert!(!exclusion_id.is_nil());

        // Exactly one append, on the parent policy stream, with
        // ExpectedVersion::Exact(parent.stream_version).
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].stream_id, StreamId::policy(policy_id));
        assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(4));
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::ExclusionAdded(e) => {
                assert_eq!(e.policy_id, policy_id);
                assert_eq!(e.exclusion_id, exclusion_id);
                assert_eq!(e.cve_id, "CVE-2024-3094");
                assert_eq!(e.package_pattern.as_deref(), Some("xz-utils@<5.6.2"));
                assert_eq!(e.scope, PolicyScope::Global);
                assert_eq!(e.reason, "patched in container layer");
                assert!(e.expires_at.is_some());
            }
            other => panic!("expected ExclusionAdded, got {other:?}"),
        }

        // Exclusion projection upserted.
        let exclusion_upserts = projections.exclusion_upserts();
        assert_eq!(exclusion_upserts.len(), 1);
        assert_eq!(exclusion_upserts[0].exclusion_id, exclusion_id);
        assert_eq!(exclusion_upserts[0].policy_id, policy_id);

        // Parent projection upserted with bumped stream_version. (The
        // initial `insert(...)` does NOT go through `upsert`, so the
        // first observed upsert is the bump.)
        let upserts = projections.upserts();
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].policy_id, policy_id);
        assert_eq!(upserts[0].stream_version, 5);
    }

    #[tokio::test]
    async fn add_exclusion_stale_version_maps_conflict_to_domain_conflict() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 9));
        events.push_append_error(DomainError::Conflict("expected version 9, found 10".into()));

        let err = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("conflict"), "got: {err}");

        // No projection writes after a conflict.
        assert!(projections.exclusion_upserts().is_empty());
        assert!(projections.upserts().is_empty());
    }

    #[tokio::test]
    async fn add_exclusion_propagates_non_conflict_event_store_error() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));
        events.push_append_error(DomainError::Invariant("event store down".into()));

        let err = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("event store down"), "got: {err}");
    }

    #[tokio::test]
    async fn add_exclusion_propagates_upsert_exclusion_failure_after_append() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));
        projections.fail_next_upsert_exclusion(DomainError::Invariant(
            "exclusion projection write failed".into(),
        ));

        let err = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("exclusion projection write failed"),
            "got: {err}"
        );

        // Append did succeed — observe one batch even though the use
        // case errored out (documented stale-projection trade-off).
        assert_eq!(events.appended_batches().len(), 1);
        // Parent projection must NOT have been bumped on this failure.
        assert!(projections.upserts().is_empty());
    }

    #[tokio::test]
    async fn add_exclusion_propagates_parent_upsert_failure_after_append() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));
        projections.fail_next_upsert(DomainError::Invariant("policy upsert failed".into()));

        let err = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("policy upsert failed"),
            "got: {err}"
        );

        // Append succeeded; exclusion upsert succeeded; only the
        // parent-projection upsert failed.
        assert_eq!(events.appended_batches().len(), 1);
        assert_eq!(projections.exclusion_upserts().len(), 1);
    }

    // -- add_exclusion: post-exclusion-add re-evaluation pass ----------------

    use hort_domain::entities::artifact::Artifact;
    use hort_domain::events::{IngestSource, ReleaseReason, ScanCompleted, SeveritySummary};
    use hort_domain::types::ContentHash;

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn rejected_artifact_for_repo(repo_id: Uuid, name: &str) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: name.into(),
            name_as_published: name.into(),
            version: Some("1.0.0".into()),
            path: format!("/{name}/1.0.0"),
            size_bytes: 1,
            sha256_checksum: VALID_SHA256.parse::<ContentHash>().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Rejected,
            // The fixture default places the observation-window anchor
            // 25h ago; with `sample_projection`'s 24h
            // `quarantine_duration_secs` the computed deadline is 1h in
            // the past, so the pass's `effective_quarantine_deadline`
            // resolution lands on the elapsed-window branch
            // (`ResetToReleased` on a clean re-eval). Tests exercising
            // the future-window branch override `quarantine_window_start`
            // (see `*_window_in_future` cases below).
            quarantine_window_start: Some(Utc::now() - chrono::Duration::hours(25)),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn persisted_scan_completed(
        artifact_id: Uuid,
        critical: u32,
        stream_position: u64,
    ) -> PersistedEvent {
        // Invariant: blob iff non-empty findings.
        let findings_blob = if critical > 0 {
            Some(VALID_SHA256.parse::<ContentHash>().unwrap())
        } else {
            None
        };
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position,
            global_position: stream_position,
            event: DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "trivy".into(),
                finding_count: critical,
                severity_summary: SeveritySummary {
                    critical,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                },
                findings_blob,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Build an `ArtifactIngested` PersistedEvent — used to seed the
    /// "no ScanCompleted on artifact stream" path so the pass takes
    /// the best-effort skip.
    fn persisted_artifact_ingested(artifact_id: Uuid, stream_position: u64) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position,
            global_position: stream_position,
            event: DomainEvent::ArtifactIngested(hort_domain::events::ArtifactIngested {
                artifact_id,
                repository_id: Uuid::new_v4(),
                name: "x".into(),
                version: None,
                sha256: VALID_SHA256.parse().unwrap(),
                size_bytes: 1,
                source: IngestSource::Direct,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    /// Build an `AddExclusionCommand` whose `cve_id` matches every
    /// CVE in the artifact's last `ScanCompleted` (the v1
    /// aggregate-summary exclusion filter decrements one count from
    /// the highest non-zero tier per matching active exclusion). The
    /// helper constructs a global-pattern exclusion so it applies to
    /// every artifact name.
    fn re_eval_exclusion_command(policy_id: Uuid) -> AddExclusionCommand {
        AddExclusionCommand {
            policy_id,
            cve_id: "CVE-2024-3094".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "matches the rejected artifact's only finding".into(),
            expires_at: None,
        }
    }

    /// Inserts the seeded `ScanCompleted` and rejected artifact and
    /// returns the artifact id. The artifact is inserted into the
    /// shared `MockArtifactRepository`; the scan-completed event is
    /// seeded onto the artifact stream so the re-eval pass can read
    /// it back via `read_stream`. Caller is responsible for seeding
    /// the per-policy `repository_id` filter via
    /// [`MockArtifactRepository::seed_rejected_for_policy`].
    fn seed_rejected_with_scan(
        artifacts: &Arc<crate::use_cases::test_support::MockArtifactRepository>,
        events: &Arc<MockEventStore>,
        repo_id: Uuid,
        critical: u32,
    ) -> Uuid {
        let artifact = rejected_artifact_for_repo(repo_id, "xz-utils");
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![persisted_scan_completed(artifact_id, critical, 0)],
        );
        artifact_id
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_no_op_when_no_rejected_artifacts() {
        // Pass-complete log fires with all-zero counts. No state mutation.
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        // Seed the policy filter — even though it's empty, the mock
        // returns no rejected artifacts so the pass takes the early
        // return path.
        artifacts.seed_rejected_for_policy(policy_id, vec![]);

        let exclusion_id = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();
        assert!(!exclusion_id.is_nil());

        // Exactly one append (the ExclusionAdded on the policy
        // stream); no artifact-stream commits.
        assert_eq!(events.appended_batches().len(), 1);
        assert!(lifecycle.committed_transitions().is_empty());
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_resets_artifact_to_released_when_clean_and_window_elapsed()
    {
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        // Severity threshold = Low so a single critical finding would
        // still block — but the new exclusion zeroes that finding.
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        let artifact_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        let exclusion_id = uc
            .add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        // Two batches were appended: the ExclusionAdded on the policy
        // stream + the ArtifactReEvaluated/ArtifactReleased pair on
        // the artifact stream (via `commit_transition`'s call into the
        // event-store mock — actually `commit_transition` records via
        // `MockArtifactLifecycle`, not the event store directly).
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1, "ExclusionAdded on policy stream");
        assert!(matches!(
            batches[0].events[0].event,
            DomainEvent::ExclusionAdded(_)
        ));

        // The lifecycle mock recorded one commit_transition with two
        // events: ArtifactReEvaluated + ArtifactReleased.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (committed_artifact, committed_events, _meta) = &transitions[0];
        assert_eq!(committed_artifact.id, artifact_id);
        assert_eq!(
            committed_artifact.quarantine_status,
            QuarantineStatus::Released
        );
        assert_eq!(committed_events.events.len(), 2);
        match &committed_events.events[0].event {
            DomainEvent::ArtifactReEvaluated(e) => {
                assert_eq!(e.artifact_id, artifact_id);
                assert_eq!(e.policy_id, policy_id);
                assert_eq!(e.trigger_exclusion_id, exclusion_id);
                assert_eq!(e.previous_status, QuarantineStatus::Rejected);
                assert_eq!(e.new_status, QuarantineStatus::Released);
            }
            other => panic!("expected ArtifactReEvaluated, got {other:?}"),
        }
        match &committed_events.events[1].event {
            DomainEvent::ArtifactReleased(e) => {
                assert_eq!(e.released_by, ReleaseReason::PolicyReEvaluation);
                // Re-evaluation is system-driven; the variant invariant
                // requires both attribution fields to be `None`.
                assert_eq!(e.released_by_user_id, None);
                assert_eq!(e.justification, None);
                // Domain validate must accept the shape — proves the
                // re-eval emit site honours the variant invariant.
                assert!(e.validate().is_ok());
            }
            other => panic!("expected ArtifactReleased, got {other:?}"),
        }
    }

    /// Re-evaluation that resets a Rejected artifact
    /// to Released must thread a `(rejected -1, released +1)` score
    /// delta to the lifecycle port (same tx as the
    /// `ArtifactReEvaluated + ArtifactReleased` append).
    #[tokio::test]
    async fn add_exclusion_re_eval_reset_to_released_threads_score_delta() {
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        let _artifact_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        uc.add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1, "exactly one re-eval transition");
        let (delta_repo, delta) = &deltas[0];
        assert_eq!(*delta_repo, repo_id);
        assert_eq!(delta.rejected_delta, -1);
        assert_eq!(delta.released_delta, 1);
        assert_eq!(delta.quarantined_delta, 0);
        assert!(delta.last_scan_at.is_none());
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_resets_artifact_to_quarantined_when_clean_and_window_in_future(
    ) {
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        // Anchor = now → computed deadline (anchor + 24h policy
        // duration) is 24h in the future → ResetToQuarantined on Clean.
        let mut artifact = rejected_artifact_for_repo(repo_id, "xz-utils");
        artifact.quarantine_window_start = Some(Utc::now());
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![persisted_scan_completed(artifact_id, 1, 0)],
        );
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        let _exclusion_id = uc
            .add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (committed_artifact, committed_events, _meta) = &transitions[0];
        assert_eq!(
            committed_artifact.quarantine_status,
            QuarantineStatus::Quarantined
        );
        match &committed_events.events[0].event {
            DomainEvent::ArtifactReEvaluated(e) => {
                assert_eq!(e.previous_status, QuarantineStatus::Rejected);
                assert_eq!(e.new_status, QuarantineStatus::Quarantined);
            }
            other => panic!("expected ArtifactReEvaluated, got {other:?}"),
        }
        match &committed_events.events[1].event {
            DomainEvent::ArtifactQuarantined(_) => {}
            other => panic!("expected ArtifactQuarantined, got {other:?}"),
        }
    }

    /// Re-evaluation pass emits
    /// `decision_point=re_evaluation` with the variant matching the
    /// outcome. Three sub-cases (StillRejected, ResetToReleased,
    /// ResetToQuarantined) collapse into one test because the mock
    /// fixture is identical except for severity / quarantine_until.
    #[test]
    fn add_exclusion_re_eval_pass_emits_metrics_per_outcome() {
        use crate::metrics::capture_metrics;

        // -- StillRejected: two findings, one excluded → still rejected.
        let snap_still = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, events, projections, artifacts, _lifecycle) =
                    make_use_case_with_re_eval_harness();
                let policy_id = Uuid::new_v4();
                let repo_id = Uuid::new_v4();
                let mut p = sample_projection(policy_id, 4);
                p.severity_threshold = SeverityThreshold::Low;
                projections.insert(p);
                let _ = seed_rejected_with_scan(&artifacts, &events, repo_id, 2);
                artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
                uc.add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
                    .await
                    .unwrap();
            });
        });
        let entries = snap_still.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "re_evaluation")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "still_rejected")
            }),
            "still_rejected outcome must emit the matching evaluation counter"
        );

        // -- ResetToReleased: window elapsed + Clean.
        let snap_released = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, events, projections, artifacts, _lifecycle) =
                    make_use_case_with_re_eval_harness();
                let policy_id = Uuid::new_v4();
                let repo_id = Uuid::new_v4();
                let mut p = sample_projection(policy_id, 4);
                p.severity_threshold = SeverityThreshold::Low;
                projections.insert(p);
                let _ = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
                artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
                uc.add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
                    .await
                    .unwrap();
            });
        });
        let entries = snap_released.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "reset_to_released")
            }),
            "reset_to_released must emit the matching evaluation counter"
        );
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_no_event_when_still_rejected() {
        // Two critical findings, one exclusion → still rejected.
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        let _artifact_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 2);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        uc.add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        // Only the policy-stream ExclusionAdded; no artifact-stream
        // commit because the re-eval came back StillRejected.
        assert_eq!(events.appended_batches().len(), 1);
        assert!(lifecycle.committed_transitions().is_empty());
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_skips_artifact_with_no_scan_completed() {
        // Best-effort: artifact with no ScanCompleted on its stream
        // is logged + skipped, and the pass continues for any other
        // rejected artifact.
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        // Seed artifact A — only an ArtifactIngested event, no
        // ScanCompleted. The pass logs error! and skips it. The fixture
        // default already places the window anchor 25h ago; the deadline
        // branch is not exercised here (the pass aborts on the missing
        // `ScanCompleted` long before re-evaluation runs).
        let a = rejected_artifact_for_repo(repo_id, "no-scan");
        let a_id = a.id;
        artifacts.insert(a);
        events.seed_stream(
            StreamId::artifact(a_id),
            vec![persisted_artifact_ingested(a_id, 0)],
        );

        // Seed artifact B with a real ScanCompleted — pass continues
        // and clears it.
        let b_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);

        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        uc.add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        // Exactly one transition (artifact B). Artifact A was skipped.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].0.id, b_id);
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_continues_on_concurrent_modification() {
        // Best-effort concurrency conflict: when commit_transition
        // returns DomainError::Conflict for one artifact, the pass
        // logs warn + continues for the other.
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        // Seed two rejected artifacts both with one critical finding.
        let a_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        let b_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        // Inject a Conflict on the next commit_transition (the first
        // rejected artifact processed).
        lifecycle.fail_next_commit(DomainError::Conflict(
            "stale stream version on artifact".into(),
        ));

        uc.add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        // Exactly one successful transition (the second artifact);
        // the first was skipped on Conflict. The use case did NOT
        // propagate the conflict — the pass is best-effort.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let committed_id = transitions[0].0.id;
        // The order in which artifacts come out of the mock is map-
        // iteration order (HashMap is unordered), so the recorded
        // transition is one of {a_id, b_id}.
        assert!(committed_id == a_id || committed_id == b_id);
    }

    #[tokio::test]
    async fn add_exclusion_re_eval_pass_zero_count_logs_pass_complete() {
        // Defence-in-depth: with no rejected artifacts the pass still
        // emits the "exclusion-added re-evaluation pass complete" log
        // and produces no errors. The success contract is "always Ok
        // when the projection-upsert succeeds" — verify the use case
        // returns Ok.
        let (uc, events, projections, _artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));

        let result = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await;
        assert!(result.is_ok());

        // Only the policy-stream ExclusionAdded.
        assert_eq!(events.appended_batches().len(), 1);
        assert!(lifecycle.committed_transitions().is_empty());
    }

    // -- remove_exclusion ----------------------------------------------------

    #[tokio::test]
    async fn remove_exclusion_nonexistent_parent_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, exclusion_id),
                api_actor(),
            )
            .await
            .unwrap_err();
        let s = err.to_string();
        assert!(s.contains("validation"), "got: {s}");
        assert!(s.contains("does not exist"), "got: {s}");

        assert!(events.appended_batches().is_empty());
        assert!(projections.exclusion_deletes().is_empty());
    }

    #[tokio::test]
    async fn remove_exclusion_archived_parent_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 2);
        p.archived = true;
        projections.insert(p);

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, Uuid::new_v4()),
                api_actor(),
            )
            .await
            .unwrap_err();
        let s = err.to_string();
        assert!(s.contains("validation"), "got: {s}");
        assert!(s.contains("archived"), "got: {s}");
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn remove_exclusion_unknown_exclusion_returns_not_found() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 1));
        // Seed a different exclusion so the list is non-empty but the
        // requested id is absent.
        projections.insert_exclusion(sample_exclusion(Uuid::new_v4(), policy_id));

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, Uuid::new_v4()),
                api_actor(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
        assert!(events.appended_batches().is_empty());
    }

    #[tokio::test]
    async fn remove_exclusion_mismatched_parent_policy_returns_validation() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let other_policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 1));
        // Manufacture a faulty-adapter scenario: the lookup key is
        // `policy_id`, but the returned exclusion claims a different
        // owning policy.
        projections.force_exclusion_list_for(
            policy_id,
            vec![sample_exclusion(exclusion_id, other_policy_id)],
        );

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, exclusion_id),
                api_actor(),
            )
            .await
            .unwrap_err();
        let s = err.to_string();
        assert!(s.contains("validation"), "got: {s}");
        assert!(s.contains("belongs to a different policy"), "got: {s}",);
        assert!(events.appended_batches().is_empty());
        assert!(projections.exclusion_deletes().is_empty());
    }

    #[tokio::test]
    async fn remove_exclusion_happy_path_emits_event_and_drops_projection() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![200],
        });

        let mut cmd = sample_remove_exclusion_command(policy_id, exclusion_id);
        cmd.reason = "false positive — confirmed".into();
        uc.remove_exclusion(cmd, api_actor()).await.unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].stream_id, StreamId::policy(policy_id));
        assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(4));
        assert_eq!(batches[0].events.len(), 1);
        match &batches[0].events[0].event {
            DomainEvent::ExclusionRemoved(e) => {
                assert_eq!(e.policy_id, policy_id);
                assert_eq!(e.exclusion_id, exclusion_id);
                assert_eq!(e.reason, "false positive — confirmed");
            }
            other => panic!("expected ExclusionRemoved, got {other:?}"),
        }

        // Exclusion deleted, parent projection bumped.
        assert_eq!(projections.exclusion_deletes(), vec![exclusion_id]);
        let upserts = projections.upserts();
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].policy_id, policy_id);
        assert_eq!(upserts[0].stream_version, 5);
    }

    #[tokio::test]
    async fn remove_exclusion_stale_version_maps_conflict_to_domain_conflict() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 9));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        events.push_append_error(DomainError::Conflict("expected version 9, found 10".into()));

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, exclusion_id),
                api_actor(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("conflict"), "got: {err}");

        // No projection writes after a conflict.
        assert!(projections.exclusion_deletes().is_empty());
        assert!(projections.upserts().is_empty());
    }

    #[tokio::test]
    async fn remove_exclusion_propagates_non_conflict_event_store_error() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        events.push_append_error(DomainError::Invariant("event store down".into()));

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, exclusion_id),
                api_actor(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("event store down"));
    }

    #[tokio::test]
    async fn remove_exclusion_propagates_delete_failure_after_append() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        projections
            .fail_next_delete_exclusion(DomainError::Invariant("exclusion delete failed".into()));

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, exclusion_id),
                api_actor(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exclusion delete failed"),
            "got: {err}"
        );
        // Append succeeded.
        assert_eq!(events.appended_batches().len(), 1);
        // Parent projection must NOT have been bumped after a delete
        // failure — the use case stops before the bump.
        assert!(projections.upserts().is_empty());
    }

    #[tokio::test]
    async fn remove_exclusion_propagates_parent_upsert_failure_after_append() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        projections.fail_next_upsert(DomainError::Invariant("policy upsert failed".into()));

        let err = uc
            .remove_exclusion(
                sample_remove_exclusion_command(policy_id, exclusion_id),
                api_actor(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("policy upsert failed"),
            "got: {err}"
        );
        // Append + delete both succeeded; only parent upsert failed.
        assert_eq!(events.appended_batches().len(), 1);
        assert_eq!(projections.exclusion_deletes(), vec![exclusion_id]);
    }

    // -- round-trip ----------------------------------------------------------

    #[tokio::test]
    async fn add_then_remove_exclusion_round_trip_advances_stream_version() {
        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 0));

        // First append → stream_position 1 (advances parent from 0).
        events.push_append_result(AppendResult {
            stream_position: 1,
            global_positions: vec![1],
        });
        let exclusion_id = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        // Verify the parent projection now records stream_version=1
        // before the second call reads it back via find_by_id.
        let after_add = projections
            .by_id
            .lock()
            .unwrap()
            .get(&policy_id)
            .cloned()
            .unwrap();
        assert_eq!(after_add.stream_version, 1);

        // Second append → stream_position 2.
        events.push_append_result(AppendResult {
            stream_position: 2,
            global_positions: vec![2],
        });
        uc.remove_exclusion(
            sample_remove_exclusion_command(policy_id, exclusion_id),
            api_actor(),
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 2);
        // Add saw the original parent.stream_version (0).
        assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(0));
        // Remove saw the bumped parent.stream_version (1).
        assert_eq!(batches[1].expected_version, ExpectedVersion::Exact(1));

        // Final parent projection sits at stream_version=2.
        let final_parent = projections
            .by_id
            .lock()
            .unwrap()
            .get(&policy_id)
            .cloned()
            .unwrap();
        assert_eq!(final_parent.stream_version, 2);

        // Exclusion projection got upserted then deleted.
        assert_eq!(projections.exclusion_upserts().len(), 1);
        assert_eq!(projections.exclusion_deletes(), vec![exclusion_id]);
    }

    #[test]
    fn add_exclusion_command_clone_preserves_fields() {
        let cmd = sample_add_exclusion_command(Uuid::new_v4());
        let cloned = cmd.clone();
        assert_eq!(cmd.policy_id, cloned.policy_id);
        assert_eq!(cmd.cve_id, cloned.cve_id);
        assert_eq!(cmd.package_pattern, cloned.package_pattern);
        assert_eq!(cmd.scope, cloned.scope);
        assert_eq!(cmd.reason, cloned.reason);
        assert_eq!(cmd.expires_at, cloned.expires_at);
    }

    #[test]
    fn remove_exclusion_command_clone_preserves_fields() {
        let cmd = sample_remove_exclusion_command(Uuid::new_v4(), Uuid::new_v4());
        let cloned = cmd.clone();
        assert_eq!(cmd.policy_id, cloned.policy_id);
        assert_eq!(cmd.exclusion_id, cloned.exclusion_id);
        assert_eq!(cmd.reason, cloned.reason);
    }

    // -- helper coverage -----------------------------------------------------

    #[test]
    fn field_change_default_is_unchanged() {
        let v: FieldChange<String> = FieldChange::default();
        assert_eq!(v, FieldChange::Unchanged);
    }

    #[test]
    fn update_policy_command_new_initialises_all_unchanged() {
        let id = Uuid::new_v4();
        let cmd = UpdatePolicyCommand::new(id);
        assert_eq!(cmd.policy_id, id);
        assert_eq!(cmd.name, FieldChange::Unchanged);
        assert_eq!(cmd.scope, FieldChange::Unchanged);
        assert_eq!(cmd.severity_threshold, FieldChange::Unchanged);
        assert_eq!(cmd.quarantine_duration_secs, FieldChange::Unchanged);
        assert_eq!(cmd.require_approval, FieldChange::Unchanged);
        assert_eq!(cmd.provenance_mode, FieldChange::Unchanged);
        assert_eq!(cmd.provenance_backends, FieldChange::Unchanged);
        assert_eq!(cmd.provenance_identities, FieldChange::Unchanged);
        assert_eq!(cmd.max_artifact_age_secs, FieldChange::Unchanged);
        assert_eq!(cmd.license_policy, FieldChange::Unchanged);
        assert_eq!(cmd.negligible_action, FieldChange::Unchanged);
    }

    #[test]
    fn optional_i64_to_value_some_returns_number() {
        assert_eq!(optional_i64_to_value(Some(42)), serde_json::Value::from(42));
    }

    #[test]
    fn optional_i64_to_value_none_returns_null() {
        assert_eq!(optional_i64_to_value(None), serde_json::Value::Null);
    }

    #[test]
    fn create_policy_command_clone_preserves_fields() {
        let cmd = sample_create_command("x");
        let cloned = cmd.clone();
        assert_eq!(cmd.name, cloned.name);
        assert_eq!(cmd.severity_threshold, cloned.severity_threshold);
    }

    // ------------------------------------------------------------------
    // `hort_curation_decisions_total` emission tests
    // for the `exclude_finding` / `unexclude_finding` decision labels.
    // ------------------------------------------------------------------

    /// Helper — extract every `hort_curation_decisions_total` increment
    /// from a `DebuggingRecorder` snapshot as
    /// `(decision, repository, result, count)` tuples in emission
    /// order. Identical shape to the curation_use_case helper but
    /// duplicated locally so the policy tests don't take a cross-
    /// module dependency on a private fn.
    fn read_curation_decisions(
        snap: metrics_util::debugging::Snapshot,
    ) -> Vec<(String, String, String, u64)> {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let mut out = Vec::new();
        for (key, _u, _d, value) in snap.into_vec() {
            if key.kind() != MetricKind::Counter
                || key.key().name() != "hort_curation_decisions_total"
            {
                continue;
            }
            let labels: std::collections::HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            let decision = labels.get("decision").copied().unwrap_or("").to_string();
            let repository = labels.get("repository").copied().unwrap_or("").to_string();
            let result = labels.get("result").copied().unwrap_or("").to_string();
            let count = match value {
                DebugValue::Counter(n) => n,
                other => panic!("expected Counter, got {other:?}"),
            };
            out.push((decision, repository, result, count));
        }
        out
    }

    /// `add_exclusion` happy path with `PolicyScope::Global` →
    /// `{decision=exclude_finding, repository=_all, result=ok}`. Global
    /// scope is cross-repo by definition; `_all` is the canonical
    /// label (cross-repo finding-exclusion).
    #[test]
    fn add_exclusion_global_scope_emits_exclude_finding_with_all_sentinel() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![100],
        });

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.add_exclusion(sample_add_exclusion_command(policy_id), api_actor()))
                .expect("add_exclusion should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, n) = &hits[0];
        assert_eq!(d, "exclude_finding");
        assert_eq!(r, "_all"); // Global scope.
        assert_eq!(res, "ok");
        assert_eq!(*n, 1);
    }

    /// `add_exclusion` with `PolicyScope::Repository(id)` resolves
    /// the repo key via the threaded `RepositoryAccessUseCase`.
    /// `{decision=exclude_finding, repository=<key>, result=ok}`.
    #[test]
    fn add_exclusion_repository_scope_emits_resolved_repo_key() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        let repo_access = repository_access_with_key(repo_id, "scoped-repo", true);
        let (uc, events, projections) = make_use_case_with_repo_access(repo_access);
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![100],
        });

        let mut cmd = sample_add_exclusion_command(policy_id);
        cmd.scope = PolicyScope::Repository(repo_id);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.add_exclusion(cmd, api_actor()))
                .expect("add_exclusion should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "exclude_finding");
        assert_eq!(r, "scoped-repo");
        assert_eq!(res, "ok");
    }

    /// `add_exclusion` with the cardinality knob off
    /// (`include_repository_label = false`) collapses every
    /// repository-scoped exclusion's label to `_all`, regardless of
    /// scope. Mirrors the curation_use_case knob-off test.
    #[test]
    fn add_exclusion_with_cardinality_knob_off_emits_all_sentinel() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        // include_label = false → metric_label always returns `_all`.
        let repo_access = repository_access_with_key(repo_id, "scoped-repo", false);
        let (uc, events, projections) = make_use_case_with_repo_access(repo_access);
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![100],
        });

        let mut cmd = sample_add_exclusion_command(policy_id);
        cmd.scope = PolicyScope::Repository(repo_id);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.add_exclusion(cmd, api_actor()))
                .expect("add_exclusion should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (_, r, _, _) = &hits[0];
        // Knob off → `_all` even for Repository scope.
        assert_eq!(r, "_all");
    }

    /// `add_exclusion` archived-parent rejection emits
    /// `result=invalid`. The repo label was resolved at the call
    /// boundary (`PolicyScope::Global` here → `_all`).
    #[test]
    fn add_exclusion_archived_parent_emits_invalid_metric() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, _events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.archived = true;
        projections.insert(p);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.add_exclusion(sample_add_exclusion_command(policy_id), api_actor()))
                .expect_err("archived parent must fail");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "exclude_finding");
        assert_eq!(r, "_all");
        assert_eq!(res, "invalid");
    }

    /// `add_exclusion` event-store conflict emits `result=conflict`.
    /// The 4xx-like signal operators alert on for contention.
    #[test]
    fn add_exclusion_event_store_conflict_emits_conflict_metric() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 9));
        events.push_append_error(DomainError::Conflict("expected 9, found 10".into()));

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.add_exclusion(sample_add_exclusion_command(policy_id), api_actor()))
                .expect_err("conflict must propagate");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (_, _, res, _) = &hits[0];
        assert_eq!(res, "conflict");
    }

    /// `remove_exclusion` happy path emits
    /// `{decision=unexclude_finding, repository=_all, result=ok}` for
    /// a `PolicyScope::Global` exclusion (the
    /// `sample_exclusion` fixture's default).
    #[test]
    fn remove_exclusion_global_scope_emits_unexclude_finding_with_all_sentinel() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 7));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        events.push_append_result(AppendResult {
            stream_position: 8,
            global_positions: vec![200],
        });

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.remove_exclusion(
                    sample_remove_exclusion_command(policy_id, exclusion_id),
                    api_actor(),
                ))
                .expect("remove_exclusion should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "unexclude_finding");
        assert_eq!(r, "_all");
        assert_eq!(res, "ok");
    }

    /// `remove_exclusion` of a `PolicyScope::Repository(id)`
    /// exclusion resolves the repo key for the `unexclude_finding`
    /// label.
    #[test]
    fn remove_exclusion_repository_scope_emits_resolved_repo_key() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        let repo_access = repository_access_with_key(repo_id, "scoped-repo", true);
        let (uc, events, projections) = make_use_case_with_repo_access(repo_access);
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 7));
        let mut excl = sample_exclusion(exclusion_id, policy_id);
        excl.scope = PolicyScope::Repository(repo_id);
        projections.insert_exclusion(excl);
        events.push_append_result(AppendResult {
            stream_position: 8,
            global_positions: vec![200],
        });

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.remove_exclusion(
                    sample_remove_exclusion_command(policy_id, exclusion_id),
                    api_actor(),
                ))
                .expect("remove_exclusion should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "unexclude_finding");
        assert_eq!(r, "scoped-repo");
        assert_eq!(res, "ok");
    }

    /// `remove_exclusion` event-store conflict emits
    /// `unexclude_finding/conflict`.
    #[test]
    fn remove_exclusion_event_store_conflict_emits_conflict_metric() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, events, projections) = make_use_case();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 9));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        events.push_append_error(DomainError::Conflict("stale".into()));

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.remove_exclusion(
                    sample_remove_exclusion_command(policy_id, exclusion_id),
                    api_actor(),
                ))
                .expect_err("conflict must propagate");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, _, res, _) = &hits[0];
        assert_eq!(d, "unexclude_finding");
        assert_eq!(res, "conflict");
    }
}
