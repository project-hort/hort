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

use hort_domain::entities::artifact::{
    is_scan_clearable, Artifact, CurationClearance, ProvenanceClearance, QuarantineStatus,
};
use hort_domain::entities::scan_policy::{
    ExclusionProjection, NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    SignerIdentityPattern,
};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ArtifactReEvaluated, ArtifactRejected, DomainEvent, ExclusionAdded, ExclusionRemoved,
    PolicyArchived, PolicyCreated, PolicyField, PolicyReactivated, PolicyScope, PolicyUpdated,
    ReEvaluationTrigger, RejectionReason, StreamId,
};
use hort_domain::policy::{
    effective_quarantine_deadline, evaluate_curation, evaluate_scan_result,
    re_evaluate_after_exclusion, CurationOutcome, ReEvaluationOutcome,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ArtifactCoords, PageRequest};

use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_curation_decision, emit_policy_evaluation, emit_policy_reevaluation_result,
    increment_policy_reevaluation_enqueue_failed, policy_decision_point,
    set_policy_reevaluation_population, CurationDecisionLabel, CurationDecisionResult,
    PolicyEvaluationResult, PolicyReEvaluationResult,
};
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::release_clearance::resolve_provenance_clearance;
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
    /// Active curation rules for an artifact's repository, the input to
    /// the **active curation precondition** of the cross-axis release
    /// conjunction (ADR 0041, invariant #6 (c)). The post-exclusion
    /// re-evaluation pass calls `list_for_repo(repo_id)` →
    /// `evaluate_curation(coords, rules)` per candidate and refuses to
    /// release any artifact a currently-active curation rule blocks —
    /// the case the rejection-reason guard alone misses (a *scan*-rejected
    /// artifact is eligible, but a curation rule added *after* the scan
    /// rejection is not re-applied by the retroactive curation pass).
    /// Read-only access — no writes.
    curation_rules: Arc<dyn CurationRuleRepository>,
    /// Repository-key resolution for the
    /// `hort_curation_decisions_total{repository}` label emitted by
    /// `add_exclusion` / `remove_exclusion` on the curator path.
    /// Exclusions with `PolicyScope::Repository(id)` resolve to the
    /// repo key via [`RepositoryAccessUseCase::metric_label`];
    /// `PolicyScope::Global` exclusions (cross-repo finding-exclusion)
    /// emit the `_all` sentinel. The same helper
    /// honours `METRICS_INCLUDE_REPOSITORY_LABEL=false`.
    repository_access: Arc<RepositoryAccessUseCase>,
    /// Job-queue port used to enqueue the async `policy-reevaluation`
    /// worker task off the policy-mutation request path (ADR 0041 Item
    /// 3). Every gate-affecting mutation (`update_policy` gate fields,
    /// `add_exclusion`, `remove_exclusion`, `reactivate_policy`) enqueues
    /// **one** row carrying `{ policy_id, trigger }`; the worker claims it
    /// and runs `run_policy_re_evaluation_pass`. A multi-field
    /// `update_policy` coalesces to a single enqueue, not one per
    /// `PolicyUpdated` event. Best-effort: an enqueue failure is logged
    /// and the mutation still succeeds (the next gate-affecting mutation
    /// re-enqueues; fail-safe in the loosen direction, and the operator's
    /// tighten is recoverable by re-applying).
    jobs: Arc<dyn JobsRepository>,
}

impl PolicyUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        events: Arc<EventStorePublisher>,
        projections: Arc<dyn PolicyProjectionRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        artifact_lifecycle: Arc<dyn ArtifactLifecyclePort>,
        storage: Arc<dyn StoragePort>,
        repository_access: Arc<RepositoryAccessUseCase>,
        curation_rules: Arc<dyn CurationRuleRepository>,
        jobs: Arc<dyn JobsRepository>,
    ) -> Self {
        Self {
            events,
            projections,
            artifacts,
            artifact_lifecycle,
            storage,
            repository_access,
            curation_rules,
            jobs,
        }
    }

    /// Enqueue **one** async `policy-reevaluation` worker task for a
    /// gate-affecting policy mutation (ADR 0041 Item 3).
    ///
    /// The job row carries `{ policy_id, trigger }` in `params`; the
    /// worker claims it and runs [`Self::run_policy_re_evaluation_pass`]
    /// off the request path. **Enqueue-once contract:** the caller invokes
    /// this exactly once per mutation — a multi-field `update_policy`
    /// (which emits one `PolicyUpdated` event per changed field) calls it
    /// a single time with the policy-scoped
    /// [`ReEvaluationTrigger::PolicyUpdated`], so the population pass is
    /// not run N times for one logical change.
    ///
    /// **Best-effort.** An enqueue failure is logged and swallowed — the
    /// policy mutation itself already committed and must not be rolled
    /// back for a queue hiccup. Fail-safe in the loosen direction (a
    /// missed loosen leaves artifacts `Rejected` — stuck, not released);
    /// the operator recovers a missed tighten by re-applying the policy
    /// (which re-enqueues). `trigger_source = "manual"` — the mutation is
    /// operator/gitops-driven (no dedicated `jobs.trigger_source`
    /// literal is added; that surface is out of scope for Item 3). No
    /// idempotency key — `policy-reevaluation` is not in
    /// `DESTRUCTIVE_TASK_KINDS` (ADR 0028) and the pass is naturally
    /// verdict-idempotent, so a duplicate enqueue at worst re-runs an
    /// all-no-ops pass.
    async fn enqueue_re_evaluation(&self, policy_id: Uuid, trigger: ReEvaluationTrigger) {
        let params = serde_json::json!({
            "policy_id": policy_id,
            "trigger": trigger,
        });
        match self
            .jobs
            .enqueue_task(
                "policy-reevaluation",
                &params,
                None, // system/gitops-driven; no operator actor on the row
                0i16, // default priority — a background population pass
                "manual",
                None, // non-destructive kind → no DB-side idempotency key
            )
            .await
        {
            Ok(outcome) => {
                tracing::info!(
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    outcome = ?outcome,
                    "enqueued policy re-evaluation pass (ADR 0041)",
                );
            }
            Err(e) => {
                // Alertable signal: the pass never ran. The completion
                // metrics (`hort_policy_reevaluation_*`) only fire at pass
                // end, so a swallowed enqueue is otherwise invisible — for a
                // TIGHTEN this leaves the now-non-compliant population
                // downloadable with no other signal. Increment, then keep
                // swallowing (the mutation already committed).
                increment_policy_reevaluation_enqueue_failed();
                tracing::warn!(
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "policy re-evaluation enqueue failed after the policy mutation \
                     committed; the pass did not run (the next gate-affecting mutation \
                     re-enqueues — fail-safe for loosen; re-apply to recover a tighten)",
                );
            }
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
        // ADR 0041 Item 3: a gate-affecting field change (severity
        // threshold / license-policy classes / negligible_action) drives
        // ONE async re-evaluation pass over the policy's population, even
        // when several gate fields changed in this single `update_policy`
        // — `update_policy` emits one `PolicyUpdated` per changed field, so
        // coalescing to a single enqueue here is the enqueue-once-per-
        // mutation contract (not one pass per field). Computed before
        // `events` is moved into the append batch.
        let gate_field_changed = events.iter().any(|e| {
            matches!(
                &e.event,
                DomainEvent::PolicyUpdated(u) if u.field.is_gate_affecting()
            )
        });
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

        // Enqueue ONE async re-evaluation pass iff a gate-affecting field
        // changed (ADR 0041 Item 3). A name/scope/timer-only update emits
        // events but enqueues nothing — those fields do not change a
        // stored-findings verdict (see `PolicyField::is_gate_affecting`).
        if gate_field_changed {
            self.enqueue_re_evaluation(policy_id, ReEvaluationTrigger::PolicyUpdated { policy_id })
                .await;
        }

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

        // Reactivation re-arms a previously-archived policy's gate over
        // its in-scope population, so re-evaluate both directions (ADR
        // 0041 §Triggers-and-scope lists `reactivate_policy`). The
        // population may have shifted under whatever default policy
        // applied while this one was archived; the pass reconciles it.
        self.enqueue_re_evaluation(policy_id, ReEvaluationTrigger::PolicyUpdated { policy_id })
            .await;

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

        // Re-evaluation is now async (ADR 0041 Item 3): adding an
        // exclusion is a loosen, so enqueue ONE `policy-reevaluation`
        // pass off the request path rather than running the bounded sweep
        // inline. The generalised pass (`run_policy_re_evaluation_pass`)
        // walks the full in-scope population with no 10k truncate — the
        // fail-open ceiling the inline post-exclusion sweep carried in the
        // tighten direction is gone. The trigger carries the just-added
        // `exclusion_id` so the audit names the driving change
        // (invariant #3); the worker re-reads the bumped projection +
        // exclusion set, so no policy snapshot is threaded into the task.
        self.enqueue_re_evaluation(
            policy_id,
            ReEvaluationTrigger::ExclusionAdded { exclusion_id },
        )
        .await;

        Ok(exclusion_id)
    }

    /// Re-hydrate the artifact's structured rejection reason from its
    /// stored `ArtifactRejected` event (ADR 0041 invariant #6 (a)).
    ///
    /// The `artifacts` projection does not persist the reason — it lives
    /// on the artifact's event stream. Scans the stream in reverse for the
    /// most recent [`DomainEvent::ArtifactRejected`] and returns its
    /// `rejected_by`. `Ok(None)` when no rejection event is present (an
    /// unknown reason — ineligible by default). Infrastructure read
    /// failures surface as `Err` so the caller can skip the artifact
    /// rather than treat an unknown reason as scan-clearable.
    async fn hydrate_rejection_reason(
        &self,
        artifact_id: Uuid,
    ) -> AppResult<Option<RejectionReason>> {
        let stream_id = StreamId::artifact(artifact_id);
        // The same 200-event reverse-scan bound the scan-history helper
        // uses; an artifact stream begins well within it.
        let persisted = self
            .events
            .read_stream(
                &stream_id,
                hort_domain::ports::event_store::ReadFrom::Start,
                200,
            )
            .await?;
        Ok(persisted.iter().rev().find_map(|e| match &e.event {
            DomainEvent::ArtifactRejected(r) => Some(r.rejected_by.clone()),
            _ => None,
        }))
    }

    /// Compute the **active curation precondition** of the cross-axis
    /// release conjunction (ADR 0041 invariant #6 (c)) for one artifact.
    ///
    /// Lists the artifact's repository's live curation rules
    /// (`list_for_repo`) and runs the pure `evaluate_curation` over coords
    /// built from the artifact (format resolved from the repository — the
    /// format gate input). Returns [`CurationClearance::Blocked`] iff a
    /// currently-active rule yields `CurationOutcome::Block`; `Warn` /
    /// `Allow` / no-match all resolve to [`CurationClearance::Cleared`].
    async fn resolve_curation_clearance(
        &self,
        artifact: &Artifact,
    ) -> AppResult<CurationClearance> {
        let rules = self
            .curation_rules
            .list_for_repo(artifact.repository_id)
            .await?;
        if rules.is_empty() {
            // Fast path: no rules → cleared, no format lookup needed.
            return Ok(CurationClearance::Cleared);
        }
        // The curation format gate needs the repository's format; every
        // artifact in a repo shares it. A missing repo row resolves to the
        // `Generic` format (the curation evaluator's `any`-format rules
        // still apply; a format-specific rule simply won't match a Generic
        // coord — the same no-match→Cleared path).
        let format = self
            .repository_access
            .repository_format(artifact.repository_id)
            .await?
            .unwrap_or(hort_domain::entities::repository::RepositoryFormat::Generic);
        let coords = ArtifactCoords {
            name: artifact.name.clone(),
            name_as_published: artifact.name_as_published.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            format,
            metadata: serde_json::Value::Null,
        };
        Ok(match evaluate_curation(&coords, &rules) {
            CurationOutcome::Block { .. } => CurationClearance::Blocked,
            CurationOutcome::Warn { .. } | CurationOutcome::Allow => CurationClearance::Cleared,
        })
    }

    /// Generalised both-directions re-evaluation pass over the **whole**
    /// in-scope population of a policy (ADR 0041 §3). Run async off the
    /// policy-mutation request path: every gate-affecting mutation
    /// (`update_policy` gate fields, `add_exclusion`, `remove_exclusion`,
    /// `reactivate_policy`) enqueues ONE `policy-reevaluation` worker task
    /// (`Self::enqueue_re_evaluation`); the worker's
    /// [`PolicyReEvaluationHandler`](crate::task_handlers::PolicyReEvaluationHandler)
    /// claims the row and dispatches here.
    ///
    /// Runs both directions against the policy's currently-stored
    /// projection + exclusions:
    ///
    /// - **Loosen** — every `Rejected` artifact whose active scan-policy
    ///   resolves to `policy_id` ([`ArtifactRepository::list_rejected_for_policy`]):
    ///   re-derive the verdict over stored findings under the bumped policy,
    ///   and (subject to ADR 0041 invariant #6's cross-axis conjunction)
    ///   transition `Released` / re-`Quarantined` / hold. Shares the exact
    ///   per-artifact body with the legacy post-exclusion pass
    ///   ([`Self::re_evaluate_one_rejected`]). This direction keeps the
    ///   `LimitedList` cap: a truncation there merely *defers* a few would-be
    ///   releases — fail-safe (the artifact stays `Rejected`).
    /// - **Tighten** — every active (`Released` / `Quarantined`) scanned
    ///   artifact ([`ArtifactRepository::list_active_for_policy`]):
    ///   re-derive the verdict; a now-failing artifact is re-held via
    ///   [`Artifact::reject_from_scan_policy_retroactive`], a still-clean one
    ///   is a no-op. This direction is **fully paginated with NO fixed cap** —
    ///   a `LimitedList` cap here would be fail-OPEN (a now-failing artifact
    ///   past the cap keeps serving), so the pass walks pages until
    ///   exhaustion.
    ///
    /// **`Ok(None)` from the domain transition is the no-op branch** — no
    /// `ArtifactReEvaluated` is appended for an unchanged verdict (both
    /// directions). The pass is naturally verdict-idempotent: a re-run over
    /// the same stored evidence + policy reaches the same verdict, so the
    /// second run is all no-ops. `commit_transition` carries event-version
    /// optimistic concurrency, so concurrent passes are safe (a stale
    /// transition fails its version check and is skipped as a best-effort).
    ///
    /// Best-effort throughout: a single artifact's infrastructure failure is
    /// logged and skipped — one bad artifact never aborts the pass.
    #[tracing::instrument(skip(self))]
    pub async fn run_policy_re_evaluation_pass(
        &self,
        policy_id: Uuid,
        trigger: ReEvaluationTrigger,
    ) {
        // Resolve the policy projection + its current exclusion set once;
        // both directions read the same bumped policy. An absent or
        // archived policy is a no-op (best-effort — a concurrent archive
        // raced the enqueue).
        let policy = match self.projections.find_by_id(policy_id).await {
            Ok(Some(p)) if !p.archived => p,
            Ok(_) => {
                tracing::info!(
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    "policy re-evaluation pass: policy missing or archived; skipping",
                );
                return;
            }
            Err(e) => {
                tracing::error!(
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "policy re-evaluation pass: find_by_id failed; skipping pass",
                );
                return;
            }
        };
        let exclusions = match self.projections.list_exclusions_for_policy(policy_id).await {
            Ok(list) => list,
            Err(e) => {
                tracing::error!(
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "policy re-evaluation pass: list_exclusions_for_policy failed; skipping pass",
                );
                return;
            }
        };

        let now = Utc::now();

        // ---- Loosen direction -------------------------------------------
        let mut loosen = LoosenTallies::default();
        let mut loosen_total: u64 = 0;
        match self.artifacts.list_rejected_for_policy(policy_id).await {
            Ok(rejected_list) => {
                if rejected_list.truncated {
                    tracing::warn!(
                        policy_id = %policy_id,
                        cap = hort_domain::types::LIMIT_LIST_MAX_ITEMS,
                        "policy re-evaluation pass (loosen): list_rejected_for_policy truncated \
                         at cap; remaining rejected artifacts stay Rejected (fail-safe) until a \
                         later pass",
                    );
                }
                loosen_total = rejected_list.items.len() as u64;
                for artifact in rejected_list.items {
                    self.re_evaluate_one_rejected(
                        artifact,
                        policy_id,
                        trigger,
                        &policy,
                        &exclusions,
                        now,
                        &mut loosen,
                    )
                    .await;
                }
            }
            Err(e) => {
                tracing::error!(
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "policy re-evaluation pass (loosen): list_rejected_for_policy failed; \
                     skipping loosen direction",
                );
            }
        }

        // ---- Tighten direction (fully paginated, NO cap) ----------------
        let mut tighten = TightenTallies::default();
        let mut tighten_total: u64 = 0;
        // Page through the whole active population. `PER_PAGE` is the
        // workspace `MAX_LIMIT` (1 000) — `PageRequest::new` clamps to it —
        // so a large population amortises to one round-trip per 1 000 rows.
        //
        // OFFSET-walk-over-a-shrinking-set invariant: a re-held artifact
        // LEAVES the active population (`Released`/`Quarantined` → `Rejected`),
        // so every subsequent `list_active_for_policy` read sees a set
        // shorter by the number already re-held. Advancing the cursor by the
        // full page size would then skip that many still-active rows. Advance
        // it only by the count that STAYED active this page (unchanged
        // no-ops + best-effort skips) — the re-held rows have shifted out
        // from under the offset. The loop terminates when a page under-
        // fetches (population exhausted) or no progress is possible.
        const PER_PAGE: u64 = 1_000;
        let mut offset: u64 = 0;
        loop {
            let page = match self
                .artifacts
                .list_active_for_policy(policy_id, PageRequest::new(offset, PER_PAGE))
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        policy_id = %policy_id,
                        trigger = ?trigger,
                        offset,
                        error = %e,
                        "policy re-evaluation pass (tighten): list_active_for_policy failed; \
                         aborting tighten walk (already-processed pages keep their transitions)",
                    );
                    break;
                }
            };
            let fetched = page.items.len() as u64;
            if fetched == 0 {
                break;
            }
            let re_held_before = tighten.re_held;
            for artifact in page.items {
                tighten_total += 1;
                self.re_evaluate_one_active(
                    artifact,
                    policy_id,
                    trigger,
                    &policy,
                    &exclusions,
                    now,
                    &mut tighten,
                )
                .await;
            }
            let re_held_this_page = tighten.re_held - re_held_before;
            // Rows that stayed active (no-op or best-effort skip) this page.
            let stayed = fetched - re_held_this_page;
            if fetched < PER_PAGE {
                // Last page (under-fetch) — population exhausted.
                break;
            }
            if stayed == 0 {
                // Whole page re-held (all left the set) — the next read at
                // the same offset surfaces fresh rows; do NOT advance.
                continue;
            }
            offset += stayed;
        }

        // ADR 0041 §5 outcome metric + completeness signal. The
        // `result`-labelled counter folds each tally bucket into the
        // closed three-value taxonomy (no high-cardinality labels):
        //   released   = loosen `reset_released`;
        //   re_held    = tighten `re_held`;
        //   unchanged  = every download-status-unchanged outcome —
        //                loosen still-rejected + the re-quarantine arm
        //                (artifact stays held, download status unchanged)
        //                + loosen cross-axis holds + tighten still-clean.
        // The population gauge reports the in-scope set this pass actually
        // walked (loosen + tighten); a direction that aborted early
        // surfaces as a population/counter gap rather than silently.
        let unchanged = loosen.still_rejected
            + loosen.reset_quarantined
            + loosen.held_cross_axis
            + tighten.unchanged;
        let population = loosen_total + tighten_total;
        emit_policy_reevaluation_result(PolicyReEvaluationResult::Released, loosen.reset_released);
        emit_policy_reevaluation_result(PolicyReEvaluationResult::ReHeld, tighten.re_held);
        emit_policy_reevaluation_result(PolicyReEvaluationResult::Unchanged, unchanged);
        set_policy_reevaluation_population(population);

        // One pass-completion summary line (NOT per artifact): trigger, the
        // in-scope population walked, and the folded released / re_held /
        // unchanged taxonomy (mirrors `hort_policy_reevaluation_*`). The
        // per-bucket loosen/tighten breakdown is retained for diagnosis.
        tracing::info!(
            policy_id = %policy_id,
            trigger = ?trigger,
            population,
            released = loosen.reset_released,
            re_held = tighten.re_held,
            unchanged,
            loosen_population = loosen_total,
            count_reset_released = loosen.reset_released,
            count_reset_quarantined = loosen.reset_quarantined,
            count_still_rejected = loosen.still_rejected,
            count_held_cross_axis = loosen.held_cross_axis,
            tighten_population = tighten_total,
            count_re_held = tighten.re_held,
            count_tighten_unchanged = tighten.unchanged,
            "policy re-evaluation pass complete",
        );
    }

    /// Re-evaluate one active (`Released` / `Quarantined`) artifact in the
    /// **tighten** direction (ADR 0041). Re-derives the verdict over the
    /// artifact's stored findings under the bumped policy via
    /// [`evaluate_scan_result`]; a now-failing verdict re-holds the
    /// artifact through [`Artifact::reject_from_scan_policy_retroactive`]
    /// (which returns `Ok(None)` on a still-clean verdict — the no-op
    /// branch, no event appended). The timer window is **not** re-opened.
    ///
    /// Best-effort: a per-artifact infrastructure failure is logged and
    /// skipped. "No stored findings" ⇒ [`ScanOutcome::Clean`] ⇒ no-op
    /// (invariant #4 — a tighten never re-rejects an artifact with no
    /// evidence it violates).
    #[allow(clippy::too_many_arguments)]
    async fn re_evaluate_one_active(
        &self,
        mut artifact: Artifact,
        policy_id: Uuid,
        trigger: ReEvaluationTrigger,
        policy: &ScanPolicyProjection,
        exclusions: &[ExclusionProjection],
        now: DateTime<Utc>,
        tallies: &mut TightenTallies,
    ) {
        let artifact_id = artifact.id;

        // Re-derive the verdict from the artifact's stored findings. A
        // genuine event-store read failure surfaces as `Err` (skip); a
        // missing/clean scan yields `None` (an empty finding set → Clean →
        // no-op, invariant #4).
        let last_findings =
            match scan_history::read_last_findings(&*self.events, &self.storage, artifact_id).await
            {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(
                        artifact_id = %artifact_id,
                        policy_id = %policy_id,
                        trigger = ?trigger,
                        error = %e,
                        "re-evaluation (tighten): failed to hydrate findings_blob; \
                         skipping artifact",
                    );
                    return;
                }
            };
        let findings = last_findings.unwrap_or_default();

        // The curation format gate input needs the repository's format;
        // resolve it (an absent repo row defaults to `Generic`, matching
        // `resolve_curation_clearance`). A lookup failure skips the
        // artifact (best-effort).
        let format = match self
            .repository_access
            .repository_format(artifact.repository_id)
            .await
        {
            Ok(f) => f.unwrap_or(hort_domain::entities::repository::RepositoryFormat::Generic),
            Err(e) => {
                tracing::error!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "re-evaluation (tighten): failed to resolve repository format; \
                     skipping artifact",
                );
                return;
            }
        };
        let coords = ArtifactCoords {
            name: artifact.name.clone(),
            name_as_published: artifact.name_as_published.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            format,
            metadata: serde_json::Value::Null,
        };

        // Both directions read ONE verdict source: `evaluate_scan_result`
        // over the stored findings under the bumped policy (invariant #2 —
        // loosen and tighten cannot diverge).
        let outcome = evaluate_scan_result(&coords, &findings, Some(policy), exclusions, now);
        let previous_status = artifact.quarantine_status;

        match artifact.reject_from_scan_policy_retroactive(&outcome, "scan-policy tighten".into()) {
            // No-op: still-clean verdict (`ScanOutcome::Clean`) — no
            // transition, no `ArtifactReEvaluated` (the threaded
            // `Ok(None)` contract from Item 1).
            Ok(None) => {
                tallies.unchanged += 1;
                emit_policy_evaluation(
                    policy_decision_point::RE_EVALUATION,
                    PolicyEvaluationResult::NoChange,
                );
            }
            // Now-failing verdict — re-hold. Commit the audit event + the
            // `ArtifactRejected` companion atomically.
            Ok(Some(rejected)) => {
                if self
                    .commit_tighten(artifact, policy_id, trigger, previous_status, rejected)
                    .await
                {
                    tallies.re_held += 1;
                    tracing::info!(
                        artifact_id = %artifact_id,
                        policy_id = %policy_id,
                        previous_status = %previous_status,
                        outcome = "re_held",
                        "artifact re-evaluated (tighten): re-held under the bumped policy",
                    );
                    emit_policy_evaluation(
                        policy_decision_point::RE_EVALUATION,
                        PolicyEvaluationResult::Reject,
                    );
                }
            }
            // Terminal source state (`None` / `Rejected` / `ScanIndeterminate`)
            // — the entity rejected the transition WITHOUT mutating, so we
            // skip the append. `list_active_for_policy` only returns
            // `Quarantined` / `Released`, so this is reachable only under a
            // concurrent transition between the list read and here.
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "re-evaluation (tighten): entity rejected the re-hold (likely a \
                     concurrent transition); skipping artifact",
                );
            }
        }
    }

    /// Commit a tighten-direction re-hold atomically: the
    /// `ArtifactReEvaluated` audit event plus the `ArtifactRejected`
    /// companion (already produced by
    /// [`Artifact::reject_from_scan_policy_retroactive`]) in one
    /// `commit_transition` call. Mirrors [`Self::commit_re_evaluation`] but
    /// for the `active → Rejected` direction.
    ///
    /// Returns `true` on success, `false` on best-effort skip (a
    /// `DomainError::Conflict` from a parallel transition that bumped the
    /// stream between the read and the append, or any other commit failure).
    async fn commit_tighten(
        &self,
        artifact: Artifact,
        policy_id: Uuid,
        trigger: ReEvaluationTrigger,
        previous_status: QuarantineStatus,
        rejected: ArtifactRejected,
    ) -> bool {
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);

        let expected_version = match read_expected_version(&*self.events, &stream_id, false).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "concurrent modification during re-evaluation pass (tighten); \
                     skipping artifact",
                );
                return false;
            }
        };

        let re_evaluated = ArtifactReEvaluated {
            artifact_id,
            policy_id,
            trigger,
            previous_status,
            new_status: QuarantineStatus::Rejected,
        };

        let score_delta = RepoSecurityScoreProjector::compute_re_evaluated_delta(
            previous_status,
            QuarantineStatus::Rejected,
        );
        let repository_id = artifact.repository_id;
        let actor = hort_domain::events::system_actor();

        match self
            .artifact_lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![
                        EventToAppend::new(DomainEvent::ArtifactReEvaluated(re_evaluated)),
                        EventToAppend::new(DomainEvent::ArtifactRejected(rejected)),
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
                    trigger = ?trigger,
                    conflict = %msg,
                    "concurrent modification during re-evaluation pass (tighten); \
                     skipping artifact",
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "re-evaluation (tighten) commit_transition failed; skipping artifact",
                );
                false
            }
        }
    }

    /// Re-evaluate one `Rejected` artifact in the **loosen** direction (the
    /// shared per-artifact body of both the legacy post-exclusion pass and
    /// the generalised `run_policy_re_evaluation_pass`).
    ///
    /// Applies ADR 0041 invariant #6's cross-axis release conjunction:
    /// (a) only a `Scanner` rejection is scan-clearable; (b)/(c) the
    /// `Released` arm fires only when provenance ∧ curation currently
    /// clear. Each per-artifact infrastructure failure is logged and
    /// skipped (best-effort — one bad artifact never aborts the pass); the
    /// matching `tallies` counter is bumped on each terminal outcome and
    /// the per-decision metric is emitted.
    #[allow(clippy::too_many_arguments)]
    async fn re_evaluate_one_rejected(
        &self,
        mut artifact: Artifact,
        policy_id: Uuid,
        trigger: ReEvaluationTrigger,
        policy: &ScanPolicyProjection,
        updated_exclusions: &[ExclusionProjection],
        now: DateTime<Utc>,
        tallies: &mut LoosenTallies,
    ) {
        let artifact_id = artifact.id;

        // (a) Eligibility guard: re-hydrate the rejection reason from
        // the stream and skip any non-scan-clearable rejection — a
        // provenance- / curation- / admin-rejected artifact is NOT a
        // candidate for a scan re-judgement (the pre-ADR-0041 pass
        // released it irrespective of reason — the live fail-open).
        // An infrastructure read failure skips the artifact.
        let reason = match self.hydrate_rejection_reason(artifact_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "re-evaluation (loosen): failed to read rejection reason; \
                     skipping artifact",
                );
                return;
            }
        };
        artifact.rejection_reason = reason.clone();
        if !is_scan_clearable(reason.as_ref()) {
            tallies.held_cross_axis += 1;
            tracing::info!(
                artifact_id = %artifact_id,
                policy_id = %policy_id,
                reason = ?reason,
                outcome = "ineligible_non_scanner",
                "artifact re-evaluation held: rejection reason is not scan-clearable \
                 (ADR 0041 invariant #6)",
            );
            emit_policy_evaluation(
                policy_decision_point::RE_EVALUATION,
                PolicyEvaluationResult::StillRejected,
            );
            return;
        }

        let last_snapshot =
            match scan_history::read_last_scan_completed(&*self.events, artifact_id).await {
                Ok(Some(s)) => s,
                Ok(None) => {
                    tracing::error!(
                        artifact_id = %artifact_id,
                        policy_id = %policy_id,
                        trigger = ?trigger,
                        "re-evaluation (loosen): no ScanCompleted on artifact stream; \
                         skipping artifact",
                    );
                    return;
                }
                Err(e) => {
                    tracing::error!(
                        artifact_id = %artifact_id,
                        policy_id = %policy_id,
                        trigger = ?trigger,
                        error = %e,
                        "re-evaluation (loosen): failed to read artifact stream; \
                         skipping artifact",
                    );
                    return;
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
            match scan_history::read_last_findings(&*self.events, &self.storage, artifact_id).await
            {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(
                        artifact_id = %artifact_id,
                        policy_id = %policy_id,
                        trigger = ?trigger,
                        error = %e,
                        "re-evaluation (loosen): failed to hydrate findings_blob; \
                         skipping artifact",
                    );
                    return;
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
                chrono::Duration::seconds(policy.quarantine_duration_secs),
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
            Some(policy),
            updated_exclusions,
            quarantine_deadline,
            now,
        );

        match outcome {
            ReEvaluationOutcome::StillRejected => {
                tallies.still_rejected += 1;
                tracing::info!(
                    artifact_id = %artifact_id,
                    outcome = "still_rejected",
                    "artifact re-evaluated (loosen)",
                );
                emit_policy_evaluation(
                    policy_decision_point::RE_EVALUATION,
                    PolicyEvaluationResult::StillRejected,
                );
            }
            ReEvaluationOutcome::ResetToQuarantined => {
                // The re-quarantine arm keeps the artifact held
                // (downloads blocked), so the cross-axis conjuncts do
                // not gate it — the eventual timer release re-applies
                // the provenance gate via `release()`. Pass the
                // not-gating clearances; `re_evaluate` ignores them on
                // this arm.
                if self
                    .commit_re_evaluation(
                        artifact,
                        policy_id,
                        trigger,
                        QuarantineStatus::Rejected,
                        QuarantineStatus::Quarantined,
                        ProvenanceClearance::NotRequired,
                        CurationClearance::Cleared,
                    )
                    .await
                {
                    tallies.reset_quarantined += 1;
                    tracing::info!(
                        artifact_id = %artifact_id,
                        outcome = "reset_to_quarantined",
                        "artifact re-evaluated (loosen)",
                    );
                    emit_policy_evaluation(
                        policy_decision_point::RE_EVALUATION,
                        PolicyEvaluationResult::ResetToQuarantined,
                    );
                }
            }
            ReEvaluationOutcome::ResetToReleased => {
                // The scan now passes and the window has elapsed — but
                // release fires only on the full conjunction
                // `scan ∧ curation ∧ provenance` (ADR 0041 invariant
                // #6). Compute the two cross-axis clearances; if either
                // currently denies, hold the artifact `Rejected`
                // (fail-closed) and count it as held — NOT released.
                let provenance = match resolve_provenance_clearance(
                    &*self.events,
                    artifact_id,
                    policy.provenance_mode,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            artifact_id = %artifact_id,
                            policy_id = %policy_id,
                            error = %e,
                            "re-evaluation (loosen): failed to resolve provenance \
                             clearance; skipping artifact",
                        );
                        return;
                    }
                };
                let curation = match self.resolve_curation_clearance(&artifact).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            artifact_id = %artifact_id,
                            policy_id = %policy_id,
                            error = %e,
                            "re-evaluation (loosen): failed to resolve curation \
                             clearance; skipping artifact",
                        );
                        return;
                    }
                };

                let provenance_clears = matches!(
                    provenance,
                    ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
                );
                let curation_clears = matches!(curation, CurationClearance::Cleared);
                if !provenance_clears || !curation_clears {
                    tallies.held_cross_axis += 1;
                    tracing::info!(
                        artifact_id = %artifact_id,
                        policy_id = %policy_id,
                        provenance = ?provenance,
                        curation = ?curation,
                        outcome = "held_cross_axis",
                        "artifact re-evaluation held: scan passes but the cross-axis \
                         release conjunction (curation ∧ provenance) does not currently \
                         clear (ADR 0041 invariant #6)",
                    );
                    emit_policy_evaluation(
                        policy_decision_point::RE_EVALUATION,
                        PolicyEvaluationResult::StillRejected,
                    );
                    return;
                }

                if self
                    .commit_re_evaluation(
                        artifact,
                        policy_id,
                        trigger,
                        QuarantineStatus::Rejected,
                        QuarantineStatus::Released,
                        provenance,
                        curation,
                    )
                    .await
                {
                    tallies.reset_released += 1;
                    tracing::info!(
                        artifact_id = %artifact_id,
                        outcome = "reset_to_released",
                        "artifact re-evaluated (loosen)",
                    );
                    emit_policy_evaluation(
                        policy_decision_point::RE_EVALUATION,
                        PolicyEvaluationResult::ResetToReleased,
                    );
                }
            }
        }
    }

    /// Commit a re-evaluation outcome atomically: `ArtifactReEvaluated`
    /// audit event plus the companion transition event
    /// (`ArtifactQuarantined` or `ArtifactReleased`) appended in one
    /// `commit_transition` call.
    ///
    /// `provenance` / `curation` are the cross-axis release clearances the
    /// caller computed (ADR 0041 invariant #6); they are threaded into
    /// [`Artifact::re_evaluate`], which is the domain authority for the
    /// `Rejected → Released` conjunction. The caller has already verified
    /// the conjunction holds on the release arm (so a denial here is a
    /// defence-in-depth re-check, surfaced as a best-effort skip), and the
    /// re-quarantine arm ignores both clearances (the artifact stays
    /// held).
    ///
    /// Returns `true` on success, `false` on best-effort skip
    /// (typically `DomainError::Conflict` from a parallel scan or
    /// admin operation that bumped the artifact stream between the
    /// read and the append, or the domain re-check denying the release).
    /// The caller logs the warn and increments the appropriate counter
    /// only on `true`.
    #[allow(clippy::too_many_arguments)]
    async fn commit_re_evaluation(
        &self,
        mut artifact: Artifact,
        policy_id: Uuid,
        trigger: ReEvaluationTrigger,
        previous_status: QuarantineStatus,
        new_status: QuarantineStatus,
        provenance: ProvenanceClearance,
        curation: CurationClearance,
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
                    trigger = ?trigger,
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
        let companion_event = match artifact.re_evaluate(Utc::now(), provenance, curation) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
                    error = %e,
                    "artifact state machine rejected re-evaluation; skipping artifact",
                );
                return false;
            }
        };

        let re_evaluated = ArtifactReEvaluated {
            artifact_id,
            policy_id,
            // The driving trigger threads through from the caller (ADR 0041's
            // widened discriminator): `ExclusionAdded` from the legacy
            // post-exclusion path, or any policy-change discriminator from
            // the generalised `run_policy_re_evaluation_pass`.
            trigger,
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
                    trigger = ?trigger,
                    conflict = %msg,
                    "concurrent modification during re-evaluation pass; skipping artifact",
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    policy_id = %policy_id,
                    trigger = ?trigger,
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

        // Removing an exclusion is a TIGHTEN — an artifact previously
        // released because the now-removed exclusion waived its blocking
        // finding may now fail the gate. This is the fail-OPEN direction
        // the status quo missed (ADR 0041): enqueue ONE async pass to
        // re-derive the population's verdicts and re-hold the now-failing
        // set. The trigger carries the removed `exclusion_id` for audit
        // attribution (invariant #3).
        self.enqueue_re_evaluation(
            policy_id,
            ReEvaluationTrigger::ExclusionRemoved { exclusion_id },
        )
        .await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Per-outcome counters for the **loosen** direction of a re-evaluation
/// pass, threaded through [`PolicyUseCase::re_evaluate_one_rejected`] so the
/// shared per-artifact body can tally without owning the pass-complete log.
#[derive(Debug, Default)]
struct LoosenTallies {
    /// Scan still blocks under the bumped policy — no transition.
    still_rejected: u64,
    /// Scan cleared but the window is still active — re-`Quarantined`.
    reset_quarantined: u64,
    /// Scan cleared and the window elapsed and the cross-axis conjunction
    /// holds — `Released`.
    reset_released: u64,
    /// Held by the cross-axis conjunction (ADR 0041 invariant #6): a
    /// non-scan-clearable rejection reason, or a scan-clear artifact whose
    /// provenance / curation gate currently denies the release.
    held_cross_axis: u64,
}

/// Per-outcome counters for the **tighten** direction of a re-evaluation
/// pass.
#[derive(Debug, Default)]
struct TightenTallies {
    /// Now-failing under the bumped policy — re-held (`Rejected`).
    re_held: u64,
    /// Still-clean under the bumped policy — no-op (no event appended).
    unchanged: u64,
}

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
        /// When `Some`, the NEXT `read_stream` call returns this error
        /// (consumed on fire). Used to exercise the re-evaluation pass's
        /// infrastructure-error skip branches (ADR 0041).
        next_read_error: Mutex<Option<DomainError>>,
        /// Running `read_stream` call count + an optional `(nth, err)` to
        /// fail a SPECIFIC read (1-based). Lets a test fail only the
        /// provenance read (the 4th stream read in the release arm) while
        /// the earlier reads succeed.
        read_count: Mutex<usize>,
        fail_read_at: Mutex<Option<(usize, DomainError)>>,
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
                next_read_error: Mutex::new(None),
                read_count: Mutex::new(0),
                fail_read_at: Mutex::new(None),
            }
        }

        /// Arm the NEXT `read_stream` to fail once with `err`. Consumed
        /// on fire — used to drive the pass's read-error skip branches.
        fn fail_next_read_stream(&self, err: DomainError) {
            *self.next_read_error.lock().unwrap() = Some(err);
        }

        /// Arm the `nth` (1-based) `read_stream` call to fail with `err`,
        /// every earlier read succeeding. Used to fail only the provenance
        /// read in the release arm (the 4th stream read).
        fn fail_read_stream_at(&self, nth: usize, err: DomainError) {
            *self.fail_read_at.lock().unwrap() = Some((nth, err));
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
            if let Some(err) = self.next_read_error.lock().unwrap().take() {
                return Box::pin(async move { Err(err) });
            }
            {
                let mut count = self.read_count.lock().unwrap();
                *count += 1;
                let mut at = self.fail_read_at.lock().unwrap();
                if let Some((nth, _)) = at.as_ref() {
                    if *nth == *count {
                        let err = at.take().unwrap().1;
                        return Box::pin(async move { Err(err) });
                    }
                }
            }
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
        let curation_rules =
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new());
        let jobs = Arc::new(crate::use_cases::test_support::MockJobsRepository::default());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts,
            lifecycle,
            storage,
            repository_access,
            curation_rules,
            jobs,
        );
        (uc, events, projections)
    }

    /// Like [`make_use_case`] but also exposes the [`MockJobsRepository`]
    /// so the ADR 0041 Item 3 trigger tests can assert the async
    /// `policy-reevaluation` enqueue (kind / params / once-per-mutation).
    fn make_use_case_with_jobs() -> (
        PolicyUseCase,
        Arc<MockEventStore>,
        Arc<MockPolicyProjections>,
        Arc<crate::use_cases::test_support::MockJobsRepository>,
    ) {
        let events = Arc::new(MockEventStore::new());
        let projections = Arc::new(MockPolicyProjections::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let storage = Arc::new(crate::use_cases::test_support::MockStoragePort::new());
        let curation_rules =
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new());
        let jobs = Arc::new(crate::use_cases::test_support::MockJobsRepository::default());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts,
            lifecycle,
            storage,
            default_repository_access(),
            curation_rules,
            jobs.clone(),
        );
        (uc, events, projections, jobs)
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
        // No curation rules seeded → the curation precondition clears for
        // every artifact (empty `list_for_repo`); provenance clears via
        // `sample_projection`'s `VerifyIfPresent` mode. The cross-axis
        // conjunction tests use `make_cross_axis_harness` to seed rules /
        // provenance.
        let curation_rules =
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new());
        let jobs = Arc::new(crate::use_cases::test_support::MockJobsRepository::default());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts.clone(),
            lifecycle.clone(),
            storage,
            default_repository_access(),
            curation_rules,
            jobs,
        );
        (uc, events, projections, artifacts, lifecycle)
    }

    /// Cross-axis (ADR 0041 invariant #6) re-evaluation harness — exposes
    /// the curation-rule + repository mocks so a test can seed a curation
    /// `Block` rule (the active-curation precondition) and the repository
    /// format (the curation format gate), and the event store so it can
    /// seed a `ProvenanceVerified` (the active-provenance precondition).
    #[allow(clippy::type_complexity)]
    fn make_cross_axis_harness() -> (
        PolicyUseCase,
        Arc<MockEventStore>,
        Arc<MockPolicyProjections>,
        Arc<crate::use_cases::test_support::MockArtifactRepository>,
        Arc<crate::use_cases::test_support::MockArtifactLifecycle>,
        Arc<crate::use_cases::test_support::MockCurationRuleRepository>,
        Arc<crate::use_cases::test_support::MockRepositoryRepository>,
    ) {
        use crate::use_cases::repository_access::RbacAccess;
        let events = Arc::new(MockEventStore::new());
        let projections = Arc::new(MockPolicyProjections::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let storage = Arc::new(crate::use_cases::test_support::MockStoragePort::new());
        let curation_rules =
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new());
        let repos = Arc::new(crate::use_cases::test_support::MockRepositoryRepository::new());
        let repository_access = Arc::new(RepositoryAccessUseCase::new(
            repos.clone(),
            RbacAccess::Disabled,
            true,
        ));
        let jobs = Arc::new(crate::use_cases::test_support::MockJobsRepository::default());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts.clone(),
            lifecycle.clone(),
            storage,
            repository_access,
            curation_rules.clone(),
            jobs,
        );
        (
            uc,
            events,
            projections,
            artifacts,
            lifecycle,
            curation_rules,
            repos,
        )
    }

    /// Harness for the generalised `run_policy_re_evaluation_pass` —
    /// exposes the storage mock too so tighten-direction tests can seed a
    /// per-finding `findings_blob` in CAS (the verdict source for
    /// `evaluate_scan_result`).
    #[allow(clippy::type_complexity)]
    fn make_full_re_eval_harness() -> (
        PolicyUseCase,
        Arc<MockEventStore>,
        Arc<MockPolicyProjections>,
        Arc<crate::use_cases::test_support::MockArtifactRepository>,
        Arc<crate::use_cases::test_support::MockArtifactLifecycle>,
        Arc<crate::use_cases::test_support::MockStoragePort>,
    ) {
        let events = Arc::new(MockEventStore::new());
        let projections = Arc::new(MockPolicyProjections::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let storage = Arc::new(crate::use_cases::test_support::MockStoragePort::new());
        let curation_rules =
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new());
        let jobs = Arc::new(crate::use_cases::test_support::MockJobsRepository::default());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            projections.clone(),
            artifacts.clone(),
            lifecycle.clone(),
            storage.clone(),
            default_repository_access(),
            curation_rules,
            jobs,
        );
        (uc, events, projections, artifacts, lifecycle, storage)
    }

    /// ADR 0041 Item 3: `add_exclusion` no longer runs the re-evaluation
    /// pass synchronously in-request — it enqueues the async
    /// `policy-reevaluation` task and returns. These loosen-direction
    /// tests (which assert the per-artifact transitions the pass commits)
    /// therefore add the exclusion, then drive the pass explicitly with
    /// the `ExclusionAdded` trigger `add_exclusion` enqueued — the
    /// production worker dispatches the same call. Returns the minted
    /// `exclusion_id` so a test can assert the `ArtifactReEvaluated`
    /// trigger attribution.
    async fn add_exclusion_then_run_pass(uc: &PolicyUseCase, policy_id: Uuid) -> Uuid {
        let exclusion_id = uc
            .add_exclusion(re_eval_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();
        uc.run_policy_re_evaluation_pass(
            policy_id,
            ReEvaluationTrigger::ExclusionAdded { exclusion_id },
        )
        .await;
        exclusion_id
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
        let curation_rules =
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new());
        let jobs = Arc::new(crate::use_cases::test_support::MockJobsRepository::default());
        let uc = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            Arc::new(FailingFindByName),
            artifacts,
            lifecycle,
            storage,
            default_repository_access(),
            curation_rules,
            jobs,
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
            //
            // Scan-rejected by default — the re-eval pass's eligibility
            // guard (ADR 0041 invariant #6) admits only `Scanner`. Tests
            // exercising the non-scan ineligibility path override this.
            rejection_reason: Some(RejectionReason::Scanner),
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

    /// Build an `ArtifactRejected` PersistedEvent carrying `rejected_by`.
    /// The post-exclusion re-evaluation pass re-hydrates the rejection
    /// reason from this event (ADR 0041 invariant #6 (a)); a rejected
    /// artifact in production always has one on its stream.
    fn persisted_artifact_rejected(
        artifact_id: Uuid,
        rejected_by: RejectionReason,
        stream_position: u64,
    ) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position,
            global_position: stream_position,
            event: DomainEvent::ArtifactRejected(ArtifactRejected {
                artifact_id,
                rejected_by,
                reason: "seeded rejection".into(),
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

    /// Inserts the seeded `ScanCompleted` + `ArtifactRejected { Scanner }`
    /// and rejected artifact and returns the artifact id. The artifact is
    /// inserted into the shared `MockArtifactRepository`; the
    /// scan-completed AND rejection events are seeded onto the artifact
    /// stream so the re-eval pass can read both back via `read_stream`
    /// (the scan summary + the scan-clearable rejection reason). Caller is
    /// responsible for seeding the per-policy `repository_id` filter via
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
            vec![
                persisted_scan_completed(artifact_id, critical, 0),
                persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 1),
            ],
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

        let exclusion_id = add_exclusion_then_run_pass(&uc, policy_id).await;

        // One batch was appended: the ExclusionAdded on the policy stream
        // (the async pass commits the ArtifactReEvaluated/ArtifactReleased
        // pair through `MockArtifactLifecycle`, not the event store
        // directly).
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
                assert_eq!(
                    e.trigger,
                    ReEvaluationTrigger::ExclusionAdded { exclusion_id }
                );
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

        add_exclusion_then_run_pass(&uc, policy_id).await;

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
            vec![
                persisted_scan_completed(artifact_id, 1, 0),
                persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 1),
            ],
        );
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        add_exclusion_then_run_pass(&uc, policy_id).await;

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
                add_exclusion_then_run_pass(&uc, policy_id).await;
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
                add_exclusion_then_run_pass(&uc, policy_id).await;
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

        add_exclusion_then_run_pass(&uc, policy_id).await;

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

        add_exclusion_then_run_pass(&uc, policy_id).await;

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

        add_exclusion_then_run_pass(&uc, policy_id).await;

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

    // -- ADR 0041 invariant #6 — cross-axis re-evaluation conjunction -------
    //
    // The post-exclusion pass releases a now-scan-clean `Rejected`
    // artifact only on the FULL conjunction `scan ∧ curation ∧
    // provenance`. These tests pin the three holds the conjunction adds
    // over the pre-ADR-0041 reason-blind release.

    /// Seed a scan-clean (single critical, cleared by the exclusion)
    /// rejected artifact whose stream carries an `ArtifactRejected` with
    /// the given reason. Returns the artifact id.
    fn seed_rejected_with_reason(
        artifacts: &Arc<crate::use_cases::test_support::MockArtifactRepository>,
        events: &Arc<MockEventStore>,
        repo_id: Uuid,
        reason: RejectionReason,
    ) -> Uuid {
        let artifact = rejected_artifact_for_repo(repo_id, "xz-utils");
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![
                persisted_scan_completed(artifact_id, 1, 0),
                persisted_artifact_rejected(artifact_id, reason, 1),
            ],
        );
        artifact_id
    }

    /// (a) A non-`Scanner` rejection is ineligible for a scan re-judgement
    /// — adding a scan exclusion must NOT release a provenance- /
    /// curation- / admin-rejected artifact whose scan now passes. This is
    /// the live cross-axis fail-open the fix closes.
    #[tokio::test]
    async fn re_eval_non_scanner_reason_is_not_released() {
        use hort_domain::events::RejectionReason as RR;
        let non_scanner = [
            RR::Admin,
            RR::CurationRetroactive {
                rule_id: Uuid::new_v4(),
            },
            RR::Curator {
                curator_id: Uuid::new_v4(),
            },
        ];
        for reason in non_scanner {
            let (uc, events, projections, artifacts, lifecycle) =
                make_use_case_with_re_eval_harness();
            let policy_id = Uuid::new_v4();
            let repo_id = Uuid::new_v4();
            let mut p = sample_projection(policy_id, 4);
            p.severity_threshold = SeverityThreshold::Low;
            projections.insert(p);

            seed_rejected_with_reason(&artifacts, &events, repo_id, reason.clone());
            artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

            add_exclusion_then_run_pass(&uc, policy_id).await;

            // The cross-axis eligibility guard held it: NO transition.
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "reason {reason:?} must not be released by a scan exclusion"
            );
        }
    }

    /// (b) Active-provenance precondition: a scan-clean `Scanner`-rejected
    /// artifact under `provenance_mode: Required` with no
    /// `ProvenanceVerified` on its stream must NOT be released (Pending →
    /// held).
    #[tokio::test]
    async fn re_eval_provenance_pending_is_not_released() {
        let (uc, events, projections, artifacts, lifecycle, _cur, _repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        // Required provenance, but no ProvenanceVerified seeded → Pending.
        p.provenance_mode = ProvenanceMode::Required;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "provenance-pending artifact must stay Rejected"
        );
    }

    /// (b) symmetric positive: the SAME artifact WITH a `ProvenanceVerified`
    /// on its stream under `Required` IS released — proves the gate is the
    /// provenance state, not a blanket Required-mode block.
    #[tokio::test]
    async fn re_eval_provenance_verified_under_required_is_released() {
        use hort_domain::events::ProvenanceVerified;
        use hort_domain::ports::provenance::SignerIdentity;
        let (uc, events, projections, artifacts, lifecycle, _cur, _repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        p.provenance_mode = ProvenanceMode::Required;
        projections.insert(p);

        let artifact = rejected_artifact_for_repo(repo_id, "xz-utils");
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![
                persisted_scan_completed(artifact_id, 1, 0),
                persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 1),
                PersistedEvent {
                    event_id: Uuid::new_v4(),
                    stream_id: StreamId::artifact(artifact_id),
                    stream_position: 2,
                    global_position: 2,
                    event: DomainEvent::ProvenanceVerified(ProvenanceVerified {
                        artifact_id,
                        content_hash: VALID_SHA256.parse().unwrap(),
                        backend: "cosign".into(),
                        signer: SignerIdentity {
                            issuer: "iss".into(),
                            san: "san".into(),
                        },
                        predicate_type: None,
                    }),
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: hort_domain::events::system_actor(),
                    event_version: 1,
                    stored_at: Utc::now(),
                },
            ],
        );
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        add_exclusion_then_run_pass(&uc, policy_id).await;

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(
            transitions[0].0.quarantine_status,
            QuarantineStatus::Released
        );
    }

    /// (c) Active-curation precondition — the case the reason guard
    /// misses: a SCANNER-rejected artifact (eligible) that a curation
    /// `Block` rule (added AFTER the scan rejection) now matches must NOT
    /// be released. The retroactive curation pass never re-marks an
    /// already-`Rejected` artifact, so only this active re-check stops it.
    #[tokio::test]
    async fn re_eval_active_curation_block_is_not_released() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::repository::RepositoryFormat;
        let (uc, events, projections, artifacts, lifecycle, curation, repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        // The artifact is "xz-utils"; seed an active Block rule matching it.
        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        // Repository format (the curation format gate input).
        let mut repo = crate::use_cases::test_support::sample_repository();
        repo.id = repo_id;
        repo.format = RepositoryFormat::Pypi;
        repos.insert(repo);

        curation.set_rules_for_repo(
            repo_id,
            vec![CurationRule {
                id: Uuid::new_v4(),
                name: "block-xz".into(),
                format: None, // any format
                package_pattern: "xz-*".into(),
                action: CurationRuleAction::Block,
                reason: "supply-chain backdoor".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([0xab; 32]),
            }],
        );

        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "an active curation Block must hold the scan-cleared artifact Rejected"
        );
    }

    /// (c) symmetric: a curation `Warn` rule (NOT a Block) does not hold
    /// the release — the artifact still releases. Exercises the
    /// `Warn → Cleared` mapping + the repository-format resolution path.
    #[tokio::test]
    async fn re_eval_curation_warn_does_not_block_release() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::repository::RepositoryFormat;
        let (uc, events, projections, artifacts, lifecycle, curation, repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        let mut repo = crate::use_cases::test_support::sample_repository();
        repo.id = repo_id;
        repo.format = RepositoryFormat::Pypi;
        repos.insert(repo);

        curation.set_rules_for_repo(
            repo_id,
            vec![CurationRule {
                id: Uuid::new_v4(),
                name: "warn-xz".into(),
                format: Some(RepositoryFormat::Pypi),
                package_pattern: "xz-*".into(),
                action: CurationRuleAction::Warn,
                reason: "noisy".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([0xab; 32]),
            }],
        );

        add_exclusion_then_run_pass(&uc, policy_id).await;

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1, "Warn does not block release");
        assert_eq!(
            transitions[0].0.quarantine_status,
            QuarantineStatus::Released
        );
    }

    /// The clean+eligible happy path through the cross-axis harness: a
    /// `Scanner`-rejected artifact, no curation rules, default
    /// (VerifyIfPresent) provenance → released (as today). Anchors that
    /// the conjunction does not over-block the previously-passing case.
    #[tokio::test]
    async fn re_eval_clean_eligible_artifact_is_released() {
        let (uc, events, projections, artifacts, lifecycle, _cur, _repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        add_exclusion_then_run_pass(&uc, policy_id).await;

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(
            transitions[0].0.quarantine_status,
            QuarantineStatus::Released
        );
    }

    /// An artifact whose stream carries NO `ArtifactRejected` event (an
    /// unknown reason) is ineligible by default — held, not released.
    #[tokio::test]
    async fn re_eval_unknown_reason_no_rejection_event_is_not_released() {
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        // Seed ONLY a ScanCompleted — no ArtifactRejected on the stream.
        let artifact = rejected_artifact_for_repo(repo_id, "xz-utils");
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![persisted_scan_completed(artifact_id, 1, 0)],
        );
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);

        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "an unknown (no ArtifactRejected event) reason is ineligible by default"
        );
    }

    /// Infrastructure-error skip (a): the rejection-reason hydrate read
    /// fails → the pass logs + skips the artifact (no transition), it does
    /// NOT abort the pass nor release the artifact.
    #[tokio::test]
    async fn re_eval_hydrate_reason_read_error_skips_artifact() {
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        // The FIRST read_stream in the loop is `hydrate_rejection_reason`.
        events.fail_next_read_stream(DomainError::Invariant("stream read down".into()));

        // The pass must not abort: add_exclusion still returns Ok.
        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "a hydrate read error skips the artifact (no transition)"
        );
    }

    /// Infrastructure-error skip (b): the provenance-clearance read fails
    /// on the release arm → skip. `Required` mode makes the provenance
    /// resolver read the stream (the 4th stream read in the release path:
    /// hydrate, read_last_scan_completed, read_last_findings, provenance).
    #[tokio::test]
    async fn re_eval_provenance_resolve_read_error_skips_artifact() {
        let (uc, events, projections, artifacts, lifecycle) = make_use_case_with_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        p.provenance_mode = ProvenanceMode::Required;
        projections.insert(p);

        // critical = 0 so there is no findings_blob → `read_last_findings`
        // still issues ONE stream read (for the ScanCompleted) but no CAS
        // fetch. Reads in the release arm: hydrate(1),
        // read_last_scan_completed(2), read_last_findings(3),
        // provenance(4). Fail the 4th.
        let artifact = rejected_artifact_for_repo(repo_id, "xz-utils");
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![
                persisted_scan_completed(artifact_id, 0, 0),
                persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 1),
            ],
        );
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        events.fail_read_stream_at(4, DomainError::Invariant("provenance read down".into()));

        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "a provenance-resolution read error skips the artifact"
        );
    }

    /// Infrastructure-error skip (c): the curation-clearance lookup
    /// (`list_for_repo`) fails on the release arm → skip.
    #[tokio::test]
    async fn re_eval_curation_resolve_error_skips_artifact() {
        let (uc, events, projections, artifacts, lifecycle, curation, _repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        // The curation precondition's `list_for_repo` fails.
        curation.fail_next_list_for_repo(DomainError::Invariant("curation lookup down".into()));

        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "a curation-resolution error skips the artifact"
        );
    }

    /// `resolve_curation_clearance` fast path: an empty rule set clears
    /// without a repository-format lookup. Indirectly exercised by the
    /// happy-path tests; this pins it explicitly with the cross-axis
    /// harness (no rules seeded, repo seeded but format lookup skipped).
    #[tokio::test]
    async fn re_eval_curation_empty_rules_clears_and_releases() {
        let (uc, events, projections, artifacts, lifecycle, _curation, repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        // Repo seeded but NO curation rules → fast-path Cleared (the
        // format lookup is skipped). The artifact releases.
        let mut repo = crate::use_cases::test_support::sample_repository();
        repo.id = repo_id;
        repos.insert(repo);

        add_exclusion_then_run_pass(&uc, policy_id).await;

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(
            transitions[0].0.quarantine_status,
            QuarantineStatus::Released
        );
    }

    /// `resolve_curation_clearance` missing-repo fallback: a curation rule
    /// IS present (so the format lookup runs), but the repository row is
    /// absent → format falls back to `Generic`. An `any`-format Block rule
    /// still matches → held; this pins the `unwrap_or(Generic)` arm.
    #[tokio::test]
    async fn re_eval_curation_missing_repo_falls_back_to_generic() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;
        let (uc, events, projections, artifacts, lifecycle, curation, _repos) =
            make_cross_axis_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);

        seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        // No repository row seeded → `repository_format` returns None →
        // coords.format = Generic. An any-format Block still matches.
        curation.set_rules_for_repo(
            repo_id,
            vec![CurationRule {
                id: Uuid::new_v4(),
                name: "block-xz".into(),
                format: None,
                package_pattern: "xz-*".into(),
                action: CurationRuleAction::Block,
                reason: "blocked".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([0xab; 32]),
            }],
        );

        add_exclusion_then_run_pass(&uc, policy_id).await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "missing repo falls back to Generic; the any-format Block still holds it"
        );
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

    // ---------------------------------------------------------------------
    // run_policy_re_evaluation_pass — ADR 0041 Item 2 (generalised both-
    // directions pass + paginated population port)
    // ---------------------------------------------------------------------

    use hort_domain::types::Finding;
    use sha2::{Digest, Sha256};

    /// Build an active (`Released` by default) artifact under `repo_id`.
    /// The tighten direction lists these via `list_active_for_policy`.
    fn active_artifact_for_repo(repo_id: Uuid, name: &str, status: QuarantineStatus) -> Artifact {
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
            quarantine_status: status,
            rejection_reason: None,
            quarantine_window_start: Some(Utc::now() - chrono::Duration::hours(25)),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn sample_finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        Finding {
            purl: format!("pkg:generic/{}@1", vuln.to_ascii_lowercase()),
            vulnerability_id: vuln.into(),
            severity: sev,
            cvss_score: None,
            title: "t".into(),
            fixed_versions: vec![],
            source_scanner: "trivy".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
        }
    }

    /// Seed an active artifact whose stored `ScanCompleted` references a
    /// per-finding blob in CAS carrying `findings`. Returns the artifact id.
    /// Used by the tighten-direction tests so `evaluate_scan_result` reads a
    /// real verdict source rather than the empty (always-Clean) fallback.
    fn seed_active_with_findings(
        artifacts: &Arc<crate::use_cases::test_support::MockArtifactRepository>,
        events: &Arc<MockEventStore>,
        storage: &Arc<crate::use_cases::test_support::MockStoragePort>,
        repo_id: Uuid,
        status: QuarantineStatus,
        findings: &[Finding],
    ) -> Uuid {
        let artifact = active_artifact_for_repo(repo_id, "xz-utils", status);
        let artifact_id = artifact.id;
        artifacts.insert(artifact);

        let (finding_count, findings_blob) = if findings.is_empty() {
            (0u32, None)
        } else {
            let bytes = serde_json::to_vec(findings).unwrap();
            let hash_hex = format!("{:x}", Sha256::digest(&bytes));
            let blob_hash: ContentHash = hash_hex.parse().unwrap();
            storage.insert_content(blob_hash.clone(), bytes);
            (findings.len() as u32, Some(blob_hash))
        };
        let summary = SeveritySummary {
            critical: findings
                .iter()
                .filter(|f| f.severity == SeverityThreshold::Critical)
                .count() as u32,
            high: findings
                .iter()
                .filter(|f| f.severity == SeverityThreshold::High)
                .count() as u32,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![PersistedEvent {
                event_id: Uuid::new_v4(),
                stream_id: StreamId::artifact(artifact_id),
                stream_position: 0,
                global_position: 0,
                event: DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count,
                    severity_summary: summary,
                    findings_blob,
                }),
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: api_actor(),
                event_version: 1,
                stored_at: Utc::now(),
            }],
        );
        artifact_id
    }

    fn policy_updated_trigger(policy_id: Uuid) -> ReEvaluationTrigger {
        ReEvaluationTrigger::PolicyUpdated { policy_id }
    }

    /// Loosen direction through the generalised pass: a `Rejected`
    /// scan-rejected artifact whose findings now clear under the policy +
    /// exclusion set is `Released` (window elapsed). Proves the generalised
    /// pass threads the loosen body and stamps the `PolicyUpdated` trigger.
    #[tokio::test]
    async fn run_pass_loosen_releases_clean_artifact() {
        let (uc, events, projections, artifacts, lifecycle, _storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        // Threshold Low so a single critical would block; the exclusion
        // zeroes it on re-eval (aggregate-summary path, no blob seeded).
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::Low;
        projections.insert(p);
        // One matching exclusion so the re-eval clears the finding.
        projections.insert_exclusion(ExclusionProjection {
            exclusion_id: Uuid::new_v4(),
            policy_id,
            cve_id: "CVE-2024-3094".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "cleared".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        let artifact_id = seed_rejected_with_scan(&artifacts, &events, repo_id, 1);
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        // No active artifacts for the tighten direction.
        artifacts.seed_active_for_policy(policy_id, vec![]);

        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1, "one loosen transition");
        let (committed_artifact, committed_events, _meta) = &transitions[0];
        assert_eq!(committed_artifact.id, artifact_id);
        assert_eq!(
            committed_artifact.quarantine_status,
            QuarantineStatus::Released
        );
        match &committed_events.events[0].event {
            DomainEvent::ArtifactReEvaluated(e) => {
                assert_eq!(e.trigger, ReEvaluationTrigger::PolicyUpdated { policy_id });
                assert_eq!(e.previous_status, QuarantineStatus::Rejected);
                assert_eq!(e.new_status, QuarantineStatus::Released);
            }
            other => panic!("expected ArtifactReEvaluated, got {other:?}"),
        }
    }

    /// Tighten direction: a `Released` artifact whose stored findings now
    /// fail under the bumped policy is re-held (`Rejected`) with
    /// `ScanPolicyRetroactive`. The timer window anchor is preserved.
    #[tokio::test]
    async fn run_pass_tighten_re_holds_now_failing_released_artifact() {
        let (uc, events, projections, artifacts, lifecycle, storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        // Threshold High → a Critical finding blocks. (DefaultPolicy would
        // also block critical, but pin it explicitly.)
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::High;
        projections.insert(p);

        // No rejected artifacts (loosen no-op).
        artifacts.seed_rejected_for_policy(policy_id, vec![]);
        let findings = vec![sample_finding("CVE-2024-0001", SeverityThreshold::Critical)];
        let artifact_id = seed_active_with_findings(
            &artifacts,
            &events,
            &storage,
            repo_id,
            QuarantineStatus::Released,
            &findings,
        );
        let anchor = artifacts.get(artifact_id).unwrap().quarantine_window_start;
        artifacts.seed_active_for_policy(policy_id, vec![repo_id]);

        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1, "one tighten re-hold");
        let (committed_artifact, committed_events, _meta) = &transitions[0];
        assert_eq!(committed_artifact.id, artifact_id);
        assert_eq!(
            committed_artifact.quarantine_status,
            QuarantineStatus::Rejected
        );
        assert_eq!(
            committed_artifact.rejection_reason,
            Some(RejectionReason::ScanPolicyRetroactive)
        );
        // The timer window anchor is NOT re-opened.
        assert_eq!(
            committed_artifact.quarantine_window_start, anchor,
            "tighten re-hold must preserve the observation-window anchor"
        );
        assert_eq!(committed_events.events.len(), 2);
        match &committed_events.events[0].event {
            DomainEvent::ArtifactReEvaluated(e) => {
                assert_eq!(e.trigger, ReEvaluationTrigger::PolicyUpdated { policy_id });
                assert_eq!(e.previous_status, QuarantineStatus::Released);
                assert_eq!(e.new_status, QuarantineStatus::Rejected);
            }
            other => panic!("expected ArtifactReEvaluated, got {other:?}"),
        }
        match &committed_events.events[1].event {
            DomainEvent::ArtifactRejected(r) => {
                assert_eq!(r.rejected_by, RejectionReason::ScanPolicyRetroactive);
            }
            other => panic!("expected ArtifactRejected, got {other:?}"),
        }
    }

    /// No-op branch: an active artifact whose stored findings stay clean
    /// under the bumped policy produces NO `ArtifactReEvaluated` (the
    /// `Ok(None)` threaded contract from Item 1).
    #[tokio::test]
    async fn run_pass_tighten_clean_verdict_is_noop_no_event() {
        let (uc, events, projections, artifacts, lifecycle, storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        artifacts.seed_rejected_for_policy(policy_id, vec![]);
        // A single High finding under threshold High does NOT block
        // (the CVE tier-walk blocks at >= threshold only via the
        // accumulator's escalation; a lone High under High threshold is
        // a Warn → Clean). Use a Low finding to be unambiguous.
        let findings = vec![sample_finding("CVE-2024-0002", SeverityThreshold::Low)];
        let _artifact_id = seed_active_with_findings(
            &artifacts,
            &events,
            &storage,
            repo_id,
            QuarantineStatus::Released,
            &findings,
        );
        artifacts.seed_active_for_policy(policy_id, vec![repo_id]);

        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "clean tighten verdict must NOT append any transition / ArtifactReEvaluated"
        );
    }

    /// Idempotency: a second pass over the same stored evidence + policy
    /// re-reaches the same verdict, so the re-held artifact (now `Rejected`)
    /// is no longer in the active population, and the second run is a
    /// complete no-op (zero new transitions).
    #[tokio::test]
    async fn run_pass_is_idempotent_second_run_all_no_ops() {
        let (uc, events, projections, artifacts, lifecycle, storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::High;
        projections.insert(p);
        artifacts.seed_rejected_for_policy(policy_id, vec![]);
        let findings = vec![sample_finding("CVE-2024-0003", SeverityThreshold::Critical)];
        let artifact_id = seed_active_with_findings(
            &artifacts,
            &events,
            &storage,
            repo_id,
            QuarantineStatus::Released,
            &findings,
        );
        artifacts.seed_active_for_policy(policy_id, vec![repo_id]);

        // First pass re-holds.
        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;
        assert_eq!(lifecycle.committed_transitions().len(), 1);
        // The MockArtifactLifecycle wrote the Rejected status back to the
        // shared repo, so the artifact is no longer active.
        assert_eq!(
            artifacts.get(artifact_id).unwrap().quarantine_status,
            QuarantineStatus::Rejected
        );

        // Second pass: the artifact is no longer in the active population
        // (it is Rejected), and the loosen set is empty, so the pass is a
        // complete no-op — no NEW transition.
        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "second run must add no new transitions (verdict-idempotent)"
        );
    }

    /// The tighten direction paginates past the old 10 000 `LimitedList`
    /// cap with NO silent truncation: seed `LIMIT_LIST_MAX_ITEMS + 5`
    /// now-failing active artifacts and assert EVERY one is re-held (the
    /// pass walks `list_active_for_policy` pages until exhaustion).
    #[tokio::test]
    async fn run_pass_tighten_paginates_past_10k_with_no_truncation() {
        let (uc, events, projections, artifacts, lifecycle, storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::High;
        projections.insert(p);
        artifacts.seed_rejected_for_policy(policy_id, vec![]);

        // One shared findings blob (same critical CVE) reused across every
        // artifact — every artifact stores a ScanCompleted pointing at it.
        let findings = vec![sample_finding("CVE-2024-9999", SeverityThreshold::Critical)];
        let bytes = serde_json::to_vec(&findings).unwrap();
        let hash_hex = format!("{:x}", Sha256::digest(&bytes));
        let blob_hash: ContentHash = hash_hex.parse().unwrap();
        storage.insert_content(blob_hash.clone(), bytes);

        let population = hort_domain::types::LIMIT_LIST_MAX_ITEMS as usize + 5;
        for i in 0..population {
            let artifact = active_artifact_for_repo(repo_id, "bulk", QuarantineStatus::Released);
            // Distinct path/version so the rows are distinct; reuse one
            // checksum (the mock does not enforce checksum uniqueness).
            let mut a = artifact;
            a.version = Some(format!("1.0.{i}"));
            a.path = format!("/bulk/1.0.{i}");
            let artifact_id = a.id;
            artifacts.insert(a);
            events.seed_stream(
                StreamId::artifact(artifact_id),
                vec![PersistedEvent {
                    event_id: Uuid::new_v4(),
                    stream_id: StreamId::artifact(artifact_id),
                    stream_position: 0,
                    global_position: 0,
                    event: DomainEvent::ScanCompleted(ScanCompleted {
                        artifact_id,
                        scanner: "trivy".into(),
                        finding_count: 1,
                        severity_summary: SeveritySummary {
                            critical: 1,
                            high: 0,
                            medium: 0,
                            low: 0,
                            negligible: 0,
                        },
                        findings_blob: Some(blob_hash.clone()),
                    }),
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: api_actor(),
                    event_version: 1,
                    stored_at: Utc::now(),
                }],
            );
        }
        artifacts.seed_active_for_policy(policy_id, vec![repo_id]);

        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;

        // EVERY artifact past the old 10k cap is processed and re-held —
        // proof the pass paginates the whole population (no LimitedList
        // truncate-and-warn fail-open).
        assert_eq!(
            lifecycle.committed_transitions().len(),
            population,
            "all {population} now-failing artifacts must be re-held — no silent truncation"
        );
    }

    /// Mixed multi-page tighten population: now-failing and still-clean
    /// artifacts interleaved across more than one page. Exercises the
    /// offset-walk-over-a-shrinking-set arithmetic (`offset += stayed`):
    /// every now-failing artifact must be re-held exactly once and every
    /// clean one left untouched — no skips, no double-processing.
    #[tokio::test]
    async fn run_pass_tighten_mixed_population_advances_offset_by_stayed() {
        let (uc, events, projections, artifacts, lifecycle, storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let mut p = sample_projection(policy_id, 4);
        p.severity_threshold = SeverityThreshold::High;
        projections.insert(p);
        artifacts.seed_rejected_for_policy(policy_id, vec![]);

        // Critical blob (now-failing) + a low-only blob (stays clean).
        let crit = vec![sample_finding("CVE-FAIL", SeverityThreshold::Critical)];
        let crit_bytes = serde_json::to_vec(&crit).unwrap();
        let crit_hash: ContentHash = format!("{:x}", Sha256::digest(&crit_bytes))
            .parse()
            .unwrap();
        storage.insert_content(crit_hash.clone(), crit_bytes);
        let low = vec![sample_finding("CVE-OK", SeverityThreshold::Low)];
        let low_bytes = serde_json::to_vec(&low).unwrap();
        let low_hash: ContentHash = format!("{:x}", Sha256::digest(&low_bytes)).parse().unwrap();
        storage.insert_content(low_hash.clone(), low_bytes);

        // 1 500 artifacts (> one 1 000-item page); even idx fail, odd clean.
        let population = 1_500usize;
        let mut expected_re_held = 0usize;
        for i in 0..population {
            let mut a = active_artifact_for_repo(repo_id, "mix", QuarantineStatus::Released);
            a.version = Some(format!("1.0.{i}"));
            a.path = format!("/mix/1.0.{i}");
            let artifact_id = a.id;
            artifacts.insert(a);
            let fails = i % 2 == 0;
            if fails {
                expected_re_held += 1;
            }
            let blob_hash = if fails {
                crit_hash.clone()
            } else {
                low_hash.clone()
            };
            let summary = if fails {
                SeveritySummary {
                    critical: 1,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                }
            } else {
                SeveritySummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 1,
                    negligible: 0,
                }
            };
            events.seed_stream(
                StreamId::artifact(artifact_id),
                vec![PersistedEvent {
                    event_id: Uuid::new_v4(),
                    stream_id: StreamId::artifact(artifact_id),
                    stream_position: 0,
                    global_position: 0,
                    event: DomainEvent::ScanCompleted(ScanCompleted {
                        artifact_id,
                        scanner: "trivy".into(),
                        finding_count: 1,
                        severity_summary: summary,
                        findings_blob: Some(blob_hash),
                    }),
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: api_actor(),
                    event_version: 1,
                    stored_at: Utc::now(),
                }],
            );
        }
        artifacts.seed_active_for_policy(policy_id, vec![repo_id]);

        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;

        // Exactly the now-failing half is re-held; the clean half stays
        // Released. Proves the offset walk neither skips nor re-processes
        // when a page mixes re-held (leaving the set) and clean (staying).
        assert_eq!(
            lifecycle.committed_transitions().len(),
            expected_re_held,
            "every now-failing artifact re-held exactly once across the mixed multi-page walk"
        );
        let still_released = artifacts
            .snapshot_all()
            .into_iter()
            .filter(|a| a.quarantine_status == QuarantineStatus::Released)
            .count();
        assert_eq!(
            still_released,
            population - expected_re_held,
            "every clean artifact stays Released — none skipped or wrongly re-held"
        );
    }

    /// An absent / archived policy is a best-effort no-op (a concurrent
    /// archive raced the enqueue) — no transitions, no panic.
    #[tokio::test]
    async fn run_pass_missing_policy_is_noop() {
        let (uc, _events, _projections, _artifacts, lifecycle, _storage) =
            make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        // No projection seeded → find_by_id returns None.
        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// A non-scan-clearable rejection (e.g. `Curator`) in the loosen set is
    /// held — the generalised pass honours the eligibility guard.
    #[tokio::test]
    async fn run_pass_loosen_holds_non_scan_clearable_rejection() {
        let (uc, events, projections, artifacts, lifecycle, _storage) = make_full_re_eval_harness();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));

        // Curator-rejected artifact — ineligible for scan re-judgement.
        let mut artifact = rejected_artifact_for_repo(repo_id, "manual-block");
        artifact.rejection_reason = Some(RejectionReason::Curator {
            curator_id: Uuid::new_v4(),
        });
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        events.seed_stream(
            StreamId::artifact(artifact_id),
            vec![
                persisted_scan_completed(artifact_id, 0, 0),
                persisted_artifact_rejected(
                    artifact_id,
                    RejectionReason::Curator {
                        curator_id: Uuid::new_v4(),
                    },
                    1,
                ),
            ],
        );
        artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
        artifacts.seed_active_for_policy(policy_id, vec![]);

        uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
            .await;

        assert!(
            lifecycle.committed_transitions().is_empty(),
            "a Curator rejection is not scan-clearable; the loosen pass must hold it"
        );
    }

    // =====================================================================
    // ADR 0041 Item 3 — async trigger wiring (enqueue the worker task)
    // =====================================================================

    /// Find the single `policy-reevaluation` enqueue and return its
    /// `(policy_id, trigger)` params, asserting the kind + that exactly
    /// one such task was enqueued.
    fn assert_one_reeval_enqueue(
        jobs: &crate::use_cases::test_support::MockJobsRepository,
    ) -> (Uuid, ReEvaluationTrigger) {
        let calls = jobs.enqueue_calls();
        let reeval: Vec<_> = calls
            .iter()
            .filter(|(kind, _, _)| kind == "policy-reevaluation")
            .collect();
        assert_eq!(
            reeval.len(),
            1,
            "exactly ONE policy-reevaluation task per mutation (got {})",
            reeval.len()
        );
        let params = &reeval[0].1;
        let policy_id: Uuid =
            serde_json::from_value(params["policy_id"].clone()).expect("policy_id param");
        let trigger: ReEvaluationTrigger =
            serde_json::from_value(params["trigger"].clone()).expect("trigger param");
        (policy_id, trigger)
    }

    /// A gate-affecting `update_policy` (severity threshold) enqueues ONE
    /// `policy-reevaluation` task carrying the policy-scoped
    /// `PolicyUpdated` trigger.
    #[tokio::test]
    async fn update_policy_gate_field_enqueues_one_reevaluation() {
        let (uc, _events, projections, jobs) = make_use_case_with_jobs();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 3));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.severity_threshold = FieldChange::Set(SeverityThreshold::Critical);
        uc.update_policy(cmd, api_actor()).await.unwrap();

        let (policy_id, trigger) = assert_one_reeval_enqueue(&jobs);
        assert_eq!(policy_id, id);
        assert_eq!(
            trigger,
            ReEvaluationTrigger::PolicyUpdated { policy_id: id }
        );
    }

    /// **Enqueue-once coalescing.** A multi-field gate update
    /// (`update_policy` emits one `PolicyUpdated` event PER changed field)
    /// must enqueue exactly ONE re-evaluation task, not one per field.
    #[tokio::test]
    async fn update_policy_multi_gate_field_enqueues_exactly_one_reevaluation() {
        let (uc, events, projections, jobs) = make_use_case_with_jobs();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 3));

        // THREE gate-affecting fields change in one update.
        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.severity_threshold = FieldChange::Set(SeverityThreshold::Critical);
        cmd.license_policy = FieldChange::Set(serde_json::json!({ "denied": ["GPL-3.0"] }));
        cmd.negligible_action = FieldChange::Set(NegligibleAction::Block);
        uc.update_policy(cmd, api_actor()).await.unwrap();

        // Three PolicyUpdated events emitted …
        assert_eq!(
            events.appended_batches()[0].events.len(),
            3,
            "three gate fields → three PolicyUpdated events",
        );
        // … but ONE re-evaluation task (coalesced).
        let (policy_id, trigger) = assert_one_reeval_enqueue(&jobs);
        assert_eq!(policy_id, id);
        assert_eq!(
            trigger,
            ReEvaluationTrigger::PolicyUpdated { policy_id: id }
        );
    }

    /// A non-gate-only `update_policy` (name + scope + quarantine duration
    /// + require_approval + provenance + scan_backends + rescan interval)
    /// changes the policy but enqueues ZERO re-evaluation tasks — none of
    /// those fields alters a stored-findings scan verdict.
    #[tokio::test]
    async fn update_policy_non_gate_fields_enqueue_no_reevaluation() {
        let (uc, events, projections, jobs) = make_use_case_with_jobs();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 3));

        let mut cmd = UpdatePolicyCommand::new(id);
        cmd.name = FieldChange::Set("renamed".into());
        cmd.quarantine_duration_secs = FieldChange::Set(48 * 3600);
        cmd.require_approval = FieldChange::Set(false);
        cmd.provenance_mode = FieldChange::Set(ProvenanceMode::Required);
        cmd.scan_backends = FieldChange::Set(vec!["osv".into()]);
        cmd.rescan_interval_hours = FieldChange::Set(12);
        uc.update_policy(cmd, api_actor()).await.unwrap();

        // The update committed (events appended) …
        assert!(!events.appended_batches().is_empty(), "update committed");
        // … but no gate field changed → no re-evaluation enqueued.
        assert!(
            jobs.enqueue_calls()
                .iter()
                .all(|(kind, _, _)| kind != "policy-reevaluation"),
            "non-gate-field update must NOT enqueue a re-evaluation pass",
        );
    }

    /// A same-value (no-op) `update_policy` emits zero events AND enqueues
    /// no re-evaluation.
    #[tokio::test]
    async fn update_policy_noop_enqueues_no_reevaluation() {
        let (uc, _events, projections, jobs) = make_use_case_with_jobs();
        let id = Uuid::new_v4();
        projections.insert(sample_projection(id, 3));

        // Every field Unchanged → zero events, early return.
        uc.update_policy(UpdatePolicyCommand::new(id), api_actor())
            .await
            .unwrap();

        assert!(
            jobs.enqueue_calls().is_empty(),
            "a no-op update must enqueue nothing",
        );
    }

    /// `add_exclusion` (a loosen) enqueues ONE re-evaluation task with the
    /// `ExclusionAdded` trigger carrying the just-minted exclusion id.
    #[tokio::test]
    async fn add_exclusion_enqueues_reevaluation_with_exclusion_added_trigger() {
        let (uc, _events, projections, jobs) = make_use_case_with_jobs();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));

        let exclusion_id = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await
            .unwrap();

        let (enq_policy, trigger) = assert_one_reeval_enqueue(&jobs);
        assert_eq!(enq_policy, policy_id);
        assert_eq!(
            trigger,
            ReEvaluationTrigger::ExclusionAdded { exclusion_id },
            "the enqueued trigger must name the just-added exclusion",
        );
    }

    /// `remove_exclusion` (a tighten) enqueues ONE re-evaluation task with
    /// the `ExclusionRemoved` trigger carrying the removed exclusion id.
    #[tokio::test]
    async fn remove_exclusion_enqueues_reevaluation_with_exclusion_removed_trigger() {
        let (uc, events, projections, jobs) = make_use_case_with_jobs();
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        projections.insert_exclusion(sample_exclusion(exclusion_id, policy_id));
        events.push_append_result(AppendResult {
            stream_position: 5,
            global_positions: vec![200],
        });

        uc.remove_exclusion(
            sample_remove_exclusion_command(policy_id, exclusion_id),
            api_actor(),
        )
        .await
        .unwrap();

        let (enq_policy, trigger) = assert_one_reeval_enqueue(&jobs);
        assert_eq!(enq_policy, policy_id);
        assert_eq!(
            trigger,
            ReEvaluationTrigger::ExclusionRemoved { exclusion_id },
        );
    }

    /// `reactivate_policy` enqueues ONE re-evaluation task (the
    /// policy-scoped `PolicyUpdated` trigger) — reactivation re-arms the
    /// gate over the in-scope population.
    #[tokio::test]
    async fn reactivate_policy_enqueues_reevaluation() {
        let (uc, _events, projections, jobs) = make_use_case_with_jobs();
        let id = Uuid::new_v4();
        let mut p = sample_projection(id, 3);
        p.archived = true;
        projections.insert(p);

        uc.reactivate_policy(id, api_actor()).await.unwrap();

        let (policy_id, trigger) = assert_one_reeval_enqueue(&jobs);
        assert_eq!(policy_id, id);
        assert_eq!(
            trigger,
            ReEvaluationTrigger::PolicyUpdated { policy_id: id }
        );
    }

    /// A best-effort enqueue failure does NOT fail the policy mutation —
    /// the mutation already committed; the queue hiccup is logged and
    /// swallowed (`add_exclusion` still returns `Ok`).
    #[tokio::test]
    async fn enqueue_failure_does_not_fail_the_mutation() {
        let (uc, _events, projections, jobs) = make_use_case_with_jobs();
        let policy_id = Uuid::new_v4();
        projections.insert(sample_projection(policy_id, 4));
        jobs.fail_next_enqueue(DomainError::Invariant("simulated queue down".into()));

        // add_exclusion must still succeed despite the enqueue error.
        let result = uc
            .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
            .await;
        assert!(
            result.is_ok(),
            "enqueue failure must not roll back the committed mutation",
        );
    }

    /// A swallowed enqueue failure fires the alertable
    /// `hort_policy_reevaluation_enqueue_failed_total` counter — the only
    /// signal that a gate-affecting mutation committed but its re-evaluation
    /// pass never ran — AND the policy mutation still succeeds (the error is
    /// swallowed, not propagated). A bare counter: no labels.
    #[test]
    fn enqueue_failure_emits_alertable_counter_and_mutation_still_succeeds() {
        use crate::metrics::capture_metrics;
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let mut result_ok = false;
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, _events, projections, jobs) = make_use_case_with_jobs();
                let policy_id = Uuid::new_v4();
                projections.insert(sample_projection(policy_id, 4));
                jobs.fail_next_enqueue(DomainError::Invariant("simulated queue down".into()));

                let result = uc
                    .add_exclusion(sample_add_exclusion_command(policy_id), api_actor())
                    .await;
                result_ok = result.is_ok();
            });
        });

        // The mutation succeeded despite the enqueue error.
        assert!(
            result_ok,
            "enqueue failure must not roll back the committed mutation",
        );

        let entries = snap.into_vec();
        let failed = entries
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_policy_reevaluation_enqueue_failed_total"
            })
            .expect("enqueue-failed counter must fire on a swallowed enqueue error");
        match &failed.3 {
            DebugValue::Counter(n) => assert_eq!(*n, 1, "one swallowed enqueue failure"),
            other => panic!("expected Counter, got {other:?}"),
        }
        // Bare counter — no labels.
        assert_eq!(
            failed.0.key().labels().count(),
            0,
            "the enqueue-failed counter must carry no labels",
        );
    }

    // =====================================================================
    // ADR 0041 §5 — outcome metric + completeness signal
    // =====================================================================

    /// A loosen pass that releases an artifact fires
    /// `hort_policy_reevaluation_artifacts_total{result="released"}` and
    /// sets the `hort_policy_reevaluation_population` completeness gauge.
    #[test]
    fn run_pass_loosen_release_emits_released_result_and_population() {
        use crate::metrics::capture_metrics;
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, events, projections, artifacts, _lifecycle) =
                    make_use_case_with_re_eval_harness();
                let policy_id = Uuid::new_v4();
                let repo_id = Uuid::new_v4();
                let mut p = sample_projection(policy_id, 4);
                p.severity_threshold = SeverityThreshold::Low;
                projections.insert(p);
                // Zero blocking findings → the scan re-evaluates Clean;
                // the fixture window is elapsed (25h ago) and the
                // cross-axis conjunction clears (no curation rules,
                // VerifyIfPresent provenance with no events) → Released.
                let _ = seed_rejected_with_scan(&artifacts, &events, repo_id, 0);
                artifacts.seed_rejected_for_policy(policy_id, vec![repo_id]);
                artifacts.seed_active_for_policy(policy_id, vec![]);
                uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
                    .await;
            });
        });
        let entries = snap.into_vec();

        // result=released counter == 1, no high-cardinality labels.
        let released = entries
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_policy_reevaluation_artifacts_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "released")
            })
            .expect("released result counter");
        match &released.3 {
            DebugValue::Counter(n) => assert_eq!(*n, 1, "one released artifact"),
            other => panic!("expected Counter, got {other:?}"),
        }
        for forbidden in &["policy_id", "artifact_id", "repository"] {
            assert!(
                !released.0.key().labels().any(|l| l.key() == *forbidden),
                "forbidden label `{forbidden}` on the re-evaluation result counter",
            );
        }

        // completeness gauge set to the walked population (1 loosen + 0
        // tighten).
        let pop = entries
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Gauge
                    && ck.key().name() == "hort_policy_reevaluation_population"
            })
            .expect("population gauge");
        match &pop.3 {
            DebugValue::Gauge(v) => assert_eq!(*v, 1.0, "population = 1 loosen candidate"),
            other => panic!("expected Gauge, got {other:?}"),
        }
    }

    /// A tighten pass that re-holds an artifact fires
    /// `hort_policy_reevaluation_artifacts_total{result="re_held"}`.
    #[test]
    fn run_pass_tighten_rehold_emits_re_held_result() {
        use crate::metrics::capture_metrics;
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, events, projections, artifacts, _lifecycle, storage) =
                    make_full_re_eval_harness();
                let policy_id = Uuid::new_v4();
                let repo_id = Uuid::new_v4();
                let mut p = sample_projection(policy_id, 4);
                p.severity_threshold = SeverityThreshold::High;
                projections.insert(p);
                artifacts.seed_rejected_for_policy(policy_id, vec![]);
                let findings = vec![sample_finding("CVE-2024-0001", SeverityThreshold::Critical)];
                let _ = seed_active_with_findings(
                    &artifacts,
                    &events,
                    &storage,
                    repo_id,
                    QuarantineStatus::Released,
                    &findings,
                );
                artifacts.seed_active_for_policy(policy_id, vec![repo_id]);
                uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
                    .await;
            });
        });
        let entries = snap.into_vec();

        let re_held = entries
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_policy_reevaluation_artifacts_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "re_held")
            })
            .expect("re_held result counter");
        match &re_held.3 {
            DebugValue::Counter(n) => assert_eq!(*n, 1, "one re-held artifact"),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    /// A pass whose verdicts are all unchanged fires
    /// `hort_policy_reevaluation_artifacts_total{result="unchanged"}` (a
    /// still-clean tighten candidate) and still sets the population gauge.
    #[test]
    fn run_pass_unchanged_emits_unchanged_result_and_population() {
        use crate::metrics::capture_metrics;
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, events, projections, artifacts, _lifecycle, storage) =
                    make_full_re_eval_harness();
                let policy_id = Uuid::new_v4();
                let repo_id = Uuid::new_v4();
                projections.insert(sample_projection(policy_id, 4));
                artifacts.seed_rejected_for_policy(policy_id, vec![]);
                // A lone Low finding under threshold High → Clean → no-op.
                let findings = vec![sample_finding("CVE-2024-0002", SeverityThreshold::Low)];
                let _ = seed_active_with_findings(
                    &artifacts,
                    &events,
                    &storage,
                    repo_id,
                    QuarantineStatus::Released,
                    &findings,
                );
                artifacts.seed_active_for_policy(policy_id, vec![repo_id]);
                uc.run_policy_re_evaluation_pass(policy_id, policy_updated_trigger(policy_id))
                    .await;
            });
        });
        let entries = snap.into_vec();

        let unchanged = entries
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_policy_reevaluation_artifacts_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "unchanged")
            })
            .expect("unchanged result counter");
        match &unchanged.3 {
            DebugValue::Counter(n) => assert_eq!(*n, 1, "one unchanged artifact"),
            other => panic!("expected Counter, got {other:?}"),
        }

        let pop = entries
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Gauge
                    && ck.key().name() == "hort_policy_reevaluation_population"
            })
            .expect("population gauge");
        match &pop.3 {
            DebugValue::Gauge(v) => assert_eq!(*v, 1.0, "population = 1 tighten candidate"),
            _ => panic!("expected Gauge"),
        }
    }
}
