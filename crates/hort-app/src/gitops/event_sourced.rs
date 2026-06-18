//! `ApplyEventSourcedKind` trait + per-kind appliers for the gitops
//! apply pipeline.
//!
//! These appliers are **pure logic** — given the desired YAML envelope
//! and the current projection, return the [`DomainEvent`]s that bring
//! the projection in line with the spec. They:
//!
//! - perform no I/O (no event-store, no projection-repo, no tracing
//!   spans),
//! - never attach an [`hort_domain::events::Actor`] — the apply pipeline
//!   wraps the events with the [`hort_domain::events::Actor::GitOps`]
//!   actor when it routes them through the event store,
//! - never write to the projection — the use case that consumes the
//!   events is responsible for projection upsert.
//!
//! ## Design anchors
//!
//! Idempotency: re-applying the same YAML must produce zero events.
//! Strict-atomic: the trait emits events; transactional ordering across
//! streams is the pipeline's concern.
//!
//! ## Scope of the trait
//!
//! The trait covers the "given desired + projection, what events?"
//! direction only. The "desired absent → archive" branch lives in the
//! pipeline, which calls [`crate::use_cases::PolicyUseCase::archive_policy`]
//! directly when the projection exists but no envelope was declared.
//! Putting archive emission inside the trait would force every call
//! site to thread an `Option<&Envelope<Spec>>`, which collapses the
//! trait's "diff what you have" semantics.
//!
//! ## Identity decisions
//!
//! - **Policy id minting (`PolicyCreated`):** the applier mints a fresh
//!   `Uuid::new_v4()` internally when no projection exists. The pipeline
//!   reads the minted id back out of the emitted [`PolicyCreated`]
//!   payload before constructing the [`hort_domain::events::StreamId::policy`]
//!   for the append. This mirrors how
//!   [`crate::use_cases::PolicyUseCase::create_policy`] already mints
//!   server-side and keeps the trait signature as `fn diff(&self,
//!   desired, projection)` — no extra context parameter.
//! - **Exclusion id minting (`ExclusionAdded`):** [`ExclusionsApplier`]
//!   carries the parent `policy_id` as a struct field — the pipeline
//!   constructs one applier per parent policy (it already knows the id
//!   from the parent projection or the just-emitted `PolicyCreated`).
//!   Each `ExclusionAdded` event mints a fresh `exclusion_id`.
//! - **Repository-name resolution:** `ScopeSpec::Repository(name)`
//!   carries a YAML-supplied repository name; the
//!   [`hort_domain::events::PolicyScope::Repository`] variant carries the
//!   resolved [`uuid::Uuid`]. Both appliers carry a `repo_id_by_name`
//!   map populated by the pipeline from the live `DesiredState`. The
//!   applier never performs the lookup itself — it just translates
//!   using the supplied map.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_config::envelope::Envelope;
use hort_config::exclusion::ExclusionSpec;
use hort_config::scan_policy::{ScanPolicySpec, SignerIdentitySpec};
use hort_config::scope::ScopeSpec;
use hort_domain::entities::scan_policy::{
    ExclusionProjection, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    SignerIdentityPattern,
};
use hort_domain::events::{
    DomainEvent, ExclusionAdded, ExclusionRemoved, PolicyCreated, PolicyField, PolicyScope,
    PolicyUpdated,
};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Pure-logic diff between a desired envelope and the current projection
/// for one event-sourced gitops kind.
///
/// Implementations return the [`DomainEvent`]s the pipeline must append
/// to bring the projection in line with `desired`. An empty `Vec`
/// signals an idempotent no-op — the projection already matches.
///
/// Implementations MUST NOT:
/// - attach an [`hort_domain::events::Actor`] (the pipeline wraps with
///   [`hort_domain::events::Actor::GitOps`]),
/// - mutate the projection,
/// - perform I/O.
///
/// The trait does **not** handle the "desired absent, projection
/// exists" archive branch — that lives in the apply pipeline, which
/// calls [`crate::use_cases::PolicyUseCase::archive_policy`] directly.
pub trait ApplyEventSourcedKind: Send + Sync {
    type Spec;
    type Projection;

    /// Compute the events to emit. Returns an empty `Vec` when the
    /// projection already matches the desired spec.
    fn diff(
        &self,
        desired: &Envelope<Self::Spec>,
        projection: Option<&Self::Projection>,
    ) -> Vec<DomainEvent>;
}

// ---------------------------------------------------------------------------
// ScanPolicyApplier
// ---------------------------------------------------------------------------

/// Applier for `kind: ScanPolicy`.
///
/// Carries a `repo_id_by_name` map populated by the pipeline so the
/// applier can translate [`ScopeSpec::Repository`] → [`PolicyScope::Repository`]
/// without performing its own lookup. The pipeline ensures every
/// repository name referenced by the desired scope is present in the
/// map before invoking [`ApplyEventSourcedKind::diff`]; an unmapped name
/// is treated as a programming error and panics with the `INVARIANT:`
/// prefix used elsewhere in `hort-app`.
#[derive(Debug, Default, Clone)]
pub struct ScanPolicyApplier {
    /// Resolved `repository.metadata.name` → `repository.id` lookups.
    /// Populated by the apply pipeline from the live `DesiredState` /
    /// `RepositoryRepository` snapshot.
    pub repo_id_by_name: HashMap<String, Uuid>,
}

impl ScanPolicyApplier {
    /// Construct an applier with the supplied resolution map.
    pub fn new(repo_id_by_name: HashMap<String, Uuid>) -> Self {
        Self { repo_id_by_name }
    }

    /// Translate a YAML-side `ScopeSpec` into the domain-side `PolicyScope`.
    ///
    /// `ScopeSpec::Repository(name)` requires the name to be present in
    /// `repo_id_by_name`; absence indicates the cross-spec validator was
    /// bypassed (a programming error) and panics with the workspace's
    /// `INVARIANT:` prefix.
    fn resolve_scope(&self, scope: &ScopeSpec) -> PolicyScope {
        match scope {
            ScopeSpec::Global => PolicyScope::Global,
            ScopeSpec::Repository(r) => {
                let id = self
                    .repo_id_by_name
                    .get(&r.repository)
                    .copied()
                    .unwrap_or_else(|| {
                        panic!(
                        "INVARIANT: ScanPolicyApplier received repository name '{}' that is not \
                         in repo_id_by_name — pipeline must resolve all referenced repo names \
                         from DesiredState before constructing the applier",
                        r.repository
                    )
                    });
                PolicyScope::Repository(id)
            }
        }
    }
}

impl ApplyEventSourcedKind for ScanPolicyApplier {
    type Spec = ScanPolicySpec;
    type Projection = ScanPolicyProjection;

    /// Diff the desired envelope against an optional projection.
    ///
    /// **Production pipeline note.** The `None` projection branch
    /// (which mints a fresh `policy_id` and emits a single
    /// [`PolicyCreated`]) is currently exercised only by unit tests
    /// in this module. The apply pipeline
    /// ([`crate::use_cases::ApplyConfigUseCase::apply_scan_policies`])
    /// builds a [`crate::use_cases::CreatePolicyCommand`] directly
    /// from [`ScanPolicySpec`] and routes it through
    /// [`crate::use_cases::PolicyUseCase::create_policy`], which mints
    /// the `policy_id` itself — so this applier is consulted only on
    /// the update path where a projection already exists. The `None`
    /// branch is retained as part of the trait's contract and may become
    /// reachable from a future caller that wants the bare event vec
    /// without the use-case wrapping.
    fn diff(
        &self,
        desired: &Envelope<ScanPolicySpec>,
        projection: Option<&ScanPolicyProjection>,
    ) -> Vec<DomainEvent> {
        let desired_scope = self.resolve_scope(&desired.spec.scope);
        let desired_threshold = parse_threshold(&desired.spec.severity_threshold);
        let desired_quarantine = parse_humantime_secs(&desired.spec.quarantine_duration);
        let desired_max_age = desired
            .spec
            .max_artifact_age
            .as_deref()
            .map(parse_humantime_secs);
        // The provenance trio. `hort-config`'s
        // `validate_scan_policy` ran first, so a parse failure here is a
        // bypassed-validator programming error (panic with `INVARIANT:`).
        let desired_provenance_mode = parse_provenance_mode(&desired.spec.provenance_mode);
        let desired_provenance_identities =
            parse_provenance_identities(&desired.spec.provenance_identities);

        match projection {
            None => {
                // No projection — emit a single PolicyCreated. The
                // applier mints `policy_id` itself; the pipeline reads
                // it back from the event payload to construct the
                // stream id for the append.
                let policy_id = Uuid::new_v4();
                let config_snapshot = build_config_snapshot(
                    &desired.metadata.name,
                    &desired_scope,
                    desired_threshold,
                    desired_quarantine,
                    desired.spec.require_approval,
                    &desired_provenance_mode,
                    &desired.spec.provenance_backends,
                    &desired_provenance_identities,
                    desired_max_age,
                    &desired.spec.license_policy,
                    &desired.spec.scan_backends,
                    desired.spec.rescan_interval_hours,
                );
                vec![DomainEvent::PolicyCreated(PolicyCreated {
                    policy_id,
                    name: desired.metadata.name.clone(),
                    scope: desired_scope,
                    config_snapshot,
                })]
            }
            Some(proj) => {
                let mut events: Vec<DomainEvent> = Vec::new();
                let pid = proj.policy_id;

                // -- Name --
                if proj.name != desired.metadata.name {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::Name,
                        previous_value: serde_json::Value::String(proj.name.clone()),
                        new_value: serde_json::Value::String(desired.metadata.name.clone()),
                    }));
                }

                // -- Scope --
                if proj.scope != desired_scope {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::Scope,
                        previous_value: serde_json::to_value(&proj.scope)
                            .expect("INVARIANT: PolicyScope serialises to JSON"),
                        new_value: serde_json::to_value(&desired_scope)
                            .expect("INVARIANT: PolicyScope serialises to JSON"),
                    }));
                }

                // -- SeverityThreshold --
                if proj.severity_threshold != desired_threshold {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::SeverityThreshold,
                        previous_value: serde_json::to_value(proj.severity_threshold)
                            .expect("INVARIANT: SeverityThreshold serialises to JSON"),
                        new_value: serde_json::to_value(desired_threshold)
                            .expect("INVARIANT: SeverityThreshold serialises to JSON"),
                    }));
                }

                // -- QuarantineDuration --
                if proj.quarantine_duration_secs != desired_quarantine {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::QuarantineDuration,
                        previous_value: serde_json::Value::from(proj.quarantine_duration_secs),
                        new_value: serde_json::Value::from(desired_quarantine),
                    }));
                }

                // -- RequireApproval --
                if proj.require_approval != desired.spec.require_approval {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::RequireApproval,
                        previous_value: serde_json::Value::Bool(proj.require_approval),
                        new_value: serde_json::Value::Bool(desired.spec.require_approval),
                    }));
                }

                // -- ProvenanceMode --
                if proj.provenance_mode != desired_provenance_mode {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::ProvenanceMode,
                        previous_value: serde_json::Value::String(proj.provenance_mode.to_string()),
                        new_value: serde_json::Value::String(desired_provenance_mode.to_string()),
                    }));
                }

                // -- ProvenanceBackends — mirrors
                // ScanBackends: element-wise + order-sensitive equality.
                if proj.provenance_backends != desired.spec.provenance_backends {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::ProvenanceBackends,
                        previous_value: serde_json::to_value(&proj.provenance_backends)
                            .expect("INVARIANT: Vec<String> serialises to JSON"),
                        new_value: serde_json::to_value(&desired.spec.provenance_backends)
                            .expect("INVARIANT: Vec<String> serialises to JSON"),
                    }));
                }

                // -- ProvenanceIdentities --
                if proj.provenance_identities != desired_provenance_identities {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::ProvenanceIdentities,
                        previous_value: serde_json::to_value(&proj.provenance_identities)
                            .expect("INVARIANT: SignerIdentityPattern serialises to JSON"),
                        new_value: serde_json::to_value(&desired_provenance_identities)
                            .expect("INVARIANT: SignerIdentityPattern serialises to JSON"),
                    }));
                }

                // -- MaxArtifactAge --
                if proj.max_artifact_age_secs != desired_max_age {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::MaxArtifactAge,
                        previous_value: optional_i64_to_value(proj.max_artifact_age_secs),
                        new_value: optional_i64_to_value(desired_max_age),
                    }));
                }

                // -- LicensePolicy --
                if proj.license_policy != desired.spec.license_policy {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::LicensePolicy,
                        previous_value: proj.license_policy.clone(),
                        new_value: desired.spec.license_policy.clone(),
                    }));
                }

                // -- ScanBackends --
                // Vec equality is element-wise + order-sensitive, so a
                // declared reordering of `scanBackends: [trivy, osv]`
                // → `[osv, trivy]` produces an event. That matches the
                // orchestrator's "invoke in declared order" contract.
                if proj.scan_backends != desired.spec.scan_backends {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::ScanBackends,
                        previous_value: serde_json::to_value(&proj.scan_backends)
                            .expect("INVARIANT: Vec<String> serialises to JSON"),
                        new_value: serde_json::to_value(&desired.spec.scan_backends)
                            .expect("INVARIANT: Vec<String> serialises to JSON"),
                    }));
                }

                // -- RescanIntervalHours --
                // Tracked alongside scan_backends — the cron-rescan-tick
                // handler reads this field per-policy. A change from
                // `24` → `0` disables rescanning for the policy's
                // artifacts; the diff produces a PolicyUpdated event
                // so the projection write reflects it.
                if proj.rescan_interval_hours != desired.spec.rescan_interval_hours {
                    events.push(DomainEvent::PolicyUpdated(PolicyUpdated {
                        policy_id: pid,
                        field: PolicyField::RescanIntervalHours,
                        previous_value: serde_json::Value::from(proj.rescan_interval_hours),
                        new_value: serde_json::Value::from(desired.spec.rescan_interval_hours),
                    }));
                }

                events
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExclusionsApplier
// ---------------------------------------------------------------------------

/// Reason text stored on `ExclusionRemoved` events the applier emits
/// when an exclusion disappears from the desired set or is replaced
/// because one of its mutable fields changed.
const REASON_REMOVED_BY_GITOPS: &str = "removed by gitops apply";
const REASON_CHANGED_BY_GITOPS: &str = "changed by gitops apply";

/// Applier for `kind: Exclusion`.
///
/// One applier instance per parent policy — `policy_id` carries the
/// parent stream id (the stream every exclusion event for this policy
/// appends to). Each `ExclusionAdded` event mints a fresh
/// `exclusion_id` internally.
///
/// Like [`ScanPolicyApplier`], the applier carries a `repo_id_by_name`
/// map for translating `ScopeSpec::Repository(name)` → `PolicyScope::Repository(uuid)`.
#[derive(Debug, Clone)]
pub struct ExclusionsApplier {
    /// The parent policy's id. Every emitted event carries this id;
    /// the pipeline appends to `StreamId::policy(policy_id)`.
    pub policy_id: Uuid,
    /// Resolved repository name → id map; same contract as
    /// [`ScanPolicyApplier::repo_id_by_name`].
    pub repo_id_by_name: HashMap<String, Uuid>,
}

impl ExclusionsApplier {
    /// Construct an applier for one parent policy.
    pub fn new(policy_id: Uuid, repo_id_by_name: HashMap<String, Uuid>) -> Self {
        Self {
            policy_id,
            repo_id_by_name,
        }
    }

    fn resolve_scope(&self, scope: &ScopeSpec) -> PolicyScope {
        match scope {
            ScopeSpec::Global => PolicyScope::Global,
            ScopeSpec::Repository(r) => {
                let id = self
                    .repo_id_by_name
                    .get(&r.repository)
                    .copied()
                    .unwrap_or_else(|| {
                        panic!(
                        "INVARIANT: ExclusionsApplier received repository name '{}' that is not \
                         in repo_id_by_name — pipeline must resolve all referenced repo names \
                         from DesiredState before constructing the applier",
                        r.repository
                    )
                    });
                PolicyScope::Repository(id)
            }
        }
    }
}

impl ApplyEventSourcedKind for ExclusionsApplier {
    type Spec = Vec<ExclusionSpec>;
    type Projection = Vec<ExclusionProjection>;

    fn diff(
        &self,
        desired: &Envelope<Vec<ExclusionSpec>>,
        projection: Option<&Vec<ExclusionProjection>>,
    ) -> Vec<DomainEvent> {
        // An absent projection is treated as an empty current set —
        // the pipeline reads the parent policy's exclusion list (which
        // is empty for a freshly-created policy) and may pass `None`
        // rather than `Some(&vec![])`.
        let empty: Vec<ExclusionProjection> = Vec::new();
        let current = projection.unwrap_or(&empty);

        // Build the desired identity → spec map and the current
        // identity → projection map.
        type Identity<'a> = (&'a str, Option<&'a str>);

        let desired_by_id: HashMap<Identity<'_>, &ExclusionSpec> = desired
            .spec
            .iter()
            .map(|e| ((e.cve_id.as_str(), e.package_pattern.as_deref()), e))
            .collect();

        let current_by_id: HashMap<Identity<'_>, &ExclusionProjection> = current
            .iter()
            .map(|p| ((p.cve_id.as_str(), p.package_pattern.as_deref()), p))
            .collect();

        let desired_ids: HashSet<Identity<'_>> = desired_by_id.keys().copied().collect();
        let current_ids: HashSet<Identity<'_>> = current_by_id.keys().copied().collect();

        let mut events: Vec<DomainEvent> = Vec::new();

        // -- Removed: in current but not in desired --
        for id in current_ids.difference(&desired_ids) {
            let proj = current_by_id[id];
            events.push(DomainEvent::ExclusionRemoved(ExclusionRemoved {
                policy_id: self.policy_id,
                exclusion_id: proj.exclusion_id,
                reason: REASON_REMOVED_BY_GITOPS.to_string(),
            }));
        }

        // -- Added: in desired but not in current --
        for id in desired_ids.difference(&current_ids) {
            let spec = desired_by_id[id];
            events.push(self.added_event(spec));
        }

        // -- Both present, mutable fields differ → Removed + Added --
        for id in desired_ids.intersection(&current_ids) {
            let spec = desired_by_id[id];
            let proj = current_by_id[id];
            let desired_scope = self.resolve_scope(&spec.scope);
            let scope_changed = proj.scope != desired_scope;
            let reason_changed = proj.reason != spec.reason;
            let expires_changed = !optional_dt_eq(proj.expires_at, spec.expires_at);

            if scope_changed || reason_changed || expires_changed {
                events.push(DomainEvent::ExclusionRemoved(ExclusionRemoved {
                    policy_id: self.policy_id,
                    exclusion_id: proj.exclusion_id,
                    reason: REASON_CHANGED_BY_GITOPS.to_string(),
                }));
                events.push(self.added_event(spec));
            }
        }

        events
    }
}

impl ExclusionsApplier {
    /// Mint a fresh `exclusion_id` and wrap the spec in an
    /// `ExclusionAdded` event under this applier's parent policy id.
    fn added_event(&self, spec: &ExclusionSpec) -> DomainEvent {
        DomainEvent::ExclusionAdded(ExclusionAdded {
            policy_id: self.policy_id,
            exclusion_id: Uuid::new_v4(),
            cve_id: spec.cve_id.clone(),
            package_pattern: spec.package_pattern.clone(),
            scope: self.resolve_scope(&spec.scope),
            reason: spec.reason.clone(),
            expires_at: spec.expires_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Mirror of `policy_use_case::build_config_snapshot` so the gitops
/// `PolicyCreated` payload is wire-compatible with the imperative path.
/// Any rename here is a wire change — keep the field names in lockstep.
#[allow(clippy::too_many_arguments)]
fn build_config_snapshot(
    name: &str,
    scope: &PolicyScope,
    severity_threshold: SeverityThreshold,
    quarantine_duration_secs: i64,
    require_approval: bool,
    provenance_mode: &ProvenanceMode,
    provenance_backends: &[String],
    provenance_identities: &[SignerIdentityPattern],
    max_artifact_age_secs: Option<i64>,
    license_policy: &serde_json::Value,
    scan_backends: &[String],
    rescan_interval_hours: i32,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "scope": scope,
        "severity_threshold": severity_threshold,
        "quarantine_duration_secs": quarantine_duration_secs,
        "require_approval": require_approval,
        // The provenance trio replaces requireSignature.
        "provenance_mode": provenance_mode.to_string(),
        "provenance_backends": provenance_backends,
        "provenance_identities": provenance_identities,
        "max_artifact_age_secs": max_artifact_age_secs,
        "license_policy": license_policy,
        "scan_backends": scan_backends,
        "rescan_interval_hours": rescan_interval_hours,
    })
}

/// Parse the validated `provenanceMode` wire string into
/// the domain enum. `hort_config::scan_policy::validate_scan_policy` ran
/// first, so a parse failure is a bypassed-validator programming error.
fn parse_provenance_mode(s: &str) -> ProvenanceMode {
    ProvenanceMode::from_str(s).unwrap_or_else(|err| {
        panic!(
            "INVARIANT: provenance mode '{s}' must have been validated by \
             hort_config::scan_policy::validate_scan_policy before reaching the \
             applier (parse error: {err})"
        )
    })
}

/// Map the validated `provenanceIdentities` wire specs to
/// the domain pattern type. Each entry already passed the per-element
/// constructor validator in `validate_scan_policy`, so a construction
/// failure here is a bypassed-validator programming error.
fn parse_provenance_identities(specs: &[SignerIdentitySpec]) -> Vec<SignerIdentityPattern> {
    specs
        .iter()
        .map(|s| {
            SignerIdentityPattern::new(s.issuer.clone(), s.san.clone()).unwrap_or_else(|err| {
                panic!(
                    "INVARIANT: provenance identity must have been validated by \
                     hort_config::scan_policy::validate_scan_policy before reaching \
                     the applier (construction error: {err})"
                )
            })
        })
        .collect()
}

/// Parse a humantime duration into integer seconds. The `hort-config`
/// validator ran first, so a parse failure here is a programming error
/// (the validator was bypassed). Panic with the workspace's
/// `INVARIANT:` prefix.
fn parse_humantime_secs(s: &str) -> i64 {
    let dur = humantime::parse_duration(s).unwrap_or_else(|err| {
        panic!(
            "INVARIANT: humantime duration '{s}' must have been validated by \
             hort_config::scan_policy::validate_scan_policy before reaching the \
             applier (parse error: {err})"
        )
    });
    i64::try_from(dur.as_secs()).unwrap_or_else(|err| {
        panic!(
            "INVARIANT: humantime duration '{s}' overflows i64 seconds \
             (validator should have rejected; conversion error: {err})"
        )
    })
}

fn parse_threshold(s: &str) -> SeverityThreshold {
    SeverityThreshold::from_str(s).unwrap_or_else(|err| {
        panic!(
            "INVARIANT: severity threshold '{s}' must have been validated by \
             hort_config::scan_policy::validate_scan_policy before reaching the \
             applier (parse error: {err})"
        )
    })
}

fn optional_i64_to_value(v: Option<i64>) -> serde_json::Value {
    match v {
        Some(n) => serde_json::Value::from(n),
        None => serde_json::Value::Null,
    }
}

/// Treat two `Option<DateTime<Utc>>` as equal iff both are `None` or
/// both are `Some` with equal instants. Direct `==` on
/// `Option<DateTime<Utc>>` already does this; the helper exists to
/// document intent at the comparison site (and lets us swap in a
/// precision-tolerant comparison later if we ever store sub-second
/// drift somewhere).
fn optional_dt_eq(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> bool {
    a == b
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use hort_config::envelope::{ApiVersion, Kind, Metadata};
    use hort_config::scope::RepositoryScope;

    // -- Builders ------------------------------------------------------------

    fn policy_envelope(spec: ScanPolicySpec) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ScanPolicy,
            metadata: Metadata {
                name: "prod-default".into(),
            },
            spec,
        }
    }

    fn baseline_spec() -> ScanPolicySpec {
        ScanPolicySpec {
            scope: ScopeSpec::Global,
            severity_threshold: "high".into(),
            quarantine_duration: "24h".into(),
            require_approval: true,
            provenance_mode: "verify_if_present".into(),
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age: Some("90d".into()),
            license_policy: serde_json::json!({
                "allowed": ["Apache-2.0", "MIT"],
                "denied": ["GPL-3.0"],
            }),
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
        }
    }

    fn baseline_projection(policy_id: Uuid) -> ScanPolicyProjection {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
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
                "denied": ["GPL-3.0"],
            }),
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            stream_version: 7,
            created_at: now,
            updated_at: now,
        }
    }

    fn exclusion_envelope(specs: Vec<ExclusionSpec>) -> Envelope<Vec<ExclusionSpec>> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::Exclusion,
            metadata: Metadata {
                name: "exclusions-for-prod-default".into(),
            },
            spec: specs,
        }
    }

    fn baseline_exclusion_spec(cve: &str) -> ExclusionSpec {
        ExclusionSpec {
            policy: "prod-default".into(),
            cve_id: cve.into(),
            package_pattern: None,
            scope: ScopeSpec::Global,
            reason: "patched in container layer".into(),
            expires_at: None,
        }
    }

    fn baseline_exclusion_projection(
        exclusion_id: Uuid,
        policy_id: Uuid,
        cve: &str,
    ) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id,
            policy_id,
            cve_id: cve.into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "patched in container layer".into(),
            added_by_actor_id: None,
            expires_at: None,
        }
    }

    // ===================================================================
    // ScanPolicyApplier — no-projection branch
    // ===================================================================

    #[test]
    fn scan_policy_no_projection_emits_one_policy_created_with_full_snapshot() {
        let applier = ScanPolicyApplier::default();
        let env = policy_envelope(baseline_spec());

        let events = applier.diff(&env, None);

        assert_eq!(events.len(), 1, "no projection must emit exactly one event");
        let DomainEvent::PolicyCreated(payload) = &events[0] else {
            panic!("expected PolicyCreated, got {:?}", events[0].event_type());
        };
        assert_eq!(payload.name, "prod-default");
        assert_eq!(payload.scope, PolicyScope::Global);
        assert_ne!(
            payload.policy_id,
            Uuid::nil(),
            "applier must mint a non-nil policy_id"
        );

        // config_snapshot reflects every spec field.
        let snap = &payload.config_snapshot;
        assert_eq!(snap["name"], "prod-default");
        assert_eq!(snap["severity_threshold"], "High");
        assert_eq!(snap["quarantine_duration_secs"], 24 * 3600);
        assert_eq!(snap["require_approval"], true);
        // The provenance trio in the create-snapshot.
        assert_eq!(snap["provenance_mode"], "verify_if_present");
        assert_eq!(snap["provenance_backends"], serde_json::json!(["cosign"]));
        assert_eq!(snap["provenance_identities"], serde_json::json!([]));
        assert_eq!(snap["max_artifact_age_secs"], 90 * 24 * 3600);
        assert!(snap["license_policy"].is_object());
        assert_eq!(snap["license_policy"]["allowed"][0], "Apache-2.0");
        // scan_backends in the create-snapshot.
        assert_eq!(snap["scan_backends"], serde_json::json!(["trivy"]));
        // rescan_interval_hours in the create-snapshot.
        assert_eq!(snap["rescan_interval_hours"], 24);
    }

    #[test]
    fn scan_policy_no_projection_resolves_repository_scope_via_map() {
        let repo_id = Uuid::from_u128(0x1234);
        let mut map = HashMap::new();
        map.insert("npm-public".to_string(), repo_id);
        let applier = ScanPolicyApplier::new(map);
        let mut spec = baseline_spec();
        spec.scope = ScopeSpec::Repository(RepositoryScope {
            repository: "npm-public".into(),
        });
        let env = policy_envelope(spec);

        let events = applier.diff(&env, None);

        let DomainEvent::PolicyCreated(payload) = &events[0] else {
            panic!();
        };
        assert_eq!(payload.scope, PolicyScope::Repository(repo_id));
    }

    #[test]
    fn scan_policy_no_projection_mints_unique_policy_ids_per_call() {
        let applier = ScanPolicyApplier::default();
        let env = policy_envelope(baseline_spec());
        let DomainEvent::PolicyCreated(a) = &applier.diff(&env, None)[0] else {
            panic!();
        };
        let DomainEvent::PolicyCreated(b) = &applier.diff(&env, None)[0] else {
            panic!();
        };
        assert_ne!(
            a.policy_id, b.policy_id,
            "successive diffs must mint fresh ids"
        );
    }

    #[test]
    fn scan_policy_no_projection_optional_max_age_omitted_serialises_as_null() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.max_artifact_age = None;
        let env = policy_envelope(spec);

        let DomainEvent::PolicyCreated(payload) = &applier.diff(&env, None)[0] else {
            panic!();
        };
        assert!(payload.config_snapshot["max_artifact_age_secs"].is_null());
    }

    #[test]
    #[should_panic(expected = "INVARIANT")]
    fn scan_policy_unmapped_repository_name_panics_with_invariant_prefix() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.scope = ScopeSpec::Repository(RepositoryScope {
            repository: "ghost-repo".into(),
        });
        let env = policy_envelope(spec);
        let _ = applier.diff(&env, None);
    }

    #[test]
    #[should_panic(expected = "INVARIANT")]
    fn scan_policy_malformed_severity_panics_with_invariant_prefix() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.severity_threshold = "nuclear".into();
        let env = policy_envelope(spec);
        let _ = applier.diff(&env, None);
    }

    #[test]
    #[should_panic(expected = "INVARIANT")]
    fn scan_policy_malformed_humantime_panics_with_invariant_prefix() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.quarantine_duration = "12garbage".into();
        let env = policy_envelope(spec);
        let _ = applier.diff(&env, None);
    }

    // ===================================================================
    // ScanPolicyApplier — projection-equal branch (idempotent no-op)
    // ===================================================================

    #[test]
    fn scan_policy_equal_projection_emits_no_events() {
        let pid = Uuid::from_u128(1);
        let applier = ScanPolicyApplier::default();
        let env = policy_envelope(baseline_spec());
        let proj = baseline_projection(pid);

        let events = applier.diff(&env, Some(&proj));
        assert!(events.is_empty(), "equal projection must yield empty Vec");
    }

    // ===================================================================
    // ScanPolicyApplier — single-field-changed branches
    // ===================================================================

    /// Helper: assert exactly one `PolicyUpdated` event for the given
    /// field, with the expected previous and new JSON values.
    fn assert_single_field_updated(
        events: &[DomainEvent],
        expected_field: &PolicyField,
        expected_previous: &serde_json::Value,
        expected_new: &serde_json::Value,
    ) {
        assert_eq!(
            events.len(),
            1,
            "expected exactly one event, got {}",
            events.len()
        );
        let DomainEvent::PolicyUpdated(payload) = &events[0] else {
            panic!("expected PolicyUpdated, got {:?}", events[0].event_type());
        };
        assert_eq!(&payload.field, expected_field);
        assert_eq!(&payload.previous_value, expected_previous);
        assert_eq!(&payload.new_value, expected_new);
    }

    #[test]
    fn scan_policy_name_change_emits_one_name_event() {
        let pid = Uuid::from_u128(1);
        let applier = ScanPolicyApplier::default();
        let mut env = policy_envelope(baseline_spec());
        env.metadata.name = "prod-strict".into();
        let proj = baseline_projection(pid);

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::Name,
            &serde_json::json!("prod-default"),
            &serde_json::json!("prod-strict"),
        );
        if let DomainEvent::PolicyUpdated(p) = &events[0] {
            assert_eq!(p.policy_id, pid);
        }
    }

    #[test]
    fn scan_policy_scope_change_global_to_repository_emits_one_scope_event() {
        let repo_id = Uuid::from_u128(0xabcd);
        let mut map = HashMap::new();
        map.insert("npm-public".to_string(), repo_id);
        let applier = ScanPolicyApplier::new(map);
        let mut spec = baseline_spec();
        spec.scope = ScopeSpec::Repository(RepositoryScope {
            repository: "npm-public".into(),
        });
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(2));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::Scope,
            &serde_json::to_value(PolicyScope::Global).unwrap(),
            &serde_json::to_value(PolicyScope::Repository(repo_id)).unwrap(),
        );
    }

    #[test]
    fn scan_policy_severity_change_high_to_critical_emits_one_threshold_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.severity_threshold = "critical".into();
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(3));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::SeverityThreshold,
            &serde_json::to_value(SeverityThreshold::High).unwrap(),
            &serde_json::to_value(SeverityThreshold::Critical).unwrap(),
        );
    }

    #[test]
    fn scan_policy_quarantine_duration_change_emits_one_event_with_secs() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.quarantine_duration = "1h".into();
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(4));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::QuarantineDuration,
            &serde_json::Value::from(24 * 3600),
            &serde_json::Value::from(3600),
        );
    }

    #[test]
    fn scan_policy_require_approval_toggle_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.require_approval = false;
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(5));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::RequireApproval,
            &serde_json::Value::Bool(true),
            &serde_json::Value::Bool(false),
        );
    }

    // The provenance trio diff-and-emit (one event per
    // changed field, mirroring the retired requireSignature toggle and
    // the scan_backends tests).
    #[test]
    fn scan_policy_provenance_mode_change_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.provenance_mode = "required".into();
        // Required needs identities to be a valid policy, but the diff
        // path only computes change events — apply-time linting is a separate concern.
        spec.provenance_identities = vec![SignerIdentitySpec {
            issuer: "iss".into(),
            san: "san".into(),
        }];
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(6));

        let events = applier.diff(&env, Some(&proj));
        // Two fields changed (mode + identities); assert the mode event.
        let mode_event = events
            .iter()
            .find_map(|e| match e {
                DomainEvent::PolicyUpdated(p) if p.field == PolicyField::ProvenanceMode => Some(p),
                _ => None,
            })
            .expect("a ProvenanceMode PolicyUpdated event");
        assert_eq!(
            mode_event.previous_value,
            serde_json::Value::String("verify_if_present".into())
        );
        assert_eq!(
            mode_event.new_value,
            serde_json::Value::String("required".into())
        );
    }

    #[test]
    fn scan_policy_provenance_mode_only_change_emits_exactly_one_event() {
        // Off → no identities required; a bare mode change is one event.
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.provenance_mode = "off".into();
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(0x6a));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::ProvenanceMode,
            &serde_json::Value::String("verify_if_present".into()),
            &serde_json::Value::String("off".into()),
        );
    }

    #[test]
    fn scan_policy_provenance_backends_change_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.provenance_backends = vec!["cosign".into(), "notary".into()];
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(0x6b));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::ProvenanceBackends,
            &serde_json::json!(["cosign"]),
            &serde_json::json!(["cosign", "notary"]),
        );
    }

    #[test]
    fn scan_policy_provenance_identities_change_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.provenance_identities = vec![SignerIdentitySpec {
            issuer: "https://token.actions.githubusercontent.com".into(),
            san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                .into(),
        }];
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(0x6c));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::ProvenanceIdentities,
            &serde_json::json!([]),
            &serde_json::json!([{
                "issuer": "https://token.actions.githubusercontent.com",
                "san": "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
            }]),
        );
    }

    #[test]
    fn scan_policy_provenance_unchanged_emits_no_event() {
        let applier = ScanPolicyApplier::default();
        let env = policy_envelope(baseline_spec());
        let proj = baseline_projection(Uuid::from_u128(0x6d));

        let events = applier.diff(&env, Some(&proj));
        assert!(events.is_empty(), "matching provenance fields → no event");
    }

    #[test]
    fn scan_policy_max_artifact_age_some_to_some_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.max_artifact_age = Some("30d".into());
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(7));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::MaxArtifactAge,
            &serde_json::Value::from(90 * 24 * 3600),
            &serde_json::Value::from(30 * 24 * 3600),
        );
    }

    #[test]
    fn scan_policy_max_artifact_age_some_to_none_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.max_artifact_age = None;
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(8));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::MaxArtifactAge,
            &serde_json::Value::from(90 * 24 * 3600),
            &serde_json::Value::Null,
        );
    }

    #[test]
    fn scan_policy_max_artifact_age_none_to_some_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.max_artifact_age = Some("7d".into());
        let env = policy_envelope(spec);
        let mut proj = baseline_projection(Uuid::from_u128(9));
        proj.max_artifact_age_secs = None;

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::MaxArtifactAge,
            &serde_json::Value::Null,
            &serde_json::Value::from(7 * 24 * 3600),
        );
    }

    #[test]
    fn scan_policy_scan_backends_change_emits_one_event() {
        // Diff a scan_backends update against the
        // baseline projection (which now defaults to `["trivy"]`).
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.scan_backends = vec!["trivy".into(), "osv".into()];
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(0xb00));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::ScanBackends,
            &serde_json::json!(["trivy"]),
            &serde_json::json!(["trivy", "osv"]),
        );
    }

    #[test]
    fn scan_policy_scan_backends_reorder_emits_event() {
        // Vec equality is order-sensitive — operators may declare
        // backends in a particular order to drive the orchestrator's
        // declared-order invocation contract. A
        // declared reorder must therefore produce an event so the
        // projection reflects the new order.
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.scan_backends = vec!["osv".into(), "trivy".into()];
        let env = policy_envelope(spec);
        let mut proj = baseline_projection(Uuid::from_u128(0xb01));
        proj.scan_backends = vec!["trivy".into(), "osv".into()];

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::ScanBackends,
            &serde_json::json!(["trivy", "osv"]),
            &serde_json::json!(["osv", "trivy"]),
        );
    }

    #[test]
    fn scan_policy_scan_backends_unchanged_emits_no_event() {
        // Idempotent no-op — same `["trivy"]` on both sides.
        let applier = ScanPolicyApplier::default();
        let env = policy_envelope(baseline_spec());
        let proj = baseline_projection(Uuid::from_u128(0xb02));

        let events = applier.diff(&env, Some(&proj));
        assert!(
            events.is_empty(),
            "matching scan_backends must yield no event"
        );
    }

    // rescan_interval_hours diff-and-emit (mirror of
    // the scan_backends tests above).
    #[test]
    fn scan_policy_rescan_interval_hours_change_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.rescan_interval_hours = 48;
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(0xc00));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::RescanIntervalHours,
            &serde_json::json!(24),
            &serde_json::json!(48),
        );
    }

    #[test]
    fn scan_policy_rescan_interval_hours_zero_emits_event_disabling_rescan() {
        // Operator-driven opt-out — a transition from `24` → `0`
        // disables rescanning. Must surface as a PolicyUpdated so the
        // projection write reflects it.
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.rescan_interval_hours = 0;
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(0xc01));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::RescanIntervalHours,
            &serde_json::json!(24),
            &serde_json::json!(0),
        );
    }

    #[test]
    fn scan_policy_rescan_interval_hours_unchanged_emits_no_event() {
        // Idempotent no-op — same `24` on both sides.
        let applier = ScanPolicyApplier::default();
        let env = policy_envelope(baseline_spec());
        let proj = baseline_projection(Uuid::from_u128(0xc02));

        let events = applier.diff(&env, Some(&proj));
        assert!(
            events.is_empty(),
            "matching rescan_interval_hours must yield no event"
        );
    }

    #[test]
    fn scan_policy_license_policy_change_emits_one_event() {
        let applier = ScanPolicyApplier::default();
        let mut spec = baseline_spec();
        spec.license_policy = serde_json::json!({"allowed": ["MIT"]});
        let env = policy_envelope(spec);
        let proj = baseline_projection(Uuid::from_u128(10));

        let events = applier.diff(&env, Some(&proj));
        assert_single_field_updated(
            &events,
            &PolicyField::LicensePolicy,
            &serde_json::json!({
                "allowed": ["Apache-2.0", "MIT"],
                "denied": ["GPL-3.0"],
            }),
            &serde_json::json!({"allowed": ["MIT"]}),
        );
    }

    // ===================================================================
    // ScanPolicyApplier — multi-field change
    // ===================================================================

    #[test]
    fn scan_policy_multiple_fields_changed_emits_one_event_each() {
        let pid = Uuid::from_u128(11);
        let applier = ScanPolicyApplier::default();
        let mut env = policy_envelope(baseline_spec());
        env.metadata.name = "prod-strict".into();
        env.spec.severity_threshold = "critical".into();
        env.spec.require_approval = false;
        env.spec.max_artifact_age = None;
        let proj = baseline_projection(pid);

        let events = applier.diff(&env, Some(&proj));

        assert_eq!(events.len(), 4, "expected one event per changed field");

        // Collect the fields seen — order is not part of the contract.
        // `PolicyField` is `PartialEq` but not `Hash`, so use a `Vec`
        // and `iter().any()` membership checks.
        let fields: Vec<PolicyField> = events
            .iter()
            .map(|e| {
                if let DomainEvent::PolicyUpdated(p) = e {
                    p.field.clone()
                } else {
                    panic!("expected PolicyUpdated, got {}", e.event_type())
                }
            })
            .collect();
        assert!(fields.contains(&PolicyField::Name));
        assert!(fields.contains(&PolicyField::SeverityThreshold));
        assert!(fields.contains(&PolicyField::RequireApproval));
        assert!(fields.contains(&PolicyField::MaxArtifactAge));

        // Every event must reference the projection's policy_id.
        for e in &events {
            if let DomainEvent::PolicyUpdated(p) = e {
                assert_eq!(p.policy_id, pid);
            }
        }
    }

    #[test]
    fn scan_policy_does_not_short_circuit_on_first_changed_field() {
        // Regression guard: if the diff returned after seeing the first
        // changed field, only one event would be emitted. This test
        // ensures every subsequent field is also examined.
        let applier = ScanPolicyApplier::default();
        let mut env = policy_envelope(baseline_spec());
        // Change Name AND LicensePolicy — Name is the first field
        // examined, LicensePolicy the last.
        env.metadata.name = "renamed".into();
        env.spec.license_policy = serde_json::json!({});
        let proj = baseline_projection(Uuid::from_u128(12));

        let events = applier.diff(&env, Some(&proj));
        assert_eq!(events.len(), 2);
    }

    // ===================================================================
    // ExclusionsApplier — empty / additive / subtractive cases
    // ===================================================================

    fn applier_for(policy_id: Uuid) -> ExclusionsApplier {
        ExclusionsApplier::new(policy_id, HashMap::new())
    }

    #[test]
    fn exclusions_both_empty_yields_no_events() {
        let applier = applier_for(Uuid::from_u128(1));
        let env = exclusion_envelope(vec![]);
        let proj: Vec<ExclusionProjection> = vec![];

        let events = applier.diff(&env, Some(&proj));
        assert!(events.is_empty());
    }

    #[test]
    fn exclusions_both_empty_with_none_projection_yields_no_events() {
        // The pipeline may pass `None` for a freshly-created policy
        // rather than `Some(&vec![])`. Both shapes must behave the same.
        let applier = applier_for(Uuid::from_u128(1));
        let env = exclusion_envelope(vec![]);

        let events = applier.diff(&env, None);
        assert!(events.is_empty());
    }

    #[test]
    fn exclusions_desired_empty_with_two_projected_emits_two_removed() {
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);
        let env = exclusion_envelope(vec![]);
        let e1 = baseline_exclusion_projection(Uuid::from_u128(10), pid, "CVE-2024-0001");
        let e2 = baseline_exclusion_projection(Uuid::from_u128(11), pid, "CVE-2024-0002");
        let proj = vec![e1.clone(), e2.clone()];

        let events = applier.diff(&env, Some(&proj));

        assert_eq!(events.len(), 2);
        let removed_ids: HashSet<Uuid> = events
            .iter()
            .map(|e| {
                if let DomainEvent::ExclusionRemoved(r) = e {
                    assert_eq!(r.policy_id, pid);
                    assert_eq!(r.reason, "removed by gitops apply");
                    r.exclusion_id
                } else {
                    panic!("expected ExclusionRemoved, got {}", e.event_type())
                }
            })
            .collect();
        assert!(removed_ids.contains(&e1.exclusion_id));
        assert!(removed_ids.contains(&e2.exclusion_id));
    }

    #[test]
    fn exclusions_projection_empty_with_two_desired_emits_two_added() {
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);
        let s1 = baseline_exclusion_spec("CVE-2024-0001");
        let s2 = baseline_exclusion_spec("CVE-2024-0002");
        let env = exclusion_envelope(vec![s1.clone(), s2.clone()]);

        let events = applier.diff(&env, Some(&vec![]));

        assert_eq!(events.len(), 2);
        let added_cves: HashSet<String> = events
            .iter()
            .map(|e| {
                if let DomainEvent::ExclusionAdded(a) = e {
                    assert_eq!(a.policy_id, pid);
                    assert_ne!(a.exclusion_id, Uuid::nil());
                    a.cve_id.clone()
                } else {
                    panic!("expected ExclusionAdded, got {}", e.event_type())
                }
            })
            .collect();
        assert!(added_cves.contains("CVE-2024-0001"));
        assert!(added_cves.contains("CVE-2024-0002"));
    }

    #[test]
    fn exclusions_same_identity_unchanged_emits_no_events() {
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);
        let s = baseline_exclusion_spec("CVE-2024-0001");
        let env = exclusion_envelope(vec![s.clone()]);
        let proj = vec![baseline_exclusion_projection(
            Uuid::from_u128(10),
            pid,
            "CVE-2024-0001",
        )];

        let events = applier.diff(&env, Some(&proj));
        assert!(events.is_empty(), "matching identity + fields → no events");
    }

    // ===================================================================
    // ExclusionsApplier — same identity, mutable field changed
    // ===================================================================

    /// Helper: diff returned a `Removed`-then-`Added` pair for one
    /// exclusion identity.
    fn assert_remove_then_add(
        events: &[DomainEvent],
        expected_policy_id: Uuid,
        expected_removed_id: Uuid,
        expected_cve: &str,
    ) {
        assert_eq!(events.len(), 2, "expected one Removed + one Added");
        match (&events[0], &events[1]) {
            (DomainEvent::ExclusionRemoved(r), DomainEvent::ExclusionAdded(a)) => {
                assert_eq!(r.policy_id, expected_policy_id);
                assert_eq!(r.exclusion_id, expected_removed_id);
                assert_eq!(r.reason, "changed by gitops apply");
                assert_eq!(a.policy_id, expected_policy_id);
                assert_eq!(a.cve_id, expected_cve);
                assert_ne!(
                    a.exclusion_id, expected_removed_id,
                    "Added must mint a fresh id"
                );
            }
            _ => panic!(
                "expected (ExclusionRemoved, ExclusionAdded), got ({}, {})",
                events[0].event_type(),
                events[1].event_type()
            ),
        }
    }

    #[test]
    fn exclusions_scope_changed_emits_remove_then_add() {
        let pid = Uuid::from_u128(1);
        let repo_id = Uuid::from_u128(0xfeed);
        let mut map = HashMap::new();
        map.insert("npm-public".to_string(), repo_id);
        let applier = ExclusionsApplier::new(pid, map);

        let mut s = baseline_exclusion_spec("CVE-2024-0001");
        s.scope = ScopeSpec::Repository(RepositoryScope {
            repository: "npm-public".into(),
        });
        let env = exclusion_envelope(vec![s]);

        let removed_id = Uuid::from_u128(10);
        let proj = vec![baseline_exclusion_projection(
            removed_id,
            pid,
            "CVE-2024-0001",
        )];

        let events = applier.diff(&env, Some(&proj));
        assert_remove_then_add(&events, pid, removed_id, "CVE-2024-0001");

        // The Added event carries the resolved repository scope.
        if let DomainEvent::ExclusionAdded(a) = &events[1] {
            assert_eq!(a.scope, PolicyScope::Repository(repo_id));
        }
    }

    #[test]
    fn exclusions_expires_at_changed_emits_remove_then_add() {
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);

        let mut s = baseline_exclusion_spec("CVE-2024-0001");
        let new_expiry = Utc.with_ymd_and_hms(2027, 12, 31, 23, 59, 59).unwrap();
        s.expires_at = Some(new_expiry);
        let env = exclusion_envelope(vec![s]);

        let removed_id = Uuid::from_u128(10);
        let proj = vec![baseline_exclusion_projection(
            removed_id,
            pid,
            "CVE-2024-0001",
        )];

        let events = applier.diff(&env, Some(&proj));
        assert_remove_then_add(&events, pid, removed_id, "CVE-2024-0001");
        if let DomainEvent::ExclusionAdded(a) = &events[1] {
            assert_eq!(a.expires_at, Some(new_expiry));
        }
    }

    #[test]
    fn exclusions_reason_changed_emits_remove_then_add() {
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);

        let mut s = baseline_exclusion_spec("CVE-2024-0001");
        s.reason = "revised rationale".into();
        let env = exclusion_envelope(vec![s]);

        let removed_id = Uuid::from_u128(10);
        let proj = vec![baseline_exclusion_projection(
            removed_id,
            pid,
            "CVE-2024-0001",
        )];

        let events = applier.diff(&env, Some(&proj));
        assert_remove_then_add(&events, pid, removed_id, "CVE-2024-0001");
        if let DomainEvent::ExclusionAdded(a) = &events[1] {
            assert_eq!(a.reason, "revised rationale");
        }
    }

    // ===================================================================
    // ExclusionsApplier — identity edge cases
    // ===================================================================

    #[test]
    fn exclusions_null_pattern_vs_some_pattern_are_distinct_identities() {
        // (CVE-2024-0001, None) and (CVE-2024-0001, Some("foo")) are
        // DIFFERENT identities — the diff must produce one Added (for
        // the null-pattern desired) and one Removed (for the
        // Some-pattern projection).
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);

        let s = baseline_exclusion_spec("CVE-2024-0001"); // pattern: None
        let env = exclusion_envelope(vec![s]);

        let mut proj_entry =
            baseline_exclusion_projection(Uuid::from_u128(10), pid, "CVE-2024-0001");
        proj_entry.package_pattern = Some("xz-utils@<5.6.2".into());
        let proj = vec![proj_entry];

        let events = applier.diff(&env, Some(&proj));

        assert_eq!(events.len(), 2);
        let mut saw_added = false;
        let mut saw_removed = false;
        for e in &events {
            match e {
                DomainEvent::ExclusionAdded(a) => {
                    saw_added = true;
                    assert!(a.package_pattern.is_none());
                    assert_eq!(a.cve_id, "CVE-2024-0001");
                }
                DomainEvent::ExclusionRemoved(r) => {
                    saw_removed = true;
                    assert_eq!(r.exclusion_id, Uuid::from_u128(10));
                    assert_eq!(r.reason, "removed by gitops apply");
                }
                other => panic!("unexpected event: {}", other.event_type()),
            }
        }
        assert!(saw_added && saw_removed);
    }

    #[test]
    fn exclusions_mixed_set_correct_add_remove_split() {
        // Desired: A (unchanged), B (new), changed-C (scope-shifted).
        // Current: A (unchanged), C (with old scope — to be replaced), D (to be removed).
        // Expected events: 1 Added(B), 1 Removed(D), 1 Removed(C-old)+Added(C-new).
        let pid = Uuid::from_u128(1);
        let repo_id = Uuid::from_u128(0xfeed);
        let mut map = HashMap::new();
        map.insert("npm-public".to_string(), repo_id);
        let applier = ExclusionsApplier::new(pid, map);

        let s_a = baseline_exclusion_spec("CVE-A");
        let s_b = baseline_exclusion_spec("CVE-B");
        let mut s_c = baseline_exclusion_spec("CVE-C");
        s_c.scope = ScopeSpec::Repository(RepositoryScope {
            repository: "npm-public".into(),
        });
        let env = exclusion_envelope(vec![s_a, s_b, s_c]);

        let p_a = baseline_exclusion_projection(Uuid::from_u128(100), pid, "CVE-A");
        let c_old_id = Uuid::from_u128(101);
        let p_c = baseline_exclusion_projection(c_old_id, pid, "CVE-C"); // global (old)
        let d_id = Uuid::from_u128(102);
        let p_d = baseline_exclusion_projection(d_id, pid, "CVE-D");
        let proj = vec![p_a, p_c, p_d];

        let events = applier.diff(&env, Some(&proj));

        // Tally by category.
        let mut added_cves: HashSet<String> = HashSet::new();
        let mut removed_ids: HashSet<Uuid> = HashSet::new();
        let mut removed_reasons: Vec<String> = Vec::new();
        for e in &events {
            match e {
                DomainEvent::ExclusionAdded(a) => {
                    added_cves.insert(a.cve_id.clone());
                }
                DomainEvent::ExclusionRemoved(r) => {
                    removed_ids.insert(r.exclusion_id);
                    removed_reasons.push(r.reason.clone());
                }
                other => panic!("unexpected event: {}", other.event_type()),
            }
        }

        // B is new → Added.
        assert!(added_cves.contains("CVE-B"));
        // C is changed → Removed(c_old_id) + Added("CVE-C").
        assert!(removed_ids.contains(&c_old_id));
        assert!(added_cves.contains("CVE-C"));
        // D is gone → Removed(d_id).
        assert!(removed_ids.contains(&d_id));
        // A is unchanged → no Added, no Removed.
        assert!(!added_cves.contains("CVE-A"));
        assert!(!removed_ids.contains(&Uuid::from_u128(100)));

        // Reason audit: D removal is "removed by gitops apply"; C
        // replacement is "changed by gitops apply".
        assert_eq!(
            removed_reasons
                .iter()
                .filter(|r| *r == "removed by gitops apply")
                .count(),
            1
        );
        assert_eq!(
            removed_reasons
                .iter()
                .filter(|r| *r == "changed by gitops apply")
                .count(),
            1
        );
    }

    #[test]
    #[should_panic(expected = "INVARIANT")]
    fn exclusions_unmapped_repository_name_panics_with_invariant_prefix() {
        let pid = Uuid::from_u128(1);
        let applier = applier_for(pid);
        let mut s = baseline_exclusion_spec("CVE-X");
        s.scope = ScopeSpec::Repository(RepositoryScope {
            repository: "ghost-repo".into(),
        });
        let env = exclusion_envelope(vec![s]);
        let _ = applier.diff(&env, Some(&vec![]));
    }

    // ===================================================================
    // Helpers — direct coverage
    // ===================================================================

    #[test]
    fn parse_humantime_secs_round_trips_typical_strings() {
        assert_eq!(parse_humantime_secs("1h"), 3600);
        assert_eq!(parse_humantime_secs("24h"), 24 * 3600);
        assert_eq!(parse_humantime_secs("7d"), 7 * 24 * 3600);
        assert_eq!(parse_humantime_secs("30s"), 30);
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
    fn optional_dt_eq_treats_two_nones_as_equal() {
        assert!(optional_dt_eq(None, None));
    }

    #[test]
    fn optional_dt_eq_treats_some_vs_none_as_distinct() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        assert!(!optional_dt_eq(Some(dt), None));
        assert!(!optional_dt_eq(None, Some(dt)));
    }

    #[test]
    fn optional_dt_eq_compares_some_instants() {
        let a = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let b = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let c = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 1).unwrap();
        assert!(optional_dt_eq(Some(a), Some(b)));
        assert!(!optional_dt_eq(Some(a), Some(c)));
    }

    #[test]
    fn parse_threshold_round_trips_all_variants() {
        assert_eq!(parse_threshold("critical"), SeverityThreshold::Critical);
        assert_eq!(parse_threshold("high"), SeverityThreshold::High);
        assert_eq!(parse_threshold("medium"), SeverityThreshold::Medium);
        assert_eq!(parse_threshold("low"), SeverityThreshold::Low);
    }

    #[test]
    fn build_config_snapshot_carries_every_field_under_snake_case_keys() {
        let snap = build_config_snapshot(
            "p",
            &PolicyScope::Global,
            SeverityThreshold::Low,
            60,
            true,
            &ProvenanceMode::Required,
            &["cosign".to_string()],
            &[SignerIdentityPattern::new("iss", "san").expect("valid pattern")],
            Some(120),
            &serde_json::json!({"x": 1}),
            &["trivy".to_string(), "osv".to_string()],
            48,
        );
        for key in [
            "name",
            "scope",
            "severity_threshold",
            "quarantine_duration_secs",
            "require_approval",
            "provenance_mode",
            "provenance_backends",
            "provenance_identities",
            "max_artifact_age_secs",
            "license_policy",
            "scan_backends",
            "rescan_interval_hours",
        ] {
            assert!(snap.get(key).is_some(), "missing key {key}");
        }
        // scan_backends preserves order.
        assert_eq!(snap["scan_backends"], serde_json::json!(["trivy", "osv"]));
        // rescan_interval_hours surfaces as the
        // supplied integer.
        assert_eq!(snap["rescan_interval_hours"], serde_json::json!(48));
        // The provenance trio under snake_case keys.
        assert_eq!(snap["provenance_mode"], "required");
        assert_eq!(snap["provenance_backends"], serde_json::json!(["cosign"]));
        assert_eq!(
            snap["provenance_identities"],
            serde_json::json!([{"issuer": "iss", "san": "san"}])
        );
    }
}
