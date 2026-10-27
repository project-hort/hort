//! The scan-policy **fold**: `events -> projection`, pure.
//!
//! [`ScanPolicyProjection`] is a read model derived from the per-policy
//! event stream (`StreamCategory::Policy`), and ADR 0002 makes the stream
//! the source of truth. Until this module existed that was a claim nothing
//! could cash: the projection could only ever be built *forward* from a
//! command, so a projection that disagreed with its stream had no way back
//! — and `PolicyUseCase` passes the projection's `stream_version` as the
//! next append's [`ExpectedVersion::Exact`], which turns one disagreement
//! into a permanent refusal of every later write.
//!
//! Everything here is pure: no I/O, no clock, no port. The only inputs are
//! the persisted events.
//!
//! # One spelling per field
//!
//! A policy field crosses the event boundary twice — inside
//! [`PolicyCreated::config_snapshot`] and as
//! [`PolicyUpdated::previous_value`] / `new_value` — and is read back by
//! the fold. [`policy_field_value`] and [`set_policy_field`] are the one
//! encode/decode pair for all three, so the create path, the update path
//! and the fold cannot disagree about a field's wire form. Both are
//! **closed matches over [`PolicyField`]**: a new variant is a compile
//! error here, never a field the fold silently drops (a dropped field
//! would heal a projection to a value the stream never stated).
//!
//! # What the fold refuses
//!
//! Fail-closed, because its consumer is a repair: a fold that guessed
//! would overwrite a projection with a state the stream does not support.
//! So it refuses a stream that does not open with [`PolicyCreated`], a
//! stream mixing policy ids, an event type that does not belong on a
//! policy stream, a `config_snapshot` missing a field's key, and any value
//! that does not decode. A refusal means the caller writes nothing.

use chrono::{DateTime, Utc};
use std::str::FromStr;

use serde_json::Value;
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};
use crate::events::{
    Actor, DomainEvent, ExclusionAdded, PersistedEvent, PolicyCreated, PolicyField, PolicyScope,
    PolicyUpdated,
};

use super::scan_policy::{
    CompositeVerdictMode, ExclusionProjection, NegligibleAction, ProvenanceMode, ScanEnforcement,
    ScanPolicyProjection, SeverityThreshold, SignerIdentityPattern,
};

// ---------------------------------------------------------------------------
// The field order
// ---------------------------------------------------------------------------

/// Every [`PolicyField`], in the canonical diff order — the order
/// [`diff_policy_fields`] emits `PolicyUpdated` events in, and the order
/// the `config_snapshot` object is built in.
///
/// Spelled as a **successor chain through a closed match** rather than as
/// an array: a new `PolicyField` variant has no arm here and so fails to
/// compile until it is given a place in the order. An array would have
/// accepted the new variant silently and simply never visited it.
const fn next_policy_field(field: &PolicyField) -> Option<PolicyField> {
    match field {
        PolicyField::Name => Some(PolicyField::Scope),
        PolicyField::Scope => Some(PolicyField::SeverityThreshold),
        PolicyField::SeverityThreshold => Some(PolicyField::QuarantineDuration),
        PolicyField::QuarantineDuration => Some(PolicyField::RequireApproval),
        PolicyField::RequireApproval => Some(PolicyField::ProvenanceMode),
        PolicyField::ProvenanceMode => Some(PolicyField::ProvenanceBackends),
        PolicyField::ProvenanceBackends => Some(PolicyField::ProvenanceIdentities),
        PolicyField::ProvenanceIdentities => Some(PolicyField::MaxArtifactAge),
        PolicyField::MaxArtifactAge => Some(PolicyField::LicensePolicy),
        PolicyField::LicensePolicy => Some(PolicyField::ScanBackends),
        PolicyField::ScanBackends => Some(PolicyField::RescanIntervalHours),
        PolicyField::RescanIntervalHours => Some(PolicyField::NegligibleAction),
        PolicyField::NegligibleAction => Some(PolicyField::Enforcement),
        PolicyField::Enforcement => Some(PolicyField::CompositeVerdictMode),
        PolicyField::CompositeVerdictMode => None,
    }
}

/// The number of fields [`policy_fields`] visits. Asserted against the
/// walk in this module's tests, so a successor arm that short-circuits the
/// chain (`NewField => None` beside an existing terminal) is caught.
pub const POLICY_FIELD_COUNT: usize = 15;

/// Walk every [`PolicyField`] in the canonical diff order.
pub fn policy_fields() -> impl Iterator<Item = PolicyField> {
    std::iter::successors(Some(PolicyField::Name), next_policy_field)
}

/// The `PolicyCreated.config_snapshot` object key for a field.
///
/// Closed match: a new [`PolicyField`] variant is a compile error until it
/// is given a key. The keys are the `ScanPolicyProjection` field names, so
/// an operator reading a raw event sees the field it set.
const fn snapshot_key(field: &PolicyField) -> &'static str {
    match field {
        PolicyField::Name => "name",
        PolicyField::Scope => "scope",
        PolicyField::SeverityThreshold => "severity_threshold",
        PolicyField::QuarantineDuration => "quarantine_duration_secs",
        PolicyField::RequireApproval => "require_approval",
        PolicyField::ProvenanceMode => "provenance_mode",
        PolicyField::ProvenanceBackends => "provenance_backends",
        PolicyField::ProvenanceIdentities => "provenance_identities",
        PolicyField::MaxArtifactAge => "max_artifact_age_secs",
        PolicyField::LicensePolicy => "license_policy",
        PolicyField::ScanBackends => "scan_backends",
        PolicyField::RescanIntervalHours => "rescan_interval_hours",
        PolicyField::NegligibleAction => "negligible_action",
        PolicyField::Enforcement => "enforcement",
        PolicyField::CompositeVerdictMode => "composite_verdict_mode",
    }
}

// ---------------------------------------------------------------------------
// The one encode / decode pair
// ---------------------------------------------------------------------------

/// Encode one policy field as the JSON the event carries.
///
/// The single encoder for `PolicyUpdated.previous_value` / `new_value`
/// **and** for the `config_snapshot` entry of the same field — so the two
/// surfaces cannot drift, and [`set_policy_field`] is the exact inverse of
/// both.
///
/// Closed match over [`PolicyField`]: a new variant is a compile error.
#[must_use]
pub fn policy_field_value(policy: &ScanPolicyProjection, field: &PolicyField) -> Value {
    // The lowercase-wire enums (`ProvenanceMode`, `NegligibleAction`,
    // `ScanEnforcement`, `CompositeVerdictMode`) go out through `Display`,
    // not serde: their `Serialize` derive writes the PascalCase variant
    // name, and the wire form every other surface (YAML, SQL) uses is the
    // lowercase one. `SeverityThreshold` is the deliberate odd one out —
    // it has always crossed this boundary through serde, so its event
    // payload is PascalCase and must stay that way to keep reading the
    // events already persisted.
    match field {
        PolicyField::Name => Value::String(policy.name.clone()),
        PolicyField::Scope => {
            serde_json::to_value(&policy.scope).expect("PolicyScope serialises to JSON")
        }
        PolicyField::SeverityThreshold => serde_json::to_value(policy.severity_threshold)
            .expect("SeverityThreshold serialises to JSON"),
        PolicyField::QuarantineDuration => Value::from(policy.quarantine_duration_secs),
        PolicyField::RequireApproval => Value::Bool(policy.require_approval),
        PolicyField::ProvenanceMode => Value::String(policy.provenance_mode.to_string()),
        PolicyField::ProvenanceBackends => serde_json::to_value(&policy.provenance_backends)
            .expect("INVARIANT: Vec<String> serialises to JSON"),
        PolicyField::ProvenanceIdentities => serde_json::to_value(&policy.provenance_identities)
            .expect("INVARIANT: SignerIdentityPattern serialises to JSON"),
        PolicyField::MaxArtifactAge => match policy.max_artifact_age_secs {
            Some(secs) => Value::from(secs),
            None => Value::Null,
        },
        PolicyField::LicensePolicy => policy.license_policy.clone(),
        PolicyField::ScanBackends => serde_json::to_value(&policy.scan_backends)
            .expect("INVARIANT: Vec<String> serialises to JSON"),
        PolicyField::RescanIntervalHours => Value::from(policy.rescan_interval_hours),
        PolicyField::NegligibleAction => Value::String(policy.negligible_action.to_string()),
        PolicyField::Enforcement => Value::String(policy.enforcement.to_string()),
        PolicyField::CompositeVerdictMode => {
            Value::String(policy.composite_verdict_mode.to_string())
        }
    }
}

/// Decode one policy field from the JSON an event carries and assign it.
///
/// The exact inverse of [`policy_field_value`], and the **only** place
/// that says "this `PolicyField` means that projection field". The
/// forward update path, the create-snapshot replay and the stream fold all
/// come through here, which is what makes the forward and backward
/// mappings one mapping.
///
/// Closed match over [`PolicyField`]: a new variant is a compile error.
/// A value that does not decode is [`DomainError::Validation`] — the
/// caller must write nothing.
pub fn set_policy_field(
    policy: &mut ScanPolicyProjection,
    field: &PolicyField,
    value: &Value,
) -> DomainResult<()> {
    match field {
        PolicyField::Name => policy.name = decode_string(field, value)?,
        PolicyField::Scope => policy.scope = decode_serde::<PolicyScope>(field, value)?,
        PolicyField::SeverityThreshold => {
            policy.severity_threshold = decode_serde::<SeverityThreshold>(field, value)?;
        }
        PolicyField::QuarantineDuration => {
            policy.quarantine_duration_secs = decode_i64(field, value)?;
        }
        PolicyField::RequireApproval => {
            policy.require_approval = value
                .as_bool()
                .ok_or_else(|| decode_error(field, value, "a JSON boolean"))?;
        }
        PolicyField::ProvenanceMode => {
            policy.provenance_mode = decode_wire::<ProvenanceMode>(field, value)?;
        }
        PolicyField::ProvenanceBackends => {
            policy.provenance_backends = decode_serde::<Vec<String>>(field, value)?;
        }
        PolicyField::ProvenanceIdentities => {
            policy.provenance_identities =
                decode_serde::<Vec<SignerIdentityPattern>>(field, value)?;
        }
        PolicyField::MaxArtifactAge => {
            policy.max_artifact_age_secs = if value.is_null() {
                None
            } else {
                Some(decode_i64(field, value)?)
            };
        }
        PolicyField::LicensePolicy => policy.license_policy = value.clone(),
        PolicyField::ScanBackends => {
            policy.scan_backends = decode_serde::<Vec<String>>(field, value)?;
        }
        PolicyField::RescanIntervalHours => {
            let hours = decode_i64(field, value)?;
            policy.rescan_interval_hours = i32::try_from(hours)
                .map_err(|_| decode_error(field, value, "a JSON integer in i32 range"))?;
        }
        PolicyField::NegligibleAction => {
            policy.negligible_action = decode_wire::<NegligibleAction>(field, value)?;
        }
        PolicyField::Enforcement => {
            policy.enforcement = decode_wire::<ScanEnforcement>(field, value)?;
        }
        PolicyField::CompositeVerdictMode => {
            policy.composite_verdict_mode = decode_wire::<CompositeVerdictMode>(field, value)?;
        }
    }
    Ok(())
}

/// Apply one [`PolicyUpdated`] to a projection. Thin by design: the field
/// mapping is [`set_policy_field`]'s, so this is the whole of "a
/// `PolicyUpdated` moves the projection".
pub fn apply_policy_updated(
    policy: &mut ScanPolicyProjection,
    update: &PolicyUpdated,
) -> DomainResult<()> {
    set_policy_field(policy, &update.field, &update.new_value)
}

// ---------------------------------------------------------------------------
// The forward diff
// ---------------------------------------------------------------------------

/// Emit one [`PolicyUpdated`] per field on which `desired` differs from
/// `current`, in [`policy_fields`] order.
///
/// Both sides are encoded through [`policy_field_value`], so "changed"
/// means "changed as the event would record it" — a field whose two
/// values encode identically produces no event, which is the
/// same-value-is-a-no-op contract the update path has always had.
///
/// This is the forward half of the fold: feeding the result back through
/// [`apply_policy_updated`] reproduces `desired`, because both directions
/// are the same per-field mapping.
#[must_use]
pub fn diff_policy_fields(
    policy_id: Uuid,
    current: &ScanPolicyProjection,
    desired: &ScanPolicyProjection,
) -> Vec<PolicyUpdated> {
    policy_fields()
        .filter_map(|field| {
            let previous_value = policy_field_value(current, &field);
            let new_value = policy_field_value(desired, &field);
            (previous_value != new_value).then_some(PolicyUpdated {
                policy_id,
                field,
                previous_value,
                new_value,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The create snapshot
// ---------------------------------------------------------------------------

/// Encode a policy's configuration as the [`PolicyCreated::config_snapshot`]
/// payload.
///
/// One encoder for every writer of a `PolicyCreated` (the imperative
/// create path and the gitops applier both used to carry their own copy,
/// kept "in lockstep" by a comment), and the exact inverse of
/// [`replay_policy_created`].
#[must_use]
pub fn policy_config_snapshot(policy: &ScanPolicyProjection) -> Value {
    Value::Object(
        policy_fields()
            .map(|field| {
                (
                    snapshot_key(&field).to_owned(),
                    policy_field_value(policy, &field),
                )
            })
            .collect(),
    )
}

/// Rebuild the projection a [`PolicyCreated`] created, from its
/// `config_snapshot`.
///
/// `created_at` is the store's `stored_at` for the event: the policy
/// events carry no timestamp of their own, so the stream's own record of
/// when the event landed is the only evidence a pure fold has. A healed
/// row's `created_at` is therefore the event's timestamp rather than the
/// `Utc::now()` the original use-case call used — the same instant to
/// within the append.
///
/// Refuses a snapshot missing any field's key, rather than defaulting it:
/// a projection healed to a default nobody declared is worse than a
/// refusal the operator can read. A policy created before a field existed
/// is exactly this case, and names the missing key.
fn replay_policy_created(
    created: &PolicyCreated,
    created_at: DateTime<Utc>,
) -> DomainResult<ScanPolicyProjection> {
    // Placeholders for the config fields only: every one is overwritten
    // from the snapshot below, and a snapshot that cannot supply one is a
    // refusal — so none of these values can reach a healed row. Written as
    // a struct literal on purpose: a new `ScanPolicyProjection` field is a
    // compile error here until the fold knows how to derive it.
    let mut policy = ScanPolicyProjection {
        policy_id: created.policy_id,
        name: String::new(),
        scope: PolicyScope::Global,
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 0,
        require_approval: false,
        provenance_mode: ProvenanceMode::Off,
        provenance_backends: Vec::new(),
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: Value::Null,
        archived: false,
        scan_backends: Vec::new(),
        rescan_interval_hours: 0,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        composite_verdict_mode: CompositeVerdictMode::Observed,
        stream_version: 0,
        created_at,
        updated_at: created_at,
    };

    for field in policy_fields() {
        let key = snapshot_key(&field);
        let value = created.config_snapshot.get(key).ok_or_else(|| {
            DomainError::Validation(format!(
                "PolicyCreated.config_snapshot for policy {} has no '{key}' entry, \
                 so the stream cannot state the policy's {field:?} — refusing to \
                 derive a projection that would invent one",
                created.policy_id
            ))
        })?;
        set_policy_field(&mut policy, &field, value)?;
    }

    // `name` and `scope` are carried twice: as event fields and inside the
    // snapshot. Both writers set them from one source, so a disagreement
    // means the payload was not produced by this system's encoder — and the
    // fold must not pick a winner between two claims about the same policy.
    if policy.name != created.name {
        return Err(DomainError::Invariant(format!(
            "PolicyCreated for policy {} disagrees with its own config_snapshot \
             about the policy name ('{}' vs '{}')",
            created.policy_id, created.name, policy.name
        )));
    }
    if policy.scope != created.scope {
        return Err(DomainError::Invariant(format!(
            "PolicyCreated for policy {} disagrees with its own config_snapshot \
             about the policy scope",
            created.policy_id
        )));
    }

    Ok(policy)
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/// Everything one policy stream states: the policy projection and the
/// exclusion rows attached to it.
///
/// The two are separate tables but one stream — an `ExclusionAdded` takes
/// a stream position like any other event, so it moves the policy's
/// `stream_version` even though it changes no policy field. A fold that
/// ignored the exclusion events would derive a version short of the
/// stream's and the repair would conflict again immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPolicyReplay {
    pub policy: ScanPolicyProjection,
    /// The exclusions still attached, in the order they were added.
    pub exclusions: Vec<ExclusionProjection>,
}

/// Fold a policy event stream into the state it states. Pure.
///
/// `events` must be the whole stream from position 0, in stream order —
/// what `EventStore::read_stream(.., ReadFrom::Start, u64::MAX)` returns.
/// `stream_version` on the result is the **last event's own
/// `stream_position`**, not a count: it is the value the next append must
/// carry as [`ExpectedVersion::Exact`](crate::ports::event_store::ExpectedVersion::Exact),
/// so it is read off the store's record rather than re-derived.
pub fn fold_scan_policy(events: &[PersistedEvent]) -> DomainResult<ScanPolicyReplay> {
    let (first, rest) = events.split_first().ok_or_else(|| DomainError::NotFound {
        entity: "ScanPolicy",
        id: "<empty policy stream>".to_owned(),
    })?;

    let DomainEvent::PolicyCreated(created) = &first.event else {
        return Err(DomainError::Invariant(format!(
            "policy stream must open with PolicyCreated, got {}",
            first.event.event_type()
        )));
    };
    let mut replay = ScanPolicyReplay {
        policy: replay_policy_created(created, first.stored_at)?,
        exclusions: Vec::new(),
    };

    for persisted in rest {
        apply_policy_event(&mut replay, &persisted.event, &persisted.actor)
            .map_err(|e| at_position(e, persisted.stream_position))?;
        replay.policy.updated_at = persisted.stored_at;
    }

    // The tail position is the store's, not a count: a fold that counted
    // would be right only while every stream started at 0 with no gaps,
    // and it is the append's expected version that has to be right.
    replay.policy.stream_version = events
        .last()
        .expect("the stream is non-empty — `split_first` succeeded above")
        .stream_position;

    Ok(replay)
}

/// Apply one post-`Created` policy event to a replay, as a reader of the
/// stream would. Pure.
///
/// `actor` is the event's **envelope** actor, not a payload field:
/// `ExclusionProjection::added_by_actor_id` is envelope-sourced, so a
/// caller folding an event it is about to append passes the actor it is
/// about to append it under.
///
/// The target policy is `replay.policy.policy_id`; an event naming a
/// different policy is refused rather than applied, because a stream that
/// mixes aggregates is not a stream this fold can speak for.
pub fn apply_policy_event(
    replay: &mut ScanPolicyReplay,
    event: &DomainEvent,
    actor: &Actor,
) -> DomainResult<()> {
    let policy_id = replay.policy.policy_id;
    match event {
        DomainEvent::PolicyUpdated(update) => {
            require_same_policy(policy_id, update.policy_id, event)?;
            apply_policy_updated(&mut replay.policy, update)?;
        }
        DomainEvent::PolicyArchived(archived) => {
            require_same_policy(policy_id, archived.policy_id, event)?;
            replay.policy.archived = true;
        }
        DomainEvent::PolicyReactivated(reactivated) => {
            require_same_policy(policy_id, reactivated.policy_id, event)?;
            replay.policy.archived = false;
        }
        DomainEvent::ExclusionAdded(added) => {
            require_same_policy(policy_id, added.policy_id, event)?;
            replay.exclusions.push(exclusion_projection(added, actor));
        }
        DomainEvent::ExclusionRemoved(removed) => {
            require_same_policy(policy_id, removed.policy_id, event)?;
            replay
                .exclusions
                .retain(|e| e.exclusion_id != removed.exclusion_id);
        }
        DomainEvent::PolicyCreated(_) => {
            return Err(DomainError::Invariant(format!(
                "policy stream for {policy_id} has a second PolicyCreated"
            )));
        }
        other => {
            // Fail closed on an event type this fold does not model. Only
            // `PolicyUseCase` writes `StreamId::policy`, so anything else
            // here means the stream is not the one the caller thinks it is
            // — deriving a projection from a stream we cannot read in full
            // would heal the row to a state missing whatever that event
            // said.
            return Err(DomainError::Invariant(format!(
                "{} does not belong on policy stream {policy_id}; no projection \
                 is derived from a stream this fold cannot read in full",
                other.event_type()
            )));
        }
    }
    Ok(())
}

/// Fold a batch that is **about to be appended** onto a replay, producing
/// the state the stream will state once it lands.
///
/// This is the forward half of the fold, and the reason the write path has
/// one field mapping rather than two: a mutation builds its events and
/// then folds them, instead of maintaining the event and the projection
/// edit side by side. `new_stream_version` is the append's
/// `AppendResult.stream_position`; `appended_at` is the instant recorded
/// as `updated_at` (the store's `stored_at` is not known until the events
/// are read back).
pub fn apply_policy_batch(
    replay: &mut ScanPolicyReplay,
    events: &[DomainEvent],
    actor: &Actor,
    appended_at: DateTime<Utc>,
    new_stream_version: u64,
) -> DomainResult<()> {
    for event in events {
        apply_policy_event(replay, event, actor)?;
    }
    replay.policy.stream_version = new_stream_version;
    replay.policy.updated_at = appended_at;
    Ok(())
}

fn require_same_policy(
    stream_policy_id: Uuid,
    event_policy_id: Uuid,
    event: &DomainEvent,
) -> DomainResult<()> {
    if stream_policy_id == event_policy_id {
        return Ok(());
    }
    Err(DomainError::Invariant(format!(
        "policy stream for {stream_policy_id} carries a {} for {event_policy_id}",
        event.event_type(),
    )))
}

/// Annotate a fold refusal with the stream position it was raised at, so
/// an operator reading the log knows which event the repair stopped on.
fn at_position(err: DomainError, position: u64) -> DomainError {
    match err {
        DomainError::Invariant(msg) => {
            DomainError::Invariant(format!("{msg} (stream position {position})"))
        }
        DomainError::Validation(msg) => {
            DomainError::Validation(format!("{msg} (stream position {position})"))
        }
        other => other,
    }
}
/// The exclusion row an [`ExclusionAdded`] materialises.
///
/// `added_by_actor_id` is **envelope**-sourced: the payload carries no
/// actor, and the projection column records the `Actor::Api` user id (NULL
/// for system / timer / gitops envelopes). The fold reads it from the same
/// place the write path does — and the write path calls this, so the row
/// it inserts and the row a later fold derives are one mapping.
#[must_use]
pub fn exclusion_projection(added: &ExclusionAdded, actor: &Actor) -> ExclusionProjection {
    ExclusionProjection {
        exclusion_id: added.exclusion_id,
        policy_id: added.policy_id,
        cve_id: added.cve_id.clone(),
        package_pattern: added.package_pattern.clone(),
        scope: added.scope.clone(),
        reason: added.reason.clone(),
        added_by_actor_id: match actor {
            Actor::Api(api) => Some(api.user_id),
            _ => None,
        },
        expires_at: added.expires_at,
    }
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn decode_error(field: &PolicyField, value: &Value, expected: &str) -> DomainError {
    DomainError::Validation(format!(
        "policy field {field:?} expects {expected}, got {value}"
    ))
}

fn decode_string(field: &PolicyField, value: &Value) -> DomainResult<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| decode_error(field, value, "a JSON string"))
}

fn decode_i64(field: &PolicyField, value: &Value) -> DomainResult<i64> {
    value
        .as_i64()
        .ok_or_else(|| decode_error(field, value, "a JSON integer"))
}

fn decode_serde<T: serde::de::DeserializeOwned>(
    field: &PolicyField,
    value: &Value,
) -> DomainResult<T> {
    serde_json::from_value(value.clone()).map_err(|e| {
        DomainError::Validation(format!(
            "policy field {field:?} does not decode ({e}): {value}"
        ))
    })
}

/// Decode one of the lowercase-wire enums through its `FromStr` — the
/// spelling `Display` wrote in [`policy_field_value`].
fn decode_wire<T: FromStr<Err = DomainError>>(
    field: &PolicyField,
    value: &Value,
) -> DomainResult<T> {
    let s = decode_string(field, value)?;
    T::from_str(&s)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::events::{ApiActor, ExclusionRemoved, PolicyArchived, PolicyReactivated, StreamId};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("in-range timestamp")
    }

    fn sample_policy(policy_id: Uuid) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id,
            name: "prod-default".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_owned()],
            provenance_identities: vec![SignerIdentityPattern::new(
                "https://token.actions.githubusercontent.com",
                "repo:acme/*",
            )
            .expect("valid pattern")],
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::json!({ "denied": ["GPL-3.0"] }),
            archived: false,
            scan_backends: vec!["trivy".to_owned()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Warn,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: ts(1_000),
            updated_at: ts(1_000),
        }
    }

    fn api_actor() -> Actor {
        Actor::Api(ApiActor {
            user_id: Uuid::from_u128(0xA11CE),
        })
    }

    fn persisted(policy_id: Uuid, position: u64, event: DomainEvent, at: i64) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::policy(policy_id),
            stream_position: position,
            global_position: position,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: api_actor(),
            event_version: 1,
            stored_at: ts(at),
        }
    }

    /// The `PolicyCreated` the create path would write for `policy`.
    fn created_event(policy: &ScanPolicyProjection) -> DomainEvent {
        DomainEvent::PolicyCreated(PolicyCreated {
            policy_id: policy.policy_id,
            name: policy.name.clone(),
            scope: policy.scope.clone(),
            config_snapshot: policy_config_snapshot(policy),
        })
    }

    /// One field set to a value that differs from [`sample_policy`]'s, for
    /// every field — the per-field round-trip corpus.
    ///
    /// Built through a **closed match** so a new [`PolicyField`] variant
    /// fails to compile until the corpus covers it: a round-trip property
    /// that silently skipped a field would be exactly the gap the fold
    /// exists to close.
    fn mutate_field(policy: &mut ScanPolicyProjection, field: &PolicyField) {
        match field {
            PolicyField::Name => policy.name = "renamed".into(),
            PolicyField::Scope => policy.scope = PolicyScope::Repository(Uuid::from_u128(7)),
            PolicyField::SeverityThreshold => {
                policy.severity_threshold = SeverityThreshold::Critical;
            }
            PolicyField::QuarantineDuration => policy.quarantine_duration_secs = 7_200,
            PolicyField::RequireApproval => policy.require_approval = false,
            PolicyField::ProvenanceMode => policy.provenance_mode = ProvenanceMode::Required,
            PolicyField::ProvenanceBackends => {
                policy.provenance_backends = vec!["cosign".to_owned(), "cosign-key".to_owned()];
            }
            PolicyField::ProvenanceIdentities => {
                policy.provenance_identities =
                    vec![
                        SignerIdentityPattern::new("https://accounts.google.com", "ci@acme.test")
                            .expect("valid pattern"),
                    ];
            }
            PolicyField::MaxArtifactAge => policy.max_artifact_age_secs = None,
            PolicyField::LicensePolicy => {
                policy.license_policy = serde_json::json!({ "allowed": ["MIT"] });
            }
            PolicyField::ScanBackends => policy.scan_backends = Vec::new(),
            PolicyField::RescanIntervalHours => policy.rescan_interval_hours = 0,
            PolicyField::NegligibleAction => policy.negligible_action = NegligibleAction::Block,
            PolicyField::Enforcement => policy.enforcement = ScanEnforcement::Record,
            PolicyField::CompositeVerdictMode => {
                policy.composite_verdict_mode = CompositeVerdictMode::Promoted;
            }
        }
    }

    // -- the field order -----------------------------------------------------

    #[test]
    fn policy_fields_visits_every_variant_once_in_order() {
        let fields: Vec<PolicyField> = policy_fields().collect();
        assert_eq!(
            fields.len(),
            POLICY_FIELD_COUNT,
            "the successor chain short-circuits: {fields:?}"
        );
        for (i, field) in fields.iter().enumerate() {
            assert!(
                !fields[..i].contains(field),
                "{field:?} appears twice in the field order"
            );
        }
        // The order is load-bearing: the update path emits one event per
        // changed field in it, and the gitops applier's own diff is
        // asserted against the same sequence.
        assert_eq!(fields.first(), Some(&PolicyField::Name));
        assert_eq!(fields.last(), Some(&PolicyField::CompositeVerdictMode));
    }

    #[test]
    fn snapshot_keys_are_distinct() {
        let keys: Vec<&str> = policy_fields().map(|f| snapshot_key(&f)).collect();
        for (i, key) in keys.iter().enumerate() {
            assert!(
                !keys[..i].contains(key),
                "snapshot key '{key}' is used by two fields"
            );
        }
        assert_eq!(keys.len(), POLICY_FIELD_COUNT);
    }

    // -- per-field round trip ------------------------------------------------

    /// The round-trip property, **per field**: the forward path (diff →
    /// events) followed by the fold (`apply_policy_updated`) reproduces
    /// exactly what the forward path produced directly.
    #[test]
    fn every_field_round_trips_through_its_event() {
        let policy_id = Uuid::from_u128(1);
        let current = sample_policy(policy_id);
        for field in policy_fields() {
            let mut desired = current.clone();
            mutate_field(&mut desired, &field);

            let events = diff_policy_fields(policy_id, &current, &desired);
            assert_eq!(
                events.len(),
                1,
                "{field:?}: one changed field must emit exactly one event, got {events:?}"
            );
            assert_eq!(events[0].field, field);
            assert_eq!(
                events[0].previous_value,
                policy_field_value(&current, &field)
            );

            let mut folded = current.clone();
            apply_policy_updated(&mut folded, &events[0]).expect("fold applies the event");
            assert_eq!(
                folded, desired,
                "{field:?}: folding the emitted event must reproduce the desired projection"
            );
        }
    }

    #[test]
    fn an_unchanged_field_emits_no_event() {
        let policy_id = Uuid::from_u128(2);
        let policy = sample_policy(policy_id);
        assert!(diff_policy_fields(policy_id, &policy, &policy).is_empty());
    }

    #[test]
    fn a_multi_field_change_emits_events_in_field_order() {
        let policy_id = Uuid::from_u128(3);
        let current = sample_policy(policy_id);
        let mut desired = current.clone();
        mutate_field(&mut desired, &PolicyField::Enforcement);
        mutate_field(&mut desired, &PolicyField::Name);
        mutate_field(&mut desired, &PolicyField::ScanBackends);

        let events = diff_policy_fields(policy_id, &current, &desired);
        let fields: Vec<&PolicyField> = events.iter().map(|e| &e.field).collect();
        assert_eq!(
            fields,
            vec![
                &PolicyField::Name,
                &PolicyField::ScanBackends,
                &PolicyField::Enforcement
            ]
        );
    }

    // -- the config snapshot -------------------------------------------------

    #[test]
    fn config_snapshot_round_trips_every_field() {
        let policy = sample_policy(Uuid::from_u128(4));
        let created = PolicyCreated {
            policy_id: policy.policy_id,
            name: policy.name.clone(),
            scope: policy.scope.clone(),
            config_snapshot: policy_config_snapshot(&policy),
        };
        let replayed = replay_policy_created(&created, policy.created_at).expect("replays");
        assert_eq!(replayed, policy);
    }

    #[test]
    fn config_snapshot_uses_the_projection_field_names() {
        let policy = sample_policy(Uuid::from_u128(5));
        let snapshot = policy_config_snapshot(&policy);
        // The wire form is observable in persisted events, so pin the
        // spellings that are NOT simply serde of the field's type.
        assert_eq!(snapshot["name"], "prod-default");
        assert_eq!(snapshot["severity_threshold"], "High");
        assert_eq!(snapshot["provenance_mode"], "verify_if_present");
        assert_eq!(snapshot["negligible_action"], "warn");
        assert_eq!(snapshot["enforcement"], "reject");
        assert_eq!(snapshot["composite_verdict_mode"], "observed");
        assert_eq!(snapshot["quarantine_duration_secs"], 86_400);
        assert_eq!(snapshot["rescan_interval_hours"], 24);
        assert_eq!(snapshot["require_approval"], true);
        assert_eq!(
            snapshot.as_object().expect("object").len(),
            POLICY_FIELD_COUNT
        );
    }

    #[test]
    fn a_null_max_artifact_age_round_trips_as_none() {
        let mut policy = sample_policy(Uuid::from_u128(6));
        policy.max_artifact_age_secs = None;
        let snapshot = policy_config_snapshot(&policy);
        assert!(snapshot["max_artifact_age_secs"].is_null());
        let created = PolicyCreated {
            policy_id: policy.policy_id,
            name: policy.name.clone(),
            scope: policy.scope.clone(),
            config_snapshot: snapshot,
        };
        let replayed = replay_policy_created(&created, policy.created_at).expect("replays");
        assert_eq!(replayed.max_artifact_age_secs, None);
    }

    #[test]
    fn a_snapshot_missing_a_field_is_refused_naming_the_key() {
        let policy = sample_policy(Uuid::from_u128(7));
        let mut snapshot = policy_config_snapshot(&policy);
        snapshot
            .as_object_mut()
            .expect("object")
            .remove("composite_verdict_mode");
        let created = PolicyCreated {
            policy_id: policy.policy_id,
            name: policy.name.clone(),
            scope: policy.scope.clone(),
            config_snapshot: snapshot,
        };
        let err = replay_policy_created(&created, policy.created_at)
            .expect_err("an incomplete snapshot must refuse");
        match err {
            DomainError::Validation(msg) => assert!(
                msg.contains("composite_verdict_mode"),
                "the refusal must name the missing key: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn a_snapshot_disagreeing_with_the_event_name_is_refused() {
        let policy = sample_policy(Uuid::from_u128(8));
        let created = PolicyCreated {
            policy_id: policy.policy_id,
            name: "something-else".into(),
            scope: policy.scope.clone(),
            config_snapshot: policy_config_snapshot(&policy),
        };
        let err = replay_policy_created(&created, policy.created_at)
            .expect_err("a self-contradicting event must refuse");
        assert!(matches!(err, DomainError::Invariant(_)), "got {err:?}");
    }

    #[test]
    fn a_snapshot_disagreeing_with_the_event_scope_is_refused() {
        let policy = sample_policy(Uuid::from_u128(9));
        let created = PolicyCreated {
            policy_id: policy.policy_id,
            name: policy.name.clone(),
            scope: PolicyScope::Repository(Uuid::from_u128(99)),
            config_snapshot: policy_config_snapshot(&policy),
        };
        let err = replay_policy_created(&created, policy.created_at)
            .expect_err("a self-contradicting event must refuse");
        assert!(matches!(err, DomainError::Invariant(_)), "got {err:?}");
    }

    // -- decode refusals -----------------------------------------------------

    #[test]
    fn a_wrongly_typed_field_value_is_refused_per_field() {
        let policy_id = Uuid::from_u128(10);
        for field in policy_fields() {
            // `LicensePolicy` is raw JSON by contract — any value is a
            // legitimate license policy document, so there is no
            // wrongly-typed value to refuse.
            if field == PolicyField::LicensePolicy {
                continue;
            }
            let mut policy = sample_policy(policy_id);
            let err = set_policy_field(&mut policy, &field, &serde_json::json!({ "no": "pe" }))
                .expect_err("an object is not a valid value for any typed field");
            assert!(
                matches!(err, DomainError::Validation(_)),
                "{field:?}: expected Validation, got {err:?}"
            );
        }
    }

    #[test]
    fn an_unknown_wire_string_is_refused() {
        let mut policy = sample_policy(Uuid::from_u128(11));
        let err = set_policy_field(
            &mut policy,
            &PolicyField::Enforcement,
            &serde_json::json!("enforced"),
        )
        .expect_err("'enforced' is not a ScanEnforcement");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    /// The wire decode inherits `FromStr`'s case-insensitivity, which is
    /// the same leniency `PgPolicyProjectionRepository` reads its columns
    /// with. Pinned so the fold and the row decode cannot answer
    /// differently about one spelling.
    #[test]
    fn the_wire_decode_is_case_insensitive_like_the_column_decode() {
        let mut policy = sample_policy(Uuid::from_u128(13));
        set_policy_field(
            &mut policy,
            &PolicyField::Enforcement,
            &serde_json::json!("RECORD"),
        )
        .expect("FromStr lowercases before matching");
        assert_eq!(policy.enforcement, ScanEnforcement::Record);
    }

    #[test]
    fn an_out_of_range_rescan_interval_is_refused() {
        let mut policy = sample_policy(Uuid::from_u128(12));
        let err = set_policy_field(
            &mut policy,
            &PolicyField::RescanIntervalHours,
            &serde_json::json!(i64::from(i32::MAX) + 1),
        )
        .expect_err("i32 range is the column's range");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    // -- the stream fold -----------------------------------------------------

    #[test]
    fn folding_a_create_only_stream_yields_the_created_projection() {
        let policy = sample_policy(Uuid::from_u128(20));
        let stream = vec![persisted(
            policy.policy_id,
            0,
            created_event(&policy),
            5_000,
        )];
        let replay = fold_scan_policy(&stream).expect("folds");
        assert_eq!(replay.policy.stream_version, 0);
        assert_eq!(replay.policy.created_at, ts(5_000));
        assert_eq!(replay.policy.updated_at, ts(5_000));
        assert!(replay.exclusions.is_empty());
        let mut expected = policy.clone();
        expected.created_at = ts(5_000);
        expected.updated_at = ts(5_000);
        assert_eq!(replay.policy, expected);
    }

    #[test]
    fn the_fold_applies_updates_archival_and_reactivation() {
        let policy = sample_policy(Uuid::from_u128(21));
        let policy_id = policy.policy_id;
        let mut desired = policy.clone();
        mutate_field(&mut desired, &PolicyField::SeverityThreshold);
        let update = diff_policy_fields(policy_id, &policy, &desired)
            .pop()
            .expect("one event");

        let stream = vec![
            persisted(policy_id, 0, created_event(&policy), 1_000),
            persisted(policy_id, 1, DomainEvent::PolicyUpdated(update), 2_000),
            persisted(
                policy_id,
                2,
                DomainEvent::PolicyArchived(PolicyArchived { policy_id }),
                3_000,
            ),
            persisted(
                policy_id,
                3,
                DomainEvent::PolicyReactivated(PolicyReactivated { policy_id }),
                4_000,
            ),
        ];

        let replay = fold_scan_policy(&stream).expect("folds");
        assert_eq!(
            replay.policy.severity_threshold,
            SeverityThreshold::Critical
        );
        assert!(!replay.policy.archived, "reactivation clears the flag");
        assert_eq!(replay.policy.stream_version, 3);
        assert_eq!(replay.policy.created_at, ts(1_000));
        assert_eq!(replay.policy.updated_at, ts(4_000));
    }

    #[test]
    fn an_archived_stream_folds_to_an_archived_projection() {
        let policy = sample_policy(Uuid::from_u128(22));
        let policy_id = policy.policy_id;
        let stream = vec![
            persisted(policy_id, 0, created_event(&policy), 1_000),
            persisted(
                policy_id,
                1,
                DomainEvent::PolicyArchived(PolicyArchived { policy_id }),
                2_000,
            ),
        ];
        let replay = fold_scan_policy(&stream).expect("folds");
        assert!(replay.policy.archived);
        assert_eq!(replay.policy.stream_version, 1);
    }

    /// An exclusion event changes no policy field but **does** take a
    /// stream position, so it moves `stream_version` — the whole reason
    /// the exclusion events are in this fold.
    #[test]
    fn exclusion_events_move_the_stream_version_and_the_exclusion_set() {
        let policy = sample_policy(Uuid::from_u128(23));
        let policy_id = policy.policy_id;
        let kept = Uuid::from_u128(0x100);
        let dropped = Uuid::from_u128(0x200);

        let add = |exclusion_id: Uuid, cve: &str| {
            DomainEvent::ExclusionAdded(ExclusionAdded {
                policy_id,
                exclusion_id,
                cve_id: cve.to_owned(),
                package_pattern: Some("acme-*".to_owned()),
                scope: PolicyScope::Global,
                reason: "triaged as not reachable".to_owned(),
                expires_at: None,
            })
        };

        let stream = vec![
            persisted(policy_id, 0, created_event(&policy), 1_000),
            persisted(policy_id, 1, add(kept, "CVE-2026-0001"), 2_000),
            persisted(policy_id, 2, add(dropped, "CVE-2026-0002"), 3_000),
            persisted(
                policy_id,
                3,
                DomainEvent::ExclusionRemoved(ExclusionRemoved {
                    policy_id,
                    exclusion_id: dropped,
                    reason: "re-triaged".to_owned(),
                }),
                4_000,
            ),
        ];

        let replay = fold_scan_policy(&stream).expect("folds");
        assert_eq!(
            replay.policy.stream_version, 3,
            "the exclusion events occupy stream positions"
        );
        assert_eq!(replay.exclusions.len(), 1);
        assert_eq!(replay.exclusions[0].exclusion_id, kept);
        assert_eq!(replay.exclusions[0].cve_id, "CVE-2026-0001");
        // Envelope-sourced attribution: the payload carries no actor.
        assert_eq!(
            replay.exclusions[0].added_by_actor_id,
            Some(Uuid::from_u128(0xA11CE))
        );
        // No policy field moved.
        assert_eq!(replay.policy.severity_threshold, policy.severity_threshold);
    }

    #[test]
    fn a_non_api_envelope_leaves_the_exclusion_author_null() {
        let policy = sample_policy(Uuid::from_u128(24));
        let policy_id = policy.policy_id;
        let mut gitops = persisted(
            policy_id,
            1,
            DomainEvent::ExclusionAdded(ExclusionAdded {
                policy_id,
                exclusion_id: Uuid::from_u128(0x300),
                cve_id: "CVE-2026-0003".to_owned(),
                package_pattern: None,
                scope: PolicyScope::Global,
                reason: "declared".to_owned(),
                expires_at: None,
            }),
            2_000,
        );
        gitops.actor = Actor::GitOps(crate::events::GitOpsActor {
            source_file: "<test>".to_owned(),
            spec_digest: [0u8; 32],
            applied_at: ts(2_000),
        });

        let stream = vec![
            persisted(policy_id, 0, created_event(&policy), 1_000),
            gitops,
        ];
        let replay = fold_scan_policy(&stream).expect("folds");
        assert_eq!(replay.exclusions[0].added_by_actor_id, None);
    }

    /// The version is the store's own `stream_position`, not a count of
    /// events — the append's expected version is what has to be right.
    #[test]
    fn the_stream_version_is_the_tail_position_not_a_count() {
        let policy = sample_policy(Uuid::from_u128(25));
        let policy_id = policy.policy_id;
        let mut tail = persisted(
            policy_id,
            41,
            DomainEvent::PolicyArchived(PolicyArchived { policy_id }),
            2_000,
        );
        tail.stream_position = 41;
        let stream = vec![persisted(policy_id, 0, created_event(&policy), 1_000), tail];
        let replay = fold_scan_policy(&stream).expect("folds");
        assert_eq!(replay.policy.stream_version, 41);
    }

    // -- fold refusals -------------------------------------------------------

    #[test]
    fn an_empty_stream_is_refused() {
        let err = fold_scan_policy(&[]).expect_err("nothing to fold");
        assert!(matches!(err, DomainError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn a_stream_not_opening_with_created_is_refused() {
        let policy_id = Uuid::from_u128(26);
        let stream = vec![persisted(
            policy_id,
            0,
            DomainEvent::PolicyArchived(PolicyArchived { policy_id }),
            1_000,
        )];
        let err = fold_scan_policy(&stream).expect_err("must open with PolicyCreated");
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("PolicyArchived"), "names what it found: {msg}");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn a_second_created_is_refused() {
        let policy = sample_policy(Uuid::from_u128(27));
        let stream = vec![
            persisted(policy.policy_id, 0, created_event(&policy), 1_000),
            persisted(policy.policy_id, 1, created_event(&policy), 2_000),
        ];
        let err = fold_scan_policy(&stream).expect_err("one Created per stream");
        assert!(matches!(err, DomainError::Invariant(_)), "got {err:?}");
    }

    #[test]
    fn a_stream_mixing_policy_ids_is_refused() {
        let policy = sample_policy(Uuid::from_u128(28));
        let other = Uuid::from_u128(29);
        let stream = vec![
            persisted(policy.policy_id, 0, created_event(&policy), 1_000),
            persisted(
                policy.policy_id,
                1,
                DomainEvent::PolicyArchived(PolicyArchived { policy_id: other }),
                2_000,
            ),
        ];
        let err = fold_scan_policy(&stream).expect_err("one aggregate per stream");
        match err {
            DomainError::Invariant(msg) => {
                assert!(
                    msg.contains(&other.to_string()),
                    "names the intruder: {msg}"
                );
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn an_event_that_does_not_belong_on_a_policy_stream_is_refused() {
        let policy = sample_policy(Uuid::from_u128(30));
        let stream = vec![
            persisted(policy.policy_id, 0, created_event(&policy), 1_000),
            persisted(
                policy.policy_id,
                1,
                DomainEvent::PolicyReactivated(PolicyReactivated {
                    policy_id: policy.policy_id,
                }),
                2_000,
            ),
        ];
        // Sanity: the modelled event is accepted …
        fold_scan_policy(&stream).expect("PolicyReactivated is modelled");

        // … and an unmodelled one is refused rather than skipped.
        let mut intruder = stream.clone();
        intruder[1].event = DomainEvent::ArtifactQuarantined(crate::events::ArtifactQuarantined {
            artifact_id: Uuid::from_u128(31),
            quarantine_window_start: ts(9_000),
        });
        let err = fold_scan_policy(&intruder).expect_err("an alien event refuses the fold");
        match err {
            DomainError::Invariant(msg) => {
                assert!(
                    msg.contains("ArtifactQuarantined"),
                    "names the alien event: {msg}"
                );
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    /// `at_position` annotates the two refusals the applier can raise and
    /// passes anything else through untouched, so a future error variant
    /// cannot have its message silently rewritten into one of those two.
    #[test]
    fn at_position_annotates_only_the_refusals_it_recognises() {
        match at_position(DomainError::Invariant("broken".into()), 7) {
            DomainError::Invariant(msg) => assert_eq!(msg, "broken (stream position 7)"),
            other => panic!("expected Invariant, got {other:?}"),
        }
        match at_position(DomainError::Validation("bad".into()), 3) {
            DomainError::Validation(msg) => assert_eq!(msg, "bad (stream position 3)"),
            other => panic!("expected Validation, got {other:?}"),
        }
        match at_position(DomainError::Conflict("raced".into()), 9) {
            DomainError::Conflict(msg) => assert_eq!(msg, "raced", "passed through verbatim"),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn an_undecodable_update_refuses_the_whole_fold() {
        let policy = sample_policy(Uuid::from_u128(32));
        let policy_id = policy.policy_id;
        let stream = vec![
            persisted(policy_id, 0, created_event(&policy), 1_000),
            persisted(
                policy_id,
                1,
                DomainEvent::PolicyUpdated(PolicyUpdated {
                    policy_id,
                    field: PolicyField::RescanIntervalHours,
                    previous_value: serde_json::json!(24),
                    new_value: serde_json::json!("every other tuesday"),
                }),
                2_000,
            ),
        ];
        let err = fold_scan_policy(&stream).expect_err("an undecodable value refuses");
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    /// The forward path and the fold are the same mapping: folding a
    /// batch about to be appended produces exactly the state a later
    /// fold of the persisted stream produces.
    #[test]
    fn folding_a_batch_matches_folding_the_stream_it_becomes() {
        let policy = sample_policy(Uuid::from_u128(40));
        let policy_id = policy.policy_id;
        let mut desired = policy.clone();
        mutate_field(&mut desired, &PolicyField::Enforcement);
        mutate_field(&mut desired, &PolicyField::QuarantineDuration);
        let batch: Vec<DomainEvent> = diff_policy_fields(policy_id, &policy, &desired)
            .into_iter()
            .map(DomainEvent::PolicyUpdated)
            .collect();
        assert_eq!(batch.len(), 2);

        // Forward: the write path folds the batch it is about to append.
        let mut forward = ScanPolicyReplay {
            policy: policy.clone(),
            exclusions: Vec::new(),
        };
        apply_policy_batch(&mut forward, &batch, &api_actor(), ts(2_000), 2)
            .expect("the batch folds");

        // Backward: the same events, read back off the stream.
        let mut stream = vec![persisted(policy_id, 0, created_event(&policy), 1_000)];
        for (i, event) in batch.into_iter().enumerate() {
            stream.push(persisted(policy_id, i as u64 + 1, event, 2_000));
        }
        let backward = fold_scan_policy(&stream).expect("the stream folds");

        assert_eq!(forward.policy, backward.policy);
        assert_eq!(forward.exclusions, backward.exclusions);
    }

    #[test]
    fn folding_a_batch_sets_the_version_and_the_update_instant() {
        let policy = sample_policy(Uuid::from_u128(41));
        let policy_id = policy.policy_id;
        let mut replay = ScanPolicyReplay {
            policy,
            exclusions: Vec::new(),
        };
        apply_policy_batch(
            &mut replay,
            &[DomainEvent::PolicyArchived(PolicyArchived { policy_id })],
            &api_actor(),
            ts(9_000),
            7,
        )
        .expect("the batch folds");
        assert!(replay.policy.archived);
        assert_eq!(replay.policy.stream_version, 7);
        assert_eq!(replay.policy.updated_at, ts(9_000));
    }

    /// An event naming another policy is refused, not applied — the
    /// defence that keeps a self-heal from rewriting a peer's row.
    #[test]
    fn folding_a_batch_refuses_an_event_for_another_policy() {
        let policy = sample_policy(Uuid::from_u128(42));
        let mut replay = ScanPolicyReplay {
            policy,
            exclusions: Vec::new(),
        };
        let err = apply_policy_batch(
            &mut replay,
            &[DomainEvent::PolicyArchived(PolicyArchived {
                policy_id: Uuid::from_u128(43),
            })],
            &api_actor(),
            ts(9_000),
            1,
        )
        .expect_err("a foreign policy_id must refuse");
        assert!(matches!(err, DomainError::Invariant(_)), "got {err:?}");
        assert!(!replay.policy.archived, "nothing is applied on refusal");
    }
}
