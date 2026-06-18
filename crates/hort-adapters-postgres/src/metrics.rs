//! # hort-adapters-postgres::metrics — label names, value constants, result enums
//!
//! Owns the metric label names and result taxonomy emitted by this adapter's
//! event store. No emission code lives here — only canonical string constants
//! and enums.
//!
//! The canonical metric catalog lives at `docs/metrics-catalog.md`. Every
//! string in this module corresponds to a row in that catalog.
//!
//! Layering: each adapter owns its own result enum locally.
//! This module MUST NOT be shared with `hort-app` or `hort-adapters-storage`,
//! and MUST NOT be added to `hort-domain`.

/// Label-name constants used as keys when emitting event-store metrics with
/// the `metrics` crate macros. Using constants (rather than string literals
/// at call sites) prevents typos from silently producing a different time
/// series.
pub mod labels {
    /// Event category (`"artifact"`, `"policy"`).
    pub const CATEGORY: &str = "category";
    /// Low-level operation identifier (`"append"`, `"read_stream"`, `"read_category"`).
    pub const OPERATION: &str = "operation";
    /// Outcome classification for the operation.
    pub const RESULT: &str = "result";
    /// Forbidden mutation that was attempted/blocked. Used by
    /// `hort_audit_events_blocked_total` — see `docs/metrics-catalog.md`.
    pub const ATTEMPTED_OP: &str = "attempted_op";
    /// Where the block was decided. Used by
    /// `hort_audit_events_blocked_total` — `startup_probe` for the
    /// `PgEventStore::new` privilege probe; `trigger_caught` for an
    /// in-flight trigger-fired Postgres error caught by the adapter.
    pub const DECISION_POINT: &str = "decision_point";
}

/// Enumerable label-value constants emitted by the event store.
pub mod values {
    /// Event category for artifact lifecycle streams.
    pub const CATEGORY_ARTIFACT: &str = "artifact";
    /// Event category for policy streams.
    pub const CATEGORY_POLICY: &str = "policy";
    /// Event category for audit-meta streams. The surviving emitter on
    /// `StreamCategory::Admin` is the `StreamSealed` tombstone on the
    /// never-deleted `admin-eventstore-retention` audit-meta stream
    /// (ADR 0002 + ADR 0004).
    pub const CATEGORY_ADMIN: &str = "admin";
    /// Event category for mutable-ref lifecycle streams.
    /// Emitted when `RefMoved` / `RefRetired` events flow through the append
    /// path. Kept as a constant so every emission site uses the same label
    /// value as the metrics catalog.
    pub const CATEGORY_REF: &str = "ref";
    /// Event category for artifact-group lifecycle streams.
    /// Emitted when `ArtifactGroupInitiated` /
    /// `ArtifactGroupMemberAdded` / `ArtifactGroupMemberRemoved` /
    /// `ArtifactGroupPrimaryRoleAssigned` events flow through the append
    /// path. Underscore-separated wire form — see the `StreamCategory`
    /// docstring for why.
    pub const CATEGORY_ARTIFACT_GROUP: &str = "artifact_group";
    /// Event category for curation-decision streams. Emitted when
    /// `CurationApplied` events flow through the append path. One stream
    /// per repository (`curation-<repository_id>`).
    pub const CATEGORY_CURATION: &str = "curation";
    /// Event category for repository-aggregate streams (ADR 0006).
    /// Emitted when `ChecksumMismatch` events flow through the append path
    /// on the upstream-verification mismatch flow — the repository, not the
    /// artifact, is the aggregate, because no artifact row is minted on that
    /// path. One stream per repository (`repository-<repository_id>`).
    pub const CATEGORY_REPOSITORY: &str = "repository";
    /// Event category for authentication-attempt audit streams
    /// (NIS2 Art. 21(2)(h)). Emitted when [`AuthenticationAttempted`]
    /// events flow through the append path. One stream per UTC date —
    /// daily rotation; the `entity_id` is a deterministic UUIDv5 derived
    /// from the `YYYY-MM-DD` date.
    pub const CATEGORY_AUTH_ATTEMPTS: &str = "auth";
    /// Event category for authorization-model mutation audit streams
    /// (NIS2 Art. 21(2)(h), ADR 0012). Emitted when
    /// `ClaimMappingApplied` / `ClaimMappingRevoked` /
    /// `PermissionGrantApplied` / `PermissionGrantRevoked` events flow
    /// through the append path. One global stream — gitops apply is
    /// infrequent and the audit consumer reads the whole stream.
    pub const CATEGORY_AUTHORIZATION: &str = "authorization";
    /// Event category for per-user audit-attribution streams (ADR 0012).
    /// Emitted when `ApiTokenIssued` / `ApiTokenRevoked` (token-owner
    /// stream) and `ApiTokenIssuanceDenied` (requesting-actor stream) flow
    /// through the append path. One stream per user (`user-<uuid>`).
    pub const CATEGORY_USER: &str = "user";
    /// Event category for opt-in per-`(repository, UTC-date)`
    /// download-audit streams (ADR 0020). Emitted when an
    /// `ArtifactDownloaded` event flows through the append path — only
    /// for repositories whose `download_audit_enabled` flag is set.
    /// Cardinality is bounded by (opted-in repos × active days); the
    /// opt-in flag is the volume control (no throttle).
    pub const CATEGORY_DOWNLOAD_AUDIT: &str = "download_audit";
    /// Event category for throttled per-`(token_id, UTC-date)`
    /// token-use audit streams (ADR 0020). Emitted when an `ApiTokenUsed`
    /// event flows through the append path — one per successful PAT
    /// validation that wins the per-`token_id` 1-hour throttle.
    /// Cardinality is bounded by (active tokens × active days); the
    /// throttle is the volume control.
    pub const CATEGORY_TOKEN_USE: &str = "token_use";
    /// Event category for the event-sourced retention-policy lifecycle
    /// stream (ADR 0020). Emitted when a `RetentionPolicyChanged` event
    /// flows through the append path — one per gitops-authored
    /// create/update/archive plus the per-sweep `Evaluated` breadcrumb.
    /// Cardinality is bounded by the (small, operator-authored)
    /// retention-policy count; no throttle needed (policy mutations are
    /// rare, the sweep breadcrumb is one per policy per sweep).
    pub const CATEGORY_RETENTION_POLICY: &str = "retention_policy";

    /// Operation name: append to an event stream.
    pub const OPERATION_APPEND: &str = "append";
    /// Operation name: read events from a single stream.
    pub const OPERATION_READ_STREAM: &str = "read_stream";
    /// Operation name: read events across a category.
    pub const OPERATION_READ_CATEGORY: &str = "read_category";
}

/// Outcome of an event-store append operation, used as the `result` label of
/// `hort_event_store_appends_total`.
///
/// String values are normative — they are part of the public metrics contract
/// declared in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStoreResult {
    /// Append succeeded; events persisted.
    Success,
    /// Optimistic-concurrency version mismatch (expected version did not match).
    Conflict,
    /// Any other failure (serialization, database I/O, etc.).
    Error,
}

impl EventStoreResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Conflict => "conflict",
            Self::Error => "error",
        }
    }
}

// ---------------------------------------------------------------------------
// Audit-event mutation block taxonomy — see docs/metrics-catalog.md
// ---------------------------------------------------------------------------

/// Forbidden mutation operation that was either probed-for at startup or
/// caught at runtime when a trigger fired. Used as the `attempted_op` label
/// of `hort_audit_events_blocked_total`.
///
/// String values are normative — they are part of the public metrics
/// contract declared in `docs/metrics-catalog.md`. Three variants only;
/// the `events_immutable` trigger fires on `UPDATE`, `DELETE`, `TRUNCATE`
/// and the matching `has_table_privilege` probes cover the same set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditBlockedOp {
    /// `UPDATE events SET ...` — would mutate an existing audit row.
    Update,
    /// `DELETE FROM events ...` — would erase an audit row.
    Delete,
    /// `TRUNCATE events` — would erase the entire audit history.
    Truncate,
}

impl AuditBlockedOp {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Truncate => "truncate",
        }
    }
}

/// Site at which the block was decided. Used as the `decision_point`
/// label of `hort_audit_events_blocked_total`.
///
/// `StartupProbe` fires inside `PgEventStore::new` when
/// `has_table_privilege('events', '<priv>')` returns `true` for the
/// runtime role — the binary refuses to start. `TriggerCaught` fires
/// when the `events_immutable` Postgres trigger raised an exception and
/// the adapter caught it (defence-in-depth in case some future code
/// path attempts a forbidden mutation; the trigger is the wall, the
/// metric is the trip-wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditBlockedDecisionPoint {
    /// Detected by the `PgEventStore::new` privilege probe.
    StartupProbe,
    /// Caught at runtime from a Postgres trigger-raised exception.
    TriggerCaught,
}

impl AuditBlockedDecisionPoint {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StartupProbe => "startup_probe",
            Self::TriggerCaught => "trigger_caught",
        }
    }
}

/// Emit `hort_audit_events_blocked_total{attempted_op, decision_point}` once.
///
/// Catalog spec: counter, two labels, no further dimensions. Cardinality
/// is bounded at 3 (ops) × 2 (decision points) = 6 series per
/// deployment. The Postgres trigger does NOT emit metrics directly —
/// emission is always Rust-side and classified by `decision_point` so
/// alerting can distinguish "operator deployed with too-permissive
/// grants" (startup_probe) from "an in-flight write path tried a
/// mutation the trigger rejected" (trigger_caught).
pub fn emit_audit_events_blocked(op: AuditBlockedOp, decision_point: AuditBlockedDecisionPoint) {
    metrics::counter!(
        "hort_audit_events_blocked_total",
        labels::ATTEMPTED_OP => op.as_str(),
        labels::DECISION_POINT => decision_point.as_str(),
    )
    .increment(1);
}

/// Classify a Postgres error returned from an attempted mutation on
/// the `events` table into the matching `AuditBlockedOp`. Used by
/// `PgEventStore` at the `trigger_caught` emission site.
///
/// The `events_immutable` trigger raises a `RAISE EXCEPTION` whose
/// message embeds `TG_OP` — `UPDATE`, `DELETE`, or `TRUNCATE`. We
/// match on that message because Postgres maps `RAISE EXCEPTION`
/// (without `ERRCODE`) to the generic `P0001` SQLSTATE, which is not
/// itself discriminating; the message is the only structured clue
/// the trigger gives us. Returns `None` if the message has no
/// recognisable verb — caller should NOT emit the metric in that
/// case (avoids polluting the counter with unrelated DB errors).
pub fn classify_trigger_error_message(message: &str) -> Option<AuditBlockedOp> {
    // The trigger formats: "events table is append-only: <TG_OP> not allowed".
    // Match case-insensitively because future Postgres versions may
    // change casing of the substituted `%` argument.
    let upper = message.to_ascii_uppercase();
    if upper.contains("UPDATE") {
        Some(AuditBlockedOp::Update)
    } else if upper.contains("DELETE") {
        Some(AuditBlockedOp::Delete)
    } else if upper.contains("TRUNCATE") {
        Some(AuditBlockedOp::Truncate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_trigger_error_message, emit_audit_events_blocked, labels, values,
        AuditBlockedDecisionPoint, AuditBlockedOp, EventStoreResult,
    };
    use std::collections::{HashMap, HashSet};

    // -------------------------------------------------------------------
    // Label-name constants match the catalog exactly.
    // -------------------------------------------------------------------

    #[test]
    fn label_category_is_category() {
        assert_eq!(labels::CATEGORY, "category");
    }

    #[test]
    fn label_operation_is_operation() {
        assert_eq!(labels::OPERATION, "operation");
    }

    #[test]
    fn label_result_is_result() {
        assert_eq!(labels::RESULT, "result");
    }

    // -------------------------------------------------------------------
    // Value constants match the catalog exactly.
    // -------------------------------------------------------------------

    #[test]
    fn value_category_artifact_is_artifact() {
        assert_eq!(values::CATEGORY_ARTIFACT, "artifact");
    }

    #[test]
    fn value_category_policy_is_policy() {
        assert_eq!(values::CATEGORY_POLICY, "policy");
    }

    #[test]
    fn value_category_admin_is_admin() {
        assert_eq!(values::CATEGORY_ADMIN, "admin");
    }

    #[test]
    fn value_category_ref_is_ref() {
        assert_eq!(values::CATEGORY_REF, "ref");
    }

    #[test]
    fn value_category_artifact_group_is_artifact_group() {
        assert_eq!(values::CATEGORY_ARTIFACT_GROUP, "artifact_group");
    }

    #[test]
    fn value_category_curation_is_curation() {
        assert_eq!(values::CATEGORY_CURATION, "curation");
    }

    #[test]
    fn value_category_repository_is_repository() {
        assert_eq!(values::CATEGORY_REPOSITORY, "repository");
    }

    #[test]
    fn value_category_auth_attempts_is_auth() {
        assert_eq!(values::CATEGORY_AUTH_ATTEMPTS, "auth");
    }

    #[test]
    fn value_category_authorization_is_authorization() {
        assert_eq!(values::CATEGORY_AUTHORIZATION, "authorization");
    }

    #[test]
    fn value_operation_append_is_append() {
        assert_eq!(values::OPERATION_APPEND, "append");
    }

    #[test]
    fn value_operation_read_stream_is_read_stream() {
        assert_eq!(values::OPERATION_READ_STREAM, "read_stream");
    }

    #[test]
    fn value_operation_read_category_is_read_category() {
        assert_eq!(values::OPERATION_READ_CATEGORY, "read_category");
    }

    // -------------------------------------------------------------------
    // EventStoreResult — every variant's `as_str()` matches the catalog.
    // -------------------------------------------------------------------

    #[test]
    fn event_store_result_success_as_str() {
        assert_eq!(EventStoreResult::Success.as_str(), "success");
    }

    #[test]
    fn event_store_result_conflict_as_str() {
        assert_eq!(EventStoreResult::Conflict.as_str(), "conflict");
    }

    #[test]
    fn event_store_result_error_as_str() {
        assert_eq!(EventStoreResult::Error.as_str(), "error");
    }

    #[test]
    fn event_store_result_values_are_unique() {
        let variants = [
            EventStoreResult::Success,
            EventStoreResult::Conflict,
            EventStoreResult::Error,
        ];
        let set: HashSet<&'static str> = variants.iter().map(EventStoreResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // Audit-block taxonomy + emission helper — see docs/metrics-catalog.md.
    // -------------------------------------------------------------------

    #[test]
    fn label_attempted_op_is_attempted_op() {
        assert_eq!(labels::ATTEMPTED_OP, "attempted_op");
    }

    #[test]
    fn label_decision_point_is_decision_point() {
        assert_eq!(labels::DECISION_POINT, "decision_point");
    }

    #[test]
    fn audit_blocked_op_as_str_covers_every_variant() {
        assert_eq!(AuditBlockedOp::Update.as_str(), "update");
        assert_eq!(AuditBlockedOp::Delete.as_str(), "delete");
        assert_eq!(AuditBlockedOp::Truncate.as_str(), "truncate");
    }

    #[test]
    fn audit_blocked_op_values_are_unique() {
        let variants = [
            AuditBlockedOp::Update,
            AuditBlockedOp::Delete,
            AuditBlockedOp::Truncate,
        ];
        let set: HashSet<&'static str> = variants.iter().map(AuditBlockedOp::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn audit_blocked_decision_point_as_str_covers_every_variant() {
        assert_eq!(
            AuditBlockedDecisionPoint::StartupProbe.as_str(),
            "startup_probe"
        );
        assert_eq!(
            AuditBlockedDecisionPoint::TriggerCaught.as_str(),
            "trigger_caught"
        );
    }

    #[test]
    fn audit_blocked_decision_point_values_are_unique() {
        let variants = [
            AuditBlockedDecisionPoint::StartupProbe,
            AuditBlockedDecisionPoint::TriggerCaught,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(AuditBlockedDecisionPoint::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    // ---- classify_trigger_error_message --------------------------------

    #[test]
    fn classify_recognises_update_in_trigger_message() {
        let msg = "events table is append-only: UPDATE not allowed";
        assert_eq!(
            classify_trigger_error_message(msg),
            Some(AuditBlockedOp::Update)
        );
    }

    #[test]
    fn classify_recognises_delete_in_trigger_message() {
        let msg = "events table is append-only: DELETE not allowed";
        assert_eq!(
            classify_trigger_error_message(msg),
            Some(AuditBlockedOp::Delete)
        );
    }

    #[test]
    fn classify_recognises_truncate_in_trigger_message() {
        let msg = "events table is append-only: TRUNCATE not allowed";
        assert_eq!(
            classify_trigger_error_message(msg),
            Some(AuditBlockedOp::Truncate)
        );
    }

    #[test]
    fn classify_is_case_insensitive() {
        assert_eq!(
            classify_trigger_error_message("blocked: update"),
            Some(AuditBlockedOp::Update)
        );
    }

    #[test]
    fn classify_returns_none_for_unrelated_message() {
        // An unrelated DB error must not pollute the audit-block counter.
        assert_eq!(classify_trigger_error_message("connection timeout"), None);
    }

    // ---- emit_audit_events_blocked fires the counter with the right -----
    // ---- label tuple ----------------------------------------------------

    #[test]
    fn emit_audit_events_blocked_fires_with_startup_probe_labels() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            emit_audit_events_blocked(
                AuditBlockedOp::Update,
                AuditBlockedDecisionPoint::StartupProbe,
            );
        });
        let entries = snapshotter.snapshot().into_vec();
        let (key, _unit, _desc, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_audit_events_blocked_total")
            .expect("hort_audit_events_blocked_total must fire");
        let labels: HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("attempted_op"), Some(&"update"));
        assert_eq!(labels.get("decision_point"), Some(&"startup_probe"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_audit_events_blocked_fires_with_trigger_caught_labels() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            emit_audit_events_blocked(
                AuditBlockedOp::Delete,
                AuditBlockedDecisionPoint::TriggerCaught,
            );
            emit_audit_events_blocked(
                AuditBlockedOp::Truncate,
                AuditBlockedDecisionPoint::TriggerCaught,
            );
        });
        let entries = snapshotter.snapshot().into_vec();
        // Two distinct label tuples should produce two series, each at 1.
        let mut found = HashSet::new();
        for (key, _, _, value) in &entries {
            if key.key().name() != "hort_audit_events_blocked_total" {
                continue;
            }
            let labels: HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("decision_point") == Some(&"trigger_caught") {
                let op = labels
                    .get("attempted_op")
                    .copied()
                    .expect("attempted_op label present");
                found.insert(op.to_string());
                match value {
                    metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
                    other => panic!("expected Counter, got {other:?}"),
                }
            }
        }
        assert!(found.contains("delete"));
        assert!(found.contains("truncate"));
    }
}
