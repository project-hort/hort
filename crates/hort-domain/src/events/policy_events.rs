use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;

use super::validation::{validate_json, validate_optional_string, validate_string};

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

const MAX_POLICY_NAME_LEN: usize = 256;
const MAX_CVE_ID_LEN: usize = 64;
const MAX_PACKAGE_PATTERN_LEN: usize = 512;
const MAX_REASON_LEN: usize = 4096;
const MAX_JSON_SIZE: usize = 32 * 1024; // 32 KB
const MAX_JSON_DEPTH: usize = 10;

// ---------------------------------------------------------------------------
// PolicyCreated
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyCreated {
    pub policy_id: Uuid,
    pub name: String,
    pub scope: PolicyScope,
    pub config_snapshot: serde_json::Value,
}

impl PolicyCreated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("name", &self.name, MAX_POLICY_NAME_LEN)?;
        validate_json(
            "config_snapshot",
            &self.config_snapshot,
            MAX_JSON_SIZE,
            MAX_JSON_DEPTH,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyScope {
    Global,
    Repository(Uuid),
}

// ---------------------------------------------------------------------------
// PolicyUpdated
// ---------------------------------------------------------------------------

/// Which policy field was changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyField {
    Name,
    Scope,
    SeverityThreshold,
    QuarantineDuration,
    RequireApproval,
    /// `provenance_mode` changed (ADR 0027). The
    /// `previous_value` / `new_value` payloads are the lowercase
    /// `ProvenanceMode` wire strings (`off` / `verify_if_present` /
    /// `required`). Supersedes the retired `RequireSignature` variant.
    ProvenanceMode,
    /// `provenance_backends` list changed. JSON arrays
    /// of strings (mirrors [`ScanBackends`](Self::ScanBackends)).
    ProvenanceBackends,
    /// `provenance_identities` list changed. The
    /// payloads are JSON arrays of `{issuer, san}` objects.
    ProvenanceIdentities,
    MaxArtifactAge,
    LicensePolicy,
    /// `scan_backends` list changed. The
    /// `previous_value` / `new_value` payloads are JSON arrays of
    /// strings.
    ScanBackends,
    /// `rescan_interval_hours` changed. The
    /// `previous_value` / `new_value` payloads are JSON integers.
    RescanIntervalHours,
    /// `negligible_action` changed. The `previous_value` / `new_value`
    /// payloads are the lowercase `NegligibleAction` wire strings
    /// (`ignore` / `warn` / `block`).
    NegligibleAction,
}

impl PolicyField {
    /// Whether a change to this field alters the **scan release gate**
    /// and therefore warrants an async re-evaluation pass over the
    /// policy's in-scope population (ADR 0041 §Triggers-and-scope).
    ///
    /// The continuous-enforcement pass re-derives each artifact's verdict
    /// by re-running the pure scan evaluator (`evaluate_scan_result`)
    /// over the artifact's **stored findings** under the bumped policy.
    /// That evaluator reads exactly three policy fields:
    /// `severity_threshold` (the blocked-severity bar), `license_policy`
    /// (the blocked-license classes), and `negligible_action` (how
    /// informational / negligible findings steer the decision). A change
    /// to any of those three can flip a stored-findings verdict and so is
    /// gate-affecting; the ADR's enumeration ("severity thresholds,
    /// blocked classes, `negligible_action`") is exactly this set.
    ///
    /// Every other field is **not** scan-gate-affecting:
    /// - `Name` / `Scope` — identity / matching, not the verdict
    ///   (`Scope` changes *which* policy matches an artifact, handled by
    ///   the matcher, not by re-deriving a verdict under one policy);
    /// - `QuarantineDuration` — anchors the timer window, not the verdict
    ///   (ADR 0041: re-evaluation re-derives the verdict, never the
    ///   timer);
    /// - `RequireApproval` — a promotion-gate knob, not the scan release
    ///   predicate;
    /// - `ProvenanceMode` / `ProvenanceBackends` / `ProvenanceIdentities`
    ///   — the provenance axis runs its own verification path
    ///   (`provenance-verify`); the cross-axis release conjunction
    ///   (invariant #6) re-checks live provenance state at release time,
    ///   so a provenance-config change does not require re-deriving the
    ///   *scan* verdict here;
    /// - `MaxArtifactAge` — an age gate enforced at ingest, not part of
    ///   the stored-findings scan verdict;
    /// - `ScanBackends` — selects *which scanners run*, i.e. which
    ///   findings get *produced* on the next scan; it does not
    ///   re-interpret already-stored findings (the evaluator never reads
    ///   it). Changing it changes future evidence, not the current
    ///   verdict over existing evidence — out of scope for this pass (the
    ///   `scan_backends: []` waiver row has no findings → untouched,
    ///   ADR 0041 cross-opt-in matrix);
    /// - `RescanIntervalHours` — schedules the cron rescan cadence, not
    ///   the verdict.
    ///
    /// Closed match (no `_` arm) so a future `PolicyField` variant fails
    /// to compile here, forcing a deliberate gate-affecting decision
    /// rather than silently defaulting either way.
    #[must_use]
    pub const fn is_gate_affecting(&self) -> bool {
        match self {
            Self::SeverityThreshold | Self::LicensePolicy | Self::NegligibleAction => true,
            Self::Name
            | Self::Scope
            | Self::QuarantineDuration
            | Self::RequireApproval
            | Self::ProvenanceMode
            | Self::ProvenanceBackends
            | Self::ProvenanceIdentities
            | Self::MaxArtifactAge
            | Self::ScanBackends
            | Self::RescanIntervalHours => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyUpdated {
    pub policy_id: Uuid,
    pub field: PolicyField,
    pub previous_value: serde_json::Value,
    pub new_value: serde_json::Value,
}

impl PolicyUpdated {
    pub fn validate(&self) -> DomainResult<()> {
        validate_json(
            "previous_value",
            &self.previous_value,
            MAX_JSON_SIZE,
            MAX_JSON_DEPTH,
        )?;
        validate_json("new_value", &self.new_value, MAX_JSON_SIZE, MAX_JSON_DEPTH)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ExclusionAdded
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExclusionAdded {
    pub policy_id: Uuid,
    pub exclusion_id: Uuid,
    pub cve_id: String,
    pub package_pattern: Option<String>,
    pub scope: PolicyScope,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ExclusionAdded {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("cve_id", &self.cve_id, MAX_CVE_ID_LEN)?;
        validate_optional_string(
            "package_pattern",
            &self.package_pattern,
            MAX_PACKAGE_PATTERN_LEN,
        )?;
        validate_string("reason", &self.reason, MAX_REASON_LEN)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ExclusionRemoved
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExclusionRemoved {
    pub policy_id: Uuid,
    pub exclusion_id: Uuid,
    pub reason: String,
}

impl ExclusionRemoved {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("reason", &self.reason, MAX_REASON_LEN)
    }
}

// ---------------------------------------------------------------------------
// PolicyArchived
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyArchived {
    pub policy_id: Uuid,
}

impl PolicyArchived {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PolicyReactivated
// ---------------------------------------------------------------------------

/// A previously [`PolicyArchived`] policy is brought back into active
/// service.
///
/// Emitted by the gitops apply pipeline when a YAML re-declares a policy
/// whose `metadata.name` matches an archived projection — the existing
/// `policy_id` and event stream are preserved (audit continuity), the
/// projection's `archived` field flips back to `false`, and any spec
/// deltas land as a follow-on `PolicyUpdated` batch in the same apply
/// pass. Without this event the apply takes the create path, mints a
/// new `policy_id`, and the subsequent projection upsert collides with
/// the existing row's UNIQUE-name constraint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyReactivated {
    pub policy_id: Uuid,
}

impl PolicyReactivated {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}
