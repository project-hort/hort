use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::artifact::QuarantineStatus;
use crate::entities::scan_policy::SeverityThreshold;
use crate::error::{DomainError, DomainResult};
use crate::ports::provenance::{ProvenanceRejectReason, SignerIdentity};
use crate::retention::ExpirationReason;
use crate::types::checksum::HashAlgorithm;
use crate::types::{ArtifactCoords, ContentHash, Finding};

use super::validation::{validate_json, validate_optional_string, validate_string};

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

const MAX_NAME_LEN: usize = 1024;
const MAX_REASON_LEN: usize = 4096;
const MAX_SCANNER_LEN: usize = 256;
const MAX_SEVERITY_COUNT: u32 = 100_000;
const MAX_NOTES_LEN: usize = 4096;
const MAX_RULE_LEN: usize = 256;
/// Cap on `PolicyViolation.message`. Operator-readable summary —
/// 4 KiB is generous for any single violation.
const MAX_MESSAGE_LEN: usize = 4096;
/// Cap on the serialised `PolicyViolation.details` JSON blob (4 KiB).
/// A violation with megabytes of structured context is a bug; the
/// scan-result event itself carries the aggregate counts.
const MAX_VIOLATION_DETAILS_SIZE: usize = 4 * 1024;
/// Maximum nesting depth for `PolicyViolation.details`. Mirrors the
/// `MAX_JSON_DEPTH` used by `policy_events`.
const MAX_VIOLATION_DETAILS_DEPTH: usize = 10;

// ---------------------------------------------------------------------------
// ArtifactIngested
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactIngested {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub sha256: ContentHash,
    pub size_bytes: i64,
    pub source: IngestSource,
    /// Format-specific upload-payload metadata captured at ingest time.
    ///
    /// Opaque JSON — each `FormatHandler` owns its own schema. The event log
    /// is the source of truth; the `artifact_metadata` projection row is
    /// rebuildable from this field.
    ///
    /// Defaults to `Value::Null` (what `serde_json::Value::default()`
    /// produces) via `#[serde(default)]` so pre-field persisted events
    /// deserialise cleanly — defence-in-depth against future schema
    /// evolution. Consumers must treat this field as opaque JSON;
    /// `Null` and `{}` are semantically equivalent at read time (both
    /// yield `None` on any `.get(key)` lookup).
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// Optional reference to the full payload stored in CAS, when the
    /// format handler's
    /// [`MetadataStrategy`](crate::ports::format_handler::MetadataStrategy)
    /// is `HashReference` and the serialised payload exceeded the
    /// handler's inline threshold. When `Some(hash)`, `metadata` carries
    /// the handler-extracted summary and the full JSON payload lives at
    /// `hash` in content-addressable storage. When `None`, `metadata`
    /// carries the full payload inline.
    ///
    /// `#[serde(default)]` so older persisted events — which
    /// never wrote this key — deserialise as `None` under the current
    /// code. The event log is immutable; this is the forward-compat
    /// contract that avoids rewriting historical `ArtifactIngested`
    /// events when the field landed.
    #[serde(default)]
    pub metadata_blob: Option<ContentHash>,
    /// Best-effort upstream publish-time hint captured at ingest time
    /// (packument `time[<version>]`, PyPI
    /// `upload_time_iso_8601`, cargo `.crate` tarball `Last-Modified`,
    /// OCI blob `Last-Modified`). `None` for direct uploads and for
    /// proxied ingests where the upstream omitted / served an
    /// unparseable hint.
    ///
    /// **Why on the event, not only on the projection:** the ingest path
    /// derives `quarantine_window_start` from this value under the
    /// per-upstream `trust_upstream_publish_time` opt-in. A projection
    /// rebuild from the event stream must therefore produce the *same*
    /// `Artifact.upstream_published_at` the original ingest committed —
    /// otherwise the rebuilt anchor (and the release authority that
    /// flows from it) would silently differ from the recorded history.
    /// A projection-only field would leave the event stream unable to
    /// reproduce it — the event is the source of truth.
    ///
    /// `#[serde(default)]` so older persisted events that never wrote this
    /// key deserialise as `None`. That matches the projection state of those
    /// same artifacts (the `artifacts` column was likewise `NULL` before the
    /// field was introduced) so a rebuild stays bit-identical to the live
    /// materialised row.
    #[serde(default)]
    pub upstream_published_at: Option<DateTime<Utc>>,
}

impl ArtifactIngested {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("name", &self.name, MAX_NAME_LEN)?;
        validate_optional_string("version", &self.version, MAX_NAME_LEN)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestSource {
    /// Uploaded directly by a client.
    Direct,
    /// Fetched from an upstream registry via proxy.
    Proxied,
}

// ---------------------------------------------------------------------------
// ChecksumVerified / ChecksumMismatch
// ---------------------------------------------------------------------------

/// Verification target supplied by the format handler matched the bytes
/// the storage adapter received. Lands on the `artifact:<id>` stream in
/// the same `EventStore::append` batch as `ArtifactIngested` — atomic
/// with the mint (mint-after-verify, ADR 0006).
///
/// `upstream_value` and `computed_value` are both hex-encoded; the use
/// case formats once and stores the canonical hex.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumVerified {
    pub artifact_id: Uuid,
    pub algorithm: HashAlgorithm,
    pub upstream_value: String,
    pub computed_value: String,
}

impl ChecksumVerified {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// Verification target disagreed with the bytes the storage adapter
/// received. Lands on the `repository:<repo_id>` stream — there is NO
/// artifact id because the mismatch path never mints an artifact row
/// (mint-after-verify, ADR 0006).
///
/// `coords` carries what was attempted so the audit query
/// "show me all detected tamperings" can identify the package by name
/// rather than by an id that was never assigned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumMismatch {
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    pub format: String,
    pub algorithm: HashAlgorithm,
    pub upstream_value: String,
    pub computed_value: String,
}

impl ChecksumMismatch {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArtifactQuarantined
// ---------------------------------------------------------------------------

/// An artifact was held under a quarantine observation window.
///
/// The payload carries the immutable observation-window **anchor**
/// (`quarantine_window_start`, ADR 0007) — `ingested_at` by default —
/// **not** a precomputed deadline. The deadline is a derived value
/// (`window_start + duration`, the duration resolved from the matched
/// `ScanPolicy`) that callers compute live via
/// [`crate::policy::effective_quarantine_deadline`]; storing it in the
/// event would freeze a stale value if the operator later changes the
/// window duration. v2 has shipped no events, so the payload shape is
/// free to carry the anchor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactQuarantined {
    pub artifact_id: Uuid,
    /// The immutable observation-window anchor (ADR 0007).
    pub quarantine_window_start: DateTime<Utc>,
}

impl ArtifactQuarantined {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ScanRequested / ScanCompleted
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRequested {
    pub artifact_id: Uuid,
    pub scanner: String,
}

impl ScanRequested {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("scanner", &self.scanner, MAX_SCANNER_LEN)
    }
}

/// Aggregate scan-result event for a single scanner backend run against
/// an artifact. Carries fast aggregate counts (`finding_count`,
/// `severity_summary`) inline for O(1) projection updates and a
/// hash-reference (`findings_blob`) into CAS for the per-finding detail.
///
/// # Invariants (enforced by [`ScanCompleted::validate`])
///
/// - `findings_blob.is_some() == (finding_count > 0)` — clean scans never
///   reference a blob; non-clean scans always do. A `Some` paired with
///   zero findings (or a `None` paired with positive findings) is a bug.
/// - `severity_summary.sum() == finding_count` — independent invariant.
///
/// # `findings_blob` layout
///
/// The blob is a JSON-serialised `Vec<Finding>` written to CAS via
/// `StoragePort::put` (the hash-reference pattern, mirroring
/// `ArtifactIngested.metadata_blob`). Reads stream from
/// `StoragePort::get(hash)`. hort-cli and the admin UI typically render
/// the inline `severity_summary` and only fetch the blob when an
/// operator drills into per-finding detail.
///
/// # Schema evolution
///
/// `findings_blob` carries `#[serde(default)]` for forward-compat,
/// matching the
/// `UpstreamPublishedChecksum::deserialize_without_re_validating`
/// precedent: every event payload must accept any shape that was once
/// written, in case in-flight test fixtures or replay logs still carry
/// an older shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanCompleted {
    pub artifact_id: Uuid,
    pub scanner: String,
    pub finding_count: u32,
    pub severity_summary: SeveritySummary,
    /// Hash-reference to a CAS blob containing the JSON `Vec<Finding>`.
    /// `None` iff `finding_count == 0`. See type-level docs for the
    /// invariant and the `#[serde(default)]` rationale.
    #[serde(default)]
    pub findings_blob: Option<ContentHash>,
}

impl ScanCompleted {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("scanner", &self.scanner, MAX_SCANNER_LEN)?;
        self.severity_summary.validate()?;
        let sum = self
            .severity_summary
            .sum()
            .ok_or_else(|| DomainError::Validation("severity counts overflow u32".into()))?;
        if self.finding_count != sum {
            return Err(DomainError::Validation(format!(
                "finding_count ({}) does not equal sum of severity counts ({sum})",
                self.finding_count
            )));
        }
        // Invariant: blob presence iff non-empty findings.
        match (self.findings_blob.is_some(), self.finding_count > 0) {
            (true, false) => {
                return Err(DomainError::Validation(
                    "ScanCompleted has findings_blob but finding_count is zero".into(),
                ));
            }
            (false, true) => {
                return Err(DomainError::Validation(
                    "ScanCompleted has finding_count > 0 but no findings_blob".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Counts of findings by severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub negligible: u32,
}

impl SeveritySummary {
    pub fn validate(&self) -> DomainResult<()> {
        for (name, val) in [
            ("critical", self.critical),
            ("high", self.high),
            ("medium", self.medium),
            ("low", self.low),
            ("negligible", self.negligible),
        ] {
            if val > MAX_SEVERITY_COUNT {
                return Err(DomainError::Validation(format!(
                    "severity_summary.{name} exceeds maximum of {MAX_SEVERITY_COUNT} (got {val})"
                )));
            }
        }
        Ok(())
    }

    /// Returns the sum of all severity counts, or `None` on overflow.
    fn sum(&self) -> Option<u32> {
        self.critical
            .checked_add(self.high)?
            .checked_add(self.medium)?
            .checked_add(self.low)?
            .checked_add(self.negligible)
    }
}

// ---------------------------------------------------------------------------
// ArtifactBecameVulnerable
// ---------------------------------------------------------------------------

/// Discrete signal that a previously-clean (or differently-vulnerable)
/// artifact is now flagged with NEW findings — the unit operators
/// alarm on. Fired only when a *prior* `ScanCompleted` exists for the
/// same artifact AND the current findings contain `(purl,
/// vulnerability_id)` pairs absent from the prior scan.
///
/// First-ever scans never emit this event ("always was vulnerable, just
/// discovered now" is not a transition). The symmetric resolution event
/// (`ArtifactClearedVulnerabilities`) is deliberately not modelled.
///
/// Lands on `StreamCategory::Artifact` in the same `EventStore::append`
/// batch as the corresponding `ScanCompleted`. The delta computation
/// itself is the pure function
/// [`crate::policy::scan_delta::compute_added_findings`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactBecameVulnerable {
    pub artifact_id: Uuid,
    /// Findings present in the current scan that were absent from the
    /// most recent prior `ScanCompleted` for this artifact, keyed by
    /// `(purl, vulnerability_id)`.
    pub new_findings: Vec<Finding>,
    /// Timestamp of the most recent prior `ScanCompleted` event — the
    /// audit-trail anchor. The artifact was provably clean *of these
    /// specific findings* from this point until now.
    pub previously_clean_at: DateTime<Utc>,
}

impl ArtifactBecameVulnerable {
    pub fn validate(&self) -> DomainResult<()> {
        if self.new_findings.is_empty() {
            return Err(DomainError::Validation(
                "ArtifactBecameVulnerable requires at least one new finding".into(),
            ));
        }
        for f in &self.new_findings {
            f.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArtifactReleased
// ---------------------------------------------------------------------------

/// Audit-trail event emitted when a quarantined artifact transitions
/// to `Released`. The payload carries an operator-attribution field +
/// `justification` so
/// operator overrides are attributable: auditors can reconstruct *who*
/// released the artifact and *why* without correlating against a
/// separate audit stream. The field name `released_by_user_id` is
/// authority-neutral
/// so the curator-waive surface populates the same
/// field as the admin-override surface — the variant tag carries the
/// authority distinction at the boundary
/// ([`crate::entities::artifact::ReleaseAuthorization`]).
///
/// Variant invariant — enforced by `validate()`:
/// - [`ReleaseReason::Admin`] / [`ReleaseReason::Curator`] ⇒
///   `released_by_user_id.is_some() && justification.is_some()`. Both
///   authorities carry operator attribution.
/// - [`ReleaseReason::Timer`] / [`ReleaseReason::PolicyReEvaluation`] ⇒
///   both fields `None` (system-driven transitions carry no operator
///   attribution; the actor is on the persisted-event envelope).
///
/// `justification` is capped at 512 bytes — any longer is a
/// validation error. The HTTP boundary additionally rejects empty
/// strings with 400 before reaching the use case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactReleased {
    pub artifact_id: Uuid,
    pub released_by: ReleaseReason,
    /// Operator (admin or curator) who issued the release. Populated
    /// iff `released_by ∈ { Admin, Curator }`. Authority-neutral —
    /// the variant tag on [`ReleaseReason`] (or the
    /// [`crate::entities::artifact::ReleaseAuthorization`] paired with
    /// it at the call site) carries which authority drove the release;
    /// this field carries only *who*.
    pub released_by_user_id: Option<Uuid>,
    /// Operator-supplied free-text rationale. Populated iff
    /// `released_by ∈ { Admin, Curator }`. ≤ 512 bytes.
    pub justification: Option<String>,
}

impl ArtifactReleased {
    pub fn validate(&self) -> DomainResult<()> {
        match self.released_by {
            ReleaseReason::Admin | ReleaseReason::Curator => {
                if self.released_by_user_id.is_none() {
                    return Err(DomainError::Validation(format!(
                        "ArtifactReleased {{ released_by: {:?} }} requires released_by_user_id",
                        self.released_by
                    )));
                }
                if self.justification.is_none() {
                    return Err(DomainError::Validation(format!(
                        "ArtifactReleased {{ released_by: {:?} }} requires justification",
                        self.released_by
                    )));
                }
            }
            ReleaseReason::Timer | ReleaseReason::PolicyReEvaluation => {
                if self.released_by_user_id.is_some() {
                    return Err(DomainError::Validation(format!(
                        "ArtifactReleased {{ released_by: {:?} }} must not carry released_by_user_id",
                        self.released_by
                    )));
                }
                if self.justification.is_some() {
                    return Err(DomainError::Validation(format!(
                        "ArtifactReleased {{ released_by: {:?} }} must not carry justification",
                        self.released_by
                    )));
                }
            }
        }
        validate_optional_string("justification", &self.justification, 512)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseReason {
    /// Quarantine period expired (background sweep).
    Timer,
    /// Admin explicitly released despite findings.
    Admin,
    /// Policy re-evaluation after exclusion removed the block.
    PolicyReEvaluation,
    /// A curator (`Permission::Curate`) issued an
    /// early release ("waive") via the `CurationUseCase::waive` path.
    /// Pairs ONLY with
    /// [`crate::entities::artifact::ReleaseAuthorization::CuratorWaiver`]
    /// in the deny-by-default release predicate. Attribution
    /// (released-by user id + justification) is populated by the
    /// application layer on the [`ArtifactReleased`] event, mirroring
    /// the [`ReleaseReason::Admin`] shape.
    Curator,
}

// ---------------------------------------------------------------------------
// ArtifactReEvaluated
// ---------------------------------------------------------------------------

/// Which policy-change event drove a re-evaluation pass (ADR 0041).
///
/// The re-evaluation pass generalises beyond the original
/// exclusion-add trigger to every gate-affecting `ScanPolicy` mutation.
/// This discriminator names *which* policy-change event drove the pass
/// so the audit trail answers "what loosened/tightened this artifact?"
/// without re-running the evaluator — invariant #3 (the audit names the
/// driving change).
///
/// Externally-tagged (the default serde representation) so each variant
/// serialises as `{ "ExclusionAdded": { "exclusion_id": "…" } }` etc.
/// **Back-compat (ADR 0002, append-only).** Events written before the
/// generalisation carried a bare `trigger_exclusion_id: Uuid` on
/// [`ArtifactReEvaluated`] (no `trigger` key). [`ArtifactReEvaluated`]'s
/// hand-written deserialisation maps that legacy field onto
/// [`Self::ExclusionAdded`]; no past event is rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReEvaluationTrigger {
    /// An exclusion was added to the policy (a loosen). `exclusion_id`
    /// is the just-added exclusion — the same value the pre-ADR-0041
    /// `trigger_exclusion_id` field carried, so a legacy event maps here
    /// (see [`ArtifactReEvaluated`]'s back-compat note).
    ExclusionAdded { exclusion_id: Uuid },
    /// An exclusion was removed from the policy (a tighten).
    ExclusionRemoved { exclusion_id: Uuid },
    /// The policy's gate fields changed (severity threshold, blocked
    /// classes, `negligible_action`, …) — either direction. Carries the
    /// `PolicyUpdated` event's `policy_id` for audit attribution; a
    /// single multi-field policy update coalesces to one re-evaluation
    /// pass, so this is policy-scoped, not per-field.
    PolicyUpdated { policy_id: Uuid },
}

/// Audit record for a re-evaluation pass decision (ADR 0041).
///
/// Emitted on the artifact's stream when a gate-affecting `ScanPolicy`
/// change re-evaluates an in-scope artifact and transitions it — a
/// previously `Rejected` artifact back to `Quarantined` / `Released`
/// (loosen), or a previously `Released` / `Quarantined` artifact to
/// re-`Quarantined` / re-`Rejected` (tighten). The `previous_status` /
/// `new_status` pair lets audit consumers project "every transition that
/// happened" without having to correlate against
/// [`ArtifactQuarantined`] / [`ArtifactReleased`] / [`ArtifactRejected`]
/// events on the same stream.
///
/// `trigger` is the [`ReEvaluationTrigger`] discriminator naming which
/// policy-change event drove the pass (invariant #3) — answers "what
/// loosened/tightened this artifact?" without re-running the evaluator.
/// `policy_id` is the policy the pass evaluated against, for symmetry
/// with [`PolicyEvaluated`].
///
/// # Schema evolution (ADR 0002, append-only)
///
/// The pre-ADR-0041 event was exclusion-shaped: a non-optional
/// `trigger_exclusion_id: Uuid` field, no `trigger`. The field is
/// **widened** to the `trigger` discriminator; no past event is
/// rewritten. [`Deserialize`] is hand-written so a legacy event (carrying
/// `trigger_exclusion_id`, no `trigger`) maps onto
/// [`ReEvaluationTrigger::ExclusionAdded`] — every shape that was once
/// written still parses, matching the
/// `UpstreamPublishedChecksum::deserialize_without_re_validating`
/// forward-compat precedent. New events serialise the `trigger` key only.
///
/// Pure metadata — `validate()` always returns `Ok(())`. The event lives
/// on the artifact stream alongside the companion transition event
/// ([`ArtifactQuarantined`] / [`ArtifactReleased`] / [`ArtifactRejected`]);
/// the pair is appended atomically via
/// [`crate::ports::artifact_lifecycle::ArtifactLifecyclePort::commit_transition`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ArtifactReEvaluated {
    pub artifact_id: Uuid,
    pub policy_id: Uuid,
    pub trigger: ReEvaluationTrigger,
    pub previous_status: QuarantineStatus,
    pub new_status: QuarantineStatus,
}

impl ArtifactReEvaluated {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// Deserialisation wire-shape for [`ArtifactReEvaluated`] that accepts
/// **both** the current (`trigger`) and legacy (`trigger_exclusion_id`)
/// shapes (ADR 0002, append-only). Both fields are `#[serde(default)]`
/// so either may be absent; the `From` conversion resolves which one was
/// present.
#[derive(Deserialize)]
struct ArtifactReEvaluatedRepr {
    artifact_id: Uuid,
    policy_id: Uuid,
    /// Current shape: the policy-change discriminator. `None` on a
    /// legacy event.
    #[serde(default)]
    trigger: Option<ReEvaluationTrigger>,
    /// Legacy shape: the bare just-added exclusion id. `None` on a
    /// current event. Mapped onto
    /// [`ReEvaluationTrigger::ExclusionAdded`] when present.
    #[serde(default)]
    trigger_exclusion_id: Option<Uuid>,
    previous_status: QuarantineStatus,
    new_status: QuarantineStatus,
}

impl From<ArtifactReEvaluatedRepr> for ArtifactReEvaluated {
    fn from(repr: ArtifactReEvaluatedRepr) -> Self {
        // Prefer the current `trigger`; fall back to the legacy
        // `trigger_exclusion_id` (mapped to ExclusionAdded). If a
        // (malformed) event carries neither, default to a nil-id
        // ExclusionAdded — an audit record must still materialise rather
        // than fail the whole stream replay; the nil id is the same
        // "no value" sentinel `PolicyEvaluated::NO_POLICY` uses.
        let trigger = repr
            .trigger
            .unwrap_or_else(|| ReEvaluationTrigger::ExclusionAdded {
                exclusion_id: repr.trigger_exclusion_id.unwrap_or_else(Uuid::nil),
            });
        ArtifactReEvaluated {
            artifact_id: repr.artifact_id,
            policy_id: repr.policy_id,
            trigger,
            previous_status: repr.previous_status,
            new_status: repr.new_status,
        }
    }
}

impl<'de> Deserialize<'de> for ArtifactReEvaluated {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ArtifactReEvaluatedRepr::deserialize(deserializer).map(ArtifactReEvaluated::from)
    }
}

// ---------------------------------------------------------------------------
// ArtifactRejected
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactRejected {
    pub artifact_id: Uuid,
    pub rejected_by: RejectionReason,
    pub reason: String,
}

impl ArtifactRejected {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("reason", &self.reason, MAX_REASON_LEN)
    }
}

// ---------------------------------------------------------------------------
// ScanIndeterminate (fail-closed scanner, ADR 0007)
// ---------------------------------------------------------------------------

/// Terminal scan failure: every configured backend errored and the
/// job exhausted its retry budget. Recorded on `StreamCategory::Artifact`
/// alongside the `QuarantineStatus -> ScanIndeterminate` transition via
/// `ArtifactLifecyclePort::commit_transition_with_score`. Fail-closed
/// (ADR 0007).
///
/// **Not a reuse of [`ScanCompleted`].** A terminal-failure event has no
/// findings and no scanner verdict; forcing it through `ScanCompleted(0)`
/// would be indistinguishable from a clean scan (the audit/metrics
/// conflation this design forbids) and would poison the consumer's prior-scan
/// reverse index. A distinct event drives the distinct
/// [`QuarantineStatus::ScanIndeterminate`](crate::entities::artifact::QuarantineStatus::ScanIndeterminate)
/// state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanIndeterminate {
    pub artifact_id: Uuid,
    /// Comma-joined backend names that were attempted (e.g.
    /// `"trivy,osv"`). Mirrors [`ScanCompleted::scanner`] for audit
    /// symmetry; may be `"(none)"` if backend resolution itself failed.
    pub scanner: String,
    /// Operator-readable last error from the exhausted job, length-capped
    /// at `MAX_REASON_LEN` (same cap as [`ArtifactRejected::reason`]).
    pub reason: String,
    /// Attempts the job made before exhaustion (`job.attempts` at the
    /// moment of `mark_failed`). Audit-only; no invariant.
    pub attempts: u32,
}

impl ScanIndeterminate {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("scanner", &self.scanner, MAX_SCANNER_LEN)?;
        validate_string("reason", &self.reason, MAX_REASON_LEN)
    }
}

// ---------------------------------------------------------------------------
// ProvenanceVerified / ProvenanceRejected (ADR 0027)
// ---------------------------------------------------------------------------

/// A supply-chain provenance attestation was **verified** against the
/// policy's allowed signer identities (ADR 0027).
///
/// The tamper-evident success record. Recorded on
/// `StreamCategory::Artifact` alongside the artifact's lifecycle stream.
/// Like `ScanCompleted(clean)` it is a *success record only* — it does
/// **NOT** release the artifact early. Under `Required` mode the release
/// sweep reads "a `ProvenanceVerified` exists" to compute
/// [`ProvenanceClearance::Cleared`](crate::entities::artifact::ProvenanceClearance::Cleared);
/// the timer/scan gate is otherwise unchanged.
///
/// `signer` is the verified `{issuer, san}` identity; `predicate_type` is
/// the attestation predicate URI (e.g. `https://slsa.dev/provenance/v1`),
/// `None` for a bare signature with no structured predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceVerified {
    /// The artifact whose attestation was verified. Same UUID as the
    /// `entity_id` of the artifact stream this event lands on.
    pub artifact_id: Uuid,
    /// The CAS content hash whose attestation was verified.
    pub content_hash: ContentHash,
    /// The verifier backend that produced the verdict (`"cosign"`).
    pub backend: String,
    /// The verified signer identity (`{issuer, san}`).
    pub signer: SignerIdentity,
    /// The attestation predicate type URI, when the bundle carried a
    /// structured predicate.
    pub predicate_type: Option<String>,
}

impl ProvenanceVerified {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("backend", &self.backend, MAX_SCANNER_LEN)?;
        validate_string("signer.issuer", &self.signer.issuer, MAX_NAME_LEN)?;
        validate_string("signer.san", &self.signer.san, MAX_NAME_LEN)?;
        validate_optional_string("predicate_type", &self.predicate_type, MAX_NAME_LEN)?;
        Ok(())
    }
}

/// A supply-chain provenance check **rejected** the artifact (ADR 0027).
/// Drives `QuarantineStatus -> Rejected`
/// (`quarantine_status = 'rejected'`), terminal under the release
/// surfaces — like `ScanCompleted(findings)`.
///
/// Emitted under `VerifyIfPresent` when a present bundle is forged /
/// untrusted, and under `Required` for both that case and the
/// unsigned-but-required case (`reason: Unsigned`). `reason` is the typed
/// [`ProvenanceRejectReason`] so an audit query can distinguish a forged
/// signature from a malformed bundle from an unsigned-under-`Required`
/// artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRejected {
    /// The artifact rejected. Same UUID as the `entity_id` of the
    /// artifact stream this event lands on.
    pub artifact_id: Uuid,
    /// The CAS content hash that failed verification.
    pub content_hash: ContentHash,
    /// The verifier backend that produced the verdict (`"cosign"`). May be
    /// `"(policy)"` for the `Required`-mode unsigned mapping, which the
    /// orchestrator derives without a backend verdict.
    pub backend: String,
    /// The typed rejection cause.
    pub reason: ProvenanceRejectReason,
}

impl ProvenanceRejected {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("backend", &self.backend, MAX_SCANNER_LEN)
    }
}

// ---------------------------------------------------------------------------
// ArtifactCorrupted
// ---------------------------------------------------------------------------

/// Recorded when the CAS integrity scrubber detects that a stored blob's
/// computed SHA-256 disagrees with its CAS key AND the operator has opted
/// into the `tombstone` action via `HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone`.
///
/// Companion to [`CasIntegrityMismatch`](super::cas_scrub_events::CasIntegrityMismatch):
/// the mismatch event is the audit-trail fact ("this blob's bytes no
/// longer match its key"); `ArtifactCorrupted` is the artifact-level
/// state transition ("this artifact has been moved to `rejected` because
/// its content is unreadable"). The two events are emitted on different
/// streams in the same scrub iteration: `CasIntegrityMismatch` lives on
/// the synthetic per-hash stream the existing flag-only scrubber uses;
/// `ArtifactCorrupted` lands on the artifact's own
/// `StreamCategory::Artifact` stream alongside the `quarantine_status`
/// transition recorded by [`crate::ports::artifact_lifecycle::ArtifactLifecyclePort::commit_transition`].
///
/// **Quarantine state vocabulary reuse:**
/// corruption is structurally identical to a disqualifying scan finding —
/// permanently bad content, time does not reverse it. The state machine
/// transitions the artifact to
/// [`QuarantineStatus::Rejected`](crate::entities::artifact::QuarantineStatus::Rejected),
/// reusing the existing vocabulary rather than introducing a fourth
/// status value. The admin-release override
/// (`POST /quarantine/:artifact_id/release`) provides the human-review
/// escape hatch for false-positive corruption (e.g. operator restored
/// the blob from a known-good backup). The policy-re-evaluation override
/// path is N/A — no policy can resolve a content-hash divergence.
///
/// **No PII or admin actor.** The scrub is a system-initiated cron job;
/// the actor on the persisted-event envelope is `Actor::Internal(System)`.
/// Operator-readable identity (which scrub run, which backend) is on the
/// companion `CasIntegrityMismatch` event's `backend` label and the
/// stream's stored `correlation_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactCorrupted {
    /// Foreign key to the `artifacts` row whose content failed
    /// re-verification. The same UUID is the entity_id of the artifact
    /// stream this event lands on.
    pub artifact_id: Uuid,
    /// SHA-256 the scrubber computed by re-streaming the bytes the
    /// storage adapter returned. Disagreed with `expected_hash`.
    pub computed_hash: ContentHash,
    /// SHA-256 the CAS layer claims for this content (the CAS key
    /// the scrubber walked into). Equal to the artifact row's
    /// `sha256_checksum` at the moment of emission.
    pub expected_hash: ContentHash,
    /// Server-wall-clock at the moment the scrubber detected the
    /// mismatch. The event store assigns its own `stored_at` on
    /// append; both are preserved (one is "the corruption was
    /// detected"; the other is "the audit log recorded it"). Same
    /// convention as `AdminBootstrapped.at` and
    /// `AdminPasswordRotated.at`.
    pub detected_at: DateTime<Utc>,
}

impl ArtifactCorrupted {
    /// Validate the event payload. Today there are no string fields to
    /// length-check — `artifact_id` is a `Uuid` (always 16 bytes),
    /// both hash fields are [`ContentHash`] (validated 64 hex chars by
    /// construction), and `detected_at` is a `DateTime<Utc>`
    /// (well-formed by construction). The method is kept for symmetry
    /// with the rest of the event vocabulary so the
    /// `DomainEvent::validate()` dispatch table doesn't need a
    /// special-case arm.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// Why an [`ArtifactRejected`] was emitted.
///
/// The name reflects that
/// the variant carries structured *reason* context — most notably the
/// retroactive-curation rule id that drove the transition. The
/// free-text [`ArtifactRejected::reason`] field stays as the operator-
/// readable description; this typed variant is the structured-audit
/// hook (event-store consumers query by variant kind, not by parsing
/// `reason`).
///
/// `Scanner` and `Admin` are unit variants — no extra context is needed
/// because the actor is already attached to the persisted event.
/// `CurationRetroactive` carries the matched rule id so an audit query
/// can show "this artifact was rejected by the retroactive evaluation
/// of rule X" without correlating across streams. `Curator`
/// carries the curator's user id so an audit query can show
/// "this artifact was manually blocked by curator X" without
/// correlating across streams — the typed payload mirrors the
/// `CurationRetroactive { rule_id }` shape (audit-query symmetry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    Scanner,
    Admin,
    /// Retroactive curation evaluation hit during gitops apply.
    /// Set by
    /// `ApplyConfigUseCase::apply_curation_rules` when a newly-created
    /// or tightened `CurationRule` matches a previously-active artifact.
    CurationRetroactive {
        rule_id: Uuid,
    },
    /// A retroactive **scan-policy** tighten re-held the artifact (ADR 0041).
    /// Set by the continuous-enforcement re-evaluation transition
    /// ([`crate::entities::artifact::Artifact::reject_from_scan_policy_retroactive`])
    /// when a gate-affecting `ScanPolicy` change re-derives a now-failing
    /// verdict from the artifact's *stored* findings and re-holds a
    /// previously `Released` / `Quarantined` artifact.
    ///
    /// A **unit variant** — symmetric to [`Scanner`](Self::Scanner): the
    /// policy that drove the tighten is attributed by the
    /// [`ArtifactReEvaluated`] audit event appended in the same
    /// `commit_transition` batch (its
    /// [`ReEvaluationTrigger::PolicyUpdated`] discriminator carries the
    /// policy-change event id), so a payload here would only duplicate
    /// that. Named distinctly from `Scanner` (a fresh-scan rejection) so
    /// an audit query can tell "a scanner found this bad at scan time"
    /// apart from "a *policy tighten* re-judged this artifact's stored
    /// evidence as now-failing" without parsing the free-text reason.
    ///
    /// **Scan-clearable (ADR 0041 invariant #6 (a)).** Like `Scanner`,
    /// this rejection is on the scan axis and a *later* policy loosen can
    /// re-release it — so
    /// [`re_evaluate`](crate::entities::artifact::Artifact::re_evaluate)'s
    /// eligibility guard admits it alongside `Scanner`. Distinct from
    /// `CurationRetroactive` (curation axis, NOT scan-clearable).
    ScanPolicyRetroactive,
    /// A curator (`Permission::Curate` or
    /// `Permission::Admin`) manually blocked the artifact via the
    /// `CurationUseCase::block` path. Carries the curator's user id so
    /// an audit query can attribute the decision without correlating
    /// across streams (mirrors the `CurationRetroactive { rule_id }`
    /// shape). Distinct from `Admin` — `Admin` is a unit variant
    /// reserved for admin-driven rejections outside the typed
    /// curator surface; `Curator { curator_id }` carries the typed
    /// curator attribution. The free-text
    /// [`ArtifactRejected::reason`] carries the curator's justification.
    Curator {
        curator_id: Uuid,
    },
}

// ---------------------------------------------------------------------------
// PromotionRequested
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionRequested {
    pub artifact_id: Uuid,
    pub source_repository_id: Uuid,
    pub target_repository_id: Uuid,
}

impl PromotionRequested {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PolicyEvaluated
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    pub artifact_id: Uuid,
    /// The policy that produced this evaluation. When the evaluator
    /// fell back to [`crate::policy::scan::DefaultPolicy`] because no
    /// operator policy was active for the artifact's repository, this
    /// is set to [`NO_POLICY`] — a sentinel `Uuid::nil()` whose
    /// purpose is structural (the schema column is `NOT NULL`, and
    /// the consumer-side audit must still attribute the decision
    /// somewhere). Hard-coding `Uuid::nil()` literals at every
    /// emission site invited drift; the constant collapses those into
    /// one named anchor that downstream code can match on.
    pub policy_id: Uuid,
    pub result: PolicyResult,
    pub violations: Vec<PolicyViolation>,
}

/// Sentinel `policy_id` used on `PolicyEvaluated` when the evaluator
/// fell back to the built-in default (no operator policy resolved for
/// the repository). Equal to `Uuid::nil()`; the schema requires the
/// column be `NOT NULL` so a typed `Option<Uuid>` would force a
/// migration. The sentinel is named to
/// make the "no policy" case greppable.
pub const NO_POLICY: Uuid = Uuid::nil();

impl PolicyEvaluated {
    pub fn validate(&self) -> DomainResult<()> {
        for v in &self.violations {
            v.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyResult {
    Pass,
    Fail,
}

/// One rule-failure record produced by a policy evaluator.
///
/// The typed `severity` drives the
/// [`crate::policy::ViolationsAccumulator`] escalation, `message`
/// remains the operator-readable summary, and `details` is the
/// structured-audit JSON blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Stable rule identifier — e.g. `"cve-severity-threshold"`,
    /// `"license-compliance"`, `"require-signature"`.
    pub rule: String,
    /// Severity of the offending finding. Drives the
    /// [`crate::policy::escalate_action_by_severity`] helper used by
    /// every accumulator.
    pub severity: SeverityThreshold,
    /// Operator-readable summary, e.g.
    /// `"Found 3 critical vulnerabilities (max allowed: 0)"`.
    pub message: String,
    /// Structured context for audit queries — counts, package names,
    /// matched exclusion ids, etc. Capped at
    /// [`MAX_VIOLATION_DETAILS_SIZE`] when serialised; default is
    /// `Value::Null` for evaluators that have no structured context.
    pub details: serde_json::Value,
}

impl PolicyViolation {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("rule", &self.rule, MAX_RULE_LEN)?;
        validate_string("message", &self.message, MAX_MESSAGE_LEN)?;
        validate_json(
            "details",
            &self.details,
            MAX_VIOLATION_DETAILS_SIZE,
            MAX_VIOLATION_DETAILS_DEPTH,
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ApprovalRequested
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequested {
    pub artifact_id: Uuid,
    pub source_repository_id: Uuid,
    pub target_repository_id: Uuid,
}

impl ApprovalRequested {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ApprovalDecided
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecided {
    pub artifact_id: Uuid,
    pub decision: ApprovalDecision,
    pub notes: Option<String>,
}

impl ApprovalDecided {
    pub fn validate(&self) -> DomainResult<()> {
        validate_optional_string("notes", &self.notes, MAX_NOTES_LEN)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

// ---------------------------------------------------------------------------
// ArtifactPromoted
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactPromoted {
    pub artifact_id: Uuid,
    pub source_repository_id: Uuid,
    pub target_repository_id: Uuid,
}

impl ArtifactPromoted {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PromotionRejected
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionRejected {
    pub artifact_id: Uuid,
    pub source_repository_id: Uuid,
    pub target_repository_id: Uuid,
    pub reason: String,
}

impl PromotionRejected {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("reason", &self.reason, MAX_REASON_LEN)
    }
}

// ---------------------------------------------------------------------------
// ArtifactExpired
// ---------------------------------------------------------------------------

/// A retention policy fired and this artifact is now eligible for purge.
///
/// Lands on the **artifact** stream
/// ([`StreamCategory::Artifact`](super::StreamCategory::Artifact)). The
/// decision is recorded **before** any storage deletion so policy
/// evaluation is auditable independently of purge success — the
/// `RetentionUseCase` / `PurgeUseCase` two-stage split. The companion
/// terminal event is [`ArtifactPurged`]; an `ArtifactExpired` with no
/// following `ArtifactPurged` is the pending-purge work item the GC
/// algorithm consumes.
///
/// # Design-vs-code divergences (intentional)
///
/// - **`policy_id` / `actor` are `Uuid`, not `PolicyId` / `ActorId`.**
///   The design writes `policy_id: PolicyId` and `Manual { actor: ActorId }`,
///   but no `PolicyId` / `ActorId` newtype exists anywhere in the
///   shipped codebase — every event payload (incl. the
///   [`ExpirationReason`], and `StreamSealed.retention_policy_id` /
///   `actor_id`) carries raw `Uuid`. Matching the shipped convention.
/// - **`reason` reuses [`ExpirationReason`]** value object
///   from `crate::retention` rather than re-declaring the inline enum
///   the design sketches. `ExpirationReason` already shipped (its module
///   docstring explicitly states "the event type itself lands on the
///   artifact stream and is wired in the retention use case"); re-declaring
///   it would duplicate the variant set and its validation. The reason
///   object already carries the `SecurityFinding` snapshot
///   (`first_detected_at` / `latest_scan_at`), so the only payload-level
///   timestamp this event adds is `eligible_at`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactExpired {
    /// The artifact this expiry decision applies to. Same UUID as the
    /// `entity_id` of the artifact stream this event lands on.
    pub artifact_id: Uuid,
    /// The retention policy whose predicate matched (foreign key into
    /// the CRUD retention-policy store).
    pub policy_id: Uuid,
    /// Denormalised policy name captured at decision time — the policy
    /// row may be archived or renamed before an auditor reads this event.
    pub policy_name: String,
    /// The discriminated reason the policy marked this artifact eligible
    /// ([`ExpirationReason`]). Snapshots the inputs that drove
    /// the decision so an audit query never re-resolves projection rows
    /// that may have shifted since.
    pub reason: ExpirationReason,
    /// Wall-clock at which the artifact became eligible for purge — the
    /// policy-evaluation timestamp. Distinct from the event store's
    /// `stored_at` (one is "the policy decided"; the other is "the audit
    /// log recorded it"), matching the `ArtifactCorrupted.detected_at`
    /// convention.
    pub eligible_at: DateTime<Utc>,
}

impl ArtifactExpired {
    /// Validate the event payload.
    ///
    /// - `policy_name` is bounded (defence-in-depth against a malformed
    ///   emitter; reuses the shared `MAX_NAME_LEN` the rest of the
    ///   artifact-event vocabulary uses for denormalised names).
    /// - `reason` delegates to [`ExpirationReason::validate`] so the
    ///   reason invariants (non-empty `Manual` reason, self-consistent
    ///   `KeepLastN`, finite in-range `SecurityFinding` CVSS, …) are
    ///   enforced uniformly through the [`super::DomainEvent::validate`]
    ///   dispatch table.
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("policy_name", &self.policy_name, MAX_NAME_LEN)?;
        self.reason.validate()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArtifactPurged
// ---------------------------------------------------------------------------

/// The storage delete completed (or the blob was confirmed already
/// absent). Lands on the **artifact** stream
/// ([`StreamCategory::Artifact`](super::StreamCategory::Artifact))
/// terminating an [`ArtifactExpired`] work item.
///
/// `refs_remaining` is the GC algorithm's post-decrement
/// cross-`kind` refcount for `content_hash` (tied to
/// `content_references`): `0` means the blob itself was deleted;
/// `> 0` means a still-live reference (e.g. a promoted ref or an OCI
/// `oci_subject` row) keeps the blob alive and only **this** artifact's
/// reference was removed.
///
/// # Idempotency
///
/// Re-emitting `ArtifactPurged` on a storage-already-absent path is
/// **correct, not an error** (the storage adapter's `delete(H)` returns
/// success on a missing key). The pure domain layer only structurally
/// validates the payload; the *idempotency property* — re-applying an
/// `ArtifactPurged` to an already-purged artifact is a no-op that does
/// not corrupt the projected state — is exercised by the replay tests
/// in this module and is a stable invariant the app/adapter layers rely
/// on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactPurged {
    /// The artifact whose reference was removed. Same UUID as the
    /// `entity_id` of the artifact stream this event lands on.
    pub artifact_id: Uuid,
    /// The CAS content hash whose reference this purge removed. A
    /// [`ContentHash`] is 64 lowercase hex chars by construction, so no
    /// extra string bound is needed.
    pub content_hash: ContentHash,
    /// Cross-`kind` `content_references` count for `content_hash`
    /// **after** this artifact's reference was removed. `0`
    /// ⇒ the blob was deleted; `> 0` ⇒ the blob stays, this ref is gone.
    pub refs_remaining: u32,
    /// Wall-clock at which the purge (or already-absent confirmation)
    /// completed. Distinct from the event store's `stored_at`, same
    /// convention as [`ArtifactExpired::eligible_at`].
    pub purged_at: DateTime<Utc>,
}

impl ArtifactPurged {
    /// Validate the event payload. There are no string fields to
    /// length-check — `artifact_id` is a `Uuid`, `content_hash` is a
    /// [`ContentHash`] (64 hex chars by construction), `refs_remaining`
    /// is a `u32`, and `purged_at` is a `DateTime<Utc>` (all well-formed
    /// by construction). Kept for symmetry with the rest of the event
    /// vocabulary so the [`super::DomainEvent::validate`] dispatch table
    /// has a uniform arm (mirrors [`ArtifactCorrupted::validate`]).
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArtifactExpired / ArtifactPurged tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod retention_event_tests {
    use super::*;
    use crate::events::DomainEvent;
    use crate::retention::ExpirationReason;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn sha256() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    fn valid_expired() -> ArtifactExpired {
        ArtifactExpired {
            artifact_id: Uuid::nil(),
            policy_id: Uuid::nil(),
            policy_name: "90-day-age".into(),
            reason: ExpirationReason::AgeExceeded {
                published_at: ts(0),
                ttl_secs: 86_400,
            },
            eligible_at: ts(1000),
        }
    }

    fn valid_purged() -> ArtifactPurged {
        ArtifactPurged {
            artifact_id: Uuid::nil(),
            content_hash: sha256(),
            refs_remaining: 0,
            purged_at: ts(2000),
        }
    }

    // -- ArtifactExpired::validate — every branch -------------------------

    #[test]
    fn expired_validate_accepts_well_formed() {
        valid_expired()
            .validate()
            .expect("well-formed ArtifactExpired validates");
    }

    #[test]
    fn expired_validate_rejects_empty_policy_name() {
        let mut e = valid_expired();
        e.policy_name = String::new();
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("policy_name"));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn expired_validate_rejects_oversize_policy_name() {
        let mut e = valid_expired();
        // MAX_NAME_LEN is 1024 (shared artifact-event name cap).
        e.policy_name = "x".repeat(MAX_NAME_LEN + 1);
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("policy_name"));
        assert!(err.to_string().contains("maximum length"));
    }

    #[test]
    fn expired_validate_policy_name_at_limit_ok() {
        let mut e = valid_expired();
        e.policy_name = "x".repeat(MAX_NAME_LEN);
        e.validate().expect("policy_name at the cap is accepted");
    }

    #[test]
    fn expired_validate_delegates_to_reason_validate() {
        // A structurally-invalid reason (empty Manual reason) must
        // surface through ArtifactExpired::validate — proving the
        // delegation arm is wired, not just the policy_name check.
        let mut e = valid_expired();
        e.reason = ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: String::new(),
        };
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn expired_validate_propagates_security_finding_reason_invariant() {
        // Second reason-delegation path: a SecurityFinding with zero
        // findings violates the reason invariant; it must bubble up here too.
        let mut e = valid_expired();
        e.reason = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(9.0),
            finding_count: 0,
            fix_available: true,
            first_detected_at: ts(0),
            latest_scan_at: ts(10),
        };
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("at least one finding"));
    }

    // -- ArtifactPurged::validate ----------------------------------------

    #[test]
    fn purged_validate_always_ok() {
        valid_purged()
            .validate()
            .expect("ArtifactPurged has no validation failure mode");
        // Non-zero refs_remaining (blob kept) is equally valid — the
        // domain does not constrain the count; it is a recorded fact.
        let mut p = valid_purged();
        p.refs_remaining = 7;
        p.validate()
            .expect("refs_remaining > 0 is a valid recorded fact");
    }

    // -- serde round-trip (wire stability) -------------------------------

    #[test]
    fn expired_serde_round_trips_every_reason_variant() {
        let reasons = vec![
            ExpirationReason::AgeExceeded {
                published_at: ts(1),
                ttl_secs: 86_400,
            },
            ExpirationReason::UnusedTtl {
                last_downloaded_at: Some(ts(2)),
                ttl_secs: 3600,
            },
            ExpirationReason::UnusedTtl {
                last_downloaded_at: None,
                ttl_secs: 3600,
            },
            ExpirationReason::KeepLastN {
                keep: 3,
                total: 9,
                rank: 7,
            },
            ExpirationReason::Manual {
                actor: Uuid::nil(),
                reason: "decommission".into(),
            },
            ExpirationReason::SecurityFinding {
                max_severity: SeverityThreshold::Critical,
                max_cvss: Some(9.8),
                finding_count: 4,
                fix_available: true,
                first_detected_at: ts(0),
                latest_scan_at: ts(1000),
            },
        ];
        for reason in reasons {
            let mut e = valid_expired();
            e.reason = reason;
            let json = serde_json::to_value(&e).unwrap();
            let back: ArtifactExpired = serde_json::from_value(json).unwrap();
            assert_eq!(e, back);
        }
    }

    #[test]
    fn purged_serde_round_trips() {
        for refs in [0u32, 1, 42] {
            let mut p = valid_purged();
            p.refs_remaining = refs;
            let json = serde_json::to_value(&p).unwrap();
            let back: ArtifactPurged = serde_json::from_value(json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn round_trips_through_domain_event_envelope() {
        // Mirrors the adapter's `{type,data}` reshape (the in-domain
        // half of the deferred adapter round-trip): wrap each event in
        // DomainEvent, serialize, reshape, deserialize, compare.
        for ev in [
            DomainEvent::ArtifactExpired(valid_expired()),
            DomainEvent::ArtifactPurged(valid_purged()),
        ] {
            let event_type = ev.event_type();
            let v = serde_json::to_value(&ev).unwrap();
            let payload = match v {
                serde_json::Value::Object(mut m) => {
                    m.remove(event_type).unwrap_or(serde_json::Value::Null)
                }
                other => other,
            };
            let reshaped = serde_json::json!({ event_type: payload });
            let back: DomainEvent = serde_json::from_value(reshaped).unwrap();
            assert_eq!(ev, back);
            back.validate()
                .expect("round-tripped event still validates");
        }
    }

    #[test]
    fn debug_clone_eq_cover() {
        let a = DomainEvent::ArtifactExpired(valid_expired());
        let b = a.clone();
        assert_eq!(a, b);
        assert!(format!("{a:?}").contains("ArtifactExpired"));
        let p = DomainEvent::ArtifactPurged(valid_purged());
        assert_ne!(a, p);
        assert!(format!("{p:?}").contains("ArtifactPurged"));
        assert_eq!(a.event_type(), "ArtifactExpired");
        assert_eq!(p.event_type(), "ArtifactPurged");
    }

    // -- Replay / projection over a fixture artifact stream --------------
    //
    // Idempotency: `ArtifactPurged` is idempotent — re-emitting on a
    // storage-already-absent path is correct, not an error. Modelled as
    // a minimal pure fold (test-only; production projection is the
    // deferred app/adapter layer's job) over a stream that contains
    // BOTH `ArtifactExpired` and `ArtifactPurged`, asserting the
    // terminal projected state and that a duplicate `ArtifactPurged`
    // does not corrupt it.

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RetentionState {
        /// No retention event seen yet.
        Live,
        /// `ArtifactExpired` seen; pending purge (a GC work item).
        Expired,
        /// `ArtifactPurged` seen; terminal. `blob_deleted` records
        /// whether the last purge reported `refs_remaining == 0`.
        Purged { blob_deleted: bool },
    }

    /// Pure replay fold for the retention slice of an artifact stream.
    /// Idempotent on `ArtifactPurged`: applying it to an
    /// already-`Purged` state is a no-op-shaped transition that keeps
    /// the terminal state rather than erroring.
    fn project(events: &[DomainEvent]) -> RetentionState {
        let mut state = RetentionState::Live;
        for e in events {
            state = match (e, &state) {
                (DomainEvent::ArtifactExpired(_), RetentionState::Live) => RetentionState::Expired,
                (DomainEvent::ArtifactPurged(p), _) => RetentionState::Purged {
                    blob_deleted: p.refs_remaining == 0,
                },
                // Any other event leaves the retention slice unchanged.
                _ => state,
            };
        }
        state
    }

    #[test]
    fn replay_expired_then_purged_reaches_terminal_state() {
        let stream = vec![
            DomainEvent::ArtifactExpired(valid_expired()),
            DomainEvent::ArtifactPurged(valid_purged()),
        ];
        assert_eq!(
            project(&stream),
            RetentionState::Purged { blob_deleted: true }
        );
    }

    #[test]
    fn replay_blob_kept_when_refs_remaining_positive() {
        let mut kept = valid_purged();
        kept.refs_remaining = 2;
        let stream = vec![
            DomainEvent::ArtifactExpired(valid_expired()),
            DomainEvent::ArtifactPurged(kept),
        ];
        assert_eq!(
            project(&stream),
            RetentionState::Purged {
                blob_deleted: false
            }
        );
    }

    #[test]
    fn replay_duplicate_purged_is_idempotent() {
        // Idempotency — a second ArtifactPurged (storage already
        // absent on a retried sweep) must not corrupt the terminal
        // state. The projection stays Purged.
        let stream = vec![
            DomainEvent::ArtifactExpired(valid_expired()),
            DomainEvent::ArtifactPurged(valid_purged()),
            DomainEvent::ArtifactPurged(valid_purged()),
        ];
        assert_eq!(
            project(&stream),
            RetentionState::Purged { blob_deleted: true }
        );
        // And the duplicate is independently a valid event.
        DomainEvent::ArtifactPurged(valid_purged())
            .validate()
            .expect("duplicate ArtifactPurged is valid (idempotent path)");
    }

    #[test]
    fn replay_unrelated_events_do_not_advance_retention_slice() {
        let stream = vec![
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: Uuid::nil(),
                quarantine_window_start: ts(5),
            }),
            DomainEvent::ArtifactExpired(valid_expired()),
            DomainEvent::ScanRequested(ScanRequested {
                artifact_id: Uuid::nil(),
                scanner: "trivy".into(),
            }),
        ];
        // Expired reached, not yet purged; the interleaved non-retention
        // events leave the slice at Expired.
        assert_eq!(project(&stream), RetentionState::Expired);
    }

    #[test]
    fn replay_empty_stream_is_live() {
        assert_eq!(project(&[]), RetentionState::Live);
    }
}

// ---------------------------------------------------------------------------
// ArtifactReEvaluated widening + serde back-compat tests (ADR 0041 Item 1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod re_evaluated_event_tests {
    use super::*;
    use crate::events::DomainEvent;

    fn nil() -> Uuid {
        Uuid::nil()
    }

    fn sample(trigger: ReEvaluationTrigger) -> ArtifactReEvaluated {
        ArtifactReEvaluated {
            artifact_id: Uuid::from_u128(1),
            policy_id: Uuid::from_u128(2),
            trigger,
            previous_status: QuarantineStatus::Rejected,
            new_status: QuarantineStatus::Released,
        }
    }

    // ---- new shape round-trips for every trigger variant ----

    #[test]
    fn new_shape_round_trips_every_trigger_variant() {
        let triggers = [
            ReEvaluationTrigger::ExclusionAdded {
                exclusion_id: Uuid::from_u128(10),
            },
            ReEvaluationTrigger::ExclusionRemoved {
                exclusion_id: Uuid::from_u128(11),
            },
            ReEvaluationTrigger::PolicyUpdated {
                policy_id: Uuid::from_u128(12),
            },
        ];
        for trigger in triggers {
            let ev = sample(trigger);
            let json = serde_json::to_value(&ev).unwrap();
            // Serialisation emits the new `trigger` key, never the legacy
            // `trigger_exclusion_id`.
            assert!(json.get("trigger").is_some(), "new shape carries `trigger`");
            assert!(
                json.get("trigger_exclusion_id").is_none(),
                "new shape must NOT carry the legacy `trigger_exclusion_id`"
            );
            let back: ArtifactReEvaluated = serde_json::from_value(json).unwrap();
            assert_eq!(ev, back);
            assert_eq!(back.trigger, trigger);
        }
    }

    // ---- legacy shape (bare trigger_exclusion_id) still deserialises ----

    #[test]
    fn legacy_shape_deserialises_to_exclusion_added() {
        // The exact wire form a pre-ADR-0041 event was persisted with: a
        // bare `trigger_exclusion_id`, NO `trigger` key (append-only,
        // ADR 0002 — past events are never rewritten).
        let legacy = serde_json::json!({
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "policy_id": "00000000-0000-0000-0000-000000000002",
            "trigger_exclusion_id": "00000000-0000-0000-0000-00000000000a",
            "previous_status": "Rejected",
            "new_status": "Released",
        });
        let back: ArtifactReEvaluated = serde_json::from_value(legacy).unwrap();
        assert_eq!(
            back.trigger,
            ReEvaluationTrigger::ExclusionAdded {
                exclusion_id: Uuid::from_u128(10),
            },
            "a legacy trigger_exclusion_id maps onto ExclusionAdded"
        );
        assert_eq!(back.artifact_id, Uuid::from_u128(1));
        assert_eq!(back.policy_id, Uuid::from_u128(2));
        assert_eq!(back.previous_status, QuarantineStatus::Rejected);
        assert_eq!(back.new_status, QuarantineStatus::Released);
    }

    #[test]
    fn legacy_shape_round_trips_through_re_serialisation_to_new_shape() {
        // A legacy event read back and re-serialised emits the NEW shape
        // (forward migration on read; the stored event itself is untouched).
        let legacy = serde_json::json!({
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "policy_id": "00000000-0000-0000-0000-000000000002",
            "trigger_exclusion_id": "00000000-0000-0000-0000-00000000000a",
            "previous_status": "Rejected",
            "new_status": "Quarantined",
        });
        let parsed: ArtifactReEvaluated = serde_json::from_value(legacy).unwrap();
        let reserialised = serde_json::to_value(&parsed).unwrap();
        assert!(reserialised.get("trigger").is_some());
        assert!(reserialised.get("trigger_exclusion_id").is_none());
        // And it parses back to the same value (idempotent on the new shape).
        let back: ArtifactReEvaluated = serde_json::from_value(reserialised).unwrap();
        assert_eq!(parsed, back);
    }

    #[test]
    fn missing_both_trigger_fields_falls_back_to_nil_exclusion_added() {
        // Defence-in-depth: a malformed event carrying neither key still
        // materialises (a nil-id ExclusionAdded) rather than failing the
        // whole stream replay — an audit record must not vanish.
        let neither = serde_json::json!({
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "policy_id": "00000000-0000-0000-0000-000000000002",
            "previous_status": "Rejected",
            "new_status": "Released",
        });
        let back: ArtifactReEvaluated = serde_json::from_value(neither).unwrap();
        assert_eq!(
            back.trigger,
            ReEvaluationTrigger::ExclusionAdded {
                exclusion_id: nil()
            }
        );
    }

    #[test]
    fn new_trigger_takes_precedence_over_a_stray_legacy_field() {
        // If both keys are present (should never happen in practice), the
        // current `trigger` wins — the `From` resolves it first.
        let both = serde_json::json!({
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "policy_id": "00000000-0000-0000-0000-000000000002",
            "trigger": { "PolicyUpdated": { "policy_id": "00000000-0000-0000-0000-00000000000c" } },
            "trigger_exclusion_id": "00000000-0000-0000-0000-00000000000a",
            "previous_status": "Released",
            "new_status": "Rejected",
        });
        let back: ArtifactReEvaluated = serde_json::from_value(both).unwrap();
        assert_eq!(
            back.trigger,
            ReEvaluationTrigger::PolicyUpdated {
                policy_id: Uuid::from_u128(12),
            },
        );
    }

    #[test]
    fn round_trips_through_domain_event_envelope() {
        // Mirrors the adapter's `{type,data}` reshape for the widened event.
        let ev = DomainEvent::ArtifactReEvaluated(sample(ReEvaluationTrigger::ExclusionRemoved {
            exclusion_id: Uuid::from_u128(11),
        }));
        let event_type = ev.event_type();
        let v = serde_json::to_value(&ev).unwrap();
        let payload = match v {
            serde_json::Value::Object(mut m) => {
                m.remove(event_type).unwrap_or(serde_json::Value::Null)
            }
            other => other,
        };
        let reshaped = serde_json::json!({ event_type: payload });
        let back: DomainEvent = serde_json::from_value(reshaped).unwrap();
        assert_eq!(ev, back);
        back.validate().expect("widened event validates");
    }

    #[test]
    fn validate_is_ok_and_derives_cover() {
        let ev = sample(ReEvaluationTrigger::PolicyUpdated { policy_id: nil() });
        ev.validate().expect("pure metadata always validates");
        let cloned = ev.clone();
        assert_eq!(ev, cloned);
        assert!(format!("{ev:?}").contains("ArtifactReEvaluated"));
        // ReEvaluationTrigger derives (Debug/Clone/Copy/PartialEq/Eq).
        let t = ReEvaluationTrigger::ExclusionAdded {
            exclusion_id: nil(),
        };
        let t2 = t;
        assert_eq!(t, t2);
        assert_ne!(
            t,
            ReEvaluationTrigger::ExclusionRemoved {
                exclusion_id: nil()
            }
        );
        assert!(!format!("{t:?}").is_empty());
    }

    // ---- the new RejectionReason variant round-trips ----

    #[test]
    fn scan_policy_retroactive_rejection_reason_round_trips() {
        let reason = RejectionReason::ScanPolicyRetroactive;
        let json = serde_json::to_value(&reason).unwrap();
        // A unit variant serialises as the bare string discriminator.
        assert_eq!(json, serde_json::json!("ScanPolicyRetroactive"));
        let back: RejectionReason = serde_json::from_value(json).unwrap();
        assert_eq!(back, reason);
    }

    #[test]
    fn scan_policy_retroactive_round_trips_inside_artifact_rejected() {
        let ev = ArtifactRejected {
            artifact_id: Uuid::from_u128(1),
            rejected_by: RejectionReason::ScanPolicyRetroactive,
            reason: "tighten re-hold".into(),
        };
        ev.validate().expect("valid");
        let json = serde_json::to_value(&ev).unwrap();
        let back: ArtifactRejected = serde_json::from_value(json).unwrap();
        assert_eq!(ev, back);
        assert_eq!(back.rejected_by, RejectionReason::ScanPolicyRetroactive);
    }
}
