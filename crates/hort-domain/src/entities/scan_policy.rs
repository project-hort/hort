//! Scan-policy projection entities.
//!
//! These are the materialised read-model for the event-sourced
//! [`PolicyCreated`](crate::events::policy_events::PolicyCreated) /
//! [`PolicyUpdated`](crate::events::policy_events::PolicyUpdated) /
//! [`ExclusionAdded`](crate::events::policy_events::ExclusionAdded) /
//! [`ExclusionRemoved`](crate::events::policy_events::ExclusionRemoved) /
//! [`PolicyArchived`](crate::events::policy_events::PolicyArchived)
//! event family. The projection is updated synchronously by
//! `PolicyUseCase` after each successful event append so
//! `find_by_name` and `list_exclusions_for_policy` are O(1) reads
//! rather than stream replays. Out-of-band rebuild from the event
//! log is a future operational tool (see
//! `docs/architecture/explanation/event-sourcing.md`).
//!
//! `ScanPolicyProjection` derives [`Serialize`] but **not**
//! [`Deserialize`]: it is a server-internal read model. Diagnostic
//! logging needs the encode side; reconstruction comes from the
//! event stream + the SQL row, never from JSON over the wire.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};
use crate::events::PolicyScope;

// ---------------------------------------------------------------------------
// SeverityThreshold
// ---------------------------------------------------------------------------

/// The minimum CVSS severity that triggers policy enforcement.
///
/// Lowercase wire-form on parse and display so the YAML, JSON, and
/// SQL surfaces all share one spelling. The CHECK constraint on
/// `policy_projections.severity_threshold` (`005_policy.sql`) mirrors
/// the four variants exactly.
// `Deserialize` derive: required so `events::PolicyViolation`, which
// holds a `severity: SeverityThreshold` field, can roundtrip through the
// event store JSONB column. Additive only — no existing code path
// depended on the absence of `Deserialize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeverityThreshold {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for SeverityThreshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => f.write_str("critical"),
            Self::High => f.write_str("high"),
            Self::Medium => f.write_str("medium"),
            Self::Low => f.write_str("low"),
        }
    }
}

impl FromStr for SeverityThreshold {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            _ => Err(DomainError::Validation(format!(
                "unknown severity threshold: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceMode (ADR 0027)
// ---------------------------------------------------------------------------

/// Per-policy supply-chain **provenance** enforcement mode (ADR 0027).
///
/// Tri-state because provenance is **sparse and heterogeneous** across a
/// proxied catalog: a blanket "require" would block the unsigned
/// majority — unusable for the proxy case.
///
/// - [`Off`](Self::Off) — no verification; provenance never gates release.
/// - [`VerifyIfPresent`](Self::VerifyIfPresent) — **the default**.
///   Verify when a bundle is present; a forged / untrusted signature is a
///   rejection, but an *unsigned* artifact is allowed and provenance
///   **never gates release** (fail-safe — a free tamper-detection win
///   where a verifier is deployed, a no-op where one isn't).
/// - [`Required`](Self::Required) — block unsigned/unverified. Adds an
///   AND-precondition on the *timer* release arm (a `ProvenanceVerified`
///   event must exist); never a new `ReleaseAuthorization`, never blocks
///   an explicit Admin/Curator/PolicyReEval release.
///
/// Lowercase wire-form on parse and display (mirrors [`SeverityThreshold`])
/// so the YAML, JSON, and SQL surfaces share one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum ProvenanceMode {
    /// No provenance verification; the field is inert for this scope.
    Off,
    /// Default — verify if a bundle is present, allow unsigned, never gate
    /// release. Only ever *adds* a rejection on a forged signature.
    #[default]
    VerifyIfPresent,
    /// Require a verified provenance attestation; gate the timer release
    /// arm until a `ProvenanceVerified` event exists.
    Required,
}

impl fmt::Display for ProvenanceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::VerifyIfPresent => f.write_str("verify_if_present"),
            Self::Required => f.write_str("required"),
        }
    }
}

impl FromStr for ProvenanceMode {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "verify_if_present" => Ok(Self::VerifyIfPresent),
            "required" => Ok(Self::Required),
            _ => Err(DomainError::Validation(format!(
                "unknown provenance mode: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// NegligibleAction
// ---------------------------------------------------------------------------

/// Per-policy steering of how **negligible / informational** findings
/// affect the release decision.
///
/// A finding lands on the non-enforcing `negligible` tier of
/// [`SeveritySummary`](crate::events::SeveritySummary) when it carries no
/// scored severity but an explicit informational classification from the
/// advisory DB (OSV `unmaintained` / `unsound` / `notice`). The CVE
/// tier-walk never enforces the negligible tier, so by default these
/// findings are non-blocking. `NegligibleAction` is the operator knob
/// that re-introduces enforcement when wanted.
///
/// - [`Ignore`](Self::Ignore) — **the default**. Negligible findings
///   never block and produce no violation. This is exactly the behaviour
///   of routing informational advisories onto the negligible tier:
///   `unmaintained != vulnerable` (matches cargo-audit's stance).
/// - [`Warn`](Self::Warn) — emit a `negligible-advisory` violation
///   collected as [`PolicyAction::Warn`](crate::policy::PolicyAction);
///   recorded for the audit trail but non-blocking in the v1 binary scan
///   path (same shape as the license-policy `Warn`).
/// - [`Block`](Self::Block) — emit a `negligible-advisory` violation
///   collected as [`PolicyAction::Block`](crate::policy::PolicyAction):
///   the artifact is rejected. Strict mode for operators who refuse
///   unmaintained / unsound dependencies.
///
/// Orthogonal to [`SeverityThreshold`]: a scored finding above the
/// threshold blocks regardless of `negligible_action`, and an excluded
/// finding is dropped before this knob is consulted.
///
/// Lowercase wire-form on parse and display (mirrors [`SeverityThreshold`]
/// and [`ProvenanceMode`]) so the YAML, JSON, and SQL surfaces share one
/// spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum NegligibleAction {
    /// Default — negligible / informational findings never block and
    /// produce no violation.
    #[default]
    Ignore,
    /// Emit a non-blocking `negligible-advisory` violation for the audit
    /// trail; the scan outcome stays clean.
    Warn,
    /// Emit a blocking `negligible-advisory` violation → the artifact is
    /// rejected.
    Block,
}

impl fmt::Display for NegligibleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ignore => f.write_str("ignore"),
            Self::Warn => f.write_str("warn"),
            Self::Block => f.write_str("block"),
        }
    }
}

impl FromStr for NegligibleAction {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ignore" => Ok(Self::Ignore),
            "warn" => Ok(Self::Warn),
            "block" => Ok(Self::Block),
            _ => Err(DomainError::Validation(format!(
                "unknown negligible action: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// SignerIdentityPattern (ADR 0027)
// ---------------------------------------------------------------------------

/// Maximum number of `provenance_identities` entries a single policy may
/// declare. Mirrored by the JSONB-shape CHECK on
/// `policy_projections.provenance_identities` (`005_policy.sql`). A small
/// cap: the allowed-signer set for one scope is a short curated list, not
/// an unbounded directory; an oversized list is an operator error (or an
/// attempt to defeat the any-signer apply-reject by enumerating noise).
pub const MAX_PROVENANCE_IDENTITIES: usize = 32;

/// Maximum byte length of a single `issuer` / `san` pattern. Bounds the
/// per-element JSONB-shape CHECK and the constructor validator so a
/// pathological pattern cannot bloat the policy row.
pub const MAX_SIGNER_PATTERN_LEN: usize = 512;

/// An **allowed-signer pattern** on a [`ScanPolicyProjection`] — the
/// `{issuer, san}` shape a candidate Sigstore signature must match one of
/// for the artifact to verify under `provenance_mode` (ADR 0027).
///
/// Distinct from [`crate::ports::provenance::SignerIdentity`],
/// which is a **concrete observed signer** carried on the
/// `ProvenanceVerified` event: this is the *policy pattern* an operator
/// declares (exact or bounded glob). The orchestrator passes the
/// resolved set of these into the verifier's
/// [`ProvenanceRequirements`](crate::ports::provenance::ProvenanceRequirements).
///
/// Per-element constructor-validated (mirrors
/// `validate_upstream_name_prefix`): both fields are non-empty, within
/// [`MAX_SIGNER_PATTERN_LEN`], and free of control characters. The DB
/// JSONB-shape CHECK mirrors only the structural invariants (non-empty,
/// count cap); the constructor is the authoritative validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentityPattern {
    /// OIDC issuer URL pattern the signing certificate must have been
    /// minted against (exact or bounded glob, e.g.
    /// `https://token.actions.githubusercontent.com`).
    pub issuer: String,
    /// Certificate Subject Alternative Name pattern (the workload
    /// identity, exact or bounded glob).
    pub san: String,
}

impl SignerIdentityPattern {
    /// Construct an allowed-signer pattern, enforcing the per-element
    /// invariants. The production construction path — gitops apply,
    /// Postgres JSONB decode, and any future REST writer flow through
    /// here so a malformed pattern never reaches the verifier.
    ///
    /// Rejects (each its own [`DomainError::Validation`]):
    /// - an empty `issuer` or `san`,
    /// - an `issuer` / `san` longer than [`MAX_SIGNER_PATTERN_LEN`],
    /// - an `issuer` / `san` containing an ASCII control character
    ///   (a newline / NUL would corrupt the audit record and the
    ///   identity-match comparison).
    pub fn new(issuer: impl Into<String>, san: impl Into<String>) -> DomainResult<Self> {
        let issuer = issuer.into();
        let san = san.into();
        Self::validate_field("issuer", &issuer)?;
        Self::validate_field("san", &san)?;
        Ok(Self { issuer, san })
    }

    fn validate_field(field: &str, value: &str) -> DomainResult<()> {
        if value.is_empty() {
            return Err(DomainError::Validation(format!(
                "SignerIdentityPattern.{field} must not be empty"
            )));
        }
        if value.len() > MAX_SIGNER_PATTERN_LEN {
            return Err(DomainError::Validation(format!(
                "SignerIdentityPattern.{field} must be <= {MAX_SIGNER_PATTERN_LEN} \
                 bytes; got {}",
                value.len()
            )));
        }
        if value.chars().any(char::is_control) {
            return Err(DomainError::Validation(format!(
                "SignerIdentityPattern.{field} must not contain control characters"
            )));
        }
        Ok(())
    }

    /// Whether an **observed** signer identity (`issuer` + `san`, read out
    /// of a verified Fulcio leaf certificate by the Sigstore adapter)
    /// matches this allowed-signer pattern.
    ///
    /// **Both** fields must match for the identity to be accepted — the
    /// `issuer` pattern against the observed OIDC issuer **and** the `san`
    /// pattern against the observed Subject Alternative Name. A match on
    /// only one is a miss (an attacker who controls a trusted *issuer* but
    /// not the *workload identity*, or vice versa, must not pass).
    ///
    /// Matching is **exact-or-bounded-glob** via the crate-canonical
    /// [`crate::policy::exclusion::pattern_matches`] engine (the same
    /// `*`-only matcher the curation exclusions and the retention
    /// `PackageNamePattern` use — one pattern surface, one
    /// engine): `*` matches any (possibly empty) substring, every other
    /// byte is literal. The matcher is linear-backtracking and obviously
    /// terminating (no regex / no ReDoS surface); the per-element length
    /// cap ([`MAX_SIGNER_PATTERN_LEN`]) bounds its worst case.
    ///
    /// A pattern with no `*` degrades to exact equality — so an operator
    /// who declares a fully-literal `{issuer, san}` gets exact matching,
    /// and the bounded glob is opt-in via an explicit `*`.
    pub fn matches(&self, issuer: &str, san: &str) -> bool {
        crate::policy::exclusion::pattern_matches(&self.issuer, issuer)
            && crate::policy::exclusion::pattern_matches(&self.san, san)
    }
}

// ---------------------------------------------------------------------------
// Provenance config validation hooks (ADR 0027 + ADR 0015)
// ---------------------------------------------------------------------------

/// A non-fatal provenance-config signal surfaced by
/// [`ScanPolicyProjection::validate_provenance_config`] — the
/// apply-time linter renders these as operator warnings (apply still
/// succeeds). The pure-domain hook reports them; the wiring lives in the
/// application layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceConfigWarning {
    /// `VerifyIfPresent` with an empty `provenance_identities`: the policy
    /// detects *tampering* (a forged/untrusted signature is rejected) but
    /// cannot enforce *which* signer is trusted. Often intended, hence a
    /// warning rather than a reject.
    VerifyIfPresentWithoutIdentities,
}

/// A fail-closed provenance-config violation surfaced by
/// [`ScanPolicyProjection::validate_provenance_config`] — the
/// apply-time linter renders these as apply rejections (ADR 0015:
/// a field accepted at apply must never be inert at runtime).
/// The keyed-cosign provenance backend name (ADR 0039) — the value in
/// [`ScanPolicyProjection::provenance_backends`] that selects the
/// pinned-public-key verifier. Single-sourced here (a policy-config concept)
/// and re-used by the `cosign-key` adapter's `ProvenancePort::name()`. The
/// keyed model anchors on a pinned public key, NOT `provenance_identities`.
pub const COSIGN_KEY_BACKEND: &str = "cosign-key";

/// Pure-domain hooks the linter consumes; one variant (`Required` on a
/// no-verifier scope) is deliberately *not* here because it needs the
/// registered-port set, which is an application-layer concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceConfigError {
    /// `provenance_mode != Off` with an empty `provenance_backends`: there
    /// is no verifier to run, so the mode is inert. Reject.
    NonOffWithoutBackends,
    /// `Required` with an empty `provenance_identities` **on a scope that runs
    /// an identity-model backend** (e.g. keyless `cosign`): every signature
    /// would match (the any-signer footgun). A `cosign-key`-only scope does NOT
    /// trip this — its pinned key is the anchor (enforced at worker boot). Reject.
    RequiredWithoutIdentities,
    /// A keyed-ONLY scope (`provenance_backends` selects `cosign-key` and no
    /// identity-model backend) that sets a non-empty `provenance_identities`:
    /// the identity patterns are **inert** for the keyed backend (the pinned
    /// public key is the anchor, ADR 0039 §3/§4), so accepting-but-ignoring them
    /// is the accepted-at-apply/inert-at-runtime footgun (ADR 0015). Reject.
    KeyedBackendWithInertIdentities,
}

// ---------------------------------------------------------------------------
// ScanPolicyProjection
// ---------------------------------------------------------------------------

/// Materialised current state of one scan policy.
///
/// `stream_version` is the post-append `AppendResult.stream_position`
/// that produced this row — `PolicyUseCase` writes the projection +
/// the event in lockstep so this version drives
/// [`ExpectedVersion::Exact`](crate::ports::event_store::ExpectedVersion::Exact)
/// on the next mutation. The gitops diff-and-emit machinery
/// reads `stream_version` to detect a concurrent imperative append
/// between projection-read and event-append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanPolicyProjection {
    pub policy_id: Uuid,
    pub name: String,
    pub scope: PolicyScope,
    pub severity_threshold: SeverityThreshold,
    pub quarantine_duration_secs: i64,
    pub require_approval: bool,
    /// Per-policy supply-chain provenance enforcement mode (ADR 0027).
    /// Default [`ProvenanceMode::VerifyIfPresent`].
    pub provenance_mode: ProvenanceMode,
    /// Names of the provenance verifier backends this
    /// policy runs, in declared order (mirrors [`scan_backends`]). Each
    /// entry must match a `ProvenancePort` registered in the worker
    /// (`name()`, e.g. `"cosign"`). Default `["cosign"]`. An empty `Vec`
    /// is permitted **only** when `provenance_mode == Off`; `mode != Off`
    /// with `[]` is an apply-time reject (the inert-mode footgun,
    /// surfaced via [`ScanPolicyProjection::validate_provenance_config`]).
    ///
    /// [`scan_backends`]: ScanPolicyProjection::scan_backends
    pub provenance_backends: Vec<String>,
    /// The allowed-signer patterns a verified signature
    /// must match one of (per-element constructor-validated via
    /// [`SignerIdentityPattern::new`]). Stored as a JSONB column. Under
    /// `Required` an empty list is an apply-time reject (any-signer
    /// footgun); under `VerifyIfPresent` an empty list is an apply-time
    /// warn (tampering-only detection) — both surfaced via
    /// [`ScanPolicyProjection::validate_provenance_config`].
    pub provenance_identities: Vec<SignerIdentityPattern>,
    pub max_artifact_age_secs: Option<i64>,
    pub license_policy: serde_json::Value,
    pub archived: bool,
    /// Names of the scanner backends this policy
    /// invokes per scan, in declared order. Each entry must match a
    /// backend registered in `scanner_registry` (validated at gitops
    /// apply time against the live worker registry, see
    /// `docs/architecture/explanation/scanning-pipeline.md`).
    /// An empty `Vec` means "no scanning"; a missing field in YAML
    /// defaults to `vec!["trivy"]` ([`crate::policy::scan::DefaultPolicy::block_on_critical_default_backends`]).
    /// `ScanOrchestrationUseCase` reads this field to dispatch
    /// scanners; it does NOT fall back to a global config knob.
    pub scan_backends: Vec<String>,
    /// Interval in hours between bulk re-scans of
    /// artifacts governed by this policy. The cron-rescan-tick handler
    /// reads this field per-policy; an artifact is
    /// eligible for re-enqueue when `now() - last_scan_at >
    /// rescan_interval_hours`.
    ///
    /// Default 24h ([`crate::policy::scan::DefaultPolicy::rescan_interval_hours`]).
    /// Apply-pipeline validation rejects negative values. The value
    /// `0` is **explicitly meaningful**: it disables rescanning for
    /// every artifact governed by this policy — the cron handler's
    /// eligibility query filters `rescan_interval_hours > 0`, so a
    /// zero policy never produces re-enqueues regardless of how stale
    /// `last_scan_at` is.
    pub rescan_interval_hours: i32,
    /// How negligible / informational findings affect the release
    /// decision. Default [`NegligibleAction::Ignore`] — informational
    /// advisories (OSV `unmaintained` / `unsound` / `notice`) never
    /// block. `Warn` records a non-blocking `negligible-advisory`
    /// violation; `Block` rejects the artifact. Consumed by
    /// [`crate::policy::scan::evaluate_scan_result`] (NOT inert).
    pub negligible_action: NegligibleAction,
    /// Last appended position on the per-policy event stream. Drives
    /// optimistic-concurrency on the next event append.
    pub stream_version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScanPolicyProjection {
    /// Pure-domain provenance-config validation hooks the apply-time
    /// linter consumes (ADR 0027 + ADR 0015).
    ///
    /// Returns `Err(ProvenanceConfigError)` for a fail-closed apply
    /// reject, or `Ok(warnings)` (possibly empty) for an apply that
    /// succeeds, with any non-fatal signals the linter surfaces to the
    /// operator. The reject takes precedence — the first violation found
    /// short-circuits.
    ///
    /// **Encoded here (pure domain):**
    /// - `mode != Off` + empty `provenance_backends` ⇒
    ///   [`ProvenanceConfigError::NonOffWithoutBackends`] (reject).
    /// - `Required` + empty `provenance_identities` **on a scope with an
    ///   identity-model backend** (keyless `cosign`) ⇒
    ///   [`ProvenanceConfigError::RequiredWithoutIdentities`] (reject).
    /// - keyed-ONLY scope (`cosign-key`, no identity-model backend) + non-empty
    ///   `provenance_identities` ⇒
    ///   [`ProvenanceConfigError::KeyedBackendWithInertIdentities`] (reject —
    ///   ADR 0015 inert-field).
    /// - `VerifyIfPresent` + empty `provenance_identities` (identity-model
    ///   backend) ⇒
    ///   [`ProvenanceConfigWarning::VerifyIfPresentWithoutIdentities`] (warn).
    ///
    /// The keyed backend's positive "a pinned key is configured" requirement is
    /// enforced at **worker boot** (the verifier's `health_check` + the
    /// composition gate), NOT here — the key is a worker env, not a policy
    /// field, so it is invisible to this pure-domain hook.
    ///
    /// **Deliberately NOT here:** `Required` on a scope whose format has
    /// no registered verifier — that needs the live registered-`ProvenancePort`
    /// set, an application-layer input, so the apply-time linter resolves
    /// it at apply. This hook is format-/registry-agnostic.
    pub fn validate_provenance_config(
        &self,
    ) -> Result<Vec<ProvenanceConfigWarning>, ProvenanceConfigError> {
        if self.provenance_mode != ProvenanceMode::Off && self.provenance_backends.is_empty() {
            return Err(ProvenanceConfigError::NonOffWithoutBackends);
        }

        // Per-backend identity model (ADR 0039 §4). The keyed `cosign-key`
        // backend anchors on a pinned public key, NOT `provenance_identities`;
        // every other backend (keyless `cosign`) uses the identity-pattern
        // model. So the identity rules below fire only when an identity-model
        // backend is present.
        let has_identity_backend = self
            .provenance_backends
            .iter()
            .any(|b| b != COSIGN_KEY_BACKEND);
        let has_keyed_backend = self
            .provenance_backends
            .iter()
            .any(|b| b == COSIGN_KEY_BACKEND);
        let identities_empty = self.provenance_identities.is_empty();

        // Inert-field reject (ADR 0015): a keyed-ONLY scope must not set
        // `provenance_identities` — they are silently ignored for `cosign-key`
        // (the pinned key is the anchor). A mixed cosign + cosign-key scope is
        // fine (identities are load-bearing for the cosign leg).
        if has_keyed_backend && !has_identity_backend && !identities_empty {
            return Err(ProvenanceConfigError::KeyedBackendWithInertIdentities);
        }

        let mut warnings = Vec::new();
        match self.provenance_mode {
            // The any-signer footgun is an identity-model concern: a
            // `cosign-key`-only Required scope is gated by its pinned key at
            // worker boot (no identities to require), so it does NOT trip this.
            ProvenanceMode::Required if has_identity_backend && identities_empty => {
                return Err(ProvenanceConfigError::RequiredWithoutIdentities);
            }
            ProvenanceMode::VerifyIfPresent if has_identity_backend && identities_empty => {
                warnings.push(ProvenanceConfigWarning::VerifyIfPresentWithoutIdentities);
            }
            _ => {}
        }
        Ok(warnings)
    }
}

// ---------------------------------------------------------------------------
// ExclusionProjection
// ---------------------------------------------------------------------------

/// Materialised current state of one exclusion attached to a scan
/// policy. Exclusions are sub-state of their parent policy and live
/// on the same event stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExclusionProjection {
    pub exclusion_id: Uuid,
    pub policy_id: Uuid,
    pub cve_id: String,
    pub package_pattern: Option<String>,
    pub scope: PolicyScope,
    pub reason: String,
    /// Envelope-side author attribution sourced from
    /// the `ExclusionAdded` event's persisted actor. `Some(user_id)`
    /// when `actor_type='api'`, `None` for non-api envelopes (system /
    /// timer / gitops). Read by `CurationExclusionsRepository`
    /// (active-exclusions listing). `ExclusionAdded` payload carries
    /// NO actor field; envelope is canonical and the projection
    /// materialises the value for the read path.
    pub added_by_actor_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SeverityThreshold round-trip ----

    #[test]
    fn severity_threshold_critical_round_trip() {
        let v = SeverityThreshold::Critical;
        assert_eq!(v.to_string(), "critical");
        assert_eq!(SeverityThreshold::from_str("critical").expect("parse"), v);
    }

    #[test]
    fn severity_threshold_high_round_trip() {
        let v = SeverityThreshold::High;
        assert_eq!(v.to_string(), "high");
        assert_eq!(SeverityThreshold::from_str("high").expect("parse"), v);
    }

    #[test]
    fn severity_threshold_medium_round_trip() {
        let v = SeverityThreshold::Medium;
        assert_eq!(v.to_string(), "medium");
        assert_eq!(SeverityThreshold::from_str("medium").expect("parse"), v);
    }

    #[test]
    fn severity_threshold_low_round_trip() {
        let v = SeverityThreshold::Low;
        assert_eq!(v.to_string(), "low");
        assert_eq!(SeverityThreshold::from_str("low").expect("parse"), v);
    }

    #[test]
    fn severity_threshold_parse_is_case_insensitive() {
        assert_eq!(
            SeverityThreshold::from_str("CRITICAL").expect("parse"),
            SeverityThreshold::Critical
        );
        assert_eq!(
            SeverityThreshold::from_str("High").expect("parse"),
            SeverityThreshold::High
        );
    }

    #[test]
    fn severity_threshold_parse_unknown_is_validation_error() {
        let err =
            SeverityThreshold::from_str("nuclear").expect_err("unknown threshold must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("nuclear"), "msg should echo input: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn severity_threshold_parse_empty_is_validation_error() {
        let err = SeverityThreshold::from_str("").expect_err("empty must reject");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ---- ProvenanceMode (ADR 0027) ----

    #[test]
    fn provenance_mode_default_is_verify_if_present() {
        // The load-bearing default (ADR 0027): fail-safe — never
        // blocks, a free tamper-detection win where a verifier is deployed.
        assert_eq!(ProvenanceMode::default(), ProvenanceMode::VerifyIfPresent);
    }

    #[test]
    fn provenance_mode_round_trips_every_variant() {
        for (variant, wire) in [
            (ProvenanceMode::Off, "off"),
            (ProvenanceMode::VerifyIfPresent, "verify_if_present"),
            (ProvenanceMode::Required, "required"),
        ] {
            assert_eq!(variant.to_string(), wire);
            assert_eq!(ProvenanceMode::from_str(wire).expect("parse"), variant);
        }
    }

    #[test]
    fn provenance_mode_parse_is_case_insensitive() {
        assert_eq!(
            ProvenanceMode::from_str("OFF").expect("parse"),
            ProvenanceMode::Off
        );
        assert_eq!(
            ProvenanceMode::from_str("Verify_If_Present").expect("parse"),
            ProvenanceMode::VerifyIfPresent
        );
        assert_eq!(
            ProvenanceMode::from_str("REQUIRED").expect("parse"),
            ProvenanceMode::Required
        );
    }

    #[test]
    fn provenance_mode_parse_unknown_is_validation_error() {
        let err = ProvenanceMode::from_str("paranoid").expect_err("unknown mode must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("paranoid"), "msg should echo input: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn provenance_mode_parse_empty_is_validation_error() {
        let err = ProvenanceMode::from_str("").expect_err("empty must reject");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn provenance_mode_serde_round_trips() {
        for m in [
            ProvenanceMode::Off,
            ProvenanceMode::VerifyIfPresent,
            ProvenanceMode::Required,
        ] {
            let json = serde_json::to_string(&m).expect("serialize");
            let back: ProvenanceMode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(m, back);
        }
    }

    // ---- NegligibleAction ----

    #[test]
    fn negligible_action_default_is_ignore() {
        // The load-bearing default: informational advisories stay
        // non-blocking unless an operator opts into Warn/Block.
        assert_eq!(NegligibleAction::default(), NegligibleAction::Ignore);
    }

    #[test]
    fn negligible_action_round_trips_every_variant() {
        for (variant, wire) in [
            (NegligibleAction::Ignore, "ignore"),
            (NegligibleAction::Warn, "warn"),
            (NegligibleAction::Block, "block"),
        ] {
            assert_eq!(variant.to_string(), wire);
            assert_eq!(NegligibleAction::from_str(wire).expect("parse"), variant);
        }
    }

    #[test]
    fn negligible_action_parse_is_case_insensitive() {
        assert_eq!(
            NegligibleAction::from_str("IGNORE").expect("parse"),
            NegligibleAction::Ignore
        );
        assert_eq!(
            NegligibleAction::from_str("Warn").expect("parse"),
            NegligibleAction::Warn
        );
        assert_eq!(
            NegligibleAction::from_str("BLOCK").expect("parse"),
            NegligibleAction::Block
        );
    }

    #[test]
    fn negligible_action_parse_unknown_is_validation_error() {
        let err = NegligibleAction::from_str("nuke").expect_err("unknown action must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("nuke"), "msg should echo input: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn negligible_action_parse_empty_is_validation_error() {
        let err = NegligibleAction::from_str("").expect_err("empty must reject");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn negligible_action_serde_round_trips() {
        for a in [
            NegligibleAction::Ignore,
            NegligibleAction::Warn,
            NegligibleAction::Block,
        ] {
            let json = serde_json::to_string(&a).expect("serialize");
            let back: NegligibleAction = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(a, back);
        }
    }

    // ---- ScanPolicyProjection clone/eq/Serialize ----

    fn sample_projection() -> ScanPolicyProjection {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("fixed timestamp");
        ScanPolicyProjection {
            policy_id: Uuid::nil(),
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
            negligible_action: NegligibleAction::Ignore,
            stream_version: 7,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn scan_policy_projection_clone_preserves_fields() {
        let p = sample_projection();
        let cloned = p.clone();
        assert_eq!(p, cloned);
    }

    #[test]
    fn scan_policy_projection_field_assignment() {
        let mut p = sample_projection();
        p.archived = true;
        p.stream_version = 8;
        p.severity_threshold = SeverityThreshold::Critical;
        p.max_artifact_age_secs = None;
        assert!(p.archived);
        assert_eq!(p.stream_version, 8);
        assert_eq!(p.severity_threshold, SeverityThreshold::Critical);
        assert_eq!(p.max_artifact_age_secs, None);
    }

    #[test]
    fn scan_policy_projection_inequality_on_field_change() {
        let a = sample_projection();
        let mut b = a.clone();
        b.name = "other".into();
        assert_ne!(a, b);
    }

    #[test]
    fn scan_policy_projection_serialises_round_trip_via_json() {
        // Diagnostic logging path — Serialize must succeed for a
        // populated projection.
        let p = sample_projection();
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("\"name\":\"prod-default\""));
        assert!(json.contains("\"severity_threshold\":\"High\""));
        assert!(json.contains("\"stream_version\":7"));
    }

    // `scan_backends` field round-trips and is part
    // of equality.
    #[test]
    fn scan_policy_projection_scan_backends_serialises_under_snake_case_key() {
        let mut p = sample_projection();
        p.scan_backends = vec!["trivy".into(), "osv".into()];
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(
            json.contains("\"scan_backends\":[\"trivy\",\"osv\"]"),
            "scan_backends must surface under snake_case key: {json}"
        );
    }

    #[test]
    fn scan_policy_projection_scan_backends_change_breaks_equality() {
        let a = sample_projection();
        let mut b = a.clone();
        b.scan_backends = vec!["osv".into()];
        assert_ne!(a, b);
    }

    // `rescan_interval_hours` field round-trips through
    // serde and participates in equality.
    #[test]
    fn scan_policy_projection_rescan_interval_hours_serialises_under_snake_case_key() {
        let mut p = sample_projection();
        p.rescan_interval_hours = 48;
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(
            json.contains("\"rescan_interval_hours\":48"),
            "rescan_interval_hours must surface under snake_case key: {json}"
        );
    }

    #[test]
    fn scan_policy_projection_rescan_interval_hours_change_breaks_equality() {
        let a = sample_projection();
        let mut b = a.clone();
        b.rescan_interval_hours = 0;
        assert_ne!(a, b);
    }

    #[test]
    fn scan_policy_projection_rescan_interval_hours_zero_means_disabled() {
        // Documented sentinel — `0` is the operator opt-out value;
        // the cron-rescan eligibility query filters
        // `rescan_interval_hours > 0`, so this row is excluded.
        let mut p = sample_projection();
        p.rescan_interval_hours = 0;
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("\"rescan_interval_hours\":0"));
    }

    // `negligible_action` field round-trips through serde and
    // participates in equality. Default Ignore.
    #[test]
    fn scan_policy_projection_negligible_action_serialises_under_snake_case_key() {
        let mut p = sample_projection();
        p.negligible_action = NegligibleAction::Block;
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(
            json.contains("\"negligible_action\":\"Block\""),
            "negligible_action must surface under snake_case key: {json}"
        );
    }

    #[test]
    fn scan_policy_projection_negligible_action_change_breaks_equality() {
        let a = sample_projection();
        let mut b = a.clone();
        b.negligible_action = NegligibleAction::Warn;
        assert_ne!(a, b);
    }

    #[test]
    fn scan_policy_projection_repository_scope_distinguishes_from_global() {
        let repo_id = Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let mut p = sample_projection();
        p.scope = PolicyScope::Repository(repo_id);
        assert_ne!(p.scope, PolicyScope::Global);
    }

    // ---- SignerIdentityPattern (ADR 0027) ----

    fn sample_pattern() -> SignerIdentityPattern {
        SignerIdentityPattern::new(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
        )
        .expect("sample pattern is valid")
    }

    #[test]
    fn signer_identity_pattern_new_accepts_valid_issuer_san() {
        let p = sample_pattern();
        assert_eq!(p.issuer, "https://token.actions.githubusercontent.com");
        assert!(p.san.contains("release.yml"));
    }

    #[test]
    fn signer_identity_pattern_new_rejects_empty_issuer() {
        let err = SignerIdentityPattern::new("", "san").expect_err("empty issuer must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("issuer"), "msg should name issuer: {msg}");
                assert!(msg.contains("empty"), "msg should say empty: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn signer_identity_pattern_new_rejects_empty_san() {
        let err = SignerIdentityPattern::new("issuer", "").expect_err("empty san must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("san"), "msg should name san: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn signer_identity_pattern_new_rejects_oversize_issuer() {
        let big = "x".repeat(MAX_SIGNER_PATTERN_LEN + 1);
        let err = SignerIdentityPattern::new(big, "san").expect_err("oversize issuer must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("issuer"), "msg should name issuer: {msg}");
                assert!(msg.contains("512"), "msg should cite the cap: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn signer_identity_pattern_new_rejects_oversize_san() {
        let big = "y".repeat(MAX_SIGNER_PATTERN_LEN + 1);
        let err = SignerIdentityPattern::new("issuer", big).expect_err("oversize san must reject");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn signer_identity_pattern_new_rejects_control_character_in_issuer() {
        let err = SignerIdentityPattern::new("iss\nuer", "san")
            .expect_err("control char in issuer must reject");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("issuer"), "msg should name issuer: {msg}");
                assert!(msg.contains("control"), "msg should mention control: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn signer_identity_pattern_new_rejects_control_character_in_san() {
        let err = SignerIdentityPattern::new("issuer", "s\0an")
            .expect_err("control char in san must reject");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn signer_identity_pattern_accepts_max_len_boundary() {
        // Exactly at the cap is allowed (off-by-one guard on the `>` check).
        let at_cap = "z".repeat(MAX_SIGNER_PATTERN_LEN);
        let p = SignerIdentityPattern::new(at_cap.clone(), at_cap.clone())
            .expect("exactly-cap pattern is valid");
        assert_eq!(p.issuer.len(), MAX_SIGNER_PATTERN_LEN);
    }

    #[test]
    fn signer_identity_pattern_serde_round_trips() {
        let p = sample_pattern();
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("\"issuer\""));
        assert!(json.contains("\"san\""));
        let back: SignerIdentityPattern = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }

    // ---- SignerIdentityPattern::matches (ADR 0027) ----
    // Exact-or-bounded-glob; both fields must match. 100%-coverage-enforced.

    #[test]
    fn matches_exact_issuer_and_san_hit() {
        let p = sample_pattern();
        assert!(p.matches(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
        ));
    }

    #[test]
    fn matches_exact_issuer_miss() {
        let p = sample_pattern();
        // Right SAN, wrong issuer → miss (issuer must also match).
        assert!(!p.matches(
            "https://accounts.google.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
        ));
    }

    #[test]
    fn matches_exact_san_miss() {
        let p = sample_pattern();
        // Right issuer, wrong SAN → miss (san must also match).
        assert!(!p.matches(
            "https://token.actions.githubusercontent.com",
            "https://github.com/evil/repo/.github/workflows/release.yml@refs/heads/main",
        ));
    }

    #[test]
    fn matches_both_fields_miss() {
        let p = sample_pattern();
        assert!(!p.matches("https://accounts.google.com", "mallory@example.com"));
    }

    #[test]
    fn matches_wildcard_san_suffix_hit() {
        // A bounded glob on the SAN: any ref under the acme/repo release
        // workflow. The issuer is exact.
        let p = SignerIdentityPattern::new(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@*",
        )
        .expect("valid wildcard pattern");
        assert!(p.matches(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
        ));
    }

    #[test]
    fn matches_wildcard_san_suffix_miss_on_different_repo() {
        // The wildcard is bounded to acme/repo — a different repo path
        // before the `*` does NOT match (the literal prefix is enforced).
        let p = SignerIdentityPattern::new(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/repo/.github/workflows/release.yml@*",
        )
        .expect("valid wildcard pattern");
        assert!(!p.matches(
            "https://token.actions.githubusercontent.com",
            "https://github.com/evil/repo/.github/workflows/release.yml@refs/heads/main",
        ));
    }

    #[test]
    fn matches_wildcard_issuer_hit() {
        // Wildcard on the issuer (e.g. a self-hosted GitHub Enterprise
        // host prefix). SAN is exact.
        let p = SignerIdentityPattern::new("https://token.actions.*", "workload@example.com")
            .expect("valid wildcard issuer pattern");
        assert!(p.matches(
            "https://token.actions.ghe.example.com",
            "workload@example.com",
        ));
        // Issuer that does not share the literal prefix is a miss.
        assert!(!p.matches("https://evil.example.com", "workload@example.com"));
    }

    #[test]
    fn matches_lone_star_san_matches_any_san_but_issuer_still_pinned() {
        // A lone `*` SAN trusts any workload identity from the pinned
        // issuer — still requires the issuer match (the issuer is the
        // anchored half).
        let p = SignerIdentityPattern::new("https://accounts.google.com", "*")
            .expect("valid lone-star san pattern");
        assert!(p.matches("https://accounts.google.com", "anything@whatever"));
        assert!(!p.matches(
            "https://token.actions.githubusercontent.com",
            "anything@whatever"
        ));
    }

    #[test]
    fn matches_wildcard_in_middle_of_san() {
        let p = SignerIdentityPattern::new(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/*/.github/workflows/release.yml@refs/heads/main",
        )
        .expect("valid mid-wildcard pattern");
        assert!(p.matches(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/service-a/.github/workflows/release.yml@refs/heads/main",
        ));
        assert!(!p.matches(
            "https://token.actions.githubusercontent.com",
            "https://github.com/acme/service-a/.github/workflows/OTHER.yml@refs/heads/main",
        ));
    }

    // ---- validate_provenance_config (ADR 0027 + ADR 0015) ----

    #[test]
    fn validate_provenance_off_with_empty_backends_is_ok_no_warnings() {
        // mode == Off is the ONLY state permitting empty provenance_backends.
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Off;
        p.provenance_backends = Vec::new();
        p.provenance_identities = Vec::new();
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    #[test]
    fn validate_provenance_verify_if_present_with_empty_backends_rejects() {
        // mode != Off + empty backends => NonOffWithoutBackends (reject).
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::VerifyIfPresent;
        p.provenance_backends = Vec::new();
        assert_eq!(
            p.validate_provenance_config(),
            Err(ProvenanceConfigError::NonOffWithoutBackends)
        );
    }

    #[test]
    fn validate_provenance_required_with_empty_backends_rejects() {
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = Vec::new();
        p.provenance_identities = vec![sample_pattern()];
        // The backends check runs first and short-circuits.
        assert_eq!(
            p.validate_provenance_config(),
            Err(ProvenanceConfigError::NonOffWithoutBackends)
        );
    }

    #[test]
    fn validate_provenance_required_with_empty_identities_rejects() {
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = Vec::new();
        assert_eq!(
            p.validate_provenance_config(),
            Err(ProvenanceConfigError::RequiredWithoutIdentities)
        );
    }

    #[test]
    fn validate_provenance_required_with_identities_is_ok_no_warnings() {
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = vec![sample_pattern()];
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    // ---- ADR 0039 §4: per-backend identity model (cosign-key) ----

    #[test]
    fn validate_provenance_keyed_only_required_without_identities_is_ok() {
        // A cosign-key-ONLY scope under Required does NOT require identities —
        // the pinned key is the anchor (enforced at worker boot, not here).
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec![COSIGN_KEY_BACKEND.into()];
        p.provenance_identities = Vec::new();
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    #[test]
    fn validate_provenance_keyed_only_with_identities_rejects_inert() {
        // ADR 0015 inert-field: identities are inert for a keyed-only scope.
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec![COSIGN_KEY_BACKEND.into()];
        p.provenance_identities = vec![sample_pattern()];
        assert_eq!(
            p.validate_provenance_config(),
            Err(ProvenanceConfigError::KeyedBackendWithInertIdentities)
        );
    }

    #[test]
    fn validate_provenance_mixed_cosign_and_keyed_with_identities_is_ok() {
        // Identities are load-bearing for the cosign leg → non-empty is fine.
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".into(), COSIGN_KEY_BACKEND.into()];
        p.provenance_identities = vec![sample_pattern()];
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    #[test]
    fn validate_provenance_mixed_required_without_identities_rejects() {
        // The cosign leg still needs identities under Required.
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".into(), COSIGN_KEY_BACKEND.into()];
        p.provenance_identities = Vec::new();
        assert_eq!(
            p.validate_provenance_config(),
            Err(ProvenanceConfigError::RequiredWithoutIdentities)
        );
    }

    #[test]
    fn validate_provenance_keyed_only_verify_if_present_empty_identities_no_warn() {
        // No identity-model backend → no any-signer warn for a keyed-only scope.
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::VerifyIfPresent;
        p.provenance_backends = vec![COSIGN_KEY_BACKEND.into()];
        p.provenance_identities = Vec::new();
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    #[test]
    fn validate_provenance_verify_if_present_empty_identities_warns() {
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::VerifyIfPresent;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = Vec::new();
        assert_eq!(
            p.validate_provenance_config(),
            Ok(vec![
                ProvenanceConfigWarning::VerifyIfPresentWithoutIdentities
            ])
        );
    }

    #[test]
    fn validate_provenance_verify_if_present_with_identities_no_warning() {
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::VerifyIfPresent;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = vec![sample_pattern()];
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    #[test]
    fn validate_provenance_off_with_backends_and_identities_is_ok() {
        // Off short-circuits the identity arm: no warning even with empty
        // identities (provenance is fully inert in Off).
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Off;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = Vec::new();
        assert_eq!(p.validate_provenance_config(), Ok(Vec::new()));
    }

    #[test]
    fn scan_policy_projection_provenance_fields_serialise_under_snake_case_keys() {
        let mut p = sample_projection();
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".into()];
        p.provenance_identities = vec![sample_pattern()];
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(
            json.contains("\"provenance_mode\":\"Required\""),
            "provenance_mode must surface under snake_case key: {json}"
        );
        assert!(
            json.contains("\"provenance_backends\":[\"cosign\"]"),
            "provenance_backends must surface under snake_case key: {json}"
        );
        assert!(
            json.contains("\"provenance_identities\""),
            "provenance_identities must surface: {json}"
        );
    }

    #[test]
    fn scan_policy_projection_provenance_mode_change_breaks_equality() {
        let a = sample_projection();
        let mut b = a.clone();
        b.provenance_mode = ProvenanceMode::Required;
        assert_ne!(a, b);
    }

    #[test]
    fn provenance_config_warning_and_error_variants_round_trip_debug() {
        // Cover the Debug/Eq derives on the signal enums.
        let w = ProvenanceConfigWarning::VerifyIfPresentWithoutIdentities;
        assert_eq!(w, w);
        assert!(!format!("{w:?}").is_empty());
        for e in [
            ProvenanceConfigError::NonOffWithoutBackends,
            ProvenanceConfigError::RequiredWithoutIdentities,
        ] {
            assert_eq!(e, e);
            assert!(!format!("{e:?}").is_empty());
        }
    }

    // ---- ExclusionProjection clone/eq ----

    fn sample_exclusion() -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id: Uuid::from_u128(1),
            policy_id: Uuid::from_u128(2),
            cve_id: "CVE-2024-3094".into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            scope: PolicyScope::Global,
            reason: "patched in container layer".into(),
            added_by_actor_id: None,
            expires_at: DateTime::<Utc>::from_timestamp(1_800_000_000, 0),
        }
    }

    #[test]
    fn exclusion_projection_clone_preserves_fields() {
        let e = sample_exclusion();
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn exclusion_projection_inequality_on_field_change() {
        let a = sample_exclusion();
        let mut b = a.clone();
        b.cve_id = "CVE-2025-0001".into();
        assert_ne!(a, b);
    }

    #[test]
    fn exclusion_projection_optional_fields_default_to_none() {
        let mut e = sample_exclusion();
        e.package_pattern = None;
        e.expires_at = None;
        assert!(e.package_pattern.is_none());
        assert!(e.expires_at.is_none());
    }
}
