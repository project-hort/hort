//! # hort-app::metrics — label names, value constants, result enums
//!
//! This module owns the metric label names and result enum taxonomies emitted
//! by the application (use case) layer. It intentionally contains no emission
//! code — only canonical string constants and enums.
//!
//! The canonical metric catalog lives at `docs/metrics-catalog.md`. Every
//! string in this module corresponds to a row in that catalog. A new metric
//! name or label value requires a catalog update first.
//!
//! Layering:
//! - Domain (`hort-domain`) has no knowledge of metrics — pure Rust, zero I/O.
//! - Storage adapter and Postgres adapter each own their own result enums
//!   (`StorageResult`, `EventStoreResult`) in their own `metrics.rs` modules.
//!   5-10 variants of duplication is cheaper than a shared dependency that
//!   pulls metric concerns into the domain layer.

/// Label-name constants used as keys when emitting metrics with the `metrics`
/// crate macros. Using constants (rather than string literals at call sites)
/// prevents typos from silently producing a different time series.
pub mod labels {
    /// Package format, e.g. `"pypi"`, `"cargo"`, `"npm"`.
    pub const FORMAT: &str = "format";
    /// Repository key (or sentinel — see `super::values`).
    pub const REPOSITORY: &str = "repository";
    /// Outcome classification for a use-case operation.
    pub const RESULT: &str = "result";
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub const METHOD: &str = "method";
    /// Matched route template (not the concrete URL path).
    pub const PATH: &str = "path";
    /// HTTP status code.
    pub const STATUS: &str = "status";
    /// Upstream hostname for proxy/fetch operations.
    pub const UPSTREAM: &str = "upstream";
    /// Event category (`"artifact"`, `"policy"`).
    pub const CATEGORY: &str = "category";
    /// Reason label for quarantine-release metrics.
    pub const REASON: &str = "reason";
    /// Storage backend identifier (`"filesystem"`, `"s3"`, etc.).
    pub const BACKEND: &str = "backend";
    /// Low-level operation identifier (`"put"`, `"get"`, `"append"`, etc.).
    pub const OPERATION: &str = "operation";
    /// Metadata-persistence strategy picked per ingest. Values live in
    /// [`super::values::STRATEGY_INLINE`] / [`super::values::STRATEGY_HASH_REFERENCE`].
    pub const STRATEGY: &str = "strategy";
    /// Declarable-kind label on
    /// `hort_gitops_objects_total`. Values live in
    /// [`super::gitops_kind`].
    pub const KIND: &str = "kind";
    /// Domain-event discriminant label on
    /// `hort_gitops_events_emitted_total`. Values come from
    /// [`hort_domain::events::DomainEvent::event_type`], which returns
    /// `&'static str` from a static table — the bound is enforced at
    /// the type level by `emit_gitops_event`'s `&'static str` parameter
    /// rather than by an enumerated value module here.
    pub const EVENT_TYPE: &str = "event_type";
    /// Decision-point label on
    /// `hort_policy_evaluation_total` and `hort_policy_violations_total`.
    /// Values live in [`super::policy_decision_point`].
    pub const DECISION_POINT: &str = "decision_point";
    /// Rule label on
    /// `hort_policy_violations_total`. Values come from
    /// [`hort_domain::events::PolicyViolation::rule`] — every violation
    /// the domain accumulator produces carries a stable rule key.
    /// Non-enumerated rule strings collapse via the helper at the
    /// emission site (see [`super::emit_policy_violations`]).
    pub const RULE: &str = "rule";
    /// Actor-kind label on
    /// `hort_api_token_revoked_total`. Values: `"self"` (caller revoking
    /// their own token) / `"admin"` (caller revoking another user's
    /// token via admin authority). Closed taxonomy.
    pub const ACTOR_KIND: &str = "actor_kind";
    /// Cache hit/miss label on
    /// `hort_api_token_validation_total`. Values: `"hit"` (cache short-
    /// circuit) / `"miss"` (full Argon2id verify path). Closed taxonomy.
    pub const CACHE: &str = "cache";
    /// Distribution-Spec action label on
    /// `hort_oci_v2_auth_scope_actions_granted_total`. Values:
    /// `"pull"` / `"push"` / `"delete"`. Closed taxonomy bounded by the
    /// scope grammar parser.
    pub const ACTION: &str = "action";
    /// Scanner backend label on
    /// `hort_scan_findings_total` and `hort_scan_duration_seconds`. Values:
    /// `"trivy"`, `"osv"`, `"advisory"` (the sentinel for advisory-only
    /// findings — pre-scan enrichment that contributed without a
    /// scanner backend running). Closed taxonomy bounded by the
    /// `scanner_registry` table; new backends register a value here as
    /// they ship.
    pub const SCANNER: &str = "scanner";
    /// Severity tier label on
    /// `hort_scan_findings_total` and `hort_artifact_became_vulnerable_total`.
    /// Values: lowercase form of `SeverityThreshold` —
    /// `"critical"`, `"high"`, `"medium"`, `"low"`. Closed taxonomy.
    pub const SEVERITY: &str = "severity";
    /// `ingest_source` label on
    /// `hort_artifact_became_vulnerable_total`. Mirrors the
    /// `IngestSource` enum on `ArtifactIngested.source` —
    /// `"direct"` (client uploads) / `"proxied"` (pull-through).
    /// Closed taxonomy.
    pub const INGEST_SOURCE: &str = "ingest_source";
    /// `trigger_source` label on
    /// `hort_scan_jobs_enqueued_total`. Values come from
    /// [`hort_domain::ports::jobs_repository::TriggerSource::as_str`] —
    /// `"ingest"` / `"cron"` / `"advisory"` / `"manual"`. The wire
    /// strings mirror the SQL CHECK constraint on
    /// `jobs.trigger_source` verbatim. Closed taxonomy of 4.
    pub const TRIGGER_SOURCE: &str = "trigger_source";
    /// Per-OSV-ecosystem label on
    /// `hort_advisory_diff_processed_total` and
    /// `hort_advisory_diff_duration_seconds`. Values are the OSV
    /// bulk-archive labels (`"npm"`, `"PyPI"`, `"crates.io"`,
    /// `"Maven"`, `"Go"`, `"RubyGems"`, `"NuGet"`, `"Packagist"`,
    /// `"Hex"`, `"Pub"`, `"Conda"`); ~8 in the v1 default
    /// configuration. Closed taxonomy bounded by
    /// [`crate::metrics::AdvisoryDiffResult`]'s call-site contract:
    /// callers MUST pass the OSV-archive label string, not a free-form
    /// ecosystem name.
    pub const ECOSYSTEM: &str = "ecosystem";
    /// Per-ServiceAccount label on
    /// `hort_rotation_lag_seconds` (and
    /// `hort_service_account_authenticated_total`). Cardinality is
    /// bounded by the operator's declared SA count (typically <50);
    /// disable via `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false` at
    /// scale (the gauge then emits `service_account="_all"`, mirroring
    /// the existing `REPOSITORY_ALL` sentinel).
    pub const SERVICE_ACCOUNT: &str = "service_account";
    /// Origin-classification label.
    ///
    /// Two distinct emitters carry this label, with disjoint, closed
    /// value sets per metric (the per-metric catalog row is authoritative):
    /// - `hort_dispatcher_principal_resolved_total` —
    ///   `{snapshot_present, snapshot_empty_admin,
    ///   snapshot_empty_no_admin}`, bounded by
    ///   [`super::DispatcherPrincipalSource`].
    /// - `hort_service_account_authenticated_total` —
    ///   `{federated, pat}`, bounded by
    ///   [`super::SA_AUTH_SOURCE_FEDERATED`] /
    ///   [`super::SA_AUTH_SOURCE_PAT`].
    ///
    /// Both value sets are small and fixed; the constant exists so the
    /// label name is a single source of truth rather than a repeated
    /// string literal.
    pub const SOURCE: &str = "source";
    /// Retention-policy id label on
    /// `hort_retention_evaluations_total` and `hort_retention_expired_total`.
    ///
    /// **Cardinality posture:** unlike scan policies
    /// (where `policy_id` is a forbidden label per the
    /// `hort_policy_evaluation_total` catalog note), retention policies
    /// are a small operator-declared set — a handful of named retention
    /// rules per deployment, so `policy_id` is bounded and the
    /// cardinality acceptable. The value is the policy UUID string.
    /// This is the one place `policy_id` is an allowed metric label,
    /// scoped to the two `hort_retention_*` metrics.
    pub const POLICY_ID: &str = "policy_id";
    /// Decision-kind label on
    /// `hort_curation_decisions_total`. Closed taxonomy of 4:
    /// `{waive, block, exclude_finding, unexclude_finding}`.
    /// `waive` and `block` come from the curation use case;
    /// `exclude_finding` / `unexclude_finding` are emitted from
    /// `PolicyUseCase::{add,remove}_exclusion`. Values bounded by
    /// [`super::CurationDecisionLabel`].
    pub const DECISION: &str = "decision";
    /// Resolved `provenance_mode` label on
    /// `hort_provenance_verify_total`. Closed taxonomy of 3, the
    /// lowercase wire-form of
    /// [`hort_domain::entities::scan_policy::ProvenanceMode`]'s `Display`:
    /// `{off, verify_if_present, required}`. `off` never reaches the
    /// emission site in production (the ingest gate never enqueues a
    /// `provenance-verify` job for an `Off` policy), but the value is
    /// reserved here so the taxonomy stays exhaustive and the defensive
    /// `SkippedOff` orchestrator arm has a valid label. Small, bounded
    /// cardinality (3 values).
    pub const MODE: &str = "mode";
}

/// Pinned `decision_point` label values for
/// `hort_policy_evaluation_total` and `hort_policy_violations_total`. One
/// constant per use case that hosts a policy evaluation gate.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
pub mod policy_decision_point {
    /// Emitted by `QuarantineUseCase::record_scan_result`.
    pub const SCAN_RESULT: &str = "scan_result";
    /// Emitted by `PromotionUseCase::evaluate_and_promote`.
    pub const PROMOTION: &str = "promotion";
    /// Emitted by `PolicyUseCase::add_exclusion` re-evaluation pass.
    pub const RE_EVALUATION: &str = "re_evaluation";
    /// Emitted by `IngestUseCase::ingest` curation gate.
    pub const CURATION: &str = "curation";
    /// Emitted by `ApplyConfigUseCase::run_retroactive_curation_for_rule`.
    pub const CURATION_RETROACTIVE: &str = "curation_retroactive";
}

/// Enumerable label-value constants that the application layer emits.
///
/// Only values that are enumerable and re-used at multiple emission sites live
/// here. Free-form values (repository keys, formats) are passed by reference
/// to the emission macros as-is.
pub mod values {
    /// Event-store category for artifact lifecycle events.
    pub const CATEGORY_ARTIFACT: &str = "artifact";
    /// Event-store category for policy events.
    pub const CATEGORY_POLICY: &str = "policy";

    /// Quarantine-release reason: timer-driven expiry.
    pub const REASON_TIMER: &str = "timer";
    /// Quarantine-release reason: administrator action.
    pub const REASON_ADMIN: &str = "admin";
    /// Quarantine-release reason: policy re-evaluation after an exclusion.
    pub const REASON_POLICY_RE_EVALUATION: &str = "policy_re_evaluation";

    /// Sentinel emitted for the `repository` label when
    /// `METRICS_INCLUDE_REPOSITORY_LABEL=false`. Distinguishes "label disabled"
    /// from "label missing" for operators.
    pub const REPOSITORY_ALL: &str = "_all";
    /// Sentinel emitted for the `repository` label when the use case cannot
    /// resolve a repository for the given id. Prevents cardinality inflation
    /// from clients supplying random UUIDs.
    pub const REPOSITORY_UNKNOWN: &str = "unknown";

    /// Sentinel emitted for the HTTP `path` label when `MatchedPath` is absent
    /// (404s, unmatched paths). Prevents cardinality explosion from arbitrary
    /// client URLs while keeping one series for the 404 case.
    pub const PATH_UNMATCHED: &str = "<unmatched>";

    /// Sentinel emitted for the `format` label when the format cannot be
    /// resolved — e.g. `ArtifactUseCase::download` is called with an
    /// artifact_id whose row/repository lookup fails. Mirrors
    /// [`REPOSITORY_UNKNOWN`] for symmetry so operators can spot
    /// classification misses in dashboards.
    pub const FORMAT_UNKNOWN: &str = "unknown";

    /// `strategy` label value: the full payload lives inline in the event
    /// and projection row. Emitted by `hort_ingest_metadata_strategy_total`
    /// whenever an ingest used the Inline strategy,
    /// either because the handler declared it or because the handler declared
    /// HashReference but the payload stayed under the inline threshold — no
    /// split means the counter is labelled `inline`, not `hash_reference`.
    pub const STRATEGY_INLINE: &str = "inline";
    /// `strategy` label value: the full payload was written to CAS and
    /// the event + projection row carry only the handler-extracted
    /// summary plus a `ContentHash` reference. Emitted only when a split
    /// actually happened.
    pub const STRATEGY_HASH_REFERENCE: &str = "hash_reference";
}

/// Outcome of an ingest operation, used as the `result` label of
/// `hort_ingest_total`.
///
/// String values are normative — they are part of the public metrics contract
/// declared in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestResult {
    /// New content stored, event emitted.
    Success,
    /// Same hash at same path — idempotent retry early-return.
    Duplicate,
    /// Different hash at same path — collision.
    Conflict,
    /// Invalid coords, invalid format, malformed input.
    ValidationError,
    /// Backend I/O failure (propagated from `StoragePort`).
    StorageError,
    /// Caller supplied a non-existent `repository_id`.
    RepositoryNotFound,
    /// `payload_metadata` serialized length exceeded the effective
    /// per-format cap (three-layer size model — see
    /// `FormatHandler::metadata_expected_max_bytes`).
    /// Distinct from `ValidationError` so dashboards can surface
    /// metadata-cap pressure without conflating it with coords-shape
    /// issues. Emitted by the outer `IngestUseCase::ingest` method
    /// without going through `classify_ingest_error`.
    MetadataTooLarge,
    /// `IngestUseCase::register_by_hash` succeeded — a pre-existing CAS
    /// object was registered into the target repository by its hash
    /// without re-streaming bytes. Primary consumer is the
    /// OCI cross-repo blob mount, where the source repo already owns
    /// the bytes and the target repo just needs a metadata row + event
    /// pointing at the same `ContentHash`. Separate label so operators
    /// can distinguish mount-style registrations from fresh ingests in
    /// dashboards (they have different storage- and network-cost
    /// profiles).
    RegisteredByHash,
    /// Caller supplied a non-None `declared_sha256` that disagreed with
    /// the hash of the streamed body on the fresh-insert path (no
    /// existing row at the coords path). Split out from `Conflict` so
    /// dashboards can distinguish client-supplied-wrong-hash — an
    /// integrity-contract violation upstream — from the classic
    /// same-path-different-content collision.
    DeclaredHashMismatch,
    /// PyPI wheel ingest succeeded but the post-commit
    /// `FormatHandler::extract_wheel_metadata_bytes` call returned a
    /// validation error (oversized METADATA per the 1 MiB cap, or other
    /// validation-class reject). The wheel itself ingested normally —
    /// this label flags ONLY the PEP 658 advertisement gap: the
    /// simple-index will not advertise `data-dist-info-metadata` for
    /// this wheel, and pip will fall back to the whole-wheel download
    /// for resolver-time `Requires-Dist` reads. Non-fatal by design;
    /// the tick is the observability surface for operators who want
    /// to dashboard pathological wheels.
    WheelMetadataExtractFailed,
}

impl IngestResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::ValidationError => "validation_error",
            Self::StorageError => "storage_error",
            Self::RepositoryNotFound => "repository_not_found",
            Self::MetadataTooLarge => "metadata_too_large",
            Self::RegisteredByHash => "registered_by_hash",
            Self::DeclaredHashMismatch => "declared_hash_mismatch",
            Self::WheelMetadataExtractFailed => "wheel_metadata_extract_failed",
        }
    }
}

/// Outcome of a download operation, used as the `result` label of
/// `hort_download_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadResult {
    /// Content delivered.
    Success,
    /// Artifact is quarantined; download refused.
    Quarantined,
    /// Policy rejected the download.
    Rejected,
    /// Artifact does not exist.
    NotFound,
    /// Backend I/O failure reading the content stream.
    StorageError,
}

impl DownloadResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::NotFound => "not_found",
            Self::StorageError => "storage_error",
        }
    }
}

/// Outcome of an opt-in download-audit append, used as the `result`
/// label of `hort_download_audit_dropped`.
/// The counter only fires on the **fail-open drop path** — a
/// successful append produces NO metric and NO log (the served-download
/// path is high-volume; routine-success info would dominate). The enum
/// is intentionally closed at one variant: the only way an enabled
/// audit emit can be dropped while still serving the artifact is an
/// event-store append error.
///
/// String value is normative; it appears verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadAuditDropResult {
    /// The event-store `append` of the `ArtifactDownloaded` event
    /// failed. The download was still served (fail-open); a
    /// `tracing::warn!(audit_write_failed=true, …)` accompanies this
    /// counter increment.
    AppendError,
}

impl DownloadAuditDropResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AppendError => "append_error",
        }
    }
}

/// Emit `hort_download_audit_dropped{format, repository, result}` — the
/// fail-open drop counter for the opt-in download-audit path.
///
/// `repo_label` / `format_label` are already resolved by the caller
/// (the [`ArtifactUseCase::repo_label`] / [`ArtifactUseCase::format_label`]
/// sentinel policy — `_all` when the label is disabled, `unknown` when
/// the lookup failed). NO per-artifact / per-user / per-hash / per-
/// stream label (those are forbidden unbounded-cardinality dimensions —
/// the per-instance detail lives in the accompanying `warn!` span).
pub fn emit_download_audit_dropped(
    format_label: &str,
    repo_label: &str,
    result: DownloadAuditDropResult,
) {
    metrics::counter!(
        "hort_download_audit_dropped",
        labels::FORMAT => format_label.to_owned(),
        labels::REPOSITORY => repo_label.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Outcome of a throttled per-use token-use audit emit, used as the
/// `result` label of `hort_api_token_used_audit_dropped`.
/// The counter fires on **both** non-append outcomes:
///
/// - `Throttled` — the per-`token_id` 1-hour throttle suppressed the
///   append. This is the **expected steady state** for any actively
///   used token (a hot CI token used thousands of times per hour
///   produces one event per hour and `throttled` on every other use),
///   NOT an error — operators must not alert on it.
/// - `AppendError` — the throttle was won but the event-store
///   `append` failed. The validation still returned `Ok` (fail-open);
///   a `tracing::warn!(error=…)` accompanies this increment.
///
/// A *successful* audit append produces NO metric and NO log (the
/// validation path is the auth hot path; routine-success info would
/// dominate). `hort_api_token_validation_total` /
/// `_duration_seconds` are entirely independent — the emit happens in
/// the `validate_pat` wrapper *after* the duration metric, best-effort.
///
/// String values are normative; they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiTokenUsedAuditDropResult {
    /// The per-`token_id` 1-hour throttle suppressed the append. The
    /// expected steady state, not an error.
    Throttled,
    /// The throttle was won but the event-store `append` failed. The
    /// validation still returned `Ok` (fail-open).
    AppendError,
}

impl ApiTokenUsedAuditDropResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Throttled => "throttled",
            Self::AppendError => "append_error",
        }
    }
}

/// Emit `hort_api_token_used_audit_dropped{result}` — the
/// throttle-or-fail-open drop counter for the per-use token-use
/// audit path.
///
/// `result` is the ONLY label: token use has no `format` /
/// `repository` dimension (contrast `hort_download_audit_dropped`),
/// and `user_id` / `token_id` are forbidden unbounded-cardinality
/// dimensions — the per-instance detail lives in the accompanying
/// `tracing::debug!` (throttled) / `tracing::warn!` (append error)
/// span.
pub fn emit_api_token_used_audit_dropped(result: ApiTokenUsedAuditDropResult) {
    metrics::counter!(
        "hort_api_token_used_audit_dropped",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Outcome of a single CAS-scrub re-hash check, used as the `result` label
/// of `hort_cas_scrub_checks_total`.
///
/// The scrubber walks `StoragePort::list_all`, fetches every blob, and
/// re-hashes the byte stream. Every listed hash produces exactly one
/// variant of this enum and one metric increment — the scrub is not
/// sampled at the metric-emission level (sampling happens before the
/// re-hash, via `ScrubOpts::sample_fraction`, and skipped hashes are
/// neither listed in the report nor emitted).
///
/// String values are normative; they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasScrubResult {
    /// Re-hash matched the CAS key.
    Ok,
    /// Re-hash produced a different digest than the CAS key. Use case
    /// emits a `CasIntegrityMismatch` domain event + `tracing::warn!`
    /// in addition to this counter. **Flag only — no quarantine.**
    HashMismatch,
    /// The hash appeared in `list_all` but `get(&hash)` returned
    /// `NotFound`. A concurrent GC, a racing delete, or an inconsistent
    /// backend listing.
    Missing,
    /// An I/O error occurred while re-hashing (streaming read failed,
    /// listing yielded a `ReadError`, etc.). Distinct from
    /// `hash_mismatch` because the scrubber cannot attest to the blob's
    /// content one way or the other.
    ReadError,
}

impl CasScrubResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::HashMismatch => "hash_mismatch",
            Self::Missing => "missing",
            Self::ReadError => "read_error",
        }
    }
}

/// Outcome of a `RefUseCase::set` / `RefUseCase::retire` call, used as
/// the `result` label of `hort_ref_moved_total`.
///
/// The enum lives in the application layer because emission happens in
/// `hort-app::use_cases::ref_use_case` — adapter-layer concerns are scoped
/// to [`hort_adapters_postgres::metrics`] per the layering rule at the top
/// of this module. The metric answers "what did the ref write path
/// actually do?"; `no_op` is a legitimate outcome (same-target re-point
/// short-circuited by the use case AND by the adapter), not an error.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefMetricResult {
    /// First placement of a ref — `RefMoved { from: None, to: target }`
    /// was appended and the projection row was inserted.
    Created,
    /// Ref already existed and pointed at a different target —
    /// `RefMoved { from: Some(prior), to: target }` was appended and
    /// the projection row was updated.
    Moved,
    /// Ref existed and was retired — `RefRetired` was appended and
    /// the projection row was deleted.
    Retired,
    /// `set` was called with a target matching the current row's target.
    /// No event was appended (both the use case and the adapter short-
    /// circuit; the metric reflects outcome, not which layer caught it).
    NoOp,
}

impl RefMetricResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Moved => "moved",
            Self::Retired => "retired",
            Self::NoOp => "no_op",
        }
    }
}

/// Emit `hort_ref_moved_total{repository, result}` — the single counter that
/// tracks every outcome of the ref write path.
///
/// `repo_label` is already resolved by the caller: either the repository
/// key, the [`values::REPOSITORY_ALL`] sentinel when the label is
/// disabled, or [`values::REPOSITORY_UNKNOWN`] when the repository could
/// not be resolved. `result` carries the canonical string value.
pub fn emit_ref_moved(repo_label: &str, result: RefMetricResult) {
    metrics::counter!(
        "hort_ref_moved_total",
        labels::REPOSITORY => repo_label.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Enumerated `role` label values emitted by
/// `hort_artifact_group_members_added_total`.
///
/// The taxonomy is closed on purpose — the catalog declares every
/// permissible value, so a misbehaving WASM format module cannot push
/// an arbitrary string into the `role` label and inflate cardinality.
/// The `Other` variant is a cardinality-safe fall-through: it maps to
/// the string `"other"`, matching `FORMAT_UNKNOWN`'s sentinel pattern.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. The list covers every role referenced by
/// the format-scoped conventions documented on
/// [`hort_domain::entities::artifact_group::ArtifactGroupMember`] (Maven,
/// Go, OCI, Debian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMemberRole {
    /// Maven — Project Object Model descriptor.
    Pom,
    /// Maven — the main compiled JAR.
    Jar,
    /// Maven — `-sources.jar` attached classifier.
    Sources,
    /// Maven — `-javadoc.jar` attached classifier.
    Javadoc,
    /// Maven — PGP/GPG `.asc` signature file.
    Signature,
    /// Maven — `.sha256` checksum file.
    Sha256,
    /// Maven — `.md5` checksum file.
    Md5,
    /// Go — `go.mod` module descriptor.
    Mod,
    /// Go — module source `.zip`.
    Zip,
    /// Go — `.info` metadata file.
    Info,
    /// OCI — image manifest.
    Manifest,
    /// OCI — image config blob.
    Config,
    /// OCI — layer blob (one `layer` value per layer in the image).
    Layer,
    /// Debian — binary `.deb` package.
    Deb,
    /// Debian — `.dsc` source control file.
    Dsc,
    /// Debian — `.changes` upload manifest.
    Changes,
    /// Debian — `.orig.tar.*` original upstream tarball.
    Orig,
    /// Gradle — `.module` Gradle Module Metadata (GMM) descriptor.
    Module,
    /// Cardinality-safe fall-through. Emitted when a handler declared a
    /// role that is not one of the enumerated values above — the raw
    /// string stays out of the metric label to prevent blow-up.
    Other,
}

impl GroupMemberRole {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pom => "pom",
            Self::Jar => "jar",
            Self::Sources => "sources",
            Self::Javadoc => "javadoc",
            Self::Signature => "signature",
            Self::Sha256 => "sha256",
            Self::Md5 => "md5",
            Self::Mod => "mod",
            Self::Zip => "zip",
            Self::Info => "info",
            Self::Manifest => "manifest",
            Self::Config => "config",
            Self::Layer => "layer",
            Self::Deb => "deb",
            Self::Dsc => "dsc",
            Self::Changes => "changes",
            Self::Orig => "orig",
            Self::Module => "module",
            Self::Other => "other",
        }
    }

    /// Classify a handler-supplied `role` string into one of the
    /// enumerated catalog values. Unknown roles collapse to
    /// [`Self::Other`] rather than surfacing as a new label.
    pub fn classify(role: &str) -> Self {
        match role {
            "pom" => Self::Pom,
            "jar" => Self::Jar,
            "sources" => Self::Sources,
            "javadoc" => Self::Javadoc,
            "signature" => Self::Signature,
            "sha256" => Self::Sha256,
            "md5" => Self::Md5,
            "mod" => Self::Mod,
            "zip" => Self::Zip,
            "info" => Self::Info,
            "manifest" => Self::Manifest,
            "config" => Self::Config,
            "layer" => Self::Layer,
            "deb" => Self::Deb,
            "dsc" => Self::Dsc,
            "changes" => Self::Changes,
            "orig" => Self::Orig,
            "module" => Self::Module,
            _ => Self::Other,
        }
    }
}

/// Emit `hort_artifact_groups_created_total{repository, format}`.
///
/// Fires once per successful first-placement `commit_member_added`
/// call — the one where `change.new_group.is_some()` and the adapter
/// returned `Committed`. Concurrent-create losers do NOT tick this
/// counter; the retry that attaches to the winner's group emits only
/// the member-add counter.
pub fn emit_artifact_group_created(repo_label: &str, format_label: &str) {
    metrics::counter!(
        "hort_artifact_groups_created_total",
        labels::REPOSITORY => repo_label.to_owned(),
        labels::FORMAT => format_label.to_owned(),
    )
    .increment(1);
}

/// Emit `hort_artifact_group_members_added_total{repository, format, role}`.
///
/// Fires once per successful `commit_member_added` call that committed
/// (not a `GroupAlreadyExists` return, not the rolled-back loser of a
/// primary-assign race). Idempotent same-role re-adds do NOT tick —
/// the adapter short-circuits without appending events and the use
/// case skips the emit.
pub fn emit_artifact_group_member_added(
    repo_label: &str,
    format_label: &str,
    role: GroupMemberRole,
) {
    metrics::counter!(
        "hort_artifact_group_members_added_total",
        labels::REPOSITORY => repo_label.to_owned(),
        labels::FORMAT => format_label.to_owned(),
        "role" => role.as_str(),
    )
    .increment(1);
}

/// Outcome of a single-event evaluation during the group-membership
/// reconciliation sweep, used as the `result`
/// label of `hort_group_reconcile_total`.
///
/// The sweep replays `ArtifactIngested` events within an operator-
/// supplied window, asks each event's `FormatHandler` whether the
/// artifact is a group member, and (if unlinked) heals the gap via
/// `ArtifactGroupUseCase::add_member`. Every processed event emits
/// exactly one increment with one of these four variants.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. The four-label set is closed; `add_member`
/// failures are folded into `EventReadError` with a `warn!` at the
/// call site (see module docstring on
/// `hort_app::use_cases::group_reconcile_use_case`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupReconcileResult {
    /// Unlinked artifact observed; `add_member` succeeded — the
    /// orphan has been reattached to its group.
    Healed,
    /// Artifact was already a member of a group; no heal needed.
    AlreadyLinked,
    /// No handler is wired for the event's format, OR the handler
    /// returned `None` from `classify_group_member` (single-file
    /// format such as PyPI sdist / Cargo `.crate`). Both collapse to
    /// `handler_declined` — operators cannot tell them apart from the
    /// metric alone, only from tracing; the metric answers "how many
    /// events did the sweep not act on because no group structure
    /// applies?".
    HandlerDeclined,
    /// An event-store read failed for a single page OR an
    /// `add_member` call failed for a single artifact. The sweep
    /// continues past the failure. See the use case docstring for
    /// why `add_member` failures are folded in here rather than
    /// carrying a separate label.
    EventReadError,
}

impl GroupReconcileResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healed => "healed",
            Self::AlreadyLinked => "already_linked",
            Self::HandlerDeclined => "handler_declined",
            Self::EventReadError => "event_read_error",
        }
    }
}

/// Emit `hort_group_reconcile_total{repository, result}` — the single
/// counter that classifies every event processed during the
/// group-membership reconciliation sweep.
///
/// `repo_label` is already resolved by the caller: either the
/// repository key, the [`values::REPOSITORY_ALL`] sentinel when the
/// label is disabled, or [`values::REPOSITORY_UNKNOWN`] when the
/// repository could not be resolved for the event.
pub fn emit_group_reconcile(repo_label: &str, result: GroupReconcileResult) {
    metrics::counter!(
        "hort_group_reconcile_total",
        labels::REPOSITORY => repo_label.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Classification of upstream-fetch outcomes, used as the `result` label of
/// `hort_upstream_fetch_total` and related metrics.
///
/// The taxonomy is fixed here so handlers cannot invent ad-hoc label
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamErrorKind {
    /// 2xx, checksum verified.
    Success,
    /// 404.
    NotFound,
    /// 401 or 403.
    Unauthorized,
    /// 429.
    RateLimited,
    /// 4xx not covered by a more specific variant.
    Upstream4xx,
    /// 5xx.
    Upstream5xx,
    /// Connection refused, DNS failure, TLS error.
    NetworkError,
    /// Deadline exceeded before response.
    Timeout,
    /// Content received, hash failed verification.
    ChecksumMismatch,
    /// Malformed metadata response.
    ParseError,
    /// Retired per-call body cap trip (the old 10 MiB metadata + 4 MiB
    /// manifest hardcaps, superseded by the per-fetch-class storage
    /// backstops below; ADR 0026). This variant is **reserved** (kept
    /// on [`UpstreamErrorKind`] so the metrics catalog still recognises
    /// the historical label) but **no longer emitted from the
    /// upstream-fetch path**.
    BodyTooLarge,
    /// `fetch_metadata` storage backstop trip.
    /// Configurable via `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`
    /// (default 64 MiB). The honest classification —
    /// operators see this label and reach for the right knob,
    /// instead of debugging the "upstream unavailable" sanitisation
    /// the buffer-cap trip used to fold into.
    MetadataTooLarge,
    /// `fetch_manifest` storage backstop trip.
    /// Configurable via `HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`
    /// (default 16 MiB). OCI-symmetric companion to
    /// [`Self::MetadataTooLarge`].
    ManifestTooLarge,
    /// Per-version-object cap trip inside a
    /// projector's `Visitor::visit_map` loop (npm `versions{}` /
    /// PyPI `releases{}`). Configurable via
    /// `HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE` (default
    /// 2 MiB). Emitted where the projectors
    /// consume the [`hort_domain::ports::upstream_proxy::CountingReader`]
    /// helper.
    VersionObjectTooLarge,
    /// Operator-pinned leaf-certificate
    /// thumbprint did not match the upstream's presented leaf cert.
    /// The upstream may have rotated to a new (legitimate) cert, or
    /// the pin is wrong, or a MITM is in progress; from the proxy's
    /// perspective these are indistinguishable so the connection is
    /// refused. Distinct from [`Self::ParseError`] and from any
    /// CA-trust failure: the upstream presented a syntactically valid
    /// certificate that chained to a trusted CA but did not match the
    /// pinned thumbprint.
    PinMismatch,
    /// TLS handshake failed because the
    /// upstream's certificate chain did not chain to a trust anchor in
    /// the configured root store (the system CA bundle, optionally
    /// augmented by a per-mapping `ca_bundle_ref`). Distinct from
    /// [`Self::PinMismatch`] (chain trust is fine, the leaf thumbprint
    /// is the discriminator) and from [`Self::Unauthorized`] (which
    /// covers post-handshake 401/403 authorisation failures).
    CaUnknown,
}

impl UpstreamErrorKind {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::Upstream4xx => "upstream_4xx",
            Self::Upstream5xx => "upstream_5xx",
            Self::NetworkError => "network_error",
            Self::Timeout => "timeout",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::ParseError => "parse_error",
            Self::BodyTooLarge => "body_too_large",
            Self::MetadataTooLarge => "metadata_too_large",
            Self::ManifestTooLarge => "manifest_too_large",
            Self::VersionObjectTooLarge => "version_object_too_large",
            Self::PinMismatch => "pin_mismatch",
            Self::CaUnknown => "ca_unknown",
        }
    }
}

/// Emit
/// `hort_upstream_fetch_total{result="version_object_too_large"}` when a
/// per-version-object cap trip aborts consumer-side streaming
/// projection of an upstream metadata body (npm `versions{}` value /
/// PyPI `files[]` entry).
///
/// **Emission-stage note.** The other `hort_upstream_fetch_total` result
/// labels are emitted by `hort-adapters-upstream-http` at the HTTP fetch
/// boundary. This one is emitted by the per-format inbound source
/// (`ProxyNpmSource` / `ProxyPypiSource`) at the *projection* stage: the
/// cap is enforced while parsing the already-fetched cached body, so the
/// trip is observed downstream of the adapter. The catalog row for
/// `version_object_too_large` records this. `format` is the format key
/// (`"npm"` / `"pypi"`); `repository` is the repo key or the
/// [`values::REPOSITORY_ALL`] sentinel when
/// `METRICS_INCLUDE_REPOSITORY_LABEL=false`.
pub fn emit_upstream_version_object_too_large(format: &str, repository: &str) {
    metrics::counter!(
        "hort_upstream_fetch_total",
        labels::FORMAT => format.to_string(),
        labels::REPOSITORY => repository.to_string(),
        labels::RESULT => UpstreamErrorKind::VersionObjectTooLarge.as_str(),
    )
    .increment(1);
}

/// Typed error returned by
/// [`crate::ports::upstream_metadata::UpstreamMetadataPort::list_versions`].
///
/// Lives in `hort-app::metrics` (not `hort-domain`) per the architect-doc rule
/// *"result enums live with the emitting layer"*: the discovery +
/// self-service-prefetch use cases are the only consumers, and they emit
/// `hort_discovery_list_versions_total` / `hort_prefetch_self_service_total`
/// with `result` labels drawn from [`UpstreamErrorKind`]. A flat
/// `AppError::Domain(DomainError::Validation(String))` from the port would
/// force the use case to re-parse a free-form message to recover the metric
/// label — exactly the classification-after-the-fact the architect-doc
/// "result enums live with the emitting layer" rule is designed to prevent.
/// The adapter (`hort-formats-upstream`) classifies once at
/// fetch time into this enum; the use case pattern-matches
/// once at emission time.
///
/// **Variant alignment with [`UpstreamErrorKind`].** The eight upstream-
/// fetch variants below align 1:1 with the upstream-fetch subset of
/// [`UpstreamErrorKind`] — `NotFound`, `Unauthorized`, `RateLimited`,
/// `Upstream4xx`, `Upstream5xx`, `NetworkError`, `Timeout`, `ParseError`.
/// Three [`UpstreamErrorKind`] variants are deliberately NOT mirrored:
/// `Success` (this enum is the error half of a `Result`), `ChecksumMismatch`
/// and `BodyTooLarge` (those fire before the port classifies the response),
/// `PinMismatch` and `CaUnknown` (transport-layer concerns surfaced on the
/// dedicated `hort_upstream_tls_handshake_total` metric, not the fetch metric).
/// `UnsupportedFormat` is the one variant that is NOT a metric label — it is
/// the OCI / unknown-format short-circuit (discovery deliberately does not
/// cover OCI) and the use case
/// converts it to `AppError::Domain(DomainError::Validation(_))`,
/// mapped to `result = "oci_unsupported"` on the metric
/// (NOT one of the [`UpstreamErrorKind`] variants).
///
/// **Sanitisation contract.** The two `String`-carrying variants
/// ([`Self::NetworkError`], [`Self::ParseError`]) MUST carry **sanitised**
/// strings: no URLs, no hostnames, no package names, no payload bytes.
/// Per the architect-doc tracing rules, untrusted upstream content must
/// not flow into our log/event stream through error messages. Adapter
/// implementations classify the upstream's response into one of these
/// variants and either (a) leave the string empty / synthesise a class
/// label (e.g. `"dns"`, `"tls"`, `"connect"`) or (b) carry a constant
/// describing the parser stage (e.g. `"npm packument deserialize"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamFetchError {
    /// Upstream returned 404. Mirrors [`UpstreamErrorKind::NotFound`].
    NotFound,
    /// Upstream returned 401 or 403. Operator-side credential issue.
    /// Mirrors [`UpstreamErrorKind::Unauthorized`].
    Unauthorized,
    /// Upstream returned 429. Mirrors [`UpstreamErrorKind::RateLimited`].
    RateLimited,
    /// Upstream returned a 4xx not covered by [`Self::NotFound`],
    /// [`Self::Unauthorized`], or [`Self::RateLimited`]. Mirrors
    /// [`UpstreamErrorKind::Upstream4xx`]. The exact status code is
    /// carried for adapter-side observability (`tracing::warn!`); the
    /// status does NOT surface to the operator at the metric-label
    /// layer (the label is just `"upstream_4xx"`).
    Upstream4xx { status: u16 },
    /// Upstream returned a 5xx. Mirrors [`UpstreamErrorKind::Upstream5xx`].
    /// The status code is carried for adapter-side observability.
    Upstream5xx { status: u16 },
    /// Connection refused, DNS failure, TLS handshake error. Mirrors
    /// [`UpstreamErrorKind::NetworkError`]. The carried string is
    /// **sanitised** — see the type-level sanitisation contract.
    NetworkError(String),
    /// Deadline exceeded before response. Mirrors
    /// [`UpstreamErrorKind::Timeout`].
    Timeout,
    /// Malformed upstream metadata. Mirrors
    /// [`UpstreamErrorKind::ParseError`]. The carried string is
    /// **sanitised** — see the type-level sanitisation contract.
    ParseError(String),
    /// The requested format is OCI or otherwise unsupported
    /// by the discovery / self-service-prefetch use cases. NOT a metric
    /// label of `hort_upstream_fetch_total`; the consuming use cases
    /// convert this variant to `AppError::Domain(DomainError::Validation(_))`
    /// and emit `result = "oci_unsupported"` on their own counters.
    UnsupportedFormat,
}

impl UpstreamFetchError {
    /// Map a fetch-error variant to the matching [`UpstreamErrorKind`]
    /// metric-label variant. The eight fetch variants map 1:1; the
    /// out-of-band [`Self::UnsupportedFormat`] returns `None` — the use
    /// case emits `result = "oci_unsupported"` for that path, NOT one of
    /// the [`UpstreamErrorKind`] label values.
    ///
    /// This helper exists so the discovery + prefetch use cases
    /// classify once at the port boundary and emit once at the
    /// metric site, with no free-form-string re-parsing in between.
    pub fn as_upstream_error_kind(&self) -> Option<UpstreamErrorKind> {
        match self {
            Self::NotFound => Some(UpstreamErrorKind::NotFound),
            Self::Unauthorized => Some(UpstreamErrorKind::Unauthorized),
            Self::RateLimited => Some(UpstreamErrorKind::RateLimited),
            Self::Upstream4xx { .. } => Some(UpstreamErrorKind::Upstream4xx),
            Self::Upstream5xx { .. } => Some(UpstreamErrorKind::Upstream5xx),
            Self::NetworkError(_) => Some(UpstreamErrorKind::NetworkError),
            Self::Timeout => Some(UpstreamErrorKind::Timeout),
            Self::ParseError(_) => Some(UpstreamErrorKind::ParseError),
            Self::UnsupportedFormat => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery — `hort_discovery_list_versions_total{format, repository, result}`
// ---------------------------------------------------------------------------

/// `result` label value for `hort_discovery_list_versions_total`.
///
/// Closed taxonomy of 12 — the eight upstream-fetch variants from
/// [`UpstreamErrorKind`] (the architect-doc canonical taxonomy: `success`,
/// `not_found`, `unauthorized`, `rate_limited`, `upstream_4xx`,
/// `upstream_5xx`, `network_error`, `timeout`, `parse_error`) plus three
/// endpoint-local additions for gates that fire **before** the port is
/// called: `permission_denied`, `token_kind_denied`, `oci_unsupported`.
///
/// **`UpstreamErrorKind` alignment is load-bearing.** This endpoint-level
/// metric consumes `UpstreamErrorKind` verbatim
/// (architect-doc: *"every format module that fetches from upstream maps
/// its errors to UpstreamErrorKind variants — no custom labels"*). Future
/// endpoint-level metric authors should mirror this taxonomy rather than
/// invent ad-hoc result strings.
///
/// **`not_found` semantic.** Ticks ONLY when the upstream lookup returns
/// 404; if the registry has held versions or the call assembles a listing
/// (empty or otherwise), it ticks `Success`. The discovery endpoint
/// itself returns 200 in all three of these cases — operators read the
/// response payload to distinguish them; the metric distinguishes "did
/// the upstream call complete cleanly".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryResult {
    /// Listing assembled cleanly — locally-held versions ∪
    /// upstream-advertised returned to the caller. Includes the
    /// no-upstream-mapping case and the empty-listing case.
    Success,
    /// Upstream returned 404 for the package lookup.
    NotFound,
    /// Upstream returned 401/403 (operator-side credential issue).
    Unauthorized,
    /// Upstream returned 429.
    RateLimited,
    /// Upstream returned a 4xx not covered by a more specific variant.
    Upstream4xx,
    /// Upstream returned a 5xx.
    Upstream5xx,
    /// Connection / TLS / DNS failure.
    NetworkError,
    /// Upstream fetch exceeded the configured timeout.
    Timeout,
    /// Upstream response body did not parse as the expected per-format
    /// metadata shape.
    ParseError,
    /// RBAC denied — caller lacks `Permission::Read` on the repo (post
    /// token-kind gate). Endpoint-local addition.
    PermissionDenied,
    /// Caller's token kind is not `TokenKind::CliSession` — the
    /// amplification-surface gate. Fires before RBAC.
    TokenKindDenied,
    /// Caller asked for OCI discovery — a deliberate non-goal. The port
    /// returns `UpstreamFetchError::UnsupportedFormat`; the use case maps
    /// to this label.
    OciUnsupported,
}

impl DiscoveryResult {
    /// Label value string — must match the catalog row in
    /// `docs/metrics-catalog.md` exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::Upstream4xx => "upstream_4xx",
            Self::Upstream5xx => "upstream_5xx",
            Self::NetworkError => "network_error",
            Self::Timeout => "timeout",
            Self::ParseError => "parse_error",
            Self::PermissionDenied => "permission_denied",
            Self::TokenKindDenied => "token_kind_denied",
            Self::OciUnsupported => "oci_unsupported",
        }
    }

    /// Promote an [`UpstreamErrorKind`] from the upstream-fetch port boundary
    /// to a `DiscoveryResult`. The eight upstream-fetch variants map 1:1; the
    /// three endpoint-local additions ([`Self::PermissionDenied`],
    /// [`Self::TokenKindDenied`], [`Self::OciUnsupported`]) are emitted
    /// directly by the use-case gate block and never flow through this helper.
    /// `UpstreamErrorKind` variants that are not in the discovery taxonomy
    /// (`ChecksumMismatch`, `BodyTooLarge`, `PinMismatch`, `CaUnknown`) fold
    /// to [`Self::NetworkError`] as a defensive bucket — discovery does not
    /// verify checksums (no ingest happens here) and the transport-layer
    /// variants would already have surfaced via the dedicated TLS metric.
    pub fn from_upstream_error_kind(kind: UpstreamErrorKind) -> Self {
        match kind {
            UpstreamErrorKind::Success => Self::Success,
            UpstreamErrorKind::NotFound => Self::NotFound,
            UpstreamErrorKind::Unauthorized => Self::Unauthorized,
            UpstreamErrorKind::RateLimited => Self::RateLimited,
            UpstreamErrorKind::Upstream4xx => Self::Upstream4xx,
            UpstreamErrorKind::Upstream5xx => Self::Upstream5xx,
            UpstreamErrorKind::NetworkError => Self::NetworkError,
            UpstreamErrorKind::Timeout => Self::Timeout,
            UpstreamErrorKind::ParseError => Self::ParseError,
            // Defensive fold — these variants are out-of-band for the
            // discovery taxonomy (no checksum verification at metadata
            // fetch; transport-layer concerns route through the
            // dedicated `hort_upstream_tls_handshake_total` metric).
            // `MetadataTooLarge` / `ManifestTooLarge` /
            // `VersionObjectTooLarge` fold to NetworkError on this path
            // for the same reason — discovery does not enforce the
            // storage backstops (they are an adapter-side fetch
            // concern) and would never see them in practice.
            UpstreamErrorKind::ChecksumMismatch
            | UpstreamErrorKind::BodyTooLarge
            | UpstreamErrorKind::MetadataTooLarge
            | UpstreamErrorKind::ManifestTooLarge
            | UpstreamErrorKind::VersionObjectTooLarge
            | UpstreamErrorKind::PinMismatch
            | UpstreamErrorKind::CaUnknown => Self::NetworkError,
        }
    }
}

/// Emit `hort_discovery_list_versions_total{format, repository, result}`.
/// One tick per discovery-endpoint HTTP call from inside
/// the use case (architect-doc *"Emission by layer"* — business metrics
/// emit at the hort-app layer, never at the inbound handler).
///
/// `format` carries the protocol key (`"npm"`, `"pypi"`, `"cargo"`); for
/// gates that fire before repo resolution (token-kind), pass
/// [`values::FORMAT_UNKNOWN`].
///
/// `repository` follows the catalog convention: pass the resolved repo
/// key from
/// [`RepositoryAccessUseCase::metric_label`](crate::use_cases::repository_access::RepositoryAccessUseCase::metric_label),
/// which already handles `METRICS_INCLUDE_REPOSITORY_LABEL=false` (returns
/// [`values::REPOSITORY_ALL`]) and resolve-failure fallback (returns
/// [`values::REPOSITORY_UNKNOWN`]).
pub fn emit_discovery_list_versions(format: &str, repository: &str, result: DiscoveryResult) {
    metrics::counter!(
        "hort_discovery_list_versions_total",
        labels::FORMAT => format.to_owned(),
        labels::REPOSITORY => repository.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Self-service prefetch — `hort_prefetch_self_service_total{format, repository, result}`
// ---------------------------------------------------------------------------

/// `result` label value for `hort_prefetch_self_service_total`.
///
/// Closed taxonomy of 13 — the eight upstream-fetch variants from
/// [`UpstreamErrorKind`] (`success`, `not_found`, `unauthorized`,
/// `rate_limited`, `upstream_4xx`, `upstream_5xx`, `network_error`,
/// `timeout`, `parse_error`) plus four endpoint-local additions:
/// `permission_denied`, `token_kind_denied`, `oci_unsupported`, and
/// `rejected_version`. The `rejected_version` value covers BOTH
/// `RejectionReason::ScanRejected` and `RejectionReason::ScanIndeterminate`
/// — the operator-facing distinction lives in
/// `PrefetchOutcome.rejected_packages[].reason`, not in the metric label
/// (the architect-doc `result` cardinality ceiling is already softer
/// here at 13; further splitting would push past it without operator-
/// actionable benefit).
///
/// Mirrors [`DiscoveryResult`] one-for-one on the 12 shared variants;
/// the only divergence is the extra `RejectedVersion` arm. The two
/// enums stay distinct so the per-metric `result` set is enforced at
/// compile time (a stray `rejected_version` tick on the discovery
/// metric would be a typo no test would catch otherwise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchSelfServiceResult {
    /// Item enqueued cleanly (per-item tick).
    Success,
    /// Upstream returned 404 for the package lookup (per-item tick).
    NotFound,
    /// Upstream returned 401/403 (per-item tick).
    Unauthorized,
    /// Upstream returned 429 (per-item tick).
    RateLimited,
    /// Upstream returned a 4xx not covered by a more specific variant
    /// (per-item tick).
    Upstream4xx,
    /// Upstream returned a 5xx (per-item tick).
    Upstream5xx,
    /// Connection / TLS / DNS failure (per-item tick).
    NetworkError,
    /// Upstream fetch exceeded the configured timeout (per-item tick).
    Timeout,
    /// Upstream response body did not parse as the expected per-format
    /// metadata shape (per-item tick).
    ParseError,
    /// RBAC denied — caller lacks `Permission::Read ∧ Permission::Prefetch`
    /// on the repo (per-call tick — short-circuit gate).
    PermissionDenied,
    /// Caller's token kind is not `TokenKind::CliSession` (per-call tick
    /// — short-circuit gate, fires first).
    TokenKindDenied,
    /// Caller asked for OCI self-service prefetch — a deliberate non-goal
    /// (per-call tick — short-circuit gate). The port returns
    /// `UpstreamFetchError::UnsupportedFormat`; the use case maps to
    /// this label.
    OciUnsupported,
    /// The registry already holds the requested version in a terminal-non-
    /// installable state (`Rejected` or `ScanIndeterminate`); re-prefetch
    /// is refused (per-item tick). Operator-facing distinction
    /// between the two terminal states lives in
    /// `PrefetchOutcome.rejected_packages[].reason`.
    RejectedVersion,
    /// Server-side infrastructure failure — DB / jobs-port / status-query
    /// error, NOT an upstream network fault (per-item tick). Distinct from
    /// [`Self::NetworkError`] so dashboards/alerts separate server-side
    /// faults (e.g. a `jobs_trigger_source_check` constraint violation)
    /// from genuine upstream egress problems.
    Internal,
}

impl PrefetchSelfServiceResult {
    /// Label value string — must match the catalog row in
    /// `docs/metrics-catalog.md` exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::Upstream4xx => "upstream_4xx",
            Self::Upstream5xx => "upstream_5xx",
            Self::NetworkError => "network_error",
            Self::Timeout => "timeout",
            Self::ParseError => "parse_error",
            Self::PermissionDenied => "permission_denied",
            Self::TokenKindDenied => "token_kind_denied",
            Self::OciUnsupported => "oci_unsupported",
            Self::RejectedVersion => "rejected_version",
            Self::Internal => "internal",
        }
    }

    /// Promote an [`UpstreamErrorKind`] from the upstream-fetch port boundary
    /// to a `PrefetchSelfServiceResult`. The eight upstream-fetch variants map
    /// 1:1; the four endpoint-local additions ([`Self::PermissionDenied`],
    /// [`Self::TokenKindDenied`], [`Self::OciUnsupported`],
    /// [`Self::RejectedVersion`]) are emitted directly by the use-case gate /
    /// pre-flight block and never flow through this helper. `UpstreamErrorKind`
    /// variants that are not in the prefetch taxonomy (`ChecksumMismatch`,
    /// `BodyTooLarge`, `PinMismatch`, `CaUnknown`) fold to [`Self::NetworkError`]
    /// as a defensive bucket — prefetch does not verify checksums in the
    /// resolver path (that happens later, at ingest in the pull-through
    /// pipeline) and the transport-layer variants would already have surfaced
    /// via the dedicated TLS metric.
    pub fn from_upstream_error_kind(kind: UpstreamErrorKind) -> Self {
        match kind {
            UpstreamErrorKind::Success => Self::Success,
            UpstreamErrorKind::NotFound => Self::NotFound,
            UpstreamErrorKind::Unauthorized => Self::Unauthorized,
            UpstreamErrorKind::RateLimited => Self::RateLimited,
            UpstreamErrorKind::Upstream4xx => Self::Upstream4xx,
            UpstreamErrorKind::Upstream5xx => Self::Upstream5xx,
            UpstreamErrorKind::NetworkError => Self::NetworkError,
            UpstreamErrorKind::Timeout => Self::Timeout,
            UpstreamErrorKind::ParseError => Self::ParseError,
            // Defensive fold — these variants are out-of-band for the
            // prefetch taxonomy (no checksum verification at metadata
            // fetch; transport-layer concerns route through the
            // dedicated `hort_upstream_tls_handshake_total` metric).
            // The three storage-backstop variants
            // (`MetadataTooLarge` / `ManifestTooLarge` /
            // `VersionObjectTooLarge`) fold here for the same reason —
            // prefetch never sees them in practice.
            UpstreamErrorKind::ChecksumMismatch
            | UpstreamErrorKind::BodyTooLarge
            | UpstreamErrorKind::MetadataTooLarge
            | UpstreamErrorKind::ManifestTooLarge
            | UpstreamErrorKind::VersionObjectTooLarge
            | UpstreamErrorKind::PinMismatch
            | UpstreamErrorKind::CaUnknown => Self::NetworkError,
        }
    }
}

/// Map a per-item [`PrefetchItemError`] (from
/// `hort_domain::entities::discovery`) to the matching
/// `PrefetchSelfServiceResult` for metric emission. One classification
/// at the port boundary (`UpstreamFetchError` → `PrefetchItemError` for
/// the response envelope), one re-mapping here for the metric label —
/// no free-form string re-parsing.
///
/// This helper exists so the `SelfServicePrefetchUseCase` per-item path
/// emits the metric tick with the same label discipline the discovery
/// use case enforces via [`DiscoveryResult::from_upstream_error_kind`].
pub fn prefetch_self_service_result_from_item_error(
    err: hort_domain::entities::discovery::PrefetchItemError,
) -> PrefetchSelfServiceResult {
    use hort_domain::entities::discovery::PrefetchItemError as E;
    match err {
        E::UpstreamNotFound => PrefetchSelfServiceResult::NotFound,
        E::Unauthorized => PrefetchSelfServiceResult::Unauthorized,
        E::RateLimited => PrefetchSelfServiceResult::RateLimited,
        E::Upstream4xx => PrefetchSelfServiceResult::Upstream4xx,
        E::Upstream5xx => PrefetchSelfServiceResult::Upstream5xx,
        E::NetworkError => PrefetchSelfServiceResult::NetworkError,
        E::Timeout => PrefetchSelfServiceResult::Timeout,
        E::ParseError => PrefetchSelfServiceResult::ParseError,
        E::Internal => PrefetchSelfServiceResult::Internal,
    }
}

/// Emit `hort_prefetch_self_service_total{format, repository, result}`.
/// Tick semantics:
///
/// - Per-call ticks for short-circuit gates (`permission_denied`,
///   `token_kind_denied`, `oci_unsupported`) — emitted ONCE per call
///   from the use-case gate block, then `Err` returned before any
///   item iteration.
/// - Per-item ticks for everything else — a 100-item batch with 80
///   successes + 15 rejected + 5 timeouts produces 100 ticks.
///
/// Emitted EXCLUSIVELY from
/// `hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase::enqueue_self_service`
/// (architect-doc *"Emission by layer"* — business metrics emit at the
/// hort-app use-case layer, never at the inbound handler).
///
/// `format` carries the protocol key (`"npm"`, `"pypi"`, `"cargo"`);
/// for gates that fire before repo resolution (token-kind), pass
/// [`values::FORMAT_UNKNOWN`].
///
/// `repository` follows the catalog convention: pass the resolved repo
/// key, or [`values::REPOSITORY_ALL`] for pre-resolution gate ticks.
pub fn emit_prefetch_self_service(
    format: &str,
    repository: &str,
    result: PrefetchSelfServiceResult,
) {
    metrics::counter!(
        "hort_prefetch_self_service_total",
        labels::FORMAT => format.to_owned(),
        labels::REPOSITORY => repository.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Outcome of one `hort_upstream_checksum_total` emission, used as the
/// `result` label. Three variants:
///
/// - `Verified` / `Mismatch` are emitted by `IngestUseCase::ingest_verified`
///   atomically with the corresponding `ChecksumVerified` /
///   `ChecksumMismatch` events on the verified-ingest path.
/// - `ChecksumMissing` is emitted by an inbound HTTP handler **before**
///   the bytes ever reach the ingest use case, when the upstream
///   response failed to supply the required verification target. The
///   canonical case is an OCI
///   tag-mode pull whose upstream response omitted
///   `Docker-Content-Digest`: refusing the pull with 502 is the only
///   way to keep `ChecksumVerified` an honest attestation that an
///   upstream-supplied digest was checked.
///
/// The previously-considered "checksum unavailable from upstream"
/// case for the *metadata* path (`parse_upstream_checksum`) is still
/// out of scope — that path returns 502 from the HTTP handler before
/// any metric is emitted (ADR 0006 mandatory-verification rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamChecksumResult {
    /// Computed hash matched upstream-published or URL-embedded digest.
    Verified,
    /// Computed hash disagreed.
    Mismatch,
    /// Upstream response carried no verification target — refused at
    /// the inbound HTTP handler with 502. The verification chain of
    /// custody is preserved by *not* emitting `ChecksumVerified` on
    /// this path.
    ChecksumMissing,
}

impl UpstreamChecksumResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::ChecksumMissing => "checksum_missing",
        }
    }
}

/// Emit `hort_upstream_checksum_total{format, result}` once per
/// verification attempt. Single emission site:
/// `IngestUseCase::ingest_verified`.
pub fn emit_upstream_checksum(format: &str, result: UpstreamChecksumResult) {
    metrics::counter!(
        "hort_upstream_checksum_total",
        labels::FORMAT => format.to_string(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Pull-through deduplication label taxonomies.
//
// Lives in `hort-app::metrics` (not `hort-domain::metrics`) per the architect-
// skill rule: "result enums live with the emitting layer". The emitter
// is `hort_app::pull_dedup::PullDedup` — a pure application-layer service.
// `hort_upstream_fetch_total` is intentionally NOT extended: followers
// never reach `hort-adapters-upstream-http`, so the
// existing counter automatically means "actual upstream HTTP requests
// issued" without modification.
// ---------------------------------------------------------------------------

/// Coalescing layer that produced an emission. Used as the `layer`
/// label of `hort_pull_dedup_total` and `hort_pull_dedup_wait_seconds`.
///
/// Closed taxonomy of two values. String values are normative — they
/// appear verbatim in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupLayer {
    /// Per-process Layer A — `DashMap<DedupKey, broadcast::Sender>`.
    /// Followers join an in-flight `broadcast::Receiver` on the same
    /// pod with zero round-trips.
    InProcess,
    /// Cluster Layer B — `EphemeralStore::put_if_absent` keyed lock
    /// + status broadcast. Followers either short-circuit on a
    ///   negative-cache hit, wait on the leader's CAS write, or
    ///   re-attempt election when the lock TTL expires without a
    ///   terminal outcome.
    Cluster,
}

impl DedupLayer {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::Cluster => "cluster",
        }
    }
}

/// Outcome of a single `coalesce_metadata` / `coalesce_blob` call.
/// Used as the `outcome` label of `hort_pull_dedup_total`.
///
/// Closed taxonomy of eight values. String values are normative —
/// they appear verbatim in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupOutcomeLabel {
    /// This caller won leader election (Layer A `DashMap::entry::or_*`
    /// vacant arm, OR Layer B `put_if_absent → true`). The fetch
    /// closure ran exactly once across the coalescing window.
    LeaderStarted,
    /// Follower waited on either the Layer-A broadcast or the Layer-B
    /// poll loop, then observed a `Succeeded*` outcome — the leader's
    /// fetch landed and the follower returned the cached result
    /// without contacting the upstream.
    FollowerWaitedHit,
    /// Follower waited on either layer and then observed a `Failed`
    /// outcome from the leader (4xx, 5xx, timeout, checksum mismatch,
    /// …). The follower returned the same error to its client without
    /// contacting the upstream — the load-bearing negative-cache
    /// property.
    FollowerWaitedFailure,
    /// Follower waited up to `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS` and
    /// the leader still had not produced a terminal outcome. Fall-
    /// through is a `503 + Retry-After: 30` response — *not* an
    /// un-coalesced fetch.
    FollowerFellthrough503,
    /// Caller arrived during a `Failed`-with-future-`expires_at`
    /// window and short-circuited on the cached failure WITHOUT
    /// re-attempting `put_if_absent`. Distinct from
    /// `FollowerWaitedFailure` because no waiting actually happened —
    /// the cached terminal record was read directly.
    NegativeCacheHit,
    /// Layer-B lock TTL expired without a terminal outcome (the
    /// previous leader pod died mid-fetch or its heartbeat task
    /// crashed). This caller won the re-election `put_if_absent` and
    /// became the new leader. Logged at `info!` — operationally
    /// interesting transition.
    LockExpiredReElected,
    /// Layer-A `broadcast::Receiver` returned `Lagged(_)` because the
    /// channel capacity (64) was exceeded. The follower fell through
    /// to a Layer-B `get` on the same key — correctness is
    /// preserved, the metric exists for visibility into this
    /// implausible-but-defended path.
    FollowerLagged,
    /// `EphemeralStore::put_if_absent` (or any other Layer-B call)
    /// returned an error. Caller proceeded as the leader anyway
    /// (fail-open); Layer A still provides
    /// per-replica coalescing for any other concurrent caller on the
    /// same pod. Cluster-wide coalescing is degraded; correctness is
    /// preserved by the existing CAS + path-conflict short-circuit.
    LayerBUnavailable,
}

impl DedupOutcomeLabel {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::LeaderStarted => "leader_started",
            Self::FollowerWaitedHit => "follower_waited_hit",
            Self::FollowerWaitedFailure => "follower_waited_failure",
            Self::FollowerFellthrough503 => "follower_fellthrough_503",
            Self::NegativeCacheHit => "negative_cache_hit",
            Self::LockExpiredReElected => "lock_expired_re_elected",
            Self::FollowerLagged => "follower_lagged",
            Self::LayerBUnavailable => "layer_b_unavailable",
        }
    }
}

// ---------------------------------------------------------------------------
// Insecure-upstream opt-in taxonomy.
// ---------------------------------------------------------------------------

// `RedirectBlockReason` / `emit_redirect_blocked` (the retired
// `hort-net-egress::redirect` module) and the
// `hort_upstream_redirect_blocked_total` metric were deleted; no consumer
// remained here after the connect-time DNS guard and hop-by-hop redirect
// SSRF re-validator were retired. The catalog row was removed from
// `docs/metrics-catalog.md` in the same change.

/// Reason a fetch passed through a plaintext (`http://`) upstream.
/// Used as the `reason` label of `hort_upstream_insecure_total`.
///
/// Two values, fixed taxonomy. The catalog rule "no new metric name
/// or label value may be introduced without updating that file in the
/// same change" forbids adding a variant without a
/// `docs/metrics-catalog.md` edit in the same PR.
///
/// Both reasons indicate the same posture problem (a credential or
/// metadata fetch went over plaintext); the distinction is provenance
/// — a `scheme_http` row was opted into by the operator via the
/// `insecure_upstream_url: true` mapping flag, while
/// `mapping_legacy` is reserved for any future row that pre-dates the
/// flag's introduction (none today; the column is `NOT NULL DEFAULT
/// FALSE` and the value-object constructor rejects non-https
/// upstreams without the opt-in). Keeping the two distinguishable in
/// the metric stream lets operators tell deliberate exceptions apart
/// from drift if a future migration ever resurrects the legacy path.
///
/// Lives in `hort-app::metrics` rather than the upstream-HTTP adapter
/// per CLAUDE.md "result enums live with the emitting layer". The
/// emission site is the adapter, but the taxonomy is a workspace-wide
/// contract owned by `hort-app`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamInsecureReason {
    /// The mapping's `upstream_url` is `http://` and the operator
    /// explicitly set `insecure_upstream_url: true` to opt in. Every
    /// fetch through such a mapping fires this counter and a
    /// `tracing::warn!` line so the posture is impossible to miss.
    SchemeHttp,
    /// Reserved for a future row that carries the `insecure` posture
    /// for legacy reasons (e.g. a back-fill from a snapshot that
    /// pre-dates the flag). No emission site uses this value today; it is
    /// declared in the taxonomy so a follow-up does not have to
    /// re-touch the catalog.
    MappingLegacy,
}

impl UpstreamInsecureReason {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly. Two values only.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SchemeHttp => "scheme_http",
            Self::MappingLegacy => "mapping_legacy",
        }
    }
}

/// Emit `hort_upstream_insecure_total{format,reason}` once per fetch
/// through a mapping that carries the `insecure_upstream_url: true`
/// opt-in. Gives operators a single counter to alert on so a plaintext
/// upstream cannot drift into the deployment unnoticed.
pub fn emit_upstream_insecure(format: &str, reason: UpstreamInsecureReason) {
    metrics::counter!(
        "hort_upstream_insecure_total",
        labels::FORMAT => format.to_string(),
        labels::REASON => reason.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Outbound TLS handshake outcomes.
// ---------------------------------------------------------------------------

/// Outcome of a single outbound TLS handshake. Used as the `result` label of
/// `hort_upstream_tls_handshake_total`. Five values, fixed taxonomy.
///
/// Why a dedicated metric and not a sub-arm of `hort_upstream_fetch_total`:
/// fetch-level counters classify the *application-layer* outcome (404,
/// checksum mismatch, body-too-large, …). The TLS-handshake counter
/// classifies the *transport-layer* outcome — the same connection that
/// later succeeds at fetch level may have produced one of these
/// transitions during its handshake (a CA augmentation, an mTLS
/// presentation, a pinning verifier ruling), and operators need to
/// alert on the transport posture independently of the fetch outcome.
///
/// `repository` label collapse via `METRICS_INCLUDE_REPOSITORY_LABEL`
/// follows the architect-skill rule: at scale operators set the toggle
/// to `false` and every series collapses to `repository="_all"`.
///
/// Lives in `hort-app::metrics` rather than the upstream-HTTP adapter
/// per CLAUDE.md "result enums live with the emitting layer". The
/// emission site is the adapter, but the taxonomy is a workspace-wide
/// contract owned by `hort-app`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTlsHandshakeResult {
    /// Handshake completed; chain validated, name validated, and
    /// (when configured) leaf-cert thumbprint matched the pin.
    Success,
    /// Server demanded a client certificate (`CertificateRequest`)
    /// but the mapping carries no `mtls_cert_ref` / `mtls_key_ref`
    /// pair. Surfaced as `Unauthorized` on the fetch metric —
    /// the operator either intends mTLS (configure the
    /// pair) or does not (server posture mismatch).
    MtlsRequired,
    /// Server's certificate chain did not chain to a trust anchor in
    /// the configured root store. The `ca_bundle_ref` augmentation
    /// is the operator's lever to extend trust.
    CaUnknown,
    /// Operator-pinned thumbprint disagreed with the
    /// upstream's presented leaf cert.
    PinMismatch,
    /// Any other transport-layer failure: TCP refused, TLS
    /// handshake aborted by the peer, deadline exceeded mid-handshake.
    /// Classified as `network_error` so dashboards can split
    /// "transport never came up" from the higher-precision
    /// classifications above.
    NetworkError,
}

impl UpstreamTlsHandshakeResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly. Five values only.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::MtlsRequired => "mtls_required",
            Self::CaUnknown => "ca_unknown",
            Self::PinMismatch => "pin_mismatch",
            Self::NetworkError => "network_error",
        }
    }
}

/// Emit `hort_upstream_tls_handshake_total{repository,result}` once per
/// outbound TLS handshake the upstream proxy completes (success or
/// failure).
///
/// `repository` is pre-resolved by the caller. The collapse helper
/// (proxy adapter) emits [`values::REPOSITORY_ALL`] when
/// `METRICS_INCLUDE_REPOSITORY_LABEL=false`; this helper does not
/// re-check the toggle so the cardinality budget is enforced exactly
/// once at the call site.
///
/// Cardinality envelope: `repository` (≤ 10k or `_all`) × 5 result
/// values. Same governance as `hort_ingest_*` and `hort_upstream_*`.
pub fn emit_upstream_tls_handshake(repository: &str, result: UpstreamTlsHandshakeResult) {
    metrics::counter!(
        "hort_upstream_tls_handshake_total",
        labels::REPOSITORY => repository.to_string(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Auth-event store + IP-bucketing helpers.
// ---------------------------------------------------------------------------

/// IPv4 prefix length used to bucket the throttle key for
/// `AuthenticationAttempted` event appends. `/24` collapses ~256 host
/// addresses into one key, bounding `EphemeralStore` cardinality from
/// the IPv4 attacker side.
pub const IPV4_BUCKET_PREFIX_BITS: u8 = 24;

/// IPv6 prefix length used to bucket the throttle key for
/// `AuthenticationAttempted` event appends. `/48` is the IETF-standard
/// site allocation boundary — coarse enough that an attacker cannot
/// mint arbitrary keys per request (which a raw IPv6 key would
/// permit, exhausting ephemeral memory) yet fine enough that
/// distinct sites do not share a throttle bucket.
pub const IPV6_BUCKET_PREFIX_BITS: u8 = 48;

/// Coarsen a client IP into a string suitable for use as a throttle
/// key dimension.
///
/// IPv4 addresses are coarsened to `/24` (first three octets);
/// IPv6 addresses are coarsened to `/48` (first three 16-bit
/// segments). The returned string carries an explicit prefix-length
/// suffix (`<bucket>/24` or `<bucket>/48`) so the wire form is
/// self-describing in audit logs and so two distinct buckets cannot
/// stringly-collide.
///
/// **Why bucket the throttle key but not the audit payload.** Raw
/// IP is the audit value — it lands verbatim in the
/// `AuthenticationAttempted` event payload's `client_ip` field. The
/// bucket is for `EphemeralStore` key cardinality only — without
/// coarsening, an IPv6 attacker can mint 2^128 unique keys and
/// exhaust ephemeral memory long before any TTL kicks in. With the
/// `/48` bucket, the active key set is bounded by the count of
/// active attacker prefixes (typically tiny — entries TTL out after
/// 60 seconds and stop being written after the first append per
/// window, so each prefix holds at most one live entry at a time).
pub fn client_ip_bucket(ip: std::net::IpAddr) -> String {
    // Dual-stack peers that arrive as
    // `::ffff:a.b.c.d` (IPv4-mapped IPv6, RFC 4291 §2.5.5) must
    // coalesce into the same bucket as the bare IPv4 form. Without
    // canonicalization the throttle key `(bucket, result)` fragments
    // across two buckets and the per-IP rate limit halves its
    // effective threshold for dual-stack callers.
    //
    // `to_canonical` is a no-op for `IpAddr::V4` and for `IpAddr::V6`
    // values that are NOT IPv4-mapped, so existing IPv6 site buckets
    // (`/48`) are preserved unchanged.
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // /24 = first three octets; the fourth is replaced with
            // 0 to make the bucket form unambiguous.
            format!(
                "{}.{}.{}.0/{}",
                octets[0], octets[1], octets[2], IPV4_BUCKET_PREFIX_BITS,
            )
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // /48 = first three 16-bit segments; the rest of the
            // address is collapsed to `::`.
            format!(
                "{:x}:{:x}:{:x}::/{}",
                segments[0], segments[1], segments[2], IPV6_BUCKET_PREFIX_BITS,
            )
        }
    }
}

/// Outcome label on `hort_auth_events_appended_total`. Four values, fixed
/// taxonomy. The catalog rule "no new metric name or label value
/// may be introduced without updating that file in the same change"
/// forbids adding a variant without a `docs/metrics-catalog.md`
/// edit in the same PR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEventResult {
    /// Reserved for completeness — successes do NOT currently
    /// produce events (tracing-only for
    /// successes). The label value is reserved in the catalog so a
    /// future policy flip does not require a new variant.
    Success,
    /// The event was successfully written to the event store.
    Appended,
    /// The throttle key (`(client_ip_bucket, result)` 60s TTL) was
    /// already engaged; no event was appended.
    Throttled,
    /// The event store rejected the append (concurrency conflict,
    /// adapter I/O error, ...). The auth path is unaffected — the
    /// caller still receives the originating 401; the audit log is
    /// best-effort.
    Error,
}

impl AuthEventResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Appended => "appended",
            Self::Throttled => "throttled",
            Self::Error => "error",
        }
    }
}

/// Emit `hort_auth_events_appended_total{result}` once per
/// auth-event-append decision.
///
/// Every failure-path classification site fires this counter exactly
/// once: `appended` when the event store accepted the write,
/// `throttled` when the EphemeralStore-backed throttle key suppressed
/// it, `error` when the append itself failed. Successes do not fire
/// this counter today (see [`AuthEventResult::Success`] docstring).
///
/// `client_ip` does NOT appear as a label — high-cardinality
/// attacker-controlled dimensions on metrics are the architect's
/// hard-block anti-pattern. Per-instance attribution lives in the
/// `AuthenticationAttempted` event payload's `client_ip` field
/// (the durable record), not in a metric series.
pub fn emit_auth_event(result: AuthEventResult) {
    metrics::counter!(
        "hort_auth_events_appended_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Persisted `is_admin`-transition observability.
// ---------------------------------------------------------------------------

/// Direction of a persisted `User.is_admin` flip, used as the `result`
/// label of `hort_is_admin_transition_total`.
///
/// Two values, fixed taxonomy. The catalog rule "no new metric name or
/// label value may be introduced without updating that file in the
/// same change" forbids adding a variant without a
/// `docs/metrics-catalog.md` edit in the same PR. There is deliberately
/// no `unchanged` variant — an idempotent recompute that leaves the
/// bit alone emits nothing at all (the metric counts flips, not
/// logins; per-login volume would swamp the signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsAdminTransitionResult {
    /// The bit flipped `false → true` — admin authority was granted.
    Granted,
    /// The bit flipped `true → false` — admin authority was revoked.
    Revoked,
}

impl IsAdminTransitionResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Revoked => "revoked",
        }
    }
}

/// Emit `hort_is_admin_transition_total{result}` once per persisted
/// `is_admin` flip.
///
/// Fired by `hort-app::use_cases::authenticate_use_case` at the
/// recompute+persist site **only** when an existing user row's
/// `is_admin` differs from the freshly-recomputed value. A
/// JIT-provisioned user (no prior durable bit) and an idempotent
/// recompute that leaves the bit unchanged both emit nothing — the
/// counter tracks transitions, not logins, so a spurious flip stands
/// out instead of being buried under per-login noise.
///
/// `user_id` / `external_id` do NOT appear as labels —
/// per-principal attribution is a high-cardinality architect
/// hard-block. The durable per-user attribution lives in the
/// `AdminStatusChanged` event payload (the audit record), not in a
/// metric series.
pub fn emit_is_admin_transition(result: IsAdminTransitionResult) {
    metrics::counter!(
        "hort_is_admin_transition_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Policy-evaluation metric taxonomy.
// ---------------------------------------------------------------------------

/// Outcome of one policy evaluation, used as the `result` label of
/// `hort_policy_evaluation_total`.
///
/// The enum is union-shaped — most decision points only emit a subset
/// of the variants. Per `docs/metrics-catalog.md`:
///
/// - `scan_result` → `Pass` | `Reject`
/// - `promotion` → `Pass` | `Warn` | `RequireApproval` | `Reject`
/// - `re_evaluation` → `StillRejected` | `ResetToQuarantined` |
///   `ResetToReleased`
/// - `curation` → `Pass` (Allow) | `Warn` | `Block`
/// - `curation_retroactive` → `NoChange` | `RetroWarn` | `RetroBlock`
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. The catalog rule "no new metric name or
/// label value may be introduced without updating that file in the
/// same change" forbids adding a variant without a catalog edit in the
/// same PR.
///
/// Lives in `hort-app::metrics` rather than `hort-domain` per CLAUDE.md
/// "result enums live with the emitting layer". The architect skill's
/// anti-pattern checklist treats `hort-domain/src/metrics.rs` as a hard
/// block; the domain has zero metric concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEvaluationResult {
    /// Allow / Clean / no-finding: the everything's-fine outcome.
    /// Normative across decision points — `IngestUseCase::ingest`'s
    /// curation-`Allow` and `QuarantineUseCase::record_scan_result`'s
    /// `Clean` both map here so dashboards aggregate happy-path traffic
    /// under one label.
    Pass,
    /// Promotion or curation evaluator returned `Warn` — proceeds with
    /// audit logging.
    Warn,
    /// Promotion gate observed `requireApproval=true` and emits an
    /// `ApprovalRequested`.
    RequireApproval,
    /// Curation gate matched a `Block` rule. Distinct from `Reject` so
    /// curation-block volume can be tracked separately from
    /// scan/promotion rejections.
    Block,
    /// Scan-result or promotion evaluator returned `Reject`.
    Reject,
    /// Re-evaluation pass: the artifact's blocking findings remain
    /// after the new exclusion. No state transition.
    StillRejected,
    /// Re-evaluation: blocking findings cleared; quarantine_until is
    /// still in the future, so the artifact returns to Quarantined.
    ResetToQuarantined,
    /// Re-evaluation: blocking findings cleared; quarantine_until has
    /// elapsed, so the artifact transitions directly to Released.
    ResetToReleased,
    /// Retroactive-curation pass: matched a `Warn` rule; no artifact
    /// stream change.
    RetroWarn,
    /// Retroactive-curation pass: matched a `Block` rule; the artifact
    /// transitions to Rejected with `RejectionReason::CurationRetroactive`.
    RetroBlock,
    /// Retroactive-curation pass: no rule matched, or matched an Allow
    /// override.
    NoChange,
}

impl PolicyEvaluationResult {
    /// Label value string — must match the catalog exactly.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::RequireApproval => "require_approval",
            Self::Block => "block",
            Self::Reject => "reject",
            Self::StillRejected => "still_rejected",
            Self::ResetToQuarantined => "reset_to_quarantined",
            Self::ResetToReleased => "reset_to_released",
            Self::RetroWarn => "retro_warn",
            Self::RetroBlock => "retro_block",
            Self::NoChange => "no_change",
        }
    }
}

/// Emit `hort_policy_evaluation_total{decision_point, result}` — fired
/// once per policy-evaluation decision regardless of whether the
/// outcome carries violations.
///
/// `decision_point` is `&'static str` to enforce the catalog-bounded
/// enum at the type level: callers pass one of the
/// [`policy_decision_point`] constants. Free-form strings cannot reach
/// this function. Mirrors the shape of [`emit_gitops_event`].
pub fn emit_policy_evaluation(decision_point: &'static str, result: PolicyEvaluationResult) {
    metrics::counter!(
        "hort_policy_evaluation_total",
        labels::DECISION_POINT => decision_point,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Emit `hort_policy_violations_total{decision_point, rule}` — fired
/// once per distinct `rule` across the supplied violation slice.
///
/// Multiple violations with the same `rule` collapse to a single
/// counter increment; this keeps the "how many evaluations produced
/// each kind of violation" semantic clean and prevents a fan-out of
/// one finding per CVE inflating the counter linearly with scan
/// findings. The dashboard signal is "the rule fired", not "the rule
/// fired N times".
///
/// Skipped when `violations` is empty (the `pass` / `no_change`
/// outcomes never reach this helper anyway).
pub fn emit_policy_violations(
    decision_point: &'static str,
    violations: &[hort_domain::events::PolicyViolation],
) {
    if violations.is_empty() {
        return;
    }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for violation in violations {
        if seen.insert(violation.rule.as_str()) {
            metrics::counter!(
                "hort_policy_violations_total",
                labels::DECISION_POINT => decision_point,
                labels::RULE => violation.rule.clone(),
            )
            .increment(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Provenance-verification observability.
//
// Two counters, emitted at the single `hort-app` orchestration layer
// (`ProvenanceOrchestrationUseCase`) — one emission layer per the
// architect's "each metric emitted at exactly one layer" rule:
//   - `hort_provenance_verify_total{backend, mode, result}`
//   - `hort_provenance_reject_total{backend, reason}`
// `backend`/`mode` are small bounded sets; NO high-cardinality labels
// (no artifact_id / content_hash / version). The domain stays
// metrics-free; the verdict + mode are surfaced to this layer by the
// use case at the emission site.
// ---------------------------------------------------------------------------

/// `result` label value for `hort_provenance_verify_total`. Closed
/// taxonomy of 3. String values are normative — they appear
/// verbatim in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceVerifyResult {
    /// A trusted signature was verified (`ProvenanceVerified` emitted).
    Verified,
    /// A typed rejection (`ProvenanceRejected` emitted) — the per-reason
    /// breakdown lives on the companion `hort_provenance_reject_total`.
    Rejected,
    /// No bundle was found / passed and the mode allowed it
    /// (`VerifyIfPresent` no-op, no event). Under `Required` an unsigned
    /// artifact is mapped to `Rejected{Unsigned}` upstream and ticks
    /// `rejected` here instead — so `no_attestation` is strictly the
    /// allowed-unsigned case.
    NoAttestation,
}

impl ProvenanceVerifyResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::NoAttestation => "no_attestation",
        }
    }
}

/// Wire string for the `reason` label on `hort_provenance_reject_total`,
/// one per [`hort_domain::ports::provenance::ProvenanceRejectReason`]
/// variant. Closed taxonomy of 5; the exhaustive match means a future
/// reject variant cannot ship without a catalog entry here (the compiler
/// flags the missing arm). String values are normative — they appear
/// verbatim in `docs/metrics-catalog.md`.
pub fn provenance_reject_reason_label(
    reason: hort_domain::ports::provenance::ProvenanceRejectReason,
) -> &'static str {
    use hort_domain::ports::provenance::ProvenanceRejectReason as R;
    match reason {
        R::Unsigned => "unsigned",
        R::UntrustedIdentity => "untrusted_identity",
        R::RekorNotFound => "rekor_not_found",
        R::CertChainInvalid => "cert_chain_invalid",
        R::BundleMalformed => "bundle_malformed",
    }
}

/// Emit `hort_provenance_verify_total{backend, mode, result}` once per
/// applied verdict. Single emission site:
/// `ProvenanceOrchestrationUseCase::verify_artifact`. `mode` is the
/// resolved `provenance_mode` lowercase wire-form
/// ([`hort_domain::entities::scan_policy::ProvenanceMode`] `Display`).
pub fn emit_provenance_verify(
    backend: &str,
    mode: hort_domain::entities::scan_policy::ProvenanceMode,
    result: ProvenanceVerifyResult,
) {
    metrics::counter!(
        "hort_provenance_verify_total",
        labels::BACKEND => backend.to_string(),
        labels::MODE => mode.to_string(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Emit `hort_provenance_reject_total{backend, reason}` once per
/// rejected verdict, in addition to the
/// `result="rejected"` tick on `hort_provenance_verify_total`. Single
/// emission site: `ProvenanceOrchestrationUseCase::verify_artifact`.
pub fn emit_provenance_reject(
    backend: &str,
    reason: hort_domain::ports::provenance::ProvenanceRejectReason,
) {
    metrics::counter!(
        "hort_provenance_reject_total",
        labels::BACKEND => backend.to_string(),
        labels::REASON => provenance_reject_reason_label(reason),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Test helper: capture emitted metrics into a snapshot.
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
use metrics_util::debugging::{DebuggingRecorder, Snapshot};

/// Capture metrics emitted inside a closure. Returns a snapshot that callers
/// can inspect via `snapshot.into_vec()`.
///
/// For async code under test, nest a runtime inside the closure because
/// `metrics::with_local_recorder` takes a sync closure:
/// ```ignore
/// let snap = capture_metrics(|| {
///     tokio::runtime::Runtime::new().unwrap().block_on(async {
///         // async code here
///     });
/// });
/// ```
#[cfg(any(test, feature = "test-support"))]
pub fn capture_metrics<F>(f: F) -> Snapshot
where
    F: FnOnce(),
{
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter.snapshot()
}

// ----------------------------------------------------------------------------
// Gitops apply
// ----------------------------------------------------------------------------

/// Per-object outcome bucket. Reported on
/// `hort_gitops_objects_total{kind, result}` with one increment per
/// affected object. `Unchanged` increments are batched at the end —
/// see `emit_gitops_objects_unchanged`.
///
/// `hort_gitops_apply_total` (the sibling apply-outcome counter) is
/// owned by `hort-server::gitops_boot` — that crate is the sole boot
/// caller of `ApplyConfigUseCase::apply` and emits the four-value
/// classification (`ok | parse_error | validation_error |
/// apply_error`) directly via `metrics::counter!`. Per the
/// architect's "each metric emitted at exactly one layer" rule, the
/// use case must NOT emit `apply_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitopsObjectResult {
    Created,
    Updated,
    Deleted,
    Unchanged,
    /// Fired exclusively on
    /// `hort_gitops_objects_total{kind="upstream_mapping"}` when an
    /// `apply_upstream_mappings` create or update is rejected because
    /// the mapping URL's host is not in `HORT_UPSTREAM_ALLOWLIST_HOSTS`.
    /// The apply aborts with `AppError::Domain(Validation(_))`
    /// immediately after the increment so the operator sees a single
    /// loud error per misconfigured mapping. Only emitted by the
    /// upstream-mapping kind — other gitops kinds never use this
    /// variant. See `docs/operator/upstream-trust-model.md`.
    RejectedNotInAllowlist,
}

impl GitopsObjectResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Deleted => "deleted",
            Self::Unchanged => "unchanged",
            Self::RejectedNotInAllowlist => "rejected_not_in_allowlist",
        }
    }
}

/// Stable kind label for the gitops metrics. Pinned at the
/// emission site rather than imported from `hort_config::Kind` because
/// the metric label set is part of the catalog contract; a future
/// rename of `Kind::label()` must NOT silently change the metric
/// label values.
pub mod gitops_kind {
    pub const REPOSITORY: &str = "repository";
    /// Additive-claims mapping kind (the `claim_mappings` table;
    /// there is no structural `group_mappings` kind under the
    /// additive-claims model).
    pub const CLAIM_MAPPING: &str = "claim_mapping";
    /// (There is no `role` kind: the structural-RBAC `Role` plan does
    /// not exist under the additive-claims model, so no emitter
    /// passes it.)
    pub const PERMISSION_GRANT: &str = "permission_grant";
    pub const CURATION_RULE: &str = "curation_rule";
    pub const SCAN_POLICY: &str = "scan_policy";
    /// The event-sourced
    /// retention-policy gitops kind (same shape as `scan_policy`:
    /// per-envelope `hort_gitops_objects_total` + per-`RetentionPolicyChanged`
    /// `hort_gitops_events_emitted_total`).
    pub const RETENTION_POLICY: &str = "retention_policy";
    pub const EXCLUSION: &str = "exclusion";
    /// The `repository_upstream_mappings` gitops writer kind.
    pub const UPSTREAM_MAPPING: &str = "upstream_mapping";
    /// Gitops surface for trusted external
    /// OIDC issuers (workload federation).
    pub const OIDC_ISSUER: &str = "oidc_issuer";
    /// Gitops surface for declared non-human
    /// identities.
    pub const SERVICE_ACCOUNT: &str = "service_account";
}

pub fn emit_gitops_object(kind: &'static str, result: GitopsObjectResult) {
    metrics::counter!(
        "hort_gitops_objects_total",
        labels::KIND => kind,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Emit `hort_gitops_events_emitted_total{kind, event_type}` — the
/// per-event counter for event-sourced gitops applies.
///
/// Distinct from [`emit_gitops_object`]: the latter rolls per
/// envelope (one increment per `created/updated/deleted/unchanged`
/// outcome), while this counter rolls per `DomainEvent` produced
/// during the apply. A `ScanPolicy` UPDATE that changes two fields
/// emits one `objects_total{result=updated}` and two
/// `events_emitted_total{event_type=PolicyUpdated}`.
///
/// Both arguments are `&'static str` to enforce the catalog-bounded
/// enum at the type level: `kind` comes from
/// [`gitops_kind::SCAN_POLICY`] / [`gitops_kind::EXCLUSION`];
/// `event_type` comes from
/// [`hort_domain::events::DomainEvent::event_type`], which returns
/// `&'static str` from a static table. Free-form strings cannot reach
/// this function (architect-doc anti-pattern checklist).
///
/// Cardinality: `kind ∈ {scan_policy, exclusion}` × `event_type ∈
/// {PolicyCreated, PolicyUpdated, ExclusionAdded, ExclusionRemoved,
/// PolicyArchived}` = 10 series max. Some combinations
/// (`kind=exclusion, event_type=PolicyCreated`) never occur and
/// simply never fire.
pub fn emit_gitops_event(kind: &'static str, event_type: &'static str) {
    metrics::counter!(
        "hort_gitops_events_emitted_total",
        labels::KIND => kind,
        labels::EVENT_TYPE => event_type,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Vulnerability-scanning metrics taxonomy.
// ---------------------------------------------------------------------------

/// Outcome label of `hort_scan_jobs_total`. Closed
/// taxonomy of 4 — every state transition the orchestrator drives
/// maps to exactly one variant.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanJobsResult {
    /// Emitted by `ScanOrchestrationUseCase::claim_pending` per claimed
    /// job — one tick per row returned from `JobsRepository::claim_scan_jobs`.
    PendingClaimed,
    /// Emitted by `record_outcome` when the job reaches the
    /// `mark_completed` arm (both `Completed { … }` and
    /// `SkippedNoBackends` route through this label).
    Completed,
    /// Emitted by `record_outcome` on the terminal `mark_failed` arm
    /// (job exhausted `max_attempts`).
    Failed,
    /// Emitted by `record_outcome` when the job is rescheduled via
    /// `JobsRepository::reschedule` for a future attempt. Mutually
    /// exclusive with `Failed` for the same observation.
    Retried,
}

impl ScanJobsResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingClaimed => "pending_claimed",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Retried => "retried",
        }
    }
}

/// Emit `hort_scan_jobs_total{result}` once per scan-job state
/// transition.
pub fn emit_scan_jobs(result: ScanJobsResult) {
    metrics::counter!(
        "hort_scan_jobs_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Outcome label of `hort_scan_terminal_total` (the release-gate
/// predicate observability — ADR 0007).
/// Closed taxonomy of 3 — every *artifact-terminal* scan decision the
/// orchestrator drives maps to exactly one variant. Distinct from
/// [`ScanJobsResult`] (per-job-attempt state) — this counts
/// artifact-terminal decisions and must NOT double-count.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTerminalResult {
    /// The scanner decided: clean. Emitted on the `Completed{[]}` and
    /// `SkippedNoBackends` (operator waiver) arms of `record_outcome`.
    Completed,
    /// The scanner could not decide: terminal scan failure after retry
    /// exhaustion. Emitted on the retry-exhausted `Failed` arm — the
    /// artifact transitioned to `scan_indeterminate`.
    Indeterminate,
    /// The scanner decided: bad content. Emitted on the
    /// `Completed{findings}` arm — the artifact transitioned to
    /// `rejected`.
    Rejected,
}

impl ScanTerminalResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Indeterminate => "indeterminate",
            Self::Rejected => "rejected",
        }
    }
}

/// Emit `hort_scan_terminal_total{result}` once per *artifact-terminal*
/// scan decision. Emitted at exactly one
/// layer — `hort-app::scan_orchestration::record_outcome` — so it never
/// double-counts the per-attempt `hort_scan_jobs_total` counter.
pub fn emit_scan_terminal(result: ScanTerminalResult) {
    metrics::counter!(
        "hort_scan_terminal_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// `result` label value of `hort_scan_record_outcome_failures_total`.
/// The metric's `result` taxonomy is intentionally
/// extensible (see `docs/metrics-catalog.md`): `failed_branch` is the
/// original worker poll-loop value (record_outcome itself errored);
/// `report_too_large` is emitted by the
/// orchestrator's per-backend failure path when a scanner backend's
/// report drain hit the `HORT_SCANNER_MAX_REPORT_SIZE` cap and the
/// adapter killed the child + returned the bounded-drain error.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanFailureResult {
    /// Emitted by `hort_worker::poll_loop::emit_failed_branch_alert`
    /// when a Failed-branch `record_outcome` call itself returned
    /// `Err`. (Owned by the worker; this enum carries the value for
    /// catalog source-of-truth parity, but the worker's local emit
    /// helper predates this enum and is left untouched.)
    FailedBranch,
    /// Emitted by `ScanOrchestrationUseCase::run_scan`
    /// when a scanner backend failed because its
    /// report exceeded `HORT_SCANNER_MAX_REPORT_SIZE` — the adapter
    /// killed the child and returned the distinguishable bounded-drain
    /// error. `scanner` carries the originating backend name.
    ReportTooLarge,
}

impl ScanFailureResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FailedBranch => "failed_branch",
            Self::ReportTooLarge => "report_too_large",
        }
    }
}

/// Emit `hort_scan_record_outcome_failures_total{result, scanner}`.
///
/// `scanner` carries the originating scanner backend's name when the
/// failure is attributable to one (e.g. the `report_too_large` cap-hit
/// path knows the backend), otherwise the `(none)` sentinel. The
/// metric is alerting-only; per-artifact drill-down stays on tracing
/// spans (no `artifact_id` label).
pub fn emit_scan_failure(result: ScanFailureResult, scanner: &str) {
    metrics::counter!(
        "hort_scan_record_outcome_failures_total",
        labels::RESULT => result.as_str(),
        labels::SCANNER => scanner.to_string(),
    )
    .increment(1);
}

/// Emit `hort_scan_findings_total{scanner, severity}` once per
/// (deduplicated) finding contributed by a scanner backend.
///
/// `scanner` is the contributor name (`trivy`, `osv`, the `advisory`
/// sentinel for advisory-only entries, or any operator-registered
/// backend). `severity` is the lowercase `Display` form of
/// `SeverityThreshold`. Per-finding identifiers (`purl`,
/// `vulnerability_id`) MUST NOT be added as labels — they live on
/// tracing spans only.
pub fn emit_scan_findings(scanner: &str, severity: &str) {
    metrics::counter!(
        "hort_scan_findings_total",
        labels::SCANNER => scanner.to_string(),
        labels::SEVERITY => severity.to_string(),
    )
    .increment(1);
}

/// Observe one sample on `hort_scan_duration_seconds{scanner}` —
/// brackets exactly one `ScannerPort::scan` invocation.
///
/// SBOM extraction, advisory enrichment, dedup, and CAS persist all
/// run outside the timer because they are not in the scanner-perf
/// hot path.
pub fn observe_scan_duration(scanner: &str, duration: std::time::Duration) {
    metrics::histogram!(
        "hort_scan_duration_seconds",
        labels::SCANNER => scanner.to_string(),
    )
    .record(duration.as_secs_f64());
}

/// Outcome label of `hort_advisory_query_total`.
/// Closed taxonomy of 6 — every distinct cache-or-upstream outcome
/// the OSV adapter produces maps to exactly one variant.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryQueryResult {
    /// Per-component cache lookup short-circuited on the
    /// `EphemeralStore` cache — no upstream request fired for this
    /// component.
    CacheHit,
    /// Per-component cache lookup found nothing; component is
    /// enqueued for the OSV batch. One tick per missed component,
    /// fired once before the upstream call regardless of the
    /// upstream's eventual outcome (the cache_miss documents cache
    /// state; the upstream tick documents request outcome).
    CacheMiss,
    /// OSV `/v1/querybatch` POST returned a 4xx status. One tick per
    /// failed batch.
    Upstream4xx,
    /// OSV `/v1/querybatch` POST returned a 5xx status. One tick per
    /// failed batch.
    Upstream5xx,
    /// `reqwest::send()` returned an error before a status code was
    /// observed (DNS, TCP, TLS). One tick per failed batch.
    NetworkError,
    /// The per-request deadline elapsed before the batch responded.
    /// One tick per timed-out batch.
    Timeout,
}

impl AdvisoryQueryResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CacheHit => "cache_hit",
            Self::CacheMiss => "cache_miss",
            Self::Upstream4xx => "upstream_4xx",
            Self::Upstream5xx => "upstream_5xx",
            Self::NetworkError => "network_error",
            Self::Timeout => "timeout",
        }
    }
}

/// Emit `hort_advisory_query_total{result}` once per advisory-port
/// outcome (cache lookup or batch HTTP call).
pub fn emit_advisory_query(result: AdvisoryQueryResult) {
    metrics::counter!(
        "hort_advisory_query_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Outcome label of `hort_sbom_extraction_total`. Closed
/// taxonomy of 3 — `FormatHandler::extract_sbom` lands on exactly one
/// per dispatch.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomExtractionResult {
    /// Handler returned `Ok(Some(sbom))`.
    Success,
    /// Handler returned `Ok(None)` — opaque format with no
    /// machine-readable manifest (Helm, Conda, Hex, Pub, Generic, …)
    /// or no handler is registered for the format.
    UnsupportedFormat,
    /// Handler returned `Err(_)` — the format would normally produce
    /// an SBOM but the payload was malformed.
    ParseError,
}

impl SbomExtractionResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::UnsupportedFormat => "unsupported_format",
            Self::ParseError => "parse_error",
        }
    }
}

/// Emit `hort_sbom_extraction_total{format, result}` once per
/// `FormatHandler::extract_sbom` dispatch.
pub fn emit_sbom_extraction(format: &str, result: SbomExtractionResult) {
    metrics::counter!(
        "hort_sbom_extraction_total",
        labels::FORMAT => format.to_string(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Emit `hort_artifact_became_vulnerable_total{repository, severity,
/// ingest_source}` once per `ArtifactBecameVulnerable` event
/// appended (the metric and the event must rise together).
///
/// `repository` is pre-resolved by the caller — either the repository
/// key, or the [`values::REPOSITORY_ALL`] sentinel when the
/// `METRICS_INCLUDE_REPOSITORY_LABEL=false` toggle is on. `severity`
/// is the highest tier among `new_findings` (lowercase
/// `SeverityThreshold` form). `ingest_source` mirrors
/// `IngestSource` (`"direct"` / `"proxied"`).
pub fn emit_artifact_became_vulnerable(repository: &str, severity: &str, ingest_source: &str) {
    metrics::counter!(
        "hort_artifact_became_vulnerable_total",
        labels::REPOSITORY => repository.to_string(),
        labels::SEVERITY => severity.to_string(),
        labels::INGEST_SOURCE => ingest_source.to_string(),
    )
    .increment(1);
}

/// Eager registration of every
/// vulnerability-scanning metric against the active recorder.
///
/// The `metrics` facade registers metrics lazily on first
/// increment/observe. That works for emitting binaries but breaks
/// operator UX in the process where a metric is *consumed* (scraped)
/// but never *emitted* — hort-server scrapes /metrics; the worker
/// increments `hort_artifact_became_vulnerable_total` and the other
/// scanning counters. Without eager registration the metric is silently
/// absent from /metrics until something fires it, which makes the
/// "scanning is wired up" cold-start probe (`# TYPE
/// hort_artifact_became_vulnerable_total` in /metrics) fail even when
/// every component is healthy.
///
/// To make the TYPE line render, this helper does two things per
/// metric:
///
/// 1. `describe_*!` records the unit + description metadata.
/// 2. `counter!`/`histogram!`/`gauge!(name)` returns a handle —
///    creating that handle registers the metric in the recorder's
///    registry (`metrics::Counter::register_counter` etc.). The
///    handle is dropped immediately; the registry retains the
///    zero-valued entry, which is what `PrometheusHandle::render`
///    iterates over when emitting TYPE/HELP lines (the renderer
///    enumerates the registry's handles, NOT the description
///    metadata — see `metrics-exporter-prometheus`
///    `Inner::render_to_write`).
///
/// The composition root for each binary (`hort-server::telemetry`,
/// `hort-worker::telemetry`) calls this immediately after
/// `install_prometheus` so both processes' /metrics scrapes carry
/// the full scanning metric catalog from the first scrape.
///
/// Pairs every metric in `docs/metrics-catalog.md §Vulnerability
/// scanning`. New scanning metrics added to that table must also be
/// added here; the architect-skill review checklist enforces the
/// pairing.
pub fn register_scan_metrics() {
    use metrics::{
        counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram, Unit,
    };

    describe_counter!(
        "hort_scan_jobs_total",
        Unit::Count,
        "scan-job state transitions, by terminal `result` \
         (pending_claimed / completed / failed / retried)"
    );
    let _ = counter!("hort_scan_jobs_total");

    describe_counter!(
        "hort_scan_findings_total",
        Unit::Count,
        "deduplicated scanner findings, by `scanner` and `severity`"
    );
    let _ = counter!("hort_scan_findings_total");

    describe_histogram!(
        "hort_scan_duration_seconds",
        Unit::Seconds,
        "wall-clock spent inside each `ScannerPort::scan` call, by `scanner`"
    );
    let _ = histogram!("hort_scan_duration_seconds");

    describe_gauge!(
        "hort_scan_queue_depth",
        Unit::Count,
        "pending scan-jobs in the global queue, sampled per worker heartbeat"
    );
    let _ = gauge!("hort_scan_queue_depth");

    describe_counter!(
        "hort_advisory_query_total",
        Unit::Count,
        "advisory-port lookups, by `result` \
         (cache_hit / cache_miss / upstream_{4xx,5xx} / network_error / timeout)"
    );
    let _ = counter!("hort_advisory_query_total");

    describe_counter!(
        "hort_sbom_extraction_total",
        Unit::Count,
        "FormatHandler::extract_sbom dispatches, by `format` and `result` \
         (success / unsupported_format / parse_error)"
    );
    let _ = counter!("hort_sbom_extraction_total");

    describe_counter!(
        "hort_artifact_became_vulnerable_total",
        Unit::Count,
        "ArtifactBecameVulnerable events appended, by `repository`, `severity`, `ingest_source`"
    );
    let _ = counter!("hort_artifact_became_vulnerable_total");

    describe_counter!(
        "hort_scan_record_outcome_failures_total",
        Unit::Count,
        "scan-job record_outcome calls that landed on the catch-all error arm, \
         by `result` (failed_branch) and `scanner`"
    );
    let _ = counter!("hort_scan_record_outcome_failures_total");
}

// ---------------------------------------------------------------------------
// Rescan / advisory-watch metrics
// ---------------------------------------------------------------------------

/// `trigger_source` label value for `hort_scan_jobs_enqueued_total`.
/// Mirrors [`hort_domain::ports::jobs_repository::TriggerSource`]
/// — the wire strings are the literal SQL CHECK constraint values on
/// `jobs.trigger_source` (`'ingest' | 'cron' | 'advisory' | 'manual'`).
/// Closed taxonomy of 4.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md` and in the SQL CHECK. A drift here would
/// either fail the INSERT loudly or, if the CHECK were ever loosened,
/// silently file scan-enqueues under the wrong observability bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerSourceLabel {
    /// First-scan at ingest. Drives the ingest enqueue path.
    Ingest,
    /// `CronRescanTickHandler` — the periodic eligibility sweep.
    Cron,
    /// `AdvisoryWatchTickHandler` — the per-ecosystem advisory diff.
    Advisory,
    /// Operator-triggered manual rescan (`ManualRescanUseCase`).
    Manual,
}

impl TriggerSourceLabel {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// AND the SQL CHECK on `jobs.trigger_source` exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Cron => "cron",
            Self::Advisory => "advisory",
            Self::Manual => "manual",
        }
    }
}

/// Emit `hort_scan_jobs_enqueued_total{trigger_source}` once per
/// successful `JobsRepository::enqueue_scan`.
///
/// `count` is the number of newly-inserted scan rows in this call —
/// callers that batch-enqueue (cron, advisory) increment by N; callers
/// that enqueue a single row (manual, ingest) pass `1`. Conflict-on-
/// enqueue paths must NOT call this helper: only landed rows count.
pub fn emit_scan_jobs_enqueued(source: TriggerSourceLabel, count: u64) {
    metrics::counter!(
        "hort_scan_jobs_enqueued_total",
        labels::TRIGGER_SOURCE => source.as_str(),
    )
    .increment(count);
}

// ---------------------------------------------------------------------------
// Patch-candidate listing metric
// ---------------------------------------------------------------------------

/// `result` label value for `hort_patch_candidates_listed_total`.
/// Closed taxonomy of 4 — operator dashboards
/// distinguish `denied` (caller authz fail), `invalid` (caller-input
/// rejection), `ok` (happy path), and `error` (adapter/infrastructure
/// failure). The split between `invalid` and `error` is load-bearing —
/// collapsing them destroys the "bad request vs unhealthy system"
/// signal.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchCandidateListResult {
    /// Admin call succeeded — repo returned a `Vec` (possibly empty).
    Ok,
    /// `require_admin()` rejected the caller — emitted before the
    /// early return; repo never called.
    Denied,
    /// `filter.limit > MAX_LIMIT` — use-case validation rejected the
    /// input; repo never called.
    Invalid,
    /// Repo call returned `Err` — adapter / infrastructure failure.
    Error,
}

impl PatchCandidateListResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Invalid => "invalid",
            Self::Error => "error",
        }
    }
}

/// Emit `hort_patch_candidates_listed_total{repository, result}` once
/// per admin call to the patch-candidate listing surface.
///
/// `repository` carries the resolved repository key when the caller
/// scoped the request via `?repository=<key>` and the
/// handler resolved it to a row before invoking the use case;
/// otherwise the [`values::REPOSITORY_ALL`] sentinel is emitted for
/// the admin-wide scope. [`values::REPOSITORY_UNKNOWN`] is reserved
/// for non-HTTP / dispatcher paths — the HTTP handler short-circuits
/// to 404 on lookup failure before the use case is reached, so the
/// `"unknown"` label is unreachable from REST callers today.
///
/// Catalog rule (`docs/metrics-catalog.md`): for v1 the repository
/// label set is `{"_all", <key>}`; `"unknown"` is reserved.
pub fn emit_patch_candidates_listed(repository: &str, result: PatchCandidateListResult) {
    metrics::counter!(
        "hort_patch_candidates_listed_total",
        labels::REPOSITORY => repository.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Curation decisions metric
// ---------------------------------------------------------------------------

/// `decision` label value for `hort_curation_decisions_total`.
/// Closed taxonomy of 4; the curation use case emits `waive` / `block`.
/// The `exclude_finding` / `unexclude_finding` arms are emitted by
/// `PolicyUseCase::{add_exclusion, remove_exclusion}` on the curator
/// path.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurationDecisionLabel {
    /// `CurationUseCase::waive` — curator-driven release.
    Waive,
    /// `CurationUseCase::block` — curator-driven rejection (any target
    /// shape; per-append ticks share this label).
    Block,
    /// `PolicyUseCase::add_exclusion` — curator-driven addition of a
    /// CVE exclusion. Emitted at every terminal
    /// outcome (ok / invalid / conflict / error). The `repository`
    /// label resolves from `PolicyScope::Repository(id) → key` via
    /// `RepositoryAccessUseCase::metric_label`; `PolicyScope::Global`
    /// exclusions emit the `_all` sentinel (cross-repo by design).
    ExcludeFinding,
    /// `PolicyUseCase::remove_exclusion` — curator-driven removal of
    /// a CVE exclusion. Emitted at every terminal outcome.
    /// Repository label follows the same `PolicyScope` resolution
    /// shape as `ExcludeFinding`.
    UnexcludeFinding,
}

impl CurationDecisionLabel {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waive => "waive",
            Self::Block => "block",
            Self::ExcludeFinding => "exclude_finding",
            Self::UnexcludeFinding => "unexclude_finding",
        }
    }
}

/// `result` label value for `hort_curation_decisions_total`.
/// Closed taxonomy of 5. Mirrors `PatchCandidateListResult` shape
/// with one additional variant — `Conflict` — distinguishing
/// event-store version conflicts (a real "race lost, retry succeeds"
/// signal) from generic adapter `Error`. Operators alarm on
/// `error` (infrastructure) and `denied` (privilege failure spikes);
/// `conflict` is the contention-pressure signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurationDecisionResult {
    Ok,
    Denied,
    Invalid,
    Conflict,
    Error,
}

impl CurationDecisionResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Invalid => "invalid",
            Self::Conflict => "conflict",
            Self::Error => "error",
        }
    }
}

/// Emit `hort_curation_decisions_total{decision, repository, result}` —
/// one tick per attempted append. For `BlockTarget::VersionList` calls
/// the helper is invoked PER appended event, not once per call. This
/// lets operators dashboard per-append error rates on bulk operations.
///
/// `repository` follows the catalog convention:
/// - `None` from the caller → emit [`values::REPOSITORY_ALL`]
///   (used pre-lookup, e.g. privilege denials / validation failures
///   that fire before any artifact load resolves the repo id; also
///   the `PolicyScope::Global` exclusion path —
///   "cross-repo finding-exclusion").
/// - `Some(key)` → emit the resolved key verbatim. Callers obtain the
///   string from `RepositoryAccessUseCase::metric_label(repo_id)`,
///   which encapsulates the `METRICS_INCLUDE_REPOSITORY_LABEL=false`
///   collapse (returns `_all`) and the resolve-failure fallback
///   (returns `unknown`). Never pass a raw UUID — high-cardinality
///   attacker-controlled dimensions on metrics are the architect's
///   hard-block anti-pattern.
///
/// See `docs/metrics-catalog.md` "Manual curation decisions" for the
/// full label cardinality envelope, the `_all` / `unknown` sentinel
/// rules, and the forbidden-labels list.
pub fn emit_curation_decision(
    decision: CurationDecisionLabel,
    repository: Option<&str>,
    result: CurationDecisionResult,
) {
    let repo_label = repository.unwrap_or(values::REPOSITORY_ALL);
    metrics::counter!(
        "hort_curation_decisions_total",
        labels::DECISION => decision.as_str(),
        labels::REPOSITORY => repo_label.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Per-ecosystem outcome label of `hort_advisory_diff_processed_total`.
/// One emission per ecosystem per advisory-watch tick
/// from inside the OSV adapter's bulk loop. Closed taxonomy of 4.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryDiffResult {
    /// Per-ecosystem fetch + parse succeeded; new advisories (possibly
    /// zero) were appended to the diff result.
    Ok,
    /// Per-ecosystem HTTP fetch failed (non-2xx status, network error,
    /// or zip-body invalid). The handler's checkpoint is NOT advanced
    /// when any per-ecosystem result lands here.
    FetchError,
    /// Per-ecosystem fetch succeeded but the JSON / zip payload could
    /// not be parsed at the per-archive boundary. Distinct from
    /// per-record skip-on-malformed (which keeps processing the
    /// archive without surfacing here).
    ParseError,
    /// The per-request deadline elapsed before the bulk archive
    /// responded. Surfaced separately from `fetch_error` so operators
    /// can split slow-upstream from upstream-broken on dashboards.
    Timeout,
}

impl AdvisoryDiffResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::FetchError => "fetch_error",
            Self::ParseError => "parse_error",
            Self::Timeout => "timeout",
        }
    }
}

/// Emit `hort_advisory_diff_processed_total{ecosystem, result}` once per
/// per-ecosystem outcome inside the OSV bulk loop.
///
/// `ecosystem` MUST be the OSV bulk-archive label (`"npm"`, `"PyPI"`,
/// `"crates.io"`, `"Maven"`, `"Go"`, `"RubyGems"`, `"NuGet"`,
/// `"Packagist"`, `"Hex"`, `"Pub"`, `"Conda"`) — passing a free-form
/// name would inflate the cardinality ceiling beyond the documented
/// `≤ 8 × 4 = 32` series.
pub fn emit_advisory_diff(ecosystem: &str, result: AdvisoryDiffResult) {
    metrics::counter!(
        "hort_advisory_diff_processed_total",
        labels::ECOSYSTEM => ecosystem.to_string(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Observe one sample on `hort_advisory_diff_duration_seconds{ecosystem}`
/// — brackets the per-ecosystem `pull_one_ecosystem` call inside
/// `OsvAdvisoryAdapter::pull_diff_since`.
///
/// `ecosystem` is the OSV bulk-archive label, identical to the value
/// passed to [`emit_advisory_diff`].
pub fn observe_advisory_diff_duration(ecosystem: &str, secs: f64) {
    metrics::histogram!(
        "hort_advisory_diff_duration_seconds",
        labels::ECOSYSTEM => ecosystem.to_string(),
    )
    .record(secs);
}

/// Set `hort_cron_rescan_eligible_artifacts` to the count of artifacts
/// the most recent `CronRescanTickHandler` invocation found needed
/// rescan, after the batch cap. No labels — single
/// global gauge.
///
/// Operators alarm on sustained `> batch_size` (cron loop can't keep
/// up): the gauge moving into that range means consecutive ticks are
/// truncating the eligible set.
pub fn set_cron_rescan_eligible_artifacts(count: u64) {
    metrics::gauge!("hort_cron_rescan_eligible_artifacts").set(count as f64);
}

// ---------------------------------------------------------------------------
// Subscription create-time SSRF block
// ---------------------------------------------------------------------------

/// Map [`hort_domain::entities::subscription::SsrfBlockReason`] to its
/// canonical `reason` label value.
///
/// Closed match — no `_ =>` arm so adding a new `SsrfBlockReason` variant
/// fails to compile here, forcing a deliberate catalog update.
pub fn ssrf_reason_label(r: hort_domain::entities::subscription::SsrfBlockReason) -> &'static str {
    use hort_domain::entities::subscription::SsrfBlockReason;
    match r {
        SsrfBlockReason::IpLiteralNotRoutable => "ip_literal_not_routable",
        SsrfBlockReason::DnsResolvedNotRoutable => "dns_resolved_not_routable",
        SsrfBlockReason::DnsResolutionFailed => "dns_resolution_failed",
    }
}

/// Increment `hort_webhook_ssrf_block_total{reason=...}`.
///
/// Called by `SubscriptionUseCase::create` (and `update`) when the
/// webhook target guard rejects the URL host. Single emitter, single
/// layer. On the **create** path the counter pairs the durable
/// `SubscriptionCreationDenied{WebhookTargetNotRoutable}` event
/// appended on the same path; on the **update**
/// re-validation path the counter is emitted only — no durable event
/// and no `info!` are appended (a known audit asymmetry, recorded in
/// the ADR 0000 open-items register — not silently dropped).
/// Cardinality is fixed (3 reasons; see [`ssrf_reason_label`]).
///
/// **Metric name authority:** the catalog name is
/// `hort_webhook_ssrf_block_total{reason}` (it superseded an earlier
/// `hort_subscription_ssrf_blocked_total` name for this exact
/// emitter). There is exactly ONE emitter and ONE name — no
/// double-count.
pub fn emit_ssrf_block(reason: &'static str) {
    metrics::counter!(
        "hort_webhook_ssrf_block_total",
        labels::REASON => reason,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Subscription delivery dispatcher
// ---------------------------------------------------------------------------

/// `target_kind` label name for dispatcher delivery metrics
/// (`hort_notify_delivery_*`).
///
/// Distinct from `labels::KIND` (the gitops declarable kind) — the metric
/// catalog reserves a dedicated `target_kind` label for subscription
/// targets so the two taxonomies cannot collide.
pub const TARGET_KIND_LABEL: &str = "target_kind";

/// Map [`hort_domain::entities::subscription::SubscriptionTarget`] to its
/// canonical `target_kind` label value.
///
/// Closed match — no `_ =>` arm so adding a new `SubscriptionTarget`
/// variant fails to compile here, forcing a deliberate catalog update.
pub fn target_kind_label(
    target: &hort_domain::entities::subscription::SubscriptionTarget,
) -> &'static str {
    use hort_domain::entities::subscription::SubscriptionTarget;
    match target {
        SubscriptionTarget::Webhook { .. } => "webhook",
        SubscriptionTarget::NatsJetStream { .. } => "nats_jetstream",
    }
}

/// Map [`hort_domain::ports::event_notifier::NotifyOutcome`] to its
/// canonical `result` label value for `hort_notify_delivery_*` metrics.
///
/// Closed match — adding a new `NotifyOutcome` variant fails to
/// compile here, forcing a deliberate catalog update.
pub fn notify_outcome_label(
    outcome: &hort_domain::ports::event_notifier::NotifyOutcome,
) -> &'static str {
    use hort_domain::ports::event_notifier::NotifyOutcome;
    match outcome {
        NotifyOutcome::Delivered => "delivered",
        NotifyOutcome::DownstreamRejected { .. } => "downstream_rejected",
        NotifyOutcome::Failed { .. } => "failed",
    }
}

/// Emit `hort_notify_delivery_total{target_kind, result}` and observe
/// `hort_notify_delivery_duration_seconds{target_kind, result}` for a
/// single per-event delivery attempt. Cardinality is fixed
/// (`target_kind ∈ {webhook, nats_jetstream}`,
/// `result ∈ {delivered, downstream_rejected, failed}`).
pub fn emit_notify_delivery(target_kind: &'static str, result: &'static str, elapsed_secs: f64) {
    metrics::counter!(
        "hort_notify_delivery_total",
        TARGET_KIND_LABEL => target_kind,
        labels::RESULT => result,
    )
    .increment(1);
    metrics::histogram!(
        "hort_notify_delivery_duration_seconds",
        TARGET_KIND_LABEL => target_kind,
        labels::RESULT => result,
    )
    .record(elapsed_secs);
}

/// Increment `hort_notify_broadcast_lagged_total` (no labels) — emitted
/// when a per-subscription task receives
/// [`tokio::sync::broadcast::error::RecvError::Lagged`].
/// Operator signal that `HORT_NOTIFY_CHANNEL_CAPACITY` should be raised.
pub fn emit_broadcast_lagged() {
    metrics::counter!("hort_notify_broadcast_lagged_total").increment(1);
}

/// Set `hort_subscription_total{state}` gauge. Called by the dispatcher's
/// 30s reconcile pass with current counts of subscriptions in each
/// state. `state ∈ {active, paused, disabled}`.
pub fn set_subscription_state_gauge(state: &'static str, count: u64) {
    metrics::gauge!(
        "hort_subscription_total",
        "state" => state,
    )
    .set(count as f64);
}

// A `hort_notify_dispatcher_lag{category}` gauge is deliberately NOT
// implemented — it requires polling state across all per-subscription
// tasks, and the gauge would otherwise have stale-data semantics that
// operators have to learn. Implemented when a concrete operator need
// surfaces.

// ---------------------------------------------------------------------------
// `GET /api/v1/events` pull-resync metrics
// ---------------------------------------------------------------------------

/// Outcome of a single `GET /api/v1/events` call, used as the `result`
/// label of `hort_events_pull_total`.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. Closed enum so adding a new outcome
/// forces a deliberate catalog update.
///
/// Note: the bad-request exit (unknown `category` query param) is
/// intentionally NOT a variant here — the taxonomy is only
/// `{success, no_match, forbidden}`. Bad-request never enters the read
/// path and is not metered (the request never reaches the substrate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventsPullResult {
    /// Returned at least one event in the page.
    Success,
    /// Read succeeded but returned zero events for the requested
    /// `(category, after, max)` filter.
    NoMatch,
    /// Admin-only category requested by a non-admin caller; the request
    /// was rejected by the per-category authz gate before the read.
    Forbidden,
}

impl EventsPullResult {
    /// Label value string — must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NoMatch => "no_match",
            Self::Forbidden => "forbidden",
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountRotationHandler rotation metrics
// ---------------------------------------------------------------------------

/// Per-ServiceAccount decide-branch outcome label of
/// `hort_rotation_total`. One emission per SA per
/// reconciler tick from inside
/// [`ServiceAccountRotationHandler::run`](crate::task_handlers::ServiceAccountRotationHandler).
/// Closed taxonomy of 6.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationResult {
    /// `read_managed` returned `Some(s)` and `s.last_rotated` was
    /// within `rotation_interval` of now — fresh, no work needed.
    SkippedFresh,
    /// `read_managed` returned `Some(s)` and
    /// `s.managed_by != Some("hort-worker")` — the Secret was created
    /// out-of-band. Operator must `kubectl delete secret <name>` to
    /// hand management over.
    Collision,
    /// `sa.fallback_rotation.target_secret_namespace` is not in the
    /// worker's authorized `rotation_namespaces` set. Defence-in-depth
    /// against an SA pointing at an out-of-policy namespace.
    NamespaceNotAuthorized,
    /// Mint + upsert succeeded — fresh PAT minted, written to k8s,
    /// audit event emitted.
    Rotated,
    /// `ApiTokenUseCase::issue_for_service_account_system` returned
    /// an error (infrastructure, name/expiry shape, etc.). The
    /// reconciler logs + continues with the next SA — one bad SA
    /// must not stall the whole tick.
    MintFailed,
    /// `secret_writer.upsert_managed` returned an error (k8s API
    /// rejected the apply, network failure). The minted PAT persists
    /// in `api_tokens`; the next tick will see the stale Secret state
    /// and retry. Operators detect via the `last_rotated` gauge
    /// staying high while `mint_failed` is zero.
    WriteFailed,
}

impl RotationResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkippedFresh => "skipped_fresh",
            Self::Collision => "collision",
            Self::NamespaceNotAuthorized => "namespace_not_authorized",
            Self::Rotated => "rotated",
            Self::MintFailed => "mint_failed",
            Self::WriteFailed => "write_failed",
        }
    }
}

/// Emit `hort_events_pull_total{category, result}` and observe
/// `hort_events_pull_duration_seconds{category}` for one
/// `GET /api/v1/events` call.
///
/// `category` is the wire-form lowercase string used by the
/// `?category=` query param — pass the value returned by
/// `hort_http_events::dto::stream_category_wire`. Cardinality is fixed
/// (one per `StreamCategory` variant × the closed result set).
pub fn emit_events_pull(category: &'static str, result: EventsPullResult, elapsed_secs: f64) {
    metrics::counter!(
        "hort_events_pull_total",
        labels::CATEGORY => category,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
    metrics::histogram!(
        "hort_events_pull_duration_seconds",
        labels::CATEGORY => category,
    )
    .record(elapsed_secs);
}

/// Emit `hort_rotation_total{result}` once per SA per reconciler tick.
/// No `service_account` label — the per-SA dimension
/// lives on the lag gauge below, where bounded cardinality is the
/// design intent. This counter is the aggregate decide-branch view.
pub fn emit_rotation_result(result: RotationResult) {
    metrics::counter!(
        "hort_rotation_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Sentinel value emitted in place of the per-SA name when
/// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false`.
/// Mirrors [`values::REPOSITORY_ALL`] for the repository axis:
/// distinguishes "label disabled by operator config" from "label
/// missing" so dashboards stay legible after the toggle flips.
pub const SERVICE_ACCOUNT_ALL: &str = "_all";

/// Source label value on `hort_service_account_authenticated_total` —
/// emitted by the federation branch on `/auth/token-exchange`.
pub const SA_AUTH_SOURCE_FEDERATED: &str = "federated";

/// Source label value on `hort_service_account_authenticated_total` —
/// emitted by the PAT-auth path when the validated token's `kind`
/// is `TokenKind::ServiceAccount`.
pub const SA_AUTH_SOURCE_PAT: &str = "pat";

/// Resolve the `service_account` label value, honouring the
/// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false` collapse. Used by
/// both `hort_rotation_lag_seconds` and
/// `hort_service_account_authenticated_total` so the two metrics stay
/// in lock-step under the toggle.
fn sa_label_value(name: &str, include_label: bool) -> &str {
    if include_label {
        name
    } else {
        SERVICE_ACCOUNT_ALL
    }
}

/// Set `hort_rotation_lag_seconds{service_account}` to the number of
/// seconds since `last_rotated` for `service_account_name`.
/// A fresh rotation passes `0`; a fresh-on-skip passes the
/// observed age. Operators alarm on
/// `max_over_time(hort_rotation_lag_seconds[15m]) > rotation_interval
/// + grace`.
///
/// Cardinality: bounded by the operator's declared SA count
/// (typically <50). At scale, disable the per-SA label via
/// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false` — the gauge then
/// emits `service_account="_all"` and the operator loses the per-SA
/// breakdown but keeps the aggregate. `include_service_account_label`
/// is forwarded by [`ServiceAccountRotationHandler`] from its
/// composition-root-supplied config.
pub fn set_rotation_lag_seconds(
    service_account_name: &str,
    lag_secs: f64,
    include_service_account_label: bool,
) {
    let label = sa_label_value(service_account_name, include_service_account_label);
    metrics::gauge!(
        "hort_rotation_lag_seconds",
        labels::SERVICE_ACCOUNT => label.to_string(),
    )
    .set(lag_secs);
}

/// Emit one `hort_service_account_authenticated_total{service_account,
/// source}` increment. Honours the
/// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL` collapse — when
/// `include_service_account_label = false` the label collapses to
/// `service_account="_all"`, keeping the aggregate-count alarm
/// working at the cost of the per-SA breakdown.
///
/// `source` is one of [`SA_AUTH_SOURCE_FEDERATED`] or
/// [`SA_AUTH_SOURCE_PAT`] — closed taxonomy per the catalog row.
pub fn emit_service_account_authenticated(
    service_account_name: &str,
    source: &str,
    include_service_account_label: bool,
) {
    let label = sa_label_value(service_account_name, include_service_account_label);
    metrics::counter!(
        "hort_service_account_authenticated_total",
        labels::SERVICE_ACCOUNT => label.to_string(),
        labels::SOURCE => source.to_string(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Claim-based RBAC metrics taxonomy.
//
// Three closed-enum-bounded counters (catalog rows in
// `docs/metrics-catalog.md` §"Claim-based RBAC"). The closed enums +
// catalog rows are the load-bearing contract regardless of wiring
// order.
// ---------------------------------------------------------------------------

/// `source` label value of `hort_dispatcher_principal_resolved_total`.
/// Classifies how the subscription-delivery dispatcher
/// synthesised the evaluation principal from
/// `subscription.snapshot_claims`. Closed taxonomy of 3 — every
/// dispatcher principal-resolution path maps to exactly one variant.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. Adding a variant forces a deliberate
/// catalog update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatcherPrincipalSource {
    /// `snapshot_claims` was non-empty — the dispatcher evaluated the
    /// subscription against the persisted claim set captured at
    /// create/update time.
    SnapshotPresent,
    /// `snapshot_claims` was empty AND the owner carries the admin bit
    /// — an admin-owned subscription evaluates with admin authority
    /// even with no claims captured.
    SnapshotEmptyAdmin,
    /// `snapshot_claims` was empty AND the owner is not an admin. The
    /// operator diagnostic for "subscription created via PAT by a
    /// non-admin user" — such a subscription can never match a
    /// claims-scoped grant and is the actionable misconfiguration
    /// signal.
    SnapshotEmptyNoAdmin,
}

impl DispatcherPrincipalSource {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotPresent => "snapshot_present",
            Self::SnapshotEmptyAdmin => "snapshot_empty_admin",
            Self::SnapshotEmptyNoAdmin => "snapshot_empty_no_admin",
        }
    }
}

/// Emit `hort_dispatcher_principal_resolved_total{source}` once per
/// principal synthesis in the subscription-delivery dispatcher.
/// 3-series counter; no per-subscription / per-user
/// labels — that detail belongs in the `debug!` span.
pub fn emit_dispatcher_principal_resolved(source: DispatcherPrincipalSource) {
    metrics::counter!(
        "hort_dispatcher_principal_resolved_total",
        labels::SOURCE => source.as_str(),
    )
    .increment(1);
}

/// `result` label value of `hort_apply_config_linter_total`.
/// One emission per `PermissionGrant` per lint rule
/// evaluated during gitops apply. Closed taxonomy of 3.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinterResult {
    /// The grant satisfied the rule (or the rule did not apply to this
    /// grant shape).
    Pass,
    /// The rule flagged the grant but the configured action is
    /// non-blocking — apply continues; CI surfaces the warning.
    Warn,
    /// The rule rejected the grant; the gitops apply fails
    /// (secure-by-default — the escape hatch is an explicit
    /// operator allowlist, never a global downgrade).
    Reject,
}

impl LinterResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Reject => "reject",
        }
    }
}

/// Emit `hort_apply_config_linter_total{rule, result}` once per grant
/// per lint rule.
///
/// `rule` MUST be one of the fixed v1 lint-rule keys
/// (`single-claim-grant`, `direct-user-grant-without-justification`,
/// `wildcard-repo-non-admin`, `claim-name-collision`).
/// It is `&'static str` precisely so a free-form / operator-authored
/// string cannot reach the label: the rule keys are compile-time
/// constants at the emission site. Cardinality is fixed at
/// the v1 rule count (4) × 3 results = 12 series max.
pub fn emit_apply_config_linter(rule: &'static str, result: LinterResult) {
    metrics::counter!(
        "hort_apply_config_linter_total",
        labels::RULE => rule,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// `result` label value of `hort_effective_permissions_lookups_total`.
/// One emission per call to the admin
/// effective-permissions endpoint. Closed taxonomy of 3.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectivePermissionsResult {
    /// Admin caller; inspected user resolved; effective-permissions
    /// view returned.
    Ok,
    /// `require_admin()` rejected the caller — emitted before the early
    /// return; the inspected user was never resolved.
    Denied,
    /// Caller was admin but the inspected `user_id` did not resolve to
    /// a user row.
    NotFound,
}

impl EffectivePermissionsResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
        }
    }
}

/// Emit `hort_effective_permissions_lookups_total{result}` once per
/// admin effective-permissions endpoint call. 3-series
/// counter; no `user_id` / `inspected_user_id` labels — actor
/// attribution lives in the `info!` audit span.
pub fn emit_effective_permissions_lookup(result: EffectivePermissionsResult) {
    metrics::counter!(
        "hort_effective_permissions_lookups_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Retention-evaluation observability.
// ---------------------------------------------------------------------------

/// Outcome of evaluating one retention policy against one artifact,
/// used as the `result` label of `hort_retention_evaluations_total`.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. The catalog rule "no new metric name or
/// label value may be introduced without updating that file in the
/// same change" forbids adding a variant without a catalog edit in the
/// same PR. `skipped_stale_scan` surfaces the stale-scan invariant —
/// operators alarming on its rate know the rescan loop is lagging
/// (the operator-facing alarm path depends on this label being
/// emitted, not just absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionEvaluationResult {
    /// The policy predicate matched — an `ArtifactExpired` was (or
    /// would be) appended.
    Matched,
    /// The predicate was evaluated and did not match.
    NoMatch,
    /// A security-driven predicate could not evaluate because the
    /// artifact's most recent scan is stale
    /// (`> 2 × resolved_rescan_interval`). NOT an error; the sweep
    /// proceeds, the artifact becomes eligible again after the next
    /// scan.
    SkippedStaleScan,
    /// The artifact is `quarantined`; GC-protected, not evaluated.
    SkippedQuarantined,
    /// The artifact is `rejected` (evidence); content stays until
    /// manual admin override, not evaluated.
    SkippedRejected,
    /// A read against a port failed for this (policy, artifact) pair;
    /// the sweep records the error and continues with the next
    /// artifact (one bad row never aborts the pass).
    Error,
}

impl RetentionEvaluationResult {
    /// Label value string — must match the catalog exactly.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::NoMatch => "no_match",
            Self::SkippedStaleScan => "skipped_stale_scan",
            Self::SkippedQuarantined => "skipped_quarantined",
            Self::SkippedRejected => "skipped_rejected",
            Self::Error => "error",
        }
    }
}

/// Emit `hort_retention_evaluations_total{policy_id, result}` once per
/// (policy, artifact) evaluation decision.
///
/// `policy_id` is the policy UUID string — a bounded label for
/// retention metrics only (see [`labels::POLICY_ID`] for the
/// cardinality rationale). Per-artifact attribution
/// (`artifact_id` / `content_hash` / `purl` / `vulnerability_id`)
/// stays in `tracing`, never on the metric (architect anti-pattern
/// hard-block).
pub fn emit_retention_evaluation(policy_id: &str, result: RetentionEvaluationResult) {
    metrics::counter!(
        "hort_retention_evaluations_total",
        labels::POLICY_ID => policy_id.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Emit `hort_retention_expired_total{policy_id, reason}` once per
/// `ArtifactExpired` decision. `reason` is the canonical
/// [`hort_domain::retention::ExpirationReason::metric_label`] string —
/// the domain owns the label vocabulary so the emitter and the
/// catalog cannot drift.
pub fn emit_retention_expired(policy_id: &str, reason: &'static str) {
    metrics::counter!(
        "hort_retention_expired_total",
        labels::POLICY_ID => policy_id.to_owned(),
        labels::REASON => reason,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Storage-GC purge observability.
// ---------------------------------------------------------------------------

/// Outcome of one `PurgeUseCase` per-content-hash purge decision, used
/// as the `result` label of `hort_retention_purged_total`.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. The catalog rule "no new metric name or
/// label value may be introduced without updating that file in the
/// same change" forbids adding a variant without a catalog edit in the
/// same PR. There is **no** `policy_id` / `artifact_id` /
/// `content_hash` label (the architect anti-pattern hard-block — those
/// stay in `tracing` fields); the only label is the bounded three-value
/// `result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPurgedResult {
    /// Cross-`kind` refcount reached `0` and the CAS blob was deleted
    /// (or confirmed already-absent — idempotent by design).
    Success,
    /// A still-live reference (promoted ref / `oci_subject` row) keeps
    /// the blob alive; only this artifact's reference was removed
    /// (`refs_remaining > 0`). The blob was deliberately NOT deleted.
    BlobKept,
    /// `StoragePort::delete` failed transiently for a refcount-0 blob.
    /// The `ArtifactExpired` decision is NOT lost (no `ArtifactPurged`
    /// emitted); the next sweep retries (two-stage idempotency).
    StorageError,
}

impl RetentionPurgedResult {
    /// Label value string — must match the catalog exactly.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::BlobKept => "blob_kept",
            Self::StorageError => "storage_error",
        }
    }
}

/// Emit `hort_retention_purged_total{result}` once per content-hash
/// purge decision.
/// Cardinality: a fixed three-value `result` only — per-artifact
/// attribution (`artifact_id` / `content_hash`) stays in `tracing`,
/// never on this series (architect anti-pattern hard-block).
pub fn emit_retention_purged(result: RetentionPurgedResult) {
    metrics::counter!(
        "hort_retention_purged_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Audit-retention stream-seal observability.
// ---------------------------------------------------------------------------

/// Outcome of one `EventStoreRetentionUseCase` per-candidate-stream
/// seal decision, used as the `result` label of
/// `hort_event_store_streams_archived_total`.
///
/// **Layer note (catalogued — see `docs/metrics-catalog.md`).** The
/// metric *name* is `hort_event_store_*`, whose ownership table normally
/// places `hort_event_store_*` in `hort-adapters-postgres`. It is emitted
/// from **`hort-app`** here on purpose: the `Skipped` outcomes
/// (meta-stream guard, non-terminal, floor-not-elapsed, already-sealed,
/// unregistered-category) never reach the adapter — the use case is the
/// only layer that observes *all three* result values. Splitting the
/// emission across layers would either double-count or silently drop
/// `skipped`. The catalog records the prefix-vs-owner
/// tension and pins the emitter to `hort-app::metrics`.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`. The catalog rule "no new metric name or
/// label value may be introduced without updating that file in the
/// same change" forbids adding a variant without a catalog edit in the
/// same PR. There is **no** `stream_id` / `category` label (the
/// architect high-cardinality hard-block — those stay in `tracing`
/// fields); the only label is the bounded three-value `result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamsArchivedResult {
    /// The stream was sealed via `EventStore::archive_stream`
    /// (`StreamRetentionMode::Archive`) — the seal chokepoint emitted the
    /// `StreamSealed` tombstone and moved the stream to cold storage.
    Archived,
    /// The stream was sealed via `EventStore::delete_stream`
    /// (`StreamRetentionMode::Delete`) — the seal chokepoint emitted the
    /// `StreamSealed` tombstone and removed the live rows.
    Deleted,
    /// A precondition was not met, so the stream was NOT sealed this
    /// pass: the meta-stream guard, a non-terminal tail (TerminalGated),
    /// the retention floor not yet elapsed, an already-sealed (empty-read)
    /// idempotent re-run, or an unregistered category. One emission per
    /// skipped candidate regardless of which precondition stopped it
    /// (the precise reason is in the `tracing` line, not the metric —
    /// cardinality hard-block).
    Skipped,
}

impl StreamsArchivedResult {
    /// Label value string — must match the catalog exactly.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Archived => "archived",
            Self::Deleted => "deleted",
            Self::Skipped => "skipped",
        }
    }
}

/// Emit `hort_event_store_streams_archived_total{result}` once per
/// candidate-stream seal decision.
/// Cardinality: a fixed three-value `result` only —
/// per-stream attribution (`stream_id` / `category`) stays in
/// `tracing`, never on this series (architect anti-pattern
/// hard-block).
pub fn emit_streams_archived(result: StreamsArchivedResult) {
    metrics::counter!(
        "hort_event_store_streams_archived_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Prefetch-dependencies amplification
// metric. Closed taxonomy of THREE values; declared in this module per
// the architect-doc rule "result enums live with the emitting layer"
// (the emission site is
// `hort-app::task_handlers::prefetch_dependencies::PrefetchDependenciesHandler::run`,
// which is application-layer code; `hort-domain` has zero metric concerns).
// ---------------------------------------------------------------------------

/// Outcome of one `prefetch-dependencies` walk, used as the `result`
/// label of `hort_prefetch_amplification_total`.
///
/// Emitted once at the end of each walk, after `plan_and_enqueue`
/// returns the `WalkSummary`. The three values are mutually exclusive
/// per-walk:
///
/// - [`Self::Normal`] — walk completed under the `max_descendants`
///   cap AND every cold-cohort upstream resolution succeeded
///   (`summary.cap_hit == false && summary.no_upstream_mapping == 0`).
///   The happy path; the steady-state value on a healthy deployment.
/// - [`Self::CapHit`] — walk truncated by the
///   `PrefetchPolicy::max_descendants` cumulative-cap safety net
///   (`summary.cap_hit == true`). The accompanying `tracing::warn!`
///   at the truncation site carries `cap` / `current_descendants` /
///   `attempted_to_enqueue` for per-instance diagnosis; the metric is
///   the dashboard signal that operators alert on.
/// - [`Self::ResolverFailed`] — cold-cohort upstream resolution
///   failed (`summary.no_upstream_mapping > 0`). Today this fires
///   when the repo has no catch-all upstream mapping
///   (`path_prefix=""`) — the cold cohort is silently skipped at
///   the resolver site (see `plan_and_enqueue` Pass 2). The metric
///   surfaces what was previously only a `summary.no_upstream_mapping`
///   internal counter on the task's `result_summary` JSON.
///
/// Precedence (in case both flags happen to fire on the same walk):
/// `CapHit` wins over `ResolverFailed`. `CapHit` is the load-bearing
/// safety net and the operator's primary signal that the cascade has
/// runaway behaviour; `ResolverFailed` is a secondary diagnostic
/// that fires on a configuration miss. Mirroring both on the same
/// walk would force a 4-value taxonomy ("both") that no operator
/// alerts on; the simpler 3-value enum + documented precedence is
/// the architect-doc-aligned answer.
///
/// String values are normative — they appear verbatim in
/// `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchAmplificationResult {
    /// Walk completed under the cap with every cold-cohort fetch
    /// resolved.
    Normal,
    /// Walk truncated by the `PrefetchPolicy::max_descendants` cap.
    CapHit,
    /// Cold-cohort upstream resolution failed
    /// (`summary.no_upstream_mapping > 0`).
    ResolverFailed,
}

impl PrefetchAmplificationResult {
    /// Wire string. Catalog rule: must match `docs/metrics-catalog.md`
    /// exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::CapHit => "cap_hit",
            Self::ResolverFailed => "resolver_failed",
        }
    }
}

/// Emit `hort_prefetch_amplification_total{format, repository, result}`
/// once at the end of each `prefetch-dependencies` walk.
///
/// The label set is conservative: `format` + `repository` + `result`
/// only. NO per-package / per-artifact / per-user dimensions —
/// per-instance detail lives in the accompanying `tracing::warn!`
/// (cap-hit) / `tracing::warn!` (no-catch-all-mapping) spans the walk
/// already emits.
///
/// `repository` honours the `hort_prefetch_*` family carve-out from
/// `METRICS_INCLUDE_REPOSITORY_LABEL=false` — see the catalog row +
/// the parallel carve-out documented on `hort_prefetch_enqueued_total`
/// (per-repo diagnostic value is load-bearing; the cardinality
/// envelope is bounded by `prefetch_policy.enabled = true` repo
/// count + `TransitiveDeps` trigger opt-in, an even smaller subset).
/// Callers pass the raw repo key.
pub fn emit_prefetch_amplification(
    format: &str,
    repository: &str,
    result: PrefetchAmplificationResult,
) {
    metrics::counter!(
        "hort_prefetch_amplification_total",
        labels::FORMAT => format.to_owned(),
        labels::REPOSITORY => repository.to_owned(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::{
        capture_metrics, emit_api_token_used_audit_dropped, emit_ref_moved, labels, values,
        ApiTokenUsedAuditDropResult, CasScrubResult, DownloadResult, IngestResult, RefMetricResult,
        UpstreamChecksumResult, UpstreamErrorKind, UpstreamFetchError, UpstreamTlsHandshakeResult,
    };
    use std::collections::HashSet;

    // -------------------------------------------------------------------
    // Label-name constants match the catalog exactly.
    // -------------------------------------------------------------------

    #[test]
    fn label_format_is_format() {
        assert_eq!(labels::FORMAT, "format");
    }

    #[test]
    fn label_repository_is_repository() {
        assert_eq!(labels::REPOSITORY, "repository");
    }

    #[test]
    fn label_result_is_result() {
        assert_eq!(labels::RESULT, "result");
    }

    #[test]
    fn label_method_is_method() {
        assert_eq!(labels::METHOD, "method");
    }

    #[test]
    fn label_path_is_path() {
        assert_eq!(labels::PATH, "path");
    }

    #[test]
    fn label_status_is_status() {
        assert_eq!(labels::STATUS, "status");
    }

    #[test]
    fn label_upstream_is_upstream() {
        assert_eq!(labels::UPSTREAM, "upstream");
    }

    #[test]
    fn label_category_is_category() {
        assert_eq!(labels::CATEGORY, "category");
    }

    #[test]
    fn label_reason_is_reason() {
        assert_eq!(labels::REASON, "reason");
    }

    #[test]
    fn label_backend_is_backend() {
        assert_eq!(labels::BACKEND, "backend");
    }

    #[test]
    fn label_operation_is_operation() {
        assert_eq!(labels::OPERATION, "operation");
    }

    // -- Label-name constants for native API tokens ----------------------

    #[test]
    fn label_actor_kind_is_actor_kind() {
        assert_eq!(labels::ACTOR_KIND, "actor_kind");
    }

    #[test]
    fn label_cache_is_cache() {
        assert_eq!(labels::CACHE, "cache");
    }

    #[test]
    fn label_action_is_action() {
        assert_eq!(labels::ACTION, "action");
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
    fn value_reason_timer_is_timer() {
        assert_eq!(values::REASON_TIMER, "timer");
    }

    #[test]
    fn value_reason_admin_is_admin() {
        assert_eq!(values::REASON_ADMIN, "admin");
    }

    #[test]
    fn value_reason_policy_re_evaluation_is_policy_re_evaluation() {
        assert_eq!(values::REASON_POLICY_RE_EVALUATION, "policy_re_evaluation");
    }

    #[test]
    fn value_repository_all_is_underscore_all() {
        assert_eq!(values::REPOSITORY_ALL, "_all");
    }

    #[test]
    fn value_repository_unknown_is_unknown() {
        assert_eq!(values::REPOSITORY_UNKNOWN, "unknown");
    }

    #[test]
    fn value_path_unmatched_is_angle_unmatched() {
        assert_eq!(values::PATH_UNMATCHED, "<unmatched>");
    }

    #[test]
    fn value_format_unknown_is_unknown() {
        assert_eq!(values::FORMAT_UNKNOWN, "unknown");
    }

    #[test]
    fn value_strategy_inline_is_inline() {
        assert_eq!(values::STRATEGY_INLINE, "inline");
    }

    #[test]
    fn value_strategy_hash_reference_is_hash_reference() {
        assert_eq!(values::STRATEGY_HASH_REFERENCE, "hash_reference");
    }

    // -------------------------------------------------------------------
    // IngestResult — every variant's `as_str()` matches the catalog.
    // -------------------------------------------------------------------

    #[test]
    fn ingest_result_success_as_str() {
        assert_eq!(IngestResult::Success.as_str(), "success");
    }

    #[test]
    fn ingest_result_duplicate_as_str() {
        assert_eq!(IngestResult::Duplicate.as_str(), "duplicate");
    }

    #[test]
    fn ingest_result_conflict_as_str() {
        assert_eq!(IngestResult::Conflict.as_str(), "conflict");
    }

    #[test]
    fn ingest_result_validation_error_as_str() {
        assert_eq!(IngestResult::ValidationError.as_str(), "validation_error");
    }

    #[test]
    fn ingest_result_storage_error_as_str() {
        assert_eq!(IngestResult::StorageError.as_str(), "storage_error");
    }

    #[test]
    fn ingest_result_repository_not_found_as_str() {
        assert_eq!(
            IngestResult::RepositoryNotFound.as_str(),
            "repository_not_found"
        );
    }

    #[test]
    fn ingest_result_metadata_too_large_as_str() {
        assert_eq!(
            IngestResult::MetadataTooLarge.as_str(),
            "metadata_too_large"
        );
    }

    #[test]
    fn ingest_result_registered_by_hash_as_str() {
        assert_eq!(
            IngestResult::RegisteredByHash.as_str(),
            "registered_by_hash"
        );
    }

    #[test]
    fn ingest_result_declared_hash_mismatch_as_str() {
        assert_eq!(
            IngestResult::DeclaredHashMismatch.as_str(),
            "declared_hash_mismatch"
        );
    }

    #[test]
    fn ingest_result_wheel_metadata_extract_failed_as_str() {
        assert_eq!(
            IngestResult::WheelMetadataExtractFailed.as_str(),
            "wheel_metadata_extract_failed"
        );
    }

    #[test]
    fn ingest_result_values_are_unique() {
        let variants = [
            IngestResult::Success,
            IngestResult::Duplicate,
            IngestResult::Conflict,
            IngestResult::ValidationError,
            IngestResult::StorageError,
            IngestResult::RepositoryNotFound,
            IngestResult::MetadataTooLarge,
            IngestResult::RegisteredByHash,
            IngestResult::DeclaredHashMismatch,
            IngestResult::WheelMetadataExtractFailed,
        ];
        let set: HashSet<&'static str> = variants.iter().map(IngestResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // DownloadResult — every variant's `as_str()` matches the catalog.
    // -------------------------------------------------------------------

    #[test]
    fn download_result_success_as_str() {
        assert_eq!(DownloadResult::Success.as_str(), "success");
    }

    #[test]
    fn download_result_quarantined_as_str() {
        assert_eq!(DownloadResult::Quarantined.as_str(), "quarantined");
    }

    #[test]
    fn download_result_rejected_as_str() {
        assert_eq!(DownloadResult::Rejected.as_str(), "rejected");
    }

    #[test]
    fn download_result_not_found_as_str() {
        assert_eq!(DownloadResult::NotFound.as_str(), "not_found");
    }

    #[test]
    fn download_result_storage_error_as_str() {
        assert_eq!(DownloadResult::StorageError.as_str(), "storage_error");
    }

    #[test]
    fn download_result_values_are_unique() {
        let variants = [
            DownloadResult::Success,
            DownloadResult::Quarantined,
            DownloadResult::Rejected,
            DownloadResult::NotFound,
            DownloadResult::StorageError,
        ];
        let set: HashSet<&'static str> = variants.iter().map(DownloadResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // UpstreamErrorKind — all 10 variants.
    // -------------------------------------------------------------------

    #[test]
    fn upstream_error_kind_success_as_str() {
        assert_eq!(UpstreamErrorKind::Success.as_str(), "success");
    }

    #[test]
    fn upstream_error_kind_not_found_as_str() {
        assert_eq!(UpstreamErrorKind::NotFound.as_str(), "not_found");
    }

    #[test]
    fn upstream_error_kind_unauthorized_as_str() {
        assert_eq!(UpstreamErrorKind::Unauthorized.as_str(), "unauthorized");
    }

    #[test]
    fn upstream_error_kind_rate_limited_as_str() {
        assert_eq!(UpstreamErrorKind::RateLimited.as_str(), "rate_limited");
    }

    #[test]
    fn upstream_error_kind_upstream_4xx_as_str() {
        assert_eq!(UpstreamErrorKind::Upstream4xx.as_str(), "upstream_4xx");
    }

    #[test]
    fn upstream_error_kind_upstream_5xx_as_str() {
        assert_eq!(UpstreamErrorKind::Upstream5xx.as_str(), "upstream_5xx");
    }

    #[test]
    fn upstream_error_kind_network_error_as_str() {
        assert_eq!(UpstreamErrorKind::NetworkError.as_str(), "network_error");
    }

    #[test]
    fn upstream_error_kind_timeout_as_str() {
        assert_eq!(UpstreamErrorKind::Timeout.as_str(), "timeout");
    }

    #[test]
    fn upstream_error_kind_checksum_mismatch_as_str() {
        assert_eq!(
            UpstreamErrorKind::ChecksumMismatch.as_str(),
            "checksum_mismatch"
        );
    }

    #[test]
    fn upstream_error_kind_parse_error_as_str() {
        assert_eq!(UpstreamErrorKind::ParseError.as_str(), "parse_error");
    }

    #[test]
    fn upstream_error_kind_body_too_large_as_str() {
        assert_eq!(UpstreamErrorKind::BodyTooLarge.as_str(), "body_too_large");
    }

    #[test]
    fn upstream_error_kind_pin_mismatch_as_str() {
        // Pin failures are operationally
        // distinct from generic parse errors (architect rule "no per-format
        // error label invention"). Catalog string is `pin_mismatch`.
        assert_eq!(UpstreamErrorKind::PinMismatch.as_str(), "pin_mismatch");
    }

    #[test]
    fn upstream_error_kind_ca_unknown_as_str() {
        // CA-trust failures get their own
        // taxonomy slot, distinct from pin failures.
        assert_eq!(UpstreamErrorKind::CaUnknown.as_str(), "ca_unknown");
    }

    // -------------------------------------------------------------------
    // UpstreamChecksumResult.
    // Three variants: Verified / Mismatch (emitted by
    // `IngestUseCase::ingest_verified`) and ChecksumMissing (emitted by
    // inbound HTTP handlers when the upstream supplied no digest).
    // -------------------------------------------------------------------

    #[test]
    fn upstream_checksum_result_verified_as_str() {
        assert_eq!(UpstreamChecksumResult::Verified.as_str(), "verified");
    }

    #[test]
    fn upstream_checksum_result_mismatch_as_str() {
        assert_eq!(UpstreamChecksumResult::Mismatch.as_str(), "mismatch");
    }

    #[test]
    fn upstream_checksum_result_checksum_missing_as_str() {
        assert_eq!(
            UpstreamChecksumResult::ChecksumMissing.as_str(),
            "checksum_missing"
        );
    }

    #[test]
    fn upstream_checksum_result_values_are_unique() {
        let variants = [
            UpstreamChecksumResult::Verified,
            UpstreamChecksumResult::Mismatch,
            UpstreamChecksumResult::ChecksumMissing,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(UpstreamChecksumResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // IP bucketing + AuthEventResult.
    // -------------------------------------------------------------------

    #[test]
    fn ipv4_bucket_prefix_bits_is_24() {
        assert_eq!(super::IPV4_BUCKET_PREFIX_BITS, 24);
    }

    #[test]
    fn ipv6_bucket_prefix_bits_is_48() {
        assert_eq!(super::IPV6_BUCKET_PREFIX_BITS, 48);
    }

    #[test]
    fn client_ip_bucket_ipv4_collapses_last_octet() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        assert_eq!(super::client_ip_bucket(ip), "203.0.113.0/24");
    }

    #[test]
    fn client_ip_bucket_ipv4_buckets_distinct_subnets_distinctly() {
        use std::net::{IpAddr, Ipv4Addr};
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 114, 42));
        assert_ne!(super::client_ip_bucket(a), super::client_ip_bucket(b));
    }

    #[test]
    fn client_ip_bucket_ipv4_same_subnet_share_bucket() {
        use std::net::{IpAddr, Ipv4Addr};
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 254));
        assert_eq!(super::client_ip_bucket(a), super::client_ip_bucket(b));
    }

    #[test]
    fn client_ip_bucket_ipv6_collapses_to_48() {
        use std::net::{IpAddr, Ipv6Addr};
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1234, 0xabcd, 0, 0, 0, 1));
        assert_eq!(super::client_ip_bucket(ip), "2001:db8:1234::/48");
    }

    #[test]
    fn client_ip_bucket_ipv6_distinct_sites_distinct_buckets() {
        use std::net::{IpAddr, Ipv6Addr};
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1234, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1235, 0, 0, 0, 0, 1));
        assert_ne!(super::client_ip_bucket(a), super::client_ip_bucket(b));
    }

    /// Dual-stack peers reported by the
    /// kernel as `::ffff:10.0.0.5` (IPv4-mapped IPv6, RFC 4291 §2.5.5)
    /// must coalesce into the same bucket as the bare IPv4 form
    /// `10.0.0.5`. Without canonicalization the throttle key
    /// `(bucket, result)` fragments across two buckets and the per-IP
    /// rate limit halves its effective threshold for dual-stack
    /// callers.
    #[test]
    fn client_ip_bucket_canonicalizes_ipv4_mapped_ipv6() {
        use std::net::IpAddr;
        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        let bare: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            super::client_ip_bucket(mapped),
            super::client_ip_bucket(bare)
        );
        assert_eq!(super::client_ip_bucket(mapped), "10.0.0.0/24");
    }

    #[test]
    fn auth_event_result_as_str_values() {
        use super::AuthEventResult;
        assert_eq!(AuthEventResult::Success.as_str(), "success");
        assert_eq!(AuthEventResult::Appended.as_str(), "appended");
        assert_eq!(AuthEventResult::Throttled.as_str(), "throttled");
        assert_eq!(AuthEventResult::Error.as_str(), "error");
    }

    #[test]
    fn auth_event_result_values_are_unique() {
        use super::AuthEventResult;
        let variants = [
            AuthEventResult::Success,
            AuthEventResult::Appended,
            AuthEventResult::Throttled,
            AuthEventResult::Error,
        ];
        let set: HashSet<&'static str> = variants.iter().map(AuthEventResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_auth_event_increments_counter_with_only_result_label() {
        use super::{emit_auth_event, AuthEventResult};
        let snap = capture_metrics(|| {
            emit_auth_event(AuthEventResult::Appended);
            emit_auth_event(AuthEventResult::Throttled);
            emit_auth_event(AuthEventResult::Error);
        });
        let mut seen_results: HashSet<String> = HashSet::new();
        let mut seen_label_keys: HashSet<String> = HashSet::new();
        for (key, _, _, _) in snap.into_vec() {
            let inner = key.key();
            if inner.name() != "hort_auth_events_appended_total" {
                continue;
            }
            for label in inner.labels() {
                seen_label_keys.insert(label.key().to_string());
                if label.key() == "result" {
                    seen_results.insert(label.value().to_string());
                }
            }
        }
        assert!(seen_results.contains("appended"));
        assert!(seen_results.contains("throttled"));
        assert!(seen_results.contains("error"));
        // Cardinality guard: only `result`. `client_ip` lives in the
        // event payload, not here.
        assert_eq!(
            seen_label_keys,
            HashSet::from(["result".to_string()]),
            "hort_auth_events_appended_total must carry only the `result` label"
        );
    }

    // -- version_object_too_large emission --

    #[test]
    fn emit_upstream_version_object_too_large_fires_with_format_repo_result() {
        use super::emit_upstream_version_object_too_large;
        let snap = capture_metrics(|| {
            emit_upstream_version_object_too_large("npm", "my-repo");
        });
        let mut found = false;
        for (key, _, _, _) in snap.into_vec() {
            let inner = key.key();
            if inner.name() != "hort_upstream_fetch_total" {
                continue;
            }
            let mut format = None;
            let mut repository = None;
            let mut result = None;
            for label in inner.labels() {
                match label.key() {
                    "format" => format = Some(label.value().to_string()),
                    "repository" => repository = Some(label.value().to_string()),
                    "result" => result = Some(label.value().to_string()),
                    _ => {}
                }
            }
            if result.as_deref() == Some("version_object_too_large") {
                assert_eq!(format.as_deref(), Some("npm"));
                assert_eq!(repository.as_deref(), Some("my-repo"));
                found = true;
            }
        }
        assert!(
            found,
            "version_object_too_large must fire on hort_upstream_fetch_total with format+repository"
        );
    }

    // -- is_admin-transition metric --

    #[test]
    fn is_admin_transition_result_as_str_values() {
        use super::IsAdminTransitionResult;
        assert_eq!(IsAdminTransitionResult::Granted.as_str(), "granted");
        assert_eq!(IsAdminTransitionResult::Revoked.as_str(), "revoked");
    }

    #[test]
    fn is_admin_transition_result_values_are_unique() {
        use super::IsAdminTransitionResult;
        let variants = [
            IsAdminTransitionResult::Granted,
            IsAdminTransitionResult::Revoked,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(IsAdminTransitionResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_is_admin_transition_increments_counter_with_only_result_label() {
        use super::{emit_is_admin_transition, IsAdminTransitionResult};
        let snap = capture_metrics(|| {
            emit_is_admin_transition(IsAdminTransitionResult::Granted);
            emit_is_admin_transition(IsAdminTransitionResult::Revoked);
        });
        let mut seen_results: HashSet<String> = HashSet::new();
        let mut seen_label_keys: HashSet<String> = HashSet::new();
        for (key, _, _, _) in snap.into_vec() {
            let inner = key.key();
            if inner.name() != "hort_is_admin_transition_total" {
                continue;
            }
            for label in inner.labels() {
                seen_label_keys.insert(label.key().to_string());
                if label.key() == "result" {
                    seen_results.insert(label.value().to_string());
                }
            }
        }
        assert!(seen_results.contains("granted"));
        assert!(seen_results.contains("revoked"));
        // Cardinality guard: only `result`. `user_id` / `external_id`
        // live in the `AdminStatusChanged` event payload, not here.
        assert_eq!(
            seen_label_keys,
            HashSet::from(["result".to_string()]),
            "hort_is_admin_transition_total must carry only the `result` label"
        );
    }

    // -------------------------------------------------------------------
    // CasScrubResult — every variant's `as_str()` matches the catalog.
    // -------------------------------------------------------------------

    #[test]
    fn cas_scrub_result_ok_as_str() {
        assert_eq!(CasScrubResult::Ok.as_str(), "ok");
    }

    #[test]
    fn cas_scrub_result_hash_mismatch_as_str() {
        assert_eq!(CasScrubResult::HashMismatch.as_str(), "hash_mismatch");
    }

    #[test]
    fn cas_scrub_result_missing_as_str() {
        assert_eq!(CasScrubResult::Missing.as_str(), "missing");
    }

    #[test]
    fn cas_scrub_result_read_error_as_str() {
        assert_eq!(CasScrubResult::ReadError.as_str(), "read_error");
    }

    #[test]
    fn cas_scrub_result_values_are_unique() {
        let variants = [
            CasScrubResult::Ok,
            CasScrubResult::HashMismatch,
            CasScrubResult::Missing,
            CasScrubResult::ReadError,
        ];
        let set: HashSet<&'static str> = variants.iter().map(CasScrubResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn upstream_error_kind_values_are_unique() {
        let variants = [
            UpstreamErrorKind::Success,
            UpstreamErrorKind::NotFound,
            UpstreamErrorKind::Unauthorized,
            UpstreamErrorKind::RateLimited,
            UpstreamErrorKind::Upstream4xx,
            UpstreamErrorKind::Upstream5xx,
            UpstreamErrorKind::NetworkError,
            UpstreamErrorKind::Timeout,
            UpstreamErrorKind::ChecksumMismatch,
            UpstreamErrorKind::ParseError,
            UpstreamErrorKind::BodyTooLarge,
            UpstreamErrorKind::PinMismatch,
            UpstreamErrorKind::CaUnknown,
        ];
        let set: HashSet<&'static str> = variants.iter().map(UpstreamErrorKind::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // UpstreamTlsHandshakeResult.
    // Five variants: success, mtls_required, ca_unknown, pin_mismatch,
    // network_error.
    // -------------------------------------------------------------------

    #[test]
    fn upstream_tls_handshake_result_success_as_str() {
        assert_eq!(UpstreamTlsHandshakeResult::Success.as_str(), "success");
    }

    #[test]
    fn upstream_tls_handshake_result_mtls_required_as_str() {
        assert_eq!(
            UpstreamTlsHandshakeResult::MtlsRequired.as_str(),
            "mtls_required"
        );
    }

    #[test]
    fn upstream_tls_handshake_result_ca_unknown_as_str() {
        assert_eq!(UpstreamTlsHandshakeResult::CaUnknown.as_str(), "ca_unknown");
    }

    #[test]
    fn upstream_tls_handshake_result_pin_mismatch_as_str() {
        assert_eq!(
            UpstreamTlsHandshakeResult::PinMismatch.as_str(),
            "pin_mismatch"
        );
    }

    #[test]
    fn upstream_tls_handshake_result_network_error_as_str() {
        assert_eq!(
            UpstreamTlsHandshakeResult::NetworkError.as_str(),
            "network_error"
        );
    }

    #[test]
    fn upstream_tls_handshake_result_values_are_unique() {
        let variants = [
            UpstreamTlsHandshakeResult::Success,
            UpstreamTlsHandshakeResult::MtlsRequired,
            UpstreamTlsHandshakeResult::CaUnknown,
            UpstreamTlsHandshakeResult::PinMismatch,
            UpstreamTlsHandshakeResult::NetworkError,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(UpstreamTlsHandshakeResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_upstream_tls_handshake_with_collapsed_repository_label() {
        // The TLS handshake metric must
        // honour the `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse —
        // when the proxy's caller passes the `_all` sentinel, that's the
        // value emitted on the wire. Pinning the contract here keeps the
        // toggle's one-line semantics from drifting.
        use metrics_util::debugging::DebuggingRecorder;
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            super::emit_upstream_tls_handshake(
                values::REPOSITORY_ALL,
                UpstreamTlsHandshakeResult::Success,
            );
        });
        let snap = snapshotter.snapshot().into_vec();
        let mut found = false;
        for (key, _, _, _) in &snap {
            let inner = key.key();
            if inner.name() != "hort_upstream_tls_handshake_total" {
                continue;
            }
            let mut repo_ok = false;
            let mut result_ok = false;
            for label in inner.labels() {
                match label.key() {
                    "repository" if label.value() == "_all" => repo_ok = true,
                    "result" if label.value() == "success" => result_ok = true,
                    _ => {}
                }
            }
            if repo_ok && result_ok {
                found = true;
            }
        }
        assert!(
            found,
            "expected hort_upstream_tls_handshake_total{{repository=_all,result=success}} \
             after passing REPOSITORY_ALL sentinel"
        );
    }

    // -------------------------------------------------------------------
    // RefMetricResult — every variant's `as_str()` matches the catalog.
    // -------------------------------------------------------------------

    #[test]
    fn ref_metric_result_created_as_str() {
        assert_eq!(RefMetricResult::Created.as_str(), "created");
    }

    #[test]
    fn ref_metric_result_moved_as_str() {
        assert_eq!(RefMetricResult::Moved.as_str(), "moved");
    }

    #[test]
    fn ref_metric_result_retired_as_str() {
        assert_eq!(RefMetricResult::Retired.as_str(), "retired");
    }

    #[test]
    fn ref_metric_result_no_op_as_str() {
        assert_eq!(RefMetricResult::NoOp.as_str(), "no_op");
    }

    #[test]
    fn ref_metric_result_values_are_unique() {
        let variants = [
            RefMetricResult::Created,
            RefMetricResult::Moved,
            RefMetricResult::Retired,
            RefMetricResult::NoOp,
        ];
        let set: HashSet<&'static str> = variants.iter().map(RefMetricResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -- emit_ref_moved fires the counter with the advertised labels -----

    #[test]
    fn emit_ref_moved_increments_counter_with_labels() {
        let snap = capture_metrics(|| {
            emit_ref_moved("my-repo", RefMetricResult::Created);
        });
        let entries = snap.into_vec();
        let (key, _unit, _desc, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("hort_ref_moved_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"my-repo"));
        assert_eq!(labels.get("result"), Some(&"created"));
        // Value was incremented once.
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -- B13: hort_api_token_used_audit_dropped ---------------------------

    #[test]
    fn api_token_used_audit_drop_result_as_str_is_catalogued() {
        // The string values are normative — they appear verbatim in
        // docs/metrics-catalog.md. A drift here is a catalog drift.
        assert_eq!(ApiTokenUsedAuditDropResult::Throttled.as_str(), "throttled");
        assert_eq!(
            ApiTokenUsedAuditDropResult::AppendError.as_str(),
            "append_error"
        );
    }

    #[test]
    fn emit_api_token_used_audit_dropped_throttled_increments_with_only_result_label() {
        let snap = capture_metrics(|| {
            emit_api_token_used_audit_dropped(ApiTokenUsedAuditDropResult::Throttled);
        });
        let entries = snap.into_vec();
        let (key, _unit, _desc, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_api_token_used_audit_dropped")
            .expect("hort_api_token_used_audit_dropped must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        // `result` is the ONLY label — no format / repository /
        // user_id / token_id (token use has no such dimension).
        assert_eq!(labels.len(), 1, "result must be the only label");
        assert_eq!(labels.get("result"), Some(&"throttled"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_api_token_used_audit_dropped_append_error_label() {
        let snap = capture_metrics(|| {
            emit_api_token_used_audit_dropped(ApiTokenUsedAuditDropResult::AppendError);
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_api_token_used_audit_dropped")
            .expect("hort_api_token_used_audit_dropped must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"append_error"));
    }

    #[test]
    fn emit_ref_moved_sentinel_label_is_underscore_all() {
        let snap = capture_metrics(|| {
            emit_ref_moved(values::REPOSITORY_ALL, RefMetricResult::NoOp);
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("hort_ref_moved_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"_all"));
        assert_eq!(labels.get("result"), Some(&"no_op"));
    }

    // -------------------------------------------------------------------
    // GroupMemberRole — every catalog-declared variant maps to the
    // exact string in docs/metrics-catalog.md. Any drift is a test
    // failure.
    // -------------------------------------------------------------------

    #[test]
    fn group_member_role_as_str_covers_every_variant() {
        use super::GroupMemberRole as R;
        let pairs = [
            (R::Pom, "pom"),
            (R::Jar, "jar"),
            (R::Sources, "sources"),
            (R::Javadoc, "javadoc"),
            (R::Signature, "signature"),
            (R::Sha256, "sha256"),
            (R::Md5, "md5"),
            (R::Mod, "mod"),
            (R::Zip, "zip"),
            (R::Info, "info"),
            (R::Manifest, "manifest"),
            (R::Config, "config"),
            (R::Layer, "layer"),
            (R::Deb, "deb"),
            (R::Dsc, "dsc"),
            (R::Changes, "changes"),
            (R::Orig, "orig"),
            (R::Module, "module"),
            (R::Other, "other"),
        ];
        let set: HashSet<&'static str> = pairs.iter().map(|(_, s)| *s).collect();
        assert_eq!(set.len(), pairs.len(), "every variant has a unique label");
        for (variant, expected) in pairs {
            assert_eq!(variant.as_str(), expected, "{variant:?} label");
        }
    }

    #[test]
    fn group_member_role_classify_recognises_every_catalog_value() {
        use super::GroupMemberRole as R;
        for (input, expected) in [
            ("pom", R::Pom),
            ("jar", R::Jar),
            ("sources", R::Sources),
            ("javadoc", R::Javadoc),
            ("signature", R::Signature),
            ("sha256", R::Sha256),
            ("md5", R::Md5),
            ("mod", R::Mod),
            ("zip", R::Zip),
            ("info", R::Info),
            ("manifest", R::Manifest),
            ("config", R::Config),
            ("layer", R::Layer),
            ("deb", R::Deb),
            ("dsc", R::Dsc),
            ("changes", R::Changes),
            ("orig", R::Orig),
            ("module", R::Module),
        ] {
            assert_eq!(R::classify(input), expected, "classify({input})");
        }
    }

    #[test]
    fn group_member_role_classify_unknown_goes_to_other() {
        use super::GroupMemberRole as R;
        assert_eq!(R::classify("this-is-not-a-role"), R::Other);
        assert_eq!(R::classify(""), R::Other);
        // Case-sensitive — catalog values are lowercase.
        assert_eq!(R::classify("JAR"), R::Other);
    }

    // -- emit_artifact_group_created / emit_artifact_group_member_added --

    #[test]
    fn emit_artifact_group_created_fires_with_labels() {
        use super::emit_artifact_group_created;
        let snap = capture_metrics(|| {
            emit_artifact_group_created("my-repo", "maven");
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_groups_created_total")
            .expect("hort_artifact_groups_created_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"my-repo"));
        assert_eq!(labels.get("format"), Some(&"maven"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_artifact_group_member_added_fires_with_labels() {
        use super::{emit_artifact_group_member_added, GroupMemberRole};
        let snap = capture_metrics(|| {
            emit_artifact_group_member_added("my-repo", "maven", GroupMemberRole::Jar);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_group_members_added_total")
            .expect("hort_artifact_group_members_added_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"my-repo"));
        assert_eq!(labels.get("format"), Some(&"maven"));
        assert_eq!(labels.get("role"), Some(&"jar"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // GroupReconcileResult — every variant's `as_str()` matches the
    // catalog, and `emit_group_reconcile` fires with the advertised
    // labels.
    // -------------------------------------------------------------------

    #[test]
    fn group_reconcile_result_healed_as_str() {
        use super::GroupReconcileResult;
        assert_eq!(GroupReconcileResult::Healed.as_str(), "healed");
    }

    #[test]
    fn group_reconcile_result_already_linked_as_str() {
        use super::GroupReconcileResult;
        assert_eq!(
            GroupReconcileResult::AlreadyLinked.as_str(),
            "already_linked"
        );
    }

    #[test]
    fn group_reconcile_result_handler_declined_as_str() {
        use super::GroupReconcileResult;
        assert_eq!(
            GroupReconcileResult::HandlerDeclined.as_str(),
            "handler_declined"
        );
    }

    #[test]
    fn group_reconcile_result_event_read_error_as_str() {
        use super::GroupReconcileResult;
        assert_eq!(
            GroupReconcileResult::EventReadError.as_str(),
            "event_read_error"
        );
    }

    #[test]
    fn group_reconcile_result_values_are_unique() {
        use super::GroupReconcileResult;
        let variants = [
            GroupReconcileResult::Healed,
            GroupReconcileResult::AlreadyLinked,
            GroupReconcileResult::HandlerDeclined,
            GroupReconcileResult::EventReadError,
        ];
        let set: HashSet<&'static str> =
            variants.iter().map(GroupReconcileResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_group_reconcile_fires_with_labels() {
        use super::{emit_group_reconcile, GroupReconcileResult};
        let snap = capture_metrics(|| {
            emit_group_reconcile("my-repo", GroupReconcileResult::Healed);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_group_reconcile_total")
            .expect("hort_group_reconcile_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"my-repo"));
        assert_eq!(labels.get("result"), Some(&"healed"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_group_reconcile_sentinel_label_is_underscore_all() {
        use super::{emit_group_reconcile, GroupReconcileResult};
        let snap = capture_metrics(|| {
            emit_group_reconcile(values::REPOSITORY_ALL, GroupReconcileResult::AlreadyLinked);
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_group_reconcile_total")
            .expect("hort_group_reconcile_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"_all"));
        assert_eq!(labels.get("result"), Some(&"already_linked"));
    }

    // -------------------------------------------------------------------
    // gitops_kind constants pinned and
    // emit_gitops_event fires with the advertised (kind, event_type)
    // labels and a +1 counter delta.
    // -------------------------------------------------------------------

    #[test]
    fn label_event_type_is_event_type() {
        assert_eq!(labels::EVENT_TYPE, "event_type");
    }

    #[test]
    fn gitops_kind_constants_match_catalog() {
        use super::gitops_kind;
        assert_eq!(gitops_kind::REPOSITORY, "repository");
        // `group_mapping` was renamed to `claim_mapping`; `role` dropped.
        assert_eq!(gitops_kind::CLAIM_MAPPING, "claim_mapping");
        assert_eq!(gitops_kind::PERMISSION_GRANT, "permission_grant");
        assert_eq!(gitops_kind::CURATION_RULE, "curation_rule");
        assert_eq!(gitops_kind::SCAN_POLICY, "scan_policy");
        assert_eq!(gitops_kind::EXCLUSION, "exclusion");
        assert_eq!(gitops_kind::UPSTREAM_MAPPING, "upstream_mapping");
        assert_eq!(gitops_kind::OIDC_ISSUER, "oidc_issuer");
        assert_eq!(gitops_kind::SERVICE_ACCOUNT, "service_account");
    }

    #[test]
    fn gitops_kind_values_are_unique() {
        use super::gitops_kind;
        let values = [
            gitops_kind::REPOSITORY,
            gitops_kind::CLAIM_MAPPING,
            gitops_kind::PERMISSION_GRANT,
            gitops_kind::CURATION_RULE,
            gitops_kind::SCAN_POLICY,
            gitops_kind::EXCLUSION,
            gitops_kind::UPSTREAM_MAPPING,
            gitops_kind::OIDC_ISSUER,
            gitops_kind::SERVICE_ACCOUNT,
        ];
        let set: HashSet<&'static str> = values.iter().copied().collect();
        assert_eq!(
            set.len(),
            values.len(),
            "every gitops kind has a unique label"
        );
    }

    #[test]
    fn emit_gitops_event_fires_with_kind_and_event_type_labels() {
        use super::{emit_gitops_event, gitops_kind};
        let snap = capture_metrics(|| {
            emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyCreated");
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_gitops_events_emitted_total")
            .expect("hort_gitops_events_emitted_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("kind"), Some(&"scan_policy"));
        assert_eq!(labels.get("event_type"), Some(&"PolicyCreated"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_gitops_event_exclusion_kind_carries_exclusion_label() {
        use super::{emit_gitops_event, gitops_kind};
        let snap = capture_metrics(|| {
            emit_gitops_event(gitops_kind::EXCLUSION, "ExclusionAdded");
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_gitops_events_emitted_total")
            .expect("hort_gitops_events_emitted_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("kind"), Some(&"exclusion"));
        assert_eq!(labels.get("event_type"), Some(&"ExclusionAdded"));
    }

    // -------------------------------------------------------------------
    // `rejected_not_in_allowlist` result
    // value on `hort_gitops_objects_total{kind="upstream_mapping"}`.
    // -------------------------------------------------------------------

    #[test]
    fn gitops_object_result_rejected_not_in_allowlist_as_str() {
        use super::GitopsObjectResult;
        assert_eq!(
            GitopsObjectResult::RejectedNotInAllowlist.as_str(),
            "rejected_not_in_allowlist"
        );
    }

    #[test]
    fn gitops_object_result_values_are_unique() {
        use super::GitopsObjectResult;
        let variants = [
            GitopsObjectResult::Created,
            GitopsObjectResult::Updated,
            GitopsObjectResult::Deleted,
            GitopsObjectResult::Unchanged,
            GitopsObjectResult::RejectedNotInAllowlist,
        ];
        let set: HashSet<&'static str> = variants.iter().map(GitopsObjectResult::as_str).collect();
        assert_eq!(
            set.len(),
            variants.len(),
            "every GitopsObjectResult variant has a unique label"
        );
    }

    #[test]
    fn emit_gitops_object_with_rejected_not_in_allowlist_fires_counter() {
        use super::{emit_gitops_object, gitops_kind, GitopsObjectResult};
        let snap = capture_metrics(|| {
            emit_gitops_object(
                gitops_kind::UPSTREAM_MAPPING,
                GitopsObjectResult::RejectedNotInAllowlist,
            );
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_gitops_objects_total")
            .expect("hort_gitops_objects_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("kind"), Some(&"upstream_mapping"));
        assert_eq!(labels.get("result"), Some(&"rejected_not_in_allowlist"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_artifact_group_member_added_other_role_collapses() {
        use super::{emit_artifact_group_member_added, GroupMemberRole};
        let snap = capture_metrics(|| {
            emit_artifact_group_member_added(
                "my-repo",
                "custom",
                GroupMemberRole::classify("weird-handler-role"),
            );
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_group_members_added_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("role"), Some(&"other"));
    }

    // -------------------------------------------------------------------
    // DECISION_POINT / RULE label constants and
    // the policy_decision_point value module match the catalog exactly.
    // -------------------------------------------------------------------

    #[test]
    fn label_decision_point_is_decision_point() {
        assert_eq!(labels::DECISION_POINT, "decision_point");
    }

    #[test]
    fn label_rule_is_rule() {
        assert_eq!(labels::RULE, "rule");
    }

    #[test]
    fn policy_decision_point_constants_match_catalog() {
        use super::policy_decision_point as dp;
        assert_eq!(dp::SCAN_RESULT, "scan_result");
        assert_eq!(dp::PROMOTION, "promotion");
        assert_eq!(dp::RE_EVALUATION, "re_evaluation");
        assert_eq!(dp::CURATION, "curation");
        assert_eq!(dp::CURATION_RETROACTIVE, "curation_retroactive");
    }

    #[test]
    fn policy_decision_point_values_are_unique() {
        use super::policy_decision_point as dp;
        let values = [
            dp::SCAN_RESULT,
            dp::PROMOTION,
            dp::RE_EVALUATION,
            dp::CURATION,
            dp::CURATION_RETROACTIVE,
        ];
        let set: HashSet<&'static str> = values.iter().copied().collect();
        assert_eq!(set.len(), values.len());
    }

    // -------------------------------------------------------------------
    // PolicyEvaluationResult — every variant's `as_str()` matches the
    // catalog and values are unique.
    // -------------------------------------------------------------------

    #[test]
    fn policy_evaluation_result_pass_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::Pass.as_str(), "pass");
    }

    #[test]
    fn policy_evaluation_result_warn_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::Warn.as_str(), "warn");
    }

    #[test]
    fn policy_evaluation_result_require_approval_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::RequireApproval.as_str(), "require_approval");
    }

    #[test]
    fn policy_evaluation_result_block_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::Block.as_str(), "block");
    }

    #[test]
    fn policy_evaluation_result_reject_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::Reject.as_str(), "reject");
    }

    #[test]
    fn policy_evaluation_result_still_rejected_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::StillRejected.as_str(), "still_rejected");
    }

    #[test]
    fn policy_evaluation_result_reset_to_quarantined_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::ResetToQuarantined.as_str(), "reset_to_quarantined");
    }

    #[test]
    fn policy_evaluation_result_reset_to_released_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::ResetToReleased.as_str(), "reset_to_released");
    }

    #[test]
    fn policy_evaluation_result_retro_warn_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::RetroWarn.as_str(), "retro_warn");
    }

    #[test]
    fn policy_evaluation_result_retro_block_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::RetroBlock.as_str(), "retro_block");
    }

    #[test]
    fn policy_evaluation_result_no_change_as_str() {
        use super::PolicyEvaluationResult as R;
        assert_eq!(R::NoChange.as_str(), "no_change");
    }

    #[test]
    fn policy_evaluation_result_values_are_unique() {
        use super::PolicyEvaluationResult as R;
        let variants = [
            R::Pass,
            R::Warn,
            R::RequireApproval,
            R::Block,
            R::Reject,
            R::StillRejected,
            R::ResetToQuarantined,
            R::ResetToReleased,
            R::RetroWarn,
            R::RetroBlock,
            R::NoChange,
        ];
        let set: HashSet<&'static str> = variants.iter().map(R::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -- emit_policy_evaluation fires with the advertised labels --------

    #[test]
    fn emit_policy_evaluation_fires_with_decision_point_and_result() {
        use super::{emit_policy_evaluation, policy_decision_point as dp, PolicyEvaluationResult};
        let snap = capture_metrics(|| {
            emit_policy_evaluation(dp::SCAN_RESULT, PolicyEvaluationResult::Reject);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_policy_evaluation_total")
            .expect("hort_policy_evaluation_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("decision_point"), Some(&"scan_result"));
        assert_eq!(labels.get("result"), Some(&"reject"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_policy_evaluation_promotion_pass_uses_pass_label() {
        use super::{emit_policy_evaluation, policy_decision_point as dp, PolicyEvaluationResult};
        let snap = capture_metrics(|| {
            emit_policy_evaluation(dp::PROMOTION, PolicyEvaluationResult::Pass);
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_policy_evaluation_total")
            .expect("hort_policy_evaluation_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("decision_point"), Some(&"promotion"));
        assert_eq!(labels.get("result"), Some(&"pass"));
    }

    // -- emit_policy_violations groups by rule --------------------------

    #[test]
    fn emit_policy_violations_skipped_on_empty_slice() {
        use super::{emit_policy_violations, policy_decision_point as dp};
        let snap = capture_metrics(|| {
            emit_policy_violations(dp::SCAN_RESULT, &[]);
        });
        let entries = snap.into_vec();
        assert!(
            entries
                .iter()
                .all(|(k, _, _, _)| k.key().name() != "hort_policy_violations_total"),
            "no policy_violations counter on empty slice"
        );
    }

    #[test]
    fn emit_policy_violations_one_increment_per_distinct_rule() {
        use hort_domain::entities::scan_policy::SeverityThreshold;
        use hort_domain::events::PolicyViolation;

        use super::{emit_policy_violations, policy_decision_point as dp};

        let violations = vec![
            PolicyViolation {
                rule: "cve-severity-threshold".into(),
                severity: SeverityThreshold::Critical,
                message: "1".into(),
                details: serde_json::Value::Null,
            },
            // Same rule — must collapse to one counter increment, not two.
            PolicyViolation {
                rule: "cve-severity-threshold".into(),
                severity: SeverityThreshold::Critical,
                message: "2".into(),
                details: serde_json::Value::Null,
            },
            PolicyViolation {
                rule: "license-compliance".into(),
                severity: SeverityThreshold::High,
                message: "3".into(),
                details: serde_json::Value::Null,
            },
        ];

        let snap = capture_metrics(|| {
            emit_policy_violations(dp::PROMOTION, &violations);
        });
        let entries = snap.into_vec();

        // Two distinct (decision_point, rule) series — one per rule.
        let mut series: Vec<(String, u64)> = entries
            .iter()
            .filter(|(k, _, _, _)| k.key().name() == "hort_policy_violations_total")
            .map(|(k, _, _, v)| {
                let labels: std::collections::HashMap<&str, &str> =
                    k.key().labels().map(|l| (l.key(), l.value())).collect();
                let rule = labels.get("rule").copied().unwrap_or("").to_string();
                let count = match v {
                    metrics_util::debugging::DebugValue::Counter(c) => *c,
                    other => panic!("expected Counter, got {other:?}"),
                };
                (rule, count)
            })
            .collect();
        series.sort();

        assert_eq!(
            series,
            vec![
                ("cve-severity-threshold".to_string(), 1),
                ("license-compliance".to_string(), 1),
            ],
            "one increment per distinct rule, not per violation"
        );

        // All series must carry the supplied decision_point label.
        for (key, _, _, _) in &entries {
            if key.key().name() == "hort_policy_violations_total" {
                let labels: std::collections::HashMap<&str, &str> =
                    key.key().labels().map(|l| (l.key(), l.value())).collect();
                assert_eq!(labels.get("decision_point"), Some(&"promotion"));
            }
        }
    }

    #[test]
    fn emit_policy_violations_curation_block_label() {
        use hort_domain::entities::scan_policy::SeverityThreshold;
        use hort_domain::events::PolicyViolation;

        use super::{emit_policy_violations, policy_decision_point as dp};

        let violations = vec![PolicyViolation {
            rule: "curation-block".into(),
            severity: SeverityThreshold::High,
            message: "blocked".into(),
            details: serde_json::Value::Null,
        }];

        let snap = capture_metrics(|| {
            emit_policy_violations(dp::CURATION, &violations);
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_policy_violations_total")
            .expect("hort_policy_violations_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("decision_point"), Some(&"curation"));
        assert_eq!(labels.get("rule"), Some(&"curation-block"));
    }

    // -------------------------------------------------------------------
    // DedupLayer / DedupOutcomeLabel
    // -------------------------------------------------------------------

    #[test]
    fn dedup_layer_in_process_serialises_to_in_process() {
        use super::DedupLayer;
        assert_eq!(DedupLayer::InProcess.as_metric_label(), "in_process");
    }

    #[test]
    fn dedup_layer_cluster_serialises_to_cluster() {
        use super::DedupLayer;
        assert_eq!(DedupLayer::Cluster.as_metric_label(), "cluster");
    }

    #[test]
    fn dedup_outcome_label_taxonomy_is_eight_distinct_strings() {
        use super::DedupOutcomeLabel;
        // Every variant in the closed taxonomy maps to a distinct
        // catalog string. If a future contributor adds a variant
        // without updating the catalog and this test, the duplicate
        // surfaces here.
        let all = [
            DedupOutcomeLabel::LeaderStarted,
            DedupOutcomeLabel::FollowerWaitedHit,
            DedupOutcomeLabel::FollowerWaitedFailure,
            DedupOutcomeLabel::FollowerFellthrough503,
            DedupOutcomeLabel::NegativeCacheHit,
            DedupOutcomeLabel::LockExpiredReElected,
            DedupOutcomeLabel::FollowerLagged,
            DedupOutcomeLabel::LayerBUnavailable,
        ];
        let labels: HashSet<&'static str> = all.iter().map(|v| v.as_metric_label()).collect();
        assert_eq!(labels.len(), 8, "dedup outcome labels must be distinct");
        // Spot-check the canonical strings against the catalog.
        assert!(labels.contains("leader_started"));
        assert!(labels.contains("follower_waited_hit"));
        assert!(labels.contains("follower_waited_failure"));
        assert!(labels.contains("follower_fellthrough_503"));
        assert!(labels.contains("negative_cache_hit"));
        assert!(labels.contains("lock_expired_re_elected"));
        assert!(labels.contains("follower_lagged"));
        assert!(labels.contains("layer_b_unavailable"));
    }

    #[test]
    fn dedup_outcome_label_individual_strings_match_catalog() {
        use super::DedupOutcomeLabel;
        // One assertion per variant — easier to read in a CI failure
        // trail than reading a HashSet diff.
        assert_eq!(
            DedupOutcomeLabel::LeaderStarted.as_metric_label(),
            "leader_started"
        );
        assert_eq!(
            DedupOutcomeLabel::FollowerWaitedHit.as_metric_label(),
            "follower_waited_hit"
        );
        assert_eq!(
            DedupOutcomeLabel::FollowerWaitedFailure.as_metric_label(),
            "follower_waited_failure"
        );
        assert_eq!(
            DedupOutcomeLabel::FollowerFellthrough503.as_metric_label(),
            "follower_fellthrough_503"
        );
        assert_eq!(
            DedupOutcomeLabel::NegativeCacheHit.as_metric_label(),
            "negative_cache_hit"
        );
        assert_eq!(
            DedupOutcomeLabel::LockExpiredReElected.as_metric_label(),
            "lock_expired_re_elected"
        );
        assert_eq!(
            DedupOutcomeLabel::FollowerLagged.as_metric_label(),
            "follower_lagged"
        );
        assert_eq!(
            DedupOutcomeLabel::LayerBUnavailable.as_metric_label(),
            "layer_b_unavailable"
        );
    }

    // -------------------------------------------------------------------
    // Vulnerability-scanning metrics.
    // -------------------------------------------------------------------

    #[test]
    fn label_scanner_is_scanner() {
        assert_eq!(labels::SCANNER, "scanner");
    }

    #[test]
    fn label_severity_is_severity() {
        assert_eq!(labels::SEVERITY, "severity");
    }

    #[test]
    fn label_ingest_source_is_ingest_source() {
        assert_eq!(labels::INGEST_SOURCE, "ingest_source");
    }

    // -- ScanJobsResult --------------------------------------------------

    #[test]
    fn scan_jobs_result_pending_claimed_as_str() {
        assert_eq!(
            super::ScanJobsResult::PendingClaimed.as_str(),
            "pending_claimed"
        );
    }

    #[test]
    fn scan_jobs_result_completed_as_str() {
        assert_eq!(super::ScanJobsResult::Completed.as_str(), "completed");
    }

    #[test]
    fn scan_jobs_result_failed_as_str() {
        assert_eq!(super::ScanJobsResult::Failed.as_str(), "failed");
    }

    #[test]
    fn scan_jobs_result_retried_as_str() {
        assert_eq!(super::ScanJobsResult::Retried.as_str(), "retried");
    }

    #[test]
    fn scan_jobs_result_values_are_unique() {
        let variants = [
            super::ScanJobsResult::PendingClaimed,
            super::ScanJobsResult::Completed,
            super::ScanJobsResult::Failed,
            super::ScanJobsResult::Retried,
        ];
        let set: HashSet<&'static str> =
            variants.iter().map(super::ScanJobsResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_scan_jobs_increments_counter_with_result_label() {
        let snap = capture_metrics(|| {
            super::emit_scan_jobs(super::ScanJobsResult::PendingClaimed);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_scan_jobs_total")
            .expect("hort_scan_jobs_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"pending_claimed"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -- ScanTerminalResult ----------------------------------------------

    #[test]
    fn scan_terminal_result_as_str_values() {
        assert_eq!(super::ScanTerminalResult::Completed.as_str(), "completed");
        assert_eq!(
            super::ScanTerminalResult::Indeterminate.as_str(),
            "indeterminate"
        );
        assert_eq!(super::ScanTerminalResult::Rejected.as_str(), "rejected");
    }

    #[test]
    fn scan_terminal_result_values_are_unique() {
        let variants = [
            super::ScanTerminalResult::Completed,
            super::ScanTerminalResult::Indeterminate,
            super::ScanTerminalResult::Rejected,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(super::ScanTerminalResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    /// `hort_scan_terminal_total{result}` fires for
    /// each of the 3 closed-taxonomy `result` labels under a
    /// `DebuggingRecorder` (acceptance: catalog test with each label).
    #[test]
    fn emit_scan_terminal_fires_for_each_of_the_three_results() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            super::emit_scan_terminal(super::ScanTerminalResult::Completed);
            super::emit_scan_terminal(super::ScanTerminalResult::Indeterminate);
            super::emit_scan_terminal(super::ScanTerminalResult::Rejected);
        });
        let snap = snapshotter.snapshot().into_vec();
        for want in ["completed", "indeterminate", "rejected"] {
            let found = snap.iter().find(|(k, _, _, _)| {
                k.key().name() == "hort_scan_terminal_total"
                    && k.key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == want)
            });
            match found {
                Some((_, _, _, DebugValue::Counter(v))) => assert_eq!(
                    *v, 1,
                    "hort_scan_terminal_total{{result={want}}} must increment once"
                ),
                Some(_) => panic!("hort_scan_terminal_total must be a counter"),
                None => panic!("hort_scan_terminal_total{{result={want}}} not emitted"),
            }
        }
    }

    // -- ScanFailureResult ------------------------------------------------

    #[test]
    fn scan_failure_result_as_str_values() {
        assert_eq!(
            super::ScanFailureResult::FailedBranch.as_str(),
            "failed_branch"
        );
        assert_eq!(
            super::ScanFailureResult::ReportTooLarge.as_str(),
            "report_too_large"
        );
    }

    #[test]
    fn scan_failure_result_values_are_unique() {
        let variants = [
            super::ScanFailureResult::FailedBranch,
            super::ScanFailureResult::ReportTooLarge,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(super::ScanFailureResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    /// `emit_scan_failure` fires
    /// `hort_scan_record_outcome_failures_total{result, scanner}` with
    /// the `report_too_large` value + the originating backend name.
    #[test]
    fn emit_scan_failure_report_too_large_carries_scanner_label() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            super::emit_scan_failure(super::ScanFailureResult::ReportTooLarge, "trivy");
        });
        let snap = snapshotter.snapshot().into_vec();
        let found = snap.iter().find(|(k, _, _, _)| {
            k.key().name() == "hort_scan_record_outcome_failures_total"
                && k.key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "report_too_large")
                && k.key()
                    .labels()
                    .any(|l| l.key() == "scanner" && l.value() == "trivy")
        });
        match found {
            Some((_, _, _, DebugValue::Counter(v))) => assert_eq!(*v, 1),
            Some(_) => panic!("hort_scan_record_outcome_failures_total must be a counter"),
            None => panic!(
                "hort_scan_record_outcome_failures_total{{result=report_too_large,scanner=trivy}} not emitted"
            ),
        }
    }

    // -- AdvisoryQueryResult ---------------------------------------------

    #[test]
    fn advisory_query_result_as_str_values() {
        assert_eq!(super::AdvisoryQueryResult::CacheHit.as_str(), "cache_hit");
        assert_eq!(super::AdvisoryQueryResult::CacheMiss.as_str(), "cache_miss");
        assert_eq!(
            super::AdvisoryQueryResult::Upstream4xx.as_str(),
            "upstream_4xx"
        );
        assert_eq!(
            super::AdvisoryQueryResult::Upstream5xx.as_str(),
            "upstream_5xx"
        );
        assert_eq!(
            super::AdvisoryQueryResult::NetworkError.as_str(),
            "network_error"
        );
        assert_eq!(super::AdvisoryQueryResult::Timeout.as_str(), "timeout");
    }

    #[test]
    fn advisory_query_result_values_are_unique() {
        let variants = [
            super::AdvisoryQueryResult::CacheHit,
            super::AdvisoryQueryResult::CacheMiss,
            super::AdvisoryQueryResult::Upstream4xx,
            super::AdvisoryQueryResult::Upstream5xx,
            super::AdvisoryQueryResult::NetworkError,
            super::AdvisoryQueryResult::Timeout,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(super::AdvisoryQueryResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_advisory_query_increments_counter_with_result_label() {
        let snap = capture_metrics(|| {
            super::emit_advisory_query(super::AdvisoryQueryResult::Upstream5xx);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_advisory_query_total")
            .expect("hort_advisory_query_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"upstream_5xx"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -- SbomExtractionResult --------------------------------------------

    #[test]
    fn sbom_extraction_result_as_str_values() {
        assert_eq!(super::SbomExtractionResult::Success.as_str(), "success");
        assert_eq!(
            super::SbomExtractionResult::UnsupportedFormat.as_str(),
            "unsupported_format"
        );
        assert_eq!(
            super::SbomExtractionResult::ParseError.as_str(),
            "parse_error"
        );
    }

    #[test]
    fn sbom_extraction_result_values_are_unique() {
        let variants = [
            super::SbomExtractionResult::Success,
            super::SbomExtractionResult::UnsupportedFormat,
            super::SbomExtractionResult::ParseError,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(super::SbomExtractionResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_sbom_extraction_increments_counter_with_format_and_result_labels() {
        let snap = capture_metrics(|| {
            super::emit_sbom_extraction("npm", super::SbomExtractionResult::Success);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_sbom_extraction_total")
            .expect("hort_sbom_extraction_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("format"), Some(&"npm"));
        assert_eq!(labels.get("result"), Some(&"success"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -- emit_scan_findings ---------------------------------------------

    #[test]
    fn emit_scan_findings_increments_counter_with_scanner_and_severity_labels() {
        let snap = capture_metrics(|| {
            super::emit_scan_findings("trivy", "high");
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_scan_findings_total")
            .expect("hort_scan_findings_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("scanner"), Some(&"trivy"));
        assert_eq!(labels.get("severity"), Some(&"high"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -- observe_scan_duration -------------------------------------------

    #[test]
    fn observe_scan_duration_records_histogram_with_scanner_label() {
        let snap = capture_metrics(|| {
            super::observe_scan_duration("trivy", std::time::Duration::from_millis(123));
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_scan_duration_seconds")
            .expect("hort_scan_duration_seconds must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("scanner"), Some(&"trivy"));
        match value {
            metrics_util::debugging::DebugValue::Histogram(samples) => {
                assert!(
                    !samples.is_empty(),
                    "histogram must have at least one sample"
                );
            }
            other => panic!("expected Histogram, got {other:?}"),
        }
    }

    // -- emit_artifact_became_vulnerable ---------------------------------

    #[test]
    fn emit_artifact_became_vulnerable_with_repo_label() {
        let snap = capture_metrics(|| {
            super::emit_artifact_became_vulnerable("npm-proxy", "critical", "proxied");
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_became_vulnerable_total")
            .expect("hort_artifact_became_vulnerable_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"npm-proxy"));
        assert_eq!(labels.get("severity"), Some(&"critical"));
        assert_eq!(labels.get("ingest_source"), Some(&"proxied"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_artifact_became_vulnerable_with_collapsed_repository_sentinel() {
        // METRICS_INCLUDE_REPOSITORY_LABEL=false collapse: caller passes
        // values::REPOSITORY_ALL — the wire reflects the "_all" sentinel
        // verbatim. Pinning the contract here mirrors the equivalent
        // TLS-handshake test.
        let snap = capture_metrics(|| {
            super::emit_artifact_became_vulnerable(values::REPOSITORY_ALL, "high", "direct");
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_became_vulnerable_total")
            .expect("hort_artifact_became_vulnerable_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"_all"));
        assert_eq!(labels.get("severity"), Some(&"high"));
        assert_eq!(labels.get("ingest_source"), Some(&"direct"));
    }

    // -------------------------------------------------------------------
    // TriggerSourceLabel
    // -------------------------------------------------------------------

    #[test]
    fn label_trigger_source_is_trigger_source() {
        assert_eq!(labels::TRIGGER_SOURCE, "trigger_source");
    }

    #[test]
    fn label_ecosystem_is_ecosystem() {
        assert_eq!(labels::ECOSYSTEM, "ecosystem");
    }

    #[test]
    fn trigger_source_label_as_str_matches_sql_check_constraint() {
        // The wire strings MUST match the SQL CHECK on jobs.trigger_source.
        // A drift here would either fail the
        // INSERT or silently file scan-enqueues under the wrong bucket.
        assert_eq!(super::TriggerSourceLabel::Ingest.as_str(), "ingest");
        assert_eq!(super::TriggerSourceLabel::Cron.as_str(), "cron");
        assert_eq!(super::TriggerSourceLabel::Advisory.as_str(), "advisory");
        assert_eq!(super::TriggerSourceLabel::Manual.as_str(), "manual");
    }

    #[test]
    fn trigger_source_label_values_are_unique() {
        let variants = [
            super::TriggerSourceLabel::Ingest,
            super::TriggerSourceLabel::Cron,
            super::TriggerSourceLabel::Advisory,
            super::TriggerSourceLabel::Manual,
        ];
        let set: HashSet<&'static str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(set.len(), variants.len(), "label values must be unique");
    }

    #[test]
    fn trigger_source_label_mirrors_domain_trigger_source_wire_form() {
        // Cross-check against the domain enum so the two layers can never
        // drift. hort-app::TriggerSourceLabel is the metric label;
        // hort_domain::ports::jobs_repository::TriggerSource is the SQL
        // wire form. The two MUST agree.
        use hort_domain::ports::jobs_repository::TriggerSource as Ts;
        assert_eq!(
            super::TriggerSourceLabel::Ingest.as_str(),
            Ts::Ingest.as_str()
        );
        assert_eq!(super::TriggerSourceLabel::Cron.as_str(), Ts::Cron.as_str());
        assert_eq!(
            super::TriggerSourceLabel::Advisory.as_str(),
            Ts::Advisory.as_str()
        );
        assert_eq!(
            super::TriggerSourceLabel::Manual.as_str(),
            Ts::Manual.as_str()
        );
    }

    #[test]
    fn emit_scan_jobs_enqueued_increments_counter_with_trigger_source_label() {
        let snap = capture_metrics(|| {
            super::emit_scan_jobs_enqueued(super::TriggerSourceLabel::Cron, 3);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_scan_jobs_enqueued_total")
            .expect("hort_scan_jobs_enqueued_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("trigger_source"), Some(&"cron"));
        // High-cardinality forbidden labels — must NOT
        // appear under any circumstances.
        assert!(!labels.contains_key("artifact_id"));
        assert!(!labels.contains_key("purl"));
        assert!(!labels.contains_key("vulnerability_id"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 3),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_scan_jobs_enqueued_with_zero_count_is_noop_increment() {
        // Defensive: callers that batch-attempt N enqueues with zero
        // landed rows must still be safe to call; the wire records a
        // 0-increment counter (no time series created at all in the
        // happy path because the counter macro short-circuits zero, but
        // we pin the API shape regardless).
        let snap = capture_metrics(|| {
            super::emit_scan_jobs_enqueued(super::TriggerSourceLabel::Manual, 0);
        });
        // No assertion on the counter's value — just confirm no panic
        // and that if a series did materialise, the trigger_source
        // label is correct.
        for (key, _, _, _) in snap.into_vec() {
            if key.key().name() == "hort_scan_jobs_enqueued_total" {
                let labels: std::collections::HashMap<&str, &str> =
                    key.key().labels().map(|l| (l.key(), l.value())).collect();
                assert_eq!(labels.get("trigger_source"), Some(&"manual"));
            }
        }
    }

    // -- PatchCandidateListResult ---------------------------------------

    #[test]
    fn patch_candidate_list_result_as_str_matches_catalog_literals() {
        // Wire strings are normative — they appear verbatim in
        // `docs/metrics-catalog.md`. A drift here would silently file
        // patch-candidate listings under the wrong observability bucket.
        assert_eq!(super::PatchCandidateListResult::Ok.as_str(), "ok");
        assert_eq!(super::PatchCandidateListResult::Denied.as_str(), "denied");
        assert_eq!(super::PatchCandidateListResult::Invalid.as_str(), "invalid");
        assert_eq!(super::PatchCandidateListResult::Error.as_str(), "error");
    }

    #[test]
    fn patch_candidate_list_result_values_are_unique() {
        // Closed taxonomy of 4 — collapsing any pair would destroy the
        // load-bearing split between `invalid` (caller input) and
        // `error` (infrastructure failure).
        let variants = [
            super::PatchCandidateListResult::Ok,
            super::PatchCandidateListResult::Denied,
            super::PatchCandidateListResult::Invalid,
            super::PatchCandidateListResult::Error,
        ];
        let set: HashSet<&'static str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(set.len(), variants.len(), "label values must be unique");
    }

    #[test]
    fn patch_candidate_list_result_round_trip_pins_each_variant_to_string() {
        // Pin each variant explicitly so a reorder/rename can't silently
        // swap two values.
        let pairs: &[(super::PatchCandidateListResult, &str)] = &[
            (super::PatchCandidateListResult::Ok, "ok"),
            (super::PatchCandidateListResult::Denied, "denied"),
            (super::PatchCandidateListResult::Invalid, "invalid"),
            (super::PatchCandidateListResult::Error, "error"),
        ];
        for (variant, wire) in pairs {
            assert_eq!(
                variant.as_str(),
                *wire,
                "{variant:?} must serialise to {wire:?}"
            );
        }
    }

    #[test]
    fn emit_patch_candidates_listed_increments_counter_with_repository_all_sentinel() {
        let snap = capture_metrics(|| {
            super::emit_patch_candidates_listed(
                values::REPOSITORY_ALL,
                super::PatchCandidateListResult::Ok,
            );
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_patch_candidates_listed_total")
            .expect("hort_patch_candidates_listed_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        // `repository="_all"` is the admin-wide sentinel;
        // the next test pins the per-key emission shape.
        assert_eq!(labels.get("repository"), Some(&"_all"));
        assert_eq!(labels.get("result"), Some(&"ok"));
        // High-cardinality forbidden labels — must NOT
        // appear under any circumstances.
        assert!(!labels.contains_key("artifact_id"));
        assert!(!labels.contains_key("actor_id"));
        assert!(!labels.contains_key("user_id"));
        assert!(!labels.contains_key("purl"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    /// `repository=<key>` is the per-scope label when
    /// the handler resolved `?repository=<key>` to a row before
    /// dispatching to the use case. Pins the verbatim pass-through
    /// of the key string to the Prometheus label.
    #[test]
    fn emit_patch_candidates_listed_carries_resolved_key_when_supplied() {
        let snap = capture_metrics(|| {
            super::emit_patch_candidates_listed("npm-proxy", super::PatchCandidateListResult::Ok);
        });
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_patch_candidates_listed_total")
            .expect("hort_patch_candidates_listed_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(
            labels.get("repository"),
            Some(&"npm-proxy"),
            "resolved key must be emitted verbatim (no quoting / mangling)"
        );
        assert_eq!(labels.get("result"), Some(&"ok"));
    }

    #[test]
    fn emit_patch_candidates_listed_emits_each_result_variant_verbatim() {
        // One emission per variant — verify the `result` label is the
        // wire string for that variant.
        for (variant, wire) in [
            (super::PatchCandidateListResult::Ok, "ok"),
            (super::PatchCandidateListResult::Denied, "denied"),
            (super::PatchCandidateListResult::Invalid, "invalid"),
            (super::PatchCandidateListResult::Error, "error"),
        ] {
            let snap = capture_metrics(|| {
                super::emit_patch_candidates_listed(values::REPOSITORY_ALL, variant);
            });
            let entries = snap.into_vec();
            let hit = entries.iter().find(|(k, _, _, _)| {
                k.key().name() == "hort_patch_candidates_listed_total"
                    && k.key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == wire)
            });
            assert!(
                hit.is_some(),
                "expected hort_patch_candidates_listed_total{{result={wire:?}}} to fire for {variant:?}"
            );
        }
    }

    // -- AdvisoryDiffResult -------------------------------------------

    #[test]
    fn advisory_diff_result_as_str_values() {
        assert_eq!(super::AdvisoryDiffResult::Ok.as_str(), "ok");
        assert_eq!(
            super::AdvisoryDiffResult::FetchError.as_str(),
            "fetch_error"
        );
        assert_eq!(
            super::AdvisoryDiffResult::ParseError.as_str(),
            "parse_error"
        );
        assert_eq!(super::AdvisoryDiffResult::Timeout.as_str(), "timeout");
    }

    #[test]
    fn advisory_diff_result_values_are_unique() {
        let variants = [
            super::AdvisoryDiffResult::Ok,
            super::AdvisoryDiffResult::FetchError,
            super::AdvisoryDiffResult::ParseError,
            super::AdvisoryDiffResult::Timeout,
        ];
        let set: HashSet<&'static str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_advisory_diff_increments_counter_with_ecosystem_and_result_labels() {
        let snap = capture_metrics(|| {
            super::emit_advisory_diff("npm", super::AdvisoryDiffResult::Ok);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_advisory_diff_processed_total")
            .expect("hort_advisory_diff_processed_total must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("ecosystem"), Some(&"npm"));
        assert_eq!(labels.get("result"), Some(&"ok"));
        // Forbidden high-cardinality labels — never on this counter.
        assert!(!labels.contains_key("artifact_id"));
        assert!(!labels.contains_key("purl"));
        assert!(!labels.contains_key("package_name"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn observe_advisory_diff_duration_records_histogram_with_ecosystem_label() {
        let snap = capture_metrics(|| {
            super::observe_advisory_diff_duration("PyPI", 0.42);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_advisory_diff_duration_seconds")
            .expect("hort_advisory_diff_duration_seconds must fire");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("ecosystem"), Some(&"PyPI"));
        match value {
            metrics_util::debugging::DebugValue::Histogram(samples) => {
                assert!(!samples.is_empty(), "histogram must have a sample");
            }
            other => panic!("expected Histogram, got {other:?}"),
        }
    }

    #[test]
    fn set_cron_rescan_eligible_artifacts_records_gauge_value() {
        let snap = capture_metrics(|| {
            super::set_cron_rescan_eligible_artifacts(1234);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_cron_rescan_eligible_artifacts")
            .expect("hort_cron_rescan_eligible_artifacts must fire");
        // No labels — single global gauge per the catalog row.
        assert_eq!(
            key.key().labels().count(),
            0,
            "hort_cron_rescan_eligible_artifacts must have NO labels (single global gauge)",
        );
        match value {
            metrics_util::debugging::DebugValue::Gauge(v) => {
                assert_eq!(*v, 1234.0);
            }
            other => panic!("expected Gauge, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // ssrf_reason_label + emit_ssrf_block
    // -------------------------------------------------------------------

    #[test]
    fn ssrf_reason_label_ip_literal() {
        use hort_domain::entities::subscription::SsrfBlockReason;
        assert_eq!(
            super::ssrf_reason_label(SsrfBlockReason::IpLiteralNotRoutable),
            "ip_literal_not_routable",
        );
    }

    #[test]
    fn ssrf_reason_label_dns_resolved() {
        use hort_domain::entities::subscription::SsrfBlockReason;
        assert_eq!(
            super::ssrf_reason_label(SsrfBlockReason::DnsResolvedNotRoutable),
            "dns_resolved_not_routable",
        );
    }

    #[test]
    fn ssrf_reason_label_dns_failed() {
        use hort_domain::entities::subscription::SsrfBlockReason;
        assert_eq!(
            super::ssrf_reason_label(SsrfBlockReason::DnsResolutionFailed),
            "dns_resolution_failed",
        );
    }

    #[test]
    fn ssrf_reason_label_values_are_unique() {
        use hort_domain::entities::subscription::SsrfBlockReason;
        let variants = [
            SsrfBlockReason::IpLiteralNotRoutable,
            SsrfBlockReason::DnsResolvedNotRoutable,
            SsrfBlockReason::DnsResolutionFailed,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .copied()
            .map(super::ssrf_reason_label)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_ssrf_block_increments_counter_with_reason_label() {
        let snap = capture_metrics(|| {
            super::emit_ssrf_block("ip_literal_not_routable");
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_webhook_ssrf_block_total")
            .expect("hort_webhook_ssrf_block_total must fire");
        let lbls: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(lbls.get("reason"), Some(&"ip_literal_not_routable"));
        // Verify no forbidden / high-cardinality labels leak through.
        for forbidden in &[
            "subscription_id",
            "owner_user_id",
            "target_url",
            "url",
            "host",
        ] {
            assert!(
                !key.key().labels().any(|l| l.key() == *forbidden),
                "hort_webhook_ssrf_block_total must not carry label {forbidden}",
            );
        }
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Dispatcher metrics helpers
    // -------------------------------------------------------------------

    #[test]
    fn target_kind_label_webhook() {
        use hort_domain::entities::subscription::SubscriptionTarget;
        use url::Url;
        let target = SubscriptionTarget::Webhook {
            url: "https://hooks.example.com/x".parse::<Url>().unwrap(),
            secret_ref: hort_domain::ports::secret_port::SecretRef {
                source: hort_domain::ports::secret_port::SecretSource::EnvVar,
                location: "HORT_WEBHOOK_SECRET".into(),
            },
        };
        assert_eq!(super::target_kind_label(&target), "webhook");
    }

    #[test]
    fn target_kind_label_nats() {
        use hort_domain::entities::subscription::SubscriptionTarget;
        let target = SubscriptionTarget::NatsJetStream {
            subject: "hort.events".into(),
        };
        assert_eq!(super::target_kind_label(&target), "nats_jetstream");
    }

    #[test]
    fn notify_outcome_label_delivered() {
        use hort_domain::ports::event_notifier::NotifyOutcome;
        assert_eq!(
            super::notify_outcome_label(&NotifyOutcome::Delivered),
            "delivered"
        );
    }

    #[test]
    fn notify_outcome_label_downstream_rejected() {
        use hort_domain::ports::event_notifier::{NotifyFailureReason, NotifyOutcome};
        let o = NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http4xx { status: 404 },
        };
        assert_eq!(super::notify_outcome_label(&o), "downstream_rejected");
    }

    #[test]
    fn notify_outcome_label_failed() {
        use hort_domain::ports::event_notifier::{NotifyFailureReason, NotifyOutcome};
        let o = NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        };
        assert_eq!(super::notify_outcome_label(&o), "failed");
    }

    #[test]
    fn emit_notify_delivery_emits_counter_and_histogram() {
        let snap = capture_metrics(|| {
            super::emit_notify_delivery("webhook", "delivered", 0.123);
        });
        let entries = snap.into_vec();
        let counter = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_notify_delivery_total")
            .expect("counter must fire");
        let lbls: std::collections::HashMap<&str, &str> = counter
            .0
            .key()
            .labels()
            .map(|l| (l.key(), l.value()))
            .collect();
        assert_eq!(lbls.get("target_kind"), Some(&"webhook"));
        assert_eq!(lbls.get("result"), Some(&"delivered"));
        match &counter.3 {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
        // Verify forbidden high-cardinality labels do NOT appear.
        for forbidden in &["subscription_id", "owner_user_id", "url", "subject"] {
            assert!(
                !counter.0.key().labels().any(|l| l.key() == *forbidden),
                "hort_notify_delivery_total must not carry label {forbidden}",
            );
        }
        let histogram = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_notify_delivery_duration_seconds")
            .expect("histogram must fire");
        match &histogram.3 {
            metrics_util::debugging::DebugValue::Histogram(samples) => {
                assert_eq!(samples.len(), 1)
            }
            other => panic!("expected Histogram, got {other:?}"),
        }
    }

    #[test]
    fn emit_broadcast_lagged_increments_counter() {
        let snap = capture_metrics(|| {
            super::emit_broadcast_lagged();
            super::emit_broadcast_lagged();
        });
        let entries = snap.into_vec();
        let counter = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_notify_broadcast_lagged_total")
            .expect("counter must fire");
        match &counter.3 {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 2),
            other => panic!("expected Counter, got {other:?}"),
        }
        // No labels.
        assert_eq!(counter.0.key().labels().count(), 0);
    }

    #[test]
    fn set_subscription_state_gauge_sets_value() {
        let snap = capture_metrics(|| {
            super::set_subscription_state_gauge("active", 42);
        });
        let entries = snap.into_vec();
        let gauge = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_subscription_total")
            .expect("gauge must fire");
        let lbls: std::collections::HashMap<&str, &str> = gauge
            .0
            .key()
            .labels()
            .map(|l| (l.key(), l.value()))
            .collect();
        assert_eq!(lbls.get("state"), Some(&"active"));
        match &gauge.3 {
            metrics_util::debugging::DebugValue::Gauge(v) => {
                assert!((v.0 - 42.0).abs() < f64::EPSILON)
            }
            other => panic!("expected Gauge, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // `GET /api/v1/events` pull metrics.
    // -------------------------------------------------------------------

    #[test]
    fn events_pull_result_success_as_str() {
        assert_eq!(super::EventsPullResult::Success.as_str(), "success");
    }

    #[test]
    fn events_pull_result_no_match_as_str() {
        assert_eq!(super::EventsPullResult::NoMatch.as_str(), "no_match");
    }

    #[test]
    fn events_pull_result_forbidden_as_str() {
        assert_eq!(super::EventsPullResult::Forbidden.as_str(), "forbidden");
    }

    #[test]
    fn events_pull_result_values_are_unique() {
        let variants = [
            super::EventsPullResult::Success,
            super::EventsPullResult::NoMatch,
            super::EventsPullResult::Forbidden,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(super::EventsPullResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn emit_events_pull_emits_counter_and_histogram() {
        let snap = capture_metrics(|| {
            super::emit_events_pull("artifact", super::EventsPullResult::Success, 0.05);
        });
        let entries = snap.into_vec();
        let counter = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_events_pull_total")
            .expect("hort_events_pull_total counter must fire");
        let lbls: std::collections::HashMap<&str, &str> = counter
            .0
            .key()
            .labels()
            .map(|l| (l.key(), l.value()))
            .collect();
        assert_eq!(lbls.get("category"), Some(&"artifact"));
        assert_eq!(lbls.get("result"), Some(&"success"));
        match &counter.3 {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
        // The duration histogram must also fire, with the category
        // label only (no result label).
        let histogram = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_events_pull_duration_seconds")
            .expect("hort_events_pull_duration_seconds histogram must fire");
        let hist_lbls: std::collections::HashMap<&str, &str> = histogram
            .0
            .key()
            .labels()
            .map(|l| (l.key(), l.value()))
            .collect();
        assert_eq!(hist_lbls.get("category"), Some(&"artifact"));
        assert!(
            !histogram.0.key().labels().any(|l| l.key() == "result"),
            "duration histogram must not carry the result label"
        );
        // Verify forbidden high-cardinality labels do NOT appear.
        for forbidden in &["after", "max", "wait_ms", "user_id", "principal"] {
            assert!(
                !counter.0.key().labels().any(|l| l.key() == *forbidden),
                "hort_events_pull_total must not carry label {forbidden}",
            );
        }
    }

    // -- Eager metric registration ------------------------------------------

    /// `register_scan_metrics` registers every
    /// vulnerability-scanning metric in the active recorder's
    /// registry so /metrics carries the catalog from the first
    /// scrape — even before any producer has fired (the worker's
    /// `record_scan_result` path is the only emitter for
    /// `hort_artifact_became_vulnerable_total` and friends; hort-server
    /// scrapes /metrics but never increments those counters).
    ///
    /// This is the *layer-appropriate* test: hort-app doesn't choose an
    /// exporter, so the test only asserts that calling
    /// `register_scan_metrics` populates the `metrics::Recorder`
    /// registry. The rendered-Prometheus-text regression
    /// (the smoke test's phase-7 surface) lives in
    /// `crates/hort-server/tests/scan_metrics_registration.rs` —
    /// `metrics-exporter-prometheus` belongs to the composition root.
    #[test]
    fn register_scan_metrics_registers_every_metric_in_recorder() {
        let snap = capture_metrics(|| {
            super::register_scan_metrics();
        });
        let entries = snap.into_vec();
        let names: HashSet<&str> = entries.iter().map(|(k, _, _, _)| k.key().name()).collect();

        // Catalog of every scanning metric — kept in sync with
        // `docs/metrics-catalog.md §Vulnerability scanning` and
        // `register_scan_metrics`'s body. The
        // `DebuggingRecorder::Snapshot` enumerator only includes
        // metrics whose handle has been registered (not describe-
        // only), so the presence of every name here is the regression
        // that `let _ = counter!(name)` lines stay paired with each
        // `describe_*!` call.
        let expected = [
            "hort_scan_jobs_total",
            "hort_scan_findings_total",
            "hort_scan_duration_seconds",
            "hort_scan_queue_depth",
            "hort_advisory_query_total",
            "hort_sbom_extraction_total",
            "hort_artifact_became_vulnerable_total",
            "hort_scan_record_outcome_failures_total",
        ];
        for name in expected {
            assert!(
                names.contains(name),
                "expected `{name}` to be registered after \
                 register_scan_metrics; registered set was {names:?}",
            );
        }
    }

    // -------------------------------------------------------------------
    // Claim-based RBAC metrics.
    // -------------------------------------------------------------------

    #[test]
    fn label_source_is_source() {
        assert_eq!(labels::SOURCE, "source");
    }

    // ---- DispatcherPrincipalSource ------------------------------------

    #[test]
    fn dispatcher_principal_source_as_str_values() {
        use super::DispatcherPrincipalSource as S;
        assert_eq!(S::SnapshotPresent.as_str(), "snapshot_present");
        assert_eq!(S::SnapshotEmptyAdmin.as_str(), "snapshot_empty_admin");
        assert_eq!(S::SnapshotEmptyNoAdmin.as_str(), "snapshot_empty_no_admin");
    }

    #[test]
    fn dispatcher_principal_source_values_are_unique() {
        use super::DispatcherPrincipalSource as S;
        let variants = [
            S::SnapshotPresent,
            S::SnapshotEmptyAdmin,
            S::SnapshotEmptyNoAdmin,
        ];
        let set: HashSet<&'static str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(
            set.len(),
            variants.len(),
            "every DispatcherPrincipalSource variant has a unique label"
        );
    }

    #[test]
    fn emit_dispatcher_principal_resolved_fires_counter_with_source_label() {
        use super::{emit_dispatcher_principal_resolved, DispatcherPrincipalSource};
        let snap = capture_metrics(|| {
            emit_dispatcher_principal_resolved(DispatcherPrincipalSource::SnapshotEmptyNoAdmin);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_dispatcher_principal_resolved_total")
            .expect("hort_dispatcher_principal_resolved_total must fire");
        let lbls: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(lbls.get("source"), Some(&"snapshot_empty_no_admin"));
        // Forbidden high-cardinality labels must never appear.
        assert!(!lbls.contains_key("subscription_id"));
        assert!(!lbls.contains_key("user_id"));
        assert!(!lbls.contains_key("owner_user_id"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_dispatcher_principal_resolved_each_variant_verbatim() {
        use super::DispatcherPrincipalSource as S;
        for (variant, wire) in [
            (S::SnapshotPresent, "snapshot_present"),
            (S::SnapshotEmptyAdmin, "snapshot_empty_admin"),
            (S::SnapshotEmptyNoAdmin, "snapshot_empty_no_admin"),
        ] {
            let snap = capture_metrics(|| {
                super::emit_dispatcher_principal_resolved(variant);
            });
            let entries = snap.into_vec();
            let hit = entries
                .iter()
                .find(|(k, _, _, _)| k.key().name() == "hort_dispatcher_principal_resolved_total")
                .expect("counter must fire");
            let got = hit
                .0
                .key()
                .labels()
                .find(|l| l.key() == "source")
                .map(|l| l.value().to_owned());
            assert_eq!(got.as_deref(), Some(wire), "{variant:?} → {wire}");
        }
    }

    // ---- LinterResult -------------------------------------------------

    #[test]
    fn linter_result_as_str_values() {
        use super::LinterResult as R;
        assert_eq!(R::Pass.as_str(), "pass");
        assert_eq!(R::Warn.as_str(), "warn");
        assert_eq!(R::Reject.as_str(), "reject");
    }

    #[test]
    fn linter_result_values_are_unique() {
        use super::LinterResult as R;
        let variants = [R::Pass, R::Warn, R::Reject];
        let set: HashSet<&'static str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(
            set.len(),
            variants.len(),
            "every LinterResult variant has a unique label"
        );
    }

    #[test]
    fn emit_apply_config_linter_fires_counter_with_rule_and_result() {
        use super::{emit_apply_config_linter, LinterResult};
        let snap = capture_metrics(|| {
            emit_apply_config_linter("single-claim-grant", LinterResult::Reject);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_apply_config_linter_total")
            .expect("hort_apply_config_linter_total must fire");
        let lbls: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(lbls.get("rule"), Some(&"single-claim-grant"));
        assert_eq!(lbls.get("result"), Some(&"reject"));
        // Operator-authored claim/group names must never become labels.
        assert!(!lbls.contains_key("claim_name"));
        assert!(!lbls.contains_key("group_name"));
        assert!(!lbls.contains_key("grant_id"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_apply_config_linter_carries_static_rule_verbatim() {
        // The four v1 lint rules — `rule` cardinality is
        // fixed at this count; each must pass through verbatim.
        for rule in [
            "single-claim-grant",
            "direct-user-grant-without-justification",
            "wildcard-repo-non-admin",
            "claim-name-collision",
        ] {
            let snap = capture_metrics(|| {
                super::emit_apply_config_linter(rule, super::LinterResult::Pass);
            });
            let entries = snap.into_vec();
            let hit = entries
                .iter()
                .find(|(k, _, _, _)| k.key().name() == "hort_apply_config_linter_total")
                .expect("counter must fire");
            let got = hit
                .0
                .key()
                .labels()
                .find(|l| l.key() == "rule")
                .map(|l| l.value().to_owned());
            assert_eq!(got.as_deref(), Some(rule));
        }
    }

    // ---- EffectivePermissionsResult -----------------------------------

    #[test]
    fn effective_permissions_result_as_str_values() {
        use super::EffectivePermissionsResult as R;
        assert_eq!(R::Ok.as_str(), "ok");
        assert_eq!(R::Denied.as_str(), "denied");
        assert_eq!(R::NotFound.as_str(), "not_found");
    }

    #[test]
    fn effective_permissions_result_values_are_unique() {
        use super::EffectivePermissionsResult as R;
        let variants = [R::Ok, R::Denied, R::NotFound];
        let set: HashSet<&'static str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(
            set.len(),
            variants.len(),
            "every EffectivePermissionsResult variant has a unique label"
        );
    }

    #[test]
    fn emit_effective_permissions_lookup_fires_counter_with_result() {
        use super::{emit_effective_permissions_lookup, EffectivePermissionsResult};
        let snap = capture_metrics(|| {
            emit_effective_permissions_lookup(EffectivePermissionsResult::NotFound);
        });
        let entries = snap.into_vec();
        let (key, _, _, value) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_effective_permissions_lookups_total")
            .expect("hort_effective_permissions_lookups_total must fire");
        let lbls: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(lbls.get("result"), Some(&"not_found"));
        // No per-user identity labels — audit goes to events/tracing.
        assert!(!lbls.contains_key("user_id"));
        assert!(!lbls.contains_key("inspected_user_id"));
        assert!(!lbls.contains_key("inspecting_user_id"));
        match value {
            metrics_util::debugging::DebugValue::Counter(v) => assert_eq!(*v, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emit_effective_permissions_lookup_each_variant_verbatim() {
        use super::EffectivePermissionsResult as R;
        for (variant, wire) in [
            (R::Ok, "ok"),
            (R::Denied, "denied"),
            (R::NotFound, "not_found"),
        ] {
            let snap = capture_metrics(|| {
                super::emit_effective_permissions_lookup(variant);
            });
            let entries = snap.into_vec();
            let hit = entries
                .iter()
                .find(|(k, _, _, _)| k.key().name() == "hort_effective_permissions_lookups_total")
                .expect("counter must fire");
            let got = hit
                .0
                .key()
                .labels()
                .find(|l| l.key() == "result")
                .map(|l| l.value().to_owned());
            assert_eq!(got.as_deref(), Some(wire), "{variant:?} → {wire}");
        }
    }

    // ---- claim_mapping label rename ------------------------------------

    #[test]
    fn gitops_kind_claim_mapping_is_claim_mapping() {
        // The gitops `group_mapping` kind was renamed to
        // `claim_mapping` (the `group_mappings` table is replaced by
        // `claim_mappings`). The catalog row + apply call sites move in
        // the same commit (catalog-and-code-atomic).
        assert_eq!(super::gitops_kind::CLAIM_MAPPING, "claim_mapping");
    }

    // ---- UpstreamFetchError variant taxonomy ---------------------------
    //
    // Every variant is constructable in isolation, equality holds (Clone +
    // PartialEq + Eq + Debug are derived), and `as_upstream_error_kind`
    // maps the eight upstream-fetch variants 1:1 onto the matching
    // `UpstreamErrorKind` label values. The out-of-band
    // `UnsupportedFormat` variant returns `None` — the use case emits
    // `result = "oci_unsupported"`, NOT one of the
    // `UpstreamErrorKind` label values.

    #[test]
    fn upstream_fetch_error_not_found_maps_to_kind_not_found() {
        let err = UpstreamFetchError::NotFound;
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::NotFound)
        );
    }

    #[test]
    fn upstream_fetch_error_unauthorized_maps_to_kind_unauthorized() {
        let err = UpstreamFetchError::Unauthorized;
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::Unauthorized),
        );
    }

    #[test]
    fn upstream_fetch_error_rate_limited_maps_to_kind_rate_limited() {
        let err = UpstreamFetchError::RateLimited;
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::RateLimited),
        );
    }

    #[test]
    fn upstream_fetch_error_upstream_4xx_maps_to_kind_upstream_4xx() {
        let err = UpstreamFetchError::Upstream4xx { status: 418 };
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::Upstream4xx),
        );
        // Status code is preserved verbatim on the variant for adapter-
        // side observability; the metric label collapses it to the
        // class string.
        match err {
            UpstreamFetchError::Upstream4xx { status } => assert_eq!(status, 418),
            other => panic!("expected Upstream4xx {{ status: 418 }}, got {other:?}"),
        }
    }

    #[test]
    fn upstream_fetch_error_upstream_5xx_maps_to_kind_upstream_5xx() {
        let err = UpstreamFetchError::Upstream5xx { status: 503 };
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::Upstream5xx),
        );
        match err {
            UpstreamFetchError::Upstream5xx { status } => assert_eq!(status, 503),
            other => panic!("expected Upstream5xx {{ status: 503 }}, got {other:?}"),
        }
    }

    #[test]
    fn upstream_fetch_error_network_error_maps_to_kind_network_error() {
        // Sanitised string — class label only, no host / URL detail.
        let err = UpstreamFetchError::NetworkError("dns".into());
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::NetworkError),
        );
        match &err {
            UpstreamFetchError::NetworkError(s) => assert_eq!(s, "dns"),
            other => panic!("expected NetworkError(_), got {other:?}"),
        }
    }

    #[test]
    fn upstream_fetch_error_timeout_maps_to_kind_timeout() {
        let err = UpstreamFetchError::Timeout;
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::Timeout),
        );
    }

    #[test]
    fn upstream_fetch_error_parse_error_maps_to_kind_parse_error() {
        // Sanitised string — parser-stage label only, no payload bytes.
        let err = UpstreamFetchError::ParseError("npm packument deserialize".into());
        assert_eq!(
            err.as_upstream_error_kind(),
            Some(UpstreamErrorKind::ParseError),
        );
        match &err {
            UpstreamFetchError::ParseError(s) => assert_eq!(s, "npm packument deserialize"),
            other => panic!("expected ParseError(_), got {other:?}"),
        }
    }

    #[test]
    fn upstream_fetch_error_unsupported_format_does_not_map_to_kind() {
        // OCI / unknown-format short-circuit — NOT one of the
        // `UpstreamErrorKind` label values. The use case emits
        // `result = "oci_unsupported"` and returns
        // `DomainError::Validation(_)` to the inbound layer.
        let err = UpstreamFetchError::UnsupportedFormat;
        assert_eq!(err.as_upstream_error_kind(), None);
    }

    #[test]
    fn upstream_fetch_error_eq_holds_for_same_variants() {
        // Eq + PartialEq let downstream tests pattern-match without
        // tearing apart the variant; this guards the derive.
        assert_eq!(UpstreamFetchError::NotFound, UpstreamFetchError::NotFound);
        assert_eq!(
            UpstreamFetchError::Upstream4xx { status: 410 },
            UpstreamFetchError::Upstream4xx { status: 410 },
        );
        assert_ne!(
            UpstreamFetchError::Upstream4xx { status: 410 },
            UpstreamFetchError::Upstream4xx { status: 451 },
        );
        assert_eq!(
            UpstreamFetchError::NetworkError("dns".into()),
            UpstreamFetchError::NetworkError("dns".into()),
        );
        assert_ne!(
            UpstreamFetchError::NetworkError("dns".into()),
            UpstreamFetchError::NetworkError("tls".into()),
        );
        assert_ne!(UpstreamFetchError::NotFound, UpstreamFetchError::Timeout);
        assert_ne!(
            UpstreamFetchError::UnsupportedFormat,
            UpstreamFetchError::NotFound,
        );
    }

    #[test]
    fn upstream_fetch_error_clone_preserves_variants() {
        // Clone is required for downstream test fixtures that hold
        // a configured error and re-yield it across multiple mock
        // invocations.
        let err = UpstreamFetchError::Upstream5xx { status: 502 };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn upstream_fetch_error_kind_alignment_is_complete() {
        // Pinned-set assertion: the eight fetch variants MUST map to
        // exactly the eight upstream-fetch `UpstreamErrorKind` label
        // values. Adding or removing a variant without updating both
        // ends breaks this test.
        //
        // `UpstreamErrorKind` is `Copy + Eq` but deliberately NOT
        // `Hash` (it is a label-value enum, not a map key), so we
        // compare on the wire string form the catalog already pins.
        let mut mapped_wire: Vec<&'static str> = [
            UpstreamFetchError::NotFound,
            UpstreamFetchError::Unauthorized,
            UpstreamFetchError::RateLimited,
            UpstreamFetchError::Upstream4xx { status: 400 },
            UpstreamFetchError::Upstream5xx { status: 500 },
            UpstreamFetchError::NetworkError(String::new()),
            UpstreamFetchError::Timeout,
            UpstreamFetchError::ParseError(String::new()),
        ]
        .iter()
        .map(|e| {
            e.as_upstream_error_kind()
                .expect("fetch variant maps to a kind")
                .as_str()
        })
        .collect();
        mapped_wire.sort_unstable();
        let mut expected_wire: Vec<&'static str> = [
            UpstreamErrorKind::NotFound,
            UpstreamErrorKind::Unauthorized,
            UpstreamErrorKind::RateLimited,
            UpstreamErrorKind::Upstream4xx,
            UpstreamErrorKind::Upstream5xx,
            UpstreamErrorKind::NetworkError,
            UpstreamErrorKind::Timeout,
            UpstreamErrorKind::ParseError,
        ]
        .iter()
        .map(UpstreamErrorKind::as_str)
        .collect();
        expected_wire.sort_unstable();
        assert_eq!(
            mapped_wire, expected_wire,
            "1:1 fetch-variant ↔ kind-label alignment",
        );

        // And the kinds NOT in the fetch subset stay unmapped from
        // this enum's surface — checksum + body-too-large + pin/CA
        // fire on other code paths; success is the Ok half.
        let unmapped_wire: HashSet<&'static str> = [
            UpstreamErrorKind::Success,
            UpstreamErrorKind::ChecksumMismatch,
            UpstreamErrorKind::BodyTooLarge,
            UpstreamErrorKind::PinMismatch,
            UpstreamErrorKind::CaUnknown,
        ]
        .iter()
        .map(UpstreamErrorKind::as_str)
        .collect();
        let mapped_set: HashSet<&'static str> = mapped_wire.iter().copied().collect();
        assert!(
            unmapped_wire.is_disjoint(&mapped_set),
            "non-fetch kinds must NOT appear in the fetch alignment set",
        );
    }

    #[test]
    fn gitops_kind_role_removed() {
        // `role` was a gitops kind for the dropped structural-RBAC
        // `Role` plan, deleted under the additive-claims model;
        // no emitter passes `role` anymore so the constant is gone.
        // This test documents the removal via the unique-set count.
        use super::gitops_kind;
        let live = [
            gitops_kind::REPOSITORY,
            gitops_kind::CLAIM_MAPPING,
            gitops_kind::PERMISSION_GRANT,
            gitops_kind::CURATION_RULE,
            gitops_kind::SCAN_POLICY,
            gitops_kind::EXCLUSION,
            gitops_kind::UPSTREAM_MAPPING,
            gitops_kind::OIDC_ISSUER,
            gitops_kind::SERVICE_ACCOUNT,
        ];
        assert!(
            !live.contains(&"role"),
            "`role` gitops kind must be gone under the additive-claims model"
        );
        assert!(
            !live.contains(&"group_mapping"),
            "`group_mapping` gitops kind renamed to `claim_mapping`"
        );
    }
}
