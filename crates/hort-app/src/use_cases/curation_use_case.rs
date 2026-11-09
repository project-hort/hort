//! `CurationUseCase` (`waive` + `block`).
//!
//! Curator decision authority over quarantined / non-terminal artifacts.
//! `waive` is **the** manual release (ADR 0007, "One authority owns the
//! manual release"). Its shape is the one every per-artifact decision
//! path in this layer uses: privilege
//! check → optimistic-concurrency stream read → state transition →
//! atomic event-append + projection-delta via the same
//! `ArtifactLifecyclePort::commit_transition_with_score` chokepoint.
//!
//! See `docs/architecture/how-to/curator-workflow.md` and ADR 0007.
//!
//! # Correlation-ID placement
//!
//! The per-call audit-grouping `correlation_id` rides on the
//! [`AppendEvents`] envelope (event-store outcome (A) — the envelope
//! already supports it). For `BlockTarget::VersionList`, a single
//! `correlation_id` is generated at the call boundary and threaded
//! through every per-artifact append's `AppendEvents` so the audit log
//! groups the bulk operation. The `ArtifactRejected` payload itself
//! does NOT carry a `correlation_id` — the envelope field is the
//! single source of truth for grouping.
//!
//! # Continue-on-error
//!
//! Per-append failures land in [`BlockOutcome::failed`]; successful
//! appends are NOT rolled back (events are immutable — event-sourcing
//! does not permit "all-or-nothing"). The justification cap is enforced
//! ONCE at the call boundary; the same justification text rides every
//! event the call emits, so oversize justification fails fast before
//! any append.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::artifact::{
    CurationClearance, ProvenanceClearance, QuarantineStatus, ReleaseAuthorization,
};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ApiActor, ArtifactReEvaluated, DomainEvent, ReEvaluationTrigger, ReleaseReason,
    StreamId, NO_POLICY,
};
use hort_domain::policy::{composite_verdict_mode_of, ReEvaluationOutcome};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::curation_decisions_repository::{
    CurationDecisionEntry, CurationDecisionFilter, CurationDecisionsRepository,
};
use hort_domain::ports::curation_exclusions_repository::{
    CurationExclusionEntry, CurationExclusionFilter, CurationExclusionsRepository,
};
use hort_domain::ports::curation_queue_repository::{
    CurationQueueEntry, CurationQueueFilter, CurationQueueRepository,
};
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{AppendEvents, EventToAppend};
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;
use hort_domain::types::{ContentHash, PageRequest};

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_curation_decision, emit_release, values, CurationDecisionLabel, CurationDecisionResult,
};
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::release_clearance::resolve_curation_clearance;
use crate::use_cases::repository_access::RepositoryAccessUseCase;
use crate::use_cases::scan_kind_resolution::scan_kind_of;
use crate::use_cases::upstream_index_cache_invalidator::invalidate_after_reject;
use crate::use_cases::{
    refuse_append_past_cap, rejected_reevaluation, scan_history, ArtifactAtVersion,
    CallerPrivileges, OverCapStream,
};

/// Maximum justification length in BYTES.
/// Mirrors `MAX_JUSTIFICATION_LEN` semantics on `ArtifactReleased::validate`.
const MAX_JUSTIFICATION_BYTES: usize = 512;

/// Maximum number of entries per bulk **block** call —
/// `BlockTarget::VersionList` and `BlockTarget::DigestList` alike.
/// Mirrors the queue `limit` shape — bounded per-call work.
const MAX_VERSIONS_PER_CALL: usize = 100;

/// Maximum number of entries per bulk **waive** call
/// ([`WaiveTarget`]), against the block cap of
/// [`MAX_VERSIONS_PER_CALL`] above.
///
/// The asymmetry is deliberate and is not two roundings of one number.
/// A block is reversible by the same curator the next minute; an
/// `ArtifactReleased` is history that cannot be retracted, so the
/// over-broad list is the footgun a fail-open verb has to bound and a
/// fail-safe one does not. Enforced here *and* at the handler boundary,
/// exactly as the block cap is — a cap that lived only at the handler
/// would be bypassable by every other caller of this use case, and the
/// gitops pipeline this addressing exists for is such a caller.
const MAX_WAIVE_ENTRIES_PER_CALL: usize = 25;

/// The one digest algorithm hort addresses content by (ADR 0003), and so
/// the only algorithm prefix a curator-supplied digest may carry — the
/// only one [`normalize_curation_digest`] strips rather than refuses.
const SHA256_DIGEST_ALGORITHM: &str = "sha256";

/// Maximum `limit` accepted by [`CurationUseCase::list_queue`] — caps
/// bounded work per call (the same 500-row cap every curation listing
/// uses). Adapter layer also clamps defensively.
const MAX_QUEUE_LIMIT: u32 = 500;

/// Cap on rows read from `ArtifactRepository::find_by_name_in_repo`
/// when resolving versions for a `VersionList` block. Mirrors
/// `MAX_VERSIONS_PER_CALL` + slack so a package with up to ~256 versions
/// resolves in a single page; larger packages spill into the
/// not-found list (defensive — `VersionList` is a curator-facing
/// bulk-input surface, not a discovery surface).
///
/// The page is bounded; the use case does not iterate pages
/// for this query (the curator's expectation is "match my list now,
/// surface misses").
const VERSION_RESOLUTION_PAGE_LIMIT: u64 = 256;

/// Target of a [`CurationUseCase::block`] call.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockTarget {
    /// Single-artifact block — the canonical primitive.
    Artifact(Uuid),
    /// Bulk block by explicit `(repository, package, versions)` list.
    /// Versions that don't resolve to an artifact_id surface in
    /// [`BlockOutcome::not_found_versions`] (NOT auto-blocked on future
    /// ingest).
    VersionList {
        repository_id: Uuid,
        package: String,
        versions: Vec<String>,
    },
    /// Bulk block by explicit `(repository, digests)` list — the
    /// content-addressed sibling of [`Self::VersionList`], for OCI and
    /// every other format where `artifacts.version` is `NULL` by
    /// construction and the bytes are the only writable address.
    ///
    /// Each digest is a bare 64-hex SHA-256 or the same value carrying a
    /// `sha256:` prefix; see [`normalize_curation_digest`]. Digests that
    /// match no live row in the repository surface in
    /// [`BlockOutcome::not_found_digests`], mirroring
    /// `not_found_versions`.
    DigestList {
        repository_id: Uuid,
        digests: Vec<String>,
    },
}

/// Result envelope for [`CurationUseCase::block`].
///
/// Returned for BOTH target shapes. For `BlockTarget::Artifact` at most
/// one of `blocked_artifact_ids` / `already_rejected_ids` / `failed`
/// has one entry. For `BlockTarget::VersionList`, the lists partition
/// the input into the four outcomes; `not_found_versions` carries the
/// strings the resolver could not match to an artifact_id.
///
/// **Why not `Clone` / `PartialEq`.** `AppError` is intentionally
/// non-cloneable (it carries error chains and non-clonable variants);
/// the outcome envelope honours that. Tests assert per-field via
/// destructuring (`outcome.failed.len() == 1` etc.) rather than via
/// whole-struct equality.
#[derive(Debug)]
pub struct BlockOutcome {
    /// Shared across every `ArtifactRejected` event this call emits —
    /// the audit log's grouping key for the operator's intent.
    pub correlation_id: Uuid,
    /// Artifacts that transitioned to `Rejected` on this call.
    pub blocked_artifact_ids: Vec<Uuid>,
    /// Artifacts already in `Rejected` — idempotent no-op (NO event
    /// appended). Counted so the operator sees the discrepancy.
    pub already_rejected_ids: Vec<Uuid>,
    /// Versions in a `VersionList` target that resolved to no
    /// artifact_id (not ingested yet). Blocking does NOT auto-block
    /// future ingests of these.
    pub not_found_versions: Vec<String>,
    /// Digests in a [`BlockTarget::DigestList`] target that matched no
    /// live row in the repository, echoed back **as the caller wrote
    /// them** (prefixed or bare). The content-addressed mirror of
    /// `not_found_versions`, with the same semantics: blocking does NOT
    /// auto-block a future ingest of those bytes.
    pub not_found_digests: Vec<String>,
    /// Per-append failures (continue-on-error): the
    /// artifact_id + the `AppError` returned by the event-store
    /// commit. Successful appends in the same call are NOT rolled
    /// back.
    pub failed: Vec<(Uuid, AppError)>,
}

/// Target of a [`CurationUseCase::waive_bulk`] call — the bulk,
/// addressed-by-what-was-reviewed counterpart to
/// [`CurationUseCase::waive`]'s bare `artifact_id`.
///
/// A UUID is neither writable by a human nor stable across
/// re-ingestion, so the two arms here are the forms a reviewed decision
/// can actually be written down in: a version list for the formats where
/// `artifacts.version` is populated and immutable, and a digest list for
/// OCI and everything else content-addressed.
///
/// **No tag is an addressing key on either arm.** A tag is a mutable
/// pointer and a curation decision binds to the bytes that were
/// reviewed; the curation queue renders tags as an annotation and
/// nothing on this path accepts one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaiveTarget {
    /// Bulk waive by explicit `(repository, package, versions)` list.
    /// Resolution mirrors [`BlockTarget::VersionList`] exactly — one
    /// resolver, so the two verbs cannot drift on what a version means.
    VersionList {
        repository_id: Uuid,
        package: String,
        versions: Vec<String>,
    },
    /// Bulk waive by explicit `(repository, digests)` list. Resolution
    /// mirrors [`BlockTarget::DigestList`] exactly, through the same
    /// resolver.
    DigestList {
        repository_id: Uuid,
        digests: Vec<String>,
    },
}

impl WaiveTarget {
    /// Split into the repository the entries resolve inside and the
    /// addressing keys themselves.
    ///
    /// [`BulkKeys`] is the shape **both** curation verbs resolve, which
    /// is what makes "one resolver per addressing mode" true rather than
    /// aspirational: a waive and a block addressed the same way go
    /// through the same code, so the two cannot drift on what a version
    /// or a digest means.
    fn into_keys(self) -> (Uuid, BulkKeys) {
        match self {
            Self::VersionList {
                repository_id,
                package,
                versions,
            } => (repository_id, BulkKeys::Versions { package, versions }),
            Self::DigestList {
                repository_id,
                digests,
            } => (repository_id, BulkKeys::Digests(digests)),
        }
    }
}

/// What a bulk waive found when it looked up one addressing entry, and
/// what it decided to do about it.
///
/// Reported for **every** entry of an aborted call, the resolvable ones
/// included: a curator who asked for five releases and got none needs to
/// see which entry stopped the batch *and* that the other four were
/// otherwise fine, or the only way to find out is to bisect the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaiveEntryVerdict {
    /// Resolved and `Quarantined` — this entry is releasable.
    Releasable,
    /// Resolved and already `Released` — the intent is already true.
    /// An idempotent success with no event, mirroring block's
    /// `already_rejected_ids`: without it a gitops re-apply of the same
    /// decision file would fail forever.
    AlreadyReleased,
    /// No live row in the repository carries this addressing key.
    Unresolvable,
    /// Several live rows in the repository carry these bytes. Never a
    /// pick — identical bytes can be ingested at several paths, and
    /// fail-closed beats guessing which row was reviewed. Carries the
    /// candidate artifact ids so the curator can re-address the decision
    /// at the row they mean.
    Ambiguous(Vec<Uuid>),
    /// Resolved, but in a state a bulk waive does not reach. Narrower
    /// than [`CurationUseCase::waive`]'s own source-state set on purpose
    /// — see [`bulk_waive_applicability`].
    StateNotReleasable(QuarantineStatus),
}

impl WaiveEntryVerdict {
    /// Stable discriminator for the wire and the audit log.
    pub const fn wire_kind(&self) -> &'static str {
        match self {
            Self::Releasable => "releasable",
            Self::AlreadyReleased => "already_released",
            Self::Unresolvable => "unresolvable",
            Self::Ambiguous(_) => "ambiguous",
            Self::StateNotReleasable(_) => "state_not_releasable",
        }
    }
}

/// One addressing entry of a bulk waive, with the key the caller wrote,
/// the row it resolved to (when it resolved to exactly one), and the
/// verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaiveEntryReport {
    /// The addressing key **verbatim as the caller supplied it** — a
    /// version string, or a digest with whatever prefix it arrived with.
    /// Echoed rather than normalised so the curator can match the report
    /// line against the decision file they applied.
    pub key: String,
    /// The resolved row, when resolution produced exactly one.
    pub artifact_id: Option<Uuid>,
    pub verdict: WaiveEntryVerdict,
}

impl WaiveEntryReport {
    /// The row this entry applies to, and whether it is already
    /// released — `None` when this is an entry that aborts the batch.
    ///
    /// **One answer rather than two.** "May the batch proceed?" and "on
    /// which row?" are asked at the same moment by the same code, so
    /// answering them separately would let the apply loop be handed an
    /// entry whose verdict permitted it while its row was absent. There
    /// is no such entry — `Releasable` and `AlreadyReleased` are exactly
    /// the verdicts resolution produced a single row for — and this
    /// function is how that stays a fact instead of a comment.
    fn applicable_row(&self) -> Option<(Uuid, bool)> {
        match (self.artifact_id, &self.verdict) {
            (Some(id), WaiveEntryVerdict::Releasable) => Some((id, false)),
            (Some(id), WaiveEntryVerdict::AlreadyReleased) => Some((id, true)),
            _ => None,
        }
    }
}

/// The applied half of a bulk waive — the four partitions of a call that
/// passed pre-validation.
#[derive(Debug)]
pub struct WaiveApplied {
    /// Shared across every `ArtifactReleased` this call emits — the
    /// audit log's grouping key for the curator's one decision.
    pub correlation_id: Uuid,
    /// Artifacts that transitioned to `Released` on this call. One
    /// `ArtifactReleased` each, no more: two entries addressing the same
    /// row (a bare and a `sha256:`-prefixed spelling of one digest)
    /// release it once.
    pub released_artifact_ids: Vec<Uuid>,
    /// Artifacts already `Released` — idempotent successes with no event
    /// appended, mirroring [`BlockOutcome::already_rejected_ids`].
    pub already_released_ids: Vec<Uuid>,
    /// Per-artifact apply failures. Reachable only through the
    /// validate→apply window: pre-validation admitted the entry and the
    /// artifact moved, or its stream did, before the append landed. Never
    /// silently skipped, and never retried into a release the curator did
    /// not review.
    pub failed: Vec<(Uuid, AppError)>,
}

/// Result of [`CurationUseCase::waive_bulk`].
///
/// **An enum rather than a struct with an `aborted` flag, deliberately.**
/// A bulk waive is fail-open — `ArtifactReleased` is history that cannot
/// be retracted — so "nothing was applied" must not be a field a caller
/// can forget to read. A caller cannot reach
/// [`WaiveApplied::released_artifact_ids`] without having handled
/// [`Self::Aborted`] first, which makes the all-or-nothing contract the
/// compiler's business rather than a reviewer's.
#[derive(Debug)]
pub enum WaiveOutcome {
    /// Every entry pre-validated. The appends below were attempted,
    /// sequentially — appends across N artifact streams are not one
    /// transaction, so this half is reported honestly rather than
    /// claimed atomic.
    Applied(WaiveApplied),
    /// At least one entry was unresolvable, ambiguous, or in a state this
    /// surface does not reach. **Zero events were appended and zero
    /// artifacts released** — the whole batch aborts, because a batch
    /// that releases the resolvable subset and reports the rest is the
    /// defect this contract exists to prevent, not a kindness. 409 at the
    /// HTTP edge (ADR 0025).
    Aborted {
        /// Every entry of the call, in the order the caller wrote them.
        entries: Vec<WaiveEntryReport>,
    },
}

/// Result envelope for [`CurationUseCase::reevaluate`].
///
/// `outcome` is the domain derivation's verdict; `previous_status` is
/// always [`QuarantineStatus::Rejected`] (the source-state guard admits
/// nothing else) and `new_status` is the artifact's status after the
/// call — `Rejected` again on `StillRejected`, else `Quarantined` /
/// `Released`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReevaluateOutcome {
    pub outcome: ReEvaluationOutcome,
    pub previous_status: QuarantineStatus,
    pub new_status: QuarantineStatus,
}

/// Application use case for curator decisions on artifacts and
/// finding-exclusions. See module docs.
pub struct CurationUseCase {
    events: Arc<EventStorePublisher>,
    artifacts: Arc<dyn ArtifactRepository>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    /// Active-policy + exclusion-set resolution for [`Self::reevaluate`],
    /// and per-row deadline resolution for `list_queue`.
    policies: Arc<dyn PolicyProjectionRepository>,
    /// Queue listing port.
    queue_repo: Arc<dyn CurationQueueRepository>,
    /// Decisions listing port.
    decisions_repo: Arc<dyn CurationDecisionsRepository>,
    /// Active-exclusions listing port.
    exclusions_repo: Arc<dyn CurationExclusionsRepository>,
    /// Repository-key resolution
    /// for the `hort_curation_decisions_total{repository}` label. Uses
    /// the existing `metric_label(repository_id)` helper which already
    /// handles the `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse
    /// to `_all` and the resolve-failure fallback to `unknown`. No new
    /// port; the use case threads through the existing read path.
    /// Also resolves the repository format for
    /// [`release_clearance::resolve_curation_clearance`] inside
    /// [`Self::reevaluate`].
    repository_access: Arc<RepositoryAccessUseCase>,
    /// Live curation rules for [`Self::reevaluate`]'s cross-axis
    /// release-clearance check (ADR 0041 invariant #6(c)).
    curation_rules: Arc<dyn CurationRuleRepository>,
    /// `ScanCompleted` summary + per-finding-row hydration for
    /// [`Self::reevaluate`] (shared with the policy-mutation pass via
    /// [`rejected_reevaluation::derive_rejected_outcome`]).
    storage: Arc<dyn StoragePort>,
    /// Compiled-in format handlers, keyed by format string — the same
    /// registry the scan orchestrator and the policy re-evaluation pass
    /// hold, wired from the same composition-root map.
    ///
    /// [`Self::reevaluate`] needs the artifact's
    /// [`ArtifactKind`](hort_domain::types::ArtifactKind) because it is
    /// the role half of ADR 0064 D2's line and therefore an input to the
    /// verdict it re-derives. A *constructor* dependency and not an
    /// optional one, for the reason `PolicyUseCase`'s copy is: "no
    /// handler, therefore `Other`" must be the registry's answer about a
    /// format, never this use case's answer about a missing dependency.
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
    /// Optional invalidator for cached
    /// upstream packument / simple-index entries on `ArtifactRejected`.
    /// `None` keeps the use case constructable without the dependency
    /// (most test harnesses); production wires it via
    /// [`Self::with_upstream_index_cache_invalidator`]. When `None`,
    /// the post-`block_one` hook is a no-op — the
    /// `NonServableStatusFilter` on the next index build is
    /// the load-bearing close, so a missing invalidator merely keeps
    /// the freshness window at TTL. Builder-
    /// shaped exactly like `with_federated_jwt_validator` /
    /// `with_lint_config` on `ApplyConfigUseCase` so the constructor
    /// signature stays unchanged (no port-contract churn).
    upstream_index_cache_invalidator: Option<Arc<dyn UpstreamIndexCacheInvalidator>>,
}

impl CurationUseCase {
    /// Construct a fully-wired `CurationUseCase`. Mirrors
    /// `QuarantineUseCase::new`'s port-only construction (no concrete
    /// adapters, no `sqlx::PgPool`, no `reqwest::Client`).
    ///
    /// All 11 fields are wired at construction time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        events: Arc<EventStorePublisher>,
        artifacts: Arc<dyn ArtifactRepository>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        policies: Arc<dyn PolicyProjectionRepository>,
        queue_repo: Arc<dyn CurationQueueRepository>,
        decisions_repo: Arc<dyn CurationDecisionsRepository>,
        exclusions_repo: Arc<dyn CurationExclusionsRepository>,
        repository_access: Arc<RepositoryAccessUseCase>,
        curation_rules: Arc<dyn CurationRuleRepository>,
        storage: Arc<dyn StoragePort>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> Self {
        Self {
            events,
            artifacts,
            lifecycle,
            policies,
            queue_repo,
            decisions_repo,
            exclusions_repo,
            repository_access,
            curation_rules,
            storage,
            handlers,
            upstream_index_cache_invalidator: None,
        }
    }

    /// Install the upstream packument /
    /// simple-index cache invalidator. Called from the composition
    /// root after [`Self::new`]; without it, the post-`block_one`
    /// cache-invalidation hook is a no-op (TTL-only
    /// freshness posture). Builder-shaped exactly like
    /// `ApplyConfigUseCase::with_federated_jwt_validator` so the
    /// constructor signature stays byte-unchanged.
    #[must_use]
    pub fn with_upstream_index_cache_invalidator(
        mut self,
        invalidator: Arc<dyn UpstreamIndexCacheInvalidator>,
    ) -> Self {
        self.upstream_index_cache_invalidator = Some(invalidator);
        self
    }

    /// Validate justification — non-empty, ≤512 bytes. Mirrors the
    /// boundary check the HTTP layer performs
    /// (`handlers::admin::curation::MAX_JUSTIFICATION_BYTES`); this
    /// helper is the use-case-side gate so a `CurationUseCase` consumer
    /// (CLI, HTTP, or future SDK) gets the same validation, and it is
    /// the one cap on the manual release — there is no second constant
    /// for the same rule.
    fn validate_justification(justification: &str) -> AppResult<()> {
        if justification.is_empty() {
            return Err(AppError::Domain(DomainError::Validation(
                "justification must be non-empty".into(),
            )));
        }
        if justification.len() > MAX_JUSTIFICATION_BYTES {
            return Err(AppError::Domain(DomainError::Validation(format!(
                "justification {} bytes exceeds {} byte cap",
                justification.len(),
                MAX_JUSTIFICATION_BYTES,
            ))));
        }
        Ok(())
    }

    /// Paginated read-only listing of curator-actionable artifacts.
    /// One row per artifact currently in
    /// `Quarantined` / `Rejected` / `ScanIndeterminate` (the
    /// curator-actionable set), with per-row quarantine deadline
    /// resolved at query time and a rejection-reason discriminator
    /// for rejected rows.
    ///
    /// Authority: `Permission::Curate` OR `Permission::Admin`
    /// (same authority as `waive` / `block`). Denial is
    /// `info!` (architect rule — not `err`).
    ///
    /// **Per-row deadline.** The adapter resolves
    /// `effective_quarantine_deadline(window_start, duration)` per
    /// row in SQL via a join to `policy_projections`;
    /// the use case does NOT pre-resolve a duration parameter. This
    /// preserves both the `limit` cap (single query) and the
    /// cross-repo result set (variable durations).
    ///
    /// **Rejection reason** is extracted by the adapter via a
    /// LATERAL JOIN against the artifact's latest `ArtifactRejected`
    /// event (bounded by `limit` × one indexed event-store lookup;
    /// queue browsing is operator-driven, low QPS).
    ///
    /// **No metric emission** — queue listings are operator-paced reads;
    /// `hort_curation_decisions_total` covers decisions, not reads.
    /// A queue-listing-specific metric is not implemented.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn list_queue(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        filter: CurationQueueFilter,
    ) -> AppResult<Vec<CurationQueueEntry>> {
        // 1) Privilege gate. Denial is `info!` (architect rule — not
        //    `err`); audit-log the attempt then propagate.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_repository_id = ?filter.repository_id,
                filter_status = ?filter.status,
                filter_rejection_reason_kind = ?filter.rejection_reason_kind,
                outcome = "denied",
                "curation queue list denied: missing curate/admin"
            );
            return Err(e);
        }

        // 2) Validate the limit BEFORE calling the repo. `limit >
        //    MAX_QUEUE_LIMIT` is a caller-input issue, not a system
        //    error — Validation.
        if filter.limit > MAX_QUEUE_LIMIT {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_limit = filter.limit,
                max_limit = MAX_QUEUE_LIMIT,
                outcome = "invalid",
                "curation queue list rejected: limit exceeds maximum"
            );
            return Err(AppError::Domain(DomainError::Validation(format!(
                "limit {n} exceeds maximum {MAX_QUEUE_LIMIT}",
                n = filter.limit
            ))));
        }

        // 3) Port call. Errors propagate as `AppError::Domain`.
        let filter_repository_id = filter.repository_id;
        let entries = self
            .queue_repo
            .list_queue(filter)
            .await
            .map_err(AppError::Domain)?;

        // 4) Success-side audit log — security-relevant read of the
        //    curator surface (per architect Observability rules).
        tracing::info!(
            actor_id = %actor.user_id,
            result_count = entries.len(),
            filter_repository_id = ?filter_repository_id,
            outcome = "ok",
            "curator queried curation queue surface"
        );

        Ok(entries)
    }

    /// Paginated event-log scan of curator decisions. One
    /// row per event — `--by-correlation` collapse is an HTTP/CLI
    /// rendering concern, NOT a port-level flag.
    ///
    /// Authority: `Permission::Curate` OR `Permission::Admin`
    /// (same gate as `list_queue`). Denial is `info!` (architect
    /// rule — not `err`).
    ///
    /// **Filter pass-through.** The use case validates the privilege
    /// + the `limit` boundary and forwards the filter to the port
    /// verbatim. The adapter applies the per-event-type curator-actor
    /// discriminator (payload-side for `ArtifactReleased` /
    /// `ArtifactRejected`; envelope-side for `ExclusionAdded` /
    /// `ExclusionRemoved` — those payloads carry no actor field, so
    /// `actor_type = 'api' AND actor_id IS NOT NULL` rides the events
    /// envelope columns instead). `--since` + `--limit` are
    /// SQL-applied; `--repository` + `--package` join through to
    /// `artifacts` for waive/block rows and are no-ops for
    /// exclude/unexclude (those are policy-keyed, not artifact-keyed).
    ///
    /// **`#[instrument]` WITHOUT `err`** — privilege denial is the
    /// security-relevant signal and rides the explicit `info!` denied
    /// path; `err` would surface every Forbidden/Validation as ERROR.
    /// Mirrors `list_queue` shape.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn list_decisions(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        filter: CurationDecisionFilter,
    ) -> AppResult<Vec<CurationDecisionEntry>> {
        // 1) Privilege gate. Denial is `info!` (architect rule — not
        //    `err`); audit-log the attempt then propagate.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_kind = ?filter.kind,
                filter_actor_id = ?filter.actor_id,
                filter_repository_id = ?filter.repository_id,
                outcome = "denied",
                "curation decisions list denied: missing curate/admin"
            );
            return Err(e);
        }

        // 2) Validate the limit BEFORE calling the repo. `limit >
        //    MAX_QUEUE_LIMIT` is a caller-input issue (limit capped at
        //    500), not a system error — Validation.
        //
        //    Reuses MAX_QUEUE_LIMIT — the same cap applies to
        //    queue / decisions / exclusions listings (bounded
        //    per-call work).
        if filter.limit > MAX_QUEUE_LIMIT {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_limit = filter.limit,
                max_limit = MAX_QUEUE_LIMIT,
                outcome = "invalid",
                "curation decisions list rejected: limit exceeds maximum"
            );
            return Err(AppError::Domain(DomainError::Validation(format!(
                "limit {n} exceeds maximum {MAX_QUEUE_LIMIT}",
                n = filter.limit
            ))));
        }

        // 3) Port call. Errors propagate as `AppError::Domain`.
        let filter_kind = filter.kind;
        let filter_actor_id = filter.actor_id;
        let filter_repository_id = filter.repository_id;
        let entries = self
            .decisions_repo
            .list_decisions(filter)
            .await
            .map_err(AppError::Domain)?;

        // 4) Success-side audit log — security-relevant read of the
        //    curator decision history (per architect Observability
        //    rules). Mirrors `list_queue` shape; does NOT include
        //    per-decision identifiers (forbidden labels on metrics
        //    apply here too).
        tracing::info!(
            actor_id = %actor.user_id,
            result_count = entries.len(),
            filter_kind = ?filter_kind,
            filter_actor_id = ?filter_actor_id,
            filter_repository_id = ?filter_repository_id,
            outcome = "ok",
            "curator queried curation decisions surface"
        );

        Ok(entries)
    }

    /// Paginated current-state listing of active CVE exclusions.
    /// Distinct from `list_decisions` because exclusions have
    /// **ongoing state** (active until removed or expired); decisions
    /// are point-in-time. Reuses the existing `exclusion_projections`
    /// table — no new projection.
    ///
    /// Authority: `Permission::Curate` OR `Permission::Admin`
    /// (same gate as `list_queue` / `list_decisions`). Denial
    /// is `info!` (architect rule — not `err`).
    ///
    /// **Filter pass-through.** The use case validates the privilege
    /// + the `limit` boundary and forwards the filter to the port
    /// verbatim. The adapter enforces SQL-level filtering. `actor_id`
    /// matches against the `added_by_actor_id` column populated by
    /// the `ExclusionAdded` projector (envelope-side — `actor_type =
    /// 'api'` carries the user_id; non-api envelopes leave the
    /// column NULL and never match this filter).
    ///
    /// **`#[instrument]` WITHOUT `err`** — privilege denial is the
    /// security-relevant signal and rides the explicit `info!` denied
    /// path; `err` would surface every Forbidden/Validation as ERROR.
    /// Mirrors `list_queue` / `list_decisions` shape.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn list_exclusions(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        filter: CurationExclusionFilter,
    ) -> AppResult<Vec<CurationExclusionEntry>> {
        // 1) Privilege gate. Denial is `info!` (architect rule — not
        //    `err`); audit-log the attempt then propagate.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_policy_id = ?filter.policy_id,
                filter_cve_id = ?filter.cve_id,
                filter_actor_id = ?filter.actor_id,
                outcome = "denied",
                "curation exclusions list denied: missing curate/admin"
            );
            return Err(e);
        }

        // 2) Validate the limit BEFORE calling the repo. Mirrors
        //    `list_queue` / `list_decisions`; the
        //    listings are capped at 500 (bounded
        //    per-call work).
        if filter.limit > MAX_QUEUE_LIMIT {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_limit = filter.limit,
                max_limit = MAX_QUEUE_LIMIT,
                outcome = "invalid",
                "curation exclusions list rejected: limit exceeds maximum"
            );
            return Err(AppError::Domain(DomainError::Validation(format!(
                "limit {n} exceeds maximum {MAX_QUEUE_LIMIT}",
                n = filter.limit
            ))));
        }

        // 3) Port call. Errors propagate as `AppError::Domain`.
        let filter_policy_id = filter.policy_id;
        let filter_cve_id = filter.cve_id.clone();
        let filter_actor_id = filter.actor_id;
        let entries = self
            .exclusions_repo
            .list_exclusions(filter)
            .await
            .map_err(AppError::Domain)?;

        // 4) Success-side audit log — security-relevant read of the
        //    active-exclusions surface (architect Observability
        //    rules). Mirrors `list_decisions` shape; does NOT include
        //    per-exclusion identifiers (forbidden labels on metrics
        //    apply here too).
        tracing::info!(
            actor_id = %actor.user_id,
            result_count = entries.len(),
            filter_policy_id = ?filter_policy_id,
            filter_cve_id = ?filter_cve_id,
            filter_actor_id = ?filter_actor_id,
            outcome = "ok",
            "curator queried active exclusions surface"
        );

        Ok(entries)
    }

    /// Curator-driven manual release of a held artifact.
    ///
    /// **The** manual release — there is no second surface for it. It
    /// reaches `Quarantined` and `ScanIndeterminate`: the curator
    /// holds the domain's authority, so a curator who may override
    /// findings a policy weighed may also clear a stuck scanner, where no
    /// verdict was reached at all (ADR 0007, "One authority owns the
    /// manual release"). `Artifact::release` is the guard; every other
    /// state answers 409 (ADR 0025).
    ///
    /// It also reaches **`Rejected`**, on the axes the curator's
    /// instrument reaches — scan, curation and provenance, never the
    /// corruption tombstone (ADR 0007, "The axis boundary for a
    /// `Rejected` artifact"). The axis verdict is
    /// `hort_domain::entities::artifact::is_curator_overridable`, a
    /// sibling of `is_scan_clearable` rather than a widening of it, so an
    /// unattended policy re-evaluation still cannot clear a curator's own
    /// block (ADR 0041 invariant #6(a)). A refused axis answers 409 with
    /// the axis named in the message.
    ///
    /// `Artifact::release` reads the axis off `Artifact::rejection_reason`,
    /// which the projection row does **not** persist (the Postgres mapper
    /// hydrates it `None`) — so this method re-derives it from the latest
    /// `ArtifactRejected` on the artifact's stream before calling in,
    /// exactly as the re-evaluation path does for the same field and the
    /// same reason. The derivation is read off the SAME stream read that
    /// fixed the `ExpectedVersion` this call's append carries, so a verdict
    /// committed since the pairing fails the append rather than being
    /// overridden on a stale reason; and it insists on a complete stream
    /// (`ArtifactAtVersion::evidence`), because a reverse scan over a
    /// truncated prefix would answer about the *oldest* rejection — a
    /// corruption tombstone that scrolled out of the window would read as
    /// the scan rejection that preceded it.
    ///
    /// Audit: emits `ArtifactReleased { authority: CuratorWaiver,
    /// released_by_user_id: Some(actor.user_id), justification:
    /// Some(_), reason: Curator, … }`.
    ///
    /// Metrics, on success: one
    /// `hort_curation_decisions_total{decision=waive, repository, result=ok}`
    /// tick (the decision) AND one
    /// `hort_quarantine_released_total{reason=curator}` tick (the
    /// release). Failure branches emit only the decision counter.
    #[tracing::instrument(skip(self, privileges, justification))]
    pub async fn waive(
        &self,
        artifact_id: Uuid,
        actor: ApiActor,
        privileges: CallerPrivileges,
        justification: String,
    ) -> AppResult<()> {
        // 1) Privilege gate. Denial is `info!` (architect rule — not
        //    `err`); emit `denied` metric then propagate.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                outcome = "denied",
                "curation waive denied: missing curate/admin"
            );
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                None,
                CurationDecisionResult::Denied,
            );
            return Err(e);
        }

        // 2) Justification cap — fail fast BEFORE any event-store
        //    interaction ("the same justification text rides every
        //    event the call emits, so an oversize justification fails
        //    the call fast").
        if let Err(e) = Self::validate_justification(&justification) {
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                justification_len = justification.len(),
                outcome = "invalid",
                "curation waive rejected: justification invalid"
            );
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(e);
        }

        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();
        let user_id = actor.user_id;

        let mut paired = match ArtifactAtVersion::load(
            &*self.artifacts,
            &*self.events,
            artifact_id,
            OverCapStream::Tolerate,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(CurationDecisionLabel::Waive, None, result);
                return Err(e);
            }
        };
        let expected_version = paired.expected_version();
        let prior_status = paired.artifact().quarantine_status;
        let repository_id = paired.artifact().repository_id;
        // Resolve `repository_id → key` for the
        // metric label using the existing `RepositoryAccessUseCase`
        // helper. The helper handles the `METRICS_INCLUDE_REPOSITORY_LABEL`
        // collapse to `_all` and the resolve-failure fallback to
        // `unknown`. Single bounded query — no N+1 (one artifact per
        // `waive` call).
        let repo_label = self.repository_access.metric_label(repository_id).await;

        // One `ArtifactReleased`. Repeatable: a waived artifact is
        // re-holdable by a rescan verdict or a retroactive curation rule
        // and waivable again, so this verb runs an unbounded number of
        // times over one artifact's life and carries the refusal rather
        // than relying on the version check, which admits an append that
        // starts exactly on the cap.
        if let Err(e) = refuse_append_past_cap(paired.stream_id(), paired.stream_len(), 1) {
            let result = classify_append_error(&e);
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %user_id,
                outcome = result.as_str(),
                "curation waive rejected: the artifact's stream has no room for the \
                 ArtifactReleased this waiver would append"
            );
            emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
            return Err(e);
        }

        // 3) Re-hydrate the rejection reason for a `Rejected` artifact —
        //    the axis `Artifact::release` decides the override on. The
        //    projection row does not carry the column (the Postgres
        //    mapper hydrates it `None`), so an un-hydrated entity would
        //    read as the illegal reason-less rejection and refuse every
        //    override. Only for `Rejected`: it is the one source state
        //    whose verdict depends on it, and `evidence()` refuses an
        //    over-cap stream, which the ordinary `Quarantined` waive has
        //    no reason to be exposed to.
        if prior_status == QuarantineStatus::Rejected {
            let reason = match paired.evidence() {
                Ok(stream) => scan_history::last_rejection_reason(stream),
                Err(e) => {
                    let result = classify_append_error(&e);
                    tracing::info!(
                        artifact_id = %artifact_id,
                        actor_id = %user_id,
                        outcome = result.as_str(),
                        "curation waive rejected: the artifact's stream cannot be read to \
                         its tail, so the rejection axis the override is decided on cannot \
                         be established"
                    );
                    emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
                    return Err(e);
                }
            };
            paired.artifact_mut().rejection_reason = reason;
        }

        // 4) Domain transition. The source-state guard inside
        //    `Artifact::release` accepts `Quarantined`,
        //    `ScanIndeterminate` and `Rejected` (the last one for this
        //    pairing alone, and only on an overridable axis) and refuses
        //    every other state. The deny-by-default release predicate
        //    (ADR 0007) accepts only `(Curator, CuratorWaiver)` for this
        //    authority.
        let mut event_payload = match paired.artifact_mut().release(
            ReleaseReason::Curator,
            ReleaseAuthorization::CuratorWaiver,
            // Curator waivers ignore the
            // provenance param (explicit overrides are unaffected); the
            // real per-candidate clearance computation lives in the
            // release-gate sweep (ADR 0027).
            ProvenanceClearance::NotRequired,
        ) {
            Ok(p) => p,
            Err(e) => {
                let app_err = AppError::Domain(e);
                let result = classify_append_error(&app_err);
                tracing::info!(
                    artifact_id = %artifact_id,
                    actor_id = %user_id,
                    outcome = result.as_str(),
                    "curation waive rejected by domain"
                );
                emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
                return Err(app_err);
            }
        };
        // Populate attribution. The
        // skeleton from `Artifact::release` has both fields `None`;
        // the variant invariant for `CuratorWaiver` requires both
        // `Some(_)`.
        event_payload.released_by_user_id = Some(user_id);
        event_payload.justification = Some(justification);

        let score_delta = RepoSecurityScoreProjector::compute_released_delta(prior_status);
        let artifact = paired.into_artifact();

        if let Err(e) = self
            .lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactReleased(
                        event_payload,
                    ))],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor),
                },
                None, // waive does not overwrite ingest metadata
                Some((repository_id, score_delta)),
            )
            .await
        {
            let app_err = AppError::Domain(e);
            let result = classify_append_error(&app_err);
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %user_id,
                outcome = result.as_str(),
                "curation waive append failed"
            );
            emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
            return Err(app_err);
        }

        emit_curation_decision(
            CurationDecisionLabel::Waive,
            Some(&repo_label),
            CurationDecisionResult::Ok,
        );
        // Both counters fire, because they answer different questions.
        // `hort_curation_decisions_total` counts curator *decisions*
        // (waive / block / exclude / unexclude, including the ones that
        // release nothing); `hort_quarantine_released_total` counts
        // *releases*, whatever authority issued them. This is the only
        // manual release, so it is the only place the `curator` reason
        // can be ticked — a counter named `quarantine_released_total`
        // that misses a release kind is the half-truth an operator
        // builds an alert on. Emitted after the commit: an attempt that
        // never appended must not show up as a release.
        emit_release(values::REASON_CURATOR);

        tracing::info!(
            artifact_id = %artifact_id,
            actor_id = %user_id,
            correlation_id = %correlation_id,
            outcome = "ok",
            "curator waived artifact"
        );
        Ok(())
    }

    /// Curator-invoked recompute of a `Rejected` artifact's verdict from
    /// its stored findings under the currently active policy — no policy
    /// mutation, no forced outcome.
    ///
    /// Source-state guard is `Rejected` ONLY: every other state is a
    /// caller-reachable precondition failure (a curator can POST this
    /// against an artifact in any state) → `DomainError::InvalidState`
    /// (ADR 0025), mirroring `waive`'s single-source-state discipline.
    ///
    /// Delegates the load-and-derive path to
    /// [`rejected_reevaluation::derive_rejected_outcome`] — the same
    /// helper the policy-mutation pass's loosen direction uses, so the
    /// two callers cannot diverge on evidence loading or the domain
    /// derivation. Three terminal, idempotent no-event outcomes fold to
    /// [`ReEvaluationOutcome::StillRejected`] in the returned envelope:
    /// the domain derivation says so directly, the rejection reason is
    /// not scan-clearable (ADR 0041 invariant #6(a) — a provenance- /
    /// curation- / admin-rejected artifact is not a scan re-judgement
    /// candidate), or the release arm's cross-axis conjunction
    /// (provenance ∧ curation, invariant #6(b)(c)) does not currently
    /// clear. A curator can safely re-invoke on any of these — no
    /// repeated events, no state churn.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn reevaluate(
        &self,
        artifact_id: Uuid,
        actor: ApiActor,
        privileges: CallerPrivileges,
    ) -> AppResult<ReevaluateOutcome> {
        // 1) Privilege gate.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                outcome = "denied",
                "curation reevaluate denied: missing curate/admin"
            );
            emit_curation_decision(
                CurationDecisionLabel::Reevaluate,
                None,
                CurationDecisionResult::Denied,
            );
            return Err(e);
        }

        let mut paired = match ArtifactAtVersion::load(
            &*self.artifacts,
            &*self.events,
            artifact_id,
            OverCapStream::Tolerate,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(CurationDecisionLabel::Reevaluate, None, result);
                return Err(e);
            }
        };
        let repository_id = paired.artifact().repository_id;
        let repo_label = self.repository_access.metric_label(repository_id).await;

        // 2) Source-state guard — Rejected only (ADR 0025: a
        //    caller-reachable state precondition is InvalidState/409,
        //    never an opaque 500).
        if paired.artifact().quarantine_status != QuarantineStatus::Rejected {
            let app_err = AppError::Domain(DomainError::InvalidState(format!(
                "cannot re-evaluate artifact in state {}",
                paired.artifact().quarantine_status
            )));
            let result = classify_append_error(&app_err);
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                status = %paired.artifact().quarantine_status,
                outcome = result.as_str(),
                "curation reevaluate rejected: source-state guard"
            );
            emit_curation_decision(CurationDecisionLabel::Reevaluate, Some(&repo_label), result);
            return Err(app_err);
        }

        // 3) Resolve the active policy + its exclusion set — the SAME
        //    resolution the ingest/scan/timer-release paths use. An
        //    absent policy is not an error (`decide_rejected_transition`
        //    falls back to `DefaultPolicy::block_on_critical`).
        let policy = match resolve_active_policy_for_repo(&*self.policies, repository_id).await {
            Ok(p) => p,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    result,
                );
                return Err(e);
            }
        };
        let exclusions = match &policy {
            Some(p) => match self.policies.list_exclusions_for_policy(p.policy_id).await {
                Ok(list) => list,
                Err(e) => {
                    let app_err = AppError::Domain(e);
                    let result = classify_append_error(&app_err);
                    emit_curation_decision(
                        CurationDecisionLabel::Reevaluate,
                        Some(&repo_label),
                        result,
                    );
                    return Err(app_err);
                }
            },
            None => Vec::new(),
        };

        // 4) Load evidence + derive the verdict — shared path.
        //
        // The role half of ADR 0064 D2's line, resolved through the same
        // registry the scan run uses. An absent repository row resolves to
        // `Generic` (no handler, therefore `ArtifactKind::Other`), matching
        // `resolve_curation_clearance`'s treatment of the same read.
        let now = Utc::now();
        let kind = match self
            .repository_access
            .repository_format(repository_id)
            .await
        {
            Ok(f) => {
                let format =
                    f.unwrap_or(hort_domain::entities::repository::RepositoryFormat::Generic);
                scan_kind_of(&self.handlers, &format.to_string(), paired.artifact())
            }
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    result,
                );
                return Err(e);
            }
        };
        let derivation = match rejected_reevaluation::derive_rejected_outcome(
            &paired,
            &self.storage,
            policy.as_ref(),
            &exclusions,
            kind,
            // **Resolved, not pinned** (ADR 0064 D6). A curator asked for
            // this one artifact to be judged again, which is the
            // operator-driven recovery D6 reserves the already-rejected
            // estate to: "recovering the existing estate is
            // operator-driven, through the curation re-evaluation". The
            // automatic policy-mutation pass pins
            // `CompositeVerdictMode::Observed` instead, so nothing
            // releases that population without someone asking.
            composite_verdict_mode_of(policy.as_ref()),
            now,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    result,
                );
                return Err(e);
            }
        };

        let still_rejected_noop = || ReevaluateOutcome {
            outcome: ReEvaluationOutcome::StillRejected,
            previous_status: QuarantineStatus::Rejected,
            new_status: QuarantineStatus::Rejected,
        };

        let (outcome, quarantine_deadline, reason, derived_provenance) = match derivation {
            // Not scan-clearable: the verdict, from a scan-evidence
            // perspective, is unchanged. No event; no state churn.
            rejected_reevaluation::RejectedDerivation::Ineligible { reason } => {
                tracing::info!(
                    artifact_id = %artifact_id,
                    actor_id = %actor.user_id,
                    reason = ?reason,
                    outcome = "ineligible_non_scanner",
                    "curator reevaluate: rejection reason is not scan-clearable \
                     (ADR 0041 invariant #6); artifact stays Rejected"
                );
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    CurationDecisionResult::Ok,
                );
                return Ok(still_rejected_noop());
            }
            rejected_reevaluation::RejectedDerivation::NoScanCompleted => {
                let app_err = AppError::Domain(DomainError::Invariant(format!(
                    "no ScanCompleted event found for artifact {artifact_id}"
                )));
                let result = classify_append_error(&app_err);
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    result,
                );
                return Err(app_err);
            }
            rejected_reevaluation::RejectedDerivation::Determined {
                outcome,
                quarantine_deadline,
                rejection_reason,
                provenance,
            } => (outcome, quarantine_deadline, rejection_reason, provenance),
        };

        if matches!(outcome, ReEvaluationOutcome::StillRejected) {
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                outcome = "still_rejected",
                "curator reevaluate: verdict unchanged"
            );
            emit_curation_decision(
                CurationDecisionLabel::Reevaluate,
                Some(&repo_label),
                CurationDecisionResult::Ok,
            );
            return Ok(still_rejected_noop());
        }

        paired.artifact_mut().rejection_reason = reason;
        // Hydrate the transient computed deadline so `Artifact::re_evaluate`
        // below branches on the same computed deadline the pure helper
        // decided against — the two MUST agree on boundary semantics.
        paired.artifact_mut().quarantine_deadline = quarantine_deadline;

        // 5) Resolve the cross-axis release clearances. The CURATION
        //    conjunct is resolved on both arms, because `re_evaluate`
        //    gates both on it: a re-quarantine hands the artifact to the
        //    timer sweep, which reads provenance and has no curation
        //    input, and the retroactive curation pass walks only the
        //    active population — so a curation question deferred past the
        //    re-quarantine is never asked again. The PROVENANCE conjunct
        //    is the release arm's alone, for the mirror-image reason: the
        //    timer release re-applies it. Mirrors the policy-mutation
        //    pass.
        //
        //    Resolved once, above the arm split, because both arms need
        //    it; the `StillRejected` outcome returned earlier and never
        //    reaches here.
        let curation = match resolve_curation_clearance(
            &*self.curation_rules,
            &self.repository_access,
            paired.artifact(),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    result,
                );
                return Err(e);
            }
        };
        if !matches!(curation, CurationClearance::Cleared) {
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                curation = ?curation,
                outcome = "held_cross_axis",
                "curator reevaluate: an active curation rule blocks the artifact, so \
                 neither a release nor a re-quarantine may proceed (ADR 0041 \
                 invariant #6); artifact stays Rejected"
            );
            emit_curation_decision(
                CurationDecisionLabel::Reevaluate,
                Some(&repo_label),
                CurationDecisionResult::Ok,
            );
            return Ok(still_rejected_noop());
        }
        let provenance = if matches!(outcome, ReEvaluationOutcome::ResetToReleased) {
            // The provenance leg came out of the derivation above, off the
            // SAME stream read the append's version came from. Resolving
            // it here from a second read would let a `ProvenanceVerified`
            // that landed after the pairing clear the gate while the
            // append still carried the pre-verification version.
            let provenance = derived_provenance;
            let provenance_clears = matches!(
                provenance,
                ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
            );
            if !provenance_clears {
                tracing::info!(
                    artifact_id = %artifact_id,
                    actor_id = %actor.user_id,
                    provenance = ?provenance,
                    outcome = "held_cross_axis",
                    "curator reevaluate: scan passes but provenance does not currently \
                     clear (ADR 0041 invariant #6); artifact stays Rejected"
                );
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    CurationDecisionResult::Ok,
                );
                return Ok(still_rejected_noop());
            }
            provenance
        } else {
            // Not read on the re-quarantine arm: the timer release it
            // defers to applies the provenance gate itself.
            ProvenanceClearance::NotRequired
        };

        // 6) Commit: `Artifact::re_evaluate` re-derives the same
        //    eligibility + boundary decision as a defence-in-depth
        //    re-check and produces the companion transition event.
        let stream_id = paired.stream_id().clone();
        let expected_version = paired.expected_version();

        // `ArtifactReEvaluated` plus the companion transition — two
        // events, which is why the batch size and not one is what the
        // cap is asked about: a stream one short of the cap has room for
        // the audit event and not for the transition it explains.
        // Repeatable: the curator may re-evaluate the same artifact on
        // every policy or exclusion change.
        if let Err(e) = refuse_append_past_cap(&stream_id, paired.stream_len(), 2) {
            let result = classify_append_error(&e);
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                outcome = result.as_str(),
                "curator reevaluate rejected: the artifact's stream has no room for the \
                 re-evaluation pair this would append"
            );
            emit_curation_decision(CurationDecisionLabel::Reevaluate, Some(&repo_label), result);
            return Err(e);
        }

        let previous_status = paired.artifact().quarantine_status;
        let companion_event = match paired.artifact_mut().re_evaluate(now, provenance, curation) {
            Ok(ev) => ev,
            Err(e) => {
                let app_err = AppError::Domain(e);
                let result = classify_append_error(&app_err);
                tracing::info!(
                    artifact_id = %artifact_id,
                    actor_id = %actor.user_id,
                    outcome = result.as_str(),
                    "curator reevaluate rejected by domain re-check"
                );
                emit_curation_decision(
                    CurationDecisionLabel::Reevaluate,
                    Some(&repo_label),
                    result,
                );
                return Err(app_err);
            }
        };
        let new_status = paired.artifact().quarantine_status;
        let artifact = paired.into_artifact();

        let re_evaluated = ArtifactReEvaluated {
            artifact_id,
            policy_id: policy.as_ref().map(|p| p.policy_id).unwrap_or(NO_POLICY),
            trigger: ReEvaluationTrigger::CuratorRequested,
            previous_status,
            new_status,
        };
        let score_delta =
            RepoSecurityScoreProjector::compute_re_evaluated_delta(previous_status, new_status);
        let correlation_id = Uuid::new_v4();

        if let Err(e) = self
            .lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![
                        EventToAppend::new(DomainEvent::ArtifactReEvaluated(re_evaluated)),
                        EventToAppend::new(companion_event),
                    ],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor.clone()),
                },
                None,
                Some((repository_id, score_delta)),
            )
            .await
        {
            let app_err = AppError::Domain(e);
            let result = classify_append_error(&app_err);
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                outcome = result.as_str(),
                "curator reevaluate append failed"
            );
            emit_curation_decision(CurationDecisionLabel::Reevaluate, Some(&repo_label), result);
            return Err(app_err);
        }

        emit_curation_decision(
            CurationDecisionLabel::Reevaluate,
            Some(&repo_label),
            CurationDecisionResult::Ok,
        );
        tracing::info!(
            artifact_id = %artifact_id,
            actor_id = %actor.user_id,
            correlation_id = %correlation_id,
            previous_status = %previous_status,
            new_status = %new_status,
            outcome = "ok",
            "curator reevaluated rejected artifact"
        );

        Ok(ReevaluateOutcome {
            outcome,
            previous_status,
            new_status,
        })
    }

    /// Curator-driven block — transitions `None` / `Quarantined` /
    /// `Released` → `Rejected`. Already-`Rejected` is an idempotent
    /// no-op (counted in `BlockOutcome.already_rejected_ids`; no event
    /// appended). Audit: emits `ArtifactRejected { rejected_by:
    /// Curator { curator_id }, reason: <justification> }` per
    /// transitioned artifact.
    ///
    /// **Continue-on-error.** Per-append failures land in
    /// `BlockOutcome.failed`; successful appends are not rolled back.
    /// The justification cap is enforced ONCE at the call boundary.
    #[tracing::instrument(skip(self, privileges, justification))]
    pub async fn block(
        &self,
        target: BlockTarget,
        actor: ApiActor,
        privileges: CallerPrivileges,
        justification: String,
    ) -> AppResult<BlockOutcome> {
        // 1) Privilege gate. Single info! + single denied tick for the
        //    whole call (per-append metric emission is on successful
        //    enter-the-loop; this is pre-loop).
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                outcome = "denied",
                "curation block denied: missing curate/admin"
            );
            emit_curation_decision(
                CurationDecisionLabel::Block,
                None,
                CurationDecisionResult::Denied,
            );
            return Err(e);
        }

        // 2) Justification cap — single boundary check ("same
        //    justification text rides every event the call emits").
        if let Err(e) = Self::validate_justification(&justification) {
            tracing::info!(
                actor_id = %actor.user_id,
                justification_len = justification.len(),
                outcome = "invalid",
                "curation block rejected: justification invalid"
            );
            emit_curation_decision(
                CurationDecisionLabel::Block,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(e);
        }

        let correlation_id = Uuid::new_v4();
        let user_id = actor.user_id;
        let mut outcome = BlockOutcome {
            correlation_id,
            blocked_artifact_ids: Vec::new(),
            already_rejected_ids: Vec::new(),
            not_found_versions: Vec::new(),
            not_found_digests: Vec::new(),
            failed: Vec::new(),
        };

        match target {
            BlockTarget::Artifact(artifact_id) => {
                // Single-artifact target: `find_by_id` IS the resolution
                // step. A miss here is a top-level `Err(NotFound)` —
                // matching `waive`'s shape, so the HTTP handler can map
                // it to 404 without inspecting the envelope.
                // The continue-on-error envelope semantics apply
                // specifically to `BlockTarget::VersionList` where N
                // artifacts share a call; the single-artifact case is
                // N=1 and the operator already knows what they targeted.
                //
                // We pre-flight `find_by_id` here so a miss bubbles as
                // `Err` (instead of being captured into
                // `outcome.failed` by `block_one`). The pre-flight is
                // throw-away — `block_one` re-loads inside its own
                // body to pick up the freshest `quarantine_status` and
                // satisfy the source-state guard. A *race-condition*
                // NotFound inside `block_one` (deleted between
                // pre-flight and append) would still land in
                // `outcome.failed`; that path is unobservable in
                // practice (curated artifacts are never hard-deleted)
                // but the semantics match VersionList's stage-2 race.
                if let Err(e) = self.artifacts.find_by_id(artifact_id).await {
                    let app_err = AppError::Domain(e);
                    let result = classify_append_error(&app_err);
                    // Pre-flight NotFound — no repository_id available;
                    // emit `_all` (`None` collapses to the sentinel at
                    // the helper). `block_one`'s own emit sites resolve
                    // the key once the second `find_by_id` succeeds.
                    emit_curation_decision(CurationDecisionLabel::Block, None, result);
                    tracing::info!(
                        artifact_id = %artifact_id,
                        actor_id = %user_id,
                        correlation_id = %correlation_id,
                        outcome = result.as_str(),
                        "curation block Artifact: resolution failed"
                    );
                    return Err(app_err);
                }
                self.block_one(
                    artifact_id,
                    &actor,
                    user_id,
                    &justification,
                    correlation_id,
                    &mut outcome,
                )
                .await;
            }
            BlockTarget::VersionList {
                repository_id,
                package,
                versions,
            } => {
                self.block_bulk(
                    repository_id,
                    BulkKeys::Versions { package, versions },
                    &actor,
                    user_id,
                    &justification,
                    correlation_id,
                    &mut outcome,
                )
                .await?;
            }
            BlockTarget::DigestList {
                repository_id,
                digests,
            } => {
                self.block_bulk(
                    repository_id,
                    BulkKeys::Digests(digests),
                    &actor,
                    user_id,
                    &justification,
                    correlation_id,
                    &mut outcome,
                )
                .await?;
            }
        }

        let blocked_count = outcome.blocked_artifact_ids.len();
        let already_count = outcome.already_rejected_ids.len();
        let not_found_count = outcome.not_found_versions.len();
        let failed_count = outcome.failed.len();
        tracing::info!(
            actor_id = %user_id,
            correlation_id = %correlation_id,
            blocked_count,
            already_count,
            not_found_count,
            failed_count,
            outcome = "ok",
            "curator block call complete"
        );

        Ok(outcome)
    }

    /// The shared bulk-**block** path: cap, resolve, refuse an
    /// unreadable request, then block each resolved row.
    ///
    /// Both addressing modes run through here, because the cap, the
    /// ambiguity refusal and the per-entry loop are the same question in
    /// either mode. `VersionList`'s contract is unchanged —
    /// continue-on-error, per-append failures in `outcome.failed`,
    /// successful appends never rolled back — and `DigestList` inherits
    /// exactly it, with `not_found_digests` playing `not_found_versions`'
    /// part.
    #[allow(clippy::too_many_arguments)]
    async fn block_bulk(
        &self,
        repository_id: Uuid,
        keys: BulkKeys,
        actor: &ApiActor,
        user_id: Uuid,
        justification: &str,
        correlation_id: Uuid,
        outcome: &mut BlockOutcome,
    ) -> AppResult<()> {
        let mode = keys.mode();
        // Per-call cap: bounded work per call.
        if let Err(e) = Self::validate_bulk_entry_count(&keys, MAX_VERSIONS_PER_CALL) {
            let entry_count = keys.keys().len();
            tracing::info!(
                actor_id = %user_id,
                mode,
                entry_count,
                outcome = "invalid",
                "curation block bulk: entry list rejected"
            );
            emit_curation_decision(
                CurationDecisionLabel::Block,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(e);
        }

        let resolved = match self.resolve_bulk(repository_id, &keys).await {
            Ok(r) => r,
            Err(e) => {
                let result = classify_append_error(&e);
                // One tick for the whole call — resolution failure
                // precedes any per-append iteration. A bulk target
                // carries `repository_id`, so the metric key resolves
                // even when the listing port failed (a different read).
                let repo_label = self.repository_access.metric_label(repository_id).await;
                emit_curation_decision(CurationDecisionLabel::Block, Some(&repo_label), result);
                let outcome = result.as_str();
                tracing::info!(
                    actor_id = %user_id,
                    correlation_id = %correlation_id,
                    mode,
                    outcome,
                    "curation block bulk: resolution failed"
                );
                return Err(e);
            }
        };

        // Reduce — and refuse an ambiguous entry here, before the first
        // append. See `reduce_block_entries` for why ambiguity is not a
        // continue-on-error outcome.
        let reduced = match reduce_block_entries(resolved) {
            Ok(r) => r,
            Err(e) => {
                let result = classify_append_error(&e);
                let repo_label = self.repository_access.metric_label(repository_id).await;
                emit_curation_decision(CurationDecisionLabel::Block, Some(&repo_label), result);
                let outcome = result.as_str();
                tracing::info!(
                    actor_id = %user_id,
                    correlation_id = %correlation_id,
                    mode,
                    outcome,
                    "curation block bulk: ambiguous entry, nothing blocked"
                );
                return Err(e);
            }
        };

        for (key, resolved_id) in reduced {
            match resolved_id {
                // Stage 2: `block_one` re-loads via `find_by_id` to pick
                // up the freshest `quarantine_status` (the resolution
                // read can race the curator). A stage-2 NotFound — the
                // artifact deleted between resolve and append — goes to
                // `outcome.failed` per continue-on-error; the call does
                // not abort the remaining entries.
                Some(artifact_id) => {
                    self.block_one(
                        artifact_id,
                        actor,
                        user_id,
                        justification,
                        correlation_id,
                        outcome,
                    )
                    .await;
                }
                None => match &keys {
                    BulkKeys::Versions { .. } => outcome.not_found_versions.push(key),
                    BulkKeys::Digests(_) => outcome.not_found_digests.push(key),
                },
            }
        }
        Ok(())
    }

    /// Bulk curator waive — **the fail-open half of curation, and the
    /// only verb in this use case that is all-or-nothing.**
    ///
    /// `waive-versions` and `waive-digests` both land here. The contract
    /// deliberately does **not** mirror [`Self::block`]'s, and the
    /// asymmetry is the point: a bulk block is fail-safe, so releasing
    /// the resolvable subset of a list and reporting the rest is a
    /// kindness there and a defect here, because `ArtifactReleased` is
    /// history that cannot be retracted.
    ///
    /// 1. **Cap [`MAX_WAIVE_ENTRIES_PER_CALL`]**, against the block cap
    ///    of [`MAX_VERSIONS_PER_CALL`]. Enforced here, not only at the
    ///    handler, because every other caller of this use case — the
    ///    gitops pipeline this addressing exists for included — reaches
    ///    the cap through this method and not through a route.
    /// 2. **Strict pre-validation, then apply.** Every entry is resolved
    ///    and state-checked before any event is appended. One entry that
    ///    is unresolvable, ambiguous, or in a state
    ///    [`bulk_waive_applicability`] does not reach aborts the whole
    ///    batch: [`WaiveOutcome::Aborted`] carrying a per-entry report,
    ///    zero releases applied, 409 at the edge (ADR 0025).
    /// 3. **`Released` entries are idempotent successes** — reported in
    ///    [`WaiveApplied::already_released_ids`] with no event, mirroring
    ///    block's `already_rejected_ids`. Without that, a gitops re-apply
    ///    of the same decision file would fail forever.
    /// 4. **Apply is sequential and honestly reported.** Appends across N
    ///    artifact streams are not one transaction, so this method does
    ///    not claim they are: a state change inside the validate→apply
    ///    window surfaces through [`Self::waive_one`] per ADR 0060 —
    ///    re-read, already-`Released` ⇒ idempotent success, otherwise the
    ///    entry lands in `failed`.
    /// 5. **One `ArtifactReleased` per released artifact, one shared
    ///    `correlation_id` per call**, each event carrying
    ///    `released_by_user_id` and the justification verbatim.
    ///
    /// Authority is `Permission::Curate` or `Permission::Admin`,
    /// identical to a single [`Self::waive`]: a batch entry's authority
    /// is one waive's authority, and the safety margin is the structural
    /// contract above rather than a permission tier. An Admin gate here
    /// would also collide with ADR 0038 (service accounts are strictly
    /// non-admin) and lock the gitops pipeline out of applying its own
    /// decisions.
    ///
    /// Metrics: `hort_curation_decisions_total{decision=waive}` — one
    /// tick per attempted append, plus one for a pre-loop refusal, same
    /// shape as [`Self::block`]'s. `hort_quarantine_released_total{reason=curator}`
    /// ticks once per artifact actually released.
    #[tracing::instrument(skip(self, privileges, justification))]
    pub async fn waive_bulk(
        &self,
        target: WaiveTarget,
        actor: ApiActor,
        privileges: CallerPrivileges,
        justification: String,
    ) -> AppResult<WaiveOutcome> {
        // 1) Privilege gate. Single info! + single denied tick for the
        //    whole call.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                outcome = "denied",
                "curation bulk waive denied: missing curate/admin"
            );
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                None,
                CurationDecisionResult::Denied,
            );
            return Err(e);
        }

        // 2) Justification cap — one boundary check; the same text rides
        //    every event the call emits, so an oversize justification
        //    fails before any resolution read.
        if let Err(e) = Self::validate_justification(&justification) {
            tracing::info!(
                actor_id = %actor.user_id,
                justification_len = justification.len(),
                outcome = "invalid",
                "curation bulk waive rejected: justification invalid"
            );
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(e);
        }

        let (repository_id, keys) = target.into_keys();
        let mode = keys.mode();
        let user_id = actor.user_id;
        let correlation_id = Uuid::new_v4();

        // 3) Per-call cap — 25, not block's 100.
        if let Err(e) = Self::validate_bulk_entry_count(&keys, MAX_WAIVE_ENTRIES_PER_CALL) {
            tracing::info!(
                actor_id = %user_id,
                mode,
                entry_count = keys.keys().len(),
                outcome = "invalid",
                "curation bulk waive rejected: entry list"
            );
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                None,
                CurationDecisionResult::Invalid,
            );
            return Err(e);
        }

        // 4) Resolve every entry. A malformed digest fails here, before
        //    any row is read and long before any append.
        let resolved = match self.resolve_bulk(repository_id, &keys).await {
            Ok(r) => r,
            Err(e) => {
                let result = classify_append_error(&e);
                let repo_label = self.repository_access.metric_label(repository_id).await;
                emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
                tracing::info!(
                    actor_id = %user_id,
                    correlation_id = %correlation_id,
                    mode,
                    outcome = result.as_str(),
                    "curation bulk waive: resolution failed"
                );
                return Err(e);
            }
        };

        // 5) Pre-validation. Every entry, then the verdict on the batch.
        //    `applicable_row` answers both halves at once, so the apply
        //    loop below receives rows and not verdicts to re-interpret.
        let entries = reduce_waive_entries(resolved);
        let applicable: Vec<(Uuid, bool)> = entries
            .iter()
            .filter_map(WaiveEntryReport::applicable_row)
            .collect();
        if applicable.len() != entries.len() {
            let repo_label = self.repository_access.metric_label(repository_id).await;
            // `conflict` is the label an aborted batch ticks: the refusal
            // is a state precondition (ADR 0025 → 409), which
            // `classify_append_error` already maps to `conflict` for the
            // per-artifact waive's own wrong-state refusal.
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                Some(&repo_label),
                CurationDecisionResult::Conflict,
            );
            tracing::info!(
                actor_id = %user_id,
                correlation_id = %correlation_id,
                mode,
                entry_count = entries.len(),
                blocking_count = entries.len() - applicable.len(),
                outcome = "conflict",
                "curation bulk waive aborted at pre-validation: nothing released"
            );
            return Ok(WaiveOutcome::Aborted { entries });
        }

        // 6) Apply. Sequential, one artifact at a time, deduplicated by
        //    resolved row: two entries spelling one digest two ways name
        //    one artifact and release it once.
        let mut applied = WaiveApplied {
            correlation_id,
            released_artifact_ids: Vec::new(),
            already_released_ids: Vec::new(),
            failed: Vec::new(),
        };
        let mut seen: Vec<Uuid> = Vec::with_capacity(applicable.len());
        for (artifact_id, already_released) in applicable {
            if seen.contains(&artifact_id) {
                continue;
            }
            seen.push(artifact_id);
            if already_released {
                // Idempotent success, decided at pre-validation and not
                // re-read: this entry appends nothing, so there is no
                // decision for a fresher read to protect.
                applied.already_released_ids.push(artifact_id);
                let repo_label = self.repository_access.metric_label(repository_id).await;
                emit_curation_decision(
                    CurationDecisionLabel::Waive,
                    Some(&repo_label),
                    CurationDecisionResult::Ok,
                );
            } else {
                self.waive_one(
                    artifact_id,
                    &actor,
                    &justification,
                    correlation_id,
                    &mut applied,
                )
                .await;
            }
        }

        tracing::info!(
            actor_id = %user_id,
            correlation_id = %correlation_id,
            mode,
            released_count = applied.released_artifact_ids.len(),
            already_count = applied.already_released_ids.len(),
            failed_count = applied.failed.len(),
            outcome = "ok",
            "curator bulk waive call complete"
        );
        Ok(WaiveOutcome::Applied(applied))
    }

    /// Release one pre-validated artifact as part of a bulk waive, and
    /// record the result in `applied`.
    ///
    /// **This is the appending function**, so the stream-cap refusal
    /// lives here rather than one call away: a bulk waive is repeatable
    /// by construction — a released artifact is re-holdable by a rescan
    /// verdict or a retroactive curation rule and waivable again — so
    /// `ONCE-ONLY-APPEND` is not available to it, and the adapter's
    /// version check is not a bound (an append paired exactly at the cap
    /// succeeds and freezes the stream).
    ///
    /// The source-state set is re-checked here against
    /// [`bulk_waive_applicability`] rather than left to
    /// `Artifact::release`'s own guard. That guard is **wider** — it
    /// reaches `ScanIndeterminate` and an overridable `Rejected` — so an
    /// entry that moved inside the validate→apply window would otherwise
    /// be released from a state this surface deliberately does not
    /// reach.
    async fn waive_one(
        &self,
        artifact_id: Uuid,
        actor: &ApiActor,
        justification: &str,
        correlation_id: Uuid,
        applied: &mut WaiveApplied,
    ) {
        let mut paired = match ArtifactAtVersion::load(
            &*self.artifacts,
            &*self.events,
            artifact_id,
            OverCapStream::Tolerate,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(CurationDecisionLabel::Waive, None, result);
                applied.failed.push((artifact_id, e));
                return;
            }
        };
        let expected_version = paired.expected_version();
        let prior_status = paired.artifact().quarantine_status;
        let repository_id = paired.artifact().repository_id;
        let repo_label = self.repository_access.metric_label(repository_id).await;

        let applicability = bulk_waive_applicability(prior_status);
        if applicability == WaiveApplicability::AlreadyTrue {
            // ADR 0060 (b) ahead of the append: the intent is already
            // true, so this is an idempotent success with no event.
            applied.already_released_ids.push(artifact_id);
            emit_curation_decision(
                CurationDecisionLabel::Waive,
                Some(&repo_label),
                CurationDecisionResult::Ok,
            );
            return;
        }

        if let Err(e) = refuse_append_past_cap(paired.stream_id(), paired.stream_len(), 1) {
            let result = classify_append_error(&e);
            let outcome = result.as_str();
            tracing::info!(
                artifact_id = %artifact_id,
                actor_id = %actor.user_id,
                outcome,
                "curation bulk waive entry failed: the artifact's stream has no room for \
                 the ArtifactReleased this waiver would append"
            );
            emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
            applied.failed.push((artifact_id, e));
            return;
        }

        // The narrow source-state refusal and the domain transition are
        // one fallible step, not two: this surface's set and
        // `Artifact::release`'s own guard both have to pass, and the
        // refusal they produce is the same `InvalidState` (ADR 0025) that
        // the entry carries into `failed`. Writing them as one `Result`
        // keeps a single recording path rather than two that could
        // classify or log the same refusal differently.
        let release_attempt = match applicability {
            WaiveApplicability::Release => paired
                .artifact_mut()
                .release(
                    ReleaseReason::Curator,
                    ReleaseAuthorization::CuratorWaiver,
                    // Curator waivers ignore the provenance param,
                    // exactly as the per-artifact waive does: an explicit
                    // override is unaffected, and the real per-candidate
                    // clearance computation lives in the release-gate
                    // sweep (ADR 0027).
                    ProvenanceClearance::NotRequired,
                )
                .map_err(AppError::Domain),
            // The state moved inside the validate→apply window into
            // something this surface does not reach — `Artifact::release`
            // would admit two of those states, and the refusal is here
            // precisely because the bulk set is narrower than the
            // domain's. `AlreadyTrue` already returned above and is
            // grouped in rather than swept under a `_`: a sixth
            // `QuarantineStatus` has to be classified in
            // `bulk_waive_applicability`, where the reasons are, and a
            // wildcard here would let it arrive unclassified.
            WaiveApplicability::AlreadyTrue | WaiveApplicability::OutOfReach => {
                Err(AppError::Domain(DomainError::InvalidState(format!(
                    "cannot bulk-waive artifact in state {prior_status}: the state changed \
                     after this batch was validated, and a bulk waive reaches only a \
                     quarantined artifact"
                ))))
            }
        };
        let mut event_payload = match release_attempt {
            Ok(p) => p,
            Err(app_err) => {
                let result = classify_append_error(&app_err);
                let outcome = result.as_str();
                tracing::info!(
                    artifact_id = %artifact_id,
                    actor_id = %actor.user_id,
                    outcome,
                    "curation bulk waive entry refused: the artifact is no longer in a \
                     state this surface releases from"
                );
                emit_curation_decision(CurationDecisionLabel::Waive, Some(&repo_label), result);
                applied.failed.push((artifact_id, app_err));
                return;
            }
        };
        // The skeleton from `Artifact::release` has both fields `None`;
        // the `CuratorWaiver` variant invariant requires both `Some(_)`.
        // The justification text is stamped verbatim on every event the
        // call emits.
        event_payload.released_by_user_id = Some(actor.user_id);
        event_payload.justification = Some(justification.to_owned());

        let score_delta = RepoSecurityScoreProjector::compute_released_delta(prior_status);
        let stream_id = StreamId::artifact(artifact_id);
        let artifact = paired.into_artifact();

        if let Err(e) = self
            .lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactReleased(
                        event_payload,
                    ))],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor.clone()),
                },
                None, // a waive does not overwrite ingest metadata
                Some((repository_id, score_delta)),
            )
            .await
        {
            let app_err = AppError::Domain(e);
            self.record_bulk_waive_append_failure(artifact_id, app_err, &repo_label, applied)
                .await;
            return;
        }

        applied.released_artifact_ids.push(artifact_id);
        emit_curation_decision(
            CurationDecisionLabel::Waive,
            Some(&repo_label),
            CurationDecisionResult::Ok,
        );
        // Both counters fire, for the reason the per-artifact waive
        // documents: one counts curator *decisions*, the other counts
        // *releases*. Emitted after the commit — an attempt that never
        // appended must not show up as a release.
        emit_release(values::REASON_CURATOR);
    }

    /// ADR 0060's reaction, for one bulk-waive entry whose append lost.
    ///
    /// Steps (a) and (b) only: re-read the artifact, and if the intent is
    /// already true — somebody else released it in the window — report an
    /// idempotent success with no event of our own. Step (c), rebuilding
    /// the batch against the refreshed version and re-appending, is
    /// **deliberately not taken**: whatever committed in that window is
    /// evidence the curator has not reviewed, and re-appending over it
    /// would turn a lost race into a release decided by a stale review.
    /// So the entry lands in `failed` — reported, never silently skipped.
    ///
    /// A non-`Conflict` error is not a lost race and gets no re-read.
    async fn record_bulk_waive_append_failure(
        &self,
        artifact_id: Uuid,
        app_err: AppError,
        repo_label: &str,
        applied: &mut WaiveApplied,
    ) {
        let result = classify_append_error(&app_err);
        if matches!(app_err, AppError::Domain(DomainError::Conflict(_))) {
            match self.artifacts.find_by_id(artifact_id).await {
                Ok(fresh)
                    if bulk_waive_applicability(fresh.quarantine_status)
                        == WaiveApplicability::AlreadyTrue =>
                {
                    tracing::info!(
                        artifact_id = %artifact_id,
                        outcome = "ok",
                        "curation bulk waive entry converged: the artifact was released \
                         inside the validate-apply window, so this entry appends nothing"
                    );
                    applied.already_released_ids.push(artifact_id);
                    emit_curation_decision(
                        CurationDecisionLabel::Waive,
                        Some(repo_label),
                        CurationDecisionResult::Ok,
                    );
                    return;
                }
                Ok(fresh) => {
                    let outcome = result.as_str();
                    tracing::info!(
                        artifact_id = %artifact_id,
                        fresh_status = %fresh.quarantine_status,
                        outcome,
                        "curation bulk waive entry lost its append and has not converged; \
                         not retried — the event that won is evidence this decision was \
                         not reviewed against"
                    );
                }
                Err(e) => {
                    // The re-read itself failed, so convergence could not
                    // be established either way. The entry keeps the
                    // append's own error — that is what happened to it —
                    // and the re-read failure is logged beside it.
                    tracing::warn!(
                        artifact_id = %artifact_id,
                        error = %e,
                        "curation bulk waive entry lost its append and could not be \
                         re-read to check for convergence"
                    );
                }
            }
        }
        emit_curation_decision(CurationDecisionLabel::Waive, Some(repo_label), result);
        applied.failed.push((artifact_id, app_err));
    }

    /// Per-call entry-count cap for a bulk target.
    ///
    /// Takes `max` rather than reading a constant, because the two verbs
    /// bound the same list differently on purpose: a block is reversible
    /// and caps at [`MAX_VERSIONS_PER_CALL`], a waive is not and caps at
    /// [`MAX_WAIVE_ENTRIES_PER_CALL`]. One function so the empty-list
    /// refusal and the message shape cannot diverge between them.
    fn validate_bulk_entry_count(keys: &BulkKeys, max: usize) -> AppResult<()> {
        let mode = keys.mode();
        let len = keys.keys().len();
        if len == 0 {
            return Err(AppError::Domain(DomainError::Validation(format!(
                "{mode} must be non-empty"
            ))));
        }
        if len > max {
            return Err(AppError::Domain(DomainError::Validation(format!(
                "{mode} length {len} exceeds {max} cap"
            ))));
        }
        Ok(())
    }

    /// Resolve a bulk target's addressing keys against the repository's
    /// live rows — **the** dispatch point, so every bulk curation call
    /// reaches the resolver for its addressing mode and no verb carries
    /// a copy.
    ///
    /// Answers one entry per input key, in the caller's order, keyed by
    /// the key **verbatim as it arrived** so the outcome envelope and the
    /// per-entry report echo what the curator wrote.
    async fn resolve_bulk(
        &self,
        repository_id: Uuid,
        keys: &BulkKeys,
    ) -> AppResult<Vec<(String, EntryResolution)>> {
        match keys {
            BulkKeys::Versions { package, versions } => {
                self.resolve_versions(repository_id, package, versions)
                    .await
            }
            BulkKeys::Digests(digests) => self.resolve_digests(repository_id, digests).await,
        }
    }

    /// Resolve `versions` against `artifacts.version` inside
    /// `(repository_id, package)`.
    ///
    /// One bounded `find_by_name_in_repo` page
    /// ([`VERSION_RESOLUTION_PAGE_LIMIT`]) and a per-version match over
    /// it — the shape `BlockTarget::VersionList` has always had, now the
    /// shape both verbs share. Versions beyond the page spill into
    /// [`EntryResolution::None`], as they did: this is a curator-facing
    /// bulk-input surface, not a discovery surface.
    ///
    /// **Never answers [`EntryResolution::Many`].** The match is
    /// first-row-wins, which is the resolution rule the design named by
    /// pointing at `BlockTarget::VersionList`, and the formats this
    /// addressing mode is for are the ones where `artifacts.version` is
    /// populated and immutable. A format that stores several rows under
    /// one version string — a PyPI release holding both an sdist and a
    /// wheel — therefore resolves to one of them here; the
    /// content-addressed mode is the one that refuses rather than picks.
    async fn resolve_versions(
        &self,
        repository_id: Uuid,
        package: &str,
        versions: &[String],
    ) -> AppResult<Vec<(String, EntryResolution)>> {
        let page = self
            .artifacts
            .find_by_name_in_repo(
                repository_id,
                package,
                PageRequest {
                    offset: 0,
                    limit: VERSION_RESOLUTION_PAGE_LIMIT,
                },
            )
            .await
            .map_err(AppError::Domain)?;
        Ok(versions
            .iter()
            .map(|version| {
                let resolution = page
                    .items
                    .iter()
                    .find(|a| a.version.as_deref() == Some(version.as_str()))
                    .map_or(EntryResolution::None, |a| EntryResolution::One {
                        artifact_id: a.id,
                        status: a.quarantine_status,
                    });
                (version.clone(), resolution)
            })
            .collect())
    }

    /// Resolve `digests` against `artifacts.checksum_sha256` inside
    /// `repository_id` — **the one digest resolver**, shared by
    /// `waive-digests` and `block-digests`.
    ///
    /// Every digest is normalised first
    /// ([`normalize_curation_digest`]), and a malformed or
    /// wrong-algorithm entry fails the whole call before a single row is
    /// read: that is a request the curator wrote incorrectly, not a
    /// resolution outcome, and answering it per-entry would let a
    /// `sha512:` digest read as "not found".
    ///
    /// Then **one** port read for the whole set
    /// ([`ArtifactRepository::find_live_rows_by_repo_and_checksums`]),
    /// re-grouped by digest. A digest several live rows carry answers
    /// [`EntryResolution::Many`] with their ids — identical bytes can be
    /// ingested at several paths, and which of those rows the curator
    /// reviewed is not something this layer may guess.
    ///
    /// Two entries spelling one digest differently (`sha256:…` and the
    /// bare hex) normalise to the same address and therefore resolve
    /// identically — each gets its own answer, both naming the same row.
    async fn resolve_digests(
        &self,
        repository_id: Uuid,
        digests: &[String],
    ) -> AppResult<Vec<(String, EntryResolution)>> {
        let mut normalized: Vec<ContentHash> = Vec::with_capacity(digests.len());
        for (index, raw) in digests.iter().enumerate() {
            normalized.push(normalize_curation_digest(index, raw)?);
        }
        // Deduplicate for the read only — the answer stays one entry per
        // input key, including two keys that normalise to one address.
        let mut wanted = normalized.clone();
        wanted.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        wanted.dedup();

        let rows = self
            .artifacts
            .find_live_rows_by_repo_and_checksums(repository_id, &wanted)
            .await
            .map_err(AppError::Domain)?;

        let mut by_digest: HashMap<String, Vec<(Uuid, QuarantineStatus)>> = HashMap::new();
        for (checksum, artifact_id, status) in rows {
            by_digest
                .entry(checksum.as_ref().to_string())
                .or_default()
                .push((artifact_id, status));
        }

        Ok(digests
            .iter()
            .zip(normalized)
            .map(|(raw, hash)| {
                let matches = by_digest.get(hash.as_ref()).map_or(&[][..], Vec::as_slice);
                let resolution = match matches {
                    [] => EntryResolution::None,
                    [(artifact_id, status)] => EntryResolution::One {
                        artifact_id: *artifact_id,
                        status: *status,
                    },
                    several => {
                        // Deterministic order so a refusal reads the same
                        // twice — the port leaves row order unspecified.
                        let mut ids: Vec<Uuid> = several.iter().map(|(id, _)| *id).collect();
                        ids.sort_unstable();
                        EntryResolution::Many(ids)
                    }
                };
                (raw.clone(), resolution)
            })
            .collect())
    }

    /// Block a single resolved artifact. Records outcome into the
    /// shared `BlockOutcome` envelope; continue-on-error on append
    /// failure (per-append failure lands in `outcome.failed`).
    ///
    /// **Caller contract.** `artifact_id` is assumed to have been
    /// resolved by the caller — either via `find_by_id` pre-flight
    /// (`BlockTarget::Artifact`) or via `find_by_name_in_repo`
    /// (`BlockTarget::VersionList` stage 1). A `NotFound` from the
    /// internal `find_by_id` re-load is therefore a *race condition*
    /// (resolution → append window) and lands in `outcome.failed` per
    /// continue-on-error. The `BlockTarget::Artifact` pre-flight is
    /// the chokepoint that turns a stale-id call into a top-level
    /// `Err(NotFound)` instead of an envelope entry — matching
    /// `waive`'s shape.
    ///
    /// Per-call metric emission: ONE tick per attempted append (not per
    /// call). `ok` for transitioned, `conflict` for failed-append
    /// (event-store conflict / domain Invariant), etc.
    /// `Already-rejected` short-circuit ticks `ok` (the operator
    /// intent succeeded — the artifact is in the requested terminal
    /// state).
    async fn block_one(
        &self,
        artifact_id: Uuid,
        actor: &ApiActor,
        user_id: Uuid,
        justification: &str,
        correlation_id: Uuid,
        outcome: &mut BlockOutcome,
    ) {
        let stream_id = StreamId::artifact(artifact_id);

        let mut paired = match ArtifactAtVersion::load(
            &*self.artifacts,
            &*self.events,
            artifact_id,
            OverCapStream::Tolerate,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(CurationDecisionLabel::Block, None, result);
                outcome.failed.push((artifact_id, e));
                return;
            }
        };
        let expected_version = paired.expected_version();
        // Resolve `repository_id → key` once
        // per attempted append (single bounded query). For
        // `BlockTarget::VersionList` this is one lookup per resolved
        // version (N <= 100 per-call cap). The cardinality knob
        // `METRICS_INCLUDE_REPOSITORY_LABEL=false` short-circuits every
        // call to the `_all` sentinel without touching the DB, so
        // operators at scale pay no cost.
        let repository_id = paired.artifact().repository_id;
        let repo_label = self.repository_access.metric_label(repository_id).await;

        // Idempotent no-op: already-Rejected short-circuits with NO
        // event appended.
        if paired.artifact().quarantine_status == QuarantineStatus::Rejected {
            outcome.already_rejected_ids.push(artifact_id);
            emit_curation_decision(
                CurationDecisionLabel::Block,
                Some(&repo_label),
                CurationDecisionResult::Ok,
            );
            return;
        }

        // One `ArtifactRejected`. Repeatable: a blocked artifact the
        // curator later waives or re-evaluates is blockable again, so the
        // verb has no per-artifact bound of its own.
        if let Err(e) = refuse_append_past_cap(&stream_id, paired.stream_len(), 1) {
            let result = classify_append_error(&e);
            emit_curation_decision(CurationDecisionLabel::Block, Some(&repo_label), result);
            outcome.failed.push((artifact_id, e));
            return;
        }

        let prior_status = paired.artifact().quarantine_status;

        let event_payload = match paired
            .artifact_mut()
            .block_by_curator(user_id, justification.to_owned())
        {
            Ok(e) => e,
            Err(e) => {
                let app_err = AppError::Domain(e);
                let result = classify_append_error(&app_err);
                emit_curation_decision(CurationDecisionLabel::Block, Some(&repo_label), result);
                outcome.failed.push((artifact_id, app_err));
                return;
            }
        };

        let score_delta = RepoSecurityScoreProjector::compute_re_evaluated_delta(
            prior_status,
            QuarantineStatus::Rejected,
        );
        let artifact = paired.into_artifact();

        if let Err(e) = self
            .lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactRejected(
                        event_payload,
                    ))],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor.clone()),
                },
                None,
                Some((repository_id, score_delta)),
            )
            .await
        {
            let app_err = AppError::Domain(e);
            let result = classify_append_error(&app_err);
            emit_curation_decision(CurationDecisionLabel::Block, Some(&repo_label), result);
            outcome.failed.push((artifact_id, app_err));
            return;
        }

        outcome.blocked_artifact_ids.push(artifact_id);
        emit_curation_decision(
            CurationDecisionLabel::Block,
            Some(&repo_label),
            CurationDecisionResult::Ok,
        );

        // Best-effort upstream-index cache
        // invalidation. Runs AFTER the `commit_transition_with_score`
        // returns Ok; failure is logged `warn!` and does NOT roll
        // back the event-store append (`NonServableStatusFilter` on
        // the next index build is the load-bearing close). The hook
        // is a no-op when the composition root did not wire an
        // invalidator (`with_upstream_index_cache_invalidator` not
        // called).
        if let Some(invalidator) = self.upstream_index_cache_invalidator.as_ref() {
            invalidate_after_reject(invalidator, artifact_id, repository_id, &artifact.name).await;
        }
    }
}

/// Normalise a curator-supplied digest to the bare 64-lowercase-hex form
/// stored in `artifacts.checksum_sha256`.
///
/// `sha256:<hex>` and a bare `<hex>` are the same address and resolve
/// identically — an operator copying a digest off an OCI manifest or off
/// a curation-queue row must not have to know which spelling this surface
/// wanted.
///
/// **Any other algorithm prefix is a validation error, never a strip.**
/// Hort addresses content by SHA-256 only (ADR 0003), so a `sha512:`
/// digest cannot match any stored row; stripping its prefix would turn
/// "you asked with the wrong algorithm" into a repo-scoped scan for a
/// hash that cannot exist, and the curator would read the answer as "that
/// artifact is not here" and go looking for a missing artifact instead of
/// a mistyped request.
///
/// `index` is the entry's position in the caller's list and is the only
/// thing the message says about *which* entry failed: the offending text
/// is operator-supplied and unbounded up to the first `:`, so it stays in
/// the caller's own request rather than being reflected into an error
/// body — the same rule the OCI digest parser follows for its
/// `UNSUPPORTED` answer.
fn normalize_curation_digest(index: usize, raw: &str) -> AppResult<ContentHash> {
    let trimmed = raw.trim();
    let hex = match trimmed.split_once(':') {
        Some((algorithm, rest)) => {
            if algorithm != SHA256_DIGEST_ALGORITHM {
                return Err(AppError::Domain(DomainError::Validation(format!(
                    "digest at entry {index}: unsupported algorithm prefix — hort addresses \
                     content by SHA-256, so pass a bare 64-hex digest or a \
                     `{SHA256_DIGEST_ALGORITHM}:`-prefixed one"
                ))));
            }
            rest
        }
        None => trimmed,
    };
    hex.parse::<ContentHash>().map_err(|e| {
        AppError::Domain(DomainError::Validation(format!(
            "digest at entry {index}: {e}"
        )))
    })
}

/// What a bulk waive does with a resolved entry whose current status is
/// `status`.
///
/// **The one definition of the bulk route's source-state set**, read by
/// the pre-validation pass *and* by the apply step. Those are the two
/// places that have to agree about it, and the validate→apply window is
/// exactly where a second copy would let the set widen: an entry
/// pre-validated as `Quarantined` can be `ScanIndeterminate` by the time
/// its append runs, and `Artifact::release`'s own guard admits that
/// state.
///
/// The set is **narrower than `Artifact::release`'s** on purpose. That
/// guard reaches `ScanIndeterminate`, and — on an overridable axis —
/// `Rejected`; a bulk, fail-open surface reaches neither. A
/// `scan_indeterminate` hold has an exit that is not a curator override:
/// the stranded-candidate sweep re-picks it and the arriving verdict
/// releases or rejects it, so there is no population there for a bulk
/// verb to rescue. `Rejected` is a recorded verdict, and overriding one
/// is a decision taken with that verdict in view — which is the
/// per-artifact `waive`, still available for the one-off.
///
/// Wildcard-free, so a sixth [`QuarantineStatus`] is a compile error here
/// rather than a state that silently becomes bulk-releasable.
const fn bulk_waive_applicability(status: QuarantineStatus) -> WaiveApplicability {
    match status {
        QuarantineStatus::Quarantined => WaiveApplicability::Release,
        QuarantineStatus::Released => WaiveApplicability::AlreadyTrue,
        QuarantineStatus::None
        | QuarantineStatus::Rejected
        | QuarantineStatus::ScanIndeterminate => WaiveApplicability::OutOfReach,
    }
}

/// The three answers [`bulk_waive_applicability`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiveApplicability {
    /// `Quarantined` — the one state a bulk waive releases from.
    Release,
    /// `Released` — the intent is already true; idempotent success.
    AlreadyTrue,
    /// Every other state, including the two `Artifact::release` itself
    /// admits.
    OutOfReach,
}

/// The addressing keys of a bulk curation call, in the caller's own
/// order — the one input shape both verbs' bulk paths resolve.
///
/// `block-versions` / `waive-versions` and `block-digests` /
/// `waive-digests` are four routes over two addressing modes, and the
/// mode is the only thing that differs about resolving them. Keeping the
/// pair here rather than one copy per verb is what failure the codebase
/// has already paid for twice asks of this change: two copies of a
/// resolution rule drift, and the drift is invisible until a curator's
/// block and a curator's waive disagree about which row a digest named.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BulkKeys {
    /// `(package, versions)` — resolved against `artifacts.version`.
    Versions {
        package: String,
        versions: Vec<String>,
    },
    /// Digests — resolved against `artifacts.checksum_sha256`.
    Digests(Vec<String>),
}

impl BulkKeys {
    /// The addressing keys verbatim, in the caller's order. The number of
    /// them is what the per-call cap bounds.
    fn keys(&self) -> &[String] {
        match self {
            Self::Versions { versions, .. } => versions,
            Self::Digests(digests) => digests,
        }
    }

    /// Addressing-mode name, for the cap's message and the audit log.
    ///
    /// Not a metric label: `hort_curation_decisions_total` carries
    /// `decision=waive` / `decision=block` for every target shape, so no
    /// catalog entry changes with a new addressing mode.
    const fn mode(&self) -> &'static str {
        match self {
            Self::Versions { .. } => "versions",
            Self::Digests(_) => "digests",
        }
    }
}

/// One addressing entry's resolution against a repository's **live**
/// rows — the shared output shape of both curation resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryResolution {
    /// Exactly one live row. Carries the status read in the same
    /// observation as the id, so a pre-validation verdict and the row it
    /// is about come from one read.
    One {
        artifact_id: Uuid,
        status: QuarantineStatus,
    },
    /// No live row in this repository.
    None,
    /// Several live rows carry these bytes. Produced by the digest
    /// resolver only — see [`CurationUseCase::resolve_versions`] for why
    /// the version resolver cannot answer it.
    Many(Vec<Uuid>),
}

/// Refuse a bulk **block** whose resolution found an ambiguous entry,
/// and otherwise reduce each entry to "this row" or "no row".
///
/// The refusal runs **before the first append**, which is the whole
/// reason this is a reduction and not a per-entry branch inside the
/// block loop: continue-on-error is about per-append failures, and an
/// ambiguity is not one — it is a request that cannot be read. Aborting
/// mid-loop would already have rejected artifacts on the curator's
/// behalf before telling them their list was unreadable.
///
/// Ambiguity is a refusal on the block side too, not a pick and not a
/// `not_found_digests` entry. The bytes *were* found; what cannot be
/// established is which of the rows carrying them the curator reviewed,
/// and `not_found` would say the opposite of what happened. The message
/// names the offending entries by **position and resolved ids** and
/// never echoes the key: the key is operator-supplied and unbounded, and
/// the ids are what the curator re-addresses the decision with.
fn reduce_block_entries(
    resolved: Vec<(String, EntryResolution)>,
) -> AppResult<Vec<(String, Option<Uuid>)>> {
    let mut ambiguous: Vec<String> = Vec::new();
    let mut reduced: Vec<(String, Option<Uuid>)> = Vec::with_capacity(resolved.len());
    for (index, (key, resolution)) in resolved.into_iter().enumerate() {
        match resolution {
            EntryResolution::One { artifact_id, .. } => reduced.push((key, Some(artifact_id))),
            EntryResolution::None => reduced.push((key, None)),
            EntryResolution::Many(ids) => ambiguous.push(describe_ambiguous_entry(index, &ids)),
        }
    }
    if ambiguous.is_empty() {
        return Ok(reduced);
    }
    Err(AppError::Domain(DomainError::Validation(format!(
        "{count} entr{plural} resolve to more than one live artifact, so the row the \
         decision was reviewed against cannot be established — re-address the decision \
         at the artifact id: {detail}",
        count = ambiguous.len(),
        plural = if ambiguous.len() == 1 { "y" } else { "ies" },
        detail = ambiguous.join("; "),
    ))))
}

/// One ambiguous entry, by position and resolved ids.
fn describe_ambiguous_entry(index: usize, ids: &[Uuid]) -> String {
    let ids = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("entry {index} -> [{ids}]")
}

/// Reduce a bulk **waive**'s resolution to its per-entry report.
///
/// The waive side keeps every entry, with the row it resolved to and the
/// verdict, because an aborted batch has to say which entry stopped it
/// *and* that the others were fine. The state verdict comes from
/// [`bulk_waive_applicability`], so the report and the apply step read
/// one definition of the source-state set.
fn reduce_waive_entries(resolved: Vec<(String, EntryResolution)>) -> Vec<WaiveEntryReport> {
    resolved
        .into_iter()
        .map(|(key, resolution)| match resolution {
            EntryResolution::One {
                artifact_id,
                status,
            } => WaiveEntryReport {
                key,
                artifact_id: Some(artifact_id),
                verdict: match bulk_waive_applicability(status) {
                    WaiveApplicability::Release => WaiveEntryVerdict::Releasable,
                    WaiveApplicability::AlreadyTrue => WaiveEntryVerdict::AlreadyReleased,
                    WaiveApplicability::OutOfReach => WaiveEntryVerdict::StateNotReleasable(status),
                },
            },
            EntryResolution::None => WaiveEntryReport {
                key,
                artifact_id: None,
                verdict: WaiveEntryVerdict::Unresolvable,
            },
            EntryResolution::Many(ids) => WaiveEntryReport {
                key,
                artifact_id: None,
                verdict: WaiveEntryVerdict::Ambiguous(ids),
            },
        })
        .collect()
}

/// Classify an `AppError` into the `result` metric label.
///
/// `conflict` for event-store version conflict (Domain::Conflict) and
/// domain-rule invariants (the source-state guard's `Invariant` flavour
/// surfaces here too — it represents a state-machine conflict at the
/// time of decision). `invalid` for `Validation`. `error` for
/// everything else (adapter / infrastructure).
fn classify_append_error(e: &AppError) -> CurationDecisionResult {
    match e {
        AppError::Domain(DomainError::Conflict(_)) => CurationDecisionResult::Conflict,
        // ADR 0025 — the curator source-state guard now surfaces as
        // InvalidState (HTTP 409); keep the metric label `conflict`,
        // matching the prior Invariant→conflict classification.
        AppError::Domain(DomainError::InvalidState(_)) => CurationDecisionResult::Conflict,
        AppError::Domain(DomainError::Invariant(_)) => CurationDecisionResult::Conflict,
        AppError::Domain(DomainError::Validation(_)) => CurationDecisionResult::Invalid,
        AppError::Domain(DomainError::Forbidden(_)) => CurationDecisionResult::Denied,
        _ => CurationDecisionResult::Error,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::{
        DomainEvent, PersistedEvent, RejectionReason, ReleaseReason, StreamId,
    };
    use hort_domain::ports::curation_decisions_repository::{
        CurationDecisionEntry, CurationDecisionFilter, CurationDecisionsRepository,
    };
    use hort_domain::ports::curation_exclusions_repository::{
        CurationExclusionEntry, CurationExclusionFilter, CurationExclusionsRepository,
    };
    use hort_domain::ports::curation_queue_repository::{
        CurationQueueEntry, CurationQueueFilter, CurationQueueRepository,
    };
    use hort_domain::ports::BoxFuture;

    use super::*;
    use crate::use_cases::test_support::*;

    // -- Mock ports --------------------------------------------------------

    /// Mock that records `list_queue` calls and returns a configurable Vec.
    pub struct MockCurationQueueRepository {
        recorded: std::sync::Mutex<Vec<CurationQueueFilter>>,
        result: std::sync::Mutex<DomainResult<Vec<CurationQueueEntry>>>,
    }

    impl MockCurationQueueRepository {
        pub fn new() -> Self {
            Self {
                recorded: std::sync::Mutex::new(Vec::new()),
                result: std::sync::Mutex::new(Ok(Vec::new())),
            }
        }

        pub fn set_result(&self, result: DomainResult<Vec<CurationQueueEntry>>) {
            *self.result.lock().unwrap() = result;
        }

        pub fn recorded_filters(&self) -> Vec<CurationQueueFilter> {
            self.recorded.lock().unwrap().clone()
        }
    }

    impl CurationQueueRepository for MockCurationQueueRepository {
        fn list_queue<'a>(
            &'a self,
            filter: CurationQueueFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationQueueEntry>>> {
            self.recorded.lock().unwrap().push(filter);
            let result = match &*self.result.lock().unwrap() {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { result })
        }
    }

    /// Mock that records `list_decisions` calls and returns a configurable Vec.
    pub struct MockCurationDecisionsRepository {
        recorded: std::sync::Mutex<Vec<CurationDecisionFilter>>,
        result: std::sync::Mutex<DomainResult<Vec<CurationDecisionEntry>>>,
    }

    impl MockCurationDecisionsRepository {
        pub fn new() -> Self {
            Self {
                recorded: std::sync::Mutex::new(Vec::new()),
                result: std::sync::Mutex::new(Ok(Vec::new())),
            }
        }

        pub fn set_result(&self, result: DomainResult<Vec<CurationDecisionEntry>>) {
            *self.result.lock().unwrap() = result;
        }

        pub fn recorded_filters(&self) -> Vec<CurationDecisionFilter> {
            self.recorded.lock().unwrap().clone()
        }
    }

    impl CurationDecisionsRepository for MockCurationDecisionsRepository {
        fn list_decisions<'a>(
            &'a self,
            filter: CurationDecisionFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationDecisionEntry>>> {
            self.recorded.lock().unwrap().push(filter);
            let result = match &*self.result.lock().unwrap() {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { result })
        }
    }

    /// Mock that records `list_exclusions` calls and returns a configurable Vec.
    pub struct MockCurationExclusionsRepository {
        recorded: std::sync::Mutex<Vec<CurationExclusionFilter>>,
        result: std::sync::Mutex<DomainResult<Vec<CurationExclusionEntry>>>,
    }

    impl MockCurationExclusionsRepository {
        pub fn new() -> Self {
            Self {
                recorded: std::sync::Mutex::new(Vec::new()),
                result: std::sync::Mutex::new(Ok(Vec::new())),
            }
        }

        pub fn set_result(&self, result: DomainResult<Vec<CurationExclusionEntry>>) {
            *self.result.lock().unwrap() = result;
        }

        pub fn recorded_filters(&self) -> Vec<CurationExclusionFilter> {
            self.recorded.lock().unwrap().clone()
        }
    }

    impl CurationExclusionsRepository for MockCurationExclusionsRepository {
        fn list_exclusions<'a>(
            &'a self,
            filter: CurationExclusionFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationExclusionEntry>>> {
            self.recorded.lock().unwrap().push(filter);
            let result = match &*self.result.lock().unwrap() {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { result })
        }
    }

    // -- Fixture -----------------------------------------------------------

    use crate::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};

    /// Default `RepositoryAccessUseCase` for tests that don't care
    /// about the metric-label resolution shape: empty repo store,
    /// disabled RBAC, `include_repository_label = true`. The empty
    /// store means every `metric_label(repo_id)` call returns the
    /// `unknown` sentinel — fine for tests that only assert "metric
    /// fired" rather than the label value.
    fn default_repository_access() -> Arc<RepositoryAccessUseCase> {
        Arc::new(RepositoryAccessUseCase::new(
            Arc::new(MockRepositoryRepository::new()),
            RbacAccess::Disabled,
            true,
        ))
    }

    /// Construct a `RepositoryAccessUseCase` seeded with a single
    /// repository at the given id whose key is `repo_key`. Used by
    /// metric-label tests that assert the resolved key is threaded
    /// through to `hort_curation_decisions_total{repository}`.
    fn repository_access_with_key(
        repo_id: Uuid,
        repo_key: &str,
        include_label: bool,
    ) -> Arc<RepositoryAccessUseCase> {
        let repos = Arc::new(MockRepositoryRepository::new());
        let mut r = sample_repository();
        r.id = repo_id;
        r.key = repo_key.into();
        repos.insert(r);
        Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            include_label,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn make_use_case() -> (
        CurationUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
    ) {
        make_use_case_with_repo_access(default_repository_access())
    }

    /// Variant of [`make_use_case`] that lets the caller supply a
    /// pre-built `RepositoryAccessUseCase` — used by metric-label
    /// tests that need the lookup to return a specific key.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_repo_access(
        repository_access: Arc<RepositoryAccessUseCase>,
    ) -> (
        CurationUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(
            artifacts.clone(),
            events.clone(),
        ));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let queue_repo = Arc::new(MockCurationQueueRepository::new());
        let decisions_repo = Arc::new(MockCurationDecisionsRepository::new());
        let exclusions_repo = Arc::new(MockCurationExclusionsRepository::new());
        let uc = CurationUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            artifacts.clone(),
            lifecycle.clone(),
            policies,
            queue_repo,
            decisions_repo,
            exclusions_repo,
            repository_access,
            Arc::new(MockCurationRuleRepository::new()),
            Arc::new(MockStoragePort::new()),
            HashMap::new(),
        );
        (uc, artifacts, events, lifecycle)
    }

    /// Variant of [`make_use_case`] that exposes the
    /// `MockCurationQueueRepository` for `list_queue` tests.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_queue() -> (CurationUseCase, Arc<MockCurationQueueRepository>) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(
            artifacts.clone(),
            events.clone(),
        ));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let queue_repo = Arc::new(MockCurationQueueRepository::new());
        let decisions_repo = Arc::new(MockCurationDecisionsRepository::new());
        let exclusions_repo = Arc::new(MockCurationExclusionsRepository::new());
        let uc = CurationUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            artifacts.clone(),
            lifecycle.clone(),
            policies,
            queue_repo.clone(),
            decisions_repo,
            exclusions_repo,
            default_repository_access(),
            Arc::new(MockCurationRuleRepository::new()),
            Arc::new(MockStoragePort::new()),
            HashMap::new(),
        );
        (uc, queue_repo)
    }

    /// Variant of [`make_use_case`] that exposes the
    /// `MockCurationDecisionsRepository` for `list_decisions` tests.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_decisions() -> (CurationUseCase, Arc<MockCurationDecisionsRepository>) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(
            artifacts.clone(),
            events.clone(),
        ));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let queue_repo = Arc::new(MockCurationQueueRepository::new());
        let decisions_repo = Arc::new(MockCurationDecisionsRepository::new());
        let exclusions_repo = Arc::new(MockCurationExclusionsRepository::new());
        let uc = CurationUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            artifacts.clone(),
            lifecycle.clone(),
            policies,
            queue_repo,
            decisions_repo.clone(),
            exclusions_repo,
            default_repository_access(),
            Arc::new(MockCurationRuleRepository::new()),
            Arc::new(MockStoragePort::new()),
            HashMap::new(),
        );
        (uc, decisions_repo)
    }

    /// Variant of [`make_use_case`] that exposes the
    /// `MockCurationExclusionsRepository` for `list_exclusions` tests.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_exclusions() -> (CurationUseCase, Arc<MockCurationExclusionsRepository>) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(
            artifacts.clone(),
            events.clone(),
        ));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let queue_repo = Arc::new(MockCurationQueueRepository::new());
        let decisions_repo = Arc::new(MockCurationDecisionsRepository::new());
        let exclusions_repo = Arc::new(MockCurationExclusionsRepository::new());
        let uc = CurationUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            artifacts.clone(),
            lifecycle.clone(),
            policies,
            queue_repo,
            decisions_repo,
            exclusions_repo.clone(),
            default_repository_access(),
            Arc::new(MockCurationRuleRepository::new()),
            Arc::new(MockStoragePort::new()),
            HashMap::new(),
        );
        (uc, exclusions_repo)
    }

    fn sample_justification() -> String {
        "CVE-2026-XXXX accepted: false-positive after manual review".into()
    }

    fn curator_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: true,
            writable_repository_ids: vec![],
        }
    }

    /// Seed an artifact in a specific quarantine state and pre-populate
    /// the event stream with a position-0 placeholder so
    /// `read_unpaired_append_version` resolves a non-`NoStream` version
    /// (mirrors a real lifecycle that landed `ArtifactIngested`/
    /// `ArtifactQuarantined` before the curator decision).
    fn seed_artifact_with_stream(
        artifacts: &Arc<MockArtifactRepository>,
        events: &Arc<MockEventStore>,
        status: QuarantineStatus,
    ) -> Uuid {
        let artifact = sample_artifact(status);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        let placeholder = dummy_persisted_event(&stream_id, artifact_id, 0);
        events.set_stream(&stream_id, vec![placeholder]);
        artifacts.insert(artifact);
        artifact_id
    }

    // ------------------------------------------------------------------
    // waive
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn waive_happy_path_releases_quarantined_artifact() {
        let (uc, artifacts, _events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &_events, QuarantineStatus::Quarantined);
        let actor = api_actor();

        uc.waive(
            artifact_id,
            actor.clone(),
            curator_privileges(),
            sample_justification(),
        )
        .await
        .expect("waive should succeed");

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
        assert_eq!(batch.events.len(), 1);
        let DomainEvent::ArtifactReleased(ev) = &batch.events[0].event else {
            panic!("expected ArtifactReleased; got {:?}", batch.events[0].event);
        };
        // `ReleaseReason::Curator` carries the authority distinction —
        // there is no separate `authority` field on the payload. The
        // `(Curator, CuratorWaiver)` pair was enforced by the
        // deny-by-default release predicate at `Artifact::release` call
        // time; the persisted payload carries `released_by =
        // Curator`.
        assert_eq!(ev.released_by, ReleaseReason::Curator);
        assert_eq!(ev.released_by_user_id, Some(actor.user_id));
        assert_eq!(ev.justification, Some(sample_justification()));
    }

    #[tokio::test]
    async fn waive_admin_privilege_also_succeeds() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        uc.waive(
            artifact_id,
            api_actor(),
            admin_privileges(),
            sample_justification(),
        )
        .await
        .expect("admin should be able to waive");
        assert_eq!(lifecycle.committed_transitions().len(), 1);
    }

    #[tokio::test]
    async fn waive_without_curator_or_admin_denies() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                unprivileged(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("curate") || msg.contains("admin"),
            "expected curate/admin in error, got: {msg}"
        );
        assert!(
            lifecycle.committed_transitions().is_empty(),
            "no transition should be appended on privilege denial"
        );
    }

    #[tokio::test]
    async fn waive_empty_justification_is_invalid() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                String::new(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-empty"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    #[tokio::test]
    async fn waive_oversize_justification_is_invalid() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        // 513 bytes — one over the cap.
        let big = "x".repeat(513);
        let err = uc
            .waive(artifact_id, api_actor(), curator_privileges(), big)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("512"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// Source-state guard: `waive` reaches `ScanIndeterminate` too, and
    /// the released event keeps full curator attribution there (ADR 0007,
    /// "One authority owns the manual release").
    #[tokio::test]
    async fn waive_from_scan_indeterminate_releases_with_attribution() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::ScanIndeterminate);
        let actor = api_actor();

        uc.waive(
            artifact_id,
            actor.clone(),
            curator_privileges(),
            sample_justification(),
        )
        .await
        .expect("a curator may clear a stuck scanner");

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
        assert_eq!(batch.events.len(), 1);
        let DomainEvent::ArtifactReleased(ev) = &batch.events[0].event else {
            panic!("expected ArtifactReleased; got {:?}", batch.events[0].event);
        };
        assert_eq!(ev.released_by, ReleaseReason::Curator);
        assert_eq!(ev.released_by_user_id, Some(actor.user_id));
        assert_eq!(ev.justification, Some(sample_justification()));
    }

    /// A `Rejected` artifact whose stream carries **no**
    /// `ArtifactRejected` is refused: the re-hydrated reason is `None`,
    /// which is D6's illegal reason-less state rather than an open door.
    /// The refusal is the caller-reachable state precondition
    /// `DomainError::InvalidState` (409, ADR 0025) — never `Invariant`
    /// (500).
    ///
    /// This is also the fail-closed shape of the hydration itself. The
    /// axis reaches this method from the stream and from nowhere else:
    /// `rejection_reason` is not a column on the `artifacts` projection,
    /// so both the Postgres mapper and `MockArtifactRepository`'s reads
    /// hand the entity back with it cleared, whatever a fixture seeded.
    /// A reason-less stream therefore cannot be talked out of its 409 by
    /// the row — and the positive direction is pinned next door by
    /// `assert_waive_overrides`, whose success is only reachable through
    /// the stream-derived axis.
    #[tokio::test]
    async fn waive_from_rejected_without_a_terminal_event_is_invalid_state_not_invariant() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Rejected);
        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        let AppError::Domain(DomainError::InvalidState(msg)) = &err else {
            panic!("expected InvalidState (409) so the route does not answer 500, got: {err:?}");
        };
        assert!(
            msg.contains("no recorded reason"),
            "the 409 must say what is missing: {msg}"
        );
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// Seed a `Rejected` artifact whose stream carries a terminal
    /// `ArtifactRejected{reason}` — the shape the production path
    /// re-derives the override axis from.
    fn seed_rejected_on_axis(
        artifacts: &Arc<MockArtifactRepository>,
        events: &Arc<MockEventStore>,
        reason: RejectionReason,
    ) -> Uuid {
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        events.set_stream(
            &stream_id,
            vec![
                dummy_persisted_event(&stream_id, artifact_id, 0),
                persisted_artifact_rejected(artifact_id, reason, 1),
            ],
        );
        artifacts.insert(artifact);
        artifact_id
    }

    /// The override, end to end: one test per admitted axis, each
    /// asserting the committed transition is `Released`, the event names
    /// the curator and carries the attribution the application layer
    /// populates, and the saved entity carries **no** stale rejection
    /// reason.
    ///
    /// The axis these overrides turn on comes from the seeded
    /// `ArtifactRejected` and can come from nowhere else: the repository
    /// read clears `rejection_reason` exactly as the projection load
    /// does, so a stop to the stream derivation turns every one of these
    /// into the reason-less 409 above.
    async fn assert_waive_overrides(reason: RejectionReason) {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id = seed_rejected_on_axis(&artifacts, &events, reason.clone());
        let actor = api_actor();

        uc.waive(
            artifact_id,
            actor.clone(),
            curator_privileges(),
            sample_justification(),
        )
        .await
        .unwrap_or_else(|e| panic!("a curator may override a {reason:?} rejection: {e:?}"));

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
        assert_eq!(
            saved.rejection_reason, None,
            "the committed entity must not carry a stale rejection reason — the next \
             policy pass would read it"
        );
        assert_eq!(batch.events.len(), 1);
        let DomainEvent::ArtifactReleased(ev) = &batch.events[0].event else {
            panic!("expected ArtifactReleased; got {:?}", batch.events[0].event);
        };
        assert_eq!(ev.released_by, ReleaseReason::Curator);
        assert_eq!(ev.released_by_user_id, Some(actor.user_id));
        assert_eq!(ev.justification, Some(sample_justification()));
    }

    #[tokio::test]
    async fn waive_overrides_a_scanner_rejection() {
        assert_waive_overrides(RejectionReason::Scanner).await;
    }

    #[tokio::test]
    async fn waive_overrides_a_scan_policy_retroactive_rejection() {
        assert_waive_overrides(RejectionReason::ScanPolicyRetroactive).await;
    }

    /// The case the capability exists for: a curator could block and
    /// could not unblock. A *different* curator's release is admitted —
    /// the authority is the role, and the releasing curator's id is what
    /// the event records.
    #[tokio::test]
    async fn waive_overrides_a_curator_block_by_another_curator() {
        assert_waive_overrides(RejectionReason::Curator {
            curator_id: Uuid::from_u128(0xB10C),
        })
        .await;
    }

    #[tokio::test]
    async fn waive_overrides_a_retroactive_curation_rejection() {
        assert_waive_overrides(RejectionReason::CurationRetroactive {
            rule_id: Uuid::from_u128(0xEE),
        })
        .await;
    }

    /// The provenance axis: what the curator verifies out of band — this
    /// content hash against the publisher's release page — answers the
    /// same question the signature answers, in both directions.
    #[tokio::test]
    async fn waive_overrides_a_provenance_rejection() {
        assert_waive_overrides(RejectionReason::Provenance).await;
    }

    /// The corruption tombstone is the one axis the override never
    /// reaches, and the 409 names it so the operator learns *why* rather
    /// than *that*.
    #[tokio::test]
    async fn waive_refuses_a_corruption_tombstone_naming_the_axis() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id = seed_rejected_on_axis(&artifacts, &events, RejectionReason::Corruption);
        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        let AppError::Domain(DomainError::InvalidState(msg)) = &err else {
            panic!("expected InvalidState (409), got: {err:?}");
        };
        assert!(
            msg.contains("corruption"),
            "the 409 must name the refused axis: {msg}"
        );
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// `RejectionReason::Admin` has no production minting path, and no
    /// override path either — asserted here so a stream that somehow
    /// carries one does not become a release.
    #[tokio::test]
    async fn waive_refuses_an_admin_rejection_naming_the_axis() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id = seed_rejected_on_axis(&artifacts, &events, RejectionReason::Admin);
        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        let AppError::Domain(DomainError::InvalidState(msg)) = &err else {
            panic!("expected InvalidState (409), got: {err:?}");
        };
        assert!(msg.contains("admin"), "the 409 must name the axis: {msg}");
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// An over-cap stream refuses the override rather than overriding on
    /// a guessed axis. The whole decision rests on the LATEST
    /// `ArtifactRejected`, and over the oldest prefix of a breached
    /// stream "the latest" is whichever one the read happened to reach —
    /// a corruption tombstone that scrolled out of the window would read
    /// as the scan rejection before it and release bytes that do not
    /// match their hash. Only `Rejected` pays this cost; the ordinary
    /// `Quarantined` waive reads no evidence and is unaffected.
    #[tokio::test]
    async fn waive_from_rejected_refuses_a_stream_past_the_event_cap() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        let over_cap: Vec<_> = (0..crate::use_cases::STREAM_EVENT_CAP + 1)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, over_cap);
        artifacts.insert(artifact);

        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("{}-event cap", crate::use_cases::STREAM_EVENT_CAP)),
            "the refusal must name the cap it is enforcing; got {err}"
        );
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// An over-cap stream does **not** refuse the ordinary waive: a
    /// `Quarantined` artifact's release reads no evidence, so the cost of
    /// the axis derivation falls only where the axis matters.
    #[tokio::test]
    async fn waive_from_quarantined_tolerates_a_stream_past_the_event_cap() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        let over_cap: Vec<_> = (0..crate::use_cases::STREAM_EVENT_CAP + 1)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, over_cap);
        artifacts.insert(artifact);

        uc.waive(
            artifact_id,
            api_actor(),
            curator_privileges(),
            sample_justification(),
        )
        .await
        .expect("the ordinary waive derives nothing from the stream");
        assert_eq!(lifecycle.committed_transitions().len(), 1);
    }

    /// The ordinary waive still refuses the append that would **cross**
    /// the cap, which is the case `Tolerate` admits and the version check
    /// lets through. Distinct from the two tests above: those are about
    /// an unprovable *prefix*, this is about a stream with no room left.
    #[tokio::test]
    async fn waive_refuses_the_event_that_would_cross_the_cap() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        let full: Vec<_> = (0..crate::use_cases::STREAM_EVENT_CAP)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, full);
        artifacts.insert(artifact);

        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains(&format!("{}-event cap", crate::use_cases::STREAM_EVENT_CAP)),
            "the refusal must name the cap it is enforcing; got {err}"
        );
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// One short of the cap there is room for the release, so the same
    /// fixture waives normally.
    #[tokio::test]
    async fn waive_still_releases_one_event_short_of_the_cap() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        let nearly_full: Vec<_> = (0..crate::use_cases::STREAM_EVENT_CAP - 1)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, nearly_full);
        artifacts.insert(artifact);

        uc.waive(
            artifact_id,
            api_actor(),
            curator_privileges(),
            sample_justification(),
        )
        .await
        .expect("one more event still fits");
        assert_eq!(lifecycle.committed_transitions().len(), 1);
    }

    /// The curator block carries the same refusal, and reports it as a
    /// per-artifact failure rather than aborting the whole call — a
    /// version-list block of a hundred artifacts must not lose the
    /// ninety-nine with room because one has none.
    #[tokio::test]
    async fn block_reports_a_full_stream_as_a_per_artifact_failure() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        let full: Vec<_> = (0..crate::use_cases::STREAM_EVENT_CAP)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, full);
        artifacts.insert(artifact);

        let outcome = uc
            .block(
                BlockTarget::Artifact(artifact_id),
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .expect("the call itself succeeds; the artifact is a per-item failure");

        assert!(outcome.blocked_artifact_ids.is_empty());
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].0, artifact_id);
        assert!(outcome.failed[0]
            .1
            .to_string()
            .contains(&format!("{}-event cap", crate::use_cases::STREAM_EVENT_CAP)));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// The reverse scan the axis is derived from must see the stream's
    /// tail. A corruption tombstone *after* a scan rejection is what the
    /// override must refuse — and reading a truncated oldest-prefix would
    /// find the scan rejection and release corrupt bytes, which is why
    /// the derivation goes through `ArtifactAtVersion::evidence` and the
    /// latest `ArtifactRejected` wins.
    #[tokio::test]
    async fn waive_reads_the_latest_rejection_not_the_first() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        events.set_stream(
            &stream_id,
            vec![
                dummy_persisted_event(&stream_id, artifact_id, 0),
                persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 1),
                persisted_artifact_rejected(artifact_id, RejectionReason::Corruption, 2),
            ],
        );
        artifacts.insert(artifact);

        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        let AppError::Domain(DomainError::InvalidState(msg)) = &err else {
            panic!("expected InvalidState (409), got: {err:?}");
        };
        assert!(
            msg.contains("corruption"),
            "the later tombstone is the live verdict, not the scan rejection before it: \
             {msg}"
        );
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// Event-store version conflict surfaces as `AppError` and never
    /// commits a transition. Simulated via `fail_next_commit` on the
    /// lifecycle mock.
    #[tokio::test]
    async fn waive_event_store_conflict_propagates() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        lifecycle.fail_next_commit(DomainError::Conflict(
            "concurrent curator decision: version mismatch".into(),
        ));
        let err = uc
            .waive(
                artifact_id,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("concurrent"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    // -- AUDIT-info-1 ---------------------------------------------------
    //
    // AUDIT-info-1: **the manual release's success log line carries the
    //   acting `user_id`.** `waive` is the one manual-release surface
    //   (ADR 0007), the denial branches already carry `actor_id`, and an
    //   operator correlates a curator's denied and succeeded decisions by
    //   that field — so the success line losing it is a silent audit
    //   regression nothing else in the suite would see.
    //
    // The capture machinery is `use_cases::test_support::tracing_capture`;
    // its doc comment states what it does and does not see.

    /// AUDIT-info-1 on the surviving path: `waive`'s success line emits
    /// `actor_id` carrying the acting user's id.
    ///
    /// Asserted on the **field**, not on the rendered line. The same line
    /// also carries `artifact_id`, and this file's listing paths log
    /// `filter_actor_id`, so a substring check for the uuid — or for
    /// `actor_id=` — can stay green precisely when the field under
    /// assertion is the one that went missing.
    ///
    /// Synchronous `#[test]` driving the async `waive` through a
    /// current-thread runtime's `block_on` inside the capture closure: the
    /// capture's serialising guard must not cross an `.await`, and an event
    /// emitted on another thread would not reach the buffer.
    #[test]
    fn audit_info_1_waive_success_log_carries_acting_user_id() {
        use crate::use_cases::test_support::tracing_capture::capture_audit_events;

        let actor = api_actor();
        let acting_user_id = actor.user_id;

        let (_, events) = capture_audit_events(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let (uc, artifacts, store, _lifecycle) = make_use_case();
                let artifact_id =
                    seed_artifact_with_stream(&artifacts, &store, QuarantineStatus::Quarantined);
                uc.waive(
                    artifact_id,
                    actor.clone(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect("waive should succeed");
            });
        });

        let success = events
            .iter()
            .find(|e| e.level == tracing::Level::INFO && e.message() == "curator waived artifact")
            .unwrap_or_else(|| panic!("expected waive's success info line; captured {events:#?}"));

        let expected = acting_user_id.to_string();
        assert_eq!(
            success.field("actor_id"),
            Some(expected.as_str()),
            "AUDIT-info-1: waive's success line must carry actor_id = the acting user's id; \
             saw {success:#?}"
        );
        assert!(
            success
                .target
                .starts_with("hort_app::use_cases::curation_use_case"),
            "the captured line must be the use case's own, not a test helper's: {success:#?}"
        );
    }

    // ------------------------------------------------------------------
    // block(Artifact)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn block_single_artifact_happy_path_transitions_to_rejected() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        let actor = api_actor();
        let outcome = uc
            .block(
                BlockTarget::Artifact(artifact_id),
                actor.clone(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .expect("block should succeed");
        assert_eq!(outcome.blocked_artifact_ids, vec![artifact_id]);
        assert!(outcome.already_rejected_ids.is_empty());
        assert!(outcome.not_found_versions.is_empty());
        assert!(outcome.failed.is_empty());

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
        // Envelope correlation_id matches the returned correlation_id —
        // the audit-grouping invariant.
        assert_eq!(batch.correlation_id, outcome.correlation_id);
        let DomainEvent::ArtifactRejected(ev) = &batch.events[0].event else {
            panic!("expected ArtifactRejected; got {:?}", batch.events[0].event);
        };
        assert_eq!(
            ev.rejected_by,
            RejectionReason::Curator {
                curator_id: actor.user_id
            }
        );
        assert_eq!(ev.reason, sample_justification());
    }

    /// Already-Rejected artifact is idempotent no-op: goes into
    /// `already_rejected_ids`, NO event appended.
    #[tokio::test]
    async fn block_single_already_rejected_is_idempotent_noop() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Rejected);
        let outcome = uc
            .block(
                BlockTarget::Artifact(artifact_id),
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .expect("block on rejected should succeed");
        assert!(outcome.blocked_artifact_ids.is_empty());
        assert_eq!(outcome.already_rejected_ids, vec![artifact_id]);
        assert!(outcome.failed.is_empty());
        // NO event appended on idempotent no-op — load-bearing assertion.
        assert!(
            lifecycle.committed_transitions().is_empty(),
            "no transition expected for already-rejected idempotent no-op"
        );
    }

    #[tokio::test]
    async fn block_single_unprivileged_denied() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);
        let err = uc
            .block(
                BlockTarget::Artifact(artifact_id),
                api_actor(),
                unprivileged(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("curate") || msg.contains("admin"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    // ------------------------------------------------------------------
    // block(VersionList)
    // ------------------------------------------------------------------

    fn seed_artifact_named(
        artifacts: &Arc<MockArtifactRepository>,
        events: &Arc<MockEventStore>,
        repository_id: Uuid,
        package: &str,
        version: &str,
        status: QuarantineStatus,
    ) -> Uuid {
        let mut a = sample_artifact(status);
        a.repository_id = repository_id;
        a.name = package.to_string();
        a.name_as_published = package.to_string();
        a.version = Some(version.to_string());
        a.path = format!("{package}/{version}/{package}-{version}.tar.gz");
        let artifact_id = a.id;
        let stream_id = StreamId::artifact(artifact_id);
        let placeholder = dummy_persisted_event(&stream_id, artifact_id, 0);
        events.set_stream(&stream_id, vec![placeholder]);
        artifacts.insert(a);
        artifact_id
    }

    /// VersionList resolves N versions to N artifacts, emits N events,
    /// every event's envelope `correlation_id` matches the returned
    /// `BlockOutcome.correlation_id`.
    #[tokio::test]
    async fn block_version_list_shares_correlation_id_across_events() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let repo_id = Uuid::new_v4();
        let id1 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.0.0",
            QuarantineStatus::Quarantined,
        );
        let id2 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.1.0",
            QuarantineStatus::None,
        );
        let id3 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.2.0",
            QuarantineStatus::Released,
        );

        let outcome = uc
            .block(
                BlockTarget::VersionList {
                    repository_id: repo_id,
                    package: "evil-pkg".into(),
                    versions: vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()],
                },
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .expect("VersionList block should succeed");

        assert_eq!(outcome.blocked_artifact_ids.len(), 3);
        assert!(outcome.blocked_artifact_ids.contains(&id1));
        assert!(outcome.blocked_artifact_ids.contains(&id2));
        assert!(outcome.blocked_artifact_ids.contains(&id3));
        assert!(outcome.already_rejected_ids.is_empty());
        assert!(outcome.not_found_versions.is_empty());
        assert!(outcome.failed.is_empty());

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 3);
        // Every event's envelope carries the SAME correlation_id —
        // the audit-grouping invariant.
        for (_, batch, _) in &transitions {
            assert_eq!(batch.correlation_id, outcome.correlation_id);
        }
    }

    /// Mixed VersionList — one resolved, one already-rejected, one
    /// not-found — each lands in its respective list.
    #[tokio::test]
    async fn block_version_list_mixed_outcomes_partitions_correctly() {
        let (uc, artifacts, events, _lifecycle) = make_use_case();
        let repo_id = Uuid::new_v4();
        let id_quarantined = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "2.0.0",
            QuarantineStatus::Quarantined,
        );
        let id_rejected = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "2.1.0",
            QuarantineStatus::Rejected,
        );

        let outcome = uc
            .block(
                BlockTarget::VersionList {
                    repository_id: repo_id,
                    package: "evil-pkg".into(),
                    versions: vec!["2.0.0".into(), "2.1.0".into(), "9.9.9-not-ingested".into()],
                },
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .expect("mixed VersionList block returns Ok");

        assert_eq!(outcome.blocked_artifact_ids, vec![id_quarantined]);
        assert_eq!(outcome.already_rejected_ids, vec![id_rejected]);
        assert_eq!(outcome.not_found_versions, vec!["9.9.9-not-ingested"]);
        assert!(outcome.failed.is_empty());
    }

    /// Empty `versions` is rejected with `Invalid` before any event-
    /// store access — defensive boundary check.
    #[tokio::test]
    async fn block_version_list_empty_is_invalid() {
        let (uc, _artifacts, _events, lifecycle) = make_use_case();
        let err = uc
            .block(
                BlockTarget::VersionList {
                    repository_id: Uuid::new_v4(),
                    package: "evil-pkg".into(),
                    versions: vec![],
                },
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-empty"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// >100 versions is rejected with `Invalid` before any event-store
    /// access — per-call cap.
    #[tokio::test]
    async fn block_version_list_oversize_is_invalid() {
        let (uc, _artifacts, _events, lifecycle) = make_use_case();
        let versions: Vec<String> = (0..101).map(|i| format!("{i}.0.0")).collect();
        let err = uc
            .block(
                BlockTarget::VersionList {
                    repository_id: Uuid::new_v4(),
                    package: "evil-pkg".into(),
                    versions,
                },
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("100"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// Oversize justification fails fast — once at the call boundary.
    /// No append, no resolution.
    #[tokio::test]
    async fn block_version_list_oversize_justification_fails_fast() {
        let (uc, _artifacts, _events, lifecycle) = make_use_case();
        let big = "x".repeat(513);
        let err = uc
            .block(
                BlockTarget::VersionList {
                    repository_id: Uuid::new_v4(),
                    package: "evil-pkg".into(),
                    versions: vec!["1.0.0".into()],
                },
                api_actor(),
                curator_privileges(),
                big,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("512"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    // ------------------------------------------------------------------
    // Continue-on-error
    // ------------------------------------------------------------------

    /// **Load-bearing test.** A per-append failure (event-store
    /// version conflict on a concurrent decision) DOES NOT abort the
    /// call: the failing artifact lands in `BlockOutcome.failed`, and
    /// the other artifacts in the same `VersionList` are still
    /// processed. Successful appends are NOT rolled back.
    ///
    /// Setup: 5 quarantined artifacts in the same repo+package. The
    /// lifecycle mock's `fail_next_commit` arms ONE failure; in this
    /// mock the failure fires on the NEXT call, then clears. We
    /// arrange that pattern by ordering the versions deterministically
    /// (page returns artifacts sorted by version per
    /// `MockArtifactRepository::find_by_name_in_repo`) and arming the
    /// failure before the 3rd call.
    ///
    /// Implementation detail: `MockArtifactLifecycle::fail_next_commit`
    /// fires on the very next `commit_transition_with_score`. To pin
    /// "the 3rd append fails", we arm the failure AFTER the first 2
    /// have landed. That isn't possible inside a single `block` call
    /// from outside — but we CAN drive 5 single `block(Artifact)`
    /// calls and arm the failure between them. That establishes
    /// "events that landed are not rolled back" but does not exercise
    /// the per-call continue-on-error loop directly. To pin the loop
    /// behaviour we instead use a single VersionList call with one
    /// artifact whose stream is corrupted (set to oversize so the
    /// event-store cap fires) — a per-append failure inside the loop.
    ///
    /// The cleanest way to pin continue-on-error on the
    /// `VersionList` loop is: 4 normal artifacts + 1 with a
    /// pre-existing terminal-but-not-Rejected state that the use case
    /// fails to commit (`block_by_curator` fails when state ==
    /// `ScanIndeterminate`, surfacing `DomainError::Invariant`). This
    /// crashes per-append without aborting the loop.
    #[tokio::test]
    async fn block_version_list_continues_on_per_append_failure() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let repo_id = Uuid::new_v4();
        // 4 normal quarantined artifacts + 1 ScanIndeterminate (which
        // is NOT in the `block_by_curator` allowed-source set —
        // `None | Quarantined | Released`).
        let id1 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.0.0",
            QuarantineStatus::Quarantined,
        );
        let id2 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.1.0",
            QuarantineStatus::Quarantined,
        );
        // 3rd in sort order is the one that fails (block_by_curator
        // refuses `ScanIndeterminate` with `DomainError::Invariant`).
        let id3 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.2.0",
            QuarantineStatus::ScanIndeterminate,
        );
        let id4 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.3.0",
            QuarantineStatus::Quarantined,
        );
        let id5 = seed_artifact_named(
            &artifacts,
            &events,
            repo_id,
            "evil-pkg",
            "1.4.0",
            QuarantineStatus::Quarantined,
        );

        let outcome = uc
            .block(
                BlockTarget::VersionList {
                    repository_id: repo_id,
                    package: "evil-pkg".into(),
                    versions: vec![
                        "1.0.0".into(),
                        "1.1.0".into(),
                        "1.2.0".into(),
                        "1.3.0".into(),
                        "1.4.0".into(),
                    ],
                },
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .expect("call returns Ok despite per-append failure");

        // Continue-on-error: the 3rd artifact failed, but 1/2/4/5
        // landed in `blocked_artifact_ids` — the call did not abort.
        assert_eq!(outcome.blocked_artifact_ids.len(), 4);
        assert!(outcome.blocked_artifact_ids.contains(&id1));
        assert!(outcome.blocked_artifact_ids.contains(&id2));
        assert!(outcome.blocked_artifact_ids.contains(&id4));
        assert!(outcome.blocked_artifact_ids.contains(&id5));
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].0, id3);

        // Successful appends are NOT rolled back: 4 transitions in
        // `committed_transitions`.
        assert_eq!(lifecycle.committed_transitions().len(), 4);

        // Every successful append's envelope carries the SAME
        // correlation_id.
        for (_, batch, _) in &lifecycle.committed_transitions() {
            assert_eq!(batch.correlation_id, outcome.correlation_id);
        }
    }

    /// Suppress the unused-warning on `PersistedEvent` import —
    /// referenced via `dummy_persisted_event` from test_support.
    #[allow(dead_code)]
    fn _silence_persisted_event(_: PersistedEvent) {}

    // ------------------------------------------------------------------
    // Branch-coverage fillers for `classify_append_error` paths
    // ------------------------------------------------------------------

    /// `waive` on a non-existent artifact_id surfaces `NotFound` from
    /// `find_by_id` — `classify_append_error` routes this through the
    /// `error` branch (NotFound is not Conflict/Invariant/Validation/
    /// Forbidden). The call returns `Err`; no transition recorded.
    #[tokio::test]
    async fn waive_unknown_artifact_id_propagates_not_found() {
        let (uc, _artifacts, _events, lifecycle) = make_use_case();
        let bogus = Uuid::new_v4();
        let err = uc
            .waive(
                bogus,
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        // NotFound surfaces with "Artifact" + bogus id in the message.
        assert!(err.to_string().contains("Artifact"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// `block(Artifact)` on a non-existent artifact_id surfaces
    /// `NotFound` from `find_by_id` as a top-level `Err` — matching
    /// `waive`'s shape. The continue-on-error envelope semantics
    /// (failures land in `BlockOutcome.failed`) apply to `VersionList`
    /// stage-2 lookups only; the single-artifact path has only one
    /// resolution step (`find_by_id`), and a miss there is a top-level
    /// error, not an envelope entry. The asymmetry is deliberately
    /// flattened to match `waive`.
    #[tokio::test]
    async fn block_single_unknown_id_returns_not_found() {
        let (uc, _artifacts, _events, lifecycle) = make_use_case();
        let bogus = Uuid::new_v4();
        let err = uc
            .block(
                BlockTarget::Artifact(bogus),
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        match &err {
            AppError::Domain(DomainError::NotFound { entity, .. }) => {
                assert_eq!(*entity, "Artifact");
            }
            other => panic!("expected AppError::Domain(NotFound), got: {other:?}"),
        }
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// `classify_append_error` covers the four mapped variants via
    /// pure-function exercise. The use case wires `Validation →
    /// Invalid`, `Conflict → Conflict`, `Invariant → Conflict`,
    /// `Forbidden → Denied`, everything else → `Error`. A direct
    /// branch-coverage test guards against silent reclassification on
    /// refactor.
    #[test]
    fn classify_append_error_maps_each_domain_variant() {
        use crate::metrics::CurationDecisionResult;
        assert_eq!(
            classify_append_error(&AppError::Domain(DomainError::Conflict("x".into()))),
            CurationDecisionResult::Conflict
        );
        assert_eq!(
            classify_append_error(&AppError::Domain(DomainError::Invariant("x".into()))),
            CurationDecisionResult::Conflict
        );
        assert_eq!(
            classify_append_error(&AppError::Domain(DomainError::InvalidState("x".into()))),
            CurationDecisionResult::Conflict
        );
        assert_eq!(
            classify_append_error(&AppError::Domain(DomainError::Validation("x".into()))),
            CurationDecisionResult::Invalid
        );
        assert_eq!(
            classify_append_error(&AppError::Domain(DomainError::Forbidden("x".into()))),
            CurationDecisionResult::Denied
        );
        assert_eq!(
            classify_append_error(&AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                id: "x".into()
            })),
            CurationDecisionResult::Error
        );
        // Non-`Domain` variants fold to `Error`.
        assert_eq!(
            classify_append_error(&AppError::Storage("x".into())),
            CurationDecisionResult::Error
        );
    }

    // ------------------------------------------------------------------
    // list_queue
    // ------------------------------------------------------------------

    use chrono::{DateTime, Utc};
    use hort_domain::entities::repository::RepositoryFormat;

    fn sample_queue_entry(artifact_id: Uuid) -> CurationQueueEntry {
        CurationQueueEntry {
            artifact_id,
            repository_id: Uuid::new_v4(),
            repository_key: "npm-main".into(),
            format: RepositoryFormat::Npm,
            package_name: "evil-pkg".into(),
            version: Some("1.0.0".into()),
            path: "evil-pkg/-/evil-pkg-1.0.0.tgz".into(),
            checksum_sha256: "a".repeat(64),
            tags: Vec::new(),
            quarantine_status: QuarantineStatus::Quarantined,
            quarantine_window_start: DateTime::<Utc>::from_timestamp(1_700_000_000, 0),
            quarantine_deadline: DateTime::<Utc>::from_timestamp(1_700_086_400, 0),
            finding_count: Some(3),
            max_severity: None,
            rejection_reason_kind: None,
        }
    }

    /// Curator privilege → ok; the use case forwards the filter to the
    /// port verbatim and returns the port's Vec untouched.
    #[tokio::test]
    async fn list_queue_curator_pass_through_succeeds() {
        let (uc, queue_repo) = make_use_case_with_queue();
        let entry = sample_queue_entry(Uuid::new_v4());
        queue_repo.set_result(Ok(vec![entry.clone()]));

        let filter = CurationQueueFilter {
            repository_id: Some(Uuid::new_v4()),
            artifact_id: None,
            status: Some(QuarantineStatus::Quarantined),
            rejection_reason_kind: None,
            limit: 50,
        };

        let out = uc
            .list_queue(api_actor(), curator_privileges(), filter.clone())
            .await
            .expect("list_queue should succeed for curator");

        assert_eq!(out, vec![entry]);
        // The port saw the same filter (no use-case-level mutation).
        let recorded = queue_repo.recorded_filters();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], filter);
    }

    /// Admin privilege → ok (`require_curate_or_admin` accepts both).
    #[tokio::test]
    async fn list_queue_admin_also_succeeds() {
        let (uc, queue_repo) = make_use_case_with_queue();
        queue_repo.set_result(Ok(Vec::new()));
        uc.list_queue(
            api_actor(),
            admin_privileges(),
            CurationQueueFilter::default(),
        )
        .await
        .expect("admin should be able to list the queue");
        assert_eq!(queue_repo.recorded_filters().len(), 1);
    }

    /// Neither Curate nor Admin → Forbidden; port is NEVER called.
    #[tokio::test]
    async fn list_queue_without_curator_or_admin_denies() {
        let (uc, queue_repo) = make_use_case_with_queue();
        let err = uc
            .list_queue(api_actor(), unprivileged(), CurationQueueFilter::default())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("curate") || msg.contains("admin"),
            "expected curate/admin in error, got: {msg}"
        );
        assert!(
            queue_repo.recorded_filters().is_empty(),
            "denied list_queue must not reach the port"
        );
    }

    /// `limit > 500` is rejected as `Validation` BEFORE the port is
    /// called. Adapter clamps defensively, but the use-case-side gate
    /// is the authoritative check.
    #[tokio::test]
    async fn list_queue_oversize_limit_is_invalid() {
        let (uc, queue_repo) = make_use_case_with_queue();
        let err = uc
            .list_queue(
                api_actor(),
                curator_privileges(),
                CurationQueueFilter {
                    limit: 501,
                    ..CurationQueueFilter::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"));
        assert!(
            queue_repo.recorded_filters().is_empty(),
            "oversize limit must not reach the port"
        );
    }

    /// `limit = 500` (boundary) is accepted.
    #[tokio::test]
    async fn list_queue_max_limit_is_accepted() {
        let (uc, queue_repo) = make_use_case_with_queue();
        queue_repo.set_result(Ok(Vec::new()));
        uc.list_queue(
            api_actor(),
            curator_privileges(),
            CurationQueueFilter {
                limit: 500,
                ..CurationQueueFilter::default()
            },
        )
        .await
        .expect("limit = MAX is accepted");
        assert_eq!(queue_repo.recorded_filters().len(), 1);
    }

    /// Adapter error propagates as `AppError::Domain(...)`.
    #[tokio::test]
    async fn list_queue_adapter_error_propagates() {
        let (uc, queue_repo) = make_use_case_with_queue();
        queue_repo.set_result(Err(DomainError::Invariant(
            "synthetic adapter error".into(),
        )));
        let err = uc
            .list_queue(
                api_actor(),
                curator_privileges(),
                CurationQueueFilter::default(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("synthetic adapter error"));
    }

    // ------------------------------------------------------------------
    // list_decisions
    // ------------------------------------------------------------------

    use hort_domain::ports::curation_decisions_repository::CurationDecisionKind;

    fn sample_decision_entry() -> CurationDecisionEntry {
        CurationDecisionEntry {
            event_id: Uuid::new_v4(),
            kind: CurationDecisionKind::Waive,
            actor_id: Uuid::new_v4(),
            artifact_id: Some(Uuid::new_v4()),
            policy_id: None,
            cve_id: None,
            justification: "false-positive after manual review".into(),
            correlation_id: Uuid::new_v4(),
            occurred_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0)
                .expect("constant timestamp"),
        }
    }

    /// Curator privilege → ok; the use case forwards the filter to the
    /// port verbatim and returns the port's Vec untouched.
    #[tokio::test]
    async fn list_decisions_curator_pass_through_succeeds() {
        let (uc, decisions_repo) = make_use_case_with_decisions();
        let entry = sample_decision_entry();
        decisions_repo.set_result(Ok(vec![entry.clone()]));

        let filter = CurationDecisionFilter {
            kind: Some(CurationDecisionKind::Waive),
            actor_id: Some(Uuid::new_v4()),
            repository_id: Some(Uuid::new_v4()),
            package: Some("evil-pkg".into()),
            since: DateTime::<Utc>::from_timestamp(1_699_000_000, 0),
            limit: 50,
        };

        let out = uc
            .list_decisions(api_actor(), curator_privileges(), filter.clone())
            .await
            .expect("list_decisions should succeed for curator");

        assert_eq!(out, vec![entry]);
        // The port saw the same filter (no use-case-level mutation).
        let recorded = decisions_repo.recorded_filters();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], filter);
    }

    /// Admin privilege → ok (`require_curate_or_admin` accepts both).
    #[tokio::test]
    async fn list_decisions_admin_also_succeeds() {
        let (uc, decisions_repo) = make_use_case_with_decisions();
        decisions_repo.set_result(Ok(Vec::new()));
        uc.list_decisions(
            api_actor(),
            admin_privileges(),
            CurationDecisionFilter::default(),
        )
        .await
        .expect("admin should be able to list decisions");
        assert_eq!(decisions_repo.recorded_filters().len(), 1);
    }

    /// Neither Curate nor Admin → Forbidden; port is NEVER called.
    /// **Load-bearing privilege test** — privilege denial must precede
    /// the port call.
    #[tokio::test]
    async fn list_decisions_without_curator_or_admin_denies() {
        let (uc, decisions_repo) = make_use_case_with_decisions();
        let err = uc
            .list_decisions(
                api_actor(),
                unprivileged(),
                CurationDecisionFilter::default(),
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("curate") || msg.contains("admin"),
            "expected curate/admin in error, got: {msg}"
        );
        assert!(
            decisions_repo.recorded_filters().is_empty(),
            "denied list_decisions must not reach the port"
        );
    }

    /// `limit > 500` is rejected as `Validation` BEFORE the port is
    /// called. Adapter clamps defensively, but the use-case-side gate
    /// is the authoritative check.
    #[tokio::test]
    async fn list_decisions_oversize_limit_is_invalid() {
        let (uc, decisions_repo) = make_use_case_with_decisions();
        let err = uc
            .list_decisions(
                api_actor(),
                curator_privileges(),
                CurationDecisionFilter {
                    limit: 501,
                    ..CurationDecisionFilter::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"));
        assert!(
            decisions_repo.recorded_filters().is_empty(),
            "oversize limit must not reach the port"
        );
    }

    /// `limit = 500` (boundary) is accepted.
    #[tokio::test]
    async fn list_decisions_max_limit_is_accepted() {
        let (uc, decisions_repo) = make_use_case_with_decisions();
        decisions_repo.set_result(Ok(Vec::new()));
        uc.list_decisions(
            api_actor(),
            curator_privileges(),
            CurationDecisionFilter {
                limit: 500,
                ..CurationDecisionFilter::default()
            },
        )
        .await
        .expect("limit = MAX is accepted");
        assert_eq!(decisions_repo.recorded_filters().len(), 1);
    }

    /// Adapter error propagates as `AppError::Domain(...)`.
    #[tokio::test]
    async fn list_decisions_adapter_error_propagates() {
        let (uc, decisions_repo) = make_use_case_with_decisions();
        decisions_repo.set_result(Err(DomainError::Invariant(
            "synthetic decisions adapter error".into(),
        )));
        let err = uc
            .list_decisions(
                api_actor(),
                curator_privileges(),
                CurationDecisionFilter::default(),
            )
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("synthetic decisions adapter error"));
    }

    // ------------------------------------------------------------------
    // The decision log's completeness (ADR 0007, "One authority owns
    // the manual release").
    //
    // `list_decisions` discriminates a curator release on the event
    // PAYLOAD: the Postgres adapter's predicate is
    // `event_data->'data'->>'released_by' = 'Curator'`
    // (`crates/hort-adapters-postgres/src/curation_decisions_repository.rs`,
    // whose own DB-backed suite pins the JSONB shape). The listing is
    // therefore complete exactly as long as EVERY manual release
    // appends `ReleaseReason::Curator` — nothing enforces that from the
    // adapter's side, and the asymmetry was real while a second,
    // admin-authority release surface existed: it appended
    // `ReleaseReason::Admin`, which this predicate does not match, so
    // those releases never appeared in the curator's decision log. With
    // one manual release left, completeness holds by construction, and
    // the test below is what says so.
    // ------------------------------------------------------------------

    /// Fixed `occurred_at` for derived entries — the adapter reads the
    /// envelope's `stored_at`, which the in-memory mocks do not model.
    /// No assertion below depends on it.
    fn derived_occurred_at() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("constant timestamp")
    }

    /// A [`CurationDecisionsRepository`] that DERIVES its listing from
    /// the events the use case actually committed, applying the
    /// production discriminator in its enum form (`released_by ==
    /// ReleaseReason::Curator`) and mapping the row the way the SQL
    /// does: `kind = waive`, `actor_id` and `correlation_id` from the
    /// events envelope, `artifact_id` and `justification` from the
    /// payload.
    ///
    /// Why not [`MockCurationDecisionsRepository`]: a canned-Vec stub
    /// cannot answer "does this release appear in the listing?" — it
    /// answers with whatever the test handed it, so the discriminator
    /// is never exercised. This double answers yes only if the release
    /// really carried the curator authority tag.
    ///
    /// The `filter` is ignored (every test using this double passes the
    /// default filter): filter semantics are SQL-side and are covered
    /// by the adapter's own suite. What is under test here is which
    /// events qualify as decisions at all.
    struct CommittedDecisionsRepository {
        lifecycle: Arc<MockArtifactLifecycle>,
    }

    impl CurationDecisionsRepository for CommittedDecisionsRepository {
        fn list_decisions<'a>(
            &'a self,
            _filter: CurationDecisionFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationDecisionEntry>>> {
            let mut out = Vec::new();
            for (_artifact, batch, _metadata) in self.lifecycle.committed_transitions() {
                let Actor::Api(ref actor) = batch.actor else {
                    // Not an API-authenticated append — no curator
                    // decision can ride it.
                    continue;
                };
                for to_append in &batch.events {
                    let DomainEvent::ArtifactReleased(ref released) = to_append.event else {
                        continue;
                    };
                    if released.released_by != ReleaseReason::Curator {
                        continue;
                    }
                    out.push(CurationDecisionEntry {
                        event_id: to_append.event_id,
                        kind: CurationDecisionKind::Waive,
                        actor_id: actor.user_id,
                        artifact_id: Some(released.artifact_id),
                        policy_id: None,
                        cve_id: None,
                        justification: released.justification.clone().unwrap_or_default(),
                        correlation_id: batch.correlation_id,
                        occurred_at: derived_occurred_at(),
                    });
                }
            }
            Box::pin(async move { Ok(out) })
        }
    }

    /// Variant of [`make_use_case`] whose decisions repository derives
    /// its listing from the committed events rather than replaying a
    /// canned Vec.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_committed_decisions() -> (
        CurationUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(
            artifacts.clone(),
            events.clone(),
        ));
        let decisions_repo = Arc::new(CommittedDecisionsRepository {
            lifecycle: lifecycle.clone(),
        });
        let uc = CurationUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            artifacts.clone(),
            lifecycle,
            Arc::new(MockPolicyProjectionRepository::new()),
            Arc::new(MockCurationQueueRepository::new()),
            decisions_repo,
            Arc::new(MockCurationExclusionsRepository::new()),
            default_repository_access(),
            Arc::new(MockCurationRuleRepository::new()),
            Arc::new(MockStoragePort::new()),
            HashMap::new(),
        );
        (uc, artifacts, events)
    }

    /// Every manual release appears in the curator's decision log —
    /// from BOTH source states the one manual release reaches.
    ///
    /// `ScanIndeterminate` is the load-bearing half: it is the state a
    /// stuck scanner leaves behind, reachable only through the manual
    /// release, and the one a second release authority would have been
    /// most tempting to add for. A release from there that did not
    /// carry `ReleaseReason::Curator` would commit, succeed, and be
    /// absent from the decision log the curator audits — which is
    /// exactly what the retired admin surface did.
    #[tokio::test]
    async fn manual_release_appears_in_list_decisions_from_both_source_states() {
        for status in [
            QuarantineStatus::Quarantined,
            QuarantineStatus::ScanIndeterminate,
        ] {
            let (uc, artifacts, events) = make_use_case_with_committed_decisions();
            let artifact_id = seed_artifact_with_stream(&artifacts, &events, status);
            let actor = api_actor();

            uc.waive(
                artifact_id,
                actor.clone(),
                curator_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_or_else(|e| panic!("waive from {status:?} should succeed: {e}"));

            let entries = uc
                .list_decisions(
                    actor.clone(),
                    curator_privileges(),
                    CurationDecisionFilter::default(),
                )
                .await
                .expect("curator may read the decision log");

            assert_eq!(
                entries.len(),
                1,
                "the manual release from {status:?} must appear exactly once in the \
                 decision log; got {entries:?}"
            );
            let entry = &entries[0];
            assert_eq!(entry.kind, CurationDecisionKind::Waive);
            assert_eq!(
                entry.artifact_id,
                Some(artifact_id),
                "decision log row must name the released artifact ({status:?})"
            );
            assert_eq!(
                entry.actor_id, actor.user_id,
                "decision log row must name the deciding curator ({status:?})"
            );
            assert_eq!(entry.justification, sample_justification());
        }
    }

    // ------------------------------------------------------------------
    // list_exclusions
    // ------------------------------------------------------------------

    fn sample_exclusion_entry() -> CurationExclusionEntry {
        CurationExclusionEntry {
            exclusion_id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            cve_id: "CVE-2026-XXXX".into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            added_by_actor_id: Some(Uuid::new_v4()),
            reason: "false positive in container layer".into(),
            scope: hort_domain::events::PolicyScope::Global,
            added_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0)
                .expect("constant timestamp"),
            expires_at: None,
        }
    }

    /// Curator privilege → ok; use case forwards the filter verbatim
    /// and returns the port's Vec untouched.
    #[tokio::test]
    async fn list_exclusions_curator_pass_through_succeeds() {
        let (uc, exclusions_repo) = make_use_case_with_exclusions();
        let entry = sample_exclusion_entry();
        exclusions_repo.set_result(Ok(vec![entry.clone()]));

        let filter = CurationExclusionFilter {
            policy_id: Some(Uuid::new_v4()),
            cve_id: Some("CVE-2026-XXXX".into()),
            actor_id: Some(Uuid::new_v4()),
            limit: 50,
        };

        let out = uc
            .list_exclusions(api_actor(), curator_privileges(), filter.clone())
            .await
            .expect("list_exclusions should succeed for curator");

        assert_eq!(out, vec![entry]);
        let recorded = exclusions_repo.recorded_filters();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], filter);
    }

    /// Admin privilege → ok (`require_curate_or_admin` accepts both).
    #[tokio::test]
    async fn list_exclusions_admin_also_succeeds() {
        let (uc, exclusions_repo) = make_use_case_with_exclusions();
        exclusions_repo.set_result(Ok(Vec::new()));
        uc.list_exclusions(
            api_actor(),
            admin_privileges(),
            CurationExclusionFilter::default(),
        )
        .await
        .expect("admin should be able to list exclusions");
        assert_eq!(exclusions_repo.recorded_filters().len(), 1);
    }

    /// Neither Curate nor Admin → Forbidden; port is NEVER called.
    /// **Load-bearing privilege test** — privilege denial must
    /// precede the port call.
    #[tokio::test]
    async fn list_exclusions_without_curator_or_admin_denies() {
        let (uc, exclusions_repo) = make_use_case_with_exclusions();
        let err = uc
            .list_exclusions(
                api_actor(),
                unprivileged(),
                CurationExclusionFilter::default(),
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("curate") || msg.contains("admin"),
            "expected curate/admin in error, got: {msg}"
        );
        assert!(
            exclusions_repo.recorded_filters().is_empty(),
            "denied list_exclusions must not reach the port"
        );
    }

    /// `limit > 500` is rejected as `Validation` BEFORE the port is
    /// called.
    #[tokio::test]
    async fn list_exclusions_oversize_limit_is_invalid() {
        let (uc, exclusions_repo) = make_use_case_with_exclusions();
        let err = uc
            .list_exclusions(
                api_actor(),
                curator_privileges(),
                CurationExclusionFilter {
                    limit: 501,
                    ..CurationExclusionFilter::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"));
        assert!(
            exclusions_repo.recorded_filters().is_empty(),
            "oversize limit must not reach the port"
        );
    }

    /// `limit = 500` (boundary) is accepted.
    #[tokio::test]
    async fn list_exclusions_max_limit_is_accepted() {
        let (uc, exclusions_repo) = make_use_case_with_exclusions();
        exclusions_repo.set_result(Ok(Vec::new()));
        uc.list_exclusions(
            api_actor(),
            curator_privileges(),
            CurationExclusionFilter {
                limit: 500,
                ..CurationExclusionFilter::default()
            },
        )
        .await
        .expect("limit = MAX is accepted");
        assert_eq!(exclusions_repo.recorded_filters().len(), 1);
    }

    /// Adapter error propagates as `AppError::Domain(...)`.
    #[tokio::test]
    async fn list_exclusions_adapter_error_propagates() {
        let (uc, exclusions_repo) = make_use_case_with_exclusions();
        exclusions_repo.set_result(Err(DomainError::Invariant(
            "synthetic exclusions adapter error".into(),
        )));
        let err = uc
            .list_exclusions(
                api_actor(),
                curator_privileges(),
                CurationExclusionFilter::default(),
            )
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("synthetic exclusions adapter error"));
    }

    // ------------------------------------------------------------------
    // `hort_curation_decisions_total` metric emission tests.
    //
    // Pins the `decision`, `repository`, and `result` labels.
    // The `repository` label: when a repo exists for the artifact's
    // `repository_id`, the label is the key; when
    // `METRICS_INCLUDE_REPOSITORY_LABEL=false`, the helper collapses to
    // `_all`; when the lookup misses, the helper falls to `unknown`.
    // ------------------------------------------------------------------

    /// Helper — read every `hort_curation_decisions_total` increment from
    /// a `DebuggingRecorder` snapshot, returning a Vec of
    /// `(decision, repository, result, count)` tuples in emission
    /// order. Tests assert on this directly.
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
            let labels: HashMap<&str, &str> =
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

    /// `waive` happy path emits exactly one
    /// `hort_curation_decisions_total{decision=waive, repository=<key>,
    /// result=ok}` tick — the resolved repo key flows through
    /// `RepositoryAccessUseCase::metric_label`.
    #[test]
    fn waive_happy_path_emits_metric_with_resolved_repository_key() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        let repo_access = repository_access_with_key(repo_id, "my-repo", true);
        let (uc, artifacts, events, _lifecycle) = make_use_case_with_repo_access(repo_access);
        // Seed an artifact whose `repository_id` matches the seeded key.
        let mut a = sample_artifact(QuarantineStatus::Quarantined);
        a.repository_id = repo_id;
        let artifact_id = a.id;
        let stream_id = StreamId::artifact(artifact_id);
        events.set_stream(
            &stream_id,
            vec![dummy_persisted_event(&stream_id, artifact_id, 0)],
        );
        artifacts.insert(a);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("waive should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(
            hits.len(),
            1,
            "exactly one tick on happy path; got {hits:?}"
        );
        let (d, r, res, n) = &hits[0];
        assert_eq!(d, "waive");
        assert_eq!(r, "my-repo");
        assert_eq!(res, "ok");
        assert_eq!(*n, 1);
    }

    /// `waive` privilege denial emits `{decision=waive, repository=_all,
    /// result=denied}` — privilege check fires BEFORE artifact lookup,
    /// so no `repository_id` is available; `_all` is correct.
    #[test]
    fn waive_denied_emits_metric_with_all_sentinel_pre_lookup() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, artifacts, events, _lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    unprivileged(),
                    sample_justification(),
                ))
                .expect_err("unprivileged waive must fail");
        });
        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, n) = &hits[0];
        assert_eq!(d, "waive");
        assert_eq!(r, "_all"); // pre-lookup, no repo_id known
        assert_eq!(res, "denied");
        assert_eq!(*n, 1);
    }

    /// `waive` justification-validation rejection fires `invalid` with
    /// `_all` (failure precedes the artifact lookup).
    #[test]
    fn waive_invalid_justification_emits_invalid_with_all_sentinel() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, artifacts, events, _lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    curator_privileges(),
                    String::new(), // empty justification — Invalid
                ))
                .expect_err("empty justification must fail");
        });
        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "waive");
        assert_eq!(r, "_all");
        assert_eq!(res, "invalid");
    }

    /// `METRICS_INCLUDE_REPOSITORY_LABEL=false` semantics — the
    /// `RepositoryAccessUseCase::metric_label` helper collapses every
    /// `(repo_id)` to `_all` regardless of whether the repo exists.
    /// The curation emission threads `Some("_all")` through, which the
    /// helper passes verbatim. Operators at scale set the knob to
    /// `false` to bound metric cardinality.
    #[test]
    fn waive_with_cardinality_knob_off_emits_all_sentinel() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        // include_label = false → metric_label always returns `_all`.
        let repo_access = repository_access_with_key(repo_id, "my-repo", false);
        let (uc, artifacts, events, _lifecycle) = make_use_case_with_repo_access(repo_access);

        let mut a = sample_artifact(QuarantineStatus::Quarantined);
        a.repository_id = repo_id;
        let artifact_id = a.id;
        let stream_id = StreamId::artifact(artifact_id);
        events.set_stream(
            &stream_id,
            vec![dummy_persisted_event(&stream_id, artifact_id, 0)],
        );
        artifacts.insert(a);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("waive should succeed");
        });
        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "waive");
        // Knob off → `_all` even though include_label normally returns the key.
        assert_eq!(r, "_all");
        assert_eq!(res, "ok");
    }

    /// Lookup-failure fallback — when `metric_label(repo_id)` cannot
    /// find a row (the seeded repo store doesn't have the id), the
    /// helper returns the `unknown` sentinel. NEVER the raw UUID (high-
    /// cardinality anti-pattern).
    #[test]
    fn waive_repo_resolution_failure_emits_unknown_sentinel() {
        use metrics_util::debugging::DebuggingRecorder;

        // RepositoryAccessUseCase has an EMPTY store — every metric_label
        // call returns `unknown`.
        let (uc, artifacts, events, _lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("waive should succeed");
        });
        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "waive");
        // Empty repo store → unknown sentinel, NOT the raw UUID.
        assert_eq!(r, "unknown");
        // Verify the UUID is NOT in the label — defence-in-depth on
        // the cardinality anti-pattern.
        assert!(!r.contains("-"), "UUID must not leak into label: {r}");
        assert_eq!(res, "ok");
    }

    // ------------------------------------------------------------------
    // `hort_quarantine_released_total` — the manual release is counted.
    //
    // The counter is about RELEASES, whatever authority issued them;
    // `hort_curation_decisions_total` is about curator DECISIONS
    // (waive / block / exclude / unexclude), most of which release
    // nothing. The manual release has to appear on both, and the
    // emitter is shared with the timer and re-evaluation paths
    // (`crate::metrics::emit_release`) so the metric name is
    // spelled once.
    // ------------------------------------------------------------------

    /// Helper — read every `hort_quarantine_released_total` increment
    /// from a `DebuggingRecorder` snapshot as `(reason, count)` pairs in
    /// emission order. Sibling of [`read_curation_decisions`].
    fn read_quarantine_released(snap: metrics_util::debugging::Snapshot) -> Vec<(String, u64)> {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let mut out = Vec::new();
        for (key, _u, _d, value) in snap.into_vec() {
            if key.kind() != MetricKind::Counter
                || key.key().name() != "hort_quarantine_released_total"
            {
                continue;
            }
            let reason = key
                .key()
                .labels()
                .find(|l| l.key() == "reason")
                .map(|l| l.value().to_string())
                .unwrap_or_default();
            let count = match value {
                DebugValue::Counter(n) => n,
                other => panic!("expected Counter, got {other:?}"),
            };
            out.push((reason, count));
        }
        out
    }

    /// A successful `waive` ticks
    /// `hort_quarantine_released_total{reason=curator}` exactly once.
    /// Mirrors
    /// [`waive_happy_path_emits_metric_with_resolved_repository_key`]'s
    /// harness (`DebuggingRecorder` + a current-thread runtime inside
    /// the recorder scope, so the emission happens on the thread the
    /// local recorder is installed on) — that test is the other half of
    /// the pair, asserting the same call's
    /// `hort_curation_decisions_total` tick. Two tests rather than one:
    /// `Snapshotter::snapshot` drains the counters it reports, so one
    /// snapshot cannot be read twice.
    #[test]
    fn waive_happy_path_emits_quarantine_released_total_with_curator_reason() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, artifacts, events, _lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("waive should succeed");
        });

        assert_eq!(
            read_quarantine_released(snapshotter.snapshot()),
            vec![("curator".to_string(), 1)],
            "the one manual release must tick the release counter once, with reason=curator"
        );
    }

    /// An attempt that released nothing must not look like a release:
    /// the privilege denial returns before any append, so
    /// `hort_quarantine_released_total` stays untouched while the
    /// decision counter records the denial (pinned by
    /// [`waive_denied_emits_metric_with_all_sentinel_pre_lookup`]).
    /// This is what holds the emission at its post-commit position — a
    /// tick placed beside the privilege gate would make denied attempts
    /// indistinguishable from releases on an operator's dashboard.
    #[test]
    fn waive_denied_does_not_emit_quarantine_released_total() {
        use metrics_util::debugging::DebuggingRecorder;

        let (uc, artifacts, events, _lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::Quarantined);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.waive(
                    artifact_id,
                    api_actor(),
                    unprivileged(),
                    sample_justification(),
                ))
                .expect_err("unprivileged waive must fail");
        });

        assert!(
            read_quarantine_released(snapshotter.snapshot()).is_empty(),
            "a denied waive released nothing and must not tick \
             hort_quarantine_released_total"
        );
    }

    /// `block(BlockTarget::Artifact)` happy path: one tick with the
    /// resolved repo key and `result=ok`.
    #[test]
    fn block_artifact_happy_path_emits_metric_with_resolved_key() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        let repo_access = repository_access_with_key(repo_id, "evil-repo", true);
        let (uc, artifacts, events, _lifecycle) = make_use_case_with_repo_access(repo_access);
        let mut a = sample_artifact(QuarantineStatus::Quarantined);
        a.repository_id = repo_id;
        let artifact_id = a.id;
        let stream_id = StreamId::artifact(artifact_id);
        events.set_stream(
            &stream_id,
            vec![dummy_persisted_event(&stream_id, artifact_id, 0)],
        );
        artifacts.insert(a);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.block(
                    BlockTarget::Artifact(artifact_id),
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("block should succeed");
        });
        let hits = read_curation_decisions(snapshotter.snapshot());
        assert_eq!(hits.len(), 1);
        let (d, r, res, _) = &hits[0];
        assert_eq!(d, "block");
        assert_eq!(r, "evil-repo");
        assert_eq!(res, "ok");
    }

    /// `block(BlockTarget::VersionList)` emits ONE tick per attempted
    /// append ("per-append per call"). Three transitioned versions →
    /// three `ok` ticks, all carrying the same resolved repo key (the
    /// VersionList target's `repository_id` is the same for every
    /// version).
    #[test]
    fn block_version_list_emits_one_metric_tick_per_attempted_append() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        let repo_access = repository_access_with_key(repo_id, "bulk-repo", true);
        let (uc, artifacts, events, _lifecycle) = make_use_case_with_repo_access(repo_access);

        // Three quarantined artifacts under the same repo+package.
        for v in ["1.0.0", "1.1.0", "1.2.0"] {
            seed_artifact_named(
                &artifacts,
                &events,
                repo_id,
                "evil-pkg",
                v,
                QuarantineStatus::Quarantined,
            );
        }

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.block(
                    BlockTarget::VersionList {
                        repository_id: repo_id,
                        package: "evil-pkg".into(),
                        versions: vec!["1.0.0".into(), "1.1.0".into(), "1.2.0".into()],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("VersionList block should succeed");
        });

        let hits = read_curation_decisions(snapshotter.snapshot());
        // The metrics-rs counter coalesces same-label ticks into ONE
        // entry with count=N. Per-attempted-append => 3 increments on
        // the same `{decision=block, repository=bulk-repo, result=ok}`
        // series → one entry with count=3.
        assert_eq!(hits.len(), 1, "expected one series; got {hits:?}");
        let (d, r, res, n) = &hits[0];
        assert_eq!(d, "block");
        assert_eq!(r, "bulk-repo");
        assert_eq!(res, "ok");
        assert_eq!(*n, 3, "VersionList(N=3) → 3 increments on the ok series");
    }

    /// Continue-on-error: mixed VersionList where one artifact's
    /// domain transition fails (`ScanIndeterminate` is not in the
    /// `block_by_curator` allowed-source set) emits TWO series:
    ///   - `{result=ok, count=4}` — 4 transitioned artifacts
    ///   - `{result=conflict, count=1}` — the `Invariant`-rejected one
    ///
    /// Pins the "per-attempted-append" semantics on the loop's failure
    /// branch.
    #[test]
    fn block_version_list_continue_on_error_emits_per_outcome_metric() {
        use metrics_util::debugging::DebuggingRecorder;

        let repo_id = Uuid::new_v4();
        let repo_access = repository_access_with_key(repo_id, "mixed-repo", true);
        let (uc, artifacts, events, _lifecycle) = make_use_case_with_repo_access(repo_access);

        // 4 normal + 1 ScanIndeterminate (the latter is the failure).
        for (v, status) in [
            ("1.0.0", QuarantineStatus::Quarantined),
            ("1.1.0", QuarantineStatus::Quarantined),
            ("1.2.0", QuarantineStatus::ScanIndeterminate),
            ("1.3.0", QuarantineStatus::Quarantined),
            ("1.4.0", QuarantineStatus::Quarantined),
        ] {
            seed_artifact_named(&artifacts, &events, repo_id, "evil-pkg", v, status);
        }

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.block(
                    BlockTarget::VersionList {
                        repository_id: repo_id,
                        package: "evil-pkg".into(),
                        versions: vec![
                            "1.0.0".into(),
                            "1.1.0".into(),
                            "1.2.0".into(),
                            "1.3.0".into(),
                            "1.4.0".into(),
                        ],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                ))
                .expect("call returns Ok despite per-append failure");
        });

        let mut hits = read_curation_decisions(snapshotter.snapshot());
        hits.sort_by(|a, b| a.2.cmp(&b.2)); // sort by result column
        assert_eq!(
            hits.len(),
            2,
            "expected (ok, conflict) series; got {hits:?}"
        );
        // conflict alphabetises before ok
        assert_eq!(hits[0].0, "block");
        assert_eq!(hits[0].1, "mixed-repo");
        assert_eq!(hits[0].2, "conflict");
        assert_eq!(hits[0].3, 1);
        assert_eq!(hits[1].0, "block");
        assert_eq!(hits[1].1, "mixed-repo");
        assert_eq!(hits[1].2, "ok");
        assert_eq!(hits[1].3, 4);
    }

    // ------------------------------------------------------------------
    // reevaluate
    // ------------------------------------------------------------------

    mod reevaluate_tests {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::scan_policy::{
            CompositeVerdictMode, NegligibleAction, ProvenanceMode, ScanEnforcement,
            ScanPolicyProjection, SeverityThreshold,
        };
        use hort_domain::events::PolicyScope;

        use super::*;

        fn sample_policy_projection(
            policy_id: Uuid,
            threshold: SeverityThreshold,
            quarantine_duration_secs: i64,
        ) -> ScanPolicyProjection {
            ScanPolicyProjection {
                policy_id,
                name: format!("policy-{policy_id}"),
                scope: PolicyScope::Global,
                severity_threshold: threshold,
                quarantine_duration_secs,
                require_approval: false,
                provenance_mode: ProvenanceMode::VerifyIfPresent,
                provenance_backends: vec!["cosign".into()],
                provenance_identities: Vec::new(),
                max_artifact_age_secs: None,
                license_policy: serde_json::Value::Null,
                archived: false,
                scan_backends: vec!["trivy".into()],
                rescan_interval_hours: 24,
                negligible_action: NegligibleAction::Ignore,
                enforcement: ScanEnforcement::Reject,
                composite_verdict_mode: CompositeVerdictMode::Observed,
                stream_version: 0,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        #[allow(clippy::type_complexity)]
        fn make_use_case_for_reevaluate() -> (
            CurationUseCase,
            Arc<MockArtifactRepository>,
            Arc<MockEventStore>,
            Arc<MockArtifactLifecycle>,
            Arc<MockPolicyProjectionRepository>,
            Arc<MockCurationRuleRepository>,
            Arc<MockStoragePort>,
        ) {
            let artifacts = Arc::new(MockArtifactRepository::new());
            let events = Arc::new(MockEventStore::new());
            let lifecycle = Arc::new(MockArtifactLifecycle::new(
                artifacts.clone(),
                events.clone(),
            ));
            let policies = Arc::new(MockPolicyProjectionRepository::new());
            let queue_repo = Arc::new(MockCurationQueueRepository::new());
            let decisions_repo = Arc::new(MockCurationDecisionsRepository::new());
            let exclusions_repo = Arc::new(MockCurationExclusionsRepository::new());
            let curation_rules = Arc::new(MockCurationRuleRepository::new());
            let storage = Arc::new(MockStoragePort::new());
            let uc = CurationUseCase::new(
                crate::event_store_publisher::wrap_for_test(events.clone()),
                artifacts.clone(),
                lifecycle.clone(),
                policies.clone(),
                queue_repo,
                decisions_repo,
                exclusions_repo,
                default_repository_access(),
                curation_rules.clone(),
                storage.clone(),
                HashMap::new(),
            );
            (
                uc,
                artifacts,
                events,
                lifecycle,
                policies,
                curation_rules,
                storage,
            )
        }

        /// Seed a `Rejected` artifact whose stream carries
        /// `ArtifactRejected { Scanner }` followed by a `ScanCompleted`
        /// with `critical` critical findings, **and** the per-finding blob
        /// that `ScanCompleted` points at.
        ///
        /// The blob is not optional for a fixture that then asserts an
        /// exclusion cleared the artifact: an exclusion names a CVE and is
        /// matched against a finding's own `vulnerability_id`, so over the
        /// recorded severity counts alone it matches nothing. The first
        /// seeded finding carries `CVE-2024-3094`, the CVE the exclusion
        /// tests below use.
        fn seed_rejected_with_scan(
            artifacts: &Arc<MockArtifactRepository>,
            events: &Arc<MockEventStore>,
            storage: &Arc<MockStoragePort>,
            critical: u32,
        ) -> Uuid {
            let artifact = sample_artifact(QuarantineStatus::Rejected);
            let artifact_id = artifact.id;
            let stream_id = StreamId::artifact(artifact_id);
            if critical > 0 {
                // `persisted_scan_completed` points every non-clean scan
                // at the same placeholder hash; the mock does not enforce
                // `hash(content) == key`, so seeding under it is enough.
                let findings: Vec<hort_domain::types::Finding> = (0..critical)
                    .map(|i| {
                        let cve = if i == 0 {
                            "CVE-2024-3094".to_string()
                        } else {
                            format!("CVE-2024-OTHER-{i}")
                        };
                        reevaluate_finding(&cve)
                    })
                    .collect();
                storage.insert_content(
                    VALID_SHA256.parse::<ContentHash>().unwrap(),
                    serde_json::to_vec(&findings).unwrap(),
                );
            }
            events.set_stream(
                &stream_id,
                vec![
                    persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 0),
                    persisted_scan_completed(artifact_id, critical, 1),
                ],
            );
            artifacts.insert(artifact);
            artifact_id
        }

        /// A stored Critical finding as the scan path wrote it into the
        /// findings blob.
        fn reevaluate_finding(vuln: &str) -> hort_domain::types::Finding {
            hort_domain::types::Finding {
                purl: "pkg:pypi/xz-utils@1.0.0".into(),
                vulnerability_id: vuln.into(),
                severity: SeverityThreshold::Critical,
                cvss_score: None,
                title: "test finding".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
                severity_basis: hort_domain::types::SeverityBasis::Assessed,
                component_relation: hort_domain::types::ComponentRelation::NotEstablished,
                statement: hort_domain::types::FindingStatement::Unstated,
                advisory_published_at: None,
            }
        }

        /// An over-cap stream refuses the re-evaluation. The verdict rests
        /// on the latest `ScanCompleted` and the latest `ArtifactRejected`
        /// reason, both read off the paired evidence — over the oldest
        /// prefix of a breached stream "the latest" is whichever one the
        /// read happened to reach, so no verdict is derived from it.
        #[tokio::test]
        async fn reevaluate_refuses_a_stream_past_the_event_cap() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact = sample_artifact(QuarantineStatus::Rejected);
            let artifact_id = artifact.id;
            let stream_id = StreamId::artifact(artifact_id);
            let over_cap: Vec<_> = (0..crate::use_cases::STREAM_EVENT_CAP + 1)
                .map(|i| persisted_scan_completed(artifact_id, 0, i))
                .collect();
            events.set_stream(&stream_id, over_cap);
            artifacts.insert(artifact);

            let err = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .unwrap_err();

            assert!(
                err.to_string()
                    .contains(&format!("{}-event cap", crate::use_cases::STREAM_EVENT_CAP)),
                "the refusal must name the cap it is enforcing; got {err}"
            );
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// The re-evaluation appends a PAIR — `ArtifactReEvaluated` plus
        /// the companion transition — so the refusal is asked about two
        /// events. One short of the cap there is room for the audit event
        /// and not for the transition it explains, and committing half a
        /// pair is not an option: the refusal fires on both.
        #[tokio::test]
        async fn reevaluate_refuses_the_pair_that_would_cross_the_cap() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, storage) =
                make_use_case_for_reevaluate();
            // Clean scan + no policy is the `ResetToReleased` fixture
            // `resets_to_released_when_no_policy_and_clean` uses, so the
            // only thing standing between this call and a committed pair
            // is the cap.
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &storage, 0);
            let stream_id = StreamId::artifact(artifact_id);
            let mut stream = events.stream_snapshot(&stream_id);
            let seeded = stream.len() as u64;
            stream.extend(
                (seeded..crate::use_cases::STREAM_EVENT_CAP - 1)
                    .map(|i| persisted_scan_completed(artifact_id, 0, i)),
            );
            assert_eq!(stream.len() as u64, crate::use_cases::STREAM_EVENT_CAP - 1);
            events.set_stream(&stream_id, stream);

            let err = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .unwrap_err();

            assert!(
                err.to_string()
                    .contains(&format!("{}-event cap", crate::use_cases::STREAM_EVENT_CAP)),
                "the refusal must name the cap it is enforcing; got {err}"
            );
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "neither half of the pair lands"
            );
        }

        /// Caller lacking both `curate` and `admin` → `Forbidden`, no
        /// artifact read, no commit.
        #[tokio::test]
        async fn denied_without_curator_or_admin() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 0);
            let privileges = CallerPrivileges {
                is_admin: false,
                is_reviewer: false,
                is_curator: false,
                writable_repository_ids: vec![],
            };
            let err = uc
                .reevaluate(artifact_id, api_actor(), privileges)
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Bogus artifact id → `NotFound` (mirrors `waive`'s shape).
        #[tokio::test]
        async fn unknown_artifact_propagates_not_found() {
            let (uc, _artifacts, _events, _lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let err = uc
                .reevaluate(Uuid::new_v4(), api_actor(), curator_privileges())
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                AppError::Domain(DomainError::NotFound { .. })
            ));
        }

        /// Source-state guard: every non-`Rejected` state → `InvalidState`
        /// (ADR 0025 → 409 at the HTTP layer), no commit.
        #[tokio::test]
        async fn non_rejected_source_state_returns_invalid_state() {
            let (uc, artifacts, _events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            for status in [
                QuarantineStatus::None,
                QuarantineStatus::Quarantined,
                QuarantineStatus::Released,
                QuarantineStatus::ScanIndeterminate,
            ] {
                let artifact = sample_artifact(status);
                let id = artifact.id;
                artifacts.insert(artifact);
                let err = uc
                    .reevaluate(id, api_actor(), curator_privileges())
                    .await
                    .unwrap_err();
                assert!(
                    matches!(err, AppError::Domain(DomainError::InvalidState(_))),
                    "status {status:?} must guard-reject, got {err:?}"
                );
            }
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A still-blocking finding (no exclusion, no policy → default
        /// `block_on_critical` threshold) → `StillRejected`, no event.
        #[tokio::test]
        async fn still_rejected_when_finding_still_blocks() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 1);
            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("still-rejected is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert_eq!(outcome.previous_status, QuarantineStatus::Rejected);
            assert_eq!(outcome.new_status, QuarantineStatus::Rejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Two Critical findings under two distinct CVEs, one exclusion
        /// matching one of them. The per-finding path drops the finding
        /// the exclusion names and leaves the other → `StillRejected`.
        #[tokio::test]
        async fn one_exclusion_leaves_the_unexcluded_finding_blocking() {
            let (uc, artifacts, events, lifecycle, policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 2);
            let policy_id = Uuid::new_v4();
            policies.insert(sample_policy_projection(
                policy_id,
                SeverityThreshold::Critical,
                0,
            ));
            policies.insert_exclusion(hort_domain::entities::scan_policy::ExclusionProjection {
                exclusion_id: Uuid::new_v4(),
                policy_id,
                cve_id: "CVE-2024-3094".into(),
                package_pattern: None,
                scope: PolicyScope::Global,
                reason: "patched upstream".into(),
                added_by_actor_id: None,
                expires_at: None,
            });

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("still-rejected is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Seed a `Rejected` artifact whose `ScanCompleted` records
        /// `critical` Criticals and points at a findings blob that is
        /// **not** in CAS — the at-rest-loss shape.
        fn seed_rejected_with_unreadable_scan(
            artifacts: &Arc<MockArtifactRepository>,
            events: &Arc<MockEventStore>,
            critical: u32,
        ) -> Uuid {
            let artifact = sample_artifact(QuarantineStatus::Rejected);
            let artifact_id = artifact.id;
            let stream_id = StreamId::artifact(artifact_id);
            events.set_stream(
                &stream_id,
                vec![
                    persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 0),
                    persisted_scan_completed(artifact_id, critical, 1),
                ],
            );
            artifacts.insert(artifact);
            artifact_id
        }

        /// **An exclusion may only subtract what it is about.** The
        /// findings blob is gone, so the recorded severity counts are the
        /// only evidence left — and they say how many Criticals there were
        /// without naming one. An exclusion matched against that would
        /// remove the count some other finding contributed and un-reject
        /// the artifact on evidence that never mentioned the excluded CVE,
        /// so it subtracts nothing and the hold stands.
        #[tokio::test]
        async fn an_exclusion_does_not_loosen_an_unreadable_blob() {
            let (uc, artifacts, events, lifecycle, policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_unreadable_scan(&artifacts, &events, 1);
            let policy_id = Uuid::new_v4();
            // Elapsed window: nothing but the verdict is holding it.
            policies.insert(sample_policy_projection(
                policy_id,
                SeverityThreshold::Critical,
                0,
            ));
            policies.insert_exclusion(hort_domain::entities::scan_policy::ExclusionProjection {
                exclusion_id: Uuid::new_v4(),
                policy_id,
                cve_id: "CVE-2024-3094".into(),
                package_pattern: None,
                scope: PolicyScope::Global,
                reason: "patched upstream".into(),
                added_by_actor_id: None,
                expires_at: None,
            });

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("still-rejected is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// **(c) gates the re-quarantine arm too, on the curator's path.**
        /// Clean scan, window still OPEN (so the verdict is
        /// `ResetToQuarantined`), and an active curation `Block` rule
        /// matches. Re-quarantining would hand the artifact to the timer
        /// sweep, whose release reads provenance and takes no curation
        /// input — so the block would be dropped rather than deferred.
        /// The artifact stays `Rejected`.
        #[tokio::test]
        async fn held_cross_axis_when_curation_blocks_a_re_quarantine() {
            let (uc, artifacts, events, lifecycle, policies, curation_rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 0);
            let repository_id = artifacts
                .find_by_id(artifact_id)
                .await
                .unwrap()
                .repository_id;
            let policy_id = Uuid::new_v4();
            // One-hour duration against a `now` anchor → the computed
            // deadline is still in the future.
            policies.insert(sample_policy_projection(
                policy_id,
                SeverityThreshold::Critical,
                3_600,
            ));

            curation_rules.set_rules_for_repo(
                repository_id,
                vec![CurationRule {
                    id: Uuid::new_v4(),
                    name: "block-my-pkg".into(),
                    format: None,
                    package_pattern: "my-pkg".into(),
                    action: CurationRuleAction::Block,
                    reason: "supply-chain concern".into(),
                    managed_by: ManagedBy::GitOps,
                    managed_by_digest: Some([0xab; 32]),
                }],
            );

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("held cross-axis is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "a re-quarantine under an active block must not commit: {:?}",
                lifecycle.committed_transitions(),
            );
            assert_eq!(
                artifacts
                    .find_by_id(artifact_id)
                    .await
                    .unwrap()
                    .quarantine_status,
                QuarantineStatus::Rejected,
            );
        }

        /// A non-scan-clearable rejection reason (ADR 0041 invariant
        /// #6(a)) is ineligible for a scan re-judgement → `StillRejected`,
        /// no event, no scan evidence read.
        #[tokio::test]
        async fn ineligible_reason_is_still_rejected_noop() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact = sample_artifact(QuarantineStatus::Rejected);
            let artifact_id = artifact.id;
            let stream_id = StreamId::artifact(artifact_id);
            events.set_stream(
                &stream_id,
                vec![persisted_artifact_rejected(
                    artifact_id,
                    RejectionReason::Admin,
                    0,
                )],
            );
            artifacts.insert(artifact);

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("ineligible is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// No `ScanCompleted` on the artifact's stream — there is no
        /// evidence to recompute a verdict from → an `Invariant` error
        /// (500), not a caller precondition.
        #[tokio::test]
        async fn no_scan_completed_returns_invariant_error() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact = sample_artifact(QuarantineStatus::Rejected);
            let artifact_id = artifact.id;
            let stream_id = StreamId::artifact(artifact_id);
            events.set_stream(
                &stream_id,
                vec![persisted_artifact_rejected(
                    artifact_id,
                    RejectionReason::Scanner,
                    0,
                )],
            );
            artifacts.insert(artifact);

            let err = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Clean scan + a policy whose computed deadline is still in the
        /// future → `ResetToQuarantined`, curator-attributed
        /// `ArtifactReEvaluated { trigger: CuratorRequested }` +
        /// `ArtifactQuarantined` committed atomically.
        #[tokio::test]
        async fn resets_to_quarantined_when_window_open() {
            let (uc, artifacts, events, lifecycle, policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 0);
            let policy_id = Uuid::new_v4();
            // 1-hour duration; `sample_artifact`'s window anchor is `now`,
            // so the computed deadline is ~1h in the future.
            policies.insert(sample_policy_projection(
                policy_id,
                SeverityThreshold::Critical,
                3600,
            ));

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("clean + open window is Ok");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::ResetToQuarantined);
            assert_eq!(outcome.previous_status, QuarantineStatus::Rejected);
            assert_eq!(outcome.new_status, QuarantineStatus::Quarantined);

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (_saved, batch, _meta) = &transitions[0];
            assert!(matches!(batch.actor, Actor::Api(_)), "curator-attributed");
            assert_eq!(batch.events.len(), 2);
            match &batch.events[0].event {
                DomainEvent::ArtifactReEvaluated(ev) => {
                    assert_eq!(ev.trigger, ReEvaluationTrigger::CuratorRequested);
                    assert_eq!(ev.previous_status, QuarantineStatus::Rejected);
                    assert_eq!(ev.new_status, QuarantineStatus::Quarantined);
                }
                other => panic!("expected ArtifactReEvaluated, got {other:?}"),
            }
            assert!(matches!(
                batch.events[1].event,
                DomainEvent::ArtifactQuarantined(_)
            ));
        }

        /// Clean scan + no active policy (deadline treated as elapsed) →
        /// `ResetToReleased`, curator-attributed `ArtifactReEvaluated` +
        /// `ArtifactReleased` committed atomically.
        #[tokio::test]
        async fn resets_to_released_when_no_policy_and_clean() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 0);

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("clean + no policy is Ok");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::ResetToReleased);
            assert_eq!(outcome.new_status, QuarantineStatus::Released);

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            let (_saved, batch, _meta) = &transitions[0];
            let mut saw_re_evaluated = false;
            let mut saw_released = false;
            for e in &batch.events {
                match &e.event {
                    DomainEvent::ArtifactReEvaluated(ev) => {
                        saw_re_evaluated = true;
                        assert_eq!(ev.trigger, ReEvaluationTrigger::CuratorRequested);
                        assert_eq!(ev.new_status, QuarantineStatus::Released);
                    }
                    DomainEvent::ArtifactReleased(_) => saw_released = true,
                    other => panic!("unexpected event {other:?}"),
                }
            }
            assert!(saw_re_evaluated && saw_released);
        }

        /// Clean scan, elapsed window, but an active curation `Block`
        /// rule matches — the cross-axis release conjunction (ADR 0041
        /// invariant #6(c)) denies release, so the artifact is held
        /// `StillRejected`, not released.
        #[tokio::test]
        async fn held_cross_axis_when_curation_rule_blocks() {
            let (uc, artifacts, events, lifecycle, _policies, curation_rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 0);
            let repository_id = artifacts
                .find_by_id(artifact_id)
                .await
                .unwrap()
                .repository_id;

            curation_rules.set_rules_for_repo(
                repository_id,
                vec![CurationRule {
                    id: Uuid::new_v4(),
                    name: "block-my-pkg".into(),
                    format: None,
                    package_pattern: "my-pkg".into(),
                    action: CurationRuleAction::Block,
                    reason: "supply-chain concern".into(),
                    managed_by: ManagedBy::GitOps,
                    managed_by_digest: Some([0xab; 32]),
                }],
            );

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("held cross-axis is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Clean scan, elapsed window, `ProvenanceMode::Required` with no
        /// `ProvenanceVerified` on the stream → provenance stays
        /// `Pending` (fail-closed); the artifact is held `StillRejected`.
        #[tokio::test]
        async fn held_cross_axis_when_provenance_required_and_unverified() {
            let (uc, artifacts, events, lifecycle, policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 0);
            let policy_id = Uuid::new_v4();
            let mut p = sample_policy_projection(policy_id, SeverityThreshold::Critical, 0);
            p.provenance_mode = ProvenanceMode::Required;
            policies.insert(p);

            let outcome = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("held cross-axis is Ok, not Err");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Idempotence: re-invoking `reevaluate` on an artifact whose
        /// verdict is `StillRejected` returns the same outcome envelope
        /// again with no repeated events and no state churn.
        #[tokio::test]
        async fn idempotent_re_invoke_on_still_rejected() {
            let (uc, artifacts, events, lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 1);

            let first = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("first call is Ok");
            let second = uc
                .reevaluate(artifact_id, api_actor(), curator_privileges())
                .await
                .expect("second call is Ok");

            assert_eq!(first.outcome, ReEvaluationOutcome::StillRejected);
            assert_eq!(second.outcome, ReEvaluationOutcome::StillRejected);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Admin caller (no explicit Curate grant) is also accepted —
        /// mirrors `waive`'s either-OR semantics.
        #[tokio::test]
        async fn admin_privilege_also_succeeds() {
            let (uc, artifacts, events, _lifecycle, _policies, _rules, _storage) =
                make_use_case_for_reevaluate();
            let artifact_id = seed_rejected_with_scan(&artifacts, &events, &_storage, 1);
            let outcome = uc
                .reevaluate(artifact_id, api_actor(), admin_privileges())
                .await
                .expect("admin is accepted");
            assert_eq!(outcome.outcome, ReEvaluationOutcome::StillRejected);
        }
    }

    // ------------------------------------------------------------------
    // Content-addressed bulk curation: the shared resolvers, the
    // digest normaliser, and the fail-open bulk waive contract.
    // ------------------------------------------------------------------

    mod addressed_by_what_was_reviewed {
        use super::*;

        const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const DIGEST_MISSING: &str =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        /// Seed an artifact with a chosen digest and a one-event stream.
        /// `path` is distinct per call so two rows can legitimately carry
        /// the same bytes — the ambiguity this surface refuses to guess
        /// about.
        fn seed_with_digest(
            artifacts: &Arc<MockArtifactRepository>,
            events: &Arc<MockEventStore>,
            repository_id: Uuid,
            digest: &str,
            path: &str,
            status: QuarantineStatus,
        ) -> Uuid {
            let mut a = sample_artifact(status);
            a.repository_id = repository_id;
            a.sha256_checksum = digest.parse().expect("test digest is 64 lowercase hex");
            a.path = path.to_string();
            // OCI's shape: no version, the bytes are the only address.
            a.version = None;
            let artifact_id = a.id;
            let stream_id = StreamId::artifact(artifact_id);
            events.set_stream(
                &stream_id,
                vec![dummy_persisted_event(&stream_id, artifact_id, 0)],
            );
            artifacts.insert(a);
            artifact_id
        }

        fn digest_target(repository_id: Uuid, digests: &[&str]) -> WaiveTarget {
            WaiveTarget::DigestList {
                repository_id,
                digests: digests.iter().map(|d| (*d).to_string()).collect(),
            }
        }

        async fn waive_digests(
            uc: &CurationUseCase,
            repository_id: Uuid,
            digests: &[&str],
        ) -> AppResult<WaiveOutcome> {
            uc.waive_bulk(
                digest_target(repository_id, digests),
                api_actor(),
                curator_privileges(),
                sample_justification(),
            )
            .await
        }

        fn expect_aborted(outcome: WaiveOutcome) -> Vec<WaiveEntryReport> {
            match outcome {
                WaiveOutcome::Aborted { entries } => entries,
                WaiveOutcome::Applied(applied) => {
                    panic!("expected an aborted batch, got {applied:?}")
                }
            }
        }

        fn expect_applied(outcome: WaiveOutcome) -> WaiveApplied {
            match outcome {
                WaiveOutcome::Applied(applied) => applied,
                WaiveOutcome::Aborted { entries } => {
                    panic!("expected an applied batch, got {entries:?}")
                }
            }
        }

        // -- the digest normaliser ------------------------------------

        /// A bare digest and the same digest carrying `sha256:` are one
        /// address.
        #[test]
        fn a_prefixed_and_a_bare_digest_normalise_to_the_same_address() {
            let bare = normalize_curation_digest(0, DIGEST_A).expect("bare hex is accepted");
            let prefixed = normalize_curation_digest(1, &format!("sha256:{DIGEST_A}"))
                .expect("a sha256: prefix is stripped");
            assert_eq!(bare, prefixed);
            assert_eq!(bare.as_ref(), DIGEST_A);
        }

        /// Surrounding whitespace is trimmed — an operator pasting a line
        /// out of a decision file should not be told their digest is
        /// malformed.
        #[test]
        fn surrounding_whitespace_is_trimmed() {
            let trimmed = normalize_curation_digest(0, &format!("  sha256:{DIGEST_A}\n"))
                .expect("whitespace around the entry is not part of the address");
            assert_eq!(trimmed.as_ref(), DIGEST_A);
        }

        /// Any other algorithm prefix is a refusal, never a strip — and
        /// the refusal names the entry's position, never the
        /// operator-supplied text.
        #[test]
        fn another_algorithm_prefix_is_refused_without_echoing_it() {
            let err = normalize_curation_digest(3, &format!("sha512:{}", "a".repeat(128)))
                .expect_err("sha512 cannot address content in a SHA-256 store");
            let message = err.to_string();
            assert!(
                matches!(err, AppError::Domain(DomainError::Validation(_))),
                "a wrong algorithm is a validation error, got {err:?}"
            );
            assert!(
                message.contains("entry 3"),
                "the refusal must name which entry, got: {message}"
            );
            assert!(
                !message.contains("sha512"),
                "the refusal must not reflect the operator-supplied algorithm, got: {message}"
            );
        }

        /// An uppercase algorithm is not `sha256` — the comparison is
        /// exact, so `SHA256:` is refused rather than silently accepted.
        #[test]
        fn an_uppercase_algorithm_name_is_refused() {
            assert!(normalize_curation_digest(0, &format!("SHA256:{DIGEST_A}")).is_err());
        }

        /// Not 64 lowercase hex characters: refused, with the entry
        /// named. `ContentHash`'s own message reports the length and
        /// nothing else, so nothing operator-supplied is reflected.
        #[test]
        fn a_malformed_hex_digest_is_refused_with_its_entry_named() {
            for raw in [
                "",
                "deadbeef",
                &"A".repeat(64),
                &format!("sha256:{}", "z".repeat(64)),
            ] {
                let err = normalize_curation_digest(7, raw)
                    .expect_err("only 64 lowercase hex characters address content");
                assert!(
                    err.to_string().contains("entry 7"),
                    "the refusal must name which entry, got: {err}"
                );
            }
        }

        // -- the source-state set -------------------------------------

        /// The bulk route's source-state set, in one place, exhaustively.
        /// `ScanIndeterminate` and `Rejected` are out of reach here even
        /// though `Artifact::release` admits them — that narrowing is the
        /// decision this surface was designed around.
        #[test]
        fn the_bulk_source_state_set_is_quarantined_and_released_only() {
            assert_eq!(
                bulk_waive_applicability(QuarantineStatus::Quarantined),
                WaiveApplicability::Release
            );
            assert_eq!(
                bulk_waive_applicability(QuarantineStatus::Released),
                WaiveApplicability::AlreadyTrue
            );
            for out_of_reach in [
                QuarantineStatus::None,
                QuarantineStatus::Rejected,
                QuarantineStatus::ScanIndeterminate,
            ] {
                assert_eq!(
                    bulk_waive_applicability(out_of_reach),
                    WaiveApplicability::OutOfReach,
                    "{out_of_reach} must not be bulk-releasable"
                );
            }
        }

        // -- the entry-count cap --------------------------------------

        /// One cap function, two verbs, two bounds — and the message
        /// names the field the caller sent.
        #[test]
        fn the_entry_count_cap_is_per_verb_and_names_its_field() {
            let empty_versions = BulkKeys::Versions {
                package: "p".into(),
                versions: Vec::new(),
            };
            let err = CurationUseCase::validate_bulk_entry_count(
                &empty_versions,
                MAX_WAIVE_ENTRIES_PER_CALL,
            )
            .expect_err("an empty list addresses nothing");
            assert!(err.to_string().contains("versions must be non-empty"));

            let twenty_six = BulkKeys::Digests((0..26).map(|n| n.to_string()).collect());
            let err =
                CurationUseCase::validate_bulk_entry_count(&twenty_six, MAX_WAIVE_ENTRIES_PER_CALL)
                    .expect_err("26 entries exceed the waive cap");
            assert!(
                err.to_string().contains("digests length 26 exceeds 25 cap"),
                "got: {err}"
            );
            // The same 26 entries are well inside the block cap — the
            // asymmetry is the point.
            CurationUseCase::validate_bulk_entry_count(&twenty_six, MAX_VERSIONS_PER_CALL)
                .expect("26 entries fit a bulk block");
            assert_eq!(twenty_six.keys().len(), 26);
            assert_eq!(twenty_six.mode(), "digests");
            assert_eq!(empty_versions.mode(), "versions");
        }

        /// The two caps are the numbers the design named, and the waive
        /// cap is strictly the tighter one. Pinned so a future edit that
        /// "harmonises" them has to argue with a test.
        #[test]
        fn the_waive_cap_is_tighter_than_the_block_cap() {
            assert_eq!(MAX_WAIVE_ENTRIES_PER_CALL, 25);
            assert_eq!(MAX_VERSIONS_PER_CALL, 100);
            const { assert!(MAX_WAIVE_ENTRIES_PER_CALL < MAX_VERSIONS_PER_CALL) };
        }

        // -- the shared digest resolver -------------------------------

        /// One row, no row, and two rows — the three answers the digest
        /// resolver can give, from one call.
        #[tokio::test]
        async fn the_digest_resolver_answers_one_none_or_many() {
            let (uc, artifacts, events, _lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let single = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            // Identical bytes at two paths: the OCI case this surface
            // refuses to guess about.
            let twin_one = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b1",
                QuarantineStatus::Quarantined,
            );
            let twin_two = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b2",
                QuarantineStatus::Released,
            );

            let resolved = uc
                .resolve_digests(
                    repo_id,
                    &[
                        DIGEST_A.to_string(),
                        format!("sha256:{DIGEST_B}"),
                        DIGEST_MISSING.to_string(),
                    ],
                )
                .await
                .expect("resolution reads one bounded page");

            assert_eq!(resolved.len(), 3, "one answer per input entry, in order");
            assert_eq!(resolved[0].0, DIGEST_A, "the key is echoed verbatim");
            assert_eq!(
                resolved[0].1,
                EntryResolution::One {
                    artifact_id: single,
                    status: QuarantineStatus::Quarantined
                }
            );
            assert_eq!(
                resolved[1].0,
                format!("sha256:{DIGEST_B}"),
                "the prefixed spelling is echoed as written"
            );
            let mut expected = vec![twin_one, twin_two];
            expected.sort_unstable();
            assert_eq!(resolved[1].1, EntryResolution::Many(expected));
            assert_eq!(resolved[2].1, EntryResolution::None);
        }

        /// Two entries spelling one digest two ways each get their own
        /// answer, and both name the same row.
        #[tokio::test]
        async fn two_spellings_of_one_digest_resolve_identically() {
            let (uc, artifacts, events, _lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let resolved = uc
                .resolve_digests(
                    repo_id,
                    &[DIGEST_A.to_string(), format!("sha256:{DIGEST_A}")],
                )
                .await
                .expect("resolution succeeds");
            let expected = EntryResolution::One {
                artifact_id: id,
                status: QuarantineStatus::Quarantined,
            };
            assert_eq!(resolved[0].1, expected);
            assert_eq!(resolved[1].1, expected);
        }

        /// A digest in another repository is not this repository's.
        #[tokio::test]
        async fn the_digest_resolver_is_repository_scoped() {
            let (uc, artifacts, events, _lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let elsewhere = Uuid::new_v4();
            seed_with_digest(
                &artifacts,
                &events,
                elsewhere,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let resolved = uc
                .resolve_digests(repo_id, &[DIGEST_A.to_string()])
                .await
                .expect("resolution succeeds");
            assert_eq!(resolved[0].1, EntryResolution::None);
        }

        /// A malformed entry fails the whole resolution before a single
        /// row is read.
        #[tokio::test]
        async fn the_digest_resolver_refuses_a_malformed_entry_outright() {
            let (uc, _artifacts, _events, _lifecycle) = make_use_case();
            let err = uc
                .resolve_digests(Uuid::new_v4(), &[DIGEST_A.to_string(), "nope".to_string()])
                .await
                .expect_err("a malformed digest is not a resolution outcome");
            assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
            assert!(err.to_string().contains("entry 1"));
        }

        // -- the shared version resolver ------------------------------

        /// The version resolver answers one row or none, and mirrors the
        /// block path's first-row-wins match.
        #[tokio::test]
        async fn the_version_resolver_answers_one_or_none() {
            let (uc, artifacts, events, _lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_artifact_named(
                &artifacts,
                &events,
                repo_id,
                "left-pad",
                "1.3.0",
                QuarantineStatus::Quarantined,
            );
            let resolved = uc
                .resolve_versions(
                    repo_id,
                    "left-pad",
                    &["1.3.0".to_string(), "9.9.9".to_string()],
                )
                .await
                .expect("resolution reads one bounded page");
            assert_eq!(
                resolved[0].1,
                EntryResolution::One {
                    artifact_id: id,
                    status: QuarantineStatus::Quarantined
                }
            );
            assert_eq!(resolved[1].1, EntryResolution::None);
        }

        /// Both verbs reach the resolver through one dispatch point, so
        /// the two addressing modes are resolved by one call each.
        #[tokio::test]
        async fn the_resolver_dispatch_covers_both_addressing_modes() {
            let (uc, artifacts, events, _lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let by_version = seed_artifact_named(
                &artifacts,
                &events,
                repo_id,
                "left-pad",
                "1.3.0",
                QuarantineStatus::Quarantined,
            );
            let by_digest = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let versions = uc
                .resolve_bulk(
                    repo_id,
                    &BulkKeys::Versions {
                        package: "left-pad".into(),
                        versions: vec!["1.3.0".into()],
                    },
                )
                .await
                .expect("version dispatch");
            let digests = uc
                .resolve_bulk(repo_id, &BulkKeys::Digests(vec![DIGEST_A.into()]))
                .await
                .expect("digest dispatch");
            assert_eq!(
                versions[0].1,
                EntryResolution::One {
                    artifact_id: by_version,
                    status: QuarantineStatus::Quarantined
                }
            );
            assert_eq!(
                digests[0].1,
                EntryResolution::One {
                    artifact_id: by_digest,
                    status: QuarantineStatus::Quarantined
                }
            );
        }

        // -- the reducers ---------------------------------------------

        /// The block reducer passes one-row and no-row entries through
        /// and refuses on ambiguity, naming positions and ids and never
        /// the key.
        #[test]
        fn the_block_reducer_refuses_ambiguity_and_passes_the_rest_through() {
            let id = Uuid::new_v4();
            let reduced = reduce_block_entries(vec![
                (
                    "k1".into(),
                    EntryResolution::One {
                        artifact_id: id,
                        status: QuarantineStatus::Quarantined,
                    },
                ),
                ("k2".into(), EntryResolution::None),
            ])
            .expect("no ambiguity, no refusal");
            assert_eq!(reduced, vec![("k1".into(), Some(id)), ("k2".into(), None)]);

            let twin_a = Uuid::new_v4();
            let twin_b = Uuid::new_v4();
            let err = reduce_block_entries(vec![(
                "secret-key".into(),
                EntryResolution::Many(vec![twin_a, twin_b]),
            )])
            .expect_err("one ambiguous entry refuses the call");
            let message = err.to_string();
            assert!(message.contains("1 entry resolve"), "singular: {message}");
            assert!(message.contains("entry 0"));
            assert!(message.contains(&twin_a.to_string()));
            assert!(message.contains(&twin_b.to_string()));
            assert!(
                !message.contains("secret-key"),
                "the refusal must not reflect the operator-supplied key: {message}"
            );
        }

        /// Two ambiguous entries: the refusal pluralises and lists both.
        #[test]
        fn the_block_reducer_pluralises_several_ambiguous_entries() {
            let err = reduce_block_entries(vec![
                ("a".into(), EntryResolution::Many(vec![Uuid::new_v4()])),
                ("b".into(), EntryResolution::Many(vec![Uuid::new_v4()])),
            ])
            .expect_err("two ambiguous entries refuse the call");
            let message = err.to_string();
            assert!(message.contains("2 entries resolve"), "plural: {message}");
            assert!(message.contains("entry 0") && message.contains("entry 1"));
        }

        /// The waive reducer keeps every entry and derives its verdict
        /// from the one source-state definition. All five verdicts, and
        /// their wire discriminators.
        #[test]
        fn the_waive_reducer_reports_every_entry_with_its_verdict() {
            let quarantined = Uuid::new_v4();
            let released = Uuid::new_v4();
            let rejected = Uuid::new_v4();
            let twins = vec![Uuid::new_v4(), Uuid::new_v4()];
            let entries = reduce_waive_entries(vec![
                (
                    "q".into(),
                    EntryResolution::One {
                        artifact_id: quarantined,
                        status: QuarantineStatus::Quarantined,
                    },
                ),
                (
                    "r".into(),
                    EntryResolution::One {
                        artifact_id: released,
                        status: QuarantineStatus::Released,
                    },
                ),
                (
                    "x".into(),
                    EntryResolution::One {
                        artifact_id: rejected,
                        status: QuarantineStatus::Rejected,
                    },
                ),
                ("missing".into(), EntryResolution::None),
                ("twin".into(), EntryResolution::Many(twins.clone())),
            ]);

            assert_eq!(entries[0].verdict, WaiveEntryVerdict::Releasable);
            assert_eq!(entries[0].artifact_id, Some(quarantined));
            assert_eq!(entries[0].applicable_row(), Some((quarantined, false)));

            assert_eq!(entries[1].verdict, WaiveEntryVerdict::AlreadyReleased);
            assert_eq!(entries[1].applicable_row(), Some((released, true)));

            assert_eq!(
                entries[2].verdict,
                WaiveEntryVerdict::StateNotReleasable(QuarantineStatus::Rejected)
            );
            assert_eq!(entries[2].applicable_row(), None);

            assert_eq!(entries[3].verdict, WaiveEntryVerdict::Unresolvable);
            assert_eq!(entries[3].artifact_id, None);
            assert_eq!(entries[3].applicable_row(), None);

            assert_eq!(entries[4].verdict, WaiveEntryVerdict::Ambiguous(twins));
            assert_eq!(entries[4].applicable_row(), None);

            let kinds: Vec<&str> = entries.iter().map(|e| e.verdict.wire_kind()).collect();
            assert_eq!(
                kinds,
                vec![
                    "releasable",
                    "already_released",
                    "state_not_releasable",
                    "unresolvable",
                    "ambiguous",
                ]
            );
        }

        /// The key echoed in a report is the caller's own spelling.
        #[test]
        fn the_waive_report_echoes_the_caller_s_own_key() {
            let entries =
                reduce_waive_entries(vec![(format!("sha256:{DIGEST_A}"), EntryResolution::None)]);
            assert_eq!(entries[0].key, format!("sha256:{DIGEST_A}"));
        }

        // -- block-digests --------------------------------------------

        /// The digest-addressed block inherits `VersionList`'s
        /// continue-on-error contract, with `not_found_digests` playing
        /// `not_found_versions`' part.
        #[tokio::test]
        async fn block_digests_partitions_like_block_versions() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let quarantined = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let already = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b",
                QuarantineStatus::Rejected,
            );

            let outcome = uc
                .block(
                    BlockTarget::DigestList {
                        repository_id: repo_id,
                        digests: vec![
                            format!("sha256:{DIGEST_A}"),
                            DIGEST_B.into(),
                            DIGEST_MISSING.into(),
                        ],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect("a digest-addressed block succeeds");

            assert_eq!(outcome.blocked_artifact_ids, vec![quarantined]);
            assert_eq!(outcome.already_rejected_ids, vec![already]);
            assert_eq!(outcome.not_found_digests, vec![DIGEST_MISSING.to_string()]);
            assert!(
                outcome.not_found_versions.is_empty(),
                "a digest call populates the digest partition only"
            );
            assert!(outcome.failed.is_empty());
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            assert_eq!(transitions[0].1.correlation_id, outcome.correlation_id);
        }

        /// An ambiguous digest refuses the block **before** the first
        /// append: not a pick, and not a `not_found_digests` entry
        /// either, because the bytes were found.
        #[tokio::test]
        async fn block_digests_refuses_an_ambiguous_entry_with_nothing_blocked() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            // A resolvable entry sits first, so a mid-loop abort would
            // have already blocked it.
            seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let twin_one = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b1",
                QuarantineStatus::Quarantined,
            );
            let twin_two = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b2",
                QuarantineStatus::Quarantined,
            );

            let err = uc
                .block(
                    BlockTarget::DigestList {
                        repository_id: repo_id,
                        digests: vec![DIGEST_A.into(), DIGEST_B.into()],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect_err("an unreadable request is refused, not partially applied");
            let message = err.to_string();
            assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
            assert!(message.contains(&twin_one.to_string()));
            assert!(message.contains(&twin_two.to_string()));
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "the refusal runs before the first append"
            );
        }

        /// A malformed digest refuses the block at the boundary.
        #[tokio::test]
        async fn block_digests_refuses_a_malformed_entry() {
            let (uc, _artifacts, _events, lifecycle) = make_use_case();
            let err = uc
                .block(
                    BlockTarget::DigestList {
                        repository_id: Uuid::new_v4(),
                        digests: vec![format!("sha512:{}", "a".repeat(128))],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect_err("a wrong-algorithm digest is refused");
            assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// The block caps and empty-list refusals reach the digest arm
        /// too, and the use case enforces them itself.
        #[tokio::test]
        async fn block_digests_enforces_the_entry_count_cap_in_the_use_case() {
            let (uc, _artifacts, _events, _lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            for digests in [
                Vec::new(),
                (0..=MAX_VERSIONS_PER_CALL).map(|n| n.to_string()).collect(),
            ] {
                let err = uc
                    .block(
                        BlockTarget::DigestList {
                            repository_id: repo_id,
                            digests,
                        },
                        api_actor(),
                        curator_privileges(),
                        sample_justification(),
                    )
                    .await
                    .expect_err("the entry-count cap is a use-case gate");
                assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
            }
        }

        /// A resolution-port failure fails the whole bulk block rather
        /// than reading as "nothing matched".
        #[tokio::test]
        async fn block_bulk_propagates_a_resolution_failure() {
            let (uc, artifacts, _events, lifecycle) = make_use_case();
            artifacts.fail_next_find_by_name_in_repo(DomainError::Invariant("db down".into()));
            let err = uc
                .block(
                    BlockTarget::VersionList {
                        repository_id: Uuid::new_v4(),
                        package: "left-pad".into(),
                        versions: vec!["1.0.0".into()],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect_err("a failed resolution is not an empty resolution");
            assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        // -- waive-digests / waive-versions: the fail-open contract ----

        /// Happy path: two quarantined rows addressed by digest, two
        /// `ArtifactReleased` events, one shared correlation id, each
        /// event carrying the curator and the justification verbatim.
        #[tokio::test]
        async fn waive_digests_releases_every_entry_under_one_correlation_id() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let first = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let second = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b",
                QuarantineStatus::Quarantined,
            );
            let actor = api_actor();

            let applied = expect_applied(
                uc.waive_bulk(
                    digest_target(repo_id, &[DIGEST_A, DIGEST_B]),
                    actor.clone(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect("a fully releasable batch applies"),
            );

            assert_eq!(applied.released_artifact_ids, vec![first, second]);
            assert!(applied.already_released_ids.is_empty());
            assert!(applied.failed.is_empty());

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 2, "one ArtifactReleased per artifact");
            for (saved, batch, _) in &transitions {
                assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
                assert_eq!(
                    batch.correlation_id, applied.correlation_id,
                    "one correlation id across the call"
                );
                assert_eq!(batch.events.len(), 1);
                match &batch.events[0].event {
                    DomainEvent::ArtifactReleased(e) => {
                        assert_eq!(e.released_by, ReleaseReason::Curator);
                        assert_eq!(e.released_by_user_id, Some(actor.user_id));
                        assert_eq!(
                            e.justification.as_deref(),
                            Some(sample_justification().as_str())
                        );
                    }
                    other => panic!("expected ArtifactReleased, got {other:?}"),
                }
            }
        }

        /// One valid entry and one non-`Quarantined` entry release
        /// **nothing** and report **both**.
        #[tokio::test]
        async fn waive_digests_one_bad_entry_releases_nothing_and_reports_both() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let good = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let bad = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b",
                QuarantineStatus::Rejected,
            );

            let entries = expect_aborted(
                waive_digests(&uc, repo_id, &[DIGEST_A, DIGEST_B])
                    .await
                    .expect("pre-validation returns an aborted batch, not an Err"),
            );

            assert_eq!(entries.len(), 2, "both entries are reported");
            assert_eq!(entries[0].artifact_id, Some(good));
            assert_eq!(
                entries[0].verdict,
                WaiveEntryVerdict::Releasable,
                "the otherwise-fine entry is reported as such"
            );
            assert_eq!(entries[1].artifact_id, Some(bad));
            assert_eq!(
                entries[1].verdict,
                WaiveEntryVerdict::StateNotReleasable(QuarantineStatus::Rejected)
            );
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "zero events on any invalid entry"
            );
        }

        /// A `ScanIndeterminate` hold is out of reach of the bulk
        /// surface even though `Artifact::release` admits it — the
        /// narrowing, asserted end to end rather than only on the
        /// predicate.
        #[tokio::test]
        async fn waive_digests_does_not_reach_a_scan_indeterminate_hold() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::ScanIndeterminate,
            );
            let entries = expect_aborted(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("an out-of-reach state aborts the batch"),
            );
            assert_eq!(
                entries[0].verdict,
                WaiveEntryVerdict::StateNotReleasable(QuarantineStatus::ScanIndeterminate)
            );
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Re-running a fully applied call converges: every id in
        /// `already_released_ids`, no event.
        #[tokio::test]
        async fn waive_digests_re_applied_converges_with_no_event() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let first = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Released,
            );
            let second = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_B,
                "blobs/b",
                QuarantineStatus::Released,
            );

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A, DIGEST_B])
                    .await
                    .expect("a converged re-apply succeeds"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert_eq!(applied.already_released_ids, vec![first, second]);
            assert!(applied.failed.is_empty());
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "an idempotent success appends nothing"
            );
        }

        /// An ambiguous digest fails the waive naming both artifact ids.
        #[tokio::test]
        async fn waive_digests_on_an_ambiguous_digest_names_both_rows() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let twin_one = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a1",
                QuarantineStatus::Quarantined,
            );
            let twin_two = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a2",
                QuarantineStatus::Quarantined,
            );
            let entries = expect_aborted(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("ambiguity aborts the batch"),
            );
            let mut expected = vec![twin_one, twin_two];
            expected.sort_unstable();
            assert_eq!(entries[0].verdict, WaiveEntryVerdict::Ambiguous(expected));
            assert_eq!(
                entries[0].artifact_id, None,
                "no row is picked, so none is reported as the resolution"
            );
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A digest matching no live row aborts the batch rather than
        /// releasing the rest of it.
        #[tokio::test]
        async fn waive_digests_on_an_unresolvable_digest_aborts_the_batch() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let entries = expect_aborted(
                waive_digests(&uc, repo_id, &[DIGEST_A, DIGEST_MISSING])
                    .await
                    .expect("an unresolvable entry aborts the batch"),
            );
            assert_eq!(entries[1].verdict, WaiveEntryVerdict::Unresolvable);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A soft-deleted row is not a live row: the digest that names
        /// it is unresolvable, so the batch aborts rather than releasing
        /// a deleted artifact.
        #[tokio::test]
        async fn waive_digests_does_not_resolve_a_soft_deleted_row() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let mut row = artifacts.get(id).expect("seeded");
            row.deleted_at = Some(Utc::now());
            artifacts.insert(row);

            let entries = expect_aborted(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("a deleted row resolves to nothing"),
            );
            assert_eq!(entries[0].verdict, WaiveEntryVerdict::Unresolvable);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A `sha256:`-prefixed and a bare digest for the same bytes
        /// release that artifact **once**: two entries, one event.
        #[tokio::test]
        async fn two_spellings_of_one_digest_release_the_artifact_once() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let applied = expect_applied(
                uc.waive_bulk(
                    WaiveTarget::DigestList {
                        repository_id: repo_id,
                        digests: vec![DIGEST_A.into(), format!("sha256:{DIGEST_A}")],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect("both spellings address one releasable row"),
            );
            assert_eq!(applied.released_artifact_ids, vec![id]);
            assert_eq!(
                lifecycle.committed_transitions().len(),
                1,
                "one ArtifactReleased per artifact, not per entry"
            );
        }

        /// A `sha512:` prefix is a validation error on the waive side
        /// too — before any resolution and long before any append.
        #[tokio::test]
        async fn waive_digests_refuses_a_wrong_algorithm_prefix() {
            let (uc, _artifacts, _events, lifecycle) = make_use_case();
            let err = waive_digests(&uc, Uuid::new_v4(), &["sha512:deadbeef"])
                .await
                .expect_err("a wrong algorithm is a validation error");
            assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// The 25-entry cap and the empty-list refusal are use-case
        /// gates, not handler-only ones.
        #[tokio::test]
        async fn waive_bulk_enforces_the_twenty_five_entry_cap_in_the_use_case() {
            let (uc, _artifacts, _events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let oversize: Vec<String> = (0..=MAX_WAIVE_ENTRIES_PER_CALL)
                .map(|n| format!("{n:064x}"))
                .collect();
            let err = uc
                .waive_bulk(
                    WaiveTarget::DigestList {
                        repository_id: repo_id,
                        digests: oversize,
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect_err("26 entries exceed the waive cap");
            assert!(err.to_string().contains("exceeds 25 cap"), "got: {err}");

            let err = uc
                .waive_bulk(
                    WaiveTarget::VersionList {
                        repository_id: repo_id,
                        package: "left-pad".into(),
                        versions: Vec::new(),
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect_err("an empty list addresses nothing");
            assert!(err.to_string().contains("versions must be non-empty"));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// The justification gate is unchanged at 512 bytes and fires
        /// before any resolution read.
        #[tokio::test]
        async fn waive_bulk_keeps_the_512_byte_justification_cap() {
            let (uc, _artifacts, _events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            for justification in [String::new(), "x".repeat(513)] {
                let err = uc
                    .waive_bulk(
                        digest_target(repo_id, &[DIGEST_A]),
                        api_actor(),
                        curator_privileges(),
                        justification,
                    )
                    .await
                    .expect_err("the justification gate is unchanged");
                assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
            }
            // 512 exactly still passes the gate (and then aborts on the
            // unseeded digest, which is the next gate down).
            let outcome = uc
                .waive_bulk(
                    digest_target(repo_id, &[DIGEST_A]),
                    api_actor(),
                    curator_privileges(),
                    "x".repeat(512),
                )
                .await
                .expect("512 bytes is inside the cap");
            assert!(matches!(outcome, WaiveOutcome::Aborted { .. }));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// Authority is `Curate` or `Admin`, and neither is a new
        /// permission: a caller with neither is denied, an admin is
        /// admitted.
        #[tokio::test]
        async fn waive_bulk_authority_is_curate_or_admin() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );

            let err = uc
                .waive_bulk(
                    digest_target(repo_id, &[DIGEST_A]),
                    api_actor(),
                    CallerPrivileges {
                        is_admin: false,
                        is_reviewer: false,
                        is_curator: false,
                        writable_repository_ids: vec![],
                    },
                    sample_justification(),
                )
                .await
                .expect_err("neither curate nor admin is denied");
            assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
            assert!(lifecycle.committed_transitions().is_empty());

            let applied = expect_applied(
                uc.waive_bulk(
                    digest_target(repo_id, &[DIGEST_A]),
                    api_actor(),
                    CallerPrivileges {
                        is_admin: true,
                        is_reviewer: false,
                        is_curator: false,
                        writable_repository_ids: vec![],
                    },
                    sample_justification(),
                )
                .await
                .expect("an admin is admitted"),
            );
            assert_eq!(applied.released_artifact_ids, vec![id]);
        }

        /// The version-addressed waive carries the same contract: a
        /// resolvable list applies, an unresolvable entry aborts it.
        #[tokio::test]
        async fn waive_versions_applies_and_aborts_on_the_same_terms() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_artifact_named(
                &artifacts,
                &events,
                repo_id,
                "left-pad",
                "1.3.0",
                QuarantineStatus::Quarantined,
            );

            let aborted = expect_aborted(
                uc.waive_bulk(
                    WaiveTarget::VersionList {
                        repository_id: repo_id,
                        package: "left-pad".into(),
                        versions: vec!["1.3.0".into(), "9.9.9".into()],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect("one unresolvable version aborts the batch"),
            );
            assert_eq!(aborted[1].verdict, WaiveEntryVerdict::Unresolvable);
            assert!(lifecycle.committed_transitions().is_empty());

            let applied = expect_applied(
                uc.waive_bulk(
                    WaiveTarget::VersionList {
                        repository_id: repo_id,
                        package: "left-pad".into(),
                        versions: vec!["1.3.0".into()],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect("a resolvable list applies"),
            );
            assert_eq!(applied.released_artifact_ids, vec![id]);
            assert_eq!(lifecycle.committed_transitions().len(), 1);
        }

        /// A resolution-port failure fails the whole bulk waive.
        #[tokio::test]
        async fn waive_bulk_propagates_a_resolution_failure() {
            let (uc, artifacts, _events, lifecycle) = make_use_case();
            artifacts.fail_next_find_by_name_in_repo(DomainError::Invariant("db down".into()));
            let err = uc
                .waive_bulk(
                    WaiveTarget::VersionList {
                        repository_id: Uuid::new_v4(),
                        package: "left-pad".into(),
                        versions: vec!["1.0.0".into()],
                    },
                    api_actor(),
                    curator_privileges(),
                    sample_justification(),
                )
                .await
                .expect_err("a failed resolution is not an empty resolution");
            assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
            assert!(lifecycle.committed_transitions().is_empty());
        }

        // -- the apply stage: the validate -> apply window -------------

        /// The artifact's stream cannot be read at apply time: the entry
        /// lands in `failed`, reported rather than silently skipped.
        #[tokio::test]
        async fn an_unreadable_stream_at_apply_time_lands_in_failed() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            // Pre-validation reads rows, not streams, so arming the
            // stream read reaches the apply stage only.
            events.fail_next_read_stream(DomainError::Invariant("event store down".into()));

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation passed, so the batch applies"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert_eq!(applied.failed.len(), 1);
            assert_eq!(applied.failed[0].0, id);
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// The state moved out of reach between validate and apply.
        ///
        /// Pre-validation resolved the row as `Quarantined`; by the time
        /// the apply step loads it, it is a terminal rejection — a state
        /// `Artifact::release` *would* admit on an overridable axis and
        /// this surface deliberately does not reach. The entry is
        /// refused at the append site and reported in `failed`, which is
        /// what the narrow source-state re-check in the appending
        /// function buys.
        #[tokio::test]
        async fn a_state_that_moves_out_of_reach_after_validation_lands_in_failed() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            artifacts.set_status_after_next_checksum_read(id, QuarantineStatus::Rejected);

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation saw a releasable row"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert_eq!(applied.failed.len(), 1);
            assert_eq!(applied.failed[0].0, id);
            assert!(
                matches!(
                    applied.failed[0].1,
                    AppError::Domain(DomainError::InvalidState(_))
                ),
                "a state precondition, not an internal error: {:?}",
                applied.failed[0].1
            );
            assert!(
                applied.failed[0]
                    .1
                    .to_string()
                    .contains("the state changed after this batch was validated"),
                "got: {}",
                applied.failed[0].1
            );
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A use case whose lifecycle double honours the batch's
        /// `ExpectedVersion`, so a concurrent append inside the
        /// validate→apply window really makes this call's append lose.
        #[allow(clippy::type_complexity)]
        fn make_use_case_with_optimistic_concurrency() -> (
            CurationUseCase,
            Arc<MockArtifactRepository>,
            Arc<MockEventStore>,
            Arc<MockArtifactLifecycle>,
        ) {
            let artifacts = Arc::new(MockArtifactRepository::new());
            let events = Arc::new(MockEventStore::new());
            let lifecycle = Arc::new(
                MockArtifactLifecycle::new(artifacts.clone(), events.clone())
                    .with_optimistic_concurrency(),
            );
            let uc = CurationUseCase::new(
                crate::event_store_publisher::wrap_for_test(events.clone()),
                artifacts.clone(),
                lifecycle.clone(),
                Arc::new(MockPolicyProjectionRepository::new()),
                Arc::new(MockCurationQueueRepository::new()),
                Arc::new(MockCurationDecisionsRepository::new()),
                Arc::new(MockCurationExclusionsRepository::new()),
                default_repository_access(),
                Arc::new(MockCurationRuleRepository::new()),
                Arc::new(MockStoragePort::new()),
                HashMap::new(),
            );
            (uc, artifacts, events, lifecycle)
        }

        /// Arm the interleaving the ADR 0060 arms are about: this call's
        /// append loses to an event that landed after the pairing, and
        /// the row the re-read then sees is `after_read`.
        fn arm_lost_append(
            artifacts: &Arc<MockArtifactRepository>,
            events: &Arc<MockEventStore>,
            artifact_id: Uuid,
            after_read: Option<QuarantineStatus>,
        ) {
            let stream_id = StreamId::artifact(artifact_id);
            events.set_stream_after_next_read(
                &stream_id,
                vec![
                    dummy_persisted_event(&stream_id, artifact_id, 0),
                    dummy_persisted_event(&stream_id, artifact_id, 1),
                ],
            );
            match after_read {
                Some(status) => artifacts.set_status_after_next_find_by_id(artifact_id, status),
                None => artifacts.remove_after_next_find_by_id(artifact_id),
            }
        }

        /// ADR 0060 (a) + (b): the append lost, the re-read shows the
        /// artifact released by whoever won, and the entry converges to
        /// an idempotent success with no event of its own.
        #[tokio::test]
        async fn a_lost_append_that_converged_is_an_idempotent_success() {
            let (uc, artifacts, events, lifecycle) = make_use_case_with_optimistic_concurrency();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            arm_lost_append(&artifacts, &events, id, Some(QuarantineStatus::Released));

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation passed"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert_eq!(
                applied.already_released_ids,
                vec![id],
                "the intent is already true, so the entry converges"
            );
            assert!(applied.failed.is_empty());
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "a converged entry appends nothing"
            );
        }

        /// ADR 0060, the half this surface deliberately does **not**
        /// take: the append lost and the artifact has not converged, so
        /// the entry lands in `failed` and is never re-appended. Whatever
        /// won the race is evidence the curator has not reviewed, and
        /// retrying over it would turn a lost race into a release decided
        /// by a stale review.
        #[tokio::test]
        async fn a_lost_append_that_did_not_converge_is_reported_and_never_retried() {
            let (uc, artifacts, events, lifecycle) = make_use_case_with_optimistic_concurrency();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            arm_lost_append(&artifacts, &events, id, Some(QuarantineStatus::Quarantined));

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation passed"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert!(applied.already_released_ids.is_empty());
            assert_eq!(applied.failed.len(), 1);
            assert_eq!(applied.failed[0].0, id);
            assert!(matches!(
                applied.failed[0].1,
                AppError::Domain(DomainError::Conflict(_))
            ));
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no retry: a second append would release on unreviewed evidence"
            );
        }

        /// The re-read itself failed, so convergence could not be
        /// established either way. The entry keeps the append's own
        /// error — that is what happened to it — and is reported.
        #[tokio::test]
        async fn a_lost_append_whose_re_read_fails_keeps_the_conflict() {
            let (uc, artifacts, events, lifecycle) = make_use_case_with_optimistic_concurrency();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            arm_lost_append(&artifacts, &events, id, None);

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation passed"),
            );
            assert_eq!(applied.failed.len(), 1);
            assert!(
                matches!(
                    applied.failed[0].1,
                    AppError::Domain(DomainError::Conflict(_))
                ),
                "the append's own error survives the failed re-read: {:?}",
                applied.failed[0].1
            );
            assert!(applied.already_released_ids.is_empty());
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A non-`Conflict` commit failure is not a lost race, so no
        /// re-read is taken and the entry is reported as it failed.
        #[tokio::test]
        async fn a_non_conflict_commit_failure_takes_no_re_read() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            // If a re-read were taken, it would observe this and
            // misreport the entry as converged.
            artifacts.set_status_after_next_find_by_id(id, QuarantineStatus::Released);
            lifecycle.fail_next_commit(DomainError::Invariant("event store down".into()));

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation passed"),
            );
            assert_eq!(applied.failed.len(), 1);
            assert!(
                applied.already_released_ids.is_empty(),
                "an infrastructure failure must not be reported as convergence"
            );
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// The artifact was released by somebody else between validate
        /// and apply, and the apply step's own load sees it.
        ///
        /// The idempotent success is decided in the **appending**
        /// function here, not in the pre-validation pass — the two
        /// consult one definition of the source-state set, and this is
        /// the half that catches a release landing inside the window.
        /// No event, and the entry is reported as converged rather than
        /// as a refusal the curator has to act on.
        #[tokio::test]
        async fn a_release_inside_the_apply_window_converges_at_the_append_site() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            artifacts.set_status_after_next_checksum_read(id, QuarantineStatus::Released);

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation saw a releasable row"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert_eq!(
                applied.already_released_ids,
                vec![id],
                "the intent was already true by the time the append ran"
            );
            assert!(applied.failed.is_empty());
            assert!(lifecycle.committed_transitions().is_empty());
        }

        /// A stream already at the event cap: the waiver is refused
        /// rather than appending the event that would freeze it.
        #[tokio::test]
        async fn an_over_cap_stream_refuses_the_bulk_waiver() {
            let (uc, artifacts, events, lifecycle) = make_use_case();
            let repo_id = Uuid::new_v4();
            let id = seed_with_digest(
                &artifacts,
                &events,
                repo_id,
                DIGEST_A,
                "blobs/a",
                QuarantineStatus::Quarantined,
            );
            let stream_id = StreamId::artifact(id);
            let full: Vec<_> = (0..1000)
                .map(|p| dummy_persisted_event(&stream_id, id, p))
                .collect();
            events.set_stream(&stream_id, full);

            let applied = expect_applied(
                waive_digests(&uc, repo_id, &[DIGEST_A])
                    .await
                    .expect("pre-validation passed"),
            );
            assert!(applied.released_artifact_ids.is_empty());
            assert_eq!(applied.failed.len(), 1);
            assert!(
                applied.failed[0].1.to_string().contains("1000-event cap"),
                "got: {}",
                applied.failed[0].1
            );
            assert!(lifecycle.committed_transitions().is_empty());
        }
    }
}
