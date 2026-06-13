//! `CurationUseCase` (`waive` + `block`).
//!
//! Curator decision authority over quarantined / non-terminal artifacts.
//! Mirrors `QuarantineUseCase::admin_release` structurally: privilege
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
//! any append. See design doc §2.3 amendment for the rationale.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::artifact::{
    ProvenanceClearance, QuarantineStatus, ReleaseAuthorization,
};
use hort_domain::error::DomainError;
use hort_domain::events::{Actor, ApiActor, DomainEvent, ReleaseReason, StreamId};
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
use hort_domain::ports::event_store::{AppendEvents, EventToAppend};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;
use hort_domain::types::PageRequest;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{emit_curation_decision, CurationDecisionLabel, CurationDecisionResult};
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::repository_access::RepositoryAccessUseCase;
use crate::use_cases::upstream_index_cache_invalidator::invalidate_after_reject;
use crate::use_cases::{read_expected_version, CallerPrivileges};

/// Maximum justification length in BYTES.
/// Mirrors `MAX_JUSTIFICATION_LEN` semantics on `ArtifactReleased::validate`.
const MAX_JUSTIFICATION_BYTES: usize = 512;

/// Maximum number of versions per `BlockTarget::VersionList` call.
/// Mirrors the queue `limit` shape — bounded per-call work (design §2.7).
const MAX_VERSIONS_PER_CALL: usize = 100;

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

/// Target of a [`CurationUseCase::block`] call (design doc §2.3 / §3).
#[derive(Debug, Clone, PartialEq)]
pub enum BlockTarget {
    /// Single-artifact block — the canonical primitive.
    Artifact(Uuid),
    /// Bulk block by explicit `(repository, package, versions)` list.
    /// Versions that don't resolve to an artifact_id surface in
    /// [`BlockOutcome::not_found_versions`] (NOT auto-blocked on future
    /// ingest — design §1 OOS).
    VersionList {
        repository_id: Uuid,
        package: String,
        versions: Vec<String>,
    },
}

/// Result envelope for [`CurationUseCase::block`] (design doc §3).
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
    /// Per-append failures (continue-on-error per design §2.3): the
    /// artifact_id + the `AppError` returned by the event-store
    /// commit. Successful appends in the same call are NOT rolled
    /// back.
    pub failed: Vec<(Uuid, AppError)>,
}

/// Application use case for curator decisions on artifacts and
/// finding-exclusions. See module docs.
pub struct CurationUseCase {
    events: Arc<EventStorePublisher>,
    artifacts: Arc<dyn ArtifactRepository>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    /// Per-row deadline resolution for `list_queue` (Item 6). Held
    /// from Item 5 so the constructor is one-shot; method body lands
    /// with Item 6's adapter.
    #[allow(dead_code)]
    policies: Arc<dyn PolicyProjectionRepository>,
    /// Queue listing port (Item 6).
    queue_repo: Arc<dyn CurationQueueRepository>,
    /// Decisions listing port (Item 7).
    decisions_repo: Arc<dyn CurationDecisionsRepository>,
    /// Active-exclusions listing port (Item 8).
    exclusions_repo: Arc<dyn CurationExclusionsRepository>,
    /// Repository-key resolution
    /// for the `hort_curation_decisions_total{repository}` label. Uses
    /// the existing `metric_label(repository_id)` helper which already
    /// handles the `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse
    /// to `_all` and the resolve-failure fallback to `unknown`. No new
    /// port; the use case threads through the existing read path.
    repository_access: Arc<RepositoryAccessUseCase>,
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
    /// All 7 fields are wired from Item 5; the three `_repo` fields'
    /// `list_*` methods land with Items 6/7/8 alongside their Postgres
    /// adapters.
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
    /// boundary check `admin_release`'s HTTP layer performs; this
    /// helper is the use-case-side gate so a `CurationUseCase` consumer
    /// (CLI, HTTP, or future SDK) gets the same validation.
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

    /// Paginated read-only listing of curator-actionable artifacts
    /// (design §2.5). One row per artifact currently in
    /// `Quarantined` / `Rejected` / `ScanIndeterminate` (the
    /// curator-actionable set), with per-row quarantine deadline
    /// resolved at query time and a rejection-reason discriminator
    /// for rejected rows.
    ///
    /// Authority: `Permission::Curate` OR `Permission::Admin`
    /// (design §2.7 — same authority as `waive` / `block`). Denial is
    /// `info!` (architect rule — not `err`).
    ///
    /// **Per-row deadline.** The adapter resolves
    /// `effective_quarantine_deadline(window_start, duration)` per
    /// row in SQL via a join to `policy_projections` (design §2.5);
    /// the use case does NOT pre-resolve a duration parameter. This
    /// preserves both the `limit` cap (single query) and the
    /// cross-repo result set (variable durations).
    ///
    /// **Rejection reason** is extracted by the adapter via a
    /// LATERAL JOIN against the artifact's latest `ArtifactRejected`
    /// event (design §2.5 — bounded by `limit` × one indexed event-
    /// store lookup; queue browsing is operator-driven, low QPS).
    ///
    /// **No metric emission in Item 6** — queue listings are
    /// operator-paced reads; the design's `hort_curation_decisions_total`
    /// covers decisions, not reads. A queue-listing-specific metric is
    /// not implemented.
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

    /// Paginated event-log scan of curator decisions (design §2.9). One
    /// row per event — `--by-correlation` collapse is an HTTP/CLI
    /// rendering concern (Items 10 / 13), NOT a port-level flag.
    ///
    /// Authority: `Permission::Curate` OR `Permission::Admin` (design
    /// §2.9 — same gate as `list_queue`). Denial is `info!` (architect
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
    /// Mirrors `list_queue` shape (Item 6).
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
        //    MAX_QUEUE_LIMIT` is a caller-input issue (design §3 — limit
        //    capped at 500), not a system error — Validation.
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

    /// Paginated current-state listing of active CVE exclusions
    /// (design §2.9). Distinct from `list_decisions` because
    /// exclusions have **ongoing state** (active until removed or
    /// expired); decisions are point-in-time. Reuses the existing
    /// `exclusion_projections` table — no new projection.
    ///
    /// Authority: `Permission::Curate` OR `Permission::Admin` (design
    /// §2.9 — same gate as `list_queue` / `list_decisions`). Denial
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

    /// Curator-driven release of a `Quarantined` artifact.
    ///
    /// Mirrors `QuarantineUseCase::admin_release`. Source-state guard
    /// is `Quarantined` ONLY (design doc §2.2) — curator does NOT
    /// clear stuck-scanner artifacts (`ScanIndeterminate`), which
    /// stays admin-only.
    ///
    /// Audit: emits `ArtifactReleased { authority: CuratorWaiver,
    /// released_by_user_id: Some(actor.user_id), justification:
    /// Some(_), reason: Curator, … }`.
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
        //    interaction (design §2.3: "the same justification text
        //    rides every event the call emits, so an oversize
        //    justification fails the call fast").
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

        let expected_version = match read_expected_version(&*self.events, &stream_id, false).await {
            Ok(v) => v,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(CurationDecisionLabel::Waive, None, result);
                return Err(e);
            }
        };

        let mut artifact = match self.artifacts.find_by_id(artifact_id).await {
            Ok(a) => a,
            Err(e) => {
                let app_err = AppError::Domain(e);
                let result = classify_append_error(&app_err);
                emit_curation_decision(CurationDecisionLabel::Waive, None, result);
                return Err(app_err);
            }
        };
        let prior_status = artifact.quarantine_status;
        let repository_id = artifact.repository_id;
        // Resolve `repository_id → key` for the
        // metric label using the existing `RepositoryAccessUseCase`
        // helper. The helper handles the `METRICS_INCLUDE_REPOSITORY_LABEL`
        // collapse to `_all` and the resolve-failure fallback to
        // `unknown`. Single bounded query — no N+1 (one artifact per
        // `waive` call).
        let repo_label = self.repository_access.metric_label(repository_id).await;

        // 3) Domain transition. Source-state guard inside
        //    `Artifact::release` rejects every non-`Quarantined`
        //    state. The deny-by-default release
        //    predicate (ADR 0007) accepts only
        //    `(Curator, CuratorWaiver)` for this authority.
        let mut event_payload = match artifact.release(
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

        tracing::info!(
            artifact_id = %artifact_id,
            actor_id = %user_id,
            correlation_id = %correlation_id,
            outcome = "ok",
            "curator waived quarantined artifact"
        );
        Ok(())
    }

    /// Curator-driven block — transitions `None` / `Quarantined` /
    /// `Released` → `Rejected`. Already-`Rejected` is an idempotent
    /// no-op (counted in `BlockOutcome.already_rejected_ids`; no event
    /// appended). Audit: emits `ArtifactRejected { rejected_by:
    /// Curator { curator_id }, reason: <justification> }` per
    /// transitioned artifact.
    ///
    /// **Continue-on-error.** Per-append failures land in
    /// `BlockOutcome.failed`; successful appends are not rolled back
    /// (design §2.3 amendment). The justification cap is enforced ONCE
    /// at the call boundary.
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

        // 2) Justification cap — single boundary check (design §2.3 —
        //    "same justification text rides every event the call
        //    emits").
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
            failed: Vec::new(),
        };

        match target {
            BlockTarget::Artifact(artifact_id) => {
                // Single-artifact target: `find_by_id` IS the resolution
                // step. A miss here is a top-level `Err(NotFound)` —
                // matching `waive`'s shape, so the HTTP handler (Item 9)
                // can map it to 404 without inspecting the envelope.
                // The continue-on-error envelope semantics (per design
                // §2.3) apply specifically to `BlockTarget::VersionList`
                // where N artifacts share a call; the single-artifact
                // case is N=1 and the operator already knows what they
                // targeted. See module docs and Item 5's review notes.
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
                    // emit `_all` (Item 14: `None` collapses to the
                    // sentinel at the helper). `block_one`'s own emit
                    // sites resolve the key once the second `find_by_id`
                    // succeeds.
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
                // Per-call cap (design §2.7): bounded work per call.
                if versions.is_empty() {
                    let e = AppError::Domain(DomainError::Validation(
                        "versions must be non-empty".into(),
                    ));
                    tracing::info!(
                        actor_id = %user_id,
                        outcome = "invalid",
                        "curation block VersionList: empty list"
                    );
                    emit_curation_decision(
                        CurationDecisionLabel::Block,
                        None,
                        CurationDecisionResult::Invalid,
                    );
                    return Err(e);
                }
                if versions.len() > MAX_VERSIONS_PER_CALL {
                    let e = AppError::Domain(DomainError::Validation(format!(
                        "versions length {} exceeds {} cap",
                        versions.len(),
                        MAX_VERSIONS_PER_CALL,
                    )));
                    tracing::info!(
                        actor_id = %user_id,
                        versions_len = versions.len(),
                        outcome = "invalid",
                        "curation block VersionList: oversize"
                    );
                    emit_curation_decision(
                        CurationDecisionLabel::Block,
                        None,
                        CurationDecisionResult::Invalid,
                    );
                    return Err(e);
                }

                // Resolve each version → artifact_id via
                // `find_by_name_in_repo`. The page bound is the
                // resolution cap; misses go to `not_found_versions`.
                let page = self
                    .artifacts
                    .find_by_name_in_repo(
                        repository_id,
                        &package,
                        PageRequest {
                            offset: 0,
                            limit: VERSION_RESOLUTION_PAGE_LIMIT,
                        },
                    )
                    .await;
                let candidates = match page {
                    Ok(p) => p.items,
                    Err(e) => {
                        let app_err = AppError::Domain(e);
                        let result = classify_append_error(&app_err);
                        // One tick for the whole call — resolution
                        // failure precedes any per-append iteration.
                        // `VersionList` carries `repository_id` so we
                        // can resolve a key for the metric even when
                        // the listing port failed (the key lookup is
                        // a different DB read).
                        let repo_label = self.repository_access.metric_label(repository_id).await;
                        emit_curation_decision(
                            CurationDecisionLabel::Block,
                            Some(&repo_label),
                            result,
                        );
                        tracing::info!(
                            actor_id = %user_id,
                            correlation_id = %correlation_id,
                            outcome = result.as_str(),
                            "curation block VersionList: resolution failed"
                        );
                        return Err(app_err);
                    }
                };

                for v in versions {
                    let resolved = candidates
                        .iter()
                        .find(|a| a.version.as_deref() == Some(v.as_str()));
                    match resolved {
                        Some(a) => {
                            // Stage 2: `block_one` re-loads via
                            // `find_by_id` to pick up the freshest
                            // `quarantine_status` (the resolution page
                            // can race the curator). A stage-2 NotFound
                            // (race: artifact deleted between resolve
                            // and append) goes to `outcome.failed` per
                            // continue-on-error (design §2.3) — the
                            // call does not abort the remaining
                            // versions.
                            self.block_one(
                                a.id,
                                &actor,
                                user_id,
                                &justification,
                                correlation_id,
                                &mut outcome,
                            )
                            .await;
                        }
                        None => {
                            outcome.not_found_versions.push(v);
                        }
                    }
                }
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
    /// Per-call metric emission (design §7): ONE tick per attempted
    /// append (not per call). `ok` for transitioned, `conflict` for
    /// failed-append (event-store conflict / domain Invariant), etc.
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

        let expected_version = match read_expected_version(&*self.events, &stream_id, false).await {
            Ok(v) => v,
            Err(e) => {
                let result = classify_append_error(&e);
                emit_curation_decision(CurationDecisionLabel::Block, None, result);
                outcome.failed.push((artifact_id, e));
                return;
            }
        };

        let mut artifact = match self.artifacts.find_by_id(artifact_id).await {
            Ok(a) => a,
            Err(e) => {
                let app_err = AppError::Domain(e);
                let result = classify_append_error(&app_err);
                emit_curation_decision(CurationDecisionLabel::Block, None, result);
                outcome.failed.push((artifact_id, app_err));
                return;
            }
        };
        // Resolve `repository_id → key` once
        // per attempted append (single bounded query). For
        // `BlockTarget::VersionList` this is one lookup per resolved
        // version (N <= 100 per call cap, design §2.7). The cardinality
        // knob `METRICS_INCLUDE_REPOSITORY_LABEL=false` short-circuits
        // every call to the `_all` sentinel without touching the DB,
        // so operators at scale pay no cost.
        let repository_id = artifact.repository_id;
        let repo_label = self.repository_access.metric_label(repository_id).await;

        // Idempotent no-op: already-Rejected short-circuits with NO
        // event appended.
        if artifact.quarantine_status == QuarantineStatus::Rejected {
            outcome.already_rejected_ids.push(artifact_id);
            emit_curation_decision(
                CurationDecisionLabel::Block,
                Some(&repo_label),
                CurationDecisionResult::Ok,
            );
            return;
        }

        let prior_status = artifact.quarantine_status;

        let event_payload = match artifact.block_by_curator(user_id, justification.to_owned()) {
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

/// Classify an `AppError` into the `result` metric label (design §7).
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

    // -- Stub ports for the Item-5 use case --------------------------------
    //
    // These stubs match the trait but panic on call: Item 5 wires the
    // ports into `CurationUseCase` from construction (the
    // port-only-construction discipline) but does NOT exercise their
    // method bodies — `waive` / `block` only touch `events` / `artifacts`
    // / `lifecycle`. Items 6-8 add proper mocks alongside their
    // `list_*` use-case-method bodies.

    /// Item 6 — proper mock that records `list_queue` calls and
    /// returns a configurable Vec. Replaces the Item-5 panic-on-call
    /// stub now that the use case calls the port.
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

    /// Item 7 — proper mock that records `list_decisions` calls and
    /// returns a configurable Vec. Replaces the Item-5 panic-on-call
    /// stub now that the use case calls the port.
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

    /// Item 8 — proper mock that records `list_exclusions` calls and
    /// returns a configurable Vec. Replaces the Item-5 panic-on-call
    /// stub now that the use case calls the port.
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
    /// Item 14 metric-label tests that assert the resolved key is
    /// threaded through to `hort_curation_decisions_total{repository}`.
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
    /// pre-built `RepositoryAccessUseCase` — used by Item 14 metric-
    /// label tests that need the lookup to return a specific key.
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
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
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
        );
        (uc, artifacts, events, lifecycle)
    }

    /// Variant of [`make_use_case`] that exposes the
    /// `MockCurationQueueRepository` for inspection by Item-6
    /// `list_queue` tests.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_queue() -> (CurationUseCase, Arc<MockCurationQueueRepository>) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
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
        );
        (uc, queue_repo)
    }

    /// Variant of [`make_use_case`] that exposes the
    /// `MockCurationDecisionsRepository` for inspection by Item-7
    /// `list_decisions` tests.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_decisions() -> (CurationUseCase, Arc<MockCurationDecisionsRepository>) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
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
        );
        (uc, decisions_repo)
    }

    /// Variant of [`make_use_case`] that exposes the
    /// `MockCurationExclusionsRepository` for inspection by Item-8
    /// `list_exclusions` tests.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_exclusions() -> (CurationUseCase, Arc<MockCurationExclusionsRepository>) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
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
    /// `read_expected_version` resolves a non-`NoStream` version
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

    /// Source-state guard: `waive` rejects non-`Quarantined` states.
    /// `ScanIndeterminate` stays admin-only via `admin_release` per
    /// design §2.2.
    #[tokio::test]
    async fn waive_non_quarantined_source_state_rejected() {
        let (uc, artifacts, events, lifecycle) = make_use_case();
        let artifact_id =
            seed_artifact_with_stream(&artifacts, &events, QuarantineStatus::ScanIndeterminate);
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
            err.to_string().contains("release"),
            "expected domain release-guard error, got: {err}"
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
    /// access — per-call cap (design §2.7).
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

    /// Oversize justification fails fast — once at the call boundary
    /// (design §2.3). No append, no resolution.
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
    // Continue-on-error (design §2.3 amendment)
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
    // list_queue (Item 6)
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
            quarantine_status: QuarantineStatus::Quarantined,
            quarantine_window_start: DateTime::<Utc>::from_timestamp(1_700_000_000, 0),
            quarantine_deadline: DateTime::<Utc>::from_timestamp(1_700_086_400, 0),
            finding_count: 3,
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
    /// called. Adapter clamps defensively (Item 6 §2.5), but the
    /// use-case-side gate is the authoritative check.
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
    // list_decisions (Item 7)
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
    // list_exclusions (Item 8)
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
    // Item 14 — `hort_curation_decisions_total` metric emission tests.
    //
    // Pin the `decision`, `repository`, and `result` labels per design
    // §7. The `repository` label is the M-2 resolution: when a repo
    // exists for the artifact's `repository_id`, the label is the key;
    // when `METRICS_INCLUDE_REPOSITORY_LABEL=false`, the helper
    // collapses to `_all`; when the lookup misses, the helper falls to
    // `unknown`.
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

    /// `waive` happy path emits exactly one
    /// `hort_curation_decisions_total{decision=waive, repository=<key>,
    /// result=ok}` tick — the resolved repo key flows through the
    /// new `RepositoryAccessUseCase::metric_label` lookup, NOT the
    /// `_all` fallback that Item 5 emitted before M-2.
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
    /// append (design §7 — "per-append per call"). Three transitioned
    /// versions → three `ok` ticks, all carrying the same resolved
    /// repo key (the VersionList target's `repository_id` is the same
    /// for every version).
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
    /// Pins the design §7 "per-attempted-append" semantics on the
    /// loop's failure branch.
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
}
