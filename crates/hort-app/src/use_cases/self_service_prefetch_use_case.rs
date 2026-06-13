//! `SelfServicePrefetchUseCase` (see
//! `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! The repo-keyed, JWT-only self-service prefetch endpoint backing
//! `POST /api/v1/repositories/{repo_key}/prefetch`. The I/O-bearing
//! orchestration: repo resolution, the `Read ∧ Prefetch` RBAC gate, the
//! token-kind gate, per-item upstream version resolution, a Hort-side
//! held/rejected pre-flight via
//! `ArtifactRepository::package_version_status`, and per-item job enqueue
//! via `JobsRepository::enqueue_task`.
//!
//! # Explicit path — NOT gated by the auto-trigger policy
//!
//! This is the EXPLICIT operator prefetch path (the honest
//! replacement for the removed `OnIndexFetch` implicit trigger). It does
//! NOT route the enqueue decision through the automatic-trigger planner
//! (`prefetch_use_case::PrefetchUseCase`): that planner's
//! `policy.enabled` / `policy.triggers.contains(TransitiveDeps)` gates
//! govern the *automatic* triggers and the *on-ingest* cascade, and
//! applying them here made every explicit prefetch a silent no-op on a
//! default proxy repo (`PrefetchPolicy::default()` is disabled with no
//! triggers). An accepted item is enqueued directly as a `prefetch`
//! leaf-ingest — a fresh ingest via the existing
//! pull-through path; the cascade fires on completion. The transitive
//! cascade and its `max_descendants` cap apply later, only if the
//! ingested root has declared dependencies and the repo opts into the
//! `TransitiveDeps` trigger. (The `prefetch-dependencies` cascade-driver
//! kind cannot ingest a fresh root — see the `PREFETCH_INGEST_KIND`
//! docstring.)
//!
//! # Gate order
//!
//! 1. **Token-kind gate** — `caller.token_kind == Some(TokenKind::CliSession)`
//!    is required. PATs and service-account tokens are rejected with
//!    `Forbidden`. Fires first (cheapest — no repo resolution required)
//!    and emits `result="token_kind_denied"` ONCE per call.
//! 2. **RBAC gate** — `Permission::Read ∧ Permission::Prefetch` on the
//!    resolved repo (§2.5 Finding E — BOTH required). Denial emits
//!    `result="permission_denied"` ONCE per call.
//! 3. **OCI rejection** — if the repo's format is `"oci"`, emits
//!    `result="oci_unsupported"` ONCE per call and returns the §8 exact
//!    wording wrapped in [`DomainError::Validation`].
//!
//! All three gates short-circuit per CALL (not per item). After all
//! three pass, the use case iterates `items` and emits per-item ticks
//! for the remaining ten `result` values (a 100-item batch with 80
//! successes + 15 rejected + 5 timeouts produces 100 ticks).
//!
//! # Per-item orchestration (§§6.3-6.5, §6.4a)
//!
//! For each [`PrefetchRequestItem`]:
//!
//! - **Resolve version.** If `item.version` is `None`, call
//!   [`UpstreamMetadataPort::list_versions`] and pick the newest per the
//!   format's [`VersionOrdering`]. An empty upstream list or an
//!   upstream-fetch failure surfaces in the `failed` bucket (or
//!   `not_found` for the 404 case).
//! - **Pre-flight against Hort's held set.** Read
//!   [`ArtifactRepository::package_version_status`] for the package
//!   and dispatch by the resolved version's status:
//!   - `Released` ∨ `Quarantined` (incl. the read-time
//!     `QuarantinedAwaitingRelease` derivation) → `skipped_already_held`
//!     (the artifact is locally ingested; already covered).
//!   - `None` → **ENQUEUE**. For a proxy, `None` means "known upstream,
//!     not locally ingested" — exactly what to warm. `None` is NOT
//!     "already held"; the old code mistook proxy `None` for an
//!     un-quarantined hosted upload and skipped every upstream version.
//!   - `Rejected` → `rejected_packages` with
//!     [`RejectionReason::ScanRejected`]; emits
//!     `result="rejected_version"` per-item (auto-release-bypass
//!     anti-pattern — re-prefetch is refused).
//!   - `ScanIndeterminate` → `rejected_packages` with
//!     [`RejectionReason::ScanIndeterminate`]; emits
//!     `result="rejected_version"` per-item.
//! - **Enqueue.** When the version is not locally held (status `None`,
//!   or absent from Hort's catalog), enqueue a `prefetch` **leaf-ingest**
//!   `jobs` row directly via [`JobsRepository::enqueue_task`] — no
//!   auto-trigger planner gate (see "Explicit path" above). This is the
//!   existing pull-through path: the worker's
//!   `PrefetchIngestHandler` pulls `(repository_id, package, version)`
//!   from upstream and `ingest_verified`s it (→ `quarantined`); the
//!   transitive-dep cascade fires *on completion* via the
//!   `IngestUseCase` on-ingest hook when the repo's
//!   `prefetch_policy.triggers` contains `TransitiveDeps`. (Earlier
//!   builds enqueued the `prefetch-dependencies` cascade-DRIVER kind
//!   directly: that handler requires an already-ingested
//!   `artifact_id`, so a fresh-root row failed worker deserialization
//!   and nothing ingested.) A `DomainError::Conflict` from the
//!   single-flight surfaces as `skipped_already_held` (NOT
//!   `failed` — another caller's enqueue is already covering this
//!   version).
//!
//! # Continue-on-error
//!
//! Per-item failures partition into the four [`PrefetchOutcome`]
//! envelope buckets; the batch never aborts on a single bad item. This
//! mirrors the `BlockOutcome` shape at
//! `crates/hort-app/src/use_cases/curation_use_case.rs:118` (§3.1 design
//! note).
//!
//! # Observability
//!
//! - `#[tracing::instrument(skip(self))]` on the public method.
//!   **No `err`** per the architect-doc rule (`err` conflates privilege
//!   denials with infrastructure errors).
//! - Token-kind / RBAC denials → `tracing::info!` (audit trail — this
//!   is a security-sensitive operation).
//! - Success → `tracing::info!` per §7 with fields `repo_key`,
//!   `package_count`, `caller_user_id`, `caller_token_kind`. Package
//!   names are intentionally NOT logged at info — they could amplify
//!   index cardinality on busy deployments.
//! - One `hort_prefetch_self_service_total{format, repository, result}`
//!   tick per call for the three short-circuit gates; per-item ticks
//!   for everything else (§7 tick semantics).

use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::instrument;

use hort_domain::entities::api_token::TokenKind;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::discovery::{
    FailedItem, PackageCoords, PrefetchItemError, PrefetchOutcome, PrefetchRequestItem,
    RejectedItem, RejectionReason,
};
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::repository::{Repository, RepositoryFormat};
use hort_domain::error::DomainError;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingRepository,
};

use crate::error::{AppError, AppResult};
use crate::metrics::{
    emit_prefetch_self_service, prefetch_self_service_result_from_item_error, values,
    PrefetchSelfServiceResult, UpstreamFetchError,
};
use crate::ports::upstream_metadata::UpstreamMetadataPort;
use crate::rbac::RbacEvaluator;
use crate::use_cases::index_serve_filter::{
    CargoSemverOrdering, NpmSemverOrdering, Pep440Ordering, VersionOrdering,
};

// Exact wording propagated verbatim to the client via
// `AppError::Domain(DomainError::Validation(_))`. Mirrors the constant
// in `discovery_use_case` byte-for-byte (the OCI rejection is shared
// across both endpoints).
const OCI_UNSUPPORTED_MESSAGE: &str =
    "discovery + prefetch are not supported for OCI; use registry-protocol-native \
     catalog/tags endpoints, or warm via crane pull";

const TOKEN_KIND_DENIED_MESSAGE: &str = "this endpoint requires a CLI session token";

/// `kind` value passed to [`JobsRepository::enqueue_task`] for each
/// per-item enqueue: the **leaf-ingest** kind
/// (`PrefetchIngestHandler`) — the existing pull-through
/// path. The handler pulls `(repository_id, package, version)` from
/// upstream and `ingest_verified`s it; its on-ingest hook then fires
/// the `prefetch-dependencies` cascade *on completion* with the freshly
/// ingested `artifact_id` — when the repo's `prefetch_policy.triggers`
/// contains `TransitiveDeps`.
///
/// **Why not `"prefetch-dependencies"`:** that kind is the
/// cascade-DRIVER — its
/// `PrefetchDependenciesHandler` requires an already-ingested
/// `artifact_id` to read an existing manifest; it does **not** ingest a
/// fresh root. A self-service row carrying no `artifact_id` would fail
/// the worker's deserialization ("missing field `artifact_id`"),
/// terminally fail the job, and ingest nothing — silently, since the
/// API has already returned the job id. The leaf-ingest kind is what
/// realises "triggers a fresh ingest via the existing pull-through
/// path … the cascade fires on completion".
const PREFETCH_INGEST_KIND: &str = "prefetch";

/// `trigger_source` value passed to [`JobsRepository::enqueue_task`]
/// for self-service enqueues. Distinguishes operator-initiated
/// prefetches from cascade-initiated ones (`"ingest"` from the
/// register-by-hash cascade), supporting operator-side audit.
const PREFETCH_TRIGGER_SOURCE: &str = "self_service";

/// Application use case for the repo-keyed self-service prefetch
/// endpoint.
///
/// Concrete `pub struct`, NOT a trait — mirrors every other use case
/// in `crates/hort-app/src/use_cases/`. Use cases are not dyn-dispatched
/// in this codebase; introducing a `pub trait SelfServicePrefetchUseCase`
/// would be a one-off pattern with no justification.
pub struct SelfServicePrefetchUseCase {
    repositories: Arc<dyn RepositoryRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    upstream_metadata: Arc<dyn UpstreamMetadataPort>,
    jobs: Arc<dyn JobsRepository>,
    rbac: Arc<ArcSwap<RbacEvaluator>>,
}

impl SelfServicePrefetchUseCase {
    /// Construct a new `SelfServicePrefetchUseCase` from its outbound
    /// ports.
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        upstream_metadata: Arc<dyn UpstreamMetadataPort>,
        jobs: Arc<dyn JobsRepository>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
    ) -> Self {
        Self {
            repositories,
            artifacts,
            upstream_mappings,
            upstream_metadata,
            jobs,
            rbac,
        }
    }

    /// Enqueue a self-service prefetch batch for `repo_key`. See
    /// module-level docs for the full contract.
    #[instrument(skip(self, items))]
    pub async fn enqueue_self_service(
        &self,
        repo_key: &str,
        items: Vec<PrefetchRequestItem>,
        caller: &CallerPrincipal,
    ) -> AppResult<PrefetchOutcome> {
        // -------- Gate 1: token-kind (cheapest first per §2.6) --------
        //
        // Pre-repo-resolution — fires before any port I/O. The `format`
        // label is unknown here because we have not resolved the repo
        // yet; emit `FORMAT_UNKNOWN` per the catalog's missing-format
        // sentinel rule. Per §7 the `repository` label collapses to
        // `REPOSITORY_ALL` for pre-resolution gate ticks.
        if caller.token_kind != Some(TokenKind::CliSession) {
            tracing::info!(
                caller_user_id = %caller.user_id,
                caller_token_kind = ?caller.token_kind,
                outcome = "denied",
                "self-service prefetch denied: token kind is not CliSession",
            );
            emit_prefetch_self_service(
                values::FORMAT_UNKNOWN,
                values::REPOSITORY_ALL,
                PrefetchSelfServiceResult::TokenKindDenied,
            );
            return Err(AppError::Domain(DomainError::Forbidden(
                TOKEN_KIND_DENIED_MESSAGE.into(),
            )));
        }

        // -------- Resolve repository (anti-enumeration via NotFound) --
        //
        // Mirrors `discovery_use_case` — a missing repo collapses to
        // `NotFound` without ticking a metric (per the catalog's
        // 13-value `result` ceiling — adding a "repo not found" bucket
        // would inflate cardinality without operator-actionable benefit;
        // the 404 envelope is the signal).
        let repository = match self.repositories.find_by_key(repo_key).await {
            Ok(r) => r,
            Err(DomainError::NotFound { .. }) => {
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Repository",
                    id: repo_key.to_string(),
                }));
            }
            Err(other) => return Err(AppError::Domain(other)),
        };
        let format_label = repository.format.to_string();
        let repository_label = repository.key.clone();

        // -------- Gate 2: RBAC `Permission::Read ∧ Permission::Prefetch` --
        //
        // Both required per §2.5 Finding E — `Prefetch` alone without
        // `Read` would let an actor amplify against a repo they cannot
        // enumerate; the AND aligns prefetch authority with discovery
        // authority. One denial tick per call (not two — the operator
        // sees a single failure mode).
        let evaluator = self.rbac.load();
        let has_read = evaluator.authorize(caller, Permission::Read, Some(repository.id));
        let has_prefetch = evaluator.authorize(caller, Permission::Prefetch, Some(repository.id));
        if !(has_read && has_prefetch) {
            tracing::info!(
                caller_user_id = %caller.user_id,
                repository = %repository.key,
                has_read,
                has_prefetch,
                outcome = "denied",
                "self-service prefetch denied: missing Permission::Read AND Permission::Prefetch on repository",
            );
            emit_prefetch_self_service(
                &format_label,
                &repository_label,
                PrefetchSelfServiceResult::PermissionDenied,
            );
            return Err(AppError::Domain(DomainError::Forbidden(format!(
                "Permission::Read AND Permission::Prefetch required on repository {}",
                repository.key,
            ))));
        }

        // -------- Gate 3: OCI rejection (§8 non-goal) ------------------
        //
        // The check is on the resolved repo's format — no need to
        // round-trip the upstream port to learn the format is OCI; the
        // dispatch table would just bounce `UnsupportedFormat` back.
        // One tick per call.
        if repository.format == RepositoryFormat::Oci {
            tracing::info!(
                caller_user_id = %caller.user_id,
                repository = %repository.key,
                "self-service prefetch rejected: OCI format is a §8 non-goal",
            );
            emit_prefetch_self_service(
                &format_label,
                &repository_label,
                PrefetchSelfServiceResult::OciUnsupported,
            );
            return Err(AppError::Domain(DomainError::Validation(
                OCI_UNSUPPORTED_MESSAGE.into(),
            )));
        }

        // -------- Resolve upstream mapping (catch-all per §6.2) -------
        //
        // The mapping resolver mirrors `discovery_use_case` and every
        // other repo-scoped proxy call site: pick the catch-all
        // (`path_prefix == ""`) mapping if present. A hosted-only repo
        // (no mapping) cannot resolve `version = None`, so per-item
        // version resolution surfaces that case as a `failed` /
        // `UpstreamNotFound` entry; an explicit version still gets
        // pre-flight-checked + planned.
        let mapping_opt = self
            .upstream_mappings
            .list_for_repository(repository.id)
            .await
            .map_err(AppError::Domain)?
            .into_iter()
            .find(|m| m.path_prefix.is_empty());

        // Per-format ordering for the "pick latest" path (version = None
        // resolves to the newest upstream-advertised version). The
        // `+ Sync` bound is load-bearing — the per-item async loop
        // holds the ref across `.await` points, which requires the
        // resulting future to be `Send` (and for that, every borrow
        // held across an await must be `Sync`).
        let ordering: &(dyn VersionOrdering + Sync) = ordering_for_format(&repository.format);

        // -------- Per-item iteration ----------------------------------
        let item_count = items.len();
        let mut outcome = PrefetchOutcome {
            enqueued_job_ids: Vec::new(),
            skipped_already_held: Vec::new(),
            rejected_packages: Vec::new(),
            failed: Vec::new(),
        };

        for item in items {
            self.process_item(
                &repository,
                &format_label,
                &repository_label,
                &mapping_opt,
                ordering,
                item,
                &mut outcome,
            )
            .await;
        }

        // -------- Success log (audit trail per §7) --------------------
        tracing::info!(
            repo_key = %repository.key,
            package_count = item_count,
            caller_user_id = %caller.user_id,
            caller_token_kind = ?caller.token_kind,
            enqueued = outcome.enqueued_job_ids.len(),
            skipped = outcome.skipped_already_held.len(),
            rejected = outcome.rejected_packages.len(),
            failed = outcome.failed.len(),
            "self-service prefetch enqueued",
        );

        Ok(outcome)
    }

    /// Single-item orchestration. Extracted from the batch loop so the
    /// continue-on-error contract is explicit at every per-item branch
    /// (no `?` propagation inside the loop; every error path lands in
    /// the envelope, not aborts the batch).
    #[allow(clippy::too_many_arguments)]
    async fn process_item(
        &self,
        repository: &Repository,
        format_label: &str,
        repository_label: &str,
        mapping_opt: &Option<RepositoryUpstreamMapping>,
        ordering: &(dyn VersionOrdering + Sync),
        item: PrefetchRequestItem,
        outcome: &mut PrefetchOutcome,
    ) {
        // ----- Resolve version (None ⇒ latest upstream) --------------
        let coords_request = PackageCoords {
            package: item.package.clone(),
            version: item.version.clone(),
        };

        let resolved_version = match item.version.clone() {
            Some(v) => v,
            None => {
                // Latest-upstream path requires a mapping AND a
                // successful list_versions call AND a non-empty result.
                let Some(mapping) = mapping_opt.as_ref() else {
                    // Hosted-only repo with `version = None` cannot
                    // resolve a latest — surface as a "not found"
                    // failure (no upstream catalog to consult).
                    outcome.failed.push(FailedItem {
                        coords: coords_request,
                        error: PrefetchItemError::UpstreamNotFound,
                    });
                    emit_prefetch_self_service(
                        format_label,
                        repository_label,
                        PrefetchSelfServiceResult::NotFound,
                    );
                    return;
                };
                match self
                    .upstream_metadata
                    .list_versions(format_label, mapping, &item.package)
                    .await
                {
                    Ok(versions) => {
                        let latest = versions
                            .iter()
                            .max_by(|a, b| ordering.compare(a, b))
                            .cloned();
                        match latest {
                            Some(v) => v,
                            None => {
                                // Upstream returned empty version set —
                                // treat as not-found (the package is
                                // unknown to the upstream catalog).
                                outcome.failed.push(FailedItem {
                                    coords: coords_request,
                                    error: PrefetchItemError::UpstreamNotFound,
                                });
                                emit_prefetch_self_service(
                                    format_label,
                                    repository_label,
                                    PrefetchSelfServiceResult::NotFound,
                                );
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        let item_err = upstream_fetch_to_item_error(&err);
                        outcome.failed.push(FailedItem {
                            coords: coords_request,
                            error: item_err,
                        });
                        emit_prefetch_self_service(
                            format_label,
                            repository_label,
                            prefetch_self_service_result_from_item_error(item_err),
                        );
                        return;
                    }
                }
            }
        };

        // Coords now carry the *resolved* version — when the caller
        // sent `version = None`, the operator-facing envelope still
        // records what HORT chose (so dashboards can correlate inputs).
        let coords_resolved = PackageCoords {
            package: item.package.clone(),
            version: Some(resolved_version.clone()),
        };

        // ----- Pre-flight against HORT's held set (§§6.3-6.5, §6.4a) ---
        let held_status = match self
            .artifacts
            .package_version_status(repository.id, &item.package)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                // Infrastructure error from the artifacts port —
                // surface as a `failed` envelope entry rather than
                // aborting the batch (continue-on-error contract).
                // H7: AK-side infrastructure failure → `Internal`, NOT
                // `network_error`. The old defensive fold mislabelled a
                // server-side `package_version_status` fault as a network
                // error, sending operators chasing egress/DNS.
                tracing::warn!(
                    repository = %repository.key,
                    package = %item.package,
                    error = %err,
                    "self-service prefetch: package_version_status failed; surfaced as Internal",
                );
                outcome.failed.push(FailedItem {
                    coords: coords_resolved,
                    error: PrefetchItemError::Internal,
                });
                emit_prefetch_self_service(
                    format_label,
                    repository_label,
                    PrefetchSelfServiceResult::Internal,
                );
                return;
            }
        };

        let held_match = held_status
            .iter()
            .find(|(v, _, _)| v == &resolved_version)
            .map(|(_, status, _)| *status);

        if let Some(status) = held_match {
            match status {
                // §6.4 + §6.4a — `Released` and `Quarantined` (incl. the
                // read-time `QuarantinedAwaitingRelease` derivation, which
                // the projection returns as plain `Quarantined`) mean the
                // artifact is locally ingested and already covered →
                // `skipped_already_held`.
                //
                // H6: `None` is deliberately NOT folded here. For a PROXY,
                // `package_version_status` returns `None` for versions
                // that are known upstream but NOT locally ingested — those
                // are exactly what self-service prefetch must warm, so
                // `None` falls through to the enqueue below. (The old code
                // mistook proxy `None` for an un-quarantined *hosted*
                // upload and skipped every upstream version.)
                QuarantineStatus::Released | QuarantineStatus::Quarantined => {
                    outcome.skipped_already_held.push(coords_resolved);
                    // Skipped items do NOT tick a per-item result —
                    // per §7 the 13-value `result` set does not have
                    // a `skipped` bucket. (Per-item observability for
                    // "already held" lives in the response envelope
                    // partition counts, not in the metric.)
                    return;
                }
                // Known upstream, not locally held → fall through to the
                // enqueue below (H6).
                QuarantineStatus::None => {}
                QuarantineStatus::Rejected => {
                    outcome.rejected_packages.push(RejectedItem {
                        coords: coords_resolved,
                        reason: RejectionReason::ScanRejected,
                    });
                    emit_prefetch_self_service(
                        format_label,
                        repository_label,
                        PrefetchSelfServiceResult::RejectedVersion,
                    );
                    return;
                }
                QuarantineStatus::ScanIndeterminate => {
                    outcome.rejected_packages.push(RejectedItem {
                        coords: coords_resolved,
                        reason: RejectionReason::ScanIndeterminate,
                    });
                    emit_prefetch_self_service(
                        format_label,
                        repository_label,
                        PrefetchSelfServiceResult::RejectedVersion,
                    );
                    return;
                }
            }
        }

        // ----- Enqueue directly --------------------------------------
        //
        // Self-service prefetch is the EXPLICIT operator path — the
        // honest replacement for the removed `OnIndexFetch` implicit
        // trigger. The accepted item is enqueued directly, deliberately
        // NOT routed through the auto-trigger planner
        // (`PrefetchUseCase::plan`): that planner's `policy.enabled` /
        // `policy.triggers.contains(TransitiveDeps)` gates govern the
        // *automatic* triggers + the *on-ingest* cascade, and applying
        // them here made every explicit prefetch a silent no-op on a
        // default proxy repo (`PrefetchPolicy::default()` is disabled
        // with no triggers).
        //
        // The enqueued kind is `prefetch` (the leaf-ingest), NOT the
        // `prefetch-dependencies` cascade-driver — only the leaf-ingest
        // pulls + ingests a fresh root (the cascade-driver needs an
        // already-ingested `artifact_id`). The held/rejected pre-flight
        // above and the auth gates are the gates; the `max_descendants`
        // cascade cap applies later, if the on-ingest hook fires the
        // cascade for an ingested root with declared dependencies.

        // ----- Enqueue the prefetch leaf-ingest row ------------------
        //
        // `params` is the `PrefetchParams` shape the worker's
        // `PrefetchIngestHandler` decodes — `(repository_id, package,
        // version)`, no `current_depth` (that field belongs to the
        // cascade-driver, not the leaf-ingest). The handler resolves the
        // repo's format + catch-all upstream mapping, fetches upstream
        // metadata to recover the published checksum, and
        // `ingest_verified`s the pulled bytes (→ `quarantined`). The
        // transitive cascade then fires *on completion* via the
        // `IngestUseCase` on-ingest hook, gated on the repo's
        // `TransitiveDeps` trigger.
        //
        // priority is `0i16` (operator-initiated prefetches are not
        // high-priority); trigger_source is `"self_service"`, which the
        // migration-009 comment frames as the operator-initiated ROOT
        // enqueue — distinct from the cascade-spawned `"prefetch"`
        // children (an unexpectedly high `self_service` rate is a
        // runaway operator, not a runaway cascade).
        let params = serde_json::json!({
            "repository_id": repository.id,
            "package": item.package,
            "version": resolved_version,
        });

        match self
            .jobs
            .enqueue_task(
                PREFETCH_INGEST_KIND,
                &params,
                None,
                0i16,
                PREFETCH_TRIGGER_SOURCE,
                None, // non-destructive — no DB-side idempotency key (ADR 0028)
            )
            .await
        {
            Ok(
                hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id }
                | hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate {
                    existing_job_id: job_id,
                },
            ) => {
                // Item 1 passes None so Duplicate cannot fire from the
                // DB layer; the L3 partial-unique single-flight that
                // self-service prefetch relies on surfaces as
                // `Err(Conflict)` from the adapter below, not as a
                // Duplicate outcome. The Duplicate arm is fused with
                // Enqueued here purely to keep the call site exhaustive
                // — if Item 2 ever wires a DB-side key here, the
                // operator intent ("this coordinate is being pulled")
                // is already satisfied and the arm naturally Just
                // Works.
                outcome.enqueued_job_ids.push(job_id);
                emit_prefetch_self_service(
                    format_label,
                    repository_label,
                    PrefetchSelfServiceResult::Success,
                );
            }
            Err(DomainError::Conflict(_)) => {
                // A single-flight conflict (another in-flight
                // `prefetch` leaf for the same `(repo, package,
                // version)` coordinate, the `jobs_prefetch_unique` L3
                // index target) means the operator-intent is already
                // covered. Surface as `skipped_already_held`, NOT
                // `failed`. (PullDedup + the artifacts
                // path-UNIQUE also absorb the redundant pull at ingest
                // time, so a non-`Conflict`-returning adapter is still
                // safe — this arm is the explicit-signal path.)
                outcome.skipped_already_held.push(coords_resolved);
            }
            Err(err) => {
                // H7: other jobs-port failures (e.g. a
                // `jobs_trigger_source_check` CHECK violation) are AK-side
                // infrastructure faults → `Internal`, NOT `network_error`.
                // (A `DomainError::Conflict` is handled by the
                // single-flight arm above.)
                tracing::warn!(
                    repository = %repository.key,
                    package = %item.package,
                    version = %resolved_version,
                    error = %err,
                    "self-service prefetch: enqueue_task failed; surfaced as Internal",
                );
                outcome.failed.push(FailedItem {
                    coords: coords_resolved,
                    error: PrefetchItemError::Internal,
                });
                emit_prefetch_self_service(
                    format_label,
                    repository_label,
                    PrefetchSelfServiceResult::Internal,
                );
            }
        }
    }
}

/// Per-format ordering selector. The three formats in scope
/// (npm / pypi / cargo) each have an existing `VersionOrdering`
/// implementation in `index_serve_filter`. Other formats fall through
/// to [`NpmSemverOrdering`] as the default — they cannot reach the
/// per-item version-resolution path because the OCI rejection (gate 3)
/// short-circuits the only currently-supported non-npm/pypi/cargo
/// format, and other formats return `UpstreamFetchError::UnsupportedFormat`
/// from the upstream port so the ordering is never actually consulted.
fn ordering_for_format(format: &RepositoryFormat) -> &'static (dyn VersionOrdering + Sync) {
    // Pin static singletons so the returned `&dyn VersionOrdering` is
    // `'static` — the use-case method holds the ref across `.await`
    // points without dragging the use-case lifetime.
    static NPM: NpmSemverOrdering = NpmSemverOrdering;
    static PEP440: Pep440Ordering = Pep440Ordering;
    // CargoSemverOrdering is a `pub type` alias for NpmSemverOrdering;
    // we reuse the NPM singleton (identical behavior — see the alias
    // doc in `index_serve_filter.rs:419`).
    static CARGO: CargoSemverOrdering = NpmSemverOrdering;
    match format {
        RepositoryFormat::Npm => &NPM,
        RepositoryFormat::Pypi => &PEP440,
        RepositoryFormat::Cargo => &CARGO,
        // Defensive default — every other format either was rejected
        // at gate 3 (OCI) or returns `UnsupportedFormat` from the
        // upstream port (so the planner sees `version = Some(_)` and
        // bypasses the ordering selection altogether).
        _ => &NPM,
    }
}

/// Map an [`UpstreamFetchError`] to the matching [`PrefetchItemError`]
/// for the per-item `failed` bucket. One-line conversion — the eight
/// fetch variants map 1:1; the `UnsupportedFormat` arm never reaches
/// here because gate 3 short-circuits OCI before any per-item call.
fn upstream_fetch_to_item_error(err: &UpstreamFetchError) -> PrefetchItemError {
    match err {
        UpstreamFetchError::NotFound => PrefetchItemError::UpstreamNotFound,
        UpstreamFetchError::Unauthorized => PrefetchItemError::Unauthorized,
        UpstreamFetchError::RateLimited => PrefetchItemError::RateLimited,
        UpstreamFetchError::Upstream4xx { .. } => PrefetchItemError::Upstream4xx,
        UpstreamFetchError::Upstream5xx { .. } => PrefetchItemError::Upstream5xx,
        UpstreamFetchError::NetworkError(_) => PrefetchItemError::NetworkError,
        UpstreamFetchError::Timeout => PrefetchItemError::Timeout,
        UpstreamFetchError::ParseError(_) => PrefetchItemError::ParseError,
        // Defensive — `UnsupportedFormat` is filtered out by the OCI
        // gate before any per-item port call. If a future refactor
        // changes the dispatch order, surfacing as `NetworkError`
        // keeps the metric closed and the batch progressing.
        UpstreamFetchError::UnsupportedFormat => PrefetchItemError::NetworkError,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use arc_swap::ArcSwap;
    use chrono::Utc;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::{PrefetchTrigger, Repository};
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use uuid::Uuid;

    use crate::task_handlers::prefetch_ingest::PrefetchParams;
    use crate::use_cases::test_support::{
        sample_repository, MockArtifactRepository, MockJobsRepository, MockRepositoryRepository,
        MockRepositoryUpstreamMappingRepository, MockUpstreamMetadataPort,
    };

    // --- fixtures --------------------------------------------------------

    fn caller_cli_session(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: Some(TokenKind::CliSession),
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn caller_with_token_kind(claims: &[&str], kind: Option<TokenKind>) -> CallerPrincipal {
        let mut c = caller_cli_session(claims);
        c.token_kind = kind;
        c
    }

    fn npm_repo() -> Repository {
        let mut r = sample_repository();
        r.format = RepositoryFormat::Npm;
        r.is_public = false;
        // Ensure the planner's policy gate lets us through.
        r.prefetch_policy.enabled = true;
        r.prefetch_policy.depth = 4;
        r.prefetch_policy.triggers = vec![PrefetchTrigger::TransitiveDeps];
        r
    }

    fn oci_repo() -> Repository {
        let mut r = sample_repository();
        r.format = RepositoryFormat::Oci;
        r.is_public = false;
        r
    }

    fn pypi_repo() -> Repository {
        let mut r = sample_repository();
        r.format = RepositoryFormat::Pypi;
        r.is_public = false;
        r.prefetch_policy.enabled = true;
        r.prefetch_policy.depth = 4;
        r.prefetch_policy.triggers = vec![PrefetchTrigger::TransitiveDeps];
        r
    }

    fn evaluator_with_grants(grants: Vec<PermissionGrant>) -> RbacEvaluator {
        RbacEvaluator::new(grants)
    }

    fn grant(subject_claim: &str, repo_id: Uuid, permission: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec![subject_claim.to_string()]),
            repository_id: Some(repo_id),
            permission,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn evaluator_with_read_and_prefetch(claim: &str, repo_id: Uuid) -> RbacEvaluator {
        evaluator_with_grants(vec![
            grant(claim, repo_id, Permission::Read),
            grant(claim, repo_id, Permission::Prefetch),
        ])
    }

    fn empty_evaluator() -> RbacEvaluator {
        RbacEvaluator::new(Vec::new())
    }

    fn mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: String::new(),
            upstream_url: "https://registry.example/".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    struct Harness {
        uc: SelfServicePrefetchUseCase,
        artifacts: Arc<MockArtifactRepository>,
        mappings: Arc<MockRepositoryUpstreamMappingRepository>,
        upstream: Arc<MockUpstreamMetadataPort>,
        jobs: Arc<MockJobsRepository>,
    }

    fn wire(repo: Repository, evaluator: RbacEvaluator) -> Harness {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);
        let artifacts = Arc::new(MockArtifactRepository::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let upstream = Arc::new(MockUpstreamMetadataPort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let rbac = Arc::new(ArcSwap::from_pointee(evaluator));
        let uc = SelfServicePrefetchUseCase::new(
            repos.clone(),
            artifacts.clone(),
            mappings.clone(),
            upstream.clone(),
            jobs.clone(),
            rbac,
        );
        Harness {
            uc,
            artifacts,
            mappings,
            upstream,
            jobs,
        }
    }

    /// Capture metrics + run a future, then return the snapshot.
    /// Same pattern as `discovery_use_case_tests::capture`.
    fn capture<F>(f: F) -> Vec<(metrics_util::CompositeKey, DebugValue)>
    where
        F: FnOnce() -> futures::future::BoxFuture<'static, ()> + Send + 'static,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter: Snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(f());
        });
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(k, _u, _d, v)| (k, v))
            .collect()
    }

    fn counter_value(
        snap: &[(metrics_util::CompositeKey, DebugValue)],
        name: &str,
        result_label: &str,
    ) -> Option<u64> {
        for (key, value) in snap {
            if key.key().name() != name {
                continue;
            }
            let labels: HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("result") != Some(&result_label) {
                continue;
            }
            if let DebugValue::Counter(v) = value {
                return Some(*v);
            }
        }
        None
    }

    fn item(pkg: &str, version: Option<&str>) -> PrefetchRequestItem {
        PrefetchRequestItem {
            package: pkg.into(),
            version: version.map(str::to_string),
        }
    }

    // ============================================================
    // H7 regression guard — code↔schema trigger_source drift
    // ============================================================

    /// Extract the `trigger_source IN ( … )` allowed-value set from a
    /// migration's SQL. Strips `--` comments first (the explanatory
    /// comments inside the `IN(...)` block contain parens that would
    /// otherwise truncate a naive close-paren scan), then collects the
    /// single-quoted tokens.
    fn parse_trigger_source_check(sql: &str) -> Vec<String> {
        let start = sql
            .find("trigger_source IN (")
            .expect("migration must define `trigger_source IN (...)`");
        let non_comment: String = sql[start..]
            .lines()
            .map(|l| match l.find("--") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let close = non_comment
            .find(')')
            .expect("unterminated `trigger_source IN (...)`");
        let block = &non_comment[..close];
        let mut out = Vec::new();
        let mut rest = block;
        while let Some(open) = rest.find('\'') {
            rest = &rest[open + 1..];
            match rest.find('\'') {
                Some(end) => {
                    out.push(rest[..end].to_string());
                    rest = &rest[end + 1..];
                }
                None => break,
            }
        }
        out
    }

    #[test]
    fn prefetch_trigger_source_is_allowed_by_jobs_check_constraint() {
        // H7: the `trigger_source` the self-service use case writes MUST
        // be in migration 009's `jobs_trigger_source_check` IN-list, or
        // every enqueue 500s on a constraint violation. rc.5 shipped the
        // code fix (`PREFETCH_TRIGGER_SOURCE = "self_service"`) but NOT
        // the schema value — this DB-free guard catches that code↔schema
        // drift in the standard `--lib` gate, before it reaches a DB.
        let migration = include_str!("../../../../migrations/009_scan_jobs_and_findings.sql");
        let allowed = parse_trigger_source_check(migration);
        assert!(
            allowed.iter().any(|v| v == PREFETCH_TRIGGER_SOURCE),
            "self-service trigger_source `{PREFETCH_TRIGGER_SOURCE}` is not in \
             jobs_trigger_source_check {allowed:?} — extend migration 009"
        );
    }

    // ============================================================
    // Gate 1: token-kind
    // ============================================================

    #[test]
    fn token_kind_denied_for_pat_caller_ticks_once_and_returns_forbidden() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                let actor = caller_with_token_kind(&["dev"], Some(TokenKind::Pat));
                let err =
                    h.uc.enqueue_self_service("any-key", vec![item("p", Some("1"))], &actor)
                        .await
                        .expect_err("PAT must be rejected");
                assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
                if let AppError::Domain(DomainError::Forbidden(msg)) = err {
                    assert!(msg.contains("CLI session"), "msg: {msg}");
                }
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "token_kind_denied",
            ),
            Some(1)
        );
    }

    #[test]
    fn token_kind_denied_for_service_account_ticks_once() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                let actor = caller_with_token_kind(&["dev"], Some(TokenKind::ServiceAccount));
                let _err =
                    h.uc.enqueue_self_service("k", vec![], &actor)
                        .await
                        .expect_err("service-account token must be rejected");
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "token_kind_denied"
            ),
            Some(1)
        );
    }

    #[test]
    fn token_kind_denied_for_none_kind_ticks_once() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                let actor = caller_with_token_kind(&["dev"], None);
                let _err =
                    h.uc.enqueue_self_service("k", vec![], &actor)
                        .await
                        .expect_err("None token-kind must be rejected");
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "token_kind_denied"
            ),
            Some(1)
        );
    }

    // ============================================================
    // Gate 2: RBAC (Read ∧ Prefetch)
    // ============================================================

    #[test]
    fn permission_denied_when_caller_lacks_both_grants() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let key = repo.key.clone();
                let h = wire(repo, empty_evaluator());
                let actor = caller_cli_session(&[]);
                let err =
                    h.uc.enqueue_self_service(&key, vec![], &actor)
                        .await
                        .expect_err("missing both grants must deny");
                assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "permission_denied"
            ),
            Some(1)
        );
    }

    #[test]
    fn permission_denied_when_caller_holds_read_but_not_prefetch() {
        // §2.5 Finding E — Read alone is insufficient; the AND
        // gate must reject.
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let eval = evaluator_with_grants(vec![grant("dev", repo_id, Permission::Read)]);
                let h = wire(repo, eval);
                let actor = caller_cli_session(&["dev"]);
                let err =
                    h.uc.enqueue_self_service(&key, vec![], &actor)
                        .await
                        .expect_err("Read-only must be rejected");
                if let AppError::Domain(DomainError::Forbidden(msg)) = err {
                    assert!(msg.contains("Read"), "msg: {msg}");
                    assert!(msg.contains("Prefetch"), "msg: {msg}");
                } else {
                    panic!("expected Forbidden, got other variant");
                }
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "permission_denied"
            ),
            Some(1)
        );
    }

    #[test]
    fn permission_denied_when_caller_holds_prefetch_but_not_read() {
        // §2.5 Finding E — Prefetch without Read is the dangerous
        // case (amplify against a repo the actor cannot enumerate);
        // the AND gate must reject.
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let eval = evaluator_with_grants(vec![grant("dev", repo_id, Permission::Prefetch)]);
                let h = wire(repo, eval);
                let actor = caller_cli_session(&["dev"]);
                let _err =
                    h.uc.enqueue_self_service(&key, vec![], &actor)
                        .await
                        .expect_err("Prefetch-only must be rejected");
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "permission_denied"
            ),
            Some(1)
        );
    }

    // ============================================================
    // Repository resolution: anti-enumeration NotFound
    // ============================================================

    #[tokio::test]
    async fn unknown_repository_key_returns_notfound() {
        let repo = npm_repo();
        let repo_id = repo.id;
        let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
        let actor = caller_cli_session(&["dev"]);
        let err =
            h.uc.enqueue_self_service("does-not-exist", vec![], &actor)
                .await
                .expect_err("unknown repo must NotFound");
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    // ============================================================
    // Gate 3: OCI rejection
    // ============================================================

    #[test]
    fn oci_format_returns_validation_with_exact_message_and_ticks_once() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = oci_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                let actor = caller_cli_session(&["dev"]);
                let err =
                    h.uc.enqueue_self_service(
                        &repo_key,
                        vec![item("library/alpine", Some("3.18"))],
                        &actor,
                    )
                    .await
                    .expect_err("OCI must be rejected");
                match err {
                    AppError::Domain(DomainError::Validation(msg)) => {
                        assert_eq!(msg, OCI_UNSUPPORTED_MESSAGE);
                    }
                    other => panic!("expected Validation, got {other:?}"),
                }
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "oci_unsupported"),
            Some(1)
        );
    }

    // ============================================================
    // Empty `items` — no per-item ticks, no enqueues
    // ============================================================

    #[test]
    fn empty_items_returns_empty_envelope_and_no_per_item_ticks() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![], &actor)
                        .await
                        .expect("ok");
                assert!(outcome.enqueued_job_ids.is_empty());
                assert!(outcome.skipped_already_held.is_empty());
                assert!(outcome.rejected_packages.is_empty());
                assert!(outcome.failed.is_empty());
                assert!(h.jobs.enqueue_calls().is_empty(), "no enqueues");
            })
        });
        // No per-item ticks — only the gate ticks would fire, and all
        // three gates passed.
        assert!(counter_value(&snap, "hort_prefetch_self_service_total", "success").is_none());
        assert!(counter_value(
            &snap,
            "hort_prefetch_self_service_total",
            "token_kind_denied"
        )
        .is_none());
    }

    // ============================================================
    // Happy paths
    // ============================================================

    #[test]
    fn all_success_enqueues_each_item_and_ticks_success_per_item() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(
                        &key,
                        vec![
                            item("a", Some("1.0.0")),
                            item("b", Some("2.0.0")),
                            item("c", Some("3.0.0")),
                        ],
                        &actor,
                    )
                    .await
                    .expect("ok");
                assert_eq!(outcome.enqueued_job_ids.len(), 3);
                assert!(outcome.skipped_already_held.is_empty());
                assert!(outcome.rejected_packages.is_empty());
                assert!(outcome.failed.is_empty());

                // Verify the leaf-ingest call shape (H8): kind="prefetch"
                // (the `PrefetchIngestHandler` kind), actor_id=None, json
                // params with `repository_id`/`package`/`version` and NO
                // `current_depth` (that field is the cascade-driver's, not
                // the leaf-ingest's).
                let calls = h.jobs.enqueue_calls();
                assert_eq!(calls.len(), 3);
                for (kind, params, actor_id) in &calls {
                    assert_eq!(kind, "prefetch");
                    assert!(actor_id.is_none(), "actor_id is None per design");
                    assert!(params.is_object());
                    assert!(params.get("repository_id").is_some());
                    assert!(params.get("package").is_some());
                    assert!(params.get("version").is_some());
                    assert!(
                        params.get("current_depth").is_none(),
                        "leaf-ingest params must not carry the cascade-driver `current_depth`",
                    );
                }
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "success"),
            Some(3)
        );
    }

    #[test]
    fn version_none_resolves_latest_from_upstream() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.upstream.insert_versions(
                    "npm",
                    "left-pad",
                    Ok(vec!["1.0.0".into(), "1.1.0".into(), "2.0.0".into()]),
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("left-pad", None)], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.enqueued_job_ids.len(), 1);
                // The picked version (2.0.0) must appear in the
                // enqueued params payload — verifies the planner
                // path consulted the ordering.
                let calls = h.jobs.enqueue_calls();
                assert_eq!(calls[0].1["version"].as_str(), Some("2.0.0"));
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "success"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn enqueues_consumable_prefetch_leaf_job_not_unconsumable_cascade_driver() {
        // Regression pin. Self-service prefetch
        // must enqueue the `prefetch` LEAF-INGEST kind — the existing
        // pull-through path: prefetch of an unknown-status
        // version triggers a fresh ingest via the existing
        // pull-through path, and the cascade fires on completion. Its
        // `PrefetchIngestHandler` pulls + ingests the root
        // `(repository_id, package, version)` from upstream.
        //
        // The earlier code enqueued `prefetch-dependencies` — the
        // cascade-DRIVER kind, whose `PrefetchDependenciesHandler`
        // requires an already-ingested `artifact_id` to read an existing
        // manifest. For a not-yet-ingested root that field is absent, so
        // the worker failed deserialization ("missing field
        // `artifact_id`"), the job terminally failed, and nothing
        // ingested — *silently*, because the API had already returned the
        // job id (worse than an explicit constraint 500). Pin BOTH the
        // kind AND that the worker's leaf consumer can actually
        // deserialize the params the use case produces.
        let repo = npm_repo();
        let repo_id = repo.id;
        let key = repo.key.clone();
        let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
        h.mappings.upsert(mapping(repo_id)).await.unwrap();
        let actor = caller_cli_session(&["dev"]);
        let outcome =
            h.uc.enqueue_self_service(&key, vec![item("is-number", Some("7.0.0"))], &actor)
                .await
                .expect("ok");
        assert_eq!(outcome.enqueued_job_ids.len(), 1);

        let calls = h.jobs.enqueue_calls();
        assert_eq!(calls.len(), 1, "exactly one enqueue for the single item");
        let (kind, params, _actor_id) = &calls[0];
        assert_eq!(
            kind, "prefetch",
            "self-service must enqueue the leaf-ingest kind that pulls + ingests the root \
             coordinate, NOT the cascade-driver `prefetch-dependencies` (which needs an \
             already-ingested artifact_id and cannot ingest a fresh root)",
        );
        // The worker dispatches by `kind` to `PrefetchIngestHandler`,
        // which deserializes `params` into `PrefetchParams`. A
        // producer→consumer params drift here is exactly the H8 defect:
        // a row the handler for its `kind` cannot parse.
        serde_json::from_value::<PrefetchParams>(params.clone())
            .expect("worker's prefetch-leaf handler must deserialize the enqueued params");
        // And the root coordinate must be carried verbatim.
        assert_eq!(params["package"].as_str(), Some("is-number"));
        assert_eq!(params["version"].as_str(), Some("7.0.0"));
    }

    // ============================================================
    // Already-held buckets (§§6.4 + 6.4a — three states fold together)
    // ============================================================

    #[test]
    fn already_held_released_skips() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p",
                    vec![("1.0.0".into(), QuarantineStatus::Released)],
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert!(outcome.enqueued_job_ids.is_empty());
                assert_eq!(outcome.skipped_already_held.len(), 1);
                assert_eq!(outcome.skipped_already_held[0].package, "p");
                assert!(h.jobs.enqueue_calls().is_empty());
            })
        });
        // Skipped is not a `result` label — verify no per-item
        // success tick.
        assert!(counter_value(&snap, "hort_prefetch_self_service_total", "success").is_none());
    }

    #[test]
    fn already_held_quarantined_skips_per_6_4a() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p",
                    vec![("1.0.0".into(), QuarantineStatus::Quarantined)],
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.skipped_already_held.len(), 1);
                assert!(outcome.rejected_packages.is_empty());
                assert!(outcome.failed.is_empty());
            })
        });
        // No rejected tick — the in-progress quarantine is not
        // terminal.
        assert!(counter_value(
            &snap,
            "hort_prefetch_self_service_total",
            "rejected_version"
        )
        .is_none());
    }

    #[test]
    fn none_status_known_upstream_is_enqueued_not_skipped() {
        // H6 (secondary): for a PROXY, `package_version_status` returns
        // `QuarantineStatus::None` for versions that are known upstream
        // but NOT locally ingested (the same projection that backs the
        // packument serve — discovery reads this `None` as "unknown").
        // Self-service prefetch must ENQUEUE these (that is the whole
        // point — warm them), NOT bucket them as `skipped_already_held`.
        // The old behaviour mistook proxy `None` for an un-quarantined
        // *hosted* upload. Only Released / Quarantined (actually locally
        // held) skip.
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p",
                    vec![("1.0.0".into(), QuarantineStatus::None)],
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert_eq!(
                    outcome.enqueued_job_ids.len(),
                    1,
                    "proxy None (known-upstream, not locally held) must enqueue"
                );
                assert!(outcome.skipped_already_held.is_empty());
                assert!(outcome.rejected_packages.is_empty());
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "success"),
            Some(1)
        );
    }

    #[test]
    fn self_service_enqueues_even_when_auto_prefetch_policy_is_disabled() {
        // Self-service prefetch is the EXPLICIT operator
        // path (the honest replacement for the removed
        // `OnIndexFetch` implicit trigger). It must NOT be gated by the
        // *automatic*-trigger `prefetch_policy` (`enabled` / `triggers`):
        // a default proxy repo carries `PrefetchPolicy::default()`
        // (disabled, no triggers), and an explicit `hort-cli prefetch`
        // against it must still enqueue. The enqueue is a `prefetch`
        // leaf-ingest; the `TransitiveDeps` trigger governs
        // the on-ingest cascade that fires later, not this root enqueue.
        let snap = capture(|| {
            Box::pin(async {
                // Deliberately NOT npm_repo() — that opts into
                // auto-prefetch. Use the disabled default policy.
                let mut repo = sample_repository();
                repo.format = RepositoryFormat::Npm;
                repo.is_public = false;
                assert!(
                    !repo.prefetch_policy.enabled,
                    "fixture must exercise the disabled default prefetch policy"
                );
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                // Fresh version — no local rows → known upstream, not held.
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("is-number", Some("7.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert_eq!(
                    outcome.enqueued_job_ids.len(),
                    1,
                    "explicit self-service prefetch must enqueue despite disabled auto-policy"
                );
                assert!(outcome.skipped_already_held.is_empty());
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "success"),
            Some(1)
        );
    }

    // ============================================================
    // Rejected buckets (§6.5 — both flavors)
    // ============================================================

    #[test]
    fn already_held_rejected_surfaces_as_scan_rejected_and_ticks_rejected_version() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p",
                    vec![("1.0.0".into(), QuarantineStatus::Rejected)],
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert!(outcome.enqueued_job_ids.is_empty());
                assert_eq!(outcome.rejected_packages.len(), 1);
                assert_eq!(
                    outcome.rejected_packages[0].reason,
                    RejectionReason::ScanRejected
                );
                assert!(
                    h.jobs.enqueue_calls().is_empty(),
                    "must NOT re-enqueue rejected"
                );
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "rejected_version"
            ),
            Some(1)
        );
    }

    #[test]
    fn already_held_scan_indeterminate_surfaces_as_scan_indeterminate() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p",
                    vec![("1.0.0".into(), QuarantineStatus::ScanIndeterminate)],
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.rejected_packages.len(), 1);
                assert_eq!(
                    outcome.rejected_packages[0].reason,
                    RejectionReason::ScanIndeterminate
                );
            })
        });
        // Both flavors of rejection tick the same metric label.
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "rejected_version"
            ),
            Some(1)
        );
    }

    // ============================================================
    // Upstream-fetch failure variants — all surface in `failed`
    // ============================================================

    fn assert_upstream_fetch_error_maps_to_label(
        seed: UpstreamFetchError,
        expected_item_error: PrefetchItemError,
        expected_result_label: &str,
    ) {
        let snap = capture(move || {
            let seed = seed;
            Box::pin(async move {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.upstream.insert_versions("npm", "p", Err(seed));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", None)], &actor)
                        .await
                        .expect("upstream errors surface in envelope, not as Err");
                assert_eq!(outcome.failed.len(), 1);
                assert_eq!(outcome.failed[0].error, expected_item_error);
                assert!(outcome.enqueued_job_ids.is_empty());
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                expected_result_label,
            ),
            Some(1),
            "expected {} tick",
            expected_result_label,
        );
    }

    #[test]
    fn upstream_not_found_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::NotFound,
            PrefetchItemError::UpstreamNotFound,
            "not_found",
        );
    }

    #[test]
    fn upstream_unauthorized_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::Unauthorized,
            PrefetchItemError::Unauthorized,
            "unauthorized",
        );
    }

    #[test]
    fn upstream_rate_limited_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::RateLimited,
            PrefetchItemError::RateLimited,
            "rate_limited",
        );
    }

    #[test]
    fn upstream_4xx_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::Upstream4xx { status: 418 },
            PrefetchItemError::Upstream4xx,
            "upstream_4xx",
        );
    }

    #[test]
    fn upstream_5xx_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::Upstream5xx { status: 503 },
            PrefetchItemError::Upstream5xx,
            "upstream_5xx",
        );
    }

    #[test]
    fn upstream_network_error_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::NetworkError("dns".into()),
            PrefetchItemError::NetworkError,
            "network_error",
        );
    }

    #[test]
    fn upstream_timeout_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::Timeout,
            PrefetchItemError::Timeout,
            "timeout",
        );
    }

    #[test]
    fn upstream_parse_error_failure() {
        assert_upstream_fetch_error_maps_to_label(
            UpstreamFetchError::ParseError("packument".into()),
            PrefetchItemError::ParseError,
            "parse_error",
        );
    }

    // ============================================================
    // Empty upstream version set → UpstreamNotFound
    // ============================================================

    #[test]
    fn empty_upstream_version_set_surfaces_as_not_found_failure() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.upstream.insert_versions("npm", "p", Ok(vec![]));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", None)], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.failed.len(), 1);
                assert_eq!(outcome.failed[0].error, PrefetchItemError::UpstreamNotFound);
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "not_found"),
            Some(1)
        );
    }

    // ============================================================
    // No upstream mapping + version = None → UpstreamNotFound
    // ============================================================

    #[test]
    fn hosted_only_repo_with_version_none_yields_upstream_not_found() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                // No mapping seeded — hosted-only repo.
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", None)], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.failed.len(), 1);
                assert_eq!(outcome.failed[0].error, PrefetchItemError::UpstreamNotFound);
                // The upstream port was never called (no mapping).
                assert!(h.upstream.calls().is_empty());
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "not_found"),
            Some(1)
        );
    }

    // ============================================================
    // Idempotency — Conflict from `enqueue_task` surfaces as skipped
    // ============================================================

    #[test]
    fn jobs_conflict_surfaces_as_skipped_already_held_not_failed() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.jobs.fail_next_enqueue(DomainError::Conflict(
                    "prefetch row already in flight".into(),
                ));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.skipped_already_held.len(), 1);
                assert!(outcome.failed.is_empty());
                assert!(outcome.enqueued_job_ids.is_empty());
                assert_eq!(outcome.skipped_already_held[0].package, "p");
            })
        });
        // No success / failed tick — idempotency hit ticks no result
        // label (envelope partition counts capture this).
        assert!(counter_value(&snap, "hort_prefetch_self_service_total", "success").is_none());
        assert!(
            counter_value(&snap, "hort_prefetch_self_service_total", "network_error").is_none()
        );
    }

    // ============================================================
    // Jobs port non-Conflict error → Internal failed (H7 fix 2)
    // ============================================================

    #[test]
    fn jobs_invariant_error_surfaces_as_internal_failed() {
        // H7 fix 2: a non-Conflict jobs-port error (e.g. the
        // `jobs_trigger_source_check` CHECK violation) is an AK-side
        // infrastructure fault → `Internal`, NOT `NetworkError` (the old
        // mislabel that sent operators chasing egress/DNS).
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.jobs
                    .fail_next_enqueue(DomainError::Invariant("jobs DB exploded".into()));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.failed.len(), 1);
                assert_eq!(outcome.failed[0].error, PrefetchItemError::Internal);
                assert!(outcome.enqueued_job_ids.is_empty());
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "internal"),
            Some(1)
        );
        assert!(
            counter_value(&snap, "hort_prefetch_self_service_total", "network_error").is_none(),
            "AK-side jobs failure must NOT tick network_error"
        );
    }

    // ============================================================
    // Mixed batch — at least one of every bucket
    // ============================================================

    #[test]
    fn mixed_batch_partitions_correctly_with_per_item_ticks() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                // success: fresh (no held row)
                // skipped: held Released
                // rejected ScanRejected: held Rejected
                // rejected ScanIndeterminate: held ScanIndeterminate
                // failed (timeout): upstream returns timeout for `t`
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p_skipped",
                    vec![("1.0.0".into(), QuarantineStatus::Released)],
                );
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p_rejected",
                    vec![("1.0.0".into(), QuarantineStatus::Rejected)],
                );
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "p_indeterminate",
                    vec![("1.0.0".into(), QuarantineStatus::ScanIndeterminate)],
                );
                h.upstream
                    .insert_versions("npm", "p_timeout", Err(UpstreamFetchError::Timeout));
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(
                        &key,
                        vec![
                            item("p_success", Some("1.0.0")),
                            item("p_skipped", Some("1.0.0")),
                            item("p_rejected", Some("1.0.0")),
                            item("p_indeterminate", Some("1.0.0")),
                            item("p_timeout", None),
                        ],
                        &actor,
                    )
                    .await
                    .expect("ok");
                assert_eq!(outcome.enqueued_job_ids.len(), 1, "1 success");
                assert_eq!(outcome.skipped_already_held.len(), 1, "1 skipped");
                assert_eq!(
                    outcome.rejected_packages.len(),
                    2,
                    "2 rejected (both flavors)"
                );
                assert_eq!(outcome.failed.len(), 1, "1 failed (timeout)");
                // Both rejection reasons are present.
                let reasons: Vec<RejectionReason> =
                    outcome.rejected_packages.iter().map(|r| r.reason).collect();
                assert!(reasons.contains(&RejectionReason::ScanRejected));
                assert!(reasons.contains(&RejectionReason::ScanIndeterminate));
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "success"),
            Some(1)
        );
        assert_eq!(
            counter_value(
                &snap,
                "hort_prefetch_self_service_total",
                "rejected_version"
            ),
            Some(2),
            "both rejected flavors tick the same label per §7",
        );
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "timeout"),
            Some(1)
        );
    }

    // ============================================================
    // Artifacts port error path — propagates per item
    // ============================================================

    /// Failing artifact mock that errors on `package_version_status`.
    /// Locally-pinned (one use, mirrors `discovery_use_case`'s
    /// `FailingArtifactsRepo`).
    struct FailingArtifactsRepo;

    impl ArtifactRepository for FailingArtifactsRepo {
        fn find_by_id(
            &self,
            _id: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<hort_domain::entities::artifact::Artifact>,
        > {
            unimplemented!("not used by self-service-prefetch test")
        }
        fn find_by_checksum(
            &self,
            _h: &hort_domain::types::ContentHash,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Option<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn find_by_repo_and_checksum(
            &self,
            _r: Uuid,
            _h: &hort_domain::types::ContentHash,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Option<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list_by_repository(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::Page<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn delete(
            &self,
            _id: Uuid,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_path(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Option<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list_distinct_names(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<hort_domain::types::Page<String>>,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_in_repo(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::Page<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_as_published(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::Page<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn list_active_for_repo(
            &self,
            _r: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_rejected_for_policy(
            &self,
            _p: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn package_version_status(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                Vec<(String, QuarantineStatus, Option<chrono::DateTime<Utc>>)>,
            >,
        > {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "package_version_status exploded".into(),
                ))
            })
        }
        fn find_pypi_wheels_without_kind(
            &self,
            _k: &str,
            _l: u32,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Vec<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[test]
    fn artifacts_port_error_surfaces_per_item_as_internal() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let repos = Arc::new(MockRepositoryRepository::new());
                repos.insert(repo);
                let artifacts: Arc<dyn ArtifactRepository> = Arc::new(FailingArtifactsRepo);
                let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
                mappings.upsert(mapping(repo_id)).await.unwrap();
                let upstream = Arc::new(MockUpstreamMetadataPort::new());
                let jobs = Arc::new(MockJobsRepository::new());
                let rbac = Arc::new(ArcSwap::from_pointee(evaluator_with_read_and_prefetch(
                    "dev", repo_id,
                )));
                let uc = SelfServicePrefetchUseCase::new(
                    repos, artifacts, mappings, upstream, jobs, rbac,
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome = uc
                    .enqueue_self_service(&key, vec![item("p", Some("1.0.0"))], &actor)
                    .await
                    .expect("ok");
                assert_eq!(outcome.failed.len(), 1);
                // H7 fix 2: artifacts-port (package_version_status) failure
                // is an AK-side fault → Internal, not NetworkError.
                assert_eq!(outcome.failed[0].error, PrefetchItemError::Internal);
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "internal"),
            Some(1)
        );
    }

    // ============================================================
    // Per-format ordering helper coverage
    // ============================================================

    #[test]
    fn ordering_for_format_covers_each_supported_format() {
        // Smoke check that the helper returns a comparator for each
        // in-scope format (npm / pypi / cargo) + a defensive default
        // for other formats. The implementations themselves are tested
        // in `index_serve_filter` — here we just verify dispatch.
        let _npm = ordering_for_format(&RepositoryFormat::Npm);
        let _pypi = ordering_for_format(&RepositoryFormat::Pypi);
        let _cargo = ordering_for_format(&RepositoryFormat::Cargo);
        let _default = ordering_for_format(&RepositoryFormat::Maven);
        // Compile-time success is the assertion; no runtime equality
        // possible across `&dyn`. Sanity check: each returns ordering
        // consistent with semver `1.0.0 < 2.0.0`.
        assert_eq!(
            ordering_for_format(&RepositoryFormat::Npm).compare("1.0.0", "2.0.0"),
            std::cmp::Ordering::Less
        );
    }

    // ============================================================
    // upstream_fetch_to_item_error coverage
    // ============================================================

    #[test]
    fn upstream_fetch_to_item_error_covers_every_arm() {
        // Pin the 1:1 mapping; UnsupportedFormat is the defensive
        // fold (gate 3 ordinarily filters it out).
        let pairs = [
            (
                UpstreamFetchError::NotFound,
                PrefetchItemError::UpstreamNotFound,
            ),
            (
                UpstreamFetchError::Unauthorized,
                PrefetchItemError::Unauthorized,
            ),
            (
                UpstreamFetchError::RateLimited,
                PrefetchItemError::RateLimited,
            ),
            (
                UpstreamFetchError::Upstream4xx { status: 418 },
                PrefetchItemError::Upstream4xx,
            ),
            (
                UpstreamFetchError::Upstream5xx { status: 503 },
                PrefetchItemError::Upstream5xx,
            ),
            (
                UpstreamFetchError::NetworkError("dns".into()),
                PrefetchItemError::NetworkError,
            ),
            (UpstreamFetchError::Timeout, PrefetchItemError::Timeout),
            (
                UpstreamFetchError::ParseError("p".into()),
                PrefetchItemError::ParseError,
            ),
            (
                UpstreamFetchError::UnsupportedFormat,
                PrefetchItemError::NetworkError,
            ),
        ];
        for (fetch_err, expected) in pairs {
            assert_eq!(upstream_fetch_to_item_error(&fetch_err), expected);
        }
    }

    // ============================================================
    // PrefetchSelfServiceResult helper coverage
    // ============================================================

    #[test]
    fn prefetch_self_service_result_as_str_covers_every_arm() {
        let pairs = [
            (PrefetchSelfServiceResult::Success, "success"),
            (PrefetchSelfServiceResult::NotFound, "not_found"),
            (PrefetchSelfServiceResult::Unauthorized, "unauthorized"),
            (PrefetchSelfServiceResult::RateLimited, "rate_limited"),
            (PrefetchSelfServiceResult::Upstream4xx, "upstream_4xx"),
            (PrefetchSelfServiceResult::Upstream5xx, "upstream_5xx"),
            (PrefetchSelfServiceResult::NetworkError, "network_error"),
            (PrefetchSelfServiceResult::Timeout, "timeout"),
            (PrefetchSelfServiceResult::ParseError, "parse_error"),
            (
                PrefetchSelfServiceResult::PermissionDenied,
                "permission_denied",
            ),
            (
                PrefetchSelfServiceResult::TokenKindDenied,
                "token_kind_denied",
            ),
            (PrefetchSelfServiceResult::OciUnsupported, "oci_unsupported"),
            (
                PrefetchSelfServiceResult::RejectedVersion,
                "rejected_version",
            ),
            (PrefetchSelfServiceResult::Internal, "internal"),
        ];
        for (variant, expected) in pairs {
            assert_eq!(variant.as_str(), expected);
        }
    }

    #[test]
    fn prefetch_self_service_result_from_upstream_error_kind_covers_taxonomy() {
        use crate::metrics::UpstreamErrorKind;
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::Success),
            PrefetchSelfServiceResult::Success
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::NotFound),
            PrefetchSelfServiceResult::NotFound
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::Unauthorized),
            PrefetchSelfServiceResult::Unauthorized
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::RateLimited),
            PrefetchSelfServiceResult::RateLimited
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::Upstream4xx),
            PrefetchSelfServiceResult::Upstream4xx
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::Upstream5xx),
            PrefetchSelfServiceResult::Upstream5xx
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::NetworkError),
            PrefetchSelfServiceResult::NetworkError
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::Timeout),
            PrefetchSelfServiceResult::Timeout
        );
        assert_eq!(
            PrefetchSelfServiceResult::from_upstream_error_kind(UpstreamErrorKind::ParseError),
            PrefetchSelfServiceResult::ParseError
        );
        // Out-of-band variants fold to NetworkError (defensive).
        for kind in [
            UpstreamErrorKind::ChecksumMismatch,
            UpstreamErrorKind::BodyTooLarge,
            UpstreamErrorKind::PinMismatch,
            UpstreamErrorKind::CaUnknown,
        ] {
            assert_eq!(
                PrefetchSelfServiceResult::from_upstream_error_kind(kind),
                PrefetchSelfServiceResult::NetworkError
            );
        }
    }

    #[test]
    fn prefetch_self_service_result_from_item_error_covers_every_arm() {
        let pairs = [
            (
                PrefetchItemError::UpstreamNotFound,
                PrefetchSelfServiceResult::NotFound,
            ),
            (
                PrefetchItemError::Unauthorized,
                PrefetchSelfServiceResult::Unauthorized,
            ),
            (
                PrefetchItemError::RateLimited,
                PrefetchSelfServiceResult::RateLimited,
            ),
            (
                PrefetchItemError::Upstream4xx,
                PrefetchSelfServiceResult::Upstream4xx,
            ),
            (
                PrefetchItemError::Upstream5xx,
                PrefetchSelfServiceResult::Upstream5xx,
            ),
            (
                PrefetchItemError::NetworkError,
                PrefetchSelfServiceResult::NetworkError,
            ),
            (
                PrefetchItemError::Timeout,
                PrefetchSelfServiceResult::Timeout,
            ),
            (
                PrefetchItemError::ParseError,
                PrefetchSelfServiceResult::ParseError,
            ),
            (
                PrefetchItemError::Internal,
                PrefetchSelfServiceResult::Internal,
            ),
        ];
        for (item_err, expected) in pairs {
            assert_eq!(
                prefetch_self_service_result_from_item_error(item_err),
                expected,
                "{item_err:?} mapped to wrong result",
            );
        }
    }

    // ============================================================
    // Pypi-format ordering exercise via "latest" path
    // ============================================================

    #[test]
    fn pypi_format_uses_pep440_ordering_for_latest_resolution() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = pypi_repo();
                let repo_id = repo.id;
                let key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_and_prefetch("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                // PEP 440 ordering: 2.0.0 > 2.0.0a1 > 1.99.99
                h.upstream.insert_versions(
                    "pypi",
                    "requests",
                    Ok(vec!["1.99.99".into(), "2.0.0a1".into(), "2.0.0".into()]),
                );
                let actor = caller_cli_session(&["dev"]);
                let outcome =
                    h.uc.enqueue_self_service(&key, vec![item("requests", None)], &actor)
                        .await
                        .expect("ok");
                assert_eq!(outcome.enqueued_job_ids.len(), 1);
                let calls = h.jobs.enqueue_calls();
                assert_eq!(
                    calls[0].1["version"].as_str(),
                    Some("2.0.0"),
                    "PEP 440: 2.0.0 outranks 2.0.0a1",
                );
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_prefetch_self_service_total", "success"),
            Some(1)
        );
    }
}
