//! Administrative endpoints.
//!
//! Routes:
//! - `GET    /repositories/:key`                          — look up a repo's UUID by key
//! - `GET    /repositories/:key/effective-config`         — resolved repo config (read-only)
//! - `GET    /gitops/apply-status`                        — this process's boot apply (read-only)
//! - `GET    /quarantine/patch-candidates`                — list patch-candidate surface
//! - `POST   /quarantine/:artifact_id/release`            — admin override release
//!
//! Mounted under `/api/v1/admin` by [`crate::router::build_router`].
//! Every handler
//! in this module declares [`AdminPrincipal`] as its first extractor — it
//! enforces `Permission::Admin` before the handler body runs
//! and emits `hort_authz_decisions_total{permission=admin, …}` from exactly
//! one spot. Handler bodies contain zero inline `rbac.authorize(...)` calls.
//!
//! Server startup (`cli::serve::run_async`) refuses to boot under
//! `HORT_AUTH_PROVIDER=disabled` — the admin surface is mounted unconditionally
//! so shipping it without authentication would be a critical-severity
//! regression.
//!
//! ## Repository lifecycle is gitops-only
//!
//! There is deliberately no `POST /repositories` create endpoint:
//! `$HORT_CONFIG_DIR` is the canonical repo-lifecycle
//! surface. Every repository is declared as a YAML envelope
//! under `$HORT_CONFIG_DIR/repositories/` and applied at boot; updates
//! and deletes happen by editing the YAML and restarting the
//! process. The `RepositoryUseCase::create` method is still callable
//! from in-process callers (the apply pipeline does NOT use it —
//! see the `save_managed` path — but the
//! `ManagedByConfiguration` collision check on `create` remains
//! load-bearing for any future inbound that mounts it).
//!
//! `GET /repositories/:key` is the single read endpoint that
//! survives. It exists so external tooling has a way to resolve
//! `:repo_id` from a stable key (UUIDs are minted at first apply,
//! so operators can't hard-code them).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::gitops_apply_status::{ApplyKindCounts, GitopsApplyStatus, KindCounts};
use hort_app::use_cases::effective_permissions_use_case::{EffectiveGrant, EffectivePermissions};
use hort_app::use_cases::effective_repository_config_use_case::EffectiveScanPolicyView;
use hort_app::use_cases::patch_candidate_use_case::MAX_LIMIT as PATCH_CANDIDATE_MAX_LIMIT;
use hort_app::use_cases::scanner_worker_query_use_case::ScannerWorkerView;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::entities::rbac::GrantSubject;
use hort_domain::entities::repository::PrefetchPolicy;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::patch_candidate_repository::{PatchCandidate, PatchCandidateFilter};
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, UpstreamAuth,
};

use crate::authz::AdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

/// Curator decision endpoints mounted under
/// `/api/v1/admin/curation/...`. Exposed as a sub-module so the
/// composition-root mount site (`hort-server::http::control_plane_routes`)
/// can pull the sub-router via `admin::curation::curation_routes()`.
/// The new routes are gated by [`crate::authz::CurateOrAdminPrincipal`],
/// NOT by the [`AdminPrincipal`] gate that protects the rest of this
/// module's `admin_routes()` tree.
pub mod curation;

/// Finding-exclusion HTTP write surface mounted
/// under `/api/v1/admin/policies/:policy_id/exclusions[/:cve_id]`.
/// Exposed as a sub-module so the composition-root mount site
/// (`hort-server::http::control_plane_routes`) can pull the sub-router
/// via `admin::policies::policies_routes()`. The new routes are gated
/// by [`crate::authz::CurateOrAdminPrincipal`], NOT by the
/// [`AdminPrincipal`] gate that protects the rest of this module's
/// `admin_routes()` tree.
pub mod policies;

/// Maximum byte length of the operator-supplied justification on
/// `POST /admin/quarantine/:artifact_id/release`. Mirrors the
/// 512-byte cap enforced by [`hort_domain::events::ArtifactReleased::validate`]
/// — the boundary check returns 400 with a clear message before the
/// request reaches the use case.
const MAX_RELEASE_JUSTIFICATION_BYTES: usize = 512;

/// Build the admin route tree. Mount under `/admin` in the top-level router.
pub fn admin_routes() -> Router<Arc<AppContext>> {
    Router::new()
        // Gitops-only repo lifecycle — there is no
        // `POST /repositories` create endpoint; this
        // GET exists so external tooling has a way to resolve
        // `:repo_id` from a stable key (UUIDs are minted at first
        // apply, so operators can't hard-code them).
        .route("/repositories/{key}", get(get_repository_by_key))
        // Admin-only, read-only projection of a repository's
        // *effective* config — what the running server actually
        // resolved (config drift, policy binding). No secrets ever
        // serialized (see `EffectiveUpstreamMappingDto`); no write
        // surface — gitops is still the only config writer.
        .route(
            "/repositories/{key}/effective-config",
            get(get_repository_effective_config),
        )
        // Admin-only, read-only view of the gitops apply THIS process
        // performed at boot — its generation fingerprint and object
        // deltas. Reads an in-memory snapshot; touches no port, so it
        // answers even when the database is unhealthy.
        .route("/gitops/apply-status", get(get_gitops_apply_status))
        // Admin-only read of the patch-candidate
        // quarantine surface. Mounted before `post_quarantine_release`
        // so the `/quarantine/*` routes group by path. The handler is
        // gated by the `AdminPrincipal` extractor (same as
        // `post_quarantine_release` below); the use-case-side
        // `require_admin()` is a no-op defence-in-depth check.
        .route(
            "/quarantine/patch-candidates",
            get(get_quarantine_patch_candidates),
        )
        // Admin override
        // release with attribution. The handler requires a non-empty,
        // ≤ 512-byte `justification` in the JSON body so the emitted
        // `ArtifactReleased` event identifies who and why.
        .route(
            "/quarantine/{artifact_id}/release",
            post(post_quarantine_release),
        )
        // Admin-only effective-permissions
        // inspection. Gated by the `AdminPrincipal` extractor (same
        // as the quarantine routes above); the use-case-side
        // `require_admin()` is a no-op defence-in-depth check. This is
        // the audit-time mitigation for the additive-claims
        // operator-discipline cost (ADR 0012;
        // docs/architecture/how-to/operate/claim-based-rbac.md).
        .route(
            "/users/{user_id}/effective-permissions",
            get(get_user_effective_permissions),
        )
        // Admin-only what-if RBAC resolver. Takes a
        // set of IdP groups in the request body and resolves the
        // `groups → claims → effective (repo, permission) grants` half hort
        // owns (no IdP query, no cache). Gated by the `AdminPrincipal`
        // extractor (same as the routes above); the use-case-side
        // `require_admin()` is a no-op defence-in-depth check. Read-only —
        // no domain event.
        .route("/rbac/resolve", post(post_rbac_resolve))
        // Admin-only read of the `scanner_registry` worker-coordination
        // table — "which workers are alive, and what backends do they
        // advertise?". Gated by the `AdminPrincipal` extractor (same as
        // the routes above); the use-case-side `require_admin()` is a
        // no-op defence-in-depth check. Read-only — no domain event.
        .route("/workers", get(get_scanner_workers))
    // There are no REST writes to repository_upstream_mappings;
    // gitops is the only writer. The standalone `UpstreamMappingSpec` gitops
    // kind is that writer — ApplyConfigUseCase emits RepositoryUpstreamMapping
    // rows from it (via `apply_upstream_mappings`). There is no inline
    // `ProxySpec.secret_ref` field (a parsed-but-never-wired field is an
    // anonymous-pull footgun); authenticated upstreams use the
    // `UpstreamMappingSpec` kind, which carries its own `secret_ref`.
}

// ---------------------------------------------------------------------------
// Repository lookup (read-only)
// ---------------------------------------------------------------------------

/// Lean lookup response. Carries only the fields a caller needs to
/// drive its tooling (`id`) and to verify provenance (`managed_by`).
/// Full-repo serialization stays out of the admin surface — anything
/// richer becomes part of a future observability-focused REST API.
#[derive(Debug, Serialize)]
struct RepositoryLookupResponse {
    id: Uuid,
    key: String,
    managed_by: String,
}

async fn get_repository_by_key(
    _admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let repo = ctx.repository_use_case.get_by_key(&key).await?;
    Ok((
        StatusCode::OK,
        Json(RepositoryLookupResponse {
            id: repo.id,
            key: repo.key,
            managed_by: repo.managed_by.to_string(),
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Effective-config read (read-only, admin-only)
// ---------------------------------------------------------------------------

/// Resolved upstream-mapping projection.
///
/// **Hard-omits every secret field** (`secret_ref`, `mtls_cert_ref`,
/// `mtls_key_ref`, `ca_bundle_ref`) — [`hort_domain::ports::secret_port::SecretRef`]
/// derives `Serialize`, so a `#[serde(flatten)]` or a raw
/// [`RepositoryUpstreamMapping`] in the response body would leak the
/// opaque-but-sensitive locator (an env var name or a mounted-file path)
/// into the admin surface. Surfaces at most `has_credentials: bool`.
/// Constructed only via [`Self::from_domain`] — there is no `From`/
/// `#[serde(flatten)]` path that could accidentally carry a secret field
/// through.
#[derive(Debug, Serialize)]
struct EffectiveUpstreamMappingDto {
    path_prefix: String,
    upstream_url: String,
    upstream_auth: &'static str,
    has_credentials: bool,
    insecure_upstream_url: bool,
    trust_upstream_publish_time: bool,
    managed_by: String,
}

impl EffectiveUpstreamMappingDto {
    fn from_domain(m: RepositoryUpstreamMapping) -> Self {
        let upstream_auth = match m.upstream_auth {
            UpstreamAuth::Anonymous => "anonymous",
            UpstreamAuth::BearerChallenge => "bearer_challenge",
            UpstreamAuth::Basic { .. } => "basic",
        };
        Self {
            path_prefix: m.path_prefix,
            upstream_url: m.upstream_url,
            upstream_auth,
            has_credentials: m.secret_ref.is_some(),
            insecure_upstream_url: m.insecure_upstream_url,
            trust_upstream_publish_time: m.trust_upstream_publish_time,
            managed_by: m.managed_by.to_string(),
        }
    }
}

/// Resolved scan-policy projection (repo-scoped > global > built-in
/// default) — see
/// [`hort_app::use_cases::effective_repository_config_use_case::EffectiveRepositoryConfigUseCase::effective_scan_policy`].
#[derive(Debug, Serialize)]
struct EffectiveScanPolicyDto {
    policy_id: Option<Uuid>,
    policy_name: Option<String>,
    severity_threshold: String,
    scan_backends: Vec<String>,
    enforcement: String,
    negligible_action: String,
    quarantine_duration_secs: i64,
}

impl EffectiveScanPolicyDto {
    fn from_view(v: EffectiveScanPolicyView) -> Self {
        Self {
            policy_id: v.policy_id,
            policy_name: v.policy_name,
            severity_threshold: v.severity_threshold.to_string(),
            scan_backends: v.scan_backends,
            enforcement: v.enforcement.to_string(),
            negligible_action: v.negligible_action.to_string(),
            quarantine_duration_secs: v.quarantine_duration_secs,
        }
    }
}

/// Response DTO for `GET /admin/repositories/:key/effective-config`.
///
/// Projects the repository aggregate + its upstream mappings + the
/// resolved scan policy into one read-only view — what the running server
/// actually resolved, for config-drift / policy-binding inspection. Every
/// field is hand-projected in [`get_repository_effective_config`]; the
/// response never `#[serde(flatten)]`s a domain row and no domain type
/// here derives `Serialize` for API purposes beyond what already exists
/// on [`PrefetchPolicy`] (a plain CRUD config value with no secret
/// fields).
#[derive(Debug, Serialize)]
struct EffectiveRepositoryConfigResponse {
    key: String,
    name: String,
    format: String,
    repo_type: String,
    is_public: bool,
    storage_backend: String,
    download_audit_enabled: bool,
    quota_bytes: Option<i64>,
    index_mode: String,
    prefetch_policy: PrefetchPolicy,
    curation_rule_names: Vec<String>,
    managed_by: String,
    upstream_mappings: Vec<EffectiveUpstreamMappingDto>,
    scan_policy: EffectiveScanPolicyDto,
}

async fn get_repository_effective_config(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let repo = ctx.repository_use_case.get_by_key(&key).await?;
    let mappings = ctx
        .repository_upstream_mappings
        .list_for_repository(repo.id)
        .await?;

    // The `AdminPrincipal` extractor already enforced `Permission::Admin`
    // at the request edge; pass `is_admin: true` so the use-case-side
    // gate is a no-op rather than a duplicate authz call (mirrors
    // `get_scanner_workers` above).
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };
    let scan_policy = ctx
        .effective_repository_config_use_case
        .effective_scan_policy(actor, privileges, repo.id)
        .await?;

    let body = EffectiveRepositoryConfigResponse {
        key: repo.key,
        name: repo.name,
        format: repo.format.to_string(),
        repo_type: repo.repo_type.to_string(),
        is_public: repo.is_public,
        storage_backend: repo.storage_backend,
        download_audit_enabled: repo.download_audit_enabled,
        quota_bytes: repo.quota_bytes,
        index_mode: repo.index_mode.to_string(),
        prefetch_policy: repo.prefetch_policy,
        curation_rule_names: repo.curation_rule_names,
        managed_by: repo.managed_by.to_string(),
        upstream_mappings: mappings
            .into_iter()
            .map(EffectiveUpstreamMappingDto::from_domain)
            .collect(),
        scan_policy: EffectiveScanPolicyDto::from_view(scan_policy),
    };

    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Gitops apply-status read (read-only, admin-only)
// ---------------------------------------------------------------------------

/// Create/update/delete/unchanged counts for one gitops kind.
#[derive(Debug, Serialize)]
struct KindCountsDto {
    created: usize,
    updated: usize,
    deleted: usize,
    unchanged: usize,
}

impl From<KindCounts> for KindCountsDto {
    fn from(c: KindCounts) -> Self {
        Self {
            created: c.created,
            updated: c.updated,
            deleted: c.deleted,
            unchanged: c.unchanged,
        }
    }
}

/// Per-kind breakdown of one apply.
///
/// These do **not** sum to the aggregate counters: the aggregate also
/// spans the event-sourced kinds (scan policies, retention policies,
/// exclusions) and the machine-identity kinds (OIDC issuers, service
/// accounts), which have no per-kind breakdown here.
#[derive(Debug, Serialize)]
struct ApplyKindCountsDto {
    repositories: KindCountsDto,
    upstream_mappings: KindCountsDto,
    claim_mappings: KindCountsDto,
    permission_grants: KindCountsDto,
    curation_rules: KindCountsDto,
}

impl From<ApplyKindCounts> for ApplyKindCountsDto {
    fn from(c: ApplyKindCounts) -> Self {
        Self {
            repositories: c.repositories.into(),
            upstream_mappings: c.upstream_mappings.into(),
            claim_mappings: c.claim_mappings.into(),
            permission_grants: c.permission_grants.into(),
            curation_rules: c.curation_rules.into(),
        }
    }
}

/// Response DTO for `GET /admin/gitops/apply-status`.
///
/// `status` is the discriminator an operator (or a script) keys on:
/// `applied` means this process ran a gitops apply and every other field
/// is populated; `no_apply_recorded` means it did not — a DSN-only boot,
/// or gitops disabled — and every other field is omitted. A zeroed
/// "applied" body would be indistinguishable from a genuine no-op apply,
/// which is why the absent case gets its own discriminator instead of
/// default values.
///
/// Hand-projected from [`GitopsApplyStatus`] rather than deriving
/// `Serialize` on the domain-adjacent type, matching the discipline of
/// the effective-config response above. There are no secrets in an apply
/// status — it carries counts, a timestamp and a digest, never a spec
/// body or a `SecretRef` — and the hand projection is what keeps that
/// true as the source type grows.
#[derive(Debug, Serialize)]
struct GitopsApplyStatusResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_at: Option<DateTime<Utc>>,
    /// Hex SHA-256 fingerprint of the applied desired state. Equal
    /// fingerprints across two processes mean they applied the same
    /// configuration; it is not a counter and does not order anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unchanged: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retro_warn_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retro_block_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_kind: Option<ApplyKindCountsDto>,
}

/// Discriminator: this process ran a gitops apply.
const APPLY_STATUS_APPLIED: &str = "applied";
/// Discriminator: this process ran no gitops apply.
const APPLY_STATUS_NONE: &str = "no_apply_recorded";

impl GitopsApplyStatusResponse {
    fn applied(s: &GitopsApplyStatus) -> Self {
        Self {
            status: APPLY_STATUS_APPLIED,
            applied_at: Some(s.applied_at),
            generation: Some(s.generation.clone()),
            created: Some(s.created),
            updated: Some(s.updated),
            deleted: Some(s.deleted),
            unchanged: Some(s.unchanged),
            retro_warn_count: Some(s.retro_warn_count),
            retro_block_count: Some(s.retro_block_count),
            per_kind: Some(s.per_kind.into()),
        }
    }

    fn no_apply_recorded() -> Self {
        Self {
            status: APPLY_STATUS_NONE,
            applied_at: None,
            generation: None,
            created: None,
            updated: None,
            deleted: None,
            unchanged: None,
            retro_warn_count: None,
            retro_block_count: None,
            per_kind: None,
        }
    }
}

/// `GET /admin/gitops/apply-status`.
///
/// Reports the gitops apply **this process** performed at boot. Not a
/// cluster-wide view: during a rolling upgrade two pods legitimately
/// report different generations, and that difference is the signal —
/// it says the rollout has not converged yet.
///
/// Reads an in-memory snapshot behind an `ArcSwap`; it consults no port,
/// so it keeps answering when the database does not.
async fn get_gitops_apply_status(
    _admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
) -> Result<Response, ApiError> {
    let guard = ctx.gitops_apply_status.load();
    let body = match guard.as_ref().as_ref() {
        Some(status) => GitopsApplyStatusResponse::applied(status),
        None => GitopsApplyStatusResponse::no_apply_recorded(),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Admin-only read of the patch-candidate surface
// ---------------------------------------------------------------------------

/// Query parameters for `GET /admin/quarantine/patch-candidates`.
///
/// `repository` filters to a single repository identified by its
/// **stable key** (e.g. `npm-proxy`) — the
/// playbook and the hort-cli surface both pass `--repo <key>`. Absent →
/// admin-wide scope. The handler resolves the key to a `Uuid` via
/// `RepositoryRepository::find_by_key`; a missing key surfaces as 404
/// with a structured `{"error":"repository_not_found","key":...}`
/// body. `Uuid`-shaped values are NOT accepted — keys are the
/// operator-facing identity in v2 (UUIDs are an internal detail and
/// are minted at first apply).
///
/// `limit` caps the row count, defaulting to 100 server-side when
/// absent and bounded to `1..=500` by the handler before dispatch to
/// the use case.
///
/// Serde-deserialising `u32` from a query-string value rejects values
/// that don't parse as an unsigned integer at extraction time,
/// producing a 400 from axum's `Query` extractor automatically — no
/// boundary check needed here. The handler body only re-validates
/// the `1..=500` window because that's a domain rule, not a parse
/// rule.
#[derive(Debug, Deserialize)]
struct PatchCandidatesQuery {
    repository: Option<String>,
    limit: Option<u32>,
}

/// Response DTO for `GET /admin/quarantine/patch-candidates`.
///
/// The domain [`PatchCandidate`] type does NOT derive `Serialize`
/// (no domain-type wire coupling); this DTO is the wire-format
/// counterpart and is constructed via [`PatchCandidateDto::from_domain`]
/// in the handler body. Enum fields are projected as their `Display`
/// strings so the JSON carries `"quarantined"` / `"npm"` / `"high"`
/// rather than the integer / variant-name shapes serde would produce.
#[derive(Debug, Serialize)]
struct PatchCandidateResponseDto {
    candidates: Vec<PatchCandidateDto>,
}

/// Wire-format row for [`PatchCandidateResponseDto`].
///
/// Field set mirrors the 12-field domain type one-to-one. `DateTime<Utc>`
/// serialises as ISO-8601 via the default chrono serde impl.
#[derive(Debug, Serialize)]
struct PatchCandidateDto {
    quarantined_artifact_id: Uuid,
    quarantined_version: Option<String>,
    /// Rendered as the lowercase status string ("quarantined", etc.)
    /// via the [`QuarantineStatus`](hort_domain::entities::artifact::QuarantineStatus)
    /// `Display` impl. Always `"quarantined"` for rows surfaced by
    /// this endpoint; the field is preserved for symmetry with the
    /// domain DTO and so any future relaxation of the filter remains
    /// forward-compatible.
    quarantined_status: String,
    quarantined_until: Option<DateTime<Utc>>,
    repository_id: Uuid,
    /// `repositories.key` resolved by the Postgres adapter
    /// and passed through verbatim by the use case.
    repository_key: String,
    /// Rendered as the lowercase format key ("npm", "pypi", …) via
    /// the [`RepositoryFormat`](hort_domain::entities::repository::RepositoryFormat)
    /// `Display` impl. Stable surface — operators script against
    /// these names.
    format: String,
    package_name: String,
    vulnerable_artifact_id: Uuid,
    vulnerable_version: Option<String>,
    vulnerable_finding_count: u32,
    /// Rendered as the lowercase severity string ("critical", "high",
    /// "medium", "low") via the
    /// [`SeverityThreshold`](hort_domain::entities::scan_policy::SeverityThreshold)
    /// `Display` impl. `None` is the type-level possibility for
    /// "no findings"; the LATERAL filter prevents it in practice.
    vulnerable_max_severity: Option<String>,
}

impl PatchCandidateDto {
    /// Domain → wire-format projection. Private so the only path to a
    /// `PatchCandidateDto` is through the use case (`PatchCandidate`
    /// → `PatchCandidateDto`); inbound HTTP cannot synthesise rows out
    /// of thin air.
    fn from_domain(c: PatchCandidate) -> Self {
        Self {
            quarantined_artifact_id: c.quarantined_artifact_id,
            quarantined_version: c.quarantined_version,
            quarantined_status: c.quarantined_status.to_string(),
            quarantined_until: c.quarantined_until,
            repository_id: c.repository_id,
            repository_key: c.repository_key,
            format: c.format.to_string(),
            package_name: c.package_name,
            vulnerable_artifact_id: c.vulnerable_artifact_id,
            vulnerable_version: c.vulnerable_version,
            vulnerable_finding_count: c.vulnerable_finding_count,
            vulnerable_max_severity: c.vulnerable_max_severity.map(|s| s.to_string()),
        }
    }
}

async fn get_quarantine_patch_candidates(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<PatchCandidatesQuery>,
) -> Result<Response, ApiError> {
    // Resolve the limit: missing → use-case default (100); supplied →
    // validate the `1..=500` window at the boundary so the use case
    // never sees `0` or oversize values. `> MAX_LIMIT` is also
    // re-checked by the use case as defence-in-depth —
    // both gates surface the same shape (400 + Validation), so a
    // future caller bypassing this handler still hits the same wall.
    let limit = match query.limit {
        None => PatchCandidateFilter::default().limit,
        Some(n) => {
            if n == 0 || n > PATCH_CANDIDATE_MAX_LIMIT {
                return Err(ApiError(AppError::Domain(DomainError::Validation(
                    format!("limit must be in 1..={PATCH_CANDIDATE_MAX_LIMIT} (got {n})"),
                ))));
            }
            n
        }
    };

    // `?repository=<key>` is the wire form.
    // Resolve the operator-facing key to a UUID via the repository
    // port; a missing key surfaces as 404 with a structured body so
    // operator tooling can distinguish "unknown key" from generic
    // 404s. The resolved key is then threaded into
    // `repository_key_for_metric` so the use-case-side metric
    // emission carries the actual key on every result path;
    // the resolved id is the query filter the
    // adapter uses.
    let (repository_id, repository_key_for_metric) = match query.repository {
        None => (None, None),
        Some(key) => match ctx.repository_use_case.get_by_key(&key).await {
            Ok(repo) => (Some(repo.id), Some(repo.key)),
            Err(AppError::Domain(DomainError::NotFound { .. })) => {
                let body = serde_json::json!({
                    "error": "repository_not_found",
                    "key": key,
                });
                return Ok((StatusCode::NOT_FOUND, Json(body)).into_response());
            }
            Err(other) => return Err(ApiError(other)),
        },
    };

    let filter = PatchCandidateFilter {
        repository_id,
        limit,
        repository_key_for_metric,
    };

    // The AdminPrincipal extractor already enforced Permission::Admin
    // at the request edge; pass `is_admin: true` so the use-case-side
    // gate is a no-op rather than a duplicate authz call. The use
    // case is the canonical info-log emission site for this read
    // — the handler does not log at info-level itself.
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };

    let candidates = ctx
        .patch_candidate_use_case
        .list(actor, privileges, filter)
        .await?;

    let body = PatchCandidateResponseDto {
        candidates: candidates
            .into_iter()
            .map(PatchCandidateDto::from_domain)
            .collect(),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Admin-only read of the scanner-worker registry
// ---------------------------------------------------------------------------

/// Response DTO for `GET /admin/workers`.
#[derive(Debug, Serialize)]
struct ScannerWorkersResponseDto {
    workers: Vec<ScannerWorkerDto>,
}

/// Wire-format row for [`ScannerWorkersResponseDto`]. Mirrors
/// [`ScannerWorkerView`] one-to-one; `DateTime<Utc>` serialises as
/// ISO-8601 via the default chrono serde impl. Constructed only via
/// [`ScannerWorkerDto::from_view`] — inbound HTTP cannot synthesise rows.
#[derive(Debug, Serialize)]
struct ScannerWorkerDto {
    worker_id: String,
    backends: Vec<String>,
    registered_at: DateTime<Utc>,
    last_heartbeat: DateTime<Utc>,
    /// `true` when the last heartbeat is within the use case's liveness
    /// threshold (~5 min); a stale worker stays in the listing with
    /// `live = false` rather than vanishing.
    live: bool,
    last_seen_secs_ago: i64,
}

impl ScannerWorkerDto {
    fn from_view(v: ScannerWorkerView) -> Self {
        Self {
            worker_id: v.worker_id,
            backends: v.backends,
            registered_at: v.registered_at,
            last_heartbeat: v.last_heartbeat,
            live: v.live,
            last_seen_secs_ago: v.last_seen_secs_ago,
        }
    }
}

async fn get_scanner_workers(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
) -> Result<Response, ApiError> {
    // The AdminPrincipal extractor already enforced Permission::Admin at
    // the request edge; pass `is_admin: true` so the use-case-side gate is
    // a no-op rather than a duplicate authz call.
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };

    let workers = ctx
        .scanner_worker_query_use_case
        .list(actor, privileges)
        .await?;

    let body = ScannerWorkersResponseDto {
        workers: workers
            .into_iter()
            .map(ScannerWorkerDto::from_view)
            .collect(),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Admin override release with attribution
// ---------------------------------------------------------------------------

/// Request DTO for `POST /admin/quarantine/:artifact_id/release`.
///
/// `justification` is operator-supplied free text recorded in the
/// emitted `ArtifactReleased` event so audit consumers can reconstruct
/// the override decision. It MUST be non-empty and ≤ 512 bytes —
/// rejected with 400 at the boundary so the use case never sees
/// invalid input. The size limit mirrors the domain-layer cap
/// (`ArtifactReleased::validate`).
#[derive(Debug, Deserialize)]
struct AdminReleaseRequest {
    justification: String,
}

async fn post_quarantine_release(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(artifact_id): Path<Uuid>,
    Json(body): Json<AdminReleaseRequest>,
) -> Result<Response, ApiError> {
    // Boundary validation — empty or oversize justification surfaces
    // as 400 BEFORE we touch the use case. Trim is intentional:
    // whitespace-only input is the same UX failure mode as empty
    // (operators copy-pasting an accidental newline), and the
    // event-store auditor reading "    " as a justification is the
    // same negative outcome as missing.
    let trimmed = body.justification.trim();
    if trimmed.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "justification must not be empty".into(),
        ))));
    }
    // Cap is on byte length (not char count) to match the domain
    // 512-byte invariant exactly. UTF-8 multibyte sequences count
    // as their byte length.
    if body.justification.len() > MAX_RELEASE_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "justification exceeds {MAX_RELEASE_JUSTIFICATION_BYTES} bytes (got {})",
                body.justification.len()
            ),
        ))));
    }

    // The AdminPrincipal extractor already enforced Permission::Admin
    // at the request edge; pass `is_admin: true` so the use-case-side
    // gate is a no-op rather than a duplicate authz call. The use
    // case is the single emission point for the audit log line, so
    // we keep `require_admin()` engaged inside the use case for
    // defence-in-depth (a future caller that bypasses this handler
    // can't accidentally skip the gate).
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };

    ctx.quarantine_use_case
        .admin_release(artifact_id, actor, privileges, body.justification)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Admin-only effective-permissions inspection
// ---------------------------------------------------------------------------

/// Wire shape of a grant's subject.
///
/// The domain [`GrantSubject`] is intentionally not `Serialize`
/// (server-constructed, never deserialised from request input —
/// architect anti-pattern: no domain-type wire coupling in the API
/// layer). This handler-local enum is the wire counterpart, projected
/// via [`GrantSourceDto::from_domain`]. `kind` is the discriminator;
/// `required` is present only for the `claims` arm. The `user` arm
/// carries no id because the inspected `user_id` is already the
/// top-level response field (§8.2 example: `{ "kind": "user" }`).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GrantSourceDto {
    Claims { required: Vec<String> },
    User,
}

impl GrantSourceDto {
    fn from_domain(s: GrantSubject) -> Self {
        match s {
            GrantSubject::Claims(required) => Self::Claims { required },
            GrantSubject::User(_) => Self::User,
        }
    }
}

/// One effective grant row. `repository_id = null` ⇒
/// global grant; `Some(_)` ⇒ repository-scoped. `permission` is the
/// lowercase [`Permission`](hort_domain::entities::rbac::Permission)
/// `Display` string (`"read"` / `"write"` / `"admin"` / …).
#[derive(Debug, Serialize)]
struct EffectiveGrantDto {
    repository_id: Option<Uuid>,
    permission: String,
    source: GrantSourceDto,
}

impl EffectiveGrantDto {
    fn from_domain(g: EffectiveGrant) -> Self {
        Self {
            repository_id: g.repository_id,
            permission: g.permission.to_string(),
            source: GrantSourceDto::from_domain(g.source),
        }
    }
}

/// Operator-facing hint paired with the
/// [`EffectivePermissionsResponseDto::claim_based_authority`] marker —
/// tells an auditor where to resolve the claim-based half this surface
/// cannot.
const CLAIM_BASED_AUTHORITY_HINT: &str =
    "claim-based authority is resolved live from the user's IdP groups — \
     use POST /api/v1/admin/rbac/resolve with the user's groups (from your \
     IdP/user-management)";

/// Response DTO for
/// `GET /admin/users/:user_id/effective-permissions`.
///
/// Reports only what hort knows about a user *without their token*: the
/// `is_admin` bit and the matching grant rows (`User`-subject grants, plus
/// synthetic-`admin`-derived grants for an admin user). The user's
/// claim-based authority cannot be resolved here — there is no claims
/// cache and OIDC resolves claims live at login — so instead
/// of an always-`[]` `claims` field this carries an honest
/// `claim_based_authority` marker and a `claim_based_authority_hint`
/// pointing at the `POST /api/v1/admin/rbac/resolve` what-if resolver.
#[derive(Debug, Serialize)]
struct EffectivePermissionsResponseDto {
    user_id: Uuid,
    is_admin: bool,
    /// Always `"not_resolvable_without_session"` — the per-user surface
    /// cannot resolve claim-based authority without the user's session.
    claim_based_authority: String,
    /// Where to resolve the claim-based half (the what-if resolver).
    claim_based_authority_hint: &'static str,
    grants: Vec<EffectiveGrantDto>,
}

impl EffectivePermissionsResponseDto {
    fn from_domain(ep: EffectivePermissions) -> Self {
        Self {
            user_id: ep.user_id,
            is_admin: ep.is_admin,
            claim_based_authority: ep.claim_based_authority.to_string(),
            claim_based_authority_hint: CLAIM_BASED_AUTHORITY_HINT,
            grants: ep
                .grants
                .into_iter()
                .map(EffectiveGrantDto::from_domain)
                .collect(),
        }
    }
}

async fn get_user_effective_permissions(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(user_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    // The AdminPrincipal extractor already enforced Permission::Admin
    // at the request edge; pass `is_admin: true` so the use-case-side
    // gate is a no-op rather than a duplicate authz call. The use case
    // is the single info-level audit-log + metric emission site
    // — the handler does not log or emit itself.
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };

    let view = ctx
        .effective_permissions_use_case
        .for_user(actor, privileges, user_id)
        .await?;

    let body = EffectivePermissionsResponseDto::from_domain(view);
    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Admin-only what-if RBAC resolver
// ---------------------------------------------------------------------------

/// Request DTO for `POST /admin/rbac/resolve`.
///
/// `groups` is the operator-supplied IdP-group set (from their own
/// IdP / user-management) the resolver flattens through `claim_mappings`
/// into claims. Handler-local and `Deserialize`-only — domain types stay
/// `Deserialize`-free (architect anti-pattern: no domain-type wire coupling
/// in the API layer). An empty array is valid: it resolves to the empty
/// footprint, not an error.
#[derive(Debug, Deserialize)]
struct RbacResolveRequest {
    groups: Vec<String>,
}

/// One resolved effective grant. `repository = null` ⇒
/// global grant; `Some(key)` ⇒ repository-scoped. `permission` is the
/// lowercase [`Permission`](hort_domain::entities::rbac::Permission)
/// `Display` string.
///
/// The value is the repository **key** — never the raw UUID, which would
/// be inconsistent with whoami's `effective_grants`,
/// which renders keys. The id→key mapping +
/// dangling-repo omission happen in [`post_rbac_resolve`], mirroring
/// whoami's `render_cells`.
#[derive(Debug, Serialize)]
struct ResolvedGrantDto {
    repository: Option<String>,
    permission: String,
}

/// Response DTO for `POST /admin/rbac/resolve`.
///
/// `resolved_claims` is the claim set the supplied groups map to;
/// `effective_grants` is the `(repository, permission)` footprint those
/// claims hold (empty when `global_admin` is `true` — the marker stands in
/// for the full authority, never an enumeration); `global_admin` is `true`
/// when a supplied group is mapped to the `admin` claim.
#[derive(Debug, Serialize)]
struct RbacResolveResponseDto {
    resolved_claims: Vec<String>,
    effective_grants: Vec<ResolvedGrantDto>,
    global_admin: bool,
}

// `RbacResolveResponseDto` is built inline in `post_rbac_resolve` (the
// repository id→key mapping is async — it calls `repository_use_case` — so
// it cannot live in a sync `from_domain`).

async fn post_rbac_resolve(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<RbacResolveRequest>,
) -> Result<Response, ApiError> {
    // The AdminPrincipal extractor already enforced Permission::Admin at
    // the request edge; pass `is_admin: true` so the use-case-side gate is
    // a no-op rather than a duplicate authz call. The use case is the
    // single info-level audit-log emission site — the handler
    // does not log itself. Read-only: no domain event.
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };

    let resolved = ctx
        .rbac_resolve_use_case
        .resolve(actor, privileges, body.groups)
        .await?;

    // Map each grant's repository_id → key, mirroring
    // whoami's `render_cells`: a dangling/deleted repo is omitted rather
    // than rendered as its UUID or a misleading `null` (which would read as
    // a global grant).
    let mut effective_grants = Vec::with_capacity(resolved.effective_grants.len());
    for grant in &resolved.effective_grants {
        let repository = match grant.repository_id {
            None => None,
            Some(id) => match ctx.repository_use_case.get_by_id(id).await {
                Ok(repo) => Some(repo.key),
                Err(_) => continue,
            },
        };
        effective_grants.push(ResolvedGrantDto {
            repository,
            permission: grant.permission.to_string(),
        });
    }
    let response = RbacResolveResponseDto {
        resolved_claims: resolved.resolved_claims,
        effective_grants,
        global_admin: resolved.global_admin,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    //! Admin handler tests.
    //!
    //! The suite runs under [`AuthContext::Enabled`] and injects a
    //! [`CallerPrincipal`] into request extensions manually — the
    //! `AdminPrincipal` extractor pulls from that slot, skipping the
    //! `require_principal` auth middleware (which needs a live IdP).
    //! This mirrors the pattern in `crate::authz::extractors::tests`.

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use super::*;
    use crate::test_support::{build_mock_ctx, with_auth};

    /// Build a principal whose resolved claim set is `claims` (the
    /// additive-claims model, ADR 0012 — a single
    /// `claims` field). The admin-only
    /// endpoints in this module short-circuit on `claims.contains("admin")`;
    /// callers pass `["admin"]` for the authorised case and a non-`admin`
    /// claim (e.g. `["reader"]`) for the negative cases.
    fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Construct a `GET /admin/repositories/<key>` request with an
    /// optional pre-inserted principal. When `principal` is `None`
    /// the AdminPrincipal extractor returns 500 (router-wiring bug).
    ///
    /// The principal is wrapped in
    /// the `AuthenticatedPrincipal` newtype before insertion. The
    /// extractors no longer consult the bare `CallerPrincipal` slot.
    fn admin_get(key: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::get(format!("/admin/repositories/{key}"))
            .body(Body::empty())
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// Build a router with the repository mock visible. Returns the
    /// router AND the mock so tests can seed a row before the GET.
    fn lookup_harness() -> (
        Router,
        Arc<hort_app::use_cases::test_support::MockRepositoryRepository>,
    ) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let repos = mocks.repositories.clone();

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                // Admin handler
                // tests don't exercise the WWW-Authenticate selector.
                issuer_url: None,
            },
        );
        let router = Router::new().nest("/admin", admin_routes()).with_state(ctx);
        (router, repos)
    }

    // ----- GET /admin/repositories/:key — repository lookup ----------

    #[tokio::test]
    async fn admin_get_returns_lookup_response_for_managed_repo() {
        use hort_app::use_cases::test_support::sample_repository;
        let (router, repos) = lookup_harness();

        // Seed a managed-by-gitops row directly into the mock —
        // mirrors what the boot apply produces in production.
        let mut row = sample_repository();
        row.key = "pypi-e2e".into();
        row.managed_by = ManagedBy::GitOps;
        row.managed_by_digest = Some([0xab; 32]);
        let row_id = row.id;
        repos.insert(row);

        let response = router
            .oneshot(admin_get(
                "pypi-e2e",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["id"], row_id.to_string());
        assert_eq!(v["key"], "pypi-e2e");
        assert_eq!(
            v["managed_by"], "gitops",
            "lookup response must surface provenance so tooling can route on it"
        );
    }

    #[tokio::test]
    async fn admin_get_unknown_key_returns_404() {
        let (router, _) = lookup_harness();
        let response = router
            .oneshot(admin_get(
                "no-such-repo",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_get_reader_principal_returns_403() {
        // AdminPrincipal extractor short-circuits on caller identity
        // before the handler body runs. The seeded row therefore never
        // matters; we don't bother seeding.
        let (router, _) = lookup_harness();
        let response = router
            .oneshot(admin_get(
                "pypi-e2e",
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            &bytes[..],
            br#"{"error":"insufficient permissions"}"#,
            "body must match the extractor's 403 shape"
        );
    }

    #[tokio::test]
    async fn admin_get_missing_principal_returns_500() {
        // Models the router-wiring bug where `require_principal` is
        // absent — the extractor surfaces it as 500.
        let (router, _) = lookup_harness();
        let response = router.oneshot(admin_get("pypi-e2e", None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        crate::error::assert_no_internal_leakage(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
    }

    // ----- GET /admin/repositories/:key/effective-config --------------

    /// Build a router exposing `/admin` plus the full `MockPorts` handle,
    /// so tests can seed a repo (`mocks.repositories`), upstream mappings
    /// (`mocks.repository_upstream_mappings`), and a scan policy
    /// (`mocks.policy_projections`) before the GET.
    fn effective_config_harness() -> (Router, crate::test_support::MockPorts) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new().nest("/admin", admin_routes()).with_state(ctx);
        (router, mocks)
    }

    fn effective_config_get(key: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::get(format!("/admin/repositories/{key}/effective-config"))
            .body(Body::empty())
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// A mapping carrying every secret-bearing field set, so the
    /// secrets-exclusion assertion below actually exercises the omission
    /// (a mapping with every secret field `None` would pass the assertion
    /// vacuously). Constructed via struct literal — safe in test
    /// scaffolding (see the port module's doc comment).
    fn mapping_with_all_secrets(repository_id: Uuid) -> RepositoryUpstreamMapping {
        use hort_domain::ports::secret_port::{SecretRef, SecretSource};
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id,
            path_prefix: String::new(),
            upstream_url: "https://upstream.example.com".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Basic {
                username: "svc-upstream".into(),
            },
            secret_ref: Some(SecretRef {
                source: SecretSource::EnvVar,
                location: "UPSTREAM_PASSWORD_ENV".into(),
            }),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x11; 32]),
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: Some(SecretRef {
                source: SecretSource::File,
                location: "/etc/hort-secrets/mtls-cert.pem".into(),
            }),
            mtls_key_ref: Some(SecretRef {
                source: SecretSource::File,
                location: "/etc/hort-secrets/mtls-key.pem".into(),
            }),
            ca_bundle_ref: Some(SecretRef {
                source: SecretSource::File,
                location: "/etc/hort-secrets/ca-bundle.pem".into(),
            }),
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn effective_config_admin_returns_projected_shape() {
        use hort_app::use_cases::test_support::sample_repository;
        use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;

        let (router, mocks) = effective_config_harness();

        let mut repo = sample_repository();
        repo.key = "npm-proxy".into();
        repo.curation_rule_names = vec!["no-gpl".into()];
        let repo_id = repo.id;
        mocks.repositories.insert(repo);

        mocks
            .repository_upstream_mappings
            .upsert(mapping_with_all_secrets(repo_id))
            .await
            .unwrap();

        let response = router
            .oneshot(effective_config_get(
                "npm-proxy",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["key"], "npm-proxy");
        assert_eq!(v["curation_rule_names"][0], "no-gpl");
        assert_eq!(
            v["upstream_mappings"][0]["upstream_url"],
            "https://upstream.example.com"
        );
        assert_eq!(v["upstream_mappings"][0]["upstream_auth"], "basic");
        assert_eq!(v["upstream_mappings"][0]["has_credentials"], true);
        assert_eq!(v["upstream_mappings"][0]["managed_by"], "gitops");
        // `build_mock_ctx` pre-seeds a permissive global policy
        // (`seed_permissive_global_policy_for_tests`) — assert the
        // resolved-policy branch of the projection against it. The
        // no-policy-bound → `DefaultPolicy` fallback branch is covered by
        // `effective_scan_policy_admin_no_policy_returns_default_policy_view`
        // in the use case's own unit tests.
        assert_eq!(
            v["scan_policy"]["policy_name"],
            "permissive-http-test-default"
        );
        assert_eq!(v["scan_policy"]["severity_threshold"], "critical");
        assert_eq!(v["scan_policy"]["quarantine_duration_secs"], 0);
    }

    #[tokio::test]
    async fn effective_config_no_secret_field_names_or_values_in_body() {
        use hort_app::use_cases::test_support::sample_repository;
        use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;

        let (router, mocks) = effective_config_harness();

        let mut repo = sample_repository();
        repo.key = "docker-proxy".into();
        let repo_id = repo.id;
        mocks.repositories.insert(repo);

        mocks
            .repository_upstream_mappings
            .upsert(mapping_with_all_secrets(repo_id))
            .await
            .unwrap();

        let response = router
            .oneshot(effective_config_get(
                "docker-proxy",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();

        for field in [
            "secret_ref",
            "mtls_cert_ref",
            "mtls_key_ref",
            "ca_bundle_ref",
        ] {
            assert!(
                !body.contains(field),
                "response body must never carry the `{field}` field name: {body}"
            );
        }
        for secret_value in [
            "UPSTREAM_PASSWORD_ENV",
            "/etc/hort-secrets/mtls-cert.pem",
            "/etc/hort-secrets/mtls-key.pem",
            "/etc/hort-secrets/ca-bundle.pem",
        ] {
            assert!(
                !body.contains(secret_value),
                "response body must never carry the secret locator `{secret_value}`: {body}"
            );
        }
    }

    #[tokio::test]
    async fn effective_config_reader_principal_returns_403() {
        use hort_app::use_cases::test_support::sample_repository;
        let (router, mocks) = effective_config_harness();
        let mut repo = sample_repository();
        repo.key = "npm-proxy".into();
        mocks.repositories.insert(repo);

        let response = router
            .oneshot(effective_config_get(
                "npm-proxy",
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn effective_config_anonymous_returns_401() {
        let (router, _mocks) = effective_config_harness();
        let mut req = Request::get("/admin/repositories/npm-proxy/effective-config")
            .body(Body::empty())
            .unwrap();
        crate::middleware::auth::test_support::inject_optional_principal_none(&mut req);

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn effective_config_unknown_repo_returns_404() {
        let (router, _mocks) = effective_config_harness();
        let response = router
            .oneshot(effective_config_get(
                "no-such-repo",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ----- GET /admin/gitops/apply-status ------------------------------

    /// Router over `/admin` plus the `AppContext`, so a test can install
    /// a recorded apply on the `ArcSwap` before the GET. Mirrors
    /// [`effective_config_harness`]; it hands back the context rather
    /// than the mock ports because the apply-status surface touches no
    /// port at all.
    fn apply_status_harness() -> (Router, Arc<AppContext>) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new()
            .nest("/admin", admin_routes())
            .with_state(ctx.clone());
        (router, ctx)
    }

    fn apply_status_get(principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::get("/admin/gitops/apply-status")
            .body(Body::empty())
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// A status with every counter distinct, so a field mixed up in the
    /// hand projection shows up as a wrong number rather than passing on
    /// coincidentally equal values.
    fn recorded_status() -> GitopsApplyStatus {
        GitopsApplyStatus {
            applied_at: Utc::now(),
            generation: "ab".repeat(32),
            created: 1,
            updated: 2,
            deleted: 3,
            unchanged: 4,
            retro_warn_count: 5,
            retro_block_count: 6,
            per_kind: ApplyKindCounts {
                repositories: KindCounts {
                    created: 7,
                    updated: 8,
                    deleted: 9,
                    unchanged: 10,
                },
                upstream_mappings: KindCounts {
                    created: 11,
                    ..KindCounts::default()
                },
                claim_mappings: KindCounts {
                    updated: 12,
                    ..KindCounts::default()
                },
                permission_grants: KindCounts {
                    deleted: 13,
                    ..KindCounts::default()
                },
                curation_rules: KindCounts {
                    unchanged: 14,
                    ..KindCounts::default()
                },
            },
        }
    }

    #[tokio::test]
    async fn apply_status_admin_sees_the_recorded_apply() {
        let (router, ctx) = apply_status_harness();
        let status = recorded_status();
        ctx.gitops_apply_status
            .store(Arc::new(Some(status.clone())));

        let response = router
            .oneshot(apply_status_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(v["status"], "applied");
        assert_eq!(v["generation"], status.generation);
        assert_eq!(v["created"], 1);
        assert_eq!(v["updated"], 2);
        assert_eq!(v["deleted"], 3);
        assert_eq!(v["unchanged"], 4);
        assert_eq!(v["retro_warn_count"], 5);
        assert_eq!(v["retro_block_count"], 6);
        assert!(
            v["applied_at"].is_string(),
            "applied_at must serialize as an RFC 3339 string: {v}"
        );

        assert_eq!(v["per_kind"]["repositories"]["created"], 7);
        assert_eq!(v["per_kind"]["repositories"]["updated"], 8);
        assert_eq!(v["per_kind"]["repositories"]["deleted"], 9);
        assert_eq!(v["per_kind"]["repositories"]["unchanged"], 10);
        assert_eq!(v["per_kind"]["upstream_mappings"]["created"], 11);
        assert_eq!(v["per_kind"]["claim_mappings"]["updated"], 12);
        assert_eq!(v["per_kind"]["permission_grants"]["deleted"], 13);
        assert_eq!(v["per_kind"]["curation_rules"]["unchanged"], 14);
    }

    /// The absent case is its own discriminator, not a zeroed body: a
    /// boot that ran no apply must be distinguishable from a genuine
    /// no-op apply.
    #[tokio::test]
    async fn apply_status_without_an_apply_reports_no_apply_recorded() {
        let (router, _ctx) = apply_status_harness();

        let response = router
            .oneshot(apply_status_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "no_apply_recorded");
        for absent in [
            "applied_at",
            "generation",
            "created",
            "updated",
            "deleted",
            "unchanged",
            "retro_warn_count",
            "retro_block_count",
            "per_kind",
        ] {
            assert!(
                v.get(absent).is_none(),
                "`{absent}` must be omitted when no apply was recorded, \
                 not reported as a zero: {v}"
            );
        }
    }

    /// A genuine no-op apply still reports `applied` with zeros — the
    /// counterpart to the test above, pinning that the two cases stay
    /// distinguishable in both directions.
    #[tokio::test]
    async fn apply_status_reports_a_no_op_apply_as_applied() {
        let (router, ctx) = apply_status_harness();
        ctx.gitops_apply_status
            .store(Arc::new(Some(GitopsApplyStatus::from_report(
                hort_app::use_cases::apply_config_use_case::ApplyReport::default(),
                [0u8; 32],
                Utc::now(),
            ))));

        let response = router
            .oneshot(apply_status_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "applied");
        assert_eq!(v["created"], 0);
        assert_eq!(v["per_kind"]["repositories"]["created"], 0);
    }

    #[tokio::test]
    async fn apply_status_reader_principal_returns_403() {
        let (router, ctx) = apply_status_harness();
        ctx.gitops_apply_status
            .store(Arc::new(Some(recorded_status())));

        let response = router
            .oneshot(apply_status_get(Some(principal_with_claims(&["reader"]))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn apply_status_anonymous_returns_401() {
        let (router, ctx) = apply_status_harness();
        ctx.gitops_apply_status
            .store(Arc::new(Some(recorded_status())));

        let mut req = Request::get("/admin/gitops/apply-status")
            .body(Body::empty())
            .unwrap();
        crate::middleware::auth::test_support::inject_optional_principal_none(&mut req);

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The status is a counts-and-digest view: no spec bodies, no
    /// credential locators, nothing an apply read out of a `SecretRef`.
    /// The DTO is hand-projected precisely so that stays true as
    /// `GitopsApplyStatus` grows; this pins the current shape.
    #[tokio::test]
    async fn apply_status_body_carries_only_counts_and_a_digest() {
        let (router, ctx) = apply_status_harness();
        ctx.gitops_apply_status
            .store(Arc::new(Some(recorded_status())));

        let response = router
            .oneshot(apply_status_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "applied_at",
                "created",
                "deleted",
                "generation",
                "per_kind",
                "retro_block_count",
                "retro_warn_count",
                "status",
                "unchanged",
                "updated",
            ],
            "a new top-level field on the apply-status response is a \
             deliberate API change — add it here once you have confirmed \
             it carries no secret"
        );

        let body = String::from_utf8(bytes.to_vec()).unwrap();
        for leaked in ["secret_ref", "secretRef", "upstream_url", "spec"] {
            assert!(
                !body.contains(leaked),
                "apply-status must never carry `{leaked}`: {body}"
            );
        }
    }

    // There is no `POST /admin/repositories` create endpoint
    // (gitops-only lifecycle). Tests for the
    // create-side `ManagedByConfiguration` collision check, the
    // proxy-without-upstream-url validator, and the unknown-format
    // guard live in `hort-app::use_cases::repository_use_case::tests`
    // since the use case is still callable in-process.

    // There are no admin upstream-mapping endpoints
    // (POST/DELETE /admin/repositories/:id/upstreams[/:prefix]).
    // Gitops is the only writer: the standalone
    // `UpstreamMappingSpec` gitops kind drives ApplyConfigUseCase to emit
    // RepositoryUpstreamMapping rows (via `apply_upstream_mappings`); there
    // is no inline `ProxySpec.secret_ref` field
    // (parsed-but-never-wired); authenticated upstreams use the
    // `UpstreamMappingSpec` kind's own `secret_ref`.

    // ----- POST /admin/quarantine/:id/release — admin override release ----

    use hort_app::use_cases::test_support::{sample_artifact, sample_repository};
    use hort_domain::entities::artifact::QuarantineStatus;

    /// Build a router that exposes `/admin` and returns the
    /// `MockPorts` so tests can seed an artifact + repo before
    /// exercising `POST /admin/quarantine/:id/release`.
    fn release_harness() -> (Router, crate::test_support::MockPorts, Arc<AppContext>) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                // Admin handler
                // tests don't exercise the WWW-Authenticate selector.
                issuer_url: None,
            },
        );
        let router = Router::new()
            .nest("/admin", admin_routes())
            .with_state(ctx.clone());
        (router, mocks, ctx)
    }

    /// Construct `POST /admin/quarantine/<id>/release` with the
    /// supplied JSON body and an optional pre-inserted admin
    /// principal. When `principal` is `None`, the AdminPrincipal
    /// extractor surfaces 500 (router-wiring bug per existing
    /// admin_get test pattern).
    fn release_post(
        artifact_id: Uuid,
        body: &str,
        principal: Option<CallerPrincipal>,
    ) -> Request<Body> {
        let mut req = Request::post(format!("/admin/quarantine/{artifact_id}/release"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// Seed a quarantined artifact + matching repository row in the
    /// mocks. Returns the artifact id so the test can drive the
    /// release route.
    fn seed_quarantined(mocks: &crate::test_support::MockPorts) -> Uuid {
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);
        id
    }

    /// Happy path: admin caller, valid body, quarantined artifact →
    /// 204 NO CONTENT and the use case emits `ArtifactReleased`
    /// with `released_by_user_id` + `justification` populated.
    #[tokio::test]
    async fn admin_release_happy_path_returns_204() {
        let (router, mocks, _ctx) = release_harness();
        let artifact_id = seed_quarantined(&mocks);

        let principal = principal_with_claims(&["admin"]);
        let admin_user_id = principal.user_id;

        let body = r#"{"justification":"CVE-2026-XXXX accepted: false-positive"}"#;
        let response = router
            .oneshot(release_post(artifact_id, body, Some(principal)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify the use case actually emitted the ArtifactReleased
        // event with the admin attribution. The lifecycle mock
        // captures every commit_transition.
        let transitions = mocks.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (_saved, batch, _meta) = &transitions[0];
        let event = &batch.events[0].event;
        match event {
            hort_domain::events::DomainEvent::ArtifactReleased(e) => {
                assert_eq!(e.released_by, hort_domain::events::ReleaseReason::Admin);
                assert_eq!(e.released_by_user_id, Some(admin_user_id));
                assert_eq!(
                    e.justification,
                    Some("CVE-2026-XXXX accepted: false-positive".into())
                );
                assert!(e.validate().is_ok());
            }
            other => panic!("expected ArtifactReleased, got {other:?}"),
        }
    }

    /// Empty justification → 400 BEFORE the use case is touched.
    /// The lifecycle mock must not record any commit.
    #[tokio::test]
    async fn admin_release_empty_justification_returns_400() {
        let (router, mocks, _ctx) = release_harness();
        let artifact_id = seed_quarantined(&mocks);

        let body = r#"{"justification":""}"#;
        let response = router
            .oneshot(release_post(
                artifact_id,
                body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // Use case is never called on a 400 — proves the boundary
        // gate fires before the application layer.
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Whitespace-only justification → 400. Operator hits Enter
    /// in a textarea or copy-pastes a stray newline; the response
    /// shape matches an empty body.
    #[tokio::test]
    async fn admin_release_whitespace_justification_returns_400() {
        let (router, mocks, _ctx) = release_harness();
        let artifact_id = seed_quarantined(&mocks);

        let body = r#"{"justification":"   \n\t  "}"#;
        let response = router
            .oneshot(release_post(
                artifact_id,
                body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// 513-byte justification → 400. One byte over the cap is
    /// rejected; the at-cap case is covered by the domain
    /// validation tests in `events/tests.rs`.
    #[tokio::test]
    async fn admin_release_oversize_justification_returns_400() {
        let (router, mocks, _ctx) = release_harness();
        let artifact_id = seed_quarantined(&mocks);

        let oversized = "x".repeat(513);
        let body = format!(r#"{{"justification":"{oversized}"}}"#);
        let response = router
            .oneshot(release_post(
                artifact_id,
                &body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Non-admin caller → 403. The AdminPrincipal extractor
    /// short-circuits before the handler body runs; the request
    /// body is never parsed.
    #[tokio::test]
    async fn admin_release_non_admin_returns_403() {
        let (router, mocks, _ctx) = release_harness();
        let artifact_id = seed_quarantined(&mocks);

        let body = r#"{"justification":"valid"}"#;
        let response = router
            .oneshot(release_post(
                artifact_id,
                body,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    // ----- GET /admin/quarantine/patch-candidates ------

    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    use hort_domain::ports::patch_candidate_repository::PatchCandidate;

    /// Build a router for the patch-candidate endpoint. Returns the
    /// router and the full mocks struct so tests can seed
    /// `mocks.patch_candidates` and assert recorded filters.
    fn patch_candidates_harness() -> (Router, crate::test_support::MockPorts) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new().nest("/admin", admin_routes()).with_state(ctx);
        (router, mocks)
    }

    /// Build `GET /admin/quarantine/patch-candidates[?<query>]` with an
    /// optional admin principal injected into request extensions.
    fn patch_candidates_get(query: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let path = if query.is_empty() {
            "/admin/quarantine/patch-candidates".to_string()
        } else {
            format!("/admin/quarantine/patch-candidates?{query}")
        };
        let mut req = Request::get(path).body(Body::empty()).unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// Construct a fully-populated [`PatchCandidate`] with the given
    /// repository scope. Mirrors the use-case-layer `sample_candidate`
    /// at `crates/hort-app/src/use_cases/patch_candidate_use_case.rs:147`
    /// — duplicated rather than re-exported so the handler tests stay
    /// independent of the use-case-private test fixture.
    fn sample_patch_candidate(repo_id: Uuid) -> PatchCandidate {
        PatchCandidate {
            quarantined_artifact_id: Uuid::new_v4(),
            quarantined_version: Some("4.17.21".into()),
            quarantined_status: QuarantineStatus::Quarantined,
            quarantined_until: Some(DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()),
            repository_id: repo_id,
            repository_key: "npm-main".into(),
            format: RepositoryFormat::Npm,
            package_name: "lodash".into(),
            vulnerable_artifact_id: Uuid::new_v4(),
            vulnerable_version: Some("4.17.20".into()),
            vulnerable_finding_count: 3,
            vulnerable_max_severity: Some(SeverityThreshold::High),
        }
    }

    /// Happy path: seed two candidates; admin GET returns 200 with the
    /// JSON envelope `{"candidates":[…,…]}` and field-by-field shape
    /// matching the seeded rows.
    #[tokio::test]
    async fn patch_candidates_happy_path_returns_200_with_seeded_rows() {
        let (router, mocks) = patch_candidates_harness();
        let repo_id = Uuid::new_v4();
        let c1 = sample_patch_candidate(repo_id);
        let c2 = sample_patch_candidate(repo_id);
        mocks.patch_candidates.seed(vec![c1.clone(), c2.clone()]);

        let response = router
            .oneshot(patch_candidates_get(
                "",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let arr = v["candidates"].as_array().expect("candidates array");
        assert_eq!(arr.len(), 2, "two seeded rows must surface");

        // First row — verify the full field set is projected and that
        // enum fields render via Display (lowercase strings).
        let r0 = &arr[0];
        assert_eq!(
            r0["quarantined_artifact_id"],
            c1.quarantined_artifact_id.to_string()
        );
        assert_eq!(r0["quarantined_version"], "4.17.21");
        assert_eq!(r0["quarantined_status"], "quarantined");
        assert_eq!(r0["repository_id"], repo_id.to_string());
        assert_eq!(r0["repository_key"], "npm-main");
        assert_eq!(r0["format"], "npm");
        assert_eq!(r0["package_name"], "lodash");
        assert_eq!(
            r0["vulnerable_artifact_id"],
            c1.vulnerable_artifact_id.to_string()
        );
        assert_eq!(r0["vulnerable_version"], "4.17.20");
        assert_eq!(r0["vulnerable_finding_count"], 3);
        assert_eq!(r0["vulnerable_max_severity"], "high");

        // Second row — pin distinct UUIDs (artifact ids are random per
        // `sample_patch_candidate`) so a regression that collapses
        // rows onto a single ID trips here.
        assert_eq!(
            arr[1]["quarantined_artifact_id"],
            c2.quarantined_artifact_id.to_string()
        );
        assert_ne!(
            arr[0]["quarantined_artifact_id"],
            arr[1]["quarantined_artifact_id"]
        );

        // Repo was reached exactly once with the default filter shape.
        let calls = mocks.patch_candidates.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].limit, 100, "default limit when ?limit absent");
        assert!(
            calls[0].repository_id.is_none(),
            "no ?repository = admin-wide scope"
        );
    }

    /// `?repository=<key>` resolves through
    /// `RepositoryRepository::find_by_key`, threads the resolved UUID
    /// into the filter, and surfaces the resolved key on the
    /// use-case-side metric label. Pins:
    /// (1) the wire form is `<key>`, NOT a UUID; (2) the lookup
    /// happens at the handler boundary, not in the use case;
    /// (3) the resolved key flows through `repository_key_for_metric`
    /// to the metric emission site.
    #[tokio::test]
    async fn patch_candidates_repository_key_resolves_to_uuid_and_threads_through_to_metric() {
        use hort_app::use_cases::test_support::sample_repository;
        let (router, mocks) = patch_candidates_harness();
        let scoped_repo = Uuid::new_v4();

        // Seed the repo so find_by_key resolves the operator-facing
        // key to its UUID.
        let mut row = sample_repository();
        row.id = scoped_repo;
        row.key = "npm-proxy".into();
        mocks.repositories.insert(row);

        mocks
            .patch_candidates
            .seed(vec![sample_patch_candidate(scoped_repo)]);

        let response = router
            .oneshot(patch_candidates_get(
                "repository=npm-proxy",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = mocks.patch_candidates.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].repository_id,
            Some(scoped_repo),
            "the handler must resolve the key to the seeded UUID before \
             dispatching to the use case",
        );
        assert_eq!(
            calls[0].repository_key_for_metric.as_deref(),
            Some("npm-proxy"),
            "the resolved key must be threaded onto the filter so the \
             use case emits it on the hort_patch_candidates_listed_total \
             repository label",
        );
    }

    /// `?repository=<unknown-key>` → 404 with a structured
    /// `{"error":"repository_not_found","key":"<value>"}` body.
    /// Pins the playbook UX: operators running `hort-cli admin
    /// quarantine list-patch-candidates --repo <typo>` get an
    /// actionable error, not the generic axum 400 the previous
    /// `Query<Uuid>` extractor produced.
    #[tokio::test]
    async fn patch_candidates_unknown_repository_key_returns_404_with_key_in_body() {
        let (router, mocks) = patch_candidates_harness();
        let response = router
            .oneshot(patch_candidates_get(
                "repository=no-such-repo",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "repository_not_found");
        assert_eq!(v["key"], "no-such-repo");

        assert!(
            mocks.patch_candidates.calls().is_empty(),
            "the patch-candidate repo must not be touched when the \
             repository-key lookup fails",
        );
    }

    /// `?limit=0` → 400 BAD REQUEST. A zero limit is a degenerate
    /// request — there is no meaningful "first zero rows" semantic
    /// — and rejecting it at the boundary keeps the use case from
    /// surfacing an empty `[]` that an operator misreads as "no
    /// candidates exist". The mock repo records no calls.
    #[tokio::test]
    async fn patch_candidates_limit_zero_returns_400_and_does_not_call_repo() {
        let (router, mocks) = patch_candidates_harness();
        let response = router
            .oneshot(patch_candidates_get(
                "limit=0",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.patch_candidates.calls().is_empty(),
            "limit=0 must fire the boundary gate, not be silently clamped"
        );
    }

    /// `?limit=500` (inclusive boundary) → 200 and the use case IS
    /// called with `filter.limit == 500`. Pins the `<=`-not-`<`
    /// contract end-to-end so a regression swapping `>` for `>=`
    /// trips here.
    #[tokio::test]
    async fn patch_candidates_limit_exact_max_returns_200_and_passes_500_through() {
        let (router, mocks) = patch_candidates_harness();
        let response = router
            .oneshot(patch_candidates_get(
                "limit=500",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = mocks.patch_candidates.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].limit, 500, "inclusive boundary must pass through");
    }

    /// `?limit=501` → 400 BAD REQUEST at the handler boundary. The
    /// use case is NEVER reached — the gate fires before any work is
    /// done. Mirrors the use-case-layer guard at the wire edge so a
    /// future caller bypassing this handler still hits the same wall.
    #[tokio::test]
    async fn patch_candidates_limit_over_max_returns_400_and_does_not_call_repo() {
        let (router, mocks) = patch_candidates_harness();
        let response = router
            .oneshot(patch_candidates_get(
                "limit=501",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.patch_candidates.calls().is_empty(),
            "boundary gate must fire before the use case is called"
        );
    }

    /// Non-admin principal → 403 FORBIDDEN. The `AdminPrincipal`
    /// extractor short-circuits before the handler body runs; the
    /// `PatchCandidateUseCase::list` is never reached and the mock
    /// repo records no calls.
    #[tokio::test]
    async fn patch_candidates_non_admin_returns_403_and_does_not_call_repo() {
        let (router, mocks) = patch_candidates_harness();
        // Seed a row so the assertion proves the body wasn't executed
        // (otherwise an empty result would be ambiguous between "use
        // case skipped" and "seed missing").
        mocks
            .patch_candidates
            .seed(vec![sample_patch_candidate(Uuid::new_v4())]);

        let response = router
            .oneshot(patch_candidates_get(
                "",
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            mocks.patch_candidates.calls().is_empty(),
            "AdminPrincipal short-circuit must not reach the use case"
        );
    }

    // ----- GET /admin/users/:user_id/effective-permissions ----

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{Permission, PermissionGrant};
    use hort_domain::entities::user::{AuthProvider, User};

    /// Reuse the patch-candidate harness shape: a fully-wired mock
    /// `AppContext` under `AuthContext::Enabled` so the
    /// `AdminPrincipal` extractor runs, plus the full `MockPorts` so the
    /// test seeds `mocks.users` and `mocks.permission_grants`.
    fn effective_permissions_harness() -> (Router, crate::test_support::MockPorts) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new().nest("/admin", admin_routes()).with_state(ctx);
        (router, mocks)
    }

    fn effective_permissions_get(
        user_id: Uuid,
        principal: Option<CallerPrincipal>,
    ) -> Request<Body> {
        let mut req = Request::get(format!("/admin/users/{user_id}/effective-permissions"))
            .body(Body::empty())
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn sample_user(id: Uuid, is_admin: bool) -> User {
        User {
            id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("oidc:alice".into()),
            display_name: Some("Alice".into()),
            is_active: true,
            is_admin,
            is_service_account: false,
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn claims_grant(required: &[&str], repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(required.iter().map(|s| (*s).to_string()).collect()),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
            created_at: Utc::now(),
        }
    }

    fn user_grant(uid: Uuid, repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
            created_at: Utc::now(),
        }
    }

    /// Acceptance — E2E happy path. A user with two matching
    /// direct-user grants + one non-matching (other-user) grant + one
    /// non-matching claims grant (the empty effective claim set can't
    /// satisfy it) → 200 enumerating exactly the two matching grants. The
    /// always-`[]` `claims`/`claims_source` fields are gone; the honest
    /// `claim_based_authority` marker + resolver pointer take their place.
    #[tokio::test]
    async fn effective_permissions_happy_path_returns_200_with_matching_grants() {
        let (router, mocks) = effective_permissions_harness();
        let uid = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        mocks.users.insert(sample_user(uid, false));
        mocks.permission_grants.seed(vec![
            user_grant(uid, Some(repo_a), Permission::Write),
            user_grant(uid, None, Permission::Read),
            user_grant(Uuid::new_v4(), None, Permission::Admin),
            claims_grant(&["developer", "team-alpha"], None, Permission::Write),
        ]);

        let response = router
            .oneshot(effective_permissions_get(
                uid,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["user_id"], uid.to_string());
        assert_eq!(v["is_admin"], false);
        // No `claims` / `claims_source` fields; the honest
        // marker stands in, with a pointer to the what-if resolver.
        assert!(
            v.get("claims").is_none(),
            "the always-[] claims field must not be present"
        );
        assert!(
            v.get("claims_source").is_none(),
            "the claims_source marker must not be present"
        );
        assert_eq!(
            v["claim_based_authority"], "not_resolvable_without_session",
            "honest marker — claim authority needs the user's session"
        );
        assert!(
            v["claim_based_authority_hint"]
                .as_str()
                .expect("hint string")
                .contains("/api/v1/admin/rbac/resolve"),
            "the marker carries a pointer to the what-if resolver"
        );
        let grants = v["grants"].as_array().expect("grants array");
        assert_eq!(grants.len(), 2, "only the two User({uid}) grants match");

        // Each matching row carries source.kind == "user" (no id —
        // §8.2 shape) and the permission Display string.
        let perms: std::collections::HashSet<&str> = grants
            .iter()
            .map(|g| {
                assert_eq!(g["source"]["kind"], "user");
                assert!(g["source"].get("required").is_none());
                g["permission"].as_str().unwrap()
            })
            .collect();
        assert!(perms.contains("write"));
        assert!(perms.contains("read"));
    }

    /// `is_admin` user → synthetic `admin` claim (ADR 0012);
    /// the `Claims(["admin"])` grant matches via the subset test and is
    /// projected with `source.kind == "claims"` + `required:["admin"]`.
    /// The `claim_based_authority` marker is constant.
    #[tokio::test]
    async fn effective_permissions_admin_user_projects_grant_source_shape() {
        let (router, mocks) = effective_permissions_harness();
        let uid = Uuid::new_v4();
        mocks.users.insert(sample_user(uid, true));
        mocks
            .permission_grants
            .seed(vec![claims_grant(&["admin"], None, Permission::Admin)]);

        let response = router
            .oneshot(effective_permissions_get(
                uid,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["is_admin"], true);
        assert_eq!(
            v["claim_based_authority"], "not_resolvable_without_session",
            "marker is constant even for an admin user"
        );
        // The synthetic `admin` claim still drives the grant match; the
        // matching grant is projected with source.kind == "claims".
        let g0 = &v["grants"][0];
        assert_eq!(g0["source"]["kind"], "claims");
        assert_eq!(g0["source"]["required"][0], "admin");
        assert_eq!(g0["permission"], "admin");
        assert!(g0["repository_id"].is_null(), "global grant ⇒ null repo");
    }

    /// Non-admin caller → 403 via the `AdminPrincipal` extractor.
    #[tokio::test]
    async fn effective_permissions_non_admin_returns_403() {
        let (router, mocks) = effective_permissions_harness();
        let uid = Uuid::new_v4();
        mocks.users.insert(sample_user(uid, false));

        let response = router
            .oneshot(effective_permissions_get(
                uid,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Admin caller, unknown inspected user → 404.
    #[tokio::test]
    async fn effective_permissions_unknown_user_returns_404() {
        let (router, _mocks) = effective_permissions_harness();

        let response = router
            .oneshot(effective_permissions_get(
                Uuid::new_v4(),
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ----- POST /admin/rbac/resolve --------------------

    /// Reuse the effective-permissions harness shape: a fully-wired mock
    /// `AppContext` under `AuthContext::Enabled` so the `AdminPrincipal`
    /// extractor runs, plus the full `MockPorts` so the test seeds
    /// `mocks.claim_mappings` (group→claim) and `mocks.permission_grants`
    /// (the grant set the resolved claims enumerate against).
    fn rbac_resolve_harness() -> (Router, crate::test_support::MockPorts) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new().nest("/admin", admin_routes()).with_state(ctx);
        (router, mocks)
    }

    /// Build `POST /admin/rbac/resolve` with the supplied JSON body and an
    /// optional admin principal injected into request extensions.
    fn rbac_resolve_post(body: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post("/admin/rbac/resolve")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn claim_mapping(idp_group: &str, claim: &str) -> hort_domain::entities::rbac::ClaimMapping {
        hort_domain::entities::rbac::ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: idp_group.into(),
            claim: claim.into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
        }
    }

    /// Acceptance — E2E happy path. Two mapped groups resolve
    /// to `["developer", "team-alpha"]`; the `developer` claim holds two
    /// cells (one global, one repo-scoped). A `ci-pusher` grant whose claim
    /// the resolved set does not hold is excluded; a `User`-subject grant is
    /// excluded (claims-only what-if, `user_id = None`).
    #[tokio::test]
    async fn rbac_resolve_happy_path_returns_200_with_claims_and_grants() {
        let (router, mocks) = rbac_resolve_harness();
        let repo_a = Uuid::new_v4();
        // The resolver maps `repository_id` → key, so seed the
        // repo (a per-repo cell whose id does not resolve to a live repo is
        // omitted as dangling — mirrors whoami's `render_cells`).
        {
            use hort_app::use_cases::test_support::sample_repository;
            let mut repo = sample_repository();
            repo.id = repo_a;
            repo.key = "repo-a".into();
            mocks.repositories.insert(repo);
        }
        mocks.claim_mappings.seed(vec![
            claim_mapping("test-developers", "developer"),
            claim_mapping("team-alpha-grp", "team-alpha"),
        ]);
        mocks.permission_grants.seed(vec![
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], Some(repo_a), Permission::Write),
            claims_grant(&["ci-pusher"], None, Permission::Delete),
            user_grant(Uuid::new_v4(), None, Permission::Admin),
        ]);

        let body = r#"{"groups":["test-developers","team-alpha-grp"]}"#;
        let response = router
            .oneshot(rbac_resolve_post(
                body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(v["global_admin"], false);
        let claims: Vec<&str> = v["resolved_claims"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(claims, vec!["developer", "team-alpha"]);

        let grants = v["effective_grants"].as_array().expect("grants array");
        assert_eq!(grants.len(), 2, "only the two developer cells hold");
        // Cells carry `repository` (UUID or null) + `permission` Display.
        let perms: std::collections::HashSet<&str> = grants
            .iter()
            .map(|g| g["permission"].as_str().unwrap())
            .collect();
        assert!(perms.contains("read"));
        assert!(perms.contains("write"));
        // The repo-scoped Write cell carries the repo KEY
        // (never the UUID); the global Read cell carries null.
        assert!(grants
            .iter()
            .any(|g| g["repository"] == "repo-a" && g["permission"] == "write"));
        assert!(grants
            .iter()
            .any(|g| g["repository"].is_null() && g["permission"] == "read"));
    }

    /// §5 edge case 1 — empty `groups` → 200 with empty resolution, NOT an
    /// error.
    #[tokio::test]
    async fn rbac_resolve_empty_groups_returns_200_empty() {
        let (router, mocks) = rbac_resolve_harness();
        mocks
            .claim_mappings
            .seed(vec![claim_mapping("devs", "developer")]);
        mocks
            .permission_grants
            .seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let response = router
            .oneshot(rbac_resolve_post(
                r#"{"groups":[]}"#,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["global_admin"], false);
        assert!(v["resolved_claims"].as_array().unwrap().is_empty());
        assert!(v["effective_grants"].as_array().unwrap().is_empty());
    }

    /// §5 edge case 2 — groups that map to no claim → 200 empty.
    #[tokio::test]
    async fn rbac_resolve_unmapped_groups_returns_200_empty() {
        let (router, mocks) = rbac_resolve_harness();
        mocks
            .claim_mappings
            .seed(vec![claim_mapping("devs", "developer")]);
        mocks
            .permission_grants
            .seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let response = router
            .oneshot(rbac_resolve_post(
                r#"{"groups":["not-mapped"]}"#,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["resolved_claims"].as_array().unwrap().is_empty());
        assert!(v["effective_grants"].as_array().unwrap().is_empty());
    }

    /// §5 edge case 3 — a group mapped to the `admin` claim → 200 with
    /// `global_admin: true` and the marker (empty `effective_grants`).
    #[tokio::test]
    async fn rbac_resolve_admin_claim_group_returns_global_admin() {
        let (router, mocks) = rbac_resolve_harness();
        mocks
            .claim_mappings
            .seed(vec![claim_mapping("platform-admins", "admin")]);
        // A concrete grant exists, but the admin marker short-circuits the
        // enumeration: the cell list stays empty.
        mocks
            .permission_grants
            .seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let response = router
            .oneshot(rbac_resolve_post(
                r#"{"groups":["platform-admins"]}"#,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["global_admin"], true);
        assert_eq!(v["resolved_claims"][0], "admin");
        assert!(
            v["effective_grants"].as_array().unwrap().is_empty(),
            "the admin marker stands in for the full authority — never an enumeration"
        );
    }

    /// Non-admin caller → 403 via the `AdminPrincipal` extractor; the
    /// request body is never parsed.
    #[tokio::test]
    async fn rbac_resolve_non_admin_returns_403() {
        let (router, _mocks) = rbac_resolve_harness();

        let response = router
            .oneshot(rbac_resolve_post(
                r#"{"groups":["devs"]}"#,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ----- GET /admin/workers ------

    use hort_domain::ports::scanner_registry_repository::ScannerRegistryEntry;

    /// Build `GET /admin/workers` with an optional admin principal.
    fn workers_get(principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::get("/admin/workers").body(Body::empty()).unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn worker_entry(id: &str, last_heartbeat: DateTime<Utc>) -> ScannerRegistryEntry {
        ScannerRegistryEntry {
            worker_id: id.into(),
            backends: vec!["trivy".into(), "osv".into()],
            registered_at: last_heartbeat,
            last_heartbeat,
        }
    }

    /// Happy path: seed a fresh worker and a stale (backdated) one; admin
    /// GET returns 200 with `{"workers":[…]}`, each row carrying the
    /// derived `live` + `last_seen_secs_ago`. The stale worker stays in
    /// the listing (`live=false`) rather than being filtered out.
    #[tokio::test]
    async fn workers_happy_path_returns_200_with_liveness() {
        // `patch_candidates_harness` builds the full `/admin` router (all
        // of `admin_routes()`), so it serves `/admin/workers` too.
        let (router, mocks) = patch_candidates_harness();
        let now = Utc::now();
        mocks.scanner_workers.seed(vec![
            worker_entry("w-fresh", now),
            worker_entry("w-stale", now - chrono::Duration::seconds(3600)),
        ]);

        let response = router
            .oneshot(workers_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let arr = v["workers"].as_array().expect("workers array");
        assert_eq!(arr.len(), 2);

        let fresh = arr.iter().find(|w| w["worker_id"] == "w-fresh").unwrap();
        assert_eq!(fresh["live"], true, "fresh heartbeat → live");
        assert_eq!(fresh["backends"], serde_json::json!(["trivy", "osv"]));

        let stale = arr.iter().find(|w| w["worker_id"] == "w-stale").unwrap();
        assert_eq!(
            stale["live"], false,
            "1h-old heartbeat → stale, still listed"
        );
        assert!(
            stale["last_seen_secs_ago"].as_i64().unwrap() >= 3500,
            "stale age ~3600s, got {}",
            stale["last_seen_secs_ago"]
        );
    }

    /// Non-admin caller → 403; the AdminPrincipal extractor short-circuits
    /// before the handler body runs (no registry read).
    #[tokio::test]
    async fn workers_non_admin_returns_403() {
        let (router, _mocks) = patch_candidates_harness();
        let response = router
            .oneshot(workers_get(Some(principal_with_claims(&["reader"]))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
