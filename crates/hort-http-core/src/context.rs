use std::sync::Arc;

use arc_swap::ArcSwap;
use metrics_exporter_prometheus::PrometheusHandle;

use hort_config::ExtraTrustAnchors;

use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::oci_token_signing::OciTokenSigningKey;
use hort_app::pull_dedup::PullDedup;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::api_token_use_case::ApiTokenUseCase;
use hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
use hort_app::use_cases::artifact_use_case::ArtifactUseCase;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::content_reference::ContentReferenceUseCase;
// `CurationUseCase` (`waive` / `block` / `list_*`) backs the three HTTP
// decision endpoints under `/api/v1/admin/curation/...`.
use hort_app::use_cases::curation_use_case::CurationUseCase;
// Repo-keyed discovery endpoint use case
// (`GET /api/v1/repositories/{repo_key}/discovery/versions/{package}`).
// Consumed by the `hort-http-discovery` inbound adapter.
use hort_app::use_cases::discovery_use_case::DiscoveryUseCase;
use hort_app::use_cases::effective_permissions_use_case::EffectivePermissionsUseCase;
use hort_app::use_cases::ingest_use_case::IngestUseCase;
use hort_app::use_cases::manual_rescan_use_case::ManualRescanUseCase;
use hort_app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase;
use hort_app::use_cases::pat_cache::PatCache;
use hort_app::use_cases::patch_candidate_use_case::PatchCandidateUseCase;
use hort_app::use_cases::scanner_worker_query_use_case::ScannerWorkerQueryUseCase;
// The finding-exclusion HTTP write surface
// (`POST/DELETE /api/v1/admin/policies/:policy_id/exclusions[/:cve_id]`)
// calls `PolicyUseCase::{add_exclusion, remove_exclusion}`. The use
// case keeps its broad `Actor` parameter so the gitops apply pipeline
// continues to call it with `Actor::Gitops`; the HTTP layer is the
// single permission gate for the user-driven surface (gate at HTTP,
// not in the use case).
use hort_app::use_cases::policy_use_case::PolicyUseCase;
// Prefetch planner consumed by the per-format
// index/metadata serve sites (`hort-http-npm` / `hort-http-cargo` /
// `hort-http-pypi`). Stateless unit struct; held as
// `Arc<PrefetchUseCase>` for shape consistency with the rest of the
// use-case surface, NOT because it has constructor dependencies.
use hort_app::use_cases::prefetch_use_case::PrefetchUseCase;
use hort_app::use_cases::promotion_use_case::PromotionUseCase;
// Repo-keyed self-service prefetch endpoint use
// case (`POST /api/v1/repositories/{repo_key}/prefetch`). Consumed by
// the `hort-http-discovery` inbound adapter.
use hort_app::use_cases::quarantine_use_case::QuarantineUseCase;
use hort_app::use_cases::rbac_resolve_use_case::RbacResolveUseCase;
use hort_app::use_cases::ref_use_case::RefUseCase;
use hort_app::use_cases::repository_access::RepositoryAccessUseCase;
use hort_app::use_cases::repository_use_case::RepositoryUseCase;
use hort_app::use_cases::security_score_use_case::SecurityScoreUseCase;
use hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase;
use hort_app::use_cases::subscription_use_case::SubscriptionUseCase;
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_app::use_cases::user_use_case::UserUseCase;
// PEP 658 `.metadata` read-path use case
// consumed by the per-format serve site in `hort-http-pypi`.
use hort_app::use_cases::wheel_metadata_use_case::WheelMetadataUseCase;
use hort_domain::ports::artifact_group_lifecycle::ArtifactGroupLifecyclePort;
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::federated_jwt_validator::FederatedJwtValidator;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::kubernetes_secret_writer::KubernetesSecretWriter;
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::ref_lifecycle::RefLifecyclePort;
use hort_domain::ports::ref_registry::RefRegistryPort;
use hort_domain::ports::repo_security_score_repository::RepoSecurityScoreRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::service_account_repository::ServiceAccountRepository;
use hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;

/// Authentication context for the router.
///
/// Known carry-forward: the `Uuid::nil()` placeholder-actor cluster
/// below awaits the subscription composition wiring + auth boundary
/// cleanup.
///
/// `Disabled` preserves the anonymous pass-through: the
/// `require_principal` / `extract_optional_principal` middleware layers are
/// NOT attached by [`crate::router::wrap_with_middleware`]; handlers skip
/// `authorize()` entirely; the existing `ApiActor { user_id: Uuid::nil() }`
/// placeholder continues to flow through. This preserves current behaviour
/// bit-for-bit when `HORT_AUTH_PROVIDER=disabled`.
///
/// `Enabled` carries the fully-wired [`AuthenticateUseCase`] +
/// [`RbacEvaluator`] pair. The middleware attaches to write-path routes;
/// handlers call [`RbacEvaluator::authorize`] with the extracted
/// [`hort_domain::entities::caller::CallerPrincipal`].
///
/// Clients obtain Bearer tokens from the IdP directly (Keycloak) —
/// hort-server never sees user passwords. The middleware validates those
/// IdP-issued JWTs via [`AuthenticateUseCase::authenticate_bearer`]; no
/// registry-minted JWT layer exists in the v2 design.
///
/// **RBAC live-refresh.** The evaluator is held
/// in an [`ArcSwap`] so a background task in `hort-server` can replace
/// the snapshot atomically every `HORT_RBAC_REFRESH_SECS` without
/// restarting the process. Read sites call [`ArcSwap::load`] to get a
/// cheap `Guard<Arc<RbacEvaluator>>`; the swap is lock-free and the
/// hot-read path carries no lock contention.
///
/// The auth-mechanism inventory is `docs/auth-catalog.md`; the RBAC
/// model is ADR 0012.
#[derive(Clone)]
pub enum AuthContext {
    /// Auth completely disabled — no OIDC, no native tokens.
    /// Middleware is not attached. Reachable only in test fixtures
    /// or when `HORT_AUTH_PROVIDER=disabled` AND
    /// `HORT_NATIVE_TOKENS_ENABLED=false`. The runtime boot gate
    /// (`hort_server::cli::serve::ensure_auth_enabled`) rejects this
    /// combination in production.
    Disabled,
    /// Auth enabled (OIDC). Middleware attaches on write paths.
    Enabled {
        authenticate: Arc<AuthenticateUseCase>,
        /// `Arc<ArcSwap<_>>` (lock-free atomic pointer swap) so the
        /// refresh task in `hort-server` can replace the snapshot
        /// without blocking any request. `Clone` is cheap; every
        /// `.load()` returns a `Guard` that derefs to the current
        /// `Arc<RbacEvaluator>`.
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        /// OIDC issuer URL used as the
        /// `realm=` value in the `WWW-Authenticate: Bearer` challenge
        /// emitted on 401s. RFC 6750 §3 ("a label or, optionally, a
        /// URL, identifying the protected resource") + modern
        /// Bearer-aware-client convention: putting the issuer URL here
        /// lets clients do OIDC discovery without registry-side
        /// wire-up.
        ///
        /// `Some(_)` in production (`composition.rs` populates from
        /// `OidcConfig.issuer_url`); `None` is tolerated for tests
        /// that don't exercise the challenge text and falls back to
        /// `realm="hort"` per
        /// `crate::middleware::auth::www_authenticate_for`.
        issuer_url: Option<String>,
    },
    /// `HORT_AUTH_PROVIDER=disabled` with `HORT_NATIVE_TOKENS_ENABLED=true`
    /// — no OIDC IdP, the native-token validator
    /// (`Bearer hort_<kind>_*`) is the inbound identity surface. The
    /// [`AuthenticateUseCase`] carries `idp = None`; OIDC-shaped
    /// bearers fail cleanly.
    ///
    /// There is deliberately NO local-password identity path here:
    /// HTTP Basic is a token *carrier* only, never an identity source
    /// (see `docs/auth-catalog.md`). What remains is the
    /// native-token-only bearer path, hence the name. The matching
    /// boot-gate signal is
    /// `HORT_AUTH_PROVIDER=disabled` + `HORT_NATIVE_TOKENS_ENABLED=true`
    /// (`hort_server::cli::serve::ensure_auth_enabled`).
    BearerOnly {
        authenticate: Arc<AuthenticateUseCase>,
        /// Same shape as [`Self::Enabled::rbac`]. Loaded from DB so
        /// service-account roles (declared via gitops apply) are
        /// honoured.
        rbac: Arc<ArcSwap<RbacEvaluator>>,
    },
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("Disabled"),
            Self::Enabled { .. } => f
                .debug_struct("Enabled")
                .field("authenticate", &"<arc>")
                .field("rbac", &"<arc>")
                .finish(),
            Self::BearerOnly { .. } => f
                .debug_struct("BearerOnly")
                .field("authenticate", &"<arc>")
                .field("rbac", &"<arc>")
                .finish(),
        }
    }
}

impl AuthContext {
    /// Returns the configured [`AuthenticateUseCase`] for both
    /// [`Self::Enabled`] and [`Self::BearerOnly`] contexts. `None`
    /// only under [`Self::Disabled`] — middleware that needs auth
    /// must treat that as "no auth wired".
    pub fn authenticate(&self) -> Option<&Arc<AuthenticateUseCase>> {
        match self {
            Self::Enabled { authenticate, .. } | Self::BearerOnly { authenticate, .. } => {
                Some(authenticate)
            }
            Self::Disabled => None,
        }
    }

    /// Returns the configured RBAC evaluator. `None` under
    /// [`Self::Disabled`]; both [`Self::Enabled`] and
    /// [`Self::BearerOnly`] carry a live, refreshable evaluator.
    pub fn rbac(&self) -> Option<&Arc<ArcSwap<RbacEvaluator>>> {
        match self {
            Self::Enabled { rbac, .. } | Self::BearerOnly { rbac, .. } => Some(rbac),
            Self::Disabled => None,
        }
    }

    /// True when any HTTP auth middleware should run (i.e. anything
    /// other than [`Self::Disabled`]). The router builder
    /// (`wrap_with_middleware`) uses this to decide whether to attach
    /// the principal-extracting layer.
    pub fn has_auth(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Application context — the composition root.
///
/// Holds all use cases and outbound port handles. Handlers receive an
/// `axum::extract::State<Arc<AppContext>>` and call into the use cases
/// for business operations.
///
/// Constructed once at startup via
/// `hort_server::composition::build_app_context`.
///
/// The ephemeral ports carry short-lived TTL-bounded key/value state
/// (stateful uploads, idempotency tokens, rate-limit counters);
/// [`Self::stateful_upload_staging`] and [`Self::content_references`]
/// are format-agnostic generalisations consumed across the format
/// crates.
pub struct AppContext {
    pub repository_use_case: Arc<RepositoryUseCase>,
    pub artifact_use_case: Arc<ArtifactUseCase>,
    /// Single source of truth for repo-key
    /// resolution + Read/Write authz + visibility filtering. Composed
    /// from the existing `repositories` port + `auth` field. Inbound
    /// HTTP handlers (every `hort-http-<format>` crate) call this rather
    /// than reaching for `ctx.repositories.find_by_key` directly — the
    /// underlying data ports are `pub(crate)` (ADR 0008).
    pub repository_access_use_case: Arc<RepositoryAccessUseCase>,
    /// Composition over the
    /// `ContentReferenceIndex` port and the `RepositoryAccessUseCase`.
    /// Replaces direct `ctx.content_references.*` access in
    /// `hort-http-oci` so visibility is enforced uniformly on the read
    /// path and the no-authz write methods carry an explicit trust
    /// contract (ADR 0008).
    pub content_reference_use_case: Arc<ContentReferenceUseCase>,
    pub ingest_use_case: Arc<IngestUseCase>,
    pub user_use_case: Arc<UserUseCase>,
    /// Native API token issuance / revocation
    /// / listing. The token-validation hot path lives elsewhere
    /// (`AuthContext::Enabled.authenticate.with_pat_validation`); this
    /// use case is the slow CRUD-style surface for the
    /// `POST /users/me/tokens`, `DELETE /users/me/tokens/:id`,
    /// `GET /users/me/tokens`, `POST /admin/users/:user_id/tokens`,
    /// and `DELETE /admin/tokens/:id` handlers.
    pub api_token_use_case: Arc<ApiTokenUseCase>,
    pub quarantine_use_case: Arc<QuarantineUseCase>,
    pub promotion_use_case: Arc<PromotionUseCase>,
    /// Write path for mutable refs. Delegates to
    /// [`RefLifecyclePort`] for transactional projection-write + event
    /// append, with adapter-authoritative idempotence on re-point.
    pub ref_use_case: Arc<RefUseCase>,
    /// Read-side surface for the per-repository
    /// `repo_security_scores` projection. The HTTP adapter
    /// (`hort-http-admin-security`) calls this rather than reaching for
    /// the `pub(crate) security_scores` data port directly (ADR 0008
    /// anti-pattern; format crates compile-error on direct port
    /// access). Composed with the `RepositoryAccessUseCase` so name
    /// resolution + visibility + Read enforcement is uniform with the
    /// rest of the inbound surface.
    pub security_score_use_case: Arc<SecurityScoreUseCase>,
    /// Admin-task enqueue use case.
    /// The inbound HTTP adapter (`hort-http-admin-tasks`) calls this to
    /// enqueue admin tasks. RBAC gating (`Permission::AdminTaskInvoke`)
    /// and the event-store `TaskInvoked` audit append both live inside
    /// the use case, keeping handler logic thin.
    pub task_use_case: Arc<TaskUseCase>,
    /// `POST /api/v1/artifacts/:id/rescan`
    /// use case. The inbound HTTP adapter (`hort-http-admin-security`)
    /// calls this to insert a `kind='scan'` row with
    /// `trigger_source='manual'`, `priority=20`. RBAC
    /// (`Permission::Write` on the artifact's parent repo), 404-vs-403
    /// collapse, and conflict detection (`status IN
    /// ('pending','running')`) all live inside the use case.
    pub manual_rescan_use_case: Arc<ManualRescanUseCase>,
    /// Admin-only read of the patch-candidate
    /// quarantine surface (`GET /admin/quarantine/patch-candidates`).
    /// The use case enforces `Permission::Admin` (defence in depth —
    /// the `AdminPrincipal` extractor enforces the same gate at the
    /// request edge) and clamps `filter.limit` at 500 before reaching
    /// the adapter.
    pub patch_candidate_use_case: Arc<PatchCandidateUseCase>,
    /// Admin-only read of the `scanner_registry` worker table
    /// (`GET /api/v1/admin/workers`). The use case enforces
    /// `Permission::Admin` (defence in depth — the `AdminPrincipal`
    /// extractor enforces the same gate at the request edge) and stamps
    /// each row with derived liveness.
    pub scanner_worker_query_use_case: Arc<ScannerWorkerQueryUseCase>,
    /// Prefetch trigger planner. Format crates
    /// (`hort-http-npm`, `hort-http-cargo`, `hort-http-pypi`) call
    /// [`PrefetchUseCase::plan`] from their index/metadata serve site
    /// when `repo.prefetch_policy.triggers` contains `OnIndexFetch`
    /// or `OnDistTagMove`. The use case is stateless (a unit struct
    /// with no constructor dependencies); the `Arc` wrapper preserves
    /// shape consistency with the rest of the `AppContext` use-case
    /// surface and lets future expansion add fields without a
    /// breaking signature change. See
    /// `docs/architecture/explanation/prefetch-pipeline.md` and
    /// `crates/hort-app/src/use_cases/prefetch_use_case.rs`.
    pub prefetch_use_case: Arc<PrefetchUseCase>,
    /// Admin-only effective-permissions
    /// inspection surface
    /// (`GET /api/v1/admin/users/:user_id/effective-permissions`). The
    /// use case enforces `Permission::Admin` (defence in depth — the
    /// `AdminPrincipal` extractor enforces the same gate at the request
    /// edge) and is the audit-time mitigation for the operator-discipline
    /// cost of the additive-claims model (ADR 0012;
    /// `docs/architecture/how-to/operate/claim-based-rbac.md`).
    pub effective_permissions_use_case: Arc<EffectivePermissionsUseCase>,
    /// Admin-only what-if RBAC resolver backing
    /// `POST /api/v1/admin/rbac/resolve`. Takes an IdP-group set as input
    /// and resolves the `groups → claims → effective (repo, permission)
    /// grants` half hort owns (no IdP query, no cache). The use case enforces
    /// `Permission::Admin` (defence in depth — the `AdminPrincipal`
    /// extractor enforces the same gate at the request edge) and is the
    /// claim-based-authority companion to
    /// [`Self::effective_permissions_use_case`] (which cannot resolve a
    /// user's claims without that user's session). See
    /// `docs/architecture/how-to/operate/claim-based-rbac.md`.
    pub rbac_resolve_use_case: Arc<RbacResolveUseCase>,
    /// Subscription CRUD use case driving the
    /// `/api/v1/subscriptions` + `/api/v1/admin/subscriptions` surfaces.
    /// Owner-or-admin authz lives inside the use case; the inbound HTTP
    /// adapter (`hort-http-subscriptions`) calls this rather than
    /// reaching for the underlying `SubscriptionRepository` directly
    /// (ADR 0008 anti-pattern: format crates never touch raw
    /// data ports).
    ///
    /// Known carry-forward (`Uuid::nil()` actor cluster): the production
    /// composition wiring has not landed — the field is unwired in
    /// production and only the mock test harness populates it.
    pub subscription_use_case: Arc<SubscriptionUseCase>,
    /// Curator decision authority over quarantined
    /// / non-terminal artifacts. The inbound HTTP adapter
    /// (`handlers/admin/curation/`) calls
    /// `CurationUseCase::{waive, block}` from the three decision
    /// endpoints mounted under `/api/v1/admin/curation/...`. Authority
    /// gating (`Permission::Curate` OR `Permission::Admin`) lives inside
    /// the use case (defence-in-depth — the HTTP edge runs
    /// `CurateOrAdminPrincipal` first); the use case is also the single
    /// audit-log + `hort_curation_decisions_total` emission point. The
    /// `list_*` methods on the same use case back the
    /// queue / decisions / exclusions read surfaces.
    pub curation_use_case: Arc<CurationUseCase>,
    /// Finding-exclusion HTTP write surface.
    /// The inbound adapter (`handlers/admin/policies/exclusions.rs`)
    /// calls `PolicyUseCase::{add_exclusion, remove_exclusion}` from
    /// `POST /api/v1/admin/policies/:policy_id/exclusions` and
    /// `DELETE …/exclusions/:cve_id`. Both endpoints are gated by
    /// [`crate::authz::CurateOrAdminPrincipal`] — the HTTP layer is the
    /// single permission source of truth for the user-driven surface.
    /// The use-case methods retain their broad `Actor` parameter so the
    /// gitops apply pipeline (`apply_config_use_case.rs`) continues to
    /// call them with `Actor::Gitops`; the use case is permission-
    /// neutral, the HTTP edge enforces curate-or-admin.
    pub policy_use_case: Arc<PolicyUseCase>,
    /// PEP 658 `.metadata` read-path use case
    /// consumed by `hort-http-pypi::metadata_endpoint::serve_pep658_metadata`.
    /// Composes the visibility-gated
    /// `ArtifactUseCase::find_visible_by_path` hop, the per-artifact
    /// status filter (Quarantined → 503, Rejected / ScanIndeterminate
    /// → 404), the `wheel_metadata` ContentReference PK lookup, and
    /// the CAS fetch. See PEP 658 and
    /// `docs/architecture/how-to/pypi-pull-through.md`.
    pub wheel_metadata_use_case: Arc<WheelMetadataUseCase>,
    /// Repo-keyed discovery endpoint use case
    /// (`GET /api/v1/repositories/{repo_key}/discovery/versions/{package}`).
    /// The inbound HTTP adapter (`hort-http-discovery`)
    /// calls this; the token-kind gate, RBAC gate, OCI rejection, and
    /// the status-overlay assembly all live inside the use case
    /// (per the architect-doc "Emission by layer" rule — the inbound
    /// handler emits no business metric). See
    /// `docs/architecture/explanation/prefetch-pipeline.md`.
    ///
    /// `Option<_>` because the use case is wired after `AppContext::new`
    /// via [`Self::with_discovery_use_cases`]. The production composition
    /// root populates it at startup before mounting the router; the test
    /// harness (`build_mock_ctx`) wires it unconditionally. Handler call
    /// sites `.expect()` it — when the router is mounted, the slot is
    /// guaranteed populated by the composition discipline.
    pub discovery_use_case: Option<Arc<DiscoveryUseCase>>,
    /// Repo-keyed self-service prefetch endpoint
    /// use case (`POST /api/v1/repositories/{repo_key}/prefetch`). The
    /// inbound HTTP adapter (`hort-http-discovery`) calls
    /// this; gate order (token-kind → RBAC Read ∧ Prefetch → OCI
    /// rejection) and continue-on-error envelope partitioning live
    /// inside the use case. See
    /// `docs/architecture/explanation/prefetch-pipeline.md`.
    ///
    /// `Option<_>` for the same post-`new` wiring split as
    /// [`Self::discovery_use_case`]; see that field's doc.
    pub self_service_prefetch_use_case: Option<Arc<SelfServicePrefetchUseCase>>,
    // ADR 0008 — the seven data ports below are `pub(crate)` so
    // format crates compile-error on direct access. They are still
    // composed into the struct (held alive by the use cases that own
    // them via separate `Arc` clones) and accessed by the
    // `test_support` module behind the `test-support` feature; without
    // that feature they're unread within `hort-http-core`, hence the
    // `#[allow(dead_code)]`.
    #[allow(dead_code)]
    pub(crate) storage: Arc<dyn StoragePort>,
    /// Raw port access for handlers that need queries not exposed via use cases.
    #[allow(dead_code)]
    pub(crate) artifacts: Arc<dyn ArtifactRepository>,
    #[allow(dead_code)]
    pub(crate) repositories: Arc<dyn RepositoryRepository>,
    /// Read port for mutable refs. Kept alongside
    /// [`Self::ref_use_case`] for handlers / projections that only need
    /// lookups and should not pay the write-path indirection.
    #[allow(dead_code)]
    pub(crate) refs: Arc<dyn RefRegistryPort>,
    /// Write port for mutable refs. Exposed at
    /// the `AppContext` level (in addition to `ref_use_case`) for
    /// adapters / projections that need the atomic write path without
    /// going through the use case.
    pub ref_lifecycle: Arc<dyn RefLifecyclePort>,
    /// Artifact-group write path. Orchestrates
    /// the concurrent-create retry loop + primary-role-assign
    /// conflict surface. Handlers and future projections go through
    /// this rather than the raw ports.
    pub artifact_group_use_case: Arc<ArtifactGroupUseCase>,
    /// Read port for artifact groups. Kept at
    /// the `AppContext` level for handlers that only need lookup (OCI
    /// `_catalog`, Maven GAV root enumeration) without paying the
    /// write-path indirection. Same read/write split as `refs` /
    /// `ref_lifecycle`.
    #[allow(dead_code)]
    pub(crate) artifact_groups: Arc<dyn ArtifactGroupRepository>,
    /// Write port for artifact groups. Exposed
    /// at the `AppContext` level for adapters / projections that need
    /// the atomic write path without going through the use case.
    pub artifact_group_lifecycle: Arc<dyn ArtifactGroupLifecyclePort>,
    /// Read-only projection of `ArtifactMetadata`. Format handlers consume
    /// this at index-render time (e.g. PyPI `data-requires-python` from
    /// `pkg_info.requires_python`). The write path flows through
    /// `ArtifactLifecyclePort::commit_transition`.
    #[allow(dead_code)]
    pub(crate) artifact_metadata: Arc<dyn ArtifactMetadataRepository>,
    /// `repo_security_scores` projection port.
    /// Read-only surface used by [`Self::security_score_use_case`].
    /// Held as `pub(crate)` per the ADR 0008 anti-pattern: format
    /// crates that need scores call the use case, not the raw port.
    /// The use case keeps a separate `Arc` clone alive on its own
    /// field; this slot exists so composition can hand the same
    /// adapter handle to both the use case and any future direct
    /// caller (e.g. a reconciliation task).
    #[allow(dead_code)]
    pub(crate) security_scores: Arc<dyn RepoSecurityScoreRepository>,
    /// `jobs` table port.
    /// Held as `pub(crate)` (ADR 0008 anti-pattern): format crates do
    /// NOT touch the queue directly — they call the relevant use case
    /// (`TaskUseCase`, `ManualRescanUseCase`). The slot exists so the
    /// composition root can hand the same adapter handle to every use
    /// case that needs the jobs surface, and so the test-support harness
    /// can rebuild use cases when the access policy changes without
    /// re-wiring every port.
    #[allow(dead_code)]
    pub(crate) jobs: Arc<dyn JobsRepository>,
    /// **Evictable** `EphemeralStore` slot. Wired
    /// to the cache consumers (Cargo / PyPI / npm sparse-index +
    /// packument caches, pull-through dedup keys). Loss is recoverable
    /// by re-fetching from upstream.
    ///
    /// Short-lived TTL-bounded KV port. Wired
    /// to the in-memory adapter in dev / test and the Redis adapter
    /// in production. Keyspace classes are registered in
    /// `hort_app::ephemeral_keyspace` (guarded by the
    /// `ephemeral_keyspace_exhaustive` test); format-crate cache
    /// consumers read from this slot.
    pub ephemeral_evictable: Arc<dyn EphemeralStore>,
    /// Raw upstream-metadata mirror (ADR 0026; logical-keyed,
    /// streaming, overwrite). NOT the CAS `storage` port — metadata is mutable.
    /// `pub` (not `pub(crate)`): consumed directly by the format crates on the
    /// fetch path, like `ephemeral_evictable`/`upstream_proxy`.
    pub metadata_mirror: Arc<dyn MetadataMirrorStore>,
    /// Pull-through deduplication service. Sits
    /// between every format crate's upstream-proxy fetch and the actual
    /// `UpstreamProxy::*` call, coalescing N parallel cache-miss requests
    /// for the same artifact into ≤ 1 upstream HTTP request (Layer A:
    /// per-replica `DashMap`; Layer B: cluster-wide `EphemeralStore`
    /// keyed lock). Construction consumes [`Self::ephemeral_evictable`]
    /// — the `pulldedup:` keyspace is registered as
    /// [`EphemeralKeyspaceClass::Evictable`](hort_app::ephemeral_keyspace::EphemeralKeyspaceClass::Evictable).
    /// Held as `Arc<PullDedup>` (an application-layer service,
    /// not a concrete adapter) so format crates compose around it
    /// uniformly via `ctx.pull_dedup.coalesce_metadata(...)` /
    /// `ctx.pull_dedup.coalesce_blob(...)`.
    pub pull_dedup: Arc<PullDedup>,
    /// **Durable** `EphemeralStore` slot. Wired
    /// to stateful and security-critical consumers (auth lockout, PAT
    /// brute-force lockout, OCI three-phase upload session records,
    /// OCI per-(repo, principal) session-count cap, auth-event
    /// throttle). Loss is tolerated only as defense-in-depth lower-tier
    /// degradation.
    ///
    /// The OCI three-phase upload session bookkeeping lives on this
    /// slot, not the Postgres port. See
    /// `hort_domain::ports::ephemeral_store::EphemeralStore`.
    pub ephemeral_durable: Arc<dyn EphemeralStore>,
    /// Event-store handle exposed for the
    /// `/readyz` HTTP probe. The handler calls
    /// [`EventStore::health_check`] which the Postgres adapter
    /// implements as a `SELECT 1` round-trip on the same `PgPool` that
    /// backs every other event-store operation; a successful ping
    /// confirms both DB-pool acquisition and DB responsiveness in one
    /// call.
    pub event_store: Arc<EventStorePublisher>,
    /// Multi-issuer JWT validator port consumed by
    /// the federation branch of `/auth/token-exchange` (ADR 0018).
    /// `Some(_)` whenever `auth_enabled = true` and at least one
    /// `OidcIssuer` row is reachable (composition constructs the adapter
    /// against the Postgres `OidcIssuerRepository` unconditionally; the
    /// `Option` wrapper lets the auth-disabled path keep a slot-shaped
    /// signature without forcing a no-op stub).
    ///
    /// `pub(crate)` per ADR 0008 + the anti-pattern checklist:
    /// federation HTTP handlers call the
    /// `FederatedTokenExchangeUseCase`; they do NOT touch
    /// this slot directly.
    #[allow(dead_code)]
    pub(crate) federated_jwt_validator: Option<Arc<dyn FederatedJwtValidator>>,
    /// `ServiceAccountRepository` consumed by the
    /// federation branch of `/auth/token-exchange`. The handler in this
    /// crate walks every SA's `federated_identities[].claims` against the
    /// validated JWT claims to resolve the target SA. `Some(_)` when
    /// `auth_enabled = true` (composition wires it against the same
    /// Postgres pool the apply pipeline uses; reads are bounded by the
    /// operator's CRD count, typically <100).
    ///
    /// `pub(crate)` per ADR 0008: only the federation handler in this
    /// crate consumes this slot. Per-format crates (npm, PyPI, …) MUST
    /// NOT reach for SA-shaped identity surfaces — that decision lives in
    /// the auth / token-exchange handler only.
    #[allow(dead_code)]
    pub(crate) service_accounts: Option<Arc<dyn ServiceAccountRepository>>,
    /// `OidcIssuerRepository` so
    /// the federation handler can resolve the matched issuer's
    /// `require_jti` flag and thread it into `FederationSource`.
    /// This is a **domain port** (`hort-domain`), not an adapter
    /// — identical wiring shape to `federated_jwt_validator` /
    /// `service_accounts` above; the dep-graph "no adapter import in
    /// `hort-http-core`" rule is preserved (the guard port itself is
    /// invoked inside `hort-app`, not here). `Some(_)` when
    /// `auth_enabled = true` (same condition as the validator slot).
    ///
    /// `pub(crate)` per ADR 0008: only the federation handler in this
    /// crate consumes this slot.
    #[allow(dead_code)]
    pub(crate) oidc_issuers: Option<Arc<dyn OidcIssuerRepository>>,
    /// The fallback-PAT-rotation reconciler's
    /// outbound k8s Secret writer. `Some(_)` when the operator opts in
    /// via `HORT_K8S_SECRET_WRITER_ENABLED=true` AND
    /// `KubernetesSecretWriterImpl::try_in_cluster()` succeeded at
    /// composition time; `None` otherwise.
    ///
    /// Only consumer is the `ServiceAccountRotationHandler`
    /// `TaskHandler` impl, which lives in
    /// `hort-app::tasks` and is registered against the worker dispatch
    /// table only when this slot is `Some(_)`. Inbound HTTP handlers
    /// never read this — `pub(crate)` per ADR 0008.
    ///
    /// Construction failure (env var set, in-cluster auth absent) is a
    /// fatal boot error in `hort-server::composition` — operators want a
    /// loud failure rather than silent degradation, since the
    /// reconciler is the only path that prevents PAT staleness for
    /// fallback-rotation SAs.
    #[allow(dead_code)]
    pub(crate) k8s_secret_writer: Option<Arc<dyn KubernetesSecretWriter>>,
    /// Scratch-space port for chunks-in-flight
    /// during three-phase / chunked stateful upload (OCI, Maven,
    /// Git LFS). Distinct from [`Self::storage`] (CAS) by design:
    /// staging bytes are keyed by session UUID (not content hash —
    /// the final SHA-256 isn't known until finalize).
    pub stateful_upload_staging: Arc<dyn StatefulUploadStagingPort>,
    /// Content-reference projection port.
    /// Narrow table keyed by `(repository_id, source_artifact_id)`
    /// with a `kind` discriminator + `metadata JSONB` sidecar. First
    /// caller is the OCI Referrers API (`kind = "oci_subject"`,
    /// read-side filter passes the same constant); future SBOM /
    /// provenance callers reuse the table with a different `kind`.
    #[allow(dead_code)]
    pub(crate) content_references: Arc<dyn ContentReferenceIndex>,
    /// Per-repository upstream mappings.
    /// Generic CRUD over the `repository_upstream_mappings` table;
    /// the longest-prefix-match resolution lives in the resolver,
    /// not here. First consumer is OCI multi-upstream
    /// mirroring; single-upstream formats (npm, PyPI, Cargo) reuse
    /// the same surface with `path_prefix = ""`.
    pub repository_upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    /// `policy_projections` /
    /// `exclusion_projections` read+write surface. Composed into
    /// `QuarantineUseCase` and `PolicyUseCase`;
    /// future consumers add additional use
    /// cases without re-wiring the adapter. `pub(crate)` because only
    /// inbound HTTP handlers in the same crate read projections, and
    /// only for response-shape coercion (404 pre-checks) and URL-
    /// identifier resolution (CVE → exclusion_id) —
    /// never for policy evaluation, which the use cases own
    /// (architect-skill "no business logic in handlers" rule).
    pub(crate) policy_projections: Arc<dyn PolicyProjectionRepository>,
    /// `curation_rules` table read+write surface. Composed into
    /// `IngestUseCase` (pre-storage gate) and
    /// `ApplyConfigUseCase` (gitops apply path).
    /// `pub(crate)` because no inbound HTTP handler reads the
    /// curation rule set directly — the use case owns the
    /// evaluation surface (architect-skill "no business logic in
    /// handlers" rule).
    #[allow(dead_code)]
    pub(crate) curation_rules: Arc<dyn CurationRuleRepository>,
    /// Pull-through upstream resolver.
    /// Maps `(repo_id, requested_name)` → `(mapping, stripped_name)`
    /// using longest-prefix-match against an in-memory snapshot of
    /// the upstream-mappings table. The snapshot is refreshed by a
    /// background task in `hort-server::main` on a
    /// `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` cadence (default 60s).
    /// Format-agnostic at this layer — the OCI handler is the first
    /// consumer; future formats with proxy semantics share the same
    /// port.
    pub upstream_resolver: Arc<dyn UpstreamResolver>,
    /// Pull-through upstream proxy. Streams
    /// blobs and fetches manifests from configured upstream
    /// registries. Format-agnostic at this layer; the concrete
    /// adapter
    /// (`hort_adapters_upstream_http::HttpUpstreamProxy`) lives in a
    /// dedicated crate to keep `reqwest` off `hort-http-oci`'s
    /// dependency edge (ADR 0008).
    pub upstream_proxy: Arc<dyn UpstreamProxy>,
    /// Prometheus handle used by `GET /metrics` to render the current
    /// snapshot. Constructed by the caller — `main.rs` installs the
    /// recorder globally via `PrometheusBuilder::install_recorder()`;
    /// tests use a local recorder scope via `metrics::with_local_recorder`
    /// and pass the handle in separately.
    pub metrics_handle: PrometheusHandle,
    /// When `false`, use cases emit the `repository` label as the sentinel
    /// [`hort_app::metrics::values::REPOSITORY_ALL`] (= `"_all"`) to keep
    /// series cardinality bounded on large deployments. See
    /// `docs/metrics-catalog.md` (ADR 0017).
    pub include_repository_label: bool,
    /// When `false`, the per-SA metric label
    /// on `hort_rotation_lag_seconds` AND
    /// `hort_service_account_authenticated_total` collapses to
    /// `service_account="_all"`. Threaded from
    /// `Config::include_service_account_label`. Defaults to `true`
    /// (operator-declared SA count is typically <50). Operators
    /// flipping the toggle govern both per-SA emission sites with one
    /// env var so the rotation gauge and the auth counter stay in
    /// lock-step.
    pub include_service_account_label: bool,
    /// Infallible pass-through for the public-facing base URL used in
    /// packument / `config.json` / index responses.
    /// This is a zero-sized type: all trust evaluation lives in
    /// [`crate::middleware::trust`], which populates
    /// [`crate::middleware::trust::RequestTrust::public_url`] on every
    /// request. Handlers call `ctx.url_resolver.resolve(&trust)` to
    /// retrieve it. See [`crate::url_resolver`].
    pub url_resolver: crate::url_resolver::UrlResolver,
    /// Per-request trust policy applied globally by
    /// [`crate::middleware::trust::request_trust_layer`]. Holds the
    /// parsed `HORT_PUBLIC_BASE_URL` + `HORT_TRUSTED_PROXY_CIDRS` so the layer
    /// can decide, for each request, whether to believe `X-Forwarded-*`
    /// and which `public_url` to publish. See
    /// `docs/architecture/explanation/security.md` (request trust).
    pub trust_config: crate::middleware::trust::TrustConfig,
    /// Per-IP rate-limit caps consumed by
    /// [`crate::middleware::rate_limit::auth_rate_limit_layer`] and
    /// [`crate::middleware::rate_limit::write_rate_limit_layer`]. Mirrors
    /// the `trust_config` pattern: config is parsed once in
    /// `hort-server::Config`, threaded into `AppContext`, consumed by the
    /// router at build time.
    pub rate_limit_config: crate::middleware::rate_limit::RateLimitConfig,
    /// Workspace-wide + per-IP
    /// concurrency caps consumed by
    /// [`crate::middleware::load_shed::global_load_shed_middleware`] and
    /// [`crate::middleware::load_shed::per_ip_load_shed_middleware`].
    /// Same threading pattern as `rate_limit_config`.
    pub concurrency_limit_config: crate::middleware::load_shed::ConcurrencyLimitConfig,
    /// Per-request deadline durations
    /// consumed by
    /// [`crate::middleware::request_timeout::request_timeout_layer`]
    /// (global default at `wrap_with_middleware`) and the OCI router's
    /// per-route override (`hort-http-oci`). Same threading pattern as
    /// `rate_limit_config`.
    pub http_timeout_config: crate::middleware::request_timeout::HttpTimeoutConfig,
    /// Per-publish body-size ceiling applied to
    /// PyPI and npm publish routes via `DefaultBodyLimit::max`. `None`
    /// means "use the shared default" ([`crate::limits::DEFAULT_PUBLISH_BODY_LIMIT`],
    /// 300 MiB). `Some(n)` comes from the `HORT_PUBLISH_BODY_MAX_SIZE`
    /// env var parsed by `hort-server::config::Config`.
    ///
    /// Cargo is deliberately NOT driven by this field; it keeps its
    /// own fixed 200 MiB ceiling via
    /// [`crate::limits::CARGO_PUBLISH_BODY_LIMIT`].
    pub publish_body_limit_bytes: Option<usize>,
    /// Per-version-object byte cap inside
    /// the streaming JSON projectors (npm `versions{}` value, PyPI
    /// `releases{}` value; ADR 0026). Threaded into `NpmPackumentProjector::new`
    /// / `PypiInfoProjector::new` at construction time. Default value
    /// is settled in `Config::from_env`
    /// (`HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE`, 2 MiB).
    /// Plain config value (not an `Arc<dyn Port>`) — matches
    /// the architect-skill rule that AppContext fields are either a
    /// port handle or a plain config value.
    pub upstream_projector_version_object_max_bytes: u64,
    /// Authentication + RBAC wiring. `AuthContext::Disabled` preserves the
    /// anonymous pass-through — the router skips attaching
    /// `require_principal` and handlers keep their `Uuid::nil()` placeholder
    /// actor. `AuthContext::Enabled` attaches the middleware and hands
    /// handlers the `AuthenticateUseCase` + `RbacEvaluator` pair they need
    /// to gate write paths (see `docs/auth-catalog.md`).
    ///
    /// Known carry-forward: the `Uuid::nil()` placeholder-actor cluster
    /// awaits the subscription composition wiring + auth boundary cleanup.
    pub auth: AuthContext,
    /// Process-wide extra CA trust bundle (ADR 0010) read once
    /// at boot from `HORT_EXTRA_CA_BUNDLE`. `None` when the env var is unset
    /// (trust only public CAs). `Some(_)` carries the DER-encoded
    /// certificates parsed by `hort_config::extra_ca::ExtraTrustAnchors`.
    ///
    /// Stored here for future inbound-HTTP middleware that may want to
    /// surface trust-bundle status (e.g. `GET /admin/trust-bundle` →
    /// `{"cert_count": N}`). No such consumer exists today, so there is
    /// **no public accessor** — `pub(crate)` keeps the field invisible to
    /// format crates per the anti-pattern rule (ADR 0008). Adapters that
    /// consume the bundle receive it directly from the composition root;
    /// they do NOT reach through `AppContext`.
    #[allow(dead_code)]
    pub(crate) extra_trust_anchors: Option<ExtraTrustAnchors>,
    /// In-process PAT validation cache.
    /// `Some(_)` when `HORT_NATIVE_TOKENS_ENABLED=true` (composition
    /// builds the cache, the validator, and spawns the
    /// `api_token_revocation` PgListener); `None` when the feature
    /// flag is unset, in which case the auth middleware's PAT branch
    /// is also a no-op via `AuthContext::Enabled.authenticate`'s
    /// missing `pat_validation` wiring. The middleware does NOT read
    /// this field directly — the validator owns the cache; the
    /// AppContext slot exists so the composition root holds the
    /// `Arc` alive (the listener task wires the cache as
    /// `Arc<dyn ApiTokenCacheInvalidator>` and the validator wires
    /// the same `Arc<PatCache>`).
    pub pat_cache: Option<Arc<PatCache>>,
    /// Operator opt-in to allow PAT
    /// authentication over plaintext HTTP. Default `false`; when
    /// `false`, the [`crate::middleware::auth::require_principal`]
    /// layer emits `426 Upgrade Required` on a `Bearer hort_<kind>_<body>`
    /// token whose request path lacks TLS evidence
    /// (`!RequestTrust.public_url.scheme() == "https"` AND no
    /// `X-Forwarded-Proto: https` from a trusted peer). Wired from
    /// `HORT_BEARER_ALLOW_OVER_HTTP` at boot. The
    /// gate also covers CliSession-family JWTs, not just PAT-shaped
    /// tokens — hence the bearer-scoped knob name.
    ///
    /// This is a **transport** flag, not a trust-knob — see
    /// `CLAUDE.md` anti-pattern: "no `*_INSECURE_TLS`". Setting
    /// this to `true` emits `tracing::warn!("HORT_BEARER_ALLOW_OVER_HTTP
    /// active — bearer auth without TLS")` ONCE at boot and sets the
    /// `hort_unsafe_config_active{kind="pat_over_http"} = 1` gauge so
    /// the misconfig is visible on every dashboard.
    pub pat_over_http_allowed: bool,
    /// OCI Distribution-Spec `/v2/auth`
    /// token-exchange use case. `Some(_)` when
    /// `HORT_NATIVE_TOKENS_ENABLED=true` AND the OCI signing key is
    /// configured; `None` otherwise. The presence of this slot is
    /// what flips the `/v2/*` challenge middleware between
    /// `WWW-Authenticate: Bearer realm=<…>/v2/auth,…` and the legacy
    /// `Basic` challenge.
    pub oci_token_exchange: Option<Arc<OciTokenExchangeUseCase>>,
    /// Ed25519 signing-key handle used to
    /// VERIFY inbound `Authorization: Bearer <distribution-spec JWT>`
    /// values on every `/v2/*` request. Same `Arc` is captured by
    /// `oci_token_exchange` (above) for the mint side; here the slot
    /// exists so the per-request middleware can verify without going
    /// through the use case (which would force a 1-hop indirection
    /// on every authenticated OCI request).
    pub oci_signing_key: Option<Arc<OciTokenSigningKey>>,
    /// Public base URL prefix used to build
    /// the `realm=<base>/v2/auth` value in the Bearer challenge.
    /// `None` when `HORT_PUBLIC_BASE_URL` is unset; the challenge
    /// middleware falls back to a relative path in that case (the
    /// `WWW-Authenticate` value still parses; clients append the host
    /// of the original request).
    pub oci_public_base_url: Option<String>,
    /// Client-bootstrap document config for
    /// `GET /.well-known/hort-client-config`. `Some(_)` when
    /// `HORT_TOKEN_EXCHANGE_ENABLED=true` (composition projects the IdP
    /// coordinates + absolute exchange URL once at startup). `None`
    /// when the feature is off; the route is then not mounted and the
    /// field is unread. Composition guarantees that, when populated,
    /// every field is non-empty (the fail-closed boot rule
    /// rejects half-formed configs before the listener binds).
    pub client_config: Option<crate::handlers::well_known::ClientBootstrapConfig>,
}

/// Public construction parts for [`AppContext`] (ADR 0008).
///
/// The seven data ports (`repositories`, `artifacts`, `refs`,
/// `artifact_groups`, `content_references`, `artifact_metadata`,
/// `storage`) are `pub(crate)` on [`AppContext`] so format crates
/// compile-error on direct access. Composition still has to wire them,
/// though, so this struct exposes the same set with `pub` fields and
/// hands off to [`AppContext::new`]. The two shapes share field names
/// 1:1 to keep the call site mechanical.
pub struct AppContextParts {
    pub repository_use_case: Arc<RepositoryUseCase>,
    pub artifact_use_case: Arc<ArtifactUseCase>,
    pub repository_access_use_case: Arc<RepositoryAccessUseCase>,
    pub content_reference_use_case: Arc<ContentReferenceUseCase>,
    pub ingest_use_case: Arc<IngestUseCase>,
    pub user_use_case: Arc<UserUseCase>,
    /// See [`AppContext::api_token_use_case`].
    pub api_token_use_case: Arc<ApiTokenUseCase>,
    pub quarantine_use_case: Arc<QuarantineUseCase>,
    pub promotion_use_case: Arc<PromotionUseCase>,
    pub ref_use_case: Arc<RefUseCase>,
    /// See [`AppContext::security_score_use_case`].
    pub security_score_use_case: Arc<SecurityScoreUseCase>,
    /// See [`AppContext::task_use_case`].
    pub task_use_case: Arc<TaskUseCase>,
    /// See [`AppContext::manual_rescan_use_case`].
    pub manual_rescan_use_case: Arc<ManualRescanUseCase>,
    /// See [`AppContext::patch_candidate_use_case`].
    pub patch_candidate_use_case: Arc<PatchCandidateUseCase>,
    /// See [`AppContext::scanner_worker_query_use_case`].
    pub scanner_worker_query_use_case: Arc<ScannerWorkerQueryUseCase>,
    /// See [`AppContext::prefetch_use_case`].
    pub prefetch_use_case: Arc<PrefetchUseCase>,
    /// See [`AppContext::effective_permissions_use_case`].
    pub effective_permissions_use_case: Arc<EffectivePermissionsUseCase>,
    /// See [`AppContext::rbac_resolve_use_case`].
    pub rbac_resolve_use_case: Arc<RbacResolveUseCase>,
    /// See [`AppContext::subscription_use_case`].
    pub subscription_use_case: Arc<SubscriptionUseCase>,

    /// See [`AppContext::curation_use_case`].
    pub curation_use_case: Arc<CurationUseCase>,
    /// See [`AppContext::policy_use_case`].
    pub policy_use_case: Arc<PolicyUseCase>,
    /// See [`AppContext::wheel_metadata_use_case`].
    pub wheel_metadata_use_case: Arc<WheelMetadataUseCase>,
    pub storage: Arc<dyn StoragePort>,
    pub artifacts: Arc<dyn ArtifactRepository>,
    pub repositories: Arc<dyn RepositoryRepository>,
    pub refs: Arc<dyn RefRegistryPort>,
    pub ref_lifecycle: Arc<dyn RefLifecyclePort>,
    pub artifact_group_use_case: Arc<ArtifactGroupUseCase>,
    pub artifact_groups: Arc<dyn ArtifactGroupRepository>,
    pub artifact_group_lifecycle: Arc<dyn ArtifactGroupLifecyclePort>,
    pub artifact_metadata: Arc<dyn ArtifactMetadataRepository>,
    /// See [`AppContext::security_scores`].
    pub security_scores: Arc<dyn RepoSecurityScoreRepository>,
    /// See [`AppContext::jobs`].
    pub jobs: Arc<dyn JobsRepository>,
    /// See [`AppContext::ephemeral_evictable`].
    pub ephemeral_evictable: Arc<dyn EphemeralStore>,
    /// See [`AppContext::metadata_mirror`].
    pub metadata_mirror: Arc<dyn MetadataMirrorStore>,
    /// See [`AppContext::pull_dedup`].
    pub pull_dedup: Arc<PullDedup>,
    /// See [`AppContext::ephemeral_durable`].
    pub ephemeral_durable: Arc<dyn EphemeralStore>,
    /// Event store handle for `/readyz`. See
    /// `AppContext::event_store`.
    pub event_store: Arc<EventStorePublisher>,
    /// Multi-issuer JWT validator. See
    /// [`AppContext::federated_jwt_validator`]. `pub` here because
    /// composition needs to wire it; the field is `pub(crate)` on the
    /// `AppContext` struct itself (handlers reach it via a use case).
    pub federated_jwt_validator: Option<Arc<dyn FederatedJwtValidator>>,
    /// `ServiceAccountRepository` for the
    /// federation branch's SA-resolution step. See
    /// [`AppContext::service_accounts`]. `pub` here because composition
    /// needs to wire it; the field is `pub(crate)` on the `AppContext`
    /// struct itself (only the federation handler in this crate touches
    /// it).
    pub service_accounts: Option<Arc<dyn ServiceAccountRepository>>,
    /// `OidcIssuerRepository` for
    /// resolving the matched issuer's `require_jti`. See
    /// [`AppContext::oidc_issuers`]. `pub` here for composition wiring;
    /// `pub(crate)` on `AppContext`.
    pub oidc_issuers: Option<Arc<dyn OidcIssuerRepository>>,
    /// k8s Secret writer for the fallback PAT
    /// rotation reconciler. `pub` here because composition needs to
    /// wire it; the field is `pub(crate)` on the `AppContext` struct
    /// itself (the reconciler in `hort-app` reaches it via a use case).
    pub k8s_secret_writer: Option<Arc<dyn KubernetesSecretWriter>>,
    pub stateful_upload_staging: Arc<dyn StatefulUploadStagingPort>,
    pub content_references: Arc<dyn ContentReferenceIndex>,
    pub repository_upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    pub upstream_resolver: Arc<dyn UpstreamResolver>,
    pub upstream_proxy: Arc<dyn UpstreamProxy>,
    pub policy_projections: Arc<dyn PolicyProjectionRepository>,
    pub curation_rules: Arc<dyn CurationRuleRepository>,
    pub metrics_handle: PrometheusHandle,
    pub include_repository_label: bool,
    /// Defaults to `true` in tests via the
    /// existing builder (`AppContextParts::default_for_test` mirrors
    /// the default-`true` posture).
    pub include_service_account_label: bool,
    pub url_resolver: crate::url_resolver::UrlResolver,
    pub trust_config: crate::middleware::trust::TrustConfig,
    pub rate_limit_config: crate::middleware::rate_limit::RateLimitConfig,
    pub concurrency_limit_config: crate::middleware::load_shed::ConcurrencyLimitConfig,
    pub http_timeout_config: crate::middleware::request_timeout::HttpTimeoutConfig,
    pub publish_body_limit_bytes: Option<usize>,
    /// See [`AppContext::upstream_projector_version_object_max_bytes`].
    pub upstream_projector_version_object_max_bytes: u64,
    pub auth: AuthContext,
    /// See [`AppContext::extra_trust_anchors`].
    pub extra_trust_anchors: Option<ExtraTrustAnchors>,
    /// See [`AppContext::pat_cache`].
    pub pat_cache: Option<Arc<PatCache>>,
    /// See [`AppContext::pat_over_http_allowed`].
    pub pat_over_http_allowed: bool,
    /// See [`AppContext::oci_token_exchange`].
    pub oci_token_exchange: Option<Arc<OciTokenExchangeUseCase>>,
    /// See [`AppContext::oci_signing_key`].
    pub oci_signing_key: Option<Arc<OciTokenSigningKey>>,
    /// See [`AppContext::oci_public_base_url`].
    pub oci_public_base_url: Option<String>,
    /// See [`AppContext::client_config`].
    pub client_config: Option<crate::handlers::well_known::ClientBootstrapConfig>,
}

impl AppContext {
    /// Construct an [`AppContext`] from a fully-wired parts struct.
    ///
    /// This is the public construction surface for the seven `pub(crate)`
    /// data ports (ADR 0008). The composition root in `hort-server`
    /// and any out-of-crate test that wires its own context use this
    /// instead of the struct literal (which is unreachable across crates
    /// because of the field visibility).
    pub fn new(parts: AppContextParts) -> Self {
        Self {
            repository_use_case: parts.repository_use_case,
            artifact_use_case: parts.artifact_use_case,
            repository_access_use_case: parts.repository_access_use_case,
            content_reference_use_case: parts.content_reference_use_case,
            ingest_use_case: parts.ingest_use_case,
            user_use_case: parts.user_use_case,
            api_token_use_case: parts.api_token_use_case,
            quarantine_use_case: parts.quarantine_use_case,
            promotion_use_case: parts.promotion_use_case,
            ref_use_case: parts.ref_use_case,
            security_score_use_case: parts.security_score_use_case,
            task_use_case: parts.task_use_case,
            manual_rescan_use_case: parts.manual_rescan_use_case,
            patch_candidate_use_case: parts.patch_candidate_use_case,
            scanner_worker_query_use_case: parts.scanner_worker_query_use_case,
            prefetch_use_case: parts.prefetch_use_case,
            effective_permissions_use_case: parts.effective_permissions_use_case,
            rbac_resolve_use_case: parts.rbac_resolve_use_case,
            subscription_use_case: parts.subscription_use_case,
            curation_use_case: parts.curation_use_case,
            policy_use_case: parts.policy_use_case,
            wheel_metadata_use_case: parts.wheel_metadata_use_case,
            // Wired after `new` via `with_discovery_use_cases`: the use
            // cases are constructed by the test harness's `with_*` helpers
            // (test side) and by the production composition wiring.
            // `AppContext::new` does not require them.
            discovery_use_case: None,
            self_service_prefetch_use_case: None,
            storage: parts.storage,
            artifacts: parts.artifacts,
            repositories: parts.repositories,
            refs: parts.refs,
            ref_lifecycle: parts.ref_lifecycle,
            artifact_group_use_case: parts.artifact_group_use_case,
            artifact_groups: parts.artifact_groups,
            artifact_group_lifecycle: parts.artifact_group_lifecycle,
            artifact_metadata: parts.artifact_metadata,
            security_scores: parts.security_scores,
            jobs: parts.jobs,
            ephemeral_evictable: parts.ephemeral_evictable,
            metadata_mirror: parts.metadata_mirror,
            pull_dedup: parts.pull_dedup,
            ephemeral_durable: parts.ephemeral_durable,
            event_store: parts.event_store,
            federated_jwt_validator: parts.federated_jwt_validator,
            service_accounts: parts.service_accounts,
            oidc_issuers: parts.oidc_issuers,
            k8s_secret_writer: parts.k8s_secret_writer,
            stateful_upload_staging: parts.stateful_upload_staging,
            content_references: parts.content_references,
            repository_upstream_mappings: parts.repository_upstream_mappings,
            upstream_resolver: parts.upstream_resolver,
            upstream_proxy: parts.upstream_proxy,
            policy_projections: parts.policy_projections,
            curation_rules: parts.curation_rules,
            metrics_handle: parts.metrics_handle,
            include_repository_label: parts.include_repository_label,
            include_service_account_label: parts.include_service_account_label,
            url_resolver: parts.url_resolver,
            trust_config: parts.trust_config,
            rate_limit_config: parts.rate_limit_config,
            concurrency_limit_config: parts.concurrency_limit_config,
            http_timeout_config: parts.http_timeout_config,
            publish_body_limit_bytes: parts.publish_body_limit_bytes,
            upstream_projector_version_object_max_bytes: parts
                .upstream_projector_version_object_max_bytes,
            auth: parts.auth,
            extra_trust_anchors: parts.extra_trust_anchors,
            pat_cache: parts.pat_cache,
            pat_over_http_allowed: parts.pat_over_http_allowed,
            oci_token_exchange: parts.oci_token_exchange,
            oci_signing_key: parts.oci_signing_key,
            oci_public_base_url: parts.oci_public_base_url,
            client_config: parts.client_config,
        }
    }

    /// Populate the discovery + self-service
    /// prefetch use case slots after `new` returns. Production composition
    /// calls this once at startup with both arguments
    /// wired against the real Postgres ports + the live `UpstreamMetadataPort`;
    /// the test harness (`crate::test_support::build_mock_ctx`) calls it
    /// with the in-memory mocks.
    ///
    /// Separate from `AppContext::new` because the wiring of these two use
    /// cases requires an outbound port (`UpstreamMetadataPort`)
    /// that did not exist when the `AppContextParts`
    /// surface was first sealed; threading it through every `new` call
    /// site would force a churn of every test and every composition
    /// shape. Production callers populate the slot at boot time, tests
    /// populate it at harness build time, the handler `.expect()`s it
    /// because mounting the router under the
    /// `/api/v1/repositories/...` namespace requires the wiring step
    /// first.
    pub fn with_discovery_use_cases(
        &mut self,
        discovery: Arc<DiscoveryUseCase>,
        self_service_prefetch: Arc<SelfServicePrefetchUseCase>,
    ) {
        self.discovery_use_case = Some(discovery);
        self.self_service_prefetch_use_case = Some(self_service_prefetch);
    }
}
