use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use hort_adapters_ephemeral_memory::{
    InMemoryEphemeralStore, MeteredEphemeralStore as MeteredMemEphemeralStore,
};
use hort_adapters_ephemeral_redis::{
    MeteredEphemeralStore as MeteredRedisEphemeralStore, RedisEphemeralStore,
};
use hort_adapters_postgres::artifact_group_lifecycle::PgArtifactGroupLifecycle;
use hort_adapters_postgres::artifact_group_repo::PgArtifactGroupRepository;
use hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle;
use hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::curation_decisions_repository::PgCurationDecisionsRepository;
use hort_adapters_postgres::curation_exclusions_repository::PgCurationExclusionsRepository;
use hort_adapters_postgres::curation_queue_repository::PgCurationQueueRepository;
use hort_adapters_postgres::curation_rule_repo::PgCurationRuleRepository;
use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_adapters_postgres::oidc_issuer_repo::PgOidcIssuerRepository;
use hort_adapters_postgres::patch_candidate_repo::PgPatchCandidateRepository;
use hort_adapters_postgres::pg_content_reference_repo::PgContentReferenceRepo;
use hort_adapters_postgres::policy_projection_repo::PgPolicyProjectionRepository;
use hort_adapters_postgres::ref_lifecycle::PgRefLifecycle;
use hort_adapters_postgres::ref_registry_repo::PgRefRegistry;
use hort_adapters_postgres::repo_security_score_repository::PgRepoSecurityScoreRepository;
use hort_adapters_postgres::repository_repo::PgRepositoryRepository;
use hort_adapters_postgres::repository_upstream_mapping_repo::PgRepositoryUpstreamMappingRepo;
use hort_adapters_postgres::subscription_repo::PgSubscriptionRepository;
use hort_adapters_postgres::user_repo::PgUserRepository;
use hort_adapters_storage::filesystem_stateful_upload_staging::FilesystemStatefulUploadStaging;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::pull_dedup::{PullDedup, PullDedupConfig};
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
use hort_app::use_cases::artifact_use_case::ArtifactUseCase;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::content_reference::ContentReferenceUseCase;
use hort_app::use_cases::curation_use_case::CurationUseCase;
use hort_app::use_cases::effective_permissions_use_case::EffectivePermissionsUseCase;
use hort_app::use_cases::ingest_use_case::IngestUseCase;
use hort_app::use_cases::manual_rescan_use_case::ManualRescanUseCase;
use hort_app::use_cases::pat_cache::{PatCache, SystemClock};
use hort_app::use_cases::pat_validation_use_case::{PatLockoutConfig, PatValidationUseCase};
use hort_app::use_cases::patch_candidate_use_case::PatchCandidateUseCase;
use hort_app::use_cases::scanner_worker_query_use_case::ScannerWorkerQueryUseCase;
// `PolicyUseCase` is exposed on `AppContext` for
// the HTTP exclusion write surface
// (`POST/DELETE /api/v1/admin/policies/:policy_id/exclusions[/:cve_id]`).
// The runtime instance is shared by the gitops apply pipeline (which
// constructs its own copy in `gitops_boot.rs` for use BEFORE the
// AppContext exists; that copy stops after boot) and the HTTP write
// path; the use-case signature is permission-neutral so both callers
// work unchanged.
use hort_app::use_cases::policy_use_case::PolicyUseCase;
// Prefetch trigger planner (`on_index_fetch` +
// `on_dist_tag_move`). Stateless unit struct; the composition root
// constructs a single shared `Arc` so the cost is one pointer per
// AppContext clone.
use hort_app::use_cases::prefetch_use_case::PrefetchUseCase;
// Repo-keyed discovery endpoint use case.
use hort_app::use_cases::discovery_use_case::DiscoveryUseCase;
// Repo-keyed self-service prefetch
// endpoint use case. Wraps the pure `PrefetchUseCase` planner above
// with the I/O-bearing orchestration (the pure
// planner stays untouched).
use hort_app::use_cases::promotion_use_case::PromotionUseCase;
use hort_app::use_cases::quarantine_use_case::QuarantineUseCase;
use hort_app::use_cases::rbac_resolve_use_case::RbacResolveUseCase;
use hort_app::use_cases::ref_use_case::RefUseCase;
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::repository_use_case::RepositoryUseCase;
use hort_app::use_cases::security_score_use_case::SecurityScoreUseCase;
use hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase;
use hort_app::use_cases::subscription_use_case::{SubscriptionUseCase, SubscriptionUseCaseConfig};
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_app::use_cases::virtual_resolution::VirtualResolutionUseCase;
// Application-layer adapter for the
// `UpstreamIndexCacheInvalidator` port. Wired into the three
// `ArtifactRejected` emitter use cases (curation/block, quarantine/
// scan-driven-reject, apply-config/retroactive-block) via their
// `with_upstream_index_cache_invalidator` builder methods.
use hort_app::use_cases::upstream_index_cache_invalidator::AppUpstreamIndexCacheInvalidator;
use hort_app::use_cases::user_use_case::UserUseCase;
// PEP 658 wheel-metadata serve use case.
use hort_app::use_cases::wheel_metadata_use_case::WheelMetadataUseCase;
use hort_domain::entities::rbac::ClaimMapping;
use hort_domain::error::DomainResult;
use hort_domain::ports::api_token_cache_invalidator::ApiTokenCacheInvalidator;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::artifact_group_lifecycle::ArtifactGroupLifecyclePort;
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::ref_lifecycle::RefLifecyclePort;
use hort_domain::ports::ref_registry::RefRegistryPort;
use hort_domain::ports::repo_security_score_repository::RepoSecurityScoreRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::secret_port::SecretPort;
use hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;

use crate::config::ConfigError;
use hort_config::ExtraTrustAnchors;
use hort_http_core::context::{AppContext, AppContextParts, AuthContext};

/// Composition output: the request-time [`AppContext`] plus auxiliary
/// concrete handles `cli::serve` needs to wire background tasks.
///
/// Keeping these adjacent to `AppContext` (rather than on it) preserves
/// the AppContext-only-holds-`Arc<dyn>` invariant. The
/// `caching_resolver` field is the same instance the `AppContext`'s
/// `upstream_resolver` points at — different views, one allocation.
pub struct BuildAppContextOutput {
    pub ctx: AppContext,
    /// Concrete handle to the upstream
    /// resolver so the refresh task in `cli::serve` can call
    /// `reload` without a downcast. The same `Arc` is held as
    /// `Arc<dyn UpstreamResolver>` on `ctx.upstream_resolver` for
    /// the request path.
    pub caching_resolver: Arc<hort_adapters_upstream_http::CachingResolver>,
    /// `JoinHandle` for the
    /// `api_token_revocation` PgListener task. `Some(_)` when
    /// `HORT_NATIVE_TOKENS_ENABLED=true` (the listener was spawned and
    /// is dispatching to `ctx.pat_cache`); `None` when the feature
    /// flag is unset (no listener, no cache). `cli::serve` aborts
    /// the handle on shutdown.
    pub pat_listener: Option<tokio::task::JoinHandle<()>>,
    /// The constructed `NotificationDispatcher`
    /// plus the paired `subscription_changes` PgListener handle.
    /// Returned to `cli::serve` so it can spawn the dispatcher task
    /// with the same shutdown token used by every other long-lived
    /// background task.
    ///
    /// `Some(_)` when `HORT_NOTIFICATIONS_ENABLED=true`; `None` when the
    /// flag is off (no dispatcher, no listener).
    pub notification_runtime: Option<NotificationRuntime>,
}

/// Packaged dispatcher + change-listener
/// returned from `build_app_context` to `cli::serve`. The serve loop
/// spawns the dispatcher under `shutdown_handle.token()` so a single
/// SIGTERM fans out to the dispatcher loop AND every per-subscription
/// task spawned by the reconcile pass (each task uses a child token of
/// the dispatcher's parent token).
pub struct NotificationRuntime {
    /// The configured dispatcher. `run(cancel)` drives the reconcile +
    /// per-subscription-task lifecycle until the token fires.
    pub dispatcher: hort_app::dispatcher::dispatcher::NotificationDispatcher,
    /// JoinHandle for the `subscription_changes` LISTEN/NOTIFY task.
    /// Held by `cli::serve` and aborted on shutdown,
    /// mirroring the `api_token_revocation` listener pattern.
    pub change_listener_handle: tokio::task::JoinHandle<()>,
}

/// Wiring config for the native API token
/// surface (ADR 0012). Threaded into [`build_app_context`] from
/// `Config::from_env`
/// so the boot path doesn't re-read env vars (composition is the
/// source of truth for parsed config).
///
/// The `oci_token_signing_key_pem` /
/// `oci_token_signing_key_prev_pem` fields keep this struct `Clone`
/// rather than `Copy` (`Option<String>` is not `Copy`).
#[derive(Debug, Clone)]
pub struct NativeTokenConfig {
    /// `HORT_NATIVE_TOKENS_ENABLED` — when `false` (default), the PAT
    /// surface is OFF: no cache, no validator, no listener; the auth
    /// middleware's PAT branch is a no-op.
    pub enabled: bool,
    /// `HORT_BEARER_ALLOW_OVER_HTTP` — when `true`, the auth
    /// middleware's 426-Upgrade-Required gate on bearer-over-plaintext
    /// (PAT-shaped tokens AND CliSession-family JWTs) is
    /// disabled. **Transport flag, not a trust knob.** Setting to
    /// `true` emits a boot-time warn and the `hort_unsafe_config_active`
    /// gauge.
    pub allow_pat_over_http: bool,
    /// `HORT_PAT_CACHE_SIZE` — LRU capacity of the in-process PAT cache.
    pub cache_size: usize,
    /// `HORT_PAT_LOCKOUT_THRESHOLD` — per-IP failures before lockout.
    pub lockout_threshold: u32,
    /// `HORT_PAT_LOCKOUT_WINDOW_SECS` — sliding window for the counter.
    pub lockout_window_secs: u64,
    /// `HORT_PAT_LOCKOUT_DURATION_SECS` — how long the lockout flag
    /// remains in effect after the threshold trips.
    pub lockout_duration_secs: u64,
    /// `HORT_TOKEN_ALLOW_ADMIN`. When `true`,
    /// the issuance use case permits `Permission::Admin` in
    /// `declared_permissions` (still gated on the caller having
    /// admin authority and clamped to `[1, 30]` days). Default
    /// `false`.
    pub allow_admin_tokens: bool,
    /// `HORT_TOKEN_ALLOW_UNBOUNDED_SVC`.
    /// When `true`, admin-mint may issue service-account tokens
    /// with `expires_in_days = null`. Default `false`.
    pub allow_unbounded_svc_tokens: bool,
    /// PKCS#8-PEM of the active OCI-token
    /// signing key. When `enabled = true`, this MUST be `Some(_)`
    /// (composition asserts; config-layer enforces via
    /// `ConfigError::OciTokenSigningKeyMissing`). When `enabled =
    /// false`, may be `None` (key not loaded).
    pub oci_token_signing_key_pem: Option<String>,
    /// Optional PEM of the previous OCI-token
    /// signing key's PUBLIC half (verify-only).
    pub oci_token_signing_key_prev_pem: Option<String>,
}

/// Event-notification substrate config (see
/// `docs/architecture/explanation/event-notifications.md`).
///
/// Built once at boot from
/// `Config::enable_notifications` / `Config::notify_channel_capacity`
/// (parsed from `HORT_NOTIFICATIONS_ENABLED` / `HORT_NOTIFY_CHANNEL_CAPACITY`)
/// and threaded into [`build_app_context`]. The composition root uses
/// these values to choose between
/// [`EventStorePublisher::new`] (broadcasts on every successful
/// `append`) and [`EventStorePublisher::without_broadcast`] (pure
/// pass-through).
#[derive(Debug, Clone)]
pub struct NotifyConfig {
    /// `HORT_NOTIFICATIONS_ENABLED` — when `false`, the publisher is built
    /// without a broadcast sender. The dispatcher does not start
    /// in this branch. Default `true` at config-parse time.
    pub enabled: bool,
    /// `HORT_NOTIFY_CHANNEL_CAPACITY` — capacity of the
    /// `broadcast::channel` between the publisher and the dispatcher.
    /// Read only when `enabled` is `true`. Default `1024`.
    pub channel_capacity: u32,
    /// `HORT_WEBHOOK_ALLOW_PLAINTEXT`. When
    /// `false` (default), webhook URLs must be `https://`. When `true`,
    /// `http://` is allowed and
    /// `hort_unsafe_config_active{kind="plaintext_webhooks"}` is set to
    /// `1` at boot. Threaded into `SubscriptionUseCaseConfig`.
    pub allow_plaintext_webhooks: bool,
    /// `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS`.
    /// When `false` (default), webhook target hosts must resolve to a
    /// routable address. When `true`, the SSRF check is skipped and
    /// `hort_unsafe_config_active{kind="webhook_nonroutable_targets"}` is
    /// set to `1` at boot. Threaded into `SubscriptionUseCaseConfig`.
    pub allow_nonroutable_webhook_targets: bool,
    /// `HORT_NATS_URL`. When `Some(_)` AND
    /// `enabled = true`, composition opens an async-nats client and
    /// registers a `NatsNotifier` with the dispatcher. When `None`,
    /// the NATS adapter is not constructed.
    pub nats_url: Option<String>,
}

/// Boot-time signal for the
/// `HORT_BEARER_ALLOW_OVER_HTTP` operator opt-in.
///
/// On the safe (`allowed = false`) path: gauge is set to `0.0` so a
/// scrape on a fresh recorder sees the metric anyway — absence vs
/// `0.0` would be ambiguous to dashboards. No `warn!` is emitted.
///
/// On the unsafe (`allowed = true`) path: emits a single
/// `tracing::warn!` so SREs see the misconfig at boot, AND sets the
/// gauge to `1.0`. The catalog entry in `docs/metrics-catalog.md`
/// pins the bounded `kind` enum (the enum gains one value per new
/// unsafe-config opt-in, on demand, not a transitional placeholder);
/// extending it requires a catalog edit per the architect-skill
/// metric-cardinality rule (ADR 0017).
pub(crate) fn emit_pat_over_http_signal(allowed: bool) {
    if allowed {
        tracing::warn!(
            "HORT_BEARER_ALLOW_OVER_HTTP active — bearer auth (PAT + CliSession JWT) \
             without TLS is allowed; use only on a trusted internal network or for development"
        );
        metrics::gauge!("hort_unsafe_config_active", "kind" => "pat_over_http").set(1.0);
    } else {
        metrics::gauge!("hort_unsafe_config_active", "kind" => "pat_over_http").set(0.0);
    }
}

/// Boot-time guardrail for the
/// deliberate test-clock auth-bypass primitive. This implements the
/// **mandatory guardrail** that auth-catalog Entry 10 ("Test-clock
/// bypass") mandates: a startup hard-fail if the bypass is enabled at
/// runtime in a release / non-feature build, plus the
/// `hort_unsafe_config_active{kind="test_clock"}` gauge.
///
/// The test-clock primitive (`POST /test/clock/advance`) is
/// double-gated: the `test-clock` cargo feature (compile-time) AND
/// `HORT_TEST_CLOCK_ENABLED=true` (runtime). Clock control subverts
/// every expiry-based auth control, so the safety argument rests on
/// those two gates never both being wrong. A release build never
/// compiles test features, so `feature_built == false` is the
/// "release / no-feature build" condition: if the operator
/// nonetheless sets the runtime flag there, the double gate is broken
/// and we MUST refuse to start.
///
/// Mirrors the [`emit_pat_over_http_signal`] precedent and is factored
/// into a `pub(crate)` fn so unit tests assert both the gauge value
/// and the hard-fail decision without standing up the Postgres
/// composition path.
///
/// - `enabled` — parsed value of `HORT_TEST_CLOCK_ENABLED` (the runtime
///   gate).
/// - `feature_built` — `cfg!(feature = "test-clock")` at the call
///   site (the compile-time gate).
///
/// Gauge: `1.0` whenever `enabled` (it is an unsafe opt-in regardless
/// of the build), `0.0` otherwise — emit on the safe path too so a
/// fresh scrape sees the metric (absence vs `0.0` is ambiguous to
/// dashboards). Returns `Err(DomainError::Invariant)` only on the
/// broken-double-gate combination so the caller can refuse to boot.
pub(crate) fn evaluate_test_clock_guard(
    enabled: bool,
    feature_built: bool,
) -> Result<(), hort_domain::error::DomainError> {
    if enabled {
        metrics::gauge!("hort_unsafe_config_active", "kind" => "test_clock").set(1.0);
        if !feature_built {
            tracing::error!(
                "HORT_TEST_CLOCK_ENABLED=true but this binary was built WITHOUT the \
                 `test-clock` cargo feature — the test-clock auth-bypass primitive \
                 is forbidden in a release/non-feature build (auth-catalog \
                 Entry 10). Refusing to start. Unset HORT_TEST_CLOCK_ENABLED, or use a \
                 build compiled with `--features test-clock` in a non-production test \
                 harness only."
            );
            return Err(hort_domain::error::DomainError::Invariant(
                "HORT_TEST_CLOCK_ENABLED=true requires a binary built with the \
                 `test-clock` cargo feature; the test-clock bypass is \
                 forbidden in a release/non-feature build (auth-catalog \
                 Entry 10)"
                    .into(),
            ));
        }
        // enabled && feature_built: the double gate is intact (a
        // deliberate test-harness build). Boot proceeds; the `1.0`
        // gauge + the catalog entry still surface the opt-in.
    } else {
        metrics::gauge!("hort_unsafe_config_active", "kind" => "test_clock").set(0.0);
    }
    Ok(())
}

/// Metric name for the staging-sweep liveness gauge.
/// Boolean (0/1), **no labels** — a single
/// global series. `1.0` means "no `staging-sweep` job has completed
/// within `staleness_multiplier × expected_interval`" (or has never
/// completed); `0.0` means a recent sweep is on record. The catalog
/// entry in `docs/metrics-catalog.md` pins the no-label contract.
const STAGING_SWEEP_OVERDUE_METRIC: &str = "hort_staging_sweep_overdue";

/// Boot-time liveness signal for the
/// `staging-sweep` task.
///
/// `hort-server` is scheduler-free (ADR 0028):
/// `staging-sweep` runs as a worker `TaskHandler` whose k8s
/// CronJob is `cronJobs.enabled:false` by default. A deployment that
/// upgrades without enabling the CronJob (the documented-safe default)
/// or runs non-k8s gets **no staging sweep at all** — orphaned
/// `stateful_upload_staging` entries accumulate unbounded until ingest
/// fails on a full filesystem, and nothing alerts. An attacker
/// triggering many incomplete uploads accelerates it.
///
/// The pure overdue/healthy decision lives in
/// [`hort_domain::policy::evaluate_staging_sweep_liveness`] (zero-I/O,
/// 100%-tested). This function is the thin composition-root shell that
/// supplies the wall-clock + the port-fetched last-completed timestamp,
/// then emits the gauge and a `warn!` on the overdue path — exactly
/// mirroring the [`evaluate_test_clock_guard`] / [`emit_pat_over_http_signal`]
/// boot-signal precedents.
///
/// **Placement rationale (boot-time emit, not a periodic loop).** A
/// periodic in-process re-check would itself be a `tokio::time`
/// scheduler — the scheduler-free `hort-server` is load-bearing
/// (ADR 0028). Instead the gauge
/// is set once at boot and scraped continuously; Prometheus alerts on
/// `max_over_time(hort_staging_sweep_overdue[…]) > 0`, the same
/// alarm shape the other boot-emitted
/// signals use. A minimal in-process sweep is
/// considered-and-declined for the same reason.
///
/// The gauge is emitted on **both** paths (`0.0` when healthy) so a
/// fresh scrape always sees the series — absence vs `0.0` is ambiguous
/// to dashboards, matching the `emit_pat_over_http_signal` convention.
/// Never returns an error / never blocks boot: a missing sweep is an
/// operational concern to alarm on, not a reason to refuse to start
/// (the deployment is otherwise serviceable; failing boot here would
/// be a worse outcome than the unbounded-staging risk it warns about).
pub(crate) fn emit_staging_sweep_liveness_signal(
    last_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    expected_interval: std::time::Duration,
    staleness_multiplier: u32,
) {
    use hort_domain::policy::{evaluate_staging_sweep_liveness, StagingSweepLiveness};

    let liveness = evaluate_staging_sweep_liveness(
        last_completed_at,
        now,
        expected_interval,
        staleness_multiplier,
    );

    match liveness {
        StagingSweepLiveness::Healthy { age_secs } => {
            tracing::debug!(
                age_secs,
                "staging-sweep liveness OK — a sweep completed within the staleness window"
            );
            metrics::gauge!(STAGING_SWEEP_OVERDUE_METRIC).set(0.0);
        }
        StagingSweepLiveness::Overdue {
            age_secs,
            threshold_secs,
        } => {
            tracing::warn!(
                age_secs,
                threshold_secs,
                expected_interval_secs = expected_interval.as_secs(),
                staleness_multiplier,
                "staging-sweep is OVERDUE — the most recent completed `staging-sweep` \
                 job is older than the staleness window. Orphaned stateful-upload \
                 staging entries accumulate unbounded until ingest fails on a full \
                 filesystem. Enable the `staging-sweep` CronJob \
                 (cronJobs.enabled=true) or run `hort-cli admin task staging-sweep`."
            );
            metrics::gauge!(STAGING_SWEEP_OVERDUE_METRIC).set(1.0);
        }
        StagingSweepLiveness::NeverRan => {
            tracing::warn!(
                expected_interval_secs = expected_interval.as_secs(),
                staleness_multiplier,
                "staging-sweep has NEVER completed on this deployment — likely \
                 upgraded without enabling the `staging-sweep` CronJob \
                 (cronJobs.enabled defaults to false) or running non-k8s. Orphaned \
                 stateful-upload staging entries will accumulate unbounded until \
                 ingest fails on a full filesystem. Enable the CronJob or run \
                 `hort-cli admin task staging-sweep`."
            );
            metrics::gauge!(STAGING_SWEEP_OVERDUE_METRIC).set(1.0);
        }
    }
}

/// Metric name for the event-chain-verifier liveness gauge.
/// Boolean (0/1), **no labels** — a single global
/// series. `1.0` means "no `verify-event-chain` run has completed within
/// `staleness_multiplier × expected_interval`" (or has never completed);
/// `0.0` means a recent verify run is on record. The catalog entry in
/// `docs/metrics-catalog.md` pins the no-label contract.
const EVENT_CHAIN_VERIFY_OVERDUE_METRIC: &str = "hort_event_chain_verify_overdue";

/// Boot-time liveness signal for the
/// `verify-event-chain` tamper-evidence run.
///
/// The event-chain verifier (`hort-server verify-event-chain`) is
/// correct crypto but ships CLI-only: nothing schedules it by default
/// and nothing alerts when it stops. That gap is closed by a
/// **default-disabled** `cronJobs.verifyEventChain` CronJob plus
/// this boot-emitted gauge. A deployment that never enabled the
/// CronJob — or enabled it and then it stopped — gets no tamper detection
/// and, without this signal, nothing would flag it.
///
/// The pure overdue/healthy decision lives in
/// [`hort_domain::policy::evaluate_event_chain_verify_liveness`] (zero-I/O,
/// 100%-tested), a deliberate parallel of the staging-sweep
/// predicate. This function is the thin composition-root shell that
/// supplies the wall-clock + the port-fetched last-completed timestamp,
/// then emits the gauge and a `warn!` on the overdue path — exactly
/// mirroring [`emit_staging_sweep_liveness_signal`].
///
/// **Placement rationale (boot-time emit, not a periodic loop).** A
/// periodic in-process re-check would itself be a `tokio::time`
/// scheduler (the scheduler-free
/// `hort-server` is load-bearing, ADR 0028). The gauge is set once at boot and
/// scraped continuously; Prometheus alerts on
/// `max_over_time(hort_event_chain_verify_overdue[…]) > 0`, the same
/// alarm shape `hort_staging_sweep_overdue` uses.
///
/// The gauge is emitted on **both** paths (`0.0` when healthy) so a fresh
/// scrape always sees the series. Never returns an error / never blocks
/// boot: a missing verify run is an operational concern to alarm on, not
/// a reason to refuse to start (the verifier is observability, not a
/// fail-closed control).
pub(crate) fn emit_event_chain_verify_liveness_signal(
    last_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    expected_interval: std::time::Duration,
    staleness_multiplier: u32,
) {
    use hort_domain::policy::{evaluate_event_chain_verify_liveness, EventChainVerifyLiveness};

    let liveness = evaluate_event_chain_verify_liveness(
        last_completed_at,
        now,
        expected_interval,
        staleness_multiplier,
    );

    match liveness {
        EventChainVerifyLiveness::Healthy { age_secs } => {
            tracing::debug!(
                age_secs,
                "event-chain verify liveness OK — a verify-event-chain run completed \
                 within the staleness window"
            );
            metrics::gauge!(EVENT_CHAIN_VERIFY_OVERDUE_METRIC).set(0.0);
        }
        EventChainVerifyLiveness::Overdue {
            age_secs,
            threshold_secs,
        } => {
            tracing::warn!(
                age_secs,
                threshold_secs,
                expected_interval_secs = expected_interval.as_secs(),
                staleness_multiplier,
                "event-chain verifier is OVERDUE — the most recent completed \
                 `verify-event-chain` run is older than the staleness window. \
                 Audit-log tamper detection is not running. Re-enable the \
                 `cronJobs.verifyEventChain` CronJob or run \
                 `hort-server verify-event-chain` out of band, and investigate why \
                 the scheduled run stopped."
            );
            metrics::gauge!(EVENT_CHAIN_VERIFY_OVERDUE_METRIC).set(1.0);
        }
        EventChainVerifyLiveness::NeverRan => {
            tracing::warn!(
                expected_interval_secs = expected_interval.as_secs(),
                staleness_multiplier,
                "event-chain verifier has NEVER completed on this deployment — the \
                 tamper-evidence verifier ships CLI-only and was likely never \
                 scheduled. Audit-log tamper detection is not running. Enable the \
                 `cronJobs.verifyEventChain` CronJob (default-disabled) or run \
                 `hort-server verify-event-chain` periodically."
            );
            metrics::gauge!(EVENT_CHAIN_VERIFY_OVERDUE_METRIC).set(1.0);
        }
    }
}

/// Structured boot-time **quarantine posture** verdict,
/// the value returned by [`evaluate_quarantine_posture`].
///
/// The out-of-the-box posture is
/// "quarantine-by-default" (ADR 0007): every ingest with no
/// matched operator `ScanPolicy` is held for
/// [`hort_domain::policy::scan::DefaultPolicy::quarantine_duration_secs`]
/// seconds. Two operator-controlled facts can narrow or widen that
/// posture and are worth surfacing once at boot so an operator
/// dashboard scrape can extract them without grepping the source:
///
/// - **Operator permissive overrides.** An operator `ScanPolicy` may set
///   `quarantineDuration: 0`, which is honoured as "no hold" (the
///   explicit-zero arm in `ingest_inner`).
///   This is a legitimate choice for an internal-only repo but worth
///   making visible: if an operator surveyed N repos and intended
///   quarantine-by-default on every one, a non-zero
///   `permissive_operator_policy_count` is a "did you mean to override
///   here?" cue.
/// - **Publish-time-trust opt-ins.** A `RepositoryUpstreamMapping` may
///   set `trust_upstream_publish_time = true`,
///   which narrows the quarantine window for an opted-in upstream by
///   anchoring on `min(upstream_published_at, ingested_at)` instead of
///   `ingested_at` alone. The count here is the "how many operators
///   opted in" signal — purely informational; the per-upstream opt-in
///   is the design's intended use.
///
/// **`default_quarantine_duration_secs` is always populated** — it is
/// the source of truth for the out-of-the-box hold and a const fn on
/// `DefaultPolicy`, but reporting it explicitly means the boot log
/// carries the full posture summary in one place rather than splitting
/// it across the source and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuarantinePosture {
    /// `DefaultPolicy::quarantine_duration_secs()` at boot — the
    /// duration applied to every fresh ingest in a repository with no
    /// matched operator `ScanPolicy`. Pinned at
    /// 86_400 (24 h).
    pub(crate) default_quarantine_duration_secs: i64,
    /// Number of active (non-archived) operator `ScanPolicy` rows whose
    /// `quarantine_duration_secs` is exactly `0` — the explicit
    /// permissive override (`warn!` when `> 0` so explicit-permissive
    /// overrides surface in dashboards alongside the quarantine-by-
    /// default posture).
    pub(crate) permissive_operator_policy_count: usize,
    /// Number of `RepositoryUpstreamMapping` rows with
    /// `trust_upstream_publish_time = true` — the per-upstream opt-in
    /// to publish-time anchoring. Purely
    /// informational at `info!` — opting in is the design's intended
    /// use, not a warn condition.
    pub(crate) trust_upstream_publish_time_count: usize,
}

/// Boot-time **quarantine posture** evaluator + log
/// emitter.
///
/// A single observability touch at
/// boot: a structured log line reporting the resolved
/// quarantine-by-default posture so an operator dashboard scrape can
/// surface (a) the `DefaultPolicy` window value, (b) any explicit
/// permissive operator overrides, and (c) per-upstream publish-time
/// opt-ins — all without grepping the source.
///
/// **Quarantine-by-default wording is load-bearing** (ADR 0007). The log
/// line reports the resolved window unconditionally (it is
/// always `> 0` for the Default — currently 86_400) and reserves the
/// `warn!` posture for the operator-policy-permissive override count.
/// "Quarantine disabled by default" or anything implying the Default is
/// permissive would contradict the quarantine-by-default posture.
///
/// **Counts come from existing port reads** — `list_active` /
/// `list_all` on the two projection ports — and an in-memory filter
/// pass: counting is `O(n)` over already-loaded `Vec`s, no new port
/// method, no port-contract change (`feedback_no_port_contract_changes`).
/// Typical deployments have O(10s) of `ScanPolicy` rows and O(10s) of
/// upstream-mapping rows, so this is bounded by config size and runs
/// once at boot.
///
/// **No new metric** — the startup
/// `info!`/`warn!` is the entire observability surface here.
/// This helper deliberately does NOT emit `metrics::gauge!` /
/// `counter!`; the structured log is the only sink.
///
/// Mirrors the `pub(crate)` + structured-verdict shape of
/// [`evaluate_test_clock_guard`] so unit tests assert the verdict
/// without standing up the full composition path (no Postgres pool, no
/// HTTP wiring). The helper is **infallible** — a misconfiguration here
/// is a permissive-posture observation, not a boot blocker; refusing to
/// start because an operator opted out of quarantine on one repo would
/// be a worse outcome than reporting the posture.
pub(crate) fn evaluate_quarantine_posture(
    scan_policies: &[hort_domain::entities::scan_policy::ScanPolicyProjection],
    upstream_mappings: &[hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping],
) -> QuarantinePosture {
    let default_quarantine_duration_secs =
        hort_domain::policy::scan::DefaultPolicy::quarantine_duration_secs();

    // The `archived` rows survive in the projection (the reactivation
    // path) but are not active policy and would skew the count; filter
    // them out so the surfaced number matches what `ingest_inner`
    // actually consults at match-time.
    let permissive_operator_policy_count = scan_policies
        .iter()
        .filter(|p| !p.archived && p.quarantine_duration_secs == 0)
        .count();

    let trust_upstream_publish_time_count = upstream_mappings
        .iter()
        .filter(|m| m.trust_upstream_publish_time)
        .count();

    let posture = QuarantinePosture {
        default_quarantine_duration_secs,
        permissive_operator_policy_count,
        trust_upstream_publish_time_count,
    };

    if posture.permissive_operator_policy_count > 0 {
        tracing::warn!(
            default_quarantine_duration_secs = posture.default_quarantine_duration_secs,
            permissive_operator_policy_count = posture.permissive_operator_policy_count,
            trust_upstream_publish_time_count = posture.trust_upstream_publish_time_count,
            "quarantine posture: out-of-the-box ingest is quarantined by default for \
             default_quarantine_duration_secs seconds. \
             permissive_operator_policy_count operator ScanPolicy rows set \
             quarantineDuration=0 (explicit permissive override — legitimate for \
             internal-only repos but worth flagging in dashboards). \
             trust_upstream_publish_time_count upstream mappings have opted in to \
             publish-time anchoring."
        );
    } else {
        tracing::info!(
            default_quarantine_duration_secs = posture.default_quarantine_duration_secs,
            permissive_operator_policy_count = posture.permissive_operator_policy_count,
            trust_upstream_publish_time_count = posture.trust_upstream_publish_time_count,
            "quarantine posture: out-of-the-box ingest is quarantined by default for \
             default_quarantine_duration_secs seconds. No operator \
             ScanPolicy currently overrides to permissive (quarantineDuration=0). \
             trust_upstream_publish_time_count upstream mappings have opted in to \
             publish-time anchoring."
        );
    }

    posture
}

/// Metric name for the boot-time extra-CA outcome counter.
/// Allowed `result` label values are exactly the three
/// constants below — the catalog entry in `docs/metrics-catalog.md`
/// pins the bounded enum.
const EXTRA_CA_LOAD_METRIC: &str = "hort_extra_ca_load_total";
const EXTRA_CA_LOAD_RESULT_OK: &str = "ok";
const EXTRA_CA_LOAD_RESULT_UNREADABLE: &str = "unreadable";
const EXTRA_CA_LOAD_RESULT_PARSE_FAILED: &str = "parse_failed";

/// Metric name for the trust-anchor count gauge.
/// Set to 0 when the bundle is not configured, N when N
/// anchors loaded successfully. Not set on a load failure: the boot
/// path bails before this point and the counter's `unreadable` /
/// `parse_failed` label carries the signal.
const EXTRA_CA_ANCHORS_METRIC: &str = "hort_extra_ca_anchors";

/// Read and parse the `HORT_EXTRA_CA_BUNDLE` environment variable.
///
/// Returns:
/// - `Ok(None)` — env var is unset (debug-log the no-op).
/// - `Ok(Some(_))` — env var is set, file is readable, PEM parses to ≥1 cert.
/// - `Err(ConfigError::ExtraCaUnreadable { .. })` — set but file unreadable.
/// - `Err(ConfigError::ExtraCaParse { .. })` — set, readable, but PEM invalid
///   or contains zero certificate blocks.
///
/// Called once by [`build_app_context`] at startup. Logging is done here
/// (not in the parser) per the `hort-config` charter (zero-I/O, no tracing).
///
/// **Observability.** Three emission points:
///
/// - `hort_extra_ca_anchors` (gauge, labels: none) — set to the loaded
///   anchor count on success, set to 0 on the unset path. Not set on
///   error paths (the load bails before this point and the counter
///   below carries the signal).
/// - `hort_extra_ca_load_total{result="ok"|"unreadable"|"parse_failed"}`
///   (counter) — fires exactly once per call. `ok` covers both the
///   "anchors loaded" and "env unset" outcomes (the gauge differentiates
///   them); `unreadable` covers `fs::read` failures; `parse_failed`
///   covers PEM-parse failures.
///
/// See `docs/metrics-catalog.md` for the bounded-enum contract.
pub(crate) fn read_extra_ca_bundle() -> Result<Option<ExtraTrustAnchors>, ConfigError> {
    const VAR: &str = "HORT_EXTRA_CA_BUNDLE";

    let path_str = match std::env::var(VAR) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            tracing::debug!("extra CA bundle: not configured");
            // Emit the boot heartbeat even on the unset
            // path so dashboards can rate-limit "no boot signal" alerts.
            // Gauge → 0 (anchors not loaded); counter → ok (boot
            // succeeded with no bundle).
            metrics::gauge!(EXTRA_CA_ANCHORS_METRIC).set(0.0);
            metrics::counter!(EXTRA_CA_LOAD_METRIC, "result" => EXTRA_CA_LOAD_RESULT_OK)
                .increment(1);
            return Ok(None);
        }
    };

    let pem_bytes = match std::fs::read(&path_str) {
        Ok(bytes) => bytes,
        Err(source) => {
            // Failure-path counter. Gauge intentionally
            // not touched — the previous value (if any) stays put; the
            // counter is the failure signal.
            metrics::counter!(EXTRA_CA_LOAD_METRIC, "result" => EXTRA_CA_LOAD_RESULT_UNREADABLE)
                .increment(1);
            return Err(ConfigError::ExtraCaUnreadable {
                path: path_str,
                source,
            });
        }
    };

    let anchors = match ExtraTrustAnchors::parse_pem(&pem_bytes) {
        Ok(a) => a,
        Err(source) => {
            // Failure-path counter. Same rationale as
            // unreadable above.
            metrics::counter!(EXTRA_CA_LOAD_METRIC, "result" => EXTRA_CA_LOAD_RESULT_PARSE_FAILED)
                .increment(1);
            return Err(ConfigError::ExtraCaParse {
                path: path_str,
                source,
            });
        }
    };

    let p = std::path::Path::new(&path_str);
    let n = anchors.cert_count();
    tracing::info!(path = %p.display(), count = n, "extra CA bundle loaded");

    // Success-path gauge + counter. Order is gauge-then-
    // counter so a scrape interleaving the boot sequence sees the
    // anchor count BEFORE the heartbeat tick (a counter without a
    // matching gauge update would be a transient inconsistency in
    // dashboards).
    metrics::gauge!(EXTRA_CA_ANCHORS_METRIC).set(n as f64);
    metrics::counter!(EXTRA_CA_LOAD_METRIC, "result" => EXTRA_CA_LOAD_RESULT_OK).increment(1);

    Ok(Some(anchors))
}

/// Derive the `(issuer, audience)` pair the
/// OCI `/v2/auth` use case mints JWTs with, from `HORT_PUBLIC_BASE_URL`.
///
/// **Boot-fail conditions:**
/// - `public_base_url = None` → [`ConfigError::OciPublicBaseUrlMissing`].
/// - `public_base_url = Some(url)` whose `host_str()` is empty (no
///   hostname component, e.g. a `data:` URL) → a defensive
///   [`ConfigError::OciPublicBaseUrlMissing`] (same variant; the doc
///   string explains both modes).
///
/// On success, returns `(issuer, audience)`:
/// - `issuer` = `<url>/v2/auth` with any trailing slash trimmed off the
///   base.
/// - `audience` = the URL's host component (no scheme, no port — just
///   the hostname Distribution-Spec clients echo as the `service=` query
///   parameter).
///
/// Pulled out of `build_app_context` as a standalone helper so the
/// boot-fail path is unit-testable without a real Postgres pool.
fn derive_oci_token_endpoint_strings(
    public_base_url: Option<&url::Url>,
) -> Result<(String, String), ConfigError> {
    let url = public_base_url.ok_or(ConfigError::OciPublicBaseUrlMissing)?;
    let host_str = url
        .host_str()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::OciPublicBaseUrlMissing)?
        .to_string();
    let trimmed = url.as_str().trim_end_matches('/');
    let issuer = format!("{trimmed}/v2/auth");
    Ok((issuer, host_str))
}

/// Resolve a per-class Redis URL via the
/// fallback chain. Returns the per-class override when set, otherwise
/// the main `HORT_REDIS_URL` fallback, otherwise
/// [`ConfigError::MissingRedisUrl`] naming the per-class env var the
/// operator failed to set.
///
/// Called only from inside the `EphemeralStoreBackend::Redis` arm —
/// the Memory branch never consults `redis_url*` and never invokes
/// this helper.
fn resolve_redis_url<'a>(
    primary: Option<&'a String>,
    fallback: Option<&'a String>,
    var_name: &'static str,
) -> Result<&'a str, ConfigError> {
    primary
        .or(fallback)
        .map(String::as_str)
        .ok_or(ConfigError::MissingRedisUrl(var_name))
}

/// Short hex prefix of the SHA-256 digest of a
/// Redis URL, used as the `url_hash` field on the per-class startup
/// `tracing::info!` line. Operators correlating "two log lines, same
/// `url_hash`" can detect single-Redis topology without the URL (which
/// carries credentials) appearing anywhere in logs.
///
/// 8 hex characters (32 bits) — collision-resistant enough for a
/// human-eyeball topology check; the URL itself is the source of
/// truth, not the hash.
fn url_hash(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(url.as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// Outputs of [`build_ephemeral_stores`].
///
/// Bundles the two `Arc<dyn EphemeralStore>` slots plus the optional
/// `(evictable_hash, durable_hash)` pair used to render the per-class
/// startup `tracing::info!` lines. The Memory arm leaves
/// `url_hashes = None` (no URLs); the Redis arm always populates it.
struct EphemeralStores {
    evictable: Arc<dyn EphemeralStore>,
    durable: Arc<dyn EphemeralStore>,
    url_hashes: Option<(String, String)>,
}

/// Construct the per-class `EphemeralStore`
/// slots per the keyspace-routing topology rules. Pulled out of
/// `build_app_context` as a standalone helper so the per-arm logic
/// (Memory always-distinct vs. Redis with URL-equality branching) is
/// individually inspectable.
async fn build_ephemeral_stores(
    backend: crate::config::EphemeralStoreBackend,
    redis_url: Option<&String>,
    redis_url_evictable: Option<&String>,
    redis_url_durable: Option<&String>,
) -> DomainResult<EphemeralStores> {
    use hort_app::ephemeral_keyspace::EphemeralKeyspaceClass;
    match backend {
        crate::config::EphemeralStoreBackend::Memory => {
            let evictable: Arc<dyn EphemeralStore> = Arc::new(MeteredMemEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Evictable,
            ));
            let durable: Arc<dyn EphemeralStore> = Arc::new(MeteredMemEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            ));
            Ok(EphemeralStores {
                evictable,
                durable,
                url_hashes: None,
            })
        }
        crate::config::EphemeralStoreBackend::Redis => {
            let evictable_url =
                resolve_redis_url(redis_url_evictable, redis_url, "HORT_REDIS_URL_EVICTABLE")
                    .map_err(|e| hort_domain::error::DomainError::Invariant(e.to_string()))?;
            let durable_url =
                resolve_redis_url(redis_url_durable, redis_url, "HORT_REDIS_URL_DURABLE")
                    .map_err(|e| hort_domain::error::DomainError::Invariant(e.to_string()))?;
            let evictable_hash = url_hash(evictable_url);
            let durable_hash = url_hash(durable_url);
            let (evictable, durable) = if evictable_url == durable_url {
                // Single-Redis topology: one connection, two
                // class-labelled wrappers sharing the same
                // `Arc<RedisEphemeralStore>`. Metric series remain
                // split by class label; no double connection.
                let inner = Arc::new(RedisEphemeralStore::connect(evictable_url).await?);
                let evictable: Arc<dyn EphemeralStore> = Arc::new(MeteredRedisEphemeralStore::new(
                    inner.clone(),
                    EphemeralKeyspaceClass::Evictable,
                ));
                let durable: Arc<dyn EphemeralStore> = Arc::new(MeteredRedisEphemeralStore::new(
                    inner,
                    EphemeralKeyspaceClass::Durable,
                ));
                (evictable, durable)
            } else {
                // Distinct Redis targets — two `connect` calls, two
                // `Arc`s, two wrappers.
                let evictable_inner = Arc::new(RedisEphemeralStore::connect(evictable_url).await?);
                let durable_inner = Arc::new(RedisEphemeralStore::connect(durable_url).await?);
                let evictable: Arc<dyn EphemeralStore> = Arc::new(MeteredRedisEphemeralStore::new(
                    evictable_inner,
                    EphemeralKeyspaceClass::Evictable,
                ));
                let durable: Arc<dyn EphemeralStore> = Arc::new(MeteredRedisEphemeralStore::new(
                    durable_inner,
                    EphemeralKeyspaceClass::Durable,
                ));
                (evictable, durable)
            };
            Ok(EphemeralStores {
                evictable,
                durable,
                url_hashes: Some((evictable_hash, durable_hash)),
            })
        }
    }
}

/// Wire all adapters and use cases together.
///
/// Async and fallible because `PgEventStore::new()` verifies the
/// immutability trigger on the `events` table at startup.
///
/// `metrics_handle` is supplied by the caller rather than constructed here
/// so the library layer contains no global state. Production (`main.rs`)
/// installs a recorder globally via
/// `PrometheusBuilder::new().install_recorder()?` and passes the returned
/// handle. Tests construct a recorder via
/// `PrometheusBuilder::new().build_recorder()` and scope it via
/// `metrics::with_local_recorder` so parallel tests do not cross-contaminate
/// a shared global recorder.
///
/// `include_repository_label` mirrors the `METRICS_INCLUDE_REPOSITORY_LABEL`
/// environment variable. When false, use cases emit the `_all` sentinel
/// repository label. See ADR 0017 + `docs/metrics-catalog.md`
/// for the cardinality rationale.
///
/// 1. Creates Postgres adapter implementations of each port trait
/// 2. Wraps them in `Arc` for shared ownership
/// 3. Injects them into the use case constructors
/// 4. Returns the fully-wired [`BuildAppContextOutput`] —
///    `AppContext` plus auxiliary concrete handles the composition
///    root needs to keep alive (currently just the
///    `CachingResolver` for the upstream-resolver refresh task).
#[allow(clippy::too_many_arguments)]
pub async fn build_app_context(
    db: PgPool,
    storage: Arc<dyn StoragePort>,
    // Raw upstream-metadata mirror (ADR 0026), built by the caller
    // (`cli::serve`) from the SAME `StorageConfig` the CAS `storage` above
    // was built from (`storage::build_with_mirror`, which shares one S3
    // backend between the two adapters). Threaded in as a
    // parameter rather than reconstructed here because composition owns the
    // parse and `build_app_context` only receives the type-erased
    // `Arc<dyn StoragePort>`, not the backend config (mirrors the `storage`
    // wiring — the parse is not duplicated).
    metadata_mirror: Arc<dyn MetadataMirrorStore>,
    metrics_handle: PrometheusHandle,
    include_repository_label: bool,
    // Sibling toggle for the per-SA label on
    // `hort_rotation_lag_seconds` AND `hort_service_account_authenticated_total`.
    // Threaded onto `AppContext.include_service_account_label` and read by
    // the federation branch on `/auth/token-exchange` + the PAT-auth path.
    include_service_account_label: bool,
    metadata_caps: HashMap<String, usize>,
    metadata_blob_max_bytes: usize,
    // Per-fetch-class storage backstops (ADR 0026) threaded
    // from `Config` (`HORT_UPSTREAM_{METADATA,MANIFEST}_CACHE_MAX_SIZE`)
    // into the upstream-HTTP adapter config below.
    upstream_metadata_cache_max_bytes: u64,
    upstream_manifest_cache_max_bytes: u64,
    upstream_projector_version_object_max_bytes: u64,
    public_base_url: Option<url::Url>,
    trust_config: hort_http_core::middleware::trust::TrustConfig,
    rate_limit_config: hort_http_core::middleware::rate_limit::RateLimitConfig,
    // Workspace-wide + per-IP concurrency
    // caps. Threaded onto `AppContext.concurrency_limit_config`;
    // `wrap_with_middleware` instantiates the shared
    // `ConcurrencyLimitState` from this config and attaches both
    // load-shed layers.
    concurrency_limit_config: hort_http_core::middleware::load_shed::ConcurrencyLimitConfig,
    // Per-request deadline durations
    // threaded onto `AppContext.http_timeout_config`. Both
    // `wrap_with_middleware` (non-OCI default) and
    // `oci_routes_with_config` (OCI upload override) read these.
    http_timeout_config: hort_http_core::middleware::request_timeout::HttpTimeoutConfig,
    publish_body_limit_bytes: Option<usize>,
    idp: Option<Arc<dyn IdentityProvider>>,
    // `claim_mappings` (ADR 0012) is consumed by
    // `AuthenticateUseCase::new`. The OIDC / CLI-session principal
    // build resolves `principal.claims` from `claims.groups` against
    // this snapshot (`hort-app::rbac::resolve_claims`).
    claim_mappings: Vec<ClaimMapping>,
    // The additive-claims evaluator (ADR 0012) is built from a flat
    // `Vec<PermissionGrant>` (`RbacEvaluator::new(grants)`). There is
    // no `RoleRepository` (roles + role-keyed grant index);
    // the grant set is sourced via `PermissionGrantRepository::
    // list_all` here and refreshed by the rbac live-refresh task.
    permission_grant_repo: Arc<dyn PermissionGrantRepository>,
    auth_enabled: bool,
    // OIDC issuer URL threaded down
    // from `cfg.auth` (`AuthConfig::Oidc(o).issuer_url`). `Some(_)`
    // when `auth_enabled = true`; `None` under `AuthConfig::Disabled`
    // (the value is unused in that branch). Stored on
    // `AuthContext::Enabled.issuer_url` and consumed by
    // `hort_http_core::middleware::auth::www_authenticate_for` to render
    // the `Bearer realm="<issuer-url>"` challenge on 401 responses.
    oidc_issuer_url: Option<String>,
    // Filesystem root for stateful-upload staging (OCI three-phase blob
    // upload, Maven chunked PUT, Git LFS batch transfer in later items).
    // Distinct from the CAS storage root — staging bytes are pre-hash
    // scratch space and must never share a directory tree with content-
    // addressed artifacts (see `filesystem_stateful_upload_staging.rs`
    // module docs). Threaded in from
    // `hort_server::Config::stateful_upload_staging_dir`
    // (`HORT_STATEFUL_UPLOAD_STAGING_DIR`).
    stateful_upload_staging_dir: std::path::PathBuf,
    // `EphemeralStore` backend selector +
    // optional Redis URL. Threaded in from
    // `hort_server::Config::ephemeral_store_backend` /
    // `hort_server::Config::redis_url`. The composition root picks the
    // adapter, wraps it in the production metrics wrapper, and hands
    // it to `AppContext.ephemeral`. The memory adapter's background
    // evictor spawns inside its constructor — no additional
    // orchestration at this layer.
    ephemeral_store_backend: crate::config::EphemeralStoreBackend,
    redis_url: Option<String>,
    // Per-class Redis URL overrides. Both
    // optional; unset → falls back to `redis_url`. Resolution runs
    // ONLY on the Redis branch (the Memory branch never consults
    // these).
    redis_url_evictable: Option<String>,
    redis_url_durable: Option<String>,
    // Pull-through deduplication config built by
    // the caller (`cli::serve`) from the five `HORT_PULL_DEDUP_*` env vars
    // on `Config`. Threaded into `PullDedup::new` after
    // `build_ephemeral_stores` returns. Composition is the consumer of
    // parsed config, never the parser.
    pull_dedup_config: PullDedupConfig,
    // Extra CA trust bundle (ADR 0010) parsed by the caller
    // (cli::serve or cli::scrub) BEFORE storage construction so the same
    // value can be fed to both storage::build and this function without
    // double-parsing. Composition owns the parse; adapters
    // receive the value directly, never via AppContext.extra_trust_anchors.
    extra_trust_anchors: Option<ExtraTrustAnchors>,
    // The
    // event store is constructed by the caller exactly once and
    // shared with both the OIDC provider's audit pathway AND the
    // use cases below. This avoids the double-construction code
    // smell of two independent
    // `PgEventStore` instances against the same pool — one extra
    // immutability-trigger probe at startup, one extra trait object
    // to keep alive, and a misleading look at the boot path. Typed
    // as the concrete `Arc<PgEventStore>` (not `Arc<dyn EventStore>`)
    // because the per-Pg-adapter lifecycle constructors
    // (`PgRefLifecycle::new`, `PgArtifactLifecycle::new`,
    // `PgArtifactGroupLifecycle::new`) require the concrete type for
    // their unit-of-work plumbing; the use-case construction sites
    // implicitly coerce `Arc<PgEventStore>` to `Arc<dyn EventStore>`
    // via Rust's unsized coercion at the call boundary, so no
    // narrowing helper is needed. composition.rs is already entangled
    // with every Pg adapter type — this is the right place for that
    // coupling, not deeper in the call graph.
    event_store: Arc<hort_adapters_postgres::event_store::PgEventStore>,
    // Native API token wiring (ADR 0012). When
    // `enabled = false` (default), the PAT branch is OFF: no cache,
    // no validator, no listener. When `true`, builds the `PatCache`,
    // wires the `PatValidationUseCase` onto `AuthenticateUseCase`,
    // and spawns the `api_token_revocation` PgListener.
    native_token_config: NativeTokenConfig,
    // Pre-rendered client-bootstrap config (ADR 0013)
    // for `GET /.well-known/hort-client-config`. `Some(_)` when the
    // caller has set `HORT_TOKEN_EXCHANGE_ENABLED=true`, the OIDC
    // issuer + cli_client_id are configured, and `public_base_url` is
    // set; the caller (`cli::serve`) builds it from `cfg` before
    // calling. `None` when the feature is off; the discovery route is
    // not mounted in that case, so the field is never read.
    // Composition trusts the boot-time fail-closed validation in
    // `hort-server::config` to guarantee non-empty fields whenever the
    // value is `Some(_)`.
    client_config: Option<hort_http_core::handlers::well_known::ClientBootstrapConfig>,
    // Event-notification substrate config.
    // `enable_notifications=true` wraps the event store in an
    // [`EventStorePublisher`] backed by a
    // `tokio::sync::broadcast::Sender` of capacity
    // `notify_channel_capacity`. The dispatcher subscribes to
    // the sender; until then the channel has no consumers and `send`
    // returns `Err(SendError)` which the publisher silently drops.
    // `enable_notifications=false` constructs the publisher with no
    // broadcast channel — every append is a transparent pass-through.
    notify_config: NotifyConfig,
) -> DomainResult<BuildAppContextOutput> {
    // Wrap the event store in an
    // `EventStorePublisher`. The publisher impls `EventStore`, so use
    // cases keep their `Arc<EventStorePublisher>` field shape, and the
    // call sites (`self.events.append(...)`, `self.events.read_*(...)`)
    // continue to resolve through the same trait dispatch. The
    // Pg-specific lifecycle adapters
    // (`PgRefLifecycle`, `PgArtifactLifecycle`,
    // `PgArtifactGroupLifecycle`) still hold the concrete
    // `Arc<PgEventStore>` directly because they need the
    // `begin_unit_of_work` Postgres-specific surface that does NOT
    // live on the `EventStore` port. Lifecycle appends therefore do
    // NOT broadcast (intentional — the dispatcher subscribes once per
    // process and the broadcast hook exists at the per-use-case
    // `EventStore::append` boundary;
    // lifecycle ports own their own transactional append paths and
    // surface persisted events back to callers via `AppendResult` which
    // the use cases re-emit through the publisher when they need
    // notification fan-out — see the design rationale in
    // `docs/architecture/explanation/event-notifications.md`).
    let event_publisher: Arc<EventStorePublisher> = if notify_config.enabled {
        let (sender, _initial_receiver) =
            tokio::sync::broadcast::channel(notify_config.channel_capacity as usize);
        // The initial receiver is dropped immediately — the
        // dispatcher creates its own subscription via
        // `publisher.subscribe()` at task spawn time. Without dropping
        // the initial receiver here, the broadcast channel would never
        // signal SendError(no_receivers) and the publisher's silent-drop
        // contract would be untestable in a single-thread harness.
        drop(_initial_receiver);
        Arc::new(EventStorePublisher::new(event_store.clone(), sender))
    } else {
        Arc::new(EventStorePublisher::without_broadcast(event_store.clone()))
    };

    let repo_repo = Arc::new(PgRepositoryRepository::new(db.clone()));
    let artifact_repo = Arc::new(PgArtifactRepository::new(db.clone()));
    let artifact_metadata_repo = Arc::new(PgArtifactMetadataRepository::new(db.clone()));
    let user_repo = Arc::new(PgUserRepository::new(db.clone()));
    // `PgApiTokenRepository` adapter. Always
    // constructed (cheap pool clone) so admin-side `revoke` /
    // `list_for_user` calls work even when `HORT_NATIVE_TOKENS_ENABLED`
    // is off; the validator branch is what's gated, not the storage
    // surface.
    let api_token_repo: Arc<dyn ApiTokenRepository> =
        Arc::new(hort_adapters_postgres::api_token_repo::PgApiTokenRepository::new(db.clone()));

    // Mutable-ref read + write adapters. Read
    // port is `Arc<dyn RefRegistryPort>` (shares the pool); write port
    // is `Arc<dyn RefLifecyclePort>` (routes through PgEventStore's
    // begin_unit_of_work — no separate pool handle needed).
    let ref_registry: Arc<dyn RefRegistryPort> = Arc::new(PgRefRegistry::new(db.clone()));
    let ref_lifecycle: Arc<dyn RefLifecyclePort> =
        Arc::new(PgRefLifecycle::new(event_store.clone()));
    // Artifact-group read + write adapters.
    // Same shape as the ref adapters above.
    let artifact_group_repo: Arc<dyn ArtifactGroupRepository> =
        Arc::new(PgArtifactGroupRepository::new(db.clone()));
    let artifact_group_lifecycle: Arc<dyn ArtifactGroupLifecyclePort> =
        Arc::new(PgArtifactGroupLifecycle::new(event_store.clone()));

    // Format-agnostic stateful-upload staging
    // (filesystem). Upload session state lives in the EphemeralStore
    // below; only the chunk payloads land on
    // the filesystem under `stateful_upload_staging_dir`.
    //
    // Binary fail-loud gate. "Wired unconditionally; an unhealthy
    // adapter does NOT block startup — handlers surface misconfiguration
    // as request-time errors" is the
    // *silent-degradation* anti-pattern: under the chart's S3
    // defaults + `readOnlyRootFilesystem: true`, a staging root on
    // the read-only rootfs would only `warn!` in `new()` while every
    // `append()` "retried" forever — OCI `docker push` / Git LFS
    // non-functional with NO readiness signal. The chart sets a
    // writable staging dir;
    // the binary additionally fails LOUD so the *next* such gap (any
    // deployment whose staging root is non-writable) is a fatal boot
    // condition (the pod never enters the Service), not a silent 5xx.
    //
    // Mechanism mirrors the `KubernetesSecretWriterImpl::try_in_cluster()`
    // fatal-boot precedent below: construct the
    // concrete adapter, run an inherent fail-loud probe, `error!` once +
    // `return Err` on failure. `verify_writable_and_ownable()` is an
    // *inherent* method on the concrete adapter, NOT a
    // `StatefulUploadStagingPort` trait method — the port signature is
    // unchanged. The per-`append()`
    // `warn!` in the adapter stays as transient-case defense-in-depth
    // (a root that goes bad *after* a healthy boot); this gate is the
    // boot-time fail-loud addition.
    //
    // Capability-gated: the gate is active iff a stateful-upload-
    // capable format/route is enabled. In the `hort-server` binary the
    // OCI Distribution router (`hort_http_oci::oci_routes_with_config`,
    // the canonical StatefulUpload capability — OCI chunked blob upload
    // + Git LFS) is merged UNCONDITIONALLY in `http::build_router_with_oci_config`;
    // there is no format/OCI disable knob (OCI/Git LFS are Tier C
    // compiled-in adapters, always present). So this boolean is a
    // structural constant `true` for this binary — the gate is always
    // active here. The named seam is kept (not hardcoded inline) so a
    // future format-disable knob can make this honestly conditional
    // without re-deriving the reasoning; today there is no
    // deployment where stateful upload is unreachable, so failing the
    // gate on an unusable root never penalises a deployment that would
    // never use it.
    const STATEFUL_UPLOAD_FORMATS_ENABLED: bool = true;
    let stateful_upload_staging_adapter =
        FilesystemStatefulUploadStaging::new(stateful_upload_staging_dir.clone());
    if STATEFUL_UPLOAD_FORMATS_ENABLED {
        if let Err(err) = stateful_upload_staging_adapter
            .verify_writable_and_ownable()
            .await
        {
            // Logged ONCE here at the gate (not per-`append()`), with
            // the staging root + the io-error kind carried in `err`'s
            // message. Deliberately NO session id / UUID anywhere —
            // session-id enumeration is an information leak,
            // and a cardinality hazard.
            tracing::error!(
                staging_root = %stateful_upload_staging_dir.display(),
                error = %err,
                "stateful-upload staging root is not writable/ownable — \
                 refusing to boot. Chunked upload (OCI `docker push`, \
                 Git LFS) would be silently non-functional. Point \
                 HORT_STATEFUL_UPLOAD_STAGING_DIR at a writable, \
                 owner-restrictable path (the Helm chart sets this to a \
                 writable emptyDir subdir)"
            );
            return Err(err);
        }
    }
    let stateful_upload_staging: Arc<dyn StatefulUploadStagingPort> =
        Arc::new(stateful_upload_staging_adapter);

    // Construct two `EphemeralStore` slots,
    // one per operational class (evictable / durable). The Memory
    // branch always builds two distinct `InMemoryEphemeralStore`
    // instances regardless of any other configuration (preserves the
    // keyspace-isolation invariant in tests). The Redis branch
    // resolves both class URLs via `resolve_redis_url`; when the URLs
    // are equal (the dominant single-Redis case) we construct ONE
    // `RedisEphemeralStore::connect`, wrap it in an `Arc`, and hand
    // that single `Arc` to two class-labelled wrappers — one
    // connection pool, two metric label sets. When the URLs differ,
    // two separate connect calls.
    //
    // `composition.rs` does NOT reach into adapter internals — the
    // memory adapter's evictor task spawns inside its own constructor.
    let ephemeral_stores = build_ephemeral_stores(
        ephemeral_store_backend,
        redis_url.as_ref(),
        redis_url_evictable.as_ref(),
        redis_url_durable.as_ref(),
    )
    .await?;
    let ephemeral_evictable = ephemeral_stores.evictable;
    let ephemeral_durable = ephemeral_stores.durable;
    let ephemeral_url_hashes = ephemeral_stores.url_hashes;

    // Pull-through deduplication service. Built
    // ONCE here and threaded onto `AppContext.pull_dedup`; format crates
    // (`hort-http-cargo`, `hort-http-pypi`, `hort-http-npm`, `hort-http-oci`)
    // wrap their `UpstreamProxy::*` calls in the `PullDedup`
    // closure-coalescing API. The `pulldedup:` keyspace is registered
    // as `EphemeralKeyspaceClass::Evictable` — which is
    // why we hand `ephemeral_evictable` (NOT `ephemeral_durable`) into
    // `PullDedup::new`.
    let pull_dedup = Arc::new(PullDedup::new(
        ephemeral_evictable.clone(),
        pull_dedup_config.clone(),
    ));
    // Content-reference projection (generalizes
    // the OCI Referrers index). First caller is the OCI
    // Referrers API (`kind = "oci_subject"`); future SBOM / provenance
    // callers reuse the table with a different `kind`. Wired
    // unconditionally — the Phase 1 read surface doesn't touch this
    // adapter, so an unhealthy one doesn't block startup.
    let content_references: Arc<dyn ContentReferenceIndex> =
        Arc::new(PgContentReferenceRepo::new(db.clone()));

    // Per-repo upstream mapping CRUD. Generic;
    // first consumer is OCI multi-upstream mirroring.
    let repository_upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository> =
        Arc::new(PgRepositoryUpstreamMappingRepo::new(db.clone()));

    // Upstream packument / simple-index
    // cache invalidator. Constructed once here and threaded into all
    // three `ArtifactRejected` emitter use cases (CurationUseCase,
    // QuarantineUseCase, ApplyConfigUseCase) via their
    // `with_upstream_index_cache_invalidator` builder methods. Holds
    // `repo_repo` (for `RepositoryFormat`), `repository_upstream_mappings`
    // (for `list_for_repository`), and `ephemeral_evictable` (all three
    // target keyspaces — `npm_packument_proj:` / `pypi_simple_proj:` /
    // `cargo_index_proj:` — are classified `Evictable`).
    let upstream_index_cache_invalidator: Arc<dyn UpstreamIndexCacheInvalidator> =
        Arc::new(AppUpstreamIndexCacheInvalidator::new(
            repo_repo.clone(),
            repository_upstream_mappings.clone(),
            ephemeral_evictable.clone(),
        ));

    // Upstream resolver. Built with an empty
    // snapshot here; the background refresh task spawned in
    // `cli::serve` primes the cache on its first tick. The
    // resolver impl lives in `hort-adapters-upstream-http`; we hold it
    // as `Arc<dyn UpstreamResolver>` to keep `AppContext` format-agnostic.
    // The concrete `Arc<CachingResolver>` is also returned so the
    // refresh task can call `reload` on it without a downcast — done
    // via a separate handle threaded into `cli::serve`.
    let caching_resolver = Arc::new(hort_adapters_upstream_http::CachingResolver::new());
    let upstream_resolver: Arc<dyn UpstreamResolver> = caching_resolver.clone();

    // Operator-wired secret resolution. Both adapters
    // always wired; the SecretRef.source field selects which adapter
    // handles a given resolution. Anonymous mappings (secret_ref = None)
    // short-circuit before reaching the SecretPort. There is no
    // process-wide HORT_SECRETS_PROVIDER selector — operators wire their
    // preferred secret-sync mechanism and hort reads the resulting env
    // vars or mounted files. See docs/architecture/how-to/wire-secrets.md
    // for operator examples.
    //
    // Optional containment root.
    // When `HORT_SECRETS_FILE_ROOT` is set, the file adapter rejects any
    // secret_ref whose canonical path falls outside the root —
    // symlink-escape protection. Unset → legacy unconstrained
    // behaviour. The env var is read here at the composition root so
    // the rest of the binary stays generic over `SecretPort`.
    let secrets_file_root: Option<std::path::PathBuf> =
        match std::env::var("HORT_SECRETS_FILE_ROOT") {
            Ok(s) if !s.is_empty() => Some(std::path::PathBuf::from(s)),
            _ => None,
        };
    if let Some(root) = secrets_file_root.as_ref() {
        tracing::info!(
            secrets_file_root = %root.display(),
            "HORT_SECRETS_FILE_ROOT configured — mounted-file adapter will enforce \
             containment (paths whose canonical form escapes this root will be rejected)",
        );
    }
    let secret_port: Arc<dyn SecretPort> = Arc::new(hort_adapters_secrets::DispatchSecretPort {
        env: Arc::new(hort_adapters_secrets::EnvVarSecretAdapter),
        file: Arc::new(
            hort_adapters_secrets::MountedFileSecretAdapter::new_with_root(secrets_file_root),
        ),
    });
    tracing::info!(
        "secret port wired with env+file dispatch (no in-tree Vault/CSI clients; \
         operators wire ESO/Vault Agent/CSI/etc. to env vars or mounted files)"
    );

    // Pull-through upstream proxy. Anonymous
    // and Docker Hub anonymous flows work out of the box; authenticated
    // (`Basic` / `BearerChallenge` with secret_ref) mappings resolve
    // their bytes through the SecretPort wired above on each fetch.
    //
    // Populate the extra CA bundle (ADR 0010) directly from
    // the local `Option<ExtraTrustAnchors>` parsed above. Composition
    // owns the parse; both `AppContext` and `HttpUpstreamProxyConfig` are
    // sinks fed from the same value. Do NOT read back through
    // `AppContext.extra_trust_anchors` — that would couple the adapter to
    // the inbound-HTTP shape, which is exactly what the layering forbids.
    let upstream_proxy_config = hort_adapters_upstream_http::HttpUpstreamProxyConfig {
        format_label: "oci".to_string(),
        extra_trust_anchors: extra_trust_anchors.clone(),
        // Thread the operator-tunable
        // storage backstops from `Config` so chart values control the
        // per-fetch-class caps. The default fallback (`Default`)
        // carries the pinned values, but composition is the explicit
        // wire-up site — never hide the cap behind `Default` once a
        // chart knob exists.
        metadata_cache_max_bytes: upstream_metadata_cache_max_bytes,
        manifest_cache_max_bytes: upstream_manifest_cache_max_bytes,
        // Outbound User-Agent: HORT_UPSTREAM_USER_AGENT or the built-in
        // default (crates.io rejects requests with no UA). Resolved by the
        // shared adapter helper so hort-server + hort-worker match.
        user_agent: hort_adapters_upstream_http::user_agent_from_env(),
        ..hort_adapters_upstream_http::HttpUpstreamProxyConfig::default()
    };
    let upstream_proxy: Arc<dyn UpstreamProxy> =
        Arc::new(hort_adapters_upstream_http::HttpUpstreamProxy::new(
            upstream_proxy_config,
            secret_port.clone(),
        )?);

    let repository_use_case = Arc::new(RepositoryUseCase::new(repo_repo.clone()));
    let user_use_case = Arc::new(UserUseCase::new(user_repo.clone()));
    let lifecycle = Arc::new(PgArtifactLifecycle::new(
        event_store.clone(),
        artifact_repo.clone(),
        artifact_metadata_repo.clone(),
    ));
    // Policy projection adapter shared
    // between `PolicyUseCase` and `QuarantineUseCase`.
    // Cheap pool clone; the pool
    // itself governs connection lifecycle.
    let policy_projections: Arc<dyn PolicyProjectionRepository> =
        Arc::new(PgPolicyProjectionRepository::new(db.clone()));
    // `repo_security_scores` projection
    // adapter. Read-only surface from the inbound HTTP perspective
    // (the lifecycle dual-write path uses the adapter-internal
    // `apply_delta_in_tx` helper rather than this trait); here we
    // wire the trait-object handle for the `SecurityScoreUseCase`.
    // Cheap pool clone.
    let security_scores: Arc<dyn RepoSecurityScoreRepository> =
        Arc::new(PgRepoSecurityScoreRepository::new(db.clone()));
    // Curation
    // rule adapter shared between `IngestUseCase` (the pre-storage
    // gate) and `ApplyConfigUseCase` (gitops apply path; see
    // `gitops_boot.rs` for the standalone instance used during
    // boot before `AppContext` is constructed).
    let curation_rules: Arc<dyn CurationRuleRepository> =
        Arc::new(PgCurationRuleRepository::new(db.clone()));
    // `QuarantineUseCase::new` takes
    // the storage port unconditionally so the misuse path
    // (`record_scan_result` without storage wired) is unreachable
    // by construction. The per-finding `scan_findings` projection
    // rows are persisted by the lifecycle adapter inside the
    // `commit_scan_result_with_score` SQL transaction; hort-server
    // itself does not need a separate `ScanFindingsRepository`
    // handle.
    let quarantine_use_case = Arc::new(
        QuarantineUseCase::new(
            artifact_repo.clone(),
            event_publisher.clone(),
            lifecycle.clone(),
            repo_repo.clone(),
            policy_projections.clone(),
            // The reject path sweeps
            // `content_references` rows for the rejected source. Threads
            // the same `Arc<dyn ContentReferenceIndex>` that the ingest
            // use case writes through; both observe the same projection.
            content_references.clone(),
            storage.clone(),
        )
        // Inject the upstream-index cache
        // invalidator. The post-`record_scan_result` Reject-branch
        // hook calls it best-effort; failure logs warn! and does not
        // roll back the reject append.
        .with_upstream_index_cache_invalidator(upstream_index_cache_invalidator.clone()),
    );
    let promotion_use_case = Arc::new(PromotionUseCase::new(
        artifact_repo.clone(),
        repo_repo.clone(),
        event_publisher.clone(),
        lifecycle.clone(),
        policy_projections.clone(),
    ));
    // The group use case is wired BEFORE the
    // ingest use case so `IngestUseCase::new` can take it by `Arc` and
    // route post-commit `classify_group_member` hits through it.
    let artifact_group_use_case = Arc::new(ArtifactGroupUseCase::new(
        artifact_group_repo.clone(),
        artifact_group_lifecycle.clone(),
        include_repository_label,
    ));
    // The `jobs` table adapter is needed earlier
    // than its later use site (`TaskUseCase`) because `IngestUseCase`
    // calls `enqueue_scan` on it for the ingest-time scan auto-enqueue
    // (when a `ScanPolicy` matches the inbound repository). Single
    // Arc shared with `TaskUseCase` + `ManualRescanUseCase` below.
    let jobs_repo = Arc::new(PgJobsRepository::new(db.clone()));
    let ingest_use_case = Arc::new(
        IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifact_repo.clone(),
            repo_repo.clone(),
            event_publisher.clone(),
            curation_rules.clone(),
            artifact_group_use_case.clone(),
            include_repository_label,
            metadata_caps.clone(),
            metadata_blob_max_bytes,
            // Refcount projection writes ride on the same
            // ContentReferenceIndex Arc that ContentReferenceUseCase wraps
            // below — the use case is constructed AFTER auth/access, but
            // IngestUseCase needs the raw port handle for unauthorised
            // post-commit projection writes (the artifact lifecycle has
            // already authorised the ingest itself).
            content_references.clone(),
            // `policy_projections` (already wired
            // above for `QuarantineUseCase`) drives the ingest-time policy
            // match; `jobs_repo` performs the actual `kind='scan'` insert.
            policy_projections.clone(),
            jobs_repo.clone(),
        )
        // Activate the provenance-verify
        // enqueue gate (ADR 0027). The set is the known Tier-1 cosign coverage
        // (cosign → OCI), passed as plain data: hort-server enqueues a
        // `provenance-verify` job iff the resolved policy `provenance_mode
        // != Off` AND the ingest's format is in this set. The literal
        // `{"oci"}` mirrors the worker's registered cosign port (Tier-1:
        // cosign → oci); hort-server derives it from that known coverage
        // WITHOUT depending on hort-adapters-provenance-sigstore (which
        // would pull sigstore's transitive reqwest 0.13 into the server
        // binary). The set is always `{"oci"}` regardless of whether the
        // worker has cosign enabled — if disabled, the enqueued jobs are
        // simply never processed (no worker handler claims them) and a
        // `Required` artifact stays Pending (fail-closed);
        // gating the enqueue on the worker flag is neither visible to the
        // server nor necessary for correctness.
        .with_provenance_capable_formats(
            hort_app::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS
                .iter()
                .copied()
                .map(String::from),
        ),
    );
    let ref_use_case = Arc::new(RefUseCase::new(
        ref_registry.clone(),
        ref_lifecycle.clone(),
        include_repository_label,
    ));

    // The resolver holds no state. All public-URL derivation lives in
    // `request_trust_layer`, which consumes `public_base_url` (threaded
    // in via `trust_config`) at request time.
    // `public_base_url` here is used only for the startup-log line below.
    let url_resolver = hort_http_core::url_resolver::UrlResolver;

    // PAT cache + validator + listener
    // wiring. Built BEFORE the auth context so the
    // `AuthenticateUseCase` builder can carry the `Arc<PatValidationUseCase>`
    // without a downstream re-bind. All three artefacts (cache,
    // validator, listener) are gated on `native_token_config.enabled`
    // — when off, none of them are constructed, the auth middleware's
    // PAT branch is a no-op, and `AppContext.pat_cache = None`.
    let (pat_cache, pat_validation_uc, pat_listener_handle) = if native_token_config.enabled {
        let cache = Arc::new(PatCache::new(
            native_token_config.cache_size,
            std::time::Duration::from_secs(300),
        ));
        let pat_lockout = PatLockoutConfig {
            threshold: native_token_config.lockout_threshold,
            window: std::time::Duration::from_secs(native_token_config.lockout_window_secs),
            duration: std::time::Duration::from_secs(native_token_config.lockout_duration_secs),
        };
        let validator = Arc::new(
            PatValidationUseCase::new(
                api_token_repo.clone(),
                user_repo.clone(),
                // PAT brute-force lockout writes to
                // the `pat-attempt:` / `pat-attempt-counter:`
                // keyspaces, both registered as Durable in
                // `KEYSPACE_REGISTRY`. The token-use audit
                // throttle (`token_use:audit:throttle:`) reuses this
                // same Durable handle (no second store handle).
                ephemeral_durable.clone(),
                cache.clone(),
                Arc::new(SystemClock),
                pat_lockout,
            )
            // Throttled per-use
            // token-use audit emit. Same `Arc<EventStorePublisher>`
            // wired onto `ArtifactUseCase::with_audit_events`.
            .with_audit_events(event_publisher.clone()),
        );
        let invalidator: Arc<dyn ApiTokenCacheInvalidator> = cache.clone();
        let listener =
            hort_adapters_postgres::api_token_revocation_listener::spawn_revocation_listener(
                db.clone(),
                invalidator,
                hort_adapters_postgres::api_token_revocation_listener::REVOCATION_CHANNEL
                    .to_string(),
            );
        (Some(cache), Some(validator), Some(listener))
    } else {
        (None, None, None)
    };

    // Boot-time warn + unsafe-config gauge
    // for the PAT-over-HTTP override. Factored into
    // [`emit_pat_over_http_signal`] so unit tests can assert the
    // gauge fires at the right value without standing up the full
    // composition path (which needs a Postgres pool).
    emit_pat_over_http_signal(native_token_config.allow_pat_over_http);

    // Boot-time guardrail for the
    // deliberate test-clock auth-bypass primitive (auth-catalog
    // Entry 10's mandatory guardrail). `HORT_TEST_CLOCK_ENABLED` is the
    // runtime half of the double gate; `cfg!(feature = "test-clock")`
    // is the compile-time half (a release build never compiles test
    // features). If the runtime flag is set in a build that did NOT
    // compile the feature, the double gate is broken and we refuse to
    // boot. The flag is parsed here (case-insensitive `"true"`,
    // empty/unset → false) rather than in `Config::from_env` so the
    // guard owns its own opt-in surface; the gauge fires on every
    // path so dashboards see OFF vs not-registered.
    let test_clock_enabled = std::env::var("HORT_TEST_CLOCK_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    evaluate_test_clock_guard(test_clock_enabled, cfg!(feature = "test-clock"))?;

    // Boot-time staging-sweep liveness
    // signal. `staging-sweep` runs as a worker CronJob that is
    // `cronJobs.enabled:false` by default; a deployment that upgrades
    // without enabling it (or runs non-k8s) gets no sweep and
    // accumulates orphaned staging entries unbounded with nothing
    // alerting. We query the newest completed `staging-sweep` row, run
    // the pure liveness predicate, and emit the
    // `hort_staging_sweep_overdue` gauge + a `warn!` when overdue. This is
    // a single boot-time emit (NOT a periodic loop — a loop would be
    // an in-process scheduler, which `hort-server` deliberately has
    // none of — ADR 0028); Prometheus alarms on
    // the scraped gauge, mirroring the other boot signals. The two knobs are
    // parsed here (owns its own opt-in surface, like the test-clock
    // guard above): expected CronJob cadence (default 300 s — matches the
    // documented `staging-sweep` schedule) and a staleness multiplier
    // (default 3 — tolerates two missed ticks before alarming so a
    // single skipped fire does not page). A query failure is logged
    // and treated as "unknown" (gauge left unset, debug log) — it must
    // not block an otherwise-serviceable boot.
    let staging_sweep_expected_interval = std::time::Duration::from_secs(
        std::env::var("HORT_STAGING_SWEEP_EXPECTED_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(300),
    );
    let staging_sweep_staleness_multiplier =
        std::env::var("HORT_STAGING_SWEEP_STALENESS_MULTIPLIER")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);
    use hort_domain::ports::jobs_repository::JobsRepository as _;
    match jobs_repo.last_completed_at_by_kind("staging-sweep").await {
        Ok(last_completed_at) => {
            emit_staging_sweep_liveness_signal(
                last_completed_at,
                chrono::Utc::now(),
                staging_sweep_expected_interval,
                staging_sweep_staleness_multiplier,
            );
        }
        Err(e) => {
            // The boot path stays serviceable even if this read fails —
            // the signal is observability, not a fail-closed control.
            tracing::debug!(
                error = %e,
                "staging-sweep liveness check skipped — last-completed query failed; \
                 hort_staging_sweep_overdue not emitted this boot"
            );
        }
    }

    // Boot-time event-chain-verifier
    // liveness signal. The verifier (`hort-server verify-event-chain`)
    // ships CLI-only and is scheduled by the default-disabled
    // `cronJobs.verifyEventChain` CronJob; a deployment that never enabled
    // it (or enabled it and it then stopped) gets no audit-log tamper
    // detection and, without this signal, nothing would flag it. We query
    // the
    // newest completed `verify-event-chain` row (written by the CLI's
    // `record_run_completion`), run the pure liveness predicate, and emit
    // the `hort_event_chain_verify_overdue` gauge + a `warn!` when overdue.
    // Single boot-time emit (NOT a periodic loop — `hort-server` is
    // scheduler-free, ADR 0028); Prometheus alarms on the scraped gauge,
    // mirroring the staging-sweep signal above. The two knobs are parsed
    // here (owns its own opt-in surface): expected CronJob cadence
    // (default 86400 s = daily — matches the `cronJobs.verifyEventChain`
    // default schedule) and a staleness multiplier (default 3 — tolerates
    // two missed ticks before alarming). A query failure is logged and
    // treated as "unknown" (gauge left unset, debug log) — it must not
    // block an otherwise-serviceable boot.
    let event_chain_verify_expected_interval = std::time::Duration::from_secs(
        std::env::var("HORT_EVENT_CHAIN_VERIFY_EXPECTED_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(86_400),
    );
    let event_chain_verify_staleness_multiplier =
        std::env::var("HORT_EVENT_CHAIN_VERIFY_STALENESS_MULTIPLIER")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);
    match jobs_repo
        .last_completed_at_by_kind("verify-event-chain")
        .await
    {
        Ok(last_completed_at) => {
            emit_event_chain_verify_liveness_signal(
                last_completed_at,
                chrono::Utc::now(),
                event_chain_verify_expected_interval,
                event_chain_verify_staleness_multiplier,
            );
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                "event-chain verify liveness check skipped — last-completed query failed; \
                 hort_event_chain_verify_overdue not emitted this boot"
            );
        }
    }

    // Boot-time quarantine-posture log. Reports
    // the resolved `DefaultPolicy` quarantine window (the
    // out-of-the-box hold — ADR 0007), the count of operator `ScanPolicy`
    // rows
    // overriding to permissive (`quarantineDuration=0`, the explicit
    // operator override — `warn!` when `> 0` so dashboards can surface
    // it alongside the quarantine-by-default posture), and the count of
    // `RepositoryUpstreamMapping` rows with
    // `trust_upstream_publish_time = true` (a
    // purely informational `info!`-level "how many operators opted in"
    // signal). Counts are derived in memory from existing `list_active`
    // / `list_all` port reads — no new port method, no new metric
    // (the startup log is the entire observability surface
    // here). A query failure is logged and treated as "unknown"
    // (posture log skipped — same pattern as the staging-sweep liveness
    // check above); it must not block an otherwise-serviceable boot.
    match policy_projections.list_active().await {
        Ok(scan_policies) => match repository_upstream_mappings.list_all().await {
            Ok(upstream_mappings) => {
                evaluate_quarantine_posture(&scan_policies, &upstream_mappings);
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "quarantine posture log skipped — list_all() on \
                     repository_upstream_mappings failed; posture not emitted this boot"
                );
            }
        },
        Err(e) => {
            tracing::debug!(
                error = %e,
                "quarantine posture log skipped — list_active() on policy_projections \
                 failed; posture not emitted this boot"
            );
        }
    }

    // Load the OCI Distribution-Spec `/v2/auth`
    // signing key + previous public half (rotation). Construction is
    // gated on `enable_native_tokens=true`: when off, we leave the
    // slots `None` so the challenge middleware emits the legacy Basic
    // challenge and `/v2/auth` returns 404. When on, the config layer
    // already guaranteed the active PEM is `Some(_)` via
    // `OciTokenSigningKeyMissing`; here we PARSE it.
    let oci_signing_key: Option<Arc<hort_app::oci_token_signing::OciTokenSigningKey>> =
        if native_token_config.enabled {
            let active_pem = native_token_config
                .oci_token_signing_key_pem
                .as_deref()
                .ok_or_else(|| {
                    hort_domain::error::DomainError::Invariant(
                        "HORT_NATIVE_TOKENS_ENABLED=true but no OCI signing key \
                        in NativeTokenConfig — config layer should have \
                        rejected this earlier (OciTokenSigningKeyMissing)"
                            .into(),
                    )
                })?;
            let prev_pem = native_token_config
                .oci_token_signing_key_prev_pem
                .as_deref();
            let key =
                hort_app::oci_token_signing::OciTokenSigningKey::from_pem(active_pem, prev_pem)
                    .map_err(|e| {
                        hort_domain::error::DomainError::Invariant(format!(
                            "OCI signing key parse failed: {e}"
                        ))
                    })?;
            tracing::info!(
                prev_configured = prev_pem.is_some(),
                "OCI token signing key loaded"
            );
            Some(Arc::new(key))
        } else {
            None
        };

    // CliSession access-token JWT signer (ADR 0013).
    //
    // Reuses the SAME `oci_signing_key` Ed25519 keypair (one
    // issuer primitive, two token families separated by `aud` +
    // `token_kind`). It is `Some(_)` exactly when the OCI signing key is
    // present — i.e. `HORT_NATIVE_TOKENS_ENABLED=true`. The boot
    // gate already requires native tokens whenever token-exchange (the
    // only CliSession mint path) is on, so the signer is always wired
    // when CliSession issuance is reachable. The `iss` claim is the
    // public base URL when configured (stable per deployment), else a
    // fixed fallback (`iss` is not security-load-bearing for the
    // CliSession family — the `aud` + `token_kind` discriminator is what
    // separates it from the OCI token; verification is by signing key).
    let cli_session_signer: Option<Arc<hort_app::cli_session_signing::CliSessionTokenSigner>> =
        oci_signing_key.as_ref().map(|key| {
            let issuer = public_base_url
                .as_ref()
                .map(|u| u.as_str().to_string())
                .unwrap_or_else(|| "hort-cli-session".to_string());
            tracing::info!("CliSession access-token JWT signer loaded");
            Arc::new(hort_app::cli_session_signing::CliSessionTokenSigner::new(
                key.clone(),
                issuer,
            ))
        });

    // Auth wiring. (`BearerOnly` was once named `LocalOnly`; the
    // rename followed the end-to-end deletion of the
    // HTTP-Basic-against-local-admin-row identity path.) Three shapes:
    //
    //   1. `AuthContext::Enabled` — `HORT_AUTH_PROVIDER=oidc`. Full OIDC
    //      + optional native tokens. Existing path; no behavioural
    //      change.
    //   2. `AuthContext::BearerOnly` — `HORT_AUTH_PROVIDER=disabled`
    //      with `HORT_NATIVE_TOKENS_ENABLED=true`. The native-token
    //      validator (`Bearer hort_<kind>_*`) is the inbound identity
    //      surface; the use case carries `idp = None`
    //      (`AuthenticateUseCase::new_local_only`); OIDC-shaped
    //      tokens fail cleanly. Native tokens are independent of
    //      OIDC (ADR 0012).
    //   3. `AuthContext::Disabled` — auth fully off, no OIDC, no
    //      native tokens. The runtime boot gate
    //      (`ensure_auth_enabled`) rejects this combination, so it
    //      is dead in production and only persists for test fixtures.
    let auth = if auth_enabled {
        let idp = idp.ok_or_else(|| {
            hort_domain::error::DomainError::Invariant(
                "auth_enabled = true but no IdentityProvider was supplied".into(),
            )
        })?;
        // The additive-claims evaluator (ADR 0012) is built from
        // the flat grant set (`RbacEvaluator::new(grants)`); there is
        // no role table to pre-index. Load every grant via the
        // permission-grant port.
        let grants = permission_grant_repo.list_all().await?;
        // Wrap the initial snapshot in
        // `ArcSwap`. The refresh task in `hort-server` swaps the
        // pointer in-place as grants change; read sites
        // dereference via `.load()` for lock-free access.
        let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(grants)));
        // Audit-event gate: every authentication
        // failure produces a tamper-resistant
        // `AuthenticationAttempted` event throttled to ≤ 1 append
        // per 60s per `(client_ip_bucket, result)` tuple via the
        // EphemeralStore. Successes stay in tracing only
        // (audit-value-per-byte).
        //
        // Chain the optional PAT validator
        // onto the same builder so a `Bearer hort_<kind>_<body>` token
        // routes through the validator before the OIDC port. When
        // `pat_validation_uc` is `None` (feature flag off), the
        // `with_pat_validation` builder is skipped and the PAT
        // routing in `authenticate_bearer` falls through to OIDC.
        let mut authenticate_builder =
            AuthenticateUseCase::new(idp, user_repo.clone(), claim_mappings)
                // Auth-event throttle writes to the
                // `auth:event:` keyspace, registered as Durable.
                .with_audit_events(event_publisher.clone(), ephemeral_durable.clone())
                // Workspace-wide cardinality
                // toggle. PAT-side
                // `hort_service_account_authenticated_total` honours
                // the same env var as the rotation gauge.
                .with_include_service_account_label(include_service_account_label);
        if let Some(uc) = pat_validation_uc.clone() {
            authenticate_builder = authenticate_builder.with_pat_validation(uc);
        }
        // Wire the CliSession JWT verifier (ADR 0013) +
        // its `jti` revocation denylist (the durable EphemeralStore).
        // Wired iff the signing key exists (native tokens on), which the
        // boot gate guarantees whenever token-exchange is on.
        if let Some(signer) = cli_session_signer.clone() {
            authenticate_builder = authenticate_builder
                .with_cli_session_verification(signer, ephemeral_durable.clone());
        }
        let authenticate = Arc::new(authenticate_builder);
        AuthContext::Enabled {
            authenticate,
            rbac,
            // Populate the
            // issuer URL so `www_authenticate_for` can render
            // `Bearer realm="<issuer>"` on 401s. Threaded in from
            // `cfg.auth` at the caller; we do not re-read the config
            // here (composition is the source of truth, not the
            // env-var loader).
            issuer_url: oidc_issuer_url,
        }
    } else {
        // HORT_AUTH_PROVIDER=disabled. The
        // password-identity path is gone end-to-end; the
        // only inbound auth surface under `disabled` is the native-token
        // bearer carrier (PAT / SA tokens). `serve::ensure_auth_enabled`
        // rejects `disabled + native_tokens=false` before composition
        // runs; this gate is a defense-in-depth backstop.
        let native_tokens_wired = pat_validation_uc.is_some();
        if native_tokens_wired {
            // Build a fully-wired `AuthenticateUseCase` minus the OIDC
            // IdP. Mirror the `Enabled` arm's audit /
            // service-account-label / PAT-validator wiring so the
            // local-only path has the same operational properties.
            // Flat grant set; no role pre-index (ADR 0012).
            let grants = permission_grant_repo.list_all().await?;
            let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(grants)));
            let mut authenticate_builder =
                AuthenticateUseCase::new_local_only(user_repo.clone(), claim_mappings)
                    .with_audit_events(event_publisher.clone(), ephemeral_durable.clone())
                    .with_include_service_account_label(include_service_account_label);
            if let Some(uc) = pat_validation_uc.clone() {
                authenticate_builder = authenticate_builder.with_pat_validation(uc);
            }
            // CliSession JWT verifier on the
            // BearerOnly path too. CliSession *minting* needs OIDC
            // (`/exchange`), so this arm rarely sees a CliSession token;
            // wiring it keeps the validate surface uniform and lets a
            // CliSession JWT issued by an Enabled peer validate here if
            // the deployment ever runs mixed.
            if let Some(signer) = cli_session_signer.clone() {
                authenticate_builder = authenticate_builder
                    .with_cli_session_verification(signer, ephemeral_durable.clone());
            }
            let authenticate = Arc::new(authenticate_builder);
            tracing::info!(
                native_tokens_wired,
                "AuthContext::BearerOnly wired (HORT_AUTH_PROVIDER=disabled with native tokens)"
            );
            AuthContext::BearerOnly { authenticate, rbac }
        } else {
            tracing::warn!(
                "AuthContext::Disabled — no OIDC, no native tokens; \
                 the runtime boot gate (ensure_auth_enabled) should reject this \
                 combination before requests can reach handlers"
            );
            AuthContext::Disabled
        }
    };

    // Multi-issuer JWT validator (ADR 0018) for the
    // federation branch of `/auth/token-exchange`.
    // Built only when auth is
    // Always wire federation slots from the DB pool — the federation
    // flow is independent of the interactive-OIDC auth mode.
    // `AuthConfig::Disabled` + `enable_native_tokens=true` enables the
    // federated-JWT branch of `/exchange` without configuring an
    // interactive IdP; the three ship-gate guardrails (anti-replay,
    // `aud`→SA binding, empty-claims fail-closed) are unaffected by
    // this auth-mode split and remain wired unconditionally.
    //
    // The validator owns its own `reqwest::Client` (built via
    // `internal::build_http_client` — extra-CA layered + redirect
    // cap + timeout + TLS-version pin), so operator trust anchors
    // declared via `HORT_EXTRA_CA_BUNDLE` apply to JWKS fetches against
    // private IdPs the same way they apply to the user-login path.
    // The `OidcIssuerRepository` is constructed against the same
    // pool the apply pipeline uses (`gitops_boot.rs`) so apply-time
    // changes to trusted issuers take effect on the very next
    // `validate()` call without bouncing the validator.
    // The `OidcIssuerRepository` is shared three ways: the JWT
    // validator, the federation handler's `require_jti` resolution
    // (threaded onto `AppContext`), and the apply pipeline. One Arc,
    // one pool, so an apply-time issuer change takes effect everywhere
    // on the next request without bouncing the server.
    // Build the issuer repo once and share it: the federation validator
    // takes it directly, and `AppContext` keeps an `Option`-wrapped clone
    // for the handler's `require_jti` resolution. Both are unconditionally
    // wired, so the previous `Option`/`expect` round-trip is unnecessary.
    let oidc_issuers_repo: Arc<
        dyn hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository,
    > = Arc::new(PgOidcIssuerRepository::new(db.clone()));
    let oidc_issuers: Option<
        Arc<dyn hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository>,
    > = Some(oidc_issuers_repo.clone());
    let federated_jwt_validator: Option<
        Arc<dyn hort_domain::ports::federated_jwt_validator::FederatedJwtValidator>,
    > = {
        let v = hort_adapters_oidc::MultiIssuerJwksValidator::new(
            oidc_issuers_repo,
            extra_trust_anchors.as_ref(),
        )
        .map_err(|e| {
            hort_domain::error::DomainError::Invariant(format!(
                "MultiIssuerJwksValidator construction failed: {e}"
            ))
        })?;
        tracing::info!("federation JWT validator wired");
        Some(Arc::new(v))
    };

    // Durable anti-replay seen-set. Always wired — the federation
    // system-mint path always has a `Some` guard and a federation mint
    // can never bypass the replay check. Non-federation issuance paths
    // set `federation_source = None` and never touch it.
    let replay_guard: Option<Arc<dyn hort_domain::ports::replay_guard::ReplayGuardPort>> =
        Some(Arc::new(
            hort_adapters_postgres::replay_guard_repo::PgReplayGuardRepository::new(db.clone()),
        ));

    // `ServiceAccountRepository` consumed by the
    // federation branch of `/auth/token-exchange`. Wired against the
    // same Postgres pool the apply pipeline uses (`gitops_boot.rs`) so
    // apply-time changes to declared SAs take effect on the next
    // federation `/exchange` call without bouncing the server.
    // Always wired — federation is independent of the interactive-OIDC
    // auth mode.
    let service_accounts: Option<
        Arc<dyn hort_domain::ports::service_account_repository::ServiceAccountRepository>,
    > = Some(Arc::new(
        hort_adapters_postgres::service_account_repo::PgServiceAccountRepository::new(db.clone()),
    ));

    // Fallback-PAT-rotation reconciler's
    // outbound k8s Secret writer. Opt-in via
    // `HORT_K8S_SECRET_WRITER_ENABLED=true` (default off — matches the
    // Helm chart's `worker.rotation.enabled: false` default). When
    // the env var is set but in-cluster auth (or kubeconfig fallback)
    // fails, we surface a loud boot error rather than silently
    // degrading to a `None` slot — operators want the failure to be
    // visible, since a `None` slot means the rotation handler
    // refuses to register and the fallback PATs go
    // stale.
    let k8s_secret_writer: Option<
        Arc<dyn hort_domain::ports::kubernetes_secret_writer::KubernetesSecretWriter>,
    > = if std::env::var("HORT_K8S_SECRET_WRITER_ENABLED")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        match hort_adapters_kubernetes::KubernetesSecretWriterImpl::try_in_cluster().await {
            Ok(impl_) => {
                tracing::info!(
                    "k8s Secret writer wired — \
                     ServiceAccountRotationHandler may register"
                );
                Some(Arc::new(impl_)
                    as Arc<
                        dyn hort_domain::ports::kubernetes_secret_writer::KubernetesSecretWriter,
                    >)
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "HORT_K8S_SECRET_WRITER_ENABLED=true but kube::Client::try_default() \
                     failed — refusing to boot (set the env var to false to disable, \
                     or ensure the in-cluster ServiceAccount token / kubeconfig is mounted)"
                );
                return Err(hort_domain::error::DomainError::Invariant(format!(
                    "kubernetes client construction failed: {err}"
                )));
            }
        }
    } else {
        None
    };

    // `RepositoryAccessUseCase` (ADR 0008). Constructed AFTER
    // `auth` so the same `Arc<ArcSwap<RbacEvaluator>>` snapshot powers
    // both the legacy extractors and the new use case. `RbacAccess`
    // mirrors the two `AuthContext` variants — kept distinct because
    // `hort-app` cannot depend on `hort-http-core`.
    let rbac_access = match &auth {
        AuthContext::Disabled => RbacAccess::Disabled,
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => {
            RbacAccess::Enabled(rbac.clone())
        }
    };

    // `ApiTokenUseCase` consumes the SAME
    // `Arc<ArcSwap<RbacEvaluator>>` pointer the per-request authorize
    // path uses, so cap-vs-authority during issuance walks admin
    // short-circuit + per-repo grants through ONE source of
    // truth AND tracks the refresh task in real time.
    // Snapshotting the evaluator into a fresh
    // `Arc<RbacEvaluator>` at boot would mean a user who gained
    // authority after a grant reload could not mint a token
    // until `hort-server` restarted — the issuance gate would keep
    // honouring
    // the boot-time evaluator. Threading the `ArcSwap` directly
    // closes that gap; each `issue_self_token` / `issue_for_service_
    // account` call takes a fresh `.load()` guard and walks the
    // current evaluator.
    //
    // When auth is disabled, the use case still needs an evaluator —
    // production deployments never run auth-disabled, so the empty-
    // grants fallback only matters for dev / bootstrap. We build a
    // one-off `ArcSwap` over an empty evaluator so the type matches
    // the Enabled arm.
    //
    // Construction is unconditional — the
    // issuance/list/revoke surface is always reachable from
    // authenticated handlers; only the validator's bearer-routing
    // branch is gated on `HORT_NATIVE_TOKENS_ENABLED`.
    let api_token_rbac: Arc<ArcSwap<RbacEvaluator>> = match &auth {
        AuthContext::Disabled => Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new()))),
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => rbac.clone(),
    };
    let api_token_use_case = {
        let uc = hort_app::use_cases::api_token_use_case::ApiTokenUseCase::new(
            api_token_repo.clone(),
            user_repo.clone(),
            event_publisher.clone(),
            api_token_rbac,
            hort_app::use_cases::api_token_use_case::ApiTokenIssuanceConfig {
                allow_admin_tokens: native_token_config.allow_admin_tokens,
                allow_unbounded_svc_tokens: native_token_config.allow_unbounded_svc_tokens,
            },
        );
        // Attach the durable
        // replay guard iff federation is enabled. The federation
        // system-mint path then always has a `Some` guard; a `None`
        // guard reached on that path (composition bug) fails CLOSED.
        let uc = match replay_guard.clone() {
            Some(g) => uc.with_replay_guard(g),
            None => uc,
        };
        // Attach the CliSession JWT signer (ADR 0013) +
        // its revocation denylist so `issue_cli_session` mints a signed
        // JWT (carrying the caller's resolved claims) instead of an
        // opaque `hort_cli_*` row. The signer + denylist ship together
        // (the denylist is the server-side immediate-revocation layer
        // the signed JWT otherwise lacks).
        let uc = match cli_session_signer.clone() {
            Some(signer) => uc.with_cli_session_signing(signer, ephemeral_durable.clone()),
            None => uc,
        };
        Arc::new(uc)
    };
    let repository_access_use_case = Arc::new(RepositoryAccessUseCase::new(
        repo_repo.clone(),
        rbac_access.clone(),
        include_repository_label,
    ));
    // Virtual-repo member resolution (ADR 0031). Composed over the repository
    // port (member listing) + the access use case (per-member Read visibility);
    // the npm/pypi/cargo serve + download paths reach it via `AppContext`.
    let virtual_resolution_use_case = Arc::new(VirtualResolutionUseCase::new(
        repo_repo.clone(),
        repository_access_use_case.clone(),
    ));
    // `ContentReferenceUseCase` (ADR 0008). Composed over the
    // existing `content_references` adapter + the access use case
    // constructed above; `hort-http-oci` calls the use case rather
    // than the raw port.
    let content_reference_use_case = Arc::new(ContentReferenceUseCase::new(
        content_references.clone(),
        repository_access_use_case.clone(),
    ));
    // `SecurityScoreUseCase`. Composed over the
    // `repo_security_scores` adapter + the repository_access use case
    // (for Read-side anti-enumeration on `find_for_repo` and visibility
    // filtering on `list_with_access`). Backs the
    // `/api/v1/repositories/:name/security-score` and
    // `/api/v1/security-score` endpoints in `hort-http-admin-security`.
    let security_score_use_case = Arc::new(SecurityScoreUseCase::new(
        security_scores.clone(),
        repo_repo.clone(),
        repository_access_use_case.clone(),
    ));

    // `TaskUseCase` for the admin-task endpoint
    // surface (`POST /api/v1/admin/tasks/{kind}`). Needs the `jobs` table
    // adapter + the event store (for `TaskInvoked` audit append) + the
    // live RBAC ArcSwap (same pointer as `AuthContext::Enabled.rbac`).
    // Wired unconditionally — even auth-disabled deployments can reach the
    // admin-task surface; RBAC in the use case will deny-all with the
    // empty evaluator from the Disabled branch.
    //
    // `jobs_repo` was already wired above (just before `IngestUseCase`)
    // because the ingest-time scan auto-enqueue needs
    // it earlier than this admin-task site.
    let task_rbac: Arc<ArcSwap<RbacEvaluator>> = match &auth {
        AuthContext::Disabled => Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new()))),
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => rbac.clone(),
    };
    let task_use_case = Arc::new(TaskUseCase::new(
        jobs_repo.clone(),
        event_publisher.clone(),
        task_rbac,
    ));

    // `ManualRescanUseCase` for the
    // `POST /api/v1/artifacts/:id/rescan` endpoint. Shares the same
    // `PgJobsRepository` Arc with `TaskUseCase` so the in-memory
    // metric counters and any future shared state stay coherent. The
    // RBAC enforcement happens through the existing
    // `RepositoryAccessUseCase` — no separate
    // ArcSwap<RbacEvaluator> indirection here.
    let manual_rescan_use_case = Arc::new(ManualRescanUseCase::new(
        artifact_repo.clone(),
        jobs_repo.clone(),
        repository_access_use_case.clone(),
    ));

    // `PatchCandidateUseCase` for the admin
    // `GET /admin/quarantine/patch-candidates` endpoint. The adapter
    // executes a join across `artifacts`, `repositories`, and
    // `scan_findings` directly on the shared `PgPool`; the use case
    // enforces `Permission::Admin` + the 500-row hard cap before
    // reaching the adapter.
    let patch_candidate_repo = Arc::new(PgPatchCandidateRepository::new(db.clone()));
    let patch_candidate_use_case = Arc::new(PatchCandidateUseCase::new(patch_candidate_repo));

    // `ScannerWorkerQueryUseCase` for the admin `GET /admin/workers`
    // endpoint. Wires the READ side of the `scanner_registry`
    // worker-coordination table — the consumer for the worker heartbeat
    // (ADR 0000 "Scanner-registry read side orphaned"; H20 removed the
    // apply-time reader, this restores one). The use case enforces
    // `Permission::Admin` and stamps each row with derived liveness.
    let scanner_registry = Arc::new(
        hort_adapters_postgres::scanner_registry_repository::PgScannerRegistryRepository::new(
            db.clone(),
        ),
    );
    let scanner_worker_query_use_case = Arc::new(ScannerWorkerQueryUseCase::new(scanner_registry));

    // Prefetch planner. Zero-cost unit struct;
    // the `Arc` mirrors the rest of the use-case surface.
    let prefetch_use_case = Arc::new(PrefetchUseCase::new());

    // `UpstreamMetadataAdapter`
    // implementing `UpstreamMetadataPort`. The four `Arc`s passed here
    // are the SAME shared instances threaded into `AppContextParts`
    // below — "shared dependency, two consumers" per the
    // cycle-avoidance discipline. The adapter NEVER holds an
    // `AppContext` (that would close a construction cycle); the
    // composition root passes the underlying ports directly.
    let upstream_metadata: Arc<dyn hort_app::ports::upstream_metadata::UpstreamMetadataPort> =
        Arc::new(hort_formats_upstream::UpstreamMetadataAdapter::new(
            upstream_resolver.clone(),
            ephemeral_evictable.clone(),
            upstream_proxy.clone(),
            pull_dedup.clone(),
        ));

    // `DiscoveryUseCase` backing
    // `GET /api/v1/repositories/:repo_key/discovery/versions/:package_name`.
    // RBAC snapshot reuses the same `Arc<ArcSwap<RbacEvaluator>>` the
    // subscription / api-token / task use cases hold — admin enforcement
    // is consistent across surfaces.
    let discovery_rbac: Arc<ArcSwap<RbacEvaluator>> = match &auth {
        AuthContext::Disabled => Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new()))),
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => rbac.clone(),
    };
    let discovery_use_case = Arc::new(DiscoveryUseCase::new(
        repo_repo.clone(),
        artifact_repo.clone(),
        repository_upstream_mappings.clone(),
        upstream_metadata.clone(),
        discovery_rbac.clone(),
        policy_projections.clone(),
    ));

    // `SelfServicePrefetchUseCase`
    // backing `POST /api/v1/repositories/:repo_key/prefetch`. Wraps
    // the existing pure planner (the pure
    // planner stays untouched); orchestration adds repo resolution,
    // token-kind + RBAC gates, per-item upstream resolution, server-side
    // pre-flight, and per-item `jobs` enqueue.
    let self_service_prefetch_use_case = Arc::new(SelfServicePrefetchUseCase::new(
        repo_repo.clone(),
        artifact_repo.clone(),
        repository_upstream_mappings.clone(),
        upstream_metadata.clone(),
        jobs_repo.clone(),
        discovery_rbac.clone(),
    ));

    // `EffectivePermissionsUseCase` backing
    // `GET /api/v1/admin/users/:user_id/effective-permissions`. Reuses
    // the already-constructed `user_repo` (resolve inspected user +
    // `is_admin`) and `permission_grant_repo` (`list_all` → enumerate
    // matching grants). The use case enforces `Permission::Admin`
    // (defence in depth — the `AdminPrincipal` extractor enforces
    // the same gate at the request edge). Mitigates the
    // additive-claims operator-discipline cost (ADR 0012).
    let effective_permissions_use_case = Arc::new(EffectivePermissionsUseCase::new(
        user_repo.clone(),
        permission_grant_repo.clone(),
    ));

    // `RbacResolveUseCase` backing
    // `POST /api/v1/admin/rbac/resolve` (the admin what-if resolver). Reads
    // the `claim_mappings` table live per request (`resolve_claims` flattens
    // the supplied IdP groups against it) and reuses the already-wired
    // `permission_grant_repo` (`list_all` → fresh `RbacEvaluator` →
    // `effective_grants`). The `PgClaimMappingRepository` is constructed
    // here from a cheap `db` pool clone — distinct from the
    // boot-snapshot `Vec<ClaimMapping>` consumed by `AuthenticateUseCase`
    // (that is a one-shot read; the resolver needs a live port because it
    // serves an admin what-if at request time, not at boot). The use case
    // enforces `Permission::Admin` (defence in depth — the
    // `AdminPrincipal` extractor enforces the same gate at the request
    // edge). No IdP query, no cache.
    let claim_mapping_repo: Arc<
        dyn hort_domain::ports::claim_mapping_repository::ClaimMappingRepository,
    > = Arc::new(
        hort_adapters_postgres::claim_mapping_repo::PgClaimMappingRepository::new(db.clone()),
    );
    let rbac_resolve_use_case = Arc::new(RbacResolveUseCase::new(
        claim_mapping_repo,
        permission_grant_repo.clone(),
    ));

    // `SubscriptionUseCase` for the
    // `/api/v1/subscriptions` REST surface (`hort-http-subscriptions`).
    //
    // Repository: `PgSubscriptionRepository`.
    //
    // Webhook SSRF guard: the real `WebhookNotifier`,
    // wired once as `Arc<WebhookNotifier>` and exposed as **both**
    // `Arc<dyn EventNotifier>` (for the dispatcher's notifier registry,
    // below) AND `Arc<dyn WebhookTargetGuard>` (for the use-case
    // constructor). One instance services both trait views — see
    // the "wire once" rationale in the event-notifications doc.
    //
    // RBAC: same `ArcSwap<RbacEvaluator>` snapshot the API-token use
    // case and the task use case already hold — admin enforcement is
    // consistent across surfaces.
    let subscription_repo: Arc<
        dyn hort_domain::ports::subscription_repository::SubscriptionRepository,
    > = Arc::new(PgSubscriptionRepository::new(db.clone()));
    let subscription_rbac: Arc<ArcSwap<RbacEvaluator>> = match &auth {
        AuthContext::Disabled => Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new()))),
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => rbac.clone(),
    };
    // Construct the real webhook notifier ONCE and
    // expose it via two trait views. The shared `Arc<WebhookNotifier>`
    // is also held by the dispatcher's notifier registry below.
    // Thread the same `Arc<dyn SecretPort>`
    // wired above for upstream-mapping credentials. The webhook signing
    // secret is a `SecretRef` resolved at delivery time — the
    // plaintext never lives on the subscription row, closing the
    // "store/backup read → forge signed deliveries" exposure.
    let webhook_notifier = Arc::new(
        hort_notifier_webhook::WebhookNotifier::new(
            extra_trust_anchors.as_ref(),
            secret_port.clone(),
        )
        .map_err(|e| {
            hort_domain::error::DomainError::Invariant(format!("webhook notifier: {e}"))
        })?,
    );
    let subscription_webhook_guard: Arc<
        dyn hort_domain::ports::webhook_target_guard::WebhookTargetGuard,
    > = webhook_notifier.clone();
    let subscription_use_case = Arc::new(SubscriptionUseCase::new(
        subscription_repo.clone(),
        user_repo.clone(),
        event_publisher.clone(),
        subscription_rbac.clone(),
        repo_repo.clone(),
        subscription_webhook_guard,
        SubscriptionUseCaseConfig {
            allow_plaintext_webhooks: notify_config.allow_plaintext_webhooks,
            allow_nonroutable_webhook_targets: notify_config.allow_nonroutable_webhook_targets,
        },
    ));

    // Boot-time unsafe-config gauges. Both default
    // OFF; flipping either flag sets the corresponding gauge to `1.0`
    // so SREs see the misconfig on every dashboard. Mirrors the
    // `emit_pat_over_http_signal` precedent — emit `0.0` on
    // the safe path so a fresh scrape sees the metric anyway
    // (absence vs `0.0` would be ambiguous to dashboards).
    if notify_config.allow_plaintext_webhooks {
        tracing::warn!(
            "HORT_WEBHOOK_ALLOW_PLAINTEXT active — webhook URLs may use http:// scheme; \
             use only on a trusted internal network"
        );
        metrics::gauge!("hort_unsafe_config_active", "kind" => "plaintext_webhooks").set(1.0);
    } else {
        metrics::gauge!("hort_unsafe_config_active", "kind" => "plaintext_webhooks").set(0.0);
    }
    if notify_config.allow_nonroutable_webhook_targets {
        tracing::warn!(
            "HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS active — webhook target SSRF check skipped; \
             use only with operator-trusted internal receivers"
        );
        metrics::gauge!(
            "hort_unsafe_config_active",
            "kind" => "webhook_nonroutable_targets"
        )
        .set(1.0);
    } else {
        metrics::gauge!(
            "hort_unsafe_config_active",
            "kind" => "webhook_nonroutable_targets"
        )
        .set(0.0);
    }

    // Assemble the `NotificationDispatcher`
    // when `enable_notifications=true`. The dispatcher itself is NOT
    // spawned here (composition does not own the cancellation token —
    // `cli::serve` does); instead we package the dispatcher + the
    // `subscription_changes` LISTEN task's `JoinHandle` into
    // `NotificationRuntime` and `cli::serve` calls `dispatcher.run(
    // shutdown_handle.token())`. This mirrors the
    // `api_token_revocation` listener pattern, where composition
    // returns the `JoinHandle` for the serve loop to hold.
    //
    // When `enable_notifications=false`, the publisher was constructed
    // without a broadcast sender; spawning the dispatcher in that
    // branch would yield a task with a closed receiver doing no useful
    // work. We skip it entirely so the no-notifications shape stays
    // zero-overhead.
    let notification_runtime: Option<NotificationRuntime> = if notify_config.enabled {
        // Notifier registry: webhook always, NATS optional.
        let mut notifiers: Vec<Arc<dyn hort_domain::ports::event_notifier::EventNotifier>> =
            Vec::with_capacity(2);
        notifiers.push(webhook_notifier.clone());

        if let Some(nats_url) = notify_config.nats_url.as_deref() {
            // Thread the process-wide
            // `HORT_EXTRA_CA_BUNDLE` into the NATS TLS leg the same way
            // every other TLS surface (upstream-http/webhook/S3/OIDC)
            // already receives it (ADR 0010). `None` keeps the plain-
            // connect behaviour byte-for-byte.
            match hort_notifier_nats::NatsNotifier::connect(nats_url, extra_trust_anchors.as_ref())
                .await
            {
                Ok(nats) => {
                    tracing::info!("NATS JetStream notifier wired");
                    notifiers.push(Arc::new(nats));
                }
                Err(e) => {
                    // Continue without NATS — webhook-only deployments still
                    // work; subscriptions targeting NATS will fail delivery
                    // until the URL is reachable, but that is a per-
                    // subscription failure not a global boot failure.
                    tracing::error!(
                        error = %e,
                        "failed to connect to NATS at HORT_NATS_URL; notifications to NATS \
                         targets will fail until reachable"
                    );
                }
            }
        }

        // Spawn the `subscription_changes` LISTEN task. Returns the
        // listener handle (consumed by the dispatcher) and the task's
        // JoinHandle (held for shutdown).
        let (change_listener, change_listener_handle) =
            hort_adapters_postgres::subscription_change_listener::spawn_subscription_change_listener(
                db.clone(),
                hort_adapters_postgres::subscription_change_listener::SUBSCRIPTION_CHANGES_CHANNEL
                    .to_string(),
            );

        let dispatcher = hort_app::dispatcher::dispatcher::NotificationDispatcher::new(
            event_publisher.clone(),
            subscription_use_case.clone(),
            subscription_rbac.clone(),
            user_repo.clone(),
            subscription_repo.clone(),
            repo_repo.clone(),
            change_listener,
            notifiers,
        );

        Some(NotificationRuntime {
            dispatcher,
            change_listener_handle,
        })
    } else {
        None
    };

    // OCI Distribution-Spec `/v2/auth` token
    // exchange. Built after the access use case (which the exchange
    // calls into to resolve scoped repo names → ids) and the rbac
    // ArcSwap (extracted out of the auth context for the use case to
    // call `authorize` directly). `Some(_)` only when both
    // `enable_native_tokens` AND a signing key landed; either-side
    // missing collapses to `None` and the route handler 404s.
    let oci_token_exchange_use_case: Option<
        Arc<hort_app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase>,
    > = match (&pat_validation_uc, &oci_signing_key, &rbac_access) {
        (Some(pat_uc), Some(sk), RbacAccess::Enabled(rbac_swap)) => {
            // Derive `(issuer, audience)` from
            // `HORT_PUBLIC_BASE_URL`. The helper boot-fails when the URL
            // is unset or has no host component; silent fallbacks
            // (`localhost` aud + relative `/v2/auth` iss) would issue JWTs
            // that real OCI clients can't consume.
            let (issuer, host_str) = derive_oci_token_endpoint_strings(public_base_url.as_ref())
                .map_err(|e| hort_domain::error::DomainError::Invariant(e.to_string()))?;
            let cfg = hort_app::use_cases::oci_token_exchange_use_case::OciTokenExchangeConfig::new(
                issuer, host_str,
            );
            Some(Arc::new(
                hort_app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase::new(
                    pat_uc.clone(),
                    user_repo.clone(),
                    rbac_swap.clone(),
                    repository_access_use_case.clone(),
                    sk.clone(),
                    cfg,
                ),
            ))
        }
        // Auth Disabled is incompatible with `/v2/auth` (no rbac to
        // intersect against); leave the slot empty.
        _ => None,
    };
    let oci_public_base_url_str = public_base_url.as_ref().map(|u| u.as_str().to_string());
    // Wire the access + metadata ports into the
    // existing artifact use case so the `find_visible_*` /
    // `batch_metadata` methods work in production. The
    // `with_*` builders are non-breaking: callers that
    // never call those methods are untouched.
    let artifact_use_case = Arc::new(
        ArtifactUseCase::new(
            artifact_repo.clone(),
            storage.clone(),
            repo_repo.clone(),
            include_repository_label,
        )
        .with_repository_access(repository_access_use_case.clone())
        .with_artifact_metadata(artifact_metadata_repo.clone())
        // Opt-in per-(repo, UTC-date)
        // download-audit emit. Fail-open; no-op unless the served
        // repository has `download_audit_enabled = true`.
        .with_audit_events(event_publisher.clone()),
    );

    // `CurationUseCase` backing the
    // three HTTP decision endpoints under `/api/v1/admin/curation/...`
    // (`waive`, `block`, `block-versions`) plus the read surfaces
    // (`list_queue`, `list_decisions`, `list_exclusions`).
    // Composes:
    //   - `event_publisher` — single per-call audit append site
    //   - `artifact_repo` + `lifecycle` — atomic state-transition write
    //     path through `commit_transition_with_score` (mirrors
    //     `QuarantineUseCase::admin_release`)
    //   - `policy_projections` — held for future per-row deadline
    //     resolution
    //   - the three Pg curation list repos — read surfaces
    let curation_queue_repo = Arc::new(PgCurationQueueRepository::new(db.clone()));
    let curation_decisions_repo = Arc::new(PgCurationDecisionsRepository::new(db.clone()));
    let curation_exclusions_repo = Arc::new(PgCurationExclusionsRepository::new(db.clone()));
    let curation_use_case = Arc::new(
        CurationUseCase::new(
            event_publisher.clone(),
            artifact_repo.clone(),
            lifecycle.clone(),
            policy_projections.clone(),
            curation_queue_repo,
            curation_decisions_repo,
            curation_exclusions_repo,
            // Thread the existing
            // `RepositoryAccessUseCase` so curation emission sites can
            // resolve `repository_id → key` for the
            // `hort_curation_decisions_total{repository}` label. No new
            // port; the helper already encapsulates the
            // `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse and the
            // resolve-failure `unknown` sentinel.
            repository_access_use_case.clone(),
        )
        // Inject the upstream-index cache
        // invalidator. The post-`block_one` hook calls it best-effort
        // after the `ArtifactRejected` append commits; failure logs
        // warn! and does NOT roll back.
        .with_upstream_index_cache_invalidator(upstream_index_cache_invalidator.clone()),
    );

    // `PolicyUseCase` for the HTTP exclusion
    // write surface. Same ports the standalone gitops-boot instance
    // takes (event_publisher, policy_projections, artifact_repo,
    // lifecycle, storage); the runtime AppContext owns its own
    // long-lived Arc so the inbound HTTP handlers can drive
    // `add_exclusion` / `remove_exclusion` on the same event store.
    // The use case signature is permission-neutral; the HTTP edge
    // (`CurateOrAdminPrincipal` extractor on
    // `/api/v1/admin/policies/:policy_id/exclusions`) is the single
    // permission gate for the user-driven surface, leaving the gitops
    // apply pipeline's `Actor::Gitops` call site working unchanged.
    let policy_use_case = Arc::new(PolicyUseCase::new(
        event_publisher.clone(),
        policy_projections.clone(),
        artifact_repo.clone(),
        lifecycle.clone(),
        storage.clone(),
        // Share the same `RepositoryAccessUseCase`
        // the curation use case uses, so `add_exclusion` /
        // `remove_exclusion` resolve `PolicyScope::Repository(id) →
        // key` for the `hort_curation_decisions_total{repository}` label.
        repository_access_use_case.clone(),
        // The post-exclusion re-evaluation pass's active-curation
        // precondition (ADR 0041 invariant #6 (c)) reads live curation
        // rules per artifact's repo via `list_for_repo`.
        curation_rules.clone(),
        // ADR 0041 Item 3: gate-affecting scan-policy mutations
        // (`update_policy` gate fields, `add_exclusion`,
        // `remove_exclusion`, `reactivate_policy`) enqueue ONE async
        // `policy-reevaluation` task; the worker runs the population pass
        // off the request path. Same jobs adapter the ingest scan-enqueue
        // path uses.
        jobs_repo.clone(),
    ));

    // `WheelMetadataUseCase`. Composed over the
    // shared `ArtifactUseCase` (for the visibility hop + the
    // quarantine-deadline hydration on the per-artifact status
    // filter), the existing `content_references` adapter (for the
    // `(repo, source, "wheel_metadata")` PK lookup), and the storage
    // port (for the CAS fetch of the METADATA bytes). The proxy
    // strategy-1 / strategy-2 fallback wraps this use
    // case as the cache-hit path.
    let wheel_metadata_use_case = Arc::new(WheelMetadataUseCase::new(
        artifact_use_case.clone(),
        content_references.clone(),
        storage.clone(),
    ));

    // Trust-config mode string. Operators need the MODE for dashboards
    // — NOT the CIDR values (those are operator secrets / internal-net
    // topology).
    let trust_mode = match (
        trust_config.public_base_url.is_some(),
        !trust_config.trusted_proxy_cidrs.is_empty(),
    ) {
        (true, false) => "public_url_pinned",
        (false, true) => "trusted_proxy_forwarding",
        (true, true) => "BOTH",
        // Unreachable — `hort-server::config::Config` rejects this combo
        // at startup. Defensive fallback keeps the log structured.
        (false, false) => "UNSET",
    };

    // Coarse label for the ephemeral-store backend; the URL is never
    // logged (contains credentials on non-local deployments).
    let ephemeral_backend_label = match ephemeral_store_backend {
        crate::config::EphemeralStoreBackend::Memory => "memory",
        crate::config::EphemeralStoreBackend::Redis => "redis",
    };

    // Per-class startup log lines so
    // operators can see, at boot, which backend each class is wired
    // to. For Redis, a short `url_hash` (SHA-256 prefix of the URL)
    // lets operators correlate "two log lines, same `url_hash`" →
    // single-Redis topology, without leaking credentials. The Memory
    // arm omits the URL hash (no URL).
    match ephemeral_url_hashes.as_ref() {
        Some((evictable_hash, durable_hash)) => {
            tracing::info!(
                class = "evictable",
                backend = ephemeral_backend_label,
                url_hash = evictable_hash,
                "ephemeral_store wired"
            );
            tracing::info!(
                class = "durable",
                backend = ephemeral_backend_label,
                url_hash = durable_hash,
                "ephemeral_store wired"
            );
        }
        None => {
            tracing::info!(
                class = "evictable",
                backend = ephemeral_backend_label,
                "ephemeral_store wired"
            );
            tracing::info!(
                class = "durable",
                backend = ephemeral_backend_label,
                "ephemeral_store wired"
            );
        }
    }

    // Single startup line per `PullDedup`
    // construction. Mirrors the `ephemeral_store wired` precedent above
    // (one line per system, with the operationally-relevant
    // configuration values). The two derived constants
    // (`LAYER_A_CHANNEL_CAPACITY = 64`, `LEADER_LOCK_TTL = 90s`) are
    // not env-tunable; the `follower_wait` knob IS the relevant
    // operator-visible value for the "is my coalescing window long
    // enough?" tuning question.
    tracing::info!(
        layer_a_capacity = 64,
        follower_wait_secs = pull_dedup_config.follower_wait.as_secs(),
        ttl_not_found_secs = pull_dedup_config.ttl_not_found.as_secs(),
        ttl_unavailable_secs = pull_dedup_config.ttl_unavailable.as_secs(),
        ttl_timeout_secs = pull_dedup_config.ttl_timeout.as_secs(),
        ttl_checksum_mismatch_secs = pull_dedup_config.ttl_checksum_mismatch.as_secs(),
        "pull_dedup wired"
    );

    tracing::info!(
        include_repository_label,
        metadata_caps_configured = metadata_caps.len(),
        metadata_blob_max_bytes,
        public_base_url = public_base_url
            .as_ref()
            .map(url::Url::as_str)
            .unwrap_or("<unset>"),
        auth_enabled,
        trust_mode,
        trusted_proxy_cidr_count = trust_config.trusted_proxy_cidrs.len(),
        stateful_upload_staging_dir = %stateful_upload_staging_dir.display(),
        ephemeral_store_backend = ephemeral_backend_label,
        "AppContext built: event_store=PgEventStore, storage=wired, \
         ingest=wired, quarantine=wired, promotion=wired, \
         artifact_metadata=wired, metrics=wired, url_resolver=wired, \
         trust=wired, auth=wired, ref_registry=wired, ref_lifecycle=wired, \
         ref_use_case=wired, artifact_groups=wired, \
         artifact_group_lifecycle=wired, artifact_group_use_case=wired, \
         stateful_upload_staging=wired, content_references=wired, \
         ephemeral_evictable=wired, ephemeral_durable=wired"
    );

    // The data ports are `pub(crate)` on
    // `AppContext` (ADR 0008). Composition uses the `AppContextParts` builder
    // shape; `AppContext::new` does the field-by-field move into
    // the private surface.
    let mut ctx = AppContext::new(AppContextParts {
        repository_use_case,
        artifact_use_case,
        repository_access_use_case,
        virtual_resolution_use_case,
        content_reference_use_case,
        ingest_use_case,
        user_use_case,
        api_token_use_case,
        quarantine_use_case,
        promotion_use_case,
        ref_use_case,
        security_score_use_case,
        task_use_case,
        manual_rescan_use_case,
        patch_candidate_use_case,
        scanner_worker_query_use_case,
        prefetch_use_case,
        effective_permissions_use_case,
        rbac_resolve_use_case,
        // The `WebhookTargetGuard` inside is the real
        // `WebhookNotifier`; `hort-server::http`
        // mounts the `/api/v1/subscriptions` + `/api/v1/events`
        // routes.
        subscription_use_case,
        // Curator decision authority over quarantined /
        // non-terminal artifacts; HTTP decision handlers mount under
        // `/api/v1/admin/curation/...`.
        curation_use_case,
        // HTTP exclusion write surface
        // (`POST/DELETE /api/v1/admin/policies/:policy_id/exclusions[/:cve_id]`)
        // calls into this use case; gitops apply pipeline calls the
        // same use case with `Actor::Gitops`.
        policy_use_case,
        wheel_metadata_use_case,
        storage,
        artifacts: artifact_repo,
        repositories: repo_repo,
        refs: ref_registry,
        ref_lifecycle,
        artifact_group_use_case,
        artifact_groups: artifact_group_repo,
        artifact_group_lifecycle,
        artifact_metadata: artifact_metadata_repo,
        security_scores,
        // Shared
        // `PgJobsRepository` Arc consumed by `TaskUseCase`,
        // `ManualRescanUseCase`, and any future jobs-port consumer.
        jobs: jobs_repo,
        ephemeral_evictable,
        // Raw upstream-metadata mirror (ADR 0026) built from the
        // same `StorageConfig` as `storage` (see the parameter doc above).
        metadata_mirror,
        pull_dedup,
        ephemeral_durable,
        // The `/readyz` HTTP probe pings this
        // handle. The same `Arc<PgEventStore>` already feeds every
        // append/read site above; we expose it on the AppContext
        // so the handler can call `health_check` without needing
        // a separate port.
        event_store: event_publisher.clone(),
        // Multi-issuer JWT validator, see
        // `AppContext::federated_jwt_validator`. `Some(_)` when
        // auth is enabled; `None` otherwise.
        federated_jwt_validator,
        // `ServiceAccountRepository` consumed by
        // the federation branch of `/auth/token-exchange`. `Some(_)`
        // when auth is enabled (paired with the validator above);
        // `None` otherwise.
        service_accounts,
        // `OidcIssuerRepository`
        // shared with the validator; the federation handler resolves
        // the matched issuer's `require_jti` from it. `Some(_)` when
        // auth is enabled; `None` otherwise.
        oidc_issuers,
        // k8s Secret writer for the fallback
        // PAT rotation reconciler. `Some(_)` only when
        // `HORT_K8S_SECRET_WRITER_ENABLED=true` AND `try_in_cluster`
        // succeeded. The boot-error path above already aborted on
        // a partial state, so this slot is fully consistent here.
        k8s_secret_writer,
        stateful_upload_staging,
        content_references,
        repository_upstream_mappings,
        upstream_resolver,
        upstream_proxy,
        policy_projections,
        curation_rules,
        metrics_handle,
        include_repository_label,
        // Wired from
        // `Config::include_service_account_label` (parsed from
        // `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL`). The federation
        // / PAT auth paths read this off `AppContext` when
        // emitting `hort_service_account_authenticated_total`. The
        // rotation handler reads the same flag via its dedicated
        // builder so a Helm operator flipping one env var
        // governs both per-SA emission sites.
        include_service_account_label,
        url_resolver,
        trust_config,
        rate_limit_config,
        concurrency_limit_config,
        http_timeout_config,
        publish_body_limit_bytes,
        upstream_projector_version_object_max_bytes,
        auth,
        extra_trust_anchors,
        // Pass through the optional cache so
        // composition (and not the request path) is the single
        // owner of the cache lifecycle. The auth middleware does
        // NOT consult this slot directly — it reads
        // `pat_over_http_allowed` only; the cache is held alive
        // here (and via the cloned `Arc` inside the
        // `PatValidationUseCase` and the listener task).
        pat_cache,
        pat_over_http_allowed: native_token_config.allow_pat_over_http,
        // `Some(_)` when native tokens enabled AND
        // signing key configured AND auth is `Enabled`. The
        // composition above already gated this; pass through.
        oci_token_exchange: oci_token_exchange_use_case,
        oci_signing_key,
        oci_public_base_url: oci_public_base_url_str,
        // Pass-through. Caller has
        // already validated that the value is `Some(_)` only when
        // every field is non-empty (boot-time fail-closed in
        // `hort-server::config`).
        client_config,
    });

    // Populate the discovery + self-service
    // prefetch use case slots that `AppContext::new` initialised to `None`.
    // Production callers reach these via the `hort-http-discovery` router
    // mounted by `crate::http::build_router_with_oci_config`; the handler
    // call sites `.expect()` the slots (forgetting this call IS the
    // structural composition bug the `.expect()` is meant to surface).
    ctx.with_discovery_use_cases(discovery_use_case, self_service_prefetch_use_case);
    tracing::info!(
        "discovery routes wired: \
         GET /api/v1/repositories/:repo_key/discovery/versions/:package_name, \
         POST /api/v1/repositories/:repo_key/prefetch"
    );

    Ok(BuildAppContextOutput {
        notification_runtime,
        ctx,
        caching_resolver,
        pat_listener: pat_listener_handle,
    })
}

// ---------------------------------------------------------------------------
// The real `WebhookNotifier` (no stub guard) is
// wired into `SubscriptionUseCase` as
// `Arc<dyn WebhookTargetGuard>` and into the dispatcher as
// `Arc<dyn EventNotifier>`. Both trait views point at the same
// `Arc<WebhookNotifier>` allocation — see the construction site near
// the `subscription_use_case` block above.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::config::ConfigError;
    use hort_config::ExtraCaParseError;

    // ----------------------------------------------------------------
    // `resolve_redis_url` + per-class store
    // construction tests.
    //
    // The four edge cases:
    //   1. Per-class URLs distinct → two separate Redis stores. We
    //      assert the resolver returns the right URL string per class;
    //      the actual `RedisEphemeralStore::connect` call is exercised
    //      by integration tests (it requires a live Redis).
    //   2. Per-class URLs equal (or main `HORT_REDIS_URL` only) → the
    //      composition root constructs ONE store and `Arc::clone`s it
    //      into two wrappers. Tested as a pure URL-equality check at
    //      the resolver layer.
    //   3. Per-class URL unset, main `HORT_REDIS_URL` set → fallback
    //      chain hands the main URL to both classes.
    //   4. Memory backend constructs two distinct
    //      `InMemoryEphemeralStore` instances regardless of any Redis
    //      env-var state.
    // ----------------------------------------------------------------

    #[test]
    fn resolve_redis_url_per_class_distinct_returns_per_class_urls() {
        let main = Some("redis://main:6379/0".to_string());
        let evictable = Some("redis://evict:6379/0".to_string());
        let durable = Some("redis://durable:6379/0".to_string());
        let evictable_resolved = resolve_redis_url(
            evictable.as_ref(),
            main.as_ref(),
            "HORT_REDIS_URL_EVICTABLE",
        )
        .expect("evictable should resolve");
        let durable_resolved =
            resolve_redis_url(durable.as_ref(), main.as_ref(), "HORT_REDIS_URL_DURABLE")
                .expect("durable should resolve");
        assert_eq!(evictable_resolved, "redis://evict:6379/0");
        assert_eq!(durable_resolved, "redis://durable:6379/0");
        assert_ne!(evictable_resolved, durable_resolved);
    }

    #[test]
    fn resolve_redis_url_equal_urls_share_inner_store_via_string_equality() {
        // Case 2 / case 3 single-Redis: when the per-class
        // overrides are absent and `redis_url` is set (OR when both
        // overrides equal the main URL), the resolver returns the
        // SAME `&str` for both classes. The composition-root
        // construction path uses `evictable_url == durable_url` as the
        // pivot to construct one underlying store and share its `Arc`
        // across two wrappers.
        let main = Some("redis://main:6379/0".to_string());
        let evictable_resolved = resolve_redis_url(None, main.as_ref(), "HORT_REDIS_URL_EVICTABLE")
            .expect("evictable should resolve to main");
        let durable_resolved = resolve_redis_url(None, main.as_ref(), "HORT_REDIS_URL_DURABLE")
            .expect("durable should resolve to main");
        assert_eq!(evictable_resolved, durable_resolved);
        assert_eq!(evictable_resolved, "redis://main:6379/0");
    }

    #[test]
    fn resolve_redis_url_per_class_unset_falls_back_to_main() {
        // Case 3 — `HORT_REDIS_URL=Some(A)`,
        // `HORT_REDIS_URL_EVICTABLE=None`, `HORT_REDIS_URL_DURABLE=None`
        // → both resolve to `A`.
        let main = Some("redis://only:6379/0".to_string());
        assert_eq!(
            resolve_redis_url(None, main.as_ref(), "HORT_REDIS_URL_EVICTABLE").unwrap(),
            "redis://only:6379/0"
        );
        assert_eq!(
            resolve_redis_url(None, main.as_ref(), "HORT_REDIS_URL_DURABLE").unwrap(),
            "redis://only:6379/0"
        );
    }

    #[test]
    fn resolve_redis_url_main_unset_per_class_only_evictable_returns_missing_for_durable() {
        // Case 1 — `HORT_REDIS_URL=None`,
        // `HORT_REDIS_URL_EVICTABLE=Some(B)`, `HORT_REDIS_URL_DURABLE=None`
        // → durable resolution fails because the chain breaks.
        // Operators get a clear actionable error naming the per-class
        // env var they failed to set.
        let evictable = Some("redis://evict:6379/0".to_string());
        let evictable_resolved =
            resolve_redis_url(evictable.as_ref(), None, "HORT_REDIS_URL_EVICTABLE")
                .expect("evictable should still resolve via its own override");
        assert_eq!(evictable_resolved, "redis://evict:6379/0");

        let durable_err = resolve_redis_url(None, None, "HORT_REDIS_URL_DURABLE")
            .expect_err("durable resolution should fail");
        match durable_err {
            ConfigError::MissingRedisUrl(var) => {
                assert_eq!(var, "HORT_REDIS_URL_DURABLE");
            }
            other => panic!("expected MissingRedisUrl, got {other:?}"),
        }
    }

    #[test]
    fn resolve_redis_url_all_unset_returns_missing() {
        // Every URL slot empty → the resolver fails with the named
        // per-class var. Operators see WHICH class they failed to
        // configure; the chain "or HORT_REDIS_URL" hint lives in the
        // error's display message.
        let err = resolve_redis_url(None, None, "HORT_REDIS_URL_EVICTABLE")
            .expect_err("must fail when both primary and fallback are absent");
        match err {
            ConfigError::MissingRedisUrl(var) => assert_eq!(var, "HORT_REDIS_URL_EVICTABLE"),
            other => panic!("expected MissingRedisUrl, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn memory_backend_constructs_two_distinct_stores() {
        // Case 4 — Memory backend always builds two distinct
        // `InMemoryEphemeralStore` instances. Verify by writing to
        // one and reading from the other; the cross-class read must
        // miss.
        use hort_app::ephemeral_keyspace::EphemeralKeyspaceClass;
        use hort_domain::ports::ephemeral_store::EphemeralStore;
        let evictable: Arc<dyn EphemeralStore> = Arc::new(MeteredMemEphemeralStore::new(
            Arc::new(InMemoryEphemeralStore::new()),
            EphemeralKeyspaceClass::Evictable,
        ));
        let durable: Arc<dyn EphemeralStore> = Arc::new(MeteredMemEphemeralStore::new(
            Arc::new(InMemoryEphemeralStore::new()),
            EphemeralKeyspaceClass::Durable,
        ));
        // Distinct vtable+data pointers. The `dyn` Arcs print as
        // wide pointers — `Arc::as_ptr` returns `*const dyn …`;
        // pointer equality across two `Arc::new(...)` calls
        // distinguishes the two stores at the `Arc` level too.
        assert!(!Arc::ptr_eq(&evictable, &durable));

        // Behavioural distinctness: write to evictable, read from
        // durable, see `None`.
        let key = "cargo_index_proj:test:smoke";
        evictable
            .put(
                key,
                axum::body::Bytes::from_static(b"value"),
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(
            durable.get(key).await.unwrap().is_none(),
            "write to evictable must NOT be visible from durable"
        );
        assert!(
            evictable.get(key).await.unwrap().is_some(),
            "write to evictable must be visible from evictable"
        );
    }

    #[test]
    fn url_hash_is_deterministic_and_short() {
        // The startup-log `url_hash` field must (a) be deterministic
        // for a given URL and (b) be a short, fixed-width hex string
        // operators can eyeball at a glance. 8 hex chars = 32 bits.
        let h1 = url_hash("redis://main:6379/0");
        let h2 = url_hash("redis://main:6379/0");
        assert_eq!(h1, h2, "url_hash must be deterministic");
        assert_eq!(h1.len(), 8, "url_hash must be 8 hex chars");
        assert!(
            h1.chars().all(|c| c.is_ascii_hexdigit()),
            "url_hash must be lowercase hex: {h1}"
        );

        // Different URLs → different hashes (overwhelmingly
        // likely; SHA-256 prefix collisions are negligible at this
        // length for the topology-correlation use case).
        let h3 = url_hash("redis://other:6379/0");
        assert_ne!(h1, h3, "different URLs must produce different hashes");
    }

    // The same single-cert PEM used in hort-config's unit tests — a real
    // EC certificate that `CertificateDer::pem_slice_iter` can parse.
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBpTCCAUugAwIBAgIUYmFzZTY0ZW5jb2RlZHRlc3RjYTEwCgYIKoZIzj0EAwIw\n\
        EjEQMA4GA1UEAxMHdGVzdC1jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw\n\
        MDBaMBIxEDAOBgNVBAMTB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n\
        AATat5eKpAEqhlMHpj9T3ZKkV1hLFCNYmplq9R1j5kQQHRiuyp8l0p4FKT8EiERQ\n\
        VGMcKaW8LBrrkAk9yTU1o2MwYTAdBgNVHQ4EFgQUHoxGqEhOInnMtNqg9j94JCXB\n\
        gMYwHwYDVR0jBBgwFoAUHoxGqEhOInnMtNqg9j94JCXBgMYwDwYDVR0TAQH/BAUw\n\
        AwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAKmfOFG4ULWX\n\
        4aT3iqFWbUTRaJ7E2tXa9r02m3qLk9gxAiB8kqIb6X/s8cLEFEEwE2RpTaqaXWrd\n\
        vz2f0FxvxGJi1Q==\n\
        -----END CERTIFICATE-----\n";

    #[test]
    fn unset_env_returns_none() {
        // `temp_env::with_var` restores the original state on exit, even on
        // panic. `None` removes the var for the duration of the closure.
        temp_env::with_var("HORT_EXTRA_CA_BUNDLE", None::<&str>, || {
            let result = read_extra_ca_bundle();
            assert!(result.is_ok(), "unset env should be Ok: {result:?}");
            assert!(result.unwrap().is_none(), "unset env should return None");
        });
    }

    #[test]
    fn set_env_valid_pem_file_returns_some_with_right_count() {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        tmp.write_all(CERT_PEM.as_bytes()).expect("write cert");
        let path = tmp.path().to_str().expect("utf8 path").to_string();

        temp_env::with_var("HORT_EXTRA_CA_BUNDLE", Some(path.as_str()), || {
            let result = read_extra_ca_bundle().expect("should parse ok");
            let anchors = result.expect("should be Some");
            assert_eq!(anchors.cert_count(), 1, "expected one cert");
        });
    }

    #[test]
    fn set_env_nonexistent_path_returns_unreadable_error() {
        temp_env::with_var(
            "HORT_EXTRA_CA_BUNDLE",
            Some("/nonexistent/path/ca.pem"),
            || {
                let err = read_extra_ca_bundle().expect_err("should fail on missing file");
                assert!(
                    matches!(err, ConfigError::ExtraCaUnreadable { .. }),
                    "expected ExtraCaUnreadable, got {err:?}",
                );
            },
        );
    }

    #[test]
    fn set_env_non_cert_content_returns_parse_error_empty() {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        // Write content that has no CERTIFICATE PEM blocks → Empty error.
        tmp.write_all(b"this is not a PEM file").expect("write");
        let path = tmp.path().to_str().expect("utf8 path").to_string();

        temp_env::with_var("HORT_EXTRA_CA_BUNDLE", Some(path.as_str()), || {
            let err = read_extra_ca_bundle().expect_err("should fail on non-cert content");
            assert!(
                matches!(
                    err,
                    ConfigError::ExtraCaParse {
                        source: ExtraCaParseError::Empty,
                        ..
                    }
                ),
                "expected ExtraCaParse(Empty), got {err:?}",
            );
        });
    }

    #[test]
    fn set_env_malformed_pem_returns_parse_error_pem_variant() {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        // A PEM header with corrupted base64 body.
        tmp.write_all(
            b"-----BEGIN CERTIFICATE-----\nnot_valid_base64!!!\n-----END CERTIFICATE-----\n",
        )
        .expect("write");
        let path = tmp.path().to_str().expect("utf8 path").to_string();

        temp_env::with_var("HORT_EXTRA_CA_BUNDLE", Some(path.as_str()), || {
            let err = read_extra_ca_bundle().expect_err("should fail on malformed PEM");
            assert!(
                matches!(
                    err,
                    ConfigError::ExtraCaParse {
                        source: ExtraCaParseError::Pem(_),
                        ..
                    }
                ),
                "expected ExtraCaParse(Pem(_)), got {err:?}",
            );
        });
    }

    // -- Extra-CA boot observability tests ------------------------------------
    //
    // The boot-time gauge + counter live on `read_extra_ca_bundle`. Each
    // test scopes a `DebuggingRecorder` via `with_local_recorder` so
    // assertions are isolated from any other test's emissions. Snapshots
    // are inspected via `metrics_util::CompositeKey` → label match.

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    /// Locate a metric of the given `kind` + `name` whose labels are a
    /// superset of `expected`. Returns a borrowed reference into
    /// `entries` (DebugValue is not Clone in metrics-util 0.20).
    fn find_metric<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != kind || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    /// Helper: scope a recorder, run `f`, return the captured entries.
    fn capture<F>(f: F) -> Vec<MetricEntry>
    where
        F: FnOnce(),
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    #[test]
    fn unset_env_emits_anchors_zero_gauge_and_ok_counter() {
        let entries = capture(|| {
            temp_env::with_var("HORT_EXTRA_CA_BUNDLE", None::<&str>, || {
                let _ = read_extra_ca_bundle().expect("unset must be Ok");
            });
        });
        let gauge = find_metric(&entries, MetricKind::Gauge, EXTRA_CA_ANCHORS_METRIC, &[])
            .expect("hort_extra_ca_anchors gauge must fire on unset path");
        match gauge {
            DebugValue::Gauge(v) => {
                assert!(
                    (f64::from(*v) - 0.0_f64).abs() < f64::EPSILON,
                    "unset path must set gauge to 0.0, got {v:?}",
                );
            }
            other => panic!("expected gauge, got {other:?}"),
        }
        let counter = find_metric(
            &entries,
            MetricKind::Counter,
            EXTRA_CA_LOAD_METRIC,
            &[("result", EXTRA_CA_LOAD_RESULT_OK)],
        )
        .expect("hort_extra_ca_load_total{result=ok} must fire on unset path");
        assert!(matches!(counter, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn loaded_bundle_emits_anchors_count_gauge_and_ok_counter() {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        tmp.write_all(CERT_PEM.as_bytes()).expect("write cert");
        let path = tmp.path().to_str().expect("utf8 path").to_string();
        let entries = capture(|| {
            temp_env::with_var("HORT_EXTRA_CA_BUNDLE", Some(path.as_str()), || {
                let result = read_extra_ca_bundle().expect("should parse ok");
                assert!(result.is_some());
            });
        });
        let gauge = find_metric(&entries, MetricKind::Gauge, EXTRA_CA_ANCHORS_METRIC, &[])
            .expect("hort_extra_ca_anchors gauge must fire on success path");
        match gauge {
            DebugValue::Gauge(v) => {
                assert!(
                    (f64::from(*v) - 1.0_f64).abs() < f64::EPSILON,
                    "loaded-bundle gauge must be 1.0 (one cert in CERT_PEM), got {v:?}",
                );
            }
            other => panic!("expected gauge, got {other:?}"),
        }
        let counter = find_metric(
            &entries,
            MetricKind::Counter,
            EXTRA_CA_LOAD_METRIC,
            &[("result", EXTRA_CA_LOAD_RESULT_OK)],
        )
        .expect("hort_extra_ca_load_total{result=ok} must fire on success path");
        assert!(matches!(counter, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn unreadable_path_emits_unreadable_counter_and_no_gauge_change() {
        let entries = capture(|| {
            temp_env::with_var(
                "HORT_EXTRA_CA_BUNDLE",
                Some("/nonexistent/path/ca.pem"),
                || {
                    let err = read_extra_ca_bundle().expect_err("should fail on missing file");
                    assert!(matches!(err, ConfigError::ExtraCaUnreadable { .. }));
                },
            );
        });
        let counter = find_metric(
            &entries,
            MetricKind::Counter,
            EXTRA_CA_LOAD_METRIC,
            &[("result", EXTRA_CA_LOAD_RESULT_UNREADABLE)],
        )
        .expect("hort_extra_ca_load_total{result=unreadable} must fire on fs::read failure");
        assert!(matches!(counter, DebugValue::Counter(n) if *n == 1));
        // Gauge intentionally not set on the failure path — the previous
        // value (or the default zero before any boot) stays put. We
        // assert the gauge metric is absent from this scope's snapshot,
        // which proves the failure handler never touched it.
        assert!(
            find_metric(&entries, MetricKind::Gauge, EXTRA_CA_ANCHORS_METRIC, &[]).is_none(),
            "gauge must NOT be set on the unreadable failure path",
        );
        // Sanity: the OK label must NOT have fired in the same scope.
        assert!(
            find_metric(
                &entries,
                MetricKind::Counter,
                EXTRA_CA_LOAD_METRIC,
                &[("result", EXTRA_CA_LOAD_RESULT_OK)],
            )
            .is_none(),
            "ok counter must NOT fire when fs::read fails",
        );
    }

    #[test]
    fn parse_failed_emits_parse_failed_counter_and_no_gauge_change() {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        tmp.write_all(b"this is not a PEM file").expect("write");
        let path = tmp.path().to_str().expect("utf8 path").to_string();
        let entries = capture(|| {
            temp_env::with_var("HORT_EXTRA_CA_BUNDLE", Some(path.as_str()), || {
                let err = read_extra_ca_bundle().expect_err("should fail on non-cert content");
                assert!(matches!(err, ConfigError::ExtraCaParse { .. }));
            });
        });
        let counter = find_metric(
            &entries,
            MetricKind::Counter,
            EXTRA_CA_LOAD_METRIC,
            &[("result", EXTRA_CA_LOAD_RESULT_PARSE_FAILED)],
        )
        .expect("hort_extra_ca_load_total{result=parse_failed} must fire on PEM-parse failure");
        assert!(matches!(counter, DebugValue::Counter(n) if *n == 1));
        assert!(
            find_metric(&entries, MetricKind::Gauge, EXTRA_CA_ANCHORS_METRIC, &[]).is_none(),
            "gauge must NOT be set on the parse-failed path",
        );
    }

    // -- emit_pat_over_http_signal ---------------------------------------

    /// Safe-path emission: gauge is set to `0.0`. The `false` branch
    /// is the default boot posture; we set the gauge anyway so a
    /// fresh scrape sees the metric and dashboards can distinguish
    /// "feature not registered" from "feature OFF".
    #[test]
    fn emit_pat_over_http_signal_sets_gauge_to_zero_when_not_allowed() {
        let entries = capture(|| {
            emit_pat_over_http_signal(false);
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            "hort_unsafe_config_active",
            &[("kind", "pat_over_http")],
        )
        .expect("gauge must fire even on the safe path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!(f.abs() < f64::EPSILON, "expected 0.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    /// Unsafe-path emission: gauge is set to `1.0`. Dashboards alarm
    /// on any non-zero value for this gauge (per the catalog entry).
    #[test]
    fn composition_emits_unsafe_config_gauge_when_pat_over_http_enabled() {
        let entries = capture(|| {
            emit_pat_over_http_signal(true);
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            "hort_unsafe_config_active",
            &[("kind", "pat_over_http")],
        )
        .expect("gauge must fire on the unsafe path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    /// Boundary-case for the NativeTokenConfig wiring decisions: the
    /// PAT path should be entirely cold under the default RC posture.
    /// `from_env`'s default is `enabled = false`, which we pin here
    /// so a future change to that default fails this test loudly.
    #[test]
    fn native_token_config_default_is_off() {
        // Mirrors the from_env defaults in `Config`; pinned so a
        // refactor that flips the RC default trips this assertion
        // and forces an updated catalog/migration plan.
        let cfg = NativeTokenConfig {
            enabled: false,
            allow_pat_over_http: false,
            cache_size: 10_000,
            lockout_threshold: 30,
            lockout_window_secs: 300,
            lockout_duration_secs: 900,
            allow_admin_tokens: false,
            allow_unbounded_svc_tokens: false,
            // Fixtures default to no signing key wired.
            oci_token_signing_key_pem: None,
            oci_token_signing_key_prev_pem: None,
        };
        assert!(!cfg.enabled);
        assert!(!cfg.allow_pat_over_http);
    }

    /// Symmetric: a flipped flag struct represents the operator
    /// opt-in posture. The gauge emission test above pairs with this
    /// to confirm the wiring and the boot signal stay in sync.
    #[test]
    fn native_token_config_enabled_flag_round_trips() {
        let cfg = NativeTokenConfig {
            enabled: true,
            allow_pat_over_http: true,
            cache_size: 100,
            lockout_threshold: 30,
            lockout_window_secs: 300,
            lockout_duration_secs: 900,
            allow_admin_tokens: false,
            allow_unbounded_svc_tokens: false,
            // Fixtures default to no signing key wired.
            oci_token_signing_key_pem: None,
            oci_token_signing_key_prev_pem: None,
        };
        // The `Option<String>` PEM fields preclude
        // a `Copy` impl; the wiring contract is `Clone`-cheap.
        let cfg2 = cfg.clone();
        assert_eq!(cfg.enabled, cfg2.enabled);
        assert_eq!(cfg.allow_pat_over_http, cfg2.allow_pat_over_http);
    }

    // -- evaluate_test_clock_guard ----------------------------------------
    //
    // Boot-time guardrail for the deliberate test-clock auth-bypass
    // primitive (auth-catalog Entry 10). Mirrors the
    // `emit_pat_over_http_signal` precedent: the gauge fires on every
    // path so dashboards can distinguish OFF from "not registered",
    // and the unsafe combination (enabled at runtime but the
    // `test-clock` cargo feature was NOT compiled in — the release-
    // build condition) returns a hard-fail decision so boot refuses.

    /// Safe-path emission: `HORT_TEST_CLOCK_ENABLED` not set →
    /// `hort_unsafe_config_active{kind=test_clock}` is `0.0` and the
    /// guard returns `Ok(())` (boot proceeds normally). The `false`
    /// branch sets the gauge anyway so a fresh scrape sees the metric.
    #[test]
    fn evaluate_test_clock_guard_gauge_zero_and_ok_when_disabled() {
        let mut decision: Option<Result<(), hort_domain::error::DomainError>> = None;
        let entries = capture(|| {
            // feature_built value is irrelevant when disabled.
            decision = Some(evaluate_test_clock_guard(false, false));
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            "hort_unsafe_config_active",
            &[("kind", "test_clock")],
        )
        .expect("gauge must fire even on the safe path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!(f.abs() < f64::EPSILON, "expected 0.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
        assert!(
            matches!(decision, Some(Ok(()))),
            "disabled posture must boot normally, got {decision:?}"
        );
    }

    /// Unsafe-path: `HORT_TEST_CLOCK_ENABLED=true` while the `test-clock`
    /// cargo feature was NOT compiled in (the release-build / no-
    /// feature condition). Gauge is `1.0` AND the guard
    /// returns a hard-fail `Err` so the composition root refuses to
    /// boot. Mirrors auth-catalog Entry 10's mandatory guardrail.
    #[test]
    fn evaluate_test_clock_guard_gauge_one_and_hard_fail_when_enabled_without_feature() {
        let mut decision: Option<Result<(), hort_domain::error::DomainError>> = None;
        let entries = capture(|| {
            decision = Some(evaluate_test_clock_guard(true, false));
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            "hort_unsafe_config_active",
            &[("kind", "test_clock")],
        )
        .expect("gauge must fire on the unsafe path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
        match decision {
            Some(Err(hort_domain::error::DomainError::Invariant(msg))) => {
                assert!(
                    msg.contains("HORT_TEST_CLOCK_ENABLED"),
                    "hard-fail message must name the misconfiguration, got: {msg}"
                );
            }
            other => panic!("expected a hard-fail Invariant Err, got {other:?}"),
        }
    }

    /// Feature-built path: `HORT_TEST_CLOCK_ENABLED=true` AND the
    /// `test-clock` cargo feature WAS compiled in (a deliberate test-
    /// harness build). Gauge is still `1.0` (it is an unsafe opt-in
    /// regardless of the build) but the guard returns `Ok(())` —
    /// boot proceeds because the double gate is intact.
    #[test]
    fn evaluate_test_clock_guard_gauge_one_and_ok_when_enabled_with_feature() {
        let mut decision: Option<Result<(), hort_domain::error::DomainError>> = None;
        let entries = capture(|| {
            decision = Some(evaluate_test_clock_guard(true, true));
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            "hort_unsafe_config_active",
            &[("kind", "test_clock")],
        )
        .expect("gauge must fire on the enabled+feature path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
        assert!(
            matches!(decision, Some(Ok(()))),
            "enabled+feature-built keeps the double gate intact and must boot, got {decision:?}"
        );
    }

    // -- emit_staging_sweep_liveness_signal --------------------------------
    //
    // Boot-time staging-sweep liveness signal. The pure overdue
    // decision is unit-tested exhaustively in
    // `hort_domain::policy::staging_sweep_liveness`; these tests pin only
    // the composition-shell behaviour: the `hort_staging_sweep_overdue`
    // gauge fires `0.0` on the healthy path and `1.0` on the
    // overdue / never-ran paths (so a fresh scrape always sees the
    // series), with NO labels.

    /// Healthy path: a sweep completed well within the staleness window
    /// → gauge `0.0`, no-label series.
    #[test]
    fn emit_staging_sweep_liveness_signal_gauge_zero_when_healthy() {
        let now = chrono::Utc::now();
        let last = now - chrono::Duration::seconds(60);
        let entries = capture(|| {
            emit_staging_sweep_liveness_signal(
                Some(last),
                now,
                std::time::Duration::from_secs(300),
                3,
            );
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            STAGING_SWEEP_OVERDUE_METRIC,
            &[],
        )
        .expect("hort_staging_sweep_overdue must fire on the healthy path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!(f.abs() < f64::EPSILON, "expected 0.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    /// Overdue path: last sweep older than `multiplier × interval` →
    /// gauge `1.0`.
    #[test]
    fn emit_staging_sweep_liveness_signal_gauge_one_when_overdue() {
        let now = chrono::Utc::now();
        // 1 hour old; window = 300 s × 3 = 900 s → overdue.
        let last = now - chrono::Duration::seconds(3600);
        let entries = capture(|| {
            emit_staging_sweep_liveness_signal(
                Some(last),
                now,
                std::time::Duration::from_secs(300),
                3,
            );
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            STAGING_SWEEP_OVERDUE_METRIC,
            &[],
        )
        .expect("hort_staging_sweep_overdue must fire on the overdue path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    /// Never-ran path: `None` (no completed sweep on record) → gauge
    /// `1.0` (the canonical "upgraded without enabling the CronJob"
    /// case the audit flags).
    #[test]
    fn emit_staging_sweep_liveness_signal_gauge_one_when_never_ran() {
        let now = chrono::Utc::now();
        let entries = capture(|| {
            emit_staging_sweep_liveness_signal(None, now, std::time::Duration::from_secs(300), 3);
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            STAGING_SWEEP_OVERDUE_METRIC,
            &[],
        )
        .expect("hort_staging_sweep_overdue must fire on the never-ran path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    // -- emit_event_chain_verify_liveness_signal ----------------------------
    //
    // Boot-time event-chain-verifier liveness signal. The pure overdue
    // decision is unit-tested exhaustively in
    // `hort_domain::policy::event_chain_verify_liveness`; these tests pin
    // only the composition-shell behaviour: the
    // `hort_event_chain_verify_overdue` gauge fires `0.0` on the healthy
    // path and `1.0` on the overdue / never-ran paths (so a fresh scrape
    // always sees the series), with NO labels. Mirrors the
    // `emit_staging_sweep_liveness_signal_gauge_*` trio above.

    /// Healthy path: a verify run completed well within the staleness
    /// window → gauge `0.0`, no-label series.
    #[test]
    fn emit_event_chain_verify_liveness_signal_gauge_zero_when_healthy() {
        let now = chrono::Utc::now();
        let last = now - chrono::Duration::seconds(60);
        let entries = capture(|| {
            emit_event_chain_verify_liveness_signal(
                Some(last),
                now,
                std::time::Duration::from_secs(86_400),
                3,
            );
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            EVENT_CHAIN_VERIFY_OVERDUE_METRIC,
            &[],
        )
        .expect("hort_event_chain_verify_overdue must fire on the healthy path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!(f.abs() < f64::EPSILON, "expected 0.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    /// Overdue path: last verify run older than `multiplier × interval` →
    /// gauge `1.0`.
    #[test]
    fn emit_event_chain_verify_liveness_signal_gauge_one_when_overdue() {
        let now = chrono::Utc::now();
        // 5 days old; window = 86400 s × 3 = 259200 s (3 days) → overdue.
        let last = now - chrono::Duration::seconds(432_000);
        let entries = capture(|| {
            emit_event_chain_verify_liveness_signal(
                Some(last),
                now,
                std::time::Duration::from_secs(86_400),
                3,
            );
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            EVENT_CHAIN_VERIFY_OVERDUE_METRIC,
            &[],
        )
        .expect("hort_event_chain_verify_overdue must fire on the overdue path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    /// Never-ran path: `None` (no completed verify run on record) → gauge
    /// `1.0` (the canonical "verifier ships CLI-only and was never
    /// scheduled" case the audit flags).
    #[test]
    fn emit_event_chain_verify_liveness_signal_gauge_one_when_never_ran() {
        let now = chrono::Utc::now();
        let entries = capture(|| {
            emit_event_chain_verify_liveness_signal(
                None,
                now,
                std::time::Duration::from_secs(86_400),
                3,
            );
        });
        let gauge = find_metric(
            &entries,
            MetricKind::Gauge,
            EVENT_CHAIN_VERIFY_OVERDUE_METRIC,
            &[],
        )
        .expect("hort_event_chain_verify_overdue must fire on the never-ran path");
        match gauge {
            DebugValue::Gauge(v) => {
                let f: f64 = (*v).into();
                assert!((f - 1.0).abs() < f64::EPSILON, "expected 1.0, got {f}");
            }
            other => panic!("expected gauge, got {other:?}"),
        }
    }

    // -- derive_oci_token_endpoint_strings ---------------------------------
    //
    // The boot-fail surface for the OCI `/v2/auth` endpoint binding;
    // a silent fallback to `localhost`
    // aud + relative `/v2/auth` iss would issue unconsumable JWTs.
    // The helper is the seam where
    // those fallbacks are forbidden — every test below pins a branch.

    /// Happy path: `https://hort.example.com` parses → issuer
    /// `https://hort.example.com/v2/auth`, audience `hort.example.com`.
    #[test]
    fn derive_oci_token_endpoint_strings_happy_path_https() {
        let url: url::Url = "https://hort.example.com".parse().unwrap();
        let (issuer, aud) =
            derive_oci_token_endpoint_strings(Some(&url)).expect("happy path must succeed");
        assert_eq!(issuer, "https://hort.example.com/v2/auth");
        assert_eq!(aud, "hort.example.com");
    }

    /// Trailing slash on the public-base URL must NOT produce
    /// `//v2/auth` (double-slash). The helper trims it; this is the
    /// only piece of normalisation it owns.
    #[test]
    fn derive_oci_token_endpoint_strings_trims_trailing_slash() {
        let url: url::Url = "https://hort.example.com/".parse().unwrap();
        let (issuer, _) = derive_oci_token_endpoint_strings(Some(&url)).expect("ok");
        assert_eq!(issuer, "https://hort.example.com/v2/auth");
        assert!(!issuer.contains("//v2/auth"));
    }

    /// HTTP scheme is accepted (operator may run behind a TLS-terminating
    /// proxy with `http://internal-host` as the canonical URL).
    #[test]
    fn derive_oci_token_endpoint_strings_accepts_http_scheme() {
        let url: url::Url = "http://internal-host:8080".parse().unwrap();
        let (issuer, aud) = derive_oci_token_endpoint_strings(Some(&url)).expect("ok");
        assert_eq!(issuer, "http://internal-host:8080/v2/auth");
        // `host_str` strips the port, which is the spec-correct shape:
        // OCI clients echo `service=<hostname>`, never `service=<hostname:port>`.
        assert_eq!(aud, "internal-host");
    }

    /// **Boot-fail trigger.** `public_base_url = None` MUST surface
    /// as `ConfigError::OciPublicBaseUrlMissing`. This is the regression
    /// guard against a silent `localhost` fallback.
    #[test]
    fn derive_oci_token_endpoint_strings_fails_when_url_missing() {
        let err = derive_oci_token_endpoint_strings(None).expect_err("must boot-fail");
        assert!(
            matches!(err, ConfigError::OciPublicBaseUrlMissing),
            "expected OciPublicBaseUrlMissing, got {err:?}"
        );
    }

    /// A URL form that parses but has no host component (e.g. a bare
    /// path `data:` URL — which `url::Url::parse` accepts) MUST also
    /// boot-fail with the same variant. We surface one variant, not two,
    /// because both modes mean "no consumable hostname for the JWT aud".
    #[test]
    fn derive_oci_token_endpoint_strings_fails_when_url_has_no_host() {
        // `data:` URLs parse but carry no host. Use one as a proxy
        // for "URL parsed yet no host_str".
        let url: url::Url = "data:text/plain,hi".parse().unwrap();
        assert!(url.host_str().is_none(), "fixture invariant");
        let err =
            derive_oci_token_endpoint_strings(Some(&url)).expect_err("hostless URL must boot-fail");
        assert!(
            matches!(err, ConfigError::OciPublicBaseUrlMissing),
            "expected OciPublicBaseUrlMissing, got {err:?}"
        );
    }

    /// Sanity: the helper's success path embeds the URL host EXACTLY,
    /// no extra trimming. A subdomain'd URL stays subdomain'd in `aud`.
    #[test]
    fn derive_oci_token_endpoint_strings_preserves_subdomain_host() {
        let url: url::Url = "https://reg.team.hort.example.com".parse().unwrap();
        let (issuer, aud) = derive_oci_token_endpoint_strings(Some(&url)).expect("ok");
        assert_eq!(aud, "reg.team.hort.example.com");
        assert_eq!(issuer, "https://reg.team.hort.example.com/v2/auth");
    }

    // -- evaluate_quarantine_posture ---------------------------------------
    //
    // A structured boot-time posture log that mirrors
    // the `evaluate_test_clock_guard` `pub(crate)` + structured-verdict
    // shape. The helper:
    //   - Always reports `DefaultPolicy::quarantine_duration_secs()` —
    //     the const (pinned 86_400) drives the
    //     out-of-the-box hold.
    //   - Counts active operator `ScanPolicy` rows whose
    //     `quarantine_duration_secs == 0` (explicit-permissive overrides);
    //     this is the `warn!` condition when `> 0`.
    //   - Counts upstream mappings with
    //     `trust_upstream_publish_time = true` (per-upstream opt-in to
    //     publish-time anchoring); pure `info!`-level visibility.
    //
    // Tests assert the structured verdict (the value the helper
    // returns); the log emission itself is best-effort observability
    // and is exercised by the `match { … }` branches at the call site,
    // which a unit test cannot meaningfully spy on without a tracing
    // subscriber harness — out of scope here (no
    // new metric; the verdict is the testable surface).

    /// Helper to build a `ScanPolicyProjection` fixture with controllable
    /// `quarantine_duration_secs` and `archived`. Mirrors the
    /// `projection(...)` helper in `hort-domain/src/policy/scan.rs`'s
    /// own test module.
    fn make_scan_policy(
        quarantine_duration_secs: i64,
        archived: bool,
    ) -> hort_domain::entities::scan_policy::ScanPolicyProjection {
        use hort_domain::entities::scan_policy::{
            NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
        };
        use hort_domain::events::PolicyScope;
        ScanPolicyProjection {
            policy_id: uuid::Uuid::new_v4(),
            name: "fixture".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Helper to build a `RepositoryUpstreamMapping` fixture with a
    /// controllable `trust_upstream_publish_time`. Struct-literal
    /// construction is supported per the entity's docstring — "Test
    /// scaffolding across the workspace continues to use struct-literal
    /// construction for brevity" (`crates/hort-domain/src/ports/
    /// repository_upstream_mapping_repository.rs:308`).
    fn make_upstream_mapping(
        trust_upstream_publish_time: bool,
    ) -> hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };
        RepositoryUpstreamMapping {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path_prefix: String::new(),
            upstream_url: "https://registry.example.com".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Pure-default case: no operator `ScanPolicy` rows at all and no
    /// publish-time opt-in mappings. The verdict reports the
    /// `DefaultPolicy` window value, zero permissive overrides, zero
    /// opt-ins — the "info!-level" branch (no `warn!`-worthy fact).
    #[test]
    fn evaluate_quarantine_posture_no_policies_no_optins_is_default_quarantining() {
        let posture = evaluate_quarantine_posture(&[], &[]);
        // Mirrors the `DefaultPolicy::quarantine_duration_secs_is_86_400`
        // pin in `hort-domain/src/policy/scan.rs` — if that constant is
        // ever flipped back to permissive, this test fails LOUD here too.
        assert_eq!(
            posture.default_quarantine_duration_secs,
            hort_domain::policy::scan::DefaultPolicy::quarantine_duration_secs(),
        );
        assert_eq!(posture.default_quarantine_duration_secs, 86_400);
        assert_eq!(posture.permissive_operator_policy_count, 0);
        assert_eq!(posture.trust_upstream_publish_time_count, 0);
    }

    /// Permissive-override case: two active operator `ScanPolicy` rows
    /// set `quarantineDuration: 0` (the explicit operator opt-out
    /// honoured by `ingest_inner`'s `Some(0)` arm). The count surfaces;
    /// the `default_quarantine_duration_secs` value is unchanged (an
    /// operator override does not move the Default const).
    #[test]
    fn evaluate_quarantine_posture_counts_permissive_operator_overrides() {
        let policies = vec![
            make_scan_policy(0, false),      // permissive override #1
            make_scan_policy(0, false),      // permissive override #2
            make_scan_policy(3_600, false),  // 1-hour hold — NOT permissive
            make_scan_policy(86_400, false), // explicit Default — NOT permissive
        ];
        let posture = evaluate_quarantine_posture(&policies, &[]);
        assert_eq!(posture.default_quarantine_duration_secs, 86_400);
        assert_eq!(
            posture.permissive_operator_policy_count, 2,
            "only the two `quarantineDuration: 0` rows are permissive overrides"
        );
        assert_eq!(posture.trust_upstream_publish_time_count, 0);
    }

    /// Archived rows must be filtered out of the permissive count — they
    /// are not active policy and `ingest_inner` would not consult them.
    /// An archived `quarantineDuration: 0` row is part of the
    /// projection's reactivation surface but NOT a live
    /// permissive override.
    #[test]
    fn evaluate_quarantine_posture_ignores_archived_permissive_policies() {
        let policies = vec![
            make_scan_policy(0, true),  // archived → excluded
            make_scan_policy(0, false), // active permissive → counted
        ];
        let posture = evaluate_quarantine_posture(&policies, &[]);
        assert_eq!(
            posture.permissive_operator_policy_count, 1,
            "archived permissive row must not be counted"
        );
    }

    /// Opt-in-mappings case: three upstream mappings, two with
    /// `trust_upstream_publish_time = true` and one without. The count
    /// reports two; permissive count is zero (no operator policies in
    /// this fixture).
    #[test]
    fn evaluate_quarantine_posture_counts_publish_time_optin_mappings() {
        let mappings = vec![
            make_upstream_mapping(true),
            make_upstream_mapping(false),
            make_upstream_mapping(true),
        ];
        let posture = evaluate_quarantine_posture(&[], &mappings);
        assert_eq!(posture.default_quarantine_duration_secs, 86_400);
        assert_eq!(posture.permissive_operator_policy_count, 0);
        assert_eq!(
            posture.trust_upstream_publish_time_count, 2,
            "exactly two mappings have trust_upstream_publish_time = true"
        );
    }

    /// All-three-at-once case — verifies the two count axes are
    /// independent and aggregate correctly when both are populated. This
    /// is the realistic operator-deployment shape: some repos with
    /// permissive policies AND some upstreams opted in to publish-time
    /// anchoring.
    #[test]
    fn evaluate_quarantine_posture_aggregates_both_signals_correctly() {
        let policies = vec![
            make_scan_policy(0, false), // permissive
            make_scan_policy(0, false), // permissive
            make_scan_policy(3_600, false),
            make_scan_policy(0, true), // archived — excluded
        ];
        let mappings = vec![
            make_upstream_mapping(true),
            make_upstream_mapping(true),
            make_upstream_mapping(true),
            make_upstream_mapping(false),
        ];
        let posture = evaluate_quarantine_posture(&policies, &mappings);
        assert_eq!(posture.default_quarantine_duration_secs, 86_400);
        assert_eq!(posture.permissive_operator_policy_count, 2);
        assert_eq!(posture.trust_upstream_publish_time_count, 3);
    }
}
