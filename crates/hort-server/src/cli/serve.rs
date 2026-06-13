//! `hort-server serve` (default) — runs the HTTP service.
//!
//! Body of this module is the pre-F3 `main.rs::main`: read config,
//! install tracing + Prometheus, open the Postgres pool, apply
//! migrations, build the storage + app context, bind listeners, serve.
//! The runtime is constructed locally so `main.rs` stays synchronous
//! and is small enough to audit at a glance.
//!
//! Exit semantics: on success (clean SIGTERM) returns [`ExitCode::SUCCESS`].
//! On any startup or serve failure, prints the `anyhow::Error` chain
//! via its `Debug` impl (captures the full context chain) and returns
//! [`ExitCode::FAILURE`] — matches the pre-F3 behaviour where
//! `main() -> anyhow::Result<()>` exited with code 1 on `Err`.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use tracing::{info, warn};

use hort_adapters_postgres::permission_grant_repo::PgPermissionGrantRepository;
use hort_http_core::context::AuthContext;
use hort_http_core::middleware::load_shed::ConcurrencyLimitConfig;
use hort_http_core::middleware::rate_limit::RateLimitConfig;
use hort_http_core::middleware::request_timeout::HttpTimeoutConfig;
use hort_http_core::middleware::trust::TrustConfig;

use crate::composition::{self, build_app_context};
use crate::http::{build_admin_router, build_control_router, build_router_with_oci_config};
use crate::serve_loop::{serve_with_hyper_util, HttpTimeouts};
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;

use crate::cli::rbac_refresh;
use crate::config::{AuthConfig, Config, ConfigError};
use crate::shutdown_deadline::{make_prometheus_inflight_reader, run_with_shutdown_deadline};
use crate::{migrate, shutdown, storage, telemetry};

/// Refuse to boot the server unless admin
/// routes have an authenticator. The admin surface is mounted
/// unconditionally; shipping it without authentication is a
/// critical-severity regression.
///
/// Two operator paths are supported:
///
/// - `HORT_AUTH_PROVIDER=oidc` — server validates Bearer tokens against
///   an external IdP. No DB query needed at this gate; the OIDC
///   provider is constructed later.
/// - `HORT_AUTH_PROVIDER=disabled` + `HORT_NATIVE_TOKENS_ENABLED=true` —
///   service-only deployments (and the standard local-bringup path).
///   The native-token validator authenticates `Bearer hort_<kind>_*`;
///   the composition root wires `AuthContext::BearerOnly`. Human admin
///   access is provisioned via `hort-server admin issue-svc-token` plus
///   `hort-cli auth login --paste`.
///
/// There is no third arm: the HTTP-Basic-against-local-admin-row
/// identity path (once seeded by an `admin bootstrap` subcommand) was
/// removed (commit b7fd6d65), so the only `disabled` arm is the
/// native-token one above.
async fn ensure_auth_enabled(auth: &AuthConfig, enable_native_tokens: bool) -> anyhow::Result<()> {
    match auth {
        AuthConfig::Oidc(_) => Ok(()),
        AuthConfig::Disabled => {
            if enable_native_tokens {
                tracing::info!(
                    "auth provider disabled; native tokens are enabled — \
                     service-account / CLI session `hort_<kind>_*` Bearer auth \
                     is the inbound path. Mint a token via \
                     `hort-server admin issue-svc-token` and paste it into \
                     `hort-cli auth login --paste`."
                );
                Ok(())
            } else {
                // Operators who skip the tracing subscriber (e.g. `--help`
                // path, broken log-format) still see the ConfigError via
                // the Debug-chain printer in `run`. This error! gives
                // deployments with working tracing a structured audit-trail
                // event in the expected place.
                tracing::error!(
                    "authentication provider is disabled AND native tokens are not enabled; \
                     refusing to start (set HORT_NATIVE_TOKENS_ENABLED=true or \
                     HORT_AUTH_PROVIDER=oidc)"
                );
                Err(ConfigError::AuthDisabled.into())
            }
        }
    }
}

/// Emit a one-shot deprecation
/// warning when the legacy `HORT_GROUP_MAPPINGS_PATH` env var is still
/// set. The variable is no longer consumed (the gitops boot apply
/// loads every mapping from `$HORT_CONFIG_DIR/auth/*.yaml`); operators
/// running older deployment templates with the var still baked in
/// would otherwise get no signal that their setting is being silently
/// ignored.
///
/// Called once at boot, AFTER `telemetry::init_tracing` so the emission
/// reaches the subscriber. `tracing::warn!` calls before that point are
/// dropped silently (see comment in `Config::from_env`). The message
/// names the var as a structured field so log shippers can alert on it
/// even when the human-readable string is reformatted.
///
/// Scope: this helper is intentionally specific to a single var rather
/// than a general "warn for any unrecognised HORT_*" framework;
/// broader unrecognised-env-var handling is tracked
/// as a separate future feature in `Config::from_env` test comments.
fn warn_legacy_group_mappings_path_set() {
    if legacy_group_mappings_path_is_set() {
        tracing::warn!(
            env_var = "HORT_GROUP_MAPPINGS_PATH",
            "Ignored env var: HORT_GROUP_MAPPINGS_PATH is no longer consumed. \
             Group mappings now load exclusively from $HORT_CONFIG_DIR/auth/*.yaml. \
             Remove this env var from your deployment templates."
        );
    }
}

/// Pure predicate split out of [`warn_legacy_group_mappings_path_set`]
/// so the env-read branch is unit-testable without taking a hard
/// dependency on a `tracing` capture harness for this single boot
/// emission. Returns `true` when the var is present and non-empty.
fn legacy_group_mappings_path_is_set() -> bool {
    std::env::var("HORT_GROUP_MAPPINGS_PATH")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Emit a startup `WARN` when the operator
/// has opted out of `/metrics` authentication via
/// `HORT_METRICS_REQUIRE_AUTH=false`. The endpoint reveals repository
/// names, error ratios, and traffic shape; opting out re-opens the
/// reconnaissance vector the lockdown closes. Operators who knowingly
/// take that trade-off (legacy Prometheus scrape configs that cannot
/// supply a bearer token) at minimum get a structured `env_var` field
/// so log shippers can alert on it.
///
/// Called once at boot, AFTER `telemetry::init_tracing` so the
/// emission reaches the subscriber.
fn warn_metrics_auth_bypass(metrics_require_auth: bool) {
    if !metrics_require_auth {
        tracing::warn!(
            env_var = "HORT_METRICS_REQUIRE_AUTH",
            value = "false",
            "metrics endpoint authentication is DISABLED. The /metrics scrape endpoint \
             reveals repository names, auth-failure rates, and traffic shape — opting out \
             of auth re-opens the reconnaissance vector the auth requirement closes. \
             Restrict the listener at the network layer (NetworkPolicy / firewall) or \
             unset HORT_METRICS_REQUIRE_AUTH to re-enable the default 401."
        );
    }
}

/// Synchronous entry point for `hort-server serve`. Delegates to the
/// shared [`super::run_with_runtime`] helper, which builds a Tokio
/// runtime, runs [`run_async`], and translates the result into an
/// [`ExitCode`] (preserving the pre-refactor exit-code semantics +
/// stderr prefixes).
pub fn run() -> ExitCode {
    super::run_with_runtime(run_async, |_| ExitCode::SUCCESS)
}

/// Async body — moved here verbatim from the pre-CLI-split `main.rs::main`.
/// Steps are order-sensitive; the inline comments carry the ordering
/// rationale.
async fn run_async() -> anyhow::Result<()> {
    // 0. Config parse — no logging yet, failures print via the Debug impl
    //    on anyhow::Error when run returns an error.
    let cfg = Config::from_env().context("parsing environment")?;

    // Refuse to boot under
    // `HORT_AUTH_PROVIDER=disabled` UNLESS `HORT_NATIVE_TOKENS_ENABLED=true`.
    // There is no local-admin-row arm — it was deleted
    // alongside the `admin bootstrap` CLI subcommand it relied on.

    // 1. Tracing. After this point, tracing::info!/warn!/error! reach stderr.
    telemetry::init_tracing(cfg.log_format)?;
    info!(
        api_addr = %cfg.api_bind_addr,
        metrics_addr = ?cfg.metrics_bind_addr,
        include_repository_label = cfg.include_repository_label,
        "hort-server starting"
    );

    // 1b. Surface the deprecation
    // for `HORT_GROUP_MAPPINGS_PATH`. Operators with stale deployment
    // templates that still set the var would otherwise see no signal
    // that the setting is being silently ignored. Called here (not from
    // `Config::from_env`) because the subscriber must be live for the
    // warn to reach stderr / the log shipper.
    warn_legacy_group_mappings_path_set();

    // 1c. Surface the security trade-off
    // when `HORT_METRICS_REQUIRE_AUTH=false`. Same subscriber-must-be-live
    // ordering rationale as the deprecation warning above.
    warn_metrics_auth_bypass(cfg.metrics_require_auth);

    // 2. Prometheus recorder. Any metric emitted before this is lost.
    let metrics_handle = telemetry::install_prometheus()?;
    info!("prometheus recorder installed");

    // 3. Pool + migrations.
    //
    // Wire the session statement-timeout and the
    // pool acquire-timeout. `acquire_timeout` is unconditional (a
    // bounded wait is the right default for every production
    // deployment). `statement_timeout` is only applied when the
    // operator opted in via `PG_STATEMENT_TIMEOUT_MS`: the `SET` is
    // interpolated into the SQL string because Postgres does not accept
    // bind parameters for `SET` configuration statements. Interpolation
    // here is safe: `ms` is a `u64` parsed from an env var by
    // `Config::from_env`, not user input — no SQL-injection surface.
    let mut pool_options =
        PgPoolOptions::new().acquire_timeout(Duration::from_secs(cfg.pg_acquire_timeout_secs));
    if let Some(ms) = cfg.pg_statement_timeout_ms {
        pool_options = pool_options.after_connect(move |conn, _meta| {
            Box::pin(async move {
                // `ms: u64` — safe to interpolate; see comment above.
                let sql = format!("SET statement_timeout = {ms}");
                if let Err(err) = conn.execute(sql.as_str()).await {
                    // Preserve the pool but flag the problem so operators
                    // see that the timeout they configured is not in
                    // force on this connection.
                    warn!(
                        statement_timeout_ms = ms,
                        error = %err,
                        "failed to apply statement_timeout on new connection"
                    );
                    return Err(err);
                }
                Ok(())
            })
        });
    }
    let pool = pool_options
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;
    info!(
        statement_timeout_ms = ?cfg.pg_statement_timeout_ms,
        acquire_timeout_secs = cfg.pg_acquire_timeout_secs,
        "postgres pool connected"
    );

    // The runtime does not apply migrations (ADR 0009). The
    // serve DSN is least-privilege (DML only, no DDL on `public`);
    // `sqlx::migrate!().run()` issues `CREATE TABLE IF NOT EXISTS
    // _sqlx_migrations` even when nothing is pending, which would
    // crashloop the runtime against a properly-scoped role. The
    // `migrate` subcommand (run as a separate Job under the admin
    // DSN) remains the canonical migration entrypoint; serve only
    // verifies the schema version matches what the binary expects.
    migrate::assert_current(&pool)
        .await
        .context("verifying schema version")?;

    // 3aa. Auth gate. A single check: `disabled` requires
    // `HORT_NATIVE_TOKENS_ENABLED=true`. There is no local-admin-row
    // arm — it was deleted along with the `admin bootstrap` CLI
    // subcommand it gated.
    ensure_auth_enabled(&cfg.auth, cfg.enable_native_tokens)
        .await
        .context("validating auth configuration")?;

    // 3a. Gitops boot apply.
    //
    // Runs BEFORE `build_app_context` so the `Vec<GroupMapping>`
    // consumed by `AuthenticateUseCase::new` reflects the post-apply
    // state. There is no mid-boot AppContext mutation; the operator
    // contract is restart-to-apply.
    //
    // Failure exits non-zero — half-applied state is recoverable by
    // the same action (correct YAML + restart), so adding rollback
    // would be ceremony.
    // Parse the extra CA trust bundle (ADR 0010) before gitops
    // boot so the apply-time JWKS warm-up validator (ADR 0018)
    // sees the same extra CAs the runtime federation validator uses.
    // The parse must run this early because the JWKS warm-up opens
    // outbound TLS during boot-time apply.
    let extra_trust_anchors =
        composition::read_extra_ca_bundle().map_err(|e| anyhow::anyhow!("extra CA bundle: {e}"))?;

    // Storage must be wired BEFORE gitops boot
    // because the post-exclusion-add re-evaluation pass triggered by
    // an `Exclusion` apply now reads each rejected artifact's
    // `findings_blob` from CAS to enable per-finding CVE matching.
    // The earlier ordering (storage built after gitops_boot) would
    // have forced the re-eval pass to fall back to the aggregate-
    // summary path during boot-time applies even when the per-finding
    // path is available.
    // Build the CAS storage AND the raw upstream-metadata
    // mirror (ADR 0026) from the SAME `StorageConfig` (and the same
    // already-parsed
    // `extra_trust_anchors`) in one call, so the S3 branch constructs its
    // `Arc<dyn ObjectStore>` exactly once and shares it between both
    // adapters — no duplicate reqwest client / connection pool /
    // trust-anchor parse. The mirror follows the operator's storage choice.
    let (storage_port, metadata_mirror) =
        storage::build_with_mirror(&cfg.storage, extra_trust_anchors.as_ref())
            .context("building storage + metadata mirror adapters")?;
    info!(?cfg.storage, "storage adapter wired");
    info!("metadata mirror adapter wired");

    if let Some(config_dir) = cfg.config_dir.as_ref() {
        info!(config_dir = %config_dir.display(), "gitops boot: starting");
        // Operator-controlled enumerated
        // upstream-host allowlist. `cfg.upstream_allowlist` is parsed
        // once at boot from `HORT_UPSTREAM_ALLOWLIST_HOSTS`; default
        // posture (`Disabled`) preserves historical behaviour for
        // existing deployments. See `docs/operator/upstream-trust-model.md`.
        let boot_result = crate::gitops_boot::apply_config_from_dir(
            &pool,
            config_dir,
            &cfg.auth,
            cfg.upstream_allowlist.clone(),
            extra_trust_anchors.as_ref(),
            storage_port.clone(),
            // Map the
            // already-in-scope `StorageConfig` to the pure
            // `EffectiveStorageBackend` so a per-repo `storage.backend`
            // mismatch is rejected at apply (fail-closed, loud).
            cfg.storage.effective_backend(),
        )
        .await;
        // Park, do NOT
        // crashloop, on a **provably-pre-write** gitops failure.
        //
        // `apply_config_from_dir` runs BEFORE any listener binds (see the
        // `serve.rs:339` comment), so the historical behaviour on `Err`
        // was a non-zero exit → kubelet `CrashLoopBackOff` → an
        // un-inspectable pod blocking `helm upgrade --wait` for the full
        // timeout. For the read-only failure classes (`Parse | Read |
        // Walk` — `is_park_eligible`, which provably wrote zero rows) we
        // instead bind the public API listener and serve a not-ready
        // *config-invalid park* router until SIGTERM: the pod stays
        // Running + inspectable, readiness never flips (so the rollout
        // still fails loud — a rejected config can't masquerade as
        // success), and the operator reads the exact error from the logs.
        //
        // `Validate | Apply` are mid-write-capable and `ApplyConfigUseCase`
        // has no rollback (`apply_config_use_case.rs:54-58`); their safety
        // rests on "boot exits non-zero on a half-applied state", so they
        // still crash unchanged. The `hort_gitops_apply_total`
        // cause metric already fired exactly once inside
        // `apply_config_from_dir`; it is NOT the park signal —
        // the metrics listener never binds on a parked boot.
        if let Err(e) = boot_result {
            if crate::gitops_boot::is_park_eligible(&e) {
                tracing::error!(
                    error = %e,
                    "gitops config invalid — serving not-ready (no crashloop); \
                     fix the config and redeploy"
                );
                // The shared shutdown coordinator is normally installed
                // much later (after `build_app_context`); on the park
                // path we never reach that, so install it here and hand
                // its token to the park serve loop. SIGTERM lets a
                // rollout replace the pod.
                let shutdown_handle = shutdown::ShutdownHandle::install();
                return crate::cli::serve_parked::serve_config_invalid_park(
                    cfg.api_bind_addr,
                    shutdown_handle.token(),
                )
                .await;
            }
            return Err(anyhow::anyhow!("gitops boot: {e}"));
        }
    }

    // Refcount-reconcile sweep at boot.
    //
    // Runs AFTER gitops apply and BEFORE any listener binds (the
    // listeners are bound much later, after `build_app_context`), so
    // it converges the eventually-authoritative `content_references`
    // refcount projection before external
    // traffic is admitted. This is the named reconcile gate
    // `PurgeUseCase` refuses to start without. Default-on
    // (fresh-install posture, `HORT_REFCOUNT_RECONCILE_ON_STARTUP`
    // defaults to `true`); upgrade installs with authoritative state
    // set it `false`. A converged projection makes the sweep a no-op,
    // so the default-on posture is always safe + idempotent. The
    // adapter is constructed inline from the pool (the
    // `reconcile-groups` CLI precedent), not threaded through
    // `build_app_context` — the sweep is a one-shot boot step with no
    // serving-path coupling. A scan/repair failure is recorded by the
    // use case (per-repo/per-case, tracing) and does NOT abort boot:
    // the projection is eventually authoritative and the next boot (or
    // a future scheduled task) retries; only a hard "cannot even list
    // repositories" surfaces as a boot error.
    if cfg.refcount_reconcile_on_startup {
        use hort_app::use_cases::refcount_reconcile_use_case::RefcountReconcileUseCase;
        use hort_domain::ports::refcount_reconcile::RefcountReconcilePort;

        info!("refcount-reconcile sweep starting (pre-traffic)");
        let port: Arc<dyn RefcountReconcilePort> = Arc::new(
            hort_adapters_postgres::refcount_reconcile::PgRefcountReconcile::new(pool.clone()),
        );
        let summary = RefcountReconcileUseCase::new(port)
            .sweep_drift()
            .await
            .context("refcount-reconcile sweep")?;
        info!(
            repos_swept = summary.repos_swept,
            drift_repaired = summary.drift_repaired,
            errors = summary.errors,
            "refcount-reconcile sweep complete (pre-traffic)"
        );
    } else {
        info!(
            "refcount-reconcile sweep skipped \
             (HORT_REFCOUNT_RECONCILE_ON_STARTUP=false — upgrade-install \
             opt-out; projection assumed authoritative)"
        );
    }

    // Construct the EventStore EXACTLY ONCE here and thread it into
    // both downstream consumers (the OIDC provider's audit pathway
    // AND `build_app_context`'s use cases). Constructing it twice
    // — once in the OIDC arm below, once inside
    // `build_app_context` — would cost one extra startup
    // immutability-trigger probe and create a code smell where the
    // boot path looks like it has two independent audit paths. Typed
    // as `Arc<PgEventStore>` (concrete, not `dyn`) because
    // `build_app_context` needs the concrete type to feed Pg-specific
    // lifecycle adapter constructors; the OIDC `with_event_store` site
    // takes `Arc<dyn EventStore>` and Rust's unsized coercion at the
    // method-arg boundary handles the projection.
    let event_store: Arc<hort_adapters_postgres::event_store::PgEventStore> = Arc::new(
        hort_adapters_postgres::event_store::PgEventStore::new(pool.clone())
            .await
            .context("event store init")?,
    );

    // 5a. Auth wiring. Construct the OIDC
    // provider only when `HORT_AUTH_PROVIDER=oidc`; `Disabled` passes `None` and
    // `auth_enabled=false` so `build_app_context` skips the RBAC snapshot
    // query entirely. Clients present IdP-issued Bearer tokens (obtained
    // from Keycloak directly) — hort-server does not mint its own JWTs and
    // never sees user passwords.
    // Capture the OIDC issuer URL
    // alongside the rest of the auth wiring so it can be threaded into
    // `build_app_context` and surface on `AuthContext::Enabled.issuer_url`.
    // The value is `None` under `AuthConfig::Disabled` (the auth context
    // is `Disabled`, so the field is never read).
    let oidc_issuer_url: Option<String> = match &cfg.auth {
        AuthConfig::Disabled => None,
        AuthConfig::Oidc(oidc) => Some(oidc.issuer_url.clone()),
    };

    let (idp, auth_enabled, claim_mappings) = match &cfg.auth {
        AuthConfig::Disabled => (None, false, Vec::new()),
        AuthConfig::Oidc(oidc) => {
            // Thread the JWKS resilience knobs
            // from `Config` into the adapter constructor. Defaults
            // (10 s per-kid signature-mismatch backoff, 1 MiB body
            // cap) are applied at config parse, not here; this code
            // path just threads them through.
            let provider = hort_adapters_oidc::OidcProvider::with_resilience(
                oidc.issuer_url.clone(),
                oidc.audience.clone(),
                oidc.groups_claim.clone(),
                Duration::from_secs(oidc.jwks_cache_ttl_seconds),
                Duration::from_secs(cfg.jwks_eviction_backoff_secs),
                cfg.jwks_resp_body_max_bytes,
                // Pass the extra CA bundle parsed above (ADR 0010)
                // so the OIDC reqwest::Client trusts internal CAs.
                // Composition is the source; the adapter receives the value
                // directly, never via AppContext.extra_trust_anchors.
                extra_trust_anchors.as_ref(),
            )
            .map_err(|e| anyhow::anyhow!("OIDC provider construction failed: {e}"))?;
            // Attach an `EventStore`
            // so observed JWKS rotations append `OidcKeyRotated`
            // events to the per-UTC-date auth-attempts stream.
            // Shares the single `event_store`
            // handle constructed above with `build_app_context`'s use
            // cases; the OIDC path uses `ExpectedVersion::Any` and is
            // independent of the use-case streams, but both call
            // sites legitimately share the same backing trigger probe.
            let provider = provider.with_event_store(event_store.clone());
            let provider_arc: Arc<dyn IdentityProvider> = Arc::new(provider);
            // There is no legacy
            // `HORT_GROUP_MAPPINGS_PATH` single-file loader; mappings
            // load exclusively through the gitops apply (which has
            // already run by this point when `HORT_CONFIG_DIR` is set).
            // `claim_mappings` (ADR 0012) is the only
            // mapping table. Read the post-apply state so
            // `AuthenticateUseCase::new` resolves `principal.claims`
            // from what operators declared. When `HORT_CONFIG_DIR` is
            // unset the table stays empty — the auth surface is dormant
            // by design until operators wire up gitops.
            let cm_repo = hort_adapters_postgres::claim_mapping_repo::PgClaimMappingRepository::new(
                pool.clone(),
            );
            use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
            let mappings = cm_repo
                .list_all()
                .await
                .context("reading claim_mappings table after gitops apply")?;
            (Some(provider_arc), true, mappings)
        }
    };

    // The additive-claims `RbacEvaluator` (ADR 0012) is built from
    // the flat `PermissionGrant` set; there is no `RoleRepository`
    // (roles + role-keyed grant index). The permission-grant
    // port sources both the boot snapshot (inside `build_app_context`)
    // and the live-refresh task.
    let permission_grant_repo: Arc<dyn PermissionGrantRepository> =
        Arc::new(PgPermissionGrantRepository::new(pool.clone()));
    // The RBAC refresh task needs its own Arc
    // handle on the grant repo (the one passed into `build_app_context`
    // is consumed there). Cloning an `Arc` is cheap; the underlying
    // `PgPermissionGrantRepository` is shared.
    let permission_grant_repo_for_refresh = permission_grant_repo.clone();

    // Proxy-trust config assembled here, fed into the
    // AppContext (the `request_trust_layer` reads it). Bind-address
    // default is the `http://<bind_addr>/` URL, used ONLY on the
    // degenerate fallback branch (untrusted peer, no Host header).
    // Config::from_env has already enforced the unconditional startup
    // check: either `HORT_PUBLIC_BASE_URL` is set or `HORT_TRUSTED_PROXY_CIDRS`
    // is non-empty — otherwise we never got here.
    let bind_addr_default = url::Url::parse(&format!("http://{}/", cfg.api_bind_addr))
        .context("deriving bind-address default URL for RequestTrust")?;
    let trust_config = TrustConfig::new(
        cfg.public_base_url.clone(),
        cfg.trusted_proxy_cidrs.clone(),
        bind_addr_default,
    );
    let trust_mode = match (
        trust_config.public_base_url.is_some(),
        !trust_config.trusted_proxy_cidrs.is_empty(),
    ) {
        (true, false) => "public_url_pinned",
        (false, true) => "trusted_proxy_forwarding",
        (true, true) => "BOTH",
        (false, false) => unreachable!("Config::from_env rejects this combination"),
    };
    info!(
        trust_mode,
        trusted_proxy_cidr_count = trust_config.trusted_proxy_cidrs.len(),
        "trust configuration loaded"
    );

    // Rate-limit config. Parsed in
    // `Config::from_env`; assembled into `RateLimitConfig` here and
    // threaded into `AppContext` the same way as `TrustConfig`.
    let rate_limit_config =
        RateLimitConfig::new(cfg.ratelimit_auth_per_min, cfg.ratelimit_write_per_min);
    info!(
        auth_per_min = rate_limit_config.auth_per_min,
        write_per_min = rate_limit_config.write_per_min,
        "rate-limit configuration loaded"
    );

    // Concurrency caps. Parsed in
    // `Config::from_env` (zero rejected at parse-time); the
    // `NonZeroUsize::new(..).expect(..)` here is total because the
    // env-parse already failed on zero.
    let concurrency_limit_config = ConcurrencyLimitConfig::new(
        std::num::NonZeroUsize::new(cfg.max_inflight)
            .expect("HORT_MAX_INFLIGHT non-zero invariant enforced by Config::from_env"),
        std::num::NonZeroUsize::new(cfg.max_inflight_per_ip)
            .expect("HORT_MAX_INFLIGHT_PER_IP non-zero invariant enforced by Config::from_env"),
    );
    info!(
        max_inflight = concurrency_limit_config.max_inflight.get(),
        max_inflight_per_ip = concurrency_limit_config.max_inflight_per_ip.get(),
        "concurrency-limit configuration loaded"
    );

    // Per-request deadline config. Parsed
    // in `Config::from_env`; assembled into `HttpTimeoutConfig` here
    // and threaded into `AppContext` the same way as `TrustConfig`.
    // Consumed by:
    // - `hort_http_core::router::wrap_with_middleware` reads the global
    //   default and applies it to the non-OCI subtree before merging.
    // - `hort_http_oci::oci_routes_with_config` reads the OCI override
    //   and applies it to the upload subtree only.
    let http_timeout_config = HttpTimeoutConfig {
        request_timeout: Duration::from_secs(cfg.http_request_timeout_secs),
        oci_upload_timeout: Duration::from_secs(cfg.http_oci_upload_timeout_secs),
    };
    info!(
        request_timeout_secs = cfg.http_request_timeout_secs,
        oci_upload_timeout_secs = cfg.http_oci_upload_timeout_secs,
        header_read_timeout_secs = cfg.http_header_read_timeout_secs,
        "http transport timeouts loaded"
    );

    // Surface the configured
    // graceful-shutdown grace so operators can correlate it with their
    // orchestrator's terminationGracePeriod / TimeoutStopSec at boot
    // time, before the first SIGTERM lands.
    info!(
        shutdown_grace_secs = cfg.shutdown_grace_secs,
        "graceful-shutdown deadline configured"
    );

    // Transport-level (hyper) timeouts.
    // The header-read timeout is the slowloris kill (default 15s);
    // HTTP/2 keep-alive bounds idle multiplexed sessions. Both apply
    // per-connection, regardless of which route is hit.
    let http_timeouts = HttpTimeouts {
        header_read_timeout: Duration::from_secs(cfg.http_header_read_timeout_secs),
        http2_keep_alive_interval: Duration::from_secs(30),
        http2_keep_alive_timeout: Duration::from_secs(30),
    };

    // 5b. App context.
    //
    // `metrics_handle` is consumed
    // by `build_app_context` (it is moved onto `AppContext` for the
    // `/metrics` scrape route). We clone it first so the
    // shutdown-deadline path retains an independent handle for the
    // in-flight gauge read at warn time. `PrometheusHandle` is
    // `Arc`-backed; the clone is cheap.
    let metrics_handle_for_shutdown = metrics_handle.clone();
    let composition::BuildAppContextOutput {
        ctx,
        caching_resolver,
        pat_listener,
        notification_runtime,
    } = build_app_context(
        pool,
        storage_port,
        // Raw upstream-metadata mirror (ADR 0026) built above from
        // the same `StorageConfig` as `storage_port`.
        metadata_mirror,
        metrics_handle,
        cfg.include_repository_label,
        cfg.include_service_account_label,
        cfg.metadata_caps.clone(),
        cfg.metadata_blob_max_bytes,
        cfg.upstream_metadata_cache_max_bytes,
        cfg.upstream_manifest_cache_max_bytes,
        cfg.upstream_projector_version_object_max_bytes,
        cfg.public_base_url.clone(),
        trust_config,
        rate_limit_config,
        concurrency_limit_config,
        http_timeout_config,
        cfg.publish_body_limit_bytes,
        idp,
        claim_mappings,
        permission_grant_repo,
        auth_enabled,
        // Issuer URL threaded down to
        // `AuthContext::Enabled.issuer_url`.
        oidc_issuer_url,
        cfg.stateful_upload_staging_dir.clone(),
        cfg.ephemeral_store_backend,
        cfg.redis_url.clone(),
        // Per-class Redis URL overrides (ephemeral-keyspace routing).
        // Resolution runs only on the Redis branch; the Memory branch
        // never consults these.
        cfg.redis_url_evictable.clone(),
        cfg.redis_url_durable.clone(),
        // Pull-through dedup config built from
        // the five `HORT_PULL_DEDUP_*` env vars parsed by `Config::from_env`.
        // Composition consumes a parsed config struct, never re-reads
        // env vars itself.
        hort_app::pull_dedup::PullDedupConfig {
            ttl_not_found: Duration::from_secs(cfg.pull_dedup_ttl_not_found_secs),
            ttl_unavailable: Duration::from_secs(cfg.pull_dedup_ttl_unavailable_secs),
            ttl_timeout: Duration::from_secs(cfg.pull_dedup_ttl_timeout_secs),
            ttl_checksum_mismatch: Duration::from_secs(cfg.pull_dedup_ttl_checksum_mismatch_secs),
            follower_wait: Duration::from_secs(cfg.pull_dedup_follower_wait_secs),
        },
        // Pass the value parsed at step 3b rather
        // than having build_app_context re-read the env var. The same
        // Option<ExtraTrustAnchors> was already forwarded to storage::build
        // (step 4) above; this is the second consumer.
        extra_trust_anchors,
        // Share the single
        // `event_store` constructed above with the OIDC audit pathway
        // (`provider.with_event_store(event_store.clone())` in step
        // 5a) so the boot path holds exactly one `PgEventStore` for
        // the lifetime of the process.
        event_store.clone(),
        // Native API token wiring (ADR 0012). Default is
        // `enabled = false` so OIDC-only deployments keep
        // a token-free wire shape. Operators flip
        // `HORT_NATIVE_TOKENS_ENABLED=true` to opt in.
        composition::NativeTokenConfig {
            enabled: cfg.enable_native_tokens,
            allow_pat_over_http: cfg.allow_pat_over_http,
            cache_size: cfg.pat_cache_size,
            lockout_threshold: cfg.pat_lockout_threshold,
            lockout_window_secs: cfg.pat_lockout_window_secs,
            lockout_duration_secs: cfg.pat_lockout_duration_secs,
            // Issuance flags.
            allow_admin_tokens: cfg.allow_admin_tokens,
            allow_unbounded_svc_tokens: cfg.allow_unbounded_svc_tokens,
            // OCI signing key PEMs (already
            // resolved through `_FILE`-precedence by `Config::from_env`).
            oci_token_signing_key_pem: cfg.oci_token_signing_key_pem.clone(),
            oci_token_signing_key_prev_pem: cfg.oci_token_signing_key_prev_pem.clone(),
        },
        // Pre-render the client-bootstrap
        // config when the feature is on (ADR 0013). The boot-time fail-closed
        // validation in `Config::from_env` (variant
        // `ConfigError::TokenExchangeRequiresVars`) guarantees that
        // when `enable_token_exchange` is `true`, `auth` is OIDC with
        // a non-empty `cli_client_id` AND `public_base_url` is `Some`;
        // anything else returned `Err` before we got here. The
        // `expect`s below therefore document invariants the validator
        // already enforced.
        if cfg.enable_token_exchange {
            let oidc = match &cfg.auth {
                AuthConfig::Oidc(o) => o,
                AuthConfig::Disabled => {
                    unreachable!(
                        "the fail-closed config validator must reject \
                         enable_token_exchange=true with AuthConfig::Disabled \
                         (ConfigError::TokenExchangeRequiresVars); reaching here \
                         would indicate a regression in `Config::from_env`."
                    )
                }
            };
            let cli_client_id = oidc
                .cli_client_id
                .clone()
                .expect("fail-closed config validator guarantees Some(_) when feature on");
            let base = cfg
                .public_base_url
                .as_ref()
                .expect("fail-closed config validator guarantees Some(_) when feature on");
            let endpoint = base
                .join("/api/v1/auth/exchange")
                .expect("static path joins cleanly with a parsed Url");
            Some(
                hort_http_core::handlers::well_known::ClientBootstrapConfig {
                    idp_issuer: oidc.issuer_url.clone(),
                    idp_cli_client_id: cli_client_id,
                    exchange_endpoint: endpoint.into(),
                },
            )
        } else {
            None
        },
        // Event-notification substrate config (see
        // `docs/architecture/explanation/event-notifications.md`):
        // enable flag, channel capacity, webhook transport flag,
        // SSRF flag, and the optional NATS URL.
        composition::NotifyConfig {
            enabled: cfg.enable_notifications,
            channel_capacity: cfg.notify_channel_capacity,
            allow_plaintext_webhooks: cfg.allow_plaintext_webhooks,
            allow_nonroutable_webhook_targets: cfg.allow_nonroutable_webhook_targets,
            nats_url: cfg.nats_url.clone(),
        },
    )
    .await
    .context("building app context")?;
    // Hold the listener handle so it stays alive across the loop;
    // shutdown aborts it via `_pat_listener` going out of scope.
    let _pat_listener = pat_listener;
    let ctx = Arc::new(ctx);

    // 6. Shutdown signal + background tasks.
    //
    // `ShutdownHandle::install` spawns a single
    // signal-listener task whose cancellation token is cloned into
    // every consumer (axum serve futures + the RBAC refresh task).
    // A one-shot future consumed by
    // one `axum::serve(...).with_graceful_shutdown(...)` call would
    // not allow a second awaiter; that needs a broadcast primitive. See
    // `crate::shutdown` module docs.
    let shutdown_handle = shutdown::ShutdownHandle::install();

    // Spawn the RBAC refresh task when auth is enabled. `Disabled`
    // contexts skip the refresh entirely — no evaluator, no snapshot,
    // no work to do.
    let rbac_refresh_task = match &ctx.auth {
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => {
            let rbac_handle = rbac.clone();
            // Compute the initial signature from a fresh DB read so the
            // first poll post-jitter observes `unchanged` when the DB
            // hasn't changed between boot and first-fire. One extra
            // round-trip at startup (two small queries) is a fair price
            // for a clean observability signal.
            // A single `list_all` grant query is the
            // whole snapshot (no role table). One round-trip at startup
            // is a fair price for a clean first-poll observability
            // signal (the first poll registers `unchanged` rather than
            // a false `success` when the DB hasn't drifted since boot).
            let initial_grants = permission_grant_repo_for_refresh
                .list_all()
                .await
                .context("fetching initial RBAC grants for refresh signature")?;
            let initial_signature = rbac_refresh::Signature::from_grants(&initial_grants);

            let interval = Duration::from_secs(u64::from(cfg.rbac_refresh_secs));
            info!(
                interval_secs = interval.as_secs(),
                "rbac live-refresh task enabled"
            );
            Some(rbac_refresh::spawn(
                rbac_handle,
                permission_grant_repo_for_refresh,
                initial_signature,
                interval,
                shutdown_handle.token(),
            ))
        }
        AuthContext::Disabled => {
            info!("auth disabled — skipping rbac live-refresh task");
            None
        }
    };

    // Upstream-resolver refresh task. Polls
    // `RepositoryUpstreamMappingRepository::list_all()` every
    // `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` (default 60s) and swaps the
    // resolver's snapshot via `CachingResolver::reload`. The first
    // iteration runs immediately so the cache is primed before
    // serving requests; subsequent iterations sleep on the interval
    // OR exit on shutdown.
    let resolver_refresh_task = {
        let resolver = caching_resolver.clone();
        let mappings = ctx.repository_upstream_mappings.clone();
        let token = shutdown_handle.token();
        let interval = Duration::from_secs(u64::from(cfg.upstream_resolver_refresh_secs));
        info!(
            interval_secs = interval.as_secs(),
            "upstream resolver refresh task enabled"
        );
        tokio::spawn(async move {
            // Prime the cache up-front. Failures here are logged but
            // do not abort startup — operators with no upstream
            // mappings configured see an empty resolver, which is
            // correct for the local-only deployment shape.
            match mappings.list_all().await {
                Ok(snapshot) => {
                    let n = resolver.reload(snapshot);
                    info!(
                        mappings_loaded = n,
                        "upstream resolver primed from initial snapshot"
                    );
                }
                Err(err) => {
                    warn!(error = %err, "upstream resolver initial prime failed; cache stays empty until next tick");
                }
            }

            loop {
                tokio::select! {
                    () = token.cancelled() => break,
                    () = tokio::time::sleep(interval) => {}
                }
                match mappings.list_all().await {
                    Ok(snapshot) => {
                        let n = resolver.reload(snapshot);
                        tracing::debug!(
                            mappings_loaded = n,
                            "upstream resolver snapshot refreshed"
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, "upstream resolver refresh failed; previous snapshot retained");
                    }
                }
            }
        })
    };

    // `NotificationDispatcher` task. The dispatcher
    // takes ownership of the publisher's broadcast subscription, the
    // per-subscription RBAC ArcSwap, and the `subscription_changes`
    // PgListener. `cli::serve` is the spawn site because composition
    // does not own the `shutdown_handle` (it is created above); a
    // single SIGTERM cancels the dispatcher loop AND every
    // per-subscription task it spawned via child cancellation tokens.
    //
    // `notification_runtime` is `Some(_)` exactly when
    // `cfg.enable_notifications=true`; when off, the dispatcher is
    // not constructed and the broadcast publisher is transparent
    // pass-through ("flag-off short-circuits").
    let (_change_listener_handle, _dispatcher_handle) = match notification_runtime {
        Some(rt) => {
            let dispatcher_cancel = shutdown_handle.token();
            let dispatcher_handle = tokio::spawn(async move {
                rt.dispatcher.run(dispatcher_cancel).await;
            });
            info!("notification dispatcher task spawned");
            (Some(rt.change_listener_handle), Some(dispatcher_handle))
        }
        None => {
            info!("HORT_NOTIFICATIONS_ENABLED=false — notification dispatcher disabled");
            (None, None)
        }
    };

    // 7. Serve. Split routers when HORT_METRICS_BIND is set so /metrics is
    //    only exposed on the admin listener.
    let api_listener = tokio::net::TcpListener::bind(cfg.api_bind_addr)
        .await
        .context("binding API listener")?;
    info!(addr = %cfg.api_bind_addr, "API listening");

    // Optional internal-only control-plane
    // listener, mirroring the `HORT_METRICS_BIND` split. Bound+built
    // BEFORE the metrics-branch below because both branches move `ctx`
    // (the metrics branch via `build_admin_router(ctx, ...)`, the
    // single-listener branch via `build_router_with_oci_config(ctx,
    // ...)`), so the control router's `ctx.clone()` has to happen
    // first. When `HORT_CONTROL_BIND` is unset, `control_split` stays
    // `false` and the control routes remain on the main router —
    // no migration. The composition
    // root logs what was wired (Observability rule — no per-handler
    // logging). Token-generation + artifact-pull routes are NEVER
    // moved here: they are public by requirement.
    let control_split = cfg.control_bind_addr.is_some();
    let control_bound = if let Some(control_addr) = cfg.control_bind_addr {
        let control_listener = tokio::net::TcpListener::bind(control_addr)
            .await
            .context("binding control-plane listener")?;
        let control_router = build_control_router(ctx.clone(), cfg.metrics_require_auth);
        info!(
            addr = %control_addr,
            "HORT_CONTROL_BIND set — control plane (/admin, /api/v1/admin/*, \
             /api/v1/subscriptions) served on internal-only listener; \
             removed from the public/main listener"
        );
        Some((control_listener, control_router))
    } else {
        info!(
            "HORT_CONTROL_BIND not set — control plane served on the main \
             listener (no behaviour change)"
        );
        None
    };

    if let Some(metrics_addr) = cfg.metrics_bind_addr {
        let admin_listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .context("binding admin listener")?;
        info!(addr = %metrics_addr, "admin /metrics listening");

        let oci_cfg = hort_http_oci::OciHttpConfig {
            legacy_catalog_enabled: cfg.oci_legacy_catalog_enabled,
            // Per-`(repo,
            // principal)` outstanding-session cap.
            max_sessions_per_principal: cfg.oci_max_sessions_per_principal,
        };
        // Metrics auth posture. The flag
        // is the same one threaded into the main listener below; the
        // admin router enforces it via its own `require_principal`
        // layer (see `build_admin_router`), independent of the public
        // router's per-path carve-out.
        let api = build_router_with_oci_config(
            ctx.clone(),
            false,
            &oci_cfg,
            cfg.metrics_require_auth,
            cfg.enable_token_exchange,
            control_split,
        );
        let admin = build_admin_router(ctx, cfg.metrics_require_auth);

        // `axum::serve(...)` is replaced
        // with `serve_with_hyper_util` so we can configure
        // `http1_header_read_timeout` (the slowloris kill) and the
        // HTTP/2 keep-alive knobs that hyper otherwise leaves at
        // permissive defaults. The function consumes the listener +
        // router and runs an explicit accept loop atop
        // `hyper_util::server::conn::auto::Builder`. Both API and
        // admin listeners take a fresh shutdown-token clone so a
        // single SIGTERM fans out to both serve futures + the
        // background refresh tasks.
        //
        // `serve_with_hyper_util` calls `into_make_service_with_connect_info::<SocketAddr>`
        // internally so the peer SocketAddr is injected as a
        // `ConnectInfo<SocketAddr>` extension on every request — the
        // `request_trust_layer` reads it from there. Behaviour
        // matches the prior `axum::serve(...).with_graceful_shutdown(...)`
        // call modulo the new transport timeouts.
        let api_token = shutdown_handle.token();
        let admin_token = shutdown_handle.token();
        let api_future = serve_with_hyper_util(api_listener, api, http_timeouts, api_token);
        let admin_future = serve_with_hyper_util(admin_listener, admin, http_timeouts, admin_token);

        // Third serve future for the optional
        // control listener. Always a concrete future so `try_join!`
        // stays homogeneous; resolves immediately to `Ok(())` when
        // `HORT_CONTROL_BIND` is unset (zero behaviour change). A single
        // SIGTERM fans out to this listener too via its own token clone.
        let control_token = shutdown_handle.token();
        let control_future = async move {
            match control_bound {
                Some((listener, router)) => {
                    serve_with_hyper_util(listener, router, http_timeouts, control_token).await
                }
                None => Ok(()),
            }
        };

        // Wall-clock cap on the
        // graceful-shutdown wait. Without it, a stuck handler (frozen
        // DB pool, hung upstream) could block `try_join!` forever and
        // force an orchestrator-issued SIGKILL to escalate, leaving
        // in-flight uploads in undefined state. The wrapper bounds the
        // wait at `HORT_SHUTDOWN_GRACE_SECS` (default 60s); on timeout
        // it emits a single `tracing::warn!(target: "hort::shutdown",
        // ...)` carrying the in-flight request count read off the
        // Prometheus registry, then returns Ok so the process exits
        // cleanly. Inner errors propagate untouched on the clean path.
        //
        // The deadline is armed only after `shutdown_signal` resolves
        // — pre-fix the wrapper armed the timer at process start and
        // fired at boot+grace regardless of SIGTERM, killing the
        // listener and presenting as a Kubernetes restart-loop. The
        // shutdown signal is a fresh clone of the shutdown token;
        // it resolves on SIGTERM/SIGINT in production.
        let grace = Duration::from_secs(cfg.shutdown_grace_secs);
        let in_flight_reader = make_prometheus_inflight_reader(metrics_handle_for_shutdown);
        let deadline_token = shutdown_handle.token();
        let shutdown_signal = async move { deadline_token.cancelled().await };
        let serve_future = async move {
            tokio::try_join!(api_future, admin_future, control_future).context("serving")?;
            Ok::<(), anyhow::Error>(())
        };
        run_with_shutdown_deadline(serve_future, shutdown_signal, grace, in_flight_reader).await?;
    } else {
        info!("HORT_METRICS_BIND not set — /metrics served on main router (dev mode)");
        let oci_cfg = hort_http_oci::OciHttpConfig {
            legacy_catalog_enabled: cfg.oci_legacy_catalog_enabled,
            // Per-`(repo,
            // principal)` outstanding-session cap.
            max_sessions_per_principal: cfg.oci_max_sessions_per_principal,
        };
        // Single-listener mode still
        // honours the metrics-auth posture: the auth dispatch carves
        // `/metrics` out to `require_principal` when the flag is set.
        let router = build_router_with_oci_config(
            ctx,
            true,
            &oci_cfg,
            cfg.metrics_require_auth,
            cfg.enable_token_exchange,
            control_split,
        );
        let token = shutdown_handle.token();

        // Optional control listener in the
        // single-(metrics-on-main)-listener topology too. Same
        // homogeneous-future shape as the split branch: a concrete
        // future that resolves to `Ok(())` immediately when
        // `HORT_CONTROL_BIND` is unset (zero behaviour change).
        let control_token = shutdown_handle.token();
        let control_future = async move {
            match control_bound {
                Some((listener, ctrl_router)) => {
                    serve_with_hyper_util(listener, ctrl_router, http_timeouts, control_token).await
                }
                None => Ok(()),
            }
        };

        // Same shutdown-deadline wrap as the
        // split-listener branch above. See that branch for the full
        // rationale; the call site is mirrored so the contract holds
        // regardless of which listener topology the operator picks.
        let grace = Duration::from_secs(cfg.shutdown_grace_secs);
        let in_flight_reader = make_prometheus_inflight_reader(metrics_handle_for_shutdown);
        let deadline_token = shutdown_handle.token();
        let shutdown_signal = async move { deadline_token.cancelled().await };
        let api_future = serve_with_hyper_util(api_listener, router, http_timeouts, token);
        let serve_future = async move {
            tokio::try_join!(api_future, control_future).context("serving")?;
            Ok::<(), anyhow::Error>(())
        };
        run_with_shutdown_deadline(serve_future, shutdown_signal, grace, in_flight_reader).await?;
    }

    // Drain the refresh task. When axum returns the shutdown token is
    // already cancelled (that's why serve stopped) — the refresh task
    // is either already exiting or will exit on its next select arm.
    // Joining avoids leaking the task; a panic in the task surfaces
    // here as a JoinError we log and swallow (no serve-path regression).
    if let Some(task) = rbac_refresh_task {
        if let Err(err) = task.await {
            warn!(error = %err, "rbac refresh task exited abnormally");
        }
    }

    // Drain the upstream-resolver refresh task on the same shutdown
    // signal. Same JoinError semantics as the RBAC task above.
    if let Err(err) = resolver_refresh_task.await {
        warn!(error = %err, "upstream resolver refresh task exited abnormally");
    }

    info!("hort-server shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Startup guard against unauthenticated admin.
    //!
    //! The guard is tested in isolation from `run_async` because
    //! spinning up a full runtime + DB pool for a single branch
    //! assertion is disproportionate. The contract is two lines:
    //!
    //! - `Disabled` + `enable_native_tokens=false` →
    //!   `Err(ConfigError::AuthDisabled)`
    //! - `Disabled` + `enable_native_tokens=true` → `Ok`
    //!   (composition root wires `AuthContext::BearerOnly`)
    //! - `Oidc` → `Ok`

    use super::*;
    use crate::config::OidcConfig;
    use tracing_test::traced_test;

    #[tokio::test]
    async fn ensure_auth_enabled_rejects_disabled_without_native_tokens() {
        let err = ensure_auth_enabled(&AuthConfig::Disabled, false)
            .await
            .unwrap_err();
        let root = err
            .downcast_ref::<ConfigError>()
            .expect("error chain must carry ConfigError::AuthDisabled");
        assert!(
            matches!(root, ConfigError::AuthDisabled),
            "expected AuthDisabled, got {root:?}"
        );
    }

    #[tokio::test]
    async fn ensure_auth_enabled_accepts_disabled_with_native_tokens() {
        // Service-only / local-bringup deployments: no human admin row,
        // only `hort_<kind>_*` Bearer auth. The composition root wires
        // `AuthContext::BearerOnly` with `idp=None` + the native-token
        // validator.
        ensure_auth_enabled(&AuthConfig::Disabled, true)
            .await
            .expect("Disabled + native-tokens=true must boot cleanly");
    }

    // The error message names the two operator paths forward — operators
    // reading stderr without the source tree need both `HORT_AUTH_PROVIDER`
    // and `HORT_NATIVE_TOKENS_ENABLED` in the string to find the fix.

    #[tokio::test]
    async fn ensure_auth_enabled_error_names_auth_provider_env_var() {
        let err = ensure_auth_enabled(&AuthConfig::Disabled, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("HORT_AUTH_PROVIDER"),
            "error message should name HORT_AUTH_PROVIDER env var; got {msg}"
        );
    }

    #[tokio::test]
    async fn ensure_auth_enabled_error_names_native_tokens_env_var() {
        let err = ensure_auth_enabled(&AuthConfig::Disabled, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("HORT_NATIVE_TOKENS_ENABLED"),
            "error message should name HORT_NATIVE_TOKENS_ENABLED env var; got {msg}"
        );
    }

    #[tokio::test]
    async fn ensure_auth_enabled_accepts_oidc() {
        // Any OIDC variant proves the guard does not over-reject. The
        // native-tokens flag is irrelevant for the OIDC arm
        // (early-returns Ok without touching it).
        let auth = AuthConfig::Oidc(OidcConfig {
            issuer_url: "https://keycloak.example/realms/hort".into(),
            audience: "hort-server".into(),
            groups_claim: "groups".into(),
            jwks_cache_ttl_seconds: 600,
            cli_client_id: None,
        });
        ensure_auth_enabled(&auth, false)
            .await
            .expect("OIDC must boot cleanly");
    }

    // The legacy
    // `HORT_GROUP_MAPPINGS_PATH` env var is no longer consumed, but
    // operators with stale deployment templates are promised
    // a deprecation warning at boot. The test below captures the
    // emission via `#[traced_test]` and asserts it fires once with the
    // expected `env_var` structured field.
    //
    // The `traced_test` macro injects a per-test span and a
    // `logs_contain` helper that filters captured log lines to that
    // span; that filtering is what makes the assertion serial-safe even
    // when other tests in this crate emit `tracing::warn!`.

    #[traced_test]
    #[test]
    fn legacy_group_mappings_path_emits_one_shot_deprecation_warning() {
        temp_env::with_var(
            "HORT_GROUP_MAPPINGS_PATH",
            Some("/etc/hort/legacy-mappings.yaml"),
            || {
                warn_legacy_group_mappings_path_set();
            },
        );

        // The structured `env_var` field is the load-bearing piece of
        // the contract — log shippers and alert rules will key on it.
        // `tracing-test` renders structured fields as `field=value` in
        // the captured line.
        assert!(
            logs_contain("env_var=\"HORT_GROUP_MAPPINGS_PATH\""),
            "expected deprecation warning to carry env_var=HORT_GROUP_MAPPINGS_PATH"
        );
        // Pin the human-readable lede so the operator-facing prose
        // can't silently drift away from the documented promise.
        assert!(
            logs_contain("Ignored env var: HORT_GROUP_MAPPINGS_PATH is no longer consumed"),
            "expected the documented deprecation message"
        );

        // Exactly-once: the `logs_assert` helper exposes the raw
        // captured lines so we can count occurrences of the warn
        // message within the per-test span.
        logs_assert(|lines: &[&str]| {
            let count = lines
                .iter()
                .filter(|l| l.contains("Ignored env var: HORT_GROUP_MAPPINGS_PATH"))
                .count();
            if count == 1 {
                Ok(())
            } else {
                Err(format!(
                    "expected exactly one deprecation warning, got {count}"
                ))
            }
        });
    }

    // `HORT_METRICS_REQUIRE_AUTH=false`
    // emits a startup `WARN`. The structured `env_var` field is the
    // load-bearing piece for log-shipper alerting. The default-true
    // case must NOT emit any warn line referencing this env var.
    #[traced_test]
    #[test]
    fn metrics_auth_bypass_emits_startup_warn() {
        warn_metrics_auth_bypass(false);

        assert!(
            logs_contain("env_var=\"HORT_METRICS_REQUIRE_AUTH\""),
            "expected metrics-bypass warning to carry env_var=HORT_METRICS_REQUIRE_AUTH"
        );
        assert!(
            logs_contain("metrics endpoint authentication is DISABLED"),
            "expected the documented bypass-warning lede"
        );
    }

    #[traced_test]
    #[test]
    fn metrics_auth_default_emits_no_bypass_warn() {
        warn_metrics_auth_bypass(true);

        assert!(
            !logs_contain("env_var=\"HORT_METRICS_REQUIRE_AUTH\""),
            "no metrics-bypass warning should be emitted when require_auth is true"
        );
    }
}
