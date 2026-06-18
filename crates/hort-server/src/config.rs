//! Environment-driven configuration for the `hort-server` binary.
//!
//! `Config::from_env()` is the only entrypoint. It returns a concrete
//! [`ConfigError`] per missing or invalid field — no defaulting for the
//! Postgres DSN or backend-specific storage fields so misconfiguration is
//! a loud startup failure, not a quiet one.
//!
//! **DSN precedence:** the canonical operator var is
//! `HORT_DATABASE_URL`; bare `DATABASE_URL` is honored as a compat fallback
//! for sqlx-cli, the Tier-2 `maybe_pool()` test helpers, and 12-factor
//! tooling. `MinimalConfig::from_env` (and thus `Config::from_env` and every
//! DB-only subcommand) reads `HORT_DATABASE_URL`, falling back to
//! `DATABASE_URL` — identical to `hort-worker`.

use std::collections::HashMap;
use std::net::{AddrParseError, SocketAddr};
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

use hort_config::ExtraCaParseError;
use hort_domain::entities::rbac::ClaimMapping;
use ipnet::IpNet;

/// Fully-parsed runtime configuration.
///
/// `Debug` is implemented manually to redact `database_url`, `redis_url`,
/// and the per-class Redis overrides `redis_url_evictable` /
/// `redis_url_durable`.
/// All four are DSN-bearing fields that carry passwords inline
/// (e.g. `postgres://user:pw@host/db`); a derive would surface them
/// through any `{:?}` expansion — panic messages, `.unwrap()` failures,
/// ad-hoc `info!(?cfg)` logging — and leak them into log shippers or
/// crash dumps. Every other field stays visible because operators rely
/// on `?cfg` output to diagnose misconfiguration.
#[derive(Clone)]
pub struct Config {
    /// Postgres connection string. Required. Read from `HORT_DATABASE_URL`
    /// (canonical), falling back to bare `DATABASE_URL` (ADR 0029).
    pub database_url: String,
    /// Storage backend + backend-specific settings.
    pub storage: StorageConfig,
    /// Address the main API listener binds to. Defaults to
    /// `127.0.0.1:8080` (an unspecified default of `0.0.0.0:8080`
    /// would silently expose the registry
    /// to every reachable network when the operator forgot the
    /// reverse-proxy's bind interface or NetworkPolicy).
    ///
    /// Operators who need the listener reachable on every interface —
    /// typically containerised deployments where ingress routes to
    /// `0.0.0.0:8080` — set `HORT_API_BIND=0.0.0.0:8080` explicitly. The
    /// chart-side decision lives in `api.bindAddr` (one value, one
    /// mental model — same shape as `metrics.bindAddr`).
    pub api_bind_addr: SocketAddr,
    /// When `true`, `Config::from_env`
    /// refuses to start if the binary has no positive evidence the
    /// public-facing connection is TLS (`HORT_PUBLIC_BASE_URL` is
    /// `http://` AND `HORT_TRUSTED_PROXY_CIDRS` is empty). Defaults to
    /// `false` so existing local-dev setups keep booting.
    ///
    /// The AND-condition is deliberate: a non-empty
    /// `HORT_TRUSTED_PROXY_CIDRS` indicates the operator has wired a
    /// reverse proxy and trusts its `X-Forwarded-Proto` header to set
    /// the public scheme — under that posture we trust the operator's
    /// deployment shape regardless of the configured base URL's
    /// scheme. Only the "neither pinned nor proxied" case fails.
    pub require_https: bool,
    /// When set, `/metrics` is served on this address only; the main router
    /// drops the scrape endpoint. Controlled via `HORT_METRICS_BIND`.
    ///
    /// **Safety guard:** binding the metrics
    /// listener to the unspecified address (`0.0.0.0` / `[::]:port`)
    /// is refused unless [`Self::metrics_public_bind`] is `true`.
    /// Misconfigured network policy (or none at all) would otherwise
    /// expose the scrape surface to every reachable network — the
    /// endpoint reveals repository names, error rates, and traffic
    /// shape, exactly the reconnaissance signal an attacker uses to
    /// time probes around real traffic.
    pub metrics_bind_addr: Option<SocketAddr>,
    /// When `true` (the default), the
    /// `/metrics` route requires admin authentication on both the
    /// admin listener (`build_admin_router`) and the main listener
    /// when `HORT_METRICS_BIND` is unset (auth dispatch carve-out in
    /// `wrap_with_middleware`). Anonymous scrapes return 401.
    ///
    /// `HORT_METRICS_REQUIRE_AUTH=false` re-permits anonymous scraping
    /// for legacy deployments and emits a startup `WARN` so the
    /// trade-off is visible in logs / log shippers. The endpoint
    /// reveals repository names, auth-failure rates, and traffic
    /// shape — opting out re-opens the reconnaissance vector this
    /// lockdown closes.
    pub metrics_require_auth: bool,
    /// When `false` (the default), the
    /// metrics listener refuses to bind to the unspecified address
    /// (`0.0.0.0:port` or `[::]:port`). Operators who genuinely want
    /// the scrape surface reachable from any network (typically
    /// because ingress / NetworkPolicy already restricts it) opt in
    /// via `HORT_METRICS_PUBLIC_BIND=true`.
    ///
    /// Loopback (`127.0.0.1` / `::1`) and concrete interface
    /// addresses are always allowed — the guard is specifically
    /// against the easy-to-typo "0.0.0.0" default that operators
    /// reach for when they want "any interface" but don't think
    /// through the public-internet exposure.
    pub metrics_public_bind: bool,
    /// When set, the internal-only
    /// **control-plane** routes (the `/admin` API, `/api/v1/admin/*`
    /// admin surfaces, and `/api/v1/subscriptions` management) are
    /// served on this address only; the public/main router drops them.
    /// Controlled via `HORT_CONTROL_BIND`, mirroring the
    /// [`Self::metrics_bind_addr`] split exactly.
    ///
    /// **Default = unset = `None`** ⇒ control routes stay on the main
    /// listener, byte-identical to today (no migration). The
    /// token-generation plane (`/api/v1/auth/exchange`, `/api/v1/auth`,
    /// OCI `/v2/auth`) and the artifact-pull plane are **never** moved
    /// here — they are public by requirement.
    ///
    /// **Safety guard:** binding to the unspecified address (`0.0.0.0`
    /// / `[::]:port`) is refused unless [`Self::control_public_bind`]
    /// is `true` — the same "0.0.0.0 footgun" refusal the metrics
    /// listener carries.
    pub control_bind_addr: Option<SocketAddr>,
    /// When `false` (the default), the
    /// control listener refuses to bind to the unspecified address
    /// (`0.0.0.0:port` or `[::]:port`). Operators who genuinely want
    /// the control surface reachable from any network (typically
    /// because ingress / NetworkPolicy already restricts it) opt in
    /// via `HORT_CONTROL_PUBLIC_BIND=true`. Mirrors
    /// [`Self::metrics_public_bind`].
    pub control_public_bind: bool,
    /// Log format. Defaults to `pretty`.
    pub log_format: LogFormat,
    /// Controls the `repository` label emitted by use cases. Defaults to
    /// `true`. Set `METRICS_INCLUDE_REPOSITORY_LABEL=false` at scale to cap
    /// series cardinality (emits the `_all` sentinel instead).
    pub include_repository_label: bool,
    /// Controls the `service_account` label on
    /// `hort_rotation_lag_seconds` and
    /// `hort_service_account_authenticated_total`. Defaults to `true`
    /// (operator-declared SA count is typically <50). Set
    /// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL=false` at scale to
    /// collapse the per-SA dimension to `_all`; both metrics honour
    /// the same toggle so the rotation gauge and the auth counter
    /// stay in lock-step.
    pub include_service_account_label: bool,
    /// Operator overrides for per-format upload-payload metadata size
    /// caps (the third layer of the three-layer model: handler
    /// declared max → per-format operator cap → global blob cap).
    ///
    /// Keys are lowercase format identifiers matching
    /// `FormatHandler::format_key()` (e.g. `"pypi"`, `"npm"`, `"cargo"`).
    /// Values are byte counts. Absent keys fall through to the handler's
    /// declared expected max.
    ///
    /// Parsed from environment variables of the form
    /// `METADATA_CAP_BYTES_<FORMAT>=<bytes>`, uppercase suffix. Empty
    /// values are ignored (fall-through to handler default); non-integer
    /// or negative values surface as [`ConfigError::InvalidInt`].
    pub metadata_caps: HashMap<String, usize>,
    /// Global safety cap on the size of a metadata blob written to CAS
    /// by the HashReference strategy. Set via `HORT_METADATA_BLOB_MAX_SIZE`
    /// (a size string, e.g. `10Mi`); defaults to 10 MB (10 * 1024 * 1024).
    ///
    /// A payload above this ceiling rejects the ingest with
    /// `hort_ingest_total{result="metadata_too_large"}` and a tracing log
    /// carrying `reason="blob-too-large"` — the same metric label as the
    /// per-format inline cap, different tracing reason.
    /// Splitting the label space further would bloat counter cardinality
    /// with no operational benefit.
    ///
    /// `0` is treated as "accept anything" — useful for tests that must
    /// exercise the CAS round-trip without worrying about ceilings, and
    /// documented explicitly as an operator escape hatch. Malformed
    /// values surface as [`ConfigError::InvalidValue`].
    pub metadata_blob_max_bytes: usize,
    /// Explicit public-facing base URL for absolute-URL emission in
    /// packument / config.json / index responses. Set via
    /// `HORT_PUBLIC_BASE_URL`, e.g. `https://hort.example.com`.
    ///
    /// When set, overrides both request headers (`X-Forwarded-Proto`,
    /// `X-Forwarded-Host`, `Host`) — the operator states the public URL
    /// explicitly. When unset, handlers fall back to
    /// `X-Forwarded-Proto` + `X-Forwarded-Host` (both forwarded),
    /// `X-Forwarded-Proto` + `Host` (only proto forwarded), or
    /// `Host` + default `https` scheme.
    ///
    /// The default-`https` fallback keeps production deployments
    /// behind a TLS-terminating proxy correct without any config: the
    /// proxy sets `X-Forwarded-Proto: https`. Deployments without a
    /// proxy (E2E harness, local dev, direct docker-compose) set
    /// this variable so clients don't get `https://<host>:<plain-http-port>`
    /// URLs that fail with `ERR_SSL_WRONG_VERSION_NUMBER`.
    ///
    /// Only scheme + authority are used — any path, query, or fragment
    /// on the configured URL is stripped. Parse errors at startup are a
    /// loud `ConfigError::InvalidUrl`, not a silent fall-through.
    ///
    /// Pattern matches Keycloak's `KC_HOSTNAME`, Gitea's `ROOT_URL`,
    /// GitLab's `external_url`, Nextcloud's `overwrite.cli.url`.
    pub public_base_url: Option<url::Url>,
    /// IP allowlist of reverse proxies whose
    /// `X-Forwarded-*` headers may be trusted. Parsed from
    /// comma-separated CSV in `HORT_TRUSTED_PROXY_CIDRS`
    /// (e.g. `10.0.0.0/8,192.168.1.0/24,::1/128`). Empty when the env
    /// var is unset or empty.
    ///
    /// **Startup invariant:** when BOTH this list is empty AND
    /// `HORT_PUBLIC_BASE_URL` is unset, `from_env` fails with
    /// [`ConfigError::TrustUnconfigured`]. The check is NOT
    /// auth-gated — X-Forwarded-Host injection poisoning package download
    /// URLs is orthogonal to authentication.
    ///
    /// Individual malformed CIDR entries surface as
    /// [`ConfigError::InvalidCidr`] with the offending string.
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// Authentication provider configuration.
    ///
    /// `AuthConfig::Disabled` (default) preserves the
    /// anonymous behaviour — no middleware attaches, handlers skip the
    /// authorization check. `AuthConfig::Oidc(_)` enables the OIDC bearer
    /// path; per-request validation lives in the OIDC adapter.
    ///
    /// Parsed from `HORT_AUTH_PROVIDER=disabled|oidc`.
    pub auth: AuthConfig,
    /// Declarative IdP-group→claim mappings (ADR 0012).
    ///
    /// There is no legacy `HORT_GROUP_MAPPINGS_PATH`
    /// single-file loader; mappings load exclusively from
    /// `$HORT_CONFIG_DIR/auth/*.yaml` via the gitops parser. This field is
    /// always the empty vec at config-parse time — `cli::serve` populates
    /// `AuthenticateUseCase::new` from `ClaimMappingRepository::list_all()`
    /// after the boot apply, so the in-process value is never consulted.
    /// Kept on `Config` so the `build_app_context` signature stays stable;
    /// once a refactor removes the parameter, this field can drop too.
    pub claim_mappings: Vec<ClaimMapping>,
    /// Directory containing the gitops YAML
    /// envelopes (one declarable object per file). Parsed from
    /// `HORT_CONFIG_DIR`. `None` when unset; `Some(p)` requires `p` to
    /// be an existing directory at parse time so a typo fails fast
    /// rather than waiting for the first file walk.
    ///
    /// When `Some(_)`, the boot sequence in `cli::serve` calls
    /// `gitops_boot::apply_config_from_dir` BEFORE `build_app_context`,
    /// so the `Vec<GroupMapping>` consumed by `AuthenticateUseCase::new`
    /// reflects the post-apply state.
    pub config_dir: Option<PathBuf>,
    /// Optional operator override of the default
    /// per-publish body-size ceiling. Parsed from
    /// `HORT_PUBLISH_BODY_MAX_SIZE` (a size string, e.g. `300Mi`). `None`
    /// → the route builders fall back to
    /// `hort_http_core::limits::DEFAULT_PUBLISH_BODY_LIMIT` (300 MiB).
    /// Malformed values surface as [`ConfigError::InvalidValue`].
    ///
    /// Only PyPI and npm consume this override; Cargo carries its own
    /// fixed 200 MiB ceiling per `hort_http_core::limits::CARGO_PUBLISH_BODY_LIMIT`.
    pub publish_body_limit_bytes: Option<usize>,
    /// Per-session Postgres statement timeout.
    /// Parsed from `PG_STATEMENT_TIMEOUT_MS`.
    ///
    /// When `Some(ms)`, the serve entrypoint registers a
    /// `PgPoolOptions::after_connect` hook that runs
    /// `SET statement_timeout = <ms>` on every freshly-opened connection.
    /// When `None`, no hook runs and Postgres' default (no statement
    /// timeout) applies. Non-integer values surface as
    /// [`ConfigError::InvalidInt`]; zero surfaces as
    /// [`ConfigError::ValueNotPositive`] (because `SET statement_timeout = 0`
    /// silently disables the timeout — not what the operator meant).
    pub pg_statement_timeout_ms: Option<u64>,
    /// Maximum time to wait for a connection from
    /// the Postgres pool. Parsed from `PG_ACQUIRE_TIMEOUT_SECS`; defaults
    /// to `30` seconds.
    ///
    /// Wired into `PgPoolOptions::acquire_timeout(Duration::from_secs(..))`
    /// unconditionally — a bounded wait is the right default for every
    /// production deployment. Non-integer values surface as
    /// [`ConfigError::InvalidInt`]; zero surfaces as
    /// [`ConfigError::ValueNotPositive`] (would make every acquisition
    /// fail immediately).
    pub pg_acquire_timeout_secs: u64,
    /// Per-kid JWKS signature-mismatch eviction
    /// cooldown, in seconds. Parsed from `HORT_JWKS_EVICTION_BACKOFF_SECS`;
    /// defaults to `10`.
    ///
    /// A second `SignatureMismatch` eviction for the same kid within
    /// this window is a no-op (no JWKS refetch fires). Closes the
    /// forged-kid DoS vector. Does NOT gate legitimate key-rotation
    /// refreshes — first-seen kids (`KidNotInCache`) always refetch.
    /// Zero surfaces as [`ConfigError::ValueNotPositive`] (would
    /// disable the mitigation entirely).
    pub jwks_eviction_backoff_secs: u64,
    /// Upper bound on discovery + JWKS response
    /// body size, in bytes. Parsed from `HORT_JWKS_RESP_BODY_MAX_SIZE`
    /// (a size string, e.g. `1Mi`); defaults to `1048576` (1 MiB).
    ///
    /// Responses exceeding this cap are rejected BEFORE parsing;
    /// prevents a malicious or misconfigured IdP from OOMing hort-server
    /// via an unbounded body. A sub-1-byte value (including zero)
    /// surfaces as [`ConfigError::InvalidValue`] (would reject every JWKS
    /// refresh).
    pub jwks_resp_body_max_bytes: usize,
    /// Per-IP auth-attempt rate-limit cap,
    /// in requests per minute. Parsed from `HORT_RATELIMIT_AUTH_PER_MIN`;
    /// defaults to `60`.
    ///
    /// Applied by [`hort_http_core::middleware::rate_limit::auth_rate_limit_layer`]
    /// wrapping `require_principal`. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`] — a zero burst would reject every
    /// request and the layer's `build_governor_config` asserts non-zero.
    pub ratelimit_auth_per_min: u32,
    /// Per-IP write-path rate-limit cap,
    /// in requests per minute. Parsed from `HORT_RATELIMIT_WRITE_PER_MIN`;
    /// defaults to `300`.
    ///
    /// Applied by [`hort_http_core::middleware::rate_limit::write_rate_limit_layer`]
    /// wrapping the POST/PUT/DELETE sub-router. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`].
    pub ratelimit_write_per_min: u32,
    /// Workspace-wide concurrent-request
    /// cap. Parsed from `HORT_MAX_INFLIGHT`; defaults to `512`.
    ///
    /// Backs [`hort_http_core::middleware::load_shed::global_load_shed_middleware`].
    /// Zero surfaces as [`ConfigError::ValueNotPositive`] — a zero cap
    /// would shed every request and `NonZeroUsize::new(0)` returns
    /// `None` at the middleware constructor.
    pub max_inflight: usize,
    /// Per-IP concurrent-request cap.
    /// Parsed from `HORT_MAX_INFLIGHT_PER_IP`; defaults to `32`.
    ///
    /// Backs [`hort_http_core::middleware::load_shed::per_ip_load_shed_middleware`].
    /// Zero surfaces as [`ConfigError::ValueNotPositive`].
    pub max_inflight_per_ip: usize,
    /// RBAC evaluator snapshot poll cadence,
    /// in seconds. Parsed from `HORT_RBAC_REFRESH_SECS`; defaults to `30`.
    ///
    /// The background task in [`crate::cli::serve`] polls
    /// `role_repo.list_all_roles() + list_grants_for_roles()` every
    /// interval and atomically swaps the `ArcSwap<RbacEvaluator>` held
    /// in `AuthContext::Enabled.rbac` if the snapshot changed. Zero
    /// surfaces as [`ConfigError::ValueNotPositive`] — a zero interval
    /// would either busy-loop the refresh task or be a nonsensical
    /// "never poll" request the operator almost certainly didn't mean.
    pub rbac_refresh_secs: u32,
    /// The
    /// checkpoint-emission cadence, in seconds, that the offline
    /// `verify-event-chain` subcommand uses for its anchor-staleness
    /// window (a checkpoint older than `2 × cadence` is reported
    /// `missing_checkpoint`). Parsed from
    /// `HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS`; defaults to `3600`
    /// (hourly). MUST match the deployment's actual
    /// `eventstore-checkpoint` CronJob cadence so the staleness window
    /// is meaningful. Zero surfaces as [`ConfigError::ValueNotPositive`]
    /// — a zero cadence would make `2 × cadence` zero and report every
    /// anchor stale.
    pub event_chain_checkpoint_cadence_secs: u64,
    /// Filesystem root for stateful-upload chunk staging (port:
    /// [`hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort`]).
    /// First consumer is the OCI three-phase
    /// upload; the port is format-agnostic.
    /// Parsed from `HORT_STATEFUL_UPLOAD_STAGING_DIR`;
    /// when the env var is unset the default is
    /// `<HORT_STORAGE_FILESYSTEM_PATH>/stateful-upload-staging` (or a fixed
    /// `/var/lib/hort/stateful-upload-staging` when the
    /// configured storage backend is S3).
    ///
    /// MUST NOT share a directory tree with the CAS root — staging
    /// bytes are pre-hash scratch space and a collision between the
    /// two naming schemes would surface as silent data corruption.
    /// Operators deploying against S3 MUST set this explicitly (the
    /// default path is a guess that may not exist on the container).
    ///
    /// Backwards compatibility: the legacy env var `HORT_OCI_STAGING_DIR`
    /// is no longer read. The on-disk directory the runtime materializes
    /// changed names too — operators upgrading from a deployment that
    /// relied on the old default `<HORT_STORAGE_FILESYSTEM_PATH>/oci-staging` should
    /// either delete the old directory (no in-flight uploads survive a
    /// process restart anyway — the EphemeralStore session entries are
    /// TTL-bounded) or set the env var explicitly to the old path
    /// during the transition.
    pub stateful_upload_staging_dir: PathBuf,
    /// Docker-legacy global `/v2/_catalog`
    /// endpoint toggle. `false` by default (modern-strict); set
    /// `HORT_OCI_LEGACY_CATALOG_ENABLED=true` to mount the aggregating
    /// endpoint. The modern per-repo `/v2/:repo_key/_catalog` is
    /// always mounted regardless of this flag.
    ///
    /// Default-off is a security choice: the global endpoint is a
    /// registry-wide enumeration surface. Operators opt in
    /// consciously, usually for Docker Hub tooling compatibility.
    pub oci_legacy_catalog_enabled: bool,
    /// Per-`(repo, principal)`
    /// outstanding-session cap on the OCI three-phase blob upload.
    /// Parsed from `HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL`; default
    /// `32`. Once a caller already holds this many open sessions
    /// against the same repository, new `POST /v2/<name>/blobs/uploads/`
    /// requests are rejected with `429 Too Many Requests` and the
    /// counter decrements on session finalize / cancel / TTL
    /// expiry.
    ///
    /// Zero surfaces as [`ConfigError::ValueNotPositive`] — a zero
    /// cap rejects every initiate, breaking the OCI push protocol
    /// for every authenticated user, which is almost certainly not
    /// what the operator meant.
    pub oci_max_sessions_per_principal: u32,
    /// Selection between the in-memory and
    /// Redis backends for the `EphemeralStore` port. Default in dev /
    /// test is [`EphemeralStoreBackend::Memory`]; operators running
    /// multi-node deployments MUST set `HORT_EPHEMERAL_STORE_BACKEND=redis`
    /// so every replica sees the same upload-session / idempotency
    /// state. Unknown values fail startup loudly.
    pub ephemeral_store_backend: EphemeralStoreBackend,
    /// Redis URL used by the Redis backend of
    /// the `EphemeralStore` port. Required when
    /// [`Self::ephemeral_store_backend`] is
    /// [`EphemeralStoreBackend::Redis`]; ignored (set to an empty
    /// string) when the memory backend is selected. Parse failures
    /// surface as [`ConfigError::InvalidUrl`]; an empty / missing
    /// URL under the Redis backend surfaces as
    /// [`ConfigError::Missing`].
    pub redis_url: Option<String>,
    /// Optional override for the **evictable**
    /// `EphemeralStore` class (Cargo / PyPI / npm sparse-index and
    /// packument caches, pull-through dedup keys). Parsed from
    /// `HORT_REDIS_URL_EVICTABLE`. Empty string is treated as unset.
    /// When unset, the composition root falls back to
    /// [`Self::redis_url`]. Parsing is independent of
    /// [`Self::ephemeral_store_backend`] — the Memory branch never
    /// consults this field at composition time.
    pub redis_url_evictable: Option<String>,
    /// Optional override for the **durable**
    /// `EphemeralStore` class (auth lockout flags + counters, PAT
    /// brute-force lockout, OCI three-phase upload session records,
    /// OCI per-(repo, principal) session-count cap, auth-event
    /// throttle). Parsed from `HORT_REDIS_URL_DURABLE`. Empty string
    /// is treated as unset. When unset, the composition root falls
    /// back to [`Self::redis_url`]. Parsing is independent of
    /// [`Self::ephemeral_store_backend`] — the Memory branch never
    /// consults this field at composition time.
    pub redis_url_durable: Option<String>,
    /// Refresh cadence (seconds) for the
    /// pull-through upstream resolver's in-memory snapshot. Parsed
    /// from `HORT_UPSTREAM_RESOLVER_REFRESH_SECS`; defaults to 60.
    /// Min 5; values below trip a parse error so a typo doesn't
    /// hammer the DB.
    pub upstream_resolver_refresh_secs: u32,
    /// Storage backstop on the cached
    /// upstream body for `fetch_metadata`, resolved to bytes. Parsed
    /// from `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`, which accepts a
    /// human-readable size string (`64Mi`, `1Gi`, `512Ki`, decimal
    /// `64M`, or a bare byte integer); default 64 MiB. Wired into
    /// [`hort_adapters_upstream_http::HttpUpstreamProxyConfig::
    /// metadata_cache_max_bytes`]. Minimum 1024 bytes (a smaller cap
    /// is a typo, not a deployment choice — every realistic packument
    /// is far larger). The backstop replaces the retired
    /// `METADATA_BODY_CAP_BYTES = 10 MiB` buffer-cap constant.
    pub upstream_metadata_cache_max_bytes: u64,
    /// Storage backstop on the cached
    /// upstream body for `fetch_manifest`, resolved to bytes. Parsed
    /// from `HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE` (size string, see
    /// above); default 16 MiB. Wired into
    /// [`hort_adapters_upstream_http::HttpUpstreamProxyConfig::
    /// manifest_cache_max_bytes`]. Minimum 1024 bytes. Replaces the
    /// retired `MANIFEST_BODY_CAP_BYTES = 4 MiB` constant.
    pub upstream_manifest_cache_max_bytes: u64,
    /// Per-version-object cap inside the
    /// streaming JSON projector (npm `versions{}` value, PyPI
    /// `files[]` entry), resolved to bytes. Parsed from
    /// `HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE` (size string,
    /// see above); default 2 MiB (raised from the sketched 1 MiB to
    /// absorb the observed `@mui/icons-material` 1.37 MB outlier
    /// without a day-one cap trip). Consumed by the per-format
    /// projectors. Minimum 1024 bytes.
    pub upstream_projector_version_object_max_bytes: u64,
    /// HTTP/1 header-read timeout (in
    /// seconds). Parsed from `HORT_HTTP_HEADER_READ_TIMEOUT_SECS`;
    /// defaults to `15`. Wired into
    /// [`crate::serve_loop::HttpTimeouts::header_read_timeout`] which
    /// then passes it through to
    /// `hyper_util::server::conn::auto::Http1Builder::header_read_timeout`.
    ///
    /// Caps how long a slow-header client can pin a hyper accept
    /// worker before the connection is dropped — the slowloris kill.
    /// On HTTP/1 keep-alive connections this also bounds between-
    /// request idle (the next request's headers must arrive within
    /// the window). Zero surfaces as
    /// [`ConfigError::ValueNotPositive`] — disabling the slowloris
    /// defence entirely is almost certainly not what the operator
    /// meant.
    pub http_header_read_timeout_secs: u64,
    /// Global per-request deadline (in
    /// seconds). Parsed from `HORT_HTTP_REQUEST_TIMEOUT_SECS`; defaults
    /// to `300` (5 minutes). Wired into
    /// [`hort_http_core::middleware::request_timeout::request_timeout_layer`]
    /// at the outer router-wrap. Handlers exceeding the deadline are
    /// cancelled and the client sees `408 Request Timeout`.
    ///
    /// Distinct from `header_read_timeout`: the deadline starts AFTER
    /// the server has parsed a complete request — it bounds handler
    /// runtime, not slowloris arrival. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`].
    ///
    /// OCI blob upload routes (`PATCH/PUT /v2/.../blobs/uploads/`)
    /// override this with the longer ceiling carried in
    /// [`Self::http_oci_upload_timeout_secs`].
    pub http_request_timeout_secs: u64,
    /// Per-route ceiling for the OCI blob
    /// upload subtree (in seconds). Parsed from
    /// `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS`; defaults to `3600` (60
    /// minutes). Multi-GB OCI layer pushes legitimately exceed the
    /// global 5-minute deadline; this longer ceiling exists so a
    /// stuck push terminates instead of pinning a worker forever.
    /// Zero surfaces as [`ConfigError::ValueNotPositive`].
    pub http_oci_upload_timeout_secs: u64,
    /// `Failed(NotFound)` negative-cache TTL
    /// for the pull-through deduplication service, in seconds.
    /// Parsed from `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS`; defaults to
    /// `30`. Wired into
    /// [`hort_app::pull_dedup::PullDedupConfig::ttl_not_found`]. Zero
    /// surfaces as [`ConfigError::ValueNotPositive`] — a zero TTL
    /// would re-fetch on every retry within the negative-cache
    /// window, defeating the coalescing benefit on 404 storms.
    pub pull_dedup_ttl_not_found_secs: u64,
    /// `Failed(RateLimited | Upstream5xx |
    /// Upstream4xx | Unauthorized)` negative-cache TTL for the
    /// pull-through deduplication service, in seconds. Parsed from
    /// `HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS`; defaults to `10`. Wired
    /// into [`hort_app::pull_dedup::PullDedupConfig::ttl_unavailable`].
    /// Shorter than the not-found TTL because transient
    /// unavailability resolves faster. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`].
    pub pull_dedup_ttl_unavailable_secs: u64,
    /// `Failed(Timeout | NetworkError)`
    /// negative-cache TTL for the pull-through deduplication
    /// service, in seconds. Parsed from
    /// `HORT_PULL_DEDUP_TTL_TIMEOUT_SECS`; defaults to `10`. Wired
    /// into [`hort_app::pull_dedup::PullDedupConfig::ttl_timeout`].
    /// Same default as `ttl_unavailable_secs`; transient transport
    /// failures cluster with transient HTTP failures. Zero surfaces
    /// as [`ConfigError::ValueNotPositive`].
    pub pull_dedup_ttl_timeout_secs: u64,
    /// `Failed(ChecksumMismatch | ParseError
    /// | BodyTooLarge | PinMismatch | CaUnknown)` negative-cache TTL
    /// for the pull-through deduplication service, in seconds.
    /// Parsed from `HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS`;
    /// defaults to `60`. Wired into
    /// [`hort_app::pull_dedup::PullDedupConfig::ttl_checksum_mismatch`].
    /// Longer than the other TTLs because content-policy and TLS-
    /// trust failures require operator intervention to resolve;
    /// holding the negative cache prevents thrash on repeated client
    /// retries during the operator's fix window. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`].
    pub pull_dedup_ttl_checksum_mismatch_secs: u64,
    /// Follower-side absolute ceiling for the
    /// pull-through deduplication service, in seconds. Parsed from
    /// `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS`; defaults to `300` (5 min).
    /// Wired into
    /// [`hort_app::pull_dedup::PullDedupConfig::follower_wait`]. On
    /// expiry the follower returns `503 + Retry-After: 30` rather
    /// than falling through to an un-coalesced fetch (breaking
    /// coalescing on a stuck leader will not speed up the underlying
    /// upstream). Zero surfaces as
    /// [`ConfigError::ValueNotPositive`].
    pub pull_dedup_follower_wait_secs: u64,
    /// Wall-clock cap on the
    /// graceful-shutdown wait, in seconds. Parsed from
    /// `HORT_SHUTDOWN_GRACE_SECS`; defaults to `60`.
    ///
    /// `axum::serve(...).with_graceful_shutdown(...)` (and the
    /// `serve_with_hyper_util` accept loop that replaced it) will
    /// otherwise block on a stuck handler indefinitely, leading
    /// orchestrators (systemd, k8s) to escalate to `SIGKILL` —
    /// which leaves in-flight uploads in undefined state. Wrapping
    /// the await in [`tokio::time::timeout`] of this duration gives
    /// a predictable shutdown bound: clean drain inside the window
    /// returns silently; expiry emits a `tracing::warn!` carrying
    /// the in-flight request count and the configured grace
    /// (target = `hort::shutdown`) before the runtime aborts the
    /// outstanding handles via drop.
    ///
    /// Zero surfaces as [`ConfigError::ValueNotPositive`] — a
    /// zero-second grace would skip drain entirely on every
    /// shutdown, which is almost never the operator-meaningful
    /// "disable" choice for a registry.
    pub shutdown_grace_secs: u64,
    /// Operator-controlled enumerated
    /// allowlist of upstream hosts, enforced at gitops-apply time
    /// when an `UpstreamMapping` row is created or updated. Parsed
    /// from `HORT_UPSTREAM_ALLOWLIST_HOSTS` via
    /// [`hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist::parse`]:
    ///
    /// - Unset OR empty string → `Disabled` (default; preserves the
    ///   historical posture where every host is accepted).
    /// - `__deny_all__` (literal sentinel, exact match) → `Strict`
    ///   (every mapping rejected — bootstrap-only deployments).
    /// - `host1,host2,...` (comma-list) → `Hosts(...)` (exact-host
    ///   match; no suffix wildcard support).
    ///
    /// Empty-string is deliberately treated the same as unset to
    /// guard against k8s ConfigMap defaults / docker-compose
    /// `${VAR:-}` / shell `export VAR=` accidentally turning every
    /// upstream pull into a hard reject.
    ///
    /// Apply-time-only enforcement: tightening the allowlist later
    /// (removing a host, then re-applying) does NOT re-validate
    /// existing mappings. See `docs/operator/upstream-trust-model.md`.
    pub upstream_allowlist: hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist,
    /// Operator-chosen response when the
    /// CAS scrubber finds a hash mismatch. Parsed from
    /// `HORT_CAS_SCRUB_ACTION_ON_MISMATCH`:
    ///
    /// - Unset / empty / `alert` → [`ActionOnMismatch::Alert`]
    ///   (default; report-only).
    /// - `tombstone` → [`ActionOnMismatch::Tombstone`] (opt-in
    ///   auto-block — the scrubber transitions the artifact to
    ///   `quarantine_status = 'rejected'` via the existing quarantine
    ///   state machine, emits an `ArtifactCorrupted` domain event, and
    ///   subsequent download attempts are blocked at the application
    ///   layer).
    ///
    /// The default-alert posture is intentional: both
    /// options are valid; default-alert preserves backwards
    /// compatibility within the RC stream so existing operators
    /// expecting flag-only behaviour are not surprised by a
    /// deploy-time policy shift.
    pub cas_scrub_action_on_mismatch: hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch,
    /// Operator opt-in to the native API
    /// token surface (`Bearer hort_<kind>_<body>`). Parsed from
    /// `HORT_NATIVE_TOKENS_ENABLED`; defaults to `false` (ADR 0012).
    /// When `true`, composition wires the
    /// `PatValidationUseCase` + `PatCache` and spawns the
    /// `api_token_revocation` PgListener. When `false` (default), the
    /// `AuthContext::Enabled.authenticate` carries no PAT validator
    /// and a `Bearer hort_<kind>_<body>` token falls through to the
    /// OIDC port (which 401s).
    pub enable_native_tokens: bool,
    /// Operator opt-out for the event-notification
    /// substrate. Parsed from `HORT_NOTIFICATIONS_ENABLED`; defaults to
    /// `true`. When `false`, the [`EventStorePublisher`] is constructed
    /// without a broadcast channel and the
    /// `NotificationDispatcher` task does not start — every
    /// `EventStore::append` is a pure pass-through and no
    /// `tokio::sync::broadcast::Sender` allocation occurs. The default-on
    /// posture is intentional: the broadcast itself is best-effort,
    /// zero-CPU when there are no subscribers, and v1 attaches the
    /// dispatcher conditionally on operator-configured `Subscription`
    /// rows existing — the runtime cost of `true` with no rows is one
    /// `broadcast::channel(N)` allocation at boot + silent `send` errors
    /// per append.
    ///
    /// [`EventStorePublisher`]: hort_app::event_store_publisher::EventStorePublisher
    pub enable_notifications: bool,
    /// Capacity of the broadcast channel between
    /// the [`EventStorePublisher`] and the
    /// `NotificationDispatcher` per-subscription tasks. Parsed from
    /// `HORT_NOTIFY_CHANNEL_CAPACITY`; defaults to `1024`. Lagging
    /// consumers see `RecvError::Lagged` and drop into catch-up against
    /// `read_category`. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`] — the
    /// `broadcast::channel(0)` shape is meaningless (no slot to hold
    /// even one in-flight event).
    ///
    /// [`EventStorePublisher`]: hort_app::event_store_publisher::EventStorePublisher
    pub notify_channel_capacity: u32,
    /// When `false` (default),
    /// webhook URLs must be `https://`. When `true`, `http://` is
    /// allowed AND `hort_unsafe_config_active{kind="plaintext_webhooks"}`
    /// is set to `1` at boot.
    ///
    /// **Transport flag, not a trust knob.** No `*_INSECURE_TLS`
    /// equivalent is allowed (ADR 0010). Operators trust
    /// internal CAs via `HORT_EXTRA_CA_BUNDLE`.
    pub allow_plaintext_webhooks: bool,
    /// When `false` (default),
    /// webhook target URLs must resolve to a routable address
    /// (`hort_net_egress::is_routable`). When `true`, the SSRF check is
    /// skipped AND `hort_unsafe_config_active{kind="webhook_nonroutable_targets"}`
    /// is set to `1` at boot. Operators with legitimate internal
    /// webhook receivers flip this deliberately.
    pub allow_nonroutable_webhook_targets: bool,
    /// When `Some(url)`, composition opens an
    /// async-nats client and exposes a `NatsNotifier` to the dispatcher.
    /// When `None`, the NATS adapter is not constructed (subscriptions
    /// with `SubscriptionTarget::NatsJetStream { ... }` will fail
    /// delivery with no notifier supporting that target_kind).
    pub nats_url: Option<String>,
    /// Operator override allowing bearer
    /// authentication over plaintext HTTP. Parsed from
    /// `HORT_BEARER_ALLOW_OVER_HTTP`; defaults to `false`. When `false`,
    /// the auth middleware emits `426 Upgrade Required` on a
    /// PAT-shaped token OR a CliSession-family JWT whose
    /// request lacks TLS evidence
    /// (`RequestTrust.public_url.scheme() != "https"`).
    ///
    /// **Transport flag, not a trust knob.** No `*_INSECURE_TLS`
    /// equivalent is allowed (see anti-pattern in CLAUDE.md). Setting
    /// this to `true` emits one boot-time `tracing::warn!` and sets
    /// `hort_unsafe_config_active{kind="pat_over_http"} = 1` so the
    /// misconfig is visible on every dashboard.
    pub allow_pat_over_http: bool,
    /// Capacity of the in-process PAT
    /// validation cache. Parsed from `HORT_PAT_CACHE_SIZE`; defaults to
    /// `10000`. LRU-evicting; entries older than the 5-minute TTL are
    /// purged on read. Zero surfaces as
    /// [`ConfigError::ValueNotPositive`].
    pub pat_cache_size: usize,
    /// Per-IP failed-attempt threshold for
    /// PAT validation. Parsed from `HORT_PAT_LOCKOUT_THRESHOLD`;
    /// defaults to `30`. This is the bearer-path PAT-specific lockout
    /// mechanism (keyspace `pat-attempt:`); there is no
    /// `authenticate_local` per-IP lockout (that path was
    /// removed end-to-end with the password-identity surface).
    pub pat_lockout_threshold: u32,
    /// Sliding window (in seconds) for the
    /// PAT failed-attempt counter. Parsed from
    /// `HORT_PAT_LOCKOUT_WINDOW_SECS`; defaults to `300` (5 min).
    /// Window-anchored at first failure; subsequent failures inside
    /// the window do NOT extend the TTL.
    pub pat_lockout_window_secs: u64,
    /// How long the PAT lockout flag stays
    /// active after the threshold trips. Parsed from
    /// `HORT_PAT_LOCKOUT_DURATION_SECS`; defaults to `900` (15 min).
    /// During lockout, every PAT validation fast-fails with
    /// [`hort_app::use_cases::pat_validation_use_case::PatValidationError::RateLimited`]
    /// and zero Argon2 calls.
    pub pat_lockout_duration_secs: u64,
    /// `HORT_TOKEN_ALLOW_ADMIN`. When `true`,
    /// the issuance use case permits `Permission::Admin` in
    /// `declared_permissions`. The caller must additionally hold
    /// admin authority and the requested expiry must fall within
    /// `[1, 30]` days. Defaults to `false` —
    /// admin tokens have caused real-world breaches at every registry
    /// that allowed them.
    pub allow_admin_tokens: bool,
    /// `HORT_TOKEN_ALLOW_UNBOUNDED_SVC`.
    /// When `true`, admin-mint may issue service-account tokens with
    /// `expires_in_days = null`. Default `false`
    /// (rotation drift / leaked-secret blast radius).
    /// Admin tokens cannot be unbounded regardless of this flag.
    pub allow_unbounded_svc_tokens: bool,
    /// Operator opt-in to the
    /// `POST /api/v1/auth/exchange` route (RFC 8693 token exchange).
    /// Parsed from `HORT_TOKEN_EXCHANGE_ENABLED`; defaults to `false`
    /// — when off, `hort-server::http` skips mounting
    /// the route and axum's default 404 fires for any caller, matching
    /// the "no surface advertised" requirement. When `true`, the route
    /// is mounted alongside the existing token endpoints.
    pub enable_token_exchange: bool,
    /// `HORT_REFCOUNT_RECONCILE_ON_STARTUP`.
    ///
    /// When `true`, `hort-server serve` runs the
    /// [`RefcountReconcileUseCase::sweep_drift`](hort_app::use_cases::refcount_reconcile_use_case::RefcountReconcileUseCase)
    /// sweep at boot — after gitops apply, **before any listener
    /// binds** (i.e. before external traffic is admitted) — bringing
    /// the eventually-authoritative `content_references` refcount
    /// projection back into agreement with `artifacts` +
    /// `artifact_metadata` (the named reconcile
    /// gate `PurgeUseCase` refuses to start without).
    ///
    /// **Default `true`** in
    /// fresh installs (off in upgrade installs that already have
    /// authoritative state). The binary defaults the flag to `true`
    /// (fresh-install posture — converging an eventually-authoritative
    /// projection is always safe and idempotent). Upgrade installs
    /// that already carry authoritative refcount state set
    /// `HORT_REFCOUNT_RECONCILE_ON_STARTUP=false` explicitly to skip the
    /// boot-time scan (a converged projection makes the sweep a no-op
    /// regardless, so the upgrade opt-out is a cost optimisation, not
    /// a correctness gate). The fresh-vs-upgrade distinction is an
    /// operator/deployment-manifest concern (Helm values), not
    /// something the binary can detect — the binary defaults to the
    /// safe posture and the upgrade manifest flips it.
    pub refcount_reconcile_on_startup: bool,
    /// PKCS#8 PEM of the active OCI-token
    /// Ed25519 signing key. Resolved from `HORT_OCI_TOKEN_SIGNING_KEY_FILE`
    /// (preferred) OR `HORT_OCI_TOKEN_SIGNING_KEY` (inline). The `_FILE`
    /// variant takes precedence when both are set with non-empty
    /// values they are treated as ambiguous and surface as
    /// [`ConfigError::AmbiguousSigningKeySource`] (boot-fail).
    ///
    /// Required when [`Self::enable_native_tokens`] is `true`; missing
    /// surfaces as [`ConfigError::OciTokenSigningKeyMissing`]. When
    /// `enable_native_tokens = false`, an unset key is the expected
    /// state and defaults to `None`; if either env var IS set the
    /// parser logs `tracing::debug!` noting it is unused and still
    /// stores it (so flipping `HORT_NATIVE_TOKENS_ENABLED=true` later
    /// without restarting the env doesn't trip a missing-key error).
    pub oci_token_signing_key_pem: Option<String>,
    /// Optional PEM of the previous OCI-token
    /// signing key's PUBLIC half (verify-only). Resolved from
    /// `HORT_OCI_TOKEN_SIGNING_KEY_PREV_FILE` / `_PREV` with the same
    /// `_FILE`-precedence + ambiguous-source rules as the active key.
    /// `None` when no previous key is wired (first deploy, or post-
    /// rotation deploy that has dropped the prev slot).
    pub oci_token_signing_key_prev_pem: Option<String>,
    /// Per-event-category audit-
    /// retention floors. Defaults to the documented GDPR retention
    /// minimums; `HORT_RETENTION_FLOOR_*_DAYS` env overrides may only
    /// *raise* a floor (a below-minimum override is a startup hard-
    /// fail). The worker composition root threads this by value into
    /// `EventStoreRetentionUseCase`. Not a `MinimalConfig` field
    /// (ADR 0009 — DB-only subcommands never run
    /// retention).
    pub audit_retention_floors: AuditRetentionFloors,
    /// The ONE global event-stream
    /// retention mode for v1 (`HORT_RETENTION_STREAM_MODE` ∈
    /// `delete` | `archive`; `HORT_RETENTION_ARCHIVE_TARGET` supplies the
    /// archive target prefix when `archive`). Defaults to
    /// [`StreamRetentionMode::Delete`].
    ///
    /// Deferred post-v1: per-stream-granular
    /// config is explicitly out of v1 scope (end-user
    /// retention DSL / YAML grammar). No pre-v1 action expected.
    pub retention_stream_mode: StreamRetentionMode,
}

impl std::fmt::Debug for Config {
    /// Hand-rolled to redact `database_url`, `redis_url`,
    /// `redis_url_evictable`, and `redis_url_durable` — DSN-bearing
    /// fields whose passwords would otherwise leak through any `{:?}`
    /// expansion. See `Config`'s rustdoc for the full rationale.
    ///
    /// All other fields are passed through verbatim (the field set
    /// matches the struct exactly) so `?cfg` retains its diagnostic
    /// value. The `<redacted>` placeholder spelling matches the existing
    /// [`StorageConfig`] redaction. For the optional per-class Redis
    /// fields, `None` is passed through as-is and only `Some(_)` is
    /// replaced — operators reading `?cfg` can still distinguish
    /// "override unset" from "override set" without seeing the value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            database_url: _,
            storage,
            api_bind_addr,
            require_https,
            metrics_bind_addr,
            metrics_require_auth,
            metrics_public_bind,
            control_bind_addr,
            control_public_bind,
            log_format,
            include_repository_label,
            include_service_account_label,
            metadata_caps,
            metadata_blob_max_bytes,
            public_base_url,
            trusted_proxy_cidrs,
            auth,
            claim_mappings,
            config_dir,
            publish_body_limit_bytes,
            pg_statement_timeout_ms,
            pg_acquire_timeout_secs,
            jwks_eviction_backoff_secs,
            jwks_resp_body_max_bytes,
            ratelimit_auth_per_min,
            ratelimit_write_per_min,
            max_inflight,
            max_inflight_per_ip,
            rbac_refresh_secs,
            event_chain_checkpoint_cadence_secs,
            stateful_upload_staging_dir,
            oci_legacy_catalog_enabled,
            oci_max_sessions_per_principal,
            ephemeral_store_backend,
            redis_url: _,
            redis_url_evictable: _,
            redis_url_durable: _,
            upstream_resolver_refresh_secs,
            upstream_metadata_cache_max_bytes,
            upstream_manifest_cache_max_bytes,
            upstream_projector_version_object_max_bytes,
            http_header_read_timeout_secs,
            http_request_timeout_secs,
            http_oci_upload_timeout_secs,
            pull_dedup_ttl_not_found_secs,
            pull_dedup_ttl_unavailable_secs,
            pull_dedup_ttl_timeout_secs,
            pull_dedup_ttl_checksum_mismatch_secs,
            pull_dedup_follower_wait_secs,
            shutdown_grace_secs,
            upstream_allowlist,
            cas_scrub_action_on_mismatch,
            enable_native_tokens,
            enable_notifications,
            notify_channel_capacity,
            allow_plaintext_webhooks,
            allow_nonroutable_webhook_targets,
            nats_url,
            allow_pat_over_http,
            pat_cache_size,
            pat_lockout_threshold,
            pat_lockout_window_secs,
            pat_lockout_duration_secs,
            allow_admin_tokens,
            allow_unbounded_svc_tokens,
            enable_token_exchange,
            refcount_reconcile_on_startup,
            oci_token_signing_key_pem: _,
            oci_token_signing_key_prev_pem: _,
            audit_retention_floors,
            retention_stream_mode,
        } = self;
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("storage", storage)
            .field("api_bind_addr", api_bind_addr)
            .field("require_https", require_https)
            .field("metrics_bind_addr", metrics_bind_addr)
            .field("metrics_require_auth", metrics_require_auth)
            .field("metrics_public_bind", metrics_public_bind)
            .field("control_bind_addr", control_bind_addr)
            .field("control_public_bind", control_public_bind)
            .field("log_format", log_format)
            .field("include_repository_label", include_repository_label)
            .field(
                "include_service_account_label",
                include_service_account_label,
            )
            .field("metadata_caps", metadata_caps)
            .field("metadata_blob_max_bytes", metadata_blob_max_bytes)
            .field("public_base_url", public_base_url)
            .field("trusted_proxy_cidrs", trusted_proxy_cidrs)
            .field("auth", auth)
            .field("claim_mappings", claim_mappings)
            .field("config_dir", config_dir)
            .field("publish_body_limit_bytes", publish_body_limit_bytes)
            .field("pg_statement_timeout_ms", pg_statement_timeout_ms)
            .field("pg_acquire_timeout_secs", pg_acquire_timeout_secs)
            .field("jwks_eviction_backoff_secs", jwks_eviction_backoff_secs)
            .field("jwks_resp_body_max_bytes", jwks_resp_body_max_bytes)
            .field("ratelimit_auth_per_min", ratelimit_auth_per_min)
            .field("ratelimit_write_per_min", ratelimit_write_per_min)
            .field("max_inflight", max_inflight)
            .field("max_inflight_per_ip", max_inflight_per_ip)
            .field("rbac_refresh_secs", rbac_refresh_secs)
            .field(
                "event_chain_checkpoint_cadence_secs",
                event_chain_checkpoint_cadence_secs,
            )
            .field("stateful_upload_staging_dir", stateful_upload_staging_dir)
            .field("oci_legacy_catalog_enabled", oci_legacy_catalog_enabled)
            .field(
                "oci_max_sessions_per_principal",
                oci_max_sessions_per_principal,
            )
            .field("ephemeral_store_backend", ephemeral_store_backend)
            .field("redis_url", &"<redacted>")
            // Per-class Redis URL overrides. Mirror
            // the signing-key redaction pattern: surface only the
            // structural shape (`Some("<redacted>")` / `None`) so a
            // reader of `?cfg` can tell the override is configured
            // without seeing the DSN.
            .field(
                "redis_url_evictable",
                &self.redis_url_evictable.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "redis_url_durable",
                &self.redis_url_durable.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "upstream_resolver_refresh_secs",
                upstream_resolver_refresh_secs,
            )
            .field(
                "upstream_metadata_cache_max_bytes",
                upstream_metadata_cache_max_bytes,
            )
            .field(
                "upstream_manifest_cache_max_bytes",
                upstream_manifest_cache_max_bytes,
            )
            .field(
                "upstream_projector_version_object_max_bytes",
                upstream_projector_version_object_max_bytes,
            )
            .field(
                "http_header_read_timeout_secs",
                http_header_read_timeout_secs,
            )
            .field("http_request_timeout_secs", http_request_timeout_secs)
            .field("http_oci_upload_timeout_secs", http_oci_upload_timeout_secs)
            .field(
                "pull_dedup_ttl_not_found_secs",
                pull_dedup_ttl_not_found_secs,
            )
            .field(
                "pull_dedup_ttl_unavailable_secs",
                pull_dedup_ttl_unavailable_secs,
            )
            .field("pull_dedup_ttl_timeout_secs", pull_dedup_ttl_timeout_secs)
            .field(
                "pull_dedup_ttl_checksum_mismatch_secs",
                pull_dedup_ttl_checksum_mismatch_secs,
            )
            .field(
                "pull_dedup_follower_wait_secs",
                pull_dedup_follower_wait_secs,
            )
            .field("shutdown_grace_secs", shutdown_grace_secs)
            .field("upstream_allowlist", upstream_allowlist)
            .field("cas_scrub_action_on_mismatch", cas_scrub_action_on_mismatch)
            .field("enable_native_tokens", enable_native_tokens)
            .field("enable_notifications", enable_notifications)
            .field("notify_channel_capacity", notify_channel_capacity)
            .field("allow_plaintext_webhooks", allow_plaintext_webhooks)
            .field(
                "allow_nonroutable_webhook_targets",
                allow_nonroutable_webhook_targets,
            )
            .field("nats_url", &nats_url.as_ref().map(|_| "<redacted>"))
            .field("allow_pat_over_http", allow_pat_over_http)
            .field("pat_cache_size", pat_cache_size)
            .field("pat_lockout_threshold", pat_lockout_threshold)
            .field("pat_lockout_window_secs", pat_lockout_window_secs)
            .field("pat_lockout_duration_secs", pat_lockout_duration_secs)
            .field("allow_admin_tokens", allow_admin_tokens)
            .field("allow_unbounded_svc_tokens", allow_unbounded_svc_tokens)
            .field("enable_token_exchange", enable_token_exchange)
            .field(
                "refcount_reconcile_on_startup",
                refcount_reconcile_on_startup,
            )
            // Never log key material verbatim. Surface
            // only the structural shape (configured / not).
            .field(
                "oci_token_signing_key_pem",
                &self
                    .oci_token_signing_key_pem
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field(
                "oci_token_signing_key_prev_pem",
                &self
                    .oci_token_signing_key_prev_pem
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("audit_retention_floors", audit_retention_floors)
            .field("retention_stream_mode", retention_stream_mode)
            .finish()
    }
}

/// Operator-visible choice for the
/// `EphemeralStore` backend. Parsed from `HORT_EPHEMERAL_STORE_BACKEND`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralStoreBackend {
    /// In-memory adapter — single-process only. Default in dev /
    /// test so a freshly-cloned dev env boots without a Redis
    /// sidecar. See `hort-adapters-ephemeral-memory`.
    Memory,
    /// Redis adapter (via `fred`). Production-multi-node default
    /// once operators opt in. See `hort-adapters-ephemeral-redis`.
    Redis,
}

/// Authentication provider selection.
///
/// Cheap to `Clone`; held on [`Config`] and passed into the composition
/// root. `Disabled` is the anonymous pass-through path —
/// there is NO synthetic anonymous principal; the downstream middleware
/// simply doesn't attach. `Oidc` carries the per-provider settings needed
/// by the OIDC adapter for IdP-issued token validation.
#[derive(Debug, Clone)]
pub enum AuthConfig {
    Disabled,
    Oidc(OidcConfig),
}

/// OIDC provider configuration.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// OIDC issuer URL — the `iss` claim each token must carry.
    pub issuer_url: String,
    /// Audience (`aud` claim) each token must target.
    pub audience: String,
    /// Name of the IdP claim carrying the caller's group memberships.
    /// Defaults to `"groups"`.
    pub groups_claim: String,
    /// How long to cache the JWKS response from the IdP, in seconds.
    /// Defaults to `600` (ten minutes).
    pub jwks_cache_ttl_seconds: u64,
    /// OAuth client name `hort-cli` presents to
    /// the IdP when running RFC 8628 device flow. Parsed from
    /// `HORT_OIDC_CLI_CLIENT_ID`. `None` is the default; required (i.e.
    /// must resolve to a non-empty value at boot) when
    /// [`Config::enable_token_exchange`] is `true` because the
    /// `/.well-known/hort-client-config` discovery document publishes
    /// this value as `idp.client_id`. The fail-closed validation in
    /// [`Config::from_env`] surfaces a missing var as
    /// [`ConfigError::TokenExchangeRequiresVars`] before the listener
    /// binds.
    pub cli_client_id: Option<String>,
}

/// Storage backend selection.
///
/// `Debug` is implemented manually to redact the S3 credentials — a derive
/// would surface `access_key_id` and `secret_access_key` verbatim through
/// any `{:?}` expansion (panics, `.unwrap()` failures, ad-hoc tracing),
/// leaking AWS keys into logs or crash dumps. Bucket, region, endpoint,
/// and `force_path_style` stay visible because operators need them to
/// diagnose misconfiguration.
#[derive(Clone)]
pub enum StorageConfig {
    Filesystem {
        root: PathBuf,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        force_path_style: bool,
        /// Opt-in to plain HTTP S3 endpoints (the rust `object_store`
        /// crate refuses HTTP by default). Required for in-cluster
        /// Garage / MinIO without TLS termination. The validator
        /// rejects mismatched (`endpoint` scheme, `allow_http`) pairs
        /// at config-parse time so a typo can't silently downgrade
        /// the transport.
        allow_http: bool,
        access_key_id: String,
        secret_access_key: String,
        /// Server-side-encryption mode.
        ///
        /// `None` ⇒ no opinion is sent on the request and the bucket's
        /// default applies. AWS S3 has applied SSE-S3 unconditionally
        /// since 2023, so `None` is safe for AWS. Non-AWS S3-compatibles
        /// expose the knob per-bucket; the storage adapter emits a
        /// startup WARN when `endpoint` is `Some` and `sse_mode` is
        /// `None` to surface the silent-cleartext-at-rest case.
        sse_mode: Option<S3SseMode>,
    },
}

impl StorageConfig {
    /// Project into the pure `hort-app`
    /// [`EffectiveStorageBackend`](hort_app::storage_backend::EffectiveStorageBackend)
    /// — the deployment's *effective global storage backend* in the
    /// `{filesystem, s3}` value-domain.
    ///
    /// The composition root threads this into `ApplyConfigUseCase` via
    /// the additive `with_effective_storage_backend` builder so a
    /// per-repo `storage.backend` differing from it is rejected at
    /// apply (fail-closed, loud).
    ///
    /// Kept as a method (not `From`), mirroring [`S3SseMode::to_adapter`]
    /// — an explicit one-way config→domain projection, not an implicit
    /// conversion. This is the *true* `{filesystem, s3}` deployment
    /// fact (never the coarse `StoragePort::backend_label()`
    /// `{filesystem, object_store}`, which would fail-*wrong* on a
    /// legitimate `s3`-on-S3 config).
    #[must_use]
    pub fn effective_backend(&self) -> hort_app::storage_backend::EffectiveStorageBackend {
        use hort_app::storage_backend::EffectiveStorageBackend;
        match self {
            Self::Filesystem { .. } => EffectiveStorageBackend::Filesystem,
            Self::S3 { .. } => EffectiveStorageBackend::S3,
        }
    }
}

/// Server-side-encryption mode for the S3 storage backend.
///
/// Mirrors [`hort_adapters_storage::builders::SseMode`] but lives in the
/// config layer so the parsing/validation keeps the adapter free of any
/// env-var concerns. The conversion is one-way (config → adapter) via
/// [`S3SseMode::to_adapter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum S3SseMode {
    /// Honour whatever encryption default the bucket itself has. Wire
    /// value: `bucket-default`.
    BucketDefault,
    /// SSE-S3, AWS-managed keys, AES256. Wire value: `sse256`.
    Sse256,
    /// SSE-KMS, customer-managed KMS key. Wire value: `sse-kms`. The
    /// KMS key ARN is required when this variant is selected; the
    /// parser rejects `HORT_S3_SSE_MODE=sse-kms` without
    /// `HORT_S3_SSE_KMS_KEY_ARN`.
    SseKms {
        /// Full KMS key ARN, e.g.
        /// `arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh-5678`.
        key_arn: String,
    },
}

impl S3SseMode {
    /// Project into the storage-adapter enum.
    ///
    /// Kept as a method (not `From`) so the call site at
    /// `crate::storage::build` reads as an explicit projection rather
    /// than implicit conversion — the two enums are intentionally
    /// distinct (one config-layer, one adapter-layer) per the
    /// hexagonal-layering rule (ADR 0001).
    #[must_use]
    pub fn to_adapter(&self) -> hort_adapters_storage::builders::SseMode {
        match self {
            Self::BucketDefault => hort_adapters_storage::builders::SseMode::BucketDefault,
            Self::Sse256 => hort_adapters_storage::builders::SseMode::Sse256,
            Self::SseKms { key_arn } => hort_adapters_storage::builders::SseMode::SseKms {
                key_arn: key_arn.clone(),
            },
        }
    }
}

impl std::fmt::Debug for StorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filesystem { root } => f.debug_struct("Filesystem").field("root", root).finish(),
            Self::S3 {
                bucket,
                region,
                endpoint,
                force_path_style,
                allow_http,
                access_key_id: _,
                secret_access_key: _,
                sse_mode,
            } => f
                .debug_struct("S3")
                .field("bucket", bucket)
                .field("region", region)
                .field("endpoint", endpoint)
                .field("force_path_style", force_path_style)
                .field("allow_http", allow_http)
                .field("access_key_id", &"<redacted>")
                .field("secret_access_key", &"<redacted>")
                .field("sse_mode", sse_mode)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

// ---------------------------------------------------------------------------
// Audit-retention floor config
// ---------------------------------------------------------------------------

/// Per-event-category audit-retention floor — the documented GDPR
/// retention schedule (see `docs/compliance/GDPR.md`). This is the
/// **single place** the
/// `StreamCategory → floor` mapping lives:
/// new audited categories (`ApiTokenUsed`, `AuthenticationAttempted`)
/// only
/// *register* their category+floor against this struct, because
/// [`AuditRetentionFloors::floor_for`]
/// matches **every** [`StreamCategory`] arm exhaustively.
///
/// `EventStoreRetentionUseCase::archive_terminal_streams` is
/// the consumer: it never seals a stream before its category's floor
/// has elapsed (proven against the stream's *oldest* event's
/// `stored_at`, never a payload timestamp). The retention scheduler
/// reads this floor from composition-root config; **it does not
/// redefine it**.
///
/// `Copy`/`Clone` and threaded **by value** into the use case (not
/// `Arc<dyn …>`) — it is five `chrono::Duration`s, cheaper to copy
/// than to share.
///
/// Env overrides (`HORT_RETENTION_FLOOR_*_DAYS`, parsed in
/// [`Config::from_env`]) may only ever *raise* a floor: an override
/// below its documented minimum is a hard
/// [`ConfigError::InvalidValue`] startup failure (mirrors the
/// `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` `>= 5` reject pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionFloors {
    /// `AuthAttempts` (`auth-{date}` streams). Minimum:
    /// ≥ 6 months (NIS2 incident-investigation horizon). Default 180d.
    authentication: chrono::Duration,
    /// `Policy` / `Authorization` / `Admin`. Minimum: ≥ 36 months
    /// (CRA Annex I secure-default attestation). Default 1080d.
    policy_authz_admin: chrono::Duration,
    /// `ArtifactDownloaded` audit. `DownloadAudit` is
    /// a real `StreamCategory`; `floor_for(C::DownloadAudit)` routes
    /// here. Minimum: ≥ 90 days (operational, high-volume).
    /// Default 90d.
    artifact_downloaded: chrono::Duration,
    /// `ApiTokenUsed` per-use audit (credential-audit class,
    /// ≥36mo — same credential/authz-audit
    /// class as policy/authz/admin). `floor_for(C::TokenUse)`
    /// (and `C::User`) route here. Default 1080d.
    api_token_used: chrono::Duration,
    /// `Artifact` / `Ref` / `ArtifactGroup` / `Curation` /
    /// `Repository` — the artifact-lifecycle aggregate streams whose
    /// terminal is `ArtifactPurged`. **USER DECISION:
    /// configurable, default 36 months.** Not in the
    /// documented audit-category table;
    /// this floor exists so a terminal artifact stream is not sealed
    /// the instant it is purged but only after the configured
    /// lifecycle-audit horizon. Default 1080d.
    artifact_lifecycle: chrono::Duration,
}

impl AuditRetentionFloors {
    /// Documented minimums, as day counts (months expressed as
    /// 30-day units: 6mo = 180d, 36mo = 1080d). An operator override
    /// below the relevant value is rejected at startup.
    pub const MIN_AUTHENTICATION_DAYS: i64 = 180;
    pub const MIN_POLICY_AUTHZ_ADMIN_DAYS: i64 = 1080;
    pub const MIN_ARTIFACT_DOWNLOADED_DAYS: i64 = 90;
    /// Credential-audit-class minimum (see field doc) — both the
    /// default and the floor.
    pub const MIN_API_TOKEN_USED_DAYS: i64 = 1080;
    /// `artifact_lifecycle` is the user-configurable floor. There is
    /// no documented audit minimum (it is not an audit category); the
    /// enforced lower bound is `1` day so a misconfigured `0`/negative
    /// override cannot make every freshly-purged stream instantly
    /// sealable. The default is 36mo.
    pub const MIN_ARTIFACT_LIFECYCLE_DAYS: i64 = 1;

    /// The defaults (every override unset). 6mo / 36mo / 90d /
    /// 36mo / 36mo as documented above.
    pub fn c1_defaults() -> Self {
        Self {
            authentication: chrono::Duration::days(Self::MIN_AUTHENTICATION_DAYS),
            policy_authz_admin: chrono::Duration::days(Self::MIN_POLICY_AUTHZ_ADMIN_DAYS),
            artifact_downloaded: chrono::Duration::days(Self::MIN_ARTIFACT_DOWNLOADED_DAYS),
            api_token_used: chrono::Duration::days(Self::MIN_API_TOKEN_USED_DAYS),
            // USER DECISION: default 36mo (configurable).
            artifact_lifecycle: chrono::Duration::days(1080),
        }
    }

    /// The single `StreamCategory → floor` mapping site (the
    /// registration seam). The match is **exhaustive on purpose**: a
    /// new [`StreamCategory`] variant fails to compile here until its
    /// retention-floor disposition is decided.
    ///
    /// `User` carries the per-user audit-attribution
    /// lifecycle stream (`ApiTokenIssued` / `ApiTokenRevoked` /
    /// `ApiTokenIssuanceDenied`); it maps to the credential-audit
    /// `api_token_used` floor. Per-use
    /// telemetry rides a **separate** `C::TokenUse` category (a
    /// dedicated per-(token_id, UTC-date) stream, NOT the `User`
    /// lifecycle stream) — it is also routed to the same
    /// `api_token_used` field (both are the credential-audit class,
    /// ≥36mo); the two arms intentionally share the field and that is
    /// not a collision.
    pub fn floor_for(&self, category: hort_domain::events::StreamCategory) -> chrono::Duration {
        use hort_domain::events::StreamCategory as C;
        match category {
            C::AuthAttempts => self.authentication,
            // The event-sourced retention-policy
            // lifecycle (`RetentionPolicyChanged`) is policy-mutation
            // history that governs destructive GC; it is the same
            // policy/authz-audit class as the scan-policy
            // (`C::Policy`) stream and seals on the ≥36mo
            // `policy_authz_admin` floor. Grouped with
            // Policy/Authorization/Admin (NOT the artifact-lifecycle
            // floor — a retention policy's audit horizon must outlive
            // the artifacts it expired).
            C::Policy | C::Authorization | C::Admin | C::RetentionPolicy => self.policy_authz_admin,
            C::User => self.api_token_used,
            // Throttled per-(token_id,
            // UTC-date) token-use audit streams seal on the ≥36mo
            // `api_token_used` credential-audit floor
            // (same field as `C::User`; a token use is a
            // credential-exercise event, not operational telemetry).
            C::TokenUse => self.api_token_used,
            // Opt-in per-(repo, UTC-date)
            // download-audit streams seal on the ≥90d
            // `artifact_downloaded` floor.
            C::DownloadAudit => self.artifact_downloaded,
            C::Artifact | C::Ref | C::ArtifactGroup | C::Curation | C::Repository => {
                self.artifact_lifecycle
            }
        }
    }

    /// Read-accessors so [`Config::from_env`] / tests can assert the
    /// resolved per-field values without exposing the fields publicly
    /// (the fields stay private so the floor invariant — every
    /// value at-or-above its documented minimum — is only ever
    /// established through validated construction).
    pub fn authentication(&self) -> chrono::Duration {
        self.authentication
    }
    pub fn policy_authz_admin(&self) -> chrono::Duration {
        self.policy_authz_admin
    }
    pub fn artifact_downloaded(&self) -> chrono::Duration {
        self.artifact_downloaded
    }
    pub fn api_token_used(&self) -> chrono::Duration {
        self.api_token_used
    }
    pub fn artifact_lifecycle(&self) -> chrono::Duration {
        self.artifact_lifecycle
    }
}

/// The ONE global event-stream retention mode for v1. v1 picks one
/// mode for the whole deployment.
///
/// Deferred post-v1: per-stream-granular
/// retention configuration is explicitly out of v1 scope
/// (the end-user retention DSL / YAML grammar). No pre-v1
/// action expected.
///
/// `Delete` routes to `EventStore::delete_stream`; `Archive` routes to
/// `EventStore::archive_stream` with a target string of
/// `format!("{target_prefix}/{stream_id}")`. The `target` is
/// adapter-opaque (`crates/hort-domain/src/ports/event_store.rs:191-199`).
///
/// Deferred post-v1: designing the cold-
/// storage *write* (S3 IA / Glacier / EventStoreDB partition) is a
/// follow-on. No pre-v1 action expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRetentionMode {
    /// `delete_stream` — the stream's rows are removed (after the
    /// `StreamSealed` tombstone). The v1 default.
    Delete,
    /// `archive_stream` — the stream is moved to a cold-storage target
    /// rooted at `target_prefix`. v1 only carries the prefix through
    /// the chokepoint.
    ///
    /// Deferred post-v1: the actual cold-
    /// storage write is a follow-on (S3 IA / Glacier /
    /// EventStoreDB partition). No pre-v1 action expected.
    Archive { target_prefix: String },
}

/// Concrete error per config field.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("invalid value for {var}: {source}")]
    InvalidAddr {
        var: &'static str,
        #[source]
        source: AddrParseError,
    },
    #[error("invalid value for {var}: {source}")]
    InvalidBool {
        var: &'static str,
        #[source]
        source: std::str::ParseBoolError,
    },
    #[error("invalid value for {var}: expected one of [pretty, json], got {got:?}")]
    InvalidLogFormat { var: &'static str, got: String },
    #[error("invalid value for {var}: expected one of [filesystem, s3], got {got:?}")]
    InvalidStorageBackend { var: &'static str, got: String },
    #[error("invalid integer value for {var}: {source}")]
    InvalidInt {
        var: &'static str,
        #[source]
        source: ParseIntError,
    },
    #[error("invalid value for {var}: {reason}")]
    InvalidValue { var: &'static str, reason: String },
    #[error("invalid URL in {var}: {source}")]
    InvalidUrl {
        var: &'static str,
        #[source]
        source: url::ParseError,
    },
    #[error("invalid URL in {var}: {reason} (got {got:?})")]
    InvalidUrlShape {
        var: &'static str,
        reason: &'static str,
        got: String,
    },
    #[error("invalid value for {var}: expected one of [disabled, oidc], got {got:?}")]
    InvalidAuthProvider { var: &'static str, got: String },
    #[error("invalid CIDR in {var}: {entry:?} ({source})")]
    InvalidCidr {
        var: &'static str,
        entry: String,
        #[source]
        source: ipnet::AddrParseError,
    },
    /// Unconditional startup failure when BOTH `HORT_PUBLIC_BASE_URL` AND
    /// `HORT_TRUSTED_PROXY_CIDRS` are unset. NOT auth-gated —
    /// X-Forwarded-Host injection poisoning package download URLs is
    /// orthogonal to authentication.
    #[error(
        "trust configuration unset: set HORT_PUBLIC_BASE_URL \
        (e.g. https://hort.example.com) to pin the public URL, \
        or HORT_TRUSTED_PROXY_CIDRS (e.g. 10.0.0.0/8,::1/128) to trust X-Forwarded-* \
        from listed reverse proxies. One of the two is required to prevent \
        X-Forwarded-Host injection from poisoning package download URLs."
    )]
    TrustUnconfigured,
    /// Env var parsed as a valid integer but the value is zero, which
    /// carries a different (and usually wrong) semantic than the
    /// operator intended — e.g. `SET statement_timeout = 0` in Postgres
    /// disables the timeout, and a zero acquire-timeout makes every pool
    /// checkout fail immediately. Both are rejected at
    /// parse time so misconfiguration is loud.
    #[error("invalid value for {var}: must be a positive integer, got {got}")]
    ValueNotPositive { var: &'static str, got: u64 },
    /// `HORT_AUTH_PROVIDER=disabled` is refused at
    /// startup unless `HORT_NATIVE_TOKENS_ENABLED=true` wires
    /// service-account Bearer auth. No env-var escape hatch exists
    /// (the "allow unauthenticated admin for dev" flag has a
    /// history of ending up in production `.env` files). Operators get two
    /// explicit paths forward; the message names both so they don't have
    /// to read source. There is no third (`admin bootstrap` + HTTP
    /// Basic) path — the
    /// HTTP-Basic-against-local-admin-row identity surface was removed
    /// (commit b7fd6d65), and the producer
    /// (`admin bootstrap` CLI) was retired together with that gate arm.
    #[error(
        "Admin routes require authentication. \
        Set `HORT_AUTH_PROVIDER=oidc` to use an OIDC identity provider, \
        OR set `HORT_NATIVE_TOKENS_ENABLED=true` with a signing key configured \
        to enable service-account / CLI-session `Bearer hort_<kind>_*` \
        authentication. The minimal-setup recipe is the native-tokens path: \
        mint a token via `hort-server admin issue-svc-token` and paste it \
        into `hort-cli auth login --paste`."
    )]
    AuthDisabled,
    /// `HORT_CONFIG_DIR` was set to a path that
    /// either doesn't exist or isn't a directory. Fail-fast on typo so
    /// the operator finds out immediately, not at first apply.
    #[error("HORT_CONFIG_DIR={path:?} does not exist or is not a directory")]
    ConfigDirNotADirectory { path: String },
    /// `HORT_EPHEMERAL_STORE_BACKEND` was set
    /// to a value outside the accepted `{memory, redis}` enum. Loud
    /// startup failure so a typo can't silently fall back to the
    /// dev default.
    #[error("invalid value for {var}: expected one of [memory, redis], got {got:?}")]
    InvalidEphemeralStoreBackend { var: &'static str, got: String },
    /// Composition-time URL resolution for the
    /// per-class `EphemeralStore` slot failed. Surfaces when the
    /// per-class env var is unset AND the `HORT_REDIS_URL` fallback is
    /// also unset, breaking the resolution chain. The named env var is
    /// the per-class one (`HORT_REDIS_URL_EVICTABLE` or
    /// `HORT_REDIS_URL_DURABLE`); operators set it OR set the main
    /// `HORT_REDIS_URL` fallback.
    #[error(
        "missing Redis URL for ephemeral-store class: neither {0} nor \
        HORT_REDIS_URL is set. Set the per-class override OR the main \
        HORT_REDIS_URL fallback."
    )]
    MissingRedisUrl(&'static str),
    /// `HORT_METRICS_BIND` was set to an
    /// unspecified address (`0.0.0.0:port` or `[::]:port`) without
    /// `HORT_METRICS_PUBLIC_BIND=true`. The unspecified-address bind
    /// makes the scrape surface reachable from every network, which
    /// expands an internal-only reconnaissance vector to the public
    /// internet for misconfigured deployments. Operators who
    /// genuinely intend that posture set the explicit opt-in.
    ///
    /// The **same** guard now also backs
    /// `HORT_CONTROL_BIND` (the internal-only control-plane listener):
    /// `opt_in_var` parameterises which opt-in env var the message
    /// names (`HORT_METRICS_PUBLIC_BIND` vs `HORT_CONTROL_PUBLIC_BIND`) so
    /// the operator-facing text stays correct for both sockets without
    /// inventing a second error pattern.
    #[error(
        "{var}={addr} binds the listener to the unspecified address; \
        set {opt_in_var}=true to confirm this is intentional, or \
        bind to a specific interface (e.g. 127.0.0.1:{port} for loopback)"
    )]
    MetricsPublicBindRefused {
        var: &'static str,
        opt_in_var: &'static str,
        addr: String,
        port: u16,
    },
    /// `HORT_REQUIRE_HTTPS=true` was set
    /// but the binary has no positive evidence the public connection
    /// is TLS: `HORT_PUBLIC_BASE_URL` is `http://...` AND
    /// `HORT_TRUSTED_PROXY_CIDRS` is empty. The combination silently ships
    /// a registry over plaintext when the operator believed the
    /// opposite (the gate's whole reason for existing); refuse to
    /// start so the misconfiguration is loud, not silent.
    #[error(
        "HORT_REQUIRE_HTTPS=true but the binary has no positive evidence the public \
        connection is TLS: HORT_PUBLIC_BASE_URL is http://... AND HORT_TRUSTED_PROXY_CIDRS \
        is empty. Either set HORT_PUBLIC_BASE_URL to an https:// URL (e.g. \
        https://hort.example.com) so the binary emits HSTS and absolute \
        URLs over TLS, or set HORT_TRUSTED_PROXY_CIDRS to the reverse-proxy ranges \
        (e.g. 10.0.0.0/8) so the binary trusts X-Forwarded-Proto from the proxy. \
        Disable the gate via HORT_REQUIRE_HTTPS=false if plaintext is intentional."
    )]
    InsecureHttp,
    /// `HORT_EXTRA_CA_BUNDLE` was set but the file
    /// at that path could not be read (missing, permission denied, etc.).
    /// Fail closed — a misconfigured trust knob must not silently degrade
    /// to "trust only public CAs" (which would be a silent TLS failure on
    /// internal services).
    #[error("HORT_EXTRA_CA_BUNDLE={path:?}: cannot read CA bundle file: {source}")]
    ExtraCaUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `HORT_EXTRA_CA_BUNDLE` was set, the file was
    /// readable, but parsing the PEM content failed. Covers both
    /// [`ExtraCaParseError::Pem`] (malformed PEM block) and
    /// [`ExtraCaParseError::Empty`] (zero certificate blocks found).
    #[error("HORT_EXTRA_CA_BUNDLE={path:?}: {source}")]
    ExtraCaParse {
        path: String,
        #[source]
        source: ExtraCaParseError,
    },
    /// Both the `_FILE` AND inline form of the
    /// same OCI signing key env var are set with non-empty values.
    /// Boot-fail to prevent the operator from accidentally validating
    /// JWTs against the wrong half. Same shape as the
    /// `HORT_EXTRA_CA_BUNDLE` ambiguous-source guard would use if it
    /// supported both forms.
    #[error(
        "ambiguous OCI signing key source: \
        both {file_var} and {inline_var} are set with non-empty \
        values; pick one. The _FILE variant is preferred for k8s \
        secret mounts."
    )]
    AmbiguousSigningKeySource {
        file_var: &'static str,
        inline_var: &'static str,
    },
    /// `HORT_OCI_TOKEN_SIGNING_KEY_FILE` (or
    /// `HORT_OCI_TOKEN_SIGNING_KEY`) was set but the file at that path
    /// could not be read. Same fail-closed shape as
    /// `ConfigError::ExtraCaUnreadable` (boot-fail rather than silent
    /// degradation).
    #[error("HORT_OCI_TOKEN_SIGNING_KEY_FILE={path:?}: cannot read signing key file: {source}")]
    OciSigningKeyUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `HORT_NATIVE_TOKENS_ENABLED=true` was set
    /// but no OCI signing key (active half) is configured. The
    /// `/v2/auth` endpoint cannot mint without a key; boot-fail
    /// rather than start in a half-functional state.
    #[error(
        "HORT_NATIVE_TOKENS_ENABLED=true but no OCI \
        signing key configured. Set HORT_OCI_TOKEN_SIGNING_KEY_FILE \
        (preferred) or HORT_OCI_TOKEN_SIGNING_KEY (inline) to a \
        PKCS#8-encoded Ed25519 PEM."
    )]
    OciTokenSigningKeyMissing,
    /// `HORT_NATIVE_TOKENS_ENABLED=true` was set
    /// AND an OCI signing key was successfully loaded, but
    /// `HORT_PUBLIC_BASE_URL` is unset. Issuing JWTs whose `iss` claim
    /// degrades to a relative `/v2/auth` and whose `aud` falls back to
    /// the literal `localhost` is a foot-gun: clients that *do* receive
    /// the right realm via the `WWW-Authenticate` challenge round-trip
    /// will mint tokens scoped to a host they cannot reach. Boot-fail
    /// closes that gap. Operators flipping `HORT_NATIVE_TOKENS_ENABLED=true`
    /// MUST also pin `HORT_PUBLIC_BASE_URL` so the `/v2/auth` realm,
    /// `iss`, and `aud` all derive from one source of truth.
    #[error(
        "HORT_NATIVE_TOKENS_ENABLED=true requires \
        HORT_PUBLIC_BASE_URL to be set. The OCI /v2/auth flow derives \
        realm / iss / aud from this URL; without it, minted JWTs \
        carry a relative iss and a `localhost` aud that real clients \
        cannot consume. Set HORT_PUBLIC_BASE_URL to the absolute URL \
        clients use to reach this server (e.g. \
        https://hort.example.com)."
    )]
    OciPublicBaseUrlMissing,
    /// `HORT_TOKEN_EXCHANGE_ENABLED=true` was set
    /// but one or more of the env vars required to render the
    /// `/.well-known/hort-client-config` discovery document are missing.
    /// The composition root publishes the `idp.issuer`, `idp.client_id`,
    /// and `exchange.endpoint` fields straight from these vars; serving
    /// a half-formed document at runtime (e.g. with a `null` client_id
    /// and a relative endpoint) would silently downgrade clients into
    /// guessing IdP coordinates out-of-band. Boot-fail closes that gap.
    /// Same fail-closed shape as
    /// [`ConfigError::OciPublicBaseUrlMissing`];
    /// the message names every missing var so operators can fix them
    /// without spelunking.
    #[error(
        "HORT_TOKEN_EXCHANGE_ENABLED=true requires the \
        following env vars to render the /.well-known/hort-client-config \
        discovery document: {missing}. Either set them, or unset \
        HORT_TOKEN_EXCHANGE_ENABLED so neither /api/v1/auth/exchange nor \
        the discovery endpoint is mounted."
    )]
    TokenExchangeRequiresVars { missing: String },
    /// `HORT_TOKEN_EXCHANGE_ENABLED=true` was set
    /// while `HORT_NATIVE_TOKENS_ENABLED=false`. The exchange endpoint
    /// mints `hort_cli_*` PAT-shape tokens (`TokenKind::CliSession`),
    /// but `PatValidationUseCase` is gated on
    /// `enable_native_tokens=true`. With this combination the server
    /// happily issues tokens it cannot subsequently validate — every
    /// authenticated request from a logged-in `hort-cli` 401s because
    /// the PAT-shape token falls through to the OIDC validator,
    /// which can't decode it as a JWT. Boot-fail closes the gap.
    #[error(
        "HORT_TOKEN_EXCHANGE_ENABLED=true requires \
        HORT_NATIVE_TOKENS_ENABLED=true. The exchange endpoint mints \
        hort_cli_* (PAT-shape) tokens, but the validator that recognises \
        them (PatValidationUseCase) only wires when native tokens are \
        enabled. With the current configuration hort-cli would log in \
        successfully and then 401 on every subsequent call. Either set \
        HORT_NATIVE_TOKENS_ENABLED=true (and provide an OCI signing key per \
        OciTokenSigningKeyMissing), or unset HORT_TOKEN_EXCHANGE_ENABLED."
    )]
    TokenExchangeRequiresNativeTokens,
}

/// Minimal config for subcommands that only touch the database.
///
/// Split off `Config` (ADR 0009) so DB-only subcommands (`migrate`,
/// `reconcile-groups`, the enqueue commands) don't demand the full
/// serve env (storage, public-base-url, OIDC, proxy-trust check). The
/// k8s migrate Job needs no `HORT_STORAGE_FILESYSTEM_PATH` /
/// `HORT_PUBLIC_BASE_URL` workaround.
///
/// Behaviour loss accepted: today, running `hort-server migrate` against
/// a partial environment (DB right, public-base-url wrong) surfaces
/// the misconfig before the serve pod tries to start. After this
/// split, that misconfig only surfaces when serve boots — same
/// `helm install`, ~10s later. The serve pod fails loud either way;
/// no silent failure mode is introduced. Do NOT add a "validation
/// parity" mode.
#[derive(Debug, Clone)]
pub struct MinimalConfig {
    pub database_url: String,
    pub log_format: LogFormat,
    /// Carried on `MinimalConfig` because `reconcile-groups` (a DB-only
    /// subcommand) needs it; one bool is the cheaper diff than reading
    /// `METRICS_INCLUDE_REPOSITORY_LABEL` directly in the CLI module.
    pub include_repository_label: bool,
    pub pg_statement_timeout_ms: Option<u64>,
    pub pg_acquire_timeout_secs: u64,
}

impl MinimalConfig {
    /// Parse the DB-only subset from process environment. Same parsing
    /// helpers as [`Config::from_env`]; reuses [`require`],
    /// [`parse_log_format`], [`parse_bool`],
    /// [`parse_pg_statement_timeout_ms`], [`parse_pg_acquire_timeout_secs`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            // `HORT_DATABASE_URL` is the canonical operator DSN var, with
            // bare `DATABASE_URL` retained as the documented compat fallback.
            // Mirrors `hort-worker`'s shape so the serve path and EVERY
            // DB-only subcommand (migrate, reconcile-groups,
            // verify-event-chain) resolve the DSN identically. Bare
            // `DATABASE_URL` stays load-bearing because sqlx-cli, the
            // Tier-2 `maybe_pool()` test helpers, and 12-factor tooling read
            // it; the fallback is the reason it cannot be dropped.
            database_url: require("HORT_DATABASE_URL").or_else(|_| require("DATABASE_URL"))?,
            log_format: parse_log_format()?,
            include_repository_label: parse_bool("METRICS_INCLUDE_REPOSITORY_LABEL", true)?,
            pg_statement_timeout_ms: parse_pg_statement_timeout_ms()?,
            pg_acquire_timeout_secs: parse_pg_acquire_timeout_secs()?,
        })
    }
}

impl Config {
    /// Parse configuration from process environment.
    ///
    /// Reads each variable via [`std::env::var`] so it can be driven by
    /// `temp-env` in tests. No global mutation, no logging side effects —
    /// telemetry is installed separately by the binary after config parse.
    pub fn from_env() -> Result<Self, ConfigError> {
        // The DB-only subset is parsed via
        // `MinimalConfig::from_env` so DB-only subcommands and the
        // full serve config share one source of truth for these
        // five fields. Behaviour for full-Config callers is unchanged.
        let MinimalConfig {
            database_url,
            log_format,
            include_repository_label,
            pg_statement_timeout_ms,
            pg_acquire_timeout_secs,
        } = MinimalConfig::from_env()?;

        let storage = parse_storage()?;

        // Narrowed default API bind to
        // loopback. Operators who need the listener reachable on every
        // interface (typical for containerised deployments) set
        // `HORT_API_BIND=0.0.0.0:8080` explicitly. The pre-rc.8
        // `HORT_BIND_PUBLIC` opt-in was dropped; the chart now sets
        // `HORT_API_BIND` directly per its `api.bindAddr` value.
        let api_bind_addr = match std::env::var("HORT_API_BIND") {
            Ok(v) if !v.is_empty() => {
                v.parse::<SocketAddr>()
                    .map_err(|source| ConfigError::InvalidAddr {
                        var: "HORT_API_BIND",
                        source,
                    })?
            }
            _ => "127.0.0.1:8080"
                .parse::<SocketAddr>()
                .expect("hard-coded bind default parses"),
        };

        // Opt-in flags for the
        // `/metrics` lockdown. Parsed BEFORE `metrics_bind_addr` so
        // the unspecified-address guard can consult them in the same
        // pass. `parse_bool` keeps the conventional defaults: auth
        // required = true, public bind = false.
        let metrics_require_auth = parse_bool("HORT_METRICS_REQUIRE_AUTH", true)?;
        let metrics_public_bind = parse_bool("HORT_METRICS_PUBLIC_BIND", false)?;

        let metrics_bind_addr = match std::env::var("HORT_METRICS_BIND") {
            Ok(ref v) if !v.is_empty() => {
                let addr = v
                    .parse::<SocketAddr>()
                    .map_err(|source| ConfigError::InvalidAddr {
                        var: "HORT_METRICS_BIND",
                        source,
                    })?;
                // Refuse unspecified-address
                // bind unless the operator opts in. `is_unspecified`
                // matches `0.0.0.0` (IPv4) and `::` (IPv6); loopback
                // and concrete interface IPs always pass through.
                if addr.ip().is_unspecified() && !metrics_public_bind {
                    return Err(ConfigError::MetricsPublicBindRefused {
                        var: "HORT_METRICS_BIND",
                        opt_in_var: "HORT_METRICS_PUBLIC_BIND",
                        addr: addr.to_string(),
                        port: addr.port(),
                    });
                }
                Some(addr)
            }
            _ => None,
        };

        // `HORT_CONTROL_BIND` internal-only
        // control-plane listener. Parsed with the SAME shape as
        // `HORT_METRICS_BIND` above (concrete-addr parse + the
        // unspecified-address "0.0.0.0 footgun" refusal, opt-out via
        // `HORT_CONTROL_PUBLIC_BIND`). When unset, `control_bind_addr`
        // is `None` and the control routes stay on the main listener —
        // byte-identical to today, no migration. See
        // `docs/architecture/how-to/deploy/security-hardening-checklist.md`.
        let control_public_bind = parse_bool("HORT_CONTROL_PUBLIC_BIND", false)?;
        let control_bind_addr = match std::env::var("HORT_CONTROL_BIND") {
            Ok(ref v) if !v.is_empty() => {
                let addr = v
                    .parse::<SocketAddr>()
                    .map_err(|source| ConfigError::InvalidAddr {
                        var: "HORT_CONTROL_BIND",
                        source,
                    })?;
                // Same `is_unspecified` gate as the metrics listener:
                // `0.0.0.0` (IPv4) / `::` (IPv6) is refused unless the
                // operator explicitly opts in; loopback and concrete
                // interface IPs always pass through.
                if addr.ip().is_unspecified() && !control_public_bind {
                    return Err(ConfigError::MetricsPublicBindRefused {
                        var: "HORT_CONTROL_BIND",
                        opt_in_var: "HORT_CONTROL_PUBLIC_BIND",
                        addr: addr.to_string(),
                        port: addr.port(),
                    });
                }
                Some(addr)
            }
            _ => None,
        };

        // `log_format`, `include_repository_label`,
        // `pg_statement_timeout_ms`, `pg_acquire_timeout_secs` are
        // already destructured from `MinimalConfig::from_env` above
        // .

        let metadata_caps = parse_metadata_caps()?;

        let metadata_blob_max_bytes = parse_metadata_blob_max_bytes()?;

        let public_base_url = parse_public_base_url()?;

        let trusted_proxy_cidrs = parse_trusted_proxy_cidrs()?;

        let publish_body_limit_bytes = parse_publish_body_limit_bytes()?;

        let jwks_eviction_backoff_secs = parse_jwks_eviction_backoff_secs()?;

        let jwks_resp_body_max_bytes = parse_jwks_resp_body_max_bytes()?;

        let ratelimit_auth_per_min = parse_ratelimit_auth_per_min()?;

        let ratelimit_write_per_min = parse_ratelimit_write_per_min()?;

        // Workspace-wide + per-IP concurrency caps. Defaults: 512 / 32.
        let max_inflight = parse_max_inflight()?;
        let max_inflight_per_ip = parse_max_inflight_per_ip()?;

        let rbac_refresh_secs = parse_rbac_refresh_secs()?;
        let event_chain_checkpoint_cadence_secs = parse_event_chain_checkpoint_cadence_secs()?;

        // HTTP transport timeouts.
        // Defaults: 15s header-read, 5min request deadline,
        // 60min OCI-upload ceiling.
        let http_header_read_timeout_secs = parse_http_header_read_timeout_secs()?;
        let http_request_timeout_secs = parse_http_request_timeout_secs()?;
        let http_oci_upload_timeout_secs = parse_http_oci_upload_timeout_secs()?;

        // Pull-through deduplication TTL + follower-wait knobs.
        // Defaults: 30 / 10 / 10 / 60 secs negative-cache TTL spread;
        // 300 secs follower wait ceiling. The four TTL knobs cluster every
        // `UpstreamErrorKind` failure variant under one of four
        // operator-tunable durations; the follower-wait knob is the
        // 503 fall-through ceiling. None of these are
        // correctness-load-bearing — operator-tunable purely so a
        // deployment with unusually high upstream failure rates can
        // dial the negative-cache window without a code change.
        let pull_dedup_ttl_not_found_secs = parse_pull_dedup_ttl_not_found_secs()?;
        let pull_dedup_ttl_unavailable_secs = parse_pull_dedup_ttl_unavailable_secs()?;
        let pull_dedup_ttl_timeout_secs = parse_pull_dedup_ttl_timeout_secs()?;
        let pull_dedup_ttl_checksum_mismatch_secs = parse_pull_dedup_ttl_checksum_mismatch_secs()?;
        let pull_dedup_follower_wait_secs = parse_pull_dedup_follower_wait_secs()?;

        // Graceful-shutdown
        // wall-clock cap. Default 60s matches the prior hard-coded
        // serve-loop deadline; making it operator-tunable lets
        // deployments bound how long a stuck handler can delay
        // orchestrator-initiated rollouts before SIGKILL escalates.
        let shutdown_grace_secs = parse_shutdown_grace_secs()?;

        // Operator-controlled enumerated
        // upstream-host allowlist for `apply_upstream_mappings`.
        // Default `Disabled` preserves the historical posture; the
        // operator opts into enforcement by setting
        // `HORT_UPSTREAM_ALLOWLIST_HOSTS`. See
        // `docs/operator/upstream-trust-model.md`.
        let upstream_allowlist = parse_upstream_allowlist();

        // Stateful-upload staging root. Explicit env var takes precedence.
        // When unset, we derive a sibling directory from the configured CAS
        // root if (and only if) the backend is filesystem:
        // `<HORT_STORAGE_FILESYSTEM_PATH>/stateful-upload-staging`. For S3 there is no
        // natural local sibling, so we fall back to a fixed
        // `/var/lib/hort/stateful-upload-staging` — operators
        // running against S3 should set `HORT_STATEFUL_UPLOAD_STAGING_DIR`
        // explicitly; the default is a best-effort that keeps the binary
        // bootable in container environments where `/var/lib/hort`
        // is the conventional writable mount point.
        let stateful_upload_staging_dir = parse_stateful_upload_staging_dir(&storage)?;

        // Docker-legacy global-catalog flag.
        // Default-off strict-modern (see field docstring on Config).
        let oci_legacy_catalog_enabled = parse_bool("HORT_OCI_LEGACY_CATALOG_ENABLED", false)?;

        // Per-`(repo,
        // principal)` outstanding-session cap. Default 32 matches
        // the audit guidance.
        let oci_max_sessions_per_principal = parse_oci_max_sessions_per_principal()?;

        // `EphemeralStore` backend + Redis URL.
        // Default is Memory so dev / test envs boot without a Redis
        // sidecar. When backend is Redis, `HORT_REDIS_URL` is required.
        let ephemeral_store_backend = parse_ephemeral_store_backend()?;
        let redis_url = match ephemeral_store_backend {
            EphemeralStoreBackend::Memory => None,
            EphemeralStoreBackend::Redis => Some(require("HORT_REDIS_URL")?),
        };
        // Optional per-class Redis URL overrides.
        // Both fields are parsed UNCONDITIONALLY (independent of
        // `HORT_EPHEMERAL_STORE_BACKEND`): a future operator who runs
        // the Memory backend in dev but pre-stages
        // the per-class env vars for production parity should not trip
        // a parse error. Resolution / fallback to `redis_url` lives
        // at composition time; this layer only
        // captures the values. Empty string is treated as `None`,
        // matching the `parse_secret_env` empty-as-None
        // pattern — protects against a Helm chart that emits an
        // empty `value:` when the override is left blank.
        let redis_url_evictable = std::env::var("HORT_REDIS_URL_EVICTABLE")
            .ok()
            .filter(|v| !v.is_empty());
        let redis_url_durable = std::env::var("HORT_REDIS_URL_DURABLE")
            .ok()
            .filter(|v| !v.is_empty());

        // Upstream-resolver refresh cadence.
        // Default 60s; clamp at 5s to bound DB load if an operator
        // typos a tiny value.
        let upstream_resolver_refresh_secs =
            match std::env::var("HORT_UPSTREAM_RESOLVER_REFRESH_SECS") {
                Ok(v) if !v.is_empty() => {
                    let parsed: u32 = v.parse().map_err(|source| ConfigError::InvalidInt {
                        var: "HORT_UPSTREAM_RESOLVER_REFRESH_SECS",
                        source,
                    })?;
                    if parsed < 5 {
                        return Err(ConfigError::InvalidValue {
                            var: "HORT_UPSTREAM_RESOLVER_REFRESH_SECS",
                            reason: format!("must be >= 5 (got {parsed})"),
                        });
                    }
                    parsed
                }
                _ => 60,
            };

        // Three storage-backstop knobs
        // (metadata 64 MiB, manifest 16 MiB, per-version-object 2 MiB),
        // each a human-readable size string (`64Mi`, `1Gi`, decimal
        // `64M`, or a bare byte integer) resolved to bytes. Size strings
        // (not bare integers) are the operator surface so a multi-GiB
        // value can never round-trip through Helm's float64 coercion into
        // scientific notation — the rc.3 boot-crash class. Minimum 1024
        // bytes — a smaller cap is a typo, not a deployment choice.
        const MIN_UPSTREAM_CAP_BYTES: u64 = 1024;
        let upstream_metadata_cache_max_bytes = parse_byte_size_env(
            "HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE",
            64 * 1024 * 1024,
            MIN_UPSTREAM_CAP_BYTES,
        )?;
        let upstream_manifest_cache_max_bytes = parse_byte_size_env(
            "HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE",
            16 * 1024 * 1024,
            MIN_UPSTREAM_CAP_BYTES,
        )?;
        let upstream_projector_version_object_max_bytes = parse_byte_size_env(
            "HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE",
            2 * 1024 * 1024,
            MIN_UPSTREAM_CAP_BYTES,
        )?;

        // Audit-retention floors. Each `HORT_RETENTION_FLOOR_*_DAYS`
        // override may only ever *raise* a floor: an override below its
        // documented minimum is a hard startup failure (mirrors the
        // `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` `>= 5` reject pattern
        // above). Unset → the default.
        let audit_retention_floors = {
            let d = AuditRetentionFloors::c1_defaults();
            AuditRetentionFloors {
                authentication: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS",
                    AuditRetentionFloors::MIN_AUTHENTICATION_DAYS,
                    d.authentication(),
                )?,
                policy_authz_admin: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_POLICY_AUTHZ_ADMIN_DAYS",
                    AuditRetentionFloors::MIN_POLICY_AUTHZ_ADMIN_DAYS,
                    d.policy_authz_admin(),
                )?,
                artifact_downloaded: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_ARTIFACT_DOWNLOADED_DAYS",
                    AuditRetentionFloors::MIN_ARTIFACT_DOWNLOADED_DAYS,
                    d.artifact_downloaded(),
                )?,
                api_token_used: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_API_TOKEN_USED_DAYS",
                    AuditRetentionFloors::MIN_API_TOKEN_USED_DAYS,
                    d.api_token_used(),
                )?,
                artifact_lifecycle: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_ARTIFACT_LIFECYCLE_DAYS",
                    AuditRetentionFloors::MIN_ARTIFACT_LIFECYCLE_DAYS,
                    d.artifact_lifecycle(),
                )?,
            }
        };

        // The ONE global stream
        // retention mode for v1. `delete` (default) or `archive`;
        // `archive` requires a non-empty `HORT_RETENTION_ARCHIVE_TARGET`
        // prefix (a missing/empty target with `archive` is a startup
        // hard-fail — silently degrading to delete would be data loss).
        let retention_stream_mode = match std::env::var("HORT_RETENTION_STREAM_MODE") {
            Ok(v) if !v.is_empty() => match v.to_ascii_lowercase().as_str() {
                "delete" => StreamRetentionMode::Delete,
                "archive" => {
                    let target = std::env::var("HORT_RETENTION_ARCHIVE_TARGET")
                        .ok()
                        .filter(|t| !t.is_empty())
                        .ok_or_else(|| ConfigError::InvalidValue {
                            var: "HORT_RETENTION_ARCHIVE_TARGET",
                            reason: "HORT_RETENTION_STREAM_MODE=archive requires a non-empty \
                                     HORT_RETENTION_ARCHIVE_TARGET prefix"
                                .to_owned(),
                        })?;
                    StreamRetentionMode::Archive {
                        target_prefix: target,
                    }
                }
                other => {
                    return Err(ConfigError::InvalidValue {
                        var: "HORT_RETENTION_STREAM_MODE",
                        reason: format!("expected one of [delete, archive], got {other:?}"),
                    });
                }
            },
            _ => StreamRetentionMode::Delete,
        };

        // Unconditional startup failure when the operator has pinned
        // neither a public URL nor a trusted-proxy allowlist.
        // Deliberately NOT auth-gated: X-Forwarded-Host poisoning of
        // package download URLs works against any deployment that
        // serves URLs to clients — auth or no auth.
        if public_base_url.is_none() && trusted_proxy_cidrs.is_empty() {
            return Err(ConfigError::TrustUnconfigured);
        }

        // `HORT_REQUIRE_HTTPS` opt-in
        // gate. When the operator has set the gate AND the binary has
        // no positive evidence the public connection is TLS, refuse
        // to start so the misconfiguration is loud. Positive evidence
        // is either:
        //   1. `HORT_PUBLIC_BASE_URL` is `https://...`, OR
        //   2. `HORT_TRUSTED_PROXY_CIDRS` is non-empty (operator wired a
        //      proxy and trusts its `X-Forwarded-Proto`).
        // The AND-condition means the gate fires only on the silent
        // plaintext-deployment case (forgot the proxy, exposed 8080
        // directly, used HTTP-only ingress) — exactly the trap the
        // gate exists to close. Default `false` keeps existing
        // local-dev setups booting without changes.
        let require_https = parse_bool("HORT_REQUIRE_HTTPS", false)?;
        if require_https {
            let base_url_is_http = public_base_url
                .as_ref()
                .map(|u| u.scheme() == "http")
                .unwrap_or(false);
            if base_url_is_http && trusted_proxy_cidrs.is_empty() {
                return Err(ConfigError::InsecureHttp);
            }
        }

        // `HORT_CONFIG_DIR`.
        let config_dir = parse_config_dir()?;

        // There is no `HORT_GROUP_MAPPINGS_PATH`
        // single-file loader; mappings load exclusively from
        // `$HORT_CONFIG_DIR/auth/*.yaml` via the gitops parser.
        // The returned `claim_mappings` vec is always empty here;
        // the gitops boot in `cli::serve` populates `AuthenticateUseCase`
        // from `ClaimMappingRepository::list_all()` after apply.
        let auth = parse_auth_provider()?;
        let claim_mappings: Vec<ClaimMapping> = Vec::new();

        // Startup log — one structured emission summarising the auth
        // surface. Token signing key is NEVER logged; issuer URL is shown
        // for OIDC only. If this fires before the tracing subscriber is
        // installed (as it currently does in `main.rs`) the emission is a
        // no-op, which is fine — the Debug impl on `Config` surfaces the
        // same fields if a caller prints it later.
        let auth_provider_label = match &auth {
            AuthConfig::Disabled => "disabled",
            AuthConfig::Oidc(_) => "oidc",
        };
        let oidc_issuer_url: Option<&str> = match &auth {
            AuthConfig::Oidc(o) => Some(o.issuer_url.as_str()),
            AuthConfig::Disabled => None,
        };
        tracing::info!(
            auth_provider = auth_provider_label,
            claim_mappings_count = claim_mappings.len(),
            oidc_issuer_url = oidc_issuer_url,
            "auth configuration loaded"
        );
        if matches!(auth, AuthConfig::Oidc(_)) && claim_mappings.is_empty() {
            tracing::warn!("claim mappings empty — no users will receive claims via OIDC");
        }

        // Native API token + PAT-cache + PAT-lockout knobs. Defaults:
        // feature flag OFF, plaintext-PAT refused, cache 10k entries,
        // 30 misses / 5 min triggers a 15-min lockout.
        let enable_native_tokens = parse_bool("HORT_NATIVE_TOKENS_ENABLED", false)?;
        // Event-notification substrate knobs.
        // Default-on for `HORT_NOTIFICATIONS_ENABLED` because the broadcast
        // path is zero-cost without subscribers and the dispatcher
        // self-disables when no `Subscription` rows exist. Default
        // `HORT_NOTIFY_CHANNEL_CAPACITY=1024`.
        let enable_notifications = parse_bool("HORT_NOTIFICATIONS_ENABLED", true)?;
        let notify_channel_capacity = parse_notify_channel_capacity()?;
        // Webhook transport + SSRF flags.
        // Both default `false`; when on, composition emits a paired
        // `hort_unsafe_config_active{kind=...}` gauge so the misconfig is
        // visible on every dashboard.
        let allow_plaintext_webhooks = parse_bool("HORT_WEBHOOK_ALLOW_PLAINTEXT", false)?;
        let allow_nonroutable_webhook_targets =
            parse_bool("HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS", false)?;
        // Optional NATS adapter. `Some(url)`
        // opens an async-nats client; `None` skips the adapter.
        // Subscriptions targeting NATS will fail delivery if this is
        // unset.
        let nats_url = std::env::var("HORT_NATS_URL")
            .ok()
            .filter(|v| !v.is_empty());
        let allow_pat_over_http = parse_bool("HORT_BEARER_ALLOW_OVER_HTTP", false)?;
        let pat_cache_size = parse_pat_cache_size()?;
        let pat_lockout_threshold = parse_pat_lockout_threshold()?;
        let pat_lockout_window_secs = parse_pat_lockout_window_secs()?;
        let pat_lockout_duration_secs = parse_pat_lockout_duration_secs()?;
        // Issuance feature flags. Both default to `false`
        // (admin tokens off, unbounded service-account tokens off).
        let allow_admin_tokens = parse_bool("HORT_TOKEN_ALLOW_ADMIN", false)?;
        let allow_unbounded_svc_tokens = parse_bool("HORT_TOKEN_ALLOW_UNBOUNDED_SVC", false)?;

        // Token-exchange feature flag. When false,
        // `POST /api/v1/auth/exchange` is not mounted and axum's
        // default 404 applies. Defaults to false (no surface
        // advertised) per the RC posture.
        let enable_token_exchange = parse_bool("HORT_TOKEN_EXCHANGE_ENABLED", false)?;
        // Fresh-install posture is the safe default
        // (`true`). Upgrade installs with authoritative refcount state
        // set this `false` explicitly (see the struct field doc).
        let refcount_reconcile_on_startup = parse_bool("HORT_REFCOUNT_RECONCILE_ON_STARTUP", true)?;

        // Fail-closed when the feature is on
        // but the discovery document at `/.well-known/hort-client-config`
        // would be served with missing fields. The route renders three
        // dependent values straight from process env; serving a
        // half-formed document would silently downgrade `hort-cli` into
        // guessing IdP coordinates out-of-band. Mirrors the
        // fail-closed pattern of `OciPublicBaseUrlMissing`.
        if enable_token_exchange {
            let mut missing: Vec<&str> = Vec::new();
            match &auth {
                AuthConfig::Disabled => {
                    // No OIDC provider → both issuer and cli_client_id
                    // are unresolvable. Name the user-facing env vars
                    // (operators set these, not `HORT_AUTH_PROVIDER`
                    // which only switches the parse branch).
                    missing.push("HORT_OIDC_ISSUER_URL");
                    missing.push("HORT_OIDC_CLI_CLIENT_ID");
                }
                AuthConfig::Oidc(o) => {
                    if o.issuer_url.is_empty() {
                        missing.push("HORT_OIDC_ISSUER_URL");
                    }
                    if o.cli_client_id.as_deref().unwrap_or("").is_empty() {
                        missing.push("HORT_OIDC_CLI_CLIENT_ID");
                    }
                }
            }
            if public_base_url.is_none() {
                missing.push("HORT_PUBLIC_BASE_URL");
            }
            if !missing.is_empty() {
                return Err(ConfigError::TokenExchangeRequiresVars {
                    missing: missing.join(", "),
                });
            }
            // Token-exchange mints `hort_cli_*`
            // (PAT-shape) tokens via `issue_cli_session`. Validation
            // of those tokens at request-time goes through
            // `PatValidationUseCase`, which the composition root
            // only wires when `enable_native_tokens=true`. Without
            // this gate, operators flipping HORT_TOKEN_EXCHANGE_ENABLED
            // alone produce a server that issues tokens it cannot
            // validate — login succeeds, every subsequent call 401s.
            // Fail-closed at boot so the misconfig surfaces as a
            // single startup error instead of a confusing runtime
            // pattern.
            if !enable_native_tokens {
                return Err(ConfigError::TokenExchangeRequiresNativeTokens);
            }
        }

        // OCI token signing keys. `_FILE`
        // takes precedence over inline; setting both with non-empty
        // values is `AmbiguousSigningKeySource` (boot-fail). When
        // `enable_native_tokens=true` and no key is configured,
        // surface `OciTokenSigningKeyMissing`.
        let oci_token_signing_key_pem = parse_secret_env(
            "HORT_OCI_TOKEN_SIGNING_KEY_FILE",
            "HORT_OCI_TOKEN_SIGNING_KEY",
        )?;
        let oci_token_signing_key_prev_pem = parse_secret_env(
            "HORT_OCI_TOKEN_SIGNING_KEY_PREV_FILE",
            "HORT_OCI_TOKEN_SIGNING_KEY_PREV",
        )?;
        if enable_native_tokens && oci_token_signing_key_pem.is_none() {
            return Err(ConfigError::OciTokenSigningKeyMissing);
        }
        if !enable_native_tokens
            && (oci_token_signing_key_pem.is_some() || oci_token_signing_key_prev_pem.is_some())
        {
            tracing::debug!(
                "HORT_OCI_TOKEN_SIGNING_KEY (and/or _PREV) configured but \
                HORT_NATIVE_TOKENS_ENABLED=false — keys held but unused"
            );
        }

        // Parsed at the full-Config boundary
        // (NOT in `MinimalConfig`, which is DB-only). Default `true`
        // mirrors the operator-declared SA count: <50 by construction.
        let include_service_account_label =
            parse_bool("METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL", true)?;

        Ok(Self {
            database_url,
            storage,
            api_bind_addr,
            require_https,
            metrics_bind_addr,
            metrics_require_auth,
            metrics_public_bind,
            control_bind_addr,
            control_public_bind,
            log_format,
            include_repository_label,
            include_service_account_label,
            metadata_caps,
            metadata_blob_max_bytes,
            public_base_url,
            trusted_proxy_cidrs,
            auth,
            claim_mappings,
            config_dir,
            publish_body_limit_bytes,
            pg_statement_timeout_ms,
            pg_acquire_timeout_secs,
            jwks_eviction_backoff_secs,
            jwks_resp_body_max_bytes,
            ratelimit_auth_per_min,
            ratelimit_write_per_min,
            max_inflight,
            max_inflight_per_ip,
            rbac_refresh_secs,
            event_chain_checkpoint_cadence_secs,
            stateful_upload_staging_dir,
            oci_legacy_catalog_enabled,
            oci_max_sessions_per_principal,
            ephemeral_store_backend,
            redis_url,
            redis_url_evictable,
            redis_url_durable,
            upstream_resolver_refresh_secs,
            upstream_metadata_cache_max_bytes,
            upstream_manifest_cache_max_bytes,
            upstream_projector_version_object_max_bytes,
            http_header_read_timeout_secs,
            http_request_timeout_secs,
            http_oci_upload_timeout_secs,
            pull_dedup_ttl_not_found_secs,
            pull_dedup_ttl_unavailable_secs,
            pull_dedup_ttl_timeout_secs,
            pull_dedup_ttl_checksum_mismatch_secs,
            pull_dedup_follower_wait_secs,
            shutdown_grace_secs,
            upstream_allowlist,
            cas_scrub_action_on_mismatch: parse_cas_scrub_action_on_mismatch()?,
            enable_native_tokens,
            enable_notifications,
            notify_channel_capacity,
            allow_plaintext_webhooks,
            allow_nonroutable_webhook_targets,
            nats_url,
            allow_pat_over_http,
            pat_cache_size,
            pat_lockout_threshold,
            pat_lockout_window_secs,
            pat_lockout_duration_secs,
            allow_admin_tokens,
            allow_unbounded_svc_tokens,
            enable_token_exchange,
            refcount_reconcile_on_startup,
            oci_token_signing_key_pem,
            oci_token_signing_key_prev_pem,
            audit_retention_floors,
            retention_stream_mode,
        })
    }
}

/// Resolve one audit-retention floor
/// from its `HORT_RETENTION_FLOOR_*_DAYS` env override, enforcing the
/// documented minimum (`docs/compliance/GDPR.md`).
///
/// Unset / empty → the documented `default`. Set → parsed as a positive day
/// count; a non-integer is [`ConfigError::InvalidInt`]; a value below
/// `min_days` is [`ConfigError::InvalidValue`] (the operator may only
/// ever *raise* a floor — lowering it below the documented GDPR/NIS2/
/// CRA minimum is a startup hard-fail, mirroring the
/// `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` `>= 5` reject pattern).
fn resolve_retention_floor_days(
    var: &'static str,
    min_days: i64,
    default: chrono::Duration,
) -> Result<chrono::Duration, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => {
            let parsed: i64 = v
                .parse()
                .map_err(|source| ConfigError::InvalidInt { var, source })?;
            if parsed < min_days {
                return Err(ConfigError::InvalidValue {
                    var,
                    reason: format!("must be >= {min_days} (minimum; got {parsed})"),
                });
            }
            Ok(chrono::Duration::days(parsed))
        }
        _ => Ok(default),
    }
}

/// `_FILE`-precedence secret loader.
///
/// Reads `file_var` first (preferred for k8s mounted secrets); falls
/// back to `inline_var` (literal env-var value). Setting both with
/// non-empty values surfaces as
/// [`ConfigError::AmbiguousSigningKeySource`] (boot-fail) so the
/// operator cannot accidentally validate against the wrong half.
///
/// `Ok(None)` when neither is set. `Ok(Some(_))` carries the literal
/// PEM (file content or inline value).
fn parse_secret_env(
    file_var: &'static str,
    inline_var: &'static str,
) -> Result<Option<String>, ConfigError> {
    let file_path = std::env::var(file_var).ok().filter(|v| !v.is_empty());
    let inline = std::env::var(inline_var).ok().filter(|v| !v.is_empty());
    if file_path.is_some() && inline.is_some() {
        return Err(ConfigError::AmbiguousSigningKeySource {
            file_var,
            inline_var,
        });
    }
    if let Some(path) = file_path {
        return std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|source| ConfigError::OciSigningKeyUnreadable { path, source });
    }
    Ok(inline)
}

/// Parse `HORT_EPHEMERAL_STORE_BACKEND`.
///
/// Absent / empty → [`EphemeralStoreBackend::Memory`] (dev / test
/// default). Case-insensitive. Unknown values fail startup via
/// [`ConfigError::InvalidEphemeralStoreBackend`] — a typo would
/// otherwise silently fall through to the memory default and break
/// multi-node deployments.
fn parse_ephemeral_store_backend() -> Result<EphemeralStoreBackend, ConfigError> {
    const VAR: &str = "HORT_EPHEMERAL_STORE_BACKEND";
    match std::env::var(VAR) {
        Ok(v) if !v.is_empty() => match v.to_lowercase().as_str() {
            "memory" => Ok(EphemeralStoreBackend::Memory),
            "redis" => Ok(EphemeralStoreBackend::Redis),
            _ => Err(ConfigError::InvalidEphemeralStoreBackend { var: VAR, got: v }),
        },
        _ => Ok(EphemeralStoreBackend::Memory),
    }
}

/// Parse `HORT_STATEFUL_UPLOAD_STAGING_DIR`.
///
/// Explicit env var wins. Fallback depends on the storage backend:
///
/// - `StorageConfig::Filesystem { root }` → `<root>/stateful-upload-staging`
/// - `StorageConfig::S3 { .. }` → fixed `/var/lib/hort/stateful-upload-staging`
///
/// The S3 fallback is documented on
/// [`Config::stateful_upload_staging_dir`]; the operator should override
/// it in container deployments where `/var/lib` is not writable.
fn parse_stateful_upload_staging_dir(storage: &StorageConfig) -> Result<PathBuf, ConfigError> {
    const VAR: &str = "HORT_STATEFUL_UPLOAD_STAGING_DIR";
    if let Ok(v) = std::env::var(VAR) {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let fallback = match storage {
        StorageConfig::Filesystem { root } => root.join("stateful-upload-staging"),
        StorageConfig::S3 { .. } => {
            // S3 has no natural local sibling for staging, so we fall
            // back to a fixed path. Warn loudly at startup — an
            // operator running on S3-backed storage who never wrote an
            // OCI blob may not discover this until the first PATCH
            // request fails on an unwritable container filesystem.
            tracing::warn!(
                fallback = "/var/lib/hort/stateful-upload-staging",
                "HORT_STATEFUL_UPLOAD_STAGING_DIR is unset and storage backend is S3; \
                 defaulting stateful-upload staging root to the fallback path. Set \
                 HORT_STATEFUL_UPLOAD_STAGING_DIR to a writable directory on every \
                 replica to silence this warning."
            );
            PathBuf::from("/var/lib/hort/stateful-upload-staging")
        }
    };
    Ok(fallback)
}

/// Parse `HORT_RATELIMIT_AUTH_PER_MIN`.
///
/// Absent or empty env var → the 60-request/minute default. Non-integer
/// values surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — `tower_governor`'s `finish()`
/// returns `None` on `burst_size == 0`, and our layer builder panics on
/// that path (defensive; should never fire because of this check).
fn parse_ratelimit_auth_per_min() -> Result<u32, ConfigError> {
    parse_positive::<u32>("HORT_RATELIMIT_AUTH_PER_MIN", 60)
}

/// Parse `HORT_RATELIMIT_WRITE_PER_MIN`.
///
/// Absent or empty env var → the 300-request/minute default. Non-integer
/// values surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`].
fn parse_ratelimit_write_per_min() -> Result<u32, ConfigError> {
    parse_positive::<u32>("HORT_RATELIMIT_WRITE_PER_MIN", 300)
}

/// Parse `HORT_MAX_INFLIGHT`.
///
/// Absent or empty env var → the 512 default (workspace-wide concurrent
/// request cap). Non-integer values surface as [`ConfigError::InvalidInt`];
/// zero surfaces as [`ConfigError::ValueNotPositive`] — `NonZeroUsize::new(0)`
/// is `None` and the middleware constructor would panic; better to
/// reject at startup.
fn parse_max_inflight() -> Result<usize, ConfigError> {
    parse_positive::<usize>(
        "HORT_MAX_INFLIGHT",
        hort_http_core::middleware::load_shed::DEFAULT_MAX_INFLIGHT,
    )
}

/// Parse `HORT_MAX_INFLIGHT_PER_IP`.
///
/// Absent or empty env var → the 32 default (per-IP concurrent request
/// cap). Non-integer values surface as [`ConfigError::InvalidInt`]; zero
/// surfaces as [`ConfigError::ValueNotPositive`].
fn parse_max_inflight_per_ip() -> Result<usize, ConfigError> {
    parse_positive::<usize>(
        "HORT_MAX_INFLIGHT_PER_IP",
        hort_http_core::middleware::load_shed::DEFAULT_MAX_INFLIGHT_PER_IP,
    )
}

/// Parse `HORT_RBAC_REFRESH_SECS`.
///
/// Absent or empty env var → the 30-second default. Non-integer values
/// surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero interval would either
/// busy-loop the refresh task or be a nonsensical "never poll" request.
/// Both are better caught at startup than at runtime.
fn parse_rbac_refresh_secs() -> Result<u32, ConfigError> {
    parse_positive::<u32>("HORT_RBAC_REFRESH_SECS", 30)
}

/// Parse `HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS`.
///
/// Absent or empty env var → the hourly (`3600`) default. Non-integer
/// values surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero cadence would make the
/// `2 × cadence` staleness window zero and report every anchor stale.
fn parse_event_chain_checkpoint_cadence_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS", 3600)
}

/// Parse `HORT_HTTP_HEADER_READ_TIMEOUT_SECS`.
///
/// Absent or empty env var → the 15-second default. Non-integer
/// values surface as [`ConfigError::InvalidInt`]; zero
/// surfaces as [`ConfigError::ValueNotPositive`] because zero would
/// disable the slowloris defence — a hyper `header_read_timeout` of
/// `Duration::ZERO` cuts every connection on the first byte, but the
/// operator-meaningful "disable" is never the right choice for a
/// public-facing surface.
fn parse_http_header_read_timeout_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_HTTP_HEADER_READ_TIMEOUT_SECS", 15)
}

/// Parse `HORT_HTTP_REQUEST_TIMEOUT_SECS`.
///
/// Absent or empty env var → the 300-second (5-minute) default. The
/// `tower_http::TimeoutLayer` cancels the inner Service future when
/// the deadline elapses and returns `408 Request Timeout`. Zero
/// surfaces as [`ConfigError::ValueNotPositive`] (would 408 every
/// request).
fn parse_http_request_timeout_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_HTTP_REQUEST_TIMEOUT_SECS", 300)
}

/// Parse `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS`.
///
/// Absent or empty env var → the 3600-second (60-minute) default. The
/// per-route override on the OCI blob upload subtree uses this longer
/// ceiling so a multi-GB layer push that legitimately exceeds the
/// global 5-minute deadline is not killed mid-stream. Zero surfaces
/// as [`ConfigError::ValueNotPositive`] (would defeat the purpose
/// of the per-route override).
fn parse_http_oci_upload_timeout_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS", 3600)
}

/// Parse `HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL`.
///
/// Absent or empty env var → the 32-session default (audit
/// guidance). Non-integer values surface as
/// [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero cap rejects every
/// initiate, breaking the OCI push protocol for every authenticated
/// user, which is almost certainly not the operator-meaningful
/// "disable cap" choice.
fn parse_oci_max_sessions_per_principal() -> Result<u32, ConfigError> {
    parse_positive::<u32>("HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL", 32)
}

/// Parse `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS`.
///
/// Absent or empty env var → 30 seconds. Non-integer values surface
/// as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero TTL would re-fetch on
/// every retry within the negative-cache window, defeating coalescing
/// on 404 storms.
fn parse_pull_dedup_ttl_not_found_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS", 30)
}

/// Parse `HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS`.
///
/// Absent or empty env var → 10 seconds. Clusters `RateLimited`,
/// `Upstream5xx`, `Upstream4xx`, and `Unauthorized`.
/// Non-integer values surface as [`ConfigError::InvalidInt`]; zero
/// surfaces as [`ConfigError::ValueNotPositive`].
fn parse_pull_dedup_ttl_unavailable_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS", 10)
}

/// Parse `HORT_PULL_DEDUP_TTL_TIMEOUT_SECS`.
///
/// Absent or empty env var → 10 seconds. Clusters `Timeout` and
/// `NetworkError`. Same default as the unavailable
/// cluster — transient transport failures resolve on a similar
/// timescale to transient HTTP failures. Non-integer values surface
/// as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`].
fn parse_pull_dedup_ttl_timeout_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PULL_DEDUP_TTL_TIMEOUT_SECS", 10)
}

/// Parse `HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS`.
///
/// Absent or empty env var → 60 seconds. Clusters
/// `ChecksumMismatch`, `ParseError`, `BodyTooLarge`, `PinMismatch`,
/// and `CaUnknown` — all five require operator intervention to
/// resolve, so a longer TTL prevents thrash on repeated client
/// retries during the operator's fix window. Non-integer values
/// surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`].
fn parse_pull_dedup_ttl_checksum_mismatch_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS", 60)
}

/// Parse `HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS`.
///
/// Absent or empty env var → 300 seconds (5 minutes). On expiry
/// the follower returns `503 + Retry-After: 30` rather than falling
/// through to an un-coalesced fetch (breaking coalescing on a stuck
/// leader will not speed up the underlying upstream). Non-integer values surface as
/// [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero ceiling would 503
/// instantly on every concurrent follower request.
fn parse_pull_dedup_follower_wait_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS", 300)
}

/// Parse `HORT_NOTIFY_CHANNEL_CAPACITY`.
///
/// Absent or empty env var → the 1024 default. Non-integer values
/// surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — the `broadcast::channel(0)`
/// shape is meaningless (no slot to hold even one in-flight event).
fn parse_notify_channel_capacity() -> Result<u32, ConfigError> {
    parse_positive::<u32>("HORT_NOTIFY_CHANNEL_CAPACITY", 1024)
}

/// Parse `HORT_PAT_CACHE_SIZE`.
///
/// Absent or empty env var → the 10k-entry default. Non-integer
/// values surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero-capacity cache would
/// thrash on every validation (the LRU would clamp to 1 internally
/// per `PatCache::new`'s zero-clamp behaviour, but we'd rather refuse
/// the misconfig at startup than silently downgrade).
fn parse_pat_cache_size() -> Result<usize, ConfigError> {
    parse_positive::<usize>("HORT_PAT_CACHE_SIZE", 10_000)
}

/// Parse `HORT_PAT_LOCKOUT_THRESHOLD`.
///
/// Absent or empty env var → the 30-attempt default ("30 misses /
/// 5 min triggers a 15-min lockout"). Non-integer values
/// surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero threshold would activate
/// the gate on the first PAT validation, locking out every legitimate
/// caller.
fn parse_pat_lockout_threshold() -> Result<u32, ConfigError> {
    parse_positive::<u32>("HORT_PAT_LOCKOUT_THRESHOLD", 30)
}

/// Parse `HORT_PAT_LOCKOUT_WINDOW_SECS`.
///
/// Absent or empty env var → 300 seconds (5 min). Non-integer values
/// surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero window would mean the
/// per-IP counter expires the moment it is written, defeating the gate.
fn parse_pat_lockout_window_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PAT_LOCKOUT_WINDOW_SECS", 300)
}

/// Parse `HORT_PAT_LOCKOUT_DURATION_SECS`.
///
/// Absent or empty env var → 900 seconds (15 min). Non-integer
/// values surface as [`ConfigError::InvalidInt`]; zero
/// surfaces as [`ConfigError::ValueNotPositive`] — a zero duration
/// would unlock the IP between the increment and the gate check,
/// defeating the cooldown.
fn parse_pat_lockout_duration_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_PAT_LOCKOUT_DURATION_SECS", 900)
}

/// Parse `HORT_SHUTDOWN_GRACE_SECS`.
///
/// Absent or empty env var → the 60-second default — long enough that a
/// well-behaved request finishes its current syscall and unwinds, short
/// enough that orchestrator rollouts (k8s `terminationGracePeriodSeconds`
/// defaults to 30s; we sit one tier above that) don't escalate to
/// SIGKILL on the deadline. Non-integer values surface as
/// [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] — a zero grace would skip
/// in-flight drain entirely on every shutdown, leaving uploads in
/// undefined state. Operators wanting "abort immediately on signal"
/// should drop their orchestrator's grace period instead.
fn parse_shutdown_grace_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_SHUTDOWN_GRACE_SECS", 60)
}

/// Sealed helper trait for integer types that env-var parsers treat as
/// "positive required": `u32`, `u64`, `usize`. Provides only what the
/// shared parser needs — a zero sentinel for the reject-zero check and a
/// lossy widening to `u64` for the `ValueNotPositive.got` field. Sealed
/// via the private `sealed` submodule so external callers can't add new
/// impls and accidentally change the parser's behaviour.
trait PositiveInt: Copy + Eq + FromStr<Err = ParseIntError> + sealed::Sealed {
    const ZERO: Self;
    /// Widen to `u64` for the `ConfigError::ValueNotPositive.got` field.
    /// Matches the pre-refactor behaviour: `u32::from` (infallible) and
    /// `usize as u64` (lossy on hypothetical >64-bit platforms; fine for
    /// the error message's purpose).
    fn to_u64_lossy(self) -> u64;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for usize {}
}

impl PositiveInt for u32 {
    const ZERO: Self = 0;
    fn to_u64_lossy(self) -> u64 {
        u64::from(self)
    }
}

impl PositiveInt for u64 {
    const ZERO: Self = 0;
    fn to_u64_lossy(self) -> u64 {
        self
    }
}

impl PositiveInt for usize {
    const ZERO: Self = 0;
    fn to_u64_lossy(self) -> u64 {
        self as u64
    }
}

/// Shared shape for positive-integer env vars with a default fallback.
/// Absent or empty env var yields `default`; a present non-integer value
/// surfaces as [`ConfigError::InvalidInt`]; a parsed zero surfaces as
/// [`ConfigError::ValueNotPositive`] (zero almost always carries a
/// different semantic than the operator intended — see the per-var
/// wrapper doc-comments for the specific rationale).
fn parse_positive<T: PositiveInt>(var: &'static str, default: T) -> Result<T, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => {
            let n = v
                .parse::<T>()
                .map_err(|source| ConfigError::InvalidInt { var, source })?;
            if n == T::ZERO {
                return Err(ConfigError::ValueNotPositive {
                    var,
                    got: n.to_u64_lossy(),
                });
            }
            Ok(n)
        }
        _ => Ok(default),
    }
}

/// Variant of [`parse_positive`] for env vars where unset means `None`
/// rather than "use a default" (currently only `PG_STATEMENT_TIMEOUT_MS`).
/// Same error semantics: non-integer → [`ConfigError::InvalidInt`], zero
/// → [`ConfigError::ValueNotPositive`].
fn parse_positive_optional<T: PositiveInt>(var: &'static str) -> Result<Option<T>, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => {
            let n = v
                .parse::<T>()
                .map_err(|source| ConfigError::InvalidInt { var, source })?;
            if n == T::ZERO {
                return Err(ConfigError::ValueNotPositive {
                    var,
                    got: n.to_u64_lossy(),
                });
            }
            Ok(Some(n))
        }
        _ => Ok(None),
    }
}

/// Parse `HORT_PUBLISH_BODY_MAX_SIZE`.
///
/// Absent or empty env var → `None`. The inbound-adapter layer then falls
/// back to `hort_http_core::limits::DEFAULT_PUBLISH_BODY_LIMIT` (300 MiB). A
/// present but malformed value surfaces as [`ConfigError::InvalidValue`]
/// — startup fails loudly rather than silently falling back to the
/// default.
///
/// The operator surface is a human-readable size string ("300Mi", "1Gi")
/// via [`parse_byte_size`], not a bare integer, so a multi-GiB body
/// limit can never round-trip through Helm's float64 coercion into
/// scientific notation. A bare byte integer is still accepted for
/// backward shape.
///
/// Note: unlike the other `Option<_>` parser this one does NOT reject
/// zero — a zero publish-body-limit is an explicit "refuse all publishes"
/// kill-switch, handled downstream — so an explicit `"0"` resolves to
/// `Some(0)`, distinct from the unset `None` (binary default).
fn parse_publish_body_limit_bytes() -> Result<Option<usize>, ConfigError> {
    const VAR: &str = "HORT_PUBLISH_BODY_MAX_SIZE";
    match std::env::var(VAR) {
        Ok(v) if !v.trim().is_empty() => parse_byte_size(&v)
            .map(|b| Some(b as usize))
            .map_err(|reason| ConfigError::InvalidValue { var: VAR, reason }),
        _ => Ok(None),
    }
}

/// Parse `PG_STATEMENT_TIMEOUT_MS`.
///
/// Absent or empty env var → `None` (no `SET statement_timeout` hook is
/// registered; Postgres' default behaviour applies). A present but
/// malformed value (non-integer, negative) surfaces as
/// [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] because `SET statement_timeout = 0`
/// in Postgres silently disables the timeout — the opposite of what an
/// operator who set this variable intended.
fn parse_pg_statement_timeout_ms() -> Result<Option<u64>, ConfigError> {
    parse_positive_optional::<u64>("PG_STATEMENT_TIMEOUT_MS")
}

/// Parse `PG_ACQUIRE_TIMEOUT_SECS`.
///
/// Absent or empty env var → the 30-second default. A present but
/// malformed value (non-integer, negative) surfaces as
/// [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] because a zero acquire-timeout
/// makes every pool checkout fail immediately.
fn parse_pg_acquire_timeout_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("PG_ACQUIRE_TIMEOUT_SECS", 30)
}

/// Parse `HORT_JWKS_EVICTION_BACKOFF_SECS`.
///
/// Absent or empty env var → the 10-second default. Non-integer values
/// surface as [`ConfigError::InvalidInt`]; zero surfaces as
/// [`ConfigError::ValueNotPositive`] because a zero backoff disables
/// the DoS mitigation entirely (every forged-kid signature mismatch
/// refetches the JWKS unbounded).
fn parse_jwks_eviction_backoff_secs() -> Result<u64, ConfigError> {
    parse_positive::<u64>("HORT_JWKS_EVICTION_BACKOFF_SECS", 10)
}

/// Parse `HORT_JWKS_RESP_BODY_MAX_SIZE`.
///
/// Absent or empty env var → the 1 MiB (1048576) default.
///
/// The operator surface is a human-readable size string ("1Mi", "4Mi")
/// via [`parse_byte_size`], not a bare integer, so a multi-MiB cap
/// can never round-trip through Helm's float64 coercion into scientific
/// notation. A bare byte integer is still accepted for backward shape.
/// Malformed values surface as [`ConfigError::InvalidValue`]; a sub-1-byte
/// value (including zero) is rejected because a zero cap would reject
/// every JWKS response (every byte exceeds the cap).
fn parse_jwks_resp_body_max_bytes() -> Result<usize, ConfigError> {
    parse_byte_size_env("HORT_JWKS_RESP_BODY_MAX_SIZE", 1024 * 1024, 1).map(|b| b as usize)
}

/// Parse `HORT_TRUSTED_PROXY_CIDRS`.
///
/// Absent or empty env var → empty `Vec` (operator hasn't set up a
/// reverse-proxy allowlist). Comma-separated list of CIDRs, e.g.
/// `10.0.0.0/8,192.168.1.0/24,::1/128`. Whitespace around entries is
/// trimmed. An empty entry (double comma, trailing comma) is skipped so
/// `foo,,bar` doesn't surprise operators. Any entry that fails to parse
/// as an `IpNet` surfaces as [`ConfigError::InvalidCidr`] naming the
/// offending string.
/// Parse `HORT_UPSTREAM_ALLOWLIST_HOSTS`
/// into the tri-state `UpstreamHostAllowlist`. Infallible by design:
/// every shape (unset, empty string, sentinel, comma-list,
/// pathological `,,,`) maps to a defined variant. The footgun guard
/// (empty string ≠ Strict) lives inside
/// `UpstreamHostAllowlist::parse` so the policy is single-sourced.
fn parse_upstream_allowlist() -> hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist {
    use hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist;
    const VAR: &str = "HORT_UPSTREAM_ALLOWLIST_HOSTS";
    match std::env::var(VAR) {
        Ok(v) => UpstreamHostAllowlist::parse(Some(v.as_str())),
        Err(std::env::VarError::NotPresent) => UpstreamHostAllowlist::Disabled,
        // Treat NotUnicode the same as unset rather than panicking
        // at boot — the operator will see a clear "host not in list"
        // error on their first apply, which is louder than a config
        // parse failure they may not associate with the var.
        Err(std::env::VarError::NotUnicode(_)) => UpstreamHostAllowlist::Disabled,
    }
}

fn parse_trusted_proxy_cidrs() -> Result<Vec<IpNet>, ConfigError> {
    const VAR: &str = "HORT_TRUSTED_PROXY_CIDRS";
    let raw = match std::env::var(VAR) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let net = trimmed
            .parse::<IpNet>()
            .map_err(|source| ConfigError::InvalidCidr {
                var: VAR,
                entry: trimmed.to_string(),
                source,
            })?;
        out.push(net);
    }
    Ok(out)
}

/// Parse `HORT_PUBLIC_BASE_URL`. Absent or empty → `None` (handlers fall
/// back to the `X-Forwarded-*` / `Host` chain with a `https` default).
/// Non-URL, relative, or schemeless values surface as
/// [`ConfigError::InvalidUrl`] / [`ConfigError::InvalidUrlShape`]; only
/// `http` / `https` schemes are accepted.
fn parse_public_base_url() -> Result<Option<url::Url>, ConfigError> {
    const VAR: &str = "HORT_PUBLIC_BASE_URL";
    let raw = match std::env::var(VAR) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    let url =
        url::Url::parse(&raw).map_err(|source| ConfigError::InvalidUrl { var: VAR, source })?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(ConfigError::InvalidUrlShape {
                var: VAR,
                reason: "scheme must be http or https",
                got: raw,
            });
        }
    }
    if url.host_str().is_none() {
        return Err(ConfigError::InvalidUrlShape {
            var: VAR,
            reason: "missing host",
            got: raw,
        });
    }
    Ok(Some(url))
}

/// Parse `HORT_AUTH_PROVIDER` and — when set to `oidc` — the OIDC settings.
///
/// Group mappings do not load alongside
/// the auth provider. There is no `HORT_GROUP_MAPPINGS_PATH` single-file
/// loader; mappings load exclusively from
/// `$HORT_CONFIG_DIR/auth/*.yaml` via the gitops parser, and
/// `cli::serve` reads the post-apply state via
/// `GroupMappingRepository::list_all()` directly.
fn parse_auth_provider() -> Result<AuthConfig, ConfigError> {
    const VAR: &str = "HORT_AUTH_PROVIDER";
    let raw = env_or(VAR, "disabled");
    match raw.to_lowercase().as_str() {
        "disabled" => Ok(AuthConfig::Disabled),
        "oidc" => Ok(AuthConfig::Oidc(parse_oidc_config()?)),
        _ => Err(ConfigError::InvalidAuthProvider { var: VAR, got: raw }),
    }
}

/// Parse `HORT_CONFIG_DIR`. Absent or empty →
/// `None`; the boot sequence then takes the legacy single-file path
/// for group mappings. Set → the directory MUST exist; a typo (e.g.
/// `/etc/hort/confg`) fails fast at config-parse time so the operator
/// finds out before the migration runs.
fn parse_config_dir() -> Result<Option<PathBuf>, ConfigError> {
    const VAR: &str = "HORT_CONFIG_DIR";
    match std::env::var(VAR) {
        Ok(v) if !v.is_empty() => {
            let path = PathBuf::from(&v);
            if !path.is_dir() {
                return Err(ConfigError::ConfigDirNotADirectory { path: v });
            }
            Ok(Some(path))
        }
        _ => Ok(None),
    }
}

/// Parse the OIDC-specific env vars. Called only when
/// `HORT_AUTH_PROVIDER=oidc`. Required fields surface as [`ConfigError::Missing`];
/// optional fields fall through to their documented defaults.
fn parse_oidc_config() -> Result<OidcConfig, ConfigError> {
    let issuer_url = require("HORT_OIDC_ISSUER_URL")?;
    let audience = require("HORT_OIDC_AUDIENCE")?;
    let groups_claim = env_or("HORT_OIDC_GROUPS_CLAIM", "groups");
    let jwks_cache_ttl_seconds = parse_u64("HORT_JWKS_CACHE_TTL_SECS", 600)?;
    // Optional at parse time; the fail-closed
    // validation in `Config::from_env` enforces "non-empty when
    // `HORT_TOKEN_EXCHANGE_ENABLED=true`" so OIDC deployments that don't
    // run an `hort-cli` keep booting without setting the var.
    let cli_client_id = match std::env::var("HORT_OIDC_CLI_CLIENT_ID") {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    };
    Ok(OidcConfig {
        issuer_url,
        audience,
        groups_claim,
        jwks_cache_ttl_seconds,
        cli_client_id,
    })
}

/// Parse a `u64` env var. Absent or empty → `default`. Non-integer
/// values surface as [`ConfigError::InvalidInt`].
fn parse_u64(var: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v
            .parse::<u64>()
            .map_err(|source| ConfigError::InvalidInt { var, source }),
        _ => Ok(default),
    }
}

/// Parse a human-readable byte-size env var to bytes
/// with a minimum-value check. Unset / empty → `default` (bytes).
/// Below-minimum or unparseable surfaces as [`ConfigError::InvalidValue`]
/// (the `min` constant in the caller is a deployment-typo guard, not a
/// silent floor).
///
/// Size strings are the operator surface (not bare integers) so a
/// multi-GiB value can never round-trip through Helm's float64 coercion
/// into scientific notation — the rc.3 boot-crash class this replaced.
fn parse_byte_size_env(var: &'static str, default: u64, min: u64) -> Result<u64, ConfigError> {
    let raw = std::env::var(var).ok().filter(|v| !v.trim().is_empty());
    let bytes = match raw {
        None => default,
        Some(s) => {
            parse_byte_size(&s).map_err(|reason| ConfigError::InvalidValue { var, reason })?
        }
    };
    if bytes < min {
        return Err(ConfigError::InvalidValue {
            var,
            reason: format!("must be >= {min} bytes (got {bytes})"),
        });
    }
    Ok(bytes)
}

/// Parse a human-readable byte-size string to a byte count.
///
/// Accepts a bare byte integer (`67108864`), a binary-suffixed value
/// (`64Ki`, `64Mi`, `1Gi`, `2Ti` — multiples of 1024), or a decimal-
/// suffixed value (`64k`, `64M`, `1G`, `2T` — multiples of 1000). A
/// trailing `B`/`iB` is tolerated (`64MiB` == `64Mi`). The unit is
/// case-insensitive — a byte-size knob never means SI milli, so `m` is
/// treated as mega (1000²), not milli. Fractional magnitudes are allowed
/// (`1.5Gi`) and rounded to the nearest byte. Errors are returned as a
/// human-readable `String` for the `ConfigError::InvalidValue` reason.
fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }
    // Split the leading numeric magnitude (digits + optional '.') from
    // the unit suffix.
    let split_at = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num_str, unit_raw) = s.split_at(split_at);
    let num: f64 = num_str
        .parse()
        .map_err(|_| format!("invalid size magnitude in '{raw}'"))?;
    if num < 0.0 {
        return Err(format!("size '{raw}' must not be negative"));
    }
    // Tolerate a single trailing 'B'/'b' so `64MiB`/`64MB` work as well
    // as `64Mi`/`64M`.
    let unit = unit_raw.trim();
    let unit = unit.strip_suffix(['B', 'b']).unwrap_or(unit);
    let mult: u64 = if unit.is_empty() {
        1
    } else if unit.eq_ignore_ascii_case("Ki") {
        1024
    } else if unit.eq_ignore_ascii_case("Mi") {
        1024 * 1024
    } else if unit.eq_ignore_ascii_case("Gi") {
        1024 * 1024 * 1024
    } else if unit.eq_ignore_ascii_case("Ti") {
        1024_u64.pow(4)
    } else if unit.eq_ignore_ascii_case("k") {
        1000
    } else if unit.eq_ignore_ascii_case("M") {
        1_000_000
    } else if unit.eq_ignore_ascii_case("G") {
        1_000_000_000
    } else if unit.eq_ignore_ascii_case("T") {
        1_000_000_000_000
    } else {
        return Err(format!("unknown size unit '{unit_raw}' in '{raw}'"));
    };
    let bytes = (num * mult as f64).round();
    if !bytes.is_finite() || bytes > u64::MAX as f64 {
        return Err(format!("size '{raw}' is out of range"));
    }
    Ok(bytes as u64)
}

/// Parse `HORT_METADATA_BLOB_MAX_SIZE`. Absent or empty → 10 MB default.
/// `0` is permitted and means "accept anything" (see field docstring).
///
/// The operator surface is a human-readable size string ("10Mi",
/// "64Mi") via [`parse_byte_size`], not a bare integer, so a multi-GiB
/// cap can never round-trip through Helm's float64 coercion into
/// scientific notation. A bare byte integer is still accepted for
/// backward shape. Malformed values surface as
/// [`ConfigError::InvalidValue`].
fn parse_metadata_blob_max_bytes() -> Result<usize, ConfigError> {
    const DEFAULT: u64 = 10 * 1024 * 1024;
    // Floor of 0 — `0` is the documented "accept anything" escape hatch,
    // so this cap (unlike the upstream backstops) must permit it.
    parse_byte_size_env("HORT_METADATA_BLOB_MAX_SIZE", DEFAULT, 0).map(|b| b as usize)
}

/// Scan the process environment for `METADATA_CAP_BYTES_<FORMAT>` entries
/// and build the operator-override map. Any matching variable with a
/// non-empty value must parse as `usize`; empty values are ignored so
/// deployments can set a variable without a value to revert to defaults.
///
/// Returns an empty map if no matching vars are set — the `IngestUseCase`
/// falls through to handler-declared defaults per format.
fn parse_metadata_caps() -> Result<HashMap<String, usize>, ConfigError> {
    const PREFIX: &str = "METADATA_CAP_BYTES_";
    // Collect names first so iteration order is stable in tests and so
    // we are not holding an iterator over `std::env::vars` while parsing.
    let raw: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k.starts_with(PREFIX))
        .collect();
    let mut out = HashMap::new();
    for (key, value) in raw {
        if value.is_empty() {
            continue;
        }
        // `METADATA_CAP_BYTES_PYPI` → `pypi`. The suffix is
        // case-insensitive from the operator's perspective — env vars
        // are conventionally uppercase, but format keys are lowercase.
        let suffix = key[PREFIX.len()..].to_ascii_lowercase();
        if suffix.is_empty() {
            // `METADATA_CAP_BYTES_` alone is not a valid per-format
            // override; skip silently rather than failing startup.
            continue;
        }
        let bytes: usize =
            value
                .parse()
                .map_err(|source: ParseIntError| ConfigError::InvalidInt {
                    // Store a 'static reference — required by ConfigError.
                    // This is a rare failure path and we accept the leak:
                    // the bounded set of format keys means at most one
                    // leak per process before exit.
                    var: leak_static(key.clone()),
                    source,
                })?;
        out.insert(suffix, bytes);
    }
    Ok(out)
}

/// Leak a `String` into a `&'static str`. Used only to carry the
/// offending env-var name through [`ConfigError::InvalidInt`]'s
/// `&'static str` field. Called at most once per failing env var during
/// startup; the process aborts immediately after, so the leak is
/// bounded.
fn leak_static(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn require(var: &'static str) -> Result<String, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(var)),
    }
}

fn env_or(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_string(),
    }
}

fn parse_bool(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v
            .parse::<bool>()
            .map_err(|source| ConfigError::InvalidBool { var, source }),
        _ => Ok(default),
    }
}

fn parse_log_format() -> Result<LogFormat, ConfigError> {
    match std::env::var("HORT_LOG_FORMAT") {
        Ok(v) if !v.is_empty() => match v.to_lowercase().as_str() {
            "pretty" => Ok(LogFormat::Pretty),
            "json" => Ok(LogFormat::Json),
            _ => Err(ConfigError::InvalidLogFormat {
                var: "HORT_LOG_FORMAT",
                got: v,
            }),
        },
        _ => Ok(LogFormat::Pretty),
    }
}

/// Parse the AWS region for the S3 storage backend.
///
/// Reads `AWS_REGION` (newer AWS SDK convention) first, then falls back
/// to `AWS_DEFAULT_REGION` (older awscli convention). Either name is
/// accepted because operators arrive from both ecosystems and both are
/// canonical in the AWS world. Both unset → [`ConfigError::Missing`]
/// naming `AWS_REGION` so the error points operators at the preferred
/// modern name.
fn parse_aws_region() -> Result<String, ConfigError> {
    for var in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
    }
    Err(ConfigError::Missing("AWS_REGION"))
}

/// Parse the S3 endpoint URL for non-AWS backends (Garage, MinIO, etc.).
///
/// Reads `AWS_ENDPOINT_URL_S3` (service-specific override, AWS SDK
/// convention) first, then falls back to `AWS_ENDPOINT_URL` (cross-
/// service default). `None` means no override — the S3 builder
/// addresses AWS S3 directly. Precedence matches what the AWS SDK and
/// boto3 implement: service-specific wins over cross-service.
fn parse_aws_s3_endpoint() -> Option<String> {
    for var in ["AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Parse `HORT_STORAGE_S3_ALLOW_HTTP` and cross-check it against the
/// endpoint's scheme.
///
/// The rust `object_store` crate refuses HTTP S3 endpoints unless
/// `with_allow_http(true)` is called on the builder. Operators running
/// Garage or MinIO inside a trusted cluster network need that opt-in;
/// operators talking to real AWS S3 (HTTPS) never do.
///
/// Three error paths catch typos that would otherwise silently bypass
/// the operator's intent:
///
///   - `endpoint` scheme is `http://` but the flag is unset → fail with
///     a message naming the flag and reminding the operator that HTTP
///     S3 should never be used over the public internet.
///   - flag is set but endpoint scheme is `https://` → fail; the
///     redundant flag suggests a misunderstanding.
///   - flag is set but no endpoint is configured (real AWS S3) → fail;
///     real AWS S3 is HTTPS-only and the flag has no effect there.
fn parse_aws_s3_allow_http_with_endpoint_check(
    endpoint: Option<&str>,
) -> Result<bool, ConfigError> {
    let allow_http = parse_bool("HORT_STORAGE_S3_ALLOW_HTTP", false)?;
    match (endpoint, allow_http) {
        (Some(ep), false) if ep.starts_with("http://") => Err(ConfigError::InvalidValue {
            var: "HORT_STORAGE_S3_ALLOW_HTTP",
            reason: format!(
                "endpoint is http:// but HORT_STORAGE_S3_ALLOW_HTTP not set; \
                 set HORT_STORAGE_S3_ALLOW_HTTP=true to opt in to plain HTTP S3 \
                 (acceptable on a trusted in-cluster network; never on the \
                 public internet). endpoint={ep:?}"
            ),
        }),
        (Some(ep), true) if ep.starts_with("https://") => Err(ConfigError::InvalidValue {
            var: "HORT_STORAGE_S3_ALLOW_HTTP",
            reason: format!(
                "HORT_STORAGE_S3_ALLOW_HTTP=true but endpoint scheme is https://; \
                 remove the flag — TLS endpoints don't need the opt-in. \
                 endpoint={ep:?}"
            ),
        }),
        (None, true) => Err(ConfigError::InvalidValue {
            var: "HORT_STORAGE_S3_ALLOW_HTTP",
            reason: "HORT_STORAGE_S3_ALLOW_HTTP=true but no endpoint set \
                     (real AWS S3 always uses HTTPS); remove the flag"
                .to_string(),
        }),
        _ => Ok(allow_http),
    }
}

/// Parse `HORT_S3_SSE_MODE` and (when applicable) `HORT_S3_SSE_KMS_KEY_ARN`.
///
/// The wire values mirror the operator-
/// facing semantics:
///
///   - unset (or empty) ⇒ `None`. The adapter sends no SSE opinion and
///     the bucket-default applies. AWS S3 has applied SSE-S3
///     unconditionally since 2023; for non-AWS S3-compatibles the
///     storage adapter additionally emits a startup WARN.
///   - `bucket-default` ⇒ explicit no-opinion. Equivalent to unset at
///     the wire level but documents intent.
///   - `sse256` ⇒ SSE-S3 (AES256 with AWS-managed keys).
///   - `sse-kms` ⇒ SSE-KMS. `HORT_S3_SSE_KMS_KEY_ARN` MUST be set; we
///     refuse to start otherwise so a misconfiguration can't silently
///     downgrade to no-opinion.
fn parse_s3_sse_mode() -> Result<Option<S3SseMode>, ConfigError> {
    let raw = match std::env::var("HORT_S3_SSE_MODE") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    match raw.to_lowercase().as_str() {
        "bucket-default" => Ok(Some(S3SseMode::BucketDefault)),
        "sse256" => Ok(Some(S3SseMode::Sse256)),
        "sse-kms" => {
            let key_arn =
                require("HORT_S3_SSE_KMS_KEY_ARN").map_err(|_| ConfigError::InvalidValue {
                    var: "HORT_S3_SSE_MODE",
                    reason: "HORT_S3_SSE_MODE=sse-kms requires HORT_S3_SSE_KMS_KEY_ARN \
                         to be set to the full KMS key ARN \
                         (e.g. arn:aws:kms:us-east-1:123456789012:key/abcd-1234-...). \
                         Refusing to start so a misconfiguration can't silently \
                         downgrade to no-opinion."
                        .to_string(),
                })?;
            Ok(Some(S3SseMode::SseKms { key_arn }))
        }
        other => Err(ConfigError::InvalidValue {
            var: "HORT_S3_SSE_MODE",
            reason: format!("expected one of [bucket-default, sse256, sse-kms], got {other:?}"),
        }),
    }
}

/// Parse `HORT_CAS_SCRUB_ACTION_ON_MISMATCH`.
///
/// Defaults to [`ActionOnMismatch::Alert`] when unset or empty. Empty
/// string is deliberately treated the same as unset to guard against
/// k8s ConfigMap defaults / shell `export VAR=` accidentally flipping
/// the deploy-time posture. Case-insensitive on the wire form (so
/// `Tombstone`, `TOMBSTONE`, `tombstone` all parse identically).
fn parse_cas_scrub_action_on_mismatch(
) -> Result<hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch, ConfigError> {
    use hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch;
    const VAR: &str = "HORT_CAS_SCRUB_ACTION_ON_MISMATCH";
    let Ok(raw) = std::env::var(VAR) else {
        return Ok(ActionOnMismatch::Alert);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "alert" => Ok(ActionOnMismatch::Alert),
        "tombstone" => Ok(ActionOnMismatch::Tombstone),
        other => Err(ConfigError::InvalidValue {
            var: VAR,
            reason: format!("expected one of [alert, tombstone], got {other:?}"),
        }),
    }
}

fn parse_storage() -> Result<StorageConfig, ConfigError> {
    let backend = env_or("HORT_STORAGE_BACKEND", "filesystem");
    match backend.to_lowercase().as_str() {
        "filesystem" => {
            let root = require("HORT_STORAGE_FILESYSTEM_PATH")?;
            Ok(StorageConfig::Filesystem {
                root: PathBuf::from(root),
            })
        }
        "s3" => {
            let endpoint = parse_aws_s3_endpoint();
            let allow_http = parse_aws_s3_allow_http_with_endpoint_check(endpoint.as_deref())?;
            let sse_mode = parse_s3_sse_mode()?;
            Ok(StorageConfig::S3 {
                bucket: require("HORT_STORAGE_S3_BUCKET")?,
                region: parse_aws_region()?,
                endpoint,
                force_path_style: parse_bool("HORT_STORAGE_S3_FORCE_PATH_STYLE", false)?,
                allow_http,
                access_key_id: require("AWS_ACCESS_KEY_ID")?,
                secret_access_key: require("AWS_SECRET_ACCESS_KEY")?,
                sse_mode,
            })
        }
        _ => Err(ConfigError::InvalidStorageBackend {
            var: "HORT_STORAGE_BACKEND",
            got: backend,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Byte-size string parsing ------------------------------------------

    #[test]
    fn parse_byte_size_bare_integer_is_bytes() {
        assert_eq!(parse_byte_size("67108864").unwrap(), 67108864);
        assert_eq!(parse_byte_size("0").unwrap(), 0);
        assert_eq!(parse_byte_size("  1024  ").unwrap(), 1024);
    }

    #[test]
    fn parse_byte_size_binary_suffixes() {
        assert_eq!(parse_byte_size("512Ki").unwrap(), 512 * 1024);
        assert_eq!(parse_byte_size("64Mi").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_byte_size("16Mi").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_byte_size("2Mi").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_size("1Gi").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_byte_size_decimal_suffixes() {
        assert_eq!(parse_byte_size("64k").unwrap(), 64_000);
        assert_eq!(parse_byte_size("64M").unwrap(), 64_000_000);
        assert_eq!(parse_byte_size("1G").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parse_byte_size_tolerates_trailing_b_and_is_case_insensitive() {
        // `64MiB` == `64Mi`, `64MB` == `64M`; `m` means mega, never milli.
        assert_eq!(parse_byte_size("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_byte_size("64mi").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_byte_size("64MB").unwrap(), 64_000_000);
        assert_eq!(parse_byte_size("64m").unwrap(), 64_000_000);
    }

    #[test]
    fn parse_byte_size_fractional_magnitude_rounds() {
        assert_eq!(parse_byte_size("1.5Gi").unwrap(), 1_610_612_736);
    }

    #[test]
    fn parse_byte_size_large_size_strings_are_exact() {
        // Operator byte caps are size strings, not bare ints, precisely
        // so a multi-GiB value survives. A small magnitude times a
        // power-of-two multiplier is exactly representable, so the cap
        // round-trips to the byte count an operator expects.
        assert_eq!(parse_byte_size("256Mi").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_byte_size("8Gi").unwrap(), 8_u64 * 1024 * 1024 * 1024);
        assert_eq!(parse_byte_size("10Mi").unwrap(), 10 * 1024 * 1024);
    }

    #[test]
    fn parse_byte_size_size_string_path_beats_float64_overflow() {
        // This is the rc.3 crash class the size-string surface closes.
        // A bare integer above 2^53 (the largest exactly-representable
        // f64 integer) loses precision when Helm loads values as float64
        // — 9007199254740993 stringifies as 9.007199254740992e15, which
        // the binary's parser would reject or mis-read. Expressed as a
        // size string, the same magnitude class stays exact because the
        // small leading magnitude (e.g. `8`) is multiplied by an exact
        // power-of-two multiplier rather than carried as one giant float.
        let exact_via_size_string = parse_byte_size("8Gi").unwrap();
        assert_eq!(exact_via_size_string, 8_589_934_592);
        // Prove the danger we are avoiding: the equivalent raw byte count
        // *just above* 2^53 cannot survive an f64 round-trip, whereas the
        // size-string form for any realistic operator cap does.
        let above_2pow53: u64 = 9_007_199_254_740_993;
        assert_ne!(above_2pow53 as f64 as u64, above_2pow53);
        // A realistic multi-GiB cap as a size string is byte-exact.
        assert_eq!(
            parse_byte_size("64Gi").unwrap(),
            64_u64 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_byte_size_rejects_garbage() {
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("abc").is_err());
        assert!(parse_byte_size("64Xi").is_err());
        assert!(parse_byte_size("-5Mi").is_err());
    }

    #[test]
    fn parse_byte_size_env_default_min_and_parse() {
        // Unique var name so the global-env touch can't collide with a
        // concurrently-running test.
        const VAR: &str = "HORT_TEST_PARSE_BYTE_SIZE_ENV_RC4";
        std::env::remove_var(VAR);
        assert_eq!(
            parse_byte_size_env(VAR, 64 * 1024 * 1024, 1024).unwrap(),
            64 * 1024 * 1024
        );

        std::env::set_var(VAR, "32Mi");
        assert_eq!(
            parse_byte_size_env(VAR, 64 * 1024 * 1024, 1024).unwrap(),
            32 * 1024 * 1024
        );

        std::env::set_var(VAR, "512"); // below the 1024 floor
        assert!(parse_byte_size_env(VAR, 64 * 1024 * 1024, 1024).is_err());

        std::env::set_var(VAR, "not-a-size");
        assert!(parse_byte_size_env(VAR, 64 * 1024 * 1024, 1024).is_err());

        std::env::remove_var(VAR);
    }

    // -- Debug-redaction regression tests ----------------------------------
    //
    // `StorageConfig::S3` carries AWS credentials. The struct must NOT
    // surface them through `Debug` — any `{:?}` expansion (panic messages,
    // `.unwrap()` failures, ad-hoc tracing) would otherwise leak the keys
    // into logs or crash dumps. See the security audit 015.

    const SENSITIVE_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SENSITIVE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn s3_config_with_sensitive_creds() -> StorageConfig {
        StorageConfig::S3 {
            bucket: "my-bucket".into(),
            region: "us-east-1".into(),
            endpoint: None,
            force_path_style: false,
            allow_http: false,
            access_key_id: SENSITIVE_ACCESS_KEY.into(),
            secret_access_key: SENSITIVE_SECRET_KEY.into(),
            sse_mode: None,
        }
    }

    #[test]
    fn storage_config_debug_does_not_leak_access_key_id() {
        let cfg = s3_config_with_sensitive_creds();
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_ACCESS_KEY),
            "Debug impl leaked access_key_id: {debug_repr}"
        );
    }

    #[test]
    fn storage_config_debug_does_not_leak_secret_access_key() {
        let cfg = s3_config_with_sensitive_creds();
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_SECRET_KEY),
            "Debug impl leaked secret_access_key: {debug_repr}"
        );
    }

    #[test]
    fn storage_config_debug_still_shows_non_secret_fields() {
        // The redaction should not swallow harmless diagnostic info —
        // operators need bucket / region in logs to spot misconfiguration.
        let cfg = s3_config_with_sensitive_creds();
        let debug_repr = format!("{cfg:?}");
        assert!(debug_repr.contains("my-bucket"));
        assert!(debug_repr.contains("us-east-1"));
    }

    #[test]
    fn config_debug_does_not_leak_s3_credentials() {
        // Full `Config` wraps `StorageConfig`; the redaction must survive
        // the wrapping `Debug` derive.
        let cfg = Config {
            database_url: "postgres://x/y".into(),
            storage: s3_config_with_sensitive_creds(),
            api_bind_addr: "0.0.0.0:8080".parse().unwrap(),
            require_https: false,
            metrics_bind_addr: None,
            // Defaults match production
            // posture (auth required, public-bind opt-out off).
            metrics_require_auth: true,
            metrics_public_bind: false,
            control_bind_addr: None,
            control_public_bind: false,
            log_format: LogFormat::Pretty,
            include_repository_label: true,
            include_service_account_label: true,
            metadata_caps: HashMap::new(),
            metadata_blob_max_bytes: 10 * 1024 * 1024,
            public_base_url: None,
            trusted_proxy_cidrs: Vec::new(),
            auth: AuthConfig::Disabled,
            claim_mappings: Vec::new(),
            publish_body_limit_bytes: None,
            pg_statement_timeout_ms: None,
            pg_acquire_timeout_secs: 30,
            jwks_eviction_backoff_secs: 10,
            jwks_resp_body_max_bytes: 1024 * 1024,
            ratelimit_auth_per_min: 60,
            ratelimit_write_per_min: 300,
            max_inflight: 512,
            max_inflight_per_ip: 32,
            rbac_refresh_secs: 30,
            event_chain_checkpoint_cadence_secs: 3600,
            stateful_upload_staging_dir: PathBuf::from("/tmp/hort-stateful-upload-staging"),
            oci_legacy_catalog_enabled: false,
            oci_max_sessions_per_principal: 32,
            ephemeral_store_backend: EphemeralStoreBackend::Memory,
            redis_url: None,
            // Per-class overrides default to None
            // (Memory backend never reads them; the redaction test
            // below seeds them via direct field assignment).
            redis_url_evictable: None,
            redis_url_durable: None,
            upstream_resolver_refresh_secs: 60,
            upstream_metadata_cache_max_bytes: 64 * 1024 * 1024,
            upstream_manifest_cache_max_bytes: 16 * 1024 * 1024,
            upstream_projector_version_object_max_bytes: 2 * 1024 * 1024,
            config_dir: None,
            http_header_read_timeout_secs: 15,
            http_request_timeout_secs: 300,
            http_oci_upload_timeout_secs: 3600,
            // Pull-through dedup defaults match the `from_env` parser
            // defaults.
            pull_dedup_ttl_not_found_secs: 30,
            pull_dedup_ttl_unavailable_secs: 10,
            pull_dedup_ttl_timeout_secs: 10,
            pull_dedup_ttl_checksum_mismatch_secs: 60,
            pull_dedup_follower_wait_secs: 300,
            shutdown_grace_secs: 60,
            upstream_allowlist:
                hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist::Disabled,
            cas_scrub_action_on_mismatch:
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Alert,
            // Defaults match `from_env` parser
            // defaults: feature flag off, plaintext-PAT refused.
            enable_native_tokens: false,
            // Substrate on by default; capacity 1024.
            enable_notifications: true,
            notify_channel_capacity: 1024,
            // Webhook transport + SSRF defaults: both
            // refused (force https, refuse RFC1918). NATS off.
            allow_plaintext_webhooks: false,
            allow_nonroutable_webhook_targets: false,
            nats_url: None,
            allow_pat_over_http: false,
            pat_cache_size: 10_000,
            pat_lockout_threshold: 30,
            pat_lockout_window_secs: 300,
            pat_lockout_duration_secs: 900,
            // Defaults: admin tokens off, unbounded service-account
            // tokens off.
            allow_admin_tokens: false,
            allow_unbounded_svc_tokens: false,
            // Token-exchange feature off by default.
            enable_token_exchange: false,
            // Fixtures pin the binary's fresh-install
            // default (`true`). Tests that exercise the upgrade
            // opt-out override this field explicitly.
            refcount_reconcile_on_startup: true,
            // Fixtures default to no signing key wired
            // (matches `enable_native_tokens=false` baseline).
            oci_token_signing_key_pem: None,
            oci_token_signing_key_prev_pem: None,
            audit_retention_floors: AuditRetentionFloors::c1_defaults(),
            retention_stream_mode: StreamRetentionMode::Delete,
        };
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_ACCESS_KEY),
            "Config Debug leaked access_key_id: {debug_repr}"
        );
        assert!(
            !debug_repr.contains(SENSITIVE_SECRET_KEY),
            "Config Debug leaked secret_access_key: {debug_repr}"
        );
    }

    // -- Config secret redaction --------------------------------------------
    //
    // `database_url` and `redis_url` are DSN-bearing fields with passwords
    // embedded inline (e.g. `postgres://user:pw@host/db`). A bare
    // `derive(Debug)` would leak them through any `{:?}` expansion — panic
    // messages, `.unwrap()` failures, ad-hoc tracing of the boot config.
    // The hand-rolled `Debug` impl substitutes `<redacted>` for these
    // fields while preserving every benign field so `?cfg` retains its
    // diagnostic value (operator can still see bind addrs, timeouts, etc).

    const SENSITIVE_DATABASE_PASSWORD: &str = "supersecretpgpw";
    const SENSITIVE_REDIS_PASSWORD: &str = "supersecretredispw";

    fn cfg_with_sensitive_dsns() -> Config {
        Config {
            database_url: format!("postgres://user:{SENSITIVE_DATABASE_PASSWORD}@localhost/db"),
            storage: StorageConfig::Filesystem {
                root: PathBuf::from("/tmp/hort-test"),
            },
            api_bind_addr: "127.0.0.1:8080".parse().unwrap(),
            require_https: true,
            metrics_bind_addr: Some("127.0.0.1:9090".parse().unwrap()),
            metrics_require_auth: true,
            metrics_public_bind: false,
            control_bind_addr: None,
            control_public_bind: false,
            log_format: LogFormat::Pretty,
            include_repository_label: true,
            include_service_account_label: true,
            metadata_caps: HashMap::new(),
            metadata_blob_max_bytes: 10 * 1024 * 1024,
            public_base_url: None,
            trusted_proxy_cidrs: Vec::new(),
            auth: AuthConfig::Disabled,
            claim_mappings: Vec::new(),
            publish_body_limit_bytes: None,
            pg_statement_timeout_ms: None,
            pg_acquire_timeout_secs: 30,
            jwks_eviction_backoff_secs: 10,
            jwks_resp_body_max_bytes: 1024 * 1024,
            ratelimit_auth_per_min: 60,
            ratelimit_write_per_min: 300,
            max_inflight: 512,
            max_inflight_per_ip: 32,
            rbac_refresh_secs: 30,
            event_chain_checkpoint_cadence_secs: 3600,
            stateful_upload_staging_dir: PathBuf::from("/tmp/hort-stateful-upload-staging"),
            oci_legacy_catalog_enabled: false,
            oci_max_sessions_per_principal: 32,
            ephemeral_store_backend: EphemeralStoreBackend::Redis,
            redis_url: Some(format!(
                "redis://user:{SENSITIVE_REDIS_PASSWORD}@localhost:6379/0"
            )),
            // Per-class overrides default to None
            // in the shared fixture; the per-field redaction tests
            // populate them with their own sensitive constants.
            redis_url_evictable: None,
            redis_url_durable: None,
            upstream_resolver_refresh_secs: 60,
            upstream_metadata_cache_max_bytes: 64 * 1024 * 1024,
            upstream_manifest_cache_max_bytes: 16 * 1024 * 1024,
            upstream_projector_version_object_max_bytes: 2 * 1024 * 1024,
            config_dir: None,
            http_header_read_timeout_secs: 15,
            http_request_timeout_secs: 300,
            http_oci_upload_timeout_secs: 3600,
            // Pull-through dedup defaults match the `from_env` parser
            // defaults.
            pull_dedup_ttl_not_found_secs: 30,
            pull_dedup_ttl_unavailable_secs: 10,
            pull_dedup_ttl_timeout_secs: 10,
            pull_dedup_ttl_checksum_mismatch_secs: 60,
            pull_dedup_follower_wait_secs: 300,
            shutdown_grace_secs: 60,
            upstream_allowlist:
                hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist::Disabled,
            cas_scrub_action_on_mismatch:
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Alert,
            // RC defaults: feature off, plaintext-PAT refused.
            enable_native_tokens: false,
            // Substrate on by default; capacity 1024.
            enable_notifications: true,
            notify_channel_capacity: 1024,
            // Webhook transport + SSRF defaults: both
            // refused (force https, refuse RFC1918). NATS off.
            allow_plaintext_webhooks: false,
            allow_nonroutable_webhook_targets: false,
            nats_url: None,
            allow_pat_over_http: false,
            pat_cache_size: 10_000,
            pat_lockout_threshold: 30,
            pat_lockout_window_secs: 300,
            pat_lockout_duration_secs: 900,
            // Defaults: admin tokens off, unbounded service-account
            // tokens off.
            allow_admin_tokens: false,
            allow_unbounded_svc_tokens: false,
            // Token-exchange feature off by default.
            enable_token_exchange: false,
            // Fixtures pin the binary's fresh-install
            // default (`true`). Tests that exercise the upgrade
            // opt-out override this field explicitly.
            refcount_reconcile_on_startup: true,
            // Fixture defaults: no signing key wired
            // (matches `enable_native_tokens=false` baseline).
            oci_token_signing_key_pem: None,
            oci_token_signing_key_prev_pem: None,
            audit_retention_floors: AuditRetentionFloors::c1_defaults(),
            retention_stream_mode: StreamRetentionMode::Delete,
        }
    }

    #[test]
    fn config_debug_does_not_leak_database_url() {
        let cfg = cfg_with_sensitive_dsns();
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_DATABASE_PASSWORD),
            "Config Debug leaked database_url password: {debug_repr}"
        );
        assert!(
            debug_repr.contains("<redacted>"),
            "Config Debug missing `<redacted>` placeholder: {debug_repr}"
        );
    }

    #[test]
    fn config_debug_does_not_leak_redis_url() {
        let cfg = cfg_with_sensitive_dsns();
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_REDIS_PASSWORD),
            "Config Debug leaked redis_url password: {debug_repr}"
        );
        assert!(
            debug_repr.contains("<redacted>"),
            "Config Debug missing `<redacted>` placeholder: {debug_repr}"
        );
    }

    // -- Per-class Redis URL overrides -------------------------------------
    //
    // `redis_url_evictable` and `redis_url_durable` are optional per-class
    // overrides that — at composition time — fall back to `redis_url` when
    // unset. Both are DSN-bearing (passwords inline) so the manual `Debug`
    // impl must redact them with the same `<redacted>` placeholder used
    // for `redis_url`. Empty string in the env var is treated as unset
    // (matches the `parse_secret_env` empty-as-None pattern).

    const SENSITIVE_REDIS_EVICTABLE_PASSWORD: &str = "supersecretevictablepw";
    const SENSITIVE_REDIS_DURABLE_PASSWORD: &str = "supersecretdurablepw";

    #[test]
    fn config_debug_does_not_leak_redis_url_evictable() {
        let mut cfg = cfg_with_sensitive_dsns();
        cfg.redis_url_evictable = Some(format!(
            "redis://user:{SENSITIVE_REDIS_EVICTABLE_PASSWORD}@evictable.example:6379/0"
        ));
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_REDIS_EVICTABLE_PASSWORD),
            "Config Debug leaked redis_url_evictable password: {debug_repr}"
        );
        assert!(
            debug_repr.contains("<redacted>"),
            "Config Debug missing `<redacted>` placeholder: {debug_repr}"
        );
    }

    #[test]
    fn config_debug_does_not_leak_redis_url_durable() {
        let mut cfg = cfg_with_sensitive_dsns();
        cfg.redis_url_durable = Some(format!(
            "redis://user:{SENSITIVE_REDIS_DURABLE_PASSWORD}@durable.example:6379/0"
        ));
        let debug_repr = format!("{cfg:?}");
        assert!(
            !debug_repr.contains(SENSITIVE_REDIS_DURABLE_PASSWORD),
            "Config Debug leaked redis_url_durable password: {debug_repr}"
        );
        assert!(
            debug_repr.contains("<redacted>"),
            "Config Debug missing `<redacted>` placeholder: {debug_repr}"
        );
    }

    #[test]
    fn redis_url_per_class_overrides_unset_when_all_redis_vars_unset() {
        // Memory backend, no Redis env vars set → both per-class
        // overrides are `None`. The Memory branch must not require
        // `HORT_REDIS_URL_EVICTABLE` / `HORT_REDIS_URL_DURABLE`.
        let env = fs_env();
        // Default `fs_env` already has all three Redis slots = None and
        // `HORT_EPHEMERAL_STORE_BACKEND` unset (→ Memory), but be explicit
        // so a future fixture-default change doesn't silently neuter
        // this test.
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().expect("memory backend with no Redis vars parses");
            assert_eq!(cfg.redis_url, None);
            assert_eq!(cfg.redis_url_evictable, None);
            assert_eq!(cfg.redis_url_durable, None);
        });
    }

    #[test]
    fn redis_url_evictable_only_set_under_memory_backend_parses() {
        // Parsing of the per-class fields is NOT gated
        // by `HORT_EPHEMERAL_STORE_BACKEND`. Setting only the evictable
        // override under the Memory backend must succeed and populate
        // `redis_url_evictable` independently.
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_REDIS_URL_EVICTABLE",
            Some("redis://evictable.example:6379/0"),
        );
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().expect("memory backend + evictable override parses");
            assert_eq!(
                cfg.redis_url_evictable.as_deref(),
                Some("redis://evictable.example:6379/0")
            );
            assert_eq!(cfg.redis_url_durable, None);
        });
    }

    #[test]
    fn redis_url_per_class_all_three_set_populate_independently() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_EPHEMERAL_STORE_BACKEND", Some("redis"));
        set_env_slot(
            &mut env,
            "HORT_REDIS_URL",
            Some("redis://main.example:6379/0"),
        );
        set_env_slot(
            &mut env,
            "HORT_REDIS_URL_EVICTABLE",
            Some("redis://evictable.example:6379/0"),
        );
        set_env_slot(
            &mut env,
            "HORT_REDIS_URL_DURABLE",
            Some("redis://durable.example:6379/0"),
        );
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().expect("redis backend with all three URLs parses");
            assert_eq!(
                cfg.redis_url.as_deref(),
                Some("redis://main.example:6379/0")
            );
            assert_eq!(
                cfg.redis_url_evictable.as_deref(),
                Some("redis://evictable.example:6379/0")
            );
            assert_eq!(
                cfg.redis_url_durable.as_deref(),
                Some("redis://durable.example:6379/0")
            );
        });
    }

    #[test]
    fn redis_url_per_class_empty_string_is_unset() {
        // `HORT_REDIS_URL_EVICTABLE=""` must surface as `None` (not
        // `Some("")`) — same empty-as-None semantics as
        // `parse_secret_env`. This protects against a Helm chart that
        // emits an empty `value:` when the override is left blank.
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_REDIS_URL_EVICTABLE", Some(""));
        set_env_slot(&mut env, "HORT_REDIS_URL_DURABLE", Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().expect("empty per-class overrides parse as unset");
            assert_eq!(cfg.redis_url_evictable, None);
            assert_eq!(cfg.redis_url_durable, None);
        });
    }

    #[test]
    fn config_debug_preserves_non_secret_fields() {
        // Cry-wolf guard: a future refactor that accidentally redacts
        // everything would defeat the purpose of `?cfg` for operators.
        // Spot-check a representative slice of benign fields covering
        // the key hardening additions (require_https, metrics_*)
        // plus the always-present diagnostic fields.
        let cfg = cfg_with_sensitive_dsns();
        let debug_repr = format!("{cfg:?}");
        assert!(
            debug_repr.contains("127.0.0.1:8080"),
            "Config Debug dropped api_bind_addr: {debug_repr}"
        );
        assert!(
            debug_repr.contains("127.0.0.1:9090"),
            "Config Debug dropped metrics_bind_addr: {debug_repr}"
        );
        assert!(
            debug_repr.contains("require_https"),
            "Config Debug dropped require_https field name: {debug_repr}"
        );
        assert!(
            debug_repr.contains("metrics_require_auth"),
            "Config Debug dropped metrics_require_auth field name: {debug_repr}"
        );
    }

    /// Minimal valid env for filesystem backend. Individual tests call
    /// `temp_env::with_vars` to override specific keys.
    fn fs_env() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("filesystem")),
            ("HORT_STORAGE_FILESYSTEM_PATH", Some("/tmp/hort-test")),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_STORAGE_S3_BUCKET", None),
            ("AWS_REGION", None),
            ("AWS_ENDPOINT_URL_S3", None),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("HORT_STORAGE_S3_ALLOW_HTTP", None),
            ("AWS_ACCESS_KEY_ID", None),
            ("AWS_SECRET_ACCESS_KEY", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            // Auth-provider vars — must stay BEFORE the
            // `HORT_PUBLIC_BASE_URL` slot so the existing
            // `public_base_url_*` tests that write via
            // `env.last_mut()` continue to hit their target.
            ("HORT_AUTH_PROVIDER", None),
            ("HORT_OIDC_ISSUER_URL", None),
            ("HORT_OIDC_AUDIENCE", None),
            ("HORT_OIDC_GROUPS_CLAIM", None),
            ("HORT_JWKS_CACHE_TTL_SECS", None),
            // The legacy loader is gone; the slot is
            // kept here as test-environment hygiene (so a developer's
            // shell var doesn't leak into the test) and to back the
            // `legacy_hort_group_mappings_path_env_var_is_a_no_op` regression
            // test that overrides the slot to verify nothing reads it.
            ("HORT_GROUP_MAPPINGS_PATH", None),
            // Trust configuration is required at
            // startup. `fs_env` defaults `HORT_PUBLIC_BASE_URL` to a
            // concrete URL so existing tests don't trip on
            // `ConfigError::TrustUnconfigured`. Tests that need the
            // unset case override this slot explicitly via
            // `env.last_mut()` or by constructing a fresh env slice.
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
            // Operator override of the shared
            // publish body-size ceiling. Absent in the default test
            // env so `publish_body_limit_bytes` falls through to
            // `None` (route builders use `DEFAULT_PUBLISH_BODY_LIMIT`).
            ("HORT_PUBLISH_BODY_MAX_SIZE", None),
            // Postgres pool timeouts. Both slots
            // absent in the default test env: `PG_STATEMENT_TIMEOUT_MS`
            // falls through to `None` (no session-level timeout set),
            // `PG_ACQUIRE_TIMEOUT_SECS` falls through to the 30 s
            // default. Tests that exercise other values override these
            // slots explicitly via `set_pg_statement_timeout_ms` /
            // `set_pg_acquire_timeout_secs`.
            ("PG_STATEMENT_TIMEOUT_MS", None),
            ("PG_ACQUIRE_TIMEOUT_SECS", None),
            // JWKS resilience knobs. Both slots
            // absent in the default test env so they fall through to
            // their documented defaults (10 s backoff, 1 MiB body cap).
            // Tests that exercise other values override these slots
            // explicitly via `set_jwks_eviction_backoff_secs` /
            // `set_jwks_resp_body_max_bytes`.
            ("HORT_JWKS_EVICTION_BACKOFF_SECS", None),
            ("HORT_JWKS_RESP_BODY_MAX_SIZE", None),
            // Per-IP rate-limit caps. Absent in
            // the default test env so they fall through to 60 /
            // 300 requests per minute. Tests override via
            // `set_ratelimit_auth_per_min` / `set_ratelimit_write_per_min`.
            ("HORT_RATELIMIT_AUTH_PER_MIN", None),
            ("HORT_RATELIMIT_WRITE_PER_MIN", None),
            // Concurrency caps. Absent in the
            // default test env so they fall through to 512 (workspace)
            // and 32 (per-IP). Tests override via `set_max_inflight` /
            // `set_max_inflight_per_ip`.
            ("HORT_MAX_INFLIGHT", None),
            ("HORT_MAX_INFLIGHT_PER_IP", None),
            // RBAC poll cadence. Absent in the
            // default test env so `rbac_refresh_secs` falls through to
            // the 30 s default. Tests override via
            // `set_rbac_refresh_secs`.
            ("HORT_RBAC_REFRESH_SECS", None),
            // Verify-event-chain anchor
            // staleness cadence. Absent in the default test env so
            // `event_chain_checkpoint_cadence_secs` falls through to the
            // hourly (3600) default. Tests override via
            // `set_event_chain_checkpoint_cadence_secs`.
            ("HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS", None),
            // Stateful-upload staging root. Absent in the default test
            // env so `stateful_upload_staging_dir` falls through to
            // `<HORT_STORAGE_FILESYSTEM_PATH>/stateful-upload-staging` (filesystem
            // backend) or the fixed S3 fallback. Tests that need a
            // concrete override set this slot explicitly.
            ("HORT_STATEFUL_UPLOAD_STAGING_DIR", None),
            // EphemeralStore backend. Absent
            // in the default test env so the backend falls through to
            // `Memory`. Tests that need to exercise the Redis branch
            // set this slot and `HORT_REDIS_URL` together.
            ("HORT_EPHEMERAL_STORE_BACKEND", None),
            ("HORT_REDIS_URL", None),
            // Per-class Redis URL overrides.
            // Both slots absent in the default test env so they fall
            // through to `None` (the composition root will fall back
            // to `HORT_REDIS_URL` at construction time). Tests that
            // exercise the override paths set these slots explicitly
            // via `set_env_slot`.
            ("HORT_REDIS_URL_EVICTABLE", None),
            ("HORT_REDIS_URL_DURABLE", None),
            // Upstream-resolver refresh
            // cadence. Default test env leaves it unset → 60s
            // default.
            ("HORT_UPSTREAM_RESOLVER_REFRESH_SECS", None),
            // HTTP transport timeouts.
            // All three slots absent in the default test env so they
            // fall through to their documented defaults
            // (15s header read / 5min request / 60min OCI upload).
            // Tests override via `set_http_header_read_timeout_secs` /
            // `set_http_request_timeout_secs` /
            // `set_http_oci_upload_timeout_secs`.
            ("HORT_HTTP_HEADER_READ_TIMEOUT_SECS", None),
            ("HORT_HTTP_REQUEST_TIMEOUT_SECS", None),
            ("HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS", None),
            // Pull-through dedup TTL + follower-wait knobs.
            // Defaults: 30 / 10 / 10 / 60 secs negative-cache TTL
            // spread; 300s follower wait ceiling. Unset in default
            // test env, fall through to defaults.
            ("HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS", None),
            ("HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS", None),
            ("HORT_PULL_DEDUP_TTL_TIMEOUT_SECS", None),
            ("HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS", None),
            ("HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS", None),
            // Graceful-shutdown
            // wall-clock cap. Default test env leaves it unset → 60s
            // default (matches the prior hard-coded serve-loop
            // deadline).
            ("HORT_SHUTDOWN_GRACE_SECS", None),
            // `/metrics` lockdown flags.
            // Both slots absent in the default test env so they fall
            // through to their documented defaults (require auth,
            // refuse `0.0.0.0` bind). Tests that exercise the bypass
            // or the public-bind opt-in override these slots
            // explicitly.
            ("HORT_METRICS_REQUIRE_AUTH", None),
            ("HORT_METRICS_PUBLIC_BIND", None),
            // HTTPS-required gate.
            // Absent in the default test env so it falls through to
            // its documented default (`require_https = false` → no
            // startup gate). Tests that exercise the opt-in / opt-out
            // override the slot explicitly.
            ("HORT_REQUIRE_HTTPS", None),
            // Upstream allowlist tri-state.
            // Default test env leaves it unset → `Disabled`. The
            // dedicated `upstream_allowlist_*` tests below override
            // this slot to exercise the empty-string footgun guard,
            // the `__deny_all__` strict sentinel, and the host-list
            // path.
            ("HORT_UPSTREAM_ALLOWLIST_HOSTS", None),
            // Native API token surface flags. Default
            // test env leaves them unset → defaults (feature off,
            // plaintext-PAT refused, 10k cache, 30/5min/15min
            // lockout). The dedicated tests below override these
            // slots to exercise the opt-in path.
            ("HORT_NATIVE_TOKENS_ENABLED", None),
            ("HORT_BEARER_ALLOW_OVER_HTTP", None),
            ("HORT_PAT_CACHE_SIZE", None),
            ("HORT_PAT_LOCKOUT_THRESHOLD", None),
            ("HORT_PAT_LOCKOUT_WINDOW_SECS", None),
            ("HORT_PAT_LOCKOUT_DURATION_SECS", None),
            // Issuance flags. Default test env leaves
            // them unset → both defaults (admin tokens off, unbounded
            // service-account tokens off).
            ("HORT_TOKEN_ALLOW_ADMIN", None),
            ("HORT_TOKEN_ALLOW_UNBOUNDED_SVC", None),
            // Webhook transport + SSRF defaults left
            // unset → both `false`, no NATS adapter.
            ("HORT_WEBHOOK_ALLOW_PLAINTEXT", None),
            ("HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS", None),
            ("HORT_NATS_URL", None),
            // `HORT_DATABASE_URL` is the canonical DSN var (bare
            // `DATABASE_URL` at index 0 is the compat fallback).
            // Pinned to None here so a developer's shell `HORT_DATABASE_URL`
            // can't leak in and shadow the `DATABASE_URL` slot the
            // positional `missing_database_url`/`s3_*` tests drive. Kept LAST
            // so index 0 (`DATABASE_URL`) and index 1 (`HORT_STORAGE_BACKEND`)
            // stay stable for the `env[0]`/`env[1]` overrides below.
            ("HORT_DATABASE_URL", None),
        ]
    }

    #[test]
    fn filesystem_defaults() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.database_url, "postgres://x/y");
            match cfg.storage {
                StorageConfig::Filesystem { root } => {
                    assert_eq!(root, PathBuf::from("/tmp/hort-test"));
                }
                _ => panic!("expected filesystem"),
            }
            // Default API bind narrowed
            // from `0.0.0.0:8080` to `127.0.0.1:8080`. Operators who
            // need the listener reachable on every interface set
            // `HORT_API_BIND=0.0.0.0:8080` explicitly (the chart wires
            // this through its `api.bindAddr` value).
            assert_eq!(cfg.api_bind_addr.to_string(), "127.0.0.1:8080");
            assert!(!cfg.require_https);
            assert!(cfg.metrics_bind_addr.is_none());
            assert_eq!(cfg.log_format, LogFormat::Pretty);
            assert!(cfg.include_repository_label);
            assert_eq!(cfg.metadata_blob_max_bytes, 10 * 1024 * 1024);
            // `fs_env()` defaults `HORT_PUBLIC_BASE_URL` to a concrete URL
            // because the trust config is mandatory at startup.
            // The unset case is covered by
            // `trust_unconfigured_fails_startup` below.
            assert!(cfg.public_base_url.is_some());
            assert!(cfg.trusted_proxy_cidrs.is_empty());
        });
    }

    #[test]
    fn missing_database_url() {
        let mut env = fs_env();
        env[0] = ("DATABASE_URL", None);
        // `HORT_DATABASE_URL` is already pinned to None by `fs_env()`, so
        // with both absent the DSN read fails. The parser tries
        // `HORT_DATABASE_URL` first then falls back to `DATABASE_URL`,
        // so the surfaced Missing variant names whichever was attempted
        // last (`DATABASE_URL`). Accept either name.
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::Missing(var)
                    if var == "HORT_DATABASE_URL" || var == "DATABASE_URL"),
                "expected Missing(HORT_DATABASE_URL|DATABASE_URL), got {err:?}"
            );
        });
    }

    #[test]
    fn filesystem_missing_storage_path() {
        let mut env = fs_env();
        env[2] = ("HORT_STORAGE_FILESYSTEM_PATH", None);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::Missing("HORT_STORAGE_FILESYSTEM_PATH")
            ));
        });
    }

    #[test]
    fn invalid_storage_backend() {
        let mut env = fs_env();
        env[1] = ("HORT_STORAGE_BACKEND", Some("glacier"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(err, ConfigError::InvalidStorageBackend { .. }));
        });
    }

    #[test]
    fn s3_backend_requires_all_fields() {
        let env: Vec<(&'static str, Option<&'static str>)> = vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_S3_BUCKET", Some("hort-bucket")),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_ENDPOINT_URL_S3", Some("http://minio:9000")),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", Some("true")),
            // The validator requires HORT_STORAGE_S3_ALLOW_HTTP=true when
            // the endpoint scheme is http:// (in-cluster MinIO/Garage
            // pattern). Without the flag, parsing fails.
            ("HORT_STORAGE_S3_ALLOW_HTTP", Some("true")),
            ("AWS_ACCESS_KEY_ID", Some("AKIA")),
            ("AWS_SECRET_ACCESS_KEY", Some("SECRET")),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            // Trust config required at startup.
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
        ];
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            match cfg.storage {
                StorageConfig::S3 {
                    bucket,
                    region,
                    endpoint,
                    force_path_style,
                    allow_http,
                    access_key_id,
                    secret_access_key,
                    sse_mode,
                } => {
                    assert_eq!(bucket, "hort-bucket");
                    assert_eq!(region, "us-east-1");
                    assert_eq!(endpoint.as_deref(), Some("http://minio:9000"));
                    assert!(force_path_style);
                    assert!(allow_http);
                    assert_eq!(access_key_id, "AKIA");
                    assert_eq!(secret_access_key, "SECRET");
                    assert_eq!(sse_mode, None, "HORT_S3_SSE_MODE unset must yield None");
                }
                _ => panic!("expected s3"),
            }
        });
    }

    #[test]
    fn s3_backend_missing_bucket() {
        let env: Vec<(&'static str, Option<&'static str>)> = vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_S3_BUCKET", None),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_ACCESS_KEY_ID", Some("A")),
            ("AWS_SECRET_ACCESS_KEY", Some("S")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("AWS_ENDPOINT_URL_S3", None),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
        ];
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::Missing("HORT_STORAGE_S3_BUCKET")
            ));
        });
    }

    // ---- AWS_REGION / AWS_DEFAULT_REGION fallback ------------------------
    //
    // `parse_aws_region` reads two env names and returns the first non-empty
    // value: `AWS_REGION` (newer SDK convention) wins; `AWS_DEFAULT_REGION`
    // (older awscli convention) is the documented fallback. Both tests fix
    // the rest of the S3 env to the same shape as `s3_backend_requires_all_fields`
    // so only the region-source axis varies.

    fn s3_env_with_region_pair(
        aws_region: Option<&'static str>,
        aws_default_region: Option<&'static str>,
    ) -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_S3_BUCKET", Some("hort-bucket")),
            ("AWS_REGION", aws_region),
            ("AWS_DEFAULT_REGION", aws_default_region),
            ("AWS_ENDPOINT_URL_S3", None),
            ("AWS_ENDPOINT_URL", None),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("AWS_ACCESS_KEY_ID", Some("AKIA")),
            ("AWS_SECRET_ACCESS_KEY", Some("SECRET")),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
        ]
    }

    fn assert_s3_region(cfg: Config, expected: &str) {
        match cfg.storage {
            StorageConfig::S3 { region, .. } => assert_eq!(region, expected),
            _ => panic!("expected s3"),
        }
    }

    #[test]
    fn s3_region_reads_aws_region() {
        let env = s3_env_with_region_pair(Some("eu-west-1"), None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_s3_region(cfg, "eu-west-1");
        });
    }

    #[test]
    fn s3_region_falls_back_to_aws_default_region() {
        let env = s3_env_with_region_pair(None, Some("ap-southeast-2"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_s3_region(cfg, "ap-southeast-2");
        });
    }

    #[test]
    fn s3_region_aws_region_takes_precedence_over_default() {
        let env = s3_env_with_region_pair(Some("us-east-1"), Some("ap-southeast-2"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            // AWS_REGION wins — newer SDK convention takes precedence over
            // the older awscli AWS_DEFAULT_REGION.
            assert_s3_region(cfg, "us-east-1");
        });
    }

    #[test]
    fn s3_region_missing_both_errors_with_aws_region_label() {
        let env = s3_env_with_region_pair(None, None);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            // The error names AWS_REGION (the preferred modern name)
            // even though either name would have satisfied the parser —
            // the operator should be steered toward the canonical form.
            assert!(matches!(err, ConfigError::Missing("AWS_REGION")));
        });
    }

    #[test]
    fn s3_region_empty_aws_region_falls_through_to_default() {
        // `AWS_REGION=` (empty string, e.g. from a docker-compose
        // `${AWS_REGION:-}` substitution) must NOT count as set —
        // the parser falls through to AWS_DEFAULT_REGION the same way
        // it would if AWS_REGION were unset entirely.
        let env = s3_env_with_region_pair(Some(""), Some("eu-central-1"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_s3_region(cfg, "eu-central-1");
        });
    }

    // ---- AWS_ENDPOINT_URL_S3 / AWS_ENDPOINT_URL fallback -----------------
    //
    // `parse_aws_s3_endpoint` mirrors the AWS SDK precedence rule: a
    // service-specific override (`AWS_ENDPOINT_URL_S3`) wins over the
    // cross-service default (`AWS_ENDPOINT_URL`). Both unset → no
    // endpoint set on the builder (default AWS S3 routing).

    fn s3_env_with_endpoint_pair(
        url_s3: Option<&'static str>,
        url: Option<&'static str>,
    ) -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_S3_BUCKET", Some("hort-bucket")),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
            ("AWS_ENDPOINT_URL_S3", url_s3),
            ("AWS_ENDPOINT_URL", url),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("AWS_ACCESS_KEY_ID", Some("AKIA")),
            ("AWS_SECRET_ACCESS_KEY", Some("SECRET")),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
        ]
    }

    fn assert_s3_endpoint(cfg: Config, expected: Option<&str>) {
        match cfg.storage {
            StorageConfig::S3 { endpoint, .. } => assert_eq!(endpoint.as_deref(), expected),
            _ => panic!("expected s3"),
        }
    }

    #[test]
    fn s3_endpoint_reads_aws_endpoint_url_s3() {
        let env = s3_env_with_endpoint_pair(Some("https://garage.example.com"), None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_s3_endpoint(cfg, Some("https://garage.example.com"));
        });
    }

    #[test]
    fn s3_endpoint_falls_back_to_aws_endpoint_url() {
        let env = s3_env_with_endpoint_pair(None, Some("https://minio.example.com"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_s3_endpoint(cfg, Some("https://minio.example.com"));
        });
    }

    #[test]
    fn s3_endpoint_url_s3_takes_precedence_over_url() {
        let env = s3_env_with_endpoint_pair(
            Some("https://garage.example.com"),
            Some("https://minio.example.com"),
        );
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            // Service-specific override wins, matching AWS SDK precedence.
            assert_s3_endpoint(cfg, Some("https://garage.example.com"));
        });
    }

    #[test]
    fn s3_endpoint_both_unset_yields_none() {
        let env = s3_env_with_endpoint_pair(None, None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            // No override → builder defaults to AWS S3 routing.
            assert_s3_endpoint(cfg, None);
        });
    }

    #[test]
    fn s3_endpoint_empty_url_s3_falls_through_to_url() {
        // `AWS_ENDPOINT_URL_S3=` (empty string) must not count as set
        // — same docker-compose / shell-substitution defence as the
        // region pair.
        let env = s3_env_with_endpoint_pair(Some(""), Some("https://minio.example.com"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_s3_endpoint(cfg, Some("https://minio.example.com"));
        });
    }

    // ---- HORT_STORAGE_S3_ALLOW_HTTP × endpoint scheme cross-check ----------
    //
    // The rust `object_store` crate refuses HTTP S3 endpoints unless
    // `with_allow_http(true)` is called on the builder. The config layer
    // requires the operator to opt into HTTP explicitly via the flag, and
    // rejects mismatched (scheme, flag) pairs at config-parse time.

    fn s3_env_with_allow_http_pair(
        endpoint: Option<&'static str>,
        allow_http: Option<&'static str>,
    ) -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_S3_BUCKET", Some("hort-bucket")),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
            ("AWS_ENDPOINT_URL_S3", endpoint),
            ("AWS_ENDPOINT_URL", None),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("HORT_STORAGE_S3_ALLOW_HTTP", allow_http),
            ("AWS_ACCESS_KEY_ID", Some("AKIA")),
            ("AWS_SECRET_ACCESS_KEY", Some("SECRET")),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
        ]
    }

    #[test]
    fn s3_http_endpoint_without_allow_http_is_rejected() {
        // The operator wrote `http://` but didn't set the opt-in flag.
        // Rejected at config-parse time so a typo can't silently
        // downgrade transport.
        let env = s3_env_with_allow_http_pair(Some("http://garage:3900"), None);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_STORAGE_S3_ALLOW_HTTP");
                    assert!(reason.contains("http://"));
                    assert!(reason.contains("HORT_STORAGE_S3_ALLOW_HTTP"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn s3_http_endpoint_with_allow_http_succeeds() {
        // Valid in-cluster Garage / MinIO pattern: explicit opt-in
        // matches the http:// scheme.
        let env = s3_env_with_allow_http_pair(Some("http://garage:3900"), Some("true"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            match cfg.storage {
                StorageConfig::S3 {
                    endpoint,
                    allow_http,
                    ..
                } => {
                    assert_eq!(endpoint.as_deref(), Some("http://garage:3900"));
                    assert!(allow_http);
                }
                _ => panic!("expected s3"),
            }
        });
    }

    #[test]
    fn s3_https_endpoint_with_allow_http_is_rejected() {
        // Redundant flag — TLS endpoints don't need the opt-in. Reject so
        // the operator notices the misunderstanding (or stale env var).
        let env = s3_env_with_allow_http_pair(Some("https://s3.example.com"), Some("true"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_STORAGE_S3_ALLOW_HTTP");
                    assert!(reason.contains("https://"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn s3_no_endpoint_with_allow_http_is_rejected() {
        // Real AWS S3 (no endpoint override) is HTTPS-only; the flag
        // has no effect. Reject so the operator removes the dead flag.
        let env = s3_env_with_allow_http_pair(None, Some("true"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_STORAGE_S3_ALLOW_HTTP");
                    assert!(reason.contains("no endpoint"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn s3_https_endpoint_without_allow_http_succeeds() {
        // Default path: real AWS S3 or HTTPS-terminated MinIO. The flag
        // is unset, the endpoint scheme is https://. No mismatch.
        let env = s3_env_with_allow_http_pair(Some("https://s3.example.com"), None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            match cfg.storage {
                StorageConfig::S3 {
                    endpoint,
                    allow_http,
                    ..
                } => {
                    assert_eq!(endpoint.as_deref(), Some("https://s3.example.com"));
                    assert!(!allow_http);
                }
                _ => panic!("expected s3"),
            }
        });
    }

    // ---- HORT_S3_SSE_MODE × HORT_S3_SSE_KMS_KEY_ARN parsing ------------------
    //
    // SSE-mode parsing. The translation into the storage
    // adapter is unit-tested in `hort_adapters_storage::builders`; here we
    // pin the env-var → `S3SseMode` projection.

    fn s3_env_with_sse(
        sse_mode: Option<&'static str>,
        kms_arn: Option<&'static str>,
    ) -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_S3_BUCKET", Some("hort-bucket")),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
            ("AWS_ENDPOINT_URL_S3", Some("https://minio.example.com")),
            ("AWS_ENDPOINT_URL", None),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("HORT_STORAGE_S3_ALLOW_HTTP", None),
            ("AWS_ACCESS_KEY_ID", Some("AKIA")),
            ("AWS_SECRET_ACCESS_KEY", Some("SECRET")),
            ("HORT_S3_SSE_MODE", sse_mode),
            ("HORT_S3_SSE_KMS_KEY_ARN", kms_arn),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
        ]
    }

    fn assert_sse_mode(cfg: &Config, expected: Option<&S3SseMode>) {
        match &cfg.storage {
            StorageConfig::S3 { sse_mode, .. } => assert_eq!(sse_mode.as_ref(), expected),
            _ => panic!("expected s3"),
        }
    }

    #[test]
    fn s3_sse_mode_unset_yields_none() {
        // Operator did not set the env var → no opinion is sent on the
        // request and the bucket-default applies. The storage adapter
        // emits a startup WARN for non-AWS endpoints in this case
        // (tested in `hort_adapters_storage::builders`).
        let env = s3_env_with_sse(None, None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_sse_mode(&cfg, None);
        });
    }

    #[test]
    fn s3_sse_mode_bucket_default_parses() {
        let env = s3_env_with_sse(Some("bucket-default"), None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_sse_mode(&cfg, Some(&S3SseMode::BucketDefault));
        });
    }

    #[test]
    fn s3_sse_mode_sse256_parses() {
        let env = s3_env_with_sse(Some("sse256"), None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_sse_mode(&cfg, Some(&S3SseMode::Sse256));
        });
    }

    #[test]
    fn s3_sse_mode_sse_kms_parses_with_arn() {
        let arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh-5678";
        let env = s3_env_with_sse(Some("sse-kms"), Some(arn));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_sse_mode(
                &cfg,
                Some(&S3SseMode::SseKms {
                    key_arn: arn.to_string(),
                }),
            );
        });
    }

    #[test]
    fn s3_sse_mode_sse_kms_without_arn_is_rejected() {
        // Refuse to start so a misconfiguration can't silently downgrade
        // to no-opinion.
        let env = s3_env_with_sse(Some("sse-kms"), None);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_S3_SSE_MODE");
                    assert!(reason.contains("HORT_S3_SSE_KMS_KEY_ARN"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn s3_sse_mode_unknown_value_is_rejected() {
        let env = s3_env_with_sse(Some("aes-128"), None);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_S3_SSE_MODE");
                    assert!(reason.contains("bucket-default"));
                    assert!(reason.contains("sse256"));
                    assert!(reason.contains("sse-kms"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn s3_sse_mode_empty_string_yields_none() {
        // Defensive against shell/docker-compose substitution emitting
        // `HORT_S3_SSE_MODE=`. Same posture as `AWS_ENDPOINT_URL_S3`.
        let env = s3_env_with_sse(Some(""), None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_sse_mode(&cfg, None);
        });
    }

    #[test]
    fn s3_sse_mode_to_adapter_round_trip() {
        // Lock the projection onto the storage-adapter enum.
        let arn = "arn:aws:kms:us-east-1:1:key/x".to_string();
        assert!(matches!(
            S3SseMode::BucketDefault.to_adapter(),
            hort_adapters_storage::builders::SseMode::BucketDefault,
        ));
        assert!(matches!(
            S3SseMode::Sse256.to_adapter(),
            hort_adapters_storage::builders::SseMode::Sse256,
        ));
        let projected = S3SseMode::SseKms {
            key_arn: arn.clone(),
        }
        .to_adapter();
        match projected {
            hort_adapters_storage::builders::SseMode::SseKms { key_arn } => {
                assert_eq!(key_arn, arn);
            }
            other => panic!("expected SseKms, got {other:?}"),
        }
    }

    // ---- HORT_CAS_SCRUB_ACTION_ON_MISMATCH parsing -------------------------
    //
    // Pin the env-var → `ActionOnMismatch`
    // projection. The default-alert posture is the RC backwards-compat
    // contract: existing operators expecting flag-only behaviour get it
    // unless they explicitly set `tombstone`.

    #[test]
    fn cas_scrub_action_on_mismatch_unset_yields_alert() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.cas_scrub_action_on_mismatch,
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Alert
            );
        });
    }

    #[test]
    fn cas_scrub_action_on_mismatch_empty_yields_alert() {
        // Defensive against shell / k8s ConfigMap defaults emitting
        // `HORT_CAS_SCRUB_ACTION_ON_MISMATCH=`. Same posture as
        // `HORT_S3_SSE_MODE=`.
        let mut env = fs_env();
        env.push(("HORT_CAS_SCRUB_ACTION_ON_MISMATCH", Some("")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.cas_scrub_action_on_mismatch,
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Alert
            );
        });
    }

    #[test]
    fn cas_scrub_action_on_mismatch_alert_parses() {
        let mut env = fs_env();
        env.push(("HORT_CAS_SCRUB_ACTION_ON_MISMATCH", Some("alert")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.cas_scrub_action_on_mismatch,
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Alert
            );
        });
    }

    #[test]
    fn cas_scrub_action_on_mismatch_tombstone_parses() {
        let mut env = fs_env();
        env.push(("HORT_CAS_SCRUB_ACTION_ON_MISMATCH", Some("tombstone")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.cas_scrub_action_on_mismatch,
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Tombstone
            );
        });
    }

    #[test]
    fn cas_scrub_action_on_mismatch_is_case_insensitive() {
        let mut env = fs_env();
        env.push(("HORT_CAS_SCRUB_ACTION_ON_MISMATCH", Some("Tombstone")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.cas_scrub_action_on_mismatch,
                hort_app::use_cases::cas_scrub_use_case::ActionOnMismatch::Tombstone
            );
        });
    }

    #[test]
    fn cas_scrub_action_on_mismatch_unknown_value_is_rejected() {
        // A typo must not silently fall through to Alert (which would
        // be operationally surprising — the operator thought they
        // enabled tombstone). Refuse to start with a clear error.
        let mut env = fs_env();
        env.push(("HORT_CAS_SCRUB_ACTION_ON_MISMATCH", Some("delete")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_CAS_SCRUB_ACTION_ON_MISMATCH");
                    assert!(reason.contains("alert"));
                    assert!(reason.contains("tombstone"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn metrics_bind_addr_parsed_when_set() {
        let mut env = fs_env();
        env[4] = ("HORT_METRICS_BIND", Some("127.0.0.1:9090"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.metrics_bind_addr.map(|a| a.to_string()),
                Some("127.0.0.1:9090".to_string())
            );
        });
    }

    /// Defaults for the new lockdown
    /// flags. Auth required, public-bind opt-out off.
    #[test]
    fn metrics_lockdown_flags_default_to_secure_posture() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(
                cfg.metrics_require_auth,
                "HORT_METRICS_REQUIRE_AUTH default must be true"
            );
            assert!(
                !cfg.metrics_public_bind,
                "HORT_METRICS_PUBLIC_BIND default must be false"
            );
        });
    }

    /// `HORT_METRICS_REQUIRE_AUTH=false`
    /// flips the bypass on and is observable on the parsed config.
    #[test]
    fn metrics_require_auth_false_parsed() {
        let mut env = fs_env();
        env.push(("HORT_METRICS_REQUIRE_AUTH", Some("false")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.metrics_require_auth);
        });
    }

    /// `HORT_METRICS_BIND=0.0.0.0:9090` is refused at config-parse
    /// time unless `HORT_METRICS_PUBLIC_BIND=true` is set. The error
    /// names both env vars so an operator reading stderr finds the fix
    /// without grepping source.
    #[test]
    fn metrics_bind_to_unspecified_address_refused_without_opt_in() {
        let mut env = fs_env();
        env[4] = ("HORT_METRICS_BIND", Some("0.0.0.0:9090"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::MetricsPublicBindRefused {
                        var: "HORT_METRICS_BIND",
                        ..
                    }
                ),
                "expected MetricsPublicBindRefused, got {err:?}"
            );
            // Operator-facing message must name both env vars + suggest
            // a concrete loopback alternative so the fix is obvious.
            let msg = format!("{err}");
            assert!(
                msg.contains("HORT_METRICS_PUBLIC_BIND"),
                "error must name HORT_METRICS_PUBLIC_BIND, got {msg}"
            );
            assert!(
                msg.contains("127.0.0.1:9090"),
                "error must suggest the loopback alternative, got {msg}"
            );
        });
    }

    /// IPv6 unspecified bind (`[::]:9090`) is refused under the same
    /// gate as the IPv4 unspecified address.
    #[test]
    fn metrics_bind_to_ipv6_unspecified_refused_without_opt_in() {
        let mut env = fs_env();
        env[4] = ("HORT_METRICS_BIND", Some("[::]:9090"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::MetricsPublicBindRefused { .. }),
                "expected MetricsPublicBindRefused, got {err:?}"
            );
        });
    }

    /// `HORT_METRICS_PUBLIC_BIND=true` re-permits the unspecified-address
    /// bind. Operators with NetworkPolicy / firewall already in front
    /// of the listener take this path explicitly.
    #[test]
    fn metrics_bind_to_unspecified_address_accepted_with_opt_in() {
        let mut env = fs_env();
        env[4] = ("HORT_METRICS_BIND", Some("0.0.0.0:9090"));
        env.push(("HORT_METRICS_PUBLIC_BIND", Some("true")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.metrics_bind_addr.map(|a| a.to_string()),
                Some("0.0.0.0:9090".to_string())
            );
            assert!(cfg.metrics_public_bind);
        });
    }

    /// Loopback bind is always allowed regardless of the public-bind
    /// opt-in — the guard targets the `0.0.0.0` foot-gun specifically.
    #[test]
    fn metrics_bind_to_loopback_always_allowed() {
        let mut env = fs_env();
        env[4] = ("HORT_METRICS_BIND", Some("127.0.0.1:9090"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.metrics_bind_addr.map(|a| a.to_string()),
                Some("127.0.0.1:9090".to_string())
            );
        });
    }

    // --- `HORT_CONTROL_BIND` internal-only
    // control-plane listener. These mirror the `HORT_METRICS_BIND`
    // tests above exactly: the unspecified-address guard is the SAME
    // `MetricsPublicBindRefused` variant, parameterised on the opt-in
    // var so the operator-facing message names `HORT_CONTROL_PUBLIC_BIND`.

    /// `HORT_CONTROL_BIND` parses into `control_bind_addr` when set to a
    /// concrete address (mirrors `metrics_bind_addr_parsed_when_set`).
    #[test]
    fn control_bind_addr_parsed_when_set() {
        let mut env = fs_env();
        env.push(("HORT_CONTROL_BIND", Some("127.0.0.1:9443")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.control_bind_addr.map(|a| a.to_string()),
                Some("127.0.0.1:9443".to_string())
            );
        });
    }

    /// `HORT_CONTROL_BIND` unset ⇒ `control_bind_addr` is `None` (the
    /// zero-behaviour-change default — control routes stay on the main
    /// listener, byte-identical to today).
    #[test]
    fn control_bind_addr_defaults_to_none_and_public_bind_off() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(
                cfg.control_bind_addr.is_none(),
                "HORT_CONTROL_BIND unset must yield None (no behaviour change)"
            );
            assert!(
                !cfg.control_public_bind,
                "HORT_CONTROL_PUBLIC_BIND default must be false"
            );
        });
    }

    /// `HORT_CONTROL_BIND=0.0.0.0:9443` is refused at config-parse time
    /// unless `HORT_CONTROL_PUBLIC_BIND=true` is set. The error names the
    /// control opt-in var + a concrete loopback alternative (extends the
    /// existing metrics 0.0.0.0 footgun guard to the new socket).
    #[test]
    fn control_bind_to_unspecified_address_refused_without_opt_in() {
        let mut env = fs_env();
        env.push(("HORT_CONTROL_BIND", Some("0.0.0.0:9443")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::MetricsPublicBindRefused {
                        var: "HORT_CONTROL_BIND",
                        ..
                    }
                ),
                "expected MetricsPublicBindRefused for HORT_CONTROL_BIND, got {err:?}"
            );
            let msg = format!("{err}");
            assert!(
                msg.contains("HORT_CONTROL_PUBLIC_BIND"),
                "error must name HORT_CONTROL_PUBLIC_BIND, got {msg}"
            );
            assert!(
                msg.contains("127.0.0.1:9443"),
                "error must suggest the loopback alternative, got {msg}"
            );
        });
    }

    /// IPv6 unspecified bind (`[::]:9443`) is refused under the same
    /// gate as the IPv4 unspecified address.
    #[test]
    fn control_bind_to_ipv6_unspecified_refused_without_opt_in() {
        let mut env = fs_env();
        env.push(("HORT_CONTROL_BIND", Some("[::]:9443")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::MetricsPublicBindRefused {
                        var: "HORT_CONTROL_BIND",
                        ..
                    }
                ),
                "expected MetricsPublicBindRefused for HORT_CONTROL_BIND, got {err:?}"
            );
        });
    }

    /// `HORT_CONTROL_PUBLIC_BIND=true` re-permits the unspecified-address
    /// bind (operators with NetworkPolicy / firewall in front).
    #[test]
    fn control_bind_to_unspecified_address_accepted_with_opt_in() {
        let mut env = fs_env();
        env.push(("HORT_CONTROL_BIND", Some("0.0.0.0:9443")));
        env.push(("HORT_CONTROL_PUBLIC_BIND", Some("true")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.control_bind_addr.map(|a| a.to_string()),
                Some("0.0.0.0:9443".to_string())
            );
            assert!(cfg.control_public_bind);
        });
    }

    /// Loopback control bind is always allowed regardless of the
    /// public-bind opt-in — the guard targets `0.0.0.0` specifically.
    #[test]
    fn control_bind_to_loopback_always_allowed() {
        let mut env = fs_env();
        env.push(("HORT_CONTROL_BIND", Some("127.0.0.1:9443")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.control_bind_addr.map(|a| a.to_string()),
                Some("127.0.0.1:9443".to_string())
            );
        });
    }

    #[test]
    fn invalid_api_bind_addr_rejected() {
        let mut env = fs_env();
        env[3] = ("HORT_API_BIND", Some("not-an-addr"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidAddr {
                    var: "HORT_API_BIND",
                    ..
                }
            ));
        });
    }

    // ---------- Narrowed bind default ----------
    //
    // The default API bind is loopback (`127.0.0.1:8080`), not
    // `0.0.0.0:8080`; operators who need
    // the listener reachable on every interface set `HORT_API_BIND`
    // explicitly. There is no `HORT_BIND_PUBLIC=true` opt-in —
    // the chart's `api.bindAddr` value sets `HORT_API_BIND`
    // directly, so the binary has one bind variable, not two.

    /// Default bind is `127.0.0.1:8080` — covered by
    /// `filesystem_defaults` above. This test pins the assertion
    /// explicitly so a future test refactor can't accidentally drop
    /// the bind-default check.
    #[test]
    fn api_bind_addr_default_is_loopback() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.api_bind_addr.to_string(), "127.0.0.1:8080");
        });
    }

    /// Explicit `HORT_API_BIND=...` overrides the loopback default. A
    /// pinned value (loopback or otherwise) is the operator's concrete
    /// choice — typically `0.0.0.0:8080` inside a container so kubelet
    /// probes can reach the pod IP.
    #[test]
    fn explicit_api_bind_addr_overrides_default() {
        let mut env = fs_env();
        env[3] = ("HORT_API_BIND", Some("0.0.0.0:9000"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.api_bind_addr.to_string(), "0.0.0.0:9000");
        });
    }

    // ---------- HORT_REQUIRE_HTTPS gate ----------
    //
    // The startup gate fires only when ALL three conditions hold:
    //   1. `HORT_REQUIRE_HTTPS=true`
    //   2. `HORT_PUBLIC_BASE_URL` is `http://...`
    //   3. `HORT_TRUSTED_PROXY_CIDRS` is empty
    // Each test below pins one branch of the truth table.

    /// Branch (5): the failure case — `HORT_REQUIRE_HTTPS=true` AND
    /// `HORT_PUBLIC_BASE_URL=http://...` AND empty `HORT_TRUSTED_PROXY_CIDRS`
    /// → `ConfigError::InsecureHttp` at parse time.
    #[test]
    fn require_https_with_http_base_url_and_no_proxy_fails_startup() {
        let mut env = fs_env();
        // `fs_env` already defaults HORT_PUBLIC_BASE_URL to
        // `http://hort-server:8080`. HORT_TRUSTED_PROXY_CIDRS is None.
        env.push(("HORT_REQUIRE_HTTPS", Some("true")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::InsecureHttp),
                "expected InsecureHttp, got {err:?}"
            );
            // Operator-facing message must name HORT_REQUIRE_HTTPS plus
            // the two paths forward (https URL or trusted proxy CIDRs).
            let msg = format!("{err}");
            assert!(
                msg.contains("HORT_REQUIRE_HTTPS"),
                "error must name HORT_REQUIRE_HTTPS, got {msg}"
            );
            assert!(
                msg.contains("HORT_PUBLIC_BASE_URL"),
                "error must name HORT_PUBLIC_BASE_URL, got {msg}"
            );
            assert!(
                msg.contains("HORT_TRUSTED_PROXY_CIDRS"),
                "error must name HORT_TRUSTED_PROXY_CIDRS, got {msg}"
            );
        });
    }

    /// Branch (6): `HORT_REQUIRE_HTTPS=true` AND
    /// `HORT_PUBLIC_BASE_URL=https://...` → OK. The pinned https URL
    /// IS positive evidence the public connection is TLS.
    #[test]
    fn require_https_with_https_base_url_starts_normally() {
        let mut env = fs_env();
        set_public_base_url(&mut env, Some("https://hort.example.com"));
        env.push(("HORT_REQUIRE_HTTPS", Some("true")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.require_https);
            assert_eq!(cfg.public_base_url.unwrap().scheme(), "https");
        });
    }

    /// Branch (7): `HORT_REQUIRE_HTTPS=true` AND
    /// `HORT_PUBLIC_BASE_URL=http://...` AND non-empty
    /// `HORT_TRUSTED_PROXY_CIDRS` → OK. A configured trusted-proxy
    /// allowlist is positive evidence the operator has wired a
    /// reverse proxy whose `X-Forwarded-Proto` carries the real
    /// public scheme.
    #[test]
    fn require_https_with_http_base_url_but_trusted_proxies_starts_normally() {
        let mut env = fs_env();
        // HORT_PUBLIC_BASE_URL stays http://hort-server:8080 (fs_env default).
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8"));
        env.push(("HORT_REQUIRE_HTTPS", Some("true")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.require_https);
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 1);
        });
    }

    /// Branch (8): `HORT_REQUIRE_HTTPS` unset / false (the default) →
    /// the gate doesn't fire regardless of other config. Existing
    /// local-dev setups boot without changes — this is the whole
    /// reason the default is `false`.
    #[test]
    fn require_https_default_false_does_not_fail_on_http_base_url() {
        // fs_env defaults HORT_PUBLIC_BASE_URL to http://... and leaves
        // HORT_TRUSTED_PROXY_CIDRS empty. With HORT_REQUIRE_HTTPS unset, this
        // is exactly the "would fail if the gate were on" config —
        // assert it boots cleanly.
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.require_https);
        });
    }

    /// Explicit `HORT_REQUIRE_HTTPS=false` with the same otherwise-bad
    /// config also passes — the gate is genuinely opt-in.
    #[test]
    fn require_https_explicit_false_does_not_fail_on_http_base_url() {
        let mut env = fs_env();
        env.push(("HORT_REQUIRE_HTTPS", Some("false")));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.require_https);
        });
    }

    #[test]
    fn invalid_log_format_rejected() {
        let mut env = fs_env();
        env[5] = ("HORT_LOG_FORMAT", Some("xml"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(err, ConfigError::InvalidLogFormat { .. }));
        });
    }

    #[test]
    fn log_format_json_accepted() {
        let mut env = fs_env();
        env[5] = ("HORT_LOG_FORMAT", Some("json"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.log_format, LogFormat::Json);
        });
    }

    #[test]
    fn include_repository_label_false() {
        let mut env = fs_env();
        env[6] = ("METRICS_INCLUDE_REPOSITORY_LABEL", Some("false"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.include_repository_label);
        });
    }

    #[test]
    fn include_repository_label_invalid_rejected() {
        let mut env = fs_env();
        env[6] = ("METRICS_INCLUDE_REPOSITORY_LABEL", Some("maybe"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(err, ConfigError::InvalidBool { .. }));
        });
    }

    // -- metadata_caps --------------------------------

    /// Base env plus caller-supplied metadata-cap vars.
    fn fs_env_with_caps(
        caps: &[(&'static str, Option<&'static str>)],
    ) -> Vec<(&'static str, Option<&'static str>)> {
        let mut v = fs_env();
        v.extend_from_slice(caps);
        v
    }

    #[test]
    fn metadata_caps_default_is_empty_when_no_vars_set() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.metadata_caps.is_empty());
        });
    }

    #[test]
    fn metadata_caps_parse_single_format() {
        let env = fs_env_with_caps(&[("METADATA_CAP_BYTES_PYPI", Some("65536"))]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_caps.get("pypi"), Some(&65_536));
            assert_eq!(cfg.metadata_caps.len(), 1);
        });
    }

    #[test]
    fn metadata_caps_parse_multiple_formats() {
        let env = fs_env_with_caps(&[
            ("METADATA_CAP_BYTES_PYPI", Some("131072")),
            ("METADATA_CAP_BYTES_NPM", Some("131072")),
            ("METADATA_CAP_BYTES_CARGO", Some("16384")),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_caps.get("pypi"), Some(&131_072));
            assert_eq!(cfg.metadata_caps.get("npm"), Some(&131_072));
            assert_eq!(cfg.metadata_caps.get("cargo"), Some(&16_384));
        });
    }

    #[test]
    fn metadata_caps_empty_value_is_ignored() {
        let env = fs_env_with_caps(&[
            ("METADATA_CAP_BYTES_PYPI", Some("")),
            ("METADATA_CAP_BYTES_NPM", Some("99")),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_caps.get("pypi"), None);
            assert_eq!(cfg.metadata_caps.get("npm"), Some(&99));
        });
    }

    #[test]
    fn metadata_caps_non_integer_rejected() {
        let env = fs_env_with_caps(&[("METADATA_CAP_BYTES_PYPI", Some("large"))]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "METADATA_CAP_BYTES_PYPI");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn metadata_caps_negative_rejected() {
        // usize can't be negative; ParseIntError surfaces from the parse.
        let env = fs_env_with_caps(&[("METADATA_CAP_BYTES_PYPI", Some("-1"))]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidInt {
                    var: "METADATA_CAP_BYTES_PYPI",
                    ..
                }
            ));
        });
    }

    // -- metadata_blob_max_bytes ---------------------

    #[test]
    fn metadata_blob_max_bytes_default_is_10_mb() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_blob_max_bytes, 10 * 1024 * 1024);
        });
    }

    #[test]
    fn metadata_blob_max_bytes_override_parsed() {
        let mut env = fs_env();
        // HORT_METADATA_BLOB_MAX_SIZE is at index 14.
        env[14] = ("HORT_METADATA_BLOB_MAX_SIZE", Some("20971520")); // 20 MB
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_blob_max_bytes, 20 * 1024 * 1024);
        });
    }

    #[test]
    fn metadata_blob_max_bytes_zero_accepted_as_unbounded() {
        // 0 is a documented escape hatch meaning "accept anything";
        // useful for tests and for operators who want to bypass the
        // blob-size ceiling entirely.
        let mut env = fs_env();
        env[14] = ("HORT_METADATA_BLOB_MAX_SIZE", Some("0"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_blob_max_bytes, 0);
        });
    }

    #[test]
    fn metadata_blob_max_bytes_non_integer_rejected() {
        let mut env = fs_env();
        env[14] = ("HORT_METADATA_BLOB_MAX_SIZE", Some("huge"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidValue {
                    var: "HORT_METADATA_BLOB_MAX_SIZE",
                    ..
                }
            ));
        });
    }

    #[test]
    fn metadata_blob_max_bytes_size_string_override_parsed() {
        // The operator surface is a size string.
        let mut env = fs_env();
        env[14] = ("HORT_METADATA_BLOB_MAX_SIZE", Some("20Mi"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_blob_max_bytes, 20 * 1024 * 1024);
        });
    }

    #[test]
    fn metadata_blob_max_bytes_empty_falls_back_to_default() {
        let mut env = fs_env();
        env[14] = ("HORT_METADATA_BLOB_MAX_SIZE", Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.metadata_blob_max_bytes, 10 * 1024 * 1024);
        });
    }

    /// Replace the `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` slot in
    /// an `fs_env` vector. Mirrors `set_public_base_url`.
    fn set_resolver_refresh_secs(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_UPSTREAM_RESOLVER_REFRESH_SECS" {
                *slot = ("HORT_UPSTREAM_RESOLVER_REFRESH_SECS", value);
                return;
            }
        }
        panic!(
            "fs_env is missing HORT_UPSTREAM_RESOLVER_REFRESH_SECS slot — check fs_env definition"
        );
    }

    /// `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` below the validated floor
    /// must abort startup with a clear error. Pinning this stops a
    /// future relaxation from silently dropping the floor — and
    /// would have caught the mirror smoke regression
    /// where the e2e compose set the var to `2`, the server died at
    /// boot, and the harness only saw "metrics endpoint never
    /// became ready" 120s later.
    #[test]
    fn upstream_resolver_refresh_secs_below_floor_rejected() {
        let mut env = fs_env();
        set_resolver_refresh_secs(&mut env, Some("2"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_UPSTREAM_RESOLVER_REFRESH_SECS");
                    assert!(
                        reason.contains(">= 5"),
                        "error reason should name the floor; got: {reason}"
                    );
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    // -----------------------------------------------------------------
    // Audit-retention floor config
    // -----------------------------------------------------------------

    /// All `HORT_RETENTION_*` vars cleared (the default test env never
    /// sets them; clear explicitly so the test is hermetic regardless
    /// of the surrounding process env).
    fn env_clear_retention(env: &mut Vec<(&'static str, Option<&'static str>)>) {
        for v in [
            "HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS",
            "HORT_RETENTION_FLOOR_POLICY_AUTHZ_ADMIN_DAYS",
            "HORT_RETENTION_FLOOR_ARTIFACT_DOWNLOADED_DAYS",
            "HORT_RETENTION_FLOOR_API_TOKEN_USED_DAYS",
            "HORT_RETENTION_FLOOR_ARTIFACT_LIFECYCLE_DAYS",
            "HORT_RETENTION_STREAM_MODE",
            "HORT_RETENTION_ARCHIVE_TARGET",
        ] {
            env.push((v, None));
        }
    }

    /// Unset → the documented retention defaults
    /// (6mo / 36mo / 90d / 36mo / 36mo) and `StreamRetentionMode::Delete`.
    #[test]
    fn retention_floors_unset_use_c1_defaults() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            let f = cfg.audit_retention_floors;
            assert_eq!(f.authentication(), chrono::Duration::days(180));
            assert_eq!(f.policy_authz_admin(), chrono::Duration::days(1080));
            assert_eq!(f.artifact_downloaded(), chrono::Duration::days(90));
            assert_eq!(f.api_token_used(), chrono::Duration::days(1080));
            // USER DECISION: artifact_lifecycle default = 36mo.
            assert_eq!(f.artifact_lifecycle(), chrono::Duration::days(1080));
            assert_eq!(cfg.retention_stream_mode, StreamRetentionMode::Delete);
        });
    }

    /// A below-minimum override is a hard startup failure, per category
    /// (mirrors `upstream_resolver_refresh_secs_below_floor_rejected`).
    #[test]
    fn retention_floor_below_c1_minimum_rejected_per_category() {
        let cases: &[(&'static str, &'static str)] = &[
            ("HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS", "179"),
            ("HORT_RETENTION_FLOOR_POLICY_AUTHZ_ADMIN_DAYS", "1079"),
            ("HORT_RETENTION_FLOOR_ARTIFACT_DOWNLOADED_DAYS", "89"),
            ("HORT_RETENTION_FLOOR_API_TOKEN_USED_DAYS", "1079"),
            ("HORT_RETENTION_FLOOR_ARTIFACT_LIFECYCLE_DAYS", "0"),
        ];
        for (var, below) in cases {
            let mut env = fs_env();
            env_clear_retention(&mut env);
            env.push((var, Some(below)));
            temp_env::with_vars(env, || {
                let err = Config::from_env().unwrap_err();
                match err {
                    ConfigError::InvalidValue { var: v, reason } => {
                        assert_eq!(v, *var, "wrong var named for {var}");
                        assert!(
                            reason.contains("minimum"),
                            "reason should name the minimum; got: {reason}"
                        );
                    }
                    other => panic!("expected InvalidValue for {var}, got {other:?}"),
                }
            });
        }
    }

    /// Exactly-at-minimum overrides are accepted (boundary).
    #[test]
    fn retention_floor_at_c1_minimum_accepted() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        env.push(("HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS", Some("180")));
        env.push(("HORT_RETENTION_FLOOR_POLICY_AUTHZ_ADMIN_DAYS", Some("1080")));
        env.push(("HORT_RETENTION_FLOOR_ARTIFACT_DOWNLOADED_DAYS", Some("90")));
        env.push(("HORT_RETENTION_FLOOR_API_TOKEN_USED_DAYS", Some("1080")));
        env.push(("HORT_RETENTION_FLOOR_ARTIFACT_LIFECYCLE_DAYS", Some("1")));
        temp_env::with_vars(env, || {
            let f = Config::from_env().unwrap().audit_retention_floors;
            assert_eq!(f.authentication(), chrono::Duration::days(180));
            assert_eq!(f.policy_authz_admin(), chrono::Duration::days(1080));
            assert_eq!(f.artifact_downloaded(), chrono::Duration::days(90));
            assert_eq!(f.api_token_used(), chrono::Duration::days(1080));
            assert_eq!(f.artifact_lifecycle(), chrono::Duration::days(1));
        });
    }

    /// An above-minimum override raises the floor (operators may only
    /// ever raise).
    #[test]
    fn retention_floor_above_minimum_raises_floor() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        env.push(("HORT_RETENTION_FLOOR_ARTIFACT_LIFECYCLE_DAYS", Some("3650")));
        temp_env::with_vars(env, || {
            let f = Config::from_env().unwrap().audit_retention_floors;
            assert_eq!(f.artifact_lifecycle(), chrono::Duration::days(3650));
        });
    }

    /// A non-integer override is `InvalidInt`, not a silent fallback.
    #[test]
    fn retention_floor_non_integer_rejected() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        env.push(("HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS", Some("forever")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidInt { var, .. }
                    if var == "HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS"),
                "expected InvalidInt, got {err:?}"
            );
        });
    }

    /// `HORT_RETENTION_STREAM_MODE=archive` requires a non-empty
    /// `HORT_RETENTION_ARCHIVE_TARGET` — silently degrading to delete
    /// would be data loss.
    #[test]
    fn retention_mode_archive_requires_target() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        env.push(("HORT_RETENTION_STREAM_MODE", Some("archive")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, .. } => {
                    assert_eq!(var, "HORT_RETENTION_ARCHIVE_TARGET");
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    /// `archive` + a target prefix parses to
    /// `StreamRetentionMode::Archive { target_prefix }`.
    #[test]
    fn retention_mode_archive_with_target_parses() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        env.push(("HORT_RETENTION_STREAM_MODE", Some("archive")));
        env.push((
            "HORT_RETENTION_ARCHIVE_TARGET",
            Some("s3://cold-bucket/hort-event-archive"),
        ));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.retention_stream_mode,
                StreamRetentionMode::Archive {
                    target_prefix: "s3://cold-bucket/hort-event-archive".to_owned()
                }
            );
        });
    }

    /// An unknown mode string is a hard startup failure (not a silent
    /// fallback to delete).
    #[test]
    fn retention_mode_unknown_value_rejected() {
        let mut env = fs_env();
        env_clear_retention(&mut env);
        env.push(("HORT_RETENTION_STREAM_MODE", Some("incinerate")));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, reason } => {
                    assert_eq!(var, "HORT_RETENTION_STREAM_MODE");
                    assert!(reason.contains("delete") && reason.contains("archive"));
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    /// `floor_for` maps **every** `StreamCategory` arm (the exhaustive
    /// exhaustive registration seam — a new variant would fail to compile
    /// in `floor_for`, this asserts the runtime mapping for the ones
    /// that exist today).
    #[test]
    fn floor_for_maps_every_stream_category() {
        use hort_domain::events::StreamCategory as C;
        // Distinct, non-default values so a mis-wired arm is caught.
        let f = AuditRetentionFloors {
            authentication: chrono::Duration::days(200),
            policy_authz_admin: chrono::Duration::days(1100),
            artifact_downloaded: chrono::Duration::days(100),
            api_token_used: chrono::Duration::days(1200),
            artifact_lifecycle: chrono::Duration::days(1300),
        };
        assert_eq!(f.floor_for(C::AuthAttempts), chrono::Duration::days(200));
        assert_eq!(f.floor_for(C::Policy), chrono::Duration::days(1100));
        assert_eq!(f.floor_for(C::Authorization), chrono::Duration::days(1100));
        assert_eq!(f.floor_for(C::Admin), chrono::Duration::days(1100));
        assert_eq!(f.floor_for(C::User), chrono::Duration::days(1200));
        assert_eq!(f.floor_for(C::Artifact), chrono::Duration::days(1300));
        assert_eq!(f.floor_for(C::Ref), chrono::Duration::days(1300));
        assert_eq!(f.floor_for(C::ArtifactGroup), chrono::Duration::days(1300));
        assert_eq!(f.floor_for(C::Curation), chrono::Duration::days(1300));
        assert_eq!(f.floor_for(C::Repository), chrono::Duration::days(1300));
        // `DownloadAudit` is now a real StreamCategory; `floor_for`
        // maps it to the ≥90d `artifact_downloaded` retention floor.
        assert_eq!(f.floor_for(C::DownloadAudit), chrono::Duration::days(100));
        // `TokenUse` is now a real StreamCategory; `floor_for` maps
        // it to the ≥36mo `api_token_used` credential-audit retention
        // floor (the SAME field `C::User` routes to — intentional,
        // both are the credential-audit class; not a collision).
        assert_eq!(f.floor_for(C::TokenUse), chrono::Duration::days(1200));
        assert_eq!(f.floor_for(C::User), f.floor_for(C::TokenUse));
        // The accessor still round-trips the same value.
        assert_eq!(f.artifact_downloaded(), chrono::Duration::days(100));
    }

    /// Boundary case: the floor itself (5) is the smallest accepted
    /// value. Pinning this means a future floor change to 6 (etc.)
    /// must also update this test, surfacing the policy change at
    /// review time instead of silently widening the rejection range.
    #[test]
    fn upstream_resolver_refresh_secs_at_floor_accepted() {
        let mut env = fs_env();
        set_resolver_refresh_secs(&mut env, Some("5"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.upstream_resolver_refresh_secs, 5);
        });
    }

    /// Default path: unset env keeps the production default of 60s.
    /// Regression guard for an accidental change to the default
    /// arm in the env-var match.
    #[test]
    fn upstream_resolver_refresh_secs_unset_defaults_to_60() {
        let mut env = fs_env();
        set_resolver_refresh_secs(&mut env, None);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.upstream_resolver_refresh_secs, 60);
        });
    }

    #[test]
    fn metadata_caps_bare_prefix_is_skipped() {
        // `METADATA_CAP_BYTES_` with an empty suffix is not a valid
        // per-format override; skip rather than failing — otherwise a
        // stray empty variable would abort startup.
        let env = fs_env_with_caps(&[("METADATA_CAP_BYTES_", Some("123"))]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.metadata_caps.is_empty());
        });
    }

    // -- public_base_url -----------------------------------------------------

    /// Overwrite the `HORT_PUBLIC_BASE_URL` slot in an `fs_env` vector.
    /// The slot's index shifts over time as new env vars are added;
    /// this helper keeps callers index-free.
    fn set_public_base_url(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_PUBLIC_BASE_URL" {
                *slot = ("HORT_PUBLIC_BASE_URL", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_PUBLIC_BASE_URL slot — check fs_env definition");
    }

    #[test]
    fn public_base_url_http_accepted() {
        let mut env = fs_env();
        set_public_base_url(&mut env, Some("http://hort-server:8080"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            let url = cfg.public_base_url.expect("parsed");
            assert_eq!(url.scheme(), "http");
            assert_eq!(url.host_str(), Some("hort-server"));
            assert_eq!(url.port(), Some(8080));
        });
    }

    #[test]
    fn public_base_url_https_accepted() {
        let mut env = fs_env();
        set_public_base_url(&mut env, Some("https://hort.example.com"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            let url = cfg.public_base_url.expect("parsed");
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("hort.example.com"));
        });
    }

    #[test]
    fn public_base_url_empty_falls_back_to_none_but_requires_trusted_cidrs() {
        // Empty HORT_PUBLIC_BASE_URL → None. Without HORT_TRUSTED_PROXY_CIDRS
        // the trust-unconfigured guard trips — cover the "empty is
        // treated as unset" branch by also setting a trusted CIDR.
        let mut env = fs_env();
        set_public_base_url(&mut env, Some(""));
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.public_base_url.is_none());
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 1);
        });
    }

    #[test]
    fn public_base_url_malformed_rejected() {
        let mut env = fs_env();
        set_public_base_url(&mut env, Some("not a url"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidUrl {
                    var: "HORT_PUBLIC_BASE_URL",
                    ..
                }
            ));
        });
    }

    #[test]
    fn public_base_url_non_http_scheme_rejected() {
        let mut env = fs_env();
        set_public_base_url(&mut env, Some("ftp://registry.example.com"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidUrlShape {
                    var: "HORT_PUBLIC_BASE_URL",
                    reason: "scheme must be http or https",
                    ..
                }
            ));
        });
    }

    // No `public_base_url_missing_host_rejected` test: `url::Url::parse`
    // is lenient about authority shape — `http:/path` parses with the path
    // segment coerced into a host. The `host_str().is_none()` guard in
    // `parse_public_base_url` is defence-in-depth and cannot be triggered
    // by any http/https URL the url crate accepts today; keep the guard,
    // skip the unprovable test.

    // -- auth ---------------------------------------------------------------
    //
    // Each test builds a full env with `fs_env_auth` — the base fs_env plus
    // caller-supplied overrides. `temp_env::with_vars` isolates the mutation
    // to the test; nothing leaks into sibling tests.
    //
    // Note: there is no temp YAML file for a
    // legacy `HORT_GROUP_MAPPINGS_PATH` loader — that loader is gone
    // (gitops apply owns the load); the temp-file helpers
    // went with it.

    /// Base env plus the auth-provider overrides, appended after
    /// fs_env's HORT_AUTH_PROVIDER / OIDC_* / HORT_TOKEN_* slots — the later
    /// entry wins in `temp_env::with_vars`.
    fn fs_env_auth(
        overrides: &[(&'static str, Option<&'static str>)],
    ) -> Vec<(&'static str, Option<&'static str>)> {
        let mut v = fs_env();
        v.extend_from_slice(overrides);
        v
    }

    // Happy path 1: default — absent HORT_AUTH_PROVIDER → Disabled.

    #[test]
    fn auth_provider_default_is_disabled() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(matches!(cfg.auth, AuthConfig::Disabled));
            assert!(cfg.claim_mappings.is_empty());
        });
    }

    // Happy path 2: explicit "disabled" string.

    #[test]
    fn auth_provider_disabled_explicit() {
        let env = fs_env_auth(&[("HORT_AUTH_PROVIDER", Some("disabled"))]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(matches!(cfg.auth, AuthConfig::Disabled));
            assert!(cfg.claim_mappings.is_empty());
        });
    }

    // Error path: unknown provider.

    #[test]
    fn auth_provider_unknown_rejected() {
        let env = fs_env_auth(&[("HORT_AUTH_PROVIDER", Some("kerberos"))]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidAuthProvider { var, got } => {
                    assert_eq!(var, "HORT_AUTH_PROVIDER");
                    assert_eq!(got, "kerberos");
                }
                other => panic!("expected InvalidAuthProvider, got {other:?}"),
            }
        });
    }

    // Error path: OIDC requires issuer URL.

    #[test]
    fn auth_provider_oidc_requires_issuer_url() {
        let env = fs_env_auth(&[
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            ("HORT_OIDC_ISSUER_URL", None),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
        ]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::Missing("HORT_OIDC_ISSUER_URL")),
                "got {err:?}"
            );
        });
    }

    // Error path: OIDC requires audience.

    #[test]
    fn auth_provider_oidc_requires_audience() {
        let env = fs_env_auth(&[
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", None),
        ]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::Missing("HORT_OIDC_AUDIENCE")),
                "got {err:?}"
            );
        });
    }

    // Happy path: OIDC with full env. Claim mappings load through the
    // gitops boot path, so `cfg.claim_mappings` is the empty
    // parse-time vec — `cli::serve` reads them from the post-apply
    // `claim_mappings` table directly. The OIDC settings still surface
    // here.

    #[test]
    fn auth_provider_oidc_happy_path() {
        let env = fs_env_auth(&[
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            ("HORT_OIDC_GROUPS_CLAIM", Some("custom_groups")),
            ("HORT_JWKS_CACHE_TTL_SECS", Some("1200")),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            match &cfg.auth {
                AuthConfig::Oidc(o) => {
                    assert_eq!(o.issuer_url, "https://idp.example/realms/hort");
                    assert_eq!(o.audience, "hort-server");
                    assert_eq!(o.groups_claim, "custom_groups");
                    assert_eq!(o.jwks_cache_ttl_seconds, 1200);
                }
                AuthConfig::Disabled => panic!("expected Oidc, got Disabled"),
            }
            // No in-process mappings load
            // here; gitops apply (run before `build_app_context`)
            // populates the use case from the table. Empty parse-time
            // vec is the contract.
            assert!(cfg.claim_mappings.is_empty());
        });
    }

    // Defaults check: minimum env surfaces the documented defaults.

    #[test]
    fn auth_provider_oidc_defaults() {
        let env = fs_env_auth(&[
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            match cfg.auth {
                AuthConfig::Oidc(o) => {
                    assert_eq!(o.groups_claim, "groups");
                    assert_eq!(o.jwks_cache_ttl_seconds, 600);
                }
                AuthConfig::Disabled => panic!("expected Oidc"),
            }
        });
    }

    // Setting `HORT_GROUP_MAPPINGS_PATH` is a
    // no-op. The legacy single-file loader is gone; nothing in
    // `Config::from_env` reads the var. The boot still succeeds; group
    // mappings stay the empty parse-time vec (gitops apply populates
    // the table separately). A future "unrecognised HORT_*" boot warning
    // would surface this for operators with stale deployment templates;
    // here we pin only the load-behaviour invariant.

    #[test]
    fn legacy_hort_group_mappings_path_env_var_is_a_no_op() {
        let unused_dummy_path = "/no-such-file-anywhere-because-loader-is-gone.yaml";
        let env = fs_env_auth(&[
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            // Slot still present in fs_env() so the override sticks via
            // `temp_env::with_vars`'s last-write-wins; if the var is
            // ever consumed again this test will surface the regression
            // because the path doesn't exist.
            ("HORT_GROUP_MAPPINGS_PATH", Some(unused_dummy_path)),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env()
                .expect("HORT_GROUP_MAPPINGS_PATH must not be consulted by Config::from_env");
            assert!(matches!(cfg.auth, AuthConfig::Oidc(_)));
            assert!(
                cfg.claim_mappings.is_empty(),
                "claim_mappings must stay empty — gitops apply owns the load"
            );
        });
    }

    /// Defence-in-depth code-inspection check: no consumer in the
    /// workspace's source tree must read `HORT_GROUP_MAPPINGS_PATH` for
    /// load-bearing behaviour. The runtime no-op
    /// test above exercises the boot path; this test guards against a
    /// regression slipping into a helper or sibling module by scanning
    /// the on-disk source.
    ///
    /// One legitimate read is permitted: the
    /// deprecation-warning probe in `cli/serve.rs`
    /// (`legacy_group_mappings_path_is_set`). It exists *only* to
    /// detect stale deployment templates and emit a `tracing::warn!`
    /// — the var still has zero effect on `Config` or
    /// `AuthenticateUseCase`. Allowlisting that one file keeps the
    /// scan honest without giving up the regression guard.
    #[test]
    fn legacy_hort_group_mappings_path_has_no_remaining_env_var_consumers() {
        use std::path::Path;
        let crates_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut hits: Vec<String> = Vec::new();
        scan_for_env_var_read(&crates_root, "HORT_GROUP_MAPPINGS_PATH", &mut hits);

        // The only allowed reader is the deprecation-warning probe in
        // `hort-server/src/cli/serve.rs`. Anything else is a regression.
        let illegitimate: Vec<&String> = hits
            .iter()
            .filter(|hit| !hit.contains("hort-server/src/cli/serve.rs"))
            .collect();
        assert!(
            illegitimate.is_empty(),
            "the legacy env var is retired; the only permitted reader is the \
             deprecation-warning probe in `cli/serve.rs`. \
             Unexpected call sites: {illegitimate:?}",
        );
    }

    /// Walk every `.rs` file under `root` (skipping target/, hidden
    /// dirs) and record any line containing
    /// `std::env::var("<name>")` or `env::var("<name>")`. Test files
    /// (`#[cfg(test)]` modules) are excluded from the scan so this
    /// test itself doesn't self-trigger; we recognise them by skipping
    /// any line in a file path containing `/tests/` or matching the
    /// `mod tests` block heuristic via a per-file string check.
    fn scan_for_env_var_read(root: &std::path::Path, var: &str, hits: &mut Vec<String>) {
        let needles = [
            format!("std::env::var(\"{var}\")"),
            format!("env::var(\"{var}\")"),
        ];
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "target" {
                continue;
            }
            if path.is_dir() {
                scan_for_env_var_read(&path, var, hits);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (lineno, line) in text.lines().enumerate() {
                if needles.iter().any(|n| line.contains(n.as_str())) {
                    // Skip the test that performs the scan itself —
                    // it embeds the env-var name as a string literal.
                    if line.contains("scan_for_env_var_read") {
                        continue;
                    }
                    hits.push(format!("{}:{}", path.display(), lineno + 1));
                }
            }
        }
    }

    // -- Proxy-trust config --------------------------------------------------

    /// Overwrite the `HORT_TRUSTED_PROXY_CIDRS` slot. Companion to
    /// [`set_public_base_url`].
    fn set_trusted_proxy_cidrs(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_TRUSTED_PROXY_CIDRS" {
                *slot = ("HORT_TRUSTED_PROXY_CIDRS", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_TRUSTED_PROXY_CIDRS slot — check fs_env definition");
    }

    // Unconditional startup failure: both unset.

    #[test]
    fn trust_unconfigured_fails_startup() {
        let mut env = fs_env();
        set_public_base_url(&mut env, None);
        // HORT_TRUSTED_PROXY_CIDRS already None in fs_env.
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(err, ConfigError::TrustUnconfigured), "got {err:?}");
        });
    }

    /// Startup-failure error message must name BOTH env vars so
    /// operators can find the fix without digging into source. Gate test
    /// on the Display output.
    #[test]
    fn trust_unconfigured_message_names_both_env_vars() {
        let mut env = fs_env();
        set_public_base_url(&mut env, None);
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("HORT_PUBLIC_BASE_URL"),
                "error message should name HORT_PUBLIC_BASE_URL; got {msg}"
            );
            assert!(
                msg.contains("HORT_TRUSTED_PROXY_CIDRS"),
                "error message should name HORT_TRUSTED_PROXY_CIDRS; got {msg}"
            );
        });
    }

    // Only HORT_PUBLIC_BASE_URL set — the default `fs_env` case.

    #[test]
    fn trust_public_base_url_alone_is_sufficient() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.public_base_url.is_some());
            assert!(cfg.trusted_proxy_cidrs.is_empty());
        });
    }

    // Only HORT_TRUSTED_PROXY_CIDRS set.

    #[test]
    fn trust_cidrs_alone_is_sufficient() {
        let mut env = fs_env();
        set_public_base_url(&mut env, None);
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8,::1/128"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.public_base_url.is_none());
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 2);
        });
    }

    // Both set (redundant but permitted — the struct holds both; the
    // middleware prefers `HORT_PUBLIC_BASE_URL` at runtime).

    #[test]
    fn trust_both_set_is_permitted() {
        let mut env = fs_env();
        // HORT_PUBLIC_BASE_URL default from fs_env is already set.
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.public_base_url.is_some());
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 1);
        });
    }

    // CIDR parsing: single entry, IPv4.

    #[test]
    fn trusted_proxy_cidrs_parses_single_ipv4() {
        let mut env = fs_env();
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 1);
            assert_eq!(
                cfg.trusted_proxy_cidrs[0],
                "10.0.0.0/8".parse::<IpNet>().unwrap()
            );
        });
    }

    // CIDR parsing: multiple entries, IPv4 + IPv6.

    #[test]
    fn trusted_proxy_cidrs_parses_multiple_entries() {
        let mut env = fs_env();
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8,192.168.1.0/24,::1/128"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 3);
        });
    }

    // CIDR parsing: whitespace and empty entries are tolerated.

    #[test]
    fn trusted_proxy_cidrs_tolerates_whitespace_and_empty_entries() {
        let mut env = fs_env();
        set_trusted_proxy_cidrs(&mut env, Some(" 10.0.0.0/8 , , ::1/128 "));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.trusted_proxy_cidrs.len(), 2);
        });
    }

    // CIDR parsing: malformed entry fails startup with the offending string.

    #[test]
    fn trusted_proxy_cidrs_malformed_entry_rejected() {
        let mut env = fs_env();
        set_trusted_proxy_cidrs(&mut env, Some("10.0.0.0/8,not-a-cidr,::1/128"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidCidr { var, entry, .. } => {
                    assert_eq!(var, "HORT_TRUSTED_PROXY_CIDRS");
                    assert_eq!(entry, "not-a-cidr");
                }
                other => panic!("expected InvalidCidr, got {other:?}"),
            }
        });
    }

    // CIDR parsing: empty env var → empty vec (but the startup guard
    // still requires HORT_PUBLIC_BASE_URL to be set — covered via default).

    #[test]
    fn trusted_proxy_cidrs_empty_env_yields_empty_vec() {
        let mut env = fs_env();
        set_trusted_proxy_cidrs(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.trusted_proxy_cidrs.is_empty());
        });
    }

    // -- Publish body-limit override -------------------------------------

    /// Overwrite the `HORT_PUBLISH_BODY_MAX_SIZE` slot. Companion to
    /// [`set_public_base_url`] / [`set_trusted_proxy_cidrs`].
    fn set_publish_body_limit(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_PUBLISH_BODY_MAX_SIZE" {
                *slot = ("HORT_PUBLISH_BODY_MAX_SIZE", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_PUBLISH_BODY_MAX_SIZE slot — check fs_env definition");
    }

    // Default — unset env var yields `None` so the route builders fall
    // back to the shared `DEFAULT_PUBLISH_BODY_LIMIT` constant.
    #[test]
    fn publish_body_limit_bytes_unset_is_none() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.publish_body_limit_bytes.is_none());
        });
    }

    // Happy path — explicit bare-integer byte count parses to `Some(n)`
    // (backward shape: `parse_byte_size` accepts a bare integer).
    #[test]
    fn publish_body_limit_bytes_explicit_value_parsed() {
        let mut env = fs_env();
        set_publish_body_limit(&mut env, Some("500000"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.publish_body_limit_bytes, Some(500_000));
        });
    }

    // The operator surface is a size string.
    #[test]
    fn publish_body_limit_bytes_size_string_parsed() {
        let mut env = fs_env();
        set_publish_body_limit(&mut env, Some("300Mi"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.publish_body_limit_bytes, Some(300 * 1024 * 1024));
        });
    }

    // An explicit `"0"` is the documented "refuse all publishes"
    // kill-switch — distinct from the unset `None` (binary default).
    #[test]
    fn publish_body_limit_bytes_explicit_zero_is_kill_switch() {
        let mut env = fs_env();
        set_publish_body_limit(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.publish_body_limit_bytes, Some(0));
        });
    }

    // Error — non-size value surfaces as `InvalidValue` (loud startup
    // failure, not silent fallback to the default).
    #[test]
    fn publish_body_limit_bytes_non_integer_rejected() {
        let mut env = fs_env();
        set_publish_body_limit(&mut env, Some("abc"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, .. } => {
                    assert_eq!(var, "HORT_PUBLISH_BODY_MAX_SIZE");
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    // Empty string treated as unset (consistent with every other
    // optional env var in this module — lets operators clear a value
    // by setting it to empty rather than unsetting entirely).
    #[test]
    fn publish_body_limit_bytes_empty_string_is_unset() {
        let mut env = fs_env();
        set_publish_body_limit(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.publish_body_limit_bytes.is_none());
        });
    }

    // Negative values — a byte size can't be negative; the parse rejects
    // it so operators see a clear failure rather than wraparound.
    #[test]
    fn publish_body_limit_bytes_negative_rejected() {
        let mut env = fs_env();
        set_publish_body_limit(&mut env, Some("-1"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidValue {
                    var: "HORT_PUBLISH_BODY_MAX_SIZE",
                    ..
                }
            ));
        });
    }

    // -- Postgres pool timeouts -------------------------------------------

    /// Overwrite the `PG_STATEMENT_TIMEOUT_MS` slot. Companion to
    /// [`set_publish_body_limit`].
    fn set_pg_statement_timeout_ms(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "PG_STATEMENT_TIMEOUT_MS" {
                *slot = ("PG_STATEMENT_TIMEOUT_MS", value);
                return;
            }
        }
        panic!("fs_env is missing PG_STATEMENT_TIMEOUT_MS slot — check fs_env definition");
    }

    /// Overwrite the `PG_ACQUIRE_TIMEOUT_SECS` slot.
    fn set_pg_acquire_timeout_secs(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "PG_ACQUIRE_TIMEOUT_SECS" {
                *slot = ("PG_ACQUIRE_TIMEOUT_SECS", value);
                return;
            }
        }
        panic!("fs_env is missing PG_ACQUIRE_TIMEOUT_SECS slot — check fs_env definition");
    }

    // PG_STATEMENT_TIMEOUT_MS — happy path parses to `Some(n)`.
    #[test]
    fn pg_statement_timeout_ms_explicit_value_parsed() {
        let mut env = fs_env();
        set_pg_statement_timeout_ms(&mut env, Some("5000"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pg_statement_timeout_ms, Some(5000));
        });
    }

    // PG_STATEMENT_TIMEOUT_MS=0 — zero is not a valid timeout. `SET
    // statement_timeout = 0` in Postgres means "no timeout", which
    // silently undermines the operator's intent; reject at parse time
    // so the misconfiguration surfaces as a loud startup failure.
    #[test]
    fn pg_statement_timeout_ms_zero_rejected() {
        let mut env = fs_env();
        set_pg_statement_timeout_ms(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "PG_STATEMENT_TIMEOUT_MS",
                    ..
                }
            ));
        });
    }

    // PG_STATEMENT_TIMEOUT_MS=abc — non-integer surfaces as InvalidInt
    // (same path as every other numeric env var in this module).
    #[test]
    fn pg_statement_timeout_ms_non_integer_rejected() {
        let mut env = fs_env();
        set_pg_statement_timeout_ms(&mut env, Some("abc"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "PG_STATEMENT_TIMEOUT_MS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    // Unset env var yields `None` — no `after_connect` hook runs and
    // Postgres' default "no statement timeout" applies.
    #[test]
    fn pg_statement_timeout_ms_unset_is_none() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.pg_statement_timeout_ms.is_none());
        });
    }

    // Empty string treated as unset — consistent with every other
    // Option<_> env var in this module.
    #[test]
    fn pg_statement_timeout_ms_empty_string_is_unset() {
        let mut env = fs_env();
        set_pg_statement_timeout_ms(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.pg_statement_timeout_ms.is_none());
        });
    }

    // PG_ACQUIRE_TIMEOUT_SECS — happy path parses the integer.
    #[test]
    fn pg_acquire_timeout_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_pg_acquire_timeout_secs(&mut env, Some("60"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pg_acquire_timeout_secs, 60);
        });
    }

    // PG_ACQUIRE_TIMEOUT_SECS=0 — zero acquire timeout would make
    // every pool acquisition fail immediately; reject as a misconfig.
    #[test]
    fn pg_acquire_timeout_secs_zero_rejected() {
        let mut env = fs_env();
        set_pg_acquire_timeout_secs(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "PG_ACQUIRE_TIMEOUT_SECS",
                    ..
                }
            ));
        });
    }

    // PG_ACQUIRE_TIMEOUT_SECS=abc — non-integer surfaces as InvalidInt.
    #[test]
    fn pg_acquire_timeout_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_pg_acquire_timeout_secs(&mut env, Some("abc"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "PG_ACQUIRE_TIMEOUT_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    // Unset env var falls back to the 30-second default.
    #[test]
    fn pg_acquire_timeout_secs_unset_defaults_to_30() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pg_acquire_timeout_secs, 30);
        });
    }

    // -- JWKS resilience knobs ----------------------------------------------

    /// Overwrite the `HORT_JWKS_EVICTION_BACKOFF_SECS` slot.
    fn set_jwks_eviction_backoff_secs(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_JWKS_EVICTION_BACKOFF_SECS" {
                *slot = ("HORT_JWKS_EVICTION_BACKOFF_SECS", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_JWKS_EVICTION_BACKOFF_SECS slot — check fs_env definition");
    }

    /// Overwrite the `HORT_JWKS_RESP_BODY_MAX_SIZE` slot.
    fn set_jwks_resp_body_max_bytes(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_JWKS_RESP_BODY_MAX_SIZE" {
                *slot = ("HORT_JWKS_RESP_BODY_MAX_SIZE", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_JWKS_RESP_BODY_MAX_SIZE slot — check fs_env definition");
    }

    #[test]
    fn jwks_eviction_backoff_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_jwks_eviction_backoff_secs(&mut env, Some("30"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.jwks_eviction_backoff_secs, 30);
        });
    }

    #[test]
    fn jwks_eviction_backoff_secs_zero_rejected() {
        let mut env = fs_env();
        set_jwks_eviction_backoff_secs(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_JWKS_EVICTION_BACKOFF_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn jwks_eviction_backoff_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_jwks_eviction_backoff_secs(&mut env, Some("abc"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_JWKS_EVICTION_BACKOFF_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn jwks_eviction_backoff_secs_unset_defaults_to_10() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.jwks_eviction_backoff_secs, 10);
        });
    }

    #[test]
    fn jwks_eviction_backoff_secs_empty_string_is_default() {
        let mut env = fs_env();
        set_jwks_eviction_backoff_secs(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.jwks_eviction_backoff_secs, 10);
        });
    }

    #[test]
    fn jwks_resp_body_max_bytes_explicit_value_parsed() {
        let mut env = fs_env();
        // Backward shape: a bare byte integer is still accepted.
        set_jwks_resp_body_max_bytes(&mut env, Some("2097152"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.jwks_resp_body_max_bytes, 2_097_152);
        });
    }

    // The operator surface is a size string.
    #[test]
    fn jwks_resp_body_max_bytes_size_string_parsed() {
        let mut env = fs_env();
        set_jwks_resp_body_max_bytes(&mut env, Some("4Mi"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.jwks_resp_body_max_bytes, 4 * 1024 * 1024);
        });
    }

    #[test]
    fn jwks_resp_body_max_bytes_zero_rejected() {
        let mut env = fs_env();
        set_jwks_resp_body_max_bytes(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::InvalidValue {
                    var: "HORT_JWKS_RESP_BODY_MAX_SIZE",
                    ..
                }
            ));
        });
    }

    #[test]
    fn jwks_resp_body_max_bytes_non_integer_rejected() {
        let mut env = fs_env();
        set_jwks_resp_body_max_bytes(&mut env, Some("one-meg"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidValue { var, .. } => {
                    assert_eq!(var, "HORT_JWKS_RESP_BODY_MAX_SIZE");
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        });
    }

    #[test]
    fn jwks_resp_body_max_bytes_unset_defaults_to_1_mib() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.jwks_resp_body_max_bytes, 1024 * 1024);
        });
    }

    // -- Rate-limit knobs -----------------------------------------------------

    fn set_ratelimit_auth_per_min(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_RATELIMIT_AUTH_PER_MIN" {
                *slot = ("HORT_RATELIMIT_AUTH_PER_MIN", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_RATELIMIT_AUTH_PER_MIN slot — check fs_env definition");
    }

    fn set_ratelimit_write_per_min(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_RATELIMIT_WRITE_PER_MIN" {
                *slot = ("HORT_RATELIMIT_WRITE_PER_MIN", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_RATELIMIT_WRITE_PER_MIN slot — check fs_env definition");
    }

    #[test]
    fn ratelimit_auth_per_min_unset_defaults_to_60() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.ratelimit_auth_per_min, 60);
        });
    }

    #[test]
    fn ratelimit_write_per_min_unset_defaults_to_300() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.ratelimit_write_per_min, 300);
        });
    }

    #[test]
    fn ratelimit_auth_per_min_explicit_value_parsed() {
        let mut env = fs_env();
        set_ratelimit_auth_per_min(&mut env, Some("120"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.ratelimit_auth_per_min, 120);
        });
    }

    #[test]
    fn ratelimit_write_per_min_explicit_value_parsed() {
        let mut env = fs_env();
        set_ratelimit_write_per_min(&mut env, Some("600"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.ratelimit_write_per_min, 600);
        });
    }

    #[test]
    fn ratelimit_auth_per_min_zero_rejected() {
        let mut env = fs_env();
        set_ratelimit_auth_per_min(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_RATELIMIT_AUTH_PER_MIN",
                    ..
                }
            ));
        });
    }

    #[test]
    fn ratelimit_write_per_min_zero_rejected() {
        let mut env = fs_env();
        set_ratelimit_write_per_min(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_RATELIMIT_WRITE_PER_MIN",
                    ..
                }
            ));
        });
    }

    #[test]
    fn ratelimit_auth_per_min_non_integer_rejected() {
        let mut env = fs_env();
        set_ratelimit_auth_per_min(&mut env, Some("many"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_RATELIMIT_AUTH_PER_MIN");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn ratelimit_write_per_min_non_integer_rejected() {
        let mut env = fs_env();
        set_ratelimit_write_per_min(&mut env, Some("fast"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_RATELIMIT_WRITE_PER_MIN");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn ratelimit_auth_per_min_empty_string_is_default() {
        let mut env = fs_env();
        set_ratelimit_auth_per_min(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.ratelimit_auth_per_min, 60);
        });
    }

    // -- Concurrency caps ------------------------------------------------------

    fn set_max_inflight(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_MAX_INFLIGHT" {
                *slot = ("HORT_MAX_INFLIGHT", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_MAX_INFLIGHT slot — check fs_env definition");
    }

    fn set_max_inflight_per_ip(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_MAX_INFLIGHT_PER_IP" {
                *slot = ("HORT_MAX_INFLIGHT_PER_IP", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_MAX_INFLIGHT_PER_IP slot — check fs_env definition");
    }

    #[test]
    fn max_inflight_unset_defaults_to_512() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.max_inflight, 512);
        });
    }

    #[test]
    fn max_inflight_per_ip_unset_defaults_to_32() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.max_inflight_per_ip, 32);
        });
    }

    #[test]
    fn max_inflight_explicit_value_parsed() {
        let mut env = fs_env();
        set_max_inflight(&mut env, Some("256"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.max_inflight, 256);
        });
    }

    #[test]
    fn max_inflight_per_ip_explicit_value_parsed() {
        let mut env = fs_env();
        set_max_inflight_per_ip(&mut env, Some("64"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.max_inflight_per_ip, 64);
        });
    }

    #[test]
    fn max_inflight_zero_rejected() {
        let mut env = fs_env();
        set_max_inflight(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_MAX_INFLIGHT",
                    ..
                }
            ));
        });
    }

    #[test]
    fn max_inflight_per_ip_zero_rejected() {
        let mut env = fs_env();
        set_max_inflight_per_ip(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_MAX_INFLIGHT_PER_IP",
                    ..
                }
            ));
        });
    }

    #[test]
    fn max_inflight_non_integer_rejected() {
        let mut env = fs_env();
        set_max_inflight(&mut env, Some("many"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => assert_eq!(var, "HORT_MAX_INFLIGHT"),
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    // -- RBAC refresh cadence -------------------------------------------------

    fn set_rbac_refresh_secs(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_RBAC_REFRESH_SECS" {
                *slot = ("HORT_RBAC_REFRESH_SECS", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_RBAC_REFRESH_SECS slot — check fs_env definition");
    }

    #[test]
    fn rbac_refresh_secs_unset_defaults_to_30() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.rbac_refresh_secs, 30);
        });
    }

    #[test]
    fn rbac_refresh_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_rbac_refresh_secs(&mut env, Some("60"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.rbac_refresh_secs, 60);
        });
    }

    #[test]
    fn rbac_refresh_secs_zero_rejected() {
        let mut env = fs_env();
        set_rbac_refresh_secs(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_RBAC_REFRESH_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn rbac_refresh_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_rbac_refresh_secs(&mut env, Some("often"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_RBAC_REFRESH_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn rbac_refresh_secs_empty_string_is_default() {
        let mut env = fs_env();
        set_rbac_refresh_secs(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.rbac_refresh_secs, 30);
        });
    }

    // -- Event-chain checkpoint cadence -------------------------------------

    fn set_event_chain_checkpoint_cadence_secs(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS" {
                *slot = ("HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS", value);
                return;
            }
        }
        panic!(
            "fs_env is missing HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS slot — \
             check fs_env definition"
        );
    }

    #[test]
    fn event_chain_checkpoint_cadence_secs_unset_defaults_to_hourly() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.event_chain_checkpoint_cadence_secs, 3600);
        });
    }

    #[test]
    fn event_chain_checkpoint_cadence_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_event_chain_checkpoint_cadence_secs(&mut env, Some("900"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.event_chain_checkpoint_cadence_secs, 900);
        });
    }

    #[test]
    fn event_chain_checkpoint_cadence_secs_zero_rejected() {
        let mut env = fs_env();
        set_event_chain_checkpoint_cadence_secs(&mut env, Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn event_chain_checkpoint_cadence_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_event_chain_checkpoint_cadence_secs(&mut env, Some("hourly"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_EVENT_CHAIN_CHECKPOINT_CADENCE_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    // -- Stateful-upload staging root --------------------------------------
    //
    // Covers every branch of `parse_stateful_upload_staging_dir`:
    //
    // - Explicit `HORT_STATEFUL_UPLOAD_STAGING_DIR` wins unconditionally.
    // - Filesystem backend + unset env var →
    //   `<HORT_STORAGE_FILESYSTEM_PATH>/stateful-upload-staging`.
    // - S3 backend + unset env var →
    //   `/var/lib/hort/stateful-upload-staging` fallback
    //   documented on `Config::stateful_upload_staging_dir`.
    // - Empty env var is treated as unset (falls through to backend default).

    fn set_stateful_upload_staging_dir(
        env: &mut [(&'static str, Option<&'static str>)],
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == "HORT_STATEFUL_UPLOAD_STAGING_DIR" {
                *slot = ("HORT_STATEFUL_UPLOAD_STAGING_DIR", value);
                return;
            }
        }
        panic!("fs_env is missing HORT_STATEFUL_UPLOAD_STAGING_DIR slot — check fs_env definition");
    }

    #[test]
    fn stateful_upload_staging_dir_explicit_env_wins() {
        let mut env = fs_env();
        set_stateful_upload_staging_dir(&mut env, Some("/custom/path"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.stateful_upload_staging_dir,
                PathBuf::from("/custom/path")
            );
        });
    }

    #[test]
    fn stateful_upload_staging_dir_filesystem_default_derivation() {
        // `fs_env` sets HORT_STORAGE_FILESYSTEM_PATH=/tmp/hort-test and leaves
        // HORT_STATEFUL_UPLOAD_STAGING_DIR unset — exactly the input this
        // test pins.
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.stateful_upload_staging_dir,
                PathBuf::from("/tmp/hort-test/stateful-upload-staging")
            );
        });
    }

    #[test]
    fn stateful_upload_staging_dir_s3_fallback() {
        // S3 backend — HORT_STATEFUL_UPLOAD_STAGING_DIR unset must fall
        // through to the fixed
        // `/var/lib/hort/stateful-upload-staging` default.
        let env: Vec<(&'static str, Option<&'static str>)> = vec![
            ("DATABASE_URL", Some("postgres://x/y")),
            ("HORT_STORAGE_BACKEND", Some("s3")),
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_S3_BUCKET", Some("hort-bucket")),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_ENDPOINT_URL_S3", None),
            ("HORT_STORAGE_S3_FORCE_PATH_STYLE", None),
            ("AWS_ACCESS_KEY_ID", Some("AKIA")),
            ("AWS_SECRET_ACCESS_KEY", Some("SECRET")),
            ("HORT_API_BIND", None),
            ("HORT_METRICS_BIND", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("HORT_METADATA_BLOB_MAX_SIZE", None),
            ("HORT_PUBLIC_BASE_URL", Some("http://hort-server:8080")),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
            ("HORT_STATEFUL_UPLOAD_STAGING_DIR", None),
        ];
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.stateful_upload_staging_dir,
                PathBuf::from("/var/lib/hort/stateful-upload-staging")
            );
        });
    }

    #[test]
    fn stateful_upload_staging_dir_empty_env_falls_through_to_default() {
        // Empty-string env var must behave identically to "unset" —
        // `parse_stateful_upload_staging_dir` treats `Ok("")` as a
        // fall-through so operators can blank the override without
        // swapping backends.
        let mut env = fs_env();
        set_stateful_upload_staging_dir(&mut env, Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.stateful_upload_staging_dir,
                PathBuf::from("/tmp/hort-test/stateful-upload-staging")
            );
        });
    }

    // -- HTTP transport timeouts ----------------------------------------------
    //
    // Three env vars (`HORT_HTTP_HEADER_READ_TIMEOUT_SECS`,
    // `HORT_HTTP_REQUEST_TIMEOUT_SECS`, `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS`),
    // each routed through `parse_positive::<u64>(...)`. The shared
    // parser is already exercised by the rbac/jwks/etc. test suites;
    // here we cover the per-env-var wiring:
    //
    //   - default applied when unset (and when set to empty string)
    //   - explicit value parsed into the right Config field
    //   - zero rejected with ValueNotPositive on the right env var
    //   - non-integer rejected with InvalidInt on the right env var

    fn set_env_slot(
        env: &mut [(&'static str, Option<&'static str>)],
        var: &'static str,
        value: Option<&'static str>,
    ) {
        for slot in env.iter_mut() {
            if slot.0 == var {
                *slot = (var, value);
                return;
            }
        }
        panic!("fs_env is missing {var} slot — check fs_env definition");
    }

    // ---- HORT_HTTP_HEADER_READ_TIMEOUT_SECS --------------------------------

    #[test]
    fn http_header_read_timeout_secs_unset_defaults_to_15() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_header_read_timeout_secs, 15);
        });
    }

    #[test]
    fn http_header_read_timeout_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_HEADER_READ_TIMEOUT_SECS", Some("45"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_header_read_timeout_secs, 45);
        });
    }

    #[test]
    fn http_header_read_timeout_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_HEADER_READ_TIMEOUT_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_HTTP_HEADER_READ_TIMEOUT_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn http_header_read_timeout_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_HTTP_HEADER_READ_TIMEOUT_SECS",
            Some("forever"),
        );
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_HTTP_HEADER_READ_TIMEOUT_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn http_header_read_timeout_secs_empty_string_is_default() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_HEADER_READ_TIMEOUT_SECS", Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_header_read_timeout_secs, 15);
        });
    }

    // ---- HORT_HTTP_REQUEST_TIMEOUT_SECS ------------------------------------

    #[test]
    fn http_request_timeout_secs_unset_defaults_to_300() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_request_timeout_secs, 300);
        });
    }

    #[test]
    fn http_request_timeout_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_REQUEST_TIMEOUT_SECS", Some("120"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_request_timeout_secs, 120);
        });
    }

    #[test]
    fn http_request_timeout_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_REQUEST_TIMEOUT_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_HTTP_REQUEST_TIMEOUT_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn http_request_timeout_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_REQUEST_TIMEOUT_SECS", Some("five"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_HTTP_REQUEST_TIMEOUT_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    // ---- HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS ---------------------------------

    #[test]
    fn http_oci_upload_timeout_secs_unset_defaults_to_3600() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_oci_upload_timeout_secs, 3600);
        });
    }

    #[test]
    fn http_oci_upload_timeout_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS", Some("7200"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.http_oci_upload_timeout_secs, 7200);
        });
    }

    #[test]
    fn http_oci_upload_timeout_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn http_oci_upload_timeout_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS",
            Some("an-hour"),
        );
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }

    // ---- HORT_SHUTDOWN_GRACE_SECS -----------------

    #[test]
    fn shutdown_grace_secs_unset_defaults_to_60() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.shutdown_grace_secs, 60);
        });
    }

    #[test]
    fn shutdown_grace_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_SHUTDOWN_GRACE_SECS", Some("120"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.shutdown_grace_secs, 120);
        });
    }

    #[test]
    fn shutdown_grace_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_SHUTDOWN_GRACE_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_SHUTDOWN_GRACE_SECS",
                    ..
                }
            ));
        });
    }

    // ---- HORT_UPSTREAM_ALLOWLIST_HOSTS --------
    //
    // The tri-state parser lives in `hort-app` (see
    // `UpstreamHostAllowlist::parse` tests there); the tests here pin
    // the integration: the env var lands on `Config.upstream_allowlist`
    // with the right discriminant for each shape.

    #[test]
    fn upstream_allowlist_unset_is_disabled() {
        // Default fs_env leaves `HORT_UPSTREAM_ALLOWLIST_HOSTS=None` —
        // existing deployments must keep the legacy posture.
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.upstream_allowlist,
                hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist::Disabled
            );
        });
    }

    #[test]
    fn upstream_allowlist_empty_string_is_disabled() {
        // The footgun guard. k8s ConfigMap defaults / docker-compose
        // `${VAR:-}` / shell `export VAR=` all silently produce the
        // empty string; treating it as Strict would silently break
        // every upstream pull.
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_UPSTREAM_ALLOWLIST_HOSTS", Some(""));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.upstream_allowlist,
                hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist::Disabled
            );
        });
    }

    #[test]
    fn upstream_allowlist_strict_sentinel_is_strict() {
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_UPSTREAM_ALLOWLIST_HOSTS",
            Some("__deny_all__"),
        );
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(
                cfg.upstream_allowlist,
                hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist::Strict
            );
        });
    }

    #[test]
    fn upstream_allowlist_comma_list_parses_to_hosts() {
        use hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist;
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_UPSTREAM_ALLOWLIST_HOSTS",
            Some("registry.npmjs.org,pypi.org,crates.io"),
        );
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            match cfg.upstream_allowlist {
                UpstreamHostAllowlist::Hosts(hs) => {
                    assert_eq!(hs, vec!["registry.npmjs.org", "pypi.org", "crates.io"]);
                }
                other => panic!("expected Hosts, got {other:?}"),
            }
        });
    }

    // -----------------------------------------------------------------
    // `MinimalConfig` tests.
    //
    // The DB-only subset must parse with only DATABASE_URL set; the
    // serve-shaped vars (HORT_STORAGE_FILESYSTEM_PATH, HORT_PUBLIC_BASE_URL, OIDC_*,
    // HORT_TRUSTED_PROXY_CIDRS, …) MUST NOT be required. The four
    // happy-path / error-path cases below cover the spec.
    // -----------------------------------------------------------------

    /// Slot list that explicitly clears every var `MinimalConfig::from_env`
    /// might consult, so the test environment can't leak in a value
    /// from the developer's shell.
    fn minimal_env_slots() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            // `HORT_DATABASE_URL` is the canonical DSN var; bare
            // `DATABASE_URL` is the compat fallback. Both pinned to None
            // here so neither leaks from the developer's shell.
            ("HORT_DATABASE_URL", None),
            ("DATABASE_URL", None),
            ("HORT_LOG_FORMAT", None),
            ("METRICS_INCLUDE_REPOSITORY_LABEL", None),
            ("PG_STATEMENT_TIMEOUT_MS", None),
            ("PG_ACQUIRE_TIMEOUT_SECS", None),
            // Slots `MinimalConfig` deliberately does NOT consult —
            // setting them to None proves the parser doesn't trip on
            // their absence.
            ("HORT_STORAGE_FILESYSTEM_PATH", None),
            ("HORT_STORAGE_BACKEND", None),
            ("HORT_PUBLIC_BASE_URL", None),
            ("HORT_TRUSTED_PROXY_CIDRS", None),
            ("HORT_AUTH_PROVIDER", None),
            ("HORT_OIDC_ISSUER_URL", None),
            ("HORT_OIDC_AUDIENCE", None),
            // Per-class Redis URL overrides land on
            // `Config`, NOT `MinimalConfig`. DB-only subcommands
            // (`migrate`, `admin bootstrap`, `reconcile-groups`) must
            // not need any Redis env vars to start. Pinning these to
            // None here asserts the minimal parser does not consult
            // them; if a future refactor accidentally adds a Redis
            // parser to the minimal path, the `does_not_require_serve_env`
            // regression test will surface the regression.
            ("HORT_REDIS_URL_EVICTABLE", None),
            ("HORT_REDIS_URL_DURABLE", None),
        ]
    }

    #[test]
    fn minimal_config_happy_path_only_database_url() {
        let mut env = minimal_env_slots();
        set_env_slot(&mut env, "DATABASE_URL", Some("postgres://x/y"));
        temp_env::with_vars(env, || {
            let cfg = MinimalConfig::from_env().expect("MinimalConfig parses");
            assert_eq!(cfg.database_url, "postgres://x/y");
            assert_eq!(cfg.log_format, LogFormat::Pretty); // documented default
            assert!(
                cfg.include_repository_label,
                "default for METRICS_INCLUDE_REPOSITORY_LABEL is true"
            );
            assert_eq!(
                cfg.pg_statement_timeout_ms, None,
                "PG_STATEMENT_TIMEOUT_MS unset → None"
            );
            assert_eq!(
                cfg.pg_acquire_timeout_secs, 30,
                "PG_ACQUIRE_TIMEOUT_SECS unset → 30 s default"
            );
        });
    }

    #[test]
    fn minimal_config_missing_database_url_errors() {
        let env = minimal_env_slots();
        // Both HORT_DATABASE_URL and DATABASE_URL stay None.
        temp_env::with_vars(env, || {
            let err = MinimalConfig::from_env().expect_err("MinimalConfig must require a DSN var");
            // The parser tries `HORT_DATABASE_URL` first then falls back
            // to `DATABASE_URL`; the surfaced Missing variant names
            // whichever was attempted last (`DATABASE_URL`).
            // Accept either name, mirroring the worker's equivalent test.
            assert!(
                matches!(err, ConfigError::Missing(var)
                    if var == "HORT_DATABASE_URL" || var == "DATABASE_URL"),
                "expected Missing(HORT_DATABASE_URL|DATABASE_URL), got {err:?}"
            );
        });
    }

    #[test]
    fn minimal_config_hort_database_url_wins_when_both_set() {
        // `HORT_DATABASE_URL` is canonical and must win over bare
        // `DATABASE_URL` when both are present.
        let mut env = minimal_env_slots();
        set_env_slot(
            &mut env,
            "HORT_DATABASE_URL",
            Some("postgres://canonical/y"),
        );
        set_env_slot(&mut env, "DATABASE_URL", Some("postgres://fallback/y"));
        temp_env::with_vars(env, || {
            let cfg = MinimalConfig::from_env().expect("MinimalConfig parses");
            assert_eq!(
                cfg.database_url, "postgres://canonical/y",
                "HORT_DATABASE_URL must take precedence over DATABASE_URL"
            );
        });
    }

    #[test]
    fn minimal_config_database_url_fallback_when_hort_prefixed_absent() {
        // Bare `DATABASE_URL` remains a load-bearing compat fallback
        // (sqlx-cli / Tier-2 `maybe_pool()` / 12-factor).
        let mut env = minimal_env_slots();
        set_env_slot(&mut env, "DATABASE_URL", Some("postgres://fallback/y"));
        temp_env::with_vars(env, || {
            let cfg = MinimalConfig::from_env().expect("DATABASE_URL fallback parses");
            assert_eq!(cfg.database_url, "postgres://fallback/y");
        });
    }

    #[test]
    fn minimal_config_invalid_log_format_errors() {
        let mut env = minimal_env_slots();
        set_env_slot(&mut env, "DATABASE_URL", Some("postgres://x/y"));
        set_env_slot(&mut env, "HORT_LOG_FORMAT", Some("yaml"));
        temp_env::with_vars(env, || {
            let err = MinimalConfig::from_env().expect_err("HORT_LOG_FORMAT=yaml must error");
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidLogFormat {
                        var: "HORT_LOG_FORMAT",
                        ..
                    }
                ),
                "unexpected error: {err:?}"
            );
        });
    }

    #[test]
    fn minimal_config_pg_pool_tunables_round_trip() {
        let mut env = minimal_env_slots();
        set_env_slot(&mut env, "DATABASE_URL", Some("postgres://x/y"));
        set_env_slot(&mut env, "PG_STATEMENT_TIMEOUT_MS", Some("5000"));
        set_env_slot(&mut env, "PG_ACQUIRE_TIMEOUT_SECS", Some("15"));
        set_env_slot(&mut env, "METRICS_INCLUDE_REPOSITORY_LABEL", Some("false"));
        temp_env::with_vars(env, || {
            let cfg = MinimalConfig::from_env().expect("MinimalConfig parses");
            assert_eq!(cfg.pg_statement_timeout_ms, Some(5000));
            assert_eq!(cfg.pg_acquire_timeout_secs, 15);
            assert!(!cfg.include_repository_label);
        });
    }

    /// Regression test — `MinimalConfig` must NOT require any of the
    /// serve-shaped vars
    /// (`HORT_STORAGE_FILESYSTEM_PATH`, `HORT_PUBLIC_BASE_URL`, `HORT_AUTH_PROVIDER`,
    /// trust-policy fields). If a future refactor accidentally
    /// re-introduces a serve-side parser into the minimal path, this
    /// test fails loud.
    #[test]
    fn minimal_config_does_not_require_serve_env() {
        let mut env = minimal_env_slots();
        set_env_slot(&mut env, "DATABASE_URL", Some("postgres://x/y"));
        // All serve-shaped slots remain None. If MinimalConfig
        // accidentally pulls in `parse_storage` / `parse_public_base_url`
        // / `parse_auth_provider` / `parse_trusted_proxy_cidrs`,
        // any of them will surface a Missing-var error here.
        temp_env::with_vars(env, || {
            MinimalConfig::from_env().expect("MinimalConfig must parse without serve-shaped vars");
        });
    }

    // ---------- parse_secret_env --------------------------------------------

    /// Both file AND inline set with non-empty values → boot-fail.
    #[test]
    fn parse_secret_env_both_set_returns_ambiguous() {
        temp_env::with_vars(
            [
                ("TEST_FILE_VAR", Some("/some/path")),
                ("TEST_INLINE_VAR", Some("inline-value")),
            ],
            || {
                let err = parse_secret_env("TEST_FILE_VAR", "TEST_INLINE_VAR").unwrap_err();
                assert!(
                    matches!(
                        err,
                        ConfigError::AmbiguousSigningKeySource {
                            file_var: "TEST_FILE_VAR",
                            inline_var: "TEST_INLINE_VAR",
                        }
                    ),
                    "unexpected error: {err:?}"
                );
            },
        );
    }

    /// Neither file nor inline set → `Ok(None)`.
    #[test]
    fn parse_secret_env_neither_set_returns_none() {
        temp_env::with_vars(
            [
                ("TEST_FILE_VAR", None::<&str>),
                ("TEST_INLINE_VAR", None::<&str>),
            ],
            || {
                let result =
                    parse_secret_env("TEST_FILE_VAR", "TEST_INLINE_VAR").expect("None is valid");
                assert!(result.is_none());
            },
        );
    }

    /// Only inline set → returns the literal value.
    #[test]
    fn parse_secret_env_inline_only_returns_value() {
        temp_env::with_vars(
            [
                ("TEST_FILE_VAR", None),
                ("TEST_INLINE_VAR", Some("literal")),
            ],
            || {
                let result = parse_secret_env("TEST_FILE_VAR", "TEST_INLINE_VAR").expect("ok");
                assert_eq!(result.as_deref(), Some("literal"));
            },
        );
    }

    /// File-precedence: only file set, file readable → returns file
    /// content. Inline NOT consulted.
    #[test]
    fn parse_secret_env_file_only_reads_path() {
        use std::io::Write as _;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"file-content").unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        temp_env::with_vars(
            [
                ("TEST_FILE_VAR", Some(path.as_str())),
                ("TEST_INLINE_VAR", None),
            ],
            || {
                let result = parse_secret_env("TEST_FILE_VAR", "TEST_INLINE_VAR").expect("ok");
                assert_eq!(result.as_deref(), Some("file-content"));
            },
        );
    }

    /// File set but unreadable → `OciSigningKeyUnreadable`.
    #[test]
    fn parse_secret_env_file_unreadable_returns_error() {
        temp_env::with_vars(
            [
                ("TEST_FILE_VAR", Some("/nonexistent-path-Init28-B8")),
                ("TEST_INLINE_VAR", None),
            ],
            || {
                let err = parse_secret_env("TEST_FILE_VAR", "TEST_INLINE_VAR").unwrap_err();
                assert!(
                    matches!(err, ConfigError::OciSigningKeyUnreadable { .. }),
                    "unexpected error: {err:?}"
                );
            },
        );
    }

    /// Empty values are treated as unset (matches the existing
    /// `require` / `env_or` convention).
    #[test]
    fn parse_secret_env_empty_values_treated_as_unset() {
        temp_env::with_vars(
            [("TEST_FILE_VAR", Some("")), ("TEST_INLINE_VAR", Some(""))],
            || {
                let result = parse_secret_env("TEST_FILE_VAR", "TEST_INLINE_VAR").expect("ok");
                assert!(result.is_none());
            },
        );
    }

    /// `ConfigError::OciPublicBaseUrlMissing`
    /// Display message must (a) name the offending env var, (b) tell
    /// the operator what flips the gate, and (c) point at the resolution.
    /// The composition root surfaces this as `DomainError::Invariant(<display>)`
    /// so the wire shape on a failed boot is the message itself.
    #[test]
    fn oci_public_base_url_missing_display_names_offending_env_var() {
        let err = ConfigError::OciPublicBaseUrlMissing;
        let s = err.to_string();
        assert!(
            s.contains("HORT_PUBLIC_BASE_URL"),
            "display must name the unset env var: {s}"
        );
        assert!(
            s.contains("HORT_NATIVE_TOKENS_ENABLED"),
            "display must name the gating flag: {s}"
        );
    }

    // -- Token-exchange fail-closed validation --------------------------------
    //
    // `HORT_TOKEN_EXCHANGE_ENABLED=true` requires the three env vars that
    // back the `/.well-known/hort-client-config` discovery document
    // (`HORT_OIDC_ISSUER_URL`, `HORT_OIDC_CLI_CLIENT_ID`, `HORT_PUBLIC_BASE_URL`).
    // Boot-fail rather than serve a half-formed document.
    //
    // Each test sets `HORT_TOKEN_EXCHANGE_ENABLED=true` and exactly one
    // missing var. The Display message of the returned ConfigError must
    // name the offending var(s) so an operator can fix the misconfig
    // without spelunking through source.

    #[test]
    fn config_boot_fails_when_token_exchange_on_and_cli_client_id_unset() {
        let env = fs_env_auth(&[
            ("HORT_TOKEN_EXCHANGE_ENABLED", Some("true")),
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example.com/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            // Explicit None: the new env var is unset.
            ("HORT_OIDC_CLI_CLIENT_ID", None),
            // Public base URL is set so it does NOT contribute to the missing list.
            ("HORT_PUBLIC_BASE_URL", Some("https://hort.example.com")),
        ]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().expect_err(
                "boot must fail when HORT_TOKEN_EXCHANGE_ENABLED=true and HORT_OIDC_CLI_CLIENT_ID is unset",
            );
            match err {
                ConfigError::TokenExchangeRequiresVars { missing } => {
                    assert!(
                        missing.contains("HORT_OIDC_CLI_CLIENT_ID"),
                        "missing list must name the unset var; got {missing:?}"
                    );
                    assert!(
                        !missing.contains("HORT_PUBLIC_BASE_URL"),
                        "missing list must NOT name a var that is set; got {missing:?}"
                    );
                    assert!(
                        !missing.contains("HORT_OIDC_ISSUER_URL"),
                        "missing list must NOT name a var that is set; got {missing:?}"
                    );
                }
                other => panic!("expected TokenExchangeRequiresVars, got {other:?}"),
            }
        });
    }

    #[test]
    fn config_boot_fails_when_token_exchange_on_and_public_base_url_unset() {
        let env = fs_env_auth(&[
            ("HORT_TOKEN_EXCHANGE_ENABLED", Some("true")),
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example.com/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            ("HORT_OIDC_CLI_CLIENT_ID", Some("hort-cli")),
            // Empty string: parse_public_base_url falls through to None.
            // Explicit Some("") (rather than None) so the
            // "trust unconfigured" check tripped earlier in `from_env`
            // is not what we observe — we want the URL-validation rule to fire.
            // Trusted-proxy CIDRs are set as a defence-in-depth so the
            // trust check passes (`(false, true)` branch) and execution
            // reaches the URL validation.
            ("HORT_PUBLIC_BASE_URL", Some("")),
            ("HORT_TRUSTED_PROXY_CIDRS", Some("10.0.0.0/8")),
        ]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().expect_err(
                "boot must fail when HORT_TOKEN_EXCHANGE_ENABLED=true and HORT_PUBLIC_BASE_URL is unset",
            );
            match err {
                ConfigError::TokenExchangeRequiresVars { missing } => {
                    assert!(
                        missing.contains("HORT_PUBLIC_BASE_URL"),
                        "missing list must name the unset var; got {missing:?}"
                    );
                }
                other => panic!("expected TokenExchangeRequiresVars, got {other:?}"),
            }
        });
    }

    #[test]
    fn config_boot_fails_when_token_exchange_on_and_auth_disabled() {
        // No HORT_AUTH_PROVIDER → `Disabled`. Issuer URL and CLI client ID
        // are unresolvable; both must surface in the missing list.
        let env = fs_env_auth(&[
            ("HORT_TOKEN_EXCHANGE_ENABLED", Some("true")),
            ("HORT_AUTH_PROVIDER", None),
            ("HORT_PUBLIC_BASE_URL", Some("https://hort.example.com")),
        ]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().expect_err(
                "boot must fail when HORT_TOKEN_EXCHANGE_ENABLED=true under AuthConfig::Disabled",
            );
            match err {
                ConfigError::TokenExchangeRequiresVars { missing } => {
                    assert!(
                        missing.contains("HORT_OIDC_ISSUER_URL"),
                        "missing list must name HORT_OIDC_ISSUER_URL; got {missing:?}"
                    );
                    assert!(
                        missing.contains("HORT_OIDC_CLI_CLIENT_ID"),
                        "missing list must name HORT_OIDC_CLI_CLIENT_ID; got {missing:?}"
                    );
                }
                other => panic!("expected TokenExchangeRequiresVars, got {other:?}"),
            }
        });
    }

    #[test]
    fn config_boot_succeeds_when_token_exchange_off_and_vars_unset() {
        // Default: HORT_TOKEN_EXCHANGE_ENABLED absent → `false`. The new
        // vars are tolerated absent; OIDC config alone (without
        // CLI_CLIENT_ID) must still parse.
        let env = fs_env_auth(&[
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example.com/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            // CLI client id absent — must NOT cause boot-fail because
            // the feature flag is off.
            ("HORT_OIDC_CLI_CLIENT_ID", None),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().expect(
                "boot must succeed when feature is off and HORT_OIDC_CLI_CLIENT_ID is unset",
            );
            assert!(!cfg.enable_token_exchange);
            match &cfg.auth {
                AuthConfig::Oidc(o) => assert!(o.cli_client_id.is_none()),
                AuthConfig::Disabled => panic!("expected Oidc"),
            }
        });
    }

    #[test]
    fn config_boot_succeeds_when_token_exchange_on_and_all_vars_set() {
        // The happy path requires
        // HORT_NATIVE_TOKENS_ENABLED=true (plus the OCI signing key the
        // native-tokens flag mandates). Without it
        // the gate `TokenExchangeRequiresNativeTokens` boots-fail —
        // exchange would mint `hort_cli_*` tokens whose validator is
        // not wired. The signing-key inline value is opaque to
        // Config::from_env (parse-validity is checked at composition
        // time), so a placeholder string is enough to clear the
        // OciTokenSigningKeyMissing gate at this layer.
        let env = fs_env_auth(&[
            ("HORT_TOKEN_EXCHANGE_ENABLED", Some("true")),
            ("HORT_NATIVE_TOKENS_ENABLED", Some("true")),
            ("HORT_OCI_TOKEN_SIGNING_KEY", Some("placeholder-pem")),
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example.com/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            ("HORT_OIDC_CLI_CLIENT_ID", Some("hort-cli")),
            ("HORT_PUBLIC_BASE_URL", Some("https://hort.example.com")),
        ]);
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().expect("happy path must succeed");
            assert!(cfg.enable_token_exchange);
            assert!(cfg.enable_native_tokens);
            match &cfg.auth {
                AuthConfig::Oidc(o) => {
                    assert_eq!(o.cli_client_id.as_deref(), Some("hort-cli"));
                }
                AuthConfig::Disabled => panic!("expected Oidc"),
            }
            assert!(cfg.public_base_url.is_some());
        });
    }

    /// HORT_TOKEN_EXCHANGE_ENABLED=true with
    /// HORT_NATIVE_TOKENS_ENABLED=false (default) MUST boot-fail. This is
    /// the gate that stops operators from accidentally creating a
    /// server that issues PAT-shape tokens (`hort_cli_*`) it cannot
    /// validate. Same fail-closed shape as the existing
    /// `TokenExchangeRequiresVars` family.
    #[test]
    fn config_boot_fails_when_token_exchange_on_and_native_tokens_off() {
        let env = fs_env_auth(&[
            ("HORT_TOKEN_EXCHANGE_ENABLED", Some("true")),
            // HORT_NATIVE_TOKENS_ENABLED unset → default false.
            ("HORT_AUTH_PROVIDER", Some("oidc")),
            (
                "HORT_OIDC_ISSUER_URL",
                Some("https://idp.example.com/realms/hort"),
            ),
            ("HORT_OIDC_AUDIENCE", Some("hort-server")),
            ("HORT_OIDC_CLI_CLIENT_ID", Some("hort-cli")),
            ("HORT_PUBLIC_BASE_URL", Some("https://hort.example.com")),
        ]);
        temp_env::with_vars(env, || {
            let err = Config::from_env().expect_err(
                "boot must fail when HORT_TOKEN_EXCHANGE_ENABLED=true and HORT_NATIVE_TOKENS_ENABLED is unset/false",
            );
            assert!(
                matches!(err, ConfigError::TokenExchangeRequiresNativeTokens),
                "got: {err:?}"
            );
            // Display surfaces both flags + the operator-actionable
            // remediation so the boot log is self-documenting.
            let s = err.to_string();
            assert!(
                s.contains("HORT_TOKEN_EXCHANGE_ENABLED")
                    && s.contains("HORT_NATIVE_TOKENS_ENABLED"),
                "display must name both flags: {s}"
            );
        });
    }

    /// Display message of the new gate must surface the offending
    /// flags and the remediation (mirrors the
    /// `token_exchange_requires_vars_display_names_offending_env_vars`
    /// shape).
    #[test]
    fn token_exchange_requires_native_tokens_display_names_offending_flags() {
        let err = ConfigError::TokenExchangeRequiresNativeTokens;
        let s = err.to_string();
        assert!(
            s.contains("HORT_TOKEN_EXCHANGE_ENABLED"),
            "display must name the consumer flag: {s}"
        );
        assert!(
            s.contains("HORT_NATIVE_TOKENS_ENABLED"),
            "display must name the dependency flag: {s}"
        );
        assert!(
            s.contains("hort_cli_") || s.contains("PAT-shape"),
            "display must explain the structural problem: {s}"
        );
    }

    /// Display message of `TokenExchangeRequiresVars` must surface the
    /// missing-var list and the gating env var so operators can resolve
    /// the misconfig without reading source. Mirrors the
    /// `oci_public_base_url_missing_display_names_offending_env_var` test.
    #[test]
    fn token_exchange_requires_vars_display_names_offending_env_vars() {
        let err = ConfigError::TokenExchangeRequiresVars {
            missing: "HORT_OIDC_CLI_CLIENT_ID".to_string(),
        };
        let s = err.to_string();
        assert!(
            s.contains("HORT_OIDC_CLI_CLIENT_ID"),
            "display must surface the missing var: {s}"
        );
        assert!(
            s.contains("HORT_TOKEN_EXCHANGE_ENABLED"),
            "display must name the gating flag: {s}"
        );
    }

    // ---- HORT_PULL_DEDUP_* -------------------------

    #[test]
    fn pull_dedup_ttl_not_found_secs_unset_defaults_to_30() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_ttl_not_found_secs, 30);
        });
    }

    #[test]
    fn pull_dedup_ttl_not_found_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS", Some("90"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_ttl_not_found_secs, 90);
        });
    }

    #[test]
    fn pull_dedup_ttl_not_found_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn pull_dedup_ttl_unavailable_secs_unset_defaults_to_10() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_ttl_unavailable_secs, 10);
        });
    }

    #[test]
    fn pull_dedup_ttl_unavailable_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_PULL_DEDUP_TTL_UNAVAILABLE_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn pull_dedup_ttl_timeout_secs_unset_defaults_to_10() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_ttl_timeout_secs, 10);
        });
    }

    #[test]
    fn pull_dedup_ttl_timeout_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_PULL_DEDUP_TTL_TIMEOUT_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_PULL_DEDUP_TTL_TIMEOUT_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn pull_dedup_ttl_checksum_mismatch_secs_unset_defaults_to_60() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_ttl_checksum_mismatch_secs, 60);
        });
    }

    #[test]
    fn pull_dedup_ttl_checksum_mismatch_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS",
            Some("0"),
        );
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_PULL_DEDUP_TTL_CHECKSUM_MISMATCH_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn pull_dedup_follower_wait_secs_unset_defaults_to_300() {
        temp_env::with_vars(fs_env(), || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_follower_wait_secs, 300);
        });
    }

    #[test]
    fn pull_dedup_follower_wait_secs_explicit_value_parsed() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS", Some("60"));
        temp_env::with_vars(env, || {
            let cfg = Config::from_env().unwrap();
            assert_eq!(cfg.pull_dedup_follower_wait_secs, 60);
        });
    }

    #[test]
    fn pull_dedup_follower_wait_secs_zero_rejected() {
        let mut env = fs_env();
        set_env_slot(&mut env, "HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS", Some("0"));
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            assert!(matches!(
                err,
                ConfigError::ValueNotPositive {
                    var: "HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS",
                    ..
                }
            ));
        });
    }

    #[test]
    fn pull_dedup_follower_wait_secs_non_integer_rejected() {
        let mut env = fs_env();
        set_env_slot(
            &mut env,
            "HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS",
            Some("not-a-num"),
        );
        temp_env::with_vars(env, || {
            let err = Config::from_env().unwrap_err();
            match err {
                ConfigError::InvalidInt { var, .. } => {
                    assert_eq!(var, "HORT_PULL_DEDUP_FOLLOWER_WAIT_SECS");
                }
                other => panic!("expected InvalidInt, got {other:?}"),
            }
        });
    }
}
