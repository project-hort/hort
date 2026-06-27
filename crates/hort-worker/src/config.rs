//! `WorkerConfig` — env-driven configuration for `hort-worker`.
//!
//! Wraps the shared [`MinimalConfig`]-equivalent slot (database URL + log
//! format) plus the scanner-specific extensions (storage selector, evictable
//! Redis URL, scanner binaries, poll interval, lock duration, worker id).
//! The worker uses the `hort_app_role` Postgres role (ADR 0009): this
//! config does NOT parse anything DDL-related (no admin DSN slot).
//!
//! Health-check validation (at least one scanner backend on PATH) is
//! performed in `composition.rs` after the binaries' `--version` probes
//! run. Parse-time validation here is structural only.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

// -----------------------------------------------------------------
// Public types
// -----------------------------------------------------------------

/// Log-output shape for the global tracing subscriber.
///
/// Mirrors `hort_server::config::LogFormat` field-for-field. We reach
/// into a private dependency for that type rather than copy because
/// the worker binary intentionally does NOT depend on `hort-server`
/// (the design forbids that direction). The two enums are parallel by
/// construction, not by import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

/// Storage backend dispatch — same shape as `hort_server::config::StorageConfig`
/// but parallel-by-construction (no `hort-server` dep). The worker reads
/// the same `HORT_STORAGE_*` env vars so its CAS namespace matches the
/// server's.
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
        allow_http: bool,
        access_key_id: String,
        secret_access_key: String,
    },
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
            } => f
                .debug_struct("S3")
                .field("bucket", bucket)
                .field("region", region)
                .field("endpoint", endpoint)
                .field("force_path_style", force_path_style)
                .field("allow_http", allow_http)
                .field("access_key_id", &"<redacted>")
                .field("secret_access_key", &"<redacted>")
                .finish(),
        }
    }
}

/// Subset of `hort_server::config::MinimalConfig` the worker consumes —
/// database URL + log format. Carried as a struct so callers can read
/// `cfg.minimal.database_url` the same way `hort-server` does.
#[derive(Clone)]
pub struct MinimalConfig {
    pub database_url: String,
    pub log_format: LogFormat,
}

impl std::fmt::Debug for MinimalConfig {
    /// Hand-rolled to redact `database_url` — a DSN with an inline
    /// password whose value would otherwise leak through any `{:?}`
    /// expansion. Mirrors `hort_server::config::Config`'s redacting
    /// `Debug` and the [`StorageConfig`] `<redacted>` placeholder
    /// spelling. `log_format` is non-secret and passes through verbatim.
    /// The exhaustive destructure forces this impl to stay in sync with
    /// the struct — a new field is a compile error here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            database_url: _,
            log_format,
        } = self;
        f.debug_struct("MinimalConfig")
            .field("database_url", &"<redacted>")
            .field("log_format", log_format)
            .finish()
    }
}

/// Full worker configuration. See module doc for the env-var surface.
#[derive(Clone)]
pub struct WorkerConfig {
    pub minimal: MinimalConfig,
    pub storage: StorageConfig,
    /// `HORT_REDIS_URL_EVICTABLE`. Mandatory when an OSV advisory cache
    /// is wired; the binary still parses it unconditionally so a missing
    /// value is loud.
    pub redis_url_evictable: Option<String>,
    /// The load-bearing Trivy enable flag, parsed from
    /// `HORT_SCANNER_TRIVY_ENABLED` (default `true`). When `false`, the
    /// composition root NEVER constructs or registers the Trivy backend,
    /// **regardless of whether the binary `--version` probe would pass**
    /// — the flag is the enabling gate; the probe is a secondary health
    /// check that only runs on flag-enabled backends. This closes the
    /// pre-release "cosmetic only" footgun where
    /// `scanner.trivy.enabled: false` did not reliably disable the
    /// backend (the probe was the real gate).
    pub trivy_enabled: bool,
    pub trivy_bin: PathBuf,
    pub trivy_db_dir: Option<PathBuf>,
    /// The load-bearing OSV-scanner enable flag, parsed from
    /// `HORT_SCANNER_OSV_ENABLED` (default `true`). Same load-bearing
    /// contract as [`Self::trivy_enabled`].
    pub osv_enabled: bool,
    pub osv_scanner_bin: PathBuf,
    /// The load-bearing cosign/Sigstore provenance verifier enable flag,
    /// parsed from `HORT_PROVENANCE_COSIGN_ENABLED` (default `false`).
    /// When `false`, the composition root NEVER constructs or registers the
    /// `ProvenancePort` and does NOT register the
    /// `ProvenanceVerifyHandler` — provenance verification is fully inert.
    /// Same load-bearing contract as [`Self::trivy_enabled`]: the flag is
    /// the enabling gate, not cosmetic. Default-OFF because the verifier
    /// requires a pinned trust root the operator must provision (no
    /// live-fetch fallback — see ADR 0027), so it cannot self-enable
    /// safely.
    pub provenance_cosign_enabled: bool,
    /// Path to the **pinned** Sigstore `trusted_root.json` the cosign
    /// verifier loads at boot. Parsed from
    /// `HORT_PROVENANCE_TRUSTED_ROOT_FILE`. REQUIRED when
    /// `provenance_cosign_enabled` is true (the composition root fails the
    /// boot path loudly when the flag is on but the path is unset/absent —
    /// a `Required` deployment must not boot a verifier with a missing
    /// trust root, ADR 0027). The trust root rotates through the
    /// image/release pipeline, NOT a live TUF fetch (no live client on the
    /// verify path; avoids unchecked-TUF-fetch; ADR 0010).
    pub provenance_trusted_root_file: Option<PathBuf>,
    /// Path to a file of one-or-more PEM ECDSA P-256 public keys for the
    /// **keyed** cosign verifier (`cosign-key`, ADR 0039 §3). Parsed from
    /// `HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE`. Its presence is the keyed
    /// backend's enabling gate — independent of [`Self::provenance_cosign_enabled`],
    /// which gates the keyless Sigstore backend: when set, the composition root
    /// loads the pinned public-key set and registers the `cosign-key`
    /// `ProvenancePort`. No live fetch; the set rotates via the mounted secret
    /// (rotation overlap = multiple keys in the file).
    pub provenance_cosign_public_keys_file: Option<PathBuf>,
    pub advisory_osv_url: String,
    /// Base URL for the per-ecosystem `osv-vulnerabilities` bulk archive
    /// host consumed by [`AdvisoryWatchTickHandler`]. Distinct from
    /// `advisory_osv_url` (the per-component `querybatch` endpoint).
    /// Default: `https://osv-vulnerabilities.storage.googleapis.com`.
    pub advisory_osv_bulk_url: String,
    /// Comma-parsed list of ecosystem labels the advisory-watch tick pulls
    /// per invocation. Each entry must match an OSV bulk-archive path
    /// segment verbatim. `None` means "use the adapter's default
    /// eight-ecosystem set" (see [`OsvAdvisoryConfig::default`]).
    pub advisory_watch_ecosystems: Option<Vec<String>>,
    /// Staging root for the `staging-sweep` task handler (the worker owns
    /// the sweep). Mirrors `hort-server`'s
    /// `HORT_STATEFUL_UPLOAD_STAGING_DIR` resolution: explicit env wins,
    /// else `<filesystem_root>/stateful-upload-staging`, else fixed
    /// `/var/lib/hort/stateful-upload-staging` for S3.
    pub stateful_upload_staging_dir: PathBuf,
    pub poll_interval: Duration,
    pub batch_size: u32,
    pub max_attempts: u32,
    pub lock_duration: Duration,
    pub worker_id: String,
    /// Set of k8s namespaces the `ServiceAccountRotationHandler` is
    /// permitted to write Secrets in. Sourced from
    /// `HORT_ROTATION_TARGET_NAMESPACES` (comma-separated). Default empty
    /// — the handler runs but every SA gets `namespace_not_authorized`,
    /// which is a safe no-op on non-k8s deployments. The Helm chart wires
    /// this from `worker.rotation.targetNamespaces`.
    pub rotation_namespaces: HashSet<String>,
    /// Registry host embedded in the `dockerconfigjson` `auths` map key.
    /// Sourced from `HORT_PUBLIC_REGISTRY_HOST`. Optional at parse time;
    /// the composition root enforces presence when the
    /// `KubernetesSecretWriter` adapter is wired.
    pub public_registry_host: Option<String>,
    /// When `false`, the per-SA label on `hort_rotation_lag_seconds`
    /// collapses to `service_account="_all"`. Parsed from
    /// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL` (default `true`) — same
    /// env var hort-server reads, so the rotation gauge and the
    /// federation/PAT auth counter remain in lock-step under
    /// operator-flipped cardinality control.
    pub include_service_account_label: bool,
    /// Run the refcount-reconcile sweep at worker boot before registering
    /// the retention handlers, flipping the in-process
    /// `RefcountReconcileGate` true only on a successful sweep. Mirrors
    /// `hort-server`'s `HORT_REFCOUNT_RECONCILE_ON_STARTUP` (default
    /// `true`: fresh-install posture; an upgrade install with authoritative
    /// state sets it `false` and the operator asserts convergence).
    /// `RetentionPurgeHandler` refuses to run while the gate is false
    /// (fail-safe, retried).
    pub refcount_reconcile_on_startup: bool,
    /// Optional dedicated DSN connected as `hort_retention_role` (the
    /// DELETE-capable role per ADR 0009 §10.2). When `Some`,
    /// `EventStoreArchiveHandler`'s `EventStorePublisher` uses a second
    /// pool over this DSN so its `delete_stream` can actually remove
    /// sealed rows. When `None`, the handler uses the `hort_app_role`
    /// pool and every `delete_stream` fails fail-safe via the still-active
    /// `events_immutable` trigger (the seal-tombstone-first transaction
    /// rolls back, zero rows removed — one fewer branch, no
    /// special-case).
    pub retention_database_url: Option<String>,
    /// The audit-retention floors, resolved here from the same
    /// `HORT_RETENTION_FLOOR_*_DAYS` env vars and the same MIN clamps
    /// `hort-server` uses. `AuditRetentionFloors` lives in `hort-server`
    /// config but the retention composition root is `hort-worker`;
    /// `hort-app` must not depend on `hort-server`, so the resolution is
    /// duplicated here. Fed positionally into `canonical_retention_rules(...)`
    /// by the composition root.
    pub audit_retention_floors: AuditRetentionFloors,
    /// The one global v1 stream-retention mode (`HORT_RETENTION_STREAM_MODE`
    /// ∈ `{delete, archive}`; `archive` requires a non-empty
    /// `HORT_RETENTION_ARCHIVE_TARGET`). Mirrors
    /// `hort-server::config::StreamRetentionMode`.
    pub retention_stream_mode: RetentionStreamMode,
    /// Defense-in-depth Postgres `lock_timeout` (in ms) applied via
    /// `.after_connect` to **both** worker pools (the main pool and the
    /// optional `hort_retention_role` retention pool). It bounds *only*
    /// lock-acquisition wait, so it fires on the pathological "blocked on
    /// a peer's uncommitted unique slot" case and never aborts a
    /// legitimately slow large-stream `DELETE`.
    ///
    /// Sourced from `HORT_WORKER_LOCK_TIMEOUT_MS`; default `120000`
    /// (2 min) — generous on purpose, because the single-flight
    /// precondition means it must never fire in correct operation; a
    /// small value risks a false abort if single-flight is ever
    /// deliberately relaxed. `0` disables the backstop (Postgres
    /// default; the composition root skips the `after_connect` `SET`
    /// entirely) — an operator escape hatch. Setting `0` re-opens the
    /// unbounded-block failure mode this backstop covers (see ADR 0020).
    pub lock_timeout_ms: u64,
    /// Bind address for the worker's internal-only `GET /metrics`
    /// Prometheus scrape listener. The worker installs a Prometheus
    /// recorder at boot; this listener makes the metrics scrapeable.
    ///
    /// Sourced from `HORT_WORKER_METRICS_BIND`. **Default: disabled (`None`)**
    /// — opt-in observability. Operators scraping from a cluster-network
    /// Prometheus set a pod-reachable address (e.g. `0.0.0.0:9090`); `off`
    /// (case-insensitive) is the explicit disable; a malformed address is a
    /// loud boot-path config error, never a silent fallback.
    ///
    /// **Auth posture.** The worker has **no inbound-HTTP auth stack** (it
    /// is a background processor, not an API surface), so mounting the
    /// server's metrics auth middleware would drag the entire
    /// auth/`AppContext` machinery into the worker — disproportionate for
    /// one scrape route. Instead this listener has **no per-request auth**;
    /// exposure is controlled by the operator-chosen bind + a **mandatory
    /// NetworkPolicy** (the `repository` labels carry repo names, so it
    /// must never be world-reachable). This is the standard pod-metrics
    /// pattern and the objectively-cheaper control.
    pub metrics_bind_addr: Option<std::net::SocketAddr>,
}

impl std::fmt::Debug for WorkerConfig {
    /// Hand-rolled to redact the DSN-bearing fields whose inline
    /// passwords would otherwise leak through any `{:?}` expansion:
    /// `redis_url_evictable` and `retention_database_url` (both
    /// `Option`), plus the nested `minimal.database_url` and the S3
    /// credentials inside `storage` (each redacted by its own `Debug`).
    /// Mirrors `hort_server::config::Config`'s redacting `Debug`: the
    /// optional DSN fields surface only their structural shape
    /// (`Some("<redacted>")` / `None`) so a reader of `?cfg` can tell the
    /// override is configured without seeing the value, and every other
    /// field passes through verbatim. The exhaustive destructure forces
    /// this impl to stay in sync with the struct — a new field is a
    /// compile error here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            minimal,
            storage,
            redis_url_evictable: _,
            trivy_enabled,
            trivy_bin,
            trivy_db_dir,
            osv_enabled,
            osv_scanner_bin,
            provenance_cosign_enabled,
            provenance_trusted_root_file,
            provenance_cosign_public_keys_file,
            advisory_osv_url,
            advisory_osv_bulk_url,
            advisory_watch_ecosystems,
            stateful_upload_staging_dir,
            poll_interval,
            batch_size,
            max_attempts,
            lock_duration,
            worker_id,
            rotation_namespaces,
            public_registry_host,
            include_service_account_label,
            refcount_reconcile_on_startup,
            retention_database_url: _,
            audit_retention_floors,
            retention_stream_mode,
            lock_timeout_ms,
            metrics_bind_addr,
        } = self;
        f.debug_struct("WorkerConfig")
            .field("minimal", minimal)
            .field("storage", storage)
            // DSN with inline password — surface only the structural
            // shape (`Some("<redacted>")` / `None`).
            .field(
                "redis_url_evictable",
                &self.redis_url_evictable.as_ref().map(|_| "<redacted>"),
            )
            .field("trivy_enabled", trivy_enabled)
            .field("trivy_bin", trivy_bin)
            .field("trivy_db_dir", trivy_db_dir)
            .field("osv_enabled", osv_enabled)
            .field("osv_scanner_bin", osv_scanner_bin)
            .field("provenance_cosign_enabled", provenance_cosign_enabled)
            .field("provenance_trusted_root_file", provenance_trusted_root_file)
            .field(
                "provenance_cosign_public_keys_file",
                provenance_cosign_public_keys_file,
            )
            .field("advisory_osv_url", advisory_osv_url)
            .field("advisory_osv_bulk_url", advisory_osv_bulk_url)
            .field("advisory_watch_ecosystems", advisory_watch_ecosystems)
            .field("stateful_upload_staging_dir", stateful_upload_staging_dir)
            .field("poll_interval", poll_interval)
            .field("batch_size", batch_size)
            .field("max_attempts", max_attempts)
            .field("lock_duration", lock_duration)
            .field("worker_id", worker_id)
            .field("rotation_namespaces", rotation_namespaces)
            .field("public_registry_host", public_registry_host)
            .field(
                "include_service_account_label",
                include_service_account_label,
            )
            .field(
                "refcount_reconcile_on_startup",
                refcount_reconcile_on_startup,
            )
            // DSN with inline password — surface only the structural
            // shape (`Some("<redacted>")` / `None`).
            .field(
                "retention_database_url",
                &self.retention_database_url.as_ref().map(|_| "<redacted>"),
            )
            .field("audit_retention_floors", audit_retention_floors)
            .field("retention_stream_mode", retention_stream_mode)
            .field("lock_timeout_ms", lock_timeout_ms)
            .field("metrics_bind_addr", metrics_bind_addr)
            .finish()
    }
}

/// Audit-retention floors, resolved in `hort-worker` from the same env
/// vars + MIN clamps as `hort-server::config::AuditRetentionFloors`.
/// Duplicated (not shared) because `hort-app`/`hort-worker` must not
/// depend on `hort-server`; the floor *values* are identical by
/// construction (same env vars, same `MIN_*` constants, same resolution).
/// The composition root passes the per-category `Duration`s positionally
/// into `canonical_retention_rules(...)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionFloors {
    pub authentication: Duration,
    pub artifact_lifecycle: Duration,
    pub artifact_downloaded: Duration,
    pub api_token_used: Duration,
}

impl AuditRetentionFloors {
    /// Documented minimum floor values (day counts; months as 30-day
    /// units). Byte-identical to `hort-server::config::AuditRetentionFloors`.
    pub const MIN_AUTHENTICATION_DAYS: i64 = 180;
    pub const MIN_ARTIFACT_DOWNLOADED_DAYS: i64 = 90;
    pub const MIN_API_TOKEN_USED_DAYS: i64 = 1080;
    pub const MIN_ARTIFACT_LIFECYCLE_DAYS: i64 = 1;

    fn c1_defaults() -> Self {
        Self {
            authentication: Duration::from_secs(Self::MIN_AUTHENTICATION_DAYS as u64 * 86_400),
            artifact_lifecycle: Duration::from_secs(1080 * 86_400),
            artifact_downloaded: Duration::from_secs(
                Self::MIN_ARTIFACT_DOWNLOADED_DAYS as u64 * 86_400,
            ),
            api_token_used: Duration::from_secs(Self::MIN_API_TOKEN_USED_DAYS as u64 * 86_400),
        }
    }
}

/// Worker mirror of `hort-server::config::StreamRetentionMode`
/// (the one global v1 stream-retention mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionStreamMode {
    Delete,
    Archive { target_prefix: String },
}

/// Concrete error per config field.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("invalid value for {var}: {reason}")]
    InvalidValue { var: &'static str, reason: String },
    #[error("invalid storage backend (var={var}): {got}")]
    InvalidStorageBackend { var: &'static str, got: String },
    #[error("invalid log format (var={var}): {got}")]
    InvalidLogFormat { var: &'static str, got: String },
}

// -----------------------------------------------------------------
// Parser
// -----------------------------------------------------------------

impl WorkerConfig {
    /// Parse the full worker config from process environment.
    ///
    /// Mirrors the [`Config::from_env`](`hort-server`) shape: pure
    /// `std::env::var` reads with no logging side effects.
    pub fn from_env() -> Result<Self, ConfigError> {
        let minimal = MinimalConfig {
            database_url: require("HORT_DATABASE_URL").or_else(|_| require("DATABASE_URL"))?,
            log_format: parse_log_format()?,
        };
        let storage = parse_storage()?;
        let redis_url_evictable = optional("HORT_REDIS_URL_EVICTABLE");
        // Load-bearing scanner enable flags. Default `true` preserves the
        // default-enabled posture (both backends register when their
        // probes pass); an explicit `false` drops that backend before the
        // probe runs.
        let trivy_enabled = parse_bool_default("HORT_SCANNER_TRIVY_ENABLED", true)?;
        let trivy_bin = path_or_default("HORT_SCANNER_TRIVY_BIN", "trivy");
        let trivy_db_dir = optional("HORT_SCANNER_TRIVY_DB_DIR").map(PathBuf::from);
        let osv_enabled = parse_bool_default("HORT_SCANNER_OSV_ENABLED", true)?;
        let osv_scanner_bin = path_or_default("HORT_SCANNER_OSV_BIN", "osv-scanner");
        // Load-bearing cosign provenance enable flag + pinned trust-root
        // path. Default OFF: the verifier needs an operator-provisioned
        // trust root, so it cannot self-enable. The composition root
        // enforces the path's presence when the flag is on (a
        // `Required`-mode deployment must not boot a verifier with a
        // missing trust root; see ADR 0027).
        let provenance_cosign_enabled =
            parse_bool_default("HORT_PROVENANCE_COSIGN_ENABLED", false)?;
        let provenance_trusted_root_file =
            optional("HORT_PROVENANCE_TRUSTED_ROOT_FILE").map(PathBuf::from);
        let provenance_cosign_public_keys_file =
            optional("HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE").map(PathBuf::from);
        let advisory_osv_url = env_or(
            "HORT_ADVISORY_OSV_API_URL",
            "https://api.osv.dev/v1/querybatch",
        );
        let advisory_osv_bulk_url = env_or(
            "HORT_ADVISORY_OSV_BULK_URL",
            "https://osv-vulnerabilities.storage.googleapis.com",
        );
        // When the env var is unset, pass `None` so the OSV adapter
        // falls back to its built-in eight-ecosystem default (which uses
        // the OSV-canonical labels `crates.io` / `Packagist`).
        let advisory_watch_ecosystems = optional("HORT_ADVISORY_WATCH_ECOSYSTEMS").map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        });
        let stateful_upload_staging_dir = parse_stateful_upload_staging_dir(&storage);
        let poll_interval =
            Duration::from_secs(parse_u64_default("HORT_SCANNER_POLL_INTERVAL_SECS", 5)?);
        let batch_size = parse_u32_default("HORT_SCANNER_BATCH_SIZE", 4)?;
        let max_attempts = parse_u32_default("HORT_SCANNER_MAX_ATTEMPTS", 5)?;
        let lock_duration =
            Duration::from_secs(parse_u64_default("HORT_SCANNER_LOCK_DURATION_SECS", 900)?);
        let worker_id = parse_worker_id();
        // Rotation handler target namespaces + registry host. Empty
        // default for namespaces is safe; missing
        // `HORT_PUBLIC_REGISTRY_HOST` is surfaced as `None` and the
        // composition root decides whether to wire the rotation handler.
        let rotation_namespaces = parse_rotation_namespaces();
        let public_registry_host = optional("HORT_PUBLIC_REGISTRY_HOST");
        // Share the SA-label cardinality switch with hort-server.
        // Default `true`.
        let include_service_account_label =
            parse_bool_default("METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL", true)?;
        // Mirrors hort-server's HORT_REFCOUNT_RECONCILE_ON_STARTUP
        // (default true: fresh-install). See ADR 0020.
        let refcount_reconcile_on_startup =
            parse_bool_default("HORT_REFCOUNT_RECONCILE_ON_STARTUP", true)?;
        // Optional dedicated hort_retention_role DSN (ADR 0009 §10.2).
        let retention_database_url = optional("HORT_RETENTION_DATABASE_URL");
        // The audit-retention floors, resolved from the same env vars +
        // MIN clamps hort-server uses (duplicated, not shared).
        let audit_retention_floors = {
            let d = AuditRetentionFloors::c1_defaults();
            AuditRetentionFloors {
                authentication: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_AUTHENTICATION_DAYS",
                    AuditRetentionFloors::MIN_AUTHENTICATION_DAYS,
                    d.authentication,
                )?,
                artifact_lifecycle: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_ARTIFACT_LIFECYCLE_DAYS",
                    AuditRetentionFloors::MIN_ARTIFACT_LIFECYCLE_DAYS,
                    d.artifact_lifecycle,
                )?,
                artifact_downloaded: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_ARTIFACT_DOWNLOADED_DAYS",
                    AuditRetentionFloors::MIN_ARTIFACT_DOWNLOADED_DAYS,
                    d.artifact_downloaded,
                )?,
                api_token_used: resolve_retention_floor_days(
                    "HORT_RETENTION_FLOOR_API_TOKEN_USED_DAYS",
                    AuditRetentionFloors::MIN_API_TOKEN_USED_DAYS,
                    d.api_token_used,
                )?,
            }
        };
        // The one global v1 stream-retention mode (mirrors
        // hort-server's HORT_RETENTION_STREAM_MODE; `archive` requires
        // a non-empty target — a missing target hard-fails rather than
        // silently degrading to delete = data loss).
        let retention_stream_mode = match std::env::var("HORT_RETENTION_STREAM_MODE") {
            Ok(v) if !v.is_empty() => match v.to_ascii_lowercase().as_str() {
                "delete" => RetentionStreamMode::Delete,
                "archive" => {
                    let target = optional("HORT_RETENTION_ARCHIVE_TARGET").ok_or_else(|| {
                        ConfigError::InvalidValue {
                            var: "HORT_RETENTION_ARCHIVE_TARGET",
                            reason: "HORT_RETENTION_STREAM_MODE=archive requires a \
                                     non-empty HORT_RETENTION_ARCHIVE_TARGET prefix"
                                .into(),
                        }
                    })?;
                    RetentionStreamMode::Archive {
                        target_prefix: target,
                    }
                }
                other => {
                    return Err(ConfigError::InvalidValue {
                        var: "HORT_RETENTION_STREAM_MODE",
                        reason: format!("expected one of [delete, archive], got {other:?}"),
                    })
                }
            },
            _ => RetentionStreamMode::Delete,
        };
        // Defense-in-depth seal-pool lock_timeout (ADR 0020). `0` is a
        // valid, documented value here (disables the backstop), so this
        // uses the plain `parse_u64_default` helper rather than a
        // positive-only parser: unlike statement_timeout, `0` is the
        // intended escape hatch, not a footgun.
        let lock_timeout_ms = parse_u64_default("HORT_WORKER_LOCK_TIMEOUT_MS", 120_000)?;
        // Worker `/metrics` listener bind. Disabled by default (opt-in);
        // `off` disables explicitly; malformed → loud error.
        let metrics_bind_addr = parse_metrics_bind_addr()?;
        Ok(Self {
            minimal,
            storage,
            redis_url_evictable,
            trivy_enabled,
            trivy_bin,
            trivy_db_dir,
            osv_enabled,
            osv_scanner_bin,
            provenance_cosign_enabled,
            provenance_trusted_root_file,
            provenance_cosign_public_keys_file,
            advisory_osv_url,
            advisory_osv_bulk_url,
            advisory_watch_ecosystems,
            stateful_upload_staging_dir,
            poll_interval,
            batch_size,
            max_attempts,
            lock_duration,
            worker_id,
            rotation_namespaces,
            public_registry_host,
            include_service_account_label,
            refcount_reconcile_on_startup,
            retention_database_url,
            audit_retention_floors,
            retention_stream_mode,
            lock_timeout_ms,
            metrics_bind_addr,
        })
    }
}

/// Resolve `HORT_WORKER_METRICS_BIND`.
///
/// - Unset / empty / `off` (case-insensitive) → `None` (listener disabled —
///   opt-in observability). A loopback default was rejected: it runs a
///   listener no cluster-network Prometheus can reach. Operators enabling
///   scraping set a pod-reachable address (e.g. `0.0.0.0:9090`) and gate it
///   with a NetworkPolicy (see the field doc on `metrics_bind_addr`).
/// - Anything else → parsed as a `SocketAddr`; a malformed value is a loud
///   `InvalidValue` boot error (never a silent fallback — an operator who
///   typo'd the bind address must learn at boot, not discover a missing
///   scrape target later).
fn parse_metrics_bind_addr() -> Result<Option<std::net::SocketAddr>, ConfigError> {
    const VAR: &str = "HORT_WORKER_METRICS_BIND";
    match optional(VAR) {
        None => Ok(None),
        Some(v) if v.eq_ignore_ascii_case("off") => Ok(None),
        Some(v) => {
            v.parse::<std::net::SocketAddr>()
                .map(Some)
                .map_err(|e| ConfigError::InvalidValue {
                    var: VAR,
                    reason: format!("expected a host:port SocketAddr or `off`, got {v:?}: {e}"),
                })
        }
    }
}

/// Mirror of `hort-server::config::resolve_retention_floor_days`.
/// An override below the documented minimum is a hard startup failure;
/// unset → the default. Duplicated (not shared) because `hort-worker`
/// must not depend on `hort-server`.
fn resolve_retention_floor_days(
    var: &'static str,
    min_days: i64,
    default: Duration,
) -> Result<Duration, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => {
            let parsed: i64 = v.parse().map_err(|e| ConfigError::InvalidValue {
                var,
                reason: format!("expected an integer day count, got {v:?}: {e}"),
            })?;
            if parsed < min_days {
                return Err(ConfigError::InvalidValue {
                    var,
                    reason: format!("must be >= {min_days} (minimum; got {parsed})"),
                });
            }
            Ok(Duration::from_secs(parsed as u64 * 86_400))
        }
        _ => Ok(default),
    }
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

fn require(var: &'static str) -> Result<String, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(var)),
    }
}

fn optional(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn env_or(var: &str, default: &str) -> String {
    optional(var).unwrap_or_else(|| default.to_string())
}

fn path_or_default(var: &str, default: &str) -> PathBuf {
    PathBuf::from(env_or(var, default))
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

fn parse_u64_default(var: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v.parse::<u64>().map_err(|e| ConfigError::InvalidValue {
            var,
            reason: format!("expected u64, got {v:?}: {e}"),
        }),
        _ => Ok(default),
    }
}

fn parse_u32_default(var: &'static str, default: u32) -> Result<u32, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v.parse::<u32>().map_err(|e| ConfigError::InvalidValue {
            var,
            reason: format!("expected u32, got {v:?}: {e}"),
        }),
        _ => Ok(default),
    }
}

/// Parse a human-readable byte-size string to a byte count.
///
/// Mirror of `hort-server::config::parse_byte_size`. Duplicated (not
/// shared) because `hort-worker` must not depend on `hort-server`
/// (same rationale as [`resolve_retention_floor_days`]).
///
/// Accepts a bare byte integer (`67108864`), a binary-suffixed value
/// (`64Ki`, `64Mi`, `1Gi`, `2Ti` — multiples of 1024), or a decimal-
/// suffixed value (`64k`, `64M`, `1G`, `2T` — multiples of 1000). A
/// trailing `B`/`iB` is tolerated (`64MiB` == `64Mi`). The unit is
/// case-insensitive — a byte-size knob never means SI milli, so `m` is
/// treated as mega (1000²), not milli. Fractional magnitudes are allowed
/// (`1.5Gi`) and rounded to the nearest byte.
///
/// Size strings are the operator surface (not bare integers) so a
/// multi-GiB value can never round-trip through Helm's float64 coercion
/// into scientific notation — the rc.3 boot-crash class this closes.
pub(crate) fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }
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

/// Resolve an operator byte-cap env var that accepts a size string,
/// falling back to `default` when the var is unset, empty, or malformed.
///
/// The scanner caps preserve "unset/invalid → adapter default" semantics
/// (the registration path is best-effort tunable, not a hard-fail boot
/// knob), but the operator surface is now a size string rather than a
/// bare integer so a multi-GiB value can never round-trip through Helm's
/// float64 coercion.
pub(crate) fn parse_byte_size_or(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .and_then(|v| parse_byte_size(&v).ok())
        .unwrap_or(default)
}

/// Resolve `HORT_WORKER_ID`:
/// 1. Use the env var verbatim if set and non-empty.
/// 2. Else use `${POD_NAME}-${random8hex}` when `POD_NAME` is set
///    (Kubernetes downward-API friendly).
/// 3. Else `pod-${random8hex}` (local-dev fallback).
fn parse_worker_id() -> String {
    if let Some(explicit) = optional("HORT_WORKER_ID") {
        return explicit;
    }
    let pod = optional("POD_NAME").unwrap_or_else(|| "pod".to_string());
    let suffix = random_hex_suffix();
    format!("{pod}-{suffix}")
}

/// 8-hex-char random suffix using `rand::random::<u32>()`. Wide enough
/// that two workers booting in the same second within the same pod
/// don't collide; small enough that the worker id stays short in logs.
fn random_hex_suffix() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u32 = rng.gen();
    format!("{n:08x}")
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
            let bucket = require("HORT_STORAGE_S3_BUCKET")?;
            let region = std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .map_err(|_| ConfigError::Missing("AWS_REGION"))?;
            let endpoint = optional("AWS_ENDPOINT_URL_S3").or_else(|| optional("AWS_ENDPOINT_URL"));
            let force_path_style = parse_bool_default("HORT_STORAGE_S3_FORCE_PATH_STYLE", false)?;
            let allow_http = parse_bool_default("HORT_STORAGE_S3_ALLOW_HTTP", false)?;
            Ok(StorageConfig::S3 {
                bucket,
                region,
                endpoint,
                force_path_style,
                allow_http,
                access_key_id: require("AWS_ACCESS_KEY_ID")?,
                secret_access_key: require("AWS_SECRET_ACCESS_KEY")?,
            })
        }
        _ => Err(ConfigError::InvalidStorageBackend {
            var: "HORT_STORAGE_BACKEND",
            got: backend,
        }),
    }
}

/// Parse `HORT_ROTATION_TARGET_NAMESPACES` (comma-separated list of k8s
/// namespaces) into a `HashSet<String>`.
///
/// Same trim + drop-empty semantics as [`parse_storage`]'s
/// `advisory_watch_ecosystems` parser. Default empty — the rotation
/// handler runs but every SA gets `namespace_not_authorized`, which is a
/// safe no-op on non-k8s deployments where the operator hasn't opted in.
fn parse_rotation_namespaces() -> HashSet<String> {
    optional("HORT_ROTATION_TARGET_NAMESPACES")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the staging root for the `staging-sweep` task handler.
/// Mirrors `hort_server::config::parse_stateful_upload_staging_dir`:
/// explicit `HORT_STATEFUL_UPLOAD_STAGING_DIR` wins; else the filesystem
/// CAS root's `stateful-upload-staging` sibling; else a fixed S3
/// fallback. The sweep does not need a writable filesystem on every
/// replica — `staging-sweep` runs at concurrency=1 and the operator is
/// expected to override the path on S3-backed deployments via the chart.
fn parse_stateful_upload_staging_dir(storage: &StorageConfig) -> PathBuf {
    if let Some(v) = optional("HORT_STATEFUL_UPLOAD_STAGING_DIR") {
        return PathBuf::from(v);
    }
    match storage {
        StorageConfig::Filesystem { root } => root.join("stateful-upload-staging"),
        StorageConfig::S3 { .. } => PathBuf::from("/var/lib/hort/stateful-upload-staging"),
    }
}

fn parse_bool_default(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v.parse::<bool>().map_err(|e| ConfigError::InvalidValue {
            var,
            reason: format!("expected bool, got {v:?}: {e}"),
        }),
        _ => Ok(default),
    }
}

// -----------------------------------------------------------------
// Tests
// -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Tests use `temp-env` semantics by reading/writing process env
    //! within `unsafe` not allowed → the project's pattern is to use
    //! the global env directly under a `serial_test` style guard.
    //! We avoid pulling another crate by serialising via a global
    //! mutex and clearing the relevant slots between tests.

    use super::*;
    use std::sync::Mutex;

    /// All env-touching tests share one mutex. Each test clears the
    /// slots it cares about before populating its inputs and restores
    /// nothing — every test starts from a known-clean baseline.
    /// Lock acquisition tolerates `PoisonError` (a sibling test that
    /// panicked while holding the lock would otherwise cascade) by
    /// extracting the inner guard via `into_inner` semantics.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: Mutex<()> = Mutex::new(());
        &LOCK
    }

    /// Acquire the mutex; on `PoisonError`, recover the guard so a
    /// prior panicking sibling does not abort downstream tests.
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Slots the worker config consults — every test clears these to
    /// avoid leakage from outer-test/env state.
    const SLOTS: &[&str] = &[
        "HORT_DATABASE_URL",
        "DATABASE_URL",
        "HORT_LOG_FORMAT",
        "HORT_STORAGE_BACKEND",
        "HORT_STORAGE_FILESYSTEM_PATH",
        "HORT_STORAGE_S3_BUCKET",
        "HORT_STORAGE_S3_FORCE_PATH_STYLE",
        "HORT_STORAGE_S3_ALLOW_HTTP",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_S3",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "HORT_REDIS_URL_EVICTABLE",
        // Load-bearing scanner enable flags.
        "HORT_SCANNER_TRIVY_ENABLED",
        "HORT_SCANNER_OSV_ENABLED",
        "HORT_SCANNER_TRIVY_BIN",
        "HORT_SCANNER_TRIVY_DB_DIR",
        "HORT_SCANNER_OSV_BIN",
        // Load-bearing cosign provenance flag + pinned trust-root path.
        "HORT_PROVENANCE_COSIGN_ENABLED",
        "HORT_PROVENANCE_TRUSTED_ROOT_FILE",
        "HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE",
        "HORT_ADVISORY_OSV_API_URL",
        "HORT_ADVISORY_OSV_BULK_URL",
        "HORT_ADVISORY_WATCH_ECOSYSTEMS",
        "HORT_STATEFUL_UPLOAD_STAGING_DIR",
        "HORT_SCANNER_POLL_INTERVAL_SECS",
        "HORT_SCANNER_BATCH_SIZE",
        "HORT_SCANNER_MAX_ATTEMPTS",
        "HORT_SCANNER_LOCK_DURATION_SECS",
        "HORT_WORKER_ID",
        "POD_NAME",
        // Rotation handler env-var surface.
        "HORT_ROTATION_TARGET_NAMESPACES",
        "HORT_PUBLIC_REGISTRY_HOST",
        // Defense-in-depth worker-pool lock_timeout knob (ADR 0020).
        "HORT_WORKER_LOCK_TIMEOUT_MS",
        // Worker /metrics listener bind.
        "HORT_WORKER_METRICS_BIND",
    ];

    fn clear_all() {
        for s in SLOTS {
            std::env::remove_var(s);
        }
    }

    #[test]
    fn defaults_apply_when_only_required_vars_are_set() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/var/lib/hort/cas");

        let cfg = WorkerConfig::from_env().expect("parses with required vars");

        assert_eq!(cfg.minimal.database_url, "postgres://x/y");
        assert_eq!(cfg.minimal.log_format, LogFormat::Pretty);
        match &cfg.storage {
            StorageConfig::Filesystem { root } => {
                assert_eq!(root.to_string_lossy(), "/var/lib/hort/cas");
            }
            other => panic!("expected Filesystem storage, got {other:?}"),
        }
        assert_eq!(cfg.redis_url_evictable, None);
        // Scanner enable flags default `true` (preserves the
        // default-enabled posture).
        assert!(
            cfg.trivy_enabled,
            "HORT_SCANNER_TRIVY_ENABLED must default to true"
        );
        assert!(
            cfg.osv_enabled,
            "HORT_SCANNER_OSV_ENABLED must default to true"
        );
        assert_eq!(cfg.trivy_bin, PathBuf::from("trivy"));
        assert!(cfg.trivy_db_dir.is_none());
        assert_eq!(cfg.osv_scanner_bin, PathBuf::from("osv-scanner"));
        // Cosign provenance defaults OFF (needs an operator-provisioned
        // pinned trust root; cannot self-enable; see ADR 0027).
        assert!(
            !cfg.provenance_cosign_enabled,
            "HORT_PROVENANCE_COSIGN_ENABLED must default to false"
        );
        assert!(
            cfg.provenance_trusted_root_file.is_none(),
            "HORT_PROVENANCE_TRUSTED_ROOT_FILE default must be None"
        );
        assert!(
            cfg.provenance_cosign_public_keys_file.is_none(),
            "HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE default must be None"
        );
        assert_eq!(cfg.advisory_osv_url, "https://api.osv.dev/v1/querybatch");
        assert_eq!(
            cfg.advisory_osv_bulk_url,
            "https://osv-vulnerabilities.storage.googleapis.com",
        );
        assert!(
            cfg.advisory_watch_ecosystems.is_none(),
            "unset HORT_ADVISORY_WATCH_ECOSYSTEMS must propagate as None so the OSV adapter \
             falls back to its built-in default ecosystem set",
        );
        // Filesystem storage default → CAS-root sibling.
        assert_eq!(
            cfg.stateful_upload_staging_dir,
            PathBuf::from("/var/lib/hort/cas/stateful-upload-staging"),
        );
        assert_eq!(cfg.poll_interval, Duration::from_secs(5));
        assert_eq!(cfg.batch_size, 4);
        assert_eq!(cfg.max_attempts, 5);
        assert_eq!(cfg.lock_duration, Duration::from_secs(900));
        // Rotation env vars default to empty / None so the rotation
        // handler is structurally registered but becomes a no-op on
        // non-k8s deployments.
        assert!(
            cfg.rotation_namespaces.is_empty(),
            "rotation_namespaces default must be empty (no opt-in)"
        );
        assert!(
            cfg.public_registry_host.is_none(),
            "public_registry_host default must be None"
        );
        // worker_id default is `pod-{8 hex chars}` — 12 char total.
        assert!(
            cfg.worker_id.starts_with("pod-") && cfg.worker_id.len() == 4 + 8,
            "worker_id default shape unexpected: {:?}",
            cfg.worker_id
        );
    }

    #[test]
    fn missing_database_url_returns_missing_error() {
        let _g = lock_env();
        clear_all();
        // No HORT_DATABASE_URL or DATABASE_URL; storage path set so the
        // storage parser doesn't short-circuit first.
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");

        let err = WorkerConfig::from_env().expect_err("missing HORT_DATABASE_URL must error");
        match err {
            // The parser tries HORT_DATABASE_URL first then falls back
            // to DATABASE_URL; the surfaced Missing variant carries
            // whichever name was attempted last (DATABASE_URL).
            ConfigError::Missing(var) => assert!(
                var == "HORT_DATABASE_URL" || var == "DATABASE_URL",
                "expected Missing(HORT_DATABASE_URL|DATABASE_URL), got Missing({var})"
            ),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn missing_storage_filesystem_path_returns_missing_error() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        // HORT_STORAGE_BACKEND defaults to filesystem, HORT_STORAGE_FILESYSTEM_PATH unset

        let err = WorkerConfig::from_env().expect_err("missing FS path must error");
        match err {
            ConfigError::Missing(var) => assert_eq!(var, "HORT_STORAGE_FILESYSTEM_PATH"),
            other => panic!("expected Missing(HORT_STORAGE_FILESYSTEM_PATH), got {other:?}"),
        }
    }

    #[test]
    fn invalid_log_format_returns_error() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_LOG_FORMAT", "yaml");

        let err = WorkerConfig::from_env().expect_err("invalid log format must error");
        match err {
            ConfigError::InvalidLogFormat { var, got } => {
                assert_eq!(var, "HORT_LOG_FORMAT");
                assert_eq!(got, "yaml");
            }
            other => panic!("expected InvalidLogFormat, got {other:?}"),
        }
    }

    #[test]
    fn worker_id_from_explicit_env_var_is_used_verbatim() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_WORKER_ID", "my-worker-7");

        let cfg = WorkerConfig::from_env().expect("parses");
        assert_eq!(cfg.worker_id, "my-worker-7");
    }

    #[test]
    fn worker_id_from_pod_name_appends_random_suffix() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("POD_NAME", "hort-worker-abc");

        let cfg = WorkerConfig::from_env().expect("parses");
        assert!(
            cfg.worker_id.starts_with("hort-worker-abc-"),
            "worker_id must start with POD_NAME: {:?}",
            cfg.worker_id
        );
        // Random suffix is 8 hex chars after the `pod-` prefix.
        assert_eq!(
            cfg.worker_id.len(),
            "hort-worker-abc-".len() + 8,
            "expected 8-char random hex suffix: {:?}",
            cfg.worker_id
        );
    }

    #[test]
    fn invalid_batch_size_returns_invalid_value_error() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_SCANNER_BATCH_SIZE", "not-a-number");

        let err = WorkerConfig::from_env().expect_err("non-numeric batch size must error");
        match err {
            ConfigError::InvalidValue { var, .. } => {
                assert_eq!(var, "HORT_SCANNER_BATCH_SIZE");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn random_hex_suffix_is_stable_length() {
        let s = random_hex_suffix();
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rotation_target_namespaces_parses_comma_separated_list() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var(
            "HORT_ROTATION_TARGET_NAMESPACES",
            "ci-system, build-env ,prod,, staging",
        );

        let cfg = WorkerConfig::from_env().expect("parses with rotation namespaces override");
        let expected: HashSet<String> = [
            "ci-system".to_string(),
            "build-env".to_string(),
            "prod".to_string(),
            "staging".to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            cfg.rotation_namespaces, expected,
            "HORT_ROTATION_TARGET_NAMESPACES must trim whitespace and drop empty entries",
        );
    }

    #[test]
    fn public_registry_host_override_lands_on_field() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_PUBLIC_REGISTRY_HOST", "registry.example.test");

        let cfg = WorkerConfig::from_env().expect("parses with registry host override");
        assert_eq!(
            cfg.public_registry_host,
            Some("registry.example.test".to_string())
        );
    }

    #[test]
    fn advisory_watch_ecosystems_parses_comma_separated_list() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var(
            "HORT_ADVISORY_WATCH_ECOSYSTEMS",
            "npm, PyPI ,crates.io,, Maven",
        );

        let cfg = WorkerConfig::from_env().expect("parses with ecosystems override");
        assert_eq!(
            cfg.advisory_watch_ecosystems,
            Some(vec![
                "npm".to_string(),
                "PyPI".to_string(),
                "crates.io".to_string(),
                "Maven".to_string(),
            ]),
            "comma-separated list must trim whitespace and drop empty entries",
        );
    }

    #[test]
    fn advisory_osv_bulk_url_override_lands_on_field() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var(
            "HORT_ADVISORY_OSV_BULK_URL",
            "https://internal-osv-mirror.example.com",
        );

        let cfg = WorkerConfig::from_env().expect("parses with bulk url override");
        assert_eq!(
            cfg.advisory_osv_bulk_url,
            "https://internal-osv-mirror.example.com",
        );
    }

    #[test]
    fn stateful_upload_staging_dir_explicit_override_wins() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_STATEFUL_UPLOAD_STAGING_DIR", "/srv/staging-explicit");

        let cfg = WorkerConfig::from_env().expect("parses with staging override");
        assert_eq!(
            cfg.stateful_upload_staging_dir,
            PathBuf::from("/srv/staging-explicit"),
            "explicit HORT_STATEFUL_UPLOAD_STAGING_DIR wins over the FS-root sibling fallback",
        );
    }

    #[test]
    fn lock_timeout_ms_defaults_to_120000() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");

        let cfg = WorkerConfig::from_env().expect("parses with required vars");
        assert_eq!(
            cfg.lock_timeout_ms, 120_000,
            "HORT_WORKER_LOCK_TIMEOUT_MS default must be 120000 (2 min); see ADR 0020 §4",
        );
    }

    #[test]
    fn lock_timeout_ms_explicit_value_is_parsed() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_WORKER_LOCK_TIMEOUT_MS", "45000");

        let cfg = WorkerConfig::from_env().expect("parses with explicit lock timeout");
        assert_eq!(
            cfg.lock_timeout_ms, 45_000,
            "HORT_WORKER_LOCK_TIMEOUT_MS override must land on cfg.lock_timeout_ms",
        );
    }

    #[test]
    fn lock_timeout_ms_zero_is_accepted_as_disabled() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        // 0 = disabled (Postgres default); the composition root skips
        // the `after_connect` SET entirely. Parsing must accept it,
        // unlike statement_timeout where 0 is rejected — here 0 is the
        // documented operator escape hatch.
        std::env::set_var("HORT_WORKER_LOCK_TIMEOUT_MS", "0");

        let cfg = WorkerConfig::from_env().expect("parses with lock timeout disabled");
        assert_eq!(
            cfg.lock_timeout_ms, 0,
            "HORT_WORKER_LOCK_TIMEOUT_MS=0 must parse as 0 (disabled escape hatch)",
        );
    }

    #[test]
    fn lock_timeout_ms_invalid_value_returns_invalid_value_error() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_WORKER_LOCK_TIMEOUT_MS", "not-a-number");

        let err = WorkerConfig::from_env().expect_err("non-numeric lock timeout must error");
        match err {
            ConfigError::InvalidValue { var, .. } => {
                assert_eq!(var, "HORT_WORKER_LOCK_TIMEOUT_MS");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn database_url_fallback_accepts_database_url_when_hort_prefixed_absent() {
        let _g = lock_env();
        clear_all();
        // Helm chart wires DSN via DATABASE_URL (no HORT_ prefix);
        // the worker accepts either name (ADR 0009).
        std::env::set_var("DATABASE_URL", "postgres://fallback/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");

        let cfg = WorkerConfig::from_env().expect("DATABASE_URL fallback parses");
        assert_eq!(cfg.minimal.database_url, "postgres://fallback/y");
    }

    // -- Scanner byte caps are size strings --------------------------------

    #[test]
    fn parse_byte_size_size_strings_and_bare_integer() {
        // Backward shape: a bare integer is bytes.
        assert_eq!(parse_byte_size("67108864").unwrap(), 67108864);
        // Size strings.
        assert_eq!(parse_byte_size("256Mi").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_byte_size("8Gi").unwrap(), 8_u64 * 1024 * 1024 * 1024);
        assert!(parse_byte_size("garbage").is_err());
        assert!(parse_byte_size("-5Mi").is_err());
    }

    #[test]
    fn parse_byte_size_size_string_path_beats_float64_overflow() {
        // The rc.3 crash class: a bare integer above 2^53 loses precision
        // through Helm's float64 coercion; the same magnitude as a size
        // string with an exact power-of-two multiplier stays byte-exact.
        let above_2pow53: u64 = 9_007_199_254_740_993;
        assert_ne!(above_2pow53 as f64 as u64, above_2pow53);
        assert_eq!(parse_byte_size("8Gi").unwrap(), 8_589_934_592);
        assert_eq!(
            parse_byte_size("64Gi").unwrap(),
            64_u64 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_byte_size_or_falls_back_on_unset_and_invalid() {
        let _g = lock_env();
        const VAR: &str = "HORT_TEST_WORKER_BYTE_SIZE_OR";
        std::env::remove_var(VAR);
        // Unset → default.
        assert_eq!(
            parse_byte_size_or(VAR, 256 * 1024 * 1024),
            256 * 1024 * 1024
        );
        // Size string parses.
        std::env::set_var(VAR, "8Gi");
        assert_eq!(
            parse_byte_size_or(VAR, 256 * 1024 * 1024),
            8_u64 * 1024 * 1024 * 1024
        );
        // Bare integer (backward shape) parses.
        std::env::set_var(VAR, "1048576");
        assert_eq!(parse_byte_size_or(VAR, 256 * 1024 * 1024), 1_048_576);
        // Invalid → default (best-effort, registration is not a hard-fail).
        std::env::set_var(VAR, "not-a-size");
        assert_eq!(
            parse_byte_size_or(VAR, 256 * 1024 * 1024),
            256 * 1024 * 1024
        );
        std::env::remove_var(VAR);
    }

    // -- Load-bearing scanner enable flags ---------------------------------

    #[test]
    fn scanner_enable_flags_parse_false_when_set() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_SCANNER_TRIVY_ENABLED", "false");
        std::env::set_var("HORT_SCANNER_OSV_ENABLED", "false");

        let cfg = WorkerConfig::from_env().expect("parses with scanner flags off");
        assert!(
            !cfg.trivy_enabled,
            "HORT_SCANNER_TRIVY_ENABLED=false must land on cfg.trivy_enabled"
        );
        assert!(
            !cfg.osv_enabled,
            "HORT_SCANNER_OSV_ENABLED=false must land on cfg.osv_enabled"
        );
    }

    #[test]
    fn scanner_enable_flag_invalid_value_returns_invalid_value_error() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_SCANNER_TRIVY_ENABLED", "yes-please");

        let err = WorkerConfig::from_env().expect_err("non-bool scanner flag must error");
        match err {
            ConfigError::InvalidValue { var, .. } => {
                assert_eq!(var, "HORT_SCANNER_TRIVY_ENABLED");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // -- Worker /metrics listener bind (HORT_WORKER_METRICS_BIND) ---------

    #[test]
    fn metrics_bind_addr_defaults_to_disabled() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");

        let cfg = WorkerConfig::from_env().expect("parses with required vars");
        assert_eq!(
            cfg.metrics_bind_addr, None,
            "HORT_WORKER_METRICS_BIND default must be disabled (opt-in); a loopback \
             default would run a listener no cluster Prometheus can reach",
        );
    }

    #[test]
    fn metrics_bind_addr_explicit_override_is_parsed() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_WORKER_METRICS_BIND", "0.0.0.0:25090");

        let cfg = WorkerConfig::from_env().expect("parses with metrics bind override");
        assert_eq!(
            cfg.metrics_bind_addr,
            Some("0.0.0.0:25090".parse().unwrap()),
            "explicit HORT_WORKER_METRICS_BIND must land on cfg.metrics_bind_addr",
        );
    }

    #[test]
    fn metrics_bind_addr_off_disables_listener() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_WORKER_METRICS_BIND", "OFF");

        let cfg = WorkerConfig::from_env().expect("parses with metrics listener off");
        assert_eq!(
            cfg.metrics_bind_addr, None,
            "HORT_WORKER_METRICS_BIND=off must disable the listener (None)",
        );
    }

    #[test]
    fn metrics_bind_addr_invalid_value_returns_invalid_value_error() {
        let _g = lock_env();
        clear_all();
        std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var("HORT_WORKER_METRICS_BIND", "not-an-addr");

        let err = WorkerConfig::from_env().expect_err("malformed metrics bind must error");
        match err {
            ConfigError::InvalidValue { var, .. } => {
                assert_eq!(var, "HORT_WORKER_METRICS_BIND");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // -- DSN redaction in `Debug` (LOG-5) ----------------------------------
    //
    // `MinimalConfig` and `WorkerConfig` carry Postgres/Redis DSNs with
    // inline passwords (`database_url`, `redis_url_evictable`,
    // `retention_database_url`). Both have hand-rolled `Debug` impls that
    // redact those fields with the `<redacted>` placeholder; a stray
    // `{:?}` must never print the passwords. Mirrors the server's
    // `config_debug_does_not_leak_database_url` regression test.

    const SENSITIVE_DATABASE_PASSWORD: &str = "supersecretdbpw";
    const SENSITIVE_REDIS_EVICTABLE_PASSWORD: &str = "supersecretevictablepw";
    const SENSITIVE_RETENTION_DATABASE_PASSWORD: &str = "supersecretretentionpw";

    #[test]
    fn worker_config_debug_does_not_leak_dsn_passwords() {
        let _g = lock_env();
        clear_all();
        // `HORT_RETENTION_DATABASE_URL` is not in `SLOTS`; set it
        // explicitly so the optional secret field is populated and the
        // redaction path is exercised deterministically (and clear any
        // inherited value implicitly by overwriting it).
        std::env::set_var(
            "HORT_DATABASE_URL",
            format!("postgres://user:{SENSITIVE_DATABASE_PASSWORD}@db.example:5432/hort"),
        );
        std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
        std::env::set_var(
            "HORT_REDIS_URL_EVICTABLE",
            format!("redis://user:{SENSITIVE_REDIS_EVICTABLE_PASSWORD}@evictable.example:6379/0"),
        );
        std::env::set_var(
            "HORT_RETENTION_DATABASE_URL",
            format!(
                "postgres://user:{SENSITIVE_RETENTION_DATABASE_PASSWORD}@retention.example:5432/hort"
            ),
        );

        let cfg = WorkerConfig::from_env().expect("parses with sensitive DSNs");

        // Sanity: the secret fields actually hold the passwords (so a
        // green assertion below means redaction, not an empty value).
        assert!(cfg
            .minimal
            .database_url
            .contains(SENSITIVE_DATABASE_PASSWORD));
        assert!(cfg
            .redis_url_evictable
            .as_deref()
            .is_some_and(|u| u.contains(SENSITIVE_REDIS_EVICTABLE_PASSWORD)));
        assert!(cfg
            .retention_database_url
            .as_deref()
            .is_some_and(|u| u.contains(SENSITIVE_RETENTION_DATABASE_PASSWORD)));

        let debug_repr = format!("{cfg:?}");
        for pw in [
            SENSITIVE_DATABASE_PASSWORD,
            SENSITIVE_REDIS_EVICTABLE_PASSWORD,
            SENSITIVE_RETENTION_DATABASE_PASSWORD,
        ] {
            assert!(
                !debug_repr.contains(pw),
                "WorkerConfig Debug leaked DSN password {pw:?}: {debug_repr}"
            );
        }
        assert!(
            debug_repr.contains("<redacted>"),
            "WorkerConfig Debug missing `<redacted>` placeholder: {debug_repr}"
        );

        // The nested `MinimalConfig` Debug must redact on its own too.
        let minimal_repr = format!("{:?}", cfg.minimal);
        assert!(
            !minimal_repr.contains(SENSITIVE_DATABASE_PASSWORD),
            "MinimalConfig Debug leaked database_url password: {minimal_repr}"
        );
        assert!(
            minimal_repr.contains("<redacted>"),
            "MinimalConfig Debug missing `<redacted>` placeholder: {minimal_repr}"
        );

        // Cleanup the slot we set outside `SLOTS`.
        std::env::remove_var("HORT_RETENTION_DATABASE_URL");
    }
}
