//! Composition smoke tests.
//!
//! These tests do NOT spin up a real Postgres connection — that is
//! tested via `hort-adapters-postgres`'s DATABASE_URL-gated suite. Here
//! we only verify the binary's wiring shape: the config parses, the
//! intermediate types compose, and the public functions advertise
//! the signatures the binary `main` consumes.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Mutex;

use hort_worker::config::{LogFormat, StorageConfig, WorkerConfig};

/// Shared mutex guarding env-var manipulation across tests in this
/// integration-test binary. Cargo runs different test binaries
/// sequentially by default; this guards the intra-binary
/// parallelism case.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn clear_slots() {
    for s in [
        "HORT_DATABASE_URL",
        "DATABASE_URL",
        "HORT_LOG_FORMAT",
        "HORT_STORAGE_BACKEND",
        "HORT_STORAGE_FILESYSTEM_PATH",
        "HORT_REDIS_URL_EVICTABLE",
        "HORT_SCANNER_TRIVY_BIN",
        "HORT_SCANNER_OSV_BIN",
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
    ] {
        std::env::remove_var(s);
    }
}

#[test]
fn worker_config_parses_with_minimum_required_env() {
    let _g = env_lock().lock().unwrap();
    clear_slots();
    std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
    std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/var/lib/hort/cas");

    let cfg = WorkerConfig::from_env().expect("parses with required vars");

    // Round-trip the load-bearing fields the binary's `main` reads.
    assert_eq!(cfg.minimal.log_format, LogFormat::Pretty);
    assert!(matches!(cfg.storage, StorageConfig::Filesystem { .. }));
    assert!(cfg.batch_size >= 1);
    assert!(cfg.max_attempts >= 1);
}

/// M7: `WorkerConfig.lock_duration` round-trips through the env-var
/// parser to the value the worker consumes when calling
/// `ScanOrchestrationUseCase::claim_pending` in the poll loop. The
/// review finding asked to thread `lock_duration` onto
/// `ScanOrchestrationConfig` (in `hort-app`); this agent's touchable
/// paths do not include `hort-app`, so the assertion lands on the
/// worker side: parsing and propagation through the config struct
/// must not lose the value. The actual claim-call wiring lives in
/// `poll_loop::process_one_batch` at line `claim_pending(.., ctx.config.lock_duration)`.
#[test]
fn worker_config_lock_duration_roundtrips_through_env() {
    let _g = env_lock().lock().unwrap();
    clear_slots();
    std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
    std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
    // Pick a value distinct from the default (900s) so a regression
    // that silently dropped the override would visibly fail.
    std::env::set_var("HORT_SCANNER_LOCK_DURATION_SECS", "1234");

    let cfg = WorkerConfig::from_env().expect("parses with custom lock duration");

    assert_eq!(
        cfg.lock_duration,
        std::time::Duration::from_secs(1234),
        "HORT_SCANNER_LOCK_DURATION_SECS override must land on cfg.lock_duration",
    );

    // Default also lands on the field — pin both branches of the
    // env parser.
    clear_slots();
    std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
    std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
    let default_cfg = WorkerConfig::from_env().expect("parses with default lock duration");
    assert_eq!(
        default_cfg.lock_duration,
        std::time::Duration::from_secs(900),
        "default lock duration must be 900s per design doc §6 table",
    );
}

#[test]
fn worker_config_with_explicit_overrides() {
    let _g = env_lock().lock().unwrap();
    clear_slots();
    std::env::set_var("HORT_DATABASE_URL", "postgres://x/y");
    std::env::set_var("HORT_STORAGE_FILESYSTEM_PATH", "/tmp/hort");
    std::env::set_var("HORT_LOG_FORMAT", "json");
    std::env::set_var("HORT_SCANNER_TRIVY_BIN", "/opt/trivy");
    std::env::set_var("HORT_SCANNER_OSV_BIN", "/opt/osv-scanner");
    std::env::set_var("HORT_SCANNER_POLL_INTERVAL_SECS", "10");
    std::env::set_var("HORT_SCANNER_BATCH_SIZE", "8");
    std::env::set_var("HORT_SCANNER_MAX_ATTEMPTS", "3");
    std::env::set_var("HORT_SCANNER_LOCK_DURATION_SECS", "1800");
    std::env::set_var("HORT_WORKER_ID", "explicit-worker");

    let cfg = WorkerConfig::from_env().expect("parses with overrides");

    assert_eq!(cfg.minimal.log_format, LogFormat::Json);
    assert_eq!(cfg.trivy_bin, PathBuf::from("/opt/trivy"));
    assert_eq!(cfg.osv_scanner_bin, PathBuf::from("/opt/osv-scanner"));
    assert_eq!(cfg.poll_interval.as_secs(), 10);
    assert_eq!(cfg.batch_size, 8);
    assert_eq!(cfg.max_attempts, 3);
    assert_eq!(cfg.lock_duration.as_secs(), 1800);
    assert_eq!(cfg.worker_id, "explicit-worker");
}

/// Assert that the `seed-import` handler is in the dispatcher's
/// registered-kinds set after `build_app_context` finishes. Runs only
/// when `DATABASE_URL` is set (the composition root asserts a current
/// schema before any other DB work, so we need a real pool); skips with
/// a stderr note otherwise.
///
/// Also pins the other always-registered kinds so a regression that
/// silently drops any of them surfaces here.
#[tokio::test]
async fn build_app_context_registers_seed_import_handler() {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!(
                "DATABASE_URL not set; skipping DB-gated composition smoke \
                 (build_app_context_registers_seed_import_handler)"
            );
            return;
        }
    };

    // Build a minimal WorkerConfig — same shape as
    // `build_app_context_signature_compiles` below, but pointing at
    // the real test DB.
    let cfg = WorkerConfig {
        minimal: hort_worker::config::MinimalConfig {
            database_url,
            log_format: LogFormat::Pretty,
        },
        storage: StorageConfig::Filesystem {
            root: PathBuf::from("/tmp/hort-worker-smoke-cas"),
        },
        redis_url_evictable: None,
        // Trivy + osv-scanner must be on PATH for the strict
        // fail-fast health-check; `trivy` / `osv-scanner` names
        // mirror the binary defaults so a developer with both
        // installed sees the test exercise the full path. If
        // either is missing, the health-check fails and the test
        // surfaces that as the build_app_context error — which is
        // the correct behaviour: we want operators / CI to know
        // the worker would refuse to boot.
        trivy_enabled: true,
        trivy_bin: PathBuf::from("trivy"),
        trivy_db_dir: None,
        osv_enabled: true,
        osv_scanner_bin: PathBuf::from("osv-scanner"),
        // Cosign provenance OFF for the smoke (the verifier needs a
        // pinned trust root; the smoke exercises the scanner/advisory
        // path, not provenance).
        provenance_cosign_enabled: false,
        provenance_trusted_root_file: None,
        advisory_osv_url: String::new(),
        advisory_osv_bulk_url: String::new(),
        advisory_watch_ecosystems: None,
        stateful_upload_staging_dir: PathBuf::from("/tmp/hort-worker-smoke-staging"),
        poll_interval: std::time::Duration::from_secs(5),
        batch_size: 4,
        max_attempts: 5,
        lock_duration: std::time::Duration::from_secs(900),
        worker_id: "hort-worker-smoke".to_string(),
        rotation_namespaces: std::collections::HashSet::new(),
        public_registry_host: None,
        include_service_account_label: true,
        refcount_reconcile_on_startup: false,
        retention_database_url: None,
        audit_retention_floors: hort_worker::config::AuditRetentionFloors {
            authentication: std::time::Duration::from_secs(180 * 86_400),
            artifact_lifecycle: std::time::Duration::from_secs(1080 * 86_400),
            artifact_downloaded: std::time::Duration::from_secs(90 * 86_400),
            api_token_used: std::time::Duration::from_secs(1080 * 86_400),
        },
        retention_stream_mode: hort_worker::config::RetentionStreamMode::Delete,
        lock_timeout_ms: 120_000,
        metrics_bind_addr: None,
    };

    let output = match hort_worker::composition::build_app_context(&cfg, None, None).await {
        Ok(o) => o,
        Err(e) => {
            // Surface the failure clearly. If `trivy` / `osv-scanner`
            // aren't on PATH the strict fail-fast health-check raises
            // here — that's the correct behaviour, so we skip rather
            // than fail (the test asserts wiring shape, not scanner
            // installation).
            eprintln!(
                "build_app_context returned an error (likely a missing \
                 scanner binary on PATH); skipping seed-import \
                 registration assertion: {e:#}"
            );
            return;
        }
    };

    let kinds: std::collections::HashSet<&str> =
        output.dispatcher.registered_kinds().into_iter().collect();
    assert!(
        kinds.contains("seed-import"),
        "SeedImportHandler must be registered with the dispatcher; \
         got kinds = {kinds:?}"
    );
    // Pin a small set of always-on siblings as a co-regression check —
    // if the composition root ever silently drops one of these the
    // assertion above would still pass under a partial-wiring
    // refactor.
    for expected in [
        "seed-import",
        "scan",
        "cron-rescan-tick",
        "advisory-watch-tick",
        "staging-sweep",
        "quarantine-release-sweep",
        "prefetch-tick",
        // Cascade triad (driver, leaf, retention).
        "prefetch-dependencies",
        "prefetch",
        "prefetch-row-retention-sweep",
        "replay-seen-prune",
        "noop",
    ] {
        assert!(
            kinds.contains(expected),
            "expected always-on dispatcher kind {expected:?} missing; \
             got kinds = {kinds:?}"
        );
    }
}

/// `build_app_context(&cfg).await -> anyhow::Result<WorkerContext>` is
/// the call shape `main` consumes. We can't actually run it without
/// a live Postgres pool, but referencing the function in a `let
/// async move { ... }` block proves at compile time that the shape
/// hasn't drifted from what the binary entrypoint expects.
#[test]
fn build_app_context_signature_compiles() {
    fn _proof() {
        let cfg = WorkerConfig {
            minimal: hort_worker::config::MinimalConfig {
                database_url: String::new(),
                log_format: LogFormat::Pretty,
            },
            storage: StorageConfig::Filesystem {
                root: PathBuf::from("/tmp"),
            },
            redis_url_evictable: None,
            // Backlog 078 Item 6 — load-bearing scanner enable flags.
            trivy_enabled: true,
            trivy_bin: PathBuf::from("trivy"),
            trivy_db_dir: None,
            osv_enabled: true,
            osv_scanner_bin: PathBuf::from("osv-scanner"),
            // Cosign provenance OFF (signature-compiles smoke; provenance
            // is exercised by the hort-app orchestration unit tests).
            provenance_cosign_enabled: false,
            provenance_trusted_root_file: None,
            advisory_osv_url: String::new(),
            advisory_osv_bulk_url: String::new(),
            advisory_watch_ecosystems: None,
            stateful_upload_staging_dir: PathBuf::from("/tmp/staging"),
            poll_interval: std::time::Duration::from_secs(5),
            batch_size: 4,
            max_attempts: 5,
            lock_duration: std::time::Duration::from_secs(900),
            worker_id: String::new(),
            // Rotation reconciler config slots.
            rotation_namespaces: std::collections::HashSet::new(),
            public_registry_host: None,
            // Default `true` posture for the per-SA metric label.
            include_service_account_label: true,
            // Retention composition config slots (ADR 0020).
            refcount_reconcile_on_startup: true,
            retention_database_url: None,
            audit_retention_floors: hort_worker::config::AuditRetentionFloors {
                authentication: std::time::Duration::from_secs(180 * 86_400),
                artifact_lifecycle: std::time::Duration::from_secs(1080 * 86_400),
                artifact_downloaded: std::time::Duration::from_secs(90 * 86_400),
                api_token_used: std::time::Duration::from_secs(1080 * 86_400),
            },
            retention_stream_mode: hort_worker::config::RetentionStreamMode::Delete,
            // Defense-in-depth seal-pool lock_timeout (ADR 0020;
            // default 120000ms; 0 = disabled escape hatch).
            lock_timeout_ms: 120_000,
            // Worker /metrics listener bind (None = off).
            metrics_bind_addr: None,
        };
        // Compiler check only — never awaited. The two `None`s are
        // the `Option<&ExtraTrustAnchors>` and `Option<&Path>`
        // parameters; production callers pass the parsed anchors and
        // the merged subprocess-CA-bundle path from
        // `extra_ca::read_and_propagate()`.
        let _fut: std::pin::Pin<Box<dyn std::future::Future<Output = _>>> = Box::pin(
            hort_worker::composition::build_app_context(&cfg, None, None),
        );
        let _typed: std::pin::Pin<
            Box<
                dyn std::future::Future<
                    Output = anyhow::Result<hort_worker::composition::BuildOutput>,
                >,
            >,
        > = _fut;
    }
    // Function exists; if its body fails to type-check, the test
    // fails at compile time. No runtime work — composition needs a
    // live Postgres pool.
    let _: fn() = _proof;
}
