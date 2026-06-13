//! Composition root for `hort-worker`.
//!
//! Wires:
//! - Postgres pool (asserts schema is current; never runs migrations).
//! - Storage adapter (filesystem or S3 — same selector as `hort-server`
//!   so the worker reads the same CAS bytes the server wrote).
//! - Evictable Redis (or in-memory fallback) for the OSV advisory cache.
//! - Postgres-backed projection adapters: event store, jobs, scan
//!   findings, repo security score, scanner registry, repository
//!   repo, policy projections, content reference index, artifact
//!   metadata, artifact lifecycle.
//! - Scanner adapters: Trivy + OSV-scanner (each health-checked at
//!   startup; refuses to start if every backend fails its probe).
//! - Advisory adapter: OSV.dev with the evictable Redis cache.
//! - Format dispatch: same compiled-in handlers hort-server uses.
//! - `QuarantineUseCase::new` — the consumer side of the orchestrator's
//!   findings flow.
//! - `ScanOrchestrationUseCase` wiring.
//! - `scanner_registry` handle for the heartbeat task — M14 review
//!   finding: the row's `upsert_self` happens on the heartbeat
//!   loop's first tick, NOT here, so the row's existence and the
//!   loop's liveness are inseparable.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use sqlx::PgPool;

use hort_adapters_advisory_osv::{OsvAdvisoryAdapter, OsvAdvisoryConfig};
use hort_adapters_checkpoint_anchor::{ObjectStoreCheckpointAnchor, ObjectStoreCheckpointEmitter};
use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
use hort_adapters_ephemeral_redis::RedisEphemeralStore;
use hort_adapters_kubernetes::KubernetesSecretWriterImpl;
use hort_adapters_postgres::advisory_sync_state::PgAdvisorySyncStateRepository;
use hort_adapters_postgres::api_token_repo::PgApiTokenRepository;
use hort_adapters_postgres::artifact_group_lifecycle::PgArtifactGroupLifecycle;
use hort_adapters_postgres::artifact_group_repo::PgArtifactGroupRepository;
use hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle;
use hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
// `SeedImportUseCase` depends on `IngestUseCase` which depends on the
// curation-rule projection (the pre-storage gate). Same adapter
// `hort-server` wires (`build_app_context`).
use hort_adapters_postgres::curation_rule_repo::PgCurationRuleRepository;
use hort_adapters_postgres::event_chain_head_reader::PgEventChainHeadReader;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_adapters_postgres::pg_content_reference_repo::PgContentReferenceRepo;
use hort_adapters_postgres::policy_projection_repo::PgPolicyProjectionRepository;
// Release-sweep candidacy query adapter.
use hort_adapters_postgres::quarantine_release_candidates::PgQuarantineReleaseCandidatesRepository;
use hort_adapters_postgres::replay_guard_repo::PgReplayGuardRepository;
use hort_adapters_postgres::repository_repo::PgRepositoryRepository;
// The PrefetchTickHandler reads upstream mappings from the DB to
// resolve the catch-all proxy URL for each tracked package walk.
// Same Postgres adapter hort-server wires.
use hort_adapters_postgres::repository_upstream_mapping_repo::PgRepositoryUpstreamMappingRepo;
use hort_adapters_postgres::rescan_candidates::PgRescanCandidatesRepository;
use hort_adapters_postgres::sbom_components::PgSbomComponentRepository;
use hort_adapters_postgres::scan_findings_repository::PgScanFindingsRepository;
use hort_adapters_postgres::scanner_registry_repository::PgScannerRegistryRepository;
use hort_adapters_postgres::service_account_repo::PgServiceAccountRepository;
use hort_adapters_postgres::user_repo::PgUserRepository;
use hort_adapters_scanner_osv::{OsvScannerAdapter, OsvScannerConfig};
use hort_adapters_scanner_trivy::{TrivyAdapter, TrivyConfig};
use hort_adapters_storage::builders::{build_s3_object_store, build_s3_storage, S3StorageOpts};
use hort_adapters_storage::filesystem_stateful_upload_staging::FilesystemStatefulUploadStaging;
use hort_adapters_storage::FilesystemStorage;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::rbac::RbacEvaluator;
use hort_app::task_dispatcher::TaskDispatcher;
use hort_app::task_handlers::eventstore_checkpoint::BackfillBaselineConfig;
use hort_app::task_handlers::{
    AdvisoryWatchTickHandler, CronRescanTickHandler, EventStoreArchiveHandler,
    EventstoreCheckpointHandler, NoopTaskHandler, PrefetchDependenciesHandler,
    PrefetchIngestHandler, PrefetchRowRetentionSweepHandler, PrefetchTickHandler,
    ProvenanceVerifyHandler, QuarantineReleaseSweepHandler, ReplaySeenPruneHandler,
    RetentionEvaluateHandler, RetentionPurgeHandler, ScanTaskHandler, SeedImportHandler,
    ServiceAccountRotationHandler, StagingSweepHandler, WheelMetadataBackfillHandler,
};
use hort_app::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
// IngestUseCase + ArtifactGroupUseCase are the dep subtree the worker
// side needs to construct the SeedImportUseCase the handler wraps.
// Mirrors the shape and ordering of
// `hort-server::composition::build_app_context`'s ingest wiring.
use hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
use hort_app::use_cases::ingest_use_case::IngestUseCase;
use hort_app::use_cases::prefetch_use_case::PrefetchUseCase;
use hort_app::use_cases::provenance_orchestration::ProvenanceOrchestrationUseCase;
use hort_app::use_cases::quarantine_use_case::QuarantineUseCase;
use hort_app::use_cases::scan_orchestration::{ScanOrchestrationConfig, ScanOrchestrationUseCase};
use hort_app::use_cases::seed_import_use_case::SeedImportUseCase;
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::advisory_sync_state::AdvisorySyncStateRepository;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::artifact_group_lifecycle::ArtifactGroupLifecyclePort;
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
// IngestUseCase's pre-storage curation gate port.
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::kubernetes_secret_writer::KubernetesSecretWriter;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
// The cosign/Sigstore provenance verifier port.
use hort_domain::ports::provenance::ProvenancePort;
// Release-sweep ports.
use hort_domain::ports::quarantine_release::QuarantineReleasePort;
use hort_domain::ports::quarantine_release_candidates::QuarantineReleaseCandidatesRepository;
use hort_domain::ports::replay_seen_prune::ReplaySeenPrunePort;
use hort_domain::ports::repository_repository::RepositoryRepository;
// Port trait for the PrefetchTickHandler's mapping resolver dep +
// the HttpUpstreamProxy adapter.
use arc_swap::ArcSwap;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::rescan_candidates::RescanCandidatesRepository;
use hort_domain::ports::sbom_component_repository::SbomComponentRepository;
use hort_domain::ports::scan_findings_repository::ScanFindingsRepository;
use hort_domain::ports::scanner::ScannerPort;
use hort_domain::ports::scanner_registry_repository::ScannerRegistryRepository;
use hort_domain::ports::secret_port::SecretPort;
use hort_domain::ports::service_account_repository::ServiceAccountRepository;
use hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::ports::user_repository::UserRepository;
use hort_formats::cargo::CargoFormatHandler;
use hort_formats::npm::NpmFormatHandler;
use hort_formats::oci::OciFormatHandler;
use hort_formats::pypi::PyPiFormatHandler;

use crate::config::{StorageConfig, WorkerConfig};

/// Output of [`build_app_context`] — the full set of handles the
/// heartbeat task (and any future operator tasks) share via `Arc`.
///
/// The `TaskDispatcher` is returned separately from `build_app_context`
/// (see the `BuildOutput` tuple) so it can be moved directly into the
/// dispatcher poll task without requiring an `Arc::try_unwrap` dance
/// (the dispatcher is `!Clone`).
pub struct WorkerContext {
    pub orchestration: Arc<ScanOrchestrationUseCase>,
    pub jobs: Arc<dyn JobsRepository>,
    pub scanner_registry: Arc<dyn ScannerRegistryRepository>,
    pub worker_id: String,
    /// The active scanner backend names, in declared order. The
    /// orchestrator's `default_scan_backends` is set from this list so
    /// every claimed job runs exactly the backends this worker has
    /// wired. Moving the scan-backend source onto `ScanPolicy.scan_backends`
    /// is tracked as a future backlog item; no separate work here.
    pub scanners: Vec<String>,
    pub config: WorkerConfig,
    /// Held so the heartbeat loop can query `hort_scan_queue_depth` from
    /// the same pool the rest of the composition uses.
    pub pool: PgPool,
}

/// The full output of [`build_app_context`]: the shared context handle
/// and the ready-to-run `TaskDispatcher`.
pub struct BuildOutput {
    pub ctx: Arc<WorkerContext>,
    /// The multi-kind task dispatcher. Registered with a
    /// `ScanTaskHandler` wrapping the orchestration use case. The
    /// caller calls `dispatcher.run(cancel_token)` in a spawned task
    /// to start the generalised poll loop.
    pub dispatcher: TaskDispatcher,
}

/// Build the full worker context. Steps mirror `hort-server`'s
/// `build_app_context` shape but diverge at the leaf adapter layer
/// (scanner / advisory adapters here; HTTP / OIDC adapters there).
///
/// **Order is significant** — the migration assertion runs before any
/// other DB work so a stale schema fails the boot path before the
/// `hort_app_role` ever issues a write.
///
/// `extra_ca` is the parsed `HORT_EXTRA_CA_BUNDLE` content (or `None`
/// when unset). It's threaded into every reqwest-using adapter
/// constructed below — same shape as `hort-server`'s composition root,
/// where the binary reads the env var at boot and passes the parsed
/// anchors into composition rather than having composition reach
/// into the environment.
///
/// `subprocess_ca_bundle` is the on-disk path to the merged
/// (system + operator) trust store the spawned Trivy / osv-scanner
/// subprocesses consume via `SSL_CERT_FILE`. `None` when the
/// extra-CA bundle is unconfigured; the scanner adapters then fall
/// back to the OS default trust store.
///
/// Returns a [`BuildOutput`] containing the shared `WorkerContext`
/// and the ready-to-run [`TaskDispatcher`].
pub async fn build_app_context(
    cfg: &WorkerConfig,
    extra_ca: Option<&hort_config::ExtraTrustAnchors>,
    subprocess_ca_bundle: Option<&std::path::Path>,
) -> anyhow::Result<BuildOutput> {
    // -----------------------------------------------------------------
    // 1. Postgres pool + schema-version assertion.
    //
    // The main pool also carries the defense-in-depth `lock_timeout`
    // backstop (ADR 0020): the retention/archive `EventStorePublisher`
    // rides THIS pool when `HORT_RETENTION_DATABASE_URL` is unset (Q5
    // branch below), so `seal_and_remove`'s unbounded `StreamSealed`
    // append must be lock-wait-bounded here too.
    // -----------------------------------------------------------------
    tracing::info!(
        lock_timeout_ms = cfg.lock_timeout_ms,
        "worker pool lock_timeout backstop \
         (0 = disabled; default 120000 = §10.2-INV single-flight \
         defense-in-depth, not reachable by a healthy sweep)"
    );
    let pool = apply_lock_timeout(
        PgPoolOptions::new().acquire_timeout(Duration::from_secs(10)),
        cfg.lock_timeout_ms,
    )
    .connect(&cfg.minimal.database_url)
    .await
    .context("connecting to postgres")?;
    assert_schema_current(&pool)
        .await
        .context("verifying schema version (run `hort-server migrate` first)")?;

    // -----------------------------------------------------------------
    // 2. Ephemeral store — evictable Redis when configured, in-memory
    //    fallback otherwise. The OSV advisory adapter is the only
    //    consumer in the worker; losing the cache forces a re-fetch.
    // -----------------------------------------------------------------
    let ephemeral_evictable: Arc<dyn EphemeralStore> = if let Some(url) =
        cfg.redis_url_evictable.as_deref()
    {
        Arc::new(
            RedisEphemeralStore::connect(url)
                .await
                .context("connecting to evictable Redis (HORT_REDIS_URL_EVICTABLE)")?,
        )
    } else {
        tracing::warn!(
            "HORT_REDIS_URL_EVICTABLE not set — using in-memory advisory cache (single-process only)"
        );
        Arc::new(InMemoryEphemeralStore::new())
    };

    // -----------------------------------------------------------------
    // 3. Storage. Same selector as `hort-server::storage::build`; copy
    //    rather than depend on hort-server.
    // -----------------------------------------------------------------
    let storage: Arc<dyn StoragePort> = build_storage(&cfg.storage)?;

    // -----------------------------------------------------------------
    // 4. Postgres-backed ports.
    // -----------------------------------------------------------------
    let pg_event_store: Arc<PgEventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .context("constructing event store (is the immutability trigger installed?)")?,
    );
    let event_store: Arc<dyn EventStore> = pg_event_store.clone();
    // The worker process does NOT run the `NotificationDispatcher`
    // (that lives in `hort-server`). Wrap in a no-broadcast publisher
    // so use cases see the same trait shape and worker-side appends
    // remain pure pass-through. If a future initiative wants the worker
    // to broadcast scan-completion events, this is the slot to construct
    // a `broadcast::Sender` and hand it to the (then-co-located)
    // dispatcher.
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(event_store.clone()));

    let artifacts_concrete: Arc<PgArtifactRepository> =
        Arc::new(PgArtifactRepository::new(pool.clone()));
    let artifacts: Arc<dyn ArtifactRepository> = artifacts_concrete.clone();

    let metadata_concrete: Arc<PgArtifactMetadataRepository> =
        Arc::new(PgArtifactMetadataRepository::new(pool.clone()));

    let lifecycle_concrete: Arc<PgArtifactLifecycle> = Arc::new(PgArtifactLifecycle::new(
        pg_event_store.clone(),
        artifacts_concrete.clone(),
        metadata_concrete.clone(),
    ));
    let lifecycle: Arc<dyn ArtifactLifecyclePort> = lifecycle_concrete;

    let repositories: Arc<dyn RepositoryRepository> =
        Arc::new(PgRepositoryRepository::new(pool.clone()));

    let policy_projections: Arc<dyn PolicyProjectionRepository> =
        Arc::new(PgPolicyProjectionRepository::new(pool.clone()));

    let content_references: Arc<dyn ContentReferenceIndex> =
        Arc::new(PgContentReferenceRepo::new(pool.clone()));

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool.clone()));

    // The per-finding `scan_findings` projection rows are persisted
    // inside the lifecycle adapter's `commit_scan_result_with_score`
    // SQL transaction (via `insert_findings_in_tx`); the
    // QuarantineUseCase no longer holds a separate handle. The
    // trait-object wire below is kept around so a future admin/CLI
    // re-scan flow can read individual rows without re-routing through
    // the lifecycle.
    let _scan_findings: Arc<dyn ScanFindingsRepository> =
        Arc::new(PgScanFindingsRepository::new(pool.clone()));

    // M8 review finding: previous code constructed an
    // `Arc<dyn RepoSecurityScoreRepository>` here and dropped it
    // immediately via a wildcard bind, which suggested the use case
    // would consume it. It does not — `QuarantineUseCase::new_for_scan_results`
    // does not take a `RepoSecurityScoreRepository` argument
    // The projection write happens inside
    // `PgArtifactLifecycle::commit_scan_result_with_score` via the
    // `apply_delta_in_tx` helper that owns its own transaction
    // handle — no application-layer port handle is involved.
    // Constructing-and-dropping the trait object here was
    // misleading dead code, so the binding (and its
    // `PgRepoSecurityScoreRepository` import) is removed.

    let scanner_registry: Arc<dyn ScannerRegistryRepository> =
        Arc::new(PgScannerRegistryRepository::new(pool.clone()));

    // -----------------------------------------------------------------
    // 5. Advisory adapter (OSV.dev) backed by the evictable Redis cache.
    // -----------------------------------------------------------------
    let advisory = {
        // The bulk-diff URL and per-tick ecosystem set are wired here
        // so the same adapter feeds both the per-component
        // `AdvisoryPort::query` path AND the watch-tick
        // `pull_diff_since` path. Unset `advisory_watch_ecosystems`
        // propagates `None` so the adapter falls back to its built-in
        // default eight-ecosystem set (which uses OSV-canonical labels
        // — see `OsvAdvisoryConfig::default`).
        let mut acfg = OsvAdvisoryConfig {
            osv_batch_url: cfg.advisory_osv_url.clone(),
            bulk_url: cfg.advisory_osv_bulk_url.clone(),
            ..OsvAdvisoryConfig::default()
        };
        if let Some(ecos) = cfg.advisory_watch_ecosystems.clone() {
            acfg.ecosystems = ecos;
        }
        // Extra CA anchors come from the binary boundary (the boot path
        // reads `HORT_EXTRA_CA_BUNDLE` and passes the parsed anchors
        // into composition; composition stays free of env-var reads).
        // ADR 0010 — no `reqwest::Client::new()` in this path.
        let osv_advisory: Arc<dyn AdvisoryPort> = Arc::new(
            OsvAdvisoryAdapter::new(acfg, ephemeral_evictable.clone(), extra_ca)
                .map_err(|e| anyhow!("OSV advisory adapter construction failed: {e}"))?,
        );
        osv_advisory
    };

    // -----------------------------------------------------------------
    // 6. Scanner adapters — health-check each at startup. H1 review
    //    finding + spec §4.2: a health-check failure on ANY configured
    //    backend means that backend is "not deployable" and the worker
    //    "logs and exits non-zero." Earlier the worker tolerated a
    //    degraded boot as long as at least one backend remained
    //    healthy; that flexibility silently hid misconfigured runtime
    //    images. The strict fail-fast policy below matches the spec.
    // -----------------------------------------------------------------
    // The merged subprocess CA bundle path (when configured) is set as
    // `SSL_CERT_FILE` on every Trivy / osv-scanner Command spawn so
    // private-CA endpoints (operator's internal Trivy DB mirror, internal
    // osv mirror) keep working alongside public roots.
    let subprocess_ca = subprocess_ca_bundle.map(std::path::Path::to_path_buf);
    // The scan-*report* drain cap is shared across both scanner backends
    // and operator-tunable via the single `HORT_SCANNER_MAX_REPORT_SIZE`
    // knob; an unset/invalid value falls back to each adapter's config
    // default (256 MiB). Read once, applied to both
    // `trivy_cfg.max_report_size` and `osv_cfg.max_report_size`.
    //
    // Backlog 078 Item 4 — both caps are human-readable SIZE strings
    // ("256Mi", "8Gi") via `config::parse_byte_size`, not bare integers,
    // so a multi-GiB value can never round-trip through Helm's float64
    // coercion into scientific notation (the rc.3 boot-crash class). A
    // bare byte integer is still accepted for backward shape.
    let trivy: Arc<dyn ScannerPort> = {
        // F-15 — the artifact-size cap is operator-tunable via
        // `HORT_SCANNER_TRIVY_MAX_ARTIFACT_SIZE`; an unset/invalid
        // value falls back to `TrivyConfig::default().max_artifact_size`
        // (8 GiB), mirroring how `timeout` flows through the default.
        let trivy_default = TrivyConfig::default();
        let trivy_max_artifact_size = crate::config::parse_byte_size_or(
            "HORT_SCANNER_TRIVY_MAX_ARTIFACT_SIZE",
            trivy_default.max_artifact_size,
        );
        let trivy_max_report_size = crate::config::parse_byte_size_or(
            "HORT_SCANNER_MAX_REPORT_SIZE",
            trivy_default.max_report_size,
        );
        let trivy_cfg = TrivyConfig {
            trivy_bin: cfg.trivy_bin.clone(),
            db_dir: cfg.trivy_db_dir.clone(),
            subprocess_ca_bundle: subprocess_ca.clone(),
            max_artifact_size: trivy_max_artifact_size,
            max_report_size: trivy_max_report_size,
            ..TrivyConfig::default()
        };
        Arc::new(TrivyAdapter::new(trivy_cfg, storage.clone()))
    };
    let osv: Arc<dyn ScannerPort> = {
        let osv_cfg = OsvScannerConfig {
            osv_scanner_bin: cfg.osv_scanner_bin.clone(),
            subprocess_ca_bundle: subprocess_ca.clone(),
            max_report_size: crate::config::parse_byte_size_or(
                "HORT_SCANNER_MAX_REPORT_SIZE",
                OsvScannerConfig::default().max_report_size,
            ),
            ..OsvScannerConfig::default()
        };
        Arc::new(OsvScannerAdapter::new(osv_cfg))
    };

    // Backlog 078 Item 6 (chart S3) — the `enabled` flags are
    // load-bearing: a flag-DISABLED backend is dropped here, BEFORE the
    // `--version` health probe runs, so a disabled backend is never
    // registered regardless of whether its binary is present. The probe
    // (`health_check_all_or_fail`) is a secondary health check that only
    // sees the flag-enabled subset. This closes the pre-078 footgun
    // where `scanner.trivy.enabled: false` was "cosmetic only" and the
    // probe was the real gate.
    let configured = select_enabled_scanners(&[(cfg.trivy_enabled, trivy), (cfg.osv_enabled, osv)]);
    if configured.is_empty() {
        return Err(anyhow!(
            "no scanner backend enabled — both HORT_SCANNER_TRIVY_ENABLED and \
             HORT_SCANNER_OSV_ENABLED are false (worker.scanner.{{trivy,osv}}.enabled). \
             A scanner worker with zero backends has nothing to scan; enable at \
             least one backend or disable the worker (worker.enabled=false)."
        ));
    }
    let healthy_names = health_check_all_or_fail(&configured).await?;
    let mut scanners_map: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    for s in configured {
        scanners_map.insert(s.name().to_string(), s);
    }

    // -----------------------------------------------------------------
    // 7. Format dispatch. Same compiled-in handlers hort-server uses.
    //    Until the WASM module loader lands, this is the canonical list.
    //
    //    The map is also consumed by the `SeedImportUseCase`
    //    registration below (step 12.f). The underlying
    //    `Arc<dyn FormatHandler>`s are cheap to clone; the `.clone()` at
    //    the orchestration call site preserves single-instance semantics
    //    for the scan path while handing a second handle to seed-import.
    // -----------------------------------------------------------------
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("pypi".into(), Arc::new(PyPiFormatHandler));
    handlers.insert("cargo".into(), Arc::new(CargoFormatHandler));
    handlers.insert("npm".into(), Arc::new(NpmFormatHandler));
    handlers.insert("oci".into(), Arc::new(OciFormatHandler));

    // -----------------------------------------------------------------
    // 8. QuarantineUseCase — the consumer of the orchestrator's
    //    findings. The constructor takes the storage port
    //    unconditionally; per-finding rows are persisted by the
    //    lifecycle port's `commit_scan_result_with_score` (PG
    //    transaction), so the use case no longer holds a separate
    //    `ScanFindingsRepository` handle.
    // -----------------------------------------------------------------
    let quarantine = Arc::new(QuarantineUseCase::new(
        artifacts.clone(),
        event_publisher.clone(),
        lifecycle.clone(),
        repositories.clone(),
        policy_projections.clone(),
        content_references.clone(),
        storage.clone(),
    ));

    // -----------------------------------------------------------------
    // 9. ScanOrchestrationUseCase. Default backends come from the wired
    //    scanner names; moving the source onto `ScanPolicy.scan_backends`
    //    is tracked as a future backlog item.
    // -----------------------------------------------------------------
    let mut orch_cfg = ScanOrchestrationConfig::defaults_for_worker(cfg.worker_id.clone());
    orch_cfg.max_attempts = cfg.max_attempts;
    orch_cfg.default_scan_backends = healthy_names.clone();

    let artifact_metadata: Arc<dyn ArtifactMetadataRepository> = metadata_concrete.clone();

    // H3 — the orchestrator no longer holds an EventStore handle; the
    // consumer (`QuarantineUseCase::record_scan_result`) owns the
    // event-store reads.
    let orchestration = Arc::new(ScanOrchestrationUseCase::new(
        jobs.clone(),
        artifacts.clone(),
        artifact_metadata,
        repositories.clone(),
        policy_projections.clone(),
        advisory.clone(),
        scanners_map,
        // Clone so the SeedImportUseCase below can consume the same
        // handler set. The `Arc<dyn FormatHandler>` values are cheap
        // clones; the SeedImportUseCase only reads
        // (`FormatHandler::format_key()` + handler lookup), so sharing
        // is safe.
        handlers.clone(),
        // `quarantine` is also consumed by the
        // QuarantineReleaseSweepHandler registration below (Arc clone
        // preserves single-instance semantics).
        quarantine.clone(),
        orch_cfg,
    ));

    // -----------------------------------------------------------------
    // 10. (Removed in M14 — composition root no longer writes the
    //     scanner_registry row. The heartbeat loop's first tick now
    //     owns `upsert_self` so the registry row's existence and
    //     the loop's liveness are inseparable. See
    //     `heartbeat::refresh_registry` for the new write site.)
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // 11. TaskDispatcher + ScanTaskHandler.
    //
    // Wraps the orchestration use case in a `ScanTaskHandler` and
    // registers it with a `TaskDispatcher`. Concurrency is pinned at 1
    // per worker — scan jobs are CPU/IO heavy (Trivy invocations);
    // parallelism within a single worker instance is controlled by the
    // number of replicas, not by intra-process concurrency.
    // -----------------------------------------------------------------
    let mut dispatcher = TaskDispatcher::new(
        jobs.clone(),
        event_publisher.clone(),
        cfg.worker_id.clone(),
        cfg.lock_duration,
        cfg.poll_interval.as_secs(),
        u16::try_from(cfg.batch_size).unwrap_or(u16::MAX),
    );
    dispatcher.register(
        Arc::new(ScanTaskHandler::new(orchestration.clone())),
        1, // max_concurrency = 1 per worker replica
    );

    // -----------------------------------------------------------------
    // 12. Register the cron-rescan, advisory-watch, NoopTaskHandler, and
    //     StagingSweepHandler. Per-kind concurrency rationale:
    //
    //       scan                  → 1  (parallelism via replicas)
    //       cron-rescan-tick      → 1  (single-active; bulk-INSERT
    //                                   loops would fight on the
    //                                   partial unique index
    //                                   `(artifact_id) WHERE kind='scan'`)
    //       advisory-watch-tick   → 1  (per-ecosystem bulk-zip download
    //                                   monopolises bandwidth)
    //       staging-sweep         → 1  (single-active per worker replica)
    //       noop                  → 16 (parallelism-tolerant; raised
    //                                   in production so the diagnostic
    //                                   canary doesn't head-of-line
    //                                   under load)
    //
    //     Single-active enforcement is two-layer: this semaphore is the
    //     second layer; k8s `concurrencyPolicy: Forbid` is the first.
    // -----------------------------------------------------------------
    let rescan_candidates: Arc<dyn RescanCandidatesRepository> =
        Arc::new(PgRescanCandidatesRepository::new(pool.clone()));
    let advisory_sync_state: Arc<dyn AdvisorySyncStateRepository> =
        Arc::new(PgAdvisorySyncStateRepository::new(pool.clone()));
    let sbom_components: Arc<dyn SbomComponentRepository> =
        Arc::new(PgSbomComponentRepository::new(pool.clone()));
    // Filesystem-backed staging port. The sweep only needs `list` /
    // `delete` — no `append` / `stream_read` — and the constructor
    // creates the root if missing (it is mkdir-idempotent). Same adapter
    // `hort-server` uses.
    let stateful_upload_staging: Arc<dyn StatefulUploadStagingPort> = Arc::new(
        FilesystemStatefulUploadStaging::new(cfg.stateful_upload_staging_dir.clone()),
    );

    dispatcher.register(
        Arc::new(CronRescanTickHandler::new(rescan_candidates, jobs.clone())),
        1, // single-active — see table above
    );
    dispatcher.register(
        Arc::new(AdvisoryWatchTickHandler::new(
            advisory.clone(),
            sbom_components,
            jobs.clone(),
            advisory_sync_state,
            artifacts.clone(),
            repositories.clone(),
        )),
        1, // single-active — see table above
    );
    dispatcher.register(
        Arc::new(StagingSweepHandler::new(
            stateful_upload_staging,
            ephemeral_evictable.clone(),
        )),
        1, // single-active — see table above
    );

    // -----------------------------------------------------------------
    // 12.d. Register the QuarantineReleaseSweepHandler (kind
    //       `quarantine-release-sweep`).
    //
    //       Unconditional: like cron-rescan-tick the handler only needs
    //       Postgres, which the worker always has — the candidacy query
    //       reads `policy_projections` + `artifacts` and hands the
    //       result to `QuarantineUseCase::release_expired` (ADR 0007
    //       fail-closed authority gate). The k8s CronJob enqueues via
    //       the runtime DSN through the `hort-server
    //       enqueue-quarantine-release-sweep` subcommand, bypassing the
    //       svc-token / `hort-cli` HTTP path.
    //
    //       Concurrency = 1 — single-active. Mirrors cron-rescan-tick /
    //       staging-sweep posture.
    // -----------------------------------------------------------------
    let quarantine_release_candidates: Arc<dyn QuarantineReleaseCandidatesRepository> =
        Arc::new(PgQuarantineReleaseCandidatesRepository::new(pool.clone()));
    // The `quarantine` use case (constructed above at step 8) implements
    // `QuarantineReleasePort` — the shim impl lives next to
    // `release_expired` in `crates/hort-app/src/use_cases/quarantine_use_case.rs`.
    let quarantine_release_port: Arc<dyn QuarantineReleasePort> = quarantine.clone();
    dispatcher.register(
        Arc::new(QuarantineReleaseSweepHandler::new(
            quarantine_release_candidates,
            quarantine_release_port,
        )),
        1, // single-active — see table above
    );

    // -----------------------------------------------------------------
    // 12.e. Register the PrefetchTickHandler (kind `prefetch-tick`).
    //
    //       Unconditional: like quarantine-release-sweep the handler only
    //       needs Postgres + the planner (zero-cost unit struct). Walks
    //       every repository whose `prefetch_policy.enabled = true` AND
    //       `triggers ⊃ Scheduled` and invokes
    //       `PrefetchUseCase::plan(... Scheduled ...)` per tracked
    //       package. The k8s CronJob enqueues via the runtime DSN
    //       through the `hort-server enqueue-prefetch-tick` subcommand,
    //       bypassing the svc-token / `hort-cli` HTTP path (same
    //       delivery contract as the quarantine-release-sweep).
    //
    //       Concurrency = 1 — single-active. Mirrors
    //       quarantine-release-sweep / cron-rescan-tick posture.
    //
    //       Default chart posture: `prefetchTick.enabled = false` (the
    //       CronJob existing-but-disabled-by-default lets operators flip
    //       a single chart value). When chart-disabled the handler still
    //       loads (no harm — no jobs are claimed of this kind).
    // -----------------------------------------------------------------
    // The handler needs UpstreamProxy + the upstream-mapping repo +
    // FormatHandler-by-key lookup so the per-tick walk can fetch
    // upstream metadata and extract the version set. The HTTP upstream
    // proxy adapter mirrors hort-server's wiring; the worker assembles
    // its own instance because it runs in its own process.
    //
    // Secret port: the smallest env+file dispatch (same shape as
    // hort-server::composition) — Phase-1 prefetch only targets the
    // Anonymous catch-all mapping (npm/cargo/pypi public registries)
    // so the SecretPort is unused at the call site, but the adapter
    // constructor requires it. HORT_SECRETS_FILE_ROOT is honoured the
    // same way hort-server reads it; the worker's pod likely has no
    // mounted-file secrets configured, in which case the file branch
    // is never reached for Anonymous mappings.
    let secrets_file_root: Option<std::path::PathBuf> =
        match std::env::var("HORT_SECRETS_FILE_ROOT") {
            Ok(s) if !s.is_empty() => Some(std::path::PathBuf::from(s)),
            _ => None,
        };
    let secret_port: Arc<dyn SecretPort> = Arc::new(hort_adapters_secrets::DispatchSecretPort {
        env: Arc::new(hort_adapters_secrets::EnvVarSecretAdapter),
        file: Arc::new(
            hort_adapters_secrets::MountedFileSecretAdapter::new_with_root(secrets_file_root),
        ),
    });
    let upstream_proxy_for_prefetch: Arc<dyn UpstreamProxy> = {
        let cfg_for_proxy = hort_adapters_upstream_http::HttpUpstreamProxyConfig {
            // `format_label` is the metric label fired on every
            // outbound fetch. The prefetch tick walks multiple
            // formats (npm/cargo/pypi) so a single static label here
            // would mis-attribute. Use a dedicated label so dashboards
            // can distinguish scheduled-prefetch traffic from the
            // OCI hot-path. The per-mapping `format` knowledge
            // never reaches the adapter (the adapter sees raw
            // mappings) — operators correlate cardinality at the
            // repo level via separate `hort_prefetch_*` metrics.
            format_label: "prefetch_tick".to_string(),
            extra_trust_anchors: extra_ca.cloned(),
            // Same upstream User-Agent as hort-server (HORT_UPSTREAM_USER_AGENT
            // or the built-in default) — worker prefetch + provenance fetches
            // carry the identical UA so a custom value applies uniformly.
            user_agent: hort_adapters_upstream_http::user_agent_from_env(),
            ..hort_adapters_upstream_http::HttpUpstreamProxyConfig::default()
        };
        Arc::new(hort_adapters_upstream_http::HttpUpstreamProxy::new(
            cfg_for_proxy,
            secret_port.clone(),
        )?)
    };
    let upstream_mappings_for_prefetch: Arc<dyn RepositoryUpstreamMappingRepository> =
        Arc::new(PgRepositoryUpstreamMappingRepo::new(pool.clone()));

    dispatcher.register(
        Arc::new(PrefetchTickHandler::new(
            repositories.clone(),
            artifacts.clone(),
            Arc::new(PrefetchUseCase::new()),
            // Spec 077 §3.1 — the tick now enqueues `prefetch` leaf rows via
            // `enqueue_prefetch_batch`; reuse the same jobs pool the cascade
            // triad uses.
            jobs.clone(),
            upstream_proxy_for_prefetch.clone(),
            upstream_mappings_for_prefetch.clone(),
            handlers.clone(),
        )),
        1, // single-active — see table above
    );

    // -----------------------------------------------------------------
    // 12.e.bis Register the cascade triad (kinds
    //          `prefetch-dependencies`, `prefetch`,
    //          `prefetch-row-retention-sweep`).
    //
    //          `PrefetchDependenciesHandler` — driver. Reads an
    //          ingested artifact's manifest, resolves runtime-dep
    //          ranges (hybrid: held-set first, upstream fetch for the
    //          cold cohort), and enqueues a `prefetch` ingest row + a
    //          child `prefetch-dependencies` row per not-already-held
    //          dep (bounded by `prefetch_policy.transitive_depth`).
    //          Dedup is the L3 partial unique on `jobs.target_key`
    //          keyed on the concrete version.
    //
    //          `PrefetchIngestHandler` — leaf-ingest. Per claimed
    //          `prefetch` row: composes the upstream pull URL via
    //          `FormatHandler::build_pull_url`, fetches via
    //          `UpstreamProxy::fetch_artifact`, and ingests via
    //          `IngestUseCase::ingest_verified`. PyPI fans out
    //          per-distribution from the per-version JSON manifest.
    //          `PullDedup` single-flights the prefetch-vs-client-pull
    //          race.
    //
    //          `PrefetchRowRetentionSweepHandler` — periodically
    //          deletes terminal `prefetch%` rows older than a
    //          configurable horizon (default 7d). Enqueued by the
    //          `enqueue-prefetch-row-retention-sweep` hort-server
    //          subcommand.
    //
    //          Concurrency: all three single-active per-worker
    //          (`max_concurrency = 1`). The cascade walks idempotent
    //          cohorts (L3 dedup absorbs duplicates); raising
    //          concurrency buys no parallelism.
    //
    //          NOTE — `PrefetchIngestHandler` is registered AFTER
    //          `ingest_use_case` is constructed below. The cascade-
    //          driver registration stays here because it does not need
    //          `ingest_use_case`; only the leaf-pull does.
    // -----------------------------------------------------------------
    let cascade_jobs: Arc<dyn JobsRepository> = jobs.clone();
    // The provenance-orchestration use case's upstream referrer-fetch arm
    // gets its OWN `HttpUpstreamProxy`, NOT a clone of the prefetch proxy.
    // The prefetch proxy carries `format_label="prefetch_tick"` (it walks
    // npm/cargo/pypi), so cloning it would mis-attribute provenance
    // referrer/manifest/blob fetches to the prefetch subsystem on
    // `hort_upstream_fetch_*`. A dedicated `format_label="provenance"`
    // instance keeps the two distinguishable on dashboards.
    let upstream_proxy_for_provenance: Arc<dyn UpstreamProxy> = {
        let cfg = hort_adapters_upstream_http::HttpUpstreamProxyConfig {
            format_label: "provenance".to_string(),
            extra_trust_anchors: extra_ca.cloned(),
            // Same upstream User-Agent as hort-server (HORT_UPSTREAM_USER_AGENT
            // or the built-in default) — worker prefetch + provenance fetches
            // carry the identical UA so a custom value applies uniformly.
            user_agent: hort_adapters_upstream_http::user_agent_from_env(),
            ..hort_adapters_upstream_http::HttpUpstreamProxyConfig::default()
        };
        Arc::new(hort_adapters_upstream_http::HttpUpstreamProxy::new(
            cfg,
            secret_port.clone(),
        )?)
    };
    // The mapping repo the boot-primed provenance resolver consumes
    // (`list_all` at boot + on every refresh tick). Cloned here, before
    // `upstream_mappings_for_prefetch` is moved into the prefetch handlers
    // below, so it survives to the resolver-prime + refresh-task wiring at
    // the `register_provenance_verify` call site.
    let upstream_mappings_for_provenance = upstream_mappings_for_prefetch.clone();
    // Item 12b — share the upstream-proxy + mapping-repo handles
    // across BOTH the cascade driver and the leaf-pull handler.
    let prefetch_proxy_for_leaf = upstream_proxy_for_prefetch.clone();
    let prefetch_mappings_for_leaf = upstream_mappings_for_prefetch.clone();
    let prefetch_handlers_for_leaf = handlers.clone();
    dispatcher.register(
        Arc::new(PrefetchDependenciesHandler::new(
            repositories.clone(),
            artifacts.clone(),
            storage.clone(),
            cascade_jobs.clone(),
            upstream_proxy_for_prefetch,
            upstream_mappings_for_prefetch,
            handlers.clone(),
        )),
        1,
    );
    dispatcher.register(
        Arc::new(PrefetchRowRetentionSweepHandler::new(cascade_jobs)),
        1,
    );

    // -----------------------------------------------------------------
    // 12.e.tris Register the WheelMetadataBackfillHandler (kind
    //          `wheel-metadata-backfill`).
    //
    //          Operator-opt-in retrofit for PyPI wheels that were
    //          ingested before wheel metadata extraction was available.
    //          Walks `artifacts.path LIKE '%.whl' AND NOT EXISTS
    //          content_references kind='wheel_metadata'` in batches;
    //          per artifact: stream wheel from CAS → invoke
    //          `extract_wheel_metadata_bytes` → persist to CAS + insert
    //          `wheel_metadata` ContentReference row. Resumable by
    //          construction.
    //
    //          Unconditional registration: the handler only needs ports
    //          already wired (artifacts, storage, content_references,
    //          PyPI FormatHandler). Enqueued via `hort-server
    //          enqueue-wheel-metadata-backfill`, bypassing the
    //          svc-token / `hort-cli` HTTP path.
    //
    //          Concurrency = 1 — single-active. Mirrors
    //          `quarantine-release-sweep` / `prefetch-tick` posture.
    //
    //          Default chart posture: `wheelMetadataBackfill.enabled =
    //          false`. The backfill is a one-shot retrofit; operators
    //          flip it once after the upgrade and back off when
    //          `artifacts_walked = 0` consistently.
    // -----------------------------------------------------------------
    let pypi_handler_for_backfill: Arc<dyn FormatHandler> = handlers
        .get("pypi")
        .expect(
            "hort-worker composition: `pypi` FormatHandler must be registered for \
             WheelMetadataBackfillHandler (it is the only format that produces \
             wheel METADATA bytes)",
        )
        .clone();
    dispatcher.register(
        Arc::new(WheelMetadataBackfillHandler::new(
            artifacts.clone(),
            content_references.clone(),
            storage.clone(),
            pypi_handler_for_backfill,
        )),
        1, // single-active — see rationale above
    );

    // -----------------------------------------------------------------
    // 12.f. Register the SeedImportHandler (kind `seed-import`,
    //       see explanation/prefetch-pipeline.md).
    //
    //       Dependency subtree (mirrors `hort-server::composition::
    //       build_app_context`'s ingest wiring; no new ports, no port
    //       contract changes — every adapter here already had a peer
    //       in the worker before Item 5b):
    //         - `IngestUseCase` (the `register_existing_cas_blob` path
    //           the use case calls into) — needs the new
    //           `CurationRuleRepository` + `ArtifactGroupUseCase`
    //           deps for full constructor parity, plus a few
    //           operator-cardinality defaults (see below).
    //         - `ArtifactGroupUseCase` — group-membership classifier
    //           the post-commit hook in `register_by_hash` invokes.
    //         - `SeedImportUseCase` — the actual cutover orchestrator
    //           (per-item dedup, backdated-anchor stamping, run
    //           summary).
    //
    //       Operator-cardinality defaults (deviation-rationale per
    //       Implementation Discipline):
    //         - `include_repository_label = true` — matches the
    //           hort-server default; the seed-import use case is a
    //           one-shot operator command, so the metric volume is
    //           bounded (operator-driven cutover, not steady-state
    //           traffic). The relevant `METRICS_INCLUDE_REPOSITORY_LABEL`
    //           env-var plumbing is not added to `WorkerConfig` here
    //           because no other worker code path consumes it today;
    //           collapsing it to a const default keeps the surface
    //           minimal until a second consumer appears.
    //         - `metadata_caps = empty` — operator overrides for
    //           per-format upload-payload metadata size caps are
    //           hort-server's surface (each format's `FormatHandler`
    //           declares the cap; the operator override layer is
    //           an edge concern). The seed-import path goes through
    //           `register_existing_cas_blob`, which bypasses the
    //           multi-stream metadata write entirely.
    //         - `metadata_blob_max_bytes = 10 MB` — mirrors the
    //           `hort-server` default. The seed-import path doesn't
    //           exercise the HashReference strategy, so this is
    //           inert; the value is supplied to satisfy the
    //           constructor signature.
    //
    //       Concurrency = 1 — single-active. Seed-import is operator-
    //       driven and one-shot; two concurrent runs of the same TSV
    //       would race on the per-item dedup query (the use case
    //       handles the race correctly — duplicates surface as
    //       `already_imported` — but the wasted CAS lookups have no
    //       benefit). Mirrors the quarantine-release-sweep posture.
    // -----------------------------------------------------------------
    let curation_rules: Arc<dyn CurationRuleRepository> =
        Arc::new(PgCurationRuleRepository::new(pool.clone()));
    let artifact_group_repo: Arc<dyn ArtifactGroupRepository> =
        Arc::new(PgArtifactGroupRepository::new(pool.clone()));
    // `PgArtifactGroupLifecycle::new` takes the concrete `Arc<PgEventStore>`
    // (not the trait object) so the lifecycle adapter can call into
    // pg-specific transactional helpers; `pg_event_store` is the concrete
    // handle constructed at step 4. Mirrors hort-server's wiring.
    let artifact_group_lifecycle: Arc<dyn ArtifactGroupLifecyclePort> =
        Arc::new(PgArtifactGroupLifecycle::new(pg_event_store.clone()));
    let artifact_group_use_case = Arc::new(ArtifactGroupUseCase::new(
        artifact_group_repo,
        artifact_group_lifecycle,
        // See the cardinality-default rationale block above.
        true,
    ));
    let ingest_use_case = Arc::new(IngestUseCase::new(
        storage.clone(),
        lifecycle.clone(),
        artifacts.clone(),
        repositories.clone(),
        event_publisher.clone(),
        curation_rules,
        artifact_group_use_case,
        // See the cardinality-default rationale block above.
        true,
        // Empty operator overrides; seed-import doesn't exercise the
        // per-format metadata-cap surface (rationale above).
        HashMap::new(),
        // `hort-server` default (10 MB); inert on the seed-import path.
        10 * 1024 * 1024,
        content_references.clone(),
        policy_projections.clone(),
        jobs.clone(),
    ));
    // Register the leaf `PrefetchIngestHandler` here (AFTER
    // `ingest_use_case` is constructed; it needs the use case for
    // `ingest_verified`). The cascade-driver + retention-sweep were
    // registered earlier in the same triad block; the leaf-pull lands
    // here so its dependency on `ingest_use_case` resolves cleanly.
    dispatcher.register(
        Arc::new(PrefetchIngestHandler::new(
            repositories.clone(),
            prefetch_proxy_for_leaf,
            prefetch_mappings_for_leaf,
            prefetch_handlers_for_leaf,
            ingest_use_case.clone(),
        )),
        1,
    );

    let seed_import_use_case = Arc::new(SeedImportUseCase::new(
        ingest_use_case,
        policy_projections.clone(),
        repositories.clone(),
        artifacts.clone(),
        handlers,
    ));
    dispatcher.register(
        Arc::new(SeedImportHandler::new(seed_import_use_case)),
        1, // single-active — see the call-site rationale.
    );
    tracing::info!(
        "SeedImportHandler registered (single-active per worker replica) \
         — seed-import jobs now claim → dispatch → \
         register-by-hash → ArtifactIngested/ArtifactQuarantined events"
    );

    // -----------------------------------------------------------------
    // 12.a. Register the ServiceAccountRotationHandler when the optional
    //       `KubernetesSecretWriter` adapter wires successfully AND
    //       `HORT_PUBLIC_REGISTRY_HOST` is set.
    //
    //      The adapter's `try_in_cluster` falls back to a kubeconfig
    //      so dev-laptop runs ALSO succeed when ~/.kube/config exists;
    //      operators who want the worker to be a no-op on bare-metal
    //      simply leave `HORT_ROTATION_TARGET_NAMESPACES` empty (the
    //      handler then runs but every SA gets `namespace_not_authorized`).
    //
    //      Concurrency = 1 — server-side apply is idempotent but
    //      parallel writes to the same Secret coordinates would
    //      double-mint PATs. Single-active per worker replica.
    // -----------------------------------------------------------------
    register_service_account_rotation(&mut dispatcher, &pool, &event_store, cfg).await;

    // -----------------------------------------------------------------
    // 12.b. Register the EventstoreCheckpointHandler when storage is S3
    //       AND both anchor key files are present (the operator-
    //       provisioned signing/verifying keypair, §14 R2).
    //
    //       Concurrency = 1 — checkpoint emission is single-active; the
    //       external CronJob uses `concurrencyPolicy: Forbid` as layer 1.
    //       If storage is filesystem OR a key file is absent the helper
    //       logs an `info!` and does NOT register (the admin-task route
    //       then 404s, mirroring the service-account-rotation skip
    //       pattern).
    // -----------------------------------------------------------------
    register_eventstore_checkpoint(&mut dispatcher, &pool, cfg, extra_ca).await;

    // -----------------------------------------------------------------
    // 12.c. Register the ReplaySeenPruneHandler (federated-JWT
    //       replay-guard seen-set TTL cleanup, ADR 0018 §4 / §12 R4).
    //
    //       Unconditional: unlike eventstore-checkpoint (which needs S3
    //       + operator anchor keys) the prune only needs the Postgres
    //       pool — the `jwt_replay_seen` table lives in the same
    //       database. The handler is always registered (like
    //       cron-rescan-tick / staging-sweep) and
    //       `/api/v1/admin/tasks/replay-seen-prune` is always live.
    //
    //       Concurrency = 1 — a single `DELETE … WHERE expires_at <
    //       now()` per tick; two concurrent ticks would only contend on
    //       the same already-expired rows for no benefit. Single-active
    //       per worker replica matches the other cleanup/cron tasks; the
    //       external CronJob uses `concurrencyPolicy: Forbid` as the
    //       first layer.
    //
    //       The handler degrades SAFE on a prune failure (spec §4): a
    //       missed prune only grows the table — the seen-set never
    //       forgets a recorded replay within TTL — so the handler
    //       returns `Failed { retry: true }` (warn!, retried next tick),
    //       never a hard worker failure.
    // -----------------------------------------------------------------
    let replay_seen_prune: Arc<dyn ReplaySeenPrunePort> =
        Arc::new(PgReplayGuardRepository::new(pool.clone()));
    dispatcher.register(
        Arc::new(ReplaySeenPruneHandler::new(replay_seen_prune)),
        1, // single-active — see the call-site rationale.
    );
    tracing::info!(
        "ReplaySeenPruneHandler registered (single-active per worker replica) \
         — F-1 jwt_replay_seen TTL cleanup is now wired (spec §12 R4, \
         default-ENABLED CronJob)"
    );

    // -----------------------------------------------------------------
    // 12.d. Register the three retention TaskHandlers + boot sweep +
    //       in-process RefcountReconcileGate + optional hort_retention_role
    //       pool (ADR 0020). Registered unconditionally: a handler whose
    //       Helm CronJob is `enabled:false` is simply never invoked —
    //       the volume control is Helm, not composition.
    //
    //       Concurrency = 1 for all three: destructive sweeps, single-
    //       active per worker replica. k8s `concurrencyPolicy: Forbid`
    //       is layer 1, this semaphore is layer 2.
    // -----------------------------------------------------------------
    {
        use hort_adapters_postgres::purge_gc::PgPurgeGcPort;
        use hort_adapters_postgres::refcount_reconcile::PgRefcountReconcile;
        use hort_adapters_postgres::retention_candidate_reader::PgRetentionCandidateReader;
        use hort_adapters_postgres::retention_policy_projection_repo::PgRetentionPolicyProjectionRepository;
        use hort_adapters_postgres::retention_scan_reader::PgRetentionScanReader;
        use hort_adapters_postgres::terminal_stream_reader::PgTerminalStreamReader;
        use hort_app::use_cases::eventstore_retention_use_case::{
            canonical_retention_rules, EventStoreRetentionUseCase, StreamRetentionModeRef,
        };
        use hort_app::use_cases::purge_use_case::{PurgeUseCase, RefcountReconcileGate};
        use hort_app::use_cases::retention_use_case::RetentionUseCase;
        use hort_domain::ports::purge_gc::PurgeGcPort;
        use hort_domain::ports::retention_candidate_reader::RetentionCandidateReader;
        use hort_domain::ports::retention_policy_projection_repository::RetentionPolicyProjectionRepository;
        use hort_domain::ports::retention_scan_reader::RetentionScanReader;
        use hort_domain::ports::terminal_stream_reader::TerminalStreamReader;

        // -- BLOCKER-2-D boot sweep + in-process gate -----------------
        // Run the Item-B3.5 reconcile sweep exactly as hort-server's
        // serve.rs does (inline from the pool — a one-shot boot step,
        // no serving-path coupling). Flip the gate true ONLY on a
        // successful sweep (or when the operator opted out of the
        // sweep on an upgrade install with authoritative state — the
        // serve.rs else-branch semantics).
        struct InProcessReconcileGate(bool);
        impl RefcountReconcileGate for InProcessReconcileGate {
            fn is_converged(&self) -> bool {
                self.0
            }
        }
        let gate_converged = if cfg.refcount_reconcile_on_startup {
            use hort_app::use_cases::refcount_reconcile_use_case::RefcountReconcileUseCase;
            use hort_domain::ports::refcount_reconcile::RefcountReconcilePort;
            tracing::info!("refcount-reconcile boot sweep starting (ADR 0020)");
            let port: Arc<dyn RefcountReconcilePort> =
                Arc::new(PgRefcountReconcile::new(pool.clone()));
            match RefcountReconcileUseCase::new(port).sweep_drift().await {
                Ok(summary) => {
                    tracing::info!(
                        repos_swept = summary.repos_swept,
                        drift_repaired = summary.drift_repaired,
                        errors = summary.errors,
                        "refcount-reconcile boot sweep converged — \
                         RetentionPurgeHandler gate OPEN"
                    );
                    true
                }
                Err(e) => {
                    // Fail-safe: the gate stays closed; the purge
                    // handler refuses + retries next cron. Boot does
                    // NOT abort (the projection is eventually
                    // authoritative; next worker boot retries).
                    tracing::warn!(
                        error = %e,
                        "refcount-reconcile boot sweep FAILED — \
                         RetentionPurgeHandler gate CLOSED (purge refuses + \
                         retries; not a boot failure)"
                    );
                    false
                }
            }
        } else {
            tracing::info!(
                "refcount-reconcile boot sweep skipped \
                 (HORT_REFCOUNT_RECONCILE_ON_STARTUP=false — upgrade-install \
                 opt-out; projection assumed authoritative — gate OPEN)"
            );
            true
        };
        let reconcile_gate: Arc<dyn RefcountReconcileGate> =
            Arc::new(InProcessReconcileGate(gate_converged));

        // -- RetentionEvaluateHandler ---------------------------------
        let retention_policy_projections: Arc<dyn RetentionPolicyProjectionRepository> =
            Arc::new(PgRetentionPolicyProjectionRepository::new(pool.clone()));
        let retention_candidates: Arc<dyn RetentionCandidateReader> =
            Arc::new(PgRetentionCandidateReader::new(pool.clone()));
        let retention_scan_reader: Arc<dyn RetentionScanReader> =
            Arc::new(PgRetentionScanReader::new(pool.clone()));
        let retention_uc = Arc::new(RetentionUseCase::new(
            event_publisher.clone(),
            retention_scan_reader,
        ));
        dispatcher.register(
            Arc::new(RetentionEvaluateHandler::new(
                retention_policy_projections,
                retention_candidates,
                retention_uc,
            )),
            1,
        );

        // -- RetentionPurgeHandler (BLOCKER-2-D gate injected) --------
        let purge_gc: Arc<dyn PurgeGcPort> = Arc::new(PgPurgeGcPort::new(pool.clone()));
        let purge_uc = Arc::new(PurgeUseCase::new(
            purge_gc,
            storage.clone(),
            event_publisher.clone(),
            reconcile_gate,
        ));
        dispatcher.register(Arc::new(RetentionPurgeHandler::new(purge_uc)), 1);

        // -- EventStoreArchiveHandler (Q5 hort_retention_role pool) -----
        // When HORT_RETENTION_DATABASE_URL is set, build a second pool
        // connected as hort_retention_role (the DELETE-capable role per
        // §10.2) and route the archive use case's EventStorePublisher
        // over it so delete_stream can actually remove sealed rows.
        // When unset (Q5): use the hort_app_role event_publisher — every
        // delete_stream fails fail-safe via the still-active
        // events_immutable trigger (the B9 seal-tombstone-first
        // transaction rolls back, zero rows removed; one fewer branch).
        let archive_publisher: Arc<EventStorePublisher> =
            if let Some(retention_dsn) = cfg.retention_database_url.as_deref() {
                // The Q5-set branch: this pool actually runs
                // `seal_and_remove`'s DELETE as `hort_retention_role`.
                // The `lock_timeout` backstop (ADR 0020) is most
                // load-bearing here (the unset branch fails fail-safe
                // on the trigger before any row-lock wait), so apply
                // the same bound the main pool carries.
                let retention_pool = apply_lock_timeout(
                    PgPoolOptions::new().acquire_timeout(Duration::from_secs(10)),
                    cfg.lock_timeout_ms,
                )
                .connect(retention_dsn)
                .await
                .context("connecting to HORT_RETENTION_DATABASE_URL (hort_retention_role)")?;
                let retention_event_store: Arc<dyn EventStore> = Arc::new(
                    PgEventStore::new(retention_pool)
                        .await
                        .context("constructing hort_retention_role event store")?,
                );
                tracing::info!(
                    "HORT_RETENTION_DATABASE_URL set — \
                     EventStoreArchiveHandler uses the hort_retention_role pool \
                     (delete_stream can remove sealed rows)"
                );
                Arc::new(EventStorePublisher::without_broadcast(
                    retention_event_store,
                ))
            } else {
                tracing::info!(
                    "HORT_RETENTION_DATABASE_URL unset — \
                     EventStoreArchiveHandler uses the hort_app_role pool; \
                     every delete_stream fails fail-safe via the \
                     events_immutable trigger (zero rows removed)"
                );
                event_publisher.clone()
            };
        let terminal_reader: Arc<dyn TerminalStreamReader> =
            Arc::new(PgTerminalStreamReader::new(pool.clone()));
        // Q6 — the C-1 floors resolved in WorkerConfig (same env vars +
        // MIN clamps as hort-server), fed positionally into the B14
        // canonical builder (AuthAttempts, Artifact, DownloadAudit,
        // TokenUse). The other artifact-lifecycle categories share the
        // artifact_lifecycle floor (B14 scope note); RetentionPolicy
        // streams are unregistered (skipped) in v1 — low-volume policy
        // audit, never sealed.
        let floors = &cfg.audit_retention_floors;
        let rules = canonical_retention_rules(
            chrono_duration(floors.authentication),
            chrono_duration(floors.artifact_lifecycle),
            chrono_duration(floors.artifact_downloaded),
            chrono_duration(floors.api_token_used),
        );
        let mode = match &cfg.retention_stream_mode {
            crate::config::RetentionStreamMode::Delete => StreamRetentionModeRef::Delete,
            crate::config::RetentionStreamMode::Archive { target_prefix } => {
                StreamRetentionModeRef::Archive {
                    target_prefix: target_prefix.clone(),
                }
            }
        };
        let archive_uc = Arc::new(EventStoreRetentionUseCase::new(
            terminal_reader,
            archive_publisher,
            rules,
            mode,
        ));
        dispatcher.register(Arc::new(EventStoreArchiveHandler::new(archive_uc)), 1);

        tracing::info!(
            "retention-evaluate / retention-purge / \
             eventstore-archive handlers registered (single-active; \
             Helm enabled:false is the volume control)"
        );
    }

    // -----------------------------------------------------------------
    // 12.e.quater Register the ProvenanceVerifyHandler (kind
    //          `provenance-verify`), gated on the load-bearing
    //          `worker.provenance.cosign.enabled` flag (ADR 0027).
    //
    //          The flag is the enabling gate, NOT a probe. When off:
    //          no `ProvenancePort` is constructed, the handler is NOT
    //          registered, and `provenance-verify` jobs sit unclaimed
    //          (a `Required` artifact stays `Pending` → never timer-
    //          releases — fail-closed).
    //
    //          The port's `health_check()` runs at startup; failure ⇒
    //          worker exits non-zero. The check verifies the cached
    //          trust root is loaded + fresh — it does NOT probe live
    //          Rekor/Fulcio (the verify path is offline).
    //
    //          Concurrency = 1 — single-active per worker replica.
    //
    // The orchestration use case also takes `UpstreamProxy` +
    // `UpstreamResolver` for the proxy referrer-fetch arm. The resolver
    // is built empty, primed at boot from
    // `RepositoryUpstreamMappingRepository::list_all`, and kept fresh by
    // a background refresh task — `list_all` every
    // `HORT_UPSTREAM_RESOLVER_REFRESH_SECS` (default 60s, floor 5s) →
    // `reload`. With a primed resolver the proxy referrer-fetch arm fires
    // for proxy-scoped repos; hosted-repo provenance is unaffected.
    let caching_resolver = Arc::new(hort_adapters_upstream_http::CachingResolver::new());
    // Boot-prime from the same mapping repo the prefetch path uses. A
    // prime failure is logged but does NOT abort boot — an operator with
    // no upstream mappings configured (or a transient DB hiccup) sees an
    // empty resolver, which is correct for the hosted-only deployment
    // shape; the background refresh task re-primes on its next tick.
    match upstream_mappings_for_provenance.list_all().await {
        Ok(snapshot) => {
            let n = caching_resolver.reload(snapshot);
            tracing::info!(
                mappings_loaded = n,
                "worker upstream resolver primed from initial snapshot"
            );
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "worker upstream resolver initial prime failed; \
                 cache stays empty until next refresh tick"
            );
        }
    }
    // Background refresh task — mirrors `hort-server::cli::serve`'s
    // resolver-refresh loop: poll `list_all` on the interval and swap the
    // snapshot atomically. Same env var + default + floor as the server
    // (`HORT_UPSTREAM_RESOLVER_REFRESH_SECS`). The
    // worker composition does not own the process `CancellationToken` (it
    // is created in `main.rs` after composition), so this is a detached
    // loop dropped when the runtime shuts down on process exit — a
    // stateless cache refresh has no cleanup obligation, unlike the
    // dispatcher / heartbeat loops which carry shutdown tokens.
    {
        let resolver = caching_resolver.clone();
        let mappings = upstream_mappings_for_provenance.clone();
        let interval = worker_resolver_refresh_interval();
        tracing::info!(
            interval_secs = interval.as_secs(),
            "worker upstream resolver refresh task enabled"
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match mappings.list_all().await {
                    Ok(snapshot) => {
                        let n = resolver.reload(snapshot);
                        tracing::debug!(
                            mappings_loaded = n,
                            "worker upstream resolver snapshot refreshed"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "worker upstream resolver refresh failed; previous snapshot retained"
                        );
                    }
                }
            }
        });
    }
    let upstream_resolver_for_provenance: Arc<dyn UpstreamResolver> = caching_resolver;
    register_provenance_verify(
        &mut dispatcher,
        cfg,
        artifacts.clone(),
        repositories.clone(),
        policy_projections.clone(),
        content_references.clone(),
        storage.clone(),
        lifecycle.clone(),
        event_publisher.clone(),
        upstream_proxy_for_provenance,
        upstream_resolver_for_provenance,
    )
    .await?;

    dispatcher.register(Arc::new(NoopTaskHandler), 16);

    let ctx = Arc::new(WorkerContext {
        orchestration,
        jobs,
        scanner_registry,
        worker_id: cfg.worker_id.clone(),
        scanners: healthy_names,
        config: cfg.clone(),
        pool,
    });

    Ok(BuildOutput { ctx, dispatcher })
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

/// Backlog 078 Item 6 (chart S3) — apply the load-bearing scanner
/// `enabled` flags BEFORE the `--version` health probe.
///
/// Takes the `(enabled, adapter)` pairs in declared order and returns
/// only the flag-enabled adapters, preserving order. A flag-disabled
/// backend is dropped here so it is never health-probed and never
/// registered — the flag is the enabling gate, not the probe. This is
/// the structural close for the pre-078 "cosmetic only" `enabled` flag
/// (the probe used to be the real gate, so `enabled: false` did not
/// reliably disable a backend whose binary was present).
///
/// Pure (no I/O, no probe) so the flag-gates-registration invariant is
/// unit-testable without a live Postgres connection or a real Trivy /
/// osv-scanner binary on PATH (see the `select_enabled_scanners_*`
/// tests).
pub(crate) fn select_enabled_scanners(
    pairs: &[(bool, Arc<dyn ScannerPort>)],
) -> Vec<Arc<dyn ScannerPort>> {
    pairs
        .iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, adapter)| adapter.clone())
        .collect()
}

/// Probe every configured scanner backend's `health_check` and refuse
/// to start if ANY backend fails. Returns the ordered list of healthy
/// backend names.
///
/// Probe every configured scanner backend's `health_check` and refuse
/// to start if ANY backend fails. "Failure means the backend is not
/// deployable; the worker logs and exits non-zero." The previous
/// implementation only failed when every backend was missing, hiding
/// silently misconfigured runtime images (an operator who accidentally
/// dropped the `osv-scanner` binary from the image would not learn until
/// a `ScanPolicy.scan_backends=["osv"]` job was claimed and failed).
/// Strict fail-fast surfaces the misconfig at pod-boot time.
pub(crate) async fn health_check_all_or_fail(
    scanners: &[Arc<dyn ScannerPort>],
) -> anyhow::Result<Vec<String>> {
    let mut healthy_names = Vec::with_capacity(scanners.len());
    for s in scanners {
        let name = s.name().to_string();
        match s.health_check().await {
            Ok(()) => {
                tracing::info!(scanner = %name, "scanner health check OK");
                healthy_names.push(name);
            }
            Err(e) => {
                tracing::error!(
                    scanner = %name,
                    error = %e,
                    "scanner backend failed its health check; refusing to start"
                );
                return Err(anyhow!(
                    "scanner backend {name:?} failed its health check: {e}. \
                     Refusing to start — verify the binary is on PATH or set \
                     HORT_SCANNER_TRIVY_BIN / HORT_SCANNER_OSV_BIN to a \
                     discoverable binary, or rebuild the runtime image with \
                     the missing binary included."
                ));
            }
        }
    }
    Ok(healthy_names)
}

/// Wire the cosign/Sigstore `ProvenanceVerifyHandler` into the dispatcher,
/// gated on the load-bearing `worker.provenance.cosign.enabled`
/// (`HORT_PROVENANCE_COSIGN_ENABLED`). See ADR 0027.
///
/// When the flag is **off** (the default): logs an `info!`, registers
/// nothing, returns `Ok(())`. Provenance verification is fully inert —
/// `provenance-verify` jobs sit unclaimed; a `Required`-mode artifact
/// stays `Pending` (fail-closed). The flag is the enabling gate, not a
/// probe.
///
/// When the flag is **on**:
/// 1. Resolves the **pinned** `trusted_root.json` path
///    (`HORT_PROVENANCE_TRUSTED_ROOT_FILE`). A missing/unset/unreadable
///    path is a **hard boot error** (`Err`). Trust-root provisioning uses
///    a pinned file with **NO live fetch**: bytes are loaded from disk via
///    `CachedTrustRoot::from_trusted_root_json`. The trust root rotates
///    via Hort releases (ADR 0010 — no live TUF client on the verify
///    path). The adapter's `refresh_trusted_root_json` live-refresh
///    method is deliberately **unreferenced** by this composition.
/// 2. Constructs the `SigstoreProvenanceAdapter` as the single
///    `Arc<dyn ProvenancePort>`.
/// 3. Runs the port's `health_check()` — failure ⇒ `Err`. The check
///    verifies the cached trust root is loaded + within its refresh
///    window; it does NOT probe live Rekor/Fulcio (offline verify path).
/// 4. Builds the `ProvenanceOrchestrationUseCase` and registers the
///    `ProvenanceVerifyHandler` (single-active, concurrency = 1).
#[allow(clippy::too_many_arguments)]
async fn register_provenance_verify(
    dispatcher: &mut TaskDispatcher,
    cfg: &WorkerConfig,
    artifacts: Arc<dyn ArtifactRepository>,
    repositories: Arc<dyn RepositoryRepository>,
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    content_references: Arc<dyn ContentReferenceIndex>,
    storage: Arc<dyn StoragePort>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    event_publisher: Arc<EventStorePublisher>,
    // The two orchestration deps for the proxy referrer-fetch arm.
    // `upstream_proxy` reuses the prefetch adapter; `upstream_resolver`
    // decides whether a repo is a proxy scope.
    upstream_proxy: Arc<dyn UpstreamProxy>,
    upstream_resolver: Arc<dyn UpstreamResolver>,
) -> anyhow::Result<()> {
    if !cfg.provenance_cosign_enabled {
        tracing::info!(
            "ProvenanceVerifyHandler not registered: HORT_PROVENANCE_COSIGN_ENABLED is false \
             (worker.provenance.cosign.enabled). Provenance verification is inert — \
             provenance-verify jobs dispatch to no handler. A repository policy with \
             provenance_mode: required on a verifiable format then leaves artifacts \
             Pending (fail-closed); enable cosign + provision a pinned trust root to \
             activate enforcement."
        );
        return Ok(());
    }

    // Flag is ON — the pinned trust-root path is REQUIRED. A missing /
    // unset / unreadable path is a hard boot failure (design §6).
    let trusted_root_path = cfg.provenance_trusted_root_file.as_ref().ok_or_else(|| {
        anyhow!(
            "HORT_PROVENANCE_COSIGN_ENABLED is true but HORT_PROVENANCE_TRUSTED_ROOT_FILE is \
             unset (worker.provenance.cosign.trustedRootFile). The cosign verifier loads a \
             PINNED Sigstore trusted_root.json (no live fetch); set the path to the mounted \
             trust-root file and rotate it through the image/release pipeline."
        )
    })?;
    let trusted_root_bytes = std::fs::read(trusted_root_path).map_err(|e| {
        anyhow!(
            "failed to read the pinned Sigstore trust root at {}: {e}. \
             Provision worker.provenance.cosign.trustedRootFile (a mounted trusted_root.json) \
             before enabling the cosign verifier.",
            trusted_root_path.display()
        )
    })?;
    let cached_trust_root =
        hort_adapters_provenance_sigstore::CachedTrustRoot::from_trusted_root_json(
            &trusted_root_bytes,
        )
        .map_err(|e| {
            anyhow!(
                "the pinned Sigstore trust root at {} did not parse as a trusted_root.json: {e}",
                trusted_root_path.display()
            )
        })?;
    let provenance_port: Arc<dyn ProvenancePort> = Arc::new(
        hort_adapters_provenance_sigstore::SigstoreProvenanceAdapter::new(cached_trust_root),
    );

    // Startup health check (mirrors the scanner `health_check_all_or_fail`
    // posture): the trust root must be loaded + fresh, else refuse to
    // start. Offline only — never probes live Rekor/Fulcio (design §6).
    provenance_port.health_check().await.map_err(|e| {
        anyhow!(
            "cosign provenance verifier {:?} failed its startup health check: {e}. \
             The pinned trust root is missing or stale (outside its refresh window). \
             Refusing to start — provision a current trusted_root.json (rotated via the \
             Hort image/release pipeline).",
            provenance_port.name()
        )
    })?;
    tracing::info!(
        backend = %provenance_port.name(),
        trusted_root_path = %trusted_root_path.display(),
        "cosign provenance verifier health check OK (pinned trust root loaded + fresh)"
    );

    let orchestration = Arc::new(ProvenanceOrchestrationUseCase::new(
        artifacts,
        repositories,
        policy_projections,
        content_references,
        storage,
        lifecycle,
        event_publisher,
        vec![provenance_port],
        upstream_proxy,
        upstream_resolver,
    ));
    dispatcher.register(
        Arc::new(ProvenanceVerifyHandler::new(orchestration)),
        1, // single-active per worker replica — parallelism via replicas
    );
    tracing::info!(
        "ProvenanceVerifyHandler registered (single-active per worker replica) \
         — cosign/OCI provenance verification is now wired"
    );
    Ok(())
}

/// The worker's upstream-resolver refresh interval.
///
/// Mirrors `hort-server`'s `HORT_UPSTREAM_RESOLVER_REFRESH_SECS`:
/// same env var, same 60s default, same 5s floor. The worker
/// `WorkerConfig` does not carry a typed slot for this
/// (no other worker code path consumes it), so the composition reads it
/// directly — the same env-var-read-in-composition shape the worker
/// already uses for `HORT_SECRETS_FILE_ROOT` / the `HORT_SCANNER_*` size
/// knobs. An unset/invalid/below-floor value collapses to the default,
/// so a misconfigured value degrades to the safe interval rather than a
/// boot failure (the server rejects below-floor at config parse; the
/// worker's lighter-weight read clamps instead — the refresh interval is
/// a freshness knob, not a security boundary, so clamping is benign).
fn worker_resolver_refresh_interval() -> Duration {
    const DEFAULT_SECS: u64 = 60;
    const FLOOR_SECS: u64 = 5;
    let secs = std::env::var("HORT_UPSTREAM_RESOLVER_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s >= FLOOR_SECS)
        .unwrap_or(DEFAULT_SECS);
    Duration::from_secs(secs)
}

/// Apply the defense-in-depth Postgres `lock_timeout` (in ms) to a
/// worker pool builder via `.after_connect` (ADR 0020).
///
/// `seal_and_remove`'s chained `StreamSealed` append has *no internal
/// wait bound*, safe only under the §10.2-INV single-flight precondition.
/// This connection-level `lock_timeout` is the backstop: if single-flight
/// is violated, a contended-slot wait degrades to the §10.2 fail-safe
/// (`Err` → `errors += 1` → retry next sweep) rather than an unbounded
/// sweep stall.
///
/// `lock_timeout`, **not** `statement_timeout` — deliberate: it bounds
/// only lock-acquisition wait, so it fires on the pathological "blocked
/// on a peer's uncommitted unique slot" case and never aborts a
/// legitimately slow large-stream `DELETE`.
///
/// `ms == 0` → the backstop is disabled (Postgres default); the
/// builder is returned unchanged with no `after_connect` hook
/// registered. Otherwise the mirror of `serve.rs:257` exactly: a
/// per-connection `SET` failure is logged via `warn!` and surfaced as
/// `Err` so the operator sees the configured bound is not in force on
/// that connection. `ms: u64` is parsed from an env var by
/// `WorkerConfig::from_env`, not user input — interpolating it into
/// the `SET` string is safe (Postgres rejects bind params for `SET`).
fn apply_lock_timeout(pool_options: PgPoolOptions, ms: u64) -> PgPoolOptions {
    if ms == 0 {
        return pool_options;
    }
    pool_options.after_connect(move |conn, _meta| {
        Box::pin(async move {
            // `ms: u64` — safe to interpolate; see fn doc.
            let sql = format!("SET lock_timeout = '{ms}'");
            if let Err(err) = conn.execute(sql.as_str()).await {
                tracing::warn!(
                    lock_timeout_ms = ms,
                    error = %err,
                    "failed to apply lock_timeout on new connection"
                );
                return Err(err);
            }
            Ok(())
        })
    })
}

/// `std::time::Duration` → `chrono::Duration` for
/// `canonical_retention_rules` (which takes `chrono::Duration`s). The
/// worker config holds the C-1 floors as `std::time::Duration` (env
/// parsing); the canonical builder is `chrono`-typed. The day-count
/// floors are far below `i64::MAX` milliseconds, so the conversion is
/// lossless; a pathological overflow saturates rather than panics.
fn chrono_duration(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

fn build_storage(cfg: &StorageConfig) -> anyhow::Result<Arc<dyn StoragePort>> {
    match cfg {
        StorageConfig::Filesystem { root } => Ok(Arc::new(FilesystemStorage::new(root.clone()))),
        StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            force_path_style,
            allow_http,
            access_key_id,
            secret_access_key,
        } => {
            let opts = S3StorageOpts {
                bucket,
                region,
                endpoint: endpoint.as_deref(),
                force_path_style: *force_path_style,
                allow_http: *allow_http,
                access_key: access_key_id,
                secret_key: secret_access_key,
                extra_trust_anchors: None,
                sse_mode: None,
            };
            let adapter = build_s3_storage(&opts).context("building S3 storage adapter")?;
            Ok(Arc::new(adapter))
        }
    }
}

/// Wire the `ServiceAccountRotationHandler` into the dispatcher when the
/// `KubernetesSecretWriter` adapter constructs successfully AND
/// `HORT_PUBLIC_REGISTRY_HOST` is set.
///
/// Failure modes (each surfaces as a `tracing::info!` and returns
/// without registering — the rest of the worker keeps booting):
/// - `try_in_cluster()` fails — no kube credentials / not in-cluster
///   AND no kubeconfig. The handler is not registered; admin POSTs
///   to `/api/v1/admin/tasks/service-account-rotation` get a 404
///   from the kind-dispatch table.
/// - `HORT_PUBLIC_REGISTRY_HOST` not set — the
///   `dockerconfigjson.auths` payload would have nowhere to point.
///   Refuse to register rather than write empty hosts.
async fn register_service_account_rotation(
    dispatcher: &mut TaskDispatcher,
    pool: &PgPool,
    event_store: &Arc<dyn EventStore>,
    cfg: &WorkerConfig,
) {
    let writer = match KubernetesSecretWriterImpl::try_in_cluster().await {
        Ok(w) => w,
        Err(err) => {
            tracing::info!(
                error = %err,
                "ServiceAccountRotationHandler not registered: kube::Client::try_default failed \
                 (no in-cluster auth and no kubeconfig); the worker is running on a non-k8s host",
            );
            return;
        }
    };
    let Some(registry_host) = cfg.public_registry_host.clone() else {
        tracing::info!(
            "ServiceAccountRotationHandler not registered: HORT_PUBLIC_REGISTRY_HOST is unset; \
             set it to the operator-facing registry hostname (e.g. \"registry.example.test\") \
             to enable rotation",
        );
        return;
    };

    let secret_writer: Arc<dyn KubernetesSecretWriter> = Arc::new(writer);
    let service_accounts: Arc<dyn ServiceAccountRepository> =
        Arc::new(PgServiceAccountRepository::new(pool.clone()));
    let api_tokens_repo: Arc<dyn ApiTokenRepository> =
        Arc::new(PgApiTokenRepository::new(pool.clone()));
    let users_repo: Arc<dyn UserRepository> = Arc::new(PgUserRepository::new(pool.clone()));

    // The system-mint path on `ApiTokenUseCase` skips the
    // cap-vs-authority gate, so the evaluator is structurally
    // required by the constructor but never consulted on the
    // rotation tick. An empty evaluator keeps the wiring honest
    // (any future use case that landed on the same `Arc` would
    // see a correctly-typed but-empty RBAC view).
    let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new())));
    // The worker does not run the notification dispatcher (that is
    // hort-server's role), so a non-broadcasting transparent wrapper is
    // the correct shape here.
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(event_store.clone()));
    let api_tokens = Arc::new(ApiTokenUseCase::new(
        api_tokens_repo,
        users_repo,
        event_publisher,
        rbac,
        ApiTokenIssuanceConfig::default(),
    ));

    let handler = ServiceAccountRotationHandler::new(
        service_accounts,
        secret_writer,
        api_tokens,
        event_store.clone(),
        cfg.rotation_namespaces.clone(),
        registry_host,
    )
    // Mirror `cfg.include_service_account_label` (parsed from
    // `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL`, same as hort-server's
    // `Config`) into the rotation handler so the per-SA dimension on
    // `hort_rotation_lag_seconds` and
    // `hort_service_account_authenticated_total` stay in lock-step
    // under operator-flipped cardinality control.
    .with_include_service_account_label(cfg.include_service_account_label);
    dispatcher.register(Arc::new(handler), 1);
    tracing::info!(
        target_namespace_count = cfg.rotation_namespaces.len(),
        "ServiceAccountRotationHandler registered (single-active per worker replica)",
    );
}

/// Wire the `EventstoreCheckpointHandler` (F-2 external-anchor I2) into
/// the dispatcher.
///
/// Registers only when **all** of the following hold; otherwise logs an
/// `info!` and returns without registering (the
/// `/api/v1/admin/tasks/eventstore-checkpoint` route then 404s — the
/// same graceful-skip posture as `register_service_account_rotation`):
///
/// 1. Storage is S3 — Object-Lock WORM anchoring requires an S3-
///    compatible object store (a filesystem deployment has no WORM
///    anchor; spec §6.1). The store is built via `build_s3_object_store`
///    so ADR 0010 TLS posture applies (no `reqwest::Client::new()`).
/// 2. `HORT_EVENT_CHAIN_ANCHOR_SIGNING_KEY_FILE` points to the
///    operator-provisioned Ed25519 PKCS#8 PEM **private** key (§14 R2 —
///    distinct from any runtime credential, never embedded/derived). A
///    missing/malformed key fails adapter construction here, loudly —
///    never a silent unsigned checkpoint.
/// 3. `HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE` points to the matching SPKI
///    PEM **public** key (the same file `hort-server verify-event-chain`
///    reads) — used to derive the next monotonic `checkpoint_seq` +
///    the first-post-migration test via the shipped Item-3 read adapter.
///
/// The §5 `backfill_baseline` honesty caveat is sourced from
/// `HORT_EVENT_CHAIN_BACKFILL_MAX_GLOBAL_POSITION` +
/// `HORT_EVENT_CHAIN_MIGRATION_TIMESTAMP` (operator-provisioned — the
/// in-migration backfill recorded these). Absent ⇒ no baseline is
/// stamped (a green-field deploy with no pre-chain history; correct).
async fn register_eventstore_checkpoint(
    dispatcher: &mut TaskDispatcher,
    pool: &PgPool,
    cfg: &WorkerConfig,
    extra_ca: Option<&hort_config::ExtraTrustAnchors>,
) {
    let StorageConfig::S3 {
        bucket,
        region,
        endpoint,
        force_path_style,
        allow_http,
        access_key_id,
        secret_access_key,
    } = &cfg.storage
    else {
        tracing::info!(
            "EventstoreCheckpointHandler not registered: storage is filesystem, not S3 \
             — S3 Object-Lock WORM is required to anchor checkpoints (F-2 spec §6.1). \
             The /api/v1/admin/tasks/eventstore-checkpoint route will 404 until an \
             S3 anchor bucket is configured.",
        );
        return;
    };

    let signing_key_pem = match std::env::var("HORT_EVENT_CHAIN_ANCHOR_SIGNING_KEY_FILE") {
        Ok(path) => match std::fs::read_to_string(&path) {
            Ok(pem) => pem,
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "EventstoreCheckpointHandler not registered: \
                     HORT_EVENT_CHAIN_ANCHOR_SIGNING_KEY_FILE is set but unreadable. \
                     Provision the operator Ed25519 PKCS#8 PEM private key (§14 R2).",
                );
                return;
            }
        },
        Err(_) => {
            tracing::info!(
                "EventstoreCheckpointHandler not registered: \
                 HORT_EVENT_CHAIN_ANCHOR_SIGNING_KEY_FILE is unset. Set it to the \
                 operator-provisioned Ed25519 PKCS#8 PEM private key (the private \
                 counterpart of HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE) to enable F-2 \
                 checkpoint emission (§14 R2).",
            );
            return;
        }
    };

    let public_key_pem = match std::env::var("HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE") {
        Ok(path) => match std::fs::read_to_string(&path) {
            Ok(pem) => pem,
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "EventstoreCheckpointHandler not registered: \
                     HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE is set but unreadable.",
                );
                return;
            }
        },
        Err(_) => {
            tracing::info!(
                "EventstoreCheckpointHandler not registered: \
                 HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE is unset (needed to derive the \
                 next checkpoint_seq via the shipped Item-3 read adapter).",
            );
            return;
        }
    };

    let opts = S3StorageOpts {
        bucket,
        region,
        endpoint: endpoint.as_deref(),
        force_path_style: *force_path_style,
        allow_http: *allow_http,
        access_key: access_key_id,
        secret_key: secret_access_key,
        extra_trust_anchors: extra_ca,
        sse_mode: None,
    };
    let store = match build_s3_object_store(&opts) {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                error = %e,
                "EventstoreCheckpointHandler not registered: building the S3 anchor \
                 object store failed.",
            );
            return;
        }
    };

    let reader = match ObjectStoreCheckpointAnchor::new(store.clone(), &public_key_pem) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            tracing::info!(
                error = %e,
                "EventstoreCheckpointHandler not registered: the anchor public-key \
                 PEM did not parse as an Ed25519 SPKI key (§14 R2).",
            );
            return;
        }
    };
    let emitter = match ObjectStoreCheckpointEmitter::new(store, &signing_key_pem) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            // A malformed signing key fails HERE (loudly), never a
            // silent unsigned checkpoint (§14 R2).
            tracing::info!(
                error = %e,
                "EventstoreCheckpointHandler not registered: the anchor signing-key \
                 PEM did not parse as an Ed25519 PKCS#8 private key (§14 R2).",
            );
            return;
        }
    };

    let heads = Arc::new(PgEventChainHeadReader::new(pool.clone()));

    // §5 honesty caveat — operator-provisioned. Both env vars must be
    // present together; a malformed value disables the baseline (the
    // first checkpoint then carries none) but still registers the
    // handler — the chain is still emitted, only the honesty caveat is
    // omitted, which a startup `info!` surfaces.
    let backfill_baseline = read_backfill_baseline();

    dispatcher.register(
        Arc::new(EventstoreCheckpointHandler::new(
            heads,
            reader,
            emitter,
            backfill_baseline.clone(),
        )),
        1, // single-active — see the call-site rationale.
    );
    tracing::info!(
        bucket = %bucket,
        backfill_baseline = backfill_baseline.is_some(),
        "EventstoreCheckpointHandler registered (single-active per worker replica) \
         — F-2 external-anchor (I2) emission is now wired",
    );
}

/// Read the §5 backfill-baseline honesty-caveat inputs from the
/// operator env. Returns `None` (no baseline stamped on the first
/// checkpoint) when either var is absent or unparseable — a green-field
/// deploy with no pre-chain history, or a misconfiguration the caller
/// surfaces via `info!`. The values were recorded by the in-migration
/// backfill (spec §5).
fn read_backfill_baseline() -> Option<BackfillBaselineConfig> {
    let max_gp: u64 = std::env::var("HORT_EVENT_CHAIN_BACKFILL_MAX_GLOBAL_POSITION")
        .ok()?
        .parse()
        .ok()?;
    let migration_timestamp = std::env::var("HORT_EVENT_CHAIN_MIGRATION_TIMESTAMP")
        .ok()?
        .parse::<chrono::DateTime<chrono::Utc>>()
        .ok()?;
    Some(BackfillBaselineConfig {
        baseline_max_global_position: max_gp,
        migration_timestamp,
    })
}

/// Schema-version assertion. Mirrors `hort-server::migrate::assert_current`
/// shape exactly (does NOT create the bookkeeping table — the runtime
/// `hort_app_role` does not have `CREATE TABLE` privilege). Copied rather
/// than depended-on so the worker does not pull in `hort-server`.
async fn assert_schema_current(pool: &PgPool) -> anyhow::Result<()> {
    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");
    let expected: i64 = MIGRATOR
        .iter()
        .map(|m| m.version)
        .max()
        .expect("migration set is non-empty at compile time");

    let row: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01") => {
                anyhow!(
                    "_sqlx_migrations not found — run `hort-server migrate` (or wait for the chart's \
                     migrate Job) before starting the scanner worker"
                )
            }
            sqlx::Error::Database(db) if db.code().as_deref() == Some("42501") => anyhow!(
                "permission denied reading _sqlx_migrations — grant SELECT on _sqlx_migrations \
                 to the runtime role (see docs/architecture/how-to/deploy/postgres-roles.md)"
            ),
            other => other.into(),
        })?;
    let applied = row.unwrap_or(0);

    if applied != expected {
        anyhow::bail!(
            "schema version mismatch: applied={applied}, binary expects={expected}. \
             Run `hort-server migrate` to advance, or roll the binary back to match the schema."
        );
    }

    tracing::info!(
        applied_version = applied,
        expected_version = expected,
        "schema version OK"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Composition-time tests are limited to the parts that don't
    //! need a live Postgres connection. The full
    //! [`build_app_context`] path is exercised in
    //! `tests/composition_smoke.rs` (DATABASE_URL-gated).

    use super::*;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{ContentHash, Finding, Sbom};
    use std::path::PathBuf;

    #[test]
    fn build_storage_filesystem_constructs_adapter() {
        let cfg = StorageConfig::Filesystem {
            root: PathBuf::from("/tmp/hort-test"),
        };
        let storage = build_storage(&cfg).expect("filesystem storage builds");
        // Cheap shape check — the trait object is constructed.
        let _: Arc<dyn StoragePort> = storage;
    }

    /// `MockScanner` — minimal `ScannerPort` carrying a name + a
    /// programmable health-check outcome. `scan` is unused for the
    /// H1 tests below.
    struct MockScanner {
        name: String,
        healthy: bool,
    }

    impl ScannerPort for MockScanner {
        fn name(&self) -> &str {
            &self.name
        }
        fn scan<'a>(
            &'a self,
            _content_hash: &'a ContentHash,
            _sbom: Option<&'a Sbom>,
        ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
            let healthy = self.healthy;
            let name = self.name.clone();
            Box::pin(async move {
                if healthy {
                    Ok(())
                } else {
                    Err(DomainError::Invariant(format!(
                        "{name} binary not found on PATH"
                    )))
                }
            })
        }
    }

    /// H1: every backend healthy → returns the full ordered name list.
    #[tokio::test]
    async fn health_check_all_or_fail_returns_all_names_when_healthy() {
        let scanners: Vec<Arc<dyn ScannerPort>> = vec![
            Arc::new(MockScanner {
                name: "trivy".into(),
                healthy: true,
            }),
            Arc::new(MockScanner {
                name: "osv".into(),
                healthy: true,
            }),
        ];
        let names = health_check_all_or_fail(&scanners)
            .await
            .expect("all-healthy must succeed");
        assert_eq!(names, vec!["trivy".to_string(), "osv".to_string()]);
    }

    /// H1: even a SINGLE unhealthy backend must propagate `Err` —
    /// the spec (§4.2) says "the worker logs and exits non-zero."
    /// The previous "tolerate degraded boot if at least one is
    /// healthy" behaviour is removed.
    #[tokio::test]
    async fn health_check_all_or_fail_propagates_err_when_any_backend_unhealthy() {
        let scanners: Vec<Arc<dyn ScannerPort>> = vec![
            Arc::new(MockScanner {
                name: "trivy".into(),
                healthy: true,
            }),
            // OSV's binary missing — the strict spec says this whole
            // worker must refuse to boot.
            Arc::new(MockScanner {
                name: "osv".into(),
                healthy: false,
            }),
        ];
        let err = health_check_all_or_fail(&scanners)
            .await
            .expect_err("single failure must propagate Err under fail-fast policy");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("\"osv\""),
            "error must name the failing backend: {msg}"
        );
        assert!(
            msg.contains("Refusing to start"),
            "error must signal refusal-to-start: {msg}"
        );
    }

    /// H1: every backend unhealthy is also fatal (was the prior
    /// boundary case — kept to lock the regression).
    #[tokio::test]
    async fn health_check_all_or_fail_propagates_err_when_all_backends_unhealthy() {
        let scanners: Vec<Arc<dyn ScannerPort>> = vec![
            Arc::new(MockScanner {
                name: "trivy".into(),
                healthy: false,
            }),
            Arc::new(MockScanner {
                name: "osv".into(),
                healthy: false,
            }),
        ];
        let err = health_check_all_or_fail(&scanners)
            .await
            .expect_err("all-unhealthy must propagate Err");
        // The first backend in the list (trivy) reports first.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("\"trivy\""),
            "error must name the FIRST failing backend (early-exit): {msg}"
        );
    }

    /// H1: empty backend list returns `Ok(empty)` — purely structural;
    /// the orchestrator's downstream "no backends" path is the right
    /// place to handle "no backends configured."
    #[tokio::test]
    async fn health_check_all_or_fail_handles_empty_backend_list() {
        let scanners: Vec<Arc<dyn ScannerPort>> = Vec::new();
        let names = health_check_all_or_fail(&scanners)
            .await
            .expect("empty list is structurally OK");
        assert!(names.is_empty());
    }

    // -- Backlog 078 Item 6 (chart S3) — load-bearing `enabled` flag -------
    //
    // The flag gates registration BEFORE the probe; a flag-disabled
    // backend is dropped even when its binary probe would pass. These
    // tests stub the probe to "available" (`healthy: true`) and assert
    // the flag still wins.

    /// The Trivy flag DISABLED drops Trivy from the configured set
    /// **even though its probe would pass** (`healthy: true`) — the flag
    /// is the gate, not the probe. OSV (flag enabled) survives and would
    /// be the only backend health-probed.
    #[tokio::test]
    async fn select_enabled_scanners_disabled_trivy_dropped_despite_healthy_probe() {
        let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "trivy".into(),
            // The probe WOULD pass — proving the flag, not the probe, is
            // the enabling gate.
            healthy: true,
        });
        let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "osv".into(),
            healthy: true,
        });
        // trivy flag = false, osv flag = true.
        let configured = select_enabled_scanners(&[(false, trivy), (true, osv)]);
        let names: Vec<String> = configured.iter().map(|s| s.name().to_string()).collect();
        assert_eq!(
            names,
            vec!["osv".to_string()],
            "a flag-disabled Trivy must be dropped even when its probe would pass"
        );
        // And the surviving (flag-enabled) backend still goes through the
        // unchanged probe path.
        let healthy = health_check_all_or_fail(&configured)
            .await
            .expect("the flag-enabled OSV backend probes healthy");
        assert_eq!(healthy, vec!["osv".to_string()]);
    }

    /// Symmetric: the OSV flag DISABLED drops OSV despite a healthy
    /// probe; Trivy (flag enabled) survives.
    #[tokio::test]
    async fn select_enabled_scanners_disabled_osv_dropped_despite_healthy_probe() {
        let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "trivy".into(),
            healthy: true,
        });
        let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "osv".into(),
            healthy: true,
        });
        let configured = select_enabled_scanners(&[(true, trivy), (false, osv)]);
        let names: Vec<String> = configured.iter().map(|s| s.name().to_string()).collect();
        assert_eq!(
            names,
            vec!["trivy".to_string()],
            "a flag-disabled OSV must be dropped even when its probe would pass"
        );
    }

    /// Both flags ENABLED → the probe behaviour is unchanged: every
    /// flag-enabled backend is health-probed and registered in declared
    /// order.
    #[tokio::test]
    async fn select_enabled_scanners_both_enabled_preserves_probe_path() {
        let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "trivy".into(),
            healthy: true,
        });
        let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "osv".into(),
            healthy: true,
        });
        let configured = select_enabled_scanners(&[(true, trivy), (true, osv)]);
        let healthy = health_check_all_or_fail(&configured)
            .await
            .expect("both flag-enabled, both probe healthy");
        assert_eq!(
            healthy,
            vec!["trivy".to_string(), "osv".to_string()],
            "both flags enabled must preserve the unchanged probe path + order"
        );
    }

    /// Both flags DISABLED → an empty configured set. The composition
    /// root turns this into a hard boot error (see `build_app_context`);
    /// the selector itself just returns the empty vec.
    #[test]
    fn select_enabled_scanners_both_disabled_is_empty() {
        let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "trivy".into(),
            healthy: true,
        });
        let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner {
            name: "osv".into(),
            healthy: true,
        });
        let configured = select_enabled_scanners(&[(false, trivy), (false, osv)]);
        assert!(
            configured.is_empty(),
            "both flags disabled selects no backends"
        );
    }
}
