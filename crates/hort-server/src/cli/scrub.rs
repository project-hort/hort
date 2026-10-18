//! `hort-server scrub` — CAS integrity scrubber CLI.
//!
//! Inbound adapter for
//! [`hort_app::use_cases::cas_scrub_use_case::CasScrubUseCase`].
//! This module parses CLI arguments, builds the composition
//! (storage + event store), invokes the use case, and maps the
//! `ScrubReport` to a process exit code. No scrub logic here.
//!
//! **Exit codes:**
//! - `0` on `ScrubReport.mismatches == 0` — includes runs where
//!   `missing` or `read_errors` were non-zero. Those are operational
//!   signals (via metric + tracing), not scrub-gate failures.
//! - `1` on any `mismatches > 0` — cron-escalatable. Paired with
//!   `hort_cas_scrub_checks_total{result="hash_mismatch"}` spikes on the
//!   dashboard.
//! - `FAILURE` (non-zero, unspecified) on config/connection errors —
//!   the scrub never ran.
//!
//! **Scope decision:** the scrub is a one-shot cron job; we use the
//! native async runtime directly (no `spawn_blocking` wrapper — the
//! re-hash is IO-bound, not CPU-bound). Matches the
//! [`super::migrate`] / [`super::admin`] pattern.

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle;
use hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::use_cases::cas_scrub_use_case::{
    ActionOnMismatch, CasScrubUseCase, ScrubOpts, ScrubReport,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::storage::StoragePort;

use crate::composition;
use crate::config::Config;
use crate::{pg_identity, storage, telemetry};

/// Default concurrency — matches `ScrubOpts::defaults()`. Pin via a
/// constant so clap's `help` output advertises the same value the use
/// case uses.
const DEFAULT_CONCURRENCY: usize = 4;
/// Default sample fraction (`1.0` = every blob).
const DEFAULT_SAMPLE_FRACTION: f64 = 1.0;

/// Arguments to `hort-server scrub`.
#[derive(Debug, Args)]
pub struct ScrubArgs {
    /// Maximum number of re-hash tasks in flight. IO-bound — higher
    /// values help when the CAS backend is latency-dominated (S3 over
    /// WAN); lower values cap the blast radius if a scrub is causing
    /// contention with the serving path. Must be >= 1.
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    pub concurrency: usize,

    /// Per-blob sampling probability in `[0.0, 1.0]`. `1.0` scrubs
    /// every blob; `0.1` ≈ 10%. Skipped blobs are not counted,
    /// logged, or metric-emitted — the scrub is silent about what it
    /// didn't check. For sampling-based cron schedules, operators
    /// typically hold the cadence fixed (hourly) and vary this knob.
    #[arg(long, default_value_t = DEFAULT_SAMPLE_FRACTION)]
    pub sample_fraction: f64,
}

/// Entry point. Delegates to [`super::run_with_runtime`] which builds
/// a Tokio runtime, runs [`run_async`], and maps the `ScrubReport` to a
/// process exit code via [`report_to_exit_code`] (0 on clean, 1 on any
/// mismatch — cron-escalatable).
pub fn run(args: ScrubArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), report_to_exit_code)
}

async fn run_async(args: ScrubArgs) -> anyhow::Result<ScrubReport> {
    // `Config::from_env` enforces the trust-policy check. Running
    // the scrub in an environment that wouldn't serve reports that
    // early — avoids the "scrub ran clean against an empty DB because
    // DATABASE_URL was wrong" surprise.
    let cfg = Config::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;

    info!(
        concurrency = args.concurrency,
        sample_fraction = args.sample_fraction,
        action_on_mismatch = cfg.cas_scrub_action_on_mismatch.as_str(),
        "hort-server scrub starting"
    );

    // Surface validation errors (bad flag values) before the expensive
    // pool + migration step so operators get a clean rejection.
    if args.sample_fraction < 0.0 || args.sample_fraction > 1.0 {
        anyhow::bail!(
            "--sample-fraction must be in [0.0, 1.0], got {}",
            args.sample_fraction
        );
    }
    if args.concurrency == 0 {
        anyhow::bail!("--concurrency must be >= 1, got 0");
    }

    // Parse the extra CA trust bundle (ADR 0010) so the
    // scrubber's S3 client trusts operator-supplied internal CAs. The
    // same env var is read by `serve` at boot; the scrub subcommand
    // is a separate process so it reads it independently.
    // Composition owns the parse; storage::build receives the value
    // directly, never via AppContext.
    let extra_trust_anchors =
        composition::read_extra_ca_bundle().map_err(|e| anyhow::anyhow!("extra CA bundle: {e}"))?;

    // Build storage from the same `StorageConfig` the server uses — one
    // source of truth for which backend is active. No bespoke flag here
    // (bespoke flags drift from the server path).
    let storage: Arc<dyn StoragePort> = storage::build(&cfg.storage, extra_trust_anchors.as_ref())?;

    // Event store uses the Postgres pool — migrations already applied
    // on the serving path; we do NOT re-run them here because the
    // scrubber is a read-mostly op and an accidental double-migrate
    // under load is worse than a missing migration (which would be
    // caught by `PgEventStore::new`'s invariant check).
    let pool = PgPoolOptions::new()
        .connect_with(pg_identity::connect_options(&cfg.database_url)?)
        .await
        .context("connecting to postgres")?;
    let pg_event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .context("constructing event store (is the immutability trigger installed?)")?,
    );
    let events: Arc<dyn EventStore> = pg_event_store.clone();
    // CLI scrub does not run the dispatcher, so wrap
    // in a no-broadcast publisher. The event-store path stays
    // pass-through; the use case sees the same trait surface.
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(events));

    // When the operator opted into tombstone-mode
    // (`HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone`), wire the
    // artifact-lookup + lifecycle ports so the scrubber can transition
    // corrupted artifacts to `quarantine_status = 'rejected'`. Alert
    // mode (the default) leaves them unwired — the use case then runs
    // the flag-only path (report, don't transition).
    let mut use_case = CasScrubUseCase::new(storage, event_publisher);
    if cfg.cas_scrub_action_on_mismatch == ActionOnMismatch::Tombstone {
        let artifact_repo = Arc::new(PgArtifactRepository::new(
            pool.clone(),
            pg_event_store.clone(),
        ));
        let metadata_repo = Arc::new(PgArtifactMetadataRepository::new(pool.clone()));
        let lifecycle = Arc::new(PgArtifactLifecycle::new(
            pg_event_store,
            artifact_repo.clone(),
            metadata_repo,
        ));
        use_case = use_case.with_artifact_lifecycle(
            artifact_repo as Arc<dyn ArtifactRepository>,
            lifecycle as Arc<dyn ArtifactLifecyclePort>,
        );
    }

    let opts = ScrubOpts {
        concurrency: args.concurrency,
        sample_fraction: args.sample_fraction,
        action_on_mismatch: cfg.cas_scrub_action_on_mismatch,
    };
    let report = use_case.run(opts).await.context("running cas scrub")?;

    // Print a one-line summary on stdout for shell capture. Cron
    // wrappers parse the exit code; this line gives humans something
    // to copy-paste.
    println!(
        "scrub: checked={} mismatches={} missing={} read_errors={}",
        report.checked, report.mismatches, report.missing, report.read_errors
    );

    Ok(report)
}

/// Map a `ScrubReport` to a `std::process::ExitCode`.
///
/// - `0` on clean (no mismatches).
/// - `1` on any mismatch — cron-escalatable.
fn report_to_exit_code(report: &ScrubReport) -> ExitCode {
    if report.mismatches == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: super::super::Command,
    }

    // -- CLI parsing --------------------------------------------------------

    #[test]
    fn scrub_parses_with_default_values() {
        let cli = TestCli::try_parse_from(["hort-server", "scrub"]).unwrap();
        let super::super::Command::Scrub(args) = cli.command else {
            panic!("expected Scrub");
        };
        assert_eq!(args.concurrency, DEFAULT_CONCURRENCY);
        assert!((args.sample_fraction - DEFAULT_SAMPLE_FRACTION).abs() < f64::EPSILON);
    }

    #[test]
    fn scrub_parses_with_explicit_concurrency() {
        let cli = TestCli::try_parse_from(["hort-server", "scrub", "--concurrency", "16"]).unwrap();
        let super::super::Command::Scrub(args) = cli.command else {
            panic!("expected Scrub");
        };
        assert_eq!(args.concurrency, 16);
    }

    #[test]
    fn scrub_parses_with_explicit_sample_fraction() {
        let cli =
            TestCli::try_parse_from(["hort-server", "scrub", "--sample-fraction", "0.1"]).unwrap();
        let super::super::Command::Scrub(args) = cli.command else {
            panic!("expected Scrub");
        };
        assert!((args.sample_fraction - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn scrub_rejects_non_numeric_concurrency() {
        let err =
            TestCli::try_parse_from(["hort-server", "scrub", "--concurrency", "many"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn scrub_rejects_non_numeric_sample_fraction() {
        let err = TestCli::try_parse_from(["hort-server", "scrub", "--sample-fraction", "much"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn scrub_help_renders() {
        let err = TestCli::try_parse_from(["hort-server", "scrub", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let rendered = err.to_string();
        assert!(rendered.contains("concurrency"));
        assert!(rendered.contains("sample-fraction"));
    }

    // -- Exit-code mapping --------------------------------------------------

    #[test]
    fn report_with_zero_mismatches_maps_to_success() {
        let report = ScrubReport {
            checked: 42,
            mismatches: 0,
            missing: 0,
            read_errors: 0,
            shards_truncated: 0,
        };
        assert_eq!(
            format!("{:?}", report_to_exit_code(&report)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn report_with_one_mismatch_maps_to_exit_one() {
        let report = ScrubReport {
            checked: 42,
            mismatches: 1,
            missing: 0,
            read_errors: 0,
            shards_truncated: 0,
        };
        assert_eq!(
            format!("{:?}", report_to_exit_code(&report)),
            format!("{:?}", ExitCode::from(1))
        );
    }

    /// Missing, read_errors, and shards_truncated alone do NOT
    /// escalate — they are observability-only. Only `mismatches > 0`
    /// fails the scrub gate.
    #[test]
    fn report_with_missing_and_read_errors_but_no_mismatch_is_success() {
        let report = ScrubReport {
            checked: 10,
            mismatches: 0,
            missing: 3,
            read_errors: 2,
            shards_truncated: 1,
        };
        assert_eq!(
            format!("{:?}", report_to_exit_code(&report)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    // -- Constants pin the catalog contract ---------------------------------

    #[test]
    fn default_concurrency_is_four() {
        // Pinned — matches `ScrubOpts::defaults()`. A drift here would
        // silently shift the scrub-throttling knob under cron wrappers
        // that expect today's default.
        assert_eq!(DEFAULT_CONCURRENCY, 4);
    }

    #[test]
    fn default_sample_fraction_is_one() {
        assert!((DEFAULT_SAMPLE_FRACTION - 1.0).abs() < f64::EPSILON);
    }

    // -- Composition: a real storage adapter driving the scrub --------------
    //
    // Every piece below is covered elsewhere in isolation — the adapters'
    // own tamper tests assert the reader fails at EOF, the use case's tests
    // assert the classification given a reader that does. What no other
    // test covers is the two *composed*, which is where the defect lived:
    // the shipped composition wrapped every read in a verifier whose
    // short-circuit the scrub then filed as a read error, so a corrupted
    // blob never reached `mismatches` and this CLI exited 0 over it.
    //
    // `report_to_exit_code` is deliberately exercised through the report
    // the composition actually produced, not through a hand-built one: a
    // hand-built `ScrubReport { mismatches: 1, .. }` cannot fail when the
    // classification upstream of it is wrong, and that is exactly the
    // shape the pre-existing exit-code tests have.

    mod composition {
        use std::io::Cursor;
        use std::process::ExitCode;
        use std::sync::Arc;

        use hort_adapters_storage::metrics::values::BACKEND_MEMORY;
        use hort_adapters_storage::{FilesystemStorage, ObjectStoreStorage};
        use hort_app::event_store_publisher::wrap_for_test;
        use hort_app::use_cases::cas_scrub_use_case::{
            ActionOnMismatch, CasScrubUseCase, ScrubOpts, ScrubReport,
        };
        use hort_app::use_cases::test_support::{
            sample_artifact, MockArtifactLifecycle, MockArtifactRepository, MockEventStore,
        };
        use hort_domain::entities::artifact::QuarantineStatus;
        use hort_domain::events::DomainEvent;
        use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
        use hort_domain::ports::artifact_repository::ArtifactRepository;
        use hort_domain::ports::storage::StoragePort;
        use hort_domain::types::ContentHash;
        use object_store::memory::InMemory;
        use object_store::{ObjectStore, ObjectStoreExt};
        use uuid::Uuid;

        use super::super::report_to_exit_code;

        /// SHA-256 of b"hello world" — the CAS key both tests store under.
        const HELLO_WORLD_SHA256: &str =
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        /// Bytes written over the stored blob behind the port.
        const TAMPERED_BYTES: &[u8] = b"TAMPERED";

        /// CAS key layout of `hort-adapters-storage`:
        /// `cas/{hash[0..2]}/{hash[2..4]}/{hash}`. Pinned by that crate's
        /// `cas::tests`; reproduced here because the derivation is
        /// adapter-internal and tampering means writing *behind* the port.
        fn cas_key(hash: &ContentHash) -> String {
            let h: &str = hash.as_ref();
            format!("cas/{}/{}/{}", &h[0..2], &h[2..4], h)
        }

        /// Digest the adapters' verifiers will compute once the stored
        /// bytes are `TAMPERED_BYTES`, derived by putting those bytes into
        /// a throwaway CAS rather than hardcoded — so the assertion
        /// compares two independent derivations of the same value instead
        /// of a literal nobody re-checks.
        async fn tampered_digest() -> ContentHash {
            let scratch = ObjectStoreStorage::new(Arc::new(InMemory::new()), BACKEND_MEMORY);
            scratch
                .put(Box::new(Cursor::new(TAMPERED_BYTES.to_vec())))
                .await
                .unwrap()
                .hash
        }

        /// Store b"hello world" through `storage` and return the CAS key
        /// the adapter derived for it.
        async fn put_hello_world(storage: &dyn StoragePort) -> ContentHash {
            let put = storage
                .put(Box::new(Cursor::new(b"hello world".to_vec())))
                .await
                .unwrap();
            assert_eq!(put.hash.as_ref(), HELLO_WORLD_SHA256);
            put.hash
        }

        /// Wire the scrub over `storage` with the artifact + lifecycle
        /// ports the tombstone action needs, seed an artifact row at
        /// `hash`, and return the pieces the assertions inspect.
        fn tombstoning_scrub(
            storage: Arc<dyn StoragePort>,
            hash: &ContentHash,
        ) -> (
            CasScrubUseCase,
            Arc<MockEventStore>,
            Arc<MockArtifactRepository>,
            Arc<MockArtifactLifecycle>,
            Uuid,
        ) {
            let events = Arc::new(MockEventStore::new());
            let artifacts = Arc::new(MockArtifactRepository::new());
            let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));

            let mut artifact = sample_artifact(QuarantineStatus::Released);
            artifact.sha256_checksum = hash.clone();
            let artifact_id = artifact.id;
            artifacts.insert(artifact);

            let uc = CasScrubUseCase::new(storage, wrap_for_test(events.clone()))
                .with_artifact_lifecycle(
                    artifacts.clone() as Arc<dyn ArtifactRepository>,
                    lifecycle.clone() as Arc<dyn ArtifactLifecyclePort>,
                );
            (uc, events, artifacts, lifecycle, artifact_id)
        }

        fn tombstone_opts() -> ScrubOpts {
            ScrubOpts {
                concurrency: 1,
                sample_fraction: 1.0,
                action_on_mismatch: ActionOnMismatch::Tombstone,
            }
        }

        /// Assertions shared by both backends: the tampered blob is a
        /// mismatch, the audit event carries the digest the verifier
        /// computed, the artifact is tombstoned, and the report this CLI
        /// returns maps to a non-zero exit code.
        fn assert_tampered_blob_escalates(
            report: &ScrubReport,
            events: &MockEventStore,
            artifacts: &MockArtifactRepository,
            lifecycle: &MockArtifactLifecycle,
            expected_hash: &ContentHash,
            observed_hash: &ContentHash,
            artifact_id: Uuid,
        ) {
            assert_eq!(report.mismatches, 1, "tampered blob must be a mismatch");
            assert_eq!(
                report.read_errors, 0,
                "the verifier's short-circuit is a classified mismatch, not a read error"
            );

            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "action=tombstone must reach commit_transition"
            );
            let (_saved, artifact_append, _meta) = &transitions[0];
            assert_eq!(
                artifacts.get(artifact_id).unwrap().quarantine_status,
                QuarantineStatus::Rejected
            );

            // Every event the run produced, across both streams: the
            // synthetic per-hash stream the scrub appends to and the
            // artifact stream the tombstone transition writes.
            let batches = events.appended_batches();
            let all_events: Vec<&DomainEvent> = batches
                .iter()
                .chain(std::iter::once(artifact_append))
                .flat_map(|b| b.events.iter())
                .map(|e| &e.event)
                .collect();

            let mismatches: Vec<_> = all_events
                .iter()
                .filter_map(|e| match e {
                    DomainEvent::CasIntegrityMismatch(m) => Some(m),
                    _ => None,
                })
                .collect();
            assert_eq!(
                mismatches.len(),
                1,
                "exactly one CasIntegrityMismatch must be appended"
            );
            assert_eq!(mismatches[0].content_hash, *expected_hash);
            assert_eq!(
                mismatches[0].observed_hash, *observed_hash,
                "the observed digest must be the one the verifier computed"
            );

            // The tombstone's own record carries the same digest — so the
            // value the real verifier produced reaches the artifact's
            // history, not just the scrub's audit stream.
            let corrupted = all_events
                .iter()
                .find_map(|e| match e {
                    DomainEvent::ArtifactCorrupted(c) => Some(c),
                    _ => None,
                })
                .expect("ArtifactCorrupted must accompany the tombstone");
            assert_eq!(corrupted.expected_hash, *expected_hash);
            assert_eq!(corrupted.computed_hash, *observed_hash);
            assert!(
                all_events
                    .iter()
                    .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
                "a terminal Rejected status must have its companion event"
            );

            // Through `report_to_exit_code` exactly as it stands — the
            // escalation comes from the classification being right, not
            // from widening the exit-code posture.
            assert_eq!(
                format!("{:?}", report_to_exit_code(report)),
                format!("{:?}", ExitCode::from(1)),
                "hort-server scrub must exit non-zero over a corrupted blob"
            );
        }

        /// Filesystem CAS: bytes swapped on disk behind the port.
        #[tokio::test]
        async fn filesystem_tampered_blob_is_a_mismatch_and_exits_non_zero() {
            let dir = tempfile::tempdir().unwrap();
            let storage = Arc::new(FilesystemStorage::new(dir.path().to_path_buf()));
            let hash = put_hello_world(storage.as_ref()).await;

            // Tamper: an operator or attacker with filesystem write access
            // replaces the bytes at the CAS key. Equal length is not
            // required — the verifier compares digests, not sizes.
            std::fs::write(dir.path().join(cas_key(&hash)), TAMPERED_BYTES).unwrap();

            let (uc, events, artifacts, lifecycle, artifact_id) =
                tombstoning_scrub(storage as Arc<dyn StoragePort>, &hash);
            let report = uc.run(tombstone_opts()).await.unwrap();

            assert_tampered_blob_escalates(
                &report,
                &events,
                &artifacts,
                &lifecycle,
                &hash,
                &tampered_digest().await,
                artifact_id,
            );
        }

        /// Object-store CAS: the object overwritten through the backing
        /// store handle, bypassing the adapter the same way a direct S3
        /// PUT would.
        #[tokio::test]
        async fn object_store_tampered_blob_is_a_mismatch_and_exits_non_zero() {
            let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
            let storage = Arc::new(ObjectStoreStorage::new(inner.clone(), BACKEND_MEMORY));
            let hash = put_hello_world(storage.as_ref()).await;

            let key: object_store::path::Path = cas_key(&hash).into();
            inner
                .put(&key, bytes::Bytes::from_static(TAMPERED_BYTES).into())
                .await
                .unwrap();

            let (uc, events, artifacts, lifecycle, artifact_id) =
                tombstoning_scrub(storage as Arc<dyn StoragePort>, &hash);
            let report = uc.run(tombstone_opts()).await.unwrap();

            assert_tampered_blob_escalates(
                &report,
                &events,
                &artifacts,
                &lifecycle,
                &hash,
                &tampered_digest().await,
                artifact_id,
            );
        }

        /// An intact CAS stays clean through the same composition, and the
        /// CLI still exits 0. Counter-assertion: without it the two tests
        /// above would also pass against a scrub that called *everything*
        /// a mismatch.
        #[tokio::test]
        async fn intact_filesystem_blob_is_clean_and_exits_zero() {
            let dir = tempfile::tempdir().unwrap();
            let storage = Arc::new(FilesystemStorage::new(dir.path().to_path_buf()));
            let hash = put_hello_world(storage.as_ref()).await;

            let (uc, events, artifacts, lifecycle, artifact_id) =
                tombstoning_scrub(storage as Arc<dyn StoragePort>, &hash);
            let report = uc.run(tombstone_opts()).await.unwrap();

            assert_eq!(report.checked, 1);
            assert_eq!(report.mismatches, 0);
            assert_eq!(report.read_errors, 0);
            assert!(events.appended_batches().is_empty());
            assert!(lifecycle.committed_transitions().is_empty());
            assert_eq!(
                artifacts.get(artifact_id).unwrap().quarantine_status,
                QuarantineStatus::Released
            );
            assert_eq!(
                format!("{:?}", report_to_exit_code(&report)),
                format!("{:?}", ExitCode::SUCCESS)
            );
        }
    }
}
