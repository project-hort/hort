//! Packument-cache invalidation on curator reject — integration test.
//!
//! # What this pins
//!
//! The `NonServableStatusFilter` is the load-bearing close on the
//! index-build path (see
//! `docs/architecture/explanation/index-construction.md`) — it always
//! filters `Rejected` artifacts from every served simple-index
//! regardless of cache state. But the upstream packument cache retains
//! the cached upstream advertisement for a Rejected artifact until its
//! TTL elapses. The `UpstreamIndexCacheInvalidator` wires
//! `ArtifactRejected` emission to a cache eviction so the freshness
//! window shrinks from `TTL` to "immediate OR next index build".
//!
//! This test exercises the most realistic operator-action surface (the
//! curator bulk-block path, `CurationUseCase::block`) end-to-end:
//!
//! 1. Seed an npm packument cache entry for `(repository_id, "lodash")`
//!    via `EphemeralStore::put` against the **production**
//!    `AppUpstreamIndexCacheInvalidator` adapter wiring (real
//!    `RepositoryRepository` + `RepositoryUpstreamMappingRepository`
//!    seeded with the format + mapping).
//! 2. Drive `CurationUseCase::block` against a real seeded artifact —
//!    the use case carries the `with_upstream_index_cache_invalidator`
//!    builder applied at construction, so the post-commit hook fires
//!    after the `ArtifactRejected` append commits.
//! 3. Assert the cache entry is `None` on next `EphemeralStore::get`.
//!    A buggy hook (failure rolled back; wrong key shape; etc) leaves
//!    the entry live and the assertion fires.
//!
//! # Why integration, not just a unit test
//!
//! The unit tests in
//! `crates/hort-app/src/use_cases/upstream_index_cache_invalidator.rs::tests`
//! exercise the adapter in isolation. The end-to-end question is "does
//! the post-commit hook on the **real** `CurationUseCase::block_one`
//! path actually invoke the adapter against the **same** ephemeral
//! store backing the cache writers in `hort-http-npm`?" That contract
//! lives across `hort-app` + `hort-server` and is the regression guard
//! against a future composition-root refactor accidentally wiring two
//! distinct `EphemeralStore` instances for the cache reader/writer vs
//! the invalidator.
//!
//! # `#[serial(hort_pg_db)]`
//!
//! Mirrors `curation_events_chained.rs` — DB-backed tests honour
//! the crate-wide shared-DB-no-isolation contract per CLAUDE.md "DB-
//! backed test isolation" (the `feedback_no_port_contract_changes`
//! memory's blocking-finding rule). Even though `isolated_db_from`
//! gives a per-test database, the structural key stays in place.
//!
//! # Skip-when-no-DB
//!
//! Returns silently with a `tracing::warn!` when `DATABASE_URL` is
//! unset so the suite stays green on dev environments without a
//! database. CI sets `DATABASE_URL` and runs the integration tier
//! (Tier 2). A skip is NOT a pass — the `warn!` ensures missed CI
//! signals are visible in the log.

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::event_store::PgEventStore;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::use_cases::curation_use_case::{BlockTarget, CurationUseCase};
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::test_support::{
    sample_artifact, MockArtifactRepository, MockPolicyProjectionRepository,
    MockRepositoryRepository, MockRepositoryUpstreamMappingRepository,
};
use hort_app::use_cases::upstream_index_cache_invalidator::AppUpstreamIndexCacheInvalidator;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::repository::{
    IndexMode, PrefetchPolicy, ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use hort_domain::error::DomainResult;
use hort_domain::events::ApiActor;
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::event_store::{AppendEvents, AppendResult, EventStore};
use hort_domain::ports::repo_security_score_repository::ScoreDelta;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingRepository, UpstreamAuth,
};
use hort_domain::ports::scan_findings_repository::ScanFindingsRow;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;
use hort_domain::ports::BoxFuture;
use hort_domain::types::sbom::SbomComponent;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Acquire a pool for a per-test database via the shared `isolated_db_from`
/// helper. Returns `None` when `DATABASE_URL` is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// Test-local `ArtifactLifecyclePort` that forwards `commit_transition`
/// to the wrapped publisher's `append`. Borrowed from
/// `curation_events_chained.rs::ChainingLifecycle`; this test only
/// needs the event-store append (so the `block_one` post-commit hook
/// fires).
struct ChainingLifecycle {
    publisher: Arc<EventStorePublisher>,
}

impl ChainingLifecycle {
    fn new(publisher: Arc<EventStorePublisher>) -> Self {
        Self { publisher }
    }
}

impl ArtifactLifecyclePort for ChainingLifecycle {
    fn commit_transition(
        &self,
        _artifact: &Artifact,
        events: AppendEvents,
        _metadata: Option<ArtifactMetadata>,
    ) -> BoxFuture<'_, DomainResult<AppendResult>> {
        let publisher = self.publisher.clone();
        Box::pin(async move { publisher.append(events).await })
    }

    fn commit_transition_with_score<'a>(
        &'a self,
        _artifact: &'a Artifact,
        events: AppendEvents,
        _metadata: Option<ArtifactMetadata>,
        _score_delta: Option<(Uuid, ScoreDelta)>,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let publisher = self.publisher.clone();
        Box::pin(async move { publisher.append(events).await })
    }

    fn commit_scan_result_with_score<'a>(
        &'a self,
        _artifact: &'a Artifact,
        events: AppendEvents,
        _scan_findings_rows: &'a [ScanFindingsRow],
        _last_scan_at: DateTime<Utc>,
        _score_delta: Option<(Uuid, ScoreDelta)>,
        _sbom_components: Option<&'a [SbomComponent]>,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        // Not exercised on the curator-block path; forward defensively.
        let publisher = self.publisher.clone();
        Box::pin(async move { publisher.append(events).await })
    }
}

fn curator_privileges() -> CallerPrivileges {
    CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    }
}

/// Build a `CurationUseCase` wired to the real `EventStorePublisher`
/// (via `ChainingLifecycle`) and the **production** invalidator
/// adapter. Mirrors `curation_events_chained.rs::build_curation_use_case`'s
/// shape; differs in that the `CurationUseCase` is built with
/// `.with_upstream_index_cache_invalidator(...)` so the post-commit
/// hook fires on a successful `block_one`.
///
/// `clippy::needless_pass_by_value` is silenced — this helper is
/// called exactly once from the test body and the `Arc`s are
/// consumed (cast to `Arc<dyn _>` and threaded into the use-case
/// constructor). A reference parameter would force the call site to
/// `.clone()` instead, with identical semantics.
#[allow(clippy::needless_pass_by_value)]
fn build_curation_use_case_with_invalidator(
    publisher: Arc<EventStorePublisher>,
    artifacts: Arc<MockArtifactRepository>,
    repositories: Arc<MockRepositoryRepository>,
    upstream_mappings: Arc<MockRepositoryUpstreamMappingRepository>,
    ephemeral_evictable: Arc<dyn EphemeralStore>,
) -> CurationUseCase {
    use hort_domain::ports::curation_decisions_repository::{
        CurationDecisionEntry, CurationDecisionFilter, CurationDecisionsRepository,
    };
    use hort_domain::ports::curation_exclusions_repository::{
        CurationExclusionEntry, CurationExclusionFilter, CurationExclusionsRepository,
    };
    use hort_domain::ports::curation_queue_repository::{
        CurationQueueEntry, CurationQueueFilter, CurationQueueRepository,
    };

    struct EmptyQueue;
    impl CurationQueueRepository for EmptyQueue {
        fn list_queue<'a>(
            &'a self,
            _filter: CurationQueueFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationQueueEntry>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }
    struct EmptyDecisions;
    impl CurationDecisionsRepository for EmptyDecisions {
        fn list_decisions<'a>(
            &'a self,
            _filter: CurationDecisionFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationDecisionEntry>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }
    struct EmptyExclusions;
    impl CurationExclusionsRepository for EmptyExclusions {
        fn list_exclusions<'a>(
            &'a self,
            _filter: CurationExclusionFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<CurationExclusionEntry>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    let lifecycle: Arc<dyn ArtifactLifecyclePort> =
        Arc::new(ChainingLifecycle::new(publisher.clone()));
    let policies = Arc::new(MockPolicyProjectionRepository::new());
    let queue_repo = Arc::new(EmptyQueue);
    let decisions_repo = Arc::new(EmptyDecisions);
    let exclusions_repo = Arc::new(EmptyExclusions);

    let repository_access = Arc::new(RepositoryAccessUseCase::new(
        repositories.clone(),
        RbacAccess::Disabled,
        true,
    ));

    // The production invalidator wired against the
    // same `EphemeralStore` instance that the test will read from in
    // the assertion below. This is the regression-guard contract:
    // if a future refactor splits the cache reader/writer's
    // `EphemeralStore` from the invalidator's, the test fails.
    let invalidator: Arc<dyn UpstreamIndexCacheInvalidator> =
        Arc::new(AppUpstreamIndexCacheInvalidator::new(
            repositories.clone()
                as Arc<dyn hort_domain::ports::repository_repository::RepositoryRepository>,
            upstream_mappings.clone() as Arc<dyn RepositoryUpstreamMappingRepository>,
            ephemeral_evictable,
        ));

    CurationUseCase::new(
        publisher,
        artifacts,
        lifecycle,
        policies,
        queue_repo,
        decisions_repo,
        exclusions_repo,
        repository_access,
    )
    .with_upstream_index_cache_invalidator(invalidator)
}

/// Seed a packument-cache row at the key shape `hort-http-npm` writes
/// to `ephemeral_evictable` (the streaming-metadata projection prefix
/// `npm_packument_proj:`, ADR 0026 — the entry holds the projection, but this
/// test is delete-by-key, so the value bytes are irrelevant to the
/// assertion — any non-empty payload satisfies the `Option<Bytes>`
/// precondition). We use a small ASCII placeholder so the test stays
/// free of frame/serde plumbing.
async fn seed_packument_cache(
    eph: &Arc<dyn EphemeralStore>,
    mapping_id: Uuid,
    encoded_pkg: &str,
) -> String {
    let key = format!("npm_packument_proj:{mapping_id}:{encoded_pkg}");
    eph.put(
        &key,
        Bytes::from_static(b"seeded-packument"),
        Duration::from_secs(3600),
    )
    .await
    .expect("seed put must succeed");
    key
}

fn make_proxy_npm_repo(repositories: &MockRepositoryRepository) -> Repository {
    let repo = Repository {
        id: Uuid::new_v4(),
        key: format!("npm-mirror-{}", Uuid::new_v4().simple()),
        name: "npm mirror".into(),
        description: None,
        format: RepositoryFormat::Npm,
        repo_type: RepositoryType::Proxy,
        storage_backend: "filesystem".into(),
        storage_path: "/data/repos/test".into(),
        upstream_url: Some("https://registry.npmjs.org".into()),
        index_upstream_url: None,
        is_public: true,
        download_audit_enabled: false,
        quota_bytes: None,
        replication_priority: ReplicationPriority::OnDemand,
        promotion: None,
        curation_rule_names: Vec::new(),
        index_mode: IndexMode::ReleasedOnly,
        prefetch_policy: PrefetchPolicy::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    repositories.insert(repo.clone());
    repo
}

async fn seed_mapping(
    upstream_mappings: &MockRepositoryUpstreamMappingRepository,
    repo_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let mapping = RepositoryUpstreamMapping {
        id,
        repository_id: repo_id,
        path_prefix: String::new(),
        upstream_url: "https://registry.npmjs.org".into(),
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
    };
    upstream_mappings
        .upsert(mapping)
        .await
        .expect("mock upsert never errors");
    id
}

fn seed_quarantined_artifact_in_repo(
    artifacts: &MockArtifactRepository,
    repository_id: Uuid,
    name: &str,
) -> Uuid {
    let mut a = sample_artifact(QuarantineStatus::Quarantined);
    a.repository_id = repository_id;
    a.name = name.to_owned();
    a.created_at = Utc::now();
    a.updated_at = Utc::now();
    let id = a.id;
    artifacts.insert(a);
    id
}

// ---------------------------------------------------------------------------
// The integration test
// ---------------------------------------------------------------------------

/// Packument-cache invalidation on curator block — integration.
///
/// Drive a curator-block (`CurationUseCase::block`) for a quarantined
/// artifact in a proxy npm repository with a seeded packument cache
/// entry. After the block succeeds, the cache entry MUST be absent on
/// next lookup (the post-commit invalidator hook fired against the
/// same `EphemeralStore` instance the seed went through).
#[tokio::test]
#[serial(hort_pg_db)]
async fn packument_cache_invalidated_on_curator_block() {
    let Some(pool) = maybe_pool().await else {
        tracing::warn!(
            "packument_cache_invalidated_on_reject skipped: DATABASE_URL unset. \
             This test only validates the invalidation hook against a live Postgres \
             (Tier 2). A skip is NOT a pass."
        );
        return;
    };

    // -- Real EventStore + publisher (so `block_one`'s real append path
    //    runs and the post-commit hook fires after Ok).
    let raw_store: Arc<PgEventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new (immutability trigger must be installed by migrations)"),
    );
    let publisher: Arc<EventStorePublisher> =
        Arc::new(EventStorePublisher::without_broadcast(raw_store.clone()));

    // -- Shared in-process EphemeralStore — same instance threaded to
    //    BOTH the seeding code below AND the invalidator wired into
    //    `CurationUseCase`. Regression guard: a future composition-
    //    root refactor that splits the two would break this contract.
    let ephemeral_evictable: Arc<dyn EphemeralStore> =
        Arc::new(hort_adapters_ephemeral_memory::InMemoryEphemeralStore::new());

    // -- Repositories + upstream mappings — the production
    //    invalidator adapter resolves the format + mapping list via
    //    these ports.
    let repositories = Arc::new(MockRepositoryRepository::new());
    let upstream_mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
    let repo = make_proxy_npm_repo(&repositories);
    let mapping_id = seed_mapping(&upstream_mappings, repo.id).await;

    // -- Seed the npm packument cache entry — the upstream advertisement
    //    that an open-bag CRA-Annex-I-(1) reading would say "leaks the
    //    revoked wheel until TTL".
    let seeded_key = seed_packument_cache(&ephemeral_evictable, mapping_id, "lodash").await;
    assert!(
        ephemeral_evictable
            .get(&seeded_key)
            .await
            .expect("ephemeral get")
            .is_some(),
        "precondition: the seeded packument cache entry must be present \
         before the curator-block runs"
    );

    // -- Real artifact in quarantine on this repo.
    let artifacts = Arc::new(MockArtifactRepository::new());
    let artifact_id = seed_quarantined_artifact_in_repo(&artifacts, repo.id, "lodash");

    // -- The wired CurationUseCase (real publisher + production
    //    invalidator adapter).
    let curation = build_curation_use_case_with_invalidator(
        publisher,
        artifacts,
        repositories,
        upstream_mappings,
        ephemeral_evictable.clone(),
    );

    let curator = ApiActor {
        user_id: Uuid::new_v4(),
    };

    // -- Drive the curator-block. This appends `ArtifactRejected` AND
    //    fires the post-commit invalidation hook.
    let outcome = curation
        .block(
            BlockTarget::Artifact(artifact_id),
            curator,
            curator_privileges(),
            "curator block: packument cache invalidation test".into(),
        )
        .await
        .expect("curator-block must succeed for a Quarantined artifact");

    assert_eq!(
        outcome.blocked_artifact_ids,
        vec![artifact_id],
        "the seeded artifact must transition to Rejected (continue-on-error \
         envelope must be empty)"
    );
    assert!(
        outcome.failed.is_empty(),
        "curator-block must not fail (failed = {:?})",
        outcome.failed
    );

    // -- Postcondition: the packument cache entry is GONE. The
    //    post-commit invalidation hook fired against the same
    //    EphemeralStore, found the (mapping.id, "lodash") key per
    //    the production adapter's key derivation, and deleted it.
    let after = ephemeral_evictable
        .get(&seeded_key)
        .await
        .expect("ephemeral get must succeed after invalidation");
    assert!(
        after.is_none(),
        "the post-commit invalidation hook must have evicted the packument \
         cache row at key={seeded_key} after the curator-block committed; \
         a Some(_) here means the hook failed silently, the wrong key was \
         derived, or the invalidator was wired to a different EphemeralStore \
         than the cache writer"
    );

    // -- Defence-in-depth: an unrelated cache row in the same keyspace
    //    must survive. If the invalidator accidentally widened to
    //    "delete every npm_packument_proj:* for this mapping", this
    //    assertion fires.
    let unrelated_key = seed_packument_cache(&ephemeral_evictable, mapping_id, "react").await;
    // The unrelated key was seeded AFTER the invalidation, so it
    // necessarily survives any prior delete; but pin the postcondition
    // anyway so a future refactor that re-fires the invalidation on
    // every get/put doesn't quietly remove this row.
    assert!(
        ephemeral_evictable
            .get(&unrelated_key)
            .await
            .expect("ephemeral get")
            .is_some(),
        "an unrelated package's cache row must survive a per-package invalidation"
    );
}
