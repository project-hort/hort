//! Curation events ride the tamper-evident event chain — positive
//! verification.
//!
//! The curation workflow emits four event types, and the event store's
//! tamper-evident hash chain + checkpoint + offline verifier cover
//! **every** `EventStore::append` (ADR 0002, ADR 0007), so curation
//! events are *prima facie* covered. This test produces positive
//! evidence rather than assuming coverage: seed each of the four
//! curation events via the **real use-case append path** (no fixture,
//! no SQL), read the affected streams back, and call the pure-core
//! verifier in-process to confirm `StreamVerdict::Ok` for each
//! affected stream.
//!
//! # The four event types
//!
//! | Event | Use-case method | Stream |
//! |---|---|---|
//! | `ArtifactReleased{authority: CuratorWaiver}` | `CurationUseCase::waive` | `artifact-<uuid>` |
//! | `ArtifactRejected{rejected_by: Curator}` | `CurationUseCase::block` (`BlockTarget::Artifact`) | `artifact-<uuid>` |
//! | `ExclusionAdded{actor=user}` | `PolicyUseCase::add_exclusion` | `policy-<uuid>` |
//! | `ExclusionRemoved{actor=user}` | `PolicyUseCase::remove_exclusion` | `policy-<uuid>` |
//!
//! # How the verification works
//!
//! Each use-case method ultimately calls `events.append(...)` on the
//! `EventStorePublisher` constructed over a real `PgEventStore`. The
//! adapter's `append_in_tx` (`event_store.rs:526-666`) computes the
//! per-event chain hash via `compute_event_hash` and binds both the
//! recomputed `event_hash` and the previous head's `prev_event_hash` on
//! every INSERT. The chain is *by construction* — there is no append
//! path in the adapter that bypasses it.
//!
//! After seeding, the test reads each affected stream's rows back from
//! `events` (the typed event via `EventStore::read_stream`, the envelope
//! columns + chain bytea columns via one extra `SELECT`), reconstructs
//! the per-row `StreamRow` exactly the way `verify_event_chain.rs`'s
//! `OwnedRow::as_stream_row` does, and calls
//! `hort_domain::events::verify_stream_chain` in-process. The pure core is
//! `pub` for exactly this purpose (the verifier lives in
//! `hort-domain`; the operator subcommand at
//! `crates/hort-server/src/cli/verify_event_chain.rs:637-669` is a thin
//! composition over the same primitive). Spawning the subcommand binary
//! would add subprocess plumbing for zero additional pin value —
//! `event_store.rs:1671, 1706, 1735, 1876, 2134` already call
//! `verify_stream_chain` in-process from the adapter's own DB-backed
//! tests; this test mirrors that established convention.
//!
//! # Why a thin chaining lifecycle instead of `PgArtifactLifecycle`
//!
//! `CurationUseCase::waive` and `::block` go through
//! [`ArtifactLifecyclePort::commit_transition_with_score`] rather than
//! calling `events.append` directly. The production adapter
//! (`PgArtifactLifecycle`) wraps the append + an `artifacts` row save +
//! an optional metadata upsert + an optional score-projection bump in a
//! single SQL transaction. Here we only care about the **chain**
//! invariant on the **events** table: a single in-test
//! `ChainingLifecycle` that forwards `events.append` to the real
//! `EventStorePublisher` (and otherwise no-ops) gives us the same chain
//! coverage with none of the unrelated DB surface (no real
//! `artifacts` / `repositories` / `repo_security_scores` seeding).
//! This is the chain-verification primitive, not an end-to-end
//! integration test of the curation transition machinery (which
//! `crates/hort-app/src/use_cases/curation_use_case.rs::tests` already
//! pins at the use-case level via mocks).
//!
//! # Skip-when-no-DB
//!
//! Mirrors `tests/task_use_case_enqueue_real_db.rs`: returns silently
//! when `DATABASE_URL` is unset so the suite stays green on dev
//! environments without a database. CI sets `DATABASE_URL` and runs the
//! integration tier (Tier 2). If the helper returns `None` the test
//! emits a `tracing::warn!` so a missed CI signal is visible in the
//! log — `maybe_pool() == None` is NOT a pass; it is a "did not run".
//!
//! # `#[serial(hort_pg_db)]`
//!
//! DB-backed tests honour the crate-wide shared-DB-no-isolation contract
//! per CLAUDE.md → "DB-backed test isolation". The test acquires a real
//! pool via `isolated_db_from`; even though that gives a per-test
//! database, the contract still mandates the key as a structural guard
//! (the `feedback_no_port_contract_changes` memory's blocking-finding
//! rule).
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test curation_events_chained
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::event_store::PgEventStore;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::use_cases::curation_use_case::{BlockTarget, CurationUseCase};
use hort_app::use_cases::policy_use_case::{
    AddExclusionCommand, CreatePolicyCommand, PolicyUseCase, RemoveExclusionCommand,
};
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::test_support::{
    sample_artifact, MockArtifactRepository, MockCurationRuleRepository, MockJobsRepository,
    MockPolicyProjectionRepository, MockRepositoryRepository, MockStoragePort,
};
use hort_app::use_cases::CallerPrivileges;
use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::entities::scan_policy::{NegligibleAction, ProvenanceMode, SeverityThreshold};
use hort_domain::error::DomainResult;
use hort_domain::events::Actor;
use hort_domain::events::PolicyScope;
use hort_domain::events::{
    verify_stream_chain, ActorCanonical, ApiActor, ChainInput, DomainEvent, EventHash,
    PersistedEvent, StreamId, StreamRow, StreamRows, StreamVerdict,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::event_store::{AppendEvents, AppendResult, EventStore, ReadFrom};
use hort_domain::ports::repo_security_score_repository::ScoreDelta;
use hort_domain::ports::scan_findings_repository::ScanFindingsRow;
use hort_domain::ports::BoxFuture;
use hort_domain::types::sbom::SbomComponent;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Acquire a pool for a per-test database via the shared `isolated_db_from`
/// helper. Returns `None` when `DATABASE_URL` is unset, mirroring the
/// convention used by every DB-backed test in this crate
/// (`task_use_case_enqueue_real_db.rs`, etc.).
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// Test-local `ArtifactLifecyclePort` that forwards `commit_transition`
/// to the wrapped publisher's `append` so the chain invariant is
/// exercised on the real `events` table. The other lifecycle surfaces
/// (`artifacts` save, `artifact_metadata`, `repo_security_scores`,
/// `scan_findings`) are intentionally skipped — this verification only
/// needs the chain-on-append behaviour, and avoiding the unrelated tables means
/// the test does not need to seed `repositories` / `artifacts` rows
/// just to satisfy FK constraints on tables this verification does
/// not touch.
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
        // Not exercised by the four curation event types — the
        // curation use case never calls this path. Still required by
        // the trait; forward to `events.append` defensively.
        let publisher = self.publisher.clone();
        Box::pin(async move { publisher.append(events).await })
    }
}

/// Curator privileges sufficient to drive both `waive` and `block`. The
/// curation use case checks `require_curate_or_admin`; one bit is
/// enough.
fn curator_privileges() -> CallerPrivileges {
    CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    }
}

/// A `RepositoryAccessUseCase` with an empty repo store. Every
/// `metric_label(repo_id)` call returns the `unknown` sentinel, which
/// is fine for this chain-verification test — we don't pin the
/// `hort_curation_decisions_total{repository=…}` label here.
fn default_repository_access() -> Arc<RepositoryAccessUseCase> {
    Arc::new(RepositoryAccessUseCase::new(
        Arc::new(MockRepositoryRepository::new()),
        RbacAccess::Disabled,
        true,
    ))
}

/// Build a `CurationUseCase` wired to the real `EventStorePublisher`
/// for the append path and to mocks elsewhere. The mocks for the three
/// read-only repos (`CurationQueueRepository` / `…DecisionsRepository`
/// / `…ExclusionsRepository`) live inline here because the `waive` /
/// `block` paths never call their methods — `CurationUseCase::tests`
/// mocks them similarly. Returning empty Vecs is safer than panicking
/// in case a future refactor adds a defensive call.
fn build_curation_use_case(
    publisher: Arc<EventStorePublisher>,
    artifacts: Arc<MockArtifactRepository>,
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

    // Inline empty-result mocks for the read-only repos — the
    // `waive` / `block` paths never call these methods, so a
    // panic-on-call would be acceptable, but returning empty Vecs is
    // safer if a future code change adds a defensive call.
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
    CurationUseCase::new(
        publisher,
        artifacts,
        lifecycle,
        policies,
        queue_repo,
        decisions_repo,
        exclusions_repo,
        default_repository_access(),
    )
}

/// Seed a single artifact in `Quarantined` state into the mock
/// repository and return its id. `waive` accepts only `Quarantined`
/// (per `Artifact::release` source-state guard); `block` accepts
/// `{None, Quarantined, Released}`. Both happy paths use `Quarantined`.
fn seed_quarantined_artifact(artifacts: &MockArtifactRepository) -> Uuid {
    let mut a = sample_artifact(QuarantineStatus::Quarantined);
    a.repository_id = Uuid::new_v4();
    a.created_at = Utc::now();
    a.updated_at = Utc::now();
    let id = a.id;
    artifacts.insert(a);
    id
}

/// Build a `PolicyUseCase` wired to the real `EventStorePublisher` for
/// the append path. `add_exclusion` / `remove_exclusion` call
/// `events.append` directly (not via lifecycle), so chain coverage on
/// the policy stream comes from the real publisher.
fn build_policy_use_case(
    publisher: Arc<EventStorePublisher>,
    projections: Arc<MockPolicyProjectionRepository>,
) -> PolicyUseCase {
    let artifacts = Arc::new(MockArtifactRepository::new());
    let lifecycle: Arc<dyn ArtifactLifecyclePort> =
        Arc::new(ChainingLifecycle::new(publisher.clone()));
    let storage = Arc::new(MockStoragePort::new());
    let curation_rules = Arc::new(MockCurationRuleRepository::new());
    let jobs = Arc::new(MockJobsRepository::default());
    PolicyUseCase::new(
        publisher,
        projections,
        artifacts,
        lifecycle,
        storage,
        default_repository_access(),
        curation_rules,
        jobs,
    )
}

/// Build a `CreatePolicyCommand` with a fresh name. The use-case path
/// appends a `PolicyCreated` event at position 0 of the policy stream
/// and seeds the mock projection's `stream_version = 0`, so the next
/// `add_exclusion`'s `ExpectedVersion::Exact(0)` precondition matches
/// the live stream tail.
fn sample_create_policy_command() -> CreatePolicyCommand {
    CreatePolicyCommand {
        name: format!("chain-verify-test-{}", Uuid::new_v4().simple()),
        scope: PolicyScope::Global,
        severity_threshold: SeverityThreshold::High,
        quarantine_duration_secs: 24 * 3600,
        require_approval: false,
        provenance_mode: ProvenanceMode::VerifyIfPresent,
        provenance_backends: vec!["cosign".to_string()],
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        scan_backends: vec!["trivy".into()],
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
    }
}

// ---------------------------------------------------------------------------
// Stream-row read-back (mirrors verify_event_chain.rs::read_stream_rows +
// event_store.rs::read_back_owned_rows)
// ---------------------------------------------------------------------------

/// Owned per-row snapshot — the four envelope columns NOT carried by
/// `PersistedEvent` (`stream_category`, the three actor columns) plus
/// the two chain bytea columns. Borrowed into `StreamRow` by
/// [`OwnedRow::as_stream_row`].
struct OwnedRow {
    persisted: PersistedEvent,
    stream_id: String,
    stream_category: String,
    actor_type: String,
    actor_id: Option<Uuid>,
    actor_source_file: Option<String>,
    actor_spec_digest: Option<Vec<u8>>,
    stored_prev: EventHash,
    stored_hash: EventHash,
}

impl OwnedRow {
    fn as_stream_row(&self) -> StreamRow<'_> {
        StreamRow {
            input: ChainInput {
                prev_event_hash: self.stored_prev,
                event_id: self.persisted.event_id,
                stream_id: &self.stream_id,
                stream_category: &self.stream_category,
                stream_position: self.persisted.stream_position,
                event_type: self.persisted.event.event_type(),
                event_version: self.persisted.event_version,
                event: &self.persisted.event,
                correlation_id: self.persisted.correlation_id,
                causation_id: self.persisted.causation_id,
                actor: ActorCanonical {
                    actor_type: &self.actor_type,
                    actor_id: self.actor_id,
                    actor_source_file: self.actor_source_file.as_deref(),
                    actor_spec_digest: self.actor_spec_digest.as_deref(),
                },
            },
            stored_prev: self.stored_prev,
            stored_hash: self.stored_hash,
        }
    }
}

fn to_event_hash(bytes: &[u8]) -> EventHash {
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("32-byte chain column (schema CHECK)");
    EventHash(arr)
}

/// Read one stream's rows in `stream_position ASC` order. Two queries:
/// the typed event payload via the production `EventStore::read_stream`
/// path (so the `event_data` JSONB round-trips through
/// `TryFrom<EventRow>` exactly the way the production verifier does),
/// then a separate `SELECT` for the envelope + chain columns
/// `read_stream` does not surface. The two are zipped by
/// `stream_position` (defence in depth — both queries ORDER BY the
/// same column).
/// Tuple shape for the envelope + chain `SELECT` — extracted to a
/// `type` alias to keep clippy's `type_complexity` happy. Field order
/// matches the `SELECT` column order: `(stream_position, stream_category,
/// actor_type, actor_id, actor_source_file, actor_spec_digest,
/// prev_event_hash, event_hash)`.
type EnvelopeChainRow = (
    i64,
    String,
    String,
    Option<Uuid>,
    Option<String>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
);

async fn read_stream_rows(pool: &PgPool, store: &PgEventStore, stream: &StreamId) -> Vec<OwnedRow> {
    let stream_str = stream.to_string();
    let events: Vec<PersistedEvent> = store
        .read_stream(stream, ReadFrom::Start, 1024)
        .await
        .expect("EventStore::read_stream must succeed");
    let cols: Vec<EnvelopeChainRow> = sqlx::query_as(
        r#"SELECT
                   stream_position,
                   stream_category,
                   actor_type,
                   actor_id,
                   actor_source_file,
                   actor_spec_digest,
                   prev_event_hash,
                   event_hash
               FROM events
               WHERE stream_id = $1
               ORDER BY stream_position ASC"#,
    )
    .bind(&stream_str)
    .fetch_all(pool)
    .await
    .expect("envelope + chain column read must succeed");
    assert_eq!(
        events.len(),
        cols.len(),
        "row count must match between EventStore::read_stream and the envelope/chain SELECT \
         (both ORDER BY stream_position ASC)"
    );
    let mut out = Vec::with_capacity(events.len());
    for (persisted, (pos, cat, atype, aid, asrc, adig, prev, hash)) in
        events.into_iter().zip(cols.into_iter())
    {
        assert_eq!(
            persisted.stream_position as i64, pos,
            "read_stream and the envelope/chain SELECT must agree on stream_position"
        );
        out.push(OwnedRow {
            persisted,
            stream_id: stream_str.clone(),
            stream_category: cat,
            actor_type: atype,
            actor_id: aid,
            actor_source_file: asrc,
            actor_spec_digest: adig,
            stored_prev: to_event_hash(&prev),
            stored_hash: to_event_hash(&hash),
        });
    }
    out
}

/// Read a stream and assert `verify_stream_chain == StreamVerdict::Ok`.
/// `expect_positions` is the contiguous closed range `0..=expect_positions`
/// the test expects the stream to cover after seeding; the verifier's
/// returned `position` must equal `expect_positions` so a missing append
/// surfaces as a mismatch rather than passing on a too-short stream.
async fn assert_stream_verifies_ok(
    pool: &PgPool,
    store: &PgEventStore,
    stream: &StreamId,
    label: &str,
    expect_last_position: u64,
) {
    let owned = read_stream_rows(pool, store, stream).await;
    assert!(
        !owned.is_empty(),
        "{label}: stream {} must have at least one row (the use-case seed)",
        stream
    );
    let views: Vec<StreamRow<'_>> = owned.iter().map(OwnedRow::as_stream_row).collect();
    let verdict = verify_stream_chain(&StreamRows::new(&views));
    match verdict {
        StreamVerdict::Ok { position, .. } => {
            assert_eq!(
                position, expect_last_position,
                "{label}: stream {} verified Ok but at position {position}, \
                 expected {expect_last_position}",
                stream
            );
        }
        other => panic!(
            "{label}: stream {} did NOT verify Ok; verdict = {other:?}. \
             Fail signal: the use-case append path bypassed the \
             tamper-evident event chain.",
            stream
        ),
    }
}

// ---------------------------------------------------------------------------
// The verification test
// ---------------------------------------------------------------------------

/// Curation events ride the tamper-evident event chain.
///
/// Drive each of the four curation event types through its real
/// use-case append path against a live `PgEventStore`, then call the
/// pure-core verifier on every affected stream in-process. The
/// expected verdict for every stream is `StreamVerdict::Ok` — positive
/// evidence of chain coverage; any other verdict surfaces which append
/// site bypassed the chain.
#[tokio::test]
#[serial(hort_pg_db)]
async fn curation_events_ride_tamper_evident_chain() {
    let Some(pool) = maybe_pool().await else {
        // DATABASE_URL absent — the integration tier is not running. The
        // suppressing return mirrors the convention used by every other
        // DB-backed test in this crate; CI runs with DATABASE_URL set
        // and exercises the assertions.
        tracing::warn!(
            "curation_events_chained skipped: DATABASE_URL unset. \
             This test only validates the chain when run against a live \
             Postgres (Tier 2). A skip is NOT a pass."
        );
        return;
    };

    // Real adapters — the chain is exercised end-to-end through these.
    let raw_store: Arc<PgEventStore> =
        Arc::new(PgEventStore::new(pool.clone()).await.expect(
            "PgEventStore::new (the immutability trigger must be installed by migrations)",
        ));
    let publisher: Arc<EventStorePublisher> =
        Arc::new(EventStorePublisher::without_broadcast(raw_store.clone()));

    // Curation use case — wired to the real publisher; the
    // `ChainingLifecycle` forwards `commit_transition_with_score` to
    // `events.append` so the artifact-stream chain is exercised.
    let artifacts = Arc::new(MockArtifactRepository::new());
    let curation = build_curation_use_case(publisher.clone(), artifacts.clone());

    let curator = ApiActor {
        user_id: Uuid::new_v4(),
    };

    // ---- Event #1: ArtifactReleased{CuratorWaiver} via CurationUseCase::waive
    let waive_artifact_id = seed_quarantined_artifact(&artifacts);
    let waive_stream = StreamId::artifact(waive_artifact_id);
    curation
        .waive(
            waive_artifact_id,
            curator.clone(),
            curator_privileges(),
            "chain verification: waive emits ArtifactReleased(CuratorWaiver)".into(),
        )
        .await
        .expect("waive must succeed for a Quarantined artifact (see Artifact::release source-state guard)");

    // ---- Event #2: ArtifactRejected{Curator} via CurationUseCase::block
    let block_artifact_id = seed_quarantined_artifact(&artifacts);
    let block_stream = StreamId::artifact(block_artifact_id);
    let outcome = curation
        .block(
            BlockTarget::Artifact(block_artifact_id),
            curator.clone(),
            curator_privileges(),
            "chain verification: block emits ArtifactRejected(Curator)".into(),
        )
        .await
        .expect("block must succeed for a Quarantined artifact");
    assert_eq!(
        outcome.blocked_artifact_ids,
        vec![block_artifact_id],
        "block must transition the seeded artifact (continue-on-error envelope must be empty)"
    );
    assert!(
        outcome.failed.is_empty(),
        "block must not fail (failed = {:?})",
        outcome.failed
    );

    // ---- Event #3 + #4: ExclusionAdded / ExclusionRemoved via PolicyUseCase
    //
    // All three events (PolicyCreated → ExclusionAdded → ExclusionRemoved)
    // ride a *single* policy stream — the `policy-<uuid>` stream that
    // `StreamId::policy(policy_id)` resolves to. After `create_policy`
    // the stream has one event (position 0); after `add_exclusion` two
    // (positions 0..=1); after `remove_exclusion` three (positions
    // 0..=2). The chain verification covers all three rows in one
    // read-back. `PolicyCreated` is a curation-adjacent event but not
    // one of the four curation names — its inclusion here is the
    // necessary precondition (without it the policy stream is empty
    // and `ExpectedVersion::Exact(0)` on `add_exclusion` fails), and
    // its presence at position 0 strengthens the verification (the
    // chain is verified through *more* events than the four curation
    // names alone).
    let projections = Arc::new(MockPolicyProjectionRepository::new());
    let policy = build_policy_use_case(publisher.clone(), projections.clone());

    let policy_id = policy
        .create_policy(sample_create_policy_command(), Actor::Api(curator.clone()))
        .await
        .expect("create_policy must succeed");
    let policy_stream = StreamId::policy(policy_id);

    let add_actor = Actor::Api(curator.clone());
    let exclusion_id = policy
        .add_exclusion(
            AddExclusionCommand {
                policy_id,
                cve_id: "CVE-2026-CHAINTEST".into(),
                package_pattern: None,
                scope: PolicyScope::Global,
                reason: "chain verification: add_exclusion emits ExclusionAdded(actor=user)".into(),
                expires_at: None,
            },
            add_actor,
        )
        .await
        .expect("add_exclusion must succeed against a non-archived policy");

    // remove_exclusion needs the post-bump parent.stream_version to
    // satisfy ExpectedVersion::Exact; the mock's `upsert` updates the
    // projection so a fresh find_by_id returns the bumped version.
    let remove_actor = Actor::Api(curator);
    policy
        .remove_exclusion(
            RemoveExclusionCommand {
                policy_id,
                exclusion_id,
                reason: "chain verification: remove_exclusion emits ExclusionRemoved(actor=user)"
                    .into(),
            },
            remove_actor,
        )
        .await
        .expect("remove_exclusion must succeed against the just-added exclusion");

    // ---- Verify all three streams in-process
    //
    // The waive / block streams each have exactly one row (position 0).
    // The policy stream has two rows (positions 0..=1) — add then
    // remove. Any other shape means an append was missed and the
    // verifier's position assertion catches it.
    assert_stream_verifies_ok(
        &pool,
        &raw_store,
        &waive_stream,
        "ArtifactReleased{CuratorWaiver} via CurationUseCase::waive",
        0,
    )
    .await;
    assert_stream_verifies_ok(
        &pool,
        &raw_store,
        &block_stream,
        "ArtifactRejected{Curator} via CurationUseCase::block",
        0,
    )
    .await;
    assert_stream_verifies_ok(
        &pool,
        &raw_store,
        &policy_stream,
        "PolicyCreated + ExclusionAdded + ExclusionRemoved via PolicyUseCase",
        2,
    )
    .await;

    // Defence-in-depth: also sanity-check the event_type strings the
    // verifier consumed match the expected typed events. A future
    // `event_type()` rename would otherwise pass verification
    // (the chain just hashes whatever payload is stored) without us
    // noticing that a different event got persisted than the audit
    // names.
    let waive_rows = read_stream_rows(&pool, &raw_store, &waive_stream).await;
    assert!(
        matches!(
            waive_rows[0].persisted.event,
            DomainEvent::ArtifactReleased(_)
        ),
        "waive must persist an ArtifactReleased event (got {})",
        waive_rows[0].persisted.event.event_type()
    );
    let block_rows = read_stream_rows(&pool, &raw_store, &block_stream).await;
    assert!(
        matches!(
            block_rows[0].persisted.event,
            DomainEvent::ArtifactRejected(_)
        ),
        "block must persist an ArtifactRejected event (got {})",
        block_rows[0].persisted.event.event_type()
    );
    let policy_rows = read_stream_rows(&pool, &raw_store, &policy_stream).await;
    assert!(
        matches!(
            policy_rows[0].persisted.event,
            DomainEvent::PolicyCreated(_)
        ),
        "create_policy must persist PolicyCreated at position 0 (got {}) — \
         this is a precondition for the curation events, not one of the four \
         names themselves",
        policy_rows[0].persisted.event.event_type()
    );
    assert!(
        matches!(
            policy_rows[1].persisted.event,
            DomainEvent::ExclusionAdded(_)
        ),
        "add_exclusion must persist ExclusionAdded at position 1 (got {})",
        policy_rows[1].persisted.event.event_type()
    );
    assert!(
        matches!(
            policy_rows[2].persisted.event,
            DomainEvent::ExclusionRemoved(_)
        ),
        "remove_exclusion must persist ExclusionRemoved at position 2 (got {})",
        policy_rows[2].persisted.event.event_type()
    );
    // exclusion_id is materialised on the projection but is also a
    // load-bearing argument to remove_exclusion; tie it back to the
    // payload of the ExclusionAdded row to surface an envelope-vs-body
    // drift if a future serde change desynchronises them.
    if let DomainEvent::ExclusionAdded(ev) = &policy_rows[1].persisted.event {
        assert_eq!(
            ev.exclusion_id, exclusion_id,
            "ExclusionAdded payload exclusion_id must match the use-case return value"
        );
    }
}
