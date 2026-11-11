//! Integration test — the OCI cross-repository blob mount against a real
//! PostgreSQL instance, with the gate requesting a scan.
//!
//! # What this proves, and why it needs a database
//!
//! `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repo>` is the OCI
//! Distribution Spec's "link the blob instead of re-uploading it"
//! optimisation (§2.3). The spec admits exactly two answers: `201` when the
//! mount succeeded, `202` when the registry falls back to an ordinary
//! upload. Anything else leaves the client with nothing to degrade to.
//!
//! The path runs `IngestUseCase::register_by_hash`, which stamps
//! `trigger_source = "register-by-hash"` on the `kind='scan'` row it
//! enqueues for the mounted blob (`"seed-import"` instead when the caller
//! supplies a quarantine-anchor override, which the mount never does). That
//! value is bound verbatim into `INSERT INTO public.jobs (… trigger_source …)`
//! inside the same transaction as the ingest transition — so if the column's
//! CHECK constraint does not admit it, the CHECK violation aborts the
//! transition and `map_register_error`'s catch-all turns it into `500`.
//!
//! **No mock can show this.** `MockArtifactLifecycle` records the
//! `IngestEnqueue` list it is handed and accepts any `trigger_source`
//! whatsoever; the CHECK lives in the schema, so only
//! `PgArtifactLifecycle` over a real database has an opinion. That is
//! exactly why `uploads.rs`'s own
//! `cross_mount_happy_path_zero_copy_and_returns_201` has been green over
//! an enqueue production cannot write.
//!
//! # The hybrid context
//!
//! The use case under test is a real `IngestUseCase` composed over the
//! Postgres event store, artifact repository, metadata repository and
//! lifecycle, swapped onto a `build_mock_ctx` context through
//! `with_ingest_use_case`. The remaining ports stay mocks: the repository
//! lookup, the CAS read and the policy projection are not what is under
//! test.
//!
//! Both halves have to agree on which repositories exist, so the two
//! `repositories` rows are inserted for real (the `artifacts` foreign key
//! needs them) **and** seeded into the mock repository under the same ids —
//! the same trick `legacy_quarantine_status_fails_closed_real_db` uses.
//!
//! The router is `hort_http_oci::uploads::router()` with no auth
//! middleware and an injected principal, the narrow-router pattern
//! `uploads.rs`'s inline tests and `register_by_hash_gate2_regression.rs`
//! both use.
//!
//! # The gate requests a scan
//!
//! `build_mock_ctx` seeds a global `ScanPolicyProjection` with
//! `scan_backends: ["trivy"]`, so `scan_will_run` is already true and the
//! mount already enqueues a scan row. The seed's `quarantine_duration_secs:
//! 0` keeps the artifact out of quarantine, which isolates the assertion to
//! the enqueue.
//!
//! # The second mount, and the gate it catches up
//!
//! The same harness carries the gate-aware dedup suite at the end of this
//! file — a repeat of a mount whose gate never landed has to run the gate
//! rather than report success and change nothing. Those tests need the
//! database for a second reason: the criterion is read off the artifact's
//! own event stream, so a test has to seed a stream a production read can
//! find and then read back what the catch-up appended. See that section's
//! header for the `artifact-` stream-id prefix and the positive control
//! every one of those tests opens with.
//!
//! # Skip-when-no-DB convention
//!
//! Every test early-returns when `DATABASE_URL` is unset, so the suite
//! stays green without a database. Each takes a per-test throwaway database
//! (`isolated_db_from`), which isolates the rows but not the server —
//! creating and migrating it is cluster-global work — so each also carries
//! the workspace-wide `#[serial(hort_pg_db)]` key.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test oci_cross_mount_scan_enqueue_real_db
//! ```

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use metrics_exporter_prometheus::PrometheusBuilder;
use serial_test::serial;
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

use hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle;
use hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::use_cases::ingest_use_case::IngestUseCase;
use hort_app::use_cases::test_support::sample_repository;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryFormat};
use hort_domain::entities::scan_policy::{
    NegligibleAction, ProvenanceMode, ScanEnforcement, ScanPolicyProjection, SeverityThreshold,
};
use hort_domain::events::{
    Actor, ApiActor, ArtifactIngested, ArtifactQuarantined, DomainEvent, IngestSource, PolicyScope,
    ScanRequested, StreamId,
};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::types::ContentHash;
use hort_http_core::context::AppContext;
use hort_http_core::test_support::{build_mock_ctx, with_ingest_use_case, MockPorts};

/// The source repository's key, and the `from=` query parameter.
const SOURCE_REPO_KEY: &str = "oci-mount-source";
/// The target repository's key — the `<name>` the mount POSTs into.
const TARGET_REPO_KEY: &str = "oci-mount-target";
/// The image name under the target repository.
const IMAGE_NAME: &str = "library/nginx";
/// The bytes already in CAS, owned by the source repository's row.
const BLOB: &[u8] = b"cross-mount proof content";

/// Connect to `DATABASE_URL` on a throwaway database of this test's own,
/// fully migrated. `None` when the env var is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Lowercase hex SHA-256 of `content`. Hand-rolled rather than pulled
/// through a `hex` dependency this crate does not otherwise carry.
fn sha256_hex(content: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(content)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// An OCI-format `Repository` entity with a caller-chosen id and key, so
/// the mock repository and the real `repositories` row agree.
fn oci_repo(id: Uuid, key: &str) -> Repository {
    let mut r = sample_repository();
    r.id = id;
    r.key = key.into();
    r.name = key.into();
    r.format = RepositoryFormat::Oci;
    r
}

/// Insert the `repositories` row the `artifacts` / `jobs` foreign keys
/// need. Mirrors `ingest_enqueue_atomicity`'s `seed_repo`, with the OCI
/// format and a caller-supplied id.
async fn insert_repository_row(pool: &PgPool, id: Uuid, key: &str) {
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $2, 'oci'::repository_format, 'hosted'::repository_type,
               'filesystem', $3, 'on_demand'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(key)
    .bind(format!("/data/repos/{key}"))
    .execute(pool)
    .await
    .expect("seed repositories row");
}

/// Insert the source repository's blob row — what
/// `find_by_repo_and_checksum` resolves the mount's authoritative
/// `size_bytes` from. `quarantine_status` is SQL `NULL`, which is the
/// stored spelling of `QuarantineStatus::None`: a non-terminal source, so
/// the anti-laundering gate lets the mount through.
async fn insert_source_blob_row(pool: &PgPool, repository_id: Uuid, hex: &str) {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status
           ) VALUES (
               $1, $2, $3, $3, NULL, $4,
               $5, $6, 'application/octet-stream', $6,
               NULL
           )"#,
    )
    .bind(id)
    .bind(repository_id)
    .bind(IMAGE_NAME)
    .bind(format!("blobs/sha256:{hex}"))
    .bind(BLOB.len() as i64)
    .bind(hex)
    .execute(pool)
    .await
    .expect("seed source artifacts row");
}

/// A mock `AppContext` whose `IngestUseCase` is composed over the real
/// Postgres event store / artifact repo / metadata repo / lifecycle.
///
/// Every other port carries forward from `build_mock_ctx`, including the
/// permissive-but-scanning global policy seed that makes the gate request a
/// scan.
async fn ctx_with_real_ingest(pool: &PgPool) -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    let (base, mocks) = build_mock_ctx(handle);

    let event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("event store init"),
    );
    let artifact_repo = Arc::new(PgArtifactRepository::new(pool.clone(), event_store.clone()));
    let metadata_repo = Arc::new(PgArtifactMetadataRepository::new(pool.clone()));
    let lifecycle = Arc::new(PgArtifactLifecycle::new(
        event_store.clone(),
        artifact_repo.clone(),
        metadata_repo,
    ));
    let publisher = Arc::new(EventStorePublisher::without_broadcast(event_store));

    let ingest = Arc::new(IngestUseCase::new(
        mocks.storage.clone(),
        lifecycle,
        artifact_repo,
        mocks.repositories.clone(),
        publisher,
        mocks.curation_rules.clone(),
        base.artifact_group_use_case.clone(),
        base.include_repository_label,
        HashMap::new(),
        0,
        mocks.content_references.clone(),
        mocks.policy_projections.clone(),
        mocks.jobs.clone(),
    ));

    let ctx = with_ingest_use_case(&base, ingest);
    (ctx, mocks)
}

/// Insert a minimal-but-valid `users` row.
///
/// `artifacts.uploaded_by` is a foreign key onto it, and
/// `register_by_hash` fills that column from the request's `ApiActor` —
/// so the authenticated principal the router carries has to be a user
/// the database knows about, or the row the mount mints fails its FK
/// before the enqueue is ever attempted. Mirrors
/// `task_use_case_enqueue_real_db`'s `create_test_user`.
async fn insert_user_row(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(format!("mount-{}", id.simple()))
    .bind(format!("mount-{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed users row");
}

/// A synthetic authenticated principal. `build_mock_ctx` returns
/// `AuthContext::Disabled`, so the narrow router carries no auth
/// middleware and the principal is injected the way the production
/// `require_principal` layer would have.
fn test_principal(user_id: Uuid) -> CallerPrincipal {
    CallerPrincipal {
        user_id,
        external_id: "test:sub".into(),
        username: "alice".into(),
        email: "alice@example.com".into(),
        claims: Vec::new(),
        token_kind: None,
        issued_at: chrono::Utc::now(),
        token_cap: None,
    }
}

/// Drive the mount. Returns the HTTP status and the response body.
async fn mount(ctx: Arc<AppContext>, hex: &str, user_id: Uuid) -> (StatusCode, String) {
    let router = hort_http_oci::uploads::router().with_state(ctx);
    let uri = format!(
        "/v2/{TARGET_REPO_KEY}/{IMAGE_NAME}/blobs/uploads/?mount=sha256:{hex}&from={SOURCE_REPO_KEY}"
    );
    let mut req = HttpRequest::post(&uri)
        .body(Body::empty())
        .expect("build request");
    hort_http_core::middleware::auth::test_support::inject_principal(
        &mut req,
        test_principal(user_id),
    );
    let resp = router.oneshot(req).await.expect("router call");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    (status, String::from_utf8_lossy(&body).to_string())
}

/// The full fixture: both repository rows (real + mock), the source blob
/// row, and the CAS content behind it.
///
/// `tune` runs with the mock ports and the target repository's id in hand,
/// before the context is handed back, so a test can replace the permissive
/// `build_mock_ctx` policy seed with the shape it needs.
async fn setup_with(
    pool: &PgPool,
    tune: impl FnOnce(&MockPorts, Uuid),
) -> (Arc<AppContext>, String, Uuid, Uuid) {
    let hex = sha256_hex(BLOB);
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    insert_user_row(pool, user_id).await;
    insert_repository_row(pool, source_id, SOURCE_REPO_KEY).await;
    insert_repository_row(pool, target_id, TARGET_REPO_KEY).await;
    insert_source_blob_row(pool, source_id, &hex).await;

    let (ctx, mocks) = ctx_with_real_ingest(pool).await;
    mocks
        .repositories
        .insert(oci_repo(source_id, SOURCE_REPO_KEY));
    mocks
        .repositories
        .insert(oci_repo(target_id, TARGET_REPO_KEY));
    let hash: ContentHash = hex.parse().expect("valid sha256");
    mocks.storage.insert_content(hash, BLOB.to_vec());
    tune(&mocks, target_id);

    (ctx, hex, user_id, target_id)
}

/// [`setup_with`] with the fixture's own policy seed left alone.
async fn setup(pool: &PgPool) -> (Arc<AppContext>, String, Uuid) {
    let (ctx, hex, user_id, _target_id) = setup_with(pool, |_mocks, _target_id| {}).await;
    (ctx, hex, user_id)
}

/// Count the `kind='scan'` rows carrying `trigger_source`.
async fn scan_rows_with_trigger_source(pool: &PgPool, trigger_source: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM public.jobs \
         WHERE kind = 'scan' AND trigger_source = $1",
    )
    .bind(trigger_source)
    .fetch_one(pool)
    .await
    .expect("count scan rows")
    .get::<i64, _>("n")
}

/// **The reachable consequence.** The mount must answer `201` — not `500` —
/// when the target repository's gate requests a scan for the mounted blob,
/// and the scan row it enqueued must be in the `jobs` table carrying the
/// `trigger_source` the use case stamps.
///
/// Before the `jobs.trigger_source` CHECK admitted `'register-by-hash'`
/// this returned `500` with an empty `jobs` table: the CHECK violation
/// aborted the whole ingest transition and `map_register_error`'s catch-all
/// mapped the resulting `DomainError` onto `OciError::Internal`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn cross_mount_with_scan_enqueue_answers_201_and_lands_the_scan_row() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (ctx, hex, user_id) = setup(&pool).await;

    let (status, body) = mount(ctx, &hex, user_id).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the mount must answer 201 with a scan enqueued; body: {body}"
    );
    assert_eq!(
        scan_rows_with_trigger_source(&pool, "register-by-hash").await,
        1,
        "the mount's scan row must be in the jobs table carrying the \
         trigger_source `register_by_hash_inner` stamps"
    );
}

/// The artifact row and its scan row land **together**. The second half of
/// the consequence: while the CHECK refused the enqueue, the mount's
/// follow-on gate commit rolled back, so the first (genesis) commit's
/// artifact row survived with no scan row behind it — a servable row that
/// was never going to be scanned, under a `500` that told the client
/// nothing had happened.
#[tokio::test]
#[serial(hort_pg_db)]
async fn cross_mount_leaves_no_artifact_without_its_scan_row() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (ctx, hex, user_id) = setup(&pool).await;

    let (status, body) = mount(ctx, &hex, user_id).await;
    assert_eq!(status, StatusCode::CREATED, "precondition; body: {body}");

    let target_rows: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM public.artifacts a \
         JOIN public.repositories r ON r.id = a.repository_id \
         WHERE r.key = $1 AND a.deleted_at IS NULL",
    )
    .bind(TARGET_REPO_KEY)
    .fetch_one(&pool)
    .await
    .expect("count target artifacts")
    .get::<i64, _>("n");
    assert_eq!(
        target_rows, 1,
        "the mount must mint exactly one row in the target repository"
    );

    let paired: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM public.artifacts a \
         JOIN public.repositories r ON r.id = a.repository_id \
         JOIN public.jobs j ON j.artifact_id = a.id AND j.kind = 'scan' \
         WHERE r.key = $1 AND a.deleted_at IS NULL",
    )
    .bind(TARGET_REPO_KEY)
    .fetch_one(&pool)
    .await
    .expect("count paired rows")
    .get::<i64, _>("n");
    assert_eq!(
        paired, 1,
        "the minted row must carry its scan job — an artifact without one is \
         the strand the rolled-back gate commit used to leave behind"
    );
}

// ---------------------------------------------------------------------------
// The gate-aware dedup: a repeat catches up a missing gate
// ---------------------------------------------------------------------------
//
// Everything above is about the FIRST mount. These are about the second.
//
// `register_by_hash_inner`'s same-path-same-hash guard used to answer
// `Duplicate` before any policy resolution and before the gate, and the
// mount maps that to `201`. So an artifact whose gate commit never landed
// stayed ungated forever, even when the same mount was repeated: a `skopeo
// copy` or a re-tag somebody ran again reported success and changed
// nothing. The resulting row is servable, carries one `ArtifactIngested`
// and nothing else, and owes a scan verdict that nothing records — in a
// repository whose policy both quarantines and scans, which is the shape
// the fixtures below build.
//
// **These need the database for a second reason on top of the one above.**
// The criterion asks whether the gate's events are on the artifact's own
// stream, so the test has to seed a stream a production read can find and
// then read back what the catch-up appended. `events.stream_id` carries an
// `artifact-` prefix (`StreamId`'s `Display` is `"{category}-{entity}"`),
// so a probe that joined on the bare UUID would match nothing and return a
// silent zero — and every assertion below would read as "nothing
// happened". Each test therefore opens with a positive control on the
// seeded `ArtifactIngested` under the prefixed stream id.

/// The row the two-commit gate split left behind, and its genesis event:
/// a minted, servable artifact at the mount's own
/// `(repository_id, path)` with `quarantine_status` SQL NULL, one
/// `ArtifactIngested` on its stream, and nothing else — the gate-less
/// genesis row the catch-up has to recognise.
///
/// The event goes through `PgEventStore::append` and not raw SQL: the
/// event chain is hash-linked (ADR 0002), so a hand-written row would be
/// a broken chain rather than a fixture.
async fn seed_gate_less_target_row(
    pool: &PgPool,
    repository_id: Uuid,
    hex: &str,
    user_id: Uuid,
) -> Uuid {
    let artifact_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, uploaded_by
           ) VALUES (
               $1, $2, $3, $3, NULL, $4,
               $5, $6, 'application/octet-stream', $6,
               NULL, $7
           )"#,
    )
    .bind(artifact_id)
    .bind(repository_id)
    .bind(IMAGE_NAME)
    .bind(format!("blobs/sha256:{hex}"))
    .bind(BLOB.len() as i64)
    .bind(hex)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed gate-less target artifacts row");

    let event_store = PgEventStore::new(pool.clone())
        .await
        .expect("event store init");
    let hash: ContentHash = hex.parse().expect("valid sha256");
    event_store
        .append(AppendEvents {
            stream_id: StreamId::artifact(artifact_id),
            expected_version: ExpectedVersion::NoStream,
            events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
                ArtifactIngested {
                    artifact_id,
                    repository_id,
                    name: IMAGE_NAME.to_string(),
                    version: None,
                    sha256: hash,
                    size_bytes: BLOB.len() as i64,
                    source: IngestSource::Direct,
                    metadata: serde_json::Value::Null,
                    metadata_blob: None,
                    upstream_published_at: None,
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor { user_id }),
        })
        .await
        .expect("seed the gate-less row's genesis event");

    artifact_id
}

/// Seed the row with its gate already landed: `ArtifactQuarantined` and
/// `ScanRequested` behind the genesis event, the row at `quarantined`, and
/// the `kind='scan'` job row the gate's commit carried. The healthy shape
/// a repeat must leave strictly alone.
async fn seed_gated_target_row(
    pool: &PgPool,
    repository_id: Uuid,
    hex: &str,
    user_id: Uuid,
) -> Uuid {
    let artifact_id = seed_gate_less_target_row(pool, repository_id, hex, user_id).await;
    let event_store = PgEventStore::new(pool.clone())
        .await
        .expect("event store init");
    event_store
        .append(AppendEvents {
            stream_id: StreamId::artifact(artifact_id),
            expected_version: ExpectedVersion::Exact(0),
            events: vec![
                EventToAppend::new(DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                    artifact_id,
                    quarantine_window_start: chrono::Utc::now(),
                })),
                EventToAppend::new(DomainEvent::ScanRequested(ScanRequested {
                    artifact_id,
                    scanner: "trivy".to_string(),
                })),
            ],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor { user_id }),
        })
        .await
        .expect("seed the gate's own events");
    sqlx::query(
        "UPDATE public.artifacts \
            SET quarantine_status = 'quarantined', quarantine_window_start = now() \
          WHERE id = $1",
    )
    .bind(artifact_id)
    .execute(pool)
    .await
    .expect("stamp the gated row");
    sqlx::query(
        "INSERT INTO public.jobs (id, kind, artifact_id, params, trigger_source) \
         VALUES ($1, 'scan', $2, '{}'::jsonb, 'register-by-hash')",
    )
    .bind(Uuid::new_v4())
    .bind(artifact_id)
    .execute(pool)
    .await
    .expect("seed the gate's scan job row");
    artifact_id
}

/// Count the events of one type on `artifact_id`'s own stream.
///
/// Addressed by `artifact-<uuid>`, which is what `StreamId::artifact`
/// writes — see this section's header for the silent zero the bare UUID
/// returns.
async fn stream_event_count(pool: &PgPool, artifact_id: Uuid, event_type: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM public.events \
         WHERE stream_id = $1 AND event_type = $2",
    )
    .bind(format!("artifact-{artifact_id}"))
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("count stream events")
    .get::<i64, _>("n")
}

/// Count the `kind='scan'` job rows belonging to one artifact.
async fn scan_rows_for_artifact(pool: &PgPool, artifact_id: Uuid) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM public.jobs \
         WHERE kind = 'scan' AND artifact_id = $1",
    )
    .bind(artifact_id)
    .fetch_one(pool)
    .await
    .expect("count scan rows")
    .get::<i64, _>("n")
}

/// The row's stored `quarantine_status` — SQL NULL is the stored spelling
/// of `QuarantineStatus::None`.
async fn stored_quarantine_status(pool: &PgPool, artifact_id: Uuid) -> Option<String> {
    sqlx::query("SELECT quarantine_status FROM public.artifacts WHERE id = $1")
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("read quarantine_status")
        .get::<Option<String>, _>("quarantine_status")
}

/// Count the live artifact rows in the target repository.
async fn target_artifact_rows(pool: &PgPool) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM public.artifacts a \
         JOIN public.repositories r ON r.id = a.repository_id \
         WHERE r.key = $1 AND a.deleted_at IS NULL",
    )
    .bind(TARGET_REPO_KEY)
    .fetch_one(pool)
    .await
    .expect("count target artifacts")
    .get::<i64, _>("n")
}

/// A quarantining, scanning repository-scoped policy over the target —
/// the shape the defect bites in, and what the permissive
/// `build_mock_ctx` seed (`quarantine_duration_secs: 0`) does not give.
fn seed_quarantining_policy(mocks: &MockPorts, target_id: Uuid) {
    hort_http_core::test_support::seed_timed_hold_policy(&mocks.policy_projections, target_id);
}

/// A repository-scoped policy with every axis waived. There is no shared
/// builder for this shape: `hort-http-core`'s seeds all carry
/// `scan_backends: ["trivy"]`, and waiving the scan axis is the whole
/// point here.
fn fully_waived_policy(repo_id: Uuid) -> ScanPolicyProjection {
    let now = chrono::Utc::now();
    ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: format!("fully-waived-{repo_id}"),
        scope: PolicyScope::Repository(repo_id),
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 0,
        require_approval: false,
        provenance_mode: ProvenanceMode::Off,
        provenance_backends: Vec::new(),
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: Vec::new(),
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        stream_version: 0,
        created_at: now,
        updated_at: now,
    }
}

/// **The proof, and the heal.** A repeat of a mount over a gate-less row
/// runs the gate it never got: the `ArtifactQuarantined` and the
/// `ScanRequested` land on the row's own stream, the `kind='scan'` job row
/// appears, and the row ends at `quarantined` — all without a second
/// artifact row or a second `ArtifactIngested`.
///
/// Before the dedup check became gate-aware, this test's `201` assertion
/// passed and the scan-request assertion right after it failed with zero:
/// the repeat reported success and changed nothing, which is the whole
/// defect.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_repeat_of_a_gate_less_mount_catches_up_the_window_and_the_scan() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (ctx, hex, user_id, target_id) = setup_with(&pool, seed_quarantining_policy).await;
    let artifact_id = seed_gate_less_target_row(&pool, target_id, &hex, user_id).await;

    // POSITIVE CONTROL: the seeded genesis event is reachable under the
    // prefixed stream id, so a zero below means "absent", not "mis-joined".
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1,
        "the fixture's genesis event must be readable under artifact-<uuid>"
    );
    assert_eq!(
        scan_rows_for_artifact(&pool, artifact_id).await,
        0,
        "precondition: the gate-less row owes a verdict nothing records"
    );

    let (status, body) = mount(ctx, &hex, user_id).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the repeat still answers 201 — the heal must never turn a \
         successful mount into an error; body: {body}"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ScanRequested").await,
        1,
        "the repeat must have caught up the missing scan request"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactQuarantined").await,
        1,
        "and the missing observation window"
    );
    assert_eq!(
        scan_rows_for_artifact(&pool, artifact_id).await,
        1,
        "with the scan job row that makes the owed verdict visible"
    );
    assert_eq!(
        stored_quarantine_status(&pool, artifact_id)
            .await
            .as_deref(),
        Some("quarantined"),
        "the row ends in the state the gate determined"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1,
        "and the catch-up is not a second mint"
    );
    assert_eq!(
        target_artifact_rows(&pool).await,
        1,
        "nor a second row — the registration is still a dedup"
    );
}

/// **Idempotence for the healthy row.** A repeat over a row that has its
/// gate result answers `Duplicate` and adds nothing: no second scan row,
/// no second `ArtifactIngested`, no second `ScanRequested`, no second
/// `ArtifactQuarantined`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_repeat_of_a_gated_mount_adds_no_second_gate() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (ctx, hex, user_id, target_id) = setup_with(&pool, seed_quarantining_policy).await;
    let artifact_id = seed_gated_target_row(&pool, target_id, &hex, user_id).await;

    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1,
        "POSITIVE CONTROL: the fixture's stream is readable under \
         artifact-<uuid>"
    );

    let (status, body) = mount(ctx, &hex, user_id).await;
    assert_eq!(status, StatusCode::CREATED, "precondition; body: {body}");

    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1,
        "no second mint"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactQuarantined").await,
        1,
        "no second observation window"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ScanRequested").await,
        1,
        "no second scan request"
    );
    assert_eq!(
        scan_rows_for_artifact(&pool, artifact_id).await,
        1,
        "no second scan row"
    );
    assert_eq!(target_artifact_rows(&pool).await, 1, "no second row");
}

/// **Idempotence for the healthy row that looks broken.** A fully waived
/// policy — `quarantineDuration: 0` AND `scanBackends: []` AND
/// `provenanceMode: off` — legitimately produces no gate artifacts at all,
/// so its rows are state-identical to the broken ones. They must keep
/// answering `Duplicate`: a criterion that could not separate them would
/// re-gate a healthy artifact on every single mount.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_repeat_under_a_fully_waived_policy_adds_nothing() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (ctx, hex, user_id, target_id) = setup_with(&pool, |mocks, target_id| {
        mocks
            .policy_projections
            .insert(fully_waived_policy(target_id));
    })
    .await;
    let artifact_id = seed_gate_less_target_row(&pool, target_id, &hex, user_id).await;

    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1,
        "POSITIVE CONTROL: the fixture's stream is readable under \
         artifact-<uuid>"
    );

    let (status, body) = mount(ctx, &hex, user_id).await;
    assert_eq!(status, StatusCode::CREATED, "precondition; body: {body}");

    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactQuarantined").await,
        0,
        "a fully waived policy quarantines nothing, and a repeat must not \
         invent a window the policy declined"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ScanRequested").await,
        0,
        "nor a scan the operator waived"
    );
    assert_eq!(scan_rows_for_artifact(&pool, artifact_id).await, 0);
    assert_eq!(
        stored_quarantine_status(&pool, artifact_id).await,
        None,
        "the row stays exactly as the waived policy left it"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1
    );
}

/// **A concurrent double repeat lands one gate, not two.** Both repeats
/// observe "no gate result"; the version read beside that evidence is what
/// makes the second append lose. The loser answers the same `201` it
/// always did, over a row the winner has already healed.
#[tokio::test]
#[serial(hort_pg_db)]
async fn two_concurrent_repeats_land_exactly_one_gate() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (ctx, hex, user_id, target_id) = setup_with(&pool, seed_quarantining_policy).await;
    let artifact_id = seed_gate_less_target_row(&pool, target_id, &hex, user_id).await;

    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactIngested").await,
        1,
        "POSITIVE CONTROL: the fixture's stream is readable under \
         artifact-<uuid>"
    );

    let (first, second) = tokio::join!(
        mount(Arc::clone(&ctx), &hex, user_id),
        mount(Arc::clone(&ctx), &hex, user_id),
    );

    assert_eq!(
        (first.0, second.0),
        (StatusCode::CREATED, StatusCode::CREATED),
        "both halves answer 201 — losing the race is a correct outcome for \
         a repeat, not an error; bodies: {} / {}",
        first.1,
        second.1
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ArtifactQuarantined").await,
        1,
        "exactly one observation window"
    );
    assert_eq!(
        stream_event_count(&pool, artifact_id, "ScanRequested").await,
        1,
        "exactly one scan request"
    );
    assert_eq!(
        scan_rows_for_artifact(&pool, artifact_id).await,
        1,
        "exactly one scan row"
    );
    assert_eq!(target_artifact_rows(&pool).await, 1);
}
