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
async fn setup(pool: &PgPool) -> (Arc<AppContext>, String, Uuid) {
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
