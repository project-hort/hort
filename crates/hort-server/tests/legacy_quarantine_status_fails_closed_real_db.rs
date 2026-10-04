//! Integration test — an `artifacts` row whose stored
//! `quarantine_status` the domain cannot classify is neither
//! downloadable nor advertised by an index, driven through the real
//! Postgres adapter and the real axum router.
//!
//! # Why this test cannot be written with a fixture
//!
//! The defect lived in the *decode*. Every mock artifact repository in
//! the workspace stores a typed
//! [`QuarantineStatus`](hort_domain::entities::artifact::QuarantineStatus),
//! so a test built on one can only ever ask what the system does with a
//! status that already parsed — and the question here is what it does
//! with one that cannot. The three spellings below
//! (`unscanned` / `clean` / `flagged`) are prototype-era scan states
//! that migration `003`'s CHECK still accepts and `QuarantineStatus`
//! cannot parse; before the fix, the row mapper discarded the parse
//! error and substituted `QuarantineStatus::None` — the most permissive
//! state in the system — so such a row was advertised by the index and
//! served on download with no release authority behind it and no
//! `ArtifactReleased` in its stream.
//!
//! So: a real row, written as raw SQL (no writer in the tree produces
//! these values), read through
//! [`PgArtifactRepository`](hort_adapters_postgres::artifact_repo::PgArtifactRepository),
//! and driven through the production npm handler stack by
//! `tower::oneshot`.
//!
//! # What each test pins, and why the control case matters
//!
//! Every assertion is made twice over the same fixture: once for the
//! legacy spelling and once for `'released'`. Without the second half,
//! a fixture that was simply broken (wrong path, missing repository,
//! absent content) would produce the same "not served" verdict and the
//! test would pass while proving nothing. The control is what makes the
//! legacy case attributable to the decode — and, in the migration test,
//! what keeps "not advertised" from being satisfied by a 404 over an
//! empty package.
//!
//! # The hybrid context
//!
//! `ctx.artifacts` is the real Postgres adapter
//! ([`with_artifacts`]); `ctx.repositories` and `ctx.storage` stay
//! mocks. That split is deliberate — the repository lookup and the CAS
//! read are not what is under test, and the artifact row's
//! `repository_id` references a real `repositories` row (inserted here
//! for the foreign key) carrying the same id as the mock fixture, so
//! both halves agree on which repository this is.
//!
//! # Skip-when-no-DB convention
//!
//! Mirrors `gitops_retention_scope_real_db`: every test early-returns
//! when `DATABASE_URL` is unset, so the suite stays green without a
//! database. Most tests take a per-test throwaway database
//! (`isolated_db_from`) — which isolates the *rows*, not the server:
//! creating and migrating it is cluster-global work, so each test also
//! carries the workspace-wide `#[serial(hort_pg_db)]` key.
//!
//! [`a_legacy_row_written_before_the_backfill_is_held_by_it`] is the one
//! exception, and it has to be: it needs a database that has NOT yet run
//! the backfill, which an `isolated_db_from` pool cannot be (that helper
//! hands back a fully-migrated database). It hand-rolls a throwaway
//! database and migrates it to the version *below* the backfill through
//! the real `MIGRATOR` — the third harness mode `CLAUDE.md` documents,
//! same shape as `migrate_schema_compat.rs`, same serial key.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test legacy_quarantine_status_fails_closed_real_db
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serial_test::serial;
use sqlx::{Executor, PgPool};
use tower::util::ServiceExt;
use uuid::Uuid;

use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{IndexMode, Repository, RepositoryFormat, RepositoryType};
use hort_domain::types::ContentHash;
use hort_http_core::context::AppContext;
use hort_http_core::test_support::{build_mock_ctx, with_artifacts, MockPorts};
use hort_server::migrate::MIGRATOR;

/// The spellings migration `003`'s CHECK accepts and the domain cannot
/// parse. `030_artifacts_quarantine_status_legacy_backfill.sql` replaces
/// them with the held state; this test is about what happens if one is
/// in front of a read anyway.
const UNCLASSIFIABLE_SPELLINGS: [&str; 3] = ["unscanned", "clean", "flagged"];

const REPO_KEY: &str = "npm-legacy-status";
const PACKAGE: &str = "legacy-pkg";
const VERSION: &str = "1.0.0";
const FILENAME: &str = "legacy-pkg-1.0.0.tgz";
const TARBALL: &[u8] = b"legacy-tarball-bytes";

/// The control version in the post-migration fixture — a `'released'`
/// row the backfill must not touch, seeded beside the legacy ones so the
/// index assertion is about which versions a 200 carries rather than
/// about an empty package.
const CONTROL_VERSION: &str = "9.9.9";

/// The migration under test, found in [`MIGRATOR`] by the description
/// sqlx derives from its file name (`_` → ` `, `.sql` dropped). Located
/// rather than hard-coded as a version number so a renumbering fails
/// loudly instead of silently migrating to the wrong waterline.
const BACKFILL_DESCRIPTION: &str = "artifacts quarantine status legacy backfill";

/// Connect to `DATABASE_URL`, on a throwaway database of this test's
/// own. Returns `None` when the env var is unset.
async fn isolated_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// [`MIGRATOR`]'s version for the backfill migration.
fn backfill_version() -> i64 {
    MIGRATOR
        .iter()
        .find(|m| m.description == BACKFILL_DESCRIPTION)
        .map(|m| m.version)
        .unwrap_or_else(|| {
            panic!(
                "no migration described {BACKFILL_DESCRIPTION:?} in MIGRATOR — the backfill was \
                 renamed or removed, and this test would otherwise migrate to an arbitrary \
                 waterline and prove nothing"
            )
        })
}

/// A throwaway database migrated to the version **below** the backfill,
/// plus the `postgres` maintenance pool and the database's name, so the
/// caller can drop it.
///
/// The partial migration is the whole point: the acceptance is about a
/// row that exists *before* the backfill runs, and a fully-migrated
/// database cannot hold one. `MIGRATOR.run_to` applies the real
/// migration files up to and including its target, so this harness does
/// not reimplement or copy any migration's SQL — the backfill below is
/// applied as the migration it is, not as a statement transcribed into a
/// test.
///
/// Returns `None` only when `DATABASE_URL` is unset. The name is
/// `isolated_db_from`'s `hort_test_<epoch>_<uuid>` shape on purpose: a
/// database leaked by a panicking test is then age-gated and reaped by
/// that helper's stale-database sweep rather than accumulating forever.
async fn pre_backfill_pool() -> Option<(PgPool, PgPool, String)> {
    let url = env::var("DATABASE_URL").ok()?;
    let admin = hort_adapters_postgres::test_support::connect_or_panic(&url).await;

    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let db_name = format!("hort_test_{epoch}_{}", Uuid::new_v4().simple());
    // Identifier interpolation is safe: the prefix is a literal, the
    // epoch is digits and the suffix is a hex-only UUID.
    admin
        .execute(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE \"{db_name}\""
        )))
        .await
        .expect("CREATE DATABASE (pre-backfill temp)");

    let pool = PgPool::connect(&temp_db_url(&url, &db_name))
        .await
        .expect("connect to the pre-backfill temp database");
    MIGRATOR
        .run_to(backfill_version() - 1, &pool)
        .await
        .expect("migrate to the version below the backfill");

    Some((pool, admin, db_name))
}

/// Apply the backfill migration — and only it — to a pool standing one
/// version below it. `MIGRATOR::run` applies every pending migration,
/// which at this waterline is exactly the backfill.
async fn run_backfill_migration(pool: &PgPool) {
    MIGRATOR
        .run(pool)
        .await
        .expect("apply the backfill migration");
}

/// `DATABASE_URL` with its database replaced by `db_name`.
fn temp_db_url(base: &str, db_name: &str) -> String {
    let mut parsed = url::Url::parse(base).expect("DATABASE_URL parses");
    parsed.set_path(db_name);
    parsed.into()
}

/// Close `pool` and drop its database, best effort.
async fn drop_temp_db(admin: &PgPool, db_name: &str, pool: PgPool) {
    pool.close().await;
    let drop_sql = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
    for attempt in 0..5 {
        match admin.execute(sqlx::AssertSqlSafe(drop_sql.clone())).await {
            Ok(_) => return,
            Err(e) if attempt < 4 => {
                eprintln!("DROP DATABASE {db_name} attempt {attempt} failed: {e}; retrying");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                eprintln!("warning: failed to drop temp DB {db_name}: {e}");
                return;
            }
        }
    }
}

/// The SHA-256 the fixture's CAS entry is keyed by. A fixed, valid
/// 64-hex value — the bytes are seeded into the mock storage under it,
/// so the control case has real content to serve.
fn fixture_hash() -> ContentHash {
    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        .parse()
        .expect("the fixture hash is valid 64-hex")
}

/// Insert the real `repositories` row the artifact's foreign key needs,
/// under `id`. The handler resolves the repository through the mock
/// port; this row exists so the artifact insert is legal.
async fn seed_repository_row(pool: &PgPool, id: Uuid) {
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               is_public, index_mode
           ) VALUES (
               $1, $2, $2, 'npm'::public.repository_format,
               'hosted'::public.repository_type, 'filesystem', $3, true, 'released_only'
           )"#,
    )
    .bind(id)
    .bind(REPO_KEY)
    .bind(format!("/data/{REPO_KEY}"))
    .execute(pool)
    .await
    .expect("seed repositories row");
}

/// Write the artifact row with `raw` in `quarantine_status`, as raw SQL.
///
/// Raw SQL is not a shortcut here, it is the only way: the adapter's
/// encoder cannot produce any of these spellings (that is the point of
/// having one encoder), so a row carrying one can only be written
/// behind it — which is also exactly how a migrated database would come
/// to hold one.
async fn seed_artifact_row(pool: &PgPool, repository_id: Uuid, raw: &str) -> Uuid {
    seed_artifact_version_row(pool, repository_id, raw, VERSION).await
}

/// [`seed_artifact_row`] for an arbitrary version, so one fixture can
/// carry several versions of the same package side by side — the shape
/// the post-migration index assertion needs (held versions next to a
/// served one, in one packument).
async fn seed_artifact_version_row(
    pool: &PgPool,
    repository_id: Uuid,
    raw: &str,
    version: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, checksum_sha1, content_type, storage_key,
               quarantine_status
           ) VALUES (
               $1, $2, $3, $3, $4, $5,
               $6, $7, $8, 'application/octet-stream', $7,
               $9
           )"#,
    )
    .bind(id)
    .bind(repository_id)
    .bind(PACKAGE)
    .bind(version)
    .bind(format!("{PACKAGE}/-/{}", tarball_filename(version)))
    .bind(TARBALL.len() as i64)
    .bind(fixture_hash().as_ref())
    .bind("0".repeat(40))
    .bind(raw)
    .execute(pool)
    .await
    .expect("seed artifacts row");
    id
}

/// The npm tarball filename for `version` — `{basename}-{version}.tgz`,
/// the shape the hosted serve path and `download_uri_for` both build.
fn tarball_filename(version: &str) -> String {
    format!("{PACKAGE}-{version}.tgz")
}

/// The production npm route tree with the request-trust layer the
/// packument handler extracts from, mirroring `hort-http-npm`'s own
/// router helper.
fn router(ctx: Arc<AppContext>) -> Router {
    let trust_cfg = ctx.trust_config.clone();
    Router::new()
        .nest("/npm", hort_http_npm::npm_routes())
        .layer(hort_http_core::middleware::trust::request_trust_layer(
            trust_cfg,
        ))
        .with_state(ctx)
}

/// Build the hybrid context: real Postgres artifact repository, mock
/// repository port seeded with the matching npm repository, mock storage
/// seeded with the fixture's content.
async fn harness(pool: &PgPool, repository_id: Uuid) -> (Arc<AppContext>, MockPorts) {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle();
    let (ctx, mocks) = build_mock_ctx(handle);

    let mut repo = hort_app::use_cases::test_support::sample_repository();
    repo.id = repository_id;
    repo.key = REPO_KEY.to_string();
    repo.format = RepositoryFormat::Npm;
    repo.repo_type = RepositoryType::Hosted;
    repo.index_mode = IndexMode::ReleasedOnly;
    mocks.repositories.insert(repo);

    mocks
        .storage
        .insert_content(fixture_hash(), TARBALL.to_vec());

    let event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new (the migrations install the immutability trigger)"),
    );
    let artifacts = Arc::new(PgArtifactRepository::new(pool.clone(), event_store));
    (with_artifacts(&ctx, artifacts), mocks)
}

/// `(status, body)` of one GET through the production router.
async fn get(ctx: &Arc<AppContext>, uri: &str) -> (StatusCode, String) {
    let response = router(ctx.clone())
        .oneshot(
            Request::get(uri)
                .header("host", "registry.example.com")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router call");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Drop the artifact rows so the next spelling starts from a clean
/// fixture within the same throwaway database.
async fn clear_artifacts(pool: &PgPool) {
    sqlx::query("DELETE FROM public.artifacts")
        .execute(pool)
        .await
        .expect("clear artifacts");
}

fn download_uri() -> String {
    format!("/npm/{REPO_KEY}/{PACKAGE}/-/{FILENAME}")
}

fn download_uri_for(version: &str) -> String {
    format!("/npm/{REPO_KEY}/{PACKAGE}/-/{}", tarball_filename(version))
}

fn packument_uri() -> String {
    format!("/npm/{REPO_KEY}/{PACKAGE}")
}

/// A real download of a row carrying an unclassifiable status does not
/// serve the bytes — and the identical fixture at `'released'` does, so
/// the refusal is attributable to the status and not to the fixture.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_unclassifiable_status_row_is_not_downloadable() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repository_id = Uuid::new_v4();
    seed_repository_row(&pool, repository_id).await;
    let (ctx, _mocks) = harness(&pool, repository_id).await;

    // Control first: the fixture is sound and the download works.
    seed_artifact_row(&pool, repository_id, "released").await;
    let (status, body) = get(&ctx, &download_uri()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: a released row must download — otherwise the legacy \
         verdict below proves nothing about the status. Body: {body}"
    );
    assert_eq!(
        body.as_bytes(),
        TARBALL,
        "control: the download must serve the seeded content"
    );

    for raw in UNCLASSIFIABLE_SPELLINGS {
        clear_artifacts(&pool).await;
        seed_artifact_row(&pool, repository_id, raw).await;

        let (status, body) = get(&ctx, &download_uri()).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a row carrying {raw:?} must not download"
        );
        assert_ne!(
            body.as_bytes(),
            TARBALL,
            "a row carrying {raw:?} must not serve its content"
        );
    }
}

/// A real hosted-index serve does not advertise the version of a row
/// carrying an unclassifiable status. Same control/legacy pairing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_unclassifiable_status_row_is_not_served_by_the_index() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repository_id = Uuid::new_v4();
    seed_repository_row(&pool, repository_id).await;
    let (ctx, _mocks) = harness(&pool, repository_id).await;

    // Control: the released row IS advertised, so "absent" below is a
    // verdict about the status rather than about an empty repository.
    seed_artifact_row(&pool, repository_id, "released").await;
    let (status, body) = get(&ctx, &packument_uri()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: a released row must be advertised. Body: {body}"
    );
    assert!(
        body.contains(VERSION),
        "control: the packument must advertise {VERSION}; got {body}"
    );

    for raw in UNCLASSIFIABLE_SPELLINGS {
        clear_artifacts(&pool).await;
        seed_artifact_row(&pool, repository_id, raw).await;

        let (status, body) = get(&ctx, &packument_uri()).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "an index serve that cannot classify a row must not answer 200 \
             for {raw:?}"
        );
        assert!(
            !body.contains(FILENAME),
            "the index must not advertise a tarball for {raw:?}; got {body}"
        );
    }
}

/// The per-version status read every format's index-serve filter
/// consumes — `ArtifactUseCase::package_version_status`, the feed for
/// the npm / PyPI / cargo proxy sources and for
/// `filter_served_versions` — fails rather than report an
/// unclassifiable row as servable.
///
/// Driven at the use-case seam on purpose: this one read is shared by
/// every format, so pinning it here covers the proxy sources of all of
/// them without four router fixtures. The per-format propagation (that
/// none of them substitutes an empty status map) is pinned in each
/// format crate's own tests.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_shared_per_version_status_read_fails_closed() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repository_id = Uuid::new_v4();
    seed_repository_row(&pool, repository_id).await;
    let (ctx, _mocks) = harness(&pool, repository_id).await;

    seed_artifact_row(&pool, repository_id, "released").await;
    let servable = ctx
        .artifact_use_case
        .package_version_status(repository_id, PACKAGE)
        .await
        .expect("control: a released row reads back");
    assert_eq!(
        servable,
        vec![(VERSION.to_string(), QuarantineStatus::Released)],
        "control: the read must report the released version"
    );

    for raw in UNCLASSIFIABLE_SPELLINGS {
        clear_artifacts(&pool).await;
        seed_artifact_row(&pool, repository_id, raw).await;

        let err = ctx
            .artifact_use_case
            .package_version_status(repository_id, PACKAGE)
            .await
            .expect_err("an unclassifiable row must not read back as a status");
        assert!(
            err.to_string().contains(raw),
            "the error must name the offending value; got {err}"
        );
    }
}

/// The migration half of the contract, and the acceptance the unit's
/// security claim rests on: a row carrying a legacy spelling **before**
/// the backfill runs is, after it, neither downloadable nor advertised
/// by an index source.
///
/// # Why the partial migration matters
///
/// The predecessor of this test asserted that the backfill's statement
/// produced SQL `NULL`, and called that correct because `NULL` is how
/// every previous release's mapper already classified the three
/// spellings. That classification was the defect: `NULL` decodes to
/// [`QuarantineStatus::None`], the most permissive state in the system
/// — `Artifact::is_downloadable` admits it and the default
/// `ReleasedOnly` index mode serves it. So the codec refused a legacy
/// spelling while the migration turned it into a valid permissive one
/// first, and for the rows the statement touched the outcome was
/// identical to the defect. The test never drove a download or an index
/// serve after the backfill, which is the step that would have shown it.
///
/// This test drives both, on a database the row predates: the harness
/// migrates to the version below the backfill, writes the rows, then
/// applies the backfill as the real migration (no statement is
/// transcribed here, so the assertion cannot drift from what ships).
///
/// # The control
///
/// A `'released'` row is seeded alongside, and the migration must not
/// touch it. Without it the packument assertion would be satisfied by a
/// 404 from an empty package, and "not advertised" would be a verdict
/// about the fixture rather than about the held versions.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_legacy_row_written_before_the_backfill_is_held_by_it() {
    let Some((pool, admin, db_name)) = pre_backfill_pool().await else {
        return;
    };
    let repository_id = Uuid::new_v4();
    seed_repository_row(&pool, repository_id).await;

    // One version per legacy spelling — 1.0.1 / 1.0.2 / 1.0.3 — plus the
    // control at 9.9.9.
    let legacy: Vec<(&str, String)> = UNCLASSIFIABLE_SPELLINGS
        .iter()
        .enumerate()
        .map(|(i, raw)| (*raw, format!("1.0.{}", i + 1)))
        .collect();
    for (raw, version) in &legacy {
        seed_artifact_version_row(&pool, repository_id, raw, version).await;
    }
    seed_artifact_version_row(&pool, repository_id, "released", CONTROL_VERSION).await;

    // Pre-condition: the rows really are in the pre-migration state this
    // test is about. Without this the partial migration could have
    // quietly included the backfill and every assertion below would pass
    // for the wrong reason.
    for (raw, version) in &legacy {
        assert_eq!(
            stored_status(&pool, version).await.as_deref(),
            Some(*raw),
            "the fixture must hold {raw:?} BEFORE the backfill runs"
        );
    }

    run_backfill_migration(&pool).await;

    // --- the column ---------------------------------------------------
    for (raw, version) in &legacy {
        assert_eq!(
            stored_status(&pool, version).await.as_deref(),
            Some("quarantined"),
            "{raw:?} must become the held state, not a permissive one"
        );
        assert!(
            stored_window_anchor(&pool, version).await.is_some(),
            "the hold for {raw:?} must carry a window anchor — the release \
             sweep's candidacy query filters `quarantine_window_start IS NOT \
             NULL`, so without one the artifact is held with no exit but an \
             admin override"
        );
    }
    assert_eq!(
        stored_status(&pool, CONTROL_VERSION).await.as_deref(),
        Some("released"),
        "control: the backfill must touch only the three legacy spellings"
    );

    // --- the shared per-version status read ---------------------------
    let (ctx, _mocks) = harness(&pool, repository_id).await;
    let mut statuses = ctx
        .artifact_use_case
        .package_version_status(repository_id, PACKAGE)
        .await
        .expect("every row reads back after the backfill");
    // Sorted by version — unique per row, so this is a total order and
    // the comparison does not depend on the adapter's row order.
    statuses.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected: Vec<(String, QuarantineStatus)> = legacy
        .iter()
        .map(|(_, v)| (v.clone(), QuarantineStatus::Quarantined))
        .collect();
    expected.push((CONTROL_VERSION.to_string(), QuarantineStatus::Released));
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        statuses, expected,
        "a backfilled row classifies as Quarantined — held. `None` was the \
         classification the fail-closed decode exists to deny it"
    );

    // --- real downloads ------------------------------------------------
    for (raw, version) in &legacy {
        let (status, body) = get(&ctx, &download_uri_for(version)).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a backfilled {raw:?} row must not download"
        );
        assert_ne!(
            body.as_bytes(),
            TARBALL,
            "a backfilled {raw:?} row must not serve its content"
        );
    }
    let (status, body) = get(&ctx, &download_uri_for(CONTROL_VERSION)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: the released row must still download after the backfill, \
         otherwise the refusals above prove nothing. Body: {body}"
    );
    assert_eq!(
        body.as_bytes(),
        TARBALL,
        "control: the download must serve the seeded content"
    );

    // --- a real index response ----------------------------------------
    //
    // Asserted against the parsed document rather than the raw body: a
    // held version legitimately appears in the packument's `hort.held`
    // transparency block (the operator-facing "why is this missing"
    // surface), which is the opposite of being advertised. What must be
    // true is that it is absent from `versions{}` and from `dist-tags`,
    // the two places a client resolves from, and that no tarball URL
    // points at it.
    let (status, body) = get(&ctx, &packument_uri()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the packument answers now that every row classifies — what has to \
         be true is which versions it carries. Body: {body}"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&body).expect("the packument is JSON; got {body}");
    let served = doc["versions"]
        .as_object()
        .expect("the packument carries a versions object");
    assert!(
        served.contains_key(CONTROL_VERSION),
        "control: the released version must be advertised; got {body}"
    );
    assert_eq!(
        doc["dist-tags"]["latest"].as_str(),
        Some(CONTROL_VERSION),
        "control: latest must resolve to the served version; got {body}"
    );
    for (raw, version) in &legacy {
        assert!(
            !served.contains_key(version.as_str()),
            "a backfilled {raw:?} row must not be advertised at {version}; got {body}"
        );
        assert!(
            !body.contains(&tarball_filename(version)),
            "a backfilled {raw:?} row must not have a tarball URL anywhere in \
             the document; got {body}"
        );
        // The other half of the same claim: the document does not merely
        // omit the version, it reports it as held. An omission alone
        // would also be produced by a fixture that never wrote the row.
        let held = doc["hort"]["held"]
            .as_array()
            .expect("the packument carries hort.held");
        assert!(
            held.iter().any(|e| e["version"].as_str() == Some(version)
                && e["status"].as_str() == Some("quarantined")),
            "the backfilled {raw:?} row must be reported held at {version}; got {body}"
        );
    }

    drop_temp_db(&admin, &db_name, pool).await;
}

/// The raw `quarantine_status` cell for the fixture's `version` row.
async fn stored_status(pool: &PgPool, version: &str) -> Option<String> {
    sqlx::query_scalar("SELECT quarantine_status FROM public.artifacts WHERE version = $1")
        .bind(version)
        .fetch_one(pool)
        .await
        .expect("read the status cell back")
}

/// The raw `quarantine_window_start` cell for the fixture's `version` row.
async fn stored_window_anchor(
    pool: &PgPool,
    version: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT quarantine_window_start FROM public.artifacts WHERE version = $1")
        .bind(version)
        .fetch_one(pool)
        .await
        .expect("read the window anchor back")
}

/// A one-liner that keeps the fixture honest: the `Repository` type the
/// mock port is seeded with is the npm hosted shape the routes need. A
/// drift here (format, type, index mode) would make the control cases
/// above fail for a reason that has nothing to do with the decode, and
/// the message would not say so.
#[test]
fn the_repository_fixture_is_an_npm_hosted_released_only_repo() {
    let mut repo: Repository = hort_app::use_cases::test_support::sample_repository();
    repo.format = RepositoryFormat::Npm;
    repo.repo_type = RepositoryType::Hosted;
    repo.index_mode = IndexMode::ReleasedOnly;
    assert_eq!(repo.format, RepositoryFormat::Npm);
    assert_eq!(repo.repo_type, RepositoryType::Hosted);
    assert_eq!(repo.index_mode, IndexMode::ReleasedOnly);
}
