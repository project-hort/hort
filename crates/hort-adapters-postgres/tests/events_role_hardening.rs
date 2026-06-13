//! `events_immutable` role hardening + startup privilege probe integration tests.
//!
//! These tests require a live PostgreSQL connection (the runtime user
//! must be a superuser, because the test creates throwaway low-privilege
//! roles to exercise both branches of the `PgEventStore::new` privilege
//! probe). Set `DATABASE_URL` to opt in:
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test events_role_hardening
//! ```
//!
//! When `DATABASE_URL` is unset every test early-returns silently
//! (matches the convention in `event_store.rs` and `policy_projection_repo.rs`)
//! so the suite stays green in dev environments without a database.
//!
//! What each test covers (see Item 7 spec — Acceptance §5):
//!
//! 1. `migration_strips_forbidden_privileges_from_hort_app_role` —
//!    after the migration runs, a fresh non-superuser user that's a
//!    member of `hort_app_role` has `INSERT, SELECT` on `events` and
//!    none of `UPDATE, DELETE, TRUNCATE, REFERENCES`. Asserted via
//!    `has_table_privilege` queries from that user's perspective.
//! 2. `migration_attempted_update_raises_permission_denied` — the same
//!    non-superuser user issues `UPDATE events SET ...` and Postgres
//!    raises a permission-denied error (SQLSTATE 42501) BEFORE the
//!    `events_immutable` trigger gets to fire. The role grant is the
//!    first wall, the trigger is the backstop.
//! 3. `startup_probe_refuses_when_app_role_holds_update` — fault
//!    injection: directly grant `UPDATE` to the test user, attempt to
//!    construct `PgEventStore` against that user's pool, assert the
//!    constructor fails with an error mentioning "UPDATE" and the
//!    `hort_audit_events_blocked_total{attempted_op="update",
//!    decision_point="startup_probe"}` metric ticks once.
//! 4. `trigger_caught_emits_metric_on_attempted_update` — bypass the
//!    role check by acting as the table owner (`hort_admin`-equivalent
//!    via the bootstrap superuser); attempt `UPDATE events SET ...`;
//!    assert the trigger fires (SQLSTATE P0001), the adapter classifier
//!    recognises the trigger error, and the metric ticks at
//!    `decision_point="trigger_caught"`.
//! 5. `member_of_hort_app_role_can_append_events_through_adapter` — the
//!    end-to-end check the previous tests didn't make: a `PgEventStore`
//!    bound to a pool whose `current_user` is a `NOSUPERUSER` member of
//!    `hort_app_role` MUST be able to drive `append()` to completion.
//!    Pre-fix the adapter's `SELECT … FOR UPDATE` on `events` requires
//!    UPDATE privilege (Postgres SQL spec) which the hardening REVOKED,
//!    so every fresh-stream append failed with 42501. The other tests
//!    above only probed the table privilege state and the *forbidden*
//!    paths (UPDATE/DELETE) — none exercised the *allowed* INSERT path
//!    through the production adapter, so the FOR UPDATE collision
//!    shipped. This test closes that gap.
//! 6. `startup_probe_skips_for_events_table_owner` — finding F12: a
//!    NOSUPERUSER role that is a member of `hort_admin` (the `events`
//!    table owner) constructs `PgEventStore` successfully. A table
//!    owner's UPDATE/DELETE/TRUNCATE is unrevokable, so the probe skips
//!    rather than refusing — this is the admin-DSN path used by
//!    `issue-svc-token` / `reconcile-groups` / `scrub`.
//!
//! Each test creates a uniquely-named throwaway user inside the test
//! body and DROPs it on exit so concurrent `cargo test` runs don't
//! collide on shared role state. The user is a NOSUPERUSER LOGIN role
//! granted membership in `hort_app_role`.

#![allow(clippy::expect_used)]

use std::env;

use hort_adapters_postgres::event_store::PgEventStore;
use hort_adapters_postgres::metrics::{
    classify_trigger_error_message, AuditBlockedDecisionPoint, AuditBlockedOp,
};
use hort_domain::events::{Actor, ApiActor, ArtifactIngested, DomainEvent, IngestSource, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::types::ContentHash;
use metrics_util::debugging::{DebuggingRecorder, Snapshot};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Connect as the migration superuser; run all migrations cleanly. Returns
/// `None` when `DATABASE_URL` is unset (matches the crate's existing
/// skip-when-no-DB pattern).
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Mint a uniquely-named NOSUPERUSER LOGIN role that is a member of
/// `hort_app_role`, returning the role name and the password. The caller
/// is responsible for `DROP USER`-ing the role at end-of-test.
async fn create_app_user(admin: &PgPool) -> (String, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let user = format!("hort_test_app_{suffix}");
    let password = format!("pw_{suffix}");
    let create = format!("CREATE USER {user} WITH NOSUPERUSER LOGIN PASSWORD '{password}'");
    admin
        .execute(create.as_str())
        .await
        .expect("CREATE USER (test app user)");
    let grant = format!("GRANT hort_app_role TO {user}");
    admin
        .execute(grant.as_str())
        .await
        .expect("GRANT hort_app_role TO test user");
    (user, password)
}

/// Mint a uniquely-named NOSUPERUSER LOGIN role that is a member of
/// `hort_admin` — the role that owns the `events` table. `NOSUPERUSER` is
/// essential: it exercises the finding-F12 table-owner skip distinctly
/// from the superuser skip that precedes it in the probe. This is the
/// admin-DSN identity `issue-svc-token` / `reconcile-groups` / `scrub`
/// connect as. The caller `drop_user`s the role (its `hort_admin`
/// membership is removed automatically by `DROP USER`).
async fn create_admin_user(admin: &PgPool) -> (String, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let user = format!("hort_test_admin_{suffix}");
    let password = format!("pw_{suffix}");
    let create = format!("CREATE USER {user} WITH NOSUPERUSER LOGIN PASSWORD '{password}'");
    admin
        .execute(create.as_str())
        .await
        .expect("CREATE USER (test admin user)");
    let grant = format!("GRANT hort_admin TO {user}");
    admin
        .execute(grant.as_str())
        .await
        .expect("GRANT hort_admin TO test user");
    (user, password)
}

/// Drop a previously-minted test user. Called in test teardown; failures
/// are logged but not propagated (a leaked role is preferable to masking
/// the real test failure).
async fn drop_user(admin: &PgPool, user: &str) {
    let revoke = format!("REVOKE hort_app_role FROM {user}");
    let _ = admin.execute(revoke.as_str()).await;
    let drop = format!("DROP USER IF EXISTS {user}");
    if let Err(e) = admin.execute(drop.as_str()).await {
        eprintln!("warning: failed to drop test user {user}: {e}");
    }
}

/// Build a connection URL for the given test user against the **isolated
/// test database** `admin` is connected to (per-test DB isolation —
/// `test_support::isolated_db_from`). The db name is discovered via
/// `current_database()` on the admin pool, NOT taken from
/// `DATABASE_URL` (that names the base DB, not this test's isolated
/// one). Host/port come from `DATABASE_URL`. `None` if unset/unparseable.
async fn user_url(admin: &PgPool, user: &str, password: &str) -> Option<String> {
    let admin_url = env::var("DATABASE_URL").ok()?;
    let parsed = url::Url::parse(&admin_url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(5432);
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(admin)
        .await
        .ok()?;
    Some(format!("postgresql://{user}:{password}@{host}:{port}/{db}"))
}

/// Re-target `DATABASE_URL` (same host/port/superuser creds) at the
/// isolated database `admin` is connected to. Used where the test needs
/// a fresh superuser pool on the SAME isolated DB (e.g. a pool created
/// inside a separate metrics-capture runtime).
async fn admin_isolated_url(admin: &PgPool) -> String {
    let mut parsed = url::Url::parse(
        &env::var("DATABASE_URL").expect("DATABASE_URL set when admin_pool() returned Some"),
    )
    .expect("DATABASE_URL parses");
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(admin)
        .await
        .expect("current_database()");
    parsed.set_path(&db);
    parsed.to_string()
}

/// Capture metrics emitted inside an async block. Mirrors the helper
/// used in `hort-app::metrics::capture_metrics` but inlined to avoid
/// pulling `hort-app`'s `test-support` feature into this crate's test
/// graph.
///
/// The future is driven on a fresh OS thread that has no inherited
/// tokio context, so `Builder::build()?.block_on(fut)` cannot collide
/// with the `#[tokio::test]` runtime active on the calling thread.
/// An earlier shape that called `Runtime::new().block_on(fut)`
/// directly under `with_local_recorder` produced
/// "Cannot start a runtime from within a runtime" panics under some
/// runner configurations (deterministic in our GitLab CI worker pod,
/// non-reproducible on developer laptops).
/// The `Send + 'static` bounds are needed because `fut` crosses the
/// thread boundary; both call sites use `async move` with owned
/// captures and meet the bounds.
fn capture_metrics_async<Fut>(fut: Fut) -> Snapshot
where
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    std::thread::spawn(move || {
        metrics::with_local_recorder(&recorder, || {
            // `current_thread` is sufficient — the captured future is a
            // single linear sequence of awaits with no `spawn`-style
            // fan-out, and a single-threaded runtime keeps the
            // thread-local recorder install on the same thread the
            // emit calls run on.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(fut);
        });
    })
    .join()
    .expect("metrics-capture thread panicked");
    snapshotter.snapshot()
}

/// Find the (possibly-zero) counter value for `name` filtered by the
/// given `(label, value)` pairs. Returns 0 when no matching series fired.
fn counter_value(snap: Snapshot, name: &str, want: &[(&str, &str)]) -> u64 {
    let entries = snap.into_vec();
    for (key, _, _, value) in &entries {
        if key.key().name() != name {
            continue;
        }
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        let matches = want.iter().all(|(k, v)| labels.get(k).copied() == Some(*v));
        if !matches {
            continue;
        }
        if let metrics_util::debugging::DebugValue::Counter(v) = value {
            return *v;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Acceptance §5 case 1 — migration strips forbidden privileges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_strips_forbidden_privileges_from_hort_app_role() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (user, password) = create_app_user(&admin).await;

    // Connect as the throwaway low-privilege user and ask Postgres what
    // it thinks our privileges on `events` are. `has_table_privilege`
    // with no role argument defaults to `current_user` — which is
    // exactly the role the runtime would connect as in production.
    let user_pool = PgPool::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as test user");

    let select_granted: bool = sqlx::query_scalar("SELECT has_table_privilege('events', 'SELECT')")
        .fetch_one(&user_pool)
        .await
        .expect("probe SELECT");
    let insert_granted: bool = sqlx::query_scalar("SELECT has_table_privilege('events', 'INSERT')")
        .fetch_one(&user_pool)
        .await
        .expect("probe INSERT");
    let update_granted: bool = sqlx::query_scalar("SELECT has_table_privilege('events', 'UPDATE')")
        .fetch_one(&user_pool)
        .await
        .expect("probe UPDATE");
    let delete_granted: bool = sqlx::query_scalar("SELECT has_table_privilege('events', 'DELETE')")
        .fetch_one(&user_pool)
        .await
        .expect("probe DELETE");
    let truncate_granted: bool =
        sqlx::query_scalar("SELECT has_table_privilege('events', 'TRUNCATE')")
            .fetch_one(&user_pool)
            .await
            .expect("probe TRUNCATE");
    let references_granted: bool =
        sqlx::query_scalar("SELECT has_table_privilege('events', 'REFERENCES')")
            .fetch_one(&user_pool)
            .await
            .expect("probe REFERENCES");

    user_pool.close().await;
    drop_user(&admin, &user).await;

    assert!(select_granted, "hort_app_role member must have SELECT");
    assert!(insert_granted, "hort_app_role member must have INSERT");
    assert!(!update_granted, "hort_app_role member must NOT have UPDATE");
    assert!(!delete_granted, "hort_app_role member must NOT have DELETE");
    assert!(
        !truncate_granted,
        "hort_app_role member must NOT have TRUNCATE"
    );
    assert!(
        !references_granted,
        "hort_app_role member must NOT have REFERENCES"
    );
}

// ---------------------------------------------------------------------------
// Acceptance §5 case 1 (continued) — attempted UPDATE is permission-denied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_attempted_update_raises_permission_denied() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (user, password) = create_app_user(&admin).await;

    let mut conn = PgConnection::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as test user");

    // Attempt a no-op UPDATE: even with WHERE 1=0 (no rows matched),
    // Postgres checks the role's UPDATE privilege at the parser/planner
    // stage and raises 42501 before any row is inspected.
    let err = sqlx::query("UPDATE events SET stream_id = stream_id WHERE 1 = 0")
        .execute(&mut conn)
        .await
        .expect_err("UPDATE must be permission-denied for hort_app_role member");

    let _ = conn.close().await;
    drop_user(&admin, &user).await;

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    let code = db_err.code().expect("Postgres error code present");
    assert_eq!(
        code.as_ref(),
        "42501",
        "expected SQLSTATE 42501 (insufficient_privilege), got {code}: {err}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance §5 case 2 — startup probe refuses when relaxed grants exist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn startup_probe_refuses_when_app_role_holds_update() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (user, password) = create_app_user(&admin).await;

    // Fault inject: explicitly GRANT UPDATE on events to the test user.
    // This simulates the H-7 vulnerability the audit identified:
    // a misconfigured deployment where the runtime role retains a
    // mutation privilege the migration intended to revoke.
    let grant = format!("GRANT UPDATE ON events TO {user}");
    admin
        .execute(grant.as_str())
        .await
        .expect("GRANT UPDATE for fault injection");

    let user_url = user_url(&admin, &user, &password)
        .await
        .expect("DATABASE_URL parses");

    // Capture metrics inside the constructor call so the
    // `startup_probe`-decision-point increment lands in the local
    // recorder. The probe runs against `current_user` so the result
    // depends entirely on which user we connected as.
    let snap = capture_metrics_async(async move {
        let pool = PgPool::connect(&user_url)
            .await
            .expect("connect as test user with extra UPDATE grant");
        let result = PgEventStore::new(pool.clone()).await;
        // Constructor MUST refuse — naming the offending privilege.
        let Err(err) = result else {
            panic!("startup probe must refuse but PgEventStore::new returned Ok")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("UPDATE"),
            "error must name the offending privilege; got: {msg}"
        );
        pool.close().await;
    });

    let revoke = format!("REVOKE UPDATE ON events FROM {user}");
    let _ = admin.execute(revoke.as_str()).await;
    drop_user(&admin, &user).await;

    let count = counter_value(
        snap,
        "hort_audit_events_blocked_total",
        &[
            ("attempted_op", AuditBlockedOp::Update.as_str()),
            (
                "decision_point",
                AuditBlockedDecisionPoint::StartupProbe.as_str(),
            ),
        ],
    );
    assert_eq!(
        count, 1,
        "hort_audit_events_blocked_total{{attempted_op=update, \
         decision_point=startup_probe}} must increment exactly once"
    );
}

// ---------------------------------------------------------------------------
// Finding F12 — privilege probe skips for the events-table owner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn startup_probe_skips_for_events_table_owner() {
    let Some(admin) = admin_pool().await else {
        return;
    };

    // A NOSUPERUSER role that is a member of `hort_admin` — the owner of
    // `events`. Without the F12 fix, `PgEventStore::new` refuses here:
    // a table owner implicitly holds UPDATE, and `has_table_privilege`
    // reports it regardless of any REVOKE, so the probe would fail with
    // a forbidden-'UPDATE' error. This reproduces the alpha-test chain
    // (the `svc-token-bootstrap` Job's `issue-svc-token` step).
    let (user, password) = create_admin_user(&admin).await;

    let user_url = user_url(&admin, &user, &password)
        .await
        .expect("DATABASE_URL parses");

    let snap = capture_metrics_async(async move {
        let pool = PgPool::connect(&user_url)
            .await
            .expect("connect as hort_admin-member test user");
        // Constructor MUST succeed — the table-owner skip applies.
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new must succeed for the events-table owner (F12)");
        pool.close().await;
    });

    drop_user(&admin, &user).await;

    // A skipped probe is not a blocked mutation — no metric series fires.
    let count = counter_value(
        snap,
        "hort_audit_events_blocked_total",
        &[(
            "decision_point",
            AuditBlockedDecisionPoint::StartupProbe.as_str(),
        )],
    );
    assert_eq!(
        count, 0,
        "owner skip must not emit hort_audit_events_blocked_total\
         {{decision_point=startup_probe}}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance §5 case 3 — trigger-caught path emits metric
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trigger_caught_emits_metric_on_attempted_update() {
    let Some(admin) = admin_pool().await else {
        return;
    };

    // Seed one event so the UPDATE has a row to target — without a
    // matching row, the trigger never fires (BEFORE UPDATE FOR EACH ROW
    // only runs per-row, and an UPDATE WHERE 1=0 affects zero rows).
    let store = PgEventStore::new(admin.clone())
        .await
        .expect("PgEventStore::new succeeds for the admin pool");
    let artifact_id = Uuid::new_v4();
    let stream = StreamId::artifact(artifact_id);
    let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("static SHA-256");
    let batch = AppendEvents {
        stream_id: stream.clone(),
        expected_version: ExpectedVersion::NoStream,
        events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
            ArtifactIngested {
                artifact_id,
                repository_id: Uuid::new_v4(),
                name: format!("trigger-caught-{}", Uuid::new_v4()),
                version: Some("1.0.0".into()),
                sha256: hash,
                size_bytes: 4,
                source: IngestSource::Direct,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            },
        ))],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
    };
    store.append(batch).await.expect("seed append");

    let stream_id_str = stream.to_string();

    // Bypass-mode UPDATE: act as the bootstrap superuser (which owns
    // the table or bypasses ACL) so the role check passes and the
    // trigger gets a chance to fire. This proves the trigger remains
    // the backstop: even an over-privileged role cannot mutate the
    // row, because the BEFORE trigger raises an exception.
    //
    // Open a fresh pool *inside* the captured future rather than
    // cloning `admin` across the boundary. `capture_metrics_async`
    // drives the future on a separate OS thread with its own tokio
    // runtime; a PgPool's reactor is bound to whichever runtime
    // created it, so a pool created on the test's outer runtime
    // would never see I/O wakeups from the inner runtime and would
    // dead-end at `acquire()` until the 30s timeout. Same DATABASE_URL
    // the outer `admin_pool()` used — same superuser identity.
    let database_url = admin_isolated_url(&admin).await;
    let snap = capture_metrics_async(async move {
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect superuser pool inside metrics-capture runtime");
        let mut conn = pool
            .acquire()
            .await
            .expect("acquire conn for trigger probe");
        let res = sqlx::query("UPDATE events SET event_data = '{}'::jsonb WHERE stream_id = $1")
            .bind(&stream_id_str)
            .execute(&mut *conn)
            .await;
        let err = res.expect_err("trigger must fire and refuse the UPDATE");
        let db_err = err
            .as_database_error()
            .expect("trigger error carries DB-side code");
        let code = db_err.code().expect("trigger error has SQLSTATE");
        assert_eq!(
            code.as_ref(),
            "P0001",
            "expected SQLSTATE P0001 (RAISE EXCEPTION); got {code}: {err}"
        );
        // Sanity: classifier recognises the trigger message.
        let op = classify_trigger_error_message(db_err.message())
            .expect("classifier recognises the trigger message");
        assert_eq!(op, AuditBlockedOp::Update);

        // The adapter's `inspect_audit_block` is the metric trip-wire
        // for any code path that reaches the events table; call it
        // directly here to drive the trigger-caught emission. (In
        // production, every adapter write site that touches `events`
        // routes its sqlx error through the same helper.)
        hort_adapters_postgres::event_store::inspect_audit_block(&err);
    });

    let count = counter_value(
        snap,
        "hort_audit_events_blocked_total",
        &[
            ("attempted_op", AuditBlockedOp::Update.as_str()),
            (
                "decision_point",
                AuditBlockedDecisionPoint::TriggerCaught.as_str(),
            ),
        ],
    );
    assert_eq!(
        count, 1,
        "hort_audit_events_blocked_total{{attempted_op=update, \
         decision_point=trigger_caught}} must increment exactly once"
    );
}

// ---------------------------------------------------------------------------
// Regression test (case 5) — append_with_conn must not require UPDATE
// ---------------------------------------------------------------------------
//
// The hardening REVOKEs UPDATE on `events` from `hort_app_role` for the
// audit-immutability invariant. The append adapter's
// `SELECT stream_position … FOR UPDATE` clause requires UPDATE privilege
// per the Postgres SQL spec — so the two were in collision and every
// fresh-stream append failed with 42501 ("permission denied for table
// events") in production. This test reproduces the failure mode against
// the real adapter and pins the post-fix contract: a `PgEventStore` bound
// to a pool whose `current_user` is a `NOSUPERUSER` member of
// `hort_app_role` can `append()` an `ArtifactIngested` event end-to-end.

#[tokio::test]
async fn member_of_hort_app_role_can_append_events_through_adapter() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (user, password) = create_app_user(&admin).await;

    let user_pool = PgPool::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as hort_app_role member");

    // Constructor's startup probe must pass: hort_app_role member holds
    // exactly the privilege set the probe expects (no UPDATE/DELETE/
    // TRUNCATE). Failures here would mean the hardening regressed the
    // role state — a different bug than the one this test pins.
    let store = PgEventStore::new(user_pool.clone())
        .await
        .expect("PgEventStore::new must succeed for an hort_app_role member");

    // Build a fresh-stream batch — `ExpectedVersion::NoStream` means
    // the SELECT-current-position read finds no rows, but the `FOR
    // UPDATE` clause (pre-fix) would still fail at the
    // privilege-check stage regardless of whether rows match. Using
    // `NoStream` here keeps the test self-contained: no seed events,
    // no cross-test interference on a shared CI database.
    let artifact_id = Uuid::new_v4();
    let stream = StreamId::artifact(artifact_id);
    let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("static SHA-256");
    let batch = AppendEvents {
        stream_id: stream.clone(),
        expected_version: ExpectedVersion::NoStream,
        events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
            ArtifactIngested {
                artifact_id,
                repository_id: Uuid::new_v4(),
                name: format!("hort-app-role-append-{}", Uuid::new_v4()),
                version: Some("1.0.0".into()),
                sha256: hash,
                size_bytes: 4,
                source: IngestSource::Direct,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            },
        ))],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
    };

    let result = store.append(batch).await;

    user_pool.close().await;
    drop_user(&admin, &user).await;

    // The contract: append succeeds. Pre-fix this failed with 42501.
    // We surface the full error chain on failure so a future regression
    // diagnoses itself in one CI run.
    let outcome = result.expect("append must succeed for an hort_app_role member");
    assert_eq!(
        outcome.stream_position, 0,
        "first event in a fresh stream lands at stream_position=0"
    );
    assert_eq!(
        outcome.global_positions.len(),
        1,
        "exactly one event was appended; one global_position must be returned"
    );
}
