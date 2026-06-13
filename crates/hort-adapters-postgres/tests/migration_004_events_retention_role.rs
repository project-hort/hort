//! `004_events.sql` retention-role mechanism tests.
//!
//! These tests pin the decided row-removal mechanism (ADR 0020): a
//! dedicated `hort_retention_role` that is the **only** role permitted to
//! `DELETE` from `events`. The `events_immutable` trigger is **never
//! disabled by app code**; it stays ENABLED at all times and its
//! function:
//!
//! - blocks **UPDATE for every role** (including `hort_retention_role`),
//! - blocks **DELETE for every role except `current_user =
//!   'hort_retention_role'`** — an **exact `current_user` match, NOT a
//!   membership test**. This exact-match is Option B's defining
//!   property: the exemption is maximally narrow, reachable only via an
//!   explicit, transaction-scoped role assumption.
//!
//! Option B consequence (the production pattern these tests pin): a
//! runtime/test connection logs in as a *member* of `hort_retention_role`.
//! A bare member `DELETE FROM events` (no role assumption) has
//! `current_user` = the login user, **not** `'hort_retention_role'`, so
//! the trigger still refuses it — that least-privilege property is
//! preserved and explicitly asserted. The sanctioned path is
//! `SET LOCAL ROLE hort_retention_role` inside the seal transaction
//! (`PgEventStore::seal_and_remove`), which makes `current_user` the
//! role for the remainder of that transaction only.
//!
//! Because `hort_retention_role` has `SELECT, DELETE` and **NO INSERT**
//! (`004_events.sql:313-314`), the retention-DSN login user must be a
//! member of BOTH `hort_app_role` (the tombstone `append_with_conn`
//! INSERT) AND `hort_retention_role` (the `SET LOCAL ROLE`'d DELETE). This
//! is an operator-provisioning fact (design §10.2); the both-membership
//! helper below documents it.
//!
//! This is the single most security-sensitive edit in B9 (co-reviewed
//! with the F-2 owner), so the contract is pinned with explicit tests:
//!
//! 1. `hort_app_role_member_cannot_delete_events` — a non-superuser
//!    member of `hort_app_role` (the runtime role) attempting
//!    `DELETE FROM events` is refused. Either the privilege wall
//!    (42501) or the still-enabled trigger (P0001) stops it; both are
//!    fail-safe.
//! 2. `default_role_cannot_delete_events` — a bare non-superuser role
//!    with **no** `hort_app_role`/`hort_retention_role` membership is
//!    likewise refused (defense in depth).
//! 3. `nobody_can_update_events` — UPDATE remains blocked for the
//!    runtime role AND for `hort_retention_role` (the role exemption is
//!    DELETE-only; the audit log is still append-only).
//! 4. `set_role_member_can_delete_events` — the **production pattern**:
//!    a login user that is a member of BOTH `hort_app_role` AND
//!    `hort_retention_role`, in one transaction, after
//!    `SET LOCAL ROLE hort_retention_role`, CAN `DELETE FROM events`. This
//!    is the sanctioned retention-sweep path.
//! 5. `bare_hort_retention_role_member_cannot_delete_without_set_role` —
//!    the **preserved least-privilege invariant**: a member of
//!    `hort_retention_role` running `DELETE FROM events` **without**
//!    `SET ROLE` is STILL refused (`current_user` = the login user ≠
//!    `'hort_retention_role'`). Option B intentionally keeps this
//!    forbidden.
//!
//! Tier-2 (DB) only — every test early-returns when `DATABASE_URL` is
//! unset, matching the convention in `events_role_hardening.rs`. The
//! runtime user must be a superuser so the test can mint throwaway
//! low-privilege roles. Every test carries the crate-wide
//! `#[serial(hort_pg_db)]` key: minting/dropping cluster-global roles
//! (`CREATE ROLE`/`DROP ROLE`), the shared `events` table, and the
//! process-global singleton `StreamId::eventstore_retention()` stream
//! every seal appends to are all global-scope work (an earlier revision
//! wrongly claimed otherwise and omitted the key — that produced a
//! nondeterministic CI failure when a concurrent sibling seal's
//! tombstone landed inside the fail-closed test's before/after window).
//! `serial_test` is process-local, and the `cargo test --tests` CI job
//! runs sibling binaries (e.g. the `event_store.rs` `b9_db_*`/`b15_*`
//! seals) that also append to that same global retention stream — so
//! the two end-to-end seal tests additionally scope every
//! `StreamSealed` assertion to the run's unique `sealed_stream_id`
//! (never a global count or before/after delta), which is race-free
//! regardless of concurrency or accumulated history.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test migration_004_events_retention_role
//! ```

#![allow(clippy::expect_used)]

use std::env;

use hort_adapters_postgres::event_store::PgEventStore;
use hort_domain::events::{system_actor, ArtifactRejected, DomainEvent, RejectionReason, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use serial_test::serial;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture helpers (mirror events_role_hardening.rs)
// ---------------------------------------------------------------------------

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Mint a uniquely-named NOSUPERUSER LOGIN role granted membership in
/// each role in `roles` (or none when empty). The caller `DROP`s it.
///
/// The slice form is what makes the Option-B production pattern
/// testable: the retention-DSN login user needs membership in BOTH
/// `hort_app_role` (the tombstone INSERT) and `hort_retention_role` (the
/// `SET LOCAL ROLE`'d DELETE) — `hort_retention_role` alone has no INSERT
/// (`004_events.sql:314`), so a single-role grant cannot exercise the
/// real seal path. This two-membership requirement is the
/// operator-provisioning contract documented in design §10.2.
async fn create_user(admin: &PgPool, roles: &[&str]) -> (String, String) {
    let suffix = Uuid::new_v4().simple().to_string();
    let user = format!("hort_test_b9_{suffix}");
    let password = format!("pw_{suffix}");
    admin
        .execute(
            format!("CREATE USER {user} WITH NOSUPERUSER LOGIN PASSWORD '{password}'").as_str(),
        )
        .await
        .expect("CREATE USER (test user)");
    for r in roles {
        // Operator-provisioning contract (ADR 0020): `hort_retention_role`
        // membership is NOINHERIT (`WITH INHERIT FALSE`, PG16+). The
        // login user therefore holds NO *ambient* DELETE on `events`, so
        // the `PgEventStore::new` append-only hardening probe
        // (`has_table_privilege(current_user,'events','DELETE')`) still
        // passes; DELETE is exercised ONLY via the transaction-scoped
        // `SET LOCAL ROLE hort_retention_role` in `seal_and_remove`
        // (`SET ROLE` works for a member regardless of INHERIT). Other
        // roles (e.g. `hort_app_role`, for the tombstone INSERT) keep the
        // default INHERIT so that privilege is ambient.
        let grant = if *r == "hort_retention_role" {
            format!("GRANT {r} TO {user} WITH INHERIT FALSE")
        } else {
            format!("GRANT {r} TO {user}")
        };
        admin
            .execute(grant.as_str())
            .await
            .expect("GRANT role TO test user");
    }
    (user, password)
}

/// Drop a previously-minted test user (best-effort teardown).
async fn drop_user(admin: &PgPool, user: &str) {
    let drop = format!("DROP USER IF EXISTS {user}");
    if let Err(e) = admin.execute(drop.as_str()).await {
        eprintln!("warning: failed to drop test user {user}: {e}");
    }
}

/// Connection URL for `user`/`password` against the **isolated test
/// database** `admin` is connected to (per-test DB isolation —
/// `test_support::isolated_db_from`). The db name is discovered via
/// `current_database()` on the admin pool, NOT taken from `DATABASE_URL`
/// (that names the base DB, not this test's isolated one); host/port
/// come from `DATABASE_URL`.
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

/// Seed one event row via the bootstrap superuser so the
/// BEFORE-DELETE/UPDATE FOR-EACH-ROW trigger has a row to fire on.
/// Returns the stream id used. Bypasses the adapter (raw INSERT, all
/// NOT NULL columns bound) so the test is self-contained.
async fn seed_event(admin: &PgPool) -> String {
    let stream_id = format!("artifact-{}", Uuid::new_v4());
    sqlx::query(
        r#"INSERT INTO events
             (event_id, stream_id, stream_category, stream_position,
              event_type, event_version, event_data, correlation_id,
              actor_type, prev_event_hash, event_hash)
           VALUES ($1, $2, 'artifact', 0, 'ArtifactRejected', 1,
                   '{"type":"ArtifactRejected","data":{}}'::jsonb, $3,
                   'system', $4, $5)"#,
    )
    .bind(Uuid::new_v4())
    .bind(&stream_id)
    .bind(Uuid::new_v4())
    .bind([0u8; 32].as_slice())
    .bind([1u8; 32].as_slice())
    .execute(admin)
    .await
    .expect("seed one event row");
    stream_id
}

// ---------------------------------------------------------------------------
// 1. hort_app_role member (the runtime role) cannot DELETE events
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn hort_app_role_member_cannot_delete_events() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let stream_id = seed_event(&admin).await;
    let (user, password) = create_user(&admin, &["hort_app_role"]).await;

    let mut conn = PgConnection::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as hort_app_role member");

    let err = sqlx::query("DELETE FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&mut conn)
        .await
        .expect_err("DELETE must be refused for an hort_app_role member");

    let _ = conn.close().await;
    drop_user(&admin, &user).await;

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    let code = db_err.code().expect("Postgres error code present");
    // Either the privilege wall (42501, REVOKE'd DELETE) or the
    // still-enabled trigger (P0001, RAISE EXCEPTION) stops it. Both are
    // fail-safe and acceptable; the contract is "not deleted".
    assert!(
        code.as_ref() == "42501" || code.as_ref() == "P0001",
        "expected permission-denied (42501) or trigger raise (P0001) \
         for an hort_app_role member DELETE, got {code}: {err}"
    );

    // The row MUST still be there (defense in depth verified end-to-end).
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .fetch_one(&admin)
        .await
        .expect("count surviving rows");
    assert_eq!(
        remaining, 1,
        "hort_app_role member must NOT be able to delete events"
    );
}

// ---------------------------------------------------------------------------
// 2. A bare default role (no membership) cannot DELETE events
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn default_role_cannot_delete_events() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let stream_id = seed_event(&admin).await;
    let (user, password) = create_user(&admin, &[]).await;

    let mut conn = PgConnection::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as bare default role");

    let err = sqlx::query("DELETE FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&mut conn)
        .await
        .expect_err("DELETE must be refused for a bare default role");

    let _ = conn.close().await;
    drop_user(&admin, &user).await;

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    let code = db_err.code().expect("Postgres error code present");
    assert!(
        code.as_ref() == "42501" || code.as_ref() == "P0001",
        "expected permission-denied (42501) or trigger raise (P0001) \
         for a default-role DELETE, got {code}: {err}"
    );

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .fetch_one(&admin)
        .await
        .expect("count surviving rows");
    assert_eq!(
        remaining, 1,
        "a bare default role must NOT be able to delete events"
    );
}

// ---------------------------------------------------------------------------
// 3. Nobody can UPDATE events — the role exemption is DELETE-only
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn nobody_can_update_events() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let stream_id = seed_event(&admin).await;

    // (a) the runtime role (hort_app_role member) cannot UPDATE.
    let (app_user, app_pw) = create_user(&admin, &["hort_app_role"]).await;
    let mut app_conn = PgConnection::connect(
        &user_url(&admin, &app_user, &app_pw)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as hort_app_role member");
    let app_err = sqlx::query("UPDATE events SET event_data = '{}'::jsonb WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&mut app_conn)
        .await
        .expect_err("UPDATE must be refused for an hort_app_role member");
    let _ = app_conn.close().await;
    let app_code = app_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .expect("Postgres error code present");
    assert!(
        app_code.as_ref() == "42501" || app_code.as_ref() == "P0001",
        "hort_app_role member UPDATE must be refused, got {app_code}: {app_err}"
    );
    drop_user(&admin, &app_user).await;

    // (b) hort_retention_role — exempt for DELETE — is STILL blocked for
    //     UPDATE by the (always-enabled) trigger, even after assuming
    //     the role via SET ROLE. This is the key security property: the
    //     audit log is append-only; the retention role may only excise
    //     whole streams, never rewrite. We `SET ROLE` first so this is
    //     the strongest form of the assertion (UPDATE refused even when
    //     `current_user = 'hort_retention_role'`).
    let (ret_user, ret_pw) = create_user(&admin, &["hort_app_role", "hort_retention_role"]).await;
    let mut ret_conn = PgConnection::connect(
        &user_url(&admin, &ret_user, &ret_pw)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as hort_retention_role member");
    sqlx::query("SET ROLE hort_retention_role")
        .execute(&mut ret_conn)
        .await
        .expect("a member may assume hort_retention_role");
    let ret_err = sqlx::query("UPDATE events SET event_data = '{}'::jsonb WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&mut ret_conn)
        .await
        .expect_err("UPDATE must be refused even for hort_retention_role");
    let _ = ret_conn.close().await;
    let ret_code = ret_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .expect("Postgres error code present");
    assert!(
        ret_code.as_ref() == "42501" || ret_code.as_ref() == "P0001",
        "hort_retention_role UPDATE must be refused (exemption is \
         DELETE-only), got {ret_code}: {ret_err}"
    );
    drop_user(&admin, &ret_user).await;

    // Payload untouched.
    let unchanged: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM events
           WHERE stream_id = $1 AND event_data->>'type' = 'ArtifactRejected'"#,
    )
    .bind(&stream_id)
    .fetch_one(&admin)
    .await
    .expect("count unchanged rows");
    assert_eq!(unchanged, 1, "no role may UPDATE (rewrite) an event row");
}

// ---------------------------------------------------------------------------
// 4. The production pattern: a member of BOTH hort_app_role AND
//    hort_retention_role, after `SET LOCAL ROLE hort_retention_role` inside
//    a transaction, CAN DELETE events. This is the sanctioned
//    retention-sweep mechanic `PgEventStore::seal_and_remove` performs.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn set_role_member_can_delete_events() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let stream_id = seed_event(&admin).await;
    // BOTH memberships: the operator-provisioning contract (design
    // §10.2). hort_app_role would carry the tombstone INSERT in the real
    // seal; hort_retention_role is what makes `current_user` the role
    // after SET ROLE so the (unchanged) trigger lets the DELETE through.
    let (user, password) = create_user(&admin, &["hort_app_role", "hort_retention_role"]).await;

    let mut conn = PgConnection::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as both-membership member");

    // Drive the role mechanic directly in one transaction, exactly as
    // `seal_and_remove` does (SET LOCAL ROLE inside the tx, then the
    // DELETE). `SET LOCAL` auto-reverts on COMMIT.
    let mut tx = conn.begin().await.expect("begin tx");
    sqlx::query("SET LOCAL ROLE hort_retention_role")
        .execute(&mut *tx)
        .await
        .expect("a member of hort_retention_role may SET LOCAL ROLE to it");
    let deleted = sqlx::query("DELETE FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&mut *tx)
        .await
        .expect(
            "after SET LOCAL ROLE hort_retention_role, current_user is the \
             role and the unchanged trigger permits the DELETE",
        )
        .rows_affected();
    tx.commit().await.expect("commit the SET-ROLE'd delete");

    let _ = conn.close().await;
    drop_user(&admin, &user).await;

    assert_eq!(
        deleted, 1,
        "the SET-ROLE'd DELETE must remove exactly the seeded row"
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .fetch_one(&admin)
        .await
        .expect("count surviving rows");
    assert_eq!(
        remaining, 0,
        "the sanctioned SET-ROLE'd hort_retention_role DELETE must remove the row"
    );
}

// ---------------------------------------------------------------------------
// 5. The preserved least-privilege invariant: a bare member of
//    hort_retention_role that does NOT SET ROLE is STILL refused. Option B
//    intentionally keeps the trigger exemption an exact `current_user`
//    match, not a membership test.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn bare_hort_retention_role_member_cannot_delete_without_set_role() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let stream_id = seed_event(&admin).await;
    let (user, password) = create_user(&admin, &["hort_retention_role"]).await;

    let mut conn = PgConnection::connect(
        &user_url(&admin, &user, &password)
            .await
            .expect("DATABASE_URL parses"),
    )
    .await
    .expect("connect as hort_retention_role member");

    // No SET ROLE: `current_user` is the login user, NOT
    // 'hort_retention_role'. The (unchanged) trigger function checks an
    // EXACT match, so it raises P0001 here — this is the least-privilege
    // property Option B preserves on purpose.
    let err = sqlx::query("DELETE FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .execute(&mut conn)
        .await
        .expect_err(
            "a bare hort_retention_role member (no SET ROLE) must STILL be \
             refused — the exemption is an exact current_user match",
        );

    let _ = conn.close().await;
    drop_user(&admin, &user).await;

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    let code = db_err.code().expect("Postgres error code present");
    // P0001 = the still-enabled trigger raised (current_user is the
    // login user, not the role). 42501 would also be fail-safe but the
    // role does hold the table DELETE privilege, so the trigger is what
    // refuses here.
    assert!(
        code.as_ref() == "P0001" || code.as_ref() == "42501",
        "expected trigger raise (P0001) for a bare hort_retention_role \
         member DELETE without SET ROLE, got {code}: {err}"
    );

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(&stream_id)
        .fetch_one(&admin)
        .await
        .expect("count surviving rows");
    assert_eq!(
        remaining, 1,
        "a bare hort_retention_role member must NOT delete without SET ROLE"
    );
}

// ---------------------------------------------------------------------------
// 6. End-to-end: drive the real `PgEventStore::delete_stream`
//    (→ `seal_and_remove`) on a connection whose login user has BOTH
//    memberships → the sealed stream's rows are gone AND a StreamSealed
//    tombstone exists on admin-eventstore-retention (SealedGap, not
//    Broken). And on an hort_app_role-only connection (the Q5-unset
//    analog) → the seal returns Err, ZERO rows removed, NO tombstone
//    (fail-closed).
// ---------------------------------------------------------------------------

/// Helper: append one terminal event to a fresh artifact stream via the
/// real adapter (running as the connecting role — both roles include
/// hort_app_role so INSERT is permitted).
async fn seed_stream_via_adapter(store: &PgEventStore) -> (Uuid, StreamId) {
    let artifact_id = Uuid::new_v4();
    let stream = StreamId::artifact(artifact_id);
    store
        .append(AppendEvents {
            stream_id: stream.clone(),
            expected_version: ExpectedVersion::NoStream,
            events: vec![EventToAppend::new(DomainEvent::ArtifactRejected(
                ArtifactRejected {
                    artifact_id,
                    rejected_by: RejectionReason::Scanner,
                    reason: "b9 e2e seal".into(),
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
        })
        .await
        .expect("seed terminal event via adapter");
    (artifact_id, stream)
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn e2e_seal_and_remove_both_memberships_succeeds_and_tombstones() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    // The retention-DSN login user: BOTH memberships, per the §10.2
    // operator-provisioning contract.
    let (user, password) = create_user(&admin, &["hort_app_role", "hort_retention_role"]).await;
    let url = user_url(&admin, &user, &password)
        .await
        .expect("DATABASE_URL parses");
    let pool = PgPool::connect(&url)
        .await
        .expect("connect a small pool as the both-membership retention user");
    let store = PgEventStore::new(pool.clone())
        .await
        .expect("PgEventStore::new (trigger present, no forbidden privs for this role)");

    let (_artifact_id, stream) = seed_stream_via_adapter(&store).await;

    let retention_sid = StreamId::eventstore_retention().to_string();

    // The real chokepoint: tombstone append (as hort_app_role-equiv) then
    // SET LOCAL ROLE hort_retention_role then DELETE, all in one tx.
    store
        .delete_stream(stream.clone())
        .await
        .expect("seal_and_remove must succeed for the both-membership user");

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(stream.to_string())
        .fetch_one(&admin)
        .await
        .expect("count sealed-stream rows");
    assert_eq!(remaining, 0, "the sealed stream's rows must be removed");

    // Scope to THIS run's unique sealed_stream_id. `eventstore_retention()`
    // is a process-global singleton every seal appends to, so a global
    // count / before-after delta races concurrent sibling seals
    // (`#[serial]` is process-local; the `--tests` CI job runs sibling
    // binaries that also append here). Filtering on this run's unique
    // sealed stream is race-free regardless of concurrency/history.
    let tombstones: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM events
           WHERE stream_id = $1 AND event_type = 'StreamSealed'
             AND event_data->'data'->>'sealed_stream_id' = $2"#,
    )
    .bind(&retention_sid)
    .bind(stream.to_string())
    .fetch_one(&admin)
    .await
    .expect("count tombstones for this sealed stream");
    assert_eq!(
        tombstones, 1,
        "exactly one StreamSealed tombstone for this sealed stream \
         (SealedGap, not Broken — the chain is anchored)"
    );
    let edata: serde_json::Value = sqlx::query_scalar(
        r#"SELECT event_data FROM events
           WHERE stream_id = $1 AND event_type = 'StreamSealed'
             AND event_data->'data'->>'sealed_stream_id' = $2
           ORDER BY stream_position DESC LIMIT 1"#,
    )
    .bind(&retention_sid)
    .bind(stream.to_string())
    .fetch_one(&admin)
    .await
    .expect("read this stream's tombstone");
    assert_eq!(edata["data"]["sealed_stream_id"], stream.to_string());

    pool.close().await;
    drop_user(&admin, &user).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn e2e_seal_and_remove_hort_app_role_only_fails_closed_no_rows_no_tombstone() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    // The Q5-unset analog: HORT_RETENTION_DATABASE_URL unset → the
    // hort_app_role pool. hort_app_role is NOT a member of
    // hort_retention_role, so `SET LOCAL ROLE hort_retention_role` raises
    // permission-denied → the seal Errs, tx rolls back: zero rows
    // removed, the staged tombstone rolled back too (no orphan).
    let (user, password) = create_user(&admin, &["hort_app_role"]).await;
    let url = user_url(&admin, &user, &password)
        .await
        .expect("DATABASE_URL parses");
    let pool = PgPool::connect(&url)
        .await
        .expect("connect a small pool as the hort_app_role-only user");
    let store = PgEventStore::new(pool.clone())
        .await
        .expect("PgEventStore::new (hort_app_role has no forbidden privs)");

    let (_artifact_id, stream) = seed_stream_via_adapter(&store).await;

    let retention_sid = StreamId::eventstore_retention().to_string();
    let rows_before: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(stream.to_string())
        .fetch_one(&admin)
        .await
        .expect("count sealed-stream rows before");
    assert_eq!(rows_before, 1, "the seeded stream has its one row");

    // Fail-closed: the SET LOCAL ROLE permission-denied must propagate
    // as Err (caught, not panicked).
    let result = store.delete_stream(stream.clone()).await;
    assert!(
        result.is_err(),
        "hort_app_role-only seal MUST fail-closed (SET LOCAL ROLE \
         hort_retention_role is permission-denied for a non-member)"
    );

    // ZERO rows removed (the sealed stream is fully intact)...
    let rows_after: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
        .bind(stream.to_string())
        .fetch_one(&admin)
        .await
        .expect("count sealed-stream rows after");
    assert_eq!(
        rows_after, 1,
        "fail-closed: NO row removed when the retention role is not assumable"
    );
    // ...and NO orphan tombstone. Scope to THIS run's unique
    // sealed_stream_id: `eventstore_retention()` is a process-global
    // singleton every seal appends to, so a global count / before-after
    // delta races concurrent sibling seals (`#[serial]` is process-local;
    // the `--tests` CI job runs sibling binaries that also append here).
    // Filtering on this run's unique sealed stream is race-free.
    let orphan_tombstones: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM events
           WHERE stream_id = $1 AND event_type = 'StreamSealed'
             AND event_data->'data'->>'sealed_stream_id' = $2"#,
    )
    .bind(&retention_sid)
    .bind(stream.to_string())
    .fetch_one(&admin)
    .await
    .expect("count orphan tombstones for this sealed stream");
    assert_eq!(
        orphan_tombstones, 0,
        "fail-closed: the staged StreamSealed tombstone MUST roll back too \
         (no orphan tombstone for this sealed stream without its deletion)"
    );

    pool.close().await;
    drop_user(&admin, &user).await;
}
