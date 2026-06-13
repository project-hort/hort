//! Integration tests for `hort_server::migrate::run`'s post-migrate
//! `harden_events_role` step (least-privilege runtime, ADR 0009).
//!
//! These tests require a live PostgreSQL connection (the runtime user
//! must be a superuser, because each test creates a throwaway database
//! and provisions roles inside it). Set `DATABASE_URL` to opt in:
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test migrate_harden_events
//! ```
//!
//! When `DATABASE_URL` is unset every test early-returns silently
//! (matches the convention in `events_role_hardening` and
//! `migrate_assert_current`) so the suite stays green in dev
//! environments without a database.
//!
//! What each test covers:
//!
//! 1. `migrate_run_self_heals_after_operator_grant_drift` —
//!    apply migrations (events hardened by 081). Simulate operator
//!    drift via `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES … TO hort_app_role`.
//!    Run `migrate::run` again. Assert events ends with INSERT/SELECT
//!    only for an hort_app_role member — i.e. the post-migrate
//!    hardening step re-asserts the invariant.
//! 2. `harden_events_role_tolerates_missing_events_table` —
//!    edge case. Call `harden_events_role` against a fresh temp DB
//!    with no migrations applied; the `events` table doesn't exist;
//!    the `DO ... EXCEPTION` block must swallow `undefined_table`
//!    and return Ok. Proves the EXCEPTION shape works without
//!    requiring a globally-droppable cluster role.

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use hort_server::migrate::{self, harden_events_role, MIGRATOR};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture helpers (shared shape with `migrate_assert_current.rs`)
// ---------------------------------------------------------------------------

async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    PgPool::connect(&url).await.ok()
}

async fn create_temp_db(admin: &PgPool) -> (String, PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let db_name = format!("hort_test_harden_{suffix}");
    let create = format!("CREATE DATABASE \"{db_name}\"");
    admin
        .execute(create.as_str())
        .await
        .expect("CREATE DATABASE (temp)");
    let url = temp_db_url(&db_name).expect("DATABASE_URL parses");
    let pool = PgPool::connect(&url).await.expect("connect to temp DB");
    (db_name, pool)
}

async fn drop_temp_db(admin: &PgPool, db_name: &str, db_pool: PgPool) {
    db_pool.close().await;
    let drop_sql = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
    for attempt in 0..5 {
        match admin.execute(drop_sql.as_str()).await {
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

fn temp_db_url(db_name: &str) -> Option<String> {
    let admin_url = env::var("DATABASE_URL").ok()?;
    let parsed = url::Url::parse(&admin_url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(5432);
    let user = parsed.username();
    let pw = parsed.password()?;
    Some(format!("postgresql://{user}:{pw}@{host}:{port}/{db_name}"))
}

// ---------------------------------------------------------------------------
// Case 1 — re-hardening after operator grant drift
//
// Migrations apply cleanly (`004_events.sql` hardens events). An
// operator then runs a bulk GRANT to give hort_app_role read/write on
// the projection tables; the bulk GRANT lands on `events` too;
// runtime probe would refuse to boot. `harden_events_role` re-asserts
// the hardening on the next migrate run, so the next chart upgrade
// self-heals without operator intervention.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrate_run_self_heals_after_operator_grant_drift() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    // First apply: `004_events.sql` hardens events. Acceptance shape
    // mirrors `events_role_hardening::migration_strips_forbidden_*`.
    migrate::run(&pool)
        .await
        .expect("first migrate::run applies cleanly");

    // Mint a throwaway non-superuser member of hort_app_role to probe
    // privileges from. Postgres' `has_table_privilege(superuser, …)`
    // always returns true, so we cannot ask "did the bulk grant land?"
    // from the admin pool — we have to ask from a non-superuser
    // role's vantage point (the same one PgEventStore::new probes
    // from in production).
    let suffix = Uuid::new_v4().simple().to_string();
    let role = format!("hort_test_app_{suffix}");
    let password = format!("pw_{suffix}");
    pool.execute(
        format!("CREATE USER \"{role}\" WITH NOSUPERUSER LOGIN PASSWORD '{password}'").as_str(),
    )
    .await
    .expect("CREATE USER (probe member)");
    pool.execute(format!("GRANT hort_app_role TO \"{role}\"").as_str())
        .await
        .expect("GRANT hort_app_role to probe member");

    // Simulate operator drift: a bulk GRANT meant to give
    // hort_app_role read/write on the projection tables, accidentally
    // landing on `events` too. After this, hort_app_role holds
    // UPDATE/DELETE on events — the state that breaks the runtime
    // startup probe.
    pool.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hort_app_role",
    )
    .await
    .expect("simulate operator bulk GRANT drift");

    // Confirm the drift took effect (sanity check — if this assertion
    // fails the test setup is wrong, not the production code).
    assert!(
        probe_has_priv(&pool, &role, &password, "UPDATE").await,
        "test setup: bulk GRANT must have landed UPDATE on hort_app_role"
    );

    // Second apply: migrate::run is idempotent on the migration set
    // (no new versions to apply) but the harden_events_role
    // step re-asserts the REVOKE every time.
    migrate::run(&pool)
        .await
        .expect("second migrate::run re-asserts events hardening");

    // After hardening: hort_app_role member has INSERT, SELECT only.
    assert!(
        probe_has_priv(&pool, &role, &password, "SELECT").await,
        "after re-harden: SELECT must remain"
    );
    assert!(
        probe_has_priv(&pool, &role, &password, "INSERT").await,
        "after re-harden: INSERT must remain"
    );
    assert!(
        !probe_has_priv(&pool, &role, &password, "UPDATE").await,
        "after re-harden: UPDATE must be revoked"
    );
    assert!(
        !probe_has_priv(&pool, &role, &password, "DELETE").await,
        "after re-harden: DELETE must be revoked"
    );
    assert!(
        !probe_has_priv(&pool, &role, &password, "TRUNCATE").await,
        "after re-harden: TRUNCATE must be revoked"
    );

    // Teardown.
    pool.execute(format!("DROP USER IF EXISTS \"{role}\"").as_str())
        .await
        .ok();
    drop_temp_db(&admin, &db_name, pool).await;
}

/// Connect as a non-superuser role and ask Postgres what privileges
/// it sees on `events`. Mirrors the shape of `PgEventStore::new`'s
/// startup probe — this is the vantage point the runtime cares about.
async fn probe_has_priv(admin: &PgPool, role: &str, password: &str, priv_name: &str) -> bool {
    let admin_url = env::var("DATABASE_URL").expect("DATABASE_URL set in this branch");
    let parsed = url::Url::parse(&admin_url).expect("DATABASE_URL parses");
    let host = parsed.host_str().expect("host");
    let port = parsed.port().unwrap_or(5432);
    // Pull the temp DB name from the admin pool's current_database()
    // so the URL points at the same temp DB the test is operating in.
    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(admin)
        .await
        .expect("current_database");
    let url = format!("postgresql://{role}:{password}@{host}:{port}/{db_name}");
    let probe_pool = PgPool::connect(&url).await.expect("connect as probe role");
    let granted: bool = sqlx::query_scalar("SELECT has_table_privilege('events', $1)")
        .bind(priv_name)
        .fetch_one(&probe_pool)
        .await
        .expect("has_table_privilege");
    probe_pool.close().await;
    granted
}

// ---------------------------------------------------------------------------
// Case 2 — DO/EXCEPTION shape tolerates missing schema
//
// `harden_events_role` must NOT fail when the schema it targets is
// incomplete — REVOKE on a missing role or table would otherwise
// crash the migrate Job. The DO/EXCEPTION block is the safety net.
//
// We exercise the `undefined_table` branch (events table missing in
// a fresh temp DB with no migrations applied). The structurally
// identical `undefined_object` branch (hort_app_role missing) cannot
// be reproduced in shared CI because Postgres roles are
// cluster-wide: once any prior test in the cluster creates
// hort_app_role (via `004_events.sql`), the role exists permanently and
// other databases hold dependent objects that block DROP. Testing
// one of the two EXCEPTION branches proves the DO block's structure
// catches errors as intended.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn harden_events_role_tolerates_missing_events_table() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    // No migrations applied — `events` does not exist in this
    // temp DB. `harden_events_role` must catch the `undefined_table`
    // SQLSTATE and return Ok rather than propagating the error.
    harden_events_role(&pool)
        .await
        .expect("harden_events_role must tolerate a missing events table");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Migration set bounds
//
// `harden_events_role` is a post-migrate code path, NOT a migration
// file (ADR 0009); the original guard here asserted the migration set
// never shrank (catching a future drift where someone added a new
// migration thinking it replaced the code path). The migration set was
// deliberately squashed into a hand-authored baseline of ~10 files
// (ADR 0022), so the >= 90 floor is no longer applicable.
//
// The new contract: the squashed set is bounded BELOW by the v2 table
// inventory's domain count (one file per logical RBAC / artifact /
// event / policy / etc. domain) and ABOVE by a sanity ceiling that
// catches accidental file proliferation. Both bounds protect against
// the same drift the original test caught — silent shrinkage of the
// canonical set.
// ---------------------------------------------------------------------------

#[test]
fn migrator_set_within_squashed_baseline_bounds() {
    let count = MIGRATOR.iter().count();
    assert!(
        (5..=15).contains(&count),
        "squashed migration set out of bounds: count={count} (expected 5..=15 per the ADR 0022 squashed baseline)"
    );
}
