//! Integration tests for `hort_server::migrate::run`'s post-migrate
//! `harden_migrations_ledger_role` step (least-privilege runtime, ADR
//! 0009).
//!
//! The invariant: the runtime role can **read** `_sqlx_migrations` and
//! cannot write it. ADR 0009 keeps the runtime role *unable* to change
//! the schema rather than merely expected not to, and that was enforced
//! on the DDL axis only — a regression that forged a ledger row,
//! rewrote a checksum or deleted a row would have succeeded in silence,
//! while `assert_current`, the expand/contract version arithmetic and
//! sqlx's own checksum-drift detection all decide on what that table
//! says.
//!
//! These tests require a live PostgreSQL connection (the `DATABASE_URL`
//! user must be a superuser: each test gets a throwaway database, and
//! most of them mint a throwaway login role to observe the runtime
//! role's privileges from a non-superuser vantage point — Postgres
//! answers `has_table_privilege` with `true` for a superuser whatever
//! the grants say). Set `DATABASE_URL` to opt in:
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test migrate_harden_ledger
//! ```
//!
//! When `DATABASE_URL` is unset every test early-returns silently, so
//! the suite stays green in dev environments without a database.
//!
//! What each test covers:
//!
//! 1. `serve_path_boots_without_write_privileges_on_the_ledger` — the
//!    evidence that no runtime path needs the write privileges this
//!    change takes away. Drives the serve path's boot sequence under a
//!    role holding `SELECT` and nothing else on the ledger, and asserts
//!    each write statement is refused with `42501`.
//! 2. `the_migrating_role_still_writes_the_ledger` — the REVOKE targets
//!    `hort_app_role`; the owner keeps its implicit privileges, so
//!    `migrate` still records its rows.
//! 3. `re_hardening_is_idempotent` — running it twice changes no ACL
//!    entry and raises no error.
//! 4. `re_hardening_tolerates_a_database_with_no_ledger` — the
//!    `undefined_table` arm of the `DO` block.
//! 5. `a_revoke_naming_an_absent_role_is_swallowed_as_undefined_object`
//!    — the `undefined_object` arm (the dev-database shape).

#![allow(clippy::expect_used)]

use std::env;

use hort_server::migrate::{self, assert_current, harden_migrations_ledger_role, MIGRATOR};
use serial_test::serial;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A throwaway `hort_test_<epoch>_<uuid>` database with the full
/// migration set applied, via the workspace isolation harness. `None`
/// only when `DATABASE_URL` is unset — a declared-but-unusable database
/// panics inside the harness rather than reporting a silent skip.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// The SQLSTATE a failed statement carried, or `None` for a non-database
/// error. Privilege refusals are asserted on the code, not the message:
/// the message is localised, the code is not.
fn sqlstate(err: &sqlx::Error) -> Option<String> {
    match err {
        sqlx::Error::Database(db) => db.code().map(std::borrow::Cow::into_owned),
        _ => None,
    }
}

/// Put the database into the privilege state the canonical operator
/// recipe produces, and that a later bulk
/// `GRANT … ON ALL TABLES … TO hort_app_role` re-produces: the runtime
/// role holding `SELECT, INSERT, UPDATE, DELETE` on every table in
/// `public` — `_sqlx_migrations` included, because the ledger is created
/// by the DDL role and so is a "future table" for
/// `ALTER DEFAULT PRIVILEGES`.
///
/// Also strips `PUBLIC` from the ledger, which the recipe's
/// `hort_admin`-owned table never carries: without that, a privilege
/// inherited from `template1` would answer for `hort_app_role` and the
/// assertions would be about the wrong grantee.
async fn grant_the_operator_recipe_dml(pool: &PgPool) {
    pool.execute("REVOKE ALL ON _sqlx_migrations FROM PUBLIC")
        .await
        .expect("REVOKE ALL on the ledger from PUBLIC");
    pool.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hort_app_role",
    )
    .await
    .expect("GRANT the operator recipe's table DML to hort_app_role");
    pool.execute("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO hort_app_role")
        .await
        .expect("GRANT the operator recipe's sequence privileges to hort_app_role");
}

/// Does `hort_app_role` itself hold `privilege` on the ledger? Asked
/// about the role by name rather than from a connection, so it reads the
/// grant without a superuser's ACL bypass in the way.
async fn app_role_holds_ledger_privilege(pool: &PgPool, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege('hort_app_role', '_sqlx_migrations', $1)")
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_table_privilege on the ledger")
}

/// Every ACL entry on the ledger, sorted — the whole grant state, so
/// "changes nothing" can be asserted rather than inferred from a handful
/// of privilege probes.
async fn ledger_acl(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT unnest(relacl)::text FROM pg_catalog.pg_class \
         WHERE relname = '_sqlx_migrations' \
         AND relnamespace = 'public'::regnamespace \
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("read the ledger's ACL")
}

/// Mint a throwaway non-superuser login role, make it a member of
/// `hort_app_role`, and connect as it — the vantage point the serving
/// process has.
///
/// No privilege is granted to the role directly: membership in
/// `hort_app_role` is the whole of its authority (which is what makes a
/// REVOKE from that role observable here), and `PUBLIC`'s default
/// `CONNECT` plus `USAGE ON SCHEMA public` carry the rest. Granting
/// either explicitly would also make the role undroppable at teardown,
/// because Postgres refuses `DROP ROLE` for a role still holding
/// privileges on an object.
async fn connect_as_runtime_role(pool: &PgPool) -> (String, PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let role = format!("hort_test_ledger_{suffix}");
    let password = format!("pw_{suffix}");
    // Identifier interpolation is safe here — `suffix` is a hex-only
    // UUID and the prefix is a literal.
    pool.execute(sqlx::AssertSqlSafe(format!(
        "CREATE USER \"{role}\" WITH NOSUPERUSER LOGIN PASSWORD '{password}'"
    )))
    .await
    .expect("CREATE USER (runtime-role member)");
    pool.execute(sqlx::AssertSqlSafe(format!(
        "GRANT hort_app_role TO \"{role}\""
    )))
    .await
    .expect("GRANT hort_app_role to the throwaway member");

    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database");
    let base: PgConnectOptions = env::var("DATABASE_URL")
        .expect("DATABASE_URL is set in this branch")
        .parse()
        .expect("DATABASE_URL parses as Postgres connection options");
    let runtime_pool =
        PgPool::connect_with(base.username(&role).password(&password).database(&database))
            .await
            .expect("connect as the throwaway runtime role");
    (role, runtime_pool)
}

/// Close the runtime pool and drop its role. A leaked cluster-wide role
/// is reported, not raised — it must not mask the real failure.
async fn disconnect_runtime_role(pool: &PgPool, role: &str, runtime_pool: PgPool) {
    runtime_pool.close().await;
    if let Err(e) = pool
        .execute(sqlx::AssertSqlSafe(format!(
            "DROP USER IF EXISTS \"{role}\""
        )))
        .await
    {
        eprintln!("warning: failed to drop throwaway role {role}: {e}");
    }
}

// ---------------------------------------------------------------------------
// 1 — the evidence: the serve path comes up with no write on the ledger
// ---------------------------------------------------------------------------

/// The claim this change rests on is that no runtime path writes
/// `_sqlx_migrations`. A code reading says so — the serve path calls
/// `assert_current`, which is a `SELECT` — but a reading is a property of
/// today's code, not a test. This drives the serve path's boot sequence
/// under a role that *cannot* write the ledger: the schema gate
/// (`migrate::assert_current` — the first statement `cli::serve` issues
/// against the schema) and `PgEventStore::new`, a later step on the same
/// sequence whose own privilege probe runs from this very connection. A
/// future write on either would fail here instead of succeeding in
/// silence.
///
/// The steps in between (the gitops boot apply, storage wiring) need the
/// serve binary's whole environment and are not driven from here; what
/// is pinned is that the boot path's ledger interaction is read-only and
/// that nothing it does next needs the write back.
#[tokio::test]
#[serial(hort_pg_db)]
async fn serve_path_boots_without_write_privileges_on_the_ledger() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    // The isolation harness has already applied the migration set with
    // the bare migrator, so this `run` applies nothing and reduces to
    // the register write plus the two hardening steps — exactly what the
    // chart's migrate Job does on an upgrade that carries no new
    // migration.
    migrate::run(&pool)
        .await
        .expect("migrate::run against an already-migrated database");

    // Operator drift: the bulk GRANT the how-to warns about, which lands
    // write privileges on the ledger just as the recipe's
    // ALTER DEFAULT PRIVILEGES did when the table was created.
    grant_the_operator_recipe_dml(&pool).await;
    assert!(
        app_role_holds_ledger_privilege(&pool, "INSERT").await,
        "test setup: the bulk GRANT must have landed INSERT on hort_app_role"
    );

    // The next migrate run self-heals it, with no operator action.
    migrate::run(&pool)
        .await
        .expect("a second migrate::run re-asserts the ledger hardening");

    let (role, runtime_pool) = connect_as_runtime_role(&pool).await;

    // SELECT stays: it is the read the boot gate is made of.
    let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations")
        .fetch_all(&runtime_pool)
        .await
        .expect("the runtime role must still read the ledger");
    assert!(
        !versions.is_empty(),
        "the runtime role's SELECT must return the applied set, not an empty one"
    );

    // Every write is refused. Asserted as real statements from the
    // runtime connection, not as a privilege lookup: a lookup can agree
    // with the ACL while the statement still goes through (ownership,
    // membership in the owner, a PUBLIC grant).
    for (label, statement) in [
        (
            "INSERT",
            "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES (-1, 'forged', now(), true, decode('00', 'hex'), 0)",
        ),
        (
            "UPDATE",
            "UPDATE _sqlx_migrations SET checksum = decode('00', 'hex')",
        ),
        ("DELETE", "DELETE FROM _sqlx_migrations"),
    ] {
        let err = sqlx::query(statement)
            .execute(&runtime_pool)
            .await
            .expect_err(&format!("{label} on the ledger must be refused"));
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42501"),
            "{label} must be refused as insufficient_privilege, got: {err}"
        );
    }

    // The serve path's schema gate — the whole reason SELECT stays —
    // runs through unchanged under the write-less role.
    assert_current(&runtime_pool)
        .await
        .expect("the serve path's schema gate must run read-only");

    // A later step on the same boot sequence, carried here so the
    // evidence is about a sequence rather than the single call that
    // reads the ledger. Its privilege probe runs from this connection,
    // which is the vantage point the whole test is about.
    hort_adapters_postgres::event_store::PgEventStore::new(runtime_pool.clone())
        .await
        .expect("the event store must construct under the hardened runtime role");

    disconnect_runtime_role(&pool, &role, runtime_pool).await;
}

// ---------------------------------------------------------------------------
// 2 — the migrate path keeps its writes
// ---------------------------------------------------------------------------

/// The REVOKE names `hort_app_role`. The role that created the ledger
/// owns it and keeps the owner's implicit privileges, which cannot be
/// revoked — so `migrate` still records a row per applied migration.
/// Without this the hardening would brick the very command that applies
/// it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_migrating_role_still_writes_the_ledger() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    migrate::run(&pool)
        .await
        .expect("migrate::run against an already-migrated database");
    grant_the_operator_recipe_dml(&pool).await;
    migrate::run(&pool)
        .await
        .expect("a second migrate::run re-asserts the ledger hardening");

    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read the applied version set");
    let embedded: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    assert_eq!(
        applied, embedded,
        "the ledger must still record the whole embedded migration set"
    );

    // A version far above anything the binary embeds, so a failure to
    // clean it up surfaces as a loud divergence refusal rather than a
    // quiet off-by-one. Insert / update / delete in sequence: the three
    // writes `sqlx::migrate!()` itself performs on this table.
    let forged = embedded.iter().copied().max().unwrap_or(0) + 1_000_000;
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
         (version, description, installed_on, success, checksum, execution_time) \
         VALUES ($1, 'owner-write-probe', now(), false, decode('00', 'hex'), 0)",
    )
    .bind(forged)
    .execute(&pool)
    .await
    .expect("the owner must still INSERT ledger rows");
    sqlx::query("UPDATE _sqlx_migrations SET success = true WHERE version = $1")
        .bind(forged)
        .execute(&pool)
        .await
        .expect("the owner must still UPDATE ledger rows");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(forged)
        .execute(&pool)
        .await
        .expect("the owner must still DELETE ledger rows");

    // The migrator's own pass over the hardened table is still clean —
    // it reads the ledger to verify the shared prefix's checksums.
    MIGRATOR
        .run(&pool)
        .await
        .expect("the migrator must still run against a hardened ledger");
}

// ---------------------------------------------------------------------------
// 3 — idempotence
// ---------------------------------------------------------------------------

/// `REVOKE` is silent when the privilege is not held, so the step is
/// safe to re-run on every deploy. Asserted on the table's whole ACL:
/// a second call must leave every entry byte-identical.
#[tokio::test]
#[serial(hort_pg_db)]
async fn re_hardening_is_idempotent() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    migrate::run(&pool)
        .await
        .expect("migrate::run against an already-migrated database");
    grant_the_operator_recipe_dml(&pool).await;

    harden_migrations_ledger_role(&pool)
        .await
        .expect("first re-harden");
    let after_first = ledger_acl(&pool).await;
    harden_migrations_ledger_role(&pool)
        .await
        .expect("second re-harden must not error");
    let after_second = ledger_acl(&pool).await;
    assert_eq!(
        after_first, after_second,
        "a second re-harden must change no ACL entry"
    );

    assert!(
        app_role_holds_ledger_privilege(&pool, "SELECT").await,
        "SELECT must survive: assert_current reads the ledger through it"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        assert!(
            !app_role_holds_ledger_privilege(&pool, privilege).await,
            "{privilege} must be revoked from hort_app_role"
        );
    }
}

/// A bulk `GRANT ALL ON ALL TABLES … TO hort_app_role` is the likelier
/// spelling of the out-of-band fix-up this hardening defends against,
/// and it lands three privileges the canonical recipe never grants:
/// `TRUNCATE`, `REFERENCES` and `TRIGGER`. `TRIGGER` is the one with
/// teeth — it would let the runtime role install a trigger that fires
/// on the DDL role's own writes during a later migration. The revoke
/// must take all of them back and still leave `SELECT`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_bulk_grant_all_is_taken_back_except_select() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    migrate::run(&pool)
        .await
        .expect("migrate::run against an already-migrated database");
    // Strips PUBLIC from the ledger as well as applying the recipe —
    // without that strip an inherited PUBLIC privilege answers
    // `has_table_privilege` and the assertions below would be about the
    // wrong grantee.
    grant_the_operator_recipe_dml(&pool).await;

    // The fix-up, scoped to the ledger: `GRANT ALL ON ALL TABLES` is the
    // shape an operator types, but only the ledger's ACL is this test's
    // subject and widening it to `events` would prove nothing extra.
    pool.execute("GRANT ALL ON _sqlx_migrations TO hort_app_role")
        .await
        .expect("the out-of-band bulk GRANT this hardening exists to undo");

    // Guard the premise: a GRANT that did not land would make every
    // assertion below pass vacuously.
    for privilege in ["TRUNCATE", "REFERENCES", "TRIGGER"] {
        assert!(
            app_role_holds_ledger_privilege(&pool, privilege).await,
            "test setup: GRANT ALL must have landed {privilege} on hort_app_role"
        );
    }

    harden_migrations_ledger_role(&pool)
        .await
        .expect("re-harden after a bulk GRANT ALL");

    for privilege in [
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    ] {
        assert!(
            !app_role_holds_ledger_privilege(&pool, privilege).await,
            "{privilege} must be revoked from hort_app_role after the re-harden"
        );
    }
    assert!(
        app_role_holds_ledger_privilege(&pool, "SELECT").await,
        "SELECT must survive: assert_current reads the ledger through it"
    );
}

// ---------------------------------------------------------------------------
// 4 — the `undefined_table` arm
// ---------------------------------------------------------------------------

/// The `DO` block must not turn a half-provisioned database into a
/// migrate failure. Reached by taking the ledger away, which is the
/// state a call against a never-migrated database is in; the ledger is
/// the only thing this database is still needed for, and the test owns
/// it exclusively.
#[tokio::test]
#[serial(hort_pg_db)]
async fn re_hardening_tolerates_a_database_with_no_ledger() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    pool.execute("DROP TABLE _sqlx_migrations")
        .await
        .expect("drop the ledger to reach the undefined_table arm");

    harden_migrations_ledger_role(&pool)
        .await
        .expect("a missing ledger must be a NOTICE, not a migration failure");
}

// ---------------------------------------------------------------------------
// 5 — the `undefined_object` arm (the dev-database shape)
// ---------------------------------------------------------------------------

/// A dev database that bootstraps without the operator's two-role recipe
/// has no `hort_app_role`, and the step must be a NOTICE there rather
/// than a failure.
///
/// That exact shape cannot be reproduced against a shared cluster:
/// Postgres roles are cluster-wide, `004_events.sql` has created
/// `hort_app_role` for every other database on this server, and those
/// databases hold dependent privileges that refuse `DROP ROLE`. (The
/// same constraint is why `migrate_harden_events.rs` covers one of its
/// two arms.) So the two halves the production arm rests on are pinned
/// directly: that Postgres classifies a REVOKE naming an absent role as
/// `undefined_object`, and that `EXCEPTION WHEN undefined_object`
/// swallows precisely that.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_revoke_naming_an_absent_role_is_swallowed_as_undefined_object() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    // A role name nothing in the cluster can have created.
    let absent = format!("hort_absent_{}", Uuid::new_v4().simple());

    let err = pool
        .execute(sqlx::AssertSqlSafe(format!(
            "REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations FROM \"{absent}\""
        )))
        .await
        .expect_err("a REVOKE naming an absent role must fail");
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some("42704"),
        "the missing-role failure must be undefined_object, got: {err}"
    );

    pool.execute(sqlx::AssertSqlSafe(format!(
        "DO $$ \
         BEGIN \
             REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations FROM \"{absent}\"; \
         EXCEPTION \
             WHEN undefined_object THEN RAISE NOTICE 'skipped'; \
         END $$;"
    )))
    .await
    .expect("the undefined_object arm must swallow a missing runtime role");
}
