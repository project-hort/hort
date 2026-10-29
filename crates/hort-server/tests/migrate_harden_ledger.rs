//! Integration tests for `hort_server::migrate::run`'s post-migrate
//! `harden_migration_bookkeeping_role` step (least-privilege runtime,
//! ADR 0009).
//!
//! The invariant: the runtime role can **read** the two
//! migration-bookkeeping tables — the applied-migration ledger
//! `_sqlx_migrations` and the compatibility register
//! `schema_compat_register` — and cannot write either. ADR 0009 keeps
//! the runtime role *unable* to change the schema rather than merely
//! expected not to, and that was enforced on the DDL axis only — a
//! regression that forged a row, rewrote a checksum or deleted a row
//! would have succeeded in silence, while `assert_current`, the
//! expand/contract version arithmetic and sqlx's own checksum-drift
//! detection all decide on what those two tables say.
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
//! 1. `serve_path_boots_without_write_privileges_on_the_bookkeeping_tables`
//!    — the evidence that no runtime path needs the write privileges
//!    this hardening takes away. Drives the serve path's boot sequence
//!    under a role holding `SELECT` and nothing else on either table,
//!    and asserts each write statement is refused with `42501`.
//! 2. `the_migrating_role_still_writes_the_bookkeeping_tables` — the
//!    REVOKE targets `hort_app_role`; the owner keeps its implicit
//!    privileges, so `migrate` still records its ledger and register
//!    rows.
//! 3. `re_hardening_is_idempotent` — running it twice changes no ACL
//!    entry on either table and raises no error.
//! 4. `a_bulk_grant_all_is_taken_back_except_select` — the full write
//!    set, including the three privileges only a `GRANT ALL` lands, is
//!    revoked from both tables and `SELECT` survives on both.
//! 5. `re_hardening_tolerates_a_database_with_no_ledger` and
//!    `..._no_register` — the `undefined_table` arm, per table.
//! 6. `a_missing_register_does_not_undo_the_ledger_revoke` — why the
//!    two REVOKEs are separate `DO` blocks: one block's exception
//!    handler would roll back the other table's revoke.
//! 7. `a_revoke_naming_an_absent_role_is_swallowed_as_undefined_object`
//!    — the `undefined_object` arm (the dev-database shape).

#![allow(clippy::expect_used)]

use std::env;

use hort_server::migrate::{self, assert_current, harden_migration_bookkeeping_role, MIGRATOR};
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

/// The two tables `harden_migration_bookkeeping_role` hardens: the
/// applied-migration ledger and the compatibility register. Both are
/// created by the DDL role and so inherit the operator recipe's write
/// grant, both are read by the boot gates, and neither is written
/// anywhere but the migrate path.
const BOOKKEEPING_TABLES: [&str; 2] = ["_sqlx_migrations", "schema_compat_register"];

/// Put the database into the privilege state the canonical operator
/// recipe produces, and that a later bulk
/// `GRANT … ON ALL TABLES … TO hort_app_role` re-produces: the runtime
/// role holding `SELECT, INSERT, UPDATE, DELETE` on every table in
/// `public` — both bookkeeping tables included, because each is created
/// by the DDL role and so is a "future table" for
/// `ALTER DEFAULT PRIVILEGES`.
///
/// Also strips `PUBLIC` from both of them, which the recipe's
/// `hort_admin`-owned tables never carry: without that, a privilege
/// inherited from `template1` would answer for `hort_app_role` and the
/// assertions would be about the wrong grantee.
async fn grant_the_operator_recipe_dml(pool: &PgPool) {
    for table in BOOKKEEPING_TABLES {
        pool.execute(sqlx::AssertSqlSafe(format!(
            "REVOKE ALL ON {table} FROM PUBLIC"
        )))
        .await
        .expect("REVOKE ALL on a bookkeeping table from PUBLIC");
    }
    pool.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hort_app_role",
    )
    .await
    .expect("GRANT the operator recipe's table DML to hort_app_role");
    pool.execute("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO hort_app_role")
        .await
        .expect("GRANT the operator recipe's sequence privileges to hort_app_role");
}

/// Does `hort_app_role` itself hold `privilege` on `table`? Asked about
/// the role by name rather than from a connection, so it reads the
/// grant without a superuser's ACL bypass in the way.
async fn app_role_holds_privilege(pool: &PgPool, table: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege('hort_app_role', $1::text, $2::text)")
        .bind(table)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_table_privilege on a bookkeeping table")
}

/// Every ACL entry on `table`, sorted — the whole grant state, so
/// "changes nothing" can be asserted rather than inferred from a handful
/// of privilege probes.
async fn table_acl(pool: &PgPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT unnest(relacl)::text FROM pg_catalog.pg_class \
         WHERE relname = $1 \
         AND relnamespace = 'public'::regnamespace \
         ORDER BY 1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("read a bookkeeping table's ACL")
}

/// The post-hardening privilege state, asserted on both bookkeeping
/// tables at once: no write privilege of any kind, `SELECT` intact.
///
/// Shared so that every test that re-asserts the hardening checks the
/// same thing on both tables — a refactor cannot narrow one table's
/// half while widening the other's, because there is only one half.
async fn assert_hardened(pool: &PgPool) {
    for table in BOOKKEEPING_TABLES {
        for privilege in [
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ] {
            assert!(
                !app_role_holds_privilege(pool, table, privilege).await,
                "{privilege} must be revoked from hort_app_role on {table}"
            );
        }
        assert!(
            app_role_holds_privilege(pool, table, "SELECT").await,
            "SELECT must survive on {table}: the boot gate reads it"
        );
    }
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
// 1 — the evidence: the serve path comes up with no write on either table
// ---------------------------------------------------------------------------

/// The claim this change rests on is that no runtime path writes
/// `_sqlx_migrations` or `schema_compat_register`. A code reading says
/// so — the serve path calls `assert_current`, which is two `SELECT`s —
/// but a reading is a property of today's code, not a test. This drives
/// the serve path's boot sequence under a role that *cannot* write
/// either table: the schema gate (`migrate::assert_current` — the first
/// statement `cli::serve` issues against the schema, and the one that
/// reads both) and `PgEventStore::new`, a later step on the same
/// sequence whose own privilege probe runs from this very connection. A
/// future write on either would fail here instead of succeeding in
/// silence.
///
/// The steps in between (the gitops boot apply, storage wiring) need the
/// serve binary's whole environment and are not driven from here; what
/// is pinned is that the boot path's bookkeeping interaction is
/// read-only and that nothing it does next needs the write back.
#[tokio::test]
#[serial(hort_pg_db)]
async fn serve_path_boots_without_write_privileges_on_the_bookkeeping_tables() {
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
    for table in BOOKKEEPING_TABLES {
        assert!(
            app_role_holds_privilege(&pool, table, "INSERT").await,
            "test setup: the bulk GRANT must have landed INSERT on {table}"
        );
    }

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
    let registered: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_compat_register")
        .fetch_all(&runtime_pool)
        .await
        .expect("the runtime role must still read the register");
    assert!(
        !registered.is_empty(),
        "the runtime role's SELECT must return the recorded rows, not an empty set"
    );

    // Every write is refused. Asserted as real statements from the
    // runtime connection, not as a privilege lookup: a lookup can agree
    // with the ACL while the statement still goes through (ownership,
    // membership in the owner, a PUBLIC grant).
    for (label, statement) in [
        (
            "ledger INSERT",
            "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES (-1, 'forged', now(), true, decode('00', 'hex'), 0)",
        ),
        (
            "ledger UPDATE",
            "UPDATE _sqlx_migrations SET checksum = decode('00', 'hex')",
        ),
        ("ledger DELETE", "DELETE FROM _sqlx_migrations"),
        // A forged register row is the register's own version of a
        // forged ledger row: it tells the boot gate that a migration
        // tolerates an older binary than the release that applied it
        // actually allows, which is what would let a binary serve a
        // schema that has already contracted out from under it.
        (
            "register INSERT",
            "INSERT INTO schema_compat_register (version, min_binary_version) \
             VALUES (-1, '0.0.1')",
        ),
        (
            "register UPDATE",
            "UPDATE schema_compat_register SET min_binary_version = '0.0.1'",
        ),
        ("register DELETE", "DELETE FROM schema_compat_register"),
    ] {
        let err = sqlx::query(statement)
            .execute(&runtime_pool)
            .await
            .expect_err(&format!("{label} must be refused"));
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42501"),
            "{label} must be refused as insufficient_privilege, got: {err}"
        );
    }

    // The serve path's schema gate — the whole reason SELECT stays on
    // both tables — runs through unchanged under the write-less role.
    // It reads the ledger and then the register, so a `SELECT` lost on
    // either one fails here.
    assert_current(&runtime_pool)
        .await
        .expect("the serve path's schema gate must run read-only");

    // A later step on the same boot sequence, carried here so the
    // evidence is about a sequence rather than the single call that
    // reads the bookkeeping tables. Its privilege probe runs from this
    // connection, which is the vantage point the whole test is about.
    hort_adapters_postgres::event_store::PgEventStore::new(runtime_pool.clone())
        .await
        .expect("the event store must construct under the hardened runtime role");

    disconnect_runtime_role(&pool, &role, runtime_pool).await;
}

// ---------------------------------------------------------------------------
// 2 — the migrate path keeps its writes
// ---------------------------------------------------------------------------

/// The REVOKE names `hort_app_role`. The role that created the two
/// bookkeeping tables owns them and keeps the owner's implicit
/// privileges, which cannot be revoked — so `migrate` still records a
/// ledger row per applied migration and a register row per embedded
/// one. Without this the hardening would brick the very command that
/// applies it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_migrating_role_still_writes_the_bookkeeping_tables() {
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

    // The register write is the migrate path's other bookkeeping write,
    // and the one `record_schema_compat` performs on every run. Taking a
    // row away and re-running `migrate::run` proves the owner still
    // reaches the register through the hardening — `ON CONFLICT DO
    // NOTHING` makes the backfill idempotent, so the row comes back.
    let registered_before: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM schema_compat_register ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read the register");
    assert_eq!(
        registered_before, embedded,
        "the register must record the whole embedded migration set"
    );
    let dropped = embedded.iter().copied().max().unwrap_or(0);
    sqlx::query("DELETE FROM schema_compat_register WHERE version = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("the owner must still DELETE register rows");
    migrate::run(&pool)
        .await
        .expect("a third migrate::run must re-record the removed register row");
    let registered_after: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM schema_compat_register ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("re-read the register");
    assert_eq!(
        registered_after, embedded,
        "the migrate path must have re-recorded the removed register row"
    );

    // The migrator's own pass over the hardened tables is still clean —
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
/// safe to re-run on every deploy. Asserted on each table's whole ACL:
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

    harden_migration_bookkeeping_role(&pool)
        .await
        .expect("first re-harden");
    let mut after_first = Vec::new();
    for table in BOOKKEEPING_TABLES {
        after_first.push(table_acl(&pool, table).await);
    }
    harden_migration_bookkeeping_role(&pool)
        .await
        .expect("second re-harden must not error");
    for (table, before) in BOOKKEEPING_TABLES.iter().zip(after_first) {
        assert_eq!(
            before,
            table_acl(&pool, table).await,
            "a second re-harden must change no ACL entry on {table}"
        );
    }

    assert_hardened(&pool).await;
}

/// A bulk `GRANT ALL ON ALL TABLES … TO hort_app_role` is the likelier
/// spelling of the out-of-band fix-up this hardening defends against,
/// and it lands three privileges the canonical recipe never grants:
/// `TRUNCATE`, `REFERENCES` and `TRIGGER`. `TRIGGER` is the one with
/// teeth — it would let the runtime role install a trigger that fires
/// on the DDL role's own writes during a later migration. The revoke
/// must take all of them back, on both bookkeeping tables, and still
/// leave `SELECT`.
///
/// Both tables in one test on purpose: the fix-up is a single statement
/// that lands on both, and asserting them together is what rules out a
/// revoke that narrows one table's set while widening the other's.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_bulk_grant_all_is_taken_back_except_select() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    migrate::run(&pool)
        .await
        .expect("migrate::run against an already-migrated database");
    // Strips PUBLIC from both bookkeeping tables as well as applying the
    // recipe — without that strip an inherited PUBLIC privilege answers
    // `has_table_privilege` and the assertions below would be about the
    // wrong grantee.
    grant_the_operator_recipe_dml(&pool).await;

    // The fix-up, scoped to the two bookkeeping tables: `GRANT ALL ON
    // ALL TABLES` is the shape an operator types, but only these two
    // ACLs are this test's subject and widening it to `events` would
    // prove nothing extra.
    for table in BOOKKEEPING_TABLES {
        pool.execute(sqlx::AssertSqlSafe(format!(
            "GRANT ALL ON {table} TO hort_app_role"
        )))
        .await
        .expect("the out-of-band bulk GRANT this hardening exists to undo");

        // Guard the premise: a GRANT that did not land would make every
        // assertion below pass vacuously.
        for privilege in ["TRUNCATE", "REFERENCES", "TRIGGER"] {
            assert!(
                app_role_holds_privilege(&pool, table, privilege).await,
                "test setup: GRANT ALL must have landed {privilege} on {table}"
            );
        }
    }

    harden_migration_bookkeeping_role(&pool)
        .await
        .expect("re-harden after a bulk GRANT ALL");

    assert_hardened(&pool).await;
}

// ---------------------------------------------------------------------------
// 4 — the `undefined_table` arm, per table
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

    harden_migration_bookkeeping_role(&pool)
        .await
        .expect("a missing ledger must be a NOTICE, not a migration failure");
}

/// The register's own `undefined_table` arm, which — unlike the
/// ledger's — is a state a real installation is in: a database whose
/// last migrate predates `025_schema_compat_register` has no such
/// table, and `read_schema_compat_register` already treats that as an
/// empty register rather than an error. The hardening must agree with
/// it instead of refusing the migrate that would create the table.
#[tokio::test]
#[serial(hort_pg_db)]
async fn re_hardening_tolerates_a_database_with_no_register() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    pool.execute("DROP TABLE schema_compat_register")
        .await
        .expect("drop the register to reach the undefined_table arm");

    harden_migration_bookkeeping_role(&pool)
        .await
        .expect("a missing register must be a NOTICE, not a migration failure");
}

/// Why the two REVOKEs live in separate `DO` blocks rather than one.
///
/// A PL/pgSQL block that handles an exception rolls back everything the
/// block did before the exception was raised. With both REVOKEs in one
/// block, a database missing the register — the pre-`025` shape above —
/// would discard the ledger's revoke on its way to the NOTICE, and the
/// hardening that already shipped would silently stop applying to the
/// installations that most need it (the oldest ones). This asserts the
/// ledger is hardened on exactly that database.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_missing_register_does_not_undo_the_ledger_revoke() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    grant_the_operator_recipe_dml(&pool).await;
    assert!(
        app_role_holds_privilege(&pool, "_sqlx_migrations", "INSERT").await,
        "test setup: the bulk GRANT must have landed INSERT on the ledger"
    );

    pool.execute("DROP TABLE schema_compat_register")
        .await
        .expect("drop the register to reach its undefined_table arm");

    harden_migration_bookkeeping_role(&pool)
        .await
        .expect("a missing register must be a NOTICE, not a migration failure");

    for privilege in [
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    ] {
        assert!(
            !app_role_holds_privilege(&pool, "_sqlx_migrations", privilege).await,
            "{privilege} must still be revoked on the ledger when the register is absent"
        );
    }
    assert!(
        app_role_holds_privilege(&pool, "_sqlx_migrations", "SELECT").await,
        "SELECT must survive on the ledger: the boot gate reads it"
    );
}

// ---------------------------------------------------------------------------
// 5 — the `undefined_object` arm (the dev-database shape)
// ---------------------------------------------------------------------------

/// A dev database that bootstraps without the operator's two-role recipe
/// has no `hort_app_role`, and the step must be a NOTICE there rather
/// than a failure — for both bookkeeping tables, since each block
/// carries its own copy of the arm.
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

    for table in BOOKKEEPING_TABLES {
        let err = pool
            .execute(sqlx::AssertSqlSafe(format!(
                "REVOKE INSERT, UPDATE, DELETE ON {table} FROM \"{absent}\""
            )))
            .await
            .expect_err("a REVOKE naming an absent role must fail");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42704"),
            "the missing-role failure must be undefined_object on {table}, got: {err}"
        );

        pool.execute(sqlx::AssertSqlSafe(format!(
            "DO $$ \
             BEGIN \
                 REVOKE INSERT, UPDATE, DELETE ON {table} FROM \"{absent}\"; \
             EXCEPTION \
                 WHEN undefined_object THEN RAISE NOTICE 'skipped'; \
             END $$;"
        )))
        .await
        .expect("the undefined_object arm must swallow a missing runtime role");
    }
}
