//! Apply `migrations/*` against a `PgPool` at startup.
//!
//! Migration files are embedded at compile time via `sqlx::migrate!`. The
//! macro resolves the path relative to the crate's `Cargo.toml`, which is
//! why the argument includes `../../migrations`.

use anyhow::Context;
use sqlx::migrate::Migrator;
use sqlx::PgPool;

/// Compile-time-embedded migration set. Used by both `run` (the
/// `migrate` subcommand) and `assert_current` (the runtime's
/// schema-version check at boot).
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Run every pending migration against `pool`, then re-assert the
/// `events` table role-hardening invariant (ADR 0009).
///
/// Returns on the first failure — there is no rollback or retry at the
/// binary layer. A deployment orchestrator (systemd, Kubernetes) is the
/// retry surface.
///
/// **Why the post-migrate hardening step.** `004_events.sql`
/// revokes UPDATE/DELETE/TRUNCATE on `events` from `hort_app_role` so
/// the runtime can never bypass the `events_immutable` trigger.
/// That migration runs **once** and is then skipped on every
/// subsequent deploy. An operator (or a
/// reconcile loop, or an out-of-band fix-up) running
/// `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
/// TO hort_app_role` will silently re-grant UPDATE/DELETE on `events`,
/// at which point `PgEventStore::new`'s startup probe refuses to
/// boot the runtime until somebody manually re-revokes.
///
/// `harden_events_role` re-asserts the invariant on every chart
/// upgrade, idempotently and as `hort_admin` (the only role with the
/// privilege to do so). The defense-in-depth rationale matches the
/// `events_immutable` trigger itself: belt-and-braces, two
/// independent mechanisms enforce the same audit invariant.
pub async fn run(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("applying schema migrations")?;
    harden_events_role(pool)
        .await
        .context("re-asserting events role hardening")?;
    Ok(())
}

/// Re-assert that `hort_app_role` holds no mutation privileges on
/// `events`. Idempotent — REVOKE is silent when the privilege is not
/// held; the surrounding `DO` block swallows the two expected
/// "doesn't exist" errors so dev DBs without the role split still
/// migrate cleanly.
///
/// Edge cases handled inline (so a missing role / table is a NOTICE,
/// not a migration failure):
/// - **Role missing** (`undefined_object`, 42704) — dev/test DBs
///   that bootstrap without the operator's two-role recipe. The
///   `events_immutable` trigger is still in force; the runtime probe
///   still skips when current_user is a superuser. Safe to continue.
/// - **Table missing** (`undefined_table`, 42P01) — should never
///   happen after `MIGRATOR.run` succeeds (`004_events.sql` creates
///   `events`), but cheap to defend against to avoid a confusing
///   crash if migration history is ever rewritten.
pub async fn harden_events_role(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        DO $$
        BEGIN
            REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
                ON events FROM hort_app_role;
        EXCEPTION
            WHEN undefined_object THEN
                RAISE NOTICE 'hort_app_role does not exist; \
                              skipping events role re-hardening \
                              (dev DB without two-role split?)';
            WHEN undefined_table THEN
                RAISE NOTICE '_events_ table not found; \
                              skipping events role re-hardening \
                              (migration history mismatch?)';
        END
        $$;
        "#,
    )
    .execute(pool)
    .await
    .context("executing harden_events_role DO block")?;

    tracing::info!("events role hardening re-asserted");
    Ok(())
}

/// Map a `_sqlx_migrations` read failure onto an operator-actionable
/// `anyhow::Error`.
///
/// Extracted (behaviour-preserving) from the `assert_current` `.map_err`
/// closure so every match arm is unit-testable without a live Postgres.
/// The `42501 insufficient_privilege` arm in particular had **no**
/// automated coverage (audit finding F-12) — there is no throwaway-role
/// harness in the workspace, so the contract is pinned by a hand-rolled
/// `sqlx::error::DatabaseError` stub in this module's `tests`.
///
/// **Enforcement model (ADR 0009).** The operator `REVOKE`/grant
/// least-privilege recipe in
/// `docs/architecture/how-to/deploy/postgres-roles.md` is the **primary**
/// enforcement of the runtime/DDL split; this serve-path `SELECT`-only
/// read-only-ness is **defense-in-depth**. The unit tests pin the
/// operator-actionable `42501`/`42P01` message contract so a `sqlx`
/// upgrade or refactor cannot silently regress it into an opaque crash.
fn map_assert_current_db_err(e: sqlx::Error) -> anyhow::Error {
    match e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01") => anyhow::anyhow!(
            "_sqlx_migrations not found — run `hort-server migrate` (or wait for the chart's \
             migrate Job) before starting the runtime"
        ),
        sqlx::Error::Database(db) if db.code().as_deref() == Some("42501") => anyhow::anyhow!(
            "permission denied reading _sqlx_migrations — grant SELECT on _sqlx_migrations \
             to the runtime role (see docs/architecture/how-to/deploy/postgres-roles.md)"
        ),
        other => other.into(),
    }
}

/// Verify the schema version matches what the binary expects, without
/// applying any migrations.
///
/// This is the runtime entrypoint — `cli::serve` calls it instead of
/// `run` so the runtime DSN can be true least-privilege (DML only,
/// no DDL on `public`). The serve path therefore never issues
/// `CREATE TABLE IF NOT EXISTS _sqlx_migrations`, which `sqlx::migrate!`
/// always does on first call even when nothing is pending. See ADR 0009.
pub async fn assert_current(pool: &PgPool) -> anyhow::Result<()> {
    let expected: i64 = MIGRATOR
        .iter()
        .map(|m| m.version)
        .max()
        .expect("migration set is non-empty at compile time");

    // SELECT only — does NOT create the bookkeeping table.
    // Failure modes:
    //   - table missing       → 42P01 undefined_table       (no migrate Job ran)
    //   - SELECT denied       → 42501 insufficient_privilege (grant missing)
    //   - applied < expected  → bail with operator-actionable message
    //   - applied > expected  → bail (binary older than schema; rolling-upgrade misordering)
    let row: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .map_err(map_assert_current_db_err)?;
    let applied = row.unwrap_or(0);

    if applied != expected {
        anyhow::bail!(
            "schema version mismatch: applied={applied}, binary expects={expected}. \
             Run `hort-server migrate` to advance, or roll the binary back to match the schema."
        );
    }

    tracing::info!(
        applied_version = applied,
        expected_version = expected,
        "schema version OK"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Pins the operator-actionable error-message contract for the
    //! `_sqlx_migrations` read failure (`assert_current`'s `.map_err`).
    //!
    //! Audit finding F-12: the `42501 insufficient_privilege` branch
    //! shipped with zero automated coverage because stubbing
    //! `code() == "42501"` requires a hand-rolled `sqlx::error::DatabaseError`
    //! impl (no throwaway-role harness exists in the workspace). These
    //! tests provide exactly that stub and drive every match arm of
    //! `map_assert_current_db_err`, so a `sqlx` upgrade or refactor that
    //! breaks the mapping fails CI instead of degrading to an opaque crash.
    //!
    //! Enforcement model: the operator `REVOKE`/grant least-privilege
    //! recipe is the *primary* control; this serve-path read-only-ness is
    //! defense-in-depth (ADR 0009).

    use super::*;
    use std::borrow::Cow;
    use std::error::Error as StdError;
    use std::fmt;

    /// Minimal test-only `sqlx::error::DatabaseError` that reports a
    /// caller-chosen SQLSTATE via `code()`. This is the F-12
    /// "known-hard part" — without it the `42501` arm is untestable.
    #[derive(Debug)]
    struct StubDbError {
        code: &'static str,
    }

    impl fmt::Display for StubDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "stub db error (SQLSTATE {})", self.code)
        }
    }

    impl StdError for StubDbError {}

    impl sqlx::error::DatabaseError for StubDbError {
        fn message(&self) -> &str {
            "stub db error"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db_err(code: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(StubDbError { code }))
    }

    /// F-12 core: `42501 insufficient_privilege` → operator-actionable
    /// "grant SELECT on _sqlx_migrations" message. This is the branch
    /// the audit flagged as untested.
    #[test]
    fn maps_42501_to_grant_select_message() {
        let mapped = map_assert_current_db_err(db_err("42501"));
        let msg = format!("{mapped}");
        assert_eq!(
            msg,
            "permission denied reading _sqlx_migrations — grant SELECT on _sqlx_migrations \
             to the runtime role (see docs/architecture/how-to/deploy/postgres-roles.md)",
            "the 42501 operator-actionable message is a regressing contract (F-12)"
        );
    }

    /// Sibling arm: `42P01 undefined_table` → "run `hort-server migrate`".
    #[test]
    fn maps_42p01_to_run_migrate_message() {
        let mapped = map_assert_current_db_err(db_err("42P01"));
        let msg = format!("{mapped}");
        assert_eq!(
            msg,
            "_sqlx_migrations not found — run `hort-server migrate` (or wait for the chart's \
             migrate Job) before starting the runtime"
        );
    }

    /// Fallthrough arm: any other DB SQLSTATE is passed through
    /// unchanged (the original `sqlx::Error` Display is preserved).
    #[test]
    fn other_db_code_falls_through_unchanged() {
        let mapped = map_assert_current_db_err(db_err("08006"));
        let msg = format!("{mapped}");
        assert!(
            msg.contains("SQLSTATE 08006"),
            "fallthrough arm must preserve the underlying sqlx error; got: {msg}"
        );
        assert!(
            !msg.contains("_sqlx_migrations"),
            "fallthrough must not synthesise a migration-specific message; got: {msg}"
        );
    }

    /// Fallthrough arm with a non-`Database` `sqlx::Error` variant —
    /// covers the `other => other.into()` path for the protocol/IO
    /// error case (no `Database` payload, so the guards never match).
    #[test]
    fn non_database_error_falls_through_unchanged() {
        let mapped = map_assert_current_db_err(sqlx::Error::RowNotFound);
        let msg = format!("{mapped}");
        assert!(
            !msg.contains("_sqlx_migrations"),
            "non-Database error must pass through, not synthesise a message; got: {msg}"
        );
    }
}
