//! Apply `migrations/*` against a `PgPool` at startup.
//!
//! Migration files are embedded at compile time via `sqlx::migrate!`. The
//! macro resolves the path relative to the crate's `Cargo.toml`, which is
//! why the argument includes `../../migrations`.

use std::collections::BTreeSet;

use anyhow::Context;
use sqlx::migrate::{Migrate, Migrator};
use sqlx::PgPool;

use hort_config::pg_identity::{parse_pg_application_name, parse_version_core};
use hort_config::schema_compat::{
    register_from_rows, schema_rollback_floor, SchemaCompatRegister, SchemaCompatibility,
};

/// Compile-time-embedded migration set. Used by both `run` (the
/// `migrate` subcommand) and `assert_current` (the runtime's
/// schema-version check at boot).
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// This binary's own version — the "how old am I" side of the schema
/// compatibility register comparison, and the runtime fleet fence's
/// "current" side. Both read the same workspace-inherited
/// `CARGO_PKG_VERSION` that `hort_config::pg_identity` stamps into
/// `application_name`, so the two answers cannot drift.
pub const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The versions [`MIGRATOR`] carries — the "embedded" side of
/// [`SchemaCompatibility::evaluate`].
fn embedded_migration_versions() -> BTreeSet<i64> {
    MIGRATOR.iter().map(|m| m.version).collect()
}

/// Run every pending migration against `pool`, then re-assert the
/// `events` table role-hardening invariant (ADR 0009).
///
/// Returns on the first failure — there is no rollback or retry at the
/// binary layer. A deployment orchestrator (systemd, Kubernetes) is the
/// retry surface.
///
/// **Why this gate exists at all on a rollback.** `hort-server.service`
/// and `hort-worker.service` require `hort-migrate.service`, and the
/// chart runs the same subcommand as a `pre-upgrade` hook, so *every*
/// start re-runs this with the installed binary — including a start of
/// the previous release. `SchemaCompatibility` decides whether that is
/// legitimate; see its docs for why a newer schema is a supported state,
/// and for the register rows that decide *how much* newer it may be.
///
/// The verdict drives one knob only, `Migrator::set_ignore_missing`,
/// which suppresses exactly one error (`MigrateError::VersionMissing`)
/// and is therefore enabled only under a `Supported` verdict. It is far
/// weaker than the predicate on its own: it tolerates *any*
/// applied-but-not-embedded version, a mid-sequence gap included, so
/// enabling it unconditionally would discard the divergence check.
/// Checksum validation of the shared prefix is untouched by it
/// (`MigrateError::VersionMismatch` still fires), as is the dirty-state
/// check.
///
/// **Why the register write lives here.** Every migration this binary
/// embeds gets a `schema_compat_register` row carrying the oldest binary
/// version it tolerates, read out of `migrations/CONTRACTIONS.toml` — the
/// manifest this binary embeds precisely because it also embeds that
/// migration. `ON CONFLICT DO NOTHING` makes this write double as a
/// backfill: it covers both what this call just applied and whatever an
/// older binary — one that predates the register, or one that crashed
/// between applying a migration and recording it — already applied before
/// this run. A future binary that does *not* embed the migration cannot
/// derive that answer from anything it ships, so the write has to happen
/// on the way past, under the DDL role, as part of the same operation
/// that applies it. The serve path only ever reads these rows
/// (see [`assert_current`], ADR 0009).
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
    let applied = applied_migration_versions(pool).await?;
    let mut register = read_schema_compat_register(pool).await?;
    let compatibility = SchemaCompatibility::evaluate(
        &applied,
        &embedded_migration_versions(),
        &register,
        BINARY_VERSION,
    );

    // The versions this invocation applies — used below only to report the
    // post-migrate applied set; the register write is scoped separately, to
    // every migration this binary embeds (see `record_schema_compat`).
    let applied_now: BTreeSet<i64> = match compatibility {
        SchemaCompatibility::Divergent(divergence) => {
            anyhow::bail!("refusing to migrate: {}", divergence.refusal());
        }
        SchemaCompatibility::Intolerable(bound) => {
            anyhow::bail!("refusing to migrate: {}", bound.refusal());
        }
        SchemaCompatibility::Supported { newer_applied } => {
            if !newer_applied.is_empty() {
                tracing::warn!(
                    newer_applied = ?newer_applied,
                    "the database is migrated past this binary's embedded set; applying nothing \
                     and verifying the shared prefix only"
                );
            }
            // Deliberately not short-circuited: with every embedded
            // migration already applied, `run` applies nothing and reduces
            // to checksum verification of the shared prefix, which is a
            // property worth keeping.
            //
            // `Migrator` is neither `Clone` nor interior-mutable and
            // `set_ignore_missing` takes `&mut self`, so the tolerance
            // cannot be toggled on the `MIGRATOR` static. Re-expanding the
            // macro here yields an owned migrator over the same embedded
            // directory, carrying every macro-derived setting (table name,
            // schemas, per-migration transaction mode) by construction
            // rather than reconstructing them field by field from
            // semver-exempt struct internals.
            let mut migrator: Migrator = sqlx::migrate!("../../migrations");
            migrator.set_ignore_missing(true);
            migrator
                .run(pool)
                .await
                .context("applying schema migrations")?;
            // Nothing was applied this run — under `Supported` every
            // embedded migration is already applied. The register write
            // below still backfills a row for each of them when an older
            // binary applied them before the register existed.
            BTreeSet::new()
        }
        SchemaCompatibility::Pending { pending, .. } => {
            MIGRATOR
                .run(pool)
                .await
                .context("applying schema migrations")?;
            pending.into_iter().collect()
        }
    };

    register.extend(record_schema_compat(pool, &embedded_migration_versions()).await?);
    let applied_after: BTreeSet<i64> = applied.union(&applied_now).copied().collect();
    tracing::info!(
        tolerates_binaries_from = %schema_rollback_floor(&applied_after, &register),
        "schema compatibility register up to date"
    );

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

/// Classify a `schema_compat_register` read failure.
///
/// `None` means "treat the register as empty and carry on": the table
/// does not exist, so this database was last migrated by a binary from
/// before the register shipped. That is not an error — every applied
/// migration the reading binary does not embed is then unregistered, and
/// [`SchemaCompatibility`]'s fail-closed rule refuses on exactly that.
/// Turning a missing table into a hard error instead would refuse boots
/// the strict gate already handles correctly.
///
/// `Some` is a genuine read failure. `42501` gets the same
/// operator-actionable grant message shape as the `_sqlx_migrations`
/// read, because it has the same cause: the runtime role's least-privilege
/// grant set missed a table.
fn map_register_read_db_err(e: sqlx::Error) -> Option<anyhow::Error> {
    match e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01") => None,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("42501") => {
            Some(anyhow::anyhow!(
                "permission denied reading schema_compat_register — grant SELECT on \
             schema_compat_register to the runtime role (see \
             docs/architecture/how-to/deploy/postgres-roles.md)"
            ))
        }
        other => Some(other.into()),
    }
}

/// Read the schema compatibility register: the oldest binary version each
/// applied migration tolerates, as recorded by the binary that applied it.
///
/// `SELECT` only, on both the migrate and the serve path — this must never
/// become a `CREATE TABLE IF NOT EXISTS` (ADR 0009). A missing table is an
/// empty register; see [`map_register_read_db_err`].
async fn read_schema_compat_register(pool: &PgPool) -> anyhow::Result<SchemaCompatRegister> {
    match sqlx::query_as::<_, (i64, Option<String>)>(
        "SELECT version, min_binary_version FROM schema_compat_register",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => Ok(register_from_rows(rows)),
        Err(e) => match map_register_read_db_err(e) {
            Some(err) => Err(err),
            None => Ok(SchemaCompatRegister::new()),
        },
    }
}

/// Record one register row per migration `embedded` names — every migration
/// this binary embeds, not only whatever this run applied — and return the
/// rows written so the caller can report the resulting rollback floor
/// without a second read.
///
/// A migration named by `migrations/CONTRACTIONS.toml` records that
/// entry's `reference_removed_in`; every other migration removed nothing
/// and records `NULL`.
///
/// `ON CONFLICT DO NOTHING` rather than an upsert: an applied migration is
/// frozen (ADR 0022), so its contraction status can never change and an
/// existing row is already the right answer. That is what makes it safe to
/// pass the whole embedded set on every call rather than just what this run
/// applied: a row already written by the release that shipped the migration
/// is never overwritten, so this both records a fresh migration and
/// backfills a migration an older, pre-register binary already applied. It
/// also makes a re-run after a partial failure safe.
async fn record_schema_compat(
    pool: &PgPool,
    embedded: &BTreeSet<i64>,
) -> anyhow::Result<SchemaCompatRegister> {
    if embedded.is_empty() {
        return Ok(SchemaCompatRegister::new());
    }
    let minimums = crate::contractions::contraction_minimum_binary_versions();
    let versions: Vec<i64> = embedded.iter().copied().collect();
    let recorded: Vec<Option<String>> = versions
        .iter()
        .map(|version| minimums.get(version).cloned())
        .collect();

    sqlx::query(
        "INSERT INTO schema_compat_register (version, min_binary_version) \
         SELECT * FROM UNNEST($1::bigint[], $2::text[]) \
         ON CONFLICT (version) DO NOTHING",
    )
    .bind(&versions)
    .bind(&recorded)
    .execute(pool)
    .await
    .context("recording schema compatibility register rows")?;

    Ok(register_from_rows(versions.into_iter().zip(recorded)))
}

/// Map a `_sqlx_migrations` read failure onto an operator-actionable
/// `anyhow::Error`.
///
/// Extracted (behaviour-preserving) from the `assert_current` `.map_err`
/// closure so every match arm is unit-testable without a live Postgres.
/// The `42501 insufficient_privilege` arm in particular had **no**
/// automated coverage — there is no throwaway-role harness in the
/// workspace, so the contract is pinned by a hand-rolled
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

/// Verify the schema this binary is about to serve against is one it
/// supports, without applying any migrations.
///
/// This is the runtime entrypoint — `cli::serve` calls it instead of
/// `run` so the runtime DSN can be true least-privilege (DML only,
/// no DDL on `public`). The serve path therefore never issues
/// `CREATE TABLE IF NOT EXISTS _sqlx_migrations`, which `sqlx::migrate!`
/// always does on first call even when nothing is pending. See ADR 0009.
///
/// The supported/pending/divergent question is answered by
/// [`SchemaCompatibility`], the same predicate `run` uses — answering it
/// differently in the two places is what would make a binary rollback
/// impossible, since one gate passing while the other refuses leaves the
/// binary unable to serve either way.
///
/// Reading the whole applied set rather than `MAX(version)` is still a
/// plain `SELECT`; this must never become a `CREATE TABLE IF NOT EXISTS`.
/// The same holds for the `schema_compat_register` read that follows it:
/// the register is written on the migrate path only, and a database whose
/// last migrate predates the register simply has no such table — an empty
/// register, which the predicate fails closed on.
pub async fn assert_current(pool: &PgPool) -> anyhow::Result<()> {
    // SELECT only — does NOT create the bookkeeping table.
    // Read failure modes:
    //   - table missing → 42P01 undefined_table        (no migrate Job ran)
    //   - SELECT denied → 42501 insufficient_privilege (grant missing)
    let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations")
        .fetch_all(pool)
        .await
        .map_err(map_assert_current_db_err)?;
    let applied: BTreeSet<i64> = versions.into_iter().collect();
    let embedded = embedded_migration_versions();
    let register = read_schema_compat_register(pool).await?;

    let compatibility =
        SchemaCompatibility::evaluate(&applied, &embedded, &register, BINARY_VERSION);
    // `boot_refusal` is `None` for exactly one verdict — the bootable one —
    // so this is the whole refusal path.
    if let Some(refusal) = compatibility.boot_refusal() {
        anyhow::bail!("{refusal}");
    }

    let applied_version = applied.iter().next_back().copied().unwrap_or(0);
    let expected_version = embedded.iter().next_back().copied().unwrap_or(0);
    // "How far back does this schema tolerate a binary" — the question a
    // rollback decision turns on, answered on the surface that already
    // reports the applied and expected schema versions.
    let tolerates_binaries_from = schema_rollback_floor(&applied, &register);
    match compatibility {
        SchemaCompatibility::Supported { newer_applied } if !newer_applied.is_empty() => {
            // Warn, not info: an operator running a rolled-back binary
            // against a migrated schema needs to see that state without
            // going looking for it.
            tracing::warn!(
                applied_version,
                expected_version,
                newer_applied = ?newer_applied,
                tolerates_binaries_from = %tolerates_binaries_from,
                "serving against a schema newer than this binary's embedded migration set; \
                 supported by the expand/contract discipline (ADR 0030), but the fleet is not \
                 on the schema's own release"
            );
        }
        _ => {
            tracing::info!(
                applied_version,
                expected_version,
                tolerates_binaries_from = %tolerates_binaries_from,
                "schema version OK"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Runtime fleet fence (ADR 0030 amendment (c)).
// ---------------------------------------------------------------------------
//
// `expand_contract_guard` (build-time) stops a contraction from being
// AUTHORED too early. It has no runtime effect: an operator who runs
// `migrate` while a previous release's binaries are still connected can
// still apply a legitimately-deferred contraction into that old fleet's
// face. This fence closes that operational-ordering gap: before applying,
// refuse when a pending migration is a declared contraction AND an older
// (or unversioned, hence unknown) hort-shaped client is still connected.
// Expand-only pending sets are never fenced — routine rolling upgrades
// stay hook-driven and unattended.

/// The result of checking the pending migration set against the connected
/// fleet. `blocked` is only ever `true` when the pending set contains a
/// declared contraction AND an older/unversioned fleet member is present;
/// `offenders` names them for the refusal message (empty when not blocked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetFenceOutcome {
    pub blocked: bool,
    pub offenders: Vec<String>,
}

/// Every migration version recorded in the `_sqlx_migrations` table.
/// Creates the bookkeeping table if it does not exist yet (a fresh
/// database has recorded nothing) — this runs under the `migrate`
/// subcommand's admin DSN, which already has DDL rights to do so. The
/// serve path must not call this: it reads the same set with a bare
/// `SELECT` in `assert_current` instead (ADR 0009).
async fn applied_migration_versions(pool: &PgPool) -> anyhow::Result<BTreeSet<i64>> {
    let mut conn = pool
        .acquire()
        .await
        .context("acquiring a connection to inspect migration state")?;
    conn.ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await
        .context("ensuring the sqlx migrations bookkeeping table exists")?;
    Ok(conn
        .list_applied_migrations(MIGRATOR.table_name.as_ref())
        .await
        .context("listing applied migrations")?
        .into_iter()
        .map(|m| m.version)
        .collect())
}

/// Every migration version in [`MIGRATOR`] that is not yet recorded in the
/// `_sqlx_migrations` table.
pub async fn pending_migration_versions(pool: &PgPool) -> anyhow::Result<BTreeSet<i64>> {
    let applied = applied_migration_versions(pool).await?;
    Ok(embedded_migration_versions()
        .into_iter()
        .filter(|v| !applied.contains(v))
        .collect())
}

/// Every hort-shaped `pg_stat_activity` client connected to the **current
/// database**, other than this connection, whose version is older than
/// `current_version` — fail-closed: a hort-shaped-but-unversioned
/// `application_name` counts as older, and a version that fails to parse
/// counts as older too. Non-hort `application_name`s never appear in the
/// result (they are unrelated).
///
/// Scoping invariant: `pg_stat_activity` is a cluster-wide view, but a
/// pending contraction only changes the schema of the database being
/// migrated — clients connected to a *different* database in the same
/// cluster (a second hort deployment, a co-hosted staging DB, a CI
/// database) cannot be broken by it and must not count as offenders. The
/// query is scoped with `datname = current_database()` accordingly.
///
/// Each entry is a human-readable `"<application_name> x<connection count>"`
/// string, ready to drop into the refusal message.
async fn older_fleet_members(pool: &PgPool, current_version: &str) -> anyhow::Result<Vec<String>> {
    let current = parse_version_core(current_version).ok_or_else(|| {
        anyhow::anyhow!("this binary's own version {current_version:?} failed to parse")
    })?;

    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT application_name, count(*) FROM pg_stat_activity \
         WHERE pid <> pg_backend_pid() AND application_name LIKE 'hort-%' \
         AND datname = current_database() \
         GROUP BY application_name \
         ORDER BY application_name",
    )
    .fetch_all(pool)
    .await
    .context("querying pg_stat_activity for connected hort fleet members")?;

    let mut offenders = Vec::new();
    for (application_name, count) in rows {
        let Some(parsed) = parse_pg_application_name(&application_name) else {
            continue;
        };
        let is_older = match parsed.version.as_deref().and_then(parse_version_core) {
            Some(client_version) => client_version < current,
            // Hort-shaped but unversioned (predates this fence, or a
            // version string this binary cannot parse): fail-closed.
            None => true,
        };
        if is_older {
            offenders.push(format!("{application_name} x{count}"));
        }
    }
    Ok(offenders)
}

/// The fence itself: block only when the pending set contains a declared
/// contraction AND an older/unversioned fleet member is connected. An
/// expand-only pending set (no contraction present) is never fenced,
/// regardless of what else is connected.
pub async fn evaluate_fleet_fence(
    pool: &PgPool,
    current_version: &str,
) -> anyhow::Result<FleetFenceOutcome> {
    let pending = pending_migration_versions(pool).await?;
    let contractions = crate::contractions::contraction_versions();
    let pending_contracts = pending.iter().any(|v| contractions.contains(v));
    if !pending_contracts {
        return Ok(FleetFenceOutcome {
            blocked: false,
            offenders: Vec::new(),
        });
    }

    let offenders = older_fleet_members(pool, current_version).await?;
    Ok(FleetFenceOutcome {
        blocked: !offenders.is_empty(),
        offenders,
    })
}

/// Pure decision: given a fence outcome and the operator's
/// `--allow-running-fleet` override, may `migrate` proceed? `Err` carries
/// the operator-actionable refusal message (naming the offending clients);
/// the override path is `Ok` but the caller is expected to log loudly that
/// it was used — this function only decides, it does not log.
pub fn gate_on_fleet_fence(
    outcome: &FleetFenceOutcome,
    allow_override: bool,
) -> Result<(), String> {
    if !outcome.blocked || allow_override {
        return Ok(());
    }
    Err(format!(
        "refusing to apply: a pending migration is a declared contraction \
         (migrations/CONTRACTIONS.toml) and an older or unversioned hort-shaped client is \
         still connected: {}. Wait for the old fleet to roll off, or pass \
         --allow-running-fleet (HORT_ALLOW_RUNNING_FLEET=true) to override.",
        outcome.offenders.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    //! Pins the operator-actionable error-message contract for the
    //! `_sqlx_migrations` read failure (`assert_current`'s `.map_err`).
    //!
    //! The `42501 insufficient_privilege` branch shipped with zero automated
    //! coverage because stubbing `code() == "42501"` requires a hand-rolled
    //! `sqlx::error::DatabaseError` impl (no throwaway-role harness exists
    //! in the workspace). These tests provide exactly that stub and drive
    //! every match arm of `map_assert_current_db_err`, so a `sqlx` upgrade
    //! or refactor that breaks the mapping fails CI instead of degrading to
    //! an opaque crash.
    //!
    //! Enforcement model: the operator `REVOKE`/grant least-privilege
    //! recipe is the *primary* control; this serve-path read-only-ness is
    //! defense-in-depth (ADR 0009).

    use super::*;
    use std::borrow::Cow;
    use std::error::Error as StdError;
    use std::fmt;

    /// Minimal test-only `sqlx::error::DatabaseError` that reports a
    /// caller-chosen SQLSTATE via `code()`. Without it the `42501` arm
    /// is untestable.
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

    /// `42501 insufficient_privilege` → operator-actionable "grant SELECT on
    /// _sqlx_migrations" message.
    #[test]
    fn maps_42501_to_grant_select_message() {
        let mapped = map_assert_current_db_err(db_err("42501"));
        let msg = format!("{mapped}");
        assert_eq!(
            msg,
            "permission denied reading _sqlx_migrations — grant SELECT on _sqlx_migrations \
             to the runtime role (see docs/architecture/how-to/deploy/postgres-roles.md)",
            "the 42501 operator-actionable message is a regression-guarded contract"
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

    // -----------------------------------------------------------------
    // `map_register_read_db_err` — the register read's failure
    // classification. `42P01` is deliberately NOT an error: a database
    // whose last migrate predates the register has no such table, and
    // the predicate's fail-closed rule covers the rollback that case
    // implies.
    // -----------------------------------------------------------------

    #[test]
    fn register_read_treats_a_missing_table_as_an_empty_register() {
        assert!(
            map_register_read_db_err(db_err("42P01")).is_none(),
            "a missing schema_compat_register must not be a boot failure"
        );
    }

    #[test]
    fn register_read_maps_42501_to_a_grant_select_message() {
        let mapped = map_register_read_db_err(db_err("42501")).expect("42501 must be an error");
        let msg = format!("{mapped}");
        assert_eq!(
            msg,
            "permission denied reading schema_compat_register — grant SELECT on \
             schema_compat_register to the runtime role (see \
             docs/architecture/how-to/deploy/postgres-roles.md)"
        );
    }

    #[test]
    fn register_read_passes_other_db_codes_through() {
        let mapped = map_register_read_db_err(db_err("08006")).expect("08006 must be an error");
        let msg = format!("{mapped}");
        assert!(msg.contains("SQLSTATE 08006"), "{msg}");
        assert!(!msg.contains("schema_compat_register"), "{msg}");
    }

    #[test]
    fn register_read_passes_non_database_errors_through() {
        let mapped =
            map_register_read_db_err(sqlx::Error::RowNotFound).expect("must stay an error");
        assert!(!format!("{mapped}").contains("schema_compat_register"));
    }

    // -----------------------------------------------------------------
    // `gate_on_fleet_fence` — pure, DB-free coverage of the
    // `--allow-running-fleet` override decision.
    // -----------------------------------------------------------------

    #[test]
    fn not_blocked_is_always_ok() {
        let outcome = FleetFenceOutcome {
            blocked: false,
            offenders: Vec::new(),
        };
        assert_eq!(gate_on_fleet_fence(&outcome, false), Ok(()));
        assert_eq!(gate_on_fleet_fence(&outcome, true), Ok(()));
    }

    #[test]
    fn blocked_without_override_refuses_and_names_offenders() {
        let outcome = FleetFenceOutcome {
            blocked: true,
            offenders: vec!["hort-server/0.11.0 x2".to_string()],
        };
        let err = gate_on_fleet_fence(&outcome, false).expect_err("must refuse");
        assert!(err.contains("hort-server/0.11.0 x2"), "message: {err}");
        assert!(err.contains("--allow-running-fleet"), "message: {err}");
    }

    #[test]
    fn blocked_with_override_proceeds() {
        let outcome = FleetFenceOutcome {
            blocked: true,
            offenders: vec!["hort-server/0.11.0 x1".to_string()],
        };
        assert_eq!(gate_on_fleet_fence(&outcome, true), Ok(()));
    }
}
