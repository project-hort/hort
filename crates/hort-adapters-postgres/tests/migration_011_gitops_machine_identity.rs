//! `011_gitops_machine_identity.sql` migration tests (ADR 0018).
//!
//! Asserts the schema invariants the migration ships with:
//!
//! 1. `oidc_issuers` table — UNIQUE name, default 1h refresh, default
//!    `{RS256}` allowed algorithms, lookup index on `issuer_url`.
//! 2. `service_accounts` table — UNIQUE name, FK on `users(id)` with
//!    `ON DELETE RESTRICT` (decision (1) in the migration header).
//! 3. `service_account_federated_identities` table — FK CASCADE on
//!    SA delete, UNIQUE(service_account_id, position), lookup index
//!    on `issuer_name`.
//! 4. `service_account_fallback_rotations` table — PK on
//!    `service_account_id` (1:1), CHECK on `format`, CHECK on
//!    `validity >= 2 * rotation_interval` (load-bearing — the test
//!    arc rejects validity < 2 × rotation, accepts validity == 2 ×
//!    rotation, and accepts validity > 2 × rotation).
//! 5. Round-trip an `OidcIssuer` row through the mapper.
//! 6. Round-trip a `ServiceAccount` + two `FederatedIdentity` rows +
//!    one `FallbackRotation` row, asserting `position`-ordered
//!    federated-identity reconstruction.
//!
//! Tests follow the convention in `migration_010_rescan_and_advisory.rs`
//! and `api_tokens_migration.rs`: require `DATABASE_URL`; if
//! unset, every test early-returns so dev environments without a
//! database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test migration_011_gitops_machine_identity
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use hort_adapters_postgres::mappers::{
    FallbackRotationRow, FederatedIdentityRow, OidcIssuerRow, ServiceAccountRow,
};
use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
use hort_domain::entities::service_account::{
    FallbackRotation, FederatedIdentity, SecretFormat, ServiceAccount,
};
use sqlx::PgPool;
use uuid::Uuid;

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

/// Insert a minimal users row and return the id. Mirrors the seed
/// pattern from `api_tokens_migration.rs::create_test_user`.
async fn seed_user(pool: &PgPool, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active, \
         is_service_account) \
         VALUES ($1, $2, $3, 'local', true, true)",
    )
    .bind(id)
    .bind(format!("{prefix}_{}", id.simple()))
    .bind(format!("{prefix}_{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed test user");
    id
}

// ---------------------------------------------------------------------------
// Test 1 — oidc_issuers table exists with the right shape, defaults,
// and lookup index.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_011_creates_oidc_issuers_with_defaults() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                        WHERE table_schema = 'public' AND table_name = 'oidc_issuers')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe oidc_issuers existence");
    assert!(table_exists, "oidc_issuers table must exist after 011");

    // INSERT with column defaults exercised — only `name`, `issuer_url`,
    // and `audiences` are supplied; the rest fall back to the migration's
    // defaults.
    let name = format!("mig011-issuer-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO public.oidc_issuers (name, issuer_url, audiences) \
         VALUES ($1, $2, ARRAY['hort-server']::text[])",
    )
    .bind(&name)
    .bind("https://issuer.example.test")
    .execute(&pool)
    .await
    .expect("INSERT oidc_issuer with column defaults");

    // Round-trip via the row mapper.
    let row: OidcIssuerRow = sqlx::query_as(
        "SELECT id, name, issuer_url, audiences, jwks_refresh_interval, allowed_algorithms, \
                require_jti, created_at, updated_at \
         FROM public.oidc_issuers WHERE name = $1",
    )
    .bind(&name)
    .fetch_one(&pool)
    .await
    .expect("read back oidc_issuer row");
    let issuer = OidcIssuer::try_from(row).expect("mapper accepts default-shaped row");
    assert_eq!(issuer.name, name);
    assert_eq!(issuer.audiences, vec!["hort-server"]);
    assert_eq!(
        issuer.jwks_refresh_interval,
        Duration::from_secs(3600),
        "INTERVAL '1 hour' default must map to 1h"
    );
    assert_eq!(
        issuer.allowed_algorithms,
        vec![JwtAlg::Rs256],
        "ARRAY['RS256'] default must map to [RS256]"
    );
    // `require_jti BOOLEAN NOT NULL DEFAULT TRUE`: a row inserted without
    // the column must come back `true` — the secure default is enforced
    // at the DB level so a row that omits the field cannot weaken it.
    assert!(
        issuer.require_jti,
        "require_jti column default must be TRUE"
    );

    // UNIQUE name — re-INSERT with the same name must reject.
    let err = sqlx::query(
        "INSERT INTO public.oidc_issuers (name, issuer_url, audiences) \
         VALUES ($1, $2, ARRAY['hort-server']::text[])",
    )
    .bind(&name)
    .bind("https://issuer.example.test")
    .execute(&pool)
    .await
    .expect_err("duplicate oidc_issuers.name must violate UNIQUE");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23505",
        "expected SQLSTATE 23505 (unique_violation), got {code}: {err}"
    );

    // Lookup index on issuer_url exists.
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'oidc_issuers' \
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .expect("probe oidc_issuers indexes");
    assert!(
        indexes.iter().any(|i| i == "idx_oidc_issuers_issuer_url"),
        "expected idx_oidc_issuers_issuer_url; saw {indexes:?}"
    );

    // Cleanup.
    let _ = sqlx::query("DELETE FROM public.oidc_issuers WHERE name = $1")
        .bind(&name)
        .execute(&pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 2 — service_accounts FK ON DELETE RESTRICT.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_011_service_account_user_delete_restricts() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let user_id = seed_user(&pool, "mig011_sa_user").await;
    let sa_name = format!("mig011-sa-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO public.service_accounts \
            (name, backing_user_id, role, repositories) \
         VALUES ($1, $2, 'developer', ARRAY['pypi-internal']::text[])",
    )
    .bind(&sa_name)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("INSERT service_account row");

    // Deleting the backing user while the SA still references it
    // must be rejected by RESTRICT (decision (1) in the migration).
    let err = sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect_err("DELETE on referenced user must violate FK RESTRICT");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23503",
        "expected SQLSTATE 23503 (foreign_key_violation), got {code}: {err}"
    );

    // Drop the SA first, then the user — clean teardown.
    sqlx::query("DELETE FROM public.service_accounts WHERE name = $1")
        .bind(&sa_name)
        .execute(&pool)
        .await
        .expect("teardown SA");
    sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("teardown user");
}

// ---------------------------------------------------------------------------
// Test 3 — federated_identities CASCADE on SA delete, position unique.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_011_federated_identities_cascade_and_unique_position() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let user_id = seed_user(&pool, "mig011_fi_user").await;
    let sa_id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.service_accounts \
            (name, backing_user_id, role, repositories) \
         VALUES ($1, $2, 'developer', ARRAY['pypi-internal']::text[]) \
         RETURNING id",
    )
    .bind(format!("mig011-fi-{}", Uuid::new_v4().simple()))
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("INSERT SA returning id");

    sqlx::query(
        "INSERT INTO public.service_account_federated_identities \
            (service_account_id, issuer_name, claims, position) \
         VALUES ($1, 'github-actions', '{\"repo\":\"a/b\"}'::jsonb, 0), \
                ($1, 'github-actions', '{\"repo\":\"c/d\"}'::jsonb, 1)",
    )
    .bind(sa_id)
    .execute(&pool)
    .await
    .expect("INSERT two federated identity rows");

    // Duplicate (service_account_id, position) must reject with the UNIQUE
    // violation. Claims must be a non-empty object: the CHECK constraint
    // chk_federated_claims_non_empty_object (ADR 0018) is evaluated before
    // the UNIQUE conflict, so an empty '{}' here would surface 23514
    // instead of the 23505 this test asserts.
    let err = sqlx::query(
        "INSERT INTO public.service_account_federated_identities \
            (service_account_id, issuer_name, claims, position) \
         VALUES ($1, 'github-actions', '{\"repo\":\"a/b\"}'::jsonb, 0)",
    )
    .bind(sa_id)
    .execute(&pool)
    .await
    .expect_err("duplicate (sa_id, position) must violate UNIQUE");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(code, "23505", "expected SQLSTATE 23505; got {code}: {err}");

    // issuer_name lookup index exists.
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = 'public' \
           AND tablename = 'service_account_federated_identities'",
    )
    .fetch_all(&pool)
    .await
    .expect("probe federated_identities indexes");
    assert!(
        indexes
            .iter()
            .any(|i| i == "idx_service_account_federated_identities_issuer_name"),
        "expected idx_service_account_federated_identities_issuer_name; saw {indexes:?}"
    );

    // CASCADE — deleting the SA must drop the federated identity rows.
    let count_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.service_account_federated_identities \
         WHERE service_account_id = $1",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("count federated identities before delete");
    assert_eq!(count_before, 2);

    sqlx::query("DELETE FROM public.service_accounts WHERE id = $1")
        .bind(sa_id)
        .execute(&pool)
        .await
        .expect("delete SA");
    let count_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.service_account_federated_identities \
         WHERE service_account_id = $1",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("count federated identities after delete");
    assert_eq!(
        count_after, 0,
        "ON DELETE CASCADE must drop federated identity rows"
    );

    // Teardown user.
    sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("teardown user");
}

// ---------------------------------------------------------------------------
// Test 4 — fallback_rotations format CHECK + validity CHECK + CASCADE.
// ---------------------------------------------------------------------------

/// Helper — INSERT a fallback rotation row directly. Returns the
/// sqlx::Error from the failed INSERT for negative tests, or `()` on
/// success.
async fn insert_fallback_rotation(
    pool: &PgPool,
    sa_id: Uuid,
    format: &str,
    rotation_secs: i64,
    validity_secs: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.service_account_fallback_rotations \
            (service_account_id, target_namespace, target_name, format, \
             rotation_interval, validity) \
         VALUES ($1, 'ci-system', 'hort-token', $2, \
                 ($3::text || ' seconds')::interval, \
                 ($4::text || ' seconds')::interval)",
    )
    .bind(sa_id)
    .bind(format)
    .bind(rotation_secs.to_string())
    .bind(validity_secs.to_string())
    .execute(pool)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn migration_011_fallback_rotation_check_constraints() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let user_id = seed_user(&pool, "mig011_fr_user").await;
    let sa_id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.service_accounts \
            (name, backing_user_id, role, repositories) \
         VALUES ($1, $2, 'developer', ARRAY['pypi-internal']::text[]) \
         RETURNING id",
    )
    .bind(format!("mig011-fr-{}", Uuid::new_v4().simple()))
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("INSERT SA returning id");

    // -- format CHECK ----------------------------------------------------

    let err = insert_fallback_rotation(&pool, sa_id, "yaml", 3600, 86_400)
        .await
        .expect_err("format='yaml' must violate CHECK constraint");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected SQLSTATE 23514 (check_violation) for bad format; got {code}: {err}"
    );

    // -- validity < 2 * rotation_interval CHECK (load-bearing) -----------

    // 3 < 2 * 2 — must reject.
    let err = insert_fallback_rotation(&pool, sa_id, "opaque", 7200, 10_800)
        .await
        .expect_err("validity < 2 * rotation_interval must violate CHECK");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected SQLSTATE 23514 for short validity; got {code}: {err}"
    );

    // -- validity == 2 * rotation_interval is accepted -------------------

    insert_fallback_rotation(&pool, sa_id, "opaque", 3600, 7200)
        .await
        .expect("validity == 2 * rotation_interval must be accepted (boundary)");

    // Re-insert with different SA to keep the boundary tests independent
    // — the row above already occupies the PRIMARY KEY slot for this SA.
    sqlx::query(
        "DELETE FROM public.service_account_fallback_rotations \
                 WHERE service_account_id = $1",
    )
    .bind(sa_id)
    .execute(&pool)
    .await
    .expect("clear fallback rotation slot");

    // -- validity == 2 * rotation_interval + 1s is accepted --------------

    insert_fallback_rotation(&pool, sa_id, "opaque", 3600, 7201)
        .await
        .expect("validity slightly above 2 * rotation_interval must be accepted");

    sqlx::query(
        "DELETE FROM public.service_account_fallback_rotations \
                 WHERE service_account_id = $1",
    )
    .bind(sa_id)
    .execute(&pool)
    .await
    .expect("clear fallback rotation slot");

    // -- dockerconfigjson format accepted --------------------------------

    insert_fallback_rotation(&pool, sa_id, "dockerconfigjson", 3600, 86_400)
        .await
        .expect("dockerconfigjson must be accepted");

    // -- CASCADE on SA delete --------------------------------------------

    sqlx::query("DELETE FROM public.service_accounts WHERE id = $1")
        .bind(sa_id)
        .execute(&pool)
        .await
        .expect("delete SA");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.service_account_fallback_rotations \
         WHERE service_account_id = $1",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("count fallback rotations after SA delete");
    assert_eq!(count, 0, "CASCADE must drop fallback rotation row");

    sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("teardown user");
}

// ---------------------------------------------------------------------------
// Test 5 — full round-trip through every new mapper.
//
// Insert one SA + 2 federated identities + 1 fallback rotation, read
// each row back through the corresponding `try_from` mapper, and
// reconstruct the full `ServiceAccount` aggregate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_011_service_account_aggregate_round_trip() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let user_id = seed_user(&pool, "mig011_rt_user").await;
    let sa_name = format!("mig011-rt-{}", Uuid::new_v4().simple());
    let sa_id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.service_accounts \
            (name, backing_user_id, role, repositories) \
         VALUES ($1, $2, 'developer', \
                 ARRAY['pypi-internal','npm-internal']::text[]) \
         RETURNING id",
    )
    .bind(&sa_name)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("INSERT SA returning id");

    // Two federated identities in reverse-position order to verify the
    // mapper preserves declared order, not insertion order.
    sqlx::query(
        "INSERT INTO public.service_account_federated_identities \
            (service_account_id, issuer_name, claims, position) \
         VALUES ($1, 'github-actions', \
                 '{\"repository\":\"my-org/my-repo\",\"environment\":\"production\"}'::jsonb, \
                 1), \
                ($1, 'gitlab-ci', \
                 '{\"project_path\":\"my-org/my-project\"}'::jsonb, \
                 0)",
    )
    .bind(sa_id)
    .execute(&pool)
    .await
    .expect("INSERT two federated identities");

    sqlx::query(
        "INSERT INTO public.service_account_fallback_rotations \
            (service_account_id, target_namespace, target_name, format, \
             rotation_interval, validity) \
         VALUES ($1, 'ci-system', 'ci-hort-token', 'dockerconfigjson', \
                 INTERVAL '6 hours', INTERVAL '24 hours')",
    )
    .bind(sa_id)
    .execute(&pool)
    .await
    .expect("INSERT fallback rotation");

    // -- Read SA row through ServiceAccountRow → ServiceAccount ----------

    let sa_row: ServiceAccountRow = sqlx::query_as(
        "SELECT id, name, backing_user_id, role, repositories, created_at, updated_at \
         FROM public.service_accounts WHERE id = $1",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("read SA row");
    let mut sa: ServiceAccount = sa_row.into();
    assert_eq!(sa.name, sa_name);
    assert_eq!(sa.role, "developer");
    assert_eq!(sa.repositories.len(), 2);
    // Sub-aggregates start empty — composed below.
    assert!(sa.federated_identities.is_empty());
    assert!(sa.fallback_rotation.is_none());

    // -- Read federated identities ordered by position -------------------

    let fi_rows: Vec<FederatedIdentityRow> = sqlx::query_as(
        "SELECT id, service_account_id, issuer_name, claims, position \
         FROM public.service_account_federated_identities \
         WHERE service_account_id = $1 ORDER BY position",
    )
    .bind(sa_id)
    .fetch_all(&pool)
    .await
    .expect("read federated identities");
    assert_eq!(fi_rows.len(), 2);
    // After ORDER BY position, [0] must be the gitlab one (position=0),
    // [1] must be the github one (position=1).
    let fis: Vec<FederatedIdentity> = fi_rows
        .into_iter()
        .map(FederatedIdentity::try_from)
        .collect::<Result<Vec<_>, _>>()
        .expect("federated identity mapper must accept seeded rows");
    assert_eq!(fis[0].issuer_name, "gitlab-ci");
    assert_eq!(fis[1].issuer_name, "github-actions");
    assert_eq!(
        fis[0].claims.get("project_path").map(String::as_str),
        Some("my-org/my-project")
    );
    assert_eq!(
        fis[1].claims.get("repository").map(String::as_str),
        Some("my-org/my-repo")
    );
    sa.federated_identities = fis;

    // -- Read fallback rotation row --------------------------------------

    let fr_row: FallbackRotationRow = sqlx::query_as(
        "SELECT service_account_id, target_namespace, target_name, format, \
                rotation_interval, validity \
         FROM public.service_account_fallback_rotations \
         WHERE service_account_id = $1",
    )
    .bind(sa_id)
    .fetch_one(&pool)
    .await
    .expect("read fallback rotation row");
    let fr = FallbackRotation::try_from(fr_row).expect("mapper accepts seeded row");
    assert_eq!(fr.target_secret_name, "ci-hort-token");
    assert_eq!(fr.target_secret_namespace, "ci-system");
    assert_eq!(fr.format, SecretFormat::Dockerconfigjson);
    assert_eq!(fr.rotation_interval, Duration::from_secs(6 * 3600));
    assert_eq!(fr.validity, Duration::from_secs(24 * 3600));
    sa.fallback_rotation = Some(fr);

    // -- Final composed aggregate sanity ---------------------------------

    assert_eq!(sa.federated_identities.len(), 2);
    assert!(sa.fallback_rotation.is_some());

    // Teardown — CASCADE drops the sub-aggregate rows; user delete
    // is allowed after the SA disappears (RESTRICT clears).
    sqlx::query("DELETE FROM public.service_accounts WHERE id = $1")
        .bind(sa_id)
        .execute(&pool)
        .await
        .expect("teardown SA");
    sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("teardown user");
}

// ---------------------------------------------------------------------------
// Test 6 — OidcIssuer round-trip with non-default values.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_011_oidc_issuer_non_default_round_trip() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let name = format!("mig011-multi-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO public.oidc_issuers \
            (name, issuer_url, audiences, jwks_refresh_interval, allowed_algorithms, \
             require_jti) \
         VALUES ($1, $2, ARRAY['aud-a','aud-b']::text[], \
                 INTERVAL '4 hours', \
                 ARRAY['RS256','ES256','RS512']::text[], \
                 false)",
    )
    .bind(&name)
    .bind("https://multi.example.test/auth/realms/test")
    .execute(&pool)
    .await
    .expect("INSERT non-default oidc_issuer");

    let row: OidcIssuerRow = sqlx::query_as(
        "SELECT id, name, issuer_url, audiences, jwks_refresh_interval, allowed_algorithms, \
                require_jti, created_at, updated_at \
         FROM public.oidc_issuers WHERE name = $1",
    )
    .bind(&name)
    .fetch_one(&pool)
    .await
    .expect("read non-default oidc_issuer");
    let issuer = OidcIssuer::try_from(row).expect("mapper accepts non-default row");
    assert_eq!(issuer.audiences, vec!["aud-a", "aud-b"]);
    assert_eq!(issuer.jwks_refresh_interval, Duration::from_secs(4 * 3600));
    assert_eq!(
        issuer.allowed_algorithms,
        vec![JwtAlg::Rs256, JwtAlg::Es256, JwtAlg::Rs512]
    );
    // An explicit `require_jti=false` (operator opted the issuer into the
    // composite fallback) round-trips through the mapper as `false`; the
    // secure default does not mask a persisted opt-down.
    assert!(
        !issuer.require_jti,
        "explicit require_jti=false must round-trip as false"
    );

    // Cleanup.
    let _ = sqlx::query("DELETE FROM public.oidc_issuers WHERE name = $1")
        .bind(&name)
        .execute(&pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 7 — `oidc_issuers` and `service_accounts` carry no `managed_by`
// column. These aggregates are gitops-only (ADR 0018); pinning the
// absence of `managed_by` makes the design decision observable in the
// test suite.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_011_no_managed_by_column_on_new_tables() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    for table in ["oidc_issuers", "service_accounts"] {
        let has_managed_by: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                            WHERE table_schema = 'public' AND table_name = $1 \
                              AND column_name = 'managed_by')",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("probe managed_by column existence");
        assert!(
            !has_managed_by,
            "{table} is gitops-only (ADR 0018) — no managed_by column",
        );
    }
}
