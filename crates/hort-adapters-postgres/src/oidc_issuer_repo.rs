//! Postgres implementation of `OidcIssuerRepository` (ADR 0018).
//!
//! CRUD against the `oidc_issuers` table (migration 011). The row
//! shape maps via [`OidcIssuerRow`](crate::mappers::OidcIssuerRow);
//! this module supplies only the SQL surface and the `Duration` →
//! `PgInterval` writer.

use sqlx::postgres::types::PgInterval;
use sqlx::PgPool;
use std::time::Duration;

use hort_domain::entities::oidc_issuer::OidcIssuer;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;

use crate::mappers::OidcIssuerRow;
use crate::{map_sqlx_error, BoxFuture};

/// Column projection used on every read. Mirrors the field order on
/// [`OidcIssuerRow`] so `sqlx::query_as` decodes positionally without
/// FromRow doing column-name lookups.
const SELECT_COLS: &str = "id, name, issuer_url, audiences, jwks_refresh_interval, \
                           allowed_algorithms, require_jti, created_at, updated_at";

pub struct PgOidcIssuerRepository {
    pool: PgPool,
}

impl PgOidcIssuerRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Convert a `std::time::Duration` to a `PgInterval` using the
/// microseconds field. Mirrors the read-side `pg_interval_to_duration`
/// shape — every value written by this adapter round-trips through
/// the mapper without month/day components.
///
/// Values that exceed `i64::MAX` microseconds (~292,000 years)
/// surface as `DomainError::Invariant`. The apply-time validator caps
/// `jwks_refresh_interval` at 24h and rotation intervals at much less,
/// so this branch is defensive.
fn duration_to_pg_interval(d: Duration) -> DomainResult<PgInterval> {
    let micros_u128 = u128::from(d.as_secs())
        .saturating_mul(1_000_000)
        .saturating_add(u128::from(d.subsec_micros()));
    if micros_u128 > i64::MAX as u128 {
        return Err(DomainError::Invariant(
            "duration exceeds PgInterval microseconds capacity".to_string(),
        ));
    }
    Ok(PgInterval {
        months: 0,
        days: 0,
        microseconds: micros_u128 as i64,
    })
}

impl OidcIssuerRepository for PgOidcIssuerRepository {
    fn list(&self) -> BoxFuture<'_, DomainResult<Vec<OidcIssuer>>> {
        Box::pin(async move {
            tracing::debug!(entity = "oidc_issuer", "list");
            let sql = format!("SELECT {SELECT_COLS} FROM oidc_issuers ORDER BY name");
            let rows: Vec<OidcIssuerRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "oidc_issuers list");
                    DomainError::Invariant(format!("oidc_issuers list: {e}"))
                })?;
            rows.into_iter().map(OidcIssuer::try_from).collect()
        })
    }

    fn get_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<OidcIssuer>>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "oidc_issuer", name = %name, "get_by_name");
            let sql = format!("SELECT {SELECT_COLS} FROM oidc_issuers WHERE name = $1 LIMIT 1");
            let row: Option<OidcIssuerRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(&name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::warn!(name = %name, error = %e, "oidc_issuers get_by_name");
                    DomainError::Invariant(format!("oidc_issuers get_by_name: {e}"))
                })?;
            row.map(OidcIssuer::try_from).transpose()
        })
    }

    fn get_by_issuer_url(&self, url: &str) -> BoxFuture<'_, DomainResult<Option<OidcIssuer>>> {
        let url = url.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "oidc_issuer", "get_by_issuer_url");
            let sql =
                format!("SELECT {SELECT_COLS} FROM oidc_issuers WHERE issuer_url = $1 LIMIT 1");
            let row: Option<OidcIssuerRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(&url)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "oidc_issuers get_by_issuer_url");
                    DomainError::Invariant(format!("oidc_issuers get_by_issuer_url: {e}"))
                })?;
            row.map(OidcIssuer::try_from).transpose()
        })
    }
}

// ---------------------------------------------------------------------------
// In-transaction writes — shared with the authority lifecycle adapter
// ---------------------------------------------------------------------------

/// Upsert one issuer row on the caller's executor, keyed on `name`.
///
/// The only writer of this statement: it runs inside the
/// authority-lifecycle transaction that also
/// appends the attesting `OidcIssuerCreated` / `OidcIssuerUpdated`
/// event (`crate::authority_lifecycle::PgAuthorityLifecycle`). An
/// issuer row is a trust anchor (ADR 0018): a serving validator reads
/// the repository at validation time, so the row and its audit event
/// must not be able to land separately.
///
/// Generic over the executor rather than taking `&mut PgConnection`
/// because the two callers legitimately differ: production passes the
/// authority adapter's open transaction, while the statement-level
/// round-trip test in this module passes the pool. A `&mut PgConnection`
/// signature would force that caller to `acquire()` a connection it does
/// not otherwise need — a round-trip and an error path nothing
/// exercises.
pub(crate) async fn upsert_in_tx<'e, E>(exec: E, issuer: &OidcIssuer) -> DomainResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    // Persist the wire form (uppercase RFC 7518) — the row mapper
    // parses through `JwtAlg::from_str`, which requires uppercase.
    let algorithms: Vec<String> = issuer
        .allowed_algorithms
        .iter()
        .map(|a| a.as_str().to_string())
        .collect();
    let interval = duration_to_pg_interval(issuer.jwks_refresh_interval)?;
    tracing::info!(entity = "oidc_issuer", name = %issuer.name, "upsert (gitops apply)");
    sqlx::query(
        r#"INSERT INTO oidc_issuers
               (id, name, issuer_url, audiences,
                jwks_refresh_interval, allowed_algorithms,
                require_jti)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (name) DO UPDATE SET
               issuer_url            = EXCLUDED.issuer_url,
               audiences             = EXCLUDED.audiences,
               jwks_refresh_interval = EXCLUDED.jwks_refresh_interval,
               allowed_algorithms    = EXCLUDED.allowed_algorithms,
               require_jti           = EXCLUDED.require_jti,
               updated_at            = NOW()"#,
    )
    .bind(issuer.id)
    .bind(&issuer.name)
    .bind(&issuer.issuer_url)
    .bind(&issuer.audiences)
    .bind(interval)
    .bind(&algorithms)
    .bind(issuer.require_jti)
    .execute(exec)
    .await
    .map_err(|e| map_sqlx_error(&e, "OidcIssuer", &issuer.name))?;
    Ok(())
}

/// Delete one issuer row by `name` on the caller's executor. Generic
/// for the same reason as [`upsert_in_tx`].
///
/// Deleting a name that no longer exists is a no-op (returns `Ok`): the
/// gitops apply diff is the only caller, and re-applying after a manual
/// `DELETE` must not error.
pub(crate) async fn delete_by_name_in_tx<'e, E>(exec: E, name: &str) -> DomainResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    tracing::info!(entity = "oidc_issuer", name = %name, "delete_by_name (gitops apply)");
    sqlx::query("DELETE FROM oidc_issuers WHERE name = $1")
        .bind(name)
        .execute(exec)
        .await
        .map_err(|e| map_sqlx_error(&e, "OidcIssuer", name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn duration_to_pg_interval_zero() {
        let iv = duration_to_pg_interval(Duration::from_secs(0)).unwrap();
        assert_eq!(iv.months, 0);
        assert_eq!(iv.days, 0);
        assert_eq!(iv.microseconds, 0);
    }

    #[test]
    fn duration_to_pg_interval_one_hour_round_trips() {
        let iv = duration_to_pg_interval(Duration::from_secs(3600)).unwrap();
        assert_eq!(iv.microseconds, 3_600_000_000);
        assert_eq!(iv.months, 0);
        assert_eq!(iv.days, 0);
    }

    #[test]
    fn duration_to_pg_interval_subsec_micros_preserved() {
        let iv = duration_to_pg_interval(Duration::new(1, 500_000_000)).unwrap();
        // 1s + 500ms = 1_500_000 micros.
        assert_eq!(iv.microseconds, 1_500_000);
    }

    #[test]
    fn duration_to_pg_interval_rejects_overflow() {
        // u64::MAX seconds exceeds i64::MAX micros — the apply
        // validator caps at 24h so this branch is defensive.
        let huge = Duration::from_secs(u64::MAX);
        let err = duration_to_pg_interval(huge).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -- DB-backed round-trip (skipped when DATABASE_URL unset) ------------

    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    fn sample_issuer(name: &str) -> OidcIssuer {
        use hort_domain::entities::oidc_issuer::JwtAlg;
        OidcIssuer {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            issuer_url: format!("https://{name}.example.com"),
            audiences: vec!["hort".to_string()],
            jwks_refresh_interval: Duration::from_secs(3600),
            allowed_algorithms: vec![JwtAlg::Rs256, JwtAlg::Es256],
            require_jti: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Round-trip every statement in this module: the two writes
    /// ([`upsert_in_tx`] / [`delete_by_name_in_tx`], here passed the
    /// pool as their executor) and the three reads that decode the row
    /// back through [`OidcIssuerRow`]. The `ON CONFLICT (name)` arm is
    /// exercised by the second upsert, which is also what keeps the
    /// gitops apply's "create path minted a fresh id for a name that
    /// already exists" case honest.
    ///
    /// The transaction the production caller wraps these statements in
    /// — together with the attesting audit event — is
    /// `PgAuthorityLifecycle::commit_oidc_issuers`, pinned by
    /// `tests/authority_audit_atomicity.rs`. What this test pins is the
    /// statements themselves.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_round_trips_reads_and_delete() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgOidcIssuerRepository::new(pool.clone());
        let name = format!("idp-{}", uuid::Uuid::new_v4().simple());
        let issuer = sample_issuer(&name);
        upsert_in_tx(&pool, &issuer).await.expect("upsert");

        let by_name = repo
            .get_by_name(&name)
            .await
            .expect("get_by_name")
            .expect("row present");
        assert_eq!(by_name.issuer_url, issuer.issuer_url);
        assert_eq!(by_name.audiences, issuer.audiences);
        assert_eq!(by_name.jwks_refresh_interval, issuer.jwks_refresh_interval);
        assert_eq!(by_name.allowed_algorithms, issuer.allowed_algorithms);
        assert!(by_name.require_jti);

        let by_url = repo
            .get_by_issuer_url(&issuer.issuer_url)
            .await
            .expect("get_by_issuer_url")
            .expect("row present");
        assert_eq!(by_url.id, by_name.id);
        assert!(repo
            .list()
            .await
            .expect("list")
            .iter()
            .any(|i| i.name == name));

        // `ON CONFLICT (name)` updates in place and keeps the original
        // id — the apply path relies on that when its create branch
        // minted a fresh uuid for an already-present name.
        let mut changed = sample_issuer(&name);
        changed.audiences = vec!["hort".to_string(), "hort-staging".to_string()];
        changed.require_jti = false;
        upsert_in_tx(&pool, &changed).await.expect("upsert again");
        let reread = repo
            .get_by_name(&name)
            .await
            .expect("get_by_name")
            .expect("row present");
        assert_eq!(reread.id, by_name.id, "the surrogate id must be stable");
        assert_eq!(reread.audiences.len(), 2);
        assert!(!reread.require_jti);

        delete_by_name_in_tx(&pool, &name)
            .await
            .expect("delete_by_name");
        assert!(repo
            .get_by_name(&name)
            .await
            .expect("get_by_name")
            .is_none());
        // Deleting an absent name is a no-op, not an error — the apply
        // diff re-applies after a manual `DELETE` and must not fail.
        delete_by_name_in_tx(&pool, &name)
            .await
            .expect("delete of an absent name is a no-op");
    }
}
