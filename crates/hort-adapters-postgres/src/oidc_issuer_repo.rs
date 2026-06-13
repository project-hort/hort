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
            let rows: Vec<OidcIssuerRow> = sqlx::query_as(&sql)
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
            let row: Option<OidcIssuerRow> = sqlx::query_as(&sql)
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
            let row: Option<OidcIssuerRow> = sqlx::query_as(&sql)
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

    fn upsert(&self, issuer: &OidcIssuer) -> BoxFuture<'_, DomainResult<()>> {
        let id = issuer.id;
        let name = issuer.name.clone();
        let issuer_url = issuer.issuer_url.clone();
        let audiences = issuer.audiences.clone();
        let jwks_refresh = issuer.jwks_refresh_interval;
        let require_jti = issuer.require_jti;
        // Persist the wire form (uppercase RFC 7518) — the row mapper
        // parses through `JwtAlg::from_str`, which requires uppercase.
        let algorithms: Vec<String> = issuer
            .allowed_algorithms
            .iter()
            .map(|a| a.as_str().to_string())
            .collect();
        Box::pin(async move {
            let interval = duration_to_pg_interval(jwks_refresh)?;
            tracing::info!(entity = "oidc_issuer", name = %name, "upsert (gitops apply)");
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
            .bind(id)
            .bind(&name)
            .bind(&issuer_url)
            .bind(&audiences)
            .bind(interval)
            .bind(&algorithms)
            .bind(require_jti)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "OidcIssuer", &name))?;
            Ok(())
        })
    }

    fn delete_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<()>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::info!(entity = "oidc_issuer", name = %name, "delete_by_name (gitops apply)");
            sqlx::query("DELETE FROM oidc_issuers WHERE name = $1")
                .bind(&name)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "OidcIssuer", &name))?;
            // Defensive: deleting a name that no longer exists is a
            // no-op (returns Ok). The apply pipeline's diff layer is
            // the only caller, and re-applying after a manual `DELETE`
            // must not error.
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
