//! Postgres implementation of `ServiceAccountRepository`.
//!
//! CRUD against three tables (migration 011): `service_accounts`,
//! `service_account_federated_identities`, and
//! `service_account_fallback_rotations`. The read paths compose the
//! aggregate (one query per table, joined in Rust to avoid N+1); the
//! write path runs the SA row UPSERT + federated-identity row replace
//! + fallback-rotation UPSERT inside a single transaction.

use std::collections::HashMap;

use sqlx::postgres::types::PgInterval;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use hort_domain::entities::service_account::{
    FallbackRotation, FederatedIdentity, SecretFormat, ServiceAccount,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::service_account_repository::ServiceAccountRepository;

use crate::mappers::{FallbackRotationRow, FederatedIdentityRow, ServiceAccountRow};
use crate::{map_sqlx_error, BoxFuture};

const SA_SELECT_COLS: &str = "id, name, backing_user_id, role, repositories, \
                              created_at, updated_at";
const FI_SELECT_COLS: &str = "id, service_account_id, issuer_name, claims, position";
const FR_SELECT_COLS: &str = "service_account_id, target_namespace, target_name, format, \
     rotation_interval, validity";

pub struct PgServiceAccountRepository {
    pool: PgPool,
}

impl PgServiceAccountRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Duration → PgInterval writer, microseconds-only. Mirrors the
/// `oidc_issuer_repo` helper — the read-side `pg_interval_to_duration`
/// in `mappers.rs` accepts the inverse shape.
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

/// Compose the full aggregate from the three row sources. Used by both
/// `list` (in bulk) and `get_by_name`.
fn compose(
    sa_row: ServiceAccountRow,
    fi_rows: Vec<FederatedIdentityRow>,
    fr_row: Option<FallbackRotationRow>,
) -> DomainResult<ServiceAccount> {
    let mut sa: ServiceAccount = sa_row.into();
    // FI rows arrive pre-sorted by position from the SELECT — preserve
    // that order so the matcher (and the apply digest) see the same
    // shape every read.
    let identities: Vec<FederatedIdentity> = fi_rows
        .into_iter()
        .map(FederatedIdentity::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    sa.federated_identities = identities;
    sa.fallback_rotation = match fr_row {
        Some(r) => Some(FallbackRotation::try_from(r)?),
        None => None,
    };
    Ok(sa)
}

impl ServiceAccountRepository for PgServiceAccountRepository {
    fn list(&self) -> BoxFuture<'_, DomainResult<Vec<ServiceAccount>>> {
        Box::pin(async move {
            tracing::debug!(entity = "service_account", "list");
            // Three bulk queries: SA rows, FI rows, FR rows. Composed
            // in Rust by service_account_id — avoids the N+1 a per-SA
            // lookup loop would produce.
            let sa_rows: Vec<ServiceAccountRow> = sqlx::query_as(&format!(
                "SELECT {SA_SELECT_COLS} FROM service_accounts ORDER BY name"
            ))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "service_accounts list");
                DomainError::Invariant(format!("service_accounts list: {e}"))
            })?;
            let fi_rows: Vec<FederatedIdentityRow> = sqlx::query_as(&format!(
                "SELECT {FI_SELECT_COLS} FROM service_account_federated_identities \
                 ORDER BY service_account_id, position"
            ))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "service_account_federated_identities list");
                DomainError::Invariant(format!("service_account_federated_identities list: {e}"))
            })?;
            let fr_rows: Vec<FallbackRotationRow> = sqlx::query_as(&format!(
                "SELECT {FR_SELECT_COLS} FROM service_account_fallback_rotations"
            ))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "service_account_fallback_rotations list");
                DomainError::Invariant(format!("service_account_fallback_rotations list: {e}"))
            })?;

            // Group FI rows by sa_id and FR rows by sa_id for assembly.
            let mut fi_by_sa: HashMap<Uuid, Vec<FederatedIdentityRow>> = HashMap::new();
            for row in fi_rows {
                fi_by_sa
                    .entry(row.service_account_id)
                    .or_default()
                    .push(row);
            }
            let mut fr_by_sa: HashMap<Uuid, FallbackRotationRow> = HashMap::new();
            for row in fr_rows {
                fr_by_sa.insert(row.service_account_id, row);
            }

            sa_rows
                .into_iter()
                .map(|sa_row| {
                    let id = sa_row.id;
                    let fi = fi_by_sa.remove(&id).unwrap_or_default();
                    let fr = fr_by_sa.remove(&id);
                    compose(sa_row, fi, fr)
                })
                .collect()
        })
    }

    fn get_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<ServiceAccount>>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "service_account", name = %name, "get_by_name");
            let sa_row: Option<ServiceAccountRow> = sqlx::query_as(&format!(
                "SELECT {SA_SELECT_COLS} FROM service_accounts WHERE name = $1 LIMIT 1"
            ))
            .bind(&name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(name = %name, error = %e, "service_accounts get_by_name");
                DomainError::Invariant(format!("service_accounts get_by_name: {e}"))
            })?;
            let Some(sa_row) = sa_row else {
                return Ok(None);
            };
            let sa_id = sa_row.id;

            let fi_rows: Vec<FederatedIdentityRow> = sqlx::query_as(&format!(
                "SELECT {FI_SELECT_COLS} FROM service_account_federated_identities \
                 WHERE service_account_id = $1 ORDER BY position"
            ))
            .bind(sa_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(%sa_id, error = %e, "service_account_federated_identities get");
                DomainError::Invariant(format!("service_account_federated_identities get: {e}"))
            })?;

            let fr_row: Option<FallbackRotationRow> = sqlx::query_as(&format!(
                "SELECT {FR_SELECT_COLS} FROM service_account_fallback_rotations \
                 WHERE service_account_id = $1 LIMIT 1"
            ))
            .bind(sa_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(%sa_id, error = %e, "service_account_fallback_rotations get");
                DomainError::Invariant(format!("service_account_fallback_rotations get: {e}"))
            })?;

            compose(sa_row, fi_rows, fr_row).map(Some)
        })
    }

    fn upsert(&self, sa: &ServiceAccount) -> BoxFuture<'_, DomainResult<()>> {
        // Capture every field — the async block runs after the borrow
        // ends so we can't keep `&sa` around.
        let id = sa.id;
        let name = sa.name.clone();
        let backing_user_id = sa.backing_user_id;
        let role = sa.role.clone();
        let repositories = sa.repositories.clone();
        let federated_identities = sa.federated_identities.clone();
        let fallback_rotation = sa.fallback_rotation.clone();

        Box::pin(async move {
            tracing::info!(entity = "service_account", name = %name, "upsert (gitops apply)");
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;

            // 1. UPSERT the SA row. `ON CONFLICT (name) DO UPDATE` so
            // the row's primary key stays stable across re-applies
            // even if the caller-supplied id differs.
            let row: (Uuid,) = sqlx::query_as(
                r#"INSERT INTO service_accounts
                       (id, name, backing_user_id, role, repositories)
                   VALUES ($1, $2, $3, $4, $5)
                   ON CONFLICT (name) DO UPDATE SET
                       backing_user_id = EXCLUDED.backing_user_id,
                       role            = EXCLUDED.role,
                       repositories    = EXCLUDED.repositories,
                       updated_at      = NOW()
                   RETURNING id"#,
            )
            .bind(id)
            .bind(&name)
            .bind(backing_user_id)
            .bind(&role)
            .bind(&repositories)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;
            let persisted_id = row.0;

            // 2. Replace federated-identity rows. DELETE existing,
            // then INSERT the new set preserving order as `position`.
            // The transaction makes the swap atomic; the unique
            // `(service_account_id, position)` index would otherwise
            // collide on a re-INSERT without the prior DELETE.
            sqlx::query(
                "DELETE FROM service_account_federated_identities \
                 WHERE service_account_id = $1",
            )
            .bind(persisted_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;

            for (position, fi) in federated_identities.iter().enumerate() {
                let claims_json = serde_json::Value::Object(
                    fi.claims
                        .iter()
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect(),
                );
                sqlx::query(
                    r#"INSERT INTO service_account_federated_identities
                           (service_account_id, issuer_name, claims, position)
                       VALUES ($1, $2, $3, $4)"#,
                )
                .bind(persisted_id)
                .bind(&fi.issuer_name)
                .bind(&claims_json)
                .bind(position as i32)
                .execute(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;
            }

            // 3. Reconcile the fallback-rotation row. If `Some`,
            // UPSERT keyed by the (PRIMARY KEY) service_account_id.
            // If `None`, DELETE any prior row.
            match fallback_rotation {
                Some(fr) => {
                    let rotation_iv = duration_to_pg_interval(fr.rotation_interval)?;
                    let validity_iv = duration_to_pg_interval(fr.validity)?;
                    let format_str = match fr.format {
                        SecretFormat::Dockerconfigjson => "dockerconfigjson",
                        SecretFormat::Opaque => "opaque",
                    };
                    sqlx::query(
                        r#"INSERT INTO service_account_fallback_rotations
                               (service_account_id, target_namespace, target_name,
                                format, rotation_interval, validity)
                           VALUES ($1, $2, $3, $4, $5, $6)
                           ON CONFLICT (service_account_id) DO UPDATE SET
                               target_namespace  = EXCLUDED.target_namespace,
                               target_name       = EXCLUDED.target_name,
                               format            = EXCLUDED.format,
                               rotation_interval = EXCLUDED.rotation_interval,
                               validity          = EXCLUDED.validity"#,
                    )
                    .bind(persisted_id)
                    .bind(&fr.target_secret_namespace)
                    .bind(&fr.target_secret_name)
                    .bind(format_str)
                    .bind(rotation_iv)
                    .bind(validity_iv)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;
                }
                None => {
                    sqlx::query(
                        "DELETE FROM service_account_fallback_rotations \
                         WHERE service_account_id = $1",
                    )
                    .bind(persisted_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;
                }
            }

            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;
            Ok(())
        })
    }

    fn delete_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<()>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::info!(
                entity = "service_account",
                name = %name,
                "delete_by_name (gitops apply)"
            );
            // The CASCADE FKs on
            // `service_account_federated_identities.service_account_id`
            // and `service_account_fallback_rotations.service_account_id`
            // drop the sub-aggregate rows alongside.
            sqlx::query("DELETE FROM service_accounts WHERE name = $1")
                .bind(&name)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ServiceAccount", &name))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_to_pg_interval_one_hour() {
        let iv = duration_to_pg_interval(Duration::from_secs(3600)).unwrap();
        assert_eq!(iv.microseconds, 3_600_000_000);
    }

    #[test]
    fn duration_to_pg_interval_rejects_overflow() {
        let err = duration_to_pg_interval(Duration::from_secs(u64::MAX)).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }
}
