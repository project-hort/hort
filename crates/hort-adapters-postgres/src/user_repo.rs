use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::{Page, PageRequest};

use crate::mappers::UserRow;
use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`UserRepository`].
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Explicit column list — no SELECT *. Auth fields are deliberately excluded.
const SELECT_COLS: &str = r#"
    id, username, email,
    auth_provider::TEXT as auth_provider,
    external_id, display_name,
    is_active, is_admin, is_service_account,
    last_login_at,
    created_at, updated_at
"#;

impl UserRepository for PgUserRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<User>> {
        Box::pin(async move {
            tracing::debug!(entity = "User", %id, "find_by_id");
            let sql = format!("SELECT {SELECT_COLS} FROM users WHERE id = $1");
            let row: UserRow = sqlx::query_as(&sql)
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &id.to_string()))?;
            User::try_from(row)
        })
    }

    fn find_by_username(&self, username: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
        let username = username.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "User", username = %username, "find_by_username");
            let sql = format!("SELECT {SELECT_COLS} FROM users WHERE username = $1");
            let row: Option<UserRow> = sqlx::query_as(&sql)
                .bind(&username)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &username))?;
            row.map(User::try_from).transpose()
        })
    }

    fn find_by_email(&self, email: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
        let email = email.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "User", email = %email, "find_by_email");
            let sql = format!("SELECT {SELECT_COLS} FROM users WHERE email = $1");
            let row: Option<UserRow> = sqlx::query_as(&sql)
                .bind(&email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &email))?;
            row.map(User::try_from).transpose()
        })
    }

    fn list(&self, page: PageRequest) -> BoxFuture<'_, DomainResult<Page<User>>> {
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "User", "list");
            let sql =
                format!("SELECT {SELECT_COLS} FROM users ORDER BY username OFFSET $1 LIMIT $2");
            let rows: Vec<UserRow> = sqlx::query_as(&sql)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", "list"))?;

            let total: Option<i64> = sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", "count"))?;

            let items = rows
                .into_iter()
                .map(User::try_from)
                .collect::<DomainResult<Vec<_>>>()?;
            Ok(Page {
                items,
                total: total.unwrap_or(0) as u64,
            })
        })
    }

    fn save(&self, user: &User) -> BoxFuture<'_, DomainResult<()>> {
        let user = user.clone();
        Box::pin(async move {
            tracing::debug!(entity = "User", username = %user.username, "save");
            let auth_provider_str = user.auth_provider.to_string();

            // The UPDATE/INSERT and the
            // `NOTIFY api_token_revocation, 'user:<id>'` emission must
            // run inside the SAME transaction so a replica's
            // `LISTEN`er cannot observe the cache-invalidation BEFORE
            // the deactivated row is visible. Same shape as
            // `api_token_repo::PgApiTokenRepository::revoke`.
            //
            // The NOTIFY fires on EVERY save where `is_active = false`
            // — including idempotent re-saves of an already-inactive
            // row, and the unusual case of a fresh INSERT with
            // `is_active = false` (e.g. a service account created
            // pre-disabled). Both are harmless: the listener-side
            // `invalidate_user` is idempotent — invalidating a cache
            // entry that doesn't exist (or was already evicted) is a
            // no-op. The contract documented in
            // `api_token_revocation_listener.rs::dispatch_payload` is
            // "consumers must be idempotent"; this emitter relies on
            // exactly that.
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &user.username))?;

            sqlx::query(
                r#"
                INSERT INTO users (
                    id, username, email,
                    auth_provider,
                    external_id, display_name,
                    is_active, is_admin, is_service_account,
                    last_login_at,
                    created_at, updated_at
                )
                VALUES (
                    $1, $2, $3,
                    $4::auth_provider,
                    $5, $6,
                    $7, $8, $9,
                    $10,
                    $11, $12
                )
                ON CONFLICT (id) DO UPDATE SET
                    username = EXCLUDED.username,
                    email = EXCLUDED.email,
                    auth_provider = EXCLUDED.auth_provider,
                    external_id = EXCLUDED.external_id,
                    display_name = EXCLUDED.display_name,
                    is_active = EXCLUDED.is_active,
                    is_admin = EXCLUDED.is_admin,
                    is_service_account = EXCLUDED.is_service_account,
                    last_login_at = EXCLUDED.last_login_at,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(user.id)
            .bind(&user.username)
            .bind(&user.email)
            .bind(&auth_provider_str)
            .bind(&user.external_id)
            .bind(&user.display_name)
            .bind(user.is_active)
            .bind(user.is_admin)
            .bind(user.is_service_account)
            .bind(user.last_login_at)
            .bind(user.created_at)
            .bind(user.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "User", &user.username))?;

            if !user.is_active {
                // Channel name is fixed (no caller input interpolated
                // into SQL); payload is the canonical UUID `Display`
                // form, no embedded quotes possible. The single-quote
                // wrapper produces a valid Postgres string literal.
                // Mirrors `api_token_repo.rs:319-324`.
                let payload = format!("'user:{}'", user.id);
                let notify_sql = format!("NOTIFY api_token_revocation, {payload}");
                sqlx::query(&notify_sql)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "User", &user.username))?;
            }

            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &user.username))?;

            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "User", %id, "delete");
            let result = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &id.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(DomainError::NotFound {
                    entity: "User",
                    id: id.to_string(),
                });
            }
            Ok(())
        })
    }

    fn find_by_external_id(
        &self,
        auth_provider: AuthProvider,
        external_id: &str,
    ) -> BoxFuture<'_, DomainResult<Option<User>>> {
        let auth_provider_str = auth_provider.to_string();
        let external_id = external_id.to_string();
        Box::pin(async move {
            tracing::debug!(
                entity = "User",
                auth_provider = %auth_provider_str,
                external_id = %external_id,
                "find_by_external_id"
            );
            let sql = format!(
                "SELECT {SELECT_COLS} FROM users \
                 WHERE auth_provider = $1::auth_provider AND external_id = $2 \
                 LIMIT 1"
            );
            let row: Option<UserRow> = sqlx::query_as(&sql)
                .bind(&auth_provider_str)
                .bind(&external_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &external_id))?;
            row.map(User::try_from).transpose()
        })
    }

    fn upsert_on_login(&self, user: &User) -> BoxFuture<'_, DomainResult<User>> {
        let user = user.clone();
        Box::pin(async move {
            tracing::debug!(
                entity = "User",
                username = %user.username,
                auth_provider = %user.auth_provider,
                "upsert_on_login"
            );
            let auth_provider_str = user.auth_provider.to_string();

            let sql = r#"
                INSERT INTO users (
                    id, username, email,
                    auth_provider,
                    external_id, display_name,
                    is_active, is_admin, is_service_account,
                    last_login_at,
                    created_at, updated_at
                )
                VALUES (
                    $1, $2, $3,
                    $4::auth_provider,
                    $5, $6,
                    $7, $8, $9,
                    $10,
                    $11, $12
                )
                ON CONFLICT (auth_provider, external_id) DO UPDATE SET
                    username      = EXCLUDED.username,
                    email         = EXCLUDED.email,
                    display_name  = EXCLUDED.display_name,
                    is_admin      = EXCLUDED.is_admin,
                    last_login_at = EXCLUDED.last_login_at,
                    updated_at    = NOW()
                RETURNING
                    id, username, email,
                    auth_provider::TEXT as auth_provider,
                    external_id, display_name,
                    is_active, is_admin, is_service_account,
                    last_login_at,
                    created_at, updated_at
            "#;

            let row: UserRow = sqlx::query_as(sql)
                .bind(user.id)
                .bind(&user.username)
                .bind(&user.email)
                .bind(&auth_provider_str)
                .bind(&user.external_id)
                .bind(&user.display_name)
                .bind(user.is_active)
                .bind(user.is_admin)
                .bind(user.is_service_account)
                .bind(user.last_login_at)
                .bind(user.created_at)
                .bind(user.updated_at)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "User", &user.username))?;

            User::try_from(row)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compat — the trait must remain usable behind
    /// `&dyn UserRepository`. Failure here is the earliest signal that
    /// a trait-method signature is no longer object-safe.
    #[test]
    fn user_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn UserRepository>();
    }

    /// `PgUserRepository::new` does not panic when handed a lazily-connected
    /// pool — no I/O happens at construction, only at first query. Wrapped
    /// in `#[tokio::test]` because `PgPool::connect_lazy` requires a Tokio
    /// runtime to instantiate its internal work queues.
    #[tokio::test]
    async fn pg_user_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgUserRepository::new(pool);
    }
}
