//! PostgreSQL implementation of [`ApiTokenRepository`].
//!
//! Implements ADR 0012 §3 (schema), §4 (issuance), §5 (validator path +
//! multi-replica revocation invalidation via `LISTEN/NOTIFY`).
//!
//! # Multi-replica revocation invalidation
//!
//! [`PgApiTokenRepository::revoke`] emits
//! `NOTIFY api_token_revocation, '<token_id>'` inside the same transaction
//! as the `UPDATE api_tokens SET revoked_at = NOW()`. Every replica
//! `LISTEN`s on this channel; the in-transaction emission means
//! cache drops cannot race ahead of the revocation row's visibility.

use std::time::Duration;

use hort_domain::entities::api_token::ApiToken;
use hort_domain::error::DomainResult;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::types::{Page, PageRequest};
use sqlx::postgres::types::PgInterval;
use sqlx::PgPool;
use uuid::Uuid;

use crate::mappers::{token_kind_to_text, ApiTokenRow};
use crate::{map_sqlx_error, BoxFuture};

/// The credential-store retention sweep's `DELETE`, as one statement.
///
/// Named rather than inlined so the predicate a reviewer has to read is
/// one block of text in one place, and so the unit test below can assert
/// the shape of it without a database.
///
/// **Each disjunct tests a row's own non-NULL mark.** `expires_at` and
/// `revoked_at` are both nullable (`migrations/008_api_tokens.sql`), so a
/// row with **neither** set is a durable identity that never expires: it
/// satisfies neither disjunct and is never deleted. That is the whole
/// safety property of this statement — the table it reclaims from is the
/// one that decides who may do what, so the bar is that the predicate
/// reads as obviously unable to reach a live credential.
///
/// Two forms are therefore ruled out, both of which compile, run, and
/// delete live credentials:
///
/// - `COALESCE(expires_at, revoked_at) < now() - $1` — flattens the two
///   marks, and `COALESCE(NULL, NULL)` is `NULL` only until somebody adds
///   a third argument to make it total.
/// - `NOT (expires_at > now() OR revoked_at IS NULL)` and relatives — any
///   predicate phrased as the negation of "still live" answers `TRUE` for
///   the row whose liveness is expressed by the *absence* of a mark.
///
/// The explicit `IS NOT NULL` guards are redundant under SQL's
/// three-valued logic (`NULL < anything` is `NULL`, which `WHERE` treats
/// as not-matched), and are written anyway: they put the NULL reasoning
/// inside the statement, so a reader checking this `DELETE` against a
/// live credential does not have to recall a rule from elsewhere.
///
/// `issued_via` is deliberately absent. It records which issuance path
/// minted the row; a sweep that consulted it would retain or discard
/// credentials by origin rather than by whether they can still
/// authenticate anybody.
const DELETE_EXPIRED_OR_REVOKED_SQL: &str = "DELETE FROM public.api_tokens\n\
                 WHERE (expires_at IS NOT NULL AND expires_at < now() - $1::interval)\n\
                    OR (revoked_at IS NOT NULL AND revoked_at < now() - $1::interval)";

/// `Duration` → `PgInterval` for the retention sweep's one bind
/// parameter.
///
/// Local to this adapter, matching how `jobs_repository`,
/// `scanner_registry_repository`, `oidc_issuer_repo` and
/// `service_account_repo` each carry their own: this crate's convention
/// is per-adapter, and consolidating the five is a change to four files
/// this one does not touch (and a real decision, since two of them
/// *reject* overflow where the other two clamp).
///
/// Clamping is the right direction **for a `DELETE`**: `i64::MAX`
/// microseconds is roughly 292 471 years, so a clamped horizon makes the
/// predicate match no row at all. An over-long horizon deletes less; a
/// saturating-to-zero one would delete every expired row at once. The
/// branch is unreachable from the handler in any case —
/// `resolve_sweep_horizon` caps the horizon at 365 days, about six orders
/// of magnitude below the overflow point — so it is tested directly
/// rather than through the sweep.
fn duration_to_pg_interval(d: Duration) -> PgInterval {
    PgInterval {
        months: 0,
        days: 0,
        microseconds: d.as_micros().try_into().unwrap_or(i64::MAX),
    }
}

/// PostgreSQL implementation of [`ApiTokenRepository`].
pub struct PgApiTokenRepository {
    pool: PgPool,
}

impl PgApiTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Explicit column list — no SELECT *. Order MUST match the
/// [`ApiTokenRow`] field order so `sqlx::query_as` resolves columns
/// positionally.
const SELECT_COLS: &str = r#"
    id, user_id, name, description, kind,
    token_hash, token_prefix,
    declared_permissions, repository_ids,
    expires_at, revoked_at,
    created_by_user_id, created_at, issued_via
"#;

// ---------------------------------------------------------------------------
// ApiTokenRepository impl
// ---------------------------------------------------------------------------

impl ApiTokenRepository for PgApiTokenRepository {
    fn insert(&self, token: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
        // Clone up-front so the future is `'static`-clean and the borrow
        // does not extend across the await boundary.
        let token = token.clone();
        Box::pin(async move {
            tracing::debug!(
                entity = "ApiToken",
                token_id = %token.id,
                user_id = %token.user_id,
                "insert"
            );

            let kind_str = token_kind_to_text(token.kind);
            let issued_via_str = token.issued_via.as_str();
            let perms: Vec<String> = token
                .declared_permissions
                .iter()
                .map(ToString::to_string)
                .collect();

            sqlx::query(
                r#"
                INSERT INTO api_tokens (
                    id, user_id, name, description, kind,
                    token_hash, token_prefix,
                    declared_permissions, repository_ids,
                    expires_at, revoked_at,
                    created_by_user_id, created_at, issued_via
                )
                VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7,
                    $8::text[], $9::uuid[],
                    $10, $11,
                    $12, $13, $14
                )
                "#,
            )
            .bind(token.id)
            .bind(token.user_id)
            .bind(&token.name)
            .bind(&token.description)
            .bind(kind_str)
            .bind(&token.token_hash)
            .bind(&token.token_prefix)
            .bind(&perms)
            .bind(&token.repository_ids)
            .bind(token.expires_at)
            .bind(token.revoked_at)
            .bind(token.created_by_user_id)
            .bind(token.created_at)
            .bind(issued_via_str)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ApiToken", &token.id.to_string()))?;

            Ok(())
        })
    }

    fn find_by_prefix(&self, prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            // Prefix lookups are debug-level only,
            // and miss is NOT a warn (no token-shape oracle in logs).
            tracing::debug!(entity = "ApiToken", "find_by_prefix");
            let sql =
                format!("SELECT {SELECT_COLS} FROM api_tokens WHERE token_prefix = $1 LIMIT 1");
            let row: Option<ApiTokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(&prefix)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", "find_by_prefix"))?;
            row.map(ApiTokenRow::try_into_api_token).transpose()
        })
    }

    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
        Box::pin(async move {
            tracing::debug!(entity = "ApiToken", token_id = %id, "find_by_id");
            let sql = format!("SELECT {SELECT_COLS} FROM api_tokens WHERE id = $1");
            let row: ApiTokenRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &id.to_string()))?;
            row.try_into_api_token()
        })
    }

    fn list_for_user(
        &self,
        user_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>> {
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "ApiToken", user_id = %user_id, "list_for_user");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM api_tokens WHERE user_id = $1 \
                 ORDER BY created_at DESC OFFSET $2 LIMIT $3"
            );
            let rows: Vec<ApiTokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &user_id.to_string()))?;

            let total: Option<i64> =
                sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "ApiToken", "count"))?;

            let items = rows
                .into_iter()
                .map(ApiTokenRow::try_into_api_token)
                .collect::<DomainResult<Vec<_>>>()?;
            Ok(Page {
                items,
                total: total.unwrap_or(0).max(0) as u64,
            })
        })
    }

    fn revoke(&self, token_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "ApiToken", token_id = %token_id, "revoke");

            // Run the UPDATE and the NOTIFY inside the same transaction so
            // listeners on `api_token_revocation` cannot observe the
            // invalidation BEFORE the `revoked_at` row is visible. The
            // multi-replica cache invalidation relies on the LISTEN side
            // wiring in the revocation listener.
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            sqlx::query(
                "UPDATE api_tokens SET revoked_at = NOW() \
                 WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(token_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            // Always emit, even on already-revoked: replicas treat
            // duplicate notifications as idempotent cache-drops, and an
            // operator-driven re-revoke is the conventional way to force
            // a cache flush. Channel name is fixed (no caller input
            // interpolated into SQL); payload is the canonical UUID
            // string from `Display`, no embedded quotes possible.
            let payload = format!("'{token_id}'");
            let notify_sql = format!("NOTIFY api_token_revocation, {payload}");
            sqlx::query(sqlx::AssertSqlSafe(notify_sql))
                .execute(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            Ok(())
        })
    }

    fn delete_expired_or_revoked_older_than(
        &self,
        horizon: Duration,
    ) -> BoxFuture<'_, DomainResult<u64>> {
        let interval = duration_to_pg_interval(horizon);
        Box::pin(async move {
            // Horizon only — no token id, no prefix, no row identity. The
            // deleted-row count is the handler's business and reaches an
            // operator through the task's `result_summary`.
            tracing::debug!(
                entity = "ApiToken",
                horizon_seconds = horizon.as_secs(),
                "delete_expired_or_revoked_older_than"
            );
            let res = sqlx::query(DELETE_EXPIRED_OR_REVOKED_SQL)
                .bind(interval)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "ApiToken", "delete_expired_or_revoked_older_than")
                })?;
            Ok(res.rows_affected())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure tests — no database required.
    // -----------------------------------------------------------------------

    /// The retention `DELETE` tests each mark against **its own**
    /// `IS NOT NULL`.
    ///
    /// Asserted on the statement text because the property is a property
    /// of the text: a database proves the current statement behaves, and
    /// this proves the next edit of it cannot quietly become one of the
    /// two forms that reach a live credential. The DB-gated test in
    /// `tests/api_token_repo.rs` asserts the behaviour against a real
    /// Postgres; the two together are what make the predicate readable
    /// *and* correct.
    /// The statement with every run of whitespace collapsed to one
    /// space.
    ///
    /// The assertions below are about the predicate, not about where the
    /// literal's line breaks fall — the statement is written across three
    /// source lines for a reader, and a check that depended on that
    /// layout would fail the next time it is re-wrapped while saying
    /// nothing about whether the predicate is still safe.
    fn normalized_retention_sql() -> String {
        DELETE_EXPIRED_OR_REVOKED_SQL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn retention_delete_pairs_each_mark_with_its_own_not_null_guard() {
        let sql = normalized_retention_sql();
        assert!(
            sql.contains("expires_at IS NOT NULL AND expires_at < now() - $1::interval"),
            "the expiry disjunct must require its own mark to be present: {sql}"
        );
        assert!(
            sql.contains("revoked_at IS NOT NULL AND revoked_at < now() - $1::interval"),
            "the revocation disjunct must require its own mark to be present: {sql}"
        );
        assert!(
            sql.contains(") OR ("),
            "the two marks are alternatives, not a conjunction: {sql}"
        );
    }

    /// The three shapes that would make the sweep reach a row it must
    /// never reach, or delete by provenance instead of by state.
    ///
    /// A counter-assertion to the test above: that one would still pass
    /// if a `COALESCE` arm were bolted on beside the two correct
    /// disjuncts, and this one would not.
    #[test]
    fn retention_delete_has_no_coalesce_no_negation_and_no_issued_via() {
        let sql = normalized_retention_sql();
        let lower = sql.to_ascii_lowercase();
        assert!(
            !lower.contains("coalesce"),
            "a COALESCE over the two marks flattens them and can reach a both-NULL row: {sql}"
        );
        // The two `IS NOT NULL` guards are the legitimate `NOT` in this
        // statement, so they come out before the negation check — which
        // is then looking for a `NOT` that inverts a liveness test. A
        // predicate phrased as the negation of "still live" answers TRUE
        // for the row whose liveness is the *absence* of a mark.
        let without_guards = lower.replace("is not null", "");
        assert!(
            !without_guards.contains("not "),
            "the only NOT in the predicate must be the two IS NOT NULL guards: {sql}"
        );
        assert!(
            !lower.contains("issued_via"),
            "the sweep deletes by state, never by provenance: {sql}"
        );
        // Counter-assertion: the scan is not vacuous — it is looking at a
        // statement that really does name the table and both marks.
        assert!(
            lower.contains("delete from public.api_tokens")
                && lower.contains("expires_at")
                && lower.contains("revoked_at"),
            "the checks above must be reading the retention DELETE: {sql}"
        );
    }

    /// 90 days — the handler's default horizon — round-trips as
    /// microseconds, with no month or day component. `months`/`days` are
    /// calendar-relative in Postgres; the horizon is a fixed duration, so
    /// carrying it entirely in `microseconds` is what keeps the window the
    /// same length across a DST boundary.
    #[test]
    fn duration_to_pg_interval_ninety_days() {
        let i = duration_to_pg_interval(Duration::from_secs(90 * 24 * 60 * 60));
        assert_eq!(i.months, 0);
        assert_eq!(i.days, 0);
        assert_eq!(i.microseconds, 90 * 24 * 60 * 60 * 1_000_000);
    }

    /// Overflow clamps to `i64::MAX` microseconds rather than wrapping.
    ///
    /// Unreachable from the handler (`resolve_sweep_horizon` caps at 365
    /// days), and the direction matters anyway: `i64::MAX` microseconds is
    /// roughly 292 471 years, so a clamped horizon makes the `DELETE`
    /// match nothing. For a statement that removes credentials, clamping
    /// up is the safe failure.
    #[test]
    fn duration_to_pg_interval_clamps_overflow_to_a_horizon_that_matches_nothing() {
        let i = duration_to_pg_interval(Duration::from_secs(u64::MAX));
        assert_eq!(i.microseconds, i64::MAX);
        assert_eq!(i.months, 0);
        assert_eq!(i.days, 0);
    }

    /// Compile-time + runtime assertion that [`PgApiTokenRepository`]
    /// satisfies the [`ApiTokenRepository`] trait through `&dyn`. Same
    /// shape as the user-repo's `_assert_dyn_compat` test — coerces the
    /// concrete type to the trait object so the method-table entry is
    /// referenced.
    #[tokio::test]
    async fn _assert_dyn_compat() {
        fn _is_dyn(_repo: &dyn ApiTokenRepository) {}
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let repo = PgApiTokenRepository::new(pool);
        _is_dyn(&repo);
    }

    /// `PgApiTokenRepository::new` does not panic on a lazily-connected
    /// pool (mirrors the `pg_user_repo_new_does_not_panic` smoke test).
    #[tokio::test]
    async fn pg_api_token_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgApiTokenRepository::new(pool);
    }
}
