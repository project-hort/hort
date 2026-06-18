//! PostgreSQL implementation of [`ApiTokenRepository`].
//!
//! Implements ADR 0012 §3 (schema), §4 (issuance), §5 (validator path +
//! multi-replica revocation invalidation via `LISTEN/NOTIFY`).
//!
//! # GDPR data minimisation
//!
//! [`PgApiTokenRepository::update_last_used`] is the sole writer of the
//! `last_used_*` columns. `last_used` retention:
//!
//! - The `last_used_ip` column is **bucketed at adapter write** —
//!   `/24` for IPv4, `/48` for IPv6 — by funnelling through
//!   `hort_app::metrics::client_ip_bucket`. Raw IPs never reach the row.
//! - The `last_used_user_agent` column is **truncated to 256 chars** at
//!   write. Truncation respects UTF-8 boundaries: a multi-byte char that
//!   straddles the 256-byte boundary is dropped wholly rather than split.
//! - Inputs that fail to parse as `std::net::IpAddr` are stored verbatim
//!   — the upstream filter rejects malformed input; this adapter MUST NOT
//!   crash on malformed input.
//!
//! # Multi-replica revocation invalidation
//!
//! [`PgApiTokenRepository::revoke`] emits
//! `NOTIFY api_token_revocation, '<token_id>'` inside the same transaction
//! as the `UPDATE api_tokens SET revoked_at = NOW()`. Every replica
//! `LISTEN`s on this channel; the in-transaction emission means
//! cache drops cannot race ahead of the revocation row's visibility.

use chrono::{DateTime, Utc};
use hort_app::metrics::client_ip_bucket;
use hort_domain::entities::api_token::ApiToken;
use hort_domain::error::DomainResult;
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::types::{Page, PageRequest};
use sqlx::PgPool;
use uuid::Uuid;

use crate::mappers::{token_kind_to_text, ApiTokenRow};
use crate::{map_sqlx_error, BoxFuture};

/// Cap on the persisted `last_used_user_agent` length.
///
/// UA strings longer than 256 chars are common fingerprinting signals
/// and are not
/// security-useful; persist the prefix only.
pub(crate) const USER_AGENT_MAX_BYTES: usize = 256;

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
    last_used_at, last_used_ip, last_used_user_agent,
    created_by_user_id, created_at
"#;

// ---------------------------------------------------------------------------
// Pure helpers — testable without a DB
// ---------------------------------------------------------------------------

/// Bucket a raw client-IP string for the `last_used_ip` column.
///
/// Strings that fail to parse as [`std::net::IpAddr`] round-trip
/// unchanged — the upstream validator is the layer that rejects
/// malformed input; this adapter is best-effort and MUST NOT crash on a
/// bad string. Strings that DO parse are funnelled through
/// `hort_app::metrics::client_ip_bucket` (`/24` IPv4, `/48` IPv6) — the
/// same buckets the brute-force lockout already operates on.
pub(crate) fn bucket_or_passthrough_ip(raw: &str) -> String {
    match raw.parse::<std::net::IpAddr>() {
        Ok(ip) => client_ip_bucket(ip),
        Err(_) => raw.to_owned(),
    }
}

/// Truncate `ua` to at most [`USER_AGENT_MAX_BYTES`] bytes on a UTF-8
/// boundary.
///
/// Naive byte truncation panics if the cut falls inside a multi-byte
/// codepoint (`String::truncate` panics on a non-char-boundary index);
/// this helper walks `char_indices` from the end to find the largest
/// boundary `<= USER_AGENT_MAX_BYTES`. ASCII inputs hit the fast path
/// (the boundary search is O(1) when every char is one byte).
pub(crate) fn truncate_user_agent(ua: &str) -> String {
    if ua.len() <= USER_AGENT_MAX_BYTES {
        return ua.to_owned();
    }
    // `floor_char_boundary` would be cleanest but is unstable. Walk
    // back from `USER_AGENT_MAX_BYTES` until we hit a char boundary.
    let mut cut = USER_AGENT_MAX_BYTES;
    while cut > 0 && !ua.is_char_boundary(cut) {
        cut -= 1;
    }
    ua[..cut].to_owned()
}

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
                    last_used_at, last_used_ip, last_used_user_agent,
                    created_by_user_id, created_at
                )
                VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7,
                    $8::text[], $9::uuid[],
                    $10, $11,
                    $12, $13, $14,
                    $15, $16
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
            .bind(token.last_used_at)
            .bind(&token.last_used_ip)
            .bind(&token.last_used_user_agent)
            .bind(token.created_by_user_id)
            .bind(token.created_at)
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
            let row: Option<ApiTokenRow> = sqlx::query_as(&sql)
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
            let row: ApiTokenRow = sqlx::query_as(&sql)
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
            let rows: Vec<ApiTokenRow> = sqlx::query_as(&sql)
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

    fn update_last_used(
        &self,
        token_id: Uuid,
        at: DateTime<Utc>,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        // Bucket + truncate BEFORE the await — `client_ip` / `user_agent`
        // are borrowed `&str` in the trait signature, and the GDPR
        // discipline says raw IPs/UAs never reach the wire.
        let bucketed_ip = client_ip.map(bucket_or_passthrough_ip);
        let truncated_ua = user_agent.map(truncate_user_agent);
        Box::pin(async move {
            // Logging: never include the raw IP or UA. Token id is
            // sufficient correlation; the bucketed IP is acceptable to
            // log but offers no investigation value at debug level.
            tracing::debug!(
                entity = "ApiToken",
                token_id = %token_id,
                "update_last_used"
            );

            sqlx::query(
                "UPDATE api_tokens \
                 SET last_used_at = $2, last_used_ip = $3, last_used_user_agent = $4 \
                 WHERE id = $1",
            )
            .bind(token_id)
            .bind(at)
            .bind(&bucketed_ip)
            .bind(&truncated_ua)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            Ok(())
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
            sqlx::query(&notify_sql)
                .execute(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "ApiToken", &token_id.to_string()))?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure tests — no database required.
    // -----------------------------------------------------------------------

    /// IPv4 `203.0.113.42` buckets to `203.0.113.0/24`.
    #[test]
    fn bucket_or_passthrough_ip_v4_truncates_to_24() {
        assert_eq!(bucket_or_passthrough_ip("203.0.113.42"), "203.0.113.0/24");
    }

    /// IPv6 input buckets to `/48` — the lower 80 bits zeroed. The
    /// expected wire form is whatever `client_ip_bucket` produces; the
    /// test asserts byte-for-byte rather than hand-rolling an
    /// expectation that could drift.
    #[test]
    fn bucket_or_passthrough_ip_v6_matches_client_ip_bucket_helper() {
        let raw = "2001:db8:abcd:0012:0000:0000:0000:0001";
        let parsed: std::net::IpAddr = raw.parse().unwrap();
        let expected = client_ip_bucket(parsed);
        // Sanity that the helper actually buckets at /48 — the lower
        // 80 bits are gone.
        assert!(expected.ends_with("/48"));
        assert!(expected.contains("2001:"));
        assert!(expected.contains("db8:"));
        assert!(expected.contains("abcd:"));
        // The adapter must surface exactly what the helper produces.
        assert_eq!(bucket_or_passthrough_ip(raw), expected);
    }

    /// Malformed IP strings (validator's job to filter) are written
    /// verbatim — the adapter MUST NOT crash on a bad input. Acceptance
    /// bullet 4 sub-bullet d: store as-is.
    #[test]
    fn bucket_or_passthrough_ip_malformed_round_trips_unchanged() {
        assert_eq!(bucket_or_passthrough_ip("not-an-ip"), "not-an-ip");
        assert_eq!(bucket_or_passthrough_ip(""), "");
        // Looks-like-IPv4 but invalid octet count.
        assert_eq!(bucket_or_passthrough_ip("203.0.113"), "203.0.113");
    }

    /// 4 KB ASCII UA truncates to exactly [`USER_AGENT_MAX_BYTES`]
    /// chars. Acceptance bullet 4 sub-bullet c: a 4 KB UA surfaces as
    /// 256 chars on read.
    #[test]
    fn truncate_user_agent_4kb_ascii_truncates_to_256_bytes() {
        let ua = "x".repeat(4096);
        let truncated = truncate_user_agent(&ua);
        assert_eq!(truncated.len(), USER_AGENT_MAX_BYTES);
        assert!(truncated.chars().all(|c| c == 'x'));
    }

    /// UA strings shorter than the cap pass through verbatim.
    #[test]
    fn truncate_user_agent_under_cap_passes_through() {
        let ua = "Mozilla/5.0";
        assert_eq!(truncate_user_agent(ua), ua);
    }

    /// UA exactly at the cap is kept verbatim — the boundary is
    /// inclusive.
    #[test]
    fn truncate_user_agent_at_exact_cap_unchanged() {
        let ua = "x".repeat(USER_AGENT_MAX_BYTES);
        assert_eq!(truncate_user_agent(&ua).len(), USER_AGENT_MAX_BYTES);
    }

    /// Multi-byte char straddling the 256-byte boundary MUST NOT cause
    /// a panic, and the truncated string MUST remain valid UTF-8.
    /// Acceptance bullet 4 sub-bullet c second clause: pick a test
    /// input that catches a naive byte split.
    ///
    /// Construction: 254 bytes of ASCII + a 3-byte UTF-8 char. Naive
    /// truncation at byte 256 would land inside the 3-byte sequence
    /// (bytes 254 / 255 of the multi-byte char) and panic via
    /// `String::truncate`. The boundary-walking implementation backs
    /// off to byte 254, dropping the multi-byte char wholly.
    #[test]
    fn truncate_user_agent_respects_utf8_boundary() {
        let mut ua = "x".repeat(254);
        // U+20AC EURO SIGN — encoded as 0xE2 0x82 0xAC (3 bytes).
        ua.push('\u{20AC}');
        // Add filler so the input clearly exceeds the 256-byte cap and
        // forces the truncation path.
        ua.extend(std::iter::repeat_n('y', 100));
        assert!(ua.len() > USER_AGENT_MAX_BYTES);

        let truncated = truncate_user_agent(&ua);
        // Must be valid UTF-8 — the `String::from_utf8` round-trip would
        // panic on a torn multi-byte sequence.
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        // The 3-byte char straddled bytes 254..256; the boundary walker
        // should back off to 254, dropping it wholly.
        assert_eq!(truncated.len(), 254);
        assert!(truncated.chars().all(|c| c == 'x'));
    }

    /// Boundary case: a 1-byte ASCII char immediately after the cap
    /// boundary is dropped cleanly with no walk-back needed.
    #[test]
    fn truncate_user_agent_257_bytes_ascii_drops_one_char() {
        let ua = "z".repeat(USER_AGENT_MAX_BYTES + 1);
        let truncated = truncate_user_agent(&ua);
        assert_eq!(truncated.len(), USER_AGENT_MAX_BYTES);
    }

    /// Empty input is the no-op fast path.
    #[test]
    fn truncate_user_agent_empty_string() {
        assert_eq!(truncate_user_agent(""), "");
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
