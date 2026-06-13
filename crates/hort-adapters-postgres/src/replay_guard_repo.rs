//! Postgres implementation of [`ReplayGuardPort`] (ADR 0018 — JTI
//! replay prevention).
//!
//! The durable anti-replay seen-set for the federation branch of
//! `/auth/token-exchange`. The single operation is one atomic
//! `INSERT … ON CONFLICT (issuer_name, key_kind, key_id) DO NOTHING
//! RETURNING key_id` against `public.jwt_replay_seen` (migration 011):
//!
//! - a returned row ⇒ [`ReplayClaim::FirstSeen`] (this exact key was
//!   not present and is now recorded — mint may proceed),
//! - zero rows ⇒ [`ReplayClaim::Replayed`] (the key was already there
//!   within its TTL window — the use case denies, no token minted),
//! - any sqlx error ⇒ [`ReplayGuardError::Unavailable`] (logged
//!   `error!` here at the adapter; the use case maps it to a
//!   fail-CLOSED 503 deny — anti-F-22).
//!
//! The database arbitrates concurrent replays via the primary key; no
//! application-level lock and no read-then-write TOCTOU window.
//!
//! DDL (the table, index, CHECK) is owned by the `migrate` role only —
//! this adapter issues DML exclusively (`INSERT … ON CONFLICT` and the
//! prune `DELETE`). The migration pins the runtime DSN's grants on this
//! table to `INSERT, SELECT, DELETE` (ADR 0009 — least-privilege runtime role).

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use hort_domain::ports::replay_guard::{ReplayClaim, ReplayGuardError, ReplayGuardPort, ReplayKey};

use crate::BoxFuture;

/// The nullable component-column bind set for one `jwt_replay_seen`
/// row, in column order `(jti, sub, iss, iat, exp)`. Exactly one
/// "shape" is populated per row (jti XOR composite); the row CHECK
/// enforces it. Aliased to keep the [`PgReplayGuardRepository::claim`]
/// body within clippy's type-complexity budget.
type ReplayBinds<'a> = (
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<i64>,
    Option<i64>,
);

pub struct PgReplayGuardRepository {
    pool: PgPool,
}

impl PgReplayGuardRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Prune expired rows (`expires_at < now()`). Called by the
    /// `replay-seen-prune` worker `TaskHandler` (default-ENABLED).
    /// Returns the number of rows deleted so the task's `result_summary`
    /// can report it.
    ///
    /// Cleanup degrades SAFE: if this never runs the table only grows
    /// (the seen-set never *forgets* within TTL, so a stale-but-present
    /// row still correctly reports `Replayed`). Security does not
    /// degrade on a prune outage — only storage.
    pub async fn prune_expired(&self) -> Result<u64, ReplayGuardError> {
        let result = sqlx::query("DELETE FROM jwt_replay_seen WHERE expires_at < now()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    "jwt_replay_seen prune DELETE failed (cleanup degrades safe — \
                     seen-set still authoritative; only storage grows)"
                );
                ReplayGuardError::Unavailable(format!("replay-seen prune failed: {e}"))
            })?;
        Ok(result.rows_affected())
    }
}

impl ReplayGuardPort for PgReplayGuardRepository {
    fn claim<'a>(
        &'a self,
        key: &'a ReplayKey,
        expires_at: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<ReplayClaim, ReplayGuardError>> {
        Box::pin(async move {
            // Decompose the typed key into the bind set. `key_id` /
            // `key_kind` come from the domain port (the composite
            // digest is computed in `hort-domain`, never here). The
            // component columns are bound verbatim to satisfy the row
            // CHECK and for audit/forensics.
            let issuer_name = key.issuer_name();
            let key_kind = key.key_kind();
            let key_id = key.key_id();
            let (jti, sub, iss, iat, exp): ReplayBinds<'_> = match key {
                ReplayKey::Jti { jti, .. } => (Some(jti.as_str()), None, None, None, None),
                ReplayKey::Composite {
                    iss, sub, iat, exp, ..
                } => (
                    None,
                    Some(sub.as_str()),
                    Some(iss.as_str()),
                    Some(*iat),
                    Some(*exp),
                ),
            };

            // The atomic claim. `ON CONFLICT … DO NOTHING RETURNING`
            // makes the database arbitrate concurrent replays: the
            // first transaction to insert this PK gets the RETURNING
            // row (FirstSeen); every concurrent / subsequent one
            // conflicts and gets zero rows (Replayed). The INSERT does
            // NOT gate on `expires_at` — an unexpired duplicate must
            // still conflict; expired-row reclamation is the prune's
            // job, never relied upon for correctness (spec §4).
            let returned: Option<(String,)> = sqlx::query_as(
                r#"INSERT INTO jwt_replay_seen
                       (issuer_name, key_kind, jti, sub, iss, iat, exp,
                        key_id, expires_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                   ON CONFLICT (issuer_name, key_kind, key_id) DO NOTHING
                   RETURNING key_id"#,
            )
            .bind(issuer_name)
            .bind(key_kind)
            .bind(jti)
            .bind(sub)
            .bind(iss)
            .bind(iat)
            .bind(exp)
            .bind(&key_id)
            .bind(expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                // Infrastructure cause logged here at the adapter
                // (error!). The app layer logs the *deny* at info!;
                // one each, no double-emit (spec §8). No jti / token
                // material in the log — only the issuer + key_kind.
                tracing::error!(
                    error = %e,
                    issuer_name = %issuer_name,
                    key_kind = %key_kind,
                    "jwt_replay_seen claim INSERT failed — replay guard \
                     unavailable; the use case will fail CLOSED (503, no mint)"
                );
                ReplayGuardError::Unavailable(format!("replay-guard claim failed: {e}"))
            })?;

            Ok(match returned {
                Some(_) => ReplayClaim::FirstSeen,
                None => ReplayClaim::Replayed,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// DB-backed tests follow the crate's established Tier-2 pattern:
// `#[ignore = "requires DATABASE_URL"]` + an explicit env read so
// `cargo test --workspace --lib` stays green locally without a
// database; CI/Tier-2 runs them with `-- --ignored`.

#[cfg(test)]
mod tests {
    use super::*;

    fn jti_key(issuer: &str, jti: &str) -> ReplayKey {
        ReplayKey::Jti {
            issuer_name: issuer.into(),
            jti: jti.into(),
        }
    }

    fn composite_key(issuer: &str, sub: &str, iat: i64) -> ReplayKey {
        ReplayKey::Composite {
            issuer_name: issuer.into(),
            iss: "https://gitlab.com".into(),
            sub: sub.into(),
            iat,
            exp: iat + 3600,
        }
    }

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    /// First presentation of a `jti` ⇒ FirstSeen (row inserted);
    /// second presentation of the *same* `jti` ⇒ Replayed (no row).
    /// This is the centerpiece replay-detection invariant.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn jti_first_seen_then_replayed() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PgReplayGuardRepository::new(pool.clone());
        let issuer = format!("itest-{}", uuid::Uuid::new_v4().simple());
        let key = jti_key(&issuer, "jti-replay-1");
        let exp = Utc::now() + chrono::Duration::hours(1);

        let first = repo.claim(&key, exp).await.expect("first claim ok");
        assert_eq!(first, ReplayClaim::FirstSeen);

        let second = repo.claim(&key, exp).await.expect("second claim ok");
        assert_eq!(
            second,
            ReplayClaim::Replayed,
            "the same jti presented again must be Replayed — no second mint"
        );

        sqlx::query("DELETE FROM jwt_replay_seen WHERE issuer_name = $1")
            .bind(&issuer)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// A different `jti` under the same issuer is independent ⇒
    /// FirstSeen (a genuinely-new JWT must still mint).
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn distinct_jti_is_independent_first_seen() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PgReplayGuardRepository::new(pool.clone());
        let issuer = format!("itest-{}", uuid::Uuid::new_v4().simple());
        let exp = Utc::now() + chrono::Duration::hours(1);

        assert_eq!(
            repo.claim(&jti_key(&issuer, "a"), exp).await.unwrap(),
            ReplayClaim::FirstSeen
        );
        assert_eq!(
            repo.claim(&jti_key(&issuer, "b"), exp).await.unwrap(),
            ReplayClaim::FirstSeen,
            "a distinct jti must not be classified as a replay"
        );

        sqlx::query("DELETE FROM jwt_replay_seen WHERE issuer_name = $1")
            .bind(&issuer)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// Composite key: first ⇒ FirstSeen, byte-identical second ⇒
    /// Replayed; a composite differing only in `iat` (a genuinely
    /// new token from the same subject) ⇒ FirstSeen.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn composite_replay_and_distinct_iat() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PgReplayGuardRepository::new(pool.clone());
        let issuer = format!("itest-{}", uuid::Uuid::new_v4().simple());
        let exp = Utc::now() + chrono::Duration::hours(1);
        let iat = 1_700_000_000;

        assert_eq!(
            repo.claim(&composite_key(&issuer, "sub-x", iat), exp)
                .await
                .unwrap(),
            ReplayClaim::FirstSeen
        );
        assert_eq!(
            repo.claim(&composite_key(&issuer, "sub-x", iat), exp)
                .await
                .unwrap(),
            ReplayClaim::Replayed,
            "byte-identical composite must be Replayed"
        );
        assert_eq!(
            repo.claim(&composite_key(&issuer, "sub-x", iat + 1), exp)
                .await
                .unwrap(),
            ReplayClaim::FirstSeen,
            "a different iat is a genuinely new token — must mint"
        );

        sqlx::query("DELETE FROM jwt_replay_seen WHERE issuer_name = $1")
            .bind(&issuer)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// The row CHECK rejects a malformed `jti` row (composite columns
    /// populated alongside `key_kind='jti'`). The adapter never builds
    /// such a row — this pins the DB-side defence-in-depth.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn check_constraint_rejects_mixed_shape_row() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let issuer = format!("itest-{}", uuid::Uuid::new_v4().simple());
        let err = sqlx::query(
            "INSERT INTO jwt_replay_seen \
                (issuer_name, key_kind, jti, sub, iss, iat, exp, key_id, expires_at) \
             VALUES ($1, 'jti', 'j', 's', 'i', 1, 2, 'j', now())",
        )
        .bind(&issuer)
        .execute(&pool)
        .await
        .expect_err("CHECK must reject a jti row carrying composite columns");
        let code = err
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default();
        assert_eq!(
            code, "23514",
            "expected check_violation SQLSTATE, got {code}"
        );
    }

    /// `prune_expired` deletes only rows past `expires_at` and leaves
    /// unexpired rows authoritative (cleanup degrades safe).
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn prune_expired_removes_only_stale_rows() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let repo = PgReplayGuardRepository::new(pool.clone());
        let issuer = format!("itest-{}", uuid::Uuid::new_v4().simple());

        // One already-expired, one still valid.
        repo.claim(
            &jti_key(&issuer, "stale"),
            Utc::now() - chrono::Duration::hours(1),
        )
        .await
        .unwrap();
        repo.claim(
            &jti_key(&issuer, "fresh"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

        let deleted = repo.prune_expired().await.expect("prune ok");
        assert!(deleted >= 1, "the stale row must be pruned");

        // The fresh row is still authoritative: re-presenting it is
        // still a replay.
        assert_eq!(
            repo.claim(
                &jti_key(&issuer, "fresh"),
                Utc::now() + chrono::Duration::hours(1)
            )
            .await
            .unwrap(),
            ReplayClaim::Replayed,
            "prune must not forget an unexpired jti"
        );

        sqlx::query("DELETE FROM jwt_replay_seen WHERE issuer_name = $1")
            .bind(&issuer)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
