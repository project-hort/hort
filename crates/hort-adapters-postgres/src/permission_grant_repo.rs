//! Postgres implementation of [`PermissionGrantRepository`].
//!
//! There is no `roles` table and no `role_id` to key grants on. A grant carries a sum-typed
//! [`GrantSubject`] mapped from two mutually-exclusive columns —
//! `required_claims TEXT[]` (subject = `Claims`) XOR `user_id UUID`
//! (subject = `User`). The `subject_exclusive` CHECK in
//! `001_users_roles_rbac.sql` guarantees exactly one is non-NULL per
//! row; the row mapper surfaces a violation as `DomainError::Invariant`
//! (only reachable via out-of-band SQL that bypassed the CHECK).
//!
//! Read-only at the public-CRUD layer — grant mutation lives with the
//! gitops apply pipeline, which reconstructs the evaluator on restart.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`PermissionGrantRepository`].
pub struct PgPermissionGrantRepository {
    pool: PgPool,
}

impl PgPermissionGrantRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Explicit column list. The `permission` enum is cast to TEXT so the
/// mapper parses it via [`Permission::from_str`]; `required_claims` and
/// `user_id` carry the sum-typed subject.
const GRANT_SELECT_COLS: &str = "id, required_claims, user_id, \
     permission::TEXT as permission, repository_id, managed_by, managed_by_digest, created_at";

// ---------------------------------------------------------------------------
// PermissionGrantRow — adapter-private projection
// ---------------------------------------------------------------------------

/// Database row for the `permission_grants` table.
///
/// Exactly one of `required_claims` / `user_id` is non-NULL per row
/// (`subject_exclusive` CHECK). `row_to_grant` maps that to the
/// [`GrantSubject`] sum type.
#[derive(Debug, FromRow)]
pub(crate) struct PermissionGrantRow {
    pub id: Uuid,
    pub required_claims: Option<Vec<String>>,
    pub user_id: Option<Uuid>,
    pub permission: String,
    pub repository_id: Option<Uuid>,
    pub managed_by: String,
    pub managed_by_digest: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Pure mapper helpers — testable without a DB
// ---------------------------------------------------------------------------

/// Parse a `permission::TEXT` column value into the domain [`Permission`].
///
/// An unknown string is `DomainError::Invariant` — the column is
/// constrained by the `permission_type` enum in
/// `001_users_roles_rbac.sql`, so any unknown value means out-of-band DB
/// tampering or a forgotten migration.
pub(crate) fn parse_permission_from_text(s: &str) -> DomainResult<Permission> {
    Permission::from_str(s).map_err(|_| {
        DomainError::Invariant(format!(
            "corrupt permission value in permission_grants row: {s}"
        ))
    })
}

/// Translate the two mutually-exclusive subject columns into the domain
/// [`GrantSubject`] sum type.
///
/// - `required_claims` non-NULL, `user_id` NULL → `Claims`. An empty
///   array is `DomainError::Invariant` (the `claims_nonempty` CHECK
///   forbids it; only out-of-band SQL reaches here).
/// - `user_id` non-NULL, `required_claims` NULL → `User`.
/// - both NULL or both non-NULL → `DomainError::Invariant` (the
///   `subject_exclusive` CHECK forbids it).
pub(crate) fn subject_from_columns(
    required_claims: Option<&[String]>,
    user_id: Option<Uuid>,
) -> DomainResult<GrantSubject> {
    match (required_claims, user_id) {
        (Some(claims), None) => {
            if claims.is_empty() {
                return Err(DomainError::Invariant(
                    "permission_grants row has empty required_claims (violates \
                     claims_nonempty CHECK)"
                        .into(),
                ));
            }
            Ok(GrantSubject::Claims(claims.to_vec()))
        }
        (None, Some(uid)) => Ok(GrantSubject::User(uid)),
        (Some(_), Some(_)) => Err(DomainError::Invariant(
            "permission_grants row has both required_claims and user_id \
             (violates subject_exclusive CHECK)"
                .into(),
        )),
        (None, None) => Err(DomainError::Invariant(
            "permission_grants row has neither required_claims nor user_id \
             (violates subject_exclusive CHECK)"
                .into(),
        )),
    }
}

/// Invert [`subject_from_columns`] for the write path: a `Claims`
/// subject binds the `required_claims` column (and NULLs `user_id`); a
/// `User` subject binds `user_id` (and NULLs `required_claims`).
pub(crate) fn subject_to_columns(subject: &GrantSubject) -> (Option<Vec<String>>, Option<Uuid>) {
    match subject {
        GrantSubject::Claims(claims) => (Some(claims.clone()), None),
        GrantSubject::User(uid) => (None, Some(*uid)),
    }
}

/// Owned column projection of a managed [`PermissionGrant`], built
/// before the `save_managed` transaction opens so the future borrows
/// nothing from `items`. Named struct (not a 6-tuple) to keep the
/// reconcile INSERT loop readable and to satisfy
/// `clippy::type_complexity` — behaviour is identical to the prior
/// tuple form. `required_claims` XOR `user_id` is non-NULL (mirrors the
/// `subject_exclusive` CHECK; see [`subject_to_columns`]).
struct PreparedGrant {
    id: Uuid,
    required_claims: Option<Vec<String>>,
    user_id: Option<Uuid>,
    permission: String,
    repository_id: Option<Uuid>,
    digest: Vec<u8>,
}

/// Fallible mapping from `PermissionGrantRow` to the domain
/// [`PermissionGrant`].
pub(crate) fn row_to_grant(row: &PermissionGrantRow) -> DomainResult<PermissionGrant> {
    let permission = parse_permission_from_text(&row.permission).inspect_err(|_| {
        tracing::warn!(
            permission = %row.permission,
            grant_id = %row.id,
            "unknown permission in permission_grants row"
        );
    })?;

    let subject =
        subject_from_columns(row.required_claims.as_deref(), row.user_id).inspect_err(|_| {
            tracing::warn!(grant_id = %row.id, "malformed subject in permission_grants row");
        })?;

    let managed_by = row.managed_by.parse().unwrap_or(ManagedBy::Local);
    let managed_by_digest = row
        .managed_by_digest
        .as_deref()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());

    Ok(PermissionGrant {
        id: row.id,
        subject,
        repository_id: row.repository_id,
        permission,
        managed_by,
        managed_by_digest,
        created_at: row.created_at,
    })
}

// ---------------------------------------------------------------------------
// PermissionGrantRepository impl
// ---------------------------------------------------------------------------

impl PermissionGrantRepository for PgPermissionGrantRepository {
    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
        Box::pin(async move {
            tracing::debug!(entity = "PermissionGrant", "list_all");
            let sql = format!("SELECT {GRANT_SELECT_COLS} FROM permission_grants");
            let rows: Vec<PermissionGrantRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "PermissionGrant", "list_all"))?;
            rows.iter().map(row_to_grant).collect()
        })
    }

    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
        Box::pin(async move {
            tracing::debug!(entity = "PermissionGrant", "list_managed_by_gitops");
            let sql = format!(
                "SELECT {GRANT_SELECT_COLS} FROM permission_grants \
                 WHERE managed_by = 'gitops'"
            );
            let rows: Vec<PermissionGrantRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "PermissionGrant", "list_managed_by_gitops"))?;
            rows.iter().map(row_to_grant).collect()
        })
    }

    fn save_managed(&self, items: &[PermissionGrant]) -> BoxFuture<'_, DomainResult<()>> {
        // Project to owned column tuples up front so the future owns no
        // borrow of `items`. Every element must carry a digest — a
        // managed grant without one violates the
        // `managed_by_digest IS NOT NULL` shape the diff layer relies
        // on; surface it before touching the DB.
        let prepared: DomainResult<Vec<PreparedGrant>> = items
            .iter()
            .map(|g| {
                let (required_claims, user_id) = subject_to_columns(&g.subject);
                let digest = g.managed_by_digest.ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "save_managed requires managed_by_digest on grant {}",
                        g.id
                    ))
                })?;
                Ok(PreparedGrant {
                    id: g.id,
                    required_claims,
                    user_id,
                    permission: g.permission.to_string(),
                    repository_id: g.repository_id,
                    digest: digest.to_vec(),
                })
            })
            .collect();
        Box::pin(async move {
            let prepared = prepared?;
            tracing::info!(
                entity = "permission_grant",
                count = prepared.len(),
                "save_managed full reconcile (gitops apply)"
            );

            // `save_managed` reconciles the ENTIRE `managed_by = 'gitops'`
            // partition to `items` in a single transaction.
            // Delete-absent + upsert-present over a content-keyed
            // partition is realised as delete-all-gitops + insert-present:
            // every row absent from `items` is removed (revoke), every
            // row present is (re)written (the surrogate PK is not the
            // gitops identity — the diff keys off the subject-dependent
            // tuple, never the PK — so a rewrite is not churn).
            // `managed_by = 'local'` rows are never in scope. The DELETE
            // + INSERTs share one tx so a failure rolls the partition back
            // to its prior state unchanged; there is no window where the
            // partition is partially applied.
            let mut tx = self.pool.begin().await.map_err(|e| {
                tracing::warn!(error = %e, "begin tx for permission_grants save_managed");
                map_sqlx_error(&e, "PermissionGrant", "save_managed:begin")
            })?;

            sqlx::query("DELETE FROM permission_grants WHERE managed_by = 'gitops'")
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "delete gitops-managed grants");
                    map_sqlx_error(&e, "PermissionGrant", "save_managed:delete")
                })?;

            for g in &prepared {
                sqlx::query(
                    r#"INSERT INTO permission_grants
                           (id, required_claims, user_id, permission,
                            repository_id, managed_by, managed_by_digest)
                       VALUES ($1, $2, $3, $4::permission_type,
                               $5, 'gitops', $6)"#,
                )
                .bind(g.id)
                .bind(&g.required_claims)
                .bind(g.user_id)
                .bind(&g.permission)
                .bind(g.repository_id)
                .bind(&g.digest)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::warn!(grant_id = %g.id, error = %e, "insert gitops grant");
                    map_sqlx_error(&e, "PermissionGrant", &g.id.to_string())
                })?;
            }

            tx.commit().await.map_err(|e| {
                tracing::warn!(error = %e, "commit permission_grants save_managed");
                map_sqlx_error(&e, "PermissionGrant", "save_managed:commit")
            })?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests — pure mapper helpers + trait dyn-compat + DB-backed round-trips
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The DB-backed tests in this crate run against one shared
    // `DATABASE_URL` database with no per-test isolation. Production
    // serialises the only writer of these partitions — gitops apply is
    // single-process per boot lock (design §3.2) — so the tests must
    // honour that same single-flight contract. `#[serial(hort_pg_db)]`
    // is one shared key across *every* DB-backed test in this crate;
    // it keeps them from running concurrently with each other (other
    // crates stay parallel). Without it, `save_managed`'s global
    // gitops-partition reconcile (and other global-scope reads) race
    // sibling tests under `cargo test --lib`.
    use serial_test::serial;

    // -- Permission parsing ------------------------------------------------

    #[test]
    fn parse_permission_accepts_every_variant() {
        for name in ["read", "write", "delete", "admin", "admin_task_invoke"] {
            let p = parse_permission_from_text(name).expect("known permission");
            assert_eq!(p.to_string(), name);
        }
    }

    #[test]
    fn parse_permission_is_case_insensitive() {
        let p = parse_permission_from_text("WRITE").unwrap();
        assert_eq!(p, Permission::Write);
    }

    #[test]
    fn parse_permission_unknown_is_invariant() {
        let err = parse_permission_from_text("publish").unwrap_err();
        match err {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("publish"), "message should mention bad value");
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    // -- subject_from_columns ----------------------------------------------

    #[test]
    fn subject_from_columns_claims() {
        let claims = vec!["developer".to_string(), "team-alpha".to_string()];
        let s = subject_from_columns(Some(&claims), None).unwrap();
        assert_eq!(s, GrantSubject::Claims(claims));
    }

    #[test]
    fn subject_from_columns_user() {
        let uid = Uuid::from_u128(0xBEEF);
        let s = subject_from_columns(None, Some(uid)).unwrap();
        assert_eq!(s, GrantSubject::User(uid));
    }

    #[test]
    fn subject_from_columns_empty_claims_is_invariant() {
        let err = subject_from_columns(Some(&[]), None).unwrap_err();
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("claims_nonempty")),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn subject_from_columns_both_set_is_invariant() {
        let claims = vec!["x".to_string()];
        let err = subject_from_columns(Some(&claims), Some(Uuid::nil())).unwrap_err();
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("subject_exclusive")),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn subject_from_columns_neither_set_is_invariant() {
        let err = subject_from_columns(None, None).unwrap_err();
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("subject_exclusive")),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    // -- subject_to_columns (inverse) --------------------------------------

    #[test]
    fn subject_to_columns_claims_round_trips() {
        let claims = vec!["a".to_string(), "b".to_string()];
        let (rc, uid) = subject_to_columns(&GrantSubject::Claims(claims.clone()));
        assert_eq!(rc, Some(claims.clone()));
        assert_eq!(uid, None);
        // Round-trip back through the read mapper.
        assert_eq!(
            subject_from_columns(rc.as_deref(), uid).unwrap(),
            GrantSubject::Claims(claims)
        );
    }

    #[test]
    fn subject_to_columns_user_round_trips() {
        let id = Uuid::from_u128(0xABC);
        let (rc, uid) = subject_to_columns(&GrantSubject::User(id));
        assert_eq!(rc, None);
        assert_eq!(uid, Some(id));
        assert_eq!(
            subject_from_columns(rc.as_deref(), uid).unwrap(),
            GrantSubject::User(id)
        );
    }

    // -- row_to_grant ------------------------------------------------------

    fn claims_row(permission: &str) -> PermissionGrantRow {
        PermissionGrantRow {
            id: Uuid::from_u128(2),
            required_claims: Some(vec!["developer".into(), "team-alpha".into()]),
            user_id: None,
            permission: permission.into(),
            repository_id: Some(Uuid::from_u128(4)),
            managed_by: "local".into(),
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn row_to_grant_claims_subject_happy_path() {
        let row = claims_row("write");
        let grant = row_to_grant(&row).unwrap();
        assert_eq!(grant.permission, Permission::Write);
        assert_eq!(grant.repository_id, Some(Uuid::from_u128(4)));
        assert_eq!(
            grant.subject,
            GrantSubject::Claims(vec!["developer".into(), "team-alpha".into()])
        );
    }

    #[test]
    fn row_to_grant_user_subject_global_scope() {
        let uid = Uuid::from_u128(0x77);
        let row = PermissionGrantRow {
            required_claims: None,
            user_id: Some(uid),
            repository_id: None,
            ..claims_row("read")
        };
        let grant = row_to_grant(&row).unwrap();
        assert!(grant.repository_id.is_none());
        assert_eq!(grant.subject, GrantSubject::User(uid));
        assert_eq!(grant.permission, Permission::Read);
    }

    #[test]
    fn row_to_grant_unknown_permission_is_invariant() {
        let row = claims_row("publish");
        let err = row_to_grant(&row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn row_to_grant_malformed_subject_is_invariant() {
        let row = PermissionGrantRow {
            required_claims: None,
            user_id: None,
            ..claims_row("read")
        };
        let err = row_to_grant(&row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn row_to_grant_managed_by_gitops_round_trips() {
        let row = PermissionGrantRow {
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0xcd; 32]),
            ..claims_row("write")
        };
        let grant = row_to_grant(&row).unwrap();
        assert_eq!(grant.managed_by, ManagedBy::GitOps);
        assert_eq!(grant.managed_by_digest, Some([0xcd; 32]));
    }

    #[test]
    fn row_to_grant_unknown_managed_by_defaults_local_and_drops_short_digest() {
        let row = PermissionGrantRow {
            managed_by: "external".into(),
            managed_by_digest: Some(vec![0; 16]),
            ..claims_row("read")
        };
        let grant = row_to_grant(&row).unwrap();
        assert_eq!(grant.managed_by, ManagedBy::Local);
        assert!(grant.managed_by_digest.is_none());
    }

    // -- Trait dyn-compat + construction ----------------------------------

    #[test]
    fn permission_grant_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn PermissionGrantRepository>();
    }

    #[tokio::test]
    async fn pg_permission_grant_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgPermissionGrantRepository::new(pool);
    }

    // -- DB-backed integration tests (skipped when DATABASE_URL unset) ------

    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    fn managed_claims_grant(id: Uuid, repo: Option<Uuid>) -> PermissionGrant {
        PermissionGrant {
            id,
            subject: GrantSubject::Claims(vec!["developer".into(), "team-alpha".into()]),
            repository_id: repo,
            permission: Permission::Write,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x11; 32]),
            created_at: Utc::now(),
        }
    }

    // `save_managed` is the authoritative-set reconcile primitive
    // (delete-absent + upsert-present over the gitops partition, one
    // transaction). The DB-backed tests below pin the full-reconcile
    // semantic. They are deferred-execution: no `DATABASE_URL` here →
    // `maybe_pool` returns `None` and they early-return.

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_claims_and_is_idempotent() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPermissionGrantRepository::new(pool.clone());
        let grant = managed_claims_grant(Uuid::new_v4(), None);
        repo.save_managed(std::slice::from_ref(&grant))
            .await
            .expect("save_managed");
        // Idempotent re-application of the same complete set — upsert
        // on the subject-dependent key, no churn.
        repo.save_managed(std::slice::from_ref(&grant))
            .await
            .expect("save_managed again (idempotent)");

        let listed = repo.list_all().await.expect("list_all");
        let found = listed
            .iter()
            .find(|g| g.subject == grant.subject && g.permission == Permission::Write)
            .expect("claims grant present");
        assert_eq!(
            found.subject,
            GrantSubject::Claims(vec!["developer".into(), "team-alpha".into()])
        );

        let managed = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert_eq!(
            managed
                .iter()
                .filter(|g| g.subject == grant.subject)
                .count(),
            1,
            "idempotent re-apply must not duplicate the managed row"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_full_reconcile_deletes_absent_managed_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPermissionGrantRepository::new(pool.clone());

        // First apply: two distinct claims grants.
        let g_a = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["alpha".into()]),
            repository_id: None,
            permission: Permission::Read,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x01; 32]),
            created_at: Utc::now(),
        };
        let g_b = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["beta".into()]),
            repository_id: None,
            permission: Permission::Read,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x02; 32]),
            created_at: Utc::now(),
        };
        repo.save_managed(&[g_a.clone(), g_b.clone()])
            .await
            .expect("first apply");

        // Second apply: only g_a — g_b must be revoked (delete-absent).
        repo.save_managed(std::slice::from_ref(&g_a))
            .await
            .expect("reconcile to {g_a}");

        let managed = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert!(
            managed.iter().any(|g| g.subject == g_a.subject),
            "g_a survives the reconcile"
        );
        assert!(
            !managed.iter().any(|g| g.subject == g_b.subject),
            "g_b absent from the new set must be deleted (save_managed IS the revoke primitive)"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_empty_set_revokes_all_gitops_grants() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgPermissionGrantRepository::new(pool.clone());
        let grant = managed_claims_grant(Uuid::new_v4(), None);
        repo.save_managed(std::slice::from_ref(&grant))
            .await
            .expect("seed one grant");

        // An explicitly-emptied gitops config revokes everything.
        repo.save_managed(&[]).await.expect("reconcile to empty");

        let managed = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert!(
            !managed.iter().any(|g| g.subject == grant.subject),
            "empty authoritative set revokes all gitops-managed grants"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_does_not_touch_local_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // A non-gitops (Local/admin-created) row must survive a gitops
        // reconcile — the partition boundary is `managed_by = gitops`.
        let local_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO permission_grants \
               (id, required_claims, permission, managed_by) \
             VALUES ($1, ARRAY['local-only'], 'read'::permission_type, 'local')",
        )
        .bind(local_id)
        .execute(&pool)
        .await
        .expect("insert local grant");

        let repo = PgPermissionGrantRepository::new(pool.clone());
        // Reconcile gitops partition to empty.
        repo.save_managed(&[])
            .await
            .expect("reconcile gitops empty");

        let all = repo.list_all().await.expect("list_all");
        assert!(
            all.iter().any(|g| matches!(
                &g.subject,
                GrantSubject::Claims(c) if c == &vec!["local-only".to_string()]
            )),
            "Local row must survive a gitops-partition reconcile"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_user_subject() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // A User-subject grant needs a real users row (FK).
        let uid = Uuid::new_v4();
        let uname = format!("sa-{}", uid.simple());
        sqlx::query(
            "INSERT INTO users (id, username, email, auth_provider, is_service_account) \
             VALUES ($1, $2, $3, 'local', true)",
        )
        .bind(uid)
        .bind(&uname)
        .bind(format!("{uname}@example.test"))
        .execute(&pool)
        .await
        .expect("insert backing user");

        let repo = PgPermissionGrantRepository::new(pool.clone());
        let grant = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id: None,
            permission: Permission::Read,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x22; 32]),
            created_at: Utc::now(),
        };
        repo.save_managed(std::slice::from_ref(&grant))
            .await
            .expect("save_managed");

        let listed = repo.list_all().await.expect("list_all");
        let found = listed
            .iter()
            .find(|g| g.subject == GrantSubject::User(uid))
            .expect("user grant present");
        assert_eq!(found.permission, Permission::Read);
        assert!(found.repository_id.is_none());
    }
}
