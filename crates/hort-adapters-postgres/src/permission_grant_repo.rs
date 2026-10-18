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
/// before the reconcile transaction opens so the future borrows
/// nothing from `items`. Named struct (not a 6-tuple) to keep the
/// reconcile INSERT loop readable and to satisfy
/// `clippy::type_complexity` — behaviour is identical to the prior
/// tuple form. `required_claims` XOR `user_id` is non-NULL (mirrors the
/// `subject_exclusive` CHECK; see [`subject_to_columns`]).
pub(crate) struct PreparedGrant {
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
            let rows: Vec<PermissionGrantRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
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
            let rows: Vec<PermissionGrantRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "PermissionGrant", "list_managed_by_gitops"))?;
            rows.iter().map(row_to_grant).collect()
        })
    }
}

// ---------------------------------------------------------------------------
// In-transaction reconcile — shared with the authority lifecycle adapter
// ---------------------------------------------------------------------------

/// Project a managed grant set to its owned column tuples, rejecting any
/// element missing a digest **before** a transaction is opened.
///
/// A managed grant without a digest violates the
/// `managed_by_digest IS NOT NULL` shape the apply diff relies on, so it
/// is surfaced before the DB is touched.
pub(crate) fn prepare_managed_grants(
    items: &[PermissionGrant],
) -> DomainResult<Vec<PreparedGrant>> {
    items
        .iter()
        .map(|g| {
            let (required_claims, user_id) = subject_to_columns(&g.subject);
            let digest = g.managed_by_digest.ok_or_else(|| {
                DomainError::Invariant(format!(
                    "a managed grant requires managed_by_digest, grant {} has none",
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
        .collect()
}

/// Reconcile the ENTIRE `managed_by = 'gitops'` partition to `prepared`
/// on the caller's open transaction.
///
/// Delete-absent + upsert-present over a content-keyed partition is
/// realised as delete-all-gitops + insert-present: every row absent from
/// `prepared` is removed (revoke), every row present is (re)written (the
/// surrogate PK is not the gitops identity — the diff keys off the
/// subject-dependent tuple, never the PK — so a rewrite is not churn).
/// `managed_by = 'local'` rows are never in scope.
///
/// The DELETE + INSERTs are one statement group, so there is no window
/// in which the partition is partially applied. The caller owns the
/// transaction boundary, which is what lets the audit append join the
/// same transaction
/// (`crate::authority_lifecycle::PgAuthorityLifecycle`); a failure on
/// either side rolls the partition back to its prior state unchanged.
pub(crate) async fn reconcile_managed_grants_in_tx(
    conn: &mut sqlx::PgConnection,
    prepared: &[PreparedGrant],
) -> DomainResult<()> {
    tracing::info!(
        entity = "permission_grant",
        count = prepared.len(),
        "managed-partition full reconcile (gitops apply)"
    );

    sqlx::query("DELETE FROM permission_grants WHERE managed_by = 'gitops'")
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "delete gitops-managed grants");
            map_sqlx_error(&e, "PermissionGrant", "reconcile_managed:delete")
        })?;

    for g in prepared {
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
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::warn!(grant_id = %g.id, error = %e, "insert gitops grant");
            map_sqlx_error(&e, "PermissionGrant", &g.id.to_string())
        })?;
    }
    Ok(())
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
    // single-process per boot lock — so the tests must
    // honour that same single-flight contract. `#[serial(hort_pg_db)]`
    // is one shared key across *every* DB-backed test in this crate;
    // it keeps them from running concurrently with each other (other
    // crates stay parallel). Without it, the global gitops-partition
    // reconcile (and other global-scope reads) race sibling tests under
    // `cargo test --lib`.

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
}
