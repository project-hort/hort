use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::managed_by::ManagedBy;
use crate::error::DomainError;

// ---------------------------------------------------------------------------
// Permission
// ---------------------------------------------------------------------------

/// Coarse-grained permission label attached to role grants.
///
/// The six variants mirror the canonical `permission_type` enum in
/// `migrations/001_users_roles_rbac.sql`. They are used throughout the authorization
/// pipeline: stored on `PermissionGrant` rows, checked against the caller's
/// resolved role set by the evaluator, and surfaced in the
/// `hort_authz_decisions_total{permission=...}` metric.
///
/// Serialization is case-insensitive on parse and lowercase on display so
/// the YAML / JSON / metric-label surfaces all share one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    Delete,
    Admin,
    /// Single coarse permission that gates every `POST /api/v1/admin/tasks/{kind}`
    /// call. No per-kind granularity; all task kinds share this one permission so
    /// operators can grant or revoke admin-task invocation without listing kinds.
    /// DB enum literal: `'admin_task_invoke'`.
    AdminTaskInvoke,
    /// Curator role — confers day-to-day decision authority
    /// over quarantined / rejected artifacts and finding-exclusions, without
    /// elevating to `Admin`. Gates `CurationUseCase::{waive, block, list_queue,
    /// list_decisions, list_exclusions}` and is accepted (alongside `Admin`) on
    /// `PolicyUseCase::{add_exclusion, remove_exclusion}`. DB enum literal:
    /// `'curate'`. Granted via the existing audited `ApplyConfigUseCase` apply
    /// path — no new admin endpoint, no grant back door. See
    /// `docs/architecture/how-to/curator-workflow.md`.
    Curate,
    /// Self-service prefetch authority — gates the
    /// `POST /api/v1/repositories/{repo_key}/prefetch` endpoint that allows
    /// a CLI-session caller to enqueue a self-service prefetch against a
    /// repo's configured upstream. Required **in addition to**
    /// `Permission::Read` on the repo (`Read ∧ Prefetch` is the
    /// authority shape; explicit separate grant, not implied by `Write` —
    /// see `docs/architecture/explanation/prefetch-pipeline.md`).
    /// DB enum literal: `'prefetch'`. Discovery (`GET .../discovery/...`)
    /// uses `Permission::Read` alone; this variant is the *amplification*
    /// gate exclusively. Granted via the existing audited gitops apply
    /// path — no new admin endpoint.
    Prefetch,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::Delete => f.write_str("delete"),
            Self::Admin => f.write_str("admin"),
            Self::AdminTaskInvoke => f.write_str("admin_task_invoke"),
            Self::Curate => f.write_str("curate"),
            Self::Prefetch => f.write_str("prefetch"),
        }
    }
}

impl FromStr for Permission {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // NB: `FromStr` is a NON-exhaustive match (the compiler will NOT force
        // a new arm when a new `Permission` variant is added). When adding a
        // variant, the corresponding `"<literal>"` arm MUST be added here
        // explicitly, or gitops `PermissionGrant` parsing silently breaks.
        match s.to_lowercase().as_str() {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "delete" => Ok(Self::Delete),
            "admin" => Ok(Self::Admin),
            "admin_task_invoke" => Ok(Self::AdminTaskInvoke),
            "curate" => Ok(Self::Curate),
            "prefetch" => Ok(Self::Prefetch),
            _ => Err(DomainError::Validation(format!("unknown permission: {s}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// GrantSubject
// ---------------------------------------------------------------------------

/// The subject a [`PermissionGrant`] binds to (ADR 0012).
///
/// Authorization uses an **additive-claims** model: a grant either
/// requires a *set of claims* the caller must all possess, or binds
/// directly to a single user id (service accounts and one-off privilege
/// escalations). The subject taxonomy is **closed at two variants**:
/// adding a third kind is a design change to the authorization model,
/// not a local edit.
///
/// - [`GrantSubject::Claims`] — set-membership match. The grant is
///   satisfied when every claim in the set is a subset of the caller's
///   resolved `principal.claims`. The empty set is a schema error
///   (`claims_nonempty` CHECK in `001_users_roles_rbac.sql`) — it would
///   mean "no claim requirements", an unintended wildcard.
/// - [`GrantSubject::User`] — identity match against
///   `principal.user_id`. Bypasses the claim mechanism entirely; this is
///   how service accounts express their authority (ADR 0018).
///
/// Intentionally NOT `Serialize`/`Deserialize`: like the carrying
/// [`PermissionGrant`], the subject is server-constructed from validated
/// gitops config or the adapter, never deserialised from request input.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantSubject {
    /// Subset-match against `principal.claims`. Non-empty by construction
    /// (DB CHECK + apply-time linter enforce `len() >= 1`).
    Claims(Vec<String>),
    /// Identity-match against `principal.user_id`.
    User(Uuid),
}

// ---------------------------------------------------------------------------
// PermissionGrant
// ---------------------------------------------------------------------------

/// A single `(subject, permission, repository?)` grant row (ADR 0012).
///
/// `repository_id = None` means the grant is global — the subject carries
/// the permission for every repository. `repository_id = Some(_)` scopes
/// the grant to a single repository. Evaluation logic lives in
/// `hort-app::rbac::RbacEvaluator::authorize`: a `Claims(_)` subject is
/// satisfied when its claim set is a subset of `principal.claims`; a
/// `User(_)` subject is satisfied when it equals `principal.user_id`.
///
/// Grants carry a `managed_by` discriminator. Gitops-declared grants are
/// written via the managed-write port and identified across applies by a
/// subject-dependent diff key
/// (`(sorted required_claims, repository_id, permission)` for `Claims`;
/// `(user_id, repository_id, permission)` for `User`).
///
/// Intentionally NOT `Serialize`/`Deserialize`: the grant is
/// server-constructed from validated gitops config or the postgres
/// adapter, never deserialised from request input. Digesting for the
/// gitops diff happens at the adapter/apply layer, so the domain type
/// carries no serde derives, in line with the other server-constructed
/// authz types.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionGrant {
    pub id: Uuid,
    pub subject: GrantSubject,
    pub repository_id: Option<Uuid>,
    pub permission: Permission,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ClaimMapping
// ---------------------------------------------------------------------------

/// Declarative mapping from an IdP group-claim string to a registry
/// **claim name** (ADR 0012).
///
/// The IdP supplies a flat `groups` claim; operators declare which group
/// names map to which claim names; the server resolves a caller's claim
/// set by flattening the `groups` claim against the `claim_mappings`
/// table (`hort-app::rbac::resolve_claims`). `ClaimMapping` is the **only**
/// source of resolved claim names — code paths must not invent claim
/// names at runtime (ADR 0012). The single synthetic exception is
/// the `admin` claim derived from `user.is_admin=true`.
///
/// The standard managed-write semantics apply: the gitops
/// apply pipeline writes `managed_by = 'gitops'` rows with a digest;
/// `managed_by_digest` is the SHA-256 of the canonicalised spec, non-
/// `None` only for `ManagedBy::GitOps` rows (DB CHECK mirrors this).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimMapping {
    pub id: Uuid,
    pub idp_group: String,
    pub claim: String,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Permission ---------------------------------------------------------

    #[test]
    fn permission_display_lowercase() {
        assert_eq!(Permission::Read.to_string(), "read");
        assert_eq!(Permission::Write.to_string(), "write");
        assert_eq!(Permission::Delete.to_string(), "delete");
        assert_eq!(Permission::Admin.to_string(), "admin");
        assert_eq!(Permission::AdminTaskInvoke.to_string(), "admin_task_invoke");
        assert_eq!(Permission::Curate.to_string(), "curate");
        assert_eq!(Permission::Prefetch.to_string(), "prefetch");
    }

    #[test]
    fn permission_from_str_roundtrip() {
        for name in &[
            "read",
            "write",
            "delete",
            "admin",
            "admin_task_invoke",
            "curate",
            "prefetch",
        ] {
            let parsed: Permission = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn permission_from_str_case_insensitive() {
        let cases = [
            ("READ", Permission::Read),
            ("Read", Permission::Read),
            ("read", Permission::Read),
            ("WRITE", Permission::Write),
            ("Delete", Permission::Delete),
            ("ADMIN", Permission::Admin),
            ("ADMIN_TASK_INVOKE", Permission::AdminTaskInvoke),
            ("Admin_Task_Invoke", Permission::AdminTaskInvoke),
            ("admin_task_invoke", Permission::AdminTaskInvoke),
            ("CURATE", Permission::Curate),
            ("Curate", Permission::Curate),
            ("curate", Permission::Curate),
            ("PREFETCH", Permission::Prefetch),
            ("Prefetch", Permission::Prefetch),
            ("prefetch", Permission::Prefetch),
        ];
        for (input, expected) in cases {
            let parsed: Permission = input.parse().unwrap();
            assert_eq!(parsed, expected, "failed on input {input}");
        }
    }

    #[test]
    fn permission_from_str_unknown_is_validation_error() {
        let result: Result<Permission, DomainError> = "publish".parse();
        match result {
            Err(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("publish"),
                    "validation message should include the bad input, got: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn permission_copy() {
        let a = Permission::Write;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_admin_task_invoke_copy_and_eq() {
        let a = Permission::AdminTaskInvoke;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_curate_copy_and_eq() {
        let a = Permission::Curate;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_prefetch_copy_and_eq() {
        let a = Permission::Prefetch;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn permission_exhaustive_match() {
        // Force a compile error if a new variant is added without updating
        // this test. Update this test and the match arms above when adding
        // variants.
        for perm in [
            Permission::Read,
            Permission::Write,
            Permission::Delete,
            Permission::Admin,
            Permission::AdminTaskInvoke,
            Permission::Curate,
            Permission::Prefetch,
        ] {
            let _display = perm.to_string();
            let _roundtrip: Permission = _display.parse().unwrap();
            assert_eq!(_roundtrip, perm);
        }
    }

    // -- GrantSubject -------------------------------------------------------

    #[test]
    fn grant_subject_claims_clone_eq() {
        let a = GrantSubject::Claims(vec!["developer".into(), "team-alpha".into()]);
        let b = a.clone();
        assert_eq!(a, b);
        match &a {
            GrantSubject::Claims(c) => assert_eq!(c, &["developer", "team-alpha"]),
            GrantSubject::User(_) => panic!("expected Claims"),
        }
    }

    #[test]
    fn grant_subject_user_clone_eq() {
        let uid = Uuid::from_u128(0x99);
        let a = GrantSubject::User(uid);
        let b = a.clone();
        assert_eq!(a, b);
        match a {
            GrantSubject::User(u) => assert_eq!(u, uid),
            GrantSubject::Claims(_) => panic!("expected User"),
        }
    }

    #[test]
    fn grant_subject_claims_and_user_are_distinct() {
        let claims = GrantSubject::Claims(vec!["admin".into()]);
        let user = GrantSubject::User(Uuid::nil());
        assert_ne!(claims, user);
    }

    // -- PermissionGrant ----------------------------------------------------

    fn sample_grant(repository_id: Option<Uuid>, permission: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::nil(),
            subject: GrantSubject::Claims(vec!["developer".into()]),
            repository_id,
            permission,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn permission_grant_global_has_no_repository() {
        let grant = sample_grant(None, Permission::Read);
        assert!(grant.repository_id.is_none());
        assert_eq!(grant.permission, Permission::Read);
    }

    #[test]
    fn permission_grant_repo_scoped_carries_repository() {
        let repo_id = Uuid::from_u128(0x1234);
        let grant = sample_grant(Some(repo_id), Permission::Write);
        assert_eq!(grant.repository_id, Some(repo_id));
        assert_eq!(grant.permission, Permission::Write);
    }

    #[test]
    fn permission_grant_clone_eq() {
        let a = sample_grant(Some(Uuid::from_u128(42)), Permission::Delete);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn permission_grant_claims_subject_round_trips() {
        let grant = sample_grant(None, Permission::Read);
        match grant.subject {
            GrantSubject::Claims(c) => assert_eq!(c, vec!["developer".to_string()]),
            GrantSubject::User(_) => panic!("expected Claims subject"),
        }
    }

    #[test]
    fn permission_grant_user_subject_round_trips() {
        let uid = Uuid::from_u128(0xBEEF);
        let grant = PermissionGrant {
            subject: GrantSubject::User(uid),
            ..sample_grant(None, Permission::Admin)
        };
        match grant.subject {
            GrantSubject::User(u) => assert_eq!(u, uid),
            GrantSubject::Claims(_) => panic!("expected User subject"),
        }
    }

    #[test]
    fn permission_grant_managed_by_gitops_carries_digest() {
        let grant = PermissionGrant {
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xcd; 32]),
            ..sample_grant(None, Permission::Read)
        };
        assert_eq!(grant.managed_by, ManagedBy::GitOps);
        assert_eq!(grant.managed_by_digest, Some([0xcd; 32]));
    }

    // -- ClaimMapping -------------------------------------------------------

    #[test]
    fn claim_mapping_construction() {
        let mapping = ClaimMapping {
            id: Uuid::from_u128(0x1),
            idp_group: "hort-admins".into(),
            claim: "admin".into(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        assert_eq!(mapping.idp_group, "hort-admins");
        assert_eq!(mapping.claim, "admin");
        assert_eq!(mapping.managed_by, ManagedBy::Local);
        assert!(mapping.managed_by_digest.is_none());
    }

    #[test]
    fn claim_mapping_clone_eq() {
        let a = ClaimMapping {
            id: Uuid::from_u128(0x2),
            idp_group: "team-alpha".into(),
            claim: "developer".into(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn claim_mapping_managed_by_gitops_carries_digest() {
        let mapping = ClaimMapping {
            id: Uuid::from_u128(0x3),
            idp_group: "g".into(),
            claim: "admin".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        assert_eq!(mapping.managed_by, ManagedBy::GitOps);
        assert_eq!(mapping.managed_by_digest, Some([0xab; 32]));
    }
}
