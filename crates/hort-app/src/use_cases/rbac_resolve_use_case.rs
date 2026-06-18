//! `RbacResolveUseCase` (the what-if resolver).
//!
//! Backs `POST /api/v1/admin/rbac/resolve`. The admin brings the
//! identity→groups half (from their IdP); Hort resolves the
//! groups→claims→permissions half it owns. **No IdP query, no cache**
//! (deliberate non-goals): the operator supplies the user's IdP groups as
//! input and this surface flattens them through the operator-declared
//! `claim_mappings` into claims, then enumerates the
//! `(repository, permission)` cells those claims hold.
//!
//! # Why a what-if resolver instead of a per-user claim view?
//!
//! The per-user endpoint ([`super::effective_permissions_use_case`]) cannot
//! resolve a named user's claim-based authority without that user's
//! session: there is deliberately no per-user claim cache (no
//! `users.claims` column; ADR 0012) and OIDC resolves claims live at
//! each fresh-session interaction. So the audit-time mitigation for the
//! claim-based half is a *what-if* surface: the admin — who has the
//! identity→groups mapping from their own IdP / user-management — supplies
//! the groups, and Hort answers "which claims do those groups resolve to,
//! and which grants do those claims hold?". This is exactly the
//! `groups → claims → permissions` half Hort owns; the IdP owns the other
//! half.
//!
//! # Claims-only (no user identity)
//!
//! The resolver runs [`RbacEvaluator::effective_grants`] with
//! `user_id = None`: this is a *claims-only* what-if with no user identity
//! in scope, so every [`GrantSubject::User`] grant is excluded by
//! construction. `is_admin = false` is passed too — the
//! synthetic `admin` claim is a *user-attribute* fact, NOT derivable from a
//! group set. A group **mapped** to the `admin`
//! claim via a [`ClaimMapping`] still yields `global_admin: true`, because
//! [`resolve_claims`] produces `["admin"]` and `effective_grants`
//! short-circuits on the resolved-claim `"admin"` — that is the
//! OIDC-admin-onboarding path (ADR 0012), not a synthesised attribute.
//!
//! # Read-only
//!
//! No mutation, no domain event, no audit-event-per-mutation obligation
//! (that rule applies to CRUD mutations, not read inspection — mirrors the
//! per-user endpoint's read-only disposition). The admin lookup is recorded
//! at `info!` (the audit trail) per the Observability rule; there is no new
//! metric (low-volume admin reads, tracing-only).

use std::sync::Arc;

use hort_domain::entities::rbac::Permission;
use hort_domain::events::ApiActor;
use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use uuid::Uuid;

use crate::error::AppResult;
use crate::rbac::{resolve_claims, RbacEvaluator};
use crate::use_cases::CallerPrivileges;

/// One resolved effective grant — a `(repository, permission)` cell the
/// resolved claim set holds.
///
/// `repository_id = None` ⇒ a global grant (every repository);
/// `Some(_)` ⇒ scoped to a single repository. The inbound HTTP adapter
/// projects this into its own wire DTO (the domain `Permission` renders via
/// its `Display` impl; there is no domain-type `Serialize` coupling in the
/// API layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGrant {
    pub repository_id: Option<Uuid>,
    pub permission: Permission,
}

/// What-if resolution result for a supplied IdP-group set.
///
/// Constructed only by [`RbacResolveUseCase::resolve`]; the inbound adapter
/// maps this to a handler-local response DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAuthority {
    /// The claims the supplied groups resolve to via `claim_mappings`
    /// (de-duplicated, `claim_mappings`-iteration order — see
    /// [`resolve_claims`]). Empty when no group maps to a claim.
    pub resolved_claims: Vec<String>,
    /// The `(repository, permission)` cells the resolved claim set holds.
    /// Empty when `global_admin` is `true` (the marker stands in for the
    /// full authority — never an enumeration of every
    /// repository) OR when the claims hold no grant.
    pub effective_grants: Vec<ResolvedGrant>,
    /// `true` ⇒ the resolved claim set includes the `admin` claim (a group
    /// mapped to `admin` via a `ClaimMapping`); the authority is a full
    /// admin and `effective_grants` is empty (the marker).
    pub global_admin: bool,
}

/// Application use case backing `POST /api/v1/admin/rbac/resolve`.
///
/// Holds the two outbound ports it reads: [`ClaimMappingRepository`] (to
/// flatten groups → claims via [`resolve_claims`]) and
/// [`PermissionGrantRepository`] (to enumerate the held cells via a fresh
/// [`RbacEvaluator`]). Port-only, mirroring
/// [`super::effective_permissions_use_case::EffectivePermissionsUseCase`].
pub struct RbacResolveUseCase {
    claim_mappings: Arc<dyn ClaimMappingRepository>,
    grants: Arc<dyn PermissionGrantRepository>,
}

impl RbacResolveUseCase {
    /// Construct from the claim-mapping + permission-grant outbound ports.
    /// The Postgres adapters provide the production impls; the inline
    /// mocks in this module's `tests` block provide the unit-test impls.
    pub fn new(
        claim_mappings: Arc<dyn ClaimMappingRepository>,
        grants: Arc<dyn PermissionGrantRepository>,
    ) -> Self {
        Self {
            claim_mappings,
            grants,
        }
    }

    /// Resolve the claims + effective grants a supplied IdP-group set holds.
    /// Admin-only.
    ///
    /// Order of operations:
    ///
    /// 1. `require_admin()` — a non-admin caller is denied **first**, before
    ///    any port is touched (no information leak about claim-mapping /
    ///    grant topology). The denial logs `info!` (audit trail, not an
    ///    error — Observability rule: no `#[instrument(err)]`).
    /// 2. `claim_mappings.list_all()` → flatten the supplied `groups`
    ///    against the operator-declared mappings via [`resolve_claims`]
    ///    (`rbac.rs`). Empty `groups`, or groups that map to no claim,
    ///    yield an empty claim set — NOT an
    ///    error.
    /// 3. `grants.list_all()` → build a fresh [`RbacEvaluator`] from the
    ///    flat grant snapshot (the SAME construction the live evaluator
    ///    uses) and run
    ///    [`effective_grants(claims, None, false)`](RbacEvaluator::effective_grants):
    ///    `user_id = None` (claims-only what-if — no user identity, so
    ///    every `User`-subject grant is excluded) and `is_admin = false`
    ///    (the synthetic `admin` claim is NOT synthesised from a group set;
    ///    a group *mapped* to `admin` still drives `global_admin: true` via
    ///    the resolved-claim short-circuit).
    #[tracing::instrument(skip(self, privileges))]
    pub async fn resolve(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        groups: Vec<String>,
    ) -> AppResult<ResolvedAuthority> {
        // 1. Authz first — a denial never reveals claim-mapping or grant
        //    topology. Inline-log-then-return mirrors
        //    `EffectivePermissionsUseCase::for_user` / `PatchCandidateUseCase::list`.
        if let Err(e) = privileges.require_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                "rbac-resolve denied: not admin",
            );
            return Err(e);
        }

        // 2. Flatten the supplied groups → claims via the operator-declared
        //    mappings. `resolve_claims` is the SINGLE source of resolved
        //    claim names (no runtime-invented
        //    claims; ADR 0012); empty input or no-mapping groups yield `[]`.
        let mappings = self.claim_mappings.list_all().await?;
        let resolved_claims = resolve_claims(&mappings, &groups);

        // 3. Enumerate the held cells. Build a fresh evaluator from the
        //    flat grant snapshot — the SAME `RbacEvaluator::new(grants)`
        //    construction the composition root + live-refresh task use — so
        //    `effective_grants` here cannot drift from the request-time
        //    gate. `user_id = None` excludes every `User` grant
        //    (claims-only what-if); `is_admin = false` does not synthesise
        //    the `admin` claim from groups.
        let all_grants = self.grants.list_all().await?;
        let evaluator = RbacEvaluator::new(all_grants);
        let grant_set = evaluator.effective_grants(&resolved_claims, None, false);

        let effective_grants: Vec<ResolvedGrant> = grant_set
            .cells
            .into_iter()
            .map(|(repository_id, permission)| ResolvedGrant {
                repository_id,
                permission,
            })
            .collect();

        tracing::info!(
            actor_id = %actor.user_id,
            input_group_count = groups.len(),
            resolved_claim_count = resolved_claims.len(),
            result_cell_count = effective_grants.len(),
            global_admin = grant_set.is_global_admin,
            "admin resolved rbac what-if",
        );

        Ok(ResolvedAuthority {
            resolved_claims,
            effective_grants,
            global_admin: grant_set.is_global_admin,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, PermissionGrant};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::BoxFuture;

    use super::*;
    use crate::error::AppError;
    use crate::use_cases::test_support::{
        admin_privileges, api_actor, reviewer_privileges, unprivileged,
    };

    // ---- mock ClaimMappingRepository ------------------------------------

    /// Inline mock — records every `list_all()` call and returns a seeded
    /// `Vec<ClaimMapping>`. One-shot failure injection mirrors the
    /// `EffectivePermissionsUseCase::tests::MockGrantRepo` shape.
    struct MockClaimMappingRepo {
        rows: Mutex<Vec<ClaimMapping>>,
        list_all_calls: Mutex<u32>,
        fail_next: Mutex<Option<DomainError>>,
    }

    impl MockClaimMappingRepo {
        fn new() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                list_all_calls: Mutex::new(0),
                fail_next: Mutex::new(None),
            }
        }

        fn seed(&self, rows: Vec<ClaimMapping>) {
            *self.rows.lock().unwrap() = rows;
        }

        fn list_all_calls(&self) -> u32 {
            *self.list_all_calls.lock().unwrap()
        }

        fn fail_next(&self, err: DomainError) {
            *self.fail_next.lock().unwrap() = Some(err);
        }
    }

    impl ClaimMappingRepository for MockClaimMappingRepo {
        fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>> {
            Box::pin(async move {
                *self.list_all_calls.lock().unwrap() += 1;
                if let Some(e) = self.fail_next.lock().unwrap().take() {
                    return Err(e);
                }
                Ok(self.rows.lock().unwrap().clone())
            })
        }

        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn save_managed(&self, _items: &[ClaimMapping]) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // ---- mock PermissionGrantRepository ---------------------------------

    struct MockGrantRepo {
        rows: Mutex<Vec<PermissionGrant>>,
        list_all_calls: Mutex<u32>,
        fail_next: Mutex<Option<DomainError>>,
    }

    impl MockGrantRepo {
        fn new() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                list_all_calls: Mutex::new(0),
                fail_next: Mutex::new(None),
            }
        }

        fn seed(&self, rows: Vec<PermissionGrant>) {
            *self.rows.lock().unwrap() = rows;
        }

        fn list_all_calls(&self) -> u32 {
            *self.list_all_calls.lock().unwrap()
        }

        fn fail_next(&self, err: DomainError) {
            *self.fail_next.lock().unwrap() = Some(err);
        }
    }

    impl PermissionGrantRepository for MockGrantRepo {
        fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            Box::pin(async move {
                *self.list_all_calls.lock().unwrap() += 1;
                if let Some(e) = self.fail_next.lock().unwrap().take() {
                    return Err(e);
                }
                Ok(self.rows.lock().unwrap().clone())
            })
        }

        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn save_managed(&self, _items: &[PermissionGrant]) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // ---- fixtures -------------------------------------------------------

    fn mapping(idp_group: &str, claim: &str) -> ClaimMapping {
        ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: idp_group.into(),
            claim: claim.into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
        }
    }

    fn claims_grant(required: &[&str], repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(required.iter().map(|s| (*s).to_string()).collect()),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
            created_at: Utc::now(),
        }
    }

    fn user_grant(uid: Uuid, repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
            created_at: Utc::now(),
        }
    }

    fn build(
        mappings: Arc<MockClaimMappingRepo>,
        grants: Arc<MockGrantRepo>,
    ) -> RbacResolveUseCase {
        RbacResolveUseCase::new(mappings, grants)
    }

    fn groups(gs: &[&str]) -> Vec<String> {
        gs.iter().map(|s| (*s).to_string()).collect()
    }

    // ---- 403: admin gate ------------------------------------------------

    #[tokio::test]
    async fn non_admin_reviewer_is_denied_before_any_port_touched() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(mappings.clone(), grants.clone());

        let err = uc
            .resolve(api_actor(), reviewer_privileges(), groups(&["devs"]))
            .await
            .expect_err("reviewer must be forbidden");
        assert!(
            matches!(err, AppError::Domain(DomainError::Forbidden(_))),
            "expected Forbidden, got {err:?}"
        );
        // Denial must not touch either store (no info leak / no work).
        assert_eq!(mappings.list_all_calls(), 0);
        assert_eq!(grants.list_all_calls(), 0);
    }

    #[tokio::test]
    async fn fully_unprivileged_is_denied() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(mappings.clone(), grants.clone());

        let err = uc
            .resolve(api_actor(), unprivileged(), groups(&["devs"]))
            .await
            .expect_err("non-admin must be forbidden");
        assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
        assert_eq!(mappings.list_all_calls(), 0);
        assert_eq!(grants.list_all_calls(), 0);
    }

    // ---- happy path -----------------------------------------------------

    #[tokio::test]
    async fn admin_resolves_groups_to_claims_and_grants() {
        let repo_a = Uuid::new_v4();
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![
            mapping("test-developers", "developer"),
            mapping("team-alpha-grp", "team-alpha"),
        ]);
        let grants = Arc::new(MockGrantRepo::new());
        grants.seed(vec![
            // `developer` claim → two cells.
            claims_grant(&["developer"], None, Permission::Read),
            claims_grant(&["developer"], Some(repo_a), Permission::Write),
            // A grant whose required claims the resolved set doesn't fully
            // hold → excluded.
            claims_grant(&["ci-pusher"], None, Permission::Delete),
        ]);

        let uc = build(mappings, grants);
        let out = uc
            .resolve(
                api_actor(),
                admin_privileges(),
                groups(&["test-developers", "team-alpha-grp"]),
            )
            .await
            .expect("admin happy path");

        assert!(!out.global_admin);
        // Both mapped groups resolve; order follows the mappings slice.
        assert_eq!(out.resolved_claims, vec!["developer", "team-alpha"]);
        // Only the two `developer` cells hold; `ci-pusher` is excluded.
        assert_eq!(out.effective_grants.len(), 2);
        assert!(out.effective_grants.contains(&ResolvedGrant {
            repository_id: None,
            permission: Permission::Read,
        }));
        assert!(out.effective_grants.contains(&ResolvedGrant {
            repository_id: Some(repo_a),
            permission: Permission::Write,
        }));
    }

    // ---- Edge case: empty groups → empty resolution ----------------

    #[tokio::test]
    async fn empty_groups_yields_empty_resolution_not_an_error() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![mapping("devs", "developer")]);
        let grants = Arc::new(MockGrantRepo::new());
        grants.seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let uc = build(mappings, grants);
        let out = uc
            .resolve(api_actor(), admin_privileges(), Vec::new())
            .await
            .expect("empty groups is a 200, not an error");

        assert!(out.resolved_claims.is_empty());
        assert!(out.effective_grants.is_empty());
        assert!(!out.global_admin);
    }

    // ---- Edge case: groups mapping to no claim → empty -------------

    #[tokio::test]
    async fn groups_mapping_to_no_claim_yields_empty_resolution() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![mapping("devs", "developer")]);
        let grants = Arc::new(MockGrantRepo::new());
        grants.seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let uc = build(mappings, grants);
        let out = uc
            .resolve(
                api_actor(),
                admin_privileges(),
                groups(&["not-mapped", "also-not-mapped"]),
            )
            .await
            .expect("unmapped groups is a 200, not an error");

        assert!(out.resolved_claims.is_empty());
        assert!(out.effective_grants.is_empty());
        assert!(!out.global_admin);
    }

    // ---- Edge case: a group mapped to `admin` → global_admin -------

    #[tokio::test]
    async fn group_mapped_to_admin_claim_yields_global_admin_marker() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![mapping("platform-admins", "admin")]);
        let grants = Arc::new(MockGrantRepo::new());
        // A concrete grant exists, but the admin marker short-circuits the
        // enumeration: the cell list is empty (the marker means
        // "everything"), never an enumeration of every repository.
        grants.seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let uc = build(mappings, grants);
        let out = uc
            .resolve(
                api_actor(),
                admin_privileges(),
                groups(&["platform-admins"]),
            )
            .await
            .expect("admin-claim group resolves");

        assert!(
            out.global_admin,
            "a group mapped to the `admin` claim yields global_admin"
        );
        assert_eq!(out.resolved_claims, vec!["admin"]);
        assert!(
            out.effective_grants.is_empty(),
            "the admin marker stands in for the full authority — never an enumeration"
        );
    }

    // ---- Edge case: `is_admin` NOT synthesised from groups ---------

    #[tokio::test]
    async fn unmapped_admin_like_group_does_not_synthesize_admin() {
        // A group literally named "admin" that is NOT mapped to the `admin`
        // claim must NOT confer global_admin. Only a `ClaimMapping` whose
        // claim is the lowercase `admin` does; `is_admin = false` is passed
        // to `effective_grants` so a group set can never synthesise the
        // user-attribute admin.
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![mapping("admin", "developer")]); // maps to `developer`, NOT `admin`
        let grants = Arc::new(MockGrantRepo::new());
        grants.seed(vec![claims_grant(&["developer"], None, Permission::Read)]);

        let uc = build(mappings, grants);
        let out = uc
            .resolve(api_actor(), admin_privileges(), groups(&["admin"]))
            .await
            .expect("admin-named group resolves to its mapped claim");

        assert!(
            !out.global_admin,
            "is_admin is a user-attribute, never synthesised from a group name"
        );
        assert_eq!(out.resolved_claims, vec!["developer"]);
        assert_eq!(out.effective_grants.len(), 1);
    }

    // ---- claims-only: User-subject grants are excluded ------------------

    #[tokio::test]
    async fn claims_only_resolution_excludes_user_subject_grants() {
        let some_user = Uuid::new_v4();
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![mapping("devs", "developer")]);
        let grants = Arc::new(MockGrantRepo::new());
        grants.seed(vec![
            // Claims grant the resolved set holds → included.
            claims_grant(&["developer"], None, Permission::Read),
            // A `User`-subject grant — the what-if has no user identity in
            // scope (`user_id = None`), so it can NEVER match.
            user_grant(some_user, None, Permission::Admin),
        ]);

        let uc = build(mappings, grants);
        let out = uc
            .resolve(api_actor(), admin_privileges(), groups(&["devs"]))
            .await
            .expect("admin happy path");

        assert!(!out.global_admin);
        assert_eq!(
            out.effective_grants,
            vec![ResolvedGrant {
                repository_id: None,
                permission: Permission::Read,
            }],
            "User-subject grants are excluded from the claims-only what-if (user_id = None)"
        );
    }

    // ---- infrastructure error propagates --------------------------------

    #[tokio::test]
    async fn claim_mapping_repo_failure_propagates() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.fail_next(DomainError::Invariant(
            "simulated mapping-store failure".into(),
        ));
        let grants = Arc::new(MockGrantRepo::new());

        let uc = build(mappings, grants.clone());
        let err = uc
            .resolve(api_actor(), admin_privileges(), groups(&["devs"]))
            .await
            .expect_err("mapping-store error must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
        // The grant store is never reached when the mapping read fails.
        assert_eq!(grants.list_all_calls(), 0);
    }

    #[tokio::test]
    async fn grant_repo_failure_propagates() {
        let mappings = Arc::new(MockClaimMappingRepo::new());
        mappings.seed(vec![mapping("devs", "developer")]);
        let grants = Arc::new(MockGrantRepo::new());
        grants.fail_next(DomainError::Invariant(
            "simulated grant-store failure".into(),
        ));

        let uc = build(mappings, grants);
        let err = uc
            .resolve(api_actor(), admin_privileges(), groups(&["devs"]))
            .await
            .expect_err("grant-store error must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }
}
