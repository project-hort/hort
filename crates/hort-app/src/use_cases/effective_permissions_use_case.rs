//! `EffectivePermissionsUseCase`.
//!
//! Admin-only inspection surface answering "what does the registry know
//! about user X *without their token*?". This is the audit-time
//! mitigation for the
//! operator-discipline cost of the additive-claims model (ADR 0012):
//! structural `(role, org)` RBAC could not let a grant
//! slip past the schema; additive-claims shifts that to operator
//! discipline, and the grant linter plus this endpoint are the two
//! load-bearing mitigations.
//!
//! # No claims store — what this surface can honestly show
//!
//! There is **no per-user claim cache**: the claim-based RBAC model
//! deliberately has no `users.claims` / `api_tokens.claims` column
//! (a structural design choice — ADR 0012). OIDC resolves
//! `principal.claims` *live*
//! at each fresh-session interaction via the `claim_mappings` table.
//! So an admin inspecting a user *who is not presenting a
//! token* has no claim set to show.
//!
//! The surface therefore carries no `claims`
//! field; instead it exposes a
//! single [`EffectivePermissions::claim_based_authority`] marker
//! ([`CLAIM_BASED_AUTHORITY_UNRESOLVABLE`]) plus a doc pointer to the
//! what-if resolver (`POST /api/v1/admin/rbac/resolve`). What it shows is
//! exactly what the registry genuinely knows per-user without a session:
//! `is_admin`,
//! every `GrantSubject::User(user_id)` grant, and (for an `is_admin` user)
//! every grant the synthetic `admin` claim
//! satisfies. Resolving the live OIDC-derived claim set would require
//! either a cache (structurally closed) or replaying the IdP exchange
//! (impossible without the caller's token) — both rejected; the what-if
//! resolver covers the claim-based half by taking the operator's IdP
//! groups as input. See `docs/architecture/how-to/operate/claim-based-rbac.md`.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::rbac::{GrantSubject, Permission};
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::user_repository::UserRepository;

use crate::error::{AppError, AppResult};
use crate::metrics::{emit_effective_permissions_lookup, EffectivePermissionsResult};
use crate::rbac::{add_admin_claim_if_admin, subject_matches};
use crate::use_cases::CallerPrivileges;

/// Stable wire value of the [`EffectivePermissions::claim_based_authority`]
/// marker. The per-user endpoint cannot resolve a user's
/// claim-based authority without that user's session: there is no per-user
/// claim cache (the column is structurally closed — ADR 0012) and OIDC
/// resolves claims
/// live at login. An admin who needs the claim-based half supplies the
/// user's IdP groups to `POST /api/v1/admin/rbac/resolve`,
/// which resolves the `groups → claims → permissions` half the registry
/// owns.
pub const CLAIM_BASED_AUTHORITY_UNRESOLVABLE: &str = "not_resolvable_without_session";

/// One grant that is currently effective for the inspected user.
///
/// `source` is the matching [`GrantSubject`] verbatim from the grant
/// row so an auditor can see *why* the grant applies (which claim set,
/// or a direct user binding). The domain `GrantSubject` is intentionally
/// not `Serialize`; the inbound HTTP adapter projects this into its own
/// wire DTO (no domain-type `Deserialize`/wire
/// coupling in the API layer).
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveGrant {
    /// `None` ⇒ the grant is global (every repository). `Some(_)` ⇒
    /// scoped to a single repository.
    pub repository_id: Option<Uuid>,
    pub permission: Permission,
    pub source: GrantSubject,
}

/// Resolved effective-permissions view for one user.
///
/// Constructed only by [`EffectivePermissionsUseCase::for_user`]; the
/// inbound adapter maps this to a handler-local response DTO.
///
/// Carries only what HORT knows about a user *without their token*: the
/// `is_admin` bit and the matching grant rows. The user's claim-based
/// authority is intentionally *absent* — see
/// [`Self::claim_based_authority`].
#[derive(Debug, Clone, PartialEq)]
pub struct EffectivePermissions {
    pub user_id: Uuid,
    pub is_admin: bool,
    /// Honest marker for the claim-based authority this surface cannot
    /// resolve without the user's session. Always
    /// [`CLAIM_BASED_AUTHORITY_UNRESOLVABLE`] — there is no claims cache
    /// and OIDC resolves claims live at login. To resolve the
    /// claim-based half, an admin supplies the user's IdP groups to
    /// `POST /api/v1/admin/rbac/resolve`.
    pub claim_based_authority: &'static str,
    /// Every grant whose subject currently matches this user: every
    /// `GrantSubject::User(user_id)` grant, plus (when `is_admin`) every
    /// grant the synthetic `admin` claim satisfies.
    pub grants: Vec<EffectiveGrant>,
}

/// Application use case backing
/// `GET /api/v1/admin/users/:user_id/effective-permissions`.
pub struct EffectivePermissionsUseCase {
    users: Arc<dyn UserRepository>,
    grants: Arc<dyn PermissionGrantRepository>,
}

impl EffectivePermissionsUseCase {
    /// Construct from the user + permission-grant outbound ports. The
    /// Postgres adapters provide the production impls; the inline mocks
    /// in this module's `tests` block provide the unit-test impls.
    pub fn new(users: Arc<dyn UserRepository>, grants: Arc<dyn PermissionGrantRepository>) -> Self {
        Self { users, grants }
    }

    /// Resolve the effective permissions of `user_id`. Admin-only.
    ///
    /// Order of operations (each early-return emits the matching
    /// `hort_effective_permissions_lookups_total{result}` series exactly
    /// once before returning):
    ///
    /// 1. `require_admin()` — non-admin callers are denied *before* the
    ///    inspected user is resolved (no information leak about whether
    ///    the target exists). Emits `result=denied`, logs `info!`
    ///    (audit trail, not an error — Observability rule: no
    ///    `#[instrument(err)]`).
    /// 2. Resolve the inspected user. `DomainError::NotFound` ⇒
    ///    `result=not_found`. Any other repo error propagates without a
    ///    metric (infrastructure failure, logged by the adapter layer).
    /// 3. Build the *internal* effective claim set used only to match
    ///    grants — `[]` + the synthetic `admin` claim iff `user.is_admin`
    ///    (via the shared `add_admin_claim_if_admin`
    ///    — claim names are never invented here). This set
    ///    is **not** returned (there is no `claims`
    ///    field); it only feeds the grant scan in step 4.
    /// 4. Scan every grant; keep those whose subject matches via the
    ///    shared [`subject_matches`] primitive (`User(uid)` identity match,
    ///    or `Claims(req)` subset of the effective claim set — one
    ///    authority source). Emits `result=ok`.
    #[tracing::instrument(skip(self, privileges), fields(inspected_user_id = %user_id))]
    pub async fn for_user(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        user_id: Uuid,
    ) -> AppResult<EffectivePermissions> {
        // 1. Authz first — a denial never reveals whether `user_id`
        //    resolves. Inline-log-then-return mirrors
        //    `PatchCandidateUseCase::list`.
        if let Err(e) = privileges.require_admin() {
            tracing::info!(
                inspecting_user_id = %actor.user_id,
                "effective-permissions lookup denied: not admin",
            );
            emit_effective_permissions_lookup(EffectivePermissionsResult::Denied);
            return Err(e);
        }

        // 2. Resolve the inspected user. `NotFound` is a caller-input
        //    outcome (404), distinct from an infrastructure failure
        //    (propagated, no metric — the adapter layer logs it).
        let user = match self.users.find_by_id(user_id).await {
            Ok(u) => u,
            Err(DomainError::NotFound { .. }) => {
                tracing::info!(
                    inspecting_user_id = %actor.user_id,
                    "effective-permissions lookup: inspected user not found",
                );
                emit_effective_permissions_lookup(EffectivePermissionsResult::NotFound);
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "User",
                    id: user_id.to_string(),
                }));
            }
            Err(other) => return Err(other.into()),
        };

        // 3. Effective claim set. No claims cache exists;
        //    the resolved set is empty plus the synthetic `admin` claim
        //    iff `is_admin`. `add_admin_claim_if_admin` is the single
        //    source of the synthetic-admin rule —
        //    not re-encoded here.
        let mut effective_claims: Vec<String> = Vec::new();
        add_admin_claim_if_admin(&mut effective_claims, user.is_admin);

        // 4. Enumerate matching grants. The per-grant subject test is the
        //    SAME `subject_matches` primitive `RbacEvaluator::user_grants_authorize`
        //    and `effective_grants` use (one authority
        //    source, no parallel `GrantSubject` match). The global admin
        //    short-circuit is deliberately *not* applied here: the surface
        //    must show the actual matching grant rows (keeping each row's
        //    subject, which `effective_grants`' cell-flattening would
        //    drop), and the synthetic `admin` claim already makes
        //    `Claims(["admin"])` grants match via the subset test.
        let all = self.grants.list_all().await?;
        let grants: Vec<EffectiveGrant> = all
            .into_iter()
            .filter(|g| subject_matches(&g.subject, &effective_claims, Some(user_id)))
            .map(|g| EffectiveGrant {
                repository_id: g.repository_id,
                permission: g.permission,
                source: g.subject,
            })
            .collect();

        tracing::info!(
            inspecting_user_id = %actor.user_id,
            result_count = grants.len(),
            "admin queried effective permissions for user",
        );
        emit_effective_permissions_lookup(EffectivePermissionsResult::Ok);

        Ok(EffectivePermissions {
            user_id,
            is_admin: user.is_admin,
            claim_based_authority: CLAIM_BASED_AUTHORITY_UNRESOLVABLE,
            grants,
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
    use hort_domain::entities::rbac::PermissionGrant;
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::error::DomainResult;
    use hort_domain::ports::BoxFuture;

    use super::*;
    use crate::use_cases::test_support::{
        api_actor, reviewer_privileges, unprivileged, MockUserRepository,
    };

    /// Inline mock — records every `list_all()` call and returns a
    /// seeded `Vec<PermissionGrant>`. One-shot failure injection mirrors
    /// the `PatchCandidateUseCase::tests::MockRepo` shape.
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

    fn user(id: Uuid, is_admin: bool) -> User {
        User {
            id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("oidc:alice".into()),
            display_name: Some("Alice".into()),
            is_active: true,
            is_admin,
            is_service_account: false,
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
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
        users: Arc<MockUserRepository>,
        grants: Arc<MockGrantRepo>,
    ) -> EffectivePermissionsUseCase {
        EffectivePermissionsUseCase::new(users, grants)
    }

    // ---------- 403: admin gate ------------------------------------------

    #[tokio::test]
    async fn non_admin_reviewer_is_denied_before_user_resolution() {
        let users = Arc::new(MockUserRepository::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(users.clone(), grants.clone());

        let err = uc
            .for_user(api_actor(), reviewer_privileges(), Uuid::new_v4())
            .await
            .expect_err("reviewer must be forbidden");
        assert!(
            matches!(err, AppError::Domain(DomainError::Forbidden(_))),
            "expected Forbidden, got {err:?}"
        );
        // Denial must not touch the grant store (no info leak / no work).
        assert_eq!(grants.list_all_calls(), 0);
    }

    #[tokio::test]
    async fn fully_unprivileged_is_denied() {
        let users = Arc::new(MockUserRepository::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(users, grants.clone());

        let err = uc
            .for_user(api_actor(), unprivileged(), Uuid::new_v4())
            .await
            .expect_err("non-admin must be forbidden");
        assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
        assert_eq!(grants.list_all_calls(), 0);
    }

    // ---------- 404: unknown user ----------------------------------------

    #[tokio::test]
    async fn admin_inspecting_unknown_user_returns_not_found() {
        let users = Arc::new(MockUserRepository::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(users, grants.clone());

        let err = uc
            .for_user(api_actor(), admin_privs(), Uuid::new_v4())
            .await
            .expect_err("unknown user must be NotFound");
        match err {
            AppError::Domain(DomainError::NotFound { entity, .. }) => {
                assert_eq!(entity, "User");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        // NotFound happens before the grant scan.
        assert_eq!(grants.list_all_calls(), 0);
    }

    // ---------- happy path: shape ----------------------------------------

    #[tokio::test]
    async fn admin_inspecting_known_non_admin_user_returns_matching_grants() {
        let uid = Uuid::new_v4();
        let repo_a = Uuid::new_v4();

        let users = Arc::new(MockUserRepository::new());
        users.insert(user(uid, false));

        let grants = Arc::new(MockGrantRepo::new());
        // Two matching (direct-user) grants + one non-matching (other
        // user, and a claims grant the empty claim set can't satisfy).
        let g1 = user_grant(uid, Some(repo_a), Permission::Write);
        let g2 = user_grant(uid, None, Permission::Read);
        let other = user_grant(Uuid::new_v4(), None, Permission::Admin);
        let unreachable_claims = claims_grant(&["developer"], None, Permission::Write);
        grants.seed(vec![g1.clone(), other, g2.clone(), unreachable_claims]);

        let uc = build(users, grants);
        let out = uc
            .for_user(api_actor(), admin_privs(), uid)
            .await
            .expect("admin happy path");

        assert_eq!(out.user_id, uid);
        // There is no `claims` field; the
        // honest marker stands in its place.
        assert_eq!(
            out.claim_based_authority,
            CLAIM_BASED_AUTHORITY_UNRESOLVABLE
        );
        assert!(!out.is_admin);
        assert_eq!(out.grants.len(), 2, "only the two User({uid}) grants match");
        assert!(out.grants.iter().any(|g| g
            == &EffectiveGrant {
                repository_id: Some(repo_a),
                permission: Permission::Write,
                source: GrantSubject::User(uid),
            }));
        assert!(out.grants.iter().any(|g| g
            == &EffectiveGrant {
                repository_id: None,
                permission: Permission::Read,
                source: GrantSubject::User(uid),
            }));
    }

    #[tokio::test]
    async fn admin_user_matches_synthetic_admin_claim_grants() {
        let uid = Uuid::new_v4();
        let users = Arc::new(MockUserRepository::new());
        users.insert(user(uid, true)); // is_admin ⇒ synthetic `admin`

        let grants = Arc::new(MockGrantRepo::new());
        let admin_grant = claims_grant(&["admin"], None, Permission::Admin);
        let dev_grant = claims_grant(&["developer"], None, Permission::Write);
        let direct = user_grant(uid, None, Permission::Delete);
        grants.seed(vec![admin_grant.clone(), dev_grant, direct.clone()]);

        let uc = build(users, grants);
        let out = uc
            .for_user(api_actor(), admin_privs(), uid)
            .await
            .expect("admin happy path");

        assert!(out.is_admin);
        // No `claims` field; the marker is constant.
        assert_eq!(
            out.claim_based_authority,
            CLAIM_BASED_AUTHORITY_UNRESOLVABLE
        );
        // The synthetic `admin` claim still drives the
        // grant match below — the `admin`-claim grant matches via the
        // subset test; the `developer` grant does not (claim set is just
        // `["admin"]`); the direct-user grant matches on identity.
        assert_eq!(out.grants.len(), 2);
        assert!(out
            .grants
            .iter()
            .any(|g| g.source == GrantSubject::Claims(vec!["admin".into()])));
        assert!(out
            .grants
            .iter()
            .any(|g| g.source == GrantSubject::User(uid)));
        assert!(out
            .grants
            .iter()
            .all(|g| g.source != GrantSubject::Claims(vec!["developer".into()])));
    }

    #[tokio::test]
    async fn no_matching_grants_yields_empty_vec() {
        let uid = Uuid::new_v4();
        let users = Arc::new(MockUserRepository::new());
        users.insert(user(uid, false));

        let grants = Arc::new(MockGrantRepo::new());
        grants.seed(vec![
            user_grant(Uuid::new_v4(), None, Permission::Write),
            claims_grant(&["developer", "team-alpha"], None, Permission::Read),
        ]);

        let uc = build(users, grants);
        let out = uc
            .for_user(api_actor(), admin_privs(), uid)
            .await
            .expect("admin happy path");
        assert!(out.grants.is_empty());
        assert_eq!(
            out.claim_based_authority,
            CLAIM_BASED_AUTHORITY_UNRESOLVABLE
        );
        assert!(!out.is_admin);
    }

    // ---------- infrastructure error propagates without a metric --------

    #[tokio::test]
    async fn grant_repo_failure_propagates() {
        let uid = Uuid::new_v4();
        let users = Arc::new(MockUserRepository::new());
        users.insert(user(uid, false));

        let grants = Arc::new(MockGrantRepo::new());
        grants.fail_next(DomainError::Invariant("simulated adapter failure".into()));

        let uc = build(users, grants);
        let err = uc
            .for_user(api_actor(), admin_privs(), uid)
            .await
            .expect_err("repo error must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }

    fn admin_privs() -> CallerPrivileges {
        crate::use_cases::test_support::admin_privileges()
    }

    // ---------- metric emission ------------------------------------------

    fn assert_effective_permissions_emitted_once(
        snap: metrics_util::debugging::Snapshot,
        expected_result: &str,
    ) {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let entries = snap.into_vec();
        let mut hits = entries.iter().filter(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_effective_permissions_lookups_total"
        });
        let (key, _, _, value) = hits
            .next()
            .expect("hort_effective_permissions_lookups_total must fire exactly once");
        assert!(
            hits.next().is_none(),
            "metric must fire only once per use-case call"
        );

        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&expected_result));
        // No high-cardinality actor / user labels (actor
        // attribution lives in the info! span, not the metric).
        for forbidden in &[
            "user_id",
            "inspected_user_id",
            "actor_id",
            "inspecting_user_id",
        ] {
            assert!(
                !labels.contains_key(*forbidden),
                "forbidden label `{forbidden}` must not appear"
            );
        }
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn emits_result_ok_on_happy_path() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let uid = Uuid::new_v4();
        let users = Arc::new(MockUserRepository::new());
        users.insert(user(uid, false));
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(users, grants);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.for_user(api_actor(), admin_privs(), uid))
                .expect("admin happy path");
        });

        assert_effective_permissions_emitted_once(snapshotter.snapshot(), "ok");
    }

    #[test]
    fn emits_result_denied_on_non_admin() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let users = Arc::new(MockUserRepository::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(users, grants);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.for_user(api_actor(), reviewer_privileges(), Uuid::new_v4()))
                .expect_err("non-admin must be forbidden");
        });

        assert_effective_permissions_emitted_once(snapshotter.snapshot(), "denied");
    }

    #[test]
    fn emits_result_not_found_on_unknown_user() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let users = Arc::new(MockUserRepository::new());
        let grants = Arc::new(MockGrantRepo::new());
        let uc = build(users, grants);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.for_user(api_actor(), admin_privs(), Uuid::new_v4()))
                .expect_err("unknown user must be NotFound");
        });

        assert_effective_permissions_emitted_once(snapshotter.snapshot(), "not_found");
    }
}
