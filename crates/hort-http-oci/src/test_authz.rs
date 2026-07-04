//! Test-only shared authz harness for the quarantine hold-exemption
//! suites (`manifests` + `blobs`): RBAC-enabled `AppContext` builders
//! over an explicit grant set, and the capability-token principal shape
//! the `/v2/auth` consume path synthesizes. Extracted so the two
//! mirrored test modules share one implementation instead of
//! byte-identical copies.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::test_support::{
    MockIdentityProvider, MockRepositoryRepository, MockUserRepository,
};
use hort_domain::entities::api_token::TokenCap;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::user_repository::UserRepository;
use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::test_support::{with_auth, with_repository_access};

/// Build an RBAC-enabled context over an explicit grant set, reusing
/// the harness's `repositories` mock so seeded repos resolve.
pub(crate) fn rbac_grant_ctx(
    base: &Arc<AppContext>,
    repositories: Arc<MockRepositoryRepository>,
    grants: Vec<PermissionGrant>,
) -> Arc<AppContext> {
    let rbac_swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(grants)));
    let authenticate = Arc::new(AuthenticateUseCase::new(
        Arc::new(MockIdentityProvider::new()) as Arc<dyn IdentityProvider>,
        Arc::new(MockUserRepository::new()) as Arc<dyn UserRepository>,
        Vec::new(),
    ));
    let ctx = with_auth(
        base,
        AuthContext::Enabled {
            authenticate,
            rbac: rbac_swap.clone(),
            issuer_url: None,
        },
    );
    let access = Arc::new(RepositoryAccessUseCase::new(
        repositories,
        RbacAccess::Enabled(rbac_swap),
        true,
    ));
    with_repository_access(&ctx, access)
}

/// RBAC-enabled context granting `claim` repo-wide `Write`.
pub(crate) fn write_grant_ctx(
    base: &Arc<AppContext>,
    repositories: Arc<MockRepositoryRepository>,
    claim: &str,
) -> Arc<AppContext> {
    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![claim.to_string()]),
        repository_id: None,
        permission: Permission::Write,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    rbac_grant_ctx(base, repositories, vec![grant])
}

/// RBAC-enabled context where `uid` holds `perms` repo-wide via
/// User-subject grants — the authority shape `/v2/auth`-minted
/// capability principals resolve against (claims stay empty on that
/// surface).
pub(crate) fn user_grant_ctx(
    base: &Arc<AppContext>,
    repositories: Arc<MockRepositoryRepository>,
    uid: Uuid,
    perms: &[Permission],
) -> Arc<AppContext> {
    let grants = perms
        .iter()
        .map(|&permission| PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id: None,
            permission,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        })
        .collect();
    rbac_grant_ctx(base, repositories, grants)
}

/// A capability-token-shaped principal: the shape
/// `synthesize_principal_from_jwt` builds for a pull-scoped `/v2/auth`
/// JWT — claims empty, `token_cap = Some([Read])`, authority carried by
/// User-subject grants of `uid`.
pub(crate) fn pull_scoped_cap_principal(uid: Uuid) -> CallerPrincipal {
    CallerPrincipal {
        user_id: uid,
        external_id: format!("oci-jwt:{uid}"),
        username: format!("oci-jwt:{uid}"),
        email: String::new(),
        claims: Vec::new(),
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: Some(TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: None,
        }),
    }
}
