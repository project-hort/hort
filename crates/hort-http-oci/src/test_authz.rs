//! Test-only shared harness for the quarantine hold suites
//! (`manifests` + `blobs` + `manifests_write`): RBAC-enabled
//! `AppContext` builders over an explicit grant set, the
//! capability-token principal shape the `/v2/auth` consume path
//! synthesizes, and the `provenance_mode: Required` policy seed those
//! suites need before a held row hydrates as an indefinite hold.
//! Extracted so the mirrored test modules share one implementation
//! instead of byte-identical copies.

use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum::response::Response;
use chrono::Utc;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::test_support::{
    MockIdentityProvider, MockPolicyProjectionRepository, MockRepositoryRepository,
    MockUserRepository,
};
use hort_domain::entities::api_token::TokenCap;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::scan_policy::{
    NegligibleAction, ProvenanceMode, ScanEnforcement, ScanPolicyProjection, SeverityThreshold,
};
use hort_domain::events::PolicyScope;
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

/// RBAC-enabled context with **no** grants: every actor — anonymous OR
/// authenticated — is denied `Read`, so a repo resolve collapses to
/// `NotFound`. The read-denial cutover suites use it to exercise both
/// branches of `read_denied_response` (anonymous → 401 challenge,
/// authenticated → `NAME_UNKNOWN` 404). No OCI signing key is wired, so
/// the anonymous challenge is the legacy `Basic realm="hort"` form.
pub(crate) fn denied_ctx(
    base: &Arc<AppContext>,
    repositories: Arc<MockRepositoryRepository>,
) -> Arc<AppContext> {
    rbac_grant_ctx(base, repositories, Vec::new())
}

/// [`denied_ctx`] with the OCI signing key + public base URL wired, so
/// the anonymous challenge selector emits the native-token Bearer form
/// (`realm="https://registry.example.com/v2/auth"`).
pub(crate) fn denied_ctx_bearer(
    base: &Arc<AppContext>,
    repositories: Arc<MockRepositoryRepository>,
) -> Arc<AppContext> {
    use hort_app::oci_token_signing::OciTokenSigningKey;
    use hort_http_core::test_support::{with_oci_public_base_url, with_oci_signing_key};

    let ctx = denied_ctx(base, repositories);
    let sk = OciTokenSigningKey::new(
        ed25519_dalek::SigningKey::generate(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng)),
        None,
    );
    let ctx = with_oci_signing_key(&ctx, Some(Arc::new(sk)));
    with_oci_public_base_url(&ctx, Some("https://registry.example.com".to_string()))
}

/// An authenticated principal with no backing grants — denied `Read`
/// under [`denied_ctx`], so a repo resolve `NotFound`s and the handler
/// takes the authenticated (`NAME_UNKNOWN` 404) branch rather than the
/// anonymous-challenge branch.
pub(crate) fn grantless_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "test:denied".into(),
        username: "denied-user".into(),
        email: "denied@example.com".into(),
        claims: Vec::new(),
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// Assert a repo-level read-denial response is the anonymous legacy-Basic
/// challenge: 401 + `Basic realm="hort"` + the `Docker-Distribution-API-Version`
/// header (Basic-branch parity). Header-only, so the body stays available.
pub(crate) fn assert_basic_challenge(resp: &Response) {
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap(),
        r#"Basic realm="hort""#
    );
    assert_eq!(
        resp.headers()
            .get("docker-distribution-api-version")
            .unwrap()
            .to_str()
            .unwrap(),
        "registry/2.0"
    );
}

/// Assert a repo-level read-denial response is the anonymous native-token
/// Bearer challenge (`realm=…/v2/auth`, path-derived `scope=`) with the
/// API-version header. `expected_scope` is the full `scope="…"` fragment.
pub(crate) fn assert_bearer_challenge(resp: &Response, expected_scope: &str) {
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(www.starts_with("Bearer "), "{www}");
    assert!(
        www.contains(r#"realm="https://registry.example.com/v2/auth""#),
        "{www}"
    );
    assert!(www.contains(expected_scope), "{www}");
    assert_eq!(
        resp.headers()
            .get("docker-distribution-api-version")
            .unwrap()
            .to_str()
            .unwrap(),
        "registry/2.0"
    );
}

/// Assert an authenticated-denial response is the unchanged
/// `NAME_UNKNOWN` 404 anti-enumeration envelope (no challenge). Consumes
/// the response body.
pub(crate) async fn assert_name_unknown_404(resp: Response) {
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
    let body = axum::body::to_bytes(resp.into_body(), 8 * 1024)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
}

/// Byte-comparable snapshot of a denial response — (status, challenge,
/// API-version, body) — for the anti-enumeration uniformity assertion
/// (nonexistent vs existing-private must be byte-identical).
pub(crate) async fn denial_snapshot(
    resp: Response,
) -> (StatusCode, Option<String>, Option<String>, Vec<u8>) {
    let status = resp.status();
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    let api = resp
        .headers()
        .get("docker-distribution-api-version")
        .map(|v| v.to_str().unwrap().to_string());
    let body = axum::body::to_bytes(resp.into_body(), 8 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, www, api, body)
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

/// Seed a repository-scoped `provenance_mode: Required` scan policy with
/// an explicit observation window.
///
/// The fixture half of the hold suites that `rbac_grant_ctx` above is the
/// authz half of: `ArtifactUseCase::hydrate_quarantine_deadline` resolves
/// `provenance_mode` off the matched policy, so a quarantined row only
/// hydrates as an **indefinite** hold (no self-resolving deadline, ADR
/// 0039 D4/D5) when a `Required` policy is in play and the row's window
/// anchor has already elapsed. Shared by the manifest read suite and the
/// manifest-PUT reference-resolution suite so the two cannot drift into
/// seeding materially different policies while claiming the same state.
///
/// Repository-scoped on purpose: it shadows the mock harness's permissive
/// global seed by `resolve_active_policy_for_repo` precedence, so the
/// global stays in place for every other test in the calling module.
pub(crate) fn seed_required_provenance_policy(
    projections: &MockPolicyProjectionRepository,
    repo_id: Uuid,
    quarantine_duration_secs: i64,
) {
    let now = Utc::now();
    projections.insert(ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: "required-provenance".to_string(),
        scope: PolicyScope::Repository(repo_id),
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs,
        require_approval: false,
        provenance_mode: ProvenanceMode::Required,
        provenance_backends: vec!["cosign".to_string()],
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: vec!["trivy".to_string()],
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        stream_version: 0,
        created_at: now,
        updated_at: now,
    });
}

/// Seed a repository-scoped **quarantining** scan policy with an explicit
/// observation window and `provenance_mode: Off` — the plain timed hold,
/// as opposed to [`seed_required_provenance_policy`]'s indefinite one.
///
/// Needed because the harness's pre-seeded permissive **global** policy
/// carries `quarantine_duration_secs = 0`: once an `ArtifactUseCase` has
/// the policy projections wired (which every `rbac_grant_ctx`-built
/// context now does, as does
/// `hort_http_core::test_support::with_provenance_hold_hydration`), a held
/// row's computed deadline collapses onto its anchor and
/// `check_quarantine`'s past-deadline clamp answers `Retry-After: 1`. A
/// test whose subject is the advertised window therefore has to seed the
/// window it means to assert; the resolver's `repo_scoped.or(global)`
/// precedence (`resolve_active_policy_for_repo`) makes this shadow the
/// global for this repository only, leaving every other test in the
/// calling module on the permissive default.
///
/// Returns the projection rather than inserting it, so a caller holding
/// several repositories in one test can seed per repository.
pub(crate) fn quarantining_policy_with_window(
    repo_id: Uuid,
    window_secs: i64,
) -> ScanPolicyProjection {
    let now = Utc::now();
    ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: format!("quarantining-{window_secs}s-{repo_id}"),
        scope: PolicyScope::Repository(repo_id),
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: window_secs,
        require_approval: false,
        provenance_mode: ProvenanceMode::Off,
        provenance_backends: Vec::new(),
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: vec!["trivy".to_string()],
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        stream_version: 0,
        created_at: now,
        updated_at: now,
    }
}
