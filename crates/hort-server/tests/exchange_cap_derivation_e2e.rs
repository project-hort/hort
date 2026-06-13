//! HEADLINE end-to-end test (ADR 0013): drive a per-repo-only dev-user
//! through the REAL issuance pipeline and assert the resulting
//! CliSession authorizes a JWT-only endpoint.
//!
//! # Why this test exists (the load-bearing acceptance criterion)
//!
//! The request-time JWT-only tests (`prefetch_jwt_only.rs` /
//! `discovery_jwt_only.rs`) inject a *hand-built* `CallerPrincipal`
//! into a `build_mock_ctx` router. That mock-vs-real shortcut has hidden
//! THREE defects so far (the original CLI-session claim-resolution
//! footgun, the grant-linter rejection, and a cap-clamp defect), because it never
//! exercises `exchange → cap-clamp → issue → bearer-validate → RBAC`.
//!
//! This test closes that gap. It wires the **real** use cases —
//! `ApiTokenUseCase::issue_cli_session` (the cap derivation + clamp under
//! test), the real `CliSessionTokenSigner` mint, the real
//! `AuthenticateUseCase::authenticate_bearer` verify path, the real
//! `RbacEvaluator`, and the real `SelfServicePrefetchUseCase` /
//! `DiscoveryUseCase` authorization gate — and threads the JWT through
//! the chain end to end:
//!
//! 1. Resolve the dev-user principal (claims `[developer, ci-pusher]`,
//!    no global grant — the canonical claim-based-RBAC shape (ADR 0012);
//!    in production this comes from validating the IdP `subject_token`).
//! 2. `issue_cli_session` derives the cap from the live `RbacEvaluator`
//!    (`{npm,pypi,cargo} × {read,prefetch}`), runs the per-repo clamp
//!    branch, and mints a real signed JWT. **Before the per-repo clamp
//!    branch existed this 403'd (`cap_exceeds_authority`) — the
//!    hardcoded `repository_ids: None` routed through the global
//!    branch.**
//! 3. `authenticate_bearer(jwt)` verifies the signed token, consults the
//!    denylist, re-resolves the user, and builds a principal carrying the
//!    resolved claims + `token_kind = CliSession` + `token_cap = None`.
//! 4. That validated principal hits the real prefetch + discovery
//!    use-case authorization gate → 200 (an enqueued batch / a version
//!    list), NOT a `403 token_kind_denied` or `403 cap_exceeds_authority`.
//!
//! # Two variants, one chain
//!
//! - `..._real_ports_in_memory` — the issuance touchpoints (user repo,
//!   event store) are the in-memory `test_support` mocks. It runs
//!   everywhere (Tier-1, no DB), so the mock-vs-real gap is caught in
//!   every CI run, not only when a Postgres service is present. This is
//!   the deliberately-broader-coverage choice (the DB-backed-only test
//!   silently skips with no DB, which is exactly when a local run would
//!   miss a regression). It is NOT `build_mock_ctx`: every use case in
//!   the chain is the real type, only the OUTBOUND ports are mocked.
//! - `..._db_backed` — the same chain, but the issuance user repo +
//!   event store are the REAL Postgres adapters (`PgUserRepository`,
//!   `PgEventStore`), exercising the `users` read + the `ApiTokenIssued`
//!   event append. Tier-2: skips silently when
//!   `DATABASE_URL` is unset (mirrors `task_use_case_enqueue_real_db.rs`),
//!   and carries `#[serial(hort_pg_db)]` per the DB-backed-test isolation
//!   contract.

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use serial_test::serial;
use uuid::Uuid;

use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
use hort_app::cli_session_signing::CliSessionTokenSigner;
use hort_app::event_store_publisher::{wrap_for_test, EventStorePublisher};
use hort_app::oci_token_signing::OciTokenSigningKey;
use hort_app::ports::upstream_metadata::UpstreamMetadataPort;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::api_token_use_case::{
    ApiTokenIssuanceConfig, ApiTokenUseCase, IssueCliSessionRequest,
};
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::discovery_use_case::DiscoveryUseCase;
use hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase;
use hort_app::use_cases::test_support::{
    sample_repository, MockApiTokenRepository, MockArtifactRepository, MockEventStore,
    MockJobsRepository, MockPolicyProjectionRepository, MockRepositoryRepository,
    MockRepositoryUpstreamMappingRepository, MockUpstreamMetadataPort, MockUserRepository,
};
use hort_domain::entities::api_token::TokenKind;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::discovery::PrefetchRequestItem;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::repository::{PrefetchTrigger, Repository, RepositoryFormat};
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingRepository, UpstreamAuth,
};
use hort_domain::ports::user_repository::UserRepository;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// A throwaway Ed25519 PKCS#8 PEM (mirrors
/// `cli_session_oci_rejection.rs`) — test-only signing material so
/// the test builds an `OciTokenSigningKey` without an `ed25519-dalek`
/// dev-dep.
const TEST_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIDZ8p91dvQwtVEfepJLRhRzzpZilORVQ8b4YDZcteA1T\n\
-----END PRIVATE KEY-----\n";

/// The dev-user id. Stable so the seeded user row and the resolved
/// principal align.
fn dev_user_id() -> Uuid {
    Uuid::from_u128(0xDE7)
}

/// The IdP-resolved dev-user principal that `/exchange` hands to
/// `issue_cli_session`: claims `[developer, ci-pusher]`, NO global grant,
/// `token_cap = None` (an OIDC bearer carries no cap). This is what
/// `AuthenticateUseCase::authenticate_bearer` would produce from a
/// validated IdP `subject_token` — we construct it directly because the
/// IdP-validation step is upstream of (and orthogonal to) the cap-clamp fix.
fn dev_user_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: dev_user_id(),
        external_id: "keycloak:dev".into(),
        username: "dev".into(),
        email: "dev@example.com".into(),
        claims: vec!["developer".into(), "ci-pusher".into()],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

fn dev_user_row() -> User {
    User {
        id: dev_user_id(),
        username: "dev".into(),
        email: "dev@example.com".into(),
        auth_provider: AuthProvider::Oidc,
        external_id: Some("keycloak:dev".into()),
        display_name: Some("Dev User".into()),
        is_active: true,
        is_admin: false,
        is_service_account: false,
        last_login_at: Some(Utc::now()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn npm_repo(repo_id: Uuid) -> Repository {
    let mut r = sample_repository();
    r.id = repo_id;
    r.key = "npm-proxy".into();
    r.format = RepositoryFormat::Npm;
    r.is_public = false;
    r.prefetch_policy.enabled = true;
    r.prefetch_policy.depth = 4;
    r.prefetch_policy.triggers = vec![PrefetchTrigger::TransitiveDeps];
    r
}

/// Per-repo `Read` + `Prefetch` grants for the `developer` claim on each
/// of the three repos — the canonical dev-user shape. NO global
/// grant: before the per-repo clamp branch this could never mint a
/// CliSession via the hardcoded-global request.
fn per_repo_dev_evaluator(repos: &[Uuid]) -> RbacEvaluator {
    let mut rows = Vec::new();
    for &repo in repos {
        rows.push(claims_grant("developer", repo, Permission::Read));
        rows.push(claims_grant("developer", repo, Permission::Prefetch));
    }
    RbacEvaluator::new(rows)
}

fn claims_grant(claim: &str, repo_id: Uuid, permission: Permission) -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![claim.into()]),
        repository_id: Some(repo_id),
        permission,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    }
}

fn upstream_mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
    let now = Utc::now();
    RepositoryUpstreamMapping {
        id: Uuid::new_v4(),
        repository_id: repo_id,
        path_prefix: String::new(),
        upstream_url: "https://registry.example/".into(),
        upstream_name_prefix: None,
        upstream_auth: UpstreamAuth::Anonymous,
        secret_ref: None,
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
        insecure_upstream_url: false,
        trust_upstream_publish_time: false,
        mtls_cert_ref: None,
        mtls_key_ref: None,
        ca_bundle_ref: None,
        pinned_cert_sha256: None,
        created_at: now,
        updated_at: now,
    }
}

fn cli_session_signer() -> Arc<CliSessionTokenSigner> {
    let key =
        Arc::new(OciTokenSigningKey::from_pem(TEST_SIGNING_KEY_PEM, None).expect("parse key"));
    Arc::new(CliSessionTokenSigner::new(key, "https://hort.test".into()))
}

/// `issue_cli_session` request with an explicit scope (the wire `scope`
/// form field the `/exchange` handler parses).
fn exchange_request(scope: Vec<Permission>) -> IssueCliSessionRequest {
    IssueCliSessionRequest {
        client_name: Some("hort-cli/1.0".into()),
        source_ip: "203.0.113.7".into(),
        requested_scope: scope,
        requested_lifetime_secs: None,
    }
}

/// Run the full chain `issue_cli_session → authenticate_bearer →
/// prefetch + discovery authorize` against the supplied (real) issuance
/// ports, with the in-memory prefetch/discovery ports. Returns nothing;
/// panics with a descriptive message on any link in the chain failing.
async fn drive_chain(
    tokens: Arc<dyn ApiTokenRepository>,
    users: Arc<dyn UserRepository>,
    events: Arc<EventStorePublisher>,
) {
    let npm = Uuid::from_u128(0x111);
    let pypi = Uuid::from_u128(0x222);
    let cargo = Uuid::from_u128(0x333);

    // Live, swappable evaluator shared by issuance + the endpoint gates —
    // the SAME `RbacEvaluator` the cap derivation queries at issuance is
    // the one the prefetch/discovery gate re-checks at request time.
    let rbac = Arc::new(ArcSwap::from_pointee(per_repo_dev_evaluator(&[
        npm, pypi, cargo,
    ])));

    let signer = cli_session_signer();
    let denylist: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());

    // --- Real ApiTokenUseCase: derive cap + clamp + mint JWT -----------
    let api_token_uc = ApiTokenUseCase::new(
        tokens,
        users.clone(),
        events,
        rbac.clone(),
        ApiTokenIssuanceConfig::default(),
    )
    .with_cli_session_signing(signer.clone(), denylist.clone());

    let principal = dev_user_principal();
    // Scope the CLI asks for: read + prefetch (the JWT-only endpoints'
    // amplification shape). Without the per-repo clamp branch this 403'd
    // because the hardcoded global request demanded GLOBAL Read+Prefetch,
    // which the per-repo grantee lacks.
    let issued = api_token_uc
        .issue_cli_session(
            &principal,
            exchange_request(vec![Permission::Read, Permission::Prefetch]),
        )
        .await
        .expect(
            "per-repo dev-user MUST mint a CliSession (pre-fix this \
             was 403 cap_exceeds_authority via the hardcoded global request)",
        );
    assert_eq!(issued.kind, TokenKind::CliSession);
    let jwt = issued.plaintext;
    assert_eq!(jwt.split('.').count(), 3, "expected a signed JWT");

    // --- Real AuthenticateUseCase: verify the JWT, build principal -----
    // Local-only (no IdP): the CliSession verify path runs before the
    // OIDC fallthrough, so the minted token never needs an IdP.
    let authenticate = AuthenticateUseCase::new_local_only(users.clone(), Vec::new())
        .with_cli_session_verification(signer.clone(), denylist.clone());

    let validated = authenticate
        .authenticate_bearer(&jwt)
        .await
        .expect("the minted CliSession JWT must validate on the bearer path");
    assert_eq!(
        validated.token_kind,
        Some(TokenKind::CliSession),
        "validated principal must be a CliSession",
    );
    assert!(
        validated.claims.contains(&"developer".to_string())
            && validated.claims.contains(&"ci-pusher".to_string()),
        "validated principal must carry the resolved claims, got {:?}",
        validated.claims,
    );
    assert!(
        validated.token_cap.is_none(),
        "CliSession authority is claims + live grants; no cap leg",
    );

    // --- Real endpoints: prefetch + discovery authorize the principal --
    let repositories = Arc::new(MockRepositoryRepository::new());
    repositories.insert(npm_repo(npm));
    let artifacts = Arc::new(MockArtifactRepository::new());
    let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
    mappings
        .upsert(upstream_mapping(npm))
        .await
        .expect("seed upstream mapping");
    let upstream = Arc::new(MockUpstreamMetadataPort::new());
    upstream.insert_versions("npm", "left-pad", Ok(vec!["1.0.0".into()]));
    let jobs = Arc::new(MockJobsRepository::new());

    let prefetch_uc = SelfServicePrefetchUseCase::new(
        repositories.clone() as Arc<dyn RepositoryRepository>,
        artifacts.clone() as Arc<dyn ArtifactRepository>,
        mappings.clone() as Arc<dyn RepositoryUpstreamMappingRepository>,
        upstream.clone() as Arc<dyn UpstreamMetadataPort>,
        jobs.clone() as Arc<dyn JobsRepository>,
        rbac.clone(),
    );

    let outcome = prefetch_uc
        .enqueue_self_service(
            "npm-proxy",
            vec![PrefetchRequestItem {
                package: "left-pad".into(),
                version: Some("1.0.0".into()),
            }],
            &validated,
        )
        .await
        .expect(
            "the validated CliSession MUST authorize the JWT-only prefetch \
             endpoint (200) — the full exchange→clamp→issue→validate→RBAC chain",
        );
    assert_eq!(
        outcome.enqueued_job_ids.len(),
        1,
        "the prefetch batch must enqueue the requested item (200)",
    );

    // Discovery (Permission::Read alone) authorizes too.
    let discovery_uc = DiscoveryUseCase::new(
        repositories as Arc<dyn RepositoryRepository>,
        artifacts as Arc<dyn ArtifactRepository>,
        mappings as Arc<dyn RepositoryUpstreamMappingRepository>,
        upstream as Arc<dyn UpstreamMetadataPort>,
        rbac,
        Arc::new(MockPolicyProjectionRepository::new())
            as Arc<
                dyn hort_domain::ports::policy_projection_repository::PolicyProjectionRepository,
            >,
    );
    let listing = discovery_uc
        .list_versions("npm-proxy", "left-pad", Some(&validated))
        .await
        .expect("the validated CliSession MUST authorize discovery (Read) → 200");
    assert!(
        listing.versions.iter().any(|v| v.version == "1.0.0"),
        "discovery must return the upstream version list, got {:?}",
        listing.versions,
    );
}

// ---------------------------------------------------------------------------
// Variant 1 — real use cases, in-memory outbound ports (always runs)
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn per_repo_dev_user_mints_and_authorizes_endpoint_real_ports_in_memory() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let tokens: Arc<dyn ApiTokenRepository> = Arc::new(MockApiTokenRepository::new());
        let users = Arc::new(MockUserRepository::new());
        users.insert(dev_user_row());
        let events = wrap_for_test(Arc::new(MockEventStore::new()));
        drive_chain(tokens, users as Arc<dyn UserRepository>, events).await;
    });
}

// ---------------------------------------------------------------------------
// Variant 2 — real Postgres issuance ports (Tier-2, skips without a DB)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn per_repo_dev_user_mints_and_authorizes_endpoint_db_backed() {
    use hort_adapters_postgres::{event_store::PgEventStore, user_repo::PgUserRepository};
    use sqlx::PgPool;

    let Some(url) = env::var("DATABASE_URL").ok() else {
        // No DATABASE_URL — silently skip (matches the Tier-2 convention
        // used by `task_use_case_enqueue_real_db.rs` and friends).
        return;
    };
    let Some(pool): Option<PgPool> =
        hort_adapters_postgres::test_support::isolated_db_from(&url).await
    else {
        return;
    };
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");

    // Seed the dev-user row the issuance + validate paths re-resolve.
    let uid = dev_user_id();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, external_id, is_active, is_admin) \
         VALUES ($1, $2, $3, 'oidc', $4, true, false)",
    )
    .bind(uid)
    .bind("dev")
    .bind("dev@example.com")
    .bind("keycloak:dev")
    .execute(&pool)
    .await
    .expect("seed dev user");

    let tokens: Arc<dyn ApiTokenRepository> =
        Arc::new(hort_adapters_postgres::api_token_repo::PgApiTokenRepository::new(pool.clone()));
    let users: Arc<dyn UserRepository> = Arc::new(PgUserRepository::new(pool.clone()));
    let raw_events: Arc<dyn EventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new (immutability trigger installed by migrations)"),
    );
    let events: Arc<EventStorePublisher> =
        Arc::new(EventStorePublisher::without_broadcast(raw_events));

    drive_chain(tokens, users, events).await;
}
