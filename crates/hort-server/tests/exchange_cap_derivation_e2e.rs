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
//!
//! # Second chain — SA federation-exchange cap snapshot
//!
//! The `federation_sa_*` tests drive the sibling unattended-issuance
//! chain end to end, all in-memory: the REAL `/api/v1/auth/exchange`
//! federation handler (grants-snapshot cap derivation ∩ requested
//! scope) → the minted `hort_svc_*` bearer → the REAL
//! `PatValidationUseCase` / `AuthenticateUseCase` validate path (B1:
//! the SA principal always carries `Some(cap)`) → the REAL
//! `OciTokenExchangeUseCase` `/v2/auth` action projection
//! (grants ∩ cap → `access[]`).

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
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase;
use hort_app::use_cases::test_support::{
    sample_repository, MockApiTokenRepository, MockArtifactRepository, MockEventStore,
    MockJobsRepository, MockPolicyProjectionRepository, MockRepositoryRepository,
    MockRepositoryUpstreamMappingRepository, MockUpstreamMetadataPort, MockUserRepository,
};
use hort_app::use_cases::virtual_resolution::VirtualResolutionUseCase;
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
    let repository_access = Arc::new(RepositoryAccessUseCase::new(
        repositories.clone() as Arc<dyn RepositoryRepository>,
        RbacAccess::Disabled,
        true,
    ));
    let virtual_resolution = Arc::new(VirtualResolutionUseCase::new(
        repositories.clone() as Arc<dyn RepositoryRepository>,
        repository_access,
    ));

    let prefetch_uc = SelfServicePrefetchUseCase::new(
        repositories.clone() as Arc<dyn RepositoryRepository>,
        artifacts.clone() as Arc<dyn ArtifactRepository>,
        mappings.clone() as Arc<dyn RepositoryUpstreamMappingRepository>,
        upstream.clone() as Arc<dyn UpstreamMetadataPort>,
        jobs.clone() as Arc<dyn JobsRepository>,
        rbac.clone(),
        virtual_resolution,
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

// ---------------------------------------------------------------------------
// SA federation-exchange cap snapshot — real handler + real validate +
// real /v2/auth projection, in-memory outbound ports
// ---------------------------------------------------------------------------

mod federation_sa {
    use super::*;

    use std::time::Duration as StdDuration;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use axum::Router;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::use_cases::api_token_use_case::ApiTokenUseCase as RealApiTokenUseCase;
    use hort_app::use_cases::oci_token_exchange_use_case::{
        OciTokenExchangeConfig, OciTokenExchangeRequest, OciTokenExchangeUseCase,
    };
    use hort_app::use_cases::pat_cache::{PatCache, SystemClock};
    use hort_app::use_cases::pat_validation_use_case::{PatLockoutConfig, PatValidationUseCase};
    use hort_app::use_cases::test_support::{
        MockFederatedJwtValidator, MockOidcIssuerRepository, MockReplayGuardPort,
        MockServiceAccountRepository,
    };
    use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
    use hort_domain::entities::service_account::{FederatedIdentity, ServiceAccount};
    use hort_domain::ports::federated_jwt_validator::{FederatedJwtValidator, ValidatedClaims};
    use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
    use hort_domain::ports::service_account_repository::ServiceAccountRepository;
    use hort_http_core::context::AuthContext;
    use hort_http_core::handlers::exchange::token_exchange_routes;
    use hort_http_core::test_support::{
        build_mock_ctx, with_api_token_use_case, with_auth, with_federation_ports,
        with_oidc_issuer_repo,
    };

    use std::sync::Mutex;

    use hort_domain::entities::api_token::ApiToken;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{Page, PageRequest};

    /// Minimal in-memory [`ApiTokenRepository`] with a WORKING
    /// `find_by_prefix` — the shared `MockApiTokenRepository`
    /// deliberately returns `None` there, and this chain needs the
    /// mint-inserted row to be found by the validate leg.
    #[derive(Default)]
    struct InMemoryApiTokenRepo {
        rows: Mutex<Vec<ApiToken>>,
    }

    impl ApiTokenRepository for InMemoryApiTokenRepo {
        fn insert(&self, token: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
            self.rows.lock().unwrap().push(token.clone());
            Box::pin(async { Ok(()) })
        }

        fn find_by_prefix(&self, prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
            let result = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.token_prefix == prefix)
                .cloned();
            Box::pin(async move { Ok(result) })
        }

        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
            let result = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.id == id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "ApiToken",
                    id: id.to_string(),
                });
            Box::pin(async move { result })
        }

        fn list_for_user(
            &self,
            _user_id: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>> {
            Box::pin(async {
                Ok(Page {
                    items: Vec::new(),
                    total: 0,
                })
            })
        }

        fn update_last_used(
            &self,
            _token_id: Uuid,
            _at: chrono::DateTime<Utc>,
            _client_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn revoke(&self, _token_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn sa_backing_user_id() -> Uuid {
        Uuid::from_u128(0x5ABE)
    }

    fn sa_user_row() -> User {
        User {
            id: sa_backing_user_id(),
            username: "sa:ci-oci".into(),
            email: "sa+ci-oci@service.local".into(),
            auth_provider: AuthProvider::Local,
            external_id: Some("local:sa:ci-oci".into()),
            display_name: Some("ci-oci".into()),
            is_active: true,
            is_admin: false,
            is_service_account: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn federation_sa() -> ServiceAccount {
        let mut claims = std::collections::BTreeMap::new();
        claims.insert("repository".to_string(), "my-org/my-repo".to_string());
        ServiceAccount {
            id: Uuid::from_u128(0x5A),
            name: "ci-oci".into(),
            backing_user_id: sa_backing_user_id(),
            federated_identities: vec![FederatedIdentity {
                issuer_name: "github-actions".into(),
                claims,
            }],
            fallback_rotation: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// `GrantSubject::User` grant for the SA's backing user — the only
    /// authority shape that enters the snapshot cap.
    fn sa_grant(repo: Option<Uuid>, permission: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(sa_backing_user_id()),
            repository_id: repo,
            permission,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn validated_claims(jti: &str) -> ValidatedClaims {
        let mut all = std::collections::BTreeMap::new();
        all.insert(
            "repository".to_string(),
            serde_json::Value::String("my-org/my-repo".into()),
        );
        ValidatedClaims {
            issuer: "https://token.actions.githubusercontent.com".into(),
            issuer_name: "github-actions".into(),
            subject: "repo:my-org/my-repo:ref:refs/heads/main".into(),
            audience: "hort-server".into(),
            jti: Some(jti.to_string()),
            expires_at: Utc::now() + chrono::Duration::seconds(600),
            iat: Some(Utc::now().timestamp() - 30),
            exp_raw: (Utc::now() + chrono::Duration::seconds(600)).timestamp(),
            all_claims: all,
        }
    }

    struct Harness {
        router: Router,
        validator: Arc<MockFederatedJwtValidator>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        authenticate: Arc<AuthenticateUseCase>,
        oci_exchange: Arc<OciTokenExchangeUseCase>,
    }

    /// Wire the REAL chain with in-memory outbound ports: the federation
    /// exchange router (real `token_exchange_routes` + real
    /// `ApiTokenUseCase`), the real bearer-validate path
    /// (`AuthenticateUseCase` + `PatValidationUseCase` over the SAME
    /// token repo the mint inserts into), and the real `/v2/auth`
    /// projection (`OciTokenExchangeUseCase` over the SAME live
    /// evaluator the exchange snapshots).
    fn harness(grants: Vec<PermissionGrant>) -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(handle);

        // The OCI repo the /v2/auth scope resolves by first segment.
        let oci_repo_id = Uuid::from_u128(0x0C1);
        let mut repo = sample_repository();
        repo.id = oci_repo_id;
        repo.key = "oci-repo".into();
        repo.format = RepositoryFormat::Oci;
        mocks.repositories.insert(repo);

        mocks.users.insert(sa_user_row());

        let rbac = Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(grants)));
        let token_repo: Arc<dyn ApiTokenRepository> = Arc::new(InMemoryApiTokenRepo::default());

        // Real PAT validation over the same token repo the mint writes.
        let pat_validation = Arc::new(PatValidationUseCase::new(
            token_repo.clone(),
            mocks.users.clone() as Arc<dyn UserRepository>,
            mocks.ephemeral_durable.clone(),
            Arc::new(PatCache::new(16, StdDuration::from_secs(300))),
            Arc::new(SystemClock),
            PatLockoutConfig::DEFAULT,
        ));
        let authenticate = Arc::new(
            AuthenticateUseCase::new_local_only(
                mocks.users.clone() as Arc<dyn UserRepository>,
                Vec::new(),
            )
            .with_pat_validation(pat_validation.clone()),
        );

        // Real mint pipeline with the replay guard's success path.
        let api_token_uc = Arc::new(
            RealApiTokenUseCase::new(
                token_repo.clone(),
                mocks.users.clone(),
                wrap_for_test(mocks.events.clone()),
                rbac.clone(),
                Default::default(),
            )
            .with_replay_guard(Arc::new(MockReplayGuardPort::first_seen())),
        );

        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate: authenticate.clone(),
                rbac: rbac.clone(),
                issuer_url: None,
            },
        );
        let validator = Arc::new(MockFederatedJwtValidator::new());
        let sas = Arc::new(MockServiceAccountRepository::new());
        sas.insert(federation_sa());
        let ctx = with_federation_ports(
            &ctx,
            validator.clone() as Arc<dyn FederatedJwtValidator>,
            sas as Arc<dyn ServiceAccountRepository>,
        );
        let oidc_repo = Arc::new(MockOidcIssuerRepository::new());
        oidc_repo.seed(OidcIssuer {
            id: Uuid::new_v4(),
            name: "github-actions".into(),
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: StdDuration::from_secs(3600),
            allowed_algorithms: vec![JwtAlg::Rs256],
            require_jti: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let ctx = with_oidc_issuer_repo(&ctx, oidc_repo as Arc<dyn OidcIssuerRepository>);
        let ctx = with_api_token_use_case(&ctx, api_token_uc);

        let oci_exchange = Arc::new(OciTokenExchangeUseCase::new(
            pat_validation,
            mocks.users.clone() as Arc<dyn UserRepository>,
            rbac.clone(),
            ctx.repository_access_use_case.clone(),
            cli_session_signer_key(),
            OciTokenExchangeConfig::new("https://hort.test/v2/auth".into(), "hort.test".into()),
        ));

        let router = Router::new()
            .nest("/api/v1", token_exchange_routes())
            .with_state(ctx);
        Harness {
            router,
            validator,
            rbac,
            authenticate,
            oci_exchange,
        }
    }

    fn cli_session_signer_key() -> Arc<OciTokenSigningKey> {
        Arc::new(OciTokenSigningKey::from_pem(TEST_SIGNING_KEY_PEM, None).expect("parse key"))
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    fn exchange_form(subject_token: &str, scope: Option<&str>) -> String {
        let mut pairs = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", subject_token),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("client_id", "ci-runner/1.0"),
        ];
        if let Some(scope) = scope {
            pairs.push(("scope", scope));
        }
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// POST the exchange form and return the minted `hort_svc_*` bearer.
    async fn exchange_token(harness: &Harness, jwt_alias: &str, scope: Option<&str>) -> String {
        harness
            .validator
            .register_token(jwt_alias, validated_claims(&format!("jti-{jwt_alias}")));
        let req = Request::post("/api/v1/auth/exchange")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(exchange_form(jwt_alias, scope)))
            .unwrap();
        let resp = harness.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "exchange must mint");
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["access_token"]
            .as_str()
            .expect("access_token in exchange response")
            .to_string()
    }

    /// Validate the SA bearer on the real bearer path and return the
    /// principal (B1: `token_cap` is always `Some` for an SA token).
    async fn validate(harness: &Harness, token: &str) -> CallerPrincipal {
        harness
            .authenticate
            .authenticate_bearer(token)
            .await
            .expect("minted SA bearer must validate")
    }

    /// Project the /v2/auth `access[]` actions for one repository scope.
    async fn v2_auth_actions(harness: &Harness, token: &str, actions: &str) -> Vec<String> {
        let resp = harness
            .oci_exchange
            .exchange(OciTokenExchangeRequest {
                plaintext_pat: token.to_string(),
                service: "hort.test".into(),
                scopes: vec![format!("repository:oci-repo/library/app:{actions}")],
                client_ip: None,
            })
            .await
            .expect("/v2/auth mint succeeds (an empty grant set is not an error)");
        resp.granted_subset
            .into_iter()
            .flat_map(|entry| entry.actions)
            .collect()
    }

    #[tokio::test]
    async fn read_write_granted_sa_cap_and_v2_auth_project_both_actions() {
        let oci_repo = Uuid::from_u128(0x0C1);
        let h = harness(vec![
            sa_grant(Some(oci_repo), Permission::Read),
            sa_grant(Some(oci_repo), Permission::Write),
        ]);
        let token = exchange_token(&h, "rw-jwt", None).await;

        let principal = validate(&h, &token).await;
        let cap = principal
            .token_cap
            .expect("B1: SA principal carries Some(cap)");
        assert_eq!(
            cap.permissions,
            vec![Permission::Read, Permission::Write],
            "cap == the SA's effective-grants snapshot",
        );
        assert!(cap.repository_ids.is_none());

        assert_eq!(
            v2_auth_actions(&h, &token, "pull,push").await,
            vec!["pull".to_string(), "push".to_string()],
            "read+write grants ∩ {{Read,Write}} cap project BOTH actions",
        );
    }

    #[tokio::test]
    async fn write_only_sa_drops_pull_from_access() {
        let oci_repo = Uuid::from_u128(0x0C1);
        let h = harness(vec![sa_grant(Some(oci_repo), Permission::Write)]);
        let token = exchange_token(&h, "w-jwt", None).await;

        let principal = validate(&h, &token).await;
        assert_eq!(
            principal.token_cap.expect("Some(cap)").permissions,
            vec![Permission::Write],
        );

        assert_eq!(
            v2_auth_actions(&h, &token, "pull,push").await,
            vec!["push".to_string()],
            "pull is dropped: no Read grant and no Read in the cap",
        );
    }

    #[tokio::test]
    async fn grant_added_between_exchanges_enters_second_cap() {
        let oci_repo = Uuid::from_u128(0x0C1);
        let h = harness(vec![sa_grant(Some(oci_repo), Permission::Read)]);

        let first = exchange_token(&h, "first-jwt", None).await;
        let first_cap = validate(&h, &first).await.token_cap.expect("Some(cap)");
        assert_eq!(first_cap.permissions, vec![Permission::Read]);

        // A Write grant lands (the live evaluator swap the grant-refresh
        // path performs); the next exchange snapshots it.
        h.rbac.store(Arc::new(RbacEvaluator::new(vec![
            sa_grant(Some(oci_repo), Permission::Read),
            sa_grant(Some(oci_repo), Permission::Write),
        ])));

        let second = exchange_token(&h, "second-jwt", None).await;
        let second_cap = validate(&h, &second).await.token_cap.expect("Some(cap)");
        assert_eq!(
            second_cap.permissions,
            vec![Permission::Read, Permission::Write],
            "the second exchange's cap includes the newly-added grant",
        );
        // The FIRST token's cap stays what it was at its issuance: the
        // added grant does not widen an outstanding token.
        assert_eq!(
            validate(&h, &first)
                .await
                .token_cap
                .expect("Some(cap)")
                .permissions,
            vec![Permission::Read],
        );
    }

    #[tokio::test]
    async fn scope_read_narrows_cap_and_v2_auth_drops_push() {
        let oci_repo = Uuid::from_u128(0x0C1);
        let h = harness(vec![
            sa_grant(Some(oci_repo), Permission::Read),
            sa_grant(Some(oci_repo), Permission::Write),
        ]);
        let token = exchange_token(&h, "narrow-jwt", Some("read")).await;

        let principal = validate(&h, &token).await;
        assert_eq!(
            principal.token_cap.expect("Some(cap)").permissions,
            vec![Permission::Read],
            "scope=read narrows the read+write snapshot to {{Read}}",
        );

        // The cap leg drops push even though the Write GRANT exists:
        // the token is attenuated below the SA's full authority.
        assert_eq!(
            v2_auth_actions(&h, &token, "pull,push").await,
            vec!["pull".to_string()],
        );
    }

    #[tokio::test]
    async fn zero_grant_sa_mints_some_empty_cap_and_empty_access() {
        let h = harness(Vec::new());
        let token = exchange_token(&h, "zero-jwt", None).await;

        // B1 + fail-closed: the principal carries Some(cap) with EMPTY
        // permissions — never None, never an issuance error.
        let principal = validate(&h, &token).await;
        let cap = principal
            .token_cap
            .expect("B1: zero-grant SA principal still carries Some(cap)");
        assert!(cap.permissions.is_empty());

        assert!(
            v2_auth_actions(&h, &token, "pull,push").await.is_empty(),
            "zero-grant SA projects an empty access[]",
        );
    }
}
