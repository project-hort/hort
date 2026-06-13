//! A non-CliSession AK-JWT (an OCI `/v2/auth` token) presented on the
//! bearer path is REJECTED (ADR 0013).
//!
//! The CliSession access token and the OCI `/v2/auth` token are both
//! signed by the shared `OciTokenSigningKey` Ed25519 primitive, so
//! **issuer/signature alone do NOT separate them.**
//! The discriminator is the CliSession-specific `aud`
//! (`urn:hort:cli-session`) + the `token_kind = "cli_session"` payload
//! claim. Without this, an OCI pull token could replay against the
//! CliSession-gated discovery/prefetch endpoints (which route through
//! the shared `AuthenticateUseCase::authenticate_bearer` bearer path,
//! NOT the OCI-path `oci_bearer_auth` middleware).
//!
//! This is the negative test the acceptance list mandates: an OCI-scope
//! AK-JWT minted with the SAME key the CliSession verifier holds must
//! NOT yield a CliSession principal. It falls through to the OIDC
//! validator (the mock IdP rejects it) → a 401-shaped error. It is
//! never `CliSessionVerifyOutcome::Verified`, so it can never carry
//! claims into a CliSession-gated authorization.

use std::sync::Arc;

use chrono::Utc;
use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
use hort_app::cli_session_signing::CliSessionTokenSigner;
use hort_app::error::AppError;
use hort_app::oci_token_signing::{AccessEntry, OciAccessClaims, OciTokenSigningKey};
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::user_repository::UserRepository;
use uuid::Uuid;

/// A throwaway Ed25519 PKCS#8 PEM (generated with
/// `openssl genpkey -algorithm ed25519`) — test-only signing material,
/// never used in production. Lets the test build an `OciTokenSigningKey`
/// without an `ed25519-dalek` dev-dep.
const TEST_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIDZ8p91dvQwtVEfepJLRhRzzpZilORVQ8b4YDZcteA1T\n\
-----END PRIVATE KEY-----\n";

#[tokio::test]
async fn oci_v2_auth_token_is_rejected_on_the_cli_session_bearer_path() {
    // Shared signing key — the OCI token and the CliSession verifier
    // use the SAME Ed25519 key (deliberate key reuse). Issuer + signature
    // are therefore identical across the two families.
    let shared_key =
        Arc::new(OciTokenSigningKey::from_pem(TEST_SIGNING_KEY_PEM, None).expect("parse test key"));

    // CliSession verifier over the shared key.
    let cli_verifier = Arc::new(CliSessionTokenSigner::new(
        shared_key.clone(),
        "https://hort.test".to_string(),
    ));
    let denylist: Arc<dyn EphemeralStore> = Arc::new(InMemoryEphemeralStore::new());

    let sub = Uuid::from_u128(0x0C1);
    let idp = Arc::new(MockIdentityProvider::new());
    let users = Arc::new(MockUserRepository::new());
    // Seed a user matching the OCI token's `sub` — to prove the
    // rejection is NOT merely "unknown user" but the discriminator: a
    // valid-signature, known-sub OCI token still must not become a
    // CliSession principal.
    users.insert(User {
        id: sub,
        username: "victim".into(),
        email: "victim@example.com".into(),
        auth_provider: AuthProvider::Oidc,
        external_id: Some("keycloak:victim".into()),
        display_name: None,
        is_active: true,
        is_admin: false,
        is_service_account: false,
        last_login_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let authenticate = AuthenticateUseCase::new(
        idp as Arc<dyn IdentityProvider>,
        users as Arc<dyn UserRepository>,
        Vec::new(),
    )
    .with_cli_session_verification(cli_verifier, denylist);

    // Mint an OCI `/v2/auth` token with the SHARED key — valid
    // signature, but the OCI `aud` (registry host) + `access[]` scope
    // shape, NOT the CliSession `aud`/`token_kind`.
    let oci_claims = OciAccessClaims {
        iss: "https://hort.test/v2/auth".into(),
        sub,
        aud: "registry.hort.test".into(),
        exp: Utc::now() + chrono::Duration::seconds(300),
        access: vec![AccessEntry {
            resource_type: "repository".into(),
            name: "library/nginx".into(),
            actions: vec!["pull".into(), "push".into()],
        }],
    };
    let oci_jwt = shared_key.mint(&oci_claims).expect("mint oci token");

    // Present it on the bearer path.
    let result = authenticate.authenticate_bearer(&oci_jwt).await;

    // It MUST be rejected — never a CliSession principal. The OCI `aud`
    // fails the CliSession verifier's `aud` gate (NotOurToken), so it
    // falls through to the OIDC validator, which (mock IdP) rejects an
    // unregistered token → 401-shaped error.
    match result {
        Ok(principal) => panic!(
            "an OCI /v2/auth token must NOT authenticate as a CliSession \
             principal — got user_id={}, claims={:?}, token_kind={:?}",
            principal.user_id, principal.claims, principal.token_kind
        ),
        Err(AppError::OidcValidation(_)) | Err(AppError::Unauthorized(_)) => {
            // Correct: rejected with a 401-shaped error.
        }
        Err(other) => panic!("expected a 401-shaped rejection, got {other:?}"),
    }
}
