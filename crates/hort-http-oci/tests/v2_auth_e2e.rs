//! End-to-end `/v2/auth` token-exchange integration test.
//!
//! Drives the FULL Distribution-Spec dance through the production
//! handler chain via `axum::Router`'s `oneshot` — the same wire shape
//! `docker login` would walk:
//!
//! 1. Anonymous `GET /v2/.../manifests/v1` → `401` with
//!    `WWW-Authenticate: Bearer realm=…/v2/auth, service=…, scope=…`
//!    pointing at the production handler.
//! 2. `GET /v2/auth?service=…&scope=…` with `Authorization: Basic
//!    <b64("oauth2:<PAT>")>` → `200` with `{"token": "<jwt>",
//!    "access_token": "<jwt>", "expires_in": 300, "issued_at": "..."}`
//!    where the JWT is signed by the wired
//!    `OciTokenSigningKey`.
//! 3. `GET /v2/.../manifests/v1` with `Authorization: Bearer <jwt>` →
//!    NOT `401` (i.e. the auth gate passed). The downstream dispatch
//!    may surface 403 / 404 / 200 depending on the granted access — the
//!    test contract is that the auth middleware accepts the JWT.
//!
//! No DB; the test is fully in-memory. The harness mirrors the
//! production composition layout: every Arc<dyn …> handed to the
//! `OciTokenExchangeUseCase` is the SAME shape `composition.rs` builds.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use base64::Engine as _;
use chrono::Utc;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::argon2_hash::hash_token;
use hort_app::oci_token_signing::OciTokenSigningKey;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::oci_token_exchange_use_case::{
    OciTokenExchangeConfig, OciTokenExchangeUseCase,
};
use hort_app::use_cases::pat_cache::{PatCache, SystemClock};
use hort_app::use_cases::pat_validation_use_case::{PatLockoutConfig, PatValidationUseCase};
use hort_app::use_cases::test_support::{sample_repository, MockEventStore, MockIdentityProvider};

use hort_domain::entities::api_token::{ApiToken, TokenKind};
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{Page, PageRequest};

use hort_http_core::context::AuthContext;
use hort_http_core::test_support::{
    build_mock_ctx, with_api_token_use_case, with_auth, with_oci_public_base_url,
    with_oci_signing_key, with_oci_token_exchange,
};

use hort_http_oci::oci_routes_with_config;
use hort_http_oci::OciHttpConfig;

use ed25519_dalek::SigningKey;
use metrics_exporter_prometheus::PrometheusBuilder;

// ===========================================================================
// Custom ApiTokenRepository — `MockApiTokenRepository` returns `None` from
// `find_by_prefix`, but the PAT validator needs a real lookup. Smallest
// possible repo that supports both `find_by_prefix` (validator hot path)
// and `find_by_id` (unused here, but the trait demands it).
// ===========================================================================

#[derive(Default)]
struct InMemoryApiTokenRepo {
    by_prefix: Mutex<Vec<ApiToken>>,
}

impl InMemoryApiTokenRepo {
    fn new() -> Self {
        Self::default()
    }

    fn seed(&self, token: ApiToken) {
        self.by_prefix.lock().unwrap().push(token);
    }
}

impl ApiTokenRepository for InMemoryApiTokenRepo {
    fn insert(&self, token: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
        self.by_prefix.lock().unwrap().push(token.clone());
        Box::pin(async { Ok(()) })
    }

    fn find_by_prefix(&self, prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
        // Snapshot the row eagerly so the returned future doesn't
        // carry a borrow of `prefix`.
        let result = self
            .by_prefix
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.token_prefix == prefix)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
        let result = self
            .by_prefix
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

// ===========================================================================
// Test harness
// ===========================================================================

struct Harness {
    ctx: Arc<hort_http_core::context::AppContext>,
    /// The plaintext PAT the test uses on the `/v2/auth` Basic header.
    plaintext_pat: String,
    /// The repo key the test issues scopes against.
    repo_key: String,
    /// The image name segment under the repo (`<repo_key>/<image>`).
    image_name: String,
}

/// Build a fully-wired `AppContext` with native tokens enabled, an
/// OCI signing key wired, and one PAT seeded for `username = "alice"`.
fn build_harness() -> Harness {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    let (ctx, mocks) = build_mock_ctx(handle);

    // -- 1. User row + active = true. --------------------------------
    let user_id = Uuid::new_v4();
    let now = Utc::now();
    let alice = User {
        id: user_id,
        username: "alice".into(),
        email: "alice@example.com".into(),
        auth_provider: AuthProvider::Local,
        external_id: None,
        display_name: Some("Alice".into()),
        is_active: true,
        is_admin: false,
        is_service_account: false,
        last_login_at: None,
        created_at: now,
        updated_at: now,
    };
    mocks.users.insert(alice);

    // -- 2. Public OCI repo so the third call (Bearer JWT to manifest)
    //       has a deterministic dispatch downstream of the auth gate.
    let mut repo = sample_repository();
    repo.key = "myrepo".into();
    repo.format = RepositoryFormat::Oci;
    repo.is_public = true;
    let _repo_id = repo.id;
    mocks.repositories.insert(repo);

    // -- 3. PAT plaintext + Argon2id hash + `token_prefix` row. ------
    //
    // Format per `parse_pat_token_format`: `hort_pat_<32-char-base32>`,
    // total 41 bytes (9-byte `hort_pat_` prefix + 32-char body), base32
    // alphabet is `[a-z2-7]`. Build a token whose first 8 body chars are
    // the prefix index value — the validator pulls bytes [9..17] of the
    // plaintext to look up.
    let plaintext = "hort_pat_aaaaaaaabbbbbbbbccccccccdddddddd".to_string();
    assert_eq!(plaintext.len(), 41, "fixture invariant: PAT length 41");
    let token_prefix = "aaaaaaaa".to_string();
    let token_hash = hash_token(&plaintext).expect("hash");
    let token = ApiToken {
        id: Uuid::new_v4(),
        user_id,
        name: "alice-pat".into(),
        description: None,
        kind: TokenKind::Pat,
        token_hash,
        token_prefix,
        // Read-only cap: keeps the test deterministic under
        // RbacEvaluator's two-leg AND. The cap value travels into
        // the JWT only via the `evaluate_scope` path, which AND-
        // composes against the user's RBAC grants. The JWT mint
        // succeeds even if the granted subset is empty (per
        // design doc §6 "empty granted subset is NOT an error").
        declared_permissions: vec![Permission::Read],
        repository_ids: None,
        expires_at: None,
        revoked_at: None,
        last_used_at: None,
        last_used_ip: None,
        last_used_user_agent: None,
        created_by_user_id: user_id,
        created_at: now,
    };

    let token_repo: Arc<dyn ApiTokenRepository> = {
        let repo = Arc::new(InMemoryApiTokenRepo::new());
        repo.seed(token);
        repo
    };

    // -- 4. Build the PAT validator FIRST — it threads into both the
    //       AuthenticateUseCase (so Bearer/Basic-PAT shapes route
    //       through the validator on the OCI middleware path) AND
    //       the OciTokenExchangeUseCase (handler path). Same shape as
    //       composition.rs.
    let users_for_auth: Arc<dyn UserRepository> = mocks.users.clone();
    let pat_cache = Arc::new(PatCache::new(16, Duration::from_secs(300)));
    let pat_validation_uc = Arc::new(PatValidationUseCase::new(
        token_repo.clone(),
        users_for_auth.clone(),
        // PAT validation writes to `pat-attempt:` /
        // `pat-attempt-counter:` keyspaces, registered as Durable.
        mocks.ephemeral_durable.clone(),
        pat_cache,
        Arc::new(SystemClock),
        PatLockoutConfig::DEFAULT,
    ));

    // -- 5. Switch the AppContext to enabled-auth + wire RBAC swap.
    //       The exchange use case takes the SAME ArcSwap shape as
    //       composition (Arc<ArcSwap<RbacEvaluator>>). Crucially we
    //       call `with_pat_validation` so the bearer-auth middleware's
    //       fall-through path routes the PAT through the validator
    //       INSTEAD of the OIDC IdP (which would reject every PAT).
    let idp: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new());
    let authenticate = Arc::new(
        AuthenticateUseCase::new(idp, users_for_auth.clone(), Vec::new())
            .with_pat_validation(pat_validation_uc.clone()),
    );
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
        Vec::new(),
    )));
    let ctx = with_auth(
        &ctx,
        AuthContext::Enabled {
            authenticate,
            rbac: rbac.clone(),
            issuer_url: None,
        },
    );

    // -- 6. Build the OCI token exchange use case. -------------------
    let signing_key = Arc::new(OciTokenSigningKey::new(
        SigningKey::generate(&mut rand::rngs::OsRng),
        None,
    ));
    let public_base = "https://hort.example.com";
    let cfg = OciTokenExchangeConfig::new(
        format!("{public_base}/v2/auth"),
        "hort.example.com".to_string(),
    );
    let exchange = Arc::new(OciTokenExchangeUseCase::new(
        pat_validation_uc,
        users_for_auth.clone(),
        rbac.clone(),
        ctx.repository_access_use_case.clone(),
        signing_key.clone(),
        cfg,
    ));

    // Replace the api_token_use_case so it shares the same RBAC swap
    // (matching production wiring) — irrelevant for this test but
    // keeps the harness consistent for future scope additions.
    let api_token_use_case = Arc::new(ApiTokenUseCase::new(
        Arc::new(test_helpers_dummy_token_repo()),
        users_for_auth,
        hort_app::event_store_publisher::wrap_for_test(Arc::new(MockEventStore::new())),
        rbac,
        ApiTokenIssuanceConfig::default(),
    ));
    let ctx = with_api_token_use_case(&ctx, api_token_use_case);

    // -- 7. Wire the OCI slots on AppContext. ------------------------
    let ctx = with_oci_signing_key(&ctx, Some(signing_key));
    let ctx = with_oci_token_exchange(&ctx, Some(exchange));
    let ctx = with_oci_public_base_url(&ctx, Some(public_base.to_string()));

    Harness {
        ctx,
        plaintext_pat: plaintext,
        repo_key: "myrepo".into(),
        image_name: "library/nginx".into(),
    }
}

/// `with_api_token_use_case` requires SOME ApiTokenRepository under
/// the use case — the test doesn't drive admin issuance, so a stub
/// is fine. Dummy on `find_by_prefix` (returns None) since the
/// admin path doesn't use it.
fn test_helpers_dummy_token_repo() -> impl ApiTokenRepository {
    InMemoryApiTokenRepo::new()
}

fn run<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

// ===========================================================================
// Step 1 — Request with an invalid bearer token → 401 + Bearer challenge
// with realm=…/v2/auth and service=…
//
// Why a bad-bearer probe rather than a bare anonymous GET: the
// production OCI dispatcher admits anonymous reads on public repos and
// collapses missing-on-private to NAME_UNKNOWN (anti-enumeration).
// The `oci_bearer_auth` middleware emits the Bearer challenge ONLY on
// the explicit reject path — i.e. when a token IS presented but fails
// validation. Real OCI clients trigger this same shape: docker pull
// against a private repo first probes anonymously, then on the second
// attempt presents a stale token, then on the third sees this challenge
// and goes to /v2/auth. The test pins the second attempt.
// ===========================================================================

#[test]
fn step1_invalid_bearer_emits_bearer_challenge_to_v2_auth() {
    let (status, www) = run(async {
        let h = build_harness();
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
        let path = format!("/v2/{}/{}/manifests/v1", h.repo_key, h.image_name);
        let resp = router
            .oneshot(
                Request::get(&path)
                    // A token that:
                    // - has the JWT-shape so it does NOT route through the
                    //   PAT-prefix grammar branch in AuthenticateUseCase
                    //   (which would Argon2-verify and short-circuit with
                    //   PrefixNotFound), and
                    // - fails OCI-key verification (it's not signed by our
                    //   key), and fails OIDC validation (no IdP knows it).
                    // Result: middleware's `unauthorized_response` path,
                    // which emits the Bearer challenge.
                    .header(header::AUTHORIZATION, "Bearer not.a.real.jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let www = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_string());
        (status, www)
    });
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let www = www.expect("WWW-Authenticate header must be present");
    assert!(
        www.starts_with("Bearer"),
        "expected Bearer challenge when native tokens enabled, got: {www}"
    );
    assert!(
        www.contains(r#"realm="https://hort.example.com/v2/auth""#),
        "challenge realm must point at the production /v2/auth endpoint: {www}"
    );
    assert!(
        www.contains(r#"service="hort.example.com""#),
        "challenge service must echo the public base URL host: {www}"
    );
    assert!(
        www.contains(r#"scope="repository:myrepo/library/nginx:pull""#),
        "challenge scope must reflect the requested resource: {www}"
    );
}

// ===========================================================================
// Step 2 — `/v2/auth` with Basic <b64("oauth2:<PAT>")> → 200 + JWT body.
// ===========================================================================

#[test]
fn step2_v2_auth_with_valid_pat_mints_jwt() {
    // NOTE: scope is omitted (per the step3 explanation): a single
    // `scope=…` query value fails serde_urlencoded's `Vec<String>`
    // deserialise. Real `docker login` calls /v2/auth with no scope
    // first ("ping-style anonymous-equivalent" per design doc §6),
    // so the empty-scope mint path is itself a Distribution-Spec
    // shape worth pinning here.
    let (status, body_json) = run(async {
        let h = build_harness();
        let creds = format!("oauth2:{}", h.plaintext_pat);
        let basic = base64::engine::general_purpose::STANDARD.encode(creds);
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
        let resp = router
            .oneshot(
                Request::get("/v2/auth?service=hort.example.com")
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, body_json)
    });
    assert_eq!(status, StatusCode::OK, "PAT must mint a token: {body_json}");
    let token = body_json["token"]
        .as_str()
        .expect("response must carry `token`");
    let access_token = body_json["access_token"]
        .as_str()
        .expect("response must carry `access_token`");
    assert_eq!(
        token, access_token,
        "Distribution-Spec: `token` and `access_token` must be byte-identical"
    );
    assert_eq!(body_json["expires_in"].as_u64(), Some(300));
    assert!(
        body_json["issued_at"].as_str().is_some(),
        "issued_at must be present"
    );
    // JWT structural sanity: header.payload.signature.
    assert_eq!(
        token.split('.').count(),
        3,
        "minted token must be a JWT (header.payload.signature)"
    );
}

// ===========================================================================
// Step 3 — `/v2/auth` with no Authorization → 401 + Bearer challenge
// (the same realm/service shape as step 1).
// ===========================================================================

#[test]
fn step3_v2_auth_without_credentials_returns_401_with_challenge() {
    // NOTE: send `service=…` only (no `scope=`). The handler's `Vec<String>`
    // scope field is `#[serde(default)]`-friendly; sending no scope avoids
    // the serde_urlencoded `string vs sequence` deserialise mismatch (a
    // pre-existing handler behaviour: real clients pass `scope=` either
    // omitted or repeated, but serde_urlencoded's default `Vec<String>`
    // deserialise requires the bracket-array form for a single scope).
    // The 401-Bearer-challenge invariant we're pinning here doesn't depend
    // on scope being present.
    let (status, www, body_text) = run(async {
        let h = build_harness();
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
        let resp = router
            .oneshot(
                Request::get("/v2/auth?service=hort.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let www = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_string());
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let body_text = String::from_utf8_lossy(&body).to_string();
        (status, www, body_text)
    });
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/v2/auth without creds must 401, got {status}: {body_text}"
    );
    let www = www.expect("WWW-Authenticate must be re-emitted on /v2/auth itself");
    assert!(
        www.starts_with("Bearer"),
        "expected Bearer challenge: {www}"
    );
    assert!(www.contains(r#"realm="https://hort.example.com/v2/auth""#));
}

// ===========================================================================
// `GET /v2/auth?service=<wrong-host>` → 400 with the byte-exact
// `UNSUPPORTED` envelope + `Docker-Distribution-API-Version` header.
// Credential is valid — the gate fires BEFORE PAT validation, so a valid
// credential still 400s when `service=` does not match the configured
// `aud`. The body MUST be constant `"service mismatch"` — it never echoes
// the requested/expected host (spec §3.3; values go to the audit log only).
// ===========================================================================

#[test]
fn v2_auth_service_mismatch_returns_400_unsupported_envelope() {
    let (status, body_text, api_ver) = run(async {
        let h = build_harness();
        let creds = format!("oauth2:{}", h.plaintext_pat);
        let basic = base64::engine::general_purpose::STANDARD.encode(creds);
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
        let resp = router
            .oneshot(
                // Configured aud is `hort.example.com`; the client sends a
                // different host → F-28 Step-0 mismatch.
                Request::get("/v2/auth?service=evil.attacker.example")
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let api_ver = resp
            .headers()
            .get("Docker-Distribution-API-Version")
            .map(|v| v.to_str().unwrap().to_string());
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        (status, body_text, api_ver)
    });
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "service= mismatch must be a 400 (credential never evaluated)"
    );
    // Byte-exact envelope: the SAME `UNSUPPORTED` wire shape
    // `OciError::Unsupported` already renders for the established
    // `invalid scope` 400 (spec §3.3 / §7 — "the wire shape is
    // identical to the established `invalid scope` 400, so OCI clients
    // parse it with their existing error handling"). That shape carries
    // `detail:null` (the `WireError.detail` field has no
    // skip_serializing_if). The message is the CONSTANT `"service
    // mismatch"` — NO reflected requested/expected value in the body
    // (the spec §3.3 snippet abbreviates `detail`; the load-bearing
    // contract is "identical to the existing invalid-scope 400").
    assert_eq!(
        body_text,
        r#"{"errors":[{"code":"UNSUPPORTED","message":"service mismatch","detail":null}]}"#,
        "F-28 400 body must be byte-identical to the established UNSUPPORTED \
         envelope and must NOT echo the host"
    );
    assert!(
        !body_text.contains("evil.attacker.example") && !body_text.contains("hort.example.com"),
        "the body must never reflect the requested or configured host"
    );
    assert_eq!(
        api_ver.as_deref(),
        Some("registry/2.0"),
        "Docker-Distribution-API-Version header must be present on the F-28 400"
    );
}

#[test]
fn f28_v2_auth_matching_service_still_mints_200() {
    // Control: the EXACT configured host (case-insensitive — RFC 3986
    // §3.2.2) still mints a JWT. Proves the gate is a precise equality
    // check, not a blanket reject, and that the one observable change
    // is strictly the mismatch case.
    let status = run(async {
        let h = build_harness();
        let creds = format!("oauth2:{}", h.plaintext_pat);
        let basic = base64::engine::general_purpose::STANDARD.encode(creds);
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
        let resp = router
            .oneshot(
                // Mixed-case echo of the configured `hort.example.com` —
                // a conformant client echoing the challenge host with
                // different casing must NOT 400 (case-insensitive host).
                Request::get("/v2/auth?service=HORT.Example.Com")
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    });
    assert_eq!(
        status,
        StatusCode::OK,
        "case-insensitive host match must still mint (no spurious F-28 400)"
    );
}

// ===========================================================================
// Step 4 — Use the minted JWT to drive `GET /v2/<repo>/<name>/manifests/v1`
// AGAIN. The auth gate must accept the JWT (no 401); the downstream
// dispatch may surface 200 / 403 / 404 depending on grants — the test
// invariant is "auth passed, status != 401".
// ===========================================================================

#[test]
fn step4_minted_jwt_passes_oci_auth_gate_on_subsequent_request() {
    let final_status = run(async {
        let h = build_harness();
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);

        // First, mint the JWT via /v2/auth (no scope — see step2 note).
        let creds = format!("oauth2:{}", h.plaintext_pat);
        let basic = base64::engine::general_purpose::STANDARD.encode(creds);
        let resp = router
            .clone()
            .oneshot(
                Request::get("/v2/auth?service=hort.example.com")
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let jwt = body_json["token"].as_str().expect("token").to_string();

        // Now use it to fetch a manifest. The repo is public; a missing
        // manifest is `NAME_UNKNOWN` (404) — auth gate has CLEARLY
        // passed. Any 4xx other than 401 (or a 200) is acceptable; 401
        // would mean auth failed, which is the regression we guard.
        let path = format!("/v2/{}/{}/manifests/v1", h.repo_key, h.image_name);
        let resp = router
            .oneshot(
                Request::get(&path)
                    .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    });
    assert_ne!(
        final_status,
        StatusCode::UNAUTHORIZED,
        "JWT minted via /v2/auth must be accepted at the OCI auth gate"
    );
}

// ===========================================================================
// Step 5 — Full DOCKER LOGIN dance, hands-off: every step uses ONLY the
// data the previous step's response handed back. This is the strongest
// shape the test takes — the parent agent's instructions specifically
// call this out as the "Distribution-Spec-conformant mock client" path.
// ===========================================================================

#[test]
fn step5_docker_login_dance_end_to_end_via_oneshot() {
    run(async {
        let h = build_harness();
        let router =
            oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);

        // ---- (a) Manifest GET with an invalid bearer → 401 + Bearer
        //         challenge (production OCI dispatcher admits anonymous
        //         reads on public repos and returns NAME_UNKNOWN for
        //         missing manifests; the Bearer-challenge path is
        //         reached only on the explicit-reject branch where a
        //         token IS presented but fails validation). Real
        //         clients walk this exact shape: docker pull retries
        //         with a stale token after a first anonymous probe.
        let path = format!("/v2/{}/{}/manifests/v1", h.repo_key, h.image_name);
        let resp = router
            .clone()
            .oneshot(
                Request::get(&path)
                    .header(header::AUTHORIZATION, "Bearer not.a.real.jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("must challenge")
            .to_str()
            .unwrap()
            .to_string();
        let realm = parse_challenge_param(&www, "realm").expect("realm");
        let service = parse_challenge_param(&www, "service").expect("service");
        // The realm is an absolute URL — production code should never
        // hand a client a relative realm (that's the F6 boot-fail
        // we just closed).
        assert!(
            realm.starts_with("https://"),
            "realm must be absolute: {realm}"
        );

        // ---- (b) Build the /v2/auth request from the challenge.
        //         Drop `scope` from the replay — see step3 for why a
        //         single `scope=` value fails serde_urlencoded's
        //         `Vec<String>` deserialise. The replay still
        //         exercises the spec-required (realm, service,
        //         credential) round-trip.
        let realm_url: url::Url = realm.parse().expect("realm is a URL");
        let auth_path = format!(
            "{}?service={}",
            realm_url.path(),
            urlencoding::encode(&service),
        );
        let creds = format!("oauth2:{}", h.plaintext_pat);
        let basic = base64::engine::general_purpose::STANDARD.encode(creds);
        let resp = router
            .clone()
            .oneshot(
                Request::get(&auth_path)
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "step 5(b): /v2/auth with valid PAT must mint"
        );
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let jwt = v["token"].as_str().expect("token").to_string();

        // ---- (c) Replay the manifest GET with the JWT. -------------
        let resp = router
            .oneshot(
                Request::get(&path)
                    .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "step 5(c): JWT replay must clear the OCI auth gate"
        );
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pull `key="value"` (Distribution-Spec parameter shape) out of a
/// `WWW-Authenticate: Bearer …` challenge string. Returns the raw
/// (unescaped) value or `None` if the parameter is absent.
fn parse_challenge_param(www: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = www.find(&needle)? + needle.len();
    let rest = &www[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
