//! Native API token issuance / revocation / listing endpoints
//! (ADR 0012; mechanism inventory in `docs/auth-catalog.md`).
//!
//! Routes (the caller `nest`s under `/api/v1`):
//!
//! ```text
//! # Public self-service plane — [`api_token_routes`]:
//! POST   /users/me/tokens             — self-mint
//! DELETE /users/me/tokens/:id         — self-revoke
//! GET    /users/me/tokens             — list own tokens
//! # Control plane — [`admin_token_routes`]:
//! POST   /admin/users/:user_id/tokens — admin-mint for service account
//! DELETE /admin/tokens/:id            — admin-revoke any token
//! ```
//!
//! The two admin routes live in a
//! separate [`admin_token_routes`] tree so the composition root in
//! `hort-server` can place them on the internal control-plane listener
//! (with the rest of `/api/v1/admin/*`) rather than the public listener
//! the self-service routes stay on. The handler extractors / use-case
//! gating are unchanged — this was purely a route-placement split.
//!
//! Validation, expiry clamps, denial-event emission, and audit-event
//! emission live in
//! [`ApiTokenUseCase`](hort_app::use_cases::api_token_use_case::ApiTokenUseCase).
//! Handlers are thin: extract the principal, pass it directly to the
//! use case (which holds an `Arc<ArcSwap<RbacEvaluator>>` and runs
//! cap-vs-authority through the same evaluator the per-request
//! authorize path uses, picking up
//! refresh-task swaps without restart), map errors to wire envelopes
//! per the status-mapping table below.
//!
//! # Wire status mapping
//!
//! | Error | Status | Body |
//! |---|---|---|
//! | `CapExceedsAuthority { failed }` | 403 | `{"error":"cap_exceeds_authority","failed":[…]}` |
//! | `ServiceAccountSelfMint` | 403 | `{"error":"service_account_must_use_admin_mint"}` |
//! | `AdminTokenDisallowed` | 400 | `{"error":"admin_tokens_disabled"}` |
//! | `AdminAuthorityRequired` | 403 | `{"error":"admin_authority_required"}` |
//! | `AdminTokenExceedsThirtyDays` | 400 | `{"error":"admin_token_max_30_days"}` |
//! | `AdminTokenUnboundedNotAllowed` | 400 | `{"error":"admin_token_must_have_expiry"}` |
//! | `UnboundedSvcTokenDisallowed` | 400 | `{"error":"unbounded_svc_token_disallowed"}` |
//! | `InvalidRepositorySet` | 400 | `{"error":"invalid_repository_set"}` |
//! | `NotServiceAccount` | 400 | `{"error":"target_not_service_account"}` |
//! | `NotAuthorized` | 403 | `{"error":"not_authorized"}` |
//! | `TokenNotFound` | 404 | `{"error":"token_not_found"}` |
//! | `DescriptionTooLong` | 400 | `{"error":"description_too_long"}` |
//! | `NameEmpty` / `NameTooLong` | 400 | `{"error":"invalid_name"}` |
//! | `ExpiryZero` / `ExpiryTooLong` | 400 | `{"error":"invalid_expires_in_days"}` |
//! | `Infrastructure(_)` | 500 | `{"error":"internal error"}` |
//!
//! # Anti-patterns
//!
//! - Request DTOs ([`IssueTokenRequestBody`]) deserialize from JSON;
//!   the domain's [`ApiToken`](hort_domain::entities::api_token::ApiToken)
//!   itself does NOT — see the entity-level docstring on the type.
//! - Response DTOs ([`IssuedTokenResponse`], [`TokenSummary`]) MUST
//!   exclude `token_hash` always. Plaintext (`token`) appears ONLY on
//!   the issuance response, never on list / get.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::use_cases::api_token_use_case::{ApiTokenError, IssueTokenRequest, IssuedToken};
use hort_domain::entities::api_token::{ApiToken, TokenKind};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::events::ApiActor;
use hort_domain::types::{Page, PageRequest};

use crate::authz::AdminPrincipal;
use crate::context::AppContext;
use crate::middleware::auth::AuthenticatedPrincipal;

// ---------------------------------------------------------------------------
// AuthenticatedCaller extractor
// ---------------------------------------------------------------------------

/// Extractor that pulls the validated [`CallerPrincipal`] out of
/// request extensions for endpoints that require *any* authenticated
/// user (no permission check). Used for `/users/me/tokens` —
/// every authenticated user can self-mint, list, and revoke their
/// own tokens.
///
/// Returns 401 / 500 mirroring the [`AdminPrincipal`] extractor's
/// rejection shape: same upstream slots, same router-wiring bug
/// detection.
struct AuthenticatedCaller(CallerPrincipal);

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for AuthenticatedCaller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(p) = parts.extensions.get::<AuthenticatedPrincipal>() {
            return Ok(Self(p.as_caller().clone()));
        }
        if let Some(Some(p)) = parts.extensions.get::<Option<AuthenticatedPrincipal>>() {
            return Ok(Self(p.as_caller().clone()));
        }
        // Auth ran and saw no token — 401.
        if let Some(None) = parts.extensions.get::<Option<AuthenticatedPrincipal>>() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "authentication required"})),
            )
                .into_response());
        }
        tracing::error!(
            "AuthenticatedCaller invoked without an AuthenticatedPrincipal — \
             require_principal layer must run first"
        );
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response())
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Build the PUBLIC self-service native-API-token route tree
/// (`/users/me/tokens*`). Caller `nest`s under `/api/v1`.
///
/// The two ADMIN routes
/// (`POST /admin/users/:user_id/tokens`,
/// `DELETE /admin/tokens/:id`) are NOT here — they live in
/// [`admin_token_routes`] so the composition root can place them on the
/// internal control-plane listener with the rest of `/api/v1/admin/*`.
/// Every authenticated user can self-mint / list / revoke their own
/// tokens, so this tree is public by requirement.
pub fn api_token_routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route("/users/me/tokens", post(post_self_token))
        .route("/users/me/tokens", get(get_self_tokens))
        .route("/users/me/tokens/:id", delete(delete_self_token))
}

/// Build the CONTROL-PLANE admin native-API-token route tree.
/// Caller `nest`s under `/api/v1`.
///
/// ```text
/// POST   /admin/users/:user_id/tokens — admin-mint for service account
/// DELETE /admin/tokens/:id            — admin-revoke any token
/// ```
///
/// Both routes are gated by the [`AdminPrincipal`] extractor (unchanged
/// by this split). They are mounted onto the internal control listener
/// by `hort_server::http::control_plane_routes` so they leave the
/// public listener when `HORT_CONTROL_BIND` is set — completing the
/// tier-(iii) `/api/v1/admin/*`-is-control-plane segmentation the
/// hardening checklist already claims.
pub fn admin_token_routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route(
            "/admin/users/:user_id/tokens",
            post(post_admin_service_account_token),
        )
        .route("/admin/tokens/:id", delete(delete_admin_token))
}

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

/// Request body for `POST /users/me/tokens` and
/// `POST /admin/users/:user_id/tokens`.
///
/// Permissions are wire strings (`read`, `write`, `delete`, `admin`)
/// — `Permission::from_str` parses case-insensitively. Unknown values
/// surface as `400 invalid_permission`.
#[derive(Debug, Deserialize)]
pub struct IssueTokenRequestBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub declared_permissions: Vec<String>,
    #[serde(default)]
    pub repository_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

/// Response body for `POST` issuance. The `token` plaintext appears
/// here ONCE; it is never recoverable afterwards. List and get
/// endpoints use [`TokenSummary`] which excludes `token`.
#[derive(Debug, Serialize)]
pub struct IssuedTokenResponse {
    pub id: Uuid,
    /// Operator-supplied human label echoed back from the request.
    pub name: String,
    pub kind: &'static str,
    /// Full plaintext: `hort_<kind>_<32 base32 chars>`.
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response body row for `GET /users/me/tokens`. Excludes
/// `token_hash`, `token_prefix`, and the full plaintext (which is
/// only ever shown on the issuance response).
#[derive(Debug, Serialize)]
pub struct TokenSummary {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: &'static str,
    pub declared_permissions: Vec<String>,
    pub repository_ids: Option<Vec<Uuid>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Page-of-tokens response shape.
#[derive(Debug, Serialize)]
pub struct TokenPageResponse {
    pub items: Vec<TokenSummary>,
    pub total: u64,
}

/// Pagination query for `GET /users/me/tokens`.
#[derive(Debug, Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

impl PageQuery {
    fn to_request(&self) -> PageRequest {
        PageRequest::new(self.offset.unwrap_or(0), self.limit.unwrap_or(20))
    }
}

// ---------------------------------------------------------------------------
// Handler bodies
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(ctx, body))]
async fn post_self_token(
    AuthenticatedCaller(principal): AuthenticatedCaller,
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<IssueTokenRequestBody>,
) -> Result<Response, ApiTokenWireError> {
    let request = parse_request(body)?;
    // Pass the principal straight through. The use
    // case holds the same `Arc<ArcSwap<RbacEvaluator>>` the per-request
    // authorize path consults, so per-repo grants are honoured in full
    // AND the refresh task propagates new grants/roles to issuance
    // without an `hort-server` restart.
    let issued = ctx
        .api_token_use_case
        .issue_self_token(&principal, request)
        .await
        .map_err(ApiTokenWireError::from)?;
    Ok((StatusCode::CREATED, Json(issued_response(&issued))).into_response())
}

#[tracing::instrument(skip(ctx, body))]
async fn post_admin_service_account_token(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<IssueTokenRequestBody>,
) -> Result<Response, ApiTokenWireError> {
    let request = parse_request(body)?;
    let issued = ctx
        .api_token_use_case
        .issue_for_service_account(&admin.0, user_id, request)
        .await
        .map_err(ApiTokenWireError::from)?;
    Ok((StatusCode::CREATED, Json(issued_response(&issued))).into_response())
}

#[tracing::instrument(skip(ctx))]
async fn delete_self_token(
    AuthenticatedCaller(principal): AuthenticatedCaller,
    State(ctx): State<Arc<AppContext>>,
    Path(token_id): Path<Uuid>,
) -> Result<Response, ApiTokenWireError> {
    ctx.api_token_use_case
        .revoke(
            ApiActor {
                user_id: principal.user_id,
            },
            token_id,
            false,
        )
        .await
        .map_err(ApiTokenWireError::from)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[tracing::instrument(skip(ctx))]
async fn delete_admin_token(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(token_id): Path<Uuid>,
) -> Result<Response, ApiTokenWireError> {
    ctx.api_token_use_case
        .revoke(
            ApiActor {
                user_id: admin.0.user_id,
            },
            token_id,
            true,
        )
        .await
        .map_err(ApiTokenWireError::from)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[tracing::instrument(skip(ctx))]
async fn get_self_tokens(
    AuthenticatedCaller(principal): AuthenticatedCaller,
    State(ctx): State<Arc<AppContext>>,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiTokenWireError> {
    let page_req = page.to_request();
    let result = ctx
        .api_token_use_case
        .list_for_user(
            ApiActor {
                user_id: principal.user_id,
            },
            principal.user_id,
            false,
            page_req,
        )
        .await
        .map_err(ApiTokenWireError::from)?;
    Ok(Json(page_response(&result)).into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_request(body: IssueTokenRequestBody) -> Result<IssueTokenRequest, ApiTokenWireError> {
    let mut declared = Vec::with_capacity(body.declared_permissions.len());
    for raw in &body.declared_permissions {
        match raw.parse::<Permission>() {
            Ok(p) => declared.push(p),
            Err(_) => return Err(ApiTokenWireError::InvalidPermission(raw.clone())),
        }
    }
    Ok(IssueTokenRequest {
        name: body.name,
        description: body.description,
        declared_permissions: declared,
        repository_ids: body.repository_ids,
        expires_in_days: body.expires_in_days,
        expires_in_seconds: None,
        // The self-mint / admin-mint REST endpoint is not
        // federation. The federation branch lives on /auth/exchange.
        federation_source: None,
    })
}

fn issued_response(issued: &IssuedToken) -> IssuedTokenResponse {
    IssuedTokenResponse {
        id: issued.id,
        name: issued.name.clone(),
        kind: kind_wire(issued.kind),
        token: issued.plaintext.clone(),
        expires_at: issued.expires_at,
    }
}

fn page_response(page: &Page<ApiToken>) -> TokenPageResponse {
    TokenPageResponse {
        total: page.total,
        items: page.items.iter().map(token_summary).collect(),
    }
}

fn token_summary(token: &ApiToken) -> TokenSummary {
    TokenSummary {
        id: token.id,
        user_id: token.user_id,
        name: token.name.clone(),
        description: token.description.clone(),
        kind: kind_wire(token.kind),
        declared_permissions: token
            .declared_permissions
            .iter()
            .map(ToString::to_string)
            .collect(),
        repository_ids: token.repository_ids.clone(),
        expires_at: token.expires_at,
        revoked_at: token.revoked_at,
        last_used_at: token.last_used_at,
        created_at: token.created_at,
    }
}

fn kind_wire(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Pat => "pat",
        TokenKind::ServiceAccount => "service_account",
        TokenKind::CliSession => "cli_session",
    }
}

// ---------------------------------------------------------------------------
// Wire error mapper
// ---------------------------------------------------------------------------

/// Newtype around the use-case error that owns the HTTP envelope
/// shape. Decoupling here means the use-case error stays pure
/// `hort-app` and the wire body is the inbound-HTTP crate's
/// responsibility.
pub enum ApiTokenWireError {
    UseCase(ApiTokenError),
    InvalidPermission(String),
}

impl From<ApiTokenError> for ApiTokenWireError {
    fn from(e: ApiTokenError) -> Self {
        Self::UseCase(e)
    }
}

impl IntoResponse for ApiTokenWireError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidPermission(value) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_permission",
                    "value": value,
                })),
            )
                .into_response(),
            Self::UseCase(err) => map_use_case_error(err),
        }
    }
}

fn map_use_case_error(err: ApiTokenError) -> Response {
    use hort_app::use_cases::api_token_use_case::ApiTokenError as E;
    match err {
        E::CapExceedsAuthority { failed } => {
            let failed_json: Vec<serde_json::Value> = failed
                .into_iter()
                .map(|(repo, perm)| {
                    serde_json::json!({
                        "repo": repo.map(|r| r.to_string()),
                        "permission": perm.to_string(),
                    })
                })
                .collect();
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "cap_exceeds_authority",
                    "failed": failed_json,
                })),
            )
                .into_response()
        }
        E::ServiceAccountSelfMint => {
            err_body(StatusCode::FORBIDDEN, "service_account_must_use_admin_mint")
        }
        E::AdminTokenDisallowed => err_body(StatusCode::BAD_REQUEST, "admin_tokens_disabled"),
        E::AdminAuthorityRequired => err_body(StatusCode::FORBIDDEN, "admin_authority_required"),
        E::AdminTokenExceedsThirtyDays => {
            err_body(StatusCode::BAD_REQUEST, "admin_token_max_30_days")
        }
        E::AdminTokenUnboundedNotAllowed => {
            err_body(StatusCode::BAD_REQUEST, "admin_token_must_have_expiry")
        }
        E::UnboundedSvcTokenDisallowed => {
            err_body(StatusCode::BAD_REQUEST, "unbounded_svc_token_disallowed")
        }
        E::InvalidRepositorySet => err_body(StatusCode::BAD_REQUEST, "invalid_repository_set"),
        E::NotServiceAccount => err_body(StatusCode::BAD_REQUEST, "target_not_service_account"),
        E::NotAuthorized => err_body(StatusCode::FORBIDDEN, "not_authorized"),
        E::TokenNotFound => err_body(StatusCode::NOT_FOUND, "token_not_found"),
        E::DescriptionTooLong => err_body(StatusCode::BAD_REQUEST, "description_too_long"),
        E::NameEmpty | E::NameTooLong => err_body(StatusCode::BAD_REQUEST, "invalid_name"),
        E::ExpiryZero | E::ExpiryTooLong => {
            err_body(StatusCode::BAD_REQUEST, "invalid_expires_in_days")
        }
        // Seconds-based path. These variants surface
        // only on the /exchange (cli_session) path today; the
        // self-mint API still uses days. Map both to 400 so wire
        // shape stays uniform with the existing expiry-bound errors.
        E::LifetimeBelowMinimum => err_body(StatusCode::BAD_REQUEST, "lifetime_below_minimum"),
        E::ExpiryUnitConflict => err_body(StatusCode::BAD_REQUEST, "expiry_unit_conflict"),
        // These three only ever arise on
        // the federation `/exchange` path (the only caller that sets
        // `federation_source = Some(_)`); the federation handler
        // intercepts them via its own `deny_outcome` and they never
        // reach this native-REST mapper. Mapped exhaustively for
        // type-safety with a status consistent with their federation
        // semantics (401 replay/jti-required, 503 fail-closed) so a
        // future caller cannot accidentally 500.
        E::ReplayDetected { .. } => err_body(StatusCode::UNAUTHORIZED, "replay_detected"),
        E::JtiRequired => err_body(StatusCode::UNAUTHORIZED, "jti_required"),
        E::ReplayGuardUnavailable => {
            err_body(StatusCode::SERVICE_UNAVAILABLE, "replay_guard_unavailable")
        }
        E::Infrastructure(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response(),
    }
}

fn err_body(status: StatusCode, key: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": key }))).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::api_token::ApiToken;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;
    use uuid::Uuid;

    use super::*;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    /// Build a principal whose resolved claim set is `claims` (the
    /// additive-claims model, ADR 0012 — a single `claims` field, no
    /// `groups`/`roles` pair). `["admin"]` triggers
    /// the evaluator admin short-circuit; any other claim is treated as
    /// a non-admin claim the seeded `GrantSubject::Claims` grants match.
    fn principal_with_claims(user_id: Uuid, claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id,
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn router_with_principal(principal: &CallerPrincipal) -> (Router, MockPorts, Arc<AppContext>) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);

        // Seed the user row referenced by `principal.user_id` so the
        // use case's `users.find_by_id` does not return NotFound.
        mocks.users.insert(User {
            id: principal.user_id,
            username: principal.username.clone(),
            email: principal.email.clone(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: principal.claims.iter().any(|c| c == "admin"),
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        // Build an enabled-auth context so AdminPrincipal /
        // AuthenticatedPrincipal extractors hit the production code path.
        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        // Seed the RBAC evaluator with `GrantSubject::Claims` grants
        // matching the principal's resolved claim set so cap-vs-authority
        // checks pass for `Read` / `Write` / `Delete` (a flat
        // claim-subject grant set — ADR 0012).
        let rbac_eval = if principal.claims.iter().any(|c| c == "admin") {
            // Admin claim — the user-grants leg short-circuits. No
            // grants needed (admin short-circuit).
            RbacEvaluator::new(Vec::new())
        } else {
            // Build global Read/Write/Delete grants bound to the
            // principal's first (non-admin) claim.
            use hort_domain::entities::managed_by::ManagedBy;
            use hort_domain::entities::rbac::{GrantSubject, PermissionGrant};
            let required = vec![principal.claims[0].clone()];
            let grants: Vec<PermissionGrant> =
                [Permission::Read, Permission::Write, Permission::Delete]
                    .into_iter()
                    .map(|perm| PermissionGrant {
                        id: Uuid::new_v4(),
                        subject: GrantSubject::Claims(required.clone()),
                        repository_id: None,
                        permission: perm,
                        created_at: Utc::now(),
                        managed_by: ManagedBy::Local,
                        managed_by_digest: None,
                    })
                    .collect();
            RbacEvaluator::new(grants)
        };
        // Rebuild the api_token_use_case with the
        // SAME `Arc<ArcSwap<RbacEvaluator>>` wired into AuthContext so
        // cap-vs-authority checks see the seeded grants AND track any
        // future swap. Otherwise the use case would be stuck with
        // `build_mock_ctx`'s empty default and every non-admin
        // issuance would fail with CapExceedsAuthority.
        let rbac_swap = Arc::new(arc_swap::ArcSwap::from_pointee(rbac_eval));
        let api_token_uc = Arc::new(ApiTokenUseCase::new(
            mocks.api_tokens.clone(),
            mocks.users.clone(),
            base.event_store.clone(),
            rbac_swap.clone(),
            ApiTokenIssuanceConfig::default(),
        ));
        let ctx_with_auth = with_auth(
            &base,
            crate::context::AuthContext::Enabled {
                authenticate,
                rbac: rbac_swap,
                issuer_url: None,
            },
        );
        let ctx = crate::test_support::with_api_token_use_case(&ctx_with_auth, api_token_uc);

        // The admin routes live in a
        // separate `admin_token_routes()` tree (mounted on the control
        // listener by the composition root). The unit tests below
        // exercise both the public self-service and the admin handlers,
        // so merge both trees here — they share the `/api/v1`-relative
        // path space with no collision.
        let router = Router::new()
            .merge(api_token_routes())
            .merge(admin_token_routes())
            .with_state(ctx.clone());
        (router, mocks, ctx)
    }

    fn inject(req: &mut Request<Body>, p: &CallerPrincipal) {
        crate::middleware::auth::test_support::inject_principal(req, p.clone());
    }

    fn happy_request_body() -> &'static str {
        r#"{"name":"ci","declared_permissions":["read","write"],"expires_in_days":90}"#
    }

    // -- POST /users/me/tokens ---------------------------------------------

    #[tokio::test]
    async fn post_self_token_returns_201_with_plaintext() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, mocks, _) = router_with_principal(&principal);
        let mut req = Request::post("/users/me/tokens")
            .header("content-type", "application/json")
            .body(Body::from(happy_request_body()))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = v["token"].as_str().expect("token plaintext present");
        assert!(token.starts_with("hort_pat_"), "got {token}");
        assert_eq!(token.len(), 41);
        assert_eq!(v["kind"], "pat");
        assert!(v["expires_at"].is_string());
        // `name` is required on the issuance response.
        // The request body sets `"name":"ci"`; the response echoes it.
        assert_eq!(v["name"], "ci");
        // Inserted into mock repo.
        assert_eq!(mocks.api_tokens.inserted().len(), 1);
    }

    #[tokio::test]
    async fn post_self_token_invalid_permission_returns_400() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, _, _) = router_with_principal(&principal);
        let mut req = Request::post("/users/me/tokens")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"ci","declared_permissions":["bogus"],"expires_in_days":30}"#,
            ))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "invalid_permission");
    }

    #[tokio::test]
    async fn post_self_token_empty_repository_ids_returns_400_invalid_repository_set() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, _, _) = router_with_principal(&principal);
        let mut req = Request::post("/users/me/tokens")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"ci","declared_permissions":["read"],"repository_ids":[],"expires_in_days":30}"#,
            ))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "invalid_repository_set");
    }

    #[tokio::test]
    async fn post_self_token_admin_token_disallowed_returns_400() {
        // Admin user requesting admin token — flag is OFF by default in
        // build_mock_ctx, so issuance is refused.
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["admin"]);
        let (router, _, _) = router_with_principal(&principal);
        let mut req = Request::post("/users/me/tokens")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"ci","declared_permissions":["admin"],"expires_in_days":15}"#,
            ))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "admin_tokens_disabled");
    }

    // -- DELETE /users/me/tokens/:id ---------------------------------------

    #[tokio::test]
    async fn delete_self_token_returns_204_on_success() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, mocks, _) = router_with_principal(&principal);
        let token_id = Uuid::new_v4();
        // Seed a token belonging to the principal.
        mocks.api_tokens.seed_token(ApiToken {
            id: token_id,
            user_id,
            name: "ci".into(),
            description: None,
            kind: TokenKind::Pat,
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
            token_prefix: "abcdefgh".into(),
            declared_permissions: vec![],
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: user_id,
            created_at: Utc::now(),
        });
        let mut req = Request::delete(format!("/users/me/tokens/{token_id}"))
            .body(Body::empty())
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(mocks.api_tokens.revoked(), vec![token_id]);
    }

    #[tokio::test]
    async fn delete_self_token_unknown_returns_404() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, _, _) = router_with_principal(&principal);
        let unknown = Uuid::new_v4();
        let mut req = Request::delete(format!("/users/me/tokens/{unknown}"))
            .body(Body::empty())
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "token_not_found");
    }

    #[tokio::test]
    async fn delete_self_token_other_users_token_returns_403_not_authorized() {
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, mocks, _) = router_with_principal(&principal);
        let token_id = Uuid::new_v4();
        mocks.api_tokens.seed_token(ApiToken {
            id: token_id,
            user_id: other_user_id, // belongs to someone else
            name: "x".into(),
            description: None,
            kind: TokenKind::Pat,
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
            token_prefix: "abcdefgh".into(),
            declared_permissions: vec![],
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: other_user_id,
            created_at: Utc::now(),
        });
        let mut req = Request::delete(format!("/users/me/tokens/{token_id}"))
            .body(Body::empty())
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "not_authorized");
        assert!(mocks.api_tokens.revoked().is_empty());
    }

    // -- GET /users/me/tokens ----------------------------------------------

    #[tokio::test]
    async fn get_self_tokens_returns_paginated_list() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, mocks, _) = router_with_principal(&principal);
        // Seed two tokens for the user.
        for i in 0..2 {
            mocks.api_tokens.seed_list(vec![
                ApiToken {
                    id: Uuid::new_v4(),
                    user_id,
                    name: format!("token-{i}"),
                    description: None,
                    kind: TokenKind::Pat,
                    token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
                    token_prefix: "abcdefgh".into(),
                    declared_permissions: vec![Permission::Read],
                    repository_ids: None,
                    expires_at: None,
                    revoked_at: None,
                    last_used_at: None,
                    last_used_ip: None,
                    last_used_user_agent: None,
                    created_by_user_id: user_id,
                    created_at: Utc::now(),
                };
                2
            ]);
        }
        let mut req = Request::get("/users/me/tokens")
            .body(Body::empty())
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["items"].is_array());
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        assert_eq!(v["total"], 2);
        // Anti-pattern: response MUST exclude token_hash.
        for item in v["items"].as_array().unwrap() {
            assert!(item.get("token_hash").is_none());
            assert!(item.get("token").is_none());
        }
    }

    // -- POST /admin/users/:user_id/tokens ---------------------------------

    #[tokio::test]
    async fn post_admin_token_requires_admin_role() {
        // Non-admin caller hitting admin endpoint — AdminPrincipal
        // extractor short-circuits with 403 before the handler runs.
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, _, _) = router_with_principal(&principal);
        let target = Uuid::new_v4();
        let mut req = Request::post(format!("/admin/users/{target}/tokens"))
            .header("content-type", "application/json")
            .body(Body::from(happy_request_body()))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_admin_token_target_not_service_account_returns_400() {
        let admin_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let principal = principal_with_claims(admin_id, &["admin"]);
        let (router, mocks, _) = router_with_principal(&principal);
        // Seed target that is NOT a service account.
        mocks.users.insert(User {
            id: target_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let mut req = Request::post(format!("/admin/users/{target_id}/tokens"))
            .header("content-type", "application/json")
            .body(Body::from(happy_request_body()))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "target_not_service_account");
    }

    #[tokio::test]
    async fn post_admin_token_for_service_account_succeeds() {
        let admin_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let principal = principal_with_claims(admin_id, &["admin"]);
        let (router, mocks, _) = router_with_principal(&principal);
        mocks.users.insert(User {
            id: target_id,
            username: "ci-bot".into(),
            email: "ci-bot@example.com".into(),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: true, // <- the load-bearing distinction
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let mut req = Request::post(format!("/admin/users/{target_id}/tokens"))
            .header("content-type", "application/json")
            .body(Body::from(happy_request_body()))
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["kind"], "service_account");
        let token = v["token"].as_str().unwrap();
        assert!(token.starts_with("hort_svc_"));
        let inserted = mocks.api_tokens.inserted();
        assert_eq!(inserted.len(), 1);
        assert_eq!(inserted[0].user_id, target_id);
        assert_eq!(inserted[0].created_by_user_id, admin_id);
    }

    // -- DELETE /admin/tokens/:id ------------------------------------------

    #[tokio::test]
    async fn delete_admin_token_revokes_any_token() {
        let admin_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let principal = principal_with_claims(admin_id, &["admin"]);
        let (router, mocks, _) = router_with_principal(&principal);
        let token_id = Uuid::new_v4();
        mocks.api_tokens.seed_token(ApiToken {
            id: token_id,
            user_id: owner_id,
            name: "x".into(),
            description: None,
            kind: TokenKind::Pat,
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
            token_prefix: "abcdefgh".into(),
            declared_permissions: vec![],
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: owner_id,
            created_at: Utc::now(),
        });
        let mut req = Request::delete(format!("/admin/tokens/{token_id}"))
            .body(Body::empty())
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(mocks.api_tokens.revoked(), vec![token_id]);
    }

    #[tokio::test]
    async fn delete_admin_token_non_admin_returns_403() {
        let user_id = Uuid::new_v4();
        let principal = principal_with_claims(user_id, &["developer"]);
        let (router, _, _) = router_with_principal(&principal);
        let token_id = Uuid::new_v4();
        let mut req = Request::delete(format!("/admin/tokens/{token_id}"))
            .body(Body::empty())
            .unwrap();
        inject(&mut req, &principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
