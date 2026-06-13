//! `GET /api/v1/auth/whoami` — return the current principal.
//!
//! # RBAC
//!
//! Any authenticated principal may call this endpoint. No permission check
//! beyond successful token validation.
//!
//! # Wire shape
//!
//! ```json
//! {
//!     "user_id": "<uuid|null>",
//!     "username": "<string|null>",
//!     "token_kind": "pat|cli_session|svc_account",
//!     "permissions": ["read", "write", "admin_task_invoke", ...]
//! }
//! ```
//!
//! `user_id` / `username` are `null` for service-account tokens (no
//! human user behind them). `token_kind` is `null` for OIDC-bearer
//! principals that carry no native-token cap.
//! `permissions` is the union of `token_cap.permissions` (when present)
//! or the resolved claim set from the principal (when no cap). For
//! OIDC-bearer principals with no cap the list is derived from
//! `claims` (the claim-based RBAC model — ADR 0012).
//!
//! `effective_grants` is a distinct self-view field —
//! the resolved `(repository, permission)` footprint *this present token*
//! can exercise (`grants ∩ claims ∩ cap`). See [`WhoamiEffectiveGrants`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use uuid::Uuid;

use hort_domain::entities::api_token::{cap_allows_optional_repo, TokenCap};
use hort_domain::entities::rbac::Permission;

use crate::context::AppContext;
use crate::middleware::auth::AuthenticatedPrincipal;

// ---------------------------------------------------------------------------
// Response DTO
// ---------------------------------------------------------------------------

/// Wire response for `GET /api/v1/auth/whoami`.
///
/// `user_id` and `username` are `None` for service-account principals
/// (identified by `token_kind = "svc_account"`).
///
/// `token_kind` is `None` when the principal arrived via an OIDC bearer
/// token with no native-token cap; it is `Some(...)` for PAT /
/// cli-session / service-account native-token principals.
///
/// `permissions` lists the effective permissions carried by the token.
/// For cap-bearing principals this is the cap's `permissions` list.
/// For OIDC-bearer principals the field lists the resolved claim set
/// (e.g. `["admin"]`; ADR 0012)
/// — not a permission enum, but the same human-readable strings
/// operators configure via `kind: ClaimMapping`.
///
/// `effective_grants` is a *distinct* field — the resolved
/// `(repository, permission)` footprint this token can actually exercise.
/// It is NOT a repackaging of `permissions`: `permissions` is the cap's
/// flat permission list (or the resolved claim names for an OIDC bearer),
/// while `effective_grants` is `grants ∩ claims ∩ cap` rendered per
/// repository. See [`WhoamiEffectiveGrants`].
#[derive(Debug, Serialize, PartialEq)]
pub struct WhoamiResponse {
    /// DB row UUID for user-typed tokens; `null` for service accounts.
    pub user_id: Option<Uuid>,
    /// Display name; `null` for service accounts.
    pub username: Option<String>,
    /// Token flavour: `"pat"`, `"cli_session"`, `"svc_account"`, or
    /// `null` for OIDC-bearer sessions.
    pub token_kind: Option<&'static str>,
    /// Effective permissions or roles carried by the token.
    pub permissions: Vec<String>,
    /// The resolved `(repository, permission)` footprint
    /// this present token can exercise: `grants ∩ claims ∩ cap`.
    pub effective_grants: WhoamiEffectiveGrants,
}

/// The resolved-footprint self-view on
/// [`WhoamiResponse`].
///
/// Serializes either as a list of `(repository, permission)` cells (for a
/// non-admin caller, or an admin caller whose token carries a *narrowing*
/// cap) or as the `{ "global_admin": true }` marker (an unrestricted admin
/// — `token_cap = None`). The admin path renders a marker, **never** an
/// enumeration of every repository (unbounded, useless).
///
/// # What this reports — and the staleness caveat
///
/// The footprint is `grants ∩ claims ∩ cap`, mirroring what
/// [`hort_app::rbac::RbacEvaluator::authorize`] itself computes
/// (`cap_leg AND grant_leg`):
///
/// - **claims** are *frozen in the present token* — for a CliSession the
///   JWT carries the claims resolved at login (≤15 min lifetime,
///   ADR 0013); a PAT/SA carries `[]` / `["admin"]`; an OIDC bearer
///   carries the live-resolved set.
/// - **grants** are the *live* `PermissionGrant` set, re-resolved on every
///   call — revoking a grant drops the footprint on the next `whoami`.
/// - **cap** is the token's fixed issuance ceiling
///   ([`cap_allows_optional_repo`]). A capped PAT/SA reports a footprint
///   `⊆ cap`, so it never advertises a `(repository, permission)` the
///   token cannot exercise.
///
/// Because claims are frozen in the token, a `ClaimMapping` / IdP-group
/// change is reflected here only **after the next login** — the
/// IdP-authoritative posture (ADR 0013). The footprint is "what
/// this token can do right now", not "what the user's IdP groups would
/// grant if they re-authenticated".
#[derive(Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum WhoamiEffectiveGrants {
    /// Unrestricted admin (synthetic `admin` claim / `is_admin`) carrying
    /// no narrowing cap. Renders `{ "global_admin": true }`.
    GlobalAdmin {
        /// Always `true` — the field exists so the marker serializes as
        /// the documented `{ "global_admin": true }` object, distinct
        /// from the cell-list array variant.
        global_admin: bool,
    },
    /// The exact `(repository, permission)` cells this token can exercise.
    /// Empty = the token holds nothing.
    Cells(Vec<EffectiveGrantCell>),
}

/// One `(repository, permission)` cell of a [`WhoamiEffectiveGrants`]
/// footprint.
#[derive(Debug, Serialize, PartialEq)]
pub struct EffectiveGrantCell {
    /// The repository key the grant is scoped to, or `null` for a grant
    /// that applies globally (every repository). A per-repo cell whose
    /// repository id no longer resolves to a live repository is omitted
    /// from the footprint entirely — never rendered as `null`, which
    /// would misrepresent it as a global grant.
    pub repository: Option<String>,
    /// The wire permission string (`"read"`, `"write"`, …).
    pub permission: String,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Build the auth route tree.
///
/// Caller nests under `/api/v1/auth`:
/// ```text
/// GET /api/v1/auth/whoami   — return current principal
/// ```
pub fn auth_routes() -> Router<Arc<AppContext>> {
    Router::new().route("/whoami", get(whoami_handler))
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /api/v1/auth/whoami` — return the current principal as JSON.
///
/// No permission check beyond "authenticated": the route is mounted
/// inside the normal auth dispatch (`extract_optional_principal` on
/// GET), but `AuthenticatedCallerExt` rejects with 401 when the
/// extension is absent or `None`.
pub async fn whoami_handler(
    State(ctx): State<Arc<AppContext>>,
    principal: AuthenticatedPrincipalExtractor,
) -> Result<Json<WhoamiResponse>, Response> {
    let caller = principal.0.as_caller();

    // `token_kind` comes from the typed `CallerPrincipal.token_kind`
    // carrier — independent of cap presence. A CliSession
    // carries `token_cap = None` yet is a
    // native-token kind, so it must report `"cli_session"`, NOT `null`.
    // Only a genuine OIDC bearer (`token_kind = None`)
    // reports `null`. Computed once here so the cap-None branch can no
    // longer mis-report a CliSession.
    let token_kind = derive_token_kind(caller);

    // `permissions` (and the svc_account user_id-null rule) still derive
    // from the cap shape.
    let (permissions, user_id, username) = match &caller.token_cap {
        Some(cap) => {
            let perms: Vec<String> = cap
                .permissions
                .iter()
                .map(|p| permission_wire(*p))
                .collect();
            // Service accounts have a real user_id (non-nil) but are denoted
            // by kind. We expose user_id as None only for svc_account kind per
            // the spec: "user_id: null for service accounts".
            let (uid, uname) = if token_kind == Some("svc_account") {
                (None, None)
            } else {
                (Some(caller.user_id), Some(caller.username.clone()))
            };
            (perms, uid, uname)
        }
        None => {
            // No native cap: an OIDC bearer (`token_kind = None`) OR a
            // CliSession (`token_kind = Some(CliSession)`, which carries
            // no cap). Expose the resolved claim set as permission
            // strings (`claims` is the carrier of the principal's
            // resolved authority labels — ADR 0012).
            let perms: Vec<String> = caller.claims.clone();
            (perms, Some(caller.user_id), Some(caller.username.clone()))
        }
    };

    let effective_grants = resolve_effective_grants(&ctx, caller).await;

    Ok(Json(WhoamiResponse {
        user_id,
        username,
        token_kind,
        permissions,
        effective_grants,
    }))
}

/// Resolve the present token's `(repository, permission)`
/// footprint: `grants ∩ claims ∩ cap`.
///
/// Mirrors what [`hort_app::rbac::RbacEvaluator::authorize`] computes per
/// call (`grant_leg AND cap_leg`), but enumerated rather than asked
/// point-wise:
///
/// 1. `effective_grants(claims, Some(user_id), is_admin)` produces the
///    *grant leg* — the cells the caller's claims + user identity hold,
///    cap-agnostic by design.
/// 2. The *cap leg* is applied here, at the consumer, via
///    [`cap_allows_optional_repo`] — the same primitive `authorize` uses.
///    `token_cap = None` (CliSession, OIDC bearer,
///    local session) is a no-op (the helper returns `true`); a capped
///    PAT/SA narrows the footprint to `⊆ cap`.
///
/// The admin marker is rendered **only** for an unrestricted admin
/// (`is_global_admin` AND `token_cap = None`). A capped admin's footprint
/// is `grants ∩ cap = cap` (the admin holds every grant), so it is
/// enumerated from the cap cells — never the marker: an
/// admin token carrying a narrowing cap is not unrestricted, so report its
/// cap-bounded footprint instead.
async fn resolve_effective_grants(
    ctx: &AppContext,
    caller: &hort_domain::entities::caller::CallerPrincipal,
) -> WhoamiEffectiveGrants {
    // The synthetic `admin` claim is carried on `claims` for every admin
    // principal (ADR 0012), so it is also the `is_admin`
    // signal `effective_grants` folds in.
    let is_admin = caller.claims.iter().any(|c| c == "admin");

    // The grant leg comes from the live evaluator. Under
    // `AuthContext::Disabled` there is no evaluator wired (dev / test
    // bootstrap); fail closed and report nothing rather than asserting an
    // authority we cannot verify.
    let Some(rbac) = ctx.auth.rbac() else {
        return WhoamiEffectiveGrants::Cells(Vec::new());
    };
    let evaluator = rbac.load();
    let grant_set = evaluator.effective_grants(&caller.claims, Some(caller.user_id), is_admin);

    if grant_set.is_global_admin {
        // Unrestricted admin → the marker. A *narrowing* cap turns the
        // admin's footprint into the cap itself (grants ⊇ cap), enumerated
        // below.
        if caller.token_cap.is_none() {
            return WhoamiEffectiveGrants::GlobalAdmin { global_admin: true };
        }
        let cells = cap_cells(caller.token_cap.as_ref());
        return render_cells(ctx, cells).await;
    }

    // Non-admin → intersect each grant-leg cell with the cap leg. This is
    // `grants ∩ cap`, the exact composition `authorize` performs.
    let cells: Vec<(Option<Uuid>, Permission)> = grant_set
        .cells
        .into_iter()
        .filter(|&(repo, perm)| cap_allows_optional_repo(caller.token_cap.as_ref(), perm, repo))
        .collect();
    render_cells(ctx, cells).await
}

/// Enumerate the `(repository, permission)` cells a [`TokenCap`] permits.
///
/// Used only for the capped-admin path: the admin holds every grant, so
/// the token's footprint equals the cap, and the cap's own cells are the
/// honest enumeration (`grants ∩ cap = cap`). A `None` cap never reaches
/// this helper (the unrestricted-admin marker handles that), but is
/// treated defensively as "no cells".
///
/// - `repository_ids = None` (global cap) → one `(None, perm)` cell per
///   permission (global on the repo axis, bounded on the permission axis).
/// - `repository_ids = Some(repos)` → one `(Some(repo), perm)` cell per
///   `permission × repository`.
fn cap_cells(cap: Option<&TokenCap>) -> Vec<(Option<Uuid>, Permission)> {
    let Some(cap) = cap else {
        return Vec::new();
    };
    let mut cells = Vec::new();
    for &perm in &cap.permissions {
        match &cap.repository_ids {
            None => cells.push((None, perm)),
            Some(repos) => {
                for &repo in repos {
                    cells.push((Some(repo), perm));
                }
            }
        }
    }
    cells
}

/// Resolve a list of `(repository_id, permission)` cells into the wire
/// [`EffectiveGrantCell`] shape, mapping repository ids to keys for
/// display.
///
/// Repo-key resolution goes through [`RepositoryUseCase::get_by_id`] (a
/// plain CRUD lookup) rather than reaching for the `pub(crate)`
/// `ctx.repositories` data port directly (ADR 0008 anti-pattern). A cell
/// whose repository id no longer resolves to a live repository is omitted
/// (a dangling grant outliving its repo) rather than rendered as a global
/// `null` cell — the caller can exercise no authority on a non-existent
/// repository, so dropping it never under-reports real authority.
async fn render_cells(
    ctx: &AppContext,
    cells: Vec<(Option<Uuid>, Permission)>,
) -> WhoamiEffectiveGrants {
    let mut out = Vec::with_capacity(cells.len());
    for (repo_id, perm) in cells {
        let repository = match repo_id {
            None => None,
            Some(id) => match ctx.repository_use_case.get_by_id(id).await {
                Ok(repo) => Some(repo.key),
                // Dangling grant (repo deleted) or infra hiccup — omit the
                // cell rather than misrepresent it as a global grant.
                Err(_) => continue,
            },
        };
        out.push(EffectiveGrantCell {
            repository,
            permission: permission_wire(perm),
        });
    }
    WhoamiEffectiveGrants::Cells(out)
}

// ---------------------------------------------------------------------------
// AuthenticatedPrincipalExtractor — shared with tests
// ---------------------------------------------------------------------------

/// Extractor that pulls `AuthenticatedPrincipal` from request extensions
/// for the whoami handler. Identical logic to `AuthenticatedCaller` in
/// `api_tokens.rs`; factored here to keep `whoami_handler` thin.
pub struct AuthenticatedPrincipalExtractor(pub AuthenticatedPrincipal);

#[async_trait::async_trait]
impl axum::extract::FromRequestParts<Arc<AppContext>> for AuthenticatedPrincipalExtractor {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(p) = parts.extensions.get::<AuthenticatedPrincipal>() {
            return Ok(Self(p.clone()));
        }
        if let Some(Some(p)) = parts.extensions.get::<Option<AuthenticatedPrincipal>>() {
            return Ok(Self(p.clone()));
        }
        if let Some(None) = parts.extensions.get::<Option<AuthenticatedPrincipal>>() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "authentication required"})),
            )
                .into_response());
        }
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the wire token-kind string from the caller's typed
/// `token_kind` carrier.
///
/// `authenticate_pat` sets `token_kind = Some(validation.kind)` for
/// every native-token kind. The wire strings are pinned by the whoami
/// tests:
/// - `TokenKind::ServiceAccount` → `"svc_account"`
/// - `TokenKind::CliSession` → `"cli_session"`
/// - `TokenKind::Pat` → `"pat"`
/// - `None` (OIDC / local-session — no native cap) → `"pat"` fallback,
///   only reached on the cap-present branch where the kind is expected
///   to be `Some(_)`; a defensive default matching prior behaviour.
///
/// The match is exhaustive over the **current** `TokenKind` variants
/// (`Pat | ServiceAccount | CliSession`) with no `_` arm. If a future
/// refresh-token phase (ADR 0013) adds `TokenKind::Refresh`, this match
/// becomes a deliberate compile error here, forcing a conscious decision
/// rather than a silent mis-label — the same forward-compat-by-construction
/// shape the marker block in
/// `hort-app::authenticate_use_case` uses. (A `Refresh` bearer would
/// never reach whoami anyway — it is refresh-endpoint-only per
/// `docs/auth-catalog.md` Entry 5 — so the future arm maps to `"pat"`.)
fn derive_token_kind(
    caller: &hort_domain::entities::caller::CallerPrincipal,
) -> Option<&'static str> {
    use hort_domain::entities::api_token::TokenKind;
    match caller.token_kind {
        Some(TokenKind::ServiceAccount) => Some("svc_account"),
        Some(TokenKind::CliSession) => Some("cli_session"),
        Some(TokenKind::Pat) => Some("pat"),
        // OIDC bearer — not a native-token kind; reports `null`. The
        // cap-None branch relies on `None => None` so a CliSession reports
        // `cli_session` rather than being lumped in with OIDC bearers.
        None => None,
    }
}

/// Map a [`Permission`] to its wire string.
fn permission_wire(p: Permission) -> String {
    p.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_domain::entities::api_token::{TokenCap, TokenKind};
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::rbac::Permission;

    use super::*;
    use crate::test_support::build_mock_ctx;

    /// Build a principal carrying `claims` + a typed `token_kind`.
    /// `token_kind` is the carrier `derive_token_kind` reads; `claims`
    /// is what the no-cap branch exposes as `permissions`.
    fn principal_with_cap(
        user_id: Uuid,
        claims: &[&str],
        token_kind: Option<TokenKind>,
        cap: Option<TokenCap>,
    ) -> CallerPrincipal {
        CallerPrincipal {
            user_id,
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind,
            issued_at: Utc::now(),
            token_cap: cap,
        }
    }

    fn build_router_for_test() -> Router {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(metrics_handle);
        // Principal is injected per-request via `inject()` below.
        Router::new().merge(auth_routes()).with_state(ctx)
    }

    fn inject(req: &mut Request<axum::body::Body>, p: &CallerPrincipal) {
        crate::middleware::auth::test_support::inject_principal(req, p.clone());
    }

    // -----------------------------------------------------------------------
    // Test 1: whoami returns full payload for a user-typed PAT
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn whoami_returns_principal_for_user_token() {
        let user_id = Uuid::new_v4();
        let cap = TokenCap {
            permissions: vec![Permission::Read, Permission::Write],
            repository_ids: None,
        };
        let principal =
            principal_with_cap(user_id, &["developer"], Some(TokenKind::Pat), Some(cap));
        let router = build_router_for_test();

        let mut req = Request::get("/whoami")
            .body(axum::body::Body::empty())
            .unwrap();
        inject(&mut req, &principal);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(v["user_id"], user_id.to_string());
        assert_eq!(v["username"], "alice");
        assert_eq!(v["token_kind"], "pat");
        let perms = v["permissions"].as_array().unwrap();
        assert!(perms.contains(&serde_json::json!("read")));
        assert!(perms.contains(&serde_json::json!("write")));
    }

    // -----------------------------------------------------------------------
    // Test 2: whoami returns null user_id for service-account token
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn whoami_returns_null_user_id_for_svc_account_token() {
        let svc_user_id = Uuid::new_v4();
        let cap = TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: None,
        };
        // Service accounts are signalled by the typed token-kind
        // carrier, not a "service_account" claim string.
        // A real SA carries `claims == []` (ADR 0012 — SAs never consume
        // claim-subject grants); the wire `token_kind` discriminates it.
        let principal =
            principal_with_cap(svc_user_id, &[], Some(TokenKind::ServiceAccount), Some(cap));
        let router = build_router_for_test();

        let mut req = Request::get("/whoami")
            .body(axum::body::Body::empty())
            .unwrap();
        inject(&mut req, &principal);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            v["user_id"].is_null(),
            "user_id must be null for svc accounts, got {v}"
        );
        assert!(
            v["username"].is_null(),
            "username must be null for svc accounts, got {v}"
        );
        assert_eq!(v["token_kind"], "svc_account");
        assert!(v["permissions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("read")));
    }

    // -----------------------------------------------------------------------
    // Test 3: whoami returns 401 for unauthenticated request
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn whoami_returns_401_for_unauthenticated_request() {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(metrics_handle);
        let router = Router::new().merge(auth_routes()).with_state(ctx);

        // No principal injected — extensions are empty.
        let req = Request::get("/whoami")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "authentication required");
    }

    // -----------------------------------------------------------------------
    // Test 4: OIDC-bearer principal (no cap) exposes claims as permissions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn whoami_oidc_bearer_exposes_claims_as_permissions() {
        let user_id = Uuid::new_v4();
        // No token_cap + token_kind None → OIDC-bearer principal.
        let principal = principal_with_cap(user_id, &["admin"], None, None);
        let router = build_router_for_test();

        let mut req = Request::get("/whoami")
            .body(axum::body::Body::empty())
            .unwrap();
        inject(&mut req, &principal);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(v["user_id"], user_id.to_string());
        assert_eq!(v["username"], "alice");
        // No cap + token_kind None → wire token_kind is null.
        assert!(v["token_kind"].is_null());
        // Claims exposed as permissions (ADR 0012).
        assert!(v["permissions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("admin")));
    }

    // -----------------------------------------------------------------------
    // Test 5: cli_session token kind is reflected correctly
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn whoami_reflects_cli_session_kind() {
        let user_id = Uuid::new_v4();
        let cap = TokenCap {
            permissions: vec![Permission::Read, Permission::Write],
            repository_ids: None,
        };
        let principal = principal_with_cap(user_id, &[], Some(TokenKind::CliSession), Some(cap));
        let router = build_router_for_test();

        let mut req = Request::get("/whoami")
            .body(axum::body::Body::empty())
            .unwrap();
        inject(&mut req, &principal);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(v["token_kind"], "cli_session");
        assert_eq!(v["user_id"], user_id.to_string());
    }

    // =======================================================================
    // `effective_grants` self-view enrichment.
    //
    // These exercise the resolved-footprint field: `grants ∩ claims ∩ cap`.
    // Unlike the tests above (which run under
    // `AuthContext::Disabled` and inject the principal directly), the
    // footprint needs a live `RbacEvaluator`, so the harness flips to
    // `AuthContext::Enabled` with a seeded grant set + seeded repositories
    // for id→key display resolution. Principal injection is unchanged.
    // =======================================================================

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{sample_repository, MockIdentityProvider};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, PermissionGrant};
    use hort_domain::entities::repository::Repository;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;
    use std::sync::Arc;

    use crate::context::AuthContext;
    use crate::test_support::with_auth;

    /// A claims-subject grant fixture.
    fn claims_grant(required: &[&str], repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(required.iter().map(|s| (*s).to_string()).collect()),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    /// A user-subject grant fixture (the service-account / direct-user
    /// authority shape).
    fn user_grant(uid: Uuid, repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::User(uid),
            repository_id: repo,
            permission: perm,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    /// Build a `whoami` router under `AuthContext::Enabled` carrying a
    /// `RbacEvaluator` seeded with `grants`, and seed `repos` into the
    /// repository mock so the handler can resolve repo ids → keys for
    /// display. Returns the router and the seeded repos so callers can
    /// assert on the rendered keys.
    fn build_enabled_router(
        grants: Vec<PermissionGrant>,
        repos: Vec<Repository>,
    ) -> (Router, Vec<Repository>) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        for repo in &repos {
            mocks.repositories.insert(repo.clone());
        }
        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(grants)));
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new().merge(auth_routes()).with_state(ctx);
        (router, repos)
    }

    /// Drive `GET /whoami` for `principal` against `router`, returning the
    /// parsed JSON body.
    async fn whoami_json(router: Router, principal: &CallerPrincipal) -> serde_json::Value {
        let mut req = Request::get("/whoami")
            .body(axum::body::Body::empty())
            .unwrap();
        inject(&mut req, principal);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    // (a) CliSession (token_cap: None) + claims:[developer] + a per-repo
    //     grant → effective_grants lists exactly that (repo_key, permission).
    #[tokio::test]
    async fn whoami_effective_grants_cli_session_lists_per_repo_cell() {
        let user_id = Uuid::new_v4();
        let mut repo = sample_repository();
        repo.key = "npm-proxy".into();
        let repo_id = repo.id;

        // developer-claim grant: Read on the one repo.
        let grants = vec![claims_grant(
            &["developer"],
            Some(repo_id),
            Permission::Read,
        )];
        let (router, _) = build_enabled_router(grants, vec![repo]);

        // CliSession carries its claims in-token; token_cap None ⇒ the
        // cap leg is a no-op.
        let principal =
            principal_with_cap(user_id, &["developer"], Some(TokenKind::CliSession), None);

        let v = whoami_json(router, &principal).await;
        let cells = v["effective_grants"].as_array().expect("cell list");
        assert_eq!(cells.len(), 1, "exactly one (repo, perm) cell: {v}");
        assert_eq!(cells[0]["repository"], "npm-proxy");
        assert_eq!(cells[0]["permission"], "read");
    }

    // (b) admin principal, token_cap: None → the global_admin marker
    //     (never an enumeration of every repo).
    #[tokio::test]
    async fn whoami_effective_grants_admin_no_cap_renders_global_marker() {
        let user_id = Uuid::new_v4();
        // Seed some repos + grants the admin would otherwise "hold" — the
        // marker must NOT enumerate them.
        let mut repo = sample_repository();
        repo.key = "npm-proxy".into();
        let grants = vec![claims_grant(
            &["developer"],
            Some(repo.id),
            Permission::Read,
        )];
        let (router, _) = build_enabled_router(grants, vec![repo]);

        let principal = principal_with_cap(user_id, &["admin"], Some(TokenKind::CliSession), None);

        let v = whoami_json(router, &principal).await;
        assert_eq!(
            v["effective_grants"]["global_admin"], true,
            "unrestricted admin renders the marker, not a cell list: {v}"
        );
        assert!(
            v["effective_grants"].as_array().is_none(),
            "marker must not serialize as a cell array: {v}"
        );
    }

    // (c) THE Finding-1 over-report guard. User holds {Read,Write}×{repoA,
    //     repoB} via User-grants, but the PAT cap is {[Read],[repoA]}. The
    //     reported footprint is EXACTLY {Read@repoA} (⊆ cap) — NOT the
    //     three cap-excluded cells.
    #[tokio::test]
    async fn whoami_effective_grants_capped_pat_reports_exactly_cap_intersection() {
        let user_id = Uuid::new_v4();
        let mut repo_a = sample_repository();
        repo_a.key = "repo-a".into();
        let mut repo_b = sample_repository();
        repo_b.key = "repo-b".into();
        let id_a = repo_a.id;
        let id_b = repo_b.id;

        // User-grants: {Read,Write} × {repoA, repoB} = 4 cells.
        let grants = vec![
            user_grant(user_id, Some(id_a), Permission::Read),
            user_grant(user_id, Some(id_a), Permission::Write),
            user_grant(user_id, Some(id_b), Permission::Read),
            user_grant(user_id, Some(id_b), Permission::Write),
        ];
        let (router, _) = build_enabled_router(grants, vec![repo_a, repo_b]);

        // PAT cap narrows to {[Read], [repoA]} — claims:[] (PATs carry no
        // claim authority), authority is the User-subject grants ∩ cap.
        let cap = TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: Some(vec![id_a]),
        };
        let principal = principal_with_cap(user_id, &[], Some(TokenKind::Pat), Some(cap));

        let v = whoami_json(router, &principal).await;
        let cells = v["effective_grants"].as_array().expect("cell list");
        assert_eq!(
            cells.len(),
            1,
            "capped PAT must report exactly {{Read@repoA}}, not the 4 ungated cells: {v}"
        );
        assert_eq!(cells[0]["repository"], "repo-a");
        assert_eq!(cells[0]["permission"], "read");
        // The three cap-excluded cells must be absent.
        let pairs: Vec<(String, String)> = cells
            .iter()
            .map(|c| {
                (
                    c["repository"].as_str().unwrap_or("").to_string(),
                    c["permission"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        assert!(!pairs.contains(&("repo-a".into(), "write".into())));
        assert!(!pairs.contains(&("repo-b".into(), "read".into())));
        assert!(!pairs.contains(&("repo-b".into(), "write".into())));
    }

    // (d) PAT claims:[], no cap → its User-subject footprint (every
    //     User-grant cell, none filtered — cap leg is a no-op).
    #[tokio::test]
    async fn whoami_effective_grants_uncapped_pat_reports_user_subject_footprint() {
        let user_id = Uuid::new_v4();
        let mut repo = sample_repository();
        repo.key = "repo-x".into();
        let repo_id = repo.id;

        // One global User-grant + one per-repo User-grant.
        let grants = vec![
            user_grant(user_id, None, Permission::Read),
            user_grant(user_id, Some(repo_id), Permission::Write),
        ];
        let (router, _) = build_enabled_router(grants, vec![repo]);

        // claims:[] (PAT carries no claim authority), no cap.
        let principal = principal_with_cap(user_id, &[], Some(TokenKind::Pat), None);

        let v = whoami_json(router, &principal).await;
        let cells = v["effective_grants"].as_array().expect("cell list");
        assert_eq!(cells.len(), 2, "both User-subject grants reported: {v}");
        let pairs: Vec<(serde_json::Value, &str)> = cells
            .iter()
            .map(|c| (c["repository"].clone(), c["permission"].as_str().unwrap()))
            .collect();
        // Global grant → repository null.
        assert!(pairs.contains(&(serde_json::Value::Null, "read")));
        // Per-repo grant → repo key.
        assert!(pairs.contains(&(serde_json::json!("repo-x"), "write")));
    }

    // Capped admin (narrowing cap) → cap-bounded footprint, NOT the
    // marker. The admin holds every grant, so the
    // footprint is the cap itself.
    #[tokio::test]
    async fn whoami_effective_grants_capped_admin_reports_cap_not_marker() {
        let user_id = Uuid::new_v4();
        let mut repo_a = sample_repository();
        repo_a.key = "repo-a".into();
        let id_a = repo_a.id;

        // No grants needed — admin short-circuits the grant leg.
        let (router, _) = build_enabled_router(Vec::new(), vec![repo_a]);

        let cap = TokenCap {
            permissions: vec![Permission::Write],
            repository_ids: Some(vec![id_a]),
        };
        let principal = principal_with_cap(user_id, &["admin"], Some(TokenKind::Pat), Some(cap));

        let v = whoami_json(router, &principal).await;
        assert!(
            v["effective_grants"]["global_admin"].is_null(),
            "capped admin must NOT render the unrestricted marker: {v}"
        );
        let cells = v["effective_grants"].as_array().expect("cell list");
        assert_eq!(cells.len(), 1, "cap-bounded footprint = the cap cells: {v}");
        assert_eq!(cells[0]["repository"], "repo-a");
        assert_eq!(cells[0]["permission"], "write");
    }

    // Capped admin with a global-scoped cap → bounded permission cells with
    // `repository: null` (global on the repo axis, permission-bounded).
    #[tokio::test]
    async fn whoami_effective_grants_capped_admin_global_cap_renders_global_cells() {
        let user_id = Uuid::new_v4();
        let (router, _) = build_enabled_router(Vec::new(), Vec::new());

        let cap = TokenCap {
            permissions: vec![Permission::Read, Permission::Write],
            repository_ids: None,
        };
        let principal = principal_with_cap(user_id, &["admin"], Some(TokenKind::Pat), Some(cap));

        let v = whoami_json(router, &principal).await;
        let cells = v["effective_grants"].as_array().expect("cell list");
        assert_eq!(cells.len(), 2, "one global cell per capped permission: {v}");
        for c in cells {
            assert!(
                c["repository"].is_null(),
                "global-cap cell → null repo: {c}"
            );
        }
    }

    // Auth-disabled context (no evaluator) fails closed: empty cell list,
    // never the admin marker — we cannot assert an authority we cannot
    // verify.
    #[tokio::test]
    async fn whoami_effective_grants_disabled_auth_is_empty_not_admin() {
        let user_id = Uuid::new_v4();
        // build_router_for_test() uses AuthContext::Disabled.
        let router = build_router_for_test();
        // Even an `admin`-claim principal gets an empty footprint here —
        // there is no evaluator to enumerate against.
        let principal = principal_with_cap(user_id, &["admin"], Some(TokenKind::Pat), None);

        let v = whoami_json(router, &principal).await;
        let cells = v["effective_grants"]
            .as_array()
            .expect("disabled-auth renders an (empty) cell list, not the marker");
        assert!(cells.is_empty(), "no evaluator ⇒ empty footprint: {v}");
    }

    // A grant cell whose repo id no longer resolves is omitted (not
    // rendered as a global `null` cell) — a dangling grant outliving its
    // repository.
    #[tokio::test]
    async fn whoami_effective_grants_drops_cell_for_unresolvable_repo() {
        let user_id = Uuid::new_v4();
        let dangling_repo_id = Uuid::new_v4(); // never seeded into the repo mock

        // One resolvable global grant + one per-repo grant on a missing repo.
        let grants = vec![
            user_grant(user_id, None, Permission::Read),
            user_grant(user_id, Some(dangling_repo_id), Permission::Write),
        ];
        let (router, _) = build_enabled_router(grants, Vec::new());

        let principal = principal_with_cap(user_id, &[], Some(TokenKind::Pat), None);

        let v = whoami_json(router, &principal).await;
        let cells = v["effective_grants"].as_array().expect("cell list");
        assert_eq!(
            cells.len(),
            1,
            "the dangling-repo cell is dropped, the global cell remains: {v}"
        );
        assert!(cells[0]["repository"].is_null());
        assert_eq!(cells[0]["permission"], "read");
    }
}
