//! `FromRequestParts` extractors — see module-level docs in [`super`].
//!
//! Four extractors:
//!
//! - [`AdminPrincipal`] — `Permission::Admin`, no repo resolution.
//! - [`WriteRepoAccess`] — `Permission::Write` scoped to a `repo_key` path
//!   param. Resolved `Arc<Repository>` carried on the extractor AND stashed
//!   into request extensions for handler re-use.
//! - [`ReadRepoAccess`] — `Permission::Read`, same shape as Write.
//! - [`DeleteRepoAccess`] — `Permission::Delete`, same shape as Write.
//!   Used by endpoints that destroy landed content visible to other
//!   readers. Cancelling an in-flight
//!   upload stays on `WriteRepoAccess` because no landed content has
//!   become visible yet — the delete-vs-write boundary is "is the
//!   operator destroying landed content visible to other readers".
//!
//! All four delegate metric emission to [`super::emit_authz_decision`] —
//! single call site per extractor, zero duplication across types.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{FromRequestParts, Path};
use axum::http::header::CONTENT_TYPE;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::Response;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::repository::Repository;
use hort_domain::error::DomainError;

use crate::authz::{emit_authz_decision, emit_repo_not_found};
use crate::context::{AppContext, AuthContext};
use crate::middleware::auth::AuthenticatedPrincipal;

// ---------------------------------------------------------------------------
// Permission / result label constants
// ---------------------------------------------------------------------------

const PERMISSION_ADMIN: &str = "admin";
const PERMISSION_READ: &str = "read";
const PERMISSION_WRITE: &str = "write";
/// Label used for `Permission::Delete`
/// authz decisions. The catalog (`docs/metrics-catalog.md`) admits
/// `delete` as a fourth `permission` label value.
const PERMISSION_DELETE: &str = "delete";
/// Label used by [`CurateOrAdminPrincipal`] for
/// the HTTP decision endpoints (`/api/v1/admin/curation/...`).
/// The catalog (`docs/metrics-catalog.md`) admits
/// `curate` as a fifth `permission` label value.
///
/// **Why a single label, not two.** The gate accepts EITHER
/// `Permission::Curate` OR `Permission::Admin`; emitting under
/// `curate` (allow / deny) keeps the curator-surface dashboard
/// independent of the global `admin` decision stream. An admin
/// caller hitting one of these routes still ticks `curate=allow`
/// — the metric tracks "decisions on the curator surface", not
/// "the curator role was the one consulted".
const PERMISSION_CURATE: &str = "curate";
const RESULT_ALLOW: &str = "allow";
const RESULT_DENY: &str = "deny";

// ---------------------------------------------------------------------------
// Extractor types
// ---------------------------------------------------------------------------

/// Asserts the caller carries `Permission::Admin`. Handlers under
/// `admin_routes()` declare this in their signature — forgetting it leaves
/// the handler with no admin-typed operation in scope, which is a
/// compile-time failure rather than a 403 at runtime.
///
/// Payload is the validated [`CallerPrincipal`] for downstream logging /
/// audit.
///
/// Under Disabled, grants unconditionally and logs an info-level audit
/// line. RBAC enforcement resumes when `AuthContext::Enabled`.
#[derive(Debug, Clone)]
pub struct AdminPrincipal(pub CallerPrincipal);

/// Asserts the caller carries EITHER `Permission::Curate` OR
/// `Permission::Admin`. Handlers under the
/// `/api/v1/admin/curation/...` decision surface declare this in their
/// signature — forgetting it leaves the handler with no curator-typed
/// operation in scope (compile-time failure rather than 403 at runtime).
///
/// **Scope is per-route, NOT a broadening of the existing
/// [`AdminPrincipal`] gate.** Mounting the existing `/admin/quarantine/...`
/// or `/admin/users/.../effective-permissions` routes behind this extractor
/// would broaden the global admin gate to also accept curators — that is
/// out of scope: `Permission::Curate` is the
/// day-to-day decision authority over quarantined / rejected artifacts
/// and is strictly less than `Admin`. Use this extractor only on the
/// curation decision routes.
///
/// Payload is the validated [`CallerPrincipal`] for downstream logging /
/// audit (the use case still takes `ApiActor { user_id }` directly).
///
/// **Privilege precedence.** The extractor checks `Permission::Curate`
/// first; on miss it retries with `Permission::Admin`. An admin caller
/// without an explicit `Curate` grant still passes — `RbacEvaluator`
/// short-circuits admin globally — but the metric label fires under
/// `permission="curate"` regardless of which leg succeeded (operator
/// dashboards track decisions on the curator surface, not which authority
/// the evaluator consulted).
///
/// Under Disabled, grants unconditionally and logs an info-level audit
/// line. RBAC enforcement resumes when `AuthContext::Enabled`.
#[derive(Debug, Clone)]
pub struct CurateOrAdminPrincipal(pub CallerPrincipal);

/// Asserts the caller is authenticated. Does NOT check any permission —
/// "any authenticated user can call this" is the contract. Use for
/// surfaces where authentication alone is the gate (e.g. read-only
/// listings exposed to every signed-in operator) and the permission
/// check happens deeper, typically inside the use case.
///
/// Why this exists alongside the four permission-bearing extractors
/// ([`AdminPrincipal`], [`WriteRepoAccess`], [`ReadRepoAccess`],
/// [`DeleteRepoAccess`]): reading the principal directly via
/// `Option<Extension<AuthenticatedPrincipal>>` in a handler is a
/// known footgun — `extract_optional_principal` (the GET-path
/// middleware) writes `Option<AuthenticatedPrincipal>`, NOT the bare
/// `AuthenticatedPrincipal` slot, so the naive extractor returns
/// `None` on every GET in production while passing tests that inject
/// the bare slot via `inject_principal`. This extractor reads both
/// slots correctly via the shared [`extract_principal`] helper, so
/// the handler signature `AuthenticatedCaller(_)` cannot regress to
/// the bug shape. The exact regression that motivated the extractor
/// is documented in `crates/hort-http-admin-tasks/tests/handlers.rs`
/// (the `*_with_optional_principal_*` tests).
///
/// Under Disabled, `extract_principal` still requires a principal
/// (matches every other extractor); call sites that want a no-auth
/// escape hatch handle that condition before invoking the extractor.
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller(pub CallerPrincipal);

/// Asserts the caller carries `Permission::Write` scoped to the repository
/// identified by the `repo_key` route param. Carries the resolved
/// [`Repository`] aggregate; downstream handlers can also pull it from
/// request extensions via `Extension<Arc<Repository>>` — either form reads
/// the same `Arc`, no re-fetch.
///
/// Under Disabled, grants unconditionally and logs an info-level audit
/// line. RBAC enforcement resumes when `AuthContext::Enabled`.
#[derive(Debug, Clone)]
pub struct WriteRepoAccess {
    pub principal: CallerPrincipal,
    pub repository: Arc<Repository>,
}

/// Asserts the caller carries `Permission::Read` scoped to the repository
/// identified by the `repo_key` route param. Shape mirrors
/// [`WriteRepoAccess`].
///
/// Under Disabled, grants unconditionally and logs an info-level audit
/// line. RBAC enforcement resumes when `AuthContext::Enabled`.
#[derive(Debug, Clone)]
pub struct ReadRepoAccess {
    pub principal: CallerPrincipal,
    pub repository: Arc<Repository>,
}

/// Asserts the caller carries `Permission::Delete` scoped to the
/// repository identified by the `repo_key` route param. Shape mirrors
/// [`WriteRepoAccess`].
///
/// `Permission::Delete` is authorized separately from `Permission::Write`
/// — conflating them would equate "I can publish" with "I can destroy
/// landed content". This
/// extractor gates the OCI `DELETE /v2/<name>/manifests/<ref>`
/// surface; cancelling an in-flight upload (`DELETE /v2/<name>/blobs/uploads/<uuid>`)
/// and finalizing one (`PUT /v2/<name>/blobs/uploads/<uuid>?digest=…`)
/// deliberately stay on [`WriteRepoAccess`] — cancelling your own
/// incomplete upload is undoing a write, not destroying landed content.
///
/// The `admin` role short-circuits via the role-name match in
/// `hort_app::rbac::RbacEvaluator::authorize` (rbac.rs:104) so admin-tier
/// principals pass without an explicit `delete` grant.
///
/// Under Disabled, grants unconditionally and logs an info-level audit
/// line. RBAC enforcement resumes when `AuthContext::Enabled`.
#[derive(Debug, Clone)]
pub struct DeleteRepoAccess {
    pub principal: CallerPrincipal,
    pub repository: Arc<Repository>,
}

// ---------------------------------------------------------------------------
// FromRequestParts impls
// ---------------------------------------------------------------------------

/// Axum's [`FromRequestParts::Rejection`] must implement [`IntoResponse`].
/// A bare `Response` qualifies but trips `clippy::result_large_err` once
/// the helper functions start returning `Result<_, Response>` — the
/// `http::Response<Body>` struct is > 128 bytes. Boxing at the helper
/// boundary keeps the happy-path `Ok` arm small; unboxing at the
/// extractor boundary restores the axum-required shape with one cheap
/// move per rejection.
type RejectResponse = Box<Response>;

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for AdminPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal(parts, state).map_err(|b| *b)?;
        authorize(state, &principal, Permission::Admin, None, PERMISSION_ADMIN).map_err(|b| *b)?;
        Ok(Self(principal))
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for CurateOrAdminPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal(parts, state).map_err(|b| *b)?;
        // Privilege precedence — Curate first, Admin as the wider
        // fall-back. `authorize_silent` does NOT emit the per-attempt
        // metric tick on miss (otherwise an admin-only caller would
        // double-count: one `curate=deny` then one `curate=allow`).
        // The final decision is emitted at the bottom of this body
        // via the explicit `emit_authz_decision` call.
        let allowed_via_curate =
            evaluate_rbac(state, &principal, Permission::Curate, None).map_err(|b| *b)?;
        let allowed = if allowed_via_curate {
            true
        } else {
            evaluate_rbac(state, &principal, Permission::Admin, None).map_err(|b| *b)?
        };
        if allowed {
            emit_authz_decision(PERMISSION_CURATE, RESULT_ALLOW);
            tracing::debug!(
                user_id = %principal.user_id,
                permission = PERMISSION_CURATE,
                via_curate = allowed_via_curate,
                "curator-or-admin authorization allowed"
            );
            Ok(Self(principal))
        } else {
            emit_authz_decision(PERMISSION_CURATE, RESULT_DENY);
            tracing::info!(
                user_id = %principal.user_id,
                permission = PERMISSION_CURATE,
                claims = ?principal.claims,
                token_kind = ?principal.token_kind,
                hint = deny_hint(&principal),
                "curator-or-admin authorization denied"
            );
            Err(*forbidden_response())
        }
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for AuthenticatedCaller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal(parts, state).map_err(|b| *b)?;
        Ok(Self(principal))
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for WriteRepoAccess {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal(parts, state).map_err(|b| *b)?;
        let repository = resolve_repository(parts, state).await.map_err(|b| *b)?;
        authorize(
            state,
            &principal,
            Permission::Write,
            Some(repository.id),
            PERMISSION_WRITE,
        )
        .map_err(|b| *b)?;
        parts.extensions.insert(repository.clone());
        Ok(Self {
            principal,
            repository,
        })
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for ReadRepoAccess {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal(parts, state).map_err(|b| *b)?;
        let repository = resolve_repository(parts, state).await.map_err(|b| *b)?;
        authorize(
            state,
            &principal,
            Permission::Read,
            Some(repository.id),
            PERMISSION_READ,
        )
        .map_err(|b| *b)?;
        parts.extensions.insert(repository.clone());
        Ok(Self {
            principal,
            repository,
        })
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for DeleteRepoAccess {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract_principal(parts, state).map_err(|b| *b)?;
        let repository = resolve_repository(parts, state).await.map_err(|b| *b)?;
        authorize(
            state,
            &principal,
            Permission::Delete,
            Some(repository.id),
            PERMISSION_DELETE,
        )
        .map_err(|b| *b)?;
        parts.extensions.insert(repository.clone());
        Ok(Self {
            principal,
            repository,
        })
    }
}

// ---------------------------------------------------------------------------
// Shared extractor plumbing
// ---------------------------------------------------------------------------

/// Pull the authenticated [`CallerPrincipal`] out of request extensions.
///
/// Returns a pre-built `500` [`Response`] on missing principal — that
/// condition is always a router-wiring bug (`require_principal` layer was
/// not attached upstream of this extractor). The wire body is the generic
/// `{"error":"internal error"}`; the tracing line carries the full
/// context at `error!`. Matches the failure mode already established by
/// `handlers/pypi.rs::resolve_actor_user_id` (pypi.rs:752).
///
/// Under [`AuthContext::Disabled`] the extractor still requires a
/// principal. F1 is only engaged on auth-enabled deployments — call sites
/// that want a no-auth escape hatch continue to use the older inline
/// pattern. Accepted as-is: refusing to
/// synthesise a `Uuid::nil()` actor silently is the intended end state,
/// not a transitional step.
fn extract_principal(
    parts: &Parts,
    _state: &Arc<AppContext>,
) -> Result<CallerPrincipal, RejectResponse> {
    // Only the
    // `AuthenticatedPrincipal` newtype is consulted. The bare
    // `CallerPrincipal` extension slot is GONE; a future middleware
    // that injects a `CallerPrincipal` for any reason can no longer
    // silently grant authorization because this function never reads
    // that slot.
    //
    // Two upstream sources populate the newtype:
    //   1. `AuthenticatedPrincipal` directly — `require_principal`
    //      writes this on POST/PUT/DELETE/PATCH paths.
    //   2. `Option<AuthenticatedPrincipal>` —
    //      `extract_optional_principal` writes `Some(p)` on
    //      GET/HEAD/OPTIONS paths when the caller presented a valid
    //      bearer (ADR 0021); the OCI bearer middleware writes
    //      the same shape on `/v2/*` requests.
    //
    // Either source is acceptable. We prefer the direct slot (it's the
    // canonical position the `require_principal` layer uses), but fall
    // back to the optional slot so a GET-side authenticated request
    // (e.g. `GET /admin/repositories/<key>`) still
    // resolves to a real principal instead of falling through to the
    // router-wiring 500.
    if let Some(p) = parts.extensions.get::<AuthenticatedPrincipal>() {
        return Ok(p.as_caller().clone());
    }
    match parts.extensions.get::<Option<AuthenticatedPrincipal>>() {
        Some(Some(p)) => return Ok(p.as_caller().clone()),
        // Explicit `None` means auth ran and the caller did NOT
        // present a token. Return 401 + Bearer challenge so
        // docker/podman/skopeo (and an unauthenticated GET on
        // an admin path) can dance through the token endpoint.
        // This is the documented OCI token flow.
        Some(None) => return Err(unauthorized_bearer_response(parts)),
        None => {}
    }
    // Neither `AuthenticatedPrincipal` nor the
    // `Option<AuthenticatedPrincipal>` sentinel is present — the
    // upstream auth middleware never ran. That's a router-wiring bug.
    tracing::error!(
        "authz extractor invoked without an AuthenticatedPrincipal in extensions — \
         require_principal / oci_bearer_auth layer must run first"
    );
    Err(internal_error_response())
}

/// Build a 401 response with `WWW-Authenticate: Basic` for OCI
/// anonymous-write callers.
///
/// We emit `Basic` here, NOT `Bearer realm=/v2/token`. The OCI
/// subtree's canonical write flow is:
///
/// 1. Client sends `Authorization: Basic <user:idp_jwt>`.
/// 2. `oci_bearer_auth` extracts the JWT from the Basic password
///    and validates via `authenticate_bearer`.
/// 3. `WriteRepoAccess` allows.
///
/// Skopeo / docker / podman / helm all follow `Basic` challenges
/// by re-issuing with their configured Basic credentials
/// preemptively — exactly the path our middleware accepts. A
/// `Bearer realm=/v2/token` challenge would force the OCI-spec
/// token-exchange dance; the legacy `require_principal` middleware
/// already used `Basic` for OCI paths (see
/// `auth.rs::unauthorized_missing_header` pre-Item-7) and this
/// matches that.
fn unauthorized_bearer_response(_parts: &Parts) -> RejectResponse {
    use axum::body::Body;
    use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};

    let challenge = r#"Basic realm="hort""#;
    let body = r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#;
    let resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(WWW_AUTHENTICATE, challenge)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static unauthorized response");
    Box::new(resp)
}

/// Resolve the repository aggregate identified by the `repo_key` route
/// param. Caches the resolved `Arc<Repository>` in request extensions as a
/// side-effect — handlers that also declare `Extension<Arc<Repository>>`
/// read from the same `Arc` with no second fetch.
///
/// Returns a pre-built 404 [`Response`] when the key does not resolve and
/// emits `hort_http_404_repo_lookups_total{format="unknown"}`. Enumeration
/// resistance: every unknown key returns 404 regardless of whether the
/// caller would have been allowed to read a real repo with that key.
/// Distinct from the `deny` signal so operator dashboards can watch
/// probing separately from authorization failures.
///
/// The `format` label cannot be the *real* format (we have no repo to
/// ask); `"unknown"` is the catalog-sanctioned sentinel for
/// pre-resolution misses.
async fn resolve_repository(
    parts: &mut Parts,
    state: &Arc<AppContext>,
) -> Result<Arc<Repository>, RejectResponse> {
    // Fast-path: the extractor was invoked twice in the same request
    // (e.g. a handler that has both `ReadRepoAccess` and
    // `Extension<Arc<Repository>>` — redundant but legal). The second
    // pass must NOT incur a DB round-trip.
    if let Some(existing) = parts.extensions.get::<Arc<Repository>>() {
        return Ok(existing.clone());
    }

    let repo_key = extract_repo_key(parts, state).await?;

    match state.repositories.find_by_key(&repo_key).await {
        Ok(repo) => {
            let arc = Arc::new(repo);
            parts.extensions.insert(arc.clone());
            Ok(arc)
        }
        Err(DomainError::NotFound { .. }) => {
            emit_repo_not_found("unknown");
            tracing::info!(
                repo_key = %repo_key,
                "repository lookup returned 404"
            );
            Err(not_found_response())
        }
        Err(err) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %err,
                "repository lookup failed"
            );
            Err(internal_error_response())
        }
    }
}

/// Pull the `repo_key` capture off the route template. Uses
/// `Path<HashMap<String, String>>` so the extractor works under any
/// downstream handler's route shape (PyPI's nested `:repo_key/:project/...`,
/// cargo's flat `:repo_key`, …).
///
/// Missing key / malformed path → 500 (router-wiring bug: the extractor
/// was mounted on a route without a `:repo_key` segment).
async fn extract_repo_key(
    parts: &mut Parts,
    state: &Arc<AppContext>,
) -> Result<String, RejectResponse> {
    let Path(params) = match Path::<HashMap<String, String>>::from_request_parts(parts, state).await
    {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(
                error = %err,
                "authz extractor could not parse route params — mis-mounted route"
            );
            return Err(internal_error_response());
        }
    };
    match params.get("repo_key") {
        Some(key) => Ok(key.clone()),
        None => {
            tracing::error!(
                "authz extractor invoked on a route without :repo_key — router-wiring bug"
            );
            Err(internal_error_response())
        }
    }
}

/// Operator-facing diagnostic appended to every deny log line.
///
/// The bare `"authorization denied"` line carries who and what but no
/// signal pointing at the GitOps surface that would fix the deny. This
/// helper discriminates the three commonest misconfiguration shapes so
/// the first time an operator sees a 403 they can grep the log for the
/// CRD that needs declaring:
///
/// 1. Empty `claims` — the IdP group claim or `kind: ClaimMapping`
///    binding is the culprit. PermissionGrants are irrelevant until a
///    claim resolves.
/// 2. Claims present, no `token_cap` — the deny is purely an RBAC-grant
///    miss. A `kind: PermissionGrant` declaring this (claims,
///    permission, repository) tuple resolves it.
/// 3. Claims present, `token_cap` set — the deny could be either the
///    RBAC-grant miss above OR the token's cap narrowing the
///    intersection (the two-leg AND). Operator needs to check
///    both the token's scope/repo set and the grant table.
///
/// The cap-aware CliSession branch is keyed off the
/// typed `principal.token_kind == Some(TokenKind::CliSession)` carrier;
/// its four behaviours (empty / cli_session-no-admin-cap /
/// cli_session-with-admin-cap / cli_session-no-cap) are pinned by the
/// tests below.
///
/// The hint is purely a static string for the log — never load-bearing
/// for the deny decision (which is `RbacEvaluator::authorize`'s
/// concern). Returns `&'static str` so adding it to the tracing call
/// has zero allocation overhead on the deny hot path.
fn deny_hint(principal: &CallerPrincipal) -> &'static str {
    use hort_domain::entities::api_token::TokenKind;
    // ServiceAccount-kind tokens carry `claims == []` by
    // construction (ADR 0012: SAs never consume
    // claim_mappings). Routing them through the generic "verify
    // ClaimMapping" branch actively misleads the operator. Branch on
    // the typed `token_kind` carrier first so SAs land on a hint that
    // names the right remediation surfaces (the SA's `repositories`
    // list, the consolidated User-subject grant from `apply_permission_
    // grants`, and the role-derived cap from the federation mint).
    if principal.token_kind == Some(TokenKind::ServiceAccount) {
        "principal is a ServiceAccount token (SAs never consume \
         ClaimMappings). Verify (a) `kind: ServiceAccount` declares this repository in \
         `spec.repositories` and the gitops apply succeeded; (b) the apply log shows the \
         consolidated `permission_grant audit events committed` line — the SA-derived \
         `GrantSubject::User(backing_user_id)` grant lands there; and \
         (c) the token's role-derived cap (developer ⇒ write, reader ⇒ read) covers the \
         requested permission (federation mint)."
    } else if principal.claims.is_empty() && principal.token_kind != Some(TokenKind::CliSession) {
        "principal has no claims — verify the IdP group claim and `kind: ClaimMapping` bindings"
    } else if principal.token_kind == Some(TokenKind::CliSession)
        && principal
            .token_cap
            .as_ref()
            .is_some_and(|c| !c.permissions.contains(&Permission::Admin))
    {
        // Most common admin-from-CLI deny shape. The
        // cli_session principal's cap was minted without admin (no
        // `--admin` at login). The hint points at the most likely
        // remediation; if the deny was actually about a per-repo
        // grant gap, the operator finds out after re-login fails.
        // Pure tracing — never load-bearing on the deny decision.
        "principal authenticated via `hort-cli auth login` (no --admin); the session token's \
         cap does not include admin. Re-login with `hort-cli auth login --admin` to mint a \
         1h admin-capable session, subject to the server's HORT_TOKEN_ALLOW_ADMIN gate."
    } else if principal.token_cap.is_some() {
        "principal has claim(s); deny may be from token-cap narrowing OR a missing \
         `kind: PermissionGrant` — check both the token's allowed scopes/repos and that a \
         matching grant exists"
    } else {
        "principal has claim(s) but no `kind: PermissionGrant` matches this (permission, \
         repository) — declare a PermissionGrant; see \
         docs/architecture/how-to/declare-gitops-config.md"
    }
}

/// Run the RBAC predicate WITHOUT emitting the per-attempt metric tick.
///
/// Used by [`CurateOrAdminPrincipal`]'s two-leg fall-back so an
/// admin-only caller does not double-count one `deny` then one
/// `allow` on the curate label. The caller is responsible for
/// emitting exactly one decision per request via
/// [`emit_authz_decision`].
///
/// `Ok(true)` means "RBAC allows"; `Ok(false)` means "RBAC denies"
/// (the caller decides whether to retry under a different
/// permission or surface a 403). `Err(_)` is the same router-wiring
/// 500 the shared [`authorize`] surfaces when [`AuthContext::Disabled`]
/// — note the inversion: under Disabled this returns `Ok(true)` (the
/// curate-or-admin extractor mirrors `authorize`'s "Disabled = allow"
/// posture).
fn evaluate_rbac(
    state: &Arc<AppContext>,
    principal: &CallerPrincipal,
    permission: Permission,
    repository_id: Option<uuid::Uuid>,
) -> Result<bool, RejectResponse> {
    let rbac_handle = match &state.auth {
        AuthContext::Disabled => {
            // Mirrors `authorize`'s Disabled branch — the F1 extractors
            // grant unconditionally under Disabled. We still need to
            // emit a single allow tick at the call site, so we return
            // `Ok(true)` here and let the caller decide whether to
            // emit (the caller short-circuits on the first `true`).
            tracing::info!(
                user_id = %principal.user_id,
                permission = ?permission,
                repository_id = ?repository_id,
                "authorization granted (auth disabled)"
            );
            return Ok(true);
        }
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => rbac.clone(),
    };
    let rbac = rbac_handle.load();
    Ok(rbac.authorize(principal, permission, repository_id))
}

/// Run the RBAC predicate, emit the allow/deny metric + trace, and shape
/// the 403 response on deny. Shared across all three extractors so metric
/// emission happens at exactly one spot per decision.
fn authorize(
    state: &Arc<AppContext>,
    principal: &CallerPrincipal,
    permission: Permission,
    repository_id: Option<uuid::Uuid>,
    permission_label: &'static str,
) -> Result<(), RejectResponse> {
    let rbac_handle = match &state.auth {
        AuthContext::Disabled => {
            // Disabled deployments opt out of auth entirely. Every F1
            // extractor grants. Audit trail still records the attempted
            // permission + anonymous actor so operators can see what
            // traffic looked like pre-Enabled. This unifies the F1 pattern
            // (extractors) with the legacy pypi/npm/cargo pattern
            // (`resolve_actor_user_id`): handlers can use `WriteRepoAccess`
            // and get correct behaviour under both Enabled and Disabled.
            tracing::info!(
                user_id = %principal.user_id,
                permission = permission_label,
                repository_id = ?repository_id,
                "authorization granted (auth disabled)"
            );
            emit_authz_decision(permission_label, RESULT_ALLOW);
            return Ok(());
        }
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => rbac.clone(),
    };

    // `.load()` returns a `Guard` that derefs
    // to `Arc<RbacEvaluator>`. The load is lock-free; the `Guard`
    // holds the snapshot alive for the duration of this call even if
    // the refresh task swaps underneath.
    let rbac = rbac_handle.load();
    if rbac.authorize(principal, permission, repository_id) {
        emit_authz_decision(permission_label, RESULT_ALLOW);
        tracing::debug!(
            user_id = %principal.user_id,
            permission = permission_label,
            repository_id = ?repository_id,
            "authorization allowed"
        );
        Ok(())
    } else {
        emit_authz_decision(permission_label, RESULT_DENY);
        tracing::info!(
            user_id = %principal.user_id,
            permission = permission_label,
            repository_id = ?repository_id,
            // The resolved claim set is logged here deliberately.
            // Claim *names* are operator-authored and may carry
            // organisational topology, but the deny log is an audit
            // surface that already records who+what; the count is the
            // safe field and the names aid the operator's grep. The
            // "claim names never logged" rule targets metric labels
            // / routine logs, not the security-relevant deny record.
            claims = ?principal.claims,
            token_kind = ?principal.token_kind,
            hint = deny_hint(principal),
            "authorization denied"
        );
        Err(forbidden_response())
    }
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

/// `403` shape used by every extractor on deny. Body is stable — native
/// clients match on `"insufficient permissions"`, so the exact string is
/// load-bearing and mirrored from `handlers/pypi.rs:789`.
fn forbidden_response() -> RejectResponse {
    Box::new(
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"insufficient permissions"}"#))
            .expect("static response"),
    )
}

/// `404` shape used when the `repo_key` does not resolve. Stable body —
/// distinct from the wider `DomainError::NotFound` mapping so future
/// handlers that want their own 404 wording aren't forced through this
/// one. Phrasing matches what downstream clients already see from the
/// existing `ApiError` → `NotFound` path for repositories.
fn not_found_response() -> RejectResponse {
    Box::new(
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"repository not found"}"#))
            .expect("static response"),
    )
}

/// `500` shape used when the extractor hits a router-wiring bug (missing
/// principal, missing :repo_key, Disabled auth context, storage error on
/// lookup). Generic body; tracing carries the specifics.
fn internal_error_response() -> RejectResponse {
    Box::new(
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"internal error"}"#))
            .expect("static response"),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap as StdHashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::test_support::{
        sample_repository, MockRepositoryRepository, MockUserRepository,
    };
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, PermissionGrant};
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::repository_repository::RepositoryRepository;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{Page, PageRequest};

    use crate::context::{AppContext, AuthContext};
    use crate::test_support::{build_mock_ctx, with_auth, with_repositories};

    // ----------------------------------------------------------------
    // Spy repository — counts find_by_key invocations.
    //
    // The shared test-support `MockRepositoryRepository` doesn't expose a
    // call counter (the perf test asserts exactly-one-call, so we need
    // one). Local to this test module; forbidden from touching
    // hort-app/src/use_cases/test_support.rs in this PR.
    // ----------------------------------------------------------------

    struct SpyRepoRepo {
        inner: Mutex<StdHashMap<String, Repository>>,
        by_key_calls: AtomicUsize,
    }

    impl SpyRepoRepo {
        fn new() -> Self {
            Self {
                inner: Mutex::new(StdHashMap::new()),
                by_key_calls: AtomicUsize::new(0),
            }
        }

        fn insert(&self, repo: Repository) {
            self.inner.lock().unwrap().insert(repo.key.clone(), repo);
        }

        fn find_calls(&self) -> usize {
            self.by_key_calls.load(Ordering::Relaxed)
        }
    }

    impl RepositoryRepository for SpyRepoRepo {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Repository>> {
            let result = self
                .inner
                .lock()
                .unwrap()
                .values()
                .find(|r| r.id == id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                });
            Box::pin(async move { result })
        }

        fn find_by_key(&self, key: &str) -> BoxFuture<'_, DomainResult<Repository>> {
            self.by_key_calls.fetch_add(1, Ordering::Relaxed);
            let result =
                self.inner
                    .lock()
                    .unwrap()
                    .get(key)
                    .cloned()
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "Repository",
                        id: key.to_string(),
                    });
            Box::pin(async move { result })
        }

        fn list(
            &self,
            _page: PageRequest,
            _search: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Page<Repository>>> {
            Box::pin(async {
                Ok(Page {
                    items: vec![],
                    total: 0,
                })
            })
        }
        fn save(&self, _repository: &Repository) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn get_virtual_members(
            &self,
            _virtual_repo_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<Repository>>> {
            Box::pin(async { Ok(vec![]) })
        }
        fn add_virtual_member(&self, _v: Uuid, _m: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn remove_virtual_member(&self, _v: Uuid, _m: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn get_storage_usage(&self, _repo_id: Uuid) -> BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }
        fn save_managed(&self, _r: &Repository, _d: &[u8; 32]) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete_managed(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // ----------------------------------------------------------------
    // Metrics helpers — mirror auth.rs::tests for the capture/find
    // pair so extractor tests can assert on individual label pairs.
    // ----------------------------------------------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn find<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != kind || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn prom_handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    // ----------------------------------------------------------------
    // AppContext scaffolding
    // ----------------------------------------------------------------

    /// Build a principal whose resolved claim set is `claims` (the
    /// evaluator subject-matches `principal.claims` — ADR 0012).
    /// `token_kind` defaults
    /// to `None` (OIDC-bearer shape); the deny_hint CliSession cases use
    /// [`cli_session_principal`] for the typed carrier.
    fn principal(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Build a CliSession-kind principal (typed `token_kind` carrier)
    /// for the cap-aware deny_hint regression cases. A
    /// non-admin CliSession carries `claims == []`;
    /// the kind is the typed `token_kind`, never a claim string.
    fn cli_session_principal() -> CallerPrincipal {
        CallerPrincipal {
            token_kind: Some(hort_domain::entities::api_token::TokenKind::CliSession),
            ..principal(&[])
        }
    }

    /// Build a ServiceAccount-kind principal (SAs never consume
    /// claim_mappings, so `claims == []` by
    /// construction). Used by the SA deny-hint regression case
    /// (the SA branch must not point operators at
    /// ClaimMapping).
    fn service_account_principal() -> CallerPrincipal {
        CallerPrincipal {
            token_kind: Some(hort_domain::entities::api_token::TokenKind::ServiceAccount),
            ..principal(&[])
        }
    }

    /// Build an `AppContext` with the supplied repository port
    /// implementation plugged in for direct `.repositories` access.
    ///
    /// Built on
    /// `build_mock_ctx` + `with_repositories` + `with_auth`. The
    /// extractor under test reads `state.repositories.find_by_key()`
    /// directly (see `resolve_repository`); the use cases composed
    /// inside the context are not exercised by these tests, so the
    /// thin slot-swap that `with_repositories` performs is sufficient.
    /// `authorize()` consults `state.auth.rbac` directly (not the
    /// access use case), so flipping auth via `with_auth` carries the
    /// rbac evaluator through.
    fn ctx_with_repos(repos: Arc<dyn RepositoryRepository>, auth: AuthContext) -> Arc<AppContext> {
        let (base, _mocks) = build_mock_ctx(prom_handle());
        let ctx = with_repositories(&base, repos);
        with_auth(&ctx, auth)
    }

    /// Shortcut: an Enabled auth context over the supplied roles + grants,
    /// with the mock authenticate use-case wiring omitted (extractor
    /// tests don't exercise it; they inject principals directly into
    /// request extensions).
    fn enabled_auth(rbac: RbacEvaluator) -> AuthContext {
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::test_support::MockIdentityProvider;
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;

        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            vec![] as Vec<ClaimMapping>,
        ));
        AuthContext::Enabled {
            authenticate,
            // Every test helper that builds an `AuthContext::Enabled`
            // wraps the evaluator in `Arc<ArcSwap<_>>`.
            rbac: Arc::new(arc_swap::ArcSwap::from_pointee(rbac)),
            // Extractor tests don't
            // exercise the `WWW-Authenticate` selector; `None` keeps
            // the realm fallback at "hort".
            issuer_url: None,
        }
    }

    /// Build an RBAC evaluator where the `developer` claim can write on
    /// `repo_id` and the `reader` claim can read anywhere (the
    /// additive-claims subject model, ADR 0012 — a flat
    /// `GrantSubject::Claims` grant set).
    fn rbac_with_write_grant(repo_id: Uuid) -> RbacEvaluator {
        let dev_grant = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["developer".into()]),
            repository_id: Some(repo_id),
            permission: Permission::Write,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        let reader_grant = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["reader".into()]),
            repository_id: None,
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        RbacEvaluator::new(vec![dev_grant, reader_grant])
    }

    // ----------------------------------------------------------------
    // Handlers used by the extractor tests
    // ----------------------------------------------------------------

    async fn admin_handler(_extractor: AdminPrincipal) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("ok"))
            .unwrap()
    }

    /// Handler that also declares `Extension<Arc<Repository>>` to prove
    /// the extractor stashed the aggregate and the second read does NOT
    /// re-fetch.
    async fn write_handler(
        extractor: WriteRepoAccess,
        Extension(from_ext): Extension<Arc<Repository>>,
    ) -> Response {
        assert_eq!(
            extractor.repository.id, from_ext.id,
            "extractor repo and Extension<Arc<Repository>> must be the same aggregate"
        );
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(extractor.repository.key.clone()))
            .unwrap()
    }

    async fn read_handler(extractor: ReadRepoAccess) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(extractor.repository.key.clone()))
            .unwrap()
    }

    async fn delete_handler(extractor: DeleteRepoAccess) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(extractor.repository.key.clone()))
            .unwrap()
    }

    fn admin_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/admin/thing", get(admin_handler))
            .with_state(ctx)
    }

    fn write_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/:repo_key/upload", get(write_handler))
            .with_state(ctx)
    }

    fn read_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/:repo_key/read", get(read_handler))
            .with_state(ctx)
    }

    fn delete_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/:repo_key/delete", get(delete_handler))
            .with_state(ctx)
    }

    /// Build an RBAC evaluator where the `deleter` claim can delete on
    /// `repo_id` (and only that). Used by the [`DeleteRepoAccess`] tests
    /// below. (Flat `GrantSubject::Claims` grant set — ADR 0012.)
    fn rbac_with_delete_grant(repo_id: Uuid) -> RbacEvaluator {
        let deleter_grant = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["deleter".into()]),
            repository_id: Some(repo_id),
            permission: Permission::Delete,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };
        RbacEvaluator::new(vec![deleter_grant])
    }

    /// Build a request with the given principal already injected as an
    /// [`AuthenticatedPrincipal`].
    /// The bare-`CallerPrincipal` slot is never consulted by the
    /// extractors, so tests must mint the newtype just like the
    /// production auth middleware does.
    fn request_with_principal(uri: &str, p: Option<CallerPrincipal>) -> HttpRequest<Body> {
        let mut req = HttpRequest::get(uri).body(Body::empty()).unwrap();
        if let Some(p) = p {
            req.extensions_mut()
                .insert(AuthenticatedPrincipal::from_validated(p));
        }
        req
    }

    fn run_async<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    // ================================================================
    // AdminPrincipal
    // ================================================================

    #[test]
    fn admin_extractor_allows_admin_role() {
        let (snap, status) = capture(|| {
            run_async(async {
                let repos = Arc::new(MockRepositoryRepository::new());
                let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
                let router = admin_router(ctx);
                let req = request_with_principal("/admin/thing", Some(principal(&["admin"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "admin"), ("result", "allow")],
        )
        .expect("admin/allow counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn admin_extractor_denies_non_admin_with_403() {
        let (snap, body_and_status) = capture(|| {
            run_async(async {
                let repos = Arc::new(MockRepositoryRepository::new());
                let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
                let router = admin_router(ctx);
                let req = request_with_principal("/admin/thing", Some(principal(&["reader"])));
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            })
        });
        let (status, body) = body_and_status;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let body_str = String::from_utf8(body).unwrap();
        assert_eq!(body_str, r#"{"error":"insufficient permissions"}"#);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "admin"), ("result", "deny")],
        )
        .expect("admin/deny counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn admin_extractor_returns_500_when_principal_missing() {
        let (status, body) = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let req = request_with_principal("/admin/thing", None);
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // Item 10: no internal leakage on 5xx.
        crate::error::assert_no_internal_leakage(status, &body);
    }

    /// Regression: GETs go through `extract_optional_principal` which
    /// inserts `Option<CallerPrincipal> = Some(principal)` rather
    /// than the bare `CallerPrincipal` slot `require_principal`
    /// uses. The `AdminPrincipal` extractor must accept that source
    /// too — otherwise admin GETs (Init 12's
    /// `GET /admin/repositories/<key>` lookup) 500 with
    /// "router-wiring bug" even though auth ran successfully.
    #[test]
    fn admin_extractor_allows_optional_principal_some_some_path() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let mut req = HttpRequest::get("/admin/thing")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert::<Option<AuthenticatedPrincipal>>(Some(
                    AuthenticatedPrincipal::from_validated(principal(&["admin"])),
                ));
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::OK);
    }

    /// Companion to the test above — `Option<CallerPrincipal> = Some(None)`
    /// (auth ran, caller anonymous) returns 401 with the Bearer
    /// challenge so the OCI flow keeps working. Pin the path the
    /// existing OCI carve-out depends on.
    #[test]
    fn admin_extractor_returns_401_on_optional_principal_none() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let mut req = HttpRequest::get("/admin/thing")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert::<Option<AuthenticatedPrincipal>>(None);
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // -- Layering integration: extract_optional_principal → AdminPrincipal --
    //
    // The two tests above inject `Option<CallerPrincipal>` directly
    // into request extensions. That exercises the extractor in
    // isolation but does NOT exercise the production wiring where
    // `extract_optional_principal` middleware is the upstream
    // producer of that extension on GET / HEAD / OPTIONS paths.
    //
    // The bug fixed in `becb03a` was specifically a missing handshake
    // between the two: middleware wrote `Some(Some(p))`, the
    // extractor only knew `Some(None)` plus the bare `CallerPrincipal`
    // slot, and a successful authenticated GET returned 500 instead
    // of reaching the handler. The next two tests reproduce the
    // production pipeline so the same regression can't slip past
    // the unit suite again.

    /// GET path with a valid bearer that JIT-resolves to an admin
    /// principal. `extract_optional_principal` writes
    /// `Option<CallerPrincipal> = Some(p)`; `AdminPrincipal` must
    /// accept that source and the handler must reach 200.
    ///
    /// Without the fix in `extract_principal`, this test fails with
    /// 500.
    #[test]
    fn admin_get_through_extract_optional_principal_middleware_returns_200() {
        let status = run_async(async {
            let token = "admin-bearer-test-token";
            let ctx = enabled_admin_ctx_with_token(token);
            let router = admin_router_behind_optional(ctx);
            let req = HttpRequest::get("/admin/thing")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap();
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "production layering must let an authenticated GET reach the AdminPrincipal handler"
        );
    }

    /// GET path with no bearer → middleware writes `Some(None)` →
    /// extractor returns 401 + Bearer challenge. Pinned alongside
    /// the 200-path test above so a regression in either direction
    /// is loud.
    #[test]
    fn admin_get_through_extract_optional_principal_middleware_returns_401_when_anonymous() {
        let status = run_async(async {
            let ctx = enabled_admin_ctx_with_token("unused");
            let router = admin_router_behind_optional(ctx);
            let req = HttpRequest::get("/admin/thing")
                .body(Body::empty())
                .unwrap();
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Build an `AppContext` whose `AuthenticateUseCase` is wired to
    /// a mock IdP that accepts `token` and JIT-creates a principal
    /// in the `hort-admins` group, mapped to the `admin`
    /// role. The RBAC admin short-circuit then allows the
    /// `AdminPrincipal` extractor without explicit grants.
    fn enabled_admin_ctx_with_token(token: &str) -> Arc<AppContext> {
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::test_support::MockIdentityProvider;
        use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims};
        use hort_domain::ports::user_repository::UserRepository;

        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token(
            token,
            IdpClaims {
                subject: "kc:admin".into(),
                username: "admin".into(),
                email: "admin@example.com".into(),
                groups: vec!["hort-admins".into()],
                issued_at: Utc::now(),
            },
        );
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp.clone() as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            vec![ClaimMapping {
                id: Uuid::new_v4(),
                idp_group: "hort-admins".into(),
                claim: "admin".into(),
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            }],
        ));
        let auth = AuthContext::Enabled {
            authenticate,
            rbac: Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
                Vec::new(),
            ))),
            // Extractor tests don't
            // exercise the `WWW-Authenticate` selector.
            issuer_url: None,
        };
        ctx_with_repos(Arc::new(MockRepositoryRepository::new()), auth)
    }

    /// Mirror of `admin_router` that ALSO wraps the route with the
    /// `extract_optional_principal` middleware — same shape as
    /// `method_based_auth_dispatch` produces in production for
    /// GET / HEAD / OPTIONS.
    fn admin_router_behind_optional(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/admin/thing", get(admin_handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                crate::middleware::auth::extract_optional_principal,
            ))
            .with_state(ctx)
    }

    // ================================================================
    // WriteRepoAccess
    // ================================================================

    fn seeded_repo() -> (Arc<SpyRepoRepo>, Repository) {
        let mut repo = sample_repository();
        repo.key = "my-repo".into();
        repo.format = RepositoryFormat::Pypi;
        let spy = Arc::new(SpyRepoRepo::new());
        spy.insert(repo.clone());
        (spy, repo)
    }

    #[test]
    fn write_extractor_allows_principal_with_write_grant() {
        // The spy's call counter must be read AFTER the request finishes,
        // so we keep a clone around outside the capture closure.
        let spy_out: Mutex<Option<Arc<SpyRepoRepo>>> = Mutex::new(None);
        let (snap, (status, body_bytes)) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                *spy_out.lock().unwrap() = Some(spy.clone());
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = write_router(ctx);
                let req =
                    request_with_principal("/my-repo/upload", Some(principal(&["developer"])));
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            })
        });
        let find_calls = spy_out.lock().unwrap().as_ref().unwrap().find_calls();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(String::from_utf8(body_bytes).unwrap(), "my-repo");
        // Perf invariant: extractor fetches once; handler's
        // `Extension<Arc<Repository>>` read does NOT produce a second
        // call. (The assert inside `write_handler` proves extractor and
        // extension carry the same Arc; this one proves the port was
        // hit exactly once.)
        assert_eq!(find_calls, 1);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "write"), ("result", "allow")],
        )
        .expect("write/allow counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn write_extractor_denies_principal_without_grant_with_403() {
        let (snap, (status, body)) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = write_router(ctx);
                let req = request_with_principal("/my-repo/upload", Some(principal(&["reader"])));
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            })
        });
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"error":"insufficient permissions"}"#
        );
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "write"), ("result", "deny")],
        )
        .expect("write/deny counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn write_extractor_returns_500_when_principal_missing() {
        let (status, body) = run_async(async {
            let (spy, repo) = seeded_repo();
            let rbac = rbac_with_write_grant(repo.id);
            let ctx = ctx_with_repos(spy, enabled_auth(rbac));
            let router = write_router(ctx);
            let req = request_with_principal("/my-repo/upload", None);
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        crate::error::assert_no_internal_leakage(status, &body);
    }

    #[test]
    fn write_extractor_returns_404_for_unknown_repo_and_emits_404_metric() {
        let (snap, (status, body)) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = write_router(ctx);
                let req =
                    request_with_principal("/ghost-repo/upload", Some(principal(&["developer"])));
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            })
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"error":"repository not found"}"#
        );
        let entries = snap.into_vec();
        // 404 metric must fire.
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_http_404_repo_lookups_total",
            &[("format", "unknown")],
        )
        .expect("hort_http_404_repo_lookups_total{format=unknown} absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        // The authz metric must NOT fire — the 404 short-circuits before
        // the RBAC decision is made.
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "write"), ("result", "allow")]
        )
        .is_none());
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "write"), ("result", "deny")]
        )
        .is_none());
    }

    // ================================================================
    // ReadRepoAccess (mirrors WriteRepoAccess)
    // ================================================================

    #[test]
    fn read_extractor_allows_reader_principal() {
        let (snap, status) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = read_router(ctx);
                let req = request_with_principal("/my-repo/read", Some(principal(&["reader"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "read"), ("result", "allow")],
        )
        .expect("read/allow counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn read_extractor_denies_principal_without_grant() {
        let (snap, status) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = read_router(ctx);
                let req = request_with_principal(
                    "/my-repo/read",
                    // A principal with a role-name not in the evaluator
                    // has zero grants → deny.
                    Some(principal(&["ghost"])),
                );
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::FORBIDDEN);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "read"), ("result", "deny")],
        )
        .expect("read/deny counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn read_extractor_returns_404_for_unknown_repo() {
        let (snap, status) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = read_router(ctx);
                let req = request_with_principal("/ghost/read", Some(principal(&["reader"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let entries = snap.into_vec();
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_http_404_repo_lookups_total",
            &[("format", "unknown")],
        )
        .is_some());
    }

    #[test]
    fn read_extractor_returns_500_when_principal_missing() {
        let (status, body) = run_async(async {
            let (spy, repo) = seeded_repo();
            let rbac = rbac_with_write_grant(repo.id);
            let ctx = ctx_with_repos(spy, enabled_auth(rbac));
            let router = read_router(ctx);
            let req = request_with_principal("/my-repo/read", None);
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        crate::error::assert_no_internal_leakage(status, &body);
    }

    // ================================================================
    // DeleteRepoAccess
    // ================================================================
    //
    // These tests pin "Permission::Delete is what
    // DeleteRepoAccess authorizes against". A future refactor that
    // accidentally drops the new constant or wires the extractor to
    // Permission::Write must show up here as a fail.

    #[test]
    fn delete_extractor_allows_principal_with_delete_grant() {
        let (snap, status) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_delete_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = delete_router(ctx);
                let req = request_with_principal("/my-repo/delete", Some(principal(&["deleter"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "delete"), ("result", "allow")],
        )
        .expect("delete/allow counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn delete_extractor_denies_principal_with_only_write_grant_with_403() {
        // Critical reclassification assertion: a principal granted
        // `Permission::Write` does NOT satisfy `DeleteRepoAccess`. This
        // is the boundary M-A5 closes — pre-fix, the OCI manifest
        // delete handler used `WriteRepoAccess` so a write-only role
        // could destroy landed manifests. Post-fix, the same role
        // gets a clean 403.
        let (snap, (status, body)) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_write_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = delete_router(ctx);
                let req =
                    request_with_principal("/my-repo/delete", Some(principal(&["developer"])));
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            })
        });
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"error":"insufficient permissions"}"#
        );
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "delete"), ("result", "deny")],
        )
        .expect("delete/deny counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        // The write-permission counter must NOT fire — the extractor
        // checked `Permission::Delete`, not `Permission::Write`.
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "write"), ("result", "allow")]
        )
        .is_none());
    }

    #[test]
    fn delete_extractor_admin_role_short_circuits_via_name_bypass() {
        // The `admin` role short-circuits in
        // `RbacEvaluator::authorize` (rbac.rs:104) without consulting
        // any grants. Even with zero `permission_grants` rows seeded,
        // an admin principal must satisfy `DeleteRepoAccess`. This
        // pins the "admin role is unaffected" line in the M-A5
        // CHANGELOG entry.
        let (snap, status) = capture(|| {
            run_async(async {
                let (spy, _repo) = seeded_repo();
                // Empty evaluator — proves the admin path doesn't
                // even need a Role row to exist.
                let rbac = RbacEvaluator::new(Vec::new());
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = delete_router(ctx);
                let req = request_with_principal("/my-repo/delete", Some(principal(&["admin"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "delete"), ("result", "allow")],
        )
        .expect("delete/allow counter absent on admin short-circuit path");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn delete_extractor_returns_404_for_unknown_repo() {
        // Repo-not-found short-circuits before the RBAC decision —
        // mirror the WriteRepoAccess equivalent. Pinning this lets a
        // future enumeration-resistance regression on the delete path
        // surface here instead of as a behavioural diff in the OCI
        // smoke tests.
        let (snap, status) = capture(|| {
            run_async(async {
                let (spy, repo) = seeded_repo();
                let rbac = rbac_with_delete_grant(repo.id);
                let ctx = ctx_with_repos(spy, enabled_auth(rbac));
                let router = delete_router(ctx);
                let req =
                    request_with_principal("/ghost-repo/delete", Some(principal(&["deleter"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let entries = snap.into_vec();
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_http_404_repo_lookups_total",
            &[("format", "unknown")],
        )
        .is_some());
        // No authz decision metric — short-circuit fired.
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "delete"), ("result", "allow")]
        )
        .is_none());
        assert!(find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "delete"), ("result", "deny")]
        )
        .is_none());
    }

    // ================================================================
    // Disabled auth context — extractor grants unconditionally and
    // records an audit-allow counter tick so operators can still see
    // Disabled traffic.
    // ================================================================

    // ================================================================
    // AuthenticatedPrincipal-newtype security-lock tests
    // ================================================================
    //
    // The whole point of the `AuthenticatedPrincipal` newtype is that
    // a bare `CallerPrincipal` in request extensions can no longer
    // grant authorization. These tests pin both directions of the
    // boundary — the architect rule says "every middleware test must
    // drive both the allow and deny paths."

    /// **Security lock — deny path.** A foreign middleware that
    /// (mistakenly or maliciously) inserts a bare `CallerPrincipal`
    /// MUST NOT satisfy the `AdminPrincipal` extractor. Pre-Item-21
    /// the bare slot was the canonical position; post-Item-21 it is
    /// not consulted at all and the request 500s with the
    /// router-wiring-bug envelope.
    #[test]
    fn admin_extractor_rejects_bare_caller_principal_extension() {
        let (status, body) = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let mut req = HttpRequest::get("/admin/thing")
                .body(Body::empty())
                .unwrap();
            // Inject ONLY the bare `CallerPrincipal`. The newtype slot
            // stays empty. Pre-Item-21 this satisfied `AdminPrincipal`
            // and authorized as admin; post-Item-21 it must 500 (no
            // upstream auth ran, from the extractor's perspective).
            req.extensions_mut().insert(principal(&["admin"]));
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "bare CallerPrincipal must not authenticate"
        );
        crate::error::assert_no_internal_leakage(status, &body);
    }

    /// **Security lock — allow path.** A request whose extensions
    /// carry a properly-minted `AuthenticatedPrincipal` reaches the
    /// admin handler. Together with the deny test above, this pins
    /// the contract: only the authentication boundary's mint can grant
    /// authorization.
    #[test]
    fn admin_extractor_accepts_authenticated_principal_extension() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let mut req = HttpRequest::get("/admin/thing")
                .body(Body::empty())
                .unwrap();
            // The mint goes through the `pub(crate)` constructor —
            // accessible here because this test lives inside
            // `hort-http-core`. Outside this crate the only way to
            // reach this constructor is via the auth middleware or
            // the named seam in `hort-http-core::middleware::auth`.
            req.extensions_mut()
                .insert(AuthenticatedPrincipal::from_validated(principal(&[
                    "admin",
                ])));
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn extractor_under_disabled_auth_grants_with_audit_info() {
        // Under `AuthContext::Disabled` every F1 extractor must grant
        // (the deployment has opted out of auth) while still emitting
        // the `hort_authz_decisions_total{result="allow"}` counter so
        // operators keep audit visibility pre-Enabled. The legacy
        // `resolve_actor_user_id` pattern had the same shape; this
        // unifies F1 with it.
        let (snap, status) = capture(|| {
            run_async(async {
                let repos = Arc::new(MockRepositoryRepository::new());
                let ctx = ctx_with_repos(repos, AuthContext::Disabled);
                let router = admin_router(ctx);
                let req = request_with_principal("/admin/thing", Some(principal(&["admin"])));
                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
        });
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_authz_decisions_total",
            &[("permission", "admin"), ("result", "allow")],
        )
        .expect("admin/allow counter absent under Disabled");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // ================================================================
    // deny_hint — operator-facing diagnostic on the deny log
    //
    // The helper is pure (no I/O, no state) so the three branches get
    // unit tests directly. A separate `#[traced_test]` further down
    // pins the wiring from `authorize`'s deny path into the actual log
    // record, so a future refactor cannot quietly drop the field.
    // ================================================================

    #[test]
    fn deny_hint_empty_claims_points_at_claim_mapping() {
        // Empty `claims`, and not a
        // CliSession principal (those route to the cap-aware branch).
        let p = principal(&[]);
        let hint = deny_hint(&p);
        assert!(hint.contains("ClaimMapping"), "hint: {hint}");
        assert!(hint.contains("group claim"), "hint: {hint}");
    }

    #[test]
    fn deny_hint_role_no_token_cap_points_at_permission_grant() {
        let p = principal(&["developer"]);
        let hint = deny_hint(&p);
        assert!(hint.contains("PermissionGrant"), "hint: {hint}");
        assert!(
            hint.contains("declare-gitops-config.md"),
            "hint should link to the gitops how-to: {hint}"
        );
    }

    #[test]
    fn deny_hint_with_token_cap_mentions_both_token_and_grant() {
        use hort_domain::entities::api_token::TokenCap;
        use hort_domain::entities::rbac::Permission;
        let mut p = principal(&["developer"]);
        p.token_cap = Some(TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: None,
        });
        let hint = deny_hint(&p);
        assert!(hint.contains("token-cap"), "hint: {hint}");
        assert!(hint.contains("PermissionGrant"), "hint: {hint}");
    }

    // -----------------------------------------------------------------------
    // Cap-aware deny-hint for cli_session principals.
    //
    // Four-row matrix:
    //   1. cli_session + cap lacks admin → new --admin hint
    //   2. cli_session + cap has admin → falls through to generic
    //      (token-cap branch) — narrower deny hint is wrong for a
    //      principal that already has admin
    //   3. pat + cap lacks admin → falls through (no --admin hint;
    //      Pat's remediation is to re-mint with admin permission,
    //      not hort-cli auth login --admin)
    //   4. cli_session + no cap → falls through (defensive; shouldn't
    //      happen in production but the hint mustn't crash)
    // -----------------------------------------------------------------------

    fn cap_with(permissions: Vec<Permission>) -> hort_domain::entities::api_token::TokenCap {
        hort_domain::entities::api_token::TokenCap {
            permissions,
            repository_ids: None,
        }
    }

    #[test]
    fn deny_hint_cli_session_without_admin_cap_points_at_admin_relogin() {
        let mut p = cli_session_principal();
        p.token_cap = Some(cap_with(vec![Permission::Read, Permission::Write]));
        let hint = deny_hint(&p);
        assert!(
            hint.contains("hort-cli auth login --admin"),
            "expected --admin remediation hint: {hint}"
        );
        assert!(
            hint.contains("HORT_TOKEN_ALLOW_ADMIN"),
            "expected HORT_TOKEN_ALLOW_ADMIN reference: {hint}"
        );
    }

    #[test]
    fn deny_hint_cli_session_with_admin_cap_falls_through_to_generic() {
        // Admin scope is present but the deny still fired — likely a
        // per-repo grant gap, not a scope-narrowing issue. The
        // generic token-cap hint is the correct remediation; the
        // --admin hint would be misleading.
        let mut p = cli_session_principal();
        p.token_cap = Some(cap_with(vec![
            Permission::Admin,
            Permission::Read,
            Permission::Write,
        ]));
        let hint = deny_hint(&p);
        assert!(
            !hint.contains("hort-cli auth login --admin"),
            "cli_session WITH admin cap must not get --admin hint: {hint}"
        );
        assert!(hint.contains("token-cap"), "hint: {hint}");
    }

    #[test]
    fn deny_hint_pat_without_admin_falls_through_to_generic() {
        // PAT principals are not cli_session principals; the
        // --admin hint points at the wrong remediation (re-minting
        // a PAT requires a different flow). Fall through to the
        // generic token-cap branch.
        let mut p = principal(&["developer"]);
        p.token_cap = Some(cap_with(vec![Permission::Read]));
        let hint = deny_hint(&p);
        assert!(
            !hint.contains("hort-cli auth login --admin"),
            "non-CliSession principal (token_kind != CliSession) must not get --admin hint: {hint}"
        );
        assert!(hint.contains("token-cap"), "hint: {hint}");
    }

    /// A `TokenKind::ServiceAccount` principal denied with
    /// `claims == []` must NOT receive the misleading "verify the IdP
    /// group claim and `kind: ClaimMapping` bindings" hint; SAs never
    /// consume claim_mappings (ADR 0012). The
    /// SA-specific branch must point at the `kind: ServiceAccount` /
    /// User-subject grant surface. The hint may
    /// reference ClaimMapping as a *disclaimer* ("SAs never consume…"),
    /// but it must not steer the operator at that surface as the
    /// remediation.
    #[test]
    fn deny_hint_service_account_branch_does_not_point_at_claim_mapping() {
        let p = service_account_principal();
        let hint = deny_hint(&p);
        assert!(
            !hint.contains("verify the IdP group claim"),
            "SA deny hint must not steer at IdP group / ClaimMapping bindings \
             (SAs never consume ClaimMappings); got: {hint}"
        );
        assert!(
            hint.contains("ServiceAccount"),
            "SA deny hint should reference the ServiceAccount surface; got: {hint}"
        );
        assert!(
            hint.contains("spec.repositories") || hint.contains("User-subject"),
            "SA deny hint should mention SA repositories or the SA-derived User-subject \
             grant — the two operator-actionable surfaces; got: {hint}"
        );
    }

    #[test]
    fn deny_hint_cli_session_without_cap_falls_through() {
        // Defensive: a CliSession principal without a token_cap
        // (shouldn't happen — every authenticate_pat path sets it,
        // and OIDC bearers carry token_kind = None) must not match
        // the cap-aware branch since the cap-check sees None and the
        // `is_some_and` short-circuits to false. It must also NOT hit
        // the "empty claims" branch (the `token_kind == CliSession`
        // guard excludes it) — it falls through to the grant-miss hint.
        let p = cli_session_principal();
        // token_cap defaults to None via principal()
        let hint = deny_hint(&p);
        assert!(
            !hint.contains("hort-cli auth login --admin"),
            "CliSession without cap must not get --admin hint: {hint}"
        );
        assert!(hint.contains("PermissionGrant"), "hint: {hint}");
    }

    /// Pin the deny-log wiring: a cli_session principal
    /// without admin cap denied on an admin operation must surface the
    /// `--admin` hint in the audit log line. Mirrors the existing
    /// `deny_log_carries_permission_grant_hint_for_role_principal_without_grant`
    /// test pattern.
    #[tracing_test::traced_test]
    #[test]
    fn deny_log_carries_admin_relogin_hint_for_cli_session_principal_without_admin_cap() {
        use hort_domain::entities::rbac::Permission;
        run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            // Empty evaluator: every authorize() returns false → deny.
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let mut p = cli_session_principal();
            p.token_cap = Some(hort_domain::entities::api_token::TokenCap {
                permissions: vec![Permission::Read, Permission::Write, Permission::Delete],
                repository_ids: None,
            });
            let req = request_with_principal("/admin/thing", Some(p));
            router.oneshot(req).await.unwrap()
        });
        assert!(logs_contain("hort-cli auth login --admin"));
    }

    /// Pins the deny-path tracing wiring: the role-bearing principal
    /// path through `authorize` must surface the `PermissionGrant` hint
    /// in the log record so an operator grepping for the CRD name in
    /// their log shipper finds the right line.
    #[tracing_test::traced_test]
    #[test]
    fn deny_log_carries_permission_grant_hint_for_role_principal_without_grant() {
        run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = admin_router(ctx);
            let req = request_with_principal("/admin/thing", Some(principal(&["reader"])));
            router.oneshot(req).await.unwrap()
        });
        assert!(
            logs_contain("authorization denied"),
            "deny log line missing"
        );
        assert!(
            logs_contain("PermissionGrant"),
            "operator-facing PermissionGrant hint missing from deny log"
        );
    }

    // ================================================================
    // AuthenticatedCaller — reads either principal slot
    //
    // The four cases pin extract_principal's slot-reading contract via
    // the public extractor. A regression to "read only bare slot" would
    // fail case 2 (the production GET shape).
    // ================================================================

    fn caller_router(ctx: Arc<AppContext>) -> Router {
        async fn handler(_caller: AuthenticatedCaller) -> StatusCode {
            StatusCode::OK
        }
        Router::new().route("/caller", get(handler)).with_state(ctx)
    }

    #[test]
    fn authenticated_caller_accepts_bare_authenticated_principal_slot() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = caller_router(ctx);
            let req = request_with_principal("/caller", Some(principal(&["reader"])));
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn authenticated_caller_accepts_option_principal_some_slot() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = caller_router(ctx);
            let mut req = HttpRequest::get("/caller").body(Body::empty()).unwrap();
            // Production GET path shape — extract_optional_principal
            // writes Some(principal) to this slot, NOT the bare slot.
            // The 2026-05-11 regression was reading the wrong slot,
            // 403'ing every authenticated GET while bare-slot tests
            // continued to pass.
            req.extensions_mut()
                .insert::<Option<AuthenticatedPrincipal>>(Some(
                    AuthenticatedPrincipal::from_validated(principal(&["reader"])),
                ));
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "AuthenticatedCaller MUST accept Option<AuthenticatedPrincipal>=Some — this is the \
             production GET-path shape from extract_optional_principal middleware"
        );
    }

    #[test]
    fn authenticated_caller_returns_401_for_option_principal_none_slot() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = caller_router(ctx);
            let mut req = HttpRequest::get("/caller").body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert::<Option<AuthenticatedPrincipal>>(None);
            router.oneshot(req).await.unwrap().status()
        });
        // "auth middleware ran, caller didn't present a token" → 401
        // + Bearer challenge so OCI clients can dance through the
        // token endpoint. Same shape `extract_principal` produces for
        // every other extractor in this module.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn authenticated_caller_returns_500_when_no_principal_slot_present() {
        let status = run_async(async {
            let repos = Arc::new(MockRepositoryRepository::new());
            let ctx = ctx_with_repos(repos, enabled_auth(RbacEvaluator::new(Vec::new())));
            let router = caller_router(ctx);
            // No principal slot of either shape — router-wiring bug.
            // Production never reaches a handler without one of the
            // auth-middleware variants running (router::auth_dispatch
            // is unconditional); this test pins the defensive 500.
            let req = HttpRequest::get("/caller").body(Body::empty()).unwrap();
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
