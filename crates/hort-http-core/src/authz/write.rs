//! Shared authorization helper for write-path handlers.
//!
//! Every write-path format handler (pypi / cargo / npm / …) resolves the
//! incoming `ApiActor` user-id through [`resolve_actor_user_id`]. The
//! helper owns:
//!
//! - The branch on [`AuthContext::Disabled`] → returns [`Uuid::nil()`]
//!   (anonymous pass-through when auth is disabled).
//! - The RBAC call on [`AuthContext::Enabled`] against
//!   [`Permission::Write`] + the request's repository id.
//! - Emission of `hort_authz_decisions_total{result, permission}` exactly
//!   once per handler invocation.
//! - The stable `403 {"error":"insufficient permissions"}` response body
//!   on deny (load-bearing — native clients match on it).
//! - The `500 {"error":"internal error"}` fallback when the router-level
//!   `require_principal` layer failed to run.
//!
//! The auth-mechanism inventory lives in `docs/auth-catalog.md`.

use axum::body::Body;
use axum::extract::Extension;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::Response;
use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::repository::{Repository, RepositoryType};

use crate::context::{AppContext, AuthContext};
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedPrincipal;

/// `hort_authz_decisions_total{result, permission}` — emitted after every
/// `RbacEvaluator::authorize()` call on a write-path handler. Catalog: see
/// `docs/metrics-catalog.md`, "Authorization decisions" section.
///
/// Not emitted under [`AuthContext::Disabled`] — the metric answers
/// "what did the authz decision look like", and under `Disabled` no
/// decision was made at all.
pub fn emit_authz_metric(result: &'static str, permission: &'static str) {
    metrics::counter!(
        "hort_authz_decisions_total",
        "result" => result,
        "permission" => permission,
    )
    .increment(1);
}

/// Result of [`resolve_actor_user_id`] — the happy path returns the actor
/// user id; both failure modes carry a fully-formed [`Response`] so the
/// helper owns the exact 403 body shape. Boxed so the `Result` stays
/// small (`clippy::result_large_err`).
///
/// Why `Response` rather than an `ApiError`? The deny body must be
/// exactly `{"error":"insufficient permissions"}`, matching
/// what native clients may match on. The default
/// `ApiError → DomainError::Forbidden` mapping in
/// [`crate::error::ApiError::into_response`] prepends `forbidden: ` to
/// the message via `DomainError`'s `Display`, so it can't be reused
/// here without clobbering the wire shape.
pub type AuthzReject = Box<Response>;

/// Resolve the actor user-id for a write-path handler, emitting the RBAC
/// decision metric and the `tracing::info!` deny audit line when the
/// authz check fires.
///
/// # Behaviour
///
/// - [`AuthContext::Disabled`]: returns [`Uuid::nil()`] unconditionally —
///   anonymous pass-through. No metric emission, no RBAC call.
/// - [`AuthContext::Enabled`] with `Some(Extension(principal))`: consults
///   [`hort_app::rbac::RbacEvaluator::authorize`] for [`Permission::Write`]
///   scoped to `repo_id`. Emits `result=allow` / `result=deny` on
///   `hort_authz_decisions_total`. Returns the principal's `user_id` on
///   allow; returns a `403` [`Response`] with the stable body
///   `{"error":"insufficient permissions"}` on deny.
/// - [`AuthContext::Enabled`] with `None`: the `require_principal` layer
///   did not run — always a router-wiring bug. Returns a `500`
///   [`Response`] with a generic body. The error string is deliberately
///   generic on the wire; tracing carries the full context at `error!`.
pub fn resolve_actor_user_id(
    ctx: &AppContext,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    repo_id: Uuid,
) -> Result<Uuid, AuthzReject> {
    match &ctx.auth {
        AuthContext::Disabled => Ok(Uuid::nil()),
        AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => {
            // The handler signature demands the `AuthenticatedPrincipal`
            // newtype slot. A future middleware that injects a bare
            // `CallerPrincipal` cannot reach this helper.
            let Some(Extension(authed)) = principal else {
                tracing::error!(
                    repository_id = %repo_id,
                    "require_principal layer must run before write-path handler"
                );
                return Err(Box::new(internal_error_response_body()));
            };
            let principal: &CallerPrincipal = authed.as_caller();
            // `.load()` returns a `Guard` that derefs to
            // `Arc<RbacEvaluator>`. Lock-free; the guard keeps the
            // snapshot alive even if the refresh task swaps underneath.
            let rbac = rbac.load();
            if rbac.authorize(principal, Permission::Write, Some(repo_id)) {
                emit_authz_metric("allow", "write");
                tracing::debug!(
                    user_id = %principal.user_id,
                    permission = "write",
                    repository_id = %repo_id,
                    "authorization allowed"
                );
                Ok(principal.user_id)
            } else {
                emit_authz_metric("deny", "write");
                tracing::info!(
                    user_id = %principal.user_id,
                    permission = "write",
                    repository_id = %repo_id,
                    "authorization denied"
                );
                Err(Box::new(forbidden_response_body()))
            }
        }
    }
}

/// Build the stable 403 response body used by every write-path deny.
///
/// Wire shape is `{"error":"insufficient permissions"}` — exactly. Native
/// clients may match on this string, so it is load-bearing.
fn forbidden_response_body() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"insufficient permissions"}"#))
        .expect("static response")
}

/// Build the 500 body used when the `require_principal` layer failed to
/// run upstream. Generic message — the tracing layer carries the full
/// context.
fn internal_error_response_body() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"internal error"}"#))
        .expect("static response")
}

/// Reject a write (publish / upload) to a `type: virtual` repository
/// (ADR 0031). Returns `Err(ApiError)` (400 Bad Request) when
/// `repo.repo_type` is [`RepositoryType::Virtual`], `Ok(())` otherwise.
///
/// Virtual repositories are read-only aggregators: they have no own store
/// and resolve reads by composing their members. A publish that reaches a
/// format write handler would otherwise fall into the hosted arm and
/// silently write the *virtual's* own (never-served) store. Every per-format
/// write path calls this **after** [`resolve_actor_user_id`] (so a caller
/// without Write still gets the stable 403 rather than a repo-type oracle)
/// and surfaces the returned [`ApiError`] verbatim via `?`.
///
/// Shared here rather than re-implemented per format crate so the rejection
/// envelope stays identical across npm / PyPI / Cargo.
pub fn reject_write_to_virtual(repo: &Repository) -> Result<(), ApiError> {
    if matches!(repo.repo_type, RepositoryType::Virtual) {
        return Err(ApiError::from(hort_app::error::AppError::Domain(
            hort_domain::error::DomainError::Validation(format!(
                "cannot publish to virtual repository `{}`: virtual repositories are \
                 read-only aggregators; publish to a member repository instead",
                repo.key
            )),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use hort_app::use_cases::test_support::sample_repository;

    use super::*;

    fn repo_of_type(t: RepositoryType) -> Repository {
        let mut r = sample_repository();
        r.repo_type = t;
        r
    }

    #[test]
    fn reject_write_to_virtual_rejects_virtual_with_400() {
        let err = reject_write_to_virtual(&repo_of_type(RepositoryType::Virtual)).unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn reject_write_to_virtual_allows_non_virtual_types() {
        for t in [
            RepositoryType::Hosted,
            RepositoryType::Proxy,
            RepositoryType::Staging,
        ] {
            assert!(
                reject_write_to_virtual(&repo_of_type(t)).is_ok(),
                "non-virtual type {t:?} must be allowed"
            );
        }
    }
}
