//! Maps `SubscriptionError` from the use case to HTTP responses.
//!
//! Mapping table mirrors design doc §5 reject paths verbatim:
//!
//! | `SubscriptionError` variant | HTTP status | Body `error` |
//! |---|---|---|
//! | `UnsupportedEventType` | 400 | `unsupported_event_type` |
//! | `RepoNotAuthorised` | 403 | `repo_not_authorised` |
//! | `AdminScopeRequiresAdmin` | 403 | `admin_scope_requires_admin` |
//! | `AdminScopeRequiresUncappedToken` | 403 | `admin_scope_requires_uncapped_token` |
//! | `RepoScopeMustBeExplicit` | 400 | `repo_scope_must_be_explicit` |
//! | `RepoScopeExceedsTokenCap` | 403 | `repo_scope_exceeds_token_cap` |
//! | `PlaintextWebhookDisallowed` | 400 | `plaintext_webhook_disallowed` |
//! | `WebhookTargetNotRoutable` | 400 | `webhook_target_not_routable` |
//! | `InvalidNatsSubject` | 400 | `invalid_nats_subject` |
//! | `DuplicateName` | 409 | `duplicate_name` |
//! | `Validation` | 400 | `validation` |
//! | `SubscriptionNotFound` | 404 | `subscription_not_found` |
//! | `NotAuthorized` | 403 | `not_authorized` |
//! | `Infrastructure` | 500 | `internal_server_error` |

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use hort_app::use_cases::subscription_use_case::SubscriptionError;

use crate::dto::DtoMapError;

/// Wrapper for [`SubscriptionError`] implementing
/// [`axum::response::IntoResponse`] — let the handler return
/// `Result<_, SubscriptionHandlerError>` and `?` does the mapping.
pub struct SubscriptionHandlerError(pub SubscriptionError);

impl From<SubscriptionError> for SubscriptionHandlerError {
    fn from(e: SubscriptionError) -> Self {
        Self(e)
    }
}

impl IntoResponse for SubscriptionHandlerError {
    fn into_response(self) -> Response {
        let (status, body) = match self.0 {
            SubscriptionError::UnsupportedEventType(kind) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "unsupported_event_type",
                    "kind": format!("{kind:?}"),
                }),
            ),
            SubscriptionError::RepoNotAuthorised { unauthorized } => (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "repo_not_authorised",
                    "unauthorized": unauthorized,
                }),
            ),
            SubscriptionError::AdminScopeRequiresAdmin => (
                StatusCode::FORBIDDEN,
                json!({"error": "admin_scope_requires_admin"}),
            ),
            SubscriptionError::AdminScopeRequiresUncappedToken => (
                StatusCode::FORBIDDEN,
                json!({"error": "admin_scope_requires_uncapped_token"}),
            ),
            SubscriptionError::RepoScopeMustBeExplicit { cap_ids } => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "repo_scope_must_be_explicit",
                    "cap_ids": cap_ids,
                }),
            ),
            SubscriptionError::RepoScopeExceedsTokenCap { offending } => (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "repo_scope_exceeds_token_cap",
                    "offending": offending,
                }),
            ),
            SubscriptionError::PlaintextWebhookDisallowed => (
                StatusCode::BAD_REQUEST,
                json!({"error": "plaintext_webhook_disallowed"}),
            ),
            SubscriptionError::WebhookTargetNotRoutable { ssrf_block_reason } => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "webhook_target_not_routable",
                    "reason": format!("{ssrf_block_reason:?}"),
                }),
            ),
            SubscriptionError::InvalidNatsSubject => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_nats_subject"}),
            ),
            SubscriptionError::DuplicateName => {
                (StatusCode::CONFLICT, json!({"error": "duplicate_name"}))
            }
            SubscriptionError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "validation",
                    "message": msg,
                }),
            ),
            SubscriptionError::SubscriptionNotFound => (
                StatusCode::NOT_FOUND,
                json!({"error": "subscription_not_found"}),
            ),
            SubscriptionError::NotAuthorized => {
                (StatusCode::FORBIDDEN, json!({"error": "not_authorized"}))
            }
            SubscriptionError::Infrastructure(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "internal_server_error"}),
            ),
        };
        (status, Json(body)).into_response()
    }
}

/// Maps a [`DtoMapError`] to a 400 response. These errors fire BEFORE
/// the use case is called, so they uniformly shape to `400 Bad Request`.
pub struct DtoHandlerError(pub DtoMapError);

impl From<DtoMapError> for DtoHandlerError {
    fn from(e: DtoMapError) -> Self {
        Self(e)
    }
}

impl IntoResponse for DtoHandlerError {
    fn into_response(self) -> Response {
        let body = match &self.0 {
            DtoMapError::UnknownStreamCategory(c) => json!({
                "error": "unknown_stream_category",
                "category": c,
            }),
            DtoMapError::UnknownEventTypeKind(k) => json!({
                "error": "unknown_event_type_kind",
                "kind": k,
            }),
            DtoMapError::UnsupportedNamedPredicate(names) => json!({
                "error": "unsupported_named_predicate",
                "names": names,
            }),
            DtoMapError::InvalidWebhookUrl(reason) => json!({
                "error": "invalid_webhook_url",
                "reason": reason,
            }),
            DtoMapError::InvalidWebhookSecretRef(reason) => json!({
                "error": "invalid_webhook_secret_ref",
                "reason": reason,
            }),
        };
        // Every `DtoMapError` fires BEFORE the use case and is a
        // client-input fault — uniformly `400`.
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}
