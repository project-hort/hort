use hort_domain::error::DomainError;
use hort_domain::ports::identity_provider::OidcValidationError;

/// Application-layer errors.
///
/// Wraps domain errors and adds infrastructure failure categories.
/// The inbound-HTTP adapter (`hort-http-core::error::ApiError`) maps these
/// to HTTP status codes.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Domain(#[from] DomainError),

    #[error("repository: {0}")]
    Repository(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("scanner: {0}")]
    Scanner(String),

    #[error("external: {0}")]
    External(String),

    #[error("event store: {0}")]
    EventStore(String),

    /// Structured identity-provider validation
    /// failure. Carries the typed [`OidcValidationError`] so the auth
    /// middleware's `hort_auth_attempts_total{result}` classifier can
    /// pattern-match the variant instead of substring-matching a message.
    #[error("oidc validation: {0}")]
    OidcValidation(#[from] OidcValidationError),

    /// OCI (and future Maven / LFS) chunked-upload
    /// `Content-Range` start did not match the session's current
    /// `bytes_received`. `current` carries the session's actual
    /// progress so the HTTP adapter can emit the spec-required
    /// `Range: 0-<current - 1>` header on the 416 response.
    ///
    /// Lives on `AppError` rather than format-local types because the
    /// same validation shape recurs across every chunked-upload format
    /// (OCI PATCH, Maven chunked PUT, Git LFS batch transfer).
    /// Representing it as a typed variant lets each HTTP adapter carry
    /// `current` through without string-parsing a `Validation(..)`
    /// payload.
    #[error("range invalid: client start did not match session bytes_received={current}")]
    RangeInvalid { current: u64 },

    /// `Content-Range` span width disagreed with
    /// the actual body byte count. Spec-mapped to 400
    /// `BLOB_UPLOAD_INVALID`; no per-session payload needed (the client
    /// sent an inconsistent header + body, the session state is
    /// irrelevant to the mapping).
    #[error("body length mismatch with declared Content-Range")]
    BodyLengthMismatch,

    /// Projected total after this chunk would
    /// exceed the configured max-blob-bytes cap. Spec-mapped to 413
    /// `SIZE_INVALID` (§2.8 — NOT 400; 413 is the spec-conformant
    /// status for "this chunk pushes the session past the cap").
    #[error("size exceeded: chunk would push session past max-blob-bytes cap")]
    SizeExceeded,

    /// Gitops apply pipeline aborted because
    /// `PolicyUseCase` returned a [`DomainError::Conflict`] from a
    /// stale [`ExpectedVersion::Exact`](hort_domain::ports::event_store::ExpectedVersion::Exact)
    /// append. The carried message is the upstream conflict text.
    ///
    /// With gitops as the sole writer of policy events, the realistic
    /// paths to this variant are a multi-replica boot race (two
    /// replicas read the same projection version, both append, the
    /// second loses) and a stale in-memory projection cache. Operator
    /// recovery is "restart" — the second boot reads the now-current
    /// projection version and re-diffs.
    #[error("concurrent modification: {0}")]
    ConcurrentModification(String),

    /// Generic credential-rejection envelope.
    ///
    /// Carries the same opaque "unauthorized" semantic the auth
    /// middleware emits for OIDC failures, but is produced by the
    /// native-API-token path so the validator's typed
    /// `PatValidationError` variants (`PrefixNotFound`, `HashMismatch`,
    /// `Expired`, `Revoked`, `UserDeactivated`) collapse to a single
    /// 401 wire shape — caller cannot distinguish them. The variant's
    /// `String` payload is operator-only context (carried into traces
    /// and audit, never the response body); the wire body is the
    /// same `invalid or expired token` envelope the OIDC path uses
    /// (see `hort_http_core::error::ApiError::into_response`).
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

/// Convenience alias used throughout the application layer.
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_error_converts_to_app_error() {
        let domain_err = DomainError::NotFound {
            entity: "Repository",
            id: "abc".into(),
        };
        let app_err: AppError = domain_err.into();
        assert!(matches!(app_err, AppError::Domain(_)));
        assert!(app_err.to_string().contains("not found"));
    }

    #[test]
    fn repository_error_display() {
        let err = AppError::Repository("connection refused".into());
        assert_eq!(err.to_string(), "repository: connection refused");
    }

    #[test]
    fn storage_error_display() {
        let err = AppError::Storage("bucket not found".into());
        assert_eq!(err.to_string(), "storage: bucket not found");
    }

    #[test]
    fn scanner_error_display() {
        let err = AppError::Scanner("timeout".into());
        assert_eq!(err.to_string(), "scanner: timeout");
    }

    #[test]
    fn external_error_display() {
        let err = AppError::External("upstream unavailable".into());
        assert_eq!(err.to_string(), "external: upstream unavailable");
    }

    #[test]
    fn event_store_error_display() {
        let err = AppError::EventStore("append failed".into());
        assert_eq!(err.to_string(), "event store: append failed");
    }

    #[test]
    fn oidc_validation_error_converts_to_app_error() {
        let oidc_err = OidcValidationError::Expired;
        let app_err: AppError = oidc_err.into();
        assert!(matches!(
            app_err,
            AppError::OidcValidation(OidcValidationError::Expired)
        ));
    }

    #[test]
    fn oidc_validation_error_display_wraps_variant() {
        let err = AppError::OidcValidation(OidcValidationError::ClaimMissing("sub".into()));
        assert_eq!(err.to_string(), "oidc validation: missing claim: sub");
    }

    #[test]
    fn range_invalid_carries_current_bytes_received_in_display() {
        let err = AppError::RangeInvalid { current: 1024 };
        let rendered = err.to_string();
        // The HTTP adapter reads `current` off the variant directly, but
        // the display form is also part of the observable surface (logs,
        // traces) — pin a stable substring so a renaming of the field
        // does not silently break log greps.
        assert!(
            rendered.contains("1024"),
            "display missing current: {rendered}"
        );
    }

    #[test]
    fn body_length_mismatch_has_stable_display() {
        assert_eq!(
            AppError::BodyLengthMismatch.to_string(),
            "body length mismatch with declared Content-Range"
        );
    }

    #[test]
    fn size_exceeded_has_stable_display() {
        assert_eq!(
            AppError::SizeExceeded.to_string(),
            "size exceeded: chunk would push session past max-blob-bytes cap"
        );
    }

    #[test]
    fn concurrent_modification_carries_message_in_display() {
        let err = AppError::ConcurrentModification("expected_version=7".into());
        let rendered = err.to_string();
        assert!(rendered.contains("concurrent modification"));
        assert!(rendered.contains("expected_version=7"));
    }

    #[test]
    fn unauthorized_carries_message_in_display() {
        // The variant is the wrapper the PAT validator
        // path uses to collapse every typed `PatValidationError` arm
        // onto one opaque 401 envelope. The display form carries the
        // operator-only context so tracing / audit logs can pivot;
        // the wire body is the generic `invalid or expired token`
        // string the HTTP adapter substitutes (see
        // `hort_http_core::error::ApiError::into_response`).
        let err = AppError::Unauthorized("token revoked".into());
        let rendered = err.to_string();
        assert!(rendered.contains("unauthorized"));
        assert!(rendered.contains("token revoked"));
    }
}
