use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use hort_app::error::AppError;
use hort_domain::error::DomainError;

/// Newtype wrapper around [`AppError`] that implements [`IntoResponse`].
///
/// Handlers return `Result<T, ApiError>` and `?` works naturally via
/// `From<AppError>`.
pub struct ApiError(pub AppError);

impl From<AppError> for ApiError {
    fn from(err: AppError) -> Self {
        Self(err)
    }
}

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        Self(AppError::Domain(err))
    }
}

/// Opaque wire body used for `AppError::External` and `AppError::Scanner`.
///
/// Exposing the inner error string (e.g. `"Connection refused:
/// postgres://user:pass@internal.host/db"` or a scanner's panic with
/// internal paths) leaks infrastructure details. The raw error stays in
/// the `error = %err` tracing attribute so operators can still debug via
/// logs.
const UPSTREAM_UNAVAILABLE_BODY: &str = r#"{"error":"upstream unavailable"}"#;

/// The internal cause that must be logged before an [`ApiError`] is
/// sanitised to an opaque `5xx` wire body.
///
/// Several arms of [`ApiError::into_response`] deliberately collapse to a
/// generic `{"error":"internal error"}` body so no infrastructure detail
/// (sqlx paths, pool state, crate names) reaches the client. Without a log
/// at that boundary the *real* error is discarded entirely — e.g. the
/// `DomainError::Invariant("jobs row decode failed: …")` the jobs row
/// mapper raises on a column/type mismatch becomes a 500 with **no log
/// line at any level**, which is exactly how the admin-task read path's
/// 500 became undebuggable in production. This function names precisely
/// the sanitised-away arms; `into_response` logs the returned detail at
/// `error!` so the cause survives in the logs while the wire body stays
/// opaque.
///
/// Returns `None` for:
/// - client-facing errors whose wire message already carries the cause; and
/// - `External` / `Scanner`, which the dedicated sanitiser branch at the
///   top of `into_response` already logs (returning `Some` here would
///   double-log them).
fn opaque_5xx_log_detail(err: &AppError) -> Option<String> {
    match err {
        AppError::Domain(DomainError::Invariant(_))
        | AppError::Repository(_)
        | AppError::Storage(_)
        | AppError::EventStore(_) => Some(err.to_string()),
        _ => None,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // `ManagedByConfiguration` produces an
        // RFC 9457 `application/problem+json` body so operators (and
        // automation) can route on the `managedBy` member without
        // string-matching the error message. Early-return so the new
        // content-type doesn't fall through to the generic
        // `serde_json::json!({"error": ...})` tail at the bottom.
        // Single inline arm rather than a `Problem` builder — there's
        // exactly one consumer in the workspace; refactoring on the
        // first additional caller is YAGNI-correct.
        if let AppError::Domain(DomainError::ManagedByConfiguration { kind, name }) = &self.0 {
            let body = serde_json::json!({
                "type": "about:blank",
                "title": "Managed by configuration",
                "status": 409,
                "detail": format!(
                    "{kind} '{name}' is declared in configuration. Modify the \
                     configuration source and restart to apply."
                ),
                "managedBy": "gitops",
            });
            return (
                StatusCode::CONFLICT,
                [(axum::http::header::CONTENT_TYPE, "application/problem+json")],
                body.to_string(),
            )
                .into_response();
        }

        // Typed storage-backstop trip (ADR 0026) emits a structured
        // 502 with `bytes_read` + `cap`, NOT folded into the generic
        // `UPSTREAM_UNAVAILABLE_BODY` sanitisation below. The operator
        // sees the honest classification and the exact numbers they
        // need to size the env knob — folding it into "upstream
        // unavailable" misdirects debugging into a network-layer dead
        // end. Early-return so the new content-type and fields don't
        // fall through to the generic `{"error": message}` tail.
        if let AppError::Domain(DomainError::UpstreamBodyTooLarge {
            fetch_class,
            bytes_read,
            cap,
        }) = &self.0
        {
            let body = serde_json::json!({
                "error": format!("upstream {fetch_class} too large"),
                "fetch_class": fetch_class.to_string(),
                "bytes_read": bytes_read,
                "cap": cap,
            });
            return (
                StatusCode::BAD_GATEWAY,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body.to_string(),
            )
                .into_response();
        }

        // `External` and `Scanner` are sanitised at the wire boundary:
        // the opaque body goes to the client; the raw error goes to
        // tracing so operators don't lose signal.
        if let AppError::External(_) | AppError::Scanner(_) = &self.0 {
            tracing::error!(
                error = %self.0,
                "upstream error sanitised on wire"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                UPSTREAM_UNAVAILABLE_BODY,
            )
                .into_response();
        }

        let (status, message) = match &self.0 {
            AppError::Domain(domain_err) => match domain_err {
                DomainError::NotFound { .. } => (StatusCode::NOT_FOUND, domain_err.to_string()),
                DomainError::Conflict(_) => (StatusCode::CONFLICT, domain_err.to_string()),
                DomainError::Validation(_) => (StatusCode::BAD_REQUEST, domain_err.to_string()),
                DomainError::Forbidden(_) => (StatusCode::FORBIDDEN, domain_err.to_string()),
                DomainError::Invariant(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                ),
                // ADR 0025 — caller-reachable state-machine precondition
                // (e.g. release a rejected artifact, promote a quarantined
                // one). The request was understood and deliberately refused
                // for the resource's state → 409 Conflict with the real
                // message, never an opaque 500. Distinct from `Conflict`,
                // which stays reserved for event-store optimistic-
                // concurrency version conflicts.
                DomainError::InvalidState(_) => (StatusCode::CONFLICT, domain_err.to_string()),
                // Caught by the early-return arm at the top of this
                // function. Match arm exists so the inner match stays
                // exhaustive — fail loudly if someone removes the
                // early return without updating both sites.
                DomainError::ManagedByConfiguration { .. } => {
                    debug_assert!(
                        false,
                        "ManagedByConfiguration must be caught by the problem+json early-return"
                    );
                    (StatusCode::CONFLICT, domain_err.to_string())
                }
                // Default mapping for the pre-storage curation gate's
                // `Block` outcome. Hits client-upload paths (twine,
                // npm publish, cargo publish, OCI manifest PUT).
                // Per-format pull-through fetch handlers (currently
                // OCI manifest GET / blob GET) intercept this variant
                // ahead of the default mapping and return 404 Not
                // Found so the client sees the same envelope as a
                // genuine upstream miss — a 403 would confirm to an
                // unauthenticated prober that a blocked package
                // exists. The operator-facing message names the rule.
                DomainError::CurationBlocked { .. } => {
                    (StatusCode::FORBIDDEN, domain_err.to_string())
                }
                // Caught by the structured-body early-return at the
                // top of this function. Match arm exists so the inner
                // match stays exhaustive — fail loudly if a future
                // edit removes the early return without updating both
                // sites. Mirrors `ManagedByConfiguration`'s pattern.
                DomainError::UpstreamBodyTooLarge { .. } => {
                    debug_assert!(
                        false,
                        "UpstreamBodyTooLarge must be caught by the structured-body \
                         early-return (ADR 0026)"
                    );
                    (StatusCode::BAD_GATEWAY, domain_err.to_string())
                }
            },
            AppError::Repository(_) | AppError::Storage(_) | AppError::EventStore(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
            AppError::External(_) | AppError::Scanner(_) => {
                // The early-return sanitiser above always short-circuits
                // these. If we ever reach here the author added a new
                // variant without updating the sanitiser check — fail
                // loudly in debug, fall through to a safe opaque body
                // in release.
                debug_assert!(
                    false,
                    "External/Scanner should be handled by the sanitiser branch"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
            // OIDC validation failures surface to
            // the caller as 401. The auth middleware handles the happy path
            // — it produces its own 401 with a RFC 6750-compliant
            // WWW-Authenticate challenge, so this arm is only hit if a
            // handler propagates an IdP error via `?`, which shouldn't
            // happen in the current flow but is kept for completeness and
            // exhaustiveness.
            AppError::OidcValidation(_) => (StatusCode::UNAUTHORIZED, "invalid token".to_string()),
            // Chunked-upload validation variants.
            // Format-specific HTTP adapters (OCI, and later Maven / LFS)
            // intercept these and emit their own envelope shapes (the
            // OCI one, for instance, maps `RangeInvalid` to 416 with a
            // `Range: 0-<current-1>` header). This arm is the generic
            // fallback for callers that propagate an `AppError` directly
            // without translating to a format envelope — handy for
            // uniformly-styled non-OCI callers (future LFS / Maven) and
            // for tests that exercise `ApiError::into_response` with
            // these variants.
            AppError::RangeInvalid { .. } => {
                (StatusCode::RANGE_NOT_SATISFIABLE, self.0.to_string())
            }
            AppError::BodyLengthMismatch => (StatusCode::BAD_REQUEST, self.0.to_string()),
            AppError::SizeExceeded => (StatusCode::PAYLOAD_TOO_LARGE, self.0.to_string()),
            // Gitops apply aborted because of
            // an optimistic-concurrency stream conflict. Surfaces from
            // the gitops boot path; an HTTP caller that propagates this
            // (none in v1, but kept for exhaustiveness) sees 409 with
            // the upstream message.
            AppError::ConcurrentModification(_) => (StatusCode::CONFLICT, self.0.to_string()),
            // The native-API-token path collapses
            // all PAT-validation failures (PrefixNotFound, HashMismatch,
            // Expired, Revoked, UserDeactivated, RateLimited) to a
            // single opaque 401 so the caller cannot pivot on which
            // typed variant fired. The internal `String` payload is
            // operator-only context surfaced via tracing; the wire body
            // is the same `invalid or expired token` envelope the OIDC
            // path uses on a bearer-validation failure.
            AppError::Unauthorized(_) => (
                StatusCode::UNAUTHORIZED,
                "invalid or expired token".to_string(),
            ),
        };

        // Preserve the cause of any sanitised 5xx in the logs. The wire
        // body for these arms is the opaque `internal error` (no infra
        // leak), so without this line the real error vanishes — a 500
        // with nothing to debug. The body is unchanged; only the log
        // gains the detail.
        if let Some(detail) = opaque_5xx_log_detail(&self.0) {
            tracing::error!(error = %detail, status = status.as_u16(), "request sanitised to opaque 5xx");
        }

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

/// Substrings that must never appear in a 5xx response body.
///
/// Each entry is evidence of an internal leak:
/// - `/` — absolute filesystem paths, URL paths with backend routes
/// - `sqlx::` — fully-qualified sqlx crate path
/// - `hort_` — any workspace crate path (`hort_app::`, `hort_domain::`, …)
/// - `Pool` — sqlx pool-exhaustion messages
/// - `postgres://` — raw connection string fragments
#[cfg(any(test, feature = "test-support"))]
const LEAKAGE_MARKERS: &[&str] = &["/", "sqlx::", "hort_", "Pool", "postgres://"];

/// Assert that a response body does not leak internal details.
///
/// For `5xx` responses, panics if the body contains any of the substrings in
/// [`LEAKAGE_MARKERS`]. Non-5xx responses pass through untouched — the helper
/// is tolerant of paths, crate names, etc. in 2xx / 4xx payloads (JSON
/// routes, validation error messages, etc.).
///
/// Test-only — gated behind `#[cfg(test)]` (in-crate) or the
/// `test-support` feature (downstream). Per-format HTTP crates can reach
/// the helper from their test modules by depending on this crate with
/// `features = ["test-support"]` under `dev-dependencies`.
#[cfg(any(test, feature = "test-support"))]
pub fn assert_no_internal_leakage(status: StatusCode, body: &[u8]) {
    if !status.is_server_error() {
        return;
    }
    // Treat the body as best-effort UTF-8. A non-UTF-8 body cannot contain
    // any of the ASCII leakage markers, so lossy decoding is sufficient.
    let body_str = String::from_utf8_lossy(body);
    for marker in LEAKAGE_MARKERS {
        assert!(
            !body_str.contains(marker),
            "5xx response body leaks internal detail {marker:?}: {body_str:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn status_of(err: AppError) -> StatusCode {
        let response = ApiError(err).into_response();
        response.status()
    }

    /// Drive an `ApiError` through `IntoResponse` and pull the body bytes
    /// out. Small local helper; keeps every wire-shape test terse.
    fn response_of(err: AppError) -> (StatusCode, Vec<u8>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let resp = ApiError(err).into_response();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        })
    }

    #[test]
    fn not_found_is_404() {
        let err = AppError::Domain(DomainError::NotFound {
            entity: "Artifact",
            id: "abc".into(),
        });
        assert_eq!(status_of(err), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_is_409() {
        let err = AppError::Domain(DomainError::Conflict("duplicate key".into()));
        assert_eq!(status_of(err), StatusCode::CONFLICT);
    }

    #[test]
    fn validation_is_400() {
        let err = AppError::Domain(DomainError::Validation("bad input".into()));
        assert_eq!(status_of(err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn forbidden_is_403() {
        let err = AppError::Domain(DomainError::Forbidden("denied".into()));
        assert_eq!(status_of(err), StatusCode::FORBIDDEN);
    }

    #[test]
    fn curation_blocked_default_is_403() {
        // The default mapping for
        // `DomainError::CurationBlocked`. Per-format pull-through
        // fetch handlers override this to 404 at the handler level;
        // client-upload paths and any caller that propagates the
        // error directly land here.
        let err = AppError::Domain(DomainError::CurationBlocked {
            rule_name: "block-event-stream".into(),
            rule_id: uuid::Uuid::nil(),
            reason: "compromised maintainer".into(),
        });
        let (status, body) = response_of(err);
        assert_eq!(status, StatusCode::FORBIDDEN);
        let body_str = String::from_utf8(body).unwrap();
        // Body carries the rule name + reason via the Display impl.
        assert!(body_str.contains("block-event-stream"));
        assert!(body_str.contains("compromised maintainer"));
    }

    #[test]
    fn invariant_is_500() {
        let err = AppError::Domain(DomainError::Invariant("broken".into()));
        assert_eq!(status_of(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn invalid_state_is_409() {
        // ADR 0025 — a caller-reachable state precondition (e.g. releasing a
        // rejected artifact) is a 409 Conflict carrying the real message,
        // NOT an opaque 500. Conflict/409 still also covers event-store OCC.
        let err = AppError::Domain(DomainError::InvalidState(
            "cannot release artifact in state rejected".into(),
        ));
        assert_eq!(status_of(err), StatusCode::CONFLICT);
    }

    #[test]
    fn repository_error_is_500() {
        let err = AppError::Repository("db down".into());
        assert_eq!(status_of(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn storage_error_is_500() {
        let err = AppError::Storage("disk full".into());
        assert_eq!(status_of(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn scanner_error_is_500() {
        let err = AppError::Scanner("timeout".into());
        assert_eq!(status_of(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn external_error_is_500() {
        let err = AppError::External("upstream down".into());
        assert_eq!(status_of(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn event_store_error_is_500() {
        let err = AppError::EventStore("append failed".into());
        assert_eq!(status_of(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn from_app_error() {
        let app_err = AppError::Domain(DomainError::NotFound {
            entity: "User",
            id: "123".into(),
        });
        let api_err: ApiError = app_err.into();
        let response = api_err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -- External / Scanner sanitisation -------------

    #[test]
    fn external_error_body_is_opaque_upstream_unavailable() {
        // An External error carrying internal infrastructure detail must
        // NOT surface on the wire; the body is a fixed sanitised string.
        let (status, body) = response_of(AppError::External(
            "Connection refused: postgres://user:pass@internal.host/db".into(),
        ));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let body_str = String::from_utf8(body).unwrap();
        assert_eq!(body_str, r#"{"error":"upstream unavailable"}"#);
        assert!(!body_str.contains("postgres://"));
        assert!(!body_str.contains("internal.host"));
    }

    #[test]
    fn scanner_error_body_is_opaque_upstream_unavailable() {
        let (status, body) = response_of(AppError::Scanner(
            "scanner panic at /usr/local/lib/hort_formats/pypi.wasm".into(),
        ));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let body_str = String::from_utf8(body).unwrap();
        assert_eq!(body_str, r#"{"error":"upstream unavailable"}"#);
        assert!(!body_str.contains("hort_formats"));
        assert!(!body_str.contains("/usr/local"));
    }

    #[test]
    fn other_500s_still_return_internal_error_body() {
        // Repository, Storage, EventStore errors keep the generic
        // `"internal error"` body (no infrastructure detail in the
        // variant payload by design; the sanitiser only applies to
        // External + Scanner).
        let (_, body) = response_of(AppError::Repository("pg down".into()));
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains(r#""error":"internal error""#));
    }

    #[test]
    fn opaque_5xx_arms_preserve_cause_for_logging() {
        // Regression: the jobs-read 500 root cause. A
        // `DomainError::Invariant("jobs row decode failed: …")` raised by
        // the jobs row mapper is sanitised to an opaque `internal error`
        // wire body — correct for the client, but the cause was ALSO
        // discarded from the logs (no log line at any level), leaving an
        // undebuggable 500. The detail must survive for the `error!` line.
        let detail = opaque_5xx_log_detail(&AppError::Domain(DomainError::Invariant(
            "jobs row decode failed: column \"actor_id\": mismatched types".into(),
        )))
        .expect("Invariant must be logged before sanitisation");
        assert!(detail.contains("jobs row decode failed"));
        assert!(detail.contains("actor_id"));

        // Repository / Storage / EventStore opaque-500s are likewise rescued.
        assert!(opaque_5xx_log_detail(&AppError::Repository("pg down".into())).is_some());
        assert!(opaque_5xx_log_detail(&AppError::Storage("bucket gone".into())).is_some());
        assert!(opaque_5xx_log_detail(&AppError::EventStore("append failed".into())).is_some());

        // External / Scanner are already logged by the dedicated wire
        // sanitiser branch at the top of `into_response` — `None` here so
        // they are not double-logged.
        assert!(opaque_5xx_log_detail(&AppError::External("upstream down".into())).is_none());
        assert!(opaque_5xx_log_detail(&AppError::Scanner("timeout".into())).is_none());

        // Client-facing errors carry their real message on the wire, so
        // there is nothing to rescue and no log entry is warranted.
        assert!(
            opaque_5xx_log_detail(&AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                id: "x".into(),
            }))
            .is_none()
        );
        assert!(
            opaque_5xx_log_detail(&AppError::Domain(DomainError::Validation("bad".into())))
                .is_none()
        );
    }

    // -- assert_no_internal_leakage helper ------------------------------

    #[test]
    fn leakage_helper_accepts_clean_5xx_body() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":"upstream unavailable"}"#,
        );
    }

    #[test]
    fn leakage_helper_accepts_clean_internal_error_body() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":"internal error"}"#,
        );
    }

    #[test]
    #[should_panic(expected = "leaks internal detail")]
    fn leakage_helper_rejects_sqlx_path_on_5xx() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"sqlx::Error connection refused",
        );
    }

    #[test]
    #[should_panic(expected = "leaks internal detail")]
    fn leakage_helper_rejects_absolute_path_on_5xx() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"scanner panic at /usr/local/lib/plugin.wasm",
        );
    }

    #[test]
    #[should_panic(expected = "leaks internal detail")]
    fn leakage_helper_rejects_hort_crate_path_on_5xx() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"error: hort_adapters_postgres::UserRepository failed",
        );
    }

    #[test]
    #[should_panic(expected = "leaks internal detail")]
    fn leakage_helper_rejects_pool_substring_on_5xx() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"PoolTimedOut: failed to acquire connection",
        );
    }

    #[test]
    #[should_panic(expected = "leaks internal detail")]
    fn leakage_helper_rejects_postgres_url_on_5xx() {
        assert_no_internal_leakage(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"postgres://user:pass@db/app",
        );
    }

    #[test]
    fn leakage_helper_tolerant_for_2xx() {
        // Non-5xx payloads may legitimately contain path characters
        // (JSON array syntax, URL paths in Link headers, etc.).
        assert_no_internal_leakage(
            StatusCode::OK,
            b"sqlx::Error /etc/passwd hort_app Pool postgres://",
        );
    }

    #[test]
    fn leakage_helper_tolerant_for_4xx() {
        assert_no_internal_leakage(
            StatusCode::BAD_REQUEST,
            br#"{"error":"path /foo/bar invalid"}"#,
        );
    }

    #[test]
    fn leakage_helper_accepts_5xx_body_without_markers() {
        assert_no_internal_leakage(
            StatusCode::BAD_GATEWAY,
            br#"{"error":"bad gateway - timeout after 30s"}"#,
        );
    }

    // -- End-to-end: sanitised External response passes the helper ----

    #[test]
    fn sanitised_external_response_passes_leakage_helper() {
        let (status, body) = response_of(AppError::External(
            "sqlx::Error at postgres://host:5432/db via /var/lib/pg".into(),
        ));
        // Even though the raw error contained /, sqlx::, and postgres://,
        // the sanitised wire body is clean.
        assert_no_internal_leakage(status, &body);
    }

    #[test]
    fn sanitised_scanner_response_passes_leakage_helper() {
        let (status, body) = response_of(AppError::Scanner(
            "hort_formats::pypi plugin at /opt/hort/plugin.wasm panicked".into(),
        ));
        assert_no_internal_leakage(status, &body);
    }

    // -- ManagedByConfiguration → 409 problem+json -----------------

    fn managed_by_response() -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let resp = ApiError(AppError::Domain(DomainError::ManagedByConfiguration {
                kind: "repository",
                name: "npm-public".into(),
            }))
            .into_response();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        })
    }

    #[test]
    fn managed_by_configuration_is_409() {
        let (status, _, _) = managed_by_response();
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[test]
    fn managed_by_configuration_uses_problem_json_content_type() {
        // RFC 9457 specifies `application/problem+json` for the body.
        // Pin the exact string — automation route on it.
        let (_, headers, _) = managed_by_response();
        let ct = headers
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type header must be present");
        assert_eq!(ct.to_str().unwrap(), "application/problem+json");
    }

    #[test]
    fn managed_by_configuration_body_includes_kind_name_and_managed_by_member() {
        let (_, _, body) = managed_by_response();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Required problem+json members.
        assert_eq!(v["type"], "about:blank");
        assert_eq!(v["title"], "Managed by configuration");
        assert_eq!(v["status"], 409);
        // Custom `managedBy` member — operators can route on this
        // without parsing the human-readable detail.
        assert_eq!(v["managedBy"], "gitops");
        // Detail names both kind and name.
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.contains("repository"));
        assert!(detail.contains("npm-public"));
        assert!(
            detail.contains("restart"),
            "detail must point operators at the restart-to-apply contract"
        );
    }

    #[test]
    fn managed_by_configuration_does_not_use_generic_error_envelope() {
        // The early-return arm's body shape is RFC 9457 problem+json,
        // NOT the legacy `{"error": "..."}` envelope used by other
        // domain errors. Pin the absence so a future refactor that
        // collapses the early-return doesn't silently change the
        // shape.
        let (_, _, body) = managed_by_response();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v.get("error").is_none(),
            "problem+json body must not include the legacy `error` field"
        );
    }

    // -- UpstreamBodyTooLarge → 502 with structured body (ADR 0026)
    //
    // The operator sees the honest classification + the exact
    // `bytes_read` / `cap` they need to size the env knob. Never folded
    // into `UPSTREAM_UNAVAILABLE_BODY` — that was the misdirection bug.

    fn upstream_body_too_large_response(
        fetch_class: hort_domain::error::FetchClass,
        bytes_read: u64,
        cap: u64,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let resp = ApiError(AppError::Domain(DomainError::UpstreamBodyTooLarge {
                fetch_class,
                bytes_read,
                cap,
            }))
            .into_response();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        })
    }

    #[test]
    fn upstream_body_too_large_metadata_is_502_with_structured_body() {
        let (status, headers, body) =
            upstream_body_too_large_response(hort_domain::error::FetchClass::Metadata, 5000, 4096);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let ct = headers
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type must be present");
        assert_eq!(ct.to_str().unwrap(), "application/json");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "upstream metadata too large");
        assert_eq!(v["fetch_class"], "metadata");
        assert_eq!(v["bytes_read"], 5000);
        assert_eq!(v["cap"], 4096);
    }

    #[test]
    fn upstream_body_too_large_manifest_carries_manifest_label() {
        let (status, _, body) = upstream_body_too_large_response(
            hort_domain::error::FetchClass::Manifest,
            20_000_000,
            16_777_216,
        );
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "upstream manifest too large");
        assert_eq!(v["fetch_class"], "manifest");
        assert_eq!(v["bytes_read"], 20_000_000);
        assert_eq!(v["cap"], 16_777_216);
    }

    #[test]
    fn upstream_body_too_large_does_not_use_upstream_unavailable_envelope() {
        // The D2 fix: the structured-body early-return MUST short-circuit
        // before the `External` / `Scanner` sanitiser path. Pin the
        // absence so a future refactor that re-orders the early-returns
        // doesn't silently swallow the typed variant.
        let (_, _, body) =
            upstream_body_too_large_response(hort_domain::error::FetchClass::Metadata, 1, 1);
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            !body_str.contains("upstream unavailable"),
            "body must NOT contain the generic 'upstream unavailable' sanitisation \
             that the old buffer cap used to fold into; got: {body_str}"
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // bytes_read + cap fields are operator-actionable; the legacy
        // envelope has neither.
        assert!(v.get("bytes_read").is_some());
        assert!(v.get("cap").is_some());
    }
}
