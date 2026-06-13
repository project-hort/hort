//! OCI Distribution error envelope.
//!
//! The spec uses a different error shape than hort-http-core's generic
//! `{"error":"..."}` — every error response is an `errors` array of
//! `{code, message, detail}` objects:
//!
//! ```json
//! {
//!   "errors": [
//!     { "code": "DENIED",
//!       "message": "requested access to the resource is denied",
//!       "detail": { "repository": "library/nginx", "actions": ["push"] } }
//!   ]
//! }
//! ```
//!
//! # Codes wired here
//!
//! `NAME_UNKNOWN`, `UNAUTHORIZED`, `DENIED`, `UNSUPPORTED`,
//! `BLOB_UNKNOWN`, `DIGEST_INVALID`, `MANIFEST_UNKNOWN`, plus two
//! spec-extension codes: `UNAVAILABLE` (quarantine hold, 503 +
//! `Retry-After`) and `INTERNAL` (500 fallback). Remaining codes
//! (`BLOB_UPLOAD_INVALID`, `SIZE_INVALID`, `TOOMANYREQUESTS`, …) land
//! as their emitters arrive.
//!
//! # Spec-extension codes
//!
//! `UNAVAILABLE` and `INTERNAL` are hort extensions — the
//! OCI Distribution v1.1 spec does not define codes for either
//! quarantine holds or unrecoverable server errors. `TOOMANYREQUESTS`
//! was rejected for quarantine because its §2.8 mapping is HTTP 429,
//! and Artifactory clients apply rate-limit-adaptive retry heuristics
//! on that code — which would misread a quarantine as rate pressure.
//! See `docs/architecture/explanation/scanning-pipeline.md` for the
//! quarantine-status HTTP mapping rationale (ADR 0007).
//!
//! # No log-on-response
//!
//! `IntoResponse` here does not emit tracing events. HTTP-level logging
//! is handled by the global `http_metrics_middleware` / request-level
//! span set up on the main router. Logging on every OCI error would
//! duplicate that signal.

use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// OCI error codes, per design §2.8. Only the four needed in this PR
/// are wired; additional variants are added as their emitting code
/// lands (Items 5+).
///
/// Each variant's carried data is what the spec's `detail` field
/// expects for that code:
///
/// - `NameUnknown { repository }` — the repo / image name the client
///   requested; surfaced in `detail.name`.
/// - `Unauthorized { message, detail }` — message carries operator-
///   supplied text; `detail` is free-form (e.g. realm / scope echo on
///   token challenges).
/// - `Denied { repository, actions }` — the repo being accessed and
///   the actions the caller requested but lacked RBAC grants for.
/// - `Unsupported { message }` — something the server cannot do
///   (e.g. a non-sha256 digest algorithm); no structured detail.
///
/// `Debug` is derived so test assertions can match on variants; the
/// data is non-sensitive (no tokens, no internal paths).
#[derive(Debug, Clone)]
pub enum OciError {
    /// 404 — the image name is not a known repository.
    NameUnknown { repository: String },
    /// 401 — the caller is unauthenticated (missing / invalid token).
    Unauthorized {
        message: String,
        detail: Option<serde_json::Value>,
    },
    /// 403 — the caller is authenticated but lacks the requested
    /// permission(s) on this repository.
    Denied {
        repository: String,
        actions: Vec<String>,
    },
    /// 400 — the server does not support the requested operation
    /// (e.g. non-sha256 digest algorithm).
    Unsupported { message: String },
    /// 404 — a blob with the given digest is not known in this
    /// repository. Item 6: `GET`/`HEAD /v2/<name>/blobs/<digest>` miss
    /// or cross-repo foreign-blob reject. `digest` is echoed in
    /// `detail.digest` so the client sees which blob the server looked
    /// for (OCI clients sometimes retry with a corrected digest on a
    /// race).
    BlobUnknown { digest: String },
    /// 404 — a manifest at the given reference is not known. Item 7:
    /// `GET`/`HEAD /v2/<name>/manifests/<ref>` miss (tag unknown, or
    /// digest-by-ref with no row at path). `reference` echoes the
    /// original client input (tag name or `sha256:<hex>`).
    ManifestUnknown { reference: String },
    /// 400 — malformed digest (wrong length, non-hex, missing
    /// algorithm prefix). Distinct from `Unsupported`, which rejects
    /// well-formed but unsupported algorithms (e.g. `sha512:<…>`):
    /// the spec assigns `UNSUPPORTED` for known-but-unsupported
    /// inputs and `DIGEST_INVALID` for the rest, and keeping the two
    /// variants separate lets the handler emit the right code without
    /// duplicating the message-vs-detail wire shape.
    DigestInvalid { message: String },
    /// 406 — the client's `Accept` header does not include the
    /// manifest's stored media-type and is not `*/*`. Item 7 content
    /// negotiation. Uses the spec's `MANIFEST_UNKNOWN` code with a 406
    /// status — the backlog pins this shape over 404 because some
    /// clients (notably tooling that hard-codes a single Accept) would
    /// loop on 404 but back off on 406. `detail.media_type` echoes the
    /// server's stored type so the client can retry with a compatible
    /// `Accept`.
    ManifestNotAcceptable { media_type: String },
    /// 503 — the artifact or manifest is in a time-bounded quarantine
    /// hold. Emits HTTP 503 + a `Retry-After` header whose value is
    /// `retry_after_seconds`. Code is `UNAVAILABLE` — a spec-extension
    /// with the closest upstream-compatible semantics; chosen over
    /// `TOOMANYREQUESTS` (which §2.8 maps to HTTP 429) to avoid
    /// overloading rate-limit-adaptive retry heuristics in strict
    /// clients like Artifactory. Documented in §2.8.
    Quarantined { retry_after_seconds: i64 },
    /// 500 — unrecoverable server error that doesn't map to any OCI
    /// standard code. Code is `INTERNAL`, an hort
    /// spec-extension. Body shape stays the OCI envelope for
    /// client-parser consistency; `detail` is always `null` — the
    /// message is a fixed "internal error" literal and no request-
    /// specific data leaks.
    Internal,
    /// 404 — three-phase blob upload session is not known (missing
    /// entirely, TTL-expired, or bound to a different repository —
    /// tenant-isolation mismatches MUST surface as `BLOB_UPLOAD_UNKNOWN`
    /// rather than `DENIED` to avoid leaking "a session for that UUID
    /// exists elsewhere" as an enumeration oracle). §2.8 + Item 2
    /// review finding tenant-isolation.
    BlobUploadUnknown { session_id: String },
    /// 400 — three-phase blob upload PATCH / PUT was rejected for a
    /// reason other than a name / digest / auth problem. Covers
    /// `Content-Range` parse errors, `Content-Length` parse errors,
    /// body-length-vs-content-range mismatch, optimistic-concurrency
    /// CAS miss, and (when accompanied by HTTP status 416) a
    /// `Content-Range` start that disagrees with the session's current
    /// `bytes_received`. The 416 form sets `Range: 0-<bytes_received-1>`
    /// via a dedicated response-helper path — the envelope field
    /// stays `BLOB_UPLOAD_INVALID` per §2.8 regardless of status.
    BlobUploadInvalid { message: String },
    /// 413 — incoming chunk would push the session past the configured
    /// max-blob-bytes cap. §2.8 pins 413 (not 400) so clients can
    /// distinguish size-cap rejection from generic upload-invalid
    /// responses. `message` carries operator-supplied copy.
    SizeInvalid { message: String },
    /// 416 — `Content-Range` start did not match the session's current
    /// `bytes_received`. The response MUST carry a `Range:
    /// 0-<current - 1>` header (or `bytes=0-0` when `current == 0`) so
    /// the client can resume. Envelope code stays `BLOB_UPLOAD_INVALID`
    /// per §2.8 — the status code, not the envelope, distinguishes
    /// range-mismatch from the generic 400 form.
    RangeNotSatisfiable { current: u64 },
    /// 400 — manifest is malformed (invalid JSON, missing required
    /// fields, media type not in the allowlist, declared digest /
    /// content mismatch on a digest-reference PUT). §2.8 pins
    /// `MANIFEST_INVALID` here — explicitly NOT `UNSUPPORTED` (which is
    /// reserved for well-formed-but-unsupported operations like
    /// `sha512:` digests). `detail` is variant-specific (operators
    /// include e.g. `{"media_type": "application/json"}` on a
    /// rejected content-type). `None` → `null` on the wire.
    ManifestInvalid { detail: Option<serde_json::Value> },
    /// 400 — the manifest references blobs that are not present in the
    /// target repository (or exist but live in a foreign repository).
    /// §2.14.3 intentionally commits the manifest artifact BEFORE this
    /// validation fires so the client's retry-after-mounting path is
    /// idempotent. The response body carries a `detail.blobs` array
    /// listing the missing digests so the client knows which ones to
    /// upload / cross-mount.
    ManifestBlobUnknown { blobs: Vec<String> },
    /// 502 — pull-through proxy could not retrieve the requested
    /// content from the configured upstream. Fires when:
    /// - The upstream returned a non-success status (and the local
    ///   cache held no usable copy).
    /// - The upstream-declared digest did not match the digest the
    ///   client asked for (security signal — `IngestUseCase::ingest`
    ///   already emitted `ChecksumMismatch`).
    /// - Streaming failed mid-flight after the upstream accepted the
    ///   request.
    ///
    /// The OCI spec has no dedicated `BAD_GATEWAY` envelope code, so
    /// the `code` field still uses one of the established codes
    /// (`MANIFEST_INVALID` for manifest paths) — only the HTTP
    /// status carries the gateway distinction. The `detail` field
    /// surfaces a human-readable reason for ops debugging.
    BadGateway { detail: Option<serde_json::Value> },
    /// 429 — request was rate-limited or rejected by a per-caller
    /// cap. The OCI three-phase blob upload `initiate` rejects new
    /// sessions when the per-`(repo, principal)` outstanding-session
    /// count would exceed the configured cap
    /// (`HORT_OCI_MAX_SESSIONS_PER_PRINCIPAL`).
    /// Carries `retry_after_seconds` for the `Retry-After` header
    /// (advisory; clients use it to back off). Spec code is
    /// `TOOMANYREQUESTS` per §2.8.
    TooManyRequests { retry_after_seconds: i64 },
    /// 400 — image name violates the OCI Distribution Spec name
    /// grammar `[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*`,
    /// the 256-byte cap, the 8-component cap, or carries control bytes
    /// (NUL, CR, LF, etc.). Emitted by every OCI handler immediately
    /// after route extraction + `parse_tail`, BEFORE any storage,
    /// manifest, or upload action.
    ///
    /// Spec code `NAME_INVALID` is defined by the OCI Distribution
    /// Spec error-codes table for malformed names. The 400 status
    /// distinguishes a syntactically-invalid name from `NAME_UNKNOWN`
    /// (404, "well-formed name that doesn't exist").
    ///
    /// `message` carries a deterministic `oci.name: <reason>` shape
    /// produced by [`crate::name::validate_oci_name`]. The message
    /// MUST NOT echo the offending input bytes — they may be
    /// attacker-controlled (CRLF, NUL, multi-MB control sequences)
    /// and surfacing them is a log-injection / response-reflection
    /// vector. The validator enforces this at its source.
    NameInvalid { message: String },
}

impl OciError {
    /// Machine-readable spec code. Uppercase; stable over time.
    fn code(&self) -> &'static str {
        match self {
            Self::NameUnknown { .. } => "NAME_UNKNOWN",
            Self::Unauthorized { .. } => "UNAUTHORIZED",
            Self::Denied { .. } => "DENIED",
            Self::Unsupported { .. } => "UNSUPPORTED",
            Self::BlobUnknown { .. } => "BLOB_UNKNOWN",
            Self::ManifestUnknown { .. } => "MANIFEST_UNKNOWN",
            Self::DigestInvalid { .. } => "DIGEST_INVALID",
            Self::ManifestNotAcceptable { .. } => "MANIFEST_UNKNOWN",
            Self::Quarantined { .. } => "UNAVAILABLE",
            Self::Internal => "INTERNAL",
            Self::BlobUploadUnknown { .. } => "BLOB_UPLOAD_UNKNOWN",
            Self::BlobUploadInvalid { .. } => "BLOB_UPLOAD_INVALID",
            Self::SizeInvalid { .. } => "SIZE_INVALID",
            // §2.8 maps 416 onto the `BLOB_UPLOAD_INVALID` envelope
            // code — the HTTP status distinguishes the range-mismatch
            // sub-case from the generic 400 form.
            Self::RangeNotSatisfiable { .. } => "BLOB_UPLOAD_INVALID",
            Self::ManifestInvalid { .. } => "MANIFEST_INVALID",
            Self::ManifestBlobUnknown { .. } => "MANIFEST_BLOB_UNKNOWN",
            // No spec-mandated code; reuse `MANIFEST_INVALID` because
            // the manifest pull-through path is the most common
            // emitter and the BAD_GATEWAY HTTP status disambiguates.
            Self::BadGateway { .. } => "MANIFEST_INVALID",
            Self::TooManyRequests { .. } => "TOOMANYREQUESTS",
            Self::NameInvalid { .. } => "NAME_INVALID",
        }
    }

    /// HTTP status per the §2.8 mapping table.
    fn status(&self) -> StatusCode {
        match self {
            Self::NameUnknown { .. } => StatusCode::NOT_FOUND,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Denied { .. } => StatusCode::FORBIDDEN,
            Self::Unsupported { .. } => StatusCode::BAD_REQUEST,
            Self::BlobUnknown { .. } => StatusCode::NOT_FOUND,
            Self::ManifestUnknown { .. } => StatusCode::NOT_FOUND,
            Self::DigestInvalid { .. } => StatusCode::BAD_REQUEST,
            Self::ManifestNotAcceptable { .. } => StatusCode::NOT_ACCEPTABLE,
            Self::Quarantined { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BlobUploadUnknown { .. } => StatusCode::NOT_FOUND,
            Self::BlobUploadInvalid { .. } => StatusCode::BAD_REQUEST,
            Self::SizeInvalid { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RangeNotSatisfiable { .. } => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::ManifestInvalid { .. } => StatusCode::BAD_REQUEST,
            Self::ManifestBlobUnknown { .. } => StatusCode::BAD_REQUEST,
            Self::BadGateway { .. } => StatusCode::BAD_GATEWAY,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::NameInvalid { .. } => StatusCode::BAD_REQUEST,
        }
    }

    /// Human-readable message. The spec copy is canonical for the
    /// well-known codes; custom variants (`Unauthorized`,
    /// `Unsupported`, `DigestInvalid`) carry operator-supplied text so
    /// future handlers can be specific about WHY a request failed.
    fn message(&self) -> String {
        match self {
            Self::NameUnknown { .. } => "repository name not known to registry".to_string(),
            Self::Unauthorized { message, .. } => message.clone(),
            Self::Denied { .. } => "requested access to the resource is denied".to_string(),
            Self::Unsupported { message } => message.clone(),
            Self::BlobUnknown { .. } => "blob unknown to registry".to_string(),
            Self::ManifestUnknown { .. } => "manifest unknown to registry".to_string(),
            Self::DigestInvalid { message } => message.clone(),
            Self::ManifestNotAcceptable { .. } => "manifest media type not acceptable".to_string(),
            Self::Quarantined { .. } => "artifact is quarantined".to_string(),
            Self::Internal => "internal error".to_string(),
            Self::BlobUploadUnknown { .. } => "blob upload session unknown".to_string(),
            Self::BlobUploadInvalid { message } => message.clone(),
            Self::SizeInvalid { message } => message.clone(),
            Self::RangeNotSatisfiable { .. } => {
                "requested range does not match session state".to_string()
            }
            Self::ManifestInvalid { .. } => "manifest invalid".to_string(),
            Self::ManifestBlobUnknown { .. } => "manifest references unknown blobs".to_string(),
            Self::BadGateway { .. } => "upstream proxy fetch failed".to_string(),
            Self::TooManyRequests { .. } => "too many requests".to_string(),
            Self::NameInvalid { message } => message.clone(),
        }
    }

    /// Per-variant `detail` payload. `None` → the wire field is
    /// serialised as `null` (which matches the spec's "optional" and
    /// every reference registry's behaviour; omitting the key is also
    /// valid but clients are more consistent about accepting `null`).
    fn detail(&self) -> Option<serde_json::Value> {
        match self {
            Self::NameUnknown { repository } => Some(serde_json::json!({ "name": repository })),
            Self::BlobUnknown { digest } => Some(serde_json::json!({ "digest": digest })),
            Self::ManifestUnknown { reference } => {
                Some(serde_json::json!({ "reference": reference }))
            }
            Self::DigestInvalid { .. } => None,
            Self::ManifestNotAcceptable { media_type } => {
                Some(serde_json::json!({ "media_type": media_type }))
            }
            Self::Unauthorized { detail, .. } => detail.clone(),
            Self::Denied {
                repository,
                actions,
            } => Some(serde_json::json!({
                "repository": repository,
                "actions": actions,
            })),
            Self::Unsupported { .. } => None,
            Self::Quarantined {
                retry_after_seconds,
            } => Some(serde_json::json!({
                "retry_after_seconds": retry_after_seconds,
            })),
            Self::Internal => None,
            Self::BlobUploadUnknown { session_id } => {
                Some(serde_json::json!({ "session_id": session_id }))
            }
            Self::BlobUploadInvalid { .. } => None,
            Self::SizeInvalid { .. } => None,
            Self::RangeNotSatisfiable { current } => {
                Some(serde_json::json!({ "bytes_received": current }))
            }
            Self::ManifestInvalid { detail } => detail.clone(),
            Self::ManifestBlobUnknown { blobs } => Some(serde_json::json!({ "blobs": blobs })),
            Self::BadGateway { detail } => detail.clone(),
            Self::TooManyRequests {
                retry_after_seconds,
            } => Some(serde_json::json!({
                "retry_after_seconds": retry_after_seconds,
            })),
            // `NameInvalid::detail` is `null` — the validator-provided
            // `message` carries the structured `oci.name: <reason>`
            // shape; surfacing it under `detail` would duplicate the
            // information without adding semantics, and the input
            // bytes that triggered the rejection are deliberately NOT
            // echoed (log-injection vector). Same shape as
            // `Unsupported`, `DigestInvalid`, etc.
            Self::NameInvalid { .. } => None,
        }
    }
}

/// Wire shape of a single error in the `errors` array.
///
/// `detail` is `Option<serde_json::Value>` so per-code detail shapes
/// can vary (object for `DENIED`, `{ "name": ... }` for
/// `NAME_UNKNOWN`, absent / null for `UNSUPPORTED`). Always emitted
/// as a field (`null` when absent) rather than skipped: clients parse
/// the array element shape as a stable record, so a missing key and a
/// null key are NOT interchangeable in strict parsers.
#[derive(Debug, Serialize)]
struct WireError {
    code: &'static str,
    message: String,
    detail: Option<serde_json::Value>,
}

/// Envelope shape: `{ "errors": [WireError, ...] }`.
///
/// The spec allows multiple errors in one response (batched manifest
/// push validation, etc.); the current code always emits one. Keeping
/// the array shape preserves forward compatibility for handlers that
/// want to report multiple validation failures in a single reply.
#[derive(Debug, Serialize)]
struct WireEnvelope<'a> {
    errors: [&'a WireError; 1],
}

impl IntoResponse for OciError {
    fn into_response(self) -> Response {
        let status = self.status();
        // `Retry-After` is variant-specific — only `Quarantined` carries
        // it. Computing it before `code()`/`message()`/`detail()`
        // because those move/borrow parts of `self`; the header is a
        // plain i64 clone so the borrow is cheap.
        let retry_after: Option<i64> = match &self {
            Self::Quarantined {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            // `Retry-After` on 429 is RFC 9110 §15.5.18-recommended;
            // clients use it to back off the open-session-create cadence.
            Self::TooManyRequests {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            _ => None,
        };
        // `Range` header is set on 416 responses per §2.8 — the client
        // uses it to resume from the session's real `bytes_received`.
        // Computed before `code()`/`message()`/`detail()` for the same
        // borrow reason as `retry_after`.
        let range_current: Option<u64> = match &self {
            Self::RangeNotSatisfiable { current } => Some(*current),
            _ => None,
        };
        let wire = WireError {
            code: self.code(),
            message: self.message(),
            detail: self.detail(),
        };
        let envelope = WireEnvelope { errors: [&wire] };
        // Serialising a static shape — the only failure mode is an
        // allocation failure, which at this layer is unrecoverable.
        // `serde_json::to_vec` returning `Err` here is a bug, not a
        // runtime contingency, so `expect` is the right reaction.
        let body = serde_json::to_vec(&envelope)
            .expect("OciError envelope serialises to JSON without failure");
        let mut response = (status, [(CONTENT_TYPE, "application/json")], body).into_response();
        if let Some(secs) = retry_after {
            // `Retry-After` per RFC 9110 §10.2.3 accepts either a
            // delta-seconds integer or an HTTP-date. We use the
            // integer form — simpler and the §2.8 table specifies it.
            // `HeaderValue::from` on i64 is infallible for any numeric
            // value; the `max(1)` clamp at the caller site guarantees
            // a positive delta.
            response.headers_mut().insert("Retry-After", secs.into());
        }
        if let Some(current) = range_current {
            // §2.8: 416 response carries `Range: 0-<current - 1>` when
            // `current > 0`, `0-0` when the session is still empty
            // (client PATCHed with start != 0 before any bytes landed).
            // The `Range` header values are bare-bytes ranges per the
            // OCI spec's precedent; they're NOT the HTTP `Range:
            // bytes=…` request-header form. `HeaderValue::from_str`
            // cannot fail here — every produced value is pure ASCII.
            let value = if current == 0 {
                "0-0".to_string()
            } else {
                format!("0-{}", current - 1)
            };
            response.headers_mut().insert(
                "Range",
                axum::http::HeaderValue::from_str(&value)
                    .expect("Range header is ASCII by construction"),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;

    async fn body_of(err: OciError) -> (StatusCode, String) {
        let response = err.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn name_unknown_is_404_with_code_and_name_detail() {
        let (status, body) = body_of(OciError::NameUnknown {
            repository: "library/nginx".into(),
        })
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let errors = parsed["errors"].as_array().expect("errors array");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["code"], "NAME_UNKNOWN");
        assert_eq!(errors[0]["detail"]["name"], "library/nginx");
        assert!(!errors[0]["message"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unauthorized_is_401_and_propagates_detail() {
        let (status, body) = body_of(OciError::Unauthorized {
            message: "token expired".into(),
            detail: Some(serde_json::json!({ "realm": "https://hort/token" })),
        })
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAUTHORIZED");
        assert_eq!(parsed["errors"][0]["message"], "token expired");
        assert_eq!(parsed["errors"][0]["detail"]["realm"], "https://hort/token");
    }

    #[tokio::test]
    async fn unauthorized_with_no_detail_emits_null() {
        let (status, body) = body_of(OciError::Unauthorized {
            message: "no credentials".into(),
            detail: None,
        })
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn denied_is_403_with_repository_and_actions_detail() {
        let (status, body) = body_of(OciError::Denied {
            repository: "private/repo".into(),
            actions: vec!["push".into(), "pull".into()],
        })
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DENIED");
        assert_eq!(parsed["errors"][0]["detail"]["repository"], "private/repo");
        let actions = parsed["errors"][0]["detail"]["actions"]
            .as_array()
            .expect("actions array");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], "push");
        assert_eq!(actions[1], "pull");
    }

    #[tokio::test]
    async fn unsupported_is_400_with_null_detail() {
        let (status, body) = body_of(OciError::Unsupported {
            message: "sha512 digests are not supported".into(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNSUPPORTED");
        assert_eq!(
            parsed["errors"][0]["message"],
            "sha512 digests are not supported"
        );
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn response_content_type_is_application_json() {
        let response = OciError::NameUnknown {
            repository: "x".into(),
        }
        .into_response();
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .expect("Content-Type missing")
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json");
    }

    #[tokio::test]
    async fn blob_unknown_is_404_with_digest_detail() {
        let (status, body) = body_of(OciError::BlobUnknown {
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .into(),
        })
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["digest"],
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(!parsed["errors"][0]["message"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn manifest_unknown_is_404_with_reference_detail() {
        let (status, body) = body_of(OciError::ManifestUnknown {
            reference: "v1.2.3".into(),
        })
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(parsed["errors"][0]["detail"]["reference"], "v1.2.3");
    }

    #[tokio::test]
    async fn manifest_not_acceptable_is_406_with_media_type_detail() {
        let (status, body) = body_of(OciError::ManifestNotAcceptable {
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
        })
        .await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Spec code is still MANIFEST_UNKNOWN — the 406 status
        // distinguishes it from the 404 form.
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["media_type"],
            "application/vnd.oci.image.manifest.v1+json"
        );
    }

    #[tokio::test]
    async fn digest_invalid_is_400_with_message_and_null_detail() {
        let (status, body) = body_of(OciError::DigestInvalid {
            message: "digest must be sha256:<64-hex>".into(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
        assert_eq!(
            parsed["errors"][0]["message"],
            "digest must be sha256:<64-hex>"
        );
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn quarantined_is_503_with_unavailable_code_and_retry_after_header() {
        let err = OciError::Quarantined {
            retry_after_seconds: 42,
        };
        let response = err.into_response();
        let status = response.status();
        let retry_after = response
            .headers()
            .get("Retry-After")
            .expect("Retry-After header missing")
            .to_str()
            .unwrap()
            .to_string();
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after, "42");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        assert_eq!(parsed["errors"][0]["detail"]["retry_after_seconds"], 42);
    }

    #[tokio::test]
    async fn internal_is_500_with_internal_code_and_null_detail() {
        let (status, body) = body_of(OciError::Internal).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "INTERNAL");
        assert_eq!(parsed["errors"][0]["message"], "internal error");
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn non_quarantine_errors_do_not_set_retry_after() {
        // Regression guard: only Quarantined should emit Retry-After.
        // A bug in IntoResponse that attached the header unconditionally
        // would be caught here.
        let response = OciError::NameUnknown {
            repository: "x".into(),
        }
        .into_response();
        assert!(
            response.headers().get("Retry-After").is_none(),
            "NameUnknown must not emit Retry-After"
        );
    }

    #[tokio::test]
    async fn blob_upload_unknown_is_404_with_session_id_detail() {
        let (status, body) = body_of(OciError::BlobUploadUnknown {
            session_id: "11111111-1111-1111-1111-111111111111".into(),
        })
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["session_id"],
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[tokio::test]
    async fn blob_upload_invalid_is_400_with_supplied_message() {
        let (status, body) = body_of(OciError::BlobUploadInvalid {
            message: "declared body length disagrees with content-range span".into(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_INVALID");
        assert_eq!(
            parsed["errors"][0]["message"],
            "declared body length disagrees with content-range span"
        );
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn size_invalid_is_413() {
        let (status, body) = body_of(OciError::SizeInvalid {
            message: "chunk would push session past 1 GiB cap".into(),
        })
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "SIZE_INVALID");
        assert_eq!(
            parsed["errors"][0]["message"],
            "chunk would push session past 1 GiB cap"
        );
    }

    #[tokio::test]
    async fn range_not_satisfiable_is_416_with_range_header() {
        // 100 bytes already received → Range: 0-99.
        let response = OciError::RangeNotSatisfiable { current: 100 }.into_response();
        let status = response.status();
        let range = response
            .headers()
            .get("Range")
            .expect("Range header required on 416")
            .to_str()
            .unwrap()
            .to_string();
        let bytes = to_bytes(response.into_body(), 4 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(range, "0-99");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // §2.8 code is BLOB_UPLOAD_INVALID on 416 (the status
        // distinguishes range-mismatch from the generic 400 form).
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_INVALID");
        assert_eq!(parsed["errors"][0]["detail"]["bytes_received"], 100);
    }

    #[tokio::test]
    async fn range_not_satisfiable_on_empty_session_emits_zero_zero() {
        // No bytes received yet → the `0-<current-1>` form would
        // underflow. The helper must clamp to "0-0" in that case so
        // the client still gets a valid resumable anchor.
        let response = OciError::RangeNotSatisfiable { current: 0 }.into_response();
        let range = response.headers().get("Range").unwrap().to_str().unwrap();
        assert_eq!(range, "0-0");
    }

    #[tokio::test]
    async fn manifest_invalid_is_400_with_optional_detail() {
        let (status, body) = body_of(OciError::ManifestInvalid {
            detail: Some(serde_json::json!({ "media_type": "application/json" })),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert_eq!(
            parsed["errors"][0]["detail"]["media_type"],
            "application/json"
        );
    }

    #[tokio::test]
    async fn manifest_invalid_with_no_detail_emits_null() {
        let (status, body) = body_of(OciError::ManifestInvalid { detail: None }).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn manifest_blob_unknown_is_400_with_blobs_array() {
        let blobs = vec![
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];
        let (status, body) = body_of(OciError::ManifestBlobUnknown {
            blobs: blobs.clone(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
        let blobs_arr = parsed["errors"][0]["detail"]["blobs"]
            .as_array()
            .expect("blobs array");
        assert_eq!(blobs_arr.len(), 2);
        assert_eq!(blobs_arr[0], blobs[0]);
        assert_eq!(blobs_arr[1], blobs[1]);
    }

    #[tokio::test]
    async fn name_invalid_is_400_with_supplied_message_and_null_detail() {
        // Spec code `NAME_INVALID`, status 400, message echoes the
        // validator's tagged `oci.name: <reason>` text, detail is null
        // (the message already carries the structured shape).
        let (status, body) = body_of(OciError::NameInvalid {
            message: "oci.name: invalid character (allowed: `[a-z0-9._-/]`)".into(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_INVALID");
        assert_eq!(
            parsed["errors"][0]["message"],
            "oci.name: invalid character (allowed: `[a-z0-9._-/]`)"
        );
        assert!(parsed["errors"][0]["detail"].is_null());
    }

    #[tokio::test]
    async fn envelope_has_errors_array_shape() {
        // Every OCI error response is an array, even when there's only
        // one error — the spec shape is non-negotiable.
        let (_, body) = body_of(OciError::Unsupported {
            message: "x".into(),
        })
        .await;
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["errors"].is_array());
        assert!(parsed.get("error").is_none(), "no generic `error` key");
    }
}
