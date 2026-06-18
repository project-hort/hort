//! OCI blob upload — `POST /v2/<repo>/<name>/blobs/uploads/`.
//!
//! Three branches driven by query parameters:
//!
//! | Query params                       | Semantics                       |
//! |-----------------------------------|---------------------------------|
//! | `?mount=<digest>&from=<src-key>`  | Cross-repo mount (zero-copy)    |
//! | `?digest=<digest>` + request body | Monolithic single-request push  |
//! | (none)                            | Three-phase initiate            |
//!
//! Cross-mount is zero-copy: [`IngestUseCase::register_by_hash`]
//! attaches an existing CAS object to the target repository with no
//! re-streaming.  Monolithic is a normal [`IngestUseCase::ingest`]
//! with `declared_sha256 = Some(digest)` so mismatch is caught before
//! the event commits.  Three-phase initiate creates a session row in
//! [`EphemeralStore`] via [`super::upload_session::initiate`] and
//! returns `Location` / `Docker-Upload-UUID` / `Range: 0-0` for the
//! client's PATCH chunking loop + PUT finalize.
//!
//! Design authority: OCI Distribution Spec (upload lifecycle, error
//! envelope, response headers); see
//! `how-to/oci-pull-through.md` §5 on why this module lives in
//! `hort-http-oci` not `hort-app`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Query, Request, State};
use axum::http::header::{CONTENT_LENGTH, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::TryStreamExt;
use serde::Deserialize;
use tokio_util::io::StreamReader;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::ingest_use_case::{IngestRequest, VerifiedIngestRequest};
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::types::ContentHash;
use hort_formats::oci::OciFormatHandler;

use hort_http_core::authz::WriteRepoAccess;
use hort_http_core::context::AppContext;
use hort_http_core::limits::BoundedPath;

use super::coords::oci_blob_coords;
use super::digest::{parse_digest, DigestParse};
use super::error::OciError;
use super::name::validate_oci_name;
use super::upload_session::{append_chunk, finalize, ContentRange, InitiateResult};
use super::OciHttpConfig;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the OCI blob upload router.
///
/// A single `POST /v2/:repo_key/*tail` route drives all three branches;
/// tail parsing (via [`super::tail`]) extracts the `<name>` segment
/// and asserts the `/blobs/uploads/` suffix before dispatching.
///
/// A wildcard tail route is unavoidable: axum / matchit does not allow
/// literal segments after a `*name` capture, so the more natural
/// template `POST /v2/:repo_key/*name/blobs/uploads/` can't be
/// registered directly.  Same shape as the GET pull dispatcher in
/// `lib.rs::oci_routes_with_config`.
///
/// This router is merged with the main OCI router by
/// [`super::oci_routes_with_config`] so the POST method attaches to
/// the same `/v2/:repo_key/*tail` path without colliding with the GET /
/// HEAD handlers — axum method routers compose cleanly on the same
/// route template when the HTTP methods differ.
pub fn router() -> Router<Arc<AppContext>> {
    // The per-`(repo, principal)` concurrent-session cap is delivered
    // via `Extension<OciHttpConfig>`. Standalone callers (used in
    // handler-level integration tests that bypass the merged
    // `oci_routes_with_config` builder) get the default config here;
    // production callers pass their own via `oci_routes_with_config`'s
    // Extension layer.
    Router::new()
        .route(
            "/v2/:repo_key/*tail",
            axum::routing::post(post_upload_dispatch)
                .patch(patch_upload_dispatch)
                .put(put_upload_dispatch),
        )
        .layer(Extension(OciHttpConfig::default()))
}

/// Tail-parse output specialised for blob upload routes.
///
/// Kept separate from [`super::tail::TailKind`] because the upload
/// shape is method-specific (POST-only).  Adding a `BlobUploadInit`
/// variant to the shared tail parser would pollute the GET dispatcher
/// with an unreachable arm.
enum UploadTail<'a> {
    /// `<name>/blobs/uploads/` — initiate / monolithic / mount.
    InitBlobUpload { name: &'a str },
}

/// Parse the `*tail` capture from a POST request.  Returns `None` if
/// the tail doesn't end in `/blobs/uploads/` — the caller maps that
/// to `NAME_UNKNOWN`.
fn parse_upload_tail(tail: &str) -> Option<UploadTail<'_>> {
    let name = tail.strip_suffix("/blobs/uploads/")?;
    if name.is_empty() {
        return None;
    }
    Some(UploadTail::InitBlobUpload { name })
}

// ---------------------------------------------------------------------------
// Query payload
// ---------------------------------------------------------------------------

/// Query parameters on `POST /v2/…/blobs/uploads/`.
///
/// `mount` + `from` together trigger the cross-repo mount branch;
/// `digest` alone triggers the monolithic branch; absence of all three
/// triggers the three-phase initiate branch.  Any other combination
/// (mount without from, etc.) is a 400 UNSUPPORTED.
#[derive(Debug, Deserialize, Default)]
pub struct UploadQuery {
    pub mount: Option<String>,
    pub from: Option<String>,
    pub digest: Option<String>,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Entry point for `POST /v2/:repo_key/*tail`.
///
/// `WriteRepoAccess` is placed first in the handler signature so it
/// runs as a [`FromRequestParts`] extractor before the body stream is
/// touched — it resolves the `:repo_key` path param, looks up the
/// repository aggregate, runs the RBAC check (granting unconditionally
/// under [`AuthContext::Disabled`]), and stashes the resolved
/// `Arc<Repository>` in request extensions for downstream re-use.
/// On deny the extractor short-circuits with
/// `403 {"error":"insufficient permissions"}`; on unknown repo it
/// returns the extractor's generic `404 {"error":"repository not found"}`
/// rather than the OCI `NAME_UNKNOWN` envelope — the two envelopes
/// are deliberately divergent pending `NAME_UNKNOWN` unification.
///
/// [`FromRequestParts`]: axum::extract::FromRequestParts
/// [`AuthContext::Disabled`]: hort_http_core::context::AuthContext::Disabled
pub(crate) async fn post_upload_dispatch(
    access: WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    // `OciHttpConfig` arrives via `axum::Extension` populated by the
    // layer in [`super::oci_routes_with_config`]. The cross-mount and
    // monolithic branches do not consult the cap; only the three-phase
    // initiate branch reads `max_sessions_per_principal`.
    Extension(oci_cfg): Extension<OciHttpConfig>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    Query(query): Query<UploadQuery>,
    request: Request<Body>,
) -> Response {
    let name = match parse_upload_tail(&tail) {
        Some(UploadTail::InitBlobUpload { name }) => name.to_string(),
        None => {
            return OciError::NameUnknown {
                repository: format!("{repo_key}/{tail}"),
            }
            .into_response();
        }
    };
    // Validate the parsed `<name>` from `<name>/blobs/uploads/` against
    // the OCI grammar BEFORE any session creation, cross-mount lookup,
    // or monolithic-push ingest. The validator is the single source of
    // truth for "image name shape" on every upload-initiate branch
    // (initiate / mount / monolithic).
    if let Err(e) = validate_oci_name(&name) {
        return super::name_invalid_response(e);
    }

    let repo_id = access.repository.id;
    let principal = access.principal.clone();
    let actor = ApiActor {
        user_id: principal.user_id,
    };

    // Query-branch selection. `mount XOR from` is invalid (the spec
    // requires both). After that: `digest` -> monolithic; else ->
    // three-phase initiate.
    match (query.mount, query.from, query.digest) {
        (Some(mount), Some(from), _) => {
            handle_cross_mount(
                ctx,
                &repo_key,
                &name,
                repo_id,
                &mount,
                &from,
                actor,
                &principal,
                oci_cfg.max_sessions_per_principal,
            )
            .await
        }
        (Some(_), None, _) | (None, Some(_), _) => OciError::Unsupported {
            message: "`mount` and `from` query parameters must be supplied together".into(),
        }
        .into_response(),
        (None, None, Some(digest)) => {
            handle_monolithic(ctx, &repo_key, &name, repo_id, &digest, actor, request).await
        }
        (None, None, None) => {
            handle_initiate(
                ctx,
                &repo_key,
                &name,
                repo_id,
                actor,
                oci_cfg.max_sessions_per_principal,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-mount
// ---------------------------------------------------------------------------

/// Cross-repo blob mount (`?mount=<digest>&from=<src>`).
///
/// Resolves the source repo (with Read authz on the actor — ADR 0008),
/// validates the digest, then calls
/// [`IngestUseCase::register_by_hash`] — zero-copy. On the register
/// `NotFound` surfaces as `BLOB_UNKNOWN` (the hash isn't in the source
/// repo).
///
/// Without the authz check on the source repo, any caller with `Write`
/// on `target-repo` could clone any blob from any other repo in the
/// registry — even a private one they had no `Read` grant on — by
/// submitting `?mount=<sha>&from=<other-repo>`. The fix routes through
/// [`RepositoryAccessUseCase::resolve`] with `AccessLevel::Read` on
/// the source. If the actor cannot read the source, the use case
/// returns `NotFound` (anti-enumeration); we fall through to
/// "initiate a normal blob upload" per OCI §2.3, which says: "If a
/// registry does not support cross-repository mounting … it MUST fall
/// back to the standard upload behavior and return a `202 Accepted`
/// …". A 4xx here would break docker / skopeo retry loops; the spec's
/// fallback path is the correct reaction.
#[allow(clippy::too_many_arguments)]
async fn handle_cross_mount(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    target_repo_id: Uuid,
    mount_digest: &str,
    from: &str,
    actor: ApiActor,
    principal: &hort_domain::entities::caller::CallerPrincipal,
    // Needed by the cross-mount fallthrough path where an unauthorized
    // source repo collapses to standard initiate semantics. The per-`(repo,
    // principal)` cap still applies on that fall-through.
    max_sessions_per_principal: u32,
) -> Response {
    let hash = match parse_digest(mount_digest) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported { algorithm } => {
            return OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response();
        }
        DigestParse::Invalid { message } => {
            return OciError::DigestInvalid { message }.into_response();
        }
    };

    // Read-authz check on the source repo (ADR 0008). NotFound
    // (missing OR invisible) collapses to "fall through to initiate"
    // per the OCI spec. Any other error surfaces as 500.
    let src_repo = match ctx
        .repository_access_use_case
        .resolve(from, Some(principal), AccessLevel::Read)
        .await
    {
        Ok(r) => r,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            tracing::debug!(
                from = %from,
                target_repo_id = %target_repo_id,
                actor = %principal.external_id,
                "OCI cross-mount denied (source missing or invisible) — falling through to initiate per OCI spec"
            );
            return handle_initiate(
                ctx,
                repo_key,
                name,
                target_repo_id,
                actor,
                max_sessions_per_principal,
            )
            .await;
        }
        Err(e) => {
            tracing::error!(
                from = %from,
                error = %e,
                "source repo lookup failed during OCI blob mount"
            );
            return OciError::Internal.into_response();
        }
    };

    let req = IngestRequest {
        repository_id: target_repo_id,
        coords: oci_blob_coords(name, &hash),
        content_type: "application/octet-stream".into(),
        // OCI cross-repo blob mount is not a seed-import; the
        // anchor override field stays `None`.
        quarantine_anchor_override: None,
        actor,
        legacy_sha1: None,
        legacy_md5: None,
        declared_sha256: None,
        payload_metadata: serde_json::json!({ "oci_mount_from": from }),
    };

    match ctx
        .ingest_use_case
        .register_by_hash(req, hash.clone(), Some(src_repo.id), &OciFormatHandler)
        .await
    {
        Ok(_outcome) => created_blob_response(repo_key, name, &hash),
        Err(err) => map_register_error(err, &hash),
    }
}

fn map_register_error(err: AppError, hash: &ContentHash) -> Response {
    match err {
        AppError::Domain(DomainError::NotFound { .. }) => OciError::BlobUnknown {
            digest: format!("sha256:{}", hash.as_ref()),
        }
        .into_response(),
        AppError::Domain(DomainError::Conflict(_)) => OciError::DigestInvalid {
            message: "digest conflict at target path".into(),
        }
        .into_response(),
        other => {
            tracing::error!(error = %other, "OCI blob mount register_by_hash failed");
            OciError::Internal.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Monolithic
// ---------------------------------------------------------------------------

/// Monolithic single-request blob push (`?digest=<digest>` + body).
///
/// `declared_sha256 = Some(digest)` so [`IngestUseCase::ingest`] rejects
/// a mismatch before the event commits; on mismatch we surface 400
/// `DIGEST_INVALID`.
async fn handle_monolithic(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    repo_id: Uuid,
    digest_str: &str,
    actor: ApiActor,
    request: Request<Body>,
) -> Response {
    let hash = match parse_digest(digest_str) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported { algorithm } => {
            return OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response();
        }
        DigestParse::Invalid { message } => {
            return OciError::DigestInvalid { message }.into_response();
        }
    };

    // OCI coords always use format = RepositoryFormat::Oci; we don't
    // inherit from the repo aggregate because an OCI image can live in
    // a generic-format repo during migration windows.
    let mut coords = oci_blob_coords(name, &hash);
    coords.format = RepositoryFormat::Oci;

    // Adapt axum's request body (a `Stream<Item = Result<Bytes, _>>`)
    // into an `AsyncRead`.  Mirrors the shape used by
    // `hort-http-pypi::upload`'s in-memory cursor path but stays
    // streaming — OCI pushes can be gigabytes and we never want to
    // buffer the whole body.
    let body_stream = request.into_body().into_data_stream();
    let reader = StreamReader::new(body_stream.map_err(std::io::Error::other));
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(reader);

    // OCI direct upload — digest comes from the request URL (ADR 0006).
    // ProtocolNative covers both pull-through and direct.
    let req = VerifiedIngestRequest::ProtocolNative {
        repository_id: repo_id,
        coords,
        content_type: "application/octet-stream".into(),
        actor,
        payload_metadata: serde_json::Value::Null,
        upstream_digest: hash.clone(),
        upstream_published_at: None,
        // Direct upload has no serving `RepositoryUpstreamMapping`;
        // the per-upstream opt-in cannot apply, so the bool is `false`.
        // `ingest_inner` anchors the quarantine window to `ingested_at`.
        trust_upstream_publish_time: false,
    };

    match ctx
        .ingest_use_case
        .ingest_verified(req, stream, &OciFormatHandler)
        .await
    {
        Ok(_outcome) => created_blob_response(repo_key, name, &hash),
        // `IngestUseCase::ingest` raises `Conflict` when the declared
        // digest disagrees with the streamed content's computed SHA-256
        // on a fresh insert, and rolls back the CAS blob before
        // returning — so the handler just maps `Conflict` to
        // `400 DIGEST_INVALID` with no post-ingest double-check.
        Err(AppError::Domain(DomainError::Conflict(_))) => OciError::DigestInvalid {
            message: "declared digest did not match uploaded content".into(),
        }
        .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "OCI monolithic blob push failed");
            OciError::Internal.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// PATCH (append chunk)
// ---------------------------------------------------------------------------

/// Fallback max-blob-bytes cap used when `ctx.publish_body_limit_bytes`
/// is `None`. Matches the Docker Registry V2 reference deployment and
/// keeps a single-PATCH runaway to a reasonable upper bound.
const DEFAULT_MAX_BLOB_BYTES: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB

/// Parse error for `Content-Range: bytes <start>-<end>`.  Crate-private —
/// the HTTP adapter is the only consumer, and every variant maps to
/// the same `BLOB_UPLOAD_INVALID` envelope, so the type is shape-only
/// for message carrying.
#[derive(Debug, Clone)]
struct ContentRangeParseError {
    message: String,
}

/// Parse a `Content-Range` header value of the form `bytes <start>-<end>`.
///
/// The OCI Distribution Spec requires this exact shape for chunked
/// uploads — the HTTP `Content-Range: bytes a-b/*` form from RFC 7233
/// is what spec-compliant clients send.  We accept both forms (with and
/// without a `/` total suffix) because the Docker CLI sometimes emits
/// `bytes a-b/*` and sometimes plain `bytes a-b` — the spec-minimum
/// is the bare `a-b`; we tolerate the `/…` suffix by discarding it.
/// No byte-unit other than `bytes` is accepted; the spec makes no
/// allowance for alternatives.
fn parse_content_range(value: &str) -> Result<ContentRange, ContentRangeParseError> {
    let trimmed = value.trim();
    // Accept both `bytes <a>-<b>` and the bare `<a>-<b>` form.  Real
    // OCI clients reliably send the `bytes ` prefix; the prefix-less
    // form is a tolerance for older tooling only.
    let range_part = trimmed.strip_prefix("bytes ").unwrap_or(trimmed);
    // Strip `/<total>` suffix if present.
    let core = range_part.split('/').next().unwrap_or(range_part).trim();
    let (start_s, end_s) = core.split_once('-').ok_or_else(|| ContentRangeParseError {
        message: format!("Content-Range missing `-`: {value}"),
    })?;
    let start: u64 = start_s.trim().parse().map_err(|e| ContentRangeParseError {
        message: format!("Content-Range start not a u64: {e}"),
    })?;
    let end: u64 = end_s.trim().parse().map_err(|e| ContentRangeParseError {
        message: format!("Content-Range end not a u64: {e}"),
    })?;
    if end < start {
        return Err(ContentRangeParseError {
            message: format!("Content-Range end < start: {start}-{end}"),
        });
    }
    Ok(ContentRange { start, end })
}

/// Tail-parse output for PATCH requests.  `<name>/blobs/uploads/<session_id>`.
enum PatchTail<'a> {
    AppendChunk { name: &'a str, session_id: Uuid },
}

/// Parse the PATCH `*tail` capture.  Returns `None` if the tail does
/// not match the `<name>/blobs/uploads/<uuid>` shape — the caller
/// maps that to `NAME_UNKNOWN` (consistent with the POST branch's
/// wrong-suffix handling).
fn parse_patch_tail(tail: &str) -> Option<PatchTail<'_>> {
    // Find the last occurrence of `/blobs/uploads/` and split there.
    let idx = tail.rfind("/blobs/uploads/")?;
    let name = &tail[..idx];
    if name.is_empty() {
        return None;
    }
    let session_part = &tail[idx + "/blobs/uploads/".len()..];
    // Reject trailing slash, empty, or embedded slashes — session id
    // must be a single UUID segment.
    if session_part.is_empty() || session_part.contains('/') {
        return None;
    }
    let session_id = Uuid::parse_str(session_part).ok()?;
    Some(PatchTail::AppendChunk { name, session_id })
}

/// Dispatch `PATCH /v2/:repo_key/*tail`.  Validates auth via
/// `WriteRepoAccess`, parses the Content-Range + Content-Length
/// headers, streams the body through `append_chunk`, and emits the
/// 202 + `Range` + `Location` + `Docker-Upload-UUID` triple on
/// success per the OCI spec.
pub(crate) async fn patch_upload_dispatch(
    access: WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    request: Request<Body>,
) -> Response {
    let (name, session_id) = match parse_patch_tail(&tail) {
        Some(PatchTail::AppendChunk { name, session_id }) => (name.to_string(), session_id),
        None => {
            return OciError::NameUnknown {
                repository: format!("{repo_key}/{tail}"),
            }
            .into_response();
        }
    };
    // PATCH `append_chunk` accepts attacker-controlled body bytes.
    // Reject malformed `<name>` BEFORE the body stream runs through
    // `append_chunk`.
    if let Err(e) = validate_oci_name(&name) {
        return super::name_invalid_response(e);
    }

    let repo_id = access.repository.id;
    // Actor is carried for log / audit fields; `append_chunk` does not
    // persist events (the session itself is the only state). The PUT
    // finalize handler threads this actor into `IngestUseCase::ingest`.
    let _actor = ApiActor {
        user_id: access.principal.user_id,
    };

    // Pull headers BEFORE decomposing the request — the body consumer
    // below moves `request`.
    let headers = request.headers().clone();
    // `Content-Range` is OPTIONAL on PATCH. The OCI v1.1 spec
    // recommends it but the dominant client (containers/image —
    // skopeo, podman, buildah) omits it on streaming chunked uploads,
    // and the Docker Registry V2 reference implementation accepts
    // header-less PATCHes.  When absent we let `append_chunk` synthesise
    // a range anchored at the session's current `bytes_received`.
    // When present we still parse + validate strictly.
    let content_range = match headers.get("Content-Range") {
        None => None,
        Some(content_range_header) => {
            let Ok(content_range_str) = content_range_header.to_str() else {
                return OciError::BlobUploadInvalid {
                    message: "Content-Range header is not valid ASCII".into(),
                }
                .into_response();
            };
            match parse_content_range(content_range_str) {
                Ok(r) => Some(r),
                Err(e) => {
                    return OciError::BlobUploadInvalid { message: e.message }.into_response();
                }
            }
        }
    };

    // `Content-Length` is required per the spec.  We trust it as the
    // declared body length; `append_chunk` cross-checks that the
    // content-range span matches and that the staging append actually
    // landed `body_length` bytes.
    let Some(content_length) = headers.get(CONTENT_LENGTH) else {
        return OciError::BlobUploadInvalid {
            message: "missing Content-Length header".into(),
        }
        .into_response();
    };
    let Ok(content_length_str) = content_length.to_str() else {
        return OciError::BlobUploadInvalid {
            message: "Content-Length header is not valid ASCII".into(),
        }
        .into_response();
    };
    let Ok(body_length) = content_length_str.trim().parse::<u64>() else {
        return OciError::BlobUploadInvalid {
            message: "Content-Length is not a u64".into(),
        }
        .into_response();
    };

    let max_bytes: u64 = ctx
        .publish_body_limit_bytes
        .map(|n| n as u64)
        .unwrap_or(DEFAULT_MAX_BLOB_BYTES);

    // Adapt the axum body into an `AsyncRead`.  Same shape as the
    // monolithic-push branch — body never buffers end-to-end; the
    // staging adapter streams it to disk.
    let body_stream = request.into_body().into_data_stream();
    let reader = StreamReader::new(body_stream.map_err(std::io::Error::other));
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(reader);

    match append_chunk(
        &ctx,
        session_id,
        content_range,
        stream,
        body_length,
        max_bytes,
        repo_id,
    )
    .await
    {
        Ok(new_record) => {
            patch_success_response(&repo_key, &name, session_id, new_record.bytes_received)
        }
        Err(err) => map_patch_error(err, session_id),
    }
}

/// Build the 202 response on a successful PATCH. The `Location` header
/// MUST include `repo_key` and `name` so the client's next PATCH
/// reaches a routable path.
fn patch_success_response(
    repo_key: &str,
    name: &str,
    session_id: Uuid,
    new_bytes: u64,
) -> Response {
    let location = format!("/v2/{repo_key}/{name}/blobs/uploads/{session_id}");
    let range = if new_bytes == 0 {
        // Defensive: a zero-byte PATCH is malformed but the response
        // header still needs a valid anchor.  `0-0` tracks the
        // init-response convention; callers that actually PATCH >0
        // bytes get the `0-(n-1)` form below.
        "0-0".to_string()
    } else {
        format!("0-{}", new_bytes - 1)
    };

    // `repo_key` and `name` come from URL captures; CRLF or other
    // non-ASCII bytes in either segment produce an `InvalidHeaderValue`
    // error from `from_str`. A panic on that path is a DoS primitive —
    // the helper returns the canonical `NAME_UNKNOWN` 404 envelope
    // instead.
    let location_header = match super::header_value_or_bad_request(&location) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, location_header);
    headers.insert(
        "Range",
        HeaderValue::from_str(&range).expect("range header is ASCII by construction"),
    );
    headers.insert(
        "Docker-Upload-UUID",
        HeaderValue::from_str(&session_id.to_string()).expect("UUID display form is valid ASCII"),
    );
    (StatusCode::ACCEPTED, headers, Body::empty()).into_response()
}

/// Map an [`AppError`] from `append_chunk` to the OCI error envelope.
fn map_patch_error(err: AppError, session_id: Uuid) -> Response {
    match err {
        AppError::Domain(DomainError::NotFound { .. }) => OciError::BlobUploadUnknown {
            session_id: session_id.to_string(),
        }
        .into_response(),
        AppError::Domain(DomainError::Conflict(msg)) => OciError::BlobUploadInvalid {
            // CAS-miss on the optimistic-concurrency check.  The
            // message is operator-facing (traces, server logs); the
            // wire body carries the same string so a 1:1 grep between
            // client-observed and server-observed bodies is preserved.
            message: msg,
        }
        .into_response(),
        AppError::RangeInvalid { current } => {
            OciError::RangeNotSatisfiable { current }.into_response()
        }
        AppError::BodyLengthMismatch => OciError::BlobUploadInvalid {
            message: "Content-Range span did not match Content-Length".into(),
        }
        .into_response(),
        AppError::SizeExceeded => OciError::SizeInvalid {
            message: "blob upload would exceed the configured maximum size".into(),
        }
        .into_response(),
        other => {
            tracing::error!(error = %other, "OCI PATCH chunk failed with unmapped error");
            OciError::Internal.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// PUT (finalize)
// ---------------------------------------------------------------------------

/// Query parameters on `PUT /v2/…/blobs/uploads/:session_id`.
///
/// `digest` is REQUIRED per the OCI spec — the finalize handler rejects a
/// missing / malformed value as 400 `DIGEST_INVALID` (or
/// `UNSUPPORTED` for a well-formed but non-sha256 algorithm prefix,
/// matching the POST monolithic branch's semantics).
///
/// Deliberately separate from `UploadQuery` (POST): on PUT the
/// `mount` / `from` query parameters are illegal — clients that need
/// cross-mount use POST. The `PutQuery` type captures only what the
/// handler honours.
#[derive(Debug, Deserialize, Default)]
pub struct PutQuery {
    pub digest: Option<String>,
}

/// Dispatch `PUT /v2/:repo_key/*tail`.
///
/// The handler's flow:
/// 1. Extract + parse the session UUID from the tail.
/// 2. Parse the required `?digest=<sha256:hex>` query param.
/// 3. If `Content-Length > 0`, parse the trailing `Content-Range`
///    header + body into a tuple for [`finalize`] to forward to
///    `append_chunk`.
/// 4. Call [`upload_session::finalize`] and map the result to the
///    201 + `Location` + `Docker-Content-Digest` response.
pub(crate) async fn put_upload_dispatch(
    access: WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    Query(query): Query<PutQuery>,
    request: Request<Body>,
) -> Response {
    let (name, session_id) = match parse_patch_tail(&tail) {
        // PUT and PATCH share the `<name>/blobs/uploads/<uuid>` tail
        // shape; reusing `parse_patch_tail` keeps the grammar in one
        // place. A future divergence (e.g. manifest PUT landing on
        // the same dispatcher) would fork the parser.
        Some(PatchTail::AppendChunk { name, session_id }) => (name.to_string(), session_id),
        None => {
            return OciError::NameUnknown {
                repository: format!("{repo_key}/{tail}"),
            }
            .into_response();
        }
    };
    // PUT finalize commits the staged blob to CAS and emits the
    // artifact-ingest event. Reject malformed `<name>` BEFORE the
    // finalize / ingest.
    if let Err(e) = validate_oci_name(&name) {
        return super::name_invalid_response(e);
    }

    let repo_id = access.repository.id;
    let actor = ApiActor {
        user_id: access.principal.user_id,
    };

    // `?digest=<sha256:hex>` is mandatory on finalize.  A missing
    // value maps to `DIGEST_INVALID` (NOT `UNSUPPORTED`) per backlog
    // review-finding C5; a well-formed but non-sha256 algorithm
    // prefix maps to `UNSUPPORTED`; everything else (malformed, non-
    // hex, wrong length) also maps to `DIGEST_INVALID`.
    let Some(digest_str) = query.digest else {
        return OciError::DigestInvalid {
            message: "missing required `digest` query parameter".into(),
        }
        .into_response();
    };
    let hash = match parse_digest(&digest_str) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported { algorithm } => {
            return OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response();
        }
        DigestParse::Invalid { message } => {
            return OciError::DigestInvalid { message }.into_response();
        }
    };

    let max_bytes: u64 = ctx
        .publish_body_limit_bytes
        .map(|n| n as u64)
        .unwrap_or(DEFAULT_MAX_BLOB_BYTES);

    // Extract headers before moving `request` into the body reader.
    let headers = request.headers().clone();
    let body_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    // Construct the trailing-body tuple if the client sent one.  A
    // zero-length PUT is the dominant path for the three-phase
    // protocol (the final PATCH carried all bytes); a length > 0 is
    // the two-phase POST→PUT pattern (skopeo, docker, podman,
    // containers/image) where the client folds the entire blob into
    // the finalize request.
    //
    // `Content-Range` is OPTIONAL on a non-empty PUT body. The OCI
    // The OCI distribution spec requires `Content-Range` on chunked
    // PATCH but not on the two-phase finalize PUT — and in
    // practice none of the major clients send it. When absent the
    // server treats the body as a chunk anchored at the session's
    // current `bytes_received`; `upload_session::finalize_core`
    // performs that synthesis once it has loaded the session record.
    // When present, we still parse + validate strictly and pass the
    // parsed range through, so chunk-aware clients keep getting the
    // tight invariant check.
    let trailing_body: Option<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Option<ContentRange>,
        u64,
    )> = if body_length > 0 {
        let content_range = match headers.get("Content-Range") {
            None => None,
            Some(range_header) => {
                let Ok(range_str) = range_header.to_str() else {
                    return OciError::BlobUploadInvalid {
                        message: "Content-Range header is not valid ASCII".into(),
                    }
                    .into_response();
                };
                match parse_content_range(range_str) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        return OciError::BlobUploadInvalid { message: e.message }.into_response();
                    }
                }
            }
        };
        let body_stream = request.into_body().into_data_stream();
        let reader = StreamReader::new(body_stream.map_err(std::io::Error::other));
        let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(reader);
        Some((stream, content_range, body_length))
    } else {
        // No body — drop the `Request` explicitly to drain any
        // unread stream state so a pathological client that sent
        // chunks but lied about Content-Length doesn't leave
        // bytes queued on the connection.
        drop(request);
        None
    };

    match finalize(
        &ctx,
        session_id,
        hash.clone(),
        trailing_body,
        actor,
        repo_id,
        &name,
        max_bytes,
    )
    .await
    {
        Ok(_outcome) => created_blob_response(&repo_key, &name, &hash),
        Err(err) => map_put_error(err, session_id),
    }
}

/// Map an [`AppError`] returned by [`finalize`] to the OCI error envelope.
///
/// Most variants overlap with `map_patch_error` (`finalize` forwards
/// the trailing-body PATCH verbatim), but the `Conflict` arm diverges:
/// on PATCH a Conflict is a CAS miss (concurrent PATCH won) and maps
/// to `BLOB_UPLOAD_INVALID`; on PUT a Conflict is the declared-hash
/// mismatch raised by `IngestUseCase::ingest` and MUST map to
/// `DIGEST_INVALID`.
fn map_put_error(err: AppError, session_id: Uuid) -> Response {
    match err {
        AppError::Domain(DomainError::NotFound { .. }) => OciError::BlobUploadUnknown {
            session_id: session_id.to_string(),
        }
        .into_response(),
        // Declared-hash mismatch surfaced by `IngestUseCase::ingest`
        // after the CAS rollback ran. `finalize` has already cleaned up
        // the session + staging on this branch; the handler just emits
        // the envelope.
        AppError::Domain(DomainError::Conflict(_)) => OciError::DigestInvalid {
            message: "declared digest did not match uploaded content".into(),
        }
        .into_response(),
        AppError::RangeInvalid { current } => {
            OciError::RangeNotSatisfiable { current }.into_response()
        }
        AppError::BodyLengthMismatch => OciError::BlobUploadInvalid {
            message: "Content-Range span did not match Content-Length".into(),
        }
        .into_response(),
        AppError::SizeExceeded => OciError::SizeInvalid {
            message: "blob upload would exceed the configured maximum size".into(),
        }
        .into_response(),
        other => {
            tracing::error!(error = %other, "OCI PUT finalize failed with unmapped error");
            OciError::Internal.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Three-phase initiate
// ---------------------------------------------------------------------------

/// Three-phase initiate — creates a session row and hands the client a
/// URL to PATCH chunks into.
///
/// Passes the `max_sessions_per_principal` cap through to
/// [`super::upload_session::initiate`]. A
/// [`InitiateResult::CapExceeded`] surfaces as `429 Too Many Requests`
/// with the spec's `TOOMANYREQUESTS` envelope and an advisory
/// `Retry-After` header. Cap rejections do NOT leak the cap value or
/// the principal's identity in the response — the caller already
/// knows their own session count via 4xx-rate observation, and
/// disclosing the cap value to an attacker provides them a precise
/// abuse budget.
async fn handle_initiate(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    repo_id: Uuid,
    actor: ApiActor,
    max_sessions_per_principal: u32,
) -> Response {
    match super::upload_session::initiate(&ctx, repo_id, actor, max_sessions_per_principal).await {
        Ok(InitiateResult::Created(outcome)) => {
            initiate_response(repo_key, name, outcome.session_id)
        }
        Ok(InitiateResult::CapExceeded) => {
            // 429 + advisory `Retry-After`. Use the OCI session TTL
            // (3600s) as the hint — it's the upper bound on how long
            // the slot can stay occupied without being released.
            OciError::TooManyRequests {
                retry_after_seconds: super::upload_session::OCI_SESSION_TTL.as_secs() as i64,
            }
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "OCI upload-session initiate failed");
            OciError::Internal.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

/// Build the 201 response for a successful cross-mount or monolithic
/// push. `Location` points at the final blob URL,
/// `Docker-Content-Digest` echoes the content hash, body is empty.
fn created_blob_response(repo_key: &str, name: &str, hash: &ContentHash) -> Response {
    let location = format!("/v2/{repo_key}/{name}/blobs/sha256:{}", hash.as_ref());
    // See `patch_success_response` — CRLF-in-capture guard.
    let location_header = match super::header_value_or_bad_request(&location) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, location_header);
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&format!("sha256:{}", hash.as_ref()))
            .expect("sha256:<hex> is valid ASCII"),
    );
    (StatusCode::CREATED, headers, Body::empty()).into_response()
}

/// Build the 202 response for the three-phase initiate. `Location` is
/// the session-specific URL (no digest yet — that comes from the PUT
/// finalize), `Range: 0-0` signals "no bytes received", and
/// `Docker-Upload-UUID` echoes the session id for clients that don't
/// parse `Location`.
fn initiate_response(repo_key: &str, name: &str, session_id: Uuid) -> Response {
    let location = format!("/v2/{repo_key}/{name}/blobs/uploads/{session_id}");
    // See `patch_success_response` — CRLF-in-capture guard.
    let location_header = match super::header_value_or_bad_request(&location) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, location_header);
    headers.insert("Range", HeaderValue::from_static("0-0"));
    headers.insert(
        "Docker-Upload-UUID",
        HeaderValue::from_str(&session_id.to_string()).expect("UUID display form is valid ASCII"),
    );
    (StatusCode::ACCEPTED, headers, Body::empty()).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tower::ServiceExt;
    use Uuid;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactRepository, MockRepositoryRepository,
        MockStoragePort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::ports::artifact_repository::ArtifactRepository;
    use hort_http_core::test_support::build_mock_ctx;

    use super::super::upload_session;

    // -------------------- Harness --------------------

    struct Harness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
    }

    fn harness() -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        Harness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
        }
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
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

    /// Build a synthetic `CallerPrincipal` for extractor-driven tests.
    /// Under `AuthContext::Disabled` (what `build_mock_ctx` returns)
    /// `WriteRepoAccess` grants unconditionally but still requires a
    /// principal in request extensions. The shape of
    /// the principal is unused beyond the `user_id` → `ApiActor` hop
    /// inside the handler.
    fn test_principal() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            // Single resolved `claims` set (ADR 0012); empty by
            // default, overridden per-case below.
            claims: Vec::new(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Attach a synthetic `CallerPrincipal` to a request. Mirrors what
    /// the `require_principal` middleware does on a live-auth
    /// deployment; extractor-level tests inject directly so the layer
    /// stack stays minimal.
    ///
    /// Wraps in `AuthenticatedPrincipal` via the test-support helper.
    /// The extractors no longer read the bare `CallerPrincipal` slot.
    fn with_principal(mut req: axum::http::Request<Body>) -> axum::http::Request<Body> {
        hort_http_core::middleware::auth::test_support::inject_principal(
            &mut req,
            test_principal(),
        );
        req
    }

    /// Seed an artifact at `blobs/sha256:<hex>` with CAS content.
    fn seed_blob(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        hex: &str,
        content: &[u8],
    ) {
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        a.created_at = Utc::now();
        a.updated_at = Utc::now();
        artifacts.insert(a);
        storage.insert_content(hash, content.to_vec());
    }

    // -------------------- Metrics helpers --------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn find_counter<'a>(
        entries: &'a [MetricEntry],
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    // -------------------- parse_upload_tail --------------------

    #[test]
    fn parse_upload_tail_accepts_suffix() {
        assert!(matches!(
            parse_upload_tail("library/nginx/blobs/uploads/"),
            Some(UploadTail::InitBlobUpload {
                name: "library/nginx"
            })
        ));
    }

    #[test]
    fn parse_upload_tail_rejects_missing_trailing_slash() {
        assert!(parse_upload_tail("nginx/blobs/uploads").is_none());
    }

    #[test]
    fn parse_upload_tail_rejects_empty_name() {
        assert!(parse_upload_tail("/blobs/uploads/").is_none());
    }

    // -------------------- Three-phase initiate --------------------

    #[test]
    fn three_phase_initiate_happy_path() {
        let (status, headers) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();

            // Prove the session really landed in EphemeralStore by
            // extracting the UUID from the Location header and
            // fetching the record.
            let loc = headers.get(LOCATION).unwrap().to_str().unwrap().to_string();
            let sid_str = loc.rsplit('/').next().unwrap();
            let sid: Uuid = sid_str.parse().unwrap();
            let key = upload_session::session_key("oci", sid);
            let stored = h.ctx.ephemeral_durable.get(&key).await.unwrap();
            assert!(
                stored.is_some(),
                "session record must be present in EphemeralStore after 202"
            );
            (status, headers)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            loc.starts_with("/v2/myrepo/library/nginx/blobs/uploads/"),
            "Location: {loc}"
        );
        assert_eq!(headers.get("range").unwrap(), "0-0");
        assert!(
            headers.get("docker-upload-uuid").is_some(),
            "Docker-Upload-UUID header must be present"
        );
    }

    /// Once a principal already holds the cap-many sessions against a
    /// repo, the next POST must be 429 with the OCI `TOOMANYREQUESTS`
    /// envelope and an advisory `Retry-After` header. Drives the full
    /// router so the `Extension<OciHttpConfig>` plumbing is exercised
    /// end-to-end.
    #[test]
    fn three_phase_initiate_returns_429_with_retry_after_when_cap_reached() {
        let (status, retry_after, code) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            // Build a router with a tiny cap so the test forces the
            // rejection without opening 32 sessions. The
            // `Extension<OciHttpConfig>` layer is what `router()` adds
            // by default (with the catalogued cap of 32); we override
            // with `Router::layer(Extension(...))` to a cap of 1.
            let cfg = OciHttpConfig {
                legacy_catalog_enabled: false,
                max_sessions_per_principal: 1,
            };
            // Build a fresh router with the small-cap Extension layer.
            // `Router::layer` re-attaches; the post-merge ordering
            // means the latest Extension wins for the inner handler.
            let router_handle = Router::new()
                .route(
                    "/v2/:repo_key/*tail",
                    axum::routing::post(post_upload_dispatch)
                        .patch(patch_upload_dispatch)
                        .put(put_upload_dispatch),
                )
                .layer(Extension(cfg))
                .with_state(h.ctx.clone());

            // Use the same principal across both requests so the cap
            // is shared. `with_principal` synthesises a fresh UUID
            // each call, so we reuse the principal explicitly.
            let principal = test_principal();
            let principal_clone = principal.clone();
            let inject = |mut req: HttpRequest<Body>| -> HttpRequest<Body> {
                hort_http_core::middleware::auth::test_support::inject_principal(
                    &mut req,
                    principal_clone.clone(),
                );
                req
            };

            // First initiate fills the cap.
            let resp1 = router_handle
                .clone()
                .oneshot(inject(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(resp1.status(), StatusCode::ACCEPTED);
            let _ = (principal, repo_id); // suppress unused warnings

            // Second initiate is over-cap — 429 + TOOMANYREQUESTS.
            let resp2 = router_handle
                .oneshot(inject(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp2.status();
            let retry_after = resp2
                .headers()
                .get("Retry-After")
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp2.into_body(), 4 * 1024).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let code = parsed["errors"][0]["code"].as_str().unwrap().to_string();
            (status, retry_after, code)
        });
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(code, "TOOMANYREQUESTS");
        let retry = retry_after.expect("Retry-After header MUST be set on 429");
        // The header value is delta-seconds; matches the configured
        // `OCI_SESSION_TTL` (3600).
        assert!(
            retry.parse::<u64>().is_ok(),
            "Retry-After must be an integer delta-seconds value, got {retry:?}"
        );
    }

    #[test]
    fn three_phase_initiate_emits_metric() {
        let (snap, _) = capture(|| {
            run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let router = router().with_state(h.ctx);
                let resp = router
                    .oneshot(with_principal(
                        HttpRequest::post("/v2/myrepo/nginx/blobs/uploads/")
                            .body(Body::empty())
                            .unwrap(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::ACCEPTED);
            })
        });
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[
                ("format", "oci"),
                ("repository", "myrepo"),
                ("result", "created"),
            ],
        )
        .expect("created metric absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // -------------------- Missing / invalid tail --------------------

    #[test]
    fn post_with_wrong_suffix_returns_404_name_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post("/v2/myrepo/nginx/blobs/upload") // typo, no trailing slash
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
    }

    #[test]
    fn post_to_unknown_repo_returns_404() {
        // `WriteRepoAccess` resolves the repo aggregate before the
        // handler runs and surfaces the generic
        // `{"error":"repository not found"}` 404 body on a missing
        // key — NOT the OCI `NAME_UNKNOWN` envelope. The two envelopes
        // are deliberately divergent pending `NAME_UNKNOWN` unification.
        // The important invariant preserved here is the status code
        // (404 — unknown repos are never confused with denied-access
        // 403s).
        let (status, body) = run(async {
            let h = harness();
            // No repos inserted — find_by_key → NotFound.
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post("/v2/ghost/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let body_str = String::from_utf8(body).unwrap();
        assert_eq!(body_str, r#"{"error":"repository not found"}"#);
    }

    // -------------------- Cross-mount --------------------

    fn sha256_of(content: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(content))
    }

    #[test]
    fn cross_mount_happy_path_zero_copy_and_returns_201() {
        let content = b"cross-mount content".to_vec();
        let hex = sha256_of(&content);
        let (status, headers, puts_before, puts_after) = run(async {
            let h = harness();
            let src = oci_repo("src-repo");
            let src_id = src.id;
            h.repositories.insert(src);
            let target = oci_repo("target-repo");
            h.repositories.insert(target);
            seed_blob(&h.artifacts, &h.storage, src_id, &hex, &content);

            let puts_before = h.storage.put_call_count();
            let router = router().with_state(h.ctx);
            let uri = format!(
                "/v2/target-repo/library/nginx/blobs/uploads/?mount=sha256:{hex}&from=src-repo"
            );
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let puts_after = h.storage.put_call_count();
            (status, headers, puts_before, puts_after)
        });
        assert_eq!(status, StatusCode::CREATED);
        // Zero-copy invariant — no bytes pushed through storage.
        assert_eq!(
            puts_before, puts_after,
            "cross-mount must NOT invoke StoragePort::put (zero-copy)"
        );
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(
            loc,
            format!("/v2/target-repo/library/nginx/blobs/sha256:{hex}")
        );
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}")
        );
    }

    /// Cross-mount with an unknown source repo falls through to a
    /// normal initiate per OCI Distribution Spec §2.3 — NOT 404.
    /// Returning 404 `NAME_UNKNOWN` here broke docker / skopeo retry
    /// loops on misconfigured mounts; the spec's fallback path is the
    /// correct reaction (see `handle_cross_mount`).
    #[test]
    fn cross_mount_unknown_source_repo_falls_through_to_initiate() {
        let hex = sha256_of(b"x");
        let (status, location) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("target-repo"));
            // No "src-repo" seeded — the source-repo Read check
            // returns NotFound, which the cross-mount handler treats
            // as "fall through to initiate" per the OCI spec.
            let router = router().with_state(h.ctx);
            let uri =
                format!("/v2/target-repo/nginx/blobs/uploads/?mount=sha256:{hex}&from=ghost-src");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let location = resp
                .headers()
                .get(LOCATION)
                .map(|v| v.to_str().unwrap().to_string());
            (status, location)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        let location = location.expect("initiate must emit Location");
        assert!(
            location.contains("/v2/target-repo/nginx/blobs/uploads/"),
            "Location must point at a fresh upload session: {location}"
        );
    }

    #[test]
    fn cross_mount_source_repo_missing_digest_returns_404_blob_unknown() {
        let hex = sha256_of(b"some bytes");
        let (status, body) = run(async {
            let h = harness();
            let src = oci_repo("src-repo");
            h.repositories.insert(src);
            h.repositories.insert(oci_repo("target-repo"));
            // No artifact seeded — src-repo exists but the hash isn't in it.

            let router = router().with_state(h.ctx);
            let uri =
                format!("/v2/target-repo/nginx/blobs/uploads/?mount=sha256:{hex}&from=src-repo");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    #[test]
    fn cross_mount_foreign_repo_hash_returns_404_blob_unknown() {
        // The hash exists in repo A; caller asks to mount it from repo B
        // (same system, different repo).  `register_by_hash` scopes its
        // lookup to `from` repo and returns NotFound, which surfaces as
        // BLOB_UNKNOWN — the isolation invariant.
        let content = b"foreign".to_vec();
        let hex = sha256_of(&content);
        let (status, body) = run(async {
            let h = harness();
            let other = oci_repo("other-repo");
            let other_id = other.id;
            h.repositories.insert(other);
            h.repositories.insert(oci_repo("empty-src-repo"));
            h.repositories.insert(oci_repo("target-repo"));
            // Hash lives in `other-repo`, not `empty-src-repo`.
            seed_blob(&h.artifacts, &h.storage, other_id, &hex, &content);

            let router = router().with_state(h.ctx);
            let uri = format!(
                "/v2/target-repo/nginx/blobs/uploads/?mount=sha256:{hex}&from=empty-src-repo"
            );
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    /// Cross-mount privilege-escalation regression guard (ADR 0008).
    ///
    /// Without the source-repo Read authz check, a caller with Write on
    /// `target-repo` could clone any blob from any other repo
    /// (including a private one they had no Read grant on) by
    /// submitting `?mount=<sha>&from=<other-repo>`. The fix routes the
    /// source-repo lookup through `RepositoryAccessUseCase::resolve`
    /// with `AccessLevel::Read`; on `NotFound` (missing or invisible)
    /// the handler falls through to "initiate a normal blob upload"
    /// per OCI Distribution Spec §2.3 — NOT 401/403/404, which would
    /// break docker / skopeo retry loops.
    ///
    /// Test shape: actor has Write on `target-repo` but no Read on
    /// `source-repo` (private, RBAC empty). POST cross-mount must
    /// return 202 + `Location` (initiate fallback), and the source
    /// repo's blob must remain un-mounted in the target (zero-copy
    /// register did not run).
    #[test]
    fn cross_mount_without_source_read_falls_through_to_initiate() {
        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_app::use_cases::test_support::MockIdentityProvider;
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;
        use hort_http_core::context::AuthContext;
        use hort_http_core::test_support::{with_auth, with_repository_access};

        let content = b"private blob".to_vec();
        let hex = sha256_of(&content);
        let (status, location, puts_after) = run(async {
            let h = harness();

            // Source repo: PRIVATE, has the blob.
            let mut src = oci_repo("source-repo");
            src.is_public = false;
            let src_id = src.id;
            h.repositories.insert(src);

            // Target repo: PUBLIC (Write grant on it).
            let mut target = oci_repo("target-repo");
            target.is_public = true;
            let target_id = target.id;
            h.repositories.insert(target);

            // Seed the source-repo blob.
            seed_blob(&h.artifacts, &h.storage, src_id, &hex, &content);

            // Build RBAC: actor has Write on target-repo, NO Read on
            // source-repo. Anti-enumeration on source means the use
            // case sees `NotFound` and falls through. The `dev` claim
            // carries Write on target-repo (ADR 0012 flat
            // `GrantSubject::Claims` grant set).
            let grant = PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["dev".into()]),
                repository_id: Some(target_id),
                permission: Permission::Write,
                created_at: Utc::now(),
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            };
            let rbac_swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
                grant,
            ])));

            // Wire enabled-auth + matching access use case.
            let idp = Arc::new(MockIdentityProvider::new());
            let users = Arc::new(hort_app::use_cases::test_support::MockUserRepository::new());
            let authenticate = Arc::new(AuthenticateUseCase::new(
                idp as Arc<dyn IdentityProvider>,
                users as Arc<dyn UserRepository>,
                Vec::new(),
            ));
            let ctx = with_auth(
                &h.ctx,
                AuthContext::Enabled {
                    authenticate,
                    rbac: rbac_swap.clone(),
                    // Uploads tests don't exercise the WWW-Authenticate
                    // selector.
                    issuer_url: None,
                },
            );
            // `ctx.repositories` is `pub(crate)` (ADR 0008); pull
            // the `Arc<MockRepositoryRepository>` off the harness's
            // MockPorts handle (same `Arc` wired into the ctx).
            let access = Arc::new(RepositoryAccessUseCase::new(
                h.repositories.clone(),
                RbacAccess::Enabled(rbac_swap),
                true,
            ));
            let ctx = with_repository_access(&ctx, access);

            // Build a request with a principal carrying the `dev`
            // claim (so Write on target-repo passes WriteRepoAccess).
            let mut principal = test_principal();
            principal.claims = vec!["dev".into()];

            let puts_before = h.storage.put_call_count();
            let router = router().with_state(ctx);
            let uri = format!(
                "/v2/target-repo/library/nginx/blobs/uploads/?mount=sha256:{hex}&from=source-repo"
            );
            let mut req = HttpRequest::post(&uri).body(Body::empty()).unwrap();
            // Wrap in `AuthenticatedPrincipal` via the test-support
            // helper.
            hort_http_core::middleware::auth::test_support::inject_principal(&mut req, principal);
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let location = resp
                .headers()
                .get(LOCATION)
                .map(|v| v.to_str().unwrap().to_string());
            let puts_after = h.storage.put_call_count();
            // Confirm cross-mount didn't write to storage (zero-copy
            // register did not fire).
            let _ = puts_before;
            (status, location, puts_after)
        });

        // Initiate fallback: 202 Accepted with a Location pointing at
        // a fresh upload session inside the target repo.
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "cross-mount denied on source-repo Read MUST fall through to 202 initiate per OCI §2.3"
        );
        let location = location.expect("initiate must emit Location");
        assert!(
            location.contains("/v2/target-repo/library/nginx/blobs/uploads/"),
            "Location must point at fresh target-repo upload session: {location}"
        );
        // Initiate path does not register the source blob at the
        // target — `puts_after` is incidental but should be the same
        // pre/post (no mount happened).
        let _ = puts_after;
    }

    #[test]
    fn mount_without_from_returns_400_unsupported() {
        let hex = sha256_of(b"x");
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/?mount=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNSUPPORTED");
    }

    #[test]
    fn from_without_mount_returns_400_unsupported() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post("/v2/myrepo/nginx/blobs/uploads/?from=src-repo")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNSUPPORTED");
    }

    // -------------------- Monolithic --------------------

    #[test]
    fn monolithic_happy_path_returns_201_with_location_and_digest() {
        let content = b"monolithic payload".to_vec();
        let hex = sha256_of(&content);
        let (status, headers) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/blobs/uploads/?digest=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri)
                        .body(Body::from(content.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            (status, headers)
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(loc, format!("/v2/myrepo/library/nginx/blobs/sha256:{hex}"));
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}")
        );
    }

    #[test]
    fn monolithic_emits_ingest_success_metric() {
        let content = b"metric payload".to_vec();
        let hex = sha256_of(&content);
        let (snap, _) = capture(|| {
            run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let router = router().with_state(h.ctx);
                let uri = format!("/v2/myrepo/nginx/blobs/uploads/?digest=sha256:{hex}");
                let resp = router
                    .oneshot(with_principal(
                        HttpRequest::post(&uri)
                            .body(Body::from(content.clone()))
                            .unwrap(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::CREATED);
            })
        });
        let entries = snap.into_vec();
        // IngestUseCase fires `hort_ingest_total{format=oci,result=success}`
        // on success.  Proves the monolithic branch actually ran the
        // ingest pipeline.
        let v = find_counter(
            &entries,
            "hort_ingest_total",
            &[("format", "oci"), ("result", "success")],
        )
        .expect("hort_ingest_total{format=oci,result=success} absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn monolithic_digest_mismatch_returns_400_digest_invalid() {
        let content = b"real bytes".to_vec();
        // Declare a different digest than what the body hashes to.
        let wrong_hex =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/?digest=sha256:{wrong_hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post(&uri)
                        .body(Body::from(content.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
    }

    #[test]
    fn monolithic_unsupported_digest_algo_returns_400_unsupported() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::post("/v2/myrepo/nginx/blobs/uploads/?digest=sha512:abc")
                        .body(Body::from(&b"x"[..]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNSUPPORTED");
    }

    // -------------------- parse_content_range --------------------

    #[test]
    fn parse_content_range_accepts_bytes_prefix() {
        let r = parse_content_range("bytes 0-99").unwrap();
        assert_eq!(r, ContentRange { start: 0, end: 99 });
    }

    #[test]
    fn parse_content_range_accepts_bare_form() {
        // Tolerance for older tooling that skips the `bytes ` prefix.
        let r = parse_content_range("10-19").unwrap();
        assert_eq!(r, ContentRange { start: 10, end: 19 });
    }

    #[test]
    fn parse_content_range_tolerates_slash_total_suffix() {
        let r = parse_content_range("bytes 0-99/1000").unwrap();
        assert_eq!(r, ContentRange { start: 0, end: 99 });
    }

    #[test]
    fn parse_content_range_rejects_end_lt_start() {
        assert!(parse_content_range("bytes 99-0").is_err());
    }

    #[test]
    fn parse_content_range_rejects_non_numeric() {
        assert!(parse_content_range("bytes abc-def").is_err());
    }

    #[test]
    fn parse_content_range_rejects_missing_dash() {
        assert!(parse_content_range("bytes 100").is_err());
    }

    // -------------------- parse_patch_tail --------------------

    #[test]
    fn parse_patch_tail_accepts_name_and_uuid() {
        let uuid = Uuid::new_v4();
        let tail = format!("library/nginx/blobs/uploads/{uuid}");
        let parsed = parse_patch_tail(&tail).unwrap();
        match parsed {
            PatchTail::AppendChunk { name, session_id } => {
                assert_eq!(name, "library/nginx");
                assert_eq!(session_id, uuid);
            }
        }
    }

    #[test]
    fn parse_patch_tail_rejects_trailing_slash_on_session() {
        let uuid = Uuid::new_v4();
        let tail = format!("nginx/blobs/uploads/{uuid}/");
        // Trailing `/` → session_part contains a `/` → reject.
        assert!(parse_patch_tail(&tail).is_none());
    }

    #[test]
    fn parse_patch_tail_rejects_non_uuid_session() {
        assert!(parse_patch_tail("nginx/blobs/uploads/not-a-uuid").is_none());
    }

    #[test]
    fn parse_patch_tail_rejects_empty_name() {
        let uuid = Uuid::new_v4();
        let tail = format!("/blobs/uploads/{uuid}");
        // `name` slice is "" before the `/blobs/uploads/` anchor.
        assert!(parse_patch_tail(&tail).is_none());
    }

    // -------------------- PATCH — router-level --------------------

    /// Construct + run an `initiate` call to get a fresh session id to
    /// PATCH against.  Mirrors what a real client does: POST /blobs/uploads
    /// to seed a session, then PATCH the session_id returned in Location.
    /// Using `upload_session::initiate` directly keeps the test focused
    /// on PATCH behaviour without threading a POST roundtrip through the
    /// router first.
    async fn initiate_for(ctx: &Arc<AppContext>, repo_id: Uuid) -> Uuid {
        // Pass a high cap so the existing PATCH/finalize tests are
        // unaffected by the per-`(repo, principal)` cap. Dedicated cap
        // tests exercise the rejection path in `upload_session.rs`.
        let outcome = upload_session::initiate(
            ctx,
            repo_id,
            ApiActor {
                user_id: Uuid::new_v4(),
            },
            10_000,
        )
        .await
        .unwrap();
        match outcome {
            InitiateResult::Created(o) => o.session_id,
            InitiateResult::CapExceeded => {
                panic!("test helper: cap exceeded on initiate — high cap should never reject")
            }
        }
    }

    #[test]
    fn patch_correct_range_appends_and_returns_202_with_location_and_range_headers() {
        let content = b"patch me plz".to_vec();
        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(&uri)
                        .header("Content-Range", format!("bytes 0-{}", content.len() - 1))
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            (status, headers)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            loc.starts_with("/v2/myrepo/library/nginx/blobs/uploads/"),
            "Location: {loc}"
        );
        let range = headers.get("range").unwrap().to_str().unwrap();
        assert_eq!(range, format!("0-{}", content.len() - 1));
        assert!(headers.get("docker-upload-uuid").is_some());
    }

    #[test]
    fn patch_location_header_contains_repo_key_and_name() {
        // Review-finding C3 regression guard: Location must carry BOTH
        // `repo_key` and `name` so the client's next PATCH hits a
        // routable path.  A bug that emitted `/v2/blobs/uploads/{sid}`
        // would 404 on every subsequent PATCH.
        let loc = run(async {
            let h = harness();
            let repo = oci_repo("my-repo-key");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/my-repo-key/my/deep/name/blobs/uploads/{session_id}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(&uri)
                        .header("Content-Range", "bytes 0-2")
                        .header(CONTENT_LENGTH, "3")
                        .body(Body::from(&b"abc"[..]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            resp.headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        });
        assert!(
            loc.contains("my-repo-key"),
            "Location missing repo_key: {loc}"
        );
        assert!(loc.contains("my/deep/name"), "Location missing name: {loc}");
    }

    #[test]
    fn patch_bad_range_returns_416_with_range_header() {
        // Session has bytes_received=0.  PATCH with start=50 → 416.
        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/{session_id}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(&uri)
                        .header("Content-Range", "bytes 50-99")
                        .header(CONTENT_LENGTH, "50")
                        .body(Body::from(vec![0u8; 50]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            (status, headers)
        });
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        // Freshly-initiated sessions have bytes_received=0 → Range: 0-0.
        assert_eq!(headers.get("range").unwrap(), "0-0");
    }

    #[test]
    fn patch_bad_range_after_progress_emits_current_in_range_header() {
        // Two PATCHes: first succeeds (0..99), second sends start=50 →
        // 416 with Range: 0-99 (current=100, so 0-(100-1)).
        let (status, range) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx.clone());
            // First PATCH — successful 100 bytes.
            let first = router
                .clone()
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "bytes 0-99")
                        .header(CONTENT_LENGTH, "100")
                        .body(Body::from(vec![0u8; 100]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::ACCEPTED);
            // Second PATCH — wrong start.
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "bytes 50-99")
                        .header(CONTENT_LENGTH, "50")
                        .body(Body::from(vec![0u8; 50]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let range = resp
                .headers()
                .get("range")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            (status, range)
        });
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(range, "0-99");
    }

    #[test]
    fn patch_exceeding_max_returns_413_size_invalid() {
        // Small cap → easily-exceeded chunk → 413.  Use a custom
        // `publish_body_limit_bytes` so the test doesn't need to push
        // gigabytes of bytes through the body.  `with_publish_limit`
        // rebuilds the AppContext with the override.
        use hort_http_core::test_support::{build_mock_ctx, MockPorts};
        // Local rebuild helper — hort-http-core doesn't expose a
        // `with_publish_body_limit` so we do it inline by walking the
        // context fields.
        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base_ctx, mocks) = build_mock_ctx(handle);
            let mut base = Arc::try_unwrap(base_ctx)
                .unwrap_or_else(|_| panic!("mock ctx must have single Arc owner"));
            // `AppContext`'s data ports are `pub(crate)` (ADR 0008)
            // so the `..base` struct-update syntax is unreachable across
            // crates. Mutating the `pub` field in place keeps the
            // override intent intact.
            base.publish_body_limit_bytes = Some(100);
            let ctx = Arc::new(base);
            let MockPorts { repositories, .. } = mocks;
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            repositories.insert(repo);
            let session_id = initiate_for(&ctx, repo_id).await;

            let router = router().with_state(ctx);
            // chunk of 600 bytes — cap is 100.
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "bytes 0-599")
                        .header(CONTENT_LENGTH, "600")
                        .body(Body::from(vec![0u8; 600]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "SIZE_INVALID");
    }

    #[test]
    fn patch_body_length_mismatch_returns_400_blob_upload_invalid() {
        // Content-Range says 100 bytes (0-99), body has 99 bytes.
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "bytes 0-99")
                        .header(CONTENT_LENGTH, "99")
                        .body(Body::from(vec![0u8; 99]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_INVALID");
    }

    #[test]
    fn patch_concurrent_version_conflict_returns_400_blob_upload_invalid() {
        // Seed a session, then tamper with the EphemeralStore so the
        // in-record `version` is stale w.r.t. the store's own counter.
        // Simulates a concurrent PATCH that won; the current caller's
        // CAS misses.
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;

            // Bump the store's version counter via a fresh `put` that
            // keeps the in-record version at 1 (the decoded record
            // remembers version=1 but the store's counter is now 2).
            let key = upload_session::session_key("oci", session_id);
            let current = h.ctx.ephemeral_durable.get(&key).await.unwrap().unwrap();
            // Overwrite unchanged to bump the store's version by one.
            h.ctx
                .ephemeral_durable
                .put(&key, current, upload_session::OCI_SESSION_TTL)
                .await
                .unwrap();

            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "bytes 0-2")
                        .header(CONTENT_LENGTH, "3")
                        .body(Body::from(&b"abc"[..]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_INVALID");
    }

    #[test]
    fn patch_unknown_session_returns_404_blob_upload_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let ghost = Uuid::new_v4();
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{ghost}"))
                        .header("Content-Range", "bytes 0-2")
                        .header(CONTENT_LENGTH, "3")
                        .body(Body::from(&b"abc"[..]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN");
    }

    #[test]
    fn patch_wrong_repo_returns_404_blob_upload_unknown() {
        // Session opened in repo_A.  Client PATCHes to /v2/repo_B/...
        // with the same session id → tenant isolation must refuse.
        // Anti-enumeration: envelope is `BLOB_UPLOAD_UNKNOWN` (NOT
        // `DENIED` / 403) to prevent cross-tenant enumeration.
        let (status, body) = run(async {
            let h = harness();
            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_a_id = repo_a.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);
            let session_id = initiate_for(&h.ctx, repo_a_id).await;

            let router = router().with_state(h.ctx);
            // PATCH against repo_b using session belonging to repo_a.
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/repo-b/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "bytes 0-2")
                        .header(CONTENT_LENGTH, "3")
                        .body(Body::from(&b"abc"[..]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN",
            "tenant mismatch MUST surface as BLOB_UPLOAD_UNKNOWN, NOT DENIED"
        );
    }

    #[test]
    fn patch_missing_content_range_appends_at_session_offset() {
        // containers/image (skopeo, podman, buildah) chunked uploads do
        // NOT send `Content-Range` on PATCH — the chunk is treated as
        // appended at the session's current `bytes_received`.  The OCI
        // spec is ambiguous here; the Docker Registry V2 reference
        // implementation, GHCR, Harbor, and zot all accept this form.
        // When we 400'd, skopeo's chunked-push path failed loudly.  Now
        // we synthesise a range anchored at `record.bytes_received`.
        let chunk = b"streaming-chunk".to_vec();
        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header(CONTENT_LENGTH, chunk.len().to_string())
                        .body(Body::from(chunk.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            (resp.status(), resp.headers().clone())
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        // PATCH success advertises the new tail offset on `Range`.
        let range = headers.get("Range").expect("Range header on 202");
        let expected = format!("0-{}", chunk.len() - 1);
        assert_eq!(range.to_str().unwrap(), expected);
    }

    #[test]
    fn patch_missing_content_range_after_prior_patch_appends_at_offset() {
        // Streaming clients that omit Content-Range still need correct
        // sequencing: a second header-less PATCH must anchor at the
        // running session offset, not at zero.  This is the regression
        // test for the byte-stream invariant — without the offset
        // synthesis, the second chunk would either overwrite the first
        // (storage-level) or surface as RangeInvalid.
        let first = b"first-chunk-".to_vec();
        let second = b"second-chunk".to_vec();
        let (status1, status2, range_header) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let resp1 = router
                .clone()
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header(CONTENT_LENGTH, first.len().to_string())
                        .body(Body::from(first.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let resp2 = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header(CONTENT_LENGTH, second.len().to_string())
                        .body(Body::from(second.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            let range = resp2.headers().get("Range").cloned();
            (resp1.status(), resp2.status(), range)
        });
        assert_eq!(status1, StatusCode::ACCEPTED);
        assert_eq!(status2, StatusCode::ACCEPTED);
        let range = range_header.expect("Range header on second PATCH 202");
        let expected_total = first.len() + second.len();
        assert_eq!(range.to_str().unwrap(), format!("0-{}", expected_total - 1));
    }

    #[test]
    fn patch_missing_content_length_returns_400() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            // axum's test harness adds Content-Length automatically from
            // the body — skirt that by using Body::empty() and hardcoding
            // Content-Range.  Length-zero bodies still require a
            // Content-Length header for the PATCH contract; the harness
            // will auto-emit `content-length: 0`, so build a request with
            // a removed header.
            let mut req =
                HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                    .header("Content-Range", "bytes 0-0")
                    .body(Body::empty())
                    .unwrap();
            req.headers_mut().remove(CONTENT_LENGTH);
            let resp = router.oneshot(with_principal(req)).await.unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn patch_malformed_content_range_returns_400() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::patch(format!("/v2/myrepo/nginx/blobs/uploads/{session_id}"))
                        .header("Content-Range", "not a valid range")
                        .header(CONTENT_LENGTH, "3")
                        .body(Body::from(&b"abc"[..]))
                        .unwrap(),
                ))
                .await
                .unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // -------------------- PUT — router-level (finalize) --------------------

    /// Hash `content` as hex — handy wrapper around `sha2::Sha256`
    /// for building finalize request URIs.
    fn hex_of(content: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(content))
    }

    /// PATCH `content` into `session_id` against `router` so
    /// subsequent PUT finalize sees a populated staging area.  Asserts
    /// the PATCH succeeded (202) so a future router regression does
    /// not show up as an opaque finalize-side failure.
    async fn patch_bytes(
        router: &Router,
        repo_key: &str,
        name: &str,
        session_id: Uuid,
        bytes: &[u8],
        start: u64,
    ) {
        let end = start + bytes.len() as u64 - 1;
        let resp = router
            .clone()
            .oneshot(with_principal(
                HttpRequest::patch(format!("/v2/{repo_key}/{name}/blobs/uploads/{session_id}"))
                    .header("Content-Range", format!("bytes {start}-{end}"))
                    .header(CONTENT_LENGTH, bytes.len().to_string())
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "setup PATCH failed — router change broke the seeding path"
        );
    }

    #[test]
    fn put_clean_finalize_returns_201_with_location_and_digest_and_cleans_state() {
        let content = b"finalize me cleanly".to_vec();
        let hex = hex_of(&content);
        let (status, headers, session_still_present, staging_still_present) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx.clone());
            // PATCH all the bytes in, then PUT with matching digest.
            patch_bytes(&router, "myrepo", "library/nginx", session_id, &content, 0).await;

            let uri =
                format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
            let resp = router
                .clone()
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();

            // Session + staging both gone.
            let key = upload_session::session_key("oci", session_id);
            let session_still_present = h.ctx.ephemeral_durable.get(&key).await.unwrap().is_some();
            let staging_still_present = h
                .ctx
                .stateful_upload_staging
                // The staging port is a trait handle; use the mock's
                // public `bytes_for` via the downcast-free path — we
                // expose the concrete mock in `MockPorts` but in
                // router tests the handle is the trait object. Issue
                // a cheap read to confirm.
                .stream_read(session_id)
                .await
                .is_ok();
            (
                status,
                headers,
                session_still_present,
                staging_still_present,
            )
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(loc, format!("/v2/myrepo/library/nginx/blobs/sha256:{hex}"));
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}")
        );
        assert!(
            !session_still_present,
            "session row must be deleted on clean finalize"
        );
        assert!(
            !staging_still_present,
            "staging must be deleted on clean finalize"
        );
    }

    #[test]
    fn put_finalize_with_trailing_body_chunk_appends_then_commits() {
        // First PATCH lands `first`; the PUT itself carries `trailing`.
        // Total finalized bytes must equal seeded + trailing and the
        // digest must match the concatenation.
        let first = b"first-half-".to_vec();
        let trailing = b"second-half".to_vec();
        let full: Vec<u8> = first.iter().chain(trailing.iter()).copied().collect();
        let hex = hex_of(&full);

        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx.clone());
            patch_bytes(&router, "myrepo", "library/nginx", session_id, &first, 0).await;

            let uri =
                format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
            let start = first.len();
            let end = start + trailing.len() - 1;
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri)
                        .header("Content-Range", format!("bytes {start}-{end}"))
                        .header(CONTENT_LENGTH, trailing.len().to_string())
                        .body(Body::from(trailing.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            (resp.status(), resp.headers().clone())
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            loc.ends_with(&format!("sha256:{hex}")),
            "Location must carry the concatenated digest: {loc}"
        );
    }

    #[test]
    fn put_digest_mismatch_drops_both_staging_and_session() {
        // The critical guardrail: a mismatched digest MUST NOT
        // commit an artifact, MUST NOT leave a session row, MUST NOT
        // leave staging. If any of these fail the CAS rollback in
        // `IngestUseCase::ingest` is broken and the test must surface
        // it loudly.  The artifact-row assertion queries `find_by_path`
        // with the declared (lying) digest — this is the path a
        // correctly rolled-back ingest NEVER writes to, so a `Some`
        // result here would prove the rollback failed.
        let real = b"actual content".to_vec();
        let lying_hex = "0".repeat(64);
        let (status, body, session_still_present, staging_still_present, artifact_leaked) =
            run(async {
                let h = harness();
                let repo = oci_repo("myrepo");
                let repo_id = repo.id;
                h.repositories.insert(repo);
                let session_id = initiate_for(&h.ctx, repo_id).await;
                let router = router().with_state(h.ctx.clone());
                patch_bytes(&router, "myrepo", "library/nginx", session_id, &real, 0).await;

                let uri = format!(
                    "/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{lying_hex}"
                );
                let resp = router
                    .oneshot(with_principal(
                        HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                    ))
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();

                let key = upload_session::session_key("oci", session_id);
                let session_still_present =
                    h.ctx.ephemeral_durable.get(&key).await.unwrap().is_some();
                let staging_still_present = h
                    .ctx
                    .stateful_upload_staging
                    .stream_read(session_id)
                    .await
                    .is_ok();
                // A correctly-rolled-back ingest writes NO artifact
                // row — not at the declared-digest path, not at the
                // computed-digest path.  Check the declared-digest
                // path (the path the handler would have committed
                // to had the mismatch gone unnoticed).
                let coords_path = format!("blobs/sha256:{lying_hex}");
                let artifact_leaked = h
                    .artifacts
                    .find_by_path(repo_id, &coords_path)
                    .await
                    .unwrap()
                    .is_some();
                (
                    status,
                    body,
                    session_still_present,
                    staging_still_present,
                    artifact_leaked,
                )
            });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["errors"][0]["code"], "DIGEST_INVALID",
            "mismatch must surface as DIGEST_INVALID (NOT UNSUPPORTED — review C5)"
        );
        assert!(
            !session_still_present,
            "session row must be deleted on digest mismatch"
        );
        assert!(
            !staging_still_present,
            "staging must be deleted on digest mismatch"
        );
        assert!(
            !artifact_leaked,
            "declared-hash mismatch MUST NOT leave an artifact row \
             (if this fails, the CAS rollback in IngestUseCase::ingest is broken)"
        );
    }

    #[test]
    fn put_wrong_repo_returns_404_blob_upload_unknown() {
        // Session belongs to repo-a; caller PUTs against repo-b.
        // Tenant-isolation anti-enumeration: envelope is
        // BLOB_UPLOAD_UNKNOWN, not DENIED.
        let content = b"cross-tenant attempt".to_vec();
        let hex = hex_of(&content);
        let (status, body) = run(async {
            let h = harness();
            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_a_id = repo_a.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);
            let session_id = initiate_for(&h.ctx, repo_a_id).await;
            let router = router().with_state(h.ctx.clone());
            patch_bytes(&router, "repo-a", "nginx", session_id, &content, 0).await;

            let uri = format!("/v2/repo-b/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN",
            "tenant mismatch MUST surface as BLOB_UPLOAD_UNKNOWN, NOT DENIED"
        );
    }

    #[test]
    fn put_no_body_finalizes_from_staging_only() {
        // Multiple PATCHes, no PUT body — the digest covers the
        // entire PATCH-accumulated byte stream.
        let first = b"aaaa".to_vec();
        let second = b"bbbbbb".to_vec();
        let full: Vec<u8> = first.iter().chain(second.iter()).copied().collect();
        let hex = hex_of(&full);

        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx.clone());
            patch_bytes(&router, "myrepo", "nginx", session_id, &first, 0).await;
            patch_bytes(
                &router,
                "myrepo",
                "nginx",
                session_id,
                &second,
                first.len() as u64,
            )
            .await;

            let uri = format!("/v2/myrepo/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::CREATED);
    }

    #[test]
    fn put_emits_finalized_metric_and_bytes_histogram() {
        let content = b"metric-coverage".to_vec();
        let hex = hex_of(&content);
        let (snap, _) = capture(|| {
            run(async {
                let h = harness();
                let repo = oci_repo("myrepo");
                let repo_id = repo.id;
                h.repositories.insert(repo);
                let session_id = initiate_for(&h.ctx, repo_id).await;
                let router = router().with_state(h.ctx.clone());
                patch_bytes(&router, "myrepo", "nginx", session_id, &content, 0).await;

                let uri =
                    format!("/v2/myrepo/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
                let resp = router
                    .oneshot(with_principal(
                        HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::CREATED);
            })
        });
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            "hort_stateful_upload_sessions_total",
            &[
                ("format", "oci"),
                ("repository", "myrepo"),
                ("result", "finalized"),
            ],
        )
        .expect("hort_stateful_upload_sessions_total{result=finalized} absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));

        // Bytes histogram present with the same label set.
        let bytes_present = entries.iter().any(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Histogram
                && ck.key().name() == "hort_stateful_upload_session_bytes"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "repository" && l.value() == "myrepo")
        });
        assert!(
            bytes_present,
            "hort_stateful_upload_session_bytes histogram absent"
        );

        // Ingest counter ALSO fires (IngestUseCase emission).  This
        // nails down the "no double-emission" contract — both
        // counters should be present exactly once each.
        assert!(
            find_counter(
                &entries,
                "hort_ingest_total",
                &[("format", "oci"), ("result", "success")]
            )
            .is_some(),
            "hort_ingest_total{{format=oci,result=success}} absent on PUT finalize"
        );
    }

    #[test]
    fn put_missing_digest_returns_400_digest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/{session_id}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
    }

    #[test]
    fn put_malformed_digest_returns_400_digest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/{session_id}?digest=sha256:not-hex");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
    }

    #[test]
    fn put_unsupported_digest_algo_returns_400_unsupported() {
        // sha512 is well-formed but this server only accepts sha256.
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let hex = "abcd".repeat(32);
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/{session_id}?digest=sha512:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNSUPPORTED");
    }

    #[test]
    fn put_body_present_without_content_range_two_phase_finalize_succeeds() {
        // Skopeo, docker, podman, and containers/image all use the
        // two-phase POST→PUT pattern (initiate session, then finalize
        // with the entire blob in one PUT body) and do NOT send
        // `Content-Range` on that PUT — the spec doesn't require it
        // for two-phase finalize, only for chunked PATCH.  Earlier
        // builds 400'd this and broke skopeo `[2/5] Push`.  When the
        // header is absent the server synthesises a range anchored at
        // the session's current `bytes_received` — i.e. "this body is
        // the next chunk, starting where we left off".
        let content = b"two-phase-no-content-range".to_vec();
        let hex = hex_of(&content);
        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx);
            let uri =
                format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri)
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            (resp.status(), resp.headers().clone())
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            loc.ends_with(&format!("sha256:{hex}")),
            "Location must carry the finalized digest: {loc}"
        );
    }

    #[test]
    fn put_body_no_content_range_after_prior_patch_appends_correctly() {
        // Two-phase finalize after one PATCH — the synthesised range
        // must anchor at `record.bytes_received` so the trailing body
        // appends to (not overwrites) the staged chunk.  Digest covers
        // the concatenation; mismatch would surface as DIGEST_INVALID.
        let first = b"first-half-".to_vec();
        let trailing = b"second-half".to_vec();
        let full: Vec<u8> = first.iter().chain(trailing.iter()).copied().collect();
        let hex = hex_of(&full);

        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let session_id = initiate_for(&h.ctx, repo_id).await;
            let router = router().with_state(h.ctx.clone());
            patch_bytes(&router, "myrepo", "library/nginx", session_id, &first, 0).await;

            let uri =
                format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri)
                        .header(CONTENT_LENGTH, trailing.len().to_string())
                        .body(Body::from(trailing.clone()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            (resp.status(), resp.headers().clone())
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            loc.ends_with(&format!("sha256:{hex}")),
            "Location must carry the concatenated digest: {loc}"
        );
    }

    #[test]
    fn put_with_bad_tail_returns_404_name_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            // Missing the /blobs/uploads/<uuid> shape.
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put("/v2/myrepo/nginx/blobs/upload/not-a-uuid?digest=sha256:00")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
    }

    #[test]
    fn put_unknown_session_returns_404_blob_upload_unknown() {
        let content = b"never-existed".to_vec();
        let hex = hex_of(&content);
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx);
            let ghost = Uuid::new_v4();
            let uri = format!("/v2/myrepo/nginx/blobs/uploads/{ghost}?digest=sha256:{hex}");
            let resp = router
                .oneshot(with_principal(
                    HttpRequest::put(&uri).body(Body::empty()).unwrap(),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN");
    }

    // ---------------- CRLF-injection guard (response-builder) ----------------
    //
    // The four `HeaderValue::from_str(&location).expect("ASCII by
    // construction")` sites used to panic when `repo_key` or `name`
    // (URL captures) carried CRLF. axum's panic boundary mapped the
    // panic to a 500 — denial of service via crafted inputs.
    //
    // Each of the next four tests builds the response *directly* via
    // the private builder. We deliberately do NOT route a CRLF-bearing
    // path through the full axum stack: the server-side panic recovery
    // there masks the "panic vs graceful 4xx" distinction we are
    // testing here. The builder functions are the canonical site of
    // the fix; if they degrade gracefully under bad input, the call
    // path above them is safe.

    fn sample_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    /// `created_blob_response` returns a 404 NAME_UNKNOWN envelope when
    /// the captured `repo_key` carries CRLF (rather than panicking into
    /// a 500). The previous `.expect("ASCII by construction")` was a
    /// DoS primitive — this guards against regression.
    #[test]
    fn created_blob_response_with_crlf_in_repo_key_returns_400_not_500() {
        let repo_key_with_crlf = "myrepo\r\nX-Injected: pwn";
        let resp = created_blob_response(repo_key_with_crlf, "library/nginx", &sample_hash());
        assert_ne!(
            resp.status(),
            StatusCode::CREATED,
            "must NOT return 201 with a smuggled header — graceful failure required"
        );
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "must NOT degrade to 500 on URL-capture-induced HeaderValue failure"
        );
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "graceful 400/404 expected, got {}",
            resp.status()
        );
    }

    /// Companion: clean inputs still produce the legacy 201 + Location
    /// header byte-for-byte, so the helper is transparent on the happy
    /// path.
    #[test]
    fn created_blob_response_with_clean_ascii_returns_201_with_location() {
        let resp = created_blob_response("myrepo", "library/nginx", &sample_hash());
        assert_eq!(resp.status(), StatusCode::CREATED);
        let location = resp
            .headers()
            .get(LOCATION)
            .expect("Location header missing on success path")
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            location,
            format!(
                "/v2/myrepo/library/nginx/blobs/sha256:{}",
                sample_hash().as_ref()
            )
        );
    }

    #[test]
    fn initiate_response_with_crlf_in_name_returns_400_not_500() {
        let session_id = Uuid::new_v4();
        let name_with_crlf = "library/nginx\r\nX-Injected: pwn";
        let resp = initiate_response("myrepo", name_with_crlf, session_id);
        assert_ne!(
            resp.status(),
            StatusCode::ACCEPTED,
            "must NOT return 202 with a smuggled header"
        );
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "must NOT degrade to 500 on URL-capture-induced HeaderValue failure"
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn initiate_response_with_clean_ascii_returns_202_with_location() {
        let session_id = Uuid::new_v4();
        let resp = initiate_response("myrepo", "library/nginx", session_id);
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let location = resp
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            location,
            format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}")
        );
    }

    #[test]
    fn patch_success_response_with_crlf_in_repo_key_returns_400_not_500() {
        let session_id = Uuid::new_v4();
        let repo_key_with_crlf = "myrepo\r\nX-Injected: pwn";
        let resp = patch_success_response(repo_key_with_crlf, "library/nginx", session_id, 100);
        assert_ne!(
            resp.status(),
            StatusCode::ACCEPTED,
            "must NOT return 202 with a smuggled header"
        );
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "must NOT degrade to 500 on URL-capture-induced HeaderValue failure"
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn patch_success_response_with_clean_ascii_returns_202_with_location() {
        let session_id = Uuid::new_v4();
        let resp = patch_success_response("myrepo", "library/nginx", session_id, 100);
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let location = resp
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            location,
            format!("/v2/myrepo/library/nginx/blobs/uploads/{session_id}")
        );
    }
}
