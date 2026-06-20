//! PyPI Simple Repository API (PEP 503) handlers.
//!
//! Routes:
//! - `POST /{repo_key}/` — twine upload
//! - `GET /{repo_key}/simple/` — root index
//! - `GET /{repo_key}/simple/{project}/` — package index
//! - `GET /{repo_key}/simple/{project}/{filename}` — download

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::Utc;

use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{RepositoryFormat, RepositoryType};
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::ArtifactCoords;
use hort_formats::pypi::PyPiFormatHandler;

// Module is `pub` so the `hort-formats-upstream` composition crate
// can call `simple_index::fetch_raw_with_cache`. Every other path
// through this module stays internal (the per-helper rustdoc declares
// the supported callers); the visibility-promotion exists only for
// that one composition seam. See `simple_index::fetch_raw_with_cache`
// for the full warning.
pub mod simple_index;
// Verified pull-through orchestrator. Wired from the `download`
// route's Proxy-cache-miss branch; no public re-export is needed.
// See `docs/architecture/how-to/pypi-pull-through.md`.
pub(crate) mod upstream_pull;
// PEP 658 `.metadata` endpoint (PEP 658 + PEP 491).
// Dispatches by `RepositoryType` (Hosted/Staging/Virtual → use case;
// Proxy → strategy-2 full-wheel pull-through then serve).
// `download` strips the `.metadata` suffix and routes here.
pub(crate) mod metadata_endpoint;

// Unified Source → Filter → Builder pipeline for the PyPI simple
// index (PEP 503 / PEP 691). `index_source` defines the
// per-format-internal `IndexSource` trait + `HostedPypiSource` /
// `ProxyPypiSource` impls; `serve` is the unified handler dispatch
// hop. See `docs/architecture/how-to/pypi-pull-through.md` and
// `docs/architecture/explanation/index-construction.md`.
pub(crate) mod index_source;
pub(crate) mod serve;
// PEP 503 HTML simple-index projector (ADR 0026).
// The serve path caches a representation-independent
// `PypiSimpleIndexProjection` for both arms; the JSON arm uses
// `hort_formats::pypi::projection::PypiSimpleIndexProjector`, the HTML arm
// uses this buffered-regex projector (PyPI bodies are ~110 KB — no
// streaming HTML parser).
pub(crate) mod html_projection;

use hort_http_core::authz::write::{reject_write_to_virtual, resolve_actor_user_id};
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::limits::{BoundedPath, DEFAULT_PUBLISH_BODY_LIMIT, MAX_MULTIPART_FIELDS};
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

/// Build the PyPI route tree with the default publish body limit.
/// Mount under `/pypi` in the top-level router.
///
/// The default ([`DEFAULT_PUBLISH_BODY_LIMIT`] — 300 MiB) is the shared
/// ceiling applied to every PyPI publish route. Operators can override
/// it via `HORT_PUBLISH_BODY_MAX_SIZE`; the override is threaded
/// through `AppContext` and reaches this builder via
/// [`pypi_routes_with_publish_limit`] in `router.rs::build_router`.
pub fn pypi_routes() -> Router<Arc<AppContext>> {
    pypi_routes_with_publish_limit(DEFAULT_PUBLISH_BODY_LIMIT)
}

/// Build the PyPI route tree with a custom publish body limit (in bytes).
///
/// `router.rs::build_router` calls this with the effective limit
/// (`HORT_PUBLISH_BODY_MAX_SIZE` or the default). Tests also use it
/// directly to exercise the body-limit reject path without sending
/// hundreds of megabytes.
///
/// The body-limit layer is attached to the `POST /:repo_key/` publish
/// route only — GET routes carry no body, so layering there would be
/// no-op noise. Mirrors the Cargo builder's route-scoped attachment.
pub fn pypi_routes_with_publish_limit(limit: usize) -> Router<Arc<AppContext>> {
    Router::new()
        .route(
            "/:repo_key/",
            post(upload).layer(DefaultBodyLimit::max(limit)),
        )
        .route("/:repo_key/simple/", get(simple_root))
        .route("/:repo_key/simple/:project/", get(simple_project))
        .route("/:repo_key/simple/:project/:filename", get(download))
}

// ---------------------------------------------------------------------------
// POST /{repo_key}/ — twine upload
// ---------------------------------------------------------------------------

async fn upload(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath(repo_key): BoundedPath<String>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    // Path-parameter length cap is enforced by `BoundedPath` before this
    // handler body runs — see `hort_http_core::limits::BoundedPath`.
    //
    // Resolve the repo via the visibility-aware use case (ADR 0008).
    // `AccessLevel::Read` gives anti-enumeration: an anonymous /
    // unauthorised principal probing for private-repo existence sees the
    // same 404 envelope as a missing repo. The subsequent
    // `resolve_actor_user_id` call below keeps enforcing the Write authz
    // gate with its existing 403 + `{"error":"insufficient permissions"}`
    // body, so the deny envelope on the WRITE permission stays verbatim.
    // Unwrap the `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`
    // for the use-case API.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    let repo = ctx
        .repository_access_use_case
        .resolve(&repo_key, actor, AccessLevel::Read)
        .await?;

    // Gate write on authorization. Under `AuthContext::Disabled` the auth
    // middleware is not attached, no principal is in extensions, and the
    // placeholder `Uuid::nil()` actor flows through unchanged. Under
    // `Enabled` the `require_principal` layer MUST have run — we reject
    // with a 500-shaped response if the principal is missing, since that
    // is always a router-wiring bug, not a request-shape bug.
    //
    // Carried-forward — `Uuid::nil()` actor cluster (2026-05-30):
    // pre-verified-authz composition. Sweep when authz boundary cleanup
    // lands.
    //
    // The helper returns a pre-shaped `Response` on reject so the deny
    // body stays `{"error":"insufficient permissions"}` verbatim — see
    // `resolve_actor_user_id`'s `AuthzReject` docs for why a custom
    // response beats the default `DomainError::Forbidden` mapping.
    let actor_user_id = match resolve_actor_user_id(&ctx, principal, repo.id) {
        Ok(id) => id,
        Err(response) => return Ok(*response),
    };

    // Read-only aggregator (ADR 0031): reject an upload to a `type: virtual`
    // repo, which would otherwise fall into the hosted arm below and write
    // the virtual's own (never-served) store. After the authz gate so a
    // caller without Write still sees the stable 403, not a repo-type oracle.
    reject_write_to_virtual(&repo)?;

    let handler = PyPiFormatHandler;

    let mut pkg_name: Option<String> = None;
    let mut pkg_version: Option<String> = None;
    let mut file_content: Option<bytes::Bytes> = None;
    let mut file_name: Option<String> = None;
    // The Warehouse/PyPI legacy upload form's `sha256_digest` field
    // (hex-encoded SHA-256; twine sends it alongside `md5_digest`).
    // Captured as a verification target for the verified-ingest framework,
    // NOT swept into `metadata_fields` as opaque PKG-INFO. `md5_digest`
    // stays in the catch-all (md5 is not a security primitive here —
    // out of scope).
    let mut sha256_digest: Option<String> = None;
    let mut metadata_fields = serde_json::Map::new();

    // Cap the number of multipart fields so a malicious client can't stall
    // the handler with thousands of empty parts. Counted per iteration of
    // `next_field()`; the reject body `{"error":"too many multipart
    // fields"}` is load-bearing — native clients may match on it.
    // `warn!` on reject because this is client misbehaviour, not
    // infrastructure failure.
    let mut field_count: usize = 0;

    while let Some(field) = match multipart.next_field().await {
        Ok(next) => next,
        // `MultipartError` already carries the correct status code
        // (notably `413` when the body exceeded `DefaultBodyLimit::max`
        // (the field-cap enforcement path). Collapsing every multipart error to a
        // generic 400 would swallow the 413 path the design requires,
        // so route through `IntoResponse` here and let the extractor
        // decide the final shape.
        Err(err) => return Ok(err.into_response()),
    } {
        field_count += 1;
        if field_count > MAX_MULTIPART_FIELDS {
            tracing::warn!(
                field_count_observed = %field_count,
                "multipart upload exceeded field cap"
            );
            return Ok(too_many_multipart_fields_response());
        }
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "name" => {
                pkg_name = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| validation_error(&format!("invalid field: {e}")))?,
                );
            }
            "version" => {
                pkg_version = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| validation_error(&format!("invalid field: {e}")))?,
                );
            }
            "content" => {
                file_name = field.file_name().map(str::to_string);
                file_content = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| validation_error(&format!("invalid file: {e}")))?,
                );
            }
            "sha256_digest" => {
                // Verification target (hex SHA-256). A dedicated branch
                // so it does NOT also land in `metadata_fields` (mirrors
                // the `name`/`version`/`content` branches). Required at
                // the presence check below; the value is parsed to a
                // `ContentHash` and routed through `ingest_verified`.
                sha256_digest = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| validation_error(&format!("invalid field: {e}")))?,
                );
            }
            ":action" => {
                // Ignore — twine sends "file_upload"
                let _ = field.text().await;
            }
            _ => {
                if let Ok(text) = field.text().await {
                    metadata_fields.insert(name, serde_json::Value::String(text));
                }
            }
        }
    }

    let pkg_name = pkg_name.ok_or_else(|| validation_error("missing field: name"))?;
    let pkg_version = pkg_version.ok_or_else(|| validation_error("missing field: version"))?;
    let file_content = file_content.ok_or_else(|| validation_error("missing field: content"))?;

    // Strict publish-side validation of every attacker-controlled multipart
    // field BEFORE any storage path is constructed, any database row is
    // built, or `IngestUseCase::ingest_verified` is awaited. The download
    // path (`PyPiFormatHandler::parse_download_path`) has called
    // `validate_pep_503_name` / `validate_pypi_filename` for some time;
    // this site closes the publish-side asymmetry the 2026-05-03 audit
    // flagged.
    //
    // `validate_pypi_version` — a permissive PEP 440 charset gate (not a
    // full PEP 440 parser; see its doc comment for why the simplification
    // is acceptable here). It catches CRLF / null-byte / traversal-marker
    // / oversize payloads that would otherwise survive into the stored row
    // and emitted index HTML.
    //
    // The previous `validate_publish_filename` helper is gone —
    // `validate_pypi_filename` covers and exceeds it (charset allowlist,
    // byte cap, control-byte rejection, no path separators).
    //
    // Validators run on pre-normalisation input — normalisation is for
    // downstream consumption (`handler.normalize_name`), not a security
    // boundary. Errors map to `DomainError::Validation` → 400 via the
    // existing `validation_error` helper; the structured
    // `pypi.<field>` shape never echoes the offending input.
    hort_formats::pypi::validate_pep_503_name(&pkg_name)
        .map_err(|e| ApiError::from(hort_app::error::AppError::Domain(e)))?;
    hort_formats::pypi::validate_pypi_version(&pkg_version)
        .map_err(|e| ApiError::from(hort_app::error::AppError::Domain(e)))?;

    // `file_name` comes from the multipart `content` field's
    // Content-Disposition `filename=…` attribute — fully attacker-controlled.
    // It ends up in `Artifact.path` and in emitted simple-index HTML.
    // Twine always sends a slash-free
    // `{name}-{version}.tar.gz` / `.whl`, so legitimate uploads are
    // unaffected. The auto-generated fallback (used when the field
    // was absent) is derived from normalised `pkg_name` + already-
    // validated `pkg_version` and is safe by construction; we still
    // run it through the validator so a single source of truth
    // covers both branches.
    let file_name = file_name.unwrap_or_else(|| {
        format!(
            "{}-{}.tar.gz",
            handler.normalize_name(&pkg_name),
            pkg_version
        )
    });
    hort_formats::pypi::validate_pypi_filename(&file_name)
        .map_err(|e| ApiError::from(hort_app::error::AppError::Domain(e)))?;

    // Require the client-declared `sha256_digest` and route the upload
    // through the verified-ingest framework (ADR 0006). The maintainer
    // chose the stronger supply-chain stance: a direct upload that omits
    // the digest is rejected. This check runs AFTER the name/version/
    // content presence + pep503/version/filename validators so those
    // negative paths keep hitting THEIR error first, and BEFORE
    // `coords`/ingest so a missing or malformed digest fails closed before
    // any storage path is touched.
    let sha256_digest =
        sha256_digest.ok_or_else(|| validation_error("missing field: sha256_digest"))?;
    let upstream_digest: hort_domain::types::ContentHash = sha256_digest
        .parse()
        .map_err(|e| validation_error(&format!("invalid field: sha256_digest: {e}")))?;

    let normalized = handler.normalize_name(&pkg_name);
    let path = format!("simple/{normalized}/{file_name}");

    let coords = ArtifactCoords {
        name: normalized,
        // Raw name as the client supplied it on the `name` multipart field,
        // before PEP 503 normalisation. Drift-resilience safety net.
        name_as_published: pkg_name.clone(),
        version: Some(pkg_version),
        path,
        format: RepositoryFormat::Pypi,
        // ArtifactCoords.metadata is the opaque output of
        // `FormatHandler::parse_download_path` — upload-payload metadata
        // now flows via `IngestRequest.payload_metadata`.
        metadata: serde_json::Value::Null,
    };

    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(file_content));

    // Actor resolved above from the `CallerPrincipal` extension (Enabled)
    // or the `Uuid::nil()` placeholder (Disabled — pre-authz composition).
    //
    // Carried-forward — `Uuid::nil()` actor cluster (2026-05-30):
    // pre-verified-authz composition. Sweep when authz boundary cleanup
    // lands.
    let actor = ApiActor {
        user_id: actor_user_id,
    };

    // Verified direct upload. The client-declared `sha256_digest` is the
    // verification target; `ingest_verified` rehashes the streamed bytes
    // and compares against it, then appends `ChecksumVerified` atomically
    // with `ArtifactIngested`. On a mismatch it rolls back the CAS blob,
    // appends `ChecksumMismatch` on the repository stream, and returns
    // `DomainError::Conflict` (→ HTTP 409 via the `?`).
    //
    // `ProtocolNative` (NOT `UpstreamPublished`): the digest is embedded
    // in the request itself by the client, which is exactly that variant's
    // definition. `UpstreamPublished` is pull-through-only (direct upload
    // does not fetch metadata and does not produce this variant), so using
    // it for a direct upload would violate its documented contract. For
    // sha256 both variants route to `ingest_verified_sha256` and are
    // functionally identical, so `ProtocolNative` is the contract-correct
    // choice.
    ctx.ingest_use_case
        .ingest_verified(
            hort_app::use_cases::ingest_use_case::VerifiedIngestRequest::ProtocolNative {
                repository_id: repo.id,
                coords,
                content_type: "application/octet-stream".into(),
                actor,
                // Multipart harvest lands here so the ArtifactIngested event
                // and the `artifact_metadata` projection row carry the PyPI
                // METADATA fields. Wrapped under `pkg_info` so the top level
                // of `payload_metadata` stays reserved for sibling namespaces
                // (scan findings, registry annotations, upstream manifests)
                // — flat would lock us into a subset of nested. The read
                // path (simple index data-requires-python) traverses the
                // same path.
                payload_metadata: serde_json::json!({ "pkg_info": metadata_fields }),
                upstream_digest,
                // Direct upload carries no upstream publish hint.
                upstream_published_at: None,
                // Direct uploads ALWAYS pass `false` — there is no serving
                // mapping, so the quarantine-anchor stays `ingested_at`.
                trust_upstream_publish_time: false,
            },
            stream,
            // `handler` (instantiated at the top of this function for
            // `normalize_name`) is reused here so the ingest cap check
            // consults the exact same `FormatHandler` instance — one
            // source of truth for the request's format behaviour.
            &handler,
        )
        .await?;

    Ok(StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/simple/ — PEP 503 root index
// ---------------------------------------------------------------------------

async fn simple_root(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath(repo_key): BoundedPath<String>,
    // GET reads the `Option<AuthenticatedPrincipal>` slot that
    // `extract_optional_principal` writes; the outer `Option` tolerates the
    // no-auth-layer test case → anonymous.
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap before this
    // handler body runs.
    //
    // `list_distinct_names_visible` resolves the repo via
    // `RepositoryAccessUseCase::resolve(_, actor, Read)` first, then
    // returns the package list (ADR 0008). Repo missing and repo invisible
    // to actor collapse to the same `NotFound` envelope (anti-enumeration).
    // The PyPI root simple index is a top-tier enumeration target — it
    // returns the entire package roster of the repo.
    // Unwrap the `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`
    // for the use-case API.
    let actor = principal
        .as_deref()
        .and_then(|opt| opt.as_ref())
        .map(AuthenticatedPrincipal::as_caller);
    let (_repo, names_list) = ctx
        .artifact_use_case
        .list_distinct_names_visible(&repo_key, actor)
        .await?;
    // When the underlying paginated read hit `LIMIT_LIST_MAX_ITEMS`, emit a
    // `Warning: 299` header so SIEM tooling can pick up the truncation.
    // PEP 503 has no protocol-level pagination on `/simple/`, so the body
    // is the best-effort prefix of distinct names; pip / other consumers
    // typically only look up specific projects, not enumerate the index.
    let truncated = names_list.truncated;
    let names = names_list.items;

    let mut html = String::from(
        "<!DOCTYPE html>\n<html>\n<head>\
         <meta name=\"pypi:repository-version\" content=\"1.0\"/>\
         <title>Simple Index</title></head>\n<body>\n",
    );

    for name in &names {
        html.push_str(&format!(
            "<a href=\"/pypi/{repo_key}/simple/{name}/\">{name}</a>\n"
        ));
    }
    html.push_str("</body>\n</html>\n");

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE.as_str(), "text/html; charset=utf-8");
    if truncated {
        builder = builder.header(
            "Warning",
            format!(
                "299 - \"results truncated at {} items\"",
                hort_domain::types::LIMIT_LIST_MAX_ITEMS
            ),
        );
    }
    Ok(builder.body(Body::from(html)).unwrap())
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/simple/{project}/ — PEP 503 package index
// ---------------------------------------------------------------------------

async fn simple_project(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, project)): BoundedPath<(String, String)>,
    headers: HeaderMap,
    // GET reads the `Option<AuthenticatedPrincipal>` slot that
    // `extract_optional_principal` writes; the outer `Option` tolerates the
    // no-auth-layer test case → anonymous.
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap before this
    // handler body runs.
    //
    // Both `Proxy` and `Hosted` / `Staging` / `Virtual` paths route
    // through the unified [`serve::serve_simple_index_unified`] handler,
    // which dispatches a source by `repo.repo_type` internally and picks
    // the builder (PypiHtmlIndexBuilder / PypiJsonIndexBuilder) based on
    // the `Accept` header via `SimpleIndexFormat::from_accept`.
    // Unwrap the `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`
    // for the use-case API.
    let actor = principal
        .as_deref()
        .and_then(|opt| opt.as_ref())
        .map(AuthenticatedPrincipal::as_caller);
    let format = simple_index::SimpleIndexFormat::from_accept(
        headers.get(ACCEPT).and_then(|v| v.to_str().ok()),
    );
    serve::serve_simple_index_unified(&ctx, &repo_key, &project, format, actor).await
}

// The pre-unification hosted/proxy split (inline HTML synthesis +
// `simple_index::serve_proxy_simple`) was deleted when the unified
// Source → Filter → Builder pipeline landed. The unified
// `serve::serve_simple_index_unified` handler dispatches both arms.

// `html_escape_attr` and `render_pep691` were deleted when the unified
// pipeline landed: `PypiHtmlIndexBuilder` / `PypiJsonIndexBuilder`
// (in `hort-formats::pypi::index`) own the HTML escaping + PEP 691 /
// PEP 700 JSON shape. `wants_pep691_json` survives as the
// `simple_index::SimpleIndexFormat::from_accept` constructor.

// ---------------------------------------------------------------------------
// GET /{repo_key}/simple/{project}/{filename} — download
// ---------------------------------------------------------------------------

async fn download(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, project, filename)): BoundedPath<(String, String, String)>,
    // GET reads the `Option<AuthenticatedPrincipal>` slot that
    // `extract_optional_principal` writes; the outer `Option` tolerates the
    // no-auth-layer test case → anonymous.
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs — a malicious client
    // that passes a 1 MiB `filename` is rejected inside the extractor,
    // not here.
    // PEP 658 `.metadata` endpoint is served from the SAME route slot —
    // axum's path syntax doesn't admit a second route with a literal
    // `.metadata` suffix on the `:filename` segment, so we branch here.
    // Strip the suffix and dispatch to the metadata handler; otherwise
    // fall through to the normal artifact download below.
    // Unwrap the `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`
    // for the use-case API.
    let actor = principal
        .as_deref()
        .and_then(|opt| opt.as_ref())
        .map(AuthenticatedPrincipal::as_caller);
    if let Some(stripped) = filename.strip_suffix(".metadata") {
        // PEP 658 `.metadata` endpoint (PEP 658 + PEP 491). Dispatches
        // by `RepositoryType` to either the hosted CAS-backed serve
        // (via `WheelMetadataUseCase`) or the proxy strategy-2 full-wheel
        // pull-through. Wheels only — sdists short-circuit to 404 inside
        // `serve_pep658_metadata`.
        return metadata_endpoint::serve_pep658_metadata(
            ctx,
            repo_key,
            project,
            stripped.to_string(),
            actor,
        )
        .await;
    }

    // Use the URL segment as-is — do NOT re-normalise. The index handler
    // emits URLs built from `artifact.name` (whatever normalisation was
    // active at ingest), so the URL segment the client follows is already
    // the stored form. Re-normalising here would break drift resilience
    // when a plugin update's `normalize_name` is not idempotent on old
    // stored names.
    let artifact_path = format!("simple/{project}/{filename}");

    // `find_visible_by_path` resolves the repo via
    // `RepositoryAccessUseCase::resolve(_, actor, Read)` first, then
    // looks up the artifact scoped to that repo's id (ADR 0008). Repo
    // missing, repo invisible to actor, and artifact missing all collapse
    // to the same `NotFound` envelope (anti-enumeration).
    //
    // On a cache miss for a `RepositoryType::Proxy` repo, route through
    // [`upstream_pull::try_upstream_file_pull`] and serve the
    // freshly-minted artifact via the existing quarantine + streaming
    // code below. Hosted/Staging/Virtual repos keep the cache-miss →
    // 404 behaviour. The branch hinges on the `entity` discriminator
    // inside `find_visible_by_path`'s `NotFound`: `"Repository"` (missing
    // or invisible) propagates as 404 immediately — same envelope, no
    // upstream side-effect; `"Artifact"` (repo visible, path missing)
    // falls through to the type-check branch below. The use case carries
    // the resolved `Repository` only on the success arm, so the Proxy
    // branch re-resolves via the access use case to inspect `repo_type`
    // (mirrors the Cargo prior art at
    // `crates/hort-http-cargo/src/lib.rs::download`).
    //
    // The quarantine block below applies to pulled-through artifacts
    // too: the freshly-ingested artifact reaches it just like a local
    // upload would. Today `VerifiedIngestRequest::UpstreamPublished`
    // sets no quarantine_until, so the pulled-through artifact lands
    // with `QuarantineStatus::None` and the response is 200 + body.
    // If a future change wires a quarantine window into the upstream-
    // pull path, the same code path will return 503 + Retry-After.
    let (_repo, artifact) = match ctx
        .artifact_use_case
        .find_visible_by_path(&repo_key, &artifact_path, actor)
        .await
    {
        Ok(pair) => pair,
        Err(hort_app::error::AppError::Domain(hort_domain::error::DomainError::NotFound {
            entity: "Artifact",
            ..
        })) => {
            // Repo is visible (the use case's access check already passed);
            // re-resolve to inspect `repo_type`. A race-deletion between
            // the two calls collapses to the same `NotFound` envelope as
            // the original (callers cannot distinguish the race from a
            // legitimate miss — anti-enumeration preserved).
            let repo = ctx
                .repository_access_use_case
                .resolve(&repo_key, actor, AccessLevel::Read)
                .await?;
            match repo.repo_type {
                RepositoryType::Proxy => {
                    match upstream_pull::try_upstream_file_pull(&ctx, &repo, &project, &filename)
                        .await
                    {
                        Ok(artifact) => (repo, artifact),
                        Err(e) => return Ok(upstream_pull::map_upstream_pull_error(&e)),
                    }
                }
                RepositoryType::Virtual => {
                    // Transparent aggregation (ADR 0031): the member sources
                    // already enforce visibility + quarantine; the resolver
                    // picks the authoritative member and we render its gate
                    // through the SAME `render_pypi_file_response` tail.
                    return serve_virtual_pypi_file(
                        &ctx,
                        &repo,
                        &project,
                        &artifact_path,
                        &filename,
                        actor,
                    )
                    .await;
                }
                RepositoryType::Hosted | RepositoryType::Staging => {
                    // Hosted / Staging cache miss → 404. Match the envelope the
                    // use case would have produced
                    // (`{"error":"not found: Artifact <repo>:<path>"}`) so the
                    // `download_not_found_returns_404` regression stays green
                    // and clients see no observable change.
                    return Err(ApiError::from(hort_app::error::AppError::Domain(
                        hort_domain::error::DomainError::NotFound {
                            entity: "Artifact",
                            id: format!("{repo_key}:{artifact_path}"),
                        },
                    )));
                }
            }
        }
        Err(other) => return Err(other.into()),
    };

    render_pypi_file_response(&ctx, artifact, actor).await
}

/// Render the final file HTTP response for a resolved artifact: surface the
/// quarantine gate (`Quarantined` → 503 + `Retry-After`,
/// `Rejected` / `ScanIndeterminate` → 403) or stream the bytes from CAS.
///
/// Shared by the hosted/proxy direct path and the virtual aggregation path
/// (ADR 0031) so the gate render + streaming live in exactly one place; the
/// virtual layer only chooses which member's artifact reaches here.
async fn render_pypi_file_response(
    ctx: &Arc<AppContext>,
    artifact: hort_domain::entities::artifact::Artifact,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // Check quarantine status directly for correct HTTP response codes.
    match artifact.quarantine_status {
        QuarantineStatus::Quarantined => {
            // The use-case layer hydrates the transient computed
            // `quarantine_deadline`; the format crate never computes it
            // (it cannot resolve a `ScanPolicy`).
            let retry_after = artifact
                .quarantine_deadline
                .map(|deadline| {
                    let secs = (deadline - Utc::now()).num_seconds().max(1);
                    secs.to_string()
                })
                .unwrap_or_else(|| "3600".to_string());

            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Retry-After", retry_after)
                .body(Body::from(
                    serde_json::json!({"error": "artifact is quarantined"}).to_string(),
                ))
                .unwrap());
        }
        QuarantineStatus::Rejected => {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    serde_json::json!({"error": "artifact is rejected"}).to_string(),
                ))
                .unwrap());
        }
        // Terminal scan failure (scanner could not decide). Fail-closed:
        // a terminal block like `Rejected`, not a timed hold (no
        // Retry-After). The Artifactory proxy 503 mapping for this state
        // is deferred — this is the native-handler path.
        QuarantineStatus::ScanIndeterminate => {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    serde_json::json!({"error": "artifact scan is indeterminate"}).to_string(),
                ))
                .unwrap());
        }
        QuarantineStatus::None | QuarantineStatus::Released => {}
    }

    // Thread the resolved principal for opt-in download-audit attribution.
    // No per-handler auth code; the caller already proved Read on the
    // (member) repo via `find_visible_by_path`.
    let (_artifact, stream) = ctx.artifact_use_case.download(artifact.id, actor).await?;

    let body = stream_blob(stream, DEFAULT_STREAM_CAPACITY);

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        artifact
            .content_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    // Always emit Content-Length — even for zero-byte artifacts. Without
    // it axum chunk-encodes the response and a mid-stream integrity
    // failure (the `VerifyingReader` EOF error) can terminate as a
    // *normal* chunked end, making the truncation client-undetectable.
    // Mirrors the OCI handler precedent
    // (`crates/hort-http-oci/src/blobs.rs::build_response`).
    headers.insert(CONTENT_LENGTH, artifact.size_bytes.into());

    Ok((StatusCode::OK, headers, body).into_response())
}

// ---------------------------------------------------------------------------
// Virtual (aggregating) download — ADR 0031
// ---------------------------------------------------------------------------

/// One virtual member's download outcome for the first-authoritative walk
/// (ADR 0031 §4.2): either the authoritative artifact, or a pre-rendered
/// response (a proxy member's upstream-pull error surfaced verbatim — 502 /
/// tampering / ingest-fail). The hosted/proxy member paths already enforce
/// visibility + quarantine; the virtual layer only chooses the member.
enum VirtualMemberDownload {
    Found(hort_domain::entities::artifact::Artifact),
    Rendered(Response),
}

/// Transparent virtual file download (ADR 0031). Resolves the authoritative
/// member via
/// [`VirtualResolutionUseCase::resolve_download`](hort_app::use_cases::virtual_resolution::VirtualResolutionUseCase::resolve_download)
/// (name-level pinning + first-authoritative walk + the fail-closed member
/// rule all live in `hort-app`), then renders the chosen artifact's gate
/// through the same [`render_pypi_file_response`] tail the hosted/proxy path
/// uses. `download` never special-cases `Virtual` past the source dispatch.
async fn serve_virtual_pypi_file(
    ctx: &Arc<AppContext>,
    virtual_repo: &hort_domain::entities::repository::Repository,
    project: &str,
    artifact_path: &str,
    filename: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    let resolved: Option<VirtualMemberDownload> =
        ctx.virtual_resolution_use_case
            .resolve_download(
                virtual_repo,
                actor,
                // Phase 1 — non-proxy name presence (reuses the member's own
                // index source so the pinning signal matches the index path).
                move |member| async move {
                    pypi_member_name_presence(ctx, &member, project, actor).await
                },
                // Phase 2 — per-member coordinate fetch (hosted lookup / proxy
                // pull), classified for the first-authoritative walk.
                move |member| async move {
                    pypi_member_coord_fetch(ctx, &member, project, artifact_path, filename, actor)
                        .await
                },
            )
            .await?;

    match resolved {
        Some(VirtualMemberDownload::Found(artifact)) => {
            render_pypi_file_response(ctx, artifact, actor).await
        }
        Some(VirtualMemberDownload::Rendered(resp)) => Ok(resp),
        // No eligible member has the coordinate (or an owned name had the
        // version absent from every owner) → 404, never a proxy fall-through.
        None => Err(ApiError::from(hort_app::error::AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Artifact",
                id: format!("{}:{}", virtual_repo.key, artifact_path),
            },
        ))),
    }
}

/// Non-proxy member name presence for the download pinning decision
/// (ADR 0031 rule 2b). Reuses the member's own [`IndexSource`] — the same
/// path the index aggregation uses — so the ownership signal is identical
/// across the index and download paths. Only invoked for non-proxy members
/// (proxies never own), so the [`SimpleIndexFormat`] passed to
/// `select_source` is inert here (the hosted source ignores it).
async fn pypi_member_name_presence(
    ctx: &Arc<AppContext>,
    member: &hort_domain::entities::repository::Repository,
    project: &str,
    actor: Option<&CallerPrincipal>,
) -> hort_app::use_cases::virtual_resolution::MemberNamePresence {
    use hort_app::use_cases::virtual_resolution::MemberNamePresence;

    match index_source::select_source(member, simple_index::SimpleIndexFormat::Json)
        .fetch(ctx, member, project, actor)
        .await
    {
        Ok(out) if !out.entries.is_empty() => MemberNamePresence::Present,
        Ok(_) => MemberNamePresence::Absent,
        // A definitive "absent here" (invisible / missing repo / no rows)
        // collapses to `NotFound` → the member does not own the name.
        Err(hort_app::error::AppError::Domain(hort_domain::error::DomainError::NotFound {
            ..
        })) => MemberNamePresence::Absent,
        // Any other error is an infrastructure failure → ownership is
        // indeterminate; a non-proxy member that errors is treated
        // fail-closed as a potential owner (proxies suppressed for the name).
        Err(_) => MemberNamePresence::Unavailable,
    }
}

/// Per-member coordinate fetch for the first-authoritative walk
/// (ADR 0031 §4.2). Returns `Ok(Some(Found))` when the member has the
/// coordinate (cache hit, or a proxy pull mints it), `Ok(Some(Rendered))`
/// when an authoritative proxy member's pull failed (surfaced verbatim —
/// no fall-through), `Ok(None)` when the member definitively lacks it (the
/// walk continues), or `Err` on infrastructure failure (propagated).
async fn pypi_member_coord_fetch(
    ctx: &Arc<AppContext>,
    member: &hort_domain::entities::repository::Repository,
    project: &str,
    artifact_path: &str,
    filename: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Option<VirtualMemberDownload>, hort_app::error::AppError> {
    // Local CAS hit on the member (any type) → authoritative.
    match ctx
        .artifact_use_case
        .find_visible_by_path(&member.key, artifact_path, actor)
        .await
    {
        Ok((_repo, artifact)) => return Ok(Some(VirtualMemberDownload::Found(artifact))),
        // Local path miss: a proxy member tries the upstream pull below; a
        // hosted/staging member simply lacks the coordinate.
        Err(hort_app::error::AppError::Domain(hort_domain::error::DomainError::NotFound {
            entity: "Artifact",
            ..
        })) => {}
        // Member vanished between resolve and fetch (Repository NotFound) →
        // treat as absent (continue the walk); other infra errors propagate.
        Err(hort_app::error::AppError::Domain(hort_domain::error::DomainError::NotFound {
            ..
        })) => return Ok(None),
        Err(other) => return Err(other),
    }

    if !matches!(member.repo_type, RepositoryType::Proxy) {
        return Ok(None);
    }

    // Proxy member: verified upstream pull (the same path the non-virtual
    // proxy download uses).
    match upstream_pull::try_upstream_file_pull(ctx, member, project, filename).await {
        Ok(_artifact) => {
            let (_repo, artifact) = ctx
                .artifact_use_case
                .find_visible_by_path(&member.key, artifact_path, actor)
                .await?;
            Ok(Some(VirtualMemberDownload::Found(artifact)))
        }
        // A genuine upstream miss / no mapping / curation block means this
        // member cannot serve the coordinate → continue the walk (the
        // virtual's own 404 renders if no member serves it). CurationBlocked
        // already collapses to 404 (anti-enumeration).
        Err(upstream_pull::UpstreamPullError::NoUpstreamMapping)
        | Err(upstream_pull::UpstreamPullError::CurationBlocked) => Ok(None),
        // Any other failure (502-class, tampering, ingest fail) is the
        // authoritative proxy member's failure → surface it verbatim, never
        // fall through to a lower-priority member.
        Err(e) => Ok(Some(VirtualMemberDownload::Rendered(
            upstream_pull::map_upstream_pull_error(&e),
        ))),
    }
}

// ---------------------------------------------------------------------------
// PEP 658 — `.metadata` endpoint is served by `metadata_endpoint.rs` via
// the suffix-branch in `download` above; axum's path syntax doesn't admit
// a literal-suffix route on the `:filename` segment. The legacy
// `serve_package_metadata` + `synthesize_pkg_info` PKG-INFO synthesizer
// was removed — synthesizing approximation bytes violated PEP 658's
// `<data-dist-info-metadata>` hash-byte contract (the simple index
// advertises the SHA-256 of the bytes served by this endpoint; synthesis
// cannot satisfy that invariant).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validation_error(msg: &str) -> ApiError {
    ApiError::from(hort_app::error::AppError::Domain(
        hort_domain::error::DomainError::Validation(msg.to_string()),
    ))
}

// ---------------------------------------------------------------------------
/// Build the 400 response emitted when a PyPI upload exceeds
/// [`hort_http_core::limits::MAX_MULTIPART_FIELDS`].
///
/// Wire shape is `{"error":"too many multipart fields"}` verbatim —
/// native clients may parse on the exact string, so the body is
/// load-bearing.
fn too_many_multipart_fields_response() -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"too many multipart fields"}"#))
        .expect("static response")
}

// `validate_publish_filename` was removed. `hort_formats::pypi::validate_pypi_filename`
// covers and exceeds it: the charset allowlist `[A-Za-z0-9._+-]` rejects
// path separators (`/`, `\`), null bytes, control bytes, the `..` literal,
// and every other byte the old check named. The single former call site in
// `upload` now calls the canonical validator.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactMetadataRepository, MockArtifactRepository,
        MockRepositoryRepository, MockStoragePort,
    };
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::Repository;

    use super::*;
    use hort_http_core::authz::write::emit_authz_metric;
    use hort_http_core::context::{AppContext, AuthContext};
    use hort_http_core::test_support::build_mock_ctx_with_label_flag;

    struct TestHarness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
        artifact_metadata: Arc<MockArtifactMetadataRepository>,
        /// Curation-gate seed handle for the
        /// `upload_curation_block_returns_403` test.
        curation_rules: Arc<hort_app::use_cases::test_support::MockCurationRuleRepository>,
        /// `wheel_metadata` ContentReference seed handle for the PEP 658
        /// `.metadata` endpoint tests. The adapter-side port is
        /// `pub(crate)` on `AppContext`; tests reach the same `Arc` via
        /// `MockPorts.content_references`.
        content_references: Arc<hort_app::use_cases::test_support::MockContentReferenceIndex>,
        /// Committed-transition handle for the verified-direct-upload tests.
        /// The match path asserts `ArtifactIngested + ChecksumVerified` ride
        /// atomically in the same `commit_transition` batch; the mismatch path
        /// asserts no transition committed.
        lifecycle: Arc<hort_app::use_cases::test_support::MockArtifactLifecycle>,
        /// Event-store handle for the verified-direct-upload tests. The
        /// mismatch path asserts a single `ChecksumMismatch` on the repository
        /// stream and that no `ChecksumVerified` / `ArtifactIngested` event
        /// fires anywhere.
        events: Arc<hort_app::use_cases::test_support::MockEventStore>,
    }

    /// Build an AppContext wired to in-memory mocks.
    ///
    /// Callers pass the `include_repository_label` flag so tests can cover
    /// both the enabled (real repo keys) and disabled (`_all` sentinel)
    /// emission paths.
    fn harness_with(include_repository_label: bool) -> TestHarness {
        // Handle bound to a fresh (unused) recorder. These handler tests do
        // not scrape `/metrics`; they rely on assertions over responses. A
        // test that does scrape `/metrics` installs its own local recorder
        // and passes the matching handle (see the `hort-server::http` tests).
        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        let (ctx, mocks) = build_mock_ctx_with_label_flag(metrics_handle, include_repository_label);
        TestHarness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
            artifact_metadata: mocks.artifact_metadata,
            curation_rules: mocks.curation_rules,
            content_references: mocks.content_references,
            lifecycle: mocks.lifecycle,
            events: mocks.events,
        }
    }

    /// Default harness with the `repository` label enabled. Most tests use this.
    fn harness() -> TestHarness {
        harness_with(true)
    }

    fn router(ctx: Arc<AppContext>) -> Router {
        Router::new().nest("/pypi", pypi_routes()).with_state(ctx)
    }

    /// Router with a caller-specified publish body-size ceiling. Lets
    /// tests exercise the `DefaultBodyLimit::max(limit)` reject path
    /// without shipping hundreds of megabytes.
    fn router_with_publish_limit(ctx: Arc<AppContext>, limit: usize) -> Router {
        Router::new()
            .nest("/pypi", pypi_routes_with_publish_limit(limit))
            .with_state(ctx)
    }

    /// Hex-encoded SHA-256 of `content` — the value the PyPI legacy upload
    /// form's `sha256_digest` field carries. The shared multipart builders
    /// call this so happy-path upload tests emit a digest that matches the
    /// bytes they embed (the verified-ingest re-anchor lives at the builder
    /// level). The `MockStoragePort::put` mock computes the same real
    /// SHA-256, so a digest produced here matches the CAS-computed hash
    /// and the upload's verification passes.
    fn content_sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    fn insert_repo(h: &TestHarness, key: &str) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.to_string();
        // Ingest requires coords.format == repo.format.
        // Align with what the PyPI handler sets in coords.
        repo.format = RepositoryFormat::Pypi;
        h.repositories.insert(repo.clone());
        repo
    }

    fn insert_artifact(
        h: &TestHarness,
        repo_id: Uuid,
        name: &str,
        filename: &str,
        status: QuarantineStatus,
    ) -> Artifact {
        let mut artifact = sample_artifact(status);
        artifact.repository_id = repo_id;
        artifact.name = name.to_string();
        artifact.path = format!("simple/{name}/{filename}");
        h.artifacts.insert(artifact.clone());
        // Pre-populate storage so download() succeeds.
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), b"file content".to_vec());
        artifact
    }

    // -- download tests -------------------------------------------------------

    #[tokio::test]
    async fn download_not_found_returns_404() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/missing/missing-1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn download_quarantined_returns_503_with_retry_after() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "pkg",
            "pkg-1.0.tar.gz",
            QuarantineStatus::Quarantined,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(res.headers().get("Retry-After").is_some());
    }

    #[tokio::test]
    async fn download_rejected_returns_403() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "pkg",
            "pkg-1.0.tar.gz",
            QuarantineStatus::Rejected,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn download_available_returns_200_with_body() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(&h, repo.id, "pkg", "pkg-1.0.tar.gz", QuarantineStatus::None);
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"file content");
    }

    // -- CAS serve-path integrity: storage io::Error fails the
    //    HTTP transfer ------------------------------------------------------
    //
    // The CAS serve-path re-verification (`VerifyingReader` in
    // `hort-adapters-storage`) is Tier-1 tested at the adapter boundary: it
    // hashes incrementally and at EOF yields `io::ErrorKind::InvalidData`
    // on a tampered blob. What was NOT proven is that this io::Error,
    // surfaced through `download() -> ReaderStream -> Body::from_stream`,
    // makes the *format HTTP handler* fail the transfer rather than serve
    // a clean, fully-delivered 200.
    //
    // These tests drive the real PyPI download handler with a storage
    // reader that emits N valid bytes then an `InvalidData` io::Error at
    // EOF — exactly the shape `VerifyingReader` produces on a tampered
    // blob (see `crates/hort-adapters-storage/src/integrity.rs`). PyPI is
    // the canonical handler; npm/cargo share the identical
    // `hort_http_core::body::stream_blob` wiring, so this guards all four
    // against a future regression that swaps streaming for buffering.
    // We do NOT re-test `VerifyingReader` here.

    /// A tampered blob whose declared `size_bytes` is non-zero MUST NOT
    /// be served as a successfully-completed body of the declared length
    /// with the bytes intact. The handler sets `Content-Length:
    /// size_bytes` and streams the body; when the underlying storage
    /// reader errors at EOF (the `VerifyingReader` integrity-failure
    /// shape) the body stream errors before `Content-Length` bytes are
    /// delivered. A conforming client sees a truncated/failed download,
    /// never a clean success.
    #[tokio::test]
    async fn download_storage_integrity_error_fails_transfer_not_clean_200() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "pkg".into();
        artifact.path = "simple/pkg/pkg-1.0.tar.gz".into();
        // Declare a non-zero size so Content-Length is emitted and the
        // truncation is client-detectable. The reader will deliver only
        // `valid_prefix.len()` bytes (< size_bytes) then error.
        artifact.size_bytes = 64;
        h.artifacts.insert(artifact.clone());

        // Register a reader for this content hash that yields 8 valid
        // bytes then `Err(io::ErrorKind::InvalidData)` at EOF — exactly
        // what `VerifyingReader` does when the accumulated SHA-256 does
        // not match the expected `ContentHash`.
        let valid_prefix = b"PARTIAL!".to_vec();
        h.storage
            .fail_next_get_truncated(artifact.sha256_checksum.clone(), valid_prefix.clone());

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // The handler resolves the artifact and starts streaming before
        // the io::Error surfaces (the error is at EOF, after the prefix),
        // so the status line is 200 and Content-Length is the declared
        // size — but the body stream MUST error before delivering that
        // many bytes. This is the concrete failure signal: a conforming
        // client reading the body sees an error / a short read, never a
        // complete success.
        assert_eq!(res.status(), StatusCode::OK);
        let declared_len: u64 = res
            .headers()
            .get(CONTENT_LENGTH)
            .expect("Content-Length must be set for a non-zero-size artifact")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared_len, 64, "Content-Length echoes size_bytes");

        // Collecting the body must FAIL (the underlying reader errored) —
        // and even if a future axum version yielded a partial body
        // instead of an error, it must be shorter than the declared
        // Content-Length. Either way the handler did NOT present this
        // tampered artifact as a complete, intact success.
        match to_bytes(res.into_body(), 1024).await {
            Err(_) => { /* expected: the body stream errored */ }
            Ok(collected) => {
                assert!(
                    (collected.len() as u64) < declared_len,
                    "tampered artifact must not be served as a complete \
                     body of the declared length; got {} bytes, declared {}",
                    collected.len(),
                    declared_len,
                );
            }
        }
    }

    /// A zero-`size_bytes` artifact must still carry `Content-Length: 0`.
    /// Before the fix the `if size_bytes > 0` guard suppressed the header,
    /// so axum chunk-encoded the response and a mid-stream integrity failure
    /// could terminate as a *normal* chunked end — client-undetectable. With
    /// the guard removed the header is unconditional (matching the OCI handler
    /// precedent in `crates/hort-http-oci/src/blobs.rs::build_response`).
    #[tokio::test]
    async fn download_zero_size_artifact_still_sets_content_length_zero() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "empty".into();
        artifact.path = "simple/empty/empty-1.0.tar.gz".into();
        artifact.size_bytes = 0;
        h.artifacts.insert(artifact.clone());
        // Seed empty content so download() resolves and streams cleanly.
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), Vec::new());

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/empty/empty-1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let cl = res
            .headers()
            .get(CONTENT_LENGTH)
            .expect("Content-Length must be set even when size_bytes == 0");
        assert_eq!(cl.to_str().unwrap(), "0");
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        assert!(body.is_empty());
    }

    // -- Proxy-cache-miss pull-through ------------------------------------------
    //
    // The `try_upstream_file_pull` orchestrator is wired into the
    // `download` handler's Proxy-cache-miss branch. Tests pin the wire shape
    // for each `UpstreamPullError` variant. Mirrors the Cargo prior art at
    // `crates/hort-http-cargo/src/lib.rs::tests::proxy_pull_through`.
    //
    // The tests drive the FULL orchestration through `MockPorts`
    // rather than mocking the orchestrator directly — `try_upstream_file_pull`
    // is not easily mockable, and the assertions here are wire-shape
    // (status + body + `X-Hort-Reason`), so the integration shape is the
    // right boundary to cover. Hosted/Staging/Virtual repos must NOT
    // enter the Proxy branch — the `download_hosted_repo_cache_miss_still_returns_404`
    // test pins this.

    mod proxy_pull_through {
        use std::sync::Arc;

        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use chrono::Utc;
        use metrics_exporter_prometheus::PrometheusBuilder;
        use sha2::{Digest, Sha256};
        use tower::ServiceExt;
        use uuid::Uuid;

        use hort_app::use_cases::test_support::sample_repository;
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::repository::{Repository, RepositoryFormat, RepositoryType};
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };
        use hort_http_core::test_support::{build_mock_ctx, MockPorts};

        use super::*;

        fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
            PrometheusBuilder::new().build_recorder().handle()
        }

        fn proxy_pypi_repo(key: &str) -> Repository {
            let mut r = sample_repository();
            r.key = key.into();
            r.format = RepositoryFormat::Pypi;
            r.repo_type = RepositoryType::Proxy;
            r.upstream_url = Some("https://pypi.org".into());
            // These proxy pull-through tests seed no `package_version_status`
            // rows; under the production default (`ReleasedOnly`) the
            // quarantine filter would drop everything. `IncludePending`
            // preserves the upstream catalog when hort has no status row,
            // keeping the mechanics assertions intact. Mirrors the
            // `simple_index::tests::proxy_pypi_repo` choice.
            r.index_mode = hort_domain::entities::repository::IndexMode::IncludePending;
            r
        }

        fn seed_mapping(mocks: &MockPorts, repo_id: Uuid) -> Uuid {
            let id = Uuid::new_v4();
            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id,
                repository_id: repo_id,
                path_prefix: "".into(),
                upstream_url: "https://pypi.org".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });
            id
        }

        /// Minimal PyPI per-version JSON body keyed on (filename, sha256, url).
        /// Mirrors the structure consumed by `parse_upstream_checksum` and
        /// `extract_upstream_file_url`.
        fn pypi_json(filename: &str, sha256: &str, url: &str) -> Vec<u8> {
            format!(
                r#"{{"urls":[{{"filename":"{filename}","url":"{url}","digests":{{"sha256":"{sha256}"}}}}]}}"#,
            )
            .into_bytes()
        }

        /// JSON body with only `md5` in `digests` — exercises the
        /// "ParseError surfaces md5-only legacy releases" branch
        /// (PyPI rejects pull-through for md5-only entries — sha256 is
        /// the security primitive).
        fn pypi_json_md5_only(filename: &str, url: &str) -> Vec<u8> {
            format!(
                r#"{{"urls":[{{"filename":"{filename}","url":"{url}","digests":{{"md5":"deadbeefdeadbeefdeadbeefdeadbeef"}}}}]}}"#,
            )
            .into_bytes()
        }

        fn router_for(ctx: Arc<AppContext>) -> Router {
            Router::new().nest("/pypi", pypi_routes()).with_state(ctx)
        }

        /// Cache miss + Proxy + happy upstream → 200 with verified bytes.
        ///
        /// `IngestUseCase::ingest_verified` is invoked with no
        /// `quarantine_until` (the `VerifiedIngestRequest::UpstreamPublished`
        /// shape has no quarantine field), so the freshly-minted artifact
        /// reaches the streaming path with `QuarantineStatus::None` and
        /// the response is 200 + body. If a future change wires a
        /// quarantine window into the upstream-pull path, this test will
        /// flip to 503 + Retry-After — at that point the assertion needs
        /// to be split per-config; today the harness has no quarantine
        /// window so 200 is the contract.
        #[tokio::test]
        async fn download_proxy_repo_cache_miss_success_returns_200() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body_bytes = b"the actual sdist body".to_vec();
            let sha = format!("{:x}", Sha256::digest(&body_bytes));
            let sdist_url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
            let json = pypi_json("requests-2.31.0.tar.gz", &sha, sdist_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/requests/2.31.0/json", json);
            mocks
                .upstream_proxy
                .insert_artifact("", sdist_url, body_bytes.clone());

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&bytes[..], body_bytes.as_slice());
        }

        /// Cache miss + Proxy + upstream serves bytes that disagree with
        /// the advertised sha256 → 502 + `X-Hort-Reason: upstream-checksum-mismatch`.
        /// Pins the security primitive against upstream tampering: the
        /// rehash inside `ingest_verified` rejects, the orchestrator
        /// surfaces `ChecksumMismatch`, and the wire-map renders 502.
        #[tokio::test]
        async fn download_proxy_repo_cache_miss_checksum_mismatch_returns_502() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual = b"actual-bytes".to_vec();
            let lying_sha = format!("{:x}", Sha256::digest(b"different-bytes"));
            let sdist_url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
            let json = pypi_json("requests-2.31.0.tar.gz", &lying_sha, sdist_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/requests/2.31.0/json", json);
            mocks.upstream_proxy.insert_artifact("", sdist_url, actual);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(
                res.headers()
                    .get("X-Hort-Reason")
                    .and_then(|v| v.to_str().ok()),
                Some("upstream-checksum-mismatch"),
            );
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "upstream tampering detected");
        }

        /// Cache miss + Proxy + upstream JSON has only `md5` in `digests` →
        /// `parse_upstream_checksum` returns `Validation`, the orchestrator
        /// surfaces `ParseError`, and the wire-map renders 502 +
        /// `X-Hort-Reason: upstream-metadata-malformed`.
        #[tokio::test]
        async fn download_proxy_repo_cache_miss_md5_only_returns_502() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let sdist_url = "https://files.pythonhosted.org/packages/abc/legacy-1.0.tar.gz";
            let json = pypi_json_md5_only("legacy-1.0.tar.gz", sdist_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/legacy/1.0/json", json);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/legacy/legacy-1.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(
                res.headers()
                    .get("X-Hort-Reason")
                    .and_then(|v| v.to_str().ok()),
                Some("upstream-metadata-malformed"),
            );
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "upstream metadata invalid");
        }

        /// Cache miss + Proxy + no upstream mapping configured →
        /// `NoUpstreamMapping` → 404 with the local-miss envelope shape so
        /// pip's "not found" detection works the same as for a Hosted repo
        /// miss. The repo IS Proxy but no mapping row exists, which is the
        /// "Proxy with no upstream configured" admin misconfiguration case.
        #[tokio::test]
        async fn download_proxy_repo_cache_miss_no_mapping_returns_404() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            // Deliberately no `seed_mapping` — `upstream_resolver.resolve`
            // returns None, the orchestrator returns `NoUpstreamMapping`.

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "package not found");
        }

        /// Cache miss on a Hosted (default) repo MUST NOT enter the Proxy
        /// pull-through branch — pre-Item-5 behaviour is preserved as a
        /// clean 404. Regression test: a routing regression that fired
        /// pull-through unconditionally would either return 200 (if
        /// upstream were seeded — it isn't) or surface a 502 from the
        /// orchestrator's `NoUpstreamMapping` path. Both fail the 404
        /// assertion. The existing `download_not_found_returns_404`
        /// test covers Hosted + missing artifact too; this one is the
        /// near-twin that makes the no-pull-through behaviour explicit
        /// using the same `MockPorts` harness as the Proxy tests so a
        /// regression in the type-check branch surfaces here.
        #[tokio::test]
        async fn download_hosted_repo_cache_miss_still_returns_404() {
            let (ctx, mocks) = build_mock_ctx(handle());
            // sample_repository → RepositoryType::Hosted by default; pin
            // it explicitly so a future test_support change cannot
            // silently flip this fixture.
            let mut repo = sample_repository();
            repo.key = "pypi-hosted".into();
            repo.format = RepositoryFormat::Pypi;
            repo.repo_type = RepositoryType::Hosted;
            mocks.repositories.insert(repo);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-hosted/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        /// Cache hit on a Proxy repo → 200 served directly from the
        /// local CAS, NO orchestrator call. Confirms the
        /// `find_visible_by_path` success arm short-circuits before the
        /// Proxy branch, so a request that already has the artifact in
        /// CAS does not perform a redundant upstream pull. The orchestrator
        /// would fail loudly here because `upstream_resolver` has no
        /// mapping — if the Proxy branch fired, the test would see 404
        /// (`NoUpstreamMapping`), not 200.
        #[tokio::test]
        async fn download_proxy_repo_cache_hit_serves_local_no_pull_through() {
            use hort_app::use_cases::test_support::sample_artifact;
            use hort_domain::entities::artifact::QuarantineStatus;

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            // Deliberately NO `seed_mapping` — if the Proxy branch fires,
            // the orchestrator returns `NoUpstreamMapping` and the wire
            // becomes 404 (not 200).

            let mut artifact = sample_artifact(QuarantineStatus::None);
            artifact.repository_id = repo.id;
            artifact.name = "requests".to_string();
            artifact.path = "simple/requests/requests-2.31.0.tar.gz".to_string();
            mocks.artifacts.insert(artifact.clone());
            mocks.storage.insert_content(
                artifact.sha256_checksum.clone(),
                b"local cached body".to_vec(),
            );

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
            assert_eq!(&body[..], b"local cached body");
        }

        // -- Upstream-verification framework-invariant assertions ----------------
        //
        // The wire-shape tests above pin status code, body, and
        // `X-Hort-Reason` headers. The three tests below extend that
        // coverage to the upstream-verification audit invariants (ADR 0006),
        // mirroring the Cargo precedent at
        // `crates/hort-http-cargo/src/lib.rs::tests::proxy_pull_through`
        // (commit `f657201`):
        //
        // 1. Happy path emits `ArtifactIngested + ChecksumVerified` in
        //    the SAME `commit_transition` batch on the artifact stream
        //    (the "atomic with the mint" rule); the blob lands in the
        //    CAS at its computed hash.
        // 2. Tampered file emits exactly one `ChecksumMismatch` on the
        //    REPOSITORY stream (never the artifact stream — under
        //    mint-after-verify no artifact row exists for the
        //    mismatch); no `ArtifactIngested` and no `ChecksumVerified`
        //    fire anywhere; the CAS net state is empty (rollback fired).
        // 3. Missing-sha256 metadata surfaces as a parser failure that
        //    runs BEFORE `ingest_verified` is invoked — therefore no
        //    event of any kind appears on either stream and
        //    `storage.put` is never called.
        //
        // Assertions ride on the existing mock ports. The framework boundary
        // worth verifying here is the use-case + orchestrator layer; the
        // HTTP-adapter's network plumbing is covered by
        // `hort-adapters-upstream-http`'s own wiremock tests, and dragging
        // wiremock into `hort-http-pypi` would re-test that boundary at the
        // wrong layer.

        /// Happy path: cache miss + Proxy + upstream serves the
        /// advertised sdist body.
        ///
        /// Wire is already covered by
        /// `download_proxy_repo_cache_miss_success_returns_200`; this
        /// test asserts the FRAMEWORK invariants:
        /// - `ArtifactIngested` and `ChecksumVerified` ride in the
        ///   SAME `commit_transition` batch (atomic with the mint),
        ///   and that batch lands on the `StreamCategory::Artifact`
        ///   stream.
        /// - The freshly-fetched body is present in the CAS at its
        ///   computed hash (`storage.put` ran exactly once and the
        ///   bytes are recoverable).
        #[tokio::test]
        async fn framework_invariant_happy_path_emits_checksum_verified_and_writes_cas() {
            use hort_domain::events::StreamCategory;
            use hort_domain::types::ContentHash;

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body_bytes = b"the actual sdist body".to_vec();
            let sha = format!("{:x}", Sha256::digest(&body_bytes));
            let sdist_url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
            let json = pypi_json("requests-2.31.0.tar.gz", &sha, sdist_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/requests/2.31.0/json", json);
            mocks
                .upstream_proxy
                .insert_artifact("", sdist_url, body_bytes.clone());

            let lifecycle = mocks.lifecycle.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&bytes[..], body_bytes.as_slice());

            // Audit invariant 1: ArtifactIngested + ChecksumVerified
            // land in the SAME commit_transition batch on the
            // artifact stream.
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "exactly one commit_transition on the happy path"
            );
            let (_artifact, batch, _meta) = &transitions[0];
            assert_eq!(
                batch.stream_id.category,
                StreamCategory::Artifact,
                "ingest commit must land on the artifact stream"
            );
            let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
            assert_eq!(
                kinds,
                vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
                "ArtifactIngested + ChecksumVerified + ScanRequested (DefaultPolicy \
                 fallback) must ride atomically in the same batch"
            );

            // Audit invariant 2: the blob is in the CAS at its
            // computed hash. `storage.put` ran exactly once for the
            // pull-through fetch.
            assert_eq!(
                storage.put_call_count(),
                1,
                "exactly one storage.put on the happy path (the pull-through fetch)"
            );
            let expected_hash: ContentHash = sha
                .parse()
                .expect("computed sha must parse as a ContentHash");
            let stored = storage.stored_hashes();
            assert!(
                stored.contains(&expected_hash),
                "freshly-fetched body must be recoverable from the CAS at its computed hash; \
                 stored hashes: {stored:?}"
            );
        }

        /// Tampered file: cache miss + Proxy + upstream serves bytes
        /// that disagree with the advertised `digests.sha256`.
        ///
        /// Wire is already covered by
        /// `download_proxy_repo_cache_miss_checksum_mismatch_returns_502`;
        /// this test asserts the FRAMEWORK invariants:
        /// - `ChecksumMismatch` is appended to the REPOSITORY stream
        ///   (never the artifact stream — there is no artifact yet
        ///   under mint-after-verify).
        /// - `ArtifactIngested` is NEVER emitted.
        /// - `ChecksumVerified` is NEVER emitted (it is only minted
        ///   on the success branch).
        /// - No artifact row is minted (no `commit_transition`).
        /// - CAS net state is empty: every put is matched by a
        ///   delete (rollback fired).
        #[tokio::test]
        async fn framework_invariant_tampered_file_emits_mismatch_and_rolls_back_cas() {
            use hort_domain::events::{DomainEvent, StreamCategory};

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual = b"actual-bytes".to_vec();
            let lying_sha = format!("{:x}", Sha256::digest(b"different-bytes"));
            let sdist_url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
            let json = pypi_json("requests-2.31.0.tar.gz", &lying_sha, sdist_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/requests/2.31.0/json", json);
            mocks.upstream_proxy.insert_artifact("", sdist_url, actual);

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(
                res.headers()
                    .get("X-Hort-Reason")
                    .and_then(|v| v.to_str().ok()),
                Some("upstream-checksum-mismatch"),
            );

            // Audit invariant: no commit_transition runs — under
            // mint-after-verify no artifact row exists for the
            // mismatch.
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "mismatch must not mint an artifact row; got {} commit(s)",
                lifecycle.committed_transitions().len()
            );

            // Audit invariant: ChecksumMismatch is appended once on
            // the REPOSITORY stream — never the artifact stream.
            let batches = events.appended_batches();
            let mismatch_total = batches
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
                .count();
            assert_eq!(
                mismatch_total, 1,
                "exactly one ChecksumMismatch on the mismatch path"
            );
            let mismatch_on_repo = batches
                .iter()
                .filter(|b| b.stream_id.category == StreamCategory::Repository)
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
                .count();
            assert_eq!(
                mismatch_on_repo, 1,
                "ChecksumMismatch must ride on the repository stream — never the artifact stream"
            );

            // Audit invariant: ChecksumVerified MUST NOT fire anywhere
            // (neither in the EventStore mock nor in any
            // commit_transition batch — and the latter is empty
            // anyway).
            let verified_in_event_store = batches
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
                .count();
            assert_eq!(
                verified_in_event_store, 0,
                "ChecksumVerified must NOT fire on the mismatch path"
            );
            // ArtifactIngested likewise NEVER fires (no artifact
            // exists under mint-after-verify).
            let ingested_total = batches
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
                .count();
            assert_eq!(
                ingested_total, 0,
                "ArtifactIngested must NOT fire on the mismatch path"
            );

            // Audit invariant: CAS net state is empty — every put
            // was matched by a rollback delete.
            assert_eq!(
                storage.put_call_count(),
                1,
                "exactly one put (the rehash) on the mismatch path"
            );
            assert_eq!(
                storage.delete_call_count(),
                1,
                "rollback must delete the rehashed bytes from the CAS"
            );
        }

        /// Missing sha256: per-version JSON body advertises only `md5`
        /// in `digests` (legacy release).
        ///
        /// Wire is already covered by
        /// `download_proxy_repo_cache_miss_md5_only_returns_502`; this
        /// test asserts the FRAMEWORK invariants:
        /// - `parse_upstream_checksum` fails BEFORE `ingest_verified`
        ///   is called, so no event is ever emitted on either stream.
        /// - `storage.put` is never called (the parser short-circuits
        ///   ahead of the file-fetch + storage.put sequence — note
        ///   `fetch_artifact` is deliberately NOT seeded, so a
        ///   regression that reaches the file leg would surface as
        ///   `MetadataFetchFailed{stage:"file"}` rather than the
        ///   expected `ParseError`).
        #[tokio::test]
        async fn framework_invariant_missing_sha256_metadata_returns_502_with_no_events_or_cas_writes(
        ) {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let sdist_url = "https://files.pythonhosted.org/packages/abc/legacy-1.0.tar.gz";
            let json = pypi_json_md5_only("legacy-1.0.tar.gz", sdist_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/legacy/1.0/json", json);
            // Deliberately NO `insert_artifact` — the parser must
            // short-circuit before the file leg fires.

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-mirror/simple/legacy/legacy-1.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(
                res.headers()
                    .get("X-Hort-Reason")
                    .and_then(|v| v.to_str().ok()),
                Some("upstream-metadata-malformed"),
            );

            // Audit invariant: no event is emitted on either stream —
            // the parser fails before `ingest_verified` runs.
            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no commit_transition on the parse-fail path"
            );
            let total_appended: usize = events
                .appended_batches()
                .iter()
                .map(|b| b.events.len())
                .sum();
            assert_eq!(
                total_appended, 0,
                "parse-fail must emit no event of any kind on any stream"
            );

            // Audit invariant: storage is never touched — the
            // parser short-circuits ahead of the file fetch and
            // before any put.
            assert_eq!(
                storage.put_call_count(),
                0,
                "parse-fail must short-circuit before any storage.put"
            );
        }

        /// When the served repo has download auditing enabled, an anonymous
        /// PyPI file pull (no principal) emits exactly one `ArtifactDownloaded`
        /// on the per-(repo, UTC-date) DownloadAudit stream with
        /// `DownloadActor::Anonymous` (no audit gap), never on the artifact
        /// aggregate stream. Threaded adapter-free via `build_mock_ctx`
        /// (no hand-rolled AppContext); the `actor` fn param is
        /// compile-required by the `ArtifactUseCase::download` signature,
        /// so this pins the anonymous mapping + the stream-sharding invariant.
        #[tokio::test]
        async fn download_audit_emits_anonymous_when_repo_opted_in() {
            use hort_app::use_cases::test_support::sample_artifact;
            use hort_domain::entities::artifact::QuarantineStatus;
            use hort_domain::events::{DomainEvent, DownloadActor, StreamCategory};

            let (ctx, mocks) = build_mock_ctx(handle());
            // Hosted repo (sample_repository default) so the local-hit
            // path serves directly from CAS — no upstream wiring.
            let mut repo = sample_repository();
            repo.key = "pypi-audit".into();
            repo.format = RepositoryFormat::Pypi;
            repo.download_audit_enabled = true;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let content = b"the requests sdist bytes";
            let mut artifact = sample_artifact(QuarantineStatus::None);
            artifact.repository_id = repo_id;
            artifact.name = "requests".to_string();
            artifact.version = Some("2.31.0".into());
            artifact.path = "simple/requests/requests-2.31.0.tar.gz".to_string();
            artifact.size_bytes = content.len() as i64;
            mocks.artifacts.insert(artifact.clone());
            mocks
                .storage
                .insert_content(artifact.sha256_checksum.clone(), content.to_vec());

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/pypi/pypi-audit/simple/requests/requests-2.31.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);

            let batches = mocks.events.appended_batches();
            let dl: Vec<_> = batches
                .iter()
                .flat_map(|b| b.events.iter().map(move |e| (b, &e.event)))
                .filter(|(_, e)| matches!(e, DomainEvent::ArtifactDownloaded(_)))
                .collect();
            assert_eq!(dl.len(), 1, "exactly one ArtifactDownloaded emitted");
            let (batch, ev) = dl[0];
            assert_eq!(batch.stream_id.category, StreamCategory::DownloadAudit);
            assert_ne!(
                batch.stream_id,
                hort_domain::events::StreamId::artifact(repo_id),
                "never the artifact aggregate stream"
            );
            match ev {
                DomainEvent::ArtifactDownloaded(e) => {
                    assert_eq!(e.repository_id, repo_id);
                    assert!(
                        matches!(e.actor, DownloadActor::Anonymous),
                        "anonymous pypi pull → DownloadActor::Anonymous"
                    );
                }
                _ => unreachable!(),
            }
        }

        // -- Virtual (aggregating) download — ADR 0031 --------------------
        //
        // The download handler is transparent (no `Virtual` branch past the
        // source dispatch); these drive `download` end-to-end through
        // `serve_virtual_pypi_file` → `resolve_download` → member sources,
        // reusing this submodule's proxy-upstream helpers for proxy members.

        use hort_domain::entities::artifact::QuarantineStatus;

        /// Seed a hosted pypi member with one file artifact (+ CAS bytes).
        #[allow(clippy::too_many_arguments)]
        fn hosted_member_with_file(
            mocks: &MockPorts,
            key: &str,
            project: &str,
            version: &str,
            filename: &str,
            bytes: &[u8],
            status: QuarantineStatus,
        ) -> Repository {
            use hort_app::use_cases::test_support::sample_artifact;
            let mut repo = sample_repository();
            repo.key = key.into();
            repo.format = RepositoryFormat::Pypi;
            repo.repo_type = RepositoryType::Hosted;
            mocks.repositories.insert(repo.clone());

            let sha256 = format!("{:x}", Sha256::digest(bytes)).parse().unwrap();
            let mut artifact = sample_artifact(status);
            artifact.repository_id = repo.id;
            artifact.name = project.into();
            artifact.version = Some(version.into());
            artifact.path = format!("simple/{project}/{filename}");
            artifact.sha256_checksum = sha256;
            artifact.size_bytes = bytes.len() as i64;
            mocks.artifacts.insert(artifact.clone());
            mocks
                .storage
                .insert_content(artifact.sha256_checksum.clone(), bytes.to_vec());
            repo
        }

        /// Seed an empty hosted pypi member (no artifacts).
        fn empty_hosted_member(mocks: &MockPorts, key: &str) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.into();
            repo.format = RepositoryFormat::Pypi;
            repo.repo_type = RepositoryType::Hosted;
            mocks.repositories.insert(repo.clone());
            repo
        }

        /// Insert a proxy pypi member with an upstream mapping seeded.
        fn proxy_member(mocks: &MockPorts, key: &str) -> Repository {
            let repo = proxy_pypi_repo(key);
            mocks.repositories.insert(repo.clone());
            seed_mapping(mocks, repo.id);
            repo
        }

        /// Seed a `type: virtual` pypi repo aggregating `members` (priority
        /// order, first = highest).
        fn virtual_member_repo(
            mocks: &MockPorts,
            key: &str,
            members: &[&Repository],
        ) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.into();
            repo.format = RepositoryFormat::Pypi;
            repo.repo_type = RepositoryType::Virtual;
            mocks.repositories.insert(repo.clone());
            for m in members {
                mocks.repositories.seed_virtual_member(repo.id, m.id);
            }
            repo
        }

        /// Seed the upstream JSON metadata + file for a proxy member so a
        /// virtual pull through it succeeds (verified).
        fn seed_upstream_file(
            mocks: &MockPorts,
            project: &str,
            version: &str,
            filename: &str,
            bytes: &[u8],
        ) {
            let url = format!("https://files.pythonhosted.org/packages/x/{filename}");
            let sha = format!("{:x}", Sha256::digest(bytes));
            let json = pypi_json(filename, &sha, &url);
            mocks.upstream_proxy.insert_metadata(
                "",
                &format!("/pypi/{project}/{version}/json"),
                json,
            );
            mocks
                .upstream_proxy
                .insert_artifact("", &url, bytes.to_vec());
        }

        async fn get_download(ctx: Arc<AppContext>, path: &str) -> Response {
            router_for(ctx)
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn virtual_download_served_from_hosted_member() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let a = hosted_member_with_file(
                &mocks,
                "pypi-a",
                "req",
                "1.0.0",
                "req-1.0.0.tar.gz",
                b"from-a",
                QuarantineStatus::Released,
            );
            let b = empty_hosted_member(&mocks, "pypi-b");
            virtual_member_repo(&mocks, "pypi-virt", &[&a, &b]);

            let res = get_download(ctx, "/pypi/pypi-virt/simple/req/req-1.0.0.tar.gz").await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&body[..], b"from-a");
        }

        #[tokio::test]
        async fn virtual_download_first_authoritative_prefers_higher_priority() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let hi = hosted_member_with_file(
                &mocks,
                "pypi-hi",
                "req",
                "1.0.0",
                "req-1.0.0.tar.gz",
                b"hi-bytes",
                QuarantineStatus::Released,
            );
            let lo = hosted_member_with_file(
                &mocks,
                "pypi-lo",
                "req",
                "1.0.0",
                "req-1.0.0.tar.gz",
                b"lo-bytes",
                QuarantineStatus::Released,
            );
            virtual_member_repo(&mocks, "pypi-virt", &[&hi, &lo]);

            let res = get_download(ctx, "/pypi/pypi-virt/simple/req/req-1.0.0.tar.gz").await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(
                &body[..],
                b"hi-bytes",
                "highest-priority holder is authoritative"
            );
        }

        #[tokio::test]
        async fn virtual_download_held_primary_returns_503_not_secondary_copy() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let hi = hosted_member_with_file(
                &mocks,
                "pypi-hi",
                "req",
                "1.0.0",
                "req-1.0.0.tar.gz",
                b"held",
                QuarantineStatus::Quarantined,
            );
            let lo = hosted_member_with_file(
                &mocks,
                "pypi-lo",
                "req",
                "1.0.0",
                "req-1.0.0.tar.gz",
                b"released",
                QuarantineStatus::Released,
            );
            virtual_member_repo(&mocks, "pypi-virt", &[&hi, &lo]);

            let res = get_download(ctx, "/pypi/pypi-virt/simple/req/req-1.0.0.tar.gz").await;
            assert_eq!(
                res.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "held primary's gate surfaces; never the secondary's released copy"
            );
        }

        #[tokio::test]
        async fn virtual_download_new_version_pinning_excludes_proxy() {
            // Dependency-confusion regression (new-version): the hosted member
            // OWNS `internalpkg` (has 1.0.0). The proxy upstream WOULD serve
            // `internalpkg@9.9.9` (the attacker's public publish). The virtual
            // MUST 404 — pinning excludes the proxy for the owned name.
            let (ctx, mocks) = build_mock_ctx(handle());
            let private = hosted_member_with_file(
                &mocks,
                "pypi-private",
                "internalpkg",
                "1.0.0",
                "internalpkg-1.0.0.tar.gz",
                b"legit",
                QuarantineStatus::Released,
            );
            let proxy = proxy_member(&mocks, "pypi-proxy");
            seed_upstream_file(
                &mocks,
                "internalpkg",
                "9.9.9",
                "internalpkg-9.9.9.tar.gz",
                b"ATTACKER-PAYLOAD",
            );
            virtual_member_repo(&mocks, "pypi-virt", &[&private, &proxy]);

            let res = get_download(
                ctx,
                "/pypi/pypi-virt/simple/internalpkg/internalpkg-9.9.9.tar.gz",
            )
            .await;
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "owned name: the attacker's proxy-only version is NOT served"
            );
        }

        #[tokio::test]
        async fn virtual_download_unowned_name_served_from_proxy() {
            // Positive control: the hosted member does NOT own `leftpad`, so
            // the proxy participates and serves it (verified pull).
            let (ctx, mocks) = build_mock_ctx(handle());
            let private = hosted_member_with_file(
                &mocks,
                "pypi-private",
                "otherpkg",
                "1.0.0",
                "otherpkg-1.0.0.tar.gz",
                b"x",
                QuarantineStatus::Released,
            );
            let proxy = proxy_member(&mocks, "pypi-proxy");
            seed_upstream_file(
                &mocks,
                "leftpad",
                "1.0.0",
                "leftpad-1.0.0.tar.gz",
                b"LEFTPAD-BYTES",
            );
            virtual_member_repo(&mocks, "pypi-virt", &[&private, &proxy]);

            let res =
                get_download(ctx, "/pypi/pypi-virt/simple/leftpad/leftpad-1.0.0.tar.gz").await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&body[..], b"LEFTPAD-BYTES", "served from the proxy member");
        }

        #[tokio::test]
        async fn virtual_download_missing_everywhere_returns_404() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let a = empty_hosted_member(&mocks, "pypi-a");
            virtual_member_repo(&mocks, "pypi-virt", &[&a]);

            let res =
                get_download(ctx, "/pypi/pypi-virt/simple/missing/missing-1.0.0.tar.gz").await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        // -- Proxy `.metadata` strategy-2 (PEP 658 pull-through) ---------------
        //
        // The PEP 658 `.metadata` strategy-2 dispatch (ADR 0026 + PEP 658
        // §"Specification") fires for proxy repos on cache-miss. The seven
        // tests below pin:
        //
        // 1. Cache hit (wheel + ContentReference both in CAS) → 200
        //    served via the hosted path with no upstream side-effect.
        // 2. Cache miss → pull-through triggered → ingest hook
        //    extracts METADATA into CAS → re-served as 200 + correct
        //    bytes + Content-Digest hash of those bytes.
        // 3. Cache miss + upstream wheel not present → maps to the
        //    same envelope a wheel-download failure would
        //    (`map_upstream_pull_error` reused verbatim).
        // 4. Cache hit + wheel in CAS but no ContentReference (legacy
        //    un-backfilled wheel) → 404, NO implicit on-the-fly
        //    extract (operator runs the wheel-metadata-backfill task).
        // 5. Concurrent requests on cache miss single-flight on the
        //    existing wheel-pull dedup keys — pinned via the
        //    `hort_pull_dedup_total{outcome="follower_waited_hit"}` metric
        //    (the same evidence the upstream_pull test uses).
        // 6. Anti-enumeration on private proxy — anonymous → 404
        //    (Repository NotFound), not 403.
        // 7. Quarantined wheel that DID ingest on the proxy → 503 +
        //    Retry-After (the status filter runs in the use case so
        //    it's repo-type-agnostic).

        mod metadata_strategy2 {
            use super::*;

            use std::sync::Mutex;

            use hort_app::use_cases::test_support::sample_artifact;
            use hort_domain::entities::artifact::QuarantineStatus;
            use hort_domain::entities::repository::{IndexMode, RepositoryFormat, RepositoryType};
            use hort_domain::ports::content_reference_index::{
                ContentReference, ContentReferenceIndex,
            };
            use hort_formats::test_support::build_wheel_zip;

            /// Build a minimal in-memory wheel ZIP whose
            /// `<dist-info>/METADATA` member carries `metadata_bytes`.
            /// Delegates to `hort_formats::test_support::build_wheel_zip`
            /// — the only crate in the workspace allowed to depend on
            /// `zip` directly per `deny.toml`'s wrappers rule. The
            /// METADATA name (`<project>-<version>.dist-info/METADATA`)
            /// matches what `extract_wheel_metadata_bytes` walks the
            /// central directory for.
            fn build_wheel_with_metadata(
                project: &str,
                version: &str,
                metadata_bytes: &[u8],
            ) -> Vec<u8> {
                let dist_info = format!("{project}-{version}.dist-info/METADATA");
                let wheel = format!("{project}-{version}.dist-info/WHEEL");
                build_wheel_zip(&[
                    (dist_info.as_str(), metadata_bytes),
                    (wheel.as_str(), b"Wheel-Version: 1.0\n"),
                ])
            }

            fn proxy_pypi_repo(key: &str) -> Repository {
                let mut r = sample_repository();
                r.key = key.into();
                r.format = RepositoryFormat::Pypi;
                r.repo_type = RepositoryType::Proxy;
                r.upstream_url = Some("https://pypi.org".into());
                r.index_mode = IndexMode::IncludePending;
                r
            }

            /// Build a per-version JSON body the orchestrator's two-leg
            /// pipeline consumes. Single entry — the wheel only; sister
            /// sdist isn't needed for the `.metadata` test surface.
            fn pypi_wheel_json(filename: &str, sha256: &str, url: &str) -> Vec<u8> {
                format!(
                    r#"{{"urls":[{{"filename":"{filename}","url":"{url}","digests":{{"sha256":"{sha256}"}}}}]}}"#,
                )
                .into_bytes()
            }

            /// Test 1 — cache hit on a proxy: wheel + `wheel_metadata`
            /// ContentReference both present in CAS (the ingest hook ran
            /// during a previous ingest). The strategy-2 dispatch's first
            /// `WheelMetadataUseCase::serve` call returns `Available`
            /// and the response is 200 + bytes + Content-Digest with
            /// no upstream side-effect.
            ///
            /// Mirror evidence that the pull-through DID NOT fire: no
            /// `upstream_resolver.insert` (no mapping seeded). If the
            /// dispatch fell through to the pull branch the
            /// orchestrator would return `NoUpstreamMapping` and the
            /// response would be 404 — pinning 200 here pins the
            /// short-circuit.
            #[tokio::test]
            async fn proxy_metadata_cache_hit_serves_local_no_pull_through() {
                let (ctx, mocks) = build_mock_ctx(handle());
                let repo = proxy_pypi_repo("pypi-mirror");
                mocks.repositories.insert(repo.clone());
                // Deliberately NO `seed_mapping` — a fall-through to
                // the pull branch would return 404 here.

                let metadata = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";
                let mut artifact = sample_artifact(QuarantineStatus::None);
                artifact.repository_id = repo.id;
                artifact.name = "example".into();
                artifact.path = "simple/example/example-1.0.0-py3-none-any.whl".into();
                mocks.artifacts.insert(artifact.clone());
                let mut hasher = Sha256::new();
                hasher.update(metadata);
                let hex = format!("{:x}", hasher.finalize());
                let hash: hort_domain::types::ContentHash = hex.parse().unwrap();
                mocks
                    .storage
                    .insert_content(hash.clone(), metadata.to_vec());
                mocks
                    .content_references
                    .insert(ContentReference {
                        source_artifact_id: artifact.id,
                        target_content_hash: hash,
                        kind: "wheel_metadata".into(),
                        metadata: serde_json::json!({}),
                        repository_id: repo.id,
                        recorded_at: Utc::now(),
                    })
                    .await
                    .unwrap();

                let router = router_for(ctx);
                let res = router
                    .oneshot(
                        Request::get(
                            "/pypi/pypi-mirror/simple/example/\
                             example-1.0.0-py3-none-any.whl.metadata",
                        )
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let body = to_bytes(res.into_body(), 8192).await.unwrap();
                assert_eq!(body.as_ref(), metadata);
            }

            /// Test 2 — cache miss → strategy-2 pull-through →
            /// re-serve. The wheel is constructed as a real ZIP with
            /// a `<dist-info>/METADATA` member; the ingest hook
            /// extracts those bytes during `try_upstream_file_pull`
            /// and writes them to CAS + a `wheel_metadata`
            /// ContentReference. The re-serve returns 200 + the
            /// extracted bytes + a Content-Digest hash matching their
            /// SHA-256.
            #[tokio::test]
            async fn proxy_metadata_cache_miss_pulls_wheel_then_serves_extracted_metadata() {
                use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
                let (ctx, mocks) = build_mock_ctx(handle());
                let repo = proxy_pypi_repo("pypi-mirror");
                mocks.repositories.insert(repo.clone());
                seed_mapping(&mocks, repo.id);

                let metadata_bytes =
                    b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\nRequires-Python: >=3.8\n";
                let wheel_bytes = build_wheel_with_metadata("example", "1.0.0", metadata_bytes);
                let wheel_sha = format!("{:x}", Sha256::digest(&wheel_bytes));
                let wheel_url =
                    "https://files.pythonhosted.org/packages/abc/example-1.0.0-py3-none-any.whl";
                let json = pypi_wheel_json("example-1.0.0-py3-none-any.whl", &wheel_sha, wheel_url);
                mocks
                    .upstream_proxy
                    .insert_metadata("", "/pypi/example/1.0.0/json", json);
                mocks
                    .upstream_proxy
                    .insert_artifact("", wheel_url, wheel_bytes);

                let router = router_for(ctx);
                let res = router
                    .oneshot(
                        Request::get(
                            "/pypi/pypi-mirror/simple/example/\
                             example-1.0.0-py3-none-any.whl.metadata",
                        )
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let cd = res
                    .headers()
                    .get("Content-Digest")
                    .and_then(|v| v.to_str().ok())
                    .expect("Content-Digest must be present")
                    .to_string();
                let body = to_bytes(res.into_body(), 8192).await.unwrap();
                // Bytes equal the METADATA member packed inside the wheel.
                assert_eq!(body.as_ref(), metadata_bytes);
                // Content-Digest carries the SHA-256 of those bytes —
                // the load-bearing PEP 658 + RFC 9530 client-verification
                // invariant the simple-index advertisement will also
                // publish.
                let expected_metadata_hex = format!("{:x}", Sha256::digest(metadata_bytes));
                let inner = cd
                    .strip_prefix("sha256=:")
                    .and_then(|s| s.strip_suffix(':'))
                    .unwrap();
                let raw = BASE64_STANDARD.decode(inner).unwrap();
                let round_trip_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(round_trip_hex, expected_metadata_hex);
            }

            /// Test 3 — cache miss + upstream returns no wheel. The
            /// orchestrator surfaces `MetadataFetchFailed{stage:"file"}`
            /// (the wheel URL was never seeded via
            /// `insert_artifact`), and the wire-map (the same
            /// `map_upstream_pull_error` the wheel-download branch
            /// uses) renders 502 + `X-Hort-Reason: upstream-metadata-
            /// fetch-failed-file`. The `.metadata` response shape
            /// MUST match the wheel-download shape for the same
            /// failure, so clients seeing a 502 on the wheel URL also
            /// see a 502 on the `.metadata` URL.
            #[tokio::test]
            async fn proxy_metadata_cache_miss_upstream_wheel_missing_returns_502() {
                let (ctx, mocks) = build_mock_ctx(handle());
                let repo = proxy_pypi_repo("pypi-mirror");
                mocks.repositories.insert(repo.clone());
                seed_mapping(&mocks, repo.id);

                // Seed the JSON metadata so the first leg succeeds; do
                // NOT seed the wheel artifact so the second leg fails
                // with `upstream:not_found:mock artifact ...`.
                let wheel_url =
                    "https://files.pythonhosted.org/packages/abc/example-1.0.0-py3-none-any.whl";
                let json = pypi_wheel_json(
                    "example-1.0.0-py3-none-any.whl",
                    &format!("{:x}", Sha256::digest(b"unused")),
                    wheel_url,
                );
                mocks
                    .upstream_proxy
                    .insert_metadata("", "/pypi/example/1.0.0/json", json);

                let router = router_for(ctx);
                let res = router
                    .oneshot(
                        Request::get(
                            "/pypi/pypi-mirror/simple/example/\
                             example-1.0.0-py3-none-any.whl.metadata",
                        )
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
                assert_eq!(
                    res.headers()
                        .get("X-Hort-Reason")
                        .and_then(|v| v.to_str().ok()),
                    Some("upstream-metadata-fetch-failed-file"),
                );
            }

            /// Test 4 — wheel IS in CAS on a proxy but has no
            /// `wheel_metadata` ContentReference row (legacy un-backfilled
            /// wheel, or the ingest hook returned `None`). The dispatch
            /// must NOT pull (the wheel is already local), so the absence
            /// of an upstream mapping would normally fail loudly via
            /// `NoUpstreamMapping` — but the disambiguation in
            /// `serve_proxy_with_pull_fallback` catches this case and
            /// returns 404 without firing the pull. The operator's recourse
            /// is the wheel-metadata-backfill task.
            #[tokio::test]
            async fn proxy_metadata_cache_hit_no_content_reference_returns_404_no_pull() {
                let (ctx, mocks) = build_mock_ctx(handle());
                let repo = proxy_pypi_repo("pypi-mirror");
                mocks.repositories.insert(repo.clone());
                // Deliberately NO `seed_mapping` — if the pull branch
                // fires, the orchestrator returns `NoUpstreamMapping`
                // and the response becomes 404 BUT via a different
                // envelope (the `package not found` body). The
                // assertion below is on status only, so we belt-and-
                // brace with an audit assertion: NO transitions
                // recorded means no ingest fired.

                // Seed the wheel artifact and CAS bytes — but NO
                // wheel_metadata ContentReference row.
                let mut artifact = sample_artifact(QuarantineStatus::None);
                artifact.repository_id = repo.id;
                artifact.name = "legacy".into();
                artifact.path = "simple/legacy/legacy-1.0.0-py3-none-any.whl".into();
                mocks.artifacts.insert(artifact.clone());
                mocks.storage.insert_content(
                    artifact.sha256_checksum.clone(),
                    b"legacy wheel body".to_vec(),
                );

                let lifecycle = mocks.lifecycle.clone();

                let router = router_for(ctx);
                let res = router
                    .oneshot(
                        Request::get(
                            "/pypi/pypi-mirror/simple/legacy/\
                             legacy-1.0.0-py3-none-any.whl.metadata",
                        )
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::NOT_FOUND);

                // No ingest fired — the disambiguation short-circuited
                // before reaching `try_upstream_file_pull`.
                assert!(
                    lifecycle.committed_transitions().is_empty(),
                    "legacy un-backfilled wheel MUST NOT trigger pull-through; \
                     no commit_transition expected, got {:?}",
                    lifecycle.committed_transitions()
                );
            }

            /// Test 5 — concurrent `.metadata` requests for the same
            /// wheel on a proxy cache miss must single-flight: exactly
            /// ONE wheel pull, exactly ONE ingest, despite TWO
            /// concurrent requests.
            ///
            /// Why no new `DedupKey::MetadataFile` variant is needed:
            /// the strategy-2 dispatch converges concurrent metadata
            /// requests onto the same wheel pull. Two paths combine
            /// to single-flight the wheel fetch:
            ///
            /// 1. **PullDedup at the wheel-fetch boundary** — the
            ///    orchestrator wraps the JSON metadata leg in
            ///    `DedupKey::metadata("pypi", repo_id, path)` and the
            ///    wheel blob leg in `DedupKey::blob_by_hash("sha256",
            ///    hex)`. Concurrent callers reaching `try_upstream_file_pull`
            ///    coalesce on those existing keys.
            /// 2. **Application-layer cache-hit short-circuit** — once
            ///    the first pull completes, the wheel + metadata
            ///    ContentReference are in CAS; the second call's
            ///    `WheelMetadataUseCase::serve` returns `Available`
            ///    directly without entering the pull branch at all.
            ///    This is a STRONGER form of single-flight than dedup
            ///    (no PullDedup invocation on the second call).
            ///
            /// Mode 2 fires when the second call arrives after the
            /// first completes (current-thread runtime, serialised
            /// awaits inside `try_upstream_file_pull`). The metric
            /// snapshot pins both behaviours:
            ///
            /// - `hort_pull_dedup_total{outcome="leader_started"}` for
            ///   the wheel-blob keyspace (`format="_any"`) is exactly
            ///   1 — no duplicate election fired.
            /// - `hort_ingest_total{result="success"}` is exactly 1 —
            ///   no duplicate ingest fired.
            /// - `hort_upstream_checksum_total{result="verified"}` is
            ///   exactly 1 — no duplicate verification fired.
            ///
            /// Mirrors the metric-harness pattern in
            /// `upstream_pull::tests::concurrent_blob_callers_coalesce_into_one_leader_started`.
            #[test]
            fn proxy_metadata_concurrent_requests_singleflight_one_pull_per_wheel() {
                use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
                use metrics_util::CompositeKey;

                type SnapshotRow = (
                    CompositeKey,
                    Option<metrics::Unit>,
                    Option<metrics::SharedString>,
                    DebugValue,
                );

                fn sum_counter_with_labels(
                    rows: &[SnapshotRow],
                    name: &str,
                    label_matches: &[(&str, &str)],
                ) -> u64 {
                    let mut total = 0u64;
                    for (ckey, _u, _d, value) in rows {
                        let k = ckey.key();
                        if k.name() != name {
                            continue;
                        }
                        let all_match = label_matches.iter().all(|(want_k, want_v)| {
                            k.labels()
                                .any(|l| l.key() == *want_k && l.value() == *want_v)
                        });
                        if all_match {
                            if let DebugValue::Counter(n) = value {
                                total = total.saturating_add(*n);
                            }
                        }
                    }
                    total
                }

                let recorder = DebuggingRecorder::new();
                let snapshotter: Snapshotter = recorder.snapshotter();
                let _captured: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

                metrics::with_local_recorder(&recorder, || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async {
                            let (ctx, mocks) = build_mock_ctx(handle());
                            let repo = proxy_pypi_repo("pypi-mirror");
                            mocks.repositories.insert(repo.clone());
                            seed_mapping(&mocks, repo.id);

                            let metadata_bytes =
                                b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";
                            let wheel_bytes =
                                build_wheel_with_metadata("example", "1.0.0", metadata_bytes);
                            let wheel_sha = format!("{:x}", Sha256::digest(&wheel_bytes));
                            let wheel_url = "https://files.pythonhosted.org/packages/abc/\
                                             example-1.0.0-py3-none-any.whl";
                            let json = pypi_wheel_json(
                                "example-1.0.0-py3-none-any.whl",
                                &wheel_sha,
                                wheel_url,
                            );
                            mocks.upstream_proxy.insert_metadata(
                                "",
                                "/pypi/example/1.0.0/json",
                                json,
                            );
                            mocks
                                .upstream_proxy
                                .insert_artifact("", wheel_url, wheel_bytes);

                            let ctx_a = ctx.clone();
                            let h1 = tokio::spawn(async move {
                                let router = router_for(ctx_a);
                                router
                                    .oneshot(
                                        Request::get(
                                            "/pypi/pypi-mirror/simple/example/\
                                             example-1.0.0-py3-none-any.whl.metadata",
                                        )
                                        .body(Body::empty())
                                        .unwrap(),
                                    )
                                    .await
                                    .unwrap()
                            });
                            let ctx_b = ctx.clone();
                            let h2 = tokio::spawn(async move {
                                let router = router_for(ctx_b);
                                router
                                    .oneshot(
                                        Request::get(
                                            "/pypi/pypi-mirror/simple/example/\
                                             example-1.0.0-py3-none-any.whl.metadata",
                                        )
                                        .body(Body::empty())
                                        .unwrap(),
                                    )
                                    .await
                                    .unwrap()
                            });

                            let r1 = h1.await.unwrap();
                            let r2 = h2.await.unwrap();
                            assert_eq!(r1.status(), StatusCode::OK);
                            assert_eq!(r2.status(), StatusCode::OK);
                        });
                });

                let snap: Vec<SnapshotRow> = snapshotter.snapshot().into_vec();
                // Exactly one wheel-blob leader election (format="_any"
                // is the cross-format hash-keyed namespace used by
                // DedupKey::blob_by_hash). If the second call had
                // re-entered try_upstream_file_pull, this would be 2.
                let wheel_blob_leader = sum_counter_with_labels(
                    &snap,
                    "hort_pull_dedup_total",
                    &[("outcome", "leader_started"), ("format", "_any")],
                );
                assert_eq!(
                    wheel_blob_leader, 1,
                    "concurrent .metadata requests on a cache-miss MUST single-flight \
                     the wheel pull (exactly one leader_started for the wheel-blob \
                     dedup key); got {wheel_blob_leader}, snap: {snap:?}"
                );
                // Exactly one ingest_verified completion — proves no
                // duplicate CAS write fired even though both requests
                // were in flight.
                let ingest_success = sum_counter_with_labels(
                    &snap,
                    "hort_ingest_total",
                    &[("result", "success"), ("format", "pypi")],
                );
                assert_eq!(
                    ingest_success, 1,
                    "concurrent .metadata requests MUST produce exactly one \
                     successful ingest; got {ingest_success}, snap: {snap:?}"
                );
                // Exactly one upstream checksum verification — proves
                // we didn't redundantly rehash the wheel.
                let checksum_verified = sum_counter_with_labels(
                    &snap,
                    "hort_upstream_checksum_total",
                    &[("result", "verified"), ("format", "pypi")],
                );
                assert_eq!(
                    checksum_verified, 1,
                    "concurrent .metadata requests MUST produce exactly one \
                     verified checksum; got {checksum_verified}, snap: {snap:?}"
                );
            }

            /// Test 6 — anti-enumeration on a private proxy.
            /// Anonymous caller → 404 (Repository NotFound),
            /// byte-identical to a missing-repo response. The visibility
            /// hop in `repository_access_use_case.resolve` runs BEFORE
            /// the proxy dispatch, so anonymous callers never trigger
            /// the pull-through.
            #[tokio::test]
            async fn proxy_metadata_anonymous_on_private_proxy_returns_404() {
                use hort_app::rbac::RbacEvaluator;
                use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
                use hort_http_core::test_support::with_repository_access;

                let (ctx, mocks) = build_mock_ctx(handle());
                let mut repo = proxy_pypi_repo("private-proxy");
                repo.is_public = false;
                mocks.repositories.insert(repo);

                // Flip to enabled-RBAC with an empty evaluator so the
                // private repo is invisible to anonymous callers.
                let access = Arc::new(RepositoryAccessUseCase::new(
                    mocks.repositories.clone(),
                    RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                        RbacEvaluator::new(Vec::new()),
                    ))),
                    true,
                ));
                let ctx = with_repository_access(&ctx, access);

                let router = router_for(ctx);
                let res = router
                    .oneshot(
                        Request::get(
                            "/pypi/private-proxy/simple/secret/\
                             secret-1.0.0-py3-none-any.whl.metadata",
                        )
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    res.status(),
                    StatusCode::NOT_FOUND,
                    "anonymous .metadata on private proxy MUST be 404 \
                     (anti-enumeration), never 403"
                );
            }

            /// Test 7 — quarantined wheel that DID ingest into a proxy
            /// (e.g. an earlier pull-through completed before the
            /// quarantine fired). The `.metadata` cache hit returns
            /// 503 + Retry-After via the use-case's status filter —
            /// repo-type-agnostic, so proxy and hosted behave the same.
            #[tokio::test]
            async fn proxy_metadata_quarantined_wheel_returns_503_with_retry_after() {
                let (ctx, mocks) = build_mock_ctx(handle());
                let repo = proxy_pypi_repo("pypi-mirror");
                mocks.repositories.insert(repo.clone());

                let metadata = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";
                let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
                artifact.repository_id = repo.id;
                artifact.name = "example".into();
                artifact.path = "simple/example/example-1.0.0-py3-none-any.whl".into();
                mocks.artifacts.insert(artifact.clone());
                let mut hasher = Sha256::new();
                hasher.update(metadata);
                let hex = format!("{:x}", hasher.finalize());
                let hash: hort_domain::types::ContentHash = hex.parse().unwrap();
                mocks
                    .storage
                    .insert_content(hash.clone(), metadata.to_vec());
                mocks
                    .content_references
                    .insert(ContentReference {
                        source_artifact_id: artifact.id,
                        target_content_hash: hash,
                        kind: "wheel_metadata".into(),
                        metadata: serde_json::json!({}),
                        repository_id: repo.id,
                        recorded_at: Utc::now(),
                    })
                    .await
                    .unwrap();

                let router = router_for(ctx);
                let res = router
                    .oneshot(
                        Request::get(
                            "/pypi/pypi-mirror/simple/example/\
                             example-1.0.0-py3-none-any.whl.metadata",
                        )
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert!(
                    res.headers().get("Retry-After").is_some(),
                    "quarantined wheel .metadata on proxy MUST emit Retry-After"
                );
            }
        }
    }

    // -- upload filename validation (security audit 015) --------------

    /// Helper: build a PyPI publish multipart with a caller-chosen
    /// `filename` on the `content` field. `build_multipart_body` hard-codes
    /// `e2e-pkg-1.0.tar.gz` — these tests need to drive arbitrary
    /// (including hostile) filenames through the handler's validation.
    fn build_publish_multipart_with_filename(
        boundary: &str,
        filename: &str,
        file_bytes: &[u8],
    ) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let push_field = |buf: &mut Vec<u8>, name: &str, value: &str| {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        };
        push_field(&mut body, "name", "evil_pkg");
        push_field(&mut body, "version", "1.0");
        push_field(&mut body, ":action", "file_upload");
        // Emit the required `sha256_digest` verification target computed
        // over the embedded content, so happy-path upload tests keep
        // exercising the success branch (the verified-ingest re-anchor
        // lives at the builder level — not at every call site).
        // See `content_sha256_hex`.
        push_field(&mut body, "sha256_digest", &content_sha256_hex(file_bytes));
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// Drive an upload with the given multipart `filename` and return the
    /// response status.
    async fn post_upload_with_filename(filename: &str) -> StatusCode {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());
        let boundary = "----hortfiletest";
        let body = build_publish_multipart_with_filename(boundary, filename, b"payload");
        router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn upload_to_virtual_repo_is_rejected() {
        // Virtual repos are read-only aggregators (ADR 0031): an upload must
        // be rejected, not silently written to the virtual's own store.
        let h = harness();
        let mut repo = sample_repository();
        repo.key = "pypi-virt".into();
        repo.format = RepositoryFormat::Pypi;
        repo.repo_type = RepositoryType::Virtual;
        h.repositories.insert(repo);
        let router = router(h.ctx.clone());
        let boundary = "----hortvirttest";
        let body = build_publish_multipart_with_filename(boundary, "req-1.0.0.tar.gz", b"payload");
        let res = router
            .oneshot(
                Request::post("/pypi/pypi-virt/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// Filenames containing path separators must be rejected with 400 —
    /// they end up in the stored `Artifact.path` and are rendered back
    /// into simple-index URLs, so accepting them gives an attacker
    /// control over both the DB row's path column and the emitted HTML.
    /// CAS storage is hash-keyed so the on-disk layout is safe, but the
    /// logical-path surface is attacker-visible and must be constrained.
    #[tokio::test]
    async fn publish_rejects_filename_with_forward_slash() {
        assert_eq!(
            post_upload_with_filename("../evil-1.0.tar.gz").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn publish_rejects_filename_with_backslash() {
        assert_eq!(
            post_upload_with_filename("evil\\1.0.tar.gz").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn publish_rejects_filename_with_parent_segment() {
        // `..` without a slash still expresses traversal intent when
        // concatenated into a path template. Rejecting the literal
        // segment is cheaper than parsing the full path and safer than
        // relying on downstream consumers to normalise.
        assert_eq!(
            post_upload_with_filename("..").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn publish_rejects_filename_with_null_byte() {
        assert_eq!(
            post_upload_with_filename("evil\0.tar.gz").await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn publish_rejects_empty_filename() {
        // An empty filename would collapse the path template to
        // `simple/{name}/` with a trailing slash — a degenerate shape
        // that neither PyPI nor our own index handler expects.
        assert_eq!(post_upload_with_filename("").await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_accepts_legitimate_filename() {
        // Regression guard: the tightening must not break real clients.
        // twine always sends `{name}-{version}.tar.gz` or
        // `{name}-{version}-{py}-{abi}-{platform}.whl` — both are
        // slash-free, non-empty, and contain no `..` segments.
        assert_eq!(
            post_upload_with_filename("evil_pkg-1.0.tar.gz").await,
            StatusCode::OK
        );
    }

    // -- publish-handler validators (name / version / filename) ---------------
    //
    // The PyPI download path calls `validate_pep_503_name` /
    // `validate_pypi_filename`; the publish path does too, plus a new
    // `validate_pypi_version` charset gate. These three tests pin the
    // publish-side promotion: each rejection case proves storage is never
    // touched when a validator fires (fail closed before any side-effecting
    // action), and the happy-path regression catches anyone re-introducing
    // a wildcard bypass.
    //
    // The weaker `validate_publish_filename` that previously sat in
    // this crate is gone — `validate_pypi_filename` covers and exceeds
    // it (charset allowlist, byte cap, control-byte rejection).

    /// Helper: build a PyPI publish multipart with caller-chosen
    /// `name`, `version`, and `filename` fields. Wraps the existing
    /// `build_publish_multipart_with_filename` shape so we can drive
    /// hostile values through name/version too.
    fn build_publish_multipart_full(
        boundary: &str,
        name: &str,
        version: &str,
        filename: &str,
        file_bytes: &[u8],
    ) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let push_field = |buf: &mut Vec<u8>, name: &str, value: &str| {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        };
        push_field(&mut body, "name", name);
        push_field(&mut body, "version", version);
        push_field(&mut body, ":action", "file_upload");
        // Required `sha256_digest` over the content
        // (builder-level re-anchor; see `content_sha256_hex`).
        push_field(&mut body, "sha256_digest", &content_sha256_hex(file_bytes));
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// `name = "foo@bar"` violates the PEP 503 charset (`@` is outside
    /// `[A-Za-z0-9_.-]`) and must be rejected at the validator. Pins
    /// the audit invariant that storage is never touched on rejection.
    #[tokio::test]
    async fn publish_rejects_invalid_name_returns_400() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        let boundary = "----hortm-a7-name";
        let body = build_publish_multipart_full(
            boundary,
            "foo@bar",
            "1.0.0",
            "foo-bar-1.0.0.tar.gz",
            b"payload",
        );

        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Audit invariant: validator short-circuits before the
        // ingest use case is awaited, so no storage write is ever
        // attempted.
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "validator must short-circuit before any storage.put"
        );
    }

    /// `version = "1.0\r\nInjected"` carries a CRLF that would survive
    /// into headers / log lines if accepted. The new
    /// `validate_pypi_version` charset gate must catch it before any
    /// side-effecting action.
    #[tokio::test]
    async fn publish_rejects_invalid_version_returns_400() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        let boundary = "----hortm-a7-ver";
        let body = build_publish_multipart_full(
            boundary,
            "valid_pkg",
            "1.0\r\nInjected",
            "valid_pkg-1.0.0.tar.gz",
            b"payload",
        );

        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "validator must short-circuit before any storage.put"
        );
    }

    /// Happy-path regression — a valid `name`/`version`/`file_name`
    /// triple flows through every validator unchanged and the publish
    /// completes with 200.
    #[tokio::test]
    async fn publish_valid_name_version_filename_returns_200() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        let boundary = "----hortm-a7-ok";
        let body = build_publish_multipart_full(
            boundary,
            "valid_pkg",
            "1.0.0",
            "valid_pkg-1.0.0.tar.gz",
            b"payload",
        );

        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Twine `POST /:repo/` upload hits a curation `Block` rule.
    /// PyPI has only the client-upload path (no pull-through fetch
    /// handler today), so the default `DomainError::CurationBlocked` → 403
    /// mapping in `hort_http_core::error::ApiError::into_response` applies.
    /// `build_publish_multipart_with_filename` hard-codes
    /// `name = "evil_pkg"`, which the handler PEP 503 normalises to
    /// `evil-pkg` — that is the value `coords.name` carries into the
    /// curation evaluator, so the rule pattern targets the normalised form.
    #[tokio::test]
    async fn upload_curation_block_returns_403() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;

        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let rule = CurationRule {
            id: Uuid::new_v4(),
            name: "block-evil-pkg".into(),
            format: None,
            package_pattern: "evil-pkg".into(),
            action: CurationRuleAction::Block,
            reason: "known-malicious".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        h.curation_rules.set_rules_for_repo(repo.id, vec![rule]);
        let router = router(h.ctx.clone());

        let boundary = "----hortcurationtest";
        let body =
            build_publish_multipart_with_filename(boundary, "evil_pkg-1.0.tar.gz", b"payload");
        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "client-upload publish keeps the default 403 mapping"
        );
        let body_bytes = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("block-evil-pkg"));
        assert!(body_str.contains("known-malicious"));
    }

    // -- Verified direct upload (require sha256_digest) -------------------------
    //
    // PyPI twine `POST {repo}/` legacy-form uploads route through
    // the upstream-verification framework (ADR 0006)
    // (`IngestUseCase::ingest_verified`, `VerifiedIngestRequest::
    // ProtocolNative`). The client-declared `sha256_digest` form field is the
    // verification target — checked against the CAS-computed hash. The digest
    // is REQUIRED: an upload that omits it is rejected 400 (a deliberately
    // stronger stance than the "accept absent" default).
    //
    // These four tests pin the contract. They build their own multipart bodies
    // with/without the digest so they are independent of the shared-builder
    // re-anchoring (the builders include a computed `sha256_digest` so the
    // bulk of pre-existing upload tests keep passing the happy path).

    /// Build a PyPI publish multipart with an optional `sha256_digest`
    /// form field. `digest = Some(hex)` emits the dedicated branch's
    /// verification target; `None` omits it entirely (the require-digest
    /// reject path). Mirrors `build_multipart_body`'s `name`/`version`/
    /// `content` shape so only the digest dimension varies.
    fn build_multipart_with_digest(
        boundary: &str,
        file_bytes: &[u8],
        digest: Option<&str>,
    ) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let push_field = |buf: &mut Vec<u8>, name: &str, value: &str| {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        };
        push_field(&mut body, "name", "e2e_pkg");
        push_field(&mut body, "version", "1.0");
        push_field(&mut body, ":action", "file_upload");
        if let Some(hex) = digest {
            push_field(&mut body, "sha256_digest", hex);
        }
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"content\"; filename=\"e2e-pkg-1.0.tar.gz\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// Drive a publish through the handler with the given body and
    /// return the full `Response`.
    async fn post_publish(h: &TestHarness, boundary: &str, body: Vec<u8>) -> Response {
        let router = router(h.ctx.clone());
        router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Match: `sha256_digest = sha256(content)` → 200. The blob lands in
    /// the CAS at its computed hash and `ArtifactIngested +
    /// ChecksumVerified` ride atomically in the same `commit_transition`
    /// batch on the artifact stream (the "atomic with the mint" invariant,
    /// ADR 0006). Mirrors `framework_invariant_happy_path_emits_
    /// checksum_verified_and_writes_cas` for the direct-upload path.
    #[tokio::test]
    async fn verified_upload_matching_digest_returns_200_and_emits_checksum_verified() {
        use hort_domain::events::StreamCategory;
        use hort_domain::types::ContentHash;
        use sha2::{Digest, Sha256};

        let h = harness();
        insert_repo(&h, "pypi-test");

        let content = b"verified-direct-upload-body".to_vec();
        let sha = format!("{:x}", Sha256::digest(&content));

        let boundary = "----hortinit54-match";
        let body = build_multipart_with_digest(boundary, &content, Some(&sha));
        let res = post_publish(&h, boundary, body).await;
        assert_eq!(res.status(), StatusCode::OK);

        // The blob is recoverable from the CAS at its computed hash.
        let expected_hash: ContentHash = sha.parse().expect("sha must parse as ContentHash");
        let stored = h.storage.stored_hashes();
        assert!(
            stored.contains(&expected_hash),
            "uploaded body must be stored at its computed hash; stored: {stored:?}"
        );

        // ArtifactIngested + ChecksumVerified ride atomically in the
        // SAME commit_transition batch on the artifact stream.
        let transitions = h.lifecycle.committed_transitions();
        assert_eq!(
            transitions.len(),
            1,
            "exactly one commit_transition on the verified-upload happy path"
        );
        let (_artifact, batch, _meta) = &transitions[0];
        assert_eq!(
            batch.stream_id.category,
            StreamCategory::Artifact,
            "ingest commit must land on the artifact stream"
        );
        let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
        assert!(
            kinds.contains(&"ArtifactIngested") && kinds.contains(&"ChecksumVerified"),
            "ArtifactIngested + ChecksumVerified must ride atomically in the same batch; got {kinds:?}"
        );
    }

    /// Mismatch: `sha256_digest` is well-formed but disagrees with the
    /// uploaded bytes → 409 (the verified-ingest mismatch maps to
    /// `DomainError::Conflict`). No artifact row is minted and the
    /// rehashed blob is rolled back out of the CAS. `ChecksumMismatch`
    /// rides once on the repository stream; `ChecksumVerified` /
    /// `ArtifactIngested` never fire. Mirrors
    /// `framework_invariant_tampered_file_emits_mismatch_and_rolls_back_cas`.
    #[tokio::test]
    async fn verified_upload_mismatched_digest_returns_409_and_rolls_back_cas() {
        use hort_domain::events::{DomainEvent, StreamCategory};
        use sha2::{Digest, Sha256};

        let h = harness();
        insert_repo(&h, "pypi-test");

        let content = b"actual-upload-bytes".to_vec();
        // Well-formed sha256 hex that does NOT match `content`.
        let lying_sha = format!("{:x}", Sha256::digest(b"different-bytes"));

        let boundary = "----hortinit54-mismatch";
        let body = build_multipart_with_digest(boundary, &content, Some(&lying_sha));
        let res = post_publish(&h, boundary, body).await;
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "checksum mismatch maps to 409 via DomainError::Conflict"
        );

        // No artifact row minted (mint-after-verify).
        assert!(
            h.lifecycle.committed_transitions().is_empty(),
            "mismatch must not mint an artifact row; got {} commit(s)",
            h.lifecycle.committed_transitions().len()
        );

        // CAS rollback: the rehashed bytes were put once then deleted.
        assert_eq!(
            h.storage.put_call_count(),
            1,
            "exactly one put (the rehash) on the mismatch path"
        );
        assert_eq!(
            h.storage.delete_call_count(),
            1,
            "rollback must delete the rehashed bytes from the CAS"
        );

        // ChecksumMismatch rides exactly once, on the repository stream.
        let batches = h.events.appended_batches();
        let mismatch_total = batches
            .iter()
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
            .count();
        assert_eq!(mismatch_total, 1, "exactly one ChecksumMismatch");
        let mismatch_on_repo = batches
            .iter()
            .filter(|b| b.stream_id.category == StreamCategory::Repository)
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
            .count();
        assert_eq!(
            mismatch_on_repo, 1,
            "ChecksumMismatch must ride on the repository stream"
        );

        // ChecksumVerified + ArtifactIngested never fire.
        let verified = batches
            .iter()
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
            .count();
        assert_eq!(verified, 0, "ChecksumVerified must NOT fire on mismatch");
        let ingested = batches
            .iter()
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
            .count();
        assert_eq!(ingested, 0, "ArtifactIngested must NOT fire on mismatch");
    }

    /// Absent digest: the `sha256_digest` field is omitted entirely →
    /// 400. This pins the maintainer's REQUIRED-digest decision as a
    /// deliberate policy (reads as a decision, not an accident). No
    /// storage write is attempted — the require-digest check fires after
    /// the field-presence + validator checks but before ingest.
    #[tokio::test]
    async fn verified_upload_absent_digest_returns_400() {
        let h = harness();
        insert_repo(&h, "pypi-test");

        let content = b"body-without-a-declared-digest".to_vec();
        let boundary = "----hortinit54-absent";
        let body = build_multipart_with_digest(boundary, &content, None);
        let res = post_publish(&h, boundary, body).await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "a direct upload that omits sha256_digest is rejected (REQUIRED policy)"
        );

        // The require-digest check short-circuits before any storage write.
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "no storage.put may run when the required digest is absent"
        );

        // Body shape is the `validation_error` envelope. `DomainError::
        // Validation`'s Display prefixes `validation: `, so the wire body
        // is `{"error":"validation: missing field: sha256_digest"}`.
        let body_bytes = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "validation: missing field: sha256_digest");
    }

    /// Malformed digest: `sha256_digest = "nothex"` is not a valid
    /// 64-char lowercase hex SHA-256 → 400. The `ContentHash` parse
    /// rejects it via `validation_error` before ingest is invoked, so no
    /// storage write happens.
    #[tokio::test]
    async fn verified_upload_malformed_digest_returns_400() {
        let h = harness();
        insert_repo(&h, "pypi-test");

        let content = b"body-with-a-malformed-digest".to_vec();
        let boundary = "----hortinit54-malformed";
        let body = build_multipart_with_digest(boundary, &content, Some("nothex"));
        let res = post_publish(&h, boundary, body).await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "a malformed sha256_digest is rejected at the ContentHash parse"
        );
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "no storage.put may run when the declared digest is malformed"
        );
    }

    // -- upload body-size + multipart-field caps -------------------------------------

    /// Build a multipart body with a caller-supplied number of trivial
    /// `meta_<i>` fields, followed by a valid `name`/`version`/`content`
    /// triple so the happy-path variant succeeds with `field_count <
    /// MAX_MULTIPART_FIELDS`. Used by the field-cap reject test below.
    fn build_multipart_with_n_meta_fields(boundary: &str, n_meta: usize) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let push_text = |buf: &mut Vec<u8>, name: &str, value: &str| {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        };
        for i in 0..n_meta {
            push_text(&mut body, &format!("meta_{i}"), "v");
        }
        push_text(&mut body, "name", "e2e_pkg");
        push_text(&mut body, "version", "1.0");
        push_text(&mut body, ":action", "file_upload");
        // Required `sha256_digest` over the hard-coded `b"payload"` content
        // (builder-level re-anchor). This counts as one multipart field;
        // the field-cap tests account for it in their `n_meta` choice
        // (see their per-test field-count maths).
        push_text(&mut body, "sha256_digest", &content_sha256_hex(b"payload"));
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"content\"; filename=\"e2e-pkg-1.0.tar.gz\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(b"payload");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// 101 multipart fields → 400 + the exact JSON body (load-bearing;
    /// native clients may match on the string `"too many multipart fields"`).
    #[tokio::test]
    async fn publish_rejects_multipart_field_count_over_cap() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        // 96 meta + (name, version, :action, sha256_digest, content) = 101
        // fields. With MAX_MULTIPART_FIELDS = 100, the 101st field trips
        // the cap. (The required `sha256_digest` field means 96 meta
        // where earlier builds used 97.)
        let boundary = "----hortfieldcap";
        let body = build_multipart_with_n_meta_fields(boundary, 96);

        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");

        let body_bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(
            body_bytes.as_ref(),
            br#"{"error":"too many multipart fields"}"#.as_ref(),
            "reject body shape is load-bearing — native clients may match on it"
        );
    }

    /// Exactly 100 fields stays under the cap. Regression guard against
    /// an off-by-one (e.g. `>=` instead of `>`) that would reject the
    /// boundary case.
    #[tokio::test]
    async fn publish_accepts_multipart_at_field_cap() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        // 95 meta + (name, version, :action, sha256_digest, content) = 100
        // fields. (The required `sha256_digest` field means 95 meta
        // where earlier builds used 96.)
        let boundary = "----hortfieldcap-ok";
        let body = build_multipart_with_n_meta_fields(boundary, 95);

        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // OK — 100 fields is the ceiling, not over it.
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Upload body > route's `DefaultBodyLimit::max` → 413 Payload Too
    /// Large from axum's built-in rejection. Uses a 1 KiB limit so we
    /// don't have to ship 300 MiB in a unit test.
    #[tokio::test]
    async fn publish_body_exceeding_limit_is_rejected() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router_with_publish_limit(h.ctx.clone(), 1024);

        let boundary = "----hortbodylimit";
        // 4 KiB payload dwarfs the 1 KiB cap; no multipart-format
        // niceties matter because axum rejects before reading bytes.
        let big_payload = vec![0u8; 4096];
        let body = build_multipart_body(boundary, &big_payload);

        let res = router
            .oneshot(
                Request::post("/pypi/pypi-test/")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // -- route-parameter length cap ---------------------------------------------------

    /// A package name past the 512-byte cap → 400 + stable JSON body
    /// naming the offending parameter.
    #[tokio::test]
    async fn download_rejects_oversized_package_name() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        // 1 KiB > MAX_ROUTE_PARAM_BYTES (512).
        let huge = "a".repeat(1024);
        let res = router
            .oneshot(
                Request::get(format!("/pypi/pypi-test/simple/{huge}/file.tar.gz"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        assert_eq!(json["parameter"], "project");
    }

    /// Boundary regression: exactly 512 bytes stays under the cap and
    /// falls through to the regular 404 path (no artifact of that name).
    /// Guards against an off-by-one (e.g. `>=` instead of `>`).
    #[tokio::test]
    async fn download_accepts_package_name_at_cap_boundary() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        // Exactly 512 bytes — at the cap, not over. Short filename so
        // the test isolates the `project` segment's boundary behaviour
        // rather than incidentally tripping the `filename` validator.
        let at_cap = "a".repeat(hort_http_core::limits::MAX_ROUTE_PARAM_BYTES);
        let res = router
            .oneshot(
                Request::get(format!("/pypi/pypi-test/simple/{at_cap}/file.tar.gz"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 512 bytes — under the cap. Not 400. The handler then falls
        // through to its own not-found logic (404).
        assert_ne!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// 513 bytes rejects — the first over-cap value. Paired with the
    /// at-boundary test above, this pins the comparator as `>` not
    /// `>=`.
    #[tokio::test]
    async fn download_rejects_package_name_one_over_cap() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());

        let over = "a".repeat(hort_http_core::limits::MAX_ROUTE_PARAM_BYTES + 1);
        let res = router
            .oneshot(
                Request::get(format!("/pypi/pypi-test/simple/{over}/file.tar.gz"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// Oversized `repo_key` also rejects with 400 + the right parameter
    /// name — covers the upload handler's extraction point.
    #[tokio::test]
    async fn upload_rejects_oversized_repo_key() {
        let h = harness();
        let router = router(h.ctx.clone());

        let huge = "a".repeat(513);
        let boundary = "----hortrouteparam";
        let body = build_multipart_body(boundary, b"payload");
        let res = router
            .oneshot(
                Request::post(format!("/pypi/{huge}/"))
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["parameter"], "repo_key");
    }

    // -- index tests ----------------------------------------------------------

    #[tokio::test]
    async fn simple_root_returns_html_with_packages() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(&h, repo.id, "pkg-a", "a.tar.gz", QuarantineStatus::None);
        insert_artifact(&h, repo.id, "pkg-b", "b.tar.gz", QuarantineStatus::None);
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("pypi:repository-version"));
        assert!(html.contains("pkg-a"));
        assert!(html.contains("pkg-b"));
    }

    /// Pins the projection-mutation→render-reflects contract for the PyPI
    /// root simple index. Two GETs against the same router; between them a
    /// new artifact row is inserted into the mock projection. NO
    /// `invalidate()` / `clear_cache()` / `flush()` call sits between the
    /// renders — the second render must reflect the mutation purely because
    /// `simple_root` reads from
    /// `ArtifactUseCase::list_distinct_names_visible` at serve time.
    /// Regression coverage: if a future change re-introduces a stored
    /// rendered-blob source-of-truth (or an undocumented cache without
    /// invalidation), this test fails.
    #[tokio::test]
    async fn simple_root_reflects_projection_mutation_without_invalidation() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "pkg-alpha",
            "alpha.tar.gz",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        // First render: projection holds only `pkg-alpha`.
        let res1 = router
            .clone()
            .oneshot(
                Request::get("/pypi/pypi-test/simple/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res1.status(), StatusCode::OK);
        let body1 = to_bytes(res1.into_body(), 8192).await.unwrap();
        let html1 = std::str::from_utf8(&body1).unwrap();
        assert!(html1.contains("pkg-alpha"));
        assert!(!html1.contains("pkg-beta"));

        // Mutate the projection in place — same mock instance, no router
        // restart, no cache flush, no invalidation hook called.
        insert_artifact(
            &h,
            repo.id,
            "pkg-beta",
            "beta.tar.gz",
            QuarantineStatus::None,
        );

        // Second render: same router, same handler; must reflect the new row.
        let res2 = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res2.status(), StatusCode::OK);
        let body2 = to_bytes(res2.into_body(), 8192).await.unwrap();
        let html2 = std::str::from_utf8(&body2).unwrap();
        assert!(html2.contains("pkg-alpha"));
        assert!(html2.contains("pkg-beta"));
    }

    #[tokio::test]
    async fn simple_project_returns_html_with_download_link() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "requests",
            "requests-2.31.0.tar.gz",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/requests/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("requests-2.31.0.tar.gz"));
        assert!(html.contains("#sha256="));
    }

    /// Proxy repos route through the `simple_index` module instead of the
    /// local-artifact list. Smoke test pinning the
    /// `if repo.repo_type == Proxy` branch fires: seed an upstream HTML
    /// body, hit the simple-project endpoint against a Proxy repo, and
    /// assert the response contains the rewritten upstream URL (which the
    /// local-artifact path could never produce because no local artifacts
    /// exist for this repo).
    #[tokio::test]
    async fn simple_project_proxy_repo_routes_through_simple_index_module() {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::repository::RepositoryType;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };
        use hort_http_core::test_support::build_mock_ctx;

        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        let (ctx, mocks) = build_mock_ctx(metrics_handle);

        let mut repo = sample_repository();
        repo.key = "pypi-mirror".into();
        repo.format = RepositoryFormat::Pypi;
        repo.repo_type = RepositoryType::Proxy;
        repo.upstream_url = Some("https://pypi.org".into());
        // This rewrite-mechanics smoke test seeds no
        // `package_version_status` rows; under `ReleasedOnly` (the
        // production default applied by `sample_repository`) the quarantine
        // filter would drop the upstream anchor and the rewrite-presence
        // assertion would fail. `IncludePending` preserves the upstream
        // catalog when hort has no status row, which is what this test
        // wants to assert on.
        repo.index_mode = hort_domain::entities::repository::IndexMode::IncludePending;
        mocks.repositories.insert(repo.clone());

        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            path_prefix: "".into(),
            upstream_url: "https://pypi.org".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        });

        let upstream_html = r#"<a href="https://files.pythonhosted.org/x/y/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>"#;
        mocks.upstream_proxy.insert_metadata(
            "",
            "/simple/requests/",
            upstream_html.as_bytes().to_vec(),
        );

        let r = router(ctx);
        let res = r
            .oneshot(
                Request::get("/pypi/pypi-mirror/simple/requests/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 16384).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        // Proof the Proxy branch fired: the upstream URL is rewritten
        // to the local file route. The local-list path could not have
        // produced this — there are no artifacts seeded for this repo.
        assert!(
            html.contains("/pypi/pypi-mirror/simple/requests/requests-2.31.0.tar.gz#sha256=abc"),
            "Proxy branch must rewrite upstream URLs: got {html}"
        );
        assert!(
            !html.contains("https://files.pythonhosted.org"),
            "no upstream URLs should remain after rewrite"
        );
    }

    /// `data-requires-python` attribute on the simple index anchor
    /// (PEP 503 §Content specifications).
    ///
    /// When the ingested metadata carries `pkg_info.requires_python` as a
    /// JSON string, the anchor MUST render the attribute with the raw value
    /// HTML-escaped (PEP 503 §Content specifications). A value like
    /// `">=3.8"` contains a `>` that must emerge as `&gt;` inside the
    /// attribute. The upload handler wraps multipart fields under
    /// `pkg_info` to leave the top-level namespace free for sibling keys.
    #[tokio::test]
    async fn simple_project_emits_data_requires_python_when_metadata_present() {
        use hort_domain::entities::artifact::ArtifactMetadata;
        use hort_domain::entities::repository::RepositoryFormat as Fmt;

        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let artifact = insert_artifact(
            &h,
            repo.id,
            "requests",
            "requests-2.31.0.tar.gz",
            QuarantineStatus::None,
        );

        h.artifact_metadata.insert(ArtifactMetadata {
            artifact_id: artifact.id,
            format: Fmt::Pypi,
            metadata: serde_json::json!({
                "pkg_info": { "requires_python": ">=3.8" }
            }),
            metadata_blob: None,
            properties: serde_json::json!({}),
        });

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/requests/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        // Attribute is present with the HTML-escaped value (`>` → `&gt;`).
        assert!(
            html.contains("data-requires-python=\"&gt;=3.8\""),
            "expected escaped data-requires-python attribute in HTML:\n{html}"
        );
        // Belt-and-braces: the raw un-escaped form must not leak into an
        // attribute (a `>` inside `"..."` would close the tag on
        // lenient parsers).
        assert!(
            !html.contains("data-requires-python=\">=3.8\""),
            "raw `>` must be escaped inside attribute value:\n{html}"
        );
    }

    /// No `data-requires-python` attribute when the ingested metadata row
    /// has no `pkg_info.requires_python` field.
    /// Missing rows, JSON `null`, and non-string values all fall through to
    /// the same "omit attribute" branch — PEP 503 says the attribute SHOULD
    /// be emitted when known; silence is the correct default when it is not.
    #[tokio::test]
    async fn simple_project_omits_data_requires_python_when_metadata_missing() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "requests",
            "requests-2.31.0.tar.gz",
            QuarantineStatus::None,
        );
        // Note: no seed into h.artifact_metadata.

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/requests/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("requests-2.31.0.tar.gz"));
        assert!(
            !html.contains("data-requires-python"),
            "attribute must be absent when pkg_info.requires_python is missing:\n{html}"
        );
    }

    /// PEP 691 JSON simple API — Accept-header negotiation returns
    /// `application/vnd.pypi.simple.v1+json` with meta.api-version="1.1",
    /// name, files (with hashes + requires-python when stored), and
    /// versions. The E2E harness (scripts/native-tests/test-pypi.sh step 4)
    /// asserts on this exact shape.
    #[tokio::test]
    async fn simple_project_returns_pep691_json_on_accept_header() {
        use hort_domain::entities::artifact::ArtifactMetadata;
        use hort_domain::entities::repository::RepositoryFormat as Fmt;

        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let wheel = insert_artifact(
            &h,
            repo.id,
            "test-pkg",
            "test_pkg-1.0-py3-none-any.whl",
            QuarantineStatus::None,
        );
        let sdist = insert_artifact(
            &h,
            repo.id,
            "test-pkg",
            "test_pkg-1.0.tar.gz",
            QuarantineStatus::None,
        );
        // Seed metadata only on the wheel — tests that per-file
        // requires-python emission follows the metadata_map lookup.
        h.artifact_metadata.insert(ArtifactMetadata {
            artifact_id: wheel.id,
            format: Fmt::Pypi,
            metadata: serde_json::json!({
                "pkg_info": { "requires_python": ">=3.8" }
            }),
            metadata_blob: None,
            properties: serde_json::json!({}),
        });

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/test-pkg/")
                    .header(ACCEPT, "application/vnd.pypi.simple.v1+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "application/vnd.pypi.simple.v1+json"
        );
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["meta"]["api-version"], "1.1");
        assert_eq!(json["name"], "test-pkg");
        let files = json["files"].as_array().expect("files is an array");
        assert_eq!(files.len(), 2, "wheel + sdist → 2 files");
        // Wheel has metadata → requires-python set.
        let wheel_file = files
            .iter()
            .find(|f| f["filename"].as_str().is_some_and(|s| s.ends_with(".whl")))
            .expect("wheel file present");
        assert_eq!(wheel_file["requires-python"], ">=3.8");
        assert!(wheel_file["hashes"]["sha256"].is_string());
        // Sdist has no metadata → requires-python absent from the object.
        let sdist_file = files
            .iter()
            .find(|f| {
                f["filename"]
                    .as_str()
                    .is_some_and(|s| s.ends_with(".tar.gz"))
            })
            .expect("sdist file present");
        assert!(sdist_file.get("requires-python").is_none());
        // versions array is PEP 700's v1.1 addition — sorted & unique.
        // `insert_artifact` helper stamps version "1.0.0" on every
        // artifact — both files share one version, so `versions` de-dupes
        // to a single entry.
        assert_eq!(
            json["versions"],
            serde_json::json!(["1.0.0"]),
            "unique sorted versions"
        );
        let _ = sdist; // insert_artifact already wired it through the mock
    }

    /// PEP 691 negative path — absent Accept header falls through to the
    /// existing HTML renderer. Regression guard so adding JSON negotiation
    /// does not silently break the default response.
    #[tokio::test]
    async fn simple_project_returns_html_when_accept_header_absent() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "test-pkg",
            "test_pkg-1.0.tar.gz",
            QuarantineStatus::None,
        );

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/test-pkg/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let content_type = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.starts_with("text/html"),
            "default response stays HTML, got {content_type}"
        );
    }

    /// Normalisation-drift regression. Exercises the **non-idempotent**
    /// drift case: a stored `name = "legacy.name"`
    /// (containing a dot — impossible under current PEP 503 normalise,
    /// only reachable by assuming ingestion under an older plugin) would
    /// be further transformed by `PyPiFormatHandler::normalize_name`
    /// today (`"legacy.name"` → `"legacy-name"`; dot folds to hyphen).
    /// If any layer re-normalises between index emission and download
    /// lookup, the download breaks.
    ///
    /// End-to-end assertions:
    /// (a) `list_by_raw_name` recovers the row via the
    ///     `name_as_published` fallback (current
    ///     `normalize("Drift-Pkg")` misses the stored name).
    /// (b) The emitted `href` carries the STORED `"legacy.name"`, not a
    ///     re-normalised request parameter.
    /// (c) A follow-up GET on the emitted URL hits. Under a re-
    ///     normalising download handler this would 404 — the handler
    ///     would compute `"simple/legacy-name/..."` which doesn't match
    ///     the stored `"simple/legacy.name/..."`.
    #[tokio::test]
    async fn simple_project_recovers_drift_era_artifact_and_follow_up_get_hits() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");

        // Stored under a name that current normalise would transform —
        // the `.` is what makes this non-idempotent.
        let filename = "legacy.name-1.0.0.tar.gz";
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "legacy.name".into();
        artifact.name_as_published = "Drift-Pkg".into();
        artifact.path = format!("simple/legacy.name/{filename}");
        h.artifacts.insert(artifact.clone());
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), b"drift bytes".to_vec());

        let router = router(h.ctx.clone());

        // (1) Request the simple index by the raw client name. Current
        // normalise("Drift-Pkg") = "drift-pkg" — primary lookup misses.
        // Fallback by `name_as_published = "Drift-Pkg"` recovers the row.
        let res = router
            .clone()
            .oneshot(
                Request::get("/pypi/pypi-test/simple/Drift-Pkg/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        // (2) Index enumerates the artifact.
        assert!(html.contains(filename), "expected filename in HTML: {html}");
        // (3) URL carries the STORED name (with the dot), not the
        // re-normalised request parameter.
        assert!(
            html.contains("/pypi/pypi-test/simple/legacy.name/"),
            "expected stored `legacy.name` in emitted href, got: {html}"
        );
        // And it MUST NOT emit the current-algorithm form of the stored
        // name — that would prove some layer re-normalised it.
        assert!(
            !html.contains("/pypi/pypi-test/simple/legacy-name/"),
            "emitted href must NOT re-normalise the stored name: {html}"
        );

        // (4) Follow-up GET on the emitted href must hit. Under a
        // re-normalising download handler, `normalize("legacy.name")`
        // → `"legacy-name"` and the lookup path would miss → 404.
        let dl = router
            .oneshot(
                Request::get(format!("/pypi/pypi-test/simple/legacy.name/{filename}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl.status(), StatusCode::OK);
        let dl_body = to_bytes(dl.into_body(), 8192).await.unwrap();
        assert_eq!(&dl_body[..], b"drift bytes");
    }

    // -- end-to-end metrics verification ------------------------------------------------

    /// End-to-end PyPI metrics verification + forbidden-label regression.
    ///
    /// Drives upload → download → `/metrics` through the real `build_router`
    /// stack with a **local** Prometheus recorder (no global install) and a
    /// real `FilesystemStorage` adapter backed by a tempdir. Asserts that a
    /// counter from every observability layer — HTTP middleware,
    /// ingest use case, download use case, storage adapter put, and
    /// storage adapter get — appears in the scrape output with the
    /// expected label shape.
    ///
    /// Forbidden-label regression: the scrape body must not contain any of
    /// the high-cardinality label keys `artifact_id`, `user_id`,
    /// `content_hash`, or `stream_id`. The `stream_category` label is
    /// permitted; a word-boundary regex keeps the allow-list precise.
    ///
    /// This test uses `FilesystemStorage` (not `MockStoragePort`) so the
    /// storage adapter's metric emission actually fires. Mocks are used for
    /// everything that touches Postgres (repository lookup, artifact repo,
    /// event store, lifecycle).
    #[test]
    fn end_to_end_pypi_metrics_verification() {
        use hort_adapters_storage::FilesystemStorage;
        use hort_http_core::router::wrap_with_middleware;
        use hort_http_core::test_support::{build_mock_ctx, with_storage};
        use metrics_exporter_prometheus::PrometheusBuilder;
        use regex::Regex;

        let tempdir = tempfile::tempdir().unwrap();

        // Local recorder + handle — scoped to this closure via
        // `with_local_recorder`. No global install, so parallel tests don't
        // cross-contaminate.
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let scrape_body = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    // Uses `build_mock_ctx` + `with_storage`. The test still
                    // requires a real `FilesystemStorage` adapter so the
                    // `backend="filesystem"` storage-operations counter
                    // fires; `with_storage` swaps the storage slot AND
                    // rebuilds `ArtifactUseCase` + `IngestUseCase` so the
                    // download / publish hot paths use the new adapter.
                    let storage: Arc<dyn hort_domain::ports::storage::StoragePort> =
                        Arc::new(FilesystemStorage::new(tempdir.path().to_path_buf()));
                    let (base, mocks) = build_mock_ctx(handle.clone());
                    let ctx = with_storage(&base, &mocks, storage);

                    // Seed a PyPI repository on the same `MockRepositoryRepository`
                    // wired into the context. Use a specific `format` so the
                    // `format="pypi"` label matches the catalog.
                    let mut repo = sample_repository();
                    repo.key = "pypi-test".to_string();
                    repo.format = RepositoryFormat::Pypi;
                    mocks.repositories.insert(repo.clone());

                    // Build a minimal router scoped to just `/pypi` + the
                    // shared middleware chain. hort-http-pypi assembles its
                    // own subset directly so the test verifies the real
                    // request → ingest → metric path without a
                    // cross-crate dep on hort-server.
                    let inner: Router<Arc<AppContext>> = Router::new().nest(
                        "/pypi",
                        pypi_routes_with_publish_limit(DEFAULT_PUBLISH_BODY_LIMIT),
                    );
                    let router = wrap_with_middleware(ctx.clone(), inner, true, true);

                    // --- 1. Upload via multipart POST -----------------------
                    let boundary = "----hortboundary9x7";
                    let payload = b"pypi-e2e-metrics-payload";
                    let body_bytes = build_multipart_body(boundary, payload);
                    let upload_res = router
                        .clone()
                        .oneshot(
                            Request::post("/pypi/pypi-test/")
                                .header(
                                    CONTENT_TYPE,
                                    format!("multipart/form-data; boundary={boundary}"),
                                )
                                .body(Body::from(body_bytes))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        upload_res.status(),
                        StatusCode::OK,
                        "upload failed: {:?}",
                        upload_res.status()
                    );

                    // --- 2. Download the same artifact ----------------------
                    // The upload handler normalizes `e2e_pkg` → `e2e-pkg` (PEP 503)
                    // and stores at `simple/e2e-pkg/e2e-pkg-1.0.tar.gz`.
                    let download_res = router
                        .clone()
                        .oneshot(
                            Request::get("/pypi/pypi-test/simple/e2e-pkg/e2e-pkg-1.0.tar.gz")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        download_res.status(),
                        StatusCode::OK,
                        "download failed: {:?}",
                        download_res.status()
                    );
                    let body = to_bytes(download_res.into_body(), 64 * 1024).await.unwrap();
                    assert_eq!(&body[..], payload);

                    // --- 3. Scrape /metrics ---------------------------------
                    let scrape = router
                        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(scrape.status(), StatusCode::OK);
                    let scrape_bytes = to_bytes(scrape.into_body(), 128 * 1024).await.unwrap();
                    String::from_utf8(scrape_bytes.to_vec()).unwrap()
                })
        });

        // ============================================================
        // Assertions — every layer's counter fired.
        // ============================================================

        // HTTP middleware: hort_http_responses_total with a path
        // label that is a route template — not the concrete URL.
        assert!(
            scrape_body.contains("hort_http_responses_total{"),
            "hort_http_responses_total missing:\n{scrape_body}"
        );
        let http_resp_line = scrape_body
            .lines()
            .find(|l| l.starts_with("hort_http_responses_total{") && l.contains("path=\"/pypi/"))
            .unwrap_or_else(|| {
                panic!("no hort_http_responses_total line with a /pypi/ path label:\n{scrape_body}")
            });
        // The path label must be a ROUTE TEMPLATE — contains `:repo_key`,
        // `:project`, or `:filename` — not the concrete URL.
        assert!(
            http_resp_line.contains(":repo_key")
                || http_resp_line.contains(":project")
                || http_resp_line.contains(":filename"),
            "path label is not a route template:\n{http_resp_line}\n\nFull scrape:\n{scrape_body}"
        );
        // Concrete URL must not have leaked.
        assert!(
            !scrape_body.contains("pypi-test/simple/e2e-pkg/e2e-pkg-1.0.tar.gz"),
            "concrete URL leaked into /metrics:\n{scrape_body}"
        );

        // Ingest use case: hort_ingest_total{format="pypi",...,result="success"} >= 1.
        assert_counter_fired(
            &scrape_body,
            "hort_ingest_total",
            &["format=\"pypi\"", "result=\"success\""],
        );

        // Download use case: hort_download_total{format="pypi",...,result="success"} >= 1.
        assert_counter_fired(
            &scrape_body,
            "hort_download_total",
            &["format=\"pypi\"", "result=\"success\""],
        );

        // Storage adapter: PUT fired with filesystem backend.
        assert_counter_fired(
            &scrape_body,
            "hort_storage_operations_total",
            &[
                "backend=\"filesystem\"",
                "operation=\"put\"",
                "result=\"success\"",
            ],
        );

        // Storage adapter: GET fired with filesystem backend.
        assert_counter_fired(
            &scrape_body,
            "hort_storage_operations_total",
            &[
                "backend=\"filesystem\"",
                "operation=\"get\"",
                "result=\"success\"",
            ],
        );

        // ============================================================
        // Forbidden-label regression: no high-cardinality identifier
        // label ever escaped into the scrape output.
        //
        // `stream_category` is allowed — only the bare identifier
        // labels are forbidden. Word-boundary regex keeps the allow-list
        // precise.
        // ============================================================
        let forbidden = Regex::new(r"\b(artifact_id|user_id|content_hash|stream_id)\b").unwrap();
        for (lineno, line) in scrape_body.lines().enumerate() {
            // `# HELP`/`# TYPE` comment lines are metadata — they can't
            // inflate cardinality, so skip them.
            if line.starts_with('#') {
                continue;
            }
            assert!(
                !forbidden.is_match(line),
                "forbidden high-cardinality label on line {lineno}:\n{line}\n\nFull scrape:\n{scrape_body}"
            );
        }
    }

    /// Cardinality-safety-valve regression: when `include_repository_label`
    /// is `false` the `repository` metric label must emit the
    /// [`hort_app::metrics::values::REPOSITORY_ALL`] sentinel (`"_all"`) and
    /// the real repo key (`pypi-disabled`) must never appear.
    ///
    /// Uses the standard mock harness — only the `hort_ingest_total` counter
    /// needs to fire to validate the plumbing, so we do not need a real
    /// filesystem or a real download round-trip. HTTP middleware
    /// `hort_http_*` counters still fire but carry no `repository` label.
    #[test]
    fn metrics_emit_repository_all_sentinel_when_flag_disabled() {
        use metrics_exporter_prometheus::PrometheusBuilder;

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let scrape = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let h = harness_with(false);
                    insert_repo(&h, "pypi-disabled");
                    let router = router(h.ctx.clone());

                    // Drive one upload so ingest_use_case emits the counter.
                    let boundary = "----hortboundary-flag";
                    let body_bytes = build_multipart_body(boundary, b"payload-disabled");
                    let res = router
                        .oneshot(
                            Request::post("/pypi/pypi-disabled/")
                                .header(
                                    CONTENT_TYPE,
                                    format!("multipart/form-data; boundary={boundary}"),
                                )
                                .body(Body::from(body_bytes))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(res.status(), StatusCode::OK);

                    handle.render()
                })
        });

        assert!(
            scrape.contains("repository=\"_all\""),
            "expected repository=\"_all\" sentinel when include_repository_label=false:\n{scrape}"
        );
        assert!(
            !scrape.contains("repository=\"pypi-disabled\""),
            "real repository key must not appear when include_repository_label=false:\n{scrape}"
        );
    }

    /// Build a minimal PyPI upload multipart body with fields `name`,
    /// `version`, and `content` (a binary file). Matches the shape the
    /// `upload` handler expects.
    fn build_multipart_body(boundary: &str, file_bytes: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let push_field = |buf: &mut Vec<u8>, name: &str, value: &str| {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        };
        push_field(&mut body, "name", "e2e_pkg");
        push_field(&mut body, "version", "1.0");
        push_field(&mut body, ":action", "file_upload");
        // Required `sha256_digest` over the embedded content (builder-level
        // re-anchor; see `content_sha256_hex`). The body-size-limit (413)
        // test passes a multi-MB payload whose digest is still computed
        // correctly here, but that test trips `DefaultBodyLimit` before
        // the handler parses any field, so the digest is never consulted
        // on that path.
        push_field(&mut body, "sha256_digest", &content_sha256_hex(file_bytes));

        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"content\"; filename=\"e2e-pkg-1.0.tar.gz\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    /// Assert that at least one line of the scrape output matches
    /// `metric{...all-labels...} N` with a numeric value >= 1. Label
    /// fragments are matched as substrings — order-independent.
    fn assert_counter_fired(scrape: &str, metric: &str, required_labels: &[&str]) {
        let prefix = format!("{metric}{{");
        let candidate = scrape
            .lines()
            .find(|line| {
                line.starts_with(&prefix)
                    && required_labels.iter().all(|lbl| line.contains(lbl))
            })
            .unwrap_or_else(|| {
                panic!(
                    "no line matched `{metric}` with labels {required_labels:?}.\n\nFull scrape:\n{scrape}"
                )
            });

        // Prometheus line shape: `metric{labels} value` — the value is the
        // whitespace-delimited trailing token.
        let value: f64 = candidate
            .split_whitespace()
            .next_back()
            .and_then(|tok| tok.parse::<f64>().ok())
            .unwrap_or_else(|| {
                panic!("could not parse numeric value from scrape line: {candidate}")
            });
        assert!(
            value >= 1.0,
            "counter `{metric}` with labels {required_labels:?} has value {value}, expected >= 1"
        );
    }

    // -- PEP 658 .metadata endpoint tests ---------------------------------------
    //
    // The legacy PKG-INFO-synthesizer tests (always-200 with hand-rolled text
    // from stored multipart `pkg_info` fields, including for sdists) were
    // removed. PEP 658 requires byte-accurate METADATA bytes whose SHA-256
    // matches the simple-index's advertised hash, and the synthesizer (an
    // approximation) could not satisfy that invariant.
    // The test matrix below pins the PEP 658 §"Specification" contract:
    // happy-path CAS-backed serve, anti-enumeration on private repos,
    // quarantine status filter (Quarantined → 503,
    // Rejected/ScanIndeterminate → 404), sdist → 404, un-backfilled
    // wheel → 404, and hash round-trip.

    /// Seed a wheel artifact, its `wheel_metadata` ContentReference row,
    /// and the CAS bytes — the harness used by PEP 658 metadata endpoint
    /// tests. Returns the artifact (so tests can read its `id`)
    /// and the SHA-256 hex of the seeded payload.
    async fn seed_wheel_with_cas_metadata(
        h: &TestHarness,
        repo_id: Uuid,
        project: &str,
        wheel_filename: &str,
        status: QuarantineStatus,
        metadata_bytes: &[u8],
    ) -> (Artifact, String) {
        use hort_domain::ports::content_reference_index::{
            ContentReference, ContentReferenceIndex,
        };
        use sha2::{Digest, Sha256};
        let mut artifact = sample_artifact(status);
        artifact.repository_id = repo_id;
        artifact.name = project.to_string();
        artifact.path = format!("simple/{project}/{wheel_filename}");
        h.artifacts.insert(artifact.clone());
        let mut hasher = Sha256::new();
        hasher.update(metadata_bytes);
        let hex = format!("{:x}", hasher.finalize());
        let hash: hort_domain::types::ContentHash = hex.parse().unwrap();
        h.storage
            .insert_content(hash.clone(), metadata_bytes.to_vec());
        // Use `MockContentReferenceIndex` directly via the test
        // harness handle — the `AppContext.content_references` slot
        // is `pub(crate)` (ADR 0008) so we avoid going through it.
        h.content_references
            .insert(ContentReference {
                source_artifact_id: artifact.id,
                target_content_hash: hash,
                kind: "wheel_metadata".to_string(),
                metadata: serde_json::json!({}),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        (artifact, hex)
    }

    /// Happy path — wheel with a `wheel_metadata` ContentReference row +
    /// CAS bytes → 200 + `text/plain; charset=utf-8` Content-Type +
    /// `Content-Digest: sha256=:<base64>:` header carrying the SHA-256
    /// of the served bytes (PEP 658 + RFC 9530).
    #[tokio::test]
    async fn metadata_endpoint_serves_cas_bytes_with_content_digest() {
        use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let payload =
            b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\nRequires-Python: >=3.8\n";
        let (_artifact, hex) = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
            payload,
        )
        .await;

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!(ct, "text/plain; charset=utf-8");
        let cd = res
            .headers()
            .get("Content-Digest")
            .and_then(|v| v.to_str().ok())
            .expect("Content-Digest header present");
        // Format: sha256=:<base64-of-32-bytes>:
        assert!(cd.starts_with("sha256=:"), "wrong Content-Digest: {cd}");
        assert!(cd.ends_with(':'), "wrong Content-Digest suffix: {cd}");
        // Round-trip: extract base64 → decode to bytes → hex → matches
        // the hex of the seeded payload (which == the row's
        // target_content_hash and == the SHA-256 of the served bytes).
        let inner = cd
            .strip_prefix("sha256=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        let raw = BASE64_STANDARD.decode(inner).unwrap();
        let round_trip_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            round_trip_hex, hex,
            "Content-Digest hash must match payload SHA-256"
        );
        // Body bytes match.
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        assert_eq!(body.as_ref(), payload);
    }

    /// Anti-enumeration on the `.metadata` endpoint. Anonymous caller
    /// on a private repo's wheel `.metadata` URL → 404. Reuses the same
    /// `enabled_rbac_harness()` + `insert_private_repo()` setup as
    /// the `anti_enumeration::anonymous_get_pep658_metadata_on_private_repo_returns_404`
    /// regression below (which exercises the sdist short-circuit branch);
    /// this test pins the WHEEL branch — the one that reaches
    /// `WheelMetadataUseCase::serve` and therefore depends on the
    /// `find_visible_by_path` anti-enumeration hop inside the use case.
    #[tokio::test]
    async fn metadata_endpoint_anonymous_caller_on_private_repo_wheel_returns_404() {
        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_http_core::test_support::with_repository_access;
        let h = harness();
        let mut repo = sample_repository();
        repo.key = "private-pypi".into();
        repo.format = RepositoryFormat::Pypi;
        repo.is_public = false;
        h.repositories.insert(repo.clone());
        // Seed a wheel + its wheel_metadata CAS row inside the
        // private repo so the only thing standing between an
        // anonymous caller and the bytes is the visibility check.
        let _ = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "secret",
            "secret-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
            b"Metadata-Version: 2.1\nName: secret\n",
        )
        .await;
        // Flip access to enabled-RBAC (empty evaluator → anonymous
        // sees nothing).
        let access = Arc::new(RepositoryAccessUseCase::new(
            h.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&h.ctx, access);
        let router = Router::new().nest("/pypi", pypi_routes()).with_state(ctx);
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/private-pypi/simple/secret/\
                     secret-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "anonymous PEP 658 .metadata read on private pypi MUST be 404 \
             (anti-enumeration)"
        );
    }

    /// Quarantined parent wheel → 503 + Retry-After matching the
    /// wheel-download handler's shape. Asserts the same status code AND
    /// header presence; the exact seconds value is non-deterministic
    /// (computed from `quarantine_deadline - Utc::now()`).
    #[tokio::test]
    async fn metadata_endpoint_quarantined_wheel_returns_503_with_retry_after() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let _ = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Quarantined,
            b"Metadata-Version: 2.1\nName: example\n",
        )
        .await;
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            res.headers().get("Retry-After").is_some(),
            "Quarantined wheel .metadata MUST emit Retry-After"
        );
    }

    /// Rejected parent wheel → 404 (NOT 403). Diverges from the
    /// wheel-download handler's 403 mapping — the metadata surface must
    /// hide the wheel's existence to deny partial enumeration (PEP 658
    /// anti-enumeration invariant).
    #[tokio::test]
    async fn metadata_endpoint_rejected_wheel_returns_404_not_403() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let _ = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::Rejected,
            b"Metadata-Version: 2.1\nName: example\n",
        )
        .await;
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "Rejected wheel .metadata MUST be 404 (anti-enumeration), not 403"
        );
    }

    /// Scan-indeterminate parent wheel → 404. Same rationale as rejected:
    /// hide existence to deny enumeration.
    #[tokio::test]
    async fn metadata_endpoint_scan_indeterminate_wheel_returns_404() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let _ = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::ScanIndeterminate,
            b"Metadata-Version: 2.1\nName: example\n",
        )
        .await;
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Sdist `.tar.gz.metadata` → 404. PEP 658 applies only to wheels
    /// (PEP 658 §"Specification"). The handler short-circuits on the
    /// non-`.whl` suffix BEFORE repo resolution, so the response is
    /// invariant of repo visibility.
    #[tokio::test]
    async fn metadata_endpoint_sdist_path_returns_404() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        // Seed a sdist artifact so we know the path-existence axis
        // doesn't matter — only the suffix.
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "example".into();
        artifact.path = "simple/example/example-1.0.0.tar.gz".into();
        h.artifacts.insert(artifact);
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/example-1.0.0.tar.gz.metadata")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Wheel without a `wheel_metadata` ContentReference row (legacy
    /// un-backfilled wheel or extraction returned None at ingest) → 404.
    /// Operator-visible safety net for clients that directly probe the URL
    /// even when the simple-index has not advertised PEP 658 for this wheel.
    #[tokio::test]
    async fn metadata_endpoint_wheel_without_cas_row_returns_404() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        // Seed wheel artifact WITHOUT the wheel_metadata ContentReference row.
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "example".into();
        artifact.path = "simple/example/example-1.0.0-py3-none-any.whl".into();
        h.artifacts.insert(artifact);
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// 404 on a wheel `.metadata` request when the wheel itself doesn't
    /// exist (anti-enumeration is delegated to `find_visible_by_path`
    /// which collapses missing-repo / missing-artifact onto one envelope).
    #[tokio::test]
    async fn metadata_endpoint_missing_wheel_returns_404() {
        let h = harness();
        insert_repo(&h, "pypi-test");
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/missing/\
                     missing-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Hash round-trip invariant (PEP 658 + RFC 9530): the SHA-256 of
    /// the served bytes equals the base64-decoded `Content-Digest`
    /// header value. The simple-index advertises the same hash, so this
    /// pins the end-to-end client verification contract.
    #[tokio::test]
    async fn metadata_endpoint_content_digest_matches_hash_of_served_bytes() {
        use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
        use sha2::{Digest, Sha256};
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let payload = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\nAuthor: nobody\n";
        let _ = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
            payload,
        )
        .await;
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cd = res
            .headers()
            .get("Content-Digest")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let body_hash_hex = format!("{:x}", hasher.finalize());
        // Extract base64 from `sha256=:<base64>:` and decode.
        let inner = cd
            .strip_prefix("sha256=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        let raw = BASE64_STANDARD.decode(inner).unwrap();
        let header_hash_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            body_hash_hex, header_hash_hex,
            "SHA-256 of served bytes MUST equal the Content-Digest header hash \
             (PEP 658 + RFC 9530 client-verification invariant)"
        );
    }

    /// Sdist anchors NEVER carry the PEP 658 `data-dist-info-metadata`
    /// attribute (the spec is wheels-only, PEP 658 §"Specification").
    /// The builder previously always emitted `="true"`, which was
    /// incorrect — sdists have no `<dist-info>/METADATA` member, so
    /// claiming PEP 658 availability for them broke pip's resolver
    /// speculation.
    #[tokio::test]
    async fn simple_project_html_omits_pep658_attribute_for_sdist() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "test-pkg",
            "test_pkg-1.0.tar.gz",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/test-pkg/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("data-dist-info-metadata"),
            "sdist anchor must NOT advertise PEP 658 (wheels-only spec):\n{html}"
        );
    }

    /// Sdist file entries in PEP 691 JSON emit `"dist-info-metadata": false`
    /// (the "no metadata available" shape per PEP 691). The builder
    /// previously always emitted `true`, which lied about availability.
    #[tokio::test]
    async fn simple_project_json_sdist_emits_dist_info_metadata_false() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "test-pkg",
            "test_pkg-1.0.tar.gz",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/test-pkg/")
                    .header(ACCEPT, "application/vnd.pypi.simple.v1+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let file0 = &json["files"][0];
        assert_eq!(
            file0["dist-info-metadata"], false,
            "expected dist-info-metadata:false on sdist file object: {json}"
        );
    }

    // -- Hosted source PEP 658 plumbing -----------------------------------------
    //
    // These tests pin the HostedPypiSource → batched
    // ContentReferenceIndex::find_by_sources_and_kind → builder
    // emission round-trip. Pip clients see the PEP 658 hash on wheel
    // anchors only when hort has the wheel's METADATA blob in CAS.

    /// Hosted wheel with a `wheel_metadata` ContentReference row →
    /// simple-index HTML carries the
    /// `data-dist-info-metadata="sha256=<hex>"` PEP 658 advertisement.
    #[tokio::test]
    async fn simple_project_html_wheel_with_wheel_metadata_row_emits_pep658_hash() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let payload =
            b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\nRequires-Python: >=3.8\n";
        let (_artifact, expected_hex) = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
            payload,
        )
        .await;
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let expected_attr = format!("data-dist-info-metadata=\"sha256={expected_hex}\"");
        assert!(
            html.contains(&expected_attr),
            "wheel with wheel_metadata CR must advertise PEP 658 hash in HTML:\n{html}"
        );
    }

    /// Hosted wheel WITHOUT a `wheel_metadata` ContentReference row →
    /// simple-index HTML omits the PEP 658 attribute entirely (NOT
    /// `="true"`, which was the prior incorrect behaviour). Pip falls
    /// back to whole-wheel download as if PEP 658 didn't exist for
    /// this wheel.
    #[tokio::test]
    async fn simple_project_html_wheel_without_cr_row_omits_pep658_attribute() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("data-dist-info-metadata"),
            "wheel without wheel_metadata CR must omit PEP 658 attribute \
             (emitting `=\"true\"` unconditionally was a bug):\n{html}"
        );
    }

    /// Hosted wheel with a `wheel_metadata` CR → simple-index JSON file
    /// entry carries `"dist-info-metadata": {"sha256": "<hex>"}` per
    /// PEP 691.
    #[tokio::test]
    async fn simple_project_json_wheel_with_cr_row_emits_dist_info_metadata_object() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let payload = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";
        let (_artifact, expected_hex) = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
            payload,
        )
        .await;
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/")
                    .header(ACCEPT, "application/vnd.pypi.simple.v1+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let file0 = &json["files"][0];
        let dim = file0
            .get("dist-info-metadata")
            .expect("dist-info-metadata field");
        let sub = dim.as_object().expect("dist-info-metadata is an object");
        assert_eq!(
            sub.get("sha256").and_then(|v| v.as_str()),
            Some(expected_hex.as_str()),
            "json wire shape per PEP 691: {file0}"
        );
    }

    /// Hosted wheel WITHOUT a `wheel_metadata` CR → JSON entry carries
    /// `"dist-info-metadata": false` per PEP 691.
    #[tokio::test]
    async fn simple_project_json_wheel_without_cr_row_emits_dist_info_metadata_false() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/")
                    .header(ACCEPT, "application/vnd.pypi.simple.v1+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let file0 = &json["files"][0];
        assert_eq!(
            file0["dist-info-metadata"], false,
            "wheel without wheel_metadata CR must emit false: {file0}"
        );
    }

    /// **The ONE-call invariant.** A hosted simple-index serve for a
    /// project with N wheels must issue EXACTLY ONE call to
    /// `ContentReferenceIndex::find_by_sources_and_kind` (not N calls
    /// to `find_by_source_and_kind`). The mock records the batch-call
    /// count; this test asserts it is exactly 1 even with 3 wheels in play.
    #[tokio::test]
    async fn simple_project_html_batches_wheel_metadata_lookup_in_one_call() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let payload = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";
        // Three wheels with CR rows, on three different versions to
        // force one artifact per version (the simple-index spine
        // groups by version — multi-file-per-version doesn't change
        // the artifact-count).
        for version in ["1.0.0", "1.1.0", "1.2.0"] {
            let filename = format!("example-{version}-py3-none-any.whl");
            let _ = seed_wheel_with_cas_metadata(
                &h,
                repo.id,
                "example",
                &filename,
                QuarantineStatus::None,
                payload,
            )
            .await;
        }
        // The mock counter is incremented inside
        // `find_by_sources_and_kind`. The seeding above used
        // `content_references.insert` (a separate code path), which
        // does NOT touch the batch counter — so the counter is at 0
        // at this point. The simple-index serve below is the only
        // thing that can increment it.
        let counter_before = h.content_references.batch_call_count();
        assert_eq!(counter_before, 0, "seeding must not touch batch counter");

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        // All three wheels' anchors must carry the PEP 658
        // advertisement (smoke check that the batched lookup
        // actually populated the data).
        let anchor_count = html.matches("data-dist-info-metadata=\"sha256=").count();
        assert_eq!(
            anchor_count, 3,
            "all 3 wheels must advertise PEP 658:\n{html}"
        );

        // THE INVARIANT: exactly ONE batched lookup, not 3
        // round-trips.
        let counter_after = h.content_references.batch_call_count();
        assert_eq!(
            counter_after, 1,
            "simple-index serve must batch the wheel_metadata lookup \
             into ONE call, not N round-trips (got {counter_after} calls \
             for 3 wheels)"
        );
    }

    /// **End-to-end PEP 658 round-trip invariant.** Ingest a wheel →
    /// simple-index advertises a hash → fetch `.metadata` → re-hash the
    /// served bytes → equals the advertised hash. The serve route
    /// (`.metadata`) and the advertisement (`/simple/<name>/`) MUST agree
    /// on the hash, byte-for-byte.
    #[tokio::test]
    async fn pep658_advertised_hash_equals_hash_of_served_metadata_bytes() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        let payload =
            b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\nRequires-Python: >=3.8\n";
        let (_artifact, expected_hex) = seed_wheel_with_cas_metadata(
            &h,
            repo.id,
            "example",
            "example-1.0.0-py3-none-any.whl",
            QuarantineStatus::None,
            payload,
        )
        .await;

        // (1) Fetch the simple-index and extract the advertised
        // PEP 658 hash.
        let router1 = router(h.ctx.clone());
        let res1 = router1
            .oneshot(
                Request::get("/pypi/pypi-test/simple/example/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res1.status(), StatusCode::OK);
        let html_bytes = to_bytes(res1.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&html_bytes).unwrap();
        let advertised = {
            // `data-dist-info-metadata="sha256=<hex>"` — extract the
            // <hex> via the same regex shape the proxy parser uses.
            let re =
                regex::Regex::new(r#"data-dist-info-metadata="sha256=([a-f0-9]{64})""#).unwrap();
            re.captures(html)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .expect("simple-index must advertise PEP 658 sha256")
        };
        assert_eq!(
            advertised, expected_hex,
            "advertised hash must match the seed (sanity)"
        );

        // (2) Fetch `.metadata` and re-hash the served bytes.
        let router2 = router(h.ctx.clone());
        let res2 = router2
            .oneshot(
                Request::get(
                    "/pypi/pypi-test/simple/example/\
                     example-1.0.0-py3-none-any.whl.metadata",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res2.status(), StatusCode::OK);
        let served_bytes = to_bytes(res2.into_body(), 8192).await.unwrap();
        let served_hex = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&served_bytes);
            format!("{:x}", hasher.finalize())
        };

        // (3) The end-to-end invariant: the advertised hash equals
        // the hash of the served bytes. This is the load-bearing
        // PEP 658 client-verification contract. If this assertion
        // EVER fails on a green build, an attacker can MITM a
        // .metadata response and pip will believe the tampered
        // bytes match the advertised hash — defeating PEP 658's
        // entire purpose.
        assert_eq!(
            advertised, served_hex,
            "the simple-index advertised hash MUST equal SHA-256 of the \
             served .metadata bytes — PEP 658 round-trip invariant"
        );
    }

    // -- Proxy index_source PEP 658 hash extraction --------------------------------
    //
    // The proxy source re-parses the rewritten upstream simple-index body.
    // The prior parser discarded the upstream's `data-dist-info-metadata`
    // value entirely — meaning the served (re-built) index advertised no
    // hash even when the upstream had one. The parser now captures the
    // upstream hash onto `PypiVersionFile.metadata_hash` so the builder
    // re-advertises it on hort's served index, preserving client-side
    // PEP 658 verification through the proxy.
    //
    // We exercise the parser via `index_source::parse_body_to_entries`
    // (crate-private but in-scope inside the test module).

    #[tokio::test]
    async fn proxy_parser_html_extracts_upstream_pep658_hash() {
        let upstream_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let html = format!(
            "<!DOCTYPE html><html><body>\
             <a href=\"https://files.pythonhosted.org/packages/00/00/\
             example-1.0.0-py3-none-any.whl#sha256=aaaa\" \
             data-requires-python=\"&gt;=3.7\" \
             data-dist-info-metadata=\"sha256={upstream_hex}\">\
             example-1.0.0-py3-none-any.whl</a>\
             </body></html>"
        );
        let (entries, _) = index_source::parse_body_to_entries(
            &bytes::Bytes::from(html),
            simple_index::SimpleIndexFormat::Html,
            "example",
            &std::collections::HashMap::new(),
        );
        assert_eq!(entries.len(), 1);
        let hort_app::use_cases::index_serve::PerVersionPayload::Pypi(payload) =
            &entries[0].payload
        else {
            unreachable!()
        };
        assert_eq!(payload.files.len(), 1);
        let metadata_hash = payload.files[0]
            .metadata_hash
            .as_ref()
            .expect("upstream advertised sha256 → metadata_hash populated");
        assert_eq!(metadata_hash.as_ref(), upstream_hex);
    }

    #[tokio::test]
    async fn proxy_parser_html_no_pep658_attribute_yields_none() {
        // Same anchor without the PEP 658 attribute → metadata_hash
        // is None → builder emits no advertisement on the served
        // index. Same wire shape as a wheel that genuinely has no
        // metadata blob (upstream doesn't serve PEP 658).
        let html = "<!DOCTYPE html><html><body>\
             <a href=\"https://files.pythonhosted.org/packages/00/00/\
             example-1.0.0-py3-none-any.whl#sha256=aaaa\" \
             data-requires-python=\"&gt;=3.7\">\
             example-1.0.0-py3-none-any.whl</a>\
             </body></html>";
        let (entries, _) = index_source::parse_body_to_entries(
            &bytes::Bytes::from(html.to_string()),
            simple_index::SimpleIndexFormat::Html,
            "example",
            &std::collections::HashMap::new(),
        );
        assert_eq!(entries.len(), 1);
        let hort_app::use_cases::index_serve::PerVersionPayload::Pypi(payload) =
            &entries[0].payload
        else {
            unreachable!()
        };
        assert!(
            payload.files[0].metadata_hash.is_none(),
            "absent upstream PEP 658 attribute must yield metadata_hash=None"
        );
    }

    #[tokio::test]
    async fn proxy_parser_html_truthy_attribute_yields_none() {
        // Upstream advertises `data-dist-info-metadata="true"` (PEP
        // 658's "metadata available, integrity unknown" shape). The
        // proxy can't VERIFY a hashless metadata blob, so we discard
        // it and emit no PEP 658 attribute on the served index. The
        // alternative would be to forward `="true"`, but we cap that
        // out to keep the cross-the-wire client verification
        // unconditional — a PEP 658 advertisement on hort's served
        // index ALWAYS has a verifiable hash.
        let html = "<!DOCTYPE html><html><body>\
             <a href=\"https://files.pythonhosted.org/packages/00/00/\
             example-1.0.0-py3-none-any.whl\" \
             data-dist-info-metadata=\"true\">\
             example-1.0.0-py3-none-any.whl</a>\
             </body></html>";
        let (entries, _) = index_source::parse_body_to_entries(
            &bytes::Bytes::from(html.to_string()),
            simple_index::SimpleIndexFormat::Html,
            "example",
            &std::collections::HashMap::new(),
        );
        let hort_app::use_cases::index_serve::PerVersionPayload::Pypi(payload) =
            &entries[0].payload
        else {
            unreachable!()
        };
        assert!(
            payload.files[0].metadata_hash.is_none(),
            "non-sha256 PEP 658 advertisement must collapse to None"
        );
    }

    #[tokio::test]
    async fn proxy_parser_json_extracts_upstream_pep658_hash() {
        let upstream_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let body = serde_json::json!({
            "meta": {"api-version": "1.1"},
            "name": "example",
            "files": [{
                "filename": "example-1.0.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/00/00/example-1.0.0-py3-none-any.whl",
                "hashes": {"sha256": "aaaa"},
                "dist-info-metadata": {"sha256": upstream_hex},
            }],
            "versions": ["1.0.0"],
        });
        let bytes_body = serde_json::to_vec(&body).unwrap();
        let (entries, _) = index_source::parse_body_to_entries(
            &bytes::Bytes::from(bytes_body),
            simple_index::SimpleIndexFormat::Json,
            "example",
            &std::collections::HashMap::new(),
        );
        assert_eq!(entries.len(), 1);
        let hort_app::use_cases::index_serve::PerVersionPayload::Pypi(payload) =
            &entries[0].payload
        else {
            unreachable!()
        };
        let metadata_hash = payload.files[0]
            .metadata_hash
            .as_ref()
            .expect("upstream advertised sha256 → metadata_hash populated");
        assert_eq!(metadata_hash.as_ref(), upstream_hex);
    }

    #[tokio::test]
    async fn proxy_parser_json_dist_info_metadata_false_yields_none() {
        // PEP 691 — `"dist-info-metadata": false` (the "no metadata
        // available" shape, the same wire value we emit when hort has
        // no `wheel_metadata` CR). The proxy parser must collapse
        // this to `None` so the built index re-emits `false` (rather
        // than re-emitting the upstream's `false` as-is — wire-shape
        // identical, but the data path is `None → Builder.None →
        // wire false`, not pass-through).
        let body = serde_json::json!({
            "meta": {"api-version": "1.1"},
            "name": "example",
            "files": [{
                "filename": "example-1.0.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/00/00/example-1.0.0-py3-none-any.whl",
                "hashes": {"sha256": "aaaa"},
                "dist-info-metadata": false,
            }],
            "versions": ["1.0.0"],
        });
        let bytes_body = serde_json::to_vec(&body).unwrap();
        let (entries, _) = index_source::parse_body_to_entries(
            &bytes::Bytes::from(bytes_body),
            simple_index::SimpleIndexFormat::Json,
            "example",
            &std::collections::HashMap::new(),
        );
        let hort_app::use_cases::index_serve::PerVersionPayload::Pypi(payload) =
            &entries[0].payload
        else {
            unreachable!()
        };
        assert!(payload.files[0].metadata_hash.is_none());
    }

    // -- authz tests ----------------------------------------------------------------
    //
    // Exercise `resolve_actor_user_id` end-to-end via the handler surface:
    // - authz-allow path → upload proceeds, 200 response.
    // - authz-deny path → 403 with stable error body, handler never hits
    //   storage.
    // - `emit_authz_metric` unit test proves both counter labels tick.
    //
    // These four tests live alongside the existing pypi handler tests
    // because the helper was intentionally co-located with the pypi handler
    // (see the "Shared authorization helpers" block in the module body).

    mod authz {
        use super::*;

        use chrono::Utc;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
        use metrics_util::{CompositeKey, MetricKind};

        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
        use hort_domain::entities::caller::CallerPrincipal;
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;

        use hort_http_core::test_support::with_auth;

        type MetricEntry = (
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        );

        /// RBAC snapshot with the `developer` claim granted
        /// `Permission::Write` globally (`GrantSubject::Claims` flat grant
        /// set). Tests use this so a principal whose resolved claims contain
        /// `developer` passes authorize, and a principal with no claims is
        /// denied.
        // Tests build the evaluator snapshot and wrap it in
        // `Arc<ArcSwap<_>>` — matches the `AuthContext::Enabled.rbac`
        // field type. Tests don't exercise the refresh path (that's
        // covered in `hort-server::cli::serve::rbac_refresh`); they just
        // need a static snapshot reachable through `.load()`.
        fn developer_write_evaluator() -> Arc<arc_swap::ArcSwap<RbacEvaluator>> {
            let grant = PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["developer".into()]),
                repository_id: None,
                permission: Permission::Write,
                created_at: Utc::now(),
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            };
            Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
                grant,
            ])))
        }

        /// Build a principal whose resolved claim set is `claims`.
        /// `["developer"]` matches the [`developer_write_evaluator`] grant
        /// and `["admin"]` triggers the evaluator admin short-circuit.
        fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
            CallerPrincipal {
                user_id: Uuid::from_u128(0xA11CE),
                external_id: "kc:alice".into(),
                username: "alice".into(),
                email: "alice@example.com".into(),
                claims: claims.iter().map(|s| (*s).to_string()).collect(),
                token_kind: None,
                issued_at: Utc::now(),
                token_cap: None,
            }
        }

        /// Transform the existing pypi harness into one whose `AppContext`
        /// carries `AuthContext::Enabled` with a test RBAC evaluator.
        /// Callers then inject a principal into request extensions (or
        /// omit one, for the "missing principal" case).
        fn enabled_harness() -> TestHarness {
            let h = harness();
            let idp = Arc::new(MockIdentityProvider::new());
            let users = Arc::new(MockUserRepository::new());
            let authenticate = Arc::new(AuthenticateUseCase::new(
                idp as Arc<dyn IdentityProvider>,
                users as Arc<dyn UserRepository>,
                Vec::new(),
            ));
            let rbac = developer_write_evaluator();
            let ctx = with_auth(
                &h.ctx,
                AuthContext::Enabled {
                    authenticate,
                    rbac,
                    // PyPI tests don't exercise the WWW-Authenticate selector.
                    issuer_url: None,
                },
            );
            TestHarness {
                ctx,
                artifacts: h.artifacts,
                repositories: h.repositories,
                storage: h.storage,
                artifact_metadata: h.artifact_metadata,
                curation_rules: h.curation_rules,
                content_references: h.content_references,
                lifecycle: h.lifecycle,
                events: h.events,
            }
        }

        fn capture<T, F: FnOnce() -> T>(f: F) -> (Snapshot, T) {
            let recorder = DebuggingRecorder::new();
            let snap = recorder.snapshotter();
            let out = metrics::with_local_recorder(&recorder, f);
            (snap.snapshot(), out)
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

        /// Drive `POST /pypi/{repo}/` with a freshly-built multipart body
        /// and an optional pre-injected principal. Returns (status, body).
        async fn post_upload_with_principal(
            ctx: Arc<AppContext>,
            principal: Option<CallerPrincipal>,
        ) -> (StatusCode, Vec<u8>) {
            let router = router(ctx);
            let boundary = "----hortauthz";
            let body_bytes = build_multipart_body(boundary, b"payload");
            let mut req = Request::post("/pypi/pypi-test/")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body_bytes))
                .unwrap();
            // Wrap in `AuthenticatedPrincipal` via the test-support helper.
            if let Some(p) = principal {
                hort_http_core::middleware::auth::test_support::inject_principal(&mut req, p);
            }
            let res = router.oneshot(req).await.unwrap();
            let status = res.status();
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        }

        /// Allow path: authorized principal flows through to ingest and
        /// returns 200. `hort_authz_decisions_total{result="allow",
        /// permission="write"}` ticks exactly once.
        #[test]
        fn upload_authorized_principal_proceeds_to_success_path() {
            let (snap, (status, _body)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = enabled_harness();
                        insert_repo(&h, "pypi-test");
                        post_upload_with_principal(
                            h.ctx.clone(),
                            Some(principal_with_claims(&["developer"])),
                        )
                        .await
                    })
            });
            assert_eq!(status, StatusCode::OK);
            let entries = snap.into_vec();
            let v = find_counter(
                &entries,
                "hort_authz_decisions_total",
                &[("result", "allow"), ("permission", "write")],
            )
            .expect("allow counter absent");
            assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        }

        /// Deny path: principal lacks any role granting `Permission::Write`.
        /// Handler returns 403 with the stable error body and
        /// `hort_authz_decisions_total{result="deny"}` ticks.
        #[test]
        fn upload_denied_principal_returns_403() {
            let (snap, (status, body)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = enabled_harness();
                        insert_repo(&h, "pypi-test");
                        post_upload_with_principal(
                            h.ctx.clone(),
                            // No roles → no grants → deny.
                            Some(principal_with_claims(&[])),
                        )
                        .await
                    })
            });
            assert_eq!(status, StatusCode::FORBIDDEN);
            let body_str = String::from_utf8(body).unwrap();
            // Stable error shape native clients may match on.
            assert!(
                body_str.contains(r#""error":"insufficient permissions""#),
                "unexpected body: {body_str}"
            );
            let entries = snap.into_vec();
            let v = find_counter(
                &entries,
                "hort_authz_decisions_total",
                &[("result", "deny"), ("permission", "write")],
            )
            .expect("deny counter absent");
            assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        }

        /// `emit_authz_metric` pure-helper unit test: both counter cells
        /// increment independently. Sanity-check the helper's label
        /// plumbing without relying on a full handler round-trip.
        #[test]
        fn emit_authz_metric_increments_both_labels() {
            let (snap, _) = capture(|| {
                emit_authz_metric("allow", "write");
                emit_authz_metric("deny", "write");
                emit_authz_metric("allow", "read");
            });
            let entries = snap.into_vec();
            let allow_write = find_counter(
                &entries,
                "hort_authz_decisions_total",
                &[("result", "allow"), ("permission", "write")],
            )
            .expect("allow/write missing");
            let deny_write = find_counter(
                &entries,
                "hort_authz_decisions_total",
                &[("result", "deny"), ("permission", "write")],
            )
            .expect("deny/write missing");
            let allow_read = find_counter(
                &entries,
                "hort_authz_decisions_total",
                &[("result", "allow"), ("permission", "read")],
            )
            .expect("allow/read missing");
            assert!(matches!(allow_write, DebugValue::Counter(n) if *n == 1));
            assert!(matches!(deny_write, DebugValue::Counter(n) if *n == 1));
            assert!(matches!(allow_read, DebugValue::Counter(n) if *n == 1));
        }

        /// `Enabled` with no principal in extensions means the
        /// `require_principal` layer did not run — that's a router-wiring
        /// bug. Surface as a 500 rather than silently allowing the write.
        #[test]
        fn upload_enabled_without_principal_returns_500() {
            let (_, (status, body)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = enabled_harness();
                        insert_repo(&h, "pypi-test");
                        // No principal injected — simulate the middleware
                        // mis-wiring case.
                        post_upload_with_principal(h.ctx.clone(), None).await
                    })
            });
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            // 5xx responses must never leak internal paths /
            // crate identifiers.
            hort_http_core::error::assert_no_internal_leakage(status, &body);
        }

        /// Sanity: the admin short-circuit carries through the handler
        /// layer as expected — admins bypass grant resolution.
        #[test]
        fn upload_admin_short_circuit_proceeds() {
            let status = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let h = enabled_harness();
                    insert_repo(&h, "pypi-test");
                    let (status, _) = post_upload_with_principal(
                        h.ctx.clone(),
                        Some(principal_with_claims(&["admin"])),
                    )
                    .await;
                    status
                });
            assert_eq!(status, StatusCode::OK);
        }
    }

    // -- Read-side anti-enumeration --------------------------------------------------
    //
    // Mirrors the Cargo + npm anti-enumeration regression tests
    // (`tests::anti_enumeration` in `crates/hort-http-cargo/src/lib.rs` &
    // `crates/hort-http-npm/src/lib.rs`). Proves that anonymous read paths
    // on a private repo collapse to `404` indistinguishably from a
    // missing-repo response (ADR 0008).
    //
    // Two scenarios per route family:
    // 1. Missing repo + anonymous → 404 (baseline, already worked).
    // 2. Private repo + anonymous → 404 (the regression — previously
    //    PyPI's `find_by_key` admitted every read with no visibility
    //    check, returning 200 + index body / package bytes).
    //
    // PyPI has four read endpoints that count as enumeration surface:
    // - root simple index (`GET /:repo/simple/`) — leaks the full
    //   package roster of the repo.
    // - per-project simple index (`GET /:repo/simple/:project/`) — the
    //   PEP 503 HTML form. Leaks every distribution + sha256 hash for
    //   a guessed package name. Same handler covers PEP 691 JSON via
    //   content-negotiation, exercised in its own assertion.
    // - tarball / wheel download (`GET /:repo/simple/:project/:filename`)
    //   — leaks the artifact bytes themselves.
    // - PEP 658 `.metadata` sibling (same route slot, suffix-branched)
    //   — leaks the wheel METADATA bytes.
    //
    // All four are exercised. The HTML + JSON branches share the same
    // `serve_*` helper after the visibility hop, so the JSON variant
    // gets its own assertion to prove the content-negotiation path
    // also flows through the use case.

    mod anti_enumeration {
        use std::sync::Arc;

        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_http_core::test_support::with_repository_access;

        use super::*;

        /// Flip the harness's `RepositoryAccessUseCase` from the
        /// default `Disabled` (admit-everything dev mode) to `Enabled`
        /// with an empty RBAC evaluator. Anonymous + private repo now
        /// collapses to `NotFound` — the realistic deployment scenario
        /// the regression test exists to lock in.
        fn enabled_rbac_harness() -> TestHarness {
            let h = harness();
            // `ctx.repositories` is `pub(crate)` (ADR 0008); construct the
            // access use case from the harness's MockPorts handle
            // (`h.repositories`), which is the same `Arc` wired into the ctx.
            let access = Arc::new(RepositoryAccessUseCase::new(
                h.repositories.clone(),
                RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                    RbacEvaluator::new(Vec::new()),
                ))),
                true,
            ));
            let ctx = with_repository_access(&h.ctx, access);
            TestHarness {
                ctx,
                artifacts: h.artifacts,
                repositories: h.repositories,
                storage: h.storage,
                artifact_metadata: h.artifact_metadata,
                curation_rules: h.curation_rules,
                content_references: h.content_references,
                lifecycle: h.lifecycle,
                events: h.events,
            }
        }

        fn insert_private_repo(h: &TestHarness, key: &str) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.to_string();
            repo.format = RepositoryFormat::Pypi;
            repo.is_public = false;
            h.repositories.insert(repo.clone());
            repo
        }

        /// Compare two `(StatusCode, Vec<u8>)` 404 responses for
        /// anti-enumeration equivalence: status MUST match and the
        /// JSON envelope shape (`{"error":"not found: Repository
        /// <id>"}`) MUST be identical except for the id token. Both
        /// are the canonical `not found: Repository <id>` envelope,
        /// differing only in the id token. Format equality is what
        /// an operator-side enumeration probe would observe.
        fn assert_anti_enumeration_envelope(
            private: &(StatusCode, Vec<u8>),
            missing: &(StatusCode, Vec<u8>),
        ) {
            assert_eq!(
                private.0, missing.0,
                "anti-enumeration: status codes must match"
            );
            assert_eq!(private.0, StatusCode::NOT_FOUND);

            let private_json: serde_json::Value =
                serde_json::from_slice(&private.1).expect("private body must be JSON");
            let missing_json: serde_json::Value =
                serde_json::from_slice(&missing.1).expect("missing body must be JSON");

            // Same set of keys (envelope shape).
            let private_keys: Vec<&str> = private_json
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let missing_keys: Vec<&str> = missing_json
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                private_keys, missing_keys,
                "anti-enumeration: envelope keys must match"
            );

            // Both messages must be the canonical Repository NotFound
            // string, differing only in the id token. An attacker
            // observing either body learns nothing beyond "no such
            // repository (or invisible)".
            let private_msg = private_json["error"].as_str().expect("error key");
            let missing_msg = missing_json["error"].as_str().expect("error key");
            assert!(
                private_msg.starts_with("not found: Repository "),
                "private envelope shape: {private_msg}"
            );
            assert!(
                missing_msg.starts_with("not found: Repository "),
                "missing envelope shape: {missing_msg}"
            );
        }

        /// Anti-enumeration regression: anonymous GET of the root
        /// PEP 503 simple index on a **private** repo MUST return the
        /// same 404 envelope as the missing-repo case. Previously
        /// the PyPI handler reached `ctx.repositories.find_by_key` +
        /// `ctx.artifacts.list_distinct_names` directly with no
        /// visibility check, so anonymous callers could enumerate
        /// every package in any private repo whose key they could guess.
        #[tokio::test]
        async fn anonymous_get_simple_root_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-pypi");
            // Seed an artifact so the missing-vs-private collapse can't
            // be explained by "no rows match the lookup" — the row
            // exists, only the visibility check rejects it.
            insert_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "secret-pkg-1.0.tar.gz",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/pypi/private-pypi/simple/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous read on private pypi root index MUST be 404 (anti-enumeration)"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/pypi/ghost-pypi/simple/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let missing_status = missing_resp.status();
            let missing_body = to_bytes(missing_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            assert_anti_enumeration_envelope(
                &(private_status, private_body),
                &(missing_status, missing_body),
            );
        }

        /// Same invariant, on the per-project HTML simple index
        /// (PEP 503). The leak shape here is per-distribution: every
        /// version, every sha256, every requires-python annotation.
        #[tokio::test]
        async fn anonymous_get_simple_project_html_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-pypi");
            insert_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "secret-pkg-1.0.tar.gz",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/pypi/private-pypi/simple/secret-pkg/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous read on private pypi simple/<project>/ MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/pypi/ghost-pypi/simple/secret-pkg/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let missing_status = missing_resp.status();
            let missing_body = to_bytes(missing_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            assert_anti_enumeration_envelope(
                &(private_status, private_body),
                &(missing_status, missing_body),
            );
        }

        /// Same invariant, on the PEP 691 JSON content-negotiation
        /// branch of the simple-project handler. The handler is the
        /// same code path; this assertion proves the visibility check
        /// fires before the content-neg branch (so a JSON-asking
        /// client cannot bypass anti-enumeration by adding an
        /// `Accept: application/vnd.pypi.simple.v1+json` header).
        #[tokio::test]
        async fn anonymous_get_simple_project_json_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-pypi");
            insert_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "secret-pkg-1.0.tar.gz",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/pypi/private-pypi/simple/secret-pkg/")
                        .header("accept", "application/vnd.pypi.simple.v1+json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous PEP 691 JSON read on private pypi MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/pypi/ghost-pypi/simple/secret-pkg/")
                        .header("accept", "application/vnd.pypi.simple.v1+json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let missing_status = missing_resp.status();
            let missing_body = to_bytes(missing_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            assert_anti_enumeration_envelope(
                &(private_status, private_body),
                &(missing_status, missing_body),
            );
        }

        /// Same invariant, on the tarball / wheel download route. The
        /// leak shape here is the worst possible: the artifact bytes
        /// themselves. Both private-repo and missing-repo MUST return
        /// the same canonical Repository 404 envelope.
        #[tokio::test]
        async fn anonymous_get_download_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-pypi");
            insert_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "secret-pkg-1.0.tar.gz",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/pypi/private-pypi/simple/secret-pkg/secret-pkg-1.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous download on private pypi repo MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/pypi/ghost-pypi/simple/secret-pkg/secret-pkg-1.0.tar.gz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let missing_status = missing_resp.status();
            let missing_body = to_bytes(missing_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            assert_anti_enumeration_envelope(
                &(private_status, private_body),
                &(missing_status, missing_body),
            );
        }

        /// Same invariant, on the PEP 658 `.metadata` sibling endpoint.
        /// Served from the same route slot as `download` via suffix
        /// branch, so it carries its own visibility hop through the
        /// `serve_package_metadata` helper. The leak shape here is the
        /// synthesised PKG-INFO block (Name, Version, requires-python,
        /// etc.) — enough to confirm a guessed (repo, package, version)
        /// triple in any private repo.
        #[tokio::test]
        async fn anonymous_get_pep658_metadata_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-pypi");
            insert_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "secret-pkg-1.0.tar.gz",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get(
                        "/pypi/private-pypi/simple/secret-pkg/secret-pkg-1.0.tar.gz.metadata",
                    )
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous PEP 658 .metadata read on private pypi MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get(
                        "/pypi/ghost-pypi/simple/secret-pkg/secret-pkg-1.0.tar.gz.metadata",
                    )
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            let missing_status = missing_resp.status();
            let missing_body = to_bytes(missing_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            assert_anti_enumeration_envelope(
                &(private_status, private_body),
                &(missing_status, missing_body),
            );
        }
    }

    // -- simple-index LIMIT / pagination ------------------------------------------------

    /// Simple-index `Warning` header is absent on a non-truncated
    /// response. Smoke test on the standard happy path: a few packages
    /// produce a complete `<a>` list with no warning.
    #[tokio::test]
    async fn simple_root_does_not_emit_warning_header_when_under_cap() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(&h, repo.id, "pkg-a", "a-1.0.tar.gz", QuarantineStatus::None);
        insert_artifact(&h, repo.id, "pkg-b", "b-1.0.tar.gz", QuarantineStatus::None);
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.headers().get("Warning").is_none(),
            "non-truncated response must not carry a Warning header"
        );
    }

    /// Simple-project `Warning` header absent under the cap. Verifies
    /// the PEP 503 happy path through `list_by_raw_name_limited`.
    #[tokio::test]
    async fn simple_project_does_not_emit_warning_header_when_under_cap() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        insert_artifact(
            &h,
            repo.id,
            "requests",
            "requests-2.31.0.tar.gz",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/requests/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.headers().get("Warning").is_none(),
            "non-truncated response must not carry a Warning header"
        );
    }

    /// 5 000-version seed on a PyPI simple-project page: the body is a
    /// complete document with no `Warning` header. Sanity-checks the
    /// non-truncation path at large legitimate scale. Mirrors the npm
    /// equivalent.
    #[tokio::test]
    #[ignore = "slow: seeds 5_000 versions"]
    async fn simple_project_handles_5000_versions_with_no_warning_header() {
        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        for i in 0..5_000_u32 {
            insert_artifact(
                &h,
                repo.id,
                "many-versions",
                &format!("many-versions-0.0.{i}.tar.gz"),
                QuarantineStatus::None,
            );
        }
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/many-versions/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.headers().get("Warning").is_none(),
            "5_000-version simple-project must not carry Warning header"
        );
    }

    /// At `LIMIT_LIST_MAX_ITEMS + 1` versions the use-case truncates and
    /// the simple-project handler emits the `Warning: 299` header.
    #[tokio::test]
    #[ignore = "slow: seeds LIMIT_LIST_MAX_ITEMS+1 versions"]
    async fn simple_project_emits_warning_header_when_truncated_at_cap() {
        use hort_domain::types::LIMIT_LIST_MAX_ITEMS;

        let h = harness();
        let repo = insert_repo(&h, "pypi-test");
        for i in 0..(LIMIT_LIST_MAX_ITEMS as u32 + 1) {
            insert_artifact(
                &h,
                repo.id,
                "many-versions",
                &format!("many-versions-0.0.{i}.tar.gz"),
                QuarantineStatus::None,
            );
        }
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/pypi/pypi-test/simple/many-versions/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let warning = res
            .headers()
            .get("Warning")
            .expect("Warning header present on truncation");
        let warning = warning.to_str().unwrap();
        assert!(
            warning.contains("results truncated"),
            "warning header content: {warning}"
        );
        assert!(
            warning.contains(&LIMIT_LIST_MAX_ITEMS.to_string()),
            "warning header should mention cap: {warning}"
        );
    }
}
