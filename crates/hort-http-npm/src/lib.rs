//! npm registry handlers.
//!
//! Routes (mounted under `/npm`):
//! - `GET  /{repo_key}/{name}`                               — unscoped packument
//! - `GET  /{repo_key}/@{scope}/{name}`                      — scoped packument
//! - `GET  /{repo_key}/{name}/-/{filename}`                  — unscoped tarball
//! - `GET  /{repo_key}/@{scope}/{name}/-/{filename}`         — scoped tarball
//! - `PUT  /{repo_key}/{name}`                               — unscoped publish
//! - `PUT  /{repo_key}/@{scope}/{name}`                      — scoped publish
//!
//! Segment count disambiguates all six routes cleanly — 2/3/4/5 path
//! segments after `/npm/`. No axum priority rules to rely on.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::Utc;

use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::ArtifactCoords;
use hort_formats::npm::NpmFormatHandler;

use hort_http_core::authz::write::{reject_write_to_virtual, resolve_actor_user_id};
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::limits::{BoundedPath, DEFAULT_PUBLISH_BODY_LIMIT};
use hort_http_core::middleware::auth::AuthenticatedPrincipal;
use hort_http_core::middleware::trust::RequestTrust;

// Packument pull-through cache for Proxy repos (see ADR 0006). The
// dispatch hop in `packument_unscoped` / `packument_scoped` resolves
// the repo first, branches on `repo_type`, and routes Proxy requests
// through this module before the existing local-CAS handler.
//
// Module is `pub` so the `hort-formats-upstream` composition crate
// can call `packument::fetch_raw_with_cache`. Every other path through
// this module stays internal (the per-helper rustdoc declares the
// supported callers); the visibility-promotion exists only for that
// one composition seam. See `packument::fetch_raw_with_cache` for the
// full warning.
pub mod packument;

// Verified tarball pull-through for Proxy repos. Wired from
// `serve_tarball` on a Proxy-repo cache miss. Mirrors PyPI / Cargo
// crate-private visibility.
pub(crate) mod upstream_pull;

// Streaming publish-body decoder: npm publish never buffers the full
// base64 `_attachments[*].data` in memory. The previous
// `body: Bytes` + `base64::decode` path held ~525 MiB per concurrent
// publish for a 200 MiB tarball; the streaming path bounds peak heap
// to O(envelope-without-base64).
pub(crate) mod streaming_publish;

// npm side of the unified Source → Filter → Builder pipeline
// (see `docs/architecture/explanation/index-construction.md`).
// `index_source` defines the per-format-internal `IndexSource` trait
// + `HostedNpmSource` / `ProxyNpmSource` impls; `serve` is the
// unified handler dispatch hop. `ProxyNpmSource` directly drives the
// upstream-fetch + cache path (`packument::fetch_raw_with_cache`).
pub(crate) mod index_source;
pub(crate) mod serve;

/// Build the npm route tree with the default publish body limit.
///
/// The default ([`DEFAULT_PUBLISH_BODY_LIMIT`] — 300 MiB) accounts for
/// ~4/3 base64 expansion over a ~200 MiB tarball. Without an explicit
/// override axum's default 2 MiB limit rejects essentially every npm
/// publish.
pub fn npm_routes() -> Router<Arc<AppContext>> {
    npm_routes_with_publish_limit(DEFAULT_PUBLISH_BODY_LIMIT)
}

/// Build the npm route tree with a custom publish body limit (in bytes).
///
/// `router.rs::build_router` calls this with the effective limit
/// (`HORT_PUBLISH_BODY_MAX_SIZE` or the default). Tests also use it
/// directly to exercise the body-limit reject path without sending
/// hundreds of megabytes.
///
/// The publish body is consumed as a streaming `Body` (no `Bytes`
/// extractor), so axum's [`DefaultBodyLimit`] no longer enforces the
/// cap on its own — the extractor that consults the marker is gone.
/// The same `limit` value is therefore propagated as a router-scoped
/// [`NpmPublishLimit`] extension, and the streaming decoder rejects
/// with 413 when the byte counter exceeds it. We keep
/// `DefaultBodyLimit::max(limit)` on the layer stack as
/// defence-in-depth for any future non-streaming extractor (or for
/// the per-route limit extractor on GET handlers, which read no body).
pub fn npm_routes_with_publish_limit(limit: usize) -> Router<Arc<AppContext>> {
    // Scoped (more-specific) routes are registered first. axum's matchit
    // disambiguates by segment count, but ordering first preserves intent
    // and guards against a future matcher rule change.
    Router::new()
        .route("/:repo_key/:scope/:name/-/:filename", get(download_scoped))
        .route(
            "/:repo_key/:scope/:name",
            get(packument_scoped).put(publish_scoped),
        )
        .route("/:repo_key/:name/-/:filename", get(download_unscoped))
        .route(
            "/:repo_key/:name",
            get(packument_unscoped).put(publish_unscoped),
        )
        // Body limit applies to every route; GET requests carry no body, so
        // only PUT publishes are actually constrained. Layering once here
        // avoids per-route layer plumbing and is still easy to override in
        // tests via `npm_routes_with_publish_limit`.
        .layer(DefaultBodyLimit::max(limit))
        // Propagate the same value to the streaming publish decoder
        // so it can emit 413 itself when counting body bytes.
        .layer(Extension(NpmPublishLimit(limit)))
}

/// Router-scoped marker carrying the configured publish body limit.
///
/// Extracted by the streaming publish handler ([`do_publish`]) and
/// passed through to [`streaming_publish::stream_decode_body`] as the
/// `body_limit_bytes` parameter. `DefaultBodyLimit` only applies to
/// extractors that consult its marker; with the streaming `Body`
/// consumer the marker is invisible, so we propagate the value via
/// this Extension.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NpmPublishLimit(pub usize);

// ---------------------------------------------------------------------------
// Packument
// ---------------------------------------------------------------------------

async fn packument_unscoped(
    State(ctx): State<Arc<AppContext>>,
    Extension(trust): Extension<RequestTrust>,
    BoundedPath((repo_key, name)): BoundedPath<(String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    let pkg = NpmFormatHandler.normalize_name(&name);
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    dispatch_packument(&ctx, &repo_key, &pkg, &trust, actor).await
}

async fn packument_scoped(
    State(ctx): State<Arc<AppContext>>,
    Extension(trust): Extension<RequestTrust>,
    BoundedPath((repo_key, scope, name)): BoundedPath<(String, String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    if !scope.starts_with('@') {
        return Err(validation_error("scoped npm name must start with '@'"));
    }
    let full = format!("{scope}/{name}");
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    dispatch_packument(&ctx, &repo_key, &full, &trust, actor).await
}

/// Packument dispatch — both `Proxy` and `Hosted` / `Staging` /
/// `Virtual` paths route through the unified
/// [`serve::serve_packument_unified`] handler, which dispatches a
/// source by `repo.repo_type` internally and threads the result
/// through the Source → Filter → Builder pipeline.
async fn dispatch_packument(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    pkg_name: &str,
    trust: &RequestTrust,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    serve::serve_packument_unified(ctx, repo_key, pkg_name, trust, actor).await
}

// ---------------------------------------------------------------------------
// Tarball download
// ---------------------------------------------------------------------------

async fn download_unscoped(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, name, filename)): BoundedPath<(String, String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    // Use the URL segment as-is. The packument handler emits tarball URLs
    // built from `artifact.name` (the stored form at ingest time), so
    // clients following those URLs carry the stored form — re-normalising
    // here would break drift resilience under a non-idempotent plugin
    // update.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    serve_tarball(&ctx, &repo_key, &name, &filename, actor).await
}

async fn download_scoped(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, scope, name, filename)): BoundedPath<(String, String, String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    if !scope.starts_with('@') {
        return Err(validation_error("scoped npm name must start with '@'"));
    }
    let full = format!("{scope}/{name}");
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    serve_tarball(&ctx, &repo_key, &full, &filename, actor).await
}

async fn serve_tarball(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    pkg_name: &str,
    filename: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    use hort_domain::entities::repository::RepositoryType;

    let artifact_path = format!("{pkg_name}/-/{filename}");

    // `find_visible_by_path` resolves the repo via
    // `RepositoryAccessUseCase::resolve(_, actor, Read)` first, then
    // looks up the artifact scoped to that repo's id. Repo missing,
    // repo invisible to actor, and artifact missing all collapse to the
    // same `NotFound` envelope (anti-enumeration).
    //
    // On a cache miss for a `RepositoryType::Proxy` repo, route through
    // [`upstream_pull::try_upstream_tarball_pull`] and serve the
    // freshly-minted artifact via the existing quarantine + streaming
    // code below. Hosted/Staging/Virtual repos keep the cache-miss → 404
    // behaviour. The branch hinges on the `entity` discriminator inside
    // `find_visible_by_path`'s `NotFound`: `"Repository"` (missing or
    // invisible) propagates as 404 immediately — same envelope, no
    // upstream side-effect; `"Artifact"` (repo visible, path missing)
    // falls through to the type-check branch below.
    let (_repo, artifact) = match ctx
        .artifact_use_case
        .find_visible_by_path(repo_key, &artifact_path, actor)
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
                .resolve(repo_key, actor, AccessLevel::Read)
                .await?;
            match repo.repo_type {
                RepositoryType::Proxy => {
                    // Filename → version inference: `{basename}-{version}.tgz`.
                    // For scoped names the basename is the post-slash segment
                    // (`@types/node` → `node`), matching the public-registry
                    // download URL convention (`@scope/pkg/-/pkg-{ver}.tgz`).
                    let basename = unscoped_basename(pkg_name);
                    let Some(version) = extract_version(filename, basename) else {
                        // The wire filename does not parse as
                        // `{basename}-{ver}.tgz`. Fall through to the same 404
                        // envelope as the local-miss path: there is nothing to
                        // fetch upstream.
                        return Err(ApiError::from(hort_app::error::AppError::Domain(
                            hort_domain::error::DomainError::NotFound {
                                entity: "Artifact",
                                id: format!("{repo_key}:{artifact_path}"),
                            },
                        )));
                    };
                    match upstream_pull::try_upstream_tarball_pull(
                        ctx, &repo, pkg_name, &version, filename,
                    )
                    .await
                    {
                        Ok(_artifact) => {
                            // The orchestrator minted the row; re-fetch via the
                            // same use case the local-CAS path uses. This keeps
                            // the response body read-from-CAS path identical.
                            ctx.artifact_use_case
                                .find_visible_by_path(repo_key, &artifact_path, actor)
                                .await?
                        }
                        Err(e) => return Ok(upstream_pull::map_upstream_pull_error(&e)),
                    }
                }
                RepositoryType::Virtual => {
                    // Transparent aggregation (ADR 0031): the member sources
                    // already enforce visibility + quarantine; the resolver
                    // picks the authoritative member and we render its gate
                    // through the SAME `render_artifact_response` tail — no
                    // `Virtual` branch leaks into the gate/stream code.
                    return serve_virtual_tarball(
                        ctx,
                        &repo,
                        pkg_name,
                        &artifact_path,
                        filename,
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

    render_artifact_response(ctx, artifact, actor).await
}

/// Render the final tarball HTTP response for a resolved artifact: surface
/// the quarantine gate (`Quarantined` → 503 + `Retry-After`,
/// `Rejected` / `ScanIndeterminate` → 403) or stream the bytes from CAS.
///
/// Shared by the hosted/proxy direct path and the virtual aggregation path
/// (ADR 0031) so the gate render + streaming live in exactly one place; the
/// virtual layer only chooses which member's artifact reaches here.
async fn render_artifact_response(
    ctx: &Arc<AppContext>,
    artifact: hort_domain::entities::artifact::Artifact,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
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
        // Retry-After). The scanning-pipeline design (ADR 0007) governs
        // the `scan_indeterminate` HTTP shape.
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

    let mut out_headers = HeaderMap::new();
    out_headers.insert(
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
    out_headers.insert(CONTENT_LENGTH, artifact.size_bytes.into());
    Ok((StatusCode::OK, out_headers, body).into_response())
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

/// Transparent virtual tarball download (ADR 0031). Resolves the
/// authoritative member via
/// [`VirtualResolutionUseCase::resolve_download`](hort_app::use_cases::virtual_resolution::VirtualResolutionUseCase::resolve_download)
/// (name-level pinning + first-authoritative walk + the fail-closed member
/// rule all live in `hort-app`), then renders the chosen artifact's gate
/// through the same [`render_artifact_response`] tail the hosted/proxy path
/// uses. `serve_tarball` never special-cases `Virtual` past the source
/// dispatch.
async fn serve_virtual_tarball(
    ctx: &Arc<AppContext>,
    virtual_repo: &hort_domain::entities::repository::Repository,
    pkg_name: &str,
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
                    npm_member_name_presence(ctx, &member, pkg_name, actor).await
                },
                // Phase 2 — per-member coordinate fetch (hosted lookup / proxy
                // pull), classified for the first-authoritative walk.
                move |member| async move {
                    npm_member_coord_fetch(ctx, &member, pkg_name, artifact_path, filename, actor)
                        .await
                },
            )
            .await?;

    match resolved {
        Some(VirtualMemberDownload::Found(artifact)) => {
            render_artifact_response(ctx, artifact, actor).await
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
/// across the index and download paths. Only invoked for non-proxy members.
async fn npm_member_name_presence(
    ctx: &Arc<AppContext>,
    member: &hort_domain::entities::repository::Repository,
    pkg_name: &str,
    actor: Option<&CallerPrincipal>,
) -> hort_app::use_cases::virtual_resolution::MemberNamePresence {
    use crate::index_source::select_source;
    use hort_app::use_cases::virtual_resolution::MemberNamePresence;

    match select_source(member)
        .fetch(ctx, member, pkg_name, actor)
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
async fn npm_member_coord_fetch(
    ctx: &Arc<AppContext>,
    member: &hort_domain::entities::repository::Repository,
    pkg_name: &str,
    artifact_path: &str,
    filename: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Option<VirtualMemberDownload>, hort_app::error::AppError> {
    use hort_domain::entities::repository::RepositoryType;

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
    let basename = unscoped_basename(pkg_name);
    let Some(version) = extract_version(filename, basename) else {
        return Ok(None);
    };
    match upstream_pull::try_upstream_tarball_pull(ctx, member, pkg_name, &version, filename).await
    {
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
        Err(upstream_pull::UpstreamPullError::NoUpstream)
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
// Publish
// ---------------------------------------------------------------------------

async fn publish_unscoped(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, name)): BoundedPath<(String, String)>,
    Extension(limit): Extension<NpmPublishLimit>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    request: axum::http::Request<Body>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    let handler = NpmFormatHandler;
    let pkg = handler.normalize_name(&name);
    // Strict-validate the URL-decoded package name BEFORE any storage
    // path is constructed or any side-effecting work happens.
    // `validate_npm_name` rejects mixed case, control bytes, traversal
    // sequences, oversize segments, leading `.`/`_`, and Unicode runes.
    // Failure surfaces as `DomainError::Validation` → 400 via `ApiError`.
    // The error message is `npm.name: <reason>` and never echoes the
    // offending input.
    hort_formats::npm::validate_npm_name(&pkg)?;
    let body = request.into_body();
    do_publish(&ctx, &repo_key, &pkg, principal, body, &handler, limit.0).await
}

async fn publish_scoped(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, scope, name)): BoundedPath<(String, String, String)>,
    Extension(limit): Extension<NpmPublishLimit>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    request: axum::http::Request<Body>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    let handler = NpmFormatHandler;
    let full = format!("{scope}/{name}");
    // Strict-validate the composed scoped name BEFORE any storage path
    // is constructed. The leading-`@` requirement is folded into
    // `validate_npm_name` itself — a non-`@` first byte means the
    // validator sees `notascope/pkg` as a single unscoped component
    // containing a `/`, which is rejected by the charset rule. This
    // replaces the prior `if !scope.starts_with('@')` early-return.
    hort_formats::npm::validate_npm_name(&full)?;
    let body = request.into_body();
    do_publish(&ctx, &repo_key, &full, principal, body, &handler, limit.0).await
}

#[tracing::instrument(skip(ctx, principal, body, handler), fields(repo_key, pkg_name, body_limit_bytes = body_limit_bytes))]
async fn do_publish(
    ctx: &AppContext,
    repo_key: &str,
    pkg_name: &str,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    body: Body,
    handler: &NpmFormatHandler,
    body_limit_bytes: usize,
) -> Result<Response, ApiError> {
    // Resolve the repo via the visibility-aware use case.
    // `AccessLevel::Read` gives anti-enumeration: an anonymous /
    // unauthorised principal probing for private-repo existence sees the
    // same 404 envelope as a missing repo. The subsequent
    // `resolve_actor_user_id` call below keeps enforcing the Write authz
    // gate with its existing 403 + `{"error":"insufficient permissions"}`
    // body, so the deny envelope on the WRITE permission stays verbatim.
    // Unwrap the `AuthenticatedPrincipal` newtype to
    // `Option<&CallerPrincipal>`.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    let repo = ctx
        .repository_access_use_case
        .resolve(repo_key, actor, AccessLevel::Read)
        .await?;

    // Gate write on authorization; see `handlers::pypi::resolve_actor_user_id`
    // for the full contract. The helper returns a pre-shaped `Response`
    // on reject so the deny body stays `{"error":"insufficient permissions"}`
    // verbatim.
    let actor_user_id = match resolve_actor_user_id(ctx, principal, repo.id) {
        Ok(id) => id,
        Err(response) => return Ok(*response),
    };

    // Read-only aggregator (ADR 0031): reject a publish to a `type: virtual`
    // repo, which would otherwise fall into the hosted arm below and write
    // the virtual's own (never-served) store. After the authz gate so a
    // caller without Write still sees the stable 403, not a repo-type oracle.
    reject_write_to_virtual(&repo)?;

    // Stream-decode the publish body. Peak heap stays
    // O(envelope-without-base64); the decoded tarball spools to a
    // `tempfile::NamedTempFile` on /tmp. SHA-1 computed during the spool
    // feeds `legacy_sha1` below; SHA-256 (CAS) is computed inside
    // `IngestUseCase::ingest_direct` against the temp-file `AsyncRead`.
    let decoded = match streaming_publish::stream_decode_body(body, body_limit_bytes).await {
        Ok(d) => d,
        Err(err) => return Ok(err.into_response()),
    };

    let body_json: serde_json::Value = serde_json::from_slice(&decoded.envelope)
        .map_err(|e| validation_error(&format!("invalid npm publish JSON: {e}")))?;

    // npm sends exactly one attachment per publish; its key is the tarball
    // filename.
    let attachments = body_json
        .get("_attachments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| validation_error("publish body missing `_attachments`"))?;
    let (filename, _attachment) = attachments
        .iter()
        .next()
        .ok_or_else(|| validation_error("publish body has no attachments"))?;

    // npm's `_attachments` key is the REGISTRY filename, which for scoped
    // packages includes the scope: `@scope/pkg-{version}.tgz`. For
    // unscoped it is just `pkg-{version}.tgz`. So the prefix to strip is
    // the full `pkg_name`, not the unscoped basename. An earlier version
    // here used the unscoped basename and rejected every scoped publish
    // from a real `npm publish` client with "cannot parse version" —
    // guarded by the scoped-publish tests below.
    let version = extract_version(filename, pkg_name).ok_or_else(|| {
        validation_error(&format!("cannot parse version from filename {filename}"))
    })?;

    // Pull the per-version packument block — `body["versions"][version]` —
    // to hand to ingest as payload metadata. npm publish requests always
    // carry at least one entry in `versions` keyed by the tarball's
    // version; we accept a missing or non-matching version block by
    // falling back to `Value::Null` (and the HashReference split-decision
    // then treats the ingest as summary-less).
    let payload_metadata = body_json
        .get("versions")
        .and_then(|v| v.as_object())
        .and_then(|versions| versions.get(&version))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // SHA-1 was computed incrementally during the streaming decode —
    // no double-pass over the tarball, no full buffer in memory.
    let sha1_hex = decoded.sha1_hex.clone();

    // The canonical stored path comes from the single SSOT constructor
    // (`{name}/-/{unscoped-basename}-{ver}.tgz`), the exact string
    // `NpmFormatHandler::parse_download_path` produces on subsequent GETs.
    // npm derives the filename from name+version, so `filename = None`.
    // (Storing the raw `_attachments` filename — which includes the scope for
    // scoped packages — would produce an unresolvable path.)
    let path = handler
        .build_artifact_logical_path(pkg_name, &version, None)
        .map_err(ApiError::from)?;
    let coords = ArtifactCoords {
        name: pkg_name.to_string(),
        // npm is case-preserving and `normalize_name` is URL-decode-only,
        // so the "as published" form equals `pkg_name` for already-decoded
        // inputs. Persisting it explicitly still guards against a future
        // plugin that applies any further transformation.
        name_as_published: pkg_name.to_string(),
        version: Some(version),
        path,
        format: RepositoryFormat::Npm,
        metadata: serde_json::Value::Null,
    };

    // Open a fresh `tokio::fs::File` handle on the spooled tarball
    // for `ingest_direct` to consume as `AsyncRead`. The
    // `NamedTempFile` itself is held by `decoded` for the lifetime
    // of this function; once `decoded` drops at scope-exit the OS
    // file is unlinked. A reopen failure here is mapped to 503
    // (infrastructure) — see `tempfile_reader` for rationale.
    let read_handle = match streaming_publish::tempfile_reader(&decoded.tarball_file).await {
        Ok(f) => f,
        Err(response) => return Ok(response),
    };
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(read_handle);

    let actor = ApiActor {
        user_id: actor_user_id,
    };

    let artifact = ctx
        .ingest_use_case
        .ingest_direct(
            hort_app::use_cases::ingest_use_case::DirectIngestRequest {
                repository_id: repo.id,
                coords,
                content_type: "application/octet-stream".into(),
                // Quarantine resolution is policy-driven; no
                // caller-supplied override field.
                actor,
                legacy_sha1: Some(sha1_hex),
                legacy_md5: None, // npm does not publish an MD5
                // Per-version packument block harvested above — the
                // minimal shape that `NpmFormatHandler::extract_metadata_summary`
                // can slice for the inline summary under the
                // HashReference strategy. Under 256 KB stays inline;
                // above 256 KB spills the full block to CAS and keeps
                // the 7-key summary on the event row.
                payload_metadata,
            },
            stream,
            // Reuse the handler flowed in from the route dispatchers —
            // one instance per request.
            handler,
        )
        .await?
        .artifact;

    // Tracing-level note for ops dashboards: emit a debug record on
    // happy-path so streaming behaviour is visible without paying
    // for an `info!` on every publish. Logging the stream-derived
    // SHA-1 alongside the artifact id makes it trivial to confirm
    // the new path produced the same hash the prior buffered path
    // would have.
    tracing::debug!(
        artifact_id = %artifact.id,
        tarball_size = decoded.tarball_size,
        sha1 = %decoded.sha1_hex,
        "npm streaming publish complete"
    );

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        serde_json::json!({
            "ok":  true,
            "id":  pkg_name,
            "rev": format!("1-{}", artifact.id),
        })
        .to_string(),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_version(filename: &str, basename: &str) -> Option<String> {
    let prefix = format!("{basename}-");
    let stripped = filename.strip_prefix(&prefix)?.strip_suffix(".tgz")?;
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_string())
    }
}

/// Strip a leading `@scope/` from an npm package name, returning the
/// unscoped basename used to compose / decompose tarball filenames.
///
/// npm tarballs follow the public-registry convention `{basename}-{ver}.tgz`
/// where `basename` is the post-slash segment of a scoped name
/// (`@types/node` → `node`) or the whole name when unscoped (`express`).
/// This is the same convention the publish path follows when storing
/// artifacts at `{pkg_name}/-/{basename}-{ver}.tgz` (see `do_publish`).
fn unscoped_basename(pkg_name: &str) -> &str {
    pkg_name.rsplit_once('/').map_or(pkg_name, |(_, b)| b)
}

fn validation_error(msg: &str) -> ApiError {
    ApiError::from(hort_app::error::AppError::Domain(
        hort_domain::error::DomainError::Validation(msg.to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use base64::Engine as _;
    use sha1::{Digest as _, Sha1};
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactLifecycle, MockArtifactRepository,
        MockRepositoryRepository, MockStoragePort,
    };
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::Repository;
    use hort_domain::ports::artifact_repository::ArtifactRepository;
    use hort_domain::ports::repository_repository::RepositoryRepository;

    use super::*;
    use hort_http_core::context::AppContext;
    use hort_http_core::test_support::{
        build_mock_ctx, trust_config_untrusted_peer_fallback, with_trust_config,
    };

    struct TestHarness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
        /// Exposed so the `payload_metadata`-flow test can inspect
        /// the `ArtifactMetadata` row committed by ingest. Other
        /// tests ignore it.
        lifecycle: Arc<MockArtifactLifecycle>,
        /// Curation-gate seed handle. Used by the
        /// `publish_curation_block_returns_403` test to install a
        /// blocking rule against the inbound repo.
        curation_rules: Arc<hort_app::use_cases::test_support::MockCurationRuleRepository>,
    }

    fn harness() -> TestHarness {
        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        let (ctx, mocks) = build_mock_ctx(metrics_handle);
        // Packument handlers pull the public URL from `RequestTrust`.
        // Override the default pinned URL so the handler falls back to
        // `Host` + `https` — keeps every
        // `host: registry.example.com` → `https://registry.example.com/...`
        // assertion in this module stable.
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        TestHarness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
            lifecycle: mocks.lifecycle,
            curation_rules: mocks.curation_rules,
        }
    }

    /// Build a router with the request-trust layer attached.
    ///
    /// Every handler that emits absolute URLs extracts `RequestTrust`
    /// from request extensions. Router helpers in this test module
    /// therefore replicate the production wiring: attach the same trust
    /// layer so handler tests exercise the same path as the integration
    /// stack.
    fn router(ctx: Arc<AppContext>) -> Router {
        let trust_cfg = ctx.trust_config.clone();
        Router::new()
            .nest("/npm", npm_routes())
            .layer(hort_http_core::middleware::trust::request_trust_layer(
                trust_cfg,
            ))
            .with_state(ctx)
    }

    fn router_with_publish_limit(ctx: Arc<AppContext>, limit: usize) -> Router {
        let trust_cfg = ctx.trust_config.clone();
        Router::new()
            .nest("/npm", npm_routes_with_publish_limit(limit))
            .layer(hort_http_core::middleware::trust::request_trust_layer(
                trust_cfg,
            ))
            .with_state(ctx)
    }

    fn insert_repo(h: &TestHarness, key: &str) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.to_string();
        repo.format = RepositoryFormat::Npm;
        h.repositories.insert(repo.clone());
        repo
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_tarball_artifact(
        h: &TestHarness,
        repo_id: Uuid,
        pkg_name: &str,
        version: &str,
        filename: &str,
        content: &[u8],
        sha1_hex: Option<&str>,
        status: QuarantineStatus,
    ) -> Artifact {
        use sha2::{Digest, Sha256};
        let sha256 = format!("{:x}", Sha256::digest(content)).parse().unwrap();

        let mut artifact = sample_artifact(status);
        artifact.repository_id = repo_id;
        artifact.name = pkg_name.to_string();
        artifact.version = Some(version.to_string());
        artifact.path = format!("{pkg_name}/-/{filename}");
        artifact.sha256_checksum = sha256;
        artifact.sha1_checksum = sha1_hex.map(str::to_string);
        artifact.size_bytes = content.len() as i64;
        h.artifacts.insert(artifact.clone());
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), content.to_vec());
        artifact
    }

    /// Build a minimal npm publish JSON body containing a single
    /// `_attachments` entry with a base64-encoded tarball.
    ///
    /// Matches real `npm publish` wire format: the `_attachments` key is
    /// `{pkg_name}-{version}.tgz` — scope-included for scoped packages
    /// (`@types/node-20.0.0.tgz`), not the unscoped basename form. An
    /// earlier version of this helper used the unscoped form for both,
    /// which let a matching bug in `do_publish` pass the scoped tests;
    /// real npm clients rejected the E2E uploads.
    fn build_publish_body(pkg_name: &str, version: &str, tarball_bytes: &[u8]) -> Vec<u8> {
        let filename = format!("{pkg_name}-{version}.tgz");
        let b64 = base64::engine::general_purpose::STANDARD.encode(tarball_bytes);

        let body = serde_json::json!({
            "name": pkg_name,
            "versions": {
                version: {
                    "name": pkg_name,
                    "version": version,
                }
            },
            "_attachments": {
                filename: {
                    "content_type": "application/octet-stream",
                    "data":         b64,
                    "length":       tarball_bytes.len(),
                }
            },
        });
        serde_json::to_vec(&body).unwrap()
    }

    // -- publish --------------------------------------------------------------

    #[tokio::test]
    async fn publish_to_virtual_repo_is_rejected() {
        // Virtual repos are read-only aggregators (ADR 0031): a publish must
        // be rejected, not silently written to the virtual's own store.
        let h = harness();
        let mut repo = sample_repository();
        repo.key = "npm-virt".into();
        repo.format = RepositoryFormat::Npm;
        repo.repo_type = hort_domain::entities::repository::RepositoryType::Virtual;
        h.repositories.insert(repo);
        let router = router(h.ctx.clone());

        let body = build_publish_body("express", "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-virt/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_unscoped_happy_path() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let body = build_publish_body("express", "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    /// npm publish hits a curation `Block` rule. This is the
    /// client-upload path (PUT /:repo_key/:name); the per-format
    /// 404-override applies only to the pull-through *fetch* path
    /// (`try_upstream_tarball_pull`'s `CurationBlocked` arm → 404,
    /// byte-identical to a miss). On the publish path the default
    /// `DomainError::CurationBlocked` → 403 mapping in
    /// `hort_http_core::error::ApiError::into_response` applies, so this
    /// must surface as 403 with the rule's reason in the body.
    #[tokio::test]
    async fn publish_unscoped_curation_block_returns_403() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;

        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        let rule = CurationRule {
            id: Uuid::new_v4(),
            name: "block-event-stream".into(),
            format: None,
            package_pattern: "event-stream".into(),
            action: CurationRuleAction::Block,
            reason: "compromised maintainer".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        h.curation_rules.set_rules_for_repo(repo.id, vec![rule]);
        let router = router(h.ctx.clone());

        let body = build_publish_body("event-stream", "3.3.6", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/event-stream")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "client-upload path keeps the default 403 mapping"
        );
        let body_bytes = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("block-event-stream"),
            "body must name the matched rule, got: {body_str}"
        );
        assert!(
            body_str.contains("compromised maintainer"),
            "body must carry the rule's reason, got: {body_str}"
        );
    }

    #[tokio::test]
    async fn publish_scoped_happy_path() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let body = build_publish_body("@types/node", "20.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/@types/node")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Scoped publish regression guard for the real-`npm publish` wire
    /// format. The previous handler stripped the unscoped basename as
    /// prefix, which rejected every real scoped upload with
    /// "cannot parse version". Covers both:
    ///
    /// 1. The `_attachments` key carries the SCOPE (`@scope/pkg-{ver}.tgz`
    ///    — what real `npm publish` sends).
    /// 2. The stored path uses the UNSCOPED filename (`@scope/pkg/-/pkg-{ver}.tgz`
    ///    — matching public-registry download URL convention), so a
    ///    follow-up download resolves correctly.
    #[tokio::test]
    async fn publish_scoped_uses_real_npm_wire_filename() {
        use serde_json::json;

        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // Hand-build the body so the assertion cannot depend on
        // `build_publish_body` masking the real wire format.
        let tarball = b"scoped-regression-bytes";
        let attachment_filename = "@test/native-package-1.0.0.tgz"; // scope-included
        let b64 = base64::engine::general_purpose::STANDARD.encode(tarball);
        let body = serde_json::to_vec(&json!({
            "name": "@test/native-package",
            "versions": {
                "1.0.0": { "name": "@test/native-package", "version": "1.0.0" }
            },
            "_attachments": {
                attachment_filename: {
                    "content_type": "application/octet-stream",
                    "data":         b64,
                    "length":       tarball.len(),
                }
            },
        }))
        .unwrap();

        let pub_res = router
            .clone()
            .oneshot(
                Request::put("/npm/npm-test/@test/native-package")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            pub_res.status(),
            StatusCode::OK,
            "scope-included `_attachments` key must parse — real npm wire format"
        );

        // Canonical stored path uses the UNSCOPED filename, so download
        // URLs match public-registry convention. The @-encoded URL segment
        // round-trips through axum's Path extractor.
        let dl_res = router
            .oneshot(
                Request::get("/npm/npm-test/@test/native-package/-/native-package-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            dl_res.status(),
            StatusCode::OK,
            "stored path must match the public-registry download convention — \
             `@scope/pkg/-/pkg-{{ver}}.tgz`, not `@scope/pkg/-/@scope/pkg-{{ver}}.tgz`"
        );
        let body = to_bytes(dl_res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body[..], tarball);
    }

    #[tokio::test]
    async fn publish_roundtrip_unscoped() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let tarball = b"roundtrip tarball content";
        let body = build_publish_body("express", "1.2.3", tarball);

        let pub_res = router
            .clone()
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pub_res.status(), StatusCode::OK);

        let dl_res = router
            .oneshot(
                Request::get("/npm/npm-test/express/-/express-1.2.3.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl_res.status(), StatusCode::OK);
        let body = to_bytes(dl_res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body[..], tarball);
    }

    #[tokio::test]
    async fn publish_roundtrip_scoped() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let tarball = b"scoped roundtrip";
        let body = build_publish_body("@types/node", "20.17.33", tarball);

        let pub_res = router
            .clone()
            .oneshot(
                Request::put("/npm/npm-test/@types/node")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pub_res.status(), StatusCode::OK);

        let dl_res = router
            .oneshot(
                Request::get("/npm/npm-test/@types/node/-/node-20.17.33.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl_res.status(), StatusCode::OK);
        let body = to_bytes(dl_res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body[..], tarball);
    }

    #[tokio::test]
    async fn publish_persists_sha1_for_packument_shasum() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let tarball = b"compute-sha1-on-me";
        let expected_sha1 = format!("{:x}", Sha1::digest(tarball));
        let body = build_publish_body("express", "1.0.0", tarball);

        let res = router
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Verify the persisted artifact carries the computed SHA-1 hex.
        let artifacts = h
            .artifacts
            .find_by_path(
                h.repositories.find_by_key("npm-test").await.unwrap().id,
                "express/-/express-1.0.0.tgz",
            )
            .await
            .unwrap();
        let artifact = artifacts.expect("artifact should be persisted");
        assert_eq!(
            artifact.sha1_checksum.as_deref(),
            Some(expected_sha1.as_str())
        );
    }

    /// Streaming-decode regression guard. A 50 MiB-equivalent publish
    /// must:
    ///
    /// 1. Succeed (200 OK).
    /// 2. Persist an `Artifact` whose `sha1_checksum` matches the SHA-1
    ///    of the original tarball — proves the streaming SHA-1 hasher
    ///    accumulated every byte exactly once across the per-frame
    ///    chunked body. A bug in the carry buffer or in the
    ///    chunk-boundary handler would corrupt this.
    /// 3. Persist the same byte content into the storage adapter under
    ///    the SHA-256 the streaming `tempfile` reader produced —
    ///    proves `ingest_direct` consumed the full `AsyncRead` (not a
    ///    truncated stream).
    ///
    /// The body is built once in memory in this unit test (we do not
    /// have a way to assert "peak heap ≤ N" portably in `#[tokio::test]`)
    /// — the streaming guarantee is a code-review property of
    /// `streaming_publish::stream_decode_body`. The matching unit
    /// test for the parser's bounded-memory shape lives in
    /// `streaming_publish::tests::memory_shape_carry_stays_bounded_across_chunks`.
    #[tokio::test]
    async fn publish_50mib_tarball_streams_and_persists_correct_sha1() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // 50 MiB tarball — enough to (a) cross many base64-group
        // boundaries, (b) demonstrate the streaming path scales past
        // the prior in-memory `Vec<u8>` and (c) keep the test under
        // the default `cargo test` time budget.
        let tarball: Vec<u8> = (0..50 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let expected_sha1 = format!("{:x}", Sha1::digest(&tarball));
        let expected_sha256 = {
            use sha2::Digest as _;
            format!("{:x}", Sha2Sha256::digest(&tarball))
        };
        let body = build_publish_body("bigpkg", "9.9.9", &tarball);
        // Total envelope ≈ 50 MiB * 4/3 + small overhead.
        // `npm_routes` uses DEFAULT_PUBLISH_BODY_LIMIT (300 MiB), so
        // this fits comfortably.

        let res = router
            .oneshot(
                Request::put("/npm/npm-test/bigpkg")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "50 MiB streaming publish must succeed"
        );

        // Persisted SHA-1 matches the streamed bytes.
        let repo_id = h.repositories.find_by_key("npm-test").await.unwrap().id;
        let artifact = h
            .artifacts
            .find_by_path(repo_id, "bigpkg/-/bigpkg-9.9.9.tgz")
            .await
            .unwrap()
            .expect("artifact should be persisted");
        assert_eq!(
            artifact.sha1_checksum.as_deref(),
            Some(expected_sha1.as_str()),
            "streaming SHA-1 must match the original tarball SHA-1"
        );
        assert_eq!(
            artifact.size_bytes as usize,
            tarball.len(),
            "persisted size must match the original tarball size"
        );
        assert_eq!(
            artifact.sha256_checksum.to_string(),
            expected_sha256,
            "CAS SHA-256 (computed by storage.put) must match the original tarball SHA-256"
        );
    }

    /// Use `sha2::Sha256` under a different alias than the local
    /// imports (which already pull in `sha2::Sha256` in some test
    /// scopes via `use sha2::{Digest, Sha256};`); the alias avoids a
    /// shadowing footgun if a future refactor moves the use-statements
    /// around.
    use sha2::Sha256 as Sha2Sha256;

    #[tokio::test]
    async fn publish_invalid_json_returns_400() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from("{not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_missing_attachments_returns_400() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let body = serde_json::json!({"name": "express"}).to_string();
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_bad_base64_returns_400() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let body = serde_json::json!({
            "name": "express",
            "_attachments": {
                "express-1.0.0.tgz": { "data": "!!!not-base64!!!" }
            }
        })
        .to_string();
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_exceeding_body_limit_is_rejected() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router_with_publish_limit(h.ctx.clone(), 1024);

        // ~4 KiB tarball balloons to ~5.5 KiB after base64 — well over 1 KiB.
        let tarball = vec![0u8; 4096];
        let body = build_publish_body("express", "1.0.0", &tarball);

        let res = router
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // -- route-parameter length cap ----------------------------------------

    /// A 1 KiB scope on a scoped publish → 400. The scope `@`-prefix
    /// check should NOT run before the length cap — a client that
    /// attacks with a huge scope must be rejected for the length, not
    /// bottlenecked in the `@` validator first.
    #[tokio::test]
    async fn publish_scoped_rejects_oversized_scope() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // 1 KiB scope, URL-encoded `@` prefix so the segment parses.
        // The validator operates on the decoded value; axum's Path
        // extractor performs the decode.
        let huge_scope = format!("@{}", "s".repeat(1024));
        let body = build_publish_body("@huge/pkg", "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put(format!("/npm/npm-test/{huge_scope}/pkg"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let body_bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        assert_eq!(json["parameter"], "scope");
    }

    /// Unscoped publish with a 1 KiB package name → 400 + parameter
    /// label `name`.
    #[tokio::test]
    async fn publish_unscoped_rejects_oversized_name() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let huge = "p".repeat(1024);
        let body = build_publish_body(&huge, "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put(format!("/npm/npm-test/{huge}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["parameter"], "name");
    }

    /// The npm upload site must route the per-version packument block
    /// into `IngestRequest.payload_metadata` so the HashReference
    /// strategy has something to summarise. Leaving this at `Value::Null`
    /// would skip the strategy dispatch entirely — `had_payload_metadata`
    /// gate — and nothing would ever spill to CAS.
    ///
    /// Two flavours in one test: a small payload that stays inline
    /// (full block persisted verbatim, no blob) and a large payload
    /// that crosses the 256 KB split threshold (summary inline, blob
    /// populated). Together they prove (a) the upload site is
    /// actually forwarding the `versions[v]` block — not
    /// `Value::Null` — and (b) the ingest-path strategy dispatch
    /// sees it and reacts correctly.
    #[tokio::test]
    async fn publish_routes_per_version_block_into_payload_metadata() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // ---- Small payload: inline path ------------------------------
        //
        // Under 256 KB the dispatch keeps the full block inline and
        // does NOT invoke `extract_metadata_summary` — the threshold
        // comparison short-circuits before the summary step. So the
        // committed `ArtifactMetadata.metadata` carries the full
        // block verbatim, readme and all.
        let small_tarball = b"small tarball";
        let small_b64 = base64::engine::general_purpose::STANDARD.encode(small_tarball);
        let small_body = serde_json::json!({
            "name": "express",
            "versions": {
                "1.2.3": {
                    "name":         "express",
                    "version":      "1.2.3",
                    "dist":         { "tarball": "u", "shasum": "s" },
                    "dependencies": { "body-parser": "^1.20" },
                    "engines":      { "node": ">=14" },
                    "readme":       "prose",
                }
            },
            "_attachments": {
                "express-1.2.3.tgz": {
                    "content_type": "application/octet-stream",
                    "data":         small_b64,
                    "length":       small_tarball.len(),
                }
            },
        });
        let res = router
            .clone()
            .oneshot(
                Request::put("/npm/npm-test/express")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&small_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let transitions = h.lifecycle.committed_transitions();
        assert_eq!(
            transitions.len(),
            1,
            "exactly one commit_transition after first publish"
        );
        let inline_md = transitions[0]
            .2
            .as_ref()
            .expect("npm ingest must commit an ArtifactMetadata row");
        let inline_obj = inline_md
            .metadata
            .as_object()
            .expect("inline metadata must be an object");
        // Proof the upload site forwarded the block: the full
        // per-version content is persisted inline, including the
        // non-summary `readme` field that `extract_metadata_summary`
        // would have filtered out.
        assert_eq!(inline_obj["name"], "express");
        assert_eq!(inline_obj["version"], "1.2.3");
        assert_eq!(inline_obj["readme"], "prose");
        assert!(inline_md.metadata_blob.is_none());

        // ---- Large payload: split path -------------------------------
        //
        // Push a per-version block past the 256 KB threshold by
        // stuffing a long `dependencies` map. The dispatch hashes the
        // full block to CAS and the committed row carries only the
        // 7-key summary — proof that both the upload site AND the
        // summary filter work end-to-end.
        let mut big_deps = serde_json::Map::new();
        for i in 0..20_000 {
            // ~30 bytes per entry * 20k ≈ 600 KB, comfortably over 256 KB.
            big_deps.insert(format!("dep-{i:05}"), serde_json::json!("^1.0.0"));
        }
        let big_tarball = b"big tarball";
        let big_b64 = base64::engine::general_purpose::STANDARD.encode(big_tarball);
        let big_body = serde_json::json!({
            "name": "bigpkg",
            "versions": {
                "9.9.9": {
                    "name":         "bigpkg",
                    "version":      "9.9.9",
                    "dist":         { "tarball": "u", "shasum": "s" },
                    "dependencies": big_deps,
                    "engines":      { "node": ">=14" },
                    "readme":       "must be stripped in the summary",
                }
            },
            "_attachments": {
                "bigpkg-9.9.9.tgz": {
                    "content_type": "application/octet-stream",
                    "data":         big_b64,
                    "length":       big_tarball.len(),
                }
            },
        });
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/bigpkg")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&big_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let transitions = h.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 2, "two commit_transitions total");
        let split_md = transitions[1]
            .2
            .as_ref()
            .expect("split ingest must commit an ArtifactMetadata row");
        let split_obj = split_md
            .metadata
            .as_object()
            .expect("summary metadata must be an object");
        assert_eq!(split_obj["name"], "bigpkg");
        assert_eq!(split_obj["version"], "9.9.9");
        assert!(split_obj.contains_key("dist"));
        assert!(split_obj.contains_key("dependencies"));
        assert!(split_obj.contains_key("engines"));
        assert!(
            !split_obj.contains_key("readme"),
            "non-summary key leaked into split row: {split_obj:?}"
        );
        assert!(
            split_md.metadata_blob.is_some(),
            "over-threshold ingest must record a blob hash"
        );
    }

    #[tokio::test]
    async fn publish_scoped_with_non_at_scope_returns_400() {
        // axum matches 3-seg path but handler rejects scope missing '@'.
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let body = build_publish_body("@types/node", "1.0.0", b"x");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/notascope/node")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // ----------------------------------------------------------------------
    // Publish-handler name validator tests.
    //
    // Both `publish_unscoped` and `publish_scoped` invoke
    // `hort_formats::npm::validate_npm_name` immediately after the package
    // name is composed and BEFORE any side effect (storage write,
    // ingest, lifecycle event). The three tests below pin both negative
    // and positive paths; the negative cases additionally assert that
    // `MockStoragePort::put` is never reached — proving the rejection
    // happens before the storage boundary, not just before HTTP success.
    // ----------------------------------------------------------------------

    /// `PUT /npm/<repo>/Foo Bar` — uppercase + space in the name.
    /// Validator must reject; status 400; storage `put` never invoked.
    #[tokio::test]
    async fn publish_unscoped_rejects_invalid_name_before_storage_write() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // The space is URL-encoded in the request line so axum's Path
        // extractor sees the decoded value `Foo Bar`. A real client would
        // either encode this or be rejected at the wire — the validator
        // covers the post-decode path inside the handler.
        let body = build_publish_body("Foo Bar", "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/Foo%20Bar")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "validator must reject before any storage write"
        );
    }

    /// `PUT /npm/<repo>/@scope/../../etc` — path-traversal attempt
    /// folded through the scoped-publish route. Validator rejects the
    /// `..` package component; status 400; storage `put` never invoked.
    #[tokio::test]
    async fn publish_scoped_rejects_traversal_before_storage_write() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // axum's `Path` extractor decodes `%2F` to `/`, so we URL-encode
        // the inner separators. The decoded scope is `@scope` and the
        // decoded "name" segment is `../../etc` — composed full name is
        // `@scope/../../etc` which the validator must reject.
        let body = build_publish_body("@scope/etc", "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/@scope/..%2F..%2Fetc")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "validator must reject traversal before any storage write"
        );
    }

    /// `PUT /npm/<repo>/@scope/valid-pkg` — happy path through the
    /// scoped publish route after the validator is wired in.
    #[tokio::test]
    async fn publish_scoped_valid_name_returns_200() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let body = build_publish_body("@scope/valid-pkg", "1.0.0", b"tarball-bytes");
        let res = router
            .oneshot(
                Request::put("/npm/npm-test/@scope/valid-pkg")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    // -- packument ------------------------------------------------------------

    #[tokio::test]
    async fn packument_unscoped_returns_tarball_url_and_shasum() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "express",
            "1.0.0",
            "express-1.0.0.tgz",
            b"content",
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/express")
                    .header("host", "registry.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"].as_str().unwrap(), "express");
        let v = &json["versions"]["1.0.0"];
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://registry.example.com/npm/npm-test/express/-/express-1.0.0.tgz"
        );
        assert_eq!(
            v["dist"]["shasum"].as_str().unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(json["dist-tags"]["latest"].as_str().unwrap(), "1.0.0");
    }

    #[tokio::test]
    async fn packument_scoped_returns_full_name() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "@types/node",
            "20.0.0",
            "node-20.0.0.tgz",
            b"x",
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/@types/node")
                    .header("host", "registry.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"].as_str().unwrap(), "@types/node");
        assert_eq!(
            json["versions"]["20.0.0"]["dist"]["tarball"]
                .as_str()
                .unwrap(),
            "https://registry.example.com/npm/npm-test/@types/node/-/node-20.0.0.tgz"
        );
    }

    #[tokio::test]
    async fn packument_missing_package_returns_404() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/missing")
                    .header("host", "example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Normalisation-drift regression. Ingest an artifact whose stored
    /// `name = "legacy-name"` differs from the current
    /// `NpmFormatHandler::normalize_name(raw)`. Request the packument using
    /// the raw `name_as_published`. Fallback must recover the row; emitted
    /// tarball URL and top-level `name` must carry the STORED name;
    /// follow-up GET on the emitted URL must succeed.
    #[tokio::test]
    async fn packument_recovers_drift_era_artifact_and_follow_up_download_hits() {
        use sha2::{Digest, Sha256};

        let h = harness();
        let repo = insert_repo(&h, "npm-test");

        let content: &[u8] = b"drift tarball bytes";
        let sha256 = format!("{:x}", Sha256::digest(content)).parse().unwrap();
        let filename = "legacy-name-1.0.0.tgz";
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "legacy-name".into();
        artifact.name_as_published = "drift-pkg".into();
        artifact.version = Some("1.0.0".into());
        artifact.path = format!("legacy-name/-/{filename}");
        artifact.sha256_checksum = sha256;
        artifact.sha1_checksum = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        artifact.size_bytes = content.len() as i64;
        h.artifacts.insert(artifact.clone());
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), content.to_vec());

        let router = router(h.ctx.clone());

        // (1) Request packument by raw client name. Current normalise of
        // "drift-pkg" yields "drift-pkg", which misses the primary lookup.
        // Fallback by `name_as_published = "drift-pkg"` recovers the row.
        let res = router
            .clone()
            .oneshot(
                Request::get("/npm/npm-test/drift-pkg")
                    .header("host", "registry.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 16 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // (2) Top-level `name` reflects the STORED form.
        assert_eq!(json["name"].as_str().unwrap(), "legacy-name");
        // (3) Tarball URL is built from the stored name, not the request
        // parameter — the client following it lands at a path that
        // matches `artifact.path` exactly.
        let tarball = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(
            tarball,
            "https://registry.example.com/npm/npm-test/legacy-name/-/legacy-name-1.0.0.tgz"
        );
        assert!(
            !tarball.contains("/drift-pkg/"),
            "URL must NOT re-normalise the request parameter: {tarball}"
        );

        // (4) Follow-up GET on the emitted tarball URL hits.
        let dl = router
            .oneshot(
                Request::get(format!("/npm/npm-test/legacy-name/-/{filename}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl.status(), StatusCode::OK);
        let dl_body = to_bytes(dl.into_body(), 16 * 1024).await.unwrap();
        assert_eq!(&dl_body[..], content);
    }

    /// A request with no `Host` header no longer produces a 400.
    /// The trust layer guarantees `RequestTrust.public_url` is populated
    /// via the bind-address fallback, so the packument handler always
    /// serves a 200 with a (possibly synthetic) tarball URL. The test
    /// harness's `TrustConfig` pins the bind-address fallback to
    /// `http://0.0.0.0:8080/`.
    #[tokio::test]
    async fn packument_missing_host_falls_back_to_bind_address() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "express",
            "1.0.0",
            "express-1.0.0.tgz",
            b"x",
            None,
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/express")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["versions"]["1.0.0"]["dist"]["tarball"]
                .as_str()
                .unwrap(),
            "http://0.0.0.0:8080/npm/npm-test/express/-/express-1.0.0.tgz"
        );
    }

    // -- download -------------------------------------------------------------

    #[tokio::test]
    async fn download_unscoped_happy_path() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "express",
            "1.0.0",
            "express-1.0.0.tgz",
            b"tarball data",
            None,
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/express/-/express-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body[..], b"tarball data");
    }

    #[tokio::test]
    async fn download_scoped_happy_path() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "@types/node",
            "20.0.0",
            "node-20.0.0.tgz",
            b"scoped data",
            None,
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/@types/node/-/node-20.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body[..], b"scoped data");
    }

    #[tokio::test]
    async fn download_not_found_returns_404() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/missing/-/missing-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn download_quarantined_returns_503() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "express",
            "1.0.0",
            "express-1.0.0.tgz",
            b"x",
            None,
            QuarantineStatus::Quarantined,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/express/-/express-1.0.0.tgz")
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
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "express",
            "1.0.0",
            "express-1.0.0.tgz",
            b"x",
            None,
            QuarantineStatus::Rejected,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/express/-/express-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn download_scoped_quarantined_returns_503() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "@types/node",
            "20.0.0",
            "node-20.0.0.tgz",
            b"x",
            None,
            QuarantineStatus::Quarantined,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/@types/node/-/node-20.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn download_scoped_rejected_returns_403() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        insert_tarball_artifact(
            &h,
            repo.id,
            "@types/node",
            "20.0.0",
            "node-20.0.0.tgz",
            b"x",
            None,
            QuarantineStatus::Rejected,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/npm/npm-test/@types/node/-/node-20.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    // -- route precedence regression ------------------------------------------

    /// Critical scoped-vs-unscoped test: publish a scoped package `@foo/bar`
    /// AND an unscoped package named `foo` to the same repository; confirm
    /// both downloads resolve correctly without cross-talk. The 2-seg vs
    /// 3-seg path shape should disambiguate cleanly in axum's matchit.
    #[tokio::test]
    async fn route_precedence_scoped_and_unscoped_same_repo() {
        let h = harness();
        insert_repo(&h, "npm-test");
        let router = router(h.ctx.clone());

        // Publish unscoped `foo@1.0.0`.
        let unscoped_body = build_publish_body("foo", "1.0.0", b"unscoped-foo-bytes");
        let res1 = router
            .clone()
            .oneshot(
                Request::put("/npm/npm-test/foo")
                    .header("content-type", "application/json")
                    .body(Body::from(unscoped_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res1.status(), StatusCode::OK);

        // Publish scoped `@foo/bar@1.0.0`.
        let scoped_body = build_publish_body("@foo/bar", "1.0.0", b"scoped-bar-bytes");
        let res2 = router
            .clone()
            .oneshot(
                Request::put("/npm/npm-test/@foo/bar")
                    .header("content-type", "application/json")
                    .body(Body::from(scoped_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res2.status(), StatusCode::OK);

        // Download unscoped — must return unscoped bytes.
        let dl1 = router
            .clone()
            .oneshot(
                Request::get("/npm/npm-test/foo/-/foo-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl1.status(), StatusCode::OK);
        let body1 = to_bytes(dl1.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body1[..], b"unscoped-foo-bytes");

        // Download scoped — must return scoped bytes.
        let dl2 = router
            .oneshot(
                Request::get("/npm/npm-test/@foo/bar/-/bar-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl2.status(), StatusCode::OK);
        let body2 = to_bytes(dl2.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body2[..], b"scoped-bar-bytes");
    }

    // -- helpers --------------------------------------------------------------

    #[test]
    fn unscoped_basename_pinning() {
        assert_eq!(unscoped_basename("express"), "express");
        assert_eq!(unscoped_basename("@types/node"), "node");
        assert_eq!(unscoped_basename("@scope/sub/leaf"), "leaf");
    }

    #[test]
    fn extract_version_strips_basename_and_extension() {
        assert_eq!(
            extract_version("express-1.0.0.tgz", "express"),
            Some("1.0.0".into())
        );
        assert_eq!(
            extract_version("node-20.0.0-beta.1.tgz", "node"),
            Some("20.0.0-beta.1".into())
        );
        assert_eq!(extract_version("express.tgz", "express"), None);
        assert_eq!(extract_version("express-1.0.0.zip", "express"), None);
        assert_eq!(extract_version("express-.tgz", "express"), None);
    }

    // -- Read-side anti-enumeration -----------------------------------------
    //
    // Mirrors the cargo regression tests (see
    // `crates/hort-http-cargo/src/lib.rs::tests::anti_enumeration`).
    // Proves that anonymous read paths on a private repo collapse to
    // `404` indistinguishably from a missing-repo response.
    //
    // Two scenarios per route family:
    // 1. Missing repo + anonymous → 404 (baseline, already worked).
    // 2. Private repo + anonymous → 404 (the regression — before the
    //    visibility check was added, npm's `find_by_key` admitted
    //    every read, returning 200 + packument body / tarball bytes).
    //
    // npm has two read endpoints that count as enumeration surface:
    // - packument (`GET /:repo/:name`, `GET /:repo/:scope/:name`) — leaks
    //   the full version list + sha1 cksum for a guessed name.
    // - tarball download (`GET /:repo/:name/-/:filename`,
    //   `GET /:repo/:scope/:name/-/:filename`) — leaks the artifact bytes
    //   themselves.
    //
    // Both are exercised. The scoped variants ride the same code path
    // (just route to the same `serve_*` helper after scope assembly) so
    // a per-variant regression isn't needed — the shared helper carries
    // the visibility check.

    mod anti_enumeration {
        use std::sync::Arc;

        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_domain::entities::artifact::QuarantineStatus;
        use hort_http_core::test_support::with_repository_access;

        use super::*;

        /// Flip the harness's `RepositoryAccessUseCase` from the
        /// default `Disabled` (admit-everything dev mode) to `Enabled`
        /// with an empty RBAC evaluator. Anonymous + private repo now
        /// collapses to `NotFound` — the realistic deployment scenario
        /// the regression test exists to lock in.
        fn enabled_rbac_harness() -> TestHarness {
            let h = harness();
            // Construct the new access use case from the harness's MockPorts
            // handle (`h.repositories`), which is the same `Arc` wired into
            // the ctx.
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
                lifecycle: h.lifecycle,
                curation_rules: h.curation_rules,
            }
        }

        fn insert_private_repo(h: &TestHarness, key: &str) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.to_string();
            repo.format = RepositoryFormat::Npm;
            repo.is_public = false;
            h.repositories.insert(repo.clone());
            repo
        }

        /// Compare two `(StatusCode, Vec<u8>)` 404 responses for
        /// anti-enumeration equivalence: status MUST match and the
        /// JSON envelope shape (`{"error":"not found: Repository
        /// <id>"}`) MUST be identical except for the id token. Both
        /// are the canonical `not found: Repository <id>` envelope,
        /// differing only in the id token — format equality is what
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

        /// Anti-enumeration regression: anonymous GET of a packument
        /// on a **private** repo MUST return the same 404 envelope as
        /// the missing-repo case. Before the visibility check was added,
        /// the npm handler reached `ctx.repositories.find_by_key`
        /// directly, so anonymous callers could enumerate every package
        /// (and its sha1 cksum + tarball URL) in any private repo
        /// whose key they could guess.
        #[tokio::test]
        async fn anonymous_get_packument_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-npm");
            // Seed an artifact so the missing-vs-private collapse can't
            // be explained by "no rows match the lookup" — the row
            // exists, only the visibility check rejects it.
            insert_tarball_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "1.0.0",
                "secret-pkg-1.0.0.tgz",
                b"secret bytes",
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/npm/private-npm/secret-pkg")
                        .header("host", "registry.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous read on private npm repo MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/npm/ghost-npm/secret-pkg")
                        .header("host", "registry.example.com")
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

        /// Same invariant, on the tarball download route. The leak
        /// shape here is the worst possible: the artifact bytes
        /// themselves. Both private-repo and missing-repo MUST return
        /// the same canonical Repository 404 envelope.
        #[tokio::test]
        async fn anonymous_get_tarball_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-npm");
            insert_tarball_artifact(
                &h,
                repo.id,
                "secret-pkg",
                "1.0.0",
                "secret-pkg-1.0.0.tgz",
                b"secret tarball bytes",
                None,
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/npm/private-npm/secret-pkg/-/secret-pkg-1.0.0.tgz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous tarball download on private npm repo MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/npm/ghost-npm/secret-pkg/-/secret-pkg-1.0.0.tgz")
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

    // -- Authz tests --------------------------------------------------------
    //
    // Both publish variants (scoped + unscoped) get allow + deny coverage —
    // four tests total. Helpers mirror the pypi / cargo submodules; the
    // pure-helper unit test for `emit_authz_metric` lives in pypi alongside
    // the helper definition.

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

        use hort_http_core::context::AuthContext;
        use hort_http_core::test_support::with_auth;

        type MetricEntry = (
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        );

        // Mirrors the pypi/cargo helpers after the ArcSwap migration. The
        // test only needs a stable snapshot reachable via `.load()`; no
        // refresh-path exercise here.
        /// Evaluator where the `developer` claim grants global `Write`
        /// (flat `GrantSubject::Claims` grant set).
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

        /// Build a principal whose resolved claim set is `claims`
        /// The `developer` claim matches the [`developer_write_evaluator`]
        /// grant.
        fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
            CallerPrincipal {
                user_id: Uuid::from_u128(0xCAFE),
                external_id: "kc:carol".into(),
                username: "carol".into(),
                email: "carol@example.com".into(),
                claims: claims.iter().map(|s| (*s).to_string()).collect(),
                token_kind: None,
                issued_at: Utc::now(),
                token_cap: None,
            }
        }

        fn enabled_ctx(base: &Arc<AppContext>) -> Arc<AppContext> {
            let idp = Arc::new(MockIdentityProvider::new());
            let users = Arc::new(MockUserRepository::new());
            let authenticate = Arc::new(AuthenticateUseCase::new(
                idp as Arc<dyn IdentityProvider>,
                users as Arc<dyn UserRepository>,
                Vec::new(),
            ));
            let rbac = developer_write_evaluator();
            with_auth(
                base,
                AuthContext::Enabled {
                    authenticate,
                    rbac,
                    // npm tests don't exercise the WWW-Authenticate
                    // selector.
                    issuer_url: None,
                },
            )
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

        async fn put_with_principal(
            ctx: Arc<AppContext>,
            path: &str,
            body_bytes: Vec<u8>,
            principal: Option<CallerPrincipal>,
        ) -> (StatusCode, Vec<u8>) {
            let router = router(ctx);
            let mut req = Request::put(path)
                .header("content-type", "application/json")
                .body(Body::from(body_bytes))
                .unwrap();
            // Wrap in `AuthenticatedPrincipal` via the test-support
            // helper.
            if let Some(p) = principal {
                hort_http_core::middleware::auth::test_support::inject_principal(&mut req, p);
            }
            let res = router.oneshot(req).await.unwrap();
            let status = res.status();
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        }

        // -- publish_unscoped -----------------------------------------------

        #[test]
        fn publish_unscoped_authorized_principal_proceeds_to_success_path() {
            let (snap, (status, _)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = harness();
                        insert_repo(&h, "npm-test");
                        let ctx = enabled_ctx(&h.ctx);
                        let body = build_publish_body("express", "1.0.0", b"tarball");
                        put_with_principal(
                            ctx,
                            "/npm/npm-test/express",
                            body,
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

        #[test]
        fn publish_unscoped_denied_principal_returns_403() {
            let (snap, (status, body)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = harness();
                        insert_repo(&h, "npm-test");
                        let ctx = enabled_ctx(&h.ctx);
                        let body = build_publish_body("express", "1.0.0", b"tarball");
                        put_with_principal(
                            ctx,
                            "/npm/npm-test/express",
                            body,
                            Some(principal_with_claims(&[])),
                        )
                        .await
                    })
            });
            assert_eq!(status, StatusCode::FORBIDDEN);
            let body_str = String::from_utf8(body).unwrap();
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

        // -- publish_scoped -------------------------------------------------

        #[test]
        fn publish_scoped_authorized_principal_proceeds_to_success_path() {
            let (snap, (status, _)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = harness();
                        insert_repo(&h, "npm-test");
                        let ctx = enabled_ctx(&h.ctx);
                        let body = build_publish_body("@types/node", "20.0.0", b"tarball");
                        put_with_principal(
                            ctx,
                            "/npm/npm-test/@types/node",
                            body,
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

        #[test]
        fn publish_scoped_denied_principal_returns_403() {
            let (snap, (status, body)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = harness();
                        insert_repo(&h, "npm-test");
                        let ctx = enabled_ctx(&h.ctx);
                        let body = build_publish_body("@types/node", "20.0.0", b"tarball");
                        put_with_principal(
                            ctx,
                            "/npm/npm-test/@types/node",
                            body,
                            Some(principal_with_claims(&[])),
                        )
                        .await
                    })
            });
            assert_eq!(status, StatusCode::FORBIDDEN);
            let body_str = String::from_utf8(body).unwrap();
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
    }

    // -- Tarball pull-through wire shape ------------------------------------
    //
    // Wires the `try_upstream_tarball_pull` orchestrator into the
    // `serve_tarball` handler's Proxy-cache-miss branch and pins the wire
    // shape for each `UpstreamPullError` variant. Mirrors the PyPI prior
    // art at `crates/hort-http-pypi/src/lib.rs::tests::proxy_pull_through`.
    //
    // The tests drive the full upstream-pull orchestration through
    // `MockPorts` rather than mocking the orchestrator directly —
    // `try_upstream_tarball_pull` is not easily mockable, and the
    // assertions here are wire-shape (status + body + `X-Hort-Reason`),
    // so the integration shape is the right boundary to cover.
    // Hosted/Staging/Virtual repos must NOT enter the Proxy branch — the
    // `serve_tarball_local_repo_cache_miss_returns_404` test pins this.
    mod proxy_pull_through {
        use std::sync::Arc;

        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use base64::Engine as _;
        use chrono::Utc;
        use metrics_exporter_prometheus::PrometheusBuilder;
        use sha2::{Digest, Sha512};
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

        fn proxy_npm_repo(key: &str) -> Repository {
            let mut r = sample_repository();
            r.key = key.into();
            r.format = RepositoryFormat::Npm;
            r.repo_type = RepositoryType::Proxy;
            r.upstream_url = Some("https://registry.npmjs.org".into());
            r
        }

        fn seed_mapping(mocks: &MockPorts, repo_id: Uuid) -> Uuid {
            let id = Uuid::new_v4();
            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id,
                repository_id: repo_id,
                path_prefix: "".into(),
                upstream_url: "https://registry.npmjs.org".into(),
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

        /// Compute an SRI string of the form `sha512-<base64>` for the
        /// given bytes. Mirrors the orchestrator-test helper.
        fn sri_sha512(content: &[u8]) -> String {
            let digest = Sha512::digest(content);
            let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
            format!("sha512-{b64}")
        }

        /// Minimal npm packument keyed on `(version, integrity, tarball)`.
        fn packument_json(version: &str, integrity: &str, tarball: &str) -> Vec<u8> {
            format!(
                r#"{{"versions":{{"{version}":{{"name":"x","version":"{version}","dist":{{"integrity":"{integrity}","tarball":"{tarball}"}}}}}}}}"#,
            )
            .into_bytes()
        }

        /// Packument with only `dist.shasum` (no `dist.integrity`) — drives
        /// the `MetadataMalformed` legacy path.
        fn packument_legacy_shasum_only(version: &str, tarball: &str, shasum: &str) -> Vec<u8> {
            format!(
                r#"{{"versions":{{"{version}":{{"name":"x","version":"{version}","dist":{{"shasum":"{shasum}","tarball":"{tarball}"}}}}}}}}"#,
            )
            .into_bytes()
        }

        fn router_for(ctx: Arc<AppContext>) -> Router {
            Router::new().nest("/npm", npm_routes()).with_state(ctx)
        }

        /// Cache hit on a Proxy repo → 200 served directly from the
        /// local CAS, NO orchestrator call. Confirms the
        /// `find_visible_by_path` success arm short-circuits before the
        /// Proxy branch, so a request that already has the artifact in
        /// CAS does not perform a redundant upstream pull. The orchestrator
        /// would fail loudly here because `upstream_resolver` has no
        /// mapping — if the Proxy branch fired, the test would see 404
        /// (`NoUpstream`), not 200.
        #[tokio::test]
        async fn serve_tarball_local_hit_ignores_upstream() {
            use hort_app::use_cases::test_support::sample_artifact;
            use hort_domain::entities::artifact::QuarantineStatus;

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            // Deliberately NO `seed_mapping` — if the Proxy branch fires,
            // the orchestrator returns `NoUpstream` and the wire becomes
            // 404 (not 200).

            let mut artifact = sample_artifact(QuarantineStatus::None);
            artifact.repository_id = repo.id;
            artifact.name = "express".to_string();
            artifact.path = "express/-/express-4.18.2.tgz".to_string();
            mocks.artifacts.insert(artifact.clone());
            mocks.storage.insert_content(
                artifact.sha256_checksum.clone(),
                b"local cached body".to_vec(),
            );

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/express/-/express-4.18.2.tgz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
            assert_eq!(&body[..], b"local cached body");
        }

        /// Cache miss + Proxy + happy upstream → 200 with verified bytes.
        ///
        /// `IngestUseCase::ingest_verified` is invoked with no
        /// `quarantine_until` (the `VerifiedIngestRequest::UpstreamPublished`
        /// shape has no quarantine field), so the freshly-minted artifact
        /// reaches the streaming path with `QuarantineStatus::None` and
        /// the response is 200 + body.
        #[tokio::test]
        async fn serve_tarball_proxy_cache_miss_pulls_through_and_serves() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body_bytes = b"the actual express 4.18.2 tarball".to_vec();
            let sri = sri_sha512(&body_bytes);
            let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
            let json = packument_json("4.18.2", &sri, url);
            mocks.upstream_proxy.insert_metadata("", "/express", json);
            mocks
                .upstream_proxy
                .insert_artifact("", url, body_bytes.clone());

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/express/-/express-4.18.2.tgz")
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
        /// the advertised sha512 → 502 + `X-Hort-Reason: upstream-checksum-mismatch`.
        /// Pins the security primitive against upstream tampering: the
        /// rehash inside `ingest_verified` rejects, the orchestrator
        /// surfaces `ChecksumMismatch`, and the wire-map renders 502.
        #[tokio::test]
        async fn serve_tarball_proxy_cache_miss_tampered_returns_502_checksum_mismatch() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual = b"actual-bytes".to_vec();
            // Packument lies — advertises the SHA-512 of `lying-bytes`
            // but the upstream serves `actual-bytes`. The rehash inside
            // `ingest_verified` detects.
            let lying_sri = sri_sha512(b"lying-bytes");
            let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
            let json = packument_json("4.18.2", &lying_sri, url);
            mocks.upstream_proxy.insert_metadata("", "/express", json);
            mocks.upstream_proxy.insert_artifact("", url, actual);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/express/-/express-4.18.2.tgz")
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

        /// Cache miss + Proxy + packument has only `dist.shasum` (legacy
        /// SHA-1 path) → `parse_upstream_checksum` returns Validation,
        /// the orchestrator surfaces `MetadataMalformed`, and the wire-map
        /// renders 502 + `X-Hort-Reason: upstream-metadata-malformed`.
        /// SHA-1 fallback is NOT accepted (collision-broken since 2017).
        #[tokio::test]
        async fn serve_tarball_proxy_cache_miss_legacy_no_integrity_returns_502_metadata_malformed()
        {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let url = "https://registry.npmjs.org/legacy/-/legacy-1.0.0.tgz";
            let json = packument_legacy_shasum_only(
                "1.0.0",
                url,
                "0123456789abcdef0123456789abcdef01234567",
            );
            mocks.upstream_proxy.insert_metadata("", "/legacy", json);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/legacy/-/legacy-1.0.0.tgz")
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

        /// Cache miss + Proxy + packument's `dist.tarball` filename
        /// differs from the request → 502 +
        /// `X-Hort-Reason: upstream-filename-mismatch`. The defence-in-depth
        /// basename check fires before any tarball fetch — an upstream
        /// substituting a different tarball under valid metadata is
        /// rejected.
        #[tokio::test]
        async fn serve_tarball_proxy_cache_miss_filename_mismatch_returns_502() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            // `dist.tarball` ends in `attacker-9.9.9.tgz`; the request
            // filename is `express-4.18.2.tgz`. The basename check rejects.
            let bad_url = "https://registry.npmjs.org/express/-/attacker-9.9.9.tgz";
            let sri = sri_sha512(b"unused");
            let json = packument_json("4.18.2", &sri, bad_url);
            mocks.upstream_proxy.insert_metadata("", "/express", json);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/express/-/express-4.18.2.tgz")
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
                Some("upstream-filename-mismatch"),
            );
            let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "upstream tarball filename mismatch");
        }

        /// Cache miss on a Hosted (default) repo MUST NOT enter the Proxy
        /// pull-through branch — pre-Item-5 behaviour is preserved as a
        /// clean 404. Regression test: a routing regression that fired
        /// pull-through unconditionally would either return 200 (if
        /// upstream were seeded — it isn't) or surface a 502 / 404 from
        /// the orchestrator's `NoUpstream` path. Both fail the 404
        /// assertion. The existing `download_not_found_returns_404`
        /// test covers Hosted + missing artifact too; this one is the
        /// near-twin that makes the no-pull-through behaviour explicit
        /// using the same `MockPorts` harness as the Proxy tests so a
        /// regression in the type-check branch surfaces here.
        #[tokio::test]
        async fn serve_tarball_local_repo_cache_miss_returns_404() {
            let (ctx, mocks) = build_mock_ctx(handle());
            // sample_repository → RepositoryType::Hosted by default; pin
            // it explicitly so a future test_support change cannot
            // silently flip this fixture.
            let mut repo = sample_repository();
            repo.key = "npm-hosted".into();
            repo.format = RepositoryFormat::Npm;
            repo.repo_type = RepositoryType::Hosted;
            mocks.repositories.insert(repo);
            // Deliberately NO `seed_mapping` and NO upstream fixtures —
            // if the Proxy branch fired, the orchestrator would surface
            // `NoUpstream` and the wire would be 404 with the simpler
            // envelope, not the use-case envelope. Either way the assertion
            // here is just "404"; the envelope shape is verified by the
            // existing `download_not_found_returns_404` test.

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-hosted/express/-/express-1.0.0.tgz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        /// Scoped package happy path: `@types/node` resolves to the
        /// `/@types%2fnode` upstream metadata path, the basename check
        /// strips the `@types/` prefix to compute the version, and the
        /// fetched tarball serves through the local CAS.
        #[tokio::test]
        async fn serve_tarball_scoped_package_proxy_cache_miss_pulls_through() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body_bytes = b"scoped tarball body".to_vec();
            let sri = sri_sha512(&body_bytes);
            let url = "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz";
            let json = packument_json("20.0.0", &sri, url);
            // Lowercase `%2f` per the npm registry convention.
            mocks
                .upstream_proxy
                .insert_metadata("", "/@types%2fnode", json);
            mocks
                .upstream_proxy
                .insert_artifact("", url, body_bytes.clone());

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/@types/node/-/node-20.0.0.tgz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&bytes[..], body_bytes.as_slice());
        }

        // -- Framework-invariant assertions --------------------------------
        //
        // The wire-shape tests above pin status code, body, and
        // `X-Hort-Reason` headers. The three tests below extend that
        // coverage to the upstream verification audit invariants (ADR 0006),
        // mirroring the PyPI precedent at
        // `crates/hort-http-pypi/src/lib.rs::tests::proxy_pull_through`
        // and the Cargo precedent at
        // `crates/hort-http-cargo/src/lib.rs::tests::proxy_pull_through`:
        //
        // 1. Happy path emits `ArtifactIngested + ChecksumVerified` in
        //    the SAME `commit_transition` batch on the artifact stream
        //    (the "atomic with the mint" rule); the tarball lands in
        //    the CAS at its computed (SHA-256) content hash. npm's
        //    upstream verification is SHA-512 (unique among v2 formats),
        //    but the CAS content hash is SHA-256 of the raw bytes —
        //    these are independent layers.
        // 2. Tampered tarball emits exactly one `ChecksumMismatch` on
        //    the REPOSITORY stream (never the artifact stream — under
        //    mint-after-verify no artifact row exists for the
        //    mismatch); no `ArtifactIngested` and no `ChecksumVerified`
        //    fire anywhere; CAS net state is empty (rollback fired).
        //    The wire-level X-Hort-Reason is covered by the wire-shape
        //    tests above; this asserts the audit-log invariants instead.
        // 3. Legacy packument (only `dist.shasum`, no `dist.integrity`)
        //    surfaces as a parser failure that runs BEFORE
        //    `ingest_verified` is invoked — therefore no event of any
        //    kind appears on either stream and `storage.put` is never
        //    called. SHA-1 fallback is rejected at the parser layer
        //    (ADR 0006); the failure short-circuits ahead of the tarball
        //    fetch + storage.put sequence.
        //
        // Assertions ride on the existing mock ports. The framework
        // boundary worth verifying here is the use-case + orchestrator
        // layer; the HTTP-adapter's network plumbing is covered by
        // `hort-adapters-upstream-http`'s own wiremock tests.

        /// Happy path: cache miss + Proxy + upstream serves the
        /// advertised tarball body.
        ///
        /// Happy path: cache miss + Proxy + upstream serves the
        /// advertised tarball body.
        ///
        /// Asserts the framework invariants:
        /// - `ArtifactIngested` and `ChecksumVerified` ride in the
        ///   SAME `commit_transition` batch (atomic with the mint),
        ///   landing on the `StreamCategory::Artifact` stream.
        /// - The freshly-fetched body is present in the CAS at its
        ///   computed content hash (`storage.put` ran exactly once
        ///   and the bytes are recoverable). The CAS hash is SHA-256
        ///   of the raw bytes; the SHA-512 SRI in `dist.integrity`
        ///   drives upstream verification but is not the storage key.
        #[tokio::test]
        async fn framework_invariant_happy_path_emits_checksum_verified_and_writes_cas() {
            use hort_domain::events::StreamCategory;
            use hort_domain::types::ContentHash;
            use sha2::Sha256;

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body_bytes = b"the actual express 4.18.2 tarball".to_vec();
            let sri = sri_sha512(&body_bytes);
            let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
            let json = packument_json("4.18.2", &sri, url);
            mocks.upstream_proxy.insert_metadata("", "/express", json);
            mocks
                .upstream_proxy
                .insert_artifact("", url, body_bytes.clone());

            let lifecycle = mocks.lifecycle.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/express/-/express-4.18.2.tgz")
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
            // computed (SHA-256) content hash. `storage.put` ran
            // exactly once for the pull-through fetch. Note: npm's
            // upstream verification is SHA-512 (the SRI in
            // `dist.integrity`), but the CAS content hash is SHA-256
            // of the raw bytes — orthogonal layers per the architect
            // skill's CAS section.
            assert_eq!(
                storage.put_call_count(),
                1,
                "exactly one storage.put on the happy path (the pull-through fetch)"
            );
            let cas_sha256 = format!("{:x}", Sha256::digest(&body_bytes));
            let expected_hash: ContentHash = cas_sha256
                .parse()
                .expect("computed sha256 must parse as a ContentHash");
            let stored = storage.stored_hashes();
            assert!(
                stored.contains(&expected_hash),
                "freshly-fetched body must be recoverable from the CAS at its computed hash; \
                 stored hashes: {stored:?}"
            );
        }

        /// Tampered tarball: cache miss + Proxy + upstream serves bytes
        /// that disagree with the advertised `dist.integrity` SHA-512.
        ///
        /// Tampered tarball: cache miss + Proxy + upstream serves bytes
        /// that disagree with the advertised `dist.integrity` SHA-512.
        ///
        /// Asserts the framework invariants:
        /// - `ChecksumMismatch` is appended to the REPOSITORY stream
        ///   (never the artifact stream — there is no artifact yet
        ///   under mint-after-verify) with `algorithm = Sha512`.
        /// - `ArtifactIngested` is NEVER emitted.
        /// - `ChecksumVerified` is NEVER emitted (it is only minted
        ///   on the success branch).
        /// - No artifact row is minted (no `commit_transition`).
        /// - CAS net state is empty: every put is matched by a
        ///   delete (rollback fired, guarded by `find_by_checksum`
        ///   coming back empty).
        #[tokio::test]
        async fn framework_invariant_tampered_tarball_emits_mismatch_and_rolls_back_cas() {
            use hort_domain::events::{DomainEvent, StreamCategory};
            use hort_domain::types::HashAlgorithm;

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual = b"actual-bytes".to_vec();
            // Packument advertises the SHA-512 SRI of `lying-bytes`;
            // upstream serves `actual-bytes`. The rehash inside
            // `ingest_verified` (wrapped via `Sha512HashingRead`)
            // detects.
            let lying_sri = sri_sha512(b"lying-bytes");
            let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
            let json = packument_json("4.18.2", &lying_sri, url);
            mocks.upstream_proxy.insert_metadata("", "/express", json);
            mocks.upstream_proxy.insert_artifact("", url, actual);

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/express/-/express-4.18.2.tgz")
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
            // the REPOSITORY stream — never the artifact stream —
            // and carries `algorithm = Sha512` (proves
            // `Sha512HashingRead` wrapped the stream rather than the
            // pipeline silently falling back to SHA-256).
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
            let mismatch_on_repo: Vec<_> = batches
                .iter()
                .filter(|b| b.stream_id.category == StreamCategory::Repository)
                .flat_map(|b| b.events.iter())
                .filter_map(|e| match &e.event {
                    DomainEvent::ChecksumMismatch(m) => Some(m.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                mismatch_on_repo.len(),
                1,
                "ChecksumMismatch must ride on the repository stream — never the artifact stream"
            );
            assert_eq!(
                mismatch_on_repo[0].algorithm,
                HashAlgorithm::Sha512,
                "ChecksumMismatch.algorithm must be Sha512 — proves Sha512HashingRead wrapped the stream"
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

        /// Legacy packument: `versions[ver].dist` advertises only
        /// `shasum` (SHA-1), no `integrity`.
        ///
        /// Legacy packument: `versions[ver].dist` advertises only
        /// `shasum` (SHA-1), no `integrity`.
        ///
        /// Asserts the framework invariants:
        /// - `parse_upstream_checksum` fails BEFORE `ingest_verified`
        ///   is called, so no event is ever emitted on either stream.
        ///   `ChecksumMismatch` only fires when bytes flowed; metadata-
        ///   parse failures fire nothing.
        /// - `storage.put` is never called (the parser short-circuits
        ///   ahead of the tarball-fetch + storage.put sequence —
        ///   note `insert_artifact` is deliberately NOT seeded, so a
        ///   regression that reaches the tarball leg would surface
        ///   as `UpstreamUnavailable` rather than the expected
        ///   `MetadataMalformed`).
        /// - SHA-1 fallback is rejected at the parser layer
        ///   (collision-broken since 2017).
        #[tokio::test]
        async fn framework_invariant_legacy_no_integrity_returns_502_with_no_events_or_cas_writes()
        {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let url = "https://registry.npmjs.org/legacy/-/legacy-1.0.0.tgz";
            let json = packument_legacy_shasum_only(
                "1.0.0",
                url,
                "0123456789abcdef0123456789abcdef01234567",
            );
            mocks.upstream_proxy.insert_metadata("", "/legacy", json);
            // Deliberately NO `insert_artifact` — the parser must
            // short-circuit before the tarball leg fires.

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-mirror/legacy/-/legacy-1.0.0.tgz")
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
            // parser short-circuits ahead of the tarball fetch and
            // before any put.
            assert_eq!(
                storage.put_call_count(),
                0,
                "parse-fail must short-circuit before any storage.put"
            );
        }

        /// When the served repo opts in, an anonymous npm tarball pull
        /// (no principal) emits exactly one `ArtifactDownloaded` on the
        /// per-(repo, UTC-date) DownloadAudit stream with
        /// `DownloadActor::Anonymous` (no audit gap), never on the
        /// artifact aggregate stream. Threaded adapter-free via
        /// `build_mock_ctx` (no hand-rolled AppContext); the `actor` fn
        /// param is compile-required by the `ArtifactUseCase::download`
        /// signature, so this pins the anonymous mapping + the
        /// stream-sharding invariant.
        #[tokio::test]
        async fn download_audit_emits_anonymous_when_repo_opted_in() {
            use hort_app::use_cases::test_support::sample_artifact;
            use hort_domain::entities::artifact::QuarantineStatus;
            use hort_domain::events::{DomainEvent, DownloadActor, StreamCategory};

            let (ctx, mocks) = build_mock_ctx(handle());
            // Hosted repo (sample_repository default) so the local-hit
            // path serves directly from CAS — no upstream wiring.
            let mut repo = sample_repository();
            repo.key = "npm-audit".into();
            repo.format = RepositoryFormat::Npm;
            repo.download_audit_enabled = true;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let content = b"the express 4.18.2 tarball bytes";
            let mut artifact = sample_artifact(QuarantineStatus::None);
            artifact.repository_id = repo_id;
            artifact.name = "express".to_string();
            artifact.version = Some("4.18.2".into());
            artifact.path = "express/-/express-4.18.2.tgz".to_string();
            artifact.size_bytes = content.len() as i64;
            mocks.artifacts.insert(artifact.clone());
            mocks
                .storage
                .insert_content(artifact.sha256_checksum.clone(), content.to_vec());

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/npm/npm-audit/express/-/express-4.18.2.tgz")
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
                        "anonymous npm pull → DownloadActor::Anonymous"
                    );
                }
                _ => unreachable!(),
            }
        }

        // -- Virtual (aggregating) download — ADR 0031 ----------------------
        //
        // The download handler is transparent (no `Virtual` branch past the
        // source dispatch); these drive `serve_tarball` end-to-end through
        // `serve_virtual_tarball` → `resolve_download` → member sources,
        // reusing this submodule's proxy-upstream helpers for proxy members.

        use hort_domain::entities::artifact::QuarantineStatus;

        /// Seed a Hosted npm member with one tarball artifact (+ CAS bytes).
        #[allow(clippy::too_many_arguments)]
        fn hosted_member_with_tarball(
            mocks: &MockPorts,
            key: &str,
            pkg: &str,
            version: &str,
            filename: &str,
            bytes: &[u8],
            status: QuarantineStatus,
        ) -> Repository {
            use hort_app::use_cases::test_support::sample_artifact;
            use sha2::Sha256;
            let mut repo = sample_repository();
            repo.key = key.into();
            repo.format = RepositoryFormat::Npm;
            repo.repo_type = RepositoryType::Hosted;
            mocks.repositories.insert(repo.clone());

            let sha256 = format!("{:x}", Sha256::digest(bytes)).parse().unwrap();
            let mut artifact = sample_artifact(status);
            artifact.repository_id = repo.id;
            artifact.name = pkg.into();
            artifact.version = Some(version.into());
            artifact.path = format!("{pkg}/-/{filename}");
            artifact.sha256_checksum = sha256;
            artifact.size_bytes = bytes.len() as i64;
            mocks.artifacts.insert(artifact.clone());
            mocks
                .storage
                .insert_content(artifact.sha256_checksum.clone(), bytes.to_vec());
            repo
        }

        /// Seed an empty Hosted npm member (no artifacts).
        fn empty_hosted_member(mocks: &MockPorts, key: &str) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.into();
            repo.format = RepositoryFormat::Npm;
            repo.repo_type = RepositoryType::Hosted;
            mocks.repositories.insert(repo.clone());
            repo
        }

        /// Insert a proxy npm member with an upstream mapping seeded.
        fn proxy_member(mocks: &MockPorts, key: &str) -> Repository {
            let repo = proxy_npm_repo(key);
            mocks.repositories.insert(repo.clone());
            seed_mapping(mocks, repo.id);
            repo
        }

        /// Seed a `type: virtual` npm repo aggregating `members` (priority
        /// order, first = highest).
        fn virtual_member_repo(
            mocks: &MockPorts,
            key: &str,
            members: &[&Repository],
        ) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.into();
            repo.format = RepositoryFormat::Npm;
            repo.repo_type = RepositoryType::Virtual;
            mocks.repositories.insert(repo.clone());
            for m in members {
                mocks.repositories.seed_virtual_member(repo.id, m.id);
            }
            repo
        }

        /// Seed the upstream packument + tarball for `pkg@version` on a proxy
        /// member so a virtual pull through it succeeds (verified).
        fn seed_upstream_tarball(mocks: &MockPorts, pkg: &str, version: &str, bytes: &[u8]) {
            let url = format!("https://registry.npmjs.org/{pkg}/-/{pkg}-{version}.tgz");
            let sri = sri_sha512(bytes);
            let json = packument_json(version, &sri, &url);
            mocks
                .upstream_proxy
                .insert_metadata("", &format!("/{pkg}"), json);
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
            let a = hosted_member_with_tarball(
                &mocks,
                "npm-a",
                "lib",
                "1.0.0",
                "lib-1.0.0.tgz",
                b"from-a",
                QuarantineStatus::Released,
            );
            let b = empty_hosted_member(&mocks, "npm-b");
            virtual_member_repo(&mocks, "npm-virt", &[&a, &b]);

            let res = get_download(ctx, "/npm/npm-virt/lib/-/lib-1.0.0.tgz").await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&body[..], b"from-a");
        }

        #[tokio::test]
        async fn virtual_download_first_authoritative_prefers_higher_priority() {
            // Same coordinate in both members; the higher-priority member is
            // authoritative — its bytes are served, never the secondary's.
            let (ctx, mocks) = build_mock_ctx(handle());
            let hi = hosted_member_with_tarball(
                &mocks,
                "npm-hi",
                "lib",
                "1.0.0",
                "lib-1.0.0.tgz",
                b"hi-bytes",
                QuarantineStatus::Released,
            );
            let lo = hosted_member_with_tarball(
                &mocks,
                "npm-lo",
                "lib",
                "1.0.0",
                "lib-1.0.0.tgz",
                b"lo-bytes",
                QuarantineStatus::Released,
            );
            virtual_member_repo(&mocks, "npm-virt", &[&hi, &lo]);

            let res = get_download(ctx, "/npm/npm-virt/lib/-/lib-1.0.0.tgz").await;
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
            // Same-version substitution defence on the download path: the
            // higher-priority member holds 1.0.0 Quarantined; the
            // lower-priority member has 1.0.0 Released. The held copy is
            // authoritative → 503; the secondary's released copy NEVER
            // substitutes it.
            let (ctx, mocks) = build_mock_ctx(handle());
            let hi = hosted_member_with_tarball(
                &mocks,
                "npm-hi",
                "lib",
                "1.0.0",
                "lib-1.0.0.tgz",
                b"held",
                QuarantineStatus::Quarantined,
            );
            let lo = hosted_member_with_tarball(
                &mocks,
                "npm-lo",
                "lib",
                "1.0.0",
                "lib-1.0.0.tgz",
                b"released",
                QuarantineStatus::Released,
            );
            virtual_member_repo(&mocks, "npm-virt", &[&hi, &lo]);

            let res = get_download(ctx, "/npm/npm-virt/lib/-/lib-1.0.0.tgz").await;
            assert_eq!(
                res.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "held primary's gate surfaces; never the secondary's released copy"
            );
        }

        #[tokio::test]
        async fn virtual_download_scan_indeterminate_member_returns_403() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let a = hosted_member_with_tarball(
                &mocks,
                "npm-a",
                "lib",
                "1.0.0",
                "lib-1.0.0.tgz",
                b"x",
                QuarantineStatus::ScanIndeterminate,
            );
            virtual_member_repo(&mocks, "npm-virt", &[&a]);

            let res = get_download(ctx, "/npm/npm-virt/lib/-/lib-1.0.0.tgz").await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn virtual_download_missing_everywhere_returns_404() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let a = empty_hosted_member(&mocks, "npm-a");
            virtual_member_repo(&mocks, "npm-virt", &[&a]);

            let res = get_download(ctx, "/npm/npm-virt/missing/-/missing-1.0.0.tgz").await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn virtual_download_new_version_pinning_excludes_proxy() {
            // Dependency-confusion regression (new-version): the hosted member
            // OWNS `internal-pkg` (has 1.0.0). The proxy upstream WOULD serve
            // `internal-pkg@9.9.9` (the attacker's public publish). The
            // virtual MUST 404 — pinning excludes the proxy for the owned
            // name, for every version.
            let (ctx, mocks) = build_mock_ctx(handle());
            let private = hosted_member_with_tarball(
                &mocks,
                "npm-private",
                "internal-pkg",
                "1.0.0",
                "internal-pkg-1.0.0.tgz",
                b"legit",
                QuarantineStatus::Released,
            );
            let proxy = proxy_member(&mocks, "npm-proxy");
            seed_upstream_tarball(&mocks, "internal-pkg", "9.9.9", b"ATTACKER-PAYLOAD");
            virtual_member_repo(&mocks, "npm-virt", &[&private, &proxy]);

            let res =
                get_download(ctx, "/npm/npm-virt/internal-pkg/-/internal-pkg-9.9.9.tgz").await;
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "owned name: the attacker's proxy-only version is NOT served"
            );
        }

        #[tokio::test]
        async fn virtual_download_unowned_name_served_from_proxy() {
            // Positive control for the pinning test: the hosted member does
            // NOT own `leftpad`, so the proxy participates and serves it
            // (verified pull). Proves the 404 above is pinning, not a broken
            // proxy path.
            let (ctx, mocks) = build_mock_ctx(handle());
            let private = hosted_member_with_tarball(
                &mocks,
                "npm-private",
                "other",
                "1.0.0",
                "other-1.0.0.tgz",
                b"x",
                QuarantineStatus::Released,
            );
            let proxy = proxy_member(&mocks, "npm-proxy");
            seed_upstream_tarball(&mocks, "leftpad", "1.0.0", b"LEFTPAD-BYTES");
            virtual_member_repo(&mocks, "npm-virt", &[&private, &proxy]);

            let res = get_download(ctx, "/npm/npm-virt/leftpad/-/leftpad-1.0.0.tgz").await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&body[..], b"LEFTPAD-BYTES", "served from the proxy member");
        }

        #[tokio::test]
        async fn virtual_download_proxy_member_tampered_surfaces_502() {
            // An authoritative proxy member whose upstream tampers (advertised
            // SRI disagrees with served bytes) surfaces its 502 verbatim — the
            // walk does NOT fall through to a lower-priority member.
            let (ctx, mocks) = build_mock_ctx(handle());
            let private = hosted_member_with_tarball(
                &mocks,
                "npm-private",
                "other",
                "1.0.0",
                "other-1.0.0.tgz",
                b"x",
                QuarantineStatus::Released,
            );
            let proxy = proxy_member(&mocks, "npm-proxy");
            // Advertise the SRI of `lying-bytes`, serve `actual-bytes`.
            let url = "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz";
            let json = packument_json("1.0.0", &sri_sha512(b"lying-bytes"), url);
            mocks.upstream_proxy.insert_metadata("", "/evil", json);
            mocks
                .upstream_proxy
                .insert_artifact("", url, b"actual-bytes".to_vec());
            virtual_member_repo(&mocks, "npm-virt", &[&private, &proxy]);

            let res = get_download(ctx, "/npm/npm-virt/evil/-/evil-1.0.0.tgz").await;
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(
                res.headers().get("X-Hort-Reason").unwrap(),
                "upstream-checksum-mismatch"
            );
        }

        #[tokio::test]
        async fn virtual_download_proxy_only_no_mapping_returns_404() {
            // A proxy member with no upstream mapping cannot serve the
            // coordinate (`NoUpstream`) → the walk continues; with no other
            // member the virtual renders its own 404 (never a stray 502).
            let (ctx, mocks) = build_mock_ctx(handle());
            let proxy = proxy_npm_repo("npm-proxy");
            mocks.repositories.insert(proxy.clone());
            // Deliberately NO `seed_mapping`.
            virtual_member_repo(&mocks, "npm-virt", &[&proxy]);

            let res = get_download(ctx, "/npm/npm-virt/leftpad/-/leftpad-1.0.0.tgz").await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }
    }

    // -- Packument LIMIT/pagination tests -----------------------------------

    /// 5 000-version seed produces a complete packument with no
    /// `Warning` header — verifies the non-truncation path works at the
    /// "large but legitimate" scale.
    ///
    /// Skipped by default — the seed is large enough that a developer
    /// loop hates it. Run with `cargo test -p hort-http-npm -- --ignored`
    /// for full coverage. The fast `iterate_pages_capped_*` tests in
    /// `hort-app` cover the same shape at a small cap.
    #[tokio::test]
    #[ignore = "slow: seeds 5_000 versions"]
    async fn packument_handles_5000_versions_with_no_warning_header() {
        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        for i in 0..5_000_u32 {
            let version = format!("0.0.{i}");
            insert_tarball_artifact(
                &h,
                repo.id,
                "many-versions",
                &version,
                &format!("many-versions-{version}.tgz"),
                format!("content-{i}").as_bytes(),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                QuarantineStatus::None,
            );
        }
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/npm/npm-test/many-versions")
                    .header("host", "registry.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // Non-truncation path: the `Warning` header is absent.
        assert!(
            res.headers().get("Warning").is_none(),
            "5_000-version response must not carry a results-truncated Warning header"
        );
    }

    /// At `LIMIT_LIST_MAX_ITEMS + 1` versions the use-case truncates and
    /// the handler emits `Warning: 299 - "results truncated at 10000 items"`.
    #[tokio::test]
    #[ignore = "slow: seeds LIMIT_LIST_MAX_ITEMS+1 versions"]
    async fn packument_emits_warning_header_when_truncated_at_cap() {
        use hort_domain::types::LIMIT_LIST_MAX_ITEMS;

        let h = harness();
        let repo = insert_repo(&h, "npm-test");
        for i in 0..(LIMIT_LIST_MAX_ITEMS as u32 + 1) {
            let version = format!("0.0.{i}");
            insert_tarball_artifact(
                &h,
                repo.id,
                "many-versions",
                &version,
                &format!("many-versions-{version}.tgz"),
                format!("c-{i}").as_bytes(),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                QuarantineStatus::None,
            );
        }
        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/npm/npm-test/many-versions")
                    .header("host", "registry.example.com")
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
