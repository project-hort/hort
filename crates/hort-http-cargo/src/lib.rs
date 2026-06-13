//! Cargo sparse registry (RFC 2789) handlers.
//!
//! Routes (mounted under `/cargo`):
//! - `GET  /{repo_key}/config.json`                             — registry config
//! - `GET  /{repo_key}/1/{crate}`                               — 1-char index
//! - `GET  /{repo_key}/2/{crate}`                               — 2-char index
//! - `GET  /{repo_key}/3/{first_char}/{crate}`                  — 3-char index
//! - `GET  /{repo_key}/{aa}/{bb}/{crate}`                       — 4+ char index
//! - `GET  /{repo_key}/api/v1/crates/{name}/{version}/download` — crate download
//! - `PUT  /{repo_key}/api/v1/crates/new`                       — publish

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Extension, Router};
use chrono::Utc;
use serde::Deserialize;

use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{RepositoryFormat, RepositoryType};
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::ArtifactCoords;
use hort_formats::cargo::CargoFormatHandler;

use hort_http_core::authz::write::resolve_actor_user_id;
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::limits::{BoundedPath, CARGO_PUBLISH_BODY_LIMIT};
use hort_http_core::middleware::auth::AuthenticatedPrincipal;
use hort_http_core::middleware::trust::RequestTrust;

// Upstream pull-through orchestrator. Wired to the route layer in the
// download handler; declared here so the module + its tests are
// reachable under `cargo test -p hort-http-cargo`.
pub(crate) mod upstream_pull;

// Sparse-index pull-through cache for `RepositoryType::Proxy`.
// `serve_index` dispatches on `repo.repo_type` and routes Proxy reads
// through `index_cache::fetch_with_cache`.
//
// Module is `pub` so the `hort-formats-upstream` composition crate can
// call `index_cache::fetch_raw_with_cache`. Every other path through
// this module stays internal (the per-helper rustdoc declares the
// supported callers); the visibility-promotion exists only for that one
// composition seam. See `index_cache::fetch_raw_with_cache` for the
// full warning.
pub mod index_cache;

// Cargo side of the unified Source → Filter → Builder pipeline.
// `index_source` defines the per-format-internal `IndexSource` trait +
// `HostedCargoSource` / `ProxyCargoSource` impls; `serve` is the
// unified handler dispatch hop.
pub(crate) mod index_source;
pub(crate) mod serve;

/// Build the Cargo route tree with the default publish body limit.
///
/// The default ([`CARGO_PUBLISH_BODY_LIMIT`] — 200 MiB) is large enough
/// for nearly every real crate; blocks runaway uploads. Without an
/// explicit override, axum's default 2 MiB limit rejects any non-
/// trivial crate, so the limit must be set at the route layer. Not
/// driven by `HORT_PUBLISH_BODY_MAX_SIZE` — see
/// `hort_http_core::limits` for the rationale.
pub fn cargo_routes() -> Router<Arc<AppContext>> {
    cargo_routes_with_publish_limit(CARGO_PUBLISH_BODY_LIMIT)
}

/// Build the Cargo route tree with a custom publish body limit (in bytes).
///
/// Tests use this to exercise the body-limit reject path without actually
/// sending hundreds of megabytes.
pub(crate) fn cargo_routes_with_publish_limit(limit: usize) -> Router<Arc<AppContext>> {
    Router::new()
        .route("/:repo_key/config.json", get(config_json))
        .route(
            "/:repo_key/api/v1/crates/:name/:version/download",
            get(download),
        )
        .route(
            "/:repo_key/api/v1/crates/new",
            put(publish).layer(DefaultBodyLimit::max(limit)),
        )
        .route("/:repo_key/1/:crate_name", get(sparse_index))
        .route("/:repo_key/2/:crate_name", get(sparse_index))
        .route(
            "/:repo_key/3/:first_char/:crate_name",
            get(sparse_index_with_first_char),
        )
        .route("/:repo_key/:aa/:bb/:crate_name", get(sparse_index_4plus))
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/config.json
// ---------------------------------------------------------------------------

async fn config_json(
    State(ctx): State<Arc<AppContext>>,
    Extension(trust): Extension<RequestTrust>,
    BoundedPath(repo_key): BoundedPath<String>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap before this
    // handler body runs.
    //
    // Resolve the repo through the visibility-aware use case so anonymous
    // reads on private repos collapse to the same `NotFound` envelope as
    // missing-repo (anti-enumeration). Cargo clients hit this first when
    // bootstrapping a registry; the leak shape would otherwise be "registry
    // exists, here's its dl/api URL" — enough to confirm a guessed private
    // repo key.
    // Unwrap the `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    let _repo = ctx
        .repository_access_use_case
        .resolve(&repo_key, actor, AccessLevel::Read)
        .await?;

    // Public URL comes from `RequestTrust` (see `hort_http_core::middleware::trust`).
    // The trust middleware resolves `HORT_PUBLIC_BASE_URL` ↦ trusted-proxy
    // `X-Forwarded-*` ↦ `Host` ↦ bind-address in that precedence order,
    // so every branch is handled there — the resolver here is a pure
    // pass-through. See `crate::middleware::trust`.
    let base_url = ctx.url_resolver.resolve(&trust);
    let base = base_url.as_str().trim_end_matches('/');

    let body = serde_json::json!({
        "dl":  format!("{base}/cargo/{repo_key}/api/v1/crates"),
        "api": format!("{base}/cargo/{repo_key}"),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/{...}/{crate} — sparse index variants
// ---------------------------------------------------------------------------

async fn sparse_index(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, crate_name)): BoundedPath<(String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs. Unwrap the
    // `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    serve_index(&ctx, &repo_key, &crate_name, actor).await
}

async fn sparse_index_with_first_char(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, first_char, crate_name)): BoundedPath<(String, String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment (including `first_char`, which the handler itself
    // doesn't read but still protects logging/tracing). Unwrap the
    // `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`.
    let _ = first_char;
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    serve_index(&ctx, &repo_key, &crate_name, actor).await
}

async fn sparse_index_4plus(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, aa, bb, crate_name)): BoundedPath<(String, String, String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment. `aa`/`bb` are index-layout segments the handler
    // itself doesn't read but the cap still protects logging/tracing and
    // keeps every extraction systematically capped. Unwrap the
    // `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`.
    let _ = (aa, bb);
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    serve_index(&ctx, &repo_key, &crate_name, actor).await
}

/// Generate the NDJSON body for one crate's sparse index entry.
///
/// Dispatches on `repository.repo_type`:
///
/// - `Proxy` → pull-through with `EphemeralStore`-backed caching via
///   [`index_cache::fetch_with_cache`]. The cached body is the
///   upstream's NDJSON verbatim — Cargo clients see whatever the
///   mirror would have served.
/// - All other types (`Hosted`, `Staging`, `Virtual`) → synthesise the
///   NDJSON from local artifacts. Returns 404 when no artifact with the
///   lowercased name exists in the repo — cargo treats a 404 index as
///   "crate does not exist" and fails cleanly.
///
/// Repo resolution goes through `RepositoryAccessUseCase::resolve(_,
/// actor, Read)` first so anonymous reads on private repos collapse to
/// the same 404 envelope as missing-repo (anti-enumeration, ADR 0008).
/// The sparse-index path is the most attractive enumeration target —
/// without this, an unauthenticated probe could enumerate every crate
/// (and its sha256 cksum) in any private repo whose key it could guess.
///
/// Both `Proxy` and `Hosted` / `Staging` / `Virtual` paths route
/// through the unified [`serve::serve_index_unified`] handler, which
/// dispatches a source by `repo.repo_type` internally and runs the
/// result through the Source → Filter → Builder pipeline.
async fn serve_index(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    crate_name: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    serve::serve_index_unified(ctx, repo_key, crate_name, actor).await
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/api/v1/crates/{name}/{version}/download
// ---------------------------------------------------------------------------

async fn download(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, name, version)): BoundedPath<(String, String, String)>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap on every
    // captured segment before this handler body runs.
    //
    // Spec 074 §2 — resolve via the single SSOT path constructor, which
    // lowercases the name (`normalize_name`). This was previously the lone
    // raw-form outlier (`crates/{name}/...` with the un-lowercased URL
    // segment), inconsistent with publish (`lib.rs` `do_publish`) and the
    // read-side `parse_download_path` — both of which store/lookup the
    // lowercased canonical row. The retired "drift-resilience" rationale
    // traded publish/read coherence for resilience against a normalization
    // change that should be a re-projection migration, not a read-time
    // guess (spec 074 §5). A `Serde`-cased download now resolves the
    // `serde`-stored row instead of 404-ing.
    let artifact_path = CargoFormatHandler
        .build_artifact_logical_path(&name, &version, None)
        .map_err(ApiError::from)?;

    // `find_visible_by_path` resolves the repo via
    // `RepositoryAccessUseCase::resolve(_, actor, Read)` first, then
    // looks up the artifact scoped to that repo's id. Repo missing,
    // repo invisible to actor, and artifact missing all collapse to the
    // same `NotFound` envelope (anti-enumeration, ADR 0008).
    //
    // On a cache miss for a `RepositoryType::Proxy` repo, route through
    // [`upstream_pull::try_upstream_crate_pull`] and serve the freshly-
    // minted artifact via the existing quarantine + streaming code below.
    // Hosted/Staging/Virtual repos: cache miss → 404. The branch hinges
    // on the `entity` discriminator inside `find_visible_by_path`'s
    // `NotFound`: `"Repository"` (missing or invisible) propagates as 404
    // immediately — same envelope, no upstream side-effect; `"Artifact"`
    // (repo visible, path missing) falls through to the type-check
    // branch below. The use case carries the resolved `Repository` only
    // on the success arm, so the Proxy branch re-resolves via the
    // access use case to inspect `repo_type` (mirrors the OCI prior art
    // at `crates/hort-http-oci/src/blobs.rs:260`).
    // Unwrap the `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
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
            if !matches!(repo.repo_type, RepositoryType::Proxy) {
                // Hosted / Staging / Virtual cache miss → 404. Match the
                // envelope the use case would have produced
                // (`{"error":"not found: Artifact <repo>:<path>"}`) so
                // the `download_not_found_returns_404` regression stays
                // green and clients see no observable change.
                return Err(ApiError::from(hort_app::error::AppError::Domain(
                    hort_domain::error::DomainError::NotFound {
                        entity: "Artifact",
                        id: format!("{repo_key}:{artifact_path}"),
                    },
                )));
            }
            match upstream_pull::try_upstream_crate_pull(&ctx, &repo, &name, &version).await {
                Ok(artifact) => (repo, artifact),
                Err(e) => return Ok(upstream_pull::map_upstream_pull_error(&e)),
            }
        }
        Err(other) => return Err(other.into()),
    };

    match artifact.quarantine_status {
        QuarantineStatus::Quarantined => {
            // The use-case layer hydrates the transient computed
            // `quarantine_deadline` (ADR 0007); the format crate never
            // computes it (it cannot resolve a `ScanPolicy`).
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
        // a terminal block like `Rejected`, not a timed hold
        // (`quarantine_until` does not apply, so no Retry-After). The
        // Artifactory transparent-proxy 503 mapping for this state is a
        // separate, deferred concern — this is the native-handler path
        // (ADR 0007).
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

    // Thread the already-resolved request principal so the opt-in
    // download-audit emit can attribute the pull (no per-handler auth
    // code; `actor` was resolved above for the `find_visible_by_path`
    // visibility hop).
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
// PUT /{repo_key}/api/v1/crates/new
// ---------------------------------------------------------------------------

/// Only the fields we need from the cargo publish metadata JSON. Cargo sends
/// many more — ignored by `serde(default)` elsewhere, implicit here because
/// extra fields are allowed unless `deny_unknown_fields` is set.
#[derive(Deserialize)]
struct PublishMetadata {
    name: String,
    vers: String,
}

async fn publish(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath(repo_key): BoundedPath<String>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    // `BoundedPath` enforces the route-parameter length cap before this
    // handler body runs.
    //
    // Resolve the repo via the visibility-aware use case. `AccessLevel::Read`
    // gives anti-enumeration: an anonymous / unauthorised principal probing
    // for private-repo existence sees the same 404 envelope as a missing
    // repo. The subsequent `resolve_actor_user_id` call below keeps
    // enforcing the Write authz gate with its existing 403 +
    // `{"error":"insufficient permissions"}` body, so the deny envelope on
    // the WRITE permission stays verbatim. Unwrap the
    // `AuthenticatedPrincipal` newtype to `Option<&CallerPrincipal>`.
    let actor = principal.as_deref().map(AuthenticatedPrincipal::as_caller);
    let repo = ctx
        .repository_access_use_case
        .resolve(&repo_key, actor, AccessLevel::Read)
        .await?;

    // Gate write on authorization. See
    // `handlers::pypi::resolve_actor_user_id` for the full contract.
    // The helper returns a pre-shaped `Response` on reject so the deny
    // body stays `{"error":"insufficient permissions"}` verbatim.
    let actor_user_id = match resolve_actor_user_id(&ctx, principal, repo.id) {
        Ok(id) => id,
        Err(response) => return Ok(*response),
    };

    let (metadata_bytes, crate_bytes) = parse_publish_body(&body)?;

    let metadata: PublishMetadata = serde_json::from_slice(metadata_bytes)
        .map_err(|e| validation_error(&format!("invalid publish metadata JSON: {e}")))?;

    // Validate the publish-side `name` and `vers` against the cargo
    // grammar BEFORE any storage path is constructed or any
    // side-effecting action is taken. Validators run on the
    // pre-normalised input — normalisation is for downstream consumption,
    // not a security boundary. Error messages emit the structured
    // `cargo.<field>` shape and never echo the offending input.
    hort_formats::cargo::validate_cargo_name(&metadata.name)
        .map_err(|e| ApiError::from(hort_app::error::AppError::Domain(e)))?;
    hort_formats::cargo::validate_cargo_version(&metadata.vers)
        .map_err(|e| ApiError::from(hort_app::error::AppError::Domain(e)))?;

    let handler = CargoFormatHandler;
    let raw_name = metadata.name.clone();
    let normalized = handler.normalize_name(&metadata.name);
    let version = metadata.vers;
    // Spec 074 §2 — the canonical stored path comes from the single SSOT
    // constructor (`crates/{n}/{v}/{n}-{v}.crate`, `n` lowercased), the
    // exact string `parse_download_path` + the download handler produce.
    // cargo derives the filename from name+version, so `filename = None`.
    let path = handler
        .build_artifact_logical_path(&raw_name, &version, None)
        .map_err(ApiError::from)?;

    let coords = ArtifactCoords {
        name: normalized,
        // Raw crate name as it appeared in publish metadata, before
        // cargo's case-folding normalisation.
        name_as_published: raw_name,
        version: Some(version),
        path,
        format: RepositoryFormat::Cargo,
        metadata: serde_json::Value::Null,
    };

    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(crate_bytes.to_vec()));

    let actor = ApiActor {
        user_id: actor_user_id,
    };

    ctx.ingest_use_case
        .ingest_direct(
            hort_app::use_cases::ingest_use_case::DirectIngestRequest {
                repository_id: repo.id,
                coords,
                content_type: "application/x-tar".into(),
                // Quarantine resolution is policy-driven (ADR 0007);
                // no caller-supplied override field. Operator
                // `ScanPolicy.quarantineDuration` or the default (24 h)
                // drives the decision inside `ingest_inner`.
                actor,
                legacy_sha1: None, // cargo's cksum IS the SHA-256 storage hash
                legacy_md5: None,
                // Cargo sparse-index metadata (`PublishMetadata` — features,
                // deps, yanked) extraction lands as a follow-up when the
                // index read path consumes it — see the Item 2 "Not in
                // scope" note in the backlog.
                payload_metadata: serde_json::Value::Null,
            },
            stream,
            // Reuse the handler instantiated earlier for `normalize_name`
            // — one FormatHandler instance per request.
            &handler,
        )
        .await?;

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        serde_json::json!({"warnings": {"invalid_categories": [], "invalid_badges": [], "other": []}})
            .to_string(),
    )
        .into_response())
}

/// Parse the cargo publish binary body:
/// `[u32 LE metadata_len][metadata JSON][u32 LE crate_len][crate bytes]`.
///
/// Returns `(metadata_bytes, crate_bytes)` as sub-slices of the input buffer,
/// or a 400-mapped `ApiError` on truncation or length overflow.
fn parse_publish_body(body: &[u8]) -> Result<(&[u8], &[u8]), ApiError> {
    // The cargo publish frame's `meta_len` is attacker-supplied; cap it
    // before any slice so a bogus declaration cannot push the parser to
    // allocate or scan multi-MiB buffers. Publish metadata in practice
    // carries a single version's metadata, which is structurally
    // comparable to a sparse-index entry — well under 64 KiB per the
    // per-entry measurements in `crates/measurement-tools/src/cargo.rs`.
    // Decoupled from `CargoFormatHandler::metadata_expected_max_bytes()`
    // (the upstream-body cap, 8 MiB; see `hort-formats/src/cargo.rs`).
    // Diagnostic carries the cap word but no body bytes.
    const PUBLISH_META_CAP: usize = 64 * 1024;

    let (meta_len_bytes, rest) = body.split_at_checked(4).ok_or_else(|| {
        validation_error("publish body truncated: missing metadata length prefix")
    })?;
    let meta_len = u32::from_le_bytes(meta_len_bytes.try_into().unwrap()) as usize;

    if meta_len > PUBLISH_META_CAP {
        return Err(validation_error("publish metadata exceeds 64 KB cap"));
    }

    let (metadata, rest) = rest.split_at_checked(meta_len).ok_or_else(|| {
        validation_error("publish body truncated: metadata shorter than declared")
    })?;

    let (crate_len_bytes, rest) = rest
        .split_at_checked(4)
        .ok_or_else(|| validation_error("publish body truncated: missing crate length prefix"))?;
    let crate_len = u32::from_le_bytes(crate_len_bytes.try_into().unwrap()) as usize;

    let crate_bytes = rest
        .get(..crate_len)
        .ok_or_else(|| validation_error("publish body truncated: crate shorter than declared"))?;

    Ok((metadata, crate_bytes))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactRepository, MockRepositoryRepository,
        MockStoragePort,
    };
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::Repository;

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
        /// Curation-gate seed handle for the
        /// `publish_curation_block_returns_403` test.
        curation_rules: Arc<hort_app::use_cases::test_support::MockCurationRuleRepository>,
    }

    fn harness() -> TestHarness {
        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        let (ctx, mocks) = build_mock_ctx(metrics_handle);
        // Post-Item-3 cargo tests drive `config.json` through the F2
        // trust layer. `TrustConfig::default()` pins
        // `http://hort-server:8080`, which would short-circuit every
        // `Host: registry.example.com` → `https://registry.example.com/...`
        // assertion. Override with the untrusted-peer fallback so the
        // layer actually falls back to `Host` + `https`.
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        TestHarness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
            curation_rules: mocks.curation_rules,
        }
    }

    /// Build a router with the F2 request-trust layer attached.
    ///
    /// Post-Item-3, `config_json` pulls the public URL from
    /// `RequestTrust` via the F2 layer. Router helpers in this test
    /// module replicate the production wiring so handler tests
    /// exercise the same path as the integration stack.
    fn router(ctx: Arc<AppContext>) -> Router {
        let trust_cfg = ctx.trust_config.clone();
        Router::new()
            .nest("/cargo", cargo_routes())
            .layer(hort_http_core::middleware::trust::request_trust_layer(
                trust_cfg,
            ))
            .with_state(ctx)
    }

    fn router_with_publish_limit(ctx: Arc<AppContext>, limit: usize) -> Router {
        let trust_cfg = ctx.trust_config.clone();
        Router::new()
            .nest("/cargo", cargo_routes_with_publish_limit(limit))
            .layer(hort_http_core::middleware::trust::request_trust_layer(
                trust_cfg,
            ))
            .with_state(ctx)
    }

    fn insert_repo(h: &TestHarness, key: &str) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.to_string();
        repo.format = RepositoryFormat::Cargo;
        h.repositories.insert(repo.clone());
        repo
    }

    fn insert_crate_artifact(
        h: &TestHarness,
        repo_id: Uuid,
        name: &str,
        version: &str,
        content: &[u8],
        status: QuarantineStatus,
    ) -> Artifact {
        use sha2::{Digest, Sha256};
        let hash_hex = format!("{:x}", Sha256::digest(content));
        let sha256 = hash_hex.parse().unwrap();

        let mut artifact = sample_artifact(status);
        artifact.repository_id = repo_id;
        artifact.name = name.to_string();
        artifact.version = Some(version.to_string());
        artifact.path = format!("crates/{name}/{version}/{name}-{version}.crate");
        artifact.sha256_checksum = sha256;
        artifact.size_bytes = content.len() as i64;
        h.artifacts.insert(artifact.clone());
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), content.to_vec());
        artifact
    }

    /// Build a well-formed cargo publish body.
    fn build_publish_body(metadata_json: &[u8], crate_bytes: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(8 + metadata_json.len() + crate_bytes.len());
        body.extend_from_slice(&(metadata_json.len() as u32).to_le_bytes());
        body.extend_from_slice(metadata_json);
        body.extend_from_slice(&(crate_bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(crate_bytes);
        body
    }

    // -- config.json ----------------------------------------------------------

    #[tokio::test]
    async fn config_json_returns_absolute_urls_with_default_https_scheme() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/config.json")
                    .header("host", "registry.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["dl"].as_str().unwrap(),
            "https://registry.example.com/cargo/cargo-test/api/v1/crates"
        );
        assert_eq!(
            json["api"].as_str().unwrap(),
            "https://registry.example.com/cargo/cargo-test"
        );
        // auth-required is intentionally omitted in 4A2 (no auth middleware yet).
        assert!(json.get("auth-required").is_none());
    }

    /// `X-Forwarded-Proto` is ONLY honoured when the socket peer is in
    /// `HORT_TRUSTED_PROXY_CIDRS`. The test harness has no trusted
    /// proxies, so an `X-Forwarded-Proto: http` sent from an untrusted
    /// peer is ignored — the trust layer still publishes an `https://…`
    /// URL built from the `Host` header. The old resolver would have
    /// rewritten the scheme; the trusted-proxy check closes that attack
    /// vector. (Trusted-proxy-forwarding coverage lives in
    /// `middleware::trust::tests`.)
    #[tokio::test]
    async fn config_json_ignores_untrusted_x_forwarded_proto() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/config.json")
                    .header("host", "registry.example.com")
                    .header("x-forwarded-proto", "http")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["dl"].as_str().unwrap().starts_with("https://"),
            "untrusted X-Forwarded-Proto must not downgrade scheme: {}",
            json["dl"]
        );
    }

    /// A request with no `Host` header no longer produces a 400. The
    /// trust layer guarantees `RequestTrust.public_url` is populated
    /// via the bind-address fallback, so `config.json` serves a 200
    /// with URLs built from that fallback. The test harness pins the
    /// bind-address default to `http://0.0.0.0:8080/`.
    #[tokio::test]
    async fn config_json_missing_host_falls_back_to_bind_address() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/config.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["dl"].as_str().unwrap(),
            "http://0.0.0.0:8080/cargo/cargo-test/api/v1/crates"
        );
        assert_eq!(
            json["api"].as_str().unwrap(),
            "http://0.0.0.0:8080/cargo/cargo-test"
        );
    }

    #[tokio::test]
    async fn config_json_unknown_repo_returns_404() {
        let h = harness();
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/missing/config.json")
                    .header("host", "registry.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    // -- download -------------------------------------------------------------

    #[tokio::test]
    async fn download_not_found_returns_404() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/missing/1.0.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn download_happy_path_returns_bytes() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            b"crate contents here",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/serde/1.0.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        assert_eq!(&body[..], b"crate contents here");
    }

    /// When the served repo opted in to download audit, an anonymous
    /// cargo download (no principal) emits one `ArtifactDownloaded` on
    /// the per-(repo, UTC-date) DownloadAudit stream with
    /// `DownloadActor::Anonymous` (no audit gap). Threaded adapter-free
    /// via `build_mock_ctx` (no hand-rolled AppContext).
    #[tokio::test]
    async fn download_audit_emits_anonymous_when_repo_opted_in() {
        use hort_domain::events::{DomainEvent, DownloadActor, StreamCategory};

        // Adapter-free wiring via build_mock_ctx — own the MockPorts
        // handle so the captured ArtifactDownloaded batch is
        // assertable on `mocks.events`.
        let (ctx, mocks) = build_mock_ctx(
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle(),
        );
        let mut repo2 = sample_repository();
        repo2.key = "cargo-audit".into();
        repo2.format = RepositoryFormat::Cargo;
        repo2.download_audit_enabled = true;
        let repo2_id = repo2.id;
        mocks.repositories.insert(repo2);
        {
            use sha2::{Digest, Sha256};
            let content = b"crate contents here";
            let sha256 = format!("{:x}", Sha256::digest(content)).parse().unwrap();
            let mut a = sample_artifact(QuarantineStatus::None);
            a.repository_id = repo2_id;
            a.name = "serde".into();
            a.version = Some("1.0.0".into());
            a.path = "crates/serde/1.0.0/serde-1.0.0.crate".into();
            a.sha256_checksum = sha256;
            a.size_bytes = content.len() as i64;
            mocks.artifacts.insert(a.clone());
            mocks
                .storage
                .insert_content(a.sha256_checksum.clone(), content.to_vec());
        }
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let router = router(ctx);

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-audit/api/v1/crates/serde/1.0.0/download")
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
            hort_domain::events::StreamId::artifact(repo2_id),
            "never the artifact aggregate stream"
        );
        match ev {
            DomainEvent::ArtifactDownloaded(e) => {
                assert_eq!(e.repository_id, repo2_id);
                assert!(
                    matches!(e.actor, DownloadActor::Anonymous),
                    "anonymous cargo pull → DownloadActor::Anonymous"
                );
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn download_quarantined_returns_503_with_retry_after() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            b"payload",
            QuarantineStatus::Quarantined,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/serde/1.0.0/download")
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
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            b"payload",
            QuarantineStatus::Rejected,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/serde/1.0.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// Spec 074 §2/§3 (behaviour change, accepted): the download handler
    /// now resolves via the single SSOT path constructor, which lowercases
    /// the name (`normalize_name`). A case-mismatched hand-constructed URL
    /// (`/Serde/1.0.0/download`) therefore RESOLVES the canonical `serde`
    /// row instead of 404-ing. This was previously the lone raw-form
    /// outlier (inconsistent with publish + `parse_download_path`, both of
    /// which store/lookup the lowercased canonical row). The retired
    /// "drift-resilience" rationale traded publish/read coherence for
    /// resilience against a normalization change that should be a
    /// re-projection migration, not a read-time guess (spec 074 §5).
    #[tokio::test]
    async fn download_resolves_case_variant_to_canonical_row() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            b"payload",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        // Case-mismatched request: stored `path = crates/serde/...`, URL
        // asks for `crates/Serde/...`. The handler lowercases via the SSOT
        // constructor and hits the canonical `serde` row.
        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/Serde/1.0.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        assert_eq!(&body[..], b"payload");
    }

    // -- Proxy-repo pull-through wiring --------------------------------------
    //
    // Regression coverage for the cache-miss + Proxy branch in the
    // `download` handler. The fixture loop mirrors `upstream_pull::tests`:
    // seed a Cargo Proxy repo + upstream mapping, preload `config.json`
    // and the per-crate NDJSON entry on the mock upstream proxy, then
    // exercise the `download` route end-to-end.
    //
    // The handler routes a Proxy cache miss through `try_upstream_crate_pull`,
    // ingests the freshly-fetched + cksum-verified bytes via
    // `IngestUseCase::ingest_verified` (no quarantine_until passed → the
    // returned artifact is `QuarantineStatus::None`), and falls into the
    // existing quarantine + streaming path. Result on the happy path:
    // 200 + verified bytes.
    //
    // Hosted/Staging/Virtual repos must NOT enter the Proxy branch — the
    // `local_repo_cache_miss_still_returns_404` test pins this.

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

        /// Crates.io-style minimal config.json — placeholder-free `dl`.
        /// `compose_download_url` then appends `/{name}/{version}/download`,
        /// matching the fixture in `upstream_pull::tests`.
        const CRATES_IO_CONFIG: &[u8] =
            br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#;

        fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
            PrometheusBuilder::new().build_recorder().handle()
        }

        fn proxy_cargo_repo(key: &str) -> Repository {
            let mut r = sample_repository();
            r.key = key.into();
            r.format = RepositoryFormat::Cargo;
            r.repo_type = RepositoryType::Proxy;
            r.upstream_url = Some("https://crates.io".into());
            // These tests seed no `package_version_status` rows; under
            // `ReleasedOnly` (the production default) the quarantine
            // filter would drop the upstream NDJSON. `IncludePending`
            // preserves the upstream catalog when no local status is
            // known, so these tests keep their original behaviour.
            // Mirrors `index_cache::tests::proxy_cargo_repo`.
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
                upstream_url: "https://crates.io".into(),
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

        fn ndjson_entry(name: &str, version: &str, cksum: &str) -> Vec<u8> {
            format!(
                r#"{{"name":"{name}","vers":"{version}","deps":[],"cksum":"{cksum}","features":{{}},"yanked":false}}"#
            )
            .into_bytes()
        }

        fn artifact_url(name: &str, version: &str) -> String {
            format!("https://static.crates.io/crates/{name}/{version}/download")
        }

        fn router_for(ctx: Arc<AppContext>) -> Router {
            let trust_cfg = ctx.trust_config.clone();
            Router::new()
                .nest("/cargo", cargo_routes())
                .layer(hort_http_core::middleware::trust::request_trust_layer(
                    trust_cfg,
                ))
                .with_state(ctx)
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
            let repo = proxy_cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body = b"the actual crate body".to_vec();
            let cksum = format!("{:x}", Sha256::digest(&body));
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.214", &cksum),
            );
            mocks.upstream_proxy.insert_artifact(
                "",
                &artifact_url("serde", "1.0.214"),
                body.clone(),
            );

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/cargo/crates-mirror/api/v1/crates/serde/1.0.214/download")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
            assert_eq!(&bytes[..], body.as_slice());
        }

        /// Cache miss + Proxy + upstream serves bytes that disagree with
        /// the advertised cksum → 502 + `X-Hort-Reason: upstream-checksum-mismatch`.
        /// Pins the security primitive against upstream tampering: the
        /// rehash inside `ingest_verified` rejects, the orchestrator
        /// surfaces `ChecksumMismatch`, and the wire-map renders 502.
        #[tokio::test]
        async fn download_proxy_repo_cache_miss_checksum_mismatch_returns_502() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual = b"actual-bytes".to_vec();
            let lying_cksum = format!("{:x}", Sha256::digest(b"different-bytes"));
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.0", &lying_cksum),
            );
            mocks
                .upstream_proxy
                .insert_artifact("", &artifact_url("serde", "1.0.0"), actual);

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/cargo/crates-mirror/api/v1/crates/serde/1.0.0/download")
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
        }

        /// Cache miss + Proxy + upstream NDJSON entry has no `cksum` →
        /// `parse_upstream_checksum` returns `Validation`, the
        /// orchestrator surfaces `ParseError`, and the wire-map renders
        /// 502 + `X-Hort-Reason: upstream-metadata-malformed`.
        #[tokio::test]
        async fn download_proxy_repo_cache_miss_no_cksum_returns_502() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            // Index entry for the right (name, version) but missing
            // the `cksum` field — `parse_upstream_checksum` returns
            // `Validation` ⇒ orchestrator surfaces `ParseError`.
            let body = br#"{"name":"serde","vers":"1.0.0","deps":[],"features":{},"yanked":false}"#;
            mocks
                .upstream_proxy
                .insert_metadata("", "/se/rd/serde", body.to_vec());

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/cargo/crates-mirror/api/v1/crates/serde/1.0.0/download")
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
        }

        /// Hosted (the `sample_repository` default) cache miss MUST NOT
        /// enter the Proxy pull-through branch — pre-Item-5 behaviour
        /// is preserved as a clean 404. Regression test: a routing
        /// regression that fired pull-through unconditionally would
        /// either return 200 (if upstream were seeded — it isn't) or
        /// surface a 502 from the orchestrator's `NoUpstreamMapping`
        /// path. Both fail the 404 assertion.
        #[tokio::test]
        async fn download_hosted_repo_cache_miss_still_returns_404() {
            let h = harness();
            insert_repo(&h, "cargo-hosted"); // sample_repository → Hosted
            let router = router(h.ctx.clone());

            let res = router
                .oneshot(
                    Request::get("/cargo/cargo-hosted/api/v1/crates/serde/1.0.0/download")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        // -- Upstream-verification framework-invariant assertions -----------
        //
        // The three tests above pin the wire shape: status code, body,
        // `X-Hort-Reason` header. The three tests below extend that
        // coverage to the upstream-verification audit invariants
        // (ADR 0006):
        //
        // 1. Happy path emits exactly one `ChecksumVerified` in the SAME
        //    `commit_transition` batch as `ArtifactIngested` (the
        //    "atomic with the mint" rule); the blob lands in the CAS.
        // 2. Tampered crate emits exactly one `ChecksumMismatch` on the
        //    REPOSITORY stream (never the artifact stream); no
        //    `ArtifactIngested` and no `ChecksumVerified` fire anywhere;
        //    no artifact row is minted (mint-after-verify).
        // 3. Missing-cksum surfaces as a parser failure that runs
        //    BEFORE `ingest_verified` is invoked — therefore no event
        //    of any kind appears on either stream and `storage.put`
        //    is never called.
        //
        // Assertions ride on the existing mock ports. The framework
        // boundary worth verifying here is the use-case + orchestrator
        // layer; the HTTP-adapter's network plumbing is covered by
        // `hort-adapters-upstream-http`'s own wiremock tests, and
        // dragging wiremock into `hort-http-cargo` would re-test that
        // boundary at the wrong layer.

        /// Happy path: cache miss + Proxy + upstream serves the
        /// advertised crate body.
        ///
        /// Wire is already covered by Item 5's
        /// `download_proxy_repo_cache_miss_success_returns_200`; this
        /// test asserts the FRAMEWORK invariants:
        /// - `ChecksumVerified` and `ArtifactIngested` ride in the
        ///   SAME `commit_transition` batch (atomic with the mint
        ///   per design §13), and that batch lands on the
        ///   `StreamCategory::Artifact` stream.
        /// - The freshly-fetched body is present in the CAS at its
        ///   computed hash (`storage.put` ran exactly once and the
        ///   bytes are recoverable).
        #[tokio::test]
        async fn download_proxy_happy_path_emits_checksum_verified_and_writes_cas() {
            use hort_domain::events::StreamCategory;
            use hort_domain::types::ContentHash;

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let body = b"the actual crate body".to_vec();
            let cksum = format!("{:x}", Sha256::digest(&body));
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.214", &cksum),
            );
            mocks.upstream_proxy.insert_artifact(
                "",
                &artifact_url("serde", "1.0.214"),
                body.clone(),
            );

            let lifecycle = mocks.lifecycle.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/cargo/crates-mirror/api/v1/crates/serde/1.0.214/download")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);

            // Audit invariant 1: ArtifactIngested + ChecksumVerified
            // (+ ScanRequested, DefaultPolicy fallback) land in the
            // SAME commit_transition batch on the artifact stream.
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
            let expected_hash: ContentHash = cksum
                .parse()
                .expect("computed cksum must parse as a ContentHash");
            let stored = storage.stored_hashes();
            assert!(
                stored.contains(&expected_hash),
                "freshly-fetched body must be recoverable from the CAS at its computed hash; \
                 stored hashes: {stored:?}"
            );
        }

        /// Tampered crate: cache miss + Proxy + upstream serves bytes
        /// that disagree with the advertised cksum.
        ///
        /// Wire is already covered by Item 5's
        /// `download_proxy_repo_cache_miss_checksum_mismatch_returns_502`;
        /// this test asserts the FRAMEWORK invariants from §13:
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
        async fn download_proxy_tampered_emits_checksum_mismatch_and_no_cas_residue() {
            use hort_domain::events::{DomainEvent, StreamCategory};

            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual = b"actual-bytes".to_vec();
            let lying_cksum = format!("{:x}", Sha256::digest(b"different-bytes"));
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.0", &lying_cksum),
            );
            mocks
                .upstream_proxy
                .insert_artifact("", &artifact_url("serde", "1.0.0"), actual);

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/cargo/crates-mirror/api/v1/crates/serde/1.0.0/download")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);

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

        /// Missing cksum: NDJSON entry for the requested
        /// (name, version) lacks the `cksum` field.
        ///
        /// Wire is already covered by Item 5's
        /// `download_proxy_repo_cache_miss_no_cksum_returns_502`; this
        /// test asserts the FRAMEWORK invariants:
        /// - `parse_upstream_checksum` fails BEFORE `ingest_verified`
        ///   is called, so no event is ever emitted on either stream.
        /// - `storage.put` is never called (the parser short-circuits
        ///   ahead of the artifact-fetch + storage.put sequence).
        #[tokio::test]
        async fn download_proxy_missing_cksum_writes_no_event_and_no_cas() {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = proxy_cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            // Index entry for the right (name, version) but missing
            // `cksum` — `parse_upstream_checksum` returns `Validation`,
            // the orchestrator surfaces `ParseError`, and the
            // pull-through path bails before `ingest_verified` is
            // invoked.
            let body = br#"{"name":"serde","vers":"1.0.0","deps":[],"features":{},"yanked":false}"#;
            mocks
                .upstream_proxy
                .insert_metadata("", "/se/rd/serde", body.to_vec());

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = router_for(ctx);
            let res = router
                .oneshot(
                    Request::get("/cargo/crates-mirror/api/v1/crates/serde/1.0.0/download")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_GATEWAY);

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
            // parser short-circuits ahead of the artifact fetch and
            // before any put.
            assert_eq!(
                storage.put_call_count(),
                0,
                "parse-fail must short-circuit before any storage.put"
            );
        }
    }

    // -- publish --------------------------------------------------------------

    #[tokio::test]
    async fn publish_happy_path_returns_200() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"mycrate","vers":"0.1.0"}"#;
        let crate_bytes = b"fake crate tarball content";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// `cargo publish` on a repository with a matching `Block` curation
    /// rule must surface as 403 (the default `DomainError::CurationBlocked`
    /// mapping). Cargo has no pull-through fetch handler today, so the
    /// per-format 404 override does not apply — this test pins the
    /// default-mapping behaviour for the publish path.
    #[tokio::test]
    async fn publish_curation_block_returns_403() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;

        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        let rule = CurationRule {
            id: Uuid::new_v4(),
            name: "block-mycrate".into(),
            format: None,
            package_pattern: "mycrate".into(),
            action: CurationRuleAction::Block,
            reason: "yanked upstream".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        h.curation_rules.set_rules_for_repo(repo.id, vec![rule]);
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"mycrate","vers":"0.1.0"}"#;
        let crate_bytes = b"fake crate tarball content";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
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
        assert!(body_str.contains("block-mycrate"));
        assert!(body_str.contains("yanked upstream"));
    }

    #[tokio::test]
    async fn publish_then_download_roundtrip_matches() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"roundtrip","vers":"2.3.4","deps":[],"features":{}}"#;
        let crate_bytes = b"the actual crate bytes to round-trip";
        let body = build_publish_body(metadata, crate_bytes);

        let pub_res = router
            .clone()
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pub_res.status(), StatusCode::OK);

        let dl_res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/roundtrip/2.3.4/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl_res.status(), StatusCode::OK);
        let body_bytes = to_bytes(dl_res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&body_bytes[..], crate_bytes);
    }

    #[tokio::test]
    async fn publish_lowercases_crate_name_on_store() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"MyCrate","vers":"0.1.0"}"#;
        let crate_bytes = b"bytes";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .clone()
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Download via lowercased path should succeed.
        let dl_res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/mycrate/0.1.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl_res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn publish_truncated_body_returns_400() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        // Declare 100-byte metadata but supply only 10 bytes.
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_le_bytes());
        body.extend_from_slice(b"short meta");
        // Missing crate_len entirely.

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_empty_body_returns_400() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_invalid_metadata_json_returns_400() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let body = build_publish_body(b"{not valid json", b"bytes");
        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // -- publish-handler input validators ------------------------------------
    //
    // `validate_cargo_name` / `validate_cargo_version` guard both the
    // download and publish paths. These three tests pin the publish-side
    // validation: each rejection case proves that storage is never touched
    // when the validator fires (fail closed before any side-effecting
    // action), and the happy-path regression catches anyone re-introducing
    // a wildcard bypass.

    /// A traversal-shaped name (`../../../etc/passwd`) is rejected at
    /// the validator and storage is never written to. The rejection
    /// grammar is already test-locked in `hort-formats::cargo`; this
    /// test pins the wiring at the HTTP boundary.
    #[tokio::test]
    async fn publish_rejects_traversal_in_name_returns_400() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"../../../etc/passwd","vers":"1.0.0"}"#;
        let crate_bytes = b"fake crate tarball content";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Audit invariant: validator short-circuits before the ingest
        // use case is awaited, so no storage write is ever attempted.
        assert_eq!(
            h.storage.put_call_count(),
            0,
            "validator must short-circuit before any storage.put"
        );
    }

    /// A version with embedded CRLF (`1.0\r\nInjected`) is rejected at
    /// the validator. Pins the response-header / log-injection class
    /// shut at the publish boundary symmetrically with the download
    /// path's existing coverage.
    #[tokio::test]
    async fn publish_rejects_crlf_in_version_returns_400() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        // Use a JSON-escaped CRLF — `serde_json::from_slice` decodes
        // `\r\n` to the actual control bytes, which is what the
        // validator must catch.
        let metadata = br#"{"name":"valid_crate","vers":"1.0\r\nInjected"}"#;
        let crate_bytes = b"fake crate tarball content";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
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

    /// Happy-path regression — a valid `name`/`vers` pair flows through
    /// the validators unchanged and the publish completes with 200.
    #[tokio::test]
    async fn publish_valid_name_and_version_returns_200() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"valid_crate","vers":"1.0.0"}"#;
        let crate_bytes = b"fake crate tarball content";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn publish_body_exceeding_limit_is_rejected() {
        // Use a small publish limit so we can realistically exceed it in a test.
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router_with_publish_limit(h.ctx.clone(), 1024);

        // Construct a body that's larger than 1 KiB.
        let metadata = br#"{"name":"big","vers":"1.0.0"}"#;
        let crate_bytes = vec![0u8; 4096];
        let body = build_publish_body(metadata, &crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // axum returns 413 Payload Too Large when the layer rejects.
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // -- route-parameter length cap -------------------------------------------

    /// A 1 KiB crate version in a download URL → 400 + stable JSON body
    /// naming the offending parameter.
    #[tokio::test]
    async fn download_rejects_oversized_version() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let huge = "9".repeat(1024);
        let res = router
            .oneshot(
                Request::get(format!(
                    "/cargo/cargo-test/api/v1/crates/serde/{huge}/download"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        assert_eq!(json["parameter"], "version");
    }

    /// Boundary regression: exactly 512 bytes stays under the cap (no
    /// 400). Falls through to 404 because no artifact of that name
    /// exists. Pins the comparator as `>` not `>=`.
    #[tokio::test]
    async fn download_accepts_version_at_cap_boundary() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let at_cap = "9".repeat(hort_http_core::limits::MAX_ROUTE_PARAM_BYTES);
        let res = router
            .oneshot(
                Request::get(format!(
                    "/cargo/cargo-test/api/v1/crates/serde/{at_cap}/download"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        // 512 bytes — under the cap. Not 400.
        assert_ne!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// Oversized `repo_key` on the publish path → 400 + `repo_key`
    /// parameter label. Covers the publish-handler extraction point.
    #[tokio::test]
    async fn publish_rejects_oversized_repo_key() {
        let h = harness();
        let router = router(h.ctx.clone());

        let huge = "a".repeat(600);
        let metadata = br#"{"name":"x","vers":"1.0.0"}"#;
        let body = build_publish_body(metadata, b"crate-bytes");
        let res = router
            .oneshot(
                Request::put(format!("/cargo/{huge}/api/v1/crates/new"))
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

    // -- sparse index ---------------------------------------------------------

    #[tokio::test]
    async fn sparse_index_returns_ndjson_with_correct_cksum() {
        use sha2::{Digest, Sha256};

        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        let content: &[u8] = b"serde-1.0.0 bytes";
        let expected_cksum = format!("{:x}", Sha256::digest(content));
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            content,
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/se/rd/serde")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        // One line of NDJSON.
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let entry: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry["name"].as_str().unwrap(), "serde");
        assert_eq!(entry["vers"].as_str().unwrap(), "1.0.0");
        assert_eq!(entry["cksum"].as_str().unwrap(), expected_cksum);
        assert!(!entry["yanked"].as_bool().unwrap());
    }

    /// Normalisation-drift regression (arch findings Item 6) — updated for
    /// spec 074. The index-emission drift recovery is UNCHANGED: a raw
    /// client name that doesn't match the current normalise is still
    /// recovered via the `name_as_published` fallback
    /// (`list_by_raw_name`), and the NDJSON `name` still carries the
    /// stored form. What spec 074 §2/§3 changes is the DOWNLOAD handler:
    /// it now resolves via the single SSOT path constructor, which
    /// lowercases the name — so the canonical projection row is stored at
    /// the lowercased path and a follow-up download via the
    /// canonical-cased URL hits it. (Storing the row at a mixed-case path
    /// and serving it via a mixed-case download URL was the retired
    /// raw-form "drift-resilience" hack — the wrong tool for a
    /// normalization change, which is a re-projection migration, spec
    /// 074 §5.)
    ///
    /// The test asserts:
    /// (a) `list_by_raw_name` recovers the row via `name_as_published`
    ///     fallback (the raw index request doesn't match the normalise),
    /// (b) NDJSON entry's `name` is the STORED `"Legacy-Crate"`,
    /// (c) a follow-up download via the canonical lowercased URL hits the
    ///     canonical projection row.
    #[tokio::test]
    async fn sparse_index_recovers_drift_era_artifact_and_canonical_download_hits() {
        use sha2::{Digest, Sha256};

        let h = harness();
        let repo = insert_repo(&h, "cargo-test");

        let content: &[u8] = b"drift crate bytes";
        let sha256 = format!("{:x}", Sha256::digest(content)).parse().unwrap();
        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        // The NDJSON `name` field echoes the stored mixed-case name (the
        // index-emission drift case is unchanged). The PROJECTION row is
        // keyed on the canonical lowercased path — spec 074: publish and
        // the read-side `parse_download_path` both store/lookup the
        // lowercased canonical path.
        artifact.name = "Legacy-Crate".into();
        artifact.name_as_published = "drift-crate".into();
        artifact.version = Some("0.1.0".into());
        artifact.path = "crates/legacy-crate/0.1.0/legacy-crate-0.1.0.crate".into();
        artifact.sha256_checksum = sha256;
        artifact.size_bytes = content.len() as i64;
        h.artifacts.insert(artifact.clone());
        h.storage
            .insert_content(artifact.sha256_checksum.clone(), content.to_vec());

        let router = router(h.ctx.clone());

        // (1) Index request with the raw client name — routes through the
        // four-char index variant (dr/if/drift-crate). `list_by_raw_name`
        // normalises to `"drift-crate"`, finds nothing, falls back to
        // `find_by_name_as_published("drift-crate")` and recovers the row.
        let res = router
            .clone()
            .oneshot(
                Request::get("/cargo/cargo-test/dr/if/drift-crate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        let entry: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        // (2) NDJSON `name` carries the STORED mixed-case name.
        assert_eq!(entry["name"].as_str().unwrap(), "Legacy-Crate");

        // (3) Follow-up download via the canonical (lowercased) URL hits
        // the canonical projection row — the SSOT constructor lowercases,
        // so `/Legacy-Crate/...` and `/legacy-crate/...` both resolve it.
        let dl = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/Legacy-Crate/0.1.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dl.status(), StatusCode::OK);
        let dl_body = to_bytes(dl.into_body(), 8192).await.unwrap();
        assert_eq!(&dl_body[..], content);
    }

    #[tokio::test]
    async fn sparse_index_single_char_route() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(&h, repo.id, "a", "0.1.0", b"x", QuarantineStatus::None);
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/1/a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sparse_index_two_char_route() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(&h, repo.id, "ab", "0.1.0", b"x", QuarantineStatus::None);
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/2/ab")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sparse_index_three_char_route() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(&h, repo.id, "abc", "0.1.0", b"x", QuarantineStatus::None);
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/3/a/abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sparse_index_missing_crate_returns_404() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/se/rd/serde")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Unknown-repo regression — pinned at the dispatcher layer because
    /// the new Item 4 dispatch resolves the repo BEFORE branching on
    /// `repo_type`. A regression that swallowed `NotFound` and routed
    /// to either branch unconditionally would surface as a 200/502 for
    /// a non-existent `repo_key` instead of the expected 404.
    #[tokio::test]
    async fn sparse_index_unknown_repo_returns_404() {
        let h = harness();
        // Deliberately do NOT insert the repo.
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/missing/se/rd/serde")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    // -- Item 4 dispatch regression -------------------------------------------

    /// `RepositoryType::Hosted` MUST NOT route through the Item 4
    /// `index_cache` path. Pin the regression by seeding bogus bytes
    /// at the Item 4 cache key shape — if the dispatcher ever
    /// accidentally routed Hosted reads through `fetch_with_cache`,
    /// the test would either return the bogus body or 502. Both fail
    /// the `OK` + actual-NDJSON assertion.
    #[tokio::test]
    async fn local_repo_uses_existing_local_index_path() {
        use sha2::{Digest, Sha256};

        let h = harness();
        let repo = insert_repo(&h, "cargo-test"); // sample_repository → Hosted
        let content: &[u8] = b"local-bytes";
        let expected_cksum = format!("{:x}", Sha256::digest(content));
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            content,
            QuarantineStatus::None,
        );

        // Seed the old cache key pattern with garbage. Hosted dispatch must
        // ignore it. The cargo per-crate index cache key is
        // `cargo_index_proj:` (renamed from `cargo_index:`).
        for mapping_id_seed in &["aaaaaaaa", "bbbbbbbb"] {
            let key = format!("cargo_index_proj:{mapping_id_seed}:se/rd/serde");
            h.ctx
                .ephemeral_evictable
                .put(
                    &key,
                    Bytes::from_static(b"poison"),
                    std::time::Duration::from_secs(60),
                )
                .await
                .unwrap();
        }

        let router = router(h.ctx.clone());
        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/se/rd/serde")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 8192).await.unwrap();
        let entry: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&body).unwrap().lines().next().unwrap())
                .unwrap();
        // The entry came from the local artifact, NOT from the poisoned
        // cache row.
        assert_eq!(entry["cksum"].as_str().unwrap(), expected_cksum);
    }

    // -- route precedence regression ------------------------------------------

    /// The PUT publish route `/api/v1/crates/new` must win over the dynamic
    /// 4-plus-char sparse-index route `/:aa/:bb/:crate_name` — axum's
    /// static-segment priority should route the publish request to the
    /// publish handler, not to an index handler that treats `api/v1/crates`
    /// as a crate name (and would then 400 because the body isn't NDJSON).
    #[tokio::test]
    async fn route_precedence_publish_beats_three_segment_index() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let metadata = br#"{"name":"precedence","vers":"1.0.0"}"#;
        let crate_bytes = b"content";
        let body = build_publish_body(metadata, crate_bytes);

        let res = router
            .oneshot(
                Request::put("/cargo/cargo-test/api/v1/crates/new")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // If the request had mis-matched to the index handler (GET-only), we'd
        // get 405. If it matched the download handler (6 segments), we'd get
        // 404 or 405. Publish returns 200 on happy path.
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// A GET to the literal 3-segment path `api/v1/crates` lands on the
    /// sparse-index 4-plus handler (`:aa=api, :bb=v1, :crate_name=crates`)
    /// and returns 404 when no `crates` crate exists — it must NOT match the
    /// publish route and must NOT 500 or succeed with 200.
    #[tokio::test]
    async fn route_precedence_api_v1_crates_without_new_returns_404() {
        let h = harness();
        insert_repo(&h, "cargo-test");
        let router = router(h.ctx.clone());

        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// The download route `/api/v1/crates/{name}/{version}/download` must
    /// win over any dynamic 4-plus match — prove by issuing a GET with a
    /// crate name that happens to be `api` (or similarly collides in the
    /// generic 3-segment pattern) and verifying the download handler is hit.
    #[tokio::test]
    async fn route_precedence_download_path_is_not_mis_routed() {
        let h = harness();
        let repo = insert_repo(&h, "cargo-test");
        insert_crate_artifact(
            &h,
            repo.id,
            "serde",
            "1.0.0",
            b"content",
            QuarantineStatus::None,
        );
        let router = router(h.ctx.clone());

        // Exercises /api/v1/crates/:name/:version/download with 5 path
        // segments after the repo_key. No dynamic 3-segment route could
        // match this, but the test guards against future route additions
        // regressing priority.
        let res = router
            .oneshot(
                Request::get("/cargo/cargo-test/api/v1/crates/serde/1.0.0/download")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // -- authz tests ---------------------------------------------------------
    //
    // Two handler tests (allow + deny). Helpers mirror pypi's `authz`
    // submodule; since `resolve_actor_user_id` + `emit_authz_metric` live
    // in `handlers::pypi`, the pure-helper unit test lives there too.
    // These tests verify cargo's specific handler signature wires the
    // principal through correctly.

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

        // Item 13 — wraps the evaluator in `Arc<ArcSwap<_>>`, matching
        // the pypi/npm helpers. Tests hold a static snapshot reachable
        // via `.load()`; the refresh path is exercised in
        // `hort-server::cli::serve::rbac_refresh`.
        /// Evaluator where the `developer` claim grants global `Write`
        /// (flat `GrantSubject::Claims` grant set per ADR 0012).
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
        /// The `developer` claim matches the [`developer_write_evaluator`]
        /// grant.
        fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
            CallerPrincipal {
                user_id: Uuid::from_u128(0xBEEF),
                external_id: "kc:bob".into(),
                username: "bob".into(),
                email: "bob@example.com".into(),
                claims: claims.iter().map(|s| (*s).to_string()).collect(),
                token_kind: None,
                issued_at: Utc::now(),
                token_cap: None,
            }
        }

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
                    // Cargo tests don't exercise the WWW-Authenticate
                    // selector.
                    issuer_url: None,
                },
            );
            TestHarness {
                ctx,
                artifacts: h.artifacts,
                repositories: h.repositories,
                storage: h.storage,
                curation_rules: h.curation_rules,
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

        async fn put_publish_with_principal(
            ctx: Arc<AppContext>,
            principal: Option<CallerPrincipal>,
        ) -> (StatusCode, Vec<u8>) {
            let router = router(ctx);
            let metadata = br#"{"name":"authz","vers":"1.0.0"}"#;
            let body_bytes = build_publish_body(metadata, b"crate bytes");
            let mut req = Request::put("/cargo/cargo-test/api/v1/crates/new")
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

        #[test]
        fn publish_authorized_principal_proceeds_to_success_path() {
            let (snap, (status, _)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = enabled_harness();
                        insert_repo(&h, "cargo-test");
                        put_publish_with_principal(
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

        #[test]
        fn publish_denied_principal_returns_403() {
            let (snap, (status, body)) = capture(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let h = enabled_harness();
                        insert_repo(&h, "cargo-test");
                        put_publish_with_principal(h.ctx.clone(), Some(principal_with_claims(&[])))
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

    // -- Read-side anti-enumeration (ADR 0008) --------------------------------
    //
    // Mirrors the OCI canary regression test
    // (`anonymous_get_on_private_repo_returns_404_name_unknown` in
    // `crates/hort-http-oci/src/blobs.rs::tests`). Proves that anonymous
    // read paths on a private repo collapse to `404` indistinguishably
    // from a missing-repo response.
    //
    // Two scenarios per route family:
    // 1. Missing repo + anonymous → 404 (baseline, already worked).
    // 2. Private repo + anonymous → 404 (the regression — cargo's
    //    `find_by_key` formerly admitted every read with no visibility
    //    check, so this used to return 200 + index body / config JSON).
    //
    // The sparse-index path is the most attractive enumeration target
    // (lists every version of a crate plus its sha256 cksum), so it's
    // the one we lock down as the canonical regression. `config.json`
    // and `download` are exercised in their own assertions to prove the
    // visibility check was wired on every read site, not just one.

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
            // Construct the access use case from the harness's MockPorts
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
                curation_rules: h.curation_rules,
            }
        }

        fn insert_private_repo(h: &TestHarness, key: &str) -> Repository {
            let mut repo = sample_repository();
            repo.key = key.to_string();
            repo.format = RepositoryFormat::Cargo;
            repo.is_public = false;
            h.repositories.insert(repo.clone());
            repo
        }

        /// Compare two `(StatusCode, Vec<u8>)` 404 responses for
        /// anti-enumeration equivalence: status MUST match and the
        /// JSON envelope shape (`{"error":"not found: Repository
        /// <id>"}`) MUST be identical except for the id token. Per
        /// design doc §5: "Both are the canonical
        /// `not found: Repository <id>` envelope, differing only in
        /// the id token. Format equality is what an operator-side
        /// enumeration probe would observe."
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

        /// Anti-enumeration regression: anonymous GET on a sparse-index
        /// path of a **private** repo MUST return the same 404 envelope
        /// as the missing-repo case. The cargo handler previously reached
        /// `ctx.repositories.find_by_key` directly with no visibility
        /// check, so anonymous callers could enumerate every crate (and
        /// its sha256 cksum) in any private repo whose key they could
        /// guess.
        #[tokio::test]
        async fn anonymous_get_sparse_index_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-cargo");
            // Seed an artifact so the missing-vs-private collapse can't
            // be explained by "no rows match the lookup" — the row
            // exists, only the visibility check rejects it.
            insert_crate_artifact(
                &h,
                repo.id,
                "secret-crate",
                "1.0.0",
                b"secret bytes",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/cargo/private-cargo/se/cr/secret-crate")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous read on private cargo repo MUST be 404 (anti-enumeration)"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/cargo/ghost-cargo/se/cr/secret-crate")
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

        /// Same invariant, on the `config.json` route. Cargo clients
        /// hit this first when bootstrapping a registry; the leak shape
        /// here would be "registry exists, here's its dl/api URL" —
        /// enough to confirm a guessed private repo key.
        #[tokio::test]
        async fn anonymous_get_config_json_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            insert_private_repo(&h, "private-cargo");
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/cargo/private-cargo/config.json")
                        .header("host", "registry.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/cargo/ghost-cargo/config.json")
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

        /// Same invariant, on the `download` route. The leak shape
        /// here would be "the crate doesn't exist in this repo" vs
        /// "this repo doesn't exist" — both must be the same envelope.
        #[tokio::test]
        async fn anonymous_get_download_on_private_repo_returns_404() {
            let h = enabled_rbac_harness();
            let repo = insert_private_repo(&h, "private-cargo");
            insert_crate_artifact(
                &h,
                repo.id,
                "secret-crate",
                "1.0.0",
                b"secret bytes",
                QuarantineStatus::None,
            );
            let router = router(h.ctx.clone());

            let private_resp = router
                .clone()
                .oneshot(
                    Request::get("/cargo/private-cargo/api/v1/crates/secret-crate/1.0.0/download")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                private_resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous download on private cargo repo MUST be 404"
            );
            let private_status = private_resp.status();
            let private_body = to_bytes(private_resp.into_body(), 4 * 1024)
                .await
                .unwrap()
                .to_vec();

            let missing_resp = router
                .oneshot(
                    Request::get("/cargo/ghost-cargo/api/v1/crates/secret-crate/1.0.0/download")
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

    // -- parse_publish_body metadata-length cap --------------------------------
    //
    // The cargo publish frame is `[u32 LE meta_len][meta][u32 LE crate_len][crate]`.
    // `meta_len` is attacker-supplied; if uncapped, an attacker could
    // declare a multi-MiB metadata segment to amplify allocator/parser
    // pressure even though publish metadata in practice is one
    // version's metadata only (structurally comparable to a single
    // sparse-index entry, well under 64 KiB per the per-entry
    // measurements in `crates/measurement-tools/src/cargo.rs`).
    //
    // The cap fires before the slice and the diagnostic carries no
    // input bytes (design-doc §5).

    /// Build a publish frame whose declared `meta_len` is `meta_len_decl`
    /// and whose metadata segment is `meta_len_decl` bytes of ASCII
    /// space — `parse_publish_body` does not parse the metadata, so any
    /// byte sequence of the declared length suffices for boundary
    /// checks. The crate segment is empty.
    fn build_publish_body_with_meta_len(meta_len_decl: u32) -> Vec<u8> {
        let meta_len = meta_len_decl as usize;
        let mut body = Vec::with_capacity(8 + meta_len);
        body.extend_from_slice(&meta_len_decl.to_le_bytes());
        body.extend(std::iter::repeat_n(b' ', meta_len));
        body.extend_from_slice(&0u32.to_le_bytes());
        body
    }

    #[test]
    fn parse_publish_body_accepts_meta_len_one_byte_under_cap() {
        // Just-under-cap meta_len (64 KiB - 1) parses successfully —
        // the slice resolves the metadata segment without firing the
        // PUBLISH_META_CAP gate.
        const PUBLISH_META_CAP: usize = 64 * 1024;
        let meta_len_decl = (PUBLISH_META_CAP - 1) as u32;
        let body = build_publish_body_with_meta_len(meta_len_decl);
        let Ok((metadata, crate_bytes)) = parse_publish_body(&body) else {
            panic!("just-under-cap publish frame must parse");
        };
        assert_eq!(metadata.len(), PUBLISH_META_CAP - 1);
        assert!(crate_bytes.is_empty());
    }

    #[test]
    fn parse_publish_body_rejects_meta_len_one_byte_over_cap() {
        // Just-over-cap meta_len (64 KiB + 1) is rejected by the cap
        // gate before any slice. Diagnostic names the cap (in KB) but
        // does not echo the body bytes.
        const PUBLISH_META_CAP: usize = 64 * 1024;
        let meta_len_decl = (PUBLISH_META_CAP + 1) as u32;
        let body = build_publish_body_with_meta_len(meta_len_decl);
        let Err(api_err) = parse_publish_body(&body) else {
            panic!("just-over-cap publish frame must reject");
        };
        let hort_app::error::AppError::Domain(hort_domain::error::DomainError::Validation(
            domain_msg,
        )) = api_err.0
        else {
            panic!("expected Validation error variant");
        };
        assert!(
            domain_msg.contains("publish metadata exceeds 64 KB cap"),
            "publish-cap diagnostic missing: {domain_msg}"
        );
        // No body bytes echoed — the metadata segment in our test body
        // is all ASCII spaces; the diagnostic must not contain the
        // attacker-supplied byte length verbatim either, so we pin a
        // stricter check: it must not contain the exact `meta_len_decl`
        // string. The 64 KiB cap value (65536 / "64 KB") is fine; the
        // OBSERVED length (65537) is NOT echoed.
        assert!(
            !domain_msg.contains(&meta_len_decl.to_string()),
            "diagnostic must not echo attacker-declared length: {domain_msg}"
        );
    }
}
