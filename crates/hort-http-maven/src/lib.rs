//! Maven / Gradle repository protocol handlers (hosted path).
//!
//! Routes (mounted under `/maven`; the server nests this tree):
//! - `GET  /{repo_key}/*artifact_path` — file / sidecar / metadata download
//! - `HEAD /{repo_key}/*artifact_path` — same, headers only
//! - `PUT  /{repo_key}/*artifact_path` — file / sidecar / metadata deploy
//!
//! A single wildcard-tail route (like OCI's `/v2/*`) captures the whole
//! Maven coordinate path; the handler parses it via
//! [`MavenFormatHandler::parse_download_path`] and dispatches on the
//! path-shape marker (`file` / `metadata_a` / `metadata_v`).
//!
//! ## Scope (Item 6 — HOSTED only)
//!
//! - **PUT** content files → [`IngestUseCase::ingest_direct`] (group
//!   membership forms automatically via the post-commit
//!   `classify_group_member` hook — the handler never calls it). Client
//!   `maven-metadata.xml` and checksum-sidecar PUTs are accepted and
//!   **discarded** (the server regenerates metadata on GET; Item 7
//!   generates sidecars on GET).
//! - **GET/HEAD** content files → exact-path lookup + quarantine gate +
//!   CAS stream. `maven-metadata.xml` → server-generated via the
//!   Source → Filter → Builder pipeline ([`serve`]). Checksum-sidecar GET
//!   → 404 for now (Item 7 wires on-demand generation).
//!
//! On-demand sidecar generation (Item 7) and unresolved-SNAPSHOT
//! resolution + V-level metadata (Item 8) are wired. Pull-through (Item 9)
//! is a later backlog item; its hook points carry `// Item N:` markers.
//!
//! ## Auth
//!
//! Reads are anonymous-by-default — the use-case visibility filter
//! (`find_visible_by_path` / `list_by_raw_name_visible`) is the ONLY read
//! authz gate; a Read denial collapses to 404 (anti-enumeration). Writes
//! go through the global `require_principal` middleware (PUT is a non-safe
//! method) + the `resolve_actor_user_id` Write authz gate.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::handler::Handler;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::Utc;

use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryFormat, RepositoryType};
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::ArtifactCoords;
use hort_formats::maven::coords::{self, MAVEN_KIND_METADATA_A, MAVEN_KIND_METADATA_V};
use hort_formats::maven::MavenFormatHandler;

use hort_http_core::authz::write::{reject_write_to_virtual, resolve_actor_user_id};
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::limits::{BoundedPath, DEFAULT_PUBLISH_BODY_LIMIT};
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

pub(crate) mod serve;
pub(crate) mod sidecar;

// Upstream pull-through orchestrator (Item 9, design §8, ADR 0033). Wired to
// the read path in `serve_file`: a Proxy-repo cache miss on an artifact FILE
// routes here for the `.sha512`→`.sha256`→`.sha1` verified pull. Declared
// here so the module + its tests are reachable under
// `cargo test -p hort-http-maven`.
pub(crate) mod upstream_pull;

use serve::MetadataLevel;

/// Build the Maven route tree (GET / HEAD / PUT on a wildcard tail).
///
/// PUT carries the shared publish body limit
/// ([`DEFAULT_PUBLISH_BODY_LIMIT`] — 300 MiB) so a large `.jar` is not
/// rejected by axum's default 2 MiB ceiling. The server mounts this tree
/// under `/maven`.
pub fn maven_routes() -> Router<Arc<AppContext>> {
    Router::new().route(
        "/:repo_key/*artifact_path",
        get(download)
            .head(download)
            .put(upload.layer(DefaultBodyLimit::max(DEFAULT_PUBLISH_BODY_LIMIT))),
    )
}

/// Resolve the repo for a Maven request and confirm it is a Maven- or
/// Gradle-format repo. Returns the same `NotFound` 404 envelope for a
/// wrong-format repo as for a missing/invisible one — a Maven client
/// hitting a non-Maven repo key sees "not here", never a format oracle
/// (mirrors how the other format mounts treat a wrong-format repo).
///
/// `actor` is threaded so a Read denial on a private repo collapses to the
/// same 404 (anti-enumeration).
async fn resolve_maven_repo(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Repository, ApiError> {
    let repo = ctx
        .repository_access_use_case
        .resolve(repo_key, actor, AccessLevel::Read)
        .await?;
    if !matches!(
        repo.format,
        RepositoryFormat::Maven | RepositoryFormat::Gradle
    ) {
        return Err(ApiError::from(hort_app::error::AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Repository",
                id: repo_key.to_string(),
            },
        )));
    }
    Ok(repo)
}

// ---------------------------------------------------------------------------
// GET / HEAD /{repo_key}/*artifact_path
// ---------------------------------------------------------------------------

async fn download(
    State(ctx): State<Arc<AppContext>>,
    method: axum::http::Method,
    BoundedPath((repo_key, artifact_path)): BoundedPath<(String, String)>,
    // GET/HEAD route through `extract_optional_principal`'s
    // `Option<AuthenticatedPrincipal>` slot (anonymous is allowed); the
    // outer `Option` tolerates the no-auth-layer case (unit tests that
    // inject neither slot) → anonymous.
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Result<Response, ApiError> {
    let actor = principal
        .as_deref()
        .and_then(|opt| opt.as_ref())
        .map(AuthenticatedPrincipal::as_caller);

    // Parse + per-format grammar validation BEFORE any lookup. A grammar
    // violation maps to 400 `maven.coordinate:` (design §17), never echoing
    // bytes; the parser already runs `validate_maven_coordinate` internally.
    let coords = MavenFormatHandler.parse_download_path(&artifact_path)?;

    // Resolve + format-gate the repo (404 on missing/invisible/wrong-format).
    let repo = resolve_maven_repo(&ctx, &repo_key, actor).await?;

    let is_head = method == axum::http::Method::HEAD;

    // A metadata path can itself carry a sidecar extension
    // (`maven-metadata.xml.sha1`, both A-level and V-level). The metadata
    // marker is set whether or not the trailing `.{ext}` is present (the
    // parser strips it to detect `maven-metadata.xml`), so detect the
    // sidecar here and digest the SERVER-GENERATED XML bytes rather than
    // serving the document.
    let metadata_sidecar_algo = metadata_sidecar_algorithm(&artifact_path);

    match coords::path_kind(&coords) {
        Some(MAVEN_KIND_METADATA_A) => {
            serve_metadata_maybe_sidecar(
                &ctx,
                &repo,
                &coords.name,
                MetadataLevel::Artifact,
                None,
                metadata_sidecar_algo,
                is_head,
                actor,
            )
            .await
        }
        Some(MAVEN_KIND_METADATA_V) => {
            serve_metadata_maybe_sidecar(
                &ctx,
                &repo,
                &coords.name,
                MetadataLevel::Snapshot,
                coords.version.as_deref(),
                metadata_sidecar_algo,
                is_head,
                actor,
            )
            .await
        }
        // file shape (the default marker) — a real file or its sidecar.
        _ => serve_file(&ctx, &repo, &coords, &artifact_path, is_head, actor).await,
    }
}

/// If the request tail's last segment is `maven-metadata.xml.{ext}`
/// (a metadata-checksum sidecar), return the sidecar algorithm token;
/// otherwise `None` (a plain `maven-metadata.xml` GET).
fn metadata_sidecar_algorithm(artifact_path: &str) -> Option<&str> {
    let last = artifact_path.rsplit('/').next().unwrap_or(artifact_path);
    let (base, ext) = coords::strip_sidecar_ext(last);
    if base == coords::MAVEN_METADATA_FILENAME {
        ext
    } else {
        None
    }
}

/// Serve a `maven-metadata.xml` GET, or — when `sidecar_algo` is `Some` —
/// the on-demand checksum sidecar over the SAME generated bytes (design
/// §6). The metadata bytes are built once via [`serve::build_metadata_bytes`]
/// (which enforces the same anti-enumeration + unknown-artifact 404 as the
/// plain GET); the sidecar branch then digests those exact bytes.
#[allow(clippy::too_many_arguments)]
async fn serve_metadata_maybe_sidecar(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    level: MetadataLevel,
    version: Option<&str>,
    sidecar_algo: Option<&str>,
    is_head: bool,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    match sidecar_algo {
        Some(algo) => {
            let xml = serve::build_metadata_bytes(ctx, repo, name, level, version, actor).await?;
            sidecar::serve_metadata_sidecar(&xml, algo, is_head)
        }
        None => serve::serve_metadata(ctx, repo, name, level, version, actor)
            .await
            .map(|r| strip_body_if_head(r, is_head)),
    }
}

/// Serve a Maven artifact file, or its on-demand checksum sidecar, by
/// exact stored path.
///
/// A sidecar GET (`<file>.{sha1,sha256,sha512,md5}`) resolves the SAME
/// target file and applies the SAME status gate, then returns the digest
/// of the stored bytes: `.sha256` is the CAS `ContentHash` (free);
/// `.sha1`/`.sha512`/`.md5` stream the blob through the hasher, memoised in
/// the Evictable `mavensum:` keyspace ([`sidecar`]). A held target's
/// sidecar inherits its file's 503 / 403 — the digest is never computed.
///
/// For a real file: `find_visible_by_path` → quarantine gate → CAS stream.
/// A miss → 404 (hosted; pull-through is Item 9). The caller is threaded
/// for anti-enumeration: missing repo, invisible repo, and missing path
/// all collapse to the same `NotFound` envelope.
async fn serve_file(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    coords: &ArtifactCoords,
    artifact_path: &str,
    is_head: bool,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // A `<file>.{sha1,sha256,sha512,md5}` sidecar request → the digest of
    // the stored `<file>`, computed on demand (design §6). The base path is
    // the request tail with the sidecar extension stripped from the
    // filename; the parser already validated the whole tail (the file-shape
    // branch runs on the sidecar's base coords).
    let filename = artifact_path.rsplit('/').next().unwrap_or(artifact_path);
    if let (base_filename, Some(algorithm)) = coords::strip_sidecar_ext(filename) {
        // Rebuild the base path: replace the final filename segment with
        // its sidecar-stripped form.
        let base_path = match artifact_path.rsplit_once('/') {
            Some((dir, _last)) => format!("{dir}/{base_filename}"),
            None => base_filename.to_string(),
        };
        return sidecar::serve_sidecar(ctx, repo, &base_path, algorithm, is_head, actor).await;
    }

    // An unresolved `foo-X-SNAPSHOT.jar` GET resolves via
    // `resolve_mutable_version` to the latest timestamped build BEFORE the
    // exact-path lookup: a `mvn deploy` stores only the timestamped files
    // (`foo-X-{ts}-N.jar`), so the literal `-SNAPSHOT` filename has no stored
    // row. Resolution gathers the base version's stored timestamped paths and
    // picks the highest `(timestamp, buildNumber)` build matching the
    // requested `(classifier, extension)`. On a match we serve THAT concrete
    // path through the normal exact-path lookup + quarantine gate (so a
    // resolved-but-held build still 503s / 403s). On no match we fall through
    // to the exact-path lookup (which 404s unless a literal `-SNAPSHOT`-named
    // file was stored, e.g. a non-Maven-3 deploy) (design §7).
    let resolved_path =
        resolve_unresolved_snapshot(ctx, repo, coords, artifact_path, actor).await?;
    let lookup_path = resolved_path.as_deref().unwrap_or(artifact_path);

    // A hosted CAS hit serves straight from local storage. On a miss, a
    // `RepositoryType::Proxy` repo routes the FILE request through the
    // verified upstream pull (Item 9, design §8); every other type stays a
    // 404. The `entity` discriminator inside `find_visible_by_path`'s
    // `NotFound` separates "repo missing/invisible" (`"Repository"` —
    // propagate 404 immediately, no upstream side-effect) from "repo visible,
    // path missing" (`"Artifact"` — the proxy branch). Mirrors the cargo
    // dispatch precisely.
    match ctx
        .artifact_use_case
        .find_visible_by_path(&repo.key, lookup_path, actor)
        .await
    {
        Ok((_repo, artifact)) => render_file_response(ctx, artifact, is_head, actor).await,
        Err(hort_app::error::AppError::Domain(hort_domain::error::DomainError::NotFound {
            entity: "Artifact",
            ..
        })) if matches!(repo.repo_type, RepositoryType::Proxy) => {
            // Pull-through applies to artifact FILES only — metadata / sidecar
            // GETs stay server-generated (handled before `serve_file`), so by
            // the time control reaches here the request is a real file. A
            // resolved-but-unresolved SNAPSHOT request whose timestamped form
            // is absent locally pulls the literal requested path (Maven
            // Central serves SNAPSHOT files by their timestamped name; an
            // unresolved `-SNAPSHOT` request only reaches here when no
            // timestamped build was found locally, in which case the literal
            // path is what the upstream is asked for).
            let pull_path = lookup_path;
            match upstream_pull::try_upstream_maven_pull(ctx, repo, coords, pull_path).await {
                // Serve the freshly-ingested artifact through the SAME
                // quarantine gate + streaming tail — a pulled artifact may be
                // quarantined (→ 503 + Retry-After).
                Ok(artifact) => render_file_response(ctx, artifact, is_head, actor).await,
                Err(e) => Ok(upstream_pull::map_upstream_pull_error(&e)),
            }
        }
        Err(other) => Err(other.into()),
    }
}

/// Resolve an unresolved base-`-SNAPSHOT` file request to the concrete
/// stored timestamped path, or `None` when the request is not an unresolved
/// snapshot (already concrete / non-snapshot) or no build matches.
///
/// Only runs the (extra) group load when the request filename actually
/// carries the literal `-SNAPSHOT` token — a release / already-timestamped
/// path skips the load entirely and falls straight through to the exact-path
/// lookup. The available timestamped paths come from
/// [`ArtifactUseCase::list_by_raw_name_visible`] (the same drift-resilient,
/// caller-threaded read the metadata source uses — a Read denial / missing
/// repo collapses to the same `NotFound`), filtered to the requested base
/// version.
async fn resolve_unresolved_snapshot(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    coords: &ArtifactCoords,
    artifact_path: &str,
    actor: Option<&CallerPrincipal>,
) -> Result<Option<String>, ApiError> {
    // Cheap pre-filter: only a request whose version segment is a base
    // `X-SNAPSHOT` AND whose filename carries the literal `-SNAPSHOT` token
    // can be an unresolved snapshot. (A timestamped file's version segment is
    // still `X-SNAPSHOT` but its filename carries the timestamp, not the
    // literal token — `resolve_mutable_version` would return `None` for it
    // anyway; this guard just avoids the group load.)
    let Some(version) = coords.version.as_deref() else {
        return Ok(None);
    };
    if !version.ends_with("-SNAPSHOT") {
        return Ok(None);
    }
    let filename = artifact_path.rsplit('/').next().unwrap_or(artifact_path);
    if !filename.contains("-SNAPSHOT") {
        return Ok(None);
    }

    // Gather the stored timestamped paths for this `group:artifact`,
    // filtered to the requested base version. Same read entry point as the
    // metadata source (anti-enumeration: a Read denial collapses to 404).
    let (_resolved_repo, artifact_list) = ctx
        .artifact_use_case
        .list_by_raw_name_visible(&repo.key, &MavenFormatHandler, &coords.name, actor)
        .await?;
    let available: Vec<String> = artifact_list
        .items
        .into_iter()
        .filter(|a| a.version.as_deref() == Some(version))
        .map(|a| a.path)
        .collect();
    let available_refs: Vec<&str> = available.iter().map(String::as_str).collect();

    Ok(MavenFormatHandler.resolve_mutable_version(artifact_path, &available_refs)?)
}

/// Surface the per-artifact status gate as the non-servable HTTP response
/// (`Quarantined` → 503 + `Retry-After`; `Rejected` → 403;
/// `ScanIndeterminate` → 403), or `None` when the artifact is servable
/// (`Released` / `None`). Shared by the file GET ([`render_file_response`])
/// and the checksum-sidecar GET ([`sidecar::serve_sidecar`]) so a sidecar
/// inherits its target file's exact status response (design §11) — a
/// quarantined file and its sidecar both 503, a rejected file and its
/// sidecar both 403, and the digest of a held version is never computed.
pub(crate) fn non_servable_response(
    artifact: &hort_domain::entities::artifact::Artifact,
) -> Option<Response> {
    match artifact.quarantine_status {
        QuarantineStatus::Quarantined => {
            // The use-case layer hydrates the transient computed
            // `quarantine_deadline` (ADR 0007); the format crate never
            // computes it. 503 + Retry-After — NEVER 409 (proxies cache it).
            let retry_after = artifact
                .quarantine_deadline
                .map(|deadline| {
                    let secs = (deadline - Utc::now()).num_seconds().max(1);
                    secs.to_string()
                })
                .unwrap_or_else(|| "3600".to_string());
            Some(
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Retry-After", retry_after)
                    .body(Body::from(
                        serde_json::json!({"error": "artifact is quarantined"}).to_string(),
                    ))
                    .unwrap(),
            )
        }
        QuarantineStatus::Rejected => Some(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    serde_json::json!({"error": "artifact is rejected"}).to_string(),
                ))
                .unwrap(),
        ),
        QuarantineStatus::ScanIndeterminate => Some(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    serde_json::json!({"error": "artifact scan is indeterminate"}).to_string(),
                ))
                .unwrap(),
        ),
        QuarantineStatus::None | QuarantineStatus::Released => None,
    }
}

/// Render the final file HTTP response: surface the quarantine gate via
/// [`non_servable_response`] or stream the bytes from CAS (design §11 /
/// §17). On a HEAD the status + headers are identical to GET but the body
/// is dropped.
async fn render_file_response(
    ctx: &Arc<AppContext>,
    artifact: hort_domain::entities::artifact::Artifact,
    is_head: bool,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    if let Some(blocked) = non_servable_response(&artifact) {
        return Ok(blocked);
    }

    let content_type: axum::http::HeaderValue = artifact
        .content_type
        .parse()
        .unwrap_or_else(|_| "application/octet-stream".parse().unwrap());
    let size_bytes = artifact.size_bytes;

    let mut out_headers = HeaderMap::new();
    out_headers.insert(CONTENT_TYPE, content_type);
    // Always emit Content-Length — even for zero-byte artifacts — so a
    // mid-stream integrity failure cannot terminate as a normal chunked
    // end (mirrors the cargo / OCI precedent).
    out_headers.insert(CONTENT_LENGTH, size_bytes.into());

    if is_head {
        // HEAD: identical status + headers, empty body. No CAS read.
        return Ok((StatusCode::OK, out_headers, Body::empty()).into_response());
    }

    // Thread the resolved principal for opt-in download-audit attribution;
    // the caller already proved Read via `find_visible_by_path`.
    let (_artifact, stream) = ctx.artifact_use_case.download(artifact.id, actor).await?;
    let body = stream_blob(stream, DEFAULT_STREAM_CAPACITY);
    Ok((StatusCode::OK, out_headers, body).into_response())
}

/// Drop the body of an already-built response for a HEAD request, keeping
/// the status + headers byte-identical (used for the metadata serve path,
/// whose builder always produces a full body).
fn strip_body_if_head(resp: Response, is_head: bool) -> Response {
    if !is_head {
        return resp;
    }
    let (parts, _body) = resp.into_parts();
    Response::from_parts(parts, Body::empty())
}

// ---------------------------------------------------------------------------
// PUT /{repo_key}/*artifact_path
// ---------------------------------------------------------------------------

async fn upload(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, artifact_path)): BoundedPath<(String, String)>,
    // PUT is a non-safe method → routed through `require_principal`, which
    // writes the bare `AuthenticatedPrincipal` slot. The outer `Option`
    // tolerates the no-auth-layer case (auth-disabled fixtures).
    principal: Option<Extension<AuthenticatedPrincipal>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    // Own a `CallerPrincipal` for the read-side hops (anti-enumeration
    // resolve, pre-existence check, audit attribution) — `principal` itself
    // is moved into `resolve_actor_user_id` below for the Write authz gate.
    let actor_owned: Option<CallerPrincipal> = principal.as_deref().map(|p| p.as_caller().clone());
    let actor = actor_owned.as_ref();

    // Parse + per-format grammar validation BEFORE any persistence side
    // effect (design §5 / §17): a grammar violation maps to 400
    // `maven.coordinate:`, never echoing bytes. The parser runs
    // `validate_maven_coordinate` internally.
    let coords = MavenFormatHandler.parse_download_path(&artifact_path)?;

    // Resolve + format-gate the repo (Read level for anti-enumeration; the
    // Write authz gate is `resolve_actor_user_id` below, which keeps the
    // stable 403 deny envelope).
    let repo = resolve_maven_repo(&ctx, &repo_key, actor).await?;

    // Gate write on authorization. `resolve_actor_user_id` returns a
    // pre-shaped 403 Response on deny (`{"error":"insufficient
    // permissions"}`) and 401 when no principal is present.
    let actor_user_id = match resolve_actor_user_id(&ctx, principal, repo.id) {
        Ok(id) => id,
        Err(response) => return Ok(*response),
    };

    // Read-only aggregator (ADR 0031): reject a publish to a virtual repo.
    // After the authz gate so a caller without Write still sees the stable
    // 403, not a repo-type oracle.
    reject_write_to_virtual(&repo)?;

    // maven-metadata.xml and checksum sidecars are ACCEPTED and DISCARDED
    // (design §6 / §17): the server regenerates metadata on GET (a
    // client copy could advertise quarantined versions) and generates
    // sidecars on GET (Item 7). Returning 200 keeps Maven clients happy —
    // they PUT these as part of a deploy and expect a success.
    match coords::path_kind(&coords) {
        Some(MAVEN_KIND_METADATA_A) | Some(MAVEN_KIND_METADATA_V) => {
            return Ok(StatusCode::OK.into_response());
        }
        _ => {}
    }
    // A checksum-sidecar PUT (file shape, sidecar extension) is likewise
    // accepted-and-discarded.
    let filename = artifact_path.rsplit('/').next().unwrap_or(&artifact_path);
    if coords::strip_sidecar_ext(filename).1.is_some() {
        return Ok(StatusCode::OK.into_response());
    }

    // A real content file → ingest_direct. The coords already carry the
    // stored logical path (= the request tail) and the GA:V identity from
    // the parser; content files become group members via the post-commit
    // `classify_group_member` hook inside IngestUseCase (the handler never
    // calls classify itself).
    let ingest_coords = ArtifactCoords {
        name: coords.name.clone(),
        name_as_published: coords.name_as_published.clone(),
        version: coords.version.clone(),
        path: coords.path.clone(),
        format: repo.format.clone(),
        // The path-shape marker is request-routing scaffolding, not
        // persisted artifact metadata — clear it for the stored row.
        metadata: serde_json::Value::Null,
    };

    // New vs re-deploy (design §17): a new path is 201 Created; re-PUTting
    // an existing path (a mutable SNAPSHOT redeploy) is 200. `IngestOutcome`
    // does not expose the created/duplicate bit, so detect existence with a
    // cheap repo-scoped path lookup before ingest. The window between this
    // check and the commit is benign — a concurrent first-writer at worst
    // shifts a 201 to a 200 (both are success; Maven clients accept either).
    let preexisting = ctx
        .artifact_use_case
        .find_visible_by_path(&repo.key, &artifact_path, actor)
        .await
        .is_ok();

    let content_type = content_type_for(filename);
    // `body` is already an owned `Bytes`; `Bytes: AsRef<[u8]> + Unpin`, so
    // `Cursor<Bytes>` satisfies the `AsyncRead + Send + Unpin` bound without a
    // second full-body copy (`to_vec()` would clone up to the 300 MiB cap).
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(std::io::Cursor::new(body));
    let actor = ApiActor {
        user_id: actor_user_id,
    };

    ctx.ingest_use_case
        .ingest_direct(
            hort_app::use_cases::ingest_use_case::DirectIngestRequest {
                repository_id: repo.id,
                coords: ingest_coords,
                content_type,
                actor,
                // Maven sidecars are server-generated on demand (Item 7);
                // nothing is precomputed at ingest. CAS key is SHA-256.
                legacy_sha1: None,
                legacy_md5: None,
                payload_metadata: serde_json::Value::Null,
            },
            stream,
            &MavenFormatHandler,
        )
        .await?;

    let status = if preexisting {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(status.into_response())
}

/// Best-effort `Content-Type` for a Maven filename by extension. Maven
/// clients do not rely on the stored content-type (they fetch by exact
/// path), so this is a sensible default, not a contract.
///
/// Shared with the upstream pull-through path
/// ([`upstream_pull`](crate::upstream_pull)) so a proxied artifact stores the
/// same content-type a directly-deployed one would.
pub(crate) fn content_type_for(filename: &str) -> String {
    let lower = filename.to_ascii_lowercase();
    let ct = if lower.ends_with(".jar") || lower.ends_with(".war") || lower.ends_with(".ear") {
        "application/java-archive"
    } else if lower.ends_with(".pom") || lower.ends_with(".xml") {
        "application/xml"
    } else if lower.ends_with(".module") || lower.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    };
    ct.to_string()
}

#[cfg(test)]
mod tests;
