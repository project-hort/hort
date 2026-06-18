//! OCI Distribution Spec v1.1 handlers.
//!
//! Routes are mounted under `/v2` by [`crate::router::build_router`].
//!
//! # Route map
//!
//! | Method | Path |
//! |---|---|
//! | `GET` | `/v2/` |
//! | `GET` / `HEAD` | `/v2/<name>/blobs/<digest>` |
//! | `HEAD` / `GET` | `/v2/<name>/manifests/<ref>` |
//! | `GET` | `/v2/<name>/tags/list` |
//! | `GET` | `/v2/_catalog` |
//! | `POST` / `PATCH` / `PUT` | `/v2/<name>/blobs/uploads/…` |
//! | `GET` | `/v2/<name>/referrers/<digest>` |

use std::sync::Arc;

use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Router;

use hort_domain::entities::caller::CallerPrincipal;
use hort_http_core::context::AppContext;
use hort_http_core::limits::BoundedPath;

pub mod blobs;
pub mod catalog;
pub mod config;
pub mod coords;
pub(crate) mod digest;
pub mod error;
pub mod manifests;
pub mod manifests_write;
pub mod middleware;
pub(crate) mod name;
// OCI `OnDistTagMove` prefetch + the guardrail asserting
// `IndexMode::ReleasedOnly` does NOT apply to OCI.
// Intentionally `pub(crate)`: the trigger fires from
// `manifests::try_upstream_manifest_pull_by_tag` and is not part of the
// crate's public API.
pub(crate) mod prefetch;
pub(crate) mod quarantine;
pub mod referrers;
pub(crate) mod tag;
pub mod tags;
pub(crate) mod tail;
pub mod upload_session;
pub mod uploads;
// Distribution-Spec `/v2/auth` token-exchange handler + the
// `path_to_scope` helper consumed by the challenge middleware (ADR 0012).
pub mod v2_auth;
pub mod version;

pub use config::OciHttpConfig;
pub use error::OciError;

/// Build a `HeaderValue` from a string that should be ASCII, falling
/// back to a graceful 400 response on a bytes-out-of-range failure
/// (CRLF-injection guard).
///
/// Several response builders construct `Location` headers from URL
/// captures (`repo_key`, `name`) interpolated into a path template. The
/// captures come from axum's wildcard route — they are NOT validated
/// for control bytes at the routing layer, so a CRLF in the capture
/// reaches `HeaderValue::from_str`, which rejects it. Without this
/// guard those call sites used `.expect("ASCII by construction")`,
/// turning a malicious-input edge case into an axum panic boundary
/// catch and HTTP 500. That is a denial-of-service primitive: the
/// panic is recoverable per-request but emits an `INTERNAL_SERVER_ERROR`
/// instead of the spec-defined 4xx.
///
/// On success returns the parsed `HeaderValue`. On failure returns the
/// already-rendered OCI error envelope (`NAME_UNKNOWN`, 404) — the
/// closest semantic match for "the captured name segment is not a
/// valid registry path component". The error is boxed (per
/// `clippy::result_large_err`) so the helper stays cheap on the hot
/// path. Callers use `match` to short-circuit the response builder.
pub(crate) fn header_value_or_bad_request(s: &str) -> Result<HeaderValue, Box<Response>> {
    HeaderValue::from_str(s).map_err(|_| {
        // `s` may contain attacker-controlled bytes; do not echo it
        // into the error envelope. The wire body uses the canonical
        // `NAME_UNKNOWN` shape; the warn line carries only the
        // (untrusted-input-derived) byte length.
        tracing::warn!(
            byte_len = s.len(),
            "OCI header value rejected (non-ASCII / control bytes in URL capture)",
        );
        Box::new(
            OciError::NameUnknown {
                repository: "<invalid>".into(),
            }
            .into_response(),
        )
    })
}

/// Map a [`name::validate_oci_name`] failure to the OCI error envelope.
///
/// The validator returns
/// [`DomainError::Validation`](hort_domain::error::DomainError::Validation)
/// carrying a structured `oci.name: <reason>` message; we extract that
/// message verbatim into [`OciError::NameInvalid`] so the wire envelope
/// surfaces the deterministic reason without re-shaping it. Other
/// `DomainError` variants are not produced by this code path — the
/// validator returns `Validation` exclusively — but we map them
/// defensively to `OciError::Internal` so a future change can't smuggle
/// an unrelated failure shape through.
///
/// `pub(crate)` because every handler that calls `validate_oci_name`
/// uses this mapping; centralising it keeps the response shape
/// single-sourced.
pub(crate) fn name_invalid_response(err: hort_domain::error::DomainError) -> Response {
    match err {
        hort_domain::error::DomainError::Validation(message) => {
            OciError::NameInvalid { message }.into_response()
        }
        // Defence in depth — the validator never returns these
        // variants today. If a future change introduces e.g.
        // a `Forbidden` shape, surface it as `Internal` rather than
        // silently mapping it onto `NameInvalid` (which would
        // misrepresent the failure on the wire).
        other => {
            tracing::error!(error = %other, "OCI name validator returned non-Validation error");
            OciError::Internal.into_response()
        }
    }
}

/// Map a [`crate::tag::validate_oci_tag`] rejection to the OCI handler
/// response — the tag-grammar sibling of [`name_invalid_response`] (INJ-4).
/// A `Validation` error becomes 400 `MANIFEST_INVALID` carrying the
/// deterministic `oci.tag:` reason (which never echoes the offending bytes —
/// see `tag.rs`); any other shape (the validator never returns one today)
/// surfaces as `Internal` rather than being silently treated as a valid tag.
/// Shared by the manifest GET / PUT / DELETE tag branches so the reject
/// shape is identical across all three.
pub(crate) fn tag_invalid_response(err: hort_domain::error::DomainError) -> Response {
    match err {
        hort_domain::error::DomainError::Validation(reason) => OciError::ManifestInvalid {
            detail: Some(serde_json::json!({ "reason": reason })),
        }
        .into_response(),
        other => {
            tracing::error!(error = %other, "OCI tag validator returned non-Validation error");
            OciError::Internal.into_response()
        }
    }
}

/// Combined query-string struct for the `/v2/:repo_key/*tail` GET
/// dispatcher. Carries both `tags::PageQuery` fields (`n`, `last` —
/// used by the tags-list branch) and `referrers::ReferrersQuery`
/// fields (`artifactType` — used by the referrers branch). `serde`
/// silently drops unknown fields on each branch's downstream parse,
/// so a tags-list request that sets `artifactType=` does NOT confuse
/// the tags handler and vice versa.
#[derive(Debug, Default, serde::Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub n: Option<u32>,
    #[serde(default)]
    pub last: Option<String>,
    /// Referrers-API filter. Absent → no filter.
    #[serde(default, rename = "artifactType")]
    pub artifact_type: Option<String>,
}

/// Dispatch a `GET /v2/:repo_key/*tail` to the right serve function.
///
/// The wildcard route captures everything after `:repo_key/` as a
/// single string; we parse it here via [`tail::parse_tail`] and hand
/// the already-split pieces to [`blobs::serve`] / [`manifests::serve`]
/// / [`tags::serve`] / [`referrers::serve`].
///
/// Extracts the `Option<CallerPrincipal>` inserted by
/// [`middleware::oci_auth::oci_bearer_auth`] from the request extensions
/// and forwards it to every serve function so `RepositoryAccessUseCase` /
/// `ArtifactUseCase::find_visible_*` can apply Read-side authz (ADR 0008).
/// The auth layer itself is unchanged; this dispatcher is the seam where
/// extension → typed `actor` parameter happens.
pub async fn get_pull(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, path)): BoundedPath<(String, String)>,
    Query(query): Query<PullQuery>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let actor = extract_actor(&request);
    dispatch(
        ctx,
        &repo_key,
        &path,
        query,
        &headers,
        /* head = */ false,
        actor.as_ref(),
    )
    .await
}

/// `HEAD` counterpart of [`get_pull`]. Same dispatch, same serve
/// functions — the `head = true` bit flips on the serve side so the
/// response body is empty while headers stay bit-identical to `GET`.
pub async fn head_pull(
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, path)): BoundedPath<(String, String)>,
    Query(query): Query<PullQuery>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let actor = extract_actor(&request);
    dispatch(
        ctx,
        &repo_key,
        &path,
        query,
        &headers,
        /* head = */ true,
        actor.as_ref(),
    )
    .await
}

/// Extract the `Option<AuthenticatedPrincipal>` inserted by the OCI
/// bearer middleware and unwrap to the wrapped [`CallerPrincipal`].
/// Absent extension (which can only happen if the middleware was bypassed
/// — e.g. the in-crate test harness driving `dispatch` directly without
/// wiring auth) collapses to `None`, matching anonymous semantics. The
/// bare-`CallerPrincipal` slot is not consulted.
fn extract_actor(request: &Request) -> Option<CallerPrincipal> {
    request
        .extensions()
        .get::<Option<hort_http_core::middleware::auth::AuthenticatedPrincipal>>()
        .cloned()
        .flatten()
        .map(hort_http_core::middleware::auth::AuthenticatedPrincipal::into_caller)
}

async fn dispatch(
    ctx: Arc<AppContext>,
    repo_key: &str,
    tail_str: &str,
    query: PullQuery,
    headers: &HeaderMap,
    head: bool,
    actor: Option<&CallerPrincipal>,
) -> Response {
    // Every branch validates the tail-extracted `name` against the OCI
    // Distribution Spec name grammar BEFORE any side effect (storage
    // lookup, ref query, metric emission). The `*tail` capture is bounded
    // to 512 bytes by `BoundedPath`; this validator additionally pins the
    // spec grammar + a 256-byte cap on the parsed `name` segment + the
    // 8-component cap.
    //
    // Match-arm-local invocation (rather than at the dispatch head)
    // because the unparsed `*tail` includes the `/blobs/<digest>`,
    // `/manifests/<ref>`, etc. suffixes — those are rejected by
    // `parse_tail`, not by `validate_oci_name`. Validating the
    // already-parsed `name` keeps the grammar check on the canonical
    // shape.
    match tail::parse_tail(tail_str) {
        Some(tail::TailKind::Blob { name, digest_str }) => {
            if let Err(e) = name::validate_oci_name(name) {
                return name_invalid_response(e);
            }
            blobs::serve(ctx, repo_key, name, digest_str, headers, head, actor).await
        }
        Some(tail::TailKind::Manifest { name, reference }) => {
            if let Err(e) = name::validate_oci_name(name) {
                return name_invalid_response(e);
            }
            manifests::serve(ctx, repo_key, name, reference, headers, head, actor).await
        }
        Some(tail::TailKind::TagsList { name }) => {
            if let Err(e) = name::validate_oci_name(name) {
                return name_invalid_response(e);
            }
            // Tags list is GET-only by spec; `head=true` dispatches
            // here anyway — we serve the full body and let axum's
            // automatic HEAD handling strip it, matching Docker
            // Registry V2 practice.
            let page_query = tags::PageQuery {
                n: query.n,
                last: query.last,
            };
            tags::serve(ctx, repo_key, name, page_query, actor).await
        }
        Some(tail::TailKind::Referrers { name, digest_str }) => {
            if let Err(e) = name::validate_oci_name(name) {
                return name_invalid_response(e);
            }
            // Referrers is GET-only per spec; on HEAD axum strips the
            // body and the response stays a valid 200 with the OCI
            // image-index Content-Type.
            referrers::serve(
                ctx,
                repo_key,
                name,
                digest_str,
                query.artifact_type.as_deref(),
                actor,
            )
            .await
        }
        None => OciError::NameUnknown {
            repository: format!("{repo_key}/{tail_str}"),
        }
        .into_response(),
    }
}

/// Build the OCI Distribution route tree.
///
/// Merged (not nested) into the top-level router by
/// [`crate::router::build_router`] so that the spec-mandated `GET /v2/`
/// probe can live on an absolute path. In axum 0.7 a `Router::nest`
/// refuses to carry a route at `/` (see `Invalid route "/"` panic in
/// axum-0.7's `nest` tests) — `/v2/` must therefore be registered at
/// the outer level rather than under a nest.
///
/// Subsequent OCI routes (blobs, manifests, tags, catalog, referrers)
/// are added via `route("/v2/<...>")` inside this builder as they
/// land. The builder's signature stays stable; only the body changes.
pub fn oci_routes(ctx: Arc<AppContext>) -> Router<Arc<AppContext>> {
    oci_routes_with_config(&OciHttpConfig::default(), ctx)
}

/// Build the OCI route tree with an explicit configuration.
///
/// `hort-server` calls this with an [`OciHttpConfig`] populated from
/// environment variables (see `OciHttpConfig` field docstrings for
/// the var names). The legacy-catalog flag conditionally registers
/// the global `/v2/_catalog` endpoint; the modern per-repo
/// `/v2/:repo_key/_catalog` is always mounted.
///
/// Route specificity matters: axum dispatches the most specific
/// route first. Literal routes (`/v2/`, `/v2/_catalog`,
/// `/v2/:repo_key/_catalog`) take precedence over the wildcard
/// `/v2/:repo_key/*tail`, so `GET /v2/myrepo/_catalog` reaches the
/// catalog handler rather than being parsed as a tail.
///
/// `ctx` is captured by the OCI bearer-auth layer (ADR 0012; the JWT
/// verifier needs `ctx.jwt_signer`). The router's state parameter
/// (`Arc<AppContext>`) is independently resolved at merge-time by the
/// outer router; we do NOT call `with_state` here — the outer
/// composition root keeps that responsibility.
pub fn oci_routes_with_config(
    config: &OciHttpConfig,
    ctx: Arc<AppContext>,
) -> Router<Arc<AppContext>> {
    // Split the OCI route tree into two sub-routers so the upload-write
    // surface can opt out of the global 5-minute request deadline.
    //
    // - `upload_router` carries POST / PATCH / PUT on
    //   `/v2/:repo_key/*tail`. POST and PATCH always target the
    //   `/blobs/uploads/...` family; PUT is dispatched at runtime
    //   between manifest writes and upload finalize via
    //   [`put_dispatch`]. Both branches get the longer
    //   `oci_upload_timeout` ceiling — PUT manifest is a small JSON
    //   document so the longer ceiling is harmless overhead, and
    //   monolithic PUT blob upload (where the entire payload ships
    //   in the PUT body) legitimately needs the headroom.
    // - `read_and_admin_router` carries everything else: the version
    //   probe, per-repo + global catalog, pull dispatcher (GET /
    //   HEAD on the wildcard), and DELETE on the wildcard (manifest
    //   delete only). These stay on the global default deadline.
    //
    // Each sub-router applies its own `TimeoutLayer` via `Router::layer`.
    // axum 0.7's `Router::merge` preserves per-router middleware
    // stacks — verified by the regression test in
    // `hort-server/tests/http_timeouts.rs::oci_upload_route_exempted_*`.
    // The OCI bearer-auth `route_layer` is attached AFTER the merge
    // so it covers both halves uniformly without diverging the auth
    // story per timeout bucket.
    let timeouts = ctx.http_timeout_config;

    let upload_router: Router<Arc<AppContext>> = Router::new()
        .route(
            "/v2/:repo_key/*tail",
            axum::routing::post(uploads::post_upload_dispatch)
                .patch(uploads::patch_upload_dispatch)
                .put(put_dispatch),
        )
        // Surface the `OciHttpConfig` to `post_upload_dispatch` via
        // Extension so the three-phase-initiate branch can consult
        // `max_sessions_per_principal`. Cloning is cheap (`Clone` on
        // `OciHttpConfig` copies a handful of `Copy` fields).
        .layer(axum::Extension(config.clone()))
        .layer(
            hort_http_core::middleware::request_timeout::request_timeout_layer(
                timeouts.oci_upload_timeout,
            ),
        );

    let mut read_and_admin_router: Router<Arc<AppContext>> = Router::new()
        .route("/v2/", axum::routing::get(version::get_version))
        // Distribution-Spec `/v2/auth` token exchange (ADR 0012). The
        // handler validates the inbound `Basic <PAT>` itself; the
        // upstream `oci_bearer_auth` middleware skips this path because
        // it has its own credential validation surface. Mounted on the
        // read-and-admin half because it is GET-only with no body.
        .route("/v2/auth", axum::routing::get(v2_auth::handle_v2_auth))
        // Per-repo catalog (modern default, always mounted). More
        // specific than `/v2/:repo_key/*tail`, so axum routes
        // `/v2/:repo_key/_catalog` here rather than into the pull
        // dispatcher.
        .route(
            "/v2/:repo_key/_catalog",
            axum::routing::get(catalog::get_repo_catalog),
        )
        // Pull dispatcher (blob + manifest + tags list). Wildcard
        // catch-all on `:repo_key`. DELETE on the same template
        // handles manifest delete.
        .route(
            "/v2/:repo_key/*tail",
            axum::routing::get(get_pull)
                .head(head_pull)
                .delete(manifests_write::delete_manifest_dispatch),
        );

    if config.legacy_catalog_enabled {
        // Docker-legacy global catalog. Opt-in via
        // `HORT_OCI_LEGACY_CATALOG_ENABLED=true`. Lists qualified
        // `<repo_key>/<name>` tuples across visible repos.
        read_and_admin_router = read_and_admin_router.route(
            "/v2/_catalog",
            axum::routing::get(catalog::get_global_catalog),
        );
    }

    let read_and_admin_router = read_and_admin_router.layer(
        hort_http_core::middleware::request_timeout::request_timeout_layer(
            timeouts.request_timeout,
        ),
    );

    // Merge the two halves. axum::Router::merge keeps each side's
    // layer stack — the upload routes carry the 60-minute ceiling,
    // the read/admin routes carry the global deadline. After merge,
    // attach the OCI bearer-auth `route_layer` covering BOTH halves.
    upload_router
        .merge(read_and_admin_router)
        // OCI bearer auth (ADR 0012). Owns the auth story for the
        // `/v2/*` subtree: validates the JWT minted by `/v2/auth`,
        // inserts the reconstituted `CallerPrincipal` into request
        // extensions for the `WriteRepoAccess` / `ReadRepoAccess`
        // extractors. The global `method_based_auth_dispatch`
        // short-circuits on OCI paths so this layer is the SOLE auth
        // gate on `/v2/*`.
        //
        // **`route_layer` (NOT `layer`)** — axum 0.7's `Router::layer`
        // wraps the entire merged router tree, including routes
        // contributed by other format crates merged in by the outer
        // composition root (npm / pypi / cargo). That would (and did)
        // cause `oci_bearer_auth` to fire on every non-OCI request
        // too. `route_layer` scopes the wrapper to ONLY the routes
        // registered in this router builder, exactly the behaviour
        // we want here.
        .route_layer(axum::middleware::from_fn_with_state(
            ctx,
            middleware::oci_auth::oci_bearer_auth,
        ))
}

/// Method-level PUT dispatcher that routes `/v2/:repo_key/*tail` PUT
/// between blob-upload finalize and manifest PUT.
///
/// Inspects the tail: `/manifests/<ref>` → manifest PUT,
/// `/blobs/uploads/<uuid>` → blob-upload PUT. A tail that matches
/// neither surfaces as `NAME_UNKNOWN` via the downstream handler
/// (both branches' tail parsers agree on that).
async fn put_dispatch(
    access: hort_http_core::authz::WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    Query(query): Query<uploads::PutQuery>,
    request: Request<axum::body::Body>,
) -> Response {
    // `BoundedPath` enforces the 512-byte per-segment cap on `repo_key`
    // and `tail`. The grammar-level `validate_oci_name` runs in the
    // downstream dispatcher (`manifests_write::put_manifest_dispatch` /
    // `uploads::put_upload_dispatch`) AFTER `parse_manifest_tail` /
    // `parse_patch_tail` extracts the canonical `<name>` segment from
    // the tail. Validating here would mean re-parsing the tail; we
    // instead push the grammar check to the downstream handlers where
    // the parsed `name` is already in scope.
    if tail.contains("/manifests/") {
        manifests_write::put_manifest_dispatch(
            access,
            State(ctx),
            BoundedPath((repo_key, tail)),
            request,
        )
        .await
    } else {
        uploads::put_upload_dispatch(
            access,
            State(ctx),
            BoundedPath((repo_key, tail)),
            Query(query),
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    //! Router-level end-to-end tests for tags list, per-repo catalog,
    //! and legacy global catalog. Handler-internal behaviour (link
    //! formatting, query parsing) is covered in the respective submodule
    //! tests; these drive the full dispatcher.

    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{
        sample_repository, MockArtifactGroupRepository, MockRefRegistryPort,
        MockRepositoryRepository,
    };
    use hort_domain::entities::artifact_group::ArtifactGroup;
    use hort_domain::entities::mutable_ref::{MutableRef, RefTarget};
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::types::{ArtifactCoords, ContentHash};
    use metrics_exporter_prometheus::PrometheusBuilder;

    use hort_http_core::test_support::build_mock_ctx;

    // ---------------- Fixtures ----------------

    struct Harness {
        ctx: Arc<AppContext>,
        repositories: Arc<MockRepositoryRepository>,
        refs: Arc<MockRefRegistryPort>,
        groups: Arc<MockArtifactGroupRepository>,
    }

    fn harness() -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        Harness {
            ctx,
            repositories: mocks.repositories,
            refs: mocks.refs,
            groups: mocks.artifact_groups,
        }
    }

    fn oci_repo(key: &str, is_public: bool) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r.is_public = is_public;
        r
    }

    fn seed_tag(refs: &MockRefRegistryPort, repo_id: Uuid, name: &str, tag: &str) {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        refs.insert(MutableRef {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            namespace: name.into(),
            ref_name: tag.into(),
            target: RefTarget::ContentHash(hash),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }

    fn seed_manifest_group(groups: &MockArtifactGroupRepository, repo_id: Uuid, image_name: &str) {
        let coords = ArtifactCoords {
            name: image_name.into(),
            name_as_published: image_name.into(),
            version: Some("sha256:abc".into()),
            path: String::new(),
            format: RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        };
        groups.insert(ArtifactGroup {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            coords,
            primary_role: "manifest".into(),
            members: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
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

    // ---------------- Tags list ----------------

    #[test]
    fn tags_list_returns_sorted_tags_non_saturated() {
        let (status, body, link) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_tag(&h.refs, repo_id, "library/nginx", "v1");
            seed_tag(&h.refs, repo_id, "library/nginx", "v2");
            seed_tag(&h.refs, repo_id, "library/nginx", "latest");

            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(
                    Request::get("/v2/myrepo/library/nginx/tags/list")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let link = resp
                .headers()
                .get("link")
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body, link)
        });
        assert_eq!(status, StatusCode::OK);
        assert!(link.is_none(), "non-saturated page must omit Link header");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["name"], "library/nginx");
        let tags: Vec<&str> = parsed["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // Byte-stable sort: `latest` < `v1` < `v2` under COLLATE "C".
        assert_eq!(tags, vec!["latest", "v1", "v2"]);
    }

    #[test]
    fn tags_list_saturated_emits_link_header() {
        let (status, link) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            let repo_id = repo.id;
            h.repositories.insert(repo);
            for tag in ["a", "b", "c", "d"] {
                seed_tag(&h.refs, repo_id, "nginx", tag);
            }

            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(
                    Request::get("/v2/myrepo/nginx/tags/list?n=2")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let link = resp
                .headers()
                .get("link")
                .map(|v| v.to_str().unwrap().to_string());
            (status, link)
        });
        assert_eq!(status, StatusCode::OK);
        let link = link.expect("saturated page must emit Link header");
        assert!(link.contains("rel=\"next\""));
        assert!(link.contains("n=2"));
        // Last tag on page 1 is "b" — cursor for page 2.
        assert!(link.contains("last=b"));
    }

    #[test]
    fn tags_list_missing_repo_returns_404_name_unknown() {
        let (status, body) = run(async {
            let h = harness();
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(
                    Request::get("/v2/missing/nginx/tags/list")
                        .body(Body::empty())
                        .unwrap(),
                )
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

    /// Build an `Arc<AppContext>` whose auth+access use case are flipped
    /// to Enabled with an empty RBAC evaluator. Used by the
    /// anonymous-on-private regression tests below. Anonymous requests
    /// under this ctx have `actor = None` after the OCI bearer middleware
    /// runs.
    ///
    /// `ctx.repositories` is `pub(crate)` (ADR 0008), so callers thread
    /// the `MockRepositoryRepository` handle from the harness's `MockPorts`
    /// rather than reading it off `base`.
    fn enabled_empty_rbac_ctx(
        base: &Arc<AppContext>,
        repositories: Arc<MockRepositoryRepository>,
    ) -> Arc<AppContext> {
        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;
        use hort_http_core::context::AuthContext;
        use hort_http_core::test_support::{with_auth, with_repository_access};

        let rbac_swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let ctx = with_auth(
            base,
            AuthContext::Enabled {
                authenticate,
                rbac: rbac_swap.clone(),
                // Test fixtures don't exercise the WWW-Authenticate
                // selector; the OCI path always yields Basic here.
                issuer_url: None,
            },
        );
        let access = Arc::new(RepositoryAccessUseCase::new(
            repositories,
            RbacAccess::Enabled(rbac_swap),
            true,
        ));
        with_repository_access(&ctx, access)
    }

    /// Visibility regression guard (ADR 0008): anonymous tags-list on a
    /// private repo MUST be 404 NAME_UNKNOWN.
    #[test]
    fn anonymous_tags_list_on_private_repo_returns_404_name_unknown() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("private-repo", false);
            h.repositories.insert(repo);
            let ctx = enabled_empty_rbac_ctx(&h.ctx, h.repositories.clone());
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), ctx.clone()).with_state(ctx);
            let resp = router
                .oneshot(
                    Request::get("/v2/private-repo/library/nginx/tags/list")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "anonymous tags list on private OCI repo MUST be 404"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
    }

    /// Visibility regression guard (ADR 0008): anonymous referrers query
    /// on a private repo MUST be 404 NAME_UNKNOWN. Without the visibility
    /// check, the existing referrers spec rule "empty result returns 200"
    /// would leak the existence of the repo to anonymous probers.
    #[test]
    fn anonymous_referrers_on_private_repo_returns_404_name_unknown() {
        let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("private-repo", false);
            h.repositories.insert(repo);
            let ctx = enabled_empty_rbac_ctx(&h.ctx, h.repositories.clone());
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), ctx.clone()).with_state(ctx);
            let uri = format!("/v2/private-repo/library/nginx/referrers/sha256:{valid_hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "anonymous referrers on private OCI repo MUST be 404"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
    }

    /// Visibility regression guard (ADR 0008): anonymous referrers on a
    /// private repo MUST still be 404 NAME_UNKNOWN through the
    /// `find_by_visible_target` use-case path. Pins that the composition
    /// didn't open a new anti-enumeration gap.
    #[test]
    fn anonymous_referrers_on_private_repo_returns_404_after_use_case_migration() {
        let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("private-repo", false);
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed a content_references row for this repo via the use
            // case's own write contract — proves the read path through
            // `find_by_visible_target` still suppresses the row from
            // anonymous callers (i.e. the visibility gate fires BEFORE
            // any rows are returned, even though the row exists).
            let ctx = enabled_empty_rbac_ctx(&h.ctx, h.repositories.clone());
            let target_hash: ContentHash = valid_hex.parse().unwrap();
            ctx.content_reference_use_case
                .insert_for_repo(
                    repo_id,
                    hort_domain::ports::content_reference_index::ContentReference {
                        source_artifact_id: Uuid::new_v4(),
                        target_content_hash: target_hash,
                        kind: "oci_subject".into(),
                        metadata: serde_json::json!({}),
                        repository_id: repo_id,
                        recorded_at: Utc::now(),
                    },
                )
                .await
                .unwrap();
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), ctx.clone()).with_state(ctx);
            let uri = format!("/v2/private-repo/library/nginx/referrers/sha256:{valid_hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "anonymous referrers on private OCI repo MUST be 404 even with seeded rows (ADR 0008)"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
        // The handler's emitted body MUST be byte-identical to the
        // missing-repo case — that is what an enumeration probe would
        // diff against.
        let body_text = String::from_utf8_lossy(&body);
        assert!(body_text.contains("NAME_UNKNOWN"));
    }

    // ---------------- Per-repo catalog ----------------

    #[test]
    fn repo_catalog_returns_distinct_image_names() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest_group(&h.groups, repo_id, "library/nginx");
            seed_manifest_group(&h.groups, repo_id, "library/alpine");

            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(
                    Request::get("/v2/myrepo/_catalog")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos: Vec<&str> = parsed["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // Unqualified names (per-repo catalog), byte-sorted.
        assert_eq!(repos, vec!["library/alpine", "library/nginx"]);
    }

    #[test]
    fn repo_catalog_saturated_emits_link_header() {
        let (status, link) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            let repo_id = repo.id;
            h.repositories.insert(repo);
            for name in ["a", "b", "c", "d"] {
                seed_manifest_group(&h.groups, repo_id, name);
            }

            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(
                    Request::get("/v2/myrepo/_catalog?n=2")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let link = resp
                .headers()
                .get("link")
                .map(|v| v.to_str().unwrap().to_string());
            (status, link)
        });
        assert_eq!(status, StatusCode::OK);
        let link = link.expect("saturated per-repo catalog must emit Link");
        assert!(link.contains("rel=\"next\""));
        assert!(link.contains("/v2/myrepo/_catalog"));
        assert!(link.contains("last=b"));
    }

    // ---------------- Global catalog (legacy flag) ----------------

    #[test]
    fn global_catalog_absent_when_legacy_flag_disabled() {
        // Default config has `legacy_catalog_enabled = false` — the
        // global endpoint must 404 rather than mount silently.
        let status = run(async {
            let h = harness();
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(Request::get("/v2/_catalog").body(Body::empty()).unwrap())
                .await
                .unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn global_catalog_legacy_flag_on_qualifies_names_across_public_repos() {
        let (status, body) = run(async {
            let h = harness();
            let r1 = oci_repo("myrepo", true);
            let r2 = oci_repo("mirror", true);
            let r1_id = r1.id;
            let r2_id = r2.id;
            h.repositories.insert(r1);
            h.repositories.insert(r2);
            seed_manifest_group(&h.groups, r1_id, "nginx");
            seed_manifest_group(&h.groups, r2_id, "alpine");

            let cfg = OciHttpConfig {
                legacy_catalog_enabled: true,
                ..OciHttpConfig::default()
            };
            let router = oci_routes_with_config(&cfg, h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(Request::get("/v2/_catalog").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = parsed["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // Qualified names, byte-sorted.
        assert_eq!(names, vec!["mirror/alpine", "myrepo/nginx"]);
    }

    #[test]
    fn global_catalog_hides_private_repos_from_anonymous() {
        // Security-load-bearing: a private repo must NOT surface in
        // anonymous catalog output, even under legacy-flag-on. This
        // is the anti-enumeration invariant the default-off flag is
        // trying to protect; with the flag on, visibility filtering
        // takes over.
        //
        // `RbacAccess::Disabled` admits every actor (ADR 0008):
        // a `RbacAccess::Disabled` access use case would visibility-filter
        // as if the caller carried every grant, so the private repo would
        // surface even on an anonymous catalog. To exercise the
        // private-repo-hidden-from-anonymous invariant we MUST run under
        // `AuthContext::Enabled` (so the bearer middleware forwards
        // `actor = None` for an unauthenticated request) with an empty
        // `RbacEvaluator` (no grants) + `RbacAccess::Enabled` on the
        // access use case. That mirrors a real-world OCI deployment with
        // auth on but no token presented.
        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_app::use_cases::test_support::MockIdentityProvider;
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;
        use hort_http_core::context::AuthContext;
        use hort_http_core::test_support::{with_auth, with_repository_access};

        let (status, body) = run(async {
            let h = harness();
            let public = oci_repo("public-repo", true);
            let private = oci_repo("private-repo", false);
            let pub_id = public.id;
            let priv_id = private.id;
            h.repositories.insert(public);
            h.repositories.insert(private);
            seed_manifest_group(&h.groups, pub_id, "pub-image");
            seed_manifest_group(&h.groups, priv_id, "private-image");

            // Build an Enabled auth context (no IdP tokens registered)
            // so the OCI bearer middleware forwards `actor = None`
            // rather than synthesising an admin under Disabled.
            let rbac_swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
                Vec::new(),
            )));
            let idp = Arc::new(MockIdentityProvider::new());
            let users = hort_app::use_cases::test_support::MockUserRepository::new();
            let authenticate = Arc::new(AuthenticateUseCase::new(
                idp as Arc<dyn IdentityProvider>,
                Arc::new(users) as Arc<dyn UserRepository>,
                Vec::new(),
            ));
            let auth = AuthContext::Enabled {
                authenticate,
                rbac: rbac_swap.clone(),
                // Test fixtures don't exercise the WWW-Authenticate selector.
                issuer_url: None,
            };
            let ctx = with_auth(&h.ctx, auth);

            // Flip the access use case to Enabled with the same RBAC
            // snapshot so `list_visible(None, _)` collapses private
            // repos to invisible for unauthenticated actors.
            // `ctx.repositories` is `pub(crate)` (ADR 0008); pull the
            // same `Arc<MockRepositoryRepository>` off the harness's
            // MockPorts handle (`h.repositories`).
            let access = Arc::new(RepositoryAccessUseCase::new(
                h.repositories.clone(),
                RbacAccess::Enabled(rbac_swap),
                true,
            ));
            let ctx = with_repository_access(&ctx, access);

            let cfg = OciHttpConfig {
                legacy_catalog_enabled: true,
                ..OciHttpConfig::default()
            };
            let router = oci_routes_with_config(&cfg, ctx.clone()).with_state(ctx);
            let resp = router
                .oneshot(Request::get("/v2/_catalog").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = parsed["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["public-repo/pub-image"]);
        assert!(
            !names.iter().any(|n| n.contains("private-image")),
            "private-repo image must NOT leak into anonymous global catalog: {names:?}"
        );
    }

    // ---------------- put_dispatch: wildcard-PUT routing --------------

    /// Regression guard for the method-level PUT dispatcher wired in
    /// `oci_routes_with_config`. Blob-upload finalize (PUT
    /// `/blobs/uploads/<uuid>`) and manifest write (PUT
    /// `/manifests/<ref>`) share the `/v2/:repo_key/*tail` template;
    /// this test exercises the manifest branch and asserts the right
    /// handler answers (MANIFEST_INVALID on unsupported content-type —
    /// uploads::put_upload_dispatch would never emit that envelope,
    /// so the code proves manifests_write took the call).
    #[test]
    fn put_dispatch_routes_manifest_put_to_manifests_write() {
        let (status, code) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            h.repositories.insert(repo);

            // Use an unsupported content-type: manifests_write rejects
            // with MANIFEST_INVALID. uploads::put_upload_dispatch does
            // not emit MANIFEST_INVALID at all — it would instead
            // return DIGEST_INVALID (missing digest query) or
            // NAME_UNKNOWN (bad tail). Seeing MANIFEST_INVALID means
            // the dispatcher routed correctly.
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let mut req = Request::put("/v2/myrepo/library/nginx/manifests/v1")
                .header("content-type", "application/json")
                .body(Body::from(b"{}".to_vec()))
                .unwrap();
            // Wrap into the `AuthenticatedPrincipal` newtype via the
            // test-support helper; the extractors no longer read the
            // bare `CallerPrincipal` slot.
            hort_http_core::middleware::auth::test_support::inject_principal(
                &mut req,
                CallerPrincipal {
                    user_id: Uuid::new_v4(),
                    external_id: "test:sub".into(),
                    username: "alice".into(),
                    email: "alice@example.com".into(),
                    claims: Vec::new(),
                    token_kind: None,
                    issued_at: Utc::now(),
                    token_cap: None,
                },
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let code = parsed["errors"][0]["code"]
                .as_str()
                .unwrap_or("")
                .to_string();
            (status, code)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            code, "MANIFEST_INVALID",
            "top-level PUT dispatcher must route /manifests/ to manifests_write"
        );
    }

    /// Companion to the above: PUT on `/blobs/uploads/<uuid>` must
    /// route to `uploads::put_upload_dispatch`, NOT to
    /// `manifests_write::put_manifest_dispatch`. A missing `?digest=`
    /// forces uploads to emit `DIGEST_INVALID` — manifests_write does
    /// not produce that envelope, so seeing it proves correct routing.
    #[test]
    fn put_dispatch_routes_blob_upload_put_to_uploads() {
        let (status, code) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            h.repositories.insert(repo);

            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let fake_uuid = Uuid::new_v4();
            let mut req = Request::put(format!(
                "/v2/myrepo/library/nginx/blobs/uploads/{fake_uuid}"
            ))
            .body(Body::empty())
            .unwrap();
            // Wrap into the `AuthenticatedPrincipal` newtype via the
            // test-support helper; the extractors no longer read the
            // bare `CallerPrincipal` slot.
            hort_http_core::middleware::auth::test_support::inject_principal(
                &mut req,
                CallerPrincipal {
                    user_id: Uuid::new_v4(),
                    external_id: "test:sub".into(),
                    username: "alice".into(),
                    email: "alice@example.com".into(),
                    claims: Vec::new(),
                    token_kind: None,
                    issued_at: Utc::now(),
                    token_cap: None,
                },
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let code = parsed["errors"][0]["code"]
                .as_str()
                .unwrap_or("")
                .to_string();
            (status, code)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            code, "DIGEST_INVALID",
            "top-level PUT dispatcher must route /blobs/uploads/ to uploads module"
        );
    }

    // ---------------- BoundedPath cap + CRLF injection guard -----------------
    //
    // Acceptance tests for the BoundedPath 512-byte cap and CRLF
    // rejection at the validator BEFORE `header_value_or_bad_request`
    // runs. The validator unit tests live in `src/name.rs::tests`; these
    // two exercise the router-integration shape so a regression at either
    // boundary is caught.

    /// Acceptance #5 — `BoundedPath` cap. A 600-byte `*tail` capture
    /// must reject with 400 at the extractor. The
    /// `MAX_ROUTE_PARAM_BYTES` cap is 512; 600 is comfortably over.
    /// The response body shape comes from `BoundedPath`'s extractor
    /// rejection (the JSON `{"error":"route parameter too long",
    /// "parameter":"tail"}` shape) — this is `hort-http-core`'s
    /// generic 400 envelope, NOT the OCI `errors[]` shape. That's
    /// the right behaviour: the cap fires BEFORE the OCI handler
    /// runs, so no OCI-specific envelope shaping is in scope.
    #[test]
    fn bounded_path_rejects_600_byte_tail_at_extractor() {
        let status = run(async {
            let h = harness();
            // 600 bytes of `a` — over the 512-byte `MAX_ROUTE_PARAM_BYTES`
            // cap. The route template is `/v2/:repo_key/*tail`; the
            // 600-byte string is the `*tail` capture.
            let huge = "a".repeat(600);
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(format!("/v2/myrepo/{huge}/manifests/v1"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            resp.status()
        });
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "600-byte tail must be rejected at the BoundedPath extractor"
        );
    }

    /// Acceptance #7 — CRLF in the tail's `<name>` segment must reject
    /// at the validator BEFORE `header_value_or_bad_request` runs.
    /// `header_value_or_bad_request` is response-side defence-in-depth
    /// (catches CRLF on the way out, into a `Location` header); the
    /// validator catches CRLF on the way IN, before any storage /
    /// metric / log emission. This test pins both:
    ///   - The status is 400 (validator), NOT 404 (which is what
    ///     `header_value_or_bad_request` would produce).
    ///   - The error code is `NAME_INVALID` (validator), NOT
    ///     `NAME_UNKNOWN` (which is what `header_value_or_bad_request`
    ///     emits).
    ///
    /// Realising this distinction matters: a 404 + `NAME_UNKNOWN` is
    /// the existing fallback for malformed-name URL captures. The
    /// validator's 400 + `NAME_INVALID` is the SPEC-CORRECT envelope
    /// per the OCI Distribution Spec error-codes table. Without the
    /// validator, CRLF would reach `Artifact.name` and metric labels
    /// before hitting the response-builder defence-in-depth.
    #[test]
    fn crlf_in_tail_name_rejects_at_validator_before_header_value_or_bad_request() {
        let (status, code) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo", true);
            h.repositories.insert(repo);
            let router =
                oci_routes_with_config(&OciHttpConfig::default(), h.ctx.clone()).with_state(h.ctx);
            // The percent-decoded `<name>` segment carries CRLF —
            // axum decodes the URL captures before they reach the
            // handler. `nginx%0D%0AInjected` decodes to
            // `nginx\r\nInjected`, the canonical CRLF-injection
            // payload. The validator must reject it.
            let resp = router
                .oneshot(
                    Request::get("/v2/myrepo/nginx%0D%0AInjected/manifests/v1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).expect("OCI envelope is JSON");
            let code = parsed["errors"][0]["code"]
                .as_str()
                .unwrap_or("")
                .to_string();
            (status, code)
        });
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "CRLF in name must be 400 (validator), NOT 404 (header_value_or_bad_request fallback)"
        );
        assert_eq!(
            code, "NAME_INVALID",
            "validator emits NAME_INVALID; header_value_or_bad_request would emit NAME_UNKNOWN"
        );
    }
}
