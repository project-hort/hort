//! PyPI unified simple-index serve handler
//! (see `docs/architecture/how-to/pypi-pull-through.md` and
//! `docs/architecture/explanation/index-construction.md`).
//!
//! This is the PyPI-side of the **Source → Filter → Builder** pipeline.
//! One handler covers both hosted and proxy repos for the
//! `GET /pypi/{repo_key}/simple/{project}/` route:
//!
//! 1. **Source.** Dispatch on `repo.repo_type`:
//!    - `Proxy` → [`ProxyPypiSource`] (calls
//!      [`crate::simple_index::fetch_with_cache`] under the hood —
//!      preserving cache + dedup + URL-rewrite + quarantine-filter +
//!      stale-while-error invariants byte-for-byte);
//!    - anything else → [`HostedPypiSource`] (reads
//!      [`ArtifactUseCase::list_by_raw_name_visible`] — the
//!      anti-enumeration-enforcing entry point).
//! 2. **Filter pipeline.** `NonServableStatusFilter` then
//!    `IndexModeFilter::new(repo.index_mode)`. Future operator-defined
//!    exclusion filters append to this list.
//! 3. **Builder.** Per the request's `Accept` header — via the
//!    existing [`SimpleIndexFormat::from_accept`] picker —
//!    [`PypiHtmlIndexBuilder`] (PEP 503) or [`PypiJsonIndexBuilder`]
//!    (PEP 691) emits the wire bytes. Two builders, NOT one builder
//!    with a content-type field on [`BuildContext`].
//!
//! # Anti-enumeration shape
//!
//! Anonymous / denied callers on a private repo receive `404`, not
//! `403`. The hosted source's `list_by_raw_name_visible` already
//! collapses denial / missing / invisible into
//! `NotFound { entity: "Repository" }`; the unified handler maps
//! that through to a 404 envelope. The proxy source re-resolves via
//! `RepositoryAccessUseCase` for defence-in-depth; same envelope.
//! Empty result sets (hosted produces zero entries; proxy parses an
//! empty `files[]`) also map to 404 with the
//! `Artifact NotFound { id: <pkg_name> }` envelope.
//!
//! # PEP 440 latest preservation
//!
//! Filtered out via the post-source filter pipeline + the JSON
//! builder's `versions[]` sort (PEP 440 ordering); the HTML builder
//! emits anchors in source order and pip derives the latest from the
//! served set.
//!
//! # Truncation `Warning: 299` header
//!
//! Threaded through [`IndexSourceOutput::truncated`]. Only the
//! hosted source can be truncated (its `list_by_raw_name_visible`
//! is paginated and capped at
//! [`LIMIT_LIST_MAX_ITEMS`](hort_domain::types::LIMIT_LIST_MAX_ITEMS));
//! the proxy source always reports `truncated = false`.
//!
//! # Observability
//!
//! - The filter pipeline reuses the existing
//!   `hort_index_versions_filtered_total{format, repository}` counter.
//!   This handler emits it once per call across the number of versions
//!   the filter pipeline dropped (universal + mode-specific arms combined).
//! - One `info!` line carries `format`, `repository`, `package`,
//!   `index_source = "hosted" | "proxy"`, and the
//!   `upstream_versions` / `served_versions` / `filtered_versions`
//!   triple.

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::Response;

use hort_app::error::AppError;
use hort_app::use_cases::index_filters::{IndexModeFilter, NonServableStatusFilter};
use hort_app::use_cases::index_serve::{BuildContext, IndexFilter, VersionEntry};
use hort_app::use_cases::index_serve_filter::Pep440Ordering;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryType};
use hort_formats::index_serve::IndexBuilder;
use hort_formats::pypi::index::{PypiHtmlIndexBuilder, PypiJsonIndexBuilder};
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

use crate::index_source::{select_source, IndexSourceOutput};
use crate::simple_index::SimpleIndexFormat;

/// Unified PyPI simple-index serve handler (Source → Filter → Builder
/// pipeline, see `docs/architecture/how-to/pypi-pull-through.md` and
/// `docs/architecture/explanation/index-construction.md`).
///
/// `caller` is threaded through the source layer; both hosted and
/// proxy sources call `RepositoryAccessUseCase::resolve(_, caller,
/// Read)` (directly or via `list_by_raw_name_visible`), so denied /
/// invisible / missing repos all collapse to a 404
/// `Repository NotFound` envelope before any rows / upstream bytes
/// are surfaced.
///
/// On success returns a 200 response whose `Content-Type` is
/// determined by the per-call [`SimpleIndexFormat`] (resolved by the
/// dispatch site from the `Accept` header): `text/html; charset=utf-8`
/// for HTML (PEP 503), `application/vnd.pypi.simple.v1+json` for
/// JSON (PEP 691). On truncation, the same response gains a
/// `Warning: 299 - "results truncated at <cap> items"` header.
#[tracing::instrument(
    skip(ctx, caller),
    fields(repo_key = %repo_key, pkg = %project, format = ?format),
)]
pub(crate) async fn serve_simple_index_unified(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    project: &str,
    format: SimpleIndexFormat,
    caller: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // ---- Resolve the repo + access check -----------------------------
    // Anti-enumeration: anonymous on private collapses to
    // `NotFound { entity: "Repository" }` (ADR 0008).
    let repo: Repository = ctx
        .repository_access_use_case
        .resolve(repo_key, caller, AccessLevel::Read)
        .await
        .map_err(ApiError::from)?;

    // ---- Step 1: Source dispatch (transparent to repo type) ----------
    // `select_source` returns the hosted / proxy / virtual source. The
    // virtual source aggregates its members behind this same seam
    // (ADR 0031), so this handler never special-cases `Virtual` — it
    // dispatches by type for the tracing label only, then runs the
    // unchanged filter pipeline + builder.
    let index_source_label = match repo.repo_type {
        RepositoryType::Proxy => "proxy",
        RepositoryType::Virtual => "virtual",
        _ => "hosted",
    };
    let output: IndexSourceOutput = select_source(&repo, format)
        .fetch(ctx, &repo, project, caller)
        .await
        .map_err(ApiError::from)?;

    // Empty hosted results → 404 (package not found in this repository).
    // For proxy the equivalent path was: `NoUpstream` → 404 (raised
    // at the source layer above); a parsed-empty body is allowed and
    // produces an empty served document.
    if matches!(
        repo.repo_type,
        RepositoryType::Hosted | RepositoryType::Staging | RepositoryType::Virtual
    ) && output.entries.is_empty()
    {
        return Err(ApiError::from(AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Artifact",
                id: project.to_string(),
            },
        )));
    }

    // ---- Step 2: Filter pipeline -------------------------------------
    let upstream_count = output.entries.len();
    let filters: Vec<Arc<dyn IndexFilter>> = vec![
        Arc::new(NonServableStatusFilter),
        Arc::new(IndexModeFilter::new(repo.index_mode)),
    ];
    let filtered: Vec<VersionEntry> = filters.iter().fold(output.entries, |acc, f| f.apply(acc));
    let served_count = filtered.len();
    let filtered_count = upstream_count.saturating_sub(served_count);

    if filtered_count > 0 {
        metrics::counter!(
            "hort_index_versions_filtered_total",
            "format" => "pypi",
            "repository" => repo_key.to_string(),
        )
        .increment(filtered_count as u64);
    }

    tracing::info!(
        package = %project,
        repository = %repo_key,
        index_source = index_source_label,
        index_mode = %repo.index_mode,
        upstream_versions = upstream_count,
        served_versions = served_count,
        filtered_versions = filtered_count,
        "pypi unified simple-index serve completed",
    );

    // ---- Step 3: Build the wire bytes --------------------------------
    // Resolve the client-facing base URL — the builder uses it to
    // compose per-file download links. Emit path-only (no scheme/host):
    // `/pypi/{repo_key}/simple/{normalized_name}`.
    let base_str = format!("/pypi/{repo_key}/simple/{}", output.canonical_name);

    let body_bytes = match format {
        SimpleIndexFormat::Html => PypiHtmlIndexBuilder.build(
            BuildContext {
                package_name: &output.canonical_name,
                base_url: &base_str,
                index_mode: repo.index_mode,
                ordering: &Pep440Ordering,
            },
            filtered,
        ),
        SimpleIndexFormat::Json => PypiJsonIndexBuilder.build(
            BuildContext {
                package_name: &output.canonical_name,
                base_url: &base_str,
                index_mode: repo.index_mode,
                ordering: &Pep440Ordering,
            },
            filtered,
        ),
    };

    let content_type = match format {
        SimpleIndexFormat::Html => "text/html; charset=utf-8",
        SimpleIndexFormat::Json => "application/vnd.pypi.simple.v1+json",
    };

    let mut builder_resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type);
    if output.truncated {
        builder_resp = builder_resp.header(
            "Warning",
            format!(
                "299 - \"results truncated at {} items\"",
                hort_domain::types::LIMIT_LIST_MAX_ITEMS
            ),
        );
    }
    Ok(builder_resp.body(Body::from(body_bytes)).unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Tests for the unified simple-index serve handler:
    //!
    //! 1. Quarantined artifact filtered from HTML and JSON output.
    //! 2. Rejected artifact filtered from HTML and JSON output.
    //! 3. Content-type negotiation preserved (HTML / JSON / default).
    //! 4. Anti-enumeration — anonymous on private repo gets
    //!    `NotFound` (404), not 403. Both content types.
    //! 5. PEP 440 versions[] ordering (JSON).
    //! 6. Smoke for the truncation-`Warning` header propagation.
    //! 7. Missing-package 404 on visible hosted repo.
    //!
    //! All tests drive the unified handler directly.
    use std::sync::Arc;

    use axum::response::IntoResponse;
    use chrono::Utc;
    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::{IndexMode, RepositoryFormat};
    use hort_domain::types::ContentHash;
    use hort_http_core::test_support::{
        build_mock_ctx, trust_config_untrusted_peer_fallback, with_repository_access,
        with_trust_config,
    };
    use metrics_exporter_prometheus::PrometheusBuilder;
    use uuid::Uuid;

    use super::*;

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    fn insert_hosted_repo(
        mocks: &hort_http_core::test_support::MockPorts,
        key: &str,
        mode: IndexMode,
    ) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.into();
        repo.format = RepositoryFormat::Pypi;
        repo.repo_type = RepositoryType::Hosted;
        repo.index_mode = mode;
        mocks.repositories.insert(repo.clone());
        repo
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_artifact(
        mocks: &hort_http_core::test_support::MockPorts,
        repo_id: Uuid,
        name: &str,
        version: &str,
        filename: &str,
        sha256_hex: &str,
        status: QuarantineStatus,
    ) -> Artifact {
        let sha256: ContentHash = sha256_hex.parse().unwrap_or_else(|_| {
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap()
        });
        let now = Utc::now();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: format!("{name}/{filename}"),
            size_bytes: 100,
            sha256_checksum: sha256,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: status,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };
        mocks.artifacts.insert(artifact.clone());
        artifact
    }

    /// Distinct 64-hex SHA-256 string per version (a placeholder; tests
    /// only care about uniqueness + format, not the actual content).
    fn fake_sha256(seed: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..64 {
            s.push(((seed % 16) + b'0') as char);
        }
        s
    }

    // -----------------------------------------------------------------
    // 2a. Quarantined hosted artifact filtered — HTML.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn quarantined_hosted_artifact_is_filtered_from_served_html() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.0.0",
            "requests-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.1.0",
            "requests-1.1.0.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.2.0",
            "requests-1.2.0.tar.gz",
            &fake_sha256(3),
            QuarantineStatus::Released,
        );

        let res = serve_simple_index_unified(
            &ctx,
            "pypi-test",
            "requests",
            SimpleIndexFormat::Html,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("requests-1.0.0.tar.gz"),
            "1.0.0 Released must be served"
        );
        assert!(
            !html.contains("requests-1.1.0.tar.gz"),
            "1.1.0 Quarantined MUST be filtered out by NonServableStatusFilter: {html}"
        );
        assert!(
            html.contains("requests-1.2.0.tar.gz"),
            "1.2.0 Released must be served"
        );
    }

    // -----------------------------------------------------------------
    // 2b. Quarantined hosted artifact filtered — JSON.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn quarantined_hosted_artifact_is_filtered_from_served_json() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.0.0",
            "requests-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.1.0",
            "requests-1.1.0.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Quarantined,
        );

        let res = serve_simple_index_unified(
            &ctx,
            "pypi-test",
            "requests",
            SimpleIndexFormat::Json,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let files = json["files"].as_array().unwrap();
        let filenames: Vec<&str> = files
            .iter()
            .map(|f| f["filename"].as_str().unwrap())
            .collect();
        assert!(filenames.contains(&"requests-1.0.0.tar.gz"));
        assert!(
            !filenames.contains(&"requests-1.1.0.tar.gz"),
            "Quarantined version MUST NOT appear in files[]: {filenames:?}"
        );
        // versions[] excludes the quarantined version too.
        let versions: Vec<&str> = json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(versions, vec!["1.0.0"]);
    }

    // -----------------------------------------------------------------
    // 3a. Rejected hosted artifact filtered — HTML.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rejected_hosted_artifact_is_filtered_from_served_html() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.0.0",
            "requests-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.1.0",
            "requests-1.1.0.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Rejected,
        );

        let res = serve_simple_index_unified(
            &ctx,
            "pypi-test",
            "requests",
            SimpleIndexFormat::Html,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("requests-1.0.0.tar.gz"));
        assert!(
            !html.contains("requests-1.1.0.tar.gz"),
            "Rejected artifact MUST be filtered by NonServableStatusFilter: {html}"
        );
    }

    // -----------------------------------------------------------------
    // 3b. Rejected hosted artifact filtered — JSON.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rejected_hosted_artifact_is_filtered_from_served_json() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.0.0",
            "requests-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.1.0",
            "requests-1.1.0.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Rejected,
        );

        let res = serve_simple_index_unified(
            &ctx,
            "pypi-test",
            "requests",
            SimpleIndexFormat::Json,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let files = json["files"].as_array().unwrap();
        let filenames: Vec<&str> = files
            .iter()
            .map(|f| f["filename"].as_str().unwrap())
            .collect();
        assert_eq!(filenames, vec!["requests-1.0.0.tar.gz"]);
    }

    // -----------------------------------------------------------------
    // 4. Content-type negotiation preserved.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn content_type_negotiation_html_returns_text_html() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.0.0",
            "requests-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );

        let res = serve_simple_index_unified(
            &ctx,
            "pypi-test",
            "requests",
            SimpleIndexFormat::Html,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let ct = res.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(ct.starts_with("text/html"), "HTML negotiation: {ct}");
    }

    #[tokio::test]
    async fn content_type_negotiation_json_returns_pep691_type() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "requests",
            "1.0.0",
            "requests-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );

        let res = serve_simple_index_unified(
            &ctx,
            "pypi-test",
            "requests",
            SimpleIndexFormat::Json,
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let ct = res.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert_eq!(ct, "application/vnd.pypi.simple.v1+json");
    }

    #[test]
    fn from_accept_unknown_or_absent_defaults_to_html() {
        // Smoke that `SimpleIndexFormat::from_accept` falls back to Html
        // on missing/unknown Accept (PEP 503 default).
        assert_eq!(
            SimpleIndexFormat::from_accept(None),
            SimpleIndexFormat::Html
        );
        assert_eq!(
            SimpleIndexFormat::from_accept(Some("application/xml")),
            SimpleIndexFormat::Html
        );
    }

    // -----------------------------------------------------------------
    // 5a. Anti-enumeration — anonymous on private repo gets 404,
    // not 403 (HTML).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn anonymous_caller_on_private_repo_receives_404_html() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());

        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx, access);

        let mut repo = sample_repository();
        repo.key = "private-pypi".into();
        repo.format = RepositoryFormat::Pypi;
        repo.repo_type = RepositoryType::Hosted;
        repo.is_public = false;
        mocks.repositories.insert(repo.clone());
        insert_artifact(
            &mocks,
            repo.id,
            "secret",
            "1.0.0",
            "secret-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );

        let err = serve_simple_index_unified(
            &ctx,
            "private-pypi",
            "secret",
            SimpleIndexFormat::Html,
            None,
        )
        .await
        .expect_err("anonymous on private MUST be denied");
        let response = err.into_response();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "anti-enumeration: denied caller MUST receive 404 (HTML), NEVER 403",
        );
    }

    // -----------------------------------------------------------------
    // 5b. Anti-enumeration — JSON branch.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn anonymous_caller_on_private_repo_receives_404_json() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());

        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx, access);

        let mut repo = sample_repository();
        repo.key = "private-pypi".into();
        repo.format = RepositoryFormat::Pypi;
        repo.repo_type = RepositoryType::Hosted;
        repo.is_public = false;
        mocks.repositories.insert(repo.clone());
        insert_artifact(
            &mocks,
            repo.id,
            "secret",
            "1.0.0",
            "secret-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );

        let err = serve_simple_index_unified(
            &ctx,
            "private-pypi",
            "secret",
            SimpleIndexFormat::Json,
            None,
        )
        .await
        .expect_err("anonymous on private MUST be denied");
        let response = err.into_response();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "anti-enumeration: denied caller MUST receive 404 (JSON), NEVER 403",
        );
    }

    // -----------------------------------------------------------------
    // 6. PEP 440 versions[] ordering preserved (JSON arm — the JSON
    // builder sorts via Pep440Ordering; this drives the unified
    // pipeline through the same path).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn json_versions_array_sorted_by_pep440_via_unified_handler() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);
        // 1.9 and 1.10 — lex orders 1.10 before 1.9; PEP 440 orders
        // 1.9 before 1.10. The unified handler must thread
        // `Pep440Ordering` through to the builder.
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.9",
            "pkg-1.9.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.10",
            "pkg-1.10.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Released,
        );

        let res =
            serve_simple_index_unified(&ctx, "pypi-test", "pkg", SimpleIndexFormat::Json, None)
                .await
                .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions: Vec<&str> = json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            versions,
            vec!["1.9", "1.10"],
            "versions[] under unified handler must be PEP 440-sorted"
        );
    }

    // -----------------------------------------------------------------
    // 7. Missing-package smoke — visible hosted repo, missing package
    // → 404.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn missing_package_on_visible_hosted_repo_returns_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let _repo = insert_hosted_repo(&mocks, "pypi-test", IndexMode::ReleasedOnly);

        let err =
            serve_simple_index_unified(&ctx, "pypi-test", "missing", SimpleIndexFormat::Html, None)
                .await
                .expect_err("missing package must 404");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------
    // Virtual (aggregating) serve — ADR 0031. The serve handler is
    // transparent (no `Virtual` branch); these drive it end-to-end through
    // `select_source` → `VirtualPypiSource` → `aggregate_index_members`.
    // -----------------------------------------------------------------

    fn insert_virtual_repo(
        mocks: &hort_http_core::test_support::MockPorts,
        key: &str,
        members: &[&Repository],
    ) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.into();
        repo.format = RepositoryFormat::Pypi;
        repo.repo_type = RepositoryType::Virtual;
        repo.index_mode = IndexMode::ReleasedOnly;
        mocks.repositories.insert(repo.clone());
        for m in members {
            mocks.repositories.seed_virtual_member(repo.id, m.id);
        }
        repo
    }

    async fn served_versions_json(res: Response) -> Vec<String> {
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn virtual_merges_member_simple_indexes() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "pypi-a", IndexMode::ReleasedOnly);
        let b = insert_hosted_repo(&mocks, "pypi-b", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            a.id,
            "req",
            "1.0.0",
            "req-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            b.id,
            "req",
            "2.0.0",
            "req-2.0.0.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Released,
        );
        insert_virtual_repo(&mocks, "pypi-virt", &[&a, &b]);

        let res =
            serve_simple_index_unified(&ctx, "pypi-virt", "req", SimpleIndexFormat::Json, None)
                .await
                .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let versions = served_versions_json(res).await;
        assert!(versions.contains(&"1.0.0".to_string()), "member a served");
        assert!(versions.contains(&"2.0.0".to_string()), "member b served");
    }

    #[tokio::test]
    async fn virtual_same_version_held_primary_not_replaced_by_secondary() {
        // Dependency-confusion regression (same-version): the higher-priority
        // member holds 1.0.0 Quarantined; a lower-priority member has the SAME
        // version Released. The held copy wins the authoritative merge and is
        // then filtered out — it is NOT replaced by the secondary's released
        // copy. Raw entries are non-empty (so no 404), but the served
        // versions[] is empty.
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let primary = insert_hosted_repo(&mocks, "pypi-primary", IndexMode::ReleasedOnly);
        let secondary = insert_hosted_repo(&mocks, "pypi-secondary", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            primary.id,
            "req",
            "1.0.0",
            "req-1.0.0.tar.gz",
            &fake_sha256(1),
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            secondary.id,
            "req",
            "1.0.0",
            "req-1.0.0.tar.gz",
            &fake_sha256(2),
            QuarantineStatus::Released,
        );
        insert_virtual_repo(&mocks, "pypi-virt", &[&primary, &secondary]);

        let res =
            serve_simple_index_unified(&ctx, "pypi-virt", "req", SimpleIndexFormat::Json, None)
                .await
                .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let versions = served_versions_json(res).await;
        assert!(
            versions.is_empty(),
            "held primary copy filtered out, NOT replaced by the secondary's released copy: {versions:?}"
        );
    }

    #[tokio::test]
    async fn virtual_with_no_matching_versions_is_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "pypi-a", IndexMode::ReleasedOnly);
        insert_virtual_repo(&mocks, "pypi-virt", &[&a]);
        // No artifacts seeded → member returns empty → merged empty → 404.
        let err =
            serve_simple_index_unified(&ctx, "pypi-virt", "req", SimpleIndexFormat::Json, None)
                .await
                .expect_err("empty virtual must 404");
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }
}
