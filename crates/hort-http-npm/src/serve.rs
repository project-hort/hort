//! npm unified packument serve handler.
//!
//! This is the npm-side of the **Source → Filter → Builder** pipeline.
//! One handler covers both the hosted and proxy repo types:
//!
//! 1. **Source.** Dispatch on `repo.repo_type`:
//!    - `Proxy` → [`ProxyNpmSource`] (calls
//!      [`crate::packument::fetch_with_cache`] under the hood — see
//!      that function's docstring for the cache + dedup + stale-while-
//!      error contract);
//!    - anything else → [`HostedNpmSource`] (reads
//!      [`ArtifactUseCase::list_by_raw_name_visible`] — the
//!      F-25-anti-enumeration-enforcing entry point).
//! 2. **Filter pipeline.** `NonServableStatusFilter` then
//!    `IndexModeFilter::new(repo.index_mode)`. Future operator-defined
//!    exclusion filters append to this list per the design doc §2.4.
//! 3. **Builder.** [`NpmIndexBuilder`] emits the packument JSON.
//!
//! # F-25 anti-enumeration shape
//!
//! Anonymous / denied callers on a private repo receive `404`, not
//! `403`. The hosted source's `list_by_raw_name_visible` already
//! collapses denial / missing / invisible into
//! `NotFound { entity: "Repository" }`; the unified handler maps
//! that through to a 404 envelope. The proxy source re-resolves via
//! `RepositoryAccessUseCase` for defence-in-depth; same envelope.
//! Empty result sets (hosted produces zero rows; proxy parses an
//! empty `versions{}`) also map to 404 with the
//! `Artifact NotFound { id: <pkg_name> }` envelope.
//!
//! # `dist-tags.latest` regression guard
//!
//! Filtered out via the post-source filter pipeline + the builder's
//! `max_by(ordering)` over the post-filter entries. An empty served
//! set produces a packument with empty `versions{}` and **no
//! `dist-tags` block at all**. See
//! [`hort_formats::npm::index::NpmIndexBuilder`] for the per-builder
//! contract.
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
//! - **No new metrics.** The filter pipeline reuses the existing
//!   `hort_index_versions_filtered_total{format, repository}` counter
//!   (see `hort_app::use_cases::prefetch_trigger`). This handler emits it once per call across the
//!   number of versions the filter pipeline dropped (universal +
//!   mode-specific arms combined).
//! - **One `info!` line** carrying `format`, `repository`, `package`,
//!   `index_source = "hosted" | "proxy"`, and the
//!   `upstream_versions` / `served_versions` / `filtered_versions`
//!   triple. `index_source` is the new tracing field design §4
//!   added; no metric exists for it (operators dashboard from the
//!   tracing field instead per the design's explicit "tracing field,
//!   NOT a new metric" rule).

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::Response;

use hort_app::error::AppError;
use hort_app::use_cases::index_filters::{IndexModeFilter, NonServableStatusFilter};
use hort_app::use_cases::index_serve::{BuildContext, IndexFilter, VersionEntry};
use hort_app::use_cases::index_serve_filter::NpmSemverOrdering;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryType};
use hort_formats::index_serve::IndexBuilder;
use hort_formats::npm::index::NpmIndexBuilder;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::middleware::trust::RequestTrust;

use crate::index_source::{HostedNpmSource, IndexSource, IndexSourceOutput, ProxyNpmSource};

/// Unified npm packument serve — the npm-side of the Source →
/// Filter → Builder pipeline.
///
/// `caller` is threaded through the source layer; both hosted and
/// proxy sources call `RepositoryAccessUseCase::resolve(_, caller,
/// Read)` (directly or via `list_by_raw_name_visible`), so denied /
/// invisible / missing repos all collapse to a 404
/// `Repository NotFound` envelope before any rows / upstream bytes
/// are surfaced.
///
/// On success returns a 200 `application/json` response carrying the
/// packument bytes; on truncation, the same response gains a
/// `Warning: 299 - "results truncated at <cap> items"` header
/// (see `hort_domain::types::LIMIT_LIST_MAX_ITEMS`).
#[tracing::instrument(
    skip(ctx, trust, caller),
    fields(repo_key = %repo_key, pkg = %pkg_name),
)]
pub(crate) async fn serve_packument_unified(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    pkg_name: &str,
    trust: &RequestTrust,
    caller: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // ---- Resolve the repo + access check -----------------------------
    // F-25: this is the central anti-enumeration hop.
    // Anonymous on private collapses to `NotFound { entity: "Repository" }`
    // — same 404 envelope as a missing repo. The hosted source re-
    // resolves through `list_by_raw_name_visible` (its own access check),
    // and the proxy source re-resolves defensively; this top-level
    // resolve gives the proxy branch a `Repository` to inspect
    // `repo_type` on without an extra check round.
    let repo: Repository = ctx
        .repository_access_use_case
        .resolve(repo_key, caller, AccessLevel::Read)
        .await
        .map_err(ApiError::from)?;

    // Resolve the client-facing base URL once. The proxy source
    // borrows it; the builder constructs the absolute `dist.tarball`
    // from `{base_url}/npm/{repo_key}/...`.
    let base_url = ctx.url_resolver.resolve(trust);
    let base_str = format!(
        "{}/npm/{}",
        base_url.as_str().trim_end_matches('/'),
        repo_key
    );

    // ---- Step 1: Source dispatch -------------------------------------
    let (output, index_source_label): (IndexSourceOutput, &'static str) = match repo.repo_type {
        RepositoryType::Proxy => {
            let src = ProxyNpmSource;
            let out = src
                .fetch(ctx, &repo, pkg_name, caller)
                .await
                .map_err(map_source_error)?;
            (out, "proxy")
        }
        _ => {
            let src = HostedNpmSource;
            let out = src
                .fetch(ctx, &repo, pkg_name, caller)
                .await
                .map_err(ApiError::from)?;
            (out, "hosted")
        }
    };

    // Empty hosted results → 404.
    // For proxy the equivalent path was: `NoUpstream` → 404 (raised
    // at the source layer above); a parsed-empty packument is allowed
    // and produces a packument with empty `versions{}`.
    if matches!(
        repo.repo_type,
        RepositoryType::Hosted | RepositoryType::Staging | RepositoryType::Virtual
    ) && output.entries.is_empty()
    {
        return Err(ApiError::from(AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Artifact",
                id: pkg_name.to_string(),
            },
        )));
    }

    // ---- Step 2: Filter pipeline -------------------------------------
    // `NonServableStatusFilter` first (universal — drops
    // Quarantined/Rejected/ScanIndeterminate regardless of mode), then
    // `IndexModeFilter` for the mode-specific never-ingested handling.
    // Future operator-exclusion filters append at the end of this list.
    let upstream_count = output.entries.len();
    let filters: Vec<Arc<dyn IndexFilter>> = vec![
        Arc::new(NonServableStatusFilter),
        Arc::new(IndexModeFilter::new(repo.index_mode)),
    ];
    let filtered: Vec<VersionEntry> = filters.iter().fold(output.entries, |acc, f| f.apply(acc));
    let served_count = filtered.len();
    let filtered_count = upstream_count.saturating_sub(served_count);

    // Emit the per-call filter metric once, summed across the filters
    // that fired (universal + mode arms). The catalog axis stays
    // `{format, repository}`.
    if filtered_count > 0 {
        metrics::counter!(
            "hort_index_versions_filtered_total",
            "format" => "npm",
            "repository" => repo_key.to_string(),
        )
        .increment(filtered_count as u64);
    }

    tracing::info!(
        package = %pkg_name,
        repository = %repo_key,
        index_source = index_source_label,
        index_mode = %repo.index_mode,
        upstream_versions = upstream_count,
        served_versions = served_count,
        filtered_versions = filtered_count,
        "npm unified packument serve completed",
    );

    // ---- Step 3: Build the wire bytes --------------------------------
    let builder = NpmIndexBuilder;
    let body_bytes = builder.build(
        BuildContext {
            package_name: &output.canonical_name,
            base_url: &base_str,
            index_mode: repo.index_mode,
            ordering: &NpmSemverOrdering,
        },
        filtered,
    );

    let mut builder_resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");
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

/// Map an [`AppError`] coming out of [`ProxyNpmSource::fetch`] to an
/// [`ApiError`] preserving the wire shape:
///
/// - `External(_)` (upstream unavailable, no cache fallback) → 502
///   bad-gateway with the `{"error":"upstream unavailable"}` envelope.
/// - Anything else → default `ApiError::from(AppError)` mapping.
///
/// The proxy-source-only `External` arm is handled here so the
/// shared `ApiError::from(AppError::External(...))` mapping (which
/// is the generic 500 / 502 path) can stay agnostic of the npm
/// dispatch contract.
fn map_source_error(err: AppError) -> ApiError {
    match err {
        AppError::External(msg) if msg.contains("npm upstream unavailable") => {
            // Construct an `ApiError` whose response body matches the
            // wire shape byte-for-byte. The simplest path: build the
            // response through the
            // `ApiError::from(AppError::External(...))` mapping —
            // matches the 502 envelope the dispatch site hand-built.
            //
            // `ApiError` doesn't have a typed 502 constructor; the
            // closest analogue is to wrap as `External` and let the
            // generic mapping emit 502. We preserve the message so
            // downstream telemetry (if any keys on it) still sees the
            // same string.
            ApiError::from(AppError::External(msg))
        }
        other => ApiError::from(other),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unified packument serve handler tests:
    //!
    //! 1. Quarantined hosted artifact filtered out of the served
    //!    packument.
    //! 2. Rejected hosted artifact (rescan-driven) filtered out.
    //! 3. `dist-tags.latest` preservation under both `IndexMode` arms.
    //! 4. F-25 anti-enumeration — anonymous caller on a private repo
    //!    receives `NotFound`, not `403`.
    //!
    //! Plus a smoke for the truncation-`Warning` header pass-through.
    //!
    //! All tests drive the unified handler directly via
    //! [`serve_packument_unified`]; the in-`lib.rs` router-level
    //! tests (which exercise the dispatch site → unified handler hop)
    //! retain their existing coverage and continue to pin the
    //! end-to-end wire shape.

    use std::sync::Arc;

    use axum::response::IntoResponse;
    use chrono::Utc;
    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::{IndexMode, RepositoryFormat};
    use hort_domain::types::ContentHash;
    use hort_http_core::middleware::trust::RequestTrust;
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

    /// Build a `RequestTrust` matching the default unit-test
    /// bind-address fallback (`http://0.0.0.0:8080/`) so tests get a
    /// stable resolved public URL without depending on a per-request
    /// `Host` header.
    fn trust_for_tests() -> RequestTrust {
        RequestTrust {
            client_ip: "127.0.0.1".parse().unwrap(),
            public_url: url::Url::parse("http://0.0.0.0:8080/").unwrap(),
        }
    }

    fn insert_hosted_repo(
        mocks: &hort_http_core::test_support::MockPorts,
        key: &str,
        mode: IndexMode,
    ) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.into();
        repo.format = RepositoryFormat::Npm;
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
        shasum: &str,
        status: QuarantineStatus,
    ) -> Artifact {
        let sha256: ContentHash = format!(
            "{:0>64}",
            format!("{name}{version}")
                .bytes()
                .map(|b| b as u64)
                .sum::<u64>()
        )
        .parse()
        .unwrap_or_else(|_| {
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
            path: format!("{name}/-/{filename}"),
            size_bytes: 100,
            sha256_checksum: sha256,
            sha1_checksum: Some(shasum.into()),
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: status,
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

    // -----------------------------------------------------------------
    // 1. Quarantined hosted artifact filtered out of the served packument.
    //    Three versions seeded; the Quarantined one (1.1.0) MUST NOT
    //    appear in `versions{}`. dist-tags.latest MUST point at 1.2.0
    //    (the semver-max of the served set), NOT 1.1.0.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn quarantined_hosted_artifact_is_filtered_from_served_packument() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "npm-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.0.0",
            "pkg-1.0.0.tgz",
            "aaa",
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.1.0",
            "pkg-1.1.0.tgz",
            "bbb",
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.2.0",
            "pkg-1.2.0.tgz",
            "ccc",
            QuarantineStatus::Released,
        );

        let trust = trust_for_tests();
        let res = serve_packument_unified(&ctx, "npm-test", "pkg", &trust, None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let versions = json["versions"].as_object().unwrap();
        assert!(
            versions.contains_key("1.0.0"),
            "1.0.0 (Released) must be served"
        );
        assert!(
            !versions.contains_key("1.1.0"),
            "1.1.0 (Quarantined) MUST be filtered out by NonServableStatusFilter"
        );
        assert!(
            versions.contains_key("1.2.0"),
            "1.2.0 (Released) must be served"
        );
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.2.0",
            "dist-tags.latest must be the semver-max of the SERVED set, not the upstream set"
        );
    }

    // -----------------------------------------------------------------
    // 2. Rejected hosted artifact (rescan-driven) filtered out.
    //    The operator-visible value-add — a long-released artifact that
    //    the rescan path transitioned to Rejected disappears from the
    //    served packument.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rejected_hosted_artifact_is_filtered_from_served_packument() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "npm-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.0.0",
            "pkg-1.0.0.tgz",
            "aaa",
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.1.0",
            "pkg-1.1.0.tgz",
            "bbb",
            QuarantineStatus::Rejected,
        );

        let trust = trust_for_tests();
        let res = serve_packument_unified(&ctx, "npm-test", "pkg", &trust, None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"));
        assert!(
            !versions.contains_key("1.1.0"),
            "1.1.0 (Rejected via rescan) MUST be filtered by NonServableStatusFilter",
        );
        assert_eq!(json["dist-tags"]["latest"].as_str().unwrap(), "1.0.0");
    }

    // -----------------------------------------------------------------
    // 3. dist-tags.latest preservation under both IndexMode arms.
    //    On hosted, the two modes collapse to "filter to {Released,
    //    None}" — but the explicit per-mode invocation pins the
    //    contract (a future mode-divergence wouldn't go unnoticed).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dist_tags_latest_preserved_under_released_only_mode() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "npm-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.0.0",
            "pkg-1.0.0.tgz",
            "aaa",
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "2.0.0",
            "pkg-2.0.0.tgz",
            "bbb",
            QuarantineStatus::Released,
        );

        let trust = trust_for_tests();
        let res = serve_packument_unified(&ctx, "npm-test", "pkg", &trust, None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "2.0.0",
            "ReleasedOnly mode: dist-tags.latest = semver-max of served Released set",
        );
    }

    #[tokio::test]
    async fn dist_tags_latest_preserved_under_include_pending_mode() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "npm-test", IndexMode::IncludePending);
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "1.0.0",
            "pkg-1.0.0.tgz",
            "aaa",
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "pkg",
            "2.0.0",
            "pkg-2.0.0.tgz",
            "bbb",
            QuarantineStatus::Released,
        );

        let trust = trust_for_tests();
        let res = serve_packument_unified(&ctx, "npm-test", "pkg", &trust, None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "2.0.0",
            "IncludePending mode: dist-tags.latest = semver-max of served set"
        );
    }

    // -----------------------------------------------------------------
    // 4. F-25 anti-enumeration — anonymous caller on a private repo
    //    receives NotFound (not 403). Mirrors the existing
    //    `anonymous_get_packument_on_private_repo_returns_404` shape
    //    but tests the unified handler directly.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn anonymous_caller_on_private_repo_receives_not_found_not_forbidden() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());

        // Flip the access use case to Enabled with an empty RBAC
        // evaluator (no claims grant any access). The analogous test
        // (`enabled_rbac_harness` in `lib.rs::tests`) proves the
        // dispatch site honours this; the unified handler must preserve
        // the property.
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx, access);

        let mut repo = sample_repository();
        repo.key = "private-npm".into();
        repo.format = RepositoryFormat::Npm;
        repo.repo_type = RepositoryType::Hosted;
        repo.is_public = false;
        mocks.repositories.insert(repo.clone());
        insert_artifact(
            &mocks,
            repo.id,
            "secret-pkg",
            "1.0.0",
            "secret-pkg-1.0.0.tgz",
            "aaa",
            QuarantineStatus::Released,
        );

        let trust = trust_for_tests();
        let err = serve_packument_unified(&ctx, "private-npm", "secret-pkg", &trust, None)
            .await
            .expect_err("anonymous on private MUST be denied");
        // The unified handler returns `ApiError`; we inspect its
        // status mapping. F-25 anti-enumeration: the envelope MUST be
        // 404, never 403.
        let response = err.into_response();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "F-25 anti-enumeration: denied caller MUST receive 404, NEVER 403",
        );
    }

    // -----------------------------------------------------------------
    // 5. Smoke: 404 envelope on a missing package, hosted repo
    //    visible. Pins the empty-entries-→ 404 path of the unified
    //    handler (the local-CAS-handler's `artifact_list.is_empty()` arm).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn missing_package_on_visible_hosted_repo_returns_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let _repo = insert_hosted_repo(&mocks, "npm-test", IndexMode::ReleasedOnly);

        let trust = trust_for_tests();
        let err = serve_packument_unified(&ctx, "npm-test", "missing-pkg", &trust, None)
            .await
            .expect_err("missing package must 404");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------
    // 6. ProxyNpmSource — happy path through the unified handler.
    //    Pins the proxy-side of the new pipeline: upstream packument
    //    parsed → per-version `VersionEntry` materialised → builder
    //    emits the same `dist.tarball` URL shape the rewriter produced.
    //    The cache + dedup + stale-while-error machinery
    //    (`fetch_with_cache`) is exercised in `packument::tests`; this
    //    test covers the new parse-and-construct step `ProxyNpmSource`
    //    layers on top.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn proxy_repo_unified_serve_emits_rewritten_tarball_url() {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());

        let mut repo = sample_repository();
        repo.key = "npm-mirror".into();
        repo.format = RepositoryFormat::Npm;
        repo.repo_type = RepositoryType::Proxy;
        repo.upstream_url = Some("https://registry.npmjs.org".into());
        repo.index_mode = IndexMode::IncludePending;
        mocks.repositories.insert(repo.clone());

        // Seed an upstream mapping so `fetch_with_cache` resolves it.
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo.id,
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

        let upstream = serde_json::json!({
            "name": "express",
            "versions": {
                "1.0.0": {
                    "name": "express",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/express/-/express-1.0.0.tgz",
                        "integrity": "sha512-aGVsbG8=",
                        "shasum": "abc123",
                    },
                },
            },
        });
        mocks.upstream_proxy.insert_metadata(
            "",
            "/express",
            serde_json::to_vec(&upstream).unwrap(),
        );

        let trust = trust_for_tests();
        let res = serve_packument_unified(&ctx, "npm-mirror", "express", &trust, None)
            .await
            .unwrap_or_else(|_| panic!("proxy unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // dist.tarball MUST be rewritten — never carries the raw
        // upstream host bytes.
        let tarball = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(
            tarball.contains("/npm/npm-mirror/express/-/express-1.0.0.tgz"),
            "rewritten tarball must embed the local base URL: {tarball}"
        );
        assert!(
            !tarball.contains("registry.npmjs.org"),
            "rewritten tarball must NOT carry the upstream host: {tarball}"
        );
        // dist.integrity / dist.shasum preserved verbatim.
        assert_eq!(
            json["versions"]["1.0.0"]["dist"]["integrity"]
                .as_str()
                .unwrap(),
            "sha512-aGVsbG8="
        );
        assert_eq!(
            json["versions"]["1.0.0"]["dist"]["shasum"]
                .as_str()
                .unwrap(),
            "abc123"
        );
        // dist-tags.latest is the served-max (1.0.0 is the only entry).
        assert_eq!(json["dist-tags"]["latest"].as_str().unwrap(), "1.0.0");
    }

    // -----------------------------------------------------------------
    // 7. The drift-resilience pin — top-level `name` reflects the
    //    STORED canonical name, not the request parameter. Mirrors
    //    `packument_recovers_drift_era_artifact_and_follow_up_download_hits`
    //    from `lib.rs::tests` but exercises the unified handler.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn unified_handler_reflects_stored_canonical_name_under_drift() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "npm-test", IndexMode::ReleasedOnly);

        // The drift: request is for "drift-pkg" but the stored
        // artifact's name is "legacy-name". The use case's
        // `list_by_raw_name_visible` performs the normalisation-drift
        // fallback; the unified handler embeds the stored name.
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            name: "legacy-name".into(),
            name_as_published: "drift-pkg".into(),
            version: Some("1.0.0".into()),
            path: "legacy-name/-/legacy-name-1.0.0.tgz".into(),
            size_bytes: 100,
            sha256_checksum: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            sha1_checksum: Some("aaa".into()),
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Released,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        mocks.artifacts.insert(artifact);

        let trust = trust_for_tests();
        let res = serve_packument_unified(&ctx, "npm-test", "drift-pkg", &trust, None)
            .await
            .unwrap_or_else(|_| panic!("drift recovery must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Top-level name carries the STORED form.
        assert_eq!(json["name"].as_str().unwrap(), "legacy-name");
        // Per-version name embeds the stored form too (drives the
        // tarball URL).
        assert_eq!(
            json["versions"]["1.0.0"]["name"].as_str().unwrap(),
            "legacy-name"
        );
        let tarball = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        // The base URL (RequestTrust default) is http://0.0.0.0:8080/;
        // the unified handler composes `/npm/{repo_key}` onto it.
        assert!(
            tarball.contains("/npm/npm-test/legacy-name/-/legacy-name-1.0.0.tgz"),
            "tarball URL must embed the stored name: {tarball}",
        );
        assert!(
            !tarball.contains("/drift-pkg/"),
            "tarball URL must NOT re-normalise the request parameter: {tarball}"
        );
    }
}
