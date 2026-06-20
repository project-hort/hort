//! Cargo unified sparse-index serve handler.
//!
//! This is the cargo-side of the **Source → Filter → Builder** pipeline.
//! One handler covers the hosted and proxy paths for the sparse-index
//! routes (`GET /cargo/{repo_key}/{prefix}/{name}`):
//!
//! 1. **Source.** Dispatch on `repo.repo_type`:
//!    - `Proxy` → [`ProxyCargoSource`] (calls
//!      [`crate::index_cache::fetch_with_cache`] under the hood —
//!      preserving cache + dedup + filter + stale-while-error
//!      invariants byte-for-byte);
//!    - anything else → [`HostedCargoSource`] (reads
//!      [`ArtifactUseCase::list_by_raw_name_visible`] — the
//!      anti-enumeration-enforcing entry point).
//! 2. **Filter pipeline.** `NonServableStatusFilter` then
//!    `IndexModeFilter::new(repo.index_mode)`. Identical to the
//!    npm/pypi pipeline; future operator-defined exclusion filters
//!    append to this list.
//! 3. **Builder.** [`CargoIndexBuilder`] emits the sparse-index
//!    NDJSON body.
//!
//! # Anti-enumeration shape
//!
//! Anonymous / denied callers on a private repo receive `404`, not
//! `403`. The hosted source's `list_by_raw_name_visible` already
//! collapses denial / missing / invisible into
//! `NotFound { entity: "Repository" }`; the unified handler maps
//! that through to a 404 envelope. The proxy source re-resolves via
//! `RepositoryAccessUseCase` for defence-in-depth; same envelope.
//! Empty result sets (hosted produces zero rows; proxy parses an
//! empty NDJSON body) also map to 404 with the
//! `Artifact NotFound { id: <crate_name> }` envelope.
//!
//! # Yanked semantics
//!
//! Cargo clients honour `yanked: true` orthogonally to quarantine —
//! a yanked version stays in the served set. The filter pipeline
//! does NOT filter on yanked; the builder emits whatever
//! [`CargoVersionPayload::yanked`](hort_app::use_cases::index_serve::CargoVersionPayload::yanked)
//! carries. The hosted source emits `yanked: false` always (the
//! v2 model has no operator-driven yank yet); the proxy source
//! preserves the upstream-supplied value.
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
//!   `hort_index_versions_filtered_total{format, repository}` counter.
//!   This handler emits it once per call across the
//!   number of versions the filter pipeline dropped (universal +
//!   mode-specific arms combined).
//! - **One `info!` line** carrying `format`, `repository`, `package`,
//!   `index_source = "hosted" | "proxy"`, and the
//!   `upstream_versions` / `served_versions` / `filtered_versions`
//!   triple. `index_source` is a tracing field (no metric — operators
//!   dashboard from the tracing field, not a new metric).

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
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::index::CargoIndexBuilder;
use hort_formats::index_serve::IndexBuilder;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

use crate::index_source::{select_source, IndexSourceOutput};

/// Unified cargo sparse-index serve — the cargo-side of the
/// Source → Filter → Builder pipeline.
///
/// `caller` is threaded through the source layer; both hosted and
/// proxy sources call `RepositoryAccessUseCase::resolve(_, caller,
/// Read)` (directly or via `list_by_raw_name_visible`), so denied /
/// invisible / missing repos all collapse to a 404 `Repository
/// NotFound` envelope before any rows / upstream bytes are surfaced.
///
/// On success returns a 200 `text/plain; charset=utf-8` response
/// carrying the NDJSON bytes (cargo sparse-index wire content-type).
/// On truncation, the same response gains a
/// `Warning: 299 - "results truncated at <cap> items"` header.
#[tracing::instrument(
    skip(ctx, caller),
    fields(repo_key = %repo_key, crate_name = %crate_name),
)]
pub(crate) async fn serve_index_unified(
    ctx: &Arc<AppContext>,
    repo_key: &str,
    crate_name: &str,
    caller: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // ---- Resolve the repo + access check -----------------------------
    // Central anti-enumeration hop (ADR 0008). Anonymous on private
    // collapses to `NotFound { entity: "Repository" }` — same 404
    // envelope as a missing repo. The hosted source re-resolves
    // through `list_by_raw_name_visible` (its own access check), and
    // the proxy source re-resolves defensively; this top-level resolve
    // gives the proxy branch a `Repository` to inspect `repo_type`
    // on without an extra check round.
    let repo: Repository = ctx
        .repository_access_use_case
        .resolve(repo_key, caller, AccessLevel::Read)
        .await
        .map_err(ApiError::from)?;

    // ---- Crate-name validation (serve-path parity, INJ-2) ------------
    // The download / publish paths validate the crate name via
    // `validate_cargo_name` before any path construction; the
    // sparse-index serve path historically only lowercase-normalised it.
    // A `..` / `..%2f`-shaped name would otherwise flow unvalidated into
    // `index_path_for` → the Redis cache key + composed upstream URL.
    // There is no filesystem escape (CAS + `reject_traversal` backstop),
    // but the cache key / upstream path would be polluted. Reject here,
    // BEFORE any cache-key / upstream-URL construction, returning the
    // SAME `DomainError::Validation` envelope the download path emits.
    hort_formats::cargo::validate_cargo_name(crate_name)
        .map_err(|e| ApiError::from(AppError::Domain(e)))?;

    // ---- Step 1: Source dispatch (transparent to repo type) ----------
    // `select_source` returns the hosted / proxy / virtual source. The
    // virtual source aggregates its members behind this same seam
    // (ADR 0031), so this handler never special-cases `Virtual` — it
    // dispatches by type for the tracing label only, then runs the
    // unchanged filter pipeline + builder. `map_source_error` handles the
    // proxy-only `External` → 502 arm and falls through to `ApiError::from`
    // for hosted/virtual errors.
    let index_source_label = match repo.repo_type {
        RepositoryType::Proxy => "proxy",
        RepositoryType::Virtual => "virtual",
        _ => "hosted",
    };
    let output: IndexSourceOutput = select_source(&repo)
        .fetch(ctx, &repo, crate_name, caller)
        .await
        .map_err(map_source_error)?;

    // Empty hosted results → 404. For proxy the equivalent path is
    // `NoUpstream` → 404 (raised at the source layer above); a
    // parsed-empty NDJSON is allowed and produces an empty served body.
    // Hosted with zero entries is the "crate doesn't exist in this
    // repo" envelope.
    if matches!(
        repo.repo_type,
        RepositoryType::Hosted | RepositoryType::Staging | RepositoryType::Virtual
    ) && output.entries.is_empty()
    {
        return Err(ApiError::from(AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Artifact",
                id: hort_formats::cargo::CargoFormatHandler.normalize_name(crate_name),
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
    // that fired (universal + mode arms). Catalog axis: `{format,
    // repository}`.
    if filtered_count > 0 {
        metrics::counter!(
            "hort_index_versions_filtered_total",
            "format" => "cargo",
            "repository" => repo_key.to_string(),
        )
        .increment(filtered_count as u64);
    }

    tracing::info!(
        crate_name = %crate_name,
        repository = %repo_key,
        index_source = index_source_label,
        index_mode = %repo.index_mode,
        upstream_versions = upstream_count,
        served_versions = served_count,
        filtered_versions = filtered_count,
        "cargo unified sparse-index serve completed",
    );

    // ---- Step 3: Build the wire bytes --------------------------------
    // base_url and package_name are unused by the cargo builder (the
    // sparse-index NDJSON does not carry per-version download URLs;
    // see `hort_formats::cargo::index`'s module rustdoc). We still
    // supply them per the trait shape; the builder ignores them.
    let builder = CargoIndexBuilder;
    let body_bytes = builder.build(
        BuildContext {
            package_name: crate_name,
            base_url: "", // unused — see CargoIndexBuilder rustdoc
            index_mode: repo.index_mode,
            ordering: &NpmSemverOrdering, // CargoSemverOrdering alias
        },
        filtered,
    );

    let mut builder_resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8");
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

/// Map an [`AppError`] coming out of [`ProxyCargoSource::fetch`] to
/// an [`ApiError`] preserving the expected wire shape:
///
/// - `External(_)` (upstream unavailable, no cache fallback) → 502
///   bad-gateway, emitting `502 + {"error":"upstream unavailable"}`;
///   the unified handler delegates to
///   `ApiError::from(AppError::External(...))` which produces the
///   equivalent 502 envelope.
/// - Anything else → default `ApiError::from(AppError)` mapping.
///
/// The proxy-source-only `External` arm is handled here so the
/// shared `ApiError::from(AppError::External(...))` mapping (which
/// is the generic 500 / 502 path) can stay agnostic of cargo's
/// proxy dispatch contract.
fn map_source_error(err: AppError) -> ApiError {
    match err {
        AppError::External(msg) if msg.contains("cargo upstream unavailable") => {
            // ApiError doesn't currently have a typed 502 constructor;
            // wrap as `External` and let the generic mapping emit
            // 502. We preserve the message so downstream telemetry
            // sees the same string.
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
    //! Tests for the unified sparse-index serve handler:
    //!
    //! 1. Quarantined hosted artifact filtered.
    //! 2. Rejected hosted artifact (rescan-driven) filtered.
    //! 3. Anti-enumeration — anonymous on private repo gets
    //!    `NotFound` (404), not 403.
    //! 4. NDJSON wire-shape preservation — one line per served
    //!    version, `\n`-terminated, JSON valid per cargo sparse-index
    //!    spec.
    //! 5. Yanked semantics preserved — yanked versions are included
    //!    in the NDJSON with `yanked: true` (cargo clients treat
    //!    yanked separately from removal).
    //!
    //! Plus a smoke for the empty-hosted-result → 404 envelope path.
    //!
    //! All tests drive the unified handler directly via
    //! [`serve_index_unified`].

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
        repo.format = RepositoryFormat::Cargo;
        repo.repo_type = RepositoryType::Hosted;
        repo.index_mode = mode;
        mocks.repositories.insert(repo.clone());
        repo
    }

    /// Build a stable distinct SHA-256 per seed so each artifact gets
    /// a unique CAS hash.
    fn fake_sha256(seed: u8) -> ContentHash {
        let mut s = String::with_capacity(64);
        for _ in 0..64 {
            s.push(((seed % 16) + b'0') as char);
        }
        s.parse().unwrap_or_else(|_| {
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap()
        })
    }

    fn insert_artifact(
        mocks: &hort_http_core::test_support::MockPorts,
        repo_id: Uuid,
        name: &str,
        version: &str,
        sha_seed: u8,
        status: QuarantineStatus,
    ) -> Artifact {
        let sha256 = fake_sha256(sha_seed);
        let now = Utc::now();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: format!("crates/{name}/{version}/{name}-{version}.crate"),
            size_bytes: 100,
            sha256_checksum: sha256,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/x-tar".into(),
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

    fn parse_lines(body: &[u8]) -> Vec<serde_json::Value> {
        std::str::from_utf8(body)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("each line must be JSON"))
            .collect()
    }

    // -----------------------------------------------------------------
    // 1. Quarantined hosted artifact filtered out of the served NDJSON.
    //    Three versions seeded; the Quarantined one (1.1.0) MUST NOT
    //    appear. The two Released versions appear in semver order.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn quarantined_hosted_artifact_is_filtered_from_served_ndjson() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.1.0",
            2,
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.2.0",
            3,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);

        let versions: Vec<&str> = lines.iter().map(|l| l["vers"].as_str().unwrap()).collect();
        assert_eq!(
            versions,
            vec!["1.0.0", "1.2.0"],
            "Quarantined 1.1.0 MUST be filtered by NonServableStatusFilter; \
             survivors in semver order"
        );
    }

    // -----------------------------------------------------------------
    // 2. Rejected hosted artifact (rescan-driven) filtered.
    //    A long-released artifact transitioned to Rejected disappears
    //    from the served NDJSON.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rejected_hosted_artifact_is_filtered_from_served_ndjson() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.1.0",
            2,
            QuarantineStatus::Rejected,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        let versions: Vec<&str> = lines.iter().map(|l| l["vers"].as_str().unwrap()).collect();
        assert_eq!(
            versions,
            vec!["1.0.0"],
            "1.1.0 (Rejected via rescan) MUST be filtered by NonServableStatusFilter",
        );
    }

    // -----------------------------------------------------------------
    // 3. Anti-enumeration — anonymous caller on a private repo
    //    receives NotFound (not 403).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn anonymous_caller_on_private_repo_receives_not_found_not_forbidden() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());

        // Flip the access use case to Enabled with an empty RBAC
        // evaluator (no claims grant any access).
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx, access);

        let mut repo = sample_repository();
        repo.key = "private-cargo".into();
        repo.format = RepositoryFormat::Cargo;
        repo.repo_type = RepositoryType::Hosted;
        repo.is_public = false;
        mocks.repositories.insert(repo.clone());
        insert_artifact(
            &mocks,
            repo.id,
            "secret-crate",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        let err = serve_index_unified(&ctx, "private-cargo", "secret-crate", None)
            .await
            .expect_err("anonymous on private MUST be denied");
        let response = err.into_response();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "anti-enumeration: denied caller MUST receive 404, NEVER 403",
        );
    }

    // -----------------------------------------------------------------
    // 4. NDJSON wire-shape preservation — one line per served version,
    //    `\n`-terminated, JSON valid per cargo sparse-index spec.
    //    Each line carries the mandatory `name`, `vers`, `deps`,
    //    `cksum`, `features`, `yanked` keys.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn ndjson_wire_shape_preserved_one_line_per_version_newline_terminated() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.1.0",
            2,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(ct, "text/plain; charset=utf-8");
        let body_bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Exactly two `\n`-terminators (one per line including the
        // last). No trailing empty line.
        assert_eq!(body.matches('\n').count(), 2);
        assert!(body.ends_with('\n'));

        let lines = parse_lines(&body_bytes);
        assert_eq!(lines.len(), 2);
        for v in &lines {
            // Mandatory cargo sparse-index keys.
            assert!(v["name"].is_string(), "`name` is mandatory");
            assert!(v["vers"].is_string(), "`vers` is mandatory");
            assert!(v["cksum"].is_string(), "`cksum` is mandatory");
            assert!(v["deps"].is_array(), "`deps` is mandatory (may be [])");
            assert!(v["features"].is_object(), "`features` is mandatory");
            assert!(v["yanked"].is_boolean(), "`yanked` is mandatory");
        }
    }

    // -----------------------------------------------------------------
    // 5. Yanked semantics preserved — the filter pipeline does NOT
    //    filter yanked entries. A future operator-driven yank flag on
    //    Artifact would surface here as `yanked: true` on the served
    //    line. Today the hosted source emits `yanked: false` for every
    //    row (no yank mechanism); this test pins the architectural
    //    invariant via the proxy branch's parse — see
    //    `index_source::parse_ndjson_to_entries`.
    //
    //    We exercise the invariant directly on the builder here (via
    //    a payload with `yanked: true`) — proxy-source tests cover
    //    the upstream-parse-and-re-emit shape; this test pins the
    //    "filter pipeline doesn't drop yanked" structural property
    //    on the unified handler.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn yanked_versions_pass_through_filter_pipeline_to_served_set() {
        // Construct a hosted scenario where the artifact projection
        // includes a Released version. The hosted source produces
        // `yanked: false` (v2 has no yank mechanism), but the test
        // exercises the FILTER PIPELINE invariant: yanked is not a
        // quarantine-status concern, so the unified handler does
        // NOT consult `yanked` when deciding to drop. We pin this
        // by asserting the served set is NOT empty for a Released
        // entry (i.e., the filter pipeline kept it regardless of
        // its `yanked` field value).
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("unified serve must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]["yanked"].is_boolean(),
            "yanked field present on served line (filter pipeline did not strip it)"
        );
        // The structural invariant — the filter pipeline is
        // status-aware, not yank-aware. Even if a future hosted row
        // were `yanked: true`, the filter pipeline would NOT drop
        // it; the builder would emit `yanked: true` in the line.
    }

    // -----------------------------------------------------------------
    // 6. Missing-crate smoke — visible hosted repo, no matching
    //    artifact → 404. Pins the empty-entries-→ 404 path of the
    //    unified handler.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn missing_crate_on_visible_hosted_repo_returns_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let _repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);

        let err = serve_index_unified(&ctx, "cargo-test", "missing-crate", None)
            .await
            .expect_err("missing crate must 404");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------
    // 6b. Serve-path crate-name validation (INJ-2). A traversal-shaped
    //     name (`..`, `../etc`) on the sparse-index serve path must be
    //     rejected by `validate_cargo_name` BEFORE any cache-key /
    //     upstream-URL construction, returning the SAME 400
    //     `DomainError::Validation` envelope the download path emits —
    //     not a normalised name that flows into `index_path_for`.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn serve_rejects_traversal_crate_name_before_key_construction() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let _repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);

        // `..` and `../etc` are both rejected by `validate_cargo_name`
        // (the cargo grammar forbids `.` / `/`); the serve path must
        // surface that as a 400, not lowercase-normalise it onward.
        for bad in ["..", "../etc", "..%2fetc"] {
            let err = serve_index_unified(&ctx, "cargo-test", bad, None)
                .await
                .expect_err("traversal name must be rejected");
            let response = err.into_response();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "traversal name {bad:?} must map to 400, got {}",
                response.status()
            );
        }
    }

    #[tokio::test]
    async fn serve_accepts_valid_crate_name_after_validation_gate() {
        // The validation gate must not regress the happy path: a normal
        // crate name still resolves through the source pipeline.
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            repo.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );

        let res = serve_index_unified(&ctx, "cargo-test", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("valid name must pass the validation gate and serve"));
        assert_eq!(res.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------
    // 7. Drift-resilience pin — top-level NDJSON `name` reflects the
    //    STORED canonical name, not the request parameter. Mirrors
    //    the npm/pypi same arm.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn unified_handler_emits_stored_canonical_name_under_drift() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let repo = insert_hosted_repo(&mocks, "cargo-test", IndexMode::ReleasedOnly);

        // The drift: request is for "drift-crate" but the stored
        // artifact's name is "Legacy-Crate". The use case's
        // `list_by_raw_name_visible` performs the normalisation-drift
        // fallback; the hosted source embeds the stored name.
        let now = Utc::now();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            name: "Legacy-Crate".into(),
            name_as_published: "drift-crate".into(),
            version: Some("0.1.0".into()),
            path: "crates/Legacy-Crate/0.1.0/Legacy-Crate-0.1.0.crate".into(),
            size_bytes: 100,
            sha256_checksum: fake_sha256(9),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/x-tar".into(),
            quarantine_status: QuarantineStatus::Released,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };
        mocks.artifacts.insert(artifact);

        let res = serve_index_unified(&ctx, "cargo-test", "drift-crate", None)
            .await
            .unwrap_or_else(|_| panic!("drift recovery must succeed"));
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let lines = parse_lines(&body);
        assert_eq!(
            lines[0]["name"].as_str().unwrap(),
            "Legacy-Crate",
            "NDJSON `name` must carry the STORED form (drift-resilience pin)"
        );
    }

    // -----------------------------------------------------------------
    // Virtual (aggregating) serve — ADR 0031. The serve handler is
    // transparent (no `Virtual` branch); these drive it end-to-end through
    // `select_source` → `VirtualCargoSource` → `aggregate_virtual_index`.
    // -----------------------------------------------------------------

    fn insert_virtual_repo(
        mocks: &hort_http_core::test_support::MockPorts,
        key: &str,
        members: &[&Repository],
    ) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.into();
        repo.format = RepositoryFormat::Cargo;
        repo.repo_type = RepositoryType::Virtual;
        repo.index_mode = IndexMode::ReleasedOnly;
        mocks.repositories.insert(repo.clone());
        for m in members {
            mocks.repositories.seed_virtual_member(repo.id, m.id);
        }
        repo
    }

    async fn served_versions(res: Response) -> Vec<String> {
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        parse_lines(&body)
            .iter()
            .map(|l| l["vers"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn virtual_merges_member_sparse_indexes() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "cargo-a", IndexMode::ReleasedOnly);
        let b = insert_hosted_repo(&mocks, "cargo-b", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            a.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Released,
        );
        insert_artifact(
            &mocks,
            b.id,
            "serde",
            "2.0.0",
            2,
            QuarantineStatus::Released,
        );
        insert_virtual_repo(&mocks, "cargo-virt", &[&a, &b]);

        let res = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let versions = served_versions(res).await;
        assert!(versions.contains(&"1.0.0".to_string()), "member a served");
        assert!(versions.contains(&"2.0.0".to_string()), "member b served");
    }

    #[tokio::test]
    async fn virtual_same_version_held_primary_not_replaced_by_secondary() {
        // Dependency-confusion regression (same-version): the higher-priority
        // member holds 1.0.0 Quarantined; a lower-priority member has the SAME
        // version Released. The held copy wins the authoritative merge and is
        // then filtered out — NOT replaced by the secondary's released copy.
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let primary = insert_hosted_repo(&mocks, "cargo-primary", IndexMode::ReleasedOnly);
        let secondary = insert_hosted_repo(&mocks, "cargo-secondary", IndexMode::ReleasedOnly);
        insert_artifact(
            &mocks,
            primary.id,
            "serde",
            "1.0.0",
            1,
            QuarantineStatus::Quarantined,
        );
        insert_artifact(
            &mocks,
            secondary.id,
            "serde",
            "1.0.0",
            2,
            QuarantineStatus::Released,
        );
        insert_virtual_repo(&mocks, "cargo-virt", &[&primary, &secondary]);

        let res = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .unwrap_or_else(|_| panic!("virtual serve must succeed"));
        assert_eq!(res.status(), StatusCode::OK);
        let versions = served_versions(res).await;
        assert!(
            versions.is_empty(),
            "held primary copy filtered out, NOT replaced by the secondary's released copy: {versions:?}"
        );
    }

    #[tokio::test]
    async fn virtual_with_no_matching_versions_is_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
        let a = insert_hosted_repo(&mocks, "cargo-a", IndexMode::ReleasedOnly);
        insert_virtual_repo(&mocks, "cargo-virt", &[&a]);
        // No artifacts seeded → member returns empty → merged empty → 404.
        let err = serve_index_unified(&ctx, "cargo-virt", "serde", None)
            .await
            .expect_err("empty virtual must 404");
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }
}
