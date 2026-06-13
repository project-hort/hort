//! Universal `NonServableStatusFilter` smoke + rescan-rejection
//! visibility integration test.
//!
//! The `NonServableStatusFilter` is the rescan-rejection closer in the
//! unified index-construction pipeline (see
//! `docs/architecture/explanation/index-construction.md`).
//!
//! # What this pins
//!
//! The operator-visible value-add the unified index-construction
//! pipeline ships: a hosted-repo artifact that is currently visible in
//! the served index transitions to `Rejected` via the rescan path, and
//! the NEXT index serve OMITS the rejected version. The per-format
//! unit tests already pin the filter at the inline-serve
//! tier with hand-constructed `Rejected` artifacts; this end-to-end
//! test exercises the full state-transition path:
//!
//! 1. Hosted artifact at status `None` (permissive mode, the only
//!    `record_scan_result`-reachable pre-state for which the artifact
//!    is BOTH served by the index AND can transition to `Rejected`).
//!    Permissive mode (`quarantineDuration:0`) is wired by the mock
//!    harness's default `seed_permissive_global_policy_for_tests`
//!    (Critical-threshold default policy with `quarantine_duration_secs=0`).
//! 2. `QuarantineUseCase::record_scan_result(findings)` invoked
//!    DIRECTLY on the use case — NOT through worker dispatch /
//!    cron-rescan-tick / job-queue. Per the direct-call
//!    discipline, the use case is the smallest seam producing the
//!    same `ScanCompleted(findings) → ArtifactRejected` projection
//!    state the production rescan path produces (the worker runs the
//!    scan, then calls `record_scan_result`); spinning up the worker
//!    infrastructure for a smoke test would explode the test surface
//!    for zero additional pin value.
//! 3. The default-policy critical-threshold reject path flips the
//!    artifact's `quarantine_status` from `None` to `Rejected` (per
//!    `Artifact::reject_from_scan` — accepts the `None` and
//!    `Quarantined` pre-states; the `None` pre-state is the
//!    permissive-mode rescan-rejection path described in
//!    `docs/architecture/explanation/index-construction.md`).
//! 4. The next index serve for that package OMITS the rejected
//!    version — the `NonServableStatusFilter` (universal, mode-
//!    agnostic) drops `Rejected` entries from the unified handler's
//!    filter pipeline. **This is the pipeline's operator-visible value-add.**
//!
//! # Pre-state choice — `None` vs `Released` vs `Quarantined`
//!
//! `Artifact::reject_from_scan` rejects from `{Quarantined, None}`
//! only (`reject_from_scan_from_released_fails` and
//! `reject_from_scan_from_rejected_fails` pin this invariant in
//! `hort-domain`). `Released → Rejected` requires
//! `reject_from_retroactive_curation`, not `record_scan_result`.
//! Of the two reachable pre-states:
//!
//! - `Quarantined` is filtered by `NonServableStatusFilter` already
//!   in the BEFORE state — the "before" assertion would fail.
//! - `None` (permissive mode) IS served in the before state under
//!   either `IndexMode` (the filter table at the top of
//!   `index_filters.rs` keeps `None` under both modes). After
//!   `record_scan_result`, status flips to `Rejected`, and the
//!   filter drops it.
//!
//! `None` is therefore the only pre-state that pins the full
//! visibility transition through `record_scan_result`. The
//! permissive-mode rescan-rejection flow is exactly the documented
//! production flow: a hosted repo with
//! `quarantineDuration:0` ingests artifacts with `status = None`,
//! and a later rescan finding flips them to `Rejected`.
//!
//! # Mock vs real DB
//!
//! All assertions hit mocks — no real Postgres connection acquired.
//! `MockArtifactLifecycle::commit_scan_result_with_score` mutates
//! the underlying `MockArtifactRepository` via `self.artifacts.insert(...)`
//! (see `hort_app::use_cases::test_support`), so the post-`record_scan_result`
//! projection read by the unified handler's hosted source reflects the
//! `None → Rejected` transition. This means `#[serial(hort_pg_db)]` is
//! NOT applied — no shared-DB contention; the tests are parallel-safe.
//!
//! # Format parameterisation
//!
//! The three v2 formats (npm packument, PyPI simple-index HTML+JSON,
//! Cargo sparse-index NDJSON) each get their own `#[tokio::test]`
//! that drives the same scenario through the unified serve handler
//! for that format. One file, four tests (PyPI HTML and JSON are
//! separate so a future content-type-specific regression surfaces
//! against the right test, not the wrong one). `#[rstest]` was
//! considered but rejected: per-format assertions (JSON vs HTML vs
//! NDJSON shape) diverge enough that a per-format `#[tokio::test]`
//! is more readable than a parameterised body branching on format.
//!
//! # Why this test exists separately from the per-format unit tests
//!
//! The per-format unit tests pin the filter at the inline `serve.rs`
//! tier with a hand-constructed `Rejected` artifact — they validate
//! the filter is wired, not the rescan transition. This test pins the
//! end-to-end state-transition path through `record_scan_result` →
//! `NonServableStatusFilter` → omitted-from-index.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::use_cases::test_support::{sample_artifact, sample_repository};
use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::repository::{Repository, RepositoryFormat, RepositoryType};
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::types::finding::severity_summary_from_findings;
use hort_domain::types::{ContentHash, Finding};
use hort_http_core::context::AppContext;
use hort_http_core::test_support::{
    build_mock_ctx, trust_config_untrusted_peer_fallback, with_trust_config, MockPorts,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Build a mock `AppContext` plus the `MockPorts` handle bag. The
/// trust config is overridden to the untrusted-peer fallback so
/// `RequestTrust` resolves with stable values from the `Host`
/// header (npm and cargo need this for absolute-URL composition;
/// pypi uses relative URLs and is unaffected).
fn make_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    let (ctx, mocks) = build_mock_ctx(handle);
    let ctx = with_trust_config(&ctx, trust_config_untrusted_peer_fallback());
    (ctx, mocks)
}

/// Insert a hosted repository of the given format and return the
/// constructed `Repository`.
///
/// The `IndexMode` is `ReleasedOnly` (the production default for
/// hosted repos). Under `ReleasedOnly` the `IndexModeFilter` keeps
/// `Some(None | Released)` entries — so a hosted artifact at status
/// `None` (permissive mode) IS served. After the rescan flips it to
/// `Rejected`, the universal `NonServableStatusFilter` drops it.
fn insert_hosted_repo(mocks: &MockPorts, key: &str, format: RepositoryFormat) -> Repository {
    let mut repo = sample_repository();
    repo.key = key.to_string();
    repo.format = format;
    repo.repo_type = RepositoryType::Hosted;
    mocks.repositories.insert(repo.clone());
    repo
}

/// Insert one hosted artifact at the given status, returning the
/// inserted row's `id` (so `record_scan_result` can target it).
///
/// `name_as_published` mirrors `name` (no normalisation drift); the
/// per-format tests below use lowercase names so this is a no-op for
/// all three formats today.
fn insert_artifact(
    mocks: &MockPorts,
    repo_id: Uuid,
    name: &str,
    version: &str,
    path: &str,
    status: QuarantineStatus,
) -> Uuid {
    // Synthesise a deterministic sha256 from the name+version so each
    // seeded artifact carries a distinct content hash. Used by the
    // cargo `cksum` assertion below; npm reads `dist.shasum` /
    // `dist.integrity` which we set independently.
    let sha_hex = format!(
        "{:0>64}",
        format!("{name}-{version}")
            .bytes()
            .map(u64::from)
            .sum::<u64>()
    );
    let sha256: ContentHash = sha_hex.parse().expect("synthesised sha256 parses");

    let mut artifact: Artifact = sample_artifact(status);
    artifact.repository_id = repo_id;
    artifact.name = name.into();
    artifact.name_as_published = name.into();
    artifact.version = Some(version.into());
    artifact.path = path.into();
    artifact.sha256_checksum = sha256;
    // sha1 is only consumed by the npm builder; setting it
    // unconditionally is harmless for the other formats.
    artifact.sha1_checksum = Some("a".repeat(40));
    artifact.size_bytes = 100;
    artifact.created_at = Utc::now();
    artifact.updated_at = Utc::now();
    let id = artifact.id;
    mocks.artifacts.insert(artifact);
    id
}

/// Construct a single critical-severity finding. Triggers the
/// default-policy Reject path (`SeverityThreshold::Critical` ≥ the
/// permissive-policy default's `Critical` threshold). One finding is
/// the minimal blocking set; multiple criticals would be redundant
/// for the projection-state pin.
fn single_critical_finding() -> Vec<Finding> {
    let finding = Finding {
        purl: "pkg:test/rescan-rejection@1.0.0".into(),
        vulnerability_id: "CVE-2026-TEST".into(),
        severity: SeverityThreshold::Critical,
        cvss_score: None,
        title: "rescan-rejection visibility test finding".into(),
        fixed_versions: Vec::new(),
        source_scanner: "rescan-test".into(),
        references: Vec::new(),
        aliases: Vec::new(),
    };
    // Sanity-check the validator against our hand-built fixture so a
    // future field-cap change surfaces against this test, not a
    // confusing production failure further down the call chain.
    finding.validate().expect("test finding must validate");
    let _ = severity_summary_from_findings(std::slice::from_ref(&finding));
    vec![finding]
}

/// Drive `QuarantineUseCase::record_scan_result` directly. Per the
/// direct-call discipline, this is the smallest seam that
/// produces the same `ScanCompleted(findings) → ArtifactRejected`
/// projection state the production rescan path produces (worker
/// claims a `kind='scan'` job → `scan_orchestration::run` → invokes
/// `record_scan_result`). Spinning up the worker for a smoke test
/// would explode the test surface for zero additional pin value.
async fn invoke_rescan_reject(ctx: &Arc<AppContext>, artifact_id: Uuid) {
    ctx.quarantine_use_case
        .record_scan_result(
            artifact_id,
            "rescan-rejection-test-scanner".into(),
            single_critical_finding(),
            None,
        )
        .await
        .expect("record_scan_result must transition None → Rejected");
}

/// Assert the artifact's `quarantine_status` is now `Rejected`. The
/// mock lifecycle's `commit_scan_result_with_score` (in
/// `hort-app::use_cases::test_support`) mutates the underlying
/// `MockArtifactRepository` via `self.artifacts.insert(artifact)`,
/// so this projection read reflects the post-record state.
fn assert_artifact_rejected(mocks: &MockPorts, artifact_id: Uuid) {
    let updated = mocks
        .artifacts
        .get(artifact_id)
        .expect("artifact projection must exist post-record");
    assert_eq!(
        updated.quarantine_status,
        QuarantineStatus::Rejected,
        "record_scan_result with a critical finding must flip None → Rejected \
         (the projection state the production rescan path also reaches)",
    );
}

// ---------------------------------------------------------------------------
// npm — packument
// ---------------------------------------------------------------------------

/// Build the npm-only router slice with the request-trust layer
/// attached (the unified packument handler reads
/// `RequestTrust.public_url` to compose absolute `dist.tarball`
/// URLs).
fn npm_router(ctx: Arc<AppContext>) -> Router {
    let trust_cfg = ctx.trust_config.clone();
    Router::new()
        .nest("/npm", hort_http_npm::npm_routes())
        .layer(hort_http_core::middleware::trust::request_trust_layer(
            trust_cfg,
        ))
        .with_state(ctx)
}

async fn get_packument(
    router: &Router,
    repo_key: &str,
    pkg: &str,
) -> (StatusCode, serde_json::Value) {
    let res = router
        .clone()
        .oneshot(
            Request::get(format!("/npm/{repo_key}/{pkg}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = if status == StatusCode::OK {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };
    (status, json)
}

/// Pin: hosted npm artifact at `None` is visible; rescan with a
/// critical finding flips it to `Rejected`; the next packument
/// omits the version. Mirrors the npm unit tier's inline
/// `rejected_hosted_artifact_is_filtered_from_served_packument`
/// but exercises `record_scan_result` end-to-end through the
/// `AppContext.quarantine_use_case` rather than seeding a
/// pre-`Rejected` artifact directly.
#[tokio::test]
async fn npm_rescan_rejection_closes_packument_visibility() {
    let (ctx, mocks) = make_ctx();
    let repo = insert_hosted_repo(&mocks, "npm-rescan", RepositoryFormat::Npm);
    let artifact_id = insert_artifact(
        &mocks,
        repo.id,
        "rescan-pkg",
        "1.0.0",
        "rescan-pkg/-/rescan-pkg-1.0.0.tgz",
        QuarantineStatus::None,
    );
    let router = npm_router(ctx.clone());

    // BEFORE: status=None under ReleasedOnly is servable → 1.0.0 in
    // the packument's `versions` map.
    let (before_status, before_body) = get_packument(&router, "npm-rescan", "rescan-pkg").await;
    assert_eq!(
        before_status,
        StatusCode::OK,
        "before-state packument must serve (status=None permissive mode)",
    );
    let before_versions = before_body["versions"]
        .as_object()
        .expect("before-state packument must carry a versions object");
    assert!(
        before_versions.contains_key("1.0.0"),
        "before-state packument MUST include 1.0.0 (status=None is servable): \
         body = {before_body}",
    );

    // TRANSITION: invoke record_scan_result directly. Produces
    // ScanCompleted + PolicyEvaluated(Fail) + ArtifactRejected (the
    // same event triple the production rescan path produces).
    invoke_rescan_reject(&ctx, artifact_id).await;
    assert_artifact_rejected(&mocks, artifact_id);

    // AFTER: NonServableStatusFilter drops the Rejected entry — the
    // next packument either omits the version OR (if it was the only
    // version) returns 404. Both shapes are valid per the unified
    // serve handler — assert the universal property: 1.0.0 MUST NOT
    // appear in any served versions map.
    let (after_status, after_body) = get_packument(&router, "npm-rescan", "rescan-pkg").await;
    // The unified handler's empty-result 404 path mirrors the
    // earlier per-format `serve_packument`; a single rejected artifact
    // leaves zero servable entries → 404. If a future change keeps
    // the 200 + empty versions shape, the contains_key assertion
    // still holds because the Rejected version is filtered out.
    match after_status {
        StatusCode::NOT_FOUND => {
            // Empty-result 404 — the universal property holds
            // vacuously (no version is served, so the rejected one
            // is not served).
        }
        StatusCode::OK => {
            let after_versions = after_body["versions"]
                .as_object()
                .expect("after-state OK packument must carry a versions object");
            assert!(
                !after_versions.contains_key("1.0.0"),
                "after-state packument MUST omit 1.0.0 (Rejected via rescan): \
                 body = {after_body}",
            );
        }
        other => panic!(
            "after-state packument returned unexpected status {other:?}; expected 200 or 404",
        ),
    }
}

// ---------------------------------------------------------------------------
// PyPI — simple-index (HTML + JSON, separate tests)
// ---------------------------------------------------------------------------

fn pypi_router(ctx: Arc<AppContext>) -> Router {
    let trust_cfg = ctx.trust_config.clone();
    Router::new()
        .nest("/pypi", hort_http_pypi::pypi_routes())
        .layer(hort_http_core::middleware::trust::request_trust_layer(
            trust_cfg,
        ))
        .with_state(ctx)
}

async fn get_simple_html(router: &Router, repo_key: &str, project: &str) -> (StatusCode, String) {
    let res = router
        .clone()
        .oneshot(
            Request::get(format!("/pypi/{repo_key}/simple/{project}/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&body).into_owned();
    (status, text)
}

async fn get_simple_json(
    router: &Router,
    repo_key: &str,
    project: &str,
) -> (StatusCode, serde_json::Value) {
    let res = router
        .clone()
        .oneshot(
            Request::get(format!("/pypi/{repo_key}/simple/{project}/"))
                .header(header::ACCEPT, "application/vnd.pypi.simple.v1+json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = if status == StatusCode::OK {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };
    (status, json)
}

/// Pin: hosted pypi artifact at `None` is visible in the HTML
/// simple-index; rescan flips it to `Rejected`; the next HTML
/// simple-index omits the file. Mirrors the PyPI unit tier's
/// HTML-content-type filter assertion via end-to-end transition.
#[tokio::test]
async fn pypi_html_rescan_rejection_closes_simple_index_visibility() {
    let (ctx, mocks) = make_ctx();
    let repo = insert_hosted_repo(&mocks, "pypi-rescan", RepositoryFormat::Pypi);
    let artifact_id = insert_artifact(
        &mocks,
        repo.id,
        "rescan-pkg",
        "1.0.0",
        "simple/rescan-pkg/rescan-pkg-1.0.0.tar.gz",
        QuarantineStatus::None,
    );
    let router = pypi_router(ctx.clone());

    let (before_status, before_html) = get_simple_html(&router, "pypi-rescan", "rescan-pkg").await;
    assert_eq!(
        before_status,
        StatusCode::OK,
        "before-state HTML simple-index must serve (status=None permissive mode)",
    );
    assert!(
        before_html.contains("rescan-pkg-1.0.0.tar.gz"),
        "before-state HTML MUST include rescan-pkg-1.0.0.tar.gz: html = {before_html}",
    );

    invoke_rescan_reject(&ctx, artifact_id).await;
    assert_artifact_rejected(&mocks, artifact_id);

    let (after_status, after_html) = get_simple_html(&router, "pypi-rescan", "rescan-pkg").await;
    // Same as npm: either 404 (empty-result, universal property
    // holds vacuously) or 200 + the rejected file absent.
    match after_status {
        StatusCode::NOT_FOUND => {}
        StatusCode::OK => {
            assert!(
                !after_html.contains("rescan-pkg-1.0.0.tar.gz"),
                "after-state HTML MUST omit rescan-pkg-1.0.0.tar.gz (Rejected via rescan): \
                 html = {after_html}",
            );
        }
        other => panic!(
            "after-state HTML simple-index returned unexpected status {other:?}; \
             expected 200 or 404",
        ),
    }
}

/// PEP 691 JSON variant of the above — the per-format builder splits
/// on content-type, so both arms must filter. The PyPI unit-tier
/// tests pin each independently; this test pins the
/// end-to-end transition through the JSON content-type negotiation.
#[tokio::test]
async fn pypi_json_rescan_rejection_closes_simple_index_visibility() {
    let (ctx, mocks) = make_ctx();
    let repo = insert_hosted_repo(&mocks, "pypi-rescan-json", RepositoryFormat::Pypi);
    let artifact_id = insert_artifact(
        &mocks,
        repo.id,
        "rescan-pkg",
        "1.0.0",
        "simple/rescan-pkg/rescan-pkg-1.0.0.tar.gz",
        QuarantineStatus::None,
    );
    let router = pypi_router(ctx.clone());

    let (before_status, before_json) =
        get_simple_json(&router, "pypi-rescan-json", "rescan-pkg").await;
    assert_eq!(
        before_status,
        StatusCode::OK,
        "before-state JSON simple-index must serve (status=None permissive mode)",
    );
    let before_files = before_json["files"]
        .as_array()
        .expect("before-state PEP 691 body carries `files` array");
    assert!(
        !before_files.is_empty(),
        "before-state PEP 691 `files` array MUST be non-empty: body = {before_json}",
    );
    let before_has = before_files
        .iter()
        .any(|f| f["filename"].as_str() == Some("rescan-pkg-1.0.0.tar.gz"));
    assert!(
        before_has,
        "before-state PEP 691 `files` MUST include rescan-pkg-1.0.0.tar.gz: \
         body = {before_json}",
    );

    invoke_rescan_reject(&ctx, artifact_id).await;
    assert_artifact_rejected(&mocks, artifact_id);

    let (after_status, after_json) =
        get_simple_json(&router, "pypi-rescan-json", "rescan-pkg").await;
    match after_status {
        StatusCode::NOT_FOUND => {}
        StatusCode::OK => {
            let after_files = after_json["files"]
                .as_array()
                .expect("after-state OK PEP 691 body must carry `files` array");
            let after_has = after_files
                .iter()
                .any(|f| f["filename"].as_str() == Some("rescan-pkg-1.0.0.tar.gz"));
            assert!(
                !after_has,
                "after-state PEP 691 `files` MUST omit rescan-pkg-1.0.0.tar.gz \
                 (Rejected via rescan): body = {after_json}",
            );
        }
        other => panic!(
            "after-state JSON simple-index returned unexpected status {other:?}; \
             expected 200 or 404",
        ),
    }
}

// ---------------------------------------------------------------------------
// Cargo — sparse-index NDJSON
// ---------------------------------------------------------------------------

fn cargo_router(ctx: Arc<AppContext>) -> Router {
    let trust_cfg = ctx.trust_config.clone();
    Router::new()
        .nest("/cargo", hort_http_cargo::cargo_routes())
        .layer(hort_http_core::middleware::trust::request_trust_layer(
            trust_cfg,
        ))
        .with_state(ctx)
}

/// Pin: hosted cargo crate at `None` is visible in the sparse-
/// index NDJSON; rescan flips it to `Rejected`; the next NDJSON
/// either omits the version line (200 with N-1 lines) or returns
/// 404 (empty-result, universal property holds vacuously).
///
/// Path layout: the cargo sparse-index URL for a 5-char crate name
/// `mylib` is `/<aa>/<bb>/<name>` where `aa = first 2 chars`,
/// `bb = next 2 chars` — i.e. `/cargo/cargo-rescan/my/li/mylib`
/// (see the `sparse_index_4plus` route in `hort-http-cargo::lib.rs`).
#[tokio::test]
async fn cargo_rescan_rejection_closes_sparse_index_visibility() {
    let (ctx, mocks) = make_ctx();
    let repo = insert_hosted_repo(&mocks, "cargo-rescan", RepositoryFormat::Cargo);
    let crate_name = "mylib";
    let artifact_id = insert_artifact(
        &mocks,
        repo.id,
        crate_name,
        "1.0.0",
        &format!("crates/{crate_name}/1.0.0/{crate_name}-1.0.0.crate"),
        QuarantineStatus::None,
    );
    let router = cargo_router(ctx.clone());

    // The 4+-char crate-name route is `/cargo/<repo>/<aa>/<bb>/<name>`
    // where `aa = first 2 chars`, `bb = chars 3-4`. For `mylib`:
    // `aa = "my"`, `bb = "li"`.
    let path = format!("/cargo/cargo-rescan/my/li/{crate_name}");

    let before_res = router
        .clone()
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        before_res.status(),
        StatusCode::OK,
        "before-state sparse-index must serve (status=None permissive mode)",
    );
    let before_bytes = to_bytes(before_res.into_body(), 64 * 1024).await.unwrap();
    let before_text = String::from_utf8_lossy(&before_bytes);
    let before_lines: Vec<&str> = before_text.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !before_lines.is_empty(),
        "before-state NDJSON MUST carry at least one line: text = {before_text}",
    );
    let before_has_1_0_0 = before_lines.iter().any(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .map(|v| v["vers"].as_str() == Some("1.0.0"))
            .unwrap_or(false)
    });
    assert!(
        before_has_1_0_0,
        "before-state NDJSON MUST include the 1.0.0 line: text = {before_text}",
    );

    invoke_rescan_reject(&ctx, artifact_id).await;
    assert_artifact_rejected(&mocks, artifact_id);

    let after_res = router
        .clone()
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let after_status = after_res.status();
    let after_bytes = to_bytes(after_res.into_body(), 64 * 1024).await.unwrap();
    let after_text = String::from_utf8_lossy(&after_bytes);
    match after_status {
        StatusCode::NOT_FOUND => {
            // Empty-result 404 — universal property holds vacuously.
        }
        StatusCode::OK => {
            let after_has_1_0_0 = after_text.lines().filter(|l| !l.is_empty()).any(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .map(|v| v["vers"].as_str() == Some("1.0.0"))
                    .unwrap_or(false)
            });
            assert!(
                !after_has_1_0_0,
                "after-state NDJSON MUST omit the 1.0.0 line (Rejected via rescan): \
                 text = {after_text}",
            );
        }
        other => panic!(
            "after-state sparse-index returned unexpected status {other:?}; \
             expected 200 or 404",
        ),
    }
}
