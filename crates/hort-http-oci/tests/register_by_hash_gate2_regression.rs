//! Trigger-level regression pins for issue #107 (`register_by_hash` bypasses
//! Gate-2) — backlog Item 3.
//!
//! Items 1-2 fixed `register_by_hash_inner` so every caller (OCI cross-repo
//! blob mount, cross-repo pull-dedup followers across every pull-through
//! format) quarantines+scans under the TARGET repo's policy, and refuses a
//! `Rejected`/`ScanIndeterminate` mount SOURCE outright. This file pins the
//! mount trigger end-to-end (mount POST followed by a blob GET against the
//! resulting row), via `build_mock_ctx` + a router merging
//! `hort_http_oci::uploads::router()` (mount) with `get_pull`/`head_pull`
//! (blob read) — the SAME no-auth-middleware narrow-router pattern
//! `uploads.rs`'s and `blobs.rs`'s own inline test modules already use,
//! just combined so one test can drive mount-then-read. Not
//! `oci_routes_with_config` (see `router()`'s own doc comment below for
//! why). No hand-rolled `AppContext` wiring either way — `build_mock_ctx`
//! stays the sole construction path.
//!
//! Pin (b) (mount of a `Rejected` source -> 404 `BLOB_UNKNOWN`, no row
//! minted) is already covered by Item 2's
//! `cross_mount_rejected_source_returns_404_blob_unknown_no_row_minted` in
//! `crates/hort-http-oci/src/uploads.rs` — not duplicated here. This file
//! adds the `ScanIndeterminate` sibling at the handler level (Item 2 only
//! covered it at the `hort-app` use-case level).
//!
//! Pin (c) (the OCI cross-repo pull-dedup FOLLOWER trigger) lives in
//! `crates/hort-http-oci/src/blobs.rs`'s inline test module instead of
//! here — it needs `pub(crate) async fn try_upstream_blob_pull` directly
//! (no HTTP surface triggers a proxy-pull follower; it only fires when two
//! concurrent pull-through fetches for the same content hash race across
//! different target repos), which an external `tests/` crate cannot reach.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::use_cases::test_support::sample_repository;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::scan_policy::{
    NegligibleAction, ProvenanceMode, ScanEnforcement, ScanPolicyProjection, SeverityThreshold,
};
use hort_domain::events::PolicyScope;
use hort_domain::types::ContentHash;

use hort_http_core::context::AppContext;
use hort_http_core::test_support::build_mock_ctx;

fn oci_repo(key: &str) -> hort_domain::entities::repository::Repository {
    let mut r = sample_repository();
    r.key = key.into();
    r.format = RepositoryFormat::Oci;
    r
}

/// Mount (POST/PATCH/PUT/DELETE, via `hort_http_oci::uploads::router()`)
/// merged with blob GET/HEAD (`hort_http_oci::get_pull`/`head_pull`) — the
/// same no-auth-middleware narrow-router pattern `uploads.rs`'s and
/// `blobs.rs`'s own inline test modules use (`router()` /
/// `blob_router()`), combined so ONE test can drive mount-then-read. Not
/// `oci_routes_with_config`: that wires the real OCI bearer-auth
/// `route_layer`, which requires a genuine authenticated principal for any
/// non-safe method even under `AuthContext::Disabled` (anonymous writes are
/// unreachable in production under Disabled, per that middleware's own
/// contract) — full auth wiring is orthogonal to what this file pins
/// (the Item 1/2 quarantine gate) and belongs to `v2_auth_e2e.rs` instead.
fn router(ctx: Arc<AppContext>) -> Router {
    hort_http_oci::uploads::router()
        .merge(Router::new().route(
            "/v2/{repo_key}/{*tail}",
            axum::routing::get(hort_http_oci::get_pull).head(hort_http_oci::head_pull),
        ))
        .with_state(ctx)
}

/// A repo-scoped, quarantining, scanning `ScanPolicy` for `repo_id` —
/// repo-scoped wins over the harness's pre-seeded permissive-global
/// default (`resolve_active_policy_for_repo`'s `repo_scoped.or(global)`),
/// so this does not disturb any other repo in the same test.
fn quarantining_policy(repo_id: Uuid) -> ScanPolicyProjection {
    let now = Utc::now();
    ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: format!("item3-regression-quarantining-{repo_id}"),
        scope: PolicyScope::Repository(repo_id),
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 3600,
        require_approval: false,
        provenance_mode: ProvenanceMode::Off,
        provenance_backends: Vec::new(),
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: vec!["trivy".to_string()],
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        stream_version: 0,
        created_at: now,
        updated_at: now,
    }
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

/// Synthetic write-authorized `CallerPrincipal` — mirrors
/// `uploads.rs`'s own `test_principal()`. The narrow merged `router()`
/// above carries no auth middleware, so `post_upload_dispatch` extracts
/// the principal purely from the request extension this injects.
fn test_principal() -> hort_domain::entities::caller::CallerPrincipal {
    hort_domain::entities::caller::CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "test:sub".into(),
        username: "alice".into(),
        email: "alice@example.com".into(),
        claims: Vec::new(),
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// Attach a synthetic `CallerPrincipal` to a mount request — mirrors
/// `uploads.rs`'s own `with_principal()`, reusing the same public
/// `hort_http_core` test-support injector (not a hand-rolled extension
/// insert).
fn with_principal(mut req: Request<Body>) -> Request<Body> {
    hort_http_core::middleware::auth::test_support::inject_principal(&mut req, test_principal());
    req
}

/// Pin (a): mount of a CLEAN source under an active `quarantineDuration >
/// 0` policy -> the target-repo row lands `Quarantined`, a scan job is
/// enqueued, and the target blob GET is held (503 + `Retry-After`) — the
/// full mount-then-serve round trip, driven through the real merged
/// router so a regression on either half (the mount-time gate, or the
/// read-time quarantine check) fails this test.
#[test]
fn mount_of_clean_source_quarantines_target_and_holds_blob_read() {
    let content = b"clean mount content for item3 regression".to_vec();
    let hex = {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(&content))
    };

    let (mount_status, get_status, retry_after) = run(async {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);

        let src = oci_repo("src-repo");
        let src_id = src.id;
        let target = oci_repo("target-repo");
        let target_id = target.id;
        mocks.repositories.insert(src);
        mocks.repositories.insert(target);
        mocks
            .policy_projections
            .insert(quarantining_policy(target_id));

        // Seed the source blob directly (mirrors `seed_blob` in the
        // inline uploads.rs/blobs.rs test modules — the mount path
        // reads it via `find_by_repo_and_checksum`, not storage.exists).
        let hash: ContentHash = hex.parse().unwrap();
        let mut src_artifact =
            hort_app::use_cases::test_support::sample_artifact(QuarantineStatus::None);
        src_artifact.repository_id = src_id;
        src_artifact.sha256_checksum = hash.clone();
        src_artifact.size_bytes = content.len() as i64;
        mocks.artifacts.insert(src_artifact);
        mocks.storage.insert_content(hash, content.clone());

        let router = router(ctx);

        let mount_uri =
            format!("/v2/target-repo/nginx/blobs/uploads/?mount=sha256:{hex}&from=src-repo");
        let mount_resp = router
            .clone()
            .oneshot(with_principal(
                Request::post(&mount_uri).body(Body::empty()).unwrap(),
            ))
            .await
            .unwrap();
        let mount_status = mount_resp.status();

        let get_uri = format!("/v2/target-repo/nginx/blobs/sha256:{hex}");
        let get_resp = router
            .oneshot(Request::get(&get_uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let get_status = get_resp.status();
        let retry_after = get_resp
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap().to_string());

        (mount_status, get_status, retry_after)
    });

    assert_eq!(
        mount_status,
        StatusCode::CREATED,
        "mount of a clean source must be accepted (201) — the fix HOLDS \
         the artifact, it does not reject the mount itself"
    );
    assert_eq!(
        get_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "issue #107 Item 1: the mounted target-repo row must be Quarantined \
         under an active duration>0 policy, so a subsequent blob GET is \
         held (503), not immediately served — pinning this at the mount \
         trigger specifically, not just via a directly-seeded row"
    );
    assert!(
        retry_after.is_some(),
        "the held-blob response must carry Retry-After"
    );
}

/// Pin (b) sibling: mount of a `ScanIndeterminate` source -> the SAME 404
/// `BLOB_UNKNOWN` / no-row-minted outcome as the `Rejected` case Item 2
/// already pins at the handler level
/// (`cross_mount_rejected_source_returns_404_blob_unknown_no_row_minted`
/// in `uploads.rs`). Added here because that one only covered `Rejected`.
#[test]
fn mount_of_scan_indeterminate_source_returns_404_blob_unknown_no_row_minted() {
    let content = b"indeterminate mount content for item3 regression".to_vec();
    let hex = {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(&content))
    };

    let (status, body, artifact_count_after) = run(async {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);

        let src = oci_repo("src-repo");
        let src_id = src.id;
        mocks.repositories.insert(src);
        mocks.repositories.insert(oci_repo("target-repo"));

        let hash: ContentHash = hex.parse().unwrap();
        let mut src_artifact =
            hort_app::use_cases::test_support::sample_artifact(QuarantineStatus::ScanIndeterminate);
        src_artifact.repository_id = src_id;
        src_artifact.sha256_checksum = hash.clone();
        src_artifact.size_bytes = content.len() as i64;
        mocks.artifacts.insert(src_artifact);
        mocks.storage.insert_content(hash, content.clone());

        let router = router(ctx);
        let mount_uri =
            format!("/v2/target-repo/nginx/blobs/uploads/?mount=sha256:{hex}&from=src-repo");
        let resp = router
            .oneshot(with_principal(
                Request::post(&mount_uri).body(Body::empty()).unwrap(),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
        (status, body, mocks.artifacts.snapshot_all().len())
    });

    assert_eq!(status, StatusCode::NOT_FOUND);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
    assert_eq!(
        artifact_count_after, 1,
        "a ScanIndeterminate source must never mint a target-repo row"
    );
}
