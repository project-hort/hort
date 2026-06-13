//! Integration tests for [`OsvAdvisoryAdapter`] driven by `wiremock`.
//!
//! Six integration scenarios:
//!
//! 1. `query_returns_findings_for_single_component` — happy path.
//! 2. `query_returns_empty_when_no_advisories` — empty `vulns` array.
//! 3. `query_returns_cached_findings_without_remote_call` — second
//!    call hits the cache (expectation: mock receives exactly one
//!    request).
//! 4. `query_propagates_malformed_response_as_validation_error` — bad
//!    JSON surfaces as `DomainError::Validation`.
//! 5. `query_skips_unknown_ecosystem_components` — `Ecosystem::Unknown`
//!    is dropped client-side; OSV is never asked about it.
//! 6. `query_chunks_oversized_input_into_multiple_batches` — 10
//!    components with `batch_size = 4` yields exactly 3 mock requests.

use std::sync::Arc;
use std::time::Duration;

use hort_adapters_advisory_osv::{OsvAdvisoryAdapter, OsvAdvisoryConfig};
use hort_adapters_ephemeral_memory::InMemoryEphemeralStore;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::DomainError;
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::types::{Ecosystem, SbomComponent};

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_component(name: &str, version: &str, eco: Ecosystem) -> SbomComponent {
    SbomComponent {
        purl: format!("pkg:test/{name}@{version}"),
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: eco,
        licenses: vec![],
        direct_dependency: false,
    }
}

async fn build_adapter_with_url(
    base_url: String,
    cache: Arc<InMemoryEphemeralStore>,
    batch_size: Option<usize>,
) -> OsvAdvisoryAdapter {
    let cfg = OsvAdvisoryConfig {
        osv_batch_url: format!("{base_url}/v1/querybatch"),
        cache_ttl: Duration::from_secs(60),
        request_timeout: Duration::from_secs(5),
        batch_size,
        ..OsvAdvisoryConfig::default()
    };
    OsvAdvisoryAdapter::new(cfg, cache, None).expect("build adapter")
}

// ---------------------------------------------------------------------------
// 1. happy path — single component, single vuln
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_returns_findings_for_single_component() {
    let server = MockServer::start().await;

    let osv_response = json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-1234-5678-9abc",
                        "summary": "Prototype pollution",
                        "database_specific": { "severity": "HIGH" },
                        "affected": [
                            { "ranges": [
                                { "events": [ {"fixed": "4.17.21"} ] }
                            ]}
                        ],
                        "references": [
                            { "url": "https://example.org/advisory" }
                        ]
                    }
                ]
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(osv_response))
        .expect(1)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache.clone(), None).await;

    let comps = vec![make_component("lodash", "4.17.20", Ecosystem::Npm)];
    let findings = adapter.query(&comps).await.expect("query succeeds");

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.purl, "pkg:test/lodash@4.17.20");
    assert_eq!(f.vulnerability_id, "GHSA-1234-5678-9abc");
    assert_eq!(f.severity, SeverityThreshold::High);
    assert_eq!(f.title, "Prototype pollution");
    assert_eq!(f.fixed_versions, vec!["4.17.21".to_string()]);
    assert_eq!(f.source_scanner, "osv");
    assert!(f
        .references
        .iter()
        .any(|r| r == "https://example.org/advisory"));
    assert!(f
        .references
        .iter()
        .any(|r| r == "https://osv.dev/vulnerability/GHSA-1234-5678-9abc"));
}

// ---------------------------------------------------------------------------
// 2. empty results — no advisories for a component
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_returns_empty_when_no_advisories() {
    let server = MockServer::start().await;

    let osv_response = json!({
        "results": [
            { "vulns": [] }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(osv_response))
        .expect(1)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;

    let comps = vec![make_component("safe-package", "1.0.0", Ecosystem::Npm)];
    let findings = adapter.query(&comps).await.expect("query succeeds");

    assert!(
        findings.is_empty(),
        "no advisories must yield empty findings: {findings:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. cache hit — second call does not touch the network
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_returns_cached_findings_without_remote_call() {
    let server = MockServer::start().await;

    let osv_response = json!({
        "results": [
            {
                "vulns": [
                    { "id": "OSV-2024-001", "database_specific": {"severity": "MEDIUM"} }
                ]
            }
        ]
    });

    // Crucial: `expect(1)` is the assertion. If the adapter goes back
    // to the network on the second call, wiremock's drop-time
    // verification fails the test.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(osv_response))
        .expect(1)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache.clone(), None).await;

    let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];

    let findings1 = adapter.query(&comps).await.expect("first call");
    assert_eq!(findings1.len(), 1, "first call returns the OSV finding");

    let findings2 = adapter.query(&comps).await.expect("second call");
    assert_eq!(
        findings2, findings1,
        "second call must return the cached findings unchanged"
    );

    server.verify().await;
}

// ---------------------------------------------------------------------------
// 4. malformed response → DomainError::Validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_propagates_malformed_response_as_validation_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("this is not JSON, it is a haiku about JSON")
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;

    let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
    let err = adapter
        .query(&comps)
        .await
        .expect_err("malformed response must error");

    match err {
        DomainError::Validation(msg) => {
            assert!(
                msg.contains("malformed batch response"),
                "error must classify as malformed: {msg}"
            );
        }
        other => panic!("expected Validation error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. unknown-ecosystem components are skipped client-side
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_skips_unknown_ecosystem_components() {
    let server = MockServer::start().await;

    // The adapter MUST NOT call OSV at all when every input component
    // has an unsupported ecosystem. `expect(0)` enforces this.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .expect(0)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;

    let comps = vec![
        make_component("chart", "1.0.0", Ecosystem::Helm),
        make_component(
            "weird",
            "1.0.0",
            Ecosystem::Unknown("not-an-osv-ecosystem".into()),
        ),
        make_component("img", "1.0.0", Ecosystem::OciImage),
    ];

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert!(
        findings.is_empty(),
        "all-unsupported input must yield empty findings: {findings:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. chunked batch — 10 inputs with batch_size=4 → 3 POSTs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_chunks_oversized_input_into_multiple_batches() {
    let server = MockServer::start().await;

    // Each batch returns a stable shape — one empty result per query
    // so the parsing layer does not produce findings (the test only
    // cares about the request count).
    let large_empty =
        json!({ "results": (0..4).map(|_| json!({"vulns": []})).collect::<Vec<_>>() });
    let small_empty =
        json!({ "results": (0..2).map(|_| json!({"vulns": []})).collect::<Vec<_>>() });

    // The mock returns the same "all-empty" shape for every request;
    // `expect(3)` is the load-bearing assertion. wiremock's first
    // matching mock wins, so any single mock can serve all three —
    // but the response must accommodate any batch size. We use the
    // larger payload (4 entries) and rely on the parser tolerating
    // shorter batches via `results.get(i).cloned().unwrap_or_default()`.
    let _ = small_empty;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(large_empty))
        .expect(3)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, Some(4)).await;

    // 10 distinct npm components. They must hit the cache as misses
    // on the first call.
    let comps: Vec<_> = (0..10)
        .map(|i| make_component(&format!("pkg-{i}"), "1.0.0", Ecosystem::Npm))
        .collect();

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert!(findings.is_empty(), "all batches return empty");

    server.verify().await;
}

// ---------------------------------------------------------------------------
// `hort_advisory_query_total{result}` emission tests.
//
// One test per result variant. Each test boots a wiremock that produces
// the relevant outcome, runs the query under
// `metrics::with_local_recorder`, and asserts the snapshot carries
// `hort_advisory_query_total` with the expected `result` label.
// ---------------------------------------------------------------------------

/// Find a `result=<expected>` counter on `hort_advisory_query_total` in a
/// snapshot. Returns the counter value (0 if the metric did not fire
/// with that label).
fn find_advisory_query_count(snap: Snapshot, expected_result: &str) -> u64 {
    for (key, _, _, value) in snap.into_vec() {
        if key.key().name() != "hort_advisory_query_total" {
            continue;
        }
        let mut matched = false;
        for label in key.key().labels() {
            if label.key() == "result" && label.value() == expected_result {
                matched = true;
            }
        }
        if matched {
            if let DebugValue::Counter(v) = value {
                return v;
            }
        }
    }
    0
}

/// Common scaffolding: build a tokio runtime, scope a
/// `DebuggingRecorder`, run the supplied closure under that recorder,
/// and return the snapshot. The closure must drive its own async work
/// via `runtime.block_on`.
fn capture_metrics_around<F>(f: F) -> Snapshot
where
    F: FnOnce(&tokio::runtime::Runtime),
{
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        f(&rt);
    });
    snapshotter.snapshot()
}

#[test]
fn metric_cache_hit_fires_on_second_lookup_with_warm_cache() {
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async move {
            let server = MockServer::start().await;
            let osv_response = json!({
                "results": [
                    { "vulns": [
                        { "id": "OSV-1", "database_specific": {"severity": "MEDIUM"} }
                    ]}
                ]
            });
            // Two calls, mock allows either count — only the first will
            // hit the upstream because the cache memoises the result.
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(osv_response))
                .mount(&server)
                .await;

            let cache = Arc::new(InMemoryEphemeralStore::new());
            let adapter = build_adapter_with_url(server.uri(), cache, None).await;
            let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
            adapter.query(&comps).await.expect("first call");
            adapter.query(&comps).await.expect("second call (cached)");
        });
    });
    assert!(
        find_advisory_query_count(snap, "cache_hit") >= 1,
        "hort_advisory_query_total{{result=cache_hit}} must fire on the cached second lookup"
    );
}

#[test]
fn metric_cache_miss_fires_on_first_lookup() {
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async move {
            let server = MockServer::start().await;
            let osv_response = json!({
                "results": [ { "vulns": [] } ]
            });
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(osv_response))
                .mount(&server)
                .await;
            let cache = Arc::new(InMemoryEphemeralStore::new());
            let adapter = build_adapter_with_url(server.uri(), cache, None).await;
            let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
            adapter.query(&comps).await.expect("first call");
        });
    });
    assert_eq!(
        find_advisory_query_count(snap, "cache_miss"),
        1,
        "hort_advisory_query_total{{result=cache_miss}} must fire once for the cold lookup"
    );
}

#[test]
fn metric_upstream_4xx_fires_on_400_response() {
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async move {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(ResponseTemplate::new(400))
                .mount(&server)
                .await;
            let cache = Arc::new(InMemoryEphemeralStore::new());
            let adapter = build_adapter_with_url(server.uri(), cache, None).await;
            let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
            let _ = adapter.query(&comps).await; // expected to error
        });
    });
    assert_eq!(
        find_advisory_query_count(snap, "upstream_4xx"),
        1,
        "hort_advisory_query_total{{result=upstream_4xx}} must fire on a 400"
    );
}

#[test]
fn metric_upstream_5xx_fires_on_500_response() {
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async move {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;
            let cache = Arc::new(InMemoryEphemeralStore::new());
            let adapter = build_adapter_with_url(server.uri(), cache, None).await;
            let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
            let _ = adapter.query(&comps).await; // expected to error
        });
    });
    assert_eq!(
        find_advisory_query_count(snap, "upstream_5xx"),
        1,
        "hort_advisory_query_total{{result=upstream_5xx}} must fire on a 500"
    );
}

#[test]
fn metric_network_error_fires_when_endpoint_unreachable() {
    // Point the adapter at a port no server listens on. reqwest
    // surfaces a connect-refused as a non-timeout transport error,
    // which must classify as `network_error`.
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async move {
            let cache = Arc::new(InMemoryEphemeralStore::new());
            let cfg = OsvAdvisoryConfig {
                osv_batch_url: "http://127.0.0.1:1/v1/querybatch".to_string(),
                cache_ttl: Duration::from_secs(60),
                request_timeout: Duration::from_secs(2),
                batch_size: None,
                ..OsvAdvisoryConfig::default()
            };
            let adapter = OsvAdvisoryAdapter::new(cfg, cache, None).expect("adapter");
            let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
            let _ = adapter.query(&comps).await; // expected to error
        });
    });
    assert_eq!(
        find_advisory_query_count(snap, "network_error"),
        1,
        "hort_advisory_query_total{{result=network_error}} must fire on connect-refused"
    );
}

#[test]
fn metric_timeout_fires_when_request_deadline_elapses() {
    // Mock that takes longer than the per-request timeout —
    // reqwest's `is_timeout` predicate then classifies the failure
    // as `Timeout`.
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async move {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "results": [ { "vulns": [] } ] }))
                        .set_delay(Duration::from_secs(5)),
                )
                .mount(&server)
                .await;
            let cache = Arc::new(InMemoryEphemeralStore::new());
            let cfg = OsvAdvisoryConfig {
                osv_batch_url: format!("{}/v1/querybatch", server.uri()),
                cache_ttl: Duration::from_secs(60),
                // Tighter than the mock's 5-second delay → timeout.
                request_timeout: Duration::from_millis(200),
                batch_size: None,
                ..OsvAdvisoryConfig::default()
            };
            let adapter = OsvAdvisoryAdapter::new(cfg, cache, None).expect("adapter");
            let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];
            let _ = adapter.query(&comps).await; // expected to error
        });
    });
    assert_eq!(
        find_advisory_query_count(snap, "timeout"),
        1,
        "hort_advisory_query_total{{result=timeout}} must fire when the per-request deadline elapses"
    );
}
