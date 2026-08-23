//! Integration tests for [`OsvAdvisoryAdapter`] driven by `wiremock`.
//!
//! ## Fixture contract — read before editing any response body here
//!
//! **`/v1/querybatch` returns `id` and `modified` and nothing else.**
//! No `severity` array, no `database_specific`, no `affected`, no
//! `references`. Every querybatch fixture in this file goes through
//! [`querybatch_body`], which physically cannot emit those fields, and
//! [`querybatch_fixture_carries_only_id_and_modified`] pins that
//! property. Anything richer is a fixture that flatters the code: it
//! validates a wire format the adapter never receives, which is exactly
//! how the severity derivation shipped inert.
//!
//! Severity therefore comes from the hydrated `/v1/vulns/{id}` record,
//! mounted with [`mount_vuln_record`]. A test that wants a scored
//! finding mounts one; a test that wants the unscored fail-closed
//! `Critical` simply does not.
//!
//! ## Scenarios
//!
//! Batch/caching path:
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
//!
//! Hydration path: see the `Full-record hydration` section below.

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
use wiremock::matchers::{body_string_contains, method, path};
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

/// A `modified` timestamp for fixtures that do not care about the
/// specific value. Distinct constants are used where the test is about
/// invalidation.
const MODIFIED: &str = "2026-04-25T06:45:06.122559Z";

/// Build a `/v1/querybatch` response body in the shape the real
/// endpoint returns: one `results[]` entry per query, each `vulns[]`
/// entry carrying **only** `id` and `modified`.
///
/// This helper is the fixture contract in code — there is no parameter
/// through which a `severity` array or a `database_specific` block can
/// reach a querybatch fixture, because the endpoint never returns one.
fn querybatch_body(per_component_ids: &[&[(&str, &str)]]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = per_component_ids
        .iter()
        .map(|ids| {
            let vulns: Vec<serde_json::Value> = ids
                .iter()
                .map(|(id, modified)| json!({ "id": id, "modified": modified }))
                .collect();
            json!({ "vulns": vulns })
        })
        .collect();
    json!({ "results": results })
}

/// Mount `GET /v1/vulns/{id}` returning `body`. `expect` pins how many
/// times the hydration pass is allowed to ask for this record —
/// load-bearing for the dedup and cache tests.
async fn mount_vuln_record(server: &MockServer, id: &str, body: serde_json::Value, expect: u64) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(expect)
        .mount(server)
        .await;
}

/// The real `/v1/vulns/RUSTSEC-2023-0071` record, trimmed to the fields
/// this adapter reads. Verified against `api.osv.dev`: the CVSS vector
/// is the *only* severity signal on it — there is no
/// `database_specific.severity` label to fall back to, so a finding for
/// this advisory is scored precisely when the record was hydrated.
fn marvin_full_record() -> serde_json::Value {
    json!({
        "id": "RUSTSEC-2023-0071",
        "modified": MODIFIED,
        "summary": "Marvin Attack: potential key recovery through timing sidechannels",
        "aliases": ["CVE-2023-49092", "GHSA-c38w-74pg-36hr"],
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
            }
        ],
        "affected": [
            {
                "package": { "ecosystem": "crates.io", "name": "rsa" },
                "ranges": [
                    { "events": [ { "introduced": "0.0.0-0" } ] }
                ]
            }
        ],
        "references": [
            { "url": "https://rustsec.org/advisories/RUSTSEC-2023-0071.html" }
        ]
    })
}

async fn build_adapter_with_url(
    base_url: String,
    cache: Arc<InMemoryEphemeralStore>,
    batch_size: Option<usize>,
) -> OsvAdvisoryAdapter {
    let cfg = OsvAdvisoryConfig {
        osv_batch_url: format!("{base_url}/v1/querybatch"),
        osv_vulns_url: format!("{base_url}/v1/vulns"),
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

    // querybatch: id + modified only. Everything the assertions below
    // check — summary, severity label, fixed version, reference URL —
    // reaches the finding through the hydrated record, because that is
    // the only place the real API publishes it.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(querybatch_body(&[&[("GHSA-1234-5678-9abc", MODIFIED)]])),
        )
        .expect(1)
        .mount(&server)
        .await;

    mount_vuln_record(
        &server,
        "GHSA-1234-5678-9abc",
        json!({
            "id": "GHSA-1234-5678-9abc",
            "modified": MODIFIED,
            "summary": "Prototype pollution",
            "database_specific": { "severity": "HIGH" },
            "affected": [
                {
                    "package": { "ecosystem": "npm", "name": "lodash" },
                    "ranges": [ { "events": [ {"fixed": "4.17.21"} ] } ]
                }
            ],
            "references": [ { "url": "https://example.org/advisory" } ]
        }),
        1,
    )
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

    server.verify().await;
}

// ---------------------------------------------------------------------------
// 2. empty results — no advisories for a component
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_returns_empty_when_no_advisories() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[]])))
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

    // Crucial: `expect(1)` is the assertion. If the adapter goes back
    // to the network on the second call, wiremock's drop-time
    // verification fails the test.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(querybatch_body(&[&[("OSV-2024-001", MODIFIED)]])),
        )
        .expect(1)
        .mount(&server)
        .await;

    mount_vuln_record(
        &server,
        "OSV-2024-001",
        json!({
            "id": "OSV-2024-001",
            "modified": MODIFIED,
            "database_specific": { "severity": "MEDIUM" }
        }),
        1,
    )
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
            // Two calls, mock allows either count — only the first will
            // hit the upstream because the cache memoises the result.
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(querybatch_body(&[&[("OSV-1", MODIFIED)]])),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/vulns/OSV-1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id": "OSV-1",
                    "modified": MODIFIED,
                    "database_specific": { "severity": "MEDIUM" }
                })))
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
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[]])))
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

// ---------------------------------------------------------------------------
// Full-record hydration
//
// The regression suite for the defect these tests exist to prevent: a
// `querybatch` response carries no severity signal at all, so severity
// derivation run against it produces a NULL score and the fail-closed
// `Critical` for every advisory — including ones OSV scored years ago.
// ---------------------------------------------------------------------------

/// Find a `result=<expected>` counter on `hort_advisory_hydration_total`.
fn find_hydration_count(snap: Snapshot, expected_result: &str) -> u64 {
    for (key, _, _, value) in snap.into_vec() {
        if key.key().name() != "hort_advisory_hydration_total" {
            continue;
        }
        if key
            .key()
            .labels()
            .any(|l| l.key() == "result" && l.value() == expected_result)
        {
            if let DebugValue::Counter(v) = value {
                return v;
            }
        }
    }
    0
}

/// Guard on the fixture builder itself, not on the adapter.
///
/// The defect this whole section exists for survived into production
/// because the unit tests constructed a vuln with a populated
/// `severity` array — a shape `/v1/querybatch` never returns. Pin the
/// property here so re-enriching a querybatch fixture reads as a
/// contradiction rather than a refactor: **the querybatch wire shape
/// has no severity in it.**
#[test]
fn querybatch_fixture_carries_only_id_and_modified() {
    let body = querybatch_body(&[&[("RUSTSEC-2023-0071", MODIFIED)]]);
    let vuln = &body["results"][0]["vulns"][0];

    let obj = vuln.as_object().expect("vuln is an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["id", "modified"],
        "a querybatch vuln entry has exactly `id` and `modified`; \
         anything else is a fixture modelling a response the endpoint does not send"
    );
    assert!(vuln.get("severity").is_none());
    assert!(vuln.get("database_specific").is_none());
    assert!(vuln.get("affected").is_none());
}

/// The end-to-end evidence for the fix, on the advisory that exposed
/// it: hydrated → CVSS vector → 5.9 → `Medium`.
#[tokio::test]
async fn hydrated_marvin_advisory_scores_medium_from_its_cvss_vector() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(querybatch_body(&[&[("RUSTSEC-2023-0071", MODIFIED)]])),
        )
        .expect(1)
        .mount(&server)
        .await;
    mount_vuln_record(&server, "RUSTSEC-2023-0071", marvin_full_record(), 1).await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;

    let comps = vec![make_component("rsa", "0.9.6", Ecosystem::Cargo)];
    let findings = adapter.query(&comps).await.expect("query succeeds");

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2023-0071");
    assert_eq!(
        f.cvss_score,
        Some(5.9),
        "the CVSS:3.1 base score must be computed from the hydrated vector"
    );
    assert_eq!(
        f.severity,
        SeverityThreshold::Medium,
        "5.9 bands to Medium; the pre-hydration behaviour was Critical with a NULL score"
    );
    // Hydration also recovers the human-facing detail querybatch omits.
    assert_eq!(
        f.title,
        "Marvin Attack: potential key recovery through timing sidechannels"
    );
    assert!(f.aliases.iter().any(|a| a == "CVE-2023-49092"));

    server.verify().await;
}

/// The same advisory with hydration unavailable: unscored, hence the
/// SUP-4 fail-closed `Critical`. This is both the pre-fix behaviour and
/// the post-fix fallback, and it is deliberately unchanged — the fix
/// removes manufactured unscored findings, not the rule that handles
/// real ones.
#[test]
fn hydration_failure_falls_back_to_unscored_critical_and_counts_the_degradation() {
    let snap = capture_metrics_around(|rt| {
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(querybatch_body(&[&[("RUSTSEC-2023-0071", MODIFIED)]])),
                )
                .mount(&server)
                .await;
            // Upstream is reachable but the record is not.
            Mock::given(method("GET"))
                .and(path("/v1/vulns/RUSTSEC-2023-0071"))
                .respond_with(ResponseTemplate::new(500))
                .expect(1)
                .mount(&server)
                .await;

            let cache = Arc::new(InMemoryEphemeralStore::new());
            let adapter = build_adapter_with_url(server.uri(), cache, None).await;
            let comps = vec![make_component("rsa", "0.9.6", Ecosystem::Cargo)];

            let findings = adapter
                .query(&comps)
                .await
                .expect("a hydration failure must not fail the query");

            assert_eq!(findings.len(), 1, "the finding still surfaces");
            assert_eq!(findings[0].cvss_score, None);
            assert_eq!(
                findings[0].severity,
                SeverityThreshold::Critical,
                "an unhydratable advisory is genuinely unscored and must fail closed"
            );

            server.verify().await;
        });
    });

    assert_eq!(
        find_hydration_count(snap, "failed"),
        1,
        "the degradation must be visible on hort_advisory_hydration_total{{result=failed}}, \
         not silent"
    );
}

/// A malformed record body is a hydration failure like any other — not
/// a `DomainError` that aborts the scan (contrast
/// `query_propagates_malformed_response_as_validation_error`, where a
/// malformed *querybatch* body does abort: without it there is nothing
/// to enrich from at all).
#[tokio::test]
async fn malformed_hydrated_record_degrades_instead_of_failing_the_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[("OSV-1", MODIFIED)]])),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/OSV-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{ not json")
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];

    let findings = adapter.query(&comps).await.expect("query still succeeds");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, SeverityThreshold::Critical);
}

/// Several components sharing one advisory cost **one** hydration
/// request between them, not one each.
#[tokio::test]
async fn shared_advisory_hydrates_once_across_components() {
    let server = MockServer::start().await;

    // Three components, all reporting the same advisory id.
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(querybatch_body(&[
            &[("GHSA-shared", MODIFIED)],
            &[("GHSA-shared", MODIFIED)],
            &[("GHSA-shared", MODIFIED)],
        ])))
        .expect(1)
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-shared",
        json!({
            "id": "GHSA-shared",
            "modified": MODIFIED,
            "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }
            ]
        }),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![
        make_component("a", "1.0.0", Ecosystem::Npm),
        make_component("b", "1.0.0", Ecosystem::Npm),
        make_component("c", "1.0.0", Ecosystem::Npm),
    ];

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert_eq!(findings.len(), 3, "each component gets its own finding");
    for f in &findings {
        assert_eq!(
            f.cvss_score,
            Some(5.9),
            "all three share the hydrated score"
        );
    }

    // `expect(1)` on the record mock is the bound: N advisories, not
    // N × components, hydration requests.
    server.verify().await;
}

/// A cached hydrated record is reused across queries while `modified`
/// is unchanged.
///
/// The two queries name *different* components so the per-component
/// findings cache misses both times — otherwise the first query's
/// cached findings would short-circuit before hydration and the test
/// would prove nothing about the hydration cache.
#[tokio::test]
async fn unchanged_modified_serves_the_hydrated_record_from_cache() {
    let server = MockServer::start().await;

    for pkg in ["pkg-a", "pkg-b"] {
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_string_contains(pkg))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(querybatch_body(&[&[("GHSA-stable", MODIFIED)]])),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    mount_vuln_record(
        &server,
        "GHSA-stable",
        json!({
            "id": "GHSA-stable",
            "modified": MODIFIED,
            "database_specific": { "severity": "HIGH" }
        }),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;

    let first = adapter
        .query(&[make_component("pkg-a", "1.0.0", Ecosystem::Npm)])
        .await
        .expect("first query");
    let second = adapter
        .query(&[make_component("pkg-b", "1.0.0", Ecosystem::Npm)])
        .await
        .expect("second query");

    assert_eq!(first[0].severity, SeverityThreshold::High);
    assert_eq!(
        second[0].severity,
        SeverityThreshold::High,
        "the cached record must carry the same severity"
    );

    // `expect(1)` on the record mock: the second query hydrated from
    // cache, so only one `/v1/vulns` request was ever issued.
    server.verify().await;
}

/// A changed `modified` shifts the cache key and forces a re-fetch —
/// which is the whole reason the key is `(id, modified)` and not `id`.
/// Here OSV rescores the advisory between the two queries; the second
/// query must pick up the new score rather than serve the stale one for
/// the rest of the TTL.
#[tokio::test]
async fn changed_modified_refetches_the_hydrated_record() {
    let server = MockServer::start().await;

    const MODIFIED_V2: &str = "2026-06-01T00:00:00Z";

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_string_contains("pkg-a"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(querybatch_body(&[&[("GHSA-moving", MODIFIED)]])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_string_contains("pkg-b"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(querybatch_body(&[&[("GHSA-moving", MODIFIED_V2)]])),
        )
        .expect(1)
        .mount(&server)
        .await;

    // wiremock matches most-recently-mounted first, so mount the
    // rescored record last and bound each to exactly one call.
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-moving"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "GHSA-moving",
            "modified": MODIFIED,
            "database_specific": { "severity": "LOW" }
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-moving"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "GHSA-moving",
            "modified": MODIFIED_V2,
            "database_specific": { "severity": "CRITICAL" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;

    let first = adapter
        .query(&[make_component("pkg-a", "1.0.0", Ecosystem::Npm)])
        .await
        .expect("first query");
    let second = adapter
        .query(&[make_component("pkg-b", "1.0.0", Ecosystem::Npm)])
        .await
        .expect("second query");

    assert_eq!(first[0].severity, SeverityThreshold::Low);
    assert_eq!(
        second[0].severity,
        SeverityThreshold::Critical,
        "a moved `modified` must invalidate the cached record, not serve the stale severity"
    );

    server.verify().await;
}

/// Partial failure: hydration is per-id, so one unreachable record
/// degrades exactly one finding. The rest of the scan keeps its scores.
#[tokio::test]
async fn partial_hydration_failure_degrades_only_the_failing_advisory() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[
                ("GHSA-ok", MODIFIED),
                ("GHSA-broken", MODIFIED),
            ]])),
        )
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-ok",
        json!({
            "id": "GHSA-ok",
            "modified": MODIFIED,
            "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }
            ]
        }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-broken"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert_eq!(findings.len(), 2);

    let ok = findings
        .iter()
        .find(|f| f.vulnerability_id == "GHSA-ok")
        .expect("hydrated finding present");
    assert_eq!(ok.cvss_score, Some(5.9));
    assert_eq!(ok.severity, SeverityThreshold::Medium);

    let broken = findings
        .iter()
        .find(|f| f.vulnerability_id == "GHSA-broken")
        .expect("degraded finding present");
    assert_eq!(broken.cvss_score, None);
    assert_eq!(broken.severity, SeverityThreshold::Critical);
}

/// A hydrated record covers every package the advisory touches. A
/// per-component finding must only read the `affected[]` entry for its
/// own package, or it reports another package's fixed version against
/// this purl.
#[tokio::test]
async fn multi_package_record_reports_only_the_matching_package_fixed_versions() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(querybatch_body(&[&[("GHSA-multi", MODIFIED)]])),
        )
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-multi",
        json!({
            "id": "GHSA-multi",
            "modified": MODIFIED,
            "database_specific": { "severity": "HIGH" },
            "affected": [
                {
                    "package": { "ecosystem": "PyPI", "name": "other-package" },
                    "ranges": [ { "events": [ { "fixed": "9.9.9" } ] } ]
                },
                {
                    "package": { "ecosystem": "npm", "name": "lodash" },
                    "ranges": [ { "events": [ { "fixed": "4.17.21" } ] } ]
                }
            ]
        }),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("lodash", "4.17.20", Ecosystem::Npm)];

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert_eq!(
        findings[0].fixed_versions,
        vec!["4.17.21".to_string()],
        "only the npm/lodash entry belongs to this purl"
    );
}

/// An out-of-spec record with no id cannot be hydrated (there is no
/// path segment to request) and must not produce a request at all. It
/// still flows through as an unscored finding, which
/// `Finding::validate()` rejects downstream.
#[tokio::test]
async fn id_less_record_issues_no_hydration_request() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[("", MODIFIED)]])),
        )
        .mount(&server)
        .await;
    // Any GET against the record endpoint is a failure of the guard.
    Mock::given(method("GET"))
        .and(path("/v1/vulns/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&server)
        .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("foo", "1.0.0", Ecosystem::Npm)];

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vulnerability_id, "");

    server.verify().await;
}

// ---------------------------------------------------------------------------
// Alias-group collapsing (ADR 0059)
//
// OSV returns a RustSec advisory and its GitHub-reviewed GHSA mirror as
// two records in the same `querybatch` response. The mirror usually
// carries neither a severity nor an informational marker, so it lowers to
// the SUP-4 fail-closed `Critical` and shadows the sibling that does carry
// the advisory's metadata — and the cross-backend merge cannot rescue it,
// because the two records have different advisory ids.
//
// Fixtures keep the file's contract: querybatch emits id + modified only;
// every richer field arrives on the hydrated `/v1/vulns/{id}` record.
// ---------------------------------------------------------------------------

/// A hydrated record with no `severity` and no informational marker — the
/// bare GHSA mirror shape. Lowering fails it closed to `Critical`.
fn bare_mirror_record(id: &str, eco: &str, pkg: &str, aliases: &[&str]) -> serde_json::Value {
    json!({
        "id": id,
        "modified": MODIFIED,
        "summary": format!("{pkg} advisory"),
        "aliases": aliases,
        "affected": [
            { "package": { "ecosystem": eco, "name": pkg } }
        ]
    })
}

/// A hydrated RustSec informational record: no CVSS by design, the class
/// under `affected[].database_specific.informational` where real RustSec
/// OSV records put it.
fn informational_record(
    id: &str,
    eco: &str,
    pkg: &str,
    class: &str,
    aliases: &[&str],
) -> serde_json::Value {
    json!({
        "id": id,
        "modified": MODIFIED,
        "summary": format!("{pkg}: {class}"),
        "aliases": aliases,
        "affected": [
            {
                "package": { "ecosystem": eco, "name": pkg },
                "database_specific": { "informational": class }
            }
        ]
    })
}

/// `rand 0.7.3` — `GHSA-cq8v-f236-94qc` (bare) + `RUSTSEC-2026-0097`
/// (`informational: unsound`). The pair must collapse to the
/// informational reading, which rides the negligible lane instead of
/// rejecting the artifact.
#[tokio::test]
async fn rand_ghsa_mirror_collapses_into_its_informational_rustsec_sibling() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[
                ("GHSA-cq8v-f236-94qc", MODIFIED),
                ("RUSTSEC-2026-0097", MODIFIED),
            ]])),
        )
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-cq8v-f236-94qc",
        bare_mirror_record(
            "GHSA-cq8v-f236-94qc",
            "crates.io",
            "rand",
            &["RUSTSEC-2026-0097"],
        ),
        1,
    )
    .await;
    mount_vuln_record(
        &server,
        "RUSTSEC-2026-0097",
        informational_record(
            "RUSTSEC-2026-0097",
            "crates.io",
            "rand",
            "unsound",
            &["GHSA-cq8v-f236-94qc"],
        ),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("rand", "0.7.3", Ecosystem::Cargo)];

    let findings = adapter.query(&comps).await.expect("query succeeds");

    assert_eq!(findings.len(), 1, "the mirror pair is one advisory");
    assert_eq!(findings[0].vulnerability_id, "RUSTSEC-2026-0097");
    assert!(
        findings[0].is_informational(),
        "the classification must survive the collapse",
    );
    assert!(
        findings[0]
            .aliases
            .iter()
            .any(|a| a == "GHSA-cq8v-f236-94qc"),
        "the collapsed-away id stays matchable by an exclusion: {:?}",
        findings[0].aliases,
    );
    server.verify().await;
}

/// `typemap 0.3.3` — `GHSA-vfv3-9w6v-23jp` (bare) + `RUSTSEC-2019-0039`
/// (`informational: unmaintained`), with the alias link pointing only
/// from the RustSec record to the mirror.
#[tokio::test]
async fn typemap_pair_collapses_to_the_informational_reading() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[
                ("GHSA-vfv3-9w6v-23jp", MODIFIED),
                ("RUSTSEC-2019-0039", MODIFIED),
            ]])),
        )
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-vfv3-9w6v-23jp",
        bare_mirror_record("GHSA-vfv3-9w6v-23jp", "crates.io", "typemap", &[]),
        1,
    )
    .await;
    mount_vuln_record(
        &server,
        "RUSTSEC-2019-0039",
        informational_record(
            "RUSTSEC-2019-0039",
            "crates.io",
            "typemap",
            "unmaintained",
            &["GHSA-vfv3-9w6v-23jp"],
        ),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("typemap", "0.3.3", Ecosystem::Cargo)];

    let findings = adapter.query(&comps).await.expect("query succeeds");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vulnerability_id, "RUSTSEC-2019-0039");
    assert!(findings[0].is_informational());
    server.verify().await;
}

/// **The load-bearing negative.** `traitobject 0.1.1` returns three
/// records: `GHSA-pp8r-vv2j-9j5v` (bare), `RUSTSEC-2020-0027` (**CVSS
/// 9.8**, `unsound`) and `RUSTSEC-2021-0144` (`unmaintained`). The
/// collapse must pick the SCORED member — a real CVSS outranks a
/// classification — so the package stays blocking. A collapse that
/// preferred the informational reading here would turn an over-blocking
/// fix into an under-blocking one (ADR 0007).
#[tokio::test]
async fn traitobject_group_collapses_to_the_scored_member_and_stays_blocking() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[
                ("GHSA-pp8r-vv2j-9j5v", MODIFIED),
                ("RUSTSEC-2020-0027", MODIFIED),
                ("RUSTSEC-2021-0144", MODIFIED),
            ]])),
        )
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-pp8r-vv2j-9j5v",
        bare_mirror_record(
            "GHSA-pp8r-vv2j-9j5v",
            "crates.io",
            "traitobject",
            &["RUSTSEC-2020-0027"],
        ),
        1,
    )
    .await;
    mount_vuln_record(
        &server,
        "RUSTSEC-2020-0027",
        json!({
            "id": "RUSTSEC-2020-0027",
            "modified": MODIFIED,
            "summary": "traitobject: unsound trait object handling",
            "aliases": ["GHSA-pp8r-vv2j-9j5v"],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "affected": [
                {
                    "package": { "ecosystem": "crates.io", "name": "traitobject" },
                    "database_specific": { "informational": "unsound" }
                }
            ]
        }),
        1,
    )
    .await;
    mount_vuln_record(
        &server,
        "RUSTSEC-2021-0144",
        informational_record(
            "RUSTSEC-2021-0144",
            "crates.io",
            "traitobject",
            "unmaintained",
            &["RUSTSEC-2020-0027"],
        ),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("traitobject", "0.1.1", Ecosystem::Cargo)];

    let findings = adapter.query(&comps).await.expect("query succeeds");

    assert_eq!(findings.len(), 1, "all three records are one advisory");
    let f = &findings[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2020-0027");
    assert_eq!(f.cvss_score, Some(9.8));
    assert_eq!(f.severity, SeverityThreshold::Critical);
    assert!(
        !f.is_informational(),
        "a scored advisory must never be demoted onto the negligible lane",
    );
    server.verify().await;
}

/// Two unrelated advisories on the same package stay two findings — the
/// collapse groups on identifiers, not on the package.
#[tokio::test]
async fn unrelated_advisories_on_one_component_are_not_collapsed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(querybatch_body(&[&[
                ("GHSA-aaaa-aaaa-aaaa", MODIFIED),
                ("GHSA-bbbb-bbbb-bbbb", MODIFIED),
            ]])),
        )
        .mount(&server)
        .await;
    mount_vuln_record(
        &server,
        "GHSA-aaaa-aaaa-aaaa",
        bare_mirror_record("GHSA-aaaa-aaaa-aaaa", "npm", "lodash", &[]),
        1,
    )
    .await;
    mount_vuln_record(
        &server,
        "GHSA-bbbb-bbbb-bbbb",
        bare_mirror_record("GHSA-bbbb-bbbb-bbbb", "npm", "lodash", &[]),
        1,
    )
    .await;

    let cache = Arc::new(InMemoryEphemeralStore::new());
    let adapter = build_adapter_with_url(server.uri(), cache, None).await;
    let comps = vec![make_component("lodash", "4.17.20", Ecosystem::Npm)];

    let findings = adapter.query(&comps).await.expect("query succeeds");
    assert_eq!(findings.len(), 2);
    server.verify().await;
}
