//! The publish kill switch, asserted where it is actually composed.
//!
//! `HORT_PUBLISH_BODY_MAX_SIZE` carries two different meanings on one
//! operator knob, and the composition root in
//! `hort_server::http::build_router_with_oci_config` is the only place
//! that can get the split right:
//!
//! - **A size.** npm, PyPI and Maven take the value as their publish
//!   ceiling. Cargo does not — it keeps its own fixed 200 MiB
//!   (`hort_http_core::limits::CARGO_PUBLISH_BODY_LIMIT`), because
//!   moving cargo's ceiling as a side effect of tuning the shared
//!   variable for Python wheels would surprise the operator who tuned
//!   it. OCI takes no ceiling from it at all: its upload path bounds
//!   each `PATCH` chunk through its own session accounting rather than
//!   capping a whole-blob request body.
//! - **Zero: refuse all publishes.** Not a smaller ceiling — a kill
//!   switch. It has to close every publish surface, cargo and OCI
//!   included. A kill switch an operator cannot trust is worse than
//!   none, because it changes what they do next: they stop looking for
//!   another way to halt writes.
//!
//! Each assertion therefore drives the **real** top-level router
//! (`build_router`) rather than a per-format route fragment: the defect
//! this suite pins was never inside a format crate, it was in which
//! surfaces the composition root handed the value to.
//!
//! # Rejection shape
//!
//! The refusal is `503 Service Unavailable` with no `Retry-After`,
//! produced by `hort_http_core::limits::refuse_publishes_when_disabled`
//! — one guard, applied once per publish subtree. It is NOT the body
//! limit: `DefaultBodyLimit::max(0)` rejects a body that has bytes in
//! it and admits one that does not, which is why every surface here is
//! asserted twice, once with a payload and once with a genuinely
//! zero-byte body. Maven's PUT has no envelope that could fail on
//! empty input, so the zero-byte case used to reach `ingest_direct`
//! and be *ingested* — an artifact row, an `ArtifactIngested`, a
//! quarantine timer and a scan job, out of a gate the operator
//! believed shut.
//!
//! `413 Payload Too Large` stays reserved for its own case: a body that
//! genuinely exceeds a configured non-zero ceiling
//! (`a_non_zero_limit_still_answers_413_for_an_over_size_body`). The two
//! cases are deliberately not one code path.
//!
//! # Mock context, no Postgres
//!
//! Every assertion runs against the in-memory `build_mock_ctx` harness —
//! no real connection is acquired, so no `#[serial(hort_pg_db)]` key is
//! needed (same reasoning as `rescan_rejection_visibility.rs`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;

use hort_app::use_cases::test_support::sample_repository;
use hort_domain::entities::repository::{RepositoryFormat, RepositoryType};
use hort_http_core::context::AppContext;
use hort_http_core::test_support::{build_mock_ctx, with_publish_body_limit, MockPorts};
use hort_server::http::build_router;

/// Publish-body size used by every non-empty assertion below. Big
/// enough to exceed the 1 KiB override the size-override tests set,
/// small enough that a unit test can hold it in memory — and,
/// crucially, non-empty, which is the only case the old body-limit
/// refusal could reject.
const BODY_BYTES: usize = 4096;

/// The size override the non-zero tests set: well under every format's
/// real ceiling, so a format that honours the override rejects
/// [`BODY_BYTES`] while a format that does not admits it.
const SMALL_OVERRIDE: usize = 1024;

/// Multipart boundary for the PyPI publish shape.
const PYPI_BOUNDARY: &str = "----hortpublishlimit";

/// An upload-session id for the OCI blob-upload PATCH / PUT / DELETE
/// shapes. The session does not exist in the mock — none of these
/// assertions is about what the handler would have answered, only
/// about whether the request reaches it.
const OCI_SESSION: &str = "550e8400-e29b-41d4-a716-446655440000";

/// Every publish surface the shared knob governs: the four hosted
/// formats plus the OCI push path.
///
/// OCI is here because the same method-discriminating guard covers it
/// — the blob-upload `POST`/`PATCH`/`PUT` dance and the manifest `PUT`
/// are exactly the methods the guard holds — so the documented
/// "refuse all publishes" reach is the real one.
#[derive(Debug, Clone, Copy)]
enum PublishSurface {
    Cargo,
    Npm,
    Pypi,
    Maven,
    Oci,
}

impl PublishSurface {
    /// Repository key seeded for this surface, and the key its publish
    /// request addresses.
    fn repo_key(self) -> &'static str {
        match self {
            Self::Cargo => "cargo-pub",
            Self::Npm => "npm-pub",
            Self::Pypi => "pypi-pub",
            Self::Maven => "maven-pub",
            Self::Oci => "oci-pub",
        }
    }

    fn repo_format(self) -> RepositoryFormat {
        match self {
            Self::Cargo => RepositoryFormat::Cargo,
            Self::Npm => RepositoryFormat::Npm,
            Self::Pypi => RepositoryFormat::Pypi,
            Self::Maven => RepositoryFormat::Maven,
            Self::Oci => RepositoryFormat::Oci,
        }
    }

    /// This surface's canonical publish route and method, as a request
    /// builder with no body attached yet.
    ///
    /// Split out from the body so the same route is exercised with a
    /// payload and with zero bytes — the pair that separates "the
    /// publish is refused" from "a body with bytes in it is refused".
    fn publish_route(self) -> axum::http::request::Builder {
        let repo = self.repo_key();
        match self {
            Self::Cargo => Request::put(format!("/cargo/{repo}/api/v1/crates/new")),
            Self::Npm => Request::put(format!("/npm/{repo}/mypkg")),
            Self::Pypi => Request::post(format!("/pypi/{repo}/")).header(
                "content-type",
                format!("multipart/form-data; boundary={PYPI_BOUNDARY}"),
            ),
            Self::Maven => Request::put(format!("/maven/{repo}/com/example/lib/1.0/lib-1.0.jar")),
            Self::Oci => Request::post(format!("/v2/{repo}/library/app/blobs/uploads/")),
        }
    }

    /// A publish request carrying [`BODY_BYTES`] bytes of payload.
    ///
    /// The payload is filler, not a well-formed artifact: every
    /// assertion here is about whether the body reaches the handler at
    /// all. PyPI gets real multipart framing around the filler because
    /// its route is reached through a `Multipart` extractor and an
    /// unframed payload would be rejected for a reason this suite is
    /// not asking about.
    fn publish_request(self) -> Request<Body> {
        let filler = vec![b'x'; BODY_BYTES];
        let body = match self {
            Self::Pypi => {
                let mut body = Vec::new();
                body.extend_from_slice(format!("--{PYPI_BOUNDARY}\r\n").as_bytes());
                body.extend_from_slice(
                    b"Content-Disposition: form-data; name=\"content\"; filename=\"pkg-1.0.tar.gz\"\r\n\r\n",
                );
                body.extend_from_slice(&filler);
                body.extend_from_slice(format!("\r\n--{PYPI_BOUNDARY}--\r\n").as_bytes());
                body
            }
            _ => filler,
        };
        self.publish_route().body(Body::from(body)).unwrap()
    }

    /// The same publish request with a genuinely zero-byte body.
    ///
    /// This is the case `DefaultBodyLimit::max(0)` admits — zero bytes
    /// is within a zero-byte ceiling — and so the case the refusal has
    /// to answer for its own reasons rather than as a side effect of
    /// the payload grammar.
    fn empty_publish_request(self) -> Request<Body> {
        self.publish_route().body(Body::empty()).unwrap()
    }

    /// A read on this surface: never held, whatever the switch says.
    fn read_request(self) -> Request<Body> {
        let repo = self.repo_key();
        match self {
            Self::Cargo => Request::get(format!("/cargo/{repo}/config.json")),
            Self::Npm => Request::get(format!("/npm/{repo}/mypkg")),
            Self::Pypi => Request::get(format!("/pypi/{repo}/simple/")),
            Self::Maven => Request::get(format!("/maven/{repo}/com/example/lib/1.0/lib-1.0.jar")),
            Self::Oci => Request::get("/v2/".to_string()),
        }
        .body(Body::empty())
        .unwrap()
    }
}

const ALL_SURFACES: [PublishSurface; 5] = [
    PublishSurface::Cargo,
    PublishSurface::Npm,
    PublishSurface::Pypi,
    PublishSurface::Maven,
    PublishSurface::Oci,
];

/// The three surfaces that take a non-zero `HORT_PUBLISH_BODY_MAX_SIZE`
/// as their publish ceiling. Cargo keeps its own, and OCI takes none.
const SIZED_SURFACES: [PublishSurface; 3] = [
    PublishSurface::Npm,
    PublishSurface::Pypi,
    PublishSurface::Maven,
];

/// Seed one hosted repository per surface onto the shared mock ports.
fn seed_repos(mocks: &MockPorts) {
    for surface in ALL_SURFACES {
        let mut repo = sample_repository();
        repo.key = surface.repo_key().to_string();
        repo.format = surface.repo_format();
        repo.repo_type = RepositoryType::Hosted;
        mocks.repositories.insert(repo);
    }
}

/// Build the production top-level router over a mock context whose
/// `publish_body_limit_bytes` is `limit` — `None` meaning the operator
/// set nothing.
fn router_with_limit(limit: Option<usize>) -> axum::Router {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    let (base, mocks) = build_mock_ctx(handle);
    seed_repos(&mocks);
    let ctx: Arc<AppContext> = with_publish_body_limit(&base, limit);
    build_router(ctx)
}

/// Fire `request` through the real top-level router composed with
/// `limit`, and return the status.
async fn status_of(limit: Option<usize>, request: Request<Body>) -> StatusCode {
    router_with_limit(limit)
        .oneshot(request)
        .await
        .expect("router call is infallible")
        .status()
}

/// One half of the kill-switch assertion for a surface: a publish
/// carrying a payload. This is the case the old body-limit refusal
/// already answered, kept so a regression that reopens it is visible.
async fn assert_payload_publish_is_held(surface: PublishSurface) {
    assert_eq!(
        status_of(Some(0), surface.publish_request()).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "{surface:?} admitted a {BODY_BYTES}-byte publish with the kill switch on"
    );
}

/// The other half, and the one this unit exists for: the same publish
/// route with a genuinely zero-byte body, which a zero-byte
/// `DefaultBodyLimit` admits.
async fn assert_empty_publish_is_held(surface: PublishSurface) {
    assert_eq!(
        status_of(Some(0), surface.empty_publish_request()).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "{surface:?} did not refuse a zero-byte publish with the kill switch on"
    );
}

// ---------------------------------------------------------------------------
// `0` refuses a publish — two tests per surface, one per body shape.
//
// The two shapes are separate tests rather than two assertions in one,
// because they fail for different reasons and the empty one is the
// regression this unit closes: a single test would stop at the first
// assertion and report the payload case, hiding which half broke.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kill_switch_refuses_a_cargo_publish() {
    assert_payload_publish_is_held(PublishSurface::Cargo).await;
}

#[tokio::test]
async fn kill_switch_refuses_an_empty_cargo_publish() {
    assert_empty_publish_is_held(PublishSurface::Cargo).await;
}

#[tokio::test]
async fn kill_switch_refuses_an_npm_publish() {
    assert_payload_publish_is_held(PublishSurface::Npm).await;
}

#[tokio::test]
async fn kill_switch_refuses_an_empty_npm_publish() {
    assert_empty_publish_is_held(PublishSurface::Npm).await;
}

#[tokio::test]
async fn kill_switch_refuses_a_pypi_publish() {
    assert_payload_publish_is_held(PublishSurface::Pypi).await;
}

#[tokio::test]
async fn kill_switch_refuses_an_empty_pypi_publish() {
    assert_empty_publish_is_held(PublishSurface::Pypi).await;
}

#[tokio::test]
async fn kill_switch_refuses_a_maven_publish() {
    assert_payload_publish_is_held(PublishSurface::Maven).await;
}

/// The regression's exemplar: this exact request — a `.jar` `PUT` with
/// no bytes — was *ingested* with the switch on, because Maven's PUT has
/// no envelope that could fail on empty input.
#[tokio::test]
async fn kill_switch_refuses_an_empty_maven_publish() {
    assert_empty_publish_is_held(PublishSurface::Maven).await;
}

#[tokio::test]
async fn kill_switch_refuses_an_oci_publish() {
    assert_payload_publish_is_held(PublishSurface::Oci).await;
}

#[tokio::test]
async fn kill_switch_refuses_an_empty_oci_publish() {
    assert_empty_publish_is_held(PublishSurface::Oci).await;
}

/// The refusal carries no `Retry-After`: this hold has no deadline to
/// quote (it ends when an operator changes the configuration), and a
/// fabricated interval is one a well-behaved client would act on. The
/// body says so instead.
#[tokio::test]
async fn the_refusal_carries_no_retry_after_and_says_why() {
    let response = router_with_limit(Some(0))
        .oneshot(PublishSurface::Maven.publish_request())
        .await
        .expect("router call is infallible");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none(),
        "the publish hold has no deadline, so it must not quote one"
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "publishing is disabled on this server");
    assert!(json["detail"]
        .as_str()
        .expect("detail is a string")
        .contains("Retry-After"),);
}

/// The OCI subtree answers in the Distribution spec's `errors`-array
/// envelope rather than the generic `{"error":...}` body, so docker and
/// the containerd resolver surface the message instead of reporting an
/// unexplained 503.
#[tokio::test]
async fn the_oci_refusal_uses_the_oci_error_envelope() {
    let response = router_with_limit(Some(0))
        .oneshot(PublishSurface::Oci.publish_request())
        .await
        .expect("router call is infallible");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none(),
        "the publish hold has no deadline, so it must not quote one"
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["errors"][0]["code"], "UNAVAILABLE");
    assert_eq!(
        json["errors"][0]["message"],
        "publishing is disabled on this server"
    );
}

/// Every method in the OCI push dance, not only the initiate POST: the
/// chunked-upload `PATCH`, the finalize `PUT`, and the manifest `PUT`
/// that is the actual publication of an image.
#[tokio::test]
async fn kill_switch_refuses_every_oci_push_method() {
    let repo = PublishSurface::Oci.repo_key();
    let pushes = [
        Request::patch(format!(
            "/v2/{repo}/library/app/blobs/uploads/{OCI_SESSION}"
        ))
        .body(Body::from(vec![b'x'; BODY_BYTES]))
        .unwrap(),
        Request::put(format!(
            "/v2/{repo}/library/app/blobs/uploads/{OCI_SESSION}?digest=sha256:{}",
            "0".repeat(64)
        ))
        .body(Body::from(vec![b'x'; BODY_BYTES]))
        .unwrap(),
        Request::put(format!("/v2/{repo}/library/app/manifests/v1"))
            .header("content-type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(r#"{"schemaVersion":2}"#))
            .unwrap(),
    ];
    for push in pushes {
        let label = format!("{} {}", push.method(), push.uri());
        assert_eq!(
            status_of(Some(0), push).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{label} was admitted with the kill switch on"
        );
    }
}

/// An npm dist-tag `PUT` retargets what `npm install <pkg>` resolves
/// to, so the guard holds it like any other publish even though its own
/// per-route body limit is far below the shared one. Behaviour change:
/// before the guard, the per-route `DefaultBodyLimit` won and the write
/// went through with the switch on.
#[tokio::test]
async fn kill_switch_refuses_an_npm_dist_tag_write() {
    let repo = PublishSurface::Npm.repo_key();
    let request = Request::put(format!("/npm/{repo}/-/package/mypkg/dist-tags/latest"))
        .body(Body::from(r#""1.0.0""#))
        .unwrap();
    assert_eq!(
        status_of(Some(0), request).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

// ---------------------------------------------------------------------------
// What the switch deliberately does NOT hold.
// ---------------------------------------------------------------------------

/// A hort that stopped serving artifacts because publishing was
/// switched off would be a worse failure than the one the switch exists
/// to produce. The guard discriminates by method, so every read passes
/// while the switch is on.
#[tokio::test]
async fn reads_are_untouched_while_the_switch_is_on() {
    for surface in ALL_SURFACES {
        let held = status_of(Some(0), surface.read_request()).await;
        assert_ne!(
            held,
            StatusCode::SERVICE_UNAVAILABLE,
            "{surface:?} refused a read with the publish kill switch on"
        );
        // Stronger than "not a hold", and the assertion that does not
        // depend on what a mock-backed read handler happens to answer:
        // the switch must make no difference to a read at all.
        assert_eq!(
            held,
            status_of(None, surface.read_request()).await,
            "{surface:?} answered a read differently with the publish kill switch on"
        );
    }
    // Maven serves HEAD off the same handler as GET; assert the method
    // itself is not held rather than trusting the GET result to cover it.
    let repo = PublishSurface::Maven.repo_key();
    let head = || {
        Request::head(format!("/maven/{repo}/com/example/lib/1.0/lib-1.0.jar"))
            .body(Body::empty())
            .unwrap()
    };
    let held_head = status_of(Some(0), head()).await;
    assert_ne!(
        held_head,
        StatusCode::SERVICE_UNAVAILABLE,
        "a Maven HEAD was refused with the publish kill switch on"
    );
    assert_eq!(
        held_head,
        status_of(None, head()).await,
        "a Maven HEAD answered differently with the publish kill switch on"
    );
}

/// `DELETE` is not a publish, and holding it would strand work a client
/// then cannot clean up: the OCI
/// `DELETE /v2/<name>/blobs/uploads/<uuid>` cancel is how a client
/// releases an upload session it can no longer finish. Removal is
/// governed elsewhere; this knob's contract is publishes.
#[tokio::test]
async fn deletes_are_untouched_while_the_switch_is_on() {
    let oci = PublishSurface::Oci.repo_key();
    let cancel = Request::delete(format!("/v2/{oci}/library/app/blobs/uploads/{OCI_SESSION}"))
        .body(Body::empty())
        .unwrap();
    assert_ne!(
        status_of(Some(0), cancel).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "an OCI upload-session cancel was refused with the publish kill switch on"
    );

    let npm = PublishSurface::Npm.repo_key();
    let dist_tag = Request::delete(format!("/npm/{npm}/-/package/mypkg/dist-tags/latest"))
        .body(Body::empty())
        .unwrap();
    assert_ne!(
        status_of(Some(0), dist_tag).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "an npm dist-tag delete was refused with the publish kill switch on"
    );
}

/// The guard wraps the subtrees' routes, not their fallback, so an
/// unmatched path still answers `404` while the switch is on instead of
/// reporting a publish hold on a route that does not exist.
#[tokio::test]
async fn an_unmatched_path_still_answers_404_while_the_switch_is_on() {
    let request = Request::post("/not-a-mount/anything")
        .body(Body::from(vec![b'x'; BODY_BYTES]))
        .unwrap();
    assert_eq!(status_of(Some(0), request).await, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// A non-zero override is a size: `413`, through the body limit, and the
// two cases stay distinct.
// ---------------------------------------------------------------------------

/// The over-size case keeps its own answer. `413` is correct here and
/// wrong for the hold, which is the whole reason the two are separate
/// mechanisms rather than one.
#[tokio::test]
async fn a_non_zero_limit_still_answers_413_for_an_over_size_body() {
    for surface in SIZED_SURFACES {
        assert_eq!(
            status_of(Some(SMALL_OVERRIDE), surface.publish_request()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{surface:?} did not answer 413 for a {BODY_BYTES}-byte body under a \
             {SMALL_OVERRIDE}-byte ceiling"
        );
    }
}

/// Maven previously hard-coded `DEFAULT_PUBLISH_BODY_LIMIT` on its PUT
/// and so ignored the configured value entirely. With the override at
/// 1 KiB a 4 KiB `.jar` must be refused — and refused as an over-size
/// body, not as a hold.
#[tokio::test]
async fn a_size_override_reaches_maven() {
    assert_eq!(
        status_of(
            Some(SMALL_OVERRIDE),
            PublishSurface::Maven.publish_request()
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

/// The recorded decision that cargo's *ceiling* is not driven by the
/// shared variable — pinned rather than merely commented. A 1 KiB
/// override leaves a 4 KiB cargo publish body admitted, and leaves it
/// answered exactly as it is with no override set at all.
///
/// The second assertion is the stronger of the two and is deliberately
/// phrased against the unset baseline rather than against a literal
/// status: what the recorded decision promises is that a shared *size*
/// changes nothing for cargo, and that holds whatever the handler
/// answers a filler payload (today a 400 on the malformed publish
/// envelope). A future change to that shape should not have to touch
/// this test.
#[tokio::test]
async fn a_size_override_does_not_move_cargos_ceiling() {
    let with_override = status_of(
        Some(SMALL_OVERRIDE),
        PublishSurface::Cargo.publish_request(),
    )
    .await;
    assert_ne!(
        with_override,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a 1 KiB shared override must not cap cargo at 1 KiB"
    );
    let unset = status_of(None, PublishSurface::Cargo.publish_request()).await;
    assert_eq!(
        with_override, unset,
        "a non-zero shared override must leave cargo's publish path indistinguishable \
         from the unset case"
    );
}

/// A non-zero shared size is not a ceiling for the OCI push path at
/// all: the upload surface bounds each chunk through its own session
/// accounting, which is what lets a multi-GB base layer through at the
/// default. A 1 KiB shared override must therefore leave an OCI push
/// indistinguishable from the unset case — only `0` reaches it.
#[tokio::test]
async fn a_size_override_does_not_reach_the_oci_push_path() {
    let with_override =
        status_of(Some(SMALL_OVERRIDE), PublishSurface::Oci.publish_request()).await;
    assert_ne!(
        with_override,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a 1 KiB shared override must not cap an OCI blob upload at 1 KiB"
    );
    let unset = status_of(None, PublishSurface::Oci.publish_request()).await;
    assert_eq!(
        with_override, unset,
        "a non-zero shared override must leave the OCI push path indistinguishable \
         from the unset case"
    );
}

// ---------------------------------------------------------------------------
// Unset leaves every surface where it is today.
// ---------------------------------------------------------------------------

/// With no override every surface keeps its own ceiling — 300 MiB for
/// npm / PyPI / Maven, 200 MiB for cargo, per-chunk accounting for OCI
/// — so a 4 KiB publish body is admitted on all five, and no surface
/// reports a hold. The exact numbers are pinned next to the constants
/// themselves (`hort_http_core::limits` → `cargo_publish_body_limit`
/// tests); what this asserts is the property a 300 MiB request cannot
/// assert in a unit test: the composition root hands each surface a
/// ceiling that admits an ordinary publish body.
#[tokio::test]
async fn an_unset_override_admits_a_publish_body_on_every_surface() {
    for surface in ALL_SURFACES {
        let status = status_of(None, surface.publish_request()).await;
        assert_ne!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{surface:?} rejected a {BODY_BYTES}-byte publish body with no override set"
        );
        assert_ne!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{surface:?} reported a publish hold with no override set"
        );
    }
}
