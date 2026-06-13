//! HTTP/1 transport timeouts (see
//! `docs/architecture/how-to/http-transport-timeouts.md`).
//!
//! Integration tests for the `serve_loop` module's `hyper_util`-backed
//! serve function. Each test binds a real loopback TCP listener, drives a
//! raw `tokio::net::TcpStream` against it (so we exercise the bytes the
//! adversary can actually send), and asserts the timeout behaviour.
//!
//! These tests intentionally do NOT go through the real router — the
//! transport-level invariants (header_read_timeout, request-deadline
//! TimeoutLayer, OCI-upload override) are what we lock here. Handler
//! correctness is covered by the per-format crate tests.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::patch;
use axum::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use hort_server::serve_loop::{serve_with_hyper_util, HttpTimeouts};

/// Bind to an ephemeral loopback port, returning both the listener and
/// the resolved `SocketAddr` (so tests can `connect()` to it).
async fn ephemeral_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    (listener, addr)
}

/// Minimal handler that returns 200 immediately. Used by the slow-header
/// test where we never send a real request.
async fn ok_handler() -> impl IntoResponse {
    StatusCode::OK
}

/// **RED → GREEN regression test for the header-read timeout.**
///
/// Open a TCP connection, write ONE byte (`G`, the start of a `GET`),
/// and assert the server closes the connection within
/// `header_read_timeout + epsilon`. With the pre-fix `axum::serve(...)`
/// invocation this connection would stay open until either the OS
/// socket timeout fired (typically minutes) or the attacker gave up —
/// the slowloris vector that `header_read_timeout` closes.
///
/// The connection-close signal is `read_to_end` returning Ok(0)
/// (EOF). We measure the wall-clock time between the byte write and
/// the EOF and assert it sits in `[header_read_timeout, header_read_timeout + epsilon]`.
#[tokio::test]
async fn slow_header_client_disconnected_within_header_read_timeout() {
    let (listener, addr) = ephemeral_listener().await;
    let app: Router = Router::new().route("/", axum::routing::get(ok_handler));
    let timeouts = HttpTimeouts {
        header_read_timeout: Duration::from_millis(500),
        http2_keep_alive_interval: Duration::from_secs(30),
        http2_keep_alive_timeout: Duration::from_secs(30),
    };

    let shutdown = CancellationToken::new();
    let serve_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            serve_with_hyper_util(listener, app, timeouts, shutdown)
                .await
                .expect("serve loop");
        })
    };

    // Open a connection and send a single byte. Hyper should refuse to
    // sit on this beyond the configured header_read_timeout.
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let started = Instant::now();
    stream.write_all(b"G").await.expect("write byte");

    // Read until EOF — the connection close from the server side.
    let mut buf = Vec::new();
    let read_result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
        .await
        .expect("server failed to close slow-header connection within 2s");
    let _ = read_result.expect("read until EOF");
    let elapsed = started.elapsed();

    // Lower bound: the server must NOT close before the configured
    // timeout (else we'd have a regression that disconnects valid
    // clients). 400ms < 500ms gives a small safety margin for OS
    // scheduling jitter at the lower edge.
    assert!(
        elapsed >= Duration::from_millis(400),
        "connection closed too early: {elapsed:?} (header_read_timeout = 500ms)"
    );
    // Upper bound: 1.5s = header_read_timeout + 1s of slack for CI
    // jitter / executor wakeup latency.
    assert!(
        elapsed <= Duration::from_millis(1500),
        "connection took too long to close: {elapsed:?} (header_read_timeout = 500ms)"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
}

/// Request-deadline TimeoutLayer.
///
/// A request whose handler exceeds the configured per-route deadline
/// must be cut off; the client sees `408 Request Timeout`. The handler
/// here sleeps 800ms; the layer is set to 200ms.
#[tokio::test]
async fn request_deadline_layer_returns_408_when_handler_exceeds_deadline() {
    use hort_http_core::middleware::request_timeout::request_timeout_layer;

    let app: Router = Router::new()
        .route(
            "/slow",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(800)).await;
                StatusCode::OK
            }),
        )
        .layer(request_timeout_layer(Duration::from_millis(200)));

    let (listener, addr) = ephemeral_listener().await;
    let timeouts = HttpTimeouts {
        header_read_timeout: Duration::from_secs(15),
        http2_keep_alive_interval: Duration::from_secs(30),
        http2_keep_alive_timeout: Duration::from_secs(30),
    };

    let shutdown = CancellationToken::new();
    let serve_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            serve_with_hyper_util(listener, app, timeouts, shutdown)
                .await
                .expect("serve loop");
        })
    };

    // Drive a real HTTP/1.1 GET request via raw bytes (no reqwest dep
    // pulled in by hort-server tests).
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write GET");
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
        .await
        .expect("response read")
        .expect("read");

    assert!(
        response.starts_with("HTTP/1.1 408") || response.contains(" 408 "),
        "expected 408 Request Timeout, got: {response}"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
}

/// Per-route OCI upload exemption.
///
/// The 5-minute global default would cut a 31-minute multi-GB OCI blob
/// PATCH; the per-route override at the OCI sub-router gives those
/// routes a 60-minute ceiling. This test pins that the override takes
/// effect: a handler that sleeps longer than the global default but
/// under the OCI ceiling completes successfully.
///
/// We compress timescales (global = 100ms, OCI override = 2s, handler
/// sleeps 500ms) so the test runs in seconds, not hours.
#[tokio::test]
async fn oci_upload_route_exempted_from_global_request_deadline() {
    use hort_http_core::middleware::request_timeout::request_timeout_layer;

    // OCI upload subtree gets the long timeout.
    let oci_uploads: Router = Router::new()
        .route(
            "/v2/:repo/blobs/uploads/:uuid",
            patch(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                StatusCode::ACCEPTED
            })
            .put(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                StatusCode::CREATED
            }),
        )
        .layer(request_timeout_layer(Duration::from_secs(2)));

    // Everything else gets the short timeout.
    let everything_else: Router = Router::new()
        .route(
            "/short",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                StatusCode::OK
            }),
        )
        .layer(request_timeout_layer(Duration::from_millis(100)));

    let app = oci_uploads.merge(everything_else);

    let (listener, addr) = ephemeral_listener().await;
    let timeouts = HttpTimeouts {
        header_read_timeout: Duration::from_secs(15),
        http2_keep_alive_interval: Duration::from_secs(30),
        http2_keep_alive_timeout: Duration::from_secs(30),
    };

    let shutdown = CancellationToken::new();
    let serve_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            serve_with_hyper_util(listener, app, timeouts, shutdown)
                .await
                .expect("serve loop");
        })
    };

    // (a) The OCI upload PATCH (handler sleeps 500ms; long timeout 2s):
    //     should succeed with 202.
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"PATCH /v2/myrepo/blobs/uploads/abc HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .expect("write PATCH");
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut response))
        .await
        .expect("response read")
        .expect("read");
    assert!(
        response.starts_with("HTTP/1.1 202"),
        "OCI upload PATCH must NOT be cut by the global short timeout — got: {response}"
    );

    // (b) The non-OCI route (handler sleeps 500ms; short timeout 100ms):
    //     must be cut, 408.
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET /short HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write GET short");
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
        .await
        .expect("response read")
        .expect("read");
    assert!(
        response.starts_with("HTTP/1.1 408") || response.contains(" 408 "),
        "non-OCI route must hit the global short timeout — got: {response}"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
}

/// Graceful shutdown.
///
/// After `cancel()` fires on the shutdown token, the serve future MUST
/// return rather than blocking forever (e.g. on a stuck timed-out
/// connection). This is the "no infinite wait" half of the acceptance
/// bar.
#[tokio::test]
async fn graceful_shutdown_returns_promptly() {
    let (listener, _addr) = ephemeral_listener().await;
    let app: Router = Router::new().route("/", axum::routing::get(ok_handler));
    let timeouts = HttpTimeouts {
        header_read_timeout: Duration::from_secs(15),
        http2_keep_alive_interval: Duration::from_secs(30),
        http2_keep_alive_timeout: Duration::from_secs(30),
    };

    let shutdown = CancellationToken::new();
    let serve_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            serve_with_hyper_util(listener, app, timeouts, shutdown)
                .await
                .expect("serve loop");
        })
    };

    // Give the accept loop a tick to settle.
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.cancel();

    // Shutdown must complete promptly — within a few hundred ms is
    // plenty of slack for the shutdown signal to propagate. The
    // upper bound is 2s to keep CI noise low.
    let outcome = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
    let _ = outcome.expect("serve loop did not return within 2s of shutdown.cancel()");
}
