//! Hyper-util backed serve loop with explicit transport timeouts.
//!
//! `axum::serve(...)` invokes hyper with all defaults: no
//! `http1_header_read_timeout`, no HTTP/2 keep-alive ping interval. The
//! result is that a single attacker can hold a slowloris connection
//! open until the OS socket timer fires (typically minutes), pinning a
//! hyper accept worker per byte trickled through. The layer's
//! [`tower_governor`]-based rate-limit only fires AFTER header parsing
//! completes, so it does not bound this surface.
//!
//! This module replaces the `axum::serve(...)` call with an explicit
//! [`hyper_util::server::conn::auto::Builder`] form so we can configure:
//!
//! - `http1_header_read_timeout` (default 15s) — the slowloris kill.
//! - HTTP/2 `keep_alive_interval` + `keep_alive_timeout` — bounds idle
//!   sessions on the multiplex side.
//! - `keep_alive(true)` for HTTP/1 — explicit (matches hyper default).
//!
//! An HTTP/1 `keep_alive_timeout` is NOT
//! exposed by hyper 1.x; between-request idle on a keep-alive HTTP/1
//! connection is governed by `header_read_timeout` (the next request's
//! request-line + headers must arrive within that window). The
//! operator how-to documents this.
//!
//! # Graceful shutdown
//!
//! On `shutdown.cancel()` the accept loop exits its outer `select!`,
//! and the [`hyper_util::server::graceful::GracefulShutdown`] watcher
//! signals every in-flight connection to finish-and-close. We bound
//! the wait at `SHUTDOWN_DEADLINE` (60 s) so a stuck timed-out
//! connection cannot pin shutdown forever — no infinite wait on stuck
//! timed-out connections.

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::{debug, warn};

/// Hard wall-clock cap on the shutdown drain. Beyond this, in-flight
/// connections are dropped on the floor — the alternative is shutdown
/// hanging indefinitely on a stuck timed-out connection.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// Per-connection HTTP transport timeouts. Carried as a struct so the
/// composition root can pass one value through the function signature
/// rather than three positional Durations.
///
/// - `header_read_timeout`: applied via
///   [`hyper_util::server::conn::auto::Http1Builder::header_read_timeout`].
///   Caps the time the server waits for a complete request line +
///   headers; under HTTP/1 keep-alive this also caps between-request
///   idle.
/// - `http2_keep_alive_interval` / `http2_keep_alive_timeout`: applied
///   via the matching HTTP/2 builder methods. The interval picks how
///   often hyper sends a PING frame; the timeout fires the connection
///   close if the peer fails to respond within that window.
#[derive(Debug, Clone, Copy)]
pub struct HttpTimeouts {
    /// Maximum time the server waits to read request headers (and,
    /// transitively, the next-request idle on an HTTP/1 keep-alive
    /// connection). Default in production: 15s.
    pub header_read_timeout: Duration,
    /// HTTP/2 PING interval. Default: 30s.
    pub http2_keep_alive_interval: Duration,
    /// HTTP/2 close-after-no-pong window. Default: 30s.
    pub http2_keep_alive_timeout: Duration,
}

impl HttpTimeouts {
    /// Production defaults. Override individual fields when callers want
    /// to tune. Tests use the explicit struct literal so the override
    /// is visible at the call site.
    pub fn defaults() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(15),
            http2_keep_alive_interval: Duration::from_secs(30),
            http2_keep_alive_timeout: Duration::from_secs(30),
        }
    }
}

/// Drive the supplied `axum::Router` over the supplied TCP listener
/// using `hyper_util`'s explicit auto-builder, with transport timeouts
/// wired in.
///
/// `router` is consumed and turned into a per-connection
/// `MakeService<SocketAddr, _>` via
/// [`Router::into_make_service_with_connect_info`] — the same call
/// path the pre-fix `axum::serve(...)` used, preserving the
/// `RequestTrust::client_ip` injection for the layer attached in
/// `wrap_with_middleware`.
///
/// `shutdown` is cloned per connection: the accept loop selects on
/// `shutdown.cancelled()` to break, and the
/// [`GracefulShutdown`] watcher signals in-flight connections to
/// drain. A connection that ignores the signal is bounded by the
/// `SHUTDOWN_DEADLINE` wall clock.
pub async fn serve_with_hyper_util(
    listener: TcpListener,
    router: Router,
    timeouts: HttpTimeouts,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // `into_make_service_with_connect_info::<SocketAddr>()` is the same
    // axum incantation the previous `axum::serve(...)` call used. It
    // produces a MakeService that accepts the peer SocketAddr and
    // returns a per-connection service; the SocketAddr is then injected
    // as a `ConnectInfo<SocketAddr>` extension so `request_trust_layer`
    // can read the peer IP. Without this wiring, the trust layer would
    // see no ConnectInfo and treat every request as untrusted-peer.
    let mut make_service = router.into_make_service_with_connect_info::<SocketAddr>();

    let builder = build_hyper_builder(timeouts);
    let graceful = GracefulShutdown::new();

    loop {
        tokio::select! {
            biased;
            // Shutdown branch first — once cancelled we stop accepting
            // and drop into the graceful drain below.
            () = shutdown.cancelled() => {
                debug!("serve_with_hyper_util: shutdown signal received; draining");
                break;
            }
            accept_result = listener.accept() => {
                let (stream, peer) = match accept_result {
                    Ok(pair) => pair,
                    Err(err) => {
                        // Accept errors are typically transient
                        // (EMFILE, ECONNABORTED). Logging then continuing
                        // matches axum::serve's behaviour.
                        warn!(error = %err, "accept failed; continuing");
                        continue;
                    }
                };

                // Hand the connected SocketAddr to the make-service so
                // the per-connection Service carries the right
                // ConnectInfo extension. `make_service.call` is
                // infallible for axum's MakeService<_, Router>, but we
                // still propagate via `?` to remain future-proof.
                let tower_service = match make_service.call(peer).await {
                    Ok(svc) => svc,
                    Err(err) => {
                        warn!(error = %err, "make_service call failed; dropping connection");
                        continue;
                    }
                };
                let hyper_service = TowerToHyperService { inner: tower_service };

                let io = TokioIo::new(stream);
                let conn = builder.serve_connection_with_upgrades(io, hyper_service);
                let watched = graceful.watch(conn.into_owned());

                tokio::spawn(async move {
                    if let Err(err) = watched.await {
                        // hyper logs its own per-connection errors at
                        // debug; surface as debug here too so the
                        // accept loop is not noisy under transient
                        // client misbehaviour (slow-header timeouts
                        // surface as IncompleteMessage and would dwarf
                        // the noise budget if logged at warn).
                        debug!(error = %err, peer = %peer, "connection ended with error");
                    }
                });
            }
        }
    }

    // Graceful drain: signal in-flight connections to finish, then wait
    // up to SHUTDOWN_DEADLINE before forcing exit. The deadline exists
    // so a stuck timed-out connection cannot pin shutdown forever.
    match tokio::time::timeout(SHUTDOWN_DEADLINE, graceful.shutdown()).await {
        Ok(()) => {
            debug!("graceful shutdown complete");
        }
        Err(_) => {
            warn!(
                deadline_secs = SHUTDOWN_DEADLINE.as_secs(),
                "shutdown deadline exceeded; dropping in-flight connections"
            );
        }
    }

    Ok(())
}

/// Build the hyper auto-builder with H-2 timeouts wired in. Factored
/// out so the configuration is unit-testable without spinning a
/// listener (and so the per-test override in `serve_with_hyper_util`
/// can call into the same constructor).
fn build_hyper_builder(timeouts: HttpTimeouts) -> Builder<TokioExecutor> {
    let mut builder = Builder::new(TokioExecutor::new());
    // hyper requires a Timer for `header_read_timeout`. TokioTimer
    // defers to `tokio::time::sleep` — same runtime the rest of the
    // server lives in.
    builder
        .http1()
        .timer(TokioTimer::new())
        .keep_alive(true)
        .header_read_timeout(timeouts.header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(timeouts.http2_keep_alive_interval)
        .keep_alive_timeout(timeouts.http2_keep_alive_timeout);
    builder
}

/// Bridge a `tower::Service<axum::extract::Request>` into a
/// `hyper::service::Service<hyper::Request<Incoming>>`.
///
/// axum 0.7's `Router::into_make_service_with_connect_info` emits a
/// MakeService whose per-connection Service consumes
/// `axum::extract::Request<Body>`. Hyper's `serve_connection_*` family
/// expects `hyper::service::Service<Request<Incoming>>`. The two
/// shapes are compatible (axum's `Request` is built atop hyper's
/// `http::Request<Body>`) — this newtype is the glue that converts
/// the body type and forwards the call.
#[derive(Clone)]
struct TowerToHyperService<S> {
    inner: S,
}

impl<S> hyper::service::Service<hyper::Request<Incoming>> for TowerToHyperService<S>
where
    S: Service<axum::extract::Request> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send,
    S::Error: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<S::Response, S::Error>> + Send + 'static>,
    >;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        // Convert the hyper `Incoming` body into axum's `Body` (which
        // wraps any `http_body::Body`). axum 0.7's `Body::new` accepts
        // anything `http_body::Body<Data = Bytes, Error: ...> + Send`.
        let req = req.map(axum::body::Body::new);
        // `Service::call` requires `&mut self`; clone gives us an owned
        // service per request. Axum's per-connection Service is `Clone`
        // for exactly this reason.
        let mut inner = self.inner.clone();
        Box::pin(async move { Service::call(&mut inner, req).await })
    }
}

/// Marker impl: hyper-util's `Connected` trait wires the peer
/// SocketAddr through the `make_service` call. axum already implements
/// `Connected<SocketAddr> for SocketAddr` so callers can use
/// `into_make_service_with_connect_info::<SocketAddr>()` — no work
/// needed here, but the dependency is documented for clarity.
#[allow(dead_code)]
fn _connected_marker(addr: SocketAddr) -> SocketAddr {
    <SocketAddr as Connected<SocketAddr>>::connect_info(addr)
}

#[cfg(test)]
mod tests {
    //! Behaviour tests live in `crates/hort-server/tests/http_timeouts.rs`
    //! (real listeners, real raw TCP clients). The unit-level tests
    //! here cover the small pure pieces — defaults struct, builder
    //! constructor — without spinning a tokio runtime.

    use super::*;

    #[test]
    fn http_timeouts_defaults_match_design_doc() {
        let d = HttpTimeouts::defaults();
        assert_eq!(d.header_read_timeout, Duration::from_secs(15));
        assert_eq!(d.http2_keep_alive_interval, Duration::from_secs(30));
        assert_eq!(d.http2_keep_alive_timeout, Duration::from_secs(30));
    }

    #[test]
    fn build_hyper_builder_accepts_arbitrary_finite_timeouts() {
        // The builder is opaque (no public getters) — this test guards
        // that the constructor itself does not panic for the values
        // the config layer produces. Hyper's `header_read_timeout`
        // panics if `timer()` is not set first; we assert the builder
        // construction stays panic-free for the boundary values.
        let _ = build_hyper_builder(HttpTimeouts {
            header_read_timeout: Duration::from_secs(1),
            http2_keep_alive_interval: Duration::from_secs(1),
            http2_keep_alive_timeout: Duration::from_secs(1),
        });
        let _ = build_hyper_builder(HttpTimeouts {
            header_read_timeout: Duration::from_secs(3600),
            http2_keep_alive_interval: Duration::from_secs(3600),
            http2_keep_alive_timeout: Duration::from_secs(3600),
        });
    }
}
