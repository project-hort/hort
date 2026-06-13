//! Per-request deadline middleware.
//!
//! Thin wrapper around [`tower_http::timeout::TimeoutLayer`]. The layer
//! cancels the inner future when the configured deadline elapses and
//! returns `408 Request Timeout` to the client.
//!
//! # Why a wrapper?
//!
//! Centralising the constructor in this module gives the composition
//! root (`hort-server`) a single attach point and keeps the per-format
//! HTTP crates (`hort-http-cargo`, `hort-http-npm`, `hort-http-pypi`,
//! `hort-http-oci`) free of `tower-http` import churn — they pull the
//! layer through `hort-http-core` the same way they pull
//! `request_trust_layer`. Per-route OCI overrides call this same
//! constructor with the longer ceiling so the override is the same
//! type of layer, not a divergent code path.
//!
//! # Slowloris vs request-deadline
//!
//! This layer is the **request-deadline** half of the protection. The
//! **slowloris** half — `http1_header_read_timeout` and the HTTP/2
//! keep-alive interval — lives at the transport layer in
//! `hort-server::serve_loop`. The two pieces are independent and both
//! must hold:
//!
//! - `header_read_timeout` (transport): caps how long a slow-header
//!   client can pin a hyper accept worker before the connection is
//!   dropped. No service is invoked.
//! - `request_timeout_layer` (this module): caps how long a handler
//!   may run after a complete request has been parsed. The Service
//!   future is dropped on timeout, freeing the worker.
//!
//! See the operator how-to in
//! `docs/architecture/how-to/http-transport-timeouts.md`.

use std::time::Duration;

use axum::http::StatusCode;
use tower_http::timeout::TimeoutLayer;

/// Composition-root carrier for the per-request deadline durations.
/// Held on `AppContext` so router builders
/// in every per-format crate can pull the values without taking
/// `hort-server::config` as a dep.
///
/// `request_timeout` is the global default applied at
/// [`crate::router::wrap_with_middleware`]. `oci_upload_timeout` is the
/// per-route override consumed by `hort-http-oci` for the upload subtree.
/// Both values are non-zero by construction (see
/// `hort-server::config::parse_http_*_timeout_secs`).
#[derive(Debug, Clone, Copy)]
pub struct HttpTimeoutConfig {
    /// Default request deadline applied via [`request_timeout_layer`]
    /// at the outer router wrap. Sourced from
    /// `HORT_HTTP_REQUEST_TIMEOUT_SECS` (default 5 minutes).
    pub request_timeout: Duration,
    /// Per-route ceiling for the OCI blob upload subtree
    /// (`/v2/:repo/.../blobs/uploads/...`). Sourced from
    /// `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS` (default 60 minutes).
    pub oci_upload_timeout: Duration,
}

impl HttpTimeoutConfig {
    /// Test/dev defaults. Production callers wire the real config from
    /// `hort-server::config`; the test harnesses in
    /// `hort_http_core::test_support` use this constructor so they do not
    /// duplicate the constants.
    pub fn defaults() -> Self {
        Self {
            request_timeout: Duration::from_secs(300),
            oci_upload_timeout: Duration::from_secs(3600),
        }
    }
}

/// Build a request-deadline `TimeoutLayer` with the configured timeout.
///
/// Default deployments wire the global default (5 minutes via
/// `HORT_HTTP_REQUEST_TIMEOUT_SECS`); the OCI router applies its own
/// longer-ceiling layer (60 minutes via `HORT_HTTP_OCI_UPLOAD_TIMEOUT_SECS`)
/// to the upload subtree. Callers MUST pass a non-zero duration — a zero
/// timeout would short-circuit every request to 408 immediately. The
/// per-env-var parsers in `hort-server::config` enforce non-zero before
/// the value reaches this layer.
pub fn request_timeout_layer(timeout: Duration) -> TimeoutLayer {
    // `with_status_code` is the non-deprecated constructor on tower-http
    // 0.6+; `TimeoutLayer::new` is gated behind a deprecation warning. We
    // pin the response code to `408 Request Timeout` (the same default
    // the deprecated constructor used) so client-visible behaviour does
    // not regress under the rename.
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout)
}

#[cfg(test)]
mod tests {
    //! The layer's actual timeout behaviour is exercised end-to-end in
    //! `hort-server`'s `tests/http_timeouts.rs` (which drives a real
    //! hyper-util listener + raw TCP client). Here we only assert that
    //! the constructor returns a usable layer for the supplied
    //! duration; failure modes (zero, negative) are caught at config
    //! parse time, not at layer-attach time.

    use super::*;

    #[test]
    fn constructor_returns_layer_for_finite_duration() {
        let _ = request_timeout_layer(Duration::from_secs(300));
        // The layer is opaque — there is no public API to read its
        // configured duration back out of `TimeoutLayer`. We rely on
        // `hort-server`'s integration test for behavioural coverage.
    }
}
