//! Public URL resolution for absolute-URL emission in packument /
//! `config.json` / index responses.
//!
//! All trust evaluation lives in the [`crate::middleware::trust`]
//! layer (see `docs/architecture/explanation/security.md`, request
//! trust). That layer populates [`RequestTrust::public_url`] exactly
//! once per request and guarantees it is always set — including the
//! "untrusted peer, no `Host` header" degenerate branch that falls
//! back to the bind address. Because the trust layer owns every branch
//! of the trust policy, `UrlResolver::resolve` is an infallible
//! pass-through.
//!
//! The type is kept as a zero-sized struct (not a free function) so
//! handlers continue to address it as `ctx.url_resolver.resolve(&trust)`
//! — minimising churn at every call site and leaving an obvious hook
//! for future URL-shaping logic (e.g. path-prefix rewriting behind a
//! sub-path proxy) that should live at the API layer rather than
//! inside the trust middleware.

use crate::middleware::trust::RequestTrust;

/// Immutable, zero-sized resolver. Stored inside `AppContext` so every
/// handler has access via `State`.
///
/// Holds no state: the trust middleware's `RequestTrust` carries everything needed to
/// build the public URL. Construct via the unit literal `UrlResolver`
/// — no `new()` / `Default` because there is nothing to vary.
/// `Clone` + `Copy` are kept so callers that composite-init
/// `AppContext` from an existing one can move or copy the resolver
/// field without fuss.
#[derive(Debug, Clone, Copy)]
pub struct UrlResolver;

impl UrlResolver {
    /// Return the public-facing base URL for this request.
    ///
    /// Infallible: the trust layer guarantees `trust.public_url` is populated on
    /// every request (see `crate::middleware::trust` policy table).
    /// Callers that need the `(scheme, authority)` pair the old API
    /// returned can derive it via [`url::Url::scheme`] +
    /// [`url::Url::authority`] (or just format the URL directly).
    pub fn resolve(&self, trust: &RequestTrust) -> url::Url {
        trust.public_url.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    fn trust(public_url: &str) -> RequestTrust {
        RequestTrust {
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            public_url: url(public_url),
        }
    }

    /// The resolver is a pure pass-through: whatever the trust layer placed in
    /// `trust.public_url` is what callers see. Trust-policy coverage
    /// (HORT_PUBLIC_BASE_URL precedence, proxy forwarding, bind-address
    /// fallback) lives in `middleware::trust::tests`.
    #[test]
    fn resolve_returns_trust_public_url_unchanged() {
        let r = UrlResolver;
        let t = trust("https://hort.example.com/");
        assert_eq!(r.resolve(&t), url("https://hort.example.com/"));
    }

    #[test]
    fn resolve_preserves_port() {
        let r = UrlResolver;
        let t = trust("http://hort-server:8080/");
        let out = r.resolve(&t);
        assert_eq!(out.scheme(), "http");
        assert_eq!(out.host_str(), Some("hort-server"));
        assert_eq!(out.port(), Some(8080));
    }

    #[test]
    fn resolve_preserves_https_default_port() {
        let r = UrlResolver;
        let t = trust("https://registry.example.com/");
        let out = r.resolve(&t);
        assert_eq!(out.scheme(), "https");
        assert_eq!(out.host_str(), Some("registry.example.com"));
        // Default https port is elided; `port()` returns None when
        // absent from the URL.
        assert_eq!(out.port(), None);
    }

    /// The returned URL is a clone — repeat calls with the same trust
    /// yield identical URLs and do not mutate the trust context.
    #[test]
    fn resolve_is_idempotent_and_non_mutating() {
        let r = UrlResolver;
        let t = trust("https://hort.example.com/");
        let first = r.resolve(&t);
        let second = r.resolve(&t);
        assert_eq!(first, second);
        assert_eq!(t.public_url, url("https://hort.example.com/"));
    }
}
