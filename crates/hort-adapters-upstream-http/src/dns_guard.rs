//! Connect-time guarded DNS resolver — upstream-artifact-fetch SSRF /
//! DNS-rebind TOCTOU fix (security audit finding INJ-1).
//!
//! # Why this exists
//!
//! [`crate::check_ssrf_safe`] resolves a metadata-supplied absolute
//! artifact URL's host (Cargo `dl`, npm tarball URL, sdist URL) and
//! `is_routable`-classifies it **once**, at URL-validation time. The
//! subsequent `reqwest` dial then **re-resolves the host independently**
//! — a classic time-of-check/time-of-use gap. An attacker who influences
//! upstream metadata can resolve a host to a public IP at check time and
//! flip DNS to `169.254.169.254` (cloud IMDS), `127.0.0.1`, or an
//! RFC1918 host before the dial → blind SSRF. The per-hop redirect guard
//! ([`crate::build_redirect_policy`]) closed the *redirect* leg of this
//! threat, but the **initial dial** of the absolute URL was not
//! connect-time guarded.
//!
//! [`GuardedDnsResolver`] closes that race by re-running
//! [`hort_net_egress::is_routable`] on **every address the resolver
//! returns**, at connect time, for the lifetime of the upstream client.
//! reqwest calls the bound [`reqwest::dns::Resolve`] impl immediately
//! before each connect, so a rebind between `check_ssrf_safe` and the
//! dial (or between dials) is caught. This mirrors the connect-time
//! `GuardedDnsResolver` in the `hort-notifier-webhook` crate that already
//! solved the same threat class for user-submitted webhook URLs.
//!
//! # IP-literal hosts bypass the resolver (and that is correct)
//!
//! hyper-util's connector parses IP-literal hosts (`127.0.0.1`,
//! `[::1]`) directly via `SocketAddrs::try_parse` and **never** invokes a
//! custom [`reqwest::dns::Resolve`]; only *host names* go through the
//! resolver. The SSRF/DNS-rebind threat is exactly a host name that
//! resolves to different addresses over time, so guarding the resolver
//! path is the right surface. (An IP-literal upstream URL is still
//! validated by [`crate::check_ssrf_safe`] before the dial; there is no
//! re-resolution race for a literal.)
//!
//! # Test seam (`redirect_test_allowlist`)
//!
//! The guard reuses the crate's existing `Arc<Vec<SocketAddr>>`
//! test-allowlist seam — the very same one
//! [`crate::build_redirect_policy`] uses. In production the allowlist is
//! **always empty** (`HttpUpstreamProxy::new`), so every
//! loopback / RFC1918 / link-local / IMDS resolution is refused at
//! connect time. The `#[cfg(test)]` constructor populates it with the
//! wiremock loopback `SocketAddr`s so a test can drive a *host name* that
//! resolves to loopback through the guard. It is scoped private to this
//! crate, never re-exported, and never placed in `hort-net-egress`.
//!
//! # Fail-closed classification
//!
//! A resolution that yields a non-routable, non-allowlisted address — or
//! a resolution failure — returns an `Err` carrying
//! [`CONNECT_SSRF_SENTINEL`]. reqwest surfaces that as a connect-class
//! error whose source chain still contains the sentinel, so
//! [`crate::map_reqwest_send_error`] classifies it identically to a
//! [`crate::check_ssrf_safe`] refusal (`UpstreamErrorKind::ParseError`) —
//! the existing `hort_upstream_fetch_total{result="parse_error"}` row is
//! reused; no new error / metric variant is introduced. The dial is never
//! made.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Stable marker embedded in the resolver's refusal error so
/// [`crate::map_reqwest_send_error`] (via `error_chain_contains`) can
/// recognise a connect-time SSRF rejection and classify it identically to
/// a [`crate::check_ssrf_safe`] refusal (`UpstreamErrorKind::ParseError`)
/// — a content-validation outcome, not a network failure. Distinct string
/// from [`crate::REDIRECT_SSRF_SENTINEL`] so logs / tests can tell the
/// initial-dial guard from the per-hop redirect guard, but both map to the
/// same `ParseError` classification.
pub(crate) const CONNECT_SSRF_SENTINEL: &str = "hort-upstream-connect-ssrf-blocked";

/// Connect-time guarded resolver bound to the upstream-http artifact /
/// metadata / manifest `reqwest::Client`(s) at the two `Client::builder()`
/// sites in this crate (see module docs for the scoping rationale).
///
/// On every resolve reqwest performs before a connect, this:
/// 1. resolves `name` via `tokio::net::lookup_host` (same primitive
///    [`crate::check_ssrf_safe`] uses — no new dependency, no second
///    resolver implementation to drift);
/// 2. permits each returned [`SocketAddr`] iff
///    [`hort_net_egress::is_routable`] passes **or** the address is in the
///    test allowlist (empty in production);
/// 3. if **any** resolved address is non-routable and not allowlisted, the
///    whole resolution is refused with an error carrying
///    [`CONNECT_SSRF_SENTINEL`] — the attacker needs only one rebind entry
///    to pivot, so a single non-routable answer fails the dial closed. A
///    resolution failure is likewise refused (fail-closed: an
///    unresolvable host cannot be proven safe).
#[derive(Debug, Clone)]
pub(crate) struct GuardedDnsResolver {
    /// Addresses to treat as routable in addition to the real
    /// `is_routable` check. **Always empty in production**; only the
    /// `#[cfg(test)]` proxy constructor seeds it with wiremock loopback
    /// addresses. Shared (same `Arc`) with [`crate::build_redirect_policy`].
    allowlist: Arc<Vec<SocketAddr>>,
}

impl GuardedDnsResolver {
    /// Build from the crate's shared test-allowlist seam. Pass an empty
    /// `Arc<Vec<_>>` (the production value) for a strict guard.
    pub(crate) fn new(allowlist: Arc<Vec<SocketAddr>>) -> Self {
        Self { allowlist }
    }

    /// Pure decision: is this resolved `addr` permitted to be dialed?
    ///
    /// Permitted iff routable OR explicitly allowlisted (test seam). This
    /// is the single connect-time security predicate; extracted so it is
    /// unit-testable without a live resolver. Mirrors the predicate
    /// [`crate::build_redirect_policy`] applies per redirect hop.
    fn permit(&self, addr: SocketAddr) -> bool {
        hort_net_egress::is_routable(addr.ip()) || self.allowlist.contains(&addr)
    }
}

impl Resolve for GuardedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = self.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // reqwest's `Name` carries no port; the port is irrelevant to
            // the routability decision (it filters by IP). A dummy `:0`
            // makes `lookup_host` happy and we discard it below.
            let lookup_target = format!("{host}:0");
            let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&lookup_target).await {
                Ok(addrs) => addrs.collect(),
                Err(e) => {
                    // Fail-closed: an unresolvable host cannot be proven
                    // safe. Carry the sentinel so the caller classifies
                    // this as a ParseError (SSRF-refusal contract), not a
                    // generic network error.
                    tracing::warn!(
                        blocked_host = %host,
                        error = %e,
                        "upstream connect-time DNS guard: host did not resolve (fail-closed)"
                    );
                    return Err(format!(
                        "{CONNECT_SSRF_SENTINEL}: upstream host {host} did not resolve: {e}"
                    )
                    .into());
                }
            };

            // Reject if ANY resolved address is non-routable and not
            // allowlisted — one rebind answer is enough to pivot.
            for addr in &resolved {
                if !guard.permit(*addr) {
                    tracing::warn!(
                        blocked_host = %host,
                        "upstream connect-time DNS guard: host resolves to a \
                         non-routable address (fail-closed)"
                    );
                    return Err(format!(
                        "{CONNECT_SSRF_SENTINEL}: upstream host {host} resolves to a \
                         non-routable address: {ip}",
                        ip = addr.ip()
                    )
                    .into());
                }
            }

            let addrs: Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }

    fn empty() -> Arc<Vec<SocketAddr>> {
        Arc::new(Vec::new())
    }

    // -- permit (the connect-time predicate) -------------------------------

    #[test]
    fn permit_allows_routable_public_without_allowlist() {
        // Public upstreams (registry.npmjs.org, pypi.org, crates.io,
        // ghcr.io, public CDNs) all resolve to routable addresses; the
        // guard must NOT block them. Pin a representative public IP.
        let g = GuardedDnsResolver::new(empty());
        assert!(g.permit(sock("1.1.1.1")));
        assert!(g.permit(sock("8.8.8.8")));
        assert!(g.permit(sock("93.184.216.34")));
        // A public IPv6 (Cloudflare) is also permitted.
        assert!(g.permit(SocketAddr::new(
            "2606:4700:4700::1111".parse().unwrap(),
            443
        )));
    }

    #[test]
    fn permit_blocks_nonroutable_without_allowlist() {
        let g = GuardedDnsResolver::new(empty());
        // The DNS-rebinding-to-IMDS case (AWS link-local metadata).
        assert!(!g.permit(sock("169.254.169.254")));
        // Loopback + RFC1918 also blocked.
        assert!(!g.permit(sock("127.0.0.1")));
        assert!(!g.permit(sock("10.1.2.3")));
        assert!(!g.permit(sock("192.168.0.1")));
        assert!(!g.permit(sock("172.16.5.5")));
    }

    #[test]
    fn permit_blocks_ipv4_mapped_ipv6_imds() {
        // `is_routable`'s IPv6 branch covers `::ffff:` mapped IMDS; pin
        // the guard wiring (IPv4-mapped IPv6 regression at connect layer).
        let g = GuardedDnsResolver::new(empty());
        assert!(!g.permit(SocketAddr::new(
            "::ffff:169.254.169.254".parse().unwrap(),
            443
        )));
    }

    #[test]
    fn permit_allows_nonroutable_when_addr_allowlisted() {
        // The test seam: a loopback address explicitly allowlisted (the
        // wiremock case) is permitted so host-name-resolving-to-loopback
        // tests can drive the guard.
        let allowed = sock("127.0.0.1");
        let g = GuardedDnsResolver::new(Arc::new(vec![allowed]));
        assert!(g.permit(allowed));
        // …but a DIFFERENT non-routable address (different port, or a
        // different IP) is still blocked — the allowlist permits ONLY the
        // exact listed `SocketAddr`s.
        assert!(!g.permit(sock("127.0.0.2")));
        assert!(!g.permit(SocketAddr::new("127.0.0.1".parse().unwrap(), 8080)));
        assert!(!g.permit(sock("169.254.169.254")));
    }

    // -- resolve (the live resolver path) ----------------------------------

    /// Positive: a public host name resolves and the routable address is
    /// RETAINED. Proves the guard does not over-block legitimate public
    /// upstreams. Uses a literal-IP "host" so the test is offline and
    /// deterministic — `lookup_host("1.1.1.1:0")` returns the literal
    /// without touching DNS, and the literal is routable.
    #[tokio::test]
    async fn resolve_keeps_routable_address() {
        let g = GuardedDnsResolver::new(empty());
        let name = Name::from_str("1.1.1.1").expect("valid name");
        let addrs: Vec<SocketAddr> = g.resolve(name).await.expect("resolve ok").collect();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].ip().is_ipv4());
        assert!(hort_net_egress::is_routable(addrs[0].ip()));
    }

    /// Negative (the SSRF block): a host name that resolves to a
    /// non-routable address is REFUSED with the sentinel error — the
    /// rebind target is never returned to reqwest, so it is never dialed.
    /// `localhost` resolves to 127.0.0.1 / ::1 (both non-routable, not
    /// allowlisted) without touching the network.
    #[tokio::test]
    async fn resolve_refuses_nonroutable_localhost_with_sentinel() {
        let g = GuardedDnsResolver::new(empty());
        let name = Name::from_str("localhost").expect("valid name");
        // `Addrs` (the Ok arm) is not `Debug`, so match rather than
        // `expect_err`.
        let err = match g.resolve(name).await {
            Ok(addrs) => panic!(
                "non-routable localhost must be refused (fail-closed), got {} address(es)",
                addrs.count()
            ),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains(CONNECT_SSRF_SENTINEL),
            "refusal must carry the SSRF sentinel so it classifies as a \
             ParseError, got: {err}"
        );
    }

    /// The test seam keeps the resolution when the loopback address is
    /// allowlisted — proves the wiremock-driven host-name path works and
    /// that the bypass is scoped to the listed address only.
    #[tokio::test]
    async fn resolve_keeps_localhost_when_allowlisted() {
        // Resolve localhost once to learn its concrete loopback addrs,
        // then allowlist exactly those (normalised to the `:0` port the
        // guard resolves with) so the exact-`SocketAddr` match succeeds.
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host("localhost:443")
            .await
            .expect("localhost resolves")
            .collect();
        let with_zero: Vec<SocketAddr> = resolved
            .iter()
            .map(|a| SocketAddr::new(a.ip(), 0))
            .collect();
        let g = GuardedDnsResolver::new(Arc::new(with_zero));
        let name = Name::from_str("localhost").expect("valid name");
        let addrs: Vec<SocketAddr> = g
            .resolve(name)
            .await
            .expect("allowlisted localhost must resolve ok")
            .collect();
        assert!(
            !addrs.is_empty(),
            "allowlisted localhost must retain its resolved loopback address"
        );
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }

    /// Fail-closed on a resolution failure: an unresolvable host is
    /// refused with the sentinel, not silently bypassed.
    #[tokio::test]
    async fn resolve_refuses_unresolvable_host_with_sentinel() {
        let g = GuardedDnsResolver::new(empty());
        // `.invalid` is the RFC 6761 guaranteed-non-resolving TLD.
        let name = Name::from_str("nonexistent-host.invalid").expect("valid name");
        let err = match g.resolve(name).await {
            Ok(addrs) => panic!(
                "unresolvable host must be refused (fail-closed), got {} address(es)",
                addrs.count()
            ),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains(CONNECT_SSRF_SENTINEL),
            "resolution-failure refusal must carry the SSRF sentinel, got: {err}"
        );
    }
}
