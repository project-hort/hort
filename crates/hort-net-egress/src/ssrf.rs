//! Routability predicate — the canonical SSRF block-list.
//!
//! Consumed at the URL-input-validation layer:
//! `hort-adapters-upstream-http::check_ssrf_safe` calls
//! [`is_routable`] on every absolute URL parsed out of upstream
//! metadata (Cargo `dl`, npm tarball URL, sdist URL) before the
//! fetch is allowed to proceed. The earlier connect-time
//! `GuardedDnsResolver` and `build_egress_redirect_policy` consumers
//! were dropped when the EGRESS-1 posture was re-evaluated — see this
//! crate's `lib.rs` history comment for the rationale. The matching
//! `is_routable_with_allowlist` / `is_ip_routable_with_allowlist`
//! test-harness helpers were dropped in a subsequent review pass
//! (zero external callers after those removals).
//!
//! IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`)
//! IPv6 addresses BOTH inherit the IPv4 filter — `to_ipv4()` matches
//! both forms (`to_ipv4_mapped()` would only match `::ffff:`, leaving
//! the IPv4-compatible form as a bypass surface).

use std::net::IpAddr;

/// True iff `ip` is a publicly-routable address.
///
/// IPv4 rejects: loopback, link-local (169.254/16 — AWS IMDS lives
/// here), RFC 1918 private (10/8, 172.16/12, 192.168/16), unspecified
/// (0.0.0.0), broadcast (255.255.255.255), multicast, RFC 6598 CGNAT
/// (100.64.0.0/10), RFC 5737 documentation (192.0.2.0/24,
/// 198.51.100.0/24, 203.0.113.0/24), and the entire 0.0.0.0/8 "this
/// network" range (ADR 0010).
///
/// IPv6 rejects: loopback, unspecified, multicast, unicast link-local
/// (fe80::/10), unique-local (fc00::/7), RFC 3849 documentation
/// (2001:db8::/32 — ADR 0010), and anything whose
/// IPv4 projection (mapped or compatible) would itself fail this
/// filter.
pub fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // ADR 0010 — additional non-routable prefixes the
                // stdlib predicates do not cover.
                || is_ipv4_cgnat(v4)
                || is_ipv4_documentation(v4)
                || is_ipv4_this_network(v4))
        }
        IpAddr::V6(v6) => {
            // `to_ipv4()` matches BOTH `::ffff:a.b.c.d` (IPv4-mapped,
            // RFC 4291 §2.5.5.2) and `::a.b.c.d` (IPv4-compatible,
            // RFC 4291 §2.5.5.1); both forms must inherit the IPv4
            // routability filter. `to_ipv4_mapped()`
            // would only match `::ffff:` and re-open the IPv4-compatible
            // bypass — kept on `to_ipv4` deliberately.
            #[allow(deprecated)]
            let mapped_v4 = v6.to_ipv4();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                // RFC 4193 unique-local (`fc00::/7`).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // ADR 0010 — RFC 3849 documentation
                // (`2001:db8::/32`); first 32 bits = `2001:0db8`.
                || is_ipv6_documentation(v6)
                || mapped_v4.is_some_and(|v4| !is_routable(IpAddr::V4(v4))))
        }
    }
}

/// RFC 6598 Carrier-Grade NAT — `100.64.0.0/10`.
///
/// First 10 bits fixed: octet 0 is `100`, the top two bits of octet 1
/// are `01` (i.e. octet 1 in `[64, 127]`).
fn is_ipv4_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
}

/// RFC 5737 documentation prefixes — TEST-NET-{1,2,3}.
///
/// - `192.0.2.0/24`     — TEST-NET-1
/// - `198.51.100.0/24`  — TEST-NET-2
/// - `203.0.113.0/24`   — TEST-NET-3
fn is_ipv4_documentation(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    matches!(
        (o[0], o[1], o[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    )
}

/// RFC 1122 §3.2.1.3 "this network" — `0.0.0.0/8`.
///
/// `Ipv4Addr::is_unspecified` only matches the literal `0.0.0.0`;
/// the entire `0.0.0.0/8` range must be rejected so a non-network
/// example like `0.1.2.3` is also blocked.
fn is_ipv4_this_network(v4: std::net::Ipv4Addr) -> bool {
    v4.octets()[0] == 0
}

/// RFC 3849 IPv6 documentation prefix — `2001:db8::/32`.
fn is_ipv6_documentation(v6: std::net::Ipv6Addr) -> bool {
    let s = v6.segments();
    s[0] == 0x2001 && s[1] == 0x0db8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    // -----------------------------------------------------------------
    // IPv4 — full classification
    // -----------------------------------------------------------------

    #[test]
    fn is_routable_classifies_ipv4_correctly() {
        // Public.
        assert!(is_routable(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        // Loopback / private / link-local / unspecified / broadcast / multicast.
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    }

    // -----------------------------------------------------------------
    // IPv6 — full classification
    // -----------------------------------------------------------------

    #[test]
    fn is_routable_classifies_ipv6_correctly() {
        // Public.
        assert!(is_routable(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
        // Loopback / unspecified / link-local / unique-local / multicast.
        assert!(!is_routable(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_routable(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_routable(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(!is_routable(IpAddr::V6("fd00::1".parse().unwrap())));
        assert!(!is_routable(IpAddr::V6("ff02::1".parse().unwrap())));
    }

    // -----------------------------------------------------------------
    // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) and IPv4-compatible IPv6
    // (`::a.b.c.d`, RFC 4291 §2.5.5) must inherit the IPv4 routability
    // filter.
    // -----------------------------------------------------------------

    #[test]
    fn ipv4_mapped_loopback_is_not_routable() {
        // ::ffff:127.0.0.1 — IPv4-mapped form of 127.0.0.1.
        assert!(!is_routable(ipv6("::ffff:127.0.0.1")));
    }

    #[test]
    fn ipv4_mapped_imds_is_not_routable() {
        // ::ffff:169.254.169.254 — IPv4-mapped form of AWS IMDS.
        assert!(!is_routable(ipv6("::ffff:169.254.169.254")));
    }

    #[test]
    fn ipv4_mapped_rfc1918_is_not_routable() {
        // ::ffff:10.0.0.1 — IPv4-mapped form of an RFC 1918 address.
        assert!(!is_routable(ipv6("::ffff:10.0.0.1")));
    }

    #[test]
    fn ipv4_mapped_public_remains_routable() {
        // Positive case — over-blocking IPv4-mapped public addrs would
        // itself be a regression. ::ffff:8.8.8.8 must pass.
        assert!(is_routable(ipv6("::ffff:8.8.8.8")));
    }

    #[test]
    fn ipv4_compatible_loopback_is_not_routable() {
        // ::127.0.0.1 — IPv4-compatible form (RFC 4291 §2.5.5).
        // `to_ipv4()` matches both forms; `to_ipv4_mapped()` only
        // matches `::ffff:`. Use `to_ipv4()` so this case is caught.
        assert!(!is_routable(ipv6("::127.0.0.1")));
    }

    #[test]
    fn ipv4_compatible_imds_is_not_routable() {
        assert!(!is_routable(ipv6("::169.254.169.254")));
    }

    #[test]
    fn ipv4_compatible_rfc1918_is_not_routable() {
        assert!(!is_routable(ipv6("::10.0.0.1")));
    }

    #[test]
    fn ipv4_compatible_public_remains_routable() {
        // ::8.8.8.8 — IPv4-compatible public; must remain routable so
        // we are not over-blocking. Note: ::1 is loopback (covered by
        // the existing v6 loopback check), and ::0.0.0.0 → ::
        // (unspecified). The smallest public-mapped IPv4-compatible
        // we can use without colliding with those is 8.8.8.8.
        assert!(is_routable(ipv6("::8.8.8.8")));
    }

    // -----------------------------------------------------------------
    // ADR 0010 — additional non-routable prefixes.
    // The stdlib `Ipv4Addr::is_private` only covers RFC 1918, and
    // `is_unspecified` only matches the literal `0.0.0.0`. Four IPv4
    // prefixes (RFC 6598 CGNAT, RFC 5737 TEST-NET-{1,2,3}, the entire
    // 0.0.0.0/8 range) and one IPv6 prefix (RFC 3849 documentation)
    // must be rejected as well.
    //
    // Each test pins one prefix with a non-boundary sample so an
    // implementation that special-cases only the network address
    // (e.g. checks `192.0.2.0` literal instead of `192.0.2.0/24`)
    // would still fail.
    // -----------------------------------------------------------------

    #[test]
    fn cgnat_100_64_0_0_slash_10_is_not_routable() {
        // RFC 6598 — Carrier-Grade NAT. Operationally significant in
        // cloud VPC and EKS overlay networks.
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1))));
    }

    #[test]
    fn test_net_1_192_0_2_0_slash_24_is_not_routable() {
        // RFC 5737 TEST-NET-1.
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))));
    }

    #[test]
    fn test_net_2_198_51_100_0_slash_24_is_not_routable() {
        // RFC 5737 TEST-NET-2.
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
    }

    #[test]
    fn test_net_3_203_0_113_0_slash_24_is_not_routable() {
        // RFC 5737 TEST-NET-3.
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
    }

    #[test]
    fn zero_slash_8_entire_range_is_not_routable() {
        // 0.0.0.0/8 — the entire range, not just the literal
        // `0.0.0.0` covered by `is_unspecified`. RFC 1122 §3.2.1.3:
        // "this network" / source-only addresses must never appear
        // as a destination on the wire.
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3))));
    }

    #[test]
    fn ipv6_documentation_2001_db8_slash_32_is_not_routable() {
        // RFC 3849 — IPv6 documentation prefix.
        assert!(!is_routable(ipv6("2001:db8::1")));
    }

    #[test]
    fn public_addresses_remain_routable_after_l_a1() {
        // Positive coverage — the ADR 0010 additions must not over-block.
        // Repeats the public-address assertions from the IPv4/IPv6
        // classification tests but lives next to those negatives
        // so a regression that flipped a prefix bit too far would
        // light up here at the same time.
        assert!(is_routable(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_routable(ipv6("2606:4700:4700::1111")));
    }

    // The `_with_allowlist` test helpers + their tests were removed in
    // a review pass after the connect-time DNS guard was dropped. They
    // covered functions that had no external callers after that removal;
    // the allowlist abstraction was exclusively a test-harness shim for
    // the now-deleted guard. Production `check_ssrf_safe` calls the
    // bare `is_routable` predicate directly.
}
