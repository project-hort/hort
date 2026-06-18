//! Connect-time guarded DNS resolver — webhook-scoped SSRF TOCTOU fix.
//!
//! # Why this exists
//!
//! [`crate::WebhookNotifier`]'s [`WebhookTargetGuard::check`] runs the
//! `is_routable` SSRF check exactly **once**, at subscription
//! create-time. `deliver()` then issues the POST with no
//! re-validation of the address actually dialed. An attacker who
//! controls a domain can resolve it to a public IP at create-time and
//! flip DNS to `169.254.169.254` / `127.0.0.1` / RFC1918 before the
//! first delivery — a classic DNS-rebinding TOCTOU.
//!
//! [`GuardedDnsResolver`] closes that race by re-running
//! [`hort_net_egress::is_routable`] on **every address the resolver
//! returns**, at connect time, for the lifetime of the webhook client.
//! reqwest calls the bound [`reqwest::dns::Resolve`] impl immediately
//! before each connect, so a rebind between create and delivery (or
//! between deliveries) is caught.
//!
//! # Scoping discipline (HARD constraint — do not relax)
//!
//! The upstream-http / OIDC / S3 targets are *operator-vetted* (config or
//! deployment-pinned) and a connect-time guard there only produced a
//! false-positive class on legitimate internal mirrors. That rationale
//! does **not** transfer to *user-submitted* webhook URLs — user-submitted
//! URLs are the SSRF threat surface, not operator-configured upstreams.
//!
//! This resolver is therefore scoped **to the webhook `reqwest::Client`
//! only**. It is constructed in, and bound by,
//! [`crate::WebhookNotifier::new`] via
//! `ClientBuilder::dns_resolver(...)` and is reachable from nowhere
//! else. It is NOT re-exported, NOT placed in `hort-net-egress`, and is
//! never threaded to the upstream-http / S3 / OIDC client builders —
//! those stay operator-vetted by deployment configuration. Re-globalizing
//! this guard to operator-vetted clients is an anti-pattern; do not do it.
//!
//! # `HORT_WEBHOOK_ALLOWLIST_HOSTS`
//!
//! Legitimate internal webhook receivers (an in-DMZ forwarder, an
//! in-cluster receiver) resolve to non-routable addresses and would be
//! blocked by a strict connect-time guard. `HORT_WEBHOOK_ALLOWLIST_HOSTS`
//! is a comma-separated list of host names and/or CIDR prefixes. A
//! dialed address is permitted when EITHER `is_routable` passes OR the
//! resolved host name matches an allowlisted host entry OR the dialed
//! IP falls inside an allowlisted CIDR. The allowlist bypasses
//! `is_routable` **only for the listed entries** — every other host
//! still default-denies on non-routable.
//!
//! The pre-existing blanket opt-out
//! (`HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS`) is unchanged and remains a
//! **documented last resort**: it disables the create-time host check
//! entirely (use-case layer). The allowlist is the targeted, intended
//! control; the blanket opt-out's blast radius (all subscriptions,
//! IMDS/RFC1918 re-opened) is stated in the deployment hardening guide
//! and the metrics catalog. Operators with one legitimate internal
//! receiver should list it here, not flip the blanket opt-out.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Environment variable carrying the comma-separated host / CIDR
/// allowlist. Absent / empty ⇒ no allowlist (strict guard).
pub(crate) const ALLOWLIST_ENV: &str = "HORT_WEBHOOK_ALLOWLIST_HOSTS";

/// Parsed `HORT_WEBHOOK_ALLOWLIST_HOSTS` — a bounded set of exact host
/// names and CIDR prefixes that bypass [`hort_net_egress::is_routable`]
/// **only for themselves**.
///
/// Entries are classified at parse time:
/// - A token that parses as an [`IpNet`] (`10.0.0.0/8`) or a bare
///   [`IpAddr`] (`10.1.2.3`, normalised to a `/32` or `/128`) is a
///   CIDR entry — a dialed IP inside the prefix bypasses the routable
///   check.
/// - Any other non-empty token is a host entry — matched
///   case-insensitively against the DNS name being resolved.
///
/// Unparseable / empty tokens are skipped (defensive: a typo must not
/// silently widen the allowlist, and must not fail webhook delivery
/// startup — the strict guard still applies to everything not matched).
#[derive(Debug, Clone, Default)]
pub(crate) struct HostAllowlist {
    /// Lower-cased exact host names.
    hosts: Vec<String>,
    /// CIDR prefixes (bare IPs normalised to `/32` or `/128`).
    cidrs: Vec<IpNet>,
}

impl HostAllowlist {
    /// Parse from the raw env value. `None` / empty ⇒ empty allowlist
    /// (strict guard, no bypass).
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        let mut hosts = Vec::new();
        let mut cidrs = Vec::new();
        let Some(raw) = raw else {
            return Self { hosts, cidrs };
        };
        for token in raw.split(',') {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(net) = IpNet::from_str(t) {
                cidrs.push(net);
                continue;
            }
            if let Ok(ip) = IpAddr::from_str(t) {
                // Bare IP ⇒ exact-host CIDR (/32 or /128).
                cidrs.push(IpNet::from(ip));
                continue;
            }
            hosts.push(t.to_ascii_lowercase());
        }
        Self { hosts, cidrs }
    }

    /// Read directly from the process environment. Webhook-scoped: this
    /// is the ONLY reader of [`ALLOWLIST_ENV`] in the workspace.
    pub(crate) fn from_env() -> Self {
        Self::parse(std::env::var(ALLOWLIST_ENV).ok().as_deref())
    }

    /// `true` iff `host` is an explicitly allowlisted host name
    /// (case-insensitive exact match).
    ///
    /// `pub(crate)` so the create/update [`crate::WebhookTargetGuard`]
    /// path (`check_url_routable` in `lib.rs`) consults the SAME matching
    /// logic the delivery-path [`GuardedDnsResolver::permit`] uses — this
    /// reuses that logic, it does not re-implement the match.
    pub(crate) fn host_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.hosts.contains(&host)
    }

    /// `true` iff `ip` falls inside an allowlisted CIDR (or equals an
    /// allowlisted bare IP).
    ///
    /// `pub(crate)` for the same reuse reason as
    /// [`HostAllowlist::host_allowed`].
    pub(crate) fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }
}

/// Connect-time guarded resolver bound to the webhook `reqwest::Client`
/// only (see module docs for the scoping rationale).
///
/// On every resolve reqwest performs before a connect, this:
/// 1. resolves `name` via `tokio::net::lookup_host` (same primitive the
///    create-time guard uses — no new dependency, no second resolver
///    implementation to drift);
/// 2. for each returned [`SocketAddr`], permits it iff
///    [`hort_net_egress::is_routable`] passes OR the host name is
///    allowlisted OR the address is inside an allowlisted CIDR;
/// 3. returns only the permitted addresses. If every address is
///    filtered out, it yields an **empty** address set, which reqwest
///    surfaces as a connect error — the delivery fails closed (the
///    rebind target is never dialed).
#[derive(Debug, Clone)]
pub(crate) struct GuardedDnsResolver {
    allowlist: HostAllowlist,
}

impl GuardedDnsResolver {
    /// Build from a parsed allowlist.
    pub(crate) fn new(allowlist: HostAllowlist) -> Self {
        Self { allowlist }
    }

    /// Pure decision: is this dialed `addr` (resolved for DNS name
    /// `host`) permitted to be connected to?
    ///
    /// Permitted iff routable, OR the host name is allowlisted, OR the
    /// address is inside an allowlisted CIDR. This is the single
    /// connect-time security predicate; extracted so it is unit-testable
    /// without a live resolver.
    fn permit(&self, host: &str, addr: SocketAddr) -> bool {
        hort_net_egress::is_routable(addr.ip())
            || self.allowlist.host_allowed(host)
            || self.allowlist.ip_allowed(addr.ip())
    }
}

impl Resolve for GuardedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allowlist = self.allowlist.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // reqwest's `Name` carries no port; the port is irrelevant to
            // the routability decision (it filters by IP). A dummy
            // `:0` makes `lookup_host` happy and we discard it below.
            let lookup_target = format!("{host}:0");
            let resolved = tokio::net::lookup_host(lookup_target).await?;

            let guard = GuardedDnsResolver { allowlist };
            // Retain only addresses that pass the connect-time guard.
            // An empty result is intentional and fail-closed: reqwest
            // turns "no addresses" into a connect error, so a rebind to
            // a non-routable, non-allowlisted target is never dialed.
            let permitted: Vec<SocketAddr> =
                resolved.filter(|addr| guard.permit(&host, *addr)).collect();
            let addrs: Addrs = Box::new(permitted.into_iter());
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

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }

    // -- HostAllowlist::parse ----------------------------------------------

    /// An empty allowlist permits nothing non-routable (strict guard).
    fn assert_strict(a: &HostAllowlist) {
        assert!(!a.host_allowed("internal.webhook.svc"));
        assert!(!a.ip_allowed("10.0.0.1".parse().unwrap()));
        assert!(!a.ip_allowed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_none_is_empty() {
        assert_strict(&HostAllowlist::parse(None));
    }

    #[test]
    fn parse_empty_string_is_empty() {
        assert_strict(&HostAllowlist::parse(Some("   ")));
        assert_strict(&HostAllowlist::parse(Some(",, ,")));
    }

    #[test]
    fn parse_classifies_host_cidr_and_bare_ip() {
        let a = HostAllowlist::parse(Some(
            "internal.webhook.svc, 10.0.0.0/8 , 192.168.1.50 ,, fd00::/8",
        ));
        assert!(a.host_allowed("internal.webhook.svc"));
        assert!(a.host_allowed("INTERNAL.WEBHOOK.SVC")); // case-insensitive
        assert!(!a.host_allowed("other.svc"));
        assert!(a.ip_allowed("10.1.2.3".parse().unwrap())); // inside /8
        assert!(a.ip_allowed("192.168.1.50".parse().unwrap())); // bare IP → /32
        assert!(!a.ip_allowed("192.168.1.51".parse().unwrap())); // not the bare IP
        assert!(a.ip_allowed("fd00::1".parse().unwrap())); // v6 cidr
    }

    #[test]
    fn parse_skips_unparseable_tokens_without_widening() {
        // A typo'd CIDR must NOT silently become a host entry that
        // matches nothing dangerous, but must also not panic / fail.
        let a = HostAllowlist::parse(Some("10.0.0.0/999, not a host!!"));
        // "10.0.0.0/999" is not a valid IpNet/IpAddr → falls to host
        // bucket (harmless, never matches a real resolved name).
        // "not a host!!" likewise lands in the host bucket verbatim.
        assert!(!a.ip_allowed("10.0.0.1".parse().unwrap()));
    }

    // -- GuardedDnsResolver::permit (the connect-time predicate) -----------

    #[test]
    fn permit_allows_routable_without_allowlist() {
        let g = GuardedDnsResolver::new(HostAllowlist::default());
        // 93.184.216.34 is publicly routable.
        assert!(g.permit("example.com", sock("93.184.216.34")));
    }

    #[test]
    fn permit_blocks_nonroutable_without_allowlist() {
        let g = GuardedDnsResolver::new(HostAllowlist::default());
        // The DNS-rebinding-to-IMDS case.
        assert!(!g.permit("rebind.attacker.example", sock("169.254.169.254")));
        // RFC1918 + loopback also blocked.
        assert!(!g.permit("rebind.attacker.example", sock("127.0.0.1")));
        assert!(!g.permit("rebind.attacker.example", sock("10.1.2.3")));
    }

    #[test]
    fn permit_blocks_ipv4_mapped_ipv6_imds() {
        // is_routable's IPv6 branch covers `::ffff:` mapped IMDS; pin
        // the guard wiring (IPv4-mapped IPv6 regression at the connect layer).
        let g = GuardedDnsResolver::new(HostAllowlist::default());
        assert!(!g.permit("rebind.example", sock("::ffff:169.254.169.254")));
    }

    #[test]
    fn permit_allows_nonroutable_when_host_allowlisted() {
        // A legitimate internal receiver, allowlisted by host.
        let g = GuardedDnsResolver::new(HostAllowlist::parse(Some("internal.webhook.svc")));
        assert!(g.permit("internal.webhook.svc", sock("10.0.0.5")));
        // …but a DIFFERENT host resolving into RFC1918 is still blocked
        // (allowlist bypasses is_routable ONLY for listed entries).
        assert!(!g.permit("evil.example", sock("10.0.0.5")));
    }

    #[test]
    fn permit_allows_nonroutable_when_cidr_allowlisted() {
        // Allowlist a CIDR; any host resolving inside it bypasses.
        let g = GuardedDnsResolver::new(HostAllowlist::parse(Some("10.0.0.0/8")));
        assert!(g.permit("anything.internal", sock("10.9.9.9")));
        // Outside the allowlisted CIDR and non-routable → still blocked.
        assert!(!g.permit("anything.internal", sock("192.168.0.1")));
    }

    #[tokio::test]
    async fn resolve_filters_nonroutable_localhost_to_empty() {
        // `localhost` resolves to 127.0.0.1 / ::1 — both non-routable
        // and not allowlisted. The guarded resolver must yield an EMPTY
        // address set so reqwest fails the connect closed (the
        // rebind/loopback target is never dialed).
        let g = GuardedDnsResolver::new(HostAllowlist::default());
        let name = Name::from_str("localhost").expect("valid name");
        let addrs: Vec<SocketAddr> = g.resolve(name).await.expect("resolve ok").collect();
        assert!(
            addrs.is_empty(),
            "non-routable localhost must resolve to an empty (fail-closed) set, got {addrs:?}"
        );
    }

    #[tokio::test]
    async fn resolve_keeps_localhost_when_allowlisted() {
        // Same `localhost`, now allowlisted by host name → the
        // loopback address is RETAINED (legitimate internal receiver).
        let g = GuardedDnsResolver::new(HostAllowlist::parse(Some("localhost")));
        let name = Name::from_str("localhost").expect("valid name");
        let addrs: Vec<SocketAddr> = g.resolve(name).await.expect("resolve ok").collect();
        assert!(
            !addrs.is_empty(),
            "allowlisted localhost must retain its resolved (loopback) address"
        );
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }
}
