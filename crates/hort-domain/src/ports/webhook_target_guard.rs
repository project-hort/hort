//! Webhook target SSRF-check port.
//!
//! See `docs/architecture/explanation/event-notifications.md` (denial path
//! `WebhookTargetNotRoutable`; webhook delivery SSRF rule).
//!
//! The trait is **pure async signature** — `hort-domain` is I/O-free. The
//! adapter implements this against `hort_net_egress::is_routable`
//! + a one-shot DNS resolution attempt; the implementation never lands in
//!   this crate.
//!
//! [`crate::entities::subscription::SsrfBlockReason`] is the canonical
//! closed enum for failure reasons and is re-exported here as a convenience
//! so the use case can `use` it from a single path.

use url::Url;

pub use crate::entities::subscription::SsrfBlockReason;

use super::BoxFuture;

/// Outbound port: check whether a webhook URL's host is routable
/// (webhook SSRF rule —
/// `docs/architecture/explanation/event-notifications.md`).
///
/// Implementations parse the URL, classify the host (IP literal vs DNS
/// name), and either:
/// - call `hort_net_egress::is_routable` on the literal, returning
///   [`SsrfBlockReason::IpLiteralNotRoutable`] on miss; or
/// - perform a single resolution attempt and call `is_routable` on every
///   resolved IP, returning [`SsrfBlockReason::DnsResolvedNotRoutable`] when
///   any resolved IP is non-routable, or
///   [`SsrfBlockReason::DnsResolutionFailed`] when the resolver itself
///   fails.
///
/// The create-time guard is still single-shot at the use-case layer.
/// A **webhook-scoped connect-time `GuardedDnsResolver`**
/// in `hort-notifier-webhook` (bound only to the webhook `reqwest` client —
/// not re-globalised to upstream/S3/OIDC, which remain operator-vetted)
/// re-checks `hort_net_egress::is_routable` on every dialed
/// address. The DNS-rebinding-between-create-and-delivery residual risk is
/// therefore **closed for the webhook delivery path** (user-submitted
/// webhook URLs warrant the connect-time guard where operator-vetted upstreams
/// do not).
pub trait WebhookTargetGuard: Send + Sync {
    /// Returns `Ok(())` when the URL is routable to a public destination,
    /// `Err(reason)` otherwise.
    fn check<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<(), SsrfBlockReason>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that [`WebhookTargetGuard`] is
    /// dyn-compatible. The use case wires it behind
    /// `Arc<dyn WebhookTargetGuard>` in `AppContext`.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn WebhookTargetGuard>();
    }

    #[test]
    fn ssrf_block_reason_re_export_is_canonical() {
        // The `pub use` above MUST re-export the canonical enum from
        // `entities::subscription`. A function whose parameter is typed
        // via the re-exported path and whose argument is constructed via
        // the original path resolves only when both paths refer to the
        // same type — this is the structural-identity check.
        fn take(_: SsrfBlockReason) {}
        // Type-import path is intentional: this binding's qualification
        // exists to assert it is the same type as the re-export, so the
        // path is *not* unnecessary qualification for the purposes of
        // the test.
        #[allow(unused_qualifications)]
        let from_entity = crate::entities::subscription::SsrfBlockReason::IpLiteralNotRoutable;
        take(from_entity);
    }
}
