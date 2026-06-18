//! Webhook `EventNotifier` + `WebhookTargetGuard` adapter.
//!
//! Implements BOTH [`EventNotifier`] (the delivery side) and
//! [`WebhookTargetGuard`] (the create-time SSRF guard). One struct, two
//! trait impls — composition wires `Arc<WebhookNotifier>` once and
//! exposes it as both `Arc<dyn EventNotifier>` and
//! `Arc<dyn WebhookTargetGuard>`.
//!
//! See `docs/architecture/explanation/event-notifications.md` §7
//! (webhook semantics), §8 (notification payload + signing), §11
//! invariants 1 / 8 / 9 / 11.
//!
//! # Delivery semantics
//!
//! - POST `application/json; charset=utf-8` to the configured URL.
//! - `X-Hort-Signature: sha256=<hex>` header with HMAC-SHA256 of the
//!   canonical body (the exact bytes as transmitted, no normalisation).
//! - `X-Hort-Subscription-Id`, `X-Hort-Schema-Version`, `X-Hort-Delivery-Id`
//!   headers; the delivery id is a fresh `Uuid::new_v4()` per call.
//! - `Policy::limited(0)` redirect policy — webhook URLs must be
//!   canonical. 3xx surfaces as
//!   `DownstreamRejected { reason: RedirectAttempted }` (blocks the
//!   "compromised receiver redirects into IMDS / RFC 1918" SSRF channel).
//! - 5s connect timeout, 10s total. Single attempt — no retry; the
//!   notifier is best-effort.
//!
//! # SSRF guard
//!
//! [`WebhookTargetGuard::check`] is called at subscription create-time
//! by `SubscriptionUseCase`. IP-literal hosts call
//! [`hort_net_egress::is_routable`] directly; DNS-name hosts perform a
//! single resolution attempt via [`tokio::net::lookup_host`] with a 5s
//! timeout and check every returned IP. Operator opt-out
//! (`HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS=true`) is consumed at the
//! use-case layer; this adapter trusts the call site to gate.
//!
//! # HMAC key derivation — SecretPort-resolved shared secret
//!
//! `SubscriptionTarget::Webhook { secret_ref }` carries a
//! [`SecretRef`] — an env-var / file **locator**, not the secret
//! material and not a hash of it. The signing secret's plaintext bytes
//! are resolved at delivery time via [`SecretPort::resolve`] and used
//! directly as the HMAC-SHA256 key. This mirrors the upstream-mapping
//! credential pattern (see `how-to/wire-secrets.md` /
//! `hort-adapters-upstream-http`): composition threads
//! `Arc<dyn SecretPort>` into the adapter and the adapter resolves on
//! each use.
//!
//! **Why the key is the SecretPort-resolved plaintext, not a stored
//! hash.** The earlier shape stored the Argon2id PHC string of the
//! secret on the row and used *that string itself* as the HMAC key.
//! Hashing the secret at rest provided no protection because the stored
//! hash *was* the key: anyone with read access to the subscription store
//! / a backup held the full signing key and could forge valid signed
//! deliveries. It was also a non-standard integration shape (receivers
//! had to store the PHC string to verify). Moving the secret out of the
//! row — the row now holds only a pointer to an operator-managed env var
//! / file — closes that exposure: a store/backup reader sees a locator,
//! not the key.
//!
//! **Wire format unchanged.** Receivers still verify HMAC-SHA256 over
//! the exact transmitted body bytes; only the *key* changes from "the
//! stored Argon2id hash" to "the SecretPort-resolved plaintext". The
//! operator provisions the same plaintext on both ends (the value
//! behind the `SecretRef` here, and the receiver's verification
//! secret) — the standard shared-secret webhook shape.
//!
//! [`SecretRef`]: hort_domain::ports::secret_port::SecretRef
//! [`SecretPort`]: hort_domain::ports::secret_port::SecretPort
//! [`SecretPort::resolve`]: hort_domain::ports::secret_port::SecretPort::resolve

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use hort_config::ExtraTrustAnchors;
use hort_domain::entities::subscription::{SsrfBlockReason, SubscriptionId, SubscriptionTarget};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::PersistedEvent;
use hort_domain::ports::event_notifier::{EventNotifier, NotifyFailureReason, NotifyOutcome};
use hort_domain::ports::secret_port::SecretPort;
use hort_domain::ports::webhook_target_guard::WebhookTargetGuard;
use hort_domain::ports::BoxFuture;
use reqwest::redirect::Policy;
use reqwest::Client;
use serde::Serialize;
use sha2::Sha256;
use url::Url;
use uuid::Uuid;

mod dns_guard;
mod extra_ca;

use dns_guard::{GuardedDnsResolver, HostAllowlist};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Connect timeout ("Connect timeout 5s, total request timeout 10s").
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total request timeout.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// DNS resolution timeout for the SSRF guard. Same 5s as the HTTP
/// connect timeout — there is no reason to wait longer than the
/// downstream connect would.
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Wire-format `schema_version`. Bumped only on breaking changes;
/// until then the wire shape is locked (invariant 7).
const SCHEMA_VERSION: u32 = 1;

/// Forward-proxy environment variables reqwest's `system-proxy` feature
/// consults. If any is set, the webhook delivery client routes through that
/// proxy and the connect-time SSRF DNS-rebind guard is delegated
/// to the proxy's egress allowlist — surfaced by the `warn!` in
/// [`WebhookNotifier::with_allowlist`].
const PROXY_ENV_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Return the [`PROXY_ENV_VARS`] that `lookup` reports set to a non-empty
/// (non-whitespace) value. Pure — takes the env lookup as a parameter — so it
/// is unit-testable without mutating process-global env state.
fn configured_proxy_vars(lookup: impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    PROXY_ENV_VARS
        .iter()
        .copied()
        .filter(|name| lookup(name).is_some_and(|v| !v.trim().is_empty()))
        .collect()
}

// ---------------------------------------------------------------------------
// Wire body
// ---------------------------------------------------------------------------

/// Wire-shape of the body POSTed to the webhook URL. Receivers verify
/// the signature against the raw bytes — they must NOT re-serialise.
#[derive(Serialize)]
struct WebhookBody<'a> {
    schema_version: u32,
    delivery_id: &'a str,
    subscription_id: String,
    delivered_at: String,
    events: &'a [PersistedEvent],
}

// ---------------------------------------------------------------------------
// WebhookNotifier — single struct, two trait impls
// ---------------------------------------------------------------------------

/// Webhook adapter implementing both [`EventNotifier`] and
/// [`WebhookTargetGuard`].
///
/// Composition wires `Arc<WebhookNotifier>` once and exposes it as
/// both `Arc<dyn EventNotifier>` (registered in the dispatcher's
/// notifier list) and `Arc<dyn WebhookTargetGuard>` (held by
/// `AppContext` for `SubscriptionUseCase::create` to invoke).
pub struct WebhookNotifier {
    client: Client,
    /// Resolves the per-subscription webhook signing secret
    /// ([`SubscriptionTarget::Webhook::secret_ref`]) to its plaintext
    /// bytes at delivery time. Composition threads the same
    /// `Arc<dyn SecretPort>` it wires for upstream-mapping credentials.
    /// The resolved [`SecretValue`] zeroizes on drop; the secret never
    /// lives on the subscription row.
    ///
    /// [`SecretValue`]: hort_domain::ports::secret_port::SecretValue
    secret_port: Arc<dyn SecretPort>,
    /// The SAME `HORT_WEBHOOK_ALLOWLIST_HOSTS` allowlist the delivery
    /// path's [`GuardedDnsResolver`] is built from. Held here so the
    /// create/update [`WebhookTargetGuard::check`] guard
    /// (`check_url_routable`) consults the allowlist *before* a direct
    /// resolve — an operator-allowlisted internal/proxy-reached receiver
    /// then passes create-time validation BY NAME, without a direct DNS
    /// resolve (so it works on a proxy-only pod with no direct DNS),
    /// rather than forcing the blanket
    /// `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` opt-out (which would
    /// re-open SSRF for ALL subscriptions). Both the delivery resolver
    /// and this guard are fed from the one
    /// [`HostAllowlist::from_env`] read in [`WebhookNotifier::new`], so
    /// they can never drift.
    allowlist: HostAllowlist,
}

impl WebhookNotifier {
    /// Construct with the optional process-wide extra CA bundle threaded
    /// through from composition (`HORT_EXTRA_CA_BUNDLE`; see ADR 0010) and
    /// the shared [`SecretPort`] used to resolve webhook signing
    /// secrets at delivery time (mirrors the `hort-adapters-upstream-http`
    /// constructor that takes `Arc<dyn SecretPort>`).
    ///
    /// # Errors
    ///
    /// Returns the upstream `upstream:ca_unknown:` sentinel
    /// [`DomainError::Invariant`] when the extra CA bundle is invalid
    /// (matching the upstream-http / advisory-osv pattern), or
    /// `upstream:client_build:` on a reqwest builder failure.
    pub fn new(
        extra_ca: Option<&ExtraTrustAnchors>,
        secret_port: Arc<dyn SecretPort>,
    ) -> DomainResult<Self> {
        Self::with_allowlist(extra_ca, secret_port, HostAllowlist::from_env())
    }

    /// Construct with an explicitly-supplied [`HostAllowlist`] instead
    /// of reading [`dns_guard::ALLOWLIST_ENV`] from the process
    /// environment. Used by tests to exercise the connect-time guard
    /// deterministically without mutating global env state; production
    /// composition uses [`WebhookNotifier::new`].
    pub(crate) fn with_allowlist(
        extra_ca: Option<&ExtraTrustAnchors>,
        secret_port: Arc<dyn SecretPort>,
        allowlist: HostAllowlist,
    ) -> DomainResult<Self> {
        // ADR 0010: ALWAYS via `Client::builder()`, never `Client::new()`.
        // The composition root threads the extra-CA bundle through
        // `apply_to_reqwest_builder`.
        let builder = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            // Policy::limited(0) — block redirects so a compromised
            // receiver cannot 3xx into IMDS / RFC 1918. 3xx responses
            // surface as `DownstreamRejected { RedirectAttempted }` via
            // the adapter's response classifier.
            .redirect(Policy::limited(0))
            // We intentionally DO NOT call `.no_proxy()`.
            // A forward/egress proxy is itself an operator security control
            // (egress allowlist, connection logging, DLP) and is frequently
            // the ONLY outbound route in hardened deployments — forcing direct
            // egress would both break webhook delivery and bypass that control,
            // and would make the webhook client the lone client ignoring the
            // proxy the upstream-http / S3 / OIDC clients honour. The
            // GuardedDnsResolver below is the SSRF DNS-rebind guard on the
            // DIRECT-connect path; when a proxy is configured, reqwest
            // resolves/connects to the target via the proxy instead, so SSRF
            // filtering is delegated to the proxy's egress allowlist. That
            // delegation is made non-silent by the proxy-detection `warn!`
            // emitted below after the client is built.
            // DNS-rebinding TOCTOU guard + allowlist: the connect-time
            // guarded resolver re-runs `hort_net_egress::is_routable` on
            // the address actually dialed, closing the create→deliver
            // rebind race. Bound HERE — to the webhook client builder
            // ONLY — and reachable from nowhere else. NOT re-globalized
            // to the upstream-http / S3 / OIDC clients: those stay
            // operator-vetted by deployment configuration (see `dns_guard`
            // module docs). `HORT_WEBHOOK_ALLOWLIST_HOSTS` only widens
            // THIS resolver, for the listed entries only.
            .dns_resolver(Arc::new(GuardedDnsResolver::new(allowlist.clone())));
        let builder = extra_ca::apply_to_reqwest_builder(builder, extra_ca)?;
        let client = builder.build().map_err(|e| {
            DomainError::Invariant(format!("upstream:client_build:reqwest_build:{e}"))
        })?;
        // If an egress proxy is configured, the connect-time GuardedDnsResolver
        // SSRF guard above cannot see the dialed target (reqwest connects to the
        // proxy; the proxy resolves the target), so SSRF filtering is DELEGATED
        // to the proxy's egress allowlist. Surface that delegation loudly so it
        // is not a silent bypass — the operator must ensure the proxy restricts
        // webhook destinations (block link-local / RFC1918 / IMDS).
        let proxied = configured_proxy_vars(|k| std::env::var(k).ok());
        if !proxied.is_empty() {
            tracing::warn!(
                proxy_env = ?proxied,
                "webhook delivery routes through an egress proxy; the connect-time \
                 SSRF DNS-rebind guard inspects only the direct-connect \
                 address and is therefore DELEGATED to the proxy's egress allowlist \
                 — ensure the proxy blocks link-local/RFC1918/IMDS webhook targets. \
                 The in-process guard is fully effective only when no proxy is set."
            );
        }
        Ok(Self {
            client,
            secret_port,
            // The create/update guard consults the SAME allowlist
            // the delivery `GuardedDnsResolver` above was built from.
            allowlist,
        })
    }
}

// ---------------------------------------------------------------------------
// EventNotifier impl
// ---------------------------------------------------------------------------

impl EventNotifier for WebhookNotifier {
    fn notify<'a>(
        &'a self,
        target: &'a SubscriptionTarget,
        subscription_id: SubscriptionId,
        events: &'a [PersistedEvent],
    ) -> BoxFuture<'a, NotifyOutcome> {
        Box::pin(async move {
            let (url, secret_ref) = match target {
                SubscriptionTarget::Webhook { url, secret_ref } => (url, secret_ref),
                SubscriptionTarget::NatsJetStream { .. } => {
                    // The dispatcher consults `supports()` first; if a
                    // misrouted target reaches us, defensively report a
                    // closed-enum failure rather than panicking.
                    return NotifyOutcome::Failed {
                        reason: NotifyFailureReason::Other("unsupported_target".into()),
                    };
                }
            };

            // Resolve the signing secret's plaintext bytes via the
            // SecretPort at delivery time. The bytes are NEVER on the
            // subscription row — only the `SecretRef` locator is. A
            // resolve failure is non-transient from this adapter's view
            // (the operator must fix the env var / mounted file); surface
            // it as a closed-enum `Other` failure WITHOUT panicking. No
            // URL / secret in the log line.
            let secret = match self.secret_port.resolve(secret_ref).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        subscription_id = %subscription_id.0,
                        error = %e,
                        "webhook signing-secret resolution failed; \
                         delivery not attempted"
                    );
                    return NotifyOutcome::Failed {
                        reason: NotifyFailureReason::Other(format!("secret_resolve:{e}")),
                    };
                }
            };

            deliver(
                &self.client,
                url,
                secret.as_bytes(),
                subscription_id,
                events,
            )
            .await
        })
    }

    fn supports(&self, target: &SubscriptionTarget) -> bool {
        matches!(target, SubscriptionTarget::Webhook { .. })
    }
}

// ---------------------------------------------------------------------------
// WebhookTargetGuard impl
// ---------------------------------------------------------------------------

impl WebhookTargetGuard for WebhookNotifier {
    fn check<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<(), SsrfBlockReason>> {
        // The create/update guard consults the SAME allowlist the delivery
        // `GuardedDnsResolver` honours, so an operator-allowlisted
        // internal/proxy-reached receiver passes create-time validation
        // by name (no direct resolve) instead of needing the blanket
        // `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` opt-out. The port
        // signature is unchanged — the allowlist is threaded from `self`,
        // not the trait method.
        Box::pin(check_url_routable(url.clone(), self.allowlist.clone()))
    }
}

// ---------------------------------------------------------------------------
// Delivery — HMAC + headers + classify
// ---------------------------------------------------------------------------

/// Single-shot webhook delivery. Builds the canonical JSON body, HMAC-
/// signs it, POSTs with the required headers, and classifies the
/// response.
async fn deliver(
    client: &Client,
    url: &Url,
    secret: &[u8],
    subscription_id: SubscriptionId,
    events: &[PersistedEvent],
) -> NotifyOutcome {
    let delivery_id = Uuid::new_v4().to_string();
    let body = WebhookBody {
        schema_version: SCHEMA_VERSION,
        delivery_id: &delivery_id,
        subscription_id: subscription_id.0.to_string(),
        delivered_at: chrono::Utc::now().to_rfc3339(),
        events,
    };
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(e) => {
            // Serialisation failure is non-transient; surface as a
            // closed-enum `Other` reason. Should never happen with our
            // domain types (`PersistedEvent` derives Serialize without
            // fallible paths).
            return NotifyOutcome::Failed {
                reason: NotifyFailureReason::Other(format!("serialize:{e}")),
            };
        }
    };

    // HMAC-SHA256(resolved-plaintext-secret bytes, body_bytes). The
    // key is the SecretPort-resolved plaintext — NOT any at-rest stored
    // value. See module-level doc for the rationale. Wire format
    // unchanged: the receiver verifies HMAC-SHA256 over the same body
    // with the same shared secret.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(&body_bytes);
    let signature_hex = hex::encode(mac.finalize().into_bytes());
    let signature_header = format!("sha256={signature_hex}");

    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Hort-Signature", signature_header)
        .header("X-Hort-Subscription-Id", subscription_id.0.to_string())
        .header("X-Hort-Schema-Version", SCHEMA_VERSION.to_string())
        .header("X-Hort-Delivery-Id", delivery_id)
        .body(body_bytes)
        .send()
        .await;

    match response {
        Ok(resp) => classify_response(resp.status()),
        Err(e) => classify_error(&e),
    }
}

/// Classify a successfully-received HTTP response into a [`NotifyOutcome`].
///
/// Closed match on the status range:
/// - 2xx → `Delivered`.
/// - 3xx → `DownstreamRejected { RedirectAttempted }` (`Policy::limited(0)`
///   surfaces redirects as a status response, not a transport error).
/// - 4xx → `DownstreamRejected { Http4xx { status } }`.
/// - 5xx → `DownstreamRejected { Http5xx { status } }`.
/// - 1xx or other (unreachable in practice for reqwest's response path)
///   → `DownstreamRejected { Other("unexpected_status:<n>") }`.
fn classify_response(status: reqwest::StatusCode) -> NotifyOutcome {
    if status.is_success() {
        NotifyOutcome::Delivered
    } else if status.is_redirection() {
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::RedirectAttempted,
        }
    } else if status.is_client_error() {
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http4xx {
                status: status.as_u16(),
            },
        }
    } else if status.is_server_error() {
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http5xx {
                status: status.as_u16(),
            },
        }
    } else {
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Other(format!("unexpected_status:{}", status.as_u16())),
        }
    }
}

/// Classify a reqwest transport error into a [`NotifyOutcome`].
///
/// Important nuance: `Policy::limited(0)` causes reqwest to surface a
/// 3xx response as a *redirect error* (not a successful response with
/// a 3xx status). We special-case `e.is_redirect()` so the dispatcher
/// sees `DownstreamRejected { RedirectAttempted }` — matching the
/// the contract that a 3xx is a downstream-side rejection,
/// not a transport failure on our side.
///
/// reqwest's other classifiers (`is_timeout`, `is_connect`) are not
/// mutually exclusive — a connect timeout can be both `is_timeout()`
/// and `is_connect()`. We prioritise the more specific timeout signal
/// because the dispatcher pages on `RequestTimeout` separately from
/// `ConnectionRefused`.
fn classify_error(e: &reqwest::Error) -> NotifyOutcome {
    if e.is_redirect() {
        // `Policy::limited(0)` redirect rejection — surface as a
        // downstream rejection, not a transport failure.
        return NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::RedirectAttempted,
        };
    }
    let reason = if e.is_timeout() {
        NotifyFailureReason::RequestTimeout
    } else if e.is_connect() {
        NotifyFailureReason::ConnectionRefused
    } else {
        // Bucket DNS, TLS, decode, body, etc. into the adapter-specific
        // `Other` variant. The port-level closed enum has no `Decode`
        // or `Body` variants on purpose — the dispatcher pages on the
        // closed-enum reasons, not on adapter implementation detail.
        NotifyFailureReason::Other(format!("transport:{e}"))
    };
    NotifyOutcome::Failed { reason }
}

// ---------------------------------------------------------------------------
// SSRF guard — IP-literal direct check + single-shot DNS resolve
// ---------------------------------------------------------------------------

/// Check whether `url`'s host is a permitted webhook target at
/// subscription create/update time.
///
/// # Allowlist precedence
///
/// The allowlist is the SAME `HORT_WEBHOOK_ALLOWLIST_HOSTS` set the
/// delivery-path [`GuardedDnsResolver`] honours (threaded from
/// [`WebhookNotifier`]). It is consulted BEFORE any direct resolve,
/// reusing [`HostAllowlist::host_allowed`] / [`HostAllowlist::ip_allowed`]
/// (the same matching the delivery [`GuardedDnsResolver::permit`] uses —
/// not a re-implementation):
///
/// 1. **DNS-name host explicitly on the allowlist BY NAME** → ACCEPT
///    with NO resolve. An
///    operator-allowlisted internal/proxy-reached receiver passes
///    create-time validation even on a proxy-only pod with no direct
///    DNS (the direct resolve below would otherwise fail / bypass the
///    egress proxy).
/// 2. **IP-literal host** → ACCEPT if it falls inside an allowlisted
///    CIDR (`ip_allowed`) OR is publicly routable
///    ([`hort_net_egress::is_routable`]); otherwise reject with
///    [`SsrfBlockReason::IpLiteralNotRoutable`]. No DNS — it is already
///    an IP, so a literal IMDS / RFC1918 address not on the allowlist is
///    still rejected.
/// 3. **Non-allowlisted DNS name** → the EXISTING single-shot resolve:
///    one resolution attempt with a 5s timeout via
///    [`tokio::net::lookup_host`]; resolver failure surfaces as
///    [`SsrfBlockReason::DnsResolutionFailed`], any non-routable resolved
///    IP as [`SsrfBlockReason::DnsResolvedNotRoutable`]. (An allowlisted
///    *CIDR* — but not the host name — is consulted here too, so a
///    resolved address inside an allowlisted prefix is accepted, matching
///    `permit`.)
///
/// The blanket `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS` opt-out is
/// unchanged — it is consumed at the use-case layer and skips this guard
/// entirely.
///
/// Never panics, never logs the resolved IP set (avoids leaking
/// internal-network topology).
async fn check_url_routable(url: Url, allowlist: HostAllowlist) -> Result<(), SsrfBlockReason> {
    // No host → reject. Backstop; the use case already rejects URLs
    // without hosts as `InvalidWebhookUrl` before reaching the guard.
    let Some(host) = url.host() else {
        return Err(SsrfBlockReason::IpLiteralNotRoutable);
    };

    // IP-literal fast path. `url::Host` is the structured form — `Ipv4`
    // / `Ipv6` variants ARE literals (regardless of how the input string
    // formatted them, e.g. `[::ffff:169.254.169.254]` parses to an
    // `Ipv6` variant whose `to_ipv4()` projection is the v4 literal).
    // `Host::Domain` is the DNS-name path.
    //
    // Allowlist precedence step 2: a literal IP is accepted if it is inside an
    // allowlisted CIDR OR routable — no DNS (it is already an IP), so a
    // literal IMDS / RFC1918 address not on the allowlist is still
    // rejected. Mirrors `GuardedDnsResolver::permit` (sans the host-name
    // arm, which cannot apply to a literal).
    let host = match host {
        url::Host::Ipv4(v4) => {
            let ip = std::net::IpAddr::V4(v4);
            return if allowlist.ip_allowed(ip) || hort_net_egress::is_routable(ip) {
                Ok(())
            } else {
                Err(SsrfBlockReason::IpLiteralNotRoutable)
            };
        }
        url::Host::Ipv6(v6) => {
            let ip = std::net::IpAddr::V6(v6);
            return if allowlist.ip_allowed(ip) || hort_net_egress::is_routable(ip) {
                Ok(())
            } else {
                Err(SsrfBlockReason::IpLiteralNotRoutable)
            };
        }
        url::Host::Domain(d) => d.to_owned(),
    };

    // Allowlist precedence step 1: a DNS name explicitly allowlisted BY NAME
    // is accepted WITHOUT a resolve — so it works on a proxy-only pod
    // with no direct DNS, and never bypasses an egress proxy at create
    // time. Reuses `HostAllowlist::host_allowed` (the same match the
    // delivery resolver uses).
    if allowlist.host_allowed(&host) {
        return Ok(());
    }

    // Allowlist precedence step 3: non-allowlisted DNS name → the EXISTING
    // single-shot resolve. (An allowlisted CIDR is still honoured per
    // address below, matching `permit`.)
    let port = url.port_or_known_default().unwrap_or(443);
    let host_port = format!("{host}:{port}");
    let resolve =
        tokio::time::timeout(DNS_RESOLVE_TIMEOUT, tokio::net::lookup_host(host_port)).await;

    let Ok(Ok(addrs)) = resolve else {
        return Err(SsrfBlockReason::DnsResolutionFailed);
    };

    let mut saw_any = false;
    for sock in addrs {
        saw_any = true;
        // Mirror `GuardedDnsResolver::permit`'s per-address decision for
        // a non-host-allowlisted name: routable OR inside an allowlisted
        // CIDR. (The host-name arm of `permit` was already decided above;
        // here only the CIDR arm can still apply.)
        if !(hort_net_egress::is_routable(sock.ip()) || allowlist.ip_allowed(sock.ip())) {
            return Err(SsrfBlockReason::DnsResolvedNotRoutable);
        }
    }
    if !saw_any {
        // Empty resolution result is rare but observed in test
        // harnesses; treat as a resolve failure rather than success.
        return Err(SsrfBlockReason::DnsResolutionFailed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::ports::secret_port::{SecretRef, SecretSource, SecretValue};

    // -- Proxy-detection helper -------------------------
    //
    // `configured_proxy_vars` is pure (takes the env lookup as a param) so
    // these assert the warn-trigger logic without mutating process-global env.

    #[test]
    fn configured_proxy_vars_reports_set_nonempty_vars() {
        let env = std::collections::HashMap::from([
            ("HTTPS_PROXY", "http://egress.corp:3128"),
            ("HTTP_PROXY", "   "), // whitespace-only → ignored
        ]);
        let got = configured_proxy_vars(|k| env.get(k).copied().map(String::from));
        assert_eq!(got, vec!["HTTPS_PROXY"]);
    }

    #[test]
    fn configured_proxy_vars_empty_when_none_set() {
        assert!(configured_proxy_vars(|_| None).is_empty());
    }

    // -- Test SecretPort stubs ----------------------------------------------
    //
    // Mirrors the `hort-adapters-upstream-http` test pattern
    // (`FixedSecretPort` / `AlwaysErr`): deterministic, no global env
    // mutation. `FixedSecret` returns a known plaintext so a test can
    // assert the HMAC key is THAT plaintext (not any at-rest value);
    // `FailingSecret` exercises the resolve-failure path.

    struct FixedSecret {
        bytes: Vec<u8>,
    }
    impl SecretPort for FixedSecret {
        fn resolve<'a>(
            &'a self,
            _reference: &'a SecretRef,
        ) -> BoxFuture<'a, DomainResult<SecretValue>> {
            let bytes = self.bytes.clone();
            Box::pin(async move { Ok(SecretValue::from_bytes(bytes)) })
        }
    }

    struct FailingSecret;
    impl SecretPort for FailingSecret {
        fn resolve<'a>(
            &'a self,
            _reference: &'a SecretRef,
        ) -> BoxFuture<'a, DomainResult<SecretValue>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "secret not found: EnvVar:HORT_WEBHOOK_SECRET".into(),
                ))
            })
        }
    }

    fn fixed_secret_port(plaintext: &[u8]) -> Arc<dyn SecretPort> {
        Arc::new(FixedSecret {
            bytes: plaintext.to_vec(),
        })
    }

    fn secret_ref() -> SecretRef {
        SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        }
    }

    // -- SSRF guard ---------------------------------------------------------

    #[tokio::test]
    async fn check_url_routable_accepts_routable_ip_literal() {
        // 93.184.216.34 was example.com's historical IP; chosen here as
        // a publicly-routable IPv4 literal that `is_routable` accepts.
        // The check does NOT perform any network I/O for IP literals.
        let url = Url::parse("http://93.184.216.34/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn check_url_routable_rejects_127_0_0_1() {
        let url = Url::parse("http://127.0.0.1/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Err(SsrfBlockReason::IpLiteralNotRoutable));
    }

    /// IPv4-mapped IPv6 form of AWS IMDS must be rejected.
    /// `hort_net_egress::is_routable` covers this in its IPv6 branch via
    /// `to_ipv4()`; this test pins the adapter wiring.
    #[tokio::test]
    async fn check_url_routable_rejects_ipv4_mapped_ipv6_imds() {
        let url = Url::parse("http://[::ffff:169.254.169.254]/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Err(SsrfBlockReason::IpLiteralNotRoutable));
    }

    /// IPv4-compatible IPv6 form (`::a.b.c.d` without `ffff:`) must
    /// ALSO be rejected — `to_ipv4()` matches both shapes, but the
    /// adapter-level test pins that we did not regress to
    /// `to_ipv4_mapped` (which would leave the compat form as a
    /// bypass surface).
    #[tokio::test]
    async fn check_url_routable_rejects_ipv4_compat_ipv6_imds() {
        let url = Url::parse("http://[::169.254.169.254]/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Err(SsrfBlockReason::IpLiteralNotRoutable));
    }

    #[tokio::test]
    async fn check_url_routable_rejects_ipv6_loopback() {
        let url = Url::parse("http://[::1]/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Err(SsrfBlockReason::IpLiteralNotRoutable));
    }

    #[tokio::test]
    async fn check_url_routable_rejects_localhost_dns_name() {
        // `localhost` resolves to 127.0.0.1 and/or ::1 on every
        // sensible system; both are non-routable. This drives the
        // DNS-name branch + the `DnsResolvedNotRoutable` mapping
        // without mocking the resolver.
        let url = Url::parse("http://localhost:9999/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Err(SsrfBlockReason::DnsResolvedNotRoutable));
    }

    #[tokio::test]
    async fn check_url_routable_rejects_nxdomain() {
        // RFC 2606 reserves `.invalid`; resolution must fail.
        let url = Url::parse("http://nx-this-name-does-not-exist.invalid/x").unwrap();
        let result = check_url_routable(url, HostAllowlist::default()).await;
        assert_eq!(result, Err(SsrfBlockReason::DnsResolutionFailed));
    }

    // -- Create/update guard consults the host-allowlist -------------------
    //
    // These pin the allowlist precedence in the create/update guard
    // (`check_url_routable`), distinct from the delivery-path
    // `GuardedDnsResolver::permit` tests in `dns_guard.rs`. The
    // load-bearing assertion is precedence step 1: an allowlisted-BY-NAME
    // host is accepted WITHOUT any resolve.

    /// A host on the allowlist BY NAME is accepted at create-time WITHOUT
    /// a resolve. Uses an RFC 2606 `.invalid` name that CANNOT resolve —
    /// before the allowlist was introduced this hit the direct-resolve path
    /// and was rejected `DnsResolutionFailed`; the by-name allowlist
    /// short-circuits before any resolve, so it is accepted. That the
    /// `.invalid` name is unresolvable is exactly what proves "no resolve
    /// happened": had the code resolved, it would have failed.
    #[tokio::test]
    async fn check_url_routable_accepts_allowlisted_name_without_resolve() {
        let url = Url::parse("https://internal-receiver.invalid/hook").unwrap();
        let allowlist = HostAllowlist::parse(Some("internal-receiver.invalid"));
        let result = check_url_routable(url, allowlist).await;
        assert_eq!(
            result,
            Ok(()),
            "an allowlisted-by-name host must be accepted at create-time \
             without a resolve (works on a proxy-only pod)"
        );
    }

    /// Case-insensitive by-name match (mirrors `host_allowed`).
    #[tokio::test]
    async fn check_url_routable_accepts_allowlisted_name_case_insensitive() {
        let url = Url::parse("https://INTERNAL-RECEIVER.invalid/hook").unwrap();
        let allowlist = HostAllowlist::parse(Some("internal-receiver.invalid"));
        assert_eq!(check_url_routable(url, allowlist).await, Ok(()));
    }

    /// A NON-allowlisted, non-routable DNS name is STILL rejected —
    /// existing behaviour preserved. `localhost` resolves to loopback
    /// (non-routable) and is not on the allowlist.
    #[tokio::test]
    async fn check_url_routable_rejects_nonallowlisted_nonroutable_name() {
        let url = Url::parse("http://localhost:9999/x").unwrap();
        // A non-matching allowlist entry must NOT widen the decision.
        let allowlist = HostAllowlist::parse(Some("some-other-host.example"));
        assert_eq!(
            check_url_routable(url, allowlist).await,
            Err(SsrfBlockReason::DnsResolvedNotRoutable),
            "a non-allowlisted non-routable host must still be rejected"
        );
    }

    /// A literal IMDS IP NOT on the allowlist is still rejected,
    /// with NO DNS (it is already an IP). `169.254.169.254` is AWS IMDS.
    #[tokio::test]
    async fn check_url_routable_rejects_literal_imds_not_allowlisted() {
        let url = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        let allowlist = HostAllowlist::parse(Some("internal-receiver.invalid"));
        assert_eq!(
            check_url_routable(url, allowlist).await,
            Err(SsrfBlockReason::IpLiteralNotRoutable),
            "a literal IMDS IP not on the allowlist must still be rejected"
        );
    }

    /// A literal RFC1918 IP NOT on the allowlist is still rejected.
    #[tokio::test]
    async fn check_url_routable_rejects_literal_rfc1918_not_allowlisted() {
        let url = Url::parse("http://10.0.0.1/x").unwrap();
        let allowlist = HostAllowlist::parse(Some("internal-receiver.invalid"));
        assert_eq!(
            check_url_routable(url, allowlist).await,
            Err(SsrfBlockReason::IpLiteralNotRoutable),
        );
    }

    /// A literal RFC1918 IP that IS inside an allowlisted CIDR is
    /// accepted — no DNS. Mirrors `ip_allowed`.
    #[tokio::test]
    async fn check_url_routable_accepts_literal_ip_in_allowlisted_cidr() {
        let url = Url::parse("http://10.9.9.9/x").unwrap();
        let allowlist = HostAllowlist::parse(Some("10.0.0.0/8"));
        assert_eq!(check_url_routable(url, allowlist).await, Ok(()));
    }

    /// A literal routable IP is still accepted even when the
    /// allowlist is non-empty and does not name it (the `is_routable`
    /// arm of the IP-literal decision is preserved).
    #[tokio::test]
    async fn check_url_routable_accepts_routable_literal_with_unrelated_allowlist() {
        let url = Url::parse("http://93.184.216.34/x").unwrap();
        let allowlist = HostAllowlist::parse(Some("10.0.0.0/8"));
        assert_eq!(check_url_routable(url, allowlist).await, Ok(()));
    }

    // -- Guard entry point (`WebhookTargetGuard::check`) -------------------
    //
    // `SubscriptionUseCase::create` AND `::update` both invoke the guard
    // through `self.webhook_guard.check(url)` — the SAME trait method.
    // These tests exercise that exact entry point through the REAL
    // `WebhookNotifier` (built via `with_allowlist`, the same code path
    // `new` takes from `HostAllowlist::from_env`), proving the allowlist
    // stored on the notifier is threaded into the create/update guard.
    // Because create and update call the identical `check`, one
    // entry-point test per outcome covers both paths (the guard logic is
    // shared; see the use case's two call sites).

    /// An allowlisted-by-name (unresolvable `.invalid`) host is ACCEPTED
    /// via the `WebhookTargetGuard::check` trait method — without a
    /// resolve.
    #[tokio::test]
    async fn guard_check_accepts_allowlisted_name_without_resolve() {
        let n = WebhookNotifier::with_allowlist(
            None,
            fixed_secret_port(b"s"),
            HostAllowlist::parse(Some("internal-receiver.invalid")),
        )
        .expect("builder builds");
        let url = Url::parse("https://internal-receiver.invalid/hook").unwrap();
        assert_eq!(
            n.check(&url).await,
            Ok(()),
            "the create/update guard (WebhookTargetGuard::check) must \
             accept an allowlisted-by-name host without a resolve"
        );
    }

    /// A non-allowlisted non-routable host is still REJECTED through
    /// the trait method (existing behaviour).
    #[tokio::test]
    async fn guard_check_rejects_nonallowlisted_nonroutable_host() {
        let n = WebhookNotifier::with_allowlist(
            None,
            fixed_secret_port(b"s"),
            HostAllowlist::parse(Some("some-other-host.example")),
        )
        .expect("builder builds");
        let url = Url::parse("http://localhost:9999/x").unwrap();
        assert_eq!(
            n.check(&url).await,
            Err(SsrfBlockReason::DnsResolvedNotRoutable),
        );
    }

    /// A literal IMDS IP not on the allowlist is still REJECTED through
    /// the trait method (no DNS).
    #[tokio::test]
    async fn guard_check_rejects_literal_imds_not_allowlisted() {
        let n = WebhookNotifier::with_allowlist(
            None,
            fixed_secret_port(b"s"),
            HostAllowlist::parse(Some("internal-receiver.invalid")),
        )
        .expect("builder builds");
        let url = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert_eq!(
            n.check(&url).await,
            Err(SsrfBlockReason::IpLiteralNotRoutable),
        );
    }

    // -- Response classifier -----------------------------------------------

    #[test]
    fn classify_response_200_is_delivered() {
        let outcome = classify_response(reqwest::StatusCode::OK);
        assert_eq!(outcome, NotifyOutcome::Delivered);
    }

    #[test]
    fn classify_response_204_is_delivered() {
        let outcome = classify_response(reqwest::StatusCode::NO_CONTENT);
        assert_eq!(outcome, NotifyOutcome::Delivered);
    }

    #[test]
    fn classify_response_302_is_redirect_attempted() {
        let outcome = classify_response(reqwest::StatusCode::FOUND);
        assert_eq!(
            outcome,
            NotifyOutcome::DownstreamRejected {
                reason: NotifyFailureReason::RedirectAttempted,
            }
        );
    }

    #[test]
    fn classify_response_307_is_redirect_attempted() {
        let outcome = classify_response(reqwest::StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            outcome,
            NotifyOutcome::DownstreamRejected {
                reason: NotifyFailureReason::RedirectAttempted,
            }
        );
    }

    #[test]
    fn classify_response_404_is_http4xx() {
        let outcome = classify_response(reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            outcome,
            NotifyOutcome::DownstreamRejected {
                reason: NotifyFailureReason::Http4xx { status: 404 },
            }
        );
    }

    #[test]
    fn classify_response_503_is_http5xx() {
        let outcome = classify_response(reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            outcome,
            NotifyOutcome::DownstreamRejected {
                reason: NotifyFailureReason::Http5xx { status: 503 },
            }
        );
    }

    // -- supports() --------------------------------------------------------

    #[test]
    fn supports_returns_true_for_webhook_target() {
        let n = WebhookNotifier::new(None, fixed_secret_port(b"s")).expect("builder builds");
        let target = SubscriptionTarget::Webhook {
            url: Url::parse("https://example.com/hook").unwrap(),
            secret_ref: secret_ref(),
        };
        assert!(n.supports(&target));
    }

    #[test]
    fn supports_returns_false_for_nats_target() {
        let n = WebhookNotifier::new(None, fixed_secret_port(b"s")).expect("builder builds");
        let target = SubscriptionTarget::NatsJetStream {
            subject: "events.artifact".into(),
        };
        assert!(!n.supports(&target));
    }

    // -- NATS target safety net ---------------------------------------------

    #[tokio::test]
    async fn notify_with_nats_target_returns_failed_not_panic() {
        // `supports()` is the dispatcher's filter, but defensively the
        // adapter must not panic if it receives a misrouted target.
        let n = WebhookNotifier::new(None, fixed_secret_port(b"s")).expect("builder builds");
        let target = SubscriptionTarget::NatsJetStream {
            subject: "events.artifact".into(),
        };
        let sub_id = SubscriptionId(Uuid::new_v4());
        let outcome = n.notify(&target, sub_id, &[]).await;
        match outcome {
            NotifyOutcome::Failed {
                reason: NotifyFailureReason::Other(s),
            } => assert_eq!(s, "unsupported_target"),
            other => panic!("expected Failed{{Other}}, got {other:?}"),
        }
    }

    // -- Connect-time guard: end-to-end through the bound client ----------
    //
    // These two tests prove the `GuardedDnsResolver` is actually BOUND
    // to the webhook `reqwest::Client` (not merely unit-correct in
    // isolation): the same DNS-name webhook target is BLOCKED when the
    // resolved address is non-routable and not allowlisted, and ALLOWED
    // when the host is allowlisted. The IP-literal SSRF cases are
    // covered by the create-time `check_url_routable` tests above; the
    // resolver only fires for DNS names (reqwest skips DNS for IP
    // literals), which is exactly the rebinding-TOCTOU surface.

    fn webhook_target(url: &str) -> SubscriptionTarget {
        SubscriptionTarget::Webhook {
            url: Url::parse(url).unwrap(),
            secret_ref: secret_ref(),
        }
    }

    #[tokio::test]
    async fn deliver_to_rebound_nonroutable_dns_name_is_blocked_by_connect_guard() {
        // Simulates the DNS-rebinding attack tail: a webhook registered on
        // a DNS name that (post-create rebind) resolves to a non-routable
        // address. `localhost` is the stable DNS name resolving to loopback
        // on every system. With the default (empty) allowlist the guarded
        // resolver filters every resolved address out, so reqwest gets an
        // empty address set and the connect fails — the rebind target is
        // NEVER dialed.
        let n = WebhookNotifier::with_allowlist(
            None,
            fixed_secret_port(b"s"),
            HostAllowlist::default(),
        )
        .expect("builder builds");
        let target = webhook_target("https://localhost:9/hook");
        let outcome = n.notify(&target, SubscriptionId(Uuid::new_v4()), &[]).await;
        // Resolver yielding zero addresses surfaces as a transport
        // failure, NOT a `Delivered` / `DownstreamRejected`. The exact
        // reqwest classification (connect vs other) is not load-bearing;
        // the security invariant is "not delivered".
        assert!(
            matches!(outcome, NotifyOutcome::Failed { .. }),
            "rebound non-routable DNS target must NOT be delivered, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn deliver_to_allowlisted_internal_host_is_permitted_by_connect_guard() {
        // An operator-allowlisted internal receiver. A wiremock
        // server bound to loopback is a faithful stand-in for an
        // in-DMZ/in-cluster webhook receiver on a non-routable address.
        // With `localhost` allowlisted, the guarded resolver RETAINS the
        // loopback address and the POST is delivered (200 → Delivered).
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        // wiremock binds to 127.0.0.1:<port>; rewrite to the `localhost`
        // DNS name so the request goes through the guarded RESOLVER
        // (IP-literal hosts bypass DNS in reqwest).
        let port = server.address().port();
        let url = format!("http://localhost:{port}/hook");

        let n = WebhookNotifier::with_allowlist(
            None,
            fixed_secret_port(b"s"),
            HostAllowlist::parse(Some("localhost")),
        )
        .expect("builder builds");
        let target = webhook_target(&url);
        let outcome = n.notify(&target, SubscriptionId(Uuid::new_v4()), &[]).await;
        assert_eq!(
            outcome,
            NotifyOutcome::Delivered,
            "allowlisted internal host must be delivered to"
        );
    }

    // -- HMAC key is the SecretPort-RESOLVED PLAINTEXT ----------------------
    //
    // The load-bearing security assertion. The signing key MUST be the
    // SecretPort-resolved plaintext bytes — NOT any at-rest stored value.
    // The discriminating test injects a known plaintext via a stub
    // SecretPort, captures the wire request, and proves the
    // `X-Hort-Signature` equals `HMAC-SHA256(known_plaintext, body)` AND
    // is NOT `HMAC-SHA256(old_stored_hash, body)` (the old vulnerable
    // key). It also pins that the receiver-side wire format is unchanged:
    // the same body bytes, the same `sha256=<hex>` shape.

    #[tokio::test]
    async fn deliver_hmac_key_is_resolved_plaintext_not_stored_value() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        // The plaintext the operator provisioned behind the SecretRef.
        const KNOWN_PLAINTEXT: &[u8] = b"the-real-shared-secret-bytes";
        // The string that the old code would have used as the key:
        // the Argon2id PHC string stored on the row. If this regressed
        // and the at-rest value were used, the signature would match
        // THIS — the test asserts it does NOT.
        const OLD_STORED_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

        let server = MockServer::start().await;
        let captured: Arc<std::sync::Mutex<Vec<Request>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        Mock::given(method("POST"))
            .respond_with(move |req: &Request| {
                captured_clone.lock().unwrap().push(req.clone());
                ResponseTemplate::new(200)
            })
            .expect(1)
            .mount(&server)
            .await;

        let n = WebhookNotifier::with_allowlist(
            None,
            fixed_secret_port(KNOWN_PLAINTEXT),
            HostAllowlist::parse(Some("localhost")),
        )
        .expect("builder builds");
        // wiremock binds 127.0.0.1; use `localhost` (allowlisted) so the
        // guarded resolver permits the loopback receiver.
        let port = server.address().port();
        let target = webhook_target(&format!("http://localhost:{port}/hook"));
        let outcome = n.notify(&target, SubscriptionId(Uuid::new_v4()), &[]).await;
        assert_eq!(outcome, NotifyOutcome::Delivered);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let body_bytes = &reqs[0].body;
        let sig = reqs[0]
            .headers
            .get("x-hort-signature")
            .expect("X-Hort-Signature present")
            .to_str()
            .unwrap();
        let received_hex = sig
            .strip_prefix("sha256=")
            .expect("wire format unchanged: sha256=<hex> prefix");

        // Expected: HMAC over the body keyed by the RESOLVED PLAINTEXT.
        let mut good =
            Hmac::<Sha256>::new_from_slice(KNOWN_PLAINTEXT).expect("any-length HMAC key");
        good.update(body_bytes);
        let expected_hex = hex::encode(good.finalize().into_bytes());

        // The old (vulnerable) key: the at-rest stored hash.
        let mut bad = Hmac::<Sha256>::new_from_slice(OLD_STORED_HASH.as_bytes())
            .expect("any-length HMAC key");
        bad.update(body_bytes);
        let stored_hash_hex = hex::encode(bad.finalize().into_bytes());

        assert_eq!(
            received_hex, expected_hex,
            "signature MUST be HMAC-SHA256(resolved_plaintext, body)"
        );
        assert_ne!(
            received_hex, stored_hash_hex,
            "signature MUST NOT be HMAC-SHA256(at-rest stored hash, body) — \
             that was the old vulnerable key"
        );
    }

    #[tokio::test]
    async fn deliver_secret_resolve_failure_maps_to_failed_without_panic() {
        // SecretPort::resolve errors (missing env var / unreadable
        // mounted file). The adapter must surface a closed-enum
        // `Failed { Other(secret_resolve:...) }` and MUST NOT panic or
        // attempt the HTTP POST.
        let n = WebhookNotifier::with_allowlist(
            None,
            Arc::new(FailingSecret),
            HostAllowlist::default(),
        )
        .expect("builder builds");
        let target = webhook_target("https://example.com/hook");
        let outcome = n.notify(&target, SubscriptionId(Uuid::new_v4()), &[]).await;
        match outcome {
            NotifyOutcome::Failed {
                reason: NotifyFailureReason::Other(s),
            } => assert!(
                s.starts_with("secret_resolve:"),
                "expected secret_resolve:… reason, got {s}"
            ),
            other => panic!("expected Failed{{Other(secret_resolve:…)}}, got {other:?}"),
        }
    }
}
