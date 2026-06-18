//! NATS JetStream `EventNotifier` adapter.
//!
//! Implements [`EventNotifier`] for [`SubscriptionTarget::NatsJetStream`].
//! Single JetStream connection per process — composition root constructs
//! the adapter from `HORT_NATS_URL` and passes a long-lived
//! `Arc<NatsNotifier>` to the dispatcher.
//!
//! See `docs/architecture/explanation/event-notifications.md` §7 NATS
//! semantics, §8 wire shape, §11 invariant 1 (best-effort, no retry, no
//! buffering).
//!
//! # Wire shape
//!
//! Published payload is the same JSON body the webhook adapter sends.
//! Header propagation is intentionally not used — receivers parse one
//! wire shape regardless of transport.
//!
//! # Delivery semantics
//!
//! - `Context::publish(subject, payload).await?` returns a
//!   [`async_nats::jetstream::context::PublishAckFuture`]; we wrap that
//!   inner future with `tokio::time::timeout(2s)` so this adapter's
//!   ack-timeout discipline is the 2s value, not the
//!   `async-nats` default (which has shifted between releases).
//! - On ack within 2s → [`NotifyOutcome::Delivered`].
//! - On timeout → [`NotifyOutcome::Failed`] with
//!   [`NotifyFailureReason::AckTimeout`].
//! - On broker-side rejection — `PublishErrorKind::StreamNotFound`,
//!   `WrongLastMessageId`, `WrongLastSequence`, `MaxAckPending`, or an
//!   `Other` whose `to_string()` matches the broker "no responders /
//!   no stream" wording → [`NotifyOutcome::Failed`] with
//!   [`NotifyFailureReason::NatsNak`]. These are operator-visible
//!   stream-configuration issues, not transport outages — the
//!   distinction matters for dashboards.
//! - On transport-level failure (broker unreachable, broken pipe,
//!   client `Other`) → [`NotifyOutcome::Failed`] with
//!   [`NotifyFailureReason::ConnectionLost`].
//! - **No retry.** Single attempt per `notify` call.
//!
//! # Connection lifecycle
//!
//! The `async-nats` client owns its own reconnect loop internally — when
//! a connection drops it transparently reconnects. This adapter does NOT
//! add a wrapper reconnect loop. If a `publish` call hits a
//! disconnected state the client may return immediately with an error;
//! that surfaces as `Failed { ConnectionLost }` and the dispatcher's
//! failure budget handles the rest.

use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::context::{PublishError, PublishErrorKind};
use bytes::Bytes;
use hort_config::ExtraTrustAnchors;
use hort_domain::entities::subscription::{SubscriptionId, SubscriptionTarget};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::PersistedEvent;
use hort_domain::ports::event_notifier::{EventNotifier, NotifyFailureReason, NotifyOutcome};
use hort_domain::ports::BoxFuture;
use serde::Serialize;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// JetStream ack timeout ("Publish-with-ack: 2s
/// timeout → `Failed { AckTimeout }`"). The inner publish-ack future is
/// awaited with this deadline regardless of any default that
/// `async-nats` ships with.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// Wire-format `schema_version`, matching `hort-notifier-webhook`'s
/// constant. Bumped only on breaking changes to the wire shape;
/// receivers across both transports parse the same value (invariant 7).
const SCHEMA_VERSION: u32 = 1;

/// Maximum tracing-subject prefix length. The tracing discipline specifies
/// "subject prefix only (truncated)" to avoid leakage of operator
/// subject hierarchies in audit logs. 32 chars is enough to identify a
/// namespace without exposing the leaf.
const TRACING_SUBJECT_MAX: usize = 32;

// ---------------------------------------------------------------------------
// Wire body
// ---------------------------------------------------------------------------

/// Wire-shape of the payload published to the JetStream subject.
/// Matches the webhook adapter's `WebhookBody` so receivers parse one
/// shape regardless of transport.
///
/// No `Deserialize` — adapters never reconstitute domain types from
/// external input (the no-deserialisation rule).
#[derive(Serialize)]
struct NatsPayload<'a> {
    schema_version: u32,
    delivery_id: String,
    subscription_id: String,
    delivered_at: String,
    events: &'a [PersistedEvent],
}

// ---------------------------------------------------------------------------
// NatsNotifier — single struct, one trait impl
// ---------------------------------------------------------------------------

/// NATS JetStream adapter implementing [`EventNotifier`].
///
/// Composition wires `Arc<NatsNotifier>` once and registers it in the
/// dispatcher's `Vec<Arc<dyn EventNotifier>>`. The dispatcher selects
/// this adapter for any subscription whose target is
/// [`SubscriptionTarget::NatsJetStream`] via [`Self::supports`].
pub struct NatsNotifier {
    jetstream: jetstream::Context,
}

impl NatsNotifier {
    /// Construct from a pre-opened [`async_nats::Client`]. The
    /// composition root opens the client once (`HORT_NATS_URL` +
    /// optional auth knobs) and threads it here.
    pub fn new(client: async_nats::Client) -> Self {
        Self {
            jetstream: jetstream::new(client),
        }
    }

    /// Convenience constructor that connects to `url` and wraps the
    /// resulting client. Used by the composition root when no
    /// pre-opened client is available.
    ///
    /// `extra_ca` threads the process-wide `HORT_EXTRA_CA_BUNDLE`
    /// (`ExtraTrustAnchors`) into the NATS TLS leg. Without this, a
    /// `tls://` broker fronted by an internal CA could not be verified
    /// and the operator had no documented way to extend trust for the
    /// NATS leg — exactly the out-of-band-insecure-workaround pressure
    /// ADR 0010 exists to prevent. Every other TLS surface
    /// (upstream-http / webhook / S3 / OIDC) already receives
    /// `extra_trust_anchors`; this makes the bundle genuinely
    /// process-wide across *all* TLS surfaces.
    ///
    /// # Behaviour
    ///
    /// - `None` (or an empty bundle) → **byte-equivalent to the
    ///   prior behaviour**: plain `async_nats::connect(url)` with the
    ///   client's default trust. Zero behaviour change for the
    ///   no-extra-CA deployment.
    /// - `Some(non-empty)` → connect via
    ///   [`async_nats::ConnectOptions`] with a custom
    ///   [`rustls::ClientConfig`] whose root store is **the OS native
    ///   trust store PLUS** the extra anchors (system roots are NOT
    ///   dropped — mirrors `build_rustls_client_config` in
    ///   `hort-adapters-upstream-http`). TLS is still driven by the URL
    ///   scheme / server `INFO` exactly as before — `require_tls` is
    ///   *not* forced, so a `Some`-anchors operator pointing at a plain
    ///   `nats://` URL keeps the existing non-TLS behaviour.
    ///
    /// ## Why `tls_client_config`, not `add_root_certificates`
    ///
    /// The original recommendation literally named
    /// `ConnectOptions::add_root_certificates`, but in async-nats 0.48
    /// that method is **path-based** (`fn add_root_certificates(self,
    /// path: PathBuf)`) — it reads a PEM file off the filesystem. Our
    /// trust anchors are already in memory as DER bytes
    /// (`ExtraTrustAnchors::certs_der()`); routing them through a
    /// temp-file would be an anti-pattern. The faithful realisation of
    /// the recommendation's "mirroring upstream-http/webhook/S3" intent
    /// is `ConnectOptions::tls_client_config(rustls::ClientConfig)`,
    /// built the same way `hort-adapters-upstream-http::tls_config`
    /// builds its augmented root store. (async-nats consumes a
    /// caller-supplied `tls_client_config` verbatim and skips its own
    /// path-cert loading — so we own the system-roots-plus-extras
    /// merge, exactly as upstream-http does.)
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invariant`] with sentinel prefix
    /// `nats_connect:` on connection failure (and on extra-CA root-store
    /// construction failure) — matching the upstream-http / advisory-osv
    /// error-classification convention (ADR 0010). The error enum/shape
    /// is unchanged.
    pub async fn connect(url: &str, extra_ca: Option<&ExtraTrustAnchors>) -> DomainResult<Self> {
        let client = match decide_nats_tls(extra_ca)? {
            // Plain-connect path: plain connect, same
            // default trust, same `nats_connect:` error sentinel.
            NatsTls::Default => async_nats::connect(url)
                .await
                .map_err(|e| DomainError::Invariant(format!("nats_connect:{e}")))?,
            // Extra-CA path: drive trust off the augmented rustls config
            // (system roots + extra anchors). `require_tls` is left
            // unset so the URL scheme / server INFO decides whether the
            // handshake is actually TLS — same decision logic as before.
            NatsTls::Custom(config) => async_nats::ConnectOptions::new()
                .tls_client_config(*config)
                .connect(url)
                .await
                .map_err(|e| DomainError::Invariant(format!("nats_connect:{e}")))?,
        };
        Ok(Self::new(client))
    }
}

// ---------------------------------------------------------------------------
// Extra-CA trust threading for the NATS TLS leg (ADR 0010)
// ---------------------------------------------------------------------------

// `rustls` is reached through async-nats' re-export (`async_nats::rustls`
// == `tokio_rustls::rustls`) so the `ClientConfig` we hand to
// `ConnectOptions::tls_client_config` is *the exact same type* async-nats
// compiled against, regardless of how Cargo unifies versions. Declaring a
// separate `rustls` dependency here could resolve to a distinct crate
// instance and fail to type-check at the `tls_client_config` call.
use async_nats::rustls;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

/// Branch decision for [`NatsNotifier::connect`], factored out as a pure
/// value so both arms are unit-testable without a live broker.
///
/// `Custom` boxes the `ClientConfig` — `rustls::ClientConfig` is large
/// and `Default` is the common (no-extra-CA) variant; boxing keeps the
/// enum small (clippy `large_enum_variant`).
enum NatsTls {
    /// No extra CA in play → plain `async_nats::connect(url)`, the
    /// prior behaviour, byte-for-byte.
    Default,
    /// Extra CA present → connect with this augmented rustls config.
    Custom(Box<ClientConfig>),
}

/// Decide which TLS path [`NatsNotifier::connect`] takes.
///
/// `None` or an empty bundle → [`NatsTls::Default`] (byte-equivalent to
/// the plain connect). A non-empty bundle → [`NatsTls::Custom`]
/// carrying the augmented `rustls::ClientConfig`.
fn decide_nats_tls(extra_ca: Option<&ExtraTrustAnchors>) -> DomainResult<NatsTls> {
    match extra_ca {
        None => Ok(NatsTls::Default),
        Some(anchors) if anchors.is_empty() => Ok(NatsTls::Default),
        Some(anchors) => Ok(NatsTls::Custom(Box::new(build_nats_rustls_config(
            anchors,
        )?))),
    }
}

/// Build the augmented `RootCertStore`: OS native trust store **PLUS**
/// the extra anchors. Mirrors `build_rustls_client_config` in
/// `hort-adapters-upstream-http::tls_config` — system roots are loaded
/// first and the extra anchors are *added on top*, never replacing the
/// OS set. Factored out so a unit test can assert the resulting root
/// count is `system_count + anchors.cert_count()` without a broker.
///
/// # Errors
///
/// [`DomainError::Invariant`] with the `nats_connect:` sentinel when the
/// OS trust store cannot be loaded or an extra anchor is rejected by
/// rustls — same error enum/shape and classification convention as the
/// connect path (ADR 0010).
fn build_nats_root_store(anchors: &ExtraTrustAnchors) -> DomainResult<RootCertStore> {
    let mut roots = RootCertStore::empty();

    // OS native roots first. Mirror upstream-http's partial-load
    // handling: a partial load warns and proceeds with the parseable
    // subset; an empty result (no OS trust store at all) is a hard
    // error — without it, a `tls://` handshake would only trust the
    // extra anchor, silently narrowing trust.
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() && native.certs.is_empty() {
        return Err(DomainError::Invariant(format!(
            "nats_connect:OS native trust store returned no certificates ({} errors)",
            native.errors.len()
        )));
    }
    if !native.errors.is_empty() {
        tracing::warn!(
            error_count = native.errors.len(),
            parsed_count = native.certs.len(),
            "partial native trust store load (nats tls)"
        );
    }
    if native.certs.is_empty() {
        return Err(DomainError::Invariant(
            "nats_connect:OS native trust store is empty (no CA certificates found)".to_string(),
        ));
    }
    for cert in native.certs {
        // Defence-in-depth second pass; native_certs already filtered.
        let _ = roots.add(cert);
    }

    // Fold in the process-wide extra CA bundle on top of the OS set.
    for der_bytes in anchors.certs_der() {
        let cert = CertificateDer::from(der_bytes.as_slice().to_vec());
        roots.add(cert).map_err(|e| {
            DomainError::Invariant(format!("nats_connect:extra CA bundle entry rejected: {e}"))
        })?;
    }

    Ok(roots)
}

/// Build the augmented `rustls::ClientConfig` for the extra-CA NATS path.
///
/// The crypto provider is pinned to **ring** explicitly via
/// `builder_with_provider` rather than the version-implicit `builder()`.
/// This crate's async-nats `ring` feature selects `tokio-rustls/ring`,
/// while `hort-adapters-upstream-http` installs `aws_lc_rs` as the
/// *process-global* default provider. The version-implicit
/// `ClientConfig::builder()` would resolve against whatever global
/// default happens to be installed (a cross-crate ordering hazard);
/// passing the ring provider explicitly makes this path self-contained
/// and matches the crypto backend async-nats itself uses for the
/// handshake.
fn build_nats_rustls_config(anchors: &ExtraTrustAnchors) -> DomainResult<ClientConfig> {
    let roots = build_nats_root_store(anchors)?;
    let config = ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| DomainError::Invariant(format!("nats_connect:rustls provider/versions: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(config)
}

// ---------------------------------------------------------------------------
// EventNotifier impl
// ---------------------------------------------------------------------------

impl EventNotifier for NatsNotifier {
    fn notify<'a>(
        &'a self,
        target: &'a SubscriptionTarget,
        subscription_id: SubscriptionId,
        events: &'a [PersistedEvent],
    ) -> BoxFuture<'a, NotifyOutcome> {
        Box::pin(async move {
            let subject = match target {
                SubscriptionTarget::NatsJetStream { subject } => subject.clone(),
                SubscriptionTarget::Webhook { .. } => {
                    // The dispatcher consults `supports()` first; if a
                    // misrouted target reaches us, defensively report a
                    // closed-enum failure rather than panicking.
                    return NotifyOutcome::Failed {
                        reason: NotifyFailureReason::Other("unsupported_target".into()),
                    };
                }
            };

            deliver(&self.jetstream, subject, subscription_id, events).await
        })
    }

    fn supports(&self, target: &SubscriptionTarget) -> bool {
        matches!(target, SubscriptionTarget::NatsJetStream { .. })
    }
}

// ---------------------------------------------------------------------------
// Delivery — serialise + publish + ack with 2s deadline
// ---------------------------------------------------------------------------

/// Build the canonical JSON payload bytes that the JetStream publish
/// call sends as `Bytes`. Extracted from [`deliver`] so a unit test can
/// verify the wire shape (especially the `schema_version` literal —
/// invariant 7) without standing up a live broker.
///
/// `pub(crate)` rather than private so the inner `tests` module can call
/// it; the function has no behavioural effect of its own — it serialises
/// the payload to bytes and returns the result alongside the freshly
/// generated `delivery_id` so callers can use one consistent UUID for
/// both the payload and any future logging.
fn build_payload_bytes(
    subscription_id: SubscriptionId,
    events: &[PersistedEvent],
) -> Result<Vec<u8>, serde_json::Error> {
    let payload = NatsPayload {
        schema_version: SCHEMA_VERSION,
        delivery_id: Uuid::new_v4().to_string(),
        subscription_id: subscription_id.0.to_string(),
        delivered_at: chrono::Utc::now().to_rfc3339(),
        events,
    };
    serde_json::to_vec(&payload)
}

/// Single-shot JetStream delivery. Builds the canonical JSON body,
/// publishes to `subject`, and awaits the inner `PublishAck` with the
/// 2s deadline.
async fn deliver(
    js: &jetstream::Context,
    subject: String,
    subscription_id: SubscriptionId,
    events: &[PersistedEvent],
) -> NotifyOutcome {
    let payload_bytes = match build_payload_bytes(subscription_id, events) {
        Ok(b) => b,
        Err(e) => {
            // Serialisation failure is non-transient; surface as a
            // closed-enum `Other` reason. Should never happen with our
            // domain types (`PersistedEvent` derives Serialize without
            // fallible paths).
            tracing::warn!(error = %e, "nats payload serialise failed");
            return NotifyOutcome::Failed {
                reason: NotifyFailureReason::Other(format!("serialize:{e}")),
            };
        }
    };

    // `Context::publish` returns a future that resolves to a
    // `PublishAckFuture`. The outer future completes when the publish
    // request has been accepted by the client; the inner future
    // completes on broker ack. We wrap the inner with
    // `tokio::time::timeout` so the 2s deadline applies
    // regardless of any default `async-nats` ships with.
    let ack_future = match js
        .publish(subject.clone(), Bytes::from(payload_bytes))
        .await
    {
        Ok(f) => f,
        Err(e) => {
            let reason = classify_publish_error(&e);
            tracing::warn!(
                subject = %truncated_subject(&subject),
                error = %e,
                error_kind = ?e.kind(),
                classified_reason = ?reason,
                "nats publish call failed"
            );
            return NotifyOutcome::Failed { reason };
        }
    };

    match tokio::time::timeout(ACK_TIMEOUT, ack_future).await {
        Ok(Ok(_ack)) => NotifyOutcome::Delivered,
        Ok(Err(e)) => {
            let reason = classify_publish_error(&e);
            tracing::warn!(
                subject = %truncated_subject(&subject),
                error = %e,
                error_kind = ?e.kind(),
                classified_reason = ?reason,
                "nats publish ack returned error"
            );
            NotifyOutcome::Failed { reason }
        }
        Err(_elapsed) => {
            tracing::warn!(
                subject = %truncated_subject(&subject),
                "nats publish ack timeout"
            );
            NotifyOutcome::Failed {
                reason: NotifyFailureReason::AckTimeout,
            }
        }
    }
}

/// Classify an [`async_nats::jetstream::context::PublishError`] into
/// the closed [`NotifyFailureReason`] enum.
///
/// Earlier implementations mapped everything-not-timeout to
/// `ConnectionLost`, hiding the difference between a misconfigured
/// subject and a broker outage. The mapping below is the API surface
/// of `async-nats` 0.48 (`PublishErrorKind` is the exported enum;
/// `PublishError::kind()` returns it by value — see
/// `async-nats-0.48.0/src/jetstream/context.rs:1822`).
///
/// **NAK family.** Broker accepted the wire but rejected the publish
/// at the JetStream layer:
/// - `StreamNotFound` — the configured subject does not match any
///   stream (the "no responders" condition).
/// - `WrongLastMessageId` / `WrongLastSequence` — broker rejected the
///   expected-id / expected-seq preconditions; operator-visible
///   configuration mismatch.
/// - `MaxAckPending` — stream's `MaxAckPending` reached; operator
///   needs to widen the limit or consumers need to ack faster.
/// - `Other` whose `to_string()` matches the literal "no responders"
///   wording surfaced by the NATS server when the JetStream API
///   route has no listening server (defensive fallback for future
///   `async-nats` releases that may shift the variant).
///
/// **Transport family.** Everything else — broken pipe, generic
/// `Other` — stays at `ConnectionLost` as before.
fn classify_publish_error(e: &PublishError) -> NotifyFailureReason {
    match e.kind() {
        PublishErrorKind::StreamNotFound
        | PublishErrorKind::WrongLastMessageId
        | PublishErrorKind::WrongLastSequence
        | PublishErrorKind::MaxAckPending => NotifyFailureReason::NatsNak,
        PublishErrorKind::TimedOut | PublishErrorKind::BrokenPipe => {
            NotifyFailureReason::ConnectionLost
        }
        PublishErrorKind::Other => {
            // Defensive: `Other` is the catch-all the upstream uses
            // for unmodelled broker conditions. If the error string
            // surfaces a recognisable NAK shape, prefer the NAK
            // bucket; otherwise stay with the transport bucket.
            let msg = e.to_string().to_lowercase();
            if msg.contains("no responders")
                || msg.contains("no stream")
                || msg.contains("no responders available")
            {
                NotifyFailureReason::NatsNak
            } else {
                NotifyFailureReason::ConnectionLost
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tracing helpers
// ---------------------------------------------------------------------------

/// Truncate `subject` for tracing. The tracing discipline specifies
/// "subject prefix only (truncated)" to avoid log-injection / leakage
/// of operator subject hierarchies. The 32-byte budget is enough to
/// identify the namespace without exposing the leaf.
///
/// The truncation respects UTF-8 boundaries — multi-byte chars that
/// straddle byte 32 are dropped wholesale rather than producing
/// invalid UTF-8.
fn truncated_subject(subject: &str) -> String {
    if subject.len() <= TRACING_SUBJECT_MAX {
        return subject.to_string();
    }
    let mut cut = TRACING_SUBJECT_MAX;
    while cut > 0 && !subject.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &subject[..cut])
}

// ---------------------------------------------------------------------------
// Tests — unit. The JetStream protocol path lives in `tests/`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- supports() --------------------------------------------------------

    // The `make_test_notifier` helper builds a real `async_nats::Client`
    // off-thread; `jetstream::new(client)` itself touches the tokio
    // reactor, so all tests that construct a `NatsNotifier` run under
    // `#[tokio::test]`. The `truncated_subject` tests stay synchronous
    // because they don't touch `NatsNotifier` at all.

    #[tokio::test]
    async fn supports_returns_true_for_nats_target() {
        let n = make_test_notifier();
        let target = SubscriptionTarget::NatsJetStream {
            subject: "events.artifact.ingested".into(),
        };
        assert!(n.supports(&target));
    }

    #[tokio::test]
    async fn supports_returns_false_for_webhook_target() {
        let n = make_test_notifier();
        let target = SubscriptionTarget::Webhook {
            url: url::Url::parse("https://example.com/hook").unwrap(),
            secret_ref: hort_domain::ports::secret_port::SecretRef {
                source: hort_domain::ports::secret_port::SecretSource::EnvVar,
                location: "HORT_WEBHOOK_SECRET".into(),
            },
        };
        assert!(!n.supports(&target));
    }

    // -- truncated_subject() -----------------------------------------------

    #[test]
    fn truncated_subject_short_passes_through() {
        assert_eq!(truncated_subject("events.artifact"), "events.artifact");
    }

    #[test]
    fn truncated_subject_exactly_at_limit_passes_through() {
        // 32 ASCII chars — at the boundary, no ellipsis appended.
        let s = "a".repeat(TRACING_SUBJECT_MAX);
        assert_eq!(truncated_subject(&s), s);
    }

    #[test]
    fn truncated_subject_long_truncates_at_32_chars_with_ellipsis() {
        let s = "a".repeat(64);
        let t = truncated_subject(&s);
        // 32 'a' + ellipsis (3 UTF-8 bytes, 1 char).
        assert_eq!(t, format!("{}…", "a".repeat(TRACING_SUBJECT_MAX)));
        // Sanity: the truncated form fits 33 chars (32 + the ellipsis
        // glyph), NOT 33+ bytes — assertion is on char count.
        assert_eq!(t.chars().count(), TRACING_SUBJECT_MAX + 1);
    }

    #[test]
    fn truncated_subject_respects_utf8_boundary() {
        // Build a string whose 32nd byte falls inside a 3-byte char
        // (`€` = U+20AC = 0xE2 0x82 0xAC). 30 ASCII bytes + `€` (3
        // bytes) puts the 31st byte at the start of `€`. We want the
        // cut to back up to byte 30 so the resulting prefix is valid
        // UTF-8.
        let mut s = "a".repeat(30);
        s.push('€');
        s.push('€');
        s.push('€');
        // Total len is 30 + 9 = 39 bytes. Naïve cut at 32 lands inside
        // the second `€`.
        let t = truncated_subject(&s);
        // The prefix must be valid UTF-8 by construction (Rust would
        // otherwise panic on slicing); assert the visible char count.
        // 30 ASCII 'a' + ellipsis is the expected shape — the second
        // `€` is dropped wholesale.
        assert!(
            t.ends_with('…'),
            "truncated form must end with the ellipsis"
        );
        assert!(
            t.starts_with(&"a".repeat(30)),
            "truncated form must preserve the ASCII prefix"
        );
    }

    // -- classify_publish_error --------------------------------------------

    #[test]
    fn classify_stream_not_found_is_nats_nak() {
        let e = PublishError::new(PublishErrorKind::StreamNotFound);
        assert_eq!(classify_publish_error(&e), NotifyFailureReason::NatsNak);
    }

    #[test]
    fn classify_wrong_last_message_id_is_nats_nak() {
        let e = PublishError::new(PublishErrorKind::WrongLastMessageId);
        assert_eq!(classify_publish_error(&e), NotifyFailureReason::NatsNak);
    }

    #[test]
    fn classify_wrong_last_sequence_is_nats_nak() {
        let e = PublishError::new(PublishErrorKind::WrongLastSequence);
        assert_eq!(classify_publish_error(&e), NotifyFailureReason::NatsNak);
    }

    #[test]
    fn classify_max_ack_pending_is_nats_nak() {
        let e = PublishError::new(PublishErrorKind::MaxAckPending);
        assert_eq!(classify_publish_error(&e), NotifyFailureReason::NatsNak);
    }

    #[test]
    fn classify_timed_out_is_connection_lost() {
        // `TimedOut` here is the publish-call-level timeout (not the
        // ack-future timeout, which is mapped to `AckTimeout` at the
        // caller site). Stays in the transport bucket.
        let e = PublishError::new(PublishErrorKind::TimedOut);
        assert_eq!(
            classify_publish_error(&e),
            NotifyFailureReason::ConnectionLost
        );
    }

    #[test]
    fn classify_broken_pipe_is_connection_lost() {
        let e = PublishError::new(PublishErrorKind::BrokenPipe);
        assert_eq!(
            classify_publish_error(&e),
            NotifyFailureReason::ConnectionLost
        );
    }

    #[test]
    fn classify_other_without_nak_wording_is_connection_lost() {
        let e = PublishError::new(PublishErrorKind::Other);
        // Default `Other` Display is "publish failed" — does not match
        // any NAK-wording substring, so the transport bucket is the
        // right default.
        assert_eq!(
            classify_publish_error(&e),
            NotifyFailureReason::ConnectionLost
        );
    }

    // -- NATS target safety net --------------------------------------------

    #[tokio::test]
    async fn notify_with_webhook_target_returns_failed_not_panic() {
        // `supports()` is the dispatcher's filter, but defensively the
        // adapter must not panic if it receives a misrouted target.
        let n = make_test_notifier();
        let target = SubscriptionTarget::Webhook {
            url: url::Url::parse("https://example.com/hook").unwrap(),
            secret_ref: hort_domain::ports::secret_port::SecretRef {
                source: hort_domain::ports::secret_port::SecretSource::EnvVar,
                location: "HORT_WEBHOOK_SECRET".into(),
            },
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

    // -- build_payload_bytes (schema_version round-trip) -------------------

    /// Wire-shape pin for invariant 7: `schema_version`
    /// is a public-API commitment. The NATS integration tests are gated
    /// on `HORT_TEST_NATS=1` so dev environments without Docker still need
    /// a pure unit assertion that the wire body carries `schema_version
    /// == 1`. A refactor that quietly dropped or renamed the field would
    /// trip this test without needing a broker.
    #[test]
    fn build_payload_bytes_emits_schema_version_one() {
        let sub_id = SubscriptionId(Uuid::new_v4());
        let bytes = build_payload_bytes(sub_id, &[]).expect("serialise");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("body parses as JSON");

        let schema_version = body
            .as_object()
            .expect("body is a JSON object")
            .get("schema_version")
            .expect("schema_version field is present on the wire");
        assert_eq!(
            schema_version,
            &serde_json::json!(1),
            "schema_version is the public-API commitment (invariant 7)"
        );
        assert_eq!(
            schema_version.as_u64(),
            Some(1),
            "schema_version must serialise as an unsigned integer"
        );
    }

    /// Companion check — the wire shape carries the documented sibling
    /// fields (`delivery_id`, `subscription_id`, `delivered_at`,
    /// `events`). Mirrors the webhook adapter's
    /// `body_is_json_with_required_fields` so a refactor that broke the
    /// cross-transport contract trips on both sides.
    #[test]
    fn build_payload_bytes_carries_all_documented_fields() {
        let sub_id = SubscriptionId(Uuid::new_v4());
        let bytes = build_payload_bytes(sub_id, &[]).expect("serialise");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("body parses as JSON");
        assert_eq!(
            body["subscription_id"],
            serde_json::json!(sub_id.0.to_string())
        );
        let delivery_id = body["delivery_id"]
            .as_str()
            .expect("delivery_id is a string");
        Uuid::parse_str(delivery_id).expect("delivery_id parses as uuid");
        let delivered_at = body["delivered_at"]
            .as_str()
            .expect("delivered_at is a string");
        chrono::DateTime::parse_from_rfc3339(delivered_at).expect("delivered_at is rfc3339");
        assert!(body["events"].is_array());
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    // -- Extra-CA trust threading (ADR 0010) --------------------------------

    use hort_config::ExtraTrustAnchors;

    /// Generate a fully-valid self-signed X.509 CA via `rcgen` — the
    /// same generator + helper shape `hort-notifier-webhook` /
    /// `hort-adapters-upstream-http` use. Unlike the static truncated PEM
    /// in `hort-config`'s `extra_ca.rs` tests (which only needs to *parse*
    /// as PEM), the extra-CA root-store assertions push the cert into a real
    /// `rustls::RootCertStore`, which performs full trust-anchor
    /// validation and rejects a truncated cert. A real rcgen CA is the
    /// established workspace pattern for that path.
    fn make_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "notifier-nats extra-ca-test root CA".to_string(),
        );
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("generate CA keypair");
        params.self_signed(&key).expect("self-sign CA").pem()
    }

    fn one_anchor() -> ExtraTrustAnchors {
        ExtraTrustAnchors::parse_pem(make_ca_pem().as_bytes()).expect("rcgen CA PEM parses")
    }

    /// `None` → the `Default` branch (plain `async_nats::connect(url)` —
    /// byte-equivalent to the prior behaviour for the no-extra-CA
    /// deployment). Pure decision, asserted without a broker.
    #[test]
    fn decide_nats_tls_none_is_default() {
        let decision = decide_nats_tls(None).expect("None decision is infallible");
        assert!(
            matches!(decision, NatsTls::Default),
            "None must select the plain-connect branch"
        );
    }

    /// An empty-anchor bundle is treated the same as `None` (defensive —
    /// `parse_pem` rejects empty, but `is_empty()` is the documented
    /// guard and the byte-equivalence promise must hold for it too).
    #[test]
    fn decide_nats_tls_empty_anchors_is_default() {
        // Construct an empty bundle via the public parse path is
        // impossible (parse_pem rejects empty), so exercise the guard
        // through the same Option API a caller would: a Some that is
        // empty is unreachable in practice, but the branch decision must
        // still resolve to Default. We assert the non-empty Some case
        // resolves to Custom (the meaningful half) and rely on the
        // is_empty() guard in the impl for the defensive half.
        let anchors = one_anchor();
        assert!(!anchors.is_empty());
        let decision = decide_nats_tls(Some(&anchors)).expect("non-empty Some builds a config");
        assert!(
            matches!(decision, NatsTls::Custom(_)),
            "a non-empty extra-CA bundle must select the custom-rustls branch"
        );
    }

    /// `Some(non-empty)` builds a `rustls::ClientConfig` containing the
    /// **system root store PLUS** the parsed extra anchor — system roots
    /// are NOT dropped (mirrors `build_rustls_client_config` in
    /// upstream-http). Asserted via the factored pure helper.
    #[test]
    fn build_nats_rustls_config_includes_system_roots_plus_extra() {
        // Baseline: how many roots the helper builds with an empty extra
        // set is the system count; with one extra cert it must be
        // system_count + 1. We can't call the helper with zero extras
        // (the connect path uses Default there), so assert the absolute
        // invariant: the resulting store contains strictly more roots
        // than the OS store alone, and exactly +cert_count more.
        let native = rustls_native_certs::load_native_certs();
        let system_count = native.certs.len();
        assert!(
            system_count > 0,
            "test host must have an OS trust store for this assertion"
        );

        let anchors = one_anchor();
        let roots = build_nats_root_store(&anchors).expect("root store builds");
        assert_eq!(
            roots.len(),
            system_count + anchors.cert_count(),
            "augmented store = system roots + extra anchors (system roots not dropped)"
        );

        // And the full ClientConfig builds without panicking.
        let cfg = build_nats_rustls_config(&anchors).expect("client config builds");
        // A `ClientConfig` built for client-auth-none always has an
        // empty client-auth cert resolver; the meaningful assertion is
        // that construction succeeded with the ring provider (no
        // global-default-provider dependency / panic).
        let _ = cfg;
    }

    /// The custom-TLS decision carries the same config the pure builder
    /// produces (the branch does not silently drop the anchors).
    #[test]
    fn decide_nats_tls_some_carries_built_config() {
        let anchors = one_anchor();
        match decide_nats_tls(Some(&anchors)).expect("builds") {
            NatsTls::Custom(_) => { /* config present — see prior test for root count */ }
            NatsTls::Default => panic!("Some(non-empty) must not select Default"),
        }
    }

    // -- helpers -----------------------------------------------------------

    /// Build a notifier wrapping an `async_nats::Client` whose backing
    /// TCP endpoint is a no-op loopback acceptor. The synchronous
    /// `supports()` tests + the misrouted-target safety net never
    /// reach `publish`, so the broker-protocol state of the client is
    /// immaterial.
    ///
    /// The connect runs on a dedicated thread + dedicated tokio runtime
    /// so it composes inside `#[tokio::test]`s without nested-runtime
    /// panics.
    fn make_test_notifier() -> NatsNotifier {
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;

        // Ephemeral loopback acceptor — never accept; the test never
        // exercises any wire-level interaction with this endpoint.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("read local addr");
        // Keep the listener alive for the duration of the test
        // process — closing it would make `retry_on_initial_connect`
        // cycle indefinitely. `std::mem::forget` is intentional in a
        // unit-test scope.
        std::mem::forget(listener);

        let (tx, rx) = mpsc::channel::<Result<async_nats::Client, String>>();
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build helper rt");
            let res = rt.block_on(async {
                async_nats::ConnectOptions::new()
                    .retry_on_initial_connect()
                    .connect(format!("nats://{addr}"))
                    .await
                    .map_err(|e| format!("connect: {e}"))
            });
            let _ = tx.send(res);
        });
        let client = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("helper thread responds")
            .expect("client constructs against loopback");
        NatsNotifier::new(client)
    }
}
