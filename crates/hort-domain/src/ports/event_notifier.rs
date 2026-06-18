//! Best-effort event-notification port.
//!
//! See `docs/architecture/explanation/event-notifications.md`.
//!
//! # Best-effort invariant
//!
//! Implementations MUST NOT retry, MUST NOT buffer beyond what the underlying
//! transport requires for a single send, and MUST NOT block the caller on
//! downstream unavailability. Failures propagate to the caller as
//! [`NotifyOutcome::Failed`]; the dispatcher records the failure for budget
//! accounting and moves on. Durable delivery is the consumer's responsibility
//! via `EventStore::read_category` (ADR 0004) re-sync.
//!
//! # Type-deserialisation invariant
//!
//! No type in this module derives `Deserialize`. The dispatcher constructs
//! these types from in-process state; nothing is reconstituted from external
//! input. Adapter-side wire deserialisation (HTTP webhook responses,
//! JetStream ack frames) is internal to the adapter and never bubbles up as
//! a domain type.

use crate::events::PersistedEvent;

use super::BoxFuture;
use crate::entities::subscription::{SubscriptionId, SubscriptionTarget};

/// Outcome of one [`EventNotifier::notify`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// Adapter sent the batch and downstream accepted it
    /// (HTTP 2xx for webhook, `PublishAck` for JetStream).
    Delivered,
    /// Adapter successfully sent but downstream returned a non-success
    /// response (HTTP 4xx/5xx for webhook, NATS NAK for JetStream).
    DownstreamRejected {
        /// Closed-enum reason for the rejection.
        reason: NotifyFailureReason,
    },
    /// Adapter could not establish transport (connection refused, DNS, TLS
    /// handshake failure, JetStream broker unreachable).
    Failed {
        /// Closed-enum reason for the transport failure.
        reason: NotifyFailureReason,
    },
}

/// Closed enum of adapter-level failure reasons surfaced to the dispatcher
/// for failure-budget accounting and `last_failure` persistence.
///
/// **Cardinality discipline.** This enum is the canonical set of failure
/// reasons used by `hort_notify_delivery_total{result=...}` and
/// `last_failure.reason`. Adding a new variant changes the metric label set
/// AND the JSONB shape of `subscriptions.last_failure`. The `Other(String)`
/// fallback handles adapter-specific edges without bloating the closed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyFailureReason {
    /// Webhook adapter blocked a 3xx response
    /// (`Policy::limited(0)` — webhook URLs must be canonical).
    RedirectAttempted,
    /// HTTP 4xx response from the webhook receiver.
    Http4xx {
        /// HTTP status code returned by the receiver.
        status: u16,
    },
    /// HTTP 5xx response from the webhook receiver.
    Http5xx {
        /// HTTP status code returned by the receiver.
        status: u16,
    },
    /// TCP connect did not complete within the connect-timeout window.
    ConnectTimeout,
    /// Connect succeeded but the request did not complete within the total
    /// request-timeout window.
    RequestTimeout,
    /// TLS handshake error (cert chain, hostname, version mismatch, …).
    Tls,
    /// DNS resolution failed at delivery time (NXDOMAIN, SERVFAIL, …).
    Dns,
    /// Remote endpoint actively refused the connection.
    ConnectionRefused,
    /// NATS JetStream `PublishAck` did not arrive within the ack-timeout
    /// window.
    AckTimeout,
    /// NATS broker explicitly rejected the publish — typically the
    /// configured subject does not match any stream (NoResponders /
    /// `PublishErrorKind::StreamNotFound` / explicit broker NAK).
    /// Distinct from [`ConnectionLost`] so dashboards can tell
    /// "misrouted subscription" from "broker unreachable" — the
    /// remediation is operator-side (fix the stream/subject mapping),
    /// not transport-side.
    ///
    /// Surfaced in tracing spans only — the
    /// `hort_notify_delivery_total{result}` cardinality stays at the
    /// outcome level (`failed`); see the cardinality discipline in
    /// `docs/architecture/explanation/event-notifications.md`.
    /// Per-failure-reason fan-out lives in spans, not
    /// metric labels.
    NatsNak,
    /// NATS connection dropped mid-send.
    ConnectionLost,
    /// Adapter-specific fallback. **Must not include PII** — adapters
    /// should map known failure shapes to dedicated variants.
    Other(String),
}

/// Best-effort delivery of newly-appended events to one subscription's target.
///
/// Implementations MUST NOT retry, MUST NOT buffer, and MUST NOT block the
/// caller on downstream unavailability. The dispatcher records failures and
/// moves on; consumers reconcile via pull (`GET /api/v1/events`).
pub trait EventNotifier: Send + Sync {
    /// Dispatch one batch of events to one subscription's target.
    ///
    /// The `subscription_id` is threaded through so adapters that surface
    /// the id on the wire (webhook `X-Ak-Subscription-Id` header + JSON
    /// body `subscription_id` field; NATS JetStream JSON body
    /// `subscription_id` field) do not need to ferry it via a separate
    /// channel. Adapters that do not need it (test stubs, future
    /// fire-and-forget transports) ignore the parameter.
    ///
    /// Returns [`NotifyOutcome`] for observability. The dispatcher does not
    /// branch on the variant beyond updating metrics + the failure-budget
    /// counter — there is no retry path.
    fn notify<'a>(
        &'a self,
        target: &'a SubscriptionTarget,
        subscription_id: SubscriptionId,
        events: &'a [PersistedEvent],
    ) -> BoxFuture<'a, NotifyOutcome>;

    /// Adapter discriminator. Used by the dispatcher to route subscriptions
    /// to the matching adapter at composition time.
    fn supports(&self, target: &SubscriptionTarget) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that [`EventNotifier`] is
    /// dyn-compatible. The dispatcher wires it behind
    /// `Vec<Arc<dyn EventNotifier>>` in the composition root; a
    /// non-dyn-compatible signature would break that wiring at compile
    /// time. The runtime `size_of` call exercises the assertion in the
    /// test body so coverage tooling counts it.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn EventNotifier>();
    }

    #[test]
    fn notify_outcome_delivered_eq() {
        assert_eq!(NotifyOutcome::Delivered, NotifyOutcome::Delivered);
    }

    #[test]
    fn notify_outcome_downstream_rejected_carries_reason() {
        let a = NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http4xx { status: 404 },
        };
        let b = NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http4xx { status: 404 },
        };
        assert_eq!(a, b);
    }

    #[test]
    fn notify_outcome_failed_eq_and_ne() {
        let a = NotifyOutcome::Failed {
            reason: NotifyFailureReason::ConnectTimeout,
        };
        let b = NotifyOutcome::Failed {
            reason: NotifyFailureReason::ConnectTimeout,
        };
        let c = NotifyOutcome::Failed {
            reason: NotifyFailureReason::Tls,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn notify_outcome_cross_variant_ne() {
        assert_ne!(
            NotifyOutcome::Delivered,
            NotifyOutcome::Failed {
                reason: NotifyFailureReason::Dns
            }
        );
    }

    #[test]
    fn notify_outcome_clone_round_trip() {
        let o = NotifyOutcome::Failed {
            reason: NotifyFailureReason::Other("custom adapter error".into()),
        };
        let cloned = o.clone();
        assert_eq!(o, cloned);
    }

    #[test]
    fn notify_failure_reason_all_variants_distinct() {
        let variants = [
            NotifyFailureReason::RedirectAttempted,
            NotifyFailureReason::Http4xx { status: 404 },
            NotifyFailureReason::Http5xx { status: 503 },
            NotifyFailureReason::ConnectTimeout,
            NotifyFailureReason::RequestTimeout,
            NotifyFailureReason::Tls,
            NotifyFailureReason::Dns,
            NotifyFailureReason::ConnectionRefused,
            NotifyFailureReason::AckTimeout,
            NotifyFailureReason::NatsNak,
            NotifyFailureReason::ConnectionLost,
            NotifyFailureReason::Other("custom".into()),
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "{i}!={j} should not be equal");
                }
            }
        }
    }

    #[test]
    fn notify_failure_reason_http_status_distinguishes() {
        let a = NotifyFailureReason::Http4xx { status: 404 };
        let b = NotifyFailureReason::Http4xx { status: 410 };
        assert_ne!(a, b);
    }

    static_assertions::assert_not_impl_any!(NotifyOutcome: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(NotifyFailureReason: serde::de::DeserializeOwned);
}
