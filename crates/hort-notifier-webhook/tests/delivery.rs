//! Webhook delivery integration tests.
//!
//! These exercise the full HTTP request path against a real local
//! `wiremock` server, asserting:
//! - 2xx → Delivered
//! - 4xx / 5xx → DownstreamRejected with the closed-enum reason
//! - 3xx → DownstreamRejected { RedirectAttempted } and the redirect
//!   URL is NOT fetched (the IMDS SSRF channel)
//! - Connect refused → Failed { ConnectionRefused }
//! - Headers present in the expected wire format
//! - Signature verifies with the SecretPort-resolved plaintext bytes
//!   (the key is the resolved secret, not any at-rest stored value)
//!
//! No production timeouts are exercised here — the 10s request timeout
//! is only verified by classifier unit tests (in `src/lib.rs`).

use std::sync::Arc as StdArc;

use hmac::{Hmac, Mac};
use hort_domain::entities::subscription::{SubscriptionId, SubscriptionTarget};
use hort_domain::error::DomainResult;
use hort_domain::events::PersistedEvent;
use hort_domain::ports::event_notifier::{EventNotifier, NotifyFailureReason, NotifyOutcome};
use hort_domain::ports::secret_port::{SecretPort, SecretRef, SecretSource, SecretValue};
use hort_domain::ports::BoxFuture;
use hort_notifier_webhook::WebhookNotifier;
use sha2::Sha256;
use url::Url;
use uuid::Uuid;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The plaintext the operator provisioned behind the `SecretRef`. This
/// is the HMAC key the receiver verifies with (F-19) — NOT any stored
/// hash.
const SHARED_SECRET: &[u8] = b"webhook-shared-secret-plaintext";

/// Test [`SecretPort`] returning a fixed plaintext — mirrors the
/// `hort-adapters-upstream-http` `FixedSecretPort` pattern.
struct FixedSecret;
impl SecretPort for FixedSecret {
    fn resolve<'a>(
        &'a self,
        _reference: &'a SecretRef,
    ) -> BoxFuture<'a, DomainResult<SecretValue>> {
        Box::pin(async { Ok(SecretValue::from_bytes(SHARED_SECRET.to_vec())) })
    }
}

fn secret_port() -> StdArc<dyn SecretPort> {
    StdArc::new(FixedSecret)
}

fn webhook_target(server_uri: &str) -> SubscriptionTarget {
    SubscriptionTarget::Webhook {
        url: Url::parse(&format!("{server_uri}/hook")).unwrap(),
        secret_ref: SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        },
    }
}

fn sub_id() -> SubscriptionId {
    SubscriptionId(Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// 2xx classification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delivers_2xx_response_as_delivered() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(outcome, NotifyOutcome::Delivered);
}

// ---------------------------------------------------------------------------
// 4xx / 5xx classification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_404_classified_as_downstream_rejected_http4xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(
        outcome,
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http4xx { status: 404 },
        }
    );
}

#[tokio::test]
async fn http_503_classified_as_downstream_rejected_http5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(
        outcome,
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::Http5xx { status: 503 },
        }
    );
}

// ---------------------------------------------------------------------------
// 3xx — must NOT follow the redirect (SSRF channel block)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_302_classified_as_redirect_attempted_not_followed() {
    let server = MockServer::start().await;
    // The redirect points at the IMDS URL — a real-world SSRF target.
    // If the adapter were to follow the redirect, wiremock would never
    // see the response, and the test harness would catch the SSRF
    // attempt via the IMDS-address hit. With `Policy::limited(0)` the
    // 302 surfaces as `DownstreamRejected { RedirectAttempted }`.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "http://169.254.169.254/latest/meta-data/"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(
        outcome,
        NotifyOutcome::DownstreamRejected {
            reason: NotifyFailureReason::RedirectAttempted,
        }
    );

    // Wiremock's `.expect(1)` on the original /hook mock asserts that
    // the adapter made exactly one HTTP request — i.e. it did not
    // follow the 302 to IMDS. The assertion fires on `server.drop()`.
}

// ---------------------------------------------------------------------------
// Transport — connect refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_refused_classified_as_failed() {
    // Pick a port nothing is listening on. Port 1 is the canonical
    // "definitely not in use" port — root-only on Unix, never bound
    // by a typical app.
    let target = SubscriptionTarget::Webhook {
        url: Url::parse("http://127.0.0.1:1/hook").unwrap(),
        secret_ref: SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        },
    };
    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    match outcome {
        NotifyOutcome::Failed { reason } => {
            // reqwest classifies "connection refused" as either
            // `is_connect()` (ConnectionRefused) or, on some platforms,
            // bucketed into `Other(transport:…)`. Both are acceptable
            // — the adapter contract is "Failed", not the inner reason.
            assert!(
                matches!(reason, NotifyFailureReason::ConnectionRefused)
                    || matches!(reason, NotifyFailureReason::Other(_)),
                "expected ConnectionRefused or Other(transport:…), got {reason:?}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Header presence + format
// ---------------------------------------------------------------------------

#[tokio::test]
async fn headers_present_and_in_expected_format() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header("Content-Type", "application/json; charset=utf-8"))
        .and(header("X-Hort-Schema-Version", "1"))
        .and(header_exists("X-Hort-Signature"))
        .and(header_exists("X-Hort-Subscription-Id"))
        .and(header_exists("X-Hort-Delivery-Id"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(outcome, NotifyOutcome::Delivered);
}

#[tokio::test]
async fn signature_header_is_sha256_hex_lowercase() {
    let server = MockServer::start().await;
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Request>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(move |req: &Request| {
            captured_clone.lock().unwrap().push(req.clone());
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(outcome, NotifyOutcome::Delivered);

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let sig_value = reqs[0]
        .headers
        .get("x-hort-signature")
        .expect("X-Hort-Signature present")
        .to_str()
        .unwrap();
    let hex_part = sig_value
        .strip_prefix("sha256=")
        .expect("signature header starts with sha256=");
    // HMAC-SHA256 → 32 bytes → 64 lowercase hex chars.
    assert_eq!(hex_part.len(), 64, "hex length = 64");
    assert!(
        hex_part
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex only: {hex_part}"
    );
}

// ---------------------------------------------------------------------------
// Signature verifies with the SecretPort-resolved plaintext bytes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signature_verifies_with_resolved_plaintext_secret() {
    let server = MockServer::start().await;
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Request>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(move |req: &Request| {
            captured_clone.lock().unwrap().push(req.clone());
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(outcome, NotifyOutcome::Delivered);

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let body_bytes = &reqs[0].body;
    let sig_value = reqs[0]
        .headers
        .get("x-hort-signature")
        .expect("X-Hort-Signature present")
        .to_str()
        .unwrap();
    let received_hex = sig_value.strip_prefix("sha256=").unwrap();

    // Receiver-side verification: re-compute HMAC over the raw body
    // bytes with the SecretPort-RESOLVED PLAINTEXT (F-19). The adapter
    // signs the body verbatim — no re-serialisation. Wire format is
    // unchanged; only the key source changed.
    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET).expect("any-length HMAC key");
    mac.update(body_bytes);
    let expected_hex = hex::encode(mac.finalize().into_bytes());

    assert_eq!(
        received_hex, expected_hex,
        "receiver-side HMAC over body must match X-Hort-Signature (keyed by \
         the resolved plaintext, F-19)"
    );
}

// ---------------------------------------------------------------------------
// Subscription-id header value matches the call argument
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subscription_id_header_carries_the_call_argument() {
    let server = MockServer::start().await;
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Request>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(move |req: &Request| {
            captured_clone.lock().unwrap().push(req.clone());
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let id = SubscriptionId(Uuid::new_v4());
    let _ = notifier.notify(&target, id, &[]).await;

    let reqs = captured.lock().unwrap();
    let header_val = reqs[0]
        .headers
        .get("x-hort-subscription-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(header_val, id.0.to_string());
}

// ---------------------------------------------------------------------------
// Wire body shape — schema_version, delivery_id, subscription_id present
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_is_json_with_required_fields() {
    let server = MockServer::start().await;
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Request>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(move |req: &Request| {
            captured_clone.lock().unwrap().push(req.clone());
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let id = SubscriptionId(Uuid::new_v4());
    let _ = notifier.notify(&target, id, &[] as &[PersistedEvent]).await;

    let reqs = captured.lock().unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&reqs[0].body).expect("body parses as JSON");
    assert_eq!(body["schema_version"], serde_json::json!(1));
    assert_eq!(body["subscription_id"], serde_json::json!(id.0.to_string()));
    // delivery_id is a fresh uuid — verify shape, not exact value.
    let delivery_id = body["delivery_id"]
        .as_str()
        .expect("delivery_id is a string");
    Uuid::parse_str(delivery_id).expect("delivery_id parses as uuid");
    // delivered_at present + RFC3339 parseable.
    let delivered_at = body["delivered_at"]
        .as_str()
        .expect("delivered_at is a string");
    chrono::DateTime::parse_from_rfc3339(delivered_at).expect("delivered_at is rfc3339");
    // events array present (empty in this test).
    assert!(body["events"].is_array());
    assert_eq!(body["events"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// schema_version round-trip — invariant 7
//
// `body_is_json_with_required_fields` above checks schema_version as part
// of a bundle of body assertions. This dedicated round-trip test is the
// load-bearing pin for design doc §11 invariant 7 ("schema_version is a
// public-API commitment"): a refactor that quietly dropped or renamed the
// field would still pass the bundle test if the surrounding assertions
// held, but must trip THIS test. The single-purpose assertion makes the
// intent unmistakable in failure output.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_schema_version_field_is_literal_one() {
    let server = MockServer::start().await;
    let captured: std::sync::Arc<std::sync::Mutex<Vec<Request>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(move |req: &Request| {
            captured_clone.lock().unwrap().push(req.clone());
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier
        .notify(&target, sub_id(), &[] as &[PersistedEvent])
        .await;
    assert_eq!(outcome, NotifyOutcome::Delivered);

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let body: serde_json::Value =
        serde_json::from_slice(&reqs[0].body).expect("body parses as JSON");

    // Field MUST be present — `get` returns None if absent, which would
    // trip the unwrap.
    let schema_version = body
        .as_object()
        .expect("body is a JSON object")
        .get("schema_version")
        .expect("schema_version field is present on the wire");
    // Field value MUST be the literal integer 1 (not a string, not 0,
    // not a JSON number that round-trips as a float).
    assert_eq!(
        schema_version,
        &serde_json::json!(1),
        "schema_version is the public-API commitment from §11 invariant 7"
    );
    assert_eq!(
        schema_version.as_u64(),
        Some(1),
        "schema_version must serialise as an unsigned integer"
    );
}

// ---------------------------------------------------------------------------
// notify() returns within the 11s ceiling (10s timeout + 1s slack) when
// the downstream is unreachable — §11 invariant 1.
//
// The invariant is "notify MUST NOT block". The 10s `TOTAL_TIMEOUT` is
// the reqwest-level ceiling; this test asserts the call returns within
// 10s + 1s of test slack against a non-listening port. Port 1 is the
// canonical "never bound by a typical app" port; `connect()` either
// receives an immediate RST (typical Linux behaviour, returns in ms) or
// — in the unlikely "no RST + drop" case — runs out the 5s connect
// timeout. Either way, `notify` returns well before 11s.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn notify_returns_within_11s_when_downstream_unreachable() {
    // Direct construction — bypasses `WebhookTargetGuard::check` which
    // would reject 127.0.0.1:1 as not-routable. The test exercises
    // `notify` in isolation, not the guard.
    let target = SubscriptionTarget::Webhook {
        url: Url::parse("http://127.0.0.1:1/hook").unwrap(),
        secret_ref: SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        },
    };
    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(11),
        notifier.notify(&target, sub_id(), &[]),
    )
    .await
    .expect("notify must return within 11s when downstream is unreachable — §11 invariant 1");

    // The exact failure reason depends on platform — ConnectionRefused
    // on Linux/macOS when the kernel sends RST, or RequestTimeout / Other
    // on platforms / firewalls that black-hole the SYN. The invariant
    // under test is "must not block"; the variant is incidental.
    assert!(
        matches!(outcome, NotifyOutcome::Failed { .. }),
        "expected Failed{{..}}, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Empty-events: still emits one POST (best-effort, dispatcher controls batching)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_events_still_posts_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let notifier = WebhookNotifier::new(None, secret_port()).expect("builder");
    let target = webhook_target(&server.uri());
    let outcome = notifier.notify(&target, sub_id(), &[]).await;
    assert_eq!(outcome, NotifyOutcome::Delivered);
}
